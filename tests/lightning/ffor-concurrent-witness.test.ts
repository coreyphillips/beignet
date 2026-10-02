import { expect } from 'chai';
import { FforState } from '../../src/lightning/ffor/types';
import { IFforIssuerHop } from '../../src/lightning/ffor/issuer-messages';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	D_DEADLINE,
	FEE_BASE,
	FEE_PPM,
	makeNodeConfig,
	NodeLink,
	openReadyChannel,
	publishChannel,
	T_EXP,
	TIP
} from './helpers/ffor-world';
import { waitFor } from './helpers/ffor-witness-world';

const AMOUNT = 1_000_000n;
let seed = 99000;

function createWorld(): {
	p: LightningNode;
	w: LightningNode;
	s: LightningNode;
	r: LightningNode;
	sr: NodeLink;
	srHex: string;
	wStorage: SqliteStorage;
	witnessHop: IFforIssuerHop;
} {
	seed += 10;
	const wStorage = new SqliteStorage(':memory:');
	wStorage.open();
	const p = new LightningNode(makeNodeConfig(seed + 1));
	const w = new LightningNode(
		makeNodeConfig(seed + 2, wStorage, {
			fforWitness: { enabled: true },
			fforIssuer: { enabled: true }
		})
	);
	const s = new LightningNode(
		makeNodeConfig(seed + 3, undefined, {
			fforConcurrent: { enabled: true },
			fforSettle: { enabled: true, allowConcurrent: true }
		})
	);
	const r = new LightningNode(
		makeNodeConfig(seed + 4, undefined, {
			fforConcurrent: { enabled: true }
		})
	);
	for (const node of [p, w, s, r]) node.on('node:error', () => {});
	new NodeLink(p, w);
	new NodeLink(w, s);
	const sr = new NodeLink(s, r);
	new NodeLink(r, w);
	const pwId = openReadyChannel(p, w);
	const wsId = openReadyChannel(w, s);
	const srId = openReadyChannel(s, r);
	const scid = (txIndex: number): Buffer =>
		encodeShortChannelId({ block: 500, txIndex, outputIndex: 0 });
	publishChannel(p, p, w, pwId, scid(1));
	publishChannel(p, w, s, wsId, scid(2));
	publishChannel(s, s, r, srId, scid(3));
	for (const node of [p, w, s, r]) node.handleNewBlock(TIP);
	// Only the two channel peers participate in concurrent negotiation.
	s.getChannelManager().setFforPeerFeatureSource((peer) =>
		peer === r.getNodeId() ? r.getLocalFeatures() : null
	);
	r.getChannelManager().setFforPeerFeatureSource((peer) =>
		peer === s.getNodeId() ? s.getLocalFeatures() : null
	);
	for (const node of [p, w]) {
		node.getOnionMessageManager().setSendFunction((to, type, payload) => {
			setImmediate(() => {
				// Match the issuer harness's asynchronous onion reply transport.
				(
					node as unknown as {
						emitOutbound(to: string, type: number, payload: Buffer): void;
					}
				).emitOutbound(to, type, payload);
			});
		});
	}
	return {
		p,
		w,
		s,
		r,
		sr,
		srHex: srId.toString('hex'),
		wStorage,
		witnessHop: {
			nodeId: Buffer.from(w.getNodeId(), 'hex'),
			shortChannelId: scid(2),
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			htlcMaximumMsat: 1_000_000_000n
		}
	};
}

type World = ReturnType<typeof createWorld>;

async function activate(w: World, version: 1 | 2): Promise<Buffer> {
	const result = w.r.startFforEpoch(w.srHex, {
		voucherAmountsMsat: [AMOUNT, AMOUNT, AMOUNT],
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: FEE_BASE,
		feeProportionalMillionths: FEE_PPM,
		concurrent: true,
		concurrentVersion: version,
		witnessPeers: [Buffer.from(w.w.getNodeId(), 'hex')]
	});
	expect(result.ok, result.error).to.be.true;
	expect(w.r.getFforEpoch(w.srHex)!.state).to.equal(FforState.ACTIVE);
	const provision = await w.r.provisionFforWitness(w.srHex, w.w.getNodeId());
	return provision.mailboxId;
}

function expectRedeemed(w: World, count: number): void {
	for (const node of [w.r, w.s]) {
		const epoch = node.getFforEpoch(w.srHex)!;
		expect(epoch.state).to.equal(FforState.ACTIVE);
		expect(
			epoch.voucherOutcomes?.map((outcome) => outcome?.outcome ?? null)
		).to.deep.equal([
			...Array<string>(count).fill('fulfilled'),
			...Array<null>(3 - count).fill(null)
		]);
	}
}

describe('FFOR concurrent witness and issuer continuity', function () {
	this.timeout(30_000);
	const worlds: World[] = [];
	afterEach(() => {
		for (const world of worlds.splice(0)) {
			for (const node of [world.p, world.w, world.s, world.r]) node.destroy();
			world.wStorage.close();
		}
	});

	it('version 1: keeps the same witness and issuer usable after each partial redemption', async () => {
		const w = createWorld();
		worlds.push(w);
		const mailboxId = await activate(w, 1);
		const { offer } = w.r.createFforIssuerOffer(w.w.getNodeId(), {
			description: 'concurrent voucher slots',
			amountMsat: AMOUNT
		});
		await w.r.provisionFforIssuer(w.srHex, w.w.getNodeId(), {
			offer,
			witnessHops: [w.witnessHop]
		});
		const hashes: string[] = [];
		for (const k of [1, 2]) {
			w.sr.disconnect();
			const invoice = await w.p.getOfferManager().requestInvoice(offer);
			expect(hashes).not.to.include(invoice.paymentHash.toString('hex'));
			hashes.push(invoice.paymentHash.toString('hex'));
			w.p.payBolt12Invoice(invoice);
			await waitFor(
				() =>
					w.p.getPayment(invoice.paymentHash)?.status ===
					PaymentStatus.COMPLETED,
				`issuer invoice ${k} to settle`
			);
			w.sr.reconnect();
			const rescued = await w.r.rescueFforEpoch(w.srHex);
			expect(rescued.action).to.equal('synced');
			expect(rescued.witnesses[0].ok).to.be.true;
			expect(rescued.witnesses[0].credited).to.equal(1);
			expectRedeemed(w, k);
			expect(w.r.getFforEpoch(w.srHex)!.issuerProvisioned).to.be.true;
			expect(
				w.r.getFforEpoch(w.srHex)!.witnesses[0].mailboxId.equals(mailboxId)
			).to.be.true;
			expect(
				w.w.getFforIssuerService()!.issuedSlots(mailboxId.toString('hex'))
			).to.deep.equal(Array.from({ length: k }, (_, i) => i + 1));
			await w.r.fetchFforIssuerStatus(w.srHex, w.w.getNodeId());
		}
	});

	it('version 2: keeps witnessing later slots after rescue and still refuses issuer provisioning', async () => {
		const w = createWorld();
		worlds.push(w);
		const mailboxId = await activate(w, 2);
		const { offer } = w.r.createFforIssuerOffer(w.w.getNodeId(), {
			description: 'version 2 witness continuity',
			amountMsat: AMOUNT
		});
		let refused: Error | undefined;
		try {
			await w.r.provisionFforIssuer(w.srHex, w.w.getNodeId(), {
				offer,
				witnessHops: [w.witnessHop]
			});
		} catch (error) {
			refused = error as Error;
		}
		expect(refused?.message).to.include(
			'independent issuer admission-stop protocol'
		);
		expect(w.r.getFforEpoch(w.srHex)!.issuerProvisioned).not.to.be.true;
		for (const k of [1, 2]) {
			const invoice = w.r.createFforVoucherInvoice(w.srHex, k);
			const hash = w.r.getFforEpoch(w.srHex)!.paymentHashes[k - 1];
			w.sr.disconnect();
			w.p.sendPayment(invoice.bolt11);
			await waitFor(
				() => w.p.getPayment(hash)?.status === PaymentStatus.COMPLETED,
				`witnessed invoice ${k} to settle`
			);
			w.sr.reconnect();
			const rescued = await w.r.rescueFforEpoch(w.srHex);
			expect(rescued.action).to.equal('synced');
			expect(rescued.witnesses[0].ok).to.be.true;
			expect(rescued.witnesses[0].credited).to.equal(1);
			expectRedeemed(w, k);
			expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
			expect(
				w.w
					.getFforWitnessService()!
					.ledger.listRecords(mailboxId.toString('hex'))
			).to.have.length(k);
		}
	});
});
