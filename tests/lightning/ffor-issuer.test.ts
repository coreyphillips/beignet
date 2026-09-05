/**
 * M9.5 (spec section 9.7, section 9.7.8): the BOLT 12 issuer, co-hosted
 * with the first receipt witness. A stock payer holding only the offer
 * obtains an invoice for an unconsumed slot over the offer's path, pays it
 * through the witness while R is offline, and R recovers d_k from the
 * witness record. Identical metadata is re-answered with the same invoice
 * byte for byte; different metadata gets a different slot or the one fixed
 * refusal; a crash between the mark and the send does not issue a slot
 * twice; every refusal is byte-identical; the attestation verifies under
 * R's node id.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { IOffer, IBolt12Invoice } from '../../src/lightning/offer/types';
import {
	encodeInvoiceTlv,
	decodeInvoiceErrorTlv
} from '../../src/lightning/offer/tlv';
import { IBlindedPath } from '../../src/lightning/onion/blinded-path';
import { FforSlotState } from '../../src/lightning/ffor/types';
import {
	FF_ISSUER_ATTESTATION_TLV,
	FF_ISSUER_REFUSAL,
	IFforIssuerHop,
	decodeAttestationTlvValue,
	verifyAttestation
} from '../../src/lightning/ffor/issuer-messages';
import {
	IWorld,
	NodeLink,
	TIP,
	D_DEADLINE,
	activate,
	makeNodeConfig,
	openReadyChannel,
	publishChannel,
	record
} from './helpers/ffor-world';

interface IIssuerWorld extends IWorld {
	w: LightningNode;
	wConfig: INodeConfig;
	wStorage: SqliteStorage;
	pw: NodeLink;
	ws: NodeLink;
	rw: NodeLink;
	pwChannelId: Buffer;
	wsChannelId: Buffer;
	scidWS: Buffer;
}

let seed = 8000;
const G = 1_000_000n;
const sleep = (ms: number): Promise<void> =>
	new Promise((r) => setTimeout(r, ms));
async function waitFor(
	cond: () => boolean,
	label: string,
	ms = 5_000
): Promise<void> {
	const deadline = Date.now() + ms;
	while (!cond()) {
		if (Date.now() > deadline) throw new Error(`timed out: ${label}`);
		await sleep(10);
	}
}

function createIssuerWorld(): IIssuerWorld {
	seed += 10;
	const pConfig = makeNodeConfig(seed + 1);
	const wStorage = new SqliteStorage(':memory:');
	wStorage.open();
	const wConfig = makeNodeConfig(seed + 4, wStorage, {
		fforWitness: { enabled: true },
		fforIssuer: { enabled: true }
	});
	const sConfig = makeNodeConfig(seed + 2);
	const rConfig = makeNodeConfig(seed + 3);
	const p = new LightningNode(pConfig);
	const w = new LightningNode(wConfig);
	const s = new LightningNode(sConfig);
	const r = new LightningNode(rConfig);
	for (const n of [p, w, s, r]) n.on('node:error', () => {});
	const errors = { p: [] as string[], s: [] as string[], r: [] as string[] };
	const pw = new NodeLink(p, w);
	const ws = new NodeLink(w, s);
	const sr = new NodeLink(s, r);
	const rw = new NodeLink(r, w);
	const pwChannelId = openReadyChannel(p, w, 1_000_000n);
	const wsChannelId = openReadyChannel(w, s, 1_000_000n);
	const srChannelId = openReadyChannel(s, r, 1_000_000n);
	const scid = (i: number): Buffer =>
		encodeShortChannelId({ block: 500, txIndex: i, outputIndex: 0 });
	publishChannel(p, p, w, pwChannelId, scid(1));
	publishChannel(p, w, s, wsChannelId, scid(2));
	publishChannel(s, s, r, srChannelId, scid(3));
	for (const n of [p, w, s, r]) n.handleNewBlock(TIP);
	// Onion messages take a tick, as on any real transport: a reply that
	// landed synchronously would reach the payer before requestInvoice had
	// registered what it is waiting for.
	for (const n of [p, w]) deferOnionSends(n);
	return {
		p,
		s,
		r,
		w,
		wConfig,
		wStorage,
		pConfig,
		sConfig,
		rConfig,
		ps: pw,
		sr,
		pw,
		ws,
		rw,
		psChannelId: pwChannelId,
		pwChannelId,
		wsChannelId,
		scidWS: scid(2),
		srChannelId,
		srHex: srChannelId.toString('hex'),
		errors
	};
}

function deferOnionSends(n: LightningNode): void {
	n.getOnionMessageManager().setSendFunction((to, type, payload) => {
		setImmediate(() => {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(n as any).emitOutbound(to, type, payload);
		});
	});
}

/** The witness hop of the template: W's real forwarding policy on W-S. */
function witnessHop(w: IIssuerWorld): IFforIssuerHop {
	return {
		nodeId: Buffer.from(w.w.getNodeId(), 'hex'),
		shortChannelId: w.scidWS,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		htlcMaximumMsat: 1_000_000_000n
	};
}

interface ISetup {
	offer: IOffer;
	encoded: string;
	mailboxId: Buffer;
}

async function setup(
	w: IIssuerWorld,
	amounts: bigint[],
	offerAmount?: bigint,
	quantityMax?: bigint
): Promise<ISetup> {
	activate(w, { amounts, witnessPeers: [Buffer.from(w.w.getNodeId(), 'hex')] });
	const { mailboxId } = await w.r.provisionFforWitness(
		w.srHex,
		w.w.getNodeId()
	);
	const { offer, encoded } = w.r.createFforIssuerOffer(w.w.getNodeId(), {
		description: 'ffor slots',
		...(offerAmount !== undefined ? { amountMsat: offerAmount } : {}),
		...(quantityMax !== undefined ? { quantityMax } : {})
	});
	expect(offer.issuerId, 'path-terminal: no issuer id').to.equal(undefined);
	const ack = await w.r.provisionFforIssuer(w.srHex, w.w.getNodeId(), {
		offer,
		witnessHops: [witnessHop(w)]
	});
	expect(ack.blindedNodeIds).to.have.length(1);
	expect(
		ack.blindedNodeIds[0].equals(offer.paths![0].blindedHops[0].blindedNodeId)
	).to.be.true;
	w.sr.disconnect();
	for (const l of [w.pw, w.ws, w.sr, w.rw]) l.log.length = 0;
	return { offer, encoded, mailboxId };
}

/** Capture what the issuer replies (invoices and errors) on the wire. */
function tapReplies(w: IIssuerWorld): { invoices: Buffer[]; errors: Buffer[] } {
	const out = { invoices: [] as Buffer[], errors: [] as Buffer[] };
	const om = w.w.getOnionMessageManager();
	const original = om.sendReply.bind(om);
	om.sendReply = ((
		path: IBlindedPath,
		data: Map<number, Buffer>,
		opts?: unknown
	): void => {
		for (const [type, bytes] of data) {
			if (type === 66) out.invoices.push(bytes);
			if (type === 68) out.errors.push(bytes);
		}
		return original(path, data, opts as never);
	}) as typeof om.sendReply;
	return out;
}

function invoiceBytes(inv: IBolt12Invoice): Buffer {
	return encodeInvoiceTlv(inv, inv.records);
}

describe('FFOR BOLT 12 issuer (M9.5, section 9.7)', function () {
	this.timeout(60_000);

	it('a stock payer with only the offer obtains a slot invoice over the path, pays through the witness, and R recovers d_k', async () => {
		const w = createIssuerWorld();
		const { offer, mailboxId } = await setup(w, [G, G, G], G);
		const sRec = record(w.s, w.srHex);
		const invoice = await w.p.getOfferManager().requestInvoice(offer);
		expect(invoice.paymentHash.equals(sRec.paymentHashes[0]), 'slot 1, H_1').to
			.be.true;
		expect(invoice.amount).to.equal(G);
		expect(
			invoice.nodeId.equals(offer.paths![0].blindedHops[0].blindedNodeId),
			'signed under the path terminal'
		).to.be.true;
		expect(invoice.paths![0].introductionNodeId.toString('hex')).to.equal(
			w.w.getNodeId()
		);
		expect(invoice.paths![0].blindedHops, 'W, S, R').to.have.length(3);
		// The attestation verifies under R's node id.
		const att = invoice.records!.find(
			(r) => r.type === FF_ISSUER_ATTESTATION_TLV
		);
		expect(att, 'ffor_issuer_attestation present').to.exist;
		const { hAct, hBook, rAttestation } = decodeAttestationTlvValue(att!.value);
		const rRec = record(w.r, w.srHex);
		expect(hAct.equals(rRec.hAct!)).to.be.true;
		expect(
			verifyAttestation(
				offer.offerId,
				hAct,
				hBook,
				Buffer.from(w.r.getNodeId(), 'hex'),
				rAttestation
			)
		).to.be.true;
		expect(
			w.w.getFforIssuerService()!.issuedSlots(mailboxId.toString('hex'))
		).to.deep.equal([1]);

		// A stock payment over the blinded path: W relays and records, S settles.
		w.p.payBolt12Invoice(invoice);
		await waitFor(
			() =>
				w.p.getPayment(invoice.paymentHash)?.status === PaymentStatus.COMPLETED,
			'the payer to complete'
		);
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.SETTLED);
		expect(w.sr.log, 'S sent R nothing').to.have.length(0);
		expect(
			w.w.getFforWitnessService()!.ledger.listRecords(mailboxId.toString('hex'))
		).to.have.length(1);
		// R returns, fetches, and holds t_1; the issuer's status names the slot.
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(fetched[0].credited).to.equal(1);
		expect(record(w.r, w.srHex).knownPreimages[0]!.equals(sRec.preimages[0])).to
			.be.true;
		const status = await w.r.fetchFforIssuerStatus(w.srHex, w.w.getNodeId());
		expect(status.ok).to.be.true;
		expect(status.slots.map((s) => s.k)).to.deep.equal([1]);
		w.wStorage.close();
	});

	it('identical metadata gets the same invoice byte for byte; different metadata gets the next slot, then the fixed refusal', async () => {
		const w = createIssuerWorld();
		const { offer } = await setup(w, [G, G], G);
		const om = w.w.getOfferManager();
		let captured: { data: Buffer; pathId?: Buffer; bp?: Buffer } | null = null;
		const original = om.handleInvoiceRequest.bind(om);
		om.handleInvoiceRequest = ((
			data: Buffer,
			reply?: IBlindedPath,
			pathId?: Buffer,
			bp?: Buffer
		) => {
			captured = { data, pathId, bp };
			return original(data, reply, pathId, bp);
		}) as typeof om.handleInvoiceRequest;
		const first = await w.p.getOfferManager().requestInvoice(offer);
		expect(captured).to.not.equal(null);
		// The same signed request again (identical invreq_metadata): the same bytes.
		const again = original(
			captured!.data,
			undefined,
			captured!.pathId,
			captured!.bp
		)!;
		expect(
			invoiceBytes(again).equals(invoiceBytes(first)),
			'byte-identical re-answer'
		).to.be.true;
		// A fresh request: the next slot.
		const second = await w.p.getOfferManager().requestInvoice(offer);
		expect(second.paymentHash.equals(record(w.s, w.srHex).paymentHashes[1])).to
			.be.true;
		// The book is exhausted: the one refusal.
		const taps = tapReplies(w);
		let refused: Error | null = null;
		try {
			await w.p.getOfferManager().requestInvoice(offer);
		} catch (err) {
			refused = err as Error;
		}
		expect(refused?.message).to.include(FF_ISSUER_REFUSAL);
		expect(taps.errors).to.have.length(1);
		w.wStorage.close();
	});

	it('every refusal is byte-identical: no matching amount, exhausted, past issue_until, after close', async () => {
		const w = createIssuerWorld();
		const { offer } = await setup(w, [G], undefined);
		const taps = tapReplies(w);
		const attempt = async (amount: bigint): Promise<void> => {
			try {
				await w.p.getOfferManager().requestInvoice(offer, { amount });
			} catch {
				// the refusal is what is under test
			}
		};
		await attempt(G + 1n); // no slot at this amount
		await w.p.getOfferManager().requestInvoice(offer, { amount: G }); // consumes the one slot
		await attempt(G); // exhausted
		w.w.handleNewBlock(D_DEADLINE); // past issue_until (= D by default)
		await attempt(G);
		// A second world for "after close": the witness mailbox closed.
		const w2 = createIssuerWorld();
		const { offer: offer2 } = await setup(w2, [G], undefined);
		const taps2 = tapReplies(w2);
		w2.sr.reconnect();
		expect(w2.r.closeFforEpoch(w2.srHex).ok).to.be.true;
		await w2.r.closeFforWitnesses(w2.srHex);
		try {
			await w2.p.getOfferManager().requestInvoice(offer2, { amount: G });
		} catch {
			// refused
		}
		const all = [...taps.errors, ...taps2.errors];
		expect(all).to.have.length(4);
		for (const e of all) {
			expect(e.equals(all[0]), 'byte-identical refusals').to.be.true;
			expect(decodeInvoiceErrorTlv(e).error).to.equal(FF_ISSUER_REFUSAL);
		}
		w.wStorage.close();
		w2.wStorage.close();
	});

	it('a crash between the mark and the send does not issue the slot twice: the restart re-answers the same slot', async () => {
		const w = createIssuerWorld();
		const { offer, mailboxId } = await setup(w, [G, G], G);
		const om = w.w.getOnionMessageManager();
		const original = om.sendReply.bind(om);
		let captured: { data: Buffer; pathId?: Buffer; bp?: Buffer } | null = null;
		const hir = w.w
			.getOfferManager()
			.handleInvoiceRequest.bind(w.w.getOfferManager());
		w.w.getOfferManager().handleInvoiceRequest = ((
			data: Buffer,
			reply?: IBlindedPath,
			pathId?: Buffer,
			bp?: Buffer
		) => {
			captured = { data, pathId, bp };
			return hir(data, reply, pathId, bp);
		}) as typeof om.sendReply extends never ? never : typeof hir;
		// The issuer marks the slot, stores the bytes, and dies before sending.
		om.sendReply = ((): void => {
			throw new Error('process died before the reply left');
		}) as typeof om.sendReply;
		const pending = w.p
			.getOfferManager()
			.requestInvoice(offer)
			.catch((e: Error) => e);
		await sleep(50);
		expect(
			w.w.getFforIssuerService()!.issuedSlots(mailboxId.toString('hex'))
		).to.deep.equal([1]);
		om.sendReply = original;
		// The issuer restarts over its database.
		for (const l of [w.pw, w.ws, w.rw]) l.connected = false;
		const w2 = new LightningNode(w.wConfig);
		w2.on('node:error', () => {});
		w2.handleNewBlock(TIP);
		expect(
			w2.getFforIssuerService()!.issuedSlots(mailboxId.toString('hex')),
			'rehydrated'
		).to.deep.equal([1]);
		// The payer retries with the identical request: the same slot, no second issuance.
		const invoice = w2
			.getOfferManager()
			.handleInvoiceRequest(
				captured!.data,
				undefined,
				captured!.pathId,
				captured!.bp
			)!;
		expect(invoice.paymentHash.equals(record(w.s, w.srHex).paymentHashes[0])).to
			.be.true;
		expect(
			w2.getFforIssuerService()!.issuedSlots(mailboxId.toString('hex'))
		).to.deep.equal([1]);
		void pending;
		w.wStorage.close();
	});

	it('a slot grid: quantity selects the exact slot, and a request with no matching amount is refused', async () => {
		const w = createIssuerWorld();
		const { offer } = await setup(w, [G, 2n * G, 3n * G], G, 3n);
		const two = await w.p
			.getOfferManager()
			.requestInvoice(offer, { quantity: 2n });
		expect(two.amount).to.equal(2n * G);
		expect(two.paymentHash.equals(record(w.s, w.srHex).paymentHashes[1])).to.be
			.true;
		let refused: Error | null = null;
		try {
			await w.p.getOfferManager().requestInvoice(offer, { amount: 5n * G });
		} catch (err) {
			refused = err as Error;
		}
		expect(refused?.message).to.include(FF_ISSUER_REFUSAL);
		w.wStorage.close();
	});
});

export const unusedCrypto = crypto;
