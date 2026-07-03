/**
 * FFOR M7.4: tower service gossip advertising + discovery.
 *
 * - Codec: IFforTowerTerms (node_ann_tlvs 55043) round-trips through
 *   encode/decodeFforTowerTerms and through a full node_announcement carrying
 *   BOTH the FFOR standing-terms TLV (55007) and the tower-terms TLV (55043)
 *   plus an address, alongside lease_rates (type 1). TLV order stays ascending.
 * - Discovery: NetworkGraph.getTowerNodes() surfaces every node whose
 *   node_announcement advertised tower terms, with the dial address taken from
 *   the SAME announcement; the variant/budget filter works.
 * - End-to-end GATE: a tower node T advertises tower-terms + its address in its
 *   node_announcement; that announcement reaches recipient R's NetworkGraph as
 *   gossip would; R.findTowers() sees T with terms + address; R adopts it with
 *   useDiscoveredTower(towerNodeId) (NO out-of-band URI); R runs the M7.3
 *   offline-receive flow: provisions T, goes offline, P pays, S settles via the
 *   discovered tower over real BOLT-8 while R is offline, R recovers.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { SqliteTowerStore } from '../../src/lightning/ffor/tower-store-sqlite';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelState } from '../../src/lightning/channel/types';
import { Network } from '../../src/lightning/invoice/types';
import { REGTEST_CHAIN_HASH } from '../../src/lightning/channel/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../src/lightning/keys/wallet-keys';
import {
	encodeFforTowerTerms,
	decodeFforTowerTerms,
	IFforTowerTerms,
	INodeAnnouncementMessage
} from '../../src/lightning/gossip/types';
import {
	encodeNodeAnnouncementMessage,
	decodeNodeAnnouncementMessage
} from '../../src/lightning/gossip/messages';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();
const TEST_MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function tmpDir(tag: string): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), `ffor-m74-${tag}-`));
}

// ─────────────── Codec round-trip ───────────────

describe('FFOR M7.4: tower-terms TLV (55043) codec', function () {
	const terms: IFforTowerTerms = {
		towerFeeBaseMsat: 1000,
		towerFeePpm: 250,
		maxBudgetMsat: 123_456_789n,
		maxEpochBlocks: 4032,
		variants: 0b10
	};

	it('encodeFforTowerTerms produces a fixed 19-byte record', function () {
		const buf = encodeFforTowerTerms(terms);
		expect(buf.length).to.equal(19);
	});

	it('round-trips through encode/decode', function () {
		const out = decodeFforTowerTerms(encodeFforTowerTerms(terms));
		expect(out.towerFeeBaseMsat).to.equal(terms.towerFeeBaseMsat);
		expect(out.towerFeePpm).to.equal(terms.towerFeePpm);
		expect(out.maxBudgetMsat).to.equal(terms.maxBudgetMsat);
		expect(out.maxEpochBlocks).to.equal(terms.maxEpochBlocks);
		expect(out.variants).to.equal(terms.variants);
	});

	it('node_announcement round-trips with BOTH TLVs (55007 + 55043) + address', function () {
		const msg: INodeAnnouncementMessage = {
			signature: Buffer.alloc(64),
			features: Buffer.alloc(0),
			timestamp: 1_700_000_000,
			nodeId: Buffer.alloc(33, 0x02),
			rgbColor: Buffer.from([1, 2, 3]),
			alias: Buffer.alloc(32),
			addresses: [{ type: 1, host: '203.0.113.7', port: 9736 }],
			leaseRates: {
				fundingWeightWitness: 720,
				leaseFeeBasis: 50,
				leaseFeeBaseSat: 500,
				channelFeeMaxBaseMsat: 100,
				channelFeeMaxProportionalThousandths: 10
			},
			fforTerms: {
				ffFeeBaseMsat: 2000,
				ffFeePpm: 300,
				maxBudgetMsat: 50_000_000n,
				maxEpochBlocks: 2016,
				variants: 0b11
			},
			fforTowerTerms: terms
		};
		const decoded = decodeNodeAnnouncementMessage(
			encodeNodeAnnouncementMessage(msg)
		);
		// FFOR standing terms (55007) preserved.
		expect(decoded.fforTerms?.maxBudgetMsat).to.equal(50_000_000n);
		// FFOR tower terms (55043) preserved.
		expect(decoded.fforTowerTerms?.towerFeeBaseMsat).to.equal(1000);
		expect(decoded.fforTowerTerms?.towerFeePpm).to.equal(250);
		expect(decoded.fforTowerTerms?.maxBudgetMsat).to.equal(123_456_789n);
		expect(decoded.fforTowerTerms?.maxEpochBlocks).to.equal(4032);
		expect(decoded.fforTowerTerms?.variants).to.equal(0b10);
		// Address preserved (the dial address that makes the tower reachable).
		expect(decoded.addresses[0].host).to.equal('203.0.113.7');
		expect(decoded.addresses[0].port).to.equal(9736);
		// Lease rates (type 1) preserved alongside.
		expect(decoded.leaseRates?.leaseFeeBaseSat).to.equal(500);
	});
});

// ─────────────── NetworkGraph.getTowerNodes ───────────────

function makeNode(seedId: number): LightningNode {
	const keys = deriveLightningKeysFromMnemonic(
		TEST_MNEMONIC,
		`ffor-m74-${seedId}`,
		LnCoinType.REGTEST
	);
	const features = FeatureFlags.empty();
	features.setOptional(Feature.STATIC_REMOTE_KEY);
	features.setOptional(Feature.PAYMENT_SECRET);
	features.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
	features.setOptional(Feature.QUIESCE);
	features.setOptional(Feature.OPTION_FF_RECEIVE);
	return new LightningNode({
		nodePrivateKey: keys.nodePrivateKey,
		channelBasepoints: keys.channelBasepoints,
		perCommitmentSeed: keys.perCommitmentSeed,
		fundingPrivkey: keys.fundingPrivkey,
		htlcBasepointSecret: keys.htlcBasepointSecret,
		revocationBasepointSecret: keys.revocationBasepointSecret,
		paymentBasepointSecret: keys.paymentBasepointSecret,
		delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
		network: Network.REGTEST,
		enableNetworking: true,
		localFeatures: features,
		chainHashes: [REGTEST_CHAIN_HASH],
		preferAnchors: true
	});
}

const sleep = (ms = 20): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function listenEphemeral(node: LightningNode): Promise<number> {
	await node.listen(0);
	const pm = node.getPeerManager()!;
	const server = (pm as unknown as { server: { address(): { port: number } } })
		.server;
	return server.address().port;
}

async function openChannelBolt8(
	opener: LightningNode,
	acceptor: LightningNode
): Promise<Buffer> {
	const om = opener.getChannelManager();
	const am = acceptor.getChannelManager();
	const ch = om.openChannel(acceptor.getNodeId(), 1_000_000n);
	await sleep(300);
	om.createFunding(ch, crypto.randomBytes(32), 0, crypto.randomBytes(64));
	await sleep(300);
	const id = ch.getChannelId()!;
	om.handleFundingConfirmed(id);
	const ach = am
		.getChannelsByPeer(opener.getNodeId())
		.find((c) => c.getChannelId()?.equals(id))!;
	am.handleFundingConfirmed(ach.getChannelId()!);
	await sleep(100);
	expect(ch.getState(), 'opener channel NORMAL').to.equal(ChannelState.NORMAL);
	return id;
}

/**
 * Inject `announcer`'s real node_announcement into `receiver`'s NetworkGraph as
 * gossip would deliver it: give the announcer a channel (node_announcement is
 * rejected for a node with zero channels), then decode the announcer's own
 * buildNodeAnnouncement bytes and applyNodeAnnouncement. Returns the decoded
 * message so the caller can assert the wire round-trip.
 */
function gossipAnnouncementInto(
	receiver: LightningNode,
	announcer: LightningNode,
	timestamp: number
): INodeAnnouncementMessage {
	const graph = receiver.getGraph();
	const announcerPub = Buffer.from(announcer.getNodeId(), 'hex');
	// Synthetic BITCOIN channel_announcement so the announcer has >= 1 channel.
	const other = crypto.randomBytes(33);
	other[0] = 0x02;
	const [n1, n2] =
		Buffer.compare(announcerPub, other) < 0
			? [announcerPub, other]
			: [other, announcerPub];
	graph.addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: crypto.randomBytes(8),
		nodeId1: n1,
		nodeId2: n2,
		bitcoinKey1: crypto.randomBytes(33),
		bitcoinKey2: crypto.randomBytes(33)
	});
	// The announcer's OWN node_announcement wire bytes (built from its advertised
	// config), decoded exactly as a receiving peer would.
	const payload = (
		announcer as unknown as {
			buildNodeAnnouncement(ts: number): Buffer | null;
		}
	).buildNodeAnnouncement(timestamp)!;
	const msg = decodeNodeAnnouncementMessage(payload);
	const applied = graph.applyNodeAnnouncement(msg);
	expect(applied, 'node_announcement applied to graph').to.equal(true);
	return msg;
}

describe('FFOR M7.4: NetworkGraph.getTowerNodes discovery', function () {
	it('surfaces advertised tower terms + address and filters by variant/budget', async function () {
		const R = makeNode(90);
		const T = makeNode(91);
		try {
			// T advertises variant-B tower terms + its dial address.
			T.enableTower(new SqliteTowerStore(':memory:'), {
				terms: {
					towerFeeBaseMsat: 1000,
					towerFeePpm: 0,
					maxBudgetMsat: 100_000_000n,
					maxEpochBlocks: 4032,
					variants: 0b10
				},
				address: { type: 1, host: '198.51.100.9', port: 9999 }
			});
			gossipAnnouncementInto(R, T, 1_700_000_100);

			const found = R.findTowers();
			expect(found.length).to.equal(1);
			expect(found[0].nodeId.toString('hex')).to.equal(T.getNodeId());
			expect(found[0].address?.host).to.equal('198.51.100.9');
			expect(found[0].address?.port).to.equal(9999);
			expect(found[0].terms.variants).to.equal(0b10);

			// Filter: variant A (bit 0) excludes a variant-B-only tower.
			expect(R.findTowers({ variant: 0b01 }).length).to.equal(0);
			// Filter: variant B (bit 1) includes it.
			expect(R.findTowers({ variant: 0b10 }).length).to.equal(1);
			// Filter: budget beyond the advertised max excludes it.
			expect(R.findTowers({ minBudgetMsat: 200_000_000n }).length).to.equal(0);
			// Filter: budget within the advertised max includes it.
			expect(R.findTowers({ minBudgetMsat: 50_000_000n }).length).to.equal(1);
		} finally {
			await R.destroy();
			await T.destroy();
		}
	});
});

// ─────────────── End-to-end gate ───────────────

describe('FFOR M7.4 GATE: discover a tower from gossip, then offline-receive through it', function () {
	this.timeout(40_000);

	it('R discovers T via findTowers/useDiscoveredTower (no URI) then completes the M7.3 flow', async function () {
		const dbDir = tmpDir('gate');
		const P = makeNode(11);
		const S = makeNode(12);
		const R = makeNode(13);
		const T = makeNode(14);
		const sPub = S.getNodeId();
		const tPub = T.getNodeId();
		const pm = P.getChannelManager();
		const sm = S.getChannelManager();
		const rm = R.getChannelManager();
		[P, S, R, T].forEach((n) => n.on('node:error', () => {}));
		[pm, sm, rm].forEach((m) => m.on('error', () => {}));
		const pFulfilled: Buffer[] = [];
		pm.on('htlc:fulfilled', (_c, _id, preimage: Buffer) =>
			pFulfilled.push(preimage)
		);

		try {
			// ── T: durable embedded tower + advertise its tower service. ──
			const tPort = await listenEphemeral(T);
			const sPort = await listenEphemeral(S);
			await listenEphemeral(R);
			await listenEphemeral(P);
			T.enableTower(new SqliteTowerStore(path.join(dbDir, 'tower.db')), {
				terms: {
					towerFeeBaseMsat: 1000,
					towerFeePpm: 0,
					maxBudgetMsat: 100_000_000n,
					maxEpochBlocks: 4032,
					variants: 0b10
				},
				address: { type: 1, host: '127.0.0.1', port: tPort }
			});

			// ── T's node_announcement reaches R's graph as gossip would. ──
			const wire = gossipAnnouncementInto(R, T, 1_700_000_200);
			// The advertised terms + address survived the gossip encode/decode.
			expect(wire.fforTowerTerms?.variants).to.equal(0b10);
			expect(wire.addresses[0].port).to.equal(tPort);

			// ── R DISCOVERS the tower from gossip (no out-of-band URI). ──
			const towers = R.findTowers({ variant: 0b10, minBudgetMsat: 1_000_000n });
			expect(towers.length, 'R discovered T from gossip').to.equal(1);
			expect(towers[0].nodeId.toString('hex')).to.equal(tPub);
			R.useDiscoveredTower(tPub);

			// Peer connections + channels: P->S (payer), S->R (recipient).
			await P.connectPeer(sPub, '127.0.0.1', sPort);
			await R.connectPeer(sPub, '127.0.0.1', sPort);
			await sleep(300);
			const psId = await openChannelBolt8(P, S);
			const srId = await openChannelBolt8(S, R);
			const rChannel = rm
				.getChannelsByPeer(sPub)
				.find((c) => c.getChannelId()?.equals(srId))!;

			// ── R provisions the DISCOVERED tower up-front, then goes offline. ──
			const epoch = await R.startOfflineReceiveEpoch({
				channelId: srId,
				budgetMsat: 100_000_000n,
				maxPayments: 2,
				minPaymentMsat: 500_000n,
				settlementDeadline: 1000,
				voucherExpiry: 2008
			});
			await sleep(200);
			expect(epoch.invoices.length).to.equal(2);
			expect(
				sm.hasFforTowerClient(),
				'S auto-resolved the tower from ff_init'
			).to.equal(true);
			expect(T.towerStatus().epochs.length).to.equal(1);

			R.disconnectPeer(sPub);
			await sleep(200);

			// ── P pays; S settles via the discovered tower while R offline. ──
			pm.addHtlc(
				psId,
				1_000_000n,
				epoch.paymentHashes[0],
				900,
				Buffer.alloc(1366)
			);
			await sleep(1500);

			expect(pFulfilled.length, 'payment completed while R offline').to.equal(
				1
			);
			expect(sha256(pFulfilled[0]).equals(epoch.paymentHashes[0])).to.equal(
				true
			);
			expect(
				S.getPeerManager()!.getPeer(tPub) !== undefined,
				'S dialed the discovered tower over BOLT-8'
			).to.equal(true);
			expect(T.towerStatus().epochs[0].lastReleased).to.equal(1);

			// ── R returns and recovers from the discovered tower. ──
			await R.connectPeer(sPub, '127.0.0.1', sPort);
			await sleep(300);
			const rec = await R.recoverFromTower(srId);
			expect(rec.ok, rec.error).to.equal(true);
			const rEpoch = rChannel.getFforEpoch()!;
			expect(rEpoch.lastSeq, 'R ingested the settled package').to.equal(1);
			expect(
				sha256(rEpoch.preimages[0]).equals(epoch.paymentHashes[0]),
				'R holds the voucher preimage fetched from the discovered tower'
			).to.equal(true);
		} finally {
			await P.destroy();
			await S.destroy();
			await R.destroy();
			await T.destroy();
			fs.rmSync(dbDir, { recursive: true, force: true });
		}
	});
});
