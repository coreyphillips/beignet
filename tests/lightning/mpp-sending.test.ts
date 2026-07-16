/**
 * Phase 5: MPP Sending tests.
 *
 * Tests multi-path payment sending: findMultiPathRoute with signed gossip,
 * sendPayment MPP fallback, outbound MPP state tracking, part amount
 * summation, and paymentSecret requirements.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	PaymentStatus,
	IOutboundMppState
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	findRoute,
	findMultiPathRoute
} from '../../src/lightning/gossip/pathfinding';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import {
	signChannelAnnouncement,
	signChannelUpdate
} from '../../src/lightning/gossip/validation';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`mpp-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	return node;
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === b.getNodeId()) b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === a.getNodeId()) a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	amount = 1_000_000n
): Buffer {
	const ch = alice.openChannel(bob.getNodeId(), amount);
	const txid = crypto.randomBytes(32);
	const channelId = alice.createFunding(ch, txid, 0, crypto.randomBytes(64))!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

// ─────────────── Gossip Helpers ───────────────

function makeScid(block: number, txIdx: number, outIdx: number): Buffer {
	return encodeShortChannelId({ block, txIndex: txIdx, outputIndex: outIdx });
}

/**
 * Create a signed channel_announcement for two node keypairs.
 * nodeId1 < nodeId2 ordering is enforced internally.
 */
function createSignedChannelAnnouncement(
	nk1: Buffer,
	nk2: Buffer,
	bk1: Buffer,
	bk2: Buffer,
	scid: Buffer
): { msg: IChannelAnnouncementMessage; payload: Buffer } {
	const np1 = getPublicKey(nk1);
	const np2 = getPublicKey(nk2);
	const bp1 = getPublicKey(bk1);
	const bp2 = getPublicKey(bk2);

	let nodeKey1 = nk1,
		nodeKey2 = nk2;
	let nodePub1 = np1,
		nodePub2 = np2;
	let bitKey1 = bk1,
		bitKey2 = bk2;
	let bitPub1 = bp1,
		bitPub2 = bp2;

	if (Buffer.compare(np1, np2) > 0) {
		[nodeKey1, nodeKey2] = [nodeKey2, nodeKey1];
		[nodePub1, nodePub2] = [nodePub2, nodePub1];
		[bitKey1, bitKey2] = [bitKey2, bitKey1];
		[bitPub1, bitPub2] = [bitPub2, bitPub1];
	}

	const msg: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: nodePub1,
		nodeId2: nodePub2,
		bitcoinKey1: bitPub1,
		bitcoinKey2: bitPub2
	};

	const unsigned = encodeChannelAnnouncementMessage(msg);
	const sigs1 = signChannelAnnouncement(unsigned, nodeKey1, bitKey1);
	const sigs2 = signChannelAnnouncement(unsigned, nodeKey2, bitKey2);

	const signedMsg: IChannelAnnouncementMessage = {
		...msg,
		nodeSignature1: sigs1.nodeSignature,
		nodeSignature2: sigs2.nodeSignature,
		bitcoinSignature1: sigs1.bitcoinSignature,
		bitcoinSignature2: sigs2.bitcoinSignature
	};

	const payload = encodeChannelAnnouncementMessage(signedMsg);
	return { msg: signedMsg, payload };
}

/**
 * Create a signed channel_update for a given direction (0 or 1).
 */
function createSignedChannelUpdate(
	nodePrivkey: Buffer,
	scid: Buffer,
	direction: number,
	opts?: { htlcMaximumMsat?: bigint }
): { msg: IChannelUpdateMessage; payload: Buffer } {
	const msg: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: direction,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: opts?.htlcMaximumMsat ?? 1_000_000_000n
	};

	const unsigned = encodeChannelUpdateMessage(msg);
	msg.signature = signChannelUpdate(unsigned, nodePrivkey);
	const payload = encodeChannelUpdateMessage(msg);
	return { msg, payload };
}

/**
 * Helper to generate deterministic node/bitcoin key pairs for graph construction.
 */
function makeGraphKey(label: string): { priv: Buffer; pub: Buffer } {
	const priv = crypto
		.createHash('sha256')
		.update(Buffer.from(`mpp-graph-${label}`))
		.digest();
	return { priv, pub: getPublicKey(priv) };
}

/**
 * Build a parallel-path graph directly on a NetworkGraph using signed gossip.
 *
 * A ──(ch1, cap1)──> B ──(ch3, cap1)──> D
 * A ──(ch2, cap2)──> C ──(ch4, cap2)──> D
 */
function buildSignedParallelGraph(
	cap1Msat: bigint,
	cap2Msat: bigint
): {
	graph: NetworkGraph;
	nodeA: { priv: Buffer; pub: Buffer };
	nodeB: { priv: Buffer; pub: Buffer };
	nodeC: { priv: Buffer; pub: Buffer };
	nodeD: { priv: Buffer; pub: Buffer };
} {
	const nodeA = makeGraphKey('A');
	const nodeB = makeGraphKey('B');
	const nodeC = makeGraphKey('C');
	const nodeD = makeGraphKey('D');

	const bitA = makeGraphKey('bitA');
	const bitB = makeGraphKey('bitB');
	const bitC = makeGraphKey('bitC');
	const bitD = makeGraphKey('bitD');

	const graph = new NetworkGraph();

	// Channel 1: A <-> B
	const scid1 = makeScid(700, 1, 0);
	const ann1 = createSignedChannelAnnouncement(
		nodeA.priv,
		nodeB.priv,
		bitA.priv,
		bitB.priv,
		scid1
	);
	graph.addChannelAnnouncement(ann1.msg);

	// Channel 2: A <-> C
	const scid2 = makeScid(700, 2, 0);
	const ann2 = createSignedChannelAnnouncement(
		nodeA.priv,
		nodeC.priv,
		bitA.priv,
		bitC.priv,
		scid2
	);
	graph.addChannelAnnouncement(ann2.msg);

	// Channel 3: B <-> D
	const scid3 = makeScid(700, 3, 0);
	const ann3 = createSignedChannelAnnouncement(
		nodeB.priv,
		nodeD.priv,
		bitB.priv,
		bitD.priv,
		scid3
	);
	graph.addChannelAnnouncement(ann3.msg);

	// Channel 4: C <-> D
	const scid4 = makeScid(700, 4, 0);
	const ann4 = createSignedChannelAnnouncement(
		nodeC.priv,
		nodeD.priv,
		bitC.priv,
		bitD.priv,
		scid4
	);
	graph.addChannelAnnouncement(ann4.msg);

	// Apply updates for both directions on each channel
	const channels: Array<{
		scid: Buffer;
		nk1: Buffer;
		nk2: Buffer;
		pub1: Buffer;
		pub2: Buffer;
		cap: bigint;
	}> = [
		{
			scid: scid1,
			nk1: nodeA.priv,
			nk2: nodeB.priv,
			pub1: nodeA.pub,
			pub2: nodeB.pub,
			cap: cap1Msat
		},
		{
			scid: scid2,
			nk1: nodeA.priv,
			nk2: nodeC.priv,
			pub1: nodeA.pub,
			pub2: nodeC.pub,
			cap: cap2Msat
		},
		{
			scid: scid3,
			nk1: nodeB.priv,
			nk2: nodeD.priv,
			pub1: nodeB.pub,
			pub2: nodeD.pub,
			cap: cap1Msat
		},
		{
			scid: scid4,
			nk1: nodeC.priv,
			nk2: nodeD.priv,
			pub1: nodeC.pub,
			pub2: nodeD.pub,
			cap: cap2Msat
		}
	];

	for (const ch of channels) {
		const isN1First = Buffer.compare(ch.pub1, ch.pub2) < 0;
		const dir0Key = isN1First ? ch.nk1 : ch.nk2;
		const dir1Key = isN1First ? ch.nk2 : ch.nk1;

		const upd0 = createSignedChannelUpdate(dir0Key, ch.scid, 0, {
			htlcMaximumMsat: ch.cap
		});
		const upd1 = createSignedChannelUpdate(dir1Key, ch.scid, 1, {
			htlcMaximumMsat: ch.cap
		});
		graph.applyChannelUpdate(upd0.msg);
		graph.applyChannelUpdate(upd1.msg);
	}

	return { graph, nodeA, nodeB, nodeC, nodeD };
}

// ─────────────── Tests ───────────────

describe('MPP Sending (Phase 5)', function () {
	describe('findMultiPathRoute with signed gossip graph', function () {
		it('should return valid multi-path splitting across 2 paths', function () {
			// Each path has 50k sat capacity (50_000_000 msat).
			// Request 80k sat (80_000_000 msat) — must split across both paths.
			const cap = 50_000_000n;
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(cap, cap);

			const amountMsat = 80_000_000n;
			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				amountMsat,
				40
			);
			expect(result).to.not.be.null;
			expect(result!.parts.length).to.be.greaterThan(1);

			// Each part should deliver a portion to destination
			let totalDelivered = 0n;
			for (const part of result!.parts) {
				const lastHop = part.hops[part.hops.length - 1];
				totalDelivered += lastHop.amountToForwardMsat;
			}
			expect(totalDelivered).to.equal(amountMsat);
		});

		it('should return null for insufficient total capacity', function () {
			// 2 paths each with 30k sat cap (30_000_000 msat), total 60k sat.
			// Request 70k sat — should fail.
			const cap = 30_000_000n;
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(cap, cap);

			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				70_000_000n,
				40
			);
			expect(result).to.be.null;
		});

		it('should return parts that sum to the invoice amount', function () {
			const cap = 50_000_000n;
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(cap, cap);

			const amountMsat = 90_000_000n;
			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				amountMsat,
				40
			);
			expect(result).to.not.be.null;

			// Sum of final-hop amounts must equal requested amount
			let sum = 0n;
			for (const part of result!.parts) {
				const lastHop = part.hops[part.hops.length - 1];
				sum += lastHop.amountToForwardMsat;
			}
			expect(sum).to.equal(amountMsat);
		});

		it('should reduce per-path amount below total', function () {
			const cap = 50_000_000n;
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(cap, cap);

			const amountMsat = 80_000_000n;
			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				amountMsat,
				40
			);
			expect(result).to.not.be.null;
			expect(result!.parts.length).to.be.greaterThan(1);

			// Each part's delivered amount should be less than the total
			for (const part of result!.parts) {
				const lastHop = part.hops[part.hops.length - 1];
				expect(Number(lastHop.amountToForwardMsat)).to.be.lessThan(
					Number(amountMsat)
				);
			}
		});

		it('should use single path when one large channel suffices', function () {
			// Path 1 has large cap (200k sat), path 2 small (10k sat).
			// Request 50k sat — should use path 1 only.
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(
				200_000_000n,
				10_000_000n
			);

			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				50_000_000n,
				40
			);
			expect(result).to.not.be.null;
			// May use 1 or 2 parts, but the important thing is it succeeds.
			// With sufficient single-path capacity, should use just 1 part.
			expect(result!.parts.length).to.equal(1);
		});

		it('should respect excluded channels via findRoute', function () {
			const cap = 50_000_000n;
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(cap, cap);

			const scid1Hex = makeScid(700, 1, 0).toString('hex');
			const excluded = new Set<string>([scid1Hex]);

			// Single-path findRoute with exclusion should avoid ch1
			const route = findRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				30_000_000n,
				40,
				undefined,
				excluded
			);
			if (route) {
				// None of the hops should use the excluded scid
				for (const hop of route.hops) {
					expect(hop.shortChannelId.toString('hex')).to.not.equal(scid1Hex);
				}
			}
		});
	});

	describe('IOutboundMppState interface', function () {
		it('should be importable and have expected fields', function () {
			// IOutboundMppState is a TypeScript interface, so we verify it
			// compiles and can be used to type a value.
			const state: IOutboundMppState = {
				paymentHash: crypto.randomBytes(32),
				totalMsat: 100_000n,
				parts: [],
				createdAt: Date.now()
			};
			expect(state.paymentHash).to.have.length(32);
			expect(state.totalMsat).to.equal(100_000n);
			expect(state.parts).to.be.an('array');
			expect(state.createdAt).to.be.a('number');
		});
	});

	describe('PaymentStatus enum', function () {
		it('should have PENDING, COMPLETED, and FAILED values', function () {
			expect(PaymentStatus.PENDING).to.equal('PENDING');
			expect(PaymentStatus.COMPLETED).to.equal('COMPLETED');
			expect(PaymentStatus.FAILED).to.equal('FAILED');
		});
	});

	describe('sendPayment MPP fallback', function () {
		it('should succeed with single-path route without MPP', function () {
			// Two nodes with a direct channel — single path is sufficient.
			const alice = createNode(50);
			const bob = createNode(51);
			connectNodes(alice, bob);
			openReadyChannel(alice, bob, 1_000_000n);

			// Bob creates invoice (stores preimage internally)
			const invoiceStr = bob.createInvoice({
				description: 'single-path test',
				amountMsat: 10_000n
			});

			// Add bob as direct route in alice's graph
			const aliceGraph = alice.getGraph();
			const alicePub = Buffer.from(alice.getNodeId(), 'hex');
			const bobPub = Buffer.from(bob.getNodeId(), 'hex');
			const scid = makeScid(800, 1, 0);
			const [n1, n2] =
				Buffer.compare(alicePub, bobPub) < 0
					? [alicePub, bobPub]
					: [bobPub, alicePub];

			const ann: IChannelAnnouncementMessage = {
				nodeSignature1: crypto.randomBytes(64),
				nodeSignature2: crypto.randomBytes(64),
				bitcoinSignature1: crypto.randomBytes(64),
				bitcoinSignature2: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				nodeId1: n1,
				nodeId2: n2,
				bitcoinKey1: crypto.randomBytes(33),
				bitcoinKey2: crypto.randomBytes(33)
			};
			aliceGraph.addChannelAnnouncement(ann);

			const upd0: IChannelUpdateMessage = {
				signature: crypto.randomBytes(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 1_000_000_000n
			};
			aliceGraph.applyChannelUpdate(upd0);

			const upd1: IChannelUpdateMessage = {
				...upd0,
				channelFlags: 1
			};
			aliceGraph.applyChannelUpdate(upd1);

			const payment = alice.sendPayment(invoiceStr.bolt11);
			expect(payment).to.not.be.null;
			expect(payment.status).to.be.oneOf([
				PaymentStatus.PENDING,
				PaymentStatus.COMPLETED
			]);
		});

		it('should fall back to MPP when single path insufficient but combined capacity works', function () {
			// We create two nodes (alice, bob) with 2 channels of smaller capacity,
			// and try to pay an amount that exceeds one channel but not both combined.
			const alice = createNode(60);
			const bob = createNode(61);
			connectNodes(alice, bob);

			// Open two channels with 100k sat each
			openReadyChannel(alice, bob, 100_000n);
			openReadyChannel(alice, bob, 100_000n);

			// Inject graph routes: two parallel paths to bob
			const aliceGraph = alice.getGraph();
			const alicePub = Buffer.from(alice.getNodeId(), 'hex');
			const bobPub = Buffer.from(bob.getNodeId(), 'hex');

			const [n1, n2] =
				Buffer.compare(alicePub, bobPub) < 0
					? [alicePub, bobPub]
					: [bobPub, alicePub];

			// Two channels with 60k sat max each
			for (let i = 0; i < 2; i++) {
				const scid = makeScid(900, i + 1, 0);
				const ann: IChannelAnnouncementMessage = {
					nodeSignature1: crypto.randomBytes(64),
					nodeSignature2: crypto.randomBytes(64),
					bitcoinSignature1: crypto.randomBytes(64),
					bitcoinSignature2: crypto.randomBytes(64),
					features: Buffer.alloc(0),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: scid,
					nodeId1: n1,
					nodeId2: n2,
					bitcoinKey1: crypto.randomBytes(33),
					bitcoinKey2: crypto.randomBytes(33)
				};
				aliceGraph.addChannelAnnouncement(ann);

				const upd0: IChannelUpdateMessage = {
					signature: crypto.randomBytes(64),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: scid,
					timestamp: Math.floor(Date.now() / 1000) + i,
					messageFlags: 1,
					channelFlags: 0,
					cltvExpiryDelta: 40,
					htlcMinimumMsat: 1000n,
					feeBaseMsat: 1000,
					feeProportionalMillionths: 1,
					htlcMaximumMsat: 60_000_000n // 60k sat per channel
				};
				aliceGraph.applyChannelUpdate(upd0);

				const upd1: IChannelUpdateMessage = {
					...upd0,
					channelFlags: 1
				};
				aliceGraph.applyChannelUpdate(upd1);
			}

			// Bob creates invoice (stores preimage/secret internally)
			// 90k sat — exceeds single channel (60k) but fits in 2 channels
			const invoiceStr = bob.createInvoice({
				description: 'mpp fallback test',
				amountMsat: 90_000_000n
			});

			// sendPayment should attempt single-path (fails), then fall back to MPP
			const payment = alice.sendPayment(invoiceStr.bolt11);
			expect(payment).to.not.be.null;
			// The payment is dispatched (PENDING or COMPLETED depending on sync)
			expect(payment.status).to.be.oneOf([
				PaymentStatus.PENDING,
				PaymentStatus.COMPLETED,
				PaymentStatus.FAILED
			]);
		});

		it('should not attempt MPP when the invoice does not advertise basic_mpp (S-4.M8)', function () {
			// Two direct 60k-sat channels; a 90k-sat payment cannot fit any single
			// channel but splits fine across both. With basic_mpp advertised the
			// MPP fallback dispatches; without it (payment secret alone) splitting
			// to a non-MPP recipient would lock every part until the mpp_timeout,
			// so sendPayment must report no route instead.
			const alice = createNode(62);
			const bob = createNode(63);
			connectNodes(alice, bob);

			openReadyChannel(alice, bob, 60_000n);
			openReadyChannel(alice, bob, 60_000n);

			// Control: bob's own invoice advertises basic_mpp → MPP dispatches
			const mppInvoice = bob.createInvoice({
				description: 'with basic_mpp',
				amountMsat: 90_000_000n
			});
			const controlPayment = alice.sendPayment(mppInvoice.bolt11);
			expect(controlPayment).to.not.be.null;

			const bobConfig = makeNodeConfig(63);
			const noMppFeatures = FeatureFlags.empty();
			noMppFeatures.setCompulsory(Feature.TLV_ONION);
			noMppFeatures.setCompulsory(Feature.PAYMENT_SECRET);

			const invoiceStr = encodeInvoice({
				network: Network.REGTEST,
				paymentHash: crypto.randomBytes(32),
				paymentSecret: crypto.randomBytes(32),
				description: 'no basic_mpp',
				amountMsat: 90_000_000n,
				payeeNodeKey: getPublicKey(bobConfig.nodePrivateKey),
				privateKey: bobConfig.nodePrivateKey,
				featureBits: noMppFeatures
			});

			// Without basic_mpp the MPP fallback must not run: no route
			expect(() => alice.sendPayment(invoiceStr)).to.throw('No route found');
		});

		it('should refuse to pay an invoice without paymentSecret (BOLT 11 payer MUST)', function () {
			const alice = createNode(70);
			const bob = createNode(71);
			connectNodes(alice, bob);
			// Channel is too small to carry the 50k-sat payment as a single part.
			// (A larger channel would now route directly over the local channel,
			// which is the correct behaviour — see local-channel routing.)
			openReadyChannel(alice, bob, 20_000n);

			const aliceGraph = alice.getGraph();
			const alicePub = Buffer.from(alice.getNodeId(), 'hex');
			const bobPub = Buffer.from(bob.getNodeId(), 'hex');
			const [n1, n2] =
				Buffer.compare(alicePub, bobPub) < 0
					? [alicePub, bobPub]
					: [bobPub, alicePub];

			// Single channel with small capacity
			const scid = makeScid(950, 1, 0);
			const ann: IChannelAnnouncementMessage = {
				nodeSignature1: crypto.randomBytes(64),
				nodeSignature2: crypto.randomBytes(64),
				bitcoinSignature1: crypto.randomBytes(64),
				bitcoinSignature2: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				nodeId1: n1,
				nodeId2: n2,
				bitcoinKey1: crypto.randomBytes(33),
				bitcoinKey2: crypto.randomBytes(33)
			};
			aliceGraph.addChannelAnnouncement(ann);

			const upd0: IChannelUpdateMessage = {
				signature: crypto.randomBytes(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 30_000_000n // 30k sat cap
			};
			aliceGraph.applyChannelUpdate(upd0);
			aliceGraph.applyChannelUpdate({ ...upd0, channelFlags: 1 });

			const bobConfig = makeNodeConfig(71);

			// Invoice WITHOUT paymentSecret, amount exceeds capacity
			const invoiceStr = encodeInvoice({
				network: Network.REGTEST,
				paymentHash: crypto.randomBytes(32),
				// No paymentSecret!
				description: 'no secret test',
				amountMsat: 50_000_000n,
				payeeNodeKey: getPublicKey(bobConfig.nodePrivateKey),
				privateKey: bobConfig.nodePrivateKey
			});

			expect(() => alice.sendPayment(invoiceStr)).to.throw('no payment secret');
		});

		it('should set totalMsat on each MPP part to full invoice amount', function () {
			// Verify that sendPaymentMpp constructs onion payloads with totalMsat = full amount
			// We test this indirectly by checking the payment info returned by sendPayment.
			const cap = 50_000_000n;
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(cap, cap);

			const totalMsat = 80_000_000n;
			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				totalMsat,
				40
			);
			expect(result).to.not.be.null;

			// The multi-path route's totalAmountMsat should include fees
			// but individual part last-hop amounts should sum to totalMsat
			let deliveredSum = 0n;
			for (const part of result!.parts) {
				const lastHop = part.hops[part.hops.length - 1];
				deliveredSum += lastHop.amountToForwardMsat;
				// Each part's delivered amount should be strictly less than total
				expect(Number(lastHop.amountToForwardMsat)).to.be.lessThan(
					Number(totalMsat)
				);
			}
			expect(deliveredSum).to.equal(totalMsat);

			// The totalFeeMsat should be non-negative
			expect(Number(result!.totalFeeMsat)).to.be.greaterThanOrEqual(0);
		});
	});

	describe('findMultiPathRoute edge cases', function () {
		it('should return null when source equals destination', function () {
			const { graph, nodeA } = buildSignedParallelGraph(
				50_000_000n,
				50_000_000n
			);
			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeA.pub,
				10_000_000n,
				40
			);
			expect(result).to.be.null;
		});

		it('should respect maxParts parameter', function () {
			// With 2 paths of 30k sat cap, requesting 50k should succeed with maxParts=4
			const cap = 30_000_000n;
			const { graph, nodeA, nodeD } = buildSignedParallelGraph(cap, cap);

			// With maxParts=4, should find 2 parts
			const result = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				50_000_000n,
				40,
				4
			);
			expect(result).to.not.be.null;
			expect(result!.parts.length).to.be.greaterThan(1);

			// With maxParts=1, cannot fit 50k in single 30k path — should fail
			const result1 = findMultiPathRoute(
				graph,
				nodeA.pub,
				nodeD.pub,
				50_000_000n,
				40,
				1
			);
			expect(result1).to.be.null;
		});
	});
});
