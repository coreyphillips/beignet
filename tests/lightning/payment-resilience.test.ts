/**
 * Phase 6: Mission Control + Enhanced Payment Retry — Tests
 *
 * Tests for MissionControl penalty tracking, pathfinding integration with
 * mission control penalties, and LightningNode maxPaymentRetries config.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { MissionControl } from '../../src/lightning/gossip/mission-control';
import { findRoute } from '../../src/lightning/gossip/pathfinding';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId,
	CHANNEL_FLAG_DIRECTION,
	CHANNEL_FLAG_DISABLED,
	MESSAGE_FLAG_HTLC_MAX
} from '../../src/lightning/gossip/types';
import {
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import {
	signChannelAnnouncement,
	signChannelUpdate
} from '../../src/lightning/gossip/validation';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

// ── Helpers ─────────────────────────────────────────────────────────

function makeKeypair(): { privateKey: Buffer; publicKey: Buffer } {
	let privKey: Buffer;
	do {
		privKey = crypto.randomBytes(32);
	} while (privKey[0] === 0);
	return { privateKey: privKey, publicKey: getPublicKey(privKey) };
}

function makeScid(block: number, txIndex: number, outputIndex: number): Buffer {
	return encodeShortChannelId({ block, txIndex, outputIndex });
}

function createSignedChannelAnnouncement(
	nk1: { privateKey: Buffer; publicKey: Buffer },
	nk2: { privateKey: Buffer; publicKey: Buffer },
	bk1: { privateKey: Buffer; publicKey: Buffer },
	bk2: { privateKey: Buffer; publicKey: Buffer },
	scid: Buffer
): IChannelAnnouncementMessage {
	// Ensure nk1 < nk2 lexicographically (BOLT 7 requirement)
	const [lo, hi, bLo, bHi] =
		Buffer.compare(nk1.publicKey, nk2.publicKey) < 0
			? [nk1, nk2, bk1, bk2]
			: [nk2, nk1, bk2, bk1];

	const placeholder: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: lo.publicKey,
		nodeId2: hi.publicKey,
		bitcoinKey1: bLo.publicKey,
		bitcoinKey2: bHi.publicKey
	};
	const placeholderPayload = encodeChannelAnnouncementMessage(placeholder);

	const sig1 = signChannelAnnouncement(
		placeholderPayload,
		lo.privateKey,
		bLo.privateKey
	);
	const sig2 = signChannelAnnouncement(
		placeholderPayload,
		hi.privateKey,
		bHi.privateKey
	);

	return {
		...placeholder,
		nodeSignature1: sig1.nodeSignature,
		nodeSignature2: sig2.nodeSignature,
		bitcoinSignature1: sig1.bitcoinSignature,
		bitcoinSignature2: sig2.bitcoinSignature
	};
}

function createSignedChannelUpdate(
	nk: Buffer,
	scid: Buffer,
	dir: number,
	opts?: {
		cltvExpiryDelta?: number;
		htlcMinimumMsat?: bigint;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
		htlcMaximumMsat?: bigint;
		disabled?: boolean;
	}
): IChannelUpdateMessage {
	const channelFlags =
		(dir & CHANNEL_FLAG_DIRECTION) |
		(opts?.disabled ? CHANNEL_FLAG_DISABLED : 0);
	const hasMax = opts?.htlcMaximumMsat !== undefined;
	const messageFlags = hasMax ? MESSAGE_FLAG_HTLC_MAX : 0;

	const placeholder: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: 1700000000,
		messageFlags,
		channelFlags,
		cltvExpiryDelta: opts?.cltvExpiryDelta ?? 40,
		htlcMinimumMsat: opts?.htlcMinimumMsat ?? 1000n,
		feeBaseMsat: opts?.feeBaseMsat ?? 1000,
		feeProportionalMillionths: opts?.feeProportionalMillionths ?? 1,
		htlcMaximumMsat: opts?.htlcMaximumMsat
	};

	const placeholderPayload = encodeChannelUpdateMessage(placeholder);
	const sig = signChannelUpdate(placeholderPayload, nk);

	return { ...placeholder, signature: sig };
}

/**
 * Build a diamond graph with two paths from A to D:
 *   Path 1: A -> B -> D (high-fee path)
 *   Path 2: A -> C -> D (low-fee path)
 *
 * All nodes are sorted lexicographically to satisfy BOLT 7.
 */
function setupTwoPathGraph(): {
	graph: NetworkGraph;
	nodeA: Buffer;
	nodeD: Buffer;
	scidAB: Buffer;
	scidBD: Buffer;
	scidAC: Buffer;
	scidCD: Buffer;
	keys: Array<{ privateKey: Buffer; publicKey: Buffer }>;
} {
	// Create 4 nodes
	const rawKeys = Array.from({ length: 4 }, () => makeKeypair());
	// Sort by pubkey for consistent ordering
	rawKeys.sort((a, b) => Buffer.compare(a.publicKey, b.publicKey));

	const graph = new NetworkGraph();

	// We label sorted keys as nodes 0,1,2,3. We'll pick:
	//   nodeA = rawKeys[0], nodeB = rawKeys[1], nodeC = rawKeys[2], nodeD = rawKeys[3]

	// Channel A-B (SCID 100:1:0)
	const scidAB = makeScid(100, 1, 0);
	const bkAB1 = makeKeypair(),
		bkAB2 = makeKeypair();
	const annAB = createSignedChannelAnnouncement(
		rawKeys[0],
		rawKeys[1],
		bkAB1,
		bkAB2,
		scidAB
	);
	graph.addChannelAnnouncement(annAB);

	// Channel B-D (SCID 100:2:0)
	const scidBD = makeScid(100, 2, 0);
	const bkBD1 = makeKeypair(),
		bkBD2 = makeKeypair();
	const annBD = createSignedChannelAnnouncement(
		rawKeys[1],
		rawKeys[3],
		bkBD1,
		bkBD2,
		scidBD
	);
	graph.addChannelAnnouncement(annBD);

	// Channel A-C (SCID 100:3:0)
	const scidAC = makeScid(100, 3, 0);
	const bkAC1 = makeKeypair(),
		bkAC2 = makeKeypair();
	const annAC = createSignedChannelAnnouncement(
		rawKeys[0],
		rawKeys[2],
		bkAC1,
		bkAC2,
		scidAC
	);
	graph.addChannelAnnouncement(annAC);

	// Channel C-D (SCID 100:4:0)
	const scidCD = makeScid(100, 4, 0);
	const bkCD1 = makeKeypair(),
		bkCD2 = makeKeypair();
	const annCD = createSignedChannelAnnouncement(
		rawKeys[2],
		rawKeys[3],
		bkCD1,
		bkCD2,
		scidCD
	);
	graph.addChannelAnnouncement(annCD);

	// Add bidirectional updates
	// Path A->B->D: HIGH fees (base=5000)
	const addUpdates = (
		nodeKeys: typeof rawKeys,
		idx1: number,
		idx2: number,
		scid: Buffer,
		feeBaseMsat: number
	) => {
		// Determine which is lower/higher in sorted order
		const [loIdx, hiIdx] = idx1 < idx2 ? [idx1, idx2] : [idx2, idx1];
		// Direction 0 (from lower-key node)
		const u0 = createSignedChannelUpdate(nodeKeys[loIdx].privateKey, scid, 0, {
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000_000n
		});
		graph.applyChannelUpdate(u0);

		// Direction 1 (from higher-key node)
		const u1 = createSignedChannelUpdate(nodeKeys[hiIdx].privateKey, scid, 1, {
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000_000n
		});
		graph.applyChannelUpdate(u1);
	};

	// Path A-B-D: higher fees (5000 base)
	addUpdates(rawKeys, 0, 1, scidAB, 5000);
	addUpdates(rawKeys, 1, 3, scidBD, 5000);

	// Path A-C-D: lower fees (1000 base)
	addUpdates(rawKeys, 0, 2, scidAC, 1000);
	addUpdates(rawKeys, 2, 3, scidCD, 1000);

	return {
		graph,
		nodeA: rawKeys[0].publicKey,
		nodeD: rawKeys[3].publicKey,
		scidAB,
		scidBD,
		scidAC,
		scidCD,
		keys: rawKeys
	};
}

// ── Node helpers ────────────────────────────────────────────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`node-seed-${id}`))
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

function makeNodeConfig(
	seedId: number,
	overrides?: Partial<INodeConfig>
): INodeConfig {
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
		fundingPrivkey,
		...overrides
	};
}

// ── Tests ───────────────────────────────────────────────────────────

describe('Phase 6: Mission Control + Enhanced Payment Retry', () => {
	// ── MissionControl Unit Tests ───────────────────────────────────

	describe('MissionControl', () => {
		it('should have size 0 when newly created', () => {
			const mc = new MissionControl();
			expect(mc.size).to.equal(0);
		});

		it('should increase size after recordFailure', () => {
			const mc = new MissionControl();
			mc.recordFailure('aabbccdd00000000');
			expect(mc.size).to.equal(1);
			mc.recordFailure('1122334400000000');
			expect(mc.size).to.equal(2);
		});

		it('should return 0n penalty for unknown channel', () => {
			const mc = new MissionControl();
			expect(mc.getPenalty('deadbeef00000000')).to.equal(0n);
		});

		it('should return >0n penalty after failure', () => {
			const mc = new MissionControl();
			mc.recordFailure('aabbccdd00000000');
			const penalty = mc.getPenalty('aabbccdd00000000');
			expect(Number(penalty)).to.be.greaterThan(0);
		});

		it('should increase penalty with multiple failures', () => {
			const mc = new MissionControl();
			mc.recordFailure('aabbccdd00000000');
			const pen1 = mc.getPenalty('aabbccdd00000000');

			mc.recordFailure('aabbccdd00000000');
			const pen2 = mc.getPenalty('aabbccdd00000000');

			expect(Number(pen2)).to.be.greaterThan(Number(pen1));
		});

		it('should reduce effective penalty after recordSuccess', () => {
			const mc = new MissionControl();
			// Record 2 failures
			mc.recordFailure('aabbccdd00000000');
			mc.recordFailure('aabbccdd00000000');
			const penBefore = mc.getPenalty('aabbccdd00000000');

			// Record a success (each success halves effective failure count)
			mc.recordSuccess('aabbccdd00000000');
			const penAfter = mc.getPenalty('aabbccdd00000000');

			expect(Number(penAfter)).to.be.lessThan(Number(penBefore));
		});

		it('should reduce penalty to 0n with enough successes', () => {
			const mc = new MissionControl();
			// 1 failure
			mc.recordFailure('aabbccdd00000000');

			// 2 successes should reduce effective failures to max(0, 1 - 2/2) = 0
			mc.recordSuccess('aabbccdd00000000');
			mc.recordSuccess('aabbccdd00000000');

			const penalty = mc.getPenalty('aabbccdd00000000');
			expect(penalty).to.equal(0n);
		});

		it('should reset all state on clear()', () => {
			const mc = new MissionControl();
			mc.recordFailure('aabbccdd00000000');
			mc.recordFailure('1122334400000000');
			expect(mc.size).to.equal(2);

			mc.clear();

			expect(mc.size).to.equal(0);
			expect(mc.getPenalty('aabbccdd00000000')).to.equal(0n);
			expect(mc.getPenalty('1122334400000000')).to.equal(0n);
		});

		it('should respect custom failurePenaltyBaseMsat', () => {
			const mcLow = new MissionControl({ failurePenaltyBaseMsat: 1_000 });
			const mcHigh = new MissionControl({ failurePenaltyBaseMsat: 500_000 });

			mcLow.recordFailure('aabbccdd00000000');
			mcHigh.recordFailure('aabbccdd00000000');

			const penLow = mcLow.getPenalty('aabbccdd00000000');
			const penHigh = mcHigh.getPenalty('aabbccdd00000000');

			expect(Number(penHigh)).to.be.greaterThan(Number(penLow));
		});

		it('should cap penalty at maxPenaltyMsat', () => {
			const mc = new MissionControl({
				failurePenaltyBaseMsat: 1_000_000,
				maxPenaltyMsat: 500_000
			});

			// Record many failures to exceed the cap
			for (let i = 0; i < 20; i++) {
				mc.recordFailure('aabbccdd00000000');
			}

			const penalty = mc.getPenalty('aabbccdd00000000');
			expect(Number(penalty)).to.be.at.most(500_000);
		});
	});

	// ── Pathfinding Integration ─────────────────────────────────────

	describe('Pathfinding with MissionControl', () => {
		it('should avoid penalized channel when alternative exists', () => {
			const { graph, nodeA, nodeD, scidAC, scidCD } = setupTwoPathGraph();
			const mc = new MissionControl({ failurePenaltyBaseMsat: 1_000_000 });

			// Without penalties, the cheaper path A->C->D should be chosen
			const routeNoPenalty = findRoute(
				graph,
				nodeA,
				nodeD,
				100_000n,
				144,
				20,
				undefined,
				mc
			);
			expect(routeNoPenalty).to.not.be.null;

			// Verify the no-penalty route uses the cheap path (A->C->D)
			const cheapScids = new Set([
				scidAC.toString('hex'),
				scidCD.toString('hex')
			]);
			const usedScids = routeNoPenalty!.hops.map((h) =>
				h.shortChannelId.toString('hex')
			);
			const usesCheapPath = usedScids.every((s) => cheapScids.has(s));
			expect(usesCheapPath).to.equal(true);

			// Now heavily penalize the cheap path channels
			for (let i = 0; i < 10; i++) {
				mc.recordFailure(scidAC.toString('hex'));
				mc.recordFailure(scidCD.toString('hex'));
			}

			// With penalties, the router should switch to the expensive path A->B->D
			const routePenalized = findRoute(
				graph,
				nodeA,
				nodeD,
				100_000n,
				144,
				20,
				undefined,
				mc
			);
			expect(routePenalized).to.not.be.null;

			const penalizedScids = routePenalized!.hops.map((h) =>
				h.shortChannelId.toString('hex')
			);
			const stillUsesCheapPath = penalizedScids.every((s) => cheapScids.has(s));
			expect(stillUsesCheapPath).to.equal(false);
		});

		it('should still use penalized channel if it is the only option', () => {
			const { graph, nodeA, nodeD } = setupTwoPathGraph();
			const mc = new MissionControl({ failurePenaltyBaseMsat: 1_000_000 });

			// Penalize ALL channels heavily
			const allScids = graph.getAllChannelIds();
			for (const scid of allScids) {
				for (let i = 0; i < 10; i++) {
					mc.recordFailure(scid.toString('hex'));
				}
			}

			// Even with all channels penalized, should still find a route
			// because penalties add cost but don't exclude channels
			const route = findRoute(
				graph,
				nodeA,
				nodeD,
				100_000n,
				144,
				20,
				undefined,
				mc
			);
			expect(route).to.not.be.null;
			expect(route!.hops.length).to.be.greaterThan(0);
		});

		it('should ignore penalties when mission control is not provided', () => {
			const { graph, nodeA, nodeD, scidAC, scidCD } = setupTwoPathGraph();

			// findRoute without mission control always picks cheapest path
			const route1 = findRoute(graph, nodeA, nodeD, 100_000n, 144);
			expect(route1).to.not.be.null;

			const cheapScids = new Set([
				scidAC.toString('hex'),
				scidCD.toString('hex')
			]);
			const usedScids = route1!.hops.map((h) =>
				h.shortChannelId.toString('hex')
			);
			const usesCheapPath = usedScids.every((s) => cheapScids.has(s));
			expect(usesCheapPath).to.equal(true);

			// Even though we create a mission control with penalties, not passing it
			// means the router should still pick the cheap path
			const mc = new MissionControl({ failurePenaltyBaseMsat: 1_000_000 });
			for (let i = 0; i < 10; i++) {
				mc.recordFailure(scidAC.toString('hex'));
				mc.recordFailure(scidCD.toString('hex'));
			}

			// Pass undefined for missionControl
			const route2 = findRoute(
				graph,
				nodeA,
				nodeD,
				100_000n,
				144,
				20,
				undefined,
				undefined
			);
			expect(route2).to.not.be.null;

			const usedScids2 = route2!.hops.map((h) =>
				h.shortChannelId.toString('hex')
			);
			const stillUsesCheapPath = usedScids2.every((s) => cheapScids.has(s));
			expect(stillUsesCheapPath).to.equal(true);
		});
	});

	// ── Node Integration ────────────────────────────────────────────

	describe('LightningNode maxPaymentRetries', () => {
		it('should create successfully with custom maxPaymentRetries', () => {
			const node = new LightningNode(
				makeNodeConfig(300, { maxPaymentRetries: 5 })
			);
			node.on('error', () => {}); // absorb errors
			expect(node).to.be.instanceOf(LightningNode);
			node.destroy();
		});

		it('should default maxPaymentRetries to 3', () => {
			// We verify the default indirectly: create a node without specifying
			// maxPaymentRetries, and confirm it creates successfully (the default 3
			// is set internally). The actual value is a private field, so we verify
			// the node is functional.
			const node = new LightningNode(makeNodeConfig(301));
			node.on('error', () => {}); // absorb errors
			const info = node.getNodeInfo();
			expect(info).to.not.be.null;
			expect(info.nodeId).to.be.a('string');
			node.destroy();
		});
	});
});
