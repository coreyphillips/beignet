/**
 * Phase 7: MPP (Multi-Part Payments) tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	findRoute,
	findMultiPathRoute
} from '../../src/lightning/gossip/pathfinding';
import {
	encodeShortChannelId,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	MESSAGE_FLAG_HTLC_MAX
} from '../../src/lightning/gossip/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { Feature } from '../../src/lightning/features/flags';

// ── Helpers ────────────────────────────────────────────────────────

function makeScid(block: number, txIndex: number, outputIndex: number): Buffer {
	return encodeShortChannelId({ block, txIndex, outputIndex });
}

function makeNodeId(suffix: number): Buffer {
	const buf = Buffer.alloc(33, 0);
	buf[0] = 0x02;
	buf[32] = suffix;
	return buf;
}

function makeAnnouncement(
	scid: Buffer,
	nodeId1: Buffer,
	nodeId2: Buffer
): IChannelAnnouncementMessage {
	const [n1, n2] =
		Buffer.compare(nodeId1, nodeId2) < 0
			? [nodeId1, nodeId2]
			: [nodeId2, nodeId1];
	return {
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
}

function makeUpdate(
	scid: Buffer,
	direction: number,
	maxMsat: bigint
): IChannelUpdateMessage {
	return {
		signature: crypto.randomBytes(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: 1000,
		messageFlags: MESSAGE_FLAG_HTLC_MAX,
		channelFlags: direction,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: maxMsat
	};
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

/**
 * Build a graph with two parallel paths from source to destination.
 *
 * source ──(ch1 50k cap)──> mid1 ──(ch3 50k cap)──> dest
 * source ──(ch2 50k cap)──> mid2 ──(ch4 50k cap)──> dest
 */
function buildParallelGraph(): {
	graph: NetworkGraph;
	source: Buffer;
	dest: Buffer;
} {
	const graph = new NetworkGraph();
	const source = makeNodeId(0x01);
	const mid1 = makeNodeId(0x10);
	const mid2 = makeNodeId(0x20);
	const dest = makeNodeId(0xff);

	const maxCap = 50_000_000n; // 50k sat in msat

	// Path 1: source -> mid1 -> dest
	const scid1 = makeScid(100, 1, 0);
	const scid3 = makeScid(100, 3, 0);
	graph.addChannelAnnouncement(makeAnnouncement(scid1, source, mid1));
	graph.addChannelAnnouncement(makeAnnouncement(scid3, mid1, dest));

	// Path 2: source -> mid2 -> dest
	const scid2 = makeScid(100, 2, 0);
	const scid4 = makeScid(100, 4, 0);
	graph.addChannelAnnouncement(makeAnnouncement(scid2, source, mid2));
	graph.addChannelAnnouncement(makeAnnouncement(scid4, mid2, dest));

	// Updates in both directions for all channels
	for (const [scid, n1, n2] of [
		[scid1, source, mid1],
		[scid3, mid1, dest],
		[scid2, source, mid2],
		[scid4, mid2, dest]
	] as [Buffer, Buffer, Buffer][]) {
		const isN1First = Buffer.compare(n1, n2) < 0;
		const dir0 = isN1First ? 0 : 1;
		const dir1 = isN1First ? 1 : 0;
		graph.applyChannelUpdate(makeUpdate(scid, dir0, maxCap));
		graph.applyChannelUpdate(makeUpdate(scid, dir1, maxCap));
	}

	return { graph, source, dest };
}

// ── Tests ──────────────────────────────────────────────────────────

describe('MPP (Phase 7)', function () {
	describe('findMultiPathRoute', function () {
		it('should find single-path route when capacity is sufficient', function () {
			const { graph, source, dest } = buildParallelGraph();

			// 40k sats — single path is sufficient (50k cap per channel)
			const result = findMultiPathRoute(graph, source, dest, 40_000_000n, 40);
			expect(result).to.not.be.null;
			expect(result!.parts.length).to.equal(1);
		});

		it('should find multi-path route for amount exceeding single channel capacity', function () {
			const { graph, source, dest } = buildParallelGraph();

			// 80k sats — needs both paths (50k cap each)
			const result = findMultiPathRoute(graph, source, dest, 80_000_000n, 40);
			expect(result).to.not.be.null;
			expect(result!.parts.length).to.equal(2);

			// Total delivered should be >= 80k
			let totalDelivered = 0n;
			for (const part of result!.parts) {
				const lastHop = part.hops[part.hops.length - 1];
				totalDelivered += lastHop.amountToForwardMsat;
			}
			expect(Number(totalDelivered)).to.be.greaterThanOrEqual(80_000_000);
		});

		it('should return null when amount exceeds total capacity', function () {
			const { graph, source, dest } = buildParallelGraph();

			// 120k sats — exceeds both paths combined (100k total)
			const result = findMultiPathRoute(graph, source, dest, 120_000_000n, 40);
			expect(result).to.be.null;
		});

		it('should return null for unreachable destination', function () {
			const graph = new NetworkGraph();
			const source = makeNodeId(0x01);
			const dest = makeNodeId(0xff);

			const result = findMultiPathRoute(graph, source, dest, 1000n, 40);
			expect(result).to.be.null;
		});

		it('should respect maxParts limit', function () {
			const { graph, source, dest } = buildParallelGraph();

			// Try to deliver 80k with maxParts=1 — should fail (single path caps at ~50k)
			const result = findMultiPathRoute(
				graph,
				source,
				dest,
				80_000_000n,
				40,
				1
			);
			expect(result).to.be.null;
		});

		it('should calculate correct total amounts and fees', function () {
			const { graph, source, dest } = buildParallelGraph();

			const result = findMultiPathRoute(graph, source, dest, 40_000_000n, 40);
			expect(result).to.not.be.null;

			// totalAmountMsat should be >= amount requested (includes fees to sender)
			expect(Number(result!.totalAmountMsat)).to.be.greaterThanOrEqual(
				40_000_000
			);
			// totalFeeMsat should be non-negative
			expect(Number(result!.totalFeeMsat)).to.be.greaterThanOrEqual(0);
		});
	});

	describe('MPP Receiver Aggregation', function () {
		function makeNode(): LightningNode {
			return new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: makeBasepoints(),
				fundingPrivkey: crypto.randomBytes(32)
			});
		}

		it('should have BASIC_MPP in default features', function () {
			const features = LightningNode.defaultFeatures();
			expect(features.hasFeature(Feature.BASIC_MPP)).to.be.true;
		});

		it('should accept mppTimeoutMs config', function () {
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: makeBasepoints(),
				fundingPrivkey: crypto.randomBytes(32),
				mppTimeoutMs: 120_000
			});
			// Should construct without error
			expect(node).to.exist;
			node.destroy();
		});

		it('should clean up pendingMppPayments on destroy', function () {
			const node = makeNode();
			// No easy way to check internal state, just ensure destroy doesn't throw
			node.destroy();
		});
	});

	describe('Pathfinding regression', function () {
		it('should still find single-path routes correctly', function () {
			const graph = new NetworkGraph();
			const source = makeNodeId(0x01);
			const dest = makeNodeId(0x02);

			const scid = makeScid(100, 1, 0);
			graph.addChannelAnnouncement(makeAnnouncement(scid, source, dest));

			const isSourceFirst = Buffer.compare(source, dest) < 0;
			graph.applyChannelUpdate(
				makeUpdate(scid, isSourceFirst ? 0 : 1, 1_000_000_000n)
			);
			graph.applyChannelUpdate(
				makeUpdate(scid, isSourceFirst ? 1 : 0, 1_000_000_000n)
			);

			const route = findRoute(graph, source, dest, 1000n, 40);
			expect(route).to.not.be.null;
			expect(route!.hops.length).to.equal(1);
		});
	});
});
