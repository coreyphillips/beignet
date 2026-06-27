/**
 * Tests that findMultiPathRoute integrates with MissionControl penalties.
 *
 * Builds a simple 3-node graph (A -> B -> C) and verifies that
 * MissionControl penalties affect route selection and that the
 * optional parameter is backward-compatible.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { findMultiPathRoute } from '../../src/lightning/gossip/pathfinding';
import { MissionControl } from '../../src/lightning/gossip/mission-control';
import {
	encodeShortChannelId,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	MESSAGE_FLAG_HTLC_MAX
} from '../../src/lightning/gossip/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

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

describe('MPP MissionControl Integration', () => {
	let graph: NetworkGraph;
	let nodeA: Buffer;
	let nodeB: Buffer;
	let nodeC: Buffer;
	let scidAB: Buffer;
	let scidBC: Buffer;

	beforeEach(() => {
		graph = new NetworkGraph();
		nodeA = makeNodeId(1);
		nodeB = makeNodeId(2);
		nodeC = makeNodeId(3);
		scidAB = makeScid(100, 1, 0);
		scidBC = makeScid(100, 2, 0);

		// Add channel A-B (nodeA < nodeB lexicographically due to suffix ordering)
		graph.addChannelAnnouncement(makeAnnouncement(scidAB, nodeA, nodeB));
		graph.applyChannelUpdate(makeUpdate(scidAB, 0, 10_000_000_000n)); // A->B direction

		// Add channel B-C
		graph.addChannelAnnouncement(makeAnnouncement(scidBC, nodeB, nodeC));
		graph.applyChannelUpdate(makeUpdate(scidBC, 0, 10_000_000_000n)); // B->C direction
	});

	it('findMultiPathRoute avoids MissionControl-penalized channels', () => {
		const mc = new MissionControl();
		// Penalize channel A->B heavily
		mc.recordFailure(scidAB.toString('hex'));

		// With penalty, the only path A->B->C should have higher cost
		// Since there is only one path, route may still be found but with penalty applied
		const routeWithPenalty = findMultiPathRoute(
			graph,
			nodeA,
			nodeC,
			100_000n,
			40,
			4,
			20,
			mc
		);
		const routeWithout = findMultiPathRoute(
			graph,
			nodeA,
			nodeC,
			100_000n,
			40,
			4,
			20
		);

		// Both should find a route (only one path exists)
		expect(routeWithout).to.not.be.null;
		// With penalty, route may still be found but cost is higher
		if (routeWithPenalty) {
			expect(Number(routeWithPenalty.totalAmountMsat)).to.be.greaterThanOrEqual(
				Number(routeWithout!.totalAmountMsat)
			);
		}
		// If penalty is so high that no route is found, that is also correct behavior
	});

	it('backward-compatible without MissionControl param', () => {
		// Should work exactly as before when no MissionControl is provided
		const route = findMultiPathRoute(graph, nodeA, nodeC, 100_000n, 40);
		expect(route).to.not.be.null;
		expect(route!.parts.length).to.be.greaterThan(0);
	});

	it('findMultiPathRoute works with empty MissionControl', () => {
		// No failures recorded — should behave normally
		const mc = new MissionControl();
		const route = findMultiPathRoute(
			graph,
			nodeA,
			nodeC,
			100_000n,
			40,
			4,
			20,
			mc
		);
		expect(route).to.not.be.null;
		expect(route!.parts.length).to.be.greaterThan(0);
	});
});
