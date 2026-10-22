/**
 * Regression (issue #1809): a mission-control penalty must stay in the cost
 * of every path through the penalized edge.
 *
 * The search used to add only the current edge's penalty, so a penalty was
 * dropped one hop upstream. A node reached past a penalized edge could then
 * offer that edge's upstream end a cheaper path back through itself, the two
 * became each other's predecessors, and route reconstruction never ended.
 */

import { expect } from 'chai';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	findMultiPathRoute,
	findRoute
} from '../../src/lightning/gossip/pathfinding';
import { MissionControl } from '../../src/lightning/gossip/mission-control';
import {
	encodeShortChannelId,
	MESSAGE_FLAG_HTLC_MAX
} from '../../src/lightning/gossip/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

function makeNodeId(suffix: number): Buffer {
	const buf = Buffer.alloc(33, 0);
	buf[0] = 0x02;
	buf[32] = suffix;
	return buf;
}

/** Announce lo-hi (lo < hi) with the same policy in both directions. */
function addChannel(
	graph: NetworkGraph,
	lo: Buffer,
	hi: Buffer,
	block: number,
	feeBaseMsat = 0,
	htlcMaximumMsat = 1_000_000_000n
): Buffer {
	const scid = encodeShortChannelId({ block, txIndex: 0, outputIndex: 0 });
	graph.addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: lo,
		nodeId2: hi,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const direction of [0, 1]) {
		graph.applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: 1000,
			messageFlags: MESSAGE_FLAG_HTLC_MAX,
			channelFlags: direction,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 0n,
			feeBaseMsat,
			feeProportionalMillionths: 0,
			htlcMaximumMsat
		});
	}
	return scid;
}

function hopPubkeys(hops: { pubkey: Buffer }[]): string[] {
	return hops.map((h) => h.pubkey.toString('hex'));
}

describe('Pathfinding: mission-control penalties (issue #1809)', () => {
	// S < A < B < D, and the insertion order A-D, A-B, S-A, put B ahead of S
	// in the heap at equal cost: B is expanded first and, with the A-D
	// penalty forgotten, undercut A's predecessor with A-B-A.
	const S = makeNodeId(1);
	const A = makeNodeId(2);
	const B = makeNodeId(3);
	const D = makeNodeId(4);
	let graph: NetworkGraph;
	let mc: MissionControl;

	beforeEach(() => {
		graph = new NetworkGraph();
		const scidAD = addChannel(graph, A, D, 100);
		addChannel(graph, A, B, 101);
		addChannel(graph, S, A, 102);
		mc = new MissionControl();
		mc.recordFailure(scidAD.toString('hex'));
	});

	it('findRoute returns S-A-D past a penalized A-D', () => {
		const route = findRoute(graph, S, D, 10_000n, 40, 20, undefined, mc);
		expect(route).to.not.equal(null);
		expect(hopPubkeys(route!.hops)).to.deep.equal([
			A.toString('hex'),
			D.toString('hex')
		]);
		expect(route!.totalAmountMsat).to.equal(10_000n);
	});

	it('findMultiPathRoute returns S-A-D past a penalized A-D', () => {
		const mpp = findMultiPathRoute(graph, S, D, 10_000n, 40, 4, 20, mc);
		expect(mpp).to.not.equal(null);
		expect(mpp!.parts).to.have.length(1);
		expect(hopPubkeys(mpp!.parts[0].hops)).to.deep.equal([
			A.toString('hex'),
			D.toString('hex')
		]);
	});

	it('weighs a penalty two hops from the source against a cheaper fee', () => {
		// S-X-D is fee-free but X-D is penalized 1500 msat. S-Y-D charges a
		// 1000 msat fee at Y, so it is the cheaper route once the penalty
		// counts at S as well as at X.
		const X = makeNodeId(2);
		const Y = makeNodeId(3);
		const g = new NetworkGraph();
		const scidXD = addChannel(g, X, D, 200);
		addChannel(g, Y, D, 201, 1000);
		addChannel(g, S, X, 202);
		addChannel(g, S, Y, 203);
		const history = new MissionControl({ failurePenaltyBaseMsat: 1500 });
		history.recordFailure(scidXD.toString('hex'));

		const route = findRoute(g, S, D, 10_000n, 40, 20, undefined, history);
		expect(route).to.not.equal(null);
		expect(hopPubkeys(route!.hops)).to.deep.equal([
			Y.toString('hex'),
			D.toString('hex')
		]);
		expect(route!.totalFeeMsat).to.equal(1000n);
	});

	it('still routes over a penalized path when the cheaper one does not fit', () => {
		// Once the X-D penalty counts, A-Y-D is A's cheapest path, but its
		// 1000 msat fee at Y needs 11,000 msat on S-A, which carries 10,000.
		const X = makeNodeId(3);
		const Y = makeNodeId(5);
		const g = new NetworkGraph();
		addChannel(g, A, X, 300);
		const scidXD = addChannel(g, X, D, 301);
		addChannel(g, A, Y, 302);
		addChannel(g, D, Y, 303, 1000);
		addChannel(g, S, A, 304, 0, 10_000n);
		const history = new MissionControl();
		history.recordFailure(scidXD.toString('hex'));
		const viaX = [A, X, D].map((node) => node.toString('hex'));

		const route = findRoute(g, S, D, 10_000n, 40, 20, undefined, history);
		expect(route).to.not.equal(null);
		expect(hopPubkeys(route!.hops)).to.deep.equal(viaX);

		const mpp = findMultiPathRoute(g, S, D, 10_000n, 40, 4, 20, history);
		expect(mpp).to.not.equal(null);
		expect(mpp!.parts).to.have.length(1);
		expect(hopPubkeys(mpp!.parts[0].hops)).to.deep.equal(viaX);
	});
});
