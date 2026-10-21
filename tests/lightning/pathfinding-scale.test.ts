/**
 * Pathfinding over a mainnet-scale graph (issue #1674): a search reads hex
 * keys the graph derived when each channel arrived, so the work per edge it
 * relaxes converts nothing.
 */

import { expect } from 'chai';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	findMultiPathRoute,
	findRoute,
	ILocalChannelEdge
} from '../../src/lightning/gossip/pathfinding';
import {
	encodeShortChannelId,
	IChannelAnnouncementMessage,
	IGraphEdge,
	MESSAGE_FLAG_HTLC_MAX
} from '../../src/lightning/gossip/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

const SIG = Buffer.alloc(64, 1);
const KEY = Buffer.alloc(33, 2);

/** A seeded generator, so every run routes over the same graph. */
function prng(seed: number): (lo: number, hi: number) => number {
	let state = seed;
	return (lo, hi) => {
		state = (state + 0x6d2b79f5) | 0;
		let t = Math.imul(state ^ (state >>> 15), 1 | state);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		const unit = ((t ^ (t >>> 14)) >>> 0) / 4294967296;
		return lo + Math.floor(unit * (hi - lo + 1));
	};
}

function nodeId(index: number): Buffer {
	const id = Buffer.alloc(33);
	id[0] = 0x02;
	id.writeUInt32BE(index + 1, 29);
	return id;
}

function announcement(
	block: number,
	a: Buffer,
	b: Buffer
): IChannelAnnouncementMessage {
	const [nodeId1, nodeId2] = Buffer.compare(a, b) < 0 ? [a, b] : [b, a];
	return {
		nodeSignature1: SIG,
		nodeSignature2: SIG,
		bitcoinSignature1: SIG,
		bitcoinSignature2: SIG,
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: encodeShortChannelId({ block, txIndex: 1, outputIndex: 0 }),
		nodeId1,
		nodeId2,
		bitcoinKey1: KEY,
		bitcoinKey2: KEY
	};
}

function applyUpdates(
	graph: NetworkGraph,
	scid: Buffer,
	rand: (lo: number, hi: number) => number
): void {
	for (const direction of [0, 1]) {
		graph.applyChannelUpdate(
			{
				signature: SIG,
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: 1_700_000_000,
				messageFlags: MESSAGE_FLAG_HTLC_MAX,
				channelFlags: direction,
				cltvExpiryDelta: rand(18, 80),
				htlcMinimumMsat: 1000n,
				feeBaseMsat: rand(0, 1000),
				feeProportionalMillionths: rand(0, 2000),
				htlcMaximumMsat: BigInt(rand(1_000_000, 2_000_000_000))
			},
			{ verified: true }
		);
	}
}

/** Random channels between `nodeCount` nodes, each with both policies. */
function buildGraph(
	channelCount: number,
	nodeCount: number
): { graph: NetworkGraph; nodes: Buffer[] } {
	const rand = prng(1674);
	const graph = new NetworkGraph();
	const nodes = Array.from({ length: nodeCount }, (_, i) => nodeId(i));
	let made = 0;
	while (made < channelCount) {
		const a = nodes[rand(0, nodeCount - 1)];
		const b = nodes[rand(0, nodeCount - 1)];
		if (a.equals(b)) continue;
		const msg = announcement(500_000 + made, a, b);
		graph.addChannelAnnouncement(msg, { verified: true });
		applyUpdates(graph, msg.shortChannelId, rand);
		made++;
	}
	return { graph, nodes };
}

/**
 * Run `fn` counting hex conversions of any Buffer, the edges the graph
 * handed to searches, and the searches (each settles the destination once).
 */
function measure<T>(
	graph: NetworkGraph,
	destination: Buffer,
	fn: () => T
): {
	result: T;
	hexCalls: number;
	edgesExamined: number;
	searches: number;
	elapsedMs: number;
} {
	const destHex = destination.toString('hex');
	let hexCalls = 0;
	let edgesExamined = 0;
	let searches = 0;
	const toString = Buffer.prototype.toString;
	const getNodeEdges = graph.getNodeEdges;
	Buffer.prototype.toString = function (
		this: Buffer,
		...args: Parameters<Buffer['toString']>
	): string {
		if (args[0] === 'hex') hexCalls++;
		return toString.apply(this, args);
	};
	graph.getNodeEdges = function (nodeIdHex: string): IGraphEdge[] {
		const edges = getNodeEdges.call(this, nodeIdHex);
		edgesExamined += edges.length;
		if (nodeIdHex === destHex) searches++;
		return edges;
	};
	const started = process.hrtime.bigint();
	try {
		const result = fn();
		const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
		return { result, hexCalls, edgesExamined, searches, elapsedMs };
	} finally {
		Buffer.prototype.toString = toString;
		graph.getNodeEdges = getNodeEdges;
	}
}

describe('Pathfinding at scale (issue #1674)', function () {
	this.timeout(60_000);

	it('keeps getNodeEdges in step with getNodeChannels through churn', () => {
		const rand = prng(7);
		const { graph, nodes } = buildGraph(300, 60);
		// Remove some channels, restore a removed one, and add one through
		// the Rapid Gossip Sync path, so every write site is exercised.
		const removed = graph.getAllChannels().filter((_, i) => i % 7 === 0);
		for (const channel of removed) graph.removeChannel(channel.shortChannelId);
		graph.restoreChannel({ ...removed[0], announcementVerified: true });
		const rgs = announcement(900_000, nodes[1], nodes[2]);
		graph.addRapidGossipChannel(rgs, {
			scidHex: rgs.shortChannelId.toString('hex'),
			node1Hex: rgs.nodeId1.toString('hex'),
			node2Hex: rgs.nodeId2.toString('hex')
		});
		applyUpdates(graph, rgs.shortChannelId, rand);

		for (const node of nodes) {
			const channels = graph.getNodeChannels(node);
			const edges = graph.getNodeEdges(node.toString('hex'));
			expect(edges.map((e) => e.channel)).to.have.ordered.members(channels);
			for (const edge of edges) {
				expect(edge.scidHex).to.equal(
					edge.channel.shortChannelId.toString('hex')
				);
				expect(edge.node1Hex).to.equal(edge.channel.nodeId1.toString('hex'));
				expect(edge.node2Hex).to.equal(edge.channel.nodeId2.toString('hex'));
			}
		}
		for (const channel of removed.slice(1)) {
			for (const id of [channel.nodeId1, channel.nodeId2]) {
				expect(
					graph
						.getNodeEdges(id.toString('hex'))
						.some((e) =>
							e.channel.shortChannelId.equals(channel.shortChannelId)
						)
				).to.equal(false);
			}
		}
	});

	describe('over 20,000 channels', function () {
		let graph: NetworkGraph;
		let nodes: Buffer[];

		before(function () {
			({ graph, nodes } = buildGraph(20_000, 4_000));
		});

		it('routes 100 payments converting only each search endpoint to hex', () => {
			const rand = prng(42);
			const payments = Array.from({ length: 100 }, () => ({
				source: nodes[rand(0, nodes.length - 1)],
				destination: nodes[rand(0, nodes.length - 1)],
				amountMsat: BigInt(rand(10_000, 1_500_000_000))
			}));
			let found = 0;
			let hexCalls = 0;
			let edgesExamined = 0;
			let elapsedMs = 0;
			for (const p of payments) {
				const run = measure(graph, p.destination, () =>
					findRoute(graph, p.source, p.destination, p.amountMsat, 40)
				);
				if (run.result) found++;
				hexCalls += run.hexCalls;
				edgesExamined += run.edgesExamined;
				elapsedMs += run.elapsedMs;
			}

			expect(found).to.be.greaterThan(50);
			// The source and destination keys of each search, and nothing per
			// edge, out of well over a million edges relaxed.
			expect(edgesExamined).to.be.greaterThan(1_000_000);
			expect(hexCalls).to.be.at.most(2 * payments.length);
			// A ceiling for gross regressions: about 0.3 s on a laptop.
			expect(elapsedMs).to.be.below(5_000);
		});

		it('runs the searches of a failing multi-path payment on one overlay', () => {
			// A source outside the graph whose own channels cannot carry the
			// amount, so every search explores the graph and fails.
			const source = nodeId(10_000);
			const destination = nodes[0];
			const localChannels: ILocalChannelEdge[] = [1, 2, 3].map((i) => ({
				shortChannelId: encodeShortChannelId({
					block: 990_000 + i,
					txIndex: 1,
					outputIndex: 0
				}),
				peer: nodes[i * 100],
				outboundMsat: 1n
			}));
			const single = measure(graph, destination, () =>
				findRoute(
					graph,
					source,
					destination,
					50_000_000n,
					40,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					localChannels
				)
			);
			const multi = measure(graph, destination, () =>
				findMultiPathRoute(
					graph,
					source,
					destination,
					50_000_000n,
					40,
					4,
					undefined,
					undefined,
					undefined,
					undefined,
					localChannels
				)
			);

			expect(single.result).to.equal(null);
			expect(multi.result).to.equal(null);
			expect(single.edgesExamined).to.be.greaterThan(20_000);
			// The full amount, then eight halvings.
			expect(multi.searches).to.equal(9);
			// Nine searches convert no more keys than one: the overlay is
			// built once and the searches themselves convert nothing.
			expect(multi.hexCalls).to.equal(single.hexCalls);
		});
	});
});
