/**
 * ChannelSuggestions — Tests
 *
 * Tests the gossip graph analysis for recommending nodes to open channels with.
 * Scoring: connectivity (40), capacity (20), freshness (20), relevance (20).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { ChannelSuggestions } from '../../src/lightning/advisor/channel-suggestions';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage
} from '../../src/lightning/gossip/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';

// ── Helpers ───────────────────────────────────────────────────────────

function makeKeypair(): { privateKey: Buffer; publicKey: Buffer } {
	let privKey: Buffer;
	do {
		privKey = crypto.randomBytes(32);
	} while (privKey[0] === 0);
	return { privateKey: privKey, publicKey: getPublicKey(privKey) };
}

/** Create two keypairs with pubkey1 < pubkey2 lexicographically. */
function orderKeys(
	a: { privateKey: Buffer; publicKey: Buffer },
	b: { privateKey: Buffer; publicKey: Buffer }
): [
	{ privateKey: Buffer; publicKey: Buffer },
	{ privateKey: Buffer; publicKey: Buffer }
] {
	if (Buffer.compare(a.publicKey, b.publicKey) < 0) return [a, b];
	return [b, a];
}

let scidCounter = 1;
function makeScid(): Buffer {
	return encodeShortChannelId({
		block: 700000,
		txIndex: scidCounter++,
		outputIndex: 0
	});
}

/**
 * Add a channel between two nodes with bidirectional updates.
 */
function addChannel(
	graph: NetworkGraph,
	key1: { privateKey: Buffer; publicKey: Buffer },
	key2: { privateKey: Buffer; publicKey: Buffer },
	opts: {
		timestamp?: number;
		htlcMaximumMsat?: bigint;
	} = {}
): Buffer {
	const [ordered1, ordered2] = orderKeys(key1, key2);
	const scid = makeScid();
	const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
	const htlcMax = opts.htlcMaximumMsat ?? 1_000_000_000n;

	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: ordered1.publicKey,
		nodeId2: ordered2.publicKey,
		bitcoinKey1: ordered1.publicKey,
		bitcoinKey2: ordered2.publicKey
	};

	graph.addChannelAnnouncement(announcement);

	// Direction 0 update (from nodeId1)
	const update1: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp,
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		htlcMaximumMsat: htlcMax,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1
	};
	graph.applyChannelUpdate(update1);

	// Direction 1 update (from nodeId2)
	const update2: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp,
		messageFlags: 1,
		channelFlags: 1,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		htlcMaximumMsat: htlcMax,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1
	};
	graph.applyChannelUpdate(update2);

	return scid;
}

describe('ChannelSuggestions', () => {
	let suggestions: ChannelSuggestions;
	let graph: NetworkGraph;

	beforeEach(() => {
		suggestions = new ChannelSuggestions();
		graph = new NetworkGraph();
		scidCounter = 1;
	});

	it('should return empty array when graph is empty', () => {
		const ownKey = makeKeypair();
		const result = suggestions.suggest(graph, ownKey.publicKey.toString('hex'));
		expect(result).to.be.an('array').with.length(0);
	});

	it('should exclude self from results', () => {
		const self = makeKeypair();
		const other = makeKeypair();
		const third = makeKeypair();

		addChannel(graph, self, other);
		addChannel(graph, other, third);

		const result = suggestions.suggest(graph, self.publicKey.toString('hex'));
		const nodeIds = result.map((s) => s.nodeId);
		expect(nodeIds).to.not.include(self.publicKey.toString('hex'));
	});

	it('should exclude existing peers', () => {
		const self = makeKeypair();
		const peerA = makeKeypair();
		const peerB = makeKeypair();
		const unrelated = makeKeypair();

		addChannel(graph, self, peerA);
		addChannel(graph, peerA, peerB);
		addChannel(graph, peerB, unrelated);

		const excludeSet = new Set([peerA.publicKey.toString('hex')]);
		const result = suggestions.suggest(graph, self.publicKey.toString('hex'), {
			excludeNodeIds: excludeSet
		});

		const nodeIds = result.map((s) => s.nodeId);
		expect(nodeIds).to.not.include(peerA.publicKey.toString('hex'));
	});

	it('should score connectivity (more channels = higher score)', () => {
		const self = makeKeypair();
		const hubNode = makeKeypair();
		const leafNode = makeKeypair();
		const extra1 = makeKeypair();
		const extra2 = makeKeypair();
		const extra3 = makeKeypair();

		// hubNode has 4 channels, leafNode has 1
		addChannel(graph, hubNode, leafNode);
		addChannel(graph, hubNode, extra1);
		addChannel(graph, hubNode, extra2);
		addChannel(graph, hubNode, extra3);

		const result = suggestions.suggest(graph, self.publicKey.toString('hex'));
		const hub = result.find(
			(s) => s.nodeId === hubNode.publicKey.toString('hex')
		);
		const leaf = result.find(
			(s) => s.nodeId === leafNode.publicKey.toString('hex')
		);

		expect(hub).to.exist;
		expect(leaf).to.exist;
		expect(hub!.score).to.be.greaterThan(leaf!.score);
		expect(hub!.channelCount).to.equal(4);
		expect(leaf!.channelCount).to.equal(1);
	});

	it('should score capacity (larger channels = higher score)', () => {
		const self = makeKeypair();
		const bigNode = makeKeypair();
		const smallNode = makeKeypair();
		const peerA = makeKeypair();
		const peerB = makeKeypair();

		const now = Math.floor(Date.now() / 1000);

		// bigNode: high capacity channel
		addChannel(graph, bigNode, peerA, {
			htlcMaximumMsat: 10_000_000_000n,
			timestamp: now
		});

		// smallNode: low capacity channel
		addChannel(graph, smallNode, peerB, {
			htlcMaximumMsat: 100_000n,
			timestamp: now
		});

		const result = suggestions.suggest(graph, self.publicKey.toString('hex'));
		const big = result.find(
			(s) => s.nodeId === bigNode.publicKey.toString('hex')
		);
		const small = result.find(
			(s) => s.nodeId === smallNode.publicKey.toString('hex')
		);

		expect(big).to.exist;
		expect(small).to.exist;
		expect(big!.score).to.be.greaterThan(small!.score);
		expect(big!.totalCapacitySats).to.be.greaterThan(small!.totalCapacitySats);
	});

	it('should score freshness (recent updates = higher)', () => {
		const self = makeKeypair();
		const recentNode = makeKeypair();
		const staleNode = makeKeypair();
		const peerA = makeKeypair();
		const peerB = makeKeypair();

		const now = Math.floor(Date.now() / 1000);
		const weekAgo = now - 7 * 24 * 3600;

		// recentNode: updated recently
		addChannel(graph, recentNode, peerA, { timestamp: now });

		// staleNode: updated a week ago
		addChannel(graph, staleNode, peerB, { timestamp: weekAgo });

		const result = suggestions.suggest(graph, self.publicKey.toString('hex'));
		const recent = result.find(
			(s) => s.nodeId === recentNode.publicKey.toString('hex')
		);
		const stale = result.find(
			(s) => s.nodeId === staleNode.publicKey.toString('hex')
		);

		expect(recent).to.exist;
		expect(stale).to.exist;
		expect(recent!.score).to.be.greaterThan(stale!.score);
	});

	it('should give relevance bonus to payment destinations', () => {
		const self = makeKeypair();
		const destNode = makeKeypair();
		const otherNode = makeKeypair();
		const peerA = makeKeypair();
		const peerB = makeKeypair();

		const now = Math.floor(Date.now() / 1000);

		// Both nodes have identical connectivity, capacity, freshness
		addChannel(graph, destNode, peerA, {
			timestamp: now,
			htlcMaximumMsat: 1_000_000_000n
		});
		addChannel(graph, otherNode, peerB, {
			timestamp: now,
			htlcMaximumMsat: 1_000_000_000n
		});

		const paymentDestinations = new Set([destNode.publicKey.toString('hex')]);
		const result = suggestions.suggest(graph, self.publicKey.toString('hex'), {
			paymentDestinations
		});

		const dest = result.find(
			(s) => s.nodeId === destNode.publicKey.toString('hex')
		);
		const other = result.find(
			(s) => s.nodeId === otherNode.publicKey.toString('hex')
		);

		expect(dest).to.exist;
		expect(other).to.exist;
		expect(dest!.score).to.be.greaterThan(other!.score);
		expect(dest!.reason).to.include('relevant to your payments');
	});

	it('should give partial relevance to neighbors of destinations', () => {
		const self = makeKeypair();
		const destNode = makeKeypair();
		const neighborNode = makeKeypair();
		const unrelatedNode = makeKeypair();
		const peerA = makeKeypair();

		const now = Math.floor(Date.now() / 1000);

		// destNode and neighborNode share a channel
		addChannel(graph, destNode, neighborNode, {
			timestamp: now,
			htlcMaximumMsat: 1_000_000_000n
		});
		// unrelatedNode has its own channel
		addChannel(graph, unrelatedNode, peerA, {
			timestamp: now,
			htlcMaximumMsat: 1_000_000_000n
		});

		const paymentDestinations = new Set([destNode.publicKey.toString('hex')]);
		const result = suggestions.suggest(graph, self.publicKey.toString('hex'), {
			paymentDestinations
		});

		const neighbor = result.find(
			(s) => s.nodeId === neighborNode.publicKey.toString('hex')
		);
		const unrelated = result.find(
			(s) => s.nodeId === unrelatedNode.publicKey.toString('hex')
		);

		expect(neighbor).to.exist;
		expect(unrelated).to.exist;
		// neighborNode gets partial relevance (10pts), unrelatedNode gets 0
		expect(neighbor!.score).to.be.greaterThan(unrelated!.score);
	});

	it('should respect maxResults limit', () => {
		const self = makeKeypair();
		const nodes: ReturnType<typeof makeKeypair>[] = [];
		for (let i = 0; i < 10; i++) {
			nodes.push(makeKeypair());
		}

		// Create a chain of channels: node0-node1, node1-node2, ...
		for (let i = 0; i < nodes.length - 1; i++) {
			addChannel(graph, nodes[i], nodes[i + 1]);
		}

		const result = suggestions.suggest(graph, self.publicKey.toString('hex'), {
			maxResults: 3
		});

		expect(result).to.have.length(3);
	});

	it('should sort by score descending', () => {
		const self = makeKeypair();

		// Create an isolated hub node with many unique leaf nodes
		const hub = makeKeypair();
		const leaves: ReturnType<typeof makeKeypair>[] = [];
		for (let i = 0; i < 6; i++) {
			leaves.push(makeKeypair());
		}

		const now = Math.floor(Date.now() / 1000);

		// hub gets 6 channels (one to each leaf)
		for (const leaf of leaves) {
			addChannel(graph, hub, leaf, { timestamp: now });
		}

		const result = suggestions.suggest(graph, self.publicKey.toString('hex'), {
			maxResults: 10
		});

		expect(result.length).to.be.greaterThan(1);

		// Verify sorted descending by score
		for (let i = 1; i < result.length; i++) {
			expect(result[i - 1].score).to.be.at.least(result[i].score);
		}

		// hub should be first (6 channels vs 1 for each leaf)
		expect(result[0].nodeId).to.equal(hub.publicKey.toString('hex'));
		expect(result[0].channelCount).to.equal(6);
	});
});
