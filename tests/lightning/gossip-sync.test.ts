/**
 * Phase 5: Gossip Sync (BOLT 7 §4) tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	encodeShortChannelIds,
	encodeShortChannelIdsCompressed,
	decodeShortChannelIds
} from '../../src/lightning/gossip/scid-encoding';
import {
	encodeQueryChannelRangeMessage,
	decodeQueryChannelRangeMessage,
	encodeReplyChannelRangeMessage,
	decodeReplyChannelRangeMessage,
	encodeQueryShortChannelIdsMessage,
	decodeQueryShortChannelIdsMessage,
	encodeReplyShortChannelIdsEndMessage,
	decodeReplyShortChannelIdsEndMessage,
	encodeGossipTimestampFilterMessage,
	decodeGossipTimestampFilterMessage
} from '../../src/lightning/gossip/gossip-queries';
import {
	encodeShortChannelId,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage
} from '../../src/lightning/gossip/types';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	GossipSyncManager,
	GossipSyncState
} from '../../src/lightning/gossip/gossip-sync';
import { MessageType } from '../../src/lightning/message/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Feature } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

// ── Helpers ────────────────────────────────────────────────────────

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

function makeScid(block: number, txIndex: number, outputIndex: number): Buffer {
	return encodeShortChannelId({ block, txIndex, outputIndex });
}

/**
 * Create a mock channel announcement for two nodes with a given SCID.
 * Node IDs are ordered so nodeId1 < nodeId2 lexicographically.
 */
function makeChannelAnnouncement(
	scid: Buffer,
	nodeId1: Buffer,
	nodeId2: Buffer
): IChannelAnnouncementMessage {
	// Ensure correct ordering
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

function makeChannelUpdate(
	scid: Buffer,
	direction: number,
	timestamp: number
): IChannelUpdateMessage {
	return {
		signature: crypto.randomBytes(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp,
		messageFlags: 0x01,
		channelFlags: direction,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
}

function makeNodeAnnouncement(
	nodeId: Buffer,
	timestamp: number
): INodeAnnouncementMessage {
	return {
		signature: crypto.randomBytes(64),
		features: Buffer.alloc(0),
		timestamp,
		nodeId,
		rgbColor: Buffer.from([255, 0, 0]),
		alias: Buffer.alloc(32),
		addresses: []
	};
}

function populateGraph(graph: NetworkGraph, channelCount: number): Buffer[] {
	const scids: Buffer[] = [];
	for (let i = 0; i < channelCount; i++) {
		const scid = makeScid(100 + i, 1, 0);
		const node1 = Buffer.alloc(33, 0);
		node1[0] = 0x02;
		node1[32] = i * 2 + 1;
		const node2 = Buffer.alloc(33, 0);
		node2[0] = 0x02;
		node2[32] = i * 2 + 2;
		graph.addChannelAnnouncement(makeChannelAnnouncement(scid, node1, node2));
		graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1000 + i));
		graph.applyChannelUpdate(makeChannelUpdate(scid, 1, 1000 + i));
		graph.applyNodeAnnouncement(makeNodeAnnouncement(node1, 1000 + i));
		graph.applyNodeAnnouncement(makeNodeAnnouncement(node2, 1000 + i));
		scids.push(scid);
	}
	return scids;
}

// ── Tests ──────────────────────────────────────────────────────────

describe('Gossip Sync (Phase 5)', function () {
	describe('SCID Encoding', function () {
		it('should encode/decode raw (type 0) round-trip', function () {
			const scids = [
				makeScid(100, 1, 0),
				makeScid(200, 2, 1),
				makeScid(300, 3, 2)
			];
			const encoded = encodeShortChannelIds(scids);
			expect(encoded[0]).to.equal(0); // type 0
			expect(encoded.length).to.equal(1 + 3 * 8);

			const decoded = decodeShortChannelIds(encoded);
			expect(decoded.length).to.equal(3);
			for (let i = 0; i < 3; i++) {
				expect(decoded[i].equals(scids[i])).to.be.true;
			}
		});

		it('rejects the removed zlib (type 1) encoding (S-7.M3)', function () {
			const scids = [makeScid(500, 10, 0), makeScid(600, 20, 1)];
			const encoded = encodeShortChannelIdsCompressed(scids);
			expect(encoded[0]).to.equal(1); // type 1
			// BOLT 7 removed the zlib encoding; decoding it is unsupported.
			expect(() => decodeShortChannelIds(encoded)).to.throw(/type 1/i);
		});

		it('does not inflate a type-1 decompression bomb (S-7.M3)', function () {
			const zlib = require('zlib');
			// ~10 MB of zeros compresses to a few KB; the old decoder would
			// inflateSync it with no cap. The fix rejects type 1 before inflating.
			const bomb = Buffer.concat([
				Buffer.from([0x01]),
				zlib.deflateSync(Buffer.alloc(10_000_000))
			]);
			expect(bomb.length).to.be.lessThan(100_000);
			expect(() => decodeShortChannelIds(bomb)).to.throw(/type 1/i);
		});

		it('should handle empty SCID list', function () {
			const encoded = encodeShortChannelIds([]);
			expect(encoded.length).to.equal(1); // just type byte
			const decoded = decodeShortChannelIds(encoded);
			expect(decoded.length).to.equal(0);
		});

		it('should reject unknown encoding type', function () {
			const bad = Buffer.from([0x05, 0x00]);
			expect(() => decodeShortChannelIds(bad)).to.throw(
				'Unknown SCID encoding type'
			);
		});

		it('should reject non-multiple-of-8 body', function () {
			const bad = Buffer.from([0x00, 0x01, 0x02, 0x03]); // type 0, 3 bytes
			expect(() => decodeShortChannelIds(bad)).to.throw('not a multiple of 8');
		});
	});

	describe('Query Message Codecs', function () {
		it('should encode/decode query_channel_range (263)', function () {
			const chainHash = crypto.randomBytes(32);
			const msg = { chainHash, firstBlocknum: 100000, numberOfBlocks: 50000 };
			const encoded = encodeQueryChannelRangeMessage(msg);
			const decoded = decodeQueryChannelRangeMessage(encoded);
			expect(decoded.chainHash.equals(chainHash)).to.be.true;
			expect(decoded.firstBlocknum).to.equal(100000);
			expect(decoded.numberOfBlocks).to.equal(50000);
		});

		it('should encode/decode reply_channel_range (264)', function () {
			const chainHash = crypto.randomBytes(32);
			const scids = encodeShortChannelIds([makeScid(100, 1, 0)]);
			const msg = {
				chainHash,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff,
				syncComplete: true,
				encodedShortIds: scids
			};
			const encoded = encodeReplyChannelRangeMessage(msg);
			const decoded = decodeReplyChannelRangeMessage(encoded);
			expect(decoded.chainHash.equals(chainHash)).to.be.true;
			expect(decoded.firstBlocknum).to.equal(0);
			expect(decoded.numberOfBlocks).to.equal(0xffffffff);
			expect(decoded.syncComplete).to.be.true;
			expect(decoded.encodedShortIds.equals(scids)).to.be.true;
		});

		it('should encode/decode reply_channel_range with syncComplete=false', function () {
			const chainHash = crypto.randomBytes(32);
			const msg = {
				chainHash,
				firstBlocknum: 50,
				numberOfBlocks: 100,
				syncComplete: false,
				encodedShortIds: encodeShortChannelIds([])
			};
			const encoded = encodeReplyChannelRangeMessage(msg);
			const decoded = decodeReplyChannelRangeMessage(encoded);
			expect(decoded.syncComplete).to.be.false;
		});

		it('should encode/decode query_short_channel_ids (261)', function () {
			const chainHash = crypto.randomBytes(32);
			const encoded_scids = encodeShortChannelIds([
				makeScid(100, 1, 0),
				makeScid(200, 2, 1)
			]);
			const msg = { chainHash, encodedShortIds: encoded_scids };
			const encoded = encodeQueryShortChannelIdsMessage(msg);
			const decoded = decodeQueryShortChannelIdsMessage(encoded);
			expect(decoded.chainHash.equals(chainHash)).to.be.true;
			expect(decoded.encodedShortIds.equals(encoded_scids)).to.be.true;
		});

		it('should encode/decode reply_short_channel_ids_end (262)', function () {
			const chainHash = crypto.randomBytes(32);
			const msg = { chainHash, complete: true };
			const encoded = encodeReplyShortChannelIdsEndMessage(msg);
			expect(encoded.length).to.equal(33);
			const decoded = decodeReplyShortChannelIdsEndMessage(encoded);
			expect(decoded.chainHash.equals(chainHash)).to.be.true;
			expect(decoded.complete).to.be.true;
		});

		it('should encode/decode reply_short_channel_ids_end with complete=false', function () {
			const chainHash = crypto.randomBytes(32);
			const encoded = encodeReplyShortChannelIdsEndMessage({
				chainHash,
				complete: false
			});
			const decoded = decodeReplyShortChannelIdsEndMessage(encoded);
			expect(decoded.complete).to.be.false;
		});

		it('should encode/decode gossip_timestamp_filter (265)', function () {
			const chainHash = crypto.randomBytes(32);
			const msg = {
				chainHash,
				firstTimestamp: 1700000000,
				timestampRange: 86400
			};
			const encoded = encodeGossipTimestampFilterMessage(msg);
			expect(encoded.length).to.equal(40);
			const decoded = decodeGossipTimestampFilterMessage(encoded);
			expect(decoded.chainHash.equals(chainHash)).to.be.true;
			expect(decoded.firstTimestamp).to.equal(1700000000);
			expect(decoded.timestampRange).to.equal(86400);
		});

		it('should reject too-short payloads', function () {
			expect(() => decodeQueryChannelRangeMessage(Buffer.alloc(10))).to.throw(
				'too short'
			);
			expect(() => decodeReplyChannelRangeMessage(Buffer.alloc(10))).to.throw(
				'too short'
			);
			expect(() =>
				decodeQueryShortChannelIdsMessage(Buffer.alloc(10))
			).to.throw('too short');
			expect(() =>
				decodeReplyShortChannelIdsEndMessage(Buffer.alloc(10))
			).to.throw('too short');
			expect(() =>
				decodeGossipTimestampFilterMessage(Buffer.alloc(10))
			).to.throw('too short');
		});
	});

	describe('NetworkGraph Sync Methods', function () {
		it('should get channels by block range', function () {
			const graph = new NetworkGraph();
			populateGraph(graph, 5); // blocks 100-104

			const result = graph.getChannelsByBlockRange(101, 3); // blocks 101, 102, 103
			expect(result.length).to.equal(3);
		});

		it('should return empty for block range with no channels', function () {
			const graph = new NetworkGraph();
			populateGraph(graph, 3); // blocks 100-102

			const result = graph.getChannelsByBlockRange(500, 100);
			expect(result.length).to.equal(0);
		});

		it('should return sorted SCIDs by block range', function () {
			const graph = new NetworkGraph();
			populateGraph(graph, 5);

			const result = graph.getChannelsByBlockRange(100, 5);
			expect(result.length).to.equal(5);
			for (let i = 1; i < result.length; i++) {
				expect(Buffer.compare(result[i - 1], result[i])).to.be.lessThan(0);
			}
		});

		it('should find missing SCIDs', function () {
			const graph = new NetworkGraph();
			const existing = populateGraph(graph, 3);

			const remote = [...existing, makeScid(999, 1, 0), makeScid(998, 2, 0)];
			const missing = graph.getMissingSCIDs(remote);
			expect(missing.length).to.equal(2);
		});

		it('should return empty when no SCIDs are missing', function () {
			const graph = new NetworkGraph();
			const existing = populateGraph(graph, 3);

			const missing = graph.getMissingSCIDs(existing);
			expect(missing.length).to.equal(0);
		});

		it('should get gossip messages for channels', function () {
			const graph = new NetworkGraph();
			const scids = populateGraph(graph, 3);

			const result = graph.getGossipMessagesForChannels(scids);
			expect(result.announcements.length).to.equal(3);
			expect(result.updates.length).to.equal(6); // 2 per channel
			expect(result.nodeAnnouncements.length).to.equal(6); // 2 per channel
		});

		it('should deduplicate node announcements', function () {
			const graph = new NetworkGraph();
			// Create two channels sharing one node
			const sharedNode = Buffer.alloc(33, 0);
			sharedNode[0] = 0x02;
			sharedNode[32] = 0x01;

			const node2 = Buffer.alloc(33, 0);
			node2[0] = 0x02;
			node2[32] = 0x02;

			const node3 = Buffer.alloc(33, 0);
			node3[0] = 0x02;
			node3[32] = 0x03;

			const scid1 = makeScid(100, 1, 0);
			const scid2 = makeScid(100, 2, 0);
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(scid1, sharedNode, node2)
			);
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(scid2, sharedNode, node3)
			);
			graph.applyNodeAnnouncement(makeNodeAnnouncement(sharedNode, 1000));
			graph.applyNodeAnnouncement(makeNodeAnnouncement(node2, 1000));
			graph.applyNodeAnnouncement(makeNodeAnnouncement(node3, 1000));

			const result = graph.getGossipMessagesForChannels([scid1, scid2]);
			// sharedNode appears in both channels but should only be returned once
			expect(result.nodeAnnouncements.length).to.equal(3); // sharedNode + node2 + node3 (deduplicated)
		});

		it('should skip unknown SCIDs', function () {
			const graph = new NetworkGraph();
			populateGraph(graph, 2);

			const result = graph.getGossipMessagesForChannels([makeScid(999, 1, 0)]);
			expect(result.announcements.length).to.equal(0);
			expect(result.updates.length).to.equal(0);
			expect(result.nodeAnnouncements.length).to.equal(0);
		});
	});

	describe('GossipSyncManager — Initiating Side', function () {
		it('should start in IDLE state', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);
			expect(mgr.getState()).to.equal(GossipSyncState.IDLE);
		});

		it('should send timestamp_filter + query_channel_range on initiateSync', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);

			const messages = mgr.initiateSync();
			expect(messages.length).to.equal(2);
			expect(messages[0].type).to.equal(MessageType.GOSSIP_TIMESTAMP_FILTER);
			expect(messages[1].type).to.equal(MessageType.QUERY_CHANNEL_RANGE);
			expect(mgr.getState()).to.equal(GossipSyncState.AWAITING_RANGE_REPLY);

			// Verify query is for full range
			const query = decodeQueryChannelRangeMessage(messages[1].payload);
			expect(query.firstBlocknum).to.equal(0);
			expect(query.numberOfBlocks).to.equal(0xffffffff);
		});

		it('should transition to SYNCED when no missing SCIDs', function () {
			const graph = new NetworkGraph();
			populateGraph(graph, 3);
			const mgr = new GossipSyncManager(graph);

			mgr.initiateSync();

			// Peer replies with same SCIDs we already have
			const allScids = graph.getAllChannelIds();
			const encodedScids = encodeShortChannelIds(allScids);
			const messages = mgr.handleReplyChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff,
				syncComplete: true,
				encodedShortIds: encodedScids
			});

			expect(messages.length).to.equal(0);
			expect(mgr.getState()).to.equal(GossipSyncState.SYNCED);
		});

		it('should query missing SCIDs', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);

			mgr.initiateSync();

			// Peer has 3 channels we don't
			const remoteScids = [
				makeScid(100, 1, 0),
				makeScid(200, 2, 0),
				makeScid(300, 3, 0)
			];
			const messages = mgr.handleReplyChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff,
				syncComplete: true,
				encodedShortIds: encodeShortChannelIds(remoteScids)
			});

			expect(messages.length).to.equal(1);
			expect(messages[0].type).to.equal(MessageType.QUERY_SHORT_CHANNEL_IDS);
			expect(mgr.getState()).to.equal(GossipSyncState.AWAITING_SCID_REPLY);

			// Decode and verify the query contains all 3 SCIDs
			const query = decodeQueryShortChannelIdsMessage(messages[0].payload);
			const queriedScids = decodeShortChannelIds(query.encodedShortIds);
			expect(queriedScids.length).to.equal(3);
		});

		it('should handle multi-chunk reply_channel_range', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);

			mgr.initiateSync();

			// First chunk — not complete
			const chunk1 = [makeScid(100, 1, 0), makeScid(200, 2, 0)];
			let messages = mgr.handleReplyChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff,
				syncComplete: false,
				encodedShortIds: encodeShortChannelIds(chunk1)
			});
			expect(messages.length).to.equal(0); // waiting for more chunks

			// Second chunk — complete
			const chunk2 = [makeScid(300, 3, 0)];
			messages = mgr.handleReplyChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff,
				syncComplete: true,
				encodedShortIds: encodeShortChannelIds(chunk2)
			});

			// Should query all 3 missing SCIDs
			expect(messages.length).to.equal(1);
			const query = decodeQueryShortChannelIdsMessage(messages[0].payload);
			const queriedScids = decodeShortChannelIds(query.encodedShortIds);
			expect(queriedScids.length).to.equal(3);
		});

		it('should transition to SYNCED after reply_short_channel_ids_end', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);

			mgr.initiateSync();

			// Peer has 1 channel we don't
			mgr.handleReplyChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff,
				syncComplete: true,
				encodedShortIds: encodeShortChannelIds([makeScid(100, 1, 0)])
			});

			// Peer finishes sending gossip data
			const messages = mgr.handleReplyShortChannelIdsEnd({
				chainHash: BITCOIN_CHAIN_HASH,
				complete: true
			});

			expect(messages.length).to.equal(0);
			expect(mgr.getState()).to.equal(GossipSyncState.SYNCED);
		});

		it('should emit synced event', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);
			let synced = false;
			mgr.on('synced', () => {
				synced = true;
			});

			mgr.initiateSync();
			mgr.handleReplyChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff,
				syncComplete: true,
				encodedShortIds: encodeShortChannelIds([])
			});

			expect(synced).to.be.true;
			expect(mgr.getState()).to.equal(GossipSyncState.SYNCED);
		});
	});

	describe('GossipSyncManager — Responding Side', function () {
		it('should respond to query_channel_range with matching channels', function () {
			const graph = new NetworkGraph();
			populateGraph(graph, 5); // blocks 100-104

			const mgr = new GossipSyncManager(graph);
			const messages = mgr.handleQueryChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 101,
				numberOfBlocks: 2
			});

			expect(messages.length).to.equal(1);
			expect(messages[0].type).to.equal(MessageType.REPLY_CHANNEL_RANGE);

			const reply = decodeReplyChannelRangeMessage(messages[0].payload);
			expect(reply.syncComplete).to.be.true;
			const scids = decodeShortChannelIds(reply.encodedShortIds);
			expect(scids.length).to.equal(2); // blocks 101, 102
		});

		it('should respond to empty query_channel_range', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);

			const messages = mgr.handleQueryChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 100
			});

			expect(messages.length).to.equal(1);
			const reply = decodeReplyChannelRangeMessage(messages[0].payload);
			expect(reply.syncComplete).to.be.true;
			const scids = decodeShortChannelIds(reply.encodedShortIds);
			expect(scids.length).to.equal(0);
		});

		it('should respond to query_short_channel_ids with gossip + end marker', function () {
			const graph = new NetworkGraph();
			const scids = populateGraph(graph, 2);

			const mgr = new GossipSyncManager(graph);
			const encoded = encodeShortChannelIds(scids);
			const messages = mgr.handleQueryShortChannelIds({
				chainHash: BITCOIN_CHAIN_HASH,
				encodedShortIds: encoded
			});

			// Should have: 2 announcements + 4 updates + 4 node announcements + 1 end marker = 11
			const announcements = messages.filter(
				(m) => m.type === MessageType.CHANNEL_ANNOUNCEMENT
			);
			const updates = messages.filter(
				(m) => m.type === MessageType.CHANNEL_UPDATE
			);
			const nodeAnns = messages.filter(
				(m) => m.type === MessageType.NODE_ANNOUNCEMENT
			);
			const endMarkers = messages.filter(
				(m) => m.type === MessageType.REPLY_SHORT_CHANNEL_IDS_END
			);

			expect(announcements.length).to.equal(2);
			expect(updates.length).to.equal(4);
			expect(nodeAnns.length).to.equal(4);
			expect(endMarkers.length).to.equal(1);

			const end = decodeReplyShortChannelIdsEndMessage(endMarkers[0].payload);
			expect(end.complete).to.be.true;
		});

		it('should respond to query_short_channel_ids with unknown SCIDs', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph);

			const messages = mgr.handleQueryShortChannelIds({
				chainHash: BITCOIN_CHAIN_HASH,
				encodedShortIds: encodeShortChannelIds([makeScid(999, 1, 0)])
			});

			// Just the end marker
			expect(messages.length).to.equal(1);
			expect(messages[0].type).to.equal(
				MessageType.REPLY_SHORT_CHANNEL_IDS_END
			);
		});
	});

	describe('Full Sync Protocol Simulation', function () {
		it('should complete full sync between two graphs', function () {
			// Graph A has channels at blocks 100-102
			const graphA = new NetworkGraph();
			populateGraph(graphA, 3);

			// Graph B has channels at blocks 200-201
			const graphB = new NetworkGraph();
			const node1 = Buffer.alloc(33, 0);
			node1[0] = 0x02;
			node1[32] = 0xa1;
			const node2 = Buffer.alloc(33, 0);
			node2[0] = 0x02;
			node2[32] = 0xa2;
			const node3 = Buffer.alloc(33, 0);
			node3[0] = 0x02;
			node3[32] = 0xa3;
			const scidB1 = makeScid(200, 1, 0);
			const scidB2 = makeScid(201, 1, 0);
			graphB.addChannelAnnouncement(
				makeChannelAnnouncement(scidB1, node1, node2)
			);
			graphB.addChannelAnnouncement(
				makeChannelAnnouncement(scidB2, node2, node3)
			);

			const syncA = new GossipSyncManager(graphA);
			const syncB = new GossipSyncManager(graphB);

			// A initiates sync with B
			const initMessages = syncA.initiateSync();
			expect(initMessages.length).to.equal(2);

			// B responds to query_channel_range
			const rangeQuery = decodeQueryChannelRangeMessage(
				initMessages[1].payload
			);
			const rangeReplies = syncB.handleQueryChannelRange(rangeQuery);

			// A processes range reply
			const rangeReply = decodeReplyChannelRangeMessage(
				rangeReplies[0].payload
			);
			const scidQueries = syncA.handleReplyChannelRange(rangeReply);

			// A should query the 2 channels it's missing from B
			expect(scidQueries.length).to.equal(1);
			const query = decodeQueryShortChannelIdsMessage(scidQueries[0].payload);
			const requestedScids = decodeShortChannelIds(query.encodedShortIds);
			expect(requestedScids.length).to.equal(2);

			// B responds to SCID query
			const gossipMessages = syncB.handleQueryShortChannelIds({
				chainHash: BITCOIN_CHAIN_HASH,
				encodedShortIds: query.encodedShortIds
			});

			// Last message should be reply_short_channel_ids_end
			const endMsg = gossipMessages[gossipMessages.length - 1];
			expect(endMsg.type).to.equal(MessageType.REPLY_SHORT_CHANNEL_IDS_END);

			// A processes end marker
			const endDecoded = decodeReplyShortChannelIdsEndMessage(endMsg.payload);
			const finalMessages = syncA.handleReplyShortChannelIdsEnd(endDecoded);
			expect(finalMessages.length).to.equal(0);
			expect(syncA.getState()).to.equal(GossipSyncState.SYNCED);
		});
	});

	describe('LightningNode Integration', function () {
		function makeNode(): LightningNode {
			return new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: makeBasepoints(),
				fundingPrivkey: crypto.randomBytes(32)
			});
		}

		it('should have GOSSIP_QUERIES in default features', function () {
			const features = LightningNode.defaultFeatures();
			expect(features.hasFeature(Feature.GOSSIP_QUERIES)).to.be.true;
		});

		it('should initiate gossip sync and send messages', function () {
			const node = makeNode();
			const outbound: Array<{ pubkey: string; type: number; payload: Buffer }> =
				[];
			node.on(
				'message:outbound',
				(pubkey: string, type: number, payload: Buffer) => {
					outbound.push({ pubkey, type, payload });
				}
			);

			node.initiateGossipSync('deadbeef'.repeat(8) + '02');
			expect(outbound.length).to.equal(2);
			expect(outbound[0].type).to.equal(MessageType.GOSSIP_TIMESTAMP_FILTER);
			expect(outbound[1].type).to.equal(MessageType.QUERY_CHANNEL_RANGE);
			node.destroy();
		});

		it('should handle inbound query_channel_range via handlePeerMessage', function () {
			const node = makeNode();
			const outbound: Array<{ pubkey: string; type: number; payload: Buffer }> =
				[];
			node.on(
				'message:outbound',
				(pubkey: string, type: number, payload: Buffer) => {
					outbound.push({ pubkey, type, payload });
				}
			);

			const peerPubkey = 'aa'.repeat(33);
			const queryPayload = encodeQueryChannelRangeMessage({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff
			});

			node.handlePeerMessage(
				peerPubkey,
				MessageType.QUERY_CHANNEL_RANGE,
				queryPayload
			);

			// Should respond with reply_channel_range
			expect(outbound.length).to.equal(1);
			expect(outbound[0].type).to.equal(MessageType.REPLY_CHANNEL_RANGE);
			node.destroy();
		});

		it('should handle inbound query_short_channel_ids via handlePeerMessage', function () {
			const node = makeNode();
			const outbound: Array<{ pubkey: string; type: number; payload: Buffer }> =
				[];
			node.on(
				'message:outbound',
				(pubkey: string, type: number, payload: Buffer) => {
					outbound.push({ pubkey, type, payload });
				}
			);

			const peerPubkey = 'bb'.repeat(33);
			const queryPayload = encodeQueryShortChannelIdsMessage({
				chainHash: BITCOIN_CHAIN_HASH,
				encodedShortIds: encodeShortChannelIds([makeScid(100, 1, 0)])
			});

			node.handlePeerMessage(
				peerPubkey,
				MessageType.QUERY_SHORT_CHANNEL_IDS,
				queryPayload
			);

			// Should respond with at least reply_short_channel_ids_end
			expect(outbound.length).to.be.greaterThan(0);
			const lastMsg = outbound[outbound.length - 1];
			expect(lastMsg.type).to.equal(MessageType.REPLY_SHORT_CHANNEL_IDS_END);
			node.destroy();
		});

		it('should get gossip sync state', function () {
			const node = makeNode();
			const peerPubkey = 'cc'.repeat(33);

			// No sync manager yet
			expect(node.getGossipSyncState(peerPubkey)).to.be.null;

			// Initiate sync
			node.initiateGossipSync(peerPubkey);
			expect(node.getGossipSyncState(peerPubkey)).to.equal(
				GossipSyncState.AWAITING_RANGE_REPLY
			);
			node.destroy();
		});

		it('should handle gossip_timestamp_filter without error', function () {
			const node = makeNode();
			const peerPubkey = 'dd'.repeat(33);
			const payload = encodeGossipTimestampFilterMessage({
				chainHash: BITCOIN_CHAIN_HASH,
				firstTimestamp: 0,
				timestampRange: 0xffffffff
			});

			// Should not throw
			node.handlePeerMessage(
				peerPubkey,
				MessageType.GOSSIP_TIMESTAMP_FILTER,
				payload
			);
			node.destroy();
		});

		it('should clean up gossip sync managers on destroy', function () {
			const node = makeNode();
			node.initiateGossipSync('ee'.repeat(33));
			expect(node.getGossipSyncState('ee'.repeat(33))).to.not.be.null;
			node.destroy();
			expect(node.getGossipSyncState('ee'.repeat(33))).to.be.null;
		});
	});
});
