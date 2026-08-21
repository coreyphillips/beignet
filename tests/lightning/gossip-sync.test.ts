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
import {
	decodeChannelAnnouncementMessage,
	encodeChannelAnnouncementMessage
} from '../../src/lightning/gossip/messages';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	makeSignedChannelKeys,
	makeSignedChannelAnnouncement,
	makeSignedChannelUpdate,
	makeSignedNodeAnnouncement
} from './helpers/signed-gossip';
import {
	GossipSyncManager,
	GossipSyncState
} from '../../src/lightning/gossip/gossip-sync';
import { MessageType } from '../../src/lightning/message/types';
import {
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Feature } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

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

async function waitFor(
	condition: () => boolean,
	timeoutMs = 5_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() >= deadline) {
			throw new Error('Timed out waiting for gossip sync state');
		}
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

/**
 * Create a mock channel announcement for two nodes with a given SCID.
 * Node IDs are ordered so nodeId1 < nodeId2 lexicographically.
 */
function makeChannelAnnouncement(
	scid: Buffer,
	nodeId1: Buffer,
	nodeId2: Buffer,
	chainHash = BITCOIN_CHAIN_HASH
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
		chainHash,
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
	timestamp: number,
	chainHash = BITCOIN_CHAIN_HASH
): IChannelUpdateMessage {
	return {
		signature: crypto.randomBytes(64),
		chainHash,
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

function populateGraph(
	graph: NetworkGraph,
	channelCount: number,
	chainHash = BITCOIN_CHAIN_HASH
): Buffer[] {
	const scids: Buffer[] = [];
	for (let i = 0; i < channelCount; i++) {
		const scid = makeScid(100 + i, 1, 0);
		const node1 = Buffer.alloc(33, 0);
		node1[0] = 0x02;
		node1[32] = i * 2 + 1;
		const node2 = Buffer.alloc(33, 0);
		node2[0] = 0x02;
		node2[32] = i * 2 + 2;
		// Marked verified so the serving-side tests exercise the responder
		// mechanics; unverified entries are never served (#340).
		graph.addChannelAnnouncement(
			makeChannelAnnouncement(scid, node1, node2, chainHash),
			{ verified: true }
		);
		graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1000 + i, chainHash), {
			verified: true
		});
		graph.applyChannelUpdate(makeChannelUpdate(scid, 1, 1000 + i, chainHash), {
			verified: true
		});
		graph.applyNodeAnnouncement(makeNodeAnnouncement(node1, 1000 + i), {
			verified: true
		});
		graph.applyNodeAnnouncement(makeNodeAnnouncement(node2, 1000 + i), {
			verified: true
		});
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

	describe('chain_hash handling (S-7.M1)', function () {
		it('reply_channel_range echoes the query chain_hash', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph, REGTEST_CHAIN_HASH);
			const reply = mgr.handleQueryChannelRange({
				chainHash: REGTEST_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff
			});
			const decoded = decodeReplyChannelRangeMessage(reply[0].payload);
			expect(decoded.chainHash.equals(REGTEST_CHAIN_HASH)).to.be.true;
		});

		it('outbound queries carry the manager chain_hash, not mainnet', function () {
			const graph = new NetworkGraph();
			const mgr = new GossipSyncManager(graph, REGTEST_CHAIN_HASH);
			const out = mgr.initiateSync();
			// Both gossip_timestamp_filter and query_channel_range start with the
			// chain_hash; it must be regtest, not the hardcoded mainnet.
			for (const m of out) {
				expect(m.payload.subarray(0, 32).equals(REGTEST_CHAIN_HASH)).to.be.true;
				expect(m.payload.subarray(0, 32).equals(BITCOIN_CHAIN_HASH)).to.be
					.false;
			}
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
				makeChannelAnnouncement(scid1, sharedNode, node2),
				{ verified: true }
			);
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(scid2, sharedNode, node3),
				{ verified: true }
			);
			graph.applyNodeAnnouncement(makeNodeAnnouncement(sharedNode, 1000), {
				verified: true
			});
			graph.applyNodeAnnouncement(makeNodeAnnouncement(node2, 1000), {
				verified: true
			});
			graph.applyNodeAnnouncement(makeNodeAnnouncement(node3, 1000), {
				verified: true
			});

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

	describe('Unverified gossip is never served (issue #340)', function () {
		// BOLT 7: a node MUST NOT relay announcements it has not validated.
		// Entries injected without { verified: true } (direct API, RGS) must be
		// excluded from both responder paths; strict peers (eclair 0.14+)
		// disconnect when served an invalid signature.
		function makeNodePair(seed: number): [Buffer, Buffer] {
			const node1 = Buffer.alloc(33, 0);
			node1[0] = 0x02;
			node1[32] = seed;
			const node2 = Buffer.alloc(33, 0);
			node2[0] = 0x02;
			node2[32] = seed + 1;
			return [node1, node2];
		}

		function messageTypes(
			messages: Array<{ type: number }>
		): Record<number, number> {
			const counts: Record<number, number> = {};
			for (const m of messages) counts[m.type] = (counts[m.type] ?? 0) + 1;
			return counts;
		}

		it('excludes unverified channels from reply_channel_range', function () {
			const graph = new NetworkGraph();
			const verifiedScid = makeScid(100, 1, 0);
			const unverifiedScid = makeScid(100, 2, 0);
			const [n1, n2] = makeNodePair(1);
			const [n3, n4] = makeNodePair(3);
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(verifiedScid, n1, n2),
				{ verified: true }
			);
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(unverifiedScid, n3, n4)
			);

			const mgr = new GossipSyncManager(graph);
			const messages = mgr.handleQueryChannelRange({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 100,
				numberOfBlocks: 10
			});
			expect(messages.length).to.equal(1);
			const reply = decodeReplyChannelRangeMessage(messages[0].payload);
			const scids = decodeShortChannelIds(reply.encodedShortIds);
			expect(scids.length).to.equal(1);
			expect(scids[0].equals(verifiedScid)).to.be.true;
		});

		it('excludes unverified channels entirely from query_short_channel_ids replies', function () {
			const graph = new NetworkGraph();
			const verifiedScid = makeScid(100, 1, 0);
			const unverifiedScid = makeScid(100, 2, 0);
			const [n1, n2] = makeNodePair(1);
			const [n3, n4] = makeNodePair(3);
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(verifiedScid, n1, n2),
				{ verified: true }
			);
			graph.applyChannelUpdate(makeChannelUpdate(verifiedScid, 0, 1000), {
				verified: true
			});
			graph.applyNodeAnnouncement(makeNodeAnnouncement(n1, 1000), {
				verified: true
			});
			// Unverified channel with updates and a node announcement: none of
			// them may be served, not even alongside a verified channel.
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(unverifiedScid, n3, n4)
			);
			graph.applyChannelUpdate(makeChannelUpdate(unverifiedScid, 0, 1000));
			graph.applyNodeAnnouncement(makeNodeAnnouncement(n3, 1000));

			const mgr = new GossipSyncManager(graph);
			const messages = mgr.handleQueryShortChannelIds({
				chainHash: BITCOIN_CHAIN_HASH,
				encodedShortIds: encodeShortChannelIds([verifiedScid, unverifiedScid])
			});
			const counts = messageTypes(messages);
			expect(counts[MessageType.CHANNEL_ANNOUNCEMENT]).to.equal(1);
			expect(counts[MessageType.CHANNEL_UPDATE]).to.equal(1);
			expect(counts[MessageType.NODE_ANNOUNCEMENT]).to.equal(1);
			expect(counts[MessageType.REPLY_SHORT_CHANNEL_IDS_END]).to.equal(1);
			const served = decodeChannelAnnouncementMessage(
				messages.find((m) => m.type === MessageType.CHANNEL_ANNOUNCEMENT)!
					.payload
			);
			expect(served.shortChannelId.equals(verifiedScid)).to.be.true;
		});

		it('skips an unverified update on a verified channel while serving the verified direction', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2), {
				verified: true
			});
			graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1000), {
				verified: true
			});
			// RGS-style zero-sig update landing on a verified channel.
			graph.applyChannelUpdate(makeChannelUpdate(scid, 1, 1000));

			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.announcements.length).to.equal(1);
			expect(result.updates.length).to.equal(1);
			expect(result.updates[0].channelFlags & 0x01).to.equal(0);
		});

		it('replaces a verified update with a newer unverified one and stops serving that direction', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2), {
				verified: true
			});
			graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1000), {
				verified: true
			});
			expect(graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 2000))).to.be
				.true;

			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.announcements.length).to.equal(1);
			expect(result.updates.length).to.equal(0);
		});

		it('skips unverified node announcements', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2), {
				verified: true
			});
			graph.applyNodeAnnouncement(makeNodeAnnouncement(n1, 1000), {
				verified: true
			});
			graph.applyNodeAnnouncement(makeNodeAnnouncement(n2, 1000));

			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.nodeAnnouncements.length).to.equal(1);
			expect(result.nodeAnnouncements[0].nodeId.equals(n1)).to.be.true;
		});

		it('never advertises or serves a channel whose update is verified but whose announcement is not', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			// RGS-primed announcement, then a signature-verified update arrives.
			graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2));
			graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1000), {
				verified: true
			});

			expect(graph.getChannelsByBlockRange(100, 10).length).to.equal(0);
			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.announcements.length).to.equal(0);
			expect(result.updates.length).to.equal(0);
			expect(result.nodeAnnouncements.length).to.equal(0);
		});

		it('lets a verified update take over an unverified slot despite an older timestamp', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2), {
				verified: true
			});
			// RGS-style: synthetic update stamped with the snapshot's global
			// latest-seen timestamp.
			graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 2000));
			// The real signed update carries its true, older timestamp and must
			// still win the slot.
			expect(
				graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1500), {
					verified: true
				})
			).to.be.true;
			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.updates.length).to.equal(1);
			expect(result.updates[0].timestamp).to.equal(1500);
		});

		it('keeps rejecting stale updates between slots of equal provenance', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2), {
				verified: true
			});
			graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1500), {
				verified: true
			});
			expect(
				graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1400), {
					verified: true
				})
			).to.be.false;
			graph.applyChannelUpdate(makeChannelUpdate(scid, 1, 2000));
			expect(graph.applyChannelUpdate(makeChannelUpdate(scid, 1, 1900))).to.be
				.false;
		});

		it('lets a verified node announcement take over an unverified one despite an older timestamp', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2), {
				verified: true
			});
			graph.applyNodeAnnouncement(makeNodeAnnouncement(n1, 2000));
			expect(
				graph.applyNodeAnnouncement(makeNodeAnnouncement(n1, 1500), {
					verified: true
				})
			).to.be.true;
			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.nodeAnnouncements.length).to.equal(1);
			expect(result.nodeAnnouncements[0].timestamp).to.equal(1500);
		});

		it('upgrades an unverified channel when a verified announcement for the same SCID arrives', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(100, 1, 0);
			const [n1, n2] = makeNodePair(1);
			const unverifiedAnn = makeChannelAnnouncement(scid, n1, n2);
			graph.addChannelAnnouncement(unverifiedAnn);
			graph.applyChannelUpdate(makeChannelUpdate(scid, 0, 1000));

			// A verified announcement with DIFFERENT endpoints is still rejected.
			const [n3, n4] = makeNodePair(5);
			expect(
				graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n3, n4), {
					verified: true
				})
			).to.be.false;
			expect(graph.getChannelsByBlockRange(100, 10).length).to.equal(0);

			// Same endpoints: the entry upgrades in place and becomes servable.
			expect(
				graph.addChannelAnnouncement(makeChannelAnnouncement(scid, n1, n2), {
					verified: true
				})
			).to.be.true;
			expect(graph.getChannelsByBlockRange(100, 10).length).to.equal(1);
			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.announcements.length).to.equal(1);
			// The pre-upgrade unverified update stays unservable.
			expect(result.updates.length).to.equal(0);
		});
	});

	describe('Deferred gossip provenance (issue #443)', function () {
		// Lazy verification: foreign gossip is admitted as 'deferred' and only
		// verified when a gossip query asks for the entry. The #340 contract
		// (nothing unverified is ever served) must hold throughout.

		/** Two random pubkeys; makeChannelAnnouncement orders them itself. */
		function randomNodePair(): [Buffer, Buffer] {
			return [
				getPublicKey(crypto.randomBytes(32)),
				getPublicKey(crypto.randomBytes(32))
			];
		}

		/** RGS-style entry: all-zero signatures, zero bitcoin keys. */
		function zeroSigAnnouncement(
			msg: IChannelAnnouncementMessage
		): IChannelAnnouncementMessage {
			return {
				...msg,
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				bitcoinKey1: Buffer.alloc(33),
				bitcoinKey2: Buffer.alloc(33)
			};
		}

		it('advertises deferred channels in reply_channel_range without verifying them, never false ones', function () {
			const graph = new NetworkGraph();
			const deferredScid = makeScid(100, 1, 0);
			const falseScid = makeScid(100, 2, 0);
			const signed = makeSignedChannelAnnouncement(
				deferredScid,
				makeSignedChannelKeys()
			);
			graph.addChannelAnnouncement(signed.msg, { verified: 'deferred' });
			// No opts: explicit false (RGS/API injection), never advertised.
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(falseScid, ...randomNodePair())
			);

			const scids = graph.getChannelsByBlockRange(100, 10);
			expect(scids.length).to.equal(1);
			expect(scids[0].equals(deferredScid)).to.be.true;
			// The range scan is the cheap heuristic: it must not verify. The
			// boolean field stays undefined while deferred, so downstream
			// truthiness checks never see unchecked data as verified.
			expect(graph.getChannel(deferredScid)!.announcementVerified).to.equal(
				undefined
			);
			expect(
				graph.getChannel(deferredScid)!.announcementVerifyDeferred
			).to.equal(true);
		});

		it('resolves deferred entries at serve time and serves the genuine ones (sticky)', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(101, 1, 0);
			const keys = makeSignedChannelKeys();
			const ann = makeSignedChannelAnnouncement(scid, keys);
			const upd = makeSignedChannelUpdate(scid, keys.nodeKey1, 0, 1000);
			const nodeAnn = makeSignedNodeAnnouncement(keys.nodeKey1, 1000);
			graph.addChannelAnnouncement(ann.msg, { verified: 'deferred' });
			graph.applyChannelUpdate(upd.msg, { verified: 'deferred' });
			graph.applyNodeAnnouncement(nodeAnn.msg, { verified: 'deferred' });

			const result = graph.getGossipMessagesForChannels([scid]);
			expect(result.announcements.length).to.equal(1);
			expect(result.updates.length).to.equal(1);
			expect(result.nodeAnnouncements.length).to.equal(1);
			// Resolution is sticky: no signature is ever checked twice.
			const ch = graph.getChannel(scid)!;
			expect(ch.announcementVerified).to.be.true;
			expect(ch.update1Verified).to.be.true;
			expect(graph.getNode(nodeAnn.msg.nodeId)!.announcementVerified).to.be
				.true;
		});

		it('resolves garbage-signature deferred entries to false and never serves them', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(102, 1, 0);
			// Random signatures: verification must fail at serve time.
			const garbage = makeChannelAnnouncement(scid, ...randomNodePair());
			graph.addChannelAnnouncement(garbage, { verified: 'deferred' });
			// A genuinely signed update under a failed announcement must stay
			// deferred: its endpoint keys are unauthenticated, so the serve loop
			// never verifies past a non-servable announcement.
			const keys = makeSignedChannelKeys();
			const upd = makeSignedChannelUpdate(scid, keys.nodeKey1, 0, 1000);
			graph.applyChannelUpdate(upd.msg, { verified: 'deferred' });

			expect(graph.getChannelsByBlockRange(102, 5).length).to.equal(1);
			const first = graph.getGossipMessagesForChannels([scid]);
			expect(first.announcements.length).to.equal(0);
			expect(first.updates.length).to.equal(0);
			// A settled failure is not incompleteness: the reply omitted
			// nothing we could ever serve.
			expect(first.complete).to.equal(true);
			expect(graph.getChannel(scid)!.announcementVerified).to.be.false;
			expect(graph.getChannel(scid)!.update1VerifyDeferred).to.equal(true);
			// Resolved false drops out of the range advertisement too.
			expect(graph.getChannelsByBlockRange(102, 5).length).to.equal(0);
			// And a second query stays empty without re-verification.
			const second = graph.getGossipMessagesForChannels([scid]);
			expect(second.announcements.length).to.equal(0);
		});

		it('stops resolving when the serve budget is exhausted and resumes on a later query', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(103, 1, 0);
			const keys = makeSignedChannelKeys();
			const ann = makeSignedChannelAnnouncement(scid, keys);
			graph.addChannelAnnouncement(ann.msg, { verified: 'deferred' });

			const budget = NetworkGraph.SERVE_VERIFY_BUDGET_MS;
			try {
				NetworkGraph.SERVE_VERIFY_BUDGET_MS = 0;
				const starved = graph.getGossipMessagesForChannels([scid]);
				expect(starved.announcements.length).to.equal(0);
				// The omission is reported: the requester must not conclude we
				// have nothing more for these SCIDs.
				expect(starved.complete).to.equal(false);
				// Unresolved, not failed: the entry stays deferred for later.
				expect(graph.getChannel(scid)!.announcementVerifyDeferred).to.equal(
					true
				);
				expect(graph.getChannel(scid)!.announcementVerified).to.equal(
					undefined
				);
			} finally {
				NetworkGraph.SERVE_VERIFY_BUDGET_MS = budget;
			}
			const served = graph.getGossipMessagesForChannels([scid]);
			expect(served.announcements.length).to.equal(1);
			expect(served.complete).to.equal(true);
			expect(graph.getChannel(scid)!.announcementVerified).to.be.true;
		});

		it('shares one verification budget across queries in a window and refreshes on roll-over', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(103, 2, 0);
			const keys = makeSignedChannelKeys();
			graph.addChannelAnnouncement(
				makeSignedChannelAnnouncement(scid, keys).msg,
				{ verified: 'deferred' }
			);
			// Model an earlier query in the SAME window having spent the whole
			// budget: a per-query timer would reset here and let a peer hold
			// the event loop by repeating queries (issue #443 review).
			const seam = graph as unknown as {
				_serveVerifyWindowStart: number;
				_serveVerifySpentMs: number;
			};
			seam._serveVerifyWindowStart = Date.now();
			seam._serveVerifySpentMs = NetworkGraph.SERVE_VERIFY_BUDGET_MS;
			const starved = graph.getGossipMessagesForChannels([scid]);
			expect(starved.announcements.length).to.equal(0);
			expect(starved.complete).to.equal(false);
			expect(graph.getChannel(scid)!.announcementVerifyDeferred).to.equal(true);

			// A new window refreshes the budget.
			seam._serveVerifyWindowStart =
				Date.now() - NetworkGraph.SERVE_VERIFY_WINDOW_MS - 1;
			const served = graph.getGossipMessagesForChannels([scid]);
			expect(served.announcements.length).to.equal(1);
			expect(served.complete).to.equal(true);
		});

		it('serves a channel atomically: never an announcement without its resolvable updates', function () {
			// A partial serve (announcement now, updates when budget returns)
			// would make the requester record the SCID as synced and never ask
			// for the missing updates again. The whole channel therefore waits
			// for budget as a unit.
			const graph = new NetworkGraph();
			const scid = makeScid(103, 3, 0);
			const keys = makeSignedChannelKeys();
			graph.addChannelAnnouncement(
				makeSignedChannelAnnouncement(scid, keys).msg,
				{ verified: 'deferred' }
			);
			graph.applyChannelUpdate(
				makeSignedChannelUpdate(scid, keys.nodeKey1, 0, 1000).msg,
				{ verified: 'deferred' }
			);
			graph.applyChannelUpdate(
				makeSignedChannelUpdate(scid, keys.nodeKey2, 1, 1000).msg,
				{ verified: 'deferred' }
			);

			const seam = graph as unknown as {
				_serveVerifyWindowStart: number;
				_serveVerifySpentMs: number;
			};
			seam._serveVerifyWindowStart = Date.now();
			seam._serveVerifySpentMs = NetworkGraph.SERVE_VERIFY_BUDGET_MS;
			const starved = graph.getGossipMessagesForChannels([scid]);
			expect(starved.announcements.length).to.equal(0);
			expect(starved.updates.length).to.equal(0);
			expect(starved.complete).to.equal(false);

			seam._serveVerifySpentMs = 0;
			const served = graph.getGossipMessagesForChannels([scid]);
			expect(served.announcements.length).to.equal(1);
			expect(served.updates.length).to.equal(2);
			expect(served.complete).to.equal(true);
		});

		it('reports partial replies through the reply_short_channel_ids_end full_information bit', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(103, 4, 0);
			const keys = makeSignedChannelKeys();
			graph.addChannelAnnouncement(
				makeSignedChannelAnnouncement(scid, keys).msg,
				{ verified: 'deferred' }
			);
			const mgr = new GossipSyncManager(graph);
			const seam = graph as unknown as {
				_serveVerifyWindowStart: number;
				_serveVerifySpentMs: number;
			};
			seam._serveVerifyWindowStart = Date.now();
			seam._serveVerifySpentMs = NetworkGraph.SERVE_VERIFY_BUDGET_MS;

			const starvedMessages = mgr.handleQueryShortChannelIds({
				chainHash: BITCOIN_CHAIN_HASH,
				encodedShortIds: encodeShortChannelIds([scid])
			});
			const starvedEnd = decodeReplyShortChannelIdsEndMessage(
				starvedMessages[starvedMessages.length - 1].payload
			);
			expect(starvedEnd.complete).to.equal(false);

			seam._serveVerifySpentMs = 0;
			const servedMessages = mgr.handleQueryShortChannelIds({
				chainHash: BITCOIN_CHAIN_HASH,
				encodedShortIds: encodeShortChannelIds([scid])
			});
			const servedEnd = decodeReplyShortChannelIdsEndMessage(
				servedMessages[servedMessages.length - 1].payload
			);
			expect(servedEnd.complete).to.equal(true);
			expect(
				servedMessages.filter(
					(m) => m.type === MessageType.CHANNEL_ANNOUNCEMENT
				).length
			).to.equal(1);
		});

		it('lets a deferred announcement take over only a signatureless slot with matching endpoints', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(104, 1, 0);
			const keys = makeSignedChannelKeys();
			const signed = makeSignedChannelAnnouncement(scid, keys);
			// RGS-primed slot: zero signatures, same endpoints.
			graph.addChannelAnnouncement(zeroSigAnnouncement(signed.msg));

			// Mismatched endpoints never take over.
			const otherScidAnn = makeSignedChannelAnnouncement(
				scid,
				makeSignedChannelKeys()
			);
			expect(
				graph.addChannelAnnouncement(otherScidAnn.msg, {
					verified: 'deferred'
				})
			).to.be.false;

			// Matching endpoints: the signed copy takes the slot as deferred.
			expect(graph.addChannelAnnouncement(signed.msg, { verified: 'deferred' }))
				.to.be.true;
			expect(graph.getChannel(scid)!.announcementVerifyDeferred).to.equal(true);

			// A re-served identical announcement refuses: the slot now carries
			// real signatures, so accepting would only re-trigger persistence.
			expect(graph.addChannelAnnouncement(signed.msg, { verified: 'deferred' }))
				.to.be.false;

			// A zero-signature candidate claiming deferred is stored as false,
			// so an identical zero-signature replay is never takeover-eligible
			// against its own slot (each acceptance would re-trigger a storage
			// write).
			const zeroScid = makeScid(104, 3, 0);
			const zeroAnn = zeroSigAnnouncement(
				makeSignedChannelAnnouncement(zeroScid, makeSignedChannelKeys()).msg
			);
			expect(graph.addChannelAnnouncement(zeroAnn, { verified: 'deferred' })).to
				.be.true;
			expect(graph.getChannel(zeroScid)!.announcementVerified).to.be.false;
			expect(graph.getChannel(zeroScid)!.announcementVerifyDeferred).to.equal(
				undefined
			);
			expect(graph.addChannelAnnouncement(zeroAnn, { verified: 'deferred' })).to
				.be.false;

			// And deferred never displaces a verified slot.
			const verifiedScid = makeScid(104, 2, 0);
			const verified = makeSignedChannelAnnouncement(
				verifiedScid,
				makeSignedChannelKeys()
			);
			graph.addChannelAnnouncement(verified.msg, { verified: true });
			expect(
				graph.addChannelAnnouncement(verified.msg, { verified: 'deferred' })
			).to.be.false;
			expect(graph.getChannel(verifiedScid)!.announcementVerified).to.be.true;
		});

		it('lets a deferred update bypass freshness only over a signatureless slot', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(105, 1, 0);
			const keys = makeSignedChannelKeys();
			const ann = makeSignedChannelAnnouncement(scid, keys);
			graph.addChannelAnnouncement(ann.msg, { verified: 'deferred' });

			// RGS-style zero-sig update stamped with a synthetic newer timestamp.
			const rgsUpdate = {
				...makeSignedChannelUpdate(scid, keys.nodeKey1, 0, 2000).msg,
				signature: Buffer.alloc(64)
			};
			graph.applyChannelUpdate(rgsUpdate);
			// A zero-signature replay claiming deferred normalizes to false, so
			// it cannot take over its own zero-signature slot repeatedly (each
			// acceptance would re-trigger a storage write).
			expect(graph.applyChannelUpdate(rgsUpdate, { verified: 'deferred' })).to
				.be.false;
			// The older real broadcast update still takes the slot.
			const older = makeSignedChannelUpdate(scid, keys.nodeKey1, 0, 1000);
			expect(graph.applyChannelUpdate(older.msg, { verified: 'deferred' })).to
				.be.true;
			expect(graph.getChannel(scid)!.update1VerifyDeferred).to.equal(true);

			// Over a REAL-signature slot, normal freshness rules: a re-served or
			// older deferred update refuses, a strictly newer one lands.
			expect(graph.applyChannelUpdate(older.msg, { verified: 'deferred' })).to
				.be.false;
			const newer = makeSignedChannelUpdate(scid, keys.nodeKey1, 0, 3000);
			expect(graph.applyChannelUpdate(newer.msg, { verified: 'deferred' })).to
				.be.true;
		});

		it('resolves deferred node announcements at the address boundary, never handing out unproven addresses', function () {
			const graph = new NetworkGraph();
			const scid = makeScid(107, 1, 0);
			const keys = makeSignedChannelKeys();
			graph.addChannelAnnouncement(
				makeSignedChannelAnnouncement(scid, keys).msg,
				{ verified: 'deferred' }
			);

			// A garbage-signature announcement claiming an address must never
			// reach a dial: resolution settles it false, stickily.
			const poison = {
				...makeSignedNodeAnnouncement(keys.nodeKey1, 1000, [
					{ type: 1, host: '127.0.0.1', port: 4242 }
				]).msg,
				signature: crypto.randomBytes(64)
			};
			graph.applyNodeAnnouncement(poison, { verified: 'deferred' });
			const node1 = getPublicKey(keys.nodeKey1);
			expect(graph.getVerifiedNodeAnnouncement(node1)).to.equal(undefined);
			expect(graph.getNode(node1)!.announcementVerified).to.be.false;
			expect(graph.getNode(node1)!.announcementVerifyDeferred).to.equal(
				undefined
			);

			// A genuinely signed deferred announcement resolves on first read
			// and hands out its addresses.
			const genuine = makeSignedNodeAnnouncement(keys.nodeKey2, 1000, [
				{ type: 1, host: '203.0.113.5', port: 9735 }
			]);
			graph.applyNodeAnnouncement(genuine.msg, { verified: 'deferred' });
			const node2 = getPublicKey(keys.nodeKey2);
			const resolved = graph.getVerifiedNodeAnnouncement(node2);
			expect(resolved).to.not.equal(undefined);
			expect(resolved!.addresses[0].host).to.equal('203.0.113.5');
			expect(graph.getNode(node2)!.announcementVerified).to.be.true;
		});

		it('re-requests signatureless entries via getMissingSCIDs in eager mode only', function () {
			const rgsScid = makeScid(106, 1, 0);
			const rgsUpdScid = makeScid(106, 2, 0);
			const failedScid = makeScid(106, 3, 0);
			const absentScid = makeScid(106, 4, 0);

			function populate(graph: NetworkGraph): void {
				const rgsKeys = makeSignedChannelKeys();
				// RGS-primed announcement: zero signatures, worth re-fetching.
				graph.addChannelAnnouncement(
					zeroSigAnnouncement(
						makeSignedChannelAnnouncement(rgsScid, rgsKeys).msg
					)
				);
				// Verified announcement with an RGS-primed (zero-sig) update.
				const updKeys = makeSignedChannelKeys();
				graph.addChannelAnnouncement(
					makeSignedChannelAnnouncement(rgsUpdScid, updKeys).msg,
					{ verified: true }
				);
				graph.applyChannelUpdate({
					...makeSignedChannelUpdate(rgsUpdScid, updKeys.nodeKey1, 0, 1000).msg,
					signature: Buffer.alloc(64)
				});
				// Real signatures that failed verification: re-fetching would
				// re-serve the same bytes forever, so never re-request.
				graph.addChannelAnnouncement(
					makeChannelAnnouncement(failedScid, ...randomNodePair())
				);
			}
			const remote = [rgsScid, rgsUpdScid, failedScid, absentScid];

			const eager = new NetworkGraph(BITCOIN_CHAIN_HASH, {
				eagerVerify: true
			});
			populate(eager);
			const eagerMissing = eager.getMissingSCIDs(remote);
			expect(eagerMissing.map((s) => s.toString('hex')).sort()).to.deep.equal(
				[rgsScid, rgsUpdScid, absentScid].map((s) => s.toString('hex')).sort()
			);

			// Lazy wallets keep the presence-only behavior (issue #441: RGS
			// priming shrinks the p2p request).
			const lazy = new NetworkGraph();
			populate(lazy);
			const lazyMissing = lazy.getMissingSCIDs(remote);
			expect(lazyMissing.length).to.equal(1);
			expect(lazyMissing[0].equals(absentScid)).to.be.true;
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
				makeChannelAnnouncement(scidB1, node1, node2),
				{ verified: true }
			);
			graphB.addChannelAnnouncement(
				makeChannelAnnouncement(scidB2, node2, node3),
				{ verified: true }
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
		function makeNode(
			enableNetworking = false,
			nodePrivateKey = crypto.randomBytes(32),
			eagerGossipVerify = false
		): LightningNode {
			return new LightningNode({
				nodePrivateKey,
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: makeBasepoints(),
				fundingPrivkey: crypto.randomBytes(32),
				enableNetworking,
				eagerGossipVerify
			});
		}

		it('completes gossip sync over the built-in TCP transport', async function () {
			this.timeout(10_000);
			const initiatorKey = crypto.randomBytes(32);
			const responderKey = crypto.randomBytes(32);
			const responderPubkey = getPublicKey(responderKey).toString('hex');
			const initiator = makeNode(true, initiatorKey);
			const responder = makeNode(true, responderKey);
			populateGraph(responder.getGraph(), 1, REGTEST_CHAIN_HASH);
			const initiatorTypes: number[] = [];
			const responderTypes: number[] = [];
			const initiatorPeerManager = initiator.getPeerManager()!;
			const responderPeerManager = responder.getPeerManager()!;
			const initiatorSend =
				initiatorPeerManager.sendToPeer.bind(initiatorPeerManager);
			const responderSend =
				responderPeerManager.sendToPeer.bind(responderPeerManager);
			initiatorPeerManager.sendToPeer = (pubkey, type, payload): void => {
				initiatorTypes.push(type);
				initiatorSend(pubkey, type, payload);
			};
			responderPeerManager.sendToPeer = (pubkey, type, payload): void => {
				responderTypes.push(type);
				responderSend(pubkey, type, payload);
			};

			try {
				await responder.listen(0, '127.0.0.1');
				const responderPort = (
					responder.getPeerManager() as unknown as {
						server: { address(): { port: number } };
					}
				).server.address().port;
				await initiator.connectPeer(
					responderPubkey,
					'127.0.0.1',
					responderPort
				);

				initiator.initiateGossipSync(responderPubkey);
				await waitFor(
					() =>
						initiator.getGossipSyncState(responderPubkey) ===
						GossipSyncState.SYNCED
				);

				expect(initiator.getGossipSyncState(responderPubkey)).to.equal(
					GossipSyncState.SYNCED
				);
				expect(initiatorTypes).to.include.members([
					MessageType.GOSSIP_TIMESTAMP_FILTER,
					MessageType.QUERY_CHANNEL_RANGE,
					MessageType.QUERY_SHORT_CHANNEL_IDS
				]);
				expect(responderTypes).to.include.members([
					MessageType.REPLY_CHANNEL_RANGE,
					MessageType.CHANNEL_ANNOUNCEMENT,
					MessageType.CHANNEL_UPDATE,
					MessageType.NODE_ANNOUNCEMENT,
					MessageType.REPLY_SHORT_CHANNEL_IDS_END
				]);
			} finally {
				initiator.destroy();
				responder.destroy();
			}
		});

		it('falls back to message:outbound when the peer is disconnected', function () {
			const node = makeNode(true);
			const peerPubkey = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const outbound: number[] = [];
			node.on('message:outbound', (_pubkey: string, type: number) => {
				outbound.push(type);
			});

			try {
				node.initiateGossipSync(peerPubkey);
				expect(outbound).to.deep.equal([
					MessageType.GOSSIP_TIMESTAMP_FILTER,
					MessageType.QUERY_CHANNEL_RANGE
				]);
			} finally {
				node.destroy();
			}
		});

		it('falls back when a registered peer is no longer ready', function () {
			const node = makeNode(true);
			const peerPubkey = getPublicKey(crypto.randomBytes(32)).toString('hex');
			const peerManager = node.getPeerManager()!;
			const originalGetPeer = peerManager.getPeer;
			const outbound: number[] = [];
			peerManager.getPeer = (): NonNullable<
				ReturnType<typeof originalGetPeer>
			> =>
				({
					getState: (): 'disconnected' => 'disconnected'
				}) as NonNullable<ReturnType<typeof originalGetPeer>>;
			node.on('message:outbound', (_pubkey: string, type: number) => {
				outbound.push(type);
			});

			try {
				node.initiateGossipSync(peerPubkey);
				expect(outbound).to.deep.equal([
					MessageType.GOSSIP_TIMESTAMP_FILTER,
					MessageType.QUERY_CHANNEL_RANGE
				]);
			} finally {
				peerManager.getPeer = originalGetPeer;
				node.destroy();
			}
		});

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

		it('serves only verified channels through handlePeerMessage query_channel_range (issue #340)', function () {
			const node = makeNode();
			const graph = node.getGraph();
			const verifiedScid = makeScid(100, 1, 0);
			const unverifiedScid = makeScid(100, 2, 0);
			const nodeA = Buffer.alloc(33, 0);
			nodeA[0] = 0x02;
			nodeA[32] = 0x01;
			const nodeB = Buffer.alloc(33, 0);
			nodeB[0] = 0x02;
			nodeB[32] = 0x02;
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(verifiedScid, nodeA, nodeB, REGTEST_CHAIN_HASH),
				{ verified: true }
			);
			// Synthetic routing hint injected through the public API: routable
			// locally, but never advertised to peers.
			graph.addChannelAnnouncement(
				makeChannelAnnouncement(
					unverifiedScid,
					nodeA,
					nodeB,
					REGTEST_CHAIN_HASH
				)
			);

			const outbound: Array<{ type: number; payload: Buffer }> = [];
			node.on(
				'message:outbound',
				(_pubkey: string, type: number, payload: Buffer) => {
					outbound.push({ type, payload });
				}
			);
			node.handlePeerMessage(
				'aa'.repeat(33),
				MessageType.QUERY_CHANNEL_RANGE,
				encodeQueryChannelRangeMessage({
					chainHash: REGTEST_CHAIN_HASH,
					firstBlocknum: 0,
					numberOfBlocks: 0xffffffff
				})
			);

			expect(outbound.length).to.equal(1);
			const reply = decodeReplyChannelRangeMessage(outbound[0].payload);
			const scids = decodeShortChannelIds(reply.encodedShortIds);
			expect(scids.length).to.equal(1);
			expect(scids[0].equals(verifiedScid)).to.be.true;
			node.destroy();
		});

		it('serves received announcements byte-identically and withholds ones with unreproducible signed bytes (issue #340, eager mode)', async function () {
			const node = makeNode(false, crypto.randomBytes(32), true);
			const peer = 'aa'.repeat(33);
			const cleanScid = makeScid(150, 1, 0);
			const extraScid = makeScid(150, 2, 0);
			const clean = makeSignedChannelAnnouncement(
				cleanScid,
				makeSignedChannelKeys(),
				REGTEST_CHAIN_HASH
			);
			// Signed future fields the codec cannot round-trip: re-encoding
			// would drop them and break the signatures.
			const extra = makeSignedChannelAnnouncement(
				extraScid,
				makeSignedChannelKeys(),
				REGTEST_CHAIN_HASH,
				Buffer.from([1, 2, 3])
			);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_ANNOUNCEMENT,
				clean.payload
			);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_ANNOUNCEMENT,
				extra.payload
			);
			// Broadcast gossip is queued off the message path (issue #437).
			await node.flushGossip();

			const graph = node.getGraph();
			// Both entries are routable...
			expect(graph.getChannel(cleanScid)!.announcementVerified).to.be.true;
			expect(graph.getChannel(extraScid)!.announcementVerified).to.be.false;

			// ...but only the clean one is served, byte-identical to the wire
			// payload whose signatures were verified.
			const outbound: Array<{ type: number; payload: Buffer }> = [];
			node.on(
				'message:outbound',
				(_pubkey: string, type: number, payload: Buffer) => {
					outbound.push({ type, payload });
				}
			);
			node.handlePeerMessage(
				peer,
				MessageType.QUERY_SHORT_CHANNEL_IDS,
				encodeQueryShortChannelIdsMessage({
					chainHash: REGTEST_CHAIN_HASH,
					encodedShortIds: encodeShortChannelIds([cleanScid, extraScid])
				})
			);
			const served = outbound.filter(
				(m) => m.type === MessageType.CHANNEL_ANNOUNCEMENT
			);
			expect(served.length).to.equal(1);
			expect(served[0].payload.equals(clean.payload)).to.be.true;
			node.destroy();
		});

		it('withholds a signed channel_update whose extra signed bytes cannot be reproduced (issue #340, eager mode)', async function () {
			const node = makeNode(false, crypto.randomBytes(32), true);
			const peer = 'aa'.repeat(33);
			const scid = makeScid(151, 1, 0);
			const keys = makeSignedChannelKeys();
			const ann = makeSignedChannelAnnouncement(scid, keys, REGTEST_CHAIN_HASH);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_ANNOUNCEMENT,
				ann.payload
			);
			const cleanUpd = makeSignedChannelUpdate(
				scid,
				keys.nodeKey1,
				0,
				1000,
				REGTEST_CHAIN_HASH
			);
			const extraUpd = makeSignedChannelUpdate(
				scid,
				keys.nodeKey2,
				1,
				1000,
				REGTEST_CHAIN_HASH,
				Buffer.from([9, 9])
			);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_UPDATE,
				cleanUpd.payload
			);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_UPDATE,
				extraUpd.payload
			);
			// Broadcast gossip is queued off the message path (issue #437).
			await node.flushGossip();

			const ch = node.getGraph().getChannel(scid)!;
			expect(ch.update1Verified).to.be.true;
			// The lossy update stays routable but unservable.
			expect(ch.update2).to.exist;
			expect(ch.update2Verified).to.be.false;
			const served = node.getGraph().getGossipMessagesForChannels([scid]);
			expect(served.updates.length).to.equal(1);
			expect(served.updates[0].channelFlags & 0x01).to.equal(0);
			node.destroy();
		});

		it('defers intake verification and resolves it at serve time (issue #443, lazy default)', async function () {
			const node = makeNode();
			const peer = 'aa'.repeat(33);
			const cleanScid = makeScid(150, 3, 0);
			const extraScid = makeScid(150, 4, 0);
			const cleanKeys = makeSignedChannelKeys();
			const clean = makeSignedChannelAnnouncement(
				cleanScid,
				cleanKeys,
				REGTEST_CHAIN_HASH
			);
			// Signed future fields the codec cannot round-trip: serve-time
			// resolution verifies the canonical re-encoding, so this one must
			// resolve unservable exactly like eager intake would classify it.
			const extra = makeSignedChannelAnnouncement(
				extraScid,
				makeSignedChannelKeys(),
				REGTEST_CHAIN_HASH,
				Buffer.from([1, 2, 3])
			);
			const cleanUpd = makeSignedChannelUpdate(
				cleanScid,
				cleanKeys.nodeKey1,
				0,
				1000,
				REGTEST_CHAIN_HASH
			);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_ANNOUNCEMENT,
				clean.payload
			);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_ANNOUNCEMENT,
				extra.payload
			);
			node.handlePeerMessage(
				peer,
				MessageType.CHANNEL_UPDATE,
				cleanUpd.payload
			);
			await node.flushGossip();

			// Intake paid for no signatures: everything sits deferred, with the
			// boolean flags unset so truthiness checks read unverified.
			const graph = node.getGraph();
			expect(graph.getChannel(cleanScid)!.announcementVerified).to.equal(
				undefined
			);
			expect(graph.getChannel(cleanScid)!.announcementVerifyDeferred).to.equal(
				true
			);
			expect(graph.getChannel(cleanScid)!.update1VerifyDeferred).to.equal(true);
			expect(graph.getChannel(extraScid)!.announcementVerifyDeferred).to.equal(
				true
			);

			// A gossip query triggers resolution: the clean entry is served
			// byte-identically, the unreproducible one is withheld.
			const outbound: Array<{ type: number; payload: Buffer }> = [];
			node.on(
				'message:outbound',
				(_pubkey: string, type: number, payload: Buffer) => {
					outbound.push({ type, payload });
				}
			);
			node.handlePeerMessage(
				peer,
				MessageType.QUERY_SHORT_CHANNEL_IDS,
				encodeQueryShortChannelIdsMessage({
					chainHash: REGTEST_CHAIN_HASH,
					encodedShortIds: encodeShortChannelIds([cleanScid, extraScid])
				})
			);
			const servedAnns = outbound.filter(
				(m) => m.type === MessageType.CHANNEL_ANNOUNCEMENT
			);
			expect(servedAnns.length).to.equal(1);
			expect(servedAnns[0].payload.equals(clean.payload)).to.be.true;
			const servedUpds = outbound.filter(
				(m) => m.type === MessageType.CHANNEL_UPDATE
			);
			expect(servedUpds.length).to.equal(1);
			expect(servedUpds[0].payload.equals(cleanUpd.payload)).to.be.true;

			// Resolution is sticky: the flags are booleans now.
			expect(graph.getChannel(cleanScid)!.announcementVerified).to.be.true;
			expect(graph.getChannel(cleanScid)!.update1Verified).to.be.true;
			expect(graph.getChannel(extraScid)!.announcementVerified).to.be.false;
			node.destroy();
		});

		it('never dials addresses from an unverified node announcement (issue #443 review)', async function () {
			const node = makeNode(true);
			try {
				const scid = makeScid(170, 1, 0);
				const keys = makeSignedChannelKeys();
				node
					.getGraph()
					.addChannelAnnouncement(
						makeSignedChannelAnnouncement(scid, keys, REGTEST_CHAIN_HASH).msg,
						{ verified: 'deferred' }
					);
				// A garbage-signature announcement claiming a dial address: the
				// pubkey-only connect path must resolve provenance before ever
				// treating the address as a candidate.
				const poison = {
					...makeSignedNodeAnnouncement(keys.nodeKey1, 1000, [
						{ type: 1, host: '127.0.0.1', port: 4242 }
					]).msg,
					signature: crypto.randomBytes(64)
				};
				node.getGraph().applyNodeAnnouncement(poison, { verified: 'deferred' });
				const pubkey = getPublicKey(keys.nodeKey1).toString('hex');

				// Silence the DNS fallback and record every dial attempt.
				(
					node as unknown as { bootstrapPeers(): Promise<unknown[]> }
				).bootstrapPeers = async () => [];
				const dials: string[] = [];
				const pm = node.getPeerManager()!;
				pm.connectPeer = (async (
					_pk: string,
					host: string,
					port: number
				): Promise<void> => {
					dials.push(`${host}:${port}`);
					throw new Error('refused');
				}) as typeof pm.connectPeer;

				let error = '';
				try {
					await node.connectPeer(pubkey);
				} catch (err) {
					error = err instanceof Error ? err.message : String(err);
				}
				expect(dials).to.deep.equal([]);
				expect(error).to.not.include('4242');
				// The poisoned announcement settled false at the read.
				expect(
					node.getGraph().getNode(getPublicKey(keys.nodeKey1))!
						.announcementVerified
				).to.be.false;
			} finally {
				node.destroy();
			}
		});

		it('refuses to cache or serve an assembled announcement with invalid counterparty signatures (issue #340)', function (done) {
			const node = makeNode();
			const scid = makeScid(160, 1, 0);
			const keys = makeSignedChannelKeys();
			// Structurally valid announcement whose signatures were never
			// validated: the counterparty sent zeros via announcement_signatures.
			const zeroSigAnn = encodeChannelAnnouncementMessage({
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: scid,
				nodeId1: getPublicKey(keys.nodeKey1),
				nodeId2: getPublicKey(keys.nodeKey2),
				bitcoinKey1: Buffer.alloc(33),
				bitcoinKey2: Buffer.alloc(33)
			});
			const upd = makeSignedChannelUpdate(
				scid,
				keys.nodeKey1,
				0,
				1000,
				REGTEST_CHAIN_HASH
			).payload;
			node.on('announcement:ready', () => {
				const gossipCache = (
					node as unknown as { _ownChannelGossip: Map<string, unknown> }
				)._ownChannelGossip;
				expect(gossipCache.size).to.equal(0);
				const ch = node.getGraph().getChannel(scid);
				// Routable locally, never advertised.
				expect(ch).to.exist;
				expect(ch!.announcementVerified).to.be.false;
				expect(node.getGraph().getChannelsByBlockRange(160, 1)).to.have.length(
					0
				);
				node.destroy();
				done();
			});
			node
				.getChannelManager()
				.emit('announcement:ready', crypto.randomBytes(32), zeroSigAnn, upd);
		});

		it('caches and serves a fully signed assembled announcement', function (done) {
			const node = makeNode();
			const scid = makeScid(161, 1, 0);
			const ann = makeSignedChannelAnnouncement(
				scid,
				makeSignedChannelKeys(),
				REGTEST_CHAIN_HASH
			);
			const upd = makeSignedChannelUpdate(
				scid,
				makeSignedChannelKeys().nodeKey1,
				0,
				1000,
				REGTEST_CHAIN_HASH
			).payload;
			node.on('announcement:ready', () => {
				const gossipCache = (
					node as unknown as { _ownChannelGossip: Map<string, unknown> }
				)._ownChannelGossip;
				expect(gossipCache.size).to.equal(1);
				expect(node.getGraph().getChannel(scid)!.announcementVerified).to.be
					.true;
				expect(node.getGraph().getChannelsByBlockRange(161, 1)).to.have.length(
					1
				);
				node.destroy();
				done();
			});
			node
				.getChannelManager()
				.emit('announcement:ready', crypto.randomBytes(32), ann.payload, upd);
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
