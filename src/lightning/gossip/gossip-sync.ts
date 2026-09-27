/**
 * BOLT 7 §4: Gossip synchronization protocol manager.
 *
 * State machine: IDLE → AWAITING_RANGE_REPLY → AWAITING_SCID_REPLY → SYNCED
 *
 * Initiating side:
 *   1. initiateSync() → send gossip_timestamp_filter + query_channel_range
 *   2. handleReplyChannelRange() → accumulate SCIDs until syncComplete
 *   3. handleReplyShortChannelIdsEnd() → send next batch or → SYNCED
 *
 * Responding side:
 *   4. handleQueryChannelRange() → return reply_channel_range
 *   5. handleQueryShortChannelIds() → return gossip messages + reply_short_channel_ids_end
 */

import { EventEmitter } from 'events';
import { BITCOIN_CHAIN_HASH } from '../channel/types';
import { NetworkGraph } from './network-graph';
import { decodeShortChannelIds, encodeShortChannelIds } from './scid-encoding';
import {
	encodeQueryChannelRangeMessage,
	encodeGossipTimestampFilterMessage,
	encodeQueryShortChannelIdsMessage,
	encodeReplyChannelRangeMessage,
	encodeReplyShortChannelIdsEndMessage
} from './gossip-queries';
import {
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage,
	encodeNodeAnnouncementMessage
} from './messages';
import { MessageType } from '../message/types';
import {
	IReplyChannelRangeMessage,
	IReplyShortChannelIdsEndMessage,
	IQueryChannelRangeMessage,
	IQueryShortChannelIdsMessage
} from './types';

export enum GossipSyncState {
	IDLE = 'IDLE',
	AWAITING_RANGE_REPLY = 'AWAITING_RANGE_REPLY',
	AWAITING_SCID_REPLY = 'AWAITING_SCID_REPLY',
	SYNCED = 'SYNCED'
}

/** Maximum SCIDs per query_short_channel_ids (stay under 65535 byte limit). */
const MAX_SCIDS_PER_QUERY = 8000;

/** Maximum SCIDs per reply_channel_range chunk. */
const MAX_SCIDS_PER_REPLY = 8000;

/**
 * Most distinct SCIDs one range sync will hold before it is abandoned. The
 * public graph is a fraction of this; the ceiling exists because a peer can
 * stream sync_complete=0 replies for as long as it likes.
 */
const MAX_RANGE_REPLY_SCIDS = 200_000;

export interface IGossipSyncMessage {
	type: MessageType;
	payload: Buffer;
}

export class GossipSyncManager extends EventEmitter {
	private _state: GossipSyncState = GossipSyncState.IDLE;
	private _graph: NetworkGraph;
	/** Keyed by SCID hex, so a re-sent SCID does not count twice. */
	private _accumulatedScids = new Map<string, Buffer>();
	private _pendingQueryBatches: Buffer[][] = [];
	private _currentBatchIndex = 0;
	private readonly _chainHash: Buffer;

	/**
	 * @param chainHash The chain to query/announce on. Defaults to mainnet; the
	 *   node passes its configured network's chain_hash so our own queries carry
	 *   the right chain and are not ignored on regtest/testnet/signet.
	 */
	constructor(graph: NetworkGraph, chainHash: Buffer = BITCOIN_CHAIN_HASH) {
		super();
		this._graph = graph;
		this._chainHash = chainHash;
	}

	getState(): GossipSyncState {
		return this._state;
	}

	/**
	 * Initiate gossip sync with a peer.
	 * Returns messages to send: gossip_timestamp_filter + query_channel_range.
	 */
	initiateSync(): IGossipSyncMessage[] {
		const messages: IGossipSyncMessage[] = [];

		// Send gossip_timestamp_filter to receive future gossip
		messages.push({
			type: MessageType.GOSSIP_TIMESTAMP_FILTER,
			payload: encodeGossipTimestampFilterMessage({
				chainHash: this._chainHash,
				firstTimestamp: 0,
				timestampRange: 0xffffffff
			})
		});

		// Query full block range
		messages.push({
			type: MessageType.QUERY_CHANNEL_RANGE,
			payload: encodeQueryChannelRangeMessage({
				chainHash: this._chainHash,
				firstBlocknum: 0,
				numberOfBlocks: 0xffffffff
			})
		});

		this._state = GossipSyncState.AWAITING_RANGE_REPLY;
		this._accumulatedScids.clear();
		return messages;
	}

	/**
	 * Handle reply_channel_range from peer.
	 * Accumulates SCIDs until syncComplete, then queries missing ones.
	 * Replies we did not ask for, or for another chain, are dropped.
	 */
	handleReplyChannelRange(
		msg: IReplyChannelRangeMessage
	): IGossipSyncMessage[] {
		if (
			this._state !== GossipSyncState.AWAITING_RANGE_REPLY ||
			!msg.chainHash.equals(this._chainHash)
		) {
			return [];
		}

		for (const scid of decodeShortChannelIds(msg.encodedShortIds)) {
			this._accumulatedScids.set(scid.toString('hex'), scid);
		}
		if (this._accumulatedScids.size > MAX_RANGE_REPLY_SCIDS) {
			this._accumulatedScids.clear();
			this._state = GossipSyncState.IDLE;
			return [];
		}

		if (!msg.syncComplete) {
			// More chunks coming
			return [];
		}

		// All range replies received — find missing SCIDs
		const missing = this._graph.getMissingSCIDs([
			...this._accumulatedScids.values()
		]);
		this._accumulatedScids.clear();

		if (missing.length === 0) {
			this._state = GossipSyncState.SYNCED;
			this.emit('synced');
			return [];
		}

		// Batch into chunks of MAX_SCIDS_PER_QUERY
		this._pendingQueryBatches = [];
		for (let i = 0; i < missing.length; i += MAX_SCIDS_PER_QUERY) {
			this._pendingQueryBatches.push(missing.slice(i, i + MAX_SCIDS_PER_QUERY));
		}
		this._currentBatchIndex = 0;

		// Send first batch
		return this._sendNextScidQuery();
	}

	/**
	 * Handle reply_short_channel_ids_end from peer.
	 * Sends next batch or transitions to SYNCED.
	 */
	handleReplyShortChannelIdsEnd(
		_msg: IReplyShortChannelIdsEndMessage
	): IGossipSyncMessage[] {
		this._currentBatchIndex++;

		if (this._currentBatchIndex >= this._pendingQueryBatches.length) {
			// All batches processed
			this._state = GossipSyncState.SYNCED;
			this._pendingQueryBatches = [];
			this.emit('synced');
			return [];
		}

		return this._sendNextScidQuery();
	}

	// ── Responding side ────────────────────────────────────────────

	/**
	 * Handle query_channel_range from peer.
	 * Returns reply_channel_range messages (chunked if large).
	 */
	handleQueryChannelRange(
		msg: IQueryChannelRangeMessage
	): IGossipSyncMessage[] {
		const scids = this._graph.getChannelsByBlockRange(
			msg.firstBlocknum,
			msg.numberOfBlocks
		);
		const messages: IGossipSyncMessage[] = [];

		if (scids.length === 0) {
			// Single empty reply
			messages.push({
				type: MessageType.REPLY_CHANNEL_RANGE,
				payload: encodeReplyChannelRangeMessage({
					// BOLT 7: reply MUST echo the query's chain_hash.
					chainHash: msg.chainHash,
					firstBlocknum: msg.firstBlocknum,
					numberOfBlocks: msg.numberOfBlocks,
					syncComplete: true,
					encodedShortIds: encodeShortChannelIds([])
				})
			});
			return messages;
		}

		// Chunk the SCIDs
		for (let i = 0; i < scids.length; i += MAX_SCIDS_PER_REPLY) {
			const chunk = scids.slice(i, i + MAX_SCIDS_PER_REPLY);
			const isLast = i + MAX_SCIDS_PER_REPLY >= scids.length;
			messages.push({
				type: MessageType.REPLY_CHANNEL_RANGE,
				payload: encodeReplyChannelRangeMessage({
					// BOLT 7: reply MUST echo the query's chain_hash.
					chainHash: msg.chainHash,
					firstBlocknum: msg.firstBlocknum,
					numberOfBlocks: msg.numberOfBlocks,
					syncComplete: isLast,
					encodedShortIds: encodeShortChannelIds(chunk)
				})
			});
		}

		return messages;
	}

	/**
	 * Handle query_short_channel_ids from peer.
	 * Returns gossip messages for requested channels + reply_short_channel_ids_end.
	 */
	handleQueryShortChannelIds(
		msg: IQueryShortChannelIdsMessage
	): IGossipSyncMessage[] {
		const scids = decodeShortChannelIds(msg.encodedShortIds);
		const gossipData = this._graph.getGossipMessagesForChannels(scids);
		const messages: IGossipSyncMessage[] = [];

		// Send channel_announcement messages
		for (const ann of gossipData.announcements) {
			messages.push({
				type: MessageType.CHANNEL_ANNOUNCEMENT,
				payload: encodeChannelAnnouncementMessage(ann)
			});
		}

		// Send channel_update messages
		for (const upd of gossipData.updates) {
			messages.push({
				type: MessageType.CHANNEL_UPDATE,
				payload: encodeChannelUpdateMessage(upd)
			});
		}

		// Send node_announcement messages
		for (const nodeAnn of gossipData.nodeAnnouncements) {
			messages.push({
				type: MessageType.NODE_ANNOUNCEMENT,
				payload: encodeNodeAnnouncementMessage(nodeAnn)
			});
		}

		// End marker. full_information drops to 0 when the shared deferred
		// verification budget forced channels out of this reply (issue #443):
		// the requester must not treat an omission we know about as "the
		// responder has nothing more".
		messages.push({
			type: MessageType.REPLY_SHORT_CHANNEL_IDS_END,
			payload: encodeReplyShortChannelIdsEndMessage({
				// BOLT 7: reply MUST echo the query's chain_hash.
				chainHash: msg.chainHash,
				complete: gossipData.complete
			})
		});

		return messages;
	}

	// ── Internal ───────────────────────────────────────────────────

	private _sendNextScidQuery(): IGossipSyncMessage[] {
		const batch = this._pendingQueryBatches[this._currentBatchIndex];
		this._state = GossipSyncState.AWAITING_SCID_REPLY;

		return [
			{
				type: MessageType.QUERY_SHORT_CHANNEL_IDS,
				payload: encodeQueryShortChannelIdsMessage({
					chainHash: this._chainHash,
					encodedShortIds: encodeShortChannelIds(batch)
				})
			}
		];
	}
}
