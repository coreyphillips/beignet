/**
 * BOLT 7 §4: Gossip query message encoding/decoding.
 *
 * query_channel_range (type 263):
 *   [32: chain_hash]
 *   [4: first_blocknum]
 *   [4: number_of_blocks]
 *
 * reply_channel_range (type 264):
 *   [32: chain_hash]
 *   [4: first_blocknum]
 *   [4: number_of_blocks]
 *   [1: sync_complete]
 *   [2: len]
 *   [len: encoded_short_ids]
 *
 * query_short_channel_ids (type 261):
 *   [32: chain_hash]
 *   [2: len]
 *   [len: encoded_short_ids]
 *
 * reply_short_channel_ids_end (type 262):
 *   [32: chain_hash]
 *   [1: complete]
 *
 * gossip_timestamp_filter (type 265):
 *   [32: chain_hash]
 *   [4: first_timestamp]
 *   [4: timestamp_range]
 */

import {
	IQueryChannelRangeMessage,
	IReplyChannelRangeMessage,
	IQueryShortChannelIdsMessage,
	IReplyShortChannelIdsEndMessage,
	IGossipTimestampFilterMessage
} from './types';

// ── query_channel_range (263) ──────────────────────────────────────

const QUERY_CHANNEL_RANGE_LENGTH = 40; // 32 + 4 + 4

export function encodeQueryChannelRangeMessage(
	msg: IQueryChannelRangeMessage
): Buffer {
	const buf = Buffer.alloc(QUERY_CHANNEL_RANGE_LENGTH);
	let offset = 0;
	msg.chainHash.copy(buf, offset);
	offset += 32;
	buf.writeUInt32BE(msg.firstBlocknum, offset);
	offset += 4;
	buf.writeUInt32BE(msg.numberOfBlocks, offset);
	return buf;
}

export function decodeQueryChannelRangeMessage(
	payload: Buffer
): IQueryChannelRangeMessage {
	if (payload.length < QUERY_CHANNEL_RANGE_LENGTH) {
		throw new Error(
			`query_channel_range too short: need ${QUERY_CHANNEL_RANGE_LENGTH}, got ${payload.length}`
		);
	}
	let offset = 0;
	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const firstBlocknum = payload.readUInt32BE(offset);
	offset += 4;
	const numberOfBlocks = payload.readUInt32BE(offset);
	return { chainHash, firstBlocknum, numberOfBlocks };
}

// ── reply_channel_range (264) ──────────────────────────────────────

const REPLY_CHANNEL_RANGE_MIN_LENGTH = 43; // 32 + 4 + 4 + 1 + 2

export function encodeReplyChannelRangeMessage(
	msg: IReplyChannelRangeMessage
): Buffer {
	const len = msg.encodedShortIds.length;
	const buf = Buffer.alloc(REPLY_CHANNEL_RANGE_MIN_LENGTH + len);
	let offset = 0;
	msg.chainHash.copy(buf, offset);
	offset += 32;
	buf.writeUInt32BE(msg.firstBlocknum, offset);
	offset += 4;
	buf.writeUInt32BE(msg.numberOfBlocks, offset);
	offset += 4;
	buf[offset] = msg.syncComplete ? 1 : 0;
	offset += 1;
	buf.writeUInt16BE(len, offset);
	offset += 2;
	msg.encodedShortIds.copy(buf, offset);
	return buf;
}

export function decodeReplyChannelRangeMessage(
	payload: Buffer
): IReplyChannelRangeMessage {
	if (payload.length < REPLY_CHANNEL_RANGE_MIN_LENGTH) {
		throw new Error(
			`reply_channel_range too short: need ${REPLY_CHANNEL_RANGE_MIN_LENGTH}, got ${payload.length}`
		);
	}
	let offset = 0;
	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const firstBlocknum = payload.readUInt32BE(offset);
	offset += 4;
	const numberOfBlocks = payload.readUInt32BE(offset);
	offset += 4;
	const syncComplete = payload[offset] === 1;
	offset += 1;
	const len = payload.readUInt16BE(offset);
	offset += 2;
	const encodedShortIds = Buffer.from(payload.subarray(offset, offset + len));
	return {
		chainHash,
		firstBlocknum,
		numberOfBlocks,
		syncComplete,
		encodedShortIds
	};
}

// ── query_short_channel_ids (261) ──────────────────────────────────

const QUERY_SHORT_CHANNEL_IDS_MIN_LENGTH = 34; // 32 + 2

export function encodeQueryShortChannelIdsMessage(
	msg: IQueryShortChannelIdsMessage
): Buffer {
	const len = msg.encodedShortIds.length;
	const buf = Buffer.alloc(QUERY_SHORT_CHANNEL_IDS_MIN_LENGTH + len);
	let offset = 0;
	msg.chainHash.copy(buf, offset);
	offset += 32;
	buf.writeUInt16BE(len, offset);
	offset += 2;
	msg.encodedShortIds.copy(buf, offset);
	return buf;
}

export function decodeQueryShortChannelIdsMessage(
	payload: Buffer
): IQueryShortChannelIdsMessage {
	if (payload.length < QUERY_SHORT_CHANNEL_IDS_MIN_LENGTH) {
		throw new Error(
			`query_short_channel_ids too short: need ${QUERY_SHORT_CHANNEL_IDS_MIN_LENGTH}, got ${payload.length}`
		);
	}
	let offset = 0;
	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const len = payload.readUInt16BE(offset);
	offset += 2;
	const encodedShortIds = Buffer.from(payload.subarray(offset, offset + len));
	return { chainHash, encodedShortIds };
}

// ── reply_short_channel_ids_end (262) ──────────────────────────────

const REPLY_SHORT_CHANNEL_IDS_END_LENGTH = 33; // 32 + 1

export function encodeReplyShortChannelIdsEndMessage(
	msg: IReplyShortChannelIdsEndMessage
): Buffer {
	const buf = Buffer.alloc(REPLY_SHORT_CHANNEL_IDS_END_LENGTH);
	msg.chainHash.copy(buf, 0);
	buf[32] = msg.complete ? 1 : 0;
	return buf;
}

export function decodeReplyShortChannelIdsEndMessage(
	payload: Buffer
): IReplyShortChannelIdsEndMessage {
	if (payload.length < REPLY_SHORT_CHANNEL_IDS_END_LENGTH) {
		throw new Error(
			`reply_short_channel_ids_end too short: need ${REPLY_SHORT_CHANNEL_IDS_END_LENGTH}, got ${payload.length}`
		);
	}
	const chainHash = Buffer.from(payload.subarray(0, 32));
	const complete = payload[32] === 1;
	return { chainHash, complete };
}

// ── gossip_timestamp_filter (265) ──────────────────────────────────

const GOSSIP_TIMESTAMP_FILTER_LENGTH = 40; // 32 + 4 + 4

export function encodeGossipTimestampFilterMessage(
	msg: IGossipTimestampFilterMessage
): Buffer {
	const buf = Buffer.alloc(GOSSIP_TIMESTAMP_FILTER_LENGTH);
	let offset = 0;
	msg.chainHash.copy(buf, offset);
	offset += 32;
	buf.writeUInt32BE(msg.firstTimestamp, offset);
	offset += 4;
	buf.writeUInt32BE(msg.timestampRange, offset);
	return buf;
}

export function decodeGossipTimestampFilterMessage(
	payload: Buffer
): IGossipTimestampFilterMessage {
	if (payload.length < GOSSIP_TIMESTAMP_FILTER_LENGTH) {
		throw new Error(
			`gossip_timestamp_filter too short: need ${GOSSIP_TIMESTAMP_FILTER_LENGTH}, got ${payload.length}`
		);
	}
	let offset = 0;
	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const firstTimestamp = payload.readUInt32BE(offset);
	offset += 4;
	const timestampRange = payload.readUInt32BE(offset);
	return { chainHash, firstTimestamp, timestampRange };
}
