/**
 * BOLT 2: HTLC and fee update message encoding/decoding.
 *
 * update_add_htlc (type 128):
 *   [32: channel_id]
 *   [8: id]
 *   [8: amount_msat]
 *   [32: payment_hash]
 *   [4: cltv_expiry]
 *   [1366: onion_routing_packet]
 *
 * update_fulfill_htlc (type 130):
 *   [32: channel_id]
 *   [8: id]
 *   [32: payment_preimage]
 *
 * update_fail_htlc (type 131):
 *   [32: channel_id]
 *   [8: id]
 *   [2: len]
 *   [len: reason]
 *
 * update_fail_malformed_htlc (type 135):
 *   [32: channel_id]
 *   [8: id]
 *   [32: sha256_of_onion]
 *   [2: failure_code]
 *
 * update_fee (type 134):
 *   [32: channel_id]
 *   [4: feerate_per_kw]
 */

import type { CustomRecords } from './custom-records';
import {
	boundedLightningPayload,
	customRecordEntries,
	decodeWithCustomRecords
} from './custom-records';
import { encodeTlvStream } from './tlv';

export interface IUpdateAddHtlcMessage {
	channelId: Buffer;
	id: bigint;
	amountMsat: bigint;
	paymentHash: Buffer;
	cltvExpiry: number;
	onionRoutingPacket: Buffer;
	/**
	 * Route blinding (BOLT 2/4): blinding_point TLV (type 0). Set by the
	 * introduction node when forwarding into a blinded path so the next blinded
	 * hop can derive its blinded node key. 33-byte compressed point.
	 */
	blindingPoint?: Buffer;
	/** Agreed liquidity fee withheld from this HTLC, in millisatoshis. */
	skimmedFeeMsat?: bigint;
	/** Protocol metadata carried by the channel HTLC, separate from its onion. */
	customRecords?: CustomRecords;
}

export interface IUpdateFulfillHtlcMessage {
	channelId: Buffer;
	id: bigint;
	paymentPreimage: Buffer;
}

export interface IUpdateFailHtlcMessage {
	channelId: Buffer;
	id: bigint;
	reason: Buffer;
}

export interface IUpdateFailMalformedHtlcMessage {
	channelId: Buffer;
	id: bigint;
	sha256OfOnion: Buffer;
	failureCode: number;
}

export interface IUpdateFeeMessage {
	channelId: Buffer;
	feeratePerKw: number;
}

/**
 * bLIP-0051 / CLN `update_blockheight` (type 137): on a leased channel the
 * OPENER advances the blockheight both sides agreed on at open, shrinking the
 * lessor's remaining-lease CSV (lease_csv = lease_expiry - blockheight).
 */
export interface IUpdateBlockheightMessage {
	channelId: Buffer;
	blockheight: number;
}

const UPDATE_ADD_HTLC_LENGTH = 1450; // 32 + 8 + 8 + 32 + 4 + 1366
const UPDATE_FULFILL_HTLC_LENGTH = 72; // 32 + 8 + 32
const UPDATE_FAIL_HTLC_FIXED_LENGTH = 42; // 32 + 8 + 2
const UPDATE_FAIL_MALFORMED_HTLC_LENGTH = 74; // 32 + 8 + 32 + 2
const UPDATE_FEE_LENGTH = 36; // 32 + 4

const TLV_BLINDING_POINT = 0n;
const TLV_SKIMMED_FEE_MSAT = 65537n;
const UPDATE_ADD_HTLC_TLV_TYPES = new Set<bigint>([
	TLV_BLINDING_POINT,
	TLV_SKIMMED_FEE_MSAT
]);

/**
 * Encode an `update_add_htlc` message payload.
 */
export function encodeUpdateAddHtlcMessage(msg: IUpdateAddHtlcMessage): Buffer {
	const buf = Buffer.alloc(UPDATE_ADD_HTLC_LENGTH);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.id, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.amountMsat, offset);
	offset += 8;
	msg.paymentHash.copy(buf, offset);
	offset += 32;
	buf.writeUInt32BE(msg.cltvExpiry, offset);
	offset += 4;
	msg.onionRoutingPacket.copy(buf, offset);

	// Optional trailing blinding_point TLV (type 0, length 33). BOLT 1 allows
	// trailing TLV extensions; legacy decoders ignore the extra bytes.
	const records = customRecordEntries(
		msg.customRecords,
		UPDATE_ADD_HTLC_TLV_TYPES
	);
	if (msg.blindingPoint) {
		if (msg.blindingPoint.length !== 33)
			throw new Error('blindingPoint must be 33 bytes');
		records.push({ type: TLV_BLINDING_POINT, value: msg.blindingPoint });
	}
	if (msg.skimmedFeeMsat !== undefined) {
		const value = Buffer.alloc(8);
		value.writeBigUInt64BE(msg.skimmedFeeMsat);
		records.push({ type: TLV_SKIMMED_FEE_MSAT, value });
	}
	records.sort((a, b) => (a.type < b.type ? -1 : 1));
	return boundedLightningPayload(
		Buffer.concat([buf, encodeTlvStream(records)])
	);
}

/**
 * Decode an `update_add_htlc` message payload.
 */
export function decodeUpdateAddHtlcMessage(
	payload: Buffer
): IUpdateAddHtlcMessage {
	if (payload.length < UPDATE_ADD_HTLC_LENGTH) {
		throw new Error(
			`update_add_htlc too short: need ${UPDATE_ADD_HTLC_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const id = payload.readBigUInt64BE(offset);
	offset += 8;
	const amountMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const paymentHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const cltvExpiry = payload.readUInt32BE(offset);
	offset += 4;
	const onionRoutingPacket = Buffer.from(
		payload.subarray(offset, offset + 1366)
	);
	offset += 1366;

	// Optional trailing update_add_htlc_tlvs.
	// Its length is checked, since every sender serializes a point as 33
	// bytes. It is not checked to be a curve point: a decode error fails the
	// channel, and an honest relay can pass on a bad point chosen by the
	// path's creator. The node fails only that HTLC, with
	// invalid_onion_blinding (BOLT 2).
	let blindingPoint: Buffer | undefined;
	let skimmedFeeMsat: bigint | undefined;
	const customRecords = new Map<bigint, Buffer>();
	if (offset < payload.length) {
		const records = decodeWithCustomRecords(
			payload,
			offset,
			UPDATE_ADD_HTLC_TLV_TYPES
		);
		for (const record of records) {
			if (record.type === TLV_BLINDING_POINT) {
				if (record.value.length !== 33) {
					throw new Error(
						`update_add_htlc: blinding_point must be 33 bytes, got ${record.value.length}`
					);
				}
				blindingPoint = record.value;
			} else if (record.type === TLV_SKIMMED_FEE_MSAT) {
				if (record.value.length !== 8) {
					throw new Error('update_add_htlc: skimmed_fee_msat must be 8 bytes');
				}
				skimmedFeeMsat = record.value.readBigUInt64BE();
			} else if (record.type >= 65536n) {
				customRecords.set(record.type, Buffer.from(record.value));
			}
		}
	}

	const result: IUpdateAddHtlcMessage = {
		channelId,
		id,
		amountMsat,
		paymentHash,
		cltvExpiry,
		onionRoutingPacket
	};
	if (blindingPoint) {
		result.blindingPoint = blindingPoint;
	}
	if (skimmedFeeMsat !== undefined) result.skimmedFeeMsat = skimmedFeeMsat;
	if (customRecords.size) result.customRecords = customRecords;
	return result;
}

/**
 * Encode an `update_fulfill_htlc` message payload.
 */
export function encodeUpdateFulfillHtlcMessage(
	msg: IUpdateFulfillHtlcMessage
): Buffer {
	const buf = Buffer.alloc(UPDATE_FULFILL_HTLC_LENGTH);
	msg.channelId.copy(buf, 0);
	buf.writeBigUInt64BE(msg.id, 32);
	msg.paymentPreimage.copy(buf, 40);
	return buf;
}

/**
 * Decode an `update_fulfill_htlc` message payload.
 */
export function decodeUpdateFulfillHtlcMessage(
	payload: Buffer
): IUpdateFulfillHtlcMessage {
	if (payload.length < UPDATE_FULFILL_HTLC_LENGTH) {
		throw new Error(
			`update_fulfill_htlc too short: need ${UPDATE_FULFILL_HTLC_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const id = payload.readBigUInt64BE(32);
	const paymentPreimage = Buffer.from(payload.subarray(40, 72));

	return { channelId, id, paymentPreimage };
}

/**
 * Encode an `update_fail_htlc` message payload.
 */
export function encodeUpdateFailHtlcMessage(
	msg: IUpdateFailHtlcMessage
): Buffer {
	const buf = Buffer.alloc(UPDATE_FAIL_HTLC_FIXED_LENGTH + msg.reason.length);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.id, offset);
	offset += 8;
	buf.writeUInt16BE(msg.reason.length, offset);
	offset += 2;
	msg.reason.copy(buf, offset);

	return buf;
}

/**
 * Decode an `update_fail_htlc` message payload.
 */
export function decodeUpdateFailHtlcMessage(
	payload: Buffer
): IUpdateFailHtlcMessage {
	if (payload.length < UPDATE_FAIL_HTLC_FIXED_LENGTH) {
		throw new Error(
			`update_fail_htlc too short: need ${UPDATE_FAIL_HTLC_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const id = payload.readBigUInt64BE(offset);
	offset += 8;
	const len = payload.readUInt16BE(offset);
	offset += 2;

	if (offset + len > payload.length) {
		throw new Error(`update_fail_htlc reason length ${len} exceeds payload`);
	}

	const reason = Buffer.from(payload.subarray(offset, offset + len));

	return { channelId, id, reason };
}

/**
 * Encode an `update_fail_malformed_htlc` message payload.
 */
export function encodeUpdateFailMalformedHtlcMessage(
	msg: IUpdateFailMalformedHtlcMessage
): Buffer {
	const buf = Buffer.alloc(UPDATE_FAIL_MALFORMED_HTLC_LENGTH);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.id, offset);
	offset += 8;
	msg.sha256OfOnion.copy(buf, offset);
	offset += 32;
	buf.writeUInt16BE(msg.failureCode, offset);

	return buf;
}

/**
 * Decode an `update_fail_malformed_htlc` message payload.
 */
export function decodeUpdateFailMalformedHtlcMessage(
	payload: Buffer
): IUpdateFailMalformedHtlcMessage {
	if (payload.length < UPDATE_FAIL_MALFORMED_HTLC_LENGTH) {
		throw new Error(
			`update_fail_malformed_htlc too short: need ${UPDATE_FAIL_MALFORMED_HTLC_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const id = payload.readBigUInt64BE(offset);
	offset += 8;
	const sha256OfOnion = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const failureCode = payload.readUInt16BE(offset);

	return { channelId, id, sha256OfOnion, failureCode };
}

/**
 * Encode an `update_fee` message payload.
 */
export function encodeUpdateFeeMessage(msg: IUpdateFeeMessage): Buffer {
	const buf = Buffer.alloc(UPDATE_FEE_LENGTH);
	msg.channelId.copy(buf, 0);
	buf.writeUInt32BE(msg.feeratePerKw, 32);
	return buf;
}

/**
 * Decode an `update_fee` message payload.
 */
export function decodeUpdateFeeMessage(payload: Buffer): IUpdateFeeMessage {
	if (payload.length < UPDATE_FEE_LENGTH) {
		throw new Error(
			`update_fee too short: need ${UPDATE_FEE_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const feeratePerKw = payload.readUInt32BE(32);

	return { channelId, feeratePerKw };
}

const UPDATE_BLOCKHEIGHT_LENGTH = 36; // 32 + 4

/**
 * Encode an `update_blockheight` message payload (bLIP-0051, type 137).
 */
export function encodeUpdateBlockheightMessage(
	msg: IUpdateBlockheightMessage
): Buffer {
	const buf = Buffer.alloc(UPDATE_BLOCKHEIGHT_LENGTH);
	msg.channelId.copy(buf, 0);
	buf.writeUInt32BE(msg.blockheight, 32);
	return buf;
}

/**
 * Decode an `update_blockheight` message payload (bLIP-0051, type 137).
 */
export function decodeUpdateBlockheightMessage(
	payload: Buffer
): IUpdateBlockheightMessage {
	if (payload.length < UPDATE_BLOCKHEIGHT_LENGTH) {
		throw new Error(
			`update_blockheight too short: need ${UPDATE_BLOCKHEIGHT_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const blockheight = payload.readUInt32BE(32);

	return { channelId, blockheight };
}
