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

export interface IUpdateAddHtlcMessage {
	channelId: Buffer;
	id: bigint;
	amountMsat: bigint;
	paymentHash: Buffer;
	cltvExpiry: number;
	onionRoutingPacket: Buffer;
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

const UPDATE_ADD_HTLC_LENGTH = 1450; // 32 + 8 + 8 + 32 + 4 + 1366
const UPDATE_FULFILL_HTLC_LENGTH = 72; // 32 + 8 + 32
const UPDATE_FAIL_HTLC_FIXED_LENGTH = 42; // 32 + 8 + 2
const UPDATE_FAIL_MALFORMED_HTLC_LENGTH = 74; // 32 + 8 + 32 + 2
const UPDATE_FEE_LENGTH = 36; // 32 + 4

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

	return buf;
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

	return {
		channelId,
		id,
		amountMsat,
		paymentHash,
		cltvExpiry,
		onionRoutingPacket
	};
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
