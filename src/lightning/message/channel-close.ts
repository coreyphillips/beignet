/**
 * BOLT 2: `shutdown` and `closing_signed` message encoding/decoding.
 *
 * shutdown (type 38):
 *   [32: channel_id]
 *   [2: len]
 *   [len: scriptpubkey]
 *
 * closing_signed (type 39):
 *   [32: channel_id]
 *   [8: fee_satoshis]
 *   [64: signature]
 */

export interface IShutdownMessage {
	channelId: Buffer;
	scriptPubkey: Buffer;
}

export interface IClosingSignedMessage {
	channelId: Buffer;
	feeSatoshis: bigint;
	signature: Buffer;
}

const SHUTDOWN_FIXED_LENGTH = 34; // 32 + 2
const CLOSING_SIGNED_LENGTH = 104; // 32 + 8 + 64

/**
 * Encode a `shutdown` message payload.
 */
export function encodeShutdownMessage(msg: IShutdownMessage): Buffer {
	const buf = Buffer.alloc(SHUTDOWN_FIXED_LENGTH + msg.scriptPubkey.length);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeUInt16BE(msg.scriptPubkey.length, offset);
	offset += 2;
	msg.scriptPubkey.copy(buf, offset);

	return buf;
}

/**
 * Decode a `shutdown` message payload.
 */
export function decodeShutdownMessage(payload: Buffer): IShutdownMessage {
	if (payload.length < SHUTDOWN_FIXED_LENGTH) {
		throw new Error(
			`shutdown too short: need ${SHUTDOWN_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const len = payload.readUInt16BE(offset);
	offset += 2;

	if (offset + len > payload.length) {
		throw new Error(`shutdown scriptpubkey length ${len} exceeds payload`);
	}

	const scriptPubkey = Buffer.from(payload.subarray(offset, offset + len));

	return { channelId, scriptPubkey };
}

/**
 * Encode a `closing_signed` message payload.
 */
export function encodeClosingSignedMessage(msg: IClosingSignedMessage): Buffer {
	const buf = Buffer.alloc(CLOSING_SIGNED_LENGTH);
	msg.channelId.copy(buf, 0);
	buf.writeBigUInt64BE(msg.feeSatoshis, 32);
	msg.signature.copy(buf, 40);
	return buf;
}

/**
 * Decode a `closing_signed` message payload.
 */
export function decodeClosingSignedMessage(
	payload: Buffer
): IClosingSignedMessage {
	if (payload.length < CLOSING_SIGNED_LENGTH) {
		throw new Error(
			`closing_signed too short: need ${CLOSING_SIGNED_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const feeSatoshis = payload.readBigUInt64BE(32);
	const signature = Buffer.from(payload.subarray(40, 104));

	return { channelId, feeSatoshis, signature };
}
