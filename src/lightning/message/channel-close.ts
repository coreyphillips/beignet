/**
 * BOLT 2: `shutdown`, `closing_signed`, and option_simple_close
 * `closing_complete` / `closing_sig` message encoding/decoding.
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
 *
 * closing_complete (type 40) / closing_sig (type 41):
 *   [32: channel_id]
 *   [2: len] [len: closer_scriptpubkey]
 *   [2: len] [len: closee_scriptpubkey]
 *   [8: fee_satoshis]
 *   [4: locktime]
 *   [closing_tlvs]
 * where ordinary closing_tlvs carries the 64-byte signature(s):
 *   type 1: closer_output_only
 *   type 2: closee_output_only
 *   type 3: closer_and_closee_outputs
 * closing_complete may carry two records (1 and 3); closing_sig must carry
 * exactly one, matching a field the closer sent (enforced in the state
 * machine, not the codec). Final Taproot uses 5/6/7 for partial signatures and
 * adds the next closee nonce in closing_sig (22).
 */

import type { CustomRecords } from './custom-records';
import {
	CUSTOM_RECORD_START,
	MAX_LIGHTNING_PAYLOAD,
	boundedLightningPayload,
	customRecordEntries,
	decodeWithCustomRecords
} from './custom-records';
import type { ITlvRecord } from './tlv';
import { decodeTlvStream, encodeTlvStream } from './tlv';

export interface IShutdownMessage {
	channelId: Buffer;
	scriptPubkey: Buffer;
	/**
	 * Records of the custom range (type 65536 and above) that travel beside
	 * the script on an asset channel. Absent on every other channel, whose
	 * encoding is unchanged.
	 */
	customRecords?: CustomRecords;
	/**
	 * MuSig2 closing pubnonce (66 bytes) for simple-taproot channels, carried
	 * as TLV type 8 (LND shutdown_nonce convention). Absent on non-taproot
	 * channels; the wire encoding is byte-identical to legacy when unset.
	 */
	shutdownNonce?: Buffer;
}

export interface IClosingSignedMessage {
	channelId: Buffer;
	feeSatoshis: bigint;
	signature: Buffer;
	/**
	 * MuSig2 partial signature (32 bytes) for simple-taproot channels, carried
	 * as TLV type 6 (LND partial_sig convention). When set, the fixed 64-byte
	 * `signature` field is zeroed on the wire.
	 */
	partialSignature?: Buffer;
}

const SHUTDOWN_FIXED_LENGTH = 34; // 32 + 2
const CLOSING_SIGNED_LENGTH = 104; // 32 + 8 + 64
const SHUTDOWN_NONCE_TLV = 8n;
const SHUTDOWN_NONCE_LENGTH = 66;
const SHUTDOWN_TLV_TYPES = new Set<bigint>([SHUTDOWN_NONCE_TLV]);
const CLOSING_PARTIAL_SIG_TLV = 6n;
const CLOSING_PARTIAL_SIG_LENGTH = 32;
const CLOSING_SIGNED_TLV_TYPES = new Set<bigint>([CLOSING_PARTIAL_SIG_TLV]);

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

	if (msg.customRecords !== undefined && msg.customRecords.size > 0) {
		// The asset records of a shutdown travel beside the nonce, in type
		// order, and have to fit one frame. A custom record may not take the
		// type of a field this message defines.
		const records = customRecordEntries(msg.customRecords, SHUTDOWN_TLV_TYPES);
		if (msg.shutdownNonce !== undefined) {
			if (msg.shutdownNonce.length !== SHUTDOWN_NONCE_LENGTH) {
				throw new Error(
					`shutdown_nonce must be ${SHUTDOWN_NONCE_LENGTH} bytes, got ${msg.shutdownNonce.length}`
				);
			}
			records.push({ type: SHUTDOWN_NONCE_TLV, value: msg.shutdownNonce });
		}
		records.sort((a, b) => (a.type < b.type ? -1 : 1));
		return boundedLightningPayload(
			Buffer.concat([buf, encodeTlvStream(records)])
		);
	}
	if (msg.shutdownNonce === undefined) return buf;
	if (msg.shutdownNonce.length !== SHUTDOWN_NONCE_LENGTH) {
		throw new Error(
			`shutdown_nonce must be ${SHUTDOWN_NONCE_LENGTH} bytes, got ${msg.shutdownNonce.length}`
		);
	}
	const tlvs = encodeTlvStream([
		{ type: SHUTDOWN_NONCE_TLV, value: msg.shutdownNonce }
	]);
	return Buffer.concat([buf, tlvs]);
}

/** How a `shutdown` payload is read. */
export interface IShutdownDecodeOptions {
	/**
	 * Read records of the custom range (type 65536 and above) into
	 * `customRecords`, whatever their parity. Off by default: the standard
	 * reader, which fails on an unknown even type and ignores an unknown odd
	 * one.
	 */
	customRecords?: boolean;
}

/**
 * Decode a `shutdown` message payload.
 */
export function decodeShutdownMessage(
	payload: Buffer,
	options: IShutdownDecodeOptions = {}
): IShutdownMessage {
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
	offset += len;

	const msg: IShutdownMessage = { channelId, scriptPubkey };
	if (offset < payload.length) {
		// Unknown even TLV types are rejected; unknown odd types are ignored.
		const records = options.customRecords
			? decodeWithCustomRecords(payload, offset, SHUTDOWN_TLV_TYPES)
			: decodeTlvStream(payload, offset, SHUTDOWN_TLV_TYPES).records;
		const custom = new Map<bigint, Buffer>();
		for (const r of records) {
			if (r.type === SHUTDOWN_NONCE_TLV) {
				if (r.value.length !== SHUTDOWN_NONCE_LENGTH) {
					throw new Error(
						`shutdown_nonce must be ${SHUTDOWN_NONCE_LENGTH} bytes, got ${r.value.length}`
					);
				}
				msg.shutdownNonce = Buffer.from(r.value);
			} else if (options.customRecords && r.type >= CUSTOM_RECORD_START) {
				custom.set(r.type, Buffer.from(r.value));
			}
		}
		if (custom.size > 0) msg.customRecords = custom;
	}
	return msg;
}

/**
 * Encode a `closing_signed` message payload.
 */
export function encodeClosingSignedMessage(msg: IClosingSignedMessage): Buffer {
	const buf = Buffer.alloc(CLOSING_SIGNED_LENGTH);
	msg.channelId.copy(buf, 0);
	buf.writeBigUInt64BE(msg.feeSatoshis, 32);
	if (msg.partialSignature === undefined) {
		msg.signature.copy(buf, 40);
		return buf;
	}
	if (msg.partialSignature.length !== CLOSING_PARTIAL_SIG_LENGTH) {
		throw new Error(
			`closing partial signature must be ${CLOSING_PARTIAL_SIG_LENGTH} bytes, got ${msg.partialSignature.length}`
		);
	}
	// Taproot: the fixed ECDSA field stays zeroed; the MuSig2 partial rides
	// in TLV type 6.
	const tlvs = encodeTlvStream([
		{ type: CLOSING_PARTIAL_SIG_TLV, value: msg.partialSignature }
	]);
	return Buffer.concat([buf, tlvs]);
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

	const msg: IClosingSignedMessage = { channelId, feeSatoshis, signature };
	if (payload.length > CLOSING_SIGNED_LENGTH) {
		// Unknown even TLV types are rejected; unknown odd types (e.g. LND's
		// fee_range, type 1) are ignored per BOLT 1.
		const { records } = decodeTlvStream(
			payload,
			CLOSING_SIGNED_LENGTH,
			CLOSING_SIGNED_TLV_TYPES
		);
		for (const r of records) {
			if (r.type === CLOSING_PARTIAL_SIG_TLV) {
				if (r.value.length !== CLOSING_PARTIAL_SIG_LENGTH) {
					throw new Error(
						`closing partial signature must be ${CLOSING_PARTIAL_SIG_LENGTH} bytes, got ${r.value.length}`
					);
				}
				msg.partialSignature = Buffer.from(r.value);
			}
			// LND also attaches an odd fee_range TLV (type 1); unknown odd
			// types are ignored per BOLT 1.
		}
	}
	return msg;
}

// ─────────────── option_simple_close ───────────────

/** closing_tlvs record types (each value is a 64-byte signature). */
export enum ClosingSigVariant {
	CLOSER_OUTPUT_ONLY = 1,
	CLOSEE_OUTPUT_ONLY = 2,
	CLOSER_AND_CLOSEE = 3
}

export interface IClosingCompleteMessage {
	channelId: Buffer;
	closerScriptPubkey: Buffer;
	closeeScriptPubkey: Buffer;
	feeSatoshis: bigint;
	locktime: number;
	/** Signature for a closing tx with only the closer's output (TLV 1). */
	closerOutputOnlySig?: Buffer;
	/** Signature for a closing tx with only the closee's output (TLV 2). */
	closeeOutputOnlySig?: Buffer;
	/** Signature for a closing tx with both outputs (TLV 3). */
	closerAndCloseeSig?: Buffer;
	/** Final TLVs 5, 6 and 7 carry a 32-byte partial plus its 66-byte nonce
	 * on a proposal, or the selected 32-byte partial alone on a reply. */
	closerOutputOnlyPartialSig?: Buffer;
	closeeOutputOnlyPartialSig?: Buffer;
	closerAndCloseePartialSig?: Buffer;
}

/** A final closing_sig also supplies the closee nonce for the next fee proposal. */
export interface IClosingSigMessage extends IClosingCompleteMessage {
	nextCloseeNonce?: Buffer;
}

export interface ISimpleCloseCodecOptions {
	/** Use the final Bitcoin Taproot channel's signature records. */
	finalTaproot?: boolean;
}

type SimpleCloseName = 'closing_complete' | 'closing_sig';

const CLOSING_TLV_TYPES = new Set<bigint>([1n, 2n, 3n]);

const FINAL_PARTIAL_SIG_FIELDS = [
	[5n, 'closerOutputOnlyPartialSig'],
	[6n, 'closeeOutputOnlyPartialSig'],
	[7n, 'closerAndCloseePartialSig']
] as const;
const NEXT_CLOSEE_NONCE = 22n;
const FINAL_COMPLETE_TYPES = new Set<bigint>(
	FINAL_PARTIAL_SIG_FIELDS.map(([type]) => type)
);
const FINAL_SIG_TYPES = new Set([...FINAL_COMPLETE_TYPES, NEXT_CLOSEE_NONCE]);

function finalClosingRecords(
	msg: IClosingSigMessage,
	name: SimpleCloseName
): ITlvRecord[] {
	if (
		msg.closerOutputOnlySig !== undefined ||
		msg.closeeOutputOnlySig !== undefined ||
		msg.closerAndCloseeSig !== undefined
	) {
		throw new Error(`${name}: final Taproot requires partial signatures`);
	}
	const reply = name === 'closing_sig';
	const length = reply ? 32 : 98;
	const records: ITlvRecord[] = [];
	for (const [type, field] of FINAL_PARTIAL_SIG_FIELDS) {
		const value = msg[field];
		if (value === undefined) continue;
		if (!Buffer.isBuffer(value) || value.length !== length) {
			throw new Error(
				`${name}: partial signature TLV ${type} must be ${length} bytes`
			);
		}
		records.push({ type, value });
	}
	if (records.length === 0 || (reply && records.length !== 1)) {
		throw new Error(
			`${name}: invalid number of final Taproot partial signatures`
		);
	}
	// Only the lesser-paid party can omit its own output.
	if (msg.closerOutputOnlyPartialSig && msg.closeeOutputOnlyPartialSig) {
		throw new Error('Conflicting single-output closing proposals');
	}
	if (reply) {
		if (
			!Buffer.isBuffer(msg.nextCloseeNonce) ||
			msg.nextCloseeNonce.length !== 66
		) {
			throw new Error('closing_sig requires a 66-byte next_closee_nonce');
		}
		records.push({ type: NEXT_CLOSEE_NONCE, value: msg.nextCloseeNonce });
	} else if (msg.nextCloseeNonce !== undefined) {
		throw new Error('next_closee_nonce is only valid on closing_sig');
	}
	return records;
}

function ordinaryClosingRecords(msg: IClosingSigMessage): ITlvRecord[] {
	if (
		msg.nextCloseeNonce !== undefined ||
		FINAL_PARTIAL_SIG_FIELDS.some(([, field]) => msg[field] !== undefined)
	) {
		throw new Error('Taproot closing fields require the final Taproot format');
	}
	const sigRecords: ITlvRecord[] = [];
	const pushSig = (type: bigint, sig?: Buffer): void => {
		if (!sig) return;
		if (sig.length !== 64) {
			throw new Error(`closing signature must be 64 bytes, got ${sig.length}`);
		}
		sigRecords.push({ type, value: sig });
	};
	pushSig(1n, msg.closerOutputOnlySig);
	pushSig(2n, msg.closeeOutputOnlySig);
	pushSig(3n, msg.closerAndCloseeSig);
	if (sigRecords.length === 0) {
		throw new Error('closing message requires at least one signature TLV');
	}

	return sigRecords;
}

function encodeSimpleCloseMessage(
	msg: IClosingSigMessage,
	name: SimpleCloseName,
	options: ISimpleCloseCodecOptions
): Buffer {
	const records = options.finalTaproot
		? finalClosingRecords(msg, name)
		: ordinaryClosingRecords(msg);
	const tlvs = encodeTlvStream(records);
	const fixedLength =
		48 + msg.closerScriptPubkey.length + msg.closeeScriptPubkey.length;
	if (options.finalTaproot) {
		if (msg.channelId.length !== 32)
			throw new Error(`${name}: channel_id must be 32 bytes`);
		if (fixedLength + tlvs.length > MAX_LIGHTNING_PAYLOAD)
			throw new Error('Lightning message exceeds BOLT 8 payload limit');
	}
	const fixed = Buffer.alloc(fixedLength);
	let offset = 0;
	msg.channelId.copy(fixed, offset);
	offset += 32;
	fixed.writeUInt16BE(msg.closerScriptPubkey.length, offset);
	offset += 2;
	msg.closerScriptPubkey.copy(fixed, offset);
	offset += msg.closerScriptPubkey.length;
	fixed.writeUInt16BE(msg.closeeScriptPubkey.length, offset);
	offset += 2;
	msg.closeeScriptPubkey.copy(fixed, offset);
	offset += msg.closeeScriptPubkey.length;
	fixed.writeBigUInt64BE(msg.feeSatoshis, offset);
	offset += 8;
	fixed.writeUInt32BE(msg.locktime, offset);

	return Buffer.concat([fixed, tlvs]);
}

function decodeSimpleCloseMessage(
	payload: Buffer,
	name: SimpleCloseName,
	options: ISimpleCloseCodecOptions
): IClosingSigMessage {
	if (options.finalTaproot) boundedLightningPayload(payload);
	// Minimum: channel_id + two empty-script length prefixes + fee + locktime
	if (payload.length < 32 + 2 + 2 + 8 + 4) {
		throw new Error(`${name} too short: got ${payload.length} bytes`);
	}

	let offset = 0;
	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;

	const readScript = (label: string): Buffer => {
		if (offset + 2 > payload.length) {
			throw new Error(`${name}: truncated ${label} length`);
		}
		const len = payload.readUInt16BE(offset);
		offset += 2;
		if (offset + len > payload.length) {
			throw new Error(`${name}: ${label} length ${len} exceeds payload`);
		}
		const script = Buffer.from(payload.subarray(offset, offset + len));
		offset += len;
		return script;
	};

	const closerScriptPubkey = readScript('closer_scriptpubkey');
	const closeeScriptPubkey = readScript('closee_scriptpubkey');

	if (offset + 12 > payload.length) {
		throw new Error(`${name}: truncated fee/locktime`);
	}
	const feeSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const locktime = payload.readUInt32BE(offset);
	offset += 4;

	// Unknown even TLV types are rejected; unknown odd types are ignored.
	const msg: IClosingSigMessage = {
		channelId,
		closerScriptPubkey,
		closeeScriptPubkey,
		feeSatoshis,
		locktime
	};
	if (options.finalTaproot) {
		const types =
			name === 'closing_sig' ? FINAL_SIG_TYPES : FINAL_COMPLETE_TYPES;
		const { records } = decodeTlvStream(payload, offset, types);
		for (const record of records) {
			if (CLOSING_TLV_TYPES.has(record.type)) {
				throw new Error(
					`${name}: unexpected ECDSA signature TLV ${record.type}`
				);
			}
			if (record.type === NEXT_CLOSEE_NONCE) {
				msg.nextCloseeNonce = record.value;
			} else {
				const entry = FINAL_PARTIAL_SIG_FIELDS.find(
					([type]) => type === record.type
				);
				if (entry) msg[entry[1]] = record.value;
			}
		}
		finalClosingRecords(msg, name);
		return msg;
	}
	const { records } = decodeTlvStream(payload, offset, CLOSING_TLV_TYPES);
	for (const record of records) {
		if (!CLOSING_TLV_TYPES.has(record.type)) continue;
		if (record.value.length !== 64) {
			throw new Error(
				`${name}: closing signature TLV ${record.type} must be 64 bytes, ` +
					`got ${record.value.length}`
			);
		}
		if (record.type === 1n) msg.closerOutputOnlySig = record.value;
		else if (record.type === 2n) msg.closeeOutputOnlySig = record.value;
		else msg.closerAndCloseeSig = record.value;
	}

	if (
		!msg.closerOutputOnlySig &&
		!msg.closeeOutputOnlySig &&
		!msg.closerAndCloseeSig
	) {
		throw new Error(`${name}: no closing signature TLV present`);
	}

	return msg;
}

/** Encode a `closing_complete` (type 40) message payload. */
export function encodeClosingCompleteMessage(
	msg: IClosingCompleteMessage,
	options: ISimpleCloseCodecOptions = {}
): Buffer {
	return encodeSimpleCloseMessage(msg, 'closing_complete', options);
}

/** Decode a `closing_complete` (type 40) message payload. */
export function decodeClosingCompleteMessage(
	payload: Buffer,
	options: ISimpleCloseCodecOptions = {}
): IClosingCompleteMessage {
	return decodeSimpleCloseMessage(payload, 'closing_complete', options);
}

/** Encode a `closing_sig` (type 41) message payload. */
export function encodeClosingSigMessage(
	msg: IClosingSigMessage,
	options: ISimpleCloseCodecOptions = {}
): Buffer {
	return encodeSimpleCloseMessage(msg, 'closing_sig', options);
}

/** Decode a `closing_sig` (type 41) message payload. */
export function decodeClosingSigMessage(
	payload: Buffer,
	options: ISimpleCloseCodecOptions = {}
): IClosingSigMessage {
	return decodeSimpleCloseMessage(payload, 'closing_sig', options);
}
