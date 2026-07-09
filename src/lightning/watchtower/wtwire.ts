/**
 * LND watchtower wire protocol (wtwire) message codecs.
 *
 * Messages ride the standard BOLT 8 Noise transport (towers listen on a
 * separate port and speak this protocol INSTEAD of BOLT 1). Framing is a
 * 2-byte big-endian message type followed by the payload; the outer transport
 * supplies length + MAC, so these codecs only handle the type+payload body.
 *
 * Field widths mirror lnd/watchtower/wtwire exactly (verified against master):
 *   - integers big-endian; []byte slices use a wire varint length prefix
 *     (wire.WriteVarBytes); fixed arrays ([16]byte hint) have no prefix.
 */

/** wtwire message type numbers (lnd MsgInit..MsgDeleteSessionReply, 600-607). */
export enum WtMessageType {
	INIT = 600,
	ERROR = 601,
	CREATE_SESSION = 602,
	CREATE_SESSION_REPLY = 603,
	STATE_UPDATE = 604,
	STATE_UPDATE_REPLY = 605,
	DELETE_SESSION = 606,
	DELETE_SESSION_REPLY = 607
}

/**
 * wtwire feature bits (lnd/watchtower/wtwire/features.go). Altruist sessions are
 * bit 0/1; anchor and taproot commitment support are 2/3 and 4/5.
 */
export enum WtFeatureBit {
	ALTRUIST_SESSIONS_REQUIRED = 0,
	ALTRUIST_SESSIONS_OPTIONAL = 1,
	ANCHOR_COMMIT_REQUIRED = 2,
	ANCHOR_COMMIT_OPTIONAL = 3,
	TAPROOT_COMMIT_REQUIRED = 4,
	TAPROOT_COMMIT_OPTIONAL = 5
}

/** Generic wtwire ErrorCode values (error_code.go). */
export enum WtErrorCode {
	OK = 0,
	TEMPORARY_FAILURE = 40,
	PERMANENT_FAILURE = 50
}

/** CreateSessionReply rejection codes (create_session_reply.go). */
export enum CreateSessionCode {
	OK = 0,
	REJECT_ALREADY_EXISTS = 60,
	REJECT_MAX_UPDATES = 61,
	REJECT_REWARD_RATE = 62,
	REJECT_SWEEP_FEE_RATE = 63,
	REJECT_BLOB_TYPE = 64
}

/** StateUpdateReply codes (error_code.go StateUpdateCode block). */
export enum StateUpdateCode {
	OK = 0,
	/** Tower's LastApplied is ahead of the client's SeqNum. */
	CLIENT_BEHIND = 40,
	MAX_UPDATES_EXCEEDED = 41,
	SEQ_NUM_OUT_OF_ORDER = 42
}

export interface IWtInit {
	/** Raw connection feature vector bytes (lnwire RawFeatureVector body). */
	connFeatures: Buffer;
	/** 32-byte genesis/chain hash (internal byte order as sent on the wire). */
	chainHash: Buffer;
}

export interface IWtError {
	code: number;
	data: Buffer;
}

export interface IWtCreateSession {
	/** blob.Type (uint16 on the wire; see blob.ts BlobType). */
	blobType: number;
	maxUpdates: number;
	rewardBase: number;
	rewardRate: number;
	/** Sweep fee rate in sat/kw. */
	sweepFeeRate: bigint;
}

export interface IWtCreateSessionReply {
	code: number;
	lastApplied: number;
	data: Buffer;
}

export interface IWtStateUpdate {
	seqNum: number;
	lastApplied: number;
	/** 1 if this is the final update of the session, else 0. */
	isComplete: number;
	/** 16-byte breach hint. */
	hint: Buffer;
	/** Encrypted justice blob. */
	encryptedBlob: Buffer;
}

export interface IWtStateUpdateReply {
	code: number;
	lastApplied: number;
}

export interface IWtDeleteSession {
	/** Empty payload in the current protocol. */
	_?: never;
}

export interface IWtDeleteSessionReply {
	code: number;
}

/**
 * Encode a []byte with a wire varint (CompactSize) length prefix, matching
 * lnd's wire.WriteVarBytes. wtwire slices never exceed 66000 bytes so the
 * prefix is at most 3 bytes.
 */
function writeVarBytes(buf: Buffer): Buffer {
	return Buffer.concat([writeVarInt(buf.length), buf]);
}

function writeVarInt(n: number): Buffer {
	if (n < 0xfd) {
		return Buffer.from([n]);
	}
	if (n <= 0xffff) {
		const b = Buffer.alloc(3);
		b[0] = 0xfd;
		b.writeUInt16LE(n, 1);
		return b;
	}
	if (n <= 0xffffffff) {
		const b = Buffer.alloc(5);
		b[0] = 0xfe;
		b.writeUInt32LE(n, 1);
		return b;
	}
	const b = Buffer.alloc(9);
	b[0] = 0xff;
	b.writeBigUInt64LE(BigInt(n), 1);
	return b;
}

function readVarInt(
	buf: Buffer,
	offset: number
): { value: number; next: number } {
	const first = buf.readUInt8(offset);
	if (first < 0xfd) {
		return { value: first, next: offset + 1 };
	}
	if (first === 0xfd) {
		return { value: buf.readUInt16LE(offset + 1), next: offset + 3 };
	}
	if (first === 0xfe) {
		return { value: buf.readUInt32LE(offset + 1), next: offset + 5 };
	}
	return { value: Number(buf.readBigUInt64LE(offset + 1)), next: offset + 9 };
}

function readVarBytes(
	buf: Buffer,
	offset: number
): { value: Buffer; next: number } {
	const { value: len, next } = readVarInt(buf, offset);
	if (next + len > buf.length) {
		throw new Error('wtwire: var bytes length exceeds buffer');
	}
	return { value: buf.subarray(next, next + len), next: next + len };
}

export function encodeInit(msg: IWtInit): Buffer {
	if (msg.chainHash.length !== 32) {
		throw new Error('wtwire init: chainHash must be 32 bytes');
	}
	// RawFeatureVector encodes as a 2-byte length prefix followed by the bytes.
	const feat = Buffer.concat([u16(msg.connFeatures.length), msg.connFeatures]);
	return Buffer.concat([feat, msg.chainHash]);
}

export function decodeInit(payload: Buffer): IWtInit {
	const featLen = payload.readUInt16BE(0);
	const connFeatures = payload.subarray(2, 2 + featLen);
	const chainHash = payload.subarray(2 + featLen, 2 + featLen + 32);
	if (chainHash.length !== 32) {
		throw new Error('wtwire init: truncated chainHash');
	}
	return { connFeatures, chainHash };
}

export function encodeError(msg: IWtError): Buffer {
	return Buffer.concat([u16(msg.code), writeVarBytes(msg.data)]);
}

export function decodeError(payload: Buffer): IWtError {
	const code = payload.readUInt16BE(0);
	const { value: data } = readVarBytes(payload, 2);
	return { code, data };
}

export function encodeCreateSession(msg: IWtCreateSession): Buffer {
	const b = Buffer.alloc(20);
	b.writeUInt16BE(msg.blobType, 0);
	b.writeUInt16BE(msg.maxUpdates, 2);
	b.writeUInt32BE(msg.rewardBase, 4);
	b.writeUInt32BE(msg.rewardRate, 8);
	b.writeBigUInt64BE(msg.sweepFeeRate, 12);
	return b;
}

export function decodeCreateSession(payload: Buffer): IWtCreateSession {
	return {
		blobType: payload.readUInt16BE(0),
		maxUpdates: payload.readUInt16BE(2),
		rewardBase: payload.readUInt32BE(4),
		rewardRate: payload.readUInt32BE(8),
		sweepFeeRate: payload.readBigUInt64BE(12)
	};
}

export function encodeCreateSessionReply(msg: IWtCreateSessionReply): Buffer {
	return Buffer.concat([
		u16(msg.code),
		u16(msg.lastApplied),
		writeVarBytes(msg.data)
	]);
}

export function decodeCreateSessionReply(
	payload: Buffer
): IWtCreateSessionReply {
	const code = payload.readUInt16BE(0);
	const lastApplied = payload.readUInt16BE(2);
	const { value: data } = readVarBytes(payload, 4);
	return { code, lastApplied, data };
}

export function encodeStateUpdate(msg: IWtStateUpdate): Buffer {
	if (msg.hint.length !== 16) {
		throw new Error('wtwire state_update: hint must be 16 bytes');
	}
	const head = Buffer.alloc(5);
	head.writeUInt16BE(msg.seqNum, 0);
	head.writeUInt16BE(msg.lastApplied, 2);
	head.writeUInt8(msg.isComplete, 4);
	return Buffer.concat([head, msg.hint, writeVarBytes(msg.encryptedBlob)]);
}

export function decodeStateUpdate(payload: Buffer): IWtStateUpdate {
	const seqNum = payload.readUInt16BE(0);
	const lastApplied = payload.readUInt16BE(2);
	const isComplete = payload.readUInt8(4);
	const hint = payload.subarray(5, 21);
	const { value: encryptedBlob } = readVarBytes(payload, 21);
	return { seqNum, lastApplied, isComplete, hint, encryptedBlob };
}

export function encodeStateUpdateReply(msg: IWtStateUpdateReply): Buffer {
	return Buffer.concat([u16(msg.code), u16(msg.lastApplied)]);
}

export function decodeStateUpdateReply(payload: Buffer): IWtStateUpdateReply {
	return {
		code: payload.readUInt16BE(0),
		lastApplied: payload.readUInt16BE(2)
	};
}

export function encodeDeleteSession(): Buffer {
	return Buffer.alloc(0);
}

export function encodeDeleteSessionReply(msg: IWtDeleteSessionReply): Buffer {
	return u16(msg.code);
}

export function decodeDeleteSessionReply(
	payload: Buffer
): IWtDeleteSessionReply {
	return { code: payload.readUInt16BE(0) };
}

function u16(n: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n, 0);
	return b;
}
