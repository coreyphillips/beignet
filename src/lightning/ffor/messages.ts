/**
 * FFOR Variant D wire codecs (spec sections 7, 7.5.4, 11.1, 14) and the
 * section 7 signing rule.
 *
 * Every message body begins `[32: channel_id][32: epoch_id]`. A signed message
 * ends with a 64-byte compact low-S ECDSA signature by the sender's node key
 * over
 *
 *     SHA256("ffor/msg" || [2: type] || body_excluding_the_signature)
 *
 * signed directly (one SHA256). The TLV stream sits between the last fixed
 * field and the signature, has no length prefix, and may be empty. Unknown
 * odd TLVs are permitted and covered by the digest; unknown even TLVs are a
 * decode error, as in BOLT 1.
 *
 * "Wire bytes", the input of the section 7.5.2 transcript hashes, are
 * `[2: type] || body` exactly as sent.
 */

import crypto from 'crypto';
import { sign, verify } from '../crypto/ecdh';
import {
	decodeTlvStream,
	encodeTlvStream,
	findTlvRecord,
	ITlvRecord
} from '../message/tlv';
import {
	FF_ABORT_TYPE,
	FF_ACCEPT_TYPE,
	FF_ACTIVATE_ACK_TYPE,
	FF_ACTIVATE_TYPE,
	FF_CLOSE_ACK_TYPE,
	FF_CLOSE_TYPE,
	FF_ERROR_TYPE,
	FF_INIT_TYPE,
	FF_INVOICES_TYPE,
	FF_REESTABLISH_TLV_TYPE,
	FforAbortReason,
	FforState,
	IFforAbortMessage,
	IFforAcceptMessage,
	IFforActivateAckMessage,
	IFforActivateMessage,
	IFforCloseAckMessage,
	IFforCloseMessage,
	IFforErrorMessage,
	IFforInitMessage,
	IFforInvoicesMessage,
	IFforReestablishTlv
} from './types';

const HEADER_LEN = 64;
const SIG_LEN = 64;
const MSG_TAG = Buffer.from('ffor/msg', 'ascii');

/** Human-readable names for logs and tests. */
export function fforMessageName(type: number): string {
	switch (type) {
		case FF_INIT_TYPE:
			return 'ff_init';
		case FF_ACCEPT_TYPE:
			return 'ff_accept';
		case FF_INVOICES_TYPE:
			return 'ff_invoices';
		case FF_ERROR_TYPE:
			return 'ff_error';
		case FF_ACTIVATE_TYPE:
			return 'ff_activate';
		case FF_ACTIVATE_ACK_TYPE:
			return 'ff_activate_ack';
		case FF_ABORT_TYPE:
			return 'ff_abort';
		case FF_CLOSE_TYPE:
			return 'ff_close';
		case FF_CLOSE_ACK_TYPE:
			return 'ff_close_ack';
		default:
			return `ff_unknown(${type})`;
	}
}

/** True for every message type this module decodes. */
export function isFforMessageType(type: number): boolean {
	return (
		type === FF_INIT_TYPE ||
		type === FF_ACCEPT_TYPE ||
		type === FF_INVOICES_TYPE ||
		type === FF_ERROR_TYPE ||
		type === FF_ACTIVATE_TYPE ||
		type === FF_ACTIVATE_ACK_TYPE ||
		type === FF_ABORT_TYPE ||
		type === FF_CLOSE_TYPE ||
		type === FF_CLOSE_ACK_TYPE
	);
}

// ---------------------------------------------------------------------------
// Small encoders
// ---------------------------------------------------------------------------

function u8(v: number): Buffer {
	return Buffer.from([v & 0xff]);
}
function u16(v: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(v, 0);
	return b;
}
function u32(v: number): Buffer {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(v >>> 0, 0);
	return b;
}
function u64(v: bigint): Buffer {
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(v, 0);
	return b;
}

function assert32(b: Buffer, name: string): void {
	if (b.length !== 32) {
		throw new Error(`${name} must be 32 bytes, got ${b.length}`);
	}
}

/** Reader over a body with bounds checks that throw a descriptive error. */
class Reader {
	private pos = 0;
	constructor(
		private readonly buf: Buffer,
		private readonly name: string
	) {}
	get offset(): number {
		return this.pos;
	}
	remaining(): number {
		return this.buf.length - this.pos;
	}
	private need(n: number): void {
		if (this.pos + n > this.buf.length) {
			throw new Error(`${this.name} too short at offset ${this.pos}`);
		}
	}
	bytes(n: number): Buffer {
		this.need(n);
		const out = Buffer.from(this.buf.subarray(this.pos, this.pos + n));
		this.pos += n;
		return out;
	}
	u8(): number {
		this.need(1);
		return this.buf[this.pos++];
	}
	u16(): number {
		this.need(2);
		const v = this.buf.readUInt16BE(this.pos);
		this.pos += 2;
		return v;
	}
	u32(): number {
		this.need(4);
		const v = this.buf.readUInt32BE(this.pos);
		this.pos += 4;
		return v;
	}
	u64(): bigint {
		this.need(8);
		const v = this.buf.readBigUInt64BE(this.pos);
		this.pos += 8;
		return v;
	}
	rest(): Buffer {
		return this.bytes(this.remaining());
	}
}

// ---------------------------------------------------------------------------
// Section 7 signing rule
// ---------------------------------------------------------------------------

/** SHA256("ffor/msg" || type || body_excluding_the_signature). */
export function fforMessageDigest(type: number, unsignedBody: Buffer): Buffer {
	return crypto
		.createHash('sha256')
		.update(MSG_TAG)
		.update(u16(type))
		.update(unsignedBody)
		.digest();
}

/** Append the node-key signature to an unsigned body, giving the wire body. */
export function signFforMessage(
	type: number,
	unsignedBody: Buffer,
	nodePrivateKey: Buffer
): Buffer {
	const sig = sign(fforMessageDigest(type, unsignedBody), nodePrivateKey);
	return Buffer.concat([unsignedBody, sig]);
}

/**
 * Verify the final 64 bytes of a signed body against the sender's node id.
 * Strict low-S, as the spec requires of every signature.
 */
export function verifyFforMessage(
	type: number,
	body: Buffer,
	nodeId: Buffer
): boolean {
	if (body.length < HEADER_LEN + SIG_LEN) return false;
	const unsigned = body.subarray(0, body.length - SIG_LEN);
	const sig = body.subarray(body.length - SIG_LEN);
	return verify(fforMessageDigest(type, unsigned), nodeId, sig, true);
}

/** `[2: type] || body`: the section 7.5.2 "wire bytes". */
export function fforWireBytes(type: number, body: Buffer): Buffer {
	return Buffer.concat([u16(type), body]);
}

/** The `[32: channel_id][32: epoch_id]` header of any FFOR body. */
export function decodeFforHeader(body: Buffer): {
	channelId: Buffer;
	epochId: Buffer;
} {
	if (body.length < HEADER_LEN) {
		throw new Error('FFOR message too short for its header');
	}
	return {
		channelId: Buffer.from(body.subarray(0, 32)),
		epochId: Buffer.from(body.subarray(32, 64))
	};
}

/**
 * Split a signed body into its unsigned part, its TLV stream (starting at
 * `fixedEnd`) and its signature, decoding the TLVs with BOLT 1 rules.
 */
function splitSigned(
	body: Buffer,
	fixedEnd: number,
	knownEven: bigint[],
	name: string
): { unsigned: Buffer; tlvs: ITlvRecord[]; signature: Buffer } {
	if (body.length < fixedEnd + SIG_LEN) {
		throw new Error(`${name} too short`);
	}
	const unsigned = Buffer.from(body.subarray(0, body.length - SIG_LEN));
	const signature = Buffer.from(body.subarray(body.length - SIG_LEN));
	const stream = unsigned.subarray(fixedEnd);
	const { records } = decodeTlvStream(stream, 0, new Set(knownEven));
	return { unsigned, tlvs: records, signature };
}

function tlvList(records: ITlvRecord[], type: bigint): Buffer | undefined {
	return findTlvRecord(records, type);
}

function splitFixed(value: Buffer, size: number, what: string): Buffer[] {
	if (value.length % size !== 0) {
		throw new Error(
			`${what}: length ${value.length} is not a multiple of ${size}`
		);
	}
	const out: Buffer[] = [];
	for (let i = 0; i < value.length; i += size) {
		out.push(Buffer.from(value.subarray(i, i + size)));
	}
	return out;
}

// ---------------------------------------------------------------------------
// ff_init (55001)
// ---------------------------------------------------------------------------

/** The unsigned body of ff_init: header, fixed fields, TLV stream. */
export function encodeFforInitUnsigned(
	msg: Omit<IFforInitMessage, 'signature'>
): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	if (msg.rPerCommitmentPoints.length > 0xffff) {
		throw new Error('too many r_per_commitment_points');
	}
	for (const p of msg.rPerCommitmentPoints) {
		if (p.length !== 33)
			throw new Error('per-commitment point must be 33 bytes');
	}
	const fixed = Buffer.concat([
		u8(msg.variant),
		u64(msg.budgetMsat),
		u16(msg.maxPayments),
		u64(msg.minPaymentMsat),
		u32(msg.settlementDeadline),
		u32(msg.voucherExpiry),
		u32(msg.feeBaseMsat),
		u32(msg.feeProportionalMillionths),
		u64(msg.escapeGranularityMsat),
		u16(msg.rPerCommitmentPoints.length),
		...msg.rPerCommitmentPoints
	]);
	const records: ITlvRecord[] = [];
	if (msg.paymentHashes && msg.paymentHashes.length > 0) {
		records.push({ type: 1n, value: Buffer.concat(msg.paymentHashes) });
	}
	if (msg.towerNodeId) {
		records.push({ type: 3n, value: msg.towerNodeId });
	}
	if (msg.towerUri) {
		records.push({ type: 5n, value: msg.towerUri });
	}
	if (msg.voucherAmountsMsat.length > 0) {
		records.push({
			type: 9n,
			value: Buffer.concat(msg.voucherAmountsMsat.map((a) => u64(a)))
		});
	}
	if (msg.witnessPeers && msg.witnessPeers.length > 0) {
		if (msg.witnessPeers.length > 0xffff) {
			throw new Error('too many witness_peers');
		}
		for (const id of msg.witnessPeers) assertNodeId(id, 'witness_peers');
		records.push({
			type: 13n,
			value: Buffer.concat([u16(msg.witnessPeers.length), ...msg.witnessPeers])
		});
	}
	if (msg.hashChain) {
		records.push({ type: 15n, value: u8(1) });
	}
	return Buffer.concat([
		msg.channelId,
		msg.epochId,
		fixed,
		encodeTlvStream(records)
	]);
}

function assertNodeId(id: Buffer, what: string): void {
	if (id.length !== 33 || (id[0] !== 0x02 && id[0] !== 0x03)) {
		throw new Error(`${what}: not a compressed node id`);
	}
}

/** ff_init TLV 13: `[2: count][count * 33: node ids]`. */
function decodeWitnessPeers(value: Buffer): Buffer[] {
	if (value.length < 2) throw new Error('ff_init TLV 13 is truncated');
	const count = value.readUInt16BE(0);
	if (value.length !== 2 + 33 * count) {
		throw new Error('ff_init TLV 13 length does not match its count');
	}
	if (count === 0) throw new Error('ff_init TLV 13 names no peer');
	const ids = splitFixed(value.subarray(2), 33, 'ff_init TLV 13');
	for (const id of ids) assertNodeId(id, 'ff_init TLV 13');
	return ids;
}

/** Decode a signed ff_init body. Does not verify the signature. */
export function decodeFforInitMessage(body: Buffer): IFforInitMessage {
	const r = new Reader(body, 'ff_init');
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const variant = r.u8();
	const budgetMsat = r.u64();
	const maxPayments = r.u16();
	const minPaymentMsat = r.u64();
	const settlementDeadline = r.u32();
	const voucherExpiry = r.u32();
	const feeBaseMsat = r.u32();
	const feeProportionalMillionths = r.u32();
	const escapeGranularityMsat = r.u64();
	const count = r.u16();
	const rPerCommitmentPoints: Buffer[] = [];
	for (let i = 0; i < count; i++) rPerCommitmentPoints.push(r.bytes(33));
	const { tlvs, signature } = splitSigned(body, r.offset, [], 'ff_init');
	const hashes = tlvList(tlvs, 1n);
	const tower = tlvList(tlvs, 3n);
	const uri = tlvList(tlvs, 5n);
	const amounts = tlvList(tlvs, 9n);
	const witnessPeers = tlvList(tlvs, 13n);
	const hashChain = tlvList(tlvs, 15n);
	if (tower !== undefined && tower.length !== 33) {
		throw new Error('ff_init TLV 3 must be 33 bytes');
	}
	if (
		hashChain !== undefined &&
		(hashChain.length !== 1 || hashChain[0] !== 1)
	) {
		throw new Error('ff_init TLV 15 must be the single byte 1');
	}
	return {
		channelId,
		epochId,
		variant,
		budgetMsat,
		maxPayments,
		minPaymentMsat,
		settlementDeadline,
		voucherExpiry,
		feeBaseMsat,
		feeProportionalMillionths,
		escapeGranularityMsat,
		rPerCommitmentPoints,
		...(hashes !== undefined
			? { paymentHashes: splitFixed(hashes, 32, 'ff_init TLV 1') }
			: {}),
		...(tower !== undefined ? { towerNodeId: tower } : {}),
		...(uri !== undefined ? { towerUri: uri } : {}),
		voucherAmountsMsat:
			amounts !== undefined
				? splitFixed(amounts, 8, 'ff_init TLV 9').map((b) =>
						b.readBigUInt64BE(0)
				  )
				: [],
		...(witnessPeers !== undefined
			? { witnessPeers: decodeWitnessPeers(witnessPeers) }
			: {}),
		...(hashChain !== undefined ? { hashChain: true } : {}),
		signature
	};
}

// ---------------------------------------------------------------------------
// ff_accept (55003)
// ---------------------------------------------------------------------------

export function encodeFforAcceptUnsigned(
	msg: Omit<IFforAcceptMessage, 'signature'>
): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	assert32(msg.initHash, 'init_hash');
	for (const h of msg.paymentHashes) assert32(h, 'payment_hash');
	const records: ITlvRecord[] = [
		{ type: 1n, value: Buffer.concat(msg.paymentHashes) },
		{ type: 7n, value: u64(msg.sHtlcIdBase) }
	];
	if (msg.voucherAmountsMsat.length > 0) {
		records.push({
			type: 9n,
			value: Buffer.concat(msg.voucherAmountsMsat.map((a) => u64(a)))
		});
	}
	records.push({ type: 11n, value: msg.initHash });
	return Buffer.concat([
		msg.channelId,
		msg.epochId,
		u64(msg.sCommitmentNumber),
		encodeTlvStream(records)
	]);
}

export function decodeFforAcceptMessage(body: Buffer): IFforAcceptMessage {
	const r = new Reader(body, 'ff_accept');
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const sCommitmentNumber = r.u64();
	const { tlvs, signature } = splitSigned(body, r.offset, [], 'ff_accept');
	const hashes = tlvList(tlvs, 1n);
	const base = tlvList(tlvs, 7n);
	const amounts = tlvList(tlvs, 9n);
	const initHash = tlvList(tlvs, 11n);
	if (hashes === undefined) throw new Error('ff_accept: TLV 1 required');
	if (base === undefined || base.length !== 8) {
		throw new Error('ff_accept: TLV 7 (s_htlc_id_base) required, 8 bytes');
	}
	if (initHash === undefined || initHash.length !== 32) {
		throw new Error('ff_accept: TLV 11 (init_hash) required, 32 bytes');
	}
	return {
		channelId,
		epochId,
		sCommitmentNumber,
		paymentHashes: splitFixed(hashes, 32, 'ff_accept TLV 1'),
		sHtlcIdBase: base.readBigUInt64BE(0),
		voucherAmountsMsat:
			amounts !== undefined
				? splitFixed(amounts, 8, 'ff_accept TLV 9').map((b) =>
						b.readBigUInt64BE(0)
				  )
				: [],
		initHash,
		signature
	};
}

// ---------------------------------------------------------------------------
// ff_invoices (55005), unsigned, chunked
// ---------------------------------------------------------------------------

export function encodeFforInvoicesMessage(msg: IFforInvoicesMessage): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	const parts: Buffer[] = [
		msg.channelId,
		msg.epochId,
		u16(msg.firstIndex),
		u16(msg.totalInvoices),
		u16(msg.invoices.length)
	];
	for (const inv of msg.invoices) {
		const b = Buffer.from(inv, 'ascii');
		if (b.length > 0xffff) throw new Error('invoice too long');
		parts.push(u16(b.length), b);
	}
	return Buffer.concat(parts);
}

export function decodeFforInvoicesMessage(body: Buffer): IFforInvoicesMessage {
	const r = new Reader(body, 'ff_invoices');
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const firstIndex = r.u16();
	const totalInvoices = r.u16();
	const num = r.u16();
	const invoices: string[] = [];
	for (let i = 0; i < num; i++) {
		const len = r.u16();
		invoices.push(r.bytes(len).toString('ascii'));
	}
	if (r.remaining() !== 0) throw new Error('ff_invoices: trailing bytes');
	return { channelId, epochId, firstIndex, totalInvoices, invoices };
}

// ---------------------------------------------------------------------------
// ff_error (55023), unsigned
// ---------------------------------------------------------------------------

export function encodeFforErrorMessage(msg: IFforErrorMessage): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	if (msg.data.length > 0xffff) throw new Error('ff_error data too long');
	return Buffer.concat([
		msg.channelId,
		msg.epochId,
		u16(msg.data.length),
		msg.data
	]);
}

export function decodeFforErrorMessage(body: Buffer): IFforErrorMessage {
	const r = new Reader(body, 'ff_error');
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const len = r.u16();
	return { channelId, epochId, data: r.bytes(len) };
}

// ---------------------------------------------------------------------------
// ff_activate (55045)
// ---------------------------------------------------------------------------

export function encodeFforActivateUnsigned(
	msg: Omit<IFforActivateMessage, 'signature'>
): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	assert32(msg.setupHash, 'setup_hash');
	assert32(msg.bookHash, 'book_hash');
	assert32(msg.commitHash, 'commit_hash');
	return Buffer.concat([
		msg.channelId,
		msg.epochId,
		msg.setupHash,
		msg.bookHash,
		msg.commitHash,
		u32(msg.epochStartHeight)
	]);
}

export function decodeFforActivateMessage(body: Buffer): IFforActivateMessage {
	const r = new Reader(body, 'ff_activate');
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const setupHash = r.bytes(32);
	const bookHash = r.bytes(32);
	const commitHash = r.bytes(32);
	const epochStartHeight = r.u32();
	const { signature } = splitSigned(body, r.offset, [], 'ff_activate');
	return {
		channelId,
		epochId,
		setupHash,
		bookHash,
		commitHash,
		epochStartHeight,
		signature
	};
}

// ---------------------------------------------------------------------------
// ff_activate_ack (55047), ff_close (55051): header + activation_hash
// ---------------------------------------------------------------------------

function encodeHashOnlyUnsigned(
	msg: { channelId: Buffer; epochId: Buffer; activationHash: Buffer },
	name: string
): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	assert32(msg.activationHash, `${name} activation_hash`);
	return Buffer.concat([msg.channelId, msg.epochId, msg.activationHash]);
}

function decodeHashOnly(body: Buffer, name: string): IFforActivateAckMessage {
	const r = new Reader(body, name);
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const activationHash = r.bytes(32);
	const { signature } = splitSigned(body, r.offset, [], name);
	return { channelId, epochId, activationHash, signature };
}

export function encodeFforActivateAckUnsigned(
	msg: Omit<IFforActivateAckMessage, 'signature'>
): Buffer {
	return encodeHashOnlyUnsigned(msg, 'ff_activate_ack');
}

export function decodeFforActivateAckMessage(
	body: Buffer
): IFforActivateAckMessage {
	return decodeHashOnly(body, 'ff_activate_ack');
}

export function encodeFforCloseUnsigned(
	msg: Omit<IFforCloseMessage, 'signature'>
): Buffer {
	return encodeHashOnlyUnsigned(msg, 'ff_close');
}

export function decodeFforCloseMessage(body: Buffer): IFforCloseMessage {
	return decodeHashOnly(body, 'ff_close');
}

// ---------------------------------------------------------------------------
// ff_abort (55049)
// ---------------------------------------------------------------------------

export function encodeFforAbortUnsigned(
	msg: Omit<IFforAbortMessage, 'signature'>
): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	assert32(msg.transcriptHash, 'transcript_hash');
	if (msg.data.length > 0xffff) throw new Error('ff_abort data too long');
	return Buffer.concat([
		msg.channelId,
		msg.epochId,
		msg.transcriptHash,
		u16(msg.reason),
		u16(msg.data.length),
		msg.data
	]);
}

export function decodeFforAbortMessage(body: Buffer): IFforAbortMessage {
	const r = new Reader(body, 'ff_abort');
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const transcriptHash = r.bytes(32);
	const reason = r.u16() as FforAbortReason;
	const len = r.u16();
	const data = r.bytes(len);
	const { signature } = splitSigned(body, r.offset, [], 'ff_abort');
	return { channelId, epochId, transcriptHash, reason, data, signature };
}

// ---------------------------------------------------------------------------
// ff_close_ack (55053)
// ---------------------------------------------------------------------------

/** ceil(K/8) bytes; bit k-1 of the bitmap is bit (k-1)%8 of byte (k-1)/8. */
export function bitmapLength(numSlots: number): number {
	return Math.ceil(numSlots / 8);
}

export function bitmapGet(bitmap: Buffer, k: number): boolean {
	const i = k - 1;
	const byte = bitmap[i >> 3];
	if (byte === undefined) return false;
	return (byte & (1 << (i & 7))) !== 0;
}

export function bitmapSet(bitmap: Buffer, k: number): void {
	const i = k - 1;
	bitmap[i >> 3] |= 1 << (i & 7);
}

export function encodeFforCloseAckUnsigned(
	msg: Omit<IFforCloseAckMessage, 'signature'>
): Buffer {
	assert32(msg.channelId, 'channel_id');
	assert32(msg.epochId, 'epoch_id');
	assert32(msg.activationHash, 'activation_hash');
	if (msg.settled.length !== bitmapLength(msg.numSlots)) {
		throw new Error('ff_close_ack: bitmap length must be ceil(K/8)');
	}
	const records: ITlvRecord[] = [];
	if (msg.preimages.length > 0) {
		let last = 0;
		const parts: Buffer[] = [];
		for (const p of msg.preimages) {
			if (p.k <= last)
				throw new Error('ff_close_ack: preimages not in k order');
			if (p.k > msg.numSlots) throw new Error('ff_close_ack: preimage k > K');
			assert32(p.preimage, 'preimage');
			last = p.k;
			parts.push(u16(p.k), p.preimage);
		}
		records.push({ type: 1n, value: Buffer.concat(parts) });
	}
	return Buffer.concat([
		msg.channelId,
		msg.epochId,
		msg.activationHash,
		u16(msg.numSlots),
		msg.settled,
		encodeTlvStream(records)
	]);
}

export function decodeFforCloseAckMessage(body: Buffer): IFforCloseAckMessage {
	const r = new Reader(body, 'ff_close_ack');
	const channelId = r.bytes(32);
	const epochId = r.bytes(32);
	const activationHash = r.bytes(32);
	const numSlots = r.u16();
	const settled = r.bytes(bitmapLength(numSlots));
	const { tlvs, signature } = splitSigned(body, r.offset, [], 'ff_close_ack');
	const raw = tlvList(tlvs, 1n);
	const preimages: { k: number; preimage: Buffer }[] = [];
	if (raw !== undefined) {
		for (const rec of splitFixed(raw, 34, 'ff_close_ack TLV 1')) {
			preimages.push({
				k: rec.readUInt16BE(0),
				preimage: Buffer.from(rec.subarray(2))
			});
		}
	}
	return {
		channelId,
		epochId,
		activationHash,
		numSlots,
		settled,
		preimages,
		signature
	};
}

// ---------------------------------------------------------------------------
// channel_reestablish TLV 55001 (section 11.1)
// ---------------------------------------------------------------------------

export const FF_REESTABLISH_TLV_LEN = 32 + 1 + 2 + 32;

export function encodeFforReestablishTlv(tlv: IFforReestablishTlv): ITlvRecord {
	assert32(tlv.epochId, 'epoch_id');
	assert32(tlv.activationHash, 'activation_hash');
	return {
		type: FF_REESTABLISH_TLV_TYPE,
		value: Buffer.concat([
			tlv.epochId,
			u8(tlv.state),
			u16(tlv.lastSeq),
			tlv.activationHash
		])
	};
}

export function decodeFforReestablishTlv(value: Buffer): IFforReestablishTlv {
	if (value.length !== FF_REESTABLISH_TLV_LEN) {
		throw new Error(
			`reestablish TLV 55001 must be ${FF_REESTABLISH_TLV_LEN} bytes, got ${value.length}`
		);
	}
	const state = value[32];
	if (state > FforState.ABORTED) {
		throw new Error(`reestablish TLV 55001: unknown state ${state}`);
	}
	return {
		epochId: Buffer.from(value.subarray(0, 32)),
		state: state as FforState,
		lastSeq: value.readUInt16BE(33),
		activationHash: Buffer.from(value.subarray(35, 67))
	};
}
