/**
 * Swap protocol messages (issue #737), as canonical Lightning TLV streams
 * riding the 44069 custom message under subtypes 48 to 55.
 *
 * Convention shared with direct funding: even types are required, odd types
 * optional, so a later revision can add an optional field without breaking a
 * decoder and cannot add a required one silently. A refusal ack carries only
 * its even fields; every term of an accepted ack is odd on the wire but the
 * decoder insists on all of them when `accepted` is set, so "accepted with a
 * term missing" is malformed rather than a swap with a hole in it.
 *
 * Amount semantics for a reverse swap: the client receives exactly
 * `onchainAmountSat` on chain and pays `invoiceAmountMsat`, which is
 * (onchainAmountSat + totalFeeSat) * 1000; `minerFeeSat` is the part of the
 * fee that pays for the provider's funding transaction and is echoed so the
 * client can see the breakdown. A client caps what it will pay with
 * `maxTotalFeeSat` on create, so a provider that reprices between quote and
 * create fails closed with FEE_CEILING.
 *
 * Amount semantics for a submarine swap (issue #743): the client locks
 * exactly `onchainAmountSat` in the contract and is paid its own invoice for
 * `invoiceAmountMsat`, which is (onchainAmountSat - totalFeeSat) * 1000. The
 * client mints that invoice BEFORE the create, so the provider derives the
 * fee from the invoice amount and accepts it when it covers the provider's
 * floor and stays under the client's `maxTotalFeeSat`; the ack echoes what
 * was accepted. `minerFeeSat` is the part that pays for the provider's claim
 * transaction. A quote (48/49) with direction 2 uses the same fields; there
 * `fundingConfirmations` is the depth the client's funding must reach before
 * the provider pays and `invoiceExpirySeconds` the minimum validity the
 * provider requires of the client's invoice at create time.
 */

import { decodeTlvStream, encodeTlvStream, ITlvRecord } from '../message/tlv';
import { isValidPublicKey } from '../crypto/ecdh';
import { SWAP_ID_BYTES } from './keys';

export const SWAP_MAX_MESSAGE_BYTES = 4096;
/** SWAP_STATUS may carry the raw funding transaction. */
export const SWAP_MAX_STATUS_BYTES = 16384;
export const SWAP_MAX_FUNDING_TX_BYTES = 8192;
export const SWAP_MAX_INVOICE_BYTES = 2048;
export const SWAP_MAX_REASON_BYTES = 200;
export const SWAP_MAX_ADDRESS_BYTES = 90;
export const SWAP_REQUEST_ID_BYTES = 8;
const P2WSH_SCRIPT_BYTES = 34;
const PUBKEY_BYTES = 33;
const HASH_BYTES = 32;

export class SwapMessageError extends Error {
	readonly code = 'MALFORMED';
	constructor(message: string) {
		super(message);
		this.name = 'SwapMessageError';
	}
}

function malformed(what: string): SwapMessageError {
	return new SwapMessageError(what);
}

export enum SwapWireDirection {
	REVERSE = 1,
	/** On-chain to Lightning: the client funds, the provider pays (issue #743). */
	SUBMARINE = 2
}

export enum SwapRefusalReason {
	NONE = 0,
	DISABLED = 1,
	UNSUPPORTED_DIRECTION = 2,
	AMOUNT_BELOW_MIN = 3,
	AMOUNT_ABOVE_MAX = 4,
	EXPOSURE_EXCEEDED = 5,
	FEE_CEILING = 6,
	REFUND_DELTA_OUT_OF_POLICY = 7,
	INVALID_KEY = 8,
	DUPLICATE_HASH = 9,
	RATE_LIMITED = 10,
	INSUFFICIENT_FUNDS = 11,
	CHAIN_UNAVAILABLE = 12,
	MALFORMED = 13,
	INTERNAL = 14,
	/** Submarine: the invoice does not match the hash, amount or network. */
	INVOICE_MISMATCH = 15,
	/** Submarine: the invoice's final CLTV cannot fit under the refund height. */
	CLTV_UNFITTABLE = 16,
	/** Submarine: the invoice is payable only by this node itself. */
	SELF_PAYMENT = 17,
	/** Submarine: no channel can carry the payment right now. */
	NO_OUTBOUND_LIQUIDITY = 18
}

/** The provider's view of a swap, as reported to its client. */
export enum SwapWireState {
	UNKNOWN = 0,
	CREATED = 1,
	HELD = 2,
	FUNDING = 3,
	FUNDED = 4,
	CLAIMED = 5,
	SETTLED = 6,
	REFUND_PENDING = 7,
	REFUNDED = 8,
	FAILED = 9,
	CANCELLED = 10,
	/**
	 * Reverse: the Lightning side was cancelled under the provider; funds are
	 * on chain. Submarine: a payment is out while the contract is not
	 * claimable.
	 */
	EXPOSED = 11,
	// Submarine states (issue #743), appended so older decoders reject them
	// as out of range rather than misread them.
	FUNDING_SEEN = 12,
	FUNDING_LOST = 13,
	PAYING = 14,
	PAYMENT_UNRESOLVED = 15,
	PREIMAGE_KNOWN = 16,
	CLAIM_BROADCAST = 17,
	CLAIM_CONFIRMED = 18,
	PAYMENT_FAILED = 19
}

export enum SwapWireResolutionKind {
	NONE = 0,
	CLAIM = 1,
	REFUND = 2,
	UNKNOWN = 3
}

// ─────────────── Message bodies ───────────────

export interface ISwapQuoteRequest {
	requestId: Buffer;
	direction: SwapWireDirection;
	/** 0 asks for limits only. */
	amountSat: bigint;
	preferredRefundDelta?: number;
}

export interface ISwapQuote {
	requestId: Buffer;
	direction: SwapWireDirection;
	accepted: boolean;
	reason: SwapRefusalReason;
	flatFeeSat: bigint;
	feePpm: number;
	minSwapSat: bigint;
	maxSwapSat: bigint;
	/** The refund delta the provider would use for a create right now. */
	refundDeltaBlocks: number;
	fundingConfirmations: number;
	invoiceExpirySeconds: number;
	/** The provider's height; informational. */
	currentHeight: number;
	/** 0 when amountSat was 0. */
	totalFeeSat: bigint;
	minerFeeSat: bigint;
	invoiceAmountMsat: bigint;
	reasonText?: string;
	minRefundDelta?: number;
	maxRefundDelta?: number;
}

export interface ISwapCreate {
	requestId: Buffer;
	direction: SwapWireDirection;
	paymentHash: Buffer;
	claimPubkey: Buffer;
	onchainAmountSat: bigint;
	maxTotalFeeSat: bigint;
	preferredRefundDelta?: number;
}

export interface ISwapTerms {
	swapId: Buffer;
	bolt11: string;
	refundPubkey: Buffer;
	refundHeight: number;
	outputScript: Buffer;
	address: string;
	invoiceAmountMsat: bigint;
	onchainAmountSat: bigint;
	totalFeeSat: bigint;
	minerFeeSat: bigint;
	fundingConfirmations: number;
	/** Unix seconds. */
	invoiceExpiresAt: number;
	currentHeight: number;
}

export interface ISwapCreateAck {
	requestId: Buffer;
	accepted: boolean;
	paymentHash: Buffer;
	reason: SwapRefusalReason;
	reasonText?: string;
	/** Present exactly when accepted. */
	terms?: ISwapTerms;
}

/** SWAP_SUBMARINE_CREATE (54): the client asks to lock coins for an invoice. */
export interface ISwapSubmarineCreate {
	requestId: Buffer;
	direction: SwapWireDirection;
	paymentHash: Buffer;
	/** The client's key for the contract's timeout branch. */
	refundPubkey: Buffer;
	/** The client's own invoice for onchainAmountSat minus the fee. */
	bolt11: string;
	onchainAmountSat: bigint;
	maxTotalFeeSat: bigint;
	preferredRefundDelta?: number;
}

export interface ISwapSubmarineTerms {
	swapId: Buffer;
	/** The provider's key for the contract's preimage branch. */
	claimPubkey: Buffer;
	refundHeight: number;
	outputScript: Buffer;
	address: string;
	invoiceAmountMsat: bigint;
	onchainAmountSat: bigint;
	totalFeeSat: bigint;
	minerFeeSat: bigint;
	/** Depth the funding must reach before the provider pays. */
	fundingConfirmations: number;
	/** Unix seconds; the provider stops watching for funding after this. */
	expiresAt: number;
	currentHeight: number;
	/**
	 * Informational: the absolute height no outgoing HTLC of the provider's
	 * payment may expire after. A client can compare it with how long its own
	 * node would hold an incoming HTLC.
	 */
	paymentCeilingHeight?: number;
}

export interface ISwapSubmarineCreateAck {
	requestId: Buffer;
	accepted: boolean;
	paymentHash: Buffer;
	reason: SwapRefusalReason;
	reasonText?: string;
	/** Present exactly when accepted. */
	terms?: ISwapSubmarineTerms;
}

export interface ISwapStatusRequest {
	requestId: Buffer;
	swapId: Buffer;
}

export interface ISwapStatus {
	requestId: Buffer;
	swapId: Buffer;
	/** False for an unknown swap, or one that belongs to another peer. */
	found: boolean;
	state: SwapWireState;
	currentHeight: number;
	refundHeight?: number;
	fundingTxid?: Buffer;
	fundingVout?: number;
	/** 0 while in the mempool. */
	fundingHeight?: number;
	fundingConfirmations?: number;
	/** Raw funding transaction; bound to fundingTxid, so trust-free. */
	fundingTx?: Buffer;
	resolutionTxid?: Buffer;
	resolutionKind?: SwapWireResolutionKind;
	resolutionHeight?: number;
	resolutionConfirmations?: number;
}

// ─────────────── TLV plumbing ───────────────

function u8Buf(n: number, what: string): Buffer {
	if (!Number.isInteger(n) || n < 0 || n > 0xff) {
		throw malformed(`${what} must be a u8, got ${n}`);
	}
	return Buffer.from([n]);
}

function u16Buf(n: number, what: string): Buffer {
	if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
		throw malformed(`${what} must be a u16, got ${n}`);
	}
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n, 0);
	return b;
}

function u32Buf(n: number, what: string): Buffer {
	if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
		throw malformed(`${what} must be a u32, got ${n}`);
	}
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n, 0);
	return b;
}

function u64Buf(n: bigint, what: string): Buffer {
	if (typeof n !== 'bigint' || n < 0n || n > 0xffffffffffffffffn) {
		throw malformed(`${what} must be a u64, got ${n}`);
	}
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(n, 0);
	return b;
}

function fixed(value: Buffer, length: number, what: string): Buffer {
	if (!Buffer.isBuffer(value) || value.length !== length) {
		throw malformed(`${what} must be ${length} bytes`);
	}
	return value;
}

function text(value: string, max: number, what: string): Buffer {
	if (typeof value !== 'string') throw malformed(`${what} must be a string`);
	const b = Buffer.from(value, 'utf8');
	if (b.length > max)
		throw malformed(`${what} is ${b.length} bytes, max ${max}`);
	return b;
}

function pubkey(value: Buffer, what: string): Buffer {
	fixed(value, PUBKEY_BYTES, what);
	if (!isValidPublicKey(value))
		throw malformed(`${what} is not a valid public key`);
	return value;
}

function p2wshScript(value: Buffer, what: string): Buffer {
	fixed(value, P2WSH_SCRIPT_BYTES, what);
	if (value[0] !== 0x00 || value[1] !== 0x20) {
		throw malformed(`${what} is not a P2WSH output script`);
	}
	return value;
}

type Fields = Map<bigint, Buffer>;

function decodeFields(
	data: Buffer,
	known: bigint[],
	what: string,
	max = SWAP_MAX_MESSAGE_BYTES
): Fields {
	if (!Buffer.isBuffer(data)) throw malformed(`${what} must be a buffer`);
	if (data.length > max) {
		throw malformed(`${what} is ${data.length} bytes, max ${max}`);
	}
	let records: ITlvRecord[];
	try {
		records = decodeTlvStream(data, 0, new Set(known)).records;
	} catch (e) {
		throw malformed(`${what}: ${(e as Error).message}`);
	}
	const fields: Fields = new Map();
	for (const r of records) fields.set(r.type, r.value);
	return fields;
}

function need(fields: Fields, type: bigint, what: string): Buffer {
	const value = fields.get(type);
	if (value === undefined) throw malformed(`${what} is missing`);
	return value;
}

function needFixed(
	fields: Fields,
	type: bigint,
	length: number,
	what: string
): Buffer {
	return Buffer.from(fixed(need(fields, type, what), length, what));
}

function needU8(fields: Fields, type: bigint, what: string): number {
	return needFixed(fields, type, 1, what)[0];
}

function needU16(fields: Fields, type: bigint, what: string): number {
	return needFixed(fields, type, 2, what).readUInt16BE(0);
}

function needU32(fields: Fields, type: bigint, what: string): number {
	return needFixed(fields, type, 4, what).readUInt32BE(0);
}

function needU64(fields: Fields, type: bigint, what: string): bigint {
	return needFixed(fields, type, 8, what).readBigUInt64BE(0);
}

function optU32(
	fields: Fields,
	type: bigint,
	what: string
): number | undefined {
	const v = fields.get(type);
	return v === undefined ? undefined : fixed(v, 4, what).readUInt32BE(0);
}

function optText(
	fields: Fields,
	type: bigint,
	max: number,
	what: string
): string | undefined {
	const v = fields.get(type);
	if (v === undefined) return undefined;
	if (v.length > max)
		throw malformed(`${what} is ${v.length} bytes, max ${max}`);
	return v.toString('utf8');
}

function direction(n: number, what: string): SwapWireDirection {
	if (n !== SwapWireDirection.REVERSE && n !== SwapWireDirection.SUBMARINE) {
		throw malformed(`${what} ${n} is not a swap direction`);
	}
	return n;
}

function reasonCode(n: number): SwapRefusalReason {
	if (
		!Number.isInteger(n) ||
		n < 0 ||
		n > SwapRefusalReason.NO_OUTBOUND_LIQUIDITY
	) {
		throw malformed(`refusal reason ${n} is out of range`);
	}
	return n;
}

function flag(n: number, what: string): boolean {
	if (n !== 0 && n !== 1) throw malformed(`${what} must be 0 or 1`);
	return n === 1;
}

function record(type: bigint, value: Buffer): ITlvRecord {
	return { type, value };
}

// ─────────────── SWAP_QUOTE_REQUEST (48) ───────────────

const QUOTE_REQUEST_TYPES = {
	requestId: 0n,
	direction: 2n,
	amountSat: 4n,
	preferredRefundDelta: 5n
};

export function encodeSwapQuoteRequest(q: ISwapQuoteRequest): Buffer {
	const records: ITlvRecord[] = [
		record(
			QUOTE_REQUEST_TYPES.requestId,
			fixed(q.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')
		),
		record(
			QUOTE_REQUEST_TYPES.direction,
			u8Buf(direction(q.direction, 'direction'), 'direction')
		),
		record(QUOTE_REQUEST_TYPES.amountSat, u64Buf(q.amountSat, 'amountSat'))
	];
	if (q.preferredRefundDelta !== undefined) {
		records.push(
			record(
				QUOTE_REQUEST_TYPES.preferredRefundDelta,
				u32Buf(q.preferredRefundDelta, 'preferredRefundDelta')
			)
		);
	}
	return encodeTlvStream(records);
}

export function decodeSwapQuoteRequest(data: Buffer): ISwapQuoteRequest {
	const f = decodeFields(
		data,
		Object.values(QUOTE_REQUEST_TYPES),
		'swap_quote_request'
	);
	return {
		requestId: needFixed(
			f,
			QUOTE_REQUEST_TYPES.requestId,
			SWAP_REQUEST_ID_BYTES,
			'requestId'
		),
		direction: direction(
			needU8(f, QUOTE_REQUEST_TYPES.direction, 'direction'),
			'direction'
		),
		amountSat: needU64(f, QUOTE_REQUEST_TYPES.amountSat, 'amountSat'),
		preferredRefundDelta: optU32(
			f,
			QUOTE_REQUEST_TYPES.preferredRefundDelta,
			'preferredRefundDelta'
		)
	};
}

// ─────────────── SWAP_QUOTE (49) ───────────────

const QUOTE_TYPES = {
	requestId: 0n,
	direction: 2n,
	accepted: 4n,
	reason: 6n,
	flatFeeSat: 8n,
	feePpm: 10n,
	minSwapSat: 12n,
	maxSwapSat: 14n,
	refundDeltaBlocks: 16n,
	fundingConfirmations: 18n,
	invoiceExpirySeconds: 20n,
	currentHeight: 22n,
	totalFeeSat: 24n,
	minerFeeSat: 26n,
	invoiceAmountMsat: 28n,
	reasonText: 29n,
	minRefundDelta: 31n,
	maxRefundDelta: 33n
};

export function encodeSwapQuote(q: ISwapQuote): Buffer {
	const records: ITlvRecord[] = [
		record(
			QUOTE_TYPES.requestId,
			fixed(q.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')
		),
		record(
			QUOTE_TYPES.direction,
			u8Buf(direction(q.direction, 'direction'), 'direction')
		),
		record(QUOTE_TYPES.accepted, u8Buf(q.accepted ? 1 : 0, 'accepted')),
		record(QUOTE_TYPES.reason, u8Buf(reasonCode(q.reason), 'reason')),
		record(QUOTE_TYPES.flatFeeSat, u64Buf(q.flatFeeSat, 'flatFeeSat')),
		record(QUOTE_TYPES.feePpm, u32Buf(q.feePpm, 'feePpm')),
		record(QUOTE_TYPES.minSwapSat, u64Buf(q.minSwapSat, 'minSwapSat')),
		record(QUOTE_TYPES.maxSwapSat, u64Buf(q.maxSwapSat, 'maxSwapSat')),
		record(
			QUOTE_TYPES.refundDeltaBlocks,
			u32Buf(q.refundDeltaBlocks, 'refundDeltaBlocks')
		),
		record(
			QUOTE_TYPES.fundingConfirmations,
			u16Buf(q.fundingConfirmations, 'fundingConfirmations')
		),
		record(
			QUOTE_TYPES.invoiceExpirySeconds,
			u32Buf(q.invoiceExpirySeconds, 'invoiceExpirySeconds')
		),
		record(QUOTE_TYPES.currentHeight, u32Buf(q.currentHeight, 'currentHeight')),
		record(QUOTE_TYPES.totalFeeSat, u64Buf(q.totalFeeSat, 'totalFeeSat')),
		record(QUOTE_TYPES.minerFeeSat, u64Buf(q.minerFeeSat, 'minerFeeSat')),
		record(
			QUOTE_TYPES.invoiceAmountMsat,
			u64Buf(q.invoiceAmountMsat, 'invoiceAmountMsat')
		)
	];
	if (q.reasonText !== undefined) {
		records.push(
			record(
				QUOTE_TYPES.reasonText,
				text(q.reasonText, SWAP_MAX_REASON_BYTES, 'reasonText')
			)
		);
	}
	if (q.minRefundDelta !== undefined) {
		records.push(
			record(
				QUOTE_TYPES.minRefundDelta,
				u32Buf(q.minRefundDelta, 'minRefundDelta')
			)
		);
	}
	if (q.maxRefundDelta !== undefined) {
		records.push(
			record(
				QUOTE_TYPES.maxRefundDelta,
				u32Buf(q.maxRefundDelta, 'maxRefundDelta')
			)
		);
	}
	return encodeTlvStream(records);
}

export function decodeSwapQuote(data: Buffer): ISwapQuote {
	const f = decodeFields(data, Object.values(QUOTE_TYPES), 'swap_quote');
	return {
		requestId: needFixed(
			f,
			QUOTE_TYPES.requestId,
			SWAP_REQUEST_ID_BYTES,
			'requestId'
		),
		direction: direction(
			needU8(f, QUOTE_TYPES.direction, 'direction'),
			'direction'
		),
		accepted: flag(needU8(f, QUOTE_TYPES.accepted, 'accepted'), 'accepted'),
		reason: reasonCode(needU8(f, QUOTE_TYPES.reason, 'reason')),
		flatFeeSat: needU64(f, QUOTE_TYPES.flatFeeSat, 'flatFeeSat'),
		feePpm: needU32(f, QUOTE_TYPES.feePpm, 'feePpm'),
		minSwapSat: needU64(f, QUOTE_TYPES.minSwapSat, 'minSwapSat'),
		maxSwapSat: needU64(f, QUOTE_TYPES.maxSwapSat, 'maxSwapSat'),
		refundDeltaBlocks: needU32(
			f,
			QUOTE_TYPES.refundDeltaBlocks,
			'refundDeltaBlocks'
		),
		fundingConfirmations: needU16(
			f,
			QUOTE_TYPES.fundingConfirmations,
			'fundingConfirmations'
		),
		invoiceExpirySeconds: needU32(
			f,
			QUOTE_TYPES.invoiceExpirySeconds,
			'invoiceExpirySeconds'
		),
		currentHeight: needU32(f, QUOTE_TYPES.currentHeight, 'currentHeight'),
		totalFeeSat: needU64(f, QUOTE_TYPES.totalFeeSat, 'totalFeeSat'),
		minerFeeSat: needU64(f, QUOTE_TYPES.minerFeeSat, 'minerFeeSat'),
		invoiceAmountMsat: needU64(
			f,
			QUOTE_TYPES.invoiceAmountMsat,
			'invoiceAmountMsat'
		),
		reasonText: optText(
			f,
			QUOTE_TYPES.reasonText,
			SWAP_MAX_REASON_BYTES,
			'reasonText'
		),
		minRefundDelta: optU32(f, QUOTE_TYPES.minRefundDelta, 'minRefundDelta'),
		maxRefundDelta: optU32(f, QUOTE_TYPES.maxRefundDelta, 'maxRefundDelta')
	};
}

// ─────────────── SWAP_CREATE (50) ───────────────

const CREATE_TYPES = {
	requestId: 0n,
	direction: 2n,
	paymentHash: 4n,
	claimPubkey: 6n,
	onchainAmountSat: 8n,
	maxTotalFeeSat: 10n,
	preferredRefundDelta: 11n
};

export function encodeSwapCreate(c: ISwapCreate): Buffer {
	const records: ITlvRecord[] = [
		record(
			CREATE_TYPES.requestId,
			fixed(c.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')
		),
		record(
			CREATE_TYPES.direction,
			u8Buf(direction(c.direction, 'direction'), 'direction')
		),
		record(
			CREATE_TYPES.paymentHash,
			fixed(c.paymentHash, HASH_BYTES, 'paymentHash')
		),
		record(CREATE_TYPES.claimPubkey, pubkey(c.claimPubkey, 'claimPubkey')),
		record(
			CREATE_TYPES.onchainAmountSat,
			u64Buf(c.onchainAmountSat, 'onchainAmountSat')
		),
		record(
			CREATE_TYPES.maxTotalFeeSat,
			u64Buf(c.maxTotalFeeSat, 'maxTotalFeeSat')
		)
	];
	if (c.preferredRefundDelta !== undefined) {
		records.push(
			record(
				CREATE_TYPES.preferredRefundDelta,
				u32Buf(c.preferredRefundDelta, 'preferredRefundDelta')
			)
		);
	}
	return encodeTlvStream(records);
}

export function decodeSwapCreate(data: Buffer): ISwapCreate {
	const f = decodeFields(data, Object.values(CREATE_TYPES), 'swap_create');
	const onchainAmountSat = needU64(
		f,
		CREATE_TYPES.onchainAmountSat,
		'onchainAmountSat'
	);
	if (onchainAmountSat === 0n)
		throw malformed('onchainAmountSat must be positive');
	return {
		requestId: needFixed(
			f,
			CREATE_TYPES.requestId,
			SWAP_REQUEST_ID_BYTES,
			'requestId'
		),
		direction: direction(
			needU8(f, CREATE_TYPES.direction, 'direction'),
			'direction'
		),
		paymentHash: needFixed(
			f,
			CREATE_TYPES.paymentHash,
			HASH_BYTES,
			'paymentHash'
		),
		claimPubkey: pubkey(
			needFixed(f, CREATE_TYPES.claimPubkey, PUBKEY_BYTES, 'claimPubkey'),
			'claimPubkey'
		),
		onchainAmountSat,
		maxTotalFeeSat: needU64(f, CREATE_TYPES.maxTotalFeeSat, 'maxTotalFeeSat'),
		preferredRefundDelta: optU32(
			f,
			CREATE_TYPES.preferredRefundDelta,
			'preferredRefundDelta'
		)
	};
}

// ─────────────── SWAP_CREATE_ACK (51) ───────────────

const CREATE_ACK_TYPES = {
	requestId: 0n,
	accepted: 2n,
	paymentHash: 4n,
	reason: 6n,
	reasonText: 7n,
	swapId: 9n,
	bolt11: 11n,
	refundPubkey: 13n,
	refundHeight: 15n,
	outputScript: 17n,
	address: 19n,
	invoiceAmountMsat: 21n,
	onchainAmountSat: 23n,
	totalFeeSat: 25n,
	minerFeeSat: 27n,
	fundingConfirmations: 29n,
	invoiceExpiresAt: 31n,
	currentHeight: 33n
};

export function encodeSwapCreateAck(a: ISwapCreateAck): Buffer {
	const records: ITlvRecord[] = [
		record(
			CREATE_ACK_TYPES.requestId,
			fixed(a.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')
		),
		record(CREATE_ACK_TYPES.accepted, u8Buf(a.accepted ? 1 : 0, 'accepted')),
		record(
			CREATE_ACK_TYPES.paymentHash,
			fixed(a.paymentHash, HASH_BYTES, 'paymentHash')
		),
		record(CREATE_ACK_TYPES.reason, u8Buf(reasonCode(a.reason), 'reason'))
	];
	if (a.reasonText !== undefined) {
		records.push(
			record(
				CREATE_ACK_TYPES.reasonText,
				text(a.reasonText, SWAP_MAX_REASON_BYTES, 'reasonText')
			)
		);
	}
	if (a.accepted) {
		const t = a.terms;
		if (!t) throw malformed('an accepted ack needs terms');
		records.push(
			record(CREATE_ACK_TYPES.swapId, fixed(t.swapId, SWAP_ID_BYTES, 'swapId')),
			record(
				CREATE_ACK_TYPES.bolt11,
				text(t.bolt11, SWAP_MAX_INVOICE_BYTES, 'bolt11')
			),
			record(
				CREATE_ACK_TYPES.refundPubkey,
				pubkey(t.refundPubkey, 'refundPubkey')
			),
			record(
				CREATE_ACK_TYPES.refundHeight,
				u32Buf(t.refundHeight, 'refundHeight')
			),
			record(
				CREATE_ACK_TYPES.outputScript,
				p2wshScript(t.outputScript, 'outputScript')
			),
			record(
				CREATE_ACK_TYPES.address,
				text(t.address, SWAP_MAX_ADDRESS_BYTES, 'address')
			),
			record(
				CREATE_ACK_TYPES.invoiceAmountMsat,
				u64Buf(t.invoiceAmountMsat, 'invoiceAmountMsat')
			),
			record(
				CREATE_ACK_TYPES.onchainAmountSat,
				u64Buf(t.onchainAmountSat, 'onchainAmountSat')
			),
			record(
				CREATE_ACK_TYPES.totalFeeSat,
				u64Buf(t.totalFeeSat, 'totalFeeSat')
			),
			record(
				CREATE_ACK_TYPES.minerFeeSat,
				u64Buf(t.minerFeeSat, 'minerFeeSat')
			),
			record(
				CREATE_ACK_TYPES.fundingConfirmations,
				u16Buf(t.fundingConfirmations, 'fundingConfirmations')
			),
			record(
				CREATE_ACK_TYPES.invoiceExpiresAt,
				u64Buf(BigInt(t.invoiceExpiresAt), 'invoiceExpiresAt')
			),
			record(
				CREATE_ACK_TYPES.currentHeight,
				u32Buf(t.currentHeight, 'currentHeight')
			)
		);
	} else if (a.terms) {
		throw malformed('a refusal must not carry terms');
	}
	return encodeTlvStream(records);
}

export function decodeSwapCreateAck(data: Buffer): ISwapCreateAck {
	const f = decodeFields(
		data,
		Object.values(CREATE_ACK_TYPES),
		'swap_create_ack'
	);
	const accepted = flag(
		needU8(f, CREATE_ACK_TYPES.accepted, 'accepted'),
		'accepted'
	);
	const ack: ISwapCreateAck = {
		requestId: needFixed(
			f,
			CREATE_ACK_TYPES.requestId,
			SWAP_REQUEST_ID_BYTES,
			'requestId'
		),
		accepted,
		paymentHash: needFixed(
			f,
			CREATE_ACK_TYPES.paymentHash,
			HASH_BYTES,
			'paymentHash'
		),
		reason: reasonCode(needU8(f, CREATE_ACK_TYPES.reason, 'reason')),
		reasonText: optText(
			f,
			CREATE_ACK_TYPES.reasonText,
			SWAP_MAX_REASON_BYTES,
			'reasonText'
		)
	};
	if (!accepted) return ack;
	const bolt11 = need(f, CREATE_ACK_TYPES.bolt11, 'bolt11');
	if (bolt11.length > SWAP_MAX_INVOICE_BYTES)
		throw malformed('bolt11 is too long');
	const address = need(f, CREATE_ACK_TYPES.address, 'address');
	if (address.length > SWAP_MAX_ADDRESS_BYTES)
		throw malformed('address is too long');
	const invoiceExpiresAt = needU64(
		f,
		CREATE_ACK_TYPES.invoiceExpiresAt,
		'invoiceExpiresAt'
	);
	if (invoiceExpiresAt > BigInt(Number.MAX_SAFE_INTEGER))
		throw malformed('invoiceExpiresAt is out of range');
	ack.terms = {
		swapId: needFixed(f, CREATE_ACK_TYPES.swapId, SWAP_ID_BYTES, 'swapId'),
		bolt11: bolt11.toString('utf8'),
		refundPubkey: pubkey(
			needFixed(f, CREATE_ACK_TYPES.refundPubkey, PUBKEY_BYTES, 'refundPubkey'),
			'refundPubkey'
		),
		refundHeight: needU32(f, CREATE_ACK_TYPES.refundHeight, 'refundHeight'),
		outputScript: p2wshScript(
			needFixed(
				f,
				CREATE_ACK_TYPES.outputScript,
				P2WSH_SCRIPT_BYTES,
				'outputScript'
			),
			'outputScript'
		),
		address: address.toString('utf8'),
		invoiceAmountMsat: needU64(
			f,
			CREATE_ACK_TYPES.invoiceAmountMsat,
			'invoiceAmountMsat'
		),
		onchainAmountSat: needU64(
			f,
			CREATE_ACK_TYPES.onchainAmountSat,
			'onchainAmountSat'
		),
		totalFeeSat: needU64(f, CREATE_ACK_TYPES.totalFeeSat, 'totalFeeSat'),
		minerFeeSat: needU64(f, CREATE_ACK_TYPES.minerFeeSat, 'minerFeeSat'),
		fundingConfirmations: needU16(
			f,
			CREATE_ACK_TYPES.fundingConfirmations,
			'fundingConfirmations'
		),
		invoiceExpiresAt: Number(invoiceExpiresAt),
		currentHeight: needU32(f, CREATE_ACK_TYPES.currentHeight, 'currentHeight')
	};
	return ack;
}

// ─────────────── SWAP_SUBMARINE_CREATE (54) ───────────────

const SUBMARINE_CREATE_TYPES = {
	requestId: 0n,
	direction: 2n,
	paymentHash: 4n,
	refundPubkey: 6n,
	bolt11: 8n,
	onchainAmountSat: 10n,
	maxTotalFeeSat: 12n,
	preferredRefundDelta: 13n
};

export function encodeSwapSubmarineCreate(c: ISwapSubmarineCreate): Buffer {
	const records: ITlvRecord[] = [
		record(
			SUBMARINE_CREATE_TYPES.requestId,
			fixed(c.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')
		),
		record(
			SUBMARINE_CREATE_TYPES.direction,
			u8Buf(direction(c.direction, 'direction'), 'direction')
		),
		record(
			SUBMARINE_CREATE_TYPES.paymentHash,
			fixed(c.paymentHash, HASH_BYTES, 'paymentHash')
		),
		record(
			SUBMARINE_CREATE_TYPES.refundPubkey,
			pubkey(c.refundPubkey, 'refundPubkey')
		),
		record(
			SUBMARINE_CREATE_TYPES.bolt11,
			text(c.bolt11, SWAP_MAX_INVOICE_BYTES, 'bolt11')
		),
		record(
			SUBMARINE_CREATE_TYPES.onchainAmountSat,
			u64Buf(c.onchainAmountSat, 'onchainAmountSat')
		),
		record(
			SUBMARINE_CREATE_TYPES.maxTotalFeeSat,
			u64Buf(c.maxTotalFeeSat, 'maxTotalFeeSat')
		)
	];
	if (c.preferredRefundDelta !== undefined) {
		records.push(
			record(
				SUBMARINE_CREATE_TYPES.preferredRefundDelta,
				u32Buf(c.preferredRefundDelta, 'preferredRefundDelta')
			)
		);
	}
	return encodeTlvStream(records);
}

export function decodeSwapSubmarineCreate(data: Buffer): ISwapSubmarineCreate {
	const f = decodeFields(
		data,
		Object.values(SUBMARINE_CREATE_TYPES),
		'swap_submarine_create'
	);
	const onchainAmountSat = needU64(
		f,
		SUBMARINE_CREATE_TYPES.onchainAmountSat,
		'onchainAmountSat'
	);
	if (onchainAmountSat === 0n)
		throw malformed('onchainAmountSat must be positive');
	const bolt11 = need(f, SUBMARINE_CREATE_TYPES.bolt11, 'bolt11');
	if (bolt11.length > SWAP_MAX_INVOICE_BYTES)
		throw malformed('bolt11 is too long');
	if (bolt11.length === 0) throw malformed('bolt11 is empty');
	return {
		requestId: needFixed(
			f,
			SUBMARINE_CREATE_TYPES.requestId,
			SWAP_REQUEST_ID_BYTES,
			'requestId'
		),
		direction: direction(
			needU8(f, SUBMARINE_CREATE_TYPES.direction, 'direction'),
			'direction'
		),
		paymentHash: needFixed(
			f,
			SUBMARINE_CREATE_TYPES.paymentHash,
			HASH_BYTES,
			'paymentHash'
		),
		refundPubkey: pubkey(
			needFixed(
				f,
				SUBMARINE_CREATE_TYPES.refundPubkey,
				PUBKEY_BYTES,
				'refundPubkey'
			),
			'refundPubkey'
		),
		bolt11: bolt11.toString('utf8'),
		onchainAmountSat,
		maxTotalFeeSat: needU64(
			f,
			SUBMARINE_CREATE_TYPES.maxTotalFeeSat,
			'maxTotalFeeSat'
		),
		preferredRefundDelta: optU32(
			f,
			SUBMARINE_CREATE_TYPES.preferredRefundDelta,
			'preferredRefundDelta'
		)
	};
}

// ─────────────── SWAP_SUBMARINE_CREATE_ACK (55) ───────────────

const SUBMARINE_CREATE_ACK_TYPES = {
	requestId: 0n,
	accepted: 2n,
	paymentHash: 4n,
	reason: 6n,
	reasonText: 7n,
	swapId: 9n,
	claimPubkey: 11n,
	refundHeight: 13n,
	outputScript: 15n,
	address: 17n,
	invoiceAmountMsat: 19n,
	onchainAmountSat: 21n,
	totalFeeSat: 23n,
	minerFeeSat: 25n,
	fundingConfirmations: 27n,
	expiresAt: 29n,
	currentHeight: 31n,
	paymentCeilingHeight: 33n
};

export function encodeSwapSubmarineCreateAck(
	a: ISwapSubmarineCreateAck
): Buffer {
	const T = SUBMARINE_CREATE_ACK_TYPES;
	const records: ITlvRecord[] = [
		record(T.requestId, fixed(a.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')),
		record(T.accepted, u8Buf(a.accepted ? 1 : 0, 'accepted')),
		record(T.paymentHash, fixed(a.paymentHash, HASH_BYTES, 'paymentHash')),
		record(T.reason, u8Buf(reasonCode(a.reason), 'reason'))
	];
	if (a.reasonText !== undefined) {
		records.push(
			record(
				T.reasonText,
				text(a.reasonText, SWAP_MAX_REASON_BYTES, 'reasonText')
			)
		);
	}
	if (a.accepted) {
		const t = a.terms;
		if (!t) throw malformed('an accepted ack needs terms');
		records.push(
			record(T.swapId, fixed(t.swapId, SWAP_ID_BYTES, 'swapId')),
			record(T.claimPubkey, pubkey(t.claimPubkey, 'claimPubkey')),
			record(T.refundHeight, u32Buf(t.refundHeight, 'refundHeight')),
			record(T.outputScript, p2wshScript(t.outputScript, 'outputScript')),
			record(T.address, text(t.address, SWAP_MAX_ADDRESS_BYTES, 'address')),
			record(
				T.invoiceAmountMsat,
				u64Buf(t.invoiceAmountMsat, 'invoiceAmountMsat')
			),
			record(
				T.onchainAmountSat,
				u64Buf(t.onchainAmountSat, 'onchainAmountSat')
			),
			record(T.totalFeeSat, u64Buf(t.totalFeeSat, 'totalFeeSat')),
			record(T.minerFeeSat, u64Buf(t.minerFeeSat, 'minerFeeSat')),
			record(
				T.fundingConfirmations,
				u16Buf(t.fundingConfirmations, 'fundingConfirmations')
			),
			record(T.expiresAt, u64Buf(BigInt(t.expiresAt), 'expiresAt')),
			record(T.currentHeight, u32Buf(t.currentHeight, 'currentHeight'))
		);
		if (t.paymentCeilingHeight !== undefined) {
			records.push(
				record(
					T.paymentCeilingHeight,
					u32Buf(t.paymentCeilingHeight, 'paymentCeilingHeight')
				)
			);
		}
	} else if (a.terms) {
		throw malformed('a refusal must not carry terms');
	}
	return encodeTlvStream(records);
}

export function decodeSwapSubmarineCreateAck(
	data: Buffer
): ISwapSubmarineCreateAck {
	const T = SUBMARINE_CREATE_ACK_TYPES;
	const f = decodeFields(data, Object.values(T), 'swap_submarine_create_ack');
	const accepted = flag(needU8(f, T.accepted, 'accepted'), 'accepted');
	const ack: ISwapSubmarineCreateAck = {
		requestId: needFixed(f, T.requestId, SWAP_REQUEST_ID_BYTES, 'requestId'),
		accepted,
		paymentHash: needFixed(f, T.paymentHash, HASH_BYTES, 'paymentHash'),
		reason: reasonCode(needU8(f, T.reason, 'reason')),
		reasonText: optText(f, T.reasonText, SWAP_MAX_REASON_BYTES, 'reasonText')
	};
	if (!accepted) return ack;
	const address = need(f, T.address, 'address');
	if (address.length > SWAP_MAX_ADDRESS_BYTES)
		throw malformed('address is too long');
	const expiresAt = needU64(f, T.expiresAt, 'expiresAt');
	if (expiresAt > BigInt(Number.MAX_SAFE_INTEGER))
		throw malformed('expiresAt is out of range');
	ack.terms = {
		swapId: needFixed(f, T.swapId, SWAP_ID_BYTES, 'swapId'),
		claimPubkey: pubkey(
			needFixed(f, T.claimPubkey, PUBKEY_BYTES, 'claimPubkey'),
			'claimPubkey'
		),
		refundHeight: needU32(f, T.refundHeight, 'refundHeight'),
		outputScript: p2wshScript(
			needFixed(f, T.outputScript, P2WSH_SCRIPT_BYTES, 'outputScript'),
			'outputScript'
		),
		address: address.toString('utf8'),
		invoiceAmountMsat: needU64(f, T.invoiceAmountMsat, 'invoiceAmountMsat'),
		onchainAmountSat: needU64(f, T.onchainAmountSat, 'onchainAmountSat'),
		totalFeeSat: needU64(f, T.totalFeeSat, 'totalFeeSat'),
		minerFeeSat: needU64(f, T.minerFeeSat, 'minerFeeSat'),
		fundingConfirmations: needU16(
			f,
			T.fundingConfirmations,
			'fundingConfirmations'
		),
		expiresAt: Number(expiresAt),
		currentHeight: needU32(f, T.currentHeight, 'currentHeight'),
		paymentCeilingHeight: optU32(
			f,
			T.paymentCeilingHeight,
			'paymentCeilingHeight'
		)
	};
	return ack;
}

// ─────────────── SWAP_STATUS_REQUEST (52) ───────────────

const STATUS_REQUEST_TYPES = { requestId: 0n, swapId: 2n };

export function encodeSwapStatusRequest(s: ISwapStatusRequest): Buffer {
	return encodeTlvStream([
		record(
			STATUS_REQUEST_TYPES.requestId,
			fixed(s.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')
		),
		record(
			STATUS_REQUEST_TYPES.swapId,
			fixed(s.swapId, SWAP_ID_BYTES, 'swapId')
		)
	]);
}

export function decodeSwapStatusRequest(data: Buffer): ISwapStatusRequest {
	const f = decodeFields(
		data,
		Object.values(STATUS_REQUEST_TYPES),
		'swap_status_request'
	);
	return {
		requestId: needFixed(
			f,
			STATUS_REQUEST_TYPES.requestId,
			SWAP_REQUEST_ID_BYTES,
			'requestId'
		),
		swapId: needFixed(f, STATUS_REQUEST_TYPES.swapId, SWAP_ID_BYTES, 'swapId')
	};
}

// ─────────────── SWAP_STATUS (53) ───────────────

const STATUS_TYPES = {
	requestId: 0n,
	swapId: 2n,
	found: 4n,
	state: 6n,
	currentHeight: 8n,
	refundHeight: 9n,
	fundingTxid: 11n,
	fundingVout: 13n,
	fundingHeight: 15n,
	fundingConfirmations: 17n,
	resolutionTxid: 19n,
	resolutionKind: 21n,
	resolutionHeight: 23n,
	resolutionConfirmations: 25n,
	fundingTx: 27n
};

function wireState(n: number): SwapWireState {
	if (!Number.isInteger(n) || n < 0 || n > SwapWireState.PAYMENT_FAILED) {
		throw malformed(`swap state ${n} is out of range`);
	}
	return n;
}

function wireResolutionKind(n: number): SwapWireResolutionKind {
	if (!Number.isInteger(n) || n < 0 || n > SwapWireResolutionKind.UNKNOWN) {
		throw malformed(`resolution kind ${n} is out of range`);
	}
	return n;
}

export function encodeSwapStatus(s: ISwapStatus): Buffer {
	const records: ITlvRecord[] = [
		record(
			STATUS_TYPES.requestId,
			fixed(s.requestId, SWAP_REQUEST_ID_BYTES, 'requestId')
		),
		record(STATUS_TYPES.swapId, fixed(s.swapId, SWAP_ID_BYTES, 'swapId')),
		record(STATUS_TYPES.found, u8Buf(s.found ? 1 : 0, 'found')),
		record(STATUS_TYPES.state, u8Buf(wireState(s.state), 'state')),
		record(STATUS_TYPES.currentHeight, u32Buf(s.currentHeight, 'currentHeight'))
	];
	const opt = (type: bigint, value: Buffer | undefined): void => {
		if (value !== undefined) records.push(record(type, value));
	};
	opt(
		STATUS_TYPES.refundHeight,
		s.refundHeight === undefined
			? undefined
			: u32Buf(s.refundHeight, 'refundHeight')
	);
	opt(
		STATUS_TYPES.fundingTxid,
		s.fundingTxid === undefined
			? undefined
			: fixed(s.fundingTxid, HASH_BYTES, 'fundingTxid')
	);
	opt(
		STATUS_TYPES.fundingVout,
		s.fundingVout === undefined
			? undefined
			: u32Buf(s.fundingVout, 'fundingVout')
	);
	opt(
		STATUS_TYPES.fundingHeight,
		s.fundingHeight === undefined
			? undefined
			: u32Buf(s.fundingHeight, 'fundingHeight')
	);
	opt(
		STATUS_TYPES.fundingConfirmations,
		s.fundingConfirmations === undefined
			? undefined
			: u32Buf(s.fundingConfirmations, 'fundingConfirmations')
	);
	opt(
		STATUS_TYPES.resolutionTxid,
		s.resolutionTxid === undefined
			? undefined
			: fixed(s.resolutionTxid, HASH_BYTES, 'resolutionTxid')
	);
	opt(
		STATUS_TYPES.resolutionKind,
		s.resolutionKind === undefined
			? undefined
			: u8Buf(wireResolutionKind(s.resolutionKind), 'resolutionKind')
	);
	opt(
		STATUS_TYPES.resolutionHeight,
		s.resolutionHeight === undefined
			? undefined
			: u32Buf(s.resolutionHeight, 'resolutionHeight')
	);
	opt(
		STATUS_TYPES.resolutionConfirmations,
		s.resolutionConfirmations === undefined
			? undefined
			: u32Buf(s.resolutionConfirmations, 'resolutionConfirmations')
	);
	if (s.fundingTx !== undefined) {
		if (
			!Buffer.isBuffer(s.fundingTx) ||
			s.fundingTx.length > SWAP_MAX_FUNDING_TX_BYTES
		) {
			throw malformed('fundingTx is too large');
		}
		records.push(record(STATUS_TYPES.fundingTx, s.fundingTx));
	}
	return encodeTlvStream(records);
}

export function decodeSwapStatus(data: Buffer): ISwapStatus {
	const f = decodeFields(
		data,
		Object.values(STATUS_TYPES),
		'swap_status',
		SWAP_MAX_STATUS_BYTES
	);
	const fundingTxid = f.get(STATUS_TYPES.fundingTxid);
	const resolutionTxid = f.get(STATUS_TYPES.resolutionTxid);
	const resolutionKind = f.get(STATUS_TYPES.resolutionKind);
	const fundingTx = f.get(STATUS_TYPES.fundingTx);
	if (fundingTx !== undefined && fundingTx.length > SWAP_MAX_FUNDING_TX_BYTES) {
		throw malformed('fundingTx is too large');
	}
	return {
		requestId: needFixed(
			f,
			STATUS_TYPES.requestId,
			SWAP_REQUEST_ID_BYTES,
			'requestId'
		),
		swapId: needFixed(f, STATUS_TYPES.swapId, SWAP_ID_BYTES, 'swapId'),
		found: flag(needU8(f, STATUS_TYPES.found, 'found'), 'found'),
		state: wireState(needU8(f, STATUS_TYPES.state, 'state')),
		currentHeight: needU32(f, STATUS_TYPES.currentHeight, 'currentHeight'),
		refundHeight: optU32(f, STATUS_TYPES.refundHeight, 'refundHeight'),
		fundingTxid:
			fundingTxid === undefined
				? undefined
				: Buffer.from(fixed(fundingTxid, HASH_BYTES, 'fundingTxid')),
		fundingVout: optU32(f, STATUS_TYPES.fundingVout, 'fundingVout'),
		fundingHeight: optU32(f, STATUS_TYPES.fundingHeight, 'fundingHeight'),
		fundingConfirmations: optU32(
			f,
			STATUS_TYPES.fundingConfirmations,
			'fundingConfirmations'
		),
		fundingTx: fundingTx === undefined ? undefined : Buffer.from(fundingTx),
		resolutionTxid:
			resolutionTxid === undefined
				? undefined
				: Buffer.from(fixed(resolutionTxid, HASH_BYTES, 'resolutionTxid')),
		resolutionKind:
			resolutionKind === undefined
				? undefined
				: wireResolutionKind(fixed(resolutionKind, 1, 'resolutionKind')[0]),
		resolutionHeight: optU32(
			f,
			STATUS_TYPES.resolutionHeight,
			'resolutionHeight'
		),
		resolutionConfirmations: optU32(
			f,
			STATUS_TYPES.resolutionConfirmations,
			'resolutionConfirmations'
		)
	};
}
