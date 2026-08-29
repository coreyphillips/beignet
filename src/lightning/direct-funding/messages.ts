/**
 * The six direct-funding protocol messages (rev 2 "The funding protocol"),
 * as canonical Lightning TLV streams.
 *
 * Rev 2 lists the fields in tables and says a final specification SHOULD
 * express them as TLV. The fork sent JSON.stringify payloads and read them
 * back with ad hoc field access, which is how peer-supplied strings reached
 * transaction outputs and map keys unchecked. TLV here means the unknown-odd
 * tolerance and unknown-even refusal come for free, and every integer field
 * arrives at a fixed width or not at all.
 *
 * Each body rides one odd custom message type (44069, #546) under the subtype
 * reserved for it in `BeignetCustomSubtype`, sealed by `frames.ts`. Subtype 20
 * (`funding_abort`) stays reserved and unimplemented.
 *
 * TLV convention here: even types are the required fields, odd types the
 * optional ones, so a later revision can add an optional field without
 * breaking a decoder and cannot add a required one silently.
 */

import crypto from 'crypto';
import { decodeTlvStream, encodeTlvStream, ITlvRecord } from '../message/tlv';
import {
	ByteReader,
	DF_MAX_MESSAGE_BYTES,
	DF_MAX_PREVOUTS,
	DF_MAX_RAW_TX_BYTES,
	DF_MAX_REASON_BYTES,
	DF_MAX_SCRIPT_BYTES,
	DF_MAX_WITNESS_ITEMS,
	DF_MAX_WITNESS_ITEM_BYTES,
	DF_NODE_ID_BYTES,
	DF_OFFER_ID_BYTES,
	DF_PREIMAGE_BYTES,
	DF_RECEIPT_HASH_BYTES,
	DF_SIGNATURE_BYTES,
	malformed
} from './types';

const TXID_BYTES = 32;
const COMPACT_SIG_BYTES = 64;

// ─────────────── Message bodies ───────────────

export interface IDfOwnershipProof {
	/**
	 * 33 bytes compressed for a P2WPKH input (ECDSA), 32 bytes x-only for a
	 * P2TR key-path input (Schnorr). The width is how the receiver knows
	 * which scheme to verify under.
	 */
	pubkey: Buffer;
	/** 64 bytes either way. */
	signature: Buffer;
}

export interface IDfOffer {
	offerId: Buffer;
	amountSat: bigint;
	/**
	 * Display byte order, the order every wallet API in this repo prints and
	 * the order the offer id is derived over. Converted once, at the
	 * transaction boundary.
	 */
	txid: Buffer;
	vout: number;
	valueSat: bigint;
	/** The exact input sequence the payer will sign with. */
	sequence: number;
	changeScript: Buffer;
	/** The payer's ceiling on its own cost above the amount. */
	maxTotalFeeSat: bigint;
	receiptHash: Buffer;
	ownership: IDfOwnershipProof;
}

export interface IDfOfferAck {
	offerId: Buffer;
	accepted: boolean;
	reason?: string;
}

export interface IDfPrevout {
	valueSat: bigint;
	script: Buffer;
}

export interface IDfAttestation {
	fundingOutputIndex: number;
	localFundingPubkey: Buffer;
	remoteFundingPubkey: Buffer;
	/** Raw 65-byte compact recoverable signature by the receiver's node key. */
	signature: Buffer;
}

export interface IDfSignRequest {
	offerId: Buffer;
	rawTx: Buffer;
	/** Script and value for EVERY input, in transaction order (BIP 341). */
	prevouts: IDfPrevout[];
	attestation: IDfAttestation;
	/** Splice extension only: the input spending the old funding outpoint. */
	sharedInputIndex?: number;
}

export interface IDfWitness {
	offerId: Buffer;
	witness: Buffer[];
}

export interface IDfReceipt {
	offerId: Buffer;
	preimage: Buffer;
	fundingTxid: Buffer;
	/** The complete signed transaction, so the payer can rebroadcast alone. */
	rawTx?: Buffer;
}

/**
 * The blind relay envelope (subtype 22), the one message the relay reads.
 * A payer addresses `to`; the relay forwards it with `from` stamped from its
 * own authenticated connection. Exactly one of the two is present, which is
 * what makes "a frame already carrying `from` is never re-forwarded" a typed
 * distinction rather than a field check on an untyped object.
 */
export interface IDfRelayFrame {
	subtype: number;
	payload: Buffer;
	to?: Buffer;
	from?: Buffer;
}

// ─────────────── TLV plumbing ───────────────

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
	if (n < 0n || n > 0xffffffffffffffffn) {
		throw malformed(`${what} must be a u64, got ${n}`);
	}
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(n, 0);
	return b;
}

function fixed(value: Buffer, length: number, what: string): Buffer {
	if (value.length !== length) {
		throw malformed(`${what} must be ${length} bytes, got ${value.length}`);
	}
	return value;
}

function bounded(value: Buffer, max: number, what: string): Buffer {
	if (value.length > max) {
		throw malformed(`${what} is ${value.length} bytes, max ${max}`);
	}
	return value;
}

type Fields = Map<bigint, Buffer>;

function decodeFields(data: Buffer, known: bigint[], what: string): Fields {
	if (data.length > DF_MAX_MESSAGE_BYTES) {
		throw malformed(
			`${what} is ${data.length} bytes, max ${DF_MAX_MESSAGE_BYTES}`
		);
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

function needU16(fields: Fields, type: bigint, what: string): number {
	return needFixed(fields, type, 2, what).readUInt16BE(0);
}

function needU32(fields: Fields, type: bigint, what: string): number {
	return needFixed(fields, type, 4, what).readUInt32BE(0);
}

function needU64(fields: Fields, type: bigint, what: string): bigint {
	return needFixed(fields, type, 8, what).readBigUInt64BE(0);
}

// ─────────────── funding_offer (subtype 16) ───────────────

const OFFER_TYPES = {
	offerId: 0n,
	amountSat: 2n,
	txid: 4n,
	vout: 6n,
	valueSat: 8n,
	sequence: 10n,
	changeScript: 12n,
	maxTotalFeeSat: 14n,
	receiptHash: 16n,
	ownershipPubkey: 18n,
	ownershipSignature: 20n
};

function ownershipPubkey(value: Buffer): Buffer {
	if (value.length !== DF_NODE_ID_BYTES && value.length !== 32) {
		throw malformed(
			`ownership pubkey must be 33 bytes (ECDSA) or 32 (Schnorr), got ${value.length}`
		);
	}
	return Buffer.from(value);
}

export function encodeDfOffer(o: IDfOffer): Buffer {
	return encodeTlvStream([
		{
			type: OFFER_TYPES.offerId,
			value: fixed(o.offerId, DF_OFFER_ID_BYTES, 'offer id')
		},
		{ type: OFFER_TYPES.amountSat, value: u64Buf(o.amountSat, 'amount_sat') },
		{ type: OFFER_TYPES.txid, value: fixed(o.txid, TXID_BYTES, 'txid') },
		{ type: OFFER_TYPES.vout, value: u32Buf(o.vout, 'vout') },
		{ type: OFFER_TYPES.valueSat, value: u64Buf(o.valueSat, 'value_sat') },
		{ type: OFFER_TYPES.sequence, value: u32Buf(o.sequence, 'sequence') },
		{
			type: OFFER_TYPES.changeScript,
			value: bounded(o.changeScript, DF_MAX_SCRIPT_BYTES, 'change script')
		},
		{
			type: OFFER_TYPES.maxTotalFeeSat,
			value: u64Buf(o.maxTotalFeeSat, 'max_total_fee_sat')
		},
		{
			type: OFFER_TYPES.receiptHash,
			value: fixed(o.receiptHash, DF_RECEIPT_HASH_BYTES, 'receipt hash')
		},
		{
			type: OFFER_TYPES.ownershipPubkey,
			value: ownershipPubkey(o.ownership.pubkey)
		},
		{
			type: OFFER_TYPES.ownershipSignature,
			value: fixed(
				o.ownership.signature,
				COMPACT_SIG_BYTES,
				'ownership signature'
			)
		}
	]);
}

export function decodeDfOffer(data: Buffer): IDfOffer {
	const f = decodeFields(data, Object.values(OFFER_TYPES), 'funding_offer');
	return {
		offerId: needFixed(f, OFFER_TYPES.offerId, DF_OFFER_ID_BYTES, 'offer id'),
		amountSat: needU64(f, OFFER_TYPES.amountSat, 'amount_sat'),
		txid: needFixed(f, OFFER_TYPES.txid, TXID_BYTES, 'txid'),
		vout: needU32(f, OFFER_TYPES.vout, 'vout'),
		valueSat: needU64(f, OFFER_TYPES.valueSat, 'value_sat'),
		sequence: needU32(f, OFFER_TYPES.sequence, 'sequence'),
		changeScript: Buffer.from(
			bounded(
				need(f, OFFER_TYPES.changeScript, 'change script'),
				DF_MAX_SCRIPT_BYTES,
				'change script'
			)
		),
		maxTotalFeeSat: needU64(f, OFFER_TYPES.maxTotalFeeSat, 'max_total_fee_sat'),
		// REQUIRED by rev 2: a session exists only for a request this receiver
		// minted, and the hash is what says which one.
		receiptHash: needFixed(
			f,
			OFFER_TYPES.receiptHash,
			DF_RECEIPT_HASH_BYTES,
			'receipt hash'
		),
		ownership: {
			pubkey: ownershipPubkey(
				need(f, OFFER_TYPES.ownershipPubkey, 'ownership pubkey')
			),
			signature: needFixed(
				f,
				OFFER_TYPES.ownershipSignature,
				COMPACT_SIG_BYTES,
				'ownership signature'
			)
		}
	};
}

// ─────────────── funding_offer_ack (17) ───────────────

const ACK_TYPES = { offerId: 0n, accepted: 2n, reason: 3n };

export function encodeDfOfferAck(a: IDfOfferAck): Buffer {
	const records: ITlvRecord[] = [
		{
			type: ACK_TYPES.offerId,
			value: fixed(a.offerId, DF_OFFER_ID_BYTES, 'offer id')
		},
		{ type: ACK_TYPES.accepted, value: Buffer.from([a.accepted ? 1 : 0]) }
	];
	if (a.reason !== undefined) {
		// Ours to write, so a long one is truncated rather than refused.
		records.push({
			type: ACK_TYPES.reason,
			value: Buffer.from(a.reason, 'utf8').subarray(0, DF_MAX_REASON_BYTES)
		});
	}
	return encodeTlvStream(records);
}

export function decodeDfOfferAck(data: Buffer): IDfOfferAck {
	const f = decodeFields(data, Object.values(ACK_TYPES), 'funding_offer_ack');
	const reason = f.get(ACK_TYPES.reason);
	return {
		offerId: needFixed(f, ACK_TYPES.offerId, DF_OFFER_ID_BYTES, 'offer id'),
		accepted: needFixed(f, ACK_TYPES.accepted, 1, 'accepted')[0] === 1,
		...(reason
			? {
					reason: bounded(reason, DF_MAX_REASON_BYTES, 'reason').toString(
						'utf8'
					)
			  }
			: {})
	};
}

// ─────────────── funding_sign_request (18) ───────────────

const SIGN_REQUEST_TYPES = {
	offerId: 0n,
	rawTx: 2n,
	prevouts: 4n,
	fundingOutputIndex: 6n,
	localFundingPubkey: 8n,
	remoteFundingPubkey: 10n,
	attestationSignature: 12n,
	sharedInputIndex: 13n
};

function encodePrevouts(prevouts: IDfPrevout[]): Buffer {
	if (prevouts.length > DF_MAX_PREVOUTS) {
		throw malformed(
			`${prevouts.length} prevouts, max ${DF_MAX_PREVOUTS} (rev 2 input cap)`
		);
	}
	const parts: Buffer[] = [u16Buf(prevouts.length, 'prevout count')];
	for (const p of prevouts) {
		parts.push(
			u64Buf(p.valueSat, 'prevout value'),
			u16Buf(p.script.length, 'prevout script length'),
			bounded(p.script, DF_MAX_SCRIPT_BYTES, 'prevout script')
		);
	}
	return Buffer.concat(parts);
}

function decodePrevouts(value: Buffer): IDfPrevout[] {
	const r = new ByteReader(value);
	const count = r.u16('prevout count');
	if (count > DF_MAX_PREVOUTS) {
		throw malformed(
			`sign request declares ${count} prevouts, max ${DF_MAX_PREVOUTS}`
		);
	}
	const prevouts: IDfPrevout[] = [];
	for (let i = 0; i < count; i++) {
		const valueSat = r.u64('prevout value');
		const len = r.u16('prevout script length');
		if (len > DF_MAX_SCRIPT_BYTES) {
			throw malformed(
				`prevout script is ${len} bytes, max ${DF_MAX_SCRIPT_BYTES}`
			);
		}
		prevouts.push({
			valueSat,
			script: Buffer.from(r.take(len, 'prevout script'))
		});
	}
	if (r.remaining() !== 0) throw malformed('prevout list has trailing bytes');
	return prevouts;
}

export function encodeDfSignRequest(s: IDfSignRequest): Buffer {
	const records: ITlvRecord[] = [
		{
			type: SIGN_REQUEST_TYPES.offerId,
			value: fixed(s.offerId, DF_OFFER_ID_BYTES, 'offer id')
		},
		{
			type: SIGN_REQUEST_TYPES.rawTx,
			value: bounded(s.rawTx, DF_MAX_RAW_TX_BYTES, 'raw transaction')
		},
		{ type: SIGN_REQUEST_TYPES.prevouts, value: encodePrevouts(s.prevouts) },
		{
			type: SIGN_REQUEST_TYPES.fundingOutputIndex,
			value: u32Buf(s.attestation.fundingOutputIndex, 'funding output index')
		},
		{
			type: SIGN_REQUEST_TYPES.localFundingPubkey,
			value: fixed(
				s.attestation.localFundingPubkey,
				DF_NODE_ID_BYTES,
				'local funding pubkey'
			)
		},
		{
			type: SIGN_REQUEST_TYPES.remoteFundingPubkey,
			value: fixed(
				s.attestation.remoteFundingPubkey,
				DF_NODE_ID_BYTES,
				'remote funding pubkey'
			)
		},
		{
			type: SIGN_REQUEST_TYPES.attestationSignature,
			value: fixed(s.attestation.signature, DF_SIGNATURE_BYTES, 'attestation')
		}
	];
	if (s.sharedInputIndex !== undefined) {
		records.push({
			type: SIGN_REQUEST_TYPES.sharedInputIndex,
			value: u32Buf(s.sharedInputIndex, 'shared input index')
		});
	}
	return encodeTlvStream(records);
}

export function decodeDfSignRequest(data: Buffer): IDfSignRequest {
	const f = decodeFields(
		data,
		Object.values(SIGN_REQUEST_TYPES),
		'funding_sign_request'
	);
	const shared = f.get(SIGN_REQUEST_TYPES.sharedInputIndex);
	return {
		offerId: needFixed(
			f,
			SIGN_REQUEST_TYPES.offerId,
			DF_OFFER_ID_BYTES,
			'offer id'
		),
		rawTx: Buffer.from(
			bounded(
				need(f, SIGN_REQUEST_TYPES.rawTx, 'raw transaction'),
				DF_MAX_RAW_TX_BYTES,
				'raw transaction'
			)
		),
		prevouts: decodePrevouts(need(f, SIGN_REQUEST_TYPES.prevouts, 'prevouts')),
		attestation: {
			fundingOutputIndex: needU32(
				f,
				SIGN_REQUEST_TYPES.fundingOutputIndex,
				'funding output index'
			),
			localFundingPubkey: needFixed(
				f,
				SIGN_REQUEST_TYPES.localFundingPubkey,
				DF_NODE_ID_BYTES,
				'local funding pubkey'
			),
			remoteFundingPubkey: needFixed(
				f,
				SIGN_REQUEST_TYPES.remoteFundingPubkey,
				DF_NODE_ID_BYTES,
				'remote funding pubkey'
			),
			signature: needFixed(
				f,
				SIGN_REQUEST_TYPES.attestationSignature,
				DF_SIGNATURE_BYTES,
				'attestation'
			)
		},
		...(shared
			? {
					sharedInputIndex: fixed(shared, 4, 'shared input index').readUInt32BE(
						0
					)
			  }
			: {})
	};
}

// ─────────────── funding_witness (19) ───────────────

const WITNESS_TYPES = { offerId: 0n, witness: 2n };

export function encodeDfWitness(w: IDfWitness): Buffer {
	if (w.witness.length > DF_MAX_WITNESS_ITEMS) {
		throw malformed(
			`witness has ${w.witness.length} items, max ${DF_MAX_WITNESS_ITEMS}`
		);
	}
	const parts: Buffer[] = [u16Buf(w.witness.length, 'witness item count')];
	for (const item of w.witness) {
		parts.push(
			u16Buf(item.length, 'witness item length'),
			bounded(item, DF_MAX_WITNESS_ITEM_BYTES, 'witness item')
		);
	}
	return encodeTlvStream([
		{
			type: WITNESS_TYPES.offerId,
			value: fixed(w.offerId, DF_OFFER_ID_BYTES, 'offer id')
		},
		{ type: WITNESS_TYPES.witness, value: Buffer.concat(parts) }
	]);
}

export function decodeDfWitness(data: Buffer): IDfWitness {
	const f = decodeFields(data, Object.values(WITNESS_TYPES), 'funding_witness');
	const r = new ByteReader(need(f, WITNESS_TYPES.witness, 'witness'));
	const count = r.u16('witness item count');
	if (count > DF_MAX_WITNESS_ITEMS) {
		throw malformed(
			`witness declares ${count} items, max ${DF_MAX_WITNESS_ITEMS}`
		);
	}
	const witness: Buffer[] = [];
	for (let i = 0; i < count; i++) {
		const len = r.u16('witness item length');
		if (len > DF_MAX_WITNESS_ITEM_BYTES) {
			throw malformed(
				`witness item is ${len} bytes, max ${DF_MAX_WITNESS_ITEM_BYTES}`
			);
		}
		witness.push(Buffer.from(r.take(len, 'witness item')));
	}
	if (r.remaining() !== 0) throw malformed('witness stack has trailing bytes');
	return {
		offerId: needFixed(f, WITNESS_TYPES.offerId, DF_OFFER_ID_BYTES, 'offer id'),
		witness
	};
}

// ─────────────── funding_receipt (21) ───────────────

const RECEIPT_TYPES = {
	offerId: 0n,
	preimage: 2n,
	fundingTxid: 4n,
	rawTx: 5n
};

export function encodeDfReceipt(r: IDfReceipt): Buffer {
	const records: ITlvRecord[] = [
		{
			type: RECEIPT_TYPES.offerId,
			value: fixed(r.offerId, DF_OFFER_ID_BYTES, 'offer id')
		},
		{
			type: RECEIPT_TYPES.preimage,
			value: fixed(r.preimage, DF_PREIMAGE_BYTES, 'preimage')
		},
		{
			type: RECEIPT_TYPES.fundingTxid,
			value: fixed(r.fundingTxid, TXID_BYTES, 'funding txid')
		}
	];
	if (r.rawTx !== undefined) {
		records.push({
			type: RECEIPT_TYPES.rawTx,
			value: bounded(r.rawTx, DF_MAX_RAW_TX_BYTES, 'raw transaction')
		});
	}
	return encodeTlvStream(records);
}

export function decodeDfReceipt(data: Buffer): IDfReceipt {
	const f = decodeFields(data, Object.values(RECEIPT_TYPES), 'funding_receipt');
	const rawTx = f.get(RECEIPT_TYPES.rawTx);
	return {
		offerId: needFixed(f, RECEIPT_TYPES.offerId, DF_OFFER_ID_BYTES, 'offer id'),
		preimage: needFixed(
			f,
			RECEIPT_TYPES.preimage,
			DF_PREIMAGE_BYTES,
			'preimage'
		),
		fundingTxid: needFixed(
			f,
			RECEIPT_TYPES.fundingTxid,
			TXID_BYTES,
			'funding txid'
		),
		...(rawTx
			? {
					rawTx: Buffer.from(
						bounded(rawTx, DF_MAX_RAW_TX_BYTES, 'raw transaction')
					)
			  }
			: {})
	};
}

// ─────────────── relay envelope (22) ───────────────

const RELAY_TYPES = { subtype: 0n, payload: 2n, to: 4n, from: 6n };

export function encodeDfRelayFrame(r: IDfRelayFrame): Buffer {
	if ((r.to === undefined) === (r.from === undefined)) {
		throw malformed('relay frame carries exactly one of to/from');
	}
	const records: ITlvRecord[] = [
		{ type: RELAY_TYPES.subtype, value: u16Buf(r.subtype, 'relayed subtype') },
		{
			type: RELAY_TYPES.payload,
			value: bounded(r.payload, DF_MAX_MESSAGE_BYTES, 'relayed payload')
		}
	];
	if (r.to) {
		records.push({
			type: RELAY_TYPES.to,
			value: fixed(r.to, DF_NODE_ID_BYTES, 'relay destination')
		});
	}
	if (r.from) {
		records.push({
			type: RELAY_TYPES.from,
			value: fixed(r.from, DF_NODE_ID_BYTES, 'relay origin')
		});
	}
	return encodeTlvStream(records);
}

export function decodeDfRelayFrame(data: Buffer): IDfRelayFrame {
	const f = decodeFields(data, Object.values(RELAY_TYPES), 'relay frame');
	const to = f.get(RELAY_TYPES.to);
	const from = f.get(RELAY_TYPES.from);
	// Both present would let a payer pre-stamp its own origin, and neither
	// leaves the relay nothing to route on.
	if ((to === undefined) === (from === undefined)) {
		throw malformed('relay frame must carry exactly one of to/from');
	}
	return {
		subtype: needU16(f, RELAY_TYPES.subtype, 'relayed subtype'),
		payload: Buffer.from(
			bounded(
				need(f, RELAY_TYPES.payload, 'relayed payload'),
				DF_MAX_MESSAGE_BYTES,
				'relayed payload'
			)
		),
		...(to
			? { to: Buffer.from(fixed(to, DF_NODE_ID_BYTES, 'relay destination')) }
			: {}),
		...(from
			? { from: Buffer.from(fixed(from, DF_NODE_ID_BYTES, 'relay origin')) }
			: {})
	};
}

// ─────────────── Signed strings ───────────────

/**
 * The offer's identity: the first 16 bytes of SHA256 over txid, vout and
 * amount. The same logical payment retries under the same id (which is what
 * makes a duplicate offer replayable), while any change of coin or amount is
 * a different offer. Rev 2 warns implementers that an earlier revision
 * derived it from a prefix that truncated BEFORE the amount.
 */
export function deriveOfferId(
	txid: Buffer,
	vout: number,
	amountSat: bigint
): Buffer {
	fixed(txid, TXID_BYTES, 'txid');
	return crypto
		.createHash('sha256')
		.update(`${txid.toString('hex')}:${vout}:${amountSat}`, 'utf8')
		.digest()
		.subarray(0, DF_OFFER_ID_BYTES);
}

/**
 * The digest the UTXO's key signs to prove control of the offered coin
 * (ECDSA for P2WPKH, Schnorr for P2TR key path).
 */
export function ownershipDigest(
	offerId: Buffer,
	txid: Buffer,
	vout: number,
	amountSat: bigint
): Buffer {
	fixed(offerId, DF_OFFER_ID_BYTES, 'offer id');
	fixed(txid, TXID_BYTES, 'txid');
	return crypto
		.createHash('sha256')
		.update(
			`lfbw-direct-funding-offer:${offerId.toString('hex')}:${txid.toString(
				'hex'
			)}:${vout}:${amountSat}`,
			'utf8'
		)
		.digest();
}

/**
 * The ASCII string the receiver's NODE key signs for the attestation, under
 * the same Lightning message-signing scheme as the envelope. It is the bridge
 * between the payment request and the chain transaction: the node id the
 * request named vouches for exactly this output in exactly this transaction.
 * The transaction is hashed rather than embedded to keep the signed string
 * fixed size; the payer recomputes the hash from the bytes it was handed.
 */
export function attestationMessage(
	offerId: Buffer,
	rawTx: Buffer,
	fundingOutputIndex: number,
	localFundingPubkey: Buffer
): string {
	fixed(offerId, DF_OFFER_ID_BYTES, 'offer id');
	fixed(localFundingPubkey, DF_NODE_ID_BYTES, 'local funding pubkey');
	const txHash = crypto.createHash('sha256').update(rawTx).digest('hex');
	return (
		`lfbw-direct-funding-attest:${offerId.toString('hex')}:${txHash}:` +
		`${fundingOutputIndex}:${localFundingPubkey.toString('hex')}`
	);
}
