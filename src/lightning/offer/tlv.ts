/**
 * BOLT 12: Offer TLV Type Enumerations and Encode/Decode.
 *
 * Defines TLV types for offers, invoice requests, and invoices,
 * plus encode/decode helpers for each type.
 */

import { encodeBigSize } from '../message/codec';
import {
	ITlvRecord,
	encodeTlvStream,
	decodeTlvStream,
	findTlvRecord
} from '../message/tlv';
import {
	encodeBlindedPaths,
	decodeBlindedPaths,
	encodeBlindedPayInfos,
	decodeBlindedPayInfos
} from '../onion/blinded-path';
import {
	IOffer,
	IInvoiceRequest,
	IBolt12Invoice,
	IInvoiceError,
	IFallbackAddress
} from './types';
// Note: merkle.ts also imports from this module; both imports are used only at
// call time, so the module cycle is benign under CommonJS.
import { computeOfferId } from './merkle';

// ── Offer TLV Types (BOLT 12) ──────────────────────────────────────

export enum OfferTlvType {
	CHAINS = 2,
	METADATA = 4,
	CURRENCY = 6,
	AMOUNT = 8,
	DESCRIPTION = 10,
	FEATURES = 12,
	ABSOLUTE_EXPIRY = 14,
	PATHS = 16,
	ISSUER = 18,
	QUANTITY_MAX = 20,
	ISSUER_ID = 22
}

// ── Invoice Request TLV Types ───────────────────────────────────────

export enum InvoiceRequestTlvType {
	// invreq_metadata: BOLT 12 type 0 (payer proof/nonce), sorts before the
	// mirrored offer fields. Type 90 (payer_info) was an obsolete draft field.
	METADATA = 0,
	CHAIN = 80,
	AMOUNT = 82,
	FEATURES = 84,
	QUANTITY = 86,
	PAYER_KEY = 88,
	PAYER_NOTE = 89,
	SIGNATURE = 240
}

// ── Invoice TLV Types ───────────────────────────────────────────────

export enum InvoiceTlvType {
	PATHS = 160,
	BLINDEDPAY = 162,
	CREATED_AT = 164,
	RELATIVE_EXPIRY = 166,
	PAYMENT_HASH = 168,
	AMOUNT = 170,
	FALLBACKS = 172,
	FEATURES = 174,
	NODE_ID = 176,
	SIGNATURE = 240
}

// ── Invoice Error TLV Types ─────────────────────────────────────────

export enum InvoiceErrorTlvType {
	ERRONEOUS_FIELD = 1,
	SUGGESTED_VALUE = 3,
	ERROR = 5
}

// ── Helpers ─────────────────────────────────────────────────────────

function encodeU64(val: bigint): Buffer {
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(val);
	return buf;
}

function encodeU32(val: number): Buffer {
	const buf = Buffer.alloc(4);
	buf.writeUInt32BE(val);
	return buf;
}

/**
 * Blinded path (de)serialization lives in onion/blinded-path.ts as the shared
 * source of truth (encodeBlindedPaths/decodeBlindedPaths), reused by both BOLT
 * 12 here and the BOLT 11 invoice blinded-paths tagged field. The thin aliases
 * below keep the existing call sites readable.
 */
const encodeBlindedPathsValue = encodeBlindedPaths;
const decodeBlindedPathsValue = decodeBlindedPaths;

// ── Offer Encode/Decode ─────────────────────────────────────────────

/**
 * Encode an IOffer into a TLV stream (raw bytes, no signature).
 * The resulting TLV records are in strictly increasing type order.
 */
export function encodeOfferTlv(offer: IOffer): Buffer {
	const records: ITlvRecord[] = [];

	if (offer.chains && offer.chains.length > 0) {
		records.push({
			type: BigInt(OfferTlvType.CHAINS),
			value: Buffer.concat(offer.chains)
		});
	}
	if (offer.metadata) {
		records.push({
			type: BigInt(OfferTlvType.METADATA),
			value: offer.metadata
		});
	}
	if (offer.currency) {
		records.push({
			type: BigInt(OfferTlvType.CURRENCY),
			value: Buffer.from(offer.currency, 'utf8')
		});
	}
	if (offer.amount !== undefined) {
		records.push({
			type: BigInt(OfferTlvType.AMOUNT),
			value: encodeTruncatedU64(offer.amount)
		});
	}
	records.push({
		type: BigInt(OfferTlvType.DESCRIPTION),
		value: Buffer.from(offer.description, 'utf8')
	});
	if (offer.features && offer.features.length > 0) {
		records.push({
			type: BigInt(OfferTlvType.FEATURES),
			value: offer.features
		});
	}
	if (offer.absoluteExpiry !== undefined) {
		records.push({
			type: BigInt(OfferTlvType.ABSOLUTE_EXPIRY),
			value: encodeTruncatedU64(offer.absoluteExpiry)
		});
	}
	if (offer.paths && offer.paths.length > 0) {
		records.push({
			type: BigInt(OfferTlvType.PATHS),
			value: encodeBlindedPathsValue(offer.paths)
		});
	}
	if (offer.issuer) {
		records.push({
			type: BigInt(OfferTlvType.ISSUER),
			value: Buffer.from(offer.issuer, 'utf8')
		});
	}
	if (offer.quantityMax !== undefined) {
		records.push({
			type: BigInt(OfferTlvType.QUANTITY_MAX),
			value: encodeTruncatedU64(offer.quantityMax)
		});
	}
	if (offer.issuerId) {
		records.push({
			type: BigInt(OfferTlvType.ISSUER_ID),
			value: offer.issuerId
		});
	}

	return encodeTlvStream(records);
}

/**
 * Decode an IOffer from a TLV stream.
 * Does NOT set offerId — caller must compute the merkle root.
 */
export function decodeOfferTlv(data: Buffer): {
	offer: Omit<IOffer, 'offerId'>;
	records: ITlvRecord[];
} {
	const { records } = decodeTlvStream(data);

	const chainsVal = findTlvRecord(records, BigInt(OfferTlvType.CHAINS));
	const metadataVal = findTlvRecord(records, BigInt(OfferTlvType.METADATA));
	const currencyVal = findTlvRecord(records, BigInt(OfferTlvType.CURRENCY));
	const amountVal = findTlvRecord(records, BigInt(OfferTlvType.AMOUNT));
	const descVal = findTlvRecord(records, BigInt(OfferTlvType.DESCRIPTION));
	const featuresVal = findTlvRecord(records, BigInt(OfferTlvType.FEATURES));
	const expiryVal = findTlvRecord(
		records,
		BigInt(OfferTlvType.ABSOLUTE_EXPIRY)
	);
	const pathsVal = findTlvRecord(records, BigInt(OfferTlvType.PATHS));
	const issuerVal = findTlvRecord(records, BigInt(OfferTlvType.ISSUER));
	const qtyMaxVal = findTlvRecord(records, BigInt(OfferTlvType.QUANTITY_MAX));
	const issuerIdVal = findTlvRecord(records, BigInt(OfferTlvType.ISSUER_ID));

	if (!descVal) {
		throw new Error('Offer missing required description field');
	}

	const offer: Omit<IOffer, 'offerId'> = {
		description: descVal.toString('utf8')
	};

	if (chainsVal) {
		const chains: Buffer[] = [];
		for (let i = 0; i < chainsVal.length; i += 32) {
			chains.push(Buffer.from(chainsVal.subarray(i, i + 32)));
		}
		offer.chains = chains;
	}
	if (metadataVal) offer.metadata = metadataVal;
	if (currencyVal) offer.currency = currencyVal.toString('utf8');
	if (amountVal) offer.amount = decodeTruncatedU64(amountVal);
	if (featuresVal) offer.features = featuresVal;
	if (expiryVal) offer.absoluteExpiry = decodeTruncatedU64(expiryVal);
	if (pathsVal) offer.paths = decodeBlindedPathsValue(pathsVal);
	if (issuerVal) offer.issuer = issuerVal.toString('utf8');
	if (qtyMaxVal) offer.quantityMax = decodeTruncatedU64(qtyMaxVal);
	if (issuerIdVal) offer.issuerId = issuerIdVal;

	return { offer, records };
}

// ── Invoice Request Encode/Decode ───────────────────────────────────

/**
 * Encode an IInvoiceRequest into a TLV stream.
 * Includes offer TLV fields (referenced by offerId) and request-specific fields.
 */
export function encodeInvoiceRequestTlv(
	request: IInvoiceRequest,
	offerTlvData?: Buffer
): Buffer {
	const records: ITlvRecord[] = [];

	// invreq_metadata (type 0): the payer's proof/nonce. BOLT 12 requires it and
	// it is covered by the signature; it sorts before the mirrored offer fields.
	if (request.metadata) {
		records.push({
			type: BigInt(InvoiceRequestTlvType.METADATA),
			value: request.metadata
		});
	}

	// Include offer TLV data at the beginning if provided (types 2-22)
	if (offerTlvData) {
		const { records: offerRecords } = decodeTlvStream(offerTlvData);
		for (const r of offerRecords) {
			records.push(r);
		}
	}

	// Request-specific fields (types 80+)
	if (request.chain) {
		records.push({
			type: BigInt(InvoiceRequestTlvType.CHAIN),
			value: request.chain
		});
	}
	if (request.amount !== undefined) {
		records.push({
			type: BigInt(InvoiceRequestTlvType.AMOUNT),
			value: encodeTruncatedU64(request.amount)
		});
	}
	if (request.features && request.features.length > 0) {
		records.push({
			type: BigInt(InvoiceRequestTlvType.FEATURES),
			value: request.features
		});
	}
	if (request.quantity !== undefined) {
		records.push({
			type: BigInt(InvoiceRequestTlvType.QUANTITY),
			value: encodeTruncatedU64(request.quantity)
		});
	}
	records.push({
		type: BigInt(InvoiceRequestTlvType.PAYER_KEY),
		value: request.payerKey
	});
	if (request.payerNote) {
		records.push({
			type: BigInt(InvoiceRequestTlvType.PAYER_NOTE),
			value: Buffer.from(request.payerNote, 'utf8')
		});
	}
	// signature (type 240): serialized last so it is on the wire. It is excluded
	// from the signed merkle tree, so emitting it does not change the hash.
	if (request.signature) {
		records.push({
			type: BigInt(InvoiceRequestTlvType.SIGNATURE),
			value: request.signature
		});
	}

	// Sort by type to ensure strict ordering
	records.sort((a, b) => {
		if (a.type < b.type) return -1;
		if (a.type > b.type) return 1;
		return 0;
	});

	return encodeTlvStream(records);
}

/**
 * Decode an IInvoiceRequest from a TLV stream.
 */
export function decodeInvoiceRequestTlv(data: Buffer): {
	request: IInvoiceRequest;
	records: ITlvRecord[];
} {
	const { records } = decodeTlvStream(data);

	const chainVal = findTlvRecord(records, BigInt(InvoiceRequestTlvType.CHAIN));
	const amountVal = findTlvRecord(
		records,
		BigInt(InvoiceRequestTlvType.AMOUNT)
	);
	const featuresVal = findTlvRecord(
		records,
		BigInt(InvoiceRequestTlvType.FEATURES)
	);
	const qtyVal = findTlvRecord(records, BigInt(InvoiceRequestTlvType.QUANTITY));
	const payerKeyVal = findTlvRecord(
		records,
		BigInt(InvoiceRequestTlvType.PAYER_KEY)
	);
	const payerNoteVal = findTlvRecord(
		records,
		BigInt(InvoiceRequestTlvType.PAYER_NOTE)
	);
	const metadataVal = findTlvRecord(
		records,
		BigInt(InvoiceRequestTlvType.METADATA)
	);
	const signatureVal = findTlvRecord(
		records,
		BigInt(InvoiceRequestTlvType.SIGNATURE)
	);

	if (!payerKeyVal) {
		throw new Error('Invoice request missing required payer_key field');
	}

	// Compute offerId from the offer TLV records mirrored into the request. Offer
	// TLVs occupy types 1-79; invreq_metadata (type 0) and the invreq fields
	// (80+) are NOT part of the offer and must be excluded, or the offer_id would
	// not match the one the issuer computed. Zero when no offer records mirrored.
	const offerRecords = records.filter((r) => r.type >= 1n && r.type <= 79n);
	const offerId =
		offerRecords.length > 0 ? computeOfferId(offerRecords) : Buffer.alloc(32);

	const request: IInvoiceRequest = {
		payerKey: payerKeyVal,
		offerId
	};

	if (chainVal) request.chain = chainVal;
	if (amountVal) request.amount = decodeTruncatedU64(amountVal);
	if (featuresVal) request.features = featuresVal;
	if (qtyVal) request.quantity = decodeTruncatedU64(qtyVal);
	if (payerNoteVal) request.payerNote = payerNoteVal.toString('utf8');
	if (metadataVal) request.metadata = metadataVal;
	if (signatureVal) request.signature = signatureVal;

	return { request, records };
}

// ── Invoice Encode/Decode ───────────────────────────────────────────

/**
 * Encode an IBolt12Invoice into a TLV stream.
 * The signature field (type 240) is included if present.
 *
 * `mirrorRecords` (BOLT 12): when the invoice responds to an invoice_request,
 * the writer MUST copy ALL non-signature fields from the request (including
 * unknown ones) — the invreq/offer fields live in types 0-159 and the
 * experimental ranges. Without the mirror every spec reader (CLN/eclair/LDK)
 * rejects the invoice outright (S-4.H3).
 */
export function encodeInvoiceTlv(
	invoice: IBolt12Invoice,
	mirrorRecords?: ITlvRecord[]
): Buffer {
	const records: ITlvRecord[] = [];

	if (mirrorRecords) {
		for (const r of mirrorRecords) {
			if (r.type === BigInt(InvoiceTlvType.SIGNATURE)) continue;
			if (
				(r.type >= 0n && r.type < 160n) ||
				(r.type >= 1_000_000_000n && r.type < 3_000_000_000n)
			) {
				records.push(r);
			}
		}
	}

	if (invoice.paths && invoice.paths.length > 0) {
		records.push({
			type: BigInt(InvoiceTlvType.PATHS),
			value: encodeBlindedPathsValue(invoice.paths)
		});
	}
	if (invoice.blindedPayInfo && invoice.blindedPayInfo.length > 0) {
		records.push({
			type: BigInt(InvoiceTlvType.BLINDEDPAY),
			value: encodeBlindedPayInfoArray(invoice.blindedPayInfo)
		});
	}
	records.push({
		type: BigInt(InvoiceTlvType.CREATED_AT),
		value: encodeTruncatedU64(invoice.createdAt)
	});
	if (invoice.relativeExpiry !== undefined) {
		records.push({
			type: BigInt(InvoiceTlvType.RELATIVE_EXPIRY),
			// BOLT 12: invoice_relative_expiry is tu32, not a fixed u32. A fixed
			// encoding carries leading zero bytes that a spec reader MUST reject.
			value: encodeTruncatedU32(invoice.relativeExpiry)
		});
	}
	records.push({
		type: BigInt(InvoiceTlvType.PAYMENT_HASH),
		value: invoice.paymentHash
	});
	records.push({
		type: BigInt(InvoiceTlvType.AMOUNT),
		value: encodeTruncatedU64(invoice.amount)
	});
	if (invoice.fallbacks && invoice.fallbacks.length > 0) {
		records.push({
			type: BigInt(InvoiceTlvType.FALLBACKS),
			value: encodeFallbacks(invoice.fallbacks)
		});
	}
	if (invoice.features && invoice.features.length > 0) {
		records.push({
			type: BigInt(InvoiceTlvType.FEATURES),
			value: invoice.features
		});
	}
	records.push({
		type: BigInt(InvoiceTlvType.NODE_ID),
		value: invoice.nodeId
	});
	if (invoice.signature) {
		records.push({
			type: BigInt(InvoiceTlvType.SIGNATURE),
			value: invoice.signature
		});
	}

	// Mirrored invreq/offer records (0-159) interleave BELOW the invoice's own
	// fields (160+); encodeTlvStream requires strictly increasing types.
	records.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));

	return encodeTlvStream(records);
}

/**
 * Decode an IBolt12Invoice from a TLV stream.
 */
export function decodeInvoiceTlv(data: Buffer): {
	invoice: IBolt12Invoice;
	records: ITlvRecord[];
} {
	const { records } = decodeTlvStream(data);

	const pathsVal = findTlvRecord(records, BigInt(InvoiceTlvType.PATHS));
	const blindedPayVal = findTlvRecord(
		records,
		BigInt(InvoiceTlvType.BLINDEDPAY)
	);
	const createdAtVal = findTlvRecord(
		records,
		BigInt(InvoiceTlvType.CREATED_AT)
	);
	const relExpiryVal = findTlvRecord(
		records,
		BigInt(InvoiceTlvType.RELATIVE_EXPIRY)
	);
	const payHashVal = findTlvRecord(
		records,
		BigInt(InvoiceTlvType.PAYMENT_HASH)
	);
	const amountVal = findTlvRecord(records, BigInt(InvoiceTlvType.AMOUNT));
	const fallbacksVal = findTlvRecord(records, BigInt(InvoiceTlvType.FALLBACKS));
	const featuresVal = findTlvRecord(records, BigInt(InvoiceTlvType.FEATURES));
	const nodeIdVal = findTlvRecord(records, BigInt(InvoiceTlvType.NODE_ID));
	const sigVal = findTlvRecord(records, BigInt(InvoiceTlvType.SIGNATURE));

	if (!payHashVal)
		throw new Error('Invoice missing required payment_hash field');
	if (!amountVal) throw new Error('Invoice missing required amount field');
	if (!nodeIdVal) throw new Error('Invoice missing required node_id field');
	if (!createdAtVal)
		throw new Error('Invoice missing required created_at field');

	// The mirrored offer_description (type 10) rides in the invoice per the
	// BOLT 12 copy-all-invreq-fields rule; use it when present.
	const mirroredDesc = findTlvRecord(records, BigInt(OfferTlvType.DESCRIPTION));
	const invoice: IBolt12Invoice = {
		paymentHash: payHashVal,
		amount: decodeTruncatedU64(amountVal),
		description: mirroredDesc ? mirroredDesc.toString('utf8') : '',
		createdAt: decodeTruncatedU64(createdAtVal),
		nodeId: nodeIdVal
	};

	if (pathsVal) invoice.paths = decodeBlindedPathsValue(pathsVal);
	if (blindedPayVal)
		invoice.blindedPayInfo = decodeBlindedPayInfoArray(blindedPayVal);
	if (relExpiryVal) invoice.relativeExpiry = decodeTruncatedU32(relExpiryVal);
	if (fallbacksVal) invoice.fallbacks = decodeFallbacks(fallbacksVal);
	if (featuresVal) invoice.features = featuresVal;
	if (sigVal) invoice.signature = sigVal;
	// Full wire records (mirrored invreq fields + unknown TLVs included):
	// the source of truth for signature verification and re-encoding.
	invoice.records = records;

	return { invoice, records };
}

// ── Invoice Error Encode/Decode ─────────────────────────────────────

/**
 * Encode an IInvoiceError into a TLV stream.
 */
export function encodeInvoiceErrorTlv(err: IInvoiceError): Buffer {
	const records: ITlvRecord[] = [];

	if (err.erroneousField !== undefined) {
		records.push({
			type: BigInt(InvoiceErrorTlvType.ERRONEOUS_FIELD),
			value: encodeTruncatedU64(err.erroneousField)
		});
	}
	if (err.suggestedValue) {
		records.push({
			type: BigInt(InvoiceErrorTlvType.SUGGESTED_VALUE),
			value: err.suggestedValue
		});
	}
	records.push({
		type: BigInt(InvoiceErrorTlvType.ERROR),
		value: Buffer.from(err.error, 'utf8')
	});

	return encodeTlvStream(records);
}

/**
 * Decode an IInvoiceError from a TLV stream.
 */
export function decodeInvoiceErrorTlv(data: Buffer): IInvoiceError {
	const { records } = decodeTlvStream(data);

	const fieldVal = findTlvRecord(
		records,
		BigInt(InvoiceErrorTlvType.ERRONEOUS_FIELD)
	);
	const sugVal = findTlvRecord(
		records,
		BigInt(InvoiceErrorTlvType.SUGGESTED_VALUE)
	);
	const errVal = findTlvRecord(records, BigInt(InvoiceErrorTlvType.ERROR));

	if (!errVal) {
		throw new Error('Invoice error missing required error field');
	}

	const result: IInvoiceError = {
		error: errVal.toString('utf8')
	};

	if (fieldVal) result.erroneousField = decodeTruncatedU64(fieldVal);
	if (sugVal) result.suggestedValue = sugVal;

	return result;
}

// ── Blinded Pay Info Encode/Decode ──────────────────────────────────
// Shared with BOLT 11 via onion/blinded-path.ts (encodeBlindedPayInfos /
// decodeBlindedPayInfos). Thin aliases preserve the existing call sites.

const encodeBlindedPayInfoArray = encodeBlindedPayInfos;
const decodeBlindedPayInfoArray = decodeBlindedPayInfos;

// ── Fallback Address Encode/Decode ──────────────────────────────────

function encodeFallbacks(addrs: IFallbackAddress[]): Buffer {
	const parts: Buffer[] = [];
	const count = Buffer.alloc(1);
	count[0] = addrs.length;
	parts.push(count);

	for (const addr of addrs) {
		const header = Buffer.alloc(3);
		header[0] = addr.version;
		header.writeUInt16BE(addr.program.length, 1);
		parts.push(header);
		parts.push(addr.program);
	}

	return Buffer.concat(parts);
}

function decodeFallbacks(buf: Buffer): IFallbackAddress[] {
	let offset = 0;
	const count = buf[offset++];
	const addrs: IFallbackAddress[] = [];

	for (let i = 0; i < count; i++) {
		const version = buf[offset++];
		const len = buf.readUInt16BE(offset);
		offset += 2;
		const program = Buffer.from(buf.subarray(offset, offset + len));
		offset += len;
		addrs.push({ version, program });
	}

	return addrs;
}

// ── Truncated u64 encoding (BOLT 12 uses TU64) ─────────────────────

/**
 * Encode a bigint as a truncated big-endian u64 (no leading zero bytes).
 * A value of 0 encodes to an empty buffer (zero-length).
 */
export function encodeTruncatedU64(val: bigint): Buffer {
	if (val === 0n) return Buffer.alloc(0);
	const full = encodeU64(val);
	let start = 0;
	while (start < full.length - 1 && full[start] === 0) {
		start++;
	}
	return Buffer.from(full.subarray(start));
}

/**
 * Decode a truncated big-endian u64 back to a bigint.
 * An empty buffer decodes to 0n.
 */
export function decodeTruncatedU64(buf: Buffer): bigint {
	if (buf.length === 0) return 0n;
	const padded = Buffer.alloc(8);
	buf.copy(padded, 8 - buf.length);
	return padded.readBigUInt64BE();
}

/**
 * Encode a number as a truncated big-endian u32 (tu32): no leading zero bytes,
 * 0 encodes to an empty buffer. BOLT 12 uses tu32 for invoice_relative_expiry.
 */
export function encodeTruncatedU32(val: number): Buffer {
	if (val === 0) return Buffer.alloc(0);
	const full = encodeU32(val >>> 0);
	let start = 0;
	while (start < full.length - 1 && full[start] === 0) {
		start++;
	}
	return Buffer.from(full.subarray(start));
}

/**
 * Decode a truncated big-endian u32 (tu32). BOLT 12 readers MUST reject a
 * non-minimal integer (a leading zero byte) or one longer than 4 bytes.
 */
export function decodeTruncatedU32(buf: Buffer): number {
	if (buf.length === 0) return 0;
	if (buf.length > 4) {
		throw new Error('tu32 value exceeds 4 bytes');
	}
	if (buf[0] === 0) {
		throw new Error('tu32 value is not minimally encoded');
	}
	const padded = Buffer.alloc(4);
	buf.copy(padded, 4 - buf.length);
	return padded.readUInt32BE();
}

/**
 * Get TLV records from raw encoded offer/request/invoice data.
 * Useful for computing merkle roots and signature hashes.
 */
export function getTlvRecords(data: Buffer): ITlvRecord[] {
	const { records } = decodeTlvStream(data);
	return records;
}

/**
 * Get TLV records excluding the signature record for signature computation.
 * Filters out type 240 (signature).
 */
export function getTlvRecordsForSigning(data: Buffer): ITlvRecord[] {
	const { records } = decodeTlvStream(data);
	return records.filter((r) => r.type !== BigInt(InvoiceTlvType.SIGNATURE));
}

/**
 * Encode individual TLV records (for merkle root computation).
 * Each record is encoded as type || length || value.
 */
export function encodeTlvRecordRaw(record: ITlvRecord): Buffer {
	const typeBytes = encodeBigSize(record.type);
	const lengthBytes = encodeBigSize(BigInt(record.value.length));
	return Buffer.concat([typeBytes, lengthBytes, record.value]);
}
