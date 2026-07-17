/**
 * BOLT 12: Offers -- Type definitions.
 *
 * Defines interfaces for all BOLT 12 message types:
 * - IOffer (lno-prefixed): Reusable payment endpoint
 * - IInvoiceRequest (lnr-prefixed): Request for a BOLT 12 invoice
 * - IBolt12Invoice (lni-prefixed): One-time payment invoice
 * - IInvoiceError: Error response to an invoice request
 */

import { IBlindedPath } from '../onion/blinded-path';

// ── Offer (lno) ─────────────────────────────────────────────────────

export interface IOffer {
	/** SHA256 merkle root of the offer TLV stream (32 bytes) */
	offerId: Buffer;
	/** Optional amount in millisatoshis */
	amount?: bigint;
	/** Human-readable description */
	description: string;
	/** Optional issuer name / info */
	issuer?: string;
	/** Optional feature bits */
	features?: Buffer;
	/** Optional blinded paths for reaching the issuer */
	paths?: IBlindedPath[];
	/** Node public key of the issuer (33-byte compressed) */
	issuerId?: Buffer;
	/** Maximum quantity that can be requested (0 = no limit) */
	quantityMax?: bigint;
	/** Absolute expiry as seconds since Unix epoch */
	absoluteExpiry?: bigint;
	/** Supported chain hashes (each 32 bytes) */
	chains?: Buffer[];
	/** Optional metadata */
	metadata?: Buffer;
	/** Optional currency (ISO 4217) */
	currency?: string;
}

// ── Invoice Request (lnr) ───────────────────────────────────────────

export interface IInvoiceRequest {
	/** 33-byte payer public key (ephemeral for this request) */
	payerKey: Buffer;
	/** Optional payer note / memo */
	payerNote?: string;
	/** Offer ID this request references */
	offerId: Buffer;
	/** Requested amount in millisatoshis */
	amount?: bigint;
	/** Optional feature bits */
	features?: Buffer;
	/** Requested quantity */
	quantity?: bigint;
	/** Chain hash (32 bytes) */
	chain?: Buffer;
	/** invreq_metadata (BOLT 12 type 0): payer-generated proof/nonce, MUST be set. */
	metadata?: Buffer;
	/** Signature over the invoice request TLV stream (64 bytes Schnorr) */
	signature?: Buffer;
}

// ── BOLT 12 Invoice (lni) ───────────────────────────────────────────

export interface IFallbackAddress {
	/** Address version (e.g. 0 for segwit v0) */
	version: number;
	/** Address program */
	program: Buffer;
}

export interface IBolt12Invoice {
	/** Payment hash (32 bytes) */
	paymentHash: Buffer;
	/** Amount in millisatoshis */
	amount: bigint;
	/** Human-readable description */
	description: string;
	/** Optional feature bits */
	features?: Buffer;
	/** Created timestamp (seconds since Unix epoch) */
	createdAt: bigint;
	/** Relative expiry in seconds from created_at */
	relativeExpiry?: number;
	/** Payment secret (32 bytes) */
	paymentSecret?: Buffer;
	/** Blinded paths for payment delivery */
	paths?: IBlindedPath[];
	/** Blinded payment info (parallel array with paths) */
	blindedPayInfo?: IBlindedPayInfo[];
	/** On-chain fallback addresses */
	fallbacks?: IFallbackAddress[];
	/** Node ID of the invoice issuer (33 bytes) */
	nodeId: Buffer;
	/** Schnorr signature (64 bytes) */
	signature?: Buffer;
	/**
	 * The full wire TLV records (BOLT 12): includes the invreq fields the
	 * invoice mirrors and any unknown TLVs. Source of truth for signature
	 * verification and faithful re-encoding — the structural fields above
	 * cannot reconstruct them. Set on decode and on issuance.
	 */
	records?: import('../message/tlv').ITlvRecord[];
	/** Optional metadata from the offer */
	metadata?: Buffer;
	/** Offer ID this invoice is for */
	offerId?: Buffer;
	/** Chain hash (32 bytes) */
	chain?: Buffer;
}

export interface IBlindedPayInfo {
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	htlcMinimumMsat: bigint;
	htlcMaximumMsat: bigint;
	features?: Buffer;
}

// ── Invoice Error ───────────────────────────────────────────────────

export interface IInvoiceError {
	/** TLV type number of the erroneous field */
	erroneousField?: bigint;
	/** Suggested replacement value */
	suggestedValue?: Buffer;
	/** Human-readable error string */
	error: string;
}
