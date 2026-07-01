/**
 * BOLT 11: Invoice (Payment Request) types and constants.
 */

import { FeatureFlags } from '../features/flags';
import { IBlindedPaymentPath } from '../onion/blinded-path';

/** Lightning network prefixes for HRP. */
export enum Network {
	MAINNET = 'bc',
	TESTNET = 'tb',
	REGTEST = 'bcrt',
	SIGNET = 'tbs'
}

/** Tagged field type identifiers per BOLT 11. */
export enum TagType {
	PAYMENT_HASH = 1,
	ROUTING_INFO = 3,
	FEATURE_BITS = 5,
	EXPIRY = 6,
	FALLBACK_ADDRESS = 9,
	DESCRIPTION = 13,
	PAYMENT_SECRET = 16,
	PAYEE_PUBKEY = 19,
	DESCRIPTION_HASH = 23,
	MIN_FINAL_CLTV_EXPIRY = 24,
	METADATA = 27,
	/**
	 * Blinded payment paths (receiver route blinding).
	 *
	 * BOLT 11 has no finalized blinded-paths tag yet, and beignet's
	 * encrypted_recipient_data uses a compact non-BOLT4 format, so this is a
	 * beignet-internal field for now. 25 is an otherwise-unused 5-bit tag value;
	 * other implementations decode it as an unknown tag and ignore it. Revisit
	 * the value (and switch to BOLT 4 TLV hop data) when the spec lands.
	 */
	BLINDED_PATHS = 25
}

/** A single hop in a routing hint (51 bytes per hop). */
export interface IRoutingHintHop {
	pubkey: Buffer;
	shortChannelId: Buffer;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
}

/** Fallback on-chain address. */
export interface IFallbackAddress {
	version: number;
	hash: Buffer;
}

/** Decoded BOLT 11 invoice. */
export interface IInvoice {
	network: Network;
	amountMsat?: bigint;
	timestamp: number;
	paymentHash: Buffer;
	paymentSecret?: Buffer;
	description?: string;
	descriptionHash?: Buffer;
	payeeNodeKey?: Buffer;
	expiry?: number;
	minFinalCltvExpiry?: number;
	fallbackAddress?: IFallbackAddress;
	routingHints?: IRoutingHintHop[][];
	blindedPaths?: IBlindedPaymentPath[];
	featureBits?: FeatureFlags;
	metadata?: Buffer;
	signature: Buffer;
	recoveredPubkey?: Buffer;
	unknownTags?: Array<{ type: number; words: number[] }>;
}

/** Options for creating/encoding a new invoice. */
export interface IInvoiceCreationOptions {
	network: Network;
	amountMsat?: bigint;
	timestamp?: number;
	paymentHash: Buffer;
	paymentSecret?: Buffer;
	description?: string;
	descriptionHash?: Buffer;
	expiry?: number;
	minFinalCltvExpiry?: number;
	fallbackAddress?: IFallbackAddress;
	routingHints?: IRoutingHintHop[][];
	blindedPaths?: IBlindedPaymentPath[];
	featureBits?: FeatureFlags;
	metadata?: Buffer;
	payeeNodeKey?: Buffer;
	privateKey: Buffer;
}

/** Default invoice expiry in seconds (1 hour). */
export const DEFAULT_EXPIRY = 3600;

/** Default min_final_cltv_expiry_delta in blocks. */
export const DEFAULT_MIN_FINAL_CLTV_EXPIRY = 40;

/** Maximum length for bech32 encoding. */
export const BECH32_MAX_LIMIT = 65535;

/** Number of 5-bit words used for the timestamp. */
export const TIMESTAMP_WORDS = 7;

/** Number of 5-bit words used for the signature (65 bytes = 104 words). */
export const SIGNATURE_WORDS = 104;

/** Bytes per routing hint hop entry. */
export const ROUTING_HOP_BYTES = 51;
