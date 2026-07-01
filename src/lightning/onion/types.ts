/**
 * BOLT 4: Onion Routing — Types & Constants
 */

// ── Interfaces ──────────────────────────────────────────────────────

export interface IHopPayload {
	shortChannelId?: Buffer;
	amountToForwardMsat: bigint;
	outgoingCltvValue: number;
	/** TLV type 8: payment_data — 32-byte payment secret (final hop only) */
	paymentSecret?: Buffer;
	/** TLV type 8: payment_data — total amount in msat for MPP (final hop only) */
	totalMsat?: bigint;
	/** TLV type 10: encrypted_recipient_data (for blinded hops) */
	encryptedRecipientData?: Buffer;
	/** TLV type 12: blinding_point (33-byte ephemeral key for blinded hops) */
	blindingPoint?: Buffer;
	/** Custom TLV records (e.g. keysend preimage at type 5482373484) */
	customRecords?: Map<number, Buffer>;
	/**
	 * Encode hint (BOLT 4): omit amt_to_forward/outgoing_cltv_value. Set for a
	 * blinded INTERMEDIATE hop, whose payload carries only encrypted_recipient_data
	 * (+ intro blinding_point); it derives amounts from its encrypted payment_relay.
	 */
	omitForwardAmounts?: boolean;
}

export interface IOnionPacket {
	version: number;
	ephemeralKey: Buffer;
	routingInfo: Buffer;
	hmac: Buffer;
}

export interface IProcessedOnion {
	hopPayload: IHopPayload;
	nextPacket: IOnionPacket;
	sharedSecret: Buffer;
}

export interface IOnionFailure {
	failureCode: number;
	failureData: Buffer;
}

export interface IHopKeys {
	rho: Buffer;
	mu: Buffer;
	pad: Buffer;
	um: Buffer;
	ammag: Buffer;
}

// ── Constants ───────────────────────────────────────────────────────

/** bLIP-0003 keysend TLV type — sender includes preimage in final hop */
export const KEYSEND_TLV_TYPE = 5482373484;

export const ONION_PACKET_LENGTH = 1366;
export const ROUTING_INFO_LENGTH = 1300;
export const ONION_VERSION = 0;
export const HOP_DATA_LEGACY_LENGTH = 32;

// ── Failure Codes ───────────────────────────────────────────────────

export const INVALID_ONION_VERSION = 0x8000 | 4;
export const INVALID_ONION_HMAC = 0x8000 | 5;
export const INVALID_ONION_KEY = 0x8000 | 6;
export const AMOUNT_BELOW_MINIMUM = 0x1000 | 11;
export const FEE_INSUFFICIENT = 0x1000 | 12;
export const INCORRECT_CLTV_EXPIRY = 0x1000 | 13;
export const EXPIRY_TOO_SOON = 0x1000 | 14;
export const UNKNOWN_NEXT_PEER = 0x4000 | 10;
export const TEMPORARY_CHANNEL_FAILURE = 0x1000 | 7;
export const INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS = 0x4000 | 15;
export const FINAL_INCORRECT_CLTV_EXPIRY = 17;
export const FINAL_INCORRECT_HTLC_AMOUNT = 18;
export const MPP_TIMEOUT = 0x4000 | 23;
export const TEMPORARY_NODE_FAILURE = 0x2000 | 2;
export const EXPIRY_TOO_FAR = 21;
export const CHANNEL_DISABLED = 0x1000 | 20;
export const PERMANENT_NODE_FAILURE = 0x4000 | 0x2000 | 2;
export const PERMANENT_CHANNEL_FAILURE = 0x4000 | 0x1000 | 8;
export const REQUIRED_NODE_FEATURE_MISSING = 0x4000 | 0x2000 | 3;
