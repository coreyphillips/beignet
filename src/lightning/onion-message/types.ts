/**
 * BOLT 7.5: Onion Message Types
 *
 * Onion messages (type 513) allow nodes to communicate arbitrary data
 * through the Lightning Network without requiring channels or HTLCs.
 * They use the same Sphinx onion routing as payments but with 1300-byte
 * payloads and no payment-specific fields.
 */

import { IBlindedPath } from '../onion/blinded-path';

// ── Constants ───────────────────────────────────────────────────────

/** Onion message type ID (BOLT 7, odd = can be ignored if unsupported) */
export const ONION_MESSAGE_TYPE = 513;

/** Onion packet length for onion messages: version(1) + ephemeral_key(33) + routing_info(1300) + hmac(32) */
export const ONION_MESSAGE_PACKET_LENGTH = 1366;

/** Routing info length within the onion packet */
export const ONION_MESSAGE_ROUTING_INFO_LENGTH = 1300;

// ── TLV Type Constants for Onion Message Payloads ────────────────

/** TLV type for encrypted_recipient_data (same as payment TLV type 10) */
export const TLV_ENCRYPTED_RECIPIENT_DATA = 4;

/** TLV type for reply_path */
export const TLV_REPLY_PATH = 2;

/** TLV type for message TLV namespace (application data, starts at 64+) */
export const TLV_MESSAGE_DATA_BASE = 64;

// ── Interfaces ──────────────────────────────────────────────────────

/**
 * Wire-format onion_message (type 513).
 * Fields: blinding_point (33 bytes) + len + onion_routing_packet (1366 bytes)
 */
export interface IOnionMessage {
	/** Ephemeral blinding point for route blinding (33-byte compressed pubkey) */
	blindingPoint: Buffer;
	/** Sphinx onion routing packet (1366 bytes) */
	onionRoutingPacket: Buffer;
}

/**
 * Decoded payload for an onion message hop.
 * Intermediate hops only see encrypted_recipient_data.
 * Final hops can see reply_path and message TLVs.
 */
export interface IOnionMessagePayload {
	/** Encrypted data for blinded hops (TLV type 4) */
	encryptedRecipientData?: Buffer;
	/** Optional reply path for the recipient to respond (TLV type 2) */
	replyPath?: IBlindedPath;
	/** Application-level message TLVs keyed by TLV type number */
	messageTlvs: Map<number, Buffer>;
}

/**
 * Result of processing an onion message at an intermediate node.
 */
export interface IOnionMessageForward {
	type: 'forward';
	/** Next hop node ID to forward to */
	nextNodeId: Buffer;
	/** Next blinding key for the next hop */
	nextBlindingKey: Buffer;
	/** Onion message to forward (re-wrapped) */
	nextOnionMessage: IOnionMessage;
}

/**
 * Result of processing an onion message at the final destination.
 */
export interface IOnionMessageDelivery {
	type: 'delivery';
	/** Decoded message payload with application data */
	payload: IOnionMessagePayload;
	/**
	 * path_id from the decrypted final-hop encrypted_recipient_data (BOLT 4),
	 * when present. The recipient verifies it matches a path_id it published;
	 * absent when the final hop carried no verifiable blinded data.
	 */
	pathId?: Buffer;
}

/** Union type for onion message processing result */
export type OnionMessageProcessResult =
	| IOnionMessageForward
	| IOnionMessageDelivery;

/**
 * Options for sending an onion message.
 */
export interface ISendOnionMessageOptions {
	/** Include a reply path so the recipient can respond */
	replyPath?: IBlindedPath;
	/**
	 * BOLT 4 path_id embedded in the final hop's encrypted recipient data of a
	 * blinded send: the recipient's delivery surfaces it, letting it verify
	 * the message arrived over a path the sender was given.
	 */
	pathId?: Buffer;
}

/**
 * Rate limiting configuration for onion messages.
 */
export interface IRateLimitConfig {
	/** Maximum messages per window (default 10) */
	maxPerWindow: number;
	/** Window duration in milliseconds (default 60000 = 1 minute) */
	windowMs: number;
}
