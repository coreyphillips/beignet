/**
 * Lightning Network message type IDs per BOLT specifications.
 *
 * Message types are 16-bit unsigned integers.
 * - Types in range 32768-65535 are for experimental use.
 * - Even-numbered types require understanding (unknown = close connection).
 * - Odd-numbered types can be ignored if unknown.
 */
export enum MessageType {
	// BOLT 1: Connection setup
	INIT = 16,
	ERROR = 17,
	WARNING = 1,
	PING = 18,
	PONG = 19,

	// BOLT 2: Channel management
	OPEN_CHANNEL = 32,
	ACCEPT_CHANNEL = 33,
	FUNDING_CREATED = 34,
	FUNDING_SIGNED = 35,
	CHANNEL_READY = 36,

	SHUTDOWN = 38,
	CLOSING_SIGNED = 39,

	// BOLT 2: option_simple_close simplified mutual close
	CLOSING_COMPLETE = 40,
	CLOSING_SIG = 41,

	// BOLT 2: Channel operation (HTLC)
	UPDATE_ADD_HTLC = 128,
	UPDATE_FULFILL_HTLC = 130,
	UPDATE_FAIL_HTLC = 131,
	UPDATE_FAIL_MALFORMED_HTLC = 135,

	COMMITMENT_SIGNED = 132,
	REVOKE_AND_ACK = 133,
	UPDATE_FEE = 134,

	CHANNEL_REESTABLISH = 136,

	// BOLT 2: Dual-funding (experimental)
	OPEN_CHANNEL2 = 64,
	ACCEPT_CHANNEL2 = 65,
	TX_ADD_INPUT = 66,
	TX_ADD_OUTPUT = 67,
	TX_REMOVE_INPUT = 68,
	TX_REMOVE_OUTPUT = 69,
	TX_COMPLETE = 70,
	TX_SIGNATURES = 71,
	TX_INIT_RBF = 72,
	TX_ACK_RBF = 73,
	TX_ABORT = 74,

	// BOLT 2: Splicing (lightning/bolts PR #1160). Note: `SPLICE` is the
	// `splice_init` message; type numbers per the merged spec.
	SPLICE = 80,
	SPLICE_ACK = 81,
	SPLICE_LOCKED = 77,

	// BOLT 2: Stfu (quiescence)
	STFU = 2,

	// BOLT 7: Gossip
	CHANNEL_ANNOUNCEMENT = 256,
	NODE_ANNOUNCEMENT = 257,
	CHANNEL_UPDATE = 258,
	ANNOUNCEMENT_SIGNATURES = 259,

	// BOLT 7: Gossip queries
	QUERY_SHORT_CHANNEL_IDS = 261,
	REPLY_SHORT_CHANNEL_IDS_END = 262,
	QUERY_CHANNEL_RANGE = 263,
	REPLY_CHANNEL_RANGE = 264,
	GOSSIP_TIMESTAMP_FILTER = 265,

	// BOLT 7: Onion messages
	ONION_MESSAGE = 513
}

/**
 * Check if a message type is even (required) or odd (optional).
 * Per BOLT 1: even types MUST be understood, odd types MAY be ignored.
 */
export function isRequiredMessageType(type: number): boolean {
	return type % 2 === 0;
}

/**
 * Get a human-readable name for a message type.
 */
export function messageTypeName(type: number): string {
	const name = MessageType[type];
	if (name) {
		return name;
	}
	return `UNKNOWN(${type})`;
}
