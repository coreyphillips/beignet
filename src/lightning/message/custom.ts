/**
 * Beignet-to-beignet custom peer messaging (issue #546, LFBW port #532
 * workstream 1E).
 *
 * Everything rides on ONE odd wire type in the BOLT 1 custom range
 * (>= 32768), so "it's OK to be odd" applies: LND, CLN, eclair and older
 * beignet peers silently ignore it, making every protocol built on top
 * fallback-safe by construction. Envelope layout:
 *
 *   [u16 protocolVersion][u16 subtype][payload...]
 *
 * Receivers must ignore unknown subtypes and versions (the node surfaces
 * them on the 'custom-message' event and refuses nothing); a payload that
 * fails to decode is logged and dropped without disconnecting the peer.
 */

/** Single odd message type carrying all beignet custom traffic. */
export const BEIGNET_CUSTOM_MESSAGE_TYPE = 44069;

export const BEIGNET_CUSTOM_PROTOCOL_VERSION = 1;

/**
 * Largest application payload one envelope can carry: BOLT 8 caps a Lightning
 * message at 65535 bytes, of which the wire type takes 2 and this envelope's
 * header 4. Enforced at encode so an oversized payload fails HERE, named,
 * instead of deep in the transport cipher after the caller thinks it sent
 * (issue #546 review).
 */
export const BEIGNET_CUSTOM_MAX_PAYLOAD = 65_535 - 2 - 4;

/**
 * Subtype registry. The numbers are RESERVED here ahead of the workstreams
 * that implement them (#532 phases 3 and 4) so no later protocol collides:
 * 1, 2, 4 and 5 belong to JIT receive, 16 to 22 to direct funding. 3
 * (LIQUIDITY_POLICY) and 20 (DIRECT_FUNDING_ABORT) are numbers the LFBW
 * fork declared but never used; they stay reserved and deliberately
 * unimplemented.
 */
export enum BeignetCustomSubtype {
	// ── JIT receive (#532 phase 3) ──
	JIT_RECEIVE_AUTHORIZATION = 1,
	JIT_RECEIVE_ACK = 2,
	/** Reserved, never implemented. */
	LIQUIDITY_POLICY = 3,
	/** A wallet asks what a JIT receive would cost and whether the LSP would
	 *  serve it right now; registers nothing on the LSP (issue #687). */
	JIT_RECEIVE_QUOTE = 4,
	JIT_RECEIVE_QUOTE_ACK = 5,
	// ── Direct funding (#532 phase 4) ──
	DIRECT_FUNDING_OFFER = 16,
	DIRECT_FUNDING_OFFER_ACK = 17,
	DIRECT_FUNDING_SIGN_REQUEST = 18,
	DIRECT_FUNDING_WITNESS = 19,
	/** Reserved, never implemented. */
	DIRECT_FUNDING_ABORT = 20,
	/** Receiver to sender after broadcast: reveals the preimage of the
	 *  receipt hash the sender's offer carried, a provable delivery
	 *  receipt. */
	DIRECT_FUNDING_RECEIPT = 21,
	/** Blind relay envelope: {to, t, p} from a sender, forwarded by the LSP
	 *  to a connected peer as {from, t, p} with `from` stamped by the LSP
	 *  itself, so neither party can spoof the other. Payloads are sealed to
	 *  the request key; the relay reads nothing. */
	DIRECT_FUNDING_RELAY = 22
}

export interface ICustomMessage {
	version: number;
	subtype: number;
	payload: Buffer;
}

export function encodeCustomMessage(
	subtype: number,
	payload: Buffer,
	version: number = BEIGNET_CUSTOM_PROTOCOL_VERSION
): Buffer {
	// writeUInt16BE would throw its own error, but only after the caller is
	// deep in a send; name the field at the boundary instead.
	if (!Number.isInteger(subtype) || subtype < 0 || subtype > 0xffff) {
		throw new Error(`custom message subtype out of range: ${subtype}`);
	}
	if (!Number.isInteger(version) || version < 0 || version > 0xffff) {
		throw new Error(`custom message version out of range: ${version}`);
	}
	if (payload.length > BEIGNET_CUSTOM_MAX_PAYLOAD) {
		throw new Error(
			`custom message payload ${payload.length} bytes exceeds the ` +
				`${BEIGNET_CUSTOM_MAX_PAYLOAD}-byte maximum (BOLT 8 message cap ` +
				'minus the wire type and envelope header)'
		);
	}
	const header = Buffer.alloc(4);
	header.writeUInt16BE(version, 0);
	header.writeUInt16BE(subtype, 2);
	return Buffer.concat([header, payload]);
}

export function decodeCustomMessage(data: Buffer): ICustomMessage {
	if (data.length < 4) {
		throw new Error('custom message too short');
	}
	return {
		version: data.readUInt16BE(0),
		subtype: data.readUInt16BE(2),
		payload: data.subarray(4)
	};
}
