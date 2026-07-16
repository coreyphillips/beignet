/**
 * Beignet↔beignet custom peer messaging.
 *
 * Everything rides on ONE odd wire type in the custom range (>= 32768), so
 * BOLT 1 "it's OK to be odd" applies: LND/CLN/Eclair and older beignet peers
 * silently ignore it, making every protocol built on top fallback-safe by
 * construction. Envelope layout:
 *
 *   [u16 protocolVersion][u16 subtype][payload...]
 *
 * Unknown subtypes/versions must be ignored by receivers.
 */

/** Single odd message type carrying all beignet custom traffic. */
export const BEIGNET_CUSTOM_MESSAGE_TYPE = 44069;

export const BEIGNET_CUSTOM_PROTOCOL_VERSION = 1;

export enum BeignetCustomSubtype {
	// ── JIT receive (M3) ──
	JIT_RECEIVE_AUTHORIZATION = 1,
	JIT_RECEIVE_ACK = 2,
	LIQUIDITY_POLICY = 3,
	// ── Direct funding (M5) ──
	DIRECT_FUNDING_OFFER = 16,
	DIRECT_FUNDING_OFFER_ACK = 17,
	DIRECT_FUNDING_SIGN_REQUEST = 18,
	DIRECT_FUNDING_WITNESS = 19,
	DIRECT_FUNDING_ABORT = 20
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
	if (subtype < 0 || subtype > 0xffff) {
		throw new Error(`custom message subtype out of range: ${subtype}`);
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
