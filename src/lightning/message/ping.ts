/**
 * BOLT 1: Ping/Pong message encoding/decoding.
 *
 * Ping messages are used for connection liveness checking and
 * can also be used to generate traffic for keep-alive.
 *
 * PING (type 18):
 *   [2: num_pong_bytes]
 *   [2: byteslen]
 *   [byteslen: ignored]
 *
 * PONG (type 19):
 *   [2: byteslen]
 *   [byteslen: ignored]
 */

export interface IPingMessage {
	numPongBytes: number;
	byteslen: number;
}

export interface IPongMessage {
	byteslen: number;
}

/**
 * Encode a PING message payload.
 * @param numPongBytes - Number of bytes the pong response should contain (0-65531)
 * @param paddingLen - Length of ignored padding bytes in the ping
 */
export function encodePingMessage(
	numPongBytes: number,
	paddingLen = 0
): Buffer {
	if (numPongBytes < 0 || numPongBytes > 65531) {
		throw new Error(`num_pong_bytes must be 0-65531, got ${numPongBytes}`);
	}
	if (paddingLen < 0 || paddingLen > 65531) {
		throw new Error(`Padding length must be 0-65531, got ${paddingLen}`);
	}

	const buf = Buffer.alloc(4 + paddingLen);
	buf.writeUInt16BE(numPongBytes, 0);
	buf.writeUInt16BE(paddingLen, 2);
	// Padding bytes are left as zeros
	return buf;
}

/**
 * Decode a PING message payload.
 */
export function decodePingMessage(payload: Buffer): IPingMessage {
	if (payload.length < 4) {
		throw new Error('Ping message too short: need at least 4 bytes');
	}

	const numPongBytes = payload.readUInt16BE(0);
	const byteslen = payload.readUInt16BE(2);

	if (payload.length < 4 + byteslen) {
		throw new Error(
			`Ping message truncated: expected ${4 + byteslen} bytes, got ${
				payload.length
			}`
		);
	}

	return { numPongBytes, byteslen };
}

/**
 * Encode a PONG message payload.
 * @param byteslen - Number of ignored bytes to include (must match ping's num_pong_bytes if ≤65531)
 */
export function encodePongMessage(byteslen: number): Buffer {
	if (byteslen < 0 || byteslen > 65531) {
		throw new Error(`byteslen must be 0-65531, got ${byteslen}`);
	}

	const buf = Buffer.alloc(2 + byteslen);
	buf.writeUInt16BE(byteslen, 0);
	// Padding bytes are left as zeros
	return buf;
}

/**
 * Decode a PONG message payload.
 */
export function decodePongMessage(payload: Buffer): IPongMessage {
	if (payload.length < 2) {
		throw new Error('Pong message too short: need at least 2 bytes');
	}

	const byteslen = payload.readUInt16BE(0);

	if (payload.length < 2 + byteslen) {
		throw new Error(
			`Pong message truncated: expected ${2 + byteslen} bytes, got ${
				payload.length
			}`
		);
	}

	return { byteslen };
}
