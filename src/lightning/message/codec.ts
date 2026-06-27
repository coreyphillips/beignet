/**
 * BOLT 1: BigSize encoding/decoding and Lightning message framing.
 *
 * BigSize is a variable-length unsigned integer encoding used throughout
 * the Lightning protocol. It is similar to Bitcoin's CompactSize but
 * uses big-endian byte order.
 *
 * Encoding:
 *   0x00..0xfc        -> 1 byte (value itself)
 *   0xfd..0xffff      -> 3 bytes (0xfd prefix + 2-byte BE value)
 *   0x10000..0xffffffff -> 5 bytes (0xfe prefix + 4-byte BE value)
 *   0x100000000+       -> 9 bytes (0xff prefix + 8-byte BE value)
 */

/**
 * Encode a number as a BigSize variable-length integer.
 * @param value - Non-negative integer to encode
 * @returns Buffer containing the BigSize encoding
 */
export function encodeBigSize(value: bigint): Buffer {
	if (value < 0n) {
		throw new Error('BigSize value must be non-negative');
	}

	if (value < 0xfdn) {
		const buf = Buffer.alloc(1);
		buf[0] = Number(value);
		return buf;
	}

	if (value < 0x10000n) {
		const buf = Buffer.alloc(3);
		buf[0] = 0xfd;
		buf.writeUInt16BE(Number(value), 1);
		return buf;
	}

	if (value < 0x100000000n) {
		const buf = Buffer.alloc(5);
		buf[0] = 0xfe;
		buf.writeUInt32BE(Number(value), 1);
		return buf;
	}

	const buf = Buffer.alloc(9);
	buf[0] = 0xff;
	buf.writeBigUInt64BE(value, 1);
	return buf;
}

/**
 * Result of decoding a BigSize value, including how many bytes were consumed.
 */
export interface IBigSizeResult {
	value: bigint;
	bytesRead: number;
}

/**
 * Decode a BigSize variable-length integer from a buffer.
 * @param data - Buffer to read from
 * @param offset - Starting offset in the buffer
 * @returns Decoded value and number of bytes consumed
 */
export function decodeBigSize(data: Buffer, offset = 0): IBigSizeResult {
	if (offset >= data.length) {
		throw new Error('BigSize: unexpected end of data');
	}

	const first = data[offset];

	if (first < 0xfd) {
		return { value: BigInt(first), bytesRead: 1 };
	}

	if (first === 0xfd) {
		if (offset + 3 > data.length) {
			throw new Error('BigSize: unexpected end of data for 2-byte value');
		}
		const value = BigInt(data.readUInt16BE(offset + 1));
		if (value < 0xfdn) {
			throw new Error(`BigSize: non-canonical encoding for value ${value}`);
		}
		return { value, bytesRead: 3 };
	}

	if (first === 0xfe) {
		if (offset + 5 > data.length) {
			throw new Error('BigSize: unexpected end of data for 4-byte value');
		}
		const value = BigInt(data.readUInt32BE(offset + 1));
		if (value < 0x10000n) {
			throw new Error(`BigSize: non-canonical encoding for value ${value}`);
		}
		return { value, bytesRead: 5 };
	}

	// first === 0xff
	if (offset + 9 > data.length) {
		throw new Error('BigSize: unexpected end of data for 8-byte value');
	}
	const value = data.readBigUInt64BE(offset + 1);
	if (value < 0x100000000n) {
		throw new Error(`BigSize: non-canonical encoding for value ${value}`);
	}
	return { value, bytesRead: 9 };
}

/**
 * Encode a Lightning message with the standard framing format.
 * Format: [2-byte type (BE)][payload]
 * @param type - Message type ID (0-65535)
 * @param payload - Message payload
 * @returns Framed message buffer
 */
export function encodeMessage(type: number, payload: Buffer): Buffer {
	if (type < 0 || type > 0xffff) {
		throw new Error(`Message type must be 0-65535, got ${type}`);
	}
	const header = Buffer.alloc(2);
	header.writeUInt16BE(type);
	return Buffer.concat([header, payload]);
}

/**
 * Decoded Lightning message.
 */
export interface IDecodedMessage {
	type: number;
	payload: Buffer;
}

/**
 * Decode a Lightning message from a buffer.
 * Format: [2-byte type (BE)][payload]
 * @param data - Raw message bytes
 * @returns Decoded message type and payload
 */
export function decodeMessage(data: Buffer): IDecodedMessage {
	if (data.length < 2) {
		throw new Error('Message too short: must be at least 2 bytes');
	}
	const type = data.readUInt16BE(0);
	const payload = data.subarray(2);
	return { type, payload };
}
