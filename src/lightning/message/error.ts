/**
 * BOLT 1: `error` and `warning` message encoding/decoding.
 *
 * Error message format:
 *   [32: channel_id]
 *   [2: len]
 *   [len: data]
 *
 * Type: 17 (ERROR), 1 (WARNING)
 *
 * If channel_id is all zeros, the error applies to all channels
 * (or the connection itself).
 */

export const ALL_CHANNELS = Buffer.alloc(32, 0);

export interface IErrorMessage {
	channelId: Buffer;
	data: Buffer;
}

/**
 * Encode an `error` or `warning` message payload.
 * @param msg - Error message data
 * @returns Encoded payload (without the 2-byte message type prefix)
 */
export function encodeErrorMessage(msg: IErrorMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	const len = Buffer.alloc(2);
	len.writeUInt16BE(msg.data.length);

	return Buffer.concat([msg.channelId, len, msg.data]);
}

/**
 * Decode an `error` or `warning` message payload.
 * @param payload - Raw payload bytes (after the 2-byte type)
 * @returns Decoded error message
 */
export function decodeErrorMessage(payload: Buffer): IErrorMessage {
	if (payload.length < 34) {
		throw new Error('Error message too short: need at least 34 bytes');
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const len = payload.readUInt16BE(32);

	if (34 + len > payload.length) {
		throw new Error('Error: data length exceeds payload');
	}

	const data = Buffer.from(payload.subarray(34, 34 + len));

	return { channelId, data };
}

/**
 * Create an error message for a specific channel.
 * @param channelId - 32-byte channel ID
 * @param message - Human-readable error message
 * @returns Encoded error message payload
 */
export function createError(channelId: Buffer, message: string): IErrorMessage {
	return {
		channelId,
		data: Buffer.from(message, 'ascii')
	};
}

/**
 * Create an error message for all channels (connection-level error).
 * @param message - Human-readable error message
 * @returns Error message with all-zero channel ID
 */
export function createConnectionError(message: string): IErrorMessage {
	return {
		channelId: ALL_CHANNELS,
		data: Buffer.from(message, 'ascii')
	};
}

/**
 * Check if an error applies to all channels (connection-level).
 * @param msg - Error message to check
 * @returns True if channel_id is all zeros
 */
export function isConnectionError(msg: IErrorMessage): boolean {
	return msg.channelId.equals(ALL_CHANNELS);
}

/**
 * Get the human-readable error text.
 * @param msg - Error message
 * @returns Error text as string
 */
export function getErrorText(msg: IErrorMessage): string {
	return msg.data.toString('ascii');
}
