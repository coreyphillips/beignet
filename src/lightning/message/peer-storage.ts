/**
 * BOLT 1: Peer storage (option_provide_storage) message encode/decode.
 *
 * Message type 7: peer_storage, a small opaque blob a peer asks us to hold.
 * Message type 9: peer_storage_retrieval, the held blob returned on reconnect.
 * Both share the same layout:
 *   [2: length]
 *   [length: blob]
 */

/**
 * Maximum blob size per BOLT 1: the 65535-byte message payload minus the
 * 2-byte type and the 2-byte length prefix.
 */
export const PEER_STORAGE_MAX_BYTES = 65531;

export interface IPeerStorageMessage {
	blob: Buffer;
}

function encodeBlobMessage(msg: IPeerStorageMessage, name: string): Buffer {
	if (msg.blob.length > PEER_STORAGE_MAX_BYTES) {
		throw new Error(
			`${name} blob too large: ${msg.blob.length} > ${PEER_STORAGE_MAX_BYTES} bytes`
		);
	}
	const buf = Buffer.alloc(2 + msg.blob.length);
	buf.writeUInt16BE(msg.blob.length, 0);
	msg.blob.copy(buf, 2);
	return buf;
}

function decodeBlobMessage(payload: Buffer, name: string): IPeerStorageMessage {
	if (payload.length < 2) {
		throw new Error(`${name} message too short`);
	}
	const length = payload.readUInt16BE(0);
	if (length > PEER_STORAGE_MAX_BYTES) {
		throw new Error(
			`${name} blob too large: ${length} > ${PEER_STORAGE_MAX_BYTES} bytes`
		);
	}
	if (payload.length < 2 + length) {
		throw new Error(`${name} truncated: declared ${length} bytes`);
	}
	return { blob: Buffer.from(payload.subarray(2, 2 + length)) };
}

export function encodePeerStorageMessage(msg: IPeerStorageMessage): Buffer {
	return encodeBlobMessage(msg, 'peer_storage');
}

export function decodePeerStorageMessage(payload: Buffer): IPeerStorageMessage {
	return decodeBlobMessage(payload, 'peer_storage');
}

export function encodePeerStorageRetrievalMessage(
	msg: IPeerStorageMessage
): Buffer {
	return encodeBlobMessage(msg, 'peer_storage_retrieval');
}

export function decodePeerStorageRetrievalMessage(
	payload: Buffer
): IPeerStorageMessage {
	return decodeBlobMessage(payload, 'peer_storage_retrieval');
}
