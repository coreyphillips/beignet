/**
 * BOLT 7.5: Onion Message Codec
 *
 * Encode/decode for message type 513 (onion_message).
 * Wire format:
 *   [33: blinding_point] [2: len] [len: onion_routing_packet]
 *
 * The onion_routing_packet is always 1366 bytes for onion messages.
 */

import { IOnionMessage, ONION_MESSAGE_PACKET_LENGTH } from './types';
import {
	IOnionMessagePayload,
	TLV_ENCRYPTED_RECIPIENT_DATA,
	TLV_REPLY_PATH,
	TLV_MESSAGE_DATA_BASE
} from './types';
import { IBlindedPath, IBlindedHop } from '../onion/blinded-path';
import { encodeBigSize, decodeBigSize } from '../message/codec';

/**
 * Encode an onion_message for the wire (type 513 payload, excluding the 2-byte type prefix).
 * Format: blinding_point(33) + len(2) + onion_routing_packet(1366)
 */
export function encodeOnionMessage(msg: IOnionMessage): Buffer {
	if (msg.blindingPoint.length !== 33) {
		throw new Error(
			`blinding_point must be 33 bytes, got ${msg.blindingPoint.length}`
		);
	}
	if (msg.onionRoutingPacket.length !== ONION_MESSAGE_PACKET_LENGTH) {
		throw new Error(
			`onion_routing_packet must be ${ONION_MESSAGE_PACKET_LENGTH} bytes, got ${msg.onionRoutingPacket.length}`
		);
	}

	const buf = Buffer.alloc(33 + 2 + ONION_MESSAGE_PACKET_LENGTH);
	msg.blindingPoint.copy(buf, 0);
	buf.writeUInt16BE(ONION_MESSAGE_PACKET_LENGTH, 33);
	msg.onionRoutingPacket.copy(buf, 35);
	return buf;
}

/**
 * Decode an onion_message from the wire (type 513 payload, excluding the 2-byte type prefix).
 */
export function decodeOnionMessage(buf: Buffer): IOnionMessage {
	if (buf.length < 35) {
		throw new Error(
			`onion_message too short: ${buf.length} bytes (minimum 35)`
		);
	}

	const blindingPoint = Buffer.from(buf.subarray(0, 33));
	const len = buf.readUInt16BE(33);

	if (buf.length < 35 + len) {
		throw new Error(
			`onion_message packet truncated: expected ${35 + len} bytes, got ${
				buf.length
			}`
		);
	}

	const onionRoutingPacket = Buffer.from(buf.subarray(35, 35 + len));

	return { blindingPoint, onionRoutingPacket };
}

/**
 * Encode a single TLV record: BigSize type + BigSize length + value.
 */
function encodeTlvRecord(type: number, value: Buffer): Buffer {
	const typeBytes = encodeBigSize(BigInt(type));
	const lengthBytes = encodeBigSize(BigInt(value.length));
	return Buffer.concat([typeBytes, lengthBytes, value]);
}

/**
 * Encode a blinded path for the reply_path TLV.
 * Format:
 *   [33: introduction_node_id]
 *   [33: blinding_point]
 *   [1: num_hops]
 *   For each hop:
 *     [33: blinded_node_id]
 *     [2: encrypted_data_len]
 *     [encrypted_data_len: encrypted_data]
 */
export function encodeBlindedPathTlv(path: IBlindedPath): Buffer {
	const parts: Buffer[] = [];

	// introduction_node_id (33 bytes)
	parts.push(path.introductionNodeId);

	// blinding_point (33 bytes)
	parts.push(path.blindingPoint);

	// num_hops (1 byte)
	const numHops = Buffer.alloc(1);
	numHops[0] = path.blindedHops.length;
	parts.push(numHops);

	// Each hop: blinded_node_id (33) + encrypted_data_len (2) + encrypted_data
	for (const hop of path.blindedHops) {
		parts.push(hop.blindedNodeId);
		const lenBuf = Buffer.alloc(2);
		lenBuf.writeUInt16BE(hop.encryptedData.length, 0);
		parts.push(lenBuf);
		parts.push(hop.encryptedData);
	}

	return Buffer.concat(parts);
}

/**
 * Decode a blinded path from a reply_path TLV value.
 */
export function decodeBlindedPathTlv(buf: Buffer): IBlindedPath {
	let offset = 0;

	if (buf.length < 67) {
		// 33 + 33 + 1
		throw new Error('reply_path TLV too short');
	}

	const introductionNodeId = Buffer.from(buf.subarray(offset, offset + 33));
	offset += 33;

	const blindingPoint = Buffer.from(buf.subarray(offset, offset + 33));
	offset += 33;

	const numHops = buf[offset++];
	const blindedHops: IBlindedHop[] = [];

	for (let i = 0; i < numHops; i++) {
		if (offset + 33 + 2 > buf.length) {
			throw new Error('reply_path TLV truncated at hop');
		}
		const blindedNodeId = Buffer.from(buf.subarray(offset, offset + 33));
		offset += 33;

		const encDataLen = buf.readUInt16BE(offset);
		offset += 2;

		if (offset + encDataLen > buf.length) {
			throw new Error('reply_path TLV truncated at hop encrypted data');
		}
		const encryptedData = Buffer.from(
			buf.subarray(offset, offset + encDataLen)
		);
		offset += encDataLen;

		blindedHops.push({ blindedNodeId, encryptedData });
	}

	return { introductionNodeId, blindingPoint, blindedHops };
}

/**
 * Encode an onion message payload as a TLV stream suitable for inclusion
 * in an onion packet hop payload.
 *
 * TLV records (sorted by type):
 *   type 2: reply_path (optional)
 *   type 4: encrypted_recipient_data (optional)
 *   type 64+: message TLVs (application data)
 */
export function encodeOnionMessagePayload(
	payload: IOnionMessagePayload
): Buffer {
	const records: Buffer[] = [];

	// Collect all TLV records with their types for sorting
	const tlvs: { type: number; data: Buffer }[] = [];

	// TLV type 2: reply_path
	if (payload.replyPath) {
		const replyPathData = encodeBlindedPathTlv(payload.replyPath);
		tlvs.push({ type: TLV_REPLY_PATH, data: replyPathData });
	}

	// TLV type 4: encrypted_recipient_data
	if (payload.encryptedRecipientData) {
		tlvs.push({
			type: TLV_ENCRYPTED_RECIPIENT_DATA,
			data: payload.encryptedRecipientData
		});
	}

	// Message TLVs (application data, type >= 64)
	for (const [type, data] of payload.messageTlvs) {
		if (type < TLV_MESSAGE_DATA_BASE) {
			throw new Error(
				`Message TLV type ${type} is below minimum ${TLV_MESSAGE_DATA_BASE}`
			);
		}
		tlvs.push({ type, data });
	}

	// Sort by type (BOLT requirement: TLVs must be in ascending order)
	tlvs.sort((a, b) => a.type - b.type);

	for (const tlv of tlvs) {
		records.push(encodeTlvRecord(tlv.type, tlv.data));
	}

	const tlvData = Buffer.concat(records);

	// Wrap in BigSize length prefix (same format as payment hop payloads)
	const lengthPrefix = encodeBigSize(BigInt(tlvData.length));
	return Buffer.concat([lengthPrefix, tlvData]);
}

/**
 * Decode an onion message payload from a TLV stream.
 */
export function decodeOnionMessagePayload(
	buf: Buffer,
	offset = 0
): { payload: IOnionMessagePayload; bytesRead: number } {
	const startOffset = offset;

	// Read payload length
	const { value: payloadLength, bytesRead: lenBytes } = decodeBigSize(
		buf,
		offset
	);
	offset += lenBytes;

	const payloadEnd = offset + Number(payloadLength);
	if (payloadEnd > buf.length) {
		throw new Error('Onion message payload extends beyond buffer');
	}

	const payload: IOnionMessagePayload = {
		messageTlvs: new Map()
	};

	while (offset < payloadEnd) {
		// Read TLV type
		const typeResult = decodeBigSize(buf, offset);
		offset += typeResult.bytesRead;
		const tlvType = Number(typeResult.value);

		// Read TLV length
		const lengthResult = decodeBigSize(buf, offset);
		offset += lengthResult.bytesRead;
		const tlvLength = Number(lengthResult.value);

		const tlvValue = Buffer.from(buf.subarray(offset, offset + tlvLength));
		offset += tlvLength;

		switch (tlvType) {
			case TLV_REPLY_PATH:
				payload.replyPath = decodeBlindedPathTlv(tlvValue);
				break;
			case TLV_ENCRYPTED_RECIPIENT_DATA:
				payload.encryptedRecipientData = tlvValue;
				break;
			default:
				if (tlvType >= TLV_MESSAGE_DATA_BASE) {
					payload.messageTlvs.set(tlvType, tlvValue);
				} else if (tlvType % 2 === 0) {
					// Unknown even TLV type — required but unrecognized
					throw new Error(
						`Unknown required TLV type ${tlvType} in onion message payload`
					);
				}
				// Odd unknown types are silently ignored
				break;
		}
	}

	return { payload, bytesRead: offset - startOffset };
}
