/**
 * BOLT 7: Gossip message encoding/decoding.
 *
 * channel_announcement (type 256):
 *   [64: node_signature_1]
 *   [64: node_signature_2]
 *   [64: bitcoin_signature_1]
 *   [64: bitcoin_signature_2]
 *   [2: len]
 *   [len: features]
 *   [32: chain_hash]
 *   [8: short_channel_id]
 *   [33: node_id_1]
 *   [33: node_id_2]
 *   [33: bitcoin_key_1]
 *   [33: bitcoin_key_2]
 *
 * node_announcement (type 257):
 *   [64: signature]
 *   [2: flen]
 *   [flen: features]
 *   [4: timestamp]
 *   [33: node_id]
 *   [3: rgb_color]
 *   [32: alias]
 *   [2: addrlen]
 *   [addrlen: addresses]
 *
 * channel_update (type 258):
 *   [64: signature]
 *   [32: chain_hash]
 *   [8: short_channel_id]
 *   [4: timestamp]
 *   [1: message_flags]
 *   [1: channel_flags]
 *   [2: cltv_expiry_delta]
 *   [8: htlc_minimum_msat]
 *   [4: fee_base_msat]
 *   [4: fee_proportional_millionths]
 *   [8: htlc_maximum_msat] (if message_flags & 1)
 *
 * announcement_signatures (type 259):
 *   [32: channel_id]
 *   [8: short_channel_id]
 *   [64: node_signature]
 *   [64: bitcoin_signature]
 */

import {
	IChannelAnnouncementMessage,
	INodeAnnouncementMessage,
	IChannelUpdateMessage,
	IAnnouncementSignaturesMessage,
	INodeAddress,
	ADDRESS_TYPE_IPV4,
	ADDRESS_TYPE_IPV6,
	ADDRESS_TYPE_TORV3,
	MESSAGE_FLAG_HTLC_MAX,
	ANNOUNCEMENT_SIGNATURES_LENGTH
} from './types';

// ── Channel Announcement ────────────────────────────────────────────

const CHANNEL_ANNOUNCEMENT_MIN_LENGTH = 430; // 256 sigs + 2 flen + 0 features + 172 fixed = 430

export function encodeChannelAnnouncementMessage(
	msg: IChannelAnnouncementMessage
): Buffer {
	const flen = msg.features.length;
	const totalLen = 256 + 2 + flen + 172;
	const buf = Buffer.alloc(totalLen);
	let offset = 0;

	msg.nodeSignature1.copy(buf, offset);
	offset += 64;
	msg.nodeSignature2.copy(buf, offset);
	offset += 64;
	msg.bitcoinSignature1.copy(buf, offset);
	offset += 64;
	msg.bitcoinSignature2.copy(buf, offset);
	offset += 64;

	buf.writeUInt16BE(flen, offset);
	offset += 2;
	msg.features.copy(buf, offset);
	offset += flen;

	msg.chainHash.copy(buf, offset);
	offset += 32;
	msg.shortChannelId.copy(buf, offset);
	offset += 8;
	msg.nodeId1.copy(buf, offset);
	offset += 33;
	msg.nodeId2.copy(buf, offset);
	offset += 33;
	msg.bitcoinKey1.copy(buf, offset);
	offset += 33;
	msg.bitcoinKey2.copy(buf, offset);
	offset += 33;

	return buf;
}

export function decodeChannelAnnouncementMessage(
	payload: Buffer
): IChannelAnnouncementMessage {
	if (payload.length < CHANNEL_ANNOUNCEMENT_MIN_LENGTH) {
		throw new Error(
			`channel_announcement too short: need ${CHANNEL_ANNOUNCEMENT_MIN_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const nodeSignature1 = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;
	const nodeSignature2 = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;
	const bitcoinSignature1 = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;
	const bitcoinSignature2 = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;

	const flen = payload.readUInt16BE(offset);
	offset += 2;
	const features = Buffer.from(payload.subarray(offset, offset + flen));
	offset += flen;

	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const shortChannelId = Buffer.from(payload.subarray(offset, offset + 8));
	offset += 8;
	const nodeId1 = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const nodeId2 = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const bitcoinKey1 = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const bitcoinKey2 = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;

	return {
		nodeSignature1,
		nodeSignature2,
		bitcoinSignature1,
		bitcoinSignature2,
		features,
		chainHash,
		shortChannelId,
		nodeId1,
		nodeId2,
		bitcoinKey1,
		bitcoinKey2
	};
}

// ── Node Announcement ───────────────────────────────────────────────

const NODE_ANNOUNCEMENT_MIN_LENGTH = 140; // 64 + 2 + 0 + 4 + 33 + 3 + 32 + 2 = 140

export function encodeNodeAnnouncementMessage(
	msg: INodeAnnouncementMessage
): Buffer {
	const flen = msg.features.length;

	// Encode addresses first to know total length
	const addrParts: Buffer[] = [];
	for (const addr of msg.addresses) {
		addrParts.push(encodeNodeAddress(addr));
	}
	const addrBuf = Buffer.concat(addrParts);
	const addrlen = addrBuf.length;

	const totalLen = 64 + 2 + flen + 4 + 33 + 3 + 32 + 2 + addrlen;
	const buf = Buffer.alloc(totalLen);
	let offset = 0;

	msg.signature.copy(buf, offset);
	offset += 64;

	buf.writeUInt16BE(flen, offset);
	offset += 2;
	msg.features.copy(buf, offset);
	offset += flen;

	buf.writeUInt32BE(msg.timestamp, offset);
	offset += 4;
	msg.nodeId.copy(buf, offset);
	offset += 33;
	msg.rgbColor.copy(buf, offset);
	offset += 3;
	msg.alias.copy(buf, offset);
	offset += 32;

	buf.writeUInt16BE(addrlen, offset);
	offset += 2;
	addrBuf.copy(buf, offset);

	return buf;
}

export function decodeNodeAnnouncementMessage(
	payload: Buffer
): INodeAnnouncementMessage {
	if (payload.length < NODE_ANNOUNCEMENT_MIN_LENGTH) {
		throw new Error(
			`node_announcement too short: need ${NODE_ANNOUNCEMENT_MIN_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const signature = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;

	const flen = payload.readUInt16BE(offset);
	offset += 2;
	const features = Buffer.from(payload.subarray(offset, offset + flen));
	offset += flen;

	const timestamp = payload.readUInt32BE(offset);
	offset += 4;
	// BOLT 7: timestamps must be greater than zero. Reject zero-timestamp
	// announcements at parse time so they never reach the network graph
	// (defends against the zero-timestamp gossip DoS class).
	if (timestamp === 0) {
		throw new Error('node_announcement timestamp must be greater than zero');
	}
	const nodeId = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const rgbColor = Buffer.from(payload.subarray(offset, offset + 3));
	offset += 3;
	const alias = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;

	const addrlen = payload.readUInt16BE(offset);
	offset += 2;
	const addresses: INodeAddress[] = [];
	const addrEnd = offset + addrlen;
	while (offset < addrEnd) {
		const { address, bytesRead } = decodeNodeAddress(payload, offset);
		addresses.push(address);
		offset += bytesRead;
	}

	return { signature, features, timestamp, nodeId, rgbColor, alias, addresses };
}

// ── Channel Update ──────────────────────────────────────────────────

const CHANNEL_UPDATE_FIXED_LENGTH = 128; // 64 + 32 + 8 + 4 + 1 + 1 + 2 + 8 + 4 + 4 = 128

export function encodeChannelUpdateMessage(msg: IChannelUpdateMessage): Buffer {
	const hasMax = (msg.messageFlags & MESSAGE_FLAG_HTLC_MAX) !== 0;
	const totalLen = CHANNEL_UPDATE_FIXED_LENGTH + (hasMax ? 8 : 0);
	const buf = Buffer.alloc(totalLen);
	let offset = 0;

	msg.signature.copy(buf, offset);
	offset += 64;
	msg.chainHash.copy(buf, offset);
	offset += 32;
	msg.shortChannelId.copy(buf, offset);
	offset += 8;
	buf.writeUInt32BE(msg.timestamp, offset);
	offset += 4;
	buf[offset] = msg.messageFlags;
	offset += 1;
	buf[offset] = msg.channelFlags;
	offset += 1;
	buf.writeUInt16BE(msg.cltvExpiryDelta, offset);
	offset += 2;
	buf.writeBigUInt64BE(msg.htlcMinimumMsat, offset);
	offset += 8;
	buf.writeUInt32BE(msg.feeBaseMsat, offset);
	offset += 4;
	buf.writeUInt32BE(msg.feeProportionalMillionths, offset);
	offset += 4;

	if (hasMax && msg.htlcMaximumMsat !== undefined) {
		buf.writeBigUInt64BE(msg.htlcMaximumMsat, offset);
	}

	return buf;
}

export function decodeChannelUpdateMessage(
	payload: Buffer
): IChannelUpdateMessage {
	if (payload.length < CHANNEL_UPDATE_FIXED_LENGTH) {
		throw new Error(
			`channel_update too short: need ${CHANNEL_UPDATE_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const signature = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;
	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const shortChannelId = Buffer.from(payload.subarray(offset, offset + 8));
	offset += 8;
	const timestamp = payload.readUInt32BE(offset);
	offset += 4;
	// BOLT 7: channel_update timestamps must be greater than zero. Reject at
	// parse time so a zero-timestamp update never reaches the network graph
	// (defends against the zero-timestamp gossip DoS class).
	if (timestamp === 0) {
		throw new Error('channel_update timestamp must be greater than zero');
	}
	const messageFlags = payload[offset];
	offset += 1;
	const channelFlags = payload[offset];
	offset += 1;
	const cltvExpiryDelta = payload.readUInt16BE(offset);
	offset += 2;
	const htlcMinimumMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const feeBaseMsat = payload.readUInt32BE(offset);
	offset += 4;
	const feeProportionalMillionths = payload.readUInt32BE(offset);
	offset += 4;

	const result: IChannelUpdateMessage = {
		signature,
		chainHash,
		shortChannelId,
		timestamp,
		messageFlags,
		channelFlags,
		cltvExpiryDelta,
		htlcMinimumMsat,
		feeBaseMsat,
		feeProportionalMillionths
	};

	if (
		(messageFlags & MESSAGE_FLAG_HTLC_MAX) !== 0 &&
		payload.length >= offset + 8
	) {
		result.htlcMaximumMsat = payload.readBigUInt64BE(offset);
	}

	return result;
}

// ── Announcement Signatures ─────────────────────────────────────────

export function encodeAnnouncementSignaturesMessage(
	msg: IAnnouncementSignaturesMessage
): Buffer {
	const buf = Buffer.alloc(ANNOUNCEMENT_SIGNATURES_LENGTH);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	msg.shortChannelId.copy(buf, offset);
	offset += 8;
	msg.nodeSignature.copy(buf, offset);
	offset += 64;
	msg.bitcoinSignature.copy(buf, offset);

	return buf;
}

export function decodeAnnouncementSignaturesMessage(
	payload: Buffer
): IAnnouncementSignaturesMessage {
	if (payload.length < ANNOUNCEMENT_SIGNATURES_LENGTH) {
		throw new Error(
			`announcement_signatures too short: need ${ANNOUNCEMENT_SIGNATURES_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const shortChannelId = Buffer.from(payload.subarray(offset, offset + 8));
	offset += 8;
	const nodeSignature = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;
	const bitcoinSignature = Buffer.from(payload.subarray(offset, offset + 64));

	return { channelId, shortChannelId, nodeSignature, bitcoinSignature };
}

// ── Node Address ────────────────────────────────────────────────────

export function encodeNodeAddress(addr: INodeAddress): Buffer {
	switch (addr.type) {
		case ADDRESS_TYPE_IPV4: {
			const buf = Buffer.alloc(7);
			buf[0] = ADDRESS_TYPE_IPV4;
			const parts = addr.host.split('.');
			if (parts.length !== 4) {
				throw new Error(`Invalid IPv4 address: ${addr.host}`);
			}
			for (let i = 0; i < 4; i++) {
				buf[1 + i] = parseInt(parts[i], 10);
			}
			buf.writeUInt16BE(addr.port, 5);
			return buf;
		}
		case ADDRESS_TYPE_IPV6: {
			const buf = Buffer.alloc(19);
			buf[0] = ADDRESS_TYPE_IPV6;
			const groups = addr.host.split(':');
			if (groups.length !== 8) {
				throw new Error(
					`Invalid IPv6 address (must be fully expanded): ${addr.host}`
				);
			}
			for (let i = 0; i < 8; i++) {
				const val = parseInt(groups[i], 16);
				buf.writeUInt16BE(val, 1 + i * 2);
			}
			buf.writeUInt16BE(addr.port, 17);
			return buf;
		}
		case ADDRESS_TYPE_TORV3: {
			const buf = Buffer.alloc(38);
			buf[0] = ADDRESS_TYPE_TORV3;
			const hostBuf = Buffer.from(addr.host, 'hex');
			if (hostBuf.length !== 35) {
				throw new Error(
					`TorV3 host must be 35 bytes (70 hex chars), got ${hostBuf.length}`
				);
			}
			hostBuf.copy(buf, 1);
			buf.writeUInt16BE(addr.port, 36);
			return buf;
		}
		default:
			throw new Error(`Unknown address type: ${addr.type}`);
	}
}

export function decodeNodeAddress(
	buf: Buffer,
	offset: number
): { address: INodeAddress; bytesRead: number } {
	const type = buf[offset];
	switch (type) {
		case ADDRESS_TYPE_IPV4: {
			const host = `${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}.${
				buf[offset + 4]
			}`;
			const port = buf.readUInt16BE(offset + 5);
			return { address: { type, host, port }, bytesRead: 7 };
		}
		case ADDRESS_TYPE_IPV6: {
			const groups: string[] = [];
			for (let i = 0; i < 8; i++) {
				groups.push(
					buf
						.readUInt16BE(offset + 1 + i * 2)
						.toString(16)
						.padStart(4, '0')
				);
			}
			const host = groups.join(':');
			const port = buf.readUInt16BE(offset + 17);
			return { address: { type, host, port }, bytesRead: 19 };
		}
		case ADDRESS_TYPE_TORV3: {
			const host = buf.subarray(offset + 1, offset + 36).toString('hex');
			const port = buf.readUInt16BE(offset + 36);
			return { address: { type, host, port }, bytesRead: 38 };
		}
		default:
			throw new Error(`Unknown address type: ${type}`);
	}
}
