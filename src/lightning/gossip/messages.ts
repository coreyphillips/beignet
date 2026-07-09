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
	ADDRESS_TYPE_TORV2,
	ADDRESS_TYPE_TORV3,
	ADDRESS_TYPE_DNS,
	MESSAGE_FLAG_HTLC_MAX,
	ANNOUNCEMENT_SIGNATURES_LENGTH,
	NODE_ANN_TLV_LEASE_RATES,
	encodeLeaseRates,
	decodeLeaseRates
} from './types';
import {
	encodeTlvStream,
	decodeTlvStream,
	findTlvRecord
} from '../message/tlv';

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

	// Optional trailing node_ann_tlvs (BOLT 7). Currently: option_will_fund
	// lease rates (type 1) for liquidity ads.
	const tlvBuf = msg.leaseRates
		? encodeTlvStream([
				{
					type: NODE_ANN_TLV_LEASE_RATES,
					value: encodeLeaseRates(msg.leaseRates)
				}
		  ])
		: Buffer.alloc(0);

	const totalLen =
		64 + 2 + flen + 4 + 33 + 3 + 32 + 2 + addrlen + tlvBuf.length;
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
	offset += addrlen;

	tlvBuf.copy(buf, offset);

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
	offset = addrEnd;

	const result: INodeAnnouncementMessage = {
		signature,
		features,
		timestamp,
		nodeId,
		rgbColor,
		alias,
		addresses
	};

	// Optional trailing node_ann_tlvs (BOLT 7): extract option_will_fund lease
	// rates if present; tolerate/ignore any other trailing TLV records.
	if (offset < payload.length) {
		try {
			const { records } = decodeTlvStream(payload, offset);
			const leaseVal = findTlvRecord(records, NODE_ANN_TLV_LEASE_RATES);
			if (leaseVal) {
				result.leaseRates = decodeLeaseRates(leaseVal);
			}
		} catch {
			/* ignore malformed trailing TLVs */
		}
	}

	return result;
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
		case ADDRESS_TYPE_TORV2: {
			// Deprecated, but still appears in the wild; round-trip it so relayed
			// announcements re-encode byte-identically to the signed payload.
			const buf = Buffer.alloc(13);
			buf[0] = ADDRESS_TYPE_TORV2;
			const hostBuf = Buffer.from(addr.host, 'hex');
			if (hostBuf.length !== 10) {
				throw new Error(
					`TorV2 host must be 10 bytes (20 hex chars), got ${hostBuf.length}`
				);
			}
			hostBuf.copy(buf, 1);
			buf.writeUInt16BE(addr.port, 11);
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
		case ADDRESS_TYPE_DNS: {
			const hostBuf = Buffer.from(addr.host, 'ascii');
			if (hostBuf.length < 1 || hostBuf.length > 255) {
				throw new Error(`DNS hostname must be 1-255 bytes: ${addr.host}`);
			}
			const buf = Buffer.alloc(1 + 1 + hostBuf.length + 2);
			buf[0] = ADDRESS_TYPE_DNS;
			buf[1] = hostBuf.length;
			hostBuf.copy(buf, 2);
			buf.writeUInt16BE(addr.port, 2 + hostBuf.length);
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
		case ADDRESS_TYPE_TORV2: {
			const host = buf.subarray(offset + 1, offset + 11).toString('hex');
			const port = buf.readUInt16BE(offset + 11);
			return { address: { type, host, port }, bytesRead: 13 };
		}
		case ADDRESS_TYPE_TORV3: {
			const host = buf.subarray(offset + 1, offset + 36).toString('hex');
			const port = buf.readUInt16BE(offset + 36);
			return { address: { type, host, port }, bytesRead: 38 };
		}
		case ADDRESS_TYPE_DNS: {
			const len = buf[offset + 1];
			const host = buf.subarray(offset + 2, offset + 2 + len).toString('ascii');
			const port = buf.readUInt16BE(offset + 2 + len);
			return { address: { type, host, port }, bytesRead: 2 + len + 2 };
		}
		default:
			throw new Error(`Unknown address type: ${type}`);
	}
}

// ── Announced Address Parsing ───────────────────────────────────────

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function base32Decode(input: string): Buffer {
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const ch of input) {
		const idx = BASE32_ALPHABET.indexOf(ch);
		if (idx === -1) {
			throw new Error(`Invalid base32 character: ${ch}`);
		}
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	return Buffer.from(out);
}

function expandIpv6(host: string): string {
	let groups: string[];
	const doubleColon = host.indexOf('::');
	if (doubleColon !== -1) {
		if (host.indexOf('::', doubleColon + 1) !== -1) {
			throw new Error(`Invalid IPv6 address: ${host}`);
		}
		const head = host
			.slice(0, doubleColon)
			.split(':')
			.filter((g) => g.length > 0);
		const tail = host
			.slice(doubleColon + 2)
			.split(':')
			.filter((g) => g.length > 0);
		const missing = 8 - head.length - tail.length;
		if (missing < 1) {
			throw new Error(`Invalid IPv6 address: ${host}`);
		}
		groups = [...head, ...new Array(missing).fill('0'), ...tail];
	} else {
		groups = host.split(':');
	}
	if (
		groups.length !== 8 ||
		groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))
	) {
		throw new Error(`Invalid IPv6 address: ${host}`);
	}
	return groups.map((g) => g.toLowerCase().padStart(4, '0')).join(':');
}

/** Verify the 2-byte checksum embedded in a Tor v3 onion address:
 *  sha3_256(".onion checksum" || pubkey || version)[0..1]. Uses the runtime's
 *  sha3-256 if available; silently skipped where it is not (e.g. browsers),
 *  since a bad checksum only makes the address unreachable, not unsafe. */
function verifyOnionV3Checksum(decoded: Buffer, host: string): void {
	let digest: Buffer;
	try {
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		const { createHash } = require('crypto');
		digest = createHash('sha3-256')
			.update(Buffer.from('.onion checksum', 'ascii'))
			.update(decoded.subarray(0, 32))
			.update(decoded.subarray(34, 35))
			.digest();
	} catch {
		return;
	}
	if (!digest.subarray(0, 2).equals(decoded.subarray(32, 34))) {
		throw new Error(`Invalid Tor v3 onion address checksum: ${host}`);
	}
}

/**
 * Parse a user-supplied "host:port" string into a BOLT 7 address descriptor
 * for our own node_announcement. Supports IPv4, IPv6 ("[addr]:port",
 * compressed forms expanded), Tor v3 ".onion" (56-char base32 label,
 * decoded to the 35-byte descriptor payload) and DNS hostnames (type 5).
 * Port defaults to 9735 when omitted.
 */
export function parseAnnouncedAddress(input: string): INodeAddress {
	const trimmed = input.trim();
	let host: string;
	let portStr: string | undefined;

	if (trimmed.startsWith('[')) {
		const end = trimmed.indexOf(']');
		if (end === -1) {
			throw new Error(`Invalid address "${input}": missing closing ']'`);
		}
		host = trimmed.slice(1, end);
		const rest = trimmed.slice(end + 1);
		if (rest.startsWith(':')) {
			portStr = rest.slice(1);
		} else if (rest.length > 0) {
			throw new Error(`Invalid address "${input}": expected [host]:port`);
		}
	} else {
		const lastColon = trimmed.lastIndexOf(':');
		if (lastColon !== -1 && trimmed.indexOf(':') !== lastColon) {
			throw new Error(
				`Invalid address "${input}": IPv6 addresses must be written as [host]:port`
			);
		}
		if (lastColon === -1) {
			host = trimmed;
		} else {
			host = trimmed.slice(0, lastColon);
			portStr = trimmed.slice(lastColon + 1);
		}
	}

	const port = portStr === undefined ? 9735 : Number(portStr);
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		throw new Error(`Invalid port in address "${input}"`);
	}
	if (!host) {
		throw new Error(`Invalid address "${input}": empty host`);
	}

	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
		if (host.split('.').some((o) => Number(o) > 255)) {
			throw new Error(`Invalid IPv4 address: ${host}`);
		}
		return { type: ADDRESS_TYPE_IPV4, host, port };
	}

	if (host.includes(':')) {
		return { type: ADDRESS_TYPE_IPV6, host: expandIpv6(host), port };
	}

	const lower = host.toLowerCase();
	if (lower.endsWith('.onion')) {
		const label = lower.slice(0, -'.onion'.length);
		if (label.length !== 56) {
			throw new Error(
				`Only Tor v3 onion addresses are supported (56-char label): ${host}`
			);
		}
		const decoded = base32Decode(label);
		if (decoded.length !== 35 || decoded[34] !== 3) {
			throw new Error(`Invalid Tor v3 onion address: ${host}`);
		}
		verifyOnionV3Checksum(decoded, host);
		return { type: ADDRESS_TYPE_TORV3, host: decoded.toString('hex'), port };
	}

	if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(lower) || lower.length > 255) {
		throw new Error(`Invalid hostname: ${host}`);
	}
	return { type: ADDRESS_TYPE_DNS, host: lower, port };
}
