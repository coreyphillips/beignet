/**
 * Builders for gossip messages carrying REAL signatures, for tests that
 * exercise the verified-serving and provenance-resolution paths (#340).
 */

import crypto from 'crypto';
import {
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage,
	encodeNodeAnnouncementMessage,
	decodeChannelAnnouncementMessage,
	decodeChannelUpdateMessage,
	decodeNodeAnnouncementMessage
} from '../../../src/lightning/gossip/messages';
import {
	signChannelAnnouncement,
	signChannelUpdate,
	signNodeAnnouncement
} from '../../../src/lightning/gossip/validation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { BITCOIN_CHAIN_HASH } from '../../../src/lightning/channel/types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage
} from '../../../src/lightning/gossip/types';

export interface ISignedChannelKeys {
	nodeKey1: Buffer;
	nodeKey2: Buffer;
	bitcoinKey1: Buffer;
	bitcoinKey2: Buffer;
}

/** Random keys with nodeId1 < nodeId2 per BOLT 7. */
export function makeSignedChannelKeys(): ISignedChannelKeys {
	let keyA = crypto.randomBytes(32);
	let keyB = crypto.randomBytes(32);
	if (Buffer.compare(getPublicKey(keyA), getPublicKey(keyB)) > 0) {
		[keyA, keyB] = [keyB, keyA];
	}
	return {
		nodeKey1: keyA,
		nodeKey2: keyB,
		bitcoinKey1: crypto.randomBytes(32),
		bitcoinKey2: crypto.randomBytes(32)
	};
}

/**
 * A channel_announcement whose four signatures genuinely validate.
 * extraSignedBytes are appended BEFORE signing, simulating signed future
 * fields our codec cannot round-trip.
 */
export function makeSignedChannelAnnouncement(
	scid: Buffer,
	keys: ISignedChannelKeys,
	chainHash: Buffer = BITCOIN_CHAIN_HASH,
	extraSignedBytes?: Buffer
): { msg: IChannelAnnouncementMessage; payload: Buffer } {
	const unsigned: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash,
		shortChannelId: scid,
		nodeId1: getPublicKey(keys.nodeKey1),
		nodeId2: getPublicKey(keys.nodeKey2),
		bitcoinKey1: getPublicKey(keys.bitcoinKey1),
		bitcoinKey2: getPublicKey(keys.bitcoinKey2)
	};
	let payload = encodeChannelAnnouncementMessage(unsigned);
	if (extraSignedBytes && extraSignedBytes.length > 0) {
		payload = Buffer.concat([payload, extraSignedBytes]);
	}
	const side1 = signChannelAnnouncement(
		payload,
		keys.nodeKey1,
		keys.bitcoinKey1
	);
	const side2 = signChannelAnnouncement(
		payload,
		keys.nodeKey2,
		keys.bitcoinKey2
	);
	side1.nodeSignature.copy(payload, 0);
	side2.nodeSignature.copy(payload, 64);
	side1.bitcoinSignature.copy(payload, 128);
	side2.bitcoinSignature.copy(payload, 192);
	return { msg: decodeChannelAnnouncementMessage(payload), payload };
}

/** A channel_update genuinely signed by the given direction's node key. */
export function makeSignedChannelUpdate(
	scid: Buffer,
	signerKey: Buffer,
	direction: 0 | 1,
	timestamp: number,
	chainHash: Buffer = BITCOIN_CHAIN_HASH,
	extraSignedBytes?: Buffer
): { msg: IChannelUpdateMessage; payload: Buffer } {
	const unsigned: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash,
		shortChannelId: scid,
		timestamp,
		messageFlags: 0x01,
		channelFlags: direction,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	let payload = encodeChannelUpdateMessage(unsigned);
	if (extraSignedBytes && extraSignedBytes.length > 0) {
		payload = Buffer.concat([payload, extraSignedBytes]);
	}
	signChannelUpdate(payload, signerKey).copy(payload, 0);
	return { msg: decodeChannelUpdateMessage(payload), payload };
}

/** A node_announcement genuinely signed by the node's key. */
export function makeSignedNodeAnnouncement(
	nodeKey: Buffer,
	timestamp: number,
	addresses: INodeAnnouncementMessage['addresses'] = []
): { msg: INodeAnnouncementMessage; payload: Buffer } {
	const unsigned: INodeAnnouncementMessage = {
		signature: Buffer.alloc(64),
		features: Buffer.alloc(0),
		timestamp,
		nodeId: getPublicKey(nodeKey),
		rgbColor: Buffer.from([255, 0, 0]),
		alias: Buffer.alloc(32),
		addresses
	};
	const payload = encodeNodeAnnouncementMessage(unsigned);
	signNodeAnnouncement(payload, nodeKey).copy(payload, 0);
	return { msg: decodeNodeAnnouncementMessage(payload), payload };
}
