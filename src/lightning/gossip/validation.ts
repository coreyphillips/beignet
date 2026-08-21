/**
 * BOLT 7: Gossip message signature validation.
 *
 * BOLT 7 signatures are computed over the double-SHA256 of the signed data.
 */

import crypto from 'crypto';
import { sign, verifySha256d } from '../crypto/ecdh';
import { CHANNEL_FLAG_DIRECTION } from './types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage
} from './types';
import {
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage,
	encodeNodeAnnouncementMessage
} from './messages';

/**
 * Compute the first SHA256 of the signed data. Signatures cover the double
 * SHA256, but verification hands the single hash to verifySha256d so the
 * fast backend can apply the second round itself (issue #441).
 */
function computeGossipFirstHash(data: Buffer): Buffer {
	return crypto.createHash('sha256').update(data).digest();
}

/**
 * Compute the double-SHA256 hash used for gossip signatures.
 */
export function computeGossipSignatureHash(data: Buffer): Buffer {
	const first = computeGossipFirstHash(data);
	return crypto.createHash('sha256').update(first).digest();
}

/**
 * Extract the signed data portion of a channel_announcement payload.
 * Everything from offset 256 onward (after the 4×64-byte signatures).
 */
export function getChannelAnnouncementSignedData(payload: Buffer): Buffer {
	return Buffer.from(payload.subarray(256));
}

/**
 * Extract the signed data portion of a node_announcement payload.
 * Everything from offset 64 onward (after the 64-byte signature).
 */
export function getNodeAnnouncementSignedData(payload: Buffer): Buffer {
	return Buffer.from(payload.subarray(64));
}

/**
 * Extract the signed data portion of a channel_update payload.
 * Everything from offset 64 onward (after the 64-byte signature).
 */
export function getChannelUpdateSignedData(payload: Buffer): Buffer {
	return Buffer.from(payload.subarray(64));
}

/**
 * Verify all 4 signatures on a channel_announcement.
 */
export function verifyChannelAnnouncement(
	msg: IChannelAnnouncementMessage,
	payload: Buffer
): boolean {
	const signedData = getChannelAnnouncementSignedData(payload);
	const firstHash = computeGossipFirstHash(signedData);

	return (
		verifySha256d(firstHash, msg.nodeId1, msg.nodeSignature1) &&
		verifySha256d(firstHash, msg.nodeId2, msg.nodeSignature2) &&
		verifySha256d(firstHash, msg.bitcoinKey1, msg.bitcoinSignature1) &&
		verifySha256d(firstHash, msg.bitcoinKey2, msg.bitcoinSignature2)
	);
}

/**
 * Verify the signature on a node_announcement.
 */
export function verifyNodeAnnouncement(
	msg: INodeAnnouncementMessage,
	payload: Buffer
): boolean {
	const signedData = getNodeAnnouncementSignedData(payload);
	const firstHash = computeGossipFirstHash(signedData);
	return verifySha256d(firstHash, msg.nodeId, msg.signature);
}

/**
 * Verify the signature on a channel_update.
 * Direction bit in channelFlags determines which node signed.
 */
export function verifyChannelUpdate(
	msg: IChannelUpdateMessage,
	payload: Buffer,
	nodeId1: Buffer,
	nodeId2: Buffer
): boolean {
	const signedData = getChannelUpdateSignedData(payload);
	const firstHash = computeGossipFirstHash(signedData);
	const direction = msg.channelFlags & CHANNEL_FLAG_DIRECTION;
	const signerKey = direction === 0 ? nodeId1 : nodeId2;
	return verifySha256d(firstHash, signerKey, msg.signature);
}

/**
 * Verify a decoded channel_announcement against its canonical re-encoding.
 * True only when the signatures validate over bytes we can reproduce, so a
 * passing message can be relayed faithfully. Signed future fields the codec
 * cannot round-trip make this false. Used to resolve provenance for stored
 * rows that predate verification flags (#340).
 */
export function verifyChannelAnnouncementMessage(
	msg: IChannelAnnouncementMessage
): boolean {
	try {
		return verifyChannelAnnouncement(
			msg,
			encodeChannelAnnouncementMessage(msg)
		);
	} catch {
		return false;
	}
}

/**
 * Verify a decoded node_announcement against its canonical re-encoding.
 * See verifyChannelAnnouncementMessage.
 */
export function verifyNodeAnnouncementMessage(
	msg: INodeAnnouncementMessage
): boolean {
	try {
		return verifyNodeAnnouncement(msg, encodeNodeAnnouncementMessage(msg));
	} catch {
		return false;
	}
}

/**
 * Verify a decoded channel_update against its canonical re-encoding.
 * See verifyChannelAnnouncementMessage.
 */
export function verifyChannelUpdateMessage(
	msg: IChannelUpdateMessage,
	nodeId1: Buffer,
	nodeId2: Buffer
): boolean {
	try {
		return verifyChannelUpdate(
			msg,
			encodeChannelUpdateMessage(msg),
			nodeId1,
			nodeId2
		);
	} catch {
		return false;
	}
}

/**
 * Sign a channel_announcement payload.
 * Returns node signature and bitcoin signature for one side.
 */
export function signChannelAnnouncement(
	payload: Buffer,
	nodePrivkey: Buffer,
	bitcoinPrivkey: Buffer
): { nodeSignature: Buffer; bitcoinSignature: Buffer } {
	const signedData = getChannelAnnouncementSignedData(payload);
	const hash = computeGossipSignatureHash(signedData);
	return {
		nodeSignature: sign(hash, nodePrivkey),
		bitcoinSignature: sign(hash, bitcoinPrivkey)
	};
}

/**
 * Sign a node_announcement payload.
 */
export function signNodeAnnouncement(
	payload: Buffer,
	nodePrivkey: Buffer
): Buffer {
	const signedData = getNodeAnnouncementSignedData(payload);
	const hash = computeGossipSignatureHash(signedData);
	return sign(hash, nodePrivkey);
}

/**
 * Sign a channel_update payload.
 */
export function signChannelUpdate(
	payload: Buffer,
	nodePrivkey: Buffer
): Buffer {
	const signedData = getChannelUpdateSignedData(payload);
	const hash = computeGossipSignatureHash(signedData);
	return sign(hash, nodePrivkey);
}
