/**
 * BOLT 7: Gossip message signature validation.
 *
 * BOLT 7 signatures are computed over the double-SHA256 of the signed data.
 */

import crypto from 'crypto';
import { sign, verify } from '../crypto/ecdh';
import { CHANNEL_FLAG_DIRECTION } from './types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage
} from './types';

/**
 * Compute the double-SHA256 hash used for gossip signatures.
 */
export function computeGossipSignatureHash(data: Buffer): Buffer {
	const first = crypto.createHash('sha256').update(data).digest();
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
	const hash = computeGossipSignatureHash(signedData);

	return (
		verify(hash, msg.nodeId1, msg.nodeSignature1) &&
		verify(hash, msg.nodeId2, msg.nodeSignature2) &&
		verify(hash, msg.bitcoinKey1, msg.bitcoinSignature1) &&
		verify(hash, msg.bitcoinKey2, msg.bitcoinSignature2)
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
	const hash = computeGossipSignatureHash(signedData);
	return verify(hash, msg.nodeId, msg.signature);
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
	const hash = computeGossipSignatureHash(signedData);
	const direction = msg.channelFlags & CHANNEL_FLAG_DIRECTION;
	const signerKey = direction === 0 ? nodeId1 : nodeId2;
	return verify(hash, signerKey, msg.signature);
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
