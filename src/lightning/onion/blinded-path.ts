/**
 * BOLT 4: Blinded Path Construction and Processing
 *
 * A blinded path consists of:
 *   - introduction_node_id: the first node in the blinded path (known to sender)
 *   - blinding_point: the initial ephemeral blinding key
 *   - blinded_hops: array of { blinded_node_id, encrypted_recipient_data }
 *
 * Each hop's encrypted_recipient_data contains the real next_node_id and
 * (for payment paths) the short_channel_id + fee/cltv parameters.
 */

import {
	deriveBlindingKeyChain,
	computeBlindedNodeId,
	deriveBlindingEncryptionKey,
	encryptBlindedData,
	decryptBlindedData,
	deriveBlindingSharedSecret,
	deriveNextBlindingKey
} from './blinding';

export interface IBlindedHop {
	/** The blinded (tweaked) node ID */
	blindedNodeId: Buffer;
	/** Encrypted data for this hop */
	encryptedData: Buffer;
}

export interface IBlindedPath {
	/** First node in the blinded portion (public, known to sender) */
	introductionNodeId: Buffer;
	/** Initial blinding point (ephemeral public key) */
	blindingPoint: Buffer;
	/** Blinded hops after the introduction node */
	blindedHops: IBlindedHop[];
}

/** Plaintext content of encrypted_recipient_data for an intermediate blinded hop */
export interface IBlindedHopData {
	/** Next node to forward to (absent for final hop) */
	nextNodeId?: Buffer;
	/** Short channel ID for forwarding */
	shortChannelId?: Buffer;
	/** Fee and CLTV parameters for payment forwarding */
	paymentRelay?: {
		cltvExpiryDelta: number;
		feeProportionalMillionths: number;
		feeBaseMsat: number;
	};
	/** Payment constraints */
	paymentConstraints?: {
		maxCltvExpiry: number;
		htlcMinimumMsat: bigint;
	};
	/** Padding for uniform hop sizes */
	padding?: Buffer;
}

/**
 * Encode blinded hop data as a compact binary blob.
 * Uses a flags byte to indicate which optional fields are present:
 *   [1: flags] [33: next_node_id (if flag 0x01)] [8: scid (if flag 0x02)]
 *   [relay data (if flag 0x04)] [constraints (if flag 0x08)] [padding (if flag 0x10)]
 */
export function encodeBlindedHopData(data: IBlindedHopData): Buffer {
	const parts: Buffer[] = [];
	let flags = 0;

	if (data.nextNodeId) {
		flags |= 0x01;
	}
	if (data.shortChannelId) {
		flags |= 0x02;
	}
	if (data.paymentRelay) {
		flags |= 0x04;
	}
	if (data.paymentConstraints) {
		flags |= 0x08;
	}
	if (data.padding) {
		flags |= 0x10;
	}

	const flagsBuf = Buffer.alloc(1);
	flagsBuf[0] = flags;
	parts.push(flagsBuf);

	if (data.nextNodeId) {
		parts.push(data.nextNodeId);
	}
	if (data.shortChannelId) {
		parts.push(data.shortChannelId);
	}
	if (data.paymentRelay) {
		const relay = Buffer.alloc(10);
		relay.writeUInt16BE(data.paymentRelay.cltvExpiryDelta, 0);
		relay.writeUInt32BE(data.paymentRelay.feeProportionalMillionths, 2);
		relay.writeUInt32BE(data.paymentRelay.feeBaseMsat, 6);
		parts.push(relay);
	}
	if (data.paymentConstraints) {
		const constraints = Buffer.alloc(12);
		constraints.writeUInt32BE(data.paymentConstraints.maxCltvExpiry, 0);
		constraints.writeBigUInt64BE(data.paymentConstraints.htlcMinimumMsat, 4);
		parts.push(constraints);
	}
	if (data.padding) {
		const lenBuf = Buffer.alloc(2);
		lenBuf.writeUInt16BE(data.padding.length, 0);
		parts.push(lenBuf);
		parts.push(data.padding);
	}

	return Buffer.concat(parts);
}

/**
 * Decode blinded hop data from a binary buffer.
 */
export function decodeBlindedHopData(buf: Buffer): IBlindedHopData {
	let offset = 0;
	const flags = buf[offset++];
	const data: IBlindedHopData = {};

	if (flags & 0x01) {
		data.nextNodeId = Buffer.from(buf.subarray(offset, offset + 33));
		offset += 33;
	}
	if (flags & 0x02) {
		data.shortChannelId = Buffer.from(buf.subarray(offset, offset + 8));
		offset += 8;
	}
	if (flags & 0x04) {
		data.paymentRelay = {
			cltvExpiryDelta: buf.readUInt16BE(offset),
			feeProportionalMillionths: buf.readUInt32BE(offset + 2),
			feeBaseMsat: buf.readUInt32BE(offset + 6)
		};
		offset += 10;
	}
	if (flags & 0x08) {
		data.paymentConstraints = {
			maxCltvExpiry: buf.readUInt32BE(offset),
			htlcMinimumMsat: buf.readBigUInt64BE(offset + 4)
		};
		offset += 12;
	}
	if (flags & 0x10) {
		const padLen = buf.readUInt16BE(offset);
		offset += 2;
		data.padding = Buffer.from(buf.subarray(offset, offset + padLen));
		offset += padLen;
	}

	return data;
}

/**
 * Construct a blinded path from a sequence of node public keys.
 *
 * @param blindingSecret - 32-byte random secret for the blinding key chain
 * @param nodePubkeys - Array of node public keys in the path (first is introduction node)
 * @param hopDataList - Plaintext data for each hop (same length as nodePubkeys)
 * @returns The blinded path
 */
export function constructBlindedPath(
	blindingSecret: Buffer,
	nodePubkeys: Buffer[],
	hopDataList: IBlindedHopData[]
): IBlindedPath {
	if (nodePubkeys.length === 0) {
		throw new Error('Path must have at least one node');
	}
	if (nodePubkeys.length !== hopDataList.length) {
		throw new Error('Must have same number of nodes and hop data');
	}

	const { blindingKeys, sharedSecrets } = deriveBlindingKeyChain(
		blindingSecret,
		nodePubkeys
	);

	const blindedHops: IBlindedHop[] = [];

	for (let i = 0; i < nodePubkeys.length; i++) {
		// Compute blinded node ID
		const blindedNodeId = computeBlindedNodeId(
			nodePubkeys[i],
			sharedSecrets[i]
		);

		// Encrypt hop data
		const plaintext = encodeBlindedHopData(hopDataList[i]);
		const encKey = deriveBlindingEncryptionKey(sharedSecrets[i]);
		const encryptedData = encryptBlindedData(encKey, plaintext);

		blindedHops.push({ blindedNodeId, encryptedData });
	}

	return {
		introductionNodeId: nodePubkeys[0],
		blindingPoint: blindingKeys[0],
		blindedHops
	};
}

/**
 * Process a blinded hop: decrypt the encrypted data and derive the next blinding key.
 *
 * @param blindingKey - The current blinding point (ephemeral pubkey)
 * @param nodePrivkey - This node's private key
 * @param encryptedData - The encrypted recipient data for this hop
 * @returns Decrypted hop data and next blinding key
 */
export function processBlindedHop(
	blindingKey: Buffer,
	nodePrivkey: Buffer,
	encryptedData: Buffer
): { hopData: IBlindedHopData; nextBlindingKey: Buffer } {
	// Derive shared secret
	const sharedSecret = deriveBlindingSharedSecret(blindingKey, nodePrivkey);

	// Derive encryption key and decrypt
	const encKey = deriveBlindingEncryptionKey(sharedSecret);
	const plaintext = decryptBlindedData(encKey, encryptedData);

	// Decode hop data
	const hopData = decodeBlindedHopData(plaintext);

	// Derive next blinding key
	const nextBlindingKey = deriveNextBlindingKey(blindingKey, sharedSecret);

	return { hopData, nextBlindingKey };
}
