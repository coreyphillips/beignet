/**
 * BOLT 1: `init` message encoding/decoding.
 *
 * The `init` message is the first message sent after the encrypted
 * transport handshake completes. It contains feature flags that
 * determine what protocol features both sides support.
 *
 * Format:
 *   [2: gflen]
 *   [gflen: globalfeatures]   (legacy, merged into features)
 *   [2: flen]
 *   [flen: features]
 *   [init_tlvs]
 *
 * Type: 16 (INIT)
 */

import { FeatureFlags } from '../features/flags';
import { decodeTlvStream, encodeTlvStream, ITlvRecord } from './tlv';

/** Well-known TLV types in init message */
const INIT_TLV_NETWORKS = 1n;

export interface IInitMessage {
	features: FeatureFlags;
	/** Optional: chain hashes the node is interested in (32 bytes each) */
	networks?: Buffer[];
}

/**
 * Encode an `init` message payload.
 * @param msg - Init message data
 * @returns Encoded payload (without the 2-byte message type prefix)
 */
export function encodeInitMessage(msg: IInitMessage): Buffer {
	const featureBuf = msg.features.toBuffer();

	// globalfeatures: empty (legacy, all features go in `features` field now)
	const gflen = Buffer.alloc(2);
	gflen.writeUInt16BE(0);

	// features
	const flen = Buffer.alloc(2);
	flen.writeUInt16BE(featureBuf.length);

	const parts: Buffer[] = [gflen, flen, featureBuf];

	// TLV records
	const tlvRecords: ITlvRecord[] = [];

	if (msg.networks && msg.networks.length > 0) {
		const networksBuf = Buffer.concat(msg.networks);
		tlvRecords.push({ type: INIT_TLV_NETWORKS, value: networksBuf });
	}

	if (tlvRecords.length > 0) {
		parts.push(encodeTlvStream(tlvRecords));
	}

	return Buffer.concat(parts);
}

/**
 * Decode an `init` message payload.
 * @param payload - Raw payload bytes (after the 2-byte type)
 * @returns Decoded init message
 */
export function decodeInitMessage(payload: Buffer): IInitMessage {
	let offset = 0;

	if (payload.length < 4) {
		throw new Error('Init message too short: need at least 4 bytes');
	}

	// Read globalfeatures
	const gflen = payload.readUInt16BE(offset);
	offset += 2;
	if (offset + gflen > payload.length) {
		throw new Error('Init: globalfeatures length exceeds payload');
	}
	const globalFeatures = payload.subarray(offset, offset + gflen);
	offset += gflen;

	// Read features
	if (offset + 2 > payload.length) {
		throw new Error('Init: missing features length');
	}
	const flen = payload.readUInt16BE(offset);
	offset += 2;
	if (offset + flen > payload.length) {
		throw new Error('Init: features length exceeds payload');
	}
	const featuresBuf = payload.subarray(offset, offset + flen);
	offset += flen;

	// Merge globalfeatures into features (OR them together)
	const mergedLen = Math.max(globalFeatures.length, featuresBuf.length);
	const merged = Buffer.alloc(mergedLen);
	// Copy features (right-aligned)
	featuresBuf.copy(merged, mergedLen - featuresBuf.length);
	// OR in globalfeatures (right-aligned)
	const gfOffset = mergedLen - globalFeatures.length;
	for (let i = 0; i < globalFeatures.length; i++) {
		merged[gfOffset + i] |= globalFeatures[i];
	}

	const features = FeatureFlags.fromBuffer(merged);

	const result: IInitMessage = { features };

	// Parse TLV records if there's remaining data
	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === INIT_TLV_NETWORKS) {
				const networks: Buffer[] = [];
				for (let i = 0; i < record.value.length; i += 32) {
					networks.push(Buffer.from(record.value.subarray(i, i + 32)));
				}
				result.networks = networks;
			}
		}
	}

	return result;
}
