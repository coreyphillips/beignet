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
import type { ITlvRecord } from './tlv';
import { decodeTlvStream, encodeTlvStream } from './tlv';
import type { CustomRecords } from './custom-records';
import {
	CUSTOM_RECORD_START,
	boundedLightningPayload,
	customRecordEntries,
	decodeWithCustomRecords
} from './custom-records';

/** Well-known TLV types in init message */
const INIT_TLV_NETWORKS = 1n;
const INIT_TLV_TYPES = new Set<bigint>([INIT_TLV_NETWORKS]);

export interface IInitMessage {
	features: FeatureFlags;
	/**
	 * Records at or above 65536. Sent only when given, and read only when the
	 * decoder is asked for them (see IInitDecodeOptions).
	 */
	customRecords?: CustomRecords;
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

	// Custom records follow the standard ones: every custom type is above
	// every standard type.
	const customRecords = customRecordEntries(msg.customRecords, INIT_TLV_TYPES);
	customRecords.sort((left, right) =>
		left.type < right.type ? -1 : left.type > right.type ? 1 : 0
	);
	tlvRecords.push(...customRecords);

	if (tlvRecords.length > 0) {
		parts.push(encodeTlvStream(tlvRecords));
	}

	const payload = Buffer.concat(parts);
	return customRecords.length > 0 ? boundedLightningPayload(payload) : payload;
}

/** How to read an init message. */
export interface IInitDecodeOptions {
	/**
	 * Keep the records at or above 65536, whatever their parity. Off by
	 * default, where an unknown even record of any type is an error. A node
	 * turns it on only when it has an auxiliary channel provider to read
	 * them.
	 */
	customRecords?: boolean;
}

/**
 * Decode an `init` message payload.
 * @param payload - Raw payload bytes (after the 2-byte type)
 * @returns Decoded init message
 */
export function decodeInitMessage(
	payload: Buffer,
	options: IInitDecodeOptions = {}
): IInitMessage {
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
		const records = options.customRecords
			? decodeWithCustomRecords(payload, offset, INIT_TLV_TYPES)
			: decodeTlvStream(payload, offset, INIT_TLV_TYPES).records;
		const customRecords = new Map<bigint, Buffer>();
		for (const record of records) {
			if (record.type === INIT_TLV_NETWORKS) {
				const networks: Buffer[] = [];
				for (let i = 0; i < record.value.length; i += 32) {
					networks.push(Buffer.from(record.value.subarray(i, i + 32)));
				}
				result.networks = networks;
			} else if (options.customRecords && record.type >= CUSTOM_RECORD_START) {
				customRecords.set(record.type, Buffer.from(record.value));
			}
		}
		if (customRecords.size > 0) result.customRecords = customRecords;
	}

	return result;
}
