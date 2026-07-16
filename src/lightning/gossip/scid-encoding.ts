/**
 * BOLT 7: SCID compact encoding for gossip queries.
 *
 * Encoding types:
 *   0 = raw (uncompressed): encoding_type(1) + concatenated 8-byte SCIDs
 *   1 = zlib compressed: encoding_type(1) + zlib.deflate(concatenated 8-byte SCIDs)
 */

import zlib from 'zlib';

/**
 * Encode short channel IDs as raw (type 0).
 * Returns: encoding_type(1) + concatenated 8-byte SCIDs.
 */
export function encodeShortChannelIds(scids: Buffer[]): Buffer {
	const body = Buffer.concat(scids);
	const result = Buffer.alloc(1 + body.length);
	result[0] = 0; // encoding_type = raw
	body.copy(result, 1);
	return result;
}

/**
 * Encode short channel IDs with zlib compression (type 1).
 * Returns: encoding_type(1) + zlib.deflate(concatenated 8-byte SCIDs).
 */
export function encodeShortChannelIdsCompressed(scids: Buffer[]): Buffer {
	const body = Buffer.concat(scids);
	const compressed = zlib.deflateSync(body);
	const result = Buffer.alloc(1 + compressed.length);
	result[0] = 1; // encoding_type = zlib
	compressed.copy(result, 1);
	return result;
}

/**
 * Decode encoded short channel IDs.
 * Supports type 0 (raw) and type 1 (zlib).
 * Returns an array of 8-byte SCID Buffers.
 */
export function decodeShortChannelIds(encoded: Buffer): Buffer[] {
	if (encoded.length < 1) {
		return [];
	}

	const encodingType = encoded[0];
	let body: Buffer;

	if (encodingType === 0) {
		// Raw encoding
		body = Buffer.from(encoded.subarray(1));
	} else if (encodingType === 1) {
		// BOLT 7 removed the zlib (type 1) encoding. Inflating attacker-supplied
		// data with no output cap is a decompression bomb (~1032:1) reachable from
		// any peer over query_short_channel_ids / reply_channel_range, so reject it
		// outright rather than calling zlib.inflateSync on peer bytes.
		throw new Error(
			'SCID zlib encoding (type 1) is unsupported: BOLT 7 removed it'
		);
	} else {
		throw new Error(`Unknown SCID encoding type: ${encodingType}`);
	}

	if (body.length % 8 !== 0) {
		throw new Error(
			`Decoded SCID body length ${body.length} is not a multiple of 8`
		);
	}

	const scids: Buffer[] = [];
	for (let i = 0; i < body.length; i += 8) {
		scids.push(Buffer.from(body.subarray(i, i + 8)));
	}
	return scids;
}
