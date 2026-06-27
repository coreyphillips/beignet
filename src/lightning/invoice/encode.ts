/**
 * BOLT 11: Invoice encoding.
 *
 * Creates a signed bech32-encoded lightning invoice string from structured options.
 */

import { bech32 } from 'bech32';
import { FeatureFlags } from '../features/flags';
import {
	IInvoiceCreationOptions,
	IRoutingHintHop,
	IFallbackAddress,
	TagType,
	BECH32_MAX_LIMIT,
	TIMESTAMP_WORDS,
	ROUTING_HOP_BYTES
} from './types';
import { buildHrp } from './amount';
import { bufferToWords, encodeUintToWords, encodeTaggedField } from './words';
import { signInvoice } from './signing';

/**
 * Encode a BOLT 11 invoice from creation options.
 * Returns the bech32-encoded invoice string.
 */
export function encode(options: IInvoiceCreationOptions): string {
	// Validate required fields
	if (!options.paymentHash || options.paymentHash.length !== 32) {
		throw new Error('paymentHash must be 32 bytes');
	}
	if (
		options.description !== undefined &&
		options.descriptionHash !== undefined
	) {
		throw new Error('Cannot specify both description and descriptionHash');
	}
	if (
		options.description === undefined &&
		options.descriptionHash === undefined
	) {
		throw new Error('Must specify either description or descriptionHash');
	}

	// Build HRP
	const hrp = buildHrp(options.network, options.amountMsat);

	// Encode timestamp (7 five-bit words)
	const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
	const dataWords: number[] = encodeUintToWords(timestamp, TIMESTAMP_WORDS);

	// Encode tagged fields in order: p, s, d/h, n, x, c, 9, f, r, m
	// Tag 1: payment_hash (required)
	dataWords.push(
		...encodeTaggedField(
			TagType.PAYMENT_HASH,
			bufferToWords(options.paymentHash)
		)
	);

	// Tag 16: payment_secret
	if (options.paymentSecret) {
		if (options.paymentSecret.length !== 32) {
			throw new Error('paymentSecret must be 32 bytes');
		}
		dataWords.push(
			...encodeTaggedField(
				TagType.PAYMENT_SECRET,
				bufferToWords(options.paymentSecret)
			)
		);
	}

	// Tag 13: description OR Tag 23: description_hash
	if (options.description !== undefined) {
		const descWords = bufferToWords(Buffer.from(options.description, 'utf8'));
		dataWords.push(...encodeTaggedField(TagType.DESCRIPTION, descWords));
	} else if (options.descriptionHash) {
		if (options.descriptionHash.length !== 32) {
			throw new Error('descriptionHash must be 32 bytes');
		}
		dataWords.push(
			...encodeTaggedField(
				TagType.DESCRIPTION_HASH,
				bufferToWords(options.descriptionHash)
			)
		);
	}

	// Tag 19: payee node key
	if (options.payeeNodeKey) {
		if (options.payeeNodeKey.length !== 33) {
			throw new Error('payeeNodeKey must be 33 bytes');
		}
		dataWords.push(
			...encodeTaggedField(
				TagType.PAYEE_PUBKEY,
				bufferToWords(options.payeeNodeKey)
			)
		);
	}

	// Tag 6: expiry
	if (options.expiry !== undefined) {
		dataWords.push(
			...encodeTaggedField(TagType.EXPIRY, encodeVarInt(options.expiry))
		);
	}

	// Tag 24: min_final_cltv_expiry
	if (options.minFinalCltvExpiry !== undefined) {
		dataWords.push(
			...encodeTaggedField(
				TagType.MIN_FINAL_CLTV_EXPIRY,
				encodeVarInt(options.minFinalCltvExpiry)
			)
		);
	}

	// Tag 5: feature bits
	if (options.featureBits) {
		dataWords.push(
			...encodeTaggedField(
				TagType.FEATURE_BITS,
				encodeFeatureBits(options.featureBits)
			)
		);
	}

	// Tag 9: fallback address
	if (options.fallbackAddress) {
		dataWords.push(
			...encodeTaggedField(
				TagType.FALLBACK_ADDRESS,
				encodeFallbackAddress(options.fallbackAddress)
			)
		);
	}

	// Tag 3: routing info (one tag per route)
	if (options.routingHints) {
		for (const route of options.routingHints) {
			dataWords.push(
				...encodeTaggedField(TagType.ROUTING_INFO, encodeRoutingInfo(route))
			);
		}
	}

	// Tag 27: metadata
	if (options.metadata) {
		dataWords.push(
			...encodeTaggedField(TagType.METADATA, bufferToWords(options.metadata))
		);
	}

	// Sign: hash(hrp || dataWords) → 65-byte signature
	const sigBytes = signInvoice(hrp, dataWords, options.privateKey);

	// Convert 65-byte signature to 5-bit words (104 words)
	const sigWords = bufferToWords(sigBytes);
	const allWords = [...dataWords, ...sigWords];

	return bech32.encode(hrp, allWords, BECH32_MAX_LIMIT);
}

/**
 * Encode a non-negative integer as variable-width 5-bit words (minimum words needed).
 */
function encodeVarInt(value: number): number[] {
	if (value === 0) {
		return [0];
	}
	const words: number[] = [];
	let v = value;
	while (v > 0) {
		words.unshift(v & 0x1f);
		v = Math.floor(v / 32);
	}
	return words;
}

/**
 * Encode routing hints (one route = array of hops, each 51 bytes).
 */
function encodeRoutingInfo(hops: IRoutingHintHop[]): number[] {
	const buf = Buffer.alloc(hops.length * ROUTING_HOP_BYTES);
	let offset = 0;
	for (const hop of hops) {
		hop.pubkey.copy(buf, offset);
		hop.shortChannelId.copy(buf, offset + 33);
		buf.writeUInt32BE(hop.feeBaseMsat, offset + 41);
		buf.writeUInt32BE(hop.feeProportionalMillionths, offset + 45);
		buf.writeUInt16BE(hop.cltvExpiryDelta, offset + 49);
		offset += ROUTING_HOP_BYTES;
	}
	return bufferToWords(buf);
}

/**
 * Encode a fallback address: version(1 word) + witness program words.
 */
function encodeFallbackAddress(addr: IFallbackAddress): number[] {
	return [addr.version, ...bufferToWords(addr.hash)];
}

/**
 * Encode FeatureFlags into 5-bit words.
 * Feature bits are packed into 5-bit words with the lowest bits in the last word.
 */
function encodeFeatureBits(features: FeatureFlags): number[] {
	const setBits = features.listSetBits();
	if (setBits.length === 0) {
		return [0];
	}

	const maxBit = setBits[setBits.length - 1];
	const wordCount = Math.ceil((maxBit + 1) / 5);
	const words: number[] = new Array(wordCount).fill(0);

	for (const bit of setBits) {
		const wordIdx = wordCount - 1 - Math.floor(bit / 5);
		const bitIdx = bit % 5;
		words[wordIdx] |= 1 << bitIdx;
	}

	return words;
}
