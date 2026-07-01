/**
 * BOLT 11: Invoice decoding.
 *
 * Parses a bech32-encoded lightning invoice string into a structured IInvoice object.
 */

import { bech32 } from 'bech32';
import { FeatureFlags } from '../features/flags';
import {
	IInvoice,
	IRoutingHintHop,
	IFallbackAddress,
	TagType,
	BECH32_MAX_LIMIT,
	TIMESTAMP_WORDS,
	SIGNATURE_WORDS,
	ROUTING_HOP_BYTES
} from './types';
import { parseHrp } from './amount';
import { wordsToBuffer, decodeUintFromWords, decodeTaggedField } from './words';
import { verifyInvoice } from './signing';
import {
	IBlindedPaymentPath,
	decodeInvoiceBlindedPaymentPaths
} from '../onion/blinded-path';

/**
 * Decode a BOLT 11 invoice string into a structured object.
 */
export function decode(invoiceString: string): IInvoice {
	// Bech32 is case-insensitive; normalize to lowercase
	const lower = invoiceString.toLowerCase();

	const decoded = bech32.decode(lower, BECH32_MAX_LIMIT);
	const { prefix, words } = decoded;

	// Parse HRP → network + optional amount
	const { network, amountMsat } = parseHrp(prefix);

	// Minimum words: timestamp(7) + signature(104) = 111
	if (words.length < TIMESTAMP_WORDS + SIGNATURE_WORDS) {
		throw new Error(
			`Invoice too short: ${words.length} words (need at least ${
				TIMESTAMP_WORDS + SIGNATURE_WORDS
			})`
		);
	}

	// Extract timestamp (first 7 words)
	const timestampWords = words.slice(0, TIMESTAMP_WORDS);
	const timestamp = decodeUintFromWords(Array.from(timestampWords));

	// Extract signature (last 104 words → 65 bytes)
	const sigStart = words.length - SIGNATURE_WORDS;
	const sigWords = words.slice(sigStart);
	const sigBytes = wordsToBuffer(Array.from(sigWords));
	const signature = sigBytes.subarray(0, 65);

	// Tagged fields are between timestamp and signature
	const taggedWords = Array.from(words.slice(TIMESTAMP_WORDS, sigStart));

	// Verify signature and recover pubkey. BOLT 11: an invoice whose signature
	// does not recover to a public key is invalid and MUST be rejected — do not
	// return a half-parsed invoice with no recoverable payee.
	const dataWords = Array.from(words.slice(0, sigStart));
	const recoveredPubkey = verifyInvoice(prefix, dataWords, signature);
	if (!recoveredPubkey) {
		throw new Error('Invoice signature is not recoverable');
	}

	// Parse tagged fields
	const result: Partial<IInvoice> = {};
	const unknownTags: Array<{ type: number; words: number[] }> = [];
	const routingHints: IRoutingHintHop[][] = [];
	let blindedPaths: IBlindedPaymentPath[] | undefined;

	let offset = 0;
	while (offset < taggedWords.length) {
		const field = decodeTaggedField(taggedWords, offset);
		offset = field.nextOffset;

		switch (field.type) {
			case TagType.PAYMENT_HASH:
				result.paymentHash = decodeFixedLengthHash(field.dataWords, 32);
				break;
			case TagType.PAYMENT_SECRET:
				result.paymentSecret = decodeFixedLengthHash(field.dataWords, 32);
				break;
			case TagType.DESCRIPTION:
				result.description = decodeDescription(field.dataWords);
				break;
			case TagType.DESCRIPTION_HASH:
				result.descriptionHash = decodeFixedLengthHash(field.dataWords, 32);
				break;
			case TagType.PAYEE_PUBKEY:
				result.payeeNodeKey = decodePayeeNodeKey(field.dataWords);
				break;
			case TagType.EXPIRY:
				result.expiry = decodeUintFromWords(field.dataWords);
				break;
			case TagType.MIN_FINAL_CLTV_EXPIRY:
				result.minFinalCltvExpiry = decodeUintFromWords(field.dataWords);
				break;
			case TagType.FALLBACK_ADDRESS:
				result.fallbackAddress = decodeFallbackAddress(field.dataWords);
				break;
			case TagType.ROUTING_INFO:
				routingHints.push(decodeRoutingInfo(field.dataWords));
				break;
			case TagType.FEATURE_BITS:
				result.featureBits = decodeFeatureBits(field.dataWords);
				break;
			case TagType.METADATA:
				result.metadata = wordsToBuffer(field.dataWords);
				break;
			case TagType.BLINDED_PATHS:
				blindedPaths = decodeInvoiceBlindedPaymentPaths(
					wordsToBuffer(field.dataWords)
				);
				break;
			default:
				unknownTags.push({ type: field.type, words: field.dataWords });
				break;
		}
	}

	// Validate: payment_hash is required
	if (!result.paymentHash) {
		throw new Error('Invoice missing required payment_hash (tag 1)');
	}

	// Validate: must have exactly one of description or description_hash
	if (
		result.description !== undefined &&
		result.descriptionHash !== undefined
	) {
		throw new Error('Invoice has both description and description_hash');
	}
	if (
		result.description === undefined &&
		result.descriptionHash === undefined
	) {
		throw new Error('Invoice missing description or description_hash');
	}

	const invoice: IInvoice = {
		network,
		timestamp,
		paymentHash: result.paymentHash,
		signature
	};

	if (amountMsat !== null) {
		invoice.amountMsat = amountMsat;
	}
	if (result.paymentSecret) {
		invoice.paymentSecret = result.paymentSecret;
	}
	if (result.description !== undefined) {
		invoice.description = result.description;
	}
	if (result.descriptionHash) {
		invoice.descriptionHash = result.descriptionHash;
	}
	if (result.payeeNodeKey) {
		invoice.payeeNodeKey = result.payeeNodeKey;
	}
	if (result.expiry !== undefined) {
		invoice.expiry = result.expiry;
	}
	if (result.minFinalCltvExpiry !== undefined) {
		invoice.minFinalCltvExpiry = result.minFinalCltvExpiry;
	}
	if (result.fallbackAddress) {
		invoice.fallbackAddress = result.fallbackAddress;
	}
	if (routingHints.length > 0) {
		invoice.routingHints = routingHints;
	}
	if (blindedPaths && blindedPaths.length > 0) {
		invoice.blindedPaths = blindedPaths;
	}
	if (result.featureBits) {
		invoice.featureBits = result.featureBits;
	}
	if (result.metadata) {
		invoice.metadata = result.metadata;
	}
	if (recoveredPubkey) {
		invoice.recoveredPubkey = recoveredPubkey;
	}
	if (unknownTags.length > 0) {
		invoice.unknownTags = unknownTags;
	}

	return invoice;
}

/** Decode a fixed-length hash from 5-bit words. */
function decodeFixedLengthHash(words: number[], expectedBytes: number): Buffer {
	const buf = wordsToBuffer(words);
	if (buf.length < expectedBytes) {
		throw new Error(`Expected ${expectedBytes} bytes, got ${buf.length}`);
	}
	return buf.subarray(0, expectedBytes);
}

/** Decode a UTF-8 description string from 5-bit words. */
function decodeDescription(words: number[]): string {
	return wordsToBuffer(words).toString('utf8');
}

/** Decode a 33-byte compressed public key from 5-bit words. */
function decodePayeeNodeKey(words: number[]): Buffer {
	const buf = wordsToBuffer(words);
	if (buf.length < 33) {
		throw new Error(`Expected 33-byte pubkey, got ${buf.length}`);
	}
	return buf.subarray(0, 33);
}

/** Decode a fallback address: version(1 word) + witness program. */
function decodeFallbackAddress(words: number[]): IFallbackAddress {
	if (words.length < 1) {
		throw new Error('Fallback address field is empty');
	}
	const version = words[0];
	const hash = wordsToBuffer(words.slice(1));
	return { version, hash };
}

/** Decode routing info: N hops of 51 bytes each. */
function decodeRoutingInfo(words: number[]): IRoutingHintHop[] {
	const data = wordsToBuffer(words);
	const hops: IRoutingHintHop[] = [];
	let offset = 0;
	while (offset + ROUTING_HOP_BYTES <= data.length) {
		hops.push({
			pubkey: data.subarray(offset, offset + 33),
			shortChannelId: data.subarray(offset + 33, offset + 41),
			feeBaseMsat: data.readUInt32BE(offset + 41),
			feeProportionalMillionths: data.readUInt32BE(offset + 45),
			cltvExpiryDelta: data.readUInt16BE(offset + 49)
		});
		offset += ROUTING_HOP_BYTES;
	}
	return hops;
}

/**
 * Decode feature bits from 5-bit words into a FeatureFlags instance.
 * Bit N is in word[wordCount - 1 - floor(N/5)] at position N % 5.
 */
function decodeFeatureBits(words: number[]): FeatureFlags {
	const ff = FeatureFlags.empty();
	for (let w = words.length - 1; w >= 0; w--) {
		const wordBitBase = (words.length - 1 - w) * 5;
		for (let b = 0; b < 5; b++) {
			if (words[w] & (1 << b)) {
				ff.setBit(wordBitBase + b);
			}
		}
	}
	return ff;
}
