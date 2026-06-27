/**
 * BOLT 11: 5-bit word ↔ byte conversion utilities.
 *
 * Bech32 encoding operates on 5-bit "words". These helpers convert between
 * 5-bit word arrays and byte buffers, and handle tagged field framing.
 */

import { bech32 } from 'bech32';

/**
 * Convert 5-bit words to a byte buffer.
 * Trailing bits (if the word count is not a multiple of 8/5) are zero-padded.
 */
export function wordsToBuffer(words: number[]): Buffer {
	return Buffer.from(bech32.fromWords(words));
}

/**
 * Convert a byte buffer to 5-bit words.
 */
export function bufferToWords(data: Buffer): number[] {
	return Array.from(bech32.toWords(data));
}

/**
 * Encode a non-negative integer as a fixed-width big-endian 5-bit word array.
 */
export function encodeUintToWords(value: number, wordCount: number): number[] {
	const words: number[] = new Array(wordCount);
	for (let i = wordCount - 1; i >= 0; i--) {
		words[i] = value & 0x1f;
		value = Math.floor(value / 32);
	}
	return words;
}

/**
 * Decode a big-endian 5-bit word array to a non-negative integer.
 */
export function decodeUintFromWords(words: number[]): number {
	let value = 0;
	for (let i = 0; i < words.length; i++) {
		value = value * 32 + words[i];
	}
	return value;
}

/**
 * Encode a tagged field: [type(1 word), lengthHi(1 word), lengthLo(1 word), ...data].
 * Length is the number of data words, encoded as two 5-bit words (10 bits, max 1023).
 */
export function encodeTaggedField(type: number, dataWords: number[]): number[] {
	const len = dataWords.length;
	return [type, (len >> 5) & 0x1f, len & 0x1f, ...dataWords];
}

/**
 * Decode a tagged field starting at `offset` in the words array.
 * Returns the tag type, data words, and the offset of the next field.
 */
export function decodeTaggedField(
	words: number[],
	offset: number
): { type: number; dataWords: number[]; nextOffset: number } {
	if (offset + 3 > words.length) {
		throw new Error('Tagged field truncated: not enough words for header');
	}
	const type = words[offset];
	const len = words[offset + 1] * 32 + words[offset + 2];
	const dataStart = offset + 3;
	const dataEnd = dataStart + len;
	if (dataEnd > words.length) {
		throw new Error(
			`Tagged field truncated: need ${len} data words but only ${
				words.length - dataStart
			} available`
		);
	}
	return {
		type,
		dataWords: words.slice(dataStart, dataEnd),
		nextOffset: dataEnd
	};
}
