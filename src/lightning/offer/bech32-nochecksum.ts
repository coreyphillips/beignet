/**
 * BOLT 12 string encoding: bech32 CHARACTERS with NO checksum.
 *
 * Unlike BOLT 11 (bech32) and segwit addresses (bech32/bech32m), BOLT 12
 * strings are "the human-readable part, 1, then the data part encoded with
 * the bech32 character set" and explicitly carry NO checksum (offers are
 * long-lived and QR/print-transmitted; a checksum would break the documented
 * `+`-continuation splitting). Encoding with a bech32m checksum (the previous
 * behavior) made every beignet offer/invreq/invoice unreadable by CLN and
 * every CLN string unreadable by beignet ("Invalid checksum").
 *
 * Readers MUST accept `+` (with optional surrounding whitespace) joins.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const CHARSET_REV = new Map<string, number>([...CHARSET].map((c, i) => [c, i]));

/** Convert 8-bit bytes to 5-bit words (no padding surprises for our sizes). */
export function toWords(data: Buffer): number[] {
	const words: number[] = [];
	let acc = 0;
	let bits = 0;
	for (const byte of data) {
		acc = (acc << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			words.push((acc >> bits) & 31);
		}
	}
	if (bits > 0) words.push((acc << (5 - bits)) & 31);
	return words;
}

/** Convert 5-bit words back to 8-bit bytes, discarding final padding bits. */
export function fromWords(words: number[]): Buffer {
	const bytes: number[] = [];
	let acc = 0;
	let bits = 0;
	for (const word of words) {
		acc = (acc << 5) | word;
		bits += 5;
		while (bits >= 8) {
			bits -= 8;
			bytes.push((acc >> bits) & 0xff);
		}
	}
	return Buffer.from(bytes);
}

/** Encode `hrp1<data>` in bech32 characters with NO checksum. */
export function encodeNoChecksum(hrp: string, data: Buffer): string {
	return `${hrp}1${toWords(data)
		.map((w) => CHARSET[w])
		.join('')}`;
}

/**
 * Decode a checksum-less BOLT 12 string. Accepts `+`-joined parts (a `+`
 * immediately after a bech32 character, followed by optional whitespace and
 * another bech32 character) and uppercase-or-lowercase (not mixed).
 */
export function decodeNoChecksum(str: string): { hrp: string; data: Buffer } {
	// BOLT 12: `+` MUST be surrounded by bech32 characters (whitespace is only
	// allowed AFTER the `+`). Stripping unconditionally accepted leading,
	// trailing, doubled, and whitespace-preceded joins the spec rejects.
	if (/(^|[^0-9a-zA-Z])\+/.test(str) || /\+(?!\s*[0-9a-zA-Z])/.test(str)) {
		throw new Error('BOLT 12 string has a misplaced + join');
	}
	const joined = str.replace(/\+\s*/g, '').trim();
	const hasUpper = /[A-Z]/.test(joined);
	const hasLower = /[a-z]/.test(joined);
	if (hasUpper && hasLower) {
		throw new Error('BOLT 12 string mixes upper and lower case');
	}
	const s = joined.toLowerCase();
	const sep = s.lastIndexOf('1');
	if (sep < 1 || sep + 1 >= s.length) {
		throw new Error('BOLT 12 string missing hrp/data separator');
	}
	const hrp = s.slice(0, sep);
	const words: number[] = [];
	for (const ch of s.slice(sep + 1)) {
		const w = CHARSET_REV.get(ch);
		if (w === undefined) {
			throw new Error(`BOLT 12 string has invalid character '${ch}'`);
		}
		words.push(w);
	}
	// Final padding must be less than a full word (else a whole character
	// carries no data) and its bits must be zero.
	const padBits = (words.length * 5) % 8;
	if (padBits >= 5) {
		throw new Error('BOLT 12 string padding exceeds 4-bit limit');
	}
	if (padBits > 0 && (words[words.length - 1] & ((1 << padBits) - 1)) !== 0) {
		throw new Error('BOLT 12 string has non-zero padding bits');
	}
	return { hrp, data: fromWords(words) };
}
