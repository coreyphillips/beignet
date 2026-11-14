/**
 * Field rules shared by several messages: the BOLT 1 "Unicode characters
 * validation" rule for human-readable strings (BOLT 11 `d`, offer strings,
 * payer notes, node aliases), and minimal encoding for the BOLT 7 and BOLT 12
 * features fields.
 *
 * Internal: not exported from the message barrel.
 */

// The reader rule: control (Cc), format (Cf: zero-width and bidi controls),
// surrogate (Cs) and private-use (Co) characters, plus the line and paragraph
// separators. Unassigned (Cn) is only a MAY for readers and is left alone, as
// it shifts with each Unicode release and would split nodes by runtime.
const READER_FORBIDDEN = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\u2028\u2029]/u;

// A writer must leave out all of "Other" (C*), Cn included.
const WRITER_FORBIDDEN = /[\p{C}\u2028\u2029]/u;

// ignoreBOM keeps a leading U+FEFF in the output so the Cf test sees it. The
// default strips it, which would let it through unnoticed.
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function codePointName(ch: string): string {
	const hex = (ch.codePointAt(0) ?? 0).toString(16).toUpperCase();
	return `U+${hex.padStart(4, '0')}`;
}

/**
 * Decode a received string under the BOLT 1 reader rule. Throws, naming
 * `field`, on invalid UTF-8 or a forbidden character.
 */
export function decodeBolt1String(bytes: Uint8Array, field: string): string {
	let value: string;
	try {
		value = strictUtf8.decode(bytes);
	} catch {
		throw new Error(`${field} is not valid UTF-8`);
	}
	const bad = READER_FORBIDDEN.exec(value);
	if (bad) {
		throw new Error(
			`${field} contains ${codePointName(bad[0])}, which BOLT 1 forbids`
		);
	}
	return value;
}

/**
 * Check outgoing text under the writer rule, or the reader rule for received
 * text being mirrored. Throws with `field` and the forbidden character.
 */
export function assertBolt1String(
	value: string,
	field: string,
	received = false
): void {
	const bad = (received ? READER_FORBIDDEN : WRITER_FORBIDDEN).exec(value);
	if (bad) {
		throw new Error(
			`${field} contains ${codePointName(bad[0])}, which BOLT 1 forbids`
		);
	}
}

/** {@link assertBolt1String}, then the UTF-8 bytes. */
export function encodeBolt1String(
	value: string,
	field: string,
	received = false
): Buffer {
	assertBolt1String(value, field, received);
	return Buffer.from(value, 'utf8');
}

/**
 * The BOLT 7 node_announcement alias: the 32-byte field with its trailing
 * zero bytes stripped, under the BOLT 1 reader rule.
 */
export function decodeNodeAlias(alias: Uint8Array): string {
	let end = alias.length;
	while (end > 0 && alias[end - 1] === 0) end--;
	return decodeBolt1String(alias.subarray(0, end), 'node_announcement alias');
}

/** A features field is minimal when it is empty or starts with a non-zero byte. */
export function isMinimalFeatures(features: Uint8Array): boolean {
	return features.length === 0 || features[0] !== 0;
}
