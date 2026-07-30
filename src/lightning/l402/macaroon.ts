/**
 * Minimal macaroon reader for L402 clients.
 *
 * A client never verifies a macaroon (only the issuing server holds the root
 * key). It needs exactly one thing from it: the payment hash the server
 * committed to when it minted the token, so the invoice in the same challenge
 * can be checked against it before any payment goes out. Without that check a
 * server could hand out a macaroon for one hash and an invoice for another,
 * and the payment would buy nothing.
 *
 * This is therefore a reader, not an implementation: it parses the v2 binary
 * format that lnd and Aperture produce, extracts the identifier, and stops.
 * Minting and verification (HMAC chain, caveats, root keys) belong to the
 * server side and are out of scope here.
 *
 * Reference: github.com/lightninglabs/L402, gopkg.in/macaroon.v2.
 */

/** Field types in the v2 binary encoding. */
const FIELD_EOS = 0;
const FIELD_LOCATION = 1;
const FIELD_IDENTIFIER = 2;
const FIELD_VID = 4;
const FIELD_SIGNATURE = 6;

/** L402 identifier layout: uint16 version, 32 byte hash, 32 byte token id. */
const L402_IDENTIFIER_VERSION_0 = 0;
const L402_IDENTIFIER_V0_LENGTH = 66;

/** Bound on a macaroon we will even attempt to parse. */
const MAX_MACAROON_BYTES = 64 * 1024;

/** What a client can learn from an L402 macaroon without the root key. */
export interface IL402Identifier {
	/** Identifier version. Only 0 is defined today. */
	version: number;
	/** The payment hash this token is bound to. */
	paymentHash: Buffer;
	/** Server-chosen token id, opaque to the client. */
	tokenId: Buffer;
}

/** A macaroon as far as a client cares: where it came from and its id. */
export interface IParsedMacaroon {
	location?: string;
	identifier: Buffer;
	signature?: Buffer;
	caveatCount: number;
}

class Reader {
	private offset = 0;

	constructor(private readonly buf: Buffer) {}

	get done(): boolean {
		return this.offset >= this.buf.length;
	}

	/** Protobuf-style base-128 varint. */
	readVarint(): number {
		let result = 0;
		let shift = 0;
		for (;;) {
			if (this.done) throw new Error('macaroon: truncated varint');
			const byte = this.buf[this.offset++];
			result |= (byte & 0x7f) << shift;
			if ((byte & 0x80) === 0) return result >>> 0;
			shift += 7;
			// A length or field type this large is malformed, and shifting past
			// 32 bits would silently wrap.
			if (shift > 28) throw new Error('macaroon: varint too large');
		}
	}

	readBytes(length: number): Buffer {
		if (length < 0 || this.offset + length > this.buf.length) {
			throw new Error('macaroon: field runs past end of buffer');
		}
		const out = this.buf.subarray(this.offset, this.offset + length);
		this.offset += length;
		return Buffer.from(out);
	}

	readByte(): number {
		if (this.done) throw new Error('macaroon: unexpected end of buffer');
		return this.buf[this.offset++];
	}

	/** Read one field, or null at an end-of-section marker. */
	readField(): { type: number; value: Buffer } | null {
		const type = this.readVarint();
		if (type === FIELD_EOS) return null;
		const length = this.readVarint();
		return { type, value: this.readBytes(length) };
	}
}

/**
 * Decode a base64 (standard or url-safe) macaroon into the parts a client
 * uses. Throws on anything it cannot parse; callers treat a throw as "this
 * challenge is not verifiable" and refuse to pay.
 */
export function parseMacaroon(base64Macaroon: string): IParsedMacaroon {
	const trimmed = base64Macaroon.trim();
	if (trimmed.length === 0) throw new Error('macaroon: empty');
	// Aperture emits standard base64; some servers use the url-safe alphabet.
	// Buffer.from tolerates both only if we normalize the two swapped chars.
	const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
	const raw = Buffer.from(normalized, 'base64');
	if (raw.length === 0) throw new Error('macaroon: not valid base64');
	if (raw.length > MAX_MACAROON_BYTES) {
		throw new Error('macaroon: unreasonably large');
	}

	const reader = new Reader(raw);
	const version = reader.readByte();
	if (version !== 2) {
		// v1 is a text format no current L402 server emits. Refusing is the
		// safe answer: an unparsed macaroon means an unchecked payment hash.
		throw new Error(`macaroon: unsupported version ${version}`);
	}

	let location: string | undefined;
	let identifier: Buffer | undefined;

	// Header section: optional location, then the identifier, then EOS.
	for (;;) {
		const field = reader.readField();
		if (field === null) break;
		if (field.type === FIELD_LOCATION) {
			location = field.value.toString('utf8');
		} else if (field.type === FIELD_IDENTIFIER) {
			identifier = field.value;
		}
		// Unknown header fields are skipped rather than rejected: the format
		// is extensible and we only need the identifier.
	}
	if (!identifier) throw new Error('macaroon: no identifier');

	// Caveat section: each caveat is its own field run ending in EOS, and the
	// whole section ends with a second EOS.
	let caveatCount = 0;
	for (;;) {
		const first = reader.readField();
		if (first === null) break;
		caveatCount++;
		if (first.type !== FIELD_LOCATION && first.type !== FIELD_IDENTIFIER) {
			throw new Error('macaroon: unexpected field opening a caveat');
		}
		for (;;) {
			const field = reader.readField();
			if (field === null) break;
			if (
				field.type !== FIELD_IDENTIFIER &&
				field.type !== FIELD_VID &&
				field.type !== FIELD_LOCATION
			) {
				throw new Error('macaroon: unexpected field inside a caveat');
			}
		}
	}

	let signature: Buffer | undefined;
	const sigField = reader.readField();
	if (sigField && sigField.type === FIELD_SIGNATURE) {
		signature = sigField.value;
	}

	return { location, identifier, signature, caveatCount };
}

/**
 * Read the L402 identifier: version, the committed payment hash, and the
 * server's token id.
 */
export function parseL402Identifier(identifier: Buffer): IL402Identifier {
	if (identifier.length !== L402_IDENTIFIER_V0_LENGTH) {
		throw new Error(
			`L402 identifier: expected ${L402_IDENTIFIER_V0_LENGTH} bytes, got ${identifier.length}`
		);
	}
	const version = identifier.readUInt16BE(0);
	if (version !== L402_IDENTIFIER_VERSION_0) {
		throw new Error(`L402 identifier: unsupported version ${version}`);
	}
	return {
		version,
		paymentHash: Buffer.from(identifier.subarray(2, 34)),
		tokenId: Buffer.from(identifier.subarray(34, 66))
	};
}

/**
 * The payment hash a macaroon commits to, or null when the macaroon cannot be
 * parsed as an L402 token.
 *
 * Returning null rather than throwing lets the caller decide: the default is
 * to refuse the payment, but a caller that has explicitly opted out of the
 * commitment check can proceed.
 */
export function macaroonPaymentHash(base64Macaroon: string): Buffer | null {
	try {
		return parseL402Identifier(parseMacaroon(base64Macaroon).identifier)
			.paymentHash;
	} catch {
		return null;
	}
}
