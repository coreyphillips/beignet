/**
 * The direct-funding payment request envelope, v3 (rev 2 "The payment request
 * envelope"). Mint, encode, decode, verify, and the BIP 21 parameter that
 * carries it.
 *
 * Fixed layout, base64url, unpadded:
 *
 *   0   u8   version (3)
 *   1   16   request_id
 *   17  32   chain_hash
 *   49  33   receiver_node_id
 *   82  u48  expires_at (milliseconds since epoch)
 *   88  u8   flags (bit 0: amount_sat present)
 *   89  u64  amount_sat, when bit 0 is set
 *   +0  32   receipt_hash
 *   +32 33   encryption_key
 *   +65 u8   num_transports, then length-prefixed descriptors
 *   tail 65  signature
 *
 * Two encoding rules are contract rather than taste. The parameter is
 * UNPADDED base64url because the LFBW dashboard gates it on
 * /^[A-Za-z0-9_-]+$/ and drops the whole parameter on a single '='; the
 * payer then silently gets a plain on-chain address instead. And the first
 * seven fields cannot be reordered because the same decoder reads the node id
 * at byte 49, the expiry at 82 and the amount at 89 by hand, inside a
 * try/catch that swallows everything, so a reordering does not fail there, it
 * displays a wrong node id. Any new field goes after the transports or behind
 * a new version byte.
 */

import {
	verifyMessageSignature,
	zbase32Decode,
	zbase32Encode
} from '../crypto/message-signing';
import { isValidPublicKey } from '../crypto/ecdh';
import {
	ByteReader,
	DF_BIP21_PARAM,
	DF_CHAIN_HASH_BYTES,
	DF_ENVELOPE_MIN_BYTES,
	DF_ENVELOPE_VERSION,
	DF_MAX_AMOUNT_SAT,
	DF_MAX_BLINDED_HOPS,
	DF_MAX_ENVELOPE_BYTES,
	DF_MAX_EXPIRES_AT,
	DF_MAX_REQUEST_TTL_MS,
	DF_MAX_TRANSPORTS,
	DF_NODE_ID_BYTES,
	DF_RECEIPT_HASH_BYTES,
	DF_REQUEST_ID_BYTES,
	DF_SIGNATURE_BYTES,
	DfTransportDescriptor,
	DfTransportType,
	DirectFundingError,
	DirectFundingErrorCode,
	IDfRequestEnvelope,
	IDfUnknownTransport,
	isUnknownTransport,
	malformed
} from './types';

/** The version tag the signed message carries, ahead of the envelope bytes. */
const SIGNED_MESSAGE_PREFIX = 'beignet-df-req:v3:';

/** Bit 0 of `flags`; every other bit is ignored on read and zero on write. */
const FLAG_AMOUNT_PRESENT = 1;

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Types this module may put into an envelope it signs. Type 4 is reserved for
 * the deferred rendezvous transport (#533): decoded and skipped, never
 * emitted, so it stays claimable by whatever implements it.
 */
const EMITTABLE_TRANSPORTS: ReadonlySet<number> = new Set([
	DfTransportType.DIRECT_PEER,
	DfTransportType.ONION_MESSAGE,
	DfTransportType.LSP_RELAY
]);

// ─────────────── base64url ───────────────

/**
 * Decode the exact alphabet the dashboard accepts. Node's base64url decoder
 * is lenient: it takes padding and skips characters outside the alphabet, so
 * a string the dashboard would drop entirely would decode here into something
 * that looks like a valid request. Re-encoding pins the canonical form,
 * which also refuses a trailing group carrying non-zero unused bits.
 */
function decodeBase64Url(text: string): Buffer {
	if (!BASE64URL_RE.test(text)) {
		throw malformed(
			'payment request must be unpadded base64url (A-Z a-z 0-9 - _)'
		);
	}
	const buf = Buffer.from(text, 'base64url');
	if (buf.toString('base64url') !== text) {
		throw malformed('payment request is not canonical base64url');
	}
	return buf;
}

// ─────────────── Encoding ───────────────

function u8(n: number): Buffer {
	return Buffer.from([n & 0xff]);
}

function u16(n: number, what: string): Buffer {
	if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
		throw malformed(`${what} must be a u16, got ${n}`);
	}
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n, 0);
	return b;
}

/**
 * Every fixed-width field is asserted at ENCODE. The fork wrote
 * `Buffer.from(hex, 'hex')` straight into the layout while the decoder read
 * fixed widths, so a short hex string produced a mis-framed envelope that was
 * then signed in that state and decoded as garbage by the payer.
 */
function fixed(value: Buffer, length: number, what: string): Buffer {
	if (value.length !== length) {
		throw malformed(`${what} must be ${length} bytes, got ${value.length}`);
	}
	return value;
}

function pubkey(value: Buffer, what: string): Buffer {
	fixed(value, DF_NODE_ID_BYTES, what);
	if (!isValidPublicKey(value)) {
		throw malformed(`${what} is not a valid compressed secp256k1 point`);
	}
	return value;
}

function hostField(host: string, port: number): Buffer {
	const h = Buffer.from(host, 'utf8');
	if (h.length > 0xff) {
		throw malformed(`transport host is ${h.length} bytes, max 255`);
	}
	return Buffer.concat([u8(h.length), h, u16(port, 'transport port')]);
}

/** One `u8 type || u16 value_length || value` descriptor. */
export function encodeTransportDescriptor(t: DfTransportDescriptor): Buffer {
	let value: Buffer;
	if (isUnknownTransport(t)) {
		// Only reachable for a descriptor we decoded and did not implement;
		// mintRequestEnvelope refuses to emit one.
		value = t.value;
	} else if (t.type === DfTransportType.DIRECT_PEER) {
		value = hostField(t.host, t.port);
	} else if (t.type === DfTransportType.ONION_MESSAGE) {
		if (t.hops.length > DF_MAX_BLINDED_HOPS) {
			throw malformed(`onion transport has ${t.hops.length} hops, max 8`);
		}
		const parts = [
			hostField(t.host, t.port),
			pubkey(t.introNodeId, 'intro node id'),
			pubkey(t.pathKey, 'path key'),
			u8(t.hops.length)
		];
		for (const hop of t.hops) {
			parts.push(
				fixed(hop.blindedNodeId, DF_NODE_ID_BYTES, 'blinded node id'),
				u16(hop.encryptedData.length, 'blinded hop data length'),
				hop.encryptedData
			);
		}
		value = Buffer.concat(parts);
	} else if (t.type === DfTransportType.LSP_RELAY) {
		value = Buffer.concat([
			pubkey(t.relayNodeId, 'relay node id'),
			hostField(t.host, t.port)
		]);
	} else {
		// The only descriptor this module emits for a type it does not
		// implement is one it decoded, verbatim, above. Reaching here means a
		// caller built a structured descriptor under an unimplemented type,
		// reserved type 4 included, and guessing a layout for it would sign
		// bytes no reader can interpret.
		throw malformed(
			`cannot encode transport type ${(t as IDfUnknownTransport).type}`
		);
	}
	if (!Number.isInteger(t.type) || t.type < 0 || t.type > 0xff) {
		throw malformed(`transport type must be a u8, got ${t.type}`);
	}
	return Buffer.concat([
		u8(t.type),
		u16(value.length, 'transport value length'),
		value
	]);
}

/** The envelope bytes with the signature omitted: what the node key signs. */
export function encodeUnsignedEnvelope(
	env: Omit<IDfRequestEnvelope, 'signature' | 'signedBytes'>
): Buffer {
	if (env.version !== DF_ENVELOPE_VERSION) {
		throw new DirectFundingError(
			DirectFundingErrorCode.UNSUPPORTED_VERSION,
			`cannot encode envelope version ${env.version}`
		);
	}
	if (
		!Number.isInteger(env.expiresAt) ||
		env.expiresAt < 0 ||
		env.expiresAt > DF_MAX_EXPIRES_AT
	) {
		throw malformed(`expires_at must fit a u48, got ${env.expiresAt}`);
	}
	const expiry = Buffer.alloc(6);
	expiry.writeUIntBE(env.expiresAt, 0, 6);
	const parts: Buffer[] = [
		u8(DF_ENVELOPE_VERSION),
		fixed(env.requestId, DF_REQUEST_ID_BYTES, 'request id'),
		fixed(env.chainHash, DF_CHAIN_HASH_BYTES, 'chain hash'),
		pubkey(env.receiverNodeId, 'receiver node id'),
		expiry
	];
	if (env.amountSat !== undefined) {
		if (env.amountSat <= 0n || env.amountSat > DF_MAX_AMOUNT_SAT) {
			throw malformed(`amount_sat out of range: ${env.amountSat}`);
		}
		const amount = Buffer.alloc(8);
		amount.writeBigUInt64BE(env.amountSat, 0);
		parts.push(u8(FLAG_AMOUNT_PRESENT), amount);
	} else {
		parts.push(u8(0));
	}
	if (env.transports.length > 0xff) {
		throw malformed(`${env.transports.length} transports, max 255`);
	}
	parts.push(
		fixed(env.receiptHash, DF_RECEIPT_HASH_BYTES, 'receipt hash'),
		pubkey(env.encryptionKey, 'encryption key'),
		u8(env.transports.length)
	);
	for (const t of env.transports) {
		parts.push(encodeTransportDescriptor(t));
	}
	return Buffer.concat(parts);
}

/** The exact ASCII string the receiver's node identity key signs. */
export function canonicalRequestMessage(unsignedBytes: Buffer): string {
	return SIGNED_MESSAGE_PREFIX + unsignedBytes.toString('base64url');
}

export interface IDfEnvelopeMintParams {
	requestId: Buffer;
	chainHash: Buffer;
	receiverNodeId: Buffer;
	expiresAt: number;
	amountSat?: bigint;
	receiptHash: Buffer;
	encryptionKey: Buffer;
	transports: DfTransportDescriptor[];
}

/**
 * Mint a signed envelope.
 *
 * @param params Envelope fields; every fixed-width one is length checked.
 * @param signMessage Signs with the node identity key and returns the zbase32
 *   signature, i.e. `LightningNode.signMessage`. The identity key signs the
 *   envelope and the funding attestation and nothing else: the per-request
 *   key does all sealing.
 * @param now Clock, for the expiry bounds.
 */
export function mintRequestEnvelope(
	params: IDfEnvelopeMintParams,
	signMessage: (message: string) => string,
	now: number = Date.now()
): IDfRequestEnvelope {
	if (params.expiresAt <= now) {
		throw new DirectFundingError(
			DirectFundingErrorCode.EXPIRED,
			'cannot mint a request that has already expired'
		);
	}
	if (params.expiresAt - now > DF_MAX_REQUEST_TTL_MS) {
		throw new DirectFundingError(
			DirectFundingErrorCode.EXPIRY_TOO_DISTANT,
			`request lifetime exceeds the ${DF_MAX_REQUEST_TTL_MS} ms maximum`
		);
	}
	if (params.transports.length > DF_MAX_TRANSPORTS) {
		throw malformed(
			`${params.transports.length} transports, max ${DF_MAX_TRANSPORTS}`
		);
	}
	for (const t of params.transports) {
		// Type, not shape: a JS caller can hand us a relay-shaped object under
		// reserved type 4, which carries no `value` and so is not "unknown".
		if (isUnknownTransport(t) || !EMITTABLE_TRANSPORTS.has(t.type)) {
			throw malformed(`refusing to mint unimplemented transport ${t.type}`);
		}
	}
	const unsigned = { version: DF_ENVELOPE_VERSION, ...params };
	const signedBytes = encodeUnsignedEnvelope(unsigned);
	const signature = zbase32Decode(
		signMessage(canonicalRequestMessage(signedBytes))
	);
	if (!signature || signature.length !== DF_SIGNATURE_BYTES) {
		throw malformed('signer did not return a 65-byte node signature');
	}
	return { ...unsigned, signature, signedBytes };
}

/** The wire form: unsigned bytes, signature, unpadded base64url. */
export function encodeRequestEnvelope(env: IDfRequestEnvelope): string {
	fixed(env.signature, DF_SIGNATURE_BYTES, 'signature');
	return Buffer.concat([env.signedBytes, env.signature]).toString('base64url');
}

// ─────────────── Decoding ───────────────

/**
 * Parse one descriptor value. A known type is read by its prefix and any
 * trailing bytes inside the descriptor are ignored, so a later revision may
 * extend a value without invalidating envelopes for decoders that predate it;
 * a value too SHORT to hold the fields it claims is malformed.
 */
function decodeTransportValue(
	type: number,
	value: Buffer
): DfTransportDescriptor {
	const r = new ByteReader(value);
	if (type === DfTransportType.DIRECT_PEER) {
		const host = r.take(r.u8('host length'), 'host').toString('utf8');
		return { type: DfTransportType.DIRECT_PEER, host, port: r.u16('port') };
	}
	if (type === DfTransportType.ONION_MESSAGE) {
		const host = r.take(r.u8('host length'), 'host').toString('utf8');
		const port = r.u16('port');
		const introNodeId = Buffer.from(r.take(DF_NODE_ID_BYTES, 'intro node id'));
		const pathKey = Buffer.from(r.take(DF_NODE_ID_BYTES, 'path key'));
		const hopCount = r.u8('hop count');
		if (hopCount > DF_MAX_BLINDED_HOPS) {
			throw malformed(`onion transport declares ${hopCount} hops, max 8`);
		}
		const hops = [];
		for (let i = 0; i < hopCount; i++) {
			const blindedNodeId = Buffer.from(
				r.take(DF_NODE_ID_BYTES, 'blinded node id')
			);
			const encryptedData = Buffer.from(
				r.take(r.u16('hop data length'), 'hop data')
			);
			hops.push({ blindedNodeId, encryptedData });
		}
		return {
			type: DfTransportType.ONION_MESSAGE,
			host,
			port,
			introNodeId,
			pathKey,
			hops
		};
	}
	if (type === DfTransportType.LSP_RELAY) {
		const relayNodeId = Buffer.from(r.take(DF_NODE_ID_BYTES, 'relay node id'));
		const host = r.take(r.u8('host length'), 'host').toString('utf8');
		return {
			type: DfTransportType.LSP_RELAY,
			relayNodeId,
			host,
			port: r.u16('port')
		};
	}
	// Type 4 (reserved for #533) and anything else: kept verbatim, skipped by
	// its length. The bytes are retained because the receiver signed them.
	return { type, value: Buffer.from(value) };
}

/**
 * Structural decode. No expiry, signature or chain check: those are
 * `verifyRequestEnvelope`, and nothing should act on the result of this
 * function alone. Use `decodeAndVerifyRequestEnvelope`.
 */
export function decodeRequestEnvelope(encoded: string): IDfRequestEnvelope {
	if (encoded.length > DF_MAX_ENVELOPE_BYTES * 2) {
		throw malformed('payment request is too long');
	}
	const raw = decodeBase64Url(encoded);
	if (raw.length > DF_MAX_ENVELOPE_BYTES) {
		throw malformed('payment request is too long');
	}
	if (raw.length < DF_ENVELOPE_MIN_BYTES) {
		throw malformed(
			`payment request is ${raw.length} bytes, minimum ${DF_ENVELOPE_MIN_BYTES}`
		);
	}
	const version = raw[0];
	if (version !== DF_ENVELOPE_VERSION) {
		throw new DirectFundingError(
			DirectFundingErrorCode.UNSUPPORTED_VERSION,
			`unsupported payment request version ${version}`
		);
	}
	const r = new ByteReader(raw);
	r.u8('version');
	const requestId = Buffer.from(r.take(DF_REQUEST_ID_BYTES, 'request id'));
	const chainHash = Buffer.from(r.take(DF_CHAIN_HASH_BYTES, 'chain hash'));
	const receiverNodeId = Buffer.from(r.take(DF_NODE_ID_BYTES, 'node id'));
	const expiresAt = r.take(6, 'expiry').readUIntBE(0, 6);
	const flags = r.u8('flags');
	const amountSat =
		(flags & FLAG_AMOUNT_PRESENT) !== 0 ? r.u64('amount') : undefined;
	if (amountSat !== undefined && amountSat > DF_MAX_AMOUNT_SAT) {
		throw malformed(`amount_sat exceeds the money supply: ${amountSat}`);
	}
	const receiptHash = Buffer.from(
		r.take(DF_RECEIPT_HASH_BYTES, 'receipt hash')
	);
	const encryptionKey = Buffer.from(r.take(DF_NODE_ID_BYTES, 'encryption key'));
	// The only use of this field is ECDH, so a non-point is a dead request:
	// refuse it here rather than deep inside the first seal.
	if (!isValidPublicKey(encryptionKey)) {
		throw malformed('encryption key is not a valid compressed secp256k1 point');
	}
	const count = r.u8('transport count');
	const transports: DfTransportDescriptor[] = [];
	for (let i = 0; i < count; i++) {
		const type = r.u8('transport type');
		const value = r.take(r.u16('transport value length'), 'transport value');
		transports.push(decodeTransportValue(type, value));
	}
	// Everything read so far, verbatim. The signature covers these exact
	// bytes, so verification never re-encodes the parsed struct.
	const signedBytes = Buffer.from(raw.subarray(0, raw.length - r.remaining()));
	const signature = Buffer.from(r.take(DF_SIGNATURE_BYTES, 'signature'));
	if (r.remaining() !== 0) {
		throw malformed('payment request has trailing bytes');
	}
	return {
		version,
		requestId,
		chainHash,
		receiverNodeId,
		expiresAt,
		...(amountSat !== undefined ? { amountSat } : {}),
		receiptHash,
		encryptionKey,
		transports,
		signature,
		signedBytes
	};
}

export interface IDfVerifyOptions {
	/** The chain this node would pay on. Rev 2 makes the refusal a MUST. */
	expectedChainHash: Buffer;
	now?: number;
	/** Furthest expiry accepted, defaulting to DF_MAX_REQUEST_TTL_MS out. */
	maxTtlMs?: number;
}

/**
 * Verify a decoded envelope, in rev 2's order: expiry, then the signature
 * recovers a key, then that key IS the node the envelope names, then the
 * chain binding. Every one of these completes before any network activity.
 *
 * Signer equality is the whole point of step three: recovery alone
 * authenticates nothing, since a tampered message still recovers SOME key
 * (see verifyMessageSignature's own contract). Chain binding is checked HERE
 * rather than in a caller: the fork's only chain check lived in one HTTP
 * handler, so every other caller of its decoder got a signature-valid request
 * bound to no chain at all.
 */
export function verifyRequestEnvelope(
	env: IDfRequestEnvelope,
	opts: IDfVerifyOptions
): void {
	const now = opts.now ?? Date.now();
	const maxTtl = opts.maxTtlMs ?? DF_MAX_REQUEST_TTL_MS;
	if (env.expiresAt <= now) {
		throw new DirectFundingError(
			DirectFundingErrorCode.EXPIRED,
			'payment request has expired; ask the receiver for a fresh one'
		);
	}
	if (env.expiresAt - now > maxTtl) {
		throw new DirectFundingError(
			DirectFundingErrorCode.EXPIRY_TOO_DISTANT,
			'payment request expires too far in the future'
		);
	}
	const verdict = verifyMessageSignature(
		canonicalRequestMessage(env.signedBytes),
		zbase32Encode(env.signature)
	);
	if (!verdict.valid || !verdict.pubkey) {
		throw new DirectFundingError(
			DirectFundingErrorCode.INVALID_SIGNATURE,
			'payment request signature is invalid'
		);
	}
	if (!verdict.pubkey.equals(env.receiverNodeId)) {
		throw new DirectFundingError(
			DirectFundingErrorCode.WRONG_SIGNER,
			'payment request signature does not match the receiver it names'
		);
	}
	if (!env.chainHash.equals(opts.expectedChainHash)) {
		throw new DirectFundingError(
			DirectFundingErrorCode.WRONG_CHAIN,
			'payment request is for a different chain than this wallet'
		);
	}
}

/** Decode and verify. Throws a coded DirectFundingError on any failure. */
export function decodeAndVerifyRequestEnvelope(
	encoded: string,
	opts: IDfVerifyOptions
): IDfRequestEnvelope {
	const env = decodeRequestEnvelope(encoded);
	verifyRequestEnvelope(env, opts);
	return env;
}

// ─────────────── BIP 21 ───────────────

/**
 * Append the request to a BIP 21 URI. Any wallet that does not know the
 * parameter pays the plain address, which is the graceful degradation the
 * whole format is shaped around.
 */
export function bip21WithRequest(uri: string, encoded: string): string {
	if (!BASE64URL_RE.test(encoded)) {
		throw malformed('encoded request is not unpadded base64url');
	}
	return `${uri}${uri.includes('?') ? '&' : '?'}${DF_BIP21_PARAM}=${encoded}`;
}

/**
 * Pull the request out of a BIP 21 URI, or null when there is none.
 *
 * The gate is the dashboard's, character for character, so this module
 * accepts exactly what the app's decoder accepts: anything it would silently
 * drop (padding, a percent-encoded '=') must not be treated as a request
 * here either, or the two disagree about what the user is paying.
 */
export function requestFromBip21(uri: string): string | null {
	const q = uri.indexOf('?');
	if (q < 0) return null;
	for (const kv of uri.slice(q + 1).split('&')) {
		const eq = kv.indexOf('=');
		if (eq < 0) continue;
		if (kv.slice(0, eq) !== DF_BIP21_PARAM) continue;
		let value: string;
		try {
			value = decodeURIComponent(kv.slice(eq + 1));
		} catch {
			return null;
		}
		return BASE64URL_RE.test(value) ? value : null;
	}
	return null;
}
