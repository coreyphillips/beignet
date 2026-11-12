/**
 * Porch: a blind relay for Lightning peer connections (protocol v1).
 *
 * A node at home (the host) dials out to a relay and waits there. A visitor
 * connects to the relay with an ordinary `pubkey@wss://relay/v1/p/<routeId>`
 * peer URI, the relay pairs the two and copies bytes. The bytes are BOLT 8,
 * so the relay can neither read them nor stand in for either side, and the
 * visitor never learns where the host runs. docs/PORCH-PROTOCOL.md is the
 * specification; this module is everything both the host and the relay need
 * to agree on, and uses no Node built-ins.
 */

import { getPublicKey, sign, verify } from '../crypto/ecdh';
import { hkdf } from '../crypto/hkdf';
import { sha256 } from '../crypto/provider';

export const PORCH_VERSION = 1;
/** Where a host opens a standby connection. */
export const PORCH_HOST_PATH = '/v1/host';
/** A visitor connects to this prefix followed by a route id. */
export const PORCH_VISITOR_PATH_PREFIX = '/v1/p/';
export const PORCH_TAG_BYTES = 16;
export const PORCH_NONCE_BYTES = 32;
/** Links one host can have live at a time. */
export const PORCH_MAX_TAGS = 256;
/** A registration naming 256 tags is about 9 KiB. */
export const PORCH_MAX_CONTROL_BYTES = 32 * 1024;
export const PORCH_MAX_TOKEN_BYTES = 256;
/**
 * WebSocket close codes with a meaning of their own here (RFC 6455 section
 * 7.4.1). 1008: the relay refuses this registration, and the same one will
 * be refused again. 1013: nothing is wrong with the request, there is no
 * room or no standby for it right now.
 */
export const PORCH_CLOSE_REFUSED = 1008;
export const PORCH_CLOSE_TRY_LATER = 1013;
const MAX_AUTHORITY_BYTES = 255;

export interface IPorchChallenge {
	t: 'challenge';
	v: number;
	/** 32 bytes, hex. Fresh for every standby connection. */
	nonce: string;
	/** The relay's own public name, as it is configured. */
	authority: string;
}

export interface IPorchRegister {
	t: 'register';
	v: number;
	/** The host key: a 33-byte compressed secp256k1 point, hex. */
	key: string;
	/** Every link this standby serves: 16-byte tags, hex, ascending. */
	tags: string[];
	/** Compact ECDSA by the host key over porchRegisterDigest, hex. */
	sig: string;
	/** For a relay that asks for one. */
	token?: string;
}

export type PorchControlMessage =
	| IPorchChallenge
	| IPorchRegister
	| { t: 'ready' }
	| { t: 'paired'; tag: string }
	| { t: 'ping' }
	| { t: 'pong' };

const HEX = /^[0-9a-f]*$/;
function isHex(value: unknown, bytes: number): value is string {
	return (
		typeof value === 'string' && value.length === bytes * 2 && HEX.test(value)
	);
}

// ─── Keys and identifiers ──────────────────────────────────────

function derive(seed: Uint8Array, info: string, length: number): Buffer {
	if (seed.length < 16) throw new Error('Porch needs a wallet seed');
	return hkdf(Buffer.alloc(32), Buffer.from(seed), Buffer.from(info), length);
}

/**
 * The host's secret key: HKDF-SHA256 from the wallet seed. It is not the
 * Lightning key and cannot be derived from it, so a relay that sees the host
 * key learns nothing about which node it serves.
 */
export function derivePorchHostSecret(seed: Uint8Array): Buffer {
	const secret = derive(seed, 'beignet/porch/host/v1', 32);
	// Throws for the two-in-2^128 outputs that are not a valid scalar.
	getPublicKey(secret);
	return secret;
}

/** The tag of the link every host has without creating one. */
export function derivePorchDefaultTag(seed: Uint8Array): Buffer {
	return derive(seed, 'beignet/porch/link/default/v1', PORCH_TAG_BYTES);
}

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
/** RFC 4648 base32, lower case, no padding. */
function base32(bytes: Uint8Array): string {
	let out = '';
	let bits = 0;
	let value = 0;
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += BASE32[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
		value &= (1 << bits) - 1;
	}
	if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
	return out;
}

/**
 * What a visitor's URL carries in place of the host key and the tag:
 * 32 characters. Two links of one host share nothing a visitor can see.
 */
export function porchRouteId(hostKey: Uint8Array, tag: Uint8Array): string {
	if (hostKey.length !== 33) throw new Error('Porch host key must be 33 bytes');
	if (tag.length !== PORCH_TAG_BYTES) {
		throw new Error(`Porch link tag must be ${PORCH_TAG_BYTES} bytes`);
	}
	return base32(
		sha256(
			Buffer.concat([Buffer.from('porch/route/v1'), hostKey, tag])
		).subarray(0, 20)
	);
}

export function isPorchRouteId(value: unknown): value is string {
	return typeof value === 'string' && /^[a-z2-7]{32}$/.test(value);
}

// ─── Relay addresses ───────────────────────────────────────────

export interface IPorchRelayAddress {
	secure: boolean;
	/** Lower case; an IPv6 literal without its brackets. */
	host: string;
	port: number;
	/**
	 * The name both sides sign: the host, with the port unless it is the
	 * scheme's default.
	 */
	authority: string;
	/** `ws(s)://authority`, with no path. */
	origin: string;
}

/**
 * Parse a relay's base URL. Only the scheme, host and port matter: a relay
 * serves fixed paths, so a URL with a path, query or credentials is refused
 * rather than silently trimmed.
 */
export function parsePorchRelayUrl(url: string): IPorchRelayAddress {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error(`Invalid Porch relay URL: ${url}`);
	}
	if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
		throw new Error(`Porch relay URL must be ws:// or wss://: ${url}`);
	}
	if (
		(parsed.pathname !== '' && parsed.pathname !== '/') ||
		parsed.search ||
		parsed.hash ||
		parsed.username ||
		parsed.password
	) {
		throw new Error(`Porch relay URL must be a scheme, host and port: ${url}`);
	}
	const secure = parsed.protocol === 'wss:';
	// URL lower-cases the host and drops a port that is the scheme's default.
	const port = parsed.port ? parseInt(parsed.port, 10) : secure ? 443 : 80;
	if (!parsed.hostname || !Number.isInteger(port) || port <= 0) {
		throw new Error(`Invalid Porch relay URL: ${url}`);
	}
	const authority = parsed.host;
	if (Buffer.byteLength(authority) > MAX_AUTHORITY_BYTES) {
		throw new Error(`Porch relay name is too long: ${url}`);
	}
	return {
		secure,
		host: parsed.hostname.replace(/^\[|\]$/g, ''),
		port,
		authority,
		origin: `${secure ? 'wss' : 'ws'}://${authority}`
	};
}

/** The URL a host dials for a standby. */
export function porchHostUrl(relay: IPorchRelayAddress): string {
	return relay.origin + PORCH_HOST_PATH;
}

/** The peer URI to hand out for one link. */
export function porchLink(
	nodeId: string,
	relay: IPorchRelayAddress,
	routeId: string
): string {
	if (!isHex(nodeId, 33)) throw new Error('Invalid node id');
	if (!isPorchRouteId(routeId)) throw new Error('Invalid Porch route id');
	return `${nodeId}@${relay.origin}${PORCH_VISITOR_PATH_PREFIX}${routeId}`;
}

// ─── Registration ──────────────────────────────────────────────

/** Sorted ascending and distinct, as a registration must list them. */
function sortedTags(tags: readonly Uint8Array[]): Buffer[] {
	if (tags.length < 1 || tags.length > PORCH_MAX_TAGS) {
		throw new Error(`A Porch host serves 1 to ${PORCH_MAX_TAGS} links`);
	}
	const sorted = tags.map((tag) => {
		if (tag.length !== PORCH_TAG_BYTES) {
			throw new Error(`Porch link tag must be ${PORCH_TAG_BYTES} bytes`);
		}
		return Buffer.from(tag);
	});
	sorted.sort(Buffer.compare);
	for (let i = 1; i < sorted.length; i++) {
		if (sorted[i].equals(sorted[i - 1])) {
			throw new Error('Porch link tags must be distinct');
		}
	}
	return sorted;
}

/**
 * What the host key signs. The nonce stops a replay; the authority stops one
 * relay from registering the host at another; the tag list is the whole of
 * what the relay will route to this connection.
 */
export function porchRegisterDigest(
	nonce: Uint8Array,
	authority: string,
	tags: readonly Uint8Array[]
): Buffer {
	if (nonce.length !== PORCH_NONCE_BYTES) {
		throw new Error(`Porch nonce must be ${PORCH_NONCE_BYTES} bytes`);
	}
	const name = Buffer.from(authority, 'utf8');
	if (name.length < 1 || name.length > MAX_AUTHORITY_BYTES) {
		throw new Error('Porch relay name must be 1 to 255 bytes');
	}
	return sha256(
		Buffer.concat([
			Buffer.from('porch/register/v1'),
			nonce,
			Buffer.from([name.length]),
			name,
			sha256(Buffer.concat(tags.map((tag) => Buffer.from(tag))))
		])
	);
}

/**
 * The host's answer to a challenge. `authority` is the name of the relay the
 * host dialed: the caller compares it with the challenge's before calling,
 * and it is what gets signed either way.
 */
export function createPorchRegister(input: {
	hostSecret: Uint8Array;
	nonce: Uint8Array;
	authority: string;
	tags: readonly Uint8Array[];
	token?: string;
}): IPorchRegister {
	const secret = Buffer.from(input.hostSecret);
	const tags = sortedTags(input.tags);
	return {
		t: 'register',
		v: PORCH_VERSION,
		key: getPublicKey(secret).toString('hex'),
		tags: tags.map((tag) => tag.toString('hex')),
		sig: sign(
			porchRegisterDigest(input.nonce, input.authority, tags),
			secret
		).toString('hex'),
		...(input.token !== undefined ? { token: input.token } : {})
	};
}

export interface IPorchRegistration {
	hostKey: Buffer;
	/** Ascending. */
	tags: Buffer[];
	/** The route id of each tag, in the same order. */
	routeIds: string[];
	token?: string;
}

/**
 * The relay's check of a registration against the challenge it sent on this
 * connection. Returns why it is refused, as a short string, or what it
 * registers.
 */
export function checkPorchRegister(
	message: IPorchRegister,
	challenge: { nonce: Uint8Array; authority: string },
	maxTags = PORCH_MAX_TAGS
): IPorchRegistration | { refused: string } {
	if (message.v !== PORCH_VERSION) return { refused: 'unsupported version' };
	if (message.tags.length > maxTags) return { refused: 'too many links' };
	const tags = message.tags.map((tag) => Buffer.from(tag, 'hex'));
	for (let i = 1; i < tags.length; i++) {
		if (Buffer.compare(tags[i - 1], tags[i]) >= 0) {
			return { refused: 'links are not sorted and distinct' };
		}
	}
	const hostKey = Buffer.from(message.key, 'hex');
	const digest = porchRegisterDigest(
		challenge.nonce,
		challenge.authority,
		tags
	);
	if (!verify(digest, hostKey, Buffer.from(message.sig, 'hex'), true)) {
		return { refused: 'bad signature' };
	}
	return {
		hostKey,
		tags,
		routeIds: tags.map((tag) => porchRouteId(hostKey, tag)),
		...(message.token !== undefined ? { token: message.token } : {})
	};
}

// ─── Control messages ──────────────────────────────────────────

export function encodePorchControl(message: PorchControlMessage): string {
	return JSON.stringify(message);
}

/**
 * Parse one control message. Anything that is not exactly a known message
 * with well-formed fields is undefined: the two ends of a control channel do
 * not trust each other, and a caller closes the connection on undefined.
 * Fields this version does not know are ignored.
 */
export function decodePorchControl(
	text: string
): PorchControlMessage | undefined {
	if (typeof text !== 'string' || text.length > PORCH_MAX_CONTROL_BYTES) {
		return undefined;
	}
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return undefined;
	}
	const m = value as Record<string, unknown>;
	switch (m.t) {
		case 'ready':
		case 'ping':
		case 'pong':
			return { t: m.t };
		case 'paired':
			return isHex(m.tag, PORCH_TAG_BYTES)
				? { t: 'paired', tag: m.tag }
				: undefined;
		case 'challenge':
			if (
				!Number.isInteger(m.v) ||
				!isHex(m.nonce, PORCH_NONCE_BYTES) ||
				typeof m.authority !== 'string' ||
				m.authority.length < 1 ||
				Buffer.byteLength(m.authority) > MAX_AUTHORITY_BYTES
			) {
				return undefined;
			}
			return {
				t: 'challenge',
				v: m.v as number,
				nonce: m.nonce,
				authority: m.authority
			};
		case 'register': {
			if (
				!Number.isInteger(m.v) ||
				!isHex(m.key, 33) ||
				!isHex(m.sig, 64) ||
				!Array.isArray(m.tags) ||
				m.tags.length < 1 ||
				m.tags.length > PORCH_MAX_TAGS ||
				!m.tags.every((tag) => isHex(tag, PORCH_TAG_BYTES))
			) {
				return undefined;
			}
			if (
				m.token !== undefined &&
				(typeof m.token !== 'string' ||
					Buffer.byteLength(m.token) > PORCH_MAX_TOKEN_BYTES)
			) {
				return undefined;
			}
			return {
				t: 'register',
				v: m.v as number,
				key: m.key,
				tags: m.tags as string[],
				sig: m.sig,
				...(m.token !== undefined ? { token: m.token as string } : {})
			};
		}
		default:
			return undefined;
	}
}
