import * as crypto from 'crypto';
import { verifyMessageSignature } from '../lightning/crypto/message-signing';
import { DfTransport } from './direct-funding';

/**
 * Direct-funding request envelope v1.
 *
 * One canonical, SIGNED payment request replaces the ad hoc BIP 21 params:
 * the receiver's Lightning node key signs the request id, expiry, funding
 * constraints, receipt hash, a per-request X25519 encryption key, and every
 * transport descriptor (host hint, swarm rendezvous, receiver Noise key).
 * A sender verifies the signature and expiry before doing ANYTHING, so a
 * tampered or stale request dies on the sender's device, and every
 * capability in the request (topic, Noise key, encryption key) is bound to
 * the Lightning identity the payment is meant for.
 *
 * The per-request X25519 key gives the protocol an application encryption
 * layer with key separation from the Lightning identity key: the same
 * sealed envelope can travel over a swarm socket, a Lightning peer relay,
 * or store-and-forward infrastructure without replumbing. Frames are
 * AES-256-GCM, keyed by ECDH(ephemeral sender key, request key) through
 * HKDF, with the request id and message subtype bound as associated data.
 */

export interface IDfTransportDescriptor {
	type: 'ln' | 'swarm';
	/** ln: a host hint the sender may reach for the identified peer path. */
	host?: string;
	port?: number;
	/** swarm: rendezvous secret (hex) the DHT topic derives from. */
	rendezvous?: string;
	/** swarm: receiver's Noise public key (hex), pinned by the sender. */
	noiseKey?: string;
}

export interface IDfRequestEnvelope {
	v: 1;
	requestId: string;
	receiverNodeId: string;
	expiresAt: number;
	/** Optional fixed amount the request asks for (sats). */
	amountSat?: number;
	receiptHash: string;
	/** Per-request X25519 public key (hex, raw 32 bytes). */
	encryptionKey: string;
	transports: IDfTransportDescriptor[];
	/** Receiver node-key signature over canonicalRequestMessage(...). */
	sig: string;
}

/** The exact string the receiver's node key signs. Deterministic. */
export function canonicalRequestMessage(
	env: Omit<IDfRequestEnvelope, 'sig'>
): string {
	const transports = env.transports
		.map((t) =>
			t.type === 'ln'
				? `ln,${t.host ?? ''},${t.port ?? ''}`
				: `swarm,${t.rendezvous ?? ''},${t.noiseKey ?? ''}`
		)
		.join('|');
	return `beignet-df-req:v1:${env.requestId}:${env.receiverNodeId}:${env.expiresAt}:${env.amountSat ?? ''}:${env.receiptHash}:${env.encryptionKey}:${transports}`;
}

export function encodeRequestEnvelope(env: IDfRequestEnvelope): string {
	return Buffer.from(JSON.stringify(env), 'utf8').toString('base64url');
}

/**
 * Decode + verify an envelope. Throws with the reason on ANY failure:
 * malformed, wrong version, expired, bad signature, or a signature that
 * recovers to a different node than the envelope names. Nothing downstream
 * runs on an unverified request.
 */
export function decodeAndVerifyRequestEnvelope(
	encoded: string
): IDfRequestEnvelope {
	let env: IDfRequestEnvelope;
	try {
		env = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
	} catch {
		throw new Error('payment request is not decodable');
	}
	if (env.v !== 1) throw new Error(`unsupported payment request version ${env.v}`);
	if (
		!/^[0-9a-f]{32}$/.test(env.requestId ?? '') ||
		!/^[0-9a-f]{66}$/.test(env.receiverNodeId ?? '') ||
		!/^[0-9a-f]{64}$/.test(env.receiptHash ?? '') ||
		!/^[0-9a-f]{64}$/.test(env.encryptionKey ?? '') ||
		!Array.isArray(env.transports) ||
		typeof env.expiresAt !== 'number'
	) {
		throw new Error('payment request is malformed');
	}
	if (Date.now() > env.expiresAt) {
		throw new Error('payment request has expired; ask the receiver for a fresh one');
	}
	const verdict = verifyMessageSignature(
		canonicalRequestMessage(env),
		env.sig
	);
	if (!verdict.valid || !verdict.pubkey) {
		throw new Error('payment request signature is invalid');
	}
	if (verdict.pubkey.toString('hex') !== env.receiverNodeId) {
		throw new Error(
			'payment request signature does not match the receiver it names'
		);
	}
	return env;
}

// ─────────────── Per-request encryption ───────────────

const HKDF_INFO = 'beignet-df-v1';

function x25519PublicFromRaw(raw: Buffer): crypto.KeyObject {
	return crypto.createPublicKey({
		key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') },
		format: 'jwk'
	});
}

export interface IRequestEncryptionKeys {
	/** Raw public key hex, published in the envelope. */
	publicKeyHex: string;
	/** PKCS8 PEM of the private key, held by the receiver until expiry. */
	privateKeyPem: string;
}

export function mintRequestEncryptionKeys(): IRequestEncryptionKeys {
	const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
	const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
	return {
		publicKeyHex: Buffer.from(jwk.x, 'base64url').toString('hex'),
		privateKeyPem: privateKey
			.export({ type: 'pkcs8', format: 'pem' })
			.toString()
	};
}

function deriveKey(sharedSecret: Buffer, requestIdHex: string): Buffer {
	return Buffer.from(
		crypto.hkdfSync(
			'sha256',
			sharedSecret,
			Buffer.from(requestIdHex, 'hex'),
			HKDF_INFO,
			32
		)
	);
}

/** Sender side: ephemeral ECDH against the request's public key. */
export function senderDeriveKey(
	requestPublicKeyHex: string,
	requestIdHex: string
): { key: Buffer; ephemeralPublicHex: string } {
	const eph = crypto.generateKeyPairSync('x25519');
	const shared = crypto.diffieHellman({
		privateKey: eph.privateKey,
		publicKey: x25519PublicFromRaw(Buffer.from(requestPublicKeyHex, 'hex'))
	});
	const jwk = eph.publicKey.export({ format: 'jwk' }) as { x: string };
	return {
		key: deriveKey(shared, requestIdHex),
		ephemeralPublicHex: Buffer.from(jwk.x, 'base64url').toString('hex')
	};
}

/** Receiver side: the request's private key against the sender ephemeral. */
export function receiverDeriveKey(
	privateKeyPem: string,
	ephemeralPublicHex: string,
	requestIdHex: string
): Buffer {
	const shared = crypto.diffieHellman({
		privateKey: crypto.createPrivateKey(privateKeyPem),
		publicKey: x25519PublicFromRaw(Buffer.from(ephemeralPublicHex, 'hex'))
	});
	return deriveKey(shared, requestIdHex);
}

function aad(requestIdHex: string, subtype: number): Buffer {
	const st = Buffer.alloc(2);
	st.writeUInt16BE(subtype, 0);
	return Buffer.concat([Buffer.from(requestIdHex, 'hex'), st]);
}

export function seal(
	key: Buffer,
	requestIdHex: string,
	subtype: number,
	payload: object
): { n: string; c: string } {
	const nonce = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
	cipher.setAAD(aad(requestIdHex, subtype));
	const ct = Buffer.concat([
		cipher.update(Buffer.from(JSON.stringify(payload), 'utf8')),
		cipher.final(),
		cipher.getAuthTag()
	]);
	return { n: nonce.toString('hex'), c: ct.toString('hex') };
}

export function open(
	key: Buffer,
	requestIdHex: string,
	subtype: number,
	frame: { n: string; c: string }
): Buffer {
	const nonce = Buffer.from(frame.n, 'hex');
	const ct = Buffer.from(frame.c, 'hex');
	const tag = ct.subarray(ct.length - 16);
	const body = ct.subarray(0, ct.length - 16);
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
	decipher.setAAD(aad(requestIdHex, subtype));
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(body), decipher.final()]);
}

/**
 * Wrap a transport so every frame is sealed to the per-request key. The
 * FIRST outbound frame (the sender's offer) additionally carries the
 * request id and the sender's ephemeral public key in the clear, which is
 * everything the receiver needs to derive the same key; every subsequent
 * frame in either direction is just {n, c}.
 */
export function encryptedTransport(
	inner: DfTransport,
	key: Buffer,
	requestIdHex: string,
	firstFrame?: { ephemeralPublicHex: string }
): DfTransport {
	let first = firstFrame;
	return {
		send: (subtype, payload) => {
			const sealed = seal(key, requestIdHex, subtype, payload);
			if (first) {
				inner.send(subtype, {
					requestId: requestIdHex,
					eph: first.ephemeralPublicHex,
					...sealed
				});
				first = undefined;
				return;
			}
			inner.send(subtype, sealed);
		},
		onMessage: (cb) =>
			inner.onMessage((subtype, payload) => {
				try {
					const frame = JSON.parse(payload.toString('utf8'));
					if (typeof frame?.n !== 'string' || typeof frame?.c !== 'string') {
						return; // not a sealed frame for this lane
					}
					cb(subtype, open(key, requestIdHex, subtype, frame));
				} catch {
					// Tampered or foreign frame: drop it. GCM authenticated it away.
				}
			})
	};
}
