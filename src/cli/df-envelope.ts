import * as crypto from 'crypto';
import {
	verifyMessageSignature,
	zbase32Encode,
	zbase32Decode
} from '../lightning/crypto/message-signing';
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

/** A blinded path in envelope form: all fields hex. */
export interface ISerializedBlindedPath {
	intro: string;
	blinding: string;
	hops: Array<{ id: string; data: string }>;
}

export interface IDfTransportDescriptor {
	type: 'ln' | 'onion' | 'lsp' | 'swarm';
	/** ln: a host hint the sender may reach for the identified peer path.
	 *  onion: the introduction node's reachable address.
	 *  lsp: the relay's reachable address. */
	host?: string;
	port?: number;
	/** lsp: the relay's Lightning node id; frames route through it blind. */
	nodeId?: string;
	/** onion: blinded path to the receiver; path_id is the request id. */
	path?: ISerializedBlindedPath;
	/** swarm: rendezvous secret (hex) the DHT topic derives from. */
	rendezvous?: string;
	/** swarm: receiver's Noise public key (hex), pinned by the sender. */
	noiseKey?: string;
}

export interface IDfRequestEnvelope {
	v: 2;
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

// ─────────────── Compact binary encoding ───────────────
//
// The envelope rides in a BIP 21 param that must fit a scannable QR, so it
// is encoded as compact binary, base64url once. The JSON-of-hex form cost
// about 2.7x the bytes and pushed real requests toward the QR ceiling.
//
//   u8   version (2)
//   16B  requestId
//   33B  receiverNodeId
//   u48  expiresAt (ms)
//   u8   flags (bit0: amountSat present)
//   [u64 amountSat]
//   32B  receiptHash
//   32B  encryptionKey
//   u8   transport count, then per transport a u8 type tag:
//     1 ln:    u8 hostLen, host, u16 port
//     2 onion: u8 hostLen, host, u16 port, 33B intro, 33B blinding,
//              u8 hopCount, per hop: 33B id, u16 dataLen, data
//     3 lsp:   33B nodeId, u8 hostLen, host, u16 port
//     4 swarm: 32B rendezvous, 32B noiseKey
//   65B  sig (compact recoverable, the zbase32 signature decoded)

const TRANSPORT_TAGS: Record<string, number> = {
	ln: 1,
	onion: 2,
	lsp: 3,
	swarm: 4
};

function encodeUnsignedBytes(env: Omit<IDfRequestEnvelope, 'sig'>): Buffer {
	const parts: Buffer[] = [];
	const u8 = (n: number): Buffer => Buffer.from([n]);
	const u16 = (n: number): Buffer => {
		const b = Buffer.alloc(2);
		b.writeUInt16BE(n);
		return b;
	};
	const hostField = (host?: string, port?: number): Buffer => {
		const h = Buffer.from(host ?? '', 'utf8');
		if (h.length > 255) throw new Error('host too long');
		return Buffer.concat([u8(h.length), h, u16(port ?? 0)]);
	};
	parts.push(u8(2));
	parts.push(Buffer.from(env.requestId, 'hex'));
	parts.push(Buffer.from(env.receiverNodeId, 'hex'));
	const exp = Buffer.alloc(6);
	exp.writeUIntBE(env.expiresAt, 0, 6);
	parts.push(exp);
	parts.push(u8(env.amountSat ? 1 : 0));
	if (env.amountSat) {
		const amt = Buffer.alloc(8);
		amt.writeBigUInt64BE(BigInt(env.amountSat));
		parts.push(amt);
	}
	parts.push(Buffer.from(env.receiptHash, 'hex'));
	parts.push(Buffer.from(env.encryptionKey, 'hex'));
	parts.push(u8(env.transports.length));
	for (const t of env.transports) {
		const tag = TRANSPORT_TAGS[t.type];
		if (!tag) throw new Error(`unknown transport type ${t.type}`);
		parts.push(u8(tag));
		if (t.type === 'ln') {
			parts.push(hostField(t.host, t.port));
		} else if (t.type === 'onion') {
			if (!t.path) throw new Error('onion transport without path');
			parts.push(hostField(t.host, t.port));
			parts.push(Buffer.from(t.path.intro, 'hex'));
			parts.push(Buffer.from(t.path.blinding, 'hex'));
			parts.push(u8(t.path.hops.length));
			for (const hop of t.path.hops) {
				const data = Buffer.from(hop.data, 'hex');
				parts.push(Buffer.from(hop.id, 'hex'), u16(data.length), data);
			}
		} else if (t.type === 'lsp') {
			parts.push(Buffer.from(t.nodeId ?? '', 'hex'));
			parts.push(hostField(t.host, t.port));
		} else {
			parts.push(Buffer.from(t.rendezvous ?? '', 'hex'));
			parts.push(Buffer.from(t.noiseKey ?? '', 'hex'));
		}
	}
	return Buffer.concat(parts);
}

/** The exact string the receiver's node key signs: the version tag plus
 *  the full unsigned binary body, so every field is covered. */
export function canonicalRequestMessage(
	env: Omit<IDfRequestEnvelope, 'sig'>
): string {
	return `beignet-df-req:v2:${encodeUnsignedBytes(env).toString('base64url')}`;
}

export function encodeRequestEnvelope(env: IDfRequestEnvelope): string {
	const sig = zbase32Decode(env.sig);
	if (!sig || sig.length !== 65) {
		throw new Error('envelope signature is not a valid node signature');
	}
	return Buffer.concat([encodeUnsignedBytes(env), sig]).toString('base64url');
}

class ByteReader {
	private off = 0;
	constructor(private readonly buf: Buffer) {}
	take(n: number): Buffer {
		if (this.off + n > this.buf.length) {
			throw new Error('payment request is malformed');
		}
		const out = this.buf.subarray(this.off, this.off + n);
		this.off += n;
		return out;
	}
	u8(): number {
		return this.take(1)[0];
	}
	u16(): number {
		return this.take(2).readUInt16BE();
	}
	remaining(): number {
		return this.buf.length - this.off;
	}
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
	let env: Omit<IDfRequestEnvelope, 'sig'>;
	let sigBytes: Buffer;
	try {
		const raw = Buffer.from(encoded, 'base64url');
		const r = new ByteReader(raw);
		const v = r.u8();
		if (v !== 2) {
			throw new Error(`unsupported payment request version ${v}`);
		}
		const requestId = r.take(16).toString('hex');
		const receiverNodeId = r.take(33).toString('hex');
		const expiresAt = r.take(6).readUIntBE(0, 6);
		const flags = r.u8();
		const amountSat =
			flags & 1 ? Number(r.take(8).readBigUInt64BE()) : undefined;
		const receiptHash = r.take(32).toString('hex');
		const encryptionKey = r.take(32).toString('hex');
		const count = r.u8();
		const transports: IDfTransportDescriptor[] = [];
		for (let i = 0; i < count; i++) {
			const tag = r.u8();
			if (tag === 1) {
				const host = r.take(r.u8()).toString('utf8');
				transports.push({ type: 'ln', host, port: r.u16() });
			} else if (tag === 2) {
				const host = r.take(r.u8()).toString('utf8');
				const port = r.u16();
				const intro = r.take(33).toString('hex');
				const blinding = r.take(33).toString('hex');
				const hopCount = r.u8();
				const hops: Array<{ id: string; data: string }> = [];
				for (let h = 0; h < hopCount; h++) {
					const id = r.take(33).toString('hex');
					hops.push({ id, data: r.take(r.u16()).toString('hex') });
				}
				transports.push({
					type: 'onion',
					host,
					port,
					path: { intro, blinding, hops }
				});
			} else if (tag === 3) {
				const nodeId = r.take(33).toString('hex');
				const host = r.take(r.u8()).toString('utf8');
				transports.push({ type: 'lsp', nodeId, host, port: r.u16() });
			} else if (tag === 4) {
				transports.push({
					type: 'swarm',
					rendezvous: r.take(32).toString('hex'),
					noiseKey: r.take(32).toString('hex')
				});
			} else {
				throw new Error('payment request is malformed');
			}
		}
		sigBytes = Buffer.from(r.take(65));
		if (r.remaining() !== 0) {
			throw new Error('payment request is malformed');
		}
		env = {
			v: 2,
			requestId,
			receiverNodeId,
			expiresAt,
			...(amountSat !== undefined ? { amountSat } : {}),
			receiptHash,
			encryptionKey,
			transports
		};
	} catch (e) {
		const msg = (e as Error).message;
		throw new Error(
			msg.startsWith('unsupported') ? msg : 'payment request is not decodable'
		);
	}
	if (Date.now() > env.expiresAt) {
		throw new Error('payment request has expired; ask the receiver for a fresh one');
	}
	const sig = zbase32Encode(sigBytes);
	const verdict = verifyMessageSignature(canonicalRequestMessage(env), sig);
	if (!verdict.valid || !verdict.pubkey) {
		throw new Error('payment request signature is invalid');
	}
	if (verdict.pubkey.toString('hex') !== env.receiverNodeId) {
		throw new Error(
			'payment request signature does not match the receiver it names'
		);
	}
	return { ...env, sig };
}

// ─────────────── Per-request encryption ───────────────

const HKDF_INFO_S2R = 'beignet-df-v1/sender-to-receiver';
const HKDF_INFO_R2S = 'beignet-df-v1/receiver-to-sender';

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

/** Send and receive keys for one endpoint of a sealed lane. Directional
 *  keys mean a frame reflected back at its author fails authentication:
 *  nothing sealed under the sender-to-receiver key ever opens under it on
 *  the way back, and vice versa. */
export interface ILaneKeys {
	sendKey: Buffer;
	recvKey: Buffer;
}

function deriveDirectional(
	sharedSecret: Buffer,
	requestIdHex: string,
	info: string
): Buffer {
	return Buffer.from(
		crypto.hkdfSync(
			'sha256',
			sharedSecret,
			Buffer.from(requestIdHex, 'hex'),
			info,
			32
		)
	);
}

/** Sender side: ephemeral ECDH against the request's public key. */
export function senderDeriveKey(
	requestPublicKeyHex: string,
	requestIdHex: string
): { keys: ILaneKeys; ephemeralPublicHex: string } {
	const eph = crypto.generateKeyPairSync('x25519');
	const shared = crypto.diffieHellman({
		privateKey: eph.privateKey,
		publicKey: x25519PublicFromRaw(Buffer.from(requestPublicKeyHex, 'hex'))
	});
	const jwk = eph.publicKey.export({ format: 'jwk' }) as { x: string };
	return {
		keys: {
			sendKey: deriveDirectional(shared, requestIdHex, HKDF_INFO_S2R),
			recvKey: deriveDirectional(shared, requestIdHex, HKDF_INFO_R2S)
		},
		ephemeralPublicHex: Buffer.from(jwk.x, 'base64url').toString('hex')
	};
}

/** Receiver side: the request's private key against the sender ephemeral. */
export function receiverDeriveKey(
	privateKeyPem: string,
	ephemeralPublicHex: string,
	requestIdHex: string
): ILaneKeys {
	const shared = crypto.diffieHellman({
		privateKey: crypto.createPrivateKey(privateKeyPem),
		publicKey: x25519PublicFromRaw(Buffer.from(ephemeralPublicHex, 'hex'))
	});
	return {
		sendKey: deriveDirectional(shared, requestIdHex, HKDF_INFO_R2S),
		recvKey: deriveDirectional(shared, requestIdHex, HKDF_INFO_S2R)
	};
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
	keys: ILaneKeys,
	requestIdHex: string,
	firstFrame?: { ephemeralPublicHex: string }
): DfTransport {
	let first = firstFrame;
	return {
		send: (subtype, payload) => {
			// Nonces are 96 random bits per frame; at this protocol's frame
			// counts (a dozen per request) collision odds are negligible, and
			// a retransmitted logical frame re-seals under a FRESH nonce, so
			// no nonce ever carries two different or two identical plaintexts.
			const sealed = seal(keys.sendKey, requestIdHex, subtype, payload);
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
					cb(subtype, open(keys.recvKey, requestIdHex, subtype, frame));
				} catch {
					// Tampered or foreign frame: drop it. GCM authenticated it away.
				}
			})
	};
}
