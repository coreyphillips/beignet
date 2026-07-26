import * as crypto from 'crypto';
import {
	verifyMessageSignature,
	zbase32Encode,
	zbase32Decode
} from '../lightning/crypto/message-signing';
import {
	ecdh,
	getPublicKey,
	isValidPrivateKey
} from '../lightning/crypto/ecdh';
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
 * ChaCha20-Poly1305, keyed per direction by secp256k1
 * ECDH(ephemeral sender key, request key) through HKDF-SHA256, with the
 * request id and message subtype bound as associated data.
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

/** BOLT chain_hash values (genesis hash, internal byte order). */
export const CHAIN_HASHES: Record<string, string> = {
	mainnet: '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000',
	testnet: '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000',
	signet: 'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000',
	regtest: '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f'
};

export interface IDfRequestEnvelope {
	v: 3;
	requestId: string;
	/** BOLT chain_hash of the intended chain. A node key reused across
	 *  networks cannot have a request replayed onto the wrong chain. */
	chainHash: string;
	receiverNodeId: string;
	expiresAt: number;
	/** Optional fixed amount the request asks for (sats). */
	amountSat?: number;
	receiptHash: string;
	/** Per-request secp256k1 public key (hex, 33 bytes compressed). Chosen
	 *  over X25519 so implementations need no primitives beyond what
	 *  Lightning already requires (secp256k1 ECDH, HKDF, ChaCha20). */
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
//   u8   version (3)
//   16B  requestId
//   32B  chainHash (BOLT chain_hash of the intended chain)
//   33B  receiverNodeId
//   u48  expiresAt (ms)
//   u8   flags (bit0: amountSat present)
//   [u64 amountSat]
//   32B  receiptHash
//   33B  encryptionKey (secp256k1 compressed)
//   u8   transport count, then per transport:
//     u8 type tag, u16 value length, value
//   65B  sig (compact recoverable, the zbase32 signature decoded)
//
// The outer length on every descriptor makes unknown types skippable, so
// new transports can be added without breaking old decoders. Values:
//     1 ln:    u8 hostLen, host, u16 port
//     2 onion: u8 hostLen, host, u16 port, 33B intro, 33B blinding,
//              u8 hopCount, per hop: 33B id, u16 dataLen, data
//     3 lsp:   33B nodeId, u8 hostLen, host, u16 port
//     4 swarm: 32B rendezvous, 32B noiseKey

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
	parts.push(u8(3));
	parts.push(Buffer.from(env.requestId, 'hex'));
	parts.push(Buffer.from(env.chainHash, 'hex'));
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
		const value: Buffer[] = [];
		if (t.type === 'ln') {
			value.push(hostField(t.host, t.port));
		} else if (t.type === 'onion') {
			if (!t.path) throw new Error('onion transport without path');
			value.push(hostField(t.host, t.port));
			value.push(Buffer.from(t.path.intro, 'hex'));
			value.push(Buffer.from(t.path.blinding, 'hex'));
			value.push(u8(t.path.hops.length));
			for (const hop of t.path.hops) {
				const data = Buffer.from(hop.data, 'hex');
				value.push(Buffer.from(hop.id, 'hex'), u16(data.length), data);
			}
		} else if (t.type === 'lsp') {
			value.push(Buffer.from(t.nodeId ?? '', 'hex'));
			value.push(hostField(t.host, t.port));
		} else {
			value.push(Buffer.from(t.rendezvous ?? '', 'hex'));
			value.push(Buffer.from(t.noiseKey ?? '', 'hex'));
		}
		const v = Buffer.concat(value);
		parts.push(u8(tag), u16(v.length), v);
	}
	return Buffer.concat(parts);
}

/** The exact string the receiver's node key signs: the version tag plus
 *  the full unsigned binary body, so every field is covered. */
export function canonicalRequestMessage(
	env: Omit<IDfRequestEnvelope, 'sig'>
): string {
	return `beignet-df-req:v3:${encodeUnsignedBytes(env).toString('base64url')}`;
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
		if (v !== 3) {
			throw new Error(`unsupported payment request version ${v}`);
		}
		const requestId = r.take(16).toString('hex');
		const chainHash = r.take(32).toString('hex');
		const receiverNodeId = r.take(33).toString('hex');
		const expiresAt = r.take(6).readUIntBE(0, 6);
		const flags = r.u8();
		const amountSat =
			flags & 1 ? Number(r.take(8).readBigUInt64BE()) : undefined;
		const receiptHash = r.take(32).toString('hex');
		const encryptionKey = r.take(33).toString('hex');
		const count = r.u8();
		const transports: IDfTransportDescriptor[] = [];
		for (let i = 0; i < count; i++) {
			const tag = r.u8();
			const value = new ByteReader(Buffer.from(r.take(r.u16())));
			if (tag === 1) {
				const host = value.take(value.u8()).toString('utf8');
				transports.push({ type: 'ln', host, port: value.u16() });
			} else if (tag === 2) {
				const host = value.take(value.u8()).toString('utf8');
				const port = value.u16();
				const intro = value.take(33).toString('hex');
				const blinding = value.take(33).toString('hex');
				const hopCount = value.u8();
				const hops: Array<{ id: string; data: string }> = [];
				for (let h = 0; h < hopCount; h++) {
					const id = value.take(33).toString('hex');
					hops.push({ id, data: value.take(value.u16()).toString('hex') });
				}
				transports.push({
					type: 'onion',
					host,
					port,
					path: { intro, blinding, hops }
				});
			} else if (tag === 3) {
				const nodeId = value.take(33).toString('hex');
				const host = value.take(value.u8()).toString('utf8');
				transports.push({ type: 'lsp', nodeId, host, port: value.u16() });
			} else if (tag === 4) {
				transports.push({
					type: 'swarm',
					rendezvous: value.take(32).toString('hex'),
					noiseKey: value.take(32).toString('hex')
				});
			}
			// Unknown tags: the outer length already skipped the value, so a
			// decoder simply does not gain that transport. Forward compatible.
		}
		sigBytes = Buffer.from(r.take(65));
		if (r.remaining() !== 0) {
			throw new Error('payment request is malformed');
		}
		env = {
			v: 3,
			requestId,
			chainHash,
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

const HKDF_INFO_S2R = 'beignet-df:v3:sender-to-receiver';
const HKDF_INFO_R2S = 'beignet-df:v3:receiver-to-sender';

export interface IRequestEncryptionKeys {
	/** Compressed secp256k1 public key hex, published in the envelope. */
	publicKeyHex: string;
	/** 32-byte private key hex, held by the receiver until expiry. */
	privateKeyHex: string;
}

/** secp256k1 keeps the primitive set to what Lightning implementations
 *  already carry: secp256k1 ECDH, HKDF-SHA256, ChaCha20-Poly1305. The
 *  node identity key still never encrypts anything. */
export function mintRequestEncryptionKeys(): IRequestEncryptionKeys {
	let priv: Buffer;
	do {
		priv = crypto.randomBytes(32);
	} while (!isValidPrivateKey(priv));
	return {
		publicKeyHex: getPublicKey(priv).toString('hex'),
		privateKeyHex: priv.toString('hex')
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
	let eph: Buffer;
	do {
		eph = crypto.randomBytes(32);
	} while (!isValidPrivateKey(eph));
	const shared = ecdh(eph, Buffer.from(requestPublicKeyHex, 'hex'));
	return {
		keys: {
			sendKey: deriveDirectional(shared, requestIdHex, HKDF_INFO_S2R),
			recvKey: deriveDirectional(shared, requestIdHex, HKDF_INFO_R2S)
		},
		ephemeralPublicHex: getPublicKey(eph).toString('hex')
	};
}

/** Receiver side: the request's private key against the sender ephemeral. */
export function receiverDeriveKey(
	privateKeyHex: string,
	ephemeralPublicHex: string,
	requestIdHex: string
): ILaneKeys {
	const shared = ecdh(
		Buffer.from(privateKeyHex, 'hex'),
		Buffer.from(ephemeralPublicHex, 'hex')
	);
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
	const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
	const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
		authTagLength: 16
	});
	cipher.setAAD(aad(requestIdHex, subtype), {
		plaintextLength: plaintext.length
	});
	const ct = Buffer.concat([
		cipher.update(plaintext),
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
	const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {
		authTagLength: 16
	});
	decipher.setAAD(aad(requestIdHex, subtype), {
		plaintextLength: body.length
	});
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
