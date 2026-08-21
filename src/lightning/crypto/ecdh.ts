import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import type { KeyObject } from 'crypto';

/**
 * Perform ECDH key agreement and return SHA256 of the shared point.
 * This follows the Lightning/Noise protocol convention where the
 * shared secret is SHA256(compressed_shared_point).
 * @param privateKey - 32-byte private key
 * @param publicKey - 33-byte compressed public key
 * @returns 32-byte shared secret (SHA256 of compressed ECDH point)
 */
export function ecdh(privateKey: Buffer, publicKey: Buffer): Buffer {
	if (privateKey.length !== 32) {
		throw new Error(`Private key must be 32 bytes, got ${privateKey.length}`);
	}
	if (publicKey.length !== 33) {
		throw new Error(
			`Public key must be 33 bytes compressed, got ${publicKey.length}`
		);
	}

	// Multiply the public key by the private key scalar
	const sharedPoint = ecc.pointMultiply(publicKey, privateKey);
	if (!sharedPoint) {
		throw new Error('ECDH failed: invalid point multiplication result');
	}

	// Return SHA256 of the compressed shared point (per Noise protocol)
	return crypto.createHash('sha256').update(sharedPoint).digest();
}

/**
 * Derive a public key from a private key.
 * @param privateKey - 32-byte private key
 * @returns 33-byte compressed public key
 */
export function getPublicKey(privateKey: Buffer): Buffer {
	if (privateKey.length !== 32) {
		throw new Error(`Private key must be 32 bytes, got ${privateKey.length}`);
	}
	const pub = ecc.pointFromScalar(privateKey);
	if (!pub) {
		throw new Error('Failed to derive public key from private key');
	}
	return Buffer.from(pub);
}

/**
 * Multiply a public key by a scalar (tweak).
 * Used in onion routing for ephemeral key blinding.
 * @param publicKey - 33-byte compressed public key
 * @param scalar - 32-byte scalar
 * @returns 33-byte compressed result point
 */
export function pointMultiply(publicKey: Buffer, scalar: Buffer): Buffer {
	const result = ecc.pointMultiply(publicKey, scalar);
	if (!result) {
		throw new Error('Point multiplication failed');
	}
	return Buffer.from(result);
}

/**
 * Add two public keys (EC point addition).
 * Used in key derivation for Lightning channels.
 * @param point1 - 33-byte compressed public key
 * @param point2 - 33-byte compressed public key
 * @returns 33-byte compressed result point
 */
export function pointAdd(point1: Buffer, point2: Buffer): Buffer {
	const result = ecc.pointAdd(point1, point2);
	if (!result) {
		throw new Error('Point addition failed');
	}
	return Buffer.from(result);
}

/**
 * Verify that a buffer is a valid compressed public key.
 * @param pubkey - Buffer to validate
 * @returns True if valid compressed public key
 */
export function isValidPublicKey(pubkey: Buffer): boolean {
	if (pubkey.length !== 33) {
		return false;
	}
	return ecc.isPoint(pubkey);
}

/**
 * Verify that a buffer is a valid private key (scalar).
 * @param privkey - Buffer to validate
 * @returns True if valid private key
 */
export function isValidPrivateKey(privkey: Buffer): boolean {
	if (privkey.length !== 32) {
		return false;
	}
	return ecc.isPrivate(privkey);
}

/**
 * Add two private keys (scalars) modulo the curve order.
 * Used for per-commitment key derivation in BOLT 3.
 * @param key1 - 32-byte private key
 * @param key2 - 32-byte private key (or scalar)
 * @returns 32-byte resulting private key
 */
export function privateAdd(key1: Buffer, key2: Buffer): Buffer {
	if (key1.length !== 32) {
		throw new Error(`Key1 must be 32 bytes, got ${key1.length}`);
	}
	if (key2.length !== 32) {
		throw new Error(`Key2 must be 32 bytes, got ${key2.length}`);
	}
	const result = ecc.privateAdd(key1, key2);
	if (!result) {
		throw new Error(
			'Private key addition failed (result is zero or exceeds curve order)'
		);
	}
	return Buffer.from(result);
}

/**
 * Multiply a private key (scalar) by another scalar modulo the curve order.
 * Used for revocation key derivation in BOLT 3.
 * @param key - 32-byte private key
 * @param tweak - 32-byte scalar
 * @returns 32-byte resulting private key
 */
export function privateMultiply(key: Buffer, tweak: Buffer): Buffer {
	if (key.length !== 32) {
		throw new Error(`Key must be 32 bytes, got ${key.length}`);
	}
	if (tweak.length !== 32) {
		throw new Error(`Tweak must be 32 bytes, got ${tweak.length}`);
	}
	// privateNegate and then combine: a*b = a + (b-1)*a ... actually we need raw multiply
	// Use pointMultiply on G to get tweak*G, but we need scalar multiply.
	// The ecc library doesn't expose raw scalar multiply, so we compute:
	// result = privateAdd(pointMultiply(key_as_point, tweak)_back_to_scalar)
	// Actually, we can use the secp256k1 library's privateMul if available.
	// For now: key * tweak mod n via bigint arithmetic.
	const n = BigInt(
		'0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
	);
	const a = BigInt('0x' + key.toString('hex'));
	const b = BigInt('0x' + tweak.toString('hex'));
	const result = (a * b) % n;
	if (result === 0n) {
		throw new Error('Private key multiplication resulted in zero');
	}
	const hex = result.toString(16).padStart(64, '0');
	return Buffer.from(hex, 'hex');
}

/**
 * Sign a 32-byte message hash with a private key.
 * @param messageHash - 32-byte hash to sign
 * @param privateKey - 32-byte private key
 * @returns 64-byte compact signature (r || s)
 */
export function sign(messageHash: Buffer, privateKey: Buffer): Buffer {
	if (messageHash.length !== 32) {
		throw new Error(`Message hash must be 32 bytes, got ${messageHash.length}`);
	}
	const sig = ecc.sign(messageHash, privateKey);
	return Buffer.from(sig);
}

/**
 * Verify a signature against a message hash and public key.
 * @param messageHash - 32-byte hash that was signed
 * @param publicKey - 33-byte compressed public key
 * @param signature - 64-byte compact signature
 * @param strict - if true, reject non-canonical (high-S) signatures (BIP146 low-S).
 *   Use this for any signature we will later place in a transaction we broadcast:
 *   a high-S signature verifies cryptographically but makes the spending tx
 *   non-standard/non-relayable, so accepting one silently yields an unbroadcastable
 *   commitment or HTLC claim.
 * @returns True if signature is valid
 */
export function verify(
	messageHash: Buffer,
	publicKey: Buffer,
	signature: Buffer,
	strict = false
): boolean {
	// Malformed input (an out-of-range scalar in the signature, a non-point
	// pubkey) makes the backend THROW rather than return false. Every caller
	// treats this as a boolean judgment over untrusted bytes, and an escaping
	// throw from a peer-message handler bypasses the refusal path entirely
	// (issue 415's shape), so malformed means invalid here.
	try {
		return ecc.verify(messageHash, publicKey, signature, strict);
	} catch {
		return false;
	}
}

/**
 * ASN.1 SubjectPublicKeyInfo prefix for a secp256k1 EC public key.
 * Concatenated with a 33-byte compressed point it forms the DER document
 * node:crypto's createPublicKey accepts; OpenSSL handles the compressed
 * encoding itself, so no decompression is needed.
 */
const SECP256K1_SPKI_PREFIX = Buffer.from(
	'3036301006072a8648ce3d020106052b8104000a032200',
	'hex'
);

/**
 * Bound on the imported-key cache. Sized to hold the announced Lightning node
 * population (~13-16k) so every recurring gossip signer stays cached through
 * a full sync; per-channel bitcoin keys are ~unique and churn the cold end.
 */
const SHA256D_KEY_CACHE_MAX = 16384;

let sha256dBackend: 'node' | 'js' | null = null;
const sha256dKeyCache = new Map<string, KeyObject>();

/**
 * Select the verification backend for verifySha256d, once. The platform must
 * PROVE the fast path before it is trusted: react-native crypto shims
 * commonly provide hashing but omit or stub asymmetric verify, and a backend
 * that lies rather than throws would corrupt every gossip verdict. Sign a
 * fixed digest with the always-present JS lib and require node:crypto to
 * accept it and reject a tampered copy; anything else selects the JS
 * fallback permanently.
 */
function resolveSha256dBackend(): 'node' | 'js' {
	if (sha256dBackend !== null) {
		return sha256dBackend;
	}
	sha256dBackend = 'js';
	try {
		if (
			typeof crypto.verify !== 'function' ||
			typeof crypto.createPublicKey !== 'function' ||
			typeof crypto.createHash !== 'function'
		) {
			return sha256dBackend;
		}
		const priv = Buffer.alloc(32, 7);
		const firstHash = crypto
			.createHash('sha256')
			.update('beignet sha256d backend self-test')
			.digest();
		const digest = crypto.createHash('sha256').update(firstHash).digest();
		const sig = sign(digest, priv);
		const key = crypto.createPublicKey({
			key: Buffer.concat([SECP256K1_SPKI_PREFIX, getPublicKey(priv)]),
			format: 'der',
			type: 'spki'
		});
		const good = crypto.verify(
			'sha256',
			firstHash,
			{ key, dsaEncoding: 'ieee-p1363' },
			sig
		);
		const tampered = Buffer.from(sig);
		tampered[tampered.length - 1] ^= 0x01;
		const bad = crypto.verify(
			'sha256',
			firstHash,
			{ key, dsaEncoding: 'ieee-p1363' },
			tampered
		);
		if (good === true && bad === false) {
			sha256dBackend = 'node';
		}
	} catch {
		// Leave the JS fallback selected.
	}
	return sha256dBackend;
}

/**
 * Import a compressed public key as a node:crypto KeyObject, cached. Cache
 * hits refresh recency so recurring gossip signers (node ids) outlive the
 * stream of ~unique per-channel bitcoin keys passing through; import
 * failures stay uncached so a flood of unique malformed keys cannot poison
 * the working set.
 */
function getCachedVerifyKey(publicKey: Buffer): KeyObject | null {
	const hex = publicKey.toString('hex');
	const cached = sha256dKeyCache.get(hex);
	if (cached !== undefined) {
		sha256dKeyCache.delete(hex);
		sha256dKeyCache.set(hex, cached);
		return cached;
	}
	if (publicKey.length !== 33) {
		return null;
	}
	let key: KeyObject;
	try {
		key = crypto.createPublicKey({
			key: Buffer.concat([SECP256K1_SPKI_PREFIX, publicKey]),
			format: 'der',
			type: 'spki'
		});
	} catch {
		return null;
	}
	if (sha256dKeyCache.size >= SHA256D_KEY_CACHE_MAX) {
		const oldest = sha256dKeyCache.keys().next().value;
		if (oldest !== undefined) {
			sha256dKeyCache.delete(oldest);
		}
	}
	sha256dKeyCache.set(hex, key);
	return key;
}

/**
 * Verify a signature that covers the double-SHA256 of some data, given the
 * FIRST SHA256 (the BOLT 7 gossip signature scheme). Taking the single hash
 * rather than the final digest is what unlocks the fast path: node:crypto
 * will not verify a bare pre-hashed digest for EC keys, but letting it hash
 * the first SHA256 with 'sha256' lands on exactly the SHA256d digest the
 * signature covers. Non-strict (high-S accepted) and malformed-means-invalid,
 * matching verify() above; verdicts agree with the JS lib on both paths.
 * @param firstHash - sha256(data); the signature covers sha256(firstHash)
 * @param publicKey - 33-byte compressed public key
 * @param signature - 64-byte compact signature (r || s)
 * @returns True if signature is valid
 */
export function verifySha256d(
	firstHash: Buffer,
	publicKey: Buffer,
	signature: Buffer
): boolean {
	if (resolveSha256dBackend() === 'node') {
		const key = getCachedVerifyKey(publicKey);
		if (key === null) {
			return false;
		}
		try {
			return crypto.verify(
				'sha256',
				firstHash,
				{ key, dsaEncoding: 'ieee-p1363' },
				signature
			);
		} catch {
			return false;
		}
	}
	return verifySha256dJs(firstHash, publicKey, signature);
}

/**
 * Pure-JS fallback for verifySha256d, used where node:crypto is unavailable
 * or fails its self-test (react-native embeddings). Exported so tests can
 * pin verdict agreement between the two backends.
 */
export function verifySha256dJs(
	firstHash: Buffer,
	publicKey: Buffer,
	signature: Buffer
): boolean {
	const digest = crypto.createHash('sha256').update(firstHash).digest();
	return verify(digest, publicKey, signature);
}

/**
 * Test hook: reset the memoized backend selection and key cache. Passing
 * force pins subsequent verifications to that backend without re-running the
 * self-test; omitting it restores automatic resolution.
 */
export function _resetSha256dBackendForTests(force?: 'node' | 'js'): void {
	sha256dBackend = force ?? null;
	sha256dKeyCache.clear();
}
