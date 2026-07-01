import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';

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
	return ecc.verify(messageHash, publicKey, signature, strict);
}
