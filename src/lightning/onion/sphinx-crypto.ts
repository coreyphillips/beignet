/**
 * BOLT 4: Sphinx Crypto Primitives
 *
 * Shared secret generation, key derivation, ephemeral key blinding,
 * and pseudo-random stream generation for onion routing.
 */

import crypto from 'crypto';
import {
	ecdh,
	getPublicKey,
	pointMultiply,
	privateMultiply
} from '../crypto/ecdh';
import { IHopKeys } from './types';

/**
 * Generate a shared secret between a session key and a hop's public key.
 * Uses ECDH which returns SHA256(compressed_shared_point).
 */
export function generateSharedSecret(
	sessionKey: Buffer,
	hopPubkey: Buffer
): Buffer {
	return ecdh(sessionKey, hopPubkey);
}

/**
 * Compute the blinding factor for ephemeral key progression.
 * blindingFactor = SHA256(ephemeralKey || sharedSecret)
 */
export function computeBlindingFactor(
	ephemeralKey: Buffer,
	sharedSecret: Buffer
): Buffer {
	return crypto
		.createHash('sha256')
		.update(ephemeralKey)
		.update(sharedSecret)
		.digest();
}

/**
 * BOLT 4: generate_key(key_type, secret) = HMAC-SHA256(key=key_type, msg=secret).
 * Used both for per-hop keys (secret = shared secret) and for the routing_info
 * pad stream (secret = the SESSION private key, so no hop can regenerate it).
 */
export function generateKey(keyType: string, secret: Buffer): Buffer {
	return Buffer.from(
		crypto
			.createHmac('sha256', Buffer.from(keyType, 'ascii'))
			.update(secret)
			.digest()
	);
}

/**
 * Derive per-hop keys from a shared secret.
 * Each key = HMAC-SHA256(sharedSecret, keyType) where keyType is ASCII.
 */
export function deriveHopKeys(sharedSecret: Buffer): IHopKeys {
	return {
		rho: generateKey('rho', sharedSecret),
		mu: generateKey('mu', sharedSecret),
		pad: generateKey('pad', sharedSecret),
		um: generateKey('um', sharedSecret),
		ammag: generateKey('ammag', sharedSecret)
	};
}

/**
 * Generate a pseudo-random cipher stream using ChaCha20 with a zero nonce.
 * Used for XOR-based encryption/decryption of routing info.
 */
export function generateCipherStream(key: Buffer, length: number): Buffer {
	const nonce = Buffer.alloc(16); // ChaCha20 uses 16-byte nonce (4 counter + 12 nonce)
	const cipher = crypto.createCipheriv('chacha20', key, nonce);
	return Buffer.from(cipher.update(Buffer.alloc(length)));
}

/**
 * Compute shared secrets and ephemeral keys for all hops in a route.
 * The sender uses sessionKey as the initial private key and derives
 * ephemeral keys that each hop will see.
 */
export function computeSharedSecrets(
	sessionKey: Buffer,
	hops: Buffer[]
): { sharedSecrets: Buffer[]; ephemeralKeys: Buffer[] } {
	const sharedSecrets: Buffer[] = [];
	const ephemeralKeys: Buffer[] = [];

	let currentKey = sessionKey;
	let ephemeralPub = getPublicKey(sessionKey);

	for (let i = 0; i < hops.length; i++) {
		ephemeralKeys.push(ephemeralPub);

		const sharedSecret = generateSharedSecret(currentKey, hops[i]);
		sharedSecrets.push(sharedSecret);

		const blindingFactor = computeBlindingFactor(ephemeralPub, sharedSecret);
		ephemeralPub = pointMultiply(ephemeralPub, blindingFactor);
		currentKey = privateMultiply(currentKey, blindingFactor);
	}

	return { sharedSecrets, ephemeralKeys };
}
