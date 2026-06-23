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
 * Derive per-hop keys from a shared secret.
 * Each key = HMAC-SHA256(sharedSecret, keyType) where keyType is ASCII.
 */
export function deriveHopKeys(sharedSecret: Buffer): IHopKeys {
	const derive = (keyType: string): Buffer => {
		// BOLT 4: generate_key(key_type, ss) = HMAC-SHA256(key=key_type, msg=ss)
		return Buffer.from(
			crypto
				.createHmac('sha256', Buffer.from(keyType, 'ascii'))
				.update(sharedSecret)
				.digest()
		);
	};
	return {
		rho: derive('rho'),
		mu: derive('mu'),
		pad: derive('pad'),
		um: derive('um'),
		ammag: derive('ammag')
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
