/**
 * BOLT 4: Route Blinding -- Key Derivation
 *
 * Route blinding allows a recipient to hide its identity and the last
 * few hops of a route by providing a "blinded path" to the sender.
 *
 * Key derivation:
 *   shared_secret = ECDH(blinding_key, node_privkey) -- at each hop
 *   blinding_factor = SHA256(blinding_key || shared_secret)
 *   next_blinding_key = blinding_key * blinding_factor
 *   blinded_node_id = node_pubkey * HMAC-SHA256("blinded_node_id", ss)
 *
 * The encrypted_recipient_data is encrypted with a key derived from the shared secret:
 *   rho = HMAC-SHA256("blinded_node_id", shared_secret)
 *   Encrypt with ChaCha20-Poly1305 using rho as key
 */

import crypto from 'crypto';
import {
	ecdh,
	pointMultiply,
	getPublicKey,
	privateMultiply
} from '../crypto/ecdh';
import { encrypt, decrypt } from '../crypto/chacha20poly1305';

/**
 * Derive the shared secret between a blinding key and a node's private key.
 */
export function deriveBlindingSharedSecret(
	blindingKey: Buffer,
	nodePrivkey: Buffer
): Buffer {
	return ecdh(nodePrivkey, blindingKey);
}

/**
 * Compute the blinding factor for the next hop.
 * blinding_factor = SHA256(blinding_key || shared_secret)
 */
export function deriveBlindingFactor(
	blindingKey: Buffer,
	sharedSecret: Buffer
): Buffer {
	return crypto
		.createHash('sha256')
		.update(blindingKey)
		.update(sharedSecret)
		.digest();
}

/**
 * Derive the next blinding key for the next hop.
 * next_blinding_key = blinding_key * blinding_factor
 */
export function deriveNextBlindingKey(
	blindingKey: Buffer,
	sharedSecret: Buffer
): Buffer {
	const factor = deriveBlindingFactor(blindingKey, sharedSecret);
	return pointMultiply(blindingKey, factor);
}

/**
 * Blinded-node-id tweak (BOLT 4): HMAC-SHA256("blinded_node_id", ss). Used to
 * tweak both the public key (computeBlindedNodeId) and, on the receiving side,
 * the private key — they must use the SAME tweak so the keys correspond.
 */
export function deriveBlindedNodeIdTweak(sharedSecret: Buffer): Buffer {
	return crypto
		.createHmac('sha256', Buffer.from('blinded_node_id'))
		.update(sharedSecret)
		.digest();
}

/**
 * Compute a blinded node ID from a node's public key and the shared secret.
 * blinded_node_id = node_pubkey * HMAC-SHA256("blinded_node_id", ss)
 */
export function computeBlindedNodeId(
	nodePubkey: Buffer,
	sharedSecret: Buffer
): Buffer {
	return pointMultiply(nodePubkey, deriveBlindedNodeIdTweak(sharedSecret));
}

/**
 * Derive the encryption key (rho) for encrypted_recipient_data (BOLT 4):
 * rho = HMAC-SHA256("rho", shared_secret). Using the spec "rho" label (not
 * "blinded_node_id") is what lets LND/CLN decrypt our encrypted_recipient_data.
 */
export function deriveBlindingEncryptionKey(sharedSecret: Buffer): Buffer {
	return crypto
		.createHmac('sha256', Buffer.from('rho'))
		.update(sharedSecret)
		.digest();
}

/**
 * Encrypt the recipient data for a blinded hop.
 * Uses ChaCha20-Poly1305 with the derived rho key.
 */
export function encryptBlindedData(
	encryptionKey: Buffer,
	plaintext: Buffer
): Buffer {
	// Use zero nonce (12 bytes) and empty associated data for blinded data
	const nonce = Buffer.alloc(12);
	const ad = Buffer.alloc(0);
	return encrypt(encryptionKey, nonce, plaintext, ad);
}

/**
 * Decrypt the recipient data at a blinded hop.
 */
export function decryptBlindedData(
	encryptionKey: Buffer,
	ciphertext: Buffer
): Buffer {
	const nonce = Buffer.alloc(12);
	const ad = Buffer.alloc(0);
	return decrypt(encryptionKey, nonce, ciphertext, ad);
}

/**
 * Derive all blinding keys for a path.
 * Given an initial blinding secret and a list of node pubkeys,
 * returns the blinding keys and shared secrets at each hop.
 */
export function deriveBlindingKeyChain(
	blindingSecret: Buffer,
	nodePubkeys: Buffer[]
): { blindingKeys: Buffer[]; sharedSecrets: Buffer[] } {
	const blindingKeys: Buffer[] = [];
	const sharedSecrets: Buffer[] = [];

	let currentBlindingKey = getPublicKey(blindingSecret);
	let currentBlindingPrivkey = Buffer.from(blindingSecret);

	for (let i = 0; i < nodePubkeys.length; i++) {
		blindingKeys.push(currentBlindingKey);

		// Shared secret at this hop
		const ss = ecdh(currentBlindingPrivkey, nodePubkeys[i]);
		sharedSecrets.push(ss);

		// Derive next blinding key
		const factor = deriveBlindingFactor(currentBlindingKey, ss);
		currentBlindingKey = pointMultiply(currentBlindingKey, factor);

		// Update private key: next_privkey = current_privkey * factor (mod order)
		currentBlindingPrivkey = privateMultiply(currentBlindingPrivkey, factor);
	}

	return { blindingKeys, sharedSecrets };
}
