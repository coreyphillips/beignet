import { chacha20Poly1305Decrypt, chacha20Poly1305Encrypt } from './provider';

const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Encrypt plaintext using ChaCha20-Poly1305 AEAD.
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param plaintext - Data to encrypt
 * @param aad - Optional additional authenticated data
 * @returns Ciphertext with 16-byte authentication tag appended
 */
export function encrypt(
	key: Uint8Array,
	nonce: Uint8Array,
	plaintext: Uint8Array,
	aad: Uint8Array = Buffer.alloc(0)
): Buffer {
	if (key.length !== KEY_LENGTH) {
		throw new Error(`Key must be ${KEY_LENGTH} bytes, got ${key.length}`);
	}
	if (nonce.length !== NONCE_LENGTH) {
		throw new Error(`Nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
	}

	return chacha20Poly1305Encrypt(key, nonce, plaintext, aad);
}

/**
 * Decrypt ciphertext using ChaCha20-Poly1305 AEAD.
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param ciphertextWithTag - Ciphertext with 16-byte authentication tag appended
 * @param aad - Optional additional authenticated data
 * @returns Decrypted plaintext
 * @throws If authentication fails (tag mismatch)
 */
export function decrypt(
	key: Uint8Array,
	nonce: Uint8Array,
	ciphertextWithTag: Uint8Array,
	aad: Uint8Array = Buffer.alloc(0)
): Buffer {
	if (key.length !== KEY_LENGTH) {
		throw new Error(`Key must be ${KEY_LENGTH} bytes, got ${key.length}`);
	}
	if (nonce.length !== NONCE_LENGTH) {
		throw new Error(`Nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
	}
	if (ciphertextWithTag.length < TAG_LENGTH) {
		throw new Error('Ciphertext too short to contain authentication tag');
	}

	return chacha20Poly1305Decrypt(key, nonce, ciphertextWithTag, aad);
}

/**
 * Build a 12-byte nonce from a 64-bit little-endian counter.
 * Lightning BOLT 8 uses 4 bytes of zeros followed by 8-byte LE counter.
 * @param counter - Nonce counter value
 * @returns 12-byte nonce buffer
 */
export function nonceFromCounter(counter: bigint): Buffer {
	const nonce = Buffer.alloc(NONCE_LENGTH);
	// First 4 bytes are zero (per BOLT 8)
	// Next 8 bytes are little-endian counter
	nonce.writeBigUInt64LE(counter, 4);
	return nonce;
}

export { KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH };
