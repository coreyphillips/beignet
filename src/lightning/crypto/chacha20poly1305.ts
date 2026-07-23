import crypto from 'crypto';

const ALGORITHM = 'chacha20-poly1305';
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
	key: Buffer,
	nonce: Buffer,
	plaintext: Buffer,
	aad: Buffer = Buffer.alloc(0)
): Buffer {
	if (key.length !== KEY_LENGTH) {
		throw new Error(`Key must be ${KEY_LENGTH} bytes, got ${key.length}`);
	}
	if (nonce.length !== NONCE_LENGTH) {
		throw new Error(`Nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Node's createCipheriv overloads omit chacha20-poly1305 + authTagLength; runtime supports both
	const cipher = crypto.createCipheriv(ALGORITHM as any, key, nonce, {
		authTagLength: TAG_LENGTH
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- see above
	} as any) as crypto.CipherGCM;
	cipher.setAAD(aad);

	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();

	return Buffer.concat([encrypted, tag]);
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
	key: Buffer,
	nonce: Buffer,
	ciphertextWithTag: Buffer,
	aad: Buffer = Buffer.alloc(0)
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

	const ciphertext = ciphertextWithTag.subarray(
		0,
		ciphertextWithTag.length - TAG_LENGTH
	);
	const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_LENGTH);

	// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Node's createDecipheriv overloads omit chacha20-poly1305 + authTagLength; runtime supports both
	const decipher = crypto.createDecipheriv(ALGORITHM as any, key, nonce, {
		authTagLength: TAG_LENGTH
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- see above
	} as any) as crypto.DecipherGCM;
	decipher.setAAD(aad);
	decipher.setAuthTag(tag);

	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
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
