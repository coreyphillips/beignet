import crypto from 'crypto';

const HASH_ALGORITHM = 'sha256';
const HASH_LENGTH = 32;

/**
 * HKDF-Extract: Extracts a pseudorandom key from input keying material.
 * @param salt - Optional salt (if not provided, uses zero-filled buffer)
 * @param ikm - Input keying material
 * @returns Pseudorandom key (32 bytes)
 */
export function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
	if (salt.length === 0) {
		salt = Buffer.alloc(HASH_LENGTH);
	}
	return crypto.createHmac(HASH_ALGORITHM, salt).update(ikm).digest();
}

/**
 * HKDF-Expand: Expands a pseudorandom key to the desired length.
 * @param prk - Pseudorandom key from extract phase
 * @param info - Optional context/application-specific info
 * @param length - Desired output length in bytes (max 255 * 32)
 * @returns Output keying material of specified length
 */
export function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
	const maxLength = 255 * HASH_LENGTH;
	if (length > maxLength) {
		throw new Error(`Output length ${length} exceeds maximum ${maxLength}`);
	}

	const n = Math.ceil(length / HASH_LENGTH);
	const okm = Buffer.alloc(n * HASH_LENGTH);
	let prev = Buffer.alloc(0);

	for (let i = 1; i <= n; i++) {
		prev = crypto
			.createHmac(HASH_ALGORITHM, prk)
			.update(prev)
			.update(info)
			.update(Buffer.from([i]))
			.digest();
		prev.copy(okm, (i - 1) * HASH_LENGTH);
	}

	return okm.subarray(0, length);
}

/**
 * HKDF: Full extract-then-expand key derivation.
 * @param salt - Optional salt value
 * @param ikm - Input keying material
 * @param info - Optional context info
 * @param length - Desired output length
 * @returns Derived key material
 */
export function hkdf(
	salt: Buffer,
	ikm: Buffer,
	info: Buffer = Buffer.alloc(0),
	length = 64
): Buffer {
	const prk = hkdfExtract(salt, ikm);
	return hkdfExpand(prk, info, length);
}

/**
 * BOLT 8 specific: HKDF that returns two 32-byte keys.
 * Used throughout the Noise protocol handshake and key rotation.
 * HKDF(salt, ikm) -> [32-byte key1, 32-byte key2]
 * @param salt - Chaining key
 * @param ikm - Input keying material
 * @returns Tuple of [chaining_key, key]
 */
export function hkdf2(salt: Buffer, ikm: Buffer): [Buffer, Buffer] {
	const output = hkdf(salt, ikm, Buffer.alloc(0), 64);
	return [output.subarray(0, 32), output.subarray(32, 64)];
}

/**
 * BOLT 8 specific: HKDF that returns three 32-byte keys.
 * Used at the end of the handshake to derive encryption keys.
 * HKDF(salt, ikm) -> [32-byte key1, 32-byte key2, 32-byte key3]
 * @param salt - Chaining key
 * @param ikm - Input keying material
 * @returns Tuple of [chaining_key, key1, key2]
 */
export function hkdf3(salt: Buffer, ikm: Buffer): [Buffer, Buffer, Buffer] {
	const output = hkdf(salt, ikm, Buffer.alloc(0), 96);
	return [
		output.subarray(0, 32),
		output.subarray(32, 64),
		output.subarray(64, 96)
	];
}
