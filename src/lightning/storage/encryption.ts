/**
 * Application-level envelope encryption for SQLite storage at rest.
 *
 * Values are encrypted with AES-256-GCM under a key derived from wallet seed
 * material via HKDF-SHA256, and stored as 'enc1:' + base64(iv || tag || ct).
 * The prefix lets readers distinguish encrypted rows from legacy plaintext,
 * so pre-encryption databases migrate lazily and safely.
 */

import {
	hkdfSync,
	randomBytes,
	createCipheriv,
	createDecipheriv
} from 'crypto';

const ENC_PREFIX = 'enc1:';
const HKDF_INFO = 'beignet-storage-encryption-v1';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Derive the 32-byte storage encryption key from wallet seed material.
 * Deterministic: the same secret always yields the same key, so a database
 * restored from backup is readable with the same mnemonic.
 */
export function deriveStorageKey(secret: Buffer): Buffer {
	return Buffer.from(
		hkdfSync('sha256', secret, Buffer.alloc(0), HKDF_INFO, KEY_LENGTH)
	);
}

/**
 * Encrypt a plaintext value. Output format: 'enc1:' + base64(iv || authTag || ciphertext).
 */
export function encryptValue(key: Buffer, plaintext: string): string {
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv('aes-256-gcm', key, iv);
	const ciphertext = Buffer.concat([
		cipher.update(plaintext, 'utf8'),
		cipher.final()
	]);
	return (
		ENC_PREFIX +
		Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64')
	);
}

/**
 * Decrypt an 'enc1:' value. Throws on a malformed value or failed auth tag
 * (wrong key or tampered ciphertext).
 */
export function decryptValue(key: Buffer, value: string): string {
	if (!value.startsWith(ENC_PREFIX)) {
		throw new Error('Value is not encrypted (missing enc1 prefix)');
	}
	const payload = Buffer.from(value.slice(ENC_PREFIX.length), 'base64');
	if (payload.length < IV_LENGTH + TAG_LENGTH) {
		throw new Error('Encrypted value is truncated');
	}
	const iv = payload.subarray(0, IV_LENGTH);
	const tag = payload.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
	const ciphertext = payload.subarray(IV_LENGTH + TAG_LENGTH);
	const decipher = createDecipheriv('aes-256-gcm', key, iv);
	decipher.setAuthTag(tag);
	return Buffer.concat([
		decipher.update(ciphertext),
		decipher.final()
	]).toString('utf8');
}

/** True when the value carries the 'enc1:' encrypted-at-rest prefix. */
export function isEncryptedValue(value: string): boolean {
	return value.startsWith(ENC_PREFIX);
}

/**
 * Thrown when a database contains encrypted rows but the storage was opened
 * without an encryptionKey. A configuration problem, not row corruption, so
 * it must NOT be swallowed by corrupt-row handling.
 */
export class StorageEncryptedError extends Error {
	constructor() {
		super('storage is encrypted; encryptionKey required');
		this.name = 'StorageEncryptedError';
	}
}
