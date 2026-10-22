/**
 * Application-level envelope encryption for SQLite storage at rest.
 *
 * Values are encrypted with AES-256-GCM under a key derived from wallet seed
 * material via HKDF-SHA256, and stored as 'enc1:' + base64(iv || tag || ct).
 * The prefix lets readers distinguish encrypted rows from legacy plaintext,
 * so pre-encryption databases migrate lazily and safely.
 */

import {
	aes256GcmDecrypt,
	aes256GcmEncrypt,
	hkdfSha256,
	randomBytes
} from '../crypto/provider';

/** Leads every value encryptValue writes; isEncryptedValue tests for it. */
export const ENC_PREFIX = 'enc1:';
const HKDF_INFO = 'beignet-storage-encryption-v1';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Derive a 32-byte AES key from seed material via HKDF-SHA256 (empty salt).
 * The info string domain-separates keys so different subsystems (storage at
 * rest, static channel backups, ...) never share an encryption key.
 */
export function hkdfKey(secret: Uint8Array, info: string): Buffer {
	return hkdfSha256(
		secret,
		Buffer.alloc(0),
		Buffer.from(info, 'utf8'),
		KEY_LENGTH
	);
}

/**
 * Derive the 32-byte storage encryption key from wallet seed material.
 * Deterministic: the same secret always yields the same key, so a database
 * restored from backup is readable with the same mnemonic.
 */
export function deriveStorageKey(secret: Uint8Array): Buffer {
	return hkdfKey(secret, HKDF_INFO);
}

/**
 * AES-256-GCM encryption core shared by storage rows and channel backups.
 * Output format: prefix + base64(iv || authTag || ciphertext).
 */
export function encryptWithPrefix(
	key: Uint8Array,
	plaintext: string,
	prefix: string
): string {
	const iv = randomBytes(IV_LENGTH);
	const sealed = aes256GcmEncrypt(key, iv, Buffer.from(plaintext, 'utf8'));
	const tag = sealed.subarray(sealed.length - TAG_LENGTH);
	const ciphertext = sealed.subarray(0, sealed.length - TAG_LENGTH);
	return prefix + Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

/**
 * AES-256-GCM decryption core. Throws on a missing prefix, malformed value,
 * or failed auth tag (wrong key or tampered ciphertext).
 */
export function decryptWithPrefix(
	key: Uint8Array,
	value: string,
	prefix: string
): string {
	if (!value.startsWith(prefix)) {
		throw new Error(`Value is not encrypted (missing ${prefix} prefix)`);
	}
	const payload = Buffer.from(value.slice(prefix.length), 'base64');
	if (payload.length < IV_LENGTH + TAG_LENGTH) {
		throw new Error('Encrypted value is truncated');
	}
	const iv = payload.subarray(0, IV_LENGTH);
	const tag = payload.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
	const ciphertext = payload.subarray(IV_LENGTH + TAG_LENGTH);
	return aes256GcmDecrypt(key, iv, Buffer.concat([ciphertext, tag])).toString(
		'utf8'
	);
}

/**
 * Encrypt a plaintext value. Output format: 'enc1:' + base64(iv || authTag || ciphertext).
 */
export function encryptValue(key: Uint8Array, plaintext: string): string {
	return encryptWithPrefix(key, plaintext, ENC_PREFIX);
}

/**
 * Decrypt an 'enc1:' value. Throws on a malformed value or failed auth tag
 * (wrong key or tampered ciphertext).
 */
export function decryptValue(key: Uint8Array, value: string): string {
	return decryptWithPrefix(key, value, ENC_PREFIX);
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
