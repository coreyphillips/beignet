/**
 * A crypto provider for tests: Node's crypto underneath, every call counted.
 * Results come back as plain Uint8Arrays, not Buffers, so a caller that
 * needs Buffer methods proves the provider seam converts them.
 */

import crypto from 'crypto';
import type { ICryptoProvider } from '../../../src/lightning/crypto/provider';

export type CryptoProviderMethod = keyof ICryptoProvider;

const TAG_LENGTH = 16;

function plain(bytes: Uint8Array): Uint8Array {
	return new Uint8Array(bytes);
}

function seal(
	algorithm: 'aes-256-gcm' | 'chacha20-poly1305',
	key: Uint8Array,
	iv: Uint8Array,
	plaintext: Uint8Array,
	aad: Uint8Array
): Uint8Array {
	const cipher = crypto.createCipheriv(algorithm as 'aes-256-gcm', key, iv, {
		authTagLength: TAG_LENGTH
	});
	cipher.setAAD(aad);
	return plain(
		Buffer.concat([
			cipher.update(plaintext),
			cipher.final(),
			cipher.getAuthTag()
		])
	);
}

function open(
	algorithm: 'aes-256-gcm' | 'chacha20-poly1305',
	key: Uint8Array,
	iv: Uint8Array,
	sealed: Uint8Array,
	aad: Uint8Array
): Uint8Array {
	const decipher = crypto.createDecipheriv(
		algorithm as 'aes-256-gcm',
		key,
		iv,
		{ authTagLength: TAG_LENGTH }
	);
	decipher.setAAD(aad);
	decipher.setAuthTag(sealed.subarray(sealed.length - TAG_LENGTH));
	return plain(
		Buffer.concat([
			decipher.update(sealed.subarray(0, sealed.length - TAG_LENGTH)),
			decipher.final()
		])
	);
}

export function createCountingCryptoProvider(): {
	provider: ICryptoProvider;
	calls: Map<CryptoProviderMethod, number>;
} {
	const calls = new Map<CryptoProviderMethod, number>();
	const count = (method: CryptoProviderMethod): void => {
		calls.set(method, (calls.get(method) ?? 0) + 1);
	};
	const provider: ICryptoProvider = {
		sha256: (data) => {
			count('sha256');
			return plain(crypto.createHash('sha256').update(data).digest());
		},
		hmacSha256: (key, data) => {
			count('hmacSha256');
			return plain(crypto.createHmac('sha256', key).update(data).digest());
		},
		hkdfSha256: (ikm, salt, info, length) => {
			count('hkdfSha256');
			return new Uint8Array(crypto.hkdfSync('sha256', ikm, salt, info, length));
		},
		aes256GcmEncrypt: (key, iv, plaintext, aad) => {
			count('aes256GcmEncrypt');
			return seal('aes-256-gcm', key, iv, plaintext, aad);
		},
		aes256GcmDecrypt: (key, iv, sealed, aad) => {
			count('aes256GcmDecrypt');
			return open('aes-256-gcm', key, iv, sealed, aad);
		},
		chacha20Poly1305Encrypt: (key, nonce, plaintext, aad) => {
			count('chacha20Poly1305Encrypt');
			return seal('chacha20-poly1305', key, nonce, plaintext, aad);
		},
		chacha20Poly1305Decrypt: (key, nonce, sealed, aad) => {
			count('chacha20Poly1305Decrypt');
			return open('chacha20-poly1305', key, nonce, sealed, aad);
		},
		chacha20: (key, nonce, data) => {
			count('chacha20');
			const iv = Buffer.concat([Buffer.alloc(4), nonce]);
			const cipher = crypto.createCipheriv('chacha20', key, iv);
			return plain(Buffer.concat([cipher.update(data), cipher.final()]));
		},
		randomBytes: (size) => {
			count('randomBytes');
			return plain(crypto.randomBytes(size));
		}
	};
	return { provider, calls };
}
