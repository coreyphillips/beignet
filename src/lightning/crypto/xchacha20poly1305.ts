import {
	encrypt as chachaEncrypt,
	decrypt as chachaDecrypt
} from './chacha20poly1305';

/**
 * XChaCha20-Poly1305 AEAD (24-byte nonce), as used by LND's watchtower blob
 * encryption (golang.org/x/crypto/chacha20poly1305 NewX). Node's built-in
 * chacha20-poly1305 is the 12-byte-nonce IETF variant only, so the extended
 * nonce is handled by deriving a subkey with HChaCha20 and delegating the
 * remaining 8 nonce bytes to the IETF construction (RFC draft-irtf-cfrg-xchacha).
 */

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function rotl32(x: number, n: number): number {
	return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * HChaCha20 core: derives a 32-byte subkey from a 32-byte key and a 16-byte
 * nonce. This is the ChaCha20 block function run for 20 rounds with the final
 * key/counter addition omitted, keeping words 0..3 and 12..15.
 */
function hchacha20(key: Buffer, nonce16: Buffer): Buffer {
	const state = new Uint32Array(16);
	state[0] = SIGMA[0];
	state[1] = SIGMA[1];
	state[2] = SIGMA[2];
	state[3] = SIGMA[3];
	for (let i = 0; i < 8; i++) {
		state[4 + i] = key.readUInt32LE(i * 4);
	}
	for (let i = 0; i < 4; i++) {
		state[12 + i] = nonce16.readUInt32LE(i * 4);
	}

	const qr = (a: number, b: number, c: number, d: number): void => {
		state[a] = (state[a] + state[b]) >>> 0;
		state[d] = rotl32(state[d] ^ state[a], 16);
		state[c] = (state[c] + state[d]) >>> 0;
		state[b] = rotl32(state[b] ^ state[c], 12);
		state[a] = (state[a] + state[b]) >>> 0;
		state[d] = rotl32(state[d] ^ state[a], 8);
		state[c] = (state[c] + state[d]) >>> 0;
		state[b] = rotl32(state[b] ^ state[c], 7);
	};

	for (let round = 0; round < 10; round++) {
		qr(0, 4, 8, 12);
		qr(1, 5, 9, 13);
		qr(2, 6, 10, 14);
		qr(3, 7, 11, 15);
		qr(0, 5, 10, 15);
		qr(1, 6, 11, 12);
		qr(2, 7, 8, 13);
		qr(3, 4, 9, 14);
	}

	const out = Buffer.alloc(32);
	for (let i = 0; i < 4; i++) {
		out.writeUInt32LE(state[i] >>> 0, i * 4);
	}
	for (let i = 0; i < 4; i++) {
		out.writeUInt32LE(state[12 + i] >>> 0, 16 + i * 4);
	}
	return out;
}

/** Build the 12-byte IETF nonce from the last 8 bytes of a 24-byte nonce. */
function ietfNonce(nonce24: Buffer): Buffer {
	const nonce = Buffer.alloc(12);
	nonce24.subarray(16, 24).copy(nonce, 4);
	return nonce;
}

/**
 * Encrypt with XChaCha20-Poly1305.
 * @param key - 32-byte key
 * @param nonce - 24-byte nonce
 * @param plaintext - data to encrypt
 * @param aad - optional additional authenticated data
 * @returns ciphertext with 16-byte Poly1305 tag appended
 */
export function encrypt(
	key: Buffer,
	nonce: Buffer,
	plaintext: Buffer,
	aad: Buffer = Buffer.alloc(0)
): Buffer {
	if (key.length !== 32) {
		throw new Error(`Key must be 32 bytes, got ${key.length}`);
	}
	if (nonce.length !== 24) {
		throw new Error(`Nonce must be 24 bytes, got ${nonce.length}`);
	}
	const subkey = hchacha20(key, nonce.subarray(0, 16));
	return chachaEncrypt(subkey, ietfNonce(nonce), plaintext, aad);
}

/**
 * Decrypt with XChaCha20-Poly1305.
 * @param key - 32-byte key
 * @param nonce - 24-byte nonce
 * @param ciphertextWithTag - ciphertext with 16-byte tag appended
 * @param aad - optional additional authenticated data
 * @returns decrypted plaintext
 * @throws if authentication fails
 */
export function decrypt(
	key: Buffer,
	nonce: Buffer,
	ciphertextWithTag: Buffer,
	aad: Buffer = Buffer.alloc(0)
): Buffer {
	if (key.length !== 32) {
		throw new Error(`Key must be 32 bytes, got ${key.length}`);
	}
	if (nonce.length !== 24) {
		throw new Error(`Nonce must be 24 bytes, got ${nonce.length}`);
	}
	const subkey = hchacha20(key, nonce.subarray(0, 16));
	return chachaDecrypt(subkey, ietfNonce(nonce), ciphertextWithTag, aad);
}
