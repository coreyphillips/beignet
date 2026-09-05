/**
 * Appendix F.3: the record body's encryption to R's enc_pubkey.
 *
 * ECIES over secp256k1: the witness draws an ephemeral key e, computes
 * s = SHA256(ECDH(e, enc_pubkey)) (beignet's ecdh() already hashes the
 * point), derives key = HKDF-SHA256(s, "ffor/witness/body") with an empty
 * salt and the tag as info, and seals the body with ChaCha20-Poly1305 under
 * an all-zero nonce (the key is single use) and the encoded record header as
 * associated data. ciphertext = [33: e_pub] || aead_output.
 */

import crypto from 'crypto';
import { ecdh, getPublicKey } from '../crypto/ecdh';
import { hkdf } from '../crypto/hkdf';
import { decrypt, encrypt } from '../crypto/chacha20poly1305';
import { FF_WITNESS_BODY_INFO } from './witness-types';

const NONCE = Buffer.alloc(12);

function keyFor(shared: Buffer): Buffer {
	return hkdf(
		Buffer.alloc(0),
		shared,
		Buffer.from(FF_WITNESS_BODY_INFO, 'ascii'),
		32
	);
}

/** Seal `body` to `encPubkey`, binding it to `headerBytes`. */
export function sealRecordBody(
	encPubkey: Buffer,
	headerBytes: Buffer,
	body: Buffer
): Buffer {
	const e = crypto.randomBytes(32);
	const ePub = getPublicKey(e);
	const key = keyFor(ecdh(e, encPubkey));
	return Buffer.concat([ePub, encrypt(key, NONCE, body, headerBytes)]);
}

/** Open a ciphertext with the enc_key private half; throws on any tamper. */
export function openRecordBody(
	encPrivkey: Buffer,
	headerBytes: Buffer,
	ciphertext: Buffer
): Buffer {
	if (ciphertext.length < 33 + 16) throw new Error('ciphertext too short');
	const ePub = ciphertext.subarray(0, 33);
	const key = keyFor(ecdh(encPrivkey, ePub));
	return decrypt(key, NONCE, ciphertext.subarray(33), headerBytes);
}
