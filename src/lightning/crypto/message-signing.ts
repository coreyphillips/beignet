/**
 * LND-compatible message signing with the node identity key.
 *
 * Digest: double-SHA256('Lightning Signed Message:' || message).
 * Signature: 65-byte compact recoverable ECDSA
 * [header(27 + 4 + recoveryId) || r(32) || s(32)], zbase32-encoded.
 * The +4 marks a compressed public key, matching btcec SignCompact as used
 * by LND's signmessage/verifymessage RPCs.
 */

import * as secp from '@noble/secp256k1';
import crypto from 'crypto';
import { ensureHmac } from '../invoice/signing';

const SIGNED_MSG_PREFIX = 'Lightning Signed Message:';

// zbase32 alphabet (Tahoe-LAFS / tv42-zbase32, used by LND).
const ZBASE32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769';
const ZBASE32_REVERSE: Map<string, number> = new Map(
	[...ZBASE32_ALPHABET].map((c, i) => [c, i])
);

/** Encode bytes as zbase32 (MSB-first 5-bit groups, no padding chars). */
export function zbase32Encode(data: Buffer): string {
	let bits = 0;
	let value = 0;
	let out = '';
	for (const byte of data) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out += ZBASE32_ALPHABET[(value >> bits) & 31];
		}
	}
	if (bits > 0) {
		out += ZBASE32_ALPHABET[(value << (5 - bits)) & 31];
	}
	return out;
}

/** Decode zbase32 text to bytes. Returns null on any invalid character. */
export function zbase32Decode(text: string): Buffer | null {
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const ch of text) {
		const v = ZBASE32_REVERSE.get(ch);
		if (v === undefined) return null;
		value = (value << 5) | v;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out.push((value >> bits) & 0xff);
		}
	}
	// Leftover bits are encoder padding and must be zero.
	if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) return null;
	return Buffer.from(out);
}

function messageDigest(message: string | Buffer): Buffer {
	const msg =
		typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
	const first = crypto
		.createHash('sha256')
		.update(Buffer.concat([Buffer.from(SIGNED_MSG_PREFIX, 'utf8'), msg]))
		.digest();
	return crypto.createHash('sha256').update(first).digest();
}

/** Sign a message with the node key. Returns the zbase32 signature string. */
export function signMessageWithKey(
	message: string | Buffer,
	privateKey: Buffer
): string {
	ensureHmac();
	const digest = messageDigest(message);
	const [sig, recId] = secp.signSync(digest, privateKey, {
		recovered: true,
		der: false
	});
	const compact = Buffer.alloc(65);
	compact[0] = 27 + 4 + recId;
	Buffer.from(sig).copy(compact, 1);
	return zbase32Encode(compact);
}

export interface IVerifyMessageResult {
	/** True when the signature decodes and recovers a public key. */
	valid: boolean;
	/** Recovered compressed public key (33 bytes) when valid. */
	pubkey: Buffer | null;
}

/**
 * Verify an LND-style message signature by recovering the signer's public key.
 * Recovery success alone does not authenticate the signer: a tampered message
 * still recovers SOME key, just a different one. Callers must compare the
 * recovered pubkey against the expected node (LND checks its graph).
 */
export function verifyMessageSignature(
	message: string | Buffer,
	signature: string
): IVerifyMessageResult {
	const compact = zbase32Decode(signature);
	if (!compact || compact.length !== 65) {
		return { valid: false, pubkey: null };
	}
	const header = compact[0];
	if (header < 27 || header > 34) {
		return { valid: false, pubkey: null };
	}
	const recId = (header - 27) & 3;
	ensureHmac();
	const digest = messageDigest(message);
	try {
		const pubkey = secp.recoverPublicKey(
			digest,
			compact.subarray(1),
			recId,
			true
		);
		return { valid: true, pubkey: Buffer.from(pubkey) };
	} catch {
		return { valid: false, pubkey: null };
	}
}
