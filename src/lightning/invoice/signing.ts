/**
 * BOLT 11: Invoice signing and verification using ECDSA with recovery ID.
 *
 * Uses @noble/secp256k1 directly since @bitcoinerlab/secp256k1 does not
 * expose signRecoverable/recoverPublicKey operations.
 */

import * as secp from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import crypto from 'crypto';

let hmacSetup = false;

/**
 * One-time setup: configure noble-secp256k1 with synchronous HMAC-SHA256.
 * Safe to call multiple times (idempotent).
 */
export function ensureHmac(): void {
	if (!hmacSetup) {
		secp.utils.hmacSha256Sync = (
			k: Uint8Array,
			...m: Uint8Array[]
		): Uint8Array => hmac(sha256, k, secp.utils.concatBytes(...m));
		hmacSetup = true;
	}
}

/**
 * Convert 5-bit words to 8-bit bytes with right-padding.
 * This matches the BOLT 11 reference implementation and LND's zpay32:
 * leftover bits are right-padded with zeros to fill the last byte.
 * Unlike bech32.fromWords, this keeps the padded final byte.
 */
function wordsToSigningBytes(words: number[]): Buffer {
	let value = 0;
	let bits = 0;
	const result: number[] = [];

	for (let i = 0; i < words.length; i++) {
		value = (value << 5) | words[i];
		bits += 5;
		while (bits >= 8) {
			bits -= 8;
			result.push((value >> bits) & 0xff);
		}
	}
	if (bits > 0) {
		result.push((value << (8 - bits)) & 0xff);
	}

	return Buffer.from(result);
}

/**
 * Compute the signing hash for a BOLT 11 invoice.
 * Per BOLT 11: SHA256( UTF8(hrp) || wordsToBytes(data) )
 *
 * The data words (5-bit values) are converted to 8-bit bytes with
 * right-padding before hashing. This matches the reference implementation
 * and LND's zpay32 decoder.
 *
 * Note: dataWords includes timestamp + tagged fields, but NOT the signature words.
 */
export function computeSigningHash(hrp: string, dataWords: number[]): Buffer {
	const hrpBytes = Buffer.from(hrp, 'utf8');
	const dataBytes = wordsToSigningBytes(dataWords);
	const preimage = Buffer.concat([hrpBytes, dataBytes]);
	return crypto.createHash('sha256').update(preimage).digest();
}

/**
 * Sign an invoice and return a 65-byte buffer: [signature(64) || recoveryId(1)].
 */
export function signInvoice(
	hrp: string,
	dataWords: number[],
	privateKey: Buffer
): Buffer {
	ensureHmac();
	const hash = computeSigningHash(hrp, dataWords);
	const [sig, recId] = secp.signSync(hash, privateKey, {
		recovered: true,
		der: false
	});
	const result = Buffer.alloc(65);
	Buffer.from(sig).copy(result, 0);
	result[64] = recId;
	return result;
}

/**
 * Derive the compressed public key for a private key using the same library
 * that signs invoices (@noble/secp256k1). This ensures the payeeNodeKey
 * in tag 19 always matches the pubkey recovered from the signature.
 */
export function getInvoiceSignerPubkey(privateKey: Buffer): Buffer {
	ensureHmac();
	return Buffer.from(secp.getPublicKey(privateKey, true));
}

/**
 * Verify an invoice signature and recover the signer's compressed public key.
 * Returns the 33-byte compressed pubkey, or null if recovery fails.
 *
 * @param signature - 65-byte buffer: [sig(64) || recoveryId(1)]
 */
export function verifyInvoice(
	hrp: string,
	dataWords: number[],
	signature: Buffer
): Buffer | null {
	if (signature.length !== 65) {
		return null;
	}
	ensureHmac();
	const hash = computeSigningHash(hrp, dataWords);
	const sig = signature.subarray(0, 64);
	const recId = signature[64];
	if (recId > 3) {
		return null;
	}
	try {
		const pubkey = secp.recoverPublicKey(hash, sig, recId, true);
		return Buffer.from(pubkey);
	} catch {
		return null;
	}
}
