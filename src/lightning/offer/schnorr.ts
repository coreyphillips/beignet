/**
 * BOLT 12: BIP 340 Schnorr Signature Wrapper.
 *
 * Uses @bitcoinerlab/secp256k1 which provides signSchnorr and verifySchnorr.
 * BIP 340 operates on x-only (32-byte) public keys.
 */

import * as ecc from '@bitcoinerlab/secp256k1';

/**
 * Sign a 32-byte message with BIP 340 Schnorr.
 *
 * @param message - 32-byte message hash to sign
 * @param privateKey - 32-byte private key
 * @returns 64-byte Schnorr signature
 */
export function schnorrSign(message: Buffer, privateKey: Buffer): Buffer {
	if (message.length !== 32) {
		throw new Error(`Message must be 32 bytes, got ${message.length}`);
	}
	if (privateKey.length !== 32) {
		throw new Error(`Private key must be 32 bytes, got ${privateKey.length}`);
	}

	const sig = ecc.signSchnorr(message, privateKey);
	return Buffer.from(sig);
}

/**
 * Verify a BIP 340 Schnorr signature.
 *
 * @param message - 32-byte message hash that was signed
 * @param publicKey - 32-byte x-only public key
 * @param signature - 64-byte Schnorr signature
 * @returns true if signature is valid
 */
export function schnorrVerify(
	message: Buffer,
	publicKey: Buffer,
	signature: Buffer
): boolean {
	if (message.length !== 32) {
		throw new Error(`Message must be 32 bytes, got ${message.length}`);
	}
	if (publicKey.length !== 32) {
		throw new Error(
			`Public key must be 32 bytes (x-only), got ${publicKey.length}`
		);
	}
	if (signature.length !== 64) {
		throw new Error(`Signature must be 64 bytes, got ${signature.length}`);
	}

	return ecc.verifySchnorr(message, publicKey, signature);
}

/**
 * Convert a 33-byte compressed public key to a 32-byte x-only public key.
 * Strips the prefix byte (0x02 or 0x03).
 */
export function toXOnlyPubkey(compressedPubkey: Buffer): Buffer {
	if (compressedPubkey.length === 32) {
		return compressedPubkey; // Already x-only
	}
	if (compressedPubkey.length !== 33) {
		throw new Error(
			`Expected 33-byte compressed pubkey, got ${compressedPubkey.length}`
		);
	}
	return Buffer.from(compressedPubkey.subarray(1));
}

/**
 * Get the x-only public key from a private key.
 */
export function xOnlyPubkeyFromPrivkey(privateKey: Buffer): Buffer {
	const xonly = ecc.xOnlyPointFromScalar(privateKey);
	return Buffer.from(xonly);
}
