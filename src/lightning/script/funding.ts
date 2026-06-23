/**
 * BOLT 3: Funding output script.
 *
 * Creates the 2-of-2 P2WSH multisig script used for channel funding.
 * The two funding public keys MUST be lexicographically sorted.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';

// Ensure ECC is initialized for bitcoinjs-lib
bitcoin.initEccLib(ecc);

/**
 * Result of creating a funding script.
 */
export interface IFundingScript {
	/** The raw witness script: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG */
	witnessScript: Buffer;
	/** The P2WSH output script: OP_0 <SHA256(witnessScript)> */
	p2wshOutput: Buffer;
	/** The P2WSH address */
	address: string;
}

/**
 * Create the 2-of-2 multisig funding script for a Lightning channel.
 * Public keys are automatically sorted lexicographically (smaller first).
 *
 * @param localFundingPubkey - 33-byte compressed public key
 * @param remoteFundingPubkey - 33-byte compressed public key
 * @param network - Bitcoin network (default: mainnet)
 * @returns Funding script components
 */
export function createFundingScript(
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): IFundingScript {
	if (localFundingPubkey.length !== 33 || remoteFundingPubkey.length !== 33) {
		throw new Error('Funding pubkeys must be 33 bytes compressed');
	}

	// Sort keys lexicographically (BOLT 3 requirement)
	const [pk1, pk2] = [localFundingPubkey, remoteFundingPubkey].sort(
		Buffer.compare
	);

	// Build witness script: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
	const witnessScript = bitcoin.script.compile([
		bitcoin.opcodes.OP_2,
		pk1,
		pk2,
		bitcoin.opcodes.OP_2,
		bitcoin.opcodes.OP_CHECKMULTISIG
	]);

	// Create P2WSH payment
	const p2wsh = bitcoin.payments.p2wsh({
		redeem: { output: witnessScript },
		network
	});

	if (!p2wsh.output || !p2wsh.address) {
		throw new Error('Failed to create P2WSH payment');
	}

	return {
		witnessScript,
		p2wshOutput: p2wsh.output,
		address: p2wsh.address
	};
}

/**
 * Get the SHA256 hash of the funding witness script.
 * This is the hash used in the P2WSH output.
 */
export function getFundingScriptHash(witnessScript: Buffer): Buffer {
	return crypto.createHash('sha256').update(witnessScript).digest();
}
