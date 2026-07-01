/**
 * Simple taproot channels (option_taproot): funding output.
 *
 * The funding output is a 2-of-2 MuSig2 key-spend P2TR. Both parties aggregate
 * their funding pubkeys (BIP327), apply the BIP341 key-spend taproot tweak with
 * an empty merkle root, and the resulting x-only output key becomes the P2TR
 * scriptPubKey. Spending requires a single co-signed BIP340 Schnorr signature.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { deriveTaprootFundingKey } from '../crypto/musig';

// Ensure ECC is initialized for bitcoinjs-lib taproot operations.
bitcoin.initEccLib(ecc);

/** Components of a taproot (option_taproot) channel funding output. */
export interface ITaprootFundingScript {
	/** 32-byte x-only INTERNAL key (the untweaked MuSig2 aggregate). */
	internalKey: Buffer;
	/** 32-byte x-only OUTPUT key (after the BIP341 key-spend tweak). */
	outputKey: Buffer;
	/** BIP341 taproot tweak scalar = taggedHash("TapTweak", internalKey). */
	tweak: Buffer;
	/** scriptPubKey: OP_1 <32-byte output key> (P2TR). */
	p2trOutput: Buffer;
	/** bech32m address for the funding output. */
	address: string;
}

/**
 * Build the 2-of-2 MuSig2 key-spend taproot funding output from both funding
 * pubkeys. Order-independent (keys are sorted via BIP327 KeySort internally).
 */
export function createTaprootFundingScript(
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ITaprootFundingScript {
	if (localFundingPubkey.length !== 33 || remoteFundingPubkey.length !== 33) {
		throw new Error('Funding pubkeys must be 33 bytes compressed');
	}
	const { internalKey, outputKey, tweak } = deriveTaprootFundingKey(
		localFundingPubkey,
		remoteFundingPubkey
	);
	// P2TR scriptPubKey: OP_1 (0x51) PUSH_32 (0x20) <output key>.
	const p2trOutput = Buffer.concat([Buffer.from([0x51, 0x20]), outputKey]);
	const address = bitcoin.address.fromOutputScript(p2trOutput, network);
	return { internalKey, outputKey, tweak, p2trOutput, address };
}

/**
 * Witness for a MuSig2 key-spend of the taproot funding output: a single BIP340
 * Schnorr signature — 64 bytes for SIGHASH_DEFAULT, or 65 bytes with the
 * sighash-type byte appended for any non-default type.
 */
export function buildTaprootKeySpendWitness(schnorrSig: Buffer): Buffer[] {
	if (schnorrSig.length !== 64 && schnorrSig.length !== 65) {
		throw new Error('Taproot key-spend signature must be 64 or 65 bytes');
	}
	return [schnorrSig];
}

/**
 * BIP341 key-spend sighash for a transaction spending taproot inputs (e.g. the
 * commitment or closing transaction spending the funding output). All spent
 * outputs' scripts and values must be supplied (BIP341 signs over all inputs).
 *
 * @param sighashType bitcoin.Transaction.SIGHASH_DEFAULT (0x00) by default.
 */
export function taprootKeySpendSighash(
	tx: bitcoin.Transaction,
	inputIndex: number,
	prevOutScripts: Buffer[],
	prevOutValues: number[],
	sighashType: number = bitcoin.Transaction.SIGHASH_DEFAULT
): Buffer {
	return tx.hashForWitnessV1(
		inputIndex,
		prevOutScripts,
		prevOutValues,
		sighashType
	);
}
