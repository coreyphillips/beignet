/**
 * BOLT 5: Penalty transaction construction.
 *
 * Builds transactions to claim all outputs when a counterparty
 * broadcasts a revoked commitment transaction.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { sign } from '../crypto/ecdh';

bitcoin.initEccLib(ecc);

/**
 * Build the witness for spending a to_local output using the revocation key.
 * Uses the OP_IF branch: <sig> 1
 *
 * @param signature - DER-encoded signature with sighash byte
 * @returns Witness stack for the revocation spend
 */
export function buildToLocalPenaltyWitness(
	signature: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [
		signature,
		Buffer.from([0x01]), // OP_TRUE for the OP_IF branch
		witnessScript
	];
}

/**
 * Build the witness for spending an HTLC output using the revocation key.
 * Uses the OP_DUP OP_HASH160 branch with the revocation pubkey.
 *
 * @param revocationSig - Signature from the revocation private key
 * @param revocationPubkey - The revocation public key
 * @param witnessScript - The HTLC witness script
 * @returns Witness stack for the revocation spend
 */
export function buildHtlcPenaltyWitness(
	revocationSig: Buffer,
	revocationPubkey: Buffer,
	witnessScript: Buffer
): Buffer[] {
	return [revocationSig, revocationPubkey, witnessScript];
}

/**
 * Parameters for building a penalty transaction.
 */
export interface IPenaltyTxParams {
	/** The revoked commitment transaction */
	revokedTx: bitcoin.Transaction;
	/** The revocation private key (derived from both secrets) */
	revocationPrivkey: Buffer;
	/** Destination address for swept funds */
	destinationAddress: string;
	/** Fee rate in satoshis per virtual byte */
	feeRatePerVbyte: number;
	/** The witness script for the to_local output */
	toLocalWitnessScript?: Buffer;
	/** Output indices to claim (to_local, HTLC outputs) */
	outputIndices: number[];
	/** Witness scripts for each output index */
	witnessScripts: Map<number, Buffer>;
	/** Network (default: mainnet) */
	network?: bitcoin.Network;
}

/**
 * Build a penalty transaction that sweeps funds from a revoked commitment.
 *
 * @returns The penalty transaction (unsigned — signatures added separately)
 */
export function buildPenaltyTx(params: IPenaltyTxParams): bitcoin.Transaction {
	const {
		revokedTx,
		destinationAddress,
		feeRatePerVbyte,
		outputIndices,
		witnessScripts,
		network = bitcoin.networks.bitcoin
	} = params;

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;

	const revokedTxid = revokedTx.getId();
	const txidBuf = Buffer.from(revokedTxid, 'hex').reverse();

	let totalValue = 0;

	for (const idx of outputIndices) {
		if (idx >= revokedTx.outs.length) {
			throw new Error(`Output index ${idx} out of range`);
		}
		tx.addInput(txidBuf, idx, 0xffffffff);
		totalValue += revokedTx.outs[idx].value;
	}

	// Estimate weight per BOLT 3. Each penalty input spends a P2WSH output whose
	// witness is [signature, <branch selector>, witnessScript]: the selector is a
	// 1-byte OP_TRUE for to_local or a 33-byte revocation pubkey for HTLC outputs
	// (use 33 as a safe upper bound). The flat 160-vbyte/input figure previously
	// used roughly doubled the true cost (~81 vb to_local / ~102 vb HTLC) and
	// over-paid materially when sweeping many outputs.
	let weightWu =
		4 * 4 /* nVersion */ +
		4 * 4 /* nLockTime */ +
		2 /* segwit marker + flag */ +
		1 * 4 /* input count (varint, assume < 253) */ +
		1 * 4; /* output count */
	for (const idx of outputIndices) {
		const scriptLen = witnessScripts.get(idx)?.length ?? 83;
		const scriptPrefix = scriptLen < 253 ? 1 : 3;
		weightWu += 41 * 4; // outpoint (36) + empty scriptSig len (1) + sequence (4)
		// witness: item count (1) + sig (1 + 73) + selector (1 + 33) + script (prefix + len)
		weightWu += 1 + (1 + 73) + (1 + 33) + (scriptPrefix + scriptLen);
	}
	weightWu += 31 * 4; // single P2WPKH-sized output (value 8 + len 1 + script 22)
	const estimatedVbytes = Math.ceil(weightWu / 4);
	const fee = estimatedVbytes * feeRatePerVbyte;

	const outputValue = totalValue - fee;
	if (outputValue <= 0) {
		throw new Error('Fee exceeds available value');
	}

	const destOutput = bitcoin.address.toOutputScript(
		destinationAddress,
		network
	);
	tx.addOutput(destOutput, outputValue);

	return tx;
}

/**
 * Sign a penalty transaction input with the revocation key.
 *
 * @param tx - The penalty transaction
 * @param inputIndex - Which input to sign
 * @param witnessScript - The witness script for the output being spent
 * @param value - The value of the output being spent
 * @param revocationPrivkey - The revocation private key
 * @returns DER-encoded signature with SIGHASH_ALL
 */
export function signPenaltyInput(
	tx: bitcoin.Transaction,
	inputIndex: number,
	witnessScript: Buffer,
	value: number,
	revocationPrivkey: Buffer
): Buffer {
	const sigHash = tx.hashForWitnessV0(
		inputIndex,
		witnessScript,
		value,
		bitcoin.Transaction.SIGHASH_ALL
	);

	const sig = sign(sigHash, revocationPrivkey);

	// Convert compact signature to DER and append sighash byte
	return Buffer.concat([
		encodeDerSignature(sig),
		Buffer.from([bitcoin.Transaction.SIGHASH_ALL])
	]);
}

/**
 * Encode a 64-byte compact signature to DER format.
 */
function encodeDerSignature(sig: Buffer): Buffer {
	if (sig.length !== 64) {
		throw new Error(`Signature must be 64 bytes, got ${sig.length}`);
	}

	const r = sig.subarray(0, 32);
	const s = sig.subarray(32, 64);

	function encodeInteger(val: Buffer): Buffer {
		let v = val;
		// Remove leading zeros
		let start = 0;
		while (start < v.length - 1 && v[start] === 0) start++;
		v = v.subarray(start);
		// Add leading zero if high bit set
		if (v[0] & 0x80) {
			v = Buffer.concat([Buffer.from([0x00]), v]);
		}
		return Buffer.concat([Buffer.from([0x02, v.length]), v]);
	}

	const rDer = encodeInteger(r);
	const sDer = encodeInteger(s);

	return Buffer.concat([
		Buffer.from([0x30, rDer.length + sDer.length]),
		rDer,
		sDer
	]);
}
