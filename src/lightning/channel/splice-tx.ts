/**
 * BOLT 2 (PR #1160): Splice transaction construction & shared-input signing.
 *
 * A splice transaction spends the channel's current funding output (a 2-of-2
 * P2WSH "shared input" requiring both parties' signatures, exactly like a
 * cooperative close) and creates a new funding output (the "shared output")
 * for the post-splice channel capacity. It may also carry:
 *   - extra inputs contributed by either party (splice-in: wallet UTXOs)
 *   - a change output (splice-in) or a destination output (splice-out)
 *
 * Both peers independently build the SAME transaction from the inputs/outputs
 * they negotiated via the interactive-tx protocol (ordered by serial_id), so
 * they derive an identical txid and can exchange signatures for the shared
 * input. This module is deliberately pure: given the negotiated inputs/outputs
 * it produces the unsigned tx, and given the funding key material it produces /
 * verifies the shared-input signature. No wallet, network, or channel state.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ChannelSigner } from '../keys/signer';
import { createFundingScript } from '../script/funding';

bitcoin.initEccLib(ecc);

/** An input in the splice transaction. */
export interface ISpliceTxInput {
	/** Serial id negotiated via the interactive-tx protocol (orders the tx). */
	serialId: bigint;
	/** Previous output txid in internal byte order (as from Transaction.getHash()). */
	prevTxid: Buffer;
	/** Previous output index. */
	prevOutputIndex: number;
	/** nSequence for this input. */
	sequence: number;
}

/** An output in the splice transaction. */
export interface ISpliceTxOutput {
	/** Serial id negotiated via the interactive-tx protocol (orders the tx). */
	serialId: bigint;
	/** Output scriptPubkey. */
	script: Buffer;
	/** Output value in satoshis. */
	valueSats: bigint;
}

/**
 * Build the unsigned splice transaction from the negotiated inputs and outputs.
 *
 * Per BOLT 2 interactive-tx, the final transaction orders inputs and outputs by
 * ascending serial_id. Version is 2 so nSequence-based relative locktime rules
 * apply.
 */
export function buildSpliceTx(
	inputs: ISpliceTxInput[],
	outputs: ISpliceTxOutput[],
	locktime: number
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = locktime >>> 0;

	const sortedInputs = [...inputs].sort((a, b) =>
		a.serialId < b.serialId ? -1 : a.serialId > b.serialId ? 1 : 0
	);
	const sortedOutputs = [...outputs].sort((a, b) =>
		a.serialId < b.serialId ? -1 : a.serialId > b.serialId ? 1 : 0
	);

	for (const input of sortedInputs) {
		if (input.prevTxid.length !== 32) {
			throw new Error(
				`prevTxid must be 32 bytes, got ${input.prevTxid.length}`
			);
		}
		// bitcoinjs addInput expects the hash in internal byte order, which is
		// exactly what we store (and what Transaction.getHash() returns).
		tx.addInput(input.prevTxid, input.prevOutputIndex, input.sequence >>> 0);
	}

	for (const output of sortedOutputs) {
		tx.addOutput(output.script, Number(output.valueSats));
	}

	return tx;
}

/**
 * Find the index (in the built, serial-id-ordered transaction) of the input
 * spending a given outpoint. Returns -1 if not present.
 */
export function findInputIndex(
	tx: bitcoin.Transaction,
	prevTxid: Buffer,
	prevOutputIndex: number
): number {
	for (let i = 0; i < tx.ins.length; i++) {
		// tx.ins[i].hash is internal byte order, same as our stored prevTxid.
		if (
			tx.ins[i].index === prevOutputIndex &&
			Buffer.from(tx.ins[i].hash).equals(prevTxid)
		) {
			return i;
		}
	}
	return -1;
}

/**
 * Find the index of the output paying to a given scriptPubkey (e.g. the new
 * funding output). Returns -1 if not present.
 */
export function findOutputIndex(
	tx: bitcoin.Transaction,
	script: Buffer
): number {
	for (let i = 0; i < tx.outs.length; i++) {
		if (tx.outs[i].script.equals(script)) {
			return i;
		}
	}
	return -1;
}

/**
 * Sign the shared 2-of-2 funding input of a splice transaction.
 *
 * This is the same sighash a cooperative close uses (SIGHASH_ALL over the
 * P2WSH 2-of-2), so it reuses ChannelSigner.signCommitmentTx.
 *
 * @param tx - The unsigned splice transaction.
 * @param sharedInputIndex - Index of the funding input within `tx`.
 * @param oldFundingWitnessScript - The 2-of-2 witness script of the output being spent.
 * @param fundingValueSats - Value of the funding output being spent.
 * @param signer - Signer holding our funding private key.
 * @returns 64-byte compact signature.
 */
export function signSpliceSharedInput(
	tx: bitcoin.Transaction,
	sharedInputIndex: number,
	oldFundingWitnessScript: Buffer,
	fundingValueSats: bigint,
	signer: ChannelSigner
): Buffer {
	const sigHash = tx.hashForWitnessV0(
		sharedInputIndex,
		oldFundingWitnessScript,
		Number(fundingValueSats),
		bitcoin.Transaction.SIGHASH_ALL
	);
	// Same primitive as commitment/closing: sign the sighash with our funding key.
	return signer.signFundingDigest(sigHash);
}

/**
 * Verify a peer's signature on the shared funding input.
 */
export function verifySpliceSharedInput(
	tx: bitcoin.Transaction,
	sharedInputIndex: number,
	oldFundingWitnessScript: Buffer,
	fundingValueSats: bigint,
	remoteFundingPubkey: Buffer,
	signature: Buffer
): boolean {
	const sigHash = tx.hashForWitnessV0(
		sharedInputIndex,
		oldFundingWitnessScript,
		Number(fundingValueSats),
		bitcoin.Transaction.SIGHASH_ALL
	);
	return ecc.verify(sigHash, remoteFundingPubkey, signature);
}

/**
 * Assemble the witness stack for the shared 2-of-2 funding input and attach it
 * to the transaction. Signature order follows the lexicographic pubkey order
 * baked into the 2-of-2 script (BOLT 3), reusing ChannelSigner.buildFundingWitness.
 */
export function finalizeSpliceSharedWitness(
	tx: bitcoin.Transaction,
	sharedInputIndex: number,
	localSig: Buffer,
	remoteSig: Buffer,
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer,
	oldFundingWitnessScript: Buffer
): void {
	const witness = ChannelSigner.buildFundingWitness(
		localSig,
		remoteSig,
		localFundingPubkey,
		remoteFundingPubkey,
		oldFundingWitnessScript
	);
	tx.setWitness(sharedInputIndex, witness);
}

/**
 * Build the new funding output (script + address) for the post-splice channel
 * from the two parties' splice funding pubkeys. Thin wrapper over
 * createFundingScript so callers don't re-import it.
 */
export function newFundingOutput(
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer,
	network?: bitcoin.Network
): { script: Buffer; witnessScript: Buffer; address: string } {
	const fs = createFundingScript(
		localFundingPubkey,
		remoteFundingPubkey,
		network
	);
	return {
		script: fs.p2wshOutput,
		witnessScript: fs.witnessScript,
		address: fs.address
	};
}
