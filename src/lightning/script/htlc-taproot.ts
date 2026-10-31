/**
 * Simple taproot channels (option_taproot): second-level HTLC transactions.
 *
 * For a taproot channel the HTLC-success / HTLC-timeout transactions spend the
 * P2TR HTLC output through its 2-of-2 tapscript leaf (offered→timeout leaf,
 * received→success leaf) and pay into a taproot second-level output (the
 * REVOCATION key as internal key + a single CSV-delay leaf — LND's
 * TaprootSecondLevelScriptTree, NOT the to_local script). Both parties sign
 * the SAME BIP342 tapscript-path sighash with their HTLC key — these are plain
 * BIP340 Schnorr signatures (only the funding output uses MuSig2), so they ride
 * in commitment_signed's htlc_signatures exactly like the legacy ECDSA ones.
 *
 * Taproot simple channels are zero-fee-HTLC (option_anchors): the second-level
 * tx pays no fee (output value = full HTLC amount) and is fee-bumped by the
 * broadcaster, who attaches its own input(s)/change. To allow that, the HTLC
 * signatures use SIGHASH_SINGLE | SIGHASH_ANYONECANPAY (taproot 0x83) — exactly
 * as the legacy option_anchors ECDSA path does — so each sig commits only to its
 * own input (the HTLC output) and the single corresponding output. The 64-byte
 * Schnorr signature is what travels in commitment_signed.htlc_signatures (the
 * 0x83 sighash byte is implicit and appended only when building the witness).
 */

import * as bitcoin from 'bitcoinjs-lib';
import type { ITaprootAuxLeaf } from './commitment-taproot';
import { tapleafHash as bip341TapleafHash } from 'bitcoinjs-lib/src/payments/bip341';
import { ecc } from '../../utils/ecc';
import {
	buildTaprootSecondLevelOutput,
	TAPLEAF_VERSION
} from './commitment-taproot';

bitcoin.initEccLib(ecc);

/**
 * Compatibility sighash type for Taproot HTLC second-level signatures: SIGHASH_SINGLE
 * (0x03) | SIGHASH_ANYONECANPAY (0x80) = 0x83. The byte is implicit on the wire
 * (sigs are 64 bytes) and appended only when assembling the spend witness.
 * Native asset channel mode 450 instead selects ALL|ANYONECANPAY (0x81).
 */
export const TAPROOT_HTLC_SIGHASH_TYPE =
	bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

/**
 * BIP341 tapleaf hash: tagged_hash("TapLeaf", leaf_version ||
 * compact_size(len(script)) || script).
 */
export function tapleafHash(
	leafScript: Buffer,
	version: number = TAPLEAF_VERSION
): Buffer {
	return bip341TapleafHash({ output: leafScript, version });
}

/**
 * BIP342 tapscript-path sighash for input 0 of a second-level HTLC transaction
 * spending a P2TR HTLC output via `leafScript`.
 */
export function taprootHtlcLeafSighash(
	tx: bitcoin.Transaction,
	htlcOutputScript: Buffer,
	htlcAmountSat: number,
	leafScript: Buffer,
	leafVersion: number = TAPLEAF_VERSION,
	hashType: 0x81 | 0x83 = 0x83
): Buffer {
	return tx.hashForWitnessV1(
		0,
		[htlcOutputScript],
		[htlcAmountSat],
		hashType,
		tapleafHash(leafScript, leafVersion)
	);
}

/**
 * Build a zero-fee taproot HTLC-success transaction (spends a received HTLC
 * output via its preimage/2-of-2 success leaf). Output = full HTLC amount into a
 * to_local-style taproot output; nLockTime 0; input nSequence 1 (1-block CSV).
 */
export function buildTaprootHtlcSuccessTx(
	htlcTxid: string,
	htlcOutputIndex: number,
	htlcAmount: bigint,
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number,
	network: bitcoin.Network = bitcoin.networks.bitcoin,
	auxiliaryLeaf?: ITaprootAuxLeaf
): bitcoin.Transaction {
	return buildSecondLevel(
		htlcTxid,
		htlcOutputIndex,
		htlcAmount,
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay,
		0,
		network,
		auxiliaryLeaf
	);
}

/**
 * Build a zero-fee taproot HTLC-timeout transaction (spends an offered HTLC
 * output via its 2-of-2 timeout leaf). Same shape as the success tx but with
 * nLockTime = cltv_expiry.
 */
export function buildTaprootHtlcTimeoutTx(
	htlcTxid: string,
	htlcOutputIndex: number,
	htlcAmount: bigint,
	cltvExpiry: number,
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number,
	network: bitcoin.Network = bitcoin.networks.bitcoin,
	auxiliaryLeaf?: ITaprootAuxLeaf
): bitcoin.Transaction {
	return buildSecondLevel(
		htlcTxid,
		htlcOutputIndex,
		htlcAmount,
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay,
		cltvExpiry,
		network,
		auxiliaryLeaf
	);
}

function buildSecondLevel(
	htlcTxid: string,
	htlcOutputIndex: number,
	htlcAmount: bigint,
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number,
	nLockTime: number,
	network: bitcoin.Network,
	auxiliaryLeaf?: ITaprootAuxLeaf
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = nLockTime;

	const txidBuf = Buffer.from(htlcTxid, 'hex').reverse();
	// Zero-fee-HTLC: 1-block CSV on the input (BOLT 3 option_anchors).
	tx.addInput(txidBuf, htlcOutputIndex, 1);

	// The second-level output is NOT the to_local script: it uses the revocation
	// key as the taproot internal key + a single delay leaf (LND
	// TaprootSecondLevelScriptTree). Must match for the htlc sigs to verify.
	const out = buildTaprootSecondLevelOutput(
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay,
		network,
		auxiliaryLeaf
	);
	// Zero-fee: the whole HTLC amount carries over (fee comes from CPFP/anchor).
	tx.addOutput(out.output, Number(htlcAmount));

	return tx;
}

/** Schnorr-sign a tapscript-path sighash with an HTLC private key (BIP340). */
export function signTaprootHtlcLeaf(sighash: Buffer, privkey: Buffer): Buffer {
	return Buffer.from(ecc.signSchnorr(sighash, privkey));
}

/** Verify a BIP340 Schnorr signature over a tapscript-path sighash. */
export function verifyTaprootHtlcLeaf(
	sighash: Buffer,
	xOnlyPubkey: Buffer,
	sig: Buffer
): boolean {
	const x = xOnlyPubkey.length === 33 ? xOnlyPubkey.subarray(1) : xOnlyPubkey;
	// A correctly-counted but malformed peer signature (out-of-range scalar)
	// makes verifySchnorr THROW rather than return false; the throw would
	// escape handleCommitmentSigned's refusal arms entirely. Malformed means
	// invalid.
	try {
		return ecc.verifySchnorr(sighash, x, sig);
	} catch {
		return false;
	}
}
