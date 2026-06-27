/**
 * BOLT 3: Anchor output scripts.
 *
 * Anchor outputs allow fee bumping via CPFP. Each commitment transaction
 * has two 330-sat anchor outputs (one for each party).
 *
 * With anchors:
 * - to_remote uses P2WSH with 1-block CSV (not plain P2WPKH)
 * - HTLC second-level txs have zero fee (fee bumped via CPFP on anchors)
 * - Two 330-sat anchor outputs are added to each commitment
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';

bitcoin.initEccLib(ecc);

/** Anchor output value per BOLT 3 (330 satoshis) */
export const ANCHOR_OUTPUT_VALUE = 330n;

/** Total anchor cost (two anchors) */
export const ANCHOR_TOTAL_COST = ANCHOR_OUTPUT_VALUE * 2n;

/**
 * Build the anchor output script:
 *   <funding_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CSV OP_ENDIF
 *
 * This allows the owner to spend immediately, or anyone after 16 blocks.
 */
export function buildAnchorScript(fundingPubkey: Buffer): Buffer {
	return bitcoin.script.compile([
		fundingPubkey,
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_IFDUP,
		bitcoin.opcodes.OP_NOTIF,
		bitcoin.opcodes.OP_16,
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
		bitcoin.opcodes.OP_ENDIF
	]);
}

/**
 * Build the to_remote script for anchor channels:
 *   <remotepubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
 *
 * This adds a 1-block CSV delay compared to the non-anchor P2WPKH to_remote.
 */
export function buildToRemoteAnchorScript(remotePubkey: Buffer): Buffer {
	return bitcoin.script.compile([
		remotePubkey,
		bitcoin.opcodes.OP_CHECKSIGVERIFY,
		bitcoin.script.number.encode(1),
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY
	]);
}

/**
 * Build the P2WSH output script for an anchor.
 */
export function buildAnchorOutput(fundingPubkey: Buffer): {
	script: Buffer;
	witnessScript: Buffer;
} {
	const witnessScript = buildAnchorScript(fundingPubkey);
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript } });
	return {
		script: p2wsh.output!,
		witnessScript
	};
}

/**
 * Build the P2WSH output script for a to_remote anchor output.
 */
export function buildToRemoteAnchorOutput(remotePubkey: Buffer): {
	script: Buffer;
	witnessScript: Buffer;
} {
	const witnessScript = buildToRemoteAnchorScript(remotePubkey);
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript } });
	return {
		script: p2wsh.output!,
		witnessScript
	};
}
