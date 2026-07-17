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
 *   <remotepubkey> OP_CHECKSIGVERIFY
 *   <csv> OP_CHECKSEQUENCEVERIFY
 *
 * csv is 1 for a normal channel (the standard anchored to_remote), and the
 * remaining lease blocks for the LESSOR's output on a leased channel — CLN's
 * bitcoin_wscript_to_remote_anchored model (bLIP-0051 leases are a pure CSV;
 * leaseCsv = lease_expiry - agreed blockheight, 4032 at open). The earlier
 * LND-Pool style CLTV variant produced commitments CLN rejects.
 */
export function buildToRemoteAnchorScript(
	remotePubkey: Buffer,
	leaseCsv?: number
): Buffer {
	const csv = leaseCsv !== undefined && leaseCsv > 1 ? leaseCsv : 1;
	return bitcoin.script.compile([
		remotePubkey,
		bitcoin.opcodes.OP_CHECKSIGVERIFY,
		bitcoin.script.number.encode(csv),
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY
	]);
}

/**
 * If the witness script is a lease-locked anchored to_remote (the CLN layout
 * above with csv > 1), return its remaining-lease CSV; undefined for the
 * plain variant or any other script. Spend paths derive the required input
 * SEQUENCE from the on-chain script itself so sweeps work even from restored
 * state that lost the lease fields.
 */
export function leaseCsvFromToRemoteScript(
	witnessScript: Buffer
): number | undefined {
	const chunks = bitcoin.script.decompile(witnessScript);
	if (!chunks || chunks.length !== 4) return undefined;
	const [pubkey, checksigverify, csvNum, csv] = chunks;
	if (
		!Buffer.isBuffer(pubkey) ||
		pubkey.length !== 33 ||
		checksigverify !== bitcoin.opcodes.OP_CHECKSIGVERIFY ||
		csv !== bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY
	) {
		return undefined;
	}
	// Plain anchored to_remote encodes 1 as OP_1 (a number opcode, not a
	// push); anything above 1 is a lease lock.
	if (csvNum === bitcoin.opcodes.OP_1) return undefined;
	if (!Buffer.isBuffer(csvNum)) return undefined;
	try {
		const v = bitcoin.script.number.decode(csvNum);
		return v > 1 ? v : undefined;
	} catch {
		return undefined;
	}
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
 * Build the P2WSH output script for a to_remote anchor output. Pass
 * `leaseCsv` (remaining lease blocks) for the lease-locked (lessor) variant.
 */
export function buildToRemoteAnchorOutput(
	remotePubkey: Buffer,
	leaseCsv?: number
): {
	script: Buffer;
	witnessScript: Buffer;
} {
	const witnessScript = buildToRemoteAnchorScript(remotePubkey, leaseCsv);
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript } });
	return {
		script: p2wsh.output!,
		witnessScript
	};
}
