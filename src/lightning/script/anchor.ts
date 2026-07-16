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
 *   [<lease_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP]   (liquidity-ads lessor only)
 *   1 OP_CHECKSEQUENCEVERIFY
 *
 * This adds a 1-block CSV delay compared to the non-anchor P2WPKH to_remote.
 *
 * When `leaseExpiry` is set (liquidity ads / script-enforced lease), an
 * absolute CLTV is inserted between the CHECKSIGVERIFY and the 1-block CSV so
 * the LESSOR cannot sweep its balance from the lessee's commitment before the
 * lease expires — matching LND's LeaseCommitScriptToRemoteConfirmed. The
 * spending tx must set nLockTime >= lease_expiry in addition to the CSV.
 */
export function buildToRemoteAnchorScript(
	remotePubkey: Buffer,
	leaseExpiry?: number
): Buffer {
	const leaseClause: (number | Buffer)[] = [];
	if (leaseExpiry !== undefined && leaseExpiry > 0) {
		leaseClause.push(
			bitcoin.script.number.encode(leaseExpiry),
			bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
			bitcoin.opcodes.OP_DROP
		);
	}
	return bitcoin.script.compile([
		remotePubkey,
		bitcoin.opcodes.OP_CHECKSIGVERIFY,
		...leaseClause,
		bitcoin.script.number.encode(1),
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY
	]);
}

/**
 * If the witness script is a lease-locked confirmed to_remote
 * (LeaseCommitScriptToRemoteConfirmed layout above), return its lease-expiry
 * height; undefined for the plain variant or any other script. Spend paths
 * derive the required nLockTime from the on-chain script itself so sweeps
 * work even from restored state that lost the lease fields.
 */
export function leaseExpiryFromToRemoteScript(
	witnessScript: Buffer
): number | undefined {
	const chunks = bitcoin.script.decompile(witnessScript);
	if (!chunks || chunks.length !== 7) return undefined;
	const [pubkey, checksigverify, expiry, cltv, drop, one, csv] = chunks;
	if (
		!Buffer.isBuffer(pubkey) ||
		pubkey.length !== 33 ||
		checksigverify !== bitcoin.opcodes.OP_CHECKSIGVERIFY ||
		!Buffer.isBuffer(expiry) ||
		cltv !== bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY ||
		drop !== bitcoin.opcodes.OP_DROP ||
		one !== bitcoin.opcodes.OP_1 ||
		csv !== bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY
	) {
		return undefined;
	}
	try {
		return bitcoin.script.number.decode(expiry);
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
 * `leaseExpiry` for the lease-locked (lessor) variant.
 */
export function buildToRemoteAnchorOutput(
	remotePubkey: Buffer,
	leaseExpiry?: number
): {
	script: Buffer;
	witnessScript: Buffer;
} {
	const witnessScript = buildToRemoteAnchorScript(remotePubkey, leaseExpiry);
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript } });
	return {
		script: p2wsh.output!,
		witnessScript
	};
}
