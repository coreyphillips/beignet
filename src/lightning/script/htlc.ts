/**
 * BOLT 3: HTLC scripts and second-level transactions.
 *
 * Defines the offered/received HTLC witness scripts and the
 * HTLC-success/HTLC-timeout second-level transactions.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';

bitcoin.initEccLib(ecc);

function ripemd160(data: Buffer): Buffer {
	return crypto.createHash('ripemd160').update(data).digest();
}

/**
 * Build the offered HTLC script (we offered, remote can claim with preimage).
 *
 * # To remote node with revocation key
 * OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
 * OP_IF
 *     OP_CHECKSIG
 * OP_ELSE
 *     <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
 *     OP_NOTIF
 *         # To local node via HTLC-timeout transaction (timelocked).
 *         OP_DROP 2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
 *     OP_ELSE
 *         # To remote node with preimage.
 *         OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *         OP_CHECKSIG
 *     OP_ENDIF
 * OP_ENDIF
 */
export function buildOfferedHtlcScript(
	revocationPubkey: Buffer,
	localHtlcPubkey: Buffer,
	remoteHtlcPubkey: Buffer,
	paymentHash: Buffer,
	useAnchors?: boolean
): Buffer {
	if (paymentHash.length !== 32) {
		throw new Error(`Payment hash must be 32 bytes, got ${paymentHash.length}`);
	}

	const revocationHash = ripemd160(
		crypto.createHash('sha256').update(revocationPubkey).digest()
	);
	const ripemdPaymentHash = ripemd160(paymentHash);

	return bitcoin.script.compile([
		bitcoin.opcodes.OP_DUP,
		bitcoin.opcodes.OP_HASH160,
		revocationHash,
		bitcoin.opcodes.OP_EQUAL,
		bitcoin.opcodes.OP_IF,
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_ELSE,
		remoteHtlcPubkey,
		bitcoin.opcodes.OP_SWAP,
		bitcoin.opcodes.OP_SIZE,
		bitcoin.script.number.encode(32),
		bitcoin.opcodes.OP_EQUAL,
		bitcoin.opcodes.OP_NOTIF,
		bitcoin.opcodes.OP_DROP,
		bitcoin.opcodes.OP_2,
		bitcoin.opcodes.OP_SWAP,
		localHtlcPubkey,
		bitcoin.opcodes.OP_2,
		bitcoin.opcodes.OP_CHECKMULTISIG,
		bitcoin.opcodes.OP_ELSE,
		bitcoin.opcodes.OP_HASH160,
		ripemdPaymentHash,
		bitcoin.opcodes.OP_EQUALVERIFY,
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_ENDIF,
		// BOLT 3: anchor channels add 1 CSV to all HTLC outputs
		...(useAnchors
			? [
					bitcoin.script.number.encode(1),
					bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
					bitcoin.opcodes.OP_DROP
			  ]
			: []),
		bitcoin.opcodes.OP_ENDIF
	]);
}

/**
 * Build the received HTLC script (we received, we can claim with preimage).
 *
 * # To remote node with revocation key
 * OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
 * OP_IF
 *     OP_CHECKSIG
 * OP_ELSE
 *     <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
 *     OP_IF
 *         # To local node via HTLC-success transaction.
 *         OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *         2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
 *     OP_ELSE
 *         # To remote node after timeout.
 *         OP_DROP <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *         OP_CHECKSIG
 *     OP_ENDIF
 * OP_ENDIF
 */
export function buildReceivedHtlcScript(
	revocationPubkey: Buffer,
	localHtlcPubkey: Buffer,
	remoteHtlcPubkey: Buffer,
	paymentHash: Buffer,
	cltvExpiry: number,
	useAnchors?: boolean
): Buffer {
	if (paymentHash.length !== 32) {
		throw new Error(`Payment hash must be 32 bytes, got ${paymentHash.length}`);
	}

	const revocationHash = ripemd160(
		crypto.createHash('sha256').update(revocationPubkey).digest()
	);
	const ripemdPaymentHash = ripemd160(paymentHash);

	return bitcoin.script.compile([
		bitcoin.opcodes.OP_DUP,
		bitcoin.opcodes.OP_HASH160,
		revocationHash,
		bitcoin.opcodes.OP_EQUAL,
		bitcoin.opcodes.OP_IF,
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_ELSE,
		remoteHtlcPubkey,
		bitcoin.opcodes.OP_SWAP,
		bitcoin.opcodes.OP_SIZE,
		bitcoin.script.number.encode(32),
		bitcoin.opcodes.OP_EQUAL,
		bitcoin.opcodes.OP_IF,
		bitcoin.opcodes.OP_HASH160,
		ripemdPaymentHash,
		bitcoin.opcodes.OP_EQUALVERIFY,
		bitcoin.opcodes.OP_2,
		bitcoin.opcodes.OP_SWAP,
		localHtlcPubkey,
		bitcoin.opcodes.OP_2,
		bitcoin.opcodes.OP_CHECKMULTISIG,
		bitcoin.opcodes.OP_ELSE,
		bitcoin.opcodes.OP_DROP,
		bitcoin.script.number.encode(cltvExpiry),
		bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
		bitcoin.opcodes.OP_DROP,
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_ENDIF,
		// BOLT 3: anchor channels add 1 CSV to all HTLC outputs
		...(useAnchors
			? [
					bitcoin.script.number.encode(1),
					bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
					bitcoin.opcodes.OP_DROP
			  ]
			: []),
		bitcoin.opcodes.OP_ENDIF
	]);
}

/**
 * Build the output script for second-level HTLC transactions.
 * This is the same format as to_local:
 *
 * OP_IF
 *   <revocationpubkey>
 * OP_ELSE
 *   <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
 *   <local_delayedpubkey>
 * OP_ENDIF
 * OP_CHECKSIG
 */
export function buildHtlcOutputScript(
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number
): Buffer {
	// BOLT 3 / CLN: second-level HTLC outputs are NEVER lease-locked (CLN's
	// htlc_tx has no lease param). Only to_local/to_remote carry the bLIP-0051
	// lease CSV; the HTLC delayed output is a plain to_self_delay CSV.
	return bitcoin.script.compile([
		bitcoin.opcodes.OP_IF,
		revocationPubkey,
		bitcoin.opcodes.OP_ELSE,
		bitcoin.script.number.encode(toSelfDelay),
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
		bitcoin.opcodes.OP_DROP,
		localDelayedPubkey,
		bitcoin.opcodes.OP_ENDIF,
		bitcoin.opcodes.OP_CHECKSIG
	]);
}

/**
 * Build an HTLC-success transaction (spends a received HTLC with preimage).
 *
 * - version: 2
 * - locktime: 0
 * - input sequence: 1 for anchor channels (1-block CSV per BOLT 3), 0 otherwise
 * - output: to_local-style script with revocation + CSV delay
 *
 * @param htlcTxid - Transaction ID containing the HTLC output
 * @param htlcOutputIndex - Index of the HTLC output
 * @param htlcAmount - Amount of the HTLC output in satoshis
 * @param revocationPubkey - Revocation public key for the output script
 * @param localDelayedPubkey - Local delayed payment key for the output script
 * @param toSelfDelay - CSV delay in blocks
 * @param feeSatoshis - Fee to deduct from the output amount
 */
export function buildHtlcSuccessTx(
	htlcTxid: string,
	htlcOutputIndex: number,
	htlcAmount: bigint,
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number,
	feeSatoshis: bigint,
	zeroFee?: boolean
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;

	const txidBuf = Buffer.from(htlcTxid, 'hex').reverse();
	// BOLT 3: nSequence = 1 for anchors (1-block CSV), 0 for non-anchor
	const inputSequence = zeroFee ? 1 : 0;
	tx.addInput(txidBuf, htlcOutputIndex, inputSequence);

	const outputScript = buildHtlcOutputScript(
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay
	);
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: outputScript } });

	// With anchors (zeroFee): output = full HTLC amount (no fee deducted)
	const outputAmount = zeroFee ? htlcAmount : htlcAmount - feeSatoshis;
	tx.addOutput(p2wsh.output!, Number(outputAmount));

	return tx;
}

/**
 * Build an HTLC-timeout transaction (spends an offered HTLC after CLTV timeout).
 *
 * - version: 2
 * - locktime: cltv_expiry
 * - input sequence: 1 for anchor channels (1-block CSV per BOLT 3), 0 otherwise
 * - output: to_local-style script with revocation + CSV delay
 */
export function buildHtlcTimeoutTx(
	htlcTxid: string,
	htlcOutputIndex: number,
	htlcAmount: bigint,
	cltvExpiry: number,
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number,
	feeSatoshis: bigint,
	zeroFee?: boolean
): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = cltvExpiry;

	const txidBuf = Buffer.from(htlcTxid, 'hex').reverse();
	// BOLT 3: nSequence = 1 for anchors (1-block CSV), 0 for non-anchor
	const inputSequence = zeroFee ? 1 : 0;
	tx.addInput(txidBuf, htlcOutputIndex, inputSequence);

	const outputScript = buildHtlcOutputScript(
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay
	);
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: outputScript } });

	// With anchors (zeroFee): output = full HTLC amount (no fee deducted)
	const outputAmount = zeroFee ? htlcAmount : htlcAmount - feeSatoshis;
	tx.addOutput(p2wsh.output!, Number(outputAmount));

	return tx;
}
