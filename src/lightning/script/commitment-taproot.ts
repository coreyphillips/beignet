/**
 * Simple taproot channels (option_taproot): commitment output scripts.
 *
 * The to_local and to_remote commitment outputs become P2TR. Key-path spends are
 * disabled by using the BIP341 NUMS point as the internal key, so funds move only
 * through the tapscript leaves:
 *   - to_local: a 2-leaf tree — a CSV-delayed self-spend leaf and a revocation
 *     leaf (mirrors the legacy OP_IF revocation / ELSE delay branches).
 *   - to_remote: a single 1-block-CSV leaf (anchor-style).
 *
 * BIP341 tweak / merkle / control-block construction is delegated to bitcoinjs
 * (initEccLib), which is well-tested; this module only defines the leaf scripts
 * and assembles the outputs. NOTE: exact-byte parity with LND's option_taproot is
 * pinned at interop (Phase 7); the leaf opcode order is documented here so any
 * divergence can be diffed and corrected against a live LND channel.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';

bitcoin.initEccLib(ecc);

const { opcodes, script } = bitcoin;

function ripemd160(data: Buffer): Buffer {
	return crypto.createHash('ripemd160').update(data).digest();
}

// Mirrors bitcoinjs-lib's (non-top-level-exported) Taptree type for p2tr.
type Tapleaf = { output: Buffer; version?: number };
type Taptree = [Taptree | Tapleaf, Taptree | Tapleaf] | Tapleaf;

/**
 * NUMS point (x-only) used as the taproot internal key for the to_local/to_remote
 * commitment outputs so key-path spends are impossible.
 *
 * MUST match LND's `TaprootNUMSKey` (compressed
 * 02dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279, the
 * "Lightning Simple Taproot" generator) — NOT the generic BIP341 H point.
 * Using H instead produces different to_local/to_remote output keys and breaks
 * commitment byte-parity with LND (verified live vs lnd v0.20).
 */
export const TAPROOT_NUMS_KEY = Buffer.from(
	'dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279',
	'hex'
);

/** Tapscript leaf version for the commitment leaves (BIP342 default 0xc0). */
export const TAPLEAF_VERSION = 0xc0;

/** Convert a 33-byte compressed key to the 32-byte x-only form for tapscript. */
export function toXOnly(pubkey: Buffer): Buffer {
	if (pubkey.length === 32) return pubkey;
	if (pubkey.length !== 33) {
		throw new Error(`Expected 33-byte compressed or 32-byte x-only key`);
	}
	return pubkey.subarray(1);
}

function taggedHash(tag: string, data: Buffer): Buffer {
	const t = crypto.createHash('sha256').update(Buffer.from(tag)).digest();
	return crypto
		.createHash('sha256')
		.update(Buffer.concat([t, t, data]))
		.digest();
}

/**
 * BIP341 key-path tweak of a private key for a P2TR output with the given merkle
 * root: tweakedPriv = (negate-if-odd d) + H_TapTweak(xonly(P) || merkleRoot).
 * Used for the taproot HTLC-output revocation KEY-PATH breach sweep (the HTLC
 * output's internal key is the revocation key). Returns the 32-byte tweaked key.
 */
export function tweakTaprootKeyPathPrivkey(
	internalPrivkey: Buffer,
	merkleRoot: Buffer
): Buffer {
	const internalPub = Buffer.from(ecc.pointFromScalar(internalPrivkey, true)!);
	const tweak = taggedHash(
		'TapTweak',
		Buffer.concat([toXOnly(internalPub), merkleRoot])
	);
	const dPrime =
		internalPub[0] === 0x02
			? internalPrivkey
			: Buffer.from(ecc.privateNegate(internalPrivkey));
	return Buffer.from(ecc.privateAdd(dPrime, tweak)!);
}

/**
 * to_local CSV-delayed self-spend leaf:
 *   <local_delayed_key> OP_CHECKSIG <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
 */
export function buildTaprootToLocalDelayScript(
	localDelayedPubkey: Buffer,
	toSelfDelay: number
): Buffer {
	return script.compile([
		toXOnly(localDelayedPubkey),
		opcodes.OP_CHECKSIG,
		script.number.encode(toSelfDelay),
		opcodes.OP_CHECKSEQUENCEVERIFY,
		opcodes.OP_DROP
	]);
}

/**
 * to_local revocation leaf:
 *   <local_delayed_key> OP_DROP <revocation_key> OP_CHECKSIG
 *
 * LND (TaprootLocalCommitRevokeScript) prepends `<self_key> OP_DROP` so the
 * revoke leaf references the delayed key too — this is part of the leaf bytes
 * and changes the to_local taproot output key, so it MUST match for commitment
 * byte-parity (verified live vs lnd v0.20). The spend witness is unchanged: just
 * the revocation signature (the delayed key is pushed+dropped by the script).
 */
export function buildTaprootToLocalRevokeScript(
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer
): Buffer {
	return script.compile([
		toXOnly(localDelayedPubkey),
		opcodes.OP_DROP,
		toXOnly(revocationPubkey),
		opcodes.OP_CHECKSIG
	]);
}

/**
 * to_remote leaf (anchor-style 1-block CSV):
 *   <remote_key> OP_CHECKSIG OP_1 OP_CHECKSEQUENCEVERIFY OP_DROP
 */
export function buildTaprootToRemoteScript(remotePubkey: Buffer): Buffer {
	return script.compile([
		toXOnly(remotePubkey),
		opcodes.OP_CHECKSIG,
		script.number.encode(1),
		opcodes.OP_CHECKSEQUENCEVERIFY,
		opcodes.OP_DROP
	]);
}

/** A tapscript leaf plus the control block needed to spend it. */
export interface ITaprootLeafSpend {
	script: Buffer;
	controlBlock: Buffer;
	leafVersion: number;
}

/** A taproot commitment output and its spend paths. */
export interface ITaprootCommitOutput {
	/** scriptPubKey: OP_1 <32-byte output key>. */
	output: Buffer;
	/** 32-byte x-only taproot output key. */
	outputKey: Buffer;
	/** bech32m address. */
	address: string;
}

function p2trControlBlock(
	internalPubkey: Buffer,
	scriptTree: Taptree,
	leaf: Buffer,
	network: bitcoin.Network
): Buffer {
	const p = bitcoin.payments.p2tr({
		internalPubkey,
		scriptTree,
		redeem: { output: leaf, redeemVersion: TAPLEAF_VERSION },
		network
	});
	const witness = p.witness!;
	// p2tr witness for a script-path: [...redeemWitness, leafScript, controlBlock].
	return witness[witness.length - 1];
}

/**
 * Build the taproot to_local output (NUMS internal key; delay + revoke leaves)
 * along with the control blocks for each spend path.
 */
export function buildTaprootToLocalOutput(
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ITaprootCommitOutput & {
	delay: ITaprootLeafSpend;
	revoke: ITaprootLeafSpend;
} {
	const delayScript = buildTaprootToLocalDelayScript(
		localDelayedPubkey,
		toSelfDelay
	);
	const revokeScript = buildTaprootToLocalRevokeScript(
		revocationPubkey,
		localDelayedPubkey
	);
	// Leaf order: [delay, revoke]. (Document for LND byte-diff at interop.)
	const scriptTree: Taptree = [
		{ output: delayScript },
		{ output: revokeScript }
	];
	const base = bitcoin.payments.p2tr({
		internalPubkey: TAPROOT_NUMS_KEY,
		scriptTree,
		network
	});
	return {
		output: base.output!,
		outputKey: base.pubkey!,
		address: base.address!,
		delay: {
			script: delayScript,
			controlBlock: p2trControlBlock(
				TAPROOT_NUMS_KEY,
				scriptTree,
				delayScript,
				network
			),
			leafVersion: TAPLEAF_VERSION
		},
		revoke: {
			script: revokeScript,
			controlBlock: p2trControlBlock(
				TAPROOT_NUMS_KEY,
				scriptTree,
				revokeScript,
				network
			),
			leafVersion: TAPLEAF_VERSION
		}
	};
}

/**
 * Build the taproot HTLC SECOND-LEVEL output (the output of an HTLC-success or
 * HTLC-timeout transaction). UNLIKE the to_local commitment output, LND's
 * TaprootSecondLevelScriptTree uses the REVOCATION key as the taproot internal
 * key (so a breach is a key-path sweep that reveals the revocation key) and a
 * SINGLE delay leaf `<delayed> CHECKSIG <csv> CSV DROP` (no revoke leaf). This
 * must match for the second-level HTLC signatures to verify against LND.
 */
export function buildTaprootSecondLevelOutput(
	revocationPubkey: Buffer,
	localDelayedPubkey: Buffer,
	toSelfDelay: number,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ITaprootCommitOutput & { delay: ITaprootLeafSpend } {
	const delayScript = buildTaprootToLocalDelayScript(
		localDelayedPubkey,
		toSelfDelay
	);
	const internalPubkey = toXOnly(revocationPubkey);
	const scriptTree: Taptree = { output: delayScript };
	const base = bitcoin.payments.p2tr({ internalPubkey, scriptTree, network });
	return {
		output: base.output!,
		outputKey: base.pubkey!,
		address: base.address!,
		delay: {
			script: delayScript,
			controlBlock: p2trControlBlock(
				internalPubkey,
				scriptTree,
				delayScript,
				network
			),
			leafVersion: TAPLEAF_VERSION
		}
	};
}

/**
 * Build the taproot to_remote output (NUMS internal key; single 1-CSV leaf) and
 * the control block to spend it.
 */
export function buildTaprootToRemoteOutput(
	remotePubkey: Buffer,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ITaprootCommitOutput & { spend: ITaprootLeafSpend } {
	const leaf = buildTaprootToRemoteScript(remotePubkey);
	const scriptTree: Taptree = { output: leaf };
	const base = bitcoin.payments.p2tr({
		internalPubkey: TAPROOT_NUMS_KEY,
		scriptTree,
		network
	});
	return {
		output: base.output!,
		outputKey: base.pubkey!,
		address: base.address!,
		spend: {
			script: leaf,
			controlBlock: p2trControlBlock(
				TAPROOT_NUMS_KEY,
				scriptTree,
				leaf,
				network
			),
			leafVersion: TAPLEAF_VERSION
		}
	};
}

// ── HTLC outputs ────────────────────────────────────────────────────────────
// Taproot HTLC outputs use the REVOCATION key as the taproot internal key, so a
// breach is swept via a key-path spend; the success (preimage) and timeout paths
// are tapscript leaves. (Opcode order documented; LND byte-parity pinned at P7.)

// LND key naming for taproot HTLC leaves (script_utils.go): senderHtlcKey =
// the HTLC offerer's key, receiverHtlcKey = the recipient's key. On an OFFERED
// HTLC the commitment owner is the sender (local) and the peer is the receiver
// (remote); on a RECEIVED HTLC it is reversed (sender = remote, receiver = local).
// We keep beignet's local/remote naming and map accordingly per leaf.

/**
 * Offered-HTLC success leaf — the receiver (remote) claims with the preimage,
 * after a 1-block CSV (LND SenderHTLCTapLeafSuccess):
 *   OP_SIZE 32 EQUALVERIFY OP_HASH160 <rmd160(ph)> EQUALVERIFY
 *   <receiver=remote> OP_CHECKSIG OP_1 OP_CSV OP_DROP
 */
export function buildTaprootOfferedHtlcSuccessLeaf(
	remoteHtlcPubkey: Buffer,
	paymentHash: Buffer
): Buffer {
	return script.compile([
		opcodes.OP_SIZE,
		script.number.encode(32),
		opcodes.OP_EQUALVERIFY,
		opcodes.OP_HASH160,
		ripemd160(paymentHash),
		opcodes.OP_EQUALVERIFY,
		toXOnly(remoteHtlcPubkey),
		opcodes.OP_CHECKSIG,
		opcodes.OP_1,
		opcodes.OP_CHECKSEQUENCEVERIFY,
		opcodes.OP_DROP
	]);
}

/**
 * Offered-HTLC timeout leaf — 2-of-2 (sender then receiver) for the HTLC-timeout
 * tx (LND SenderHTLCTapLeafTimeout):
 *   <sender=local> OP_CHECKSIGVERIFY <receiver=remote> OP_CHECKSIG
 */
export function buildTaprootOfferedHtlcTimeoutLeaf(
	localHtlcPubkey: Buffer,
	remoteHtlcPubkey: Buffer
): Buffer {
	return script.compile([
		toXOnly(localHtlcPubkey),
		opcodes.OP_CHECKSIGVERIFY,
		toXOnly(remoteHtlcPubkey),
		opcodes.OP_CHECKSIG
	]);
}

/**
 * Received-HTLC success leaf — 2-of-2 (receiver then sender) + preimage for the
 * HTLC-success tx (LND ReceiverHtlcTapLeafSuccess):
 *   OP_SIZE 32 EQUALVERIFY OP_HASH160 <rmd160(ph)> EQUALVERIFY
 *   <receiver=local> OP_CHECKSIGVERIFY <sender=remote> OP_CHECKSIG
 */
export function buildTaprootReceivedHtlcSuccessLeaf(
	localHtlcPubkey: Buffer,
	remoteHtlcPubkey: Buffer,
	paymentHash: Buffer
): Buffer {
	return script.compile([
		opcodes.OP_SIZE,
		script.number.encode(32),
		opcodes.OP_EQUALVERIFY,
		opcodes.OP_HASH160,
		ripemd160(paymentHash),
		opcodes.OP_EQUALVERIFY,
		toXOnly(localHtlcPubkey),
		opcodes.OP_CHECKSIGVERIFY,
		toXOnly(remoteHtlcPubkey),
		opcodes.OP_CHECKSIG
	]);
}

/**
 * Received-HTLC timeout leaf — the sender (remote) reclaims after a 1-block CSV
 * AND the CLTV expiry (LND ReceiverHtlcTapLeafTimeout):
 *   <sender=remote> OP_CHECKSIG OP_1 OP_CSV OP_DROP <cltv> OP_CLTV OP_DROP
 */
export function buildTaprootReceivedHtlcTimeoutLeaf(
	remoteHtlcPubkey: Buffer,
	cltvExpiry: number
): Buffer {
	return script.compile([
		toXOnly(remoteHtlcPubkey),
		opcodes.OP_CHECKSIG,
		opcodes.OP_1,
		opcodes.OP_CHECKSEQUENCEVERIFY,
		opcodes.OP_DROP,
		script.number.encode(cltvExpiry),
		opcodes.OP_CHECKLOCKTIMEVERIFY,
		opcodes.OP_DROP
	]);
}

/** A taproot HTLC output: revocation key-path internal key + success/timeout leaves. */
export interface ITaprootHtlcOutput extends ITaprootCommitOutput {
	/** 32-byte x-only revocation key = the taproot internal key (key-path = breach). */
	internalKey: Buffer;
	/** Tapscript merkle root (for deriving the key-path tweak). */
	merkleRoot: Buffer;
	success: ITaprootLeafSpend;
	timeout: ITaprootLeafSpend;
}

function assembleHtlcOutput(
	revocationPubkey: Buffer,
	successScript: Buffer,
	timeoutScript: Buffer,
	network: bitcoin.Network
): ITaprootHtlcOutput {
	const internalPubkey = toXOnly(revocationPubkey);
	const scriptTree: Taptree = [
		{ output: successScript },
		{ output: timeoutScript }
	];
	const base = bitcoin.payments.p2tr({ internalPubkey, scriptTree, network });
	return {
		output: base.output!,
		outputKey: base.pubkey!,
		address: base.address!,
		internalKey: internalPubkey,
		merkleRoot: base.hash!,
		success: {
			script: successScript,
			controlBlock: p2trControlBlock(
				internalPubkey,
				scriptTree,
				successScript,
				network
			),
			leafVersion: TAPLEAF_VERSION
		},
		timeout: {
			script: timeoutScript,
			controlBlock: p2trControlBlock(
				internalPubkey,
				scriptTree,
				timeoutScript,
				network
			),
			leafVersion: TAPLEAF_VERSION
		}
	};
}

/** Build the taproot OFFERED-HTLC output (we sent the payment). */
export function buildTaprootOfferedHtlcOutput(
	revocationPubkey: Buffer,
	localHtlcPubkey: Buffer,
	remoteHtlcPubkey: Buffer,
	paymentHash: Buffer,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ITaprootHtlcOutput {
	return assembleHtlcOutput(
		revocationPubkey,
		buildTaprootOfferedHtlcSuccessLeaf(remoteHtlcPubkey, paymentHash),
		buildTaprootOfferedHtlcTimeoutLeaf(localHtlcPubkey, remoteHtlcPubkey),
		network
	);
}

// ── Anchor output ───────────────────────────────────────────────────────────

/**
 * Taproot anchor leaf — anyone may sweep the 330-sat anchor after 16 blocks:
 *   OP_16 OP_CHECKSEQUENCEVERIFY
 */
export function buildTaprootAnchorLeaf(): Buffer {
	return script.compile([opcodes.OP_16, opcodes.OP_CHECKSEQUENCEVERIFY]);
}

/**
 * Build a taproot anchor output. The owning party's funding key is the taproot
 * internal key (immediate key-path sweep); the single 16-CSV leaf lets anyone
 * sweep after 16 blocks (so the anchor can't pin the UTXO set forever).
 */
export function buildTaprootAnchorOutput(
	fundingPubkey: Buffer,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ITaprootCommitOutput & {
	internalKey: Buffer;
	merkleRoot: Buffer;
	anyone: ITaprootLeafSpend;
} {
	const internalPubkey = toXOnly(fundingPubkey);
	const leaf = buildTaprootAnchorLeaf();
	const scriptTree: Taptree = { output: leaf };
	const base = bitcoin.payments.p2tr({ internalPubkey, scriptTree, network });
	return {
		output: base.output!,
		outputKey: base.pubkey!,
		address: base.address!,
		internalKey: internalPubkey,
		merkleRoot: base.hash!,
		anyone: {
			script: leaf,
			controlBlock: p2trControlBlock(internalPubkey, scriptTree, leaf, network),
			leafVersion: TAPLEAF_VERSION
		}
	};
}

/** Build the taproot RECEIVED-HTLC output (we received the payment). */
export function buildTaprootReceivedHtlcOutput(
	revocationPubkey: Buffer,
	localHtlcPubkey: Buffer,
	remoteHtlcPubkey: Buffer,
	paymentHash: Buffer,
	cltvExpiry: number,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): ITaprootHtlcOutput {
	return assembleHtlcOutput(
		revocationPubkey,
		buildTaprootReceivedHtlcSuccessLeaf(
			localHtlcPubkey,
			remoteHtlcPubkey,
			paymentHash
		),
		buildTaprootReceivedHtlcTimeoutLeaf(remoteHtlcPubkey, cltvExpiry),
		network
	);
}
