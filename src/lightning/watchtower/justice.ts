/**
 * Build an encrypted justice kit + breach hint from a revoked remote commitment.
 *
 * The client pre-signs the penalty input(s) so a tower that only ever sees the
 * blob can reassemble and broadcast the penalty transaction. Because the
 * signatures commit to the exact justice-transaction output values (SIGHASH_ALL
 * for v0, SIGHASH_DEFAULT taproot digests for v1), the client MUST build the
 * same transaction the tower will: BIP69-sorted inputs and a single sweep
 * output of totalAmt - fee, where the fee comes from the session's
 * sweep_fee_rate applied to lnd's fixed witness/weight estimates. Those
 * estimates are mirrored here (input/size.go, blob/commitments.go) so the
 * signatures validate on an LND altruist tower.
 *
 * Coverage per channel type (matching lnd blob.CommitmentType):
 *   - legacy: v0 kit; to_local P2WSH penalty + optional p2wpkh to_remote.
 *   - anchor: v0 kit; to_local P2WSH penalty + optional 1-CSV P2WSH to_remote
 *     (CommitScriptToRemoteConfirmed, input sequence 1).
 *   - taproot: v1 kit; to_local revoke-leaf script-path penalty + optional
 *     to_remote settle-leaf script-path sweep (sequence 1), schnorr signatures.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { sign } from '../crypto/ecdh';
import {
	deriveRevocationPubkey,
	derivePublicKey,
	deriveRevocationPrivkey,
	perCommitmentPointFromSecret
} from '../keys/derivation';
import { buildToLocalScript } from '../script/commitment';
import { buildToRemoteAnchorScript } from '../script/anchor';
import { isDustOutput } from '../chain/closing';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	toXOnly
} from '../script/commitment-taproot';
import { tapleafHash } from '../script/htlc-taproot';
import {
	BlobType,
	IJusticeKitV0,
	IJusticeKitV1,
	breachHintFromTxid,
	breachKeyFromTxid,
	encryptJusticeKitV0,
	encryptJusticeKitV1
} from './blob';

bitcoin.initEccLib(ecc);

// lnd input/size.go weight constants (weight units).
const WITNESS_SCALE_FACTOR = 4;
const BASE_TX_SIZE = 8;
const INPUT_SIZE = 41;
const P2WKH_OUTPUT_SIZE = 31;
const P2WSH_OUTPUT_SIZE = 43;
// ToLocalPenaltyWitnessSize = 1+1+73+1+1+1+ToLocalScriptSize(79) = 157.
const TO_LOCAL_PENALTY_WITNESS_SIZE = 157;
// Legacy commitments underestimate by one byte; lnd preserves the bug so its
// historical signatures stay valid (blob/commitments.go ToLocalWitnessSize).
const TO_LOCAL_PENALTY_WITNESS_SIZE_LEGACY = TO_LOCAL_PENALTY_WITNESS_SIZE - 1;
const P2WKH_WITNESS_SIZE = 109;
// ToRemoteConfirmedWitnessSize = 1+1+73+1+ToRemoteConfirmedScriptSize(37) = 113.
const TO_REMOTE_CONFIRMED_WITNESS_SIZE = 113;
// TaprootToLocalRevokeWitnessSize = 1+1+65+1+68+1+33+32 = 202.
const TAPROOT_TO_LOCAL_REVOKE_WITNESS_SIZE = 202;
// TaprootToRemoteWitnessSize = 1+1+65+1+37+1+33 = 139.
const TAPROOT_TO_REMOTE_WITNESS_SIZE = 139;

/** Everything needed to build a justice kit for one revoked commitment. */
export interface IJusticeContext {
	channelId: string;
	/** The revoked remote commitment transaction (deserialized). */
	revokedTx: bitcoin.Transaction;
	/** Revealed per-commitment secret for the revoked state. */
	perCommitmentSecret: Buffer;
	/** Our revocation basepoint (public). */
	revocationBasepoint: Buffer;
	/** Our revocation basepoint secret (signs the to_local penalty). */
	revocationBasepointSecret: Buffer;
	/** Remote party's delayed-payment basepoint (public). */
	remoteDelayedBasepoint: Buffer;
	/** to_self_delay enforced on the remote to_local output. */
	toSelfDelay: number;
	/** True for anchor channels (affects blob type + witness weight). */
	isAnchor: boolean;
	/**
	 * True for simple taproot channels: use the version-1 (schnorr) justice kit.
	 * Takes precedence over isAnchor (taproot channel_types imply anchor-style
	 * commitments elsewhere in beignet).
	 */
	isTaproot?: boolean;
	/** Our static to_remote payment pubkey on the remote commitment. */
	localPaymentPubkey?: Buffer;
	/** Secret for localPaymentPubkey (signs the to_remote sweep). */
	paymentBasepointSecret?: Buffer;
	/** Witness program we sweep breached funds into (<= 42 bytes). */
	sweepScript: Buffer;
	network: bitcoin.Network;
	/**
	 * Liquidity ads: set when the channel carries a script-enforced lease.
	 * The blob v0 format has no lease field — LND towers rebuild the PLAIN
	 * scripts with locktime 0 — so lease-locked outputs cannot ride in the
	 * kit (see buildJusticeBackupV0).
	 */
	isLessor?: boolean;
	leaseExpiry?: number;
}

/** Negotiated per-session parameters that shape the justice transaction. */
export interface ISessionPolicy {
	blobType: number;
	/** Sweep fee rate in sat/kw. */
	sweepFeeRate: bigint;
}

export interface IJusticeBackup {
	hint: Buffer;
	encryptedBlob: Buffer;
	/** Internal-byte-order txid of the revoked commitment. */
	revokedTxid: Buffer;
	sweptSats: bigint;
}

interface IPenaltyInput {
	index: number;
	value: number;
	/** v0: witnessScript for the BIP143 digest. v1: the tapleaf script. */
	witnessScript: Buffer;
	/** Witness weight the tower's estimator will assume for this input. */
	witnessWeight: number;
	/** nSequence the tower will set on this input (anchor/taproot to_remote: 1). */
	sequence: number;
	privkey: Buffer;
}

/**
 * Build the encrypted justice kit for a revoked commitment under one session's
 * policy. Throws if the to_local penalty output cannot be located or signed
 * (fund safety: never emit a blob that cannot punish the breach).
 */
export function buildJusticeBackup(
	ctx: IJusticeContext,
	policy: ISessionPolicy
): IJusticeBackup {
	// BOLT: the user-supplied sweep script MUST be a standard witness program
	// (P2WPKH=22 / P2WSH=34 here); an off-spec length makes LND's tower error
	// at breach time, silently voiding protection. Checked up front, before any
	// key derivation, so a misconfiguration fails loudly at session setup.
	if (ctx.sweepScript.length !== 22 && ctx.sweepScript.length !== 34) {
		throw new Error(
			`watchtower: sweep script must be 22 or 34 bytes, got ${ctx.sweepScript.length}`
		);
	}
	return ctx.isTaproot
		? buildJusticeBackupV1(ctx, policy)
		: buildJusticeBackupV0(ctx, policy);
}

/** Version-0 kit: legacy + anchor channels (ECDSA / SIGHASH_ALL). */
function buildJusticeBackupV0(
	ctx: IJusticeContext,
	policy: ISessionPolicy
): IJusticeBackup {
	const keys = deriveJusticeKeys(ctx);
	const toLocalScript = buildToLocalScript(
		keys.revocationPubkey,
		keys.theirDelayedPubkey,
		ctx.toSelfDelay
	);
	const toLocalSpk = bitcoin.payments.p2wsh({
		redeem: { output: toLocalScript },
		network: ctx.network
	}).output!;

	const toLocalIndex = findOutput(ctx.revokedTx, toLocalSpk);
	if (toLocalIndex < 0) {
		// Lessee side of a leased channel: the peer (lessor) commitment's
		// to_local carries a lease CLTV the blob v0 format cannot express (only
		// csvDelay travels; an LND tower rebuilds the plain script). Name the
		// limitation instead of a generic mismatch.
		if (ctx.leaseExpiry && !ctx.isLessor) {
			const leaseToLocalSpk = bitcoin.payments.p2wsh({
				redeem: {
					output: buildToLocalScript(
						keys.revocationPubkey,
						keys.theirDelayedPubkey,
						ctx.toSelfDelay,
						ctx.leaseExpiry
					)
				},
				network: ctx.network
			}).output!;
			if (findOutput(ctx.revokedTx, leaseToLocalSpk) >= 0) {
				throw new Error(
					`watchtower: blob v0 cannot express the lease-locked to_local of leased channel ${ctx.channelId} (LND towers rebuild the plain script); tower protection is unavailable for the lessee side of a leased channel`
				);
			}
		}
		throw new Error(
			`watchtower: to_local output not found on revoked commitment ${ctx.channelId}`
		);
	}

	const inputs: IPenaltyInput[] = [
		{
			index: toLocalIndex,
			value: ctx.revokedTx.outs[toLocalIndex].value,
			witnessScript: toLocalScript,
			witnessWeight: ctx.isAnchor
				? TO_LOCAL_PENALTY_WITNESS_SIZE
				: TO_LOCAL_PENALTY_WITNESS_SIZE_LEGACY,
			sequence: 0,
			privkey: keys.revocationPrivkey
		}
	];

	// to_remote: legacy is a plain p2wpkh; anchor is a 1-CSV P2WSH
	// (CommitScriptToRemoteConfirmed) spent with sequence 1. Include it so a
	// tower sweeps everything in one transaction; the to_local penalty still
	// stands alone when we don't hold a to_remote output.
	//
	// EXCEPTION — lessor's lease-locked to_remote: blob v0 has no lease field,
	// so an LND-format tower rebuilds the PLAIN confirmed script with
	// locktime 0 and could never locate/spend the CLTV-locked output. Because
	// the client pre-signs SIGHASH_ALL over the exact tx the tower assembles,
	// including it would make the tower build a DIFFERENT tx and invalidate
	// the to_local penalty signature too — bricking the entire kit. Skip it:
	// the to_local penalty (whose revocation branch has no CLTV) still
	// punishes the breach, and our own chain monitor sweeps the lease-locked
	// to_remote after expiry via the lease-aware output resolver.
	let toRemotePubkey: Buffer | undefined;
	let toRemoteIndex = -1;
	const leaseLockedToRemote = !!(
		ctx.isAnchor &&
		ctx.isLessor &&
		ctx.leaseExpiry
	);
	if (
		!leaseLockedToRemote &&
		ctx.localPaymentPubkey &&
		ctx.paymentBasepointSecret
	) {
		const toRemoteSpk = ctx.isAnchor
			? bitcoin.payments.p2wsh({
					redeem: {
						output: buildToRemoteAnchorScript(ctx.localPaymentPubkey)
					},
					network: ctx.network
			  }).output!
			: bitcoin.payments.p2wpkh({
					pubkey: ctx.localPaymentPubkey,
					network: ctx.network
			  }).output!;
		toRemoteIndex = findOutput(ctx.revokedTx, toRemoteSpk);
		if (toRemoteIndex >= 0) {
			toRemotePubkey = ctx.localPaymentPubkey;
			inputs.push({
				index: toRemoteIndex,
				value: ctx.revokedTx.outs[toRemoteIndex].value,
				witnessScript: ctx.isAnchor
					? buildToRemoteAnchorScript(ctx.localPaymentPubkey)
					: p2pkhScript(ctx.localPaymentPubkey),
				witnessWeight: ctx.isAnchor
					? TO_REMOTE_CONFIRMED_WITNESS_SIZE
					: P2WKH_WITNESS_SIZE,
				sequence: ctx.isAnchor ? 1 : 0,
				privkey: ctx.paymentBasepointSecret
			});
		}
	}

	const { justiceTx, orderedInputs } = buildJusticeTx(ctx, policy, inputs);

	// Sign each input over the assembled justice transaction (SIGHASH_ALL).
	const sigs = new Map<number, Buffer>();
	for (let i = 0; i < orderedInputs.length; i++) {
		const inp = orderedInputs[i];
		const sighash = justiceTx.hashForWitnessV0(
			i,
			inp.witnessScript,
			inp.value,
			bitcoin.Transaction.SIGHASH_ALL
		);
		const raw = sign(sighash, inp.privkey);
		if (raw.length !== 64) {
			throw new Error('watchtower: unexpected signature length');
		}
		sigs.set(inp.index, raw);
	}

	const toLocalSig = sigs.get(toLocalIndex);
	if (!toLocalSig) {
		throw new Error('watchtower: failed to sign to_local penalty input');
	}

	const kit: IJusticeKitV0 = {
		sweepAddress: ctx.sweepScript,
		revocationPubKey: keys.revocationPubkey,
		localDelayPubKey: keys.theirDelayedPubkey,
		csvDelay: ctx.toSelfDelay,
		commitToLocalSig: toLocalSig
	};
	if (toRemotePubkey) {
		kit.commitToRemotePubKey = toRemotePubkey;
		kit.commitToRemoteSig = sigs.get(toRemoteIndex);
	}

	return finishBackup(ctx, justiceTx, (key) => encryptJusticeKitV0(kit, key));
}

/** Version-1 kit: simple taproot channels (schnorr / SIGHASH_DEFAULT). */
function buildJusticeBackupV1(
	ctx: IJusticeContext,
	policy: ISessionPolicy
): IJusticeBackup {
	const keys = deriveJusticeKeys(ctx);
	const toLocal = buildTaprootToLocalOutput(
		keys.revocationPubkey,
		keys.theirDelayedPubkey,
		ctx.toSelfDelay,
		ctx.network
	);
	const toLocalIndex = findOutput(ctx.revokedTx, toLocal.output);
	if (toLocalIndex < 0) {
		throw new Error(
			`watchtower: to_local output not found on revoked commitment ${ctx.channelId}`
		);
	}

	const inputs: IPenaltyInput[] = [
		{
			index: toLocalIndex,
			value: ctx.revokedTx.outs[toLocalIndex].value,
			witnessScript: toLocal.revoke.script,
			witnessWeight: TAPROOT_TO_LOCAL_REVOKE_WITNESS_SIZE,
			sequence: 0,
			privkey: keys.revocationPrivkey
		}
	];

	// Taproot to_remote: NUMS-keyed P2TR with a single 1-CSV settle leaf, spent
	// script-path with sequence 1 (blob/commitments.go TaprootCommitment).
	let toRemotePubkey: Buffer | undefined;
	let toRemoteIndex = -1;
	if (ctx.localPaymentPubkey && ctx.paymentBasepointSecret) {
		const toRemote = buildTaprootToRemoteOutput(
			ctx.localPaymentPubkey,
			ctx.network
		);
		toRemoteIndex = findOutput(ctx.revokedTx, toRemote.output);
		if (toRemoteIndex >= 0) {
			toRemotePubkey = ctx.localPaymentPubkey;
			inputs.push({
				index: toRemoteIndex,
				value: ctx.revokedTx.outs[toRemoteIndex].value,
				witnessScript: toRemote.spend.script,
				witnessWeight: TAPROOT_TO_REMOTE_WITNESS_SIZE,
				sequence: 1,
				privkey: ctx.paymentBasepointSecret
			});
		}
	}

	const { justiceTx, orderedInputs } = buildJusticeTx(ctx, policy, inputs);

	// BIP341 script-path digests commit to every prevout's script + amount.
	const prevoutScripts = orderedInputs.map(
		(inp) => ctx.revokedTx.outs[inp.index].script
	);
	const prevoutValues = orderedInputs.map((inp) => inp.value);

	const sigs = new Map<number, Buffer>();
	for (let i = 0; i < orderedInputs.length; i++) {
		const inp = orderedInputs[i];
		const sighash = justiceTx.hashForWitnessV1(
			i,
			prevoutScripts,
			prevoutValues,
			bitcoin.Transaction.SIGHASH_DEFAULT,
			tapleafHash(inp.witnessScript)
		);
		sigs.set(inp.index, Buffer.from(ecc.signSchnorr(sighash, inp.privkey)));
	}

	const toLocalSig = sigs.get(toLocalIndex);
	if (!toLocalSig) {
		throw new Error('watchtower: failed to sign to_local penalty input');
	}

	const kit: IJusticeKitV1 = {
		sweepAddress: ctx.sweepScript,
		revocationPubKey: toXOnly(keys.revocationPubkey),
		localDelayPubKey: toXOnly(keys.theirDelayedPubkey),
		commitToLocalSig: toLocalSig,
		delayScriptHash: tapleafHash(toLocal.delay.script)
	};
	if (toRemotePubkey) {
		kit.commitToRemotePubKey = toRemotePubkey;
		kit.commitToRemoteSig = sigs.get(toRemoteIndex);
	}

	return finishBackup(ctx, justiceTx, (key) => encryptJusticeKitV1(kit, key));
}

/** Derive the revoked state's revocation/delayed keys shared by both kits. */
function deriveJusticeKeys(ctx: IJusticeContext): {
	revocationPubkey: Buffer;
	revocationPrivkey: Buffer;
	theirDelayedPubkey: Buffer;
} {
	const point = perCommitmentPointFromSecret(ctx.perCommitmentSecret);
	return {
		revocationPubkey: deriveRevocationPubkey(ctx.revocationBasepoint, point),
		revocationPrivkey: deriveRevocationPrivkey(
			ctx.revocationBasepointSecret,
			ctx.perCommitmentSecret,
			ctx.revocationBasepoint,
			point
		),
		theirDelayedPubkey: derivePublicKey(ctx.remoteDelayedBasepoint, point)
	};
}

function finishBackup(
	ctx: IJusticeContext,
	justiceTx: bitcoin.Transaction,
	encrypt: (key: Buffer) => Buffer
): IJusticeBackup {
	const revokedTxid = Buffer.from(ctx.revokedTx.getId(), 'hex').reverse();
	const key = breachKeyFromTxid(revokedTxid);
	const hint = breachHintFromTxid(revokedTxid);
	const encryptedBlob = encrypt(key);
	const swept = justiceTx.outs.reduce((a, o) => a + BigInt(o.value), 0n);
	return { hint, encryptedBlob, revokedTxid, sweptSats: swept };
}

/**
 * Assemble the (unsigned) justice transaction exactly as the tower will:
 * BIP69-ordered inputs (single revoked-tx source, so by output index) and a
 * lone sweep output of totalAmt - fee.
 */
function buildJusticeTx(
	ctx: IJusticeContext,
	policy: ISessionPolicy,
	inputs: IPenaltyInput[]
): { justiceTx: bitcoin.Transaction; orderedInputs: IPenaltyInput[] } {
	const orderedInputs = [...inputs].sort((a, b) => a.index - b.index);

	const weight = estimateJusticeWeight(ctx, orderedInputs);
	const fee = (policy.sweepFeeRate * BigInt(weight)) / 1000n;
	const totalAmt = orderedInputs.reduce((a, x) => a + BigInt(x.value), 0n);
	const sweepAmt = totalAmt - fee;
	if (sweepAmt <= 0n) {
		throw new Error('watchtower: justice fee exceeds swept value');
	}
	// A dust justice output is unredeemable: the tower ships a blob that can
	// never be mined, so a tiny channel silently loses breach protection.
	// The floor depends on the sweep script type (P2WPKH 294 / P2WSH 330 /
	// other witness programs 354), so use the shared per-script check.
	if (isDustOutput(ctx.sweepScript, sweepAmt)) {
		throw new Error(
			`watchtower: justice sweep output ${sweepAmt} sat is below the dust limit for the sweep script`
		);
	}

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;
	const revokedTxidBuf = Buffer.from(ctx.revokedTx.getId(), 'hex').reverse();
	for (const inp of orderedInputs) {
		tx.addInput(revokedTxidBuf, inp.index, inp.sequence);
	}
	tx.addOutput(ctx.sweepScript, Number(sweepAmt));
	return { justiceTx: tx, orderedInputs };
}

function estimateJusticeWeight(
	ctx: IJusticeContext,
	inputs: IPenaltyInput[]
): number {
	let inputVBytes = 0;
	let witnessWeight = 0;
	for (const inp of inputs) {
		inputVBytes += INPUT_SIZE;
		witnessWeight += inp.witnessWeight;
	}
	// P2TR sweep outputs are 34-byte programs like P2WSH, same 43-byte output
	// size (lookout/justice_descriptor.go handles P2TR via the P2WSH case).
	const outputVBytes =
		ctx.sweepScript.length === 22 ? P2WKH_OUTPUT_SIZE : P2WSH_OUTPUT_SIZE;
	const stripped =
		BASE_TX_SIZE +
		varIntSize(inputs.length) +
		inputVBytes +
		varIntSize(1) +
		outputVBytes;
	// hasWitness: + witness header (2) + witness sizes.
	return stripped * WITNESS_SCALE_FACTOR + 2 + witnessWeight;
}

function varIntSize(n: number): number {
	if (n < 0xfd) return 1;
	if (n <= 0xffff) return 3;
	if (n <= 0xffffffff) return 5;
	return 9;
}

function findOutput(tx: bitcoin.Transaction, scriptPubKey: Buffer): number {
	for (let i = 0; i < tx.outs.length; i++) {
		if (tx.outs[i].script.equals(scriptPubKey)) {
			return i;
		}
	}
	return -1;
}

function p2pkhScript(pubkey: Buffer): Buffer {
	return bitcoin.payments.p2pkh({ pubkey }).output!;
}

/** Pick the blob type for a channel (blob.TypeFromChannel: taproot first). */
export function blobTypeForChannel(
	isAnchor: boolean,
	isTaproot = false
): BlobType {
	if (isTaproot) return BlobType.ALTRUIST_TAPROOT_COMMIT;
	return isAnchor ? BlobType.ALTRUIST_ANCHOR_COMMIT : BlobType.ALTRUIST_COMMIT;
}
