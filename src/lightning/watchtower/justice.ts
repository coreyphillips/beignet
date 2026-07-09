/**
 * Build an encrypted justice kit + breach hint from a revoked remote commitment.
 *
 * The client pre-signs the penalty input(s) so a tower that only ever sees the
 * blob can reassemble and broadcast the penalty transaction. Because the
 * signatures are SIGHASH_ALL, they commit to the exact justice-transaction
 * output values, so the client MUST build the same transaction the tower will:
 * BIP69-sorted inputs and a single sweep output of totalAmt - fee, where the fee
 * comes from the session's sweep_fee_rate applied to lnd's fixed witness/weight
 * estimates. Those estimates are mirrored here (input/size.go) so the signatures
 * validate on an LND altruist tower.
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
import {
	BlobType,
	IJusticeKitV0,
	breachHintFromTxid,
	breachKeyFromTxid,
	encryptJusticeKitV0
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
	/** Our static to_remote payment pubkey on the remote commitment. */
	localPaymentPubkey?: Buffer;
	/** Secret for localPaymentPubkey (signs the to_remote sweep). */
	paymentBasepointSecret?: Buffer;
	/** Witness program we sweep breached funds into (<= 42 bytes). */
	sweepScript: Buffer;
	network: bitcoin.Network;
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
	witnessScript: Buffer;
	isP2wkh: boolean;
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
	const point = perCommitmentPointFromSecret(ctx.perCommitmentSecret);
	const revocationPubkey = deriveRevocationPubkey(
		ctx.revocationBasepoint,
		point
	);
	const theirDelayedPubkey = derivePublicKey(ctx.remoteDelayedBasepoint, point);
	const revocationPrivkey = deriveRevocationPrivkey(
		ctx.revocationBasepointSecret,
		ctx.perCommitmentSecret,
		ctx.revocationBasepoint,
		point
	);
	const toLocalScript = buildToLocalScript(
		revocationPubkey,
		theirDelayedPubkey,
		ctx.toSelfDelay
	);
	const toLocalSpk = bitcoin.payments.p2wsh({
		redeem: { output: toLocalScript },
		network: ctx.network
	}).output!;

	const toLocalIndex = findOutput(ctx.revokedTx, toLocalSpk);
	if (toLocalIndex < 0) {
		throw new Error(
			`watchtower: to_local output not found on revoked commitment ${ctx.channelId}`
		);
	}

	const inputs: IPenaltyInput[] = [
		{
			index: toLocalIndex,
			value: ctx.revokedTx.outs[toLocalIndex].value,
			witnessScript: toLocalScript,
			isP2wkh: false,
			privkey: revocationPrivkey
		}
	];

	// Legacy (non-anchor) to_remote is a plain p2wpkh we control; include it so a
	// tower sweeps everything in one transaction. Anchor to_remote (1-block CSV)
	// and taproot are not yet packed; the to_local penalty still stands alone.
	let toRemotePubkey: Buffer | undefined;
	if (!ctx.isAnchor && ctx.localPaymentPubkey && ctx.paymentBasepointSecret) {
		const toRemoteSpk = bitcoin.payments.p2wpkh({
			pubkey: ctx.localPaymentPubkey,
			network: ctx.network
		}).output!;
		const toRemoteIndex = findOutput(ctx.revokedTx, toRemoteSpk);
		if (toRemoteIndex >= 0) {
			toRemotePubkey = ctx.localPaymentPubkey;
			inputs.push({
				index: toRemoteIndex,
				value: ctx.revokedTx.outs[toRemoteIndex].value,
				witnessScript: p2pkhScript(ctx.localPaymentPubkey),
				isP2wkh: true,
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
		revocationPubKey: revocationPubkey,
		localDelayPubKey: theirDelayedPubkey,
		csvDelay: ctx.toSelfDelay,
		commitToLocalSig: toLocalSig
	};
	if (toRemotePubkey) {
		kit.commitToRemotePubKey = toRemotePubkey;
		kit.commitToRemoteSig = sigs.get(inputs.find((x) => x.isP2wkh)!.index);
	}

	const revokedTxid = Buffer.from(ctx.revokedTx.getId(), 'hex').reverse();
	const key = breachKeyFromTxid(revokedTxid);
	const hint = breachHintFromTxid(revokedTxid);
	const encryptedBlob = encryptJusticeKitV0(kit, key);

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

	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;
	const revokedTxidBuf = Buffer.from(ctx.revokedTx.getId(), 'hex').reverse();
	for (const inp of orderedInputs) {
		// Anchor to_remote would need sequence 1; to_local uses 0.
		tx.addInput(revokedTxidBuf, inp.index, 0);
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
		if (inp.isP2wkh) {
			witnessWeight += P2WKH_WITNESS_SIZE;
		} else {
			witnessWeight += ctx.isAnchor
				? TO_LOCAL_PENALTY_WITNESS_SIZE
				: TO_LOCAL_PENALTY_WITNESS_SIZE_LEGACY;
		}
	}
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

/** Pick the version-0 blob type for a channel (taproot is not yet supported). */
export function blobTypeForChannel(isAnchor: boolean): BlobType {
	return isAnchor ? BlobType.ALTRUIST_ANCHOR_COMMIT : BlobType.ALTRUIST_COMMIT;
}
