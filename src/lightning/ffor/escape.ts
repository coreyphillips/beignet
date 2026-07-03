/**
 * FFOR M5 — pre-signed escapes (spec §7.4, §10, Appendix B).
 *
 * If R never returns, S must not be locked forever. At setup R pre-signs
 * J = ceil(budget/G) alternative commitments E_1..E_J, all at S's commitment
 * number n0+1, each carrying one "aggregate voucher" output of j*G paying R
 * (Appendix B.1). This module builds the deterministic escape set (both sides
 * derive it byte-identically), the aggregate-voucher witness script (B.2), and
 * the three spend paths (R claim / S refund / revocation penalty).
 *
 * The construction reuses beignet's real BOLT 3 low-level commitment builder
 * (buildCommitmentTx) and sweep primitives, so output ordering, anchors,
 * obscured-number encoding, and signatures are production code paths.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { IChannelBasepoints } from '../keys/derivation';
import { deriveCommitmentKeys } from '../channel/commitment-builder';
import {
	buildCommitmentTx,
	calculateObscuredCommitmentNumber,
	ICommitmentTxResult
} from '../script/commitment';
import { calculateCommitmentFee } from '../channel/commitment-builder';
import { ANCHOR_TOTAL_COST } from '../script/anchor';
import { createFundingScript } from '../script/funding';
import { ChannelSigner } from '../keys/signer';
import { verify } from '../crypto/ecdh';
import { signSweepInput } from '../chain/sweep';
import { escapeCount } from './epoch';

/** Everything needed to derive the escape set deterministically (both sides). */
export interface IEscapeChannelContext {
	fundingTxid: Buffer; // internal byte order
	fundingOutputIndex: number;
	fundingSatoshis: bigint;
	/** Whether S is the channel opener (funder). Escapes are S's commitment;
	 *  the funder pays the commitment fee (BOLT 3 / Appendix B.1 step 3). */
	sIsOpener: boolean;
	sBasepoints: IChannelBasepoints;
	rBasepoints: IChannelBasepoints;
	/** S's per-commitment point at n0+1 (R holds it from the last pre-epoch
	 *  revoke_and_ack; S derives it from its own seed). */
	sPerCommitmentPointN0Plus1: Buffer;
	/** n0: S's commitment number at epoch start (escapes live at n0+1). */
	n0: bigint;
	/** Pre-epoch (quiescent) balances, millisatoshis. */
	preEpochSLocalMsat: bigint;
	preEpochRLocalMsat: bigint;
	sToSelfDelay: number; // to_self_delay S must wait (R required of S)
	frozenFeeratePerKw: number;
	/** T_exp: voucher_expiry, the CLTV on the aggregate voucher refund path. */
	voucherExpiry: number;
	/** bLIP-51 lease encumbrance on S's to_local, if S is the lessor. */
	sLeaseExpiry?: number;
	network?: bitcoin.Network;
}

/**
 * Appendix B.2 aggregate-voucher witness script (P2WSH). Three paths:
 *   1 revocation (R/tower penalize a revoked escape)
 *   2 S refund after T_exp, revocation-delayed
 *   3 R claim: static R payment key, 1-block CSV
 */
export function buildAggregateVoucherScript(
	revocationPubkey: Buffer,
	sDelayedPubkey: Buffer,
	rPaymentBasepoint: Buffer,
	voucherExpiry: number,
	toSelfDelay: number
): Buffer {
	return bitcoin.script.compile([
		bitcoin.opcodes.OP_DUP,
		bitcoin.opcodes.OP_HASH160,
		bitcoin.crypto.hash160(revocationPubkey),
		bitcoin.opcodes.OP_EQUAL,
		bitcoin.opcodes.OP_IF,
		// Path 1 — revocation
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_ELSE,
		bitcoin.opcodes.OP_NOTIF,
		// Path 2 — S refund (T_exp CLTV + to_self_delay CSV, in-script)
		bitcoin.script.number.encode(voucherExpiry),
		bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
		bitcoin.opcodes.OP_DROP,
		bitcoin.script.number.encode(toSelfDelay),
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
		bitcoin.opcodes.OP_DROP,
		sDelayedPubkey,
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_ELSE,
		// Path 3 — R claim (bare sig, 1-block CSV)
		bitcoin.opcodes.OP_1,
		bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
		bitcoin.opcodes.OP_DROP,
		rPaymentBasepoint,
		bitcoin.opcodes.OP_CHECKSIG,
		bitcoin.opcodes.OP_ENDIF,
		bitcoin.opcodes.OP_ENDIF
	]);
}

/** Keys + the aggregate-voucher script for a given escape context. */
export function escapeVoucherKeys(ctx: IEscapeChannelContext): {
	revocationPubkey: Buffer;
	sDelayedPubkey: Buffer;
	rPaymentBasepoint: Buffer;
	voucherScript: Buffer;
} {
	// E_j is S's OWN commitment (holder = S): deriveCommitmentKeys with S local.
	const keys = deriveCommitmentKeys(
		ctx.sBasepoints,
		ctx.rBasepoints,
		ctx.sPerCommitmentPointN0Plus1,
		true
	);
	const voucherScript = buildAggregateVoucherScript(
		keys.revocationPubkey,
		keys.localDelayedPubkey,
		ctx.rBasepoints.paymentBasepoint,
		ctx.voucherExpiry,
		ctx.sToSelfDelay
	);
	return {
		revocationPubkey: keys.revocationPubkey,
		sDelayedPubkey: keys.localDelayedPubkey,
		rPaymentBasepoint: ctx.rBasepoints.paymentBasepoint,
		voucherScript
	};
}

export interface IBuiltEscape {
	j: number;
	tx: bitcoin.Transaction;
	/** Aggregate voucher output index and value (satoshis). */
	voucherOutputIndex: number;
	voucherValueSat: bigint;
	voucherScript: Buffer;
	fundingWitnessScript: Buffer;
	fundingAmountSat: number;
	outputMap: ICommitmentTxResult['outputMap'];
}

/**
 * Build E_j deterministically (Appendix B.1): S's commitment at n0+1 with
 * to_local reduced by j*G and one aggregate voucher output of j*G. The funder
 * pays the +172 WU fee for the extra output at the frozen feerate.
 */
export function buildEscapeCommitment(
	ctx: IEscapeChannelContext,
	j: number,
	granularityMsat: bigint
): IBuiltEscape {
	if (granularityMsat % 1000n !== 0n) {
		throw new Error('escape_granularity_msat must be a multiple of 1000');
	}
	const voucherValueSat = (BigInt(j) * granularityMsat) / 1000n;
	const { revocationPubkey, voucherScript } = escapeVoucherKeys(ctx);
	const keys = deriveCommitmentKeys(
		ctx.sBasepoints,
		ctx.rBasepoints,
		ctx.sPerCommitmentPointN0Plus1,
		true
	);

	// Anchor channel (spec §5). One extra untrimmed output ⇒ fee for 1 HTLC.
	const fee = calculateCommitmentFee(ctx.frozenFeeratePerKw, 1, true);

	// S is the funder: its to_local pays the fee + both anchors + gives up j*G.
	const sLocalSat = ctx.preEpochSLocalMsat / 1000n;
	const rLocalSat = ctx.preEpochRLocalMsat / 1000n;
	let localAmount: bigint;
	let remoteAmount: bigint;
	if (ctx.sIsOpener) {
		localAmount = sLocalSat - voucherValueSat - fee - ANCHOR_TOTAL_COST;
		remoteAmount = rLocalSat;
	} else {
		localAmount = sLocalSat - voucherValueSat;
		remoteAmount = rLocalSat - fee - ANCHOR_TOTAL_COST;
	}
	if (localAmount < 0n) localAmount = 0n;
	if (remoteAmount < 0n) remoteAmount = 0n;

	const commitNum = ctx.n0 + 1n;
	const openPaymentBasepoint = ctx.sIsOpener
		? ctx.sBasepoints.paymentBasepoint
		: ctx.rBasepoints.paymentBasepoint;
	const acceptPaymentBasepoint = ctx.sIsOpener
		? ctx.rBasepoints.paymentBasepoint
		: ctx.sBasepoints.paymentBasepoint;
	const obscured = calculateObscuredCommitmentNumber(
		openPaymentBasepoint,
		acceptPaymentBasepoint,
		commitNum
	);

	const funding = createFundingScript(
		ctx.sBasepoints.fundingPubkey,
		ctx.rBasepoints.fundingPubkey,
		ctx.network
	);

	const result = buildCommitmentTx({
		fundingTxid: ctx.fundingTxid.toString('hex'),
		fundingOutputIndex: ctx.fundingOutputIndex,
		fundingAmount: ctx.fundingSatoshis,
		obscuredCommitmentNumber: obscured,
		localAmount,
		revocationPubkey: keys.revocationPubkey,
		localDelayedPubkey: keys.localDelayedPubkey,
		toSelfDelay: ctx.sToSelfDelay,
		leaseExpiry: ctx.sLeaseExpiry,
		remoteAmount,
		remotePaymentPubkey: keys.remotePaymentPubkey,
		// The aggregate voucher rides as a single "HTLC" output carrying our
		// custom P2WSH script (the builder wraps it and sorts it BIP 69).
		htlcOutputs: [
			{
				script: voucherScript,
				amount: voucherValueSat,
				cltvExpiry: ctx.voucherExpiry,
				paymentHash: bitcoin.crypto.hash160(revocationPubkey)
			}
		],
		dustLimitSatoshis: 546n,
		useAnchors: true,
		localFundingPubkey: ctx.sBasepoints.fundingPubkey,
		remoteFundingPubkey: ctx.rBasepoints.fundingPubkey
	});

	const voucherOutputIndex = result.outputMap.htlcs[0];
	return {
		j,
		tx: result.tx,
		voucherOutputIndex,
		voucherValueSat,
		voucherScript,
		fundingWitnessScript: funding.witnessScript,
		fundingAmountSat: Number(ctx.fundingSatoshis),
		outputMap: result.outputMap
	};
}

/** Build the full escape set E_1..E_J. */
export function buildEscapeSet(
	ctx: IEscapeChannelContext,
	budgetMsat: bigint,
	granularityMsat: bigint
): IBuiltEscape[] {
	const J = escapeCount(budgetMsat, granularityMsat);
	const set: IBuiltEscape[] = [];
	for (let j = 1; j <= J; j++) {
		set.push(buildEscapeCommitment(ctx, j, granularityMsat));
	}
	return set;
}

// ─────────────── ff_escape_sigs (R signs, S verifies) ───────────────

/** R: ECDSA SIGHASH_ALL funding-key signature on E_j (compact 64-byte). */
export function signEscape(
	escape: IBuiltEscape,
	rSigner: ChannelSigner
): Buffer {
	return rSigner.signCommitmentTx(
		escape.tx,
		escape.fundingWitnessScript,
		escape.fundingAmountSat
	);
}

/** S: verify R's signature on E_j against R's funding pubkey. */
export function verifyEscapeSig(
	escape: IBuiltEscape,
	sig: Buffer,
	rFundingPubkey: Buffer
): boolean {
	const sigHash = escape.tx.hashForWitnessV0(
		0,
		escape.fundingWitnessScript,
		escape.fundingAmountSat,
		bitcoin.Transaction.SIGHASH_ALL
	);
	try {
		return verify(sigHash, rFundingPubkey, sig);
	} catch {
		return false;
	}
}

// ─────────────── Escape broadcast (S) ───────────────

/**
 * Apply the 2-of-2 funding witness so E_j is broadcastable. S signs its side;
 * R's signature came from ff_escape_sigs (compact). Returns the same tx.
 */
export function finalizeEscapeForBroadcast(
	escape: IBuiltEscape,
	sSigner: ChannelSigner,
	rEscapeSig: Buffer,
	sFundingPubkey: Buffer,
	rFundingPubkey: Buffer
): bitcoin.Transaction {
	const sSig = sSigner.signCommitmentTx(
		escape.tx,
		escape.fundingWitnessScript,
		escape.fundingAmountSat
	);
	const witness = ChannelSigner.buildFundingWitness(
		sSig,
		rEscapeSig,
		sFundingPubkey,
		rFundingPubkey,
		escape.fundingWitnessScript
	);
	escape.tx.setWitness(0, witness);
	return escape.tx;
}

/** j = ceil(owed/G), rounding UP so S bears the rounding cost (spec §10). */
export function escapeJForOwed(
	owedMsat: bigint,
	granularityMsat: bigint
): number {
	if (owedMsat <= 0n) return 0;
	return Number((owedMsat + granularityMsat - 1n) / granularityMsat);
}

// ─────────────── Aggregate-voucher spend paths (Appendix B.2) ───────────────

const DUST_FEE_SATS_DEFAULT = 300n;

export interface IEscapeSpendParams {
	escapeTxid: string; // display byte order (getId())
	voucherOutputIndex: number;
	voucherValueSat: bigint;
	voucherScript: Buffer;
	destinationScript: Buffer;
	feeSatoshis?: bigint;
}

/**
 * Path 3 — R claim. Static R payment key, input nSequence = 1 (1-block CSV).
 * Witness: <R_sig> <0x01> <script>. Requires only R's payment_basepoint
 * PRIVATE key (seed-derivable) + the funding outpoint — no epoch data.
 */
export function buildEscapeRClaim(
	params: IEscapeSpendParams,
	rPaymentBasepointSecret: Buffer
): bitcoin.Transaction {
	const fee = params.feeSatoshis ?? DUST_FEE_SATS_DEFAULT;
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;
	tx.addInput(
		Buffer.from(params.escapeTxid, 'hex').reverse(),
		params.voucherOutputIndex,
		1
	);
	const out = params.voucherValueSat - fee;
	if (out <= 0n)
		throw new Error('fee exceeds aggregate voucher value (R claim)');
	tx.addOutput(params.destinationScript, Number(out));
	const sig = signSweepInput(
		tx,
		0,
		params.voucherScript,
		Number(params.voucherValueSat),
		rPaymentBasepointSecret
	);
	tx.setWitness(0, [sig, Buffer.from([0x01]), params.voucherScript]);
	return tx;
}

/**
 * Path 2 — S refund after T_exp. nLockTime = T_exp, input nSequence =
 * to_self_delay. Witness: <S_sig> <> <script>. sDelayedSecret is S's delayed
 * payment key at n0+1.
 */
export function buildEscapeSRefund(
	params: IEscapeSpendParams,
	sDelayedSecret: Buffer,
	voucherExpiry: number,
	toSelfDelay: number
): bitcoin.Transaction {
	const fee = params.feeSatoshis ?? DUST_FEE_SATS_DEFAULT;
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = voucherExpiry;
	tx.addInput(
		Buffer.from(params.escapeTxid, 'hex').reverse(),
		params.voucherOutputIndex,
		toSelfDelay
	);
	const out = params.voucherValueSat - fee;
	if (out <= 0n)
		throw new Error('fee exceeds aggregate voucher value (S refund)');
	tx.addOutput(params.destinationScript, Number(out));
	const sig = signSweepInput(
		tx,
		0,
		params.voucherScript,
		Number(params.voucherValueSat),
		sDelayedSecret
	);
	tx.setWitness(0, [sig, Buffer.alloc(0), params.voucherScript]);
	return tx;
}

/**
 * Path 1 — revocation penalty. Witness: <rev_sig> <revocationPubkey> <script>.
 * No timelock. revocationSecret is the derived revocation PRIVATE key for S's
 * commitment n0+1 (R's revocation basepoint secret combined with S's revealed
 * per_commitment_secret[n0+1]).
 */
export function buildEscapeRevocation(
	params: IEscapeSpendParams,
	revocationSecret: Buffer,
	revocationPubkey: Buffer
): bitcoin.Transaction {
	const fee = params.feeSatoshis ?? DUST_FEE_SATS_DEFAULT;
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.locktime = 0;
	tx.addInput(
		Buffer.from(params.escapeTxid, 'hex').reverse(),
		params.voucherOutputIndex,
		0xffffffff
	);
	const out = params.voucherValueSat - fee;
	if (out <= 0n)
		throw new Error('fee exceeds aggregate voucher value (revocation)');
	tx.addOutput(params.destinationScript, Number(out));
	const sig = signSweepInput(
		tx,
		0,
		params.voucherScript,
		Number(params.voucherValueSat),
		revocationSecret
	);
	tx.setWitness(0, [sig, revocationPubkey, params.voucherScript]);
	return tx;
}

/**
 * Sign the aggregate voucher output of a broadcast E_j for the revocation path
 * without building the whole tx — used by the tower/justice path to add the
 * escape-voucher input to a larger penalty sweep.
 */
export function signEscapeVoucherRevocation(
	tx: bitcoin.Transaction,
	inputIndex: number,
	voucherScript: Buffer,
	voucherValueSat: bigint,
	revocationSecret: Buffer,
	revocationPubkey: Buffer
): Buffer[] {
	const sig = signSweepInput(
		tx,
		inputIndex,
		voucherScript,
		Number(voucherValueSat),
		revocationSecret
	);
	return [sig, revocationPubkey, voucherScript];
}

// ─────────────── Classification of a broadcast E_j ───────────────

export interface IEscapeMatch {
	isEscape: boolean;
	/** Which E_j (1..J), if identified by voucher value. */
	j?: number;
	voucherOutputIndex?: number;
	voucherValueSat?: bigint;
	voucherScript?: Buffer;
}

/**
 * Recognize a broadcast escape by matching the aggregate-voucher P2WSH output
 * (spec §B.5 / §10). The voucher script is deterministic from the context; a
 * broadcast tx is an escape iff it spends the funding outpoint and contains a
 * P2WSH output paying that script. `j` is recovered from the output value.
 */
export function matchEscapeBroadcast(
	tx: bitcoin.Transaction,
	ctx: IEscapeChannelContext,
	granularityMsat: bigint
): IEscapeMatch {
	const spendsFunding = tx.ins.some(
		(i) =>
			Buffer.from(i.hash).equals(ctx.fundingTxid) &&
			i.index === ctx.fundingOutputIndex
	);
	if (!spendsFunding) return { isEscape: false };
	const { voucherScript } = escapeVoucherKeys(ctx);
	const p2wsh = bitcoin.payments.p2wsh({
		redeem: { output: voucherScript }
	}).output!;
	for (let i = 0; i < tx.outs.length; i++) {
		if (Buffer.from(tx.outs[i].script).equals(p2wsh)) {
			const valueSat = BigInt(tx.outs[i].value);
			const gSat = granularityMsat / 1000n;
			const j = gSat > 0n ? Number(valueSat / gSat) : undefined;
			return {
				isEscape: true,
				j,
				voucherOutputIndex: i,
				voucherValueSat: valueSat,
				voucherScript
			};
		}
	}
	return { isEscape: false };
}
