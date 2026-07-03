/**
 * FFOR M2 — deterministic voucher commitment C_i^R and settlement packages
 * (spec §8/§9.1), Variant A.
 *
 * C_i^R is a standard BOLT 3 commitment for R at commitment number n_R + i,
 * built by S ALONE from the last co-signed pre-epoch state plus the settlement
 * history, at the frozen feerate. Both sides construct it through beignet's
 * real commitment builder (buildRemoteCommitment on S / buildLocalCommitment
 * on R), so trimming, BOLT 3 output ordering, anchors, and the sub-satoshi
 * remainder rule (§8: the truncated msat remainder of each voucher output
 * stays with the offerer, S) are inherited from the production code path —
 * byte-compatible with the canonical Appendix A vectors
 * (specs/ffor-test-vectors.md), which were generated with the same builder.
 */

import crypto from 'crypto';
import { IChannelState } from '../channel/channel-state';
import { HtlcDirection, HtlcState, IHtlcEntry } from '../channel/types';
import {
	buildLocalCommitment,
	buildRemoteCommitment,
	signRemoteCommitment,
	verifyRemoteCommitmentSig,
	verifyRemoteHtlcSignatures,
	calculateCommitmentFee
} from '../channel/commitment-builder';
import { ChannelSigner } from '../keys/signer';
import { perCommitmentPointFromSecret } from '../keys/derivation';
import {
	FforRole,
	FforVariant,
	IFforEpochStateData,
	FFOR_SETTLEMENT_SAFETY_DELTA
} from './types';
import {
	FF_SETTLEMENT_TYPE,
	IFforSettlementMessage,
	encodeFforSettlementMessage,
	decodeFforSettlementMessage,
	fforMessageDigest,
	verifyFforMessageSignature
} from './messages';
import { voucherDustFloorMsat } from './epoch';

/** Spec §8: fee(a) = fee_base_msat + a · fee_proportional_millionths / 10^6. */
export function fforSkimFeeMsat(
	epoch: IFforEpochStateData,
	htlcAmountMsat: bigint
): bigint {
	return (
		BigInt(epoch.params.feeBaseMsat) +
		(htlcAmountMsat * BigInt(epoch.params.feeProportionalMillionths)) /
			1_000_000n
	);
}

/** The HTLC id voucher seq k assumes at reconciliation (prototype rule). */
export function fforVoucherHtlcId(
	epoch: IFforEpochStateData,
	seq: number
): bigint {
	return epoch.sHtlcIdBase + BigInt(seq - 1);
}

/** Sum of v_1..v_upto (msat-exact). */
export function fforVoucherSumMsat(
	epoch: IFforEpochStateData,
	upto: number
): bigint {
	let sum = 0n;
	for (let k = 0; k < upto; k++) {
		sum += epoch.voucherAmountsMsat[k];
	}
	return sum;
}

/** One voucher as an HTLC entry (insertion order = voucher seq, per Appendix A). */
function voucherEntry(
	epoch: IFforEpochStateData,
	seq: number,
	direction: HtlcDirection
): IHtlcEntry {
	return {
		id: fforVoucherHtlcId(epoch, seq),
		amountMsat: epoch.voucherAmountsMsat[seq - 1],
		paymentHash: epoch.params.paymentHashes![seq - 1],
		cltvExpiry: epoch.params.voucherExpiry,
		onionRoutingPacket: Buffer.alloc(0),
		direction,
		state: HtlcState.COMMITTED
	};
}

/**
 * A shallow working copy of the channel state describing C_i^R's world:
 * vouchers 1..upto as HTLCs, S's balance reduced by Σ v_k, and every
 * feerate input pinned to the frozen epoch rate (spec §5). The LIVE state is
 * never mutated — the epoch freezes it until reconciliation adoption.
 */
export function buildVoucherStateClone(
	base: IChannelState,
	epoch: IFforEpochStateData,
	upto: number,
	role: FforRole
): IChannelState {
	const htlcs = new Map<string, IHtlcEntry>();
	const direction =
		role === 'settlement_peer' ? HtlcDirection.OFFERED : HtlcDirection.RECEIVED;
	for (let k = 1; k <= upto; k++) {
		htlcs.set(`ffor-${k}`, voucherEntry(epoch, k, direction));
	}
	const sumV = fforVoucherSumMsat(epoch, upto);
	return {
		...base,
		htlcs,
		localBalanceMsat:
			role === 'settlement_peer'
				? base.localBalanceMsat - sumV
				: base.localBalanceMsat,
		remoteBalanceMsat:
			role === 'recipient'
				? base.remoteBalanceMsat - sumV
				: base.remoteBalanceMsat,
		localConfig: {
			...base.localConfig,
			feeratePerKw: epoch.frozenFeeratePerKw
		},
		remoteConfig: {
			...base.remoteConfig,
			feeratePerKw: epoch.frozenFeeratePerKw
		},
		pendingFeeratePerKw: undefined,
		lastSignedCommitFeeratePerKw: epoch.frozenFeeratePerKw
	};
}

/** Reasons a delegated payment must be refused (spec §8). Null = acceptable. */
export function fforSettlementCheckError(
	base: IChannelState,
	epoch: IFforEpochStateData,
	seq: number,
	htlcAmountMsat: bigint,
	upstreamCltvExpiry: number,
	currentBlockHeight: number
): string | null {
	const params = epoch.params;
	if (seq > params.maxPayments) {
		return `settlement ${seq} exceeds max_payments ${params.maxPayments}`;
	}
	if (htlcAmountMsat < params.minPaymentMsat) {
		return `htlc_amount ${htlcAmountMsat} below min_payment_msat ${params.minPaymentMsat}`;
	}
	const fee = fforSkimFeeMsat(epoch, htlcAmountMsat);
	const v = htlcAmountMsat - fee;
	const dustFloor = voucherDustFloorMsat(
		base.localConfig.dustLimitSatoshis > base.remoteConfig.dustLimitSatoshis
			? base.localConfig.dustLimitSatoshis
			: base.remoteConfig.dustLimitSatoshis,
		epoch.frozenFeeratePerKw,
		true // spec §5 prerequisite: anchor channels (zero-fee second level)
	);
	if (v < dustFloor) {
		return `voucher v_${seq} = ${v} msat below the voucher dust floor ${dustFloor} (would be trimmed)`;
	}
	const cumulative = fforVoucherSumMsat(epoch, seq - 1) + v;
	if (cumulative > params.budgetMsat) {
		return `cumulative voucher value ${cumulative} exceeds budget_msat ${params.budgetMsat}`;
	}
	// max_htlc_value_in_flight semantics: vouchers are S-offered — bounded by
	// what R accepts in flight.
	const rMaxInFlight =
		epoch.role === 'settlement_peer'
			? base.remoteConfig.maxHtlcValueInFlightMsat
			: base.localConfig.maxHtlcValueInFlightMsat;
	if (cumulative > rMaxInFlight) {
		return `cumulative voucher value ${cumulative} exceeds max_htlc_value_in_flight ${rMaxInFlight}`;
	}
	// S's post-update balance (minus the commitment fee it funds at the frozen
	// feerate with seq untrimmed vouchers) must stay above channel_reserve.
	const sBalance =
		epoch.role === 'settlement_peer'
			? base.localBalanceMsat
			: base.remoteBalanceMsat;
	const sReserveSat =
		epoch.role === 'settlement_peer'
			? base.remoteConfig.channelReserveSatoshis
			: base.localConfig.channelReserveSatoshis;
	const commitFee =
		calculateCommitmentFee(epoch.frozenFeeratePerKw, seq, true) * 1000n;
	if (sBalance - cumulative - commitFee < sReserveSat * 1000n) {
		return `settlement ${seq} would push S below channel_reserve`;
	}
	if (currentBlockHeight > 0) {
		if (currentBlockHeight >= params.settlementDeadline) {
			return `height ${currentBlockHeight} at/past settlement_deadline ${params.settlementDeadline}`;
		}
		if (
			currentBlockHeight >=
			upstreamCltvExpiry - FFOR_SETTLEMENT_SAFETY_DELTA
		) {
			return `upstream cltv_expiry ${upstreamCltvExpiry} within the safety delta of height ${currentBlockHeight}`;
		}
	}
	return null;
}

/**
 * S side: build, sign, and encode settlement package `seq` (§9.1). The caller
 * has already run fforSettlementCheckError and recorded
 * htlcAmountsMsat/voucherAmountsMsat[seq−1].
 */
export function buildSettlementPackage(args: {
	base: IChannelState;
	signer: ChannelSigner;
	epoch: IFforEpochStateData;
	channelId: Buffer;
	seq: number;
	signFn: (digest: Buffer) => Buffer;
	upstreamScid?: Buffer;
}): { payload: Buffer; msg: IFforSettlementMessage } {
	const { base, signer, epoch, channelId, seq, signFn } = args;
	const n = epoch.nR + BigInt(seq);
	const rPoint = epoch.params.rPerCommitmentPoints[seq - 1];
	const clone = buildVoucherStateClone(base, epoch, seq, epoch.role);
	const { signature, htlcSignatures } = signRemoteCommitment(
		clone,
		signer,
		rPoint,
		n
	);

	const msg: IFforSettlementMessage = {
		channelId,
		epochId: epoch.epochId,
		seq,
		paymentHash: epoch.params.paymentHashes![seq - 1],
		htlcAmountMsat: epoch.htlcAmountsMsat[seq - 1],
		voucherAmountMsat: epoch.voucherAmountsMsat[seq - 1],
		rCommitmentNumber: n,
		commitmentSig: signature,
		htlcSigs: htlcSignatures,
		// §9.1 TLV 1: the pre-revocation, REQUIRED in seq 1 (both variants).
		// S keeps per_commitment_secret_S[n0] in sRevocationSecretN0; in
		// variant A that equals preimages[0] (the §7.2 binding).
		revocationSecretN0:
			seq === 1 ? epoch.sRevocationSecretN0 ?? epoch.preimages[0] : undefined,
		// Variant A TLV 3 (P_1 IS per_commitment_secret_S[n0], §12.1).
		preimage:
			epoch.params.variant === FforVariant.A
				? epoch.preimages[seq - 1]
				: undefined,
		upstreamScid: args.upstreamScid,
		signature: Buffer.alloc(64)
	};
	const payload = encodeFforSettlementMessage(msg);
	const sig = signFn(fforMessageDigest(FF_SETTLEMENT_TYPE, payload));
	sig.copy(payload, payload.length - 64);
	msg.signature = Buffer.from(sig);
	return { payload, msg };
}

/**
 * R side (and the tower's checklist, §9.4): validate settlement package `seq`
 * against our own state. On success the decoded message is returned; the
 * caller records amounts/preimage/package and, at seq == j, adopts C_j^R.
 *
 * `sPerCommitmentPointN0` is S's per-commitment point at n0 — the anchor for
 * the seq-1 pre-revocation and the Variant-A H_1 binding (§7.2, verified
 * ex post here).
 */
export function validateSettlementPackage(args: {
	base: IChannelState;
	signer: ChannelSigner;
	epoch: IFforEpochStateData;
	payload: Buffer;
	remoteNodeId: Buffer;
	sPerCommitmentPointN0: Buffer;
	currentBlockHeight: number;
}): { ok: boolean; error?: string; msg?: IFforSettlementMessage } {
	const { base, signer, epoch, payload, remoteNodeId } = args;
	let msg: IFforSettlementMessage;
	try {
		msg = decodeFforSettlementMessage(payload);
	} catch (e) {
		return { ok: false, error: `undecodable package: ${(e as Error).message}` };
	}
	const fail = (error: string): { ok: false; error: string } => ({
		ok: false,
		error: `package ${msg.seq}: ${error}`
	});

	// ✍ node-key signature (fraud-proof anchor, §12.2).
	if (!verifyFforMessageSignature(FF_SETTLEMENT_TYPE, payload, remoteNodeId)) {
		return fail('node-key signature invalid');
	}
	if (!msg.epochId.equals(epoch.epochId)) {
		return fail('epoch_id mismatch');
	}
	// Checklist 1 (§9.4): strictly sequential; hash matches H_seq.
	if (msg.seq !== epoch.lastSeq + 1) {
		return fail(`out of order (expected ${epoch.lastSeq + 1})`);
	}
	const expectedHash = epoch.params.paymentHashes?.[msg.seq - 1];
	if (!expectedHash || !msg.paymentHash.equals(expectedHash)) {
		return fail('payment_hash != H_seq');
	}
	// Checklist 2: amounts and fee math; §8 constraints.
	if (
		msg.voucherAmountMsat !==
		msg.htlcAmountMsat - fforSkimFeeMsat(epoch, msg.htlcAmountMsat)
	) {
		return fail('voucher_amount != htlc_amount − fee(htlc_amount)');
	}
	const checkErr = fforSettlementCheckError(
		base,
		epoch,
		msg.seq,
		msg.htlcAmountMsat,
		// R has no upstream HTLC; pass an expiry far above the safety delta.
		Number.MAX_SAFE_INTEGER,
		args.currentBlockHeight
	);
	if (checkErr) {
		return fail(checkErr);
	}
	if (msg.rCommitmentNumber !== epoch.nR + BigInt(msg.seq)) {
		return fail('r_commitment_number != n_R + seq');
	}

	// Record this package's amounts so the deterministic rebuild includes it.
	epoch.htlcAmountsMsat[msg.seq - 1] = msg.htlcAmountMsat;
	epoch.voucherAmountsMsat[msg.seq - 1] = msg.voucherAmountMsat;

	// Checklist 3: deterministic reconstruction + signature verification.
	const n = epoch.nR + BigInt(msg.seq);
	const rPoint = epoch.params.rPerCommitmentPoints[msg.seq - 1];
	const clone = buildVoucherStateClone(base, epoch, msg.seq, 'recipient');
	// verify* helpers derive the commitment number as localCommitmentNumber + 1.
	clone.localCommitmentNumber = n - 1n;
	if (!verifyRemoteCommitmentSig(clone, signer, rPoint, msg.commitmentSig, n)) {
		return fail('commitment_sig does not verify against S funding pubkey');
	}
	if (!verifyRemoteHtlcSignatures(clone, signer, rPoint, msg.htlcSigs)) {
		return fail('htlc_sigs do not verify (output-index order, §8)');
	}

	// Checklist 4: the seq-1 pre-revocation binds to per_commitment_point_S[n0].
	if (msg.seq === 1) {
		if (!msg.revocationSecretN0) {
			return fail('missing revocation_secret_n0 (REQUIRED in seq 1)');
		}
		if (
			!perCommitmentPointFromSecret(msg.revocationSecretN0).equals(
				args.sPerCommitmentPointN0
			)
		) {
			return fail('revocation_secret_n0 · G != per_commitment_point_S[n0]');
		}
	}
	// Variant A: the preimage must hash to H_seq; for seq 1 it IS the
	// revocation secret (the §7.2/§12.1 binding, verified ex post).
	if (epoch.params.variant === FforVariant.A) {
		if (!msg.preimage) {
			return fail('missing variant-A preimage');
		}
		const hash = crypto.createHash('sha256').update(msg.preimage).digest();
		if (!hash.equals(msg.paymentHash)) {
			return fail('SHA256(preimage) != payment_hash');
		}
		if (msg.seq === 1 && !msg.preimage.equals(msg.revocationSecretN0!)) {
			return fail('P_1 != revocation_secret_n0 (H_1 binding, §7.2)');
		}
	}

	return { ok: true, msg };
}

/**
 * Rebuild C_i^R exactly as S constructs it (for tests / audits): returns the
 * built commitment from S's perspective (buildRemoteCommitment).
 */
export function buildVoucherCommitment(
	base: IChannelState,
	epoch: IFforEpochStateData,
	seq: number
): ReturnType<typeof buildRemoteCommitment> {
	const clone = buildVoucherStateClone(base, epoch, seq, epoch.role);
	return buildRemoteCommitment(
		clone,
		seq === 0
			? // C_0 uses R's pre-epoch point; callers rarely need it (audit only).
			  epoch.rPreEpochPoint!
			: epoch.params.rPerCommitmentPoints[seq - 1],
		epoch.nR + BigInt(seq)
	);
}

/**
 * Rebuild C_i^R from R's own (mirror) state, byte-identically (Appendix A
 * verification 2) — used by tests to pin both directions to the vectors.
 */
export function buildVoucherCommitmentLocal(
	base: IChannelState,
	epoch: IFforEpochStateData,
	seq: number
): ReturnType<typeof buildLocalCommitment> {
	const clone = buildVoucherStateClone(base, epoch, seq, 'recipient');
	const n = epoch.nR + BigInt(seq);
	clone.localCommitmentNumber = n - 1n;
	return buildLocalCommitment(
		clone,
		epoch.params.rPerCommitmentPoints[seq - 1],
		n
	);
}

/**
 * Reconciliation adoption (spec §11.1): graft the epoch's j vouchers onto the
 * LIVE channel state as ordinary COMMITTED HTLCs and shift the balance, so the
 * post-ff_end channel runs the stock update_fulfill_htlc/commitment dance with
 * zero new machinery (§8 "machinery reuse").
 */
export function adoptVouchersIntoLiveState(
	state: IChannelState,
	epoch: IFforEpochStateData,
	role: FforRole
): void {
	const j = epoch.lastSeq;
	const sumV = fforVoucherSumMsat(epoch, j);
	for (let k = 1; k <= j; k++) {
		const id = fforVoucherHtlcId(epoch, k);
		if (role === 'settlement_peer') {
			state.htlcs.set(
				`offered-${id}`,
				voucherEntry(epoch, k, HtlcDirection.OFFERED)
			);
		} else {
			state.htlcs.set(
				`received-${id}`,
				voucherEntry(epoch, k, HtlcDirection.RECEIVED)
			);
		}
	}
	if (role === 'settlement_peer') {
		state.localBalanceMsat -= sumV;
		state.localHtlcCounter = epoch.sHtlcIdBase + BigInt(j);
	} else {
		state.remoteBalanceMsat -= sumV;
	}
	// The epoch ran at the frozen feerate; the adopted commitments were built
	// (and verified) at it.
	state.lastSignedCommitFeeratePerKw = epoch.frozenFeeratePerKw;
	state.needsCommitment = false;
}
