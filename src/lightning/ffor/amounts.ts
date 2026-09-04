/**
 * FFOR section 7.6 amount arithmetic and the setup-time book checks
 * (sections 7.1, 7.2, 7.5.3, 7.6, 8, 9.5.1 bounds).
 *
 * All arithmetic is in bigint, so `d * fee_proportional_millionths` cannot
 * overflow; the 2^64 - 1 bounds are then explicit checks.
 */

import { calculateCommitmentFee } from '../channel/commitment-builder';
import {
	FF_BLINDED_HOPS_N,
	FF_MAX_K,
	FF_RECONCILE_MARGIN_BLOCKS,
	FforVariant,
	IFforEpochParams
} from './types';

export const U64_MAX = (1n << 64n) - 1n;
const MILLION = 1_000_000n;
/** BOLT 3: 330 sat per anchor, two anchors. */
export const ANCHOR_TOTAL_SAT = 660n;

/** fee_S(a) = fee_base_msat + floor(a * ppm / 10^6), on the PAYEE amount. */
export function feeS(
	amountMsat: bigint,
	feeBaseMsat: number,
	feeProportionalMillionths: number
): bigint {
	return (
		BigInt(feeBaseMsat) +
		(amountMsat * BigInt(feeProportionalMillionths)) / MILLION
	);
}

/** gross_into_S(a) = a + fee_S(a). */
export function grossIntoS(
	amountMsat: bigint,
	feeBaseMsat: number,
	feeProportionalMillionths: number
): bigint {
	return amountMsat + feeS(amountMsat, feeBaseMsat, feeProportionalMillionths);
}

/**
 * BOLT 4's inverse relay formula, used under a blinded path where S's hop
 * payload carries no plaintext amt_to_forward:
 *
 *   amt_to_forward = ((amount_msat - fee_base) * 10^6 + 10^6 + ppm - 1)
 *                    / (10^6 + ppm)
 *
 * Returns null when amount_msat is below the base fee.
 */
export function inverseAmtToForward(
	amountMsat: bigint,
	feeBaseMsat: number,
	feeProportionalMillionths: number
): bigint | null {
	const base = BigInt(feeBaseMsat);
	if (amountMsat < base) return null;
	const ppm = BigInt(feeProportionalMillionths);
	return ((amountMsat - base) * MILLION + MILLION + ppm - 1n) / (MILLION + ppm);
}

/** rounding_slack(d) = 2N + 1 + ceil(N * d / 10^6) with N = 8. */
export function roundingSlackMsat(amountMsat: bigint): bigint {
	const n = BigInt(FF_BLINDED_HOPS_N);
	return 2n * n + 1n + (n * amountMsat + MILLION - 1n) / MILLION;
}

export type FforHopKind = 'plaintext' | 'blinded';

export interface IFforAmountCheckInput {
	/** d_k from the book. */
	payeeAmountMsat: bigint;
	/** The incoming HTLC's amount_msat. */
	amountMsat: bigint;
	/**
	 * Plaintext: the hop payload's amt_to_forward. Blinded: ignored; derived
	 * from amount_msat by the inverse formula.
	 */
	amtToForwardMsat: bigint | null;
	hopKind: FforHopKind;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
}

/**
 * Section 7.6 checks 1 and 2 for the fixed-amount profile. Returns the
 * failing check, or null when the payment may be settled.
 */
export function checkDelegatedAmounts(
	input: IFforAmountCheckInput
):
	| null
	| { check: 1; reason: 'underpay' | 'overpay' | 'missing_amount' }
	| { check: 2; reason: 'fee_insufficient' } {
	const d = input.payeeAmountMsat;
	let forward: bigint;
	if (input.hopKind === 'blinded') {
		const derived = inverseAmtToForward(
			input.amountMsat,
			input.feeBaseMsat,
			input.feeProportionalMillionths
		);
		if (derived === null) return { check: 1, reason: 'underpay' };
		forward = derived;
		if (forward < d) return { check: 1, reason: 'underpay' };
		if (forward > d + roundingSlackMsat(d)) {
			return { check: 1, reason: 'overpay' };
		}
	} else {
		if (input.amtToForwardMsat === null) {
			return { check: 1, reason: 'missing_amount' };
		}
		forward = input.amtToForwardMsat;
		if (forward < d) return { check: 1, reason: 'underpay' };
		if (forward > d) return { check: 1, reason: 'overpay' };
	}
	const fee = feeS(d, input.feeBaseMsat, input.feeProportionalMillionths);
	if (input.amountMsat - forward < fee) {
		return { check: 2, reason: 'fee_insufficient' };
	}
	return null;
}

/** What the book checks need to know about the channel. */
export interface IFforBookCheckContext {
	/** R's limits bind the vouchers (S-offered). */
	rMaxAcceptedHtlcs: number;
	rMaxHtlcValueInFlightMsat: bigint;
	/** The channel's htlc_minimum_msat as S sees it for its own offers. */
	htlcMinimumMsat: bigint;
	/** R's dust limit: the voucher outputs live on R's commitment too. */
	dustLimitSatoshis: bigint;
	/** Frozen commitment feerate. */
	feeratePerKw: number;
	/** S's spendable local balance before the round, msat. */
	sLocalBalanceMsat: bigint;
	rLocalBalanceMsat: bigint;
	sChannelReserveSat: bigint;
	rChannelReserveSat: bigint;
	sIsFunder: boolean;
	anchors: boolean;
}

/**
 * Every requirement on the book (sections 7.1, 7.2, 7.5.3, 7.6, 8, 9.5.1),
 * checked at ff_accept and rechecked at ff_activate. Returns the first
 * failing requirement as a message, or null.
 */
export function checkVoucherBook(
	params: IFforEpochParams,
	ctx: IFforBookCheckContext
): string | null {
	const amounts = params.voucherAmountsMsat;
	const K = params.maxPayments;
	if (params.variant !== FforVariant.D) {
		return `variant ${params.variant} is not Variant D`;
	}
	if (params.escapeGranularityMsat !== 0n) {
		return 'escape_granularity_msat must be 0 in Variant D';
	}
	if (params.rPerCommitmentPoints.length !== 0) {
		return 'r_per_commitment_points must be empty in Variant D';
	}
	if (K === 0) return 'max_payments must be at least 1';
	if (amounts.length !== K) {
		return `TLV 9 carries ${amounts.length} amounts, max_payments is ${K}`;
	}
	if (K > FF_MAX_K) return `K = ${K} exceeds ${FF_MAX_K}`;
	if (K > ctx.rMaxAcceptedHtlcs) {
		return `K = ${K} exceeds R's max_accepted_htlcs ${ctx.rMaxAcceptedHtlcs}`;
	}
	let sum = 0n;
	for (let i = 0; i < amounts.length; i++) {
		const d = amounts[i];
		const k = i + 1;
		if (d < params.minPaymentMsat) {
			return `d_${k} = ${d} below min_payment_msat ${params.minPaymentMsat}`;
		}
		if (d < ctx.htlcMinimumMsat) {
			return `d_${k} = ${d} below htlc_minimum_msat ${ctx.htlcMinimumMsat}`;
		}
		if (d / 1000n < ctx.dustLimitSatoshis) {
			return `d_${k} = ${d} would trim (dust limit ${ctx.dustLimitSatoshis} sat)`;
		}
		if (d * BigInt(params.feeProportionalMillionths) > U64_MAX) {
			return `d_${k} * fee_proportional_millionths overflows u64`;
		}
		if (
			grossIntoS(d, params.feeBaseMsat, params.feeProportionalMillionths) >
			U64_MAX
		) {
			return `gross_into_S(d_${k}) overflows u64`;
		}
		sum += d;
	}
	if (sum !== params.budgetMsat) {
		return `sum of d_k ${sum} != budget_msat ${params.budgetMsat}`;
	}
	if (sum > ctx.rMaxHtlcValueInFlightMsat) {
		return `sum of d_k ${sum} exceeds R's max_htlc_value_in_flight_msat`;
	}
	if (
		params.voucherExpiry <
		params.settlementDeadline + FF_RECONCILE_MARGIN_BLOCKS
	) {
		return `voucher_expiry ${params.voucherExpiry} < settlement_deadline ${params.settlementDeadline} + ${FF_RECONCILE_MARGIN_BLOCKS}`;
	}
	// S holds budget + its reserve spendable.
	if (ctx.sLocalBalanceMsat < sum + ctx.sChannelReserveSat * 1000n) {
		return 'S cannot cover budget_msat plus its channel reserve';
	}
	// The funder covers fee(K) + anchors at the frozen rate, and the
	// fee-spike buffer at twice the rate, above its own reserve.
	const anchors = ctx.anchors ? ANCHOR_TOTAL_SAT : 0n;
	const feeFrozen = calculateCommitmentFee(
		ctx.feeratePerKw,
		K,
		ctx.anchors,
		false
	);
	const feeSpike = calculateCommitmentFee(
		2 * ctx.feeratePerKw,
		K,
		ctx.anchors,
		false
	);
	const sAfterMsat = ctx.sLocalBalanceMsat - sum;
	const funderAfterSat =
		(ctx.sIsFunder ? sAfterMsat : ctx.rLocalBalanceMsat) / 1000n;
	const funderReserve = ctx.sIsFunder
		? ctx.sChannelReserveSat
		: ctx.rChannelReserveSat;
	if (funderAfterSat - funderReserve < feeFrozen + anchors) {
		return 'funder cannot cover the commitment fee for K vouchers plus anchors';
	}
	if (funderAfterSat - funderReserve < feeSpike + anchors) {
		return 'funder cannot cover the fee-spike buffer (twice the frozen feerate)';
	}
	const sPostSat =
		sAfterMsat / 1000n - (ctx.sIsFunder ? feeFrozen + anchors : 0n);
	const rPostSat =
		ctx.rLocalBalanceMsat / 1000n - (ctx.sIsFunder ? 0n : feeFrozen + anchors);
	if (sPostSat < ctx.sChannelReserveSat) {
		return 'S post-round balance below its channel reserve';
	}
	// Section 8 reads "both parties' post-update balances >= their
	// respective channel_reserve". BOLT 2 binds only the side whose balance
	// the update lowers, and R's balance moves only when R is the funder
	// (the per-voucher commitment weight fee): an S-funded channel where R
	// holds nothing yet must still be able to carry vouchers.
	if (!ctx.sIsFunder && rPostSat < ctx.rChannelReserveSat) {
		return 'R post-round balance below its channel reserve';
	}
	return null;
}
