/**
 * Swap exposure policy (issue #737, phase 2): the operator's caps on what a
 * provider will put at risk, evaluated against the ledger's live records.
 *
 * The balance check is optional because IFundingProvider exposes no balance;
 * an engine that can quote spendable funds (quoteSpliceIn's spendableSats,
 * or the wallet directly) passes it in, and the policy then also keeps the
 * configured fee reserve untouched. Without a balance the other caps still
 * hold and the wallet's own coin selection is the last line.
 */

import { ISwapRecord, SwapDirection, isSwapExposure } from './ledger';

export interface ISwapExposurePolicy {
	minSwapSat: bigint;
	maxSwapSat: bigint;
	/** Sum of principal at risk across every unresolved swap. */
	maxTotalExposureSat: bigint;
	/**
	 * Swaps whose principal is at risk at once (isSwapExposure). An unpaid
	 * create does not count: any peer can make one for free.
	 */
	maxConcurrentSwaps: number;
	/** Wallet balance that must remain after funding, when a balance is known. */
	feeReserveSat: bigint;
	/** Refuse to fund above this rate rather than pay whatever the estimator says. */
	fundingFeeRateCeilingSatPerVbyte: number;
}

export interface ISwapExposureInput {
	direction: SwapDirection;
	amountSat: bigint;
	/** Miner fee the funding transaction is expected to pay (reverse). */
	estimatedFundingFeeSat?: bigint;
	feeRateSatPerVbyte?: number;
	/** ledger.atRisk(), or any set of rows that holds it. */
	live: readonly ISwapRecord[];
	/**
	 * The provider's resolution depth: an exposed row stops counting only
	 * once its resolution, verified this session, reached it (default 1).
	 */
	resolutionConfirmations?: number;
	availableBalanceSat?: bigint;
}

export type SwapExposureRefusal =
	| 'below-min'
	| 'above-max'
	| 'exposure'
	| 'concurrency'
	| 'fee-rate'
	| 'insufficient-balance';

export type SwapAdmissionVerdict =
	| { ok: true; reservedSat: bigint }
	| { ok: false; reason: SwapExposureRefusal; detail: string };

export function validateSwapExposurePolicy(policy: ISwapExposurePolicy): void {
	const sats: Array<[string, bigint]> = [
		['minSwapSat', policy.minSwapSat],
		['maxSwapSat', policy.maxSwapSat],
		['maxTotalExposureSat', policy.maxTotalExposureSat],
		['feeReserveSat', policy.feeReserveSat]
	];
	for (const [name, value] of sats) {
		if (typeof value !== 'bigint' || value < 0n) {
			throw new Error(`${name} must be a non-negative bigint`);
		}
	}
	if (policy.minSwapSat <= 0n) throw new Error('minSwapSat must be positive');
	if (policy.maxSwapSat < policy.minSwapSat) {
		throw new Error('maxSwapSat must be at least minSwapSat');
	}
	if (policy.maxTotalExposureSat < policy.maxSwapSat) {
		throw new Error('maxTotalExposureSat must be at least maxSwapSat');
	}
	if (
		!Number.isSafeInteger(policy.maxConcurrentSwaps) ||
		policy.maxConcurrentSwaps < 1
	) {
		throw new Error('maxConcurrentSwaps must be a positive integer');
	}
	if (
		!Number.isFinite(policy.fundingFeeRateCeilingSatPerVbyte) ||
		policy.fundingFeeRateCeilingSatPerVbyte <= 0
	) {
		throw new Error('fundingFeeRateCeilingSatPerVbyte must be positive');
	}
}

/**
 * Admission against the caps. Only rows whose principal is at risk
 * (isSwapExposure) count toward concurrency and exposure; the candidate
 * itself is added to both. The engines judge again right before the step
 * that commits the provider (a reverse hold admitted, a submarine payment
 * dispatched), which is where the cap actually binds.
 */
export function evaluateSwapExposure(
	policy: ISwapExposurePolicy,
	input: ISwapExposureInput
): SwapAdmissionVerdict {
	validateSwapExposurePolicy(policy);
	const { amountSat } = input;
	if (typeof amountSat !== 'bigint' || amountSat < policy.minSwapSat) {
		return {
			ok: false,
			reason: 'below-min',
			detail: `${amountSat} sat is below the ${policy.minSwapSat} sat minimum`
		};
	}
	if (amountSat > policy.maxSwapSat) {
		return {
			ok: false,
			reason: 'above-max',
			detail: `${amountSat} sat is above the ${policy.maxSwapSat} sat maximum`
		};
	}
	if (
		input.feeRateSatPerVbyte !== undefined &&
		input.feeRateSatPerVbyte > policy.fundingFeeRateCeilingSatPerVbyte
	) {
		return {
			ok: false,
			reason: 'fee-rate',
			detail: `${input.feeRateSatPerVbyte} sat/vB exceeds the ${policy.fundingFeeRateCeilingSatPerVbyte} sat/vB ceiling`
		};
	}
	let exposedCount = 0;
	let exposedSat = 0n;
	for (const r of input.live) {
		if (isSwapExposure(r, input.resolutionConfirmations ?? 1)) {
			exposedCount++;
			exposedSat += BigInt(r.onchainSat);
		}
	}
	if (exposedCount + 1 > policy.maxConcurrentSwaps) {
		return {
			ok: false,
			reason: 'concurrency',
			detail: `${exposedCount} swaps at risk already, limit ${policy.maxConcurrentSwaps}`
		};
	}
	if (exposedSat + amountSat > policy.maxTotalExposureSat) {
		return {
			ok: false,
			reason: 'exposure',
			detail: `${exposedSat} sat already at risk plus ${amountSat} exceeds ${policy.maxTotalExposureSat}`
		};
	}
	const fee = input.estimatedFundingFeeSat ?? 0n;
	if (input.availableBalanceSat !== undefined) {
		const remaining = input.availableBalanceSat - amountSat - fee;
		if (remaining < policy.feeReserveSat) {
			return {
				ok: false,
				reason: 'insufficient-balance',
				detail: `${input.availableBalanceSat} sat available leaves ${remaining} after ${amountSat} + ${fee} fee, below the ${policy.feeReserveSat} sat reserve`
			};
		}
	}
	return { ok: true, reservedSat: amountSat + fee };
}
