import { calculateCommitmentFee } from './commitment-builder';
import { v2ReserveWeEnforce, v2ReserveWeKeep } from './htlc-policy';
import { ANCHOR_TOTAL_COST } from '../script/anchor';
import type {
	IFinalBalances,
	IFinalOpeningTerms
} from './final-opening-commitment';

type Policy = Pick<
	IFinalOpeningTerms,
	| 'localDustLimitSatoshis'
	| 'remoteDustLimitSatoshis'
	| 'commitmentFeeratePerKw'
>;
type Amounts = ReadonlyArray<{ amountMsat: bigint }>;

export function finalFundingReserveSats(
	capacity: bigint,
	terms: Policy,
	local: boolean
): bigint {
	const reserve = local ? v2ReserveWeKeep : v2ReserveWeEnforce;
	return reserve(
		capacity,
		BigInt(terms.localDustLimitSatoshis),
		BigInt(terms.remoteDustLimitSatoshis)
	);
}

/** Price the more expensive commitment: its holder trims at the lower dust limit. */
export function finalFunderCostMsat(
	terms: Policy,
	htlcs: Amounts,
	additionalUntrimmed = 0
): bigint {
	const dust =
		BigInt(
			Math.min(terms.localDustLimitSatoshis, terms.remoteDustLimitSatoshis)
		) * 1000n;
	const count =
		htlcs.filter((h) => h.amountMsat >= dust).length + additionalUntrimmed;
	return (
		(calculateCommitmentFee(terms.commitmentFeeratePerKw, count, true, true) +
			ANCHOR_TOTAL_COST) *
		1000n
	);
}

export function validateFinalSpliceReserves(
	capacity: bigint,
	terms: Policy,
	balances: IFinalBalances,
	htlcs: Amounts,
	localIsOpener: boolean,
	outputOwners: readonly [boolean, boolean]
): void {
	const cost = finalFunderCostMsat(terms, htlcs);
	for (const local of [true, false]) {
		const balance = local
			? balances.localBalanceMsat
			: balances.remoteBalanceMsat;
		const afterFees = balance - (local === localIsOpener ? cost : 0n);
		const floor = outputOwners[local ? 0 : 1]
			? finalFundingReserveSats(capacity, terms, local) * 1000n
			: 0n;
		if (afterFees < floor)
			throw new Error(
				'Splice breaches the channel reserve or commitment fee budget'
			);
	}
}

/** Largest total splice withdrawal, including its funding fee, while keeping the reserve at the resulting capacity. */
export function finalSpliceWithdrawalSats(
	capacity: bigint,
	terms: Policy,
	localMsat: bigint,
	htlcs: Amounts,
	localIsOpener: boolean
): bigint {
	const free =
		(localMsat - (localIsOpener ? finalFunderCostMsat(terms, htlcs) : 0n)) /
		1000n;
	let lower = 0n;
	let upper = free;
	while (lower < upper) {
		const withdrawal = (lower + upper + 1n) / 2n;
		if (
			free - withdrawal >=
			finalFundingReserveSats(capacity - withdrawal, terms, true)
		)
			lower = withdrawal;
		else upper = withdrawal - 1n;
	}
	return lower;
}
