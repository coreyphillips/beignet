/**
 * Rebalance planner: turns channel snapshots into concrete circular-rebalance
 * pairs. Pure and deterministic -- no side effects, no clock, no network.
 */

import { IChannelSnapshot } from './liquidity-advisor';

/** A concrete circular-rebalance instruction (execution decides fee caps). */
export interface IRebalancePlan {
	/** Channel to push liquidity OUT of (high local balance). */
	fromChannelId: string;
	/** Channel to pull liquidity IN on (low local balance). */
	toChannelId: string;
	amountSats: bigint;
	reason: string;
}

/** Below this amount a rebalance is not worth its fees. */
export const MIN_REBALANCE_SATS = 1_000n;

/** Default imbalance threshold: local balance under 20% (or over 80%). */
export const DEFAULT_MIN_IMBALANCE_PCT = 20;

/**
 * Pair saturated channels (donors, local balance above 100 - minImbalancePct
 * percent of capacity) with depleted ones (receivers, local balance below
 * minImbalancePct percent), moving each side toward 50%. Greedy over donors
 * sorted by most-saturated first and receivers by most-depleted first, with
 * channelId as the tiebreak so the plan is deterministic for a given snapshot.
 */
export function planRebalances(
	channels: IChannelSnapshot[],
	options?: { minImbalancePct?: number }
): IRebalancePlan[] {
	const minPct = options?.minImbalancePct ?? DEFAULT_MIN_IMBALANCE_PCT;

	interface ISide {
		channelId: string;
		localSats: bigint;
		halfSats: bigint;
		localPct: number;
	}
	const donors: ISide[] = [];
	const receivers: ISide[] = [];

	for (const ch of channels) {
		if (ch.state !== 'NORMAL' || ch.capacitySats <= 0) continue;
		const localSats = ch.localBalanceMsat / 1000n;
		const localPct = (Number(localSats) / ch.capacitySats) * 100;
		const side: ISide = {
			channelId: ch.channelId,
			localSats,
			halfSats: BigInt(Math.floor(ch.capacitySats / 2)),
			localPct
		};
		if (localPct >= 100 - minPct) donors.push(side);
		else if (localPct <= minPct) receivers.push(side);
	}

	donors.sort(
		(a, b) => b.localPct - a.localPct || a.channelId.localeCompare(b.channelId)
	);
	receivers.sort(
		(a, b) => a.localPct - b.localPct || a.channelId.localeCompare(b.channelId)
	);

	const plans: IRebalancePlan[] = [];
	let d = 0;
	let r = 0;
	while (d < donors.length && r < receivers.length) {
		const donor = donors[d];
		const receiver = receivers[r];
		// Move only what brings each side toward (not past) 50/50.
		const donorExcess = donor.localSats - donor.halfSats;
		const receiverDeficit = receiver.halfSats - receiver.localSats;
		const amountSats =
			donorExcess < receiverDeficit ? donorExcess : receiverDeficit;
		if (amountSats >= MIN_REBALANCE_SATS) {
			plans.push({
				fromChannelId: donor.channelId,
				toChannelId: receiver.channelId,
				amountSats,
				reason: `local balance ${donor.localPct.toFixed(
					0
				)}% on donor vs ${receiver.localPct.toFixed(0)}% on receiver`
			});
		}
		donor.localSats -= amountSats;
		receiver.localSats += amountSats;
		if (donor.localSats - donor.halfSats < MIN_REBALANCE_SATS) d++;
		if (receiver.halfSats - receiver.localSats < MIN_REBALANCE_SATS) r++;
	}

	return plans;
}
