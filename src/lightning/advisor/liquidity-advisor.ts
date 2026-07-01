/**
 * LiquidityAdvisor: Analyzes channel liquidity and generates recommendations.
 * Pure analysis class -- no side effects, no network calls.
 */

import { ILeaseRates } from '../gossip/types';
import { computeLeaseFeeSat } from '../channel/liquidity-ads';

export enum RecommendationType {
	OPEN_CHANNEL = 'OPEN_CHANNEL',
	CLOSE_CHANNEL = 'CLOSE_CHANNEL',
	REBALANCE_NEEDED = 'REBALANCE_NEEDED',
	/** Buy inbound liquidity via a liquidity-ads lease (bLIP-0051). */
	BUY_LEASE = 'BUY_LEASE'
}

export enum RecommendationPriority {
	CRITICAL = 'CRITICAL',
	HIGH = 'HIGH',
	MEDIUM = 'MEDIUM',
	LOW = 'LOW',
	INFO = 'INFO'
}

export interface ILiquidityRecommendation {
	type: RecommendationType;
	priority: RecommendationPriority;
	reason: string;
	channelId?: string;
}

export interface IChannelSnapshot {
	channelId: string;
	state: string;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	capacitySats: number;
	peerPubkey: string;
	/** Number of blocks the channel has been stuck in AWAITING_REESTABLISH (optional) */
	stuckBlocks?: number;
	/** Timestamp of last activity on this channel (optional) */
	lastActivityAt?: number;
}

export interface ILiquiditySnapshot {
	totalLocalBalanceSats: number;
	totalRemoteBalanceSats: number;
	totalCapacitySats: number;
	channelCount: number;
	activeChannelCount: number;
	outboundLiquidityPct: number;
	inboundLiquidityPct: number;
	recommendations: ILiquidityRecommendation[];
}

export class LiquidityAdvisor {
	/**
	 * Analyze channels and produce a liquidity snapshot with recommendations.
	 */
	analyze(channels: IChannelSnapshot[]): ILiquiditySnapshot {
		let totalLocalMsat = 0n;
		let totalRemoteMsat = 0n;
		let totalCapacitySats = 0;
		let activeCount = 0;
		const recommendations: ILiquidityRecommendation[] = [];

		const activeChannels = channels.filter((ch) => ch.state === 'NORMAL');
		activeCount = activeChannels.length;

		for (const ch of activeChannels) {
			totalLocalMsat += ch.localBalanceMsat;
			totalRemoteMsat += ch.remoteBalanceMsat;
			totalCapacitySats += ch.capacitySats;
		}

		const totalLocalSats = Number(totalLocalMsat / 1000n);
		const totalRemoteSats = Number(totalRemoteMsat / 1000n);
		const totalSats = totalLocalSats + totalRemoteSats;
		const outboundPct =
			totalSats > 0 ? Math.round((totalLocalSats / totalSats) * 100) : 0;
		const inboundPct =
			totalSats > 0 ? Math.round((totalRemoteSats / totalSats) * 100) : 0;

		// Rule 1: No active channels -> OPEN_CHANNEL (CRITICAL)
		if (activeCount === 0 && channels.length === 0) {
			recommendations.push({
				type: RecommendationType.OPEN_CHANNEL,
				priority: RecommendationPriority.CRITICAL,
				reason:
					'No channels exist. Open a channel to send and receive payments.'
			});
		} else if (activeCount === 0 && channels.length > 0) {
			recommendations.push({
				type: RecommendationType.OPEN_CHANNEL,
				priority: RecommendationPriority.CRITICAL,
				reason:
					'No active channels. All channels are in non-operational states.'
			});
		}

		// Rule 2: All channels <10% local balance -> OPEN_CHANNEL (HIGH)
		if (activeCount > 0) {
			const allLowOutbound = activeChannels.every((ch) => {
				const cap = ch.capacitySats > 0 ? ch.capacitySats : 1;
				return Number(ch.localBalanceMsat / 1000n) / cap < 0.1;
			});
			if (allLowOutbound) {
				recommendations.push({
					type: RecommendationType.OPEN_CHANNEL,
					priority: RecommendationPriority.HIGH,
					reason:
						'All channels have less than 10% outbound capacity. Open a new channel for sending.'
				});
			}

			// Rule 3: All channels <10% remote balance -> REBALANCE_NEEDED (MEDIUM)
			const allLowInbound = activeChannels.every((ch) => {
				const cap = ch.capacitySats > 0 ? ch.capacitySats : 1;
				return Number(ch.remoteBalanceMsat / 1000n) / cap < 0.1;
			});
			if (allLowInbound) {
				recommendations.push({
					type: RecommendationType.REBALANCE_NEEDED,
					priority: RecommendationPriority.MEDIUM,
					reason:
						'All channels have less than 10% inbound capacity. Spending or circular rebalancing needed.'
				});
				recommendations.push({
					type: RecommendationType.BUY_LEASE,
					priority: RecommendationPriority.MEDIUM,
					reason:
						'Inbound capacity is critically low. Consider buying inbound liquidity via a liquidity-ads lease (bLIP-0051).'
				});
			}

			// Rule 5: Outbound:inbound ratio > 5:1 -> OPEN_CHANNEL (MEDIUM)
			if (totalRemoteSats > 0 && totalLocalSats / totalRemoteSats >= 5) {
				recommendations.push({
					type: RecommendationType.OPEN_CHANNEL,
					priority: RecommendationPriority.MEDIUM,
					reason:
						'Outbound to inbound ratio exceeds 5:1. Consider opening a channel where peer pushes balance.'
				});
			}
		}

		// Rule 4: Channel stuck in AWAITING_REESTABLISH >100 blocks -> CLOSE_CHANNEL (HIGH)
		for (const ch of channels) {
			if (
				ch.state === 'AWAITING_REESTABLISH' &&
				ch.stuckBlocks !== undefined &&
				ch.stuckBlocks > 100
			) {
				recommendations.push({
					type: RecommendationType.CLOSE_CHANNEL,
					priority: RecommendationPriority.HIGH,
					reason: `Channel has been stuck in AWAITING_REESTABLISH for ${ch.stuckBlocks} blocks. Consider force-closing.`,
					channelId: ch.channelId
				});
			}
		}

		// Rule 6: Channel near-empty + idle >24h -> CLOSE_CHANNEL (LOW)
		const now = Date.now();
		const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000;
		for (const ch of activeChannels) {
			const localPct =
				ch.capacitySats > 0
					? Number(ch.localBalanceMsat / 1000n) / ch.capacitySats
					: 0;
			const remotePct =
				ch.capacitySats > 0
					? Number(ch.remoteBalanceMsat / 1000n) / ch.capacitySats
					: 0;
			const nearEmpty = localPct < 0.02 && remotePct < 0.02;
			const idle =
				ch.lastActivityAt !== undefined &&
				now - ch.lastActivityAt > TWENTY_FOUR_HOURS;
			if (nearEmpty && idle) {
				recommendations.push({
					type: RecommendationType.CLOSE_CHANNEL,
					priority: RecommendationPriority.LOW,
					reason:
						'Channel is nearly empty and has been idle for over 24 hours.',
					channelId: ch.channelId
				});
			}
		}

		return {
			totalLocalBalanceSats: totalLocalSats,
			totalRemoteBalanceSats: totalRemoteSats,
			totalCapacitySats,
			channelCount: channels.length,
			activeChannelCount: activeCount,
			outboundLiquidityPct: outboundPct,
			inboundLiquidityPct: inboundPct,
			recommendations
		};
	}

	// ─────────────── Liquidity Ads (bLIP-0051) ───────────────

	/**
	 * Buyer: score a set of sellers' advertised lease rates for the inbound
	 * liquidity needed, cheapest total fee first. Lets an agent pick whom to lease
	 * from (and whether any quote is acceptable vs maxFeeSats).
	 */
	quoteLeases(
		offers: ILeaseOffer[],
		requestedSats: bigint,
		fundingFeeratePerkw: number
	): ILeaseQuote[] {
		return offers
			.map((offer) => {
				const feeSats = computeLeaseFeeSat(
					offer.leaseRates,
					requestedSats,
					fundingFeeratePerkw
				);
				// Effective fee as a fraction of the leased amount (for comparison).
				const feeRatePct =
					requestedSats > 0n ? Number(feeSats) / Number(requestedSats) : 0;
				return { offer, requestedSats, feeSats, feeRatePct };
			})
			.sort((a, b) => Number(a.feeSats - b.feeSats));
	}

	/**
	 * Seller: suggest lease rates to advertise, given available outbound liquidity
	 * to lease and the current funding feerate. Conservative defaults — price the
	 * mining-fee share via funding_weight, a flat base fee, and a small
	 * proportional fee; cap routing fees the lease permits.
	 */
	suggestLeaseRates(opts: {
		/** Base flat lease fee in satoshis. */
		leaseFeeBaseSat?: number;
		/** Proportional fee in 1/10_000 of the leased amount. */
		leaseFeeBasis?: number;
		/** Witness weight of the seller's funding input (~weight units). */
		fundingWeightWitness?: number;
	} = {}): ILeaseRates {
		return {
			fundingWeightWitness: opts.fundingWeightWitness ?? 666,
			leaseFeeBasis: opts.leaseFeeBasis ?? 40, // 0.4%
			leaseFeeBaseSat: opts.leaseFeeBaseSat ?? 500,
			channelFeeMaxBaseMsat: 5000,
			channelFeeMaxProportionalThousandths: 10
		};
	}
}

/** A seller's advertised lease offer (from node_announcement lease rates). */
export interface ILeaseOffer {
	sellerNodeId: string;
	leaseRates: ILeaseRates;
}

/** A scored lease quote for the buyer. */
export interface ILeaseQuote {
	offer: ILeaseOffer;
	requestedSats: bigint;
	feeSats: bigint;
	/** Fee as a fraction of the leased amount (0.01 = 1%). */
	feeRatePct: number;
}
