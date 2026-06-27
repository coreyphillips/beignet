import { expect } from 'chai';
import {
	LiquidityAdvisor,
	RecommendationType,
	RecommendationPriority,
	IChannelSnapshot
} from '../../src/lightning/advisor/liquidity-advisor';

describe('LiquidityAdvisor', () => {
	let advisor: LiquidityAdvisor;

	beforeEach(() => {
		advisor = new LiquidityAdvisor();
	});

	function makeChannel(
		overrides: Partial<IChannelSnapshot> = {}
	): IChannelSnapshot {
		return {
			channelId: 'abc123',
			state: 'NORMAL',
			localBalanceMsat: 500_000_000n, // 500k sats
			remoteBalanceMsat: 500_000_000n,
			capacitySats: 1_000_000,
			peerPubkey: '02' + 'aa'.repeat(32),
			...overrides
		};
	}

	it('returns snapshot with correct balance totals', () => {
		const result = advisor.analyze([makeChannel()]);
		expect(result.totalLocalBalanceSats).to.equal(500_000);
		expect(result.totalRemoteBalanceSats).to.equal(500_000);
		expect(result.totalCapacitySats).to.equal(1_000_000);
	});

	it('returns correct channel counts', () => {
		const channels = [
			makeChannel({ channelId: 'ch1' }),
			makeChannel({ channelId: 'ch2', state: 'AWAITING_FUNDING_CONFIRMED' }),
			makeChannel({ channelId: 'ch3' })
		];
		const result = advisor.analyze(channels);
		expect(result.channelCount).to.equal(3);
		expect(result.activeChannelCount).to.equal(2);
	});

	it('calculates outbound/inbound percentages correctly', () => {
		const result = advisor.analyze([
			makeChannel({
				localBalanceMsat: 750_000_000n, // 750k sats
				remoteBalanceMsat: 250_000_000n // 250k sats
			})
		]);
		expect(result.outboundLiquidityPct).to.equal(75);
		expect(result.inboundLiquidityPct).to.equal(25);
	});

	it('with no channels returns CRITICAL OPEN_CHANNEL recommendation', () => {
		const result = advisor.analyze([]);
		expect(result.recommendations).to.have.lengthOf(1);
		expect(result.recommendations[0].type).to.equal(
			RecommendationType.OPEN_CHANNEL
		);
		expect(result.recommendations[0].priority).to.equal(
			RecommendationPriority.CRITICAL
		);
		expect(result.recommendations[0].reason).to.include('No channels exist');
	});

	it('with only non-NORMAL channels returns CRITICAL OPEN_CHANNEL', () => {
		const result = advisor.analyze([
			makeChannel({ channelId: 'ch1', state: 'AWAITING_FUNDING_CONFIRMED' }),
			makeChannel({ channelId: 'ch2', state: 'SHUTTING_DOWN' })
		]);
		expect(
			result.recommendations.some(
				(r) =>
					r.type === RecommendationType.OPEN_CHANNEL &&
					r.priority === RecommendationPriority.CRITICAL
			)
		).to.be.true;
		expect(result.recommendations[0].reason).to.include('non-operational');
	});

	it('when all channels have <10% local balance returns HIGH OPEN_CHANNEL', () => {
		const result = advisor.analyze([
			makeChannel({
				channelId: 'ch1',
				localBalanceMsat: 50_000_000n, // 50k sats = 5% of 1M
				remoteBalanceMsat: 950_000_000n
			}),
			makeChannel({
				channelId: 'ch2',
				localBalanceMsat: 80_000_000n, // 80k sats = 8% of 1M
				remoteBalanceMsat: 920_000_000n
			})
		]);
		expect(
			result.recommendations.some(
				(r) =>
					r.type === RecommendationType.OPEN_CHANNEL &&
					r.priority === RecommendationPriority.HIGH
			)
		).to.be.true;
	});

	it('when all channels have <10% remote balance returns MEDIUM REBALANCE_NEEDED', () => {
		const result = advisor.analyze([
			makeChannel({
				channelId: 'ch1',
				localBalanceMsat: 950_000_000n,
				remoteBalanceMsat: 50_000_000n // 5%
			}),
			makeChannel({
				channelId: 'ch2',
				localBalanceMsat: 920_000_000n,
				remoteBalanceMsat: 80_000_000n // 8%
			})
		]);
		expect(
			result.recommendations.some(
				(r) =>
					r.type === RecommendationType.REBALANCE_NEEDED &&
					r.priority === RecommendationPriority.MEDIUM
			)
		).to.be.true;
	});

	it('when outbound:inbound ratio > 5:1 returns MEDIUM OPEN_CHANNEL', () => {
		// Channel 1: 900k local, 100k remote -> but need to avoid low-inbound rule
		// Use two channels where ratio is >5:1 but not all have <10% remote
		const result = advisor.analyze([
			makeChannel({
				channelId: 'ch1',
				localBalanceMsat: 5_500_000_000n, // 5.5M sats
				remoteBalanceMsat: 500_000_000n, // 500k sats (not <10% of 6M cap)
				capacitySats: 6_000_000
			})
		]);
		// 5500k / 500k = 11:1 ratio
		expect(
			result.recommendations.some(
				(r) =>
					r.type === RecommendationType.OPEN_CHANNEL &&
					r.priority === RecommendationPriority.MEDIUM &&
					r.reason.includes('5:1')
			)
		).to.be.true;
	});

	it('with AWAITING_REESTABLISH channel stuck >100 blocks returns HIGH CLOSE_CHANNEL', () => {
		const result = advisor.analyze([
			makeChannel({
				channelId: 'stuck_ch',
				state: 'AWAITING_REESTABLISH',
				stuckBlocks: 150
			})
		]);
		expect(
			result.recommendations.some(
				(r) =>
					r.type === RecommendationType.CLOSE_CHANNEL &&
					r.priority === RecommendationPriority.HIGH &&
					r.channelId === 'stuck_ch'
			)
		).to.be.true;
	});

	it('with near-empty idle channel returns LOW CLOSE_CHANNEL', () => {
		const twoDaysAgo = Date.now() - 48 * 60 * 60 * 1000;
		const result = advisor.analyze([
			makeChannel({
				channelId: 'empty_ch',
				localBalanceMsat: 10_000n, // ~10 sats on 1M cap -> 0.001%
				remoteBalanceMsat: 10_000n,
				lastActivityAt: twoDaysAgo
			})
		]);
		expect(
			result.recommendations.some(
				(r) =>
					r.type === RecommendationType.CLOSE_CHANNEL &&
					r.priority === RecommendationPriority.LOW &&
					r.channelId === 'empty_ch'
			)
		).to.be.true;
	});

	it('with healthy channels returns no recommendations', () => {
		const result = advisor.analyze([
			makeChannel({
				channelId: 'ch1',
				localBalanceMsat: 500_000_000n,
				remoteBalanceMsat: 500_000_000n
			})
		]);
		expect(result.recommendations).to.have.lengthOf(0);
	});

	it('includes channelId for channel-specific recommendations', () => {
		const result = advisor.analyze([
			makeChannel({
				channelId: 'target_ch',
				state: 'AWAITING_REESTABLISH',
				stuckBlocks: 200
			})
		]);
		const rec = result.recommendations.find(
			(r) => r.type === RecommendationType.CLOSE_CHANNEL
		);
		expect(rec).to.exist;
		expect(rec!.channelId).to.equal('target_ch');
	});

	it('returns zero percentages when total is zero', () => {
		const result = advisor.analyze([]);
		expect(result.outboundLiquidityPct).to.equal(0);
		expect(result.inboundLiquidityPct).to.equal(0);
	});

	it('handles single channel correctly', () => {
		const result = advisor.analyze([
			makeChannel({
				localBalanceMsat: 300_000_000n,
				remoteBalanceMsat: 700_000_000n
			})
		]);
		expect(result.totalLocalBalanceSats).to.equal(300_000);
		expect(result.totalRemoteBalanceSats).to.equal(700_000);
		expect(result.channelCount).to.equal(1);
		expect(result.activeChannelCount).to.equal(1);
		expect(result.outboundLiquidityPct).to.equal(30);
		expect(result.inboundLiquidityPct).to.equal(70);
	});

	it('RecommendationType enum values are correct', () => {
		expect(RecommendationType.OPEN_CHANNEL).to.equal('OPEN_CHANNEL');
		expect(RecommendationType.CLOSE_CHANNEL).to.equal('CLOSE_CHANNEL');
		expect(RecommendationType.REBALANCE_NEEDED).to.equal('REBALANCE_NEEDED');
	});

	it('RecommendationPriority enum values are correct', () => {
		expect(RecommendationPriority.CRITICAL).to.equal('CRITICAL');
		expect(RecommendationPriority.HIGH).to.equal('HIGH');
		expect(RecommendationPriority.MEDIUM).to.equal('MEDIUM');
		expect(RecommendationPriority.LOW).to.equal('LOW');
		expect(RecommendationPriority.INFO).to.equal('INFO');
	});

	it('with mixed channel states counts only NORMAL as active', () => {
		const channels = [
			makeChannel({ channelId: 'ch1', state: 'NORMAL' }),
			makeChannel({ channelId: 'ch2', state: 'AWAITING_REESTABLISH' }),
			makeChannel({ channelId: 'ch3', state: 'FORCE_CLOSED' }),
			makeChannel({ channelId: 'ch4', state: 'NORMAL' }),
			makeChannel({ channelId: 'ch5', state: 'SHUTTING_DOWN' })
		];
		const result = advisor.analyze(channels);
		expect(result.channelCount).to.equal(5);
		expect(result.activeChannelCount).to.equal(2);
		// Only NORMAL channels contribute to balance totals
		expect(result.totalLocalBalanceSats).to.equal(1_000_000); // 2 * 500k
		expect(result.totalRemoteBalanceSats).to.equal(1_000_000);
	});

	it('combines multiple recommendations', () => {
		const twoDaysAgo = Date.now() - 48 * 60 * 60 * 1000;
		const channels = [
			// Near-empty idle NORMAL channel -> LOW CLOSE_CHANNEL
			makeChannel({
				channelId: 'empty_ch',
				localBalanceMsat: 5_000n,
				remoteBalanceMsat: 5_000n,
				lastActivityAt: twoDaysAgo
			}),
			// Stuck AWAITING_REESTABLISH channel -> HIGH CLOSE_CHANNEL
			makeChannel({
				channelId: 'stuck_ch',
				state: 'AWAITING_REESTABLISH',
				stuckBlocks: 200
			})
		];
		const result = advisor.analyze(channels);
		// Should have at least: LOW CLOSE_CHANNEL for empty_ch, HIGH CLOSE_CHANNEL for stuck_ch,
		// and possibly an OPEN_CHANNEL (HIGH) if the one active channel has <10% local balance
		const closeRecs = result.recommendations.filter(
			(r) => r.type === RecommendationType.CLOSE_CHANNEL
		);
		expect(closeRecs.length).to.be.at.least(2);
		expect(closeRecs.some((r) => r.channelId === 'empty_ch')).to.be.true;
		expect(closeRecs.some((r) => r.channelId === 'stuck_ch')).to.be.true;
	});
});
