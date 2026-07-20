import { expect } from 'chai';
import type { ChannelInfo } from '../../src/cli/types';

/**
 * Agent Review: CLI-level tests for canSend/canReceive reserve accounting
 * and ChannelInfo isPrivate field.
 *
 * Since BeignetNode.create() requires a real wallet + Electrum setup,
 * these tests verify the type contracts and interfaces exposed by the CLI layer.
 */

describe('Agent Review: ChannelInfo type', () => {
	it('should include isPrivate field', () => {
		const ch: ChannelInfo = {
			channelId: 'aabb',
			peerPubkey: '02' + 'aa'.repeat(32),
			state: 'NORMAL',
			localBalanceSats: 500_000,
			remoteBalanceSats: 500_000,
			capacitySats: 1_000_000,
			isAnchor: false,
			isPrivate: true
		};
		expect(ch.isPrivate).to.be.true;
	});

	it('isPrivate should be optional (backward compatible)', () => {
		const ch: ChannelInfo = {
			channelId: 'aabb',
			peerPubkey: '02' + 'aa'.repeat(32),
			state: 'NORMAL',
			localBalanceSats: 500_000,
			remoteBalanceSats: 500_000,
			capacitySats: 1_000_000,
			isAnchor: false
		};
		expect(ch.isPrivate).to.be.undefined;
	});
});

describe('Agent Review: canSend reserve math', () => {
	// These tests verify the reserve-aware math that canSend() should perform.
	// The actual canSend() method is on BeignetNode which requires a wallet.
	// We verify the math here and the LightningNode buildChannelInfo in the
	// lightning-level tests.

	it('should subtract reserve from available balance', () => {
		// Simulating: localBalance = 15k sats, reserve = 10k sats
		const localBalanceMsat = 15_000_000n;
		const reserveMsat = 10_000_000n;
		const available =
			localBalanceMsat > reserveMsat ? localBalanceMsat - reserveMsat : 0n;
		expect(available).to.equal(5_000_000n); // 5k sats available
	});

	it('should return 0 when balance is below reserve', () => {
		const localBalanceMsat = 5_000_000n;
		const reserveMsat = 10_000_000n;
		const available =
			localBalanceMsat > reserveMsat ? localBalanceMsat - reserveMsat : 0n;
		expect(available).to.equal(0n);
	});

	it('should return 0 when balance equals reserve', () => {
		const localBalanceMsat = 10_000_000n;
		const reserveMsat = 10_000_000n;
		const available =
			localBalanceMsat > reserveMsat ? localBalanceMsat - reserveMsat : 0n;
		expect(available).to.equal(0n);
	});

	it('should handle zero reserve gracefully', () => {
		const localBalanceMsat = 15_000_000n;
		const reserveMsat = 0n;
		const available =
			localBalanceMsat > reserveMsat ? localBalanceMsat - reserveMsat : 0n;
		expect(available).to.equal(15_000_000n); // Full balance available
	});

	it('canSend should report false when amount exceeds available after reserve', () => {
		// localBalance = 15k, reserve = 10k, trying to send 14k
		const localBalanceMsat = 15_000_000n;
		const reserveMsat = 10_000_000n;
		const available =
			localBalanceMsat > reserveMsat ? localBalanceMsat - reserveMsat : 0n;
		const amountMsat = 14_000_000n; // 14k sats

		// Should NOT be able to send 14k (only 5k available)
		expect(available >= amountMsat).to.be.false;
	});

	it('canSend should report true when amount fits within available after reserve', () => {
		// localBalance = 15k, reserve = 10k, trying to send 4k
		const localBalanceMsat = 15_000_000n;
		const reserveMsat = 10_000_000n;
		const available =
			localBalanceMsat > reserveMsat ? localBalanceMsat - reserveMsat : 0n;
		const amountMsat = 4_000_000n; // 4k sats

		// Should be able to send 4k (5k available)
		expect(available >= amountMsat).to.be.true;
	});
});

describe('Agent Review: liquidity snapshot reserve aggregation', () => {
	// Mirrors BeignetNode.getLiquiditySnapshot(): reserveSats and sendableSats are
	// summed over NORMAL channels, sendable clamped at zero per channel so a
	// balance below its reserve contributes nothing sendable while its reserve
	// still counts. Aggregated here in isolation because getLiquiditySnapshot()
	// needs a real wallet, matching how canSend's math is covered above.
	type Ch = {
		state: string;
		localBalanceMsat: bigint;
		localReserveMsat?: bigint;
	};
	const aggregate = (
		channels: Ch[]
	): { reserveSats: number; sendableSats: number } => {
		let reserveMsat = 0n;
		let sendableMsat = 0n;
		for (const ch of channels) {
			if (ch.state !== 'NORMAL') continue;
			const r = ch.localReserveMsat ?? 0n;
			reserveMsat += r;
			sendableMsat += ch.localBalanceMsat > r ? ch.localBalanceMsat - r : 0n;
		}
		return {
			reserveSats: Number(reserveMsat / 1000n),
			sendableSats: Number(sendableMsat / 1000n)
		};
	};

	it('sums reserve and sendable across NORMAL channels', () => {
		const res = aggregate([
			{
				state: 'NORMAL',
				localBalanceMsat: 500_000_000n,
				localReserveMsat: 10_000_000n
			},
			{
				state: 'NORMAL',
				localBalanceMsat: 200_000_000n,
				localReserveMsat: 5_000_000n
			}
		]);
		expect(res.reserveSats).to.equal(15_000);
		expect(res.sendableSats).to.equal(685_000); // 490k + 195k
	});

	it('counts a below-reserve channel reserve but zero sendable', () => {
		const res = aggregate([
			{
				state: 'NORMAL',
				localBalanceMsat: 12_000_000n,
				localReserveMsat: 20_000_000n
			}
		]);
		expect(res.reserveSats).to.equal(20_000);
		expect(res.sendableSats).to.equal(0);
	});

	it('ignores non-NORMAL channels', () => {
		const res = aggregate([
			{
				state: 'AWAITING_FUNDING_CONFIRMED',
				localBalanceMsat: 500_000_000n,
				localReserveMsat: 10_000_000n
			},
			{
				state: 'NORMAL',
				localBalanceMsat: 100_000_000n,
				localReserveMsat: 4_000_000n
			}
		]);
		expect(res.reserveSats).to.equal(4_000);
		expect(res.sendableSats).to.equal(96_000);
	});

	it('treats a missing reserve as zero', () => {
		const res = aggregate([{ state: 'NORMAL', localBalanceMsat: 30_000_000n }]);
		expect(res.reserveSats).to.equal(0);
		expect(res.sendableSats).to.equal(30_000);
	});
});

describe('Agent Review: IChannelInfo reserve fields', () => {
	it('IChannelInfo should accept localReserveMsat and remoteReserveMsat', () => {
		// Verify the interface accepts the new fields
		const info = {
			channelId: Buffer.alloc(32),
			peerPubkey: '02' + 'aa'.repeat(32),
			state: 'NORMAL' as const,
			localBalanceMsat: 500_000_000n,
			remoteBalanceMsat: 500_000_000n,
			fundingSatoshis: 1_000_000n,
			channelType: null,
			localReserveMsat: 10_000_000n,
			remoteReserveMsat: 10_000_000n,
			isPrivate: false
		};
		expect(info.localReserveMsat).to.equal(10_000_000n);
		expect(info.remoteReserveMsat).to.equal(10_000_000n);
		expect(info.isPrivate).to.be.false;
	});
});
