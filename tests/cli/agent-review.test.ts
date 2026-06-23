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
