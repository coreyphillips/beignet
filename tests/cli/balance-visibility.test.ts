/**
 * Balance visibility — pending-close vs errored channel funds.
 *
 * - pendingCloseBalanceSats counts only channels still resolving a close
 *   (FORCE_CLOSED / SHUTTING_DOWN / NEGOTIATING_CLOSING) — never CLOSED.
 * - erroredBalanceSats surfaces local balance stuck in ERRORED channels,
 *   which is counted in no other figure.
 * - recoverFallbackFunds is exposed on BeignetNode.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { ChannelState } from '../../src/lightning/channel/types';

type FakeChannel = { state: ChannelState; localBalanceMsat: bigint };

function fakeNode(channels: FakeChannel[]): {
	node: { listChannels: () => FakeChannel[] };
} {
	return { node: { listChannels: () => channels } };
}

function pendingCloseSats(channels: FakeChannel[]): number {
	return (BeignetNode.prototype as any).getPendingCloseBalanceSats.call(
		fakeNode(channels)
	);
}

function erroredSats(channels: FakeChannel[]): number {
	return (BeignetNode.prototype as any).getErroredBalanceSats.call(
		fakeNode(channels)
	);
}

describe('Balance visibility (pending close / errored)', () => {
	it('pendingCloseBalanceSats sums closing-state channels only', () => {
		const sats = pendingCloseSats([
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 20_000_000n },
			{ state: ChannelState.SHUTTING_DOWN, localBalanceMsat: 5_000_000n },
			{ state: ChannelState.NEGOTIATING_CLOSING, localBalanceMsat: 3_000_000n },
			{ state: ChannelState.NORMAL, localBalanceMsat: 100_000_000n }
		]);
		expect(sats).to.equal(28_000);
	});

	it('pendingCloseBalanceSats excludes CLOSED (resolved) channels', () => {
		const sats = pendingCloseSats([
			{ state: ChannelState.CLOSED, localBalanceMsat: 20_000_000n },
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 7_000_000n }
		]);
		expect(sats).to.equal(7_000);
	});

	it('pendingCloseBalanceSats excludes ERRORED channels', () => {
		const sats = pendingCloseSats([
			{ state: ChannelState.ERRORED, localBalanceMsat: 22_000_000n }
		]);
		expect(sats).to.equal(0);
	});

	it('erroredBalanceSats sums only ERRORED channels', () => {
		const sats = erroredSats([
			{ state: ChannelState.ERRORED, localBalanceMsat: 22_000_000n },
			{ state: ChannelState.ERRORED, localBalanceMsat: 1_500_000n },
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 9_000_000n },
			{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n }
		]);
		expect(sats).to.equal(23_500);
	});

	it('erroredBalanceSats is 0 with no errored channels', () => {
		expect(
			erroredSats([
				{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n },
				{ state: ChannelState.CLOSED, localBalanceMsat: 10_000_000n }
			])
		).to.equal(0);
	});

	it('BeignetNode exposes recoverFallbackFunds()', () => {
		expect(typeof BeignetNode.prototype.recoverFallbackFunds).to.equal(
			'function'
		);
	});
});
