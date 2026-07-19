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

type FakeChannel = {
	state: ChannelState;
	localBalanceMsat: bigint;
	pendingSpliceLocalBalanceMsat?: bigint;
	htlcUsable?: boolean;
};

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

function splicingSats(channels: FakeChannel[]): number {
	return (BeignetNode.prototype as any).getSplicingBalanceSats.call(
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

	it('splicingBalanceSats reports the POST-splice balance for a splice-in', () => {
		// The scare this guards against, observed on mainnet: a max splice-in
		// sweeps the on-chain balance into the splice, the canonical lightning
		// balance excludes the SPLICING channel, and the live localBalanceMsat
		// stays PRE-splice until splice_locked — so the newly spliced-in sats
		// appeared in no reported figure at all. The bucket must use the
		// pending post-splice balance (old local 132,295 + spliced ~79,451).
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 132_295_000n,
				pendingSpliceLocalBalanceMsat: 211_746_000n
			},
			{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n },
			{ state: ChannelState.FORCE_CLOSED, localBalanceMsat: 9_000_000n }
		]);
		expect(sats).to.equal(211_746);
	});

	it('splicingBalanceSats reports the POST-splice balance for a splice-out', () => {
		// The inverse error: a splice-out's live balance is still the old
		// 120k, but only ~20k rejoins Lightning at splice_locked; the rest is
		// on its way on-chain and must not be promised back to Lightning.
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 120_000_000n,
				pendingSpliceLocalBalanceMsat: 20_000_000n
			}
		]);
		expect(sats).to.equal(20_000);
	});

	it('splicingBalanceSats falls back to the live balance pre point-of-no-return', () => {
		// A channel still negotiating its splice has no pending figure yet; the
		// wallet inputs are still visible on-chain, so the live balance is the
		// double-count-free number.
		const sats = splicingSats([
			{ state: ChannelState.SPLICING, localBalanceMsat: 132_295_000n }
		]);
		expect(sats).to.equal(132_295);
	});

	it('splicingBalanceSats holds only the arriving delta for a channel paying through its splice-in', () => {
		// Pay-during-splice: the canonical balance counts a usable mid-splice
		// channel at min(live, settle-to), so the bucket keeps only what is
		// still in transit — here the ~79,451 sats arriving with the splice.
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 132_295_000n,
				pendingSpliceLocalBalanceMsat: 211_746_000n,
				htlcUsable: true
			}
		]);
		expect(sats).to.equal(79_451);
	});

	it('splicingBalanceSats is 0 for a channel paying through its splice-out', () => {
		// The canonical balance already counts the settle-to side (20k); the
		// departing 100k surfaces on-chain once the splice tx is seen.
		const sats = splicingSats([
			{
				state: ChannelState.SPLICING,
				localBalanceMsat: 120_000_000n,
				pendingSpliceLocalBalanceMsat: 20_000_000n,
				htlcUsable: true
			}
		]);
		expect(sats).to.equal(0);
	});

	it('splicingBalanceSats is 0 with no splice in flight', () => {
		expect(
			splicingSats([
				{ state: ChannelState.NORMAL, localBalanceMsat: 50_000_000n }
			])
		).to.equal(0);
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
