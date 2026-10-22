/**
 * Issue #1699: getFullState() is typed read-only, and the writes callers
 * made through it are named transitions on Channel. Each one changes exactly
 * the fields the assignment it replaced did, which is what these pin.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { writableState } from './helpers/writable-state';

function point(): Buffer {
	return Buffer.concat([Buffer.from([0x02]), crypto.randomBytes(32)]);
}

function makeChannel(): Channel {
	return new Channel(
		createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: {
				fundingPubkey: point(),
				revocationBasepoint: point(),
				paymentBasepoint: point(),
				delayedPaymentBasepoint: point(),
				htlcBasepoint: point(),
				firstPerCommitmentPoint: point()
			},
			localPerCommitmentSeed: crypto.randomBytes(32)
		})
	);
}

/** The top-level state fields `transition` changed, by identity. */
function changedFields(channel: Channel, transition: () => unknown): string[] {
	const before: Record<string, unknown> = { ...channel.getFullState() };
	transition();
	const after: Record<string, unknown> = { ...channel.getFullState() };
	const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
	return [...keys].filter((key) => before[key] !== after[key]).sort();
}

describe('Channel named state transitions (issue #1699)', () => {
	it('getFullState() is the live state, so an earlier reference sees a transition', () => {
		const channel = makeChannel();
		const earlier = channel.getFullState();
		channel.setTrustedPeer();
		expect(channel.getFullState()).to.equal(earlier);
		expect(earlier.trustedPeer).to.equal(true);
	});

	it('setTrustedPeer records membership and enables nothing else', () => {
		const channel = makeChannel();
		expect(
			changedFields(channel, () => channel.setTrustedPeer())
		).to.deep.equal(['trustedPeer']);
		expect(channel.getFullState().zeroConfEnabled).to.equal(false);
	});

	it('failOpenOnDisconnect sets ERRORED and nothing else', () => {
		for (const open of [
			ChannelState.SENT_OPEN,
			ChannelState.SENT_FUNDING_CREATED,
			ChannelState.DUAL_FUNDING_V2
		]) {
			const channel = makeChannel();
			writableState(channel).state = open;
			expect(
				changedFields(channel, () => channel.failOpenOnDisconnect())
			).to.deep.equal(['state']);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		}
	});

	it('markNegotiatingClosing takes a CLOSED channel back to NEGOTIATING_CLOSING', () => {
		const channel = makeChannel();
		writableState(channel).state = ChannelState.CLOSED;
		expect(
			changedFields(channel, () => channel.markNegotiatingClosing())
		).to.deep.equal(['state']);
		expect(channel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
	});

	it('setFundingOutpoint sets the outpoint and derives no channel id', () => {
		const channel = makeChannel();
		const txid = crypto.randomBytes(32);
		expect(
			changedFields(channel, () => channel.setFundingOutpoint(txid, 1))
		).to.deep.equal(['fundingOutputIndex', 'fundingTxid']);
		expect(channel.getFullState().fundingTxid).to.equal(txid);
		expect(channel.getFullState().fundingOutputIndex).to.equal(1);
		expect(channel.getChannelId()).to.equal(null);
	});

	describe('rollbackShutdown', () => {
		const previous = {
			state: ChannelState.NORMAL,
			localShutdownScript: null,
			externalClose: undefined,
			staleCloseRiskAccepted: undefined,
			simpleClose: null
		};

		function shutDown(channel: Channel): void {
			const state = writableState(channel);
			state.state = ChannelState.SHUTTING_DOWN;
			state.localShutdownScript = Buffer.from('0014' + '11'.repeat(20), 'hex');
			state.externalClose = {
				scriptHex: '0014' + '22'.repeat(20),
				timestamp: 1
			};
			state.staleCloseRiskAccepted = true;
			state.simpleClose = true;
		}

		it('restores the state and the four close fields', () => {
			const channel = makeChannel();
			shutDown(channel);
			channel.rollbackShutdown(previous);
			const state = channel.getFullState();
			expect(state.state).to.equal(ChannelState.NORMAL);
			expect(state.localShutdownScript).to.equal(null);
			expect(state.externalClose).to.equal(undefined);
			expect(state.staleCloseRiskAccepted).to.equal(undefined);
			expect(state.simpleClose).to.equal(null);
		});

		it('rewrites the state a disconnect will return to, not the disconnect', () => {
			const channel = makeChannel();
			shutDown(channel);
			writableState(channel).preReestablishState = ChannelState.SHUTTING_DOWN;
			writableState(channel).state = ChannelState.AWAITING_REESTABLISH;
			channel.rollbackShutdown(previous);
			expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
			expect(channel.getFullState().preReestablishState).to.equal(
				ChannelState.NORMAL
			);
			expect(channel.getFullState().localShutdownScript).to.equal(null);
		});
	});

	it('reopenForceCloseResolution moves only a CLOSED channel back to FORCE_CLOSED', () => {
		const closed = makeChannel();
		writableState(closed).state = ChannelState.CLOSED;
		expect(closed.reopenForceCloseResolution()).to.equal(true);
		expect(closed.getState()).to.equal(ChannelState.FORCE_CLOSED);

		const open = makeChannel();
		writableState(open).state = ChannelState.NORMAL;
		expect(open.reopenForceCloseResolution()).to.equal(false);
		expect(open.getState()).to.equal(ChannelState.NORMAL);
	});

	it('retainFundingPayload is what clearRetainedFundingPayload retires', () => {
		const channel = makeChannel();
		expect(
			changedFields(channel, () => channel.retainFundingPayload('0200'))
		).to.deep.equal(['pendingFundingTxHex']);
		expect(channel.getFullState().pendingFundingTxHex).to.equal('0200');
		expect(channel.clearRetainedFundingPayload()).to.equal(true);
		expect('pendingFundingTxHex' in channel.getFullState()).to.equal(false);
	});

	it('stampFundingBroadcastHeight stamps once, and never without a chain tip', () => {
		const channel = makeChannel();
		expect(channel.stampFundingBroadcastHeight(0)).to.equal(false);
		expect(channel.getFullState().fundingBroadcastHeight).to.equal(0);
		expect(channel.stampFundingBroadcastHeight(800)).to.equal(true);
		expect(channel.stampFundingBroadcastHeight(900)).to.equal(false);
		expect(channel.getFullState().fundingBroadcastHeight).to.equal(800);
	});

	it('retirePreSpliceSpendWatch drops one outpoint and removes an emptied list', () => {
		const channel = makeChannel();
		const watch = (
			txid: string,
			outputIndex: number
		): {
			txid: string;
			outputIndex: number;
			script: string;
			spliceTxid: string;
		} => ({
			txid,
			outputIndex,
			script: '00',
			spliceTxid: 'ff'.repeat(32)
		});
		writableState(channel).preSpliceSpendWatches = [
			watch('aa'.repeat(32), 0),
			watch('bb'.repeat(32), 1)
		];
		expect(channel.retirePreSpliceSpendWatch('cc'.repeat(32), 0)).to.equal(
			false
		);
		expect(channel.retirePreSpliceSpendWatch('aa'.repeat(32), 1)).to.equal(
			false
		);
		expect(channel.retirePreSpliceSpendWatch('aa'.repeat(32), 0)).to.equal(
			true
		);
		expect(channel.getFullState().preSpliceSpendWatches).to.deep.equal([
			watch('bb'.repeat(32), 1)
		]);
		expect(channel.retirePreSpliceSpendWatch('bb'.repeat(32), 1)).to.equal(
			true
		);
		expect(channel.getFullState().preSpliceSpendWatches).to.equal(undefined);
	});
});
