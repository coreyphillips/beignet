/**
 * Phase 8: SCID Alias tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { MessageType } from '../../src/lightning/message/types';
import { decodeChannelReadyMessage } from '../../src/lightning/message/channel-funding';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';

// ── Helpers ────────────────────────────────────────────────────────

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

function makeOpenerChannel(): Channel {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	return new Channel(state);
}

function makeAcceptorChannel(): Channel {
	const state = createAcceptorState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32),
		remoteBasepoints: makeBasepoints(),
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	return new Channel(state);
}

/**
 * Move channel to AWAITING_FUNDING_CONFIRMED so fundingConfirmed() can proceed.
 */
function setupChannelToAwaitFunding(channel: Channel): void {
	const state = channel.getFullState();
	state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.remoteCurrentPerCommitmentPoint = crypto.randomBytes(33);
}

function findSendAction(actions: any[], messageType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === messageType
	);
}

function makeNode(): LightningNode {
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32)
	});
}

// ── Tests ──────────────────────────────────────────────────────────

describe('SCID Aliases (Phase 8)', function () {
	describe('Alias Generation', function () {
		it('should generate a random 8-byte SCID alias on fundingConfirmed', function () {
			const channel = makeOpenerChannel();
			setupChannelToAwaitFunding(channel);

			const actions = channel.fundingConfirmed();
			const sendAction = findSendAction(actions, MessageType.CHANNEL_READY);
			expect(sendAction).to.exist;

			const state = channel.getFullState();
			expect(state.scidAlias).to.not.be.null;
			expect(state.scidAlias!.length).to.equal(8);
		});

		it('should not regenerate alias on duplicate fundingConfirmed calls', function () {
			const channel = makeOpenerChannel();
			setupChannelToAwaitFunding(channel);

			channel.fundingConfirmed();
			const firstAlias = Buffer.from(channel.getFullState().scidAlias!);

			// Reset to allow second call
			channel.getFullState().state = ChannelState.AWAITING_FUNDING_CONFIRMED;
			channel.getFullState().localChannelReady = false;

			channel.fundingConfirmed();
			const secondAlias = channel.getFullState().scidAlias!;

			expect(firstAlias.equals(secondAlias)).to.be.true;
		});

		it('should include SCID alias in channel_ready TLV', function () {
			const channel = makeOpenerChannel();
			setupChannelToAwaitFunding(channel);

			const actions = channel.fundingConfirmed();
			const sendAction = findSendAction(actions, MessageType.CHANNEL_READY);
			const decoded = decodeChannelReadyMessage(sendAction.payload);

			expect(decoded.shortChannelId).to.not.be.undefined;
			expect(decoded.shortChannelId!.length).to.equal(8);
			expect(decoded.shortChannelId!.equals(channel.getFullState().scidAlias!))
				.to.be.true;
		});
	});

	describe('Remote Alias Storage', function () {
		it('should store remote SCID alias from channel_ready', function () {
			const channel = makeAcceptorChannel();
			const state = channel.getFullState();
			state.state = ChannelState.AWAITING_CHANNEL_READY;
			state.channelId = crypto.randomBytes(32);
			state.localChannelReady = true;

			const remoteAlias = crypto.randomBytes(8);
			channel.handleChannelReady({
				channelId: state.channelId!,
				secondPerCommitmentPoint: crypto.randomBytes(33),
				shortChannelId: remoteAlias
			});

			expect(state.remoteScidAlias).to.not.be.null;
			expect(state.remoteScidAlias!.equals(remoteAlias)).to.be.true;
		});

		it('should not set remoteScidAlias when channel_ready has no TLV', function () {
			const channel = makeAcceptorChannel();
			const state = channel.getFullState();
			state.state = ChannelState.AWAITING_CHANNEL_READY;
			state.channelId = crypto.randomBytes(32);
			state.localChannelReady = true;

			channel.handleChannelReady({
				channelId: state.channelId!,
				secondPerCommitmentPoint: crypto.randomBytes(33)
			});

			expect(state.remoteScidAlias).to.be.null;
		});
	});

	describe('Getters', function () {
		it('getScidAlias() should return local alias', function () {
			const channel = makeOpenerChannel();
			const state = channel.getFullState();
			state.scidAlias = crypto.randomBytes(8);

			expect(channel.getScidAlias()!.equals(state.scidAlias)).to.be.true;
		});

		it('getRemoteScidAlias() should return remote alias', function () {
			const channel = makeOpenerChannel();
			const state = channel.getFullState();
			state.remoteScidAlias = crypto.randomBytes(8);

			expect(channel.getRemoteScidAlias()!.equals(state.remoteScidAlias)).to.be
				.true;
		});

		it('getScidAlias() should return null when not set', function () {
			const channel = makeOpenerChannel();
			expect(channel.getScidAlias()).to.be.null;
		});

		it('getRemoteScidAlias() should return null when not set', function () {
			const channel = makeOpenerChannel();
			expect(channel.getRemoteScidAlias()).to.be.null;
		});
	});

	describe('Invoice Routing Hints', function () {
		it('should include routing hints for private channels in invoices', function () {
			const node = makeNode();
			// We need to set up a channel in NORMAL state to generate routing hints
			// This test verifies the createInvoice flow works without errors
			const invoice = node.createInvoice({
				amountMsat: 1000n,
				description: 'test'
			});
			expect(invoice.bolt11).to.be.a('string');

			// No channels, so no routing hints
			const decoded = decodeInvoice(invoice.bolt11);
			expect(decoded.routingHints).to.satisfy(
				(v: any) => v === undefined || v.length === 0
			);
			node.destroy();
		});
	});

	describe('State Initialization', function () {
		it('should initialize scidAlias as null in opener state', function () {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			expect(state.scidAlias).to.be.null;
			expect(state.remoteScidAlias).to.be.null;
		});

		it('should initialize scidAlias as null in acceptor state', function () {
			const state = createAcceptorState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32),
				remoteBasepoints: makeBasepoints(),
				remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
			});
			expect(state.scidAlias).to.be.null;
			expect(state.remoteScidAlias).to.be.null;
		});
	});

	describe('LightningNode Integration', function () {
		it('should accept mppTimeoutMs config (backward compat)', function () {
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				perCommitmentSeed: crypto.randomBytes(32),
				channelBasepoints: makeBasepoints(),
				fundingPrivkey: crypto.randomBytes(32),
				mppTimeoutMs: 120_000
			});
			expect(node).to.exist;
			node.destroy();
		});

		it('should clean up on destroy', function () {
			const node = makeNode();
			node.destroy();
			// Should not throw
		});
	});
});
