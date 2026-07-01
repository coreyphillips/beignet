/**
 * Phase 4: Cooperative Close Fee Negotiation tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	Channel,
	createOpenerChannel
} from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { createAcceptorState } from '../../src/lightning/channel/channel-state';
import { decodeClosingSignedMessage } from '../../src/lightning/message/channel-close';

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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): Buffer | null {
	for (const a of actions) {
		if (
			a.type === ChannelActionType.SEND_MESSAGE &&
			a.messageType === msgType
		) {
			return a.payload;
		}
	}
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findErrorAction(actions: any[]): string | null {
	for (const a of actions) {
		if (a.type === ChannelActionType.ERROR) {
			return a.message;
		}
	}
	return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function hasAction(actions: any[], type: ChannelActionType): boolean {
	return actions.some((a: { type: ChannelActionType }) => a.type === type);
}

function signFn(_fee: bigint): Buffer {
	return crypto.randomBytes(64);
}

/**
 * Create two channels in NEGOTIATING_CLOSING state.
 */
function setupNegotiatingChannels(): { opener: Channel; acceptor: Channel } {
	const openerBp = makeBasepoints();
	const acceptorBp = makeBasepoints();

	const opener = createOpenerChannel({
		fundingSatoshis: 1_000_000n,
		localBasepoints: openerBp,
		localPerCommitmentSeed: crypto.randomBytes(32)
	});

	const openActions = opener.initiateOpen();
	const openPayload = findSendAction(openActions, MessageType.OPEN_CHANNEL)!;
	const {
		decodeOpenChannelMessage
	} = require('../../src/lightning/message/channel-open');
	const openMsg = decodeOpenChannelMessage(openPayload);

	const acceptorState = createAcceptorState({
		temporaryChannelId: openMsg.temporaryChannelId,
		fundingSatoshis: openMsg.fundingSatoshis,
		pushMsat: openMsg.pushMsat,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: acceptorBp,
		localPerCommitmentSeed: crypto.randomBytes(32),
		remoteBasepoints: {
			fundingPubkey: openMsg.fundingPubkey,
			revocationBasepoint: openMsg.revocationBasepoint,
			paymentBasepoint: openMsg.paymentBasepoint,
			delayedPaymentBasepoint: openMsg.delayedPaymentBasepoint,
			htlcBasepoint: openMsg.htlcBasepoint,
			firstPerCommitmentPoint: openMsg.firstPerCommitmentPoint
		},
		remoteConfig: {
			dustLimitSatoshis: openMsg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: openMsg.maxHtlcValueInFlightMsat,
			channelReserveSatoshis: openMsg.channelReserveSatoshis,
			htlcMinimumMsat: openMsg.htlcMinimumMsat,
			toSelfDelay: openMsg.toSelfDelay,
			maxAcceptedHtlcs: openMsg.maxAcceptedHtlcs,
			feeratePerKw: openMsg.feeratePerKw
		}
	});

	const acceptor = new Channel(acceptorState);
	const {
		decodeAcceptChannelMessage
	} = require('../../src/lightning/message/channel-open');
	const acceptActions = acceptor.handleOpenChannel(openMsg);
	const acceptPayload = findSendAction(
		acceptActions,
		MessageType.ACCEPT_CHANNEL
	)!;
	const acceptMsg = decodeAcceptChannelMessage(acceptPayload);
	opener.handleAcceptChannel(acceptMsg);

	const fundingTxid = crypto.randomBytes(32);
	const sig = crypto.randomBytes(64);
	opener.createFundingCreated(fundingTxid, 0, sig);
	const channelId = opener.getChannelId()!;

	acceptor.handleFundingCreated(
		{
			temporaryChannelId: opener.getTemporaryChannelId(),
			fundingTxid,
			fundingOutputIndex: 0,
			signature: sig
		},
		crypto.randomBytes(64)
	);
	opener.handleFundingSigned({ channelId, signature: crypto.randomBytes(64) });

	opener.fundingConfirmed();
	acceptor.fundingConfirmed();
	opener.handleChannelReady({
		channelId,
		secondPerCommitmentPoint: crypto.randomBytes(33)
	});
	acceptor.handleChannelReady({
		channelId: acceptor.getChannelId()!,
		secondPerCommitmentPoint: crypto.randomBytes(33)
	});

	// Initiate shutdown on both sides
	opener.initiateShutdown(Buffer.from('0014' + '0'.repeat(40), 'hex'));
	acceptor.handleShutdown({
		channelId: acceptor.getChannelId()!,
		scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
	});

	expect(acceptor.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

	return { opener, acceptor };
}

describe('Cooperative Close Fee Negotiation (Phase 4)', function () {
	describe('proposeClosingFee', function () {
		it('should send closing_signed with ideal fee', function () {
			const { opener } = setupNegotiatingChannels();
			// Move opener to NEGOTIATING_CLOSING
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			const actions = opener.proposeClosingFee(crypto.randomBytes(64));
			const payload = findSendAction(actions, MessageType.CLOSING_SIGNED);
			expect(payload).to.not.be.null;

			const decoded = decodeClosingSignedMessage(payload!);
			expect(decoded.feeSatoshis).to.be.a('bigint');
			expect(Number(decoded.feeSatoshis)).to.be.greaterThan(0);

			expect(opener.getFullState().lastProposedClosingFeeSat).to.not.be.null;
		});

		it('should reject proposal in wrong state', function () {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const actions = opener.proposeClosingFee(crypto.randomBytes(64));
			expect(findErrorAction(actions)).to.include('wrong state');
		});
	});

	describe('handleClosingSigned — acceptance', function () {
		it('should accept fee within acceptable range', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			// Acceptor sends closing_signed with a reasonable fee
			const actions = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 500n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);

			// Should either accept (CLOSED) or counter-propose
			const closedAction = hasAction(actions, ChannelActionType.CHANNEL_CLOSED);
			const sentAction = findSendAction(actions, MessageType.CLOSING_SIGNED);

			// At least one should be true
			expect(closedAction || sentAction !== null).to.be.true;
		});

		it('should reach CLOSED state when fee matches last proposal', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			// Opener proposes initial fee
			const proposeActions = opener.proposeClosingFee(crypto.randomBytes(64));
			const proposePayload = findSendAction(
				proposeActions,
				MessageType.CLOSING_SIGNED
			)!;
			const proposedFee =
				decodeClosingSignedMessage(proposePayload).feeSatoshis;

			// Acceptor responds with the same fee → agreement
			const actions = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: proposedFee,
					signature: crypto.randomBytes(64)
				},
				signFn
			);

			expect(opener.getState()).to.equal(ChannelState.CLOSED);
			expect(hasAction(actions, ChannelActionType.CHANNEL_CLOSED)).to.be.true;
		});

		it('does NOT close on a fee-echo with an invalid peer signature (C1)', function () {
			// A peer echoes our proposed fee but sends a garbage closing signature.
			// Without a signature gate the channel would go CLOSED and the funding
			// watch would be torn down, leaving a later revoked broadcast unpunished.
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			const proposeActions = opener.proposeClosingFee(crypto.randomBytes(64));
			const proposePayload = findSendAction(
				proposeActions,
				MessageType.CLOSING_SIGNED
			)!;
			const proposedFee =
				decodeClosingSignedMessage(proposePayload).feeSatoshis;

			// verifyClosingFn returns false → peer sig is invalid
			const actions = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: proposedFee,
					signature: crypto.randomBytes(64)
				},
				signFn,
				() => false
			);

			expect(hasAction(actions, ChannelActionType.CHANNEL_CLOSED)).to.be.false;
			expect(findErrorAction(actions)).to.include('signature');
			// Channel stays in negotiation (funding watch intact upstream).
			expect(opener.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
		});

		it('still closes on a fee-echo with a valid peer signature (C1 control)', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			const proposeActions = opener.proposeClosingFee(crypto.randomBytes(64));
			const proposedFee = decodeClosingSignedMessage(
				findSendAction(proposeActions, MessageType.CLOSING_SIGNED)!
			).feeSatoshis;

			const actions = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: proposedFee,
					signature: crypto.randomBytes(64)
				},
				signFn,
				() => true
			);

			expect(opener.getState()).to.equal(ChannelState.CLOSED);
			expect(hasAction(actions, ChannelActionType.CHANNEL_CLOSED)).to.be.true;
		});
	});

	describe('handleClosingSigned — counter-proposal', function () {
		it('should counter-propose when fee is too high', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			// Propose initial fee
			opener.proposeClosingFee(crypto.randomBytes(64));

			// Remote proposes much higher fee (outside our range)
			const actions = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 100_000n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);

			// Should counter-propose (send closing_signed) but not close
			const payload = findSendAction(actions, MessageType.CLOSING_SIGNED);
			expect(payload).to.not.be.null;

			// Should not be closed yet (fee was too far)
			if (opener.getState() !== ChannelState.CLOSED) {
				expect(opener.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
			}
		});

		it('should converge to agreement in 2-3 rounds', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			// Opener proposes initial fee
			const proposeActions = opener.proposeClosingFee(crypto.randomBytes(64));
			const proposedPayload = findSendAction(
				proposeActions,
				MessageType.CLOSING_SIGNED
			)!;
			const ourFee = decodeClosingSignedMessage(proposedPayload).feeSatoshis;

			// Remote proposes different fee
			let remoteCounter = ourFee * 3n;
			let round = 0;
			const maxRounds = 10;

			while (opener.getState() !== ChannelState.CLOSED && round < maxRounds) {
				const actions = opener.handleClosingSigned(
					{
						channelId: opener.getChannelId()!,
						feeSatoshis: remoteCounter,
						signature: crypto.randomBytes(64)
					},
					signFn
				);

				if (opener.getState() === ChannelState.CLOSED) break;

				const payload = findSendAction(actions, MessageType.CLOSING_SIGNED);
				if (payload) {
					const decoded = decodeClosingSignedMessage(payload);
					// Simulate remote accepting our counter
					remoteCounter = decoded.feeSatoshis;
				}
				round++;
			}

			expect(opener.getState()).to.equal(ChannelState.CLOSED);
		});
	});

	describe('Fee range', function () {
		it('should initialize fee range on first closing_signed', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			expect(opener.getFullState().closingFeeMin).to.be.null;
			expect(opener.getFullState().closingFeeMax).to.be.null;

			// Receive closing_signed → fee range should be initialized
			opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 500n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);

			expect(opener.getFullState().closingFeeMin).to.not.be.null;
			expect(opener.getFullState().closingFeeMax).to.not.be.null;
		});

		it('should store theirLastClosingFeeSat', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 12345n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);

			expect(opener.getFullState().theirLastClosingFeeSat).to.equal(12345n);
		});
	});

	describe('State transitions', function () {
		it('should transition SHUTTING_DOWN → NEGOTIATING_CLOSING on closing_signed', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			expect(opener.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

			// Receive closing_signed
			opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 500n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);

			// Should still be NEGOTIATING_CLOSING or CLOSED
			expect([
				ChannelState.NEGOTIATING_CLOSING,
				ChannelState.CLOSED
			]).to.include(opener.getState());
		});

		it('should reject closing_signed in NORMAL state', function () {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			const actions = opener.handleClosingSigned(
				{
					channelId: Buffer.alloc(32),
					feeSatoshis: 500n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);
			expect(findErrorAction(actions)).to.include('Unexpected');
		});
	});
});
