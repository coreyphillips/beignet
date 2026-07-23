/**
 * Phase 4: Cooperative Close Fee Negotiation tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
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
		// Real curve points: open/accept validation now rejects off-curve
		// basepoints (BOLT 2 LOW hardening).
		fundingPubkey: getPublicKey(crypto.randomBytes(32)),
		revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
		paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
		htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
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
function setupNegotiatingChannels(opts?: { withPendingHtlc?: boolean }): {
	opener: Channel;
	acceptor: Channel;
} {
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

	if (opts?.withPendingHtlc) {
		// Put an offered HTLC in flight on the opener, then have the peer
		// initiate shutdown. The opener holds at SHUTTING_DOWN.
		const addActions = opener.addHtlc(
			50_000_000n,
			crypto.randomBytes(32),
			500,
			Buffer.alloc(1366)
		);
		expect(findErrorAction(addActions)).to.be.null;
		opener.handleShutdown({
			channelId: opener.getChannelId()!,
			scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
		});
		expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);
		return { opener, acceptor };
	}

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

		it('prices the close from the real tx weight, clearing a CLN-style fee floor (mainnet regression)', function () {
			// Live-node regression: an anchors channel carries the 253 sat/kw
			// commitment-feerate floor, and the old 170-WU shortcut priced the
			// closing tx at 44 sat. CLN's minimum acceptable close fee was 139
			// sat, and with closingFeeMax capped at 2x ideal (88 sat) the
			// negotiation could NEVER succeed: warning + disconnect, forever.
			// The real closing tx weight (~674 WU with two P2WPKH outputs) at
			// the same 253 sat/kw clears that floor.
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			const actions = opener.proposeClosingFee(crypto.randomBytes(64));
			const decoded = decodeClosingSignedMessage(
				findSendAction(actions, MessageType.CLOSING_SIGNED)!
			);
			expect(decoded.feeSatoshis >= 139n, 'ideal fee clears CLN floor').to.be
				.true;

			// The peer counters at its 139-sat floor; that must now fall inside
			// our acceptable range and complete the close.
			const counter = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 139n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);
			expect(hasAction(counter, ChannelActionType.CHANNEL_CLOSED)).to.be.true;
		});

		it('uses an injected live closing feerate over the commitment floor', function () {
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			const floorActions = opener.proposeClosingFee(crypto.randomBytes(64));
			const floorFee = decodeClosingSignedMessage(
				findSendAction(floorActions, MessageType.CLOSING_SIGNED)!
			).feeSatoshis;

			// 10 sat/vB live rate = 2500 sat/kw; the effective closing feerate
			// takes the higher of live and commitment.
			opener.setClosingFeeratePerKw(2500);
			expect(opener.getClosingFeeratePerKw()).to.equal(2500);
			const liveActions = opener.proposeClosingFee(crypto.randomBytes(64));
			const liveFee = decodeClosingSignedMessage(
				findSendAction(liveActions, MessageType.CLOSING_SIGNED)!
			).feeSatoshis;

			expect(liveFee > floorFee, 'live rate raises the fee').to.be.true;
			// 2500/253 ≈ 9.9x; allow rounding.
			expect(Number(liveFee)).to.be.closeTo(
				Number(floorFee) * (2500 / 253),
				20
			);

			// A live rate BELOW the commitment feerate never lowers the fee.
			opener.setClosingFeeratePerKw(100);
			expect(opener.getClosingFeeratePerKw()).to.equal(253);
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

		it('reserves the opener dust limit in closingFeeMax so our output is not burned', function () {
			// Fund-safety: the fee comes out of the opener's output, and the
			// closing tx silently omits an output below dust. Capping the fee at
			// the whole opener balance therefore allowed an accepted fee to push
			// our output below dust and burn it. The cap must reserve our dust
			// limit.
			const { opener } = setupNegotiatingChannels();
			opener.handleShutdown({
				channelId: opener.getChannelId()!,
				scriptPubkey: Buffer.from('0014' + '0'.repeat(40), 'hex')
			});

			// Shrink our (opener) balance so the balance cap binds: ideal fee at
			// feeratePerKw 253 is 44 sat, so the 2x cap is 88 sat. With 400 sat of
			// balance the old cap (whole balance) allowed fees up to 88 sat,
			// leaving 312 sat < 354 dust and burning our output.
			opener.getFullState().localBalanceMsat = 400_000n;

			opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 88n,
					signature: crypto.randomBytes(64)
				},
				signFn
			);

			// 400 sat balance minus the 354 sat dust limit
			expect(opener.getFullState().closingFeeMax).to.equal(46n);
			expect(opener.getState()).to.not.equal(ChannelState.CLOSED);
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

		it('rejects closing_signed while HTLCs are pending (fund-safety)', function () {
			// The closing tx pays out the settled balances only, so signing a
			// mutual close with an HTLC in flight burns that HTLC's value to
			// fees. A peer that sends shutdown followed by closing_signed while
			// we still have a pending HTLC must be rejected, and the channel
			// (plus its funding watch) must stay intact.
			const { opener } = setupNegotiatingChannels({ withPendingHtlc: true });

			expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);

			const actions = opener.handleClosingSigned(
				{
					channelId: opener.getChannelId()!,
					feeSatoshis: 500n,
					signature: crypto.randomBytes(64)
				},
				signFn,
				() => true
			);

			expect(findErrorAction(actions)).to.include('pending HTLCs');
			expect(hasAction(actions, ChannelActionType.CHANNEL_CLOSED)).to.be.false;
			expect(findSendAction(actions, MessageType.CLOSING_SIGNED)).to.be.null;
			expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);
		});

		it('rejects proposeClosingFee while HTLCs are pending (fund-safety)', function () {
			const { opener } = setupNegotiatingChannels({ withPendingHtlc: true });

			const actions = opener.proposeClosingFee(crypto.randomBytes(64));

			expect(findErrorAction(actions)).to.include('pending HTLCs');
			expect(findSendAction(actions, MessageType.CLOSING_SIGNED)).to.be.null;
			expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);
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
