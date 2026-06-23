/**
 * Phase 1: Robust channel_reestablish (BOLT 2 §5) tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	decodeChannelReestablishMessage,
	IChannelReestablishMessage
} from '../../src/lightning/message/channel-reestablish';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { createOpenerChannel } from '../../src/lightning/channel/channel';

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

function getPerCommitmentPoint(seed: Buffer, commitmentNumber: bigint): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	const secret = generateFromSeed(seed, index);
	return perCommitmentPointFromSecret(secret);
}

function getPerCommitmentSecret(
	seed: Buffer,
	commitmentNumber: bigint
): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	return generateFromSeed(seed, index);
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

/**
 * Helper: create two channels (opener + acceptor) and advance them to NORMAL state.
 */
function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerSeed: Buffer;
	acceptorSeed: Buffer;
} {
	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);
	const openerBp = makeBasepoints();
	const acceptorBp = makeBasepoints();

	const opener = createOpenerChannel({
		fundingSatoshis: 1_000_000n,
		localBasepoints: openerBp,
		localPerCommitmentSeed: openerSeed
	});

	// Opener initiates
	const openActions = opener.initiateOpen();
	const openPayload = findSendAction(openActions, MessageType.OPEN_CHANNEL)!;

	// Build the acceptor from open_channel decoded fields
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
		localPerCommitmentSeed: acceptorSeed,
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
	const acceptActions = acceptor.handleOpenChannel(openMsg);
	const acceptPayload = findSendAction(
		acceptActions,
		MessageType.ACCEPT_CHANNEL
	)!;
	const {
		decodeAcceptChannelMessage
	} = require('../../src/lightning/message/channel-open');
	const acceptMsg = decodeAcceptChannelMessage(acceptPayload);

	// Opener handles accept
	opener.handleAcceptChannel(acceptMsg);

	// Funding
	const fundingTxid = crypto.randomBytes(32);
	const sig = crypto.randomBytes(64);
	opener.createFundingCreated(fundingTxid, 0, sig);

	const channelId = opener.getChannelId()!;

	// Acceptor handles funding_created
	acceptor.handleFundingCreated(
		{
			temporaryChannelId: opener.getTemporaryChannelId(),
			fundingTxid,
			fundingOutputIndex: 0,
			signature: sig
		},
		crypto.randomBytes(64)
	);

	// Opener handles funding_signed
	opener.handleFundingSigned({ channelId, signature: crypto.randomBytes(64) });

	// Both confirm funding
	opener.fundingConfirmed();
	acceptor.fundingConfirmed();

	// Exchange channel_ready
	const acceptorSecondPoint = getPerCommitmentPoint(acceptorSeed, 1n);
	const openerSecondPoint = getPerCommitmentPoint(openerSeed, 1n);

	opener.handleChannelReady({
		channelId,
		secondPerCommitmentPoint: acceptorSecondPoint
	});
	acceptor.handleChannelReady({
		channelId: acceptor.getChannelId()!,
		secondPerCommitmentPoint: openerSecondPoint
	});

	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

	return { opener, acceptor, openerSeed, acceptorSeed };
}

describe('Channel Reestablish (BOLT 2 §5)', function () {
	describe('markForReestablish', function () {
		it('should transition NORMAL → AWAITING_REESTABLISH', function () {
			const { opener } = setupNormalChannels();
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			opener.markForReestablish();
			expect(opener.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
			expect(opener.getFullState().preReestablishState).to.equal(
				ChannelState.NORMAL
			);
		});

		it('should transition SHUTTING_DOWN → AWAITING_REESTABLISH', function () {
			const { opener } = setupNormalChannels();
			opener.initiateShutdown(Buffer.from('0014' + '0'.repeat(40), 'hex'));
			expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);
			opener.markForReestablish();
			expect(opener.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
			expect(opener.getFullState().preReestablishState).to.equal(
				ChannelState.SHUTTING_DOWN
			);
		});

		it('should not modify state if already AWAITING_REESTABLISH', function () {
			const { opener } = setupNormalChannels();
			opener.markForReestablish();
			const savedState = opener.getFullState().preReestablishState;
			opener.markForReestablish();
			expect(opener.getFullState().preReestablishState).to.equal(savedState);
		});

		it('tolerates a retransmitted channel_ready while AWAITING_REESTABLISH (no force-fail)', function () {
			// A peer legitimately retransmits channel_ready on reconnect (BOLT 2 §5).
			// Receiving it for an already-established channel must be a no-op, never
			// an ERROR — the latter previously surfaced "Unexpected channel_ready"
			// on every reconnect of a live channel.
			const { opener, acceptorSeed } = setupNormalChannels();
			opener.markForReestablish();
			expect(opener.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

			const actions = opener.handleChannelReady({
				channelId: opener.getChannelId()!,
				secondPerCommitmentPoint: getPerCommitmentPoint(acceptorSeed, 1n)
			});

			expect(actions.find((a) => a.type === ChannelActionType.ERROR)).to.be
				.undefined;
			expect(opener.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});

		it('should not modify non-operational channels', function () {
			const opener = createOpenerChannel({
				fundingSatoshis: 1_000_000n,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			opener.markForReestablish();
			expect(opener.getState()).to.equal(ChannelState.NONE);
		});
	});

	describe('markErrored (BOLT 1 peer error → stop reestablishing)', function () {
		it('transitions an operational channel to ERRORED and reports the change', function () {
			const { opener } = setupNormalChannels();
			expect(opener.markErrored()).to.be.true;
			expect(opener.getState()).to.equal(ChannelState.ERRORED);
		});

		it('is idempotent (no-op once ERRORED/closed)', function () {
			const { opener } = setupNormalChannels();
			opener.markErrored();
			expect(opener.markErrored()).to.be.false;
			expect(opener.getState()).to.equal(ChannelState.ERRORED);
		});

		it('an ERRORED channel is no longer eligible for reestablish (stops the storm)', function () {
			const { opener } = setupNormalChannels();
			opener.markErrored();
			// markForReestablish must NOT resurrect it — otherwise we'd send
			// channel_reestablish again on reconnect and the peer would re-error.
			opener.markForReestablish();
			expect(opener.getState()).to.equal(ChannelState.ERRORED);
		});
	});

	describe('createReestablish', function () {
		it('should produce valid channel_reestablish message', function () {
			const { opener } = setupNormalChannels();
			const actions = opener.createReestablish();
			expect(actions).to.have.length(1);
			const payload = findSendAction(actions, MessageType.CHANNEL_REESTABLISH);
			expect(payload).to.not.be.null;

			const msg = decodeChannelReestablishMessage(payload!);
			expect(msg.channelId.equals(opener.getChannelId()!)).to.be.true;
			expect(msg.nextCommitmentNumber).to.equal(
				opener.getFullState().localCommitmentNumber + 1n
			);
			expect(msg.nextRevocationNumber).to.equal(
				opener.getFullState().remoteCommitmentNumber
			);
		});

		it('should include correct myCurrentPerCommitmentPoint', function () {
			const { opener, openerSeed } = setupNormalChannels();
			const actions = opener.createReestablish();
			const msg = decodeChannelReestablishMessage(
				findSendAction(actions, MessageType.CHANNEL_REESTABLISH)!
			);
			const expectedPoint = getPerCommitmentPoint(
				openerSeed,
				opener.getFullState().localCommitmentNumber
			);
			expect(msg.myCurrentPerCommitmentPoint.equals(expectedPoint)).to.be.true;
		});
	});

	describe('handleReestablish — no message loss', function () {
		it('should resume with no retransmissions when both sides are synced', function () {
			const { opener, acceptor } = setupNormalChannels();

			opener.markForReestablish();
			acceptor.markForReestablish();

			const openerReestablishMsg = decodeChannelReestablishMessage(
				findSendAction(
					opener.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				)!
			);
			const acceptorReestablishMsg = decodeChannelReestablishMessage(
				findSendAction(
					acceptor.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				)!
			);

			const openerResult = opener.handleReestablish(acceptorReestablishMsg);
			const acceptorResult = acceptor.handleReestablish(openerReestablishMsg);

			expect(findErrorAction(openerResult)).to.be.null;
			expect(findErrorAction(acceptorResult)).to.be.null;

			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		});
	});

	describe('handleReestablish — commitment_signed retransmission', function () {
		it('should retransmit commitment_signed if peer missed it', function () {
			const { opener, acceptor } = setupNormalChannels();

			const commitSig = crypto.randomBytes(64);
			opener.signCommitment(commitSig, []);

			opener.markForReestablish();
			acceptor.markForReestablish();

			const acceptorReestablish = decodeChannelReestablishMessage(
				findSendAction(
					acceptor.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				)!
			);

			const result = opener.handleReestablish(acceptorReestablish);

			const retransmittedCommit = findSendAction(
				result,
				MessageType.COMMITMENT_SIGNED
			);
			expect(retransmittedCommit).to.not.be.null;

			const decodedCommit = decodeCommitmentSignedMessage(retransmittedCommit!);
			expect(decodedCommit.signature.equals(commitSig)).to.be.true;
		});
	});

	describe('handleReestablish — revoke_and_ack retransmission', function () {
		it('should retransmit revoke_and_ack if peer missed it', function () {
			const { opener, acceptor } = setupNormalChannels();

			const revokeActions = acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: crypto.randomBytes(64),
				htlcSignatures: []
			});

			const revokeSent = findSendAction(
				revokeActions,
				MessageType.REVOKE_AND_ACK
			);
			expect(revokeSent).to.not.be.null;

			acceptor.markForReestablish();
			opener.markForReestablish();

			const openerReestablish = decodeChannelReestablishMessage(
				findSendAction(
					opener.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				)!
			);

			const result = acceptor.handleReestablish(openerReestablish);

			const retransmittedRevoke = findSendAction(
				result,
				MessageType.REVOKE_AND_ACK
			);
			expect(retransmittedRevoke).to.not.be.null;

			const decoded = decodeRevokeAndAckMessage(retransmittedRevoke!);
			expect(
				decoded.perCommitmentSecret.equals(
					acceptor.getFullState().lastSentRevokeSecret!
				)
			).to.be.true;
			expect(
				decoded.nextPerCommitmentPoint.equals(
					acceptor.getFullState().lastSentRevokeNextPoint!
				)
			).to.be.true;
		});
	});

	describe('handleReestablish — data loss protection', function () {
		it('should accept valid per-commitment secret', function () {
			const { opener, acceptor, acceptorSeed } = setupNormalChannels();

			opener.signCommitment(crypto.randomBytes(64), []);
			acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: crypto.randomBytes(64),
				htlcSignatures: []
			});
			opener.handleRevokeAndAck({
				channelId: opener.getChannelId()!,
				perCommitmentSecret: getPerCommitmentSecret(acceptorSeed, 0n),
				nextPerCommitmentPoint: getPerCommitmentPoint(acceptorSeed, 2n)
			});

			opener.markForReestablish();
			acceptor.markForReestablish();

			const acceptorReestablish = decodeChannelReestablishMessage(
				findSendAction(
					acceptor.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				)!
			);

			const result = opener.handleReestablish(acceptorReestablish);
			expect(findErrorAction(result)).to.be.null;
		});

		it('should reject invalid per-commitment secret', function () {
			const { opener, acceptorSeed } = setupNormalChannels();

			opener.signCommitment(crypto.randomBytes(64), []);
			// Simulate having received a revocation
			opener.handleRevokeAndAck({
				channelId: opener.getChannelId()!,
				perCommitmentSecret: getPerCommitmentSecret(acceptorSeed, 0n),
				nextPerCommitmentPoint: getPerCommitmentPoint(acceptorSeed, 2n)
			});

			opener.markForReestablish();

			const badReestablish: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: 1n,
				nextRevocationNumber: 1n,
				yourLastPerCommitmentSecret: crypto.randomBytes(32),
				myCurrentPerCommitmentPoint: crypto.randomBytes(33)
			};

			const result = opener.handleReestablish(badReestablish);
			expect(findErrorAction(result)).to.contain(
				'Invalid per-commitment secret'
			);
		});
	});

	describe('handleReestablish — irrecoverable gaps', function () {
		it('should error on future commitment gap', function () {
			const { opener } = setupNormalChannels();
			opener.markForReestablish();

			const badReestablish: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: 100n,
				nextRevocationNumber: 0n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: crypto.randomBytes(33)
			};

			const result = opener.handleReestablish(badReestablish);
			expect(findErrorAction(result)).to.contain('future commitment');
		});

		it('should error on future revocation gap', function () {
			const { opener } = setupNormalChannels();
			opener.markForReestablish();

			const badReestablish: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: 1n,
				nextRevocationNumber: 100n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: crypto.randomBytes(33)
			};

			const result = opener.handleReestablish(badReestablish);
			expect(findErrorAction(result)).to.contain('future revocation');
		});
	});

	describe('handleReestablish — state restoration', function () {
		it('should restore NORMAL state after reestablish', function () {
			const { opener } = setupNormalChannels();

			opener.markForReestablish();
			expect(opener.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

			const reestablishMsg: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: opener.getFullState().remoteCommitmentNumber + 1n,
				nextRevocationNumber: opener.getFullState().localCommitmentNumber,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: crypto.randomBytes(33)
			};

			opener.handleReestablish(reestablishMsg);
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should restore SHUTTING_DOWN state after reestablish', function () {
			const { opener } = setupNormalChannels();

			opener.initiateShutdown(Buffer.from('0014' + '0'.repeat(40), 'hex'));
			expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);

			opener.markForReestablish();
			expect(opener.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

			const reestablishMsg: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: opener.getFullState().remoteCommitmentNumber + 1n,
				nextRevocationNumber: opener.getFullState().localCommitmentNumber,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: crypto.randomBytes(33)
			};

			opener.handleReestablish(reestablishMsg);
			expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);
		});
	});

	describe('Caching', function () {
		it('should cache commitment_signed signature on signCommitment', function () {
			const { opener } = setupNormalChannels();
			const sig = crypto.randomBytes(64);
			const htlcSig1 = crypto.randomBytes(64);
			opener.signCommitment(sig, [htlcSig1]);

			expect(opener.getFullState().lastSentCommitmentSigned).to.not.be.null;
			expect(opener.getFullState().lastSentCommitmentSigned!.equals(sig)).to.be
				.true;
			expect(opener.getFullState().lastSentHtlcSignatures).to.have.length(1);
			expect(opener.getFullState().lastSentHtlcSignatures[0].equals(htlcSig1))
				.to.be.true;
		});

		it('should cache revoke_and_ack on handleCommitmentSigned', function () {
			const { acceptor, acceptorSeed } = setupNormalChannels();
			acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: crypto.randomBytes(64),
				htlcSignatures: []
			});

			expect(acceptor.getFullState().lastSentRevokeSecret).to.not.be.null;
			expect(acceptor.getFullState().lastSentRevokeNextPoint).to.not.be.null;

			const expectedSecret = getPerCommitmentSecret(acceptorSeed, 0n);
			expect(
				acceptor.getFullState().lastSentRevokeSecret!.equals(expectedSecret)
			).to.be.true;

			// BOLT 2: after revoking commitment 0 and adopting commitment 1, the
			// revoke's next_per_commitment_point is for the NEXT commitment (#2).
			const expectedPoint = getPerCommitmentPoint(acceptorSeed, 2n);
			expect(
				acceptor.getFullState().lastSentRevokeNextPoint!.equals(expectedPoint)
			).to.be.true;
		});

		it('should update cache across multiple commitment rounds', function () {
			const { opener, acceptorSeed } = setupNormalChannels();

			opener.signCommitment(crypto.randomBytes(64), []);
			opener.handleRevokeAndAck({
				channelId: opener.getChannelId()!,
				perCommitmentSecret: getPerCommitmentSecret(acceptorSeed, 0n),
				nextPerCommitmentPoint: getPerCommitmentPoint(acceptorSeed, 2n)
			});

			const sig2 = crypto.randomBytes(64);
			opener.signCommitment(sig2, []);

			expect(opener.getFullState().lastSentCommitmentSigned!.equals(sig2)).to.be
				.true;
		});
	});

	describe('AWAITING_REESTABLISH guards', function () {
		it('should reject addHtlc while AWAITING_REESTABLISH', function () {
			const { opener } = setupNormalChannels();
			opener.markForReestablish();

			const actions = opener.addHtlc(
				50_000_000n,
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);

			const error = findErrorAction(actions);
			expect(error).to.contain('AWAITING_REESTABLISH');
		});
	});

	describe('ChannelManager integration', function () {
		it('should mark channels AWAITING_REESTABLISH on peer disconnect', function () {
			const basepoints = makeBasepoints();
			const seed = crypto.randomBytes(32);
			const manager = new ChannelManager({
				localBasepoints: basepoints,
				localPerCommitmentSeed: seed,
				localFundingPrivkey: crypto.randomBytes(32)
			});
			manager.on('error', () => {}); // absorb

			const peerPubkey = crypto.randomBytes(33).toString('hex');

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: seed
			});
			state.channelId = crypto.randomBytes(32);
			state.state = ChannelState.NORMAL;
			const channel = new Channel(state);
			manager.restoreChannel(channel, peerPubkey);

			manager.handlePeerDisconnected(peerPubkey);
			expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});

		it('should send channel_reestablish on peer reconnect', function () {
			const basepoints = makeBasepoints();
			const seed = crypto.randomBytes(32);
			const manager = new ChannelManager({
				localBasepoints: basepoints,
				localPerCommitmentSeed: seed,
				localFundingPrivkey: crypto.randomBytes(32)
			});
			manager.on('error', () => {}); // absorb

			const peerPubkey = crypto.randomBytes(33).toString('hex');

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: seed
			});
			state.channelId = crypto.randomBytes(32);
			state.state = ChannelState.NORMAL;
			const channel = new Channel(state);

			manager.restoreChannel(channel, peerPubkey);
			manager.handlePeerDisconnected(peerPubkey);
			expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

			const sent: { type: number }[] = [];
			manager.on('message:outbound', (_peer: string, type: number) => {
				sent.push({ type });
			});

			manager.handlePeerReconnected(peerPubkey);
			expect(sent.some((m) => m.type === MessageType.CHANNEL_REESTABLISH)).to.be
				.true;
		});
	});

	describe('Serialization', function () {
		it('should round-trip new IChannelState fields through serialization', function () {
			const { opener } = setupNormalChannels();

			opener.signCommitment(crypto.randomBytes(64), [crypto.randomBytes(64)]);
			opener.markForReestablish();

			const state = opener.getFullState();
			const serialized = serializeChannelState(state);
			const deserialized = deserializeChannelState(serialized);

			expect(deserialized.lastSentCommitmentSigned).to.not.be.null;
			expect(
				deserialized.lastSentCommitmentSigned!.equals(
					state.lastSentCommitmentSigned!
				)
			).to.be.true;
			expect(deserialized.lastSentHtlcSignatures).to.have.length(1);
			expect(deserialized.preReestablishState).to.equal(ChannelState.NORMAL);
			expect(deserialized.state).to.equal(ChannelState.AWAITING_REESTABLISH);
			expect(deserialized.shortChannelId).to.be.null;
			expect(deserialized.fundingConfirmationHeight).to.equal(0);
			expect(deserialized.announcementSigsSent).to.be.false;
			expect(deserialized.announceChannel).to.be.true;
			// scidAlias is generated during fundingConfirmed()
			if (state.scidAlias) {
				expect(deserialized.scidAlias).to.not.be.null;
				expect(deserialized.scidAlias!.equals(state.scidAlias)).to.be.true;
			} else {
				expect(deserialized.scidAlias).to.be.null;
			}
			expect(deserialized.remoteScidAlias).to.be.null;
			expect(deserialized.lastProposedClosingFeeSat).to.be.null;
			expect(deserialized.closingFeeMin).to.be.null;
		});
	});

	describe('Full two-party reestablish simulation', function () {
		it('should recover from disconnect after commitment exchange', function () {
			const { opener, acceptor, acceptorSeed } = setupNormalChannels();

			opener.signCommitment(crypto.randomBytes(64), []);

			acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: crypto.randomBytes(64),
				htlcSignatures: []
			});

			opener.handleRevokeAndAck({
				channelId: opener.getChannelId()!,
				perCommitmentSecret: getPerCommitmentSecret(acceptorSeed, 0n),
				nextPerCommitmentPoint: getPerCommitmentPoint(acceptorSeed, 2n)
			});

			opener.markForReestablish();
			acceptor.markForReestablish();

			const openerReest = decodeChannelReestablishMessage(
				findSendAction(
					opener.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				)!
			);
			const acceptorReest = decodeChannelReestablishMessage(
				findSendAction(
					acceptor.createReestablish(),
					MessageType.CHANNEL_REESTABLISH
				)!
			);

			const openerResult = opener.handleReestablish(acceptorReest);
			const acceptorResult = acceptor.handleReestablish(openerReest);

			expect(findErrorAction(openerResult)).to.be.null;
			expect(findErrorAction(acceptorResult)).to.be.null;

			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

			const htlcResult = opener.addHtlc(
				10_000_000n,
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);
			expect(findErrorAction(htlcResult)).to.be.null;
			expect(findSendAction(htlcResult, MessageType.UPDATE_ADD_HTLC)).to.not.be
				.null;
		});
	});
});
