/**
 * Phase 1: Robust channel_reestablish (BOLT 2 §5) tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
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
import { decodeFundingSignedMessage } from '../../src/lightning/message/channel-funding';
import {
	signerFromSeed,
	realInitialCommitmentSig,
	realCommitmentSigs
} from './helpers/real-signing';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	// Real curve points: open/accept validation now rejects off-curve
	// basepoints (BOLT 2 LOW hardening). Derived as sha256(seed || [i]) so
	// signerFromSeed(seed) holds the matching funding/HTLC privkeys.
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
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
	const openerBpSeed = crypto.randomBytes(32);
	const acceptorBpSeed = crypto.randomBytes(32);
	const openerBp = makeBasepoints(openerBpSeed);
	const acceptorBp = makeBasepoints(acceptorBpSeed);

	const opener = createOpenerChannel({
		fundingSatoshis: 1_000_000n,
		localBasepoints: openerBp,
		localPerCommitmentSeed: openerSeed
	});
	opener.setSigner(signerFromSeed(openerBpSeed));

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
	acceptor.setSigner(signerFromSeed(acceptorBpSeed));
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
	const sig = realInitialCommitmentSig(opener, fundingTxid, 0);
	opener.createFundingCreated(fundingTxid, 0, sig);

	const channelId = opener.getChannelId()!;

	// Acceptor handles funding_created
	const fsActions = acceptor.handleFundingCreated(
		{
			temporaryChannelId: opener.getTemporaryChannelId(),
			fundingTxid,
			fundingOutputIndex: 0,
			signature: sig
		},
		realInitialCommitmentSig(acceptor, fundingTxid, 0)
	);

	// Opener handles funding_signed
	opener.handleFundingSigned(
		decodeFundingSignedMessage(
			findSendAction(fsActions, MessageType.FUNDING_SIGNED)!
		)
	);

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
				localBasepoints: makeBasepoints(crypto.randomBytes(32)),
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

			const openerSigs = realCommitmentSigs(opener);
			const revokeActions = acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: openerSigs.signature,
				htlcSignatures: openerSigs.htlcSignatures
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

			const openerSigs = realCommitmentSigs(opener);
			opener.signCommitment(openerSigs.signature, openerSigs.htlcSignatures);
			acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: openerSigs.signature,
				htlcSignatures: openerSigs.htlcSignatures
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
			const { opener, acceptor, acceptorSeed } = setupNormalChannels();
			const openerSigs = realCommitmentSigs(opener);
			acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: openerSigs.signature,
				htlcSignatures: openerSigs.htlcSignatures
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
			const basepoints = makeBasepoints(crypto.randomBytes(32));
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
			const basepoints = makeBasepoints(crypto.randomBytes(32));
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
			// option_taproot: the peer's signing nonce for the current commitment is
			// persisted so a restored taproot channel can still force-close.
			state.remoteSigningNonce = crypto.randomBytes(66);
			const serialized = serializeChannelState(state);
			const deserialized = deserializeChannelState(serialized);

			expect(deserialized.remoteSigningNonce, 'remoteSigningNonce round-trips')
				.to.not.be.undefined;
			expect(deserialized.remoteSigningNonce!.equals(state.remoteSigningNonce!))
				.to.be.true;
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

	describe('static channel reserve repair (issue 381)', function () {
		/**
		 * A row as it exists on disk, with the fields the repair reads set by the
		 * caller. Built by round-tripping a real NORMAL channel so every other
		 * field is genuine.
		 *
		 * LEGACY by default: the version stamp the open sites write is stripped,
		 * which is the whole population the repair exists for. Pass `recorded` for
		 * a row written by a build that had the stamp, and note that the fixture
		 * has to opt IN to that rather than out, so a test cannot accidentally
		 * assert the repair's conservative value against a row that negotiated
		 * something better.
		 */
		function restoredRow(overrides: {
			fundingSatoshis: string;
			channelReserveSatoshis: string;
			dustLimitSatoshis?: string;
			remoteDustLimitSatoshis?: string;
			fundingVersion?: 1 | 2;
			acceptorRole?: boolean;
			spliced?: boolean;
			recorded?: boolean;
		}): Channel {
			const { opener, acceptor } = setupNormalChannels();
			const source = overrides.acceptorRole ? acceptor : opener;
			const json = JSON.parse(
				JSON.stringify(serializeChannelState(source.getFullState()))
			);
			if (!overrides.recorded) {
				delete json.channelReserveVersion;
			}
			json.fundingSatoshis = overrides.fundingSatoshis;
			json.localConfig.channelReserveSatoshis =
				overrides.channelReserveSatoshis;
			if (overrides.dustLimitSatoshis !== undefined) {
				json.localConfig.dustLimitSatoshis = overrides.dustLimitSatoshis;
			}
			if (overrides.remoteDustLimitSatoshis !== undefined) {
				json.remoteConfig.dustLimitSatoshis = overrides.remoteDustLimitSatoshis;
			}
			if (overrides.fundingVersion !== undefined) {
				json.fundingVersion = overrides.fundingVersion;
			}
			if (overrides.spliced) {
				json.spliceFundingTxid = 'ab'.repeat(32);
			}
			return new Channel(deserializeChannelState(json));
		}

		const reserveOf = (c: Channel): bigint =>
			c.getFullState().localConfig.channelReserveSatoshis;

		it('repairs a v1 row that predates the derivation (issue 381)', function () {
			// The open sites now record what they advertise, but they cannot
			// reach a channel that is already open: without this the change
			// repairs nothing that exists, and a 150,000-sat channel keeps
			// refusing every peer HTLC that leaves it under 10,000.
			const channel = restoredRow({
				fundingSatoshis: '150000',
				channelReserveSatoshis: '10000'
			});
			channel.repairEnforcedChannelReserve();
			expect(reserveOf(channel)).to.equal(1_500n);
		});

		it('never raises the reserve of a row that predates the derivation (issue 381)', function () {
			// Above 1,000,000 sat the derived value is the larger one. Adopting
			// it would start refusing HTLCs the peer believes are legal, which is
			// the failure this repair exists to end, so the repair only lowers.
			const channel = restoredRow({
				fundingSatoshis: '5000000',
				channelReserveSatoshis: '10000'
			});
			channel.repairEnforcedChannelReserve();
			expect(reserveOf(channel)).to.equal(10_000n);
		});

		it('leaves an already-derived row alone, and is idempotent (issue 381)', function () {
			// reserveWeEnforceAt reads nothing the repair writes, so min against it
			// is a fixed point after one application. That, not a gate, is what
			// makes it safe to run on every load and safe to compose with the
			// splice adoption tail, which takes the same min.
			const channel = restoredRow({
				fundingSatoshis: '150000',
				channelReserveSatoshis: '1500'
			});
			channel.repairEnforcedChannelReserve();
			expect(reserveOf(channel)).to.equal(1_500n);
			channel.repairEnforcedChannelReserve();
			expect(reserveOf(channel)).to.equal(1_500n);
		});

		it('prices a v2 row by the derived rule, not the v1 one (issue 381, issue 387)', function () {
			// fundingVersion is persisted and survives splice adoption, so a
			// confirmed v2 row IS distinguishable. Pricing it with the v1 helper
			// gets it wrong in both directions: here the 20% cap would pull a
			// correctly derived 1,062 down to 1,000, and on a 20,000-sat row the
			// 546-sat policy floor would push 354 up to 546.
			const capped = restoredRow({
				fundingSatoshis: '5000',
				channelReserveSatoshis: '1062',
				dustLimitSatoshis: '1062',
				remoteDustLimitSatoshis: '1062',
				fundingVersion: 2
			});
			capped.repairEnforcedChannelReserve();
			expect(reserveOf(capped)).to.equal(1_062n);

			// And a v2 row still carrying the static value (issue 387: nothing
			// re-derived either reserve for rows opened before #383) is repaired
			// to what the v2 rule prices, which is below what the v1 one would.
			const stale = restoredRow({
				fundingSatoshis: '20000',
				channelReserveSatoshis: '10000',
				remoteDustLimitSatoshis: '546',
				fundingVersion: 2
			});
			stale.repairEnforcedChannelReserve();
			expect(reserveOf(stale)).to.equal(354n);

			// Issue 387's own worked example, which the configuration gate used to
			// skip on any node whose configured reserve was not exactly 10,000.
			const established = restoredRow({
				fundingSatoshis: '150000',
				channelReserveSatoshis: '10000',
				fundingVersion: 2
			});
			established.repairEnforcedChannelReserve();
			expect(reserveOf(established)).to.equal(1_500n);
		});

		it('repairs a row whose node configuration has since changed (issue 381)', function () {
			// The old gate was "the stored value still equals the node's
			// configured one", so an operator who changed channelReserveSatoshis
			// between opening this channel and this restart skipped the repair
			// forever and kept the whole force-closing band. The derivation reads
			// the row alone, so the configuration cannot make a row unrepairable.
			const channel = restoredRow({
				fundingSatoshis: '150000',
				channelReserveSatoshis: '25000'
			});
			channel.repairEnforcedChannelReserve();
			expect(reserveOf(channel)).to.equal(1_500n);
		});

		it('keeps a negotiated reserve that a site actually recorded (issue 381)', function () {
			// The conservative re-derivation is right for an UNMARKED row and
			// wrong for a marked one. A modern v1 acceptor advertises and stores
			// max(1% of capacity, both dust limits), so on 50,000 sat against a
			// 1,000-sat peer dust limit it promised 1,000; re-deriving 546 would
			// hand a faulty or hostile peer 454 sats of room BOLT 2 makes the
			// RECEIVER responsible for refusing, and would make
			// IChannelInfo.remoteReserveMsat disagree with the negotiation. The
			// version stamp is what tells the two rows apart.
			const recorded = restoredRow({
				fundingSatoshis: '50000',
				channelReserveSatoshis: '1000',
				remoteDustLimitSatoshis: '1000',
				acceptorRole: true,
				recorded: true
			});
			recorded.repairEnforcedChannelReserve();
			expect(reserveOf(recorded)).to.equal(1_000n);
			// Idempotent from the other side too: a marked row is never touched,
			// however many times the node restarts.
			recorded.repairEnforcedChannelReserve();
			expect(reserveOf(recorded)).to.equal(1_000n);
		});

		it('errs low rather than high on an acceptor row (issue 381)', function () {
			// TODAY's acceptor site advertises max(1% of capacity, both dusts), so
			// it would have put 1,000 on the wire here. Re-deriving THAT would
			// wedge the very rows this repair exists for: the peer-dust floor
			// arrived in PR #115 and our own in #381, while computeChannelReserve
			// itself has not changed since the first commit, so a row written
			// before either advertised the unfloored 546 and nothing on disk tells
			// the two apart. Landing above what the peer keeps is the force-close
			// chain; landing below is inert, because the peer's own gate binds.
			const channel = restoredRow({
				fundingSatoshis: '50000',
				channelReserveSatoshis: '10000',
				remoteDustLimitSatoshis: '1000',
				acceptorRole: true
			});
			channel.repairEnforcedChannelReserve();
			expect(reserveOf(channel)).to.equal(546n);
		});

		it('prices a row that has been spliced by the derived rule (issue 381, issue 382)', function () {
			// eclair switches a channel to the derived reserve rule the moment it
			// is spliced (fundingTxIndex > 0), v1 included, and keeps
			// max(1% of capacity, a dust limit). computeChannelReserve's 546-sat
			// policy floor sits above that, so pricing a spliced-down v1 row by the
			// negotiated rule leaves a 192-sat band of refusals the peer believes
			// are legal. spliceFundingTxid is the durable marker: persisted, null
			// until the first adoption, never cleared.
			const spliced = restoredRow({
				fundingSatoshis: '20000',
				channelReserveSatoshis: '10000',
				spliced: true
			});
			spliced.repairEnforcedChannelReserve();
			expect(reserveOf(spliced)).to.equal(354n);

			// The same row that has never been spliced keeps the negotiated rule,
			// so the repair still lands exactly on what its open_channel
			// advertised rather than under it.
			const unspliced = restoredRow({
				fundingSatoshis: '20000',
				channelReserveSatoshis: '10000'
			});
			unspliced.repairEnforcedChannelReserve();
			expect(reserveOf(unspliced)).to.equal(546n);
		});

		it('is a no-op on a row the open sites already derived (issue 381)', function () {
			// The point of the change: what a v1 open advertises is what it
			// enforces. A repair that moved a correctly derived row would undo
			// that on the first restart.
			for (const [capacity, reserve] of [
				['150000', 1_500n],
				['20000', 546n],
				['5000000', 50_000n]
			] as const) {
				const channel = restoredRow({
					fundingSatoshis: capacity,
					channelReserveSatoshis: reserve.toString()
				});
				channel.repairEnforcedChannelReserve();
				expect(reserveOf(channel)).to.equal(reserve);
			}
		});

		it('leaves an unfunded row alone (issue 381)', function () {
			// A capacity of zero prices a reserve of zero, which would disable
			// enforcement outright. Nothing restorable should carry it, so the
			// guard is a backstop rather than a live path.
			const channel = restoredRow({
				fundingSatoshis: '0',
				channelReserveSatoshis: '10000'
			});
			channel.repairEnforcedChannelReserve();
			expect(reserveOf(channel)).to.equal(10_000n);
		});

		it('runs on the ordinary restore path (issue 381)', function () {
			// The repair is only worth anything if it is wired into the load the
			// node actually performs, not just callable.
			const channel = restoredRow({
				fundingSatoshis: '150000',
				channelReserveSatoshis: '10000'
			});
			const manager = new ChannelManager({
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(crypto.randomBytes(32)),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32),
				htlcBasepointSecret: crypto.randomBytes(32)
			});
			manager.on('error', () => {
				/* restore emits nothing here; absorb regardless */
			});
			manager.restoreChannel(channel, 'ab'.repeat(33));
			expect(reserveOf(channel)).to.equal(1_500n);
		});
	});

	describe('Full two-party reestablish simulation', function () {
		it('should recover from disconnect after commitment exchange', function () {
			const { opener, acceptor, acceptorSeed } = setupNormalChannels();

			const openerSigs = realCommitmentSigs(opener);
			opener.signCommitment(openerSigs.signature, openerSigs.htlcSignatures);

			acceptor.handleCommitmentSigned({
				channelId: acceptor.getChannelId()!,
				signature: openerSigs.signature,
				htlcSignatures: openerSigs.htlcSignatures
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
