/**
 * Data loss protection: the "fell behind" recovery flow (BOLT 2).
 *
 * When the peer's channel_reestablish proves OUR restored state is stale
 * (it supplies a per-commitment secret only derivable from our seed at an
 * index we have not reached), we must NOT broadcast our own commitment -
 * it is revoked in the peer's view and would be swept by the justice path.
 * Instead we error out, wait for the peer's force close, and sweep only
 * our to_remote from THEIR (newer) commitment.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState,
	mustNotBroadcastCommitment,
	isRecencyUnproven
} from '../../src/lightning/channel/channel-state';
import { ChannelRecoveryStatus } from '../../src/lightning/recovery/channel-status';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { IChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { classifyCommitmentTx } from '../../src/lightning/chain/output-resolver';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	MonitorState,
	ChainActionType,
	CommitmentType,
	OutputType
} from '../../src/lightning/chain/types';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	signerFromSeed,
	realInitialCommitmentSig,
	realCommitmentSigs
} from './helpers/real-signing';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		privkeys.push(privkey);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(privkeys[0]),
			revocationBasepoint: getPublicKey(privkeys[1]),
			paymentBasepoint: getPublicKey(privkeys[2]),
			delayedPaymentBasepoint: getPublicKey(privkeys[3]),
			htlcBasepoint: getPublicKey(privkeys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		privkeys
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

/**
 * Set up two channels through the full opening handshake into NORMAL state
 * (real basepoints so real commitment txs can be built and classified).
 */
function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
	acceptorPrivkeys: Buffer[];
	openerCommitmentSeed: Buffer;
	acceptorCommitmentSeed: Buffer;
} {
	const openerSeed = Buffer.alloc(32, 0x51);
	const acceptorSeed = Buffer.alloc(32, 0x52);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('dlp-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('dlp-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints, privkeys: acceptorPrivkeys } =
		makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xdc),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitmentSeed
	});

	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xdc),
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: acceptorCommitmentSeed,
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});

	const acceptor = new Channel(acceptorState);
	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));

	// Opening handshake
	const openActions = opener.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL);
	opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

	const fundingTxid = crypto.randomBytes(32);
	const fcActions = opener.createFundingCreated(
		fundingTxid,
		0,
		realInitialCommitmentSig(opener, fundingTxid, 0)
	);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
	const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);
	const fsActions = acceptor.handleFundingCreated(
		decodedFc,
		realInitialCommitmentSig(
			acceptor,
			decodedFc.fundingTxid,
			decodedFc.fundingOutputIndex
		)
	);
	const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
	opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

	const openerReadyActions = opener.fundingConfirmed();
	const openerReadyMsg = findSendAction(
		openerReadyActions,
		MessageType.CHANNEL_READY
	);
	acceptor.handleChannelReady(
		decodeChannelReadyMessage(openerReadyMsg.payload)
	);

	const acceptorReadyActions = acceptor.fundingConfirmed();
	const acceptorReadyMsg = findSendAction(
		acceptorReadyActions,
		MessageType.CHANNEL_READY
	);
	opener.handleChannelReady(
		decodeChannelReadyMessage(acceptorReadyMsg.payload)
	);

	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

	return {
		opener,
		acceptor,
		openerPrivkeys,
		acceptorPrivkeys,
		openerCommitmentSeed,
		acceptorCommitmentSeed
	};
}

/** One full commitment round in each direction (advances both numbers to 1). */
function exchangeCommitments(opener: Channel, acceptor: Channel): void {
	const openerSigs = realCommitmentSigs(opener);
	const commitActions1 = opener.signCommitment(
		openerSigs.signature,
		openerSigs.htlcSignatures
	);
	const commitMsg1 = findSendAction(
		commitActions1,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions1 = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg1.payload)
	);
	const raaMsg1 = findSendAction(raaActions1, MessageType.REVOKE_AND_ACK);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const acceptorSigs = realCommitmentSigs(acceptor);
	const commitActions2 = acceptor.signCommitment(
		acceptorSigs.signature,
		acceptorSigs.htlcSignatures
	);
	const commitMsg2 = findSendAction(
		commitActions2,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions2 = opener.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg2.payload)
	);
	const raaMsg2 = findSendAction(raaActions2, MessageType.REVOKE_AND_ACK);
	acceptor.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg2.payload));
}

/** A valid but unknown-to-the-opener per-commitment point. */
function makeForeignPoint(tag: string): Buffer {
	return perCommitmentPointFromSecret(
		crypto.createHash('sha256').update(Buffer.from(tag)).digest()
	);
}

/**
 * The refusal a wrong yourLastPerCommitmentSecret draws above
 * next_revocation_number 0 (issue #907): the channel fails with the
 * validator's wire error, persisted first, and records no proof of data
 * loss. What the failure may then broadcast is NOT answered here:
 * handleReestablish returns no BROADCAST_TX on any path, the close is driven
 * by the node from the ERRORED-plus-wire-error pair, so each cell asserts the
 * never-broadcast predicate and forceClose itself, and
 * reestablish-secret-hold.test.ts drives the same messages through a node.
 */
function expectWrongSecretRefusal(
	channel: Channel,
	actions: ReturnType<Channel['handleReestablish']>
): void {
	expect(channel.getState()).to.equal(ChannelState.ERRORED);
	// Persist FIRST: the ERRORED row must outlive a crash before the send.
	expect(actions[0].type).to.equal(ChannelActionType.PERSIST_STATE);
	const errSend = findSendAction(actions, MessageType.ERROR);
	expect(errSend, 'a wire error goes to the peer').to.exist;
	const decoded = decodeErrorMessage(errSend.payload);
	expect(decoded.channelId.equals(channel.getChannelId()!)).to.equal(true);
	expect(decoded.data.toString('ascii')).to.contain(
		'Invalid per-commitment secret in channel_reestablish'
	);
	const state = channel.getFullState();
	expect(state.dataLossDetected).to.not.equal(true);
	expect(state.dlpRemotePerCommitmentPoint).to.not.exist;
}

/**
 * The HOLD an unverifiable gap claim lands in (issue #907): the row carries
 * reestablishRecencyUnproven and NOT stateUncertain, so the never-broadcast
 * predicate stays false and the operator's labelled force close remains the
 * exit; the hold predicate every automatic close and new-HTLC admission
 * consults is true; the derived reestablish-unproven disposition regenerates
 * the peer-close request for every reconnect; the status names the hold; the
 * flag survives a serialization round trip; and the channel-level forceClose,
 * which is the operator's route (the daemon gates it behind
 * acceptStaleStateRisk), still builds our commitment.
 */
function expectHeldForPeerClose(channel: Channel, signerPrivkey: Buffer): void {
	const state = channel.getFullState();
	expect(state.reestablishRecencyUnproven).to.equal(true);
	expect(state.stateUncertain).to.not.equal(true);
	expect(state.dataLossDetected).to.not.equal(true);
	expect(state.restoreRecencyUnproven).to.not.equal(true);
	// Derived from the flag, never stamped, exactly as restore-unproven is.
	expect(state.recoveryCloseReason).to.not.exist;
	expect(channel.getRecoveryCloseReason()).to.equal('reestablish-unproven');
	expect(channel.hasRecoveryCloseDisposition()).to.equal(true);
	expect(mustNotBroadcastCommitment(state)).to.equal(false);
	expect(isRecencyUnproven(state)).to.equal(true);
	expect(channel.acceptsNewHtlcs()).to.equal(false);
	expect(channel.isMutualCloseHeld()).to.equal(true);
	expect(channel.getRecoveryStatus()).to.equal(
		ChannelRecoveryStatus.ReestablishRecencyUnproven
	);
	const regenerated = channel.buildRecoveryCloseActions();
	expect(regenerated[0].type).to.equal(ChannelActionType.PERSIST_STATE);
	const request = findSendAction(regenerated, MessageType.ERROR);
	expect(request, 'the peer-close request regenerates').to.exist;
	expect(decodeErrorMessage(request.payload).data.toString('ascii')).to.contain(
		'without the per-commitment secret proving it'
	);
	// A restart must not forget the hold.
	const restored = deserializeChannelState(serializeChannelState(state));
	expect(restored.reestablishRecencyUnproven).to.equal(true);
	expect(restored.stateUncertain).to.not.equal(true);
	expect(restored.state).to.equal(ChannelState.ERRORED);
	expect(isRecencyUnproven(restored)).to.equal(true);
	// The operator's exit: the hold never refuses a force close at this
	// level, so the commitment is built; the daemon is what asks for the
	// acknowledgement first.
	const closeActions = channel.forceClose(new ChannelSigner(signerPrivkey));
	expect(
		closeActions.find((a) => a.type === ChannelActionType.BROADCAST_TX),
		'the labelled operator exit still builds our commitment'
	).to.exist;
	expect(channel.getState()).to.equal(ChannelState.FORCE_CLOSED);
}

describe('DLP fell-behind recovery (BOLT 2 data loss protection)', function () {
	describe('handleReestablish - fell behind detection', function () {
		it('detects data loss when the peer proves a future state with a valid secret', function () {
			const { opener, acceptor, openerCommitmentSeed } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);

			const pre = opener.getFullState();
			// The peer claims to be several rounds ahead of our restored state.
			const nextCommitmentNumber = pre.remoteCommitmentNumber + 3n;
			const nextRevocationNumber = pre.localCommitmentNumber + 3n;
			// The proof: OUR per-commitment secret at an index we (believe we)
			// have not revoked yet - only derivable from our seed, so the peer
			// can only know it if we really did advance there and lost the data.
			const proofSecret = generateFromSeed(
				openerCommitmentSeed,
				MAX_INDEX - (nextRevocationNumber - 1n)
			);
			const peerPoint = makeForeignPoint('peer-current-point');

			opener.markForReestablish();
			const msg: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber,
				nextRevocationNumber,
				yourLastPerCommitmentSecret: proofSecret,
				myCurrentPerCommitmentPoint: peerPoint
			};
			const actions = opener.handleReestablish(msg);

			const state = opener.getFullState();
			expect(state.dataLossDetected).to.equal(true);
			expect(state.dlpRemotePerCommitmentPoint).to.exist;
			expect(state.dlpRemotePerCommitmentPoint!.equals(peerPoint)).to.equal(
				true
			);
			expect(opener.getState()).to.equal(ChannelState.ERRORED);

			// Persist FIRST so a crash cannot forget the broadcast ban.
			expect(actions[0].type).to.equal(ChannelActionType.PERSIST_STATE);

			// A BOLT 1 error goes to the peer so it force-closes.
			const errSend = findSendAction(actions, MessageType.ERROR);
			expect(errSend).to.exist;
			const decoded = decodeErrorMessage(errSend.payload);
			expect(decoded.channelId.equals(opener.getChannelId()!)).to.equal(true);
			expect(decoded.data.toString('ascii')).to.contain('stale');

			// The local error is distinctive and no commitment is broadcast.
			const errAction = actions.find((a) => a.type === ChannelActionType.ERROR);
			expect(errAction).to.exist;
			expect((errAction as { message: string }).message).to.contain(
				'fell behind'
			);
			const broadcast = actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			);
			expect(broadcast).to.not.exist;
		});

		it('refuses an all-zero secret on a counter gap and holds the channel for the peer', function () {
			// The bug (issue #907): with zeroes, the same gap that a real secret
			// turns into the fell-behind proof used to reach the plain gap arm,
			// which sets no broadcast ban. BOLT 2 allows zeroes only at
			// next_revocation_number 0, so above it they are a wrong secret.
			// And a wrong secret at an index this row never released is a claim
			// it can check in neither direction, so the refusal must not put
			// OUR commitment on chain by itself either: the node fails every
			// ERRORED-plus-wire-error pair on chain unless a hold says
			// otherwise, and the hold here is the capsule restore's, not
			// StateUncertain, so the operator's labelled exit stays open.
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);

			const pre = opener.getFullState();
			opener.markForReestablish();
			const msg: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: pre.remoteCommitmentNumber + 3n,
				nextRevocationNumber: pre.localCommitmentNumber + 3n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: crypto.randomBytes(33)
			};
			const actions = opener.handleReestablish(msg);

			expectWrongSecretRefusal(opener, actions);
			expect(
				actions.find(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						(a as { message: string }).message.includes('Remote expects future')
				),
				'the plain gap arms never see it'
			).to.not.exist;
			expectHeldForPeerClose(opener, openerPrivkeys[0]);
		});

		it('holds on any wrong secret at the smallest unreleased index', function () {
			// The class is "a secret we cannot check at an index we never
			// released", not zeroes in particular: next_revocation_number at
			// localCommitmentNumber + 1 names index localCommitmentNumber, the
			// first one this row has not revoked, and a random value there is
			// as unverifiable as zeroes. The fell-behind arm would not have
			// claimed this shape even with the real secret (the sig-in-flight
			// case), so without the hold the refusal alone reached the chain.
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);

			const pre = opener.getFullState();
			opener.markForReestablish();
			const msg: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: pre.remoteCommitmentNumber + 1n,
				nextRevocationNumber: pre.localCommitmentNumber + 1n,
				yourLastPerCommitmentSecret: crypto.randomBytes(32),
				myCurrentPerCommitmentPoint: makeForeignPoint('garbage-plus-one')
			};
			const actions = opener.handleReestablish(msg);

			expectWrongSecretRefusal(opener, actions);
			expectHeldForPeerClose(opener, openerPrivkeys[0]);
		});

		it('refuses an all-zero secret at a compatible non-zero revocation number', function () {
			// Compatible counters do not excuse it either: above 0 the peer MUST
			// send the last secret it received from us, and the validator, not
			// the retransmission logic, answers a wrong one. The index named
			// here (localCommitmentNumber - 1) is one this row DID release, so
			// the wrong value is a plain violation with no claim on our state:
			// no hold, and the node fails the channel on chain as it does for
			// any other wire error.
			const { opener, acceptor } = setupNormalChannels();
			exchangeCommitments(opener, acceptor);

			const pre = opener.getFullState();
			expect(Number(pre.localCommitmentNumber)).to.be.greaterThan(0);
			opener.markForReestablish();
			const msg: IChannelReestablishMessage = {
				channelId: opener.getChannelId()!,
				nextCommitmentNumber: pre.remoteCommitmentNumber + 1n,
				nextRevocationNumber: pre.localCommitmentNumber,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: makeForeignPoint('zeros-level')
			};
			const actions = opener.handleReestablish(msg);

			expectWrongSecretRefusal(opener, actions);
			const state = opener.getFullState();
			expect(state.stateUncertain).to.not.equal(true);
			expect(state.reestablishRecencyUnproven).to.not.equal(true);
			expect(isRecencyUnproven(state)).to.equal(false);
			expect(state.recoveryCloseReason).to.not.exist;
			expect(opener.getRecoveryCloseReason()).to.not.exist;
			expect(mustNotBroadcastCommitment(state)).to.equal(false);
			expect(opener.getRecoveryStatus()).to.equal(
				ChannelRecoveryStatus.ForceClosing
			);
		});
	});

	describe('forceClose - broadcast refusal after data loss', function () {
		it('refuses to broadcast the stale commitment once dataLossDetected is set', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			opener.getFullState().dataLossDetected = true;

			const signer = new ChannelSigner(openerPrivkeys[0]);
			const actions = opener.forceClose(signer);

			expect(actions).to.have.length(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as { message: string }).message).to.contain('stale');
			const broadcast = actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			);
			expect(broadcast).to.not.exist;
			// The channel must not be marked FORCE_CLOSED by the refusal.
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});
	});

	describe('classifyCommitmentTx - future remote commitment', function () {
		it('classifies a commitment beyond our remote number as THEIR_FUTURE_COMMITMENT', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();

			const futureNumber = state.remoteCommitmentNumber + 2n;
			const futurePoint = makeForeignPoint('peer-future-point');
			const built = buildRemoteCommitment(state, futurePoint, futureNumber);

			const result = classifyCommitmentTx(built.result.tx, state);
			expect(result.type).to.equal(CommitmentType.THEIR_FUTURE_COMMITMENT);
			expect(result.commitmentNumber).to.equal(futureNumber);
		});
	});

	describe('Serialization - DLP fields round-trip', function () {
		it('preserves dataLossDetected and dlpRemotePerCommitmentPoint', function () {
			const { opener } = setupNormalChannels();
			const state = opener.getFullState();
			const point = makeForeignPoint('serialized-point');
			state.dataLossDetected = true;
			state.dlpRemotePerCommitmentPoint = point;

			const restored = deserializeChannelState(serializeChannelState(state));
			expect(restored.dataLossDetected).to.equal(true);
			expect(restored.dlpRemotePerCommitmentPoint).to.exist;
			expect(restored.dlpRemotePerCommitmentPoint!.equals(point)).to.equal(
				true
			);
		});

		it('leaves the fields unset for states that never fell behind', function () {
			const { opener } = setupNormalChannels();
			const restored = deserializeChannelState(
				serializeChannelState(opener.getFullState())
			);
			expect(restored.dataLossDetected).to.not.equal(true);
			expect(restored.dlpRemotePerCommitmentPoint).to.not.exist;
		});
	});

	describe('ChainMonitor - future remote commitment sweep', function () {
		it('resolves ONLY the to_remote output when a future commitment confirms', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();

			// An in-flight HTLC so the future commitment carries an HTLC output
			// we must NOT try to claim (its script needs the point we never saw).
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			opener.handleUpdateAddHtlc({
				channelId: opener.getChannelId()!,
				id: 0n,
				amountMsat: 10_000_000n,
				paymentHash,
				cltvExpiry: 500,
				onionRoutingPacket: Buffer.alloc(1366)
			});

			const state = opener.getFullState();
			const futurePoint = makeForeignPoint('monitor-future-point');
			state.dataLossDetected = true;
			state.dlpRemotePerCommitmentPoint = futurePoint;

			const destScript = bitcoin.payments.p2wpkh({
				pubkey: getPublicKey(openerPrivkeys[0]),
				network
			}).output!;
			// Full key material available - the HTLC must still go unclaimed.
			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network,
				openerPrivkeys[3],
				openerPrivkeys[4]
			);
			monitor.addPreimage(paymentHash, preimage);

			const futureNumber = state.remoteCommitmentNumber + 2n;
			const built = buildRemoteCommitment(state, futurePoint, futureNumber);
			const actions = monitor.handleFundingSpent(built.result.tx, 100);

			expect(monitor.getState()).to.equal(MonitorState.RESOLVING);

			// Only to_remote is tracked - to_local/HTLC scripts are unknowable.
			const tracked = monitor.getTrackedOutputs();
			expect(tracked.length).to.equal(1);
			expect(tracked[0].outputType).to.equal(OutputType.TO_REMOTE);

			// The to_remote claim broadcasts immediately (static_remotekey P2WPKH).
			const broadcasts = actions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(broadcasts.length).to.equal(1);
			expect(
				(broadcasts[0] as { description?: string }).description
			).to.contain('to_remote');
		});
	});
});
