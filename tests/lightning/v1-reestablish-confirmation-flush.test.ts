/**
 * Issue #420: a v1 funding confirmation observed while the channel is wrapped
 * in AWAITING_REESTABLISH hits fundingConfirmed's late gate, which stamps
 * fundingConfirmedLate durably and does nothing else. The depth callback is
 * one-shot, so handleReestablish must consume the stamp and run the ready
 * flow the observation was owed — exactly once, never doubled with the
 * BOLT 2 §5 channel_ready retransmit.
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
import {
	ChannelAction,
	ChannelActionType,
	ISendMessageAction
} from '../../src/lightning/channel/channel-actions';
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
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	signerFromSeed,
	realInitialCommitmentSig
} from './helpers/real-signing';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	// Real curve points, derived as sha256(seed || [i]) so signerFromSeed(seed)
	// holds the matching funding/HTLC privkeys.
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

function findAction(
	actions: ChannelAction[],
	type: ChannelActionType
): ChannelAction | undefined {
	return actions.find((a) => a.type === type);
}

function findSendActions(
	actions: ChannelAction[],
	msgType: MessageType
): ISendMessageAction[] {
	return actions.filter(
		(a): a is ISendMessageAction =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

function findSendAction(
	actions: ChannelAction[],
	msgType: MessageType
): ISendMessageAction | undefined {
	return findSendActions(actions, msgType)[0];
}

function reestablishOf(channel: Channel): IChannelReestablishMessage {
	const send = findSendAction(
		channel.createReestablish(),
		MessageType.CHANNEL_REESTABLISH
	)!;
	return decodeChannelReestablishMessage(send.payload);
}

/**
 * Drive a full v1 open between two direct Channel objects and STOP right
 * before fundingConfirmed: both sides sit in AWAITING_FUNDING_CONFIRMED.
 */
function setupPendingChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerBpSeed: Buffer;
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
	const openMsg = decodeOpenChannelMessage(
		findSendAction(openActions, MessageType.OPEN_CHANNEL)!.payload
	);

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
	const acceptMsg = decodeAcceptChannelMessage(
		findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL)!.payload
	);

	// Opener handles accept
	opener.handleAcceptChannel(acceptMsg);

	// Funding
	const fundingTxid = crypto.randomBytes(32);
	const fcActions = opener.createFundingCreated(
		fundingTxid,
		0,
		realInitialCommitmentSig(opener, fundingTxid, 0)
	);
	const decodedFc = decodeFundingCreatedMessage(
		findSendAction(fcActions, MessageType.FUNDING_CREATED)!.payload
	);

	const fsActions = acceptor.handleFundingCreated(
		decodedFc,
		realInitialCommitmentSig(acceptor, fundingTxid, 0)
	);
	opener.handleFundingSigned(
		decodeFundingSignedMessage(
			findSendAction(fsActions, MessageType.FUNDING_SIGNED)!.payload
		)
	);

	// STOP here: no fundingConfirmed on either side.
	expect(opener.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
	expect(acceptor.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);

	return { opener, acceptor, openerBpSeed };
}

/**
 * Zero-conf fixture: both sides fast-track through the ready flow with no
 * chain evidence and reach NORMAL.
 */
function setupZeroConfNormalChannels(): { opener: Channel; acceptor: Channel } {
	const openerSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('zc-opener'))
		.digest();
	const acceptorSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('zc-acceptor'))
		.digest();
	const openerBasepoints = makeBasepoints(openerSeed);
	const acceptorBasepoints = makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xaa),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: crypto
			.createHash('sha256')
			.update(Buffer.from('zc-opener-commitment'))
			.digest()
	});
	openerState.zeroConfEnabled = true;
	openerState.trustedPeer = true;
	openerState.minimumDepth = 0;
	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xaa),
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: crypto
			.createHash('sha256')
			.update(Buffer.from('zc-acceptor-commitment'))
			.digest(),
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	acceptorState.zeroConfEnabled = true;
	acceptorState.trustedPeer = true;
	acceptorState.minimumDepth = 0;
	const acceptor = new Channel(acceptorState);

	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));

	// Opening handshake
	const openActions = opener.initiateOpen();
	const decodedOpen = decodeOpenChannelMessage(
		findSendAction(openActions, MessageType.OPEN_CHANNEL)!.payload
	);
	const acceptActions = acceptor.handleOpenChannel(decodedOpen);
	const decodedAccept = decodeAcceptChannelMessage(
		findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL)!.payload
	);
	opener.handleAcceptChannel(decodedAccept);

	// Funding exchange: zero-conf fast-tracks channel_ready on both sides.
	const fundingTxid = crypto.randomBytes(32);
	const fcActions = opener.createFundingCreated(
		fundingTxid,
		0,
		realInitialCommitmentSig(opener, fundingTxid, 0)
	);
	const decodedFc = decodeFundingCreatedMessage(
		findSendAction(fcActions, MessageType.FUNDING_CREATED)!.payload
	);
	const fsActions = acceptor.handleFundingCreated(
		decodedFc,
		realInitialCommitmentSig(
			acceptor,
			decodedFc.fundingTxid,
			decodedFc.fundingOutputIndex
		)
	);
	const decodedFs = decodeFundingSignedMessage(
		findSendAction(fsActions, MessageType.FUNDING_SIGNED)!.payload
	);

	// Opener receives funding_signed -> auto channel_ready (zero-conf).
	const openerActions = opener.handleFundingSigned(decodedFs);
	const openerReady = findSendAction(openerActions, MessageType.CHANNEL_READY)!;
	// Acceptor fast-tracks too.
	const acceptorReadyActions = acceptor.fundingConfirmed();
	const acceptorReady = findSendAction(
		acceptorReadyActions,
		MessageType.CHANNEL_READY
	)!;

	// Exchange channel_ready to reach NORMAL on both sides.
	opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));
	acceptor.handleChannelReady(decodeChannelReadyMessage(openerReady.payload));

	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

	return { opener, acceptor };
}

/**
 * Common first act of most cases: wrap both sides, stamp the opener-side
 * channel with a while-disconnected confirmation, assert the stamp took and
 * nothing else happened.
 */
function wrapAndStamp(channel: Channel, peer: Channel): void {
	channel.markForReestablish();
	peer.markForReestablish();
	expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);

	const stampActions = channel.fundingConfirmed();
	// Exactly a durable stamp: no channel_ready, no CHANNEL_READY action.
	expect(stampActions).to.deep.equal([
		{ type: ChannelActionType.PERSIST_STATE }
	]);
	expect(channel.getFullState().fundingConfirmedLate).to.equal(true);
	expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
}

/**
 * Assert the reestablish result carries the flush: exactly one NON-replay
 * channel_ready, persist first.
 */
function expectFlushedReady(result: ChannelAction[]): void {
	expect(findAction(result, ChannelActionType.ERROR)).to.equal(undefined);
	const readySends = findSendActions(result, MessageType.CHANNEL_READY);
	expect(readySends).to.have.length(1);
	expect(readySends[0].replay).to.not.equal(true);
	expect(result[0].type).to.equal(ChannelActionType.PERSIST_STATE);
}

describe('v1 reestablish confirmation flush (issue #420)', function () {
	it('opener: a confirmation parked while wrapped flushes exactly one fresh channel_ready on reestablish', function () {
		const { opener, acceptor } = setupPendingChannels();
		wrapAndStamp(opener, acceptor);

		const result = opener.handleReestablish(reestablishOf(acceptor));

		expectFlushedReady(result);
		// Remote not ready yet: the flow parks awaiting the peer's ready.
		expect(findAction(result, ChannelActionType.CHANNEL_READY)).to.equal(
			undefined
		);
		expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
	});

	it('acceptor: the flush works identically on the accept side', function () {
		const { opener, acceptor } = setupPendingChannels();
		wrapAndStamp(acceptor, opener);

		const result = acceptor.handleReestablish(reestablishOf(opener));

		expectFlushedReady(result);
		expect(findAction(result, ChannelActionType.CHANNEL_READY)).to.equal(
			undefined
		);
		expect(acceptor.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
	});

	it('crossed readys: remote-ready-first shape flushes to NORMAL with a CHANNEL_READY action', function () {
		const { opener, acceptor } = setupPendingChannels();

		// The acceptor confirms normally and its channel_ready lands BEFORE the
		// disconnect; ours never left.
		const acceptorReadyActions = acceptor.fundingConfirmed();
		const acceptorReady = findSendAction(
			acceptorReadyActions,
			MessageType.CHANNEL_READY
		)!;
		opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));
		expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);

		wrapAndStamp(opener, acceptor);

		const result = opener.handleReestablish(reestablishOf(acceptor));

		expectFlushedReady(result);
		// Both directions ready now: the channel is open for business.
		expect(findAction(result, ChannelActionType.CHANNEL_READY)).to.not.equal(
			undefined
		);
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
	});

	it('the stamp survives the flush as durable chain evidence', function () {
		const { opener, acceptor } = setupPendingChannels();
		wrapAndStamp(opener, acceptor);

		opener.handleReestablish(reestablishOf(acceptor));

		expect(opener.getFullState().fundingConfirmedLate).to.equal(true);
		expect(opener.isFundingKnownOnChain()).to.equal(true);
	});

	it('restored from disk: the stamp roundtrips, repeat observations are no-ops, and the first reestablish flushes', function () {
		const { opener, acceptor, openerBpSeed } = setupPendingChannels();
		wrapAndStamp(opener, acceptor);

		// Crash + restart at the last persist: the wrapped, stamped row.
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(opener.getFullState()))
		);
		const restored = new Channel(
			deserializeChannelState(json),
			signerFromSeed(openerBpSeed)
		);
		expect(restored.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(restored.getFullState().fundingConfirmedLate).to.equal(true);

		// The stamp is one-shot: a repeat observation while wrapped is silent.
		expect(restored.fundingConfirmed()).to.have.length(0);

		const result = restored.handleReestablish(reestablishOf(acceptor));

		expectFlushedReady(result);
		expect(restored.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
	});

	it('no flush when channel_ready already left: reestablish only retransmits (replay)', function () {
		const { opener, acceptor } = setupPendingChannels();

		// Funding confirms normally BEFORE the disconnect: channel_ready leaves.
		const confirmActions = opener.fundingConfirmed();
		expect(
			findSendAction(confirmActions, MessageType.CHANNEL_READY)
		).to.not.equal(undefined);
		expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);

		opener.markForReestablish();
		acceptor.markForReestablish();

		// A depth observation while wrapped still stamps durably (late gate),
		// but localChannelReady blocks the flush from re-running the flow.
		expect(opener.fundingConfirmed()).to.deep.equal([
			{ type: ChannelActionType.PERSIST_STATE }
		]);
		expect(opener.getFullState().fundingConfirmedLate).to.equal(true);

		const result = opener.handleReestablish(reestablishOf(acceptor));

		const readySends = findSendActions(result, MessageType.CHANNEL_READY);
		expect(readySends).to.have.length(1);
		expect(readySends[0].replay).to.equal(true);
		expect(findAction(result, ChannelActionType.CHANNEL_READY)).to.equal(
			undefined
		);
		expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
	});

	it('second reestablish is idempotent: only the BOLT 2 retransmit, no duplicate ready flow', function () {
		const { opener, acceptor } = setupPendingChannels();
		wrapAndStamp(opener, acceptor);

		const first = opener.handleReestablish(reestablishOf(acceptor));
		expectFlushedReady(first);
		expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);

		// A second disconnect/reconnect cycle.
		opener.markForReestablish();
		const second = opener.handleReestablish(reestablishOf(acceptor));

		const readySends = findSendActions(second, MessageType.CHANNEL_READY);
		expect(readySends).to.have.length(1);
		expect(readySends[0].replay).to.equal(true);
		expect(findAction(second, ChannelActionType.CHANNEL_READY)).to.equal(
			undefined
		);
		// No regression: still parked awaiting the peer's ready.
		expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
		expect(opener.getFullState().fundingConfirmedLate).to.equal(true);
	});

	it('zero-conf: the fast-tracked channel is unaffected by the flush', function () {
		const { opener, acceptor } = setupZeroConfNormalChannels();

		opener.markForReestablish();
		acceptor.markForReestablish();

		// Real depth arrives while disconnected: recorded durably, nothing else
		// (the ready flow already ran with no chain evidence).
		expect(opener.fundingConfirmed()).to.deep.equal([
			{ type: ChannelActionType.PERSIST_STATE }
		]);
		expect(opener.getFullState().fundingConfirmedLate).to.equal(true);

		const result = opener.handleReestablish(reestablishOf(acceptor));

		// Any channel_ready in the batch is the BOLT 2 §5 retransmit (the
		// peer's next_commitment_number is 1), never the flush's fresh flow.
		const readySends = findSendActions(result, MessageType.CHANNEL_READY);
		expect(readySends.filter((a) => a.replay !== true)).to.have.length(0);
		expect(findAction(result, ChannelActionType.CHANNEL_READY)).to.equal(
			undefined
		);
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(opener.getFullState().fundingConfirmedLate).to.equal(true);
	});
});
