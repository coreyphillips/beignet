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
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
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

	// Opening handshake
	const openActions = opener.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL);
	opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

	const fundingTxid = crypto.randomBytes(32);
	const fakeSig = crypto.randomBytes(64);
	const fcActions = opener.createFundingCreated(fundingTxid, 0, fakeSig);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
	const fsActions = acceptor.handleFundingCreated(
		decodeFundingCreatedMessage(fcMsg.payload),
		crypto.randomBytes(64)
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
	const sig1 = crypto.randomBytes(64);
	const commitActions1 = opener.signCommitment(sig1, []);
	const commitMsg1 = findSendAction(
		commitActions1,
		MessageType.COMMITMENT_SIGNED
	);
	const raaActions1 = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(commitMsg1.payload)
	);
	const raaMsg1 = findSendAction(raaActions1, MessageType.REVOKE_AND_ACK);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const sig2 = crypto.randomBytes(64);
	const commitActions2 = acceptor.signCommitment(sig2, []);
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

		it('keeps the plain error when the gap has no DLP proof (all-zero secret)', function () {
			const { opener, acceptor } = setupNormalChannels();
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

			const state = opener.getFullState();
			expect(state.dataLossDetected).to.not.equal(true);
			expect(state.dlpRemotePerCommitmentPoint).to.not.exist;
			expect(opener.getState()).to.not.equal(ChannelState.ERRORED);

			expect(actions).to.have.length(1);
			expect(actions[0].type).to.equal(ChannelActionType.ERROR);
			expect((actions[0] as { message: string }).message).to.contain(
				'Remote expects future commitment'
			);
			expect(findSendAction(actions, MessageType.ERROR)).to.not.exist;
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
