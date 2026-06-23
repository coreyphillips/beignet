import { expect } from 'chai';
import crypto from 'crypto';
import {
	encodeStfuMessage,
	decodeStfuMessage,
	IStfuMessage
} from '../../src/lightning/message/stfu';
import {
	QuiescenceManager,
	QuiescenceState
} from '../../src/lightning/channel/quiescence';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function findAction(actions: any[], type: ChannelActionType): any {
	return actions.find((a: any) => a.type === type);
}

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
		.digest();
}

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey
	};
}

function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyB) {
				managerB.handleMessage(pubkeyA, type, payload);
			}
		}
	);
	managerB.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyA) {
				managerA.handleMessage(pubkeyB, type, payload);
			}
		}
	);
}

describe('Quiescence (STFU)', function () {
	const openerSeed = Buffer.alloc(32, 0x01);
	const acceptorSeed = Buffer.alloc(32, 0x02);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('opener-commitment'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('acceptor-commitment'))
		.digest();

	const FUNDING_SATOSHIS = 1_000_000n;

	function createTestChannels(): { opener: Channel; acceptor: Channel } {
		const openerBasepoints = makeBasepoints(openerSeed);
		const acceptorBasepoints = makeBasepoints(acceptorSeed);

		const openerState = createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xaa),
			fundingSatoshis: FUNDING_SATOSHIS,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBasepoints,
			localPerCommitmentSeed: openerCommitmentSeed
		});

		const opener = new Channel(openerState);

		const acceptorState = createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xaa),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBasepoints,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: openerBasepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		});

		const acceptor = new Channel(acceptorState);

		return { opener, acceptor };
	}

	function getToNormal(): { opener: Channel; acceptor: Channel } {
		const { opener, acceptor } = createTestChannels();

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
			crypto.randomBytes(64)
		);
		const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
		const fsActions = acceptor.handleFundingCreated(
			decodeFundingCreatedMessage(fcMsg.payload),
			crypto.randomBytes(64)
		);
		const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
		opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

		const openerReady = opener.fundingConfirmed();
		const acceptorReady = acceptor.fundingConfirmed();

		const orMsg = findSendAction(openerReady, MessageType.CHANNEL_READY);
		const arMsg = findSendAction(acceptorReady, MessageType.CHANNEL_READY);

		opener.handleChannelReady(decodeChannelReadyMessage(arMsg.payload));
		acceptor.handleChannelReady(decodeChannelReadyMessage(orMsg.payload));

		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

		return { opener, acceptor };
	}

	// ─────────────── STFU Message encode/decode ───────────────

	describe('STFU Message encode/decode', function () {
		it('should encode valid STFU with initiator=true', function () {
			const channelId = crypto.randomBytes(32);
			const msg: IStfuMessage = { channelId, initiator: true };
			const buf = encodeStfuMessage(msg);
			expect(buf.length).to.equal(33);
			expect(buf[32]).to.equal(1);
		});

		it('should encode valid STFU with initiator=false', function () {
			const channelId = crypto.randomBytes(32);
			const msg: IStfuMessage = { channelId, initiator: false };
			const buf = encodeStfuMessage(msg);
			expect(buf.length).to.equal(33);
			expect(buf[32]).to.equal(0);
		});

		it('should round-trip encode/decode', function () {
			const channelId = crypto.randomBytes(32);
			const original: IStfuMessage = { channelId, initiator: true };
			const encoded = encodeStfuMessage(original);
			const decoded = decodeStfuMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(decoded.initiator).to.equal(true);
		});

		it('should decode with initiator=1', function () {
			const buf = Buffer.alloc(33);
			const channelId = crypto.randomBytes(32);
			channelId.copy(buf, 0);
			buf[32] = 1;
			const decoded = decodeStfuMessage(buf);
			expect(decoded.initiator).to.be.true;
		});

		it('should decode with initiator=0', function () {
			const buf = Buffer.alloc(33);
			const channelId = crypto.randomBytes(32);
			channelId.copy(buf, 0);
			buf[32] = 0;
			const decoded = decodeStfuMessage(buf);
			expect(decoded.initiator).to.be.false;
		});

		it('should throw on too-short payload', function () {
			expect(() => decodeStfuMessage(Buffer.alloc(32))).to.throw(
				'STFU message too short'
			);
		});

		it('should preserve channel ID', function () {
			const channelId = crypto.randomBytes(32);
			const msg: IStfuMessage = { channelId, initiator: false };
			const encoded = encodeStfuMessage(msg);
			const decoded = decodeStfuMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.be.true;
			// Ensure it's a copy, not the same buffer
			expect(decoded.channelId).to.not.equal(channelId);
		});

		it('should produce a payload of length 33', function () {
			const msg: IStfuMessage = {
				channelId: Buffer.alloc(32),
				initiator: true
			};
			const buf = encodeStfuMessage(msg);
			expect(buf.length).to.equal(33);
		});
	});

	// ─────────────── QuiescenceManager state machine ───────────────

	describe('QuiescenceManager state machine', function () {
		it('should start in NORMAL state', function () {
			const qm = new QuiescenceManager();
			expect(qm.getState()).to.equal(QuiescenceState.NORMAL);
		});

		it('should transition to SENT_STFU on initiate()', function () {
			const qm = new QuiescenceManager();
			const ok = qm.initiate();
			expect(ok).to.be.true;
			expect(qm.getState()).to.equal(QuiescenceState.SENT_STFU);
		});

		it('should reject initiate() from non-NORMAL state', function () {
			const qm = new QuiescenceManager();
			qm.initiate();
			const ok = qm.initiate();
			expect(ok).to.be.false;
			expect(qm.getState()).to.equal(QuiescenceState.SENT_STFU);
		});

		it('should handle peer STFU from NORMAL -> RECEIVED_STFU with shouldRespond', function () {
			const qm = new QuiescenceManager();
			const result = qm.handlePeerStfu();
			expect(result.shouldRespond).to.be.true;
			expect(result.error).to.be.undefined;
			expect(qm.getState()).to.equal(QuiescenceState.RECEIVED_STFU);
		});

		it('should complete handshake from RECEIVED_STFU -> QUIESCENT', function () {
			const qm = new QuiescenceManager();
			qm.handlePeerStfu();
			expect(qm.getState()).to.equal(QuiescenceState.RECEIVED_STFU);
			qm.completeHandshake();
			expect(qm.getState()).to.equal(QuiescenceState.QUIESCENT);
		});

		it('should handle peer STFU from SENT_STFU -> QUIESCENT', function () {
			const qm = new QuiescenceManager();
			qm.initiate();
			const result = qm.handlePeerStfu();
			expect(result.shouldRespond).to.be.false;
			expect(result.error).to.be.undefined;
			expect(qm.getState()).to.equal(QuiescenceState.QUIESCENT);
		});

		it('should return error on peer STFU from RECEIVED_STFU', function () {
			const qm = new QuiescenceManager();
			qm.handlePeerStfu();
			const result = qm.handlePeerStfu();
			expect(result.error).to.equal('Unexpected STFU in current state');
			expect(result.shouldRespond).to.be.false;
		});

		it('should return error on peer STFU from QUIESCENT', function () {
			const qm = new QuiescenceManager();
			qm.initiate();
			qm.handlePeerStfu();
			expect(qm.getState()).to.equal(QuiescenceState.QUIESCENT);
			const result = qm.handlePeerStfu();
			expect(result.error).to.equal('Unexpected STFU in current state');
		});

		it('should exit quiescence from QUIESCENT -> NORMAL', function () {
			const qm = new QuiescenceManager();
			qm.initiate();
			qm.handlePeerStfu();
			expect(qm.getState()).to.equal(QuiescenceState.QUIESCENT);
			const ok = qm.exitQuiescence();
			expect(ok).to.be.true;
			expect(qm.getState()).to.equal(QuiescenceState.NORMAL);
		});

		it('should reject exit from non-QUIESCENT state', function () {
			const qm = new QuiescenceManager();
			const ok = qm.exitQuiescence();
			expect(ok).to.be.false;
			expect(qm.getState()).to.equal(QuiescenceState.NORMAL);
		});

		it('should report isQuiescent() true only when QUIESCENT', function () {
			const qm = new QuiescenceManager();
			expect(qm.isQuiescent()).to.be.false;
			qm.initiate();
			expect(qm.isQuiescent()).to.be.false;
			qm.handlePeerStfu();
			expect(qm.isQuiescent()).to.be.true;
		});

		it('should report isQuiescing() true for SENT_STFU, RECEIVED_STFU, QUIESCENT', function () {
			const qm = new QuiescenceManager();
			expect(qm.isQuiescing()).to.be.false;

			qm.initiate();
			expect(qm.isQuiescing()).to.be.true;

			qm.handlePeerStfu();
			expect(qm.isQuiescing()).to.be.true;

			qm.exitQuiescence();
			expect(qm.isQuiescing()).to.be.false;

			// Also check RECEIVED_STFU path
			const qm2 = new QuiescenceManager();
			qm2.handlePeerStfu();
			expect(qm2.isQuiescing()).to.be.true;
		});

		it('should report isInitiator() true when we initiate', function () {
			const qm = new QuiescenceManager();
			expect(qm.isInitiator()).to.be.false;
			qm.initiate();
			expect(qm.isInitiator()).to.be.true;
		});

		it('should report isInitiator() false when peer initiates', function () {
			const qm = new QuiescenceManager();
			qm.handlePeerStfu();
			expect(qm.isInitiator()).to.be.false;
		});

		it('should reset to NORMAL', function () {
			const qm = new QuiescenceManager();
			qm.initiate();
			qm.handlePeerStfu();
			expect(qm.getState()).to.equal(QuiescenceState.QUIESCENT);
			qm.reset();
			expect(qm.getState()).to.equal(QuiescenceState.NORMAL);
			expect(qm.isInitiator()).to.be.false;
		});

		it('should complete full handshake flow (both sides)', function () {
			// Simulate: A initiates, B receives, B responds, A receives response
			const qmA = new QuiescenceManager();
			const qmB = new QuiescenceManager();

			// A initiates
			const initiated = qmA.initiate();
			expect(initiated).to.be.true;
			expect(qmA.getState()).to.equal(QuiescenceState.SENT_STFU);

			// B receives STFU from A
			const resultB = qmB.handlePeerStfu();
			expect(resultB.shouldRespond).to.be.true;
			expect(qmB.getState()).to.equal(QuiescenceState.RECEIVED_STFU);

			// B sends STFU response and completes handshake
			qmB.completeHandshake();
			expect(qmB.getState()).to.equal(QuiescenceState.QUIESCENT);

			// A receives STFU from B
			const resultA = qmA.handlePeerStfu();
			expect(resultA.shouldRespond).to.be.false;
			expect(qmA.getState()).to.equal(QuiescenceState.QUIESCENT);

			// Both are quiescent
			expect(qmA.isQuiescent()).to.be.true;
			expect(qmB.isQuiescent()).to.be.true;
			expect(qmA.isInitiator()).to.be.true;
			expect(qmB.isInitiator()).to.be.false;
		});
	});

	// ─────────────── Channel quiescence integration ───────────────

	describe('Channel quiescence integration', function () {
		it('should send STFU when initiating quiescence', function () {
			const { opener } = getToNormal();
			const actions = opener.initiateQuiescence();
			const stfuMsg = findSendAction(actions, MessageType.STFU);
			expect(stfuMsg).to.exist;
			const decoded = decodeStfuMessage(stfuMsg.payload);
			expect(decoded.initiator).to.be.true;
			expect(decoded.channelId.equals(opener.getChannelId()!)).to.be.true;
		});

		it('should fail to initiate quiescence if not in NORMAL state', function () {
			const { opener } = createTestChannels();
			// Channel is in NONE state
			const actions = opener.initiateQuiescence();
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('not in NORMAL state');
		});

		it('should fail to initiate quiescence with pending HTLCs', function () {
			const { opener } = getToNormal();

			// Add an HTLC
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();
			opener.addHtlc(
				50_000_000n,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);

			const actions = opener.initiateQuiescence();
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('pending HTLCs exist');
		});

		it('should fail to initiate quiescence if already quiescing', function () {
			const { opener } = getToNormal();
			opener.initiateQuiescence();
			const actions = opener.initiateQuiescence();
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('already quiescing');
		});

		it('should respond with STFU and enter QUIESCENT when peer sends STFU', function () {
			const { acceptor } = getToNormal();

			const stfuMsg: IStfuMessage = {
				channelId: acceptor.getChannelId()!,
				initiator: true
			};

			const actions = acceptor.handleStfuMessage(stfuMsg);
			const responseStfu = findSendAction(actions, MessageType.STFU);
			expect(responseStfu).to.exist;
			const decoded = decodeStfuMessage(responseStfu.payload);
			expect(decoded.initiator).to.be.false;

			// Should be quiescent now
			expect(acceptor.isQuiescent()).to.be.true;
			expect(acceptor.getQuiescenceState()).to.equal(QuiescenceState.QUIESCENT);
		});

		it('should enter QUIESCENT when we already sent STFU and receive peer STFU', function () {
			const { opener } = getToNormal();

			// We initiate
			opener.initiateQuiescence();
			expect(opener.getQuiescenceState()).to.equal(QuiescenceState.SENT_STFU);

			// Peer responds
			const stfuMsg: IStfuMessage = {
				channelId: opener.getChannelId()!,
				initiator: false
			};
			const actions = opener.handleStfuMessage(stfuMsg);
			// No response needed (both already sent)
			expect(findSendAction(actions, MessageType.STFU)).to.not.exist;
			expect(opener.isQuiescent()).to.be.true;
		});

		it('should reject STFU with pending HTLCs', function () {
			const { opener, acceptor } = getToNormal();

			// Add an HTLC to acceptor (incoming)
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();
			const addActions = opener.addHtlc(
				50_000_000n,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			const addMsg = findSendAction(addActions, MessageType.UPDATE_ADD_HTLC);
			acceptor.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(addMsg.payload));

			const stfuMsg: IStfuMessage = {
				channelId: acceptor.getChannelId()!,
				initiator: true
			};
			const actions = acceptor.handleStfuMessage(stfuMsg);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('pending HTLCs exist');
		});

		it('should exit quiescence and return to normal', function () {
			const { opener } = getToNormal();

			// Enter quiescence
			opener.initiateQuiescence();
			const stfuMsg: IStfuMessage = {
				channelId: opener.getChannelId()!,
				initiator: false
			};
			opener.handleStfuMessage(stfuMsg);
			expect(opener.isQuiescent()).to.be.true;

			// Exit
			const actions = opener.exitQuiescence();
			expect(actions).to.have.length(0);
			expect(opener.isQuiescent()).to.be.false;
			expect(opener.getQuiescenceState()).to.equal(QuiescenceState.NORMAL);
		});

		it('should reject addHtlc during quiescence', function () {
			const { opener } = getToNormal();

			opener.initiateQuiescence();
			const stfuMsg: IStfuMessage = {
				channelId: opener.getChannelId()!,
				initiator: false
			};
			opener.handleStfuMessage(stfuMsg);
			expect(opener.isQuiescent()).to.be.true;

			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();
			const actions = opener.addHtlc(
				50_000_000n,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('quiescing');
		});

		it('should reject handleUpdateAddHtlc during quiescence', function () {
			const { opener } = getToNormal();

			opener.initiateQuiescence();
			const stfuMsg: IStfuMessage = {
				channelId: opener.getChannelId()!,
				initiator: false
			};
			opener.handleStfuMessage(stfuMsg);

			const fakeHtlcMsg = {
				channelId: opener.getChannelId()!,
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: crypto.randomBytes(1366)
			};
			const actions = opener.handleUpdateAddHtlc(fakeHtlcMsg);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('quiescing');
		});

		it('should return correct quiescence state via getQuiescenceState', function () {
			const { opener } = getToNormal();
			expect(opener.getQuiescenceState()).to.equal(QuiescenceState.NORMAL);
			opener.initiateQuiescence();
			expect(opener.getQuiescenceState()).to.equal(QuiescenceState.SENT_STFU);
		});

		it('should return correct value from isQuiescent()', function () {
			const { opener } = getToNormal();
			expect(opener.isQuiescent()).to.be.false;
			opener.initiateQuiescence();
			expect(opener.isQuiescent()).to.be.false;
			const stfuMsg: IStfuMessage = {
				channelId: opener.getChannelId()!,
				initiator: false
			};
			opener.handleStfuMessage(stfuMsg);
			expect(opener.isQuiescent()).to.be.true;
		});

		it('should persist quiescence state in channel state', function () {
			const { opener } = getToNormal();
			opener.initiateQuiescence();
			const state = opener.getFullState();
			expect(state.quiescenceState).to.equal(QuiescenceState.SENT_STFU);
			expect(state.quiescenceInitiator).to.be.true;
		});

		it('should complete full quiescence flow between opener and acceptor', function () {
			const { opener, acceptor } = getToNormal();

			// Opener initiates quiescence
			const initiateActions = opener.initiateQuiescence();
			const stfuSent = findSendAction(initiateActions, MessageType.STFU);
			expect(stfuSent).to.exist;
			const decodedSent = decodeStfuMessage(stfuSent.payload);
			expect(decodedSent.initiator).to.be.true;
			expect(opener.getQuiescenceState()).to.equal(QuiescenceState.SENT_STFU);

			// Acceptor receives STFU and responds
			const responseActions = acceptor.handleStfuMessage(decodedSent);
			const stfuResponse = findSendAction(responseActions, MessageType.STFU);
			expect(stfuResponse).to.exist;
			const decodedResponse = decodeStfuMessage(stfuResponse.payload);
			expect(decodedResponse.initiator).to.be.false;
			expect(acceptor.isQuiescent()).to.be.true;

			// Opener receives STFU response
			const finalActions = opener.handleStfuMessage(decodedResponse);
			expect(findSendAction(finalActions, MessageType.STFU)).to.not.exist;
			expect(opener.isQuiescent()).to.be.true;

			// Both channels are quiescent
			expect(opener.isQuiescent()).to.be.true;
			expect(acceptor.isQuiescent()).to.be.true;

			// HTLCs should be blocked on both sides
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();
			const openerHtlcActions = opener.addHtlc(
				10_000_000n,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			expect(findAction(openerHtlcActions, ChannelActionType.ERROR)).to.exist;
		});
	});

	// ─────────────── ChannelManager quiescence ───────────────

	describe('ChannelManager quiescence', function () {
		const aliceConfig = makeConfig(10);
		const bobConfig = makeConfig(20);
		const alicePubkey =
			aliceConfig.localBasepoints.fundingPubkey.toString('hex');
		const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

		function createConnectedManagers(): {
			alice: ChannelManager;
			bob: ChannelManager;
		} {
			const alice = new ChannelManager(aliceConfig);
			const bob = new ChannelManager(bobConfig);
			connectManagers(alice, alicePubkey, bob, bobPubkey);
			// Absorb errors
			alice.on('error', () => {});
			bob.on('error', () => {});
			return { alice, bob };
		}

		function openAndReadyChannel(): {
			alice: ChannelManager;
			bob: ChannelManager;
			channelId: Buffer;
		} {
			const { alice, bob } = createConnectedManagers();
			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const fundingTxid = crypto.randomBytes(32);
			const channelId = alice.createFunding(
				channel,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			return { alice, bob, channelId };
		}

		it('should initiate quiescence and send STFU to peer', function () {
			const { alice, channelId } = openAndReadyChannel();
			const result = alice.initiateQuiescence(channelId);
			expect(result.ok).to.be.true;
			const stfuAction = findSendAction(result.actions, MessageType.STFU);
			expect(stfuAction).to.exist;
		});

		it('should return error for unknown channel', function () {
			const { alice } = openAndReadyChannel();
			const fakeChannelId = crypto.randomBytes(32);
			const result = alice.initiateQuiescence(fakeChannelId);
			expect(result.ok).to.be.false;
			expect(result.error).to.contain('Channel not found');
		});

		it('should route STFU message from peer to channel', function () {
			const { alice, bob, channelId } = openAndReadyChannel();
			const aliceChannel = alice.getChannel(channelId)!;
			const bobChannel = bob.getChannel(channelId)!;

			// Alice initiates quiescence via ChannelManager
			// The message is routed to Bob via the loopback
			alice.initiateQuiescence(channelId);

			// Bob's channel should now be quiescent (received STFU and responded)
			expect(bobChannel.isQuiescent()).to.be.true;

			// Alice should also be quiescent because Bob responded via loopback
			expect(aliceChannel.isQuiescent()).to.be.true;
		});

		it('should complete full quiescence flow through ChannelManager', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			const aliceChannel = alice.getChannel(channelId)!;
			const bobChannel = bob.getChannel(channelId)!;

			// Initial state
			expect(aliceChannel.isQuiescent()).to.be.false;
			expect(bobChannel.isQuiescent()).to.be.false;

			// Alice initiates quiescence (loopback delivers to Bob, Bob responds, loopback delivers back)
			const result = alice.initiateQuiescence(channelId);
			expect(result.ok).to.be.true;

			// Both should be quiescent
			expect(aliceChannel.isQuiescent()).to.be.true;
			expect(bobChannel.isQuiescent()).to.be.true;
		});

		it('should block HTLC additions during quiescence', function () {
			const { alice, channelId } = openAndReadyChannel();

			alice.initiateQuiescence(channelId);

			const aliceChannel = alice.getChannel(channelId)!;
			expect(aliceChannel.isQuiescent()).to.be.true;

			// Try to add HTLC
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();
			const result = alice.addHtlc(
				channelId,
				10_000_000n,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			// The actions returned from addHtlc contain an error
			const error = findAction(result.actions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('quiescing');
		});

		it('should quiesce multiple channels independently', function () {
			const { alice, bob } = createConnectedManagers();

			// Open first channel
			const ch1 = alice.openChannel(bobPubkey, 1_000_000n);
			const txid1 = crypto.randomBytes(32);
			const cid1 = alice.createFunding(ch1, txid1, 0, crypto.randomBytes(64))!;
			alice.handleFundingConfirmed(cid1);
			bob.handleFundingConfirmed(cid1);

			// Open second channel
			const ch2 = alice.openChannel(bobPubkey, 2_000_000n);
			const txid2 = crypto.randomBytes(32);
			const cid2 = alice.createFunding(ch2, txid2, 0, crypto.randomBytes(64))!;
			alice.handleFundingConfirmed(cid2);
			bob.handleFundingConfirmed(cid2);

			// Quiesce only first channel
			const result1 = alice.initiateQuiescence(cid1);
			expect(result1.ok).to.be.true;

			const aliceCh1 = alice.getChannel(cid1)!;
			const aliceCh2 = alice.getChannel(cid2)!;

			expect(aliceCh1.isQuiescent()).to.be.true;
			expect(aliceCh2.isQuiescent()).to.be.false;
		});

		it('should return channel to normal after exit', function () {
			const { alice, channelId } = openAndReadyChannel();

			alice.initiateQuiescence(channelId);

			const aliceChannel = alice.getChannel(channelId)!;
			expect(aliceChannel.isQuiescent()).to.be.true;

			// Exit quiescence
			const exitActions = aliceChannel.exitQuiescence();
			expect(exitActions).to.have.length(0);
			expect(aliceChannel.isQuiescent()).to.be.false;
			expect(aliceChannel.getQuiescenceState()).to.equal(
				QuiescenceState.NORMAL
			);

			// Should be able to add HTLCs again
			const paymentHash = crypto
				.createHash('sha256')
				.update(crypto.randomBytes(32))
				.digest();
			const htlcActions = aliceChannel.addHtlc(
				10_000_000n,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			const stfuMsg = findSendAction(htlcActions, MessageType.UPDATE_ADD_HTLC);
			expect(stfuMsg).to.exist;
		});

		it('should handle error for invalid quiescence state transitions', function () {
			const { alice, channelId } = openAndReadyChannel();

			const aliceChannel = alice.getChannel(channelId)!;

			// Exit quiescence when not quiescent
			const exitActions = aliceChannel.exitQuiescence();
			const error = findAction(exitActions, ChannelActionType.ERROR);
			expect(error).to.exist;
			expect(error.message).to.contain('not quiescent');
		});
	});
});
