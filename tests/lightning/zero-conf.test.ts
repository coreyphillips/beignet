import { expect } from 'chai';
import crypto from 'crypto';
import { ZeroConfManager } from '../../src/lightning/channel/zero-conf';
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
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
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
import { LightningNode } from '../../src/lightning/node/lightning-node';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
		.digest();
}

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

function findAction(actions: any[], type: ChannelActionType): any {
	return actions.find((a: any) => a.type === type);
}

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

function makeValidPubkey(seedByte: number): string {
	const privkey = crypto
		.createHash('sha256')
		.update(Buffer.from([seedByte]))
		.digest();
	return getPublicKey(privkey).toString('hex');
}

// ─── Tests ───

describe('Zero-Conf Channels', function () {
	// ─── ZeroConfManager ───

	describe('ZeroConfManager', function () {
		let mgr: ZeroConfManager;

		beforeEach(function () {
			mgr = new ZeroConfManager();
		});

		it('should add a trusted peer', function () {
			const pubkey = makeValidPubkey(1);
			mgr.addTrustedPeer(pubkey);
			expect(mgr.isTrustedPeer(pubkey)).to.be.true;
		});

		it('should remove a trusted peer', function () {
			const pubkey = makeValidPubkey(2);
			mgr.addTrustedPeer(pubkey);
			mgr.removeTrustedPeer(pubkey);
			expect(mgr.isTrustedPeer(pubkey)).to.be.false;
		});

		it('should return true for isTrustedPeer with added peer', function () {
			const pubkey = makeValidPubkey(3);
			mgr.addTrustedPeer(pubkey);
			expect(mgr.isTrustedPeer(pubkey)).to.be.true;
		});

		it('should return false for isTrustedPeer with unknown peer', function () {
			const pubkey = makeValidPubkey(4);
			expect(mgr.isTrustedPeer(pubkey)).to.be.false;
		});

		it('should list all trusted peers', function () {
			const p1 = makeValidPubkey(5);
			const p2 = makeValidPubkey(6);
			mgr.addTrustedPeer(p1);
			mgr.addTrustedPeer(p2);
			const list = mgr.listTrustedPeers();
			expect(list).to.have.length(2);
			expect(list).to.include(p1);
			expect(list).to.include(p2);
		});

		it('should clear all trusted peers', function () {
			mgr.addTrustedPeer(makeValidPubkey(7));
			mgr.addTrustedPeer(makeValidPubkey(8));
			mgr.clearTrustedPeers();
			expect(mgr.listTrustedPeers()).to.have.length(0);
		});

		it('should return true for shouldUseZeroConf when trusted + requested', function () {
			const pubkey = makeValidPubkey(9);
			mgr.addTrustedPeer(pubkey);
			expect(mgr.shouldUseZeroConf(pubkey, true)).to.be.true;
		});

		it('should return false for shouldUseZeroConf when not trusted', function () {
			const pubkey = makeValidPubkey(10);
			expect(mgr.shouldUseZeroConf(pubkey, true)).to.be.false;
		});

		it('should return false for shouldUseZeroConf when not requested', function () {
			const pubkey = makeValidPubkey(11);
			mgr.addTrustedPeer(pubkey);
			expect(mgr.shouldUseZeroConf(pubkey, false)).to.be.false;
		});

		it('should handle duplicate add idempotently', function () {
			const pubkey = makeValidPubkey(12);
			mgr.addTrustedPeer(pubkey);
			mgr.addTrustedPeer(pubkey);
			expect(mgr.listTrustedPeers()).to.have.length(1);
		});

		it('should handle removing a non-existent peer as no-op', function () {
			const pubkey = makeValidPubkey(13);
			mgr.removeTrustedPeer(pubkey);
			expect(mgr.listTrustedPeers()).to.have.length(0);
		});

		it('should manage multiple peers independently', function () {
			const p1 = makeValidPubkey(14);
			const p2 = makeValidPubkey(15);
			mgr.addTrustedPeer(p1);
			mgr.addTrustedPeer(p2);
			mgr.removeTrustedPeer(p1);
			expect(mgr.isTrustedPeer(p1)).to.be.false;
			expect(mgr.isTrustedPeer(p2)).to.be.true;
		});
	});

	// ─── Channel state zero-conf fields ───

	describe('Channel state zero-conf fields', function () {
		const seed = Buffer.alloc(32, 0x01);
		const basepoints = makeBasepoints(seed);
		const commitmentSeed = crypto
			.createHash('sha256')
			.update(Buffer.from('seed'))
			.digest();

		it('createOpenerState has zeroConfEnabled = false by default', function () {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitmentSeed
			});
			expect(state.zeroConfEnabled).to.be.false;
		});

		it('createAcceptorState has zeroConfEnabled = false by default', function () {
			const state = createAcceptorState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitmentSeed,
				remoteBasepoints: basepoints,
				remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
			});
			expect(state.zeroConfEnabled).to.be.false;
		});

		it('createOpenerState has trustedPeer = false by default', function () {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitmentSeed
			});
			expect(state.trustedPeer).to.be.false;
		});

		it('can set zeroConfEnabled on state', function () {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitmentSeed
			});
			state.zeroConfEnabled = true;
			expect(state.zeroConfEnabled).to.be.true;
		});

		it('can set trustedPeer on state', function () {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitmentSeed
			});
			state.trustedPeer = true;
			expect(state.trustedPeer).to.be.true;
		});

		it('state preserves zero-conf fields through Channel wrapper', function () {
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: basepoints,
				localPerCommitmentSeed: commitmentSeed
			});
			state.zeroConfEnabled = true;
			state.trustedPeer = true;
			const channel = new Channel(state);
			const fullState = channel.getFullState();
			expect(fullState.zeroConfEnabled).to.be.true;
			expect(fullState.trustedPeer).to.be.true;
		});
	});

	// ─── Channel zero-conf flow ───

	describe('Channel zero-conf flow', function () {
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

		function createTestChannels(opts?: { zeroConf?: boolean }): {
			opener: Channel;
			acceptor: Channel;
		} {
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

			if (opts?.zeroConf) {
				openerState.zeroConfEnabled = true;
				openerState.trustedPeer = true;
				openerState.minimumDepth = 0;
			}

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

			if (opts?.zeroConf) {
				acceptorState.zeroConfEnabled = true;
				acceptorState.trustedPeer = true;
				acceptorState.minimumDepth = 0;
			}

			const acceptor = new Channel(acceptorState);

			return { opener, acceptor };
		}

		function driveOpeningHandshake(opener: Channel, acceptor: Channel): void {
			// Step 1: Opener sends open_channel
			const openActions = opener.initiateOpen();
			const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
			const decodedOpen = decodeOpenChannelMessage(openMsg.payload);

			// Step 2: Acceptor receives, sends accept_channel
			const acceptActions = acceptor.handleOpenChannel(decodedOpen);
			const acceptMsg = findSendAction(
				acceptActions,
				MessageType.ACCEPT_CHANNEL
			);
			const decodedAccept = decodeAcceptChannelMessage(acceptMsg.payload);

			// Step 3: Opener receives accept_channel
			opener.handleAcceptChannel(decodedAccept);
		}

		function driveFunding(opener: Channel, acceptor: Channel): void {
			const fundingTxid = crypto.randomBytes(32);
			const fakeSig = crypto.randomBytes(64);

			// Step 4: Opener creates funding
			const fundingCreatedActions = opener.createFundingCreated(
				fundingTxid,
				0,
				fakeSig
			);
			const fcMsg = findSendAction(
				fundingCreatedActions,
				MessageType.FUNDING_CREATED
			);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			// Step 5: Acceptor responds with funding_signed
			const fakeSig2 = crypto.randomBytes(64);
			const fundingSignedActions = acceptor.handleFundingCreated(
				decodedFc,
				fakeSig2
			);
			const fsMsg = findSendAction(
				fundingSignedActions,
				MessageType.FUNDING_SIGNED
			);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			// Step 6: Opener receives funding_signed
			opener.handleFundingSigned(decodedFs);
		}

		it('normal channel: handleFundingSigned does NOT auto-send channel_ready', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: false });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			const actions = opener.handleFundingSigned(decodedFs);

			// Should NOT contain channel_ready message
			const readyMsg = findSendAction(actions, MessageType.CHANNEL_READY);
			expect(readyMsg).to.be.undefined;
			expect(opener.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
		});

		it('zero-conf opener: handleFundingSigned sends channel_ready immediately', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			const actions = opener.handleFundingSigned(decodedFs);

			// Should contain channel_ready
			const readyMsg = findSendAction(actions, MessageType.CHANNEL_READY);
			expect(readyMsg).to.exist;
			// Opener should be in AWAITING_CHANNEL_READY (sent channel_ready, waiting for remote)
			expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
		});

		it('zero-conf: channel moves to NORMAL after both sides send channel_ready', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			// Opener receives funding_signed, auto-sends channel_ready
			const openerActions = opener.handleFundingSigned(decodedFs);
			const openerReadyMsg = findSendAction(
				openerActions,
				MessageType.CHANNEL_READY
			);
			expect(openerReadyMsg).to.exist;

			// Acceptor sends channel_ready (manually since acceptor side needs confirmation or zero-conf too)
			const acceptorReadyActions = acceptor.fundingConfirmed();
			const acceptorReadyMsg = findSendAction(
				acceptorReadyActions,
				MessageType.CHANNEL_READY
			);
			expect(acceptorReadyMsg).to.exist;

			// Now exchange channel_ready messages
			const decodedOpenerReady = decodeChannelReadyMessage(
				openerReadyMsg.payload
			);
			const decodedAcceptorReady = decodeChannelReadyMessage(
				acceptorReadyMsg.payload
			);

			// Opener handles acceptor's channel_ready
			opener.handleChannelReady(decodedAcceptorReady);
			expect(opener.getState()).to.equal(ChannelState.NORMAL);

			// Acceptor handles opener's channel_ready
			acceptor.handleChannelReady(decodedOpenerReady);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		});

		it('zero-conf: uses SCID alias before real SCID available', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			const openerActions = opener.handleFundingSigned(decodedFs);
			const readyMsg = findSendAction(openerActions, MessageType.CHANNEL_READY);

			// Decode the channel_ready to check it contains an SCID alias
			const decoded = decodeChannelReadyMessage(readyMsg.payload);
			expect(decoded.shortChannelId).to.not.be.null;
			// No real SCID yet (not confirmed)
			expect(opener.getShortChannelId()).to.be.null;
			// But SCID alias should be set
			expect(opener.getScidAlias()).to.not.be.null;
		});

		it('zero-conf: handleChannelReady accepts in SENT_FUNDING_CREATED state', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			// Create funding but don't process funding_signed yet
			const fundingTxid = crypto.randomBytes(32);
			opener.createFundingCreated(fundingTxid, 0, crypto.randomBytes(64));
			expect(opener.getState()).to.equal(ChannelState.SENT_FUNDING_CREATED);

			// Simulate receiving a channel_ready while still in SENT_FUNDING_CREATED
			const fakeChannelReady = {
				channelId: opener.getChannelId() || crypto.randomBytes(32),
				secondPerCommitmentPoint: crypto.randomBytes(33),
				shortChannelId: crypto.randomBytes(8)
			};

			const actions = opener.handleChannelReady(fakeChannelReady);
			// Should not return an error
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.be.undefined;
		});

		it('zero-conf: handleChannelReady accepts in AWAITING_FUNDING_CONFIRMED state', function () {
			const { opener, acceptor } = createTestChannels();
			driveOpeningHandshake(opener, acceptor);
			driveFunding(opener, acceptor);

			expect(opener.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);

			const fakeChannelReady = {
				channelId: opener.getChannelId()!,
				secondPerCommitmentPoint: crypto.randomBytes(33),
				shortChannelId: crypto.randomBytes(8)
			};

			const actions = opener.handleChannelReady(fakeChannelReady);
			const error = findAction(actions, ChannelActionType.ERROR);
			expect(error).to.be.undefined;
		});

		it('zero-conf: channel usable before funding confirms (can add HTLC)', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			const openerActions = opener.handleFundingSigned(decodedFs);
			const openerReadyMsg = findSendAction(
				openerActions,
				MessageType.CHANNEL_READY
			);

			// Acceptor also sends channel_ready
			const acceptorReadyActions = acceptor.fundingConfirmed();
			const acceptorReadyMsg = findSendAction(
				acceptorReadyActions,
				MessageType.CHANNEL_READY
			);

			// Exchange channel_ready
			const decodedAcceptorReady = decodeChannelReadyMessage(
				acceptorReadyMsg.payload
			);
			opener.handleChannelReady(decodedAcceptorReady);
			expect(opener.getState()).to.equal(ChannelState.NORMAL);

			const decodedOpenerReady = decodeChannelReadyMessage(
				openerReadyMsg.payload
			);
			acceptor.handleChannelReady(decodedOpenerReady);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);

			// Now try adding an HTLC (channel is usable before confirmation)
			const htlcActions = opener.addHtlc(
				10_000_000n,
				crypto.randomBytes(32),
				500,
				crypto.randomBytes(1366)
			);
			const htlcMsg = findSendAction(htlcActions, MessageType.UPDATE_ADD_HTLC);
			expect(htlcMsg).to.exist;
		});

		it('zero-conf: fundingConfirmed still works after already being ready', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			const openerActions = opener.handleFundingSigned(decodedFs);
			const openerReadyMsg = findSendAction(
				openerActions,
				MessageType.CHANNEL_READY
			);

			// Acceptor also sends channel_ready
			const acceptorReadyActions = acceptor.fundingConfirmed();
			const acceptorReadyMsg = findSendAction(
				acceptorReadyActions,
				MessageType.CHANNEL_READY
			);

			// Exchange channel_ready to reach NORMAL
			const decodedAcceptorReady = decodeChannelReadyMessage(
				acceptorReadyMsg.payload
			);
			opener.handleChannelReady(decodedAcceptorReady);
			const decodedOpenerReady = decodeChannelReadyMessage(
				openerReadyMsg.payload
			);
			acceptor.handleChannelReady(decodedOpenerReady);

			expect(opener.getState()).to.equal(ChannelState.NORMAL);

			// Now funding confirms for real
			const confirmActions = opener.fundingConfirmed();
			// Should be empty (no error) — channel already in NORMAL
			const err = findAction(confirmActions, ChannelActionType.ERROR);
			expect(err).to.be.undefined;
			expect(confirmActions).to.have.length(0);
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});

		it('both sides zero-conf: immediate NORMAL state', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			// Opener receives funding_signed -> auto channel_ready
			const openerActions = opener.handleFundingSigned(decodedFs);
			const openerReadyMsg = findSendAction(
				openerActions,
				MessageType.CHANNEL_READY
			);
			expect(openerReadyMsg).to.exist;

			// Acceptor also does zero-conf -> auto channel_ready
			const acceptorReadyActions = acceptor.fundingConfirmed();
			const acceptorReadyMsg = findSendAction(
				acceptorReadyActions,
				MessageType.CHANNEL_READY
			);
			expect(acceptorReadyMsg).to.exist;

			// Exchange channel_ready
			const decodedAcceptorReady = decodeChannelReadyMessage(
				acceptorReadyMsg.payload
			);
			opener.handleChannelReady(decodedAcceptorReady);

			const decodedOpenerReady = decodeChannelReadyMessage(
				openerReadyMsg.payload
			);
			acceptor.handleChannelReady(decodedOpenerReady);

			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		});

		it('zero-conf with minimumDepth = 0', function () {
			const { opener } = createTestChannels({ zeroConf: true });
			const state = opener.getFullState();
			expect(state.minimumDepth).to.equal(0);
			expect(state.zeroConfEnabled).to.be.true;
		});

		it('zero-conf: watch funding action has minimumDepth = 0', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			const actions = opener.handleFundingSigned(decodedFs);
			const watchAction = findAction(actions, ChannelActionType.WATCH_FUNDING);
			expect(watchAction).to.exist;
			expect(watchAction.minimumDepth).to.equal(0);
		});

		it('zero-conf opener sends channel_ready with SCID alias', function () {
			const { opener, acceptor } = createTestChannels({ zeroConf: true });
			driveOpeningHandshake(opener, acceptor);

			const fundingTxid = crypto.randomBytes(32);
			const fcActions = opener.createFundingCreated(
				fundingTxid,
				0,
				crypto.randomBytes(64)
			);
			const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
			const decodedFc = decodeFundingCreatedMessage(fcMsg.payload);

			const fakeSig2 = crypto.randomBytes(64);
			const fsActions = acceptor.handleFundingCreated(decodedFc, fakeSig2);
			const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
			const decodedFs = decodeFundingSignedMessage(fsMsg.payload);

			const actions = opener.handleFundingSigned(decodedFs);
			const readyMsg = findSendAction(actions, MessageType.CHANNEL_READY);
			const decoded = decodeChannelReadyMessage(readyMsg.payload);

			// SCID alias should be an 8-byte value
			expect(decoded.shortChannelId).to.exist;
			expect(decoded.shortChannelId!.length).to.equal(8);
		});
	});

	// ─── ChannelManager zero-conf ───

	describe('ChannelManager zero-conf', function () {
		const aliceConfig = makeConfig(1);
		const bobConfig = makeConfig(2);
		const alicePubkey =
			aliceConfig.localBasepoints.fundingPubkey.toString('hex');
		const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

		function createConnectedManagerPair(): {
			alice: ChannelManager;
			bob: ChannelManager;
		} {
			const alice = new ChannelManager(aliceConfig);
			const bob = new ChannelManager(bobConfig);
			alice.on('error', () => {}); // absorb
			bob.on('error', () => {}); // absorb
			connectManagers(alice, alicePubkey, bob, bobPubkey);
			return { alice, bob };
		}

		it('addTrustedPeer / isTrustedPeer works', function () {
			const alice = new ChannelManager(aliceConfig);
			alice.on('error', () => {});
			alice.addTrustedPeer(bobPubkey);
			expect(alice.isTrustedPeer(bobPubkey)).to.be.true;
		});

		it('removeTrustedPeer works', function () {
			const alice = new ChannelManager(aliceConfig);
			alice.on('error', () => {});
			alice.addTrustedPeer(bobPubkey);
			alice.removeTrustedPeer(bobPubkey);
			expect(alice.isTrustedPeer(bobPubkey)).to.be.false;
		});

		it('listTrustedPeers works', function () {
			const alice = new ChannelManager(aliceConfig);
			alice.on('error', () => {});
			alice.addTrustedPeer(bobPubkey);
			alice.addTrustedPeer(alicePubkey);
			const list = alice.listTrustedPeers();
			expect(list).to.have.length(2);
			expect(list).to.include(bobPubkey);
			expect(list).to.include(alicePubkey);
		});

		it('openZeroConfChannel creates channel with zeroConfEnabled', function () {
			const { alice } = createConnectedManagerPair();
			alice.addTrustedPeer(bobPubkey);
			const channel = alice.openZeroConfChannel(bobPubkey, 1_000_000n);
			expect(channel).to.not.be.null;
			expect(channel!.getFullState().zeroConfEnabled).to.be.true;
		});

		it('openZeroConfChannel returns null for untrusted peer', function () {
			const { alice } = createConnectedManagerPair();
			// Don't add bob as trusted
			const channel = alice.openZeroConfChannel(bobPubkey, 1_000_000n);
			expect(channel).to.be.null;
		});

		it('openZeroConfChannel emits error for untrusted peer', function () {
			const alice = new ChannelManager(aliceConfig);
			const errors: string[] = [];
			alice.on('error', (_cid: any, msg: string) => errors.push(msg));
			alice.openZeroConfChannel(bobPubkey, 1_000_000n);
			expect(errors.length).to.be.greaterThan(0);
			expect(errors[0]).to.include('not trusted');
		});

		it('openZeroConfChannel sets minimumDepth = 0 when both sides trust each other', function () {
			const { alice, bob } = createConnectedManagerPair();
			alice.addTrustedPeer(bobPubkey);
			bob.addTrustedPeer(alicePubkey);
			const channel = alice.openZeroConfChannel(bobPubkey, 1_000_000n);
			expect(channel).to.not.be.null;
			// Bob trusts Alice, so Bob's accept_channel has minimumDepth=0
			expect(channel!.getFullState().minimumDepth).to.equal(0);
		});

		it('zero-conf channel: funding_signed triggers immediate channel_ready', function () {
			const managers = createConnectedManagerPair();
			const alice = managers.alice;
			// The open now carries the zero_conf channel type on the wire, so the
			// acceptor must trust the opener too or it rejects the proposal.
			managers.bob.addTrustedPeer(alicePubkey);
			alice.addTrustedPeer(bobPubkey);

			const channel = alice.openZeroConfChannel(bobPubkey, 1_000_000n);
			expect(channel).to.not.be.null;

			// After loopback, channel is SENT_ACCEPT
			expect(channel!.getState()).to.equal(ChannelState.SENT_ACCEPT);

			// Create funding (triggers funding_created -> funding_signed -> auto channel_ready via loopback)
			const fundingTxid = crypto.randomBytes(32);
			alice.createFunding(channel!, fundingTxid, 0, crypto.randomBytes(64));

			// Zero-conf opener should have auto-sent channel_ready and be in AWAITING_CHANNEL_READY
			const state = channel!.getState();
			expect(
				state === ChannelState.AWAITING_CHANNEL_READY ||
					state === ChannelState.NORMAL
			).to.be.true;
		});

		it('zero-conf channel: emits channel:zero-conf-ready event', function () {
			const managers = createConnectedManagerPair();
			const alice = managers.alice;
			// Mutual trust: the zero_conf channel type is rejected otherwise.
			managers.bob.addTrustedPeer(alicePubkey);
			alice.addTrustedPeer(bobPubkey);

			const events: Buffer[] = [];
			alice.on('channel:zero-conf-ready', (channelId: Buffer) => {
				events.push(channelId);
			});

			const channel = alice.openZeroConfChannel(bobPubkey, 1_000_000n);
			expect(channel).to.not.be.null;

			const fundingTxid = crypto.randomBytes(32);
			alice.createFunding(channel!, fundingTxid, 0, crypto.randomBytes(64));

			expect(events.length).to.equal(1);
		});

		it('regular openChannel does not set zeroConfEnabled', function () {
			const { alice } = createConnectedManagerPair();
			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			expect(channel.getFullState().zeroConfEnabled).to.be.false;
		});

		it('handleOpenChannel sets trustedPeer when peer is trusted', function () {
			const { alice, bob } = createConnectedManagerPair();

			// Bob trusts Alice
			bob.addTrustedPeer(alicePubkey);

			// Alice opens a normal channel (triggers open_channel -> accept_channel loopback)
			const channel = alice.openChannel(bobPubkey, 1_000_000n);

			// Drive funding so the channel moves to the permanent map
			const fundingTxid = crypto.randomBytes(32);
			const channelId = alice.createFunding(
				channel,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;
			expect(channelId).to.not.be.null;

			// Verify Bob's side has trustedPeer = true
			const bobChannel = bob.getChannel(channelId);
			expect(bobChannel).to.exist;
			expect(bobChannel!.getFullState().trustedPeer).to.be.true;
		});

		it('multiple zero-conf channels with same peer', function () {
			const managers = createConnectedManagerPair();
			const alice = managers.alice;
			void managers.bob; // needed for loopback routing
			alice.addTrustedPeer(bobPubkey);

			const ch1 = alice.openZeroConfChannel(bobPubkey, 500_000n);
			const ch2 = alice.openZeroConfChannel(bobPubkey, 700_000n);

			expect(ch1).to.not.be.null;
			expect(ch2).to.not.be.null;
			expect(ch1!.getFullState().zeroConfEnabled).to.be.true;
			expect(ch2!.getFullState().zeroConfEnabled).to.be.true;
		});

		it('zero-conf channel reaches NORMAL after full flow', function () {
			const { alice, bob } = createConnectedManagerPair();
			// Mutual trust: the zero_conf channel type is rejected otherwise.
			bob.addTrustedPeer(alicePubkey);
			alice.addTrustedPeer(bobPubkey);

			const channel = alice.openZeroConfChannel(bobPubkey, 1_000_000n);
			expect(channel).to.not.be.null;

			// Create funding
			const fundingTxid = crypto.randomBytes(32);
			const channelId = alice.createFunding(
				channel!,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;
			expect(channelId).to.not.be.null;

			// At this point Alice has auto-sent channel_ready.
			// Bob needs to confirm funding (or also be zero-conf) to send channel_ready back.
			bob.handleFundingConfirmed(channelId);

			// After funding confirmed and channel_ready exchange, channel should be NORMAL
			const aliceChannel = alice.getChannel(channelId);
			expect(aliceChannel).to.exist;
			expect(aliceChannel!.getState()).to.equal(ChannelState.NORMAL);
		});

		it('openZeroConfChannel with pushMsat', function () {
			const { alice } = createConnectedManagerPair();
			alice.addTrustedPeer(bobPubkey);
			const channel = alice.openZeroConfChannel(
				bobPubkey,
				1_000_000n,
				100_000_000n
			);
			expect(channel).to.not.be.null;
			const state = channel!.getFullState();
			expect(state.pushMsat).to.equal(100_000_000n);
			expect(state.zeroConfEnabled).to.be.true;
		});
	});

	// ─── LightningNode zero-conf ───

	describe('LightningNode zero-conf', function () {
		function makeNodeConfig(seedByte: number) {
			const privkey = crypto
				.createHash('sha256')
				.update(Buffer.from(`node-${seedByte}`))
				.digest();
			const pubkey = getPublicKey(privkey);
			const fundingPrivkey = crypto
				.createHash('sha256')
				.update(Buffer.from(`funding-${seedByte}`))
				.digest();

			const seed = makeSeed(seedByte + 50);
			const basepoints = makeBasepoints(seed);

			return {
				nodePrivateKey: privkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: makeSeed(seedByte + 200),
				fundingPrivkey,
				pubkey
			};
		}

		it('addTrustedPeer works', function () {
			const config = makeNodeConfig(1);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			const peerPubkey = makeValidPubkey(99);
			node.addTrustedPeer(peerPubkey);
			expect(node.listTrustedPeers()).to.include(peerPubkey);

			node.destroy();
		});

		it('removeTrustedPeer works', function () {
			const config = makeNodeConfig(2);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			const peerPubkey = makeValidPubkey(98);
			node.addTrustedPeer(peerPubkey);
			node.removeTrustedPeer(peerPubkey);
			expect(node.listTrustedPeers()).to.not.include(peerPubkey);

			node.destroy();
		});

		it('listTrustedPeers works', function () {
			const config = makeNodeConfig(3);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			const p1 = makeValidPubkey(97);
			const p2 = makeValidPubkey(96);
			node.addTrustedPeer(p1);
			node.addTrustedPeer(p2);
			const list = node.listTrustedPeers();
			expect(list).to.have.length(2);
			expect(list).to.include(p1);
			expect(list).to.include(p2);

			node.destroy();
		});

		it('openZeroConfChannel throws for untrusted peer', function () {
			// The legacy helper now routes through openChannel(..., trusted),
			// which validates trust up front and throws, rather than the old
			// emit-error-and-return-null.
			const config = makeNodeConfig(4);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			const peerPubkey = makeValidPubkey(95);
			// Don't add as trusted
			expect(() => node.openZeroConfChannel(peerPubkey, 1_000_000n)).to.throw(
				'not in the trusted set'
			);

			node.destroy();
		});

		it('addTrustedPeer validates pubkey format', function () {
			const config = makeNodeConfig(5);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			expect(() => node.addTrustedPeer('invalid')).to.throw();
			expect(() => node.addTrustedPeer('0x' + '00'.repeat(32))).to.throw();

			node.destroy();
		});

		it('openZeroConfChannel validates pubkey', function () {
			const config = makeNodeConfig(6);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			expect(() => node.openZeroConfChannel('bad', 1_000_000n)).to.throw();

			node.destroy();
		});

		it('openZeroConfChannel validates fundingSatoshis', function () {
			const config = makeNodeConfig(7);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			const peerPubkey = makeValidPubkey(94);
			node.addTrustedPeer(peerPubkey);
			expect(() => node.openZeroConfChannel(peerPubkey, 0n)).to.throw();
			expect(() => node.openZeroConfChannel(peerPubkey, -1n)).to.throw();

			node.destroy();
		});

		it('integration: zero-conf channel opening via node API', function () {
			const config = makeNodeConfig(8);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			const peerPubkey = makeValidPubkey(93);
			node.addTrustedPeer(peerPubkey);

			// Opening won't complete (no peer connected), but should not throw
			// and should return null because peer is trusted but there's no transport
			const channel = node.openZeroConfChannel(peerPubkey, 500_000n);
			expect(channel).to.not.be.null;
			expect(channel!.getFullState().zeroConfEnabled).to.be.true;
			expect(channel!.getFullState().trustedPeer).to.be.true;
			expect(channel!.getFullState().minimumDepth).to.equal(0);

			node.destroy();
		});

		it('defaultFeatures advertises ZERO_CONF as optional', function () {
			const features = LightningNode.defaultFeatures();
			// Advertising only signals capability: zero-conf treatment still
			// requires the peer to be in the trusted set.
			const { Feature } = require('../../src/lightning/features/flags');
			expect(features.hasFeature(Feature.ZERO_CONF)).to.be.true;
			expect(features.isCompulsory(Feature.ZERO_CONF)).to.be.false;
		});

		it('zero-conf trusted peers survive across operations', function () {
			const config = makeNodeConfig(9);
			const node = new LightningNode({
				nodePrivateKey: config.nodePrivateKey,
				channelBasepoints: config.channelBasepoints,
				perCommitmentSeed: config.perCommitmentSeed,
				fundingPrivkey: config.fundingPrivkey
			});
			node.on('node:error', () => {});

			const p1 = makeValidPubkey(92);
			const p2 = makeValidPubkey(91);
			const p3 = makeValidPubkey(90);

			node.addTrustedPeer(p1);
			node.addTrustedPeer(p2);
			node.addTrustedPeer(p3);

			// Open a channel with p1 (message goes to 'message:outbound' since no peer manager)
			const ch = node.openZeroConfChannel(p1, 100_000n);
			expect(ch).to.not.be.null;

			// p2 and p3 should still be trusted
			expect(node.listTrustedPeers()).to.have.length(3);
			expect(node.listTrustedPeers()).to.include(p2);

			// Remove p2
			node.removeTrustedPeer(p2);
			expect(node.listTrustedPeers()).to.have.length(2);
			expect(node.listTrustedPeers()).to.not.include(p2);

			node.destroy();
		});
	});
});
