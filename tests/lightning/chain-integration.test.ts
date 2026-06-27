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
	DEFAULT_CHANNEL_CONFIG,
	ChannelRole
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
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
import { decodeUpdateFeeMessage } from '../../src/lightning/message/channel-update';
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import { buildClosingTx } from '../../src/lightning/chain/closing';
import {
	MonitorState,
	ChainActionType,
	OutputType
} from '../../src/lightning/chain/types';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	perCommitmentPointFromSecret,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../src/lightning/keys/derivation';
import {
	buildToLocalScript,
	calculateObscuredCommitmentNumber
} from '../../src/lightning/script/commitment';

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

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

function makeP2wpkhScript(pubkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({ pubkey, network }).output!;
}

/**
 * Set up two channels through the full opening handshake into NORMAL state.
 * Returns both channels and their private key material.
 */
function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
	acceptorPrivkeys: Buffer[];
	openerCommitmentSeed: Buffer;
	acceptorCommitmentSeed: Buffer;
	openerBasepoints: IChannelBasepoints;
	acceptorBasepoints: IChannelBasepoints;
} {
	const openerSeed = Buffer.alloc(32, 0x41);
	const acceptorSeed = Buffer.alloc(32, 0x42);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('integration-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('integration-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints, privkeys: acceptorPrivkeys } =
		makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xdd),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitmentSeed
	});

	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xdd),
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
		acceptorCommitmentSeed,
		openerBasepoints,
		acceptorBasepoints
	};
}

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

describe('Chain Integration (Phase 4D)', function () {
	describe('Force Close via Channel', function () {
		it('should force close and return BROADCAST_TX + CHANNEL_CLOSED', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();

			const signer = new ChannelSigner(openerPrivkeys[0]);
			const actions = opener.forceClose(signer);

			expect(opener.getState()).to.equal(ChannelState.FORCE_CLOSED);

			const broadcastAction = actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			);
			expect(broadcastAction).to.exist;
			expect((broadcastAction as any).tx).to.be.instanceOf(Buffer);
			expect((broadcastAction as any).tx.length).to.be.greaterThan(0);

			const closedAction = actions.find(
				(a) => a.type === ChannelActionType.CHANNEL_CLOSED
			);
			expect(closedAction).to.exist;
		});

		it('re-running force close rebroadcasts the identical commitment (recovery path)', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const signer = new ChannelSigner(openerPrivkeys[0]);

			const first = opener.forceClose(signer);
			const firstTx = (
				first.find((a) => a.type === ChannelActionType.BROADCAST_TX) as any
			).tx;

			// A second call is the rebroadcast path (the first broadcast may have
			// never reached the network): deterministic signing yields the
			// byte-identical commitment, no error.
			const second = opener.forceClose(signer);
			const errorAction = second.find(
				(a) => a.type === ChannelActionType.ERROR
			);
			expect(errorAction).to.be.undefined;
			const secondTx = (
				second.find((a) => a.type === ChannelActionType.BROADCAST_TX) as any
			).tx;
			expect(secondTx.equals(firstTx), 'rebroadcast is byte-identical').to.be
				.true;
		});

		it('should reject force close in wrong state', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const signer = new ChannelSigner(openerPrivkeys[0]);

			// A cooperatively-closed channel has nothing to force close.
			opener.getFullState().state = ChannelState.CLOSED;
			const actions = opener.forceClose(signer);
			const errorAction = actions.find(
				(a) => a.type === ChannelActionType.ERROR
			);
			expect(errorAction).to.exist;
		});

		it('should produce a valid commitment transaction', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();

			const signer = new ChannelSigner(openerPrivkeys[0]);
			const actions = opener.forceClose(signer);

			const broadcastAction = actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			);
			expect(broadcastAction).to.exist;

			// Parse the broadcast tx
			const tx = bitcoin.Transaction.fromBuffer((broadcastAction as any).tx);
			expect(tx.version).to.equal(2);
			expect(tx.ins).to.have.length(1);
			expect(tx.outs.length).to.be.greaterThan(0);

			// Should have witness (2-of-2 multisig)
			expect(tx.ins[0].witness).to.have.length(4);
		});
	});

	describe('Force Close via ChannelManager', function () {
		it('should emit broadcast event when force closing', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();

			// Create a ChannelManager-like setup
			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};

			const manager = new ChannelManager(config);

			// Manually register the channel
			const channelId = opener.getChannelId()!;
			(manager as any).channels.set(channelId.toString('hex'), opener);
			(manager as any).channelPeers.set(channelId.toString('hex'), 'test-peer');

			let broadcastEmitted = false;
			manager.on('broadcast:tx', () => {
				broadcastEmitted = true;
			});

			let closedEmitted = false;
			manager.on('channel:closed', () => {
				closedEmitted = true;
			});

			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));
			const result = manager.forceClose(channelId, destScript, 10, network);

			expect(result.ok).to.be.true;
			expect(result.actions.length).to.be.greaterThan(0);
			expect(broadcastEmitted).to.be.true;
			expect(closedEmitted).to.be.true;

			// Monitor should be created
			const monitor = manager.getMonitor(channelId);
			expect(monitor).to.exist;
		});

		it('persists the monitor immediately on force close (monitor:updated)', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();
			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};
			const manager = new ChannelManager(config);
			const channelId = opener.getChannelId()!;
			(manager as any).channels.set(channelId.toString('hex'), opener);
			(manager as any).channelPeers.set(channelId.toString('hex'), 'test-peer');

			// Without this emit the monitor only reaches storage once the funding
			// spend is detected — if the session ends first, the next restore sees
			// FORCE_CLOSED with no monitor and never watches the funding again.
			const persisted: string[] = [];
			manager.on('monitor:updated', (cidHex: string) => persisted.push(cidHex));

			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));
			const result = manager.forceClose(channelId, destScript, 10, network);
			expect(result.ok).to.be.true;
			expect(persisted).to.include(channelId.toString('hex'));
		});
	});

	describe('End-to-end Cooperative Close', function () {
		it('should detect cooperative close and fully resolve', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const config: IChannelManagerConfig = {
				localBasepoints: state.localBasepoints,
				localPerCommitmentSeed: state.localPerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};

			const manager = new ChannelManager(config);
			const channelId = opener.getChannelId()!;
			(manager as any).channels.set(channelId.toString('hex'), opener);
			(manager as any).channelPeers.set(channelId.toString('hex'), 'test-peer');

			// Build a cooperative closing tx
			const closingResult = buildClosingTx({
				fundingTxid: state.fundingTxid!.toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex,
				fundingAmount: state.fundingSatoshis,
				localScriptPubkey: destScript,
				remoteScriptPubkey: Buffer.alloc(22, 0x02),
				localAmount: 800_000n,
				remoteAmount: 199_000n,
				feeAmount: 1_000n
			});

			let resolvedEmitted = false;
			manager.on('channel:resolved', () => {
				resolvedEmitted = true;
			});

			const chainActions = manager.handleFundingSpent(
				channelId,
				closingResult.tx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Should be fully resolved immediately
			expect(resolvedEmitted).to.be.true;

			const resolvedAction = chainActions.find(
				(a) => a.type === ChainActionType.CHANNEL_FULLY_RESOLVED
			);
			expect(resolvedAction).to.exist;

			const monitor = manager.getMonitor(channelId);
			expect(monitor).to.exist;
			expect(monitor!.isFullyResolved()).to.be.true;
		});
	});

	describe('Offline-close reconciliation (restart detection)', function () {
		// When a channel is closed on-chain while the node is offline, the chain
		// watcher detects the funding spend on restart. handleFundingSpent() must
		// reconcile the Channel state machine (not just the ChainMonitor) so that
		// listChannels() reflects reality instead of staying AWAITING_REESTABLISH.

		it('should transition an AWAITING_REESTABLISH channel to CLOSED on a detected cooperative close', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// Simulate a restored channel still waiting to reestablish.
			(opener as any)._state.state = ChannelState.AWAITING_REESTABLISH;

			const config: IChannelManagerConfig = {
				localBasepoints: state.localBasepoints,
				localPerCommitmentSeed: state.localPerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};
			const manager = new ChannelManager(config);
			const channelId = opener.getChannelId()!;
			(manager as any).channels.set(channelId.toString('hex'), opener);
			(manager as any).channelPeers.set(channelId.toString('hex'), 'test-peer');

			const closingResult = buildClosingTx({
				fundingTxid: state.fundingTxid!.toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex,
				fundingAmount: state.fundingSatoshis,
				localScriptPubkey: destScript,
				remoteScriptPubkey: Buffer.alloc(22, 0x02),
				localAmount: 800_000n,
				remoteAmount: 199_000n,
				feeAmount: 1_000n
			});

			let closedChannelId: Buffer | null = null;
			manager.on('channel:closed', (id: Buffer) => {
				closedChannelId = id;
			});

			manager.handleFundingSpent(
				channelId,
				closingResult.tx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			expect(opener.getState()).to.equal(ChannelState.CLOSED);
			expect(closedChannelId).to.not.be.null;
			expect((closedChannelId as unknown as Buffer).equals(channelId)).to.be
				.true;
		});

		it('should transition an AWAITING_REESTABLISH channel to FORCE_CLOSED on a detected commitment broadcast', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();
			const signer = new ChannelSigner(openerPrivkeys[0]);
			const channelId = opener.getChannelId()!;
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// Capture our commitment tx, then reset to simulate a restored channel
			// that hasn't yet learned about the on-chain force close.
			const forceCloseActions = opener.forceClose(signer);
			const broadcastAction = forceCloseActions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			);
			const commitmentTx = bitcoin.Transaction.fromBuffer(
				(broadcastAction as any).tx
			);
			(opener as any)._state.state = ChannelState.AWAITING_REESTABLISH;

			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};
			const manager = new ChannelManager(config);
			(manager as any).channels.set(channelId.toString('hex'), opener);
			(manager as any).channelPeers.set(channelId.toString('hex'), 'test-peer');

			let closedEmitted = false;
			manager.on('channel:closed', () => {
				closedEmitted = true;
			});

			manager.handleFundingSpent(
				channelId,
				commitmentTx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			expect(opener.getState()).to.equal(ChannelState.FORCE_CLOSED);
			expect(closedEmitted).to.be.true;
		});

		it('should not re-emit channel:closed for an already-closed channel (idempotent)', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const config: IChannelManagerConfig = {
				localBasepoints: state.localBasepoints,
				localPerCommitmentSeed: state.localPerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};
			const manager = new ChannelManager(config);
			const channelId = opener.getChannelId()!;
			(manager as any).channels.set(channelId.toString('hex'), opener);
			(manager as any).channelPeers.set(channelId.toString('hex'), 'test-peer');

			const closingResult = buildClosingTx({
				fundingTxid: state.fundingTxid!.toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex,
				fundingAmount: state.fundingSatoshis,
				localScriptPubkey: destScript,
				remoteScriptPubkey: Buffer.alloc(22, 0x02),
				localAmount: 800_000n,
				remoteAmount: 199_000n,
				feeAmount: 1_000n
			});

			let closedCount = 0;
			manager.on('channel:closed', () => {
				closedCount++;
			});

			manager.handleFundingSpent(
				channelId,
				closingResult.tx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);
			// A duplicate detection (e.g. repeated scripthash notification) must be a no-op.
			manager.handleFundingSpent(
				channelId,
				closingResult.tx,
				101,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			expect(opener.getState()).to.equal(ChannelState.CLOSED);
			expect(closedCount).to.equal(1);
		});
	});

	describe('End-to-end Unilateral Close (Our Commitment)', function () {
		it('should force close, detect on-chain, sweep after CSV', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();

			const signer = new ChannelSigner(openerPrivkeys[0]);
			const channelId = opener.getChannelId()!;
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// Force close
			const forceCloseActions = opener.forceClose(signer);
			expect(opener.getState()).to.equal(ChannelState.FORCE_CLOSED);

			const broadcastAction = forceCloseActions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			);
			expect(broadcastAction).to.exist;

			// Parse the broadcast commitment tx
			const commitmentTx = bitcoin.Transaction.fromBuffer(
				(broadcastAction as any).tx
			);

			// Set up ChannelManager to process the on-chain event
			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};

			const manager = new ChannelManager(config);
			(manager as any).channels.set(channelId.toString('hex'), opener);

			// Handle funding spent (our commitment confirmed on-chain)
			const chainActions = manager.handleFundingSpent(
				channelId,
				commitmentTx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const monitor = manager.getMonitor(channelId);
			expect(monitor).to.exist;
			expect(monitor!.getState()).to.equal(MonitorState.RESOLVING);

			// The to_local sweep is CSV-locked: it must be held, not broadcast at
			// the detection height (broadcasting early = non-BIP68-final).
			const immediate = chainActions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(immediate.length).to.equal(0);

			// Once the CSV matures, the sweep is broadcast.
			const toLocal = monitor!
				.getTrackedOutputs()
				.find((o) => o.outputType === OutputType.TO_LOCAL);
			expect(toLocal).to.exist;
			expect(toLocal!.maturityHeight).to.be.greaterThan(100);
			const matured = manager.handleNewBlock(toLocal!.maturityHeight!);
			const sweepActions = matured.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(sweepActions.length).to.be.greaterThan(0);
		});
	});

	describe('End-to-end Unilateral Close (Their Commitment)', function () {
		it('should detect their commitment and claim to_remote', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();

			const channelId = opener.getChannelId()!;
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// Build their commitment (as if they force-closed)
			const remotePerCommitmentPoint = state.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(state, remotePerCommitmentPoint);

			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};

			const manager = new ChannelManager(config);
			(manager as any).channels.set(channelId.toString('hex'), opener);

			let broadcastEmitted = false;
			manager.on('broadcast:tx', () => {
				broadcastEmitted = true;
			});

			const chainActions = manager.handleFundingSpent(
				channelId,
				built.result.tx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			expect(broadcastEmitted).to.be.true;

			const monitor = manager.getMonitor(channelId);
			expect(monitor).to.exist;
			expect(monitor!.getState()).to.equal(MonitorState.RESOLVING);

			// Should have claim tx for to_remote
			const claimActions = chainActions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(claimActions.length).to.be.greaterThan(0);
		});
	});

	describe('End-to-end Breach Remedy', function () {
		it('should detect revoked commitment and penalty sweep', function () {
			const {
				opener,
				acceptor,
				openerPrivkeys,
				openerBasepoints,
				openerCommitmentSeed
			} = setupNormalChannels();

			// Exchange commitments to get revocable state
			exchangeCommitments(opener, acceptor);

			const channelId = opener.getChannelId()!;
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// Build a revoked commitment (number 0, now revoked)
			const secretIndex = MAX_INDEX - 0n;
			const secret = state.shaChainStore.getSecret(secretIndex);
			expect(secret).to.not.be.null;

			const revokedPoint = perCommitmentPointFromSecret(secret!);
			const revocationPubkey = deriveRevocationPubkey(
				state.localBasepoints.revocationBasepoint,
				revokedPoint
			);
			const theirDelayedPubkey = derivePublicKey(
				state.remoteBasepoints!.delayedPaymentBasepoint,
				revokedPoint
			);

			const isOpener = state.role === ChannelRole.OPENER;
			const openPBP = isOpener
				? state.localBasepoints.paymentBasepoint
				: state.remoteBasepoints!.paymentBasepoint;
			const acceptPBP = isOpener
				? state.remoteBasepoints!.paymentBasepoint
				: state.localBasepoints.paymentBasepoint;

			const obscured = calculateObscuredCommitmentNumber(
				openPBP,
				acceptPBP,
				0n
			);
			const revokedTx = new bitcoin.Transaction();
			revokedTx.version = 2;
			revokedTx.locktime = 0x20000000 | Number(obscured & 0xffffffn);
			const seq = (0x80000000 | Number((obscured >> 24n) & 0xffffffn)) >>> 0;
			const fundingTxidBuf = Buffer.from(
				state.fundingTxid!.toString('hex'),
				'hex'
			).reverse();
			revokedTx.addInput(fundingTxidBuf, state.fundingOutputIndex, seq);

			const toLocalScript = buildToLocalScript(
				revocationPubkey,
				theirDelayedPubkey,
				state.localConfig.toSelfDelay
			);
			const p2wsh = bitcoin.payments.p2wsh({
				redeem: { output: toLocalScript }
			});
			revokedTx.addOutput(p2wsh.output!, 800_000);

			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};

			const manager = new ChannelManager(config);
			(manager as any).channels.set(channelId.toString('hex'), opener);

			let broadcastEmitted = false;
			manager.on('broadcast:tx', () => {
				broadcastEmitted = true;
			});

			const chainActions = manager.handleFundingSpent(
				channelId,
				revokedTx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			expect(broadcastEmitted).to.be.true;

			const monitor = manager.getMonitor(channelId);
			expect(monitor).to.exist;
			expect(monitor!.getState()).to.equal(MonitorState.RESOLVING);

			// Should have penalty broadcast
			const penaltyActions = chainActions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(penaltyActions.length).to.be.greaterThan(0);
		});
	});

	describe('Multiple Channels', function () {
		it('should forward handleNewBlock to all monitors', function () {
			const {
				opener: opener1,
				openerPrivkeys: pk1,
				openerBasepoints: bp1,
				openerCommitmentSeed: cs1
			} = setupNormalChannels();
			const { opener: opener2 } = setupNormalChannels();

			const config: IChannelManagerConfig = {
				localBasepoints: bp1,
				localPerCommitmentSeed: cs1,
				localFundingPrivkey: pk1[0]
			};

			const manager = new ChannelManager(config);

			const channelId1 = opener1.getChannelId()!;
			const channelId2 = opener2.getChannelId()!;
			(manager as any).channels.set(channelId1.toString('hex'), opener1);
			(manager as any).channels.set(channelId2.toString('hex'), opener2);

			const destScript1 = makeP2wpkhScript(getPublicKey(pk1[0]));

			const state1 = opener1.getFullState();

			// Cooperative close first channel
			const closing1 = buildClosingTx({
				fundingTxid: state1.fundingTxid!.toString('hex'),
				fundingOutputIndex: state1.fundingOutputIndex,
				fundingAmount: state1.fundingSatoshis,
				localScriptPubkey: destScript1,
				remoteScriptPubkey: Buffer.alloc(22, 0x02),
				localAmount: 800_000n,
				remoteAmount: 199_000n,
				feeAmount: 1_000n
			});

			manager.handleFundingSpent(
				channelId1,
				closing1.tx,
				100,
				destScript1,
				10,
				pk1[1],
				pk1[2],
				network
			);

			// handleNewBlock should work even with multiple monitors
			const actions = manager.handleNewBlock(200);
			// Cooperative close is fully resolved, so no new actions
			expect(actions).to.have.length(0);
		});
	});

	describe('Preimage Extraction Flow', function () {
		it('should extract preimage from on-chain HTLC spend and emit event', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();

			// Add an HTLC
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			opener.addHtlc(10_000_000n, paymentHash, 500, Buffer.alloc(1366));

			const channelId = opener.getChannelId()!;
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// Build our commitment with the HTLC
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};

			const manager = new ChannelManager(config);
			(manager as any).channels.set(channelId.toString('hex'), opener);

			// Detect our commitment on-chain
			manager.handleFundingSpent(
				channelId,
				built.result.tx,
				100,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const monitor = manager.getMonitor(channelId);
			expect(monitor).to.exist;

			// Find the HTLC output
			const tracked = monitor!.getTrackedOutputs();
			const htlcOutput = tracked.find(
				(o) => o.outputType === OutputType.OFFERED_HTLC
			);

			if (htlcOutput) {
				let preimageEmitted = false;
				manager.on('preimage:learned', (hash: Buffer, pi: Buffer) => {
					preimageEmitted = true;
					expect(hash).to.deep.equal(paymentHash);
					expect(pi).to.deep.equal(preimage);
				});

				// Simulate remote claiming HTLC with preimage on-chain
				const claimTx = new bitcoin.Transaction();
				claimTx.version = 2;
				const txidBuf = Buffer.from(htlcOutput.txid, 'hex').reverse();
				claimTx.addInput(txidBuf, htlcOutput.outputIndex);
				claimTx.addOutput(Buffer.alloc(22), 9_000);
				claimTx.setWitness(0, [
					Buffer.alloc(0),
					Buffer.alloc(72),
					Buffer.alloc(72),
					preimage,
					Buffer.alloc(100)
				]);

				const spentActions = manager.handleOutputSpent(
					htlcOutput.txid,
					htlcOutput.outputIndex,
					claimTx,
					101
				);

				const preimageAction = spentActions.find(
					(a) => a.type === ChainActionType.PREIMAGE_LEARNED
				);
				expect(preimageAction).to.exist;
				expect(preimageEmitted).to.be.true;
			}
		});
	});

	describe('update_fee staging (commitment-fee desync hardening)', function () {
		it('stages the new feerate instead of applying it immediately', function () {
			const { opener } = setupNormalChannels();
			const committed = opener.getFullState().localConfig.feeratePerKw;
			const proposed = committed * 2;

			opener.updateFee(proposed);

			const st = opener.getFullState();
			expect(
				st.localConfig.feeratePerKw,
				'committed fee unchanged until the round finalizes'
			).to.equal(committed);
			expect(st.pendingFeeratePerKw, 'new fee held as pending').to.equal(
				proposed
			);
		});

		it('promotes the staged fee on both sides once the commitment round completes', function () {
			const { opener, acceptor } = setupNormalChannels();
			const committed = opener.getFullState().localConfig.feeratePerKw;
			const proposed = committed * 2;

			// Opener proposes; deliver the update_fee to the acceptor.
			const actions = opener.updateFee(proposed);
			const feeMsg = findSendAction(actions, MessageType.UPDATE_FEE);
			acceptor.handleUpdateFee(decodeUpdateFeeMessage(feeMsg.payload));
			expect(acceptor.getFullState().pendingFeeratePerKw).to.equal(proposed);

			// Complete a full commitment round in both directions.
			exchangeCommitments(opener, acceptor);

			expect(
				opener.getFullState().localConfig.feeratePerKw,
				'opener committed the new fee'
			).to.equal(proposed);
			expect(opener.getFullState().pendingFeeratePerKw).to.be.undefined;
			expect(
				acceptor.getFullState().remoteConfig.feeratePerKw,
				'acceptor committed the opener fee'
			).to.equal(proposed);
			expect(acceptor.getFullState().pendingFeeratePerKw).to.be.undefined;
		});

		it('rolls back an uncommitted fee update on reestablish (no desync)', function () {
			const { opener } = setupNormalChannels();
			const committed = opener.getFullState().localConfig.feeratePerKw;

			opener.updateFee(committed * 2);
			expect(opener.getFullState().pendingFeeratePerKw).to.equal(committed * 2);

			// A disconnect/restart before the round finalizes must roll the fee back
			// to the last committed value, not leave it stuck at the proposed value.
			opener.markForReestablish();
			expect(opener.getFullState().pendingFeeratePerKw, 'pending fee discarded')
				.to.be.undefined;
			expect(
				opener.getFullState().localConfig.feeratePerKw,
				'committed fee preserved'
			).to.equal(committed);
		});
	});
});
