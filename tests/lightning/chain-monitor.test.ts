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
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
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
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import { buildClosingTx } from '../../src/lightning/chain/closing';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	MonitorState,
	ChainActionType,
	OutputStatus,
	OutputType,
	IRREVOCABLE_DEPTH,
	CommitmentType
} from '../../src/lightning/chain/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	perCommitmentPointFromSecret,
	deriveRevocationPubkey,
	derivePublicKey
} from '../../src/lightning/keys/derivation';
import { buildToLocalScript } from '../../src/lightning/script/commitment';
import { calculateObscuredCommitmentNumber } from '../../src/lightning/script/commitment';

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

function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
	acceptorPrivkeys: Buffer[];
	openerCommitmentSeed: Buffer;
	acceptorCommitmentSeed: Buffer;
} {
	const openerSeed = Buffer.alloc(32, 0x31);
	const acceptorSeed = Buffer.alloc(32, 0x32);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('monitor-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('monitor-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints, privkeys: acceptorPrivkeys } =
		makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xcc),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitmentSeed
	});

	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xcc),
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

function makeP2wpkhScript(pubkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({ pubkey, network }).output!;
}

describe('Chain Monitor (Phase 4C)', function () {
	describe('Initialization', function () {
		it('should start in WATCHING state', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			expect(monitor.getState()).to.equal(MonitorState.WATCHING);
			expect(monitor.getTrackedOutputs()).to.have.length(0);
			expect(monitor.isFullyResolved()).to.be.false;
		});
	});

	describe('Cooperative Close', function () {
		it('should detect and immediately mark as FULLY_RESOLVED', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

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

			const actions = monitor.handleFundingSpent(closingResult.tx, 100);

			expect(monitor.getState()).to.equal(MonitorState.FULLY_RESOLVED);
			expect(monitor.isFullyResolved()).to.be.true;

			const resolvedAction = actions.find(
				(a) => a.type === ChainActionType.CHANNEL_FULLY_RESOLVED
			);
			expect(resolvedAction).to.exist;
		});
	});

	describe('Our Commitment', function () {
		it('should detect our commitment and start resolving', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Build our local commitment
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			const actions = monitor.handleFundingSpent(built.result.tx, 100);

			expect(monitor.getState()).to.equal(MonitorState.RESOLVING);

			// Should have WATCH_OUTPUT actions for each output
			const watchActions = actions.filter(
				(a) => a.type === ChainActionType.WATCH_OUTPUT
			);
			expect(watchActions.length).to.be.greaterThan(0);

			// The to_local sweep is CSV-locked, so it must NOT be broadcast
			// immediately (broadcasting before maturity = non-BIP68-final).
			const immediate = actions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(immediate.length).to.equal(0);

			// It is held until its CSV matures, then released by handleNewBlock.
			const toLocal = monitor
				.getTrackedOutputs()
				.find((o) => o.outputType === OutputType.TO_LOCAL);
			expect(toLocal).to.exist;
			expect(toLocal!.maturityHeight).to.be.greaterThan(100);
			const matured = monitor.handleNewBlock(toLocal!.maturityHeight!);
			const broadcastActions = matured.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(broadcastActions.length).to.be.greaterThan(0);
		});

		it('holds the to_local sweep until its CSV matures, then releases it', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			// Commitment confirms at height 100; the to_local CSV = to_self_delay.
			monitor.handleFundingSpent(built.result.tx, 100);
			const toLocal = monitor
				.getTrackedOutputs()
				.find((o) => o.outputType === OutputType.TO_LOCAL);
			expect(toLocal, 'to_local output tracked').to.exist;
			const maturity = toLocal!.maturityHeight!;
			expect(maturity).to.be.greaterThan(100);

			// One block before maturity: still held, nothing broadcast.
			const early = monitor.handleNewBlock(maturity - 1);
			expect(
				early.filter((a) => a.type === ChainActionType.BROADCAST_TX).length
			).to.equal(0);
			expect(
				monitor
					.getTrackedOutputs()
					.find((o) => o.outputType === OutputType.TO_LOCAL)!.status
			).to.equal(OutputStatus.CONFIRMED);

			// Exactly at maturity: the sweep is released.
			const atMaturity = monitor.handleNewBlock(maturity);
			expect(
				atMaturity.filter((a) => a.type === ChainActionType.BROADCAST_TX).length
			).to.equal(1);
			expect(
				monitor
					.getTrackedOutputs()
					.find((o) => o.outputType === OutputType.TO_LOCAL)!.status
			).to.equal(OutputStatus.SPEND_BROADCAST);
		});

		it('holds a CSV sweep seen in the mempool (height 0) until the spend confirms', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			// The watcher reports a mempool spend with height 0. A BIP68 (CSV)
			// sweep counts from the parent's confirmation, which is unknown — it
			// must be held, NOT broadcast against height 0 (non-BIP68-final).
			const actions = monitor.handleFundingSpent(built.result.tx, 0);
			expect(
				actions.filter((a) => a.type === ChainActionType.BROADCAST_TX).length
			).to.equal(0);

			const toLocal = () =>
				monitor
					.getTrackedOutputs()
					.find((o) => o.outputType === OutputType.TO_LOCAL)!;
			expect(toLocal().status).to.equal(OutputStatus.CONFIRMED);
			expect(toLocal().maturityHeight).to.equal(Number.MAX_SAFE_INTEGER);

			// Even far in the future the sweep stays held while unconfirmed.
			const later = monitor.handleNewBlock(900_000);
			expect(
				later.filter((a) => a.type === ChainActionType.BROADCAST_TX).length
			).to.equal(0);

			// The funding watch re-fires once the spend confirms: the monitor
			// adopts the confirmation height and re-derives the real maturity.
			const adopted = monitor.handleFundingSpent(built.result.tx, 900_001);
			expect(
				adopted.filter((a) => a.type === ChainActionType.BROADCAST_TX).length
			).to.equal(0);
			const maturity = toLocal().maturityHeight!;
			expect(maturity).to.be.greaterThan(900_001);
			expect(maturity).to.be.lessThan(Number.MAX_SAFE_INTEGER);
			expect(toLocal().confirmationHeight).to.equal(900_001);

			// And the sweep releases exactly at maturity.
			const atMaturity = monitor.handleNewBlock(maturity);
			expect(
				atMaturity.filter((a) => a.type === ChainActionType.BROADCAST_TX).length
			).to.equal(1);
			expect(toLocal().status).to.equal(OutputStatus.SPEND_BROADCAST);
		});

		it('puts a prematurely-broadcast CSV sweep back on hold when the spend confirms', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			monitor.handleFundingSpent(built.result.tx, 0);
			const toLocal = () =>
				monitor
					.getTrackedOutputs()
					.find((o) => o.outputType === OutputType.TO_LOCAL)!;
			// Simulate the pre-fix persisted shape: sweep already (futilely)
			// broadcast against the unconfirmed parent.
			toLocal().status = OutputStatus.SPEND_BROADCAST;
			toLocal().broadcastHeight = 900_000;

			monitor.handleNewBlock(900_000);
			monitor.handleFundingSpent(built.result.tx, 900_001);

			// Back on hold with the true maturity — no fee-bump churn until then.
			expect(toLocal().status).to.equal(OutputStatus.CONFIRMED);
			expect(toLocal().broadcastHeight).to.be.undefined;
			expect(toLocal().maturityHeight).to.be.greaterThan(900_001);
		});

		it('should track outputs for resolution', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			monitor.handleFundingSpent(built.result.tx, 100);

			const tracked = monitor.getTrackedOutputs();
			expect(tracked.length).to.be.greaterThan(0);

			const toLocal = tracked.find((o) => o.outputType === OutputType.TO_LOCAL);
			const toRemote = tracked.find(
				(o) => o.outputType === OutputType.TO_REMOTE
			);
			expect(toLocal).to.exist;
			expect(toRemote).to.exist;
		});
	});

	describe('Their Current Commitment', function () {
		it('should detect their commitment and claim to_remote immediately', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Build their (remote) commitment
			const remotePerCommitmentPoint = state.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(state, remotePerCommitmentPoint);

			const actions = monitor.handleFundingSpent(built.result.tx, 100);

			expect(monitor.getState()).to.equal(MonitorState.RESOLVING);

			// Should broadcast to_remote claim
			const broadcastActions = actions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(broadcastActions.length).to.be.greaterThan(0);

			// At least one should be to_remote claim
			const toRemoteClaim = broadcastActions.find(
				(a: any) => a.description && a.description.includes('to_remote')
			);
			expect(toRemoteClaim).to.exist;
		});

		// Regression: on a remote force-close we must be able to claim a received
		// HTLC (our inbound funds) with a known preimage. This previously failed
		// silently because the monitor did not forward htlcBasepointSecret /
		// remotePerCommitmentPoint to resolveTheirCurrentCommitmentOutputs, leaving
		// the preimage-claim branch dead and the funds unswept.
		it('claims a received HTLC with a known preimage on their current commitment', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();

			// Peer offers us an HTLC (we are the receiver, so we know the preimage).
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
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// Construct the monitor WITH the delayed + htlc basepoint secrets so the
			// preimage-claim path has the key material it needs.
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

			// We learned the preimage before the peer force-closed.
			monitor.addPreimage(paymentHash, preimage);

			// Peer broadcasts their current commitment (which carries the HTLC).
			const remotePerCommitmentPoint = state.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(state, remotePerCommitmentPoint);
			const actions = monitor.handleFundingSpent(built.result.tx, 100);

			const htlcClaim = actions.find(
				(a: any) =>
					a.type === ChainActionType.BROADCAST_TX &&
					a.description &&
					a.description.includes('HTLC claim')
			);
			expect(htlcClaim, 'received-HTLC preimage claim must be broadcast').to
				.exist;
		});

		// C2 fund-safety: the preimage is learned AFTER the peer force-closed with
		// their current commitment (e.g. we forwarded the HTLC, the downstream leg
		// settled later). addPreimage must convert the tracked-but-unswept received
		// HTLC into an on-chain preimage claim — otherwise the peer reclaims it via
		// HTLC-timeout and we lose the full forwarded amount.
		it('claims a received HTLC when the preimage is learned AFTER the peer force-closed (C2)', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();

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
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));
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

			// Peer force-closes with their current commitment BEFORE we know the preimage.
			const remotePerCommitmentPoint = state.remoteCurrentPerCommitmentPoint!;
			const built = buildRemoteCommitment(state, remotePerCommitmentPoint);
			const closeActions = monitor.handleFundingSpent(built.result.tx, 100);

			// The received HTLC cannot be claimed yet — no HTLC claim is broadcast.
			const preClaim = closeActions.find(
				(a: any) =>
					a.type === ChainActionType.BROADCAST_TX &&
					a.description &&
					a.description.includes('HTLC claim')
			);
			expect(preClaim, 'no HTLC claim before the preimage is known').to.be
				.undefined;

			// The preimage now arrives — the claim must be built and broadcast.
			const actions = monitor.addPreimage(paymentHash, preimage);
			const htlcClaim = actions.find(
				(a: any) =>
					a.type === ChainActionType.BROADCAST_TX &&
					a.description &&
					a.description.includes('HTLC claim (preimage learned)')
			);
			expect(
				htlcClaim,
				'preimage-claim must be broadcast once the preimage is learned'
			).to.exist;
		});
	});

	describe('Revoked Commitment', function () {
		it('should detect and penalty sweep revoked commitment', function () {
			const { opener, acceptor, openerPrivkeys } = setupNormalChannels();

			// Exchange commitments to create revocable state
			exchangeCommitments(opener, acceptor);

			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Build a revoked commitment (commitment number 0, which is now revoked)
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

			const actions = monitor.handleFundingSpent(revokedTx, 100);

			expect(monitor.getState()).to.equal(MonitorState.RESOLVING);

			// Should broadcast penalty tx
			const broadcastActions = actions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(broadcastActions.length).to.be.greaterThan(0);

			const penaltyBroadcast = broadcastActions.find(
				(a: any) => a.description && a.description.includes('penalty')
			);
			expect(penaltyBroadcast).to.exist;
		});
	});

	describe('Stuck HTLC re-fee-bump (M1)', function () {
		function anchorMonitorWithStuckHtlc(anchor: boolean): {
			monitor: ChainMonitor;
			bump: () => any;
		} {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
			if (anchor) flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
			state.channelType = flags.toBuffer();

			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));
			const monitor = new ChainMonitor(
				state,
				destScript,
				5,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network,
				openerPrivkeys[3],
				openerPrivkeys[4]
			);

			// Our commitment is on-chain and we broadcast a second-level HTLC-timeout
			// tx at height 100 that is now stuck at the original feerate.
			(monitor as any)._state = MonitorState.RESOLVING;
			(monitor as any)._commitmentBroadcast = {
				commitmentType: CommitmentType.OUR_COMMITMENT,
				commitmentNumber: 0n
			};
			(monitor as any)._trackedOutputs = [
				{
					txid: 'aa'.repeat(32),
					outputIndex: 0,
					amount: 100_000n,
					outputType: OutputType.OFFERED_HTLC,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					broadcastHeight: 100,
					originalFeeRate: 5,
					currentFeeRate: 5,
					// Opaque hex — the rebroadcast loop only rewraps it into the action.
					sweepTxHex: '0200000000010000000000'
				}
			];

			// Advance past REBROADCAST_INTERVAL (6) since the broadcast.
			const actions = monitor.handleNewBlock(106);
			const bump = () =>
				actions.find(
					(a: any) =>
						a.type === ChainActionType.FEE_BUMP_AND_BROADCAST &&
						a.kind === 'htlc-fee-attach'
				);
			return { monitor, bump };
		}

		it('re-fee-bumps a stuck ANCHOR second-level HTLC tx to keep the HTLC race', function () {
			const { bump } = anchorMonitorWithStuckHtlc(true);
			const action = bump();
			expect(action, 'stuck anchor HTLC tx must be re-fee-bumped').to.exist;
			expect(action.feeratePerVbyte).to.be.greaterThan(5);
		});

		it('does NOT RBF a non-anchor second-level HTLC tx (fee is counterparty-signed)', function () {
			const { bump } = anchorMonitorWithStuckHtlc(false);
			expect(bump(), 'non-anchor HTLC tx must not be RBF-rebuilt').to.be
				.undefined;
		});

		it('re-fee-bumps a stuck preimage claim on the PEER commitment (H2)', function () {
			// The PEER force-closed (their current commitment). Our received-HTLC
			// preimage claim is a SINGLE wallet-signed tx we fully control, so it can
			// be freely RBF'd. Previously the blanket `continue` for HTLC outputs
			// pinned it at the initial feerate and a fee spike let the peer win the
			// HTLC-timeout race. It must now go through the generic REBUILD_SWEEP.
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));
			const monitor = new ChainMonitor(
				state,
				destScript,
				5,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network,
				openerPrivkeys[3],
				openerPrivkeys[4]
			);

			(monitor as any)._state = MonitorState.RESOLVING;
			(monitor as any)._commitmentBroadcast = {
				commitmentType: CommitmentType.THEIR_CURRENT_COMMITMENT,
				commitmentNumber: 0n
			};
			(monitor as any)._trackedOutputs = [
				{
					txid: 'aa'.repeat(32),
					outputIndex: 0,
					amount: 100_000n,
					outputType: OutputType.RECEIVED_HTLC,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					broadcastHeight: 100,
					originalFeeRate: 5,
					currentFeeRate: 5,
					sweepTxHex: '0200000000010000000000'
				}
			];

			const actions = monitor.handleNewBlock(106);
			const rebuild: any = actions.find(
				(a: any) => a.type === ChainActionType.REBUILD_SWEEP
			);
			expect(
				rebuild,
				'stuck preimage claim on the peer commitment must be re-fee-bumped'
			).to.exist;
			expect(rebuild.feeRatePerVbyte).to.be.greaterThan(5);
		});
	});

	describe('Reorg recovery (spend evicted)', function () {
		function monitorWithConfirmedSweep(): {
			monitor: ChainMonitor;
			txid: string;
		} {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));
			const monitor = new ChainMonitor(
				state,
				destScript,
				5,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network,
				openerPrivkeys[3],
				openerPrivkeys[4]
			);
			const txid = 'bb'.repeat(32);
			(monitor as any)._state = MonitorState.RESOLVING;
			(monitor as any)._commitmentBroadcast = {
				commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
				commitmentNumber: 0n
			};
			(monitor as any)._currentBlockHeight = 105;
			(monitor as any)._trackedOutputs = [
				{
					txid,
					outputIndex: 0,
					amount: 100_000n,
					outputType: OutputType.TO_LOCAL, // our penalty on a revoked to_local
					status: OutputStatus.SPEND_CONFIRMED,
					resolutionTxid: 'cc'.repeat(32),
					confirmationHeight: 100,
					sweepTxHex: '0200000000010000000000' // our penalty tx (opaque)
				}
			];
			return { monitor, txid };
		}

		it('re-broadcasts our penalty when its confirmed spend is reorged out', function () {
			const { monitor, txid } = monitorWithConfirmedSweep();
			const actions = monitor.handleSpendUnconfirmed(txid, 0);

			const rebroadcast = actions.find(
				(a: any) =>
					a.type === ChainActionType.BROADCAST_TX &&
					a.description &&
					a.description.includes('reorg recovery')
			);
			expect(rebroadcast, 'evicted penalty must be re-broadcast').to.exist;

			const out = (monitor as any)._trackedOutputs[0];
			expect(out.status).to.equal(OutputStatus.SPEND_BROADCAST);
			expect(out.resolutionTxid, 'stale spend record cleared').to.be.undefined;
		});

		it('handleOutputSpent is idempotent for a repeated spend notification', function () {
			const { monitor, txid } = monitorWithConfirmedSweep();
			// Reset the tracked output to unspent so the first call does the real work.
			(monitor as any)._trackedOutputs[0].status = OutputStatus.CONFIRMED;
			(monitor as any)._trackedOutputs[0].resolutionTxid = undefined;

			const spendTx = new bitcoin.Transaction();
			spendTx.version = 2;
			spendTx.addInput(Buffer.from(txid, 'hex').reverse(), 0);
			spendTx.addOutput(Buffer.alloc(22, 0x00), 90_000);

			monitor.handleOutputSpent(txid, 0, spendTx, 100);
			// A retained watch re-fires the subscription; the same spend must be a no-op.
			const second = monitor.handleOutputSpent(txid, 0, spendTx, 100);
			expect(second.length, 'duplicate spend is not reprocessed').to.equal(0);
		});
	});

	describe('Block Progression', function () {
		it('should not resolve on early blocks', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Cooperative close
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

			monitor.handleFundingSpent(closingResult.tx, 100);
			expect(monitor.isFullyResolved()).to.be.true;

			// New blocks on already-resolved should be no-op
			const actions = monitor.handleNewBlock(101);
			expect(actions).to.have.length(0);
		});

		it('should resolve outputs after IRREVOCABLE_DEPTH', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Build our commitment
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			monitor.handleFundingSpent(built.result.tx, 100);

			// Mark all outputs as SPEND_CONFIRMED
			const fullState = monitor.getFullState();
			for (const output of fullState.trackedOutputs) {
				output.status = OutputStatus.SPEND_CONFIRMED;
				output.resolutionTxid = crypto.randomBytes(32).toString('hex');
				output.confirmationHeight = 100;
			}

			// Advance to IRREVOCABLE_DEPTH
			const actions = monitor.handleNewBlock(100 + IRREVOCABLE_DEPTH);

			const resolvedActions = actions.filter(
				(a) => a.type === ChainActionType.OUTPUT_RESOLVED
			);
			expect(resolvedActions.length).to.be.greaterThan(0);

			const fullyResolved = actions.find(
				(a) => a.type === ChainActionType.CHANNEL_FULLY_RESOLVED
			);
			expect(fullyResolved).to.exist;
			expect(monitor.isFullyResolved()).to.be.true;
		});
	});

	describe('Output Spent Events', function () {
		it('should extract preimage from HTLC spend witness', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();

			// Add an HTLC
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			opener.addHtlc(10_000_000n, paymentHash, 500, Buffer.alloc(1366));

			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Build our commitment with the HTLC
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			monitor.handleFundingSpent(built.result.tx, 100);

			// Find the HTLC output
			const tracked = monitor.getTrackedOutputs();
			const htlcOutput = tracked.find(
				(o) => o.outputType === OutputType.OFFERED_HTLC
			);

			if (htlcOutput) {
				// Simulate remote claiming HTLC with preimage
				const spendingTx = new bitcoin.Transaction();
				spendingTx.version = 2;
				const txidBuf = Buffer.from(htlcOutput.txid, 'hex').reverse();
				spendingTx.addInput(txidBuf, htlcOutput.outputIndex);
				spendingTx.addOutput(Buffer.alloc(22), 9_000);

				// Set witness with preimage
				spendingTx.setWitness(0, [
					Buffer.alloc(0),
					Buffer.alloc(72), // remoteSig
					Buffer.alloc(72), // localSig
					preimage,
					Buffer.alloc(100) // witnessScript
				]);

				const actions = monitor.handleOutputSpent(
					htlcOutput.txid,
					htlcOutput.outputIndex,
					spendingTx,
					101
				);

				const preimageAction = actions.find(
					(a) => a.type === ChainActionType.PREIMAGE_LEARNED
				);
				expect(preimageAction).to.exist;
				expect((preimageAction as any).preimage).to.deep.equal(preimage);
				expect((preimageAction as any).paymentHash).to.deep.equal(paymentHash);
			}
		});
	});

	describe('Preimage Addition', function () {
		it('should allow adding preimages for later resolution', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();

			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			// Adding preimage before commitment detected should be fine
			const actions = monitor.addPreimage(paymentHash, preimage);
			// No actions since we're in WATCHING state
			expect(actions).to.have.length(0);
		});
	});

	describe('handleNewBlock in WATCHING state', function () {
		it('should be a no-op', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const actions = monitor.handleNewBlock(500);
			expect(actions).to.have.length(0);
			expect(monitor.getState()).to.equal(MonitorState.WATCHING);
		});
	});

	describe('Duplicate funding spent', function () {
		it('should be an idempotent no-op if funding already spent', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

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

			monitor.handleFundingSpent(closingResult.tx, 100);
			const stateAfterFirst = monitor.getState();

			// Try again — should be an idempotent no-op (no error, no re-processing)
			const actions = monitor.handleFundingSpent(closingResult.tx, 101);
			expect(actions).to.be.an('array').that.is.empty;
			expect(monitor.getState()).to.equal(stateAfterFirst);
		});
	});

	describe('getFullState', function () {
		it('should return serializable state snapshot', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);

			const fullState = monitor.getFullState();
			expect(fullState.monitorState).to.equal(MonitorState.WATCHING);
			expect(fullState.commitmentBroadcast).to.be.null;
			expect(fullState.trackedOutputs).to.have.length(0);
		});
	});
});
