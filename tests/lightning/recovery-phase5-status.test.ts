/**
 * Recovery Protocol phase 5: the per-channel ChannelRecoveryStatus machine
 * (docs/RECOVERY-PROTOCOL.md 5.6).
 *
 * Every branch of the machine, with the never-broadcast invariant proved at
 * the action level: a channel in LocalDataLoss or StateUncertain must never
 * produce a BROADCAST_TX for its stored commitment, no matter which path
 * asks (explicit force close, the errored backstop, the stuck-channel
 * scanner), even if the peer stays unreachable indefinitely. StateUncertain
 * is the restore-side half, and its hardest property is NEGATIVE: a
 * compatible channel_reestablish proves nothing about exactness (a peer can
 * under-report counters while holding a newer state), so the flag never
 * clears on the wire; only recovery-storage provenance can leave it off.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState,
	mustNotBroadcastCommitment
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
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { ChannelRecoveryStatus } from '../../src/lightning/recovery';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { Network } from '../../src/lightning/invoice/types';

bitcoin.initEccLib(ecc);

// ── Channel-pair harness (pattern shared with dlp-fell-behind.test.ts) ──

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(privkeys[0]),
			revocationBasepoint: getPublicKey(privkeys[1]),
			paymentBasepoint: getPublicKey(privkeys[2]),
			delayedPaymentBasepoint: getPublicKey(privkeys[3]),
			htlcBasepoint: getPublicKey(privkeys[4]),
			firstPerCommitmentPoint: getPublicKey(privkeys[5])
		},
		privkeys
	};
}

function findSendAction(
	actions: Array<{ type: ChannelActionType }>,
	msgType: MessageType
): { payload: Buffer } | undefined {
	return actions.find(
		(a) =>
			a.type === ChannelActionType.SEND_MESSAGE &&
			(a as unknown as { messageType: MessageType }).messageType === msgType
	) as { payload: Buffer } | undefined;
}

function setupNormalChannels(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
	openerCommitmentSeed: Buffer;
	acceptorCommitmentSeed: Buffer;
} {
	const openerSeed = Buffer.alloc(32, 0x61);
	const acceptorSeed = Buffer.alloc(32, 0x62);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('status-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('status-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints } = makeBasepoints(acceptorSeed);

	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xd5),
			fundingSatoshis: 1_000_000n,
			pushMsat: 200_000_000n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBasepoints,
			localPerCommitmentSeed: openerCommitmentSeed
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xd5),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBasepoints,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: openerBasepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);

	const openActions = opener.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL)!;
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL)!;
	opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

	const fundingTxid = crypto.randomBytes(32);
	const fcActions = opener.createFundingCreated(
		fundingTxid,
		0,
		crypto.randomBytes(64)
	);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED)!;
	const fsActions = acceptor.handleFundingCreated(
		decodeFundingCreatedMessage(fcMsg.payload),
		crypto.randomBytes(64)
	);
	const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED)!;
	opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

	const openerReady = findSendAction(
		opener.fundingConfirmed(),
		MessageType.CHANNEL_READY
	)!;
	acceptor.handleChannelReady(decodeChannelReadyMessage(openerReady.payload));
	const acceptorReady = findSendAction(
		acceptor.fundingConfirmed(),
		MessageType.CHANNEL_READY
	)!;
	opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));

	expect(opener.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
	return {
		opener,
		acceptor,
		openerPrivkeys,
		openerCommitmentSeed,
		acceptorCommitmentSeed
	};
}

/** One full commitment round in each direction (advances both numbers to 1). */
function exchangeCommitments(opener: Channel, acceptor: Channel): void {
	const commitMsg1 = findSendAction(
		opener.signCommitment(crypto.randomBytes(64), []),
		MessageType.COMMITMENT_SIGNED
	)!;
	const raaMsg1 = findSendAction(
		acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(commitMsg1.payload)
		),
		MessageType.REVOKE_AND_ACK
	)!;
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg1.payload));

	const commitMsg2 = findSendAction(
		acceptor.signCommitment(crypto.randomBytes(64), []),
		MessageType.COMMITMENT_SIGNED
	)!;
	const raaMsg2 = findSendAction(
		opener.handleCommitmentSigned(
			decodeCommitmentSignedMessage(commitMsg2.payload)
		),
		MessageType.REVOKE_AND_ACK
	)!;
	acceptor.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg2.payload));
}

/** The peer's honest reestablish toward `channel` (counters agree). */
function cleanReestablishFor(channel: Channel): IChannelReestablishMessage {
	const s = channel.getFullState();
	return {
		channelId: channel.getChannelId()!,
		nextCommitmentNumber: s.remoteCommitmentNumber + 1n,
		nextRevocationNumber: s.localCommitmentNumber,
		yourLastPerCommitmentSecret:
			s.localCommitmentNumber > 0n
				? generateFromSeed(
						s.localPerCommitmentSeed,
						MAX_INDEX - (s.localCommitmentNumber - 1n)
				  )
				: Buffer.alloc(32),
		myCurrentPerCommitmentPoint: perCommitmentPointFromSecret(
			crypto.createHash('sha256').update(Buffer.from('peer-point')).digest()
		)
	};
}

describe('Recovery phase 5: ChannelRecoveryStatus machine', function () {
	it('Active for a normal channel, Quarantined once marked for reestablish', function () {
		const { opener, acceptor } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		expect(opener.getRecoveryStatus()).to.equal(ChannelRecoveryStatus.Active);

		// Restored, reestablish not yet exchanged: the spec's Quarantined.
		opener.markForReestablish();
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.Quarantined
		);
	});

	it('a clean reestablish on an exact channel lands in Active', function () {
		const { opener, acceptor } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		opener.markForReestablish();

		const actions = opener.handleReestablish(cleanReestablishFor(opener));
		// Nothing needed retransmission, the channel resumed NORMAL.
		expect(
			actions.some(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					(a as unknown as { replay?: boolean }).replay === true
			)
		).to.equal(false);
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(opener.getRecoveryStatus()).to.equal(ChannelRecoveryStatus.Active);
	});

	it('Reestablishing while resuming into a non-quiescent state', function () {
		const { opener, acceptor } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		// A real non-quiescent state: shutdown initiated before the restart.
		const script = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			crypto
				.createHash('sha256')
				.update(Buffer.from('shutdown-script'))
				.digest()
				.subarray(0, 20)
		]);
		const shutdownActions = opener.initiateShutdown(script);
		expect(findSendAction(shutdownActions, MessageType.SHUTDOWN)).to.exist;
		expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);

		opener.markForReestablish();
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.Quarantined
		);
		opener.handleReestablish(cleanReestablishFor(opener));
		// Counters agreed, but the channel resumed into SHUTTING_DOWN, not
		// quiescent operation: the exchange is not finished being resumed.
		expect(opener.getState()).to.equal(ChannelState.SHUTTING_DOWN);
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.Reestablishing
		);
	});

	it('ReplayRequired while retransmissions are being served, Active on fresh signed traffic', function () {
		const { opener, acceptor, acceptorCommitmentSeed } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		void acceptorCommitmentSeed;

		// The opener claims it never received the acceptor's revoke_and_ack:
		// nextRevocationNumber one behind demands a retransmission.
		acceptor.markForReestablish();
		const s = acceptor.getFullState();
		const msg: IChannelReestablishMessage = {
			channelId: acceptor.getChannelId()!,
			nextCommitmentNumber: s.remoteCommitmentNumber + 1n,
			nextRevocationNumber: s.localCommitmentNumber - 1n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: perCommitmentPointFromSecret(
				crypto.createHash('sha256').update(Buffer.from('opener-pt')).digest()
			)
		};
		const actions = acceptor.handleReestablish(msg);
		const replayed = actions.filter(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				(a as unknown as { replay?: boolean }).replay === true
		);
		expect(replayed.length).to.be.greaterThan(0);
		expect(
			replayed.some(
				(a) =>
					(a as unknown as { messageType: MessageType }).messageType ===
					MessageType.REVOKE_AND_ACK
			)
		).to.equal(true);
		expect(acceptor.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.ReplayRequired
		);

		// Fresh signed traffic ends the exchange: the status machine moves on.
		const commitMsg = findSendAction(
			opener.signCommitment(crypto.randomBytes(64), []),
			MessageType.COMMITMENT_SIGNED
		)!;
		acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(commitMsg.payload)
		);
		expect(acceptor.getRecoveryStatus()).to.equal(ChannelRecoveryStatus.Active);
	});

	it('LocalDataLoss when the peer proves a future state, and no path broadcasts', function () {
		const { opener, acceptor, openerPrivkeys, openerCommitmentSeed } =
			setupNormalChannels();
		exchangeCommitments(opener, acceptor);

		const pre = opener.getFullState();
		const nextRevocationNumber = pre.localCommitmentNumber + 3n;
		opener.markForReestablish();
		const actions = opener.handleReestablish({
			channelId: opener.getChannelId()!,
			nextCommitmentNumber: pre.remoteCommitmentNumber + 3n,
			nextRevocationNumber,
			yourLastPerCommitmentSecret: generateFromSeed(
				openerCommitmentSeed,
				MAX_INDEX - (nextRevocationNumber - 1n)
			),
			myCurrentPerCommitmentPoint: perCommitmentPointFromSecret(
				crypto.createHash('sha256').update(Buffer.from('ahead')).digest()
			)
		});
		expect(
			actions.some((a) => a.type === ChannelActionType.BROADCAST_TX)
		).to.equal(false);
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.LocalDataLoss
		);
		// The durable peer-close disposition rides the same transition.
		expect(opener.getFullState().recoveryCloseReason).to.equal(
			'local-data-loss'
		);
		// The invariant, at the action level: force close refuses.
		const refusal = opener.forceClose(new ChannelSigner(openerPrivkeys[0]));
		expect(refusal).to.have.length(1);
		expect(refusal[0].type).to.equal(ChannelActionType.ERROR);
		expect(
			refusal.some((a) => a.type === ChannelActionType.BROADCAST_TX)
		).to.equal(false);
		expect(mustNotBroadcastCommitment(opener.getFullState())).to.equal(true);
	});

	it('StateUncertain never broadcasts, and a compatible reestablish does NOT clear it', function () {
		const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);

		// The restore driver's marking: this state cannot be proven current.
		opener.getFullState().stateUncertain = true;
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.StateUncertain
		);

		// The invariant: no explicit force close may broadcast, indefinitely.
		const refusal = opener.forceClose(new ChannelSigner(openerPrivkeys[0]));
		expect(refusal).to.have.length(1);
		expect(refusal[0].type).to.equal(ChannelActionType.ERROR);
		expect((refusal[0] as { message: string }).message).to.contain(
			'not proven current'
		);
		expect(
			refusal.some((a) => a.type === ChannelActionType.BROADCAST_TX)
		).to.equal(false);
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(mustNotBroadcastCommitment(opener.getFullState())).to.equal(true);

		// Compatible counters prove NOTHING about exactness: BOLT 2's
		// stale-state proof only works upward, and a peer can under-report.
		// The exchange must route to the DLP path, not resume the channel.
		opener.markForReestablish();
		const actions = opener.handleReestablish(cleanReestablishFor(opener));
		expect(opener.getFullState().stateUncertain).to.equal(true);
		expect(opener.getState()).to.equal(ChannelState.ERRORED);
		expect(opener.getFullState().recoveryCloseReason).to.equal(
			'state-uncertain'
		);
		// Persist FIRST, then the wire error asking the peer to close.
		expect(actions[0].type).to.equal(ChannelActionType.PERSIST_STATE);
		const errSend = findSendAction(actions, MessageType.ERROR);
		expect(errSend).to.exist;
		expect(
			decodeErrorMessage(errSend!.payload).data.toString('ascii')
		).to.contain('proven current');
		// No retransmission and certainly no broadcast from an unprovable state.
		expect(
			actions.some(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					(a as unknown as { replay?: boolean }).replay === true
			)
		).to.equal(false);
		expect(
			actions.some((a) => a.type === ChannelActionType.BROADCAST_TX)
		).to.equal(false);
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.StateUncertain
		);
		expect(mustNotBroadcastCommitment(opener.getFullState())).to.equal(true);
	});

	it('a down-reporting peer cannot launder a stale restore into Active', function () {
		// The adversarial case the machine exists for: the peer really holds
		// a NEWER state, but sends counters compatible with our stale restore
		// plus an old (genuinely held) secret. Nothing in channel_reestablish
		// attests its highest state, so this exchange must change nothing.
		const { opener, acceptor, openerCommitmentSeed } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);

		// Snapshot the opener at state N... then the world moves to N+1.
		const stale = deserializeChannelState(
			serializeChannelState(opener.getFullState())
		);
		exchangeCommitments(opener, acceptor);
		expect(
			Number(opener.getFullState().localCommitmentNumber)
		).to.be.greaterThan(Number(stale.localCommitmentNumber));

		// A fresh install restores the stale snapshot; the driver marks it.
		stale.stateUncertain = true;
		const restored = new Channel(stale);
		restored.markForReestablish();

		// The peer under-reports: counters compatible with N, and OUR secret
		// at index N-1, which it legitimately holds from the honest rounds.
		const actions = restored.handleReestablish({
			channelId: restored.getChannelId()!,
			nextCommitmentNumber: stale.remoteCommitmentNumber + 1n,
			nextRevocationNumber: stale.localCommitmentNumber,
			yourLastPerCommitmentSecret: generateFromSeed(
				openerCommitmentSeed,
				MAX_INDEX - (stale.localCommitmentNumber - 1n)
			),
			myCurrentPerCommitmentPoint: perCommitmentPointFromSecret(
				crypto.createHash('sha256').update(Buffer.from('down-report')).digest()
			)
		});

		// The laundering fails: still uncertain, routed to the DLP path, and
		// the stale commitment (revoked in the peer's true view) never flies.
		expect(restored.getFullState().stateUncertain).to.equal(true);
		expect(restored.getState()).to.equal(ChannelState.ERRORED);
		expect(restored.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.StateUncertain
		);
		expect(
			actions.some((a) => a.type === ChannelActionType.BROADCAST_TX)
		).to.equal(false);
		expect(mustNotBroadcastCommitment(restored.getFullState())).to.equal(true);
	});

	it('ReplayRequired serves the exact PERSISTED bytes across a restart', function () {
		// The spec's requirement for ReplayRequired: the peer gets exactly
		// what was sent before the crash, from persistence, not a rebuild.
		const { opener, acceptor } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);

		// An update goes out and is never committed; the process dies.
		const addActions = opener.addHtlc(
			50_000_000n,
			crypto.createHash('sha256').update(Buffer.from('replay-htlc')).digest(),
			500_000,
			Buffer.alloc(1366)
		);
		const sentAdd = findSendAction(addActions, MessageType.UPDATE_ADD_HTLC)!;
		const sentBytes = Buffer.from(sentAdd.payload);

		// Restart: the channel is rebuilt from PERSISTED state alone.
		const restored = new Channel(
			deserializeChannelState(serializeChannelState(opener.getFullState()))
		);
		restored.markForReestablish();

		const actions = restored.handleReestablish(cleanReestablishFor(restored));
		const replayed = actions.filter(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				(a as unknown as { replay?: boolean }).replay === true &&
				(a as unknown as { messageType: MessageType }).messageType ===
					MessageType.UPDATE_ADD_HTLC
		) as unknown as Array<{ payload: Buffer }>;
		expect(replayed).to.have.length(1);
		// Byte for byte what was sent before the crash.
		expect(replayed[0].payload.equals(sentBytes)).to.equal(true);
		expect(restored.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.ReplayRequired
		);
	});

	it('an uncertain channel shown a future state upgrades to LocalDataLoss', function () {
		const { opener, acceptor, openerCommitmentSeed } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		opener.getFullState().stateUncertain = true;

		const pre = opener.getFullState();
		const nextRevocationNumber = pre.localCommitmentNumber + 2n;
		opener.markForReestablish();
		opener.handleReestablish({
			channelId: opener.getChannelId()!,
			nextCommitmentNumber: pre.remoteCommitmentNumber + 2n,
			nextRevocationNumber,
			yourLastPerCommitmentSecret: generateFromSeed(
				openerCommitmentSeed,
				MAX_INDEX - (nextRevocationNumber - 1n)
			),
			myCurrentPerCommitmentPoint: perCommitmentPointFromSecret(
				crypto.createHash('sha256').update(Buffer.from('ahead2')).digest()
			)
		});
		const state = opener.getFullState();
		// Proven stale outranks unprovable; the uncertainty flag is NOT
		// cleared, because this exchange proved the opposite of currency.
		expect(state.dataLossDetected).to.equal(true);
		expect(state.stateUncertain).to.equal(true);
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.LocalDataLoss
		);
	});

	it('the peer-close request survives a crash and is re-sent on reconnect', function () {
		// The reviewer's crash point: ERRORED plus the disposition commit,
		// then the process dies BEFORE the error reaches the socket. The
		// request must not die with it: the persisted disposition regenerates
		// the deterministic error on the next reconnect.
		const { opener, acceptor } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		opener.getFullState().stateUncertain = true;
		opener.markForReestablish();
		// The exchange routes to the DLP path... and the error send is LOST.
		opener.handleReestablish(cleanReestablishFor(opener));
		expect(opener.getFullState().recoveryCloseReason).to.equal(
			'state-uncertain'
		);

		// Restart from persisted state alone.
		const restored = new Channel(
			deserializeChannelState(serializeChannelState(opener.getFullState()))
		);
		expect(restored.getState()).to.equal(ChannelState.ERRORED);
		expect(restored.getFullState().recoveryCloseReason).to.equal(
			'state-uncertain'
		);
		expect(restored.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.StateUncertain
		);

		// The peer connects: the manager repeats the close request.
		const cm = new ChannelManager({
			localBasepoints: makeBasepoints(Buffer.alloc(32, 0x71)).basepoints,
			localPerCommitmentSeed: crypto
				.createHash('sha256')
				.update(Buffer.from('close-req-seed'))
				.digest(),
			localFundingPrivkey: crypto
				.createHash('sha256')
				.update(Buffer.from('close-req-funding'))
				.digest()
		});
		cm.on('error', () => {});
		const peer = getPublicKey(Buffer.alloc(32, 0x72)).toString('hex');
		cm.restoreChannel(restored, peer);
		const sent: Array<{ type: MessageType; payload: Buffer }> = [];
		cm.on('message:outbound', (_p: string, type: number, payload: Buffer) => {
			sent.push({ type, payload });
		});
		let broadcasts = 0;
		cm.on('broadcast:tx', () => {
			broadcasts++;
		});
		cm.handlePeerReconnected(peer);

		const errSent = sent.find((m) => m.type === MessageType.ERROR);
		expect(errSent).to.exist;
		expect(
			decodeErrorMessage(errSent!.payload).data.toString('ascii')
		).to.contain('proven current');
		// And still nothing broadcasts, ever.
		expect(broadcasts).to.equal(0);
		expect(restored.getState()).to.equal(ChannelState.ERRORED);
	});

	it('startup dialing includes channels carrying a recovery-close disposition', function () {
		// A crash after the disposition commit must not strand the request on
		// a node that never dials: the auto-reconnect selection includes
		// recovery-close channels alongside reestablish-needing ones.
		const { opener, acceptor } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		opener.getFullState().stateUncertain = true;
		opener.markForReestablish();
		opener.handleReestablish(cleanReestablishFor(opener));
		const state = deserializeChannelState(
			serializeChannelState(opener.getFullState())
		);
		expect(state.recoveryCloseReason).to.equal('state-uncertain');

		const storage = new SqliteStorage(':memory:');
		storage.open();
		const peer = getPublicKey(Buffer.alloc(32, 0x73)).toString('hex');
		storage.saveChannel(state.channelId!.toString('hex'), state, peer);
		// A dead port: the dial fails, but the ATTEMPT is what is asserted.
		storage.savePeerAddress(peer, '127.0.0.1', 9);

		const seed = crypto
			.createHash('sha256')
			.update(Buffer.from('close-dial-node'))
			.digest();
		const node = new LightningNode({
			nodePrivateKey: seed,
			network: Network.REGTEST as Network,
			channelBasepoints: makeBasepoints(Buffer.alloc(32, 0x74)).basepoints,
			perCommitmentSeed: crypto
				.createHash('sha256')
				.update(Buffer.from('close-dial-pcs'))
				.digest(),
			fundingPrivkey: crypto
				.createHash('sha256')
				.update(Buffer.from('close-dial-funding'))
				.digest(),
			htlcBasepointSecret: crypto
				.createHash('sha256')
				.update(Buffer.from('close-dial-htlc'))
				.digest(),
			storage,
			enableNetworking: true,
			autoReconnect: true
		});
		node.on('error', () => {});
		node.on('node:error', () => {});
		// The constructor's dial pass selected the recovery-close channel's
		// peer: a reconnect timer is armed for it.
		expect(
			(node as unknown as { _reconnectTimers: Set<unknown> })._reconnectTimers
				.size
		).to.equal(1);
		node.destroy();
	});

	it('ForceClosing after a real force close', function () {
		const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		const actions = opener.forceClose(new ChannelSigner(openerPrivkeys[0]));
		expect(
			actions.some((a) => a.type === ChannelActionType.BROADCAST_TX)
		).to.equal(true);
		expect(opener.getState()).to.equal(ChannelState.FORCE_CLOSED);
		expect(opener.getRecoveryStatus()).to.equal(
			ChannelRecoveryStatus.ForceClosing
		);
	});

	it('stateUncertain survives the serialization round trip', function () {
		const { opener, acceptor } = setupNormalChannels();
		exchangeCommitments(opener, acceptor);
		const state = opener.getFullState();
		state.stateUncertain = true;
		const restored = deserializeChannelState(serializeChannelState(state));
		expect(restored.stateUncertain).to.equal(true);
		expect(mustNotBroadcastCommitment(restored)).to.equal(true);
	});
});
