/**
 * Issue #919: a shachain store that cannot produce the secret our own
 * channel_reestablish owes the peer is a LOCAL fault, announced locally,
 * never 32 zero bytes on the wire.
 *
 * BOLT 2 permits an all-zero your_last_per_commitment_secret only at
 * next_revocation_number 0; above it the sender MUST send the last secret it
 * received. The old `|| Buffer.alloc(32)` fallback in createReestablish
 * therefore turned a lost write (or a partly restored row, or a counter that
 * disagrees with its store) into a protocol violation the peer acts on: CLN
 * fails the connection, and this implementation since issue #907 fails the
 * channel, on chain at or below its own localCommitmentNumber and under the
 * recency hold above it. Nothing local said why.
 *
 * The message is no longer built. The row is marked with the persisted
 * reestablishSecretMissing flag, which carries exactly the hold issues #469
 * and #907 defined (isRecencyUnproven answers for all three), the peer gets a
 * BOLT 1 error that says only that this node cannot produce the message, and
 * the operator gets the index and the store in a node:error and a structured
 * log. The revocation-0 arm is untouched: zeroes are correct there.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IStructuredLog } from '../../src/lightning/node/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	ChannelCloseReason,
	IChannelState,
	isRecencyUnproven,
	mustNotBroadcastCommitment
} from '../../src/lightning/channel/channel-state';
import { ChannelRecoveryStatus } from '../../src/lightning/recovery/channel-status';
import { MessageType } from '../../src/lightning/message/types';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { ShaChainStore } from '../../src/lightning/keys/shachain';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';

const TAG = 'reestablish-secret-missing';
const SWEEP_SCRIPT = Buffer.concat([
	Buffer.from([0x00, 0x14]),
	crypto.randomBytes(20)
]);
/** What the peer is allowed to learn. */
const WIRE_TEXT = 'cannot produce channel_reestablish from local state';
/** What only this node learns. */
const LOCAL_TEXT = 'shachain store holds no per-commitment secret';

/** A node:error as the cells here read it. */
interface INodeError {
	code: string;
	message: string;
	channelId?: Buffer;
}

/** The central automatic force-close guard, private on the node. */
interface IGuardAccess {
	_forceCloseWithReason(
		channelId: Buffer,
		destinationScript: Buffer,
		feeRatePerVbyte: number,
		reason: ChannelCloseReason
	): { ok: boolean; error?: string; actions: Array<{ type: string }> };
}

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	/** node:error codes Alice emitted, and the events whole. */
	events: string[];
	errorEvents: INodeError[];
	/** category:action of every structured log Alice emitted, and the records. */
	logs: string[];
	records: IStructuredLog[];
	/** Message types Alice sent Bob, and the text of every wire error. */
	sent: number[];
	errorsSent: string[];
	/** Every channel_reestablish Alice put on the wire, decoded. */
	reestablishesSent: Array<ReturnType<typeof decodeChannelReestablishMessage>>;
	state: () => IChannelState;
	destroy: () => void;
}

/**
 * Two nodes and a ready channel. `rounds` HTLC rounds leave Alice holding
 * secrets received from Bob, so her remoteRevocationNumber is above zero and
 * her reestablish owes a real secret; zero rounds leaves the revocation-0
 * case, where the zeroes are what BOLT 2 requires.
 */
function setup(seedBase: number, rounds = 1): IFixture {
	const alice = createNode(TAG, seedBase);
	const bob = createNode(TAG, seedBase + 1);
	connectNodes(alice, bob);
	const channelId = openReadyChannel(alice, bob);
	for (let i = 0; i < rounds; i++) {
		// Bob fails it back (the hash is random), which is all this needs: the
		// round itself is what makes Bob revoke and Alice store his secret.
		alice
			.getChannelManager()
			.addHtlc(
				channelId,
				10_000_000n,
				crypto.randomBytes(32),
				500,
				Buffer.alloc(1366)
			);
	}
	const events: string[] = [];
	const errorEvents: INodeError[] = [];
	const logs: string[] = [];
	const records: IStructuredLog[] = [];
	const sent: number[] = [];
	const errorsSent: string[] = [];
	const reestablishesSent: Array<
		ReturnType<typeof decodeChannelReestablishMessage>
	> = [];
	alice.on('node:error', (err: INodeError) => {
		events.push(err.code);
		errorEvents.push(err);
	});
	alice.on('log', (log: IStructuredLog) => {
		logs.push(`${log.category}:${log.action}`);
		records.push(log);
	});
	alice.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey !== bob.getNodeId()) return;
			sent.push(type);
			if (type === MessageType.ERROR) {
				errorsSent.push(decodeErrorMessage(payload).data.toString('ascii'));
			}
			if (type === MessageType.CHANNEL_REESTABLISH) {
				reestablishesSent.push(decodeChannelReestablishMessage(payload));
			}
		}
	);
	return {
		alice,
		bob,
		channelId,
		events,
		errorEvents,
		logs,
		records,
		sent,
		errorsSent,
		reestablishesSent,
		state: (): IChannelState =>
			alice.getChannelManager().getChannel(channelId)!.getFullState(),
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/**
 * The fault itself: the store loses every entry while the counter that names
 * them stands. A lost write, a partly restored row, or a counter that
 * disagrees with its store all arrive here.
 */
function loseTheSecrets(fx: IFixture): bigint {
	const state = fx.state();
	const revocationCount =
		state.remoteRevocationNumber ?? state.remoteCommitmentNumber;
	expect(
		Number(revocationCount),
		'the fixture released a secret'
	).to.be.at.least(1);
	state.shaChainStore = ShaChainStore.restore(
		[],
		state.shaChainStore.getKnownCount()
	);
	return revocationCount;
}

/** Alice reconnects to Bob and tries to send her channel_reestablish. */
function reconnect(fx: IFixture): void {
	fx.alice.getChannelManager().handlePeerDisconnected(fx.bob.getNodeId());
	fx.alice.getChannelManager().handlePeerReconnected(fx.bob.getNodeId());
}

/** The hold, on the row and on every surface that reports it. */
function expectSecretMissingHold(fx: IFixture): void {
	const state = fx.state();
	expect(state.reestablishSecretMissing).to.equal(true);
	expect(state.state).to.equal(ChannelState.ERRORED);
	expect(state.stateUncertain).to.not.equal(true);
	expect(state.dataLossDetected).to.not.equal(true);
	expect(state.restoreRecencyUnproven).to.not.equal(true);
	expect(state.reestablishRecencyUnproven).to.not.equal(true);
	// The operator's exit stays open: this is a hold, not the never-broadcast
	// invariant.
	expect(mustNotBroadcastCommitment(state)).to.equal(false);
	expect(isRecencyUnproven(state)).to.equal(true);
	const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
	expect(channel.getRecoveryCloseReason()).to.equal(
		'reestablish-secret-missing'
	);
	expect(channel.getRecoveryStatus()).to.equal(
		ChannelRecoveryStatus.ReestablishSecretMissing
	);
	expect(channel.acceptsNewHtlcs()).to.equal(false);
	expect(channel.isMutualCloseHeld()).to.equal(true);
	const idHex = fx.channelId.toString('hex');
	const row = fx.alice
		.getRecoveryStatus()
		.channels.find((c) => c.channelId === idHex);
	expect(row?.status).to.equal(ChannelRecoveryStatus.ReestablishSecretMissing);
	expect(row?.reestablishSecretMissing).to.equal(true);
	expect(row?.restoreRecencyUnproven).to.not.equal(true);
	expect(row?.reestablishRecencyUnproven).to.not.equal(true);
	const info = fx.alice
		.listChannels()
		.find((c) => c.channelId.equals(fx.channelId));
	expect(info?.reestablishSecretMissing).to.equal(true);
	expect(info?.htlcUsable).to.equal(false);
}

describe('Issue #919: a missing per-commitment secret never leaves as zeroes', function () {
	this.timeout(20_000);

	it('builds no channel_reestablish, and persists the fault before anything else', () => {
		// The action list itself, at the channel layer: PERSIST_STATE leads (a
		// crash between here and the socket must not forget the hold), the
		// peer gets the bare wire error, the local ERROR carries the detail,
		// and no CHANNEL_REESTABLISH is built at all.
		const fx = setup(31);
		const revocationCount = loseTheSecrets(fx);
		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;

		const actions = channel.createReestablish();

		expect(actions[0].type).to.equal(ChannelActionType.PERSIST_STATE);
		expect(
			actions.some(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					a.messageType === MessageType.CHANNEL_REESTABLISH
			),
			'no channel_reestablish is built'
		).to.equal(false);
		const wire = actions.find(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				a.messageType === MessageType.ERROR
		);
		expect(wire, 'the peer is told the channel is failed').to.exist;
		const wireText = decodeErrorMessage(
			(wire as { payload: Buffer }).payload
		).data.toString('ascii');
		expect(wireText).to.include(WIRE_TEXT);
		expect(wireText).to.include('awaiting your force close');
		// What the peer must NOT learn: which secret this node lost tells it
		// where its own revoked commitments may go unpunished.
		expect(wireText).to.not.include('shachain');
		expect(wireText).to.not.include(String(revocationCount - 1n));
		const local = actions.find((a) => a.type === ChannelActionType.ERROR);
		expect(local, 'the local error names the fault').to.exist;
		const localText = (local as { message: string }).message;
		expect(localText).to.include(LOCAL_TEXT);
		expect(localText).to.include(`revocation index ${revocationCount - 1n}`);
		expect(localText).to.include('acceptStaleStateRisk: true');
		expect(localText).to.include(fx.channelId.toString('hex'));

		// The flag is on the row and survives storage.
		const state = fx.state();
		expect(state.reestablishSecretMissing).to.equal(true);
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(serializeChannelState(state)))
		);
		expect(restored.reestablishSecretMissing).to.equal(true);
		expect(isRecencyUnproven(restored)).to.equal(true);
		fx.destroy();
	});

	it('sends no zeroes at a non-zero next_revocation_number, and holds the row', () => {
		const fx = setup(33);
		loseTheSecrets(fx);

		reconnect(fx);

		expect(
			fx.sent.includes(MessageType.CHANNEL_REESTABLISH),
			'nothing carrying a fabricated secret left the node'
		).to.equal(false);
		expect(fx.reestablishesSent).to.have.length(0);
		expect(
			fx.errorsSent.some((m) => m.includes(WIRE_TEXT)),
			'the peer was told the channel is failed'
		).to.equal(true);
		expect(
			fx.errorsSent.some((m) => m.includes('awaiting your force close')),
			'...and asked to close it, which is the 5.6 disposition'
		).to.equal(true);
		// Not closed on chain by our own hand: the row may be the rolled-back
		// copy, which is what the hold exists for.
		expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSED');
		expect(fx.logs).to.include('channel:close_skipped_restore_unproven');
		const skip = fx.records.find(
			(r) => r.action === 'close_skipped_restore_unproven'
		)!;
		expect(skip.data.hold).to.equal('secret-missing');
		expectSecretMissingHold(fx);
		fx.destroy();
	});

	it('announces the fault locally: the structured log and the node:error', () => {
		const fx = setup(35);
		const revocationCount = loseTheSecrets(fx);

		reconnect(fx);

		expect(fx.logs).to.include('channel:reestablish_secret_missing');
		const log = fx.records.find(
			(r) => r.action === 'reestablish_secret_missing'
		)!;
		expect(log.category).to.equal('channel');
		expect(log.data.channelId).to.equal(fx.channelId.toString('hex'));
		expect(log.data.revocationIndex).to.equal(String(revocationCount - 1n));
		expect(log.data.secretIndex).to.be.a('string');

		expect(fx.events).to.include('REESTABLISH_SECRET_MISSING');
		const err = fx.errorEvents.find(
			(e) => e.code === 'REESTABLISH_SECRET_MISSING'
		)!;
		expect(err.channelId?.equals(fx.channelId)).to.equal(true);
		expect(err.message).to.include(fx.channelId.toString('hex'));
		expect(err.message).to.include(`revocation index ${revocationCount - 1n}`);
		expect(err.message).to.include('acceptStaleStateRisk: true');
		// The operator hears it BEFORE the peer's answer can do anything.
		expect(fx.events.indexOf('REESTABLISH_SECRET_MISSING')).to.equal(0);
		fx.destroy();
	});

	it('takes no new HTLCs, and says which fault disabled them', () => {
		const fx = setup(37);
		loseTheSecrets(fx);
		reconnect(fx);
		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
		const before = fx.state().htlcs.size;

		const actions = channel.addHtlc(
			1_000_000n,
			crypto.randomBytes(32),
			500,
			Buffer.alloc(1366)
		);

		const refusal = actions.find((a) => a.type === ChannelActionType.ERROR);
		expect(refusal, 'the add is refused').to.exist;
		const text = (refusal as { message: string }).message;
		expect(text).to.include('could not produce the per-commitment secret');
		expect(text).to.include('on-chain HTLC backstops are disabled');
		// This origin, not one of the other two, and not the bare state name.
		expect(text).to.not.include('Recovery Capsule');
		expect(text).to.not.include('ERRORED state');
		expect(fx.state().htlcs.size).to.equal(before);
		fx.destroy();
	});

	it('refuses a cooperative close in both directions without the acknowledgement', () => {
		const fx = setup(39);
		loseTheSecrets(fx);
		reconnect(fx);
		const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;

		const refused = channel.initiateShutdown(SWEEP_SCRIPT);

		const refusal = refused.find((a) => a.type === ChannelActionType.ERROR);
		expect(refusal, 'the close is refused').to.exist;
		const text = (refusal as { message: string }).message;
		expect(text).to.include('Cannot close cooperatively');
		expect(text).to.include(
			'could not produce the per-commitment secret its own channel_reestablish'
		);
		expect(text).to.not.include('Recovery Capsule');
		expect(
			refused.some(
				(a) =>
					a.type === ChannelActionType.SEND_MESSAGE &&
					a.messageType === MessageType.SHUTDOWN
			),
			'no shutdown advertises a close we would then refuse'
		).to.equal(false);
		// The manager's post-reestablish resume asks the same question.
		const resumed = channel.refuseHeldMutualClose();
		const resumeText = (
			resumed.find((a) => a.type === ChannelActionType.ERROR) as {
				message: string;
			}
		).message;
		expect(resumeText).to.include('Cannot resume cooperative close');
		expect(resumeText).to.include(
			'could not produce the per-commitment secret'
		);
		fx.destroy();
	});

	it('refuses every automatic force close and admits the operator', () => {
		// The per-arm skips are one layer; the central guard is the one that
		// has to hold on its own, so it is reached directly here with an
		// automatic reason, as a path that forgot its skip would.
		const fx = setup(41);
		loseTheSecrets(fx);
		reconnect(fx);
		expectSecretMissingHold(fx);
		const guard = fx.alice as unknown as IGuardAccess;

		const refused = guard._forceCloseWithReason(
			fx.channelId,
			SWEEP_SCRIPT,
			10,
			'STUCK_CHANNEL_FORCE_CLOSED'
		);

		expect(refused.ok).to.equal(false);
		expect(refused.error).to.contain('recency hold');
		expect(refused.actions.some((a) => a.type === 'BROADCAST_TX')).to.equal(
			false
		);
		expect(fx.state().state).to.equal(ChannelState.ERRORED);
		expect(fx.state().closeReason).to.not.exist;
		expectSecretMissingHold(fx);

		// The exit: the operator's own close, which is reason 'user'. The
		// daemon asks for the labelled acknowledgement first
		// (tests/cli/recovery-surface.test.ts); the engine does not gate it.
		const result = fx.alice.forceCloseChannel(fx.channelId, SWEEP_SCRIPT);

		expect(result.ok, result.error).to.equal(true);
		expect(result.commitmentTxid).to.be.a('string');
		expect(fx.events).to.not.include('FORCE_CLOSE_FAILED');
		expect(fx.state().state).to.equal(ChannelState.FORCE_CLOSED);
		fx.destroy();
	});

	it('repeats the peer-close request on every later reconnect', () => {
		// The row is ERRORED from the moment the flag is set, so it never
		// builds another reestablish; the derived disposition is the only
		// thing that moves it, and it has to survive a reconnect.
		const fx = setup(43);
		loseTheSecrets(fx);
		reconnect(fx);
		const before = fx.errorsSent.length;

		fx.alice.getChannelManager().handlePeerReconnected(fx.bob.getNodeId());

		expect(fx.errorsSent.length).to.be.greaterThan(before);
		expect(
			fx.errorsSent[fx.errorsSent.length - 1],
			'the regenerated request, still saying nothing about the secret'
		).to.include(WIRE_TEXT);
		expect(fx.sent.includes(MessageType.CHANNEL_REESTABLISH)).to.equal(false);
		expect(fx.state().state).to.equal(ChannelState.ERRORED);
		fx.destroy();
	});

	it('leaves the next_revocation_number 0 case exactly as it was', () => {
		// BOLT 2 REQUIRES the 32 zero bytes there, and an empty store is
		// correct rather than damaged: nothing has been revoked yet.
		const fx = setup(45, 0);
		const state = fx.state();
		expect(
			state.remoteRevocationNumber ?? state.remoteCommitmentNumber
		).to.equal(0n);
		expect(state.shaChainStore.getEntryCount()).to.equal(0);

		reconnect(fx);

		expect(
			fx.reestablishesSent,
			'the reestablish still goes out'
		).to.have.length(1);
		const msg = fx.reestablishesSent[0];
		expect(msg.nextRevocationNumber).to.equal(0n);
		expect(msg.yourLastPerCommitmentSecret.equals(Buffer.alloc(32))).to.equal(
			true
		);
		expect(fx.state().reestablishSecretMissing).to.not.equal(true);
		expect(fx.state().state).to.not.equal(ChannelState.ERRORED);
		expect(fx.events).to.not.include('REESTABLISH_SECRET_MISSING');
		fx.destroy();
	});

	it('a healthy channel still sends the real secret', () => {
		// The control: nothing about the fixture, the rounds or the reconnect
		// makes a reestablish refuse by itself.
		const fx = setup(47);
		const state = fx.state();
		const revocationCount =
			state.remoteRevocationNumber ?? state.remoteCommitmentNumber;

		reconnect(fx);

		expect(fx.reestablishesSent).to.have.length(1);
		const msg = fx.reestablishesSent[0];
		expect(msg.nextRevocationNumber).to.equal(revocationCount);
		expect(msg.yourLastPerCommitmentSecret.equals(Buffer.alloc(32))).to.equal(
			false
		);
		expect(fx.state().reestablishSecretMissing).to.not.equal(true);
		expect(fx.events).to.not.include('REESTABLISH_SECRET_MISSING');
		fx.destroy();
	});
});
