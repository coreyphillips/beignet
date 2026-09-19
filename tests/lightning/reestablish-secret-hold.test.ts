/**
 * Issue #907, end to end: a channel_reestablish that counts a revoke_and_ack
 * this node never sent, without the secret that would prove it, must not
 * end in OUR commitment on chain by the node's own hand.
 *
 * Channel.handleReestablish refuses a wrong your_last_per_commitment_secret
 * with a wire error and ERRORED, and the node drives every such pair to a
 * force close (handleChannelErrored, issue #175). Read together, a wrong
 * secret at an index this row never released would broadcast a commitment
 * the peer may hold the revocation for, at once rather than after the
 * reestablish timeout, and a peer holding the newer state could choose that
 * outcome with 32 zero bytes. The refusal now marks the row
 * reestablishRecencyUnproven first: the same hold a capsule restore carries,
 * so the errored close, the timeout backstops and the HTLC deadline backstops
 * all skip it and the peer is asked to close with its own commitment. It is
 * NOT StateUncertain: a hostile peer can make this claim for free against a
 * healthy channel, so the operator's labelled force close stays open as the
 * exit (ungated at the node, behind acceptStaleStateRisk on the daemon). A
 * wrong secret at an index this row DID release is a plain violation and
 * keeps the on-chain failure.
 *
 * Every cell here goes through LightningNode, because handleReestablish
 * itself returns no BROADCAST_TX on any path: the on-chain consequence of a
 * refusal is decided one layer up.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IStructuredLog } from '../../src/lightning/node/types';
import {
	ChannelState,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import {
	IChannelState,
	isRecencyUnproven,
	mustNotBroadcastCommitment
} from '../../src/lightning/channel/channel-state';
import { ChannelRecoveryStatus } from '../../src/lightning/recovery/channel-status';
import { MessageType } from '../../src/lightning/message/types';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { encodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';

const TAG = 'reestablish-secret-hold';
const HEIGHT = 800_000;
const SWEEP_SCRIPT = Buffer.concat([
	Buffer.from([0x00, 0x14]),
	crypto.randomBytes(20)
]);
const VALIDATOR_ERROR = 'Invalid per-commitment secret in channel_reestablish';
const PEER_CLOSE_REQUEST = 'without the per-commitment secret proving it';

/** The per-block scans and the timeout, private on the node. */
interface IScanAccess {
	reestablishTimeoutBlocks: number;
	scanStuckChannels(blockHeight: number): void;
	scanExpiringHtlcs(blockHeight: number): void;
	scanExpiringOfferedHtlcs(blockHeight: number): void;
}

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	/** node:error codes Alice emitted. */
	events: string[];
	/** category:action of every structured log Alice emitted. */
	logs: string[];
	/** The text of every wire error Alice sent Bob. */
	errorsSent: string[];
	state: () => IChannelState;
	destroy: () => void;
}

function setup(seedBase: number): IFixture {
	const alice = createNode(TAG, seedBase);
	const bob = createNode(TAG, seedBase + 1);
	connectNodes(alice, bob);
	const channelId = openReadyChannel(alice, bob);
	// One HTLC round through the loopback, so Alice's row has released a
	// secret (localCommitmentNumber >= 1) and a compatible non-zero
	// next_revocation_number exists for the control cell. Bob never settles
	// it (the hash is random), so it stays an offered HTLC on Alice's row
	// for the deadline-backstop cell.
	alice
		.getChannelManager()
		.addHtlc(
			channelId,
			10_000_000n,
			crypto.randomBytes(32),
			500,
			Buffer.alloc(1366)
		);
	const events: string[] = [];
	const logs: string[] = [];
	const errorsSent: string[] = [];
	alice.on('node:error', (err: { code: string }) => events.push(err.code));
	alice.on('log', (log: IStructuredLog) =>
		logs.push(`${log.category}:${log.action}`)
	);
	alice.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === bob.getNodeId() && type === MessageType.ERROR) {
				errorsSent.push(decodeErrorMessage(payload).data.toString('ascii'));
			}
		}
	);
	return {
		alice,
		bob,
		channelId,
		events,
		logs,
		errorsSent,
		state: (): IChannelState =>
			alice.getChannelManager().getChannel(channelId)!.getFullState(),
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
		}
	};
}

/**
 * Bob's channel_reestablish, hand built so the counters and the secret are
 * the test's to choose. The disconnect first rolls Alice's row into
 * AWAITING_REESTABLISH, where handleReestablish runs.
 */
function reestablishFromBob(
	fx: IFixture,
	fields: {
		nextCommitmentNumber: bigint;
		nextRevocationNumber: bigint;
		yourLastPerCommitmentSecret: Buffer;
	}
): void {
	fx.alice.getChannelManager().handlePeerDisconnected(fx.bob.getNodeId());
	fx.alice.handlePeerMessage(
		fx.bob.getNodeId(),
		MessageType.CHANNEL_REESTABLISH,
		encodeChannelReestablishMessage({
			channelId: fx.channelId,
			...fields,
			myCurrentPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
		})
	);
}

/** Zeroes at a revocation gap: the issue's message. */
function zeroSecretGap(fx: IFixture): void {
	const pre = fx.state();
	expect(Number(pre.localCommitmentNumber)).to.be.at.least(1);
	reestablishFromBob(fx, {
		nextCommitmentNumber: pre.remoteCommitmentNumber + 50n,
		nextRevocationNumber: pre.localCommitmentNumber + 3n,
		yourLastPerCommitmentSecret: Buffer.alloc(32)
	});
}

/**
 * ERRORED and not closed by the node's own hand. `via` names the branch of
 * handleChannelErrored that declined: the hold's skip (issue #907, and the
 * capsule restore's), or the never-broadcast predicate's (data loss).
 */
function expectHeldNotClosed(
	fx: IFixture,
	via: 'close_skipped_restore_unproven' | 'errored_awaiting_peer_close'
): void {
	const state = fx.state();
	expect(state.state).to.equal(ChannelState.ERRORED);
	expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSED');
	expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSE_FAILED');
	expect(fx.logs).to.include(`channel:${via}`);
}

/** The hold itself, on the row and on every surface that reports it. */
function expectReestablishHold(fx: IFixture): void {
	const state = fx.state();
	expect(state.reestablishRecencyUnproven).to.equal(true);
	expect(state.stateUncertain).to.not.equal(true);
	expect(state.dataLossDetected).to.not.equal(true);
	expect(state.restoreRecencyUnproven).to.not.equal(true);
	expect(mustNotBroadcastCommitment(state)).to.equal(false);
	expect(isRecencyUnproven(state)).to.equal(true);
	const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
	expect(channel.getRecoveryCloseReason()).to.equal('reestablish-unproven');
	expect(channel.acceptsNewHtlcs()).to.equal(false);
	const idHex = fx.channelId.toString('hex');
	const row = fx.alice
		.getRecoveryStatus()
		.channels.find((c) => c.channelId === idHex);
	expect(row?.status).to.equal(
		ChannelRecoveryStatus.ReestablishRecencyUnproven
	);
	expect(row?.reestablishRecencyUnproven).to.equal(true);
	expect(row?.restoreRecencyUnproven).to.not.equal(true);
	const info = fx.alice
		.listChannels()
		.find((c) => c.channelId.equals(fx.channelId));
	expect(info?.reestablishRecencyUnproven).to.equal(true);
	expect(info?.htlcUsable).to.equal(false);
}

describe('Issue #907: a wrong secret at an unreleased index is held, never closed by us', function () {
	this.timeout(20_000);

	it('holds the channel ERRORED for the peer instead of failing it on chain', () => {
		const fx = setup(11);

		zeroSecretGap(fx);

		expectHeldNotClosed(fx, 'close_skipped_restore_unproven');
		expect(fx.logs).to.not.include('channel:errored_awaiting_peer_close');
		expect(
			fx.errorsSent.some((m) => m.includes(VALIDATOR_ERROR)),
			'the validator wire error went to the peer'
		).to.equal(true);
		expect(
			fx.errorsSent.some((m) => m.includes(PEER_CLOSE_REQUEST)),
			'the peer-close request left at once, not only on the next reconnect'
		).to.equal(true);
		expectReestablishHold(fx);
		fx.destroy();
	});

	it("the operator's force close is the exit: ungated at the node", () => {
		// The hold refuses the node's OWN closes. The operator's is reason
		// 'user', which every hold admits (the daemon asks for the labelled
		// acknowledgement first; tests/cli/recovery-surface.test.ts).
		const fx = setup(13);
		zeroSecretGap(fx);
		expectHeldNotClosed(fx, 'close_skipped_restore_unproven');
		expectReestablishHold(fx);

		const result = fx.alice.forceCloseChannel(fx.channelId, SWEEP_SCRIPT);

		expect(result.ok, result.error).to.equal(true);
		expect(result.commitmentTxid).to.be.a('string');
		expect(fx.events).to.not.include('FORCE_CLOSE_FAILED');
		expect(fx.state().state).to.equal(ChannelState.FORCE_CLOSED);
		fx.destroy();
	});

	it('the HTLC deadline backstops skip the held row', () => {
		// ERRORED is admitted by the expiry scanners on purpose (a failed
		// peer is the one that cannot be trusted to resolve an HTLC), and a
		// wrong-secret row is ERRORED, so without the hold the scans would
		// close it at the first expiry even if the errored close had not.
		const fx = setup(15);
		// The fixture's own HTLC is failed back by Bob (unknown hash), so the
		// two shapes the backstops close for are placed on the row directly,
		// as error-forecloses-channel.test.ts does: an offered HTLC past its
		// expiry (HTLC_EXPIRY_FORCE_CLOSE) and an inbound one whose preimage
		// this node holds (HTLC_CLAIM_FORCE_CLOSE).
		const state = fx.state();
		state.htlcs.set('offered-7', {
			id: 7n,
			amountMsat: 50_000_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.OFFERED,
			state: HtlcState.COMMITTED
		});
		state.localBalanceMsat -= 50_000_000n;
		state.htlcs.set('received-7', {
			id: 7n,
			amountMsat: 20_000_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.FULFILLED
		});

		zeroSecretGap(fx);
		expectHeldNotClosed(fx, 'close_skipped_restore_unproven');
		const scan = fx.alice as unknown as IScanAccess;
		const skipsBefore = fx.logs.filter(
			(l) => l === 'channel:close_skipped_restore_unproven'
		).length;

		// Past expiry, zero grace on an errored channel.
		scan.scanExpiringOfferedHtlcs(600);
		scan.scanExpiringHtlcs(600);

		expect(fx.events).to.not.include('HTLC_EXPIRY_FORCE_CLOSE');
		expect(fx.events).to.not.include('HTLC_CLAIM_FORCE_CLOSE');
		expect(
			fx.logs.filter((l) => l === 'channel:close_skipped_restore_unproven')
				.length,
			'each backstop declined through the hold, not by accident'
		).to.be.at.least(skipsBefore + 2);
		expect(fx.state().state).to.equal(ChannelState.ERRORED);
		fx.destroy();
	});

	it('the ERRORED and reestablish timeout backstops never fire on it', () => {
		const fx = setup(17);
		zeroSecretGap(fx);
		expectHeldNotClosed(fx, 'close_skipped_restore_unproven');
		const scan = fx.alice as unknown as IScanAccess;

		scan.scanStuckChannels(HEIGHT);
		scan.scanStuckChannels(HEIGHT + scan.reestablishTimeoutBlocks + 1);

		expect(fx.events).to.not.include('ERRORED_TIMEOUT_FORCE_CLOSED');
		expect(fx.events).to.not.include('REESTABLISH_TIMEOUT_FORCE_CLOSED');
		expect(fx.state().state).to.equal(ChannelState.ERRORED);
		fx.destroy();
	});

	it('the grief case: 32 random bytes at L + 1 against a healthy channel', () => {
		// The cost to a hostile peer is one message. What it buys is this
		// hold, never a commitment of ours on chain and never StateUncertain:
		// the channel is parked, the peer is asked to close, and the operator
		// can leave through the labelled force close at any time.
		const fx = setup(19);
		const pre = fx.state();
		expect(pre.state).to.equal(ChannelState.NORMAL);

		reestablishFromBob(fx, {
			nextCommitmentNumber: pre.remoteCommitmentNumber + 1n,
			nextRevocationNumber: pre.localCommitmentNumber + 1n,
			yourLastPerCommitmentSecret: crypto.randomBytes(32)
		});

		expectHeldNotClosed(fx, 'close_skipped_restore_unproven');
		expect(fx.errorsSent.some((m) => m.includes(VALIDATOR_ERROR))).to.equal(
			true
		);
		expectReestablishHold(fx);

		const result = fx.alice.forceCloseChannel(fx.channelId, SWEEP_SCRIPT);
		expect(result.ok, result.error).to.equal(true);
		expect(fx.state().state).to.equal(ChannelState.FORCE_CLOSED);
		fx.destroy();
	});

	it('a later reestablish is answered with an error and still not closed on chain', () => {
		// The ERRORED row never reaches handleReestablish again: the manager
		// answers with a wire error and re-drives the errored close, which the
		// hold declines as before. The peer's own close is the exit.
		const fx = setup(21);
		zeroSecretGap(fx);
		expectHeldNotClosed(fx, 'close_skipped_restore_unproven');
		const before = fx.errorsSent.length;
		const pre = fx.state();

		reestablishFromBob(fx, {
			nextCommitmentNumber: pre.remoteCommitmentNumber + 50n,
			nextRevocationNumber: pre.localCommitmentNumber + 3n,
			yourLastPerCommitmentSecret: generateFromSeed(
				pre.localPerCommitmentSeed,
				MAX_INDEX - (pre.localCommitmentNumber + 2n)
			)
		});

		expect(fx.errorsSent.length).to.be.greaterThan(before);
		expectHeldNotClosed(fx, 'close_skipped_restore_unproven');
		expectReestablishHold(fx);
		fx.destroy();
	});

	it('the real secret at the same gap lands in the fell-behind arm, not the hold', () => {
		// Control for the arm the issue's message was hiding behind: with the
		// secret the gap is PROVEN and the row is LocalDataLoss, held on the
		// never-broadcast predicate, which closes the operator's exit too.
		const fx = setup(23);
		const pre = fx.state();
		expect(Number(pre.localCommitmentNumber)).to.be.at.least(1);

		reestablishFromBob(fx, {
			nextCommitmentNumber: pre.remoteCommitmentNumber + 50n,
			nextRevocationNumber: pre.localCommitmentNumber + 3n,
			yourLastPerCommitmentSecret: generateFromSeed(
				pre.localPerCommitmentSeed,
				MAX_INDEX - (pre.localCommitmentNumber + 2n)
			)
		});

		expectHeldNotClosed(fx, 'errored_awaiting_peer_close');
		const state = fx.state();
		expect(state.dataLossDetected).to.equal(true);
		expect(state.reestablishRecencyUnproven).to.not.equal(true);
		expect(state.stateUncertain).to.not.equal(true);
		expect(state.recoveryCloseReason).to.equal('local-data-loss');
		expect(mustNotBroadcastCommitment(state)).to.equal(true);
		fx.destroy();
	});

	it('a wrong secret at a released index still fails the channel on chain', () => {
		// The boundary: next_revocation_number at localCommitmentNumber names
		// index localCommitmentNumber - 1, which this row released, so a wrong
		// value there makes no claim on our state. The ordinary wire-error
		// failure stands, and the node closes on chain as it does for any
		// other protocol violation, exactly as master did.
		const fx = setup(25);
		const pre = fx.state();
		expect(Number(pre.localCommitmentNumber)).to.be.at.least(1);

		reestablishFromBob(fx, {
			nextCommitmentNumber: pre.remoteCommitmentNumber + 1n,
			nextRevocationNumber: pre.localCommitmentNumber,
			yourLastPerCommitmentSecret: Buffer.alloc(32)
		});

		expect(fx.state().state).to.equal(ChannelState.FORCE_CLOSED);
		expect(fx.events).to.include('CHANNEL_FAILED_FORCE_CLOSED');
		expect(fx.state().reestablishRecencyUnproven).to.not.equal(true);
		expect(fx.state().stateUncertain).to.not.equal(true);
		expect(fx.errorsSent.some((m) => m.includes(VALIDATOR_ERROR))).to.equal(
			true
		);
		fx.destroy();
	});
});
