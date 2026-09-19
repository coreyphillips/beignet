/**
 * Issue #907, end to end: a channel_reestablish that counts a revoke_and_ack
 * this node never sent, without the secret that would prove it, must not
 * end in OUR commitment on chain.
 *
 * Channel.handleReestablish refuses a wrong your_last_per_commitment_secret
 * with a wire error and ERRORED, and the node drives every such pair to a
 * force close (handleChannelErrored, issue #175). Read together, a wrong
 * secret at an index this row never released would broadcast a commitment
 * the peer may hold the revocation for, at once rather than after the
 * reestablish timeout, and a peer holding the newer state could choose that
 * outcome with 32 zero bytes. The refusal now marks the row StateUncertain
 * first, so the never-broadcast predicate closes the errored close, the
 * timeout backstop and the operator's force close alike, and the peer is
 * asked to close with its own commitment instead. A wrong secret at an index
 * this row DID release is a plain violation and keeps the on-chain failure.
 *
 * Every cell here goes through LightningNode, because handleReestablish
 * itself returns no BROADCAST_TX on any path: the on-chain consequence of a
 * refusal is decided one layer up.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IStructuredLog } from '../../src/lightning/node/types';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	IChannelState,
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

/** The per-block scan and its timeout, private on the node. */
interface IScanAccess {
	reestablishTimeoutBlocks: number;
	scanStuckChannels(blockHeight: number): void;
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
	// next_revocation_number exists for the control cell.
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

function expectHeldNotClosed(fx: IFixture): void {
	const state = fx.state();
	expect(state.state).to.equal(ChannelState.ERRORED);
	expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSED');
	expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSE_FAILED');
	expect(fx.logs).to.include('channel:errored_awaiting_peer_close');
}

describe('Issue #907: a wrong secret at an unreleased index never puts our commitment on chain', function () {
	this.timeout(20_000);

	it('holds the channel ERRORED for the peer instead of failing it on chain', () => {
		const fx = setup(11);

		zeroSecretGap(fx);

		expectHeldNotClosed(fx);
		expect(
			fx.errorsSent.some((m) =>
				m.includes('Invalid per-commitment secret in channel_reestablish')
			),
			'the validator wire error went to the peer'
		).to.equal(true);
		const state = fx.state();
		expect(state.stateUncertain).to.equal(true);
		expect(state.dataLossDetected).to.not.equal(true);
		expect(state.recoveryCloseReason).to.equal('state-uncertain');
		expect(mustNotBroadcastCommitment(state)).to.equal(true);
		const row = fx.alice
			.getRecoveryStatus()
			.channels.find((c) => c.channelId === fx.channelId.toString('hex'));
		expect(row?.status).to.equal(ChannelRecoveryStatus.StateUncertain);
		fx.destroy();
	});

	it("refuses the operator's force close on the same predicate", () => {
		const fx = setup(13);
		zeroSecretGap(fx);
		expectHeldNotClosed(fx);

		const result = fx.alice.forceCloseChannel(fx.channelId, SWEEP_SCRIPT);

		expect(result.ok).to.equal(false);
		expect(result.error).to.contain('not proven current');
		expect(fx.events).to.include('FORCE_CLOSE_FAILED');
		expect(fx.state().state).to.equal(ChannelState.ERRORED);
		fx.destroy();
	});

	it('the ERRORED timeout backstop never fires on it', () => {
		const fx = setup(15);
		zeroSecretGap(fx);
		expectHeldNotClosed(fx);
		const scan = fx.alice as unknown as IScanAccess;

		scan.scanStuckChannels(HEIGHT);
		scan.scanStuckChannels(HEIGHT + scan.reestablishTimeoutBlocks + 1);

		expect(fx.events).to.not.include('ERRORED_TIMEOUT_FORCE_CLOSED');
		expect(fx.events).to.not.include('REESTABLISH_TIMEOUT_FORCE_CLOSED');
		expect(fx.state().state).to.equal(ChannelState.ERRORED);
		fx.destroy();
	});

	it('a later reestablish is answered with an error and still not closed on chain', () => {
		// The ERRORED row never reaches handleReestablish again: the manager
		// answers with a wire error and re-drives the errored close, which the
		// predicate refuses as before. The peer's own close is the exit.
		const fx = setup(17);
		zeroSecretGap(fx);
		expectHeldNotClosed(fx);
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
		expectHeldNotClosed(fx);
		fx.destroy();
	});

	it('the real secret at the same gap lands in the fell-behind arm, not the hold', () => {
		// Control for the arm the issue's message was hiding behind: with the
		// secret the gap is PROVEN and the row is LocalDataLoss, held for the
		// peer's close on the same predicate.
		const fx = setup(19);
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

		expectHeldNotClosed(fx);
		const state = fx.state();
		expect(state.dataLossDetected).to.equal(true);
		expect(state.stateUncertain).to.not.equal(true);
		expect(state.recoveryCloseReason).to.equal('local-data-loss');
		fx.destroy();
	});

	it('a wrong secret at a released index still fails the channel on chain', () => {
		// The boundary: next_revocation_number at localCommitmentNumber names
		// index localCommitmentNumber - 1, which this row released, so a wrong
		// value there makes no claim on our state. The ordinary wire-error
		// failure stands, and the node closes on chain as it does for any
		// other protocol violation.
		const fx = setup(21);
		const pre = fx.state();
		expect(Number(pre.localCommitmentNumber)).to.be.at.least(1);

		reestablishFromBob(fx, {
			nextCommitmentNumber: pre.remoteCommitmentNumber + 1n,
			nextRevocationNumber: pre.localCommitmentNumber,
			yourLastPerCommitmentSecret: Buffer.alloc(32)
		});

		expect(fx.state().state).to.equal(ChannelState.FORCE_CLOSED);
		expect(fx.events).to.include('CHANNEL_FAILED_FORCE_CLOSED');
		expect(fx.state().stateUncertain).to.not.equal(true);
		expect(
			fx.errorsSent.some((m) =>
				m.includes('Invalid per-commitment secret in channel_reestablish')
			)
		).to.equal(true);
		fx.destroy();
	});
});
