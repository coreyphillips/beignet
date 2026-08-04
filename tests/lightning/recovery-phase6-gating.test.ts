/**
 * Recovery Protocol phase 6, part 4: the barrier at the dispatch boundary
 * (docs/RECOVERY-PROTOCOL.md 5.8 and 9).
 *
 * This is where the guarantee is actually enforced, so the invariants are
 * about what does and does not reach the wire:
 *
 * 1. No revoke_and_ack, fulfill or irreversible splice message leaves before
 *    the journal frame that authorized it is quorum durable.
 * 2. A held batch holds its WHOLE remainder, not only its sends. The dispatch
 *    loop interleaves broadcasts, force closes and the re-entrant HTLC emits
 *    with the sends in one order; releasing any of them early inverts the
 *    batch, and a splice signs and broadcasts in the same array.
 * 3. Wire order survives the wait. A channel that is holding messages holds
 *    everything after them too.
 * 4. Guardian latency does not stall unrelated channels: the queue is per
 *    channel, and a batch with nothing barrier-class in it never waits.
 * 5. A refusal DROPS the held bytes rather than flushing them later, and a
 *    disconnect purges them, because markForReestablish rolls the channel
 *    backward under anything parked.
 * 6. Nothing is marked sent until it is actually sent.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	ChannelAction,
	ChannelActionType,
	IChannelPersistEvent,
	IWireDurabilityBarrier
} from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';

// ─────────────── Fixtures ───────────────

const PEER = 'aa'.repeat(33);
const OTHER_PEER = 'bb'.repeat(33);

function stubChannel(channelId: Buffer): Channel {
	return {
		setLocalNodeIdLower: (): void => undefined,
		getChannelId: (): Buffer => channelId,
		getTemporaryChannelId: (): Buffer | null => null,
		getState: (): ChannelState => ChannelState.NORMAL,
		markForReestablish: (): void => undefined
	} as unknown as Channel;
}

/**
 * A barrier under the test's direct control. Real guardians are exercised in
 * recovery-phase6-barrier.test.ts; here the question is what the DISPATCH
 * path does with each answer, so the answers are scripted.
 */
class ScriptedBarrier implements IWireDurabilityBarrier {
	enforcing = true;
	private watermark = 0n;
	private waiters: Array<{
		sequence: bigint;
		resolve: (outcome: { released: boolean; reason: string }) => void;
	}> = [];

	// Mirrors the production barrier, including its fail-closed answer to a
	// missing frame: no frame is not permission, because an unattributed
	// transition names nothing a guardian could ever have receipted.
	isReleased(sequence: bigint | null): boolean {
		if (sequence == null) return false;
		return sequence <= this.watermark;
	}

	whenReleased(
		sequence: bigint | null
	): Promise<{ released: boolean; reason: string }> {
		if (sequence == null) {
			return Promise.resolve({ released: false, reason: 'missing-frame' });
		}
		if (this.isReleased(sequence)) {
			return Promise.resolve({ released: true, reason: 'durable' });
		}
		return new Promise((resolve) => {
			this.waiters.push({ sequence: sequence as bigint, resolve });
		});
	}

	/** Cumulative advance: releases every waiter at or below `through`. */
	advance(through: bigint): void {
		this.watermark = through;
		const released = this.waiters.filter((w) => w.sequence <= through);
		this.waiters = this.waiters.filter((w) => w.sequence > through);
		for (const waiter of released) {
			waiter.resolve({ released: true, reason: 'durable' });
		}
	}

	/** Refuse everything currently held, as a timeout or a fence would. */
	refuse(reason: string): void {
		const waiting = this.waiters;
		this.waiters = [];
		for (const waiter of waiting) waiter.resolve({ released: false, reason });
	}

	get waiting(): number {
		return this.waiters.length;
	}
}

interface IHarness {
	manager: ChannelManager;
	barrier: ScriptedBarrier;
	sent: Array<{ peer: string; type: number }>;
	broadcasts: number;
	frozen: Array<{ channelId: string; reason: string; dropped: number }>;
	dispatchFailed: Array<{
		channelId: string;
		reason: string;
		dropped: number;
	}>;
	errors: string[];
	held: string[];
	outboxSent: Array<Array<number | null>>;
	/** Next frame sequence the persist listener will report. */
	nextFrame: bigint;
}

function makeHarness(enforcing = true): IHarness {
	const barrier = new ScriptedBarrier();
	barrier.enforcing = enforcing;
	const manager = new ChannelManager({
		durabilityBarrier: barrier
	} as unknown as ConstructorParameters<typeof ChannelManager>[0]);

	const harness: IHarness = {
		manager,
		barrier,
		sent: [],
		broadcasts: 0,
		frozen: [],
		dispatchFailed: [],
		errors: [],
		held: [],
		outboxSent: [],
		nextFrame: 1n
	};
	// ChannelManager is a bare EventEmitter, so an unhandled 'error' emit
	// throws out of the call that produced it.
	manager.on('error', (_id: Buffer | null, message: string) => {
		harness.errors.push(message);
	});
	manager.on('channel:persist', ({ request }: IChannelPersistEvent) => {
		if (!request) return;
		request.committed = true;
		request.frameSequence = harness.nextFrame;
		request.outboxIds = request.outbound.map((_m, index) => index + 1);
	});
	manager.on('message:outbound', (peer: string, type: number) => {
		harness.sent.push({ peer, type });
	});
	manager.on('broadcast:tx', () => {
		harness.broadcasts += 1;
	});
	manager.on('outbox:sent', (ids: Array<number | null>) => {
		harness.outboxSent.push(ids);
	});
	manager.on('transition:held', (_peer: string, channelId: string) => {
		harness.held.push(channelId);
	});
	manager.on(
		'transition:frozen',
		(
			_peer: string,
			channelId: string,
			reason: string,
			dropped: number
		): void => {
			harness.frozen.push({ channelId, reason, dropped });
		}
	);
	manager.on(
		'transition:dispatch-failed',
		(
			_peer: string,
			channelId: string,
			reason: string,
			dropped: number
		): void => {
			harness.dispatchFailed.push({ channelId, reason, dropped });
		}
	);
	return harness;
}

function dispatch(
	manager: ChannelManager,
	channel: Channel,
	actions: ChannelAction[],
	peer = PEER
): void {
	(
		manager as unknown as {
			processActions(
				peerPubkey: string,
				channel: Channel,
				actions: ChannelAction[]
			): void;
		}
	).processActions(peer, channel, actions);
}

function send(messageType: number, payload = 1): ChannelAction {
	return {
		type: ChannelActionType.SEND_MESSAGE,
		messageType,
		payload: Buffer.from([payload])
	} as ChannelAction;
}

/** A recovery declaration: gated by its MARK, not by its message type. */
function declare(messageType: number, payload = 1): ChannelAction {
	return {
		type: ChannelActionType.SEND_MESSAGE,
		messageType,
		payload: Buffer.from([payload]),
		durabilityCritical: true
	} as ChannelAction;
}

function forwardAction(htlcId: bigint): ChannelAction {
	return {
		type: ChannelActionType.HTLC_FORWARDED,
		htlcId,
		amountMsat: 1_000n,
		paymentHash: crypto.randomBytes(32)
	} as ChannelAction;
}

/** Let the barrier's promise callbacks run. */
async function settle(): Promise<void> {
	await new Promise((resolve) => setImmediate(resolve));
	await new Promise((resolve) => setImmediate(resolve));
}

// ─────────────── Tests ───────────────

describe('Recovery phase 6: what the barrier holds at the wire', () => {
	it('a revoke_and_ack does NOT reach the peer before its frame is durable', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);

		expect(harness.sent).to.have.length(0);
		expect(harness.held).to.have.length(1);
		// Not marked sent either: a row reading sent_unacked while the bytes
		// are parked would make restart reestablish accounting believe the
		// peer had seen it.
		expect(harness.outboxSent).to.have.length(0);

		harness.barrier.advance(1n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK
		]);
		expect(harness.outboxSent).to.have.length(1);
	});

	it('a batch with nothing barrier-class in it is never delayed', () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.UPDATE_ADD_HTLC),
			send(MessageType.UPDATE_FEE)
		]);

		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.UPDATE_ADD_HTLC,
			MessageType.UPDATE_FEE
		]);
		expect(harness.held).to.have.length(0);
	});

	it('a frame already below the watermark dispatches SYNCHRONOUSLY', () => {
		const harness = makeHarness();
		harness.barrier.advance(5n);
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);

		// No await anywhere: the common case must not become asynchronous, or
		// every loopback harness in the suite changes behaviour.
		expect(harness.sent).to.have.length(1);
		expect(harness.held).to.have.length(0);
	});

	it('a barrier that is not enforcing changes nothing at all', () => {
		const harness = makeHarness(false);
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK),
			send(MessageType.COMMITMENT_SIGNED)
		]);

		expect(harness.sent).to.have.length(2);
		expect(harness.held).to.have.length(0);
	});

	it('the WHOLE remainder is held, so a splice cannot broadcast before it signs', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		// tx_signatures and the BROADCAST_TX of the transaction it signs sit in
		// one array. Deferring the send alone would put the transaction on the
		// network before the peer saw the message authorizing it.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.TX_SIGNATURES),
			{
				type: ChannelActionType.BROADCAST_TX,
				tx: Buffer.from([0xff])
			} as ChannelAction
		]);

		expect(harness.sent).to.have.length(0);
		expect(harness.broadcasts).to.equal(0);

		harness.barrier.advance(1n);
		await settle();
		expect(harness.sent).to.have.length(1);
		expect(harness.broadcasts).to.equal(1);
	});

	it('actions BEFORE the persist still run, since the persist never authorized them', () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			send(MessageType.UPDATE_ADD_HTLC),
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);

		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.UPDATE_ADD_HTLC
		]);
	});
});

describe('Recovery phase 6: wire order survives the wait', () => {
	it('a channel already holding messages holds everything AFTER them too', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);
		// A follow-on batch with nothing barrier-class in it. Letting it
		// overtake the held revoke would reorder this channel's wire stream.
		harness.nextFrame = 2n;
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.UPDATE_ADD_HTLC)
		]);
		expect(harness.sent).to.have.length(0);

		harness.barrier.advance(2n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK,
			MessageType.UPDATE_ADD_HTLC
		]);
	});

	it('a single cumulative advance releases MANY held batches in order', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		const order = [
			MessageType.REVOKE_AND_ACK,
			MessageType.COMMITMENT_SIGNED,
			MessageType.UPDATE_FULFILL_HTLC
		];
		order.forEach((type, index) => {
			harness.nextFrame = BigInt(index + 1);
			dispatch(harness.manager, channel, [
				{ type: ChannelActionType.PERSIST_STATE },
				send(type)
			]);
		});
		expect(harness.sent).to.have.length(0);

		// One receipt at or above the newest frame frees all three.
		harness.barrier.advance(3n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal(order);
	});
});

describe('Recovery phase 6: one channel waiting does not stall another', () => {
	it('an unrelated channel keeps sending while the first is held', async () => {
		const harness = makeHarness();
		const waiting = stubChannel(crypto.randomBytes(32));
		const other = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, waiting, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);
		expect(harness.sent).to.have.length(0);

		// The other channel carries a BARRIER-CLASS message, so the barrier is
		// genuinely consulted for it; its frame is simply already durable. An
		// ungated message type here would prove nothing, because
		// _shouldHoldBatch would return before ever asking.
		harness.barrier.advance(0n);
		harness.nextFrame = 0n;
		dispatch(
			harness.manager,
			other,
			[
				{ type: ChannelActionType.PERSIST_STATE },
				send(MessageType.REVOKE_AND_ACK)
			],
			OTHER_PEER
		);

		expect(harness.sent.map((e) => e.peer)).to.deep.equal([OTHER_PEER]);
		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK
		]);
		expect(harness.barrier.waiting).to.equal(1);
	});
});

describe('Recovery phase 6: nothing overtakes a held channel', () => {
	it('a batch with NO PERSIST_STATE queues behind held messages', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);
		// initiateShutdown, the closing_signed rounds, stfu and
		// createReestablish all dispatch persist-less arrays. The barrier is
		// consulted at the PERSIST_STATE action, so without a separate check
		// these walk straight past a parked revoke_and_ack.
		dispatch(harness.manager, channel, [send(MessageType.SHUTDOWN)]);
		expect(harness.sent).to.have.length(0);

		harness.barrier.advance(1n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK,
			MessageType.SHUTDOWN
		]);
	});
});

describe('Recovery phase 6: a refusal drops the wire half only', () => {
	it('the internal effects of a refused batch still run', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));
		const forwarded: bigint[] = [];
		harness.manager.on('htlc:forwarded', (_id: Buffer, htlcId: bigint) => {
			forwarded.push(htlcId);
		});

		// handleRevokeAndAck sets htlc.forwardEmitted = true while BUILDING
		// its actions, and the batch's own persist commits that flag. Dropping
		// the HTLC_FORWARDED would mean no later commitment round ever emits
		// it again, and the inbound HTLC sits unforwarded until its CLTV.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK),
			{
				type: ChannelActionType.HTLC_FORWARDED,
				htlcId: 7n,
				amountMsat: 1_000n,
				paymentHash: crypto.randomBytes(32)
			} as ChannelAction
		]);
		expect(forwarded).to.deep.equal([]);

		harness.barrier.refuse('timeout');
		await settle();

		// The wire half is gone, the forward is not.
		expect(harness.sent).to.have.length(0);
		expect(forwarded).to.deep.equal([7n]);
	});
});

describe('Recovery phase 6: a refusal drops, it never flushes late', () => {
	it('a refused barrier sends NOTHING and reports the channel frozen', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = stubChannel(channelId);

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);
		harness.barrier.refuse('timeout');
		await settle();

		expect(harness.sent).to.have.length(0);
		expect(harness.frozen).to.have.length(1);
		expect(harness.frozen[0].reason).to.equal('timeout');
		expect(harness.frozen[0].channelId).to.equal(channelId.toString('hex'));

		// And a LATER advance must not resurrect them. A timeout is not a
		// postponement of permission.
		harness.barrier.advance(10n);
		await settle();
		expect(harness.sent).to.have.length(0);
	});

	it('a disconnect PURGES held messages rather than flushing them', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = stubChannel(channelId);
		(
			harness.manager as unknown as {
				channels: Map<string, Channel>;
				channelPeers: Map<string, string>;
			}
		).channels.set(channelId.toString('hex'), channel);
		(
			harness.manager as unknown as { channelPeers: Map<string, string> }
		).channelPeers.set(channelId.toString('hex'), PEER);

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);
		expect(harness.sent).to.have.length(0);

		// markForReestablish rolls uncommitted updates back under anything
		// parked, so a held message describes a view the channel no longer has.
		harness.manager.handlePeerDisconnected(PEER);
		harness.barrier.advance(10n);
		await settle();

		expect(harness.sent).to.have.length(0);
	});
});

describe('Recovery phase 6: nothing goes out on a frame nobody named', () => {
	it('a barrier-class message with NO persist ahead of it is refused, never sent', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = stubChannel(channelId);

		// The barrier is consulted at the PERSIST_STATE action and nowhere
		// else, so a batch without one used to walk straight past it. There is
		// no receipt that could ever cover this message: refusing is the only
		// honest answer.
		dispatch(harness.manager, channel, [send(MessageType.REVOKE_AND_ACK)]);
		await settle();

		expect(harness.sent).to.have.length(0);
		expect(harness.frozen).to.have.length(1);
		expect(harness.frozen[0].reason).to.equal('missing-frame');
		expect(harness.frozen[0].channelId).to.equal(channelId.toString('hex'));
		expect(harness.errors.join(' ')).to.contain('PERSIST_STATE');
		// And it must RETURN rather than throw: processActions runs inside the
		// socket data callback, with no try/catch anywhere above it.
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(0);
	});

	it('a recovery declaration is refused too, so the regenerated close waits', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		// buildRecoveryCloseActions regenerates the data-loss error on every
		// reconnect. Without its own persist it names no frame, and a peer
		// acting on it while the disposition is still only local is exactly
		// how a restore comes back believing it may broadcast again.
		dispatch(harness.manager, channel, [declare(MessageType.ERROR)]);
		await settle();

		expect(harness.sent).to.have.length(0);
		expect(harness.frozen.map((f) => f.reason)).to.deep.equal([
			'missing-frame'
		]);
	});

	it('the declaration DOES go out once its own frame is durable', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			declare(MessageType.ERROR)
		]);
		expect(harness.sent).to.have.length(0);
		expect(harness.held).to.have.length(1);

		harness.barrier.advance(1n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([MessageType.ERROR]);
	});

	it('an ORDINARY protocol error is not held at all', () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		// error is BOLT 1's single overloaded failure channel. Holding a
		// protocol-violation error would buy nothing (it advances no
		// commitment state) and cost a great deal: it is not retransmittable,
		// so a refused one is lost for good, and the local force close it
		// drives rides the same send.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.ERROR)
		]);

		expect(harness.sent.map((e) => e.type)).to.deep.equal([MessageType.ERROR]);
		expect(harness.held).to.have.length(0);
	});
});

describe('Recovery phase 6: a partial dispatch takes its queue with it', () => {
	it('a batch that throws partway stops every batch queued behind it', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = stubChannel(channelId);

		// One inbound commitment_signed reliably parks revoke_and_ack ahead of
		// the commitment_signed that answers it. If the first dies partway and
		// the second still drains, the peer gets a commitment with no
		// preceding revocation, which is a BOLT 2 violation it answers by
		// failing the channel with HTLCs in flight.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK),
			forwardAction(1n)
		]);
		harness.nextFrame = 2n;
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.COMMITMENT_SIGNED)
		]);
		expect(harness.sent).to.have.length(0);

		harness.manager.on('htlc:forwarded', () => {
			throw new Error('observer exploded');
		});
		harness.barrier.advance(2n);
		await settle();

		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK
		]);
		expect(harness.dispatchFailed).to.have.length(1);
		expect(harness.dispatchFailed[0].reason).to.contain('observer exploded');
		expect(harness.dispatchFailed[0].dropped).to.equal(2);
		expect(harness.dispatchFailed[0].channelId).to.equal(
			channelId.toString('hex')
		);
		// Nothing is marked sent, so reestablish offers the rows again.
		expect(harness.outboxSent).to.have.length(0);
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(0);

		// A later advance must not resurrect the abandoned queue either.
		harness.barrier.advance(10n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.REVOKE_AND_ACK
		]);
	});

	it('the failed batch keeps the committed effects of its own tail', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));
		const seen: bigint[] = [];
		harness.manager.on('htlc:forwarded', (_id: Buffer, htlcId: bigint) => {
			seen.push(htlcId);
			if (htlcId === 1n) throw new Error('first observer exploded');
		});

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK),
			forwardAction(1n),
			forwardAction(2n)
		]);
		harness.barrier.advance(1n);
		await settle();

		// forwardEmitted was set while the batch was BUILT and is already on
		// disk, so a forward skipped here is never emitted by any later
		// commitment round and the HTLC sits unforwarded until its CLTV.
		expect(seen).to.deep.equal([1n, 2n]);
		expect(harness.dispatchFailed).to.have.length(1);
		expect(harness.dispatchFailed[0].dropped).to.equal(1);
	});
});

describe('Recovery phase 6: the peer-close request survives a refusal', () => {
	/** An ERRORED channel whose disposition regenerates the close request. */
	function erroredRecoveryChannel(channelId: Buffer): Channel {
		return {
			setLocalNodeIdLower: (): void => undefined,
			getChannelId: (): Buffer => channelId,
			getTemporaryChannelId: (): Buffer | null => null,
			getState: (): ChannelState => ChannelState.ERRORED,
			markForReestablish: (): void => undefined,
			buildRecoveryCloseActions: (): ChannelAction[] => [
				{ type: ChannelActionType.PERSIST_STATE },
				declare(MessageType.ERROR)
			]
		} as unknown as Channel;
	}

	it('times out, reconnects, and STILL sends nothing while the quorum is behind', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = erroredRecoveryChannel(channelId);
		(
			harness.manager as unknown as {
				channels: Map<string, Channel>;
				channelPeers: Map<string, string>;
			}
		).channels.set(channelId.toString('hex'), channel);
		(
			harness.manager as unknown as { channelPeers: Map<string, string> }
		).channelPeers.set(channelId.toString('hex'), PEER);

		// The original declaration is held and then refused.
		dispatch(harness.manager, channel, channel.buildRecoveryCloseActions());
		expect(harness.sent).to.have.length(0);
		harness.barrier.refuse('timeout');
		await settle();
		expect(harness.sent).to.have.length(0);
		expect(harness.frozen.map((f) => f.reason)).to.deep.equal(['timeout']);

		// The peer reconnects while the quorum is STILL unreachable. The
		// disposition regenerates the request, and it must not walk out on the
		// strength of having been regenerated rather than replicated.
		harness.nextFrame = 2n;
		harness.manager.handlePeerReconnected(PEER);
		await settle();
		expect(harness.sent).to.have.length(0);
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(1);

		// Quorum returns, covering the frame the RECONNECT persist minted.
		harness.barrier.advance(2n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([MessageType.ERROR]);
	});
});

describe('Recovery phase 6: funding does not outrun its own frame', () => {
	const authorize = (): ChannelAction =>
		({
			type: ChannelActionType.AUTHORIZE_FUNDING_BROADCAST,
			fundingTxid: crypto.randomBytes(32)
		}) as ChannelAction;

	const watchFunding = (): ChannelAction =>
		({
			type: ChannelActionType.WATCH_FUNDING,
			fundingTxid: crypto.randomBytes(32),
			fundingOutputIndex: 0,
			minimumDepth: 1
		}) as ChannelAction;

	it("the fundee's funding_signed waits for the frame that first records the channel", async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));
		const watched: number[] = [];
		harness.manager.on('watch:funding', () => watched.push(1));

		// The real acceptor batch. A restore below this frame comes back with
		// no channel at all, while a 2-of-2 naming us is on the network.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.FUNDING_SIGNED),
			watchFunding()
		]);
		expect(harness.sent).to.have.length(0);
		expect(watched).to.have.length(0);
		expect(harness.held).to.have.length(1);

		harness.barrier.advance(1n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.FUNDING_SIGNED
		]);
		expect(watched).to.have.length(1);
	});

	it("the funder's authorization is held, and the watch still arms on a refusal", async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));
		const authorized: number[] = [];
		const watched: number[] = [];
		harness.manager.on('funding:authorized', () => authorized.push(1));
		harness.manager.on('watch:funding', () => watched.push(1));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			watchFunding(),
			authorize()
		]);
		expect(authorized).to.have.length(0);

		// A refusal runs the suffix for its internal effects with the
		// irreversible ones suppressed, which is exactly the right disposition
		// here: the outpoint is watched, the transaction is not created.
		harness.barrier.refuse('timeout');
		await settle();
		expect(watched).to.have.length(1);
		expect(authorized).to.have.length(0);
		expect(harness.frozen.map((f) => f.reason)).to.deep.equal(['timeout']);
	});

	it('a released funder batch authorizes exactly once, after its frame', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));
		const authorized: number[] = [];
		harness.manager.on('funding:authorized', () => authorized.push(1));

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			watchFunding(),
			authorize(),
			// The zero-conf tail rides the same batch and must not overtake the
			// authorization.
			send(MessageType.CHANNEL_READY)
		]);
		expect(authorized).to.have.length(0);
		expect(harness.sent).to.have.length(0);

		harness.barrier.advance(1n);
		await settle();
		expect(authorized).to.have.length(1);
		expect(harness.sent.map((e) => e.type)).to.deep.equal([
			MessageType.CHANNEL_READY
		]);
	});

	it('a failed persist withholds the authorization', () => {
		const harness = makeHarness(false);
		const channel = stubChannel(crypto.randomBytes(32));
		const authorized: number[] = [];
		harness.manager.on('funding:authorized', () => authorized.push(1));
		harness.manager.removeAllListeners('channel:persist');
		harness.manager.on(
			'channel:persist',
			({ request }: IChannelPersistEvent) => {
				if (request) request.committed = false;
			}
		);

		// Independent of quorum mode: a funding transaction whose channel state
		// never reached disk is a 2-of-2 no restored node can enumerate. As a
		// bare emit off watch:funding this could not be withheld at all.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			watchFunding(),
			authorize()
		]);
		expect(authorized).to.have.length(0);
	});

	it('a funding-critical broadcast is held, and a force close never is', async () => {
		const harness = makeHarness();
		const channel = stubChannel(crypto.randomBytes(32));

		// The splice and v2 paths build a BROADCAST_TX of their own. When WE
		// signed first there is no tx_signatures left in the batch, so without
		// the mark nothing in it would be barrier-class.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			{
				type: ChannelActionType.BROADCAST_TX,
				tx: Buffer.from([1]),
				fundingCritical: true
			} as ChannelAction
		]);
		expect(harness.broadcasts).to.equal(0);
		harness.barrier.advance(1n);
		await settle();
		expect(harness.broadcasts).to.equal(1);

		// A force close carries no persist at all. Gating BROADCAST_TX by type
		// would route it through the unattributed refusal and take away the
		// only exit an operator has left.
		const closing = stubChannel(crypto.randomBytes(32));
		dispatch(harness.manager, closing, [
			{ type: ChannelActionType.BROADCAST_TX, tx: Buffer.from([2]) }
		]);
		expect(harness.broadcasts).to.equal(2);
	});
});

describe('Recovery phase 6: force close is the exit, never a queue entry', () => {
	it('a force close on a HELD channel broadcasts, and the queue never flushes', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = stubChannel(channelId);
		const idHex = channelId.toString('hex');
		const manager = harness.manager as unknown as {
			channels: Map<string, Channel>;
			channelPeers: Map<string, string>;
			_abandonQueueForTerminalClose(id: string): void;
		};
		manager.channels.set(idHex, channel);
		manager.channelPeers.set(idHex, PEER);
		const overrides: Array<{ channelId: string; dropped: number }> = [];
		harness.manager.on(
			'transition:terminal-override',
			(_peer: string, id: string, dropped: number) => {
				overrides.push({ channelId: id, dropped });
			}
		);

		// Something irreversible is already parked on this channel.
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			send(MessageType.REVOKE_AND_ACK)
		]);
		expect(harness.sent).to.have.length(0);
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(1);

		// The operator's exit. Its batch carries no persist, so the wire-order
		// rule would park it behind the held revoke; a refusal there would then
		// suppress the commitment broadcast while the CHANNEL_CLOSED beside it
		// still ran, and the caller would already have been told ok.
		manager._abandonQueueForTerminalClose(idHex);
		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.BROADCAST_TX, tx: Buffer.from([7]) },
			{ type: ChannelActionType.CHANNEL_CLOSED, channelId } as ChannelAction
		]);

		expect(harness.broadcasts).to.equal(1);
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(0);
		expect(overrides).to.deep.equal([{ channelId: idHex, dropped: 1 }]);

		// And the abandoned revoke never reaches the peer, before or after the
		// barrier resolves either way. Once the commitment is on chain, an
		// older message would describe a channel that no longer exists.
		harness.barrier.advance(10n);
		await settle();
		expect(harness.sent).to.have.length(0);

		harness.barrier.refuse('timeout');
		await settle();
		expect(harness.sent).to.have.length(0);
	});
});

describe('Recovery phase 6: a restart asks the barrier, it does not assume', () => {
	/** A restored channel that still owes its funding broadcast. */
	function restoredFunder(channelId: Buffer, txid: Buffer): Channel {
		return {
			setLocalNodeIdLower: (): void => undefined,
			getChannelId: (): Buffer => channelId,
			getTemporaryChannelId: (): Buffer | null => null,
			getState: (): ChannelState => ChannelState.AWAITING_FUNDING_CONFIRMED,
			markForReestablish: (): void => undefined,
			buildFundingReauthorizationActions: (): ChannelAction[] => [
				{ type: ChannelActionType.PERSIST_STATE },
				{
					type: ChannelActionType.AUTHORIZE_FUNDING_BROADCAST,
					fundingTxid: txid
				} as ChannelAction
			],
			buildSpliceRebroadcastActions: (): ChannelAction[] => [
				{ type: ChannelActionType.PERSIST_STATE },
				{
					type: ChannelActionType.BROADCAST_TX,
					tx: Buffer.from([3]),
					fundingCritical: true
				} as ChannelAction
			]
		} as unknown as Channel;
	}

	it('a re-asked funding authorization is HELD until its new frame is durable', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const txid = crypto.randomBytes(32);
		const channel = restoredFunder(channelId, txid);
		const idHex = channelId.toString('hex');
		(
			harness.manager as unknown as {
				channels: Map<string, Channel>;
				channelPeers: Map<string, string>;
			}
		).channels.set(idHex, channel);
		(
			harness.manager as unknown as { channelPeers: Map<string, string> }
		).channelPeers.set(idHex, PEER);
		const authorized: Buffer[] = [];
		harness.manager.on('funding:authorized', (id: Buffer) =>
			authorized.push(id)
		);

		// This is the restart path. Its frame is brand new, so the barrier can
		// wait on it; the channel row that proves the obligation cannot.
		expect(harness.manager.reauthorizeFundingBroadcast(channelId)).to.equal(
			true
		);
		expect(authorized).to.have.length(0);
		expect(harness.held).to.deep.equal([idHex]);

		harness.barrier.advance(1n);
		await settle();
		expect(authorized).to.have.length(1);
		expect(authorized[0].equals(txid)).to.equal(true);
	});

	it('a re-asked splice rebroadcast is held the same way', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = restoredFunder(channelId, crypto.randomBytes(32));
		const idHex = channelId.toString('hex');
		(
			harness.manager as unknown as {
				channels: Map<string, Channel>;
				channelPeers: Map<string, string>;
			}
		).channels.set(idHex, channel);
		(
			harness.manager as unknown as { channelPeers: Map<string, string> }
		).channelPeers.set(idHex, PEER);

		expect(harness.manager.reauthorizeSpliceBroadcast(channelId)).to.equal(
			true
		);
		expect(harness.broadcasts).to.equal(0);

		harness.barrier.advance(1n);
		await settle();
		expect(harness.broadcasts).to.equal(1);
	});

	it('a refused re-ask broadcasts NOTHING, and leaves the obligation to ask again', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const channel = restoredFunder(channelId, crypto.randomBytes(32));
		const idHex = channelId.toString('hex');
		(
			harness.manager as unknown as {
				channels: Map<string, Channel>;
				channelPeers: Map<string, string>;
			}
		).channels.set(idHex, channel);
		(
			harness.manager as unknown as { channelPeers: Map<string, string> }
		).channelPeers.set(idHex, PEER);
		const authorized: Buffer[] = [];
		harness.manager.on('funding:authorized', (id: Buffer) =>
			authorized.push(id)
		);

		harness.manager.reauthorizeFundingBroadcast(channelId);
		harness.barrier.refuse('backfill-lost');
		await settle();

		expect(authorized).to.have.length(0);
		expect(harness.broadcasts).to.equal(0);
		expect(harness.frozen.map((f) => f.reason)).to.deep.equal([
			'backfill-lost'
		]);
		// The queue is gone, so the next sweep can ask again rather than piling
		// a second request behind a dead one.
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(0);
	});
});

describe('Recovery phase 6: a refused terminal close leaves the queue alone', () => {
	it('a force close that REFUSES does not consume the batch it would replace', async () => {
		const harness = makeHarness();
		const channelId = crypto.randomBytes(32);
		const idHex = channelId.toString('hex');
		// A channel that must not broadcast: restored, unprovable state. Its
		// forceClose refuses rather than putting a possibly stale commitment on
		// chain, and that refusal must not cost it the recovery declaration it
		// is already holding.
		//
		// This case is about the QUEUE, so the channel is a stub. What a
		// refusal must not do to the CHANNEL is pinned on real channels
		// instead: splice.test.ts (a confirmed splice with no post-splice
		// signature, alongside a held batch) and taproot-force-close.test.ts
		// (a missing peer nonce), where there is real state to compare byte
		// for byte.
		const channel = {
			setLocalNodeIdLower: (): void => undefined,
			getChannelId: (): Buffer => channelId,
			getTemporaryChannelId: (): Buffer | null => null,
			getState: (): ChannelState => ChannelState.NORMAL,
			markForReestablish: (): void => undefined,
			getSigner: (): unknown => ({}),
			channelKeyIndex: 0,
			prepareForceClose: (): { ok: false; error: string } => ({
				ok: false,
				error: 'Refusing to broadcast: restored state is not proven current'
			}),
			getFullState: (): unknown => ({ channelId })
		} as unknown as Channel;
		(
			harness.manager as unknown as {
				channels: Map<string, Channel>;
				channelPeers: Map<string, string>;
			}
		).channels.set(idHex, channel);
		(
			harness.manager as unknown as { channelPeers: Map<string, string> }
		).channelPeers.set(idHex, PEER);

		dispatch(harness.manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			declare(MessageType.ERROR)
		]);
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(1);

		const result = harness.manager.forceClose(channelId, Buffer.alloc(22), 10);
		expect(result.ok).to.equal(false);

		// The held declaration is still held, and still releases on its own
		// frame. A failed terminal operation must not consume the operation it
		// was meant to replace.
		expect(harness.manager.channelsAwaitingDurability().size).to.equal(1);
		expect(harness.broadcasts).to.equal(0);

		harness.barrier.advance(1n);
		await settle();
		expect(harness.sent.map((e) => e.type)).to.deep.equal([MessageType.ERROR]);
	});
});
