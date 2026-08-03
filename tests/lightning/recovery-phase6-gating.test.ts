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
	IChannelPersistRequest,
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

	isReleased(sequence: bigint | null): boolean {
		if (sequence == null) return true;
		return sequence <= this.watermark;
	}

	whenReleased(
		sequence: bigint | null
	): Promise<{ released: boolean; reason: string }> {
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
		held: [],
		outboxSent: [],
		nextFrame: 1n
	};
	manager.on(
		'channel:persist',
		(_id: Buffer, request?: IChannelPersistRequest) => {
			if (!request) return;
			request.committed = true;
			request.frameSequence = harness.nextFrame;
			request.outboxIds = request.outbound.map((_m, index) => index + 1);
		}
	);
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

		// The other channel's frame is already durable, so it is not affected
		// by the first channel's outstanding receipt.
		harness.barrier.advance(0n);
		harness.nextFrame = 0n;
		dispatch(
			harness.manager,
			other,
			[
				{ type: ChannelActionType.PERSIST_STATE },
				send(MessageType.UPDATE_ADD_HTLC)
			],
			OTHER_PEER
		);

		expect(harness.sent.map((e) => e.peer)).to.deep.equal([OTHER_PEER]);
		expect(harness.barrier.waiting).to.equal(1);
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
