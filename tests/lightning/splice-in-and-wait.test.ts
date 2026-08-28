/**
 * LightningNode.spliceInAndWait (issue #572): resolves on splice:complete
 * for the channel, rejects on a SPLICE_IN_FAILED node error scoped to it or
 * on timeout, and throws when spliceIn refuses synchronously. The listeners
 * are registered BEFORE spliceIn runs so a synchronous completion cannot be
 * lost, and every settle path removes them.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import { encodeStfuMessage } from '../../src/lightning/message/stfu';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ILightningError } from '../../src/lightning/node/types';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
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

function createTestNode(): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update('splice-in-and-wait-node')
		.digest();
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update('splice-in-and-wait-priv')
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** Replace spliceIn with a recording stub returning a fixed result. */
function stubSpliceIn(
	node: LightningNode,
	result: { ok: boolean; error?: string }
): Array<{ channelId: Buffer; amountSats: bigint; feeratePerKw: number }> {
	const calls: Array<{
		channelId: Buffer;
		amountSats: bigint;
		feeratePerKw: number;
	}> = [];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).spliceIn = (
		channelId: Buffer,
		amountSats: bigint,
		feeratePerKw = 253
	): { ok: boolean; error?: string } => {
		calls.push({ channelId, amountSats, feeratePerKw });
		return result;
	};
	return calls;
}

function waitListenerCount(node: LightningNode): number {
	return (
		node.listenerCount('splice:complete') +
		node.listenerCount('splice:aborted') +
		node.listenerCount('node:error')
	);
}

describe('LightningNode.spliceInAndWait (issue #572)', function () {
	this.timeout(10_000);

	it('resolves on splice:complete for the channel and ignores other ids', async function () {
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		const calls = stubSpliceIn(node, { ok: true });

		const wait = node.spliceInAndWait(channelId, 50_000n, 5_000, 300);
		// Another channel's completion must not settle this wait.
		node.emit('splice:complete', {
			channelId: crypto.randomBytes(32),
			fundingTxid: crypto.randomBytes(32)
		});
		node.emit('splice:complete', {
			channelId,
			fundingTxid: crypto.randomBytes(32)
		});
		await wait;

		expect(calls).to.have.length(1);
		expect(calls[0].channelId.equals(channelId)).to.equal(true);
		expect(calls[0].feeratePerKw).to.equal(300);
		expect(waitListenerCount(node), 'listeners removed').to.equal(baseline);
		node.destroy();
	});

	it('rejects on a SPLICE_IN_FAILED scoped to the channel', async function () {
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		stubSpliceIn(node, { ok: true });

		const wait = node.spliceInAndWait(channelId, 50_000n);
		// A different channel's failure and an unrelated error code pass by.
		node.emit('node:error', {
			code: 'SPLICE_IN_FAILED',
			channelId: crypto.randomBytes(32),
			message: 'someone else',
			timestamp: Date.now()
		} as ILightningError);
		node.emit('node:error', {
			code: 'CHANNEL_ERROR',
			channelId,
			message: 'unrelated',
			timestamp: Date.now()
		} as ILightningError);
		node.emit('node:error', {
			code: 'SPLICE_IN_FAILED',
			channelId,
			message: 'wallet selection failed',
			timestamp: Date.now()
		} as ILightningError);

		let error = '';
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('wallet selection failed');
		expect(waitListenerCount(node), 'listeners removed').to.equal(baseline);
		node.destroy();
	});

	it('throws when spliceIn refuses synchronously, leaving nothing armed', async function () {
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		stubSpliceIn(node, { ok: false, error: 'Channel not found' });

		let error = '';
		try {
			await node.spliceInAndWait(channelId, 50_000n);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('Channel not found');
		expect(waitListenerCount(node), 'no leaked listeners').to.equal(baseline);
		node.destroy();
	});

	it('a REAL peer tx_abort mid-splice settles the wait through the whole chain', async function () {
		// End to end over the actual machinery (no fabricated events): a
		// SPLICING channel inside the manager receives the peer's tx_abort,
		// unwinds to NORMAL, the manager emits splice:aborted, the node
		// relays it, and the wait rejects.
		const node = createTestNode();
		const peer = '02'.padEnd(66, 'ab');
		const seed = crypto.randomBytes(32);
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: seed
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.NORMAL;
		state.fundingTxid = crypto.randomBytes(32);
		state.localBalanceMsat = 1_000_000_000n;
		state.remoteBalanceMsat = 0n;
		const channel = new Channel(state);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const manager = (node as any).channelManager;
		manager.channels.set(state.channelId!.toString('hex'), channel);
		manager.channelPeers.set(state.channelId!.toString('hex'), peer);
		const channelId = state.channelId!;

		// Quiesce as the responder and receive splice_init: SPLICING.
		channel.handleStfuMessage({ channelId, initiator: true });
		channel.handleSplice({
			channelId,
			fundingPubkey: Buffer.alloc(33, 0x02),
			relativeSatoshis: 0n,
			fundingFeeratePerkw: 253,
			locktime: 0
		});
		expect(channel.getState()).to.equal(ChannelState.SPLICING);

		stubSpliceIn(node, { ok: true });
		const wait = node.spliceInAndWait(channelId, 50_000n);
		node.getChannelManager().handleMessage(
			peer,
			MessageType.TX_ABORT,
			encodeTxAbortMessage({
				channelId,
				data: Buffer.from('stop', 'ascii')
			})
		);

		let error = '';
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('peer sent tx_abort');
		expect(channel.getState(), 'channel back to NORMAL').to.equal(
			ChannelState.NORMAL
		);
		node.destroy();
	});

	it('a LOCAL abort settles the wait; the later echo does not double-fire', async function () {
		// ChannelManager.abortSplice restores the channel to NORMAL before
		// the tx_abort echo ever returns, so the echo handler's transition
		// predicate cannot fire for it: the local site must emit the terminal
		// event itself or the wait burns its full timeout (issue #572
		// review). The two sites stay mutually exclusive.
		const node = createTestNode();
		const peer = '02'.padEnd(66, 'ab');
		const seed = crypto.randomBytes(32);
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: seed
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.NORMAL;
		state.fundingTxid = crypto.randomBytes(32);
		state.localBalanceMsat = 1_000_000_000n;
		state.remoteBalanceMsat = 0n;
		const channel = new Channel(state);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const manager = (node as any).channelManager;
		manager.channels.set(state.channelId!.toString('hex'), channel);
		manager.channelPeers.set(state.channelId!.toString('hex'), peer);
		const channelId = state.channelId!;
		const outbound: MessageType[] = [];
		manager.on('message:outbound', (_peer: string, type: MessageType): void => {
			outbound.push(type);
		});

		channel.handleStfuMessage({ channelId, initiator: true });
		channel.handleSplice({
			channelId,
			fundingPubkey: Buffer.alloc(33, 0x02),
			relativeSatoshis: 0n,
			fundingFeeratePerkw: 253,
			locktime: 0
		});
		expect(channel.getState()).to.equal(ChannelState.SPLICING);

		// Diagnostics and observers are public. Neither may suppress the waiter,
		// later observers or the tx_abort owed to the peer.
		node.on('log', (): void => {
			throw new Error('log observer failed');
		});
		node.on('splice:aborted', (): void => {
			throw new Error('observer failed');
		});
		const aborted: string[] = [];
		const observerReceivers: unknown[] = [];
		node.on(
			'splice:aborted',
			function (this: LightningNode, data: { reason: string }): void {
				observerReceivers.push(this);
				aborted.push(data.reason);
			}
		);
		stubSpliceIn(node, { ok: true });
		const wait = node.spliceInAndWait(channelId, 50_000n, 300);
		const result = node
			.getChannelManager()
			.abortSplice(channelId, 'operator changed their mind');
		expect(result.ok).to.equal(true);
		expect(
			outbound.filter((type) => type === MessageType.TX_ABORT),
			'the observer cannot suppress tx_abort'
		).to.have.length(1);

		let error = '';
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('operator changed their mind');
		expect(observerReceivers, 'observer receiver').to.deep.equal([node]);
		expect(channel.getState()).to.equal(ChannelState.NORMAL);

		// The peer's echo arrives afterwards: the transition predicate sees
		// NORMAL before and after, so no second event fires.
		node.getChannelManager().handleMessage(
			peer,
			MessageType.TX_ABORT,
			encodeTxAbortMessage({
				channelId,
				data: Buffer.from('ack', 'ascii')
			})
		);
		expect(aborted).to.deep.equal(['operator changed their mind']);
		node.destroy();
	});

	it('a repeated pending-quiescence cancel emits exactly once', async function () {
		// The first cancel of a splice still parked behind quiescence signals
		// (the wait must settle); repeats are silent no-op successes and must
		// not re-emit (issue #581 review).
		const node = createTestNode();
		const peer = '02'.padEnd(66, 'ab');
		const seed = crypto.randomBytes(32);
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: seed
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.NORMAL;
		state.fundingTxid = crypto.randomBytes(32);
		state.localBalanceMsat = 1_000_000_000n;
		state.remoteBalanceMsat = 0n;
		const channel = new Channel(state);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const manager = (node as any).channelManager;
		manager.channels.set(state.channelId!.toString('hex'), channel);
		manager.channelPeers.set(state.channelId!.toString('hex'), peer);
		const channelId = state.channelId!;

		// stfu out, quiescence pending: the splice is parked, not sessioned.
		channel.initiateSplice(100_000n, 253);
		expect(channel.getState()).to.equal(ChannelState.NORMAL);

		const aborted: string[] = [];
		node.on('splice:aborted', (data: { reason: string }) =>
			aborted.push(data.reason)
		);
		const first = node.getChannelManager().abortSplice(channelId, 'first');
		expect(first.ok).to.equal(true);
		const second = node.getChannelManager().abortSplice(channelId, 'again');
		expect(second.ok, 'repeat cancel stays a no-op success').to.equal(true);
		expect(aborted, 'exactly one event').to.deep.equal(['first']);

		// Completing the peer side of quiescence performs the deferred wire
		// unwind. It is still the same cancelled attempt, so it must not emit
		// another terminal event.
		manager.handleMessage(
			peer,
			MessageType.STFU,
			encodeStfuMessage({ channelId, initiator: false })
		);
		expect(aborted, 'deferred unwind stays silent').to.deep.equal(['first']);
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
		node.destroy();
	});

	it('a DISCONNECTED abort still settles the wait (never passes through NORMAL)', async function () {
		// An abort while marked for reestablish succeeds but leaves the
		// channel in AWAITING_REESTABLISH: any NORMAL-based emit condition
		// misses it and the wait burned its timeout (issue #581 review). The
		// channel's newly-aborted action signals regardless of the landing
		// state.
		const node = createTestNode();
		const peer = '02'.padEnd(66, 'ab');
		const seed = crypto.randomBytes(32);
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(seed),
			localPerCommitmentSeed: seed
		});
		state.channelId = crypto.randomBytes(32);
		state.state = ChannelState.NORMAL;
		state.fundingTxid = crypto.randomBytes(32);
		state.localBalanceMsat = 1_000_000_000n;
		state.remoteBalanceMsat = 0n;
		const channel = new Channel(state);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const manager = (node as any).channelManager;
		manager.channels.set(state.channelId!.toString('hex'), channel);
		manager.channelPeers.set(state.channelId!.toString('hex'), peer);
		const channelId = state.channelId!;

		// The disconnected shape Corey's audit named: a splice whose durable
		// record survived the disconnect (created at the commitment round,
		// nothing signed yet) on a channel marked for reestablish. The abort
		// succeeds via the record-drop arm without ever passing NORMAL.
		state.state = ChannelState.AWAITING_REESTABLISH;
		state.spliceInFlight = {
			spliceTxid: crypto.randomBytes(32),
			newFundingOutputIndex: 0,
			newFundingSatoshis: 1_100_000n,
			spliceTxHex: '02000000000100000000',
			fullySigned: false,
			isInitiator: true,
			localRelativeSatoshis: 100_000n,
			remoteRelativeSatoshis: 0n,
			remoteFundingPubkey: getPublicKey(crypto.randomBytes(32)),
			ourSharedInputSig: Buffer.alloc(64),
			ourWalletWitnesses: [],
			ourWalletInputIndices: [],
			inputPrevouts: [],
			remoteCommitmentSig: null,
			sentTxSignatures: false,
			receivedTxSignatures: false,
			localSpliceLocked: false,
			remoteSpliceLocked: false,
			confirmed: false
		};

		stubSpliceIn(node, { ok: true });
		const wait = node.spliceInAndWait(channelId, 50_000n);
		const result = node
			.getChannelManager()
			.abortSplice(channelId, 'gave up while disconnected');
		expect(result.ok).to.equal(true);
		expect(channel.getState(), 'never passes through NORMAL').to.equal(
			ChannelState.AWAITING_REESTABLISH
		);

		let error = '';
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('gave up while disconnected');
		node.destroy();
	});

	it('rejects when the peer aborts the splice back to NORMAL', async function () {
		// A peer tx_abort unwinds the splice without emitting any
		// SPLICE_IN_FAILED; the dedicated splice:aborted signal settles the
		// wait instead of letting it burn its timeout.
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		stubSpliceIn(node, { ok: true });

		const wait = node.spliceInAndWait(channelId, 50_000n);
		// Another channel's abort passes by; ours settles the wait.
		node.emit('splice:aborted', {
			channelId: crypto.randomBytes(32),
			reason: 'someone else'
		});
		node.emit('splice:aborted', {
			channelId,
			reason: 'splice aborted (tx_abort)'
		});

		let error = '';
		try {
			await wait;
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('splice aborted (tx_abort)');
		expect(waitListenerCount(node), 'listeners removed').to.equal(baseline);
		node.destroy();
	});

	it('a spliceIn validation throw unwinds the wait, leaving nothing armed', async function () {
		const node = createTestNode();
		const baseline = waitListenerCount(node);
		const channelId = crypto.randomBytes(32);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).spliceIn = (): { ok: boolean } => {
			throw new Error('fundingFeeratePerkw must be a u32');
		};

		let error = '';
		try {
			await node.spliceInAndWait(channelId, 50_000n);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.equal('fundingFeeratePerkw must be a u32');
		expect(waitListenerCount(node), 'no leaked listeners').to.equal(baseline);
		node.destroy();
	});

	it('rejects on timeout', async function () {
		const node = createTestNode();
		const channelId = crypto.randomBytes(32);
		stubSpliceIn(node, { ok: true });

		let error = '';
		try {
			await node.spliceInAndWait(channelId, 50_000n, 100);
		} catch (err) {
			error = (err as Error).message;
		}
		expect(error).to.match(/not locked within 100ms/);
		node.destroy();
	});
});
