/**
 * A replayed update_fulfill_htlc must re-drive the node-level settlement it
 * authorizes, and a downstream fulfill that cannot yet reach the inbound leg
 * must not destroy the forward linkage that a later attempt needs.
 *
 * The quorum dispatch pipeline parks barrier-class sends while commits keep
 * landing, so a deferred channel persist can capture in-memory state that
 * already includes a processed downstream fulfill. A forwarder killed right
 * after that persist restarts with the outbound HTLC durably FULFILLED, no
 * preimage anywhere on disk, and the forward linkage intact. The peer then
 * retransmits the fulfill (BOLT 2: it was never acked), which is the only
 * remaining source of the preimage, but the channel-level dedup returned []
 * for an entry already FULFILLED, so the node never learned the preimage,
 * never fulfilled upstream, and the inbound HTLC sat committed until its
 * CLTV forced a close. That is issue 295: value paid downstream and never
 * claimed off-chain upstream.
 *
 * Three repairs, each with its regression here:
 * - the dedup branch verifies the preimage and re-emits HTLC_FULFILLED, so
 *   node-level listeners (all repeat-tolerant) run again;
 * - the forwarder's settle path checks the inbound leg can actually carry
 *   the fulfill before consuming the linkage, instead of durably deleting
 *   it around a refused fulfill (which also primed the restore-time
 *   redispatch pass to forward the same inbound HTLC a second time);
 * - a channel returning to NORMAL settles any forward whose downstream
 *   preimage is already known, covering the orderings where the replay
 *   arrives while the inbound leg is still mid-reestablish, and the live
 *   variant where the inbound peer was simply disconnected when the
 *   downstream leg settled.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	BITCOIN_CHAIN_HASH,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { IWireDurabilityBarrier } from '../../src/lightning/channel/channel-actions';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	IRecoveryCommitResult,
	SafetyTransition
} from '../../src/lightning/recovery/types';

const ALICE_SEED = 81;
const BOB_SEED = 82;
const CHARLIE_SEED = 83;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(`fulfill-replay-seed-${id}`)
		.digest();
}

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

function makeNodeConfig(
	seedId: number,
	storage?: IStorageBackend,
	recovery?: INodeConfig['recovery']
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage,
		recovery
	};
}

function createNode(
	seedId: number,
	storage?: IStorageBackend,
	recovery?: INodeConfig['recovery']
): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage, recovery));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/**
 * The quorum barrier reduced to its dispatch-visible shape: every gated
 * batch parks, and each park is released on the next macrotask. That one
 * asynchronous suspension pipelines the dispatch loop the way a real
 * guardian round trip does, letting later processing interleave between a
 * commit and the sends it authorized, which is the reordering under test.
 */
class AsyncAutoBarrier implements IWireDurabilityBarrier {
	readonly enforcing = true;
	isReleased(): boolean {
		return false;
	}
	whenReleased(
		sequence: bigint | null
	): Promise<{ released: boolean; reason: string }> {
		if (sequence == null) {
			return Promise.resolve({ released: false, reason: 'missing-frame' });
		}
		return new Promise((resolve) =>
			setImmediate(() => resolve({ released: true, reason: 'durable' }))
		);
	}

	// The node-side wiring surface (fencing, replication, compaction), all
	// irrelevant to the dispatch reordering this stand-in exists to produce.
	onFenced(): void {}
	onDurableAdvance(): void {}
	kickReplication(): void {}
	stop(): void {}
	watermark(): bigint {
		return 0n;
	}
}

/**
 * The node config names the concrete DurabilityBarrier class, but the
 * dispatch path consumes only the IWireDurabilityBarrier surface, so the
 * scripted stand-in is passed through the config type the same way the
 * phase 6 gating tests pass theirs to the ChannelManager.
 */
function quorumRecovery(): INodeConfig['recovery'] {
	return {
		enabled: true,
		durability: 'quorum',
		barrier: new AsyncAutoBarrier() as unknown as NonNullable<
			INodeConfig['recovery']
		>['barrier']
	};
}

/**
 * Storage that stops accepting writes once the process is "dead": a killed
 * process writes nothing, but the in-process zombie turn after the
 * simulated kill would. Reads pass through; close stays callable so
 * destroy() can release the file.
 */
function sealableStorage(
	inner: IStorageBackend,
	dead: { val: boolean }
): IStorageBackend {
	return new Proxy(inner, {
		get(target, prop, receiver): unknown {
			const value = Reflect.get(target, prop, receiver);
			if (typeof value !== 'function') return value;
			if (dead.val && prop !== 'close') {
				return (): undefined => undefined;
			}
			return value.bind(target);
		}
	}) as IStorageBackend;
}

interface ICut {
	val: boolean;
}

interface IWireGate {
	hold: boolean;
	queue: Array<{ to: LightningNode; from: string; type: number; p: Buffer }>;
}

/**
 * Event-relay wire for one node pair with a cut switch (the pair's link is
 * down, or the victim's process is gone) and an optional hold gate. A real
 * connection delivers BOTH channel_reestablish messages before any response
 * they trigger, so a live reconnect holds the wire and drains it in order.
 */
function wire(
	a: LightningNode,
	b: LightningNode,
	cut: ICut,
	gate?: IWireGate
): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (cut.val) return;
			if (pk !== to.getNodeId()) return;
			if (gate?.hold) {
				gate.queue.push({ to, from: from.getNodeId(), type: t, p });
				return;
			}
			to.handlePeerMessage(from.getNodeId(), t, p);
		});
	};
	route(a, b);
	route(b, a);
}

/** One full disconnect/reconnect cycle on two LIVE nodes over their wire. */
async function cycleConnection(
	a: LightningNode,
	b: LightningNode,
	cut: ICut,
	gate: IWireGate
): Promise<void> {
	cut.val = true;
	a.getChannelManager().handlePeerDisconnected(b.getNodeId());
	b.getChannelManager().handlePeerDisconnected(a.getNodeId());
	await settle();
	cut.val = false;
	gate.hold = true;
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	while (gate.queue.length > 0) {
		const m = gate.queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.p);
	}
	gate.hold = false;
	await settle();
}

/**
 * Reconnect a restarted node to a live peer the way a real socket pair
 * delivers: both channel_reestablish messages cross before any responses.
 */
async function reconnect(
	restarted: LightningNode,
	peer: LightningNode
): Promise<void> {
	const queue: Array<{
		to: LightningNode;
		from: string;
		type: number;
		payload: Buffer;
	}> = [];
	let hold = true;
	const rewire = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (hold) {
				queue.push({ to, from: from.getNodeId(), type: t, payload: p });
			} else {
				to.handlePeerMessage(from.getNodeId(), t, p);
			}
		});
	};
	rewire(restarted, peer);
	rewire(peer, restarted);
	restarted.getChannelManager().handlePeerReconnected(peer.getNodeId());
	peer.getChannelManager().handlePeerReconnected(restarted.getNodeId());
	while (queue.length > 0) {
		const m = queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.payload);
	}
	hold = false;
	await settle();
}

/**
 * Barrier-tolerant open: a quorum-mode participant parks its gated funding
 * messages until the frame behind them is released, so each step waits for
 * the state it needs instead of assuming the synchronous loopback finished.
 */
async function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode
): Promise<Buffer> {
	const channel = opener.openChannel(acceptor.getNodeId(), 1_000_000n);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	await waitFor(
		() => channel.getState() !== ChannelState.SENT_FUNDING_CREATED,
		'funding_signed to arrive'
	);
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	await waitFor(
		() => channel.getState() === ChannelState.NORMAL,
		'the opened channel to reach NORMAL'
	);
	return channelId;
}

/** Add an announced channel + both-direction updates to a node's graph. */
function addGraphChannel(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const aIs1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIs1 ? pubA : pubB,
		nodeId2: aIs1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: dir,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
}

function nodePubkey(seedId: number): Buffer {
	return getPublicKey(makeNodeConfig(seedId).nodePrivateKey);
}

interface IForwardWorld {
	alice: LightningNode;
	bob: LightningNode;
	charlie: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
	cutAB: ICut;
	cutBC: ICut;
	gateAB: IWireGate;
}

/**
 * Alice -> Bob -> Charlie with a known fee: Bob's policy is base 5000 /
 * ppm 0, propagated to Charlie's invoice hint so the payer attaches the
 * exact fee. Same shape as forwarding-history.test.ts.
 */
async function setupForwardWorld(
	bobStorage?: IStorageBackend,
	bobRecovery?: INodeConfig['recovery']
): Promise<IForwardWorld> {
	const alice = createNode(ALICE_SEED);
	const bob = createNode(BOB_SEED, bobStorage, bobRecovery);
	const charlie = createNode(CHARLIE_SEED);
	const cutAB: ICut = { val: false };
	const cutBC: ICut = { val: false };
	const gateAB: IWireGate = { hold: false, queue: [] };
	wire(alice, bob, cutAB, gateAB);
	wire(bob, charlie, cutBC);

	const abChannelId = await openReadyChannel(alice, bob);
	const bcChannelId = await openReadyChannel(bob, charlie);
	await waitFor(
		() =>
			[alice, bob, charlie].every((n) =>
				n
					.getChannelManager()
					.listChannels()
					.every((c) => c.getState() === ChannelState.NORMAL)
			),
		'every channel on every node to reach NORMAL'
	);

	const scidAB = encodeShortChannelId({
		block: 830,
		txIndex: 1,
		outputIndex: 0
	});
	const scidBC = encodeShortChannelId({
		block: 830,
		txIndex: 2,
		outputIndex: 0
	});
	bob.registerChannelScid(abChannelId, scidAB);
	bob.registerChannelScid(bcChannelId, scidBC);
	alice.registerChannelScid(abChannelId, scidAB);
	bob
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;
	charlie
		.getChannelManager()
		.getChannel(bcChannelId)!
		.getFullState().remoteScidAlias = scidBC;
	addGraphChannel(alice, scidAB, nodePubkey(ALICE_SEED), nodePubkey(BOB_SEED));
	bob.setChannelPolicy(bcChannelId, {
		feeBaseMsat: 5000,
		feeProportionalMillionths: 0
	});

	return {
		alice,
		bob,
		charlie,
		abChannelId,
		bcChannelId,
		cutAB,
		cutBC,
		gateAB
	};
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

async function settle(rounds = 6): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

async function waitFor(
	predicate: () => boolean,
	what: string,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) {
			throw new Error(`timed out waiting for ${what}`);
		}
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

/**
 * Wrap Bob's recovery.commit so that the run dies the instant a commit
 * lands whose channel_state carries an offered HTLC in FULFILLED state
 * while no payment_preimage mutation has committed yet. That is the disk
 * shape the quorum pipeline produces (a deferred persist capturing a
 * processed downstream fulfill ahead of the node-level preimage commit),
 * derived from the mutations themselves rather than a pinned ordinal.
 */
function killAtPipelinedFulfillPersist(
	bob: LightningNode,
	dead: { val: boolean }
): void {
	const holder = bob as unknown as {
		recovery: {
			commit: (transition: SafetyTransition) => IRecoveryCommitResult;
		};
	};
	const realCommit = holder.recovery.commit.bind(holder.recovery);
	let preimageCommitted = false;
	holder.recovery.commit = (
		transition: SafetyTransition
	): IRecoveryCommitResult => {
		if (dead.val) {
			return {
				committed: false,
				released: [],
				frameSequence: null,
				error: new Error('crashed')
			} as unknown as IRecoveryCommitResult;
		}
		for (const m of transition.mutations) {
			if (m.type === 'payment_preimage') preimageCommitted = true;
		}
		const result = realCommit(transition);
		const fulfilledOffered = transition.mutations.some(
			(m) =>
				m.type === 'channel_state' &&
				[...m.state.htlcs.entries()].some(
					([key, entry]) =>
						key.startsWith('offered-') && entry.state === HtlcState.FULFILLED
				)
		);
		if (!preimageCommitted && fulfilledOffered) {
			dead.val = true;
		}
		return result;
	};
}

/** Disk-shape sanity for the kill point issue 295 describes. */
function assertKillDiskShape(
	inspect: SqliteStorage,
	paymentHashHex: string
): void {
	const channels = inspect.loadAllChannels();
	expect(channels.length, 'both channels on disk').to.equal(2);
	let sawFulfilledOffered = false;
	let sawCommittedReceived = false;
	for (const row of channels) {
		for (const [key, entry] of row.state.htlcs) {
			if (key.startsWith('offered-') && entry.state === HtlcState.FULFILLED) {
				sawFulfilledOffered = true;
			}
			if (key.startsWith('received-') && entry.state === HtlcState.COMMITTED) {
				sawCommittedReceived = true;
			}
		}
	}
	expect(sawFulfilledOffered, 'outbound HTLC durably FULFILLED').to.equal(true);
	expect(sawCommittedReceived, 'inbound HTLC still COMMITTED').to.equal(true);
	expect(
		inspect.loadAllPreimages().some((p) => p.paymentHash === paymentHashHex),
		'no preimage anywhere on disk'
	).to.equal(false);
	expect(
		inspect.loadAllForwardedHtlcs().length,
		'forward linkage row intact'
	).to.equal(1);
}

describe('Replayed update_fulfill_htlc re-drives settlement (issue 295)', () => {
	it('a replayed fulfill re-emits HTLC_FULFILLED instead of a silent no-op', async function () {
		this.timeout(20_000);
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED);
		const aliceId = alice.getNodeId();
		const bobId = bob.getNodeId();

		// Hand-rolled wire: when Bob's fulfill goes out, capture the exact
		// bytes and cut the Alice -> Bob direction, so Alice processes the
		// fulfill but her responses never complete the removal round. The
		// offered entry then stays present in FULFILLED state, which is the
		// state a reestablish replay meets.
		let captured: Buffer | null = null;
		const aliceToBobCut = { val: false };
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== aliceId) return;
			if (t === MessageType.UPDATE_FULFILL_HTLC) {
				captured = Buffer.from(p);
				aliceToBobCut.val = true;
			}
			alice.handlePeerMessage(bobId, t, p);
		});
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== bobId) return;
			if (aliceToBobCut.val) return;
			bob.handlePeerMessage(aliceId, t, p);
		});

		await openReadyChannel(alice, bob);
		addGraphChannel(
			alice,
			encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 }),
			nodePubkey(ALICE_SEED),
			nodePubkey(BOB_SEED)
		);
		alice.registerChannelScid(
			alice.getChannelManager().listChannels()[0].getChannelId()!,
			encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 })
		);

		let fulfillEvents = 0;
		alice.getChannelManager().on('htlc:fulfilled', () => {
			fulfillEvents++;
		});
		const managerErrors: string[] = [];
		alice
			.getChannelManager()
			.on('error', (_id: Buffer | null, message: string) => {
				managerErrors.push(message);
			});

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'replay unit'
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await settle();
		expect(payment.status, 'payment settled by the fulfill').to.equal(
			PaymentStatus.COMPLETED
		);
		expect(captured, 'fulfill bytes captured').to.not.equal(null);
		expect(fulfillEvents, 'one fulfill event so far').to.equal(1);
		const channel = alice.getChannelManager().listChannels()[0];
		const entry = channel.getFullState().htlcs.get('offered-0');
		expect(entry?.state, 'entry parked in FULFILLED').to.equal(
			HtlcState.FULFILLED
		);

		// BOLT 2 retransmission: the peer replays the identical bytes after
		// a reconnect. The dedup must not swallow the node-level event, and
		// it must not corrupt channel state either.
		alice.handlePeerMessage(bobId, MessageType.UPDATE_FULFILL_HTLC, captured!);
		await settle();
		expect(fulfillEvents, 'the replay re-emitted the fulfill event').to.equal(
			2
		);
		expect(
			channel.getFullState().htlcs.get('offered-0')?.state,
			'entry unchanged by the replay'
		).to.equal(HtlcState.FULFILLED);
		expect(payment.status, 'payment stays settled').to.equal(
			PaymentStatus.COMPLETED
		);
		expect(managerErrors.length, 'no error from the valid replay').to.equal(0);

		// A replay whose preimage does not hash to the HTLC is peer
		// misbehaviour, not a repeat, and must be rejected loudly.
		const corrupted = Buffer.from(captured!);
		corrupted[corrupted.length - 1] ^= 0xff;
		alice.handlePeerMessage(bobId, MessageType.UPDATE_FULFILL_HTLC, corrupted);
		await settle();
		expect(
			managerErrors.some((m) => m.includes('Invalid preimage')),
			'corrupted replay rejected'
		).to.equal(true);
		expect(fulfillEvents, 'corrupted replay emitted nothing').to.equal(2);

		alice.destroy();
		bob.destroy();
	});

	it('a forwarder killed after the pipelined fulfill persist settles upstream on restart', async function () {
		this.timeout(30_000);
		const dbPath = tempDb('fulfill-replay-kill');
		const raw = new SqliteStorage(dbPath);
		raw.open();
		const dead = { val: false };
		const world = await setupForwardWorld(
			sealableStorage(raw, dead),
			quorumRecovery()
		);
		const { alice, bob, charlie } = world;
		killAtPipelinedFulfillPersist(bob, dead);

		const invoice = charlie.createInvoice({
			amountMsat: 80_000n,
			description: 'replay kill'
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await waitFor(
			() => dead.val,
			'the pipelined FULFILLED persist to land before the preimage'
		);
		world.cutAB.val = true;
		world.cutBC.val = true;
		await settle(10);
		expect(payment.status, 'payer still pending at the kill').to.equal(
			PaymentStatus.PENDING
		);
		bob.destroy();
		const bobId = bob.getNodeId();
		alice.getChannelManager().handlePeerDisconnected(bobId);
		charlie.getChannelManager().handlePeerDisconnected(bobId);
		alice.removeAllListeners('message:outbound');
		charlie.removeAllListeners('message:outbound');

		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		assertKillDiskShape(inspect, invoice.paymentHash.toString('hex'));

		const restored = createNode(BOB_SEED, inspect, quorumRecovery());
		// The payer's channel reestablishes first, then the downstream one:
		// the replayed fulfill arrives with the inbound leg already NORMAL.
		await reconnect(restored, alice);
		await reconnect(restored, charlie);
		await waitFor(
			() => payment.status === PaymentStatus.COMPLETED,
			'the payer to settle from the replayed fulfill'
		);

		const inbound = restored.getChannelManager().getChannel(world.abChannelId)!;
		await waitFor(
			() =>
				![...inbound.getFullState().htlcs.values()].some(
					(h) => h.state === HtlcState.COMMITTED
				),
			'the inbound HTLC to leave COMMITTED'
		);
		expect(inbound.getState()).to.equal(ChannelState.NORMAL);
		expect(
			inspect
				.loadAllPreimages()
				.some((p) => p.paymentHash === invoice.paymentHash.toString('hex')),
			'preimage durable after the replay'
		).to.equal(true);
		await waitFor(
			() => inspect.loadAllForwardedHtlcs().length === 0,
			'the settled forward linkage to clear'
		);

		restored.destroy();
		alice.destroy();
		charlie.destroy();
	});

	it('the restart settles upstream even when the replay precedes the inbound reestablish', async function () {
		this.timeout(30_000);
		const dbPath = tempDb('fulfill-replay-order');
		const raw = new SqliteStorage(dbPath);
		raw.open();
		const dead = { val: false };
		const world = await setupForwardWorld(
			sealableStorage(raw, dead),
			quorumRecovery()
		);
		const { alice, bob, charlie } = world;
		killAtPipelinedFulfillPersist(bob, dead);

		const invoice = charlie.createInvoice({
			amountMsat: 80_000n,
			description: 'replay order'
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await waitFor(
			() => dead.val,
			'the pipelined FULFILLED persist to land before the preimage'
		);
		world.cutAB.val = true;
		world.cutBC.val = true;
		await settle(10);
		bob.destroy();
		const bobId = bob.getNodeId();
		alice.getChannelManager().handlePeerDisconnected(bobId);
		charlie.getChannelManager().handlePeerDisconnected(bobId);
		alice.removeAllListeners('message:outbound');
		charlie.removeAllListeners('message:outbound');

		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		assertKillDiskShape(inspect, invoice.paymentHash.toString('hex'));

		// Count upstream fulfills so the two repair paths cannot both fire.
		let upstreamFulfills = 0;

		const restored = createNode(BOB_SEED, inspect, quorumRecovery());
		restored.on('message:outbound', (pk: string, t: number) => {
			if (pk === alice.getNodeId() && t === MessageType.UPDATE_FULFILL_HTLC) {
				upstreamFulfills++;
			}
		});
		// Downstream first: the replayed fulfill arrives while the inbound
		// channel is still waiting for its own reestablish. The linkage must
		// survive that refusal and the inbound channel's return to NORMAL
		// must settle it.
		await reconnect(restored, charlie);
		await settle(10);
		await reconnect(restored, alice);
		await waitFor(
			() => payment.status === PaymentStatus.COMPLETED,
			'the payer to settle once the inbound leg reestablished'
		);
		expect(upstreamFulfills, 'exactly one upstream fulfill').to.equal(1);

		const inbound = restored.getChannelManager().getChannel(world.abChannelId)!;
		await waitFor(
			() =>
				![...inbound.getFullState().htlcs.values()].some(
					(h) => h.state === HtlcState.COMMITTED
				),
			'the inbound HTLC to leave COMMITTED'
		);

		restored.destroy();
		alice.destroy();
		charlie.destroy();
	});

	it('a live inbound disconnect during the downstream settle keeps the linkage and settles on reconnect', async function () {
		this.timeout(30_000);
		const world = await setupForwardWorld();
		const { alice, bob, charlie } = world;

		// Hold invoice at Charlie parks the payment with both adds fully
		// committed. Then the inbound link goes down BEFORE the downstream
		// settle, so the fulfill arrives while the inbound channel cannot
		// carry it.
		const invoice = charlie.createInvoice({
			amountMsat: 80_000n,
			description: 'live disconnect',
			hold: true
		});
		const payment = alice.sendPayment(invoice.bolt11);
		await waitFor(
			() => charlie.listHoldInvoices().some((h) => h.state === 'ACCEPTED'),
			'the HTLC to park at Charlie'
		);
		expect(payment.status, 'held payment pending').to.equal(
			PaymentStatus.PENDING
		);

		world.cutAB.val = true;
		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		await settle();

		charlie.settleHeldHtlc(invoice.paymentHash);
		await settle(10);

		// The downstream leg settled and Bob holds the preimage, but the
		// inbound channel could not carry the fulfill. The linkage must
		// still exist, because it is the only record tying the preimage Bob
		// paid for to the inbound HTLC it claims.
		const bobInternals = bob as unknown as {
			forwardedHtlcs: Map<string, unknown>;
		};
		expect(
			bobInternals.forwardedHtlcs.size,
			'forward linkage survives the refused fulfill'
		).to.equal(1);

		await cycleConnection(alice, bob, world.cutAB, world.gateAB);
		await waitFor(
			() => payment.status === PaymentStatus.COMPLETED,
			'the payer to settle after the reconnect'
		);
		const inbound = bob.getChannelManager().getChannel(world.abChannelId)!;
		await waitFor(
			() =>
				![...inbound.getFullState().htlcs.values()].some(
					(h) => h.state === HtlcState.COMMITTED
				),
			'the inbound HTLC to leave COMMITTED'
		);
		expect(
			bobInternals.forwardedHtlcs.size,
			'linkage cleared by the settle'
		).to.equal(0);

		alice.destroy();
		bob.destroy();
		charlie.destroy();
	});
});
