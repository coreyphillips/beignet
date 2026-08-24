/**
 * A committed inbound HTLC whose resolution died with the process must be
 * re-dispatched once reestablish completes.
 *
 * The repair pass for this exists (redispatchUnresolvedReceivedHtlcs) and
 * is driven from 'channel:ready', but the CHANNEL_READY action reaches that
 * event only when channel_ready itself is retransmitted, which is true only
 * for a channel that never completed a commitment round. On any channel
 * past its first round, a crash in the window between "peer's
 * revoke_and_ack durably processed" (which persists the once-only
 * forwardEmitted marker) and "resolution durably begun" left the HTLC
 * COMMITTED forever: nothing re-emits it, scanForwardTimeouts skips
 * received HTLCs with no outgoing leg, and the CLTV backstop ends a final
 * hop in a force close because we hold the preimage. The fix passes every
 * channel that returns to NORMAL through 'channel:ready' at the tail of
 * handleChannelReestablish.
 *
 * Found by the phase 7 chaos matrix (S1b post-commit:6 through
 * pre-commit:10, S3 likewise); these are the minimal standalone shapes.
 *
 * The repair fires on its OWN one-shot event, armed when a channel is
 * restored from persistence, never on 'channel:ready' and never for a
 * channel that stayed live. An ordinary TCP disconnect also puts a live
 * channel into AWAITING_REESTABLISH, and the repair is not idempotent
 * against node state that never went away: re-offering an already
 * accumulated inbound MPP part would count its amount twice, so a payer
 * could cycle the connection until the set reached its declared total
 * having sent less. The last two tests here are that boundary.
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
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	IRecoveryCommitResult,
	SafetyTransition
} from '../../src/lightning/recovery/types';

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`redispatch-seed-${id}`).digest();
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
	storage?: IStorageBackend
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
		storage
	};
}

function createNode(seedId: number, storage?: IStorageBackend): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/**
 * Storage that stops accepting writes when the process is "dead": a killed
 * process writes nothing, but the in-process zombie turn that follows the
 * simulated kill would (persistHeldHtlcs writes metadata outside
 * RecoveryManager.commit). Reads pass through; close stays callable so
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

interface IWireGate {
	hold: boolean;
	queue: Array<{ to: LightningNode; from: string; type: number; p: Buffer }>;
}

/**
 * Event-relay wire with a dead switch (dead = the victim's process is gone)
 * and an optional hold gate. A real connection delivers BOTH
 * channel_reestablish messages before any response they trigger, so a
 * reconnect holds the wire and drains it in order.
 */
function wire(
	a: LightningNode,
	b: LightningNode,
	dead: { val: boolean },
	gate?: IWireGate
): void {
	const route = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (dead.val) return;
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

/** One full disconnect/reconnect cycle on two LIVE nodes. */
async function cycleConnection(
	a: LightningNode,
	b: LightningNode,
	gate: IWireGate
): Promise<void> {
	a.getChannelManager().handlePeerDisconnected(b.getNodeId());
	b.getChannelManager().handlePeerDisconnected(a.getNodeId());
	await settle();
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

function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode
): Buffer {
	const channel = opener.openChannel(acceptor.getNodeId(), 1_000_000n);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	return channelId;
}

function buildDirectGraph(
	payer: LightningNode,
	payerSeedId: number,
	payeeSeedId: number
): void {
	const payerPubkey = getPublicKey(makeNodeConfig(payerSeedId).nodePrivateKey);
	const payeePubkey = getPublicKey(makeNodeConfig(payeeSeedId).nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });
	const payerIsNode1 = Buffer.compare(payerPubkey, payeePubkey) < 0;
	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: payerIsNode1 ? payerPubkey : payeePubkey,
		nodeId2: payerIsNode1 ? payeePubkey : payerPubkey,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	payer.getGraph().addChannelAnnouncement(announcement);
	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	payer.getGraph().applyChannelUpdate(update);
	payer.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
	payer.registerChannelScid(
		payer.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

async function settle(rounds = 4): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

/**
 * Reconnect a restarted node to its live peer the way a real socket pair
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

const ALICE_SEED = 41;
const BOB_SEED = 42;

describe('Reestablish re-dispatches committed-but-unresolved received HTLCs', () => {
	it('a receiver crash after the add round commits still fulfills after restart', async function () {
		this.timeout(20_000);
		const dbPath = tempDb('redispatch-fulfill');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const dead = { val: false };
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED, sealableStorage(storage1, dead));
		wire(alice, bob, dead);
		openReadyChannel(alice, bob);
		buildDirectGraph(alice, ALICE_SEED, BOB_SEED);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'redispatch'
		});

		// Kill bob the instant the commit that processes alice's
		// revoke_and_ack returns. That commit ends the add round and persists
		// the once-only forwardEmitted marker; the fulfill chain that follows
		// lives only in memory, which is the whole hazard. Counted from here:
		// commit 1 covers received commitment_signed (our revoke leaves),
		// commit 2 our own commitment_signed, commit 3 the peer's revoke.
		// The disk-shape sanity asserts below fail loudly if these ordinals
		// ever drift.
		const holder = bob as unknown as {
			recovery: {
				commit: (transition: SafetyTransition) => IRecoveryCommitResult;
			};
		};
		const realCommit = holder.recovery.commit.bind(holder.recovery);
		let commits = 0;
		holder.recovery.commit = (
			transition: SafetyTransition
		): IRecoveryCommitResult => {
			if (dead.val) {
				return {
					committed: false,
					released: [],
					frameSequence: null,
					error: new Error('crashed')
				};
			}
			const result = realCommit(transition);
			if (++commits === 3) dead.val = true;
			return result;
		};

		const payment = alice.sendPayment(invoice.bolt11);
		expect(payment.status, 'payment interrupted by the crash').to.equal(
			PaymentStatus.PENDING
		);
		await settle();
		bob.destroy();

		// The crash left exactly the stranded shape: HTLC committed with its
		// dispatch marker durable, no resolution anywhere.
		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const row = inspect.loadAllChannels()[0];
		const committedEntries = [...row.state.htlcs.entries()].filter(
			([key, entry]) =>
				key.startsWith('received-') && entry.state === HtlcState.COMMITTED
		);
		expect(committedEntries.length, 'one committed received HTLC').to.equal(1);
		expect(
			committedEntries[0][1].forwardEmitted,
			'dispatch marker persisted before the crash'
		).to.equal(true);

		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		alice.removeAllListeners('message:outbound');
		const restarted = createNode(BOB_SEED, inspect);
		await reconnect(restarted, alice);

		// The repair pass must have re-driven the fulfill: the payer settles
		// and the receiver's channel is clean.
		expect(payment.status, 'payer settled after the restart').to.equal(
			PaymentStatus.COMPLETED
		);
		const channel = restarted.getChannelManager().listChannels()[0];
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
		expect(channel.getFullState().htlcs.size, 'no HTLC left pending').to.equal(
			0
		);

		restarted.destroy();
		alice.destroy();
	});

	it('a capsule-restored channel still fulfills the HTLC the capsule committed', async function () {
		// The restore hold refuses NEW HTLCs, and the refusal used to key on
		// the hold alone, so the redispatch of an HTLC the capsule itself had
		// committed was failed back instead of fulfilled: the payer lost a
		// payment the restore exists to preserve (issue #469). Provenance is
		// per HTLC now, and only an add admitted while the hold already stood
		// is refused.
		this.timeout(20_000);
		const dbPath = tempDb('redispatch-held-fulfill');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const dead = { val: false };
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED, sealableStorage(storage1, dead));
		wire(alice, bob, dead);
		openReadyChannel(alice, bob);
		buildDirectGraph(alice, ALICE_SEED, BOB_SEED);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'held redispatch'
		});

		// Same crash point as the test above: the add round's commit lands,
		// the fulfill chain dies with the process.
		const holder = bob as unknown as {
			recovery: {
				commit: (transition: SafetyTransition) => IRecoveryCommitResult;
			};
		};
		const realCommit = holder.recovery.commit.bind(holder.recovery);
		let commits = 0;
		holder.recovery.commit = (
			transition: SafetyTransition
		): IRecoveryCommitResult => {
			if (dead.val) {
				return {
					committed: false,
					released: [],
					frameSequence: null,
					error: new Error('crashed')
				};
			}
			const result = realCommit(transition);
			if (++commits === 3) dead.val = true;
			return result;
		};

		const payment = alice.sendPayment(invoice.bolt11);
		expect(payment.status, 'payment interrupted by the crash').to.equal(
			PaymentStatus.PENDING
		);
		await settle();
		bob.destroy();

		// The capsule install stamps the hold on every restored row; this is
		// that marker over the crash shape above. The committed HTLC predates
		// it, so it carries no admitted-while-held provenance.
		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const row = inspect.loadAllChannels()[0];
		const committedEntries = [...row.state.htlcs.entries()].filter(
			([key, entry]) =>
				key.startsWith('received-') && entry.state === HtlcState.COMMITTED
		);
		expect(committedEntries.length, 'one committed received HTLC').to.equal(1);
		expect(
			committedEntries[0][1].addedWhileRestoreUnproven,
			'the capsule HTLC predates the hold'
		).to.equal(undefined);
		row.state.restoreRecencyUnproven = true;
		inspect.saveChannel(row.channelId, row.state, row.peerPubkey);

		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		alice.removeAllListeners('message:outbound');
		const restarted = createNode(BOB_SEED, inspect);
		await reconnect(restarted, alice);

		// The redispatch must fulfill, not fail back: the HTLC was admitted
		// before the hold began.
		expect(payment.status, 'payer settled despite the hold').to.equal(
			PaymentStatus.COMPLETED
		);
		const channel = restarted.getChannelManager().listChannels()[0];
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
		expect(channel.getFullState().htlcs.size, 'no HTLC left pending').to.equal(
			0
		);
		expect(
			channel.getFullState().restoreRecencyUnproven,
			'the hold itself still stands'
		).to.equal(true);

		restarted.destroy();
		alice.destroy();
	});

	it('a receiver crash before the hold-park persists leaves the HTLC reachable by settle', async function () {
		this.timeout(20_000);
		const dbPath = tempDb('redispatch-hold');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const dead = { val: false };
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED, sealableStorage(storage1, dead));
		wire(alice, bob, dead);
		openReadyChannel(alice, bob);
		buildDirectGraph(alice, ALICE_SEED, BOB_SEED);

		const invoice = bob.createInvoice({
			amountMsat: 60_000n,
			description: 'redispatch hold',
			hold: true
		});

		// Same crash window as above, on a HOLD invoice: the add round is
		// durable (forwardEmitted persisted with the peer's revoke), but the
		// PARK decision and its held_htlcs metadata are in-memory only and
		// die with the process. Without the repair pass the restart holds a
		// committed HTLC no settle or cancel can reach, and the hold invoice
		// it pays reads OPEN forever.
		const holder = bob as unknown as {
			recovery: {
				commit: (transition: SafetyTransition) => IRecoveryCommitResult;
			};
		};
		const realCommit = holder.recovery.commit.bind(holder.recovery);
		let commits = 0;
		holder.recovery.commit = (
			transition: SafetyTransition
		): IRecoveryCommitResult => {
			if (dead.val) {
				return {
					committed: false,
					released: [],
					frameSequence: null,
					error: new Error('crashed')
				};
			}
			const result = realCommit(transition);
			if (++commits === 3) dead.val = true;
			return result;
		};

		const payment = alice.sendPayment(invoice.bolt11);
		expect(payment.status, 'payment interrupted by the crash').to.equal(
			PaymentStatus.PENDING
		);
		await settle();
		bob.destroy();

		// The crash left the stranded shape: HTLC committed, park nowhere.
		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const row = inspect.loadAllChannels()[0];
		const committedEntries = [...row.state.htlcs.entries()].filter(
			([key, entry]) =>
				key.startsWith('received-') && entry.state === HtlcState.COMMITTED
		);
		expect(committedEntries.length, 'one committed received HTLC').to.equal(1);
		expect(
			inspect.loadMetadata('held_htlcs') ?? '[]',
			'the park never reached disk'
		).to.not.contain(invoice.paymentHash.toString('hex'));

		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		alice.removeAllListeners('message:outbound');
		const restarted = createNode(BOB_SEED, inspect);
		await reconnect(restarted, alice);
		await settle();

		// The repair pass re-parked it: settle works and the payer completes.
		expect(payment.status, 'still parked, not settled by itself').to.equal(
			PaymentStatus.PENDING
		);
		const settled = restarted.settleHeldHtlc(invoice.paymentHash);
		expect(settled, 'the re-parked HTLC was reachable by settle').to.equal(
			true
		);
		await settle();
		expect(payment.status, 'payer settled after the restart').to.equal(
			PaymentStatus.COMPLETED
		);
		expect(
			restarted.getChannelManager().listChannels()[0].getFullState().htlcs.size,
			'no HTLC left pending'
		).to.equal(0);

		restarted.destroy();
		alice.destroy();
	});

	it('a restored SHUTTING_DOWN channel still gets the restore repair', async function () {
		// The repair gate was NORMAL-only, and a restored SHUTTING_DOWN channel
		// returns to SHUTTING_DOWN after reestablish, so it never fired. An
		// unresolved committed HTLC then kept the shutdown from ever reaching
		// zero, and on a channel held for unproven capsule recency the
		// automatic close that would otherwise end it is refused (issue #469).
		this.timeout(20_000);
		const dbPath = tempDb('redispatch-shutdown');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED, storage1);
		wire(alice, bob, { val: false });
		openReadyChannel(alice, bob);
		await settle();
		bob.destroy();

		// Bring the row back mid-shutdown, which is what a channel persisted
		// during a cooperative close looks like on disk.
		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const row = inspect.loadAllChannels()[0];
		row.state.state = ChannelState.SHUTTING_DOWN;
		row.state.localShutdownScript = Buffer.from(
			'0014' + '33'.repeat(20),
			'hex'
		);
		inspect.saveChannel(row.channelId, row.state, row.peerPubkey);

		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		alice.removeAllListeners('message:outbound');
		const restarted = createNode(BOB_SEED, inspect);
		const repaired: string[] = [];
		restarted
			.getChannelManager()
			.on('channel:restore-ready', (id: Buffer) =>
				repaired.push(id.toString('hex'))
			);

		await reconnect(restarted, alice);

		// The repair runs at the reestablish tail, while the channel is back in
		// SHUTTING_DOWN; the close negotiation that follows may then carry it
		// all the way to CLOSED in the same drain, which is the point - it can
		// only get there once its HTLCs resolve.
		expect(
			repaired,
			'the repair that resolves its last HTLC still runs'
		).to.have.length(1);
		const channel = restarted.getChannelManager().listChannels()[0];
		expect(
			channel.getState() === ChannelState.SHUTTING_DOWN ||
				channel.getState() === ChannelState.CLOSED,
			`the close proceeds rather than stalling (got ${channel.getState()})`
		).to.equal(true);

		restarted.destroy();
		alice.destroy();
	});

	it('a held channel restored mid-close is refused onto the peer-close path at reconnect', async function () {
		// A capsule can capture a row DURING a cooperative close. Resuming
		// that negotiation after the restore would sign the split the capsule
		// carries without the operator ever passing the initiateShutdown
		// gate, and doing nothing would leave the row in SHUTTING_DOWN with
		// nothing else driving it. The manager refuses terminally at the
		// reestablish tail instead, which derives the 5.6 peer-close
		// disposition (issue #469).
		this.timeout(20_000);
		const dbPath = tempDb('redispatch-held-close');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED, storage1);
		wire(alice, bob, { val: false });
		openReadyChannel(alice, bob);
		await settle();
		bob.destroy();

		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const row = inspect.loadAllChannels()[0];
		row.state.state = ChannelState.SHUTTING_DOWN;
		row.state.localShutdownScript = Buffer.from(
			'0014' + '33'.repeat(20),
			'hex'
		);
		row.state.restoreRecencyUnproven = true;
		inspect.saveChannel(row.channelId, row.state, row.peerPubkey);

		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		alice.removeAllListeners('message:outbound');
		const restarted = createNode(BOB_SEED, inspect);
		const sentShutdowns: number[] = [];
		restarted.on('message:outbound', (_pk: string, t: number) => {
			// 38 = BOLT 2 shutdown
			if (t === 38) sentShutdowns.push(t);
		});
		await reconnect(restarted, alice);

		const channel = restarted.getChannelManager().listChannels()[0];
		expect(channel.getState()).to.equal(ChannelState.ERRORED);
		expect(channel.getRecoveryCloseReason()).to.equal('restore-unproven');
		expect(
			sentShutdowns,
			'our shutdown is not retransmitted for a close we would refuse'
		).to.have.length(0);

		restarted.destroy();
		alice.destroy();
	});

	it('an acknowledged mid-close restore resumes the negotiation at reconnect', async function () {
		// The same shape with the operator's persisted acknowledgement on the
		// row: the negotiation must resume rather than refuse, which is also
		// the round trip proving the acknowledgement survives a restart.
		this.timeout(20_000);
		const dbPath = tempDb('redispatch-acked-close');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED, storage1);
		wire(alice, bob, { val: false });
		openReadyChannel(alice, bob);
		await settle();
		bob.destroy();

		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const row = inspect.loadAllChannels()[0];
		row.state.state = ChannelState.SHUTTING_DOWN;
		row.state.localShutdownScript = Buffer.from(
			'0014' + '33'.repeat(20),
			'hex'
		);
		row.state.restoreRecencyUnproven = true;
		row.state.staleCloseRiskAccepted = true;
		inspect.saveChannel(row.channelId, row.state, row.peerPubkey);

		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		alice.removeAllListeners('message:outbound');
		const restarted = createNode(BOB_SEED, inspect);
		await reconnect(restarted, alice);

		const channel = restarted.getChannelManager().listChannels()[0];
		expect(
			channel.getFullState().staleCloseRiskAccepted,
			'the acknowledgement survived the restart'
		).to.equal(true);
		expect(
			channel.getState(),
			'the close proceeds rather than refusing'
		).to.be.oneOf([
			ChannelState.SHUTTING_DOWN,
			ChannelState.NEGOTIATING_CLOSING,
			ChannelState.CLOSED
		]);

		restarted.destroy();
		alice.destroy();
	});

	it('a live reconnect does NOT re-run the repair (the restart-only boundary)', async function () {
		this.timeout(20_000);
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED);
		const dead = { val: false };
		const gate: IWireGate = { hold: false, queue: [] };
		wire(alice, bob, dead, gate);
		openReadyChannel(alice, bob);
		buildDirectGraph(alice, ALICE_SEED, BOB_SEED);

		// Count the repair ITSELF, not the event that drives it, so this bites
		// against any implementation that reaches it by another route.
		let repairs = 0;
		const holder = bob as unknown as {
			redispatchUnresolvedReceivedHtlcs: (channelId: Buffer) => void;
		};
		const realRepair = holder.redispatchUnresolvedReceivedHtlcs.bind(bob);
		holder.redispatchUnresolvedReceivedHtlcs = (channelId: Buffer): void => {
			repairs++;
			realRepair(channelId);
		};

		// Two full disconnect/reconnect cycles on nodes that never restarted.
		for (let i = 0; i < 2; i++) await cycleConnection(alice, bob, gate);

		expect(
			repairs,
			'a channel that never left this process is never repaired'
		).to.equal(0);
		expect(
			bob.getChannelManager().listChannels()[0].getState(),
			'the channel reestablished normally'
		).to.equal(ChannelState.NORMAL);

		bob.destroy();
		alice.destroy();
	});

	it('an accumulated MPP part is never counted twice across a live reconnect', async function () {
		this.timeout(20_000);
		// The vulnerability this boundary exists for: one 60k part of a 100k
		// invoice, then the payer cycles the connection. If the repair ran on
		// a live reconnect, the same HTLC would be accumulated again, the set
		// would sum to 120k, cross its declared total and reveal the preimage
		// for 60k of real money.
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED);
		const dead = { val: false };
		const gate: IWireGate = { hold: false, queue: [] };
		wire(alice, bob, dead, gate);
		const channelId = openReadyChannel(alice, bob);
		buildDirectGraph(alice, ALICE_SEED, BOB_SEED);

		const invoice = bob.createInvoice({
			amountMsat: 100_000n,
			description: 'mpp reconnect'
		});
		const scid = encodeShortChannelId({
			block: 500,
			txIndex: 1,
			outputIndex: 0
		});
		const finalCltv = (
			alice as unknown as { paddedFinalCltvExpiry: () => number }
		).paddedFinalCltvExpiry();

		// One part: 60k of a declared 100k total.
		alice.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.getNodeId(), 'hex'),
						shortChannelId: scid,
						amountToForwardMsat: 60_000n,
						outgoingCltvValue: finalCltv
					}
				]
			},
			invoice.paymentHash,
			finalCltv,
			invoice.paymentSecret,
			100_000n
		);
		await settle();

		const hashHex = invoice.paymentHash.toString('hex');
		const pendingMpp = (
			bob as unknown as {
				pendingMppPayments: Map<string, { receivedParts: unknown[] }>;
			}
		).pendingMppPayments;
		expect(
			pendingMpp.get(hashHex)?.receivedParts.length,
			'exactly one part accumulated'
		).to.equal(1);
		const settledBefore = alice.getPayment(invoice.paymentHash)!.status;
		expect(settledBefore, 'payer still pending').to.equal(
			PaymentStatus.PENDING
		);

		// Cycle the connection twice.
		for (let i = 0; i < 2; i++) await cycleConnection(alice, bob, gate);

		expect(
			pendingMpp.get(hashHex)?.receivedParts.length,
			'the part was not accumulated again'
		).to.equal(1);
		expect(
			alice.getPayment(invoice.paymentHash)!.status,
			'no preimage was revealed for an underpaid set'
		).to.equal(PaymentStatus.PENDING);
		const htlcs = bob
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState().htlcs;
		expect(htlcs.size, 'the single real HTLC is still unresolved').to.equal(1);

		// The genuine remaining 40k completes the set exactly once.
		let received = 0;
		bob.on('payment:received', () => {
			received++;
		});
		alice.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.getNodeId(), 'hex'),
						shortChannelId: scid,
						amountToForwardMsat: 40_000n,
						outgoingCltvValue: finalCltv
					}
				]
			},
			invoice.paymentHash,
			finalCltv,
			invoice.paymentSecret,
			100_000n
		);
		await settle();
		expect(received, 'the set settled exactly once').to.equal(1);

		bob.destroy();
		alice.destroy();
	});
});
