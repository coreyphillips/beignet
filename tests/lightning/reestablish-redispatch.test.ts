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

/** Event-relay wire with a dead switch: dead = the victim's process is gone. */
function wire(
	a: LightningNode,
	b: LightningNode,
	dead: { val: boolean }
): void {
	a.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (dead.val) return;
		if (pk === b.getNodeId()) b.handlePeerMessage(a.getNodeId(), t, p);
	});
	b.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (dead.val) return;
		if (pk === a.getNodeId()) a.handlePeerMessage(b.getNodeId(), t, p);
	});
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
});
