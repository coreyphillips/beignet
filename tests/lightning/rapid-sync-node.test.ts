/**
 * LightningNode's cooperative Rapid Gossip Sync import
 * (loadRapidGossipSnapshotAsync): imports run one at a time, the broadcast
 * gossip intake holds until the import ends, a stale-gossip prune asked for
 * mid-import waits for its end (the import adds every channel before any
 * update, so a prune in between would wipe the snapshot), and destroy()
 * stops it without leaving the intake stuck.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	IChannelAnnouncementMessage,
	NetworkGraph,
	RapidGossipCancelledError,
	applyRapidGossipSnapshot,
	encodeChannelAnnouncementMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig } from '../../src/lightning/node/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	BITCOIN_CHAIN_HASH,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	buildV1Snapshot,
	generateNodes,
	generateSnapshot,
	prng
} from './helpers/rgs-snapshot';

function makeConfig(storage: SqliteStorage): INodeConfig {
	const seed = crypto.randomBytes(32);
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
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		// RGS snapshots are mainnet: only a mainnet graph admits them.
		network: Network.MAINNET as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: keys[0],
		storage,
		enableNetworking: false
	};
}

/** A mainnet snapshot stamped a minute ago; `updatedShare` of its channels get updates. */
function snapshot(seed: number, updatedShare = 1): Buffer {
	const rand = prng(seed);
	const { nodes, duplicates } = generateNodes(rand, 150);
	const { spec } = generateSnapshot(rand, {
		latestSeen: Math.floor(Date.now() / 1000) - 60,
		nodes,
		duplicates,
		channels: 600,
		updateTargets: (scids) => scids.filter(() => rand() < updatedShare)
	});
	return buildV1Snapshot(spec);
}

/** Broadcast channel_announcement bytes for a fresh mainnet channel. */
function announcement(block: number): { scid: Buffer; payload: Buffer } {
	const keys = [0, 1].map(() => getPublicKey(crypto.randomBytes(32)));
	keys.sort(Buffer.compare);
	const msg: IChannelAnnouncementMessage = {
		nodeSignature1: crypto.randomBytes(64),
		nodeSignature2: crypto.randomBytes(64),
		bitcoinSignature1: crypto.randomBytes(64),
		bitcoinSignature2: crypto.randomBytes(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: encodeShortChannelId({
			block,
			txIndex: 1,
			outputIndex: 0
		}),
		nodeId1: keys[0],
		nodeId2: keys[1],
		bitcoinKey1: getPublicKey(crypto.randomBytes(32)),
		bitcoinKey2: getPublicKey(crypto.randomBytes(32))
	};
	return {
		scid: msg.shortChannelId,
		payload: encodeChannelAnnouncementMessage(msg)
	};
}

async function rejection(promise: Promise<unknown>): Promise<Error> {
	try {
		await promise;
	} catch (err) {
		return err as Error;
	}
	throw new Error('expected a rejection');
}

describe('Rapid Gossip Sync import on a LightningNode', function () {
	this.timeout(30_000);

	const savedSlice = LightningNode.RAPID_GOSSIP_SLICE_MS;
	let storage: SqliteStorage;
	let dbPath: string;
	let node: LightningNode;

	type TInternals = {
		graph: NetworkGraph;
		rapidGossipImporting: boolean;
		gossipIntakeDraining: boolean;
		handleGossipMessage(pubkey: string, type: number, payload: Buffer): void;
		pruneStaleGossipWithStorage(): void;
	};
	const internals = (n: LightningNode): TInternals =>
		n as unknown as TInternals;
	const feed = (payload: Buffer): void =>
		internals(node).handleGossipMessage(
			'aa'.repeat(33),
			MessageType.CHANNEL_ANNOUNCEMENT,
			payload
		);

	beforeEach(() => {
		// One step of 32 entries per slice: every import spans many slices.
		LightningNode.RAPID_GOSSIP_SLICE_MS = 0;
		dbPath = path.join(
			os.tmpdir(),
			`beignet-test-rgs-node-${Date.now()}-${Math.random()
				.toString(36)
				.slice(2)}.db`
		);
		storage = new SqliteStorage(dbPath);
		storage.open();
		node = new LightningNode(makeConfig(storage));
	});

	afterEach(() => {
		LightningNode.RAPID_GOSSIP_SLICE_MS = savedSlice;
		node.destroy();
		storage.close();
		try {
			fs.unlinkSync(dbPath);
		} catch {
			/* ignore */
		}
	});

	it('applies the same graph as the one-pass import', async () => {
		const data = snapshot(1);
		const reference = new NetworkGraph();
		const expected = applyRapidGossipSnapshot(reference, data);
		let slices = 0;
		const result = await node.loadRapidGossipSnapshotAsync(data, {
			onSlice: () => slices++
		});
		expect(result).to.deep.equal(expected);
		expect(slices).to.be.greaterThan(10);
		const graph = internals(node).graph;
		expect(graph.getChannelCount()).to.equal(reference.getChannelCount());
		expect(graph.getNodeCount()).to.equal(reference.getNodeCount());
		expect(internals(node).rapidGossipImporting).to.equal(false);
	});

	it('runs concurrent imports one after the other', async () => {
		const order: string[] = [];
		const first = node.loadRapidGossipSnapshotAsync(snapshot(2), {
			onSlice: () => order.push('first')
		});
		const second = node.loadRapidGossipSnapshotAsync(snapshot(3), {
			onSlice: () => order.push('second')
		});
		await Promise.all([first, second]);
		const firstSlices = order.filter((s) => s === 'first').length;
		expect(firstSlices).to.be.greaterThan(10);
		// Every slice of the first import precedes every slice of the second.
		expect(order.indexOf('second')).to.equal(firstSlices);
		expect(order.lastIndexOf('first')).to.equal(firstSlices - 1);
	});

	it('a failed import releases the queue for the next one', async () => {
		const broken = Buffer.from(snapshot(4));
		broken[3] = 2; // unsupported version
		const failed = node.loadRapidGossipSnapshotAsync(broken);
		const next = node.loadRapidGossipSnapshotAsync(snapshot(5));
		expect((await rejection(failed)).message).to.match(/version 2/);
		expect((await next).channelsAdded).to.be.greaterThan(0);
		expect(internals(node).rapidGossipImporting).to.equal(false);
	});

	it('holds the gossip intake until the import ends, then drains it', async () => {
		const gossip = announcement(900_000);
		const graph = internals(node).graph;
		let fed = false;
		let landedMidImport = false;
		let flushed: Promise<void> | undefined;
		await node.loadRapidGossipSnapshotAsync(snapshot(6), {
			onSlice: () => {
				if (!fed) {
					feed(gossip.payload);
					fed = true;
					// The barrier must wait for the import, not resolve early.
					flushed = node.flushGossip();
					return;
				}
				if (graph.getChannel(gossip.scid)) landedMidImport = true;
			}
		});
		expect(fed).to.equal(true);
		expect(landedMidImport).to.equal(false);
		expect(graph.getChannel(gossip.scid)).to.equal(undefined);
		await flushed;
		expect(graph.getChannel(gossip.scid)).to.not.equal(undefined);
		expect(internals(node).gossipIntakeDraining).to.equal(false);
	});

	it('defers a stale-gossip prune asked for mid-import to its end', async () => {
		// Half the channels get no update: the prune drops exactly those.
		const data = snapshot(7, 0.5);
		const reference = new NetworkGraph();
		const expected = applyRapidGossipSnapshot(reference, data);
		reference.pruneStaleChannels(Math.floor(Date.now() / 1000));
		expect(reference.getChannelCount()).to.be.within(
			1,
			expected.channelsAdded - 1
		);

		const graph = internals(node).graph;
		let asked = false;
		let atLastSlice = 0;
		const result = await node.loadRapidGossipSnapshotAsync(data, {
			onSlice: () => {
				// Mid announcements: every channel held so far has no update.
				if (!asked && graph.getChannelCount() > 0) {
					internals(node).pruneStaleGossipWithStorage();
					asked = true;
				}
				atLastSlice = graph.getChannelCount();
			}
		});
		expect(asked).to.equal(true);
		// Nothing was pruned while the import ran...
		expect(atLastSlice).to.equal(result.channelsAdded);
		// ...and the deferred prune ran as it ended.
		expect(graph.getChannelCount()).to.equal(reference.getChannelCount());
	});

	it('stops when the node is destroyed, without leaving the intake stuck', async () => {
		const graph = internals(node).graph;
		let slices = 0;
		let atDestroy = -1;
		const run = node.loadRapidGossipSnapshotAsync(snapshot(8), {
			onSlice: () => {
				slices++;
				if (slices === 1) feed(announcement(900_001).payload);
				if (slices === 3) {
					node.destroy();
					atDestroy = graph.getChannelCount();
				}
			}
		});
		const err = await rejection(run);
		expect(err).to.be.instanceOf(RapidGossipCancelledError);
		expect(slices).to.equal(3);
		expect(internals(node).rapidGossipImporting).to.equal(false);
		// The held intake notices the destroy and closes; nothing more lands.
		await node.flushGossip();
		await new Promise<void>((resolve) => setTimeout(resolve, 40));
		expect(graph.getChannelCount()).to.equal(atDestroy);
		expect(internals(node).gossipIntakeDraining).to.equal(false);
	});

	it('an import queued behind a destroy never starts', async () => {
		let slices = 0;
		const first = node.loadRapidGossipSnapshotAsync(snapshot(9), {
			onSlice: () => {
				if (++slices === 2) node.destroy();
			}
		});
		const queued = node.loadRapidGossipSnapshotAsync(snapshot(10), {
			onSlice: () => slices++
		});
		expect(await rejection(first)).to.be.instanceOf(RapidGossipCancelledError);
		expect(await rejection(queued)).to.be.instanceOf(RapidGossipCancelledError);
		expect(slices).to.equal(2);
	});
});
