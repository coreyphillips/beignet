/**
 * The stored network map's restore in slices (cooperativeGraphRestore):
 * the same graph and the same rows left on disk as the inline restore, the
 * event loop served between slices, live gossip kept over older disk rows,
 * and a node that pays, imports RGS, shuts down or loses its storage
 * mid-restore handled the way the inline restore would have left it.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	BITCOIN_CHAIN_HASH,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	NetworkGraph,
	encodeChannelUpdateMessage,
	encodeQueryChannelRangeMessage
} from '../../src/lightning/gossip';
import {
	DEFAULT_PRUNE_MAX_AGE,
	IChannelUpdateMessage,
	IGraphChannel,
	IGraphNode
} from '../../src/lightning/gossip/types';
import { Network } from '../../src/lightning/invoice/types';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IGraphRestoreStats,
	INodeConfig
} from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { buildV1Snapshot } from './helpers/rgs-snapshot';

const NOW = (): number => Math.floor(Date.now() / 1000);

function makeConfig(
	storage: SqliteStorage,
	cooperativeGraphRestore: boolean
): INodeConfig {
	const keys = Array.from({ length: 5 }, () => crypto.randomBytes(32));
	return {
		nodePrivateKey: crypto.randomBytes(32),
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
		enableNetworking: false,
		cooperativeGraphRestore
	};
}

const scidOf = (i: number): Buffer => {
	const out = Buffer.alloc(8);
	out.writeUIntBE(800_000 + i, 0, 3);
	out.writeUIntBE(1, 3, 3);
	return out;
};

function update(
	scid: Buffer,
	direction: 0 | 1,
	timestamp: number
): IChannelUpdateMessage {
	return {
		signature: crypto.randomBytes(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp,
		messageFlags: 1,
		channelFlags: direction,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 100,
		htlcMaximumMsat: 100_000_000n
	};
}

function channel(
	i: number,
	nodes: [Buffer, Buffer],
	timestamp: number,
	verified: boolean | undefined
): IGraphChannel {
	const [nodeId1, nodeId2] =
		Buffer.compare(nodes[0], nodes[1]) < 0 ? nodes : [nodes[1], nodes[0]];
	const scid = scidOf(i);
	return {
		shortChannelId: scid,
		nodeId1,
		nodeId2,
		features: Buffer.alloc(0),
		announcement: {
			nodeSignature1: crypto.randomBytes(64),
			nodeSignature2: crypto.randomBytes(64),
			bitcoinSignature1: crypto.randomBytes(64),
			bitcoinSignature2: crypto.randomBytes(64),
			features: Buffer.alloc(0),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			nodeId1,
			nodeId2,
			bitcoinKey1: getPublicKey(crypto.randomBytes(32)),
			bitcoinKey2: getPublicKey(crypto.randomBytes(32))
		},
		announcementVerified: verified,
		update1: update(scid, 0, timestamp),
		update1Verified: verified,
		update2: update(scid, 1, timestamp - 5),
		update2Verified: verified
	};
}

interface IStore {
	dbPath: string;
	nodeIds: Buffer[];
	staleScids: string[];
	orphanIds: string[];
}

/**
 * A store with every kind of row the restore treats differently: fresh
 * channels, verified and not, stale ones, one with a far-future update,
 * node rows behind channels, and orphan node rows with none.
 */
function buildStore(channels = 160): IStore {
	const dbPath = path.join(
		os.tmpdir(),
		`beignet-test-graph-restore-${process.pid}-${crypto
			.randomBytes(4)
			.toString('hex')}.db`
	);
	const storage = new SqliteStorage(dbPath);
	storage.open();
	const nodeIds = Array.from({ length: 60 }, () =>
		getPublicKey(crypto.randomBytes(32))
	);
	const staleScids: string[] = [];
	const linked = nodeIds.map(() => new Set<string>());
	const now = NOW();
	for (let i = 0; i < channels; i++) {
		const a = i % nodeIds.length;
		const b =
			(i * 7 + 3) % nodeIds.length === a ? (a + 1) % 60 : (i * 7 + 3) % 60;
		const stale = i % 16 === 5;
		const verified = i % 3 === 0 ? undefined : i % 3 === 1 ? true : false;
		const row = channel(
			i,
			[nodeIds[a], nodeIds[b]],
			stale ? now - DEFAULT_PRUNE_MAX_AGE - 3600 : now - 60 - i,
			verified
		);
		if (i === 7) row.update2 = update(row.shortChannelId, 1, now + 86_400);
		const scidHex = row.shortChannelId.toString('hex');
		if (stale) staleScids.push(scidHex);
		storage.saveGossipChannel(scidHex, row);
		if (!stale) {
			linked[a].add(scidHex);
			linked[b].add(scidHex);
		}
	}
	nodeIds.forEach((nodeId, i) => {
		const node: IGraphNode = {
			nodeId,
			channels: linked[i],
			announcement: {
				signature: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				timestamp: now - 120,
				nodeId,
				rgbColor: Buffer.alloc(3),
				alias: Buffer.alloc(32),
				addresses: [{ type: 1, host: '203.0.113.9', port: 9735 }]
			},
			announcementVerified: i % 2 === 0
		};
		storage.saveGossipNode(nodeId.toString('hex'), node);
	});
	const orphanIds = [0, 1, 2].map(() => {
		const nodeId = getPublicKey(crypto.randomBytes(32));
		storage.saveGossipNode(nodeId.toString('hex'), {
			nodeId,
			channels: new Set(['cc'.repeat(8)])
		});
		return nodeId.toString('hex');
	});
	storage.close();
	return { dbPath, nodeIds, staleScids, orphanIds };
}

function copyStore(store: IStore): string {
	const copy = store.dbPath.replace(/\.db$/, '-copy.db');
	fs.copyFileSync(store.dbPath, copy);
	return copy;
}

function removeDb(dbPath: string): void {
	for (const suffix of ['', '-wal', '-shm']) {
		fs.rmSync(dbPath + suffix, { force: true });
	}
}

/** What the graph holds, in its own order, and what is left on disk. */
function outcome(node: LightningNode, storage: SqliteStorage): unknown {
	const graph = node.getGraph();
	return {
		channels: graph.getAllChannels().map((c) => ({
			scid: c.shortChannelId.toString('hex'),
			nodes: [c.nodeId1.toString('hex'), c.nodeId2.toString('hex')],
			update1: c.update1?.timestamp,
			update2: c.update2?.timestamp,
			announcementVerified: c.announcementVerified,
			announcementVerifyDeferred: c.announcementVerifyDeferred,
			update1Verified: c.update1Verified,
			update2Verified: c.update2Verified
		})),
		nodes: graph.getAllNodes().map((n) => ({
			id: n.nodeId.toString('hex'),
			channels: [...n.channels].sort(),
			announced: !!n.announcement,
			verified: n.announcementVerified
		})),
		diskChannels: storage
			.loadAllGossipChannels()
			.map((c) => c.shortChannelId.toString('hex'))
			.sort(),
		diskNodes: storage
			.loadAllGossipNodes()
			.map((n) => n.nodeId.toString('hex'))
			.sort()
	};
}

describe('Cooperative restore of the stored network map', () => {
	const savedSlice = LightningNode.GRAPH_RESTORE_SLICE_MS;
	const savedCap = NetworkGraph.MAX_CHANNELS;
	const cleanup: Array<() => void> = [];

	afterEach(() => {
		LightningNode.GRAPH_RESTORE_SLICE_MS = savedSlice;
		NetworkGraph.MAX_CHANNELS = savedCap;
		for (const step of cleanup.splice(0).reverse()) {
			try {
				step();
			} catch {
				/* already gone */
			}
		}
	});

	/** Opens `dbPath` and builds a node on it, torn down after the test. */
	function open(
		dbPath: string,
		cooperative: boolean
	): { node: LightningNode; storage: SqliteStorage } {
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const node = new LightningNode(makeConfig(storage, cooperative));
		cleanup.push(() => removeDb(dbPath));
		cleanup.push(() => storage.close());
		cleanup.push(() => node.destroy());
		return { node, storage };
	}

	it('leaves the same graph, in the same order, and the same rows on disk as the inline restore', async () => {
		const store = buildStore();
		const copy = copyStore(store);
		// A ceiling below the row count, so eviction runs in both.
		NetworkGraph.MAX_CHANNELS = 120;
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;

		const inline = open(store.dbPath, false);
		expect(inline.node.isGraphRestoring()).to.equal(false);
		const sliced = open(copy, true);
		expect(sliced.node.isGraphRestoring()).to.equal(true);
		expect(await sliced.node.whenGraphRestored()).to.equal(true);
		expect(sliced.node.isGraphRestoring()).to.equal(false);

		expect(outcome(sliced.node, sliced.storage)).to.deep.equal(
			outcome(inline.node, inline.storage)
		);
		const inlineStats = inline.node.getGraphRestoreStats()!;
		const slicedStats = sliced.node.getGraphRestoreStats()!;
		expect(inlineStats).to.include({ cooperative: false, slices: 1 });
		expect(slicedStats.cooperative).to.equal(true);
		expect(slicedStats.slices).to.be.greaterThan(5);
		for (const key of [
			'channelRows',
			'staleChannels',
			'nodeRows',
			'orphanNodes',
			'graphChannels',
			'graphNodes'
		] as const) {
			expect(slicedStats[key], key).to.equal(inlineStats[key]);
		}
		expect(slicedStats.staleChannels).to.equal(store.staleScids.length);
		expect(slicedStats.orphanNodes).to.equal(store.orphanIds.length);
		// The stale channel rows and orphan node rows are gone from disk.
		const left = sliced.storage
			.loadAllGossipChannels()
			.map((c) => c.shortChannelId.toString('hex'));
		for (const scid of store.staleScids) expect(left).to.not.include(scid);
	});

	it('times its parts within the whole, inline and in slices', async () => {
		const store = buildStore(40);
		const copy = copyStore(store);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const check = (stats: IGraphRestoreStats): void => {
			const parts =
				stats.loadChannelsMs +
				stats.restoreChannelsMs +
				stats.loadNodesMs +
				stats.restoreNodesMs +
				stats.deleteMs +
				stats.pruneMs +
				stats.reannounceMs;
			expect(parts).to.be.at.most(stats.busyMs);
			expect(stats.busyMs).to.be.at.most(stats.graphMs);
		};
		const inline = open(store.dbPath, false);
		const inlineStats = inline.node.getGraphRestoreStats()!;
		check(inlineStats);
		// Inline, the constructor's own restore holds the map's.
		expect(inlineStats.restoreMs).to.be.at.least(inlineStats.graphMs);

		const sliced = open(copy, true);
		// Nothing to report until it is back.
		expect(sliced.node.getGraphRestoreStats()).to.equal(null);
		const reported = new Promise<IGraphRestoreStats>((resolve) =>
			sliced.node.once('graph:restored', resolve)
		);
		await sliced.node.whenGraphRestored();
		const event = await reported;
		check(event);
		expect(event).to.deep.equal(sliced.node.getGraphRestoreStats());
		const logged = sliced.storage
			.loadActionLog({ category: 'peer' })
			.filter((entry) => entry.action === 'graph_restored');
		expect(logged).to.have.length(1);
	});

	it('yields between slices, so a due timer runs before the restore ends', async () => {
		const store = buildStore(200);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const order: string[] = [];
		const { node } = open(store.dbPath, true);
		setTimeout(() => order.push('timer'), 0);
		void node.whenGraphRestored().then(() => order.push('restored'));
		await node.whenGraphRestored();
		await new Promise((resolve) => setTimeout(resolve, 5));
		expect(order).to.deep.equal(['timer', 'restored']);
	});

	it('reads a page at a time in storage order, skipping a corrupt row', () => {
		const store = buildStore(30);
		const storage = new SqliteStorage(store.dbPath);
		storage.open();
		cleanup.push(() => removeDb(store.dbPath));
		cleanup.push(() => storage.close());
		(
			storage as unknown as {
				db: { prepare(sql: string): { run(...args: unknown[]): void } };
			}
		).db
			.prepare(
				'INSERT INTO gossip_channels (scid_hex, channel_json) VALUES (?, ?)'
			)
			.run('ff'.repeat(8), '{not json');
		const whole = storage
			.loadAllGossipChannels()
			.map((c) => c.shortChannelId.toString('hex'));
		const paged: string[] = [];
		let cursor = 0;
		for (;;) {
			const page = storage.loadGossipChannelsAfter(cursor, 7);
			paged.push(...page.rows.map((c) => c.shortChannelId.toString('hex')));
			expect(page.cursor).to.be.at.least(cursor);
			cursor = page.cursor;
			if (page.done) break;
		}
		expect(paged).to.deep.equal(whole);
		expect(whole).to.have.length(30);
		const nodes = storage.loadGossipNodesAfter(0, 1000);
		expect(nodes.done).to.equal(true);
		expect(nodes.rows).to.have.length(storage.loadAllGossipNodes().length);
	});

	it('restores whole on a storage that cannot page', async () => {
		const store = buildStore(50);
		const copy = copyStore(store);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const inline = open(store.dbPath, false);
		const storage = new SqliteStorage(copy);
		storage.open();
		const unpaged = storage as unknown as Record<string, unknown>;
		unpaged.loadGossipChannelsAfter = undefined;
		unpaged.loadGossipNodesAfter = undefined;
		const node = new LightningNode(makeConfig(storage, true));
		cleanup.push(() => removeDb(copy));
		cleanup.push(() => storage.close());
		cleanup.push(() => node.destroy());
		expect(await node.whenGraphRestored()).to.equal(true);
		expect(outcome(node, storage)).to.deep.equal(
			outcome(inline.node, inline.storage)
		);
	});

	it('holds broadcast gossip until the map is back, so a newer update outlives the older row', async () => {
		const store = buildStore(120);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const { node } = open(store.dbPath, true);
		// A channel whose row comes late in the store: still on disk now.
		const scid = scidOf(110);
		expect(node.getGraph().getChannel(scid)).to.equal(undefined);
		const newer = NOW() - 1;
		(
			node as unknown as {
				handleGossipMessage(p: string, t: number, b: Buffer): void;
			}
		).handleGossipMessage(
			'aa'.repeat(33),
			MessageType.CHANNEL_UPDATE,
			encodeChannelUpdateMessage(update(scid, 0, newer))
		);
		await node.whenGraphRestored();
		await node.flushGossip();
		expect(node.getGraph().getChannel(scid)?.update1?.timestamp).to.equal(
			newer
		);
	});

	it('answers a peer query, and starts a gossip sync, only once the map is back', async () => {
		const store = buildStore(120);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const { node } = open(store.dbPath, true);
		const waiting = (): number =>
			(node as unknown as { afterGraphRestore: unknown[] }).afterGraphRestore
				.length;
		(
			node as unknown as {
				handleGossipMessage(p: string, t: number, b: Buffer): void;
			}
		).handleGossipMessage(
			'bb'.repeat(33),
			MessageType.QUERY_CHANNEL_RANGE,
			encodeQueryChannelRangeMessage({
				chainHash: BITCOIN_CHAIN_HASH,
				firstBlocknum: 0,
				numberOfBlocks: 1_000_000
			})
		);
		node.initiateGossipSync('cc'.repeat(33));
		expect(waiting()).to.equal(2);
		expect(node.getGossipSyncState('cc'.repeat(33))).to.equal(null);
		await node.whenGraphRestored();
		expect(waiting()).to.equal(0);
		expect(node.getGossipSyncState('cc'.repeat(33))).to.not.equal(null);
	});

	it('defers a stale-gossip prune to its own end', async () => {
		const store = buildStore(120);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const { node } = open(store.dbPath, true);
		const inner = node as unknown as {
			pruneStaleGossipWithStorage(): void;
			gossipPruneDeferred: boolean;
		};
		inner.pruneStaleGossipWithStorage();
		expect(inner.gossipPruneDeferred).to.equal(true);
		expect(node.isGraphRestoring()).to.equal(true);
		await node.whenGraphRestored();
		expect(inner.gossipPruneDeferred).to.equal(false);
	});

	it('runs an RGS import only after the stored map is back, and the stored rows win', async () => {
		const store = buildStore(120);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const { node } = open(store.dbPath, true);
		const events: string[] = [];
		node.once('graph:restored', () => events.push('restored'));
		// One channel the store holds, between two of its nodes, and one it
		// does not.
		const disk = node.getGraph();
		const snapshot = buildV1Snapshot({
			latestSeen: NOW() - 60,
			nodes: [store.nodeIds[0], store.nodeIds[1]].sort(Buffer.compare),
			channels: [
				{ scid: scidOf(0).readBigUInt64BE(0), n1: 0, n2: 1 },
				{ scid: scidOf(5000).readBigUInt64BE(0), n1: 0, n2: 1 }
			],
			defaults: {
				cltv: 40,
				htlcMin: 1000n,
				feeBase: 1000,
				feeProp: 100,
				htlcMax: 100_000_000n
			},
			updates: []
		});
		const imported = node.loadRapidGossipSnapshotAsync(snapshot, {
			onSlice: () => {
				if (!events.includes('import')) events.push('import');
			}
		});
		const result = await imported;
		expect(events).to.deep.equal(['restored', 'import']);
		// The stored row kept its place; only the new channel was added.
		expect(result.channelsAdded).to.equal(1);
		expect(
			disk.getChannel(scidOf(0))?.announcement?.nodeSignature1
		).to.not.deep.equal(Buffer.alloc(64));
	});

	it('finishes at once when a route is asked for mid-restore', async () => {
		const store = buildStore(160);
		const copy = copyStore(store);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const inline = open(store.dbPath, false);
		const { node, storage } = open(copy, true);
		expect(node.isGraphRestoring()).to.equal(true);
		const forced = new Promise<Record<string, unknown>>((resolve) =>
			node.on(
				'log',
				(entry: { action: string; data: Record<string, unknown> }) => {
					if (entry.action === 'graph_restore_forced') resolve(entry.data);
				}
			)
		);
		const target = store.nodeIds[3];
		const route = node.queryRoute(target, 10_000n);
		expect(node.isGraphRestoring()).to.equal(false);
		expect((await forced).caller).to.equal('queryRoute');
		expect(route).to.deep.equal(inline.node.queryRoute(target, 10_000n));
		expect(outcome(node, storage)).to.deep.equal(
			outcome(inline.node, inline.storage)
		);
	});

	it('drops the restore when the node is destroyed mid-way: nothing deleted, holds let go', async () => {
		const store = buildStore(160);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const storage = new SqliteStorage(store.dbPath);
		storage.open();
		cleanup.push(() => removeDb(store.dbPath));
		cleanup.push(() => storage.close());
		const node = new LightningNode(makeConfig(storage, true));
		node.initiateGossipSync('dd'.repeat(33));
		node.destroy();
		expect(await node.whenGraphRestored()).to.equal(false);
		expect(node.isGraphRestoring()).to.equal(false);
		expect(
			(node as unknown as { afterGraphRestore: unknown[] }).afterGraphRestore
		).to.have.length(0);
		// The node closed its storage as it went; what it left is read afresh.
		const after = new SqliteStorage(store.dbPath);
		after.open();
		cleanup.push(() => after.close());
		const left = after
			.loadAllGossipChannels()
			.map((c) => c.shortChannelId.toString('hex'));
		for (const scid of store.staleScids) expect(left).to.include(scid);
		expect(node.getGraphRestoreStats()).to.equal(null);
	});

	it('ends with what came back when the storage fails mid-restore, deleting nothing', async () => {
		const store = buildStore(160);
		LightningNode.GRAPH_RESTORE_SLICE_MS = 0;
		const storage = new SqliteStorage(store.dbPath);
		storage.open();
		cleanup.push(() => removeDb(store.dbPath));
		cleanup.push(() => storage.close());
		const real = storage.loadGossipChannelsAfter.bind(storage);
		let pages = 0;
		storage.loadGossipChannelsAfter = (
			after,
			limit
		): ReturnType<typeof real> => {
			if (++pages === 3) throw new Error('disk I/O error');
			return real(after, limit);
		};
		const node = new LightningNode(makeConfig(storage, true));
		cleanup.push(() => node.destroy());
		const errors: string[] = [];
		node.on('node:error', (e: { code: string }) => errors.push(e.code));
		expect(await node.whenGraphRestored()).to.equal(false);
		expect(errors).to.deep.equal(['GRAPH_RESTORE_FAILED']);
		expect(node.isGraphRestoring()).to.equal(false);
		const left = storage
			.loadAllGossipChannels()
			.map((c) => c.shortChannelId.toString('hex'));
		for (const scid of store.staleScids) expect(left).to.include(scid);
		const stats = node.getGraphRestoreStats()!;
		expect(stats.channelRows).to.be.lessThan(160);
	});
});

describe('BeignetNode deferGraphRestore', () => {
	const OFFLINE_ELECTRUM = {
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false
	};

	it('makes a payment wait for a restore still running, rather than finish it at once', async function () {
		this.timeout(20_000);
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-defer-pay-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: dir,
			logLevel: 'silent',
			deferGraphRestore: true,
			...OFFLINE_ELECTRUM
		});
		try {
			await node.getNode().whenGraphRestored();
			// Stand in for a restore that has not ended.
			let finish!: () => void;
			const restored = new Promise<boolean>((resolve) => {
				finish = (): void => resolve(true);
			});
			let restoring = true;
			const inner = node.getNode() as unknown as {
				isGraphRestoring(): boolean;
				whenGraphRestored(): Promise<boolean>;
			};
			inner.isGraphRestoring = (): boolean => restoring;
			inner.whenGraphRestored = (): Promise<boolean> => restored;
			let settled = false;
			const paying = node.payInvoice('lnbcrt1notaninvoice').then(
				() => {
					settled = true;
				},
				(err: Error) => {
					settled = true;
					return err;
				}
			);
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(settled).to.equal(false);
			restoring = false;
			finish();
			// The payment then goes on as usual, here to refuse the request.
			expect(await paying).to.be.instanceOf(Error);
		} finally {
			await node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	for (const deferGraphRestore of [false, true]) {
		it(`brings the stored map back ${
			deferGraphRestore ? 'after create, in slices' : 'inside create'
		} and reports it`, async function () {
			this.timeout(20_000);
			const dir = fs.mkdtempSync(
				path.join(os.tmpdir(), 'beignet-defer-graph-')
			);
			const node = await BeignetNode.create({
				network: 'regtest',
				dataDir: dir,
				logLevel: 'silent',
				deferGraphRestore,
				...OFFLINE_ELECTRUM
			});
			try {
				expect(await node.getNode().whenGraphRestored()).to.equal(true);
				const stats = node.getGraphRestoreStats();
				expect(stats?.cooperative).to.equal(deferGraphRestore);
				expect(stats?.constructMs).to.be.a('number');
				expect(node.getGraphInfo().restoring).to.equal(undefined);
			} finally {
				await node.destroy();
				fs.rmSync(dir, { recursive: true, force: true });
			}
		});
	}
});
