/**
 * Network map restore benchmark: how long a node takes to bring back the
 * gossip rows stored in its SQLite database (read through
 * getGraphRestoreStats), on a store the size of a phone's after a few weeks
 * on mainnet. Each run builds a fresh node on the same database; the median
 * run is reported. Usage:
 *   npx ts-node scripts/bench-graph-restore.ts [runs]
 * BENCH_CHANNELS and BENCH_NODES set the store's size (default 20300 and
 * 8000, a phone's on 2026-10-06; a node no channel reaches is left out);
 * BENCH_DB keeps the store in that file and reuses it when it exists.
 * Run node with --expose-gc to collect between runs, and with --jitless for a
 * rough stand-in for Hermes, which has no JIT either. A phone is slower again:
 * its Buffer is a JavaScript polyfill that decodes hex a byte at a time.
 *
 * Each run restores the store inline, as the constructor always did, and
 * cooperatively (cooperativeGraphRestore), in slices of
 * LightningNode.GRAPH_RESTORE_SLICE_MS; the two are interleaved so machine
 * load hits them alike.
 *
 * Columns: graphMs is the map's restore from start to end, busyMs the part
 * spent restoring, slices how many turns it took, and maxLagMs the longest
 * the event loop went without serving a probe timer, which is what a tap
 * waits for. Then the restore's steps in milliseconds, as
 * getGraphRestoreStats splits them (load is the read and the parse of each
 * row), and the cost per channel row of loading and restoring channels.
 */
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../src/lightning/channel/types';
import { getPublicKey } from '../src/lightning/crypto/ecdh';
import {
	IChannelUpdateMessage,
	IGraphChannel,
	IGraphNode
} from '../src/lightning/gossip/types';
import { Network } from '../src/lightning/invoice/types';
import { LightningNode } from '../src/lightning/node/lightning-node';
import { IGraphRestoreStats, INodeConfig } from '../src/lightning/node/types';
import { SqliteStorage } from '../src/lightning/storage/sqlite-storage';

/** A repeatable byte source, so every store this builds is the same. */
function bytes(seed: string): (length: number) => Buffer {
	let counter = 0;
	return (length) => {
		const out = Buffer.alloc(length);
		for (let at = 0; at < length; at += 32) {
			crypto
				.createHash('sha256')
				.update(seed)
				.update(String(counter++))
				.digest()
				.copy(out, at);
		}
		return out;
	};
}

const scid = (index: number): Buffer => {
	const out = Buffer.alloc(8);
	// Block, transaction and output in the mainnet range, all distinct.
	out.writeUIntBE(700_000 + Math.floor(index / 1000), 0, 3);
	out.writeUIntBE(index % 1000, 3, 3);
	out.writeUInt16BE(index % 2, 6);
	return out;
};

/** Writes a store of `channels` channel rows among `nodes` node rows. */
function buildStore(dbPath: string, channels: number, nodes: number): void {
	const random = bytes(`bench-graph-restore:${channels}:${nodes}`);
	const nodeIds = Array.from({ length: nodes }, () =>
		Buffer.concat([Buffer.from([0x02]), random(32)])
	);
	const linked = nodeIds.map(() => new Set<string>());
	const now = Math.floor(Date.now() / 1000);
	const storage = new SqliteStorage(dbPath);
	storage.open();
	storage.transaction(() => {
		for (let i = 0; i < channels; i++) {
			const a = random(4).readUInt32BE(0) % nodes;
			let b = random(4).readUInt32BE(0) % nodes;
			if (b === a) b = (b + 1) % nodes;
			const [one, two] =
				Buffer.compare(nodeIds[a], nodeIds[b]) < 0 ? [a, b] : [b, a];
			const id = scid(i);
			const update = (direction: number): IChannelUpdateMessage => ({
				signature: random(64),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: id,
				timestamp: now - 3600 - (i % 86_400),
				messageFlags: 1,
				channelFlags: direction,
				cltvExpiryDelta: 144,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 100 + (i % 900),
				htlcMaximumMsat: 990_000_000n
			});
			const channel: IGraphChannel = {
				shortChannelId: id,
				nodeId1: nodeIds[one],
				nodeId2: nodeIds[two],
				features: Buffer.alloc(0),
				announcement: {
					nodeSignature1: random(64),
					nodeSignature2: random(64),
					bitcoinSignature1: random(64),
					bitcoinSignature2: random(64),
					features: Buffer.alloc(0),
					chainHash: REGTEST_CHAIN_HASH,
					shortChannelId: id,
					nodeId1: nodeIds[one],
					nodeId2: nodeIds[two],
					bitcoinKey1: Buffer.concat([Buffer.from([0x03]), random(32)]),
					bitcoinKey2: Buffer.concat([Buffer.from([0x02]), random(32)])
				},
				announcementVerified: true,
				update1: update(0),
				update1Verified: true,
				update2: update(1),
				update2Verified: true
			};
			const scidHex = id.toString('hex');
			storage.saveGossipChannel(scidHex, channel);
			linked[one].add(scidHex);
			linked[two].add(scidHex);
		}
		nodeIds.forEach((nodeId, i) => {
			// A node no channel reaches is an orphan the first restore deletes,
			// which would shrink the store after the warm-up run.
			if (linked[i].size === 0) return;
			const node: IGraphNode = {
				nodeId,
				channels: linked[i],
				announcement: {
					signature: random(64),
					features: Buffer.from('0800000a69a2', 'hex'),
					timestamp: now - 7200,
					nodeId,
					rgbColor: random(3),
					alias: random(32),
					addresses: [{ type: 1, host: '203.0.113.7', port: 9735 }]
				},
				announcementVerified: true
			};
			storage.saveGossipNode(nodeId.toString('hex'), node);
		});
	});
	storage.close();
}

function nodeConfig(
	storage: SqliteStorage,
	cooperativeGraphRestore: boolean
): INodeConfig {
	const random = bytes('bench-graph-restore:node');
	const keys = Array.from({ length: 5 }, () => random(32));
	return {
		nodePrivateKey: random(32),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		perCommitmentSeed: random(32),
		fundingPrivkey: keys[0],
		storage,
		enableNetworking: false,
		cooperativeGraphRestore
	};
}

interface IRun {
	stats: IGraphRestoreStats;
	/** The longest the event loop went without serving a probe timer. */
	maxLagMs: number;
}

/**
 * Builds a node on the store, inline or cooperatively, and waits for its
 * map to come back, timing the longest stretch the event loop was held.
 */
async function restoreOnce(
	dbPath: string,
	cooperative: boolean
): Promise<IRun> {
	let maxLagMs = 0;
	let last = Date.now();
	let probing = true;
	const probe = (): void => {
		const now = Date.now();
		maxLagMs = Math.max(maxLagMs, now - last);
		last = now;
		if (probing) setTimeout(probe, 1);
	};
	setTimeout(probe, 1);
	// Building the node is itself a stretch the probe cannot interrupt.
	await new Promise((resolve) => setTimeout(resolve, 5));
	last = Date.now();
	const storage = new SqliteStorage(dbPath);
	storage.open();
	const node = new LightningNode(nodeConfig(storage, cooperative));
	try {
		await node.whenGraphRestored();
		probing = false;
		maxLagMs = Math.max(maxLagMs, Date.now() - last);
		const stats = node.getGraphRestoreStats();
		if (!stats) throw new Error('the node reported no restore');
		return { stats, maxLagMs };
	} finally {
		node.destroy();
		storage.close();
	}
}

const median = (xs: number[]): number => {
	const s = [...xs].sort((a, b) => a - b);
	return s[Math.floor(s.length / 2)];
};

const main = async (): Promise<void> => {
	const runs = Number(process.argv[2] ?? 5);
	const channels = Number(process.env.BENCH_CHANNELS ?? 20_300);
	const nodes = Number(process.env.BENCH_NODES ?? 8_000);
	const kept = process.env.BENCH_DB;
	const dbPath =
		kept ??
		path.join(os.tmpdir(), `beignet-bench-graph-restore-${process.pid}.db`);
	if (!kept || !fs.existsSync(kept)) {
		const started = Date.now();
		buildStore(dbPath, channels, nodes);
		console.log(`built ${dbPath} in ${Date.now() - started}ms`);
	}
	console.log(
		`store: ${dbPath}, ${runs} runs, node ${process.version}` +
			(process.execArgv.includes('--jitless') ? ' --jitless' : '')
	);
	const gc = (globalThis as { gc?: () => void }).gc;
	const modes: Array<[string, boolean]> = [
		['inline', false],
		[`cooperative (${LightningNode.GRAPH_RESTORE_SLICE_MS}ms)`, true]
	];
	const results = new Map<string, IRun[]>(modes.map(([name]) => [name, []]));
	// One warm-up pass, then interleaved measured runs.
	for (let r = -1; r < runs; r++) {
		for (const [name, cooperative] of modes) {
			gc?.();
			const run = await restoreOnce(dbPath, cooperative);
			if (r >= 0) results.get(name)!.push(run);
		}
	}
	const rows = modes.map(([name]) => {
		const rs = results.get(name)!;
		const pick = (key: keyof IGraphRestoreStats): number =>
			median(rs.map((run) => Number(run.stats[key] ?? 0)));
		const first = rs[0].stats;
		return {
			mode: name,
			channelRows: first.channelRows,
			nodeRows: first.nodeRows,
			graphMs: pick('graphMs'),
			busyMs: pick('busyMs'),
			slices: pick('slices'),
			maxLagMs: median(rs.map((run) => run.maxLagMs)),
			loadChannelsMs: pick('loadChannelsMs'),
			restoreChannelsMs: pick('restoreChannelsMs'),
			loadNodesMs: pick('loadNodesMs'),
			restoreNodesMs: pick('restoreNodesMs'),
			usPerChannelRow: Math.round(
				((pick('loadChannelsMs') + pick('restoreChannelsMs')) * 1000) /
					Math.max(1, first.channelRows)
			)
		};
	});
	console.table(rows);
	if (!kept) fs.rmSync(dbPath, { force: true });
};

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
