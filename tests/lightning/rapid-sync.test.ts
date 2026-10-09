import { expect } from 'chai';
import { EventEmitter } from 'events';
import https from 'https';
import sinon from 'sinon';
import { PassThrough } from 'stream';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	applyRapidGossipSnapshot,
	applyRapidGossipSnapshotAsync,
	fetchRapidGossipSnapshot,
	IRapidGossipResult,
	MAX_RGS_SNAPSHOT_BYTES,
	RapidGossipCancelledError,
	DEFAULT_RGS_URL
} from '../../src/lightning/gossip/rapid-sync';
import {
	encodeShortChannelId,
	decodeShortChannelId,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	IGraphChannel,
	IGraphNode
} from '../../src/lightning/gossip/types';
import {
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import {
	serializeGraphChannel,
	serializeGraphNode
} from '../../src/lightning/storage/serialization';
import { applyRapidGossipSnapshotReference } from './helpers/rapid-sync-reference';
import {
	IUpdate,
	TWO_32,
	TWO_63,
	TWO_64,
	buildV1Snapshot,
	generateNodes,
	generateSnapshot,
	prng,
	u64,
	unknownScids
} from './helpers/rgs-snapshot';

const NODE_A = Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, 0xaa)]);
const NODE_B = Buffer.concat([Buffer.from([0x03]), Buffer.alloc(32, 0xbb)]); // A < B

/** The one-pass and the sliced import, behind one signature. */
const PATHS: Array<{
	name: string;
	apply: (
		graph: NetworkGraph,
		data: Buffer,
		expectedChainHash?: Buffer
	) => Promise<IRapidGossipResult>;
}> = [
	{
		name: 'sync',
		apply: async (graph, data, expectedChainHash) =>
			applyRapidGossipSnapshot(graph, data, expectedChainHash)
	},
	{
		name: 'async',
		apply: (graph, data, expectedChainHash) =>
			applyRapidGossipSnapshotAsync(graph, data, {
				expectedChainHash,
				sliceMs: 0
			})
	}
];

async function rejection(promise: Promise<unknown>): Promise<Error> {
	try {
		await promise;
	} catch (err) {
		return err as Error;
	}
	throw new Error('expected a rejection');
}

for (const { name, apply } of PATHS) {
	describe(`Rapid Gossip Sync (v1 snapshot parsing, ${name})`, () => {
		const scid = encodeShortChannelId({
			block: 800000,
			txIndex: 5,
			outputIndex: 1
		}).readBigUInt64BE();
		const defaults = {
			cltv: 40,
			htlcMin: 1000n,
			feeBase: 1000,
			feeProp: 1,
			htlcMax: 100_000_000n
		};

		function baseSnapshot(updates: IUpdate[]): Buffer {
			return buildV1Snapshot({
				latestSeen: 1_700_000_000,
				nodes: [NODE_A, NODE_B],
				channels: [{ scid, n1: 0, n2: 1 }],
				defaults,
				updates
			});
		}

		it('ingests a channel and both directional updates', async () => {
			const graph = new NetworkGraph();
			const snap = baseSnapshot([
				{ scid, flags: 0x00 }, // direction 0, all defaults
				{ scid, flags: 0x41, cltv: 144 } // direction 1, cltv present
			]);

			const result = await apply(graph, snap);
			expect(result.version).to.equal(1);
			expect(result.channelsAdded).to.equal(1);
			expect(result.updatesApplied).to.equal(2);

			const scidBuf = encodeShortChannelId(
				decodeShortChannelId(Buffer.from(u64(scid)))
			);
			const ch = graph.getChannel(scidBuf);
			expect(ch, 'channel present in graph').to.exist;
			expect(ch!.nodeId1.equals(NODE_A)).to.be.true;
			expect(ch!.nodeId2.equals(NODE_B)).to.be.true;

			// Direction 0 used defaults.
			expect(ch!.update1).to.exist;
			expect(ch!.update1!.cltvExpiryDelta).to.equal(40);
			expect(ch!.update1!.feeBaseMsat).to.equal(1000);
			expect(ch!.update1!.htlcMaximumMsat).to.equal(100_000_000n);
			// Direction 1 overrode cltv only.
			expect(ch!.update2).to.exist;
			expect(ch!.update2!.cltvExpiryDelta).to.equal(144);
			expect(ch!.update2!.feeProportionalMillionths).to.equal(1);
		});

		it('makes the channel usable for pathfinding (both endpoints linked)', async () => {
			const graph = new NetworkGraph();
			await apply(
				graph,
				baseSnapshot([
					{ scid, flags: 0x00 },
					{ scid, flags: 0x01 }
				])
			);
			expect(graph.getNodeChannels(NODE_A).length).to.equal(1);
			expect(graph.getNodeChannels(NODE_B).length).to.equal(1);
			expect(graph.getChannelCount()).to.equal(1);
		});

		it('keeps snapshot entries unverified so gossip queries never serve them (issue #340)', async () => {
			// RGS strips signatures, so serving these would get us disconnected by
			// strict peers (BOLT 7: MUST NOT relay unvalidated announcements).
			const graph = new NetworkGraph();
			await apply(
				graph,
				baseSnapshot([
					{ scid, flags: 0x00 },
					{ scid, flags: 0x01 }
				])
			);
			const scidBuf = encodeShortChannelId(
				decodeShortChannelId(Buffer.from(u64(scid)))
			);
			expect(graph.getChannel(scidBuf)!.announcementVerified).to.not.be.true;
			expect(graph.getChannelsByBlockRange(800000, 1).length).to.equal(0);
			const served = graph.getGossipMessagesForChannels([scidBuf]);
			expect(served.announcements.length).to.equal(0);
			expect(served.updates.length).to.equal(0);
		});

		it('lets a real verified update replace an RGS slot despite the snapshot timestamp (issue #340)', async () => {
			// RGS stamps every synthetic update with the snapshot's global
			// latest-seen timestamp; the live signed update carries its true,
			// older timestamp and must still take the slot.
			const graph = new NetworkGraph();
			await apply(graph, baseSnapshot([{ scid, flags: 0x00 }]));
			const scidBuf = encodeShortChannelId(
				decodeShortChannelId(Buffer.from(u64(scid)))
			);
			const realUpdate = {
				signature: Buffer.alloc(64, 1),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scidBuf,
				timestamp: 1_700_000_000 - 3600,
				messageFlags: 0x01,
				channelFlags: 0,
				cltvExpiryDelta: 144,
				htlcMinimumMsat: 1n,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				htlcMaximumMsat: 1_000n
			};
			expect(graph.applyChannelUpdate(realUpdate, { verified: true })).to.be
				.true;
			const ch = graph.getChannel(scidBuf)!;
			expect(ch.update1Verified).to.be.true;
			expect(ch.update1!.timestamp).to.equal(1_700_000_000 - 3600);
		});

		it('applies all explicitly-present update fields', async () => {
			const graph = new NetworkGraph();
			// flags: dir0 + all five field bits (0x40|0x20|0x10|0x08|0x04) = 0x7C
			const snap = baseSnapshot([
				{
					scid,
					flags: 0x7c,
					cltv: 80,
					htlcMin: 2000n,
					feeBase: 500,
					feeProp: 10,
					htlcMax: 50_000_000n
				}
			]);
			await apply(graph, snap);
			const ch = graph.getChannel(
				encodeShortChannelId(decodeShortChannelId(Buffer.from(u64(scid))))
			)!;
			expect(ch.update1!.cltvExpiryDelta).to.equal(80);
			expect(ch.update1!.htlcMinimumMsat).to.equal(2000n);
			expect(ch.update1!.feeBaseMsat).to.equal(500);
			expect(ch.update1!.feeProportionalMillionths).to.equal(10);
			expect(ch.update1!.htlcMaximumMsat).to.equal(50_000_000n);
		});

		it('rejects a snapshot with a bad prefix', async () => {
			const snap = baseSnapshot([{ scid, flags: 0x00 }]);
			snap[0] = 0x00;
			const err = await rejection(apply(new NetworkGraph(), snap));
			expect(err.message).to.match(/bad prefix/);
		});

		it('rejects an unsupported version', async () => {
			const snap = buildV1Snapshot({
				version: 2,
				latestSeen: 1,
				nodes: [NODE_A, NODE_B],
				channels: [],
				defaults,
				updates: []
			});
			const err = await rejection(apply(new NetworkGraph(), snap));
			expect(err.message).to.match(/version 2/);
		});

		it('rejects a chain hash mismatch', async () => {
			const wrong = Buffer.alloc(32, 0x99);
			const snap = buildV1Snapshot({
				chainHash: wrong,
				latestSeen: 1,
				nodes: [NODE_A, NODE_B],
				channels: [],
				defaults,
				updates: []
			});
			const err = await rejection(apply(new NetworkGraph(), snap));
			expect(err.message).to.match(/chain hash/);
		});
	});
}

describe('Rapid Gossip Sync endpoint', () => {
	it('exposes the default public RGS endpoint', () => {
		expect(DEFAULT_RGS_URL).to.match(/^https:\/\//);
	});
});

describe('Rapid Gossip Sync download', () => {
	afterEach(() => sinon.restore());

	/** Answer https.get with a 200 carrying `body`, counting req.destroy calls. */
	function serve(body: Buffer[]): { destroys: number } {
		const seen = { destroys: 0 };
		sinon.stub(https, 'get').callsFake(((
			_url: string,
			onResponse: (res: PassThrough) => void
		) => {
			const req = Object.assign(new EventEmitter(), {
				setTimeout: () => req,
				destroy: () => {
					seen.destroys++;
				}
			});
			setImmediate(() => {
				const res = Object.assign(new PassThrough(), { statusCode: 200 });
				onResponse(res);
				for (const chunk of body) res.write(chunk);
				res.end();
			});
			return req;
		}) as unknown as typeof https.get);
		return seen;
	}

	it('refuses a body past the cap and drops the connection', async () => {
		// One shared half-cap chunk keeps the test from allocating the cap.
		const half = Buffer.alloc(MAX_RGS_SNAPSHOT_BYTES / 2);
		const seen = serve([half, half, half]);
		const err = await rejection(fetchRapidGossipSnapshot());
		expect(err.message).to.equal(
			`Rapid gossip sync snapshot exceeds ${MAX_RGS_SNAPSHOT_BYTES} bytes`
		);
		expect(seen.destroys).to.equal(1);
	});

	it('accepts a body of exactly the cap', async () => {
		const seen = serve([Buffer.from([1, 2]), Buffer.from([3, 4])]);
		const data = await fetchRapidGossipSnapshot(DEFAULT_RGS_URL, 60_000, 4);
		expect([...data]).to.deep.equal([1, 2, 3, 4]);
		expect(seen.destroys).to.equal(0);
	});
});

// ─────────────── Equivalence with the 0.27.0 parser ───────────────

interface IGraphInternals {
	_channels: Map<string, IGraphChannel>;
	_nodes: Map<string, IGraphNode>;
	_unverifiedChannels: Set<string>;
	_unfundedChannels: Set<string>;
}

/**
 * Everything a graph holds, in Map iteration order: each channel and node as
 * storage serializes it, every object's own keys in order (serialization
 * drops undefined values, the key lists do not), and the eviction indexes.
 */
function graphState(graph: NetworkGraph): string[] {
	const g = graph as unknown as IGraphInternals;
	const rows: string[] = [];
	for (const [key, ch] of g._channels) {
		const shape = [ch, ch.announcement, ch.update1, ch.update2].map((o) =>
			o ? Object.keys(o).join(',') : '-'
		);
		rows.push(
			`channel ${key} ${serializeGraphChannel(ch)} ${shape.join(' | ')}`
		);
	}
	for (const [key, node] of g._nodes) {
		rows.push(`node ${key} ${serializeGraphNode(node)}`);
	}
	rows.push(`unverified ${[...g._unverifiedChannels].join(',')}`);
	rows.push(`unfunded ${[...g._unfundedChannels].join(',')}`);
	return rows;
}

function expectSameState(
	actual: string[],
	expected: string[],
	label: string
): void {
	const n = Math.min(actual.length, expected.length);
	for (let i = 0; i < n; i++) {
		if (actual[i] !== expected[i]) {
			expect(actual[i], `${label}: row ${i}`).to.equal(expected[i]);
		}
	}
	expect(actual.length, `${label}: row count`).to.equal(expected.length);
}

type TOutcome = { result?: IRapidGossipResult; error?: string };

function describeError(err: unknown): string {
	if (!(err instanceof Error)) return String(err);
	const code = (err as { code?: string }).code;
	return `${err.name}${code ? ` [${code}]` : ''}: ${err.message}`;
}

function runSync(
	apply: (g: NetworkGraph, d: Buffer, c?: Buffer) => IRapidGossipResult,
	graph: NetworkGraph,
	data: Buffer,
	chainHash?: Buffer
): TOutcome {
	try {
		return { result: apply(graph, data, chainHash) };
	} catch (err) {
		return { error: describeError(err) };
	}
}

async function runAsync(
	graph: NetworkGraph,
	data: Buffer,
	sliceMs: number,
	chainHash?: Buffer
): Promise<TOutcome> {
	try {
		return {
			result: await applyRapidGossipSnapshotAsync(graph, data, {
				expectedChainHash: chainHash,
				sliceMs
			})
		};
	} catch (err) {
		return { error: describeError(err) };
	}
}

/** Three graphs fed alike: the oracle, the one-pass and the sliced import. */
class Trio {
	readonly oracle: NetworkGraph;
	readonly sync: NetworkGraph;
	readonly sliced: NetworkGraph;

	constructor(make: () => NetworkGraph) {
		this.oracle = make();
		this.sync = make();
		this.sliced = make();
	}

	/** Apply to all three; outcomes and graphs must match the oracle's. */
	async apply(
		data: Buffer,
		label: string,
		opts: { sliceMs?: number; chainHash?: Buffer } = {}
	): Promise<TOutcome> {
		const expected = runSync(
			applyRapidGossipSnapshotReference,
			this.oracle,
			data,
			opts.chainHash
		);
		const sync = runSync(
			applyRapidGossipSnapshot,
			this.sync,
			data,
			opts.chainHash
		);
		const sliced = await runAsync(
			this.sliced,
			data,
			opts.sliceMs ?? 0,
			opts.chainHash
		);
		expect(sync, `${label}: sync outcome`).to.deep.equal(expected);
		expect(sliced, `${label}: async outcome`).to.deep.equal(expected);
		const state = graphState(this.oracle);
		expectSameState(graphState(this.sync), state, `${label}: sync graph`);
		expectSameState(graphState(this.sliced), state, `${label}: async graph`);
		return expected;
	}
}

/** Signed gossip already held when a snapshot lands, built anew per graph. */
function seedSigned(
	graph: NetworkGraph,
	scids: bigint[],
	nodes: Buffer[],
	latestSeen: number
): void {
	scids.forEach((scid, i) => {
		const [a, b] = [nodes[i % nodes.length], nodes[(i + 1) % nodes.length]];
		const [nodeId1, nodeId2] = Buffer.compare(a, b) < 0 ? [a, b] : [b, a];
		const shortChannelId = u64(scid);
		const announcement: IChannelAnnouncementMessage = {
			nodeSignature1: Buffer.alloc(64, 1),
			nodeSignature2: Buffer.alloc(64, 2),
			bitcoinSignature1: Buffer.alloc(64, 3),
			bitcoinSignature2: Buffer.alloc(64, 4),
			features: Buffer.alloc(0),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId,
			nodeId1,
			nodeId2,
			bitcoinKey1: Buffer.alloc(33, 5),
			bitcoinKey2: Buffer.alloc(33, 6)
		};
		graph.addChannelAnnouncement(announcement, {
			verified: i % 3 === 0 ? 'deferred' : true
		});
		const update: IChannelUpdateMessage = {
			signature: Buffer.alloc(64, 7),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId,
			// Older than the snapshot (its update takes the slot) or newer
			// (the snapshot's is refused).
			timestamp: latestSeen + (i % 2 === 0 ? -300 : 300),
			messageFlags: 1,
			channelFlags: i % 4 < 2 ? 0 : 1,
			cltvExpiryDelta: 18,
			htlcMinimumMsat: 1n,
			feeBaseMsat: 1,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 10_000n
		};
		graph.applyChannelUpdate(update, { verified: true });
	});
}

describe('Rapid Gossip Sync import matches the 0.27.0 parser', function () {
	this.timeout(60_000);

	const savedCap = NetworkGraph.MAX_CHANNELS;
	afterEach(() => {
		NetworkGraph.MAX_CHANNELS = savedCap;
	});

	const now = Math.floor(Date.now() / 1000);
	const variants = [
		'a fresh graph',
		'signed gossip already held',
		'a channel ceiling that bites mid-import',
		'a second snapshot stamped far in the future',
		'a regtest graph'
	];

	for (let seed = 1; seed <= 20; seed++) {
		const variant = seed % variants.length;
		it(`seed ${seed}: a full then an incremental snapshot over ${variants[variant]}`, async () => {
			const rand = prng(seed);
			const { nodes, duplicates } = generateNodes(rand, 300);
			const regtest = variant === 4;
			const t1 = now - 7200;
			const t2 = variant === 3 ? now + 7200 : t1 + 600;
			const trio = new Trio(
				() =>
					new NetworkGraph(regtest ? REGTEST_CHAIN_HASH : BITCOIN_CHAIN_HASH)
			);

			// On regtest the first snapshot is a regtest one, checked against
			// its own chain hash; the second stays mainnet and is refused
			// channel by channel by the graph.
			const chainHash = regtest ? REGTEST_CHAIN_HASH : undefined;
			const full = generateSnapshot(rand, {
				latestSeen: t1,
				nodes,
				duplicates,
				channels: 2000,
				chainHash,
				updateTargets: (scids) => [...scids, ...unknownScids(rand, 60, scids)]
			});
			if (variant === 1) {
				const held = full.channelScids.filter((_, i) => i % 40 === 0);
				for (const g of [trio.oracle, trio.sync, trio.sliced]) {
					seedSigned(g, held, nodes, t1);
				}
			}
			if (variant === 2) NetworkGraph.MAX_CHANNELS = 1200;
			const first = await trio.apply(buildV1Snapshot(full.spec), 'full', {
				sliceMs: seed % 3,
				chainHash
			});
			expect(first.error, 'the full snapshot parses').to.equal(undefined);
			expect(first.result!.channelsAdded).to.be.greaterThan(0);
			expect(first.result!.updatesApplied).to.be.greaterThan(0);

			// The second snapshot repeats some channels, adds new ones, and
			// updates old and new; its incremental updates inherit from the
			// first snapshot's, which are older.
			const again = full.channelScids.filter(() => rand() < 0.2);
			const fresh = unknownScids(rand, 800, full.channelScids);
			const second = generateSnapshot(rand, {
				latestSeen: t2,
				nodes,
				duplicates,
				channels: 0,
				scids: [...again, ...fresh],
				updateTargets: (scids) => [
					...scids,
					...full.channelScids.filter(() => rand() < 0.5),
					...unknownScids(rand, 40, scids)
				]
			});
			const next = await trio.apply(buildV1Snapshot(second.spec), 'second', {
				sliceMs: (seed + 1) % 3
			});
			expect(next.error, 'the second snapshot parses').to.equal(undefined);
		});
	}

	it('a snapshot without updates carries no defaults and stops after the announcements', async () => {
		const rand = prng(99);
		const { nodes, duplicates } = generateNodes(rand, 50);
		const snap = generateSnapshot(rand, {
			latestSeen: now - 60,
			nodes,
			duplicates,
			channels: 200,
			updateTargets: () => []
		});
		const trio = new Trio(() => new NetworkGraph());
		const out = await trio.apply(buildV1Snapshot(snap.spec), 'no updates');
		expect(out.result!.updatesApplied).to.equal(0);
		// Trailing bytes after a zero update count are ignored, as before.
		await trio.apply(
			Buffer.concat([buildV1Snapshot(snap.spec), Buffer.from([0xff, 1, 2])]),
			'no updates, trailing bytes'
		);
	});
});

// ─────────────── Truncated and corrupted snapshots ───────────────

/**
 * A small snapshot with one of everything: each BigSize width, a carry and
 * a 2^64 wrap in both sections, features, swapped, equal, duplicate and
 * out-of-range node indices, bit 63 on node 2, a duplicate SCID, updates
 * with every optional field, incremental ones, one for an unknown SCID, and
 * a last one whose fields run to the final byte.
 */
function sampleSnapshot(latestSeen: number): Buffer {
	const node = (fill: number, prefix = 0x02): Buffer =>
		Buffer.concat([Buffer.from([prefix]), Buffer.alloc(32, fill)]);
	const nodes = [node(0x11), node(0x22, 0x03), node(0x33), node(0x22, 0x03)];
	const s1 = 5n;
	const s2 = s1 + 0x1234n; // 0xfd
	const s3 = s2 + 0x12345678n; // 0xfe
	const s4 = s3 + (800_000n << 40n); // 0xff
	const s5 = s4 + (TWO_32 - (s4 % TWO_32)) + 7n; // the low half carries
	const s6 = s5; // duplicate SCID
	const s7 = s6 + 3n;
	const s8 = s7 + 0x10000n;
	const s9 = s8 + (TWO_64 - (s8 % TWO_64)) + 3n; // wraps to 3
	const s10 = s9 + TWO_32 + 1n;
	const s11 = s10 + 1n;
	const channels = [
		{ scid: s1, n1: 0, n2: 1, features: Buffer.from([0x01, 0x02]) },
		{ scid: s2, n1: 1, n2: 0 }, // swapped
		{ scid: s3, n1: 2, n2: 2 }, // the same node twice
		{ scid: s4, n1: 0, n2: 2 },
		{ scid: s5, n1: 2, n2: 1 },
		{ scid: s6, n1: 0, n2: 1 }, // duplicate SCID
		{ scid: s7, n1: 1, n2: 3 }, // identical ids at two indices
		{ scid: s8, n1: 2, n2: TWO_63 + 1n, features: Buffer.from([0xff]) },
		{ scid: s9, n1: 0, n2: 1 },
		{ scid: s10, n1: TWO_32, n2: 0 }, // high half set
		{ scid: s11, n1: 0x1ff, n2: 1 } // past the table, 3-byte index
	];
	const fields = {
		cltv: 300,
		htlcMin: TWO_32 + 9n,
		feeBase: 0xffffffff,
		feeProp: 77,
		htlcMax: 123_456n
	};
	const updates: IUpdate[] = [
		{ scid: s1, flags: 0x00 },
		{ scid: s1, flags: 0x41, ...fields },
		{ scid: s1, flags: 0x90, ...fields }, // incremental over a held slot
		{ scid: s2, flags: 0x7c, ...fields },
		{ scid: s2, flags: 0x85, ...fields }, // incremental, direction 1
		{ scid: s4, flags: 0xa0, ...fields }, // incremental over an empty slot
		{ scid: s4, flags: 0x03 },
		{ scid: s5, flags: 0x10, ...fields },
		{ scid: s5 + 1n, flags: 0x48, ...fields }, // unknown SCID
		{ scid: s8, flags: 0xc1, ...fields },
		{ scid: s9, flags: 0x20, ...fields }, // past 2^64 again
		{ scid: s10, flags: 0xff, ...fields }
	];
	return buildV1Snapshot({
		latestSeen,
		nodes,
		channels,
		defaults: {
			cltv: 40,
			htlcMin: 1000n,
			feeBase: 1000,
			feeProp: 1,
			htlcMax: TWO_32 * 3n
		},
		updates
	});
}

describe('Rapid Gossip Sync import fails like the 0.27.0 parser', function () {
	this.timeout(120_000);
	const latestSeen = Math.floor(Date.now() / 1000) - 3600;
	const sample = sampleSnapshot(latestSeen);

	it('the sample snapshot parses and exercises the graph', async () => {
		const trio = new Trio(() => new NetworkGraph());
		const out = await trio.apply(sample, 'sample');
		expect(out.result!.channelsAdded).to.equal(6);
		expect(out.result!.updatesApplied).to.equal(9);
	});

	it('cut at every byte: the same error and the same partial graph', async () => {
		for (let cut = 0; cut < sample.length; cut++) {
			const trio = new Trio(() => new NetworkGraph());
			await trio.apply(sample.subarray(0, cut), `cut at ${cut}`, {
				sliceMs: cut % 2
			});
		}
	});

	it('corrupt any byte but the node count: the same outcome', async () => {
		// The node count (bytes 40 to 43) is left alone: a huge count makes
		// the 0.27.0 parser walk billions of table entries.
		for (let p = 0; p < sample.length; p++) {
			if (p >= 40 && p <= 43) continue;
			for (const value of [0x00, 0xfd, 0xfe, 0xff, sample[p] ^ 0x80]) {
				if (value === sample[p]) continue;
				const data = Buffer.from(sample);
				data[p] = value;
				const trio = new Trio(() => new NetworkGraph());
				await trio.apply(data, `byte ${p} = ${value}`);
			}
		}
	});
});

// ─────────────── The cooperative driver ───────────────

describe('Rapid Gossip Sync cooperative import', function () {
	this.timeout(30_000);
	const now = Math.floor(Date.now() / 1000);

	function bigSnapshot(seed: number): { data: Buffer; entries: number } {
		const rand = prng(seed);
		const { nodes, duplicates } = generateNodes(rand, 200);
		const { spec } = generateSnapshot(rand, {
			latestSeen: now - 60,
			nodes,
			duplicates,
			channels: 1500
		});
		return {
			data: buildV1Snapshot(spec),
			entries: spec.channels.length + spec.updates.length
		};
	}

	it('with sliceMs 0 yields to the event loop after every step', async () => {
		const { data, entries } = bigSnapshot(31);
		let slices = 0;
		let ticks = 0;
		let ticking = true;
		const tick = (): void => {
			if (!ticking) return;
			ticks++;
			setImmediate(tick);
		};
		setImmediate(tick);
		await applyRapidGossipSnapshotAsync(new NetworkGraph(), data, {
			sliceMs: 0,
			onSlice: () => slices++
		});
		ticking = false;
		// One step of 32 entries per slice, and the loop turned between them.
		expect(slices).to.equal(Math.ceil(entries / 32));
		expect(ticks).to.be.at.least(slices - 2);
	});

	it('reports every slice through onSlice, and their time adds up', async () => {
		const { data } = bigSnapshot(32);
		const times: number[] = [];
		const start = Date.now();
		const result = await applyRapidGossipSnapshotAsync(
			new NetworkGraph(),
			data,
			{
				sliceMs: 2,
				onSlice: (ms) => times.push(ms)
			}
		);
		const wall = Date.now() - start;
		expect(result.channelsAdded).to.be.greaterThan(0);
		expect(times.length).to.be.at.least(1);
		for (const ms of times) expect(ms).to.be.at.least(0);
		expect(times.reduce((a, b) => a + b, 0)).to.be.at.most(wall);
	});

	it('cancelled stops the import with RapidGossipCancelledError and changes nothing more', async () => {
		const { data } = bigSnapshot(33);
		const graph = new NetworkGraph();
		let slices = 0;
		const err = await rejection(
			applyRapidGossipSnapshotAsync(graph, data, {
				sliceMs: 0,
				onSlice: () => slices++,
				cancelled: () => slices >= 3
			})
		);
		expect(err).to.be.instanceOf(RapidGossipCancelledError);
		expect(err.name).to.equal('RapidGossipCancelledError');
		expect(slices).to.equal(3);
		// Three steps of 32 announcements, some refused.
		expect(graph.getChannelCount()).to.be.within(1, 3 * 32);
		const atCancel = graphState(graph);
		for (let i = 0; i < 5; i++) {
			await new Promise<void>((resolve) => setImmediate(resolve));
		}
		await new Promise<void>((resolve) => setTimeout(resolve, 20));
		expectSameState(graphState(graph), atCancel, 'after cancel');
		expect(slices).to.equal(3);
	});

	it('cancelled before the first slice touches nothing, not even the header', async () => {
		const graph = new NetworkGraph();
		let slices = 0;
		const err = await rejection(
			applyRapidGossipSnapshotAsync(graph, Buffer.from('not a snapshot'), {
				onSlice: () => slices++,
				cancelled: () => true
			})
		);
		expect(err).to.be.instanceOf(RapidGossipCancelledError);
		expect(slices).to.equal(0);
		expect(graph.getChannelCount()).to.equal(0);
	});
});

// ─────────────── NetworkGraph entry points for the importer ───────────────

describe('NetworkGraph Rapid Gossip Sync entry points', () => {
	const savedCap = NetworkGraph.MAX_CHANNELS;
	afterEach(() => {
		NetworkGraph.MAX_CHANNELS = savedCap;
	});

	const node = (fill: number): Buffer =>
		Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, fill)]);

	/** An announcement shaped like the importer's: zero signatures and keys. */
	function rgsAnnouncement(
		scid: bigint,
		nodeId1: Buffer,
		nodeId2: Buffer,
		chainHash = BITCOIN_CHAIN_HASH
	): IChannelAnnouncementMessage {
		return {
			nodeSignature1: Buffer.alloc(64),
			nodeSignature2: Buffer.alloc(64),
			bitcoinSignature1: Buffer.alloc(64),
			bitcoinSignature2: Buffer.alloc(64),
			features: Buffer.alloc(0),
			chainHash,
			shortChannelId: u64(scid),
			nodeId1,
			nodeId2,
			bitcoinKey1: Buffer.alloc(33),
			bitcoinKey2: Buffer.alloc(33)
		};
	}

	function rgsUpdate(
		scid: bigint,
		timestamp: number,
		direction: number,
		signature = Buffer.alloc(64)
	): IChannelUpdateMessage {
		return {
			signature,
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: u64(scid),
			timestamp,
			messageFlags: 1,
			channelFlags: direction,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 5_000_000n
		};
	}

	const keysOf = (
		msg: IChannelAnnouncementMessage
	): { scidHex: string; node1Hex: string; node2Hex: string } => ({
		scidHex: msg.shortChannelId.toString('hex'),
		node1Hex: msg.nodeId1.toString('hex'),
		node2Hex: msg.nodeId2.toString('hex')
	});

	it('admits exactly what addChannelAnnouncement admits unverified, into the same state', () => {
		NetworkGraph.MAX_CHANNELS = 5;
		const viaPublic = new NetworkGraph();
		const viaRgs = new NetworkGraph();
		const [a, b, c, d] = [node(1), node(2), node(3), node(4)];
		const messages = [
			rgsAnnouncement(10n, a, b),
			rgsAnnouncement(11n, b, c),
			rgsAnnouncement(10n, a, b), // duplicate SCID
			rgsAnnouncement(12n, c, b), // disordered
			rgsAnnouncement(13n, c, c), // the same node twice
			rgsAnnouncement(14n, a, d, REGTEST_CHAIN_HASH), // another chain
			rgsAnnouncement(15n, a, c),
			rgsAnnouncement(16n, b, d),
			rgsAnnouncement(17n, c, d),
			rgsAnnouncement(18n, a, d) // over the ceiling
		];
		for (const msg of messages) {
			expect(viaRgs.addRapidGossipChannel(msg, keysOf(msg))).to.equal(
				viaPublic.addChannelAnnouncement({ ...msg })
			);
		}
		expect(viaRgs.getChannelCount()).to.equal(5);
		expectSameState(graphState(viaRgs), graphState(viaPublic), 'admission');
	});

	it('at the ceiling refuses and evicts nothing, while a verified admission still evicts an RGS entry', () => {
		NetworkGraph.MAX_CHANNELS = 2;
		const evicted: string[] = [];
		const graph = new NetworkGraph(BITCOIN_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		const [a, b, c] = [node(1), node(2), node(3)];
		for (const scid of [1n, 2n]) {
			const msg = rgsAnnouncement(scid, a, b);
			expect(graph.addRapidGossipChannel(msg, keysOf(msg))).to.equal(true);
		}
		const third = rgsAnnouncement(3n, b, c);
		expect(graph.addRapidGossipChannel(third, keysOf(third))).to.equal(false);
		expect(graph.getChannelCount()).to.equal(2);
		expect(evicted).to.deep.equal([]);

		const signed = {
			...rgsAnnouncement(4n, a, c),
			nodeSignature1: Buffer.alloc(64, 9)
		};
		expect(graph.addChannelAnnouncement(signed, { verified: true })).to.equal(
			true
		);
		expect(evicted).to.deep.equal([u64(1n).toString('hex')]);
		expect(graph.getChannel(u64(4n))!.announcementVerified).to.equal(true);
	});

	it('never upgrades an entry, while a verified announcement still upgrades an RGS slot', () => {
		const graph = new NetworkGraph();
		const [a, b] = [node(1), node(2)];
		const rgs = rgsAnnouncement(7n, a, b);
		expect(graph.addRapidGossipChannel(rgs, keysOf(rgs))).to.equal(true);
		const internals = graph as unknown as IGraphInternals;
		expect([...internals._unverifiedChannels]).to.deep.equal([
			u64(7n).toString('hex')
		]);

		const signed = {
			...rgsAnnouncement(7n, a, b),
			nodeSignature1: Buffer.alloc(64, 9)
		};
		expect(graph.addChannelAnnouncement(signed, { verified: true })).to.equal(
			true
		);
		const ch = graph.getChannel(u64(7n))!;
		expect(ch.announcement).to.equal(signed);
		expect(ch.announcementVerified).to.equal(true);
		expect([...internals._unverifiedChannels]).to.deep.equal([]);
		expect([...internals._unfundedChannels]).to.deep.equal([
			u64(7n).toString('hex')
		]);

		// An RGS entry for a held SCID changes nothing.
		const before = graphState(graph);
		const again = rgsAnnouncement(7n, a, b);
		expect(graph.addRapidGossipChannel(again, keysOf(again))).to.equal(false);
		expectSameState(graphState(graph), before, 'held SCID');
	});

	it('stores the importer buffers without copies; addChannelAnnouncement still copies', () => {
		const graph = new NetworkGraph();
		const [a, b, c] = [node(1), node(2), node(3)];
		const first = rgsAnnouncement(1n, a, b);
		const second = rgsAnnouncement(2n, a, c);
		graph.addRapidGossipChannel(first, keysOf(first));
		graph.addRapidGossipChannel(second, keysOf(second));
		const ch = graph.getChannel(u64(1n))!;
		expect(ch.shortChannelId).to.equal(first.shortChannelId);
		expect(ch.nodeId1).to.equal(a);
		expect(ch.features).to.equal(first.features);
		// One buffer per node, shared by the node entry and its channels.
		expect(graph.getNode(a)!.nodeId).to.equal(a);
		expect(graph.getChannel(u64(2n))!.nodeId1).to.equal(a);

		const copied = rgsAnnouncement(3n, b, c);
		graph.addChannelAnnouncement(copied);
		const held = graph.getChannel(u64(3n))!;
		expect(held.shortChannelId).to.not.equal(copied.shortChannelId);
		expect(held.shortChannelId.equals(copied.shortChannelId)).to.equal(true);
	});

	it('builds entries in the order the 0.27.0 graph did (rows are serialized as built)', () => {
		// The oracle runs on the same graph code, so the shared admission
		// and update helpers are pinned here directly.
		const graph = new NetworkGraph();
		const [x, y, z] = [node(1), node(2), node(3)];
		const first = rgsAnnouncement(5n, y, z);
		const second = rgsAnnouncement(6n, x, z);
		graph.addRapidGossipChannel(first, keysOf(first));
		graph.addRapidGossipChannel(second, keysOf(second));
		const now = Math.floor(Date.now() / 1000);
		graph.applyRapidGossipUpdate(
			rgsUpdate(5n, now - 10, 1),
			u64(5n).toString('hex')
		);
		graph.applyRapidGossipUpdate(
			rgsUpdate(5n, now - 10, 0),
			u64(5n).toString('hex')
		);

		const internals = graph as unknown as IGraphInternals;
		const hex = (b: Buffer): string => b.toString('hex');
		expect([...internals._nodes.keys()]).to.deep.equal([y, z, x].map(hex));
		expect([...graph.getNode(z)!.channels]).to.deep.equal(
			[u64(5n), u64(6n)].map(hex)
		);
		expect([...internals._unverifiedChannels]).to.deep.equal(
			[u64(5n), u64(6n)].map(hex)
		);
		expect(Object.keys(graph.getChannel(u64(5n))!)).to.deep.equal([
			'shortChannelId',
			'nodeId1',
			'nodeId2',
			'features',
			'announcement',
			'announcementVerified',
			'announcementVerifyDeferred',
			'update2',
			'update2Verified',
			'update2VerifyDeferred',
			'update1',
			'update1Verified',
			'update1VerifyDeferred'
		]);
		expect(Object.keys(graph.getNode(y)!)).to.deep.equal([
			'nodeId',
			'channels'
		]);
	});

	it('applies updates exactly as applyChannelUpdate does for an unverified update', () => {
		const now = Math.floor(Date.now() / 1000);
		const viaPublic = new NetworkGraph();
		const viaRgs = new NetworkGraph();
		const [a, b] = [node(1), node(2)];
		for (const g of [viaPublic, viaRgs]) {
			g.addChannelAnnouncement(rgsAnnouncement(1n, a, b));
			g.addChannelAnnouncement(rgsAnnouncement(2n, a, b));
			// A verified slot an unverified update replaces only when newer.
			g.applyChannelUpdate(rgsUpdate(2n, now - 100, 1, Buffer.alloc(64, 5)), {
				verified: true
			});
		}
		const updates = [
			rgsUpdate(1n, now - 50, 0),
			rgsUpdate(1n, now - 50, 0), // not newer
			rgsUpdate(1n, now - 60, 0), // older
			rgsUpdate(1n, now - 40, 0), // newer
			rgsUpdate(1n, now - 50, 1),
			rgsUpdate(9n, now - 50, 0), // unknown SCID
			rgsUpdate(1n, now + 7200, 1), // far in the future
			rgsUpdate(2n, now - 200, 1), // older than the verified slot
			rgsUpdate(2n, now - 100, 1), // as old as the verified slot
			rgsUpdate(2n, now - 10, 1) // newer than the verified slot
		];
		for (const msg of updates) {
			expect(
				viaRgs.applyRapidGossipUpdate(msg, msg.shortChannelId.toString('hex'))
			).to.equal(viaPublic.applyChannelUpdate({ ...msg }));
		}
		expectSameState(graphState(viaRgs), graphState(viaPublic), 'updates');
	});
});
