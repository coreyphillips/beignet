/**
 * Rapid Gossip Sync v1 snapshot builders for tests: buildV1Snapshot writes
 * the wire format from absolute values, and generateSnapshot draws seeded,
 * deterministic snapshots that cover every shape the parser has to handle
 * (each BigSize width, carries and 2^64 wraps of the running SCID, bit 63
 * of node 2's index, out-of-range and equal node indices, swapped and
 * duplicate node ids, features, duplicate SCIDs, every update flag byte,
 * and updates for SCIDs no announcement names).
 */

import { encodeBigSize } from '../../../src/lightning/message/codec';
import { BITCOIN_CHAIN_HASH } from '../../../src/lightning/channel/types';

export interface IUpdate {
	scid: bigint;
	flags: number;
	cltv?: number;
	htlcMin?: bigint;
	feeBase?: number;
	feeProp?: number;
	htlcMax?: bigint;
}

export interface IChannelEntry {
	scid: bigint;
	n1: number | bigint;
	n2: number | bigint;
	features?: Buffer;
}

export interface ISnapshotSpec {
	version?: number;
	chainHash?: Buffer;
	latestSeen: number;
	nodes: Buffer[];
	channels: IChannelEntry[];
	defaults: {
		cltv: number;
		htlcMin: bigint;
		feeBase: number;
		feeProp: number;
		htlcMax: bigint;
	};
	updates: IUpdate[];
}

export function u16(n: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n);
	return b;
}
export function u32(n: number): Buffer {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n);
	return b;
}
export function u64(n: bigint): Buffer {
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(n);
	return b;
}

/**
 * Encode a v1 snapshot. SCIDs are absolute and may exceed 2^64: the wire
 * carries each one as its delta from the previous entry (which must lie in
 * [0, 2^64)), and the parser's running sum wraps mod 2^64.
 */
export function buildV1Snapshot(opts: ISnapshotSpec): Buffer {
	const parts: Buffer[] = [];
	parts.push(Buffer.from([0x4c, 0x44, 0x4b, opts.version ?? 1]));
	parts.push(opts.chainHash ?? BITCOIN_CHAIN_HASH);
	parts.push(u32(opts.latestSeen));
	parts.push(u32(opts.nodes.length));
	for (const n of opts.nodes) parts.push(n);

	parts.push(u32(opts.channels.length));
	let prevScid = 0n;
	for (const ch of opts.channels) {
		const features = ch.features ?? Buffer.alloc(0);
		parts.push(u16(features.length));
		parts.push(features);
		parts.push(encodeBigSize(ch.scid - prevScid));
		prevScid = ch.scid;
		parts.push(encodeBigSize(BigInt(ch.n1)));
		parts.push(encodeBigSize(BigInt(ch.n2)));
	}

	// Update count comes BEFORE the defaults; defaults present only if count > 0.
	parts.push(u32(opts.updates.length));
	if (opts.updates.length > 0) {
		parts.push(u16(opts.defaults.cltv));
		parts.push(u64(opts.defaults.htlcMin));
		parts.push(u32(opts.defaults.feeBase));
		parts.push(u32(opts.defaults.feeProp));
		parts.push(u64(opts.defaults.htlcMax));
	}

	let prevU = 0n;
	for (const up of opts.updates) {
		parts.push(encodeBigSize(up.scid - prevU));
		prevU = up.scid;
		parts.push(Buffer.from([up.flags]));
		if (up.flags & 0x40) parts.push(u16(up.cltv!));
		if (up.flags & 0x20) parts.push(u64(up.htlcMin!));
		if (up.flags & 0x10) parts.push(u32(up.feeBase!));
		if (up.flags & 0x08) parts.push(u32(up.feeProp!));
		if (up.flags & 0x04) parts.push(u64(up.htlcMax!));
	}
	return Buffer.concat(parts);
}

export const TWO_32 = 1n << 32n;
export const TWO_63 = 1n << 63n;
export const TWO_64 = 1n << 64n;

/** mulberry32: a small deterministic PRNG, so every seed replays exactly. */
export function prng(seed: number): () => number {
	let a = seed >>> 0;
	return (): number => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

const below = (rand: () => number, n: number): number => Math.floor(rand() * n);

const randomU64 = (rand: () => number): bigint =>
	(BigInt(below(rand, 2 ** 32)) << 32n) + BigInt(below(rand, 2 ** 32));

function randomBytes(rand: () => number, length: number): Buffer {
	const out = Buffer.alloc(length);
	for (let i = 0; i < length; i++) out[i] = below(rand, 256);
	return out;
}

/**
 * A node table with a few duplicated ids: two indices naming identical
 * bytes cannot form a channel (BOLT 7 wants nodeId1 < nodeId2).
 */
export function generateNodes(
	rand: () => number,
	count: number
): { nodes: Buffer[]; duplicates: Array<[number, number]> } {
	const nodes: Buffer[] = [];
	const duplicates: Array<[number, number]> = [];
	for (let i = 0; i < count; i++) {
		if (i > 0 && rand() < 0.02) {
			const j = below(rand, i);
			nodes.push(Buffer.from(nodes[j]));
			duplicates.push([j, i]);
		} else {
			const id = randomBytes(rand, 33);
			id[0] = rand() < 0.5 ? 0x02 : 0x03;
			nodes.push(id);
		}
	}
	return { nodes, duplicates };
}

/** One SCID delta, drawn so every BigSize width, carry and wrap occurs. */
function scidDelta(rand: () => number, current: bigint): bigint {
	const r = rand();
	const low = current % TWO_32;
	const mod = current % TWO_64;
	if (r < 0.04) return 0n; // the previous SCID again
	if (r < 0.18) return BigInt(1 + below(rand, 0xfc)); // one byte
	if (r < 0.28) return BigInt(0xfd + below(rand, 0x10000 - 0xfd)); // 0xfd
	if (r < 0.42) return BigInt(0x10000 + below(rand, 2 ** 32 - 0x10000)); // 0xfe
	if (r < 0.5 && low > 0n) {
		// The low half overflows into the high half, alone or with a high
		// half of its own.
		const carry = TWO_32 - low + BigInt(below(rand, Number(low)));
		return rand() < 0.5
			? carry
			: (BigInt(1 + below(rand, 1000)) << 32n) + carry;
	}
	if (r < 0.53 && mod > 0n) {
		// Past 2^64: the running SCID wraps to a small value.
		return TWO_64 - mod + BigInt(below(rand, Math.min(1000, Number(mod))));
	}
	if (r < 0.54) return TWO_64 - 1n; // the largest BigSize: one step back
	// 0xff, the mainnet shape: block heights in the top 24 bits.
	return (BigInt(1 + below(rand, 3000)) << 40n) + BigInt(below(rand, 2 ** 32));
}

/** A node index, mostly valid, sometimes out of range in each way. */
function nodeIndex(rand: () => number, nodeCount: number): bigint {
	const r = rand();
	const valid = BigInt(below(rand, nodeCount));
	if (r < 0.86) return valid;
	if (r < 0.89) return BigInt(nodeCount + below(rand, 4)); // past the table
	if (r < 0.92) return TWO_32 + valid; // low half in range, high half set
	if (r < 0.95) return TWO_63 + valid; // bit 63: cleared for node 2 only
	if (r < 0.97) return TWO_63 + TWO_32 + valid; // bit 63 and a high bit
	return TWO_64 - 1n;
}

function nodePair(
	rand: () => number,
	nodeCount: number,
	duplicates: Array<[number, number]>
): [bigint, bigint] {
	const r = rand();
	if (r < 0.03) {
		const i = BigInt(below(rand, nodeCount));
		return [i, i];
	}
	if (r < 0.05 && duplicates.length > 0) {
		const [i, j] = duplicates[below(rand, duplicates.length)];
		return rand() < 0.5 ? [BigInt(i), BigInt(j)] : [BigInt(j), BigInt(i)];
	}
	return [nodeIndex(rand, nodeCount), nodeIndex(rand, nodeCount)];
}

function updateFor(rand: () => number, scid: bigint, flags: number): IUpdate {
	return {
		scid,
		flags,
		cltv: below(rand, 0x10000),
		htlcMin: rand() < 0.7 ? BigInt(below(rand, 2 ** 32)) : randomU64(rand),
		feeBase: below(rand, 2 ** 32),
		feeProp: below(rand, 2 ** 32),
		htlcMax: rand() < 0.5 ? BigInt(below(rand, 2 ** 32)) : randomU64(rand)
	};
}

/**
 * Channels and updates for one snapshot. Channel SCIDs follow drawn
 * deltas, or, with `scids`, are those values in ascending order. Updates
 * target the given SCIDs (each mod 2^64) in ascending order, one to three
 * per SCID with flag bytes cycling through all 256 values first, then wrap
 * past 2^64 once more to revisit some of them.
 */
export function generateSnapshot(
	rand: () => number,
	opts: {
		latestSeen: number;
		nodes: Buffer[];
		duplicates: Array<[number, number]>;
		channels: number;
		scids?: bigint[];
		updateTargets?: (channelScids: bigint[]) => bigint[];
		chainHash?: Buffer;
	}
): { spec: ISnapshotSpec; channelScids: bigint[] } {
	const nodeCount = opts.nodes.length;
	const channels: IChannelEntry[] = [];
	const channelScids: bigint[] = [];
	let current = 0n;
	const fixed = opts.scids ? [...opts.scids].sort(compareBigInt) : undefined;
	const count = fixed ? fixed.length : opts.channels;
	for (let i = 0; i < count; i++) {
		current = fixed ? fixed[i] : current + scidDelta(rand, current);
		const [n1, n2] = nodePair(rand, nodeCount, opts.duplicates);
		channels.push({
			scid: current,
			n1,
			n2,
			features: rand() < 0.1 ? randomBytes(rand, 1 + below(rand, 8)) : undefined
		});
		channelScids.push(current % TWO_64);
	}

	const targets = (opts.updateTargets ?? ((s): bigint[] => s))(channelScids)
		.map((s) => s % TWO_64)
		.sort(compareBigInt);
	const updates: IUpdate[] = [];
	let flagCursor = 0;
	const nextFlags = (): number =>
		flagCursor < 256 ? flagCursor++ : below(rand, 256);
	const emit = (scid: bigint): void => {
		const r = rand();
		const n = r < 0.75 ? 2 : r < 0.9 ? 1 : 3;
		for (let k = 0; k < n; k++)
			updates.push(updateFor(rand, scid, nextFlags()));
	};
	for (const scid of targets) emit(scid);
	// Wrap past 2^64 and revisit some SCIDs below the last one.
	const last = targets.length > 0 ? targets[targets.length - 1] : 0n;
	for (const scid of targets.filter((s) => s < last && rand() < 0.05)) {
		emit(scid + TWO_64);
	}

	return {
		spec: {
			chainHash: opts.chainHash,
			latestSeen: opts.latestSeen,
			nodes: opts.nodes,
			channels,
			defaults: {
				cltv: below(rand, 0x10000),
				htlcMin: randomU64(rand),
				feeBase: below(rand, 2 ** 32),
				feeProp: below(rand, 2 ** 32),
				htlcMax: randomU64(rand)
			},
			updates
		},
		channelScids
	};
}

/** Draw `count` distinct values not in `taken`, for SCIDs no channel holds. */
export function unknownScids(
	rand: () => number,
	count: number,
	taken: bigint[]
): bigint[] {
	const seen = new Set(taken);
	const out: bigint[] = [];
	while (out.length < count) {
		const s = randomU64(rand);
		if (!seen.has(s)) {
			seen.add(s);
			out.push(s);
		}
	}
	return out;
}

export function compareBigInt(a: bigint, b: bigint): number {
	return a < b ? -1 : a > b ? 1 : 0;
}
