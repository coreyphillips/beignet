/**
 * Rapid Gossip Sync (RGS): LDK-compatible compact graph snapshot.
 *
 * Instead of crawling the p2p gossip network (slow, heavy, and unreliable from
 * arbitrary peers), a node can download a compact, signature-stripped snapshot
 * of the public channel graph over HTTPS and apply it directly. This is how
 * lightweight nodes obtain the full graph needed for multi-hop routing.
 *
 * This implements the LDK Rapid Gossip Sync **version 1** binary format
 * (served by e.g. https://rapidsync.lightningdevkit.org/snapshot/0). The
 * snapshot is trusted (signatures are omitted), so it must come from a source
 * you trust.
 *
 * Wire format (all multi-byte integers big-endian unless noted):
 *   "LDK" (3 bytes) | version (u8=1) | chain_hash (32) | latest_seen (u32)
 *   node_count (u32) | node_ids (33 bytes each)
 *   announcement_count (u32) | per announcement:
 *       features_len (u16) | features (bytes)
 *       scid_delta (BigSize) | node1_index (BigSize) | node2_index (BigSize)
 *   update_count (u32), then only when update_count > 0:
 *   default: cltv_expiry_delta (u16) htlc_minimum_msat (u64) fee_base_msat (u32)
 *            fee_proportional_millionths (u32) htlc_maximum_msat (u64)
 *   per update:
 *       scid_delta (BigSize) | flags (u8)
 *       [flags&0x40] cltv_expiry_delta (u16)
 *       [flags&0x20] htlc_minimum_msat (u64)
 *       [flags&0x10] fee_base_msat (u32)
 *       [flags&0x08] fee_proportional_millionths (u32)
 *       [flags&0x04] htlc_maximum_msat (u64)
 *     flags bit0 = direction, bit1 = disable, bit7 = incremental.
 *
 * A full mainnet snapshot is tens of thousands of channels and twice as many
 * updates. Applied in one synchronous pass it holds the event loop for
 * seconds on a phone's JS thread, so applyRapidGossipSnapshotAsync applies
 * it in time slices with the same result as the one-pass
 * applyRapidGossipSnapshot.
 */

import * as https from 'https';
import { readBigSizeParts } from '../message/codec';
import { NetworkGraph } from './network-graph';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	CHANNEL_FLAG_DIRECTION,
	CHANNEL_FLAG_DISABLED,
	MESSAGE_FLAG_HTLC_MAX
} from './types';
import { BITCOIN_CHAIN_HASH } from '../channel/types';

/** "LDK" prefix that begins every RGS snapshot. */
const RGS_PREFIX = Buffer.from([0x4c, 0x44, 0x4b]);

const EMPTY_SIG = Buffer.alloc(64);
const EMPTY_KEY = Buffer.alloc(33);
// Shared by every featureless announcement (graph buffers are never written
// in place, see network-graph.ts).
const EMPTY_FEATURES = Buffer.alloc(0);

/** Default time slice of applyRapidGossipSnapshotAsync, in milliseconds. */
const DEFAULT_SLICE_MS = 8;
/** Entries applied between clock reads inside one slice. */
const ENTRIES_PER_STEP = 32;

const PHASE_ANNOUNCEMENTS = 0;
const PHASE_UPDATES = 1;
const PHASE_DONE = 2;

export interface IRapidGossipResult {
	version: number;
	latestSeen: number;
	nodeCount: number;
	channelsAdded: number;
	updatesApplied: number;
}

export interface IRapidGossipApplyOptions {
	/** Chain the snapshot must be for (default mainnet). */
	expectedChainHash?: Buffer;
	/** Work per slice before yielding to the event loop, in milliseconds. */
	sliceMs?: number;
	/**
	 * Polled before the first slice and between slices; once it returns true
	 * the import stops with RapidGossipCancelledError and changes nothing
	 * more. Entries applied before that stay in the graph.
	 */
	cancelled?: () => boolean;
	/** Called after every slice with the milliseconds it took. */
	onSlice?: (ms: number) => void;
}

/** A cooperative import stopped by its cancelled() check. */
export class RapidGossipCancelledError extends Error {
	constructor() {
		super('Rapid gossip sync import cancelled');
		this.name = 'RapidGossipCancelledError';
	}
}

/** Big-endian u32 at an offset the caller has already bounds-checked. */
function readU32Unchecked(data: Buffer, off: number): number {
	return (
		data[off] * 0x1000000 +
		((data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3])
	);
}

// The field readers below take the inline path when the bytes are there and
// otherwise defer to the Buffer method, which throws the exact error the
// one-pass parser always threw for a truncated snapshot.

function readU16(data: Buffer, off: number): number {
	return off + 2 <= data.length
		? (data[off] << 8) | data[off + 1]
		: data.readUInt16BE(off);
}

function readU32(data: Buffer, off: number): number {
	return off + 4 <= data.length
		? readU32Unchecked(data, off)
		: data.readUInt32BE(off);
}

/** A u64 field as a bigint; one BigInt allocation when it fits in 32 bits. */
function readU64(data: Buffer, off: number): bigint {
	if (off + 8 > data.length) return data.readBigUInt64BE(off);
	const hi = readU32Unchecked(data, off);
	const lo = readU32Unchecked(data, off + 4);
	return hi === 0 ? BigInt(lo) : (BigInt(hi) << 32n) + BigInt(lo);
}

/** Two lowercase hex digits for every byte value. */
const HEX_BYTE: string[] = Array.from(
	{ length: 256 },
	(_, i) => (i < 16 ? '0' : '') + i.toString(16)
);

/**
 * Hex of an SCID held as two u32 halves, 8 digits each: what
 * Buffer#toString('hex') gives for its wire form, the graph's key. A byte
 * table measured faster than Number#toString(16) with padding.
 */
function scidHex(hi: number, lo: number): string {
	return (
		HEX_BYTE[hi >>> 24] +
		HEX_BYTE[(hi >>> 16) & 0xff] +
		HEX_BYTE[(hi >>> 8) & 0xff] +
		HEX_BYTE[hi & 0xff] +
		HEX_BYTE[lo >>> 24] +
		HEX_BYTE[(lo >>> 16) & 0xff] +
		HEX_BYTE[(lo >>> 8) & 0xff] +
		HEX_BYTE[lo & 0xff]
	);
}

/** The 8-byte big-endian wire form of an SCID held as two u32 halves. */
function scidBuffer(hi: number, lo: number): Buffer {
	// Every byte is written below, so the unzeroed allocation is safe.
	const buf = Buffer.allocUnsafe(8);
	buf[0] = hi >>> 24;
	buf[1] = hi >>> 16;
	buf[2] = hi >>> 8;
	buf[3] = hi;
	buf[4] = lo >>> 24;
	buf[5] = lo >>> 16;
	buf[6] = lo >>> 8;
	buf[7] = lo;
	return buf;
}

/**
 * One snapshot being applied to a graph, resumable between entries so a
 * driver can yield to the event loop. The entries, their order and the
 * errors are those of the one-pass parser this replaced; only the per-entry
 * cost differs:
 *
 * - The running SCID is two u32 halves with carry, wrapping mod 2^64. The
 *   one-pass parser summed unmasked BigInts and masked only when writing the
 *   buffer, which is the same value since (a mod 2^64 + d) mod 2^64 equals
 *   (a + d) mod 2^64. No BigInt is allocated per SCID or node index.
 * - Each node id is copied once, on first use, and that buffer and its hex
 *   are shared by every channel naming the node. Consecutive updates for
 *   the same SCID (delta 0, normally the two directions of a channel) share
 *   one SCID buffer and hex.
 *
 * After step() throws the import is finished and must not be stepped again.
 */
class RapidGossipImport {
	readonly version: number;
	readonly latestSeen: number;
	readonly nodeCount: number;
	channelsAdded = 0;
	updatesApplied = 0;

	private readonly graph: NetworkGraph;
	private readonly data: Buffer;
	private readonly chainHash: Buffer;
	private readonly nodeIdsOffset: number;
	private readonly nodeIds: Array<Buffer | undefined>;
	private readonly nodeHexes: string[];
	private off: number;
	private phase = PHASE_ANNOUNCEMENTS;
	/** Entries left in the current section. */
	private left: number;
	/** Running SCID of the current section, as u32 halves. */
	private scidHi = 0;
	private scidLo = 0;
	private defCltv = 0;
	private defHtlcMin = 0n;
	private defFeeBase = 0;
	private defFeeProp = 0;
	private defHtlcMax = 0n;
	/** The current update SCID's buffer and hex, reused while delta is 0. */
	private updScid: Buffer | undefined;
	private updScidHex = '';
	/** BigSize scratch, reused for every field. */
	private readonly part = { hi: 0, lo: 0 };

	/** Reads and validates the header; throws as the one-pass parser did. */
	constructor(graph: NetworkGraph, data: Buffer, expectedChainHash: Buffer) {
		if (data.length < 40 || !data.subarray(0, 3).equals(RGS_PREFIX)) {
			throw new Error('Invalid rapid gossip snapshot: bad prefix');
		}
		let off = 3;
		const version = data[off];
		off += 1;
		if (version !== 1) {
			throw new Error(
				`Unsupported rapid gossip snapshot version ${version} (only v1 is supported)`
			);
		}
		const chainHash = data.subarray(off, off + 32);
		off += 32;
		if (!chainHash.equals(expectedChainHash)) {
			throw new Error(
				'Rapid gossip snapshot chain hash does not match this network'
			);
		}
		const latestSeen = data.readUInt32BE(off);
		off += 4;

		// ── Node IDs ──
		// Read per index on first use (nodeAt); skipping the table moves the
		// offset exactly as reading it did, so the count below fails the same
		// way on a truncated table.
		const nodeCount = data.readUInt32BE(off);
		off += 4;
		this.nodeIdsOffset = off;
		off += 33 * nodeCount;

		const annCount = data.readUInt32BE(off);
		off += 4;

		this.graph = graph;
		this.data = data;
		this.chainHash = expectedChainHash;
		this.version = version;
		this.latestSeen = latestSeen;
		this.nodeCount = nodeCount;
		this.nodeIds = new Array<Buffer | undefined>(nodeCount);
		this.nodeHexes = new Array<string>(nodeCount);
		this.off = off;
		this.left = annCount;
	}

	/**
	 * Apply up to `budget` more entries, announcements and updates alike.
	 * Returns true once the whole snapshot is applied. A malformed entry
	 * throws the one-pass parser's error with the entries before it applied.
	 */
	step(budget: number): boolean {
		let remaining = budget;
		if (this.phase === PHASE_ANNOUNCEMENTS) {
			while (this.left > 0) {
				if (remaining <= 0) return false;
				remaining--;
				this.left--;
				this.applyAnnouncement();
			}
			this.beginUpdates();
		}
		if (this.phase === PHASE_UPDATES) {
			while (this.left > 0) {
				if (remaining <= 0) return false;
				remaining--;
				this.left--;
				this.applyUpdate();
			}
			this.phase = PHASE_DONE;
		}
		return true;
	}

	result(): IRapidGossipResult {
		return {
			version: this.version,
			latestSeen: this.latestSeen,
			nodeCount: this.nodeCount,
			channelsAdded: this.channelsAdded,
			updatesApplied: this.updatesApplied
		};
	}

	/** Add a delta (in this.part) to the running SCID, mod 2^64. */
	private advanceScid(): void {
		const lo = this.scidLo + this.part.lo;
		this.scidLo = lo >>> 0;
		this.scidHi =
			(this.scidHi + this.part.hi + (lo > 0xffffffff ? 1 : 0)) >>> 0;
	}

	/** The node id at a valid table index, copied once on first use. */
	private nodeAt(index: number): Buffer {
		let id = this.nodeIds[index];
		if (id === undefined) {
			const at = this.nodeIdsOffset + index * 33;
			id = Buffer.from(this.data.subarray(at, at + 33));
			this.nodeIds[index] = id;
			this.nodeHexes[index] = id.toString('hex');
		}
		return id;
	}

	private applyAnnouncement(): void {
		const data = this.data;
		const part = this.part;
		let off = this.off;
		const featuresLen = readU16(data, off);
		off += 2;
		const featuresAt = off;
		off += featuresLen;

		off += readBigSizeParts(data, off, part);
		this.advanceScid();
		off += readBigSizeParts(data, off, part);
		const n1Hi = part.hi;
		const n1 = part.lo;
		off += readBigSizeParts(data, off, part);
		this.off = off;
		// Bit 63 of node_id_2_index flags trailing data (v2 only); clear it. v1
		// snapshots never set it and carry no per-announcement additional data.
		const n2Hi = part.hi & 0x7fffffff;
		const n2 = part.lo;

		// An index names a node only when it is below the table size.
		const nodeCount = this.nodeCount;
		if (n1Hi !== 0 || n1 >= nodeCount || n2Hi !== 0 || n2 >= nodeCount) {
			return;
		}
		const a = this.nodeAt(n1);
		const b = this.nodeAt(n2);

		// BOLT 7 requires nodeId1 < nodeId2; RGS preserves it, but order defensively.
		const swap = Buffer.compare(a, b) >= 0;
		const msg: IChannelAnnouncementMessage = {
			nodeSignature1: EMPTY_SIG,
			nodeSignature2: EMPTY_SIG,
			bitcoinSignature1: EMPTY_SIG,
			bitcoinSignature2: EMPTY_SIG,
			features:
				featuresLen === 0
					? EMPTY_FEATURES
					: Buffer.from(data.subarray(featuresAt, featuresAt + featuresLen)),
			chainHash: this.chainHash,
			shortChannelId: scidBuffer(this.scidHi, this.scidLo),
			nodeId1: swap ? b : a,
			nodeId2: swap ? a : b,
			bitcoinKey1: EMPTY_KEY,
			bitcoinKey2: EMPTY_KEY
		};
		// RGS strips signatures by design, so the entry stays unverified and is
		// never relayed to gossip queries (BOLT 7, #340).
		if (
			this.graph.addRapidGossipChannel(msg, {
				scidHex: scidHex(this.scidHi, this.scidLo),
				node1Hex: this.nodeHexes[swap ? n2 : n1],
				node2Hex: this.nodeHexes[swap ? n1 : n2]
			})
		) {
			this.channelsAdded++;
		}
	}

	/** Read the update section's header once every announcement is applied. */
	private beginUpdates(): void {
		const data = this.data;
		let off = this.off;
		// ── Channel updates ──
		// The update count is encoded BEFORE the default values, and the
		// defaults are only present when there is at least one update.
		const updCount = data.readUInt32BE(off);
		off += 4;
		if (updCount === 0) {
			this.off = off;
			this.phase = PHASE_DONE;
			return;
		}
		this.defCltv = data.readUInt16BE(off);
		off += 2;
		this.defHtlcMin = data.readBigUInt64BE(off);
		off += 8;
		this.defFeeBase = data.readUInt32BE(off);
		off += 4;
		this.defFeeProp = data.readUInt32BE(off);
		off += 4;
		this.defHtlcMax = data.readBigUInt64BE(off);
		off += 8;
		this.off = off;
		this.left = updCount;
		this.scidHi = 0;
		this.scidLo = 0;
		this.phase = PHASE_UPDATES;
	}

	private applyUpdate(): void {
		const data = this.data;
		const part = this.part;
		let off = this.off;
		off += readBigSizeParts(data, off, part);
		let scid = this.updScid;
		if (scid === undefined || part.hi !== 0 || part.lo !== 0) {
			this.advanceScid();
			scid = scidBuffer(this.scidHi, this.scidLo);
			this.updScid = scid;
			this.updScidHex = scidHex(this.scidHi, this.scidLo);
		}

		// Past the end this reads undefined, as the one-pass parser did: every
		// flag reads clear, and the next entry (if any) throws.
		const flags = data[off];
		off += 1;
		const direction = flags & 0x01;
		const disable = (flags & 0x02) !== 0;
		const incremental = (flags & 0x80) !== 0;

		// Incremental updates inherit unspecified fields from the existing update.
		let cltv = this.defCltv,
			htlcMin = this.defHtlcMin,
			feeBase = this.defFeeBase,
			feeProp = this.defFeeProp,
			htlcMax = this.defHtlcMax;
		if (incremental) {
			const ch = this.graph.getChannel(scid);
			const existing = direction === 0 ? ch?.update1 : ch?.update2;
			if (existing) {
				cltv = existing.cltvExpiryDelta;
				htlcMin = existing.htlcMinimumMsat;
				feeBase = existing.feeBaseMsat;
				feeProp = existing.feeProportionalMillionths;
				htlcMax = existing.htlcMaximumMsat ?? this.defHtlcMax;
			}
		}
		if (flags & 0x40) {
			cltv = readU16(data, off);
			off += 2;
		}
		if (flags & 0x20) {
			htlcMin = readU64(data, off);
			off += 8;
		}
		if (flags & 0x10) {
			feeBase = readU32(data, off);
			off += 4;
		}
		if (flags & 0x08) {
			feeProp = readU32(data, off);
			off += 4;
		}
		if (flags & 0x04) {
			htlcMax = readU64(data, off);
			off += 8;
		}
		this.off = off;

		const msg: IChannelUpdateMessage = {
			signature: EMPTY_SIG,
			chainHash: this.chainHash,
			shortChannelId: scid,
			timestamp: this.latestSeen,
			messageFlags: MESSAGE_FLAG_HTLC_MAX,
			channelFlags:
				(direction ? CHANNEL_FLAG_DIRECTION : 0) |
				(disable ? CHANNEL_FLAG_DISABLED : 0),
			cltvExpiryDelta: cltv,
			htlcMinimumMsat: htlcMin,
			feeBaseMsat: feeBase,
			feeProportionalMillionths: feeProp,
			htlcMaximumMsat: htlcMax
		};
		// Unverified (RGS strips signatures): applied for routing, never relayed.
		if (this.graph.applyRapidGossipUpdate(msg, this.updScidHex)) {
			this.updatesApplied++;
		}
	}
}

/**
 * Parse an RGS v1 snapshot and apply it to a NetworkGraph in one
 * synchronous pass. Returns counts of what was ingested. Throws on a
 * malformed snapshot, wrong version, or chain-hash mismatch.
 */
export function applyRapidGossipSnapshot(
	graph: NetworkGraph,
	data: Buffer,
	expectedChainHash: Buffer = BITCOIN_CHAIN_HASH
): IRapidGossipResult {
	const run = new RapidGossipImport(graph, data, expectedChainHash);
	run.step(Infinity);
	return run.result();
}

/**
 * applyRapidGossipSnapshot in time slices of about `sliceMs` (default 8),
 * yielding to the event loop between slices so a full mainnet snapshot
 * never holds the thread for long. The resulting graph and counts are the
 * one-pass ones, and so are the errors. The yield is a macrotask
 * (setImmediate, which the portable build maps to setTimeout 0), so I/O,
 * timers and UI events run between slices. Rejects with
 * RapidGossipCancelledError once `cancelled` returns true.
 */
export async function applyRapidGossipSnapshotAsync(
	graph: NetworkGraph,
	data: Buffer,
	opts: IRapidGossipApplyOptions = {}
): Promise<IRapidGossipResult> {
	const sliceMs = opts.sliceMs ?? DEFAULT_SLICE_MS;
	if (opts.cancelled?.()) throw new RapidGossipCancelledError();
	const run = new RapidGossipImport(
		graph,
		data,
		opts.expectedChainHash ?? BITCOIN_CHAIN_HASH
	);
	for (;;) {
		const start = Date.now();
		let done: boolean;
		do {
			done = run.step(ENTRIES_PER_STEP);
		} while (!done && Date.now() - start < sliceMs);
		opts.onSlice?.(Date.now() - start);
		if (done) return run.result();
		await new Promise<void>((resolve) => setImmediate(resolve));
		if (opts.cancelled?.()) throw new RapidGossipCancelledError();
	}
}

/** Default public RGS snapshot endpoint (full sync from genesis). */
export const DEFAULT_RGS_URL =
	'https://rapidsync.lightningdevkit.org/snapshot/0';

/**
 * Download a rapid gossip sync snapshot over HTTPS.
 */
export function fetchRapidGossipSnapshot(
	url: string = DEFAULT_RGS_URL,
	timeoutMs = 60_000
): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const req = https.get(url, (res) => {
			if (res.statusCode !== 200) {
				res.resume();
				reject(
					new Error(`Rapid gossip sync request failed: HTTP ${res.statusCode}`)
				);
				return;
			}
			const chunks: Buffer[] = [];
			res.on('data', (c: Buffer) => chunks.push(c));
			res.on('end', () => resolve(Buffer.concat(chunks)));
			res.on('error', reject);
		});
		req.on('error', reject);
		req.setTimeout(timeoutMs, () => {
			req.destroy(new Error('Rapid gossip sync request timed out'));
		});
	});
}
