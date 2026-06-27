/**
 * Rapid Gossip Sync (RGS) — LDK-compatible compact graph snapshot.
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
 *   default: cltv_expiry_delta (u16) htlc_minimum_msat (u64) fee_base_msat (u32)
 *            fee_proportional_millionths (u32) htlc_maximum_msat (u64)
 *   update_count (u32) | per update:
 *       scid_delta (BigSize) | flags (u8)
 *       [flags&0x40] cltv_expiry_delta (u16)
 *       [flags&0x20] htlc_minimum_msat (u64)
 *       [flags&0x10] fee_base_msat (u32)
 *       [flags&0x08] fee_proportional_millionths (u32)
 *       [flags&0x04] htlc_maximum_msat (u64)
 *     flags bit0 = direction, bit1 = disable, bit7 = incremental.
 */

import * as https from 'https';
import { decodeBigSize } from '../message/codec';
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

export interface IRapidGossipResult {
	version: number;
	latestSeen: number;
	nodeCount: number;
	channelsAdded: number;
	updatesApplied: number;
}

/** Convert a u64 short_channel_id to its 8-byte big-endian wire buffer. */
function scidToBuffer(scid: bigint): Buffer {
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(scid & 0xffffffffffffffffn);
	return buf;
}

/**
 * Parse an RGS v1 snapshot and apply it to a NetworkGraph.
 * Returns counts of what was ingested. Throws on a malformed snapshot,
 * wrong version, or chain-hash mismatch.
 */
export function applyRapidGossipSnapshot(
	graph: NetworkGraph,
	data: Buffer,
	expectedChainHash: Buffer = BITCOIN_CHAIN_HASH
): IRapidGossipResult {
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
	const nodeCount = data.readUInt32BE(off);
	off += 4;
	const nodeIds: Buffer[] = new Array(nodeCount);
	for (let i = 0; i < nodeCount; i++) {
		nodeIds[i] = data.subarray(off, off + 33);
		off += 33;
	}

	// ── Channel announcements ──
	const annCount = data.readUInt32BE(off);
	off += 4;
	let prevAnnScid = 0n;
	let channelsAdded = 0;
	for (let i = 0; i < annCount; i++) {
		const featuresLen = data.readUInt16BE(off);
		off += 2;
		const features = data.subarray(off, off + featuresLen);
		off += featuresLen;

		const sd = decodeBigSize(data, off);
		off += sd.bytesRead;
		prevAnnScid += sd.value;
		const n1 = decodeBigSize(data, off);
		off += n1.bytesRead;
		const n2 = decodeBigSize(data, off);
		off += n2.bytesRead;
		// Bit 63 of node_id_2_index flags trailing data (v2 only); clear it. v1
		// snapshots never set it and carry no per-announcement additional data.
		const n2index = n2.value & ~(1n << 63n);

		const a = nodeIds[Number(n1.value)];
		const b = nodeIds[Number(n2index)];
		if (!a || !b) continue;

		// BOLT 7 requires nodeId1 < nodeId2; RGS preserves it, but order defensively.
		const [nodeId1, nodeId2] = Buffer.compare(a, b) < 0 ? [a, b] : [b, a];
		const msg: IChannelAnnouncementMessage = {
			nodeSignature1: EMPTY_SIG,
			nodeSignature2: EMPTY_SIG,
			bitcoinSignature1: EMPTY_SIG,
			bitcoinSignature2: EMPTY_SIG,
			features: Buffer.from(features),
			chainHash: expectedChainHash,
			shortChannelId: scidToBuffer(prevAnnScid),
			nodeId1: Buffer.from(nodeId1),
			nodeId2: Buffer.from(nodeId2),
			bitcoinKey1: EMPTY_KEY,
			bitcoinKey2: EMPTY_KEY
		};
		if (graph.addChannelAnnouncement(msg)) channelsAdded++;
	}

	// ── Channel updates ──
	// The update count is encoded BEFORE the default values, and the defaults are
	// only present when there is at least one update.
	const updCount = data.readUInt32BE(off);
	off += 4;
	let updatesApplied = 0;
	if (updCount === 0) {
		return { version, latestSeen, nodeCount, channelsAdded, updatesApplied };
	}

	const defCltv = data.readUInt16BE(off);
	off += 2;
	const defHtlcMin = data.readBigUInt64BE(off);
	off += 8;
	const defFeeBase = data.readUInt32BE(off);
	off += 4;
	const defFeeProp = data.readUInt32BE(off);
	off += 4;
	const defHtlcMax = data.readBigUInt64BE(off);
	off += 8;

	let prevUpdScid = 0n;
	for (let i = 0; i < updCount; i++) {
		const sd = decodeBigSize(data, off);
		off += sd.bytesRead;
		prevUpdScid += sd.value;
		const scidBuf = scidToBuffer(prevUpdScid);

		const flags = data[off];
		off += 1;
		const direction = flags & 0x01;
		const disable = (flags & 0x02) !== 0;
		const incremental = (flags & 0x80) !== 0;

		// Incremental updates inherit unspecified fields from the existing update.
		let cltv = defCltv,
			htlcMin = defHtlcMin,
			feeBase = defFeeBase,
			feeProp = defFeeProp,
			htlcMax = defHtlcMax;
		if (incremental) {
			const ch = graph.getChannel(scidBuf);
			const existing = direction === 0 ? ch?.update1 : ch?.update2;
			if (existing) {
				cltv = existing.cltvExpiryDelta;
				htlcMin = existing.htlcMinimumMsat;
				feeBase = existing.feeBaseMsat;
				feeProp = existing.feeProportionalMillionths;
				htlcMax = existing.htlcMaximumMsat ?? defHtlcMax;
			}
		}
		if (flags & 0x40) {
			cltv = data.readUInt16BE(off);
			off += 2;
		}
		if (flags & 0x20) {
			htlcMin = data.readBigUInt64BE(off);
			off += 8;
		}
		if (flags & 0x10) {
			feeBase = data.readUInt32BE(off);
			off += 4;
		}
		if (flags & 0x08) {
			feeProp = data.readUInt32BE(off);
			off += 4;
		}
		if (flags & 0x04) {
			htlcMax = data.readBigUInt64BE(off);
			off += 8;
		}

		const msg: IChannelUpdateMessage = {
			signature: EMPTY_SIG,
			chainHash: expectedChainHash,
			shortChannelId: scidBuf,
			timestamp: latestSeen,
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
		if (graph.applyChannelUpdate(msg)) updatesApplied++;
	}

	return { version, latestSeen, nodeCount, channelsAdded, updatesApplied };
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
