/**
 * Test oracle: the one-pass Rapid Gossip Sync parser as released in 0.27.0
 * (1c59fa65), copied verbatim apart from its name and import paths. The
 * cooperative importer in src/lightning/gossip/rapid-sync.ts must leave a
 * graph in exactly the state this leaves it, entry for entry, and fail with
 * the same errors at the same points. Do not "fix" anything here: it is the
 * reference, not the implementation.
 */

import { decodeBigSize } from '../../../src/lightning/message/codec';
import { NetworkGraph } from '../../../src/lightning/gossip/network-graph';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	CHANNEL_FLAG_DIRECTION,
	CHANNEL_FLAG_DISABLED,
	MESSAGE_FLAG_HTLC_MAX
} from '../../../src/lightning/gossip/types';
import { IRapidGossipResult } from '../../../src/lightning/gossip/rapid-sync';
import { BITCOIN_CHAIN_HASH } from '../../../src/lightning/channel/types';

/** "LDK" prefix that begins every RGS snapshot. */
const RGS_PREFIX = Buffer.from([0x4c, 0x44, 0x4b]);

const EMPTY_SIG = Buffer.alloc(64);
const EMPTY_KEY = Buffer.alloc(33);

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
export function applyRapidGossipSnapshotReference(
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
		// RGS strips signatures by design, so the entry stays unverified and is
		// never relayed to gossip queries (BOLT 7, #340).
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
		// Unverified (RGS strips signatures): applied for routing, never relayed.
		if (graph.applyChannelUpdate(msg)) updatesApplied++;
	}

	return { version, latestSeen, nodeCount, channelsAdded, updatesApplied };
}
