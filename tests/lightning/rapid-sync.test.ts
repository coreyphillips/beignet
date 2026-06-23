import { expect } from 'chai';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	applyRapidGossipSnapshot,
	DEFAULT_RGS_URL
} from '../../src/lightning/gossip/rapid-sync';
import { encodeBigSize } from '../../src/lightning/message/codec';
import {
	encodeShortChannelId,
	decodeShortChannelId
} from '../../src/lightning/gossip/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

const NODE_A = Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, 0xaa)]);
const NODE_B = Buffer.concat([Buffer.from([0x03]), Buffer.alloc(32, 0xbb)]); // A < B

interface IUpdate {
	scid: bigint;
	flags: number;
	cltv?: number;
	htlcMin?: bigint;
	feeBase?: number;
	feeProp?: number;
	htlcMax?: bigint;
}

function u16(n: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n);
	return b;
}
function u32(n: number): Buffer {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n);
	return b;
}
function u64(n: bigint): Buffer {
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(n);
	return b;
}

function buildV1Snapshot(opts: {
	version?: number;
	chainHash?: Buffer;
	latestSeen: number;
	nodes: Buffer[];
	channels: Array<{ scid: bigint; n1: number; n2: number; features?: Buffer }>;
	defaults: {
		cltv: number;
		htlcMin: bigint;
		feeBase: number;
		feeProp: number;
		htlcMax: bigint;
	};
	updates: IUpdate[];
}): Buffer {
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

describe('Rapid Gossip Sync (v1 snapshot parsing)', () => {
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

	it('ingests a channel and both directional updates', () => {
		const graph = new NetworkGraph();
		const snap = baseSnapshot([
			{ scid, flags: 0x00 }, // direction 0, all defaults
			{ scid, flags: 0x41, cltv: 144 } // direction 1, cltv present
		]);

		const result = applyRapidGossipSnapshot(graph, snap);
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

	it('makes the channel usable for pathfinding (both endpoints linked)', () => {
		const graph = new NetworkGraph();
		applyRapidGossipSnapshot(
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

	it('applies all explicitly-present update fields', () => {
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
		applyRapidGossipSnapshot(graph, snap);
		const ch = graph.getChannel(
			encodeShortChannelId(decodeShortChannelId(Buffer.from(u64(scid))))
		)!;
		expect(ch.update1!.cltvExpiryDelta).to.equal(80);
		expect(ch.update1!.htlcMinimumMsat).to.equal(2000n);
		expect(ch.update1!.feeBaseMsat).to.equal(500);
		expect(ch.update1!.feeProportionalMillionths).to.equal(10);
		expect(ch.update1!.htlcMaximumMsat).to.equal(50_000_000n);
	});

	it('rejects a snapshot with a bad prefix', () => {
		const snap = baseSnapshot([{ scid, flags: 0x00 }]);
		snap[0] = 0x00;
		expect(() => applyRapidGossipSnapshot(new NetworkGraph(), snap)).to.throw(
			/bad prefix/
		);
	});

	it('rejects an unsupported version', () => {
		const snap = buildV1Snapshot({
			version: 2,
			latestSeen: 1,
			nodes: [NODE_A, NODE_B],
			channels: [],
			defaults,
			updates: []
		});
		expect(() => applyRapidGossipSnapshot(new NetworkGraph(), snap)).to.throw(
			/version 2/
		);
	});

	it('rejects a chain hash mismatch', () => {
		const wrong = Buffer.alloc(32, 0x99);
		const snap = buildV1Snapshot({
			chainHash: wrong,
			latestSeen: 1,
			nodes: [NODE_A, NODE_B],
			channels: [],
			defaults,
			updates: []
		});
		expect(() => applyRapidGossipSnapshot(new NetworkGraph(), snap)).to.throw(
			/chain hash/
		);
	});

	it('exposes the default public RGS endpoint', () => {
		expect(DEFAULT_RGS_URL).to.match(/^https:\/\//);
	});
});
