/**
 * Graph query surface (roadmap M3)
 *
 * - SCID JSON formatting/parsing (human "BxTxO" + 16-char hex)
 * - Route JSON <-> library route conversion, both ways
 * - LightningNode.queryRoute: pathfinding without sending
 * - BeignetNode graph queries: info/node/channel/describe (+ NOT_FOUND, paging)
 * - BeignetNode.queryRoute / sendToRoute wiring
 * - send-to-route composes with route-query output end to end (loopback pair)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	PaymentStatus,
	PaymentDirection,
	IPaymentInfo
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage,
	IRoute,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	BeignetNode,
	formatScid,
	parseScid,
	routeHopsToJson,
	jsonToRouteHops
} from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`graph-query-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function pubkeyOf(seedId: number): Buffer {
	return getPublicKey(makeNodeConfig(seedId).nodePrivateKey);
}

interface ISeedChannelOpts {
	block?: number;
	txIndex?: number;
	feeBaseMsat?: number;
	feeProportionalMillionths?: number;
	cltvExpiryDelta?: number;
	htlcMinimumMsat?: bigint;
	htlcMaximumMsat?: bigint;
	timestamp?: number;
	/** Disable the direction-1 update (channelFlags disabled bit) */
	disableDirection1?: boolean;
	/** Only publish the direction-0 update */
	skipUpdate1?: boolean;
}

/** Announce a channel between two pubkeys with bidirectional updates. */
function seedChannel(
	graph: NetworkGraph,
	pubkeyA: Buffer,
	pubkeyB: Buffer,
	opts: ISeedChannelOpts = {}
): Buffer {
	const [nodeId1, nodeId2] =
		Buffer.compare(pubkeyA, pubkeyB) < 0
			? [pubkeyA, pubkeyB]
			: [pubkeyB, pubkeyA];
	const scid = encodeShortChannelId({
		block: opts.block ?? 700_000,
		txIndex: opts.txIndex ?? 1,
		outputIndex: 0
	});
	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1,
		nodeId2,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	expect(graph.addChannelAnnouncement(announcement)).to.equal(true);

	const base: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: opts.timestamp ?? Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: opts.cltvExpiryDelta ?? 40,
		htlcMinimumMsat: opts.htlcMinimumMsat ?? 1000n,
		htlcMaximumMsat: opts.htlcMaximumMsat ?? 1_000_000_000n,
		feeBaseMsat: opts.feeBaseMsat ?? 1000,
		feeProportionalMillionths: opts.feeProportionalMillionths ?? 100
	};
	if (!opts.skipUpdate1) {
		expect(graph.applyChannelUpdate({ ...base })).to.equal(true);
	}
	expect(
		graph.applyChannelUpdate({
			...base,
			channelFlags: 1 | (opts.disableDirection1 ? 2 : 0)
		})
	).to.equal(true);
	return scid;
}

function seedNodeAnnouncement(
	graph: NetworkGraph,
	pubkey: Buffer,
	alias: string
): INodeAnnouncementMessage {
	const aliasBuf = Buffer.alloc(32);
	aliasBuf.write(alias, 'utf8');
	const msg: INodeAnnouncementMessage = {
		signature: Buffer.alloc(64),
		features: Buffer.from([0x80, 0x00]),
		timestamp: Math.floor(Date.now() / 1000),
		nodeId: pubkey,
		rgbColor: Buffer.from([0xff, 0x99, 0x00]),
		alias: aliasBuf,
		addresses: [{ type: 1, host: '203.0.113.7', port: 9735 }]
	};
	expect(graph.applyNodeAnnouncement(msg)).to.equal(true);
	return msg;
}

// ─────────────── SCID formatting ───────────────

describe('Graph query: SCID formatting', () => {
	it('formatScid renders block x txIndex x outputIndex', () => {
		const scid = encodeShortChannelId({
			block: 700_123,
			txIndex: 45,
			outputIndex: 1
		});
		expect(formatScid(scid)).to.equal('700123x45x1');
	});

	it('parseScid roundtrips the human format', () => {
		const scid = encodeShortChannelId({
			block: 812_000,
			txIndex: 3,
			outputIndex: 2
		});
		expect(parseScid(formatScid(scid)).equals(scid)).to.equal(true);
	});

	it('parseScid accepts 16-char hex', () => {
		const scid = encodeShortChannelId({
			block: 700_000,
			txIndex: 1,
			outputIndex: 0
		});
		expect(parseScid(scid.toString('hex')).equals(scid)).to.equal(true);
	});

	it('parseScid rejects malformed input with INVALID_PARAMS', () => {
		for (const bad of ['nonsense', '1x2', '0xdeadbeef', 'zz'.repeat(8), '']) {
			try {
				parseScid(bad);
				expect.fail(`should have thrown for ${JSON.stringify(bad)}`);
			} catch (err) {
				expect(err).to.be.instanceOf(BeignetError);
				expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
			}
		}
	});
});

// ─────────────── Route JSON conversion ───────────────

describe('Graph query: route JSON conversion', () => {
	function makeRoute(): IRoute {
		const scid1 = encodeShortChannelId({
			block: 700_000,
			txIndex: 1,
			outputIndex: 0
		});
		const scid2 = encodeShortChannelId({
			block: 700_000,
			txIndex: 2,
			outputIndex: 0
		});
		return {
			hops: [
				{
					pubkey: pubkeyOf(1),
					shortChannelId: scid1,
					amountToForwardMsat: 100_011_000n,
					outgoingCltvValue: 80,
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 40
				},
				{
					pubkey: pubkeyOf(2),
					shortChannelId: scid2,
					amountToForwardMsat: 100_000_000n,
					outgoingCltvValue: 40,
					feeBaseMsat: 1000,
					feeProportionalMillionths: 100,
					cltvExpiryDelta: 40
				}
			],
			totalAmountMsat: 100_011_000n,
			totalCltvDelta: 80,
			totalFeeMsat: 11_000n
		};
	}

	it('routeHopsToJson emits string msat amounts and per-hop fees', () => {
		const json = routeHopsToJson(makeRoute());
		expect(json).to.have.length(2);
		expect(json[0].amountToForwardMsat).to.equal('100011000');
		// Intermediate hop fee = received minus forwarded
		expect(json[0].feeMsat).to.equal('11000');
		expect(json[0].shortChannelId).to.equal('700000x1x0');
		expect(json[0].outgoingCltvValue).to.equal(80);
		// Final hop forwards nothing, so charges nothing
		expect(json[1].feeMsat).to.equal('0');
		expect(json[1].amountToForwardMsat).to.equal('100000000');
	});

	it('jsonToRouteHops roundtrips routeHopsToJson output', () => {
		const route = makeRoute();
		const back = jsonToRouteHops(routeHopsToJson(route));
		expect(back).to.have.length(route.hops.length);
		for (let i = 0; i < back.length; i++) {
			expect(back[i].pubkey.equals(route.hops[i].pubkey)).to.equal(true);
			expect(
				back[i].shortChannelId.equals(route.hops[i].shortChannelId)
			).to.equal(true);
			expect(back[i].amountToForwardMsat).to.equal(
				route.hops[i].amountToForwardMsat
			);
			expect(back[i].outgoingCltvValue).to.equal(
				route.hops[i].outgoingCltvValue
			);
		}
	});

	it('jsonToRouteHops rejects malformed hops with INVALID_PARAMS', () => {
		const good = routeHopsToJson(makeRoute());
		const cases = [
			[{ ...good[0], pubkey: 'beef' }],
			[{ ...good[0], amountToForwardMsat: 'not-a-number' }],
			[{ ...good[0], outgoingCltvValue: -1 }],
			[{ ...good[0], outgoingCltvValue: 1.5 }],
			[{ ...good[0], shortChannelId: 'bogus' }]
		];
		for (const hops of cases) {
			try {
				jsonToRouteHops(hops);
				expect.fail('should have thrown');
			} catch (err) {
				expect(err).to.be.instanceOf(BeignetError);
				expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
			}
		}
	});
});

// ─────────────── LightningNode.queryRoute ───────────────

describe('Graph query: LightningNode.queryRoute', () => {
	it('finds a multi-hop route with fees matching the graph policies', () => {
		const alice = createNode(10);
		const alicePub = Buffer.from(alice.getNodeId(), 'hex');
		const bobPub = pubkeyOf(11);
		const carolPub = pubkeyOf(12);
		seedChannel(alice.getGraph(), alicePub, bobPub, { txIndex: 1 });
		seedChannel(alice.getGraph(), bobPub, carolPub, { txIndex: 2 });

		const amountMsat = 100_000_000n;
		const route = alice.queryRoute(carolPub, amountMsat);
		expect(route).to.not.equal(null);
		expect(route!.hops).to.have.length(2);
		expect(route!.hops[0].pubkey.equals(bobPub)).to.equal(true);
		expect(route!.hops[1].pubkey.equals(carolPub)).to.equal(true);
		// Only the intermediate hop charges: 1000 base + 100 ppm of 100_000_000
		expect(route!.totalFeeMsat).to.equal(11_000n);
		expect(route!.hops[1].amountToForwardMsat).to.equal(amountMsat);
		expect(route!.totalAmountMsat).to.equal(amountMsat + 11_000n);
		alice.destroy();
	});

	it('does NOT create a payment or send anything', () => {
		const alice = createNode(13);
		const alicePub = Buffer.from(alice.getNodeId(), 'hex');
		const bobPub = pubkeyOf(14);
		seedChannel(alice.getGraph(), alicePub, bobPub);
		const route = alice.queryRoute(bobPub, 1_000_000n);
		expect(route).to.not.equal(null);
		expect(alice.listPayments()).to.have.length(0);
		alice.destroy();
	});

	it('returns null when no path exists', () => {
		const alice = createNode(15);
		const route = alice.queryRoute(pubkeyOf(16), 1_000_000n);
		expect(route).to.equal(null);
		alice.destroy();
	});
});

// ─────────────── BeignetNode graph queries ───────────────

describe('Graph query: BeignetNode surface', function () {
	this.timeout(60_000);

	let bn: BeignetNode;
	let tmpDir: string;
	let graph: NetworkGraph;
	let ourPub: Buffer;
	const alicePub = pubkeyOf(20);
	const bobPub = pubkeyOf(21);
	const carolPub = pubkeyOf(22);
	const scids: Buffer[] = [];
	let aliceAnn: INodeAnnouncementMessage;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-graph-'));
		bn = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent'
		});
		graph = bn.getNode().getGraph();
		ourPub = Buffer.from(bn.getNode().getNodeId(), 'hex');
		// our node -> alice -> bob line (for route queries), plus bob -> carol
		scids.push(seedChannel(graph, ourPub, alicePub, { txIndex: 1 }));
		scids.push(
			seedChannel(graph, alicePub, bobPub, {
				txIndex: 2,
				feeBaseMsat: 2000,
				feeProportionalMillionths: 250,
				disableDirection1: true
			})
		);
		scids.push(
			seedChannel(graph, bobPub, carolPub, { txIndex: 3, skipUpdate1: true })
		);
		aliceAnn = seedNodeAnnouncement(graph, alicePub, 'graph-test-alice');
	});

	after(async () => {
		await bn.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('getGraphInfo reports node and channel counts', () => {
		const info = bn.getGraphInfo();
		expect(info.nodeCount).to.equal(4);
		expect(info.channelCount).to.equal(3);
		// No gossip/RGS sync has run in this offline session
		expect(info.lastSyncAt).to.equal(undefined);
	});

	it('getGraphNode returns announcement info + known channels', () => {
		const node = bn.getGraphNode(alicePub.toString('hex'));
		expect(node).to.not.equal(null);
		expect(node!.pubkey).to.equal(alicePub.toString('hex'));
		expect(node!.alias).to.equal('graph-test-alice');
		expect(node!.color).to.equal('ff9900');
		expect(node!.featuresHex).to.equal('8000');
		expect(node!.lastUpdate).to.equal(aliceAnn.timestamp);
		expect(node!.addresses).to.deep.equal([
			{ type: 1, host: '203.0.113.7', port: 9735 }
		]);
		expect(node!.channelCount).to.equal(2);
		expect(node!.channels).to.have.members([
			formatScid(scids[0]),
			formatScid(scids[1])
		]);
	});

	it('getGraphNode works for a node with no announcement', () => {
		const node = bn.getGraphNode(carolPub.toString('hex'));
		expect(node).to.not.equal(null);
		expect(node!.alias).to.equal(undefined);
		expect(node!.channels).to.deep.equal([formatScid(scids[2])]);
	});

	it('getGraphNode returns null for an unknown node (NOT_FOUND path)', () => {
		expect(bn.getGraphNode(pubkeyOf(99).toString('hex'))).to.equal(null);
	});

	it('getGraphNode rejects malformed pubkeys', () => {
		try {
			bn.getGraphNode('feed');
			expect.fail('should have thrown');
		} catch (err) {
			expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
		}
	});

	it('getGraphChannel returns endpoints and both direction policies', () => {
		const ch = bn.getGraphChannel(formatScid(scids[1]));
		expect(ch).to.not.equal(null);
		expect(ch!.shortChannelId).to.equal(formatScid(scids[1]));
		const [n1, n2] =
			Buffer.compare(alicePub, bobPub) < 0
				? [alicePub, bobPub]
				: [bobPub, alicePub];
		expect(ch!.node1Pubkey).to.equal(n1.toString('hex'));
		expect(ch!.node2Pubkey).to.equal(n2.toString('hex'));
		// Capacity proxy from htlc_maximum_msat (1_000_000_000 msat)
		expect(ch!.capacitySats).to.equal(1_000_000);
		expect(ch!.node1Policy).to.not.equal(undefined);
		expect(ch!.node2Policy).to.not.equal(undefined);
		expect(ch!.node1Policy!.feeBaseMsat).to.equal(2000);
		expect(ch!.node1Policy!.feeProportionalMillionths).to.equal(250);
		expect(ch!.node1Policy!.cltvExpiryDelta).to.equal(40);
		expect(ch!.node1Policy!.htlcMinimumMsat).to.equal('1000');
		expect(ch!.node1Policy!.htlcMaximumMsat).to.equal('1000000000');
		expect(ch!.node1Policy!.disabled).to.equal(false);
		expect(ch!.node2Policy!.disabled).to.equal(true);
	});

	it('getGraphChannel omits a direction with no update', () => {
		const ch = bn.getGraphChannel(formatScid(scids[2]));
		expect(ch).to.not.equal(null);
		expect(ch!.node1Policy).to.equal(undefined);
		expect(ch!.node2Policy).to.not.equal(undefined);
	});

	it('getGraphChannel accepts hex SCIDs', () => {
		const ch = bn.getGraphChannel(scids[0].toString('hex'));
		expect(ch).to.not.equal(null);
		expect(ch!.shortChannelId).to.equal(formatScid(scids[0]));
	});

	it('getGraphChannel returns null for unknown SCIDs (NOT_FOUND path)', () => {
		expect(bn.getGraphChannel('999999x999x9')).to.equal(null);
	});

	it('describeGraph defaults to limit 500 and reports totals', () => {
		const page = bn.describeGraph();
		expect(page.limit).to.equal(500);
		expect(page.offset).to.equal(0);
		expect(page.totalChannels).to.equal(3);
		expect(page.channels).to.have.length(3);
	});

	it('describeGraph pages with limit and offset', () => {
		const all = bn.describeGraph().channels.map((c) => c.shortChannelId);
		const page = bn.describeGraph(2, 2);
		expect(page.limit).to.equal(2);
		expect(page.offset).to.equal(2);
		expect(page.channels.map((c) => c.shortChannelId)).to.deep.equal(
			all.slice(2, 4)
		);
		expect(bn.describeGraph(2, 0).channels).to.have.length(2);
	});

	it('describeGraph caps the page size at 500 (never unbounded)', () => {
		expect(bn.describeGraph(1_000_000).limit).to.equal(500);
	});

	it('describeGraph returns empty page past the end', () => {
		const page = bn.describeGraph(10, 50);
		expect(page.channels).to.have.length(0);
		expect(page.totalChannels).to.equal(3);
	});

	it('queryRoute computes hops + totals from the graph without sending', () => {
		const amountSats = 50_000;
		const result = bn.queryRoute(bobPub.toString('hex'), amountSats);
		expect(result.destination).to.equal(bobPub.toString('hex'));
		expect(result.amountSats).to.equal(amountSats);
		expect(result.hops).to.have.length(2);
		expect(result.hops[0].pubkey).to.equal(alicePub.toString('hex'));
		expect(result.hops[1].pubkey).to.equal(bobPub.toString('hex'));
		// Alice forwards over scids[1]: 2000 base + 250 ppm of 50_000_000 msat
		const expectedFee = 2000n + (50_000_000n * 250n) / 1_000_000n;
		expect(result.totalFeeMsat).to.equal(expectedFee.toString());
		expect(result.hops[0].feeMsat).to.equal(expectedFee.toString());
		expect(result.hops[1].feeMsat).to.equal('0');
		expect(result.hops[1].amountToForwardMsat).to.equal('50000000');
		expect(result.totalAmountMsat).to.equal(
			(50_000_000n + expectedFee).toString()
		);
		// Nothing was sent
		expect(bn.listPayments()).to.have.length(0);
	});

	it('queryRoute enforces maxFeeSats', () => {
		try {
			bn.queryRoute(bobPub.toString('hex'), 50_000, 0);
			expect.fail('should have thrown');
		} catch (err) {
			expect((err as BeignetError).code).to.equal('FEE_EXCEEDS_MAX');
		}
	});

	it('queryRoute throws NO_ROUTE for unknown destinations', () => {
		try {
			bn.queryRoute(pubkeyOf(98).toString('hex'), 1000);
			expect.fail('should have thrown');
		} catch (err) {
			expect((err as BeignetError).code).to.equal('NO_ROUTE');
		}
	});

	it('queryRoute validates destination and amount', () => {
		for (const call of [
			(): unknown => bn.queryRoute('xyz', 1000),
			(): unknown => bn.queryRoute(bobPub.toString('hex'), 0),
			(): unknown => bn.queryRoute(bobPub.toString('hex'), 1.5)
		]) {
			try {
				call();
				expect.fail('should have thrown');
			} catch (err) {
				expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
			}
		}
	});

	it('sendToRoute validates paymentHash and route shape', () => {
		const route = bn.queryRoute(bobPub.toString('hex'), 1000);
		for (const call of [
			(): unknown => bn.sendToRoute('nothex', route),
			(): unknown =>
				bn.sendToRoute(crypto.randomBytes(32).toString('hex'), { hops: [] }),
			(): unknown =>
				bn.sendToRoute(crypto.randomBytes(32).toString('hex'), route, 'short')
		]) {
			try {
				call();
				expect.fail('should have thrown');
			} catch (err) {
				expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
			}
		}
	});

	it('sendToRoute wires queryRoute output into sendPaymentToRoute', () => {
		// No real channel to the first hop exists, so the library rejects with
		// NO_CHANNEL_TO_HOP: proof the JSON route reached sendPaymentToRoute.
		const route = bn.queryRoute(bobPub.toString('hex'), 1000);
		try {
			bn.sendToRoute(crypto.randomBytes(32).toString('hex'), route);
			expect.fail('should have thrown');
		} catch (err) {
			expect((err as BeignetError).code).to.equal('NO_CHANNEL_TO_HOP');
		}
	});
});

// ─────────────── send-to-route end to end (loopback) ───────────────

describe('Graph query: send-to-route composes with route query (loopback)', () => {
	function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
		nodeA.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === nodeB.getNodeId()) {
					nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
				}
			}
		);
		nodeB.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === nodeA.getNodeId()) {
					nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
				}
			}
		);
	}

	function setupPair(
		aliceSeedId: number,
		bobSeedId: number
	): { alice: LightningNode; bob: LightningNode } {
		const alice = createNode(aliceSeedId);
		const bob = createNode(bobSeedId);
		connectNodes(alice, bob);
		const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		const scid = seedChannel(
			alice.getGraph(),
			Buffer.from(alice.getNodeId(), 'hex'),
			Buffer.from(bob.getNodeId(), 'hex')
		);
		alice.registerChannelScid(channelId, scid);
		return { alice, bob };
	}

	it('pays end to end along a queried route after a JSON roundtrip', () => {
		const { alice, bob } = setupPair(30, 31);
		const amountMsat = 50_000n;
		const invoice = bob.createInvoice({
			amountMsat,
			description: 'send-to-route e2e'
		});

		let received: IPaymentInfo | undefined;
		bob.on('payment:received', (info: IPaymentInfo) => {
			received = info;
		});

		const route = alice.queryRoute(
			Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat
		);
		expect(route).to.not.equal(null);
		// Simulate the daemon boundary: route -> JSON -> route
		const jsonHops = routeHopsToJson(route!);
		const hops = jsonToRouteHops(jsonHops);
		const finalHop = hops[hops.length - 1];

		const payment = alice.sendPaymentToRoute(
			{ hops },
			invoice.paymentHash,
			finalHop.outgoingCltvValue,
			invoice.paymentSecret,
			finalHop.amountToForwardMsat
		);

		// Synchronous loopback fulfills immediately
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(received).to.not.equal(undefined);
		expect(received!.direction).to.equal(PaymentDirection.INCOMING);
		expect(received!.amountMsat).to.equal(amountMsat);
		const sender = alice.getPayment(invoice.paymentHash);
		expect(sender!.status).to.equal(PaymentStatus.COMPLETED);
		alice.destroy();
		bob.destroy();
	});
});

// ─────────────── Daemon wiring + OpenAPI ───────────────

describe('Graph query: daemon routes + OpenAPI', () => {
	const daemonSrc = fs.readFileSync(
		path.join(__dirname, '../../src/cli/daemon.ts'),
		'utf8'
	);

	for (const route of [
		"'GET /graph/info'",
		"'GET /graph/node'",
		"'GET /graph/channel'",
		"'GET /graph/describe'",
		"'POST /route/query'",
		"'POST /payment/send-to-route'"
	]) {
		it(`daemon registers ${route}`, () => {
			expect(daemonSrc).to.include(route);
		});
	}

	it('OpenAPI documents the graph and send-to-route endpoints', () => {
		const { getOpenApiSpec } = require('../../src/cli/openapi');
		const spec = getOpenApiSpec();
		expect(spec.paths['/graph/info'].get).to.not.equal(undefined);
		expect(spec.paths['/graph/node'].get).to.not.equal(undefined);
		expect(spec.paths['/graph/channel'].get).to.not.equal(undefined);
		expect(spec.paths['/graph/describe'].get).to.not.equal(undefined);
		expect(spec.paths['/route/query'].post).to.not.equal(undefined);
		expect(spec.paths['/payment/send-to-route'].post).to.not.equal(undefined);
		expect(spec.components.schemas.RouteHop).to.not.equal(undefined);
		expect(spec.components.schemas.RouteQueryResult).to.not.equal(undefined);
		expect(spec.components.schemas.GraphNodeInfo).to.not.equal(undefined);
		expect(spec.components.schemas.GraphChannelInfo).to.not.equal(undefined);
	});
});
