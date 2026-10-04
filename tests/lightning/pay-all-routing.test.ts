import { expect } from 'chai';
import { findPayAllRoute } from '../../src/lightning/gossip/pay-all';
import {
	findRoute,
	policyOverrideKey,
	edgeDirection,
	calculateFee
} from '../../src/lightning/gossip/pathfinding';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { IChannelUpdateMessage } from '../../src/lightning/gossip/types';

const node = (id: number): Buffer => Buffer.alloc(33, id);
const scid = (id: number): Buffer => Buffer.alloc(8, id);
const source = node(1);
const peer = node(2);
const destination = node(3);
const now = Math.floor(Date.now() / 1000);

function edge(
	graph: NetworkGraph,
	from: Buffer,
	to: Buffer,
	id: number,
	changes: Partial<IChannelUpdateMessage> = {}
): IChannelUpdateMessage {
	const [nodeId1, nodeId2] =
		Buffer.compare(from, to) < 0 ? [from, to] : [to, from];
	graph.addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: Buffer.alloc(32),
		shortChannelId: scid(id),
		nodeId1,
		nodeId2,
		bitcoinKey1: source,
		bitcoinKey2: peer
	});
	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: Buffer.alloc(32),
		shortChannelId: scid(id),
		timestamp: now,
		messageFlags: 1,
		channelFlags: from.equals(nodeId1) ? 0 : 1,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 0n,
		htlcMaximumMsat: 1_000_000n,
		feeBaseMsat: 0,
		feeProportionalMillionths: 1000,
		...changes
	};
	graph.applyChannelUpdate(update);
	return update;
}

function fixture(changes: Partial<IChannelUpdateMessage> = {}) {
	const graph = new NetworkGraph(Buffer.alloc(32));
	const update = edge(graph, peer, destination, 2, changes);
	const options: Parameters<typeof findPayAllRoute>[0] = {
		graph,
		source,
		destination,
		debitMsat: 1000n,
		maxFeeMsat: 1n,
		finalCltvExpiry: 18,
		localChannels: [{ shortChannelId: scid(1), peer, outboundMsat: 1000n }]
	};
	return { options, update };
}

describe('Pay-all debit-aware routing', () => {
	it('finds a route the full-recipient search rejects and places the one-msat fee gap at the first hop', () => {
		const { options } = fixture();
		expect(
			findRoute(
				options.graph,
				source,
				destination,
				1000n,
				18,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				options.localChannels
			)
		).to.equal(null);
		const found = findPayAllRoute(options);
		expect(found.route!.hops.map((h) => h.amountToForwardMsat)).to.deep.equal([
			1000n,
			999n
		]);
		expect(found.route!.totalFeeMsat).to.equal(1n);
		expect(found.remainderMsat).to.equal(0n);
	});

	it('names the fee gap when the approved fee cap cannot absorb it', () => {
		const { options } = fixture();
		const found = findPayAllRoute({ ...options, maxFeeMsat: 0n });
		expect(found.route).to.equal(null);
		expect(found.remainderMsat).to.equal(1n);
	});

	it('does not turn a capacity-limited remainder into an extra fee', () => {
		const { options } = fixture({ htlcMaximumMsat: 500n });
		const found = findPayAllRoute({ ...options, maxFeeMsat: 600n });
		expect(found.route).to.equal(null);
		expect(found.remainderMsat).to.equal(500n);
	});

	it('finds a narrow feasible interval despite a high HTLC minimum', () => {
		const { options } = fixture({ htlcMinimumMsat: 999n });
		expect(
			findPayAllRoute(options).route!.hops[1].amountToForwardMsat
		).to.equal(999n);
		const impossible = fixture({ htlcMinimumMsat: 1000n });
		expect(findPayAllRoute(impossible.options).route).to.equal(null);
	});

	it('checks the actual padded local debit against the local HTLC minimum', () => {
		const { options } = fixture();
		options.localChannels[0].htlcMinimumMsat = 1000n;
		expect(findPayAllRoute(options).route!.totalAmountMsat).to.equal(1000n);
		options.localChannels[0].htlcMinimumMsat = 1001n;
		expect(findPayAllRoute(options).route).to.equal(null);
	});

	for (const changes of [
		{ channelFlags: 2 },
		{ timestamp: now - 15 * 86400 },
		{ cltvExpiryDelta: 3000 },
		{ htlcMinimumMsat: 2000n }
	]) {
		it(`refuses an unusable downstream policy: ${
			Object.keys(changes)[0]
		}`, () => {
			expect(findPayAllRoute(fixture(changes).options).route).to.equal(null);
		});
	}

	it('honors payment-scoped policies without modifying the graph', () => {
		const { options, update } = fixture();
		options.policyOverrides = new Map([
			[
				policyOverrideKey(
					scid(2).toString('hex'),
					edgeDirection(peer.toString('hex'), destination.toString('hex'))
				),
				{ ...update, feeProportionalMillionths: 0 }
			]
		]);
		expect(
			findPayAllRoute(options).route!.hops[1].amountToForwardMsat
		).to.equal(1000n);
		expect(
			findPayAllRoute({ ...options, policyOverrides: undefined }).route!.hops[1]
				.amountToForwardMsat
		).to.equal(999n);
	});

	it('uses private routing hints, including a leading self hint', () => {
		const { options } = fixture();
		options.graph = new NetworkGraph();
		options.routingHints = [
			[
				{
					pubkey: source,
					shortChannelId: scid(1),
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 0
				},
				{
					pubkey: peer,
					shortChannelId: scid(2),
					feeBaseMsat: 0,
					feeProportionalMillionths: 1000,
					cltvExpiryDelta: 40
				}
			]
		];
		expect(
			findPayAllRoute(options).route!.hops[1].amountToForwardMsat
		).to.equal(999n);
	});

	it('never falls back to graph-only first hops when local channels are unavailable', () => {
		const { options } = fixture();
		edge(options.graph, source, peer, 1, { feeProportionalMillionths: 0 });
		expect(findPayAllRoute({ ...options, localChannels: [] }).route).to.equal(
			null
		);
		options.localChannels[0].outboundMsat = 999n;
		expect(findPayAllRoute(options).route).to.equal(null);
	});

	it('maximizes recipient amount across paths and honors full local admission', () => {
		const { options } = fixture();
		const other = node(4);
		edge(options.graph, other, destination, 4, {
			feeProportionalMillionths: 0
		});
		options.localChannels.push({
			shortChannelId: scid(3),
			peer: other,
			outboundMsat: 1000n
		});
		expect(findPayAllRoute(options).route!.totalFeeMsat).to.equal(0n);
		options.canSend = (route) => !route.hops[0].pubkey.equals(other);
		expect(findPayAllRoute(options).route!.totalFeeMsat).to.equal(1n);
		options.excludedChannels = new Set([scid(2).toString('hex')]);
		expect(findPayAllRoute(options).route).to.equal(null);
	});

	it('refuses a bounded search that has not proved the maximum', () => {
		const { options } = fixture();
		const found = findPayAllRoute({ ...options, maxCandidates: 1 });
		expect(found.route).to.equal(null);
		expect(found.searchExhausted).to.equal(true);
	});

	it('matches exhaustive fixed-path pricing over fee-rounding boundaries', () => {
		for (const ppm of [0, 1000, 99999, 1000000]) {
			for (let debit = 90n; debit <= 130n; debit++) {
				const { options } = fixture({
					feeBaseMsat: 2,
					feeProportionalMillionths: ppm
				});
				options.debitMsat = debit;
				options.maxFeeMsat = debit - 1n;
				let best = 0n;
				for (let amount = 1n; amount <= debit; amount++) {
					if (amount + calculateFee(amount, 2, ppm) <= debit) best = amount;
				}
				const route = findPayAllRoute(options).route!;
				expect(route.hops[1].amountToForwardMsat).to.equal(best);
				expect(route.totalAmountMsat).to.equal(debit);
			}
		}
	});
});
