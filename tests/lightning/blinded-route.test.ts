/**
 * M1.3 — findRouteToBlindedPath builds the blinded tail correctly.
 *
 * Verifies the introduction-node hop carries the blinding point + its encrypted
 * data, downstream blinded hops carry only their encrypted data, the blinded
 * section's aggregate fee is folded in at the introduction node, and the
 * recipient still receives exactly the requested amount.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { findRouteToBlindedPath } from '../../src/lightning/gossip/pathfinding';
import {
	encodeShortChannelId,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	MESSAGE_FLAG_HTLC_MAX
} from '../../src/lightning/gossip/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import { IBlindedPath } from '../../src/lightning/onion/blinded-path';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function nodeId(): Buffer {
	return getPublicKey(crypto.randomBytes(32));
}

function announce(
	scid: Buffer,
	a: Buffer,
	b: Buffer
): IChannelAnnouncementMessage {
	const [n1, n2] = Buffer.compare(a, b) < 0 ? [a, b] : [b, a];
	return {
		nodeSignature1: crypto.randomBytes(64),
		nodeSignature2: crypto.randomBytes(64),
		bitcoinSignature1: crypto.randomBytes(64),
		bitcoinSignature2: crypto.randomBytes(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: n1,
		nodeId2: n2,
		bitcoinKey1: crypto.randomBytes(33),
		bitcoinKey2: crypto.randomBytes(33)
	};
}

function update(scid: Buffer, dir: number): IChannelUpdateMessage {
	return {
		signature: crypto.randomBytes(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: 1000,
		messageFlags: MESSAGE_FLAG_HTLC_MAX,
		channelFlags: dir,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
}

describe('findRouteToBlindedPath blinded tail (M1.3)', function () {
	it('attaches blinding fields and folds the blinded fee at the intro node', function () {
		const graph = new NetworkGraph();
		const alice = nodeId();
		const bob = nodeId(); // introduction node
		const scid = encodeShortChannelId({
			block: 100,
			txIndex: 1,
			outputIndex: 0
		});
		graph.addChannelAnnouncement(announce(scid, alice, bob));
		const aliceFirst = Buffer.compare(alice, bob) < 0;
		graph.applyChannelUpdate(update(scid, aliceFirst ? 0 : 1));
		graph.applyChannelUpdate(update(scid, aliceFirst ? 1 : 0));

		// Blinded path [bob (intro), recipient]. blindedHops[0] = intro node.
		const introData = crypto.randomBytes(24);
		const finalData = crypto.randomBytes(18);
		const blindingPoint = nodeId();
		const blindedPath: IBlindedPath = {
			introductionNodeId: bob,
			blindingPoint,
			blindedHops: [
				{ blindedNodeId: nodeId(), encryptedData: introData },
				{ blindedNodeId: nodeId(), encryptedData: finalData }
			]
		};
		const payInfo = {
			feeBaseMsat: 500,
			feeProportionalMillionths: 1000, // 0.1%
			cltvExpiryDelta: 100,
			htlcMinimumMsat: 0n,
			htlcMaximumMsat: 1_000_000_000n
		};

		const amount = 1_000_000n;
		const route = findRouteToBlindedPath(
			graph,
			alice,
			blindedPath,
			payInfo,
			amount,
			40
		);
		expect(route, 'route found').to.not.be.null;

		const hops = route!.hops;
		// Last hop = recipient, carries only its encrypted data, exact amount.
		const recipient = hops[hops.length - 1];
		expect(recipient.encryptedRecipientData).to.deep.equal(finalData);
		expect(recipient.blindingPoint).to.be.undefined;
		expect(recipient.amountToForwardMsat).to.equal(amount);

		// Previous hop = introduction node (bob), carries blinding point + data.
		const intro = hops[hops.length - 2];
		expect(intro.encryptedRecipientData).to.deep.equal(introData);
		expect(intro.blindingPoint).to.deep.equal(blindingPoint);

		// Blinded fee folded in: intro receives amount + base + 0.1%.
		const expectedFee = 500n + (amount * 1000n) / 1_000_000n;
		expect(intro.amountToForwardMsat).to.equal(amount + expectedFee);

		// The route's fee is everything sent beyond what the recipient
		// receives, the payee-written blinded fee included (issue #1001): over
		// a direct channel to the introduction node this reported 0 while
		// totalAmountMsat carried the fee.
		expect(route!.totalFeeMsat).to.equal(route!.totalAmountMsat - amount);
		expect(route!.totalFeeMsat).to.equal(expectedFee);
	});

	it('returns just the blinded tail when source is the intro node', function () {
		const graph = new NetworkGraph();
		const me = nodeId();
		const blindedPath: IBlindedPath = {
			introductionNodeId: me,
			blindingPoint: nodeId(),
			blindedHops: [
				{ blindedNodeId: nodeId(), encryptedData: crypto.randomBytes(20) },
				{ blindedNodeId: nodeId(), encryptedData: crypto.randomBytes(20) }
			]
		};
		const route = findRouteToBlindedPath(
			graph,
			me,
			blindedPath,
			{
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: 1_000_000_000n
			},
			5000n,
			40
		);
		expect(route!.hops).to.have.length(2);
		// Intro hop's real pubkey is known (it's us).
		expect(route!.hops[0].pubkey).to.deep.equal(me);
		expect(route!.hops[0].blindingPoint).to.deep.equal(
			blindedPath.blindingPoint
		);
	});
});

/** alice with one public channel to bob, and a blinded path introduced at bob. */
function directWorld(): {
	graph: NetworkGraph;
	alice: Buffer;
	bob: Buffer;
	blindedPath: IBlindedPath;
} {
	const graph = new NetworkGraph();
	const alice = nodeId();
	const bob = nodeId();
	const scid = encodeShortChannelId({ block: 100, txIndex: 1, outputIndex: 0 });
	graph.addChannelAnnouncement(announce(scid, alice, bob));
	const aliceFirst = Buffer.compare(alice, bob) < 0;
	graph.applyChannelUpdate(update(scid, aliceFirst ? 0 : 1));
	graph.applyChannelUpdate(update(scid, aliceFirst ? 1 : 0));
	const blindedPath: IBlindedPath = {
		introductionNodeId: bob,
		blindingPoint: nodeId(),
		blindedHops: [
			{ blindedNodeId: nodeId(), encryptedData: crypto.randomBytes(24) },
			{ blindedNodeId: nodeId(), encryptedData: crypto.randomBytes(18) }
		]
	};
	return { graph, alice, bob, blindedPath };
}

describe('findRouteToBlindedPath payinfo htlc bounds (issue #1001)', function () {
	// 500 msat + 0.1% on 1_000_000 msat: 1_001_500 msat enters the blinded
	// section at the introduction node, and the recipient receives
	// 1_000_000. The bounds apply to the RECIPIENT'S amount: every writer
	// expresses them net of the path's fees.
	const amount = 1_000_000n;
	const atIntro = 1_001_500n;
	const payInfo = (bounds: {
		min: bigint;
		max: bigint;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
	}) => ({
		feeBaseMsat: bounds.feeBaseMsat ?? 500,
		feeProportionalMillionths: bounds.feeProportionalMillionths ?? 1000,
		cltvExpiryDelta: 100,
		htlcMinimumMsat: bounds.min,
		htlcMaximumMsat: bounds.max
	});

	it('refuses a path whose htlc_minimum_msat is above the amount', function () {
		const { graph, alice, blindedPath } = directWorld();
		expect(
			findRouteToBlindedPath(
				graph,
				alice,
				blindedPath,
				payInfo({ min: amount + 1n, max: 1_000_000_000n }),
				amount,
				40
			),
			'one msat over the amount refuses'
		).to.be.null;
		const route = findRouteToBlindedPath(
			graph,
			alice,
			blindedPath,
			payInfo({ min: amount, max: 1_000_000_000n }),
			amount,
			40
		);
		expect(route, 'the bound itself admits').to.not.be.null;
		expect(route!.totalAmountMsat).to.equal(atIntro);
	});

	it('refuses a path whose htlc_maximum_msat is below the amount', function () {
		const { graph, alice, blindedPath } = directWorld();
		expect(
			findRouteToBlindedPath(
				graph,
				alice,
				blindedPath,
				payInfo({ min: 0n, max: amount - 1n }),
				amount,
				40
			),
			'one msat under the amount refuses'
		).to.be.null;
		expect(
			findRouteToBlindedPath(
				graph,
				alice,
				blindedPath,
				payInfo({ min: 0n, max: amount }),
				amount,
				40
			),
			'the bound itself admits'
		).to.not.be.null;
	});

	it('routes an eclair-shaped invoice: htlc_maximum_msat equals the amount and the path charges a fee', function () {
		// eclair seeds the aggregate maximum with the invoice amount and only
		// lowers it, so with any fee the amount at the introduction node is
		// above the maximum. Judging that amount refused every eclair BOLT 12
		// invoice with a fee-bearing path.
		const { graph, alice, blindedPath } = directWorld();
		const route = findRouteToBlindedPath(
			graph,
			alice,
			blindedPath,
			payInfo({ min: 1n, max: amount }),
			amount,
			40
		);
		expect(route, 'routes').to.not.be.null;
		expect(route!.totalAmountMsat).to.equal(atIntro);
		expect(route!.totalFeeMsat).to.equal(atIntro - amount);
	});

	it('routes an LDK-shaped invoice: the amount equals the channel maximum net of the path fee', function () {
		// LDK's compute_payinfo subtracts each relay fee from the channel's
		// htlc_maximum_msat, so an invoice for exactly that maximum has
		// amount == max and amount + fee == the channel's real limit.
		const { graph, alice, blindedPath } = directWorld();
		const channelMax = 5_000_000n;
		const feeBaseMsat = 250;
		const feeProportionalMillionths = 0;
		const max = channelMax - BigInt(feeBaseMsat);
		const route = findRouteToBlindedPath(
			graph,
			alice,
			blindedPath,
			payInfo({ min: 1n, max, feeBaseMsat, feeProportionalMillionths }),
			max,
			40
		);
		expect(route, 'routes').to.not.be.null;
		expect(route!.totalAmountMsat).to.equal(channelMax);
		expect(route!.totalFeeMsat).to.equal(BigInt(feeBaseMsat));
	});

	it('a payinfo maximum of 0 admits nothing: the decoder has no absent value', function () {
		const { graph, alice, blindedPath } = directWorld();
		expect(
			findRouteToBlindedPath(
				graph,
				alice,
				blindedPath,
				payInfo({ min: 0n, max: 0n }),
				amount,
				40
			)
		).to.be.null;
	});

	it('applies the bounds to the self-introduction tail as well', function () {
		const { graph, blindedPath } = directWorld();
		const me = blindedPath.introductionNodeId;
		expect(
			findRouteToBlindedPath(
				graph,
				me,
				blindedPath,
				payInfo({ min: 0n, max: amount - 1n }),
				amount,
				40
			)
		).to.be.null;
		expect(
			findRouteToBlindedPath(
				graph,
				me,
				blindedPath,
				payInfo({ min: amount, max: amount }),
				amount,
				40
			)
		).to.not.be.null;
	});
});
