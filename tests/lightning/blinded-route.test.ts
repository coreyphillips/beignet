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
