/**
 * M1.2 — createInvoice generates receiver route-blinding blinded paths.
 *
 * Injects a NORMAL channel with a known peer + SCID, then asserts that
 * createInvoice({ useBlindedPaths: true }) emits a blinded path whose
 * introduction node is the peer (not us), sets ROUTE_BLINDING, and omits
 * cleartext routing hints.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { decode } from '../../src/lightning/invoice/decode';
import { Feature } from '../../src/lightning/features/flags';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';

function validPriv(): Buffer {
	let k: Buffer;
	do {
		k = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(k));
	return k;
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

function injectNormalChannel(
	node: LightningNode
): { channelId: Buffer; peerPubkey: Buffer; scid: Buffer } {
	const channelId = crypto.randomBytes(32);
	const peerPubkey = getPublicKey(validPriv());
	const scid = encodeShortChannelId({ block: 800000, txIndex: 1, outputIndex: 0 });

	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = channelId;
	state.scidAlias = scid;

	const channel = new Channel(state);
	const cm = (node as any).channelManager;
	cm.channels.set(channelId.toString('hex'), channel);
	cm.channelPeers.set(channelId.toString('hex'), peerPubkey.toString('hex'));
	return { channelId, peerPubkey, scid };
}

describe('createInvoice blinded paths (M1.2)', function () {
	function makeNode(): LightningNode {
		const node = new LightningNode({
			nodePrivateKey: validPriv(),
			channelBasepoints: makeBasepoints(),
			perCommitmentSeed: crypto.randomBytes(32),
			fundingPrivkey: validPriv(),
			network: Network.REGTEST
		});
		node.on('error', () => {});
		return node;
	}

	it('emits a blinded path with the peer as introduction node', function () {
		const node = makeNode();
		const { peerPubkey } = injectNormalChannel(node);
		const ourNodeId = Buffer.from(node.getNodeId(), 'hex');

		const res = node.createInvoice({
			description: 'blinded',
			amountMsat: 100_000n,
			useBlindedPaths: true
		});

		const inv = decode(res.bolt11);
		expect(inv.blindedPaths, 'has blinded paths').to.have.length(1);
		const bp = inv.blindedPaths![0];
		// Introduction node is the PEER, not us — that's the privacy property.
		expect(bp.path.introductionNodeId).to.deep.equal(peerPubkey);
		expect(bp.path.introductionNodeId).to.not.deep.equal(ourNodeId);
		// 2-hop path: [peer, us].
		expect(bp.path.blindedHops).to.have.length(2);
		// Pay info is populated.
		expect(bp.payInfo.htlcMaximumMsat).to.equal(1_000_000n * 1000n);

		// ROUTE_BLINDING advertised; cleartext hints suppressed for privacy.
		expect(inv.featureBits!.hasFeature(Feature.ROUTE_BLINDING)).to.be.true;
		expect(inv.routingHints).to.be.undefined;

		node.destroy();
	});

	it('falls back to cleartext hints when useBlindedPaths is not set', function () {
		const node = makeNode();
		injectNormalChannel(node);

		const inv = decode(
			node.createInvoice({ description: 'plain', amountMsat: 100_000n }).bolt11
		);
		expect(inv.blindedPaths).to.be.undefined;
		expect(inv.routingHints, 'cleartext hint present').to.have.length(1);

		node.destroy();
	});

	it('falls back to cleartext hints when no channel can be blinded', function () {
		const node = makeNode();
		// No channels injected → no blinded path can be built.
		const inv = decode(
			node.createInvoice({
				description: 'no-chan',
				amountMsat: 100_000n,
				useBlindedPaths: true
			}).bolt11
		);
		expect(inv.blindedPaths).to.be.undefined;
		expect(inv.featureBits!.hasFeature(Feature.ROUTE_BLINDING)).to.be.false;

		node.destroy();
	});
});
