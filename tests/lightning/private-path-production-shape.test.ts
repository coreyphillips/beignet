/**
 * Production shape of the private-path machinery (issue #544 review).
 *
 * The stubbed-builder tests in offer-private-payment-paths.test.ts pin the
 * OfferManager's selection logic; these pin what the REAL builders emit, by
 * decrypting the hops exactly as the relaying peer would:
 * - a payment relay hop is SCID-addressed ONLY (BOLT 4 allows exactly one of
 *   short_channel_id and next_node_id; emitting both made compliant
 *   introduction nodes reject the path);
 * - the advertised payinfo includes our final min_final CLTV delta and the
 *   peer's real amount bounds (a blinded path hides the hops, so the payer
 *   cannot infer any of it);
 * - the payment_constraints absolute CLTV bound is never an already-expired
 *   height (pre-sync height 0 used to publish max_cltv_expiry 2016);
 * - a message hop is next_node_id-addressed with no payment records;
 * - the public-reachability gate demands exchanged announcement_signatures,
 *   not the announceChannel intent flag (pending and wire-private taproot
 *   channels keep the flag true).
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
import {
	processBlindedHop,
	IBlindedPath,
	IBlindedPaymentPath
} from '../../src/lightning/onion/blinded-path';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

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

const PEER_POLICY = {
	feeBaseMsat: 1_000,
	feeProportionalMillionths: 250,
	cltvExpiryDelta: 40,
	htlcMinimumMsat: 1_000n,
	htlcMaximumMsat: 300_000_000n,
	timestamp: 1
};

interface IHarness {
	node: LightningNode;
	peerPriv: Buffer;
	peerPubkey: Buffer;
	scid: Buffer;
	state: ReturnType<Channel['getFullState']>;
}

function nodeWithChannel(): IHarness {
	const node = new LightningNode({
		nodePrivateKey: validPriv(),
		channelBasepoints: makeBasepoints(),
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: validPriv(),
		network: Network.REGTEST
	});
	node.on('error', () => {});
	const peerPriv = validPriv();
	const peerPubkey = getPublicKey(peerPriv);
	const scid = encodeShortChannelId({
		block: 800000,
		txIndex: 5,
		outputIndex: 0
	});
	const channelId = crypto.randomBytes(32);
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
	state.remoteScidAlias = scid;
	state.remoteForwardingPolicy = { ...PEER_POLICY };
	const cm = (node as any).channelManager;
	cm.channels.set(channelId.toString('hex'), new Channel(state));
	cm.channelPeers.set(channelId.toString('hex'), peerPubkey.toString('hex'));
	return { node, peerPriv, peerPubkey, scid, state };
}

type NodeInternals = {
	currentBlockHeight: number;
	buildBlindedPaymentPaths: (
		asyncHold: boolean,
		numHops: number,
		pathId?: Buffer
	) => IBlindedPaymentPath[];
	buildBlindedMessagePaths: (
		numHops: number,
		pathId?: Buffer
	) => IBlindedPath[];
	hasPublishedPublicChannel: () => boolean;
};

describe('Private payment path production shape (issue #544)', () => {
	it('payment relay hops are SCID-addressed only, with the peer policy', () => {
		const h = nodeWithChannel();
		try {
			const pathId = crypto.randomBytes(32);
			const paths = (
				h.node as unknown as NodeInternals
			).buildBlindedPaymentPaths(false, 2, pathId);
			expect(paths).to.have.length(1);
			const { hopData } = processBlindedHop(
				paths[0].path.blindingPoint,
				h.peerPriv,
				paths[0].path.blindedHops[0].encryptedData
			);
			// Exactly one identifier: SCID for payment relay.
			expect(hopData.shortChannelId).to.deep.equal(h.scid);
			expect(hopData.nextNodeId, 'exactly one identifier').to.be.undefined;
			expect(hopData.paymentRelay!.feeBaseMsat).to.equal(
				PEER_POLICY.feeBaseMsat
			);
			expect(hopData.paymentConstraints!.htlcMinimumMsat).to.equal(
				PEER_POLICY.htlcMinimumMsat
			);
			expect(hopData.holdHtlc, 'no hold on a plain path').to.equal(undefined);
		} finally {
			h.node.destroy();
		}
	});

	it('payinfo includes the final delta and the peer amount bounds', () => {
		const h = nodeWithChannel();
		try {
			const paths = (
				h.node as unknown as NodeInternals
			).buildBlindedPaymentPaths(false, 2);
			const info = paths[0].payInfo;
			// Relay delta 40 + our DEFAULT_MIN_FINAL_CLTV_EXPIRY 40: the payer
			// cannot add a final delta it cannot see.
			expect(info.cltvExpiryDelta).to.equal(PEER_POLICY.cltvExpiryDelta + 40);
			expect(info.htlcMinimumMsat).to.equal(PEER_POLICY.htlcMinimumMsat);
			// Peer policy max (300k sats) is below capacity (1M sats): it wins.
			expect(info.htlcMaximumMsat).to.equal(PEER_POLICY.htlcMaximumMsat);
		} finally {
			h.node.destroy();
		}
	});

	it('caps payinfo max at capacity when the peer policy allows more', () => {
		const h = nodeWithChannel();
		try {
			h.state.remoteForwardingPolicy!.htlcMaximumMsat = 5_000_000_000n;
			const paths = (
				h.node as unknown as NodeInternals
			).buildBlindedPaymentPaths(false, 2);
			expect(paths[0].payInfo.htlcMaximumMsat).to.equal(
				1_000_000n * 1000n // capacity in msat
			);
		} finally {
			h.node.destroy();
		}
	});

	it('never publishes an already-expired absolute CLTV bound', () => {
		const h = nodeWithChannel();
		try {
			const internals = h.node as unknown as NodeInternals;
			// Pre-sync (height 0): the bound must not be height 2016, which
			// the chain passed years ago; it degrades to the encoding maximum.
			let paths = internals.buildBlindedPaymentPaths(false, 2);
			let { hopData } = processBlindedHop(
				paths[0].path.blindingPoint,
				h.peerPriv,
				paths[0].path.blindedHops[0].encryptedData
			);
			expect(hopData.paymentConstraints!.maxCltvExpiry).to.equal(499_999_999);
			// Synced: a real bound from the tip.
			internals.currentBlockHeight = 800_000;
			paths = internals.buildBlindedPaymentPaths(false, 2);
			({ hopData } = processBlindedHop(
				paths[0].path.blindingPoint,
				h.peerPriv,
				paths[0].path.blindedHops[0].encryptedData
			));
			expect(hopData.paymentConstraints!.maxCltvExpiry).to.equal(
				800_000 + 2016
			);
		} finally {
			h.node.destroy();
		}
	});

	it('message hops are node-id-addressed with no payment records', () => {
		const h = nodeWithChannel();
		try {
			const pathId = crypto.randomBytes(32);
			const paths = (
				h.node as unknown as NodeInternals
			).buildBlindedMessagePaths(2, pathId);
			expect(paths).to.have.length(1);
			expect(paths[0].introductionNodeId).to.deep.equal(h.peerPubkey);
			const peerHop = processBlindedHop(
				paths[0].blindingPoint,
				h.peerPriv,
				paths[0].blindedHops[0].encryptedData
			);
			expect(peerHop.hopData.nextNodeId).to.deep.equal(
				Buffer.from(h.node.getNodeId(), 'hex')
			);
			expect(peerHop.hopData.shortChannelId).to.be.undefined;
			expect(peerHop.hopData.paymentRelay).to.be.undefined;
			expect(peerHop.hopData.paymentConstraints).to.be.undefined;
			// Final hop carries the binding path_id.
			const finalHop = processBlindedHop(
				peerHop.nextBlindingKey,
				(h.node as unknown as { nodePrivkey: Buffer }).nodePrivkey,
				paths[0].blindedHops[1].encryptedData
			);
			expect(finalHop.hopData.pathId).to.deep.equal(pathId);
		} finally {
			h.node.destroy();
		}
	});

	it('reachability needs exchanged announcement signatures, not the intent flag', () => {
		const h = nodeWithChannel();
		try {
			const internals = h.node as unknown as NodeInternals;
			// Intent flag alone (pending public channel, or a preferTaproot
			// opener whose wire flag is private): NOT publicly reachable.
			h.state.announceChannel = true;
			expect(internals.hasPublishedPublicChannel()).to.equal(false);
			// Wire-private taproot keeps the flag true too; still private.
			const taproot = FeatureFlags.empty();
			taproot.setCompulsory(Feature.OPTION_TAPROOT);
			h.state.channelType = taproot.toBuffer();
			expect(internals.hasPublishedPublicChannel()).to.equal(false);
			// Announcement signatures exchanged: the channel_announcement is
			// out; payers can find us.
			h.state.channelType = null;
			h.state.announcementSigsSent = true;
			h.state.announcementSigsReceived = true;
			expect(internals.hasPublishedPublicChannel()).to.equal(true);
		} finally {
			h.node.destroy();
		}
	});

	it('an unannounced node auto-builds offer message paths; a published one does not', () => {
		const h = nodeWithChannel();
		try {
			// Unannounced: BOLT 12 requires reachable paths, or no external
			// payer can deliver an invoice_request at all.
			const { offer } = h.node.createOffer({ description: 'private' });
			expect(offer.paths, 'offer carries a message path').to.have.length(1);
			expect(offer.paths![0].introductionNodeId).to.deep.equal(h.peerPubkey);
			// And the offer names its chain: without offer_chains BOLT 12
			// implies MAINNET, and a compliant payer on regtest refuses the
			// offer as wrong-chain before anything else happens (observed
			// live against CLN's fetchinvoice; issue #544 review).
			expect(offer.chains, 'regtest offer names its chain').to.have.length(1);
			// Published public channel: reachable through the graph, no paths.
			h.state.announceChannel = true;
			h.state.announcementSigsSent = true;
			h.state.announcementSigsReceived = true;
			const { offer: publicOffer } = h.node.createOffer({
				description: 'public'
			});
			expect(publicOffer.paths ?? []).to.have.length(0);
		} finally {
			h.node.destroy();
		}
	});
});
