/**
 * S-7.M1 (remainder) regression: gossip must be scoped to the node's OWN
 * chain, not hardcoded mainnet.
 *
 * Before this fix `NetworkGraph.addChannelAnnouncement` accepted ONLY
 * mainnet announcements (so a regtest/testnet/signet node's graph stayed
 * permanently empty and pathfinding had nothing to work with), and the
 * node's own channel_announcement/channel_update — including the SIGNED
 * announcement digest — defaulted to the mainnet chain hash on every
 * network, so conformant peers discarded them.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelAnnouncementMessage } from '../../src/lightning/gossip/types';

function makeAnnouncement(chainHash: Buffer): IChannelAnnouncementMessage {
	// nodeId1 < nodeId2 lexicographically (required by the graph).
	const nodeId1 = Buffer.concat([Buffer.from([0x02]), crypto.randomBytes(32)]);
	const nodeId2 = Buffer.concat([Buffer.from([0x03]), crypto.randomBytes(32)]);
	return {
		nodeSignature1: crypto.randomBytes(64),
		nodeSignature2: crypto.randomBytes(64),
		bitcoinSignature1: crypto.randomBytes(64),
		bitcoinSignature2: crypto.randomBytes(64),
		features: Buffer.alloc(0),
		chainHash,
		shortChannelId: crypto.randomBytes(8),
		nodeId1,
		nodeId2,
		bitcoinKey1: Buffer.concat([Buffer.from([0x02]), crypto.randomBytes(32)]),
		bitcoinKey2: Buffer.concat([Buffer.from([0x03]), crypto.randomBytes(32)])
	};
}

describe('S-7.M1: chain-scoped gossip', function () {
	it('a regtest graph accepts regtest announcements and rejects mainnet', function () {
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH);
		expect(
			graph.addChannelAnnouncement(makeAnnouncement(REGTEST_CHAIN_HASH))
		).to.equal(true);
		expect(
			graph.addChannelAnnouncement(makeAnnouncement(BITCOIN_CHAIN_HASH))
		).to.equal(false);
		expect(graph.getChannelCount()).to.equal(1);
	});

	it('the default graph stays mainnet-scoped', function () {
		const graph = new NetworkGraph();
		expect(
			graph.addChannelAnnouncement(makeAnnouncement(BITCOIN_CHAIN_HASH))
		).to.equal(true);
		expect(
			graph.addChannelAnnouncement(makeAnnouncement(REGTEST_CHAIN_HASH))
		).to.equal(false);
	});

	it('the SIGNED channel_announcement digest carries the channel chain scope', function () {
		// The signing digest and the emitted announcement come from the same
		// builder; a mainnet-hardcoded digest makes non-mainnet announcement
		// signatures invalid for the actual chain.
		const {
			createOpenerChannel
		} = require('../../src/lightning/channel/channel');
		const { getPublicKey } = require('../../src/lightning/crypto/ecdh');
		const channel = createOpenerChannel({
			fundingSatoshis: 1_000_000n,
			localBasepoints: {
				fundingPubkey: getPublicKey(crypto.randomBytes(32)),
				revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
				paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
				delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
				htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
				firstPerCommitmentPoint: Buffer.alloc(33)
			},
			localPerCommitmentSeed: crypto.randomBytes(32)
		});
		channel.getFullState().remoteBasepoints =
			channel.getFullState().localBasepoints;
		channel.getFullState().shortChannelId = crypto.randomBytes(8);
		channel.announcementChainHash = REGTEST_CHAIN_HASH;

		const nodeId1 = Buffer.concat([
			Buffer.from([0x02]),
			crypto.randomBytes(32)
		]);
		const nodeId2 = Buffer.concat([
			Buffer.from([0x03]),
			crypto.randomBytes(32)
		]);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const digest: Buffer = (channel as any).buildAnnouncementData(
			nodeId1,
			nodeId2
		);
		// Layout after the signatures: [2: flen=0][32: chain_hash][8: scid]...
		expect(digest.subarray(2, 34).equals(REGTEST_CHAIN_HASH)).to.equal(true);
	});
});
