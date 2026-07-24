/**
 * Regression: an invoice routing hint whose SCID is already announced in the
 * gossip graph must not disable the graph edge it points at.
 *
 * buildSyntheticEdges defers to the graph for announced SCIDs (no synthetic
 * edge), but buildHintDestinationMap used to claim the SCID anyway. During
 * traversal that claim flips the real graph channel into hint-edge semantics
 * (upstream = nodeId1), and whenever the destination happens to BE nodeId1
 * the edge becomes a dead self-loop: the payer gets NO_ROUTE on the exact
 * channel the invoice hint was advertising.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`hint-map-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
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
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		// Secret behind makeBasepoints' htlcBasepoint (keys[4]): without it
		// per-HTLC signatures use a fallback key and the peer rejects them.
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
	};
}

describe('Pathfinding: announced-channel routing hints', function () {
	it('a hint for an announced channel does not kill the graph edge', function () {
		const alice = new LightningNode(makeNodeConfig(1));
		const bob = new LightningNode(makeNodeConfig(2));
		for (const n of [alice, bob]) {
			n.on('error', () => {});
			n.on('node:error', () => {});
		}
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === bob.getNodeId()) {
				bob.handlePeerMessage(alice.getNodeId(), t, p);
			}
		});
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === alice.getNodeId()) {
				alice.handlePeerMessage(bob.getNodeId(), t, p);
			}
		});

		const aBuf = Buffer.from(alice.getNodeId(), 'hex');
		const bBuf = Buffer.from(bob.getNodeId(), 'hex');
		// The bug only bites when the DESTINATION is nodeId1 (the
		// lexicographically smaller pubkey). The seed prefix was chosen to make
		// bob node1; if this assertion ever fails, pick a new prefix.
		expect(Buffer.compare(bBuf, aBuf) < 0, 'bob must be nodeId1').to.be.true;

		const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);

		// Announce the channel into both graphs with both directions enabled,
		// exactly as the gossip machinery does after 6 confirmations, and give
		// the channel its real SCID so bob's invoice hints carry it.
		const [n1, n2] =
			Buffer.compare(aBuf, bBuf) < 0 ? [aBuf, bBuf] : [bBuf, aBuf];
		const scid = encodeShortChannelId({
			block: 700_000,
			txIndex: 1,
			outputIndex: 0
		});
		for (const n of [alice, bob]) {
			const g = n.getGraph();
			g.addChannelAnnouncement({
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: scid,
				nodeId1: n1,
				nodeId2: n2,
				bitcoinKey1: Buffer.alloc(33, 2),
				bitcoinKey2: Buffer.alloc(33, 3)
			});
			const base = {
				signature: Buffer.alloc(64),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				htlcMaximumMsat: 500_000_000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1
			};
			g.applyChannelUpdate({ ...base });
			g.applyChannelUpdate({ ...base, channelFlags: 1 });
			const ch = n.getChannelManager().getChannel(channelId);
			if (ch) ch.getFullState().shortChannelId = scid;
			n.registerChannelScid(channelId, scid);
		}

		// Sanity: the graph alone routes this.
		expect(alice.queryRoute(bBuf, 100_000_000n)).to.not.equal(null);

		// The payment decodes bob's invoice, whose hint carries the announced
		// SCID. Without the fix this threw NO_ROUTE.
		const inv = bob.createInvoice({
			amountMsat: 100_000_000n,
			description: 'announced hint'
		});
		const res = alice.sendPayment(inv.bolt11);
		expect(res.status).to.equal(PaymentStatus.COMPLETED);
	});
});
