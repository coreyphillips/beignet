/**
 * Regression: payment retry never dispatched.
 *
 * The retry marked the existing payment PENDING and then re-entered
 * sendPayment(), whose deduplication rejects a hash that is already in flight.
 * Every retry therefore threw DUPLICATE_PAYMENT into an empty catch and fell
 * through to marking the payment failed, so a payment that failed for a purely
 * temporary reason was abandoned on the first attempt even though
 * maxPaymentRetries defaults to 3.
 *
 * Nothing covered this, because the catch swallowed the error and blamed it on
 * "no alternative route".
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import { TEMPORARY_NODE_FAILURE } from '../../src/lightning/onion/types';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`retry-seed-${id}`))
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
			.digest()
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function setupPair(
	aliceSeed: number,
	bobSeed: number
): {
	alice: LightningNode;
	bob: LightningNode;
} {
	const alice = createNode(aliceSeed);
	const bob = createNode(bobSeed);

	alice.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === bob.getNodeId()) {
			bob.handlePeerMessage(alice.getNodeId(), type, payload);
		}
	});
	bob.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === alice.getNodeId()) {
			alice.handlePeerMessage(bob.getNodeId(), type, payload);
		}
	});

	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);

	const apk = Buffer.from(alice.getNodeId(), 'hex');
	const bpk = Buffer.from(bob.getNodeId(), 'hex');
	const aliceIsNode1 = Buffer.compare(apk, bpk) < 0;
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });

	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aliceIsNode1 ? apk : bpk,
		nodeId2: aliceIsNode1 ? bpk : apk,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	const update1: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};

	alice.getGraph().addChannelAnnouncement(announcement);
	alice.getGraph().applyChannelUpdate(update1);
	alice.getGraph().applyChannelUpdate({ ...update1, channelFlags: 1 });
	alice.registerChannelScid(channelId, scid);

	return { alice, bob };
}

/**
 * Make bob reject every incoming HTLC with a TEMPORARY failure, which is
 * explicitly retryable (no PERM bit), and count how many arrive.
 */
function failEveryHtlcTemporarily(bob: LightningNode): () => number {
	let attempts = 0;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const node = bob as any;
	node.handleFinalHopHtlc = (channelId: Buffer, htlcId: bigint): void => {
		attempts++;
		const key = `${channelId.toString('hex')}:${htlcId}`;
		const sharedSecret = node.receivedHtlcSharedSecrets.get(key);
		node.channelManager.failHtlc(
			channelId,
			htlcId,
			createFailureMessage(sharedSecret, TEMPORARY_NODE_FAILURE)
		);
	};
	return () => attempts;
}

describe('Payment retry actually dispatches', () => {
	it('redispatches after a temporary failure', () => {
		const { alice, bob } = setupPair(900, 901);
		const attempts = failEveryHtlcTemporarily(bob);

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'retry'
		});
		alice.sendPayment(invoice.bolt11);

		// Before the fix this was exactly 1: the retry threw DUPLICATE_PAYMENT
		// into an empty catch and the payment was abandoned on first failure.
		expect(
			attempts(),
			'the payment was redispatched at least once'
		).to.be.greaterThan(1);

		alice.destroy();
		bob.destroy();
	});

	it('reports a retry count matching the attempts actually made', () => {
		const { alice, bob } = setupPair(902, 903);
		const attempts = failEveryHtlcTemporarily(bob);

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'retry-count'
		});
		const sent = alice.sendPayment(invoice.bolt11);

		const settled = alice
			.listPayments()
			.find((p) => p.paymentHash.equals(sent.paymentHash));
		expect(settled, 'payment record exists').to.not.be.undefined;
		// retryCount incremented even when nothing was redispatched, so it used to
		// claim a retry that never happened.
		expect(settled!.retryCount ?? 0).to.equal(attempts() - 1);

		alice.destroy();
		bob.destroy();
	});
});
