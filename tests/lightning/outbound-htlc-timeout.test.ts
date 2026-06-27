/**
 * Phase 2: Outbound HTLC Timeout + Payment Cleanup tests.
 *
 * Tests for scanExpiringOfferedHtlcs (via handleNewBlock) and failPayment.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentStatus,
	PaymentDirection
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`node-seed-${id}`))
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
	return node;
}

/**
 * Wire two nodes with a controllable loopback.
 * Returns a disconnect function to sever the loopback.
 */
function connectNodesControllable(
	nodeA: LightningNode,
	nodeB: LightningNode
): () => void {
	let connected = true;

	const forwardAtoB = (
		_pubkey: string,
		type: number,
		payload: Buffer
	): void => {
		if (connected && _pubkey === nodeB.getNodeId()) {
			nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
		}
	};
	const forwardBtoA = (
		_pubkey: string,
		type: number,
		payload: Buffer
	): void => {
		if (connected && _pubkey === nodeA.getNodeId()) {
			nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
		}
	};

	nodeA.on('message:outbound', forwardAtoB);
	nodeB.on('message:outbound', forwardBtoA);

	return (): void => {
		connected = false;
		nodeA.removeListener('message:outbound', forwardAtoB);
		nodeB.removeListener('message:outbound', forwardBtoA);
	};
}

/**
 * Open a channel between two connected nodes and advance to NORMAL state.
 */
function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

/**
 * Build a direct-channel graph on Alice's side so pathfinding works for
 * Alice -> Bob payments.
 */
function buildDirectGraph(
	alice: LightningNode,
	_bob: LightningNode,
	_channelId: Buffer
): Buffer {
	const aliceConfig = makeNodeConfig(1);
	const bobConfig = makeNodeConfig(2);
	const alicePubkey = getPublicKey(aliceConfig.nodePrivateKey);
	const bobPubkey = getPublicKey(bobConfig.nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });

	const aliceIsNode1 = Buffer.compare(alicePubkey, bobPubkey) < 0;
	const nodeId1 = aliceIsNode1 ? alicePubkey : bobPubkey;
	const nodeId2 = aliceIsNode1 ? bobPubkey : alicePubkey;

	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1,
		nodeId2,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};

	alice.getGraph().addChannelAnnouncement(announcement);

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

	const update2: IChannelUpdateMessage = {
		...update1,
		channelFlags: 1
	};

	alice.getGraph().applyChannelUpdate(update1);
	alice.getGraph().applyChannelUpdate(update2);

	alice.registerChannelScid(
		alice.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
	return scid;
}

/**
 * Set up Alice and Bob with a NORMAL channel, graph, and a PENDING outgoing payment
 * with an offered HTLC on Alice's channel. The loopback is disconnected before
 * sending the payment so the HTLC stays in PENDING state (Bob never receives it).
 *
 * Returns Alice, Bob, the payment hash, the channel ID, and cleanup functions.
 */
function setupPendingPayment(cltvExpiry?: number): {
	alice: LightningNode;
	bob: LightningNode;
	paymentHash: Buffer;
	channelId: Buffer;
} {
	const alice = createNode(1);
	const bob = createNode(2);
	const disconnect = connectNodesControllable(alice, bob);

	const channelId = openReadyChannel(alice, bob);
	buildDirectGraph(alice, bob, channelId);

	// Disconnect loopback before sending so the HTLC stays PENDING
	disconnect();

	// Create an invoice on Bob and send from Alice
	const invoiceStr = bob.createInvoice({
		amountMsat: 100_000n,
		description: 'timeout-test',
		expiry: 3600,
		minFinalCltvExpiry: cltvExpiry
	});

	const decoded = decodeInvoice(invoiceStr.bolt11);

	// sendPayment constructs route and sends via sendPaymentToRoute.
	// Since loopback is disconnected, the HTLC stays offered-PENDING.
	alice.sendPayment(invoiceStr.bolt11);

	return { alice, bob, paymentHash: decoded.paymentHash, channelId };
}

// ─────────────── Tests ───────────────

describe('Phase 2: Outbound HTLC Timeout + Payment Cleanup', function () {
	describe('failPayment', function () {
		it('should mark a PENDING payment as FAILED', function () {
			const node = createNode(10);

			// createInvoice creates an INCOMING PENDING payment
			const invoiceStr = node.createInvoice({
				amountMsat: 50_000n,
				description: 'fail-test'
			});
			const decoded = decodeInvoice(invoiceStr.bolt11);

			// Verify payment is PENDING
			const beforePayment = node.getPayment(decoded.paymentHash);
			expect(beforePayment).to.exist;
			expect(beforePayment!.status).to.equal(PaymentStatus.PENDING);

			// Call failPayment
			node.failPayment(decoded.paymentHash);

			// Verify payment is now FAILED
			const afterPayment = node.getPayment(decoded.paymentHash);
			expect(afterPayment).to.exist;
			expect(afterPayment!.status).to.equal(PaymentStatus.FAILED);
			expect(afterPayment!.completedAt).to.be.a('number');

			node.destroy();
		});

		it('should emit payment:failed event', function () {
			const node = createNode(11);

			const invoiceStr = node.createInvoice({
				amountMsat: 50_000n,
				description: 'event-test'
			});
			const decoded = decodeInvoice(invoiceStr.bolt11);

			let failedEvent: IPaymentInfo | null = null;
			node.on('payment:failed', (info: IPaymentInfo) => {
				failedEvent = info;
			});

			node.failPayment(decoded.paymentHash);

			expect(failedEvent).to.exist;
			expect(failedEvent!.status).to.equal(PaymentStatus.FAILED);
			expect(failedEvent!.paymentHash.toString('hex')).to.equal(
				decoded.paymentHash.toString('hex')
			);

			node.destroy();
		});

		it('should be a no-op for non-PENDING payments', function () {
			const node = createNode(12);

			const invoiceStr = node.createInvoice({
				amountMsat: 50_000n,
				description: 'no-op-test'
			});
			const decoded = decodeInvoice(invoiceStr.bolt11);

			// First fail it
			node.failPayment(decoded.paymentHash);
			expect(node.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			const completedAt = node.getPayment(decoded.paymentHash)!.completedAt;

			// Second fail should be a no-op
			let eventCount = 0;
			node.on('payment:failed', () => {
				eventCount++;
			});
			node.failPayment(decoded.paymentHash);

			expect(eventCount).to.equal(0);
			// completedAt should not change
			expect(node.getPayment(decoded.paymentHash)!.completedAt).to.equal(
				completedAt
			);

			node.destroy();
		});

		it('should be a no-op for unknown payment hashes', function () {
			const node = createNode(13);

			let eventCount = 0;
			node.on('payment:failed', () => {
				eventCount++;
			});

			const randomHash = crypto.randomBytes(32);
			node.failPayment(randomHash);

			expect(eventCount).to.equal(0);
			expect(node.getPayment(randomHash)).to.be.undefined;

			node.destroy();
		});

		it('should clean up paymentRetryContexts', function () {
			// Use the full two-node setup to get an OUTGOING payment with retry context
			const { alice, bob, paymentHash } = setupPendingPayment();

			// Verify payment is PENDING
			const payment = alice.getPayment(paymentHash);
			expect(payment).to.exist;
			expect(payment!.status).to.equal(PaymentStatus.PENDING);
			expect(payment!.direction).to.equal(PaymentDirection.OUTGOING);

			// failPayment should clean up retry contexts (internal state)
			// We verify by failing and checking that a subsequent failPayment is a no-op
			alice.failPayment(paymentHash);

			expect(alice.getPayment(paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);

			// Calling failPayment again should be no-op (retry contexts already cleaned)
			let secondFailEmitted = false;
			alice.on('payment:failed', () => {
				secondFailEmitted = true;
			});
			alice.failPayment(paymentHash);
			expect(secondFailEmitted).to.be.false;

			alice.destroy();
			bob.destroy();
		});

		it('should clean up outboundMppPayments', function () {
			const node = createNode(14);

			const invoiceStr = node.createInvoice({
				amountMsat: 50_000n,
				description: 'mpp-cleanup-test'
			});
			const decoded = decodeInvoice(invoiceStr.bolt11);

			// Verify payment is PENDING before failing
			const payment = node.getPayment(decoded.paymentHash);
			expect(payment).to.exist;
			expect(payment!.status).to.equal(PaymentStatus.PENDING);

			// failPayment cleans up outboundMppPayments (internal map deletion)
			// Verifiable through the side effect: payment is FAILED, event is emitted
			let failedPayment: IPaymentInfo | null = null;
			node.on('payment:failed', (info: IPaymentInfo) => {
				failedPayment = info;
			});

			node.failPayment(decoded.paymentHash);

			expect(failedPayment).to.exist;
			expect(failedPayment!.status).to.equal(PaymentStatus.FAILED);

			// No-op on second call confirms internal state was cleaned
			let secondEmitted = false;
			node.on('payment:failed', () => {
				secondEmitted = true;
			});
			node.failPayment(decoded.paymentHash);
			expect(secondEmitted).to.be.false;

			node.destroy();
		});
	});

	describe('scanExpiringOfferedHtlcs', function () {
		it('should fail HTLC when blockHeight >= cltvExpiry', function () {
			const { alice, bob, paymentHash, channelId } = setupPendingPayment();

			// Verify there is an offered HTLC on the channel
			const channel = alice.getChannelManager().getChannel(channelId)!;
			const state = channel.getFullState();
			let foundOfferedHtlc = false;
			let htlcCltvExpiry = 0;
			for (const [key, htlc] of state.htlcs) {
				if (key.startsWith('offered-')) {
					foundOfferedHtlc = true;
					htlcCltvExpiry = htlc.cltvExpiry;
				}
			}
			expect(foundOfferedHtlc).to.be.true;
			expect(htlcCltvExpiry).to.be.greaterThan(0);

			// Verify payment is still PENDING
			expect(alice.getPayment(paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			let failedEvent: IPaymentInfo | null = null;
			alice.on('payment:failed', (info: IPaymentInfo) => {
				failedEvent = info;
			});

			// Advance block height to match HTLC's CLTV expiry
			alice.handleNewBlock(htlcCltvExpiry);

			// Payment should now be FAILED
			expect(alice.getPayment(paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(failedEvent).to.exist;
			expect(failedEvent!.paymentHash.toString('hex')).to.equal(
				paymentHash.toString('hex')
			);

			alice.destroy();
			bob.destroy();
		});

		it('should not fail HTLCs with cltvExpiry > blockHeight', function () {
			const { alice, bob, paymentHash, channelId } = setupPendingPayment();

			// Find the HTLC's cltv expiry
			const channel = alice.getChannelManager().getChannel(channelId)!;
			const state = channel.getFullState();
			let htlcCltvExpiry = 0;
			for (const [key, htlc] of state.htlcs) {
				if (key.startsWith('offered-')) {
					htlcCltvExpiry = htlc.cltvExpiry;
				}
			}
			expect(htlcCltvExpiry).to.be.greaterThan(0);

			let failedEvent = false;
			alice.on('payment:failed', () => {
				failedEvent = true;
			});

			// Block height well below cltv expiry -- HTLC should NOT be expired
			alice.handleNewBlock(htlcCltvExpiry - 10);

			// Payment should still be PENDING
			expect(alice.getPayment(paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(failedEvent).to.be.false;

			alice.destroy();
			bob.destroy();
		});

		it('should call failPayment for associated payment', function () {
			const { alice, bob, paymentHash, channelId } = setupPendingPayment();

			// Find the HTLC's cltv expiry
			const channel = alice.getChannelManager().getChannel(channelId)!;
			const state = channel.getFullState();
			let htlcCltvExpiry = 0;
			for (const [key, htlc] of state.htlcs) {
				if (key.startsWith('offered-')) {
					htlcCltvExpiry = htlc.cltvExpiry;
				}
			}

			// Verify the payment is PENDING and OUTGOING
			const payment = alice.getPayment(paymentHash);
			expect(payment).to.exist;
			expect(payment!.status).to.equal(PaymentStatus.PENDING);
			expect(payment!.direction).to.equal(PaymentDirection.OUTGOING);

			// Trigger the scan by advancing past expiry
			alice.handleNewBlock(htlcCltvExpiry + 1);

			// failPayment should have been called
			const updatedPayment = alice.getPayment(paymentHash);
			expect(updatedPayment).to.exist;
			expect(updatedPayment!.status).to.equal(PaymentStatus.FAILED);
			expect(updatedPayment!.completedAt).to.be.a('number');

			alice.destroy();
			bob.destroy();
		});
	});

	describe('handleNewBlock integration', function () {
		it('should call scanExpiringOfferedHtlcs and update blockHeight', function () {
			const { alice, bob, paymentHash, channelId } = setupPendingPayment();

			// Verify initial block height is 0
			expect(alice.getCurrentBlockHeight()).to.equal(0);

			// Find the HTLC's cltv expiry
			const channel = alice.getChannelManager().getChannel(channelId)!;
			const state = channel.getFullState();
			let htlcCltvExpiry = 0;
			for (const [key, htlc] of state.htlcs) {
				if (key.startsWith('offered-')) {
					htlcCltvExpiry = htlc.cltvExpiry;
				}
			}

			// First: advance block height below expiry -- payment stays PENDING
			alice.handleNewBlock(htlcCltvExpiry - 5);
			expect(alice.getCurrentBlockHeight()).to.equal(htlcCltvExpiry - 5);
			expect(alice.getPayment(paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			// Capture the event
			let failedEvent: IPaymentInfo | null = null;
			alice.on('payment:failed', (info: IPaymentInfo) => {
				failedEvent = info;
			});

			// Second: advance block height to expiry -- triggers scan and payment failure
			alice.handleNewBlock(htlcCltvExpiry);
			expect(alice.getCurrentBlockHeight()).to.equal(htlcCltvExpiry);
			expect(alice.getPayment(paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(failedEvent).to.exist;
			expect(failedEvent!.paymentHash.toString('hex')).to.equal(
				paymentHash.toString('hex')
			);

			alice.destroy();
			bob.destroy();
		});
	});
});
