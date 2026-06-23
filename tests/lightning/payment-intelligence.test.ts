/**
 * Payment Intelligence: estimatePayment() tests.
 *
 * Tests the IPaymentEstimate interface and estimatePayment() method
 * on LightningNode, including route quality, success probability,
 * fee warnings, and MPP alternative detection.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, IPaymentEstimate } from '../../src/lightning/node/types';
import {
	Network,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY
} from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`payment-intel-seed-${id}`))
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
	return new LightningNode(makeNodeConfig(seedId));
}

/**
 * Create an invoice signed by a given private key.
 */
function createTestInvoice(
	privateKey: Buffer,
	amountMsat?: bigint,
	description = 'test invoice'
): string {
	return encodeInvoice({
		network: Network.REGTEST,
		amountMsat,
		timestamp: Math.floor(Date.now() / 1000),
		paymentHash: crypto.randomBytes(32),
		paymentSecret: crypto.randomBytes(32),
		description,
		expiry: 3600,
		minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
		privateKey
	});
}

/**
 * Build a network graph with a given number of hops from source → destination.
 * Returns the private keys and node configs for each node in the chain.
 *
 * chain: node0 --scid0-- node1 --scid1-- node2 ... --scid(n-1)-- nodeN
 *
 * node0 is the source node (the LightningNode), nodeN is the destination.
 * Graph channels are injected into the source node's graph.
 */
function buildChain(
	sourceNode: LightningNode,
	hopCount: number,
	opts?: { feeBaseMsat?: number; feeProportionalMillionths?: number }
): {
	destPrivkey: Buffer;
	allPrivkeys: Buffer[];
	allBitcoinPrivkeys: Buffer[];
} {
	const graph = sourceNode.getGraph();

	// Generate node privkeys for each additional node
	// node0 = sourceNode (already exists)
	const allPrivkeys: Buffer[] = [];
	const allBitcoinPrivkeys: Buffer[] = [];

	// Create unique deterministic keys for each node in the chain
	for (let i = 0; i <= hopCount; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(Buffer.from(`chain-node-${i}-${Date.now()}-${Math.random()}`))
			.digest();
		const bitcoinPrivkey = crypto
			.createHash('sha256')
			.update(Buffer.from(`chain-bitcoin-${i}-${Date.now()}-${Math.random()}`))
			.digest();
		allPrivkeys.push(privkey);
		allBitcoinPrivkeys.push(bitcoinPrivkey);
	}

	// Override node0's privkey with the source node's actual identity
	// We need the source node's privkey for signing; since we can't extract it,
	// we'll use the generated privkeys and just set node0's pubkey in the graph.
	// Instead, we build the graph so that allPrivkeys[0]'s pubkey is a neighbor
	// that the source node can route to.

	// Actually, for graph injection we need channel announcements between
	// allPrivkeys[i] and allPrivkeys[i+1]. The source node finds routes
	// FROM its own nodeId. So we need the first channel to connect sourceNode
	// to allPrivkeys[1].

	// For this to work, we need the sourceNode's privkey. Let's extract it
	// from the config. We'll use the makeNodeConfig approach.

	// Simpler: inject channels directly into the graph using restoreChannel.
	// This bypasses signature verification.

	const sourceNodeId = Buffer.from(sourceNode.getNodeId(), 'hex');

	for (let i = 0; i < hopCount; i++) {
		const scid = encodeShortChannelId({
			block: 700000 + i,
			txIndex: i + 1,
			outputIndex: 0
		});

		let nodeId1: Buffer;
		let nodeId2: Buffer;

		if (i === 0) {
			// First hop: sourceNode → allPrivkeys[1]
			nodeId1 = sourceNodeId;
			nodeId2 = getPublicKey(allPrivkeys[1]);
		} else {
			// Subsequent hops: allPrivkeys[i] → allPrivkeys[i+1]
			nodeId1 = getPublicKey(allPrivkeys[i]);
			nodeId2 = getPublicKey(allPrivkeys[i + 1]);
		}

		// Ensure nodeId1 < nodeId2
		if (Buffer.compare(nodeId1, nodeId2) > 0) {
			[nodeId1, nodeId2] = [nodeId2, nodeId1];
		}

		const feeBase = opts?.feeBaseMsat ?? 1000;
		const feeProp = opts?.feeProportionalMillionths ?? 1;

		graph.restoreChannel({
			shortChannelId: scid,
			nodeId1,
			nodeId2,
			features: Buffer.alloc(0),
			announcement: {} as any,
			update1: {
				signature: Buffer.alloc(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: feeBase,
				feeProportionalMillionths: feeProp,
				htlcMaximumMsat: 1_000_000_000n
			},
			update2: {
				signature: Buffer.alloc(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 1,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: feeBase,
				feeProportionalMillionths: feeProp,
				htlcMaximumMsat: 1_000_000_000n
			}
		});
	}

	return {
		destPrivkey: allPrivkeys[hopCount],
		allPrivkeys,
		allBitcoinPrivkeys
	};
}

// ─────────────── Tests ───────────────

describe('Payment Intelligence — estimatePayment()', () => {
	it('returns null for invalid invoice string', () => {
		const node = createNode(501);
		const result = node.estimatePayment('not-a-valid-invoice');
		expect(result).to.be.null;
		node.destroy();
	});

	it('returns null when no route exists (empty graph)', () => {
		const node = createNode(502);
		// Create a valid invoice from a random destination
		const destPrivkey = crypto
			.createHash('sha256')
			.update(Buffer.from('payment-intel-dest-502'))
			.digest();
		const invoice = createTestInvoice(destPrivkey, 10_000_000n);
		const result = node.estimatePayment(invoice);
		expect(result).to.be.null;
		node.destroy();
	});

	it('IPaymentEstimate has correct fields', () => {
		const node = createNode(503);
		const { destPrivkey } = buildChain(node, 1);
		const invoice = createTestInvoice(destPrivkey, 100_000_000n);
		const estimate = node.estimatePayment(invoice);

		expect(estimate).to.not.be.null;
		const e = estimate as IPaymentEstimate;
		expect(e).to.have.property('successProbabilityPct').that.is.a('number');
		expect(e).to.have.property('estimatedTimeMs').that.is.a('number');
		expect(e).to.have.property('routeQuality').that.is.a('string');
		expect(e).to.have.property('alternativeAvailable').that.is.a('boolean');
		expect(e).to.have.property('estimatedFeeSats').that.is.a('number');
		expect(e).to.have.property('hopCount').that.is.a('number');
		// warning is optional
		if (e.warning !== undefined) {
			expect(e.warning).to.be.a('string');
		}
		node.destroy();
	});

	it('routeQuality is HIGH for short direct route', () => {
		const node = createNode(504);
		const { destPrivkey } = buildChain(node, 1);
		const invoice = createTestInvoice(destPrivkey, 100_000_000n);
		const estimate = node.estimatePayment(invoice);

		expect(estimate).to.not.be.null;
		// 1-hop route with no MC failures → HIGH quality
		expect(estimate!.routeQuality).to.equal('HIGH');
		expect(estimate!.hopCount).to.equal(1);
		node.destroy();
	});

	it('routeQuality is LOW for long routes (>4 hops)', () => {
		const node = createNode(505);
		const { destPrivkey } = buildChain(node, 5);
		const invoice = createTestInvoice(destPrivkey, 100_000_000n);
		const estimate = node.estimatePayment(invoice);

		expect(estimate).to.not.be.null;
		expect(estimate!.hopCount).to.be.greaterThan(4);
		expect(estimate!.routeQuality).to.equal('LOW');
		node.destroy();
	});

	it('routeQuality is MEDIUM for moderate routes (3 hops)', () => {
		const node = createNode(506);
		const { destPrivkey } = buildChain(node, 3);
		const invoice = createTestInvoice(destPrivkey, 100_000_000n);
		const estimate = node.estimatePayment(invoice);

		expect(estimate).to.not.be.null;
		expect(estimate!.hopCount).to.equal(3);
		expect(estimate!.routeQuality).to.equal('MEDIUM');
		node.destroy();
	});

	it('warning is set when fees are high (>3%)', () => {
		const node = createNode(507);
		// Use very high fees so that the fee exceeds 3% of the payment
		const { destPrivkey } = buildChain(node, 2, {
			feeBaseMsat: 500_000, // 500 sat base fee per hop
			feeProportionalMillionths: 50_000 // 5% proportional fee per hop
		});
		// Small payment: 10,000 sat — fee will be huge relative to amount
		const invoice = createTestInvoice(destPrivkey, 10_000_000n);
		const estimate = node.estimatePayment(invoice);

		expect(estimate).to.not.be.null;
		expect(estimate!.warning).to.equal('Fees exceed 3% of payment amount');
		node.destroy();
	});

	it('estimatedTimeMs scales with hop count', () => {
		const node1 = createNode(508);
		const chain1 = buildChain(node1, 1);
		const invoice1 = createTestInvoice(chain1.destPrivkey, 100_000_000n);
		const est1 = node1.estimatePayment(invoice1);

		const node3 = createNode(509);
		const chain3 = buildChain(node3, 3);
		const invoice3 = createTestInvoice(chain3.destPrivkey, 100_000_000n);
		const est3 = node3.estimatePayment(invoice3);

		expect(est1).to.not.be.null;
		expect(est3).to.not.be.null;
		// 1 hop → 2000ms, 3 hops → 6000ms
		expect(est1!.estimatedTimeMs).to.equal(2000);
		expect(est3!.estimatedTimeMs).to.equal(6000);
		expect(est3!.estimatedTimeMs).to.be.greaterThan(est1!.estimatedTimeMs);
		node1.destroy();
		node3.destroy();
	});

	it('successProbabilityPct is between 0 and 100', () => {
		const node = createNode(510);
		const { destPrivkey } = buildChain(node, 2);
		const invoice = createTestInvoice(destPrivkey, 100_000_000n);
		const estimate = node.estimatePayment(invoice);

		expect(estimate).to.not.be.null;
		expect(estimate!.successProbabilityPct).to.be.at.least(0);
		expect(estimate!.successProbabilityPct).to.be.at.most(100);
		node.destroy();
	});

	it('alternativeAvailable reflects MPP availability', () => {
		// With a single-path graph, alternativeAvailable should be false
		const node = createNode(511);
		const { destPrivkey } = buildChain(node, 1);
		const invoice = createTestInvoice(destPrivkey, 100_000_000n);
		const estimate = node.estimatePayment(invoice);

		expect(estimate).to.not.be.null;
		// A linear chain only has one path, so MPP can't split
		expect(estimate!.alternativeAvailable).to.equal(false);
		node.destroy();
	});

	it('returns null for amount-less invoice without amountSats parameter', () => {
		const node = createNode(512);
		const { destPrivkey } = buildChain(node, 1);
		// Create an invoice without an amount
		const invoice = createTestInvoice(destPrivkey, undefined);
		const result = node.estimatePayment(invoice);
		// Without amountSats override, should return null since amountMsat is undefined
		expect(result).to.be.null;
		node.destroy();
	});
});
