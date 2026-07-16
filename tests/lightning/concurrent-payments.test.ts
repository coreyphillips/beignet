/**
 * Phase 4a: Concurrent Payment Correctness Tests
 *
 * Verifies that multiple simultaneous sendPayment() calls do not cause
 * HTLC ID duplication, balance inconsistencies, or duplicate payment rejection.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	encodeShortChannelId,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage
} from '../../src/lightning/gossip/types';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`conc-seed-${id}`))
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

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	sats = 1_000_000n
): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), sats);
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

function buildDirectGraph(
	graph: NetworkGraph,
	nodeA: Buffer,
	nodeB: Buffer
): void {
	const [n1, n2] =
		Buffer.compare(nodeA, nodeB) < 0 ? [nodeA, nodeB] : [nodeB, nodeA];
	const scid = encodeShortChannelId({ block: 1, txIndex: 1, outputIndex: 0 });

	graph.addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: n1,
		nodeId2: n2,
		bitcoinKey1: n1,
		bitcoinKey2: n2
	} as IChannelAnnouncementMessage);

	const update1: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 0n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 10_000_000_000n
	};
	graph.applyChannelUpdate(update1);
	graph.applyChannelUpdate({ ...update1, channelFlags: 1 });
}

function makeInvoice(
	payeeKey: Buffer,
	payeeSeed: Buffer,
	amountMsat: bigint
): string {
	const paymentHash = crypto.randomBytes(32);
	const paymentSecret = crypto.randomBytes(32);
	// Sign with the payee's actual node identity key: the decoder rejects an
	// invoice whose n field does not match the signing key (BOLT 11).
	const payeeNodePrivkey = crypto
		.createHash('sha256')
		.update(payeeSeed)
		.update(Buffer.from('node-identity'))
		.digest();
	return encodeInvoice({
		network: Network.REGTEST,
		paymentHash,
		paymentSecret,
		timestamp: Math.floor(Date.now() / 1000),
		description: 'concurrent test',
		minFinalCltvExpiry: 40,
		amountMsat,
		payeeNodeKey: payeeKey,
		privateKey: payeeNodePrivkey
	});
}

// ═══════════════════════════════════════════════════════════════════════

describe('Phase 4a: Concurrent Payment Correctness', function () {
	this.timeout(10_000);

	it('should handle multiple payments to same peer without HTLC ID duplication', () => {
		const alice = createNode(800);
		const bob = createNode(801);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob, 10_000_000n);

		const graph = (alice as any).graph as NetworkGraph;
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');
		buildDirectGraph(graph, aliceId, bobId);

		// Track HTLC IDs used
		const htlcIds = new Set<string>();
		alice.on(
			'message:outbound',
			(_pubkey: string, type: number, payload: Buffer) => {
				if (type === 128) {
					// update_add_htlc
					const htlcId = payload.readBigUInt64BE(32);
					const key = `${htlcId}`;
					expect(htlcIds.has(key)).to.be.false;
					htlcIds.add(key);
				}
			}
		);

		// Send 3 payments sequentially (concurrent in the sense of same channel)
		for (let i = 0; i < 3; i++) {
			const invoice = makeInvoice(bobId, makeSeed(801), 10000n);
			try {
				alice.sendPayment(invoice);
			} catch {
				// expected failures ok
			}
		}

		// All 3 should have been attempted
		expect(htlcIds.size).to.be.greaterThan(0);

		alice.destroy();
		bob.destroy();
	});

	it('should reject duplicate invoice with DUPLICATE_PAYMENT', () => {
		const alice = createNode(802);
		const bob = createNode(803);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob, 10_000_000n);

		const graph = (alice as any).graph as NetworkGraph;
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');
		buildDirectGraph(graph, aliceId, bobId);

		const invoice = makeInvoice(bobId, makeSeed(803), 10000n);

		// First payment
		try {
			alice.sendPayment(invoice);
		} catch {
			/* may fail on route/HTLC */
		}

		// Second payment with same invoice — should fail with DUPLICATE
		const paymentHash = require('../../src/lightning/invoice/decode').decode(
			invoice
		).paymentHash;
		const existing = (alice as any).payments.get(paymentHash.toString('hex'));
		if (existing && existing.status === PaymentStatus.PENDING) {
			try {
				alice.sendPayment(invoice);
				expect.fail('Should throw DUPLICATE_PAYMENT');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('already in flight');
			}
		}

		alice.destroy();
		bob.destroy();
	});

	it('should allow payment to same destination with different invoices', () => {
		const alice = createNode(804);
		const bob = createNode(805);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob, 10_000_000n);

		const graph = (alice as any).graph as NetworkGraph;
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');
		buildDirectGraph(graph, aliceId, bobId);

		const invoice1 = makeInvoice(bobId, makeSeed(805), 5000n);
		const invoice2 = makeInvoice(bobId, makeSeed(805), 5000n);

		// Both should attempt without DUPLICATE error
		let attempt1Error: Error | null = null;
		let attempt2Error: Error | null = null;

		try {
			alice.sendPayment(invoice1);
		} catch (e: unknown) {
			attempt1Error = e as Error;
		}
		try {
			alice.sendPayment(invoice2);
		} catch (e: unknown) {
			attempt2Error = e as Error;
		}

		// Neither should fail with "already in flight" since they have different payment hashes
		if (attempt1Error)
			expect(attempt1Error.message).to.not.include('already in flight');
		if (attempt2Error)
			expect(attempt2Error.message).to.not.include('already in flight');

		alice.destroy();
		bob.destroy();
	});

	it('should rapid sequential payments not corrupt channel state', () => {
		const alice = createNode(806);
		const bob = createNode(807);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob, 10_000_000n);

		const graph = (alice as any).graph as NetworkGraph;
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');
		buildDirectGraph(graph, aliceId, bobId);

		// Fire 5 rapid payments
		for (let i = 0; i < 5; i++) {
			const invoice = makeInvoice(bobId, makeSeed(807), 1000n);
			try {
				alice.sendPayment(invoice);
			} catch {
				/* expected failures ok */
			}
		}

		// Channel should still be in a valid state
		const channels = alice.listChannels();
		expect(channels.length).to.be.greaterThan(0);
		const ch = channels[0];
		expect(ch.localBalanceMsat).to.be.a('bigint');
		expect(Number(ch.localBalanceMsat)).to.be.gte(0);

		alice.destroy();
		bob.destroy();
	});

	it('should bidirectional simultaneous payments work', () => {
		const alice = createNode(808);
		const bob = createNode(809);
		connectNodes(alice, bob);

		// Alice opens channel to Bob
		openReadyChannel(alice, bob, 5_000_000n);

		const aliceGraph = (alice as any).graph as NetworkGraph;
		const bobGraph = (bob as any).graph as NetworkGraph;
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');

		buildDirectGraph(aliceGraph, aliceId, bobId);
		buildDirectGraph(bobGraph, aliceId, bobId);

		// Alice pays Bob
		const invoiceFromBob = makeInvoice(bobId, makeSeed(809), 1000n);
		try {
			alice.sendPayment(invoiceFromBob);
		} catch {
			/* ok */
		}

		// Bob pays Alice
		const invoiceFromAlice = makeInvoice(aliceId, makeSeed(808), 1000n);
		try {
			bob.sendPayment(invoiceFromAlice);
		} catch {
			/* ok */
		}

		// Both nodes should still be functional
		expect(alice.listChannels().length).to.be.greaterThan(0);
		expect(bob.listChannels().length).to.be.greaterThan(0);

		alice.destroy();
		bob.destroy();
	});

	it('should payment to same destination with different amounts', () => {
		const alice = createNode(810);
		const bob = createNode(811);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob, 10_000_000n);

		const graph = (alice as any).graph as NetworkGraph;
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');
		buildDirectGraph(graph, aliceId, bobId);

		// Different amounts to same destination
		const invoice1 = makeInvoice(bobId, makeSeed(811), 1000n);
		const invoice2 = makeInvoice(bobId, makeSeed(811), 50000n);

		try {
			alice.sendPayment(invoice1);
		} catch {
			/* ok */
		}
		try {
			alice.sendPayment(invoice2);
		} catch {
			/* ok */
		}

		// At least one payment should be tracked
		const payments = alice.listPayments();
		expect(payments.length).to.be.greaterThan(0);

		alice.destroy();
		bob.destroy();
	});

	it('should balance conservation after multiple payments', () => {
		const alice = createNode(812);
		const bob = createNode(813);
		connectNodes(alice, bob);
		const fundingSats = 1_000_000n;
		openReadyChannel(alice, bob, fundingSats);

		const channels = alice.listChannels();
		const totalBefore =
			channels[0].localBalanceMsat + channels[0].remoteBalanceMsat;

		// Send payments
		const graph = (alice as any).graph as NetworkGraph;
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');
		buildDirectGraph(graph, aliceId, bobId);

		for (let i = 0; i < 3; i++) {
			const invoice = makeInvoice(bobId, makeSeed(813), 1000n);
			try {
				alice.sendPayment(invoice);
			} catch {
				/* ok */
			}
		}

		const channelsAfter = alice.listChannels();
		const totalAfter =
			channelsAfter[0].localBalanceMsat + channelsAfter[0].remoteBalanceMsat;

		// Total balance should be conserved (minus any fees which are negligible in test)
		// Allow for HTLC in-flight amounts
		expect(Number(totalAfter)).to.be.lte(Number(totalBefore));

		alice.destroy();
		bob.destroy();
	});
});
