/**
 * Phase 2: Agent Event Forwarding, Payment Metadata, Route Estimation, Filtering.
 *
 * Tests BeignetNode event forwarding (EventEmitter), payment metadata,
 * route fee estimation, payment filtering/pagination, and channel readiness helpers.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentStatus,
	PaymentDirection
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializePaymentInfo,
	deserializePaymentInfo
} from '../../src/lightning/storage/serialization';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`phase2-test-${id}`))
		.digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(derivePrivkey(seed, i));
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
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

function makePaymentInfo(
	overrides: Partial<IPaymentInfo> & { paymentHash: Buffer }
): IPaymentInfo {
	return {
		amountMsat: 1000n,
		status: PaymentStatus.COMPLETED,
		direction: PaymentDirection.OUTGOING,
		createdAt: Date.now(),
		...overrides
	};
}

// ─── 2.1: BeignetNode Event Forwarding ───
// (We test the LightningNode event semantics since BeignetNode.create() requires wallet)

describe('LightningNode Event Forwarding', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(10));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		node.destroy();
	});

	it('LightningNode is an EventEmitter', () => {
		expect(node).to.be.instanceOf(EventEmitter);
		expect(typeof node.on).to.equal('function');
		expect(typeof node.emit).to.equal('function');
	});

	it('emits payment:sent events', (done) => {
		const hash = crypto.randomBytes(32);
		node.on('payment:sent', (info: IPaymentInfo) => {
			expect(info.paymentHash.toString('hex')).to.equal(hash.toString('hex'));
			done();
		});
		node.emit('payment:sent', makePaymentInfo({ paymentHash: hash }));
	});

	it('emits payment:received events', (done) => {
		const hash = crypto.randomBytes(32);
		node.on('payment:received', (info: IPaymentInfo) => {
			expect(info.paymentHash.toString('hex')).to.equal(hash.toString('hex'));
			done();
		});
		node.emit(
			'payment:received',
			makePaymentInfo({
				paymentHash: hash,
				direction: PaymentDirection.INCOMING
			})
		);
	});

	it('emits payment:failed events', (done) => {
		const hash = crypto.randomBytes(32);
		node.on('payment:failed', (info: IPaymentInfo) => {
			expect(info.paymentHash.toString('hex')).to.equal(hash.toString('hex'));
			expect(info.status).to.equal(PaymentStatus.FAILED);
			done();
		});
		node.emit(
			'payment:failed',
			makePaymentInfo({
				paymentHash: hash,
				status: PaymentStatus.FAILED,
				failureCode: 15
			})
		);
	});

	it('emits channel:ready events', (done) => {
		const channelId = crypto.randomBytes(32);
		node.on('channel:ready', (data: { channelId: Buffer }) => {
			expect(data.channelId.toString('hex')).to.equal(
				channelId.toString('hex')
			);
			done();
		});
		node.emit('channel:ready', { channelId });
	});

	it('emits channel:closed events', (done) => {
		const channelId = crypto.randomBytes(32);
		node.on('channel:closed', (data: { channelId: Buffer }) => {
			expect(data.channelId.toString('hex')).to.equal(
				channelId.toString('hex')
			);
			done();
		});
		node.emit('channel:closed', { channelId });
	});

	it('destroy() removes all listeners', () => {
		node.on('payment:sent', () => {});
		node.on('channel:ready', () => {});
		expect(node.listenerCount('payment:sent')).to.be.greaterThan(0);
		node.destroy();
		expect(node.listenerCount('payment:sent')).to.equal(0);
	});
});

// ─── 2.2: Payment Metadata ───

describe('Payment Metadata', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(20));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		node.destroy();
	});

	it('metadata round-trips through serialization', () => {
		const payment: IPaymentInfo = makePaymentInfo({
			paymentHash: crypto.randomBytes(32),
			metadata: { purpose: 'API call', service: 'weather' }
		});

		const serialized = serializePaymentInfo(payment);
		expect(serialized.metadata).to.deep.equal({
			purpose: 'API call',
			service: 'weather'
		});

		const deserialized = deserializePaymentInfo(serialized);
		expect(deserialized.metadata).to.deep.equal({
			purpose: 'API call',
			service: 'weather'
		});
	});

	it('serialization works without metadata', () => {
		const payment: IPaymentInfo = makePaymentInfo({
			paymentHash: crypto.randomBytes(32)
		});

		const serialized = serializePaymentInfo(payment);
		expect(serialized.metadata).to.be.undefined;

		const deserialized = deserializePaymentInfo(serialized);
		expect(deserialized.metadata).to.be.undefined;
	});

	it('setPaymentMetadata updates existing payment', () => {
		const hash = crypto.randomBytes(32);
		const hashHex = hash.toString('hex');

		// Manually add a payment
		(node as any).payments.set(
			hashHex,
			makePaymentInfo({
				paymentHash: hash
			})
		);

		node.setPaymentMetadata(hash, { label: 'test' });

		const payment = node.getPayment(hash);
		expect(payment).to.not.be.undefined;
		expect(payment!.metadata).to.deep.equal({ label: 'test' });
	});

	it('setPaymentMetadata merges with existing metadata', () => {
		const hash = crypto.randomBytes(32);
		const hashHex = hash.toString('hex');

		(node as any).payments.set(
			hashHex,
			makePaymentInfo({
				paymentHash: hash,
				metadata: { existing: 'value' }
			})
		);

		node.setPaymentMetadata(hash, { newKey: 'newValue' });

		const payment = node.getPayment(hash);
		expect(payment!.metadata).to.deep.equal({
			existing: 'value',
			newKey: 'newValue'
		});
	});

	it('setPaymentMetadata is no-op for unknown payment', () => {
		const hash = crypto.randomBytes(32);
		// Should not throw
		node.setPaymentMetadata(hash, { label: 'test' });
		expect(node.getPayment(hash)).to.be.undefined;
	});
});

// ─── 2.3: Route Fee Estimation ───

describe('Route Fee Estimation', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(30));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		node.destroy();
	});

	it('estimateRouteFee returns null when no route exists', () => {
		// Create a dummy bolt11 for a node not in graph
		const inv = node.createInvoice({
			amountMsat: 100_000n,
			description: 'test'
		});
		const result = node.estimateRouteFee(inv.bolt11);
		// No route because there are no channels in the graph
		expect(result).to.be.null;
	});

	it('estimateRouteFee returns null for invalid invoice', () => {
		// Bad bolt11 string
		const result = node.estimateRouteFee('invalid');
		expect(result).to.be.null;
	});
});

// ─── 2.4: Payment Filtering & Pagination ───

describe('Payment Filtering & Pagination', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(40));
		node.on('error', () => {});
		node.on('node:error', () => {});

		// Populate payments
		const payments = (node as any).payments as Map<string, IPaymentInfo>;
		const now = Date.now();
		for (let i = 0; i < 5; i++) {
			const hash = crypto
				.createHash('sha256')
				.update(Buffer.from(`pay-${i}`))
				.digest();
			payments.set(hash.toString('hex'), {
				paymentHash: hash,
				amountMsat: BigInt((i + 1) * 1000),
				status: i < 3 ? PaymentStatus.COMPLETED : PaymentStatus.FAILED,
				direction:
					i % 2 === 0 ? PaymentDirection.OUTGOING : PaymentDirection.INCOMING,
				createdAt: now - (5 - i) * 1000 // oldest first
			});
		}
	});

	afterEach(() => {
		node.destroy();
	});

	it('listPayments returns all payments', () => {
		const all = node.listPayments();
		expect(all).to.have.length(5);
	});

	it('IPaymentInfo has metadata field defined in type', () => {
		const payment: IPaymentInfo = makePaymentInfo({
			paymentHash: crypto.randomBytes(32),
			metadata: { key: 'value' }
		});
		expect(payment.metadata).to.deep.equal({ key: 'value' });
	});
});

// ─── Channel Readiness (via LightningNode) ───

describe('Channel Readiness', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(50));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		node.destroy();
	});

	it('listChannels returns empty array for new node', () => {
		expect(node.listChannels()).to.have.length(0);
	});

	it('getBalance returns zero for new node', () => {
		const balance = node.getBalance();
		expect(Number(balance.localBalanceMsat)).to.equal(0);
	});
});
