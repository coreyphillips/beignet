import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	IPaymentProof,
	PaymentStatus,
	PaymentDirection
} from '../../src/lightning/node/types';
import { IRoute } from '../../src/lightning/gossip/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`proof-seed-${id}`))
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

function createTestNode(seedId = 1): LightningNode {
	return new LightningNode(makeNodeConfig(seedId));
}

// ─────────────── Tests ───────────────

describe('Payment Proof Bundle (Feature 1.1)', () => {
	describe('LightningNode.getPaymentProof()', () => {
		it('returns null for unknown payment hash', () => {
			const node = createTestNode(10);
			const unknownHash = crypto.randomBytes(32);
			const proof = node.getPaymentProof(unknownHash);
			expect(proof).to.be.null;
			node.destroy();
		});

		it('returns null for PENDING payment', () => {
			const node = createTestNode(11);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');

			const payment: IPaymentInfo = {
				paymentHash,
				amountMsat: 100_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now()
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash);
			expect(proof).to.be.null;
			node.destroy();
		});

		it('returns null for FAILED payment', () => {
			const node = createTestNode(12);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');

			const payment: IPaymentInfo = {
				paymentHash,
				amountMsat: 50_000n,
				status: PaymentStatus.FAILED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now(),
				failureCode: 0x400f
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash);
			expect(proof).to.be.null;
			node.destroy();
		});

		it('returns proof for COMPLETED payment with preimage', () => {
			const node = createTestNode(13);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');
			const now = Date.now();

			const payment: IPaymentInfo = {
				paymentHash,
				preimage,
				amountMsat: 200_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: now - 5000,
				completedAt: now
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash);
			expect(proof).to.not.be.null;
			expect(proof!.paymentHash).to.deep.equal(paymentHash);
			expect(proof!.preimage).to.deep.equal(preimage);
			expect(proof!.amountMsat).to.equal(200_000n);
			expect(proof!.completedAt).to.equal(now);
			node.destroy();
		});

		it('includes invoice string when available in metadata', () => {
			const node = createTestNode(14);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');
			const invoiceStr = 'lnbcrt500n1test_invoice_string';

			const payment: IPaymentInfo = {
				paymentHash,
				preimage,
				amountMsat: 50_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now() - 1000,
				completedAt: Date.now(),
				metadata: { _invoice: invoiceStr, label: 'coffee' }
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash);
			expect(proof).to.not.be.null;
			expect(proof!.invoice).to.equal(invoiceStr);
			node.destroy();
		});

		it('includes route info when available', () => {
			const node = createTestNode(15);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');

			const route: IRoute = {
				hops: [
					{
						pubkey: crypto.randomBytes(33),
						shortChannelId: Buffer.from('0000010000020003', 'hex'),
						amountToForwardMsat: 100_000n,
						outgoingCltvValue: 150,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1,
						cltvExpiryDelta: 40
					},
					{
						pubkey: crypto.randomBytes(33),
						shortChannelId: Buffer.from('0000040000050006', 'hex'),
						amountToForwardMsat: 100_000n,
						outgoingCltvValue: 110,
						feeBaseMsat: 500,
						feeProportionalMillionths: 1,
						cltvExpiryDelta: 40
					}
				],
				totalAmountMsat: 101_000n,
				totalCltvDelta: 80,
				totalFeeMsat: 1_000n
			};

			const payment: IPaymentInfo = {
				paymentHash,
				preimage,
				amountMsat: 100_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now() - 2000,
				completedAt: Date.now(),
				route
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash);
			expect(proof).to.not.be.null;
			expect(proof!.route).to.not.be.undefined;
			expect(proof!.route!.hops).to.have.length(2);
			expect(proof!.route!.totalFeeMsat).to.equal(1_000n);
			node.destroy();
		});

		it('uses createdAt as fallback when completedAt is not set', () => {
			const node = createTestNode(16);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');
			const createdAt = Date.now() - 3000;

			const payment: IPaymentInfo = {
				paymentHash,
				preimage,
				amountMsat: 75_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt
				// completedAt intentionally not set
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash);
			expect(proof).to.not.be.null;
			expect(proof!.completedAt).to.equal(createdAt);
			node.destroy();
		});

		it('returns null for COMPLETED payment without preimage', () => {
			const node = createTestNode(17);
			const paymentHash = crypto.randomBytes(32);
			const hashHex = paymentHash.toString('hex');

			const payment: IPaymentInfo = {
				paymentHash,
				// preimage intentionally missing
				amountMsat: 30_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now(),
				completedAt: Date.now()
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash);
			expect(proof).to.be.null;
			node.destroy();
		});
	});

	describe('IPaymentProof interface shape', () => {
		it('has correct fields with proper types', () => {
			const node = createTestNode(20);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');

			const payment: IPaymentInfo = {
				paymentHash,
				preimage,
				amountMsat: 500_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now() - 1000,
				completedAt: Date.now(),
				metadata: { _invoice: 'lnbcrt1test' }
			};
			(node as any).payments.set(hashHex, payment);

			const proof = node.getPaymentProof(paymentHash) as IPaymentProof;
			expect(proof).to.not.be.null;

			// Verify types
			expect(Buffer.isBuffer(proof.paymentHash)).to.be.true;
			expect(Buffer.isBuffer(proof.preimage)).to.be.true;
			expect(typeof proof.amountMsat).to.equal('bigint');
			expect(typeof proof.completedAt).to.equal('number');
			expect(typeof proof.invoice).to.equal('string');
			// route is optional and not set in this test
			expect(proof.route).to.be.undefined;

			node.destroy();
		});
	});
});
