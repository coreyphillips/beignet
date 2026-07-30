/**
 * Regression: BOLT 12 payments get no retry context and no height-skew
 * recovery (issue #261).
 *
 * payBolt12Invoice dispatched through sendPaymentToRoute without seeding
 * paymentRetryContexts, unlike sendPayment, the MPP path and keysend. Any
 * transient failure therefore permanently failed the payment on the first
 * attempt, and noteHeightSkewFailure bailed at its `if (!ctx)` guard, so a
 * payment rejected only because the payee's block height was ahead of ours
 * was abandoned instead of retried against the reported height.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import {
	TEMPORARY_NODE_FAILURE,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
} from '../../src/lightning/onion/types';
import {
	encodeOfferTlv,
	encodeInvoiceRequestTlv,
	getTlvRecords,
	computeMerkleRootFromRecords,
	computeSignatureHash,
	schnorrSign,
	IInvoiceRequest,
	IBolt12Invoice
} from '../../src/lightning/offer';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`b12-retry-seed-${id}`))
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
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
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
): { alice: LightningNode; bob: LightningNode } {
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

	return { alice, bob };
}

/**
 * Bob publishes an offer and issues a BOLT 12 invoice in response to a
 * signed invoice_request, exactly as the onion-message handler would. The
 * invoice carries the single-hop blinded payment path (bob as introduction
 * node) whose encrypted path_id authenticates the payment.
 */
function issueBolt12Invoice(
	bob: LightningNode,
	payerSeedId: number,
	amountMsat: bigint
): IBolt12Invoice {
	const payerPriv = makeNodeConfig(payerSeedId).nodePrivateKey;
	const offerMgr = bob.getOfferManager();
	const { offer } = offerMgr.createOffer({
		description: 'bolt12 retry',
		amount: amountMsat
	});
	const request: IInvoiceRequest = {
		payerKey: getPublicKey(payerPriv),
		offerId: offer.offerId,
		amount: amountMsat,
		metadata: crypto.randomBytes(16)
	};
	const offerTlv = encodeOfferTlv(offer);
	const unsigned = encodeInvoiceRequestTlv(request, offerTlv);
	request.signature = schnorrSign(
		computeSignatureHash(
			'lightninginvoice_requestsignature',
			computeMerkleRootFromRecords(getTlvRecords(unsigned))
		),
		payerPriv
	);
	const invoice = offerMgr.handleInvoiceRequest(
		encodeInvoiceRequestTlv(request, offerTlv)
	);
	expect(invoice, 'bob issued a BOLT 12 invoice').to.not.be.null;
	return invoice!;
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
	return (): number => attempts;
}

describe('BOLT 12 payment retry (issue #261)', () => {
	it('redispatches a BOLT 12 payment after a temporary failure', () => {
		const { alice, bob } = setupPair(930, 931);
		const invoice = issueBolt12Invoice(bob, 930, 50_000n);
		const attempts = failEveryHtlcTemporarily(bob);

		alice.payBolt12Invoice(invoice);

		// Before the fix this was exactly 1: with no retry context the failure
		// handler treated the first transient failure as final.
		expect(
			attempts(),
			'the payment was redispatched at least once'
		).to.be.greaterThan(1);

		alice.destroy();
		bob.destroy();
	});

	it('recovers from final-node block-height skew (PERM|15 with a reported height)', () => {
		const { alice, bob } = setupPair(932, 933);
		// Bob is 5 blocks ahead of alice (within MAX_TRUSTED_PEER_HEIGHT_SKEW).
		alice.handleNewBlock(800_000);
		bob.handleNewBlock(800_005);
		const invoice = issueBolt12Invoice(bob, 932, 50_000n);

		// Bob rejects the FIRST attempt exactly as finalHopSafetyFailure
		// rejects a too-low expiry: PERM|15 whose failure data carries his
		// height. The second attempt goes through the real handler and
		// settles. PERM|15 is otherwise permanent, so a retry can only happen
		// through the height-skew branch consuming the reported height.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const bobAny = bob as any;
		const realHandler = bobAny.handleFinalHopHtlc.bind(bob);
		let attempts = 0;
		bobAny.handleFinalHopHtlc = (
			channelId: Buffer,
			htlcId: bigint,
			...rest: unknown[]
		): void => {
			attempts++;
			if (attempts === 1) {
				const key = `${channelId.toString('hex')}:${htlcId}`;
				const sharedSecret = bobAny.receivedHtlcSharedSecrets.get(key);
				const data = Buffer.alloc(12);
				data.writeBigUInt64BE(50_000n, 0);
				data.writeUInt32BE(800_005, 8);
				bobAny.channelManager.failHtlc(
					channelId,
					htlcId,
					createFailureMessage(
						sharedSecret,
						INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
						data
					)
				);
				return;
			}
			realHandler(channelId, htlcId, ...rest);
		};

		let received = false;
		bob.on('payment:received', () => {
			received = true;
		});

		alice.payBolt12Invoice(invoice);

		// The retry must be built against the reported height, exactly as a
		// BOLT 11 payment recovers. Before the fix there was no retry context,
		// so noteHeightSkewFailure returned false and the payment failed for
		// good on the first attempt.
		const settled = alice
			.listPayments()
			.find((p) => p.paymentHash.equals(invoice.paymentHash));
		expect(settled, 'payment record exists').to.not.be.undefined;
		expect(settled!.status).to.equal(PaymentStatus.COMPLETED);
		expect(settled!.retryCount, 'recovered on the first retry').to.equal(1);
		expect(
			settled!.cltvBaseHeight,
			'the retry was built against the reported height, not our stale tip'
		).to.equal(800_005);
		expect(received, 'bob received the payment').to.be.true;

		alice.destroy();
		bob.destroy();
	});

	it('drops the retry context once the payment settles', () => {
		const { alice, bob } = setupPair(934, 935);
		const invoice = issueBolt12Invoice(bob, 934, 50_000n);

		alice.payBolt12Invoice(invoice);

		expect(
			alice.getPayment(invoice.paymentHash)!.status,
			'payment settled'
		).to.equal(PaymentStatus.COMPLETED);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((alice as any).paymentRetryContexts.size).to.equal(0);

		alice.destroy();
		bob.destroy();
	});

	it('a dispatch that finds no route leaves no retry context', () => {
		const alice = createNode(936);
		const bob = createNode(937);
		// No channel between them: routing must fail before any context is
		// registered, mirroring sendPayment and keysend.
		const invoice = issueBolt12Invoice(bob, 936, 50_000n);

		expect(() => alice.payBolt12Invoice(invoice)).to.throw(/route/i);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const contexts = (alice as any).paymentRetryContexts as Map<
			string,
			unknown
		>;
		expect(
			contexts.size,
			'no context for a payment that never existed'
		).to.equal(0);

		alice.destroy();
		bob.destroy();
	});

	it('rejects a second dispatch while the payment is in flight', () => {
		const { alice, bob } = setupPair(938, 939);
		const invoice = issueBolt12Invoice(bob, 938, 50_000n);
		// Bob parks the HTLC so the first dispatch stays PENDING.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(bob as any).handleFinalHopHtlc = (): void => {};

		alice.payBolt12Invoice(invoice);
		expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		expect(() => alice.payBolt12Invoice(invoice)).to.throw(
			/already in flight/i
		);

		alice.destroy();
		bob.destroy();
	});
});
