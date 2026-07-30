/**
 * Regression: blinded final hop MPP ignored total_amount_msat (issue #262).
 *
 * The final-hop MPP gate and the invoice amount check only recognised a
 * multi-part payment via BOLT 11 payment_data (total_msat). A blinded final
 * hop carries no payment_data at all; its declared total lives in
 * total_amount_msat (TLV 18). Each part of a spec-compliant split BOLT 12
 * payment was therefore treated as a standalone payment whose amount is
 * below the invoice amount, and failed with
 * incorrect_or_unknown_payment_details, so an MPP-splitting payer could not
 * pay a beignet-issued offer at all.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { findRouteToBlindedPath } from '../../src/lightning/gossip/pathfinding';
import {
	MPP_TIMEOUT,
	FINAL_INCORRECT_HTLC_AMOUNT,
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
		.update(Buffer.from(`b12-mpp-seed-${id}`))
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
 * signed invoice_request, exactly as the onion-message handler would.
 */
function issueBolt12Invoice(
	bob: LightningNode,
	payerSeedId: number,
	amountMsat: bigint
): IBolt12Invoice {
	const payerPriv = makeNodeConfig(payerSeedId).nodePrivateKey;
	const offerMgr = bob.getOfferManager();
	const { offer } = offerMgr.createOffer({
		description: 'bolt12 mpp receive',
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
 * Send one part of a split BOLT 12 payment over the invoice's blinded path,
 * as a spec-compliant MPP payer does: the part's HTLC carries partMsat and
 * the blinded final payload declares declaredTotalMsat via total_amount_msat
 * (TLV 18). No payment_secret exists; the path's encrypted path_id
 * authenticates each part at the recipient.
 */
function payBlindedPart(
	alice: LightningNode,
	invoice: IBolt12Invoice,
	partMsat: bigint,
	declaredTotalMsat: bigint
): IPaymentInfo {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const a = alice as any;
	const finalCltvExpiry = a.paddedFinalCltvExpiry() as number;
	const route = findRouteToBlindedPath(
		alice.getGraph(),
		Buffer.from(alice.getNodeId(), 'hex'),
		invoice.paths![0],
		invoice.blindedPayInfo![0],
		partMsat,
		finalCltvExpiry,
		undefined,
		undefined,
		undefined,
		a.getLocalChannelEdges()
	);
	expect(route, 'a route to the blinded path for this part').to.not.be.null;
	return alice.sendPaymentToRoute(
		route!,
		invoice.paymentHash,
		finalCltvExpiry,
		undefined,
		declaredTotalMsat
	);
}

function pendingMpp(
	bob: LightningNode
): Map<string, { receivedParts: unknown[]; createdAt: number }> {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return (bob as any).pendingMppPayments;
}

describe('Blinded final hop MPP receive (issue #262)', () => {
	const AMOUNT = 10_000_000n;

	it('accumulates parts declared via total_amount_msat and settles them together', () => {
		const { alice, bob } = setupPair(940, 941);
		const invoice = issueBolt12Invoice(bob, 940, AMOUNT);

		let received: IPaymentInfo | null = null;
		let receivedCount = 0;
		bob.on('payment:received', (p: IPaymentInfo) => {
			received = p;
			receivedCount++;
		});

		// First part: below the invoice amount on its own. Before the fix it
		// was judged as a standalone underpayment and failed with
		// incorrect_or_unknown_payment_details instead of being parked.
		payBlindedPart(alice, invoice, 6_000_000n, AMOUNT);
		expect(
			alice.getPayment(invoice.paymentHash)!.status,
			'first part parked, not failed'
		).to.equal(PaymentStatus.PENDING);
		expect(
			pendingMpp(bob).get(invoice.paymentHash.toString('hex'))?.receivedParts,
			'bob accumulated the part'
		).to.have.length(1);
		expect(received, 'no settlement on a partial total').to.be.null;

		// Second part completes the declared total: both parts settle.
		payBlindedPart(alice, invoice, 4_000_000n, AMOUNT);

		expect(receivedCount, 'settled exactly once').to.equal(1);
		expect(received!.status).to.equal(PaymentStatus.COMPLETED);
		expect(received!.amountMsat).to.equal(AMOUNT);
		const bobPayment = bob.getPayment(invoice.paymentHash)!;
		expect(bobPayment.status).to.equal(PaymentStatus.COMPLETED);
		const hash = crypto
			.createHash('sha256')
			.update(bobPayment.preimage!)
			.digest();
		expect(hash.equals(invoice.paymentHash), 'preimage matches the hash').to.be
			.true;
		expect(
			alice.getPayment(invoice.paymentHash)!.status,
			'sender saw both parts fulfilled'
		).to.equal(PaymentStatus.COMPLETED);
		expect(pendingMpp(bob).size, 'pending set cleaned up').to.equal(0);

		alice.destroy();
		bob.destroy();
	});

	it('fails a lone underpaying part at the MPP timeout without revealing the preimage', () => {
		const { alice, bob } = setupPair(942, 943);
		const invoice = issueBolt12Invoice(bob, 942, AMOUNT);

		let received = false;
		bob.on('payment:received', () => {
			received = true;
		});

		payBlindedPart(alice, invoice, 6_000_000n, AMOUNT);
		const hashHex = invoice.paymentHash.toString('hex');
		expect(pendingMpp(bob).get(hashHex), 'part parked').to.not.be.undefined;

		// The payer never sends the rest: the parked part must be failed back
		// at the MPP timeout, and the preimage never revealed.
		pendingMpp(bob).get(hashHex)!.createdAt -= 120_000;
		bob.failTimedOutMppPayments();

		expect(pendingMpp(bob).size, 'pending set dropped').to.equal(0);
		expect(received, 'no settlement for an incomplete set').to.be.false;
		const payment = alice.getPayment(invoice.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(MPP_TIMEOUT);

		alice.destroy();
		bob.destroy();
	});

	it('fails a part whose declared total disagrees with the pending set', () => {
		const { alice, bob } = setupPair(944, 945);
		const invoice = issueBolt12Invoice(bob, 944, AMOUNT);

		let received = false;
		bob.on('payment:received', () => {
			received = true;
		});

		payBlindedPart(alice, invoice, 5_000_000n, AMOUNT);
		// BOLT 4: every part MUST carry the same total. A disagreeing part is
		// failed alone; the conformant part stays parked.
		payBlindedPart(alice, invoice, 5_000_000n, 12_000_000n);

		const payment = alice.getPayment(invoice.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(FINAL_INCORRECT_HTLC_AMOUNT);
		expect(
			pendingMpp(bob).get(invoice.paymentHash.toString('hex'))?.receivedParts,
			'the conformant part is still parked'
		).to.have.length(1);
		expect(received, 'no settlement').to.be.false;

		alice.destroy();
		bob.destroy();
	});

	it('rejects a part whose declared total underpays the invoice', () => {
		const { alice, bob } = setupPair(946, 947);
		const invoice = issueBolt12Invoice(bob, 946, AMOUNT);

		let received = false;
		bob.on('payment:received', () => {
			received = true;
		});

		// The declared total itself is below the invoice amount: rejecting the
		// part up front (rather than parking it) is what stops a payer from
		// assembling a cheaper proof-of-payment out of parts.
		payBlindedPart(alice, invoice, 4_000_000n, 8_000_000n);

		const payment = alice.getPayment(invoice.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS);
		expect(pendingMpp(bob).size, 'nothing parked').to.equal(0);
		expect(received, 'no settlement').to.be.false;

		alice.destroy();
		bob.destroy();
	});
});
