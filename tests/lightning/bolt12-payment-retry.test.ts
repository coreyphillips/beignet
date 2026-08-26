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
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';

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

	// The private-payment-path gate (issue #544) demands a PUBLISHED public
	// channel before an issuer keeps the CLN-style self path; these suites
	// were written against that self-path shape and test machinery orthogonal
	// to path topology, so pin the published branch on both nodes.
	for (const n of [alice, bob]) {
		for (const ch of n.getChannelManager().listChannels()) {
			const st = ch.getFullState();
			st.announceChannel = true;
			st.announcementSigsSent = true;
			st.announcementSigsReceived = true;
		}
	}

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

	it('rotates to another blinded path when the blinded segment fails', () => {
		const { alice, bob } = setupPair(948, 949);
		const invoice = issueBolt12Invoice(bob, 948, 50_000n);

		// Prepend a decoy path whose PUBLIC prefix is fine (bob, the
		// introduction node, is reachable) but whose blinded tail is broken:
		// bob must relay onward to a phantom hop he has no channel to, and
		// fails the HTLC with invalid_onion_blinding. Channel exclusion cannot
		// route around that (the erring hop's SCID is opaque), so without path
		// exclusion every retry re-selected this path and the payment died
		// without ever trying the invoice's working path.
		const bobPub = Buffer.from(bob.getNodeId(), 'hex');
		const phantomPub = getPublicKey(crypto.randomBytes(32));
		const brokenPath = constructBlindedPath(
			crypto.randomBytes(32),
			[bobPub, phantomPub],
			[
				{
					shortChannelId: Buffer.alloc(8, 9),
					paymentRelay: {
						cltvExpiryDelta: 40,
						feeProportionalMillionths: 0,
						feeBaseMsat: 0
					}
				},
				{ pathId: crypto.randomBytes(32) }
			]
		);
		invoice.paths = [brokenPath, ...invoice.paths!];
		invoice.blindedPayInfo = [
			{
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: 50_000n
			},
			...invoice.blindedPayInfo!
		];

		// Count how often the broken path is attempted (it terminates in a
		// forward on bob; the working single-hop path terminates at bob).
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const bobAny = bob as any;
		const realForward = bobAny.handleForwardHtlc.bind(bob);
		let forwardAttempts = 0;
		bobAny.handleForwardHtlc = (...args: unknown[]): void => {
			forwardAttempts++;
			realForward(...args);
		};

		let received = false;
		bob.on('payment:received', () => {
			received = true;
		});

		alice.payBolt12Invoice(invoice);

		const settled = alice
			.listPayments()
			.find((p) => p.paymentHash.equals(invoice.paymentHash));
		expect(settled, 'payment record exists').to.not.be.undefined;
		expect(settled!.status).to.equal(PaymentStatus.COMPLETED);
		expect(settled!.retryCount, 'recovered on the first retry').to.equal(1);
		expect(forwardAttempts, 'the broken path was tried exactly once').to.equal(
			1
		);
		expect(received, "settled over the invoice's working path").to.be.true;

		alice.destroy();
		bob.destroy();
	});

	it('a dispatch exception after route construction leaves no retry context', () => {
		const { alice, bob } = setupPair(950, 951);
		const invoice = issueBolt12Invoice(bob, 950, 50_000n);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = alice as any;
		const contexts = a.paymentRetryContexts as Map<string, unknown>;

		// Route construction succeeds; resolving the first-hop channel fails,
		// so sendPaymentToRoute throws AFTER the context was registered. A
		// local failure never reaches the onion failure handler, so nothing
		// else would clean the context up.
		a.findChannelForPeer = (): null => null;
		a.findLocalChannelByScid = (): null => null;

		expect(() => alice.payBolt12Invoice(invoice)).to.throw(
			/No channel to first hop/
		);
		expect(
			contexts.size,
			'no context survives a local dispatch exception'
		).to.equal(0);

		alice.destroy();
		bob.destroy();
	});

	it('a local HTLC refusal after route construction leaves no retry context', () => {
		const { alice, bob } = setupPair(952, 953);
		const invoice = issueBolt12Invoice(bob, 952, 50_000n);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = alice as any;
		const contexts = a.paymentRetryContexts as Map<string, unknown>;

		// addHtlc refuses the HTLC: sendPaymentToRoute returns a FAILED
		// payment instead of throwing, again without any onion failure to
		// drive the retry machinery.
		a.channelManager.addHtlc = (): { ok: boolean; error: string } => ({
			ok: false,
			error: 'test: HTLC refused locally'
		});

		const failed = alice.payBolt12Invoice(invoice);
		expect(failed.status).to.equal(PaymentStatus.FAILED);
		expect(contexts.size, 'no context survives a local HTLC refusal').to.equal(
			0
		);

		alice.destroy();
		bob.destroy();
	});

	it('fails a pending BOLT 12 payment once its invoice expires', () => {
		const { alice, bob } = setupPair(954, 955);
		const invoice = issueBolt12Invoice(bob, 954, 50_000n);
		// Issued two hours ago with a one-hour expiry.
		invoice.createdAt = BigInt(Math.floor(Date.now() / 1000) - 7200);
		invoice.relativeExpiry = 3600;
		// Bob parks the HTLC so the payment stays PENDING past its expiry.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(bob as any).handleFinalHopHtlc = (): void => {};

		alice.payBolt12Invoice(invoice);
		expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);

		// The expiry scanner previously only understood BOLT 11 invoice
		// strings, so a BOLT 12 context was silently skipped here forever.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(alice as any).scanExpiredPendingPayments();

		const payment = alice.getPayment(invoice.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureReason ?? '').to.contain('expired');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect((alice as any).paymentRetryContexts.size).to.equal(0);

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
