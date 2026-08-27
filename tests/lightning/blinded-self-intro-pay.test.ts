/**
 * Blinded-path payer self-relay: paying a path whose introduction node is US
 * (issue #550).
 *
 * The routine case: an unannounced node's BOLT 12 offer names its direct
 * peer as the payment path's introduction, and that peer is the payer. The
 * payer used to fail route construction with "No channel to first hop <own
 * id>". A compliant payer processes its own introduction hop exactly like a
 * relaying forward: decrypt the encrypted_data with the node key for the
 * onward SCID and payment_relay, derive the next blinding point, and send
 * the HTLC straight into the blinded segment with the point on
 * update_add_htlc. Full loopback E2E over a real channel: the recipient
 * authenticates the encrypted path_id and settles.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
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
import {
	constructBlindedPath,
	processBlindedHop,
	IBlindedHopData,
	IBlindedPath
} from '../../src/lightning/onion/blinded-path';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`self-intro-seed-${id}`))
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

/**
 * Payer (alice) and UNANNOUNCED issuer (bob) with a real loopback channel.
 * Deliberately NOT pinned to the published branch: bob's invoices carry the
 * private payment path whose introduction is alice herself.
 */
function setupPair(): { alice: LightningNode; bob: LightningNode } {
	const alice = createNode(1);
	const bob = createNode(2);

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

/** Bob issues a BOLT 12 invoice exactly as the onion-message handler would. */
function issueBolt12Invoice(
	bob: LightningNode,
	payerSeedId: number,
	amountMsat: bigint
): IBolt12Invoice {
	const payerPriv = makeNodeConfig(payerSeedId).nodePrivateKey;
	const offerMgr = bob.getOfferManager();
	const { offer } = offerMgr.createOffer({
		description: 'self-intro pay',
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

describe('Blinded-path payer self-relay (issue #550)', function () {
	it('pays an unannounced direct peer through a path introduced by ourselves', function () {
		const { alice, bob } = setupPair();
		try {
			const amountMsat = 5_000_000n;
			const invoice = issueBolt12Invoice(bob, 1, amountMsat);

			// The invoice names ALICE as the introduction node: bob is
			// unannounced, his only channel peer is his payer.
			expect(invoice.paths, 'invoice carries a blinded path').to.have.length(1);
			expect(
				Buffer.from(invoice.paths![0].introductionNodeId).equals(
					Buffer.from(alice.getNodeId(), 'hex')
				),
				'introduction node is the payer itself'
			).to.equal(true);

			const settled: unknown[] = [];
			bob.on('invoice:settled', (info: unknown) => settled.push(info));

			const payment = alice.payBolt12Invoice(invoice);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			// We do not charge ourselves the introduction fee: the wire amount
			// equals the invoice amount (the payinfo fee was OUR OWN relay fee,
			// inverted away by the self-relay).
			expect(payment.amountMsat).to.equal(amountMsat);
			expect(settled, 'bob settled the invoice').to.have.length(1);
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});

	it('settles at a rounding-hostile amount for exactly the invoice amount', function () {
		// The sender-side floor fee and the relay-side ceiling inversion must
		// cancel at EVERY amount, not just ones that divide evenly (issue
		// #550 review): a stray msat either overpays or dies downstream.
		const { alice, bob } = setupPair();
		try {
			const amountMsat = 999_999n;
			const invoice = issueBolt12Invoice(bob, 1, amountMsat);
			const payment = alice.payBolt12Invoice(invoice);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(payment.amountMsat).to.equal(amountMsat);
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});

	it('a genuinely zero-fee self-intro payment passes maxFeeMsat 0 (BOLT 11)', function () {
		// The fee cap judges the fee actually PAID: the payinfo fee is OUR
		// OWN introduction fee, which the self-relay inverts away, so a cap
		// of 0 must pass and the stored route must report 0 fee (issue #550
		// review: it was rejected FEE_EXCEEDS_MAX while reporting 1005 msat
		// of fees never paid).
		const { alice, bob } = setupPair();
		try {
			const created = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'blinded bolt11 self-intro',
				useBlindedPaths: true,
				blindedPathNumHops: 2
			});
			const payment = alice.sendPayment(
				created.bolt11,
				undefined,
				0n // maxFeeMsat: a real fee would be refused
			);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(payment.route?.totalFeeMsat).to.equal(0n);
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});

	it('fails by name when the onward SCID resolves no usable channel', function () {
		const { alice, bob } = setupPair();
		try {
			const invoice = issueBolt12Invoice(bob, 1, 5_000_000n);
			// Break the SCID mapping: force-drop the channel from alice's view
			// of usable channels by closing it locally.
			for (const ch of alice.getChannelManager().listChannels()) {
				const st = ch.getFullState();
				st.remoteScidAlias = null;
				st.scidAlias = null;
				st.shortChannelId = null;
			}
			(
				alice as unknown as { scidToChannelId: Map<string, Buffer> }
			).scidToChannelId.clear();
			let error: unknown;
			try {
				alice.payBolt12Invoice(invoice);
			} catch (err) {
				error = err;
			}
			expect(String(error), 'named refusal, not a mystery').to.match(
				/onward SCID|No channel|No route/
			);
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});
});

/** The hop data the REAL invoice encrypted to alice, for forging variants. */
function aliceRealHop(
	invoice: IBolt12Invoice,
	alicePriv: Buffer
): IBlindedHopData {
	const path = invoice.paths![0];
	const { hopData } = processBlindedHop(
		path.blindingPoint,
		alicePriv,
		path.blindedHops[0].encryptedData
	);
	return hopData;
}

/** A forged self-intro path [alice -> secondNode] with controlled hop data. */
function forgePath(
	alicePub: Buffer,
	secondNode: Buffer,
	aliceHop: IBlindedHopData,
	finalPathId?: Buffer
): IBlindedPath {
	return constructBlindedPath(
		crypto.randomBytes(32),
		[alicePub, secondNode],
		[aliceHop, { pathId: finalPathId ?? crypto.randomBytes(32) }]
	);
}

/** The REAL final-hop path_id of the invoice's first path (test-side keys). */
function realFinalPathId(
	invoice: IBolt12Invoice,
	alicePriv: Buffer,
	bobPriv: Buffer
): Buffer {
	const path = invoice.paths![0];
	const aliceHop = processBlindedHop(
		path.blindingPoint,
		alicePriv,
		path.blindedHops[0].encryptedData
	);
	const bobHop = processBlindedHop(
		aliceHop.nextBlindingKey,
		bobPriv,
		path.blindedHops[1].encryptedData
	);
	return bobHop.hopData.pathId!;
}

describe('Self-relay failure handling (issue #550 review)', function () {
	interface IForgeSetup {
		alice: LightningNode;
		bob: LightningNode;
		invoice: IBolt12Invoice;
		alicePriv: Buffer;
		alicePub: Buffer;
		bobPub: Buffer;
		realHop: IBlindedHopData;
	}

	function forgeSetup(amountMsat: bigint): IForgeSetup {
		const { alice, bob } = setupPair();
		const invoice = issueBolt12Invoice(bob, 1, amountMsat);
		const alicePriv = makeNodeConfig(1).nodePrivateKey;
		return {
			alice,
			bob,
			invoice,
			alicePriv,
			alicePub: Buffer.from(alice.getNodeId(), 'hex'),
			bobPub: Buffer.from(bob.getNodeId(), 'hex'),
			realHop: aliceRealHop(invoice, alicePriv)
		};
	}

	function prependForged(invoice: IBolt12Invoice, forged: IBlindedPath): void {
		invoice.paths = [forged, ...invoice.paths!];
		invoice.blindedPayInfo = [
			{ ...invoice.blindedPayInfo![0] },
			...invoice.blindedPayInfo!
		];
	}

	it('attributes a final-hop failure to the FINAL hop of the stored route', function () {
		// A wrong final path_id makes bob (the blinded FINAL hop) reject the
		// payment's authentication. With the intro hop sliced off, the
		// decoded failure index must name the final hop of the STORED
		// (wire-true) route; the pre-fix mismatch decoded index 0 against a
		// stored route that still carried the intro hop, so every recipient
		// failure read as an introduction failure and recipient-specific
		// handling (height-skew retry included) never engaged (issue #550
		// review).
		const s = forgeSetup(50_000n);
		try {
			s.invoice.paths = [forgePath(s.alicePub, s.bobPub, { ...s.realHop })];
			s.alice.payBolt12Invoice(s.invoice);
			const settled = s.alice
				.listPayments()
				.find((p) => p.paymentHash.equals(s.invoice.paymentHash));
			// A recipient-judged failure (unknown payment) must NOT rotate
			// paths, and must be pinned on the recipient:
			expect(settled?.status).to.equal(PaymentStatus.FAILED);
			expect(
				settled?.route?.hops,
				'stored route is the wire route'
			).to.have.length(1);
			expect(
				settled?.failureSourceIndex,
				'failure attributed to the final hop'
			).to.equal((settled?.route?.hops.length ?? 0) - 1);
		} finally {
			s.alice.destroy();
			s.bob.destroy();
		}
	});

	it('a malformed blinded failure from the peer rotates to the next path', function () {
		// The second hop is encrypted to a phantom key: bob cannot process
		// the onion and, holding a blinding point from the add, answers
		// update_fail_malformed_htlc with a BARE code. That reason cannot be
		// onion-decrypted; unclassified, the broken path was retried forever
		// while the working path sat unused (issue #550 review).
		const s = forgeSetup(50_000n);
		try {
			const phantom = getPublicKey(
				crypto.createHash('sha256').update(Buffer.from('phantom')).digest()
			);
			prependForged(
				s.invoice,
				forgePath(s.alicePub, phantom, { ...s.realHop })
			);
			s.alice.payBolt12Invoice(s.invoice);
			const settled = s.alice
				.listPayments()
				.find((p) => p.paymentHash.equals(s.invoice.paymentHash));
			expect(settled?.status, settled?.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(settled?.retryCount, 'recovered on the first retry').to.equal(1);
		} finally {
			s.alice.destroy();
			s.bob.destroy();
		}
	});

	it('a locally unusable first path is skipped during selection, no retry burned', function () {
		// Route construction accepts a self-intro path as the bare tail before
		// any validation, so an unusable path used to abort the payment with
		// the working path unread (issue #550 review). Selection now validates
		// and keeps scanning, without consuming a retry.
		const s = forgeSetup(50_000n);
		try {
			prependForged(
				s.invoice,
				forgePath(s.alicePub, s.bobPub, {
					...s.realHop,
					shortChannelId: Buffer.alloc(8, 9) // resolves nothing
				})
			);
			const payment = s.alice.payBolt12Invoice(s.invoice);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(payment.retryCount ?? 0, 'no retry consumed').to.equal(0);
		} finally {
			s.alice.destroy();
			s.bob.destroy();
		}
	});

	it('accepts a next_node_id-addressed introduction hop', function () {
		// BOLT 4 allows either identifier; requiring the SCID rejected valid
		// paths (issue #550 review). The forged path keeps the REAL final
		// path_id so the recipient's authentication still passes.
		const s = forgeSetup(50_000n);
		try {
			const bobPriv = makeNodeConfig(2).nodePrivateKey;
			const pathId = realFinalPathId(s.invoice, s.alicePriv, bobPriv);
			const hop: IBlindedHopData = { ...s.realHop };
			delete hop.shortChannelId;
			hop.nextNodeId = s.bobPub;
			s.invoice.paths = [forgePath(s.alicePub, s.bobPub, hop, pathId)];
			const payment = s.alice.payBolt12Invoice(s.invoice);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
		} finally {
			s.alice.destroy();
			s.bob.destroy();
		}
	});

	it('refuses a hop carrying both identifiers, by name', function () {
		const s = forgeSetup(50_000n);
		try {
			const hop: IBlindedHopData = { ...s.realHop, nextNodeId: s.bobPub };
			s.invoice.paths = [forgePath(s.alicePub, s.bobPub, hop)];
			let error: unknown;
			try {
				s.alice.payBolt12Invoice(s.invoice);
			} catch (err) {
				error = err;
			}
			expect(String(error)).to.match(/No route|both/);
		} finally {
			s.alice.destroy();
			s.bob.destroy();
		}
	});

	it('refuses an expired blinded path, by name', function () {
		// payment_constraints.max_cltv_expiry behind the required expiry: the
		// relay would refuse it, and so must the self-relay; it used to
		// complete (issue #550 review).
		const s = forgeSetup(50_000n);
		try {
			const hop: IBlindedHopData = {
				...s.realHop,
				paymentConstraints: { maxCltvExpiry: 1, htlcMinimumMsat: 0n }
			};
			s.invoice.paths = [forgePath(s.alicePub, s.bobPub, hop)];
			let error: unknown;
			try {
				s.alice.payBolt12Invoice(s.invoice);
			} catch (err) {
				error = err;
			}
			expect(String(error)).to.match(/No route|expired/i);
		} finally {
			s.alice.destroy();
			s.bob.destroy();
		}
	});
});
