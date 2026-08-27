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
