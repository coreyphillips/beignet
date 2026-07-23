/**
 * S-4.H3 (remainder) regression: a BOLT 12 invoice answering an
 * invoice_request MUST copy all non-signature fields from the request
 * (including unknown fields) and MUST include invoice_paths with exactly one
 * blinded_payinfo per path.
 *
 * Before this fix the invoice carried only its own 160+ fields (no mirror,
 * paths optional and usually absent), so every spec reader — CLN included —
 * rejected beignet invoices outright, and beignet never checked what it was
 * handed back. Live-CLN validated: an invoice issued through this flow now
 * decodes at CLN as `valid: true` with the mirrored offer/invreq fields, the
 * blinded path and the per-path payinfo all parsed (see PR).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { OfferManager } from '../../src/lightning/offer/offer-manager';
import {
	encodeOfferTlv,
	encodeInvoiceRequestTlv,
	encodeInvoiceTlv,
	getTlvRecords
} from '../../src/lightning/offer/tlv';
import {
	computeSignatureHash,
	computeMerkleRootFromRecords
} from '../../src/lightning/offer/merkle';
import { schnorrSign } from '../../src/lightning/offer/schnorr';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeBolt12Invoice } from '../../src/lightning/offer/encode';
import { decodeBolt12Invoice } from '../../src/lightning/offer/decode';
import { encodeTlvStream } from '../../src/lightning/message/tlv';
import {
	IInvoiceRequest,
	IOffer,
	IBolt12Invoice
} from '../../src/lightning/offer/types';

const issuerPriv = crypto.randomBytes(32);
const payerPriv = crypto.randomBytes(32);

function makeSignedRequestTlv(
	fields: Partial<IInvoiceRequest>,
	offer: IOffer
): Buffer {
	const request: IInvoiceRequest = {
		payerKey: getPublicKey(payerPriv),
		offerId: offer.offerId,
		metadata: crypto.randomBytes(16),
		...fields
	};
	const offerTlv = encodeOfferTlv(offer);
	const unsigned = encodeInvoiceRequestTlv(request, offerTlv);
	const merkleRoot = computeMerkleRootFromRecords(getTlvRecords(unsigned));
	const sigHash = computeSignatureHash(
		'lightninginvoice_requestsignature',
		merkleRoot
	);
	request.signature = schnorrSign(sigHash, payerPriv);
	return encodeInvoiceRequestTlv(request, offerTlv);
}

describe('S-4.H3: BOLT 12 invoice mirrors the invoice_request', function () {
	it('copies every non-signature invreq record byte-identically', function () {
		const mgr = new OfferManager(issuerPriv);
		const { offer } = mgr.createOffer({
			description: 'mirror me',
			amount: 42_000n
		});
		const requestTlv = makeSignedRequestTlv({ amount: 42_000n }, offer);
		const requestRecords = getTlvRecords(requestTlv);

		const invoice = mgr.handleInvoiceRequest(requestTlv)!;
		expect(invoice).to.not.equal(null);

		for (const sent of requestRecords) {
			if (sent.type === 240n) continue;
			const mirrored = invoice.records!.find((r) => r.type === sent.type);
			expect(mirrored, `record ${sent.type} mirrored`).to.not.equal(undefined);
			expect(
				mirrored!.value.equals(sent.value),
				`record ${sent.type} byte-identical`
			).to.equal(true);
		}
		mgr.destroy();
	});

	it('always includes invoice_paths with exactly one payinfo per path', function () {
		const mgr = new OfferManager(issuerPriv);
		// An offer WITHOUT paths (announced-node case): the invoice still must
		// carry a blinded path terminating at the issuer.
		const { offer } = mgr.createOffer({
			description: 'pathless offer',
			amount: 10_000n
		});
		const invoice = mgr.handleInvoiceRequest(
			makeSignedRequestTlv({ amount: 10_000n }, offer)
		)!;
		expect(invoice.paths).to.have.length(1);
		expect(invoice.blindedPayInfo).to.have.length(1);
		expect(
			invoice.paths![0].introductionNodeId.equals(invoice.nodeId)
		).to.equal(true);
		mgr.destroy();
	});

	it('string round-trip keeps the mirror and the signature verifiable', function () {
		const mgr = new OfferManager(issuerPriv);
		const { offer } = mgr.createOffer({
			description: 'round trip',
			amount: 7_000n
		});
		const invoice = mgr.handleInvoiceRequest(
			makeSignedRequestTlv({ amount: 7_000n }, offer)
		)!;

		const lni = encodeBolt12Invoice(invoice);
		const decoded = decodeBolt12Invoice(lni);
		// Mirrored description survives the round trip on the decoded object.
		expect(decoded.description).to.equal('round trip');
		// Signature verifies over the decoded RAW records (a structural
		// re-encode would drop the mirror and wrongly fail).
		expect(mgr.verifyInvoiceSignature(decoded)).to.equal(true);
		mgr.destroy();
	});

	it('the payer rejects an invoice that does not mirror its request', async function () {
		const payer = new OfferManager(payerPriv);
		const issuer = new OfferManager(issuerPriv);
		const { offer } = issuer.createOffer({
			description: 'strict payer',
			amount: 5_000n
		});

		// No onion manager wired: requestInvoice registers the pending entry
		// and waits; we feed the response by hand.
		const pending = payer.requestInvoice(offer, { amount: 5_000n });
		pending.catch(() => {}); // asserted below; avoid unhandled rejection

		// The issuer answers a DIFFERENT (forged) request. The invoice is
		// validly signed over ITS OWN records, but the mirrored fields cannot
		// match the payer's invreq (metadata + payer key differ).
		const forged = issuer.handleInvoiceRequest(
			makeSignedRequestTlv({ amount: 5_000n }, offer)
		)!;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(payer as any).handleIncomingInvoice(encodeTlvStream(forged.records!));

		let rejected = '';
		await pending.catch((e: Error) => {
			rejected = e.message;
		});
		expect(rejected).to.match(/does not mirror/);
		payer.destroy();
		issuer.destroy();
	});

	it('the payer rejects an invoice without blinded paths', async function () {
		const payer = new OfferManager(payerPriv);
		const issuer = new OfferManager(issuerPriv);
		const { offer } = issuer.createOffer({
			description: 'needs paths',
			amount: 3_000n
		});
		const pending = payer.requestInvoice(offer, { amount: 3_000n });
		pending.catch(() => {});

		const issued = issuer.handleInvoiceRequest(
			makeSignedRequestTlv({ amount: 3_000n }, offer)
		)!;
		// Rebuild the invoice WITHOUT paths/payinfo (keeping the mirror) and
		// re-sign it so only the paths check can fail.
		const stripped: IBolt12Invoice = {
			paymentHash: issued.paymentHash,
			amount: issued.amount,
			description: issued.description,
			createdAt: issued.createdAt,
			relativeExpiry: issued.relativeExpiry,
			nodeId: issued.nodeId
		};
		const mirror = issued.records!.filter((r) => r.type < 160n);
		const unsigned = encodeInvoiceTlv(stripped, mirror);
		const root = computeMerkleRootFromRecords(getTlvRecords(unsigned));
		stripped.signature = schnorrSign(
			computeSignatureHash('lightninginvoicesignature', root),
			issuerPriv
		);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(payer as any).handleIncomingInvoice(encodeInvoiceTlv(stripped, mirror));

		let rejected = '';
		await pending.catch((e: Error) => {
			rejected = e.message;
		});
		expect(rejected).to.match(/invoice_paths/);
		payer.destroy();
		issuer.destroy();
	});
});
