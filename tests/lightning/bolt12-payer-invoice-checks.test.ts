/**
 * Issue #1006: the BOLT 12 payer holds an invoice that arrives over its own
 * reply path to the offer it asked about. The invoice must charge exactly the
 * invreq_amount that was sent, be signed by the offer's issuer, and not have
 * expired; each of those used to be accepted and paid.
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
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import {
	constructBlindedPath,
	deriveBlindedPrivkey
} from '../../src/lightning/onion/blinded-path';
import {
	IBolt12Invoice,
	IInvoiceRequest
} from '../../src/lightning/offer/types';
import { ITlvRecord } from '../../src/lightning/message/tlv';

const issuerPriv = crypto.randomBytes(32);
const strangerPriv = crypto.randomBytes(32);

interface IExchange {
	payer: OfferManager;
	issuer: OfferManager;
	omm: OnionMessageManager;
	/** The payer's request, still waiting for its invoice. */
	pending: Promise<IBolt12Invoice | Error>;
	/** The path_id our reply path surfaces, as the onion layer would. */
	replyPathId: Buffer;
	/** The issuer's genuine answer to that request. */
	issued: IBolt12Invoice;
	errors: Array<{ error: string; matchedPendingRequest?: boolean }>;
}

/**
 * A payer wired to a wire that goes nowhere, so its request carries a real
 * reply path; the invoice is then delivered by hand with that path's path_id.
 */
function openExchange(): IExchange {
	const payerPriv = crypto.randomBytes(32);
	const omm = new OnionMessageManager(payerPriv);
	omm.setSendFunction(() => {});
	const payer = new OfferManager(payerPriv, {
		onionMessageManager: omm,
		invoiceRequestTimeoutMs: 5_000
	});
	const issuer = new OfferManager(issuerPriv);
	const { offer } = issuer.createOffer({
		description: '1000 sat offer',
		amount: 1_000_000n
	});
	const errors: IExchange['errors'] = [];
	payer.on('invoice:error', (e) => errors.push(e));
	let request: IInvoiceRequest | null = null;
	payer.on('invoice:requested', (r: IInvoiceRequest) => {
		request = r;
	});
	const pending = payer.requestInvoice(offer).catch((e: Error) => e);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const keys = [...(payer as any).pendingInvoiceRequests.keys()] as string[];
	expect(keys).to.have.length(1);
	const issued = issuer.handleInvoiceRequest(
		encodeInvoiceRequestTlv(request!, encodeOfferTlv(offer))
	)!;
	expect(issued).to.not.equal(null);
	return {
		payer,
		issuer,
		omm,
		pending,
		replyPathId: Buffer.from(keys[0], 'hex'),
		issued,
		errors
	};
}

/** The issued invoice with fields replaced, signed by `signerPriv`. */
function reissue(
	issued: IBolt12Invoice,
	signerPriv: Buffer,
	fields: Partial<IBolt12Invoice> = {}
): Buffer {
	const invoice: IBolt12Invoice = {
		paymentHash: issued.paymentHash,
		amount: issued.amount,
		description: issued.description,
		createdAt: issued.createdAt,
		relativeExpiry: issued.relativeExpiry,
		nodeId: getPublicKey(signerPriv),
		paths: issued.paths,
		blindedPayInfo: issued.blindedPayInfo,
		...fields
	};
	const mirror = issued.records!.filter((r) => r.type < 160n);
	const root = computeMerkleRootFromRecords(
		getTlvRecords(encodeInvoiceTlv(invoice, mirror))
	);
	invoice.signature = schnorrSign(
		computeSignatureHash('lightninginvoicesignature', root),
		signerPriv
	);
	return encodeInvoiceTlv(invoice, mirror);
}

function deliver(x: IExchange, invoiceTlv: Buffer): void {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(x.payer as any).handleIncomingInvoice(invoiceTlv, x.replyPathId);
}

async function expectRejected(x: IExchange, reason: RegExp): Promise<void> {
	const outcome = await x.pending;
	expect(outcome).to.be.instanceOf(Error);
	expect((outcome as Error).message).to.match(reason);
	expect(x.errors).to.have.length(1);
	expect(x.errors[0].error).to.match(reason);
	expect(x.errors[0].matchedPendingRequest).to.equal(true);
}

describe('BOLT 12 payer checks the invoice against its request (#1006)', function () {
	let x: IExchange;

	beforeEach(() => {
		x = openExchange();
	});

	afterEach(() => {
		x.payer.destroy();
		x.issuer.destroy();
		x.omm.destroy();
	});

	it('accepts the issuer invoice for the requested amount', async function () {
		deliver(x, reissue(x.issued, issuerPriv));
		const outcome = await x.pending;
		expect(outcome).to.not.be.instanceOf(Error);
		expect((outcome as IBolt12Invoice).amount).to.equal(1_000_000n);
	});

	it('rejects an issuer-signed invoice charging more than was requested', async function () {
		deliver(x, reissue(x.issued, issuerPriv, { amount: 1_000_000_000n }));
		await expectRejected(
			x,
			/invoice_amount 1000000000 msat is not the requested 1000000 msat/
		);
	});

	it('rejects an invoice charging less than was requested', async function () {
		deliver(x, reissue(x.issued, issuerPriv, { amount: 999_999n }));
		await expectRejected(x, /is not the requested/);
	});

	it('rejects an invoice signed by a key other than the offer issuer', async function () {
		deliver(x, reissue(x.issued, strangerPriv));
		await expectRejected(x, /not the signer the offer designates/);
	});

	it('rejects an invoice whose relative expiry has passed', async function () {
		const tenDaysAgo = BigInt(Math.floor(Date.now() / 1000) - 10 * 86_400);
		deliver(x, reissue(x.issued, issuerPriv, { createdAt: tenDaysAgo }));
		await expectRejected(x, /invoice has expired/);
	});

	it('applies the 7200s default when the invoice sets no relative expiry', async function () {
		const createdAt = BigInt(Math.floor(Date.now() / 1000) - 7_300);
		deliver(
			x,
			reissue(x.issued, issuerPriv, { createdAt, relativeExpiry: undefined })
		);
		await expectRejected(x, /invoice has expired/);
	});
});

describe('BOLT 12 payer holds a path-terminal invoice to the path it used (#1095)', function () {
	const terminalPrivs = [crypto.randomBytes(32), crypto.randomBytes(32)];
	const offerPaths = terminalPrivs.map((priv) =>
		constructBlindedPath(crypto.randomBytes(32), [getPublicKey(priv)], [{}])
	);
	let payer: OfferManager;
	let issuer: OfferManager;
	let omm: OnionMessageManager;
	let pending: Promise<IBolt12Invoice | Error>;
	let replyPathId: Buffer;
	let sentRecords: ITlvRecord[];
	let errors: Array<{ error: string; matchedPendingRequest?: boolean }>;

	beforeEach(() => {
		const payerPriv = crypto.randomBytes(32);
		omm = new OnionMessageManager(payerPriv);
		omm.setSendFunction(() => {});
		payer = new OfferManager(payerPriv, {
			onionMessageManager: omm,
			invoiceRequestTimeoutMs: 5_000
		});
		issuer = new OfferManager(issuerPriv);
		const { offer } = issuer.createOffer({
			description: 'two-path offer',
			amount: 1_000_000n,
			paths: offerPaths,
			pathTerminal: true
		});
		errors = [];
		payer.on('invoice:error', (e) => errors.push(e));
		pending = payer.requestInvoice(offer).catch((e: Error) => e);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const entries = [...(payer as any).pendingInvoiceRequests.entries()];
		expect(entries).to.have.length(1);
		replyPathId = Buffer.from(entries[0][0], 'hex');
		sentRecords = entries[0][1].sentRecords;
	});

	afterEach(() => {
		payer.destroy();
		issuer.destroy();
		omm.destroy();
	});

	/** A valid invoice for the request, signed by the terminal of `pathIndex`. */
	function signedByPath(pathIndex: number): Buffer {
		const path = offerPaths[pathIndex];
		const signerPriv = deriveBlindedPrivkey(
			path.blindingPoint,
			terminalPrivs[pathIndex]
		);
		const invoice: IBolt12Invoice = {
			paymentHash: crypto.randomBytes(32),
			amount: 1_000_000n,
			description: 'two-path offer',
			createdAt: BigInt(Math.floor(Date.now() / 1000)),
			relativeExpiry: 7200,
			nodeId: path.blindedHops[0].blindedNodeId,
			paths: [path],
			blindedPayInfo: [
				{
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 18,
					htlcMinimumMsat: 1n,
					htlcMaximumMsat: 1_000_000_000n
				}
			]
		};
		const mirror = sentRecords.filter((r) => r.type < 160n);
		const root = computeMerkleRootFromRecords(
			getTlvRecords(encodeInvoiceTlv(invoice, mirror))
		);
		invoice.signature = schnorrSign(
			computeSignatureHash('lightninginvoicesignature', root),
			signerPriv
		);
		return encodeInvoiceTlv(invoice, mirror);
	}

	function deliverPathInvoice(invoiceTlv: Buffer): void {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(payer as any).handleIncomingInvoice(invoiceTlv, replyPathId);
	}

	it('accepts an invoice signed by the terminal of the path it sent to', async function () {
		deliverPathInvoice(signedByPath(0));
		const outcome = await pending;
		expect(outcome).to.not.be.instanceOf(Error);
		expect((outcome as IBolt12Invoice).nodeId).to.deep.equal(
			offerPaths[0].blindedHops[0].blindedNodeId
		);
	});

	it('rejects an invoice signed by the terminal of another offer path', async function () {
		deliverPathInvoice(signedByPath(1));
		const outcome = await pending;
		expect(outcome).to.be.instanceOf(Error);
		expect((outcome as Error).message).to.match(
			/not the signer the offer designates/
		);
		expect(errors).to.have.length(1);
		expect(errors[0].matchedPendingRequest).to.equal(true);
	});
});

describe('BOLT 12 payer needs an amount for an amountless offer (#1006)', function () {
	it('refuses before sending a request with nothing to hold the invoice to', async function () {
		const payerPriv = crypto.randomBytes(32);
		const omm = new OnionMessageManager(payerPriv);
		let sends = 0;
		omm.setSendFunction(() => {
			sends++;
		});
		const payer = new OfferManager(payerPriv, { onionMessageManager: omm });
		const issuer = new OfferManager(issuerPriv);
		try {
			const { offer } = issuer.createOffer({ description: 'any amount' });
			const outcome = await payer.requestInvoice(offer).catch((e: Error) => e);
			expect(outcome).to.be.instanceOf(Error);
			expect((outcome as Error).message).to.match(/Amount required/);
			expect(sends).to.equal(0);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect((payer as any).pendingInvoiceRequests.size).to.equal(0);
		} finally {
			payer.destroy();
			issuer.destroy();
			omm.destroy();
		}
	});
});
