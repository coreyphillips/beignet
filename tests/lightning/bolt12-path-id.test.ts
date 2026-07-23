/**
 * BOLT 4/12 path_id verification.
 *
 * The payer embeds a path_id in the 1-hop blinded reply path it sends with
 * every invoice_request; the invoice MUST come back over that path (its
 * decrypted recipient data surfaces the path_id) to resolve the pending
 * request. Symmetrically, an offer whose blinded paths carry a path_id only
 * accepts invoice_requests that arrived over one of those paths.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	OfferManager,
	TLV_INVOICE_REQUEST,
	TLV_INVOICE
} from '../../src/lightning/offer/offer-manager';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';

function generateKeyPair(): { privkey: Buffer; pubkey: Buffer } {
	let privkey: Buffer;
	do {
		privkey = crypto.randomBytes(32);
	} while (privkey[0] === 0);
	return { privkey, pubkey: getPublicKey(privkey) };
}

interface IParty {
	privkey: Buffer;
	pubkey: Buffer;
	omm: OnionMessageManager;
	mgr: OfferManager;
}

/** Two OfferManagers wired through real onion messages (full sphinx). */
function setupParties(timeoutMs = 500): { payer: IParty; issuer: IParty } {
	const payerKeys = generateKeyPair();
	const issuerKeys = generateKeyPair();
	const payerOmm = new OnionMessageManager(payerKeys.privkey);
	const issuerOmm = new OnionMessageManager(issuerKeys.privkey);
	const payer: IParty = {
		...payerKeys,
		omm: payerOmm,
		mgr: new OfferManager(payerKeys.privkey, {
			onionMessageManager: payerOmm,
			invoiceRequestTimeoutMs: timeoutMs
		})
	};
	const issuer: IParty = {
		...issuerKeys,
		omm: issuerOmm,
		mgr: new OfferManager(issuerKeys.privkey, {
			onionMessageManager: issuerOmm,
			invoiceRequestTimeoutMs: timeoutMs
		})
	};

	const byId = new Map<string, OnionMessageManager>([
		[payerKeys.pubkey.toString('hex'), payerOmm],
		[issuerKeys.pubkey.toString('hex'), issuerOmm]
	]);
	for (const p of [payer, issuer]) {
		p.omm.setSendFunction((peer, _type, payload) => {
			// Deliver asynchronously (like a real wire): requestInvoice must be
			// able to register its pending entry before the reply lands.
			setImmediate(() => {
				byId.get(peer)?.handleMessage(p.pubkey.toString('hex'), payload);
			});
		});
	}
	return { payer, issuer };
}

function destroyParties(parties: { payer: IParty; issuer: IParty }): void {
	parties.payer.mgr.destroy();
	parties.issuer.mgr.destroy();
	parties.payer.omm.destroy();
	parties.issuer.omm.destroy();
}

describe('BOLT 12 path_id verification', function () {
	it('resolves an invoice that returns over our blinded reply path (E2E)', async function () {
		const parties = setupParties();
		const { payer, issuer } = parties;
		try {
			const { offer } = issuer.mgr.createOffer({
				description: 'path-id happy path',
				amount: 1000n
			});
			const invoice = await payer.mgr.requestInvoice(offer);
			expect(invoice.description).to.equal('path-id happy path');
			expect(invoice.amount).to.equal(1000n);
		} finally {
			destroyParties(parties);
		}
	});

	it('ignores an invoice whose path_id matches no pending request', async function () {
		const parties = setupParties(400);
		const { payer, issuer } = parties;
		try {
			// Capture the real invoice TLV as it arrives (extra handler).
			let invoiceTlv: Buffer | null = null;
			payer.omm.registerTlvHandler(TLV_INVOICE, (_f, _t, data) => {
				invoiceTlv = data;
			});
			const { offer } = issuer.mgr.createOffer({
				description: 'first request',
				amount: 1000n
			});
			await payer.mgr.requestInvoice(offer);
			expect(invoiceTlv).to.not.be.null;

			// Second pending request over a DEAD wire (the issuer never sees
			// it); replay the captured invoice with a FORGED path_id. It must
			// not resolve the pending request.
			payer.omm.setSendFunction(() => {});
			const { offer: offer2 } = issuer.mgr.createOffer({
				description: 'first request', // same desc: would match without path_id
				amount: 1000n
			});
			const errors: string[] = [];
			payer.mgr.on('invoice:error', (e: { error: string }) =>
				errors.push(e.error)
			);
			const pending = payer.mgr.requestInvoice(offer2).catch((e) => e);
			// Deliver by hand, bypassing the issuer entirely.
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(payer.mgr as any).handleIncomingInvoice(
				invoiceTlv!,
				crypto.randomBytes(32)
			);
			const outcome = await pending;
			expect(outcome).to.be.instanceOf(Error);
			expect((outcome as Error).message).to.match(/timed out/);
			expect(errors.some((e) => e.includes('matches no pending'))).to.be.true;
		} finally {
			destroyParties(parties);
		}
	});

	it('does not resolve a reply-path-bound pending request from a pathless invoice', async function () {
		const parties = setupParties(400);
		const { payer, issuer } = parties;
		try {
			let invoiceTlv: Buffer | null = null;
			payer.omm.registerTlvHandler(TLV_INVOICE, (_f, _t, data) => {
				invoiceTlv = data;
			});
			const { offer } = issuer.mgr.createOffer({
				description: 'no-path replay',
				amount: 1000n
			});
			await payer.mgr.requestInvoice(offer);

			// Dead wire: the second request never reaches the issuer.
			payer.omm.setSendFunction(() => {});
			const { offer: offer2 } = issuer.mgr.createOffer({
				description: 'no-path replay',
				amount: 1000n
			});
			const errors: string[] = [];
			payer.mgr.on('invoice:error', (e: { error: string }) =>
				errors.push(e.error)
			);
			const pending = payer.mgr.requestInvoice(offer2).catch((e) => e);
			// Deliver with NO path_id (as if it came addressed to us directly,
			// not over the blinded reply path we issued).
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(payer.mgr as any).handleIncomingInvoice(invoiceTlv!);
			const outcome = await pending;
			expect(outcome).to.be.instanceOf(Error);
			expect((outcome as Error).message).to.match(/timed out/);
			expect(errors.some((e) => e.includes('lacks the path_id'))).to.be.true;
		} finally {
			destroyParties(parties);
		}
	});

	it('accepts an invoice_request only over the offer path carrying its path_id (E2E + reject)', async function () {
		const parties = setupParties();
		const { payer, issuer } = parties;
		try {
			// Offer with a 1-hop blinded path to the issuer carrying a path_id.
			const offerPathId = crypto.randomBytes(32);
			const offerPath = constructBlindedPath(
				crypto.randomBytes(32),
				[issuer.pubkey],
				[{ pathId: offerPathId }]
			);
			// Capture the raw invreq TLV as the issuer receives it.
			let invreqTlv: Buffer | null = null;
			issuer.omm.registerTlvHandler(TLV_INVOICE_REQUEST, (_f, _t, data) => {
				invreqTlv = data;
			});
			const { offer } = issuer.mgr.createOffer({
				description: 'pathed offer',
				amount: 2000n,
				paths: [offerPath],
				pathId: offerPathId
			});

			// Happy path end to end: the invreq travels over the offer path, its
			// path_id decrypts at the issuer, and the invoice comes back.
			const invoice = await payer.mgr.requestInvoice(offer);
			expect(invoice.description).to.equal('pathed offer');
			expect(invreqTlv).to.not.be.null;

			// The SAME invreq delivered without (or with a wrong) path_id is
			// rejected: it did not arrive over the offer's blinded path.
			const errors: string[] = [];
			issuer.mgr.on('invoice:error', (e: { error: string }) =>
				errors.push(e.error)
			);
			expect(issuer.mgr.handleInvoiceRequest(invreqTlv!, undefined)).to.be.null;
			expect(
				issuer.mgr.handleInvoiceRequest(
					invreqTlv!,
					undefined,
					crypto.randomBytes(32)
				)
			).to.be.null;
			expect(errors.filter((e) => e === 'Invalid path_id').length).to.equal(2);

			// With the right path_id it issues.
			expect(
				issuer.mgr.handleInvoiceRequest(invreqTlv!, undefined, offerPathId)
			).to.not.be.null;
		} finally {
			destroyParties(parties);
		}
	});
});
