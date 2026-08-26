/**
 * Routable offer invoices for unannounced nodes (issue #544, LFBW port #532
 * workstream 1D).
 *
 * A node with no announced channels used to issue BOLT 12 invoices whose
 * single-hop blinded payment path terminated at the node itself: an
 * introduction node no payer can route to, since nothing about the node is
 * in the public graph. The OfferManager now consults an injected
 * buildPrivatePaymentPaths, which the LightningNode wires to real two-hop
 * paths through its peers with the peers' true payinfo, only when nothing is
 * announced. Hold paths keep absolute precedence and announced nodes (the
 * builder answers []) keep the CLN-style single-hop self path.
 *
 * Full E2E over real onion messages (the bolt12-path-id harness): the payer
 * receives and resolves the signed invoice, so the assertions cover what a
 * payer actually decodes.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { OfferManager } from '../../src/lightning/offer/offer-manager';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import {
	constructBlindedPath,
	IBlindedPaymentPath
} from '../../src/lightning/onion/blinded-path';

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
function setupParties(issuerOptions?: {
	buildHoldPaymentPaths?: (pathId: Buffer) => IBlindedPaymentPath[];
	buildPrivatePaymentPaths?: (pathId: Buffer) => IBlindedPaymentPath[];
}): { payer: IParty; issuer: IParty } {
	const payerKeys = generateKeyPair();
	const issuerKeys = generateKeyPair();
	const payerOmm = new OnionMessageManager(payerKeys.privkey);
	const issuerOmm = new OnionMessageManager(issuerKeys.privkey);
	const payer: IParty = {
		...payerKeys,
		omm: payerOmm,
		mgr: new OfferManager(payerKeys.privkey, {
			onionMessageManager: payerOmm,
			invoiceRequestTimeoutMs: 500
		})
	};
	const issuer: IParty = {
		...issuerKeys,
		omm: issuerOmm,
		mgr: new OfferManager(issuerKeys.privkey, {
			onionMessageManager: issuerOmm,
			invoiceRequestTimeoutMs: 500,
			...issuerOptions
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

/** A two-hop [peer -> issuer] payment path with the peer's "true" payinfo. */
function twoHopPath(
	peerPubkey: Buffer,
	issuerPubkey: Buffer,
	pathId: Buffer
): IBlindedPaymentPath {
	return {
		path: constructBlindedPath(
			crypto.randomBytes(32),
			[peerPubkey, issuerPubkey],
			[{ shortChannelId: Buffer.alloc(8, 5) }, { pathId }]
		),
		payInfo: {
			feeBaseMsat: 1000,
			feeProportionalMillionths: 250,
			cltvExpiryDelta: 80,
			htlcMinimumMsat: 1n,
			htlcMaximumMsat: 1_000_000_000n
		}
	};
}

describe('Offer invoices via private payment paths (issue #544)', function () {
	it('an unannounced issuer serves the two-hop path with the peer payinfo', async function () {
		const peer = generateKeyPair();
		const builderCalls: Buffer[] = [];
		const issuerPubkeyRef: { v?: Buffer } = {};
		const parties = setupParties({
			buildPrivatePaymentPaths: (pathId: Buffer): IBlindedPaymentPath[] => {
				builderCalls.push(pathId);
				return [twoHopPath(peer.pubkey, issuerPubkeyRef.v!, pathId)];
			}
		});
		issuerPubkeyRef.v = parties.issuer.pubkey;
		try {
			const { offer } = parties.issuer.mgr.createOffer({
				description: 'private-path offer',
				amount: 1000n
			});
			const invoice = await parties.payer.mgr.requestInvoice(offer);
			// The payer decodes an introduction node it can actually route to:
			// the PEER, not the unannounced issuer.
			expect(invoice.paths).to.have.length(1);
			expect(
				Buffer.from(invoice.paths![0].introductionNodeId).equals(peer.pubkey)
			).to.equal(true);
			// And the peer's true forwarding policy rides as the payinfo, so
			// the payer sizes fees and timelocks correctly.
			expect(invoice.blindedPayInfo).to.have.length(1);
			expect(invoice.blindedPayInfo![0].feeBaseMsat).to.equal(1000);
			expect(invoice.blindedPayInfo![0].feeProportionalMillionths).to.equal(
				250
			);
			expect(invoice.blindedPayInfo![0].cltvExpiryDelta).to.equal(80);
			// The builder received the per-invoice path_id (32 bytes), the same
			// authentication the self path carries.
			expect(builderCalls).to.have.length(1);
			expect(builderCalls[0].length).to.equal(32);
		} finally {
			destroyParties(parties);
		}
	});

	it('an announced issuer (builder answers []) keeps the single-hop self path', async function () {
		const parties = setupParties({
			buildPrivatePaymentPaths: (): IBlindedPaymentPath[] => []
		});
		try {
			const { offer } = parties.issuer.mgr.createOffer({
				description: 'announced offer',
				amount: 1000n
			});
			const invoice = await parties.payer.mgr.requestInvoice(offer);
			expect(invoice.paths).to.have.length(1);
			expect(
				Buffer.from(invoice.paths![0].introductionNodeId).equals(
					parties.issuer.pubkey
				)
			).to.equal(true);
			// The CLN-style shape: zero-fee self path, unchanged.
			expect(invoice.blindedPayInfo![0].feeBaseMsat).to.equal(0);
			expect(invoice.blindedPayInfo![0].cltvExpiryDelta).to.equal(18);
		} finally {
			destroyParties(parties);
		}
	});

	it('a bare OfferManager (no builder) is unchanged', async function () {
		const parties = setupParties();
		try {
			const { offer } = parties.issuer.mgr.createOffer({
				description: 'bare offer',
				amount: 1000n
			});
			const invoice = await parties.payer.mgr.requestInvoice(offer);
			expect(
				Buffer.from(invoice.paths![0].introductionNodeId).equals(
					parties.issuer.pubkey
				)
			).to.equal(true);
		} finally {
			destroyParties(parties);
		}
	});

	it('hold paths keep precedence; the private builder is never consulted', async function () {
		const peer = generateKeyPair();
		const counters = { privateCalls: 0 };
		const issuerPubkeyRef: { v?: Buffer } = {};
		const parties = setupParties({
			buildHoldPaymentPaths: (pathId: Buffer): IBlindedPaymentPath[] => [
				twoHopPath(peer.pubkey, issuerPubkeyRef.v!, pathId)
			],
			buildPrivatePaymentPaths: (): IBlindedPaymentPath[] => {
				counters.privateCalls++;
				return [];
			}
		});
		issuerPubkeyRef.v = parties.issuer.pubkey;
		try {
			const { offer } = parties.issuer.mgr.createOffer({
				description: 'hold offer',
				amount: 1000n,
				asyncHold: true
			});
			const invoice = await parties.payer.mgr.requestInvoice(offer);
			// The hold path (also through the peer here) won, untouched by 1D.
			expect(
				Buffer.from(invoice.paths![0].introductionNodeId).equals(peer.pubkey)
			).to.equal(true);
			expect(counters.privateCalls, 'private builder never consulted').to.equal(
				0
			);
		} finally {
			destroyParties(parties);
		}
	});

	it('an async-hold offer with NO hold paths falls to the self path, never a private one', async function () {
		// A private hop carries no hold_htlc: substituting it for a missing
		// hold path would make the LSP forward the HTLC to an offline
		// recipient instead of parking it (issue #544 review). The safe
		// fallback is the self path, exactly as before this change.
		const counters = { privateCalls: 0 };
		const parties = setupParties({
			buildHoldPaymentPaths: (): IBlindedPaymentPath[] => [],
			buildPrivatePaymentPaths: (): IBlindedPaymentPath[] => {
				counters.privateCalls++;
				return [];
			}
		});
		try {
			const { offer } = parties.issuer.mgr.createOffer({
				description: 'hold offer, no usable LSP path',
				amount: 1000n,
				asyncHold: true
			});
			const invoice = await parties.payer.mgr.requestInvoice(offer);
			expect(
				Buffer.from(invoice.paths![0].introductionNodeId).equals(
					parties.issuer.pubkey
				),
				'self path'
			).to.equal(true);
			expect(
				counters.privateCalls,
				'private builder never consulted for a hold offer'
			).to.equal(0);
		} finally {
			destroyParties(parties);
		}
	});
});
