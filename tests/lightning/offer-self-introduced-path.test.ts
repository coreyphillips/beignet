/**
 * Issue #1974: a payer that is the introduction node of an offer's blinded
 * path. An unannounced issuer's offer path is [its channel peer, issuer],
 * and when that peer pays the offer it cannot hand the invoice_request to
 * its own node id: it processes its own hop and sends to the issuer. A path
 * that ends at the payer (its own offer) is delivered locally.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { InvalidRequestError } from '../../src/lightning/node/types';
import { OfferManager } from '../../src/lightning/offer/offer-manager';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';
import {
	PeerError,
	PeerErrorCode
} from '../../src/lightning/transport/peer-manager';

interface IParty {
	pubkey: Buffer;
	hex: string;
	omm: OnionMessageManager;
	mgr: OfferManager;
	/** Node ids this party's transport was asked to send to. */
	sentTo: string[];
	/** Node ids requestInvoice asked to be connected to. */
	dialed: string[];
}

function party(privkey: Buffer): IParty {
	const omm = new OnionMessageManager(privkey);
	const dialed: string[] = [];
	const mgr = new OfferManager(privkey, {
		onionMessageManager: omm,
		invoiceRequestTimeoutMs: 1_000,
		connectFirstHop: async (nodeId: Buffer): Promise<void> => {
			dialed.push(nodeId.toString('hex'));
		}
	});
	const pubkey = getPublicKey(privkey);
	return { pubkey, hex: pubkey.toString('hex'), omm, mgr, sentTo: [], dialed };
}

/** Parties linked the way PeerManager links them: no link to oneself. */
function link(parties: IParty[]): void {
	const byId = new Map(parties.map((p) => [p.hex, p]));
	for (const p of parties) {
		p.omm.setSendFunction((peer, _type, payload) => {
			p.sentTo.push(peer);
			const to = byId.get(peer);
			if (!to || to === p) {
				throw new PeerError(
					PeerErrorCode.NOT_CONNECTED,
					`Not connected to peer ${peer}`
				);
			}
			setImmediate(() => to.omm.handleMessage(p.hex, payload));
		});
	}
}

function destroy(parties: IParty[]): void {
	for (const p of parties) {
		p.mgr.destroy();
		p.omm.destroy();
	}
}

describe('Offer paths introduced by the payer (issue #1974)', function () {
	let payer: IParty;
	let issuer: IParty;

	beforeEach(() => {
		payer = party(crypto.randomBytes(32));
		issuer = party(crypto.randomBytes(32));
		link([payer, issuer]);
	});

	afterEach(() => destroy([payer, issuer]));

	it('sends the invoice_request to the hop after the payer', async () => {
		// The message path an unannounced issuer builds through its peer.
		const pathId = crypto.randomBytes(32);
		const { offer } = issuer.mgr.createOffer({
			description: 'introduced by the payer',
			amount: 1_234_000n,
			paths: [
				constructBlindedPath(
					crypto.randomBytes(32),
					[payer.pubkey, issuer.pubkey],
					[{ nextNodeId: issuer.pubkey }, { pathId }]
				)
			],
			pathId
		});

		const invoice = await payer.mgr.requestInvoice(offer);

		expect(invoice.amount).to.equal(1_234_000n);
		expect(payer.dialed).to.deep.equal([issuer.hex]);
		expect(payer.sentTo).to.deep.equal([issuer.hex]);
		// The invoice came back over the payer's reply path.
		expect(issuer.sentTo).to.deep.equal([payer.hex]);
	});

	it('delivers a request over a path that ends at the payer locally', async () => {
		const { offer } = payer.mgr.createOffer({
			description: 'my own offer',
			amount: 5_000n
		});

		const invoice = await payer.mgr.requestInvoice(offer);

		expect(invoice.amount).to.equal(5_000n);
		expect(payer.sentTo).to.deep.equal([]);
	});

	it('refuses a path naming the payer whose hop it cannot read', async () => {
		const stranger = getPublicKey(crypto.randomBytes(32));
		const path = constructBlindedPath(
			crypto.randomBytes(32),
			[stranger, issuer.pubkey],
			[{ nextNodeId: issuer.pubkey }, {}]
		);
		const { offer } = issuer.mgr.createOffer({
			description: 'forged introduction',
			amount: 1_000n,
			paths: [{ ...path, introductionNodeId: payer.pubkey }]
		});

		let err: unknown;
		try {
			await payer.mgr.requestInvoice(offer);
		} catch (e) {
			err = e;
		}

		expect(err).to.be.instanceOf(InvalidRequestError);
		expect((err as Error).message).to.contain('Cannot decrypt our own hop');
		expect(payer.sentTo).to.deep.equal([]);
	});
});
