/**
 * Issue #2047: an invoice_request tries each of the offer's blinded paths in
 * turn, so a first path whose introduction node cannot be reached does not
 * end the request, and a `sciddir` introduction point is resolved to the
 * node it names before dialing.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { OfferManager } from '../../src/lightning/offer/offer-manager';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';
import {
	PeerError,
	PeerErrorCode
} from '../../src/lightning/transport/peer-manager';

/** Introduction nodes every party's dialer fails to reach. */
const unreachable = new Set<string>();

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
			if (unreachable.has(nodeId.toString('hex'))) {
				throw new Error('cannot reach introduction node');
			}
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

describe('Offer path fallback for invoice requests (issue #2047)', function () {
	let payer: IParty;
	let issuer: IParty;

	beforeEach(() => {
		unreachable.clear();
		payer = party(crypto.randomBytes(32));
		issuer = party(crypto.randomBytes(32));
		link([payer, issuer]);
	});

	afterEach(() => destroy([payer, issuer]));

	it('sends over the second path when the first introduction node is unreachable', async () => {
		const ghost = getPublicKey(crypto.randomBytes(32));
		unreachable.add(ghost.toString('hex'));
		const pathId = crypto.randomBytes(32);
		const { offer } = issuer.mgr.createOffer({
			description: 'two paths',
			amount: 2_000n,
			paths: [
				constructBlindedPath(
					crypto.randomBytes(32),
					[ghost, issuer.pubkey],
					[{ nextNodeId: issuer.pubkey }, { pathId }]
				),
				constructBlindedPath(
					crypto.randomBytes(32),
					[issuer.pubkey],
					[{ pathId }]
				)
			],
			pathId
		});

		const invoice = await payer.mgr.requestInvoice(offer);

		expect(invoice.amount).to.equal(2_000n);
		expect(payer.dialed).to.deep.equal([ghost.toString('hex'), issuer.hex]);
		expect(payer.sentTo).to.deep.equal([issuer.hex]);
	});

	it('reports the last failure when no path can be reached', async () => {
		const ghost = getPublicKey(crypto.randomBytes(32));
		unreachable.add(ghost.toString('hex'));
		unreachable.add(issuer.hex);
		const { offer } = issuer.mgr.createOffer({
			description: 'no reachable path',
			amount: 2_000n,
			paths: [
				constructBlindedPath(
					crypto.randomBytes(32),
					[ghost, issuer.pubkey],
					[{ nextNodeId: issuer.pubkey }, {}]
				),
				constructBlindedPath(crypto.randomBytes(32), [issuer.pubkey], [{}])
			]
		});

		let err: unknown;
		try {
			await payer.mgr.requestInvoice(offer);
		} catch (e) {
			err = e;
		}
		expect((err as Error).message).to.equal('cannot reach introduction node');
		expect(payer.dialed).to.deep.equal([ghost.toString('hex'), issuer.hex]);
		expect(payer.sentTo).to.deep.equal([]);
	});

	it('dials the node a sciddir introduction point names', async () => {
		const scid = Buffer.alloc(8, 5);
		payer.omm.setChannelLookup((s) =>
			s.equals(scid)
				? {
						nodeId1: issuer.pubkey,
						nodeId2: getPublicKey(crypto.randomBytes(32))
				  }
				: undefined
		);
		const pathId = crypto.randomBytes(32);
		const path = constructBlindedPath(
			crypto.randomBytes(32),
			[issuer.pubkey],
			[{ pathId }]
		);
		const { offer } = issuer.mgr.createOffer({
			description: 'sciddir',
			amount: 3_000n,
			paths: [
				{ ...path, introductionNodeId: Buffer.concat([Buffer.from([0]), scid]) }
			],
			pathId
		});

		const invoice = await payer.mgr.requestInvoice(offer);

		expect(invoice.amount).to.equal(3_000n);
		expect(payer.dialed).to.deep.equal([issuer.hex]);
		expect(payer.sentTo).to.deep.equal([issuer.hex]);
	});
});
