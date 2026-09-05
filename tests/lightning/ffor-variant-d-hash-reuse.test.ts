/**
 * M8.8: hash reuse on Variant D, characterization (spec section 13.7, issue
 * #719). Two tests that pin the open problem rather than gate against it.
 *
 * (a) An honest S refuses a second payment on a consumed hash: single use
 *     IS implemented.
 * (b) A malicious S, the same node with its own duplicate guard omitted,
 *     settles a second payer on H_k with the token alone: the payment
 *     completes, R's epoch record is byte-identical before and after, and
 *     nothing reaches R. The theft is possible and evidence-free today.
 *
 * Test (b) is written to INVERT, that is to start failing, the day a
 * payer-and-amount binding (BOLT 12 / PTLC, section 13.5, section 13.7.1)
 * makes the second settlement unconstructable, giving that work a
 * regression target. Until then a change that makes (b) fail is a change
 * that closed the problem and should update this file, not a bug.
 */

import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { serializeFforEpoch } from '../../src/lightning/storage/serialization';
import { FforSlotState } from '../../src/lightning/ffor/types';
import {
	IWorld,
	NodeLink,
	TIP,
	activate,
	createWorld,
	exposeAndLeave,
	makeNodeConfig,
	openReadyChannel,
	pay,
	publishChannel,
	record
} from './helpers/ffor-world';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';

/** A second payer with its own channel to S, so the same invoice can be paid twice. */
function addPayer(w: IWorld): { p2: LightningNode; link: NodeLink } {
	const p2 = new LightningNode(
		makeNodeConfig(9_000 + Math.floor(Math.random() * 1000))
	);
	p2.on('node:error', () => {});
	const link = new NodeLink(p2, w.s);
	const channelId = openReadyChannel(p2, w.s, 1_000_000n);
	const scid = encodeShortChannelId({ block: 500, txIndex: 9, outputIndex: 0 });
	publishChannel(p2, p2, w.s, channelId, scid);
	p2.handleNewBlock(TIP);
	return { p2, link };
}

function payFrom(p: LightningNode, bolt11: string): PaymentStatus | undefined {
	const decoded = decodeInvoice(bolt11);
	try {
		p.sendPayment(bolt11);
	} catch {
		// retries may exhaust; the status is what matters
	}
	return p.getPayment(decoded.paymentHash)?.status;
}

describe('FFOR Variant D: hash reuse characterization (M8.8, section 13.7)', function () {
	this.timeout(30_000);

	it('(a) an honest S refuses a second payment on a consumed hash', () => {
		const w = createWorld();
		activate(w);
		const { p2 } = addPayer(w);
		const reasons: string[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			reasons.push(e.reason)
		);
		const [inv1] = exposeAndLeave(w, [1]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.SETTLED);
		expect(payFrom(p2, inv1)).to.equal(PaymentStatus.FAILED);
		expect(reasons).to.include('duplicate delegated payment for consumed hash');
	});

	it('(b) a malicious S settles a second payer with the token alone, evidence-free at R (inverts when payer-and-amount binding lands, section 13.7.1)', () => {
		const w = createWorld();
		activate(w);
		const { p2 } = addPayer(w);
		const [inv1] = exposeAndLeave(w, [1]);
		w.sr.log.length = 0;
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		const before = JSON.stringify(serializeFforEpoch(record(w.r, w.srHex)));

		// The same node, its duplicate guard omitted: the slot forgets it was
		// consumed. Nothing else changes; S still holds t_1 and the book.
		const sRec = record(w.s, w.srHex);
		sRec.slotStates[0] = FforSlotState.UNUSED;
		sRec.slotUpstream[0] = null;

		expect(
			payFrom(p2, inv1),
			'the second payer is settled on the same hash'
		).to.equal(PaymentStatus.COMPLETED);
		const after = JSON.stringify(serializeFforEpoch(record(w.r, w.srHex)));
		expect(after, "R's epoch record is byte-identical").to.equal(before);
		expect(w.sr.log, 'nothing reached R').to.have.length(0);
	});
});
