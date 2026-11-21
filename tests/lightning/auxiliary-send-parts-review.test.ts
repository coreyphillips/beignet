/**
 * Issue #2098, step 9: what the record of an asset payment sent in parts
 * says once it completed, on the chain world of auxiliary-forward-world.ts
 * (Alice pays Carol through Bob): no failure of a part that was replaced,
 * in the one record object every send of the payment returned.
 */

import { expect } from 'chai';
import { PaymentStatus } from '../../src/lightning/node/types';
import { TEMPORARY_CHANNEL_FAILURE } from '../../src/lightning/onion/types';
import { rounds } from './helpers/auxiliary-forward-scene';
import {
	forwardChainWorld,
	partsInvoice,
	sendAssetPart
} from './helpers/auxiliary-forward-world';
import {
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	withAssetPartsSent
} from './helpers/auxiliary-nodes';
import { collected } from './helpers/auxiliary-parts-checks';
import { openSendScene } from './helpers/auxiliary-send-scene';

describe('the record of an asset payment sent in parts (#2098, step 9)', function () {
	this.timeout(120_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	withAssetPartsSent();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	it('completes without the failure of a part that was replaced, in the record object every send of it returned', async () => {
		const tag = 'review-parts-record';
		const s = await openSendScene(world, tag, {
			world: { secondIn: 'asset' }
		});
		const invoice = partsInvoice(s.w, tag, 5_000_000n);
		const h = invoice.paymentHash;
		const alice = s.w.hosts.alice.node;
		const first = sendAssetPart(s.w, invoice, { valueMsat: 3_000_000n });
		expect(first.error).to.equal(undefined);
		await rounds(
			'Carol collects the first part',
			() => collected(s.w.hosts.carol, h) === 1,
			60
		);
		s.bobRefuses.next = 1;
		const second = sendAssetPart(s.w, invoice, { valueMsat: 2_000_000n });
		expect(second.error).to.equal(undefined);
		expect(
			first.payment === alice.getPayment(h),
			'the record the first send returned is still the node record'
		).to.equal(true);
		await rounds(
			'the second part has failed',
			() =>
				alice.getAuxiliaryPaymentHtlcs(h).some((part) => part.failed === true),
			60
		);
		await turns(50);
		const again = sendAssetPart(s.w, invoice, {
			valueMsat: 2_000_000n,
			channelId: s.w.inChannel2
		});
		expect(again.error).to.equal(undefined);
		await rounds(
			'Alice is paid',
			() => alice.getPayment(h)?.status === PaymentStatus.COMPLETED,
			60
		);
		await turns(50);
		const record = alice.getPayment(h)!;
		expect(
			first.payment?.status,
			'the object the first send returned sees the settle'
		).to.equal(PaymentStatus.COMPLETED);
		expect({
			status: record.status,
			failureCode: record.failureCode,
			failureSourceIndex: record.failureSourceIndex
		}).to.deep.equal({
			status: PaymentStatus.COMPLETED,
			failureCode: undefined,
			failureSourceIndex: undefined
		});
		void TEMPORARY_CHANNEL_FAILURE;
	});
});
