/**
 * Issue #2093: the records of a payment that asset HTLCs carried.
 *
 * The HTLC of an asset payment carries 354 sat of bitcoin and the units in
 * its custom records. Its sender's record keeps that carrier in amountMsat,
 * where the receiver's has what the host valued the units at, so neither is
 * bitcoin that moved. Both are marked `auxiliary: true`, the sender's also
 * says what the payment is worth to the payee, and the invoice it paid is
 * marked too. A record of an ordinary payment has none of these keys.
 */

import { expect } from 'chai';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	deserializeInvoiceInfo,
	deserializePaymentInfo,
	serializeInvoiceInfo,
	serializePaymentInfo
} from '../../src/lightning/storage/serialization';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	payAssetUnits,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

describe('the records of a payment that asset HTLCs carried (issue #2093 step 8)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	it('marks the payment on both sides and the invoice it paid, and gives the sender what it was worth to the payee', async () => {
		const alice = assetHost('aux-records', 1, {}, { sqlite: true });
		const bob = assetHost(
			'aux-records',
			2,
			{ valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n },
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag: 'aux-records',
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const settled: Array<Record<string, unknown>> = [];
		bob.node.on('invoice:settled', (data: Record<string, unknown>) => {
			settled.push(data);
		});
		const invoice = bob.node.createInvoice({
			amountMsat: 5_000_000n,
			description: 'paid in units'
		});
		const hashHex = invoice.paymentHash.toString('hex');
		// Unpaid, the invoice says nothing of assets.
		expect('auxiliary' in bob.node.getInvoice(hashHex)!).to.equal(false);
		payAssetUnits(alice, bob, channelId, invoice, 5_000_000n, 5000n);
		await turns(200);

		const sent = alice.node.getPayment(invoice.paymentHash)!;
		expect(sent.status).to.equal(PaymentStatus.COMPLETED);
		// The bitcoin of the carrier, unchanged, and beside it the value.
		expect(sent.amountMsat).to.equal(354_000n);
		expect(sent.auxiliary).to.equal(true);
		expect(sent.auxiliaryValueMsat).to.equal(5_000_000n);

		const received = bob.node.getPayment(invoice.paymentHash)!;
		expect(received.status).to.equal(PaymentStatus.COMPLETED);
		expect(received.amountMsat).to.equal(5_000_000n);
		expect(received.auxiliary).to.equal(true);
		expect('auxiliaryValueMsat' in received).to.equal(false);

		expect(bob.node.getInvoice(hashHex)!.auxiliary).to.equal(true);
		expect(settled).to.have.length(1);
		expect(settled[0].auxiliary).to.equal(true);

		// The marks are in what is stored, and come back from it.
		for (const record of [sent, received]) {
			const stored = serializePaymentInfo(record);
			expect(stored.auxiliary).to.equal(true);
			const back = deserializePaymentInfo(
				JSON.parse(JSON.stringify(stored)) as typeof stored
			);
			expect(back.auxiliary).to.equal(true);
			expect(back.auxiliaryValueMsat).to.equal(record.auxiliaryValueMsat);
		}
		const storedInvoice = serializeInvoiceInfo(bob.node.getInvoice(hashHex)!);
		expect(storedInvoice.auxiliary).to.equal(true);
		expect(
			deserializeInvoiceInfo(
				JSON.parse(JSON.stringify(storedInvoice)) as typeof storedInvoice
			).auxiliary
		).to.equal(true);
		const row = bob.storage!.loadPayment(hashHex);
		expect(row, 'the stored payment').to.not.equal(null);
		expect(row!.auxiliary).to.equal(true);
	});

	it('leaves the record of a payment no asset HTLC carried, and its stored form, without the keys', () => {
		const bob = assetHost('aux-records-plain', 2, {}, { sqlite: true });
		hosts.push(bob);
		const invoice = bob.node.createInvoice({
			amountMsat: 1_000_000n,
			description: 'bitcoin'
		});
		const record = bob.node.getPayment(invoice.paymentHash)!;
		const stored = serializePaymentInfo(record);
		for (const key of ['auxiliary', 'auxiliaryValueMsat']) {
			expect(key in record, `record.${key}`).to.equal(false);
			expect(key in stored, `stored.${key}`).to.equal(false);
			expect(key in deserializePaymentInfo(stored)).to.equal(false);
		}
		const info = bob.node.getInvoice(invoice.paymentHash.toString('hex'))!;
		expect('auxiliary' in info).to.equal(false);
		expect('auxiliary' in serializeInvoiceInfo(info)).to.equal(false);
		expect(
			'auxiliary' in deserializeInvoiceInfo(serializeInvoiceInfo(info))
		).to.equal(false);
	});
});
