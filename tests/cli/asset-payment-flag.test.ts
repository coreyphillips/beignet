/**
 * The daemon carries the node's mark on a payment or an invoice that asset
 * HTLCs carried, and marks the events of an asset channel (issue #2093).
 *
 * `auxiliary: true` is on the rows and events of such a payment, invoice or
 * channel and on no other: a wallet without asset channels answers the
 * bytes it did. A marked outgoing payment also says what it was worth to
 * the payee, since its amount and fee are the bitcoin that carried it, and
 * no bitcoin total of getStats counts a marked payment.
 *
 * The node's records are faked here, at the one place the daemon reads
 * them, so each figure below is the daemon's own doing.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import type { IPaymentInfo } from '../../src/lightning/node/payment-types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/payment-types';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => Record<string, unknown>
>;

const payment = (fill: number, extra: Partial<IPaymentInfo>): IPaymentInfo => ({
	paymentHash: Buffer.alloc(32, fill),
	amountMsat: 20_000_000n,
	status: PaymentStatus.COMPLETED,
	direction: PaymentDirection.OUTGOING,
	createdAt: 1_700_000_000_000,
	...extra
});

/** An ordinary payment out, with a fee of 21 sats. */
const sent = payment(1, { sentMsat: 20_021_000n });
/** An ordinary payment in. */
const received = payment(2, {
	direction: PaymentDirection.INCOMING,
	receivedMsat: 20_000_000n
});
/** An asset payment out: 354 sats carried it, worth 25000 to the payee. */
const assetSent = payment(3, {
	amountMsat: 354_000n,
	sentMsat: 355_000n,
	auxiliary: true,
	auxiliaryValueMsat: 25_000_000n
});
/** An asset payment in. */
const assetReceived = payment(4, {
	direction: PaymentDirection.INCOMING,
	amountMsat: 354_000n,
	receivedMsat: 354_000n,
	auxiliary: true
});

const assetChannel = Buffer.alloc(32, 7);

const daemonOf = (payments: IPaymentInfo[]): unknown => ({
	node: {
		listPayments: (): IPaymentInfo[] => payments,
		getAuxiliaryChannelInfo: (channelId: Buffer): unknown =>
			channelId.equals(assetChannel) ? { localAssetBalance: 1n } : undefined
	},
	startedAt: Date.now()
});

const rowOf = (record: IPaymentInfo): Record<string, unknown> =>
	methods.toPaymentInfo.call(daemonOf([]), record);

describe('The daemon carries the mark of an asset payment, invoice and channel (#2093)', () => {
	it('marks the row of a payment that asset HTLCs carried, and says what an outgoing one was worth', () => {
		const out = rowOf(assetSent);
		expect(out.auxiliary).to.equal(true);
		expect(out.auxiliaryValueSats).to.equal(25_000);
		// The amount and the fee stay what the node has: the carrier.
		expect(out.amountSats).to.equal(
			rowOf({ ...assetSent, auxiliary: undefined }).amountSats
		);
		expect(out.feeSats).to.equal(1);
		const incoming = rowOf(assetReceived);
		expect(incoming.auxiliary).to.equal(true);
		expect(incoming).to.not.have.property('auxiliaryValueSats');
	});

	it('answers an ordinary payment the row it did, with no key of an asset payment', () => {
		expect(rowOf(sent)).to.deep.equal({
			paymentHash: '01'.repeat(32),
			amountSats: 20_021,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: 1_700_000_000_000,
			feeSats: 21
		});
		expect(rowOf(received)).to.deep.equal({
			paymentHash: '02'.repeat(32),
			amountSats: 20_000,
			status: 'COMPLETED',
			direction: 'INCOMING',
			createdAt: 1_700_000_000_000
		});
		// A value without the mark is not an asset payment's.
		expect(rowOf({ ...sent, auxiliaryValueMsat: 5_000n })).to.deep.equal(
			rowOf(sent)
		);
	});

	it('marks the row of an invoice that asset HTLCs paid, and no other', () => {
		const invoice = {
			bolt11: 'lnbcrt1invoice',
			paymentHash: '05'.repeat(32),
			amountMsat: 354_000n,
			createdAt: 1_700_000_000,
			expiry: 3600
		};
		const plain = methods.toInvoiceInfo.call(daemonOf([]), invoice, true);
		expect(plain).to.deep.equal({
			bolt11: 'lnbcrt1invoice',
			paymentHash: '05'.repeat(32),
			amountSats: 354,
			expiry: 3600,
			createdAt: 1_700_000_000,
			status: 'PAID'
		});
		const marked = methods.toInvoiceInfo.call(
			daemonOf([]),
			{ ...invoice, auxiliary: true },
			true
		);
		expect(marked).to.deep.equal({ ...plain, auxiliary: true });
	});

	it('relays the mark of a settled invoice, and nothing for an ordinary one', () => {
		const data = {
			paymentHash: Buffer.alloc(32, 5),
			bolt11: 'lnbcrt1invoice',
			amountMsat: 354_000n
		};
		expect(methods.invoiceSettledInfo.call(daemonOf([]), data)).to.deep.equal({
			paymentHash: '05'.repeat(32),
			bolt11: 'lnbcrt1invoice',
			amountSats: 354
		});
		expect(
			methods.invoiceSettledInfo.call(daemonOf([]), {
				...data,
				auxiliary: true
			})
		).to.deep.equal({
			paymentHash: '05'.repeat(32),
			bolt11: 'lnbcrt1invoice',
			amountSats: 354,
			auxiliary: true
		});
	});

	it('marks the events of an asset channel the node holds, and adds no key to those of any other', () => {
		const daemon = daemonOf([]);
		expect(methods.assetChannelMark.call(daemon, assetChannel)).to.deep.equal({
			auxiliary: true
		});
		expect(
			methods.assetChannelMark.call(daemon, Buffer.alloc(32, 8))
		).to.deep.equal({});
		// A node that cannot answer marks nothing.
		expect(
			methods.assetChannelMark.call(
				{
					node: {
						getAuxiliaryChannelInfo: (): never => {
							throw new Error('the node is stopping');
						}
					}
				},
				assetChannel
			)
		).to.deep.equal({});
	});

	it('leaves a marked payment out of every figure of getStats, and counts the others as it did', () => {
		const ordinary = methods.getStats.call(daemonOf([sent, received]));
		const beside = methods.getStats.call(
			daemonOf([sent, assetSent, received, assetReceived])
		);
		expect(ordinary.totalPaymentsSent).to.equal(1);
		expect(ordinary.totalPaymentsReceived).to.equal(1);
		expect(ordinary.totalSatsSent).to.equal(20_021);
		expect(ordinary.totalSatsReceived).to.equal(20_000);
		expect(ordinary.totalFeesPaid).to.equal(21);
		const figures = (
			stats: Record<string, unknown>
		): Record<string, unknown> => {
			const { uptimeSeconds: _uptime, ...rest } = stats;
			return rest;
		};
		expect(figures(beside)).to.deep.equal(figures(ordinary));
		// Asset payments alone: nothing sent, received or paid in fees.
		const alone = methods.getStats.call(daemonOf([assetSent, assetReceived]));
		expect(alone.totalPaymentsSent).to.equal(0);
		expect(alone.totalPaymentsReceived).to.equal(0);
		expect(alone.totalSatsSent).to.equal(0);
		expect(alone.totalSatsReceived).to.equal(0);
		expect(alone.totalFeesPaid).to.equal(0);
		expect(alone).to.not.have.property('avgFeePct');
	});
});
