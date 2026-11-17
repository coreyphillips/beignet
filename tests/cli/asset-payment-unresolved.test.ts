/**
 * The daemon shows the mark of a payment it cannot follow (issue #2093).
 *
 * A capsule restore that leaves asset channels out marks every PENDING
 * payment record that had an HTLC on one as `unresolved`. The daemon
 * carries the mark on the payment's row and on the row of an unpaid
 * invoice, and refuses to cancel such a payment, since the engine does not
 * fail it and an `ok` would say it had. A record with no mark answers the
 * row it did.
 *
 * The node's records are faked here, at the one place the daemon reads
 * them, so each answer below is the daemon's own doing.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import type { IPaymentInfo } from '../../src/lightning/node/payment-types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/payment-types';
import type { IInvoiceInfo } from '../../src/lightning/storage/types';

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => Record<string, unknown>
>;

const CHANNEL = '7a'.repeat(32);
const MARK = {
	code: 'CHANNEL_OMITTED_AT_RESTORE' as const,
	channelIds: [CHANNEL]
};

const payment = (fill: number, extra: Partial<IPaymentInfo>): IPaymentInfo => ({
	paymentHash: Buffer.alloc(32, fill),
	amountMsat: 354_000n,
	status: PaymentStatus.PENDING,
	direction: PaymentDirection.OUTGOING,
	createdAt: 1_700_000_000_000,
	...extra
});

/** An asset payment out whose channel a restore left out. */
const out = payment(1, {
	auxiliary: true,
	auxiliaryValueMsat: 3_000_000n,
	unresolved: MARK
});
/** A payment in, held when the channel was left out. */
const incoming = payment(2, {
	direction: PaymentDirection.INCOMING,
	amountMsat: 500_000n,
	unresolved: MARK
});
/** An ordinary payment out, still PENDING. */
const plain = payment(3, { amountMsat: 20_000_000n });

const invoiceOf = (record: IPaymentInfo): IInvoiceInfo =>
	({
		paymentHash: record.paymentHash.toString('hex'),
		bolt11: 'lnbcrt1',
		amountMsat: record.amountMsat,
		description: 'held',
		expiry: 3600,
		createdAt: Math.floor(Date.now() / 1000),
		hold: true
	}) as IInvoiceInfo;

function daemonOf(payments: IPaymentInfo[]): {
	daemon: Record<string, unknown>;
	failed: string[];
} {
	const failed: string[] = [];
	const find = (hash: Buffer): IPaymentInfo | undefined =>
		payments.find((record) => record.paymentHash.equals(hash));
	const daemon: Record<string, unknown> = {
		node: {
			listPayments: (): IPaymentInfo[] => payments,
			getPayment: find,
			failPayment: (hash: Buffer): void => {
				failed.push(hash.toString('hex'));
			},
			getInvoice: (hashHex: string): IInvoiceInfo | null => {
				const record = find(Buffer.from(hashHex, 'hex'));
				return record ? invoiceOf(record) : null;
			},
			listInvoices: (): IInvoiceInfo[] =>
				payments
					.filter((record) => record.direction === PaymentDirection.INCOMING)
					.map(invoiceOf)
		},
		storage: {
			loadPayment: (): null => null,
			loadAllPayments: (): [] => []
		},
		sqlite: (): undefined => undefined,
		toInvoiceInfo: methods.toInvoiceInfo
	};
	return { daemon, failed };
}

const rowOf = (record: IPaymentInfo): Record<string, unknown> =>
	methods.toPaymentInfo.call(daemonOf([]).daemon, record);

describe('The daemon shows a payment that was in flight on a channel a restore left out (#2093)', () => {
	it('carries the mark on the row of a PENDING payment, sent or received, and keeps it PENDING', () => {
		for (const record of [out, incoming]) {
			const row = rowOf(record);
			expect(row.status).to.equal('PENDING');
			expect(row.unresolved).to.deep.equal(MARK);
			expect(row).to.not.have.property('preimage');
			expect(row).to.not.have.property('completedAt');
			expect(row).to.not.have.property('failureDescription');
		}
		// The asset figures of the row are what they were.
		expect(rowOf(out).auxiliary).to.equal(true);
		expect(rowOf(out).auxiliaryValueSats).to.equal(3000);
	});

	it('adds no key to the row of any other payment, and none to a marked record that has got an outcome', () => {
		expect(rowOf(plain)).to.deep.equal({
			paymentHash: '03'.repeat(32),
			amountSats: 20_000,
			status: 'PENDING',
			direction: 'OUTGOING',
			createdAt: 1_700_000_000_000
		});
		for (const status of [PaymentStatus.COMPLETED, PaymentStatus.FAILED]) {
			expect(rowOf({ ...incoming, status })).to.not.have.property('unresolved');
		}
	});

	it('carries the mark on the row of the invoice while it is not paid, alone and in the list', () => {
		const { daemon } = daemonOf([
			incoming,
			payment(4, {
				direction: PaymentDirection.INCOMING
			})
		]);
		const marked = methods.getInvoice.call(daemon, '02'.repeat(32));
		expect(marked.unresolved).to.deep.equal(MARK);
		expect(marked.status).to.equal('PENDING');
		const unmarked = methods.getInvoice.call(daemon, '04'.repeat(32));
		expect(unmarked).to.not.have.property('unresolved');
		const listed = methods.listInvoices.call(daemon) as unknown as Array<
			Record<string, unknown>
		>;
		expect(listed.map((row) => row.unresolved)).to.deep.equal([
			MARK,
			undefined
		]);
		expect(listed[1]).to.not.have.property('unresolved');

		// Paid by an HTLC on a channel the wallet holds, it is PAID and no
		// longer unresolved.
		const paid = daemonOf([
			{ ...incoming, status: PaymentStatus.COMPLETED, unresolved: undefined }
		]).daemon;
		const row = methods.getInvoice.call(paid, '02'.repeat(32));
		expect(row.status).to.equal('PAID');
		expect(row).to.not.have.property('unresolved');
	});

	it('refuses to cancel it with PAYMENT_UNRESOLVED and asks the engine nothing, and cancels any other as it did', () => {
		const { daemon, failed } = daemonOf([out, plain]);
		let refusal: unknown;
		try {
			methods.cancelPayment.call(daemon, '01'.repeat(32));
		} catch (err) {
			refusal = err;
		}
		expect(refusal).to.be.instanceOf(BeignetError);
		expect((refusal as BeignetError).code).to.equal('PAYMENT_UNRESOLVED');
		expect((refusal as BeignetError).paymentHash).to.equal('01'.repeat(32));
		expect((refusal as BeignetError).message).to.include(CHANNEL);
		expect(failed).to.deep.equal([]);

		expect(methods.cancelPayment.call(daemon, '03'.repeat(32))).to.deep.equal({
			ok: true
		});
		expect(failed).to.deep.equal(['03'.repeat(32)]);
	});
});
