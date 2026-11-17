/**
 * Issue #2093: two places that end an incoming payment leave one alone
 * that a capsule restore marked unresolved.
 *
 * A payment that was in flight on an asset channel a restore left out
 * stays PENDING, because the peer still holds the channel and may have
 * settled it. The sweep of expired issued invoices and the cancel of a
 * hold invoice both end the payment of an invoice that was not paid, and
 * neither ends a marked one. Each case shows the same record without the
 * mark being ended, so the mark is what kept it.
 */

import { expect } from 'chai';
import { createHash } from 'crypto';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/payment-types';
import { createNode } from './helpers/loopback-nodes';

interface IInner {
	invoices: Map<string, Record<string, unknown>>;
	payments: Map<string, IPaymentInfo>;
	sweepExpiredIssuedInvoices: () => void;
}

describe('an unresolved payment is not ended by the invoice it was for (issue #2093 step 14)', () => {
	const nodes: LightningNode[] = [];
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
	});

	const sha = (data: Buffer | string): Buffer =>
		createHash('sha256').update(data).digest();
	const MARK = {
		code: 'CHANNEL_OMITTED_AT_RESTORE' as const,
		channelIds: ['ab'.repeat(32)]
	};

	const make = (tag: string): { node: LightningNode; inner: IInner } => {
		const node = createNode(tag, 1);
		node.on('node:error', () => undefined);
		nodes.push(node);
		return { node, inner: node as unknown as IInner };
	};

	it('keeps the record and the invoice of an expired issued invoice whose payment is unresolved, and sweeps the same one without the mark', () => {
		const { inner } = make('unresolved-sweep');
		const hash = sha('an issued invoice');
		const hex = hash.toString('hex');
		const longAgo = Math.floor(Date.now() / 1000) - 100_000;
		inner.invoices.set(hex, {
			paymentHash: hash,
			bolt11: '',
			bolt12: true,
			amountMsat: 1_000_000n,
			description: 'issued',
			expiry: 60,
			createdAt: longAgo
		});
		inner.payments.set(hex, {
			paymentHash: hash,
			amountMsat: 1_000_000n,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.INCOMING,
			createdAt: longAgo * 1000,
			unresolved: MARK
		});
		inner.sweepExpiredIssuedInvoices();
		expect(inner.invoices.has(hex)).to.equal(true);
		expect(inner.payments.get(hex)?.status).to.equal(PaymentStatus.PENDING);
		expect(inner.payments.get(hex)?.unresolved).to.deep.equal(MARK);

		delete inner.payments.get(hex)!.unresolved;
		inner.sweepExpiredIssuedInvoices();
		expect(inner.invoices.has(hex)).to.equal(false);
		expect(inner.payments.has(hex)).to.equal(false);
	});

	it('leaves an unresolved payment PENDING when its hold invoice is cancelled, and fails the payment of one without the mark', () => {
		const { node, inner } = make('unresolved-hold-cancel');
		const record = (label: string, marked: boolean): Buffer => {
			const hash = sha(sha(label));
			node.createInvoice({
				amountMsat: 1_000_000n,
				description: label,
				hold: true,
				paymentHash: hash
			});
			inner.payments.set(hash.toString('hex'), {
				paymentHash: hash,
				amountMsat: 1_000_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.INCOMING,
				createdAt: Date.now(),
				...(marked ? { unresolved: MARK } : {})
			});
			return hash;
		};
		const marked = record('held on a channel left out', true);
		const plain = record('held and cancelled', false);
		expect(node.cancelHoldInvoice(marked)).to.deep.equal({ htlcsFailed: 0 });
		expect(node.cancelHoldInvoice(plain)).to.deep.equal({ htlcsFailed: 0 });
		expect(node.getPayment(marked)!.status).to.equal(PaymentStatus.PENDING);
		expect(node.getPayment(marked)!.unresolved).to.deep.equal(MARK);
		expect(node.getPayment(plain)!.status).to.equal(PaymentStatus.FAILED);
	});
});
