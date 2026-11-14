/**
 * The BOLT 11 reader rules a payer applies to a decoded invoice on top of
 * decode(). They live here rather than in decode() because they are about
 * paying: which features this payer implements, and that a payment needs a
 * secret. decode() still parses a secretless invoice so it can be shown.
 */

import { Feature } from '../features/flags';
import type { IInvoice } from '../invoice/types';
import { LightningErrorCode, LightningPaymentError } from './types';

/**
 * Invoice feature bits this payer implements (BOLT 11 `9` field). An unknown
 * even (compulsory) bit outside this set MUST fail the payment. Listed by the
 * even bit; the odd variant is unknown-odd and always safe to ignore.
 */
export const PAYER_UNDERSTOOD_INVOICE_FEATURES: ReadonlySet<number> = new Set([
	Feature.TLV_ONION,
	Feature.PAYMENT_SECRET,
	Feature.BASIC_MPP,
	Feature.ROUTE_BLINDING,
	Feature.PAYMENT_METADATA
]);

/**
 * Throw INVALID_INVOICE when this payer must not pay a decoded invoice: it
 * requires an unknown even feature bit, or it has no payment secret (without
 * one any forwarding node can probe or steal an amount-adjusted payment).
 */
export function assertPayableInvoice(
	invoice: IInvoice
): asserts invoice is IInvoice & { paymentSecret: Buffer } {
	for (const bit of invoice.featureBits?.listSetBits() ?? []) {
		if (bit % 2 === 0 && !PAYER_UNDERSTOOD_INVOICE_FEATURES.has(bit)) {
			throw new LightningPaymentError(
				LightningErrorCode.INVALID_INVOICE,
				`Invoice requires unknown feature bit ${bit}`
			);
		}
	}
	if (!invoice.paymentSecret) {
		throw new LightningPaymentError(
			LightningErrorCode.INVALID_INVOICE,
			'Invoice has no payment secret (s field); refusing to pay'
		);
	}
}
