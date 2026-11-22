/**
 * Asset invoices (issue #2098, step 10): createInvoice's `assetInvoice`
 * field, and the readings of a BOLT 11 string these tests compare by. The
 * field is set on an options object cast once, here, and read back by its
 * error's name, code and option, so no test names a type for it.
 */

import { decode as decodeInvoice } from '../../../src/lightning/invoice/decode';
import type { IRoutingHintHop } from '../../../src/lightning/invoice/types';
import type { ICreateInvoiceOptions } from '../../../src/lightning/node/types';

/**
 * createInvoice's options with `assetInvoice` set to `field`, or to `{}`
 * when no field is given. An explicit `undefined` is kept as given, so a
 * case can pass the field left unset.
 */
export function assetInvoiceOptions(
	options: ICreateInvoiceOptions,
	...field: [unknown?]
): ICreateInvoiceOptions {
	return {
		...options,
		assetInvoice: field.length === 0 ? {} : field[0]
	} as unknown as ICreateInvoiceOptions;
}

/** The feature bits an invoice sets, lowest first. */
export function featureBitsOf(bolt11: string): number[] {
	return [...(decodeInvoice(bolt11).featureBits?.listSetBits() ?? [])].sort(
		(a, b) => a - b
	);
}

/** One hop of a routing hint, as text and numbers. */
export interface IHintHopView {
	pubkey: string;
	shortChannelId: string;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
}

export const hintView = (hint: IRoutingHintHop[]): IHintHopView[] =>
	hint.map((hop) => ({
		pubkey: hop.pubkey.toString('hex'),
		shortChannelId: hop.shortChannelId.toString('hex'),
		feeBaseMsat: hop.feeBaseMsat,
		feeProportionalMillionths: hop.feeProportionalMillionths,
		cltvExpiryDelta: hop.cltvExpiryDelta
	}));

/** The routing hints an invoice carries, in order; none as an empty list. */
export function hintsOf(bolt11: string): IHintHopView[][] {
	return (decodeInvoice(bolt11).routingHints ?? []).map(hintView);
}

/** What a refusal of createInvoice names. */
export interface IRefusal {
	name?: string;
	code?: string;
	option?: string;
	message?: string;
}

/**
 * What `call` threw, read by its name, code and option (and its message,
 * for an error with no code), or `{ thrown: false }` when it returned.
 */
export function refusalOf(call: () => unknown): IRefusal | { thrown: false } {
	try {
		call();
	} catch (error) {
		const { name, code, option, message } = error as IRefusal;
		return code === undefined ? { name, message } : { name, code, option };
	}
	return { thrown: false };
}

/** The refusal of an asset invoice, as refusalOf reads it. */
export const assetRefusal = (code: string, option: string): IRefusal => ({
	name: 'AuxiliaryInvoiceError',
	code,
	option
});
