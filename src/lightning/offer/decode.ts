/**
 * BOLT 12: Bech32m Decoding for Offers, Invoice Requests, and Invoices.
 *
 * Decodes bech32m-encoded strings back into their BOLT 12 type representations.
 */

import { bech32m } from 'bech32';
import { IOffer, IInvoiceRequest, IBolt12Invoice } from './types';
import {
	decodeOfferTlv,
	decodeInvoiceRequestTlv,
	decodeInvoiceTlv
} from './tlv';
import { computeOfferId } from './merkle';

/** Maximum bech32m encoding length */
const BECH32M_MAX_LIMIT = 65535;

/**
 * Decode a bech32m offer string ("lno" prefix) into an IOffer.
 */
export function decodeOffer(str: string): IOffer {
	const decoded = bech32m.decode(str, BECH32M_MAX_LIMIT);
	if (decoded.prefix !== 'lno') {
		throw new Error(`Expected 'lno' prefix, got '${decoded.prefix}'`);
	}
	const data = Buffer.from(bech32m.fromWords(decoded.words));
	const { offer, records } = decodeOfferTlv(data);

	// Compute offerId from the TLV records (merkle root)
	const offerId = computeOfferId(records);

	return { ...offer, offerId };
}

/**
 * Decode a bech32m invoice request string ("lnr" prefix) into an IInvoiceRequest.
 */
export function decodeInvoiceRequest(str: string): IInvoiceRequest {
	const decoded = bech32m.decode(str, BECH32M_MAX_LIMIT);
	if (decoded.prefix !== 'lnr') {
		throw new Error(`Expected 'lnr' prefix, got '${decoded.prefix}'`);
	}
	const data = Buffer.from(bech32m.fromWords(decoded.words));
	const { request, records } = decodeInvoiceRequestTlv(data);

	// Compute offerId from the offer TLV records (types <= 22)
	const offerRecords = records.filter((r) => Number(r.type) <= 22);
	if (offerRecords.length > 0) {
		request.offerId = computeOfferId(offerRecords);
	}

	return request;
}

/**
 * Decode a bech32m invoice string ("lni" prefix) into an IBolt12Invoice.
 */
export function decodeBolt12Invoice(str: string): IBolt12Invoice {
	const decoded = bech32m.decode(str, BECH32M_MAX_LIMIT);
	if (decoded.prefix !== 'lni') {
		throw new Error(`Expected 'lni' prefix, got '${decoded.prefix}'`);
	}
	const data = Buffer.from(bech32m.fromWords(decoded.words));
	const { invoice } = decodeInvoiceTlv(data);
	return invoice;
}

/**
 * Detect the type of a BOLT 12 encoded string based on its prefix.
 * Returns 'offer' | 'invoice_request' | 'invoice' | null.
 */
export function detectBolt12Type(
	str: string
): 'offer' | 'invoice_request' | 'invoice' | null {
	const lower = str.toLowerCase();
	if (lower.startsWith('lno1') || lower.startsWith('lno:')) return 'offer';
	if (lower.startsWith('lnr1') || lower.startsWith('lnr:'))
		return 'invoice_request';
	if (lower.startsWith('lni1') || lower.startsWith('lni:')) return 'invoice';
	return null;
}
