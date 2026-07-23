/**
 * BOLT 12: String Decoding for Offers, Invoice Requests, and Invoices.
 *
 * BOLT 12 strings use the bech32 character set with NO checksum (and may be
 * split with `+`); see bech32-nochecksum.ts.
 */

import { IOffer, IInvoiceRequest, IBolt12Invoice } from './types';
import {
	decodeOfferTlv,
	decodeInvoiceRequestTlv,
	decodeInvoiceTlv
} from './tlv';
import { computeOfferId } from './merkle';
import { decodeNoChecksum } from './bech32-nochecksum';

/**
 * Decode a BOLT 12 offer string ("lno" prefix) into an IOffer.
 */
export function decodeOffer(str: string): IOffer {
	const decoded = decodeNoChecksum(str);
	if (decoded.hrp !== 'lno') {
		throw new Error(`Expected 'lno' prefix, got '${decoded.hrp}'`);
	}
	const { offer, records } = decodeOfferTlv(decoded.data);

	// Compute offerId from the TLV records (merkle root)
	const offerId = computeOfferId(records);

	return { ...offer, offerId };
}

/**
 * Decode a bech32m invoice request string ("lnr" prefix) into an IInvoiceRequest.
 */
export function decodeInvoiceRequest(str: string): IInvoiceRequest {
	const decoded = decodeNoChecksum(str);
	if (decoded.hrp !== 'lnr') {
		throw new Error(`Expected 'lnr' prefix, got '${decoded.hrp}'`);
	}
	const { request, records } = decodeInvoiceRequestTlv(decoded.data);

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
	const decoded = decodeNoChecksum(str);
	if (decoded.hrp !== 'lni') {
		throw new Error(`Expected 'lni' prefix, got '${decoded.hrp}'`);
	}
	const { invoice } = decodeInvoiceTlv(decoded.data);
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
