/**
 * BOLT 12: Bech32m Encoding for Offers, Invoice Requests, and Invoices.
 *
 * BOLT 12 uses bech32m (BIP 350) encoding with specific HRP prefixes:
 * - "lno" for offers
 * - "lnr" for invoice requests
 * - "lni" for invoices
 *
 * The data portion is the TLV stream converted to 5-bit words.
 */

import { bech32m } from 'bech32';
import { IOffer, IInvoiceRequest, IBolt12Invoice } from './types';
import {
	encodeOfferTlv,
	encodeInvoiceRequestTlv,
	encodeInvoiceTlv
} from './tlv';

/** Maximum bech32m encoding length (generous limit for offers) */
const BECH32M_MAX_LIMIT = 65535;

/**
 * Encode an IOffer as a bech32m string with "lno" prefix.
 */
export function encodeOffer(offer: IOffer): string {
	const tlvData = encodeOfferTlv(offer);
	const words = bech32m.toWords(tlvData);
	return bech32m.encode('lno', words, BECH32M_MAX_LIMIT);
}

/**
 * Encode an IInvoiceRequest as a bech32m string with "lnr" prefix.
 */
export function encodeInvoiceRequest(
	request: IInvoiceRequest,
	offerTlvData?: Buffer
): string {
	const tlvData = encodeInvoiceRequestTlv(request, offerTlvData);
	const words = bech32m.toWords(tlvData);
	return bech32m.encode('lnr', words, BECH32M_MAX_LIMIT);
}

/**
 * Encode an IBolt12Invoice as a bech32m string with "lni" prefix.
 */
export function encodeBolt12Invoice(invoice: IBolt12Invoice): string {
	const tlvData = encodeInvoiceTlv(invoice);
	const words = bech32m.toWords(tlvData);
	return bech32m.encode('lni', words, BECH32M_MAX_LIMIT);
}
