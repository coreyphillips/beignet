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

import { IOffer, IInvoiceRequest, IBolt12Invoice } from './types';
import {
	encodeOfferTlv,
	encodeInvoiceRequestTlv,
	encodeInvoiceTlv
} from './tlv';
import { encodeNoChecksum } from './bech32-nochecksum';

/**
 * Encode an IOffer as a checksum-less bech32 string with "lno" prefix
 * (BOLT 12 strings carry NO checksum; see bech32-nochecksum.ts).
 */
export function encodeOffer(offer: IOffer): string {
	return encodeNoChecksum('lno', encodeOfferTlv(offer));
}

/**
 * Encode an IInvoiceRequest as a checksum-less bech32 string ("lnr" prefix).
 */
export function encodeInvoiceRequest(
	request: IInvoiceRequest,
	offerTlvData?: Buffer
): string {
	return encodeNoChecksum(
		'lnr',
		encodeInvoiceRequestTlv(request, offerTlvData)
	);
}

/**
 * Encode an IBolt12Invoice as a checksum-less bech32 string ("lni" prefix).
 */
export function encodeBolt12Invoice(invoice: IBolt12Invoice): string {
	return encodeNoChecksum('lni', encodeInvoiceTlv(invoice));
}
