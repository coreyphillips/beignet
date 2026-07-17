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
import { ITlvRecord, encodeTlvStream } from '../message/tlv';
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
 *
 * When the invoice carries its full wire `records` (set on decode and on
 * issuance) they are re-encoded verbatim — the BOLT 12 mirror of the
 * invoice_request and any unknown TLVs live only there, and the signature
 * commits to them. `mirrorRecords` overrides for callers assembling a fresh
 * invoice against known invreq records.
 */
export function encodeBolt12Invoice(
	invoice: IBolt12Invoice,
	mirrorRecords?: ITlvRecord[]
): string {
	if (!mirrorRecords && invoice.records) {
		return encodeNoChecksum('lni', encodeTlvStream(invoice.records));
	}
	return encodeNoChecksum('lni', encodeInvoiceTlv(invoice, mirrorRecords));
}
