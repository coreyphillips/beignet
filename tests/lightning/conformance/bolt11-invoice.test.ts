/**
 * BOLT 11: Invoice encoding/decoding test vectors (spec "Examples").
 *
 * Decodes each spec invoice and asserts the documented fields, then performs a
 * semantic round-trip (decode -> encode -> decode) for invoices whose fields
 * beignet can fully reconstruct. Note: beignet emits tagged fields in a
 * different order than the spec examples, so round-trip is asserted at the
 * decoded-field level, not byte-for-byte on the string. Invalid vectors assert
 * the decoder rejects malformed input.
 */

import { expect } from 'chai';
import { decode } from '../../../src/lightning/invoice/decode';
import { encode } from '../../../src/lightning/invoice/encode';
import { IInvoice, IInvoiceCreationOptions } from '../../../src/lightning/invoice/types';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IExpect {
	network: string;
	amountMsat?: number | null;
	timestamp?: number;
	paymentHash?: string;
	paymentSecret?: string;
	description?: string;
	expiry?: number;
	recoveredPubkey?: string;
	hasDescriptionHash?: boolean;
	hasFallbackAddress?: boolean;
	hasRoutingHints?: boolean;
	featureBitsSet?: number[];
}

interface IValidCase {
	name: string;
	invoice: string;
	expect: IExpect;
	roundTrip?: boolean;
}

interface IInvoiceVectors {
	priv_key: string;
	valid: IValidCase[];
	invalid: { name: string; invoice: string }[];
	secretEnforcedAtReceiveLayer: { name: string; invoice: string }[];
}

const v = loadVectors<IInvoiceVectors>('bolt11/invoices.json');

describe('BOLT 11: invoice decode conformance', function () {
	for (const tc of v.valid) {
		it(tc.name, function () {
			const inv = decode(tc.invoice);
			const e = tc.expect;

			expect(inv.network).to.equal(e.network);

			if (e.amountMsat === null) {
				expect(inv.amountMsat).to.equal(undefined);
			} else if (e.amountMsat !== undefined) {
				expect(inv.amountMsat).to.equal(BigInt(e.amountMsat));
			}
			if (e.timestamp !== undefined) {
				expect(inv.timestamp).to.equal(e.timestamp);
			}
			if (e.paymentHash !== undefined) {
				expect(bufferToHex(inv.paymentHash)).to.equal(e.paymentHash);
			}
			if (e.paymentSecret !== undefined) {
				expect(inv.paymentSecret && bufferToHex(inv.paymentSecret)).to.equal(
					e.paymentSecret
				);
			}
			if (e.description !== undefined) {
				expect(inv.description).to.equal(e.description);
			}
			if (e.expiry !== undefined) {
				expect(inv.expiry).to.equal(e.expiry);
			}
			if (e.recoveredPubkey !== undefined) {
				expect(inv.recoveredPubkey && bufferToHex(inv.recoveredPubkey)).to.equal(
					e.recoveredPubkey
				);
			}
			if (e.hasDescriptionHash) {
				expect(inv.descriptionHash, 'descriptionHash present').to.not.equal(
					undefined
				);
				expect(inv.descriptionHash!.length).to.equal(32);
			}
			if (e.hasFallbackAddress) {
				expect(inv.fallbackAddress, 'fallbackAddress present').to.not.equal(
					undefined
				);
			}
			if (e.hasRoutingHints) {
				expect(inv.routingHints && inv.routingHints.length).to.be.greaterThan(0);
			}
			if (e.featureBitsSet) {
				expect(inv.featureBits, 'featureBits present').to.not.equal(undefined);
				const setBits = inv.featureBits!.listSetBits();
				for (const bit of e.featureBitsSet) {
					expect(setBits, `feature bit ${bit} set`).to.include(bit);
				}
			}
		});
	}
});

describe('BOLT 11: invoice semantic round-trip', function () {
	const priv = hexToBuffer(v.priv_key);

	for (const tc of v.valid.filter((c) => c.roundTrip)) {
		it(tc.name, function () {
			const original = decode(tc.invoice);
			const reEncoded = encode(invoiceToOptions(original, priv));
			const reDecoded = decode(reEncoded);

			// Scalar fields must survive the round-trip.
			expect(reDecoded.network).to.equal(original.network);
			expect(reDecoded.amountMsat).to.equal(original.amountMsat);
			expect(reDecoded.timestamp).to.equal(original.timestamp);
			expect(bufferToHex(reDecoded.paymentHash)).to.equal(
				bufferToHex(original.paymentHash)
			);
			expect(reDecoded.description).to.equal(original.description);
			expect(reDecoded.expiry).to.equal(original.expiry);
			expect(
				reDecoded.paymentSecret && bufferToHex(reDecoded.paymentSecret)
			).to.equal(original.paymentSecret && bufferToHex(original.paymentSecret));
			// Re-signed invoice must recover to the same payee key.
			expect(
				reDecoded.recoveredPubkey && bufferToHex(reDecoded.recoveredPubkey)
			).to.equal(
				original.recoveredPubkey && bufferToHex(original.recoveredPubkey)
			);
		});
	}
});

describe('BOLT 11: invalid invoices are rejected', function () {
	for (const tc of v.invalid) {
		it(tc.name, function () {
			expect(() => decode(tc.invoice)).to.throw();
		});
	}
});

/**
 * payment_secret is compulsory for an invoice that carries one, but that is a
 * rule about NODE BEHAVIOR, not bech32 parsing. beignet keeps decode() lenient
 * (a parser) and enforces the secret at the final-hop receive path instead
 * (lightning-node.ts: an HTLC is failed when the invoice's expectedSecret is
 * set and the onion omits/mismatches it). So decode() is expected to PARSE the
 * secretless invoice without throwing — this test pins that intentional
 * layering so it can't silently regress into a hard decode-time rejection.
 */
describe('BOLT 11: payment_secret enforced at receive layer, not in decode', function () {
	for (const tc of v.secretEnforcedAtReceiveLayer) {
		it(tc.name, function () {
			expect(() => decode(tc.invoice)).to.not.throw();
		});
	}
});

/** Map a decoded invoice back into creation options for re-encoding. */
function invoiceToOptions(
	inv: IInvoice,
	privateKey: Buffer
): IInvoiceCreationOptions {
	return {
		network: inv.network,
		amountMsat: inv.amountMsat,
		timestamp: inv.timestamp,
		paymentHash: inv.paymentHash,
		paymentSecret: inv.paymentSecret,
		description: inv.description,
		descriptionHash: inv.descriptionHash,
		expiry: inv.expiry,
		minFinalCltvExpiry: inv.minFinalCltvExpiry,
		fallbackAddress: inv.fallbackAddress,
		routingHints: inv.routingHints,
		featureBits: inv.featureBits,
		metadata: inv.metadata,
		payeeNodeKey: inv.payeeNodeKey,
		privateKey
	};
}
