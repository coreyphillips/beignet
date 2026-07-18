/**
 * BOLT 12: offer decoding test vectors (bolt12/offers-test.json).
 *
 * Valid cases must decode AND their TLV records must match the vector's
 * field-by-field breakdown exactly (type, length, value). Invalid cases
 * cover the reader MUSTs: TLV structure and ranges, unknown even types,
 * strict UTF-8, valid points in issuer_id and blinded paths, description
 * required with an amount, currency requiring an amount, non-zero amount,
 * reachability (issuer_id or a path), whole 32-byte chains, non-empty
 * paths, unknown required feature bits, and bech32 padding limits.
 */

import { expect } from 'chai';
import { decodeOffer } from '../../../src/lightning/offer/decode';
import { decodeNoChecksum } from '../../../src/lightning/offer/bech32-nochecksum';
import { decodeTlvStream } from '../../../src/lightning/message/tlv';
import { loadVectors, bufferToHex } from './helpers';

interface IOfferCase {
	description: string;
	valid: boolean;
	bolt12: string;
	fields?: { type: number; length: number; hex: string }[];
}

const v = loadVectors<{ cases: IOfferCase[] }>('bolt12/offers.json');

describe('BOLT 12: offer decoding conformance', function () {
	for (const c of v.cases) {
		if (c.valid) {
			it(`accepts: ${c.description}`, function () {
				expect(() => decodeOffer(c.bolt12)).to.not.throw();

				// The raw TLV records must match the vector's breakdown.
				const { data } = decodeNoChecksum(c.bolt12);
				const { records } = decodeTlvStream(data);
				const fields = c.fields ?? [];
				expect(records.length).to.equal(fields.length);
				records.forEach((r, i) => {
					expect(Number(r.type), `field ${i} type`).to.equal(fields[i].type);
					expect(r.value.length, `field ${i} length`).to.equal(
						fields[i].length
					);
					expect(bufferToHex(r.value), `field ${i} value`).to.equal(
						fields[i].hex
					);
				});
			});
		} else {
			it(`rejects: ${c.description}`, function () {
				expect(() => decodeOffer(c.bolt12)).to.throw();
			});
		}
	}
});
