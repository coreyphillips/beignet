/**
 * BOLT 12: string format test vectors (bolt12/format-string-test.json).
 *
 * The checksum-less bech32 format: uppercase or lowercase (not mixed), and
 * `+` joins that must sit between bech32 characters (whitespace allowed
 * only after the `+`). Every case decodes the same underlying offer.
 */

import { expect } from 'chai';
import { decodeOffer } from '../../../src/lightning/offer/decode';
import { loadVectors } from './helpers';

interface IFormatCase {
	comment: string;
	valid: boolean;
	string: string;
}

const v = loadVectors<{ cases: IFormatCase[] }>('bolt12/format-string.json');

describe('BOLT 12: string format conformance', function () {
	for (const c of v.cases) {
		it(`${c.valid ? 'accepts' : 'rejects'}: ${c.comment}`, function () {
			if (c.valid) {
				expect(() => decodeOffer(c.string)).to.not.throw();
			} else {
				expect(() => decodeOffer(c.string)).to.throw();
			}
		});
	}
});
