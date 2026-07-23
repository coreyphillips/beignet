/**
 * BOLT 1: BigSize test vectors (Appendix A).
 *
 * Decoding: every valid vector must decode to the exact value consuming the
 * exact byte count; every error vector must throw. The upstream `exp_error`
 * strings are Go library messages, so errors are classified (non-canonical vs
 * truncated) rather than string-matched verbatim.
 * Encoding: every value must encode to the exact spec bytes.
 */

import { expect } from 'chai';
import {
	encodeBigSize,
	decodeBigSize
} from '../../../src/lightning/message/codec';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IBigSizeCase {
	name: string;
	value: string;
	bytes: string;
	exp_error?: string;
}

interface IBigSizeVectors {
	decode: IBigSizeCase[];
	encode: IBigSizeCase[];
}

const v = loadVectors<IBigSizeVectors>('bolt01/bigsize.json');

describe('BOLT 1: BigSize conformance', function () {
	describe('decoding tests', function () {
		for (const c of v.decode) {
			it(`${c.name}`, function () {
				const bytes = hexToBuffer(c.bytes);
				if (c.exp_error) {
					// Classify the failure: canonicality errors must complain
					// about the encoding, truncation errors about running out
					// of data (upstream's exact Go message is not required).
					const pattern = c.exp_error.includes('canonical')
						? /non-canonical/
						: /end of data/;
					expect(() => decodeBigSize(bytes)).to.throw(pattern);
					return;
				}
				const result = decodeBigSize(bytes);
				expect(result.value).to.equal(BigInt(c.value));
				expect(result.bytesRead).to.equal(bytes.length);
			});
		}
	});

	describe('encoding tests', function () {
		for (const c of v.encode) {
			it(`${c.name}`, function () {
				expect(bufferToHex(encodeBigSize(BigInt(c.value)))).to.equal(c.bytes);
			});
		}
	});
});
