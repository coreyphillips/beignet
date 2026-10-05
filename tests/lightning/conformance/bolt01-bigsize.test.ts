/**
 * BOLT 1: BigSize test vectors (Appendix A).
 *
 * Decoding: every valid vector must decode to the exact value consuming the
 * exact byte count; every error vector must throw. The upstream `exp_error`
 * strings are Go library messages, so errors are classified (non-canonical vs
 * truncated) rather than string-matched verbatim.
 * Encoding: every value must encode to the exact spec bytes.
 * readBigSizeParts (the BigInt-free decoder of the Rapid Gossip Sync import)
 * runs the same decoding vectors and must agree with decodeBigSize exactly:
 * the same value, byte count, and error message.
 */

import { expect } from 'chai';
import {
	encodeBigSize,
	decodeBigSize,
	readBigSizeParts
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

	describe('decoding tests via readBigSizeParts', function () {
		const decodeParts = (
			bytes: Buffer,
			offset: number
		): { value: bigint; bytesRead: number } => {
			const out = { hi: -1, lo: -1 };
			const bytesRead = readBigSizeParts(bytes, offset, out);
			expect(out.hi).to.be.within(0, 0xffffffff);
			expect(out.lo).to.be.within(0, 0xffffffff);
			return { value: (BigInt(out.hi) << 32n) + BigInt(out.lo), bytesRead };
		};
		const messageOf = (fn: () => unknown): string => {
			try {
				fn();
			} catch (err) {
				return (err as Error).message;
			}
			throw new Error('expected a throw');
		};

		for (const c of v.decode) {
			it(`${c.name}`, function () {
				// At the start of a buffer and behind unrelated bytes alike.
				for (const prefix of [Buffer.alloc(0), Buffer.from([0xff, 0xfd, 7])]) {
					const bytes = Buffer.concat([prefix, hexToBuffer(c.bytes)]);
					const at = prefix.length;
					if (c.exp_error) {
						const pattern = c.exp_error.includes('canonical')
							? /non-canonical/
							: /end of data/;
						const message = messageOf(() =>
							readBigSizeParts(bytes, at, { hi: 0, lo: 0 })
						);
						expect(message).to.match(pattern);
						expect(message).to.equal(messageOf(() => decodeBigSize(bytes, at)));
						continue;
					}
					expect(decodeParts(bytes, at)).to.deep.equal(
						decodeBigSize(bytes, at)
					);
					expect(decodeParts(bytes, at).value).to.equal(BigInt(c.value));
				}
			});
		}

		it('round-trips every width boundary', function () {
			const values = [
				0n,
				0xfcn,
				0xfdn,
				0xffffn,
				0x10000n,
				0xffffffffn,
				0x100000000n,
				0x1_0000_0001n,
				0xffff_ffff_0000_0000n,
				0xffff_ffff_ffff_ffffn
			];
			for (const value of values) {
				const bytes = encodeBigSize(value);
				expect(decodeParts(bytes, 0)).to.deep.equal({
					value,
					bytesRead: bytes.length
				});
			}
		});
	});
});
