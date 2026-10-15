/**
 * BIP341 tapleaf hash across the compact-size boundary. The expected hashes
 * were computed independently (Python hashlib, compact_size written by hand)
 * over a script of `length` OP_1 bytes.
 */

import { expect } from 'chai';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';

const VECTORS: { length: number; hash: string }[] = [
	// Last length with a one-byte compact size.
	{
		length: 252,
		hash: 'efd60aaa9b2b3e736636417d829ec0853d9f12d474f57b0ee01d93d74fe13ff8'
	},
	// First length with the 0xfd + u16 compact size.
	{
		length: 253,
		hash: '7b4b1828075de9371d1864408562b48dff100ac657e97fbc74c168a6333064e1'
	},
	// Longer than one byte can hold at all.
	{
		length: 300,
		hash: '14dbbf1ba8fbe4da51312d7f13eaa4178026942da2ce20cb4c9c8f0c1f538dfd'
	}
];

describe('tapleafHash', function () {
	for (const { length, hash } of VECTORS) {
		it(`hashes a ${length}-byte tapscript leaf per BIP341`, function () {
			const script = Buffer.alloc(length, 0x51);
			expect(tapleafHash(script).toString('hex')).to.equal(hash);
		});
	}
});
