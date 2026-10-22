/**
 * Issue #1691: txid byte order goes through txidToDisplayHex and
 * txidFromDisplayHex, pinned here against the genesis coinbase, and each
 * module converted to them keeps no hand-written flip. Fully offline.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as path from 'path';

import { txidFromDisplayHex, txidToDisplayHex } from '../src/utils/identifiers';

/** The coinbase of block 0. */
const GENESIS_COINBASE_HEX =
	'01000000010000000000000000000000000000000000000000000000000000000000000000' +
	'ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368' +
	'616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066' +
	'6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a671' +
	'30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c38' +
	'4df7ba0b8d578a4c702b6bf11d5fac00000000';
/** As bitcoind and every explorer print it. */
const GENESIS_TXID =
	'4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b';
/** As the transaction's hash and an outpoint spending it hold it. */
const GENESIS_HASH =
	'3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a';

describe('Issue #1691: txid byte order helpers', () => {
	it('names the genesis coinbase by its display txid', () => {
		const tx = bitcoin.Transaction.fromHex(GENESIS_COINBASE_HEX);
		expect(tx.getHash().toString('hex')).to.equal(GENESIS_HASH);
		expect(txidToDisplayHex(tx.getHash())).to.equal(GENESIS_TXID);
		expect(txidToDisplayHex(tx.getHash())).to.equal(tx.getId());
	});

	it('puts the hash bytes into an outpoint that spends it', () => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(txidFromDisplayHex(GENESIS_TXID), 0);
		// Version (4 bytes) and input count (1 byte), then the outpoint hash.
		expect(tx.toHex().slice(10, 74)).to.equal(GENESIS_HASH);
	});

	it('takes uppercase hex', () => {
		expect(
			txidFromDisplayHex(GENESIS_TXID.toUpperCase()).toString('hex')
		).to.equal(GENESIS_HASH);
	});

	it('round-trips', () => {
		expect(txidToDisplayHex(txidFromDisplayHex(GENESIS_TXID))).to.equal(
			GENESIS_TXID
		);
	});

	it("leaves the caller's buffer as it was", () => {
		const hash = Buffer.from(GENESIS_HASH, 'hex');
		txidToDisplayHex(hash);
		expect(hash.toString('hex')).to.equal(GENESIS_HASH);
	});

	it('takes a plain Uint8Array', () => {
		expect(
			txidToDisplayHex(new Uint8Array(Buffer.from(GENESIS_HASH, 'hex')))
		).to.equal(GENESIS_TXID);
	});

	for (const [label, txid] of [
		['62 characters', GENESIS_TXID.slice(2)],
		['a trailing character', GENESIS_TXID + 'a'],
		['a non-hex pair', GENESIS_TXID.slice(0, 62) + 'zz'],
		['an empty string', '']
	]) {
		it(`refuses a txid with ${label}`, () => {
			expect(() => txidFromDisplayHex(txid)).to.throw(
				RangeError,
				'A txid is 64 hex characters'
			);
		});
	}

	it('refuses a hash that is not 32 bytes', () => {
		expect(() => txidToDisplayHex(Buffer.alloc(31))).to.throw(
			RangeError,
			'A transaction hash is 32 bytes, got 31'
		);
		expect(() => txidToDisplayHex(Buffer.alloc(0))).to.throw(RangeError);
	});
});

/**
 * The source trees whose txid flips go through the helpers. A module joins
 * this list in the change that converts it.
 */
const CONVERTED = ['src/cli'];

const ROOT = path.join(__dirname, '..');

/** A Buffer reversed in place: the bytes of a txid flipped by hand. */
function handWrittenFlips(source: string): string[] {
	const flip =
		/(?:Buffer\.from\((?:[^()]|\([^()]*\))*\)|\.getHash\(\))\s*\.reverse\(\)/g;
	return [...source.matchAll(flip)].map(
		(m) => `${source.slice(0, m.index).split('\n').length}: ${m[0]}`
	);
}

function sourceFiles(dir: string): string[] {
	return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) return sourceFiles(full);
		return entry.name.endsWith('.ts') ? [full] : [];
	});
}

describe('Issue #1691: converted modules flip txids only through the helpers', () => {
	for (const tree of CONVERTED) {
		it(`${tree} has no hand-written txid flip`, () => {
			const hits = sourceFiles(path.join(ROOT, tree)).flatMap((file) =>
				handWrittenFlips(fs.readFileSync(file, 'utf8')).map(
					(hit) => `${path.relative(ROOT, file)}:${hit}`
				)
			);
			expect(hits).to.deep.equal([]);
		});
	}

	it('catches a flip reintroduced', () => {
		const planted = [
			"const a = Buffer.from(input.hash).reverse().toString('hex');",
			"const b = Buffer.from(txid, 'hex').reverse();",
			'const c = Buffer.from(data.fundingTxid)',
			'\t.reverse()',
			"\t.toString('hex');",
			'const d = tx.getHash().reverse();',
			'const e = Buffer.from(pick(x, y)).reverse();',
			"const f = Buffer.from(value, 'hex');",
			'const g = [...list].reverse();'
		].join('\n');
		expect(
			handWrittenFlips(planted).map((hit) => hit.split(':')[0])
		).to.deep.equal(['1', '2', '3', '6', '7']);
	});
});
