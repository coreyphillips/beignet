import { expect } from 'chai';
import {
	decodeFforAssetRecords,
	decodeFforAssetTerms,
	encodeFforAssetTerms,
	quoteFforAssetAmount,
	type IFforAssetTerms
} from '../../src/lightning/ffor/assets';
import { getPublicKey } from '../../src/lightning/crypto';

const terms = (): IFforAssetTerms => ({
	assetId: Buffer.alloc(32, 0x11),
	quoteId: Buffer.alloc(32, 0x22),
	priceNumerator: 7n,
	priceDenominator: 3n,
	carrierMsat: 354000n,
	amounts: [2n],
	customRecords: [Buffer.from('fe0001000001aa', 'hex')]
});

describe('FFOR signed asset custody terms', () => {
	it('encodes the exact versioned asset terms independently from the Bitcoin carrier and quoted value', () => {
		const expected =
			'0100' +
			'11'.repeat(32) +
			'22'.repeat(32) +
			'0000000000000007000000000000000300000000000566d00001' +
			'00000000000000020007fe0001000001aa';
		const value = terms();
		expect(encodeFforAssetTerms(value).toString('hex')).to.equal(expected);
		expect(decodeFforAssetTerms(Buffer.from(expected, 'hex'))).to.deep.equal(
			value
		);
		expect(quoteFforAssetAmount(value, 2n)).to.equal(4n);
		expect(value.carrierMsat).to.equal(354000n);
	});
	it('retains exact authenticated group identity and clones decoded fields', () => {
		const value = {
			...terms(),
			assetId: undefined,
			groupKey: getPublicKey(Buffer.alloc(32, 1))
		};
		const bytes = encodeFforAssetTerms(value),
			decoded = decodeFforAssetTerms(bytes);
		expect(decoded.groupKey).to.deep.equal(value.groupKey);
		bytes.fill(0);
		expect(decoded.groupKey).to.deep.equal(value.groupKey);
		expect(decoded.customRecords[0]).to.deep.equal(value.customRecords[0]);
	});
	it('rejects every truncated prefix, changed version or identity kind, and trailing bytes', () => {
		const bytes = encodeFforAssetTerms(terms());
		for (let length = 0; length < bytes.length; length++)
			expect(
				() => decodeFforAssetTerms(bytes.subarray(0, length)),
				`length ${length}`
			).to.throw();
		for (const offset of [0, 1]) {
			const changed = Buffer.from(bytes);
			changed[offset] = 2;
			expect(() => decodeFforAssetTerms(changed)).to.throw();
		}
		expect(() =>
			decodeFforAssetTerms(Buffer.concat([bytes, Buffer.from([0])]))
		).to.throw();
		expect(() => decodeFforAssetTerms(Buffer.alloc(48001))).to.throw();
	});
	it('rejects ambiguous identities, invalid carrier amounts, zero or overflowing quotes, and mismatched slots', () => {
		const mutations: Partial<IFforAssetTerms>[] = [
			{ assetId: undefined },
			{ groupKey: getPublicKey(Buffer.alloc(32, 1)) },
			{ assetId: undefined, groupKey: Buffer.alloc(33) },
			{ quoteId: Buffer.alloc(31) },
			{ carrierMsat: 353000n },
			{ carrierMsat: 354001n },
			{ carrierMsat: 1n << 64n },
			{ amounts: [0n] },
			{ amounts: [] },
			{ amounts: [1n << 64n] },
			{ priceNumerator: 0n },
			{ priceDenominator: 0n },
			{ priceNumerator: 1n, priceDenominator: 100n },
			{ priceNumerator: (1n << 64n) - 1n, priceDenominator: 1n },
			{ customRecords: [] },
			{
				amounts: Array(484).fill(2n),
				customRecords: Array(484).fill(terms().customRecords[0])
			}
		];
		for (const mutation of mutations)
			expect(() =>
				encodeFforAssetTerms({ ...terms(), ...mutation })
			).to.throw();
	});
	it('rejects duplicate, unsorted, noncanonical and non-custom HTLC records', () => {
		for (const hex of [
			'',
			'0101aa',
			'fe0001000001aafe0001000001bb',
			'fe0001000101aafe0001000001bb',
			'ff000000000001000001aa',
			'fe0001000002aa'
		])
			expect(
				() => decodeFforAssetRecords(Buffer.from(hex, 'hex')),
				hex
			).to.throw();
		expect(() => decodeFforAssetRecords(Buffer.alloc(4097))).to.throw();
	});
});
