import { decodeTlvStream, encodeTlvStream } from '../message/tlv';
import { isValidPublicKey } from '../crypto/ecdh';
import type { IFforEpochParams } from './types';

/** Signed asset custody terms carried in ff_init and echoed in ff_accept TLV 19. */
export interface IFforAssetTerms {
	assetId?: Buffer;
	groupKey?: Buffer;
	/** Identity of the fixed exchange quote for this epoch. */
	quoteId: Buffer;
	/** Quoted millisatoshis per asset unit, as an exact positive rational. */
	priceNumerator: bigint;
	priceDenominator: bigint;
	/** Bitcoin output value of each precommitted voucher, independent of its quote. */
	carrierMsat: bigint;
	/** Integer asset units, in the same slot order as voucherAmountsMsat. */
	amounts: bigint[];
	/** Canonical update_add_htlc custom TLV streams, one per slot. */
	customRecords: Buffer[];
}
export const FF_ASSET_FEATURE_BIT = 448;
export const FF_ASSET_TERMS_TLV = 19n;
const MAX = 0xffffffffffffffffn;
const uint = (value: bigint): Buffer => {
	if (typeof value !== 'bigint' || value < 0n || value > MAX)
		throw new Error('Invalid FFOR asset uint64');
	const out = Buffer.alloc(8);
	out.writeBigUInt64BE(value);
	return out;
};
const short = (value: number): Buffer => {
	const out = Buffer.alloc(2);
	out.writeUInt16BE(value);
	return out;
};
export function quoteFforAssetAmount(
	terms: IFforAssetTerms,
	amount: bigint
): bigint {
	if (
		terms.priceNumerator <= 0n ||
		terms.priceNumerator > MAX ||
		terms.priceDenominator <= 0n ||
		terms.priceDenominator > MAX ||
		amount <= 0n ||
		amount > MAX
	)
		throw new Error('Invalid FFOR asset quote');
	const value = (amount * terms.priceNumerator) / terms.priceDenominator;
	if (value <= 0n || value > MAX)
		throw new Error('FFOR asset quote value out of range');
	return value;
}
export function decodeFforAssetRecords(bytes: Buffer): Map<bigint, Buffer> {
	if (bytes.length === 0 || bytes.length > 4096)
		throw new Error('Invalid FFOR asset custom records');
	const { records } = decodeTlvStream(bytes);
	if (
		!records.length ||
		records.some((record) => record.type < 65536n) ||
		!encodeTlvStream(records).equals(bytes)
	)
		throw new Error('Noncanonical FFOR asset custom records');
	return new Map(
		records.map((record) => [record.type, Buffer.from(record.value)])
	);
}
export function encodeFforAssetTerms(terms: IFforAssetTerms): Buffer {
	if (
		!!terms.assetId === !!terms.groupKey ||
		(terms.assetId && terms.assetId.length !== 32) ||
		(terms.groupKey &&
			(terms.groupKey.length !== 33 || !isValidPublicKey(terms.groupKey))) ||
		terms.quoteId.length !== 32 ||
		terms.carrierMsat < 354000n ||
		terms.carrierMsat > MAX ||
		terms.carrierMsat % 1000n !== 0n ||
		terms.amounts.length < 1 ||
		terms.amounts.length > 483 ||
		terms.customRecords.length !== terms.amounts.length
	)
		throw new Error('Invalid FFOR asset terms');
	const rows = terms.amounts.map((amount, index) => {
		quoteFforAssetAmount(terms, amount);
		const records = terms.customRecords[index];
		decodeFforAssetRecords(records);
		return Buffer.concat([uint(amount), short(records.length), records]);
	});
	const encoded = Buffer.concat([
		Buffer.from([1, terms.assetId ? 0 : 1]),
		terms.assetId ?? terms.groupKey!,
		terms.quoteId,
		uint(terms.priceNumerator),
		uint(terms.priceDenominator),
		uint(terms.carrierMsat),
		short(rows.length),
		...rows
	]);
	if (encoded.length > 48000)
		throw new Error('FFOR asset terms exceed wire budget');
	return encoded;
}
export function decodeFforAssetTerms(bytes: Buffer): IFforAssetTerms {
	let offset = 0;
	const take = (length: number): Buffer => {
		if (offset + length > bytes.length)
			throw new Error('Truncated FFOR asset terms');
		const out = bytes.subarray(offset, offset + length);
		offset += length;
		return out;
	};
	if (bytes.length > 48000 || take(1)[0] !== 1)
		throw new Error('Unsupported FFOR asset terms');
	const kind = take(1)[0];
	if (kind > 1) throw new Error('Unknown FFOR asset identity');
	const identity = Buffer.from(take(kind === 0 ? 32 : 33));
	const quoteId = Buffer.from(take(32)),
		priceNumerator = take(8).readBigUInt64BE(),
		priceDenominator = take(8).readBigUInt64BE(),
		carrierMsat = take(8).readBigUInt64BE();
	const count = take(2).readUInt16BE();
	if (count < 1 || count > 483)
		throw new Error('Invalid FFOR asset slot count');
	const amounts: bigint[] = [],
		customRecords: Buffer[] = [];
	for (let i = 0; i < count; i++) {
		amounts.push(take(8).readBigUInt64BE());
		customRecords.push(Buffer.from(take(take(2).readUInt16BE())));
	}
	const terms = {
		...(kind === 0 ? { assetId: identity } : { groupKey: identity }),
		quoteId,
		priceNumerator,
		priceDenominator,
		carrierMsat,
		amounts,
		customRecords
	};
	if (offset !== bytes.length || !encodeFforAssetTerms(terms).equals(bytes))
		throw new Error('Noncanonical FFOR asset terms');
	return terms;
}
export function fforVoucherWireAmount(
	params: IFforEpochParams,
	index: number
): bigint {
	return params.assetTerms?.carrierMsat ?? params.voucherAmountsMsat[index];
}
