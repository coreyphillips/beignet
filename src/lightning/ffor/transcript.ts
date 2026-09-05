/**
 * FFOR section 7.5.2 transcript hashes, the section 7.5.3 voucher book, and
 * the section 9.5.1 voucher onion payload secret.
 *
 *   T_init   = SHA256("ffor/tr/init"   || ff_init wire bytes)
 *   T_setup  = SHA256("ffor/tr/setup"  || T_init || ff_accept wire bytes)
 *   H_book   = SHA256("ffor/book"      || book)
 *   H_commit = SHA256("ffor/commit"    || n_R^act || txid(C^R) || n_S^act || txid(C^S))
 *   H_act    = SHA256("ffor/activate"  || T_setup || H_book || H_commit || epoch_start_height)
 *
 * Tags are the ASCII bytes without a terminator; commitment numbers are u64
 * big-endian, the height u32 big-endian, txids in internal byte order.
 */

import crypto from 'crypto';
import { FF_PROFILE_FIXED_AMOUNT, FforVariant, IFforBookEntry } from './types';

function sha256(...parts: Buffer[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts) h.update(p);
	return h.digest();
}

function ascii(s: string): Buffer {
	return Buffer.from(s, 'ascii');
}
function u8(v: number): Buffer {
	return Buffer.from([v & 0xff]);
}
function u16(v: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(v, 0);
	return b;
}
function u32(v: number): Buffer {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(v >>> 0, 0);
	return b;
}
function u64(v: bigint): Buffer {
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(v, 0);
	return b;
}

export function computeTInit(initWire: Buffer): Buffer {
	return sha256(ascii('ffor/tr/init'), initWire);
}

export function computeTSetup(tInit: Buffer, acceptWire: Buffer): Buffer {
	return sha256(ascii('ffor/tr/setup'), tInit, acceptWire);
}

/** One section 7.5.3 entry: `[2: k][32: H_k][8: d_k][4: T_exp][4: D][8: s_htlc_id]`. */
export function encodeBookEntry(e: IFforBookEntry): Buffer {
	return Buffer.concat([
		u16(e.k),
		e.paymentHash,
		u64(e.amountMsat),
		u32(e.voucherExpiry),
		u32(e.settlementDeadline),
		u64(e.sHtlcId)
	]);
}

export const BOOK_ENTRY_LEN = 2 + 32 + 8 + 4 + 4 + 8;
export const BOOK_HEADER_LEN = 32 + 1 + 1 + 2;

/** Section 7.5.3: entries in slot order, k 1-based. */
export function buildVoucherBook(
	epochId: Buffer,
	variant: FforVariant,
	entries: IFforBookEntry[]
): Buffer {
	const parts: Buffer[] = [
		epochId,
		u8(variant),
		u8(FF_PROFILE_FIXED_AMOUNT),
		u16(entries.length)
	];
	for (const e of entries) parts.push(encodeBookEntry(e));
	return Buffer.concat(parts);
}

/** The inverse of buildVoucherBook; throws on a malformed book. */
export function decodeVoucherBook(book: Buffer): {
	epochId: Buffer;
	variant: FforVariant;
	profile: number;
	entries: IFforBookEntry[];
} {
	if (book.length < BOOK_HEADER_LEN) throw new Error('book too short');
	const epochId = Buffer.from(book.subarray(0, 32));
	const variant = book[32] as FforVariant;
	const profile = book[33];
	const count = book.readUInt16BE(34);
	if (book.length !== BOOK_HEADER_LEN + count * BOOK_ENTRY_LEN) {
		throw new Error('book length does not match its entry count');
	}
	const entries: IFforBookEntry[] = [];
	let at = BOOK_HEADER_LEN;
	for (let i = 0; i < count; i++) {
		entries.push({
			k: book.readUInt16BE(at),
			paymentHash: Buffer.from(book.subarray(at + 2, at + 34)),
			amountMsat: book.readBigUInt64BE(at + 34),
			voucherExpiry: book.readUInt32BE(at + 42),
			settlementDeadline: book.readUInt32BE(at + 46),
			sHtlcId: book.readBigUInt64BE(at + 50)
		});
		at += BOOK_ENTRY_LEN;
	}
	return { epochId, variant, profile, entries };
}

export function computeHBook(book: Buffer): Buffer {
	return sha256(ascii('ffor/book'), book);
}

/** Section 7.5.2 H_commit. Txids in internal byte order (tx.getHash()). */
export function computeHCommit(
	nRAct: bigint,
	rTxidInternal: Buffer,
	nSAct: bigint,
	sTxidInternal: Buffer
): Buffer {
	return sha256(
		ascii('ffor/commit'),
		u64(nRAct),
		rTxidInternal,
		u64(nSAct),
		sTxidInternal
	);
}

export function computeHAct(
	tSetup: Buffer,
	hBook: Buffer,
	hCommit: Buffer,
	epochStartHeight: number
): Buffer {
	return sha256(
		ascii('ffor/activate'),
		tSetup,
		hBook,
		hCommit,
		u32(epochStartHeight)
	);
}

/** Section 9.5.1: payment_secret of voucher k's onion payload. */
export function voucherPaymentSecret(epochId: Buffer, k: number): Buffer {
	return sha256(ascii('ffor/voucher-secret'), epochId, u16(k));
}
