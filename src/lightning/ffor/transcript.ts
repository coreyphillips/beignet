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
	for (const e of entries) {
		parts.push(
			u16(e.k),
			e.paymentHash,
			u64(e.amountMsat),
			u32(e.voucherExpiry),
			u32(e.settlementDeadline),
			u64(e.sHtlcId)
		);
	}
	return Buffer.concat(parts);
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
