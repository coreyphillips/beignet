/**
 * FFOR section 9.5.1: the voucher onion and voucher recognition.
 *
 * S builds each voucher's onion as a single-hop BOLT 4 packet to R with a
 * fresh random ephemeral key, associated data `payment_hash = H_k`, and a
 * final payload of exactly TLVs 2, 4 and 8:
 *   amt_to_forward = d_k, outgoing_cltv_value = T_exp,
 *   payment_data = { payment_secret = SHA256("ffor/voucher-secret" ||
 *   epoch_id || [2: k]), total_msat = d_k }.
 * R recognises a voucher from the book alone and never acts on the payload.
 */

import crypto from 'crypto';
import {
	constructOnionPacket,
	decodeOnionPacket,
	encodeOnionPacket,
	isFinalHop,
	processOnionPacket
} from '../onion';
import { voucherPaymentSecret } from './transcript';
import { IFforBookEntry } from './types';

export interface IVoucherOnionInput {
	recipientNodeId: Buffer;
	epochId: Buffer;
	k: number;
	amountMsat: bigint;
	voucherExpiry: number;
	paymentHash: Buffer;
	/** Fresh random when absent; fixed only for vectors. */
	sessionKey?: Buffer;
}

/** The 1366-byte onion_routing_packet of voucher k. */
export function buildVoucherOnion(input: IVoucherOnionInput): Buffer {
	const sessionKey = input.sessionKey ?? crypto.randomBytes(32);
	const packet = constructOnionPacket(
		sessionKey,
		[
			{
				pubkey: input.recipientNodeId,
				payload: {
					amountToForwardMsat: input.amountMsat,
					outgoingCltvValue: input.voucherExpiry,
					paymentSecret: voucherPaymentSecret(input.epochId, input.k),
					totalMsat: input.amountMsat
				}
			}
		],
		input.paymentHash
	);
	return encodeOnionPacket(packet);
}

/**
 * Section 9.5.1: an R that decodes the voucher onion MUST find exactly the
 * specified values or treat the add as mismatching. Returns null when the
 * onion decodes to the expected final payload, else the mismatch.
 */
export function verifyVoucherOnion(
	onion: Buffer,
	nodePrivateKey: Buffer,
	epochId: Buffer,
	entry: IFforBookEntry
): string | null {
	try {
		const processed = processOnionPacket(
			decodeOnionPacket(onion),
			nodePrivateKey,
			entry.paymentHash
		);
		if (!isFinalHop(processed.nextPacket)) return 'voucher onion is not final';
		const p = processed.hopPayload;
		const secret = voucherPaymentSecret(epochId, entry.k);
		if (p.amountToForwardMsat !== entry.amountMsat) {
			return 'voucher onion amt_to_forward != d_k';
		}
		if (p.outgoingCltvValue !== entry.voucherExpiry) {
			return 'voucher onion outgoing_cltv_value != T_exp';
		}
		if (!p.paymentSecret || !p.paymentSecret.equals(secret)) {
			return 'voucher onion payment_secret mismatch';
		}
		if (p.totalMsat !== entry.amountMsat) {
			return 'voucher onion total_msat != d_k';
		}
		if (p.shortChannelId !== undefined) {
			return 'voucher onion carries short_channel_id';
		}
		return null;
	} catch (e) {
		return `voucher onion undecodable: ${(e as Error).message}`;
	}
}

/**
 * Section 9.5.1 step 3: R recognises a voucher by (id, amount_msat,
 * payment_hash, cltv_expiry) matching the book exactly. Returns the entry
 * or null.
 */
export function matchVoucher(
	entries: IFforBookEntry[],
	add: {
		id: bigint;
		amountMsat: bigint;
		paymentHash: Buffer;
		cltvExpiry: number;
	}
): IFforBookEntry | null {
	for (const e of entries) {
		if (
			e.sHtlcId === add.id &&
			e.amountMsat === add.amountMsat &&
			e.voucherExpiry === add.cltvExpiry &&
			e.paymentHash.equals(add.paymentHash)
		) {
			return e;
		}
	}
	return null;
}
