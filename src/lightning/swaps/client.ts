/**
 * Client-side helpers for the swap protocol (issue #737): pure functions a
 * wallet or the chicory client runs before it pays. Nothing here talks to a
 * node; the caller supplies what it sent, what came back, its own height and
 * its own policy, and gets a verdict it can act on.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { decode as decodeInvoice } from '../invoice/decode';
import {
	DEFAULT_EXPIRY,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../invoice/types';
import { buildSwapHtlc, ISwapHtlc } from './htlc';
import {
	ISwapCreate,
	ISwapCreateAck,
	ISwapSubmarineCreate,
	ISwapSubmarineCreateAck,
	SwapRefusalReason
} from './messages';

export interface IReverseSwapFeeTerms {
	flatFeeSat: bigint;
	feePpm: number;
	minerFeeSat: bigint;
}

/** The provider's total fee for a reverse swap of `amountSat`. */
export function reverseSwapFee(
	amountSat: bigint,
	terms: IReverseSwapFeeTerms
): bigint {
	if (typeof amountSat !== 'bigint' || amountSat < 0n) {
		throw new Error('amountSat must be a non-negative bigint');
	}
	if (!Number.isSafeInteger(terms.feePpm) || terms.feePpm < 0) {
		throw new Error('feePpm must be a non-negative integer');
	}
	const proportional =
		(amountSat * BigInt(terms.feePpm) + 999_999n) / 1_000_000n;
	return terms.flatFeeSat + proportional + terms.minerFeeSat;
}

export interface ISubmarineSwapFeeTerms extends IReverseSwapFeeTerms {
	/**
	 * The routing fee the provider may spend paying the invoice, per
	 * million of the amount it pays. It is charged on the net amount and
	 * added to the fee, so a payee cannot author route-hint fees that turn
	 * the swap into a loss for the provider (#743 audit).
	 */
	routingFeePpm?: number;
}

/**
 * The provider's total fee for a submarine swap of `amountSat` locked on
 * chain (issue #743): flat + ppm + the claim miner fee, plus the routing
 * budget on what is left. The client is paid `amountSat - fee` over
 * Lightning.
 */
export function submarineSwapFee(
	amountSat: bigint,
	terms: ISubmarineSwapFeeTerms
): bigint {
	const base = reverseSwapFee(amountSat, terms);
	const ppm = terms.routingFeePpm ?? 0;
	if (!Number.isSafeInteger(ppm) || ppm < 0) {
		throw new Error('routingFeePpm must be a non-negative integer');
	}
	if (ppm === 0 || amountSat <= base) return base;
	const routing = ((amountSat - base) * BigInt(ppm) + 999_999n) / 1_000_000n;
	return base + routing;
}

export interface IReverseSwapTermsCheck {
	/** What the client sent. */
	create: ISwapCreate;
	ack: ISwapCreateAck;
	/** The client's own chain view; the ack's height is never trusted. */
	currentHeight: number;
	network: Network;
	/** refundHeight - currentHeight must fall within [min, max]. */
	minRefundDelta: number;
	maxRefundDelta: number;
	/** The most the client will pay above the on-chain amount. */
	maxTotalFeeSat: bigint;
}

export type ReverseSwapTermsVerdict =
	| {
			ok: true;
			htlc: ISwapHtlc;
			address: string;
			outputScript: Buffer;
			invoice: { paymentHash: Buffer; amountMsat: bigint; expiresAt: number };
	  }
	| { ok: false; reason: string; refusal?: SwapRefusalReason };

function bitcoinNetwork(network: Network): bitcoin.Network {
	switch (network) {
		case Network.MAINNET:
			return bitcoin.networks.bitcoin;
		case Network.REGTEST:
			return bitcoin.networks.regtest;
		default:
			return bitcoin.networks.testnet;
	}
}

/**
 * Verify a reverse swap ack against what was asked and the client's policy:
 * the contract rebuilt from the client's own hash and claim key plus the
 * provider's refund key and height must equal the ack's script and address;
 * the invoice must carry that hash for exactly the quoted amount on the
 * expected network; the fee and refund window must be within policy.
 */
export function verifyReverseSwapTerms(
	check: IReverseSwapTermsCheck
): ReverseSwapTermsVerdict {
	const { create, ack } = check;
	if (!ack.requestId.equals(create.requestId)) {
		return { ok: false, reason: 'ack answers a different request' };
	}
	if (!ack.paymentHash.equals(create.paymentHash)) {
		return { ok: false, reason: 'ack names a different payment hash' };
	}
	if (!ack.accepted || !ack.terms) {
		return {
			ok: false,
			reason: `provider refused: ${
				SwapRefusalReason[ack.reason] ?? ack.reason
			}${ack.reasonText ? ` (${ack.reasonText})` : ''}`,
			refusal: ack.reason
		};
	}
	const terms = ack.terms;
	if (terms.onchainAmountSat !== create.onchainAmountSat) {
		return { ok: false, reason: 'on-chain amount differs from the request' };
	}
	if (terms.totalFeeSat > check.maxTotalFeeSat) {
		return { ok: false, reason: 'fee exceeds the client ceiling' };
	}
	if (terms.totalFeeSat > create.maxTotalFeeSat) {
		return { ok: false, reason: 'fee exceeds the ceiling the request carried' };
	}
	if (terms.minerFeeSat > terms.totalFeeSat) {
		return { ok: false, reason: 'miner fee exceeds the total fee' };
	}
	const expectedMsat = (terms.onchainAmountSat + terms.totalFeeSat) * 1000n;
	if (terms.invoiceAmountMsat !== expectedMsat) {
		return {
			ok: false,
			reason: 'invoice amount does not equal amount plus fee'
		};
	}
	if (terms.refundPubkey.equals(create.claimPubkey)) {
		return { ok: false, reason: 'refund key equals the claim key' };
	}
	const delta = terms.refundHeight - check.currentHeight;
	if (delta < check.minRefundDelta) {
		return { ok: false, reason: 'refund height is too soon' };
	}
	if (delta > check.maxRefundDelta) {
		return { ok: false, reason: 'refund height is too far away' };
	}
	const htlc: ISwapHtlc = {
		paymentHash: create.paymentHash,
		claimPublicKey: create.claimPubkey,
		refundPublicKey: terms.refundPubkey,
		refundHeight: terms.refundHeight
	};
	let built: ReturnType<typeof buildSwapHtlc>;
	try {
		built = buildSwapHtlc(htlc, bitcoinNetwork(check.network));
	} catch (err) {
		return {
			ok: false,
			reason: `contract does not build: ${
				err instanceof Error ? err.message : String(err)
			}`
		};
	}
	if (!built.outputScript.equals(terms.outputScript)) {
		return { ok: false, reason: 'output script does not match the contract' };
	}
	if (built.address !== terms.address) {
		return { ok: false, reason: 'address does not match the contract' };
	}
	let invoice: ReturnType<typeof decodeInvoice>;
	try {
		invoice = decodeInvoice(terms.bolt11);
	} catch (err) {
		return {
			ok: false,
			reason: `invoice does not decode: ${
				err instanceof Error ? err.message : String(err)
			}`
		};
	}
	if (invoice.network !== check.network) {
		return { ok: false, reason: 'invoice is for another network' };
	}
	if (!invoice.paymentHash.equals(create.paymentHash)) {
		return { ok: false, reason: 'invoice carries another payment hash' };
	}
	if (invoice.amountMsat !== terms.invoiceAmountMsat) {
		return { ok: false, reason: 'invoice amount differs from the terms' };
	}
	const expiresAt = invoice.timestamp + (invoice.expiry ?? DEFAULT_EXPIRY);
	if (terms.invoiceExpiresAt !== expiresAt) {
		return { ok: false, reason: 'invoice expiry differs from the terms' };
	}
	return {
		ok: true,
		htlc,
		address: built.address,
		outputScript: built.outputScript,
		invoice: {
			paymentHash: invoice.paymentHash,
			amountMsat: terms.invoiceAmountMsat,
			expiresAt
		}
	};
}

export interface ISubmarineSwapTermsCheck {
	/** What the client sent, including its own invoice. */
	create: ISwapSubmarineCreate;
	ack: ISwapSubmarineCreateAck;
	/** The client's own chain view; the ack's height is never trusted. */
	currentHeight: number;
	network: Network;
	/** refundHeight - currentHeight must fall within [min, max]. */
	minRefundDelta: number;
	maxRefundDelta: number;
	/** The most the client will give up below the on-chain amount. */
	maxTotalFeeSat: bigint;
}

export type SubmarineSwapTermsVerdict =
	| {
			ok: true;
			htlc: ISwapHtlc;
			address: string;
			outputScript: Buffer;
			invoice: {
				paymentHash: Buffer;
				amountMsat: bigint;
				minFinalCltvExpiry: number;
				expiresAt: number;
			};
	  }
	| { ok: false; reason: string; refusal?: SwapRefusalReason };

/**
 * Verify a submarine swap ack against what was asked and the client's
 * policy (issue #743): the contract rebuilt from the client's own hash and
 * refund key plus the provider's claim key and height must equal the ack's
 * script and address; the client's own invoice must carry that hash for
 * exactly the acked amount on the expected network; the fee the terms imply
 * (on-chain amount minus invoice amount) must be what the ack states and
 * within the client's ceiling; the refund window must be within policy.
 * Whether the invoice's final CLTV fits under the refund height is the
 * client's own policy and is left to it (it knows its node's hold behaviour).
 */
export function verifySubmarineSwapTerms(
	check: ISubmarineSwapTermsCheck
): SubmarineSwapTermsVerdict {
	const { create, ack } = check;
	if (!ack.requestId.equals(create.requestId)) {
		return { ok: false, reason: 'ack answers a different request' };
	}
	if (!ack.paymentHash.equals(create.paymentHash)) {
		return { ok: false, reason: 'ack names a different payment hash' };
	}
	if (!ack.accepted || !ack.terms) {
		return {
			ok: false,
			reason: `provider refused: ${
				SwapRefusalReason[ack.reason] ?? ack.reason
			}${ack.reasonText ? ` (${ack.reasonText})` : ''}`,
			refusal: ack.reason
		};
	}
	const terms = ack.terms;
	if (terms.onchainAmountSat !== create.onchainAmountSat) {
		return { ok: false, reason: 'on-chain amount differs from the request' };
	}
	if (terms.totalFeeSat > check.maxTotalFeeSat) {
		return { ok: false, reason: 'fee exceeds the client ceiling' };
	}
	if (terms.totalFeeSat > create.maxTotalFeeSat) {
		return { ok: false, reason: 'fee exceeds the ceiling the request carried' };
	}
	if (terms.minerFeeSat > terms.totalFeeSat) {
		return { ok: false, reason: 'miner fee exceeds the total fee' };
	}
	if (terms.totalFeeSat >= terms.onchainAmountSat) {
		return { ok: false, reason: 'fee leaves nothing to pay' };
	}
	const expectedMsat = (terms.onchainAmountSat - terms.totalFeeSat) * 1000n;
	if (terms.invoiceAmountMsat !== expectedMsat) {
		return {
			ok: false,
			reason: 'invoice amount does not equal amount minus fee'
		};
	}
	if (terms.claimPubkey.equals(create.refundPubkey)) {
		return { ok: false, reason: 'claim key equals the refund key' };
	}
	if (terms.fundingConfirmations < 1) {
		return {
			ok: false,
			reason: 'provider would pay on an unconfirmed funding'
		};
	}
	const delta = terms.refundHeight - check.currentHeight;
	if (delta < check.minRefundDelta) {
		return { ok: false, reason: 'refund height is too soon' };
	}
	if (delta > check.maxRefundDelta) {
		return { ok: false, reason: 'refund height is too far away' };
	}
	const htlc: ISwapHtlc = {
		paymentHash: create.paymentHash,
		claimPublicKey: terms.claimPubkey,
		refundPublicKey: create.refundPubkey,
		refundHeight: terms.refundHeight
	};
	let built: ReturnType<typeof buildSwapHtlc>;
	try {
		built = buildSwapHtlc(htlc, bitcoinNetwork(check.network));
	} catch (err) {
		return {
			ok: false,
			reason: `contract does not build: ${
				err instanceof Error ? err.message : String(err)
			}`
		};
	}
	if (!built.outputScript.equals(terms.outputScript)) {
		return { ok: false, reason: 'output script does not match the contract' };
	}
	if (built.address !== terms.address) {
		return { ok: false, reason: 'address does not match the contract' };
	}
	let invoice: ReturnType<typeof decodeInvoice>;
	try {
		invoice = decodeInvoice(create.bolt11);
	} catch (err) {
		return {
			ok: false,
			reason: `invoice does not decode: ${
				err instanceof Error ? err.message : String(err)
			}`
		};
	}
	if (invoice.network !== check.network) {
		return { ok: false, reason: 'invoice is for another network' };
	}
	if (!invoice.paymentHash.equals(create.paymentHash)) {
		return { ok: false, reason: 'invoice carries another payment hash' };
	}
	if (invoice.amountMsat !== terms.invoiceAmountMsat) {
		return { ok: false, reason: 'invoice amount differs from the terms' };
	}
	const expiresAt = invoice.timestamp + (invoice.expiry ?? DEFAULT_EXPIRY);
	if (terms.expiresAt > expiresAt) {
		return {
			ok: false,
			reason: 'provider would watch for funding past the invoice expiry'
		};
	}
	return {
		ok: true,
		htlc,
		address: built.address,
		outputScript: built.outputScript,
		invoice: {
			paymentHash: invoice.paymentHash,
			amountMsat: terms.invoiceAmountMsat,
			minFinalCltvExpiry:
				invoice.minFinalCltvExpiry ?? DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			expiresAt
		}
	};
}
