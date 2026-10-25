/**
 * Payment records, kept apart from node/types so storage and recovery can
 * name them without importing the node layer. Re-exported from node/types.
 */

import type { IRoute } from '../gossip/types';

export enum PaymentStatus {
	PENDING = 'PENDING',
	COMPLETED = 'COMPLETED',
	FAILED = 'FAILED'
}

export enum PaymentDirection {
	OUTGOING = 'OUTGOING',
	INCOMING = 'INCOMING'
}

export interface IPayAllBudget {
	debitMsat: bigint;
	maxFeeMsat: bigint;
}

export interface IPayAllQuote extends IPayAllBudget {
	minRecipientMsat: bigint;
	routeFound: boolean;
	remainderMsat: bigint;
	searchExhausted: boolean;
}

/** Planned figures while pending; exact settled figures when completed. */
export interface IPayAllPayment extends IPayAllBudget {
	deliveredMsat: bigint;
	feeMsat: bigint;
	/** Unspent part of the approved debit, excluding reserves and later receipts. */
	remainderMsat: bigint;
}

export interface IPaymentInfo {
	payAll?: IPayAllPayment;
	paymentHash: Buffer;
	preimage?: Buffer;
	amountMsat: bigint;
	/**
	 * The msat that left this node, fees included, when amountMsat is not
	 * that figure. A single-path send records its first-hop amount in
	 * amountMsat, so it needs nothing here; an MPP send records the invoice
	 * amount there and the sum of its parts' first-hop amounts here, written
	 * with the record's first persist. A part refused at dispatch is not
	 * subtracted, so this can overstate by that part.
	 */
	sentMsat?: bigint;
	/**
	 * The msat this node was credited for an incoming payment, the sum of the
	 * HTLCs it settled, when amountMsat is not that figure. amountMsat stays
	 * the invoice (or onion-declared) amount the payment was validated
	 * against. A JIT skim settles HTLCs short of it by the LSP's opening fee,
	 * and an overpaying sender's HTLCs exceed it.
	 */
	receivedMsat?: bigint;
	status: PaymentStatus;
	direction: PaymentDirection;
	route?: IRoute;
	sharedSecrets?: Buffer[];
	failureCode?: number;
	failureSourceIndex?: number;
	/**
	 * Why a payment failed when no onion failure code is available: it failed
	 * LOCALLY, before the HTLC ever reached the network, or a peer's failure came
	 * back undecryptable. Without this a local failure is indistinguishable from a
	 * remote one, since both surface only as an absent failureCode.
	 */
	failureReason?: string;
	retryCount?: number;
	/**
	 * Block height this attempt converted its relative route CLTV deltas against.
	 * A payee reporting a height at or below this cannot be telling us anything
	 * new, so it is what a height-skew failure must be judged against, not our
	 * live height.
	 */
	cltvBaseHeight?: number;
	createdAt: number;
	completedAt?: number;
	/**
	 * The received HTLCs (`channelIdHex:htlcId`) that completed an incoming
	 * payment. A restart redispatch fulfills only these for a completed hash;
	 * any other HTLC for it is a replay.
	 */
	settledHtlcs?: string[];
	metadata?: Record<string, string>;
}
