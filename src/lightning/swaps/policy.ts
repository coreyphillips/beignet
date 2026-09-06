import { assertBlockHeight, MAX_MONEY_SATOSHIS } from './validation';

function assertBlocks(value: number, name: string, allowZero = false): void {
	if (
		!Number.isSafeInteger(value) ||
		value < (allowZero ? 0 : 1) ||
		value >= 500_000_000
	) {
		throw new Error(
			`${name} must be an integer block count ${
				allowZero ? 'at least zero' : 'greater than zero'
			}`
		);
	}
}

export interface ISubmarineSwapAdmission {
	currentHeight: number;
	refundHeight: number;
	/** Enforced upper bound across every outgoing Lightning attempt/MPP part. */
	latestOutgoingHtlcExpiry: number;
	/** Chain claim, confirmation and reorg budget after the last LN expiry. */
	claimSafetyBlocks: number;
	fundingConfirmations: number;
	minimumFundingConfirmations: number;
}

/**
 * Client locks BTC, provider pays Lightning and claims BTC with the preimage.
 * Requires refundHeight > latestOutgoingHtlcExpiry + claimSafetyBlocks.
 * A wall-clock payment timeout is not an outgoing HTLC expiry bound.
 * This pure check does not enforce that bound in the Lightning payment engine.
 */
export function validateSubmarineSwapAdmission(
	params: ISubmarineSwapAdmission
): void {
	assertBlockHeight(params.currentHeight, 'Current height');
	assertBlockHeight(params.refundHeight, 'Refund height');
	assertBlockHeight(
		params.latestOutgoingHtlcExpiry,
		'Latest outgoing HTLC expiry'
	);
	assertBlocks(params.claimSafetyBlocks, 'Claim safety margin');
	assertBlocks(params.fundingConfirmations, 'Funding confirmations', true);
	assertBlocks(
		params.minimumFundingConfirmations,
		'Minimum funding confirmations'
	);
	if (params.fundingConfirmations < params.minimumFundingConfirmations) {
		throw new Error('Swap funding has insufficient confirmations');
	}
	if (params.latestOutgoingHtlcExpiry <= params.currentHeight) {
		throw new Error('Outgoing HTLC expiry must be in the future');
	}
	if (
		params.refundHeight <=
		params.latestOutgoingHtlcExpiry + params.claimSafetyBlocks
	) {
		throw new Error(
			'Submarine refund must outlive outgoing HTLC expiry and claim margin'
		);
	}
}

export interface ICommittedSwapHtlc {
	/** Unique local channel-id/HTLC-id pair, not merely the payment hash. */
	id: string;
	paymentHash: Buffer;
	amountMsat: bigint;
	cltvExpiry: number;
}

export interface IReverseSwapAdmission {
	currentHeight: number;
	refundHeight: number;
	paymentHash: Buffer;
	expectedAmountMsat: bigint;
	/** Only irrevocably committed parts of this held invoice from local state. */
	committedHtlcs: readonly ICommittedSwapHtlc[];
	/** Minimum time reserved for funding and the client's claim before refund. */
	fundingSafetyBlocks: number;
	/** Includes refund inclusion, confirmations, reorg risk and LN settlement. */
	resolutionSafetyBlocks: number;
	/** Actual early automatic hold-cancellation margin used by the LN node. */
	holdCancelSafetyBlocks: number;
}

/**
 * Client pays a held invoice; provider locks BTC for the client to claim.
 * Requires a complete MPP set and:
 * earliestIncomingExpiry - holdCancelSafetyBlocks > refundHeight + resolutionSafetyBlocks.
 * Returns the earliest effective cancellation height, not permission to cancel.
 * The caller must obtain commitment and expiry data from authoritative local LN
 * state and coordinate automatic cancellation before using this for funding.
 */
export function validateReverseSwapAdmission(
	params: IReverseSwapAdmission
): number {
	assertBlockHeight(params.currentHeight, 'Current height');
	assertBlockHeight(params.refundHeight, 'Refund height');
	assertBlocks(params.fundingSafetyBlocks, 'Funding safety margin');
	assertBlocks(params.resolutionSafetyBlocks, 'Resolution safety margin');
	assertBlocks(params.holdCancelSafetyBlocks, 'Hold cancellation margin', true);
	if (
		!Buffer.isBuffer(params.paymentHash) ||
		params.paymentHash.length !== 32
	) {
		throw new Error('Payment hash must be 32 bytes');
	}
	if (
		typeof params.expectedAmountMsat !== 'bigint' ||
		params.expectedAmountMsat <= 0n ||
		params.expectedAmountMsat > MAX_MONEY_SATOSHIS * 1000n
	) {
		throw new Error(
			'Expected amount must be positive millisatoshis within Bitcoin money range'
		);
	}
	if (
		params.refundHeight <=
		params.currentHeight + params.fundingSafetyBlocks
	) {
		throw new Error(
			'Reverse refund height leaves insufficient funding and claim time'
		);
	}
	let total = 0n;
	let earliestExpiry = 500_000_000;
	const ids = new Set<string>();
	for (const part of params.committedHtlcs) {
		if (typeof part.id !== 'string' || !part.id || ids.has(part.id)) {
			throw new Error('Committed HTLC ids must be nonempty and unique');
		}
		ids.add(part.id);
		if (
			!Buffer.isBuffer(part.paymentHash) ||
			!part.paymentHash.equals(params.paymentHash)
		) {
			throw new Error('Committed HTLC payment hash does not match the swap');
		}
		if (
			typeof part.amountMsat !== 'bigint' ||
			part.amountMsat <= 0n ||
			part.amountMsat > params.expectedAmountMsat
		) {
			throw new Error(
				'Committed HTLC amount must be positive and at most the expected amount'
			);
		}
		assertBlockHeight(part.cltvExpiry, 'Incoming HTLC expiry');
		total += part.amountMsat;
		earliestExpiry = Math.min(earliestExpiry, part.cltvExpiry);
	}
	if (total !== params.expectedAmountMsat) {
		throw new Error(
			'Committed HTLCs must fund the complete expected invoice amount'
		);
	}
	const cancellationHeight = earliestExpiry - params.holdCancelSafetyBlocks;
	if (
		cancellationHeight <=
		params.refundHeight + params.resolutionSafetyBlocks
	) {
		throw new Error(
			'Reverse incoming HTLCs must outlive refund resolution and hold cancellation margins'
		);
	}
	return cancellationHeight;
}
