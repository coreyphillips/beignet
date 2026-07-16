/**
 * Interactive Transaction Construction validation.
 *
 * Rules:
 * - Serial ID parity: even = initiator, odd = acceptor
 * - No duplicate prevouts (same txid:vout)
 * - Outputs must be above dust (546 sats for P2WPKH)
 * - Transaction must have at least one input and one output
 * - Fee must be sufficient
 */

import { IInteractiveTxInput, IInteractiveTxOutput } from './types';

const DUST_LIMIT_SATS = 546n;

/** BOLT 2 interactive-tx: each peer may add at most 252 inputs / 252 outputs. */
export const MAX_INTERACTIVE_TX_INPUTS = 252;
export const MAX_INTERACTIVE_TX_OUTPUTS = 252;
/** Consensus money cap: 21M BTC in satoshis. */
export const MAX_MONEY_SATS = 2_100_000_000_000_000n;
/** Standardness cap: a heavier tx will not relay, stranding the channel. */
export const MAX_STANDARD_TX_WEIGHT = 400_000;

/**
 * Validate serial ID parity.
 * Initiator must use even serial IDs, acceptor must use odd.
 */
export function validateSerialIdParity(
	serialId: bigint,
	isInitiator: boolean
): string | null {
	const isEven = serialId % 2n === 0n;
	if (isInitiator && !isEven) {
		return 'Initiator must use even serial IDs';
	}
	if (!isInitiator && isEven) {
		return 'Acceptor must use odd serial IDs';
	}
	return null;
}

/**
 * Validate that a serial ID from the peer has correct parity.
 * Peer's parity is opposite of ours.
 */
export function validatePeerSerialIdParity(
	serialId: bigint,
	weAreInitiator: boolean
): string | null {
	// Peer's IDs should have opposite parity
	return validateSerialIdParity(serialId, !weAreInitiator);
}

/**
 * Check for duplicate prevouts among inputs.
 */
export function checkDuplicatePrevouts(
	inputs: IInteractiveTxInput[]
): string | null {
	const seen = new Set<string>();
	for (const input of inputs) {
		const key = `${input.prevTxid.toString('hex')}:${input.prevOutputIndex}`;
		if (seen.has(key)) {
			return `Duplicate prevout: ${key}`;
		}
		seen.add(key);
	}
	return null;
}

/**
 * Check that all outputs meet the dust limit (the negotiated limit when
 * known; never below the 546-sat floor) and the consensus money cap.
 */
export function checkDustOutputs(
	outputs: IInteractiveTxOutput[],
	dustLimitSats: bigint = DUST_LIMIT_SATS
): string | null {
	const dust =
		dustLimitSats > DUST_LIMIT_SATS ? dustLimitSats : DUST_LIMIT_SATS;
	for (const output of outputs) {
		if (output.amountSats < dust) {
			return `Output amount ${output.amountSats} below dust limit ${dust}`;
		}
		if (output.amountSats > MAX_MONEY_SATS) {
			return `Output amount ${output.amountSats} exceeds MAX_MONEY`;
		}
	}
	return null;
}

/**
 * Validate a complete interactive transaction.
 */
export function validateInteractiveTx(
	inputs: IInteractiveTxInput[],
	outputs: IInteractiveTxOutput[],
	dustLimitSats?: bigint
): string | null {
	if (inputs.length === 0) {
		return 'Transaction must have at least one input';
	}
	if (outputs.length === 0) {
		return 'Transaction must have at least one output';
	}
	if (inputs.length > MAX_INTERACTIVE_TX_INPUTS * 2) {
		return `Transaction has ${inputs.length} inputs, above the interactive-tx cap`;
	}
	if (outputs.length > MAX_INTERACTIVE_TX_OUTPUTS * 2) {
		return `Transaction has ${outputs.length} outputs, above the interactive-tx cap`;
	}

	const dupError = checkDuplicatePrevouts(inputs);
	if (dupError) return dupError;

	const dustError = checkDustOutputs(outputs, dustLimitSats);
	if (dustError) return dustError;

	return null;
}

/**
 * Per-peer completion checks for a negotiated interactive tx (BOLT 2, on
 * tx_complete): each side's inputs must cover its outputs plus its positive
 * channel contribution, the paid fee must meet the negotiated feerate, and
 * the transaction must stay under the 400k-WU standardness cap. The shared
 * splice input/output are excluded from the per-side sums by the caller
 * (their net effect is each side's contribution).
 */
export function validateCompletedInteractiveTx(opts: {
	/** Peer's non-shared input total (sats). */
	remoteInputSats: bigint;
	/** Peer's non-shared output total (sats). */
	remoteOutputSats: bigint;
	/**
	 * Peer's SIGNED channel contribution (v2 funding sats, or splice relative
	 * sats). A negative contribution (splice-out) funds the peer's destination
	 * output from the shared output rather than from its inputs.
	 */
	remoteContributionSats: bigint;
	/** Full transaction fee: all inputs minus all outputs, shared included. */
	feeSats: bigint;
	/** Estimated transaction weight in WU. */
	weight: number;
	/** Negotiated funding feerate (sat/kw). */
	feeratePerKw: number;
}): string | null {
	if (opts.weight > MAX_STANDARD_TX_WEIGHT) {
		return `Transaction weight ${opts.weight} exceeds ${MAX_STANDARD_TX_WEIGHT} WU`;
	}
	const owed = opts.remoteOutputSats + opts.remoteContributionSats;
	const remoteOwes = owed > 0n ? owed : 0n;
	if (opts.remoteInputSats < remoteOwes) {
		return `Peer inputs ${opts.remoteInputSats} sats do not cover its outputs and contribution ${remoteOwes} sats`;
	}
	if (opts.feeSats < 0n) {
		return 'Negotiated transaction outputs exceed its inputs';
	}
	return checkFeeSufficiency(opts.feeSats, opts.weight, opts.feeratePerKw);
}

/**
 * Calculate the fee of an interactive transaction.
 * Fee = total input value - total output value.
 * Input values must be provided separately since inputs reference previous outputs.
 */
export function calculateTxFee(
	inputValues: bigint[],
	outputs: IInteractiveTxOutput[]
): bigint {
	let totalIn = 0n;
	for (const v of inputValues) totalIn += v;
	let totalOut = 0n;
	for (const o of outputs) totalOut += o.amountSats;
	return totalIn - totalOut;
}

/**
 * Check that fee is sufficient given a fee rate.
 * @param fee - Fee in satoshis
 * @param weight - Transaction weight in weight units
 * @param minFeeratePerKw - Minimum fee rate in sat/kw
 */
export function checkFeeSufficiency(
	fee: bigint,
	weight: number,
	minFeeratePerKw: number
): string | null {
	const minFee = BigInt(Math.ceil((weight * minFeeratePerKw) / 1000));
	if (fee < minFee) {
		return `Fee ${fee} is below minimum ${minFee} for weight ${weight} at ${minFeeratePerKw} sat/kw`;
	}
	return null;
}
