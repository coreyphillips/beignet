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
 * Check that all outputs meet dust limit.
 */
export function checkDustOutputs(
	outputs: IInteractiveTxOutput[]
): string | null {
	for (const output of outputs) {
		if (output.amountSats < DUST_LIMIT_SATS) {
			return `Output amount ${output.amountSats} below dust limit ${DUST_LIMIT_SATS}`;
		}
	}
	return null;
}

/**
 * Validate a complete interactive transaction.
 */
export function validateInteractiveTx(
	inputs: IInteractiveTxInput[],
	outputs: IInteractiveTxOutput[]
): string | null {
	if (inputs.length === 0) {
		return 'Transaction must have at least one input';
	}
	if (outputs.length === 0) {
		return 'Transaction must have at least one output';
	}

	const dupError = checkDuplicatePrevouts(inputs);
	if (dupError) return dupError;

	const dustError = checkDustOutputs(outputs);
	if (dustError) return dustError;

	return null;
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
