/**
 * Helpers both swap provider engines share (issue #743): the wire mappings
 * of ledger states and resolutions, the exposure refusal mapping, the
 * contract rebuilt from a row, and the native-segwit destination test. Pure
 * functions only; the engines own every side effect.
 */

import { ISwapHtlc } from './htlc';
import { ISwapRecord, ISwapResolutionRecord, SwapState } from './ledger';
import { SwapExposureRefusal } from './exposure';
import {
	SwapRefusalReason,
	SwapWireResolutionKind,
	SwapWireState
} from './messages';

/** Below this an output is dust for every destination the builders accept. */
export const SWAP_DUST_FLOOR_SAT = 330n;

export function exposureRefusal(
	reason: SwapExposureRefusal
): SwapRefusalReason {
	switch (reason) {
		case 'below-min':
			return SwapRefusalReason.AMOUNT_BELOW_MIN;
		case 'above-max':
			return SwapRefusalReason.AMOUNT_ABOVE_MAX;
		case 'exposure':
		case 'concurrency':
			return SwapRefusalReason.EXPOSURE_EXCEEDED;
		case 'fee-rate':
			return SwapRefusalReason.CHAIN_UNAVAILABLE;
		case 'insufficient-balance':
			return SwapRefusalReason.INSUFFICIENT_FUNDS;
	}
}

export function swapWireState(state: SwapState): SwapWireState {
	switch (state) {
		case 'CREATED':
			return SwapWireState.CREATED;
		case 'HELD':
			return SwapWireState.HELD;
		case 'FUNDING':
		case 'FUNDING_BROADCAST':
			return SwapWireState.FUNDING;
		case 'FUNDED':
			return SwapWireState.FUNDED;
		case 'CLAIMED':
			return SwapWireState.CLAIMED;
		case 'SETTLED':
			return SwapWireState.SETTLED;
		case 'REFUND_PENDING':
			return SwapWireState.REFUND_PENDING;
		case 'REFUNDED':
			return SwapWireState.REFUNDED;
		case 'EXPOSED':
			return SwapWireState.EXPOSED;
		case 'CANCELLED':
			return SwapWireState.CANCELLED;
		case 'FAILED':
			return SwapWireState.FAILED;
		case 'FUNDING_SEEN':
			return SwapWireState.FUNDING_SEEN;
		case 'FUNDING_LOST':
			return SwapWireState.FUNDING_LOST;
		case 'PAYING':
			return SwapWireState.PAYING;
		case 'PAYMENT_UNRESOLVED':
			return SwapWireState.PAYMENT_UNRESOLVED;
		case 'PREIMAGE_KNOWN':
			return SwapWireState.PREIMAGE_KNOWN;
		case 'CLAIM_BROADCAST':
			return SwapWireState.CLAIM_BROADCAST;
		case 'CLAIM_CONFIRMED':
			return SwapWireState.CLAIM_CONFIRMED;
		case 'PAYMENT_FAILED':
			return SwapWireState.PAYMENT_FAILED;
		default:
			return SwapWireState.UNKNOWN;
	}
}

export function swapWireResolution(
	kind: ISwapResolutionRecord['kind']
): SwapWireResolutionKind {
	switch (kind) {
		case 'claim':
			return SwapWireResolutionKind.CLAIM;
		case 'refund':
			return SwapWireResolutionKind.REFUND;
		default:
			return SwapWireResolutionKind.UNKNOWN;
	}
}

export function htlcOfRecord(record: ISwapRecord): ISwapHtlc {
	return {
		paymentHash: Buffer.from(record.paymentHashHex, 'hex'),
		claimPublicKey: Buffer.from(record.claimPubkeyHex, 'hex'),
		refundPublicKey: Buffer.from(record.refundPubkeyHex, 'hex'),
		refundHeight: record.refundHeight
	};
}

/**
 * The claim and refund builders pay native segwit only. Returns a reason
 * when the script is anything else, so no swap is quoted or created that
 * could never be resolved to the node's own wallet.
 */
export function nativeSegwitProblem(script: unknown): string | undefined {
	const native =
		Buffer.isBuffer(script) &&
		((script.length === 22 && script[0] === 0x00 && script[1] === 20) ||
			(script.length === 34 &&
				(script[0] === 0x00 || script[0] === 0x51) &&
				script[1] === 32));
	return native ? undefined : 'destination is not native segwit';
}
