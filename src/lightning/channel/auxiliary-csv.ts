/**
 * Asset channels: the CSV delay policy an opening was negotiated under,
 * kept with the channel so a restart cannot change it.
 */

import type { IAuxiliaryOpeningCsvState } from './auxiliary';

function validDelay(value: number): boolean {
	return Number.isInteger(value) && value >= 1 && value <= 2016;
}

/** Validate and copy the immutable policy retained by an unfinished open. */
export function copyAuxiliaryOpeningCsvPolicy(
	policy: IAuxiliaryOpeningCsvState
): IAuxiliaryOpeningCsvState {
	if (
		!policy ||
		policy.mode !== 'symmetric' ||
		!validDelay(policy.minimumDelay) ||
		!validDelay(policy.maximumDelay) ||
		!validDelay(policy.localDelay) ||
		policy.maximumDelay < policy.minimumDelay ||
		policy.localDelay < policy.minimumDelay ||
		policy.localDelay > policy.maximumDelay
	)
		throw new Error('Invalid persisted asset channel CSV policy');
	return {
		mode: 'symmetric',
		minimumDelay: policy.minimumDelay,
		maximumDelay: policy.maximumDelay,
		localDelay: policy.localDelay
	};
}
