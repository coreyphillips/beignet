/**
 * Asset channels: the CSV delay policy an opening was negotiated under,
 * kept with the channel so a restart cannot change it.
 */

import type {
	IAuxiliaryOpeningCsvPolicy,
	IAuxiliaryOpeningCsvState
} from './auxiliary';

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

/**
 * Choose the delay an asset opening advertises, before any key is shown or
 * funding prepared. The opener proposes its preferred delay; the acceptor,
 * given the opener's, answers with the same one or refuses. A host with no
 * policy gets none, and the configured delay is used as for any channel.
 */
export function createAuxiliaryOpeningCsvPolicy(
	policy: IAuxiliaryOpeningCsvPolicy | undefined,
	configuredDelay: number,
	remoteDelay?: number
): IAuxiliaryOpeningCsvState | undefined {
	if (policy === undefined) return undefined;
	if (!policy || policy.mode !== 'symmetric' || !validDelay(configuredDelay))
		throw new Error('Invalid asset channel CSV opening policy');
	const minimumDelay = policy.minimumDelay ?? configuredDelay;
	const maximumDelay = policy.maximumDelay ?? 2016;
	const preferredDelay = policy.preferredDelay ?? minimumDelay;
	if (minimumDelay < configuredDelay)
		throw new Error(
			'Asset channel CSV policy cannot reduce configured protection'
		);
	try {
		copyAuxiliaryOpeningCsvPolicy({
			mode: 'symmetric',
			minimumDelay,
			maximumDelay,
			localDelay: preferredDelay
		});
	} catch {
		throw new Error('Invalid asset channel CSV opening policy');
	}
	const localDelay = remoteDelay ?? preferredDelay;
	if (
		!validDelay(localDelay) ||
		localDelay < minimumDelay ||
		localDelay > maximumDelay
	)
		throw new Error(
			`Asset channel CSV delay ${localDelay} is outside the permitted range ${minimumDelay}..${maximumDelay}`
		);
	return { mode: 'symmetric', minimumDelay, maximumDelay, localDelay };
}

/**
 * Why the delays of an asset opening break its policy, or undefined. The
 * delay this side advertised never changes once chosen, the peer's has to
 * be inside the permitted range, and the two have to be equal.
 */
export function auxiliaryCsvPolicyError(
	policy: IAuxiliaryOpeningCsvState | undefined,
	localDelay: number,
	remoteDelay: number
): string | undefined {
	if (!policy) return undefined;
	try {
		copyAuxiliaryOpeningCsvPolicy(policy);
	} catch {
		return 'Invalid persisted asset channel CSV policy';
	}
	if (localDelay !== policy.localDelay)
		return 'Asset channel advertised CSV delay changed';
	if (
		!validDelay(remoteDelay) ||
		remoteDelay < policy.minimumDelay ||
		remoteDelay > policy.maximumDelay
	)
		return `Asset channel CSV delay ${remoteDelay} is outside the permitted range ${policy.minimumDelay}..${policy.maximumDelay}`;
	if (localDelay !== remoteDelay)
		return `Asset channel requires symmetric CSV delays: local ${localDelay}, remote ${remoteDelay}; a new opening is required`;
	return undefined;
}
