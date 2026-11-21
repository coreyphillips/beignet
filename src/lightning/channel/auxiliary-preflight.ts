/**
 * Asset channels (issue #2093): ask the provider about the commitment an
 * update would have this node sign, before the update is made.
 *
 * An update goes on the wire before the commitment that carries it. If the
 * provider then cannot answer for that commitment, the peer holds an update
 * this node can never sign for. So each update this node originates is first
 * tried on a copy of the state, the way localCommitmentEmptyRefusal tries
 * one: the copy takes the update, the peer's next commitment is built from
 * it, and the provider is asked. A refusal leaves nothing behind. The
 * answer is kept (see applyAuxiliaryCommitment), so the signature that
 * follows for the same commitment does not ask again.
 */

import type { IChannelState } from './channel-state';
import type { IHtlcEntry } from './types';
import { buildRemoteCommitment } from './commitment-builder';
import type { AuxiliaryProviderError } from './auxiliary';
import { auxiliaryProviderError } from './auxiliary';

/** What an update changes, as far as a commitment is built from it. */
export interface IAuxiliaryRoundUpdate {
	localBalanceMsat?: bigint;
	remoteBalanceMsat?: bigint;
	/** A local update_fee, staged the way updateFee stages it. */
	pendingFeeratePerKw?: number;
	/** An HTLC added, or an existing one as the update leaves it. */
	htlc?: { key: string; entry: IHtlcEntry };
	/**
	 * Several existing HTLCs as one round leaves them (issue #2098, step 8:
	 * the parts of an asset set fulfilled together), after `htlc`.
	 */
	htlcs?: ReadonlyArray<{ key: string; entry: IHtlcEntry }>;
	/** The asset balances after the update, where it moves them. */
	auxiliaryBalances?: { local: bigint; remote: bigint };
}

/**
 * The refusal of `operation` on an asset channel whose provider cannot
 * answer for the commitment the update leads to, or undefined when it can,
 * or for a channel without asset state, which is not looked at.
 */
export function auxiliaryRoundRefusal(
	state: Readonly<IChannelState>,
	operation: string,
	update: IAuxiliaryRoundUpdate
): AuxiliaryProviderError | undefined {
	if (!state.auxiliaryState) return undefined;
	const candidate: IChannelState = { ...state };
	if (update.localBalanceMsat !== undefined) {
		candidate.localBalanceMsat = update.localBalanceMsat;
	}
	if (update.remoteBalanceMsat !== undefined) {
		candidate.remoteBalanceMsat = update.remoteBalanceMsat;
	}
	if (update.pendingFeeratePerKw !== undefined) {
		candidate.pendingFeeratePerKw = update.pendingFeeratePerKw;
		candidate.pendingFeerateSignable = false;
		candidate.pendingFeerateCommitted = false;
	}
	if (update.htlc || update.htlcs?.length) {
		candidate.htlcs = new Map(state.htlcs);
		if (update.htlc) candidate.htlcs.set(update.htlc.key, update.htlc.entry);
		for (const htlc of update.htlcs ?? []) {
			candidate.htlcs.set(htlc.key, htlc.entry);
		}
	}
	if (update.auxiliaryBalances) {
		candidate.auxiliaryState = {
			...state.auxiliaryState,
			localBalance: update.auxiliaryBalances.local,
			remoteBalance: update.auxiliaryBalances.remote
		};
	}
	const point =
		candidate.remoteNextPerCommitmentPoint ??
		candidate.remoteCurrentPerCommitmentPoint;
	try {
		if (!point) throw new Error('no peer commitment point');
		buildRemoteCommitment(
			candidate,
			point,
			candidate.remoteCommitmentNumber + 1n
		);
	} catch (err) {
		return auxiliaryProviderError(state, operation, err);
	}
	return undefined;
}
