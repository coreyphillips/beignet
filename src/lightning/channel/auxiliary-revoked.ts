/**
 * The views of revoked commitments of an asset channel (issue #2093).
 *
 * To punish a revoked commitment whose outputs carry units, the node needs
 * the asset side of that commitment as it was signed: the leaf of each
 * output, and what the provider kept with it. A channel signs a commitment
 * for every round, so the views are not kept in the channel row. When the
 * view of a revoked commitment leaves the views the row holds, it is put
 * among `revokedCommitments`; the storage writes it to its store of revoked
 * views in the transaction that writes the row, and once that transaction
 * has committed the view leaves memory and later rows.
 *
 * A storage without such a store keeps every view in the row, which grows
 * with the life of the channel. A node restored from a recovery frame has
 * the views the frame held, which are the last few: of an older revoked
 * commitment it can punish the outputs without units and no other.
 */

import type { IAuxiliaryCommitmentData } from './auxiliary';
import type { IChannelState } from './channel-state';

/** Keep the view of a commitment of the peer that is now revoked. */
export function recordAuxiliaryRevokedView(
	state: IChannelState,
	commitmentNumber: bigint,
	view: IAuxiliaryCommitmentData
): void {
	if (!state.auxiliaryState) return;
	(state.auxiliaryState.revokedCommitments ??= new Map()).set(
		commitmentNumber,
		view
	);
}

/** The revoked views a write of this channel has to put in the store. */
export function auxiliaryRevokedViewsToStore(
	state: IChannelState
): ReadonlyMap<bigint, IAuxiliaryCommitmentData> | undefined {
	const views = state.auxiliaryState?.revokedCommitments;
	return views?.size ? views : undefined;
}

/**
 * Let go of the views a committed transaction put in the store. The view of
 * a revoked commitment that is on the chain stays.
 */
export function markAuxiliaryRevokedViewsStored(
	state: IChannelState,
	commitmentNumbers: Iterable<bigint>
): void {
	const auxiliary = state.auxiliaryState;
	if (!auxiliary?.revokedCommitments) return;
	for (const commitmentNumber of commitmentNumbers) {
		if (commitmentNumber === auxiliary.revokedCommitmentHeld) continue;
		auxiliary.revokedCommitments.delete(commitmentNumber);
	}
	if (auxiliary.revokedCommitments.size === 0) {
		delete auxiliary.revokedCommitments;
	}
}

/**
 * Hold the view of a revoked commitment that is on the chain, read back
 * from the store when it had left memory. False when the view is nowhere:
 * the outputs of that commitment that carry units cannot be punished.
 */
export function holdAuxiliaryRevokedView(
	state: IChannelState,
	commitmentNumber: bigint,
	load: () => IAuxiliaryCommitmentData | null | undefined
): boolean {
	const auxiliary = state.auxiliaryState;
	if (!auxiliary) return false;
	if (
		!auxiliary.revokedCommitments?.has(commitmentNumber) &&
		!auxiliary.remoteCommitments.has(commitmentNumber)
	) {
		const stored = load();
		if (!stored) return false;
		recordAuxiliaryRevokedView(state, commitmentNumber, stored);
	}
	auxiliary.revokedCommitmentHeld = commitmentNumber;
	return true;
}
