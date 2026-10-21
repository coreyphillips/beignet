/**
 * Which revoked-commitment HTLC snapshots storage already holds.
 *
 * A channel keeps every snapshot in memory for the penalty resolver, but
 * storage keeps them in their own table and a journal frame carries only
 * the ones a save adds, so per-save cost does not grow with the channel's
 * history. A state with no entry here (decoded from a frame, or never
 * loaded from storage) counts its whole history as unsaved: writing it
 * upserts every snapshot, which is always correct, only slower.
 */

import { IChannelState } from './channel-state';
import { IHtlcSnapshotEntry } from './types';

const unsavedSnapshots = new WeakMap<IChannelState, Set<string>>();

/**
 * Record the HTLCs of a remote commitment we signed. An empty set is not
 * kept: the resolver reads a missing snapshot and an empty one the same way.
 */
export function recordRevokedHtlcSnapshot(
	state: IChannelState,
	commitmentNumber: string,
	entries: IHtlcSnapshotEntry[]
): void {
	if (entries.length === 0) return;
	(state.revokedHtlcSnapshots ??= new Map()).set(commitmentNumber, entries);
	unsavedSnapshots.get(state)?.add(commitmentNumber);
}

/** The snapshots a save of this state still has to write. */
export function unsavedRevokedHtlcSnapshots(
	state: IChannelState
): Map<string, IHtlcSnapshotEntry[]> | undefined {
	const history = state.revokedHtlcSnapshots;
	const unsaved = unsavedSnapshots.get(state);
	if (!history || !unsaved) return history;
	const delta = new Map<string, IHtlcSnapshotEntry[]>();
	for (const key of unsaved) {
		const entries = history.get(key);
		if (entries) delta.set(key, entries);
	}
	return delta;
}

/** Note that storage holds these commitments' snapshots. */
export function markRevokedHtlcSnapshotsSaved(
	state: IChannelState,
	saved: Iterable<string>
): void {
	let unsaved = unsavedSnapshots.get(state);
	if (!unsaved) {
		unsaved = new Set(state.revokedHtlcSnapshots?.keys());
		unsavedSnapshots.set(state, unsaved);
	}
	for (const key of saved) unsaved.delete(key);
}
