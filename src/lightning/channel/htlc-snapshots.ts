/**
 * Which revoked-commitment HTLC snapshots storage already holds.
 *
 * A channel keeps every snapshot in memory for the penalty resolver, but
 * storage keeps them in their own table and a journal frame carries only
 * the ones a save adds, so per-save cost does not grow with the channel's
 * history. A state with no entry here (decoded from a frame, or never
 * loaded from storage) counts its whole history as unsaved: writing it
 * upserts every snapshot, which is always correct, only slower. What is
 * saved holds for one store only, so a state written into another one
 * carries its whole history there.
 */

import { IChannelState } from './channel-state';
import { IHtlcSnapshotEntry } from './types';

const tracked = new WeakMap<
	IChannelState,
	{ storage: object; unsaved: Set<string> }
>();

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
	tracked.get(state)?.unsaved.add(commitmentNumber);
}

/**
 * The snapshots a save of this state into `storage` still has to write.
 * Asking for another store than the one tracked forgets the tracking, so
 * the journal frame of that save, which names no store, carries them all.
 */
export function unsavedRevokedHtlcSnapshots(
	state: IChannelState,
	storage?: object
): Map<string, IHtlcSnapshotEntry[]> | undefined {
	const history = state.revokedHtlcSnapshots;
	let entry = tracked.get(state);
	if (storage && entry && entry.storage !== storage) {
		tracked.delete(state);
		entry = undefined;
	}
	if (!history || !entry) return history;
	const delta = new Map<string, IHtlcSnapshotEntry[]>();
	for (const key of entry.unsaved) {
		const entries = history.get(key);
		if (entries) delta.set(key, entries);
	}
	return delta;
}

/** Note that `storage` holds these commitments' snapshots. */
export function markRevokedHtlcSnapshotsSaved(
	state: IChannelState,
	storage: object,
	saved: Iterable<string>
): void {
	let entry = tracked.get(state);
	if (entry?.storage !== storage) {
		entry = { storage, unsaved: new Set(state.revokedHtlcSnapshots?.keys()) };
		tracked.set(state, entry);
	}
	for (const key of saved) entry.unsaved.delete(key);
}
