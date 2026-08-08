/**
 * Composable storage transactions without nesting.
 *
 * IStorageBackend.transaction promises atomicity for ONE call; it does not
 * promise that transactions nest (the SQLite backend happens to tolerate
 * nesting via better-sqlite3 savepoints, but a conforming backend may
 * reject a BEGIN inside a BEGIN outright). Composed operations, e.g. a
 * capsule install whose reconstruction replays frames through
 * RecoveryManager.commit, therefore must SHARE one transaction rather than
 * open one per unit.
 *
 * This helper tracks, per backend instance, whether a transaction opened
 * through it is already active: the outermost call opens the real backend
 * transaction, and every call made inside it simply joins, so a throw
 * anywhere unwinds to the outermost frame and rolls the whole composition
 * back. Only transactions opened THROUGH this helper are visible to it; a
 * caller that opens a raw backend transaction and then calls into helper
 * users keeps the backend's own (unspecified) nesting behavior.
 */

import { IStorageBackend } from './types';

const activeTransactions = new WeakSet<IStorageBackend>();

export function withStorageTransaction<T>(
	storage: IStorageBackend,
	fn: () => T
): T {
	if (activeTransactions.has(storage)) {
		return fn();
	}
	activeTransactions.add(storage);
	try {
		return storage.transaction(fn);
	} finally {
		activeTransactions.delete(storage);
	}
}
