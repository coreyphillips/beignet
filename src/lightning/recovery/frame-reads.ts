/**
 * Bounded reads of the recovery frame store, shared by the journal, the
 * guardian replicator and rotation. Each prefers the backend's point
 * getters and falls back to a range load only on a backend that lacks them.
 * Not exported from the recovery barrel.
 */

import type {
	IStorageBackend,
	IStoredRecoveryFrame,
	IStoredRecoveryFrameHeader
} from '../storage/types';

/** The stored frame at exactly `sequence`, or null. */
export function storedFrameAt(
	storage: IStorageBackend,
	sequence: bigint
): IStoredRecoveryFrame | null {
	if (storage.loadRecoveryFrame) {
		return storage.loadRecoveryFrame(Number(sequence));
	}
	const [row] = storage.loadRecoveryFrames?.(Number(sequence) - 1) ?? [];
	return row && BigInt(row.sequence) === sequence ? row : null;
}

/** The cleartext columns of the stored frame at exactly `sequence`, or null. */
export function storedFrameHeaderAt(
	storage: IStorageBackend,
	sequence: bigint
): IStoredRecoveryFrameHeader | null {
	if (storage.loadRecoveryFrameHeader) {
		return storage.loadRecoveryFrameHeader(Number(sequence));
	}
	return storedFrameAt(storage, sequence);
}

/** Row count and sequence span of the frame store, null when empty. */
export function storedFrameSpan(storage: IStorageBackend): {
	count: number;
	minSequence: number;
	maxSequence: number;
} | null {
	const stats = storage.recoveryFrameStats?.();
	if (stats !== undefined) return stats;
	const rows = storage.loadRecoveryFrames?.() ?? [];
	if (rows.length === 0) return null;
	return {
		count: rows.length,
		minSequence: rows[0].sequence,
		maxSequence: rows[rows.length - 1].sequence
	};
}

/**
 * The sequence of the first stored frame after `sequence`, or null when
 * nothing is stored above it. Answered from the store's span, so it never
 * steps over a hole: inside the span it names `sequence + 1` whether or
 * not that frame exists, and a caller's point read then finds the gap
 * instead of silently resuming past it.
 */
export function firstStoredSequenceAfter(
	storage: IStorageBackend,
	sequence: bigint
): bigint | null {
	const span = storedFrameSpan(storage);
	if (!span || BigInt(span.maxSequence) <= sequence) return null;
	const min = BigInt(span.minSequence);
	return sequence < min ? min : sequence + 1n;
}
