/**
 * Mission Control: Tracks payment success/failure history per channel
 * and provides penalty scores for pathfinding to avoid unreliable channels.
 */

export interface IMissionControlConfig {
	/** Base penalty in msat for a failed channel (default 100_000 = 100 sat) */
	failurePenaltyBaseMsat?: number;
	/** Half-life of penalty decay in ms (default 3_600_000 = 1 hour) */
	penaltyHalfLifeMs?: number;
	/** Maximum penalty in msat (default 10_000_000 = 10k sat) */
	maxPenaltyMsat?: number;
}

interface IChannelHistory {
	lastFailureTs: number;
	failureCount: number;
	successCount: number;
	/** Amount of the last failed payment in msat (for amount-aware penalties) */
	lastFailureAmountMsat?: number;
}

export class MissionControl {
	private penalties: Map<string, IChannelHistory> = new Map();
	private failurePenaltyBaseMsat: number;
	private penaltyHalfLifeMs: number;
	private maxPenaltyMsat: number;

	constructor(config?: IMissionControlConfig) {
		this.failurePenaltyBaseMsat = config?.failurePenaltyBaseMsat ?? 100_000;
		this.penaltyHalfLifeMs = config?.penaltyHalfLifeMs ?? 3_600_000;
		this.maxPenaltyMsat = config?.maxPenaltyMsat ?? 10_000_000;
	}

	recordFailure(scidHex: string, amountMsat?: bigint): void {
		const existing = this.penalties.get(scidHex);
		if (existing) {
			existing.failureCount++;
			existing.lastFailureTs = Date.now();
			if (amountMsat !== undefined) {
				existing.lastFailureAmountMsat = Number(amountMsat);
			}
		} else {
			this.penalties.set(scidHex, {
				lastFailureTs: Date.now(),
				failureCount: 1,
				successCount: 0,
				lastFailureAmountMsat:
					amountMsat !== undefined ? Number(amountMsat) : undefined
			});
		}
	}

	recordSuccess(scidHex: string): void {
		const existing = this.penalties.get(scidHex);
		if (existing) {
			existing.successCount++;
		} else {
			this.penalties.set(scidHex, {
				lastFailureTs: 0,
				failureCount: 0,
				successCount: 1
			});
		}
	}

	/**
	 * Get the penalty for a channel in msat.
	 * Penalty = base * failureCount * 2^(-age/halfLife)
	 * Reduced by success count (each success halves effective failure count).
	 *
	 * If currentAmountMsat is provided and is significantly smaller than the
	 * last failure amount, the penalty is scaled down (amount-aware routing).
	 */
	getPenalty(scidHex: string, currentAmountMsat?: bigint): bigint {
		const history = this.penalties.get(scidHex);
		if (!history || history.failureCount === 0) return 0n;

		const age = Date.now() - history.lastFailureTs;
		const decayFactor = Math.pow(2, -age / this.penaltyHalfLifeMs);

		// Effective failures reduced by successes
		const effectiveFailures = Math.max(
			0,
			history.failureCount - history.successCount / 2
		);
		if (effectiveFailures <= 0) return 0n;

		let penalty = this.failurePenaltyBaseMsat * effectiveFailures * decayFactor;

		// Amount-aware scaling: if current amount is much smaller than failure amount,
		// reduce the penalty (a channel that failed 1M sats may still work for 1K sats)
		if (
			currentAmountMsat !== undefined &&
			history.lastFailureAmountMsat !== undefined &&
			history.lastFailureAmountMsat > 0
		) {
			const ratio = Number(currentAmountMsat) / history.lastFailureAmountMsat;
			if (ratio < 1) {
				// Scale penalty by ratio (e.g., trying 1/10 the amount → 1/10 the penalty)
				penalty *= ratio;
			}
		}

		const capped = Math.min(penalty, this.maxPenaltyMsat);

		return BigInt(Math.floor(capped));
	}

	/**
	 * Prune stale entries: remove entries whose penalty has decayed below
	 * a threshold and channels with no recent activity.
	 * Returns number of entries pruned.
	 */
	prune(thresholdMsat = 1): number {
		let pruned = 0;
		for (const [scid, history] of this.penalties) {
			// Purely successful entries with no failures
			if (history.failureCount === 0) {
				this.penalties.delete(scid);
				pruned++;
				continue;
			}
			// Decayed penalty below threshold
			const penalty = this.getPenalty(scid);
			if (penalty <= BigInt(thresholdMsat)) {
				this.penalties.delete(scid);
				pruned++;
			}
		}
		return pruned;
	}

	/**
	 * Reset all penalty history.
	 */
	clear(): void {
		this.penalties.clear();
	}

	/**
	 * Get the number of tracked channels.
	 */
	get size(): number {
		return this.penalties.size;
	}

	/**
	 * Export penalty data as a JSON string for persistence.
	 */
	export(): string {
		const data: Array<{
			scid: string;
			lastFailureTs: number;
			failureCount: number;
			successCount: number;
			lastFailureAmountMsat?: number;
		}> = [];
		for (const [scid, history] of this.penalties) {
			data.push({ scid, ...history });
		}
		return JSON.stringify(data);
	}

	/**
	 * Import penalty data from a JSON string (previously exported).
	 */
	import(json: string): void {
		let data: unknown;
		try {
			data = JSON.parse(json);
		} catch {
			return; // Invalid JSON — skip silently
		}
		if (!Array.isArray(data)) return;
		for (const entry of data) {
			if (
				entry &&
				typeof entry === 'object' &&
				typeof (entry as Record<string, unknown>).scid === 'string' &&
				typeof (entry as Record<string, unknown>).lastFailureTs === 'number' &&
				typeof (entry as Record<string, unknown>).failureCount === 'number' &&
				typeof (entry as Record<string, unknown>).successCount === 'number'
			) {
				const e = entry as {
					scid: string;
					lastFailureTs: number;
					failureCount: number;
					successCount: number;
					lastFailureAmountMsat?: number;
				};
				this.penalties.set(e.scid, {
					lastFailureTs: e.lastFailureTs,
					failureCount: e.failureCount,
					successCount: e.successCount,
					lastFailureAmountMsat:
						typeof e.lastFailureAmountMsat === 'number'
							? e.lastFailureAmountMsat
							: undefined
				});
			}
			// Skip invalid entries
		}
	}
}
