/**
 * The quorum durability barrier (docs/RECOVERY-PROTOCOL.md 5.8, Phase 6).
 *
 * One question, asked at one place: may the wire messages authorized by
 * journal frame N leave this node yet?
 *
 * In `local` and `async-remote` the answer is always yes and the barrier is a
 * synchronous pass-through, which is the node's pre-Phase-6 conduct exactly.
 * In `quorum` the answer is yes once the replication watermark has reached N,
 * and until then the caller holds those messages. The guarantee that buys is
 * the whole reason the mode exists: once a peer has seen new channel state
 * from us, sufficient remote information already exists to restore it, so a
 * restored device resumes the channel instead of falling back to DLP.
 *
 * Three properties are load-bearing, and each one is a spec requirement
 * rather than an optimization:
 *
 * - RELEASE IS CUMULATIVE. A receipt for head S certifies every record from
 *   the chain origin through S, so one advance releases every waiter at or
 *   below it. There is no per-frame bookkeeping and no per-frame round trip.
 * - APPENDS NEVER WAIT. The barrier holds MESSAGES, never commits. Frames
 *   N+1, N+2 and beyond are journaled and handed to replication while N's
 *   receipt is still outstanding, and the receipt that eventually covers the
 *   newest of them releases all of them at once.
 * - A TIMEOUT FREEZES, IT DOES NOT PROCEED. Silence from the quorum is not
 *   permission. A barrier that times out reports a refusal and the caller
 *   withholds the message; nothing anywhere converts a timeout into a send.
 *
 * The barrier is also the only production driver of replication: it is what
 * turns a committed frame into a record on its way to the guardians, in every
 * mode, so `async-remote` gets its background replication from the same pump
 * that `quorum` waits on.
 */

import { GuardianState } from './guardian-wire';
import { GuardianReplicator } from './guardian-replication';
import { IWriterLeaseKeys } from './writer-lease';
import { RecoveryDurability } from './types';

/** Why a barrier let a message go, or refused to. */
export type BarrierOutcome =
	| {
			released: true;
			/** `not-required` in local and async-remote; `durable` in quorum. */
			reason: 'not-required' | 'durable';
	  }
	| {
			released: false;
			/**
			 * `timeout`: the quorum did not answer in time, so the message is
			 * withheld. `fenced`: another device provably owns this namespace, so
			 * the message must never go out at all. `stopped`: the node is
			 * shutting down. `missing-frame`: nothing named the frame that
			 * authorized this message, so there is no receipt that could ever
			 * release it. `backfill-lost`: compaction pruned frames the quorum
			 * never received, so the namespace can never advance again.
			 */
			reason:
				| 'timeout'
				| 'fenced'
				| 'stopped'
				| 'missing-frame'
				| 'backfill-lost';
	  };

export interface IDurabilityBarrierEvent {
	type:
		| 'barrier:durable'
		| 'barrier:waiting'
		| 'barrier:timeout'
		| 'barrier:fenced'
		| 'barrier:backfill-lost'
		| 'barrier:unreachable';
	detail: string;
	/** The frame sequence the event is about, where there is one. */
	sequence?: bigint;
	/** Waiters still held when the event fired. */
	waiting?: number;
}

export interface IDurabilityBarrierConfig {
	/** The mode in force. Only `quorum` ever holds a message. */
	durability: RecoveryDurability;
	replicator: GuardianReplicator;
	/**
	 * The lease records are signed under. A function rather than a value
	 * because ownership is established asynchronously at startup, and the
	 * barrier may be constructed before the lease exists. Returning null means
	 * ownership is unsettled, which is never a reason to release: a node that
	 * cannot prove it owns the namespace cannot prove anything is durable.
	 *
	 * ORDERING MATTERS when a GuardianStartupGate drives the wakeup. The gate
	 * invokes its open listeners SYNCHRONOUSLY inside `confirm`, before that
	 * promise resolves, so this closure has to be answering with the new lease
	 * BEFORE confirm is called. Install first, then confirm; the reverse order
	 * kicks a pump that still sees null and puts the gap straight back.
	 */
	lease: () => IWriterLeaseKeys | null;
	/**
	 * How long one message waits before the barrier gives up on it and the
	 * caller freezes. Default 30s, matching the guardian client's own request
	 * timeout closely enough that a barrier outlives a single stalled request.
	 */
	timeoutMs?: number;
	/** Gap between retry passes while waiters are outstanding. Default 1s. */
	retryDelayMs?: number;
	/**
	 * Has this namespace lost the ability to backfill its guardians?
	 *
	 * Defaults to the replicator's own reading of the journal metadata, so
	 * nothing has to be wired for it. Override only to test the refusal.
	 *
	 * A PREDICATE over the database rather than a push from the journal, and
	 * deliberately so: the database stays the single source of truth, a
	 * compaction that rolls back cannot brick a live barrier, a restart cannot
	 * forget one that committed, and nothing has to call into the barrier from
	 * inside an open storage transaction.
	 *
	 * What it buys is a NAMED refusal. Without it a dead namespace is
	 * indistinguishable from an unreachable quorum: every batch waits out the
	 * full timeout and reports one, forever.
	 */
	backfillLost?: () => boolean;
	onEvent?: (event: IDurabilityBarrierEvent) => void;
}

interface IWaiter {
	sequence: bigint;
	resolve: (outcome: BarrierOutcome) => void;
	timer: ReturnType<typeof setTimeout>;
	/** When the wait began, for the latency record. */
	startedAt: number;
}

/**
 * What the barrier has cost so far, for the status surface (issue #702).
 *
 * Only waits that actually PARKED a batch are counted: a frame already below
 * the watermark releases on the synchronous path and costs nothing. The
 * percentiles are over the most recent `sampled` released waits, so a node
 * that has run for a week reports the guardians it has now rather than the
 * ones it had on Monday. A refused wait (timeout, fence, stop) counts under
 * `refused` and contributes no sample, since its duration says how long the
 * timeout is, not how far the guardians are.
 */
export interface IBarrierLatency {
	/** Waits that parked a batch and were released by a receipt. */
	released: number;
	/** Waits that ended in a refusal. */
	refused: number;
	/** Released waits behind the percentiles below. */
	sampled: number;
	/** The most recent released wait. */
	lastMs: number | null;
	meanMs: number | null;
	p50Ms: number | null;
	p95Ms: number | null;
	maxMs: number | null;
}

const LATENCY_WINDOW = 256;

function percentile(sorted: number[], fraction: number): number {
	const index = Math.min(
		sorted.length - 1,
		Math.max(0, Math.ceil(sorted.length * fraction) - 1)
	);
	return sorted[index];
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY_DELAY_MS = 1_000;

export class DurabilityBarrier {
	private config: IDurabilityBarrierConfig;
	private readonly timeoutMs: number;
	private readonly retryDelayMs: number;

	/** Highest sequence a quorum has provably stored. Seeded from disk. */
	private durableThrough: bigint | null = null;
	private waiters: IWaiter[] = [];
	/** Released waits, most recent last, capped at LATENCY_WINDOW. */
	private samples: number[] = [];
	private releasedCount = 0;
	private refusedCount = 0;
	private lastWaitMs: number | null = null;
	/** A pass is running; further kicks coalesce into the pass after it. */
	private pumping = false;
	private kicked = false;
	private fenced = false;
	private supersededBy: GuardianState | undefined;
	/** Monotone, like the fact it mirrors: once lost, never regained. */
	private backfillLost = false;
	private stopped = false;
	private retryTimer: ReturnType<typeof setTimeout> | null = null;
	/** Resolves the pump's in-flight delay, so a stop does not strand it. */
	private wakeRetry: (() => void) | null = null;
	private fenceListeners: Array<(superseding?: GuardianState) => void> = [];
	private durableListeners: Array<(through: bigint) => void> = [];

	/**
	 * Point the barrier at another replicator (a rotation's incoming set,
	 * wire 5.9 step 4). The watermark it releases on is the new
	 * replicator's, which the switch made the journal's own.
	 */
	swapReplicator(next: GuardianReplicator): void {
		this.config = { ...this.config, replicator: next };
		this.durableThrough = next.replicatedThrough();
	}

	constructor(config: IDurabilityBarrierConfig) {
		this.config = config;
		this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		this.retryDelayMs = config.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
		// The watermark is read from disk and RELEASED on, so it has to be a
		// statement about frames this device can still produce. In quorum mode
		// a mark above the local tip is fatal and must NOT be clamped down:
		// clamping would release every frame under it as durable while
		// discarding the one piece of evidence that this device is behind what
		// its peers already saw, which is the data-loss case, not a repair.
		// Other modes only stand to lose replication progress, so they report
		// it and keep running.
		const stale = config.replicator.watermarkExceedingJournal();
		if (stale) {
			if (config.durability === 'quorum') {
				throw new Error(
					`recovery: ${stale}; a quorum writer cannot prove durability ` +
						'against a chain it does not hold, so restore this device from ' +
						'the guardian set or start a new recovery namespace'
				);
			}
			config.onEvent?.({ type: 'barrier:unreachable', detail: stale });
		}
	}

	/**
	 * Run `listener` when a proven supersession fences this writer. Fires
	 * BEFORE the held messages are refused, so the node's hard freeze (spec
	 * 5.6) has torn the transport down before anything could be released into
	 * it. Register during construction of whatever owns the barrier; a
	 * listener added after the fence still runs, immediately.
	 */
	onFenced(listener: (superseding?: GuardianState) => void): void {
		this.fenceListeners.push(listener);
		if (this.fenced) listener(this.supersededBy);
	}

	/**
	 * Run `listener` when the watermark advances. The journal hangs its
	 * deferred compaction off this: frames held back for a lagging replica
	 * become prunable exactly when that replica catches up.
	 */
	onDurableAdvance(listener: (through: bigint) => void): void {
		this.durableListeners.push(listener);
	}

	/** True when this mode holds messages at all. */
	get enforcing(): boolean {
		return this.config.durability === 'quorum';
	}

	/**
	 * This namespace can never advance again: compaction pruned frames the
	 * quorum never received, so every guardian behind that point refuses every
	 * later record with a sequence gap and no guardian can repair another from
	 * records none of them hold.
	 *
	 * Read through to storage until it turns true, then cached, because the
	 * fact it mirrors is itself set once and never cleared. The dispatch
	 * boundary reads this to refuse a NEW channel: opening one is the single
	 * irreversible step the barrier does not otherwise gate, since
	 * funding_created and channel_ready are not barrier-class. Closing is
	 * deliberately left working, in both forms: it is the only exit an operator
	 * has.
	 */
	get namespaceLost(): boolean {
		if (!this.backfillLost) {
			this.backfillLost =
				this.config.backfillLost?.() ??
				this.config.replicator.namespaceLostBackfill() !== null;
		}
		return this.backfillLost;
	}

	get durability(): RecoveryDurability {
		return this.config.durability;
	}

	/** The watermark, read through from storage the first time. */
	watermark(): bigint {
		if (this.durableThrough == null) {
			this.durableThrough = this.config.replicator.replicatedThrough();
		}
		return this.durableThrough;
	}

	/**
	 * The synchronous question the dispatch path asks first.
	 *
	 * Returning true here is what keeps the common case free: a batch whose
	 * frame is already durable, or a node not in quorum mode, dispatches
	 * inline with no promise, no deferral and no reordering risk. Only a batch
	 * that genuinely has to wait ever leaves the synchronous path.
	 */
	isReleased(sequence: bigint | null): boolean {
		if (!this.enforcing) return true;
		if (this.fenced || this.stopped) return false;
		// NO FRAME IS NOT PERMISSION. An unattributed transition names nothing
		// the guardians could have receipted, so no receipt can ever release
		// it and answering yes here would be a message going out on no
		// evidence at all. Quorum mode cannot even be configured without a
		// journal, so in production this is a caller that asked about a batch
		// with no PERSIST_STATE, which the dispatch boundary refuses outright.
		if (sequence == null) return false;
		return sequence <= this.watermark();
	}

	/**
	 * Wait for frame `sequence` to be durable.
	 *
	 * Resolves immediately when the barrier does not apply or the watermark is
	 * already past it. Otherwise the caller is parked and the replication pump
	 * is kicked; the wait ends when the watermark reaches the sequence, when
	 * the writer is fenced, or when the timeout expires and the message is
	 * refused.
	 */
	whenReleased(sequence: bigint | null): Promise<BarrierOutcome> {
		if (!this.enforcing) {
			return Promise.resolve({ released: true, reason: 'not-required' });
		}
		if (this.fenced) {
			return Promise.resolve({ released: false, reason: 'fenced' });
		}
		// Asked here rather than in isReleased, which is the per-batch hot path
		// and is already correct without it: the watermark simply can never
		// reach the sequence. This turns the resulting 30s stall into an
		// immediate, named refusal.
		if (this.noticeNamespaceLost()) {
			return Promise.resolve({ released: false, reason: 'backfill-lost' });
		}
		if (this.stopped) {
			return Promise.resolve({ released: false, reason: 'stopped' });
		}
		// Same rule as isReleased, and it has to be repeated here rather than
		// delegated: this is the path a caller reaches when it decided to wait,
		// and a wait on nothing must end in a refusal, never in a release.
		if (sequence == null) {
			return Promise.resolve({ released: false, reason: 'missing-frame' });
		}
		if (sequence <= this.watermark()) {
			return Promise.resolve({ released: true, reason: 'durable' });
		}
		return new Promise<BarrierOutcome>((resolve) => {
			const waiter: IWaiter = {
				sequence,
				resolve,
				startedAt: Date.now(),
				timer: setTimeout(() => {
					this.waiters = this.waiters.filter((entry) => entry !== waiter);
					this.refusedCount += 1;
					this.emit({
						type: 'barrier:timeout',
						detail:
							`frame ${sequence} did not reach the quorum within ` +
							`${this.timeoutMs}ms; the messages it authorized stay withheld`,
						sequence,
						waiting: this.waiters.length
					});
					resolve({ released: false, reason: 'timeout' });
				}, this.timeoutMs)
			};
			// Never hold the process open on a barrier alone; the node's own
			// lifecycle decides how long it runs.
			waiter.timer.unref?.();
			this.waiters.push(waiter);
			this.emit({
				type: 'barrier:waiting',
				detail: `holding messages behind frame ${sequence}`,
				sequence,
				waiting: this.waiters.length
			});
			this.kick();
		});
	}

	/**
	 * A frame was committed. Starts replication without waiting for it, which
	 * is what "appends are pipelined" means from this side: the commit path
	 * calls this and returns, and frames keep landing while earlier receipts
	 * are still outstanding.
	 */
	noteCommitted(): void {
		if (this.fenced || this.stopped) return;
		this.kick();
	}

	/**
	 * Ownership settled: start replicating whatever is already committed.
	 *
	 * The pump gives up when it finds no lease AND no waiter, because with
	 * nobody held there is nothing for a retry loop to rescue and spinning on
	 * an absent lease would burn a timer forever. That leaves one real gap: a
	 * frame committed BEFORE the lease existed, with no barrier waiter behind
	 * it (every async-remote commit, and any non-critical quorum commit made
	 * during startup), sits unreplicated until some later commit happens to
	 * kick the pump. Whoever installs the lease closes that gap by calling
	 * this; without it a quiet node can hold an unreplicated frame for as long
	 * as it stays quiet, which is exactly the window replication exists for.
	 */
	kickReplication(): void {
		if (this.fenced || this.stopped) return;
		this.kick();
	}

	/** Stop the pump and refuse every outstanding waiter. */
	stop(): void {
		if (this.stopped) return;
		this.stopped = true;
		this.cancelRetry();
		this.settleAll({ released: false, reason: 'stopped' });
	}

	/** Barrier state for the node's recovery status surface. */
	snapshot(): {
		durability: RecoveryDurability;
		durableThrough: bigint;
		waiting: number;
		fenced: boolean;
		backfillLost: boolean;
		latency: IBarrierLatency;
	} {
		return {
			durability: this.config.durability,
			durableThrough: this.watermark(),
			waiting: this.waiters.length,
			fenced: this.fenced,
			latency: this.latency(),
			// Beside `fenced`, never folded into it. They are different facts
			// with different remedies: a fence means another device owns this
			// namespace, and this means nobody can advance it again.
			backfillLost: this.namespaceLost
		};
	}

	/**
	 * What the barrier has cost so far (issue #702): the waits that parked
	 * a batch, how they ended, and the distribution of the released ones
	 * over the most recent LATENCY_WINDOW. This is the number the funds-only
	 * barrier question is to be decided on, measured on the node that would
	 * pay it rather than guessed.
	 */
	latency(): IBarrierLatency {
		const sorted = [...this.samples].sort((a, b) => a - b);
		const none = sorted.length === 0;
		return {
			released: this.releasedCount,
			refused: this.refusedCount,
			sampled: sorted.length,
			lastMs: this.lastWaitMs,
			meanMs: none
				? null
				: Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length),
			p50Ms: none ? null : percentile(sorted, 0.5),
			p95Ms: none ? null : percentile(sorted, 0.95),
			maxMs: none ? null : sorted[sorted.length - 1]
		};
	}

	// ─────────────── internals ───────────────

	private recordReleased(waitMs: number): void {
		this.releasedCount += 1;
		this.lastWaitMs = waitMs;
		this.samples.push(waitMs);
		if (this.samples.length > LATENCY_WINDOW) {
			this.samples.splice(0, this.samples.length - LATENCY_WINDOW);
		}
	}

	/** Clear a pending retry AND release the frame awaiting it. */
	private cancelRetry(): void {
		if (this.retryTimer) {
			clearTimeout(this.retryTimer);
			this.retryTimer = null;
		}
		const wake = this.wakeRetry;
		this.wakeRetry = null;
		if (wake) wake();
	}

	private emit(event: IDurabilityBarrierEvent): void {
		this.config.onEvent?.(event);
	}

	private settleAll(outcome: BarrierOutcome): void {
		const waiting = this.waiters;
		this.waiters = [];
		if (!outcome.released) this.refusedCount += waiting.length;
		for (const waiter of waiting) {
			clearTimeout(waiter.timer);
			waiter.resolve(outcome);
		}
	}

	/**
	 * Raise the watermark and release everything it covers.
	 *
	 * This is the cumulative-receipt rule in code: one advance to S resolves
	 * every waiter at or below S, however many frames and however many
	 * channels they came from.
	 */
	private advance(through: bigint): void {
		if (through <= this.watermark()) return;
		this.durableThrough = through;
		const released: IWaiter[] = [];
		const held: IWaiter[] = [];
		for (const waiter of this.waiters) {
			(waiter.sequence <= through ? released : held).push(waiter);
		}
		this.waiters = held;
		const now = Date.now();
		for (const waiter of released) {
			clearTimeout(waiter.timer);
			this.recordReleased(Math.max(0, now - waiter.startedAt));
			waiter.resolve({ released: true, reason: 'durable' });
		}
		this.emit({
			type: 'barrier:durable',
			detail: `records through ${through} are durable; released ${released.length} held batches`,
			sequence: through,
			waiting: held.length
		});
		for (const listener of this.durableListeners) {
			try {
				listener(through);
			} catch {
				// Observer only: a compaction retry must never fail a release.
			}
		}
	}

	/**
	 * Notice the loss and act on it: report it once, and refuse everything
	 * parked rather than leaving each waiter to run out its own timeout and
	 * report the wrong reason.
	 *
	 * Separate from the `namespaceLost` getter, which stays a plain
	 * observation, so that reading the operator status surface cannot settle a
	 * channel's held messages as a side effect of being asked a question.
	 */
	private noticeNamespaceLost(): boolean {
		const alreadyKnown = this.backfillLost;
		if (!this.namespaceLost) return false;
		if (alreadyKnown) return true;
		this.emit({
			type: 'barrier:backfill-lost',
			detail:
				'this recovery namespace lost its guardian backfill, so no further ' +
				'transition can ever be proven durable',
			waiting: this.waiters.length
		});
		this.cancelRetry();
		this.settleAll({ released: false, reason: 'backfill-lost' });
		return true;
	}

	/** Fence this writer for good; public so a rotation seen elsewhere (wire 5.9) can apply the same freeze. */
	fence(superseding?: GuardianState): void {
		if (this.fenced) return;
		this.fenced = true;
		this.supersededBy = superseding;
		this.cancelRetry();
		this.emit({
			type: 'barrier:fenced',
			detail:
				`another device provably owns this namespace` +
				(superseding ? ` at epoch ${superseding.lease.epoch}` : '') +
				'; every held message is refused permanently',
			waiting: this.waiters.length
		});
		// The node hard freezes BEFORE the waiters are told, so nothing can be
		// released into a transport that is still open.
		for (const listener of this.fenceListeners) {
			try {
				listener(superseding);
			} catch {
				// Observer only.
			}
		}
		this.settleAll({ released: false, reason: 'fenced' });
	}

	private kick(): void {
		if (this.fenced || this.stopped) return;
		if (this.pumping) {
			this.kicked = true;
			return;
		}
		void this.pump();
	}

	private async delay(ms: number): Promise<void> {
		await new Promise<void>((resolve) => {
			if (this.stopped) {
				resolve();
				return;
			}
			this.retryTimer = setTimeout(() => {
				this.retryTimer = null;
				this.wakeRetry = null;
				resolve();
			}, ms);
			this.retryTimer.unref?.();
			// stop() resolves through this rather than only clearing the timer:
			// clearTimeout alone leaves the awaiting async frame suspended
			// forever, retaining the whole barrier object graph.
			this.wakeRetry = resolve;
		});
	}

	/**
	 * Drive replication until nothing is waiting.
	 *
	 * One pass replicates EVERY pending frame, so a burst of commits and a
	 * queue of waiters share a single pass rather than each paying their own.
	 * Kicks that arrive during a pass coalesce into the next one.
	 */
	private async pump(): Promise<void> {
		this.pumping = true;
		try {
			do {
				this.kicked = false;
				// Checked once per pass so a waiter parked when compaction
				// killed the namespace is settled now, rather than sitting out
				// its full timeout and reporting the wrong reason.
				if (this.noticeNamespaceLost()) return;
				const lease = this.config.lease();
				if (!lease) {
					// Ownership is unsettled. Releasing here would be exactly the
					// unproven send the barrier exists to prevent, so waiters keep
					// waiting. But they must keep waiting on a RETRY rather than
					// on their own timeout: ownership settles asynchronously at
					// startup, often milliseconds later, and nothing else kicks
					// the pump when it does. Returning outright would freeze a
					// channel for the full timeout over a race with startup.
					this.emit({
						type: 'barrier:unreachable',
						detail:
							'no writer lease is held yet, so nothing can be proven durable',
						waiting: this.waiters.length
					});
					if (this.waiters.length === 0 && !this.kicked) return;
					await this.delay(this.retryDelayMs);
					continue;
				}
				try {
					const result = await this.config.replicator.replicatePending(lease);
					if (this.stopped) return;
					if (result.outcome === 'fenced') {
						this.fence(result.verifiedCurrentState);
						return;
					}
					this.advance(result.replicatedThrough);
					if (result.outcome === 'under-replicated') {
						this.emit({
							type: 'barrier:unreachable',
							detail: `the quorum is behind at ${result.replicatedThrough}`,
							sequence: result.replicatedThrough,
							waiting: this.waiters.length
						});
					}
				} catch (error) {
					if (this.stopped) return;
					this.emit({
						type: 'barrier:unreachable',
						detail: `replication pass failed: ${
							error instanceof Error ? error.message : String(error)
						}`,
						waiting: this.waiters.length
					});
				}
				if (this.waiters.length === 0) {
					if (!this.kicked) return;
					continue;
				}
				// Someone is still held. Retry rather than sit idle: their only
				// other exit is a timeout, which freezes a channel.
				await this.delay(this.retryDelayMs);
			} while (!this.stopped && !this.fenced);
		} finally {
			this.pumping = false;
		}
	}
}
