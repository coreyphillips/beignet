/**
 * PaymentQueue: Priority queue for AI agent payment processing.
 * Capacity-aware dispatch, concurrency control, never crashes.
 * Supports optional persistent storage for crash recovery.
 */

import { EventEmitter } from 'events';
import { QueuedPayment } from './types';

/**
 * How a payment the queue was dispatching when the process stopped ended, as
 * the node's own record for its invoice tells it (issue #967). 'completed':
 * the payment was made (its preimage is known), so it must never be sent
 * again. 'unpaid': every HTLC it offered is resolved and none paid, so
 * nothing was paid and it may be sent again.
 */
export type InterruptedPaymentOutcome =
	| { status: 'completed'; paymentHash: string }
	| { status: 'unpaid' };

export interface PaymentQueueOptions {
	maxConcurrent?: number;
	/** Timeout per payment in ms (default 60000) */
	paymentTimeoutMs?: number;
	/**
	 * Settles a restored entry that was 'dispatching' when the process
	 * stopped, before anything sends it again (issue #967). It resolves once
	 * the payment's outcome is final, which can take until its HTLCs expire.
	 * A rejection (or a throw) means the outcome is unknown right now, and the
	 * entry stays 'dispatching' for the next start to ask again. Without a
	 * resolver such an entry is recorded 'failed' at restore: the queue
	 * cannot tell whether it was paid, and sending it again could pay twice.
	 */
	resolveInterrupted?: (bolt11: string) => Promise<InterruptedPaymentOutcome>;
}

/** Recorded on a restored in-flight entry when no resolver can settle it. */
export const INTERRUPTED_PAYMENT_ERROR =
	'Interrupted by a restart while dispatching; outcome unknown. Check the ' +
	'payment for this invoice before paying it again.';

export interface IPaymentQueueStorage {
	saveQueueEntry(entry: {
		id: string;
		bolt11: string;
		priority: number;
		status: string;
		amountSats?: number;
		maxFeeSats?: number;
		metadata?: string;
		createdAt: number;
	}): void;
	updateQueueEntryStatus(
		id: string,
		status: string,
		error?: string,
		completedAt?: number
	): void;
	deleteQueueEntry(id: string): void;
	loadAllQueueEntries(): Array<{
		id: string;
		bolt11: string;
		priority: number;
		status: string;
		amountSats?: number;
		maxFeeSats?: number;
		metadata?: string;
		error?: string;
		createdAt: number;
		completedAt?: number;
	}>;
}

type PayInvoiceSafeFn = (
	bolt11: string,
	timeoutMs?: number,
	maxFeeSats?: number,
	amountSats?: number,
	metadata?: Record<string, string>
) => Promise<{ status: string; paymentHash: string }>;
type CanSendFn = (amountSats: number) => {
	canSend: boolean;
	availableSats: number;
};

export class PaymentQueue extends EventEmitter {
	private queue: QueuedPayment[] = [];
	private activeCount = 0;
	private maxConcurrent: number;
	private paymentTimeoutMs: number;
	private payInvoiceSafe: PayInvoiceSafeFn;
	private canSend: CanSendFn;
	private processing = false;
	private stopped = false;
	private started = false;
	private idCounter = 0;
	private storage: IPaymentQueueStorage | null;
	private resolveInterrupted?: PaymentQueueOptions['resolveInterrupted'];
	/**
	 * Restored entries that were 'dispatching' when the process stopped. They
	 * stay 'dispatching' until start() settles each against the node's record
	 * for its invoice (issue #967).
	 */
	private interrupted = new Set<string>();

	constructor(
		payInvoiceSafe: PayInvoiceSafeFn,
		canSend: CanSendFn,
		options?: PaymentQueueOptions,
		storage?: IPaymentQueueStorage
	) {
		super();
		this.payInvoiceSafe = payInvoiceSafe;
		this.canSend = canSend;
		this.maxConcurrent = options?.maxConcurrent ?? 3;
		this.paymentTimeoutMs = options?.paymentTimeoutMs ?? 60_000;
		this.resolveInterrupted = options?.resolveInterrupted;
		this.storage = storage ?? null;

		// Restore persisted queue entries. Nothing dispatches here: start()
		// does, once the payer can pay (issue #967).
		if (this.storage) {
			try {
				for (const row of this.storage.loadAllQueueEntries()) {
					const entry: QueuedPayment = {
						id: row.id,
						bolt11: row.bolt11,
						priority: row.priority,
						status: row.status as QueuedPayment['status'],
						amountSats: row.amountSats,
						maxFeeSats: row.maxFeeSats,
						metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
						error: row.error,
						createdAt: row.createdAt,
						completedAt: row.completedAt
					};
					this.queue.push(entry);

					// A row still 'dispatching' was in flight when the process
					// stopped, and its payment may have been made. Sending it
					// again is not safe: the node refuses a second payment to the
					// same hash only while the first is pending, so one that
					// already completed would be paid twice (issue #967). It
					// stays 'dispatching' until start() has the resolver settle
					// it. With no resolver it is recorded 'failed', for the
					// operator to check.
					if (row.status === 'dispatching') {
						if (this.resolveInterrupted) {
							this.interrupted.add(row.id);
						} else {
							entry.status = 'failed';
							entry.error = INTERRUPTED_PAYMENT_ERROR;
							entry.completedAt = Date.now();
							try {
								this.storage.updateQueueEntryStatus(
									row.id,
									entry.status,
									entry.error,
									entry.completedAt
								);
							} catch {
								/* best-effort */
							}
						}
					}

					// Track max ID counter for new entries
					const idParts = row.id.match(/^q-(\d+)-/);
					if (idParts) {
						const num = parseInt(idParts[1], 10);
						if (num > this.idCounter) this.idCounter = num;
					}
				}
				// Re-sort by priority
				this.queue.sort((a, b) => a.priority - b.priority);
			} catch {
				// Storage failure should not prevent startup
			}
		}
	}

	/**
	 * Add a payment to the queue.
	 * @param bolt11 - BOLT 11 invoice
	 * @param priority - 1 (highest) to 10 (lowest), default 5
	 * @param opts - Optional amount, maxFee, metadata
	 * @returns The queued payment entry
	 */
	enqueue(
		bolt11: string,
		priority = 5,
		opts?: {
			amountSats?: number;
			maxFeeSats?: number;
			metadata?: Record<string, string>;
		}
	): QueuedPayment {
		if (!bolt11) throw new Error('bolt11 is required');
		if (priority < 1 || priority > 10)
			throw new Error('priority must be between 1 and 10');

		const entry: QueuedPayment = {
			id: `q-${++this.idCounter}-${Date.now()}`,
			bolt11,
			priority,
			status: 'queued',
			amountSats: opts?.amountSats,
			maxFeeSats: opts?.maxFeeSats,
			metadata: opts?.metadata,
			createdAt: Date.now()
		};
		this.queue.push(entry);
		// Sort by priority (lower number = higher priority)
		this.queue.sort((a, b) => a.priority - b.priority);

		// Persist to storage
		if (this.storage) {
			try {
				this.storage.saveQueueEntry({
					id: entry.id,
					bolt11: entry.bolt11,
					priority: entry.priority,
					status: entry.status,
					amountSats: entry.amountSats,
					maxFeeSats: entry.maxFeeSats,
					metadata: entry.metadata ? JSON.stringify(entry.metadata) : undefined,
					createdAt: entry.createdAt
				});
			} catch {
				// Best-effort — queue still works in-memory
			}
		}

		// Return a snapshot before processing to preserve 'queued' status
		const snapshot: QueuedPayment = { ...entry };

		// Try to process the queue
		this.processQueue();

		return snapshot;
	}

	/**
	 * Cancel a queued payment.
	 * @returns true if the payment was found and cancelled
	 */
	cancel(id: string): boolean {
		const entry = this.queue.find((e) => e.id === id);
		if (!entry) return false;
		if (entry.status !== 'queued') return false;
		entry.status = 'cancelled';
		this.queue = this.queue.filter((e) => e.id !== id);

		if (this.storage) {
			try {
				this.storage.updateQueueEntryStatus(id, 'cancelled');
			} catch {
				/* best-effort */
			}
		}

		return true;
	}

	/**
	 * List all items in the queue (including completed/failed for recent history).
	 */
	list(): QueuedPayment[] {
		return this.queue.map((e) => ({ ...e }));
	}

	/**
	 * Get the number of pending items.
	 */
	get pendingCount(): number {
		return this.queue.filter((e) => e.status === 'queued').length;
	}

	/**
	 * Get the number of active (dispatching) items.
	 */
	get activePayments(): number {
		return this.activeCount;
	}

	/**
	 * Clear completed/failed entries from the queue.
	 */
	prune(): number {
		const before = this.queue.length;
		const toRemove = this.queue.filter(
			(e) => e.status !== 'queued' && e.status !== 'dispatching'
		);
		this.queue = this.queue.filter(
			(e) => e.status === 'queued' || e.status === 'dispatching'
		);

		if (this.storage) {
			for (const entry of toRemove) {
				try {
					this.storage.deleteQueueEntry(entry.id);
				} catch {
					/* best-effort */
				}
			}
		}

		return before - this.queue.length;
	}

	/**
	 * Start dispatching what the constructor restored, once the payer can pay
	 * (issue #967). Each entry that was 'dispatching' when the process stopped
	 * is settled by the resolver first: a payment that was made is recorded
	 * 'completed' and never sent again, one that paid nothing is queued
	 * again, and one whose HTLCs are still out stays 'dispatching' until they
	 * resolve. Such an entry holds no concurrency slot while it waits (a
	 * stuck HTLC can last until its expiry, and canSend already counts what
	 * it holds), so the restored 'queued' entries dispatch now rather than on
	 * the next enqueue(). Runs once, and does nothing after stop().
	 */
	start(): void {
		if (this.stopped || this.started) return;
		this.started = true;
		const interrupted = this.queue.filter((e) => this.interrupted.has(e.id));
		this.interrupted.clear();
		for (const entry of interrupted) this.reconcileInterrupted(entry);
		this.processQueue();
	}

	/**
	 * Stop dispatching, for shutdown. Payments already dispatching still
	 * record how they ended; queued ones, including any enqueued after this,
	 * stay 'queued' in storage. The next start restores them, and they
	 * dispatch on its start(). Without this, a dispatch against the stopped
	 * node fails at once and persists 'failed', now that the database stays
	 * open while the wallet stops (issue #958). A restored in-flight entry
	 * the resolver has not settled yet stays 'dispatching', for the next
	 * start to settle (issue #967).
	 */
	stop(): void {
		this.stopped = true;
	}

	/**
	 * Settle one restored entry that was 'dispatching' when the process
	 * stopped (issue #967). An outcome that arrives after stop() is still
	 * recorded, as dispatchPayment records one; an 'unpaid' entry is then
	 * left 'queued' for the next start.
	 */
	private reconcileInterrupted(entry: QueuedPayment): void {
		const resolve = this.resolveInterrupted;
		if (!resolve) return;
		let outcome: Promise<InterruptedPaymentOutcome>;
		try {
			outcome = Promise.resolve(resolve(entry.bolt11));
		} catch {
			// Unknown right now: it stays 'dispatching' for the next start.
			return;
		}
		outcome
			.then(
				(result) => this.recordInterruptedOutcome(entry, result),
				() => {
					// Unknown right now: it stays 'dispatching' for the next start.
				}
			)
			.catch(() => {
				// A 'queue:completed' listener threw. The outcome is already
				// recorded, and the throw must not become an unhandled
				// rejection.
			});
	}

	private recordInterruptedOutcome(
		entry: QueuedPayment,
		result: InterruptedPaymentOutcome | undefined
	): void {
		if (entry.status !== 'dispatching') return;
		if (
			result?.status === 'completed' &&
			typeof result.paymentHash === 'string'
		) {
			entry.status = 'completed';
			entry.completedAt = Date.now();
			if (this.storage) {
				try {
					this.storage.updateQueueEntryStatus(
						entry.id,
						entry.status,
						undefined,
						entry.completedAt
					);
				} catch {
					/* best-effort */
				}
			}
			this.emit('queue:completed', {
				id: entry.id,
				paymentHash: result.paymentHash
			});
			return;
		}
		// Anything but a clear 'unpaid' is treated as unknown, never as leave
		// to send the payment again.
		if (result?.status !== 'unpaid') return;
		// Every HTLC it offered resolved and none paid, so nothing was paid:
		// it takes its turn again like any queued payment.
		entry.status = 'queued';
		if (this.storage) {
			try {
				this.storage.updateQueueEntryStatus(entry.id, entry.status);
			} catch {
				/* best-effort */
			}
		}
		this.processQueue();
	}

	private processQueue(): void {
		if (this.processing || this.stopped) return;
		this.processing = true;

		// Process all eligible entries
		while (this.activeCount < this.maxConcurrent) {
			const next = this.queue.find((e) => e.status === 'queued');
			if (!next) break;

			// Check capacity
			const amountToCheck = next.amountSats ?? 0;
			if (amountToCheck > 0) {
				const check = this.canSend(amountToCheck);
				if (!check.canSend) break; // No capacity, stop processing
			}

			next.status = 'dispatching';
			this.activeCount++;
			this.emit('queue:dispatched', { id: next.id, bolt11: next.bolt11 });

			if (this.storage) {
				try {
					this.storage.updateQueueEntryStatus(next.id, 'dispatching');
				} catch {
					/* best-effort */
				}
			}

			// Fire and forget -- will call back when done
			this.dispatchPayment(next).catch(() => {
				// Error already handled in dispatchPayment
			});
		}

		this.processing = false;
	}

	private async dispatchPayment(entry: QueuedPayment): Promise<void> {
		try {
			const result = await this.payInvoiceSafe(
				entry.bolt11,
				this.paymentTimeoutMs,
				entry.maxFeeSats,
				entry.amountSats,
				entry.metadata
			);
			entry.completedAt = Date.now();
			if (result.status === 'COMPLETED') {
				entry.status = 'completed';
				this.emit('queue:completed', {
					id: entry.id,
					paymentHash: result.paymentHash
				});
			} else {
				entry.status = 'failed';
				entry.error = `Payment status: ${result.status}`;
				this.emit('queue:failed', { id: entry.id, error: entry.error });
			}
		} catch (err: unknown) {
			entry.status = 'failed';
			entry.error = err instanceof Error ? err.message : String(err);
			entry.completedAt = Date.now();
			this.emit('queue:failed', { id: entry.id, error: entry.error });
		} finally {
			// Update storage with final status
			if (this.storage) {
				try {
					this.storage.updateQueueEntryStatus(
						entry.id,
						entry.status,
						entry.error,
						entry.completedAt
					);
				} catch {
					/* best-effort */
				}
			}
			this.activeCount--;
			// Process more items
			this.processQueue();
		}
	}
}
