/**
 * PaymentQueue: Priority queue for AI agent payment processing.
 * Capacity-aware dispatch, concurrency control, never crashes.
 * Supports optional persistent storage for crash recovery.
 *
 * The capacity check uses an entry's amountSats or, when that is absent, the
 * amount the owner decodes from its invoice through the invoiceAmountSats
 * option (issue #981). The queue itself never decodes an invoice.
 *
 * An entry is recorded 'failed' only on a verdict. A dispatch whose payment
 * is still out when the queue's own payment timeout fires (payInvoiceSafe
 * answers with the PENDING record: its HTLC can still settle) is not one:
 * the entry stays 'dispatching', its slot is released, and the
 * resolveInterrupted resolver records how the node's payment ended, exactly
 * as for an entry a restart interrupted (issue #976). Without a resolver
 * such an entry is recorded 'failed' with its outcome unknown, as a restored
 * in-flight entry is, never as a failure to send again.
 */

import { EventEmitter } from 'events';
import { BeignetError, BeignetErrorCode } from './errors';
import { QueuedPayment } from './types';

const SATS_MESSAGE = 'must be a whole number of satoshis, zero or greater';

/** A whole number of satoshis, zero or greater. */
function isWholeSats(value: unknown): value is number {
	return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Absent, or a whole number of satoshis, zero or greater. An explicit null
 * counts as absent, as it always has: generated clients send null for an
 * unset optional field.
 */
function optionalSats(value: unknown, field: string): number | undefined {
	if (value === undefined || value === null) return undefined;
	if (!isWholeSats(value)) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			`${field} ${SATS_MESSAGE}`
		);
	}
	return value;
}

/**
 * How a payment the queue was dispatching ended, as the node's own record
 * for its invoice tells it: one the process stopped during (issue #967), or
 * one still out at the queue's payment timeout (issue #976). 'completed':
 * the payment was made (its preimage is known), so it must never be sent
 * again. 'unpaid': every HTLC it offered is resolved and none paid, so
 * nothing was paid; a restored entry may then be sent again, and a timed-out
 * dispatch is recorded failed.
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
	 * stopped, before anything sends it again (issue #967), and a dispatch
	 * whose payment was still out when paymentTimeoutMs fired (issue #976).
	 * It resolves once the payment's outcome is final, which can take until
	 * its HTLCs expire. A rejection (or a throw) means the outcome is unknown
	 * right now, and the entry stays 'dispatching' for the next start to ask
	 * again. Without a resolver such an entry is recorded 'failed', outcome
	 * unknown: the queue cannot tell whether it was paid, and sending it
	 * again could pay twice.
	 */
	resolveInterrupted?: (bolt11: string) => Promise<InterruptedPaymentOutcome>;
	/**
	 * The amount, in whole satoshis, of the invoice an entry carries, for the
	 * capacity check of an entry enqueued without amountSats (issue #981).
	 * The owner decodes the invoice; the queue itself never does. Asked once
	 * per entry. A throw, or anything but a whole number of satoshis, counts
	 * as no amount: the entry then dispatches with no capacity check, as it
	 * did without this option, and an invoice that does not decode fails in
	 * payInvoiceSafe as before. Without this option such an entry is
	 * dispatched into "no route" and recorded 'failed' where one with
	 * amountSats would have waited for capacity.
	 */
	invoiceAmountSats?: (bolt11: string) => number | undefined;
}

/** Recorded on a restored in-flight entry when no resolver can settle it. */
export const INTERRUPTED_PAYMENT_ERROR =
	'Interrupted by a restart while dispatching; outcome unknown. Check the ' +
	'payment for this invoice before paying it again.';

/**
 * Recorded on a dispatch whose payment was still out at the queue's payment
 * timeout when no resolver can settle it (issue #976).
 */
export const IN_FLIGHT_PAYMENT_ERROR =
	'Dispatch timed out while its HTLC may still be in flight; outcome ' +
	'unknown. Check the payment for this invoice before paying it again.';

/**
 * Recorded on a dispatch whose payment was still out at the queue's payment
 * timeout once the resolver found that nothing was paid (issue #976).
 */
export const TIMED_OUT_PAYMENT_ERROR =
	'Payment failed after the dispatch timed out';

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
	private invoiceAmountSats?: PaymentQueueOptions['invoiceAmountSats'];
	/**
	 * What invoiceAmountSats answered for each entry, undefined included, so
	 * an invoice is decoded once rather than on every pass (issue #981).
	 */
	private invoiceAmounts = new WeakMap<QueuedPayment, number | undefined>();
	/**
	 * Restored entries that were 'dispatching' when the process stopped. They
	 * stay 'dispatching' until start() settles each against the node's record
	 * for its invoice (issue #967).
	 */
	private interrupted = new Set<string>();
	/**
	 * Entries restored from storage, including an interrupted one queued
	 * again as unpaid. Only start() releases them: an enqueue() before it
	 * dispatches its own entry, never these into channels that cannot carry
	 * them yet (issue #967).
	 */
	private restored = new Set<string>();

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
		this.invoiceAmountSats = options?.invoiceAmountSats;
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
					this.restored.add(row.id);

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
		if (!bolt11) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'bolt11 is required'
			);
		}
		if (!(priority >= 1 && priority <= 10)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'priority must be between 1 and 10'
			);
		}
		// A persisted amount the capacity check refuses would be refused again
		// at every start, so it is refused here, before it is stored (issue
		// #967).
		const amountSats = optionalSats(opts?.amountSats, 'amountSats');
		const maxFeeSats = optionalSats(opts?.maxFeeSats, 'maxFeeSats');

		const entry: QueuedPayment = {
			id: `q-${++this.idCounter}-${Date.now()}`,
			bolt11,
			priority,
			status: 'queued',
			amountSats,
			maxFeeSats,
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
	 * the next enqueue(). Until this runs, restored entries do not dispatch
	 * at all; entries enqueued since do. Runs once, and does nothing after
	 * stop().
	 */
	start(): void {
		if (this.stopped || this.started) return;
		this.started = true;
		const interrupted = this.queue.filter((e) => this.interrupted.has(e.id));
		this.interrupted.clear();
		for (const entry of interrupted) this.reconcileInterrupted(entry, 'queue');
		this.processQueue();
	}

	/**
	 * Look at the queue again because capacity may have appeared, such as a
	 * channel that can carry HTLCs again after a restart (issue #967). An
	 * entry held back by canSend otherwise waits for the next enqueue() or
	 * finished dispatch. Does nothing before start() or after stop().
	 */
	poke(): void {
		if (!this.started || this.stopped) return;
		this.processQueue();
	}

	/**
	 * Stop dispatching, for shutdown. Payments already dispatching still
	 * record how they ended; queued ones, including any enqueued after this,
	 * stay 'queued' in storage. The next start restores them, and they
	 * dispatch on its start(). Without this, a dispatch against the stopped
	 * node fails at once and persists 'failed', now that the database stays
	 * open while the wallet stops (issue #958). An in-flight entry the
	 * resolver has not settled yet, restored (issue #967) or timed out with
	 * its HTLC still out (issue #976), stays 'dispatching', for the next
	 * start to settle.
	 */
	stop(): void {
		this.stopped = true;
	}

	/**
	 * Settle one 'dispatching' entry through the resolver: a restored one
	 * the process stopped during (issue #967, onUnpaid 'queue'), or one
	 * whose payment was still out at the queue's payment timeout (issue
	 * #976, onUnpaid 'fail'). An outcome that arrives after stop() is still
	 * recorded, as dispatchPayment records one; a restored 'unpaid' entry is
	 * then left 'queued' for the next start.
	 */
	private reconcileInterrupted(
		entry: QueuedPayment,
		onUnpaid: 'queue' | 'fail'
	): void {
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
				(result) => this.recordInterruptedOutcome(entry, result, onUnpaid),
				() => {
					// Unknown right now: it stays 'dispatching' for the next start.
				}
			)
			.catch(() => {
				// A 'queue:completed' or 'queue:failed' listener threw. The
				// outcome is already recorded, and the throw must not become
				// an unhandled rejection.
			});
	}

	private recordInterruptedOutcome(
		entry: QueuedPayment,
		result: InterruptedPaymentOutcome | undefined,
		onUnpaid: 'queue' | 'fail'
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
		if (onUnpaid === 'fail') {
			// The dispatch had its turn and every HTLC it offered resolved
			// with none paid: that is its verdict. Not queued again: an entry
			// sent again on every timeout could loop for as long as the route
			// keeps failing late (issue #976).
			this.recordFailed(entry, new Error(TIMED_OUT_PAYMENT_ERROR));
			return;
		}
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

		// Reset however the pass ends: a throw that left it set would stop
		// every later pass, and so the queue, for good (issue #967).
		try {
			// Process all eligible entries
			while (this.activeCount < this.maxConcurrent) {
				// A restored entry waits for start() (issue #967).
				const next = this.queue.find(
					(e) =>
						e.status === 'queued' && (this.started || !this.restored.has(e.id))
				);
				if (!next) break;

				// Check capacity for the entry's amountSats or, when that is
				// absent, the amount its invoice carries (issue #981). Zero,
				// an amountless invoice or one the owner cannot decode, skips
				// the check, and the dispatch fails on its own if it must.
				const amountToCheck = next.amountSats ?? this.invoiceAmount(next) ?? 0;
				if (!isWholeSats(amountToCheck)) {
					// A row stored before enqueue() validated amounts (only
					// amountSats can be anything else here): the check refuses
					// it on every pass, so fail it rather than hold the rest
					// behind it.
					this.recordFailed(next, new Error(`amountSats ${SATS_MESSAGE}`));
					continue;
				}
				if (amountToCheck > 0) {
					let check: ReturnType<CanSendFn>;
					try {
						check = this.canSend(amountToCheck);
					} catch {
						// Any other refusal is temporary (no node yet, say):
						// treated as no capacity, and looked at again later.
						break;
					}
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
		} finally {
			this.processing = false;
		}
	}

	/**
	 * Record an entry as failed with the given error, persist it and emit
	 * queue:failed: a queued entry that can never be dispatched, or one the
	 * resolver found paid nothing after its dispatch timed out (issue #976).
	 */
	private recordFailed(entry: QueuedPayment, err: unknown): void {
		entry.status = 'failed';
		entry.error = err instanceof Error ? err.message : String(err);
		entry.completedAt = Date.now();
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
		this.emit('queue:failed', { id: entry.id, error: entry.error });
	}

	/**
	 * The amount the invoice of an entry without amountSats carries, from the
	 * owner's invoiceAmountSats (issue #981). Asked once per entry, whatever
	 * it answers: the invoice does not change, and the check runs on every
	 * pass. Undefined without the option, when it throws, or when it answers
	 * anything but a whole number of satoshis.
	 */
	private invoiceAmount(entry: QueuedPayment): number | undefined {
		if (!this.invoiceAmountSats) return undefined;
		if (this.invoiceAmounts.has(entry)) return this.invoiceAmounts.get(entry);
		let amount: number | undefined;
		try {
			const decoded = this.invoiceAmountSats(entry.bolt11);
			amount = isWholeSats(decoded) ? decoded : undefined;
		} catch {
			amount = undefined;
		}
		this.invoiceAmounts.set(entry, amount);
		return amount;
	}

	private async dispatchPayment(entry: QueuedPayment): Promise<void> {
		// Set when the payer answered PENDING and a resolver will settle the
		// entry: it stays 'dispatching' past the slot release below.
		let stillOut = false;
		try {
			const result = await this.payInvoiceSafe(
				entry.bolt11,
				this.paymentTimeoutMs,
				entry.maxFeeSats,
				entry.amountSats,
				entry.metadata
			);
			if (result.status === 'COMPLETED') {
				entry.status = 'completed';
				entry.completedAt = Date.now();
				this.emit('queue:completed', {
					id: entry.id,
					paymentHash: result.paymentHash
				});
			} else if (result.status === 'PENDING') {
				// The node still has the payment out: the queue's own attempt
				// timed out with an HTLC still offered, or the hash was already
				// in flight and payInvoiceSafe answered with that record. The
				// HTLC can settle after this, so 'failed' would be a verdict
				// the queue does not have, and one an agent acts on by paying
				// again (issue #976). With a resolver the entry stays
				// 'dispatching' and the node's outcome records it; without
				// one it is failed as unknown, like a restored in-flight row.
				if (this.resolveInterrupted) {
					stillOut = true;
				} else {
					entry.status = 'failed';
					entry.error = IN_FLIGHT_PAYMENT_ERROR;
					entry.completedAt = Date.now();
					this.emit('queue:failed', { id: entry.id, error: entry.error });
				}
			} else {
				entry.status = 'failed';
				entry.error = `Payment status: ${result.status}`;
				entry.completedAt = Date.now();
				this.emit('queue:failed', { id: entry.id, error: entry.error });
			}
		} catch (err: unknown) {
			entry.status = 'failed';
			entry.error = err instanceof Error ? err.message : String(err);
			entry.completedAt = Date.now();
			this.emit('queue:failed', { id: entry.id, error: entry.error });
		} finally {
			// The status this dispatch ended with, 'dispatching' included: an
			// entry still out is persisted as such for a restart to settle.
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
			// The slot goes once, here, whatever the outcome: an entry still
			// out holds none while the resolver waits (a stuck HTLC can last
			// until its expiry, and canSend already counts what it holds).
			this.activeCount--;
			// Process more items
			this.processQueue();
		}
		if (stillOut) this.reconcileInterrupted(entry, 'fail');
	}
}
