/**
 * PaymentQueue: Priority queue for AI agent payment processing.
 * Capacity-aware dispatch, concurrency control, never crashes.
 * Supports optional persistent storage for crash recovery.
 */

import { EventEmitter } from 'events';
import { QueuedPayment } from './types';

export interface PaymentQueueOptions {
	maxConcurrent?: number;
	/** Timeout per payment in ms (default 60000) */
	paymentTimeoutMs?: number;
}

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
	private idCounter = 0;
	private storage: IPaymentQueueStorage | null;

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
		this.storage = storage ?? null;

		// Restore persisted queue entries
		if (this.storage) {
			try {
				for (const row of this.storage.loadAllQueueEntries()) {
					const restoredStatus =
						row.status === 'dispatching' ? 'queued' : row.status;
					const entry: QueuedPayment = {
						id: row.id,
						bolt11: row.bolt11,
						priority: row.priority,
						status: restoredStatus as QueuedPayment['status'],
						amountSats: row.amountSats,
						maxFeeSats: row.maxFeeSats,
						metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
						error: row.error,
						createdAt: row.createdAt,
						completedAt: row.completedAt
					};
					this.queue.push(entry);

					// Reset dispatching→queued in storage
					if (row.status === 'dispatching') {
						try {
							this.storage.updateQueueEntryStatus(row.id, 'queued');
						} catch {
							/* best-effort */
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

	private processQueue(): void {
		if (this.processing) return;
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
