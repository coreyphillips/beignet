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
 *
 * Queued and dispatching entries are held apart from finished ones (issue
 * #1866): a pass reads the next queued entry from the front of its own list,
 * and memory keeps only the most recently finished entries, up to
 * maxRetainedHistory. Storage keeps every entry until prune(), and get() and
 * history() read the ones memory no longer holds.
 */

import { EventEmitter } from 'events';
import { BeignetError, BeignetErrorCode } from './errors';
import type { QueuedPayment } from './types';

const SATS_MESSAGE = 'must be a whole number of satoshis, zero or greater';

/** The default for PaymentQueueOptions.maxRetainedHistory. */
const DEFAULT_RETAINED_HISTORY = 1000;
/** The page size history() uses without a limit, and the most it returns. */
const DEFAULT_HISTORY_PAGE = 100;
const MAX_HISTORY_PAGE = 1000;

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
	 * right now, and the entry stays 'dispatching' for start(), resettle() or
	 * the next process start to ask again. Without a resolver such an entry
	 * is recorded 'failed', outcome
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
	/**
	 * How many finished entries (completed, failed, or cancelled in an
	 * earlier process) list() keeps: the most recently finished, 1000 by
	 * default. Infinity keeps every one, as before issue #1866. An older entry
	 * leaves memory only: storage still holds it, get() and history() still
	 * read it, and only prune() deletes it. Queued and dispatching entries
	 * are never counted against this or dropped, however many there are.
	 * Without storage, where a dropped entry is gone, an entry whose outcome
	 * is unknown stays past this limit too, until prune().
	 */
	maxRetainedHistory?: number;
}

/** Recorded on a restored in-flight entry when no resolver can settle it. */
export const INTERRUPTED_PAYMENT_ERROR =
	'Interrupted by a restart while dispatching; outcome unknown. Check the ' +
	'payment for this invoice before paying it again.';

/**
 * Recorded on a dispatch that ended with the payment still pending (its own
 * timeout with an HTLC out, or a refusal for a hash already in flight) when
 * no resolver can settle it (issue #976).
 */
export const IN_FLIGHT_PAYMENT_ERROR =
	'Dispatch ended with the payment still pending and no resolver to settle ' +
	'it; outcome unknown. Check the payment for this invoice before paying ' +
	'it again.';

/**
 * Recorded on a dispatch that ended with the payment still pending once the
 * resolver found that nothing was paid (issue #976).
 */
export const TIMED_OUT_PAYMENT_ERROR =
	'Payment was left pending by the dispatch and then failed without paying';

/** A payment queue entry as storage holds it. */
export interface PaymentQueueRow {
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
	loadAllQueueEntries(): PaymentQueueRow[];
	/**
	 * The rows still 'queued' or 'dispatching'. With loadQueueHistory, a
	 * start reads only these and the history it keeps; without them it reads
	 * every row (issue #1866).
	 */
	loadActiveQueueEntries?(): PaymentQueueRow[];
	/**
	 * Up to limit finished rows (any status but 'queued' and 'dispatching'),
	 * the most recently finished first: by completedAt, or createdAt for a
	 * row without one, then by id, both descending. With before, the rows
	 * after that finished row in this order, and none when no finished row
	 * has that id. Without it, history() sorts loadAllQueueEntries().
	 */
	loadQueueHistory?(limit: number, before?: string): PaymentQueueRow[];
	/** The row with this id. Without it, get() searches loadAllQueueEntries(). */
	loadQueueEntry?(id: string): PaymentQueueRow | undefined;
}

function isActiveStatus(status: string): boolean {
	return status === 'queued' || status === 'dispatching';
}

/** history() order: the most recently finished first, as loadQueueHistory. */
function newestFinishedFirst(
	a: { id: string; createdAt: number; completedAt?: number },
	b: { id: string; createdAt: number; completedAt?: number }
): number {
	const at = (b.completedAt ?? b.createdAt) - (a.completedAt ?? a.createdAt);
	if (at !== 0) return at;
	return a.id < b.id ? 1 : a.id > b.id ? -1 : 0;
}

/** The page of sorted history after the entry with id before. */
function historyPage<T extends { id: string }>(
	sorted: T[],
	limit: number,
	before?: string
): T[] {
	if (before === undefined) return sorted.slice(0, limit);
	const at = sorted.findIndex((e) => e.id === before);
	return at < 0 ? [] : sorted.slice(at + 1, at + 1 + limit);
}

/** The counter in an id enqueue() made, 0 for any other id. */
function idCounterOf(id: string): number {
	const parts = id.match(/^q-(\d+)-/);
	return parts ? parseInt(parts[1], 10) : 0;
}

function entryFromRow(row: PaymentQueueRow): QueuedPayment {
	return {
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
}

/**
 * A failed entry the queue could not settle: its payment may have been
 * made, and nothing but this record says to check before paying again.
 */
function isOutcomeUnknown(entry: QueuedPayment): boolean {
	return (
		entry.status === 'failed' &&
		(entry.error === INTERRUPTED_PAYMENT_ERROR ||
			entry.error === IN_FLIGHT_PAYMENT_ERROR)
	);
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
	/**
	 * Queued and dispatching entries, by id. None is ever dropped to bound
	 * memory: each may yet be sent, or is still out.
	 */
	private active = new Map<string, QueuedPayment>();
	/**
	 * The queued entries of active in dispatch order (priority, then the
	 * order they were queued in), so a pass reads the next one from the front
	 * rather than searching past finished ones (issue #1866).
	 */
	private pending: QueuedPayment[] = [];
	/** Finished entries list() shows, oldest finished first. */
	private finished = new Map<string, QueuedPayment>();
	/**
	 * Finished entries whose outcome is unknown, in a queue without storage
	 * or one whose storage may not hold their outcome. They are the only
	 * record that the payment needs checking before it is paid again, so
	 * maxRetainedHistory does not drop them; prune() does.
	 */
	private unknownOutcomes = new Map<string, QueuedPayment>();
	/**
	 * Entries a storage write threw for. An update of a row that was never
	 * saved does not throw, so a failed save counts too.
	 */
	private unstored = new WeakSet<QueuedPayment>();
	/** Where each entry falls among those of its priority in list() order. */
	private sequence = new WeakMap<QueuedPayment, number>();
	private nextSequence = 0;
	private maxRetainedHistory: number;
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
	 * Entries restored from storage still queued or dispatching. Only start()
	 * releases them: an enqueue() before it dispatches its own entry, never
	 * these into channels that cannot carry them yet (issue #967).
	 */
	private restored = new Set<string>();
	/**
	 * Entries awaiting an outcome whose last ask of the resolver was refused
	 * (no node to ask yet), with the verdict an 'unpaid' answer gets. start()
	 * and resettle() ask again; nothing else does in this process (issue
	 * #976).
	 */
	private awaitingOutcome = new Map<QueuedPayment, 'queue' | 'fail'>();

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
		const retained = options?.maxRetainedHistory ?? DEFAULT_RETAINED_HISTORY;
		if (
			retained !== Infinity &&
			!(Number.isSafeInteger(retained) && retained >= 0)
		) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'maxRetainedHistory must be a whole number, zero or greater, or Infinity'
			);
		}
		this.maxRetainedHistory = retained;

		// Restore persisted queue entries. Nothing dispatches here: start()
		// does, once the payer can pay (issue #967).
		if (this.storage) {
			try {
				const entries: QueuedPayment[] = [];
				for (const row of this.restoredRows(this.storage)) {
					try {
						entries.push(entryFromRow(row));
					} catch {
						// Metadata that does not parse: the row stays in
						// storage, and the rest are restored.
					}
				}
				// The id's counter settles a tie in enqueue order: history
				// arrives most recently finished first.
				entries.sort(
					(a, b) =>
						a.priority - b.priority ||
						a.createdAt - b.createdAt ||
						idCounterOf(a.id) - idCounterOf(b.id)
				);
				const finished: QueuedPayment[] = [];
				for (const entry of entries) {
					this.sequence.set(entry, this.nextSequence++);
					if (entry.status === 'queued') {
						this.active.set(entry.id, entry);
						this.pending.push(entry);
						this.restored.add(entry.id);
					} else if (entry.status === 'dispatching') {
						// A row still 'dispatching' was in flight when the
						// process stopped, and its payment may have been made.
						// Sending it again is not safe: the node refuses a
						// second payment to the same hash only while the first
						// is pending, so one that already completed would be
						// paid twice (issue #967). It stays 'dispatching' until
						// start() has the resolver settle it. With no resolver
						// it is recorded 'failed', for the operator to check.
						if (this.resolveInterrupted) {
							this.active.set(entry.id, entry);
							this.restored.add(entry.id);
							this.interrupted.add(entry.id);
						} else {
							entry.status = 'failed';
							entry.error = INTERRUPTED_PAYMENT_ERROR;
							entry.completedAt = Date.now();
							try {
								this.storage.updateQueueEntryStatus(
									entry.id,
									entry.status,
									entry.error,
									entry.completedAt
								);
							} catch {
								this.unstored.add(entry);
							}
							finished.push(entry);
						}
					} else {
						finished.push(entry);
					}

					// Track max ID counter for new entries
					this.idCounter = Math.max(this.idCounter, idCounterOf(entry.id));
				}
				finished.sort((a, b) => newestFinishedFirst(b, a));
				for (const entry of finished) this.retire(entry);
			} catch {
				// Storage failure should not prevent startup
			}
		}
	}

	/**
	 * The rows a start restores: every queued and dispatching one, and the
	 * most recently finished up to maxRetainedHistory. Older finished rows
	 * stay in storage, unread (issue #1866).
	 */
	private restoredRows(storage: IPaymentQueueStorage): PaymentQueueRow[] {
		const keep = this.maxRetainedHistory;
		if (storage.loadActiveQueueEntries && storage.loadQueueHistory) {
			const active = storage.loadActiveQueueEntries();
			if (keep === 0) return active;
			return [
				...active,
				...storage.loadQueueHistory(Math.min(keep, Number.MAX_SAFE_INTEGER))
			];
		}
		const rows = storage.loadAllQueueEntries();
		return [
			...rows.filter((row) => isActiveStatus(row.status)),
			...rows
				.filter((row) => !isActiveStatus(row.status))
				.sort(newestFinishedFirst)
				.slice(0, keep)
		];
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
		this.sequence.set(entry, this.nextSequence++);
		this.active.set(entry.id, entry);
		this.addPending(entry);

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
				this.unstored.add(entry);
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
		const entry = this.active.get(id);
		if (!entry) return false;
		if (entry.status !== 'queued') return false;
		entry.status = 'cancelled';
		this.active.delete(id);
		const at = this.pending.indexOf(entry);
		if (at >= 0) this.pending.splice(at, 1);

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
	 * Every queued and dispatching entry, with the most recently finished
	 * ones (up to maxRetainedHistory), by priority and then in the order they
	 * were queued. history() pages through every finished entry storage
	 * holds, and get() finds any one by id.
	 */
	list(): QueuedPayment[] {
		return [
			...this.active.values(),
			...this.finished.values(),
			...this.unknownOutcomes.values()
		]
			.sort(this.inListOrder)
			.map((e) => ({ ...e }));
	}

	/**
	 * The entry with this id, whatever its status: from memory, else from
	 * storage, so an entry list() no longer holds is still found (issue
	 * #1866). Undefined when neither holds it. A storage read that fails
	 * throws rather than answering that there is no such entry.
	 */
	get(id: string): QueuedPayment | undefined {
		const held =
			this.active.get(id) ??
			this.finished.get(id) ??
			this.unknownOutcomes.get(id);
		if (held) return { ...held };
		if (!this.storage) return undefined;
		const row = this.storage.loadQueueEntry
			? this.storage.loadQueueEntry(id)
			: this.storage.loadAllQueueEntries().find((r) => r.id === id);
		return row ? entryFromRow(row) : undefined;
	}

	/**
	 * Finished entries (completed, failed, cancelled), the most recently
	 * finished first, one page at a time (issue #1866): up to limit (100 by
	 * default, at most 1000), after the entry with id before when given, so
	 * the last id of one page asks for the next. With storage it reads every
	 * finished entry stored, which prune() alone deletes; without storage,
	 * those memory holds. A before that is no finished entry's id gives an
	 * empty page. A storage read that fails throws.
	 */
	history(opts?: { limit?: number; before?: string }): QueuedPayment[] {
		const limit = opts?.limit ?? DEFAULT_HISTORY_PAGE;
		if (!(Number.isSafeInteger(limit) && limit >= 1)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'limit must be a whole number, 1 or greater'
			);
		}
		const size = Math.min(limit, MAX_HISTORY_PAGE);
		const before = opts?.before;
		if (!this.storage) {
			const held = [
				...this.finished.values(),
				...this.unknownOutcomes.values()
			];
			return historyPage(held.sort(newestFinishedFirst), size, before).map(
				(e) => ({ ...e })
			);
		}
		const rows = this.storage.loadQueueHistory
			? this.storage.loadQueueHistory(size, before)
			: historyPage(
					this.storage
						.loadAllQueueEntries()
						.filter((row) => !isActiveStatus(row.status))
						.sort(newestFinishedFirst),
					size,
					before
			  );
		return rows.map(entryFromRow);
	}

	/**
	 * Get the number of pending items.
	 */
	get pendingCount(): number {
		return this.pending.length;
	}

	/**
	 * Get the number of active (dispatching) items.
	 */
	get activePayments(): number {
		return this.activeCount;
	}

	/**
	 * Delete every finished entry (completed, failed, cancelled), from memory
	 * and from storage, those memory no longer holds included: this is the
	 * only call that deletes queue history. Queued and dispatching entries,
	 * an in-flight one the resolver has not settled among them, are never
	 * touched. Returns how many entries it removed.
	 */
	prune(): number {
		const removed = new Set<string>([
			...this.finished.keys(),
			...this.unknownOutcomes.keys()
		]);
		this.finished.clear();
		this.unknownOutcomes.clear();

		if (this.storage) {
			try {
				for (const id of this.storedHistoryIds(this.storage)) {
					if (!this.active.has(id)) removed.add(id);
				}
			} catch {
				/* best-effort */
			}
			for (const id of removed) {
				try {
					this.storage.deleteQueueEntry(id);
				} catch {
					/* best-effort */
				}
			}
		}

		return removed.size;
	}

	/** The id of every finished row in storage, read a page at a time. */
	private storedHistoryIds(storage: IPaymentQueueStorage): Set<string> {
		const ids = new Set<string>();
		if (!storage.loadQueueHistory) {
			for (const row of storage.loadAllQueueEntries()) {
				if (!isActiveStatus(row.status)) ids.add(row.id);
			}
			return ids;
		}
		let page = storage.loadQueueHistory(MAX_HISTORY_PAGE);
		for (;;) {
			const known = ids.size;
			for (const row of page) ids.add(row.id);
			// A page with nothing new ends it too: a storage that ignores
			// before would otherwise answer the same page forever.
			if (page.length < MAX_HISTORY_PAGE || ids.size === known) return ids;
			page = storage.loadQueueHistory(
				MAX_HISTORY_PAGE,
				page[page.length - 1].id
			);
		}
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
	 * at all; entries enqueued since do. An entry enqueued before this whose
	 * ask of the resolver was refused is asked about again here, as
	 * resettle() does (issue #976). Runs once, and does nothing after stop().
	 */
	start(): void {
		if (this.stopped || this.started) return;
		this.started = true;
		this.restored.clear();
		const interrupted: QueuedPayment[] = [];
		for (const id of this.interrupted) {
			const entry = this.active.get(id);
			if (entry) interrupted.push(entry);
		}
		this.interrupted.clear();
		// Before the restored rows, so a refusal they meet just now is not
		// asked about again in the same pass.
		this.resettle();
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
	 * Ask the resolver again about every entry awaiting an outcome whose
	 * last ask was refused (issue #976): a timed-out dispatch, or a restored
	 * row, that it could not answer because no node was there to ask (a
	 * capsule resume rebuilding it, a restart required). Nothing else asks
	 * again in this process: start() runs once, so without this the entry
	 * stayed 'dispatching' until the next process start. The owner calls it
	 * once the rebuilt node can pay, after start(). Does nothing after
	 * stop(): the next start settles the entry like any interrupted one.
	 */
	resettle(): void {
		if (this.stopped) return;
		const waiting = [...this.awaitingOutcome];
		this.awaitingOutcome.clear();
		for (const [entry, onUnpaid] of waiting) {
			this.reconcileInterrupted(entry, onUnpaid);
		}
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
	 * then left 'queued' for the next start. A refused ask leaves the entry
	 * 'dispatching' and remembered for start() or resettle() to ask again.
	 */
	private reconcileInterrupted(
		entry: QueuedPayment,
		onUnpaid: 'queue' | 'fail'
	): void {
		const resolve = this.resolveInterrupted;
		if (!resolve) return;
		this.awaitingOutcome.delete(entry);
		// Unknown right now (no node to ask): it stays 'dispatching', and
		// start(), resettle() or the next process start asks again.
		const refused = (): void => {
			if (entry.status === 'dispatching') {
				this.awaitingOutcome.set(entry, onUnpaid);
			}
		};
		let outcome: Promise<InterruptedPaymentOutcome>;
		try {
			outcome = Promise.resolve(resolve(entry.bolt11));
		} catch {
			refused();
			return;
		}
		outcome
			.then(
				(result) => this.recordInterruptedOutcome(entry, result, onUnpaid),
				refused
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
			this.retire(entry);
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
		this.addPending(entry);
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
				// A restored entry waits for start() (issue #967), which
				// empties restored: from then on this is the front entry.
				const index = this.pending.findIndex((e) => !this.restored.has(e.id));
				if (index < 0) break;
				const next = this.pending[index];

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
					this.pending.splice(index, 1);
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

				this.pending.splice(index, 1);
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
		this.retire(entry);
		this.emit('queue:failed', { id: entry.id, error: entry.error });
	}

	/** Place a queued entry in pending, in dispatch order. */
	private addPending(entry: QueuedPayment): void {
		let low = 0;
		let high = this.pending.length;
		while (low < high) {
			const mid = (low + high) >>> 1;
			if (this.inListOrder(this.pending[mid], entry) < 0) low = mid + 1;
			else high = mid;
		}
		this.pending.splice(low, 0, entry);
	}

	/**
	 * Move an entry that has just finished out of active and into the
	 * history list() shows, dropping the oldest finished entries past
	 * maxRetainedHistory. Storage keeps every one of them.
	 */
	private retire(entry: QueuedPayment): void {
		this.active.delete(entry.id);
		if (
			(!this.storage || this.unstored.has(entry)) &&
			isOutcomeUnknown(entry)
		) {
			this.unknownOutcomes.set(entry.id, entry);
			return;
		}
		this.finished.set(entry.id, entry);
		for (const id of this.finished.keys()) {
			if (this.finished.size <= this.maxRetainedHistory) break;
			this.finished.delete(id);
		}
	}

	/** list() order: priority, then the order the entries were queued in. */
	private inListOrder = (a: QueuedPayment, b: QueuedPayment): number =>
		a.priority - b.priority ||
		(this.sequence.get(a) ?? 0) - (this.sequence.get(b) ?? 0);

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
		// entry: it stays 'dispatching' past the slot release in the finally.
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
					this.unstored.add(entry);
				}
			}
			if (!stillOut) this.retire(entry);
			// The slot goes once, here, whatever the outcome: an entry still
			// out holds none while the resolver waits (a stuck HTLC can last
			// until its expiry, and canSend already counts what it holds).
			this.activeCount--;
			// Asked before the pass below: a listener that throws in it must
			// not leave the entry with nobody to settle it.
			if (stillOut) this.reconcileInterrupted(entry, 'fail');
			// Process more items
			this.processQueue();
		}
	}
}
