/**
 * Issue #1866: the queue kept every finished entry in the one array its
 * passes searched, so memory and the cost of each dispatch grew with the
 * queue's lifetime history, and a start loaded every row ever stored. Memory
 * now holds the queued and dispatching entries and the most recently
 * finished ones; storage keeps the rest for get() and history().
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	IN_FLIGHT_PAYMENT_ERROR,
	InterruptedPaymentOutcome,
	IPaymentQueueStorage,
	PaymentQueue,
	PaymentQueueRow
} from '../../src/cli/payment-queue';
import { QueuedPayment } from '../../src/cli/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

type PayResult = { status: string; paymentHash: string };

const canSend = (): { canSend: boolean; availableSats: number } => ({
	canSend: true,
	availableSats: 1_000_000
});

const settle = (ms = 20): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/** A payer that records each call and answers as told, COMPLETED by default. */
const payer = (
	answers: Record<string, string> = {}
): { calls: string[]; pay: (bolt11: string) => Promise<PayResult> } => {
	const calls: string[] = [];
	return {
		calls,
		pay: async (bolt11: string): Promise<PayResult> => {
			calls.push(bolt11);
			return {
				status: answers[bolt11] ?? 'COMPLETED',
				paymentHash: `hash-${bolt11}`
			};
		}
	};
};

/** Resolves once nothing is queued or dispatching in this process. */
const drained = async (queue: PaymentQueue): Promise<void> => {
	while (queue.pendingCount > 0 || queue.activePayments > 0) {
		await new Promise((resolve) => setImmediate(resolve));
	}
};

/** The queue's own structures, to show a pass reads only active work. */
const internals = (
	queue: PaymentQueue
): {
	pending: QueuedPayment[];
	active: Map<string, QueuedPayment>;
	finished: Map<string, QueuedPayment>;
} =>
	queue as unknown as {
		pending: QueuedPayment[];
		active: Map<string, QueuedPayment>;
		finished: Map<string, QueuedPayment>;
	};

/** Every finished entry, a page at a time, as an agent would read them. */
const allHistory = (queue: PaymentQueue, limit: number): QueuedPayment[] => {
	const all: QueuedPayment[] = [];
	let page = queue.history({ limit });
	while (page.length > 0) {
		all.push(...page);
		page = queue.history({ limit, before: page[page.length - 1].id });
	}
	return all;
};

const codeOf = (run: () => unknown): string | undefined => {
	try {
		run();
	} catch (err: unknown) {
		return (err as { code?: string }).code;
	}
	return undefined;
};

/** Only the methods every IPaymentQueueStorage had before issue #1866. */
const requiredOnly = (storage: SqliteStorage): IPaymentQueueStorage => ({
	saveQueueEntry: (entry) => storage.saveQueueEntry(entry),
	updateQueueEntryStatus: (id, status, error, completedAt) =>
		storage.updateQueueEntryStatus(id, status, error, completedAt),
	deleteQueueEntry: (id) => storage.deleteQueueEntry(id),
	loadAllQueueEntries: () => storage.loadAllQueueEntries()
});

describe('PaymentQueue keeps finished history out of memory and dispatch (issue #1866)', () => {
	let storage: SqliteStorage;

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});

	afterEach(() => {
		storage.close();
	});

	/** A finished row, finished at completedAt (none for a cancelled one). */
	const seedFinished = (
		id: string,
		status: string,
		completedAt?: number,
		createdAt = 1_000
	): void => {
		storage.saveQueueEntry({
			id,
			bolt11: `lnbc_${id}`,
			priority: 5,
			status,
			createdAt
		});
		storage.updateQueueEntryStatus(id, status, undefined, completedAt);
	};

	const seedActive = (id: string, bolt11: string, status: string): void =>
		storage.saveQueueEntry({
			id,
			bolt11,
			priority: 5,
			status,
			createdAt: Date.now()
		});

	it('an enqueue/complete soak holds memory at the retention bound, and every entry stays in durable history', async () => {
		const { calls, pay } = payer();
		const queue = new PaymentQueue(
			pay,
			canSend,
			{ maxConcurrent: 3, maxRetainedHistory: 50 },
			storage
		);
		const enqueued: string[] = [];
		for (let batch = 0; batch < 100; batch++) {
			for (let i = 0; i < 20; i++) {
				enqueued.push(queue.enqueue(`lnbc_${batch}_${i}`).id);
			}
			await drained(queue);
			// Nothing a pass reads is left over from earlier batches.
			expect(internals(queue).pending).to.have.length(0);
			expect(internals(queue).active.size).to.equal(0);
			expect(queue.list()).to.have.length(Math.min(50, enqueued.length));
		}

		// Each payment went out once.
		expect(calls).to.have.length(2_000);
		expect(new Set(calls).size).to.equal(2_000);
		// Memory holds the 50 most recently finished.
		const listed = queue.list().map((e) => e.id);
		expect(listed).to.have.members(enqueued.slice(-50));
		// Storage holds all 2000, and history() pages through every one,
		// most recently finished first, with no entry twice.
		const rows = storage.loadAllQueueEntries();
		expect(rows).to.have.length(2_000);
		expect(rows.every((r) => r.status === 'completed')).to.equal(true);
		const history = allHistory(queue, 1_000);
		expect(history.map((e) => e.id)).to.have.members(enqueued);
		for (let i = 1; i < history.length; i++) {
			const newer = history[i - 1].completedAt!;
			const older = history[i].completedAt!;
			expect(newer >= older).to.equal(true);
		}
		// The first entry left memory long ago; get() still finds it.
		expect(queue.get(enqueued[0])?.status).to.equal('completed');
		expect(queue.get(enqueued[0])?.bolt11).to.equal('lnbc_0_0');
	});

	it('a dispatch left pending at its timeout is never dropped, however much finishes after it, and is recorded once it settles', async () => {
		const { calls, pay } = payer({ lnbc_out: 'PENDING' });
		let answer!: (o: InterruptedPaymentOutcome) => void;
		const asked: string[] = [];
		const queue = new PaymentQueue(
			pay,
			canSend,
			{
				maxConcurrent: 1,
				maxRetainedHistory: 3,
				resolveInterrupted: (bolt11): Promise<InterruptedPaymentOutcome> => {
					asked.push(bolt11);
					return new Promise((resolve) => {
						answer = resolve;
					});
				}
			},
			storage
		);
		const out = queue.enqueue('lnbc_out');
		await settle();
		for (let i = 0; i < 10; i++) queue.enqueue(`lnbc_done_${i}`);
		await drained(queue);

		expect(asked).to.deep.equal(['lnbc_out']);
		expect(queue.get(out.id)?.status).to.equal('dispatching');
		const listed = queue.list();
		expect(listed).to.have.length(4);
		expect(listed.find((e) => e.id === out.id)?.status).to.equal('dispatching');
		// prune() deletes the ten finished rows and nothing else.
		expect(queue.prune()).to.equal(10);
		expect(storage.loadAllQueueEntries().map((r) => r.id)).to.deep.equal([
			out.id
		]);

		answer({ status: 'completed', paymentHash: 'dd'.repeat(32) });
		await settle();
		expect(queue.get(out.id)?.status).to.equal('completed');
		expect(queue.history({ limit: 1 }).map((e) => e.id)).to.deep.equal([
			out.id
		]);
		expect(storage.loadQueueEntry(out.id)?.status).to.equal('completed');
		expect(calls.filter((b) => b === 'lnbc_out')).to.have.length(1);
	});

	it('a restart reads only the active rows and the newest history, settles interrupted rows, and sends nothing twice', async () => {
		for (let i = 1; i <= 40; i++)
			seedFinished(`q-${i}-x`, 'completed', 1_000 + i);
		seedActive('q-41-x', 'lnbc_inflight_paid', 'dispatching');
		seedActive('q-42-x', 'lnbc_inflight_unpaid', 'dispatching');
		seedActive('q-43-x', 'lnbc_waiting', 'queued');
		let fullReads = 0;
		const counted: IPaymentQueueStorage = {
			saveQueueEntry: (e) => storage.saveQueueEntry(e),
			updateQueueEntryStatus: (id, s, e, c) =>
				storage.updateQueueEntryStatus(id, s, e, c),
			deleteQueueEntry: (id) => storage.deleteQueueEntry(id),
			loadAllQueueEntries: () => {
				fullReads++;
				return storage.loadAllQueueEntries();
			},
			loadActiveQueueEntries: () => storage.loadActiveQueueEntries(),
			loadQueueHistory: (limit, before) =>
				storage.loadQueueHistory(limit, before),
			loadQueueEntry: (id) => storage.loadQueueEntry(id)
		};
		const { calls, pay } = payer();
		const queue = new PaymentQueue(
			pay,
			canSend,
			{
				maxRetainedHistory: 5,
				resolveInterrupted: async (
					bolt11
				): Promise<InterruptedPaymentOutcome> =>
					bolt11 === 'lnbc_inflight_paid'
						? { status: 'completed', paymentHash: 'ee'.repeat(32) }
						: { status: 'unpaid' }
			},
			counted
		);

		expect(queue.list().map((e) => e.id)).to.have.members([
			'q-36-x',
			'q-37-x',
			'q-38-x',
			'q-39-x',
			'q-40-x',
			'q-41-x',
			'q-42-x',
			'q-43-x'
		]);
		expect(queue.pendingCount).to.equal(1);
		await settle();
		expect(calls).to.deep.equal([]);

		queue.start();
		await settle();
		await drained(queue);

		// The paid one is recorded from the node's record and never sent;
		// the unpaid one and the queued one are each sent once.
		expect(calls).to.have.members(['lnbc_inflight_unpaid', 'lnbc_waiting']);
		expect(calls).to.have.length(2);
		expect(queue.get('q-41-x')?.status).to.equal('completed');
		expect(queue.get('q-42-x')?.status).to.equal('completed');
		expect(queue.get('q-43-x')?.status).to.equal('completed');
		expect(queue.list()).to.have.length(5);
		expect(queue.list().map((e) => e.id)).to.include.members([
			'q-41-x',
			'q-42-x',
			'q-43-x'
		]);
		// Durable history is complete, and the next id follows the stored ones.
		expect(allHistory(queue, 10)).to.have.length(43);
		expect(queue.enqueue('lnbc_next').id).to.match(/^q-44-/);
		expect(fullReads).to.equal(0);
	});

	it('a storage with only the original four methods restores, pages and prunes the same way', async () => {
		for (let i = 1; i <= 10; i++)
			seedFinished(`q-${i}-x`, 'completed', 2_000 - i);
		seedFinished('q-11-x', 'cancelled', undefined, 1_500);
		seedActive('q-12-x', 'lnbc_waiting', 'queued');
		const queue = new PaymentQueue(
			payer().pay,
			canSend,
			{ maxConcurrent: 0, maxRetainedHistory: 2 },
			requiredOnly(storage)
		);
		expect(queue.list().map((e) => e.id)).to.have.members([
			'q-1-x',
			'q-2-x',
			'q-12-x'
		]);
		// The same order the SQLite query gives.
		expect(allHistory(queue, 4).map((e) => e.id)).to.deep.equal(
			storage.loadQueueHistory(100).map((r) => r.id)
		);
		expect(queue.get('q-10-x')?.status).to.equal('completed');
		expect(queue.get('q-11-x')?.status).to.equal('cancelled');
		expect(queue.get('nope')).to.equal(undefined);

		expect(queue.prune()).to.equal(11);
		expect(storage.loadAllQueueEntries().map((r) => r.id)).to.deep.equal([
			'q-12-x'
		]);
		expect(queue.list().map((e) => e.id)).to.deep.equal(['q-12-x']);
	});

	it('a cancelled entry leaves list() but stays in storage for get() and history()', () => {
		const queue = new PaymentQueue(
			payer().pay,
			canSend,
			{ maxConcurrent: 0 },
			storage
		);
		const kept = queue.enqueue('lnbc_kept');
		const dropped = queue.enqueue('lnbc_dropped');
		expect(queue.cancel(dropped.id)).to.equal(true);
		expect(queue.list().map((e) => e.id)).to.deep.equal([kept.id]);
		expect(queue.pendingCount).to.equal(1);
		expect(queue.get(dropped.id)?.status).to.equal('cancelled');
		expect(queue.history().map((e) => e.id)).to.deep.equal([dropped.id]);
	});

	it('without storage, finished entries past the bound are gone, but one whose outcome is unknown stays until prune()', async () => {
		const { pay } = payer({ lnbc_unknown: 'PENDING' });
		const queue = new PaymentQueue(pay, canSend, { maxRetainedHistory: 2 });
		const unknown = queue.enqueue('lnbc_unknown');
		const done: string[] = [];
		for (let i = 0; i < 5; i++) done.push(queue.enqueue(`lnbc_${i}`).id);
		await drained(queue);

		expect(queue.get(unknown.id)?.error).to.equal(IN_FLIGHT_PAYMENT_ERROR);
		expect(queue.list().map((e) => e.id)).to.have.members([
			unknown.id,
			done[3],
			done[4]
		]);
		expect(queue.get(done[0])).to.equal(undefined);
		expect(queue.history().map((e) => e.id)).to.have.members([
			unknown.id,
			done[3],
			done[4]
		]);
		expect(queue.prune()).to.equal(3);
		expect(queue.list()).to.deep.equal([]);
	});

	it('maxRetainedHistory takes a whole number zero or greater, or Infinity to keep every finished entry', async () => {
		for (const bad of [-1, 1.5, Number.NaN, '5']) {
			expect(
				codeOf(
					() =>
						new PaymentQueue(payer().pay, canSend, {
							maxRetainedHistory: bad as number
						})
				),
				String(bad)
			).to.equal('INVALID_PARAMS');
		}

		const all = new PaymentQueue(payer().pay, canSend, {
			maxRetainedHistory: Infinity
		});
		for (let i = 0; i < 5; i++) all.enqueue(`lnbc_all_${i}`);
		await drained(all);
		expect(all.list()).to.have.length(5);

		const none = new PaymentQueue(
			payer().pay,
			canSend,
			{ maxRetainedHistory: 0 },
			storage
		);
		const entry = none.enqueue('lnbc_none');
		await drained(none);
		expect(none.list()).to.deep.equal([]);
		expect(none.get(entry.id)?.status).to.equal('completed');
		// A restart over the same rows keeps none of them either.
		const restarted = new PaymentQueue(
			payer().pay,
			canSend,
			{ maxRetainedHistory: 0 },
			storage
		);
		expect(restarted.list()).to.deep.equal([]);
		expect(restarted.history().map((e) => e.id)).to.deep.equal([entry.id]);
	});

	it('history() refuses a limit that is not a whole number 1 or greater, caps a page at 1000, and answers an unknown cursor with an empty page', () => {
		for (let i = 1; i <= 1_001; i++) seedFinished(`q-${i}-x`, 'completed', i);
		seedActive('q-2000-x', 'lnbc_waiting', 'queued');
		const queue = new PaymentQueue(
			payer().pay,
			canSend,
			{ maxConcurrent: 0 },
			storage
		);
		for (const limit of [0, -1, 1.5, Number.NaN]) {
			expect(
				codeOf(() => queue.history({ limit })),
				String(limit)
			).to.equal('INVALID_PARAMS');
		}
		expect(queue.history()).to.have.length(100);
		expect(queue.history({ limit: 5_000 })).to.have.length(1_000);
		expect(queue.history({ before: 'nope' })).to.deep.equal([]);
		// The id of an entry that has not finished is no cursor either.
		expect(queue.history({ before: 'q-2000-x' })).to.deep.equal([]);
	});

	it('SqliteStorage orders history by finish time, then id, both descending, and pages across a tie', () => {
		seedFinished('q-1-a', 'completed', 500);
		seedFinished('q-2-a', 'failed', 500);
		seedFinished('q-3-a', 'completed', 500);
		// No completedAt: it sorts by createdAt.
		seedFinished('q-4-a', 'cancelled', undefined, 500);
		seedFinished('q-5-a', 'completed', 600);
		seedFinished('q-6-a', 'completed', 400);
		seedActive('q-7-a', 'lnbc_waiting', 'queued');
		seedActive('q-8-a', 'lnbc_out', 'dispatching');

		const ids = (rows: PaymentQueueRow[]): string[] => rows.map((r) => r.id);
		expect(ids(storage.loadQueueHistory(10))).to.deep.equal([
			'q-5-a',
			'q-4-a',
			'q-3-a',
			'q-2-a',
			'q-1-a',
			'q-6-a'
		]);
		expect(ids(storage.loadQueueHistory(2))).to.deep.equal(['q-5-a', 'q-4-a']);
		expect(ids(storage.loadQueueHistory(2, 'q-4-a'))).to.deep.equal([
			'q-3-a',
			'q-2-a'
		]);
		expect(ids(storage.loadQueueHistory(2, 'q-2-a'))).to.deep.equal([
			'q-1-a',
			'q-6-a'
		]);
		expect(ids(storage.loadQueueHistory(2, 'q-6-a'))).to.deep.equal([]);
		expect(ids(storage.loadQueueHistory(2, 'q-7-a'))).to.deep.equal([]);
		expect(ids(storage.loadActiveQueueEntries())).to.have.members([
			'q-7-a',
			'q-8-a'
		]);
		expect(storage.loadQueueEntry('q-4-a')?.status).to.equal('cancelled');
		expect(storage.loadQueueEntry('nope')).to.equal(undefined);
	});
});

describe('SqliteStorage indexes the payment queue on open (issue #1866)', () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-index-'));
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('a database made before the indexes gets them on its next open', () => {
		const file = path.join(dir, 'queue.db');
		const first = new SqliteStorage(file);
		first.open();
		const db = (s: SqliteStorage): { exec(sql: string): void } =>
			(s as unknown as { db: { exec(sql: string): void } }).db;
		db(first).exec(
			'DROP INDEX idx_payment_queue_status; DROP INDEX idx_payment_queue_finished'
		);
		first.close();

		const second = new SqliteStorage(file);
		second.open();
		try {
			const names = (
				second as unknown as {
					db: { prepare(sql: string): { all(): Array<{ name: string }> } };
				}
			).db
				.prepare(
					"SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'payment_queue'"
				)
				.all()
				.map((r) => r.name);
			expect(names).to.include.members([
				'idx_payment_queue_status',
				'idx_payment_queue_finished'
			]);
		} finally {
			second.close();
		}
	});
});
