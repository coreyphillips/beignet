/**
 * Tests for payment queue persistence — queued payments survive crashes.
 */

import { expect } from 'chai';
import {
	INTERRUPTED_PAYMENT_ERROR,
	InterruptedPaymentOutcome,
	PaymentQueue
} from '../../src/cli/payment-queue';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

// Stub functions that never actually pay — we only test persistence
const noopPay = async (_bolt11: string) => ({
	status: 'FAILED',
	paymentHash: 'abc'
});
const noopCanSend = () => ({ canSend: true, availableSats: 100000 });

describe('Payment Queue Persistence', () => {
	let storage: SqliteStorage;

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});

	afterEach(() => {
		storage.close();
	});

	it('queued entries survive restart', () => {
		// Don't actually dispatch — use maxConcurrent=0 hack (or just check storage)
		const queue1 = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		queue1.enqueue('lnbc1000test1', 3);
		queue1.enqueue('lnbc2000test2', 7);

		// Verify in storage
		const rows = storage.loadAllQueueEntries();
		expect(rows).to.have.lengthOf(2);
		expect(rows[0].bolt11).to.equal('lnbc1000test1');
		expect(rows[0].priority).to.equal(3);
	});

	it('with no resolver, a restored dispatching entry is recorded failed, never sent again (issue #967)', () => {
		// Manually insert a "dispatching" entry into storage to simulate crash
		storage.saveQueueEntry({
			id: 'q-1-12345',
			bolt11: 'lnbc_crashed',
			priority: 5,
			status: 'dispatching',
			createdAt: Date.now()
		});

		let calls = 0;
		const queue = new PaymentQueue(
			async () => {
				calls++;
				return { status: 'COMPLETED', paymentHash: 'abc' };
			},
			noopCanSend,
			undefined,
			storage
		);
		queue.start();
		queue.enqueue('lnbc_other', 5);
		const list = queue.list();
		const crashed = list.find((e) => e.id === 'q-1-12345');
		// It may have been paid before the crash: sending it again could pay
		// twice, and with no resolver nothing can tell.
		expect(crashed?.status).to.equal('failed');
		expect(crashed?.error).to.equal(INTERRUPTED_PAYMENT_ERROR);
		expect(crashed?.completedAt).to.be.a('number');
		const row = storage.loadAllQueueEntries().find((r) => r.id === 'q-1-12345');
		expect(row?.status).to.equal('failed');
		expect(row?.error).to.equal(INTERRUPTED_PAYMENT_ERROR);
		expect(row?.completedAt).to.be.a('number');
		// Only the new entry was paid.
		expect(calls).to.equal(1);
	});

	it('completed/failed entries are loadable', () => {
		storage.saveQueueEntry({
			id: 'q-1-1000',
			bolt11: 'lnbc_done',
			priority: 5,
			status: 'completed',
			createdAt: Date.now() - 60000
		});
		storage.updateQueueEntryStatus(
			'q-1-1000',
			'completed',
			undefined,
			Date.now()
		);

		const rows = storage.loadAllQueueEntries();
		expect(rows).to.have.lengthOf(1);
		expect(rows[0].status).to.equal('completed');
	});

	it('prune removes from storage', () => {
		const queue = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		queue.enqueue('lnbc_a', 5);
		queue.enqueue('lnbc_b', 5);

		// Manually mark one as completed in the queue
		const list = queue.list();
		expect(list).to.have.lengthOf(2);

		// Insert a completed entry directly to test prune
		storage.saveQueueEntry({
			id: 'q-99-999',
			bolt11: 'lnbc_old',
			priority: 5,
			status: 'completed',
			createdAt: Date.now() - 120000
		});

		// Verify it's in storage
		expect(storage.loadAllQueueEntries()).to.have.lengthOf(3);

		// Create new queue (restores all) and prune
		const queue2 = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		const pruned = queue2.prune();
		expect(pruned).to.equal(1); // The completed one

		expect(storage.loadAllQueueEntries()).to.have.lengthOf(2);
	});

	it('cancel updates storage', () => {
		const queue = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		const entry = queue.enqueue('lnbc_cancel_me', 5);
		expect(queue.cancel(entry.id)).to.be.true;

		// Check storage was updated
		const rows = storage.loadAllQueueEntries();
		expect(rows).to.have.lengthOf(1);
		expect(rows[0].status).to.equal('cancelled');
	});

	it('backward compatible — no storage means in-memory', () => {
		const queue = new PaymentQueue(noopPay, noopCanSend, { maxConcurrent: 0 });
		const entry = queue.enqueue('lnbc_mem', 5);
		expect(queue.list()).to.have.lengthOf(1);
		expect(queue.cancel(entry.id)).to.be.true;
		// No crash
	});

	it('ID counter resumes from max stored ID', () => {
		// Insert entries with known IDs
		storage.saveQueueEntry({
			id: 'q-42-1000',
			bolt11: 'lnbc_a',
			priority: 5,
			status: 'queued',
			createdAt: Date.now()
		});
		storage.saveQueueEntry({
			id: 'q-100-2000',
			bolt11: 'lnbc_b',
			priority: 5,
			status: 'queued',
			createdAt: Date.now()
		});

		const queue = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		const entry = queue.enqueue('lnbc_new', 5);
		// New entry should have ID > 100
		const match = entry.id.match(/^q-(\d+)-/);
		expect(match).to.not.be.null;
		const num = parseInt(match![1], 10);
		expect(num).to.be.greaterThan(100);
	});

	// Issue #958: shutdown now keeps the database open while the wallet
	// stops, so a dispatch against the stopped node would persist 'failed'.
	// stop() leaves queued entries in storage for the next start instead.
	describe('stop()', () => {
		type PayResult = { status: string; paymentHash: string };
		const statusOf = (id: string): string | undefined =>
			storage.loadAllQueueEntries().find((row) => row.id === id)?.status;

		it('lets a dispatch in flight record how it ended, and dispatches nothing more', async () => {
			const finishers: Array<(result: PayResult) => void> = [];
			const heldPay = (): Promise<PayResult> =>
				new Promise((resolve) => finishers.push(resolve));
			const queue = new PaymentQueue(
				heldPay,
				noopCanSend,
				{ maxConcurrent: 1 },
				storage
			);
			const inFlight = queue.enqueue('lnbc_in_flight', 1);
			const waiting = queue.enqueue('lnbc_waiting', 5);
			expect(statusOf(inFlight.id)).to.equal('dispatching');
			expect(statusOf(waiting.id)).to.equal('queued');

			queue.stop();
			const late = queue.enqueue('lnbc_after_stop', 5);
			finishers[0]({ status: 'COMPLETED', paymentHash: 'h1' });
			await new Promise((resolve) => setTimeout(resolve, 20));

			expect(statusOf(inFlight.id)).to.equal('completed');
			expect(statusOf(waiting.id)).to.equal('queued');
			expect(statusOf(late.id)).to.equal('queued');
			expect(finishers).to.have.length(1);
			expect(queue.activePayments).to.equal(0);

			// The next start restores them; they dispatch on its start().
			const restarted = new PaymentQueue(
				noopPay,
				noopCanSend,
				{ maxConcurrent: 0 },
				storage
			);
			expect(restarted.pendingCount).to.equal(2);
		});

		it('records a dispatch that fails after stop() as failed, and leaves the rest queued', async () => {
			let calls = 0;
			let failIt!: (e: Error) => void;
			const heldPay = (): Promise<PayResult> => {
				calls++;
				return new Promise((_resolve, reject) => {
					failIt = reject;
				});
			};
			const queue = new PaymentQueue(
				heldPay,
				noopCanSend,
				{ maxConcurrent: 1 },
				storage
			);
			const inFlight = queue.enqueue('lnbc_in_flight', 1);
			const waiting = queue.enqueue('lnbc_waiting', 5);

			queue.stop();
			failIt(new Error('Payment timed out'));
			await new Promise((resolve) => setTimeout(resolve, 20));

			expect(statusOf(inFlight.id)).to.equal('failed');
			expect(statusOf(waiting.id)).to.equal('queued');
			expect(calls).to.equal(1);
		});
	});

	// Issue #967: restored entries dispatched only on the next unrelated
	// enqueue(), and an entry in flight at the restart was restored 'queued'
	// and sent again. The node refuses a second payment to the same hash only
	// while the first is pending, so one that had completed was paid twice.
	describe('restart (issue #967)', () => {
		type PayResult = { status: string; paymentHash: string };
		type Row = ReturnType<SqliteStorage['loadAllQueueEntries']>[number];
		const rowOf = (id: string): Row | undefined =>
			storage.loadAllQueueEntries().find((row) => row.id === id);
		const statusOf = (id: string): string | undefined => rowOf(id)?.status;
		const seed = (
			id: string,
			bolt11: string,
			status: string,
			priority = 5
		): void =>
			storage.saveQueueEntry({
				id,
				bolt11,
				priority,
				status,
				createdAt: Date.now()
			});
		const settle = (): Promise<void> =>
			new Promise((resolve) => setTimeout(resolve, 20));

		/** A payer that records each call and completes it at once. */
		const recordingPay = (): {
			calls: string[];
			pay: (bolt11: string) => Promise<PayResult>;
		} => {
			const calls: string[] = [];
			return {
				calls,
				pay: async (bolt11: string): Promise<PayResult> => {
					calls.push(bolt11);
					return { status: 'COMPLETED', paymentHash: `paid-${bolt11}` };
				}
			};
		};

		/** A resolver whose answers the test gives, one per call. */
		const heldResolver = (): {
			asked: string[];
			answer: (index: number, outcome: InterruptedPaymentOutcome) => void;
			refuse: (index: number) => void;
			resolve: (bolt11: string) => Promise<InterruptedPaymentOutcome>;
		} => {
			const asked: string[] = [];
			const pending: Array<{
				resolve: (o: InterruptedPaymentOutcome) => void;
				reject: (e: Error) => void;
			}> = [];
			return {
				asked,
				answer: (index, outcome): void => pending[index].resolve(outcome),
				refuse: (index): void =>
					pending[index].reject(new Error('Node destroyed')),
				resolve: (bolt11): Promise<InterruptedPaymentOutcome> => {
					asked.push(bolt11);
					return new Promise((resolve, reject) =>
						pending.push({ resolve, reject })
					);
				}
			};
		};

		it('restored queued rows are not paid at construction, and dispatch on start() with no enqueue', async () => {
			seed('q-1-a', 'lnbc_restored_a', 'queued', 1);
			seed('q-2-b', 'lnbc_restored_b', 'queued', 5);
			const { calls, pay } = recordingPay();
			const queue = new PaymentQueue(pay, noopCanSend, undefined, storage);
			await settle();
			expect(calls).to.have.length(0);
			expect(queue.pendingCount).to.equal(2);

			queue.start();
			await settle();
			expect(calls).to.deep.equal(['lnbc_restored_a', 'lnbc_restored_b']);
			expect(statusOf('q-1-a')).to.equal('completed');
			expect(statusOf('q-2-b')).to.equal('completed');
		});

		it('start() after stop() dispatches nothing, and the rows stay queued', async () => {
			seed('q-1-a', 'lnbc_restored_a', 'queued');
			seed('q-2-b', 'lnbc_in_flight', 'dispatching');
			const { calls, pay } = recordingPay();
			const resolver = heldResolver();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{ resolveInterrupted: resolver.resolve },
				storage
			);
			queue.stop();
			queue.start();
			await settle();
			expect(calls).to.have.length(0);
			expect(resolver.asked).to.have.length(0);
			expect(statusOf('q-1-a')).to.equal('queued');
			expect(statusOf('q-2-b')).to.equal('dispatching');
		});

		it('a second start() calls neither the payer nor the resolver again', async () => {
			seed('q-1-a', 'lnbc_restored_a', 'queued');
			seed('q-2-b', 'lnbc_in_flight', 'dispatching');
			const { calls, pay } = recordingPay();
			const resolver = heldResolver();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{ resolveInterrupted: resolver.resolve },
				storage
			);
			queue.start();
			await settle();
			queue.start();
			await settle();
			expect(calls).to.deep.equal(['lnbc_restored_a']);
			expect(resolver.asked).to.deep.equal(['lnbc_in_flight']);
		});

		it('with a resolver, a restored dispatching row stays dispatching, and is not asked about before start()', async () => {
			seed('q-1-a', 'lnbc_in_flight', 'dispatching');
			const { calls, pay } = recordingPay();
			const resolver = heldResolver();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{ resolveInterrupted: resolver.resolve },
				storage
			);
			// An enqueue before start() dispatches as always, but never the
			// restored row: it is not 'queued'.
			queue.enqueue('lnbc_new', 5);
			await settle();
			expect(queue.list().find((e) => e.id === 'q-1-a')?.status).to.equal(
				'dispatching'
			);
			expect(statusOf('q-1-a')).to.equal('dispatching');
			expect(resolver.asked).to.have.length(0);
			expect(calls).to.deep.equal(['lnbc_new']);
		});

		it("the resolver's 'completed' records it completed with its hash, and never pays it", async () => {
			seed('q-1-a', 'lnbc_in_flight', 'dispatching');
			const { calls, pay } = recordingPay();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{
					resolveInterrupted: async (): Promise<InterruptedPaymentOutcome> => ({
						status: 'completed',
						paymentHash: 'aa'.repeat(32)
					})
				},
				storage
			);
			const completed: Array<{ id: string; paymentHash: string }> = [];
			queue.on('queue:completed', (e) => completed.push(e));
			queue.start();
			await settle();

			expect(calls).to.have.length(0);
			expect(completed).to.deep.equal([
				{ id: 'q-1-a', paymentHash: 'aa'.repeat(32) }
			]);
			const row = rowOf('q-1-a');
			expect(row?.status).to.equal('completed');
			expect(row?.completedAt).to.be.a('number');
			const entry = queue.list().find((e) => e.id === 'q-1-a');
			expect(entry?.status).to.equal('completed');
			expect(entry?.completedAt).to.be.a('number');
		});

		it("the resolver's 'unpaid' queues it again, and it is paid exactly once with the outcome recorded", async () => {
			seed('q-1-a', 'lnbc_never_paid', 'dispatching');
			const { calls, pay } = recordingPay();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{
					resolveInterrupted: async (): Promise<InterruptedPaymentOutcome> => ({
						status: 'unpaid'
					})
				},
				storage
			);
			const completed: Array<{ id: string; paymentHash: string }> = [];
			queue.on('queue:completed', (e) => completed.push(e));
			queue.start();
			await settle();

			expect(calls).to.deep.equal(['lnbc_never_paid']);
			expect(completed).to.deep.equal([
				{ id: 'q-1-a', paymentHash: 'paid-lnbc_never_paid' }
			]);
			expect(statusOf('q-1-a')).to.equal('completed');
		});

		it('while the resolver waits, the entry stays dispatching, cannot be cancelled or pruned, and holds no slot', async () => {
			seed('q-1-a', 'lnbc_stuck', 'dispatching', 1);
			seed('q-2-b', 'lnbc_restored', 'queued', 5);
			const { calls, pay } = recordingPay();
			const resolver = heldResolver();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{ maxConcurrent: 1, resolveInterrupted: resolver.resolve },
				storage
			);
			queue.start();
			await settle();

			expect(resolver.asked).to.deep.equal(['lnbc_stuck']);
			// A stuck HTLC can last until its expiry; the single slot is not
			// held for it.
			expect(calls).to.deep.equal(['lnbc_restored']);
			expect(statusOf('q-2-b')).to.equal('completed');
			expect(queue.activePayments).to.equal(0);

			expect(queue.cancel('q-1-a')).to.equal(false);
			expect(queue.prune()).to.equal(1); // the completed q-2-b only
			expect(queue.list().map((e) => e.id)).to.deep.equal(['q-1-a']);
			expect(queue.list()[0].status).to.equal('dispatching');
			expect(statusOf('q-1-a')).to.equal('dispatching');

			resolver.answer(0, { status: 'completed', paymentHash: 'bb'.repeat(32) });
			await settle();
			expect(statusOf('q-1-a')).to.equal('completed');
			expect(calls).to.deep.equal(['lnbc_restored']);
		});

		it('a resolver that rejects or throws leaves it dispatching, and the next start asks again', async () => {
			seed('q-1-a', 'lnbc_in_flight', 'dispatching');
			const { calls, pay } = recordingPay();
			const asked: string[] = [];

			const throwing = new PaymentQueue(
				pay,
				noopCanSend,
				{
					resolveInterrupted: (
						bolt11: string
					): Promise<InterruptedPaymentOutcome> => {
						asked.push(bolt11);
						throw new Error('no node yet');
					}
				},
				storage
			);
			throwing.start();
			await settle();
			expect(statusOf('q-1-a')).to.equal('dispatching');
			expect(throwing.list()[0].status).to.equal('dispatching');

			const rejecting = new PaymentQueue(
				pay,
				noopCanSend,
				{
					resolveInterrupted: async (
						bolt11: string
					): Promise<InterruptedPaymentOutcome> => {
						asked.push(bolt11);
						throw new Error('Node destroyed');
					}
				},
				storage
			);
			rejecting.start();
			await settle();
			expect(statusOf('q-1-a')).to.equal('dispatching');
			expect(rejecting.list()[0].status).to.equal('dispatching');

			const answering = new PaymentQueue(
				pay,
				noopCanSend,
				{
					resolveInterrupted: async (
						bolt11: string
					): Promise<InterruptedPaymentOutcome> => {
						asked.push(bolt11);
						return { status: 'unpaid' };
					}
				},
				storage
			);
			answering.start();
			await settle();
			expect(asked).to.deep.equal([
				'lnbc_in_flight',
				'lnbc_in_flight',
				'lnbc_in_flight'
			]);
			// Paid once, by the start that could settle it.
			expect(calls).to.deep.equal(['lnbc_in_flight']);
			expect(statusOf('q-1-a')).to.equal('completed');
		});

		it('an outcome that arrives after stop() is recorded; an unpaid one stays queued and is not dispatched', async () => {
			seed('q-1-a', 'lnbc_paid', 'dispatching');
			seed('q-2-b', 'lnbc_unpaid', 'dispatching');
			const { calls, pay } = recordingPay();
			const resolver = heldResolver();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{ resolveInterrupted: resolver.resolve },
				storage
			);
			queue.start();
			await settle();
			expect(resolver.asked).to.deep.equal(['lnbc_paid', 'lnbc_unpaid']);

			queue.stop();
			resolver.answer(0, { status: 'completed', paymentHash: 'cc'.repeat(32) });
			resolver.answer(1, { status: 'unpaid' });
			await settle();

			expect(statusOf('q-1-a')).to.equal('completed');
			expect(statusOf('q-2-b')).to.equal('queued');
			expect(calls).to.have.length(0);

			// The next start restores it queued, to dispatch on its start().
			const restarted = new PaymentQueue(pay, noopCanSend, undefined, storage);
			expect(restarted.pendingCount).to.equal(1);
		});

		it('a resolver answer the queue does not know leaves it dispatching', async () => {
			seed('q-1-a', 'lnbc_in_flight', 'dispatching');
			const { calls, pay } = recordingPay();
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{
					resolveInterrupted: async (): Promise<InterruptedPaymentOutcome> =>
						({ status: 'pending' }) as unknown as InterruptedPaymentOutcome
				},
				storage
			);
			queue.start();
			await settle();
			expect(statusOf('q-1-a')).to.equal('dispatching');
			expect(calls).to.have.length(0);
		});

		it('a throwing queue:completed listener neither loses the outcome nor becomes an unhandled rejection', async () => {
			seed('q-1-a', 'lnbc_in_flight', 'dispatching');
			const unhandled: unknown[] = [];
			const onUnhandled = (reason: unknown): void => {
				unhandled.push(reason);
			};
			process.on('unhandledRejection', onUnhandled);
			try {
				const queue = new PaymentQueue(
					noopPay,
					noopCanSend,
					{
						resolveInterrupted:
							async (): Promise<InterruptedPaymentOutcome> => ({
								status: 'completed',
								paymentHash: 'dd'.repeat(32)
							})
					},
					storage
				);
				queue.on('queue:completed', () => {
					throw new Error('listener bug');
				});
				queue.start();
				await settle();
				expect(statusOf('q-1-a')).to.equal('completed');
				expect(unhandled).to.have.length(0);
			} finally {
				process.removeListener('unhandledRejection', onUnhandled);
			}
		});

		/** BeignetNode.canSend's own guard: a whole number of sats or a throw. */
		const strictCanSend = (
			amountSats: number
		): { canSend: boolean; availableSats: number } => {
			if (!Number.isSafeInteger(amountSats) || amountSats < 0) {
				throw new Error(
					'amountSats must be a whole number of satoshis, zero or greater'
				);
			}
			return { canSend: true, availableSats: 100_000 };
		};

		// Review round 1: a canSend that throws left processQueue's
		// `processing` flag set, and every later pass returned at once. The
		// row stayed queued, so every start hit it again.
		it('a restored row whose amountSats the capacity check refuses is failed at start, and the queue keeps dispatching', async () => {
			storage.saveQueueEntry({
				id: 'q-1-bad',
				bolt11: 'lnbc_bad_amount',
				priority: 1,
				status: 'queued',
				amountSats: 1.5,
				createdAt: Date.now()
			});
			seed('q-2-next', 'lnbc_next', 'queued', 5);
			const { calls, pay } = recordingPay();
			const queue = new PaymentQueue(pay, strictCanSend, undefined, storage);
			const failed: Array<{ id: string; error: string }> = [];
			queue.on('queue:failed', (e) => failed.push(e));

			expect(() => queue.start()).to.not.throw();
			await settle();
			const row = rowOf('q-1-bad');
			expect(row?.status).to.equal('failed');
			expect(row?.error).to.contain('whole number of satoshis');
			expect(row?.completedAt).to.be.a('number');
			expect(failed.map((e) => e.id)).to.deep.equal(['q-1-bad']);
			// The rest of the queue is not held behind it.
			expect(calls).to.deep.equal(['lnbc_next']);

			const later = queue.enqueue('lnbc_later', 5);
			await settle();
			expect(calls).to.deep.equal(['lnbc_next', 'lnbc_later']);
			expect(statusOf(later.id)).to.equal('completed');
		});

		it('enqueue() refuses an amountSats or maxFeeSats that is not a whole number of satoshis, and stores nothing', () => {
			const queue = new PaymentQueue(
				noopPay,
				noopCanSend,
				{ maxConcurrent: 0 },
				storage
			);
			const bad: Array<Record<string, unknown>> = [
				{ amountSats: 1.5 },
				{ amountSats: '1000' },
				{ amountSats: -1 },
				{ amountSats: Number.NaN },
				{ maxFeeSats: 0.5 },
				{ maxFeeSats: -2 }
			];
			for (const opts of bad) {
				let refused: unknown;
				try {
					queue.enqueue('lnbc_bad', 5, opts as { amountSats?: number });
				} catch (err: unknown) {
					refused = err;
				}
				expect(
					(refused as { code?: string } | undefined)?.code,
					JSON.stringify(opts)
				).to.equal('INVALID_PARAMS');
			}
			expect(storage.loadAllQueueEntries()).to.deep.equal([]);
			expect(queue.list()).to.deep.equal([]);
			// Absent and whole amounts are still taken.
			queue.enqueue('lnbc_good', 5, { amountSats: 0, maxFeeSats: 10 });
			queue.enqueue('lnbc_plain', 5);
			expect(queue.list()).to.have.length(2);
		});

		it('poke() dispatches an entry canSend held back once capacity appears, only between start() and stop()', async () => {
			const seedWithAmount = (id: string, bolt11: string): void =>
				storage.saveQueueEntry({
					id,
					bolt11,
					priority: 5,
					status: 'queued',
					amountSats: 1_000,
					createdAt: Date.now()
				});
			seedWithAmount('q-1-a', 'lnbc_needs_capacity');
			let capacity = false;
			const canSend = (): { canSend: boolean; availableSats: number } => ({
				canSend: capacity,
				availableSats: capacity ? 10_000 : 0
			});
			const { calls, pay } = recordingPay();
			const queue = new PaymentQueue(pay, canSend, undefined, storage);
			capacity = true;
			queue.poke();
			await settle();
			expect(calls, 'not before start()').to.deep.equal([]);

			capacity = false;
			queue.start();
			await settle();
			expect(calls).to.deep.equal([]);
			expect(statusOf('q-1-a')).to.equal('queued');

			capacity = true;
			queue.poke();
			await settle();
			expect(calls).to.deep.equal(['lnbc_needs_capacity']);
			expect(statusOf('q-1-a')).to.equal('completed');

			// A stopped queue leaves it for the next start.
			seedWithAmount('q-2-b', 'lnbc_after_stop');
			capacity = false;
			const stopped = new PaymentQueue(pay, canSend, undefined, storage);
			stopped.start();
			stopped.stop();
			capacity = true;
			stopped.poke();
			await settle();
			expect(calls).to.deep.equal(['lnbc_needs_capacity']);
			expect(statusOf('q-2-b')).to.equal('queued');
		});

		// Review round 2 (C1): processQueue() is ungated for enqueue(), so one
		// enqueue between the boot and the first usable channel sent every
		// restored row into channels that could not carry it yet.
		it('an enqueue before start() dispatches only its own entry; restored rows wait for start()', async () => {
			seed('q-1-restored', 'lnbc_restored', 'queued', 1);
			seed('q-2-in-flight', 'lnbc_in_flight', 'dispatching', 1);
			const { calls, pay } = recordingPay();
			const unpaid = async (): Promise<InterruptedPaymentOutcome> => ({
				status: 'unpaid'
			});
			const queue = new PaymentQueue(
				pay,
				noopCanSend,
				{ resolveInterrupted: unpaid },
				storage
			);
			const fresh = queue.enqueue('lnbc_fresh', 5);
			await settle();
			expect(calls).to.deep.equal(['lnbc_fresh']);
			expect(statusOf(fresh.id)).to.equal('completed');
			expect(statusOf('q-1-restored')).to.equal('queued');
			expect(statusOf('q-2-in-flight')).to.equal('dispatching');

			queue.start();
			await settle();
			expect([...calls].sort()).to.deep.equal(
				['lnbc_fresh', 'lnbc_in_flight', 'lnbc_restored'].sort()
			);
			expect(statusOf('q-1-restored')).to.equal('completed');
			expect(statusOf('q-2-in-flight')).to.equal('completed');
		});

		// Review round 2 (C4): a canSend that throws is not a verdict on the
		// entry. BeignetNode's has no node to ask while a guardian restore is
		// pending, and a whole amount recorded failed for that is a payment
		// the operator has to enqueue again.
		it('a canSend that throws for a whole amount leaves the entry queued, and it dispatches once canSend answers', async () => {
			let broken = true;
			const canSend = (): { canSend: boolean; availableSats: number } => {
				if (broken) throw new TypeError('Cannot read properties of undefined');
				return { canSend: true, availableSats: 10_000 };
			};
			const { calls, pay } = recordingPay();
			const queue = new PaymentQueue(pay, canSend, undefined, storage);
			queue.start();
			const entry = queue.enqueue('lnbc_waits_for_a_node', 5, {
				amountSats: 1_000
			});
			await settle();
			expect(calls).to.deep.equal([]);
			expect(statusOf(entry.id)).to.equal('queued');
			expect(queue.list()[0].status).to.equal('queued');

			broken = false;
			queue.poke();
			await settle();
			expect(calls).to.deep.equal(['lnbc_waits_for_a_node']);
			expect(statusOf(entry.id)).to.equal('completed');
		});

		// Review round 2 (P4): null always behaved as absent, and generated
		// clients send it for an unset optional field.
		it('enqueue() takes an explicit null amountSats or maxFeeSats as absent', () => {
			const queue = new PaymentQueue(
				noopPay,
				noopCanSend,
				{ maxConcurrent: 0 },
				storage
			);
			const entry = queue.enqueue('lnbc_nulls', 5, {
				amountSats: null,
				maxFeeSats: null
			} as unknown as { amountSats?: number; maxFeeSats?: number });
			expect(entry.amountSats).to.equal(undefined);
			expect(entry.maxFeeSats).to.equal(undefined);
			const row = rowOf(entry.id);
			expect(row?.amountSats).to.equal(undefined);
			expect(row?.maxFeeSats).to.equal(undefined);
		});
	});

	it('metadata JSON round-trips', () => {
		const queue1 = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		queue1.enqueue('lnbc_meta', 5, {
			metadata: { orderId: '12345', customer: 'alice' }
		});

		const queue2 = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		const list = queue2.list();
		expect(list).to.have.lengthOf(1);
		expect(list[0].metadata).to.deep.equal({
			orderId: '12345',
			customer: 'alice'
		});
	});
});
