/**
 * Tests for payment queue persistence — queued payments survive crashes.
 */

import { expect } from 'chai';
import { PaymentQueue } from '../../src/cli/payment-queue';
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

	it('dispatching entries reset to queued on restore (crash recovery)', () => {
		// Manually insert a "dispatching" entry into storage to simulate crash
		storage.saveQueueEntry({
			id: 'q-1-12345',
			bolt11: 'lnbc_crashed',
			priority: 5,
			status: 'dispatching',
			createdAt: Date.now()
		});

		const queue = new PaymentQueue(
			noopPay,
			noopCanSend,
			{ maxConcurrent: 0 },
			storage
		);
		const list = queue.list();
		expect(list).to.have.lengthOf(1);
		expect(list[0].status).to.equal('queued'); // Reset from dispatching
		expect(list[0].bolt11).to.equal('lnbc_crashed');
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

			// The next start restores them; they dispatch on its first enqueue.
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
