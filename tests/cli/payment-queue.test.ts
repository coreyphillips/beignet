import { expect } from 'chai';
import { PaymentQueue } from '../../src/cli/payment-queue';

describe('PaymentQueue', () => {
	const mockPayInvoiceSafe = async (
		_bolt11: string
	): Promise<{ status: string; paymentHash: string }> => {
		return { status: 'COMPLETED', paymentHash: 'abc123' };
	};
	const mockCanSend = (
		_amount: number
	): { canSend: boolean; availableSats: number } => {
		return { canSend: true, availableSats: 1_000_000 };
	};

	it('enqueue() adds a payment to the queue with unique ID', () => {
		const pq = new PaymentQueue(mockPayInvoiceSafe, mockCanSend);
		const entry = pq.enqueue('lnbc1000...');
		expect(entry.id).to.be.a('string');
		expect(entry.id).to.match(/^q-\d+-\d+$/);
		expect(entry.bolt11).to.equal('lnbc1000...');
		expect(entry.status).to.equal('queued');
		expect(entry.priority).to.equal(5);
		expect(entry.createdAt).to.be.a('number');

		// Second enqueue gets a different ID
		const entry2 = pq.enqueue('lnbc2000...');
		expect(entry2.id).to.not.equal(entry.id);
	});

	it('enqueue() sorts by priority (lower number first)', () => {
		// Use a payInvoiceSafe that never resolves so nothing gets dispatched during test
		const slowPay = (): Promise<{ status: string; paymentHash: string }> =>
			new Promise(() => {});
		// canSend returns false so nothing dispatches
		const noSend = (
			_a: number
		): { canSend: boolean; availableSats: number } => ({
			canSend: false,
			availableSats: 0
		});
		const pq = new PaymentQueue(slowPay, noSend);

		pq.enqueue('inv-low', 10, { amountSats: 100 });
		pq.enqueue('inv-high', 1, { amountSats: 100 });
		pq.enqueue('inv-mid', 5, { amountSats: 100 });

		const list = pq.list();
		expect(list[0].priority).to.equal(1);
		expect(list[0].bolt11).to.equal('inv-high');
		expect(list[1].priority).to.equal(5);
		expect(list[1].bolt11).to.equal('inv-mid');
		expect(list[2].priority).to.equal(10);
		expect(list[2].bolt11).to.equal('inv-low');
	});

	it('enqueue() throws if bolt11 is empty', () => {
		const pq = new PaymentQueue(mockPayInvoiceSafe, mockCanSend);
		expect(() => pq.enqueue('')).to.throw('bolt11 is required');
	});

	it('enqueue() throws if priority is out of range', () => {
		const pq = new PaymentQueue(mockPayInvoiceSafe, mockCanSend);
		expect(() => pq.enqueue('lnbc1000...', 0)).to.throw(
			'priority must be between 1 and 10'
		);
		expect(() => pq.enqueue('lnbc1000...', 11)).to.throw(
			'priority must be between 1 and 10'
		);
	});

	it('cancel() removes a queued payment', () => {
		// canSend returns false so nothing dispatches
		const noSend = (
			_a: number
		): { canSend: boolean; availableSats: number } => ({
			canSend: false,
			availableSats: 0
		});
		const pq = new PaymentQueue(mockPayInvoiceSafe, noSend);
		const entry = pq.enqueue('lnbc1000...', 5, { amountSats: 100 });
		expect(pq.pendingCount).to.equal(1);

		const result = pq.cancel(entry.id);
		expect(result).to.be.true;
		expect(pq.pendingCount).to.equal(0);
	});

	it('cancel() returns false for unknown ID', () => {
		const pq = new PaymentQueue(mockPayInvoiceSafe, mockCanSend);
		expect(pq.cancel('nonexistent-id')).to.be.false;
	});

	it('cancel() returns false for non-queued (dispatching) payment', async () => {
		// Use a payInvoiceSafe that never resolves so payment stays in dispatching state
		const slowPay = (): Promise<{ status: string; paymentHash: string }> =>
			new Promise(() => {});
		const pq = new PaymentQueue(slowPay, mockCanSend);
		const entry = pq.enqueue('lnbc1000...');

		// Wait for microtask to allow processQueue to run
		await new Promise((resolve) => setTimeout(resolve, 10));

		// The entry is now dispatching
		const list = pq.list();
		const dispatching = list.find((e) => e.id === entry.id);
		expect(dispatching?.status).to.equal('dispatching');

		// Attempting to cancel a dispatching payment returns false
		expect(pq.cancel(entry.id)).to.be.false;
	});

	it('list() returns all queue entries', () => {
		const noSend = (
			_a: number
		): { canSend: boolean; availableSats: number } => ({
			canSend: false,
			availableSats: 0
		});
		const pq = new PaymentQueue(mockPayInvoiceSafe, noSend);
		pq.enqueue('inv1', 3, { amountSats: 100 });
		pq.enqueue('inv2', 7, { amountSats: 200 });

		const list = pq.list();
		expect(list).to.have.length(2);
		expect(list[0].bolt11).to.equal('inv1');
		expect(list[1].bolt11).to.equal('inv2');

		// list returns copies (modifying returned items should not affect queue)
		list[0].bolt11 = 'modified';
		expect(pq.list()[0].bolt11).to.equal('inv1');
	});

	it('prune() removes completed/failed entries', async () => {
		const pq = new PaymentQueue(mockPayInvoiceSafe, mockCanSend);
		pq.enqueue('inv1');

		// Wait for payment to complete
		await new Promise<void>((resolve) => {
			pq.on('queue:completed', () => resolve());
		});

		expect(pq.list()).to.have.length(1);
		expect(pq.list()[0].status).to.equal('completed');

		const pruned = pq.prune();
		expect(pruned).to.equal(1);
		expect(pq.list()).to.have.length(0);
	});

	it('maxConcurrent limits active dispatches', async () => {
		const resolvers: Array<
			(v: { status: string; paymentHash: string }) => void
		> = [];
		const slowPay = (): Promise<{ status: string; paymentHash: string }> => {
			return new Promise((resolve) => {
				resolvers.push(resolve);
			});
		};
		const pq = new PaymentQueue(slowPay, mockCanSend, { maxConcurrent: 2 });

		pq.enqueue('inv1');
		pq.enqueue('inv2');
		pq.enqueue('inv3');

		// Wait for first two to dispatch
		await new Promise((resolve) => setTimeout(resolve, 20));

		expect(pq.activePayments).to.equal(2);
		expect(pq.pendingCount).to.equal(1);

		// Complete first payment, third should start
		resolvers[0]({ status: 'COMPLETED', paymentHash: 'h1' });
		await new Promise((resolve) => setTimeout(resolve, 20));

		expect(pq.activePayments).to.equal(2);
		expect(pq.pendingCount).to.equal(0);

		// Resolve remaining
		resolvers[1]({ status: 'COMPLETED', paymentHash: 'h2' });
		resolvers[2]({ status: 'COMPLETED', paymentHash: 'h3' });
		await new Promise((resolve) => setTimeout(resolve, 20));

		expect(pq.activePayments).to.equal(0);
	});

	it('dispatch calls payInvoiceSafe with correct args', async () => {
		let capturedArgs: unknown[] = [];
		const capturePay = async (
			bolt11: string,
			timeoutMs?: number,
			maxFeeSats?: number,
			amountSats?: number,
			metadata?: Record<string, string>
		): Promise<{ status: string; paymentHash: string }> => {
			capturedArgs = [bolt11, timeoutMs, maxFeeSats, amountSats, metadata];
			return { status: 'COMPLETED', paymentHash: 'abc' };
		};
		const pq = new PaymentQueue(capturePay, mockCanSend, {
			paymentTimeoutMs: 30_000
		});

		pq.enqueue('lnbc500...', 3, {
			amountSats: 500,
			maxFeeSats: 10,
			metadata: { ref: 'order-42' }
		});

		await new Promise<void>((resolve) => {
			pq.on('queue:completed', () => resolve());
		});

		expect(capturedArgs[0]).to.equal('lnbc500...');
		expect(capturedArgs[1]).to.equal(30_000); // paymentTimeoutMs
		expect(capturedArgs[2]).to.equal(10); // maxFeeSats
		expect(capturedArgs[3]).to.equal(500); // amountSats
		expect(capturedArgs[4]).to.deep.equal({ ref: 'order-42' }); // metadata
	});

	it('completed payment emits queue:completed event', async () => {
		const pq = new PaymentQueue(mockPayInvoiceSafe, mockCanSend);

		const eventPromise = new Promise<{ id: string; paymentHash: string }>(
			(resolve) => {
				pq.on('queue:completed', (data: { id: string; paymentHash: string }) =>
					resolve(data)
				);
			}
		);

		const entry = pq.enqueue('lnbc1000...');
		const event = await eventPromise;

		expect(event.id).to.equal(entry.id);
		expect(event.paymentHash).to.equal('abc123');
	});

	it('failed payment emits queue:failed event', async () => {
		const failPay = async (): Promise<{
			status: string;
			paymentHash: string;
		}> => {
			return { status: 'FAILED', paymentHash: 'fail123' };
		};
		const pq = new PaymentQueue(failPay, mockCanSend);

		const eventPromise = new Promise<{ id: string; error: string }>(
			(resolve) => {
				pq.on('queue:failed', (data: { id: string; error: string }) =>
					resolve(data)
				);
			}
		);

		const entry = pq.enqueue('lnbc1000...');
		const event = await eventPromise;

		expect(event.id).to.equal(entry.id);
		expect(event.error).to.include('FAILED');
	});

	it('canSend check prevents dispatch when insufficient capacity', async () => {
		const noCapacity = (
			_amount: number
		): { canSend: boolean; availableSats: number } => {
			return { canSend: false, availableSats: 0 };
		};
		const pq = new PaymentQueue(mockPayInvoiceSafe, noCapacity);

		pq.enqueue('lnbc1000...', 5, { amountSats: 50000 });

		await new Promise((resolve) => setTimeout(resolve, 20));

		// Payment should remain queued since canSend returned false
		expect(pq.pendingCount).to.equal(1);
		expect(pq.activePayments).to.equal(0);
		expect(pq.list()[0].status).to.equal('queued');
	});
});
