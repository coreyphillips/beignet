/**
 * Issue #967: the payment queue across a restart. Restored entries used to
 * dispatch only on the next unrelated enqueue, and an entry that was in
 * flight at the restart was restored 'queued' and sent again. sendPayment
 * refuses a second payment to a hash only while the first is PENDING, so a
 * payment that had COMPLETED was paid a second time. BeignetNode now settles
 * such an entry against its own record before anything sends it again.
 *
 * Offline suite: the node boots against an unreachable Electrum server, so
 * nothing here needs a chain or a channel.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import sinon from 'sinon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { QueuedPayment } from '../../src/cli/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	IOutgoingPaymentResolution,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

// Same rationale as tests/cli/pay-invoice-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const bootNode = (dataDir: string): Promise<BeignetNode> =>
	BeignetNode.create({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir,
		logLevel: 'silent',
		rapidGossipSync: false,
		autoGossipSync: false,
		...OFFLINE_ELECTRUM
	});

/** An invoice from somebody else, for a preimage the test knows. */
const invoiceFrom = (
	description: string,
	amountSats = 1_000
): { bolt11: string; paymentHash: Buffer; preimage: Buffer } => {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat: BigInt(amountSats) * 1000n,
			timestamp: Math.floor(Date.now() / 1000),
			paymentHash,
			paymentSecret: crypto.randomBytes(32),
			description,
			expiry: 3600,
			minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			privateKey: crypto
				.createHash('sha256')
				.update(Buffer.from(`payee-${description}`))
				.digest()
		}),
		paymentHash,
		preimage
	};
};

const resolution = (
	paymentHash: Buffer,
	status: PaymentStatus | null,
	preimage?: Buffer
): IOutgoingPaymentResolution => ({
	paymentHash,
	status,
	htlcs: [],
	resolved: true,
	latestOutstandingExpiry: null,
	...(preimage ? { preimage } : {})
});

const settle = (ms = 20): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/** Replaces payInvoiceSafe with a recorder that completes every payment. */
const stubPayInvoiceSafe = (node: BeignetNode): string[] => {
	const calls: string[] = [];
	(
		node as unknown as {
			payInvoiceSafe: (b: string) => Promise<unknown>;
		}
	).payInvoiceSafe = async (bolt11: string): Promise<unknown> => {
		calls.push(bolt11);
		return {
			paymentHash: 'stub',
			amountSats: 1_000,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: Date.now()
		};
	};
	return calls;
};

/** The queue entry once it reaches a status the queue leaves it in. */
const queueEntryOnceFinal = async (
	node: BeignetNode,
	id: string,
	timeoutMs = 10_000
): Promise<QueuedPayment> => {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const entry = node.listQueue().find((e) => e.id === id);
		if (entry && entry.status !== 'queued' && entry.status !== 'dispatching') {
			return entry;
		}
		if (Date.now() > deadline) {
			throw new Error(
				`queue entry ${id} never settled (last status: ${entry?.status})`
			);
		}
		await settle(25);
	}
};

describe('BeignetNode.resolveInterruptedPayment (issue #967)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-resolve-'));
		node = await bootNode(tmpDir);
	});

	afterEach(() => {
		sinon.restore();
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('is completed when the preimage is known, whatever the record says, and waits with no timeout', async () => {
		const { bolt11, paymentHash, preimage } = invoiceFrom('preimage');
		const wait = sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, PaymentStatus.FAILED, preimage));

		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'completed',
			paymentHash: paymentHash.toString('hex')
		});
		expect(wait.calledOnce).to.equal(true);
		expect((wait.firstCall.args[0] as Buffer).equals(paymentHash)).to.equal(
			true
		);
		expect(wait.firstCall.args[1]).to.equal(undefined);
	});

	it('is completed when the record says COMPLETED', async () => {
		const { bolt11, paymentHash } = invoiceFrom('completed');
		sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, PaymentStatus.COMPLETED));

		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'completed',
			paymentHash: paymentHash.toString('hex')
		});
	});

	it('is unpaid when every HTLC resolved and none revealed the preimage', async () => {
		const { bolt11, paymentHash } = invoiceFrom('failed');
		sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, PaymentStatus.FAILED));

		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'unpaid'
		});
	});

	it('is unpaid when the node has no record and offered nothing for the hash', async () => {
		const { bolt11 } = invoiceFrom('never sent');
		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'unpaid'
		});
	});

	it('waits while the payment is unresolved', async () => {
		const { bolt11, paymentHash, preimage } = invoiceFrom('held');
		let release!: (view: IOutgoingPaymentResolution) => void;
		sinon.stub(node.getNode(), 'awaitPaymentResolution').returns(
			new Promise<IOutgoingPaymentResolution>((resolve) => {
				release = resolve;
			})
		);

		let settled = false;
		const outcome = node.resolveInterruptedPayment(bolt11).then((o) => {
			settled = true;
			return o;
		});
		await settle(50);
		expect(settled).to.equal(false);

		release(resolution(paymentHash, PaymentStatus.COMPLETED, preimage));
		expect(await outcome).to.deep.equal({
			status: 'completed',
			paymentHash: paymentHash.toString('hex')
		});
	});

	it('is unpaid for a string that does not decode, without asking the node', async () => {
		const wait = sinon.stub(node.getNode(), 'awaitPaymentResolution');
		expect(
			await node.resolveInterruptedPayment('lnbcrt_not_an_invoice')
		).to.deep.equal({ status: 'unpaid' });
		expect(wait.called).to.equal(false);
	});

	it('throws while there is no node to ask, so the entry waits for the next start', async () => {
		const { bolt11 } = invoiceFrom('no node');
		const wait = sinon.stub(node.getNode(), 'awaitPaymentResolution');
		const flags = node as unknown as Record<string, boolean>;
		const expected: Array<[string, string]> = [
			['_restorePending', 'NODE_RESTORE_PENDING'],
			['_resuming', 'NODE_RESTORE_PENDING'],
			['_restartRequired', 'NODE_RESTART_REQUIRED'],
			['destroyed', 'NODE_DESTROYED']
		];
		for (const [flag, code] of expected) {
			flags[flag] = true;
			try {
				let refused: unknown;
				try {
					await node.resolveInterruptedPayment(bolt11);
				} catch (err: unknown) {
					refused = err;
				}
				expect((refused as { code?: string } | undefined)?.code, flag).to.equal(
					code
				);
			} finally {
				flags[flag] = false;
			}
		}
		expect(wait.called).to.equal(false);
	});
});

describe('BeignetNode.whenReadyToPay (issue #967)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;
	let flags: Record<string, boolean>;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-ready-'));
		node = await bootNode(tmpDir);
		flags = node as unknown as Record<string, boolean>;
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('runs once the node is ready', async () => {
		let runs = 0;
		node.whenReadyToPay(() => runs++);
		await settle();
		expect(runs).to.equal(1);
	});

	it('never runs while a capsule restore rebuilds the node or a restart is required', async () => {
		let runs = 0;
		for (const flag of ['_resuming', '_restartRequired']) {
			flags[flag] = true;
			try {
				node.whenReadyToPay(() => runs++);
				await settle();
			} finally {
				flags[flag] = false;
			}
		}
		expect(runs).to.equal(0);
	});

	it('waits for a pending guardian restore to finish', async () => {
		let runs = 0;
		const before = node.listenerCount('recovery:restored');
		flags._restorePending = true;
		try {
			node.whenReadyToPay(() => runs++);
			await settle();
			expect(runs).to.equal(0);
			expect(node.listenerCount('recovery:restored')).to.equal(before + 1);
		} finally {
			flags._restorePending = false;
		}
		node.emit('recovery:restored', {});
		await settle();
		expect(runs).to.equal(1);
		expect(node.listenerCount('recovery:restored')).to.equal(before);
	});

	it('a wait on a pending restore does not outlive shutdown', async () => {
		let runs = 0;
		flags._restorePending = true;
		try {
			node.whenReadyToPay(() => runs++);
		} finally {
			flags._restorePending = false;
		}
		await node.destroy();
		expect(node.listenerCount('recovery:restored')).to.equal(0);
		node.whenReadyToPay(() => runs++);
		await settle();
		expect(runs).to.equal(0);
	});
});

describe('A payment in flight at a restart is not paid again (issue #967)', function () {
	this.timeout(60_000);

	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-restart-'));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * Run 1: leave the node's record of an outgoing payment and a queue row
	 * the queue never got to update, as a stop mid-payment does.
	 */
	const seedRun = async (seed: (node: BeignetNode) => void): Promise<void> => {
		const first = await bootNode(tmpDir);
		try {
			seed(first);
		} finally {
			await first.destroy();
		}
	};

	const recordOutgoing = (
		node: BeignetNode,
		paymentHash: Buffer,
		status: PaymentStatus,
		preimage?: Buffer
	): void => {
		const storage = node.getStorage();
		const hashHex = paymentHash.toString('hex');
		storage.savePayment(hashHex, {
			paymentHash,
			...(preimage ? { preimage } : {}),
			amountMsat: 1_000_000n,
			status,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now() - 1_000,
			completedAt: Date.now()
		});
		if (preimage) storage.savePreimage(hashHex, preimage);
	};

	it('a payment that completed before the restart is recorded completed, and never sent again, even when another payment is enqueued first', async () => {
		const paid = invoiceFrom('paid before the restart');
		await seedRun((first) => {
			recordOutgoing(
				first,
				paid.paymentHash,
				PaymentStatus.COMPLETED,
				paid.preimage
			);
			first.getStorage().saveQueueEntry({
				id: 'q-1-967',
				bolt11: paid.bolt11,
				priority: 5,
				status: 'dispatching',
				createdAt: Date.now() - 1_000
			});
		});

		const second = await bootNode(tmpDir);
		try {
			const payCalls = stubPayInvoiceSafe(second);
			expect(second.listQueue().map((e) => e.id)).to.include('q-1-967');
			// Before the fix this dispatched the restored row again: the
			// engine does not refuse a hash whose record is COMPLETED.
			const other = invoiceFrom('an unrelated payment');
			const added = second.enqueuePayment(other.bolt11);

			const restored = await queueEntryOnceFinal(second, 'q-1-967');
			expect(restored.status).to.equal('completed');
			expect(payCalls).to.not.include(paid.bolt11);
			await queueEntryOnceFinal(second, added.id);
			expect(payCalls).to.deep.equal([other.bolt11]);
			const row = second
				.getStorage()
				.loadAllQueueEntries()
				.find((r) => r.id === 'q-1-967');
			expect(row?.status).to.equal('completed');
		} finally {
			await second.destroy();
		}
	});

	it('what was queued, or in flight and paid nothing, dispatches once the node is ready, with no enqueue', async () => {
		const unpaid = invoiceFrom('failed before the restart');
		const waiting = invoiceFrom('queued before the restart');
		await seedRun((first) => {
			recordOutgoing(first, unpaid.paymentHash, PaymentStatus.FAILED);
			const storage = first.getStorage();
			storage.saveQueueEntry({
				id: 'q-1-unpaid',
				bolt11: unpaid.bolt11,
				priority: 5,
				status: 'dispatching',
				createdAt: Date.now() - 1_000
			});
			storage.saveQueueEntry({
				id: 'q-2-waiting',
				bolt11: waiting.bolt11,
				priority: 5,
				status: 'queued',
				createdAt: Date.now() - 1_000
			});
		});

		const second = await bootNode(tmpDir);
		try {
			const payCalls = stubPayInvoiceSafe(second);
			// Only builds the queue: nothing is enqueued in this run.
			second.listQueue();

			expect((await queueEntryOnceFinal(second, 'q-1-unpaid')).status).to.equal(
				'completed'
			);
			expect(
				(await queueEntryOnceFinal(second, 'q-2-waiting')).status
			).to.equal('completed');
			expect([...payCalls].sort()).to.deep.equal(
				[unpaid.bolt11, waiting.bolt11].sort()
			);
		} finally {
			await second.destroy();
		}
	});
});
