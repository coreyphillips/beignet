/**
 * Blocking payment admission (issue #528): payInvoice and everything that
 * delegates to it (payInvoiceSafe, payInvoiceWithRetry, the payment queue and
 * the HTTP routes) apply the spending limits, the pending reservation and the
 * daily accounting to the amount the engine will actually pay — the invoice's
 * own amount whenever it carries one, and the caller's amountSats only for an
 * amountless invoice.
 *
 * Offline suite: the node boots against an unreachable Electrum server and the
 * engine's sendPayment is stubbed, so nothing here needs a chain or a channel.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetNode } from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';
import { QueuedPayment } from '../../src/cli/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';

// Same rationale as tests/cli/async-payment-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

type StubbedEngine = {
	sendPayment: (...args: unknown[]) => unknown;
	emit: (event: string, info: unknown) => boolean;
};

type Internals = {
	node: StubbedEngine;
	_pendingSpendSats: number;
	_blockingPaymentHashes: Map<string, number>;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

/**
 * An invoice from somebody else, which is what a payment path is given. A
 * self-issued invoice already has a payment record of its own, and both the
 * engine's duplicate check and payInvoiceSafe's "return the persisted record"
 * fallback answer from it.
 */
const invoiceFrom = (
	amountSats: number | undefined,
	description: string
): { bolt11: string; paymentHash: string } => {
	const paymentHash = crypto.randomBytes(32);
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat:
				amountSats !== undefined ? BigInt(amountSats) * 1000n : undefined,
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
		paymentHash: paymentHash.toString('hex')
	};
};

/** Replaces sendPayment with a recorder; returns the recorded submissions. */
const stubSendPayment = (node: BeignetNode): string[] => {
	const calls: string[] = [];
	internals(node).node.sendPayment = (...args: unknown[]): unknown => {
		calls.push(String(args[0]));
		return { status: 'PENDING' };
	};
	return calls;
};

/** Emits the engine event that settles a payment, as the real node would. */
const settle = (
	node: BeignetNode,
	paymentHash: string,
	amountSats: number,
	status: 'COMPLETED' | 'FAILED'
): void => {
	internals(node).node.emit(
		status === 'COMPLETED' ? 'payment:sent' : 'payment:failed',
		{
			paymentHash: Buffer.from(paymentHash, 'hex'),
			amountMsat: BigInt(amountSats) * 1000n,
			status,
			direction: 'OUTGOING',
			createdAt: Date.now(),
			completedAt: Date.now()
		}
	);
};

/** The message a payment attempt was refused with, or '' if it resolved. */
const refusalOf = async (attempt: Promise<unknown>): Promise<string> => {
	try {
		await attempt;
		return '';
	} catch (err: unknown) {
		return err instanceof Error ? err.message : String(err);
	}
};

/** The queue entry once the queue has finished with it. */
const settledQueueEntry = async (
	node: BeignetNode,
	id: string
): Promise<QueuedPayment> => {
	for (let i = 0; i < 200; i++) {
		const entry = node.listQueue().find((e) => e.id === id);
		if (entry && entry.status !== 'queued' && entry.status !== 'dispatching') {
			return entry;
		}
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
	throw new Error(`queue entry ${id} never settled`);
};

describe('payInvoice admission on a fixed-amount invoice (#528)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-limits-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			...OFFLINE_ELECTRUM
		});
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('limits a fixed-amount invoice by its own amount, not by the override', async () => {
		const calls = stubSendPayment(node);
		// The engine pays the encoded 6 000 sats whatever the override says, so
		// admitting the payment on the override's word waves it past both limits.
		const { bolt11 } = invoiceFrom(6_000, 'fixed');

		expect(
			await refusalOf(node.payInvoice(bolt11, 5_000, undefined, 1))
		).to.contain('Payment amount 6000 sats exceeds per-payment limit');
		// Zero is the worse case: it used to skip the checks altogether.
		expect(
			await refusalOf(node.payInvoice(bolt11, 5_000, undefined, 0))
		).to.contain('Payment amount 6000 sats exceeds per-payment limit');

		expect(calls).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);
	});

	it('refuses a fixed invoice the daily budget can no longer cover', async () => {
		const calls = stubSendPayment(node);
		for (const description of ['first', 'second']) {
			const invoice = invoiceFrom(4_000, description);
			const paid = node.payInvoice(invoice.bolt11, 5_000);
			settle(node, invoice.paymentHash, 4_000, 'COMPLETED');
			await paid;
		}
		expect(node.getDailySpendInfo().spentSats).to.equal(8_000);

		const { bolt11 } = invoiceFrom(4_000, 'over budget');
		const refusal = await refusalOf(
			node.payInvoice(bolt11, 5_000, undefined, 1)
		);
		expect(refusal).to.contain('Daily spend limit exceeded');
		expect(refusal).to.contain('requested: 4000 sats');
		expect(calls).to.have.length(2);
	});

	it('reserves and records the encoded amount when the override understates it', async () => {
		stubSendPayment(node);
		const invoice = invoiceFrom(3_000, 'understated');

		const paid = node.payInvoice(invoice.bolt11, 5_000, undefined, 1);
		// Reserving the override left 9 999 sats of a 10 000 sat budget apparently
		// free while 3 000 were on their way out.
		expect(internals(node)._pendingSpendSats).to.equal(3_000);

		settle(node, invoice.paymentHash, 3_000, 'COMPLETED');
		await paid;
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(node.getDailySpendInfo().lightningSats).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('still admits an amountless invoice on the override, which is what gets paid', async () => {
		const calls = stubSendPayment(node);
		const invoice = invoiceFrom(undefined, 'amountless');

		expect(
			await refusalOf(node.payInvoice(invoice.bolt11, 5_000, undefined, 5_001))
		).to.contain('exceeds per-payment limit');

		const paid = node.payInvoice(invoice.bolt11, 5_000, undefined, 4_000);
		expect(internals(node)._pendingSpendSats).to.equal(4_000);
		expect(calls).to.have.length(1);

		settle(node, invoice.paymentHash, 4_000, 'COMPLETED');
		await paid;
		expect(node.getDailySpendInfo().spentSats).to.equal(4_000);
	});

	it('leaves an amountless invoice with no override for the engine to refuse', async () => {
		// Unstubbed on purpose: there is nothing to admit, and the failure has to
		// stay the engine's own MISSING_AMOUNT.
		const { bolt11 } = invoiceFrom(undefined, 'no amount anywhere');

		expect(await refusalOf(node.payInvoice(bolt11, 5_000))).to.contain(
			'Invoice has no amount'
		);
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);
	});

	it('reports the refusal through payInvoiceSafe rather than paying', async () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = invoiceFrom(6_000, 'safe');

		const result = await node.payInvoiceSafe(bolt11, 5_000, undefined, 1);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.contain('SPENDING_LIMIT_EXCEEDED');
		expect(calls).to.have.length(0);
	});

	it('does not retry a fixed invoice past the limits', async () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = invoiceFrom(6_000, 'retried');

		const result = await node.payInvoiceWithRetry(bolt11, { amountSats: 0 });
		expect(result.status).to.equal('FAILED');
		expect(result.attempts).to.equal(1);
		expect(result.failureDescription).to.contain('exceeds per-payment limit');
		expect(calls).to.have.length(0);
	});

	it('queues a fixed invoice at its encoded amount', async () => {
		const calls = stubSendPayment(node);
		// The queue's own capacity gate is not what is under test, and an offline
		// node has no channels to pass it with.
		const alwaysHasCapacity = (): { canSend: boolean } => ({ canSend: true });
		(node as unknown as { canSend: typeof alwaysHasCapacity }).canSend =
			alwaysHasCapacity;
		const { bolt11 } = invoiceFrom(6_000, 'queued');

		const entry = node.enqueuePayment(bolt11, 1, { amountSats: 1 });
		const settled = await settledQueueEntry(node, entry.id);
		expect(settled.status).to.equal('failed');
		// The limits refused it, so the engine never saw it.
		expect(calls).to.have.length(0);
	});

	it('previews the amount the engine will pay', () => {
		const { bolt11 } = invoiceFrom(6_000, 'preview');
		const result = node.validatePayment(bolt11, 1);

		expect(result.status).to.equal('FAIL');
		const check = (name: string): string =>
			result.checks.find((c) => c.name === name)?.message ?? '';
		expect(check('AMOUNT')).to.contain('6000');
		// Reporting the override's 1 sat told a caller a payment was within limits
		// that payInvoice would refuse outright.
		expect(check('MAX_PAYMENT')).to.contain(
			'Amount 6000 sats exceeds per-payment limit'
		);
		expect(
			result.checks.find((c) => c.name === 'MAX_PAYMENT')?.status
		).to.equal('FAIL');
	});
});

describe('HTTP payment routes admit the encoded amount (#528)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	const post = (
		route: string,
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: route,
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Content-Length': Buffer.byteLength(payload)
					}
				},
				(res) => {
					const chunks: Buffer[] = [];
					res.on('data', (chunk: Buffer) => chunks.push(chunk));
					res.on('end', () => {
						try {
							resolve({
								status: res.statusCode!,
								body: JSON.parse(Buffer.concat(chunks).toString())
							});
						} catch {
							resolve({ status: res.statusCode!, body: {} });
						}
					});
				}
			);
			req.on('error', reject);
			req.write(payload);
			req.end();
		});

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-limits-api-'));
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			daemonPort: 0,
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			...OFFLINE_ELECTRUM
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async () => {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('answers 403 SPENDING_LIMIT_EXCEEDED whatever the override says', async () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = invoiceFrom(6_000, 'route fixed');

		for (const amountSats of [1, 0]) {
			const res = await post('/invoice/pay', { bolt11, amountSats });
			expect(res.status).to.equal(403);
			expect((res.body.error as { code: string }).code).to.equal(
				'SPENDING_LIMIT_EXCEEDED'
			);
		}
		expect(calls).to.have.length(0);
	});

	it('reports the refusal on the never-throwing routes', async () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = invoiceFrom(6_000, 'route safe');

		const safe = await post('/invoice/pay-safe', { bolt11, amountSats: 1 });
		expect(safe.body.ok).to.equal(true);
		const safeResult = safe.body.result as {
			status: string;
			failureDescription: string;
		};
		expect(safeResult.status).to.equal('FAILED');
		expect(safeResult.failureDescription).to.contain('SPENDING_LIMIT_EXCEEDED');

		const retry = await post('/invoice/pay-retry', { bolt11, amountSats: 1 });
		expect(retry.body.ok).to.equal(true);
		const retryResult = retry.body.result as {
			status: string;
			attempts: number;
		};
		expect(retryResult.status).to.equal('FAILED');
		expect(retryResult.attempts).to.equal(1);

		expect(calls).to.have.length(0);
	});

	it('validates against the encoded amount', async () => {
		const { bolt11 } = invoiceFrom(6_000, 'route validate');
		const res = await post('/invoice/validate', { bolt11, amountSats: 1 });

		const checks = (
			res.body.result as { checks: Array<{ name: string; message: string }> }
		).checks;
		const maxPayment = checks.find((c) => c.name === 'MAX_PAYMENT');
		expect(maxPayment?.message).to.contain(
			'Amount 6000 sats exceeds per-payment limit'
		);
	});
});
