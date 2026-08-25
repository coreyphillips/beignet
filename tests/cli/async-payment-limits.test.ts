/**
 * Async payment admission (issue #526): sendPaymentAsync and the
 * POST /invoice/pay-async route apply drain mode, the per-payment and daily
 * spending limits, and the same pending-spend reservation payInvoice applies,
 * despite returning before the payment settles.
 *
 * Offline suite: the node boots against an unreachable Electrum server and the
 * engine's sendPayment is stubbed, so nothing here needs a chain or a channel.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetNode } from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';

// Same rationale as tests/cli/agent-production-hardening.ts: a refused loopback
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
	_asyncSpendReservations: Map<string, number>;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

/** Replaces sendPayment with a recorder; returns the recorded submissions. */
const stubSendPayment = (node: BeignetNode, throws?: Error): string[] => {
	const calls: string[] = [];
	internals(node).node.sendPayment = (...args: unknown[]): unknown => {
		calls.push(String(args[0]));
		if (throws) throw throws;
		return undefined;
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

describe('sendPaymentAsync admission and spend accounting (#526)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-async-'));
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

	it('refuses a new payment while draining, without reaching the engine', () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = node.createInvoice(1_000, 'draining');
		node.setDraining(true);

		expect(() => node.sendPaymentAsync(bolt11)).to.throw('Node is draining');
		expect(calls).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('refuses a payment over the per-payment limit', () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = node.createInvoice(5_001, 'too big');

		expect(() => node.sendPaymentAsync(bolt11)).to.throw(
			'exceeds per-payment limit'
		);
		expect(calls).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('enforces the per-payment limit on the amount override of an amountless invoice', () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = node.createInvoice(undefined, 'amountless');

		expect(() => node.sendPaymentAsync(bolt11, undefined, 5_001)).to.throw(
			'exceeds per-payment limit'
		);
		expect(calls).to.have.length(0);
	});

	it('reserves the amount while pending so concurrent submissions cannot overshoot the daily limit', () => {
		const calls = stubSendPayment(node);
		const first = node.sendPaymentAsync(
			node.createInvoice(4_000, 'first').bolt11
		);
		const second = node.sendPaymentAsync(
			node.createInvoice(4_000, 'second').bolt11
		);
		expect(first.status).to.equal('PENDING');
		expect(second.status).to.equal('PENDING');
		expect(internals(node)._pendingSpendSats).to.equal(8_000);
		// Nothing has settled, so the reported spend is still zero: it is the
		// reservation, not the spend, that has to refuse the third payment.
		expect(node.getDailySpendInfo().spentSats).to.equal(0);

		const third = node.createInvoice(4_000, 'third').bolt11;
		expect(() => node.sendPaymentAsync(third)).to.throw(
			'Daily spend limit exceeded'
		);
		expect(calls).to.have.length(2);
	});

	it('records the spend once and drops the reservation on settlement', () => {
		stubSendPayment(node);
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(3_000, 'settles').bolt11
		);
		expect(internals(node)._pendingSpendSats).to.equal(3_000);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(internals(node)._pendingSpendSats).to.equal(0);
		const info = node.getDailySpendInfo();
		expect(info.spentSats).to.equal(3_000);
		expect(info.lightningSats).to.equal(3_000);

		// A repeated terminal event must not count the payment twice.
		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('releases the reservation on failure without recording a spend', () => {
		stubSendPayment(node);
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(3_000, 'fails').bolt11
		);

		settle(node, paymentHash, 3_000, 'FAILED');
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(node.getDailySpendInfo().spentSats).to.equal(0);
		expect(internals(node)._asyncSpendReservations.size).to.equal(0);
	});

	it('releases the reservation when the engine refuses the submission', () => {
		stubSendPayment(node, new Error('No route found'));
		const { bolt11 } = node.createInvoice(3_000, 'no route');

		expect(() => node.sendPaymentAsync(bolt11)).to.throw('No route found');
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(internals(node)._asyncSpendReservations.size).to.equal(0);
		// The budget is intact: a payment that never started holds no capacity.
		expect(() => node.sendPaymentAsync(bolt11)).to.throw('No route found');
	});

	it('leaves the accounting alone for an amountless invoice with no override', () => {
		stubSendPayment(node);
		const { bolt11 } = node.createInvoice(undefined, 'amountless');

		expect(node.sendPaymentAsync(bolt11).status).to.equal('PENDING');
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(internals(node)._asyncSpendReservations.size).to.equal(0);
	});
});

describe('POST /invoice/pay-async admission (#526)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;
	let calls: string[];

	const post = (
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: '/invoice/pay-async',
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
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-async-api-'));
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
		calls = stubSendPayment(node);
	});

	after(async () => {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('answers 403 SPENDING_LIMIT_EXCEEDED over the per-payment limit', async () => {
		const { bolt11 } = node.createInvoice(5_001, 'too big');
		const res = await post({ bolt11 });
		expect(res.status).to.equal(403);
		expect((res.body.error as { code: string }).code).to.equal(
			'SPENDING_LIMIT_EXCEEDED'
		);
		expect(calls).to.have.length(0);
	});

	it('answers 409 SERVICE_DRAINING while draining', async () => {
		const { bolt11 } = node.createInvoice(1_000, 'draining');
		node.setDraining(true);
		try {
			const res = await post({ bolt11 });
			expect(res.status).to.equal(409);
			expect((res.body.error as { code: string }).code).to.equal(
				'SERVICE_DRAINING'
			);
			expect(calls).to.have.length(0);
		} finally {
			node.setDraining(false);
		}
	});

	it('reserves an accepted payment against the daily budget', async () => {
		const accepted = await post({
			bolt11: node.createInvoice(4_000, 'accepted').bolt11
		});
		expect(accepted.body.ok).to.equal(true);
		expect(calls).to.have.length(1);
		expect(internals(node)._pendingSpendSats).to.equal(4_000);

		const overshoot = await post({
			bolt11: node.createInvoice(4_000, 'overshoot').bolt11
		});
		expect(overshoot.body.ok).to.equal(true);
		const refused = await post({
			bolt11: node.createInvoice(4_000, 'refused').bolt11
		});
		expect(refused.status).to.equal(403);
		expect((refused.body.error as { code: string }).code).to.equal(
			'SPENDING_LIMIT_EXCEEDED'
		);
		expect(calls).to.have.length(2);
	});
});
