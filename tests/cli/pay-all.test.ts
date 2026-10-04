import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import { AddressInfo } from 'net';
import { startDaemon, IStartedDaemon } from '../../src/cli/daemon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IPaymentInfo,
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { createNode } from '../lightning/helpers/loopback-nodes';
import { getOpenApiSpec } from '../../src/cli/openapi';
import { getRouteScopes } from '../../src/cli/auth';

function request(port: number, route: string, body: unknown) {
	return new Promise<{
		status: number;
		body: {
			ok: boolean;
			result?: Record<string, unknown>;
			error?: { code: string };
		};
	}>((resolve, reject) => {
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
				res.on('end', () =>
					resolve({
						status: res.statusCode!,
						body: JSON.parse(Buffer.concat(chunks).toString())
					})
				);
			}
		);
		req.on('error', reject);
		req.end(payload);
	});
}

describe('Pay-all daemon and spending accounting', function () {
	this.timeout(30_000);
	let daemon: IStartedDaemon;
	let node: BeignetNode;
	let engine: LightningNode;
	let payee: LightningNode;
	let dir: string;
	let port: number;
	beforeEach(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-all-api-'));
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			daemonPort: 0,
			dataDir: dir,
			maxPaymentSats: 2000,
			dailySpendLimitSats: 10000
		});
		node = daemon.node;
		engine = (node as unknown as { node: LightningNode }).node;
		port = (daemon.server.address() as AddressInfo).port;
		payee = createNode('pay-all-api', 10);
	});
	afterEach(async () => {
		await daemon?.stop();
		payee?.destroy();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function record(hash: Buffer, debit = 1_999_001n): IPaymentInfo {
		return {
			paymentHash: hash,
			amountMsat: debit,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now(),
			payAll: {
				debitMsat: debit,
				maxFeeMsat: 500n,
				deliveredMsat: debit - 1n,
				feeMsat: 1n,
				remainderMsat: 0n
			},
			route: {
				hops: [],
				totalAmountMsat: debit,
				totalFeeMsat: 1n,
				totalCltvDelta: 0
			}
		};
	}
	function put(payment: IPaymentInfo): void {
		(engine as unknown as { payments: Map<string, IPaymentInfo> }).payments.set(
			payment.paymentHash.toString('hex'),
			payment
		);
	}

	it('forwards exact decimal strings through the quote without reserving spending capacity', async () => {
		engine.quotePayAll = (invoice, cap) => {
			expect(invoice).to.equal('invoice');
			expect(cap).to.equal(123n);
			return {
				debitMsat: 9_007_199_254_741_123n,
				maxFeeMsat: cap,
				minRecipientMsat: 9_007_199_254_741_000n,
				routeFound: true,
				remainderMsat: 0n,
				searchExhausted: false
			};
		};
		const response = await request(port, '/invoice/pay-all/quote', {
			bolt11: 'invoice',
			maxFeeMsat: '123'
		});
		expect(response.status).to.equal(200);
		expect(response.body.result!.debitMsat).to.equal('9007199254741123');
		expect(node.getDailySpendInfo().pendingSats).to.equal(0);
	});

	it('admits and charges only the debit, preserves legacy history and returns exact result fields', async () => {
		const invoice = payee.createInvoice({ description: 'api pay-all' });
		engine.sendPayAll = (bolt11, debit, cap) => {
			expect(bolt11).to.equal(invoice.bolt11);
			expect(debit).to.equal(1_999_001n);
			expect(cap).to.equal(500n);
			expect(node.getDailySpendInfo().pendingSats).to.equal(2000);
			const payment = record(invoice.paymentHash);
			payment.status = PaymentStatus.COMPLETED;
			put(payment);
			engine.emit('payment:sent', payment);
			return payment;
		};
		const response = await request(port, '/invoice/pay-all', {
			bolt11: invoice.bolt11,
			debitMsat: '1999001',
			maxFeeMsat: '500'
		});
		expect(response.status).to.equal(200);
		expect(response.body.result!.amountSats).to.equal(2000);
		expect(response.body.result!.payAll).to.deep.equal({
			debitMsat: '1999001',
			maxFeeMsat: '500',
			deliveredMsat: '1999000',
			feeMsat: '1',
			remainderMsat: '0'
		});
		expect(node.getDailySpendInfo().pendingSats).to.equal(0);
		expect(node.getDailySpendInfo().spentSats).to.equal(2000);
		expect(
			node.getPayment(invoice.paymentHash.toString('hex'))!.payAll
		).to.deep.equal(response.body.result!.payAll);
	});

	it('releases a duplicate request claim while preserving the original pending claim', async () => {
		const invoice = payee.createInvoice({ description: 'duplicate' });
		const payment = record(invoice.paymentHash);
		let inFlight = false;
		engine.hasHtlcInFlight = () => inFlight;
		engine.sendPayAll = () => {
			if (inFlight)
				throw new LightningPaymentError(
					LightningErrorCode.DUPLICATE_PAYMENT,
					'already in flight'
				);
			inFlight = true;
			put(payment);
			return payment;
		};
		const first = node.payInvoiceAll(invoice.bolt11, '1999001', '500');
		const duplicate = await request(port, '/invoice/pay-all', {
			bolt11: invoice.bolt11,
			debitMsat: '1999001',
			maxFeeMsat: '500'
		});
		expect(duplicate.body.error!.code).to.equal('DUPLICATE_PAYMENT');
		expect(node.getDailySpendInfo().pendingSats).to.equal(2000);
		inFlight = false;
		payment.status = PaymentStatus.COMPLETED;
		engine.emit('payment:sent', payment);
		await first;
		expect(node.getDailySpendInfo().pendingSats).to.equal(0);
	});

	it('retains the claim and freezes retries when dispatch throws after creating a live HTLC', async () => {
		const invoice = payee.createInvoice({ description: 'transport exception' });
		const payment = record(invoice.paymentHash);
		let frozen = false;
		engine.hasHtlcInFlight = () => true;
		engine.failPaymentUnlessInFlight = () => {
			frozen = true;
			return false;
		};
		engine.sendPayAll = () => {
			put(payment);
			throw new Error('transport failure');
		};
		try {
			await node.payInvoiceAll(invoice.bolt11, '1999001', '500');
			expect.fail('must reject');
		} catch (error) {
			expect(error).to.be.instanceOf(Error);
		}
		expect(frozen).to.equal(true);
		expect(node.getDailySpendInfo().pendingSats).to.equal(2000);
		expect(engine.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
	});

	it('maps expired reviews to 409 and releases their unspent claim', async () => {
		const invoice = payee.createInvoice({ description: 'expired review' });
		engine.sendPayAll = () => {
			throw new LightningPaymentError(
				LightningErrorCode.PAY_ALL_REVIEW_EXPIRED,
				'review expired'
			);
		};
		const response = await request(port, '/invoice/pay-all', {
			bolt11: invoice.bolt11,
			debitMsat: '1999001',
			maxFeeMsat: '500'
		});
		expect(response.status).to.equal(409);
		expect(response.body.error!.code).to.equal('PAY_ALL_REVIEW_EXPIRED');
		expect(node.getDailySpendInfo().pendingSats).to.equal(0);
	});

	it('rejects missing, fractional and unsafe numeric msat fields before admission', async () => {
		const invoice = payee.createInvoice({ description: 'invalid' });
		for (const debit of [undefined, '1.5', -1, Number.MAX_SAFE_INTEGER + 1]) {
			const response = await request(port, '/invoice/pay-all', {
				bolt11: invoice.bolt11,
				debitMsat: debit,
				maxFeeMsat: '0'
			});
			expect(response.status).to.equal(400);
		}
		expect(node.getDailySpendInfo().pendingSats).to.equal(0);
	});

	it('documents both routes and gives only the quote readonly scope', () => {
		const spec = getOpenApiSpec() as { paths: Record<string, unknown> };
		expect(spec.paths).to.have.property('/invoice/pay-all/quote');
		expect(spec.paths).to.have.property('/invoice/pay-all');
		expect(getRouteScopes('POST /invoice/pay-all/quote')).to.deep.equal([
			'readonly'
		]);
		expect(getRouteScopes('POST /invoice/pay-all')).to.deep.equal([]);
	});
});
