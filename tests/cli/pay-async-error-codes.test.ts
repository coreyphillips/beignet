/**
 * Issue #991: POST /invoice/pay-async answered 502 PAYMENT_FAILED for every
 * refusal the engine threw. sendPaymentAsync let the engine's
 * LightningPaymentError through unmapped, and the route, seeing no
 * BeignetError, flattened it. A duplicate (a hash already paid, or one with
 * an HTLC still out), no route, an expired invoice and the rest are permanent
 * for the same request, and 502 is the status an agent retries on, so it
 * kept resubmitting a payment that was already made. payInvoice mapped the
 * same errors to their own codes; now one helper does it for every payment
 * method.
 *
 * Offline suite: the node boots against an unreachable Electrum server. The
 * duplicate is refused from a durable COMPLETED row, the no-route from an
 * empty graph; the remaining codes come from a stubbed engine.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	IStartedDaemon,
	startDaemon,
	statusForErrorCode
} from '../../src/cli/daemon';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

const TOKEN = 'pay-async-codes-token';

// A refused loopback connect returns instantly, where the regtest default is
// a public host (the pay-invoice-limits pattern).
const BOOT = {
	mnemonic:
		'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
	network: 'regtest' as const,
	logLevel: 'silent' as const,
	rapidGossipSync: false,
	autoGossipSync: false,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

/** An invoice from somebody else, for a preimage the test knows. */
const invoiceFrom = (
	description: string
): { bolt11: string; paymentHash: Buffer; preimage: Buffer } => {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat: 1_000_000n,
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

/** A paid OUTGOING row in storage alone, as the 24-hour prune leaves it. */
const seedPaidRow = (
	node: BeignetNode,
	description: string
): { bolt11: string; hashHex: string } => {
	const { bolt11, paymentHash, preimage } = invoiceFrom(description);
	const hashHex = paymentHash.toString('hex');
	node.getStorage().savePayment(hashHex, {
		paymentHash,
		preimage,
		amountMsat: 1_000_000n,
		status: PaymentStatus.COMPLETED,
		direction: PaymentDirection.OUTGOING,
		createdAt: Date.now() - 2_000,
		completedAt: Date.now() - 1_000
	});
	expect(node.getPayment(hashHex), 'memory holds nothing').to.equal(null);
	return { bolt11, hashHex };
};

type Engine = {
	sendPayment: (...args: unknown[]) => unknown;
	sendKeysend: (...args: unknown[]) => unknown;
};

const engineOf = (node: BeignetNode): Engine =>
	(node as unknown as { node: Engine }).node;

const pendingSats = (node: BeignetNode): number =>
	(node as unknown as { _pendingSpendSats: number })._pendingSpendSats;

/** What a synchronous call threw, which has to be a BeignetError. */
const thrownBy = (run: () => unknown): BeignetError => {
	let thrown: unknown;
	try {
		run();
	} catch (err) {
		thrown = err;
	}
	expect(thrown, 'nothing was thrown').to.not.equal(undefined);
	expect(thrown).to.be.instanceOf(BeignetError);
	return thrown as BeignetError;
};

/** The BeignetError a rejected promise carries. */
const rejectedWith = async (
	run: () => Promise<unknown>
): Promise<BeignetError> => {
	let thrown: unknown;
	try {
		await run();
	} catch (err) {
		thrown = err;
	}
	expect(thrown, 'the promise resolved').to.not.equal(undefined);
	expect(thrown).to.be.instanceOf(BeignetError);
	return thrown as BeignetError;
};

/** One authenticated request to the daemon, JSON in and out. */
const request = (
	port: number,
	method: string,
	urlPath: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> =>
	new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {
			Authorization: `Bearer ${TOKEN}`
		};
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
		const req = http.request(
			{ hostname: '127.0.0.1', port, path: urlPath, method, headers },
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch (err) {
						reject(err);
					}
				});
			}
		);
		req.on('error', reject);
		if (payload) req.write(payload);
		req.end();
	});

describe('sendPaymentAsync answers an engine refusal with a BeignetError (issue #991)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-async-codes-'));
		node = await BeignetNode.create({ ...BOOT, dataDir: tmpDir });
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('refuses a hash whose durable record says it was paid with DUPLICATE_PAYMENT', () => {
		const { bolt11 } = seedPaidRow(node, 'pruned paid');

		// Before the fix this threw the engine's LightningPaymentError itself.
		const err = thrownBy(() => node.sendPaymentAsync(bolt11));
		expect(err.code).to.equal(BeignetErrorCode.DUPLICATE_PAYMENT);
		expect(err.message).to.include('already completed');
		// A payment that never started holds no capacity.
		expect(pendingSats(node)).to.equal(0);
	});

	it('refuses a hash with an attempt still out with DUPLICATE_PAYMENT, typed or by message', () => {
		const { bolt11 } = invoiceFrom('in flight');
		engineOf(node).sendPayment = (): never => {
			throw new LightningPaymentError(
				LightningErrorCode.DUPLICATE_PAYMENT,
				'Payment already in flight for this invoice'
			);
		};
		expect(thrownBy(() => node.sendPaymentAsync(bolt11)).code).to.equal(
			BeignetErrorCode.DUPLICATE_PAYMENT
		);

		// payInvoice's string fallback for an untyped throw, kept as it was.
		engineOf(node).sendPayment = (): never => {
			throw new Error('Payment already in flight');
		};
		expect(thrownBy(() => node.sendPaymentAsync(bolt11)).code).to.equal(
			BeignetErrorCode.DUPLICATE_PAYMENT
		);
		expect(pendingSats(node)).to.equal(0);
	});

	it('answers NO_ROUTE for an invoice nothing can reach', () => {
		// Nothing stubbed: the node has no channel and no graph.
		const { bolt11 } = invoiceFrom('unreachable');
		const err = thrownBy(() => node.sendPaymentAsync(bolt11));
		expect(err.code).to.equal(BeignetErrorCode.NO_ROUTE);
	});

	it('maps every typed engine code the way payInvoice does', () => {
		const cases: Array<[LightningErrorCode, string]> = [
			[LightningErrorCode.NO_ROUTE, 'NO_ROUTE'],
			[LightningErrorCode.NO_CHANNEL_TO_HOP, 'PEER_NOT_CONNECTED'],
			[LightningErrorCode.FEE_EXCEEDS_MAX, 'PAYMENT_FAILED'],
			[LightningErrorCode.CLTV_EXCEEDS_MAX, 'CLTV_EXCEEDS_MAX'],
			[LightningErrorCode.MISSING_AMOUNT, 'INVALID_PARAMS'],
			[LightningErrorCode.INVALID_INVOICE, 'INVALID_PARAMS'],
			[LightningErrorCode.INVOICE_EXPIRED, 'INVOICE_EXPIRED']
		];
		const { bolt11 } = invoiceFrom('typed');
		for (const [engineCode, code] of cases) {
			engineOf(node).sendPayment = (): never => {
				throw new LightningPaymentError(engineCode, `refused: ${engineCode}`);
			};
			const err = thrownBy(() => node.sendPaymentAsync(bolt11));
			expect(err.code, engineCode).to.equal(code);
			expect(err.message).to.equal(`refused: ${engineCode}`);
		}

		// An untyped throw whose message matches nothing is a plain failure.
		engineOf(node).sendPayment = (): never => {
			throw new Error('something else entirely');
		};
		const err = thrownBy(() => node.sendPaymentAsync(bolt11));
		expect(err.code).to.equal(BeignetErrorCode.PAYMENT_FAILED);
		expect(err.message).to.equal('something else entirely');
	});

	it('sendKeysend answers an engine refusal with its code too', async () => {
		const pubkey = `02${'ab'.repeat(32)}`;
		engineOf(node).sendKeysend = (): never => {
			throw new LightningPaymentError(
				LightningErrorCode.DUPLICATE_PAYMENT,
				'Payment already in flight'
			);
		};
		const err = await rejectedWith(() =>
			node.sendKeysend(pubkey, 1_000, 2_000)
		);
		expect(err.code).to.equal(BeignetErrorCode.DUPLICATE_PAYMENT);
		expect(pendingSats(node)).to.equal(0);
	});

	it('sendKeysend refuses a destination that is not a key as INVALID_PARAMS', async () => {
		// The engine's own INVALID_KEYSEND, unstubbed: 32 bytes, not 33.
		const err = await rejectedWith(() =>
			node.sendKeysend('ab'.repeat(32), 1_000, 2_000)
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		expect(err.message).to.include('33-byte');
	});
});

describe('POST /invoice/pay-async answers an engine refusal with its own code and status (issue #991)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let daemon: IStartedDaemon | undefined;
	let port: number;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-async-http-'));
		daemon = await startDaemon({
			...BOOT,
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: TOKEN
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon?.stop();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	const payAsync = (
		bolt11: string
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		request(port, 'POST', '/invoice/pay-async', { bolt11 });

	it('answers 409 DUPLICATE_PAYMENT for a hash already paid, not a retryable 502', async () => {
		const { bolt11 } = seedPaidRow(daemon!.node, 'paid over http');

		const res = await payAsync(bolt11);
		expect(res.status).to.equal(409);
		expect(res.body.ok).to.equal(false);
		const error = res.body.error as { code: string; message: string };
		expect(error.code).to.equal('DUPLICATE_PAYMENT');
		expect(error.message).to.include('already completed');
	});

	it('answers NO_ROUTE with its own status for an invoice nothing can reach', async () => {
		const res = await payAsync(invoiceFrom('unreachable over http').bolt11);
		expect(res.status).to.equal(statusForErrorCode('NO_ROUTE'));
		expect(res.body.ok).to.equal(false);
		expect((res.body.error as { code: string }).code).to.equal('NO_ROUTE');
	});

	it('answers 400 INVALID_INVOICE for a bolt11 that does not decode', async () => {
		const res = await payAsync('lnbc1notaninvoice');
		expect(res.status).to.equal(400);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_INVOICE'
		);
	});
});
