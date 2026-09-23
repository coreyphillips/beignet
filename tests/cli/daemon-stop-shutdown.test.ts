/**
 * Issue 402: the daemon's graceful teardown must be reachable outside the
 * POST /stop route. startDaemon returns a shared stop() handle that the CLI
 * signal handler awaits, so Ctrl-C runs the same sequence as /stop instead
 * of process.exit(0) abandoning an in-flight backup and an open SQLite
 * handle. Boots offline (unreachable Electrum, same pattern as
 * tests/cli/auth-scopes.test.ts).
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon, IStartedDaemon } from '../../src/cli/daemon';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** An invoice from somebody else, for a preimage the test knows. */
function invoiceFrom(description: string): {
	bolt11: string;
	paymentHash: Buffer;
	preimage: Buffer;
} {
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
}

const TOKEN = 'stop-shutdown-token';

function bootDaemon(tmpDir: string): Promise<IStartedDaemon> {
	return startDaemon({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir: tmpDir,
		logLevel: 'silent',
		rapidGossipSync: false,
		autoGossipSync: false,
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		daemonPort: 0,
		apiToken: TOKEN
	});
}

function isDestroyed(daemon: IStartedDaemon): boolean {
	return (daemon.node as unknown as { destroyed: boolean }).destroyed;
}

async function waitFor(
	condition: () => boolean,
	timeoutMs = 10_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

function request(
	port: number,
	method: string,
	urlPath: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
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
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			}
		);
		req.on('error', reject);
		if (payload) req.write(payload);
		req.end();
	});
}

/**
 * Open an SSE connection and resolve once the server has acknowledged it.
 * The returned `closed` promise settles when the server ends the stream.
 */
function openSse(port: number): Promise<{ closed: Promise<void> }> {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: '/events',
				method: 'GET',
				headers: { Authorization: `Bearer ${TOKEN}` }
			},
			(res) => {
				const closed = new Promise<void>((resolveClosed) => {
					res.on('close', () => resolveClosed());
				});
				res.once('data', () => resolve({ closed }));
				res.on('error', () => {});
			}
		);
		req.on('error', reject);
		req.end();
	});
}

describe('Daemon stop() handle (issue 402)', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let daemon: IStartedDaemon;
	let port: number;

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-stop-handle-'));
		daemon = await bootDaemon(tmpDir);
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async function () {
		daemon?.server.close();
		await daemon?.node.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('tears the daemon down once, shared by concurrent callers, closing SSE', async () => {
		expect(isDestroyed(daemon)).to.equal(false);
		expect(daemon.server.listening).to.equal(true);
		const sse = await openSse(port);

		// A second caller (a signal arriving during /stop) must wait for the
		// SAME teardown, not resolve while the first is still in flight.
		const first = daemon.stop();
		const second = daemon.stop();
		expect(second).to.equal(first);
		await second;

		expect(isDestroyed(daemon)).to.equal(true);
		expect(daemon.server.listening).to.equal(false);
		await sse.closed;
	});

	it('is idempotent, and the usual test teardown stays safe after it', async () => {
		await daemon.stop();
		await daemon.stop(5_000);
		await daemon.node.destroy();
	});
});

describe('Webhooks survive a graceful stop (issue 402)', function () {
	this.timeout(120_000);

	let tmpDir: string;

	before(function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-stop-webhooks-'));
	});

	after(function () {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('a registration made before stop() is still listed after a restart', async () => {
		const first = await bootDaemon(tmpDir);
		const firstPort = (first.server.address() as AddressInfo).port;
		const registered = await request(firstPort, 'POST', '/webhooks/register', {
			url: 'http://127.0.0.1:9/hook',
			events: ['*']
		});
		expect(registered.status).to.equal(200);
		await first.stop();

		const second = await bootDaemon(tmpDir);
		const secondPort = (second.server.address() as AddressInfo).port;
		try {
			const listed = await request(secondPort, 'GET', '/webhooks');
			expect(listed.status).to.equal(200);
			expect(listed.body.result).to.have.length(1);
			expect((listed.body.result as Array<{ url: string }>)[0].url).to.equal(
				'http://127.0.0.1:9/hook'
			);
		} finally {
			await second.stop();
		}
	});
});

describe('A queued payment survives a graceful stop (issue #958)', function () {
	this.timeout(120_000);

	let tmpDir: string;

	before(function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-stop-queue-'));
	});

	after(function () {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	// The database stays open while the wallet stops, so stop() halts the
	// queue first: a payment still waiting its turn is not dispatched to the
	// stopped node and recorded as failed, it stays queued for the next boot.
	// That boot dispatches it once the node is ready, with no enqueue, and
	// settles a row left dispatching against the node's record rather than
	// sending it again (issue #967).
	it('a payment waiting its turn at stop() is not dispatched, and the next boot dispatches it and settles one left in flight', async () => {
		type Entry = { id: string; status: string; error?: string };
		const paid = invoiceFrom('paid before the stop');
		const first = await bootDaemon(tmpDir);
		const firstPort = (first.server.address() as AddressInfo).port;
		const payCalls: string[] = [];
		const failPays: Array<(e: Error) => void> = [];
		let stopCalled = false;
		(
			first.node as unknown as {
				payInvoiceSafe: (b: string) => Promise<unknown>;
			}
		).payInvoiceSafe = (bolt11: string): Promise<unknown> => {
			payCalls.push(bolt11);
			// As the stopped node does: a dispatch after stop() fails at once,
			// so one the queue should have held back persists 'failed'.
			if (stopCalled) return Promise.reject(new Error('node destroyed'));
			return new Promise((_resolve, reject) => failPays.push(reject));
		};
		const listQueue = async (port: number): Promise<Entry[]> =>
			(await request(port, 'GET', '/queue')).body.result as Entry[];
		let waiting: Entry | undefined;
		try {
			while (!waiting && payCalls.length < 10) {
				const added = await request(firstPort, 'POST', '/queue/add', {
					bolt11: `lnbcrt_issue958_${payCalls.length}`
				});
				expect(added.status).to.equal(200);
				waiting = (await listQueue(firstPort)).find(
					(e) => e.status === 'queued'
				);
			}
			expect(waiting).to.not.equal(undefined);
			const inFlight = payCalls.length;

			// A payment the node completed while its queue row stayed
			// 'dispatching', as a stop mid-payment leaves it. The engine does
			// not refuse a hash whose record is COMPLETED, so sending it again
			// would pay twice.
			const storage = first.node.getStorage();
			storage.savePayment(paid.paymentHash.toString('hex'), {
				paymentHash: paid.paymentHash,
				preimage: paid.preimage,
				amountMsat: 1_000_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now() - 1_000,
				completedAt: Date.now()
			});
			storage.savePreimage(paid.paymentHash.toString('hex'), paid.preimage);
			storage.saveQueueEntry({
				id: 'q-1-issue967',
				bolt11: paid.bolt11,
				priority: 5,
				status: 'dispatching',
				createdAt: Date.now() - 1_000
			});

			stopCalled = true;
			const stopped = first.stop();
			// The stopped node fails what it had in flight.
			for (const fail of failPays) fail(new Error('node destroyed'));
			await stopped;
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(payCalls).to.have.length(inFlight);
		} finally {
			await first.stop();
		}

		const second = await bootDaemon(tmpDir);
		try {
			const secondPort = (second.server.address() as AddressInfo).port;
			// Nothing is enqueued on this boot: the queue dispatches what it
			// restored once the node is ready.
			const isFinal = (e: Entry | undefined): boolean =>
				e !== undefined && e.status !== 'queued' && e.status !== 'dispatching';
			let restored: Entry | undefined;
			let settled: Entry | undefined;
			const deadline = Date.now() + 15_000;
			for (;;) {
				const entries = await listQueue(secondPort);
				restored = entries.find((e) => e.id === waiting!.id);
				settled = entries.find((e) => e.id === 'q-1-issue967');
				if (isFinal(restored) && isFinal(settled)) break;
				if (Date.now() > deadline) {
					throw new Error(
						`restored queue rows never settled: ${JSON.stringify(entries)}`
					);
				}
				await new Promise((resolve) => setTimeout(resolve, 25));
			}
			// The real payer refuses the placeholder invoice, so reaching it
			// at all is what shows the dispatch.
			expect(restored?.status).to.equal('failed');
			expect(restored?.error).to.equal('Payment status: FAILED');
			// Settled against the node's COMPLETED record: never sent again.
			expect(settled?.status).to.equal('completed');
			const record = second.node.getPayment(paid.paymentHash.toString('hex'));
			expect(record?.status).to.equal('COMPLETED');
		} finally {
			await second.stop();
		}
	});
});

describe('POST /stop runs the shared teardown (issue 402)', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let daemon: IStartedDaemon;
	let port: number;

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-stop-route-'));
		daemon = await bootDaemon(tmpDir);
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async function () {
		daemon?.server.close();
		await daemon?.node.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('answers 200 and actually shuts the daemon down', async () => {
		const res = await request(port, 'POST', '/stop', {});
		expect(res.status).to.equal(200);
		expect(res.body.ok).to.equal(true);
		expect(res.body.result).to.deep.equal({ stopped: true, drained: false });

		// The route answers before the teardown finishes; wait for it to land.
		await waitFor(() => isDestroyed(daemon) && !daemon.server.listening);
	});

	it('the returned stop() still resolves after a route-driven stop', async () => {
		await daemon.stop();
		expect(isDestroyed(daemon)).to.equal(true);
	});
});
