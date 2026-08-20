/**
 * Issue 402: the daemon's graceful teardown must be reachable outside the
 * POST /stop route. startDaemon returns a shared stop() handle that the CLI
 * signal handler awaits, so Ctrl-C runs the same sequence as /stop instead
 * of process.exit(0) abandoning an in-flight backup and an open SQLite
 * handle. Boots offline (unreachable Electrum, same pattern as
 * tests/cli/auth-scopes.test.ts).
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon, IStartedDaemon } from '../../src/cli/daemon';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

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
