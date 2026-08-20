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

describe('Daemon stop() handle (issue 402)', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let daemon: IStartedDaemon;

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-stop-handle-'));
		daemon = await bootDaemon(tmpDir);
	});

	after(async function () {
		daemon?.server.close();
		await daemon?.node.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('tears the daemon down: node destroyed, server closed', async () => {
		expect(isDestroyed(daemon)).to.equal(false);
		expect(daemon.server.listening).to.equal(true);

		await daemon.stop();

		expect(isDestroyed(daemon)).to.equal(true);
		expect(daemon.server.listening).to.equal(false);
	});

	it('is idempotent, and the usual test teardown stays safe after it', async () => {
		await daemon.stop();
		await daemon.stop(5_000);
		await daemon.node.destroy();
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
