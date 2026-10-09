/**
 * HTTP server limits (issue #1401).
 *
 * The rate limiter existed but no config field reached it, so `beignet start`
 * could not turn it on. The server itself set no connection cap and relied on
 * whatever header and request timeouts the running Node defaulted to.
 *
 * Chainless: an unreachable Electrum, daemonPort 0, and only /health.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { resolveConfig, saveConfig } from '../../src/cli/config';
import { daemonOptions } from '../../src/cli/daemon-options';
import {
	HTTP_HEADERS_TIMEOUT_MS,
	HTTP_KEEP_ALIVE_TIMEOUT_MS,
	HTTP_MAX_CONNECTIONS,
	HTTP_REQUEST_TIMEOUT_MS,
	startDaemon
} from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import { RateLimitOptions } from '../../src/cli/http-rate-limiter';

type Daemon = Awaited<ReturnType<typeof startDaemon>>;

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	daemonPort: 0,
	mnemonic: MNEMONIC
};

function health(port: number): Promise<number> {
	return new Promise((resolve, reject) => {
		http
			.get(
				{ host: '127.0.0.1', port, path: '/health', agent: false },
				(res) => {
					res.resume();
					res.on('end', () => resolve(res.statusCode ?? 0));
				}
			)
			.on('error', reject);
	});
}

async function until(check: () => Promise<boolean>): Promise<void> {
	const deadline = Date.now() + 10_000;
	while (!(await check())) {
		if (Date.now() > deadline) throw new Error('condition not reached');
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}

const connectionCount = (daemon: Daemon): Promise<number> =>
	new Promise((resolve, reject) =>
		daemon.server.getConnections((err, count) =>
			err ? reject(err) : resolve(count)
		)
	);

describe('rateLimit from the config file (issue #1401)', function () {
	this.timeout(60_000);
	const origHome = process.env.HOME;
	let root: string;
	let daemon: Daemon | null = null;

	beforeEach(() => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1401-'));
		process.env.HOME = root;
	});

	afterEach(async () => {
		if (daemon) await daemon.stop();
		daemon = null;
		process.env.HOME = origHome;
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('reaches the limiter the CLI starts', async () => {
		saveConfig({ rateLimit: { maxRequests: 2, windowMs: 60_000 } });
		const options = daemonOptions(resolveConfig({}), 0);
		expect(options.rateLimit).to.deep.equal({
			maxRequests: 2,
			windowMs: 60_000
		});
		daemon = await startDaemon({
			...options,
			...OFFLINE,
			dataDir: path.join(root, 'node')
		});
		const port = (daemon.server.address() as AddressInfo).port;
		expect(await health(port)).to.equal(200);
		expect(await health(port)).to.equal(200);
		expect(await health(port)).to.equal(429);
	});

	it('stays off when the config file does not set it', () => {
		expect(daemonOptions(resolveConfig({}), 0).rateLimit).to.equal(undefined);
	});

	const bad: Array<[string, unknown]> = [
		['maxRequests', 0],
		['maxRequests', -5],
		['windowMs', 1.5],
		['windowMs', '60000'],
		['maxClients', 0]
	];
	for (const [field, value] of bad) {
		it(`refuses rateLimit.${field} ${JSON.stringify(
			value
		)} at startup`, async () => {
			let error: unknown;
			try {
				daemon = await startDaemon({
					...OFFLINE,
					dataDir: path.join(root, 'node'),
					rateLimit: { [field]: value } as RateLimitOptions
				});
			} catch (e) {
				error = e;
			}
			expect(error).to.be.instanceOf(BeignetError);
			expect((error as Error).message).to.include(
				`rateLimit.${field} must be a positive integer`
			);
		});
	}
});

describe('HTTP server connection limits (issue #1401)', function () {
	this.timeout(60_000);
	let root: string;
	let daemon: Daemon;
	let port: number;
	const held: net.Socket[] = [];

	before(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1401-conn-'));
		daemon = await startDaemon({
			...OFFLINE,
			dataDir: path.join(root, 'node')
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		for (const socket of held) socket.destroy();
		await daemon.stop();
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('sets the timeouts explicitly rather than inheriting Node defaults', () => {
		expect(daemon.server.headersTimeout).to.equal(HTTP_HEADERS_TIMEOUT_MS);
		expect(daemon.server.requestTimeout).to.equal(HTTP_REQUEST_TIMEOUT_MS);
		expect(daemon.server.keepAliveTimeout).to.equal(HTTP_KEEP_ALIVE_TIMEOUT_MS);
		expect(daemon.server.maxConnections).to.equal(HTTP_MAX_CONNECTIONS);
	});

	it('closes connections past the cap and admits one again once a slot frees', async () => {
		for (let i = 0; i < HTTP_MAX_CONNECTIONS; i++) {
			const socket = net.connect(port, '127.0.0.1');
			socket.on('error', () => undefined);
			held.push(socket);
		}
		await until(
			async () => (await connectionCount(daemon)) === HTTP_MAX_CONNECTIONS
		);

		let refused: unknown = null;
		try {
			await health(port);
		} catch (e) {
			refused = e;
		}
		expect(refused, 'a connection past the cap is closed').to.be.instanceOf(
			Error
		);

		held.pop()!.destroy();
		await until(
			async () => (await connectionCount(daemon)) < HTTP_MAX_CONNECTIONS
		);
		expect(await health(port)).to.equal(200);
	});
});
