/**
 * Daemon exposure limits (issue #1045).
 *
 * GET /events took any number of streams per key and buffered every frame
 * for a client that stopped reading. GET /openapi.json was rebuilt and
 * serialized on every unauthenticated request, outside the rate limiter. An
 * oversized body reset the connection before its 413 was written. Webhooks
 * took any URL, private hosts included, and lost their HMAC secret on a
 * restart. A short credential was accepted on a network-facing bind.
 *
 * Chainless, like tests/cli/daemon-browser-guards.test.ts: an unreachable
 * Electrum, daemonPort 0, and the routes used here are local operations.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import * as sinon from 'sinon';
import { DaemonOptions, startDaemon } from '../../src/cli/daemon';
import * as openapi from '../../src/cli/openapi';

type Daemon = Awaited<ReturnType<typeof startDaemon>>;
type Reply = {
	status: number;
	headers: http.IncomingHttpHeaders;
	body: string;
	json: Record<string, unknown>;
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ADMIN_TOKEN = 'exposure-limits-admin-token';
const READONLY_KEY = 'exposure-limits-readonly-key';

const errorCode = (reply: Reply): string =>
	(reply.json.error as { code: string }).code;

function send(
	port: number,
	method: string,
	route: string,
	options: { token?: string; body?: string | Buffer } = {}
): Promise<Reply> {
	return new Promise((resolve, reject) => {
		const headers: Record<string, string | number> = {};
		if (options.token) headers['Authorization'] = `Bearer ${options.token}`;
		if (options.body !== undefined) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(options.body);
		}
		const req = http.request(
			{ host: '127.0.0.1', port, path: route, method, headers },
			(res) => {
				let body = '';
				res.setEncoding('utf8');
				res.on('data', (c: string) => (body += c));
				res.on('end', () => {
					let json: Record<string, unknown> = {};
					try {
						json = JSON.parse(body) as Record<string, unknown>;
					} catch {
						// Not every answer here is JSON.
					}
					resolve({
						status: res.statusCode ?? 0,
						headers: res.headers,
						body,
						json
					});
				});
			}
		);
		req.on('error', reject);
		if (options.body !== undefined) req.write(options.body);
		req.end();
	});
}

interface IStream {
	status: number;
	res: http.IncomingMessage;
	req: http.ClientRequest;
}

/** Open GET /events and resolve once the status line is in. */
function openStream(port: number, token: string): Promise<IStream> {
	return new Promise((resolve, reject) => {
		const req: http.ClientRequest = http.request(
			{
				host: '127.0.0.1',
				port,
				path: '/events',
				method: 'GET',
				headers: { Authorization: `Bearer ${token}` },
				agent: false
			},
			(res) => resolve({ status: res.statusCode ?? 0, res, req })
		);
		req.on('error', reject);
		req.end();
	});
}

async function boot(
	dataDir: string,
	extra: Partial<DaemonOptions> = {}
): Promise<{ daemon: Daemon; port: number }> {
	const daemon = await startDaemon({
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		rapidGossipSync: false,
		autoGossipSync: false,
		logLevel: 'silent',
		network: 'regtest',
		mnemonic: MNEMONIC,
		dataDir,
		daemonPort: 0,
		apiToken: ADMIN_TOKEN,
		apiKeys: [{ name: 'watcher', key: READONLY_KEY, scopes: ['readonly'] }],
		...extra
	});
	return { daemon, port: (daemon.server.address() as AddressInfo).port };
}

const emitRelayed = (daemon: Daemon, event: string, data: unknown): void => {
	(daemon.node as unknown as EventEmitter).emit(event, data);
};

const sleep = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

describe('daemon exposure limits (issue #1045)', function () {
	this.timeout(90_000);
	let root: string;
	let daemon: Daemon;
	let port: number;

	before(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1045-'));
		({ daemon, port } = await boot(path.join(root, 'main')));
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('answers an oversized body with 413 BODY_TOO_LARGE instead of a reset', async () => {
		const body = JSON.stringify({ description: 'x'.repeat(4 * 1_048_576) });
		const reply = await send(port, 'POST', '/invoice/create', {
			token: ADMIN_TOKEN,
			body
		});
		expect(reply.status).to.equal(413);
		expect(errorCode(reply)).to.equal('BODY_TOO_LARGE');
	});

	it('serves /openapi.json unauthenticated without rebuilding the spec per request', async () => {
		const build = sinon.spy(openapi, 'getOpenApiSpec');
		try {
			const first = await send(port, 'GET', '/openapi.json');
			const second = await send(port, 'GET', '/openapi.json');
			expect(first.status).to.equal(200);
			expect(first.json.openapi).to.equal('3.0.3');
			expect(Number(first.headers['content-length'])).to.equal(
				Buffer.byteLength(first.body)
			);
			expect(second.body).to.equal(first.body);
			expect(build.callCount).to.equal(0);
		} finally {
			build.restore();
		}
	});

	describe('GET /events', () => {
		it('caps the streams one credential can hold open', async () => {
			const streams: IStream[] = [];
			try {
				for (let i = 0; i < 16; i++) {
					const stream = await openStream(port, READONLY_KEY);
					streams.push(stream);
					expect(stream.status, `stream ${i}`).to.equal(200);
				}
				const refused = await send(port, 'GET', '/events', {
					token: READONLY_KEY
				});
				expect(refused.status).to.equal(429);
				expect(errorCode(refused)).to.equal('RATE_LIMITED');

				// Another credential has its own allowance.
				const admin = await openStream(port, ADMIN_TOKEN);
				streams.push(admin);
				expect(admin.status).to.equal(200);
			} finally {
				for (const stream of streams) stream.req.destroy();
			}

			// Closed streams give their slots back.
			const deadline = Date.now() + 5000;
			let reopened: IStream | undefined;
			while (Date.now() < deadline) {
				const attempt = await openStream(port, READONLY_KEY);
				if (attempt.status === 200) {
					reopened = attempt;
					break;
				}
				attempt.req.destroy();
				await sleep(50);
			}
			expect(reopened, 'a slot came back').to.not.equal(undefined);
			reopened!.req.destroy();
		});

		it('drops a client that stops reading and keeps one that reads', async () => {
			const stalled = net.createConnection({ host: '127.0.0.1', port });
			await new Promise<void>((resolve) => stalled.on('connect', resolve));
			stalled.write(
				'GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n' +
					`Authorization: Bearer ${READONLY_KEY}\r\n\r\n`
			);
			await new Promise<void>((resolve) =>
				stalled.once('data', () => resolve())
			);
			stalled.pause();
			let stalledBytes = 0;
			let stalledClosed = false;
			stalled.on('data', (chunk: Buffer) => (stalledBytes += chunk.length));
			stalled.on('error', () => {
				// A reset is as good as a close here.
			});
			const stalledClose = new Promise<void>((resolve) =>
				stalled.on('close', () => {
					stalledClosed = true;
					resolve();
				})
			);

			const reader = await openStream(port, ADMIN_TOKEN);
			expect(reader.status).to.equal(200);
			let readerFrames = 0;
			let readerClosed = false;
			reader.res.setEncoding('utf8');
			reader.res.on('data', (chunk: string) => {
				readerFrames += chunk.split('event: peer:connect\n').length - 1;
			});
			reader.res.on('close', () => (readerClosed = true));

			// Far more than the kernel buffers on both ends can hold, so the
			// daemon's own backlog for the stalled client passes its bound.
			const frames = 400;
			const padding = 'x'.repeat(64 * 1024);
			for (let i = 0; i < frames; i++) {
				emitRelayed(daemon, 'peer:connect', { pubkey: padding, i });
				await sleep(2);
			}

			const deadline = Date.now() + 10_000;
			while (readerFrames < frames && Date.now() < deadline) await sleep(20);
			expect(readerFrames, 'the reading client got every frame').to.equal(
				frames
			);
			expect(readerClosed, 'the reading client is still connected').to.equal(
				false
			);

			stalled.resume();
			await Promise.race([stalledClose, sleep(10_000)]);
			expect(stalledClosed, 'the stalled client was dropped').to.equal(true);
			expect(stalledBytes).to.be.below(frames * padding.length);
			reader.req.destroy();
		});
	});

	describe('POST /webhooks/register', () => {
		const register = (body: Record<string, unknown>): Promise<Reply> =>
			send(port, 'POST', '/webhooks/register', {
				token: ADMIN_TOKEN,
				body: JSON.stringify({ events: ['*'], ...body })
			});

		it('refuses a url that is not http or https', async () => {
			for (const url of ['file:///etc/passwd', 'ftp://example.com/hook']) {
				const reply = await register({ url, allowPrivateNetwork: true });
				expect(reply.status, url).to.equal(400);
				expect(errorCode(reply), url).to.equal('INVALID_PARAMS');
			}
		});

		it('refuses a private host unless allowPrivateNetwork is set', async () => {
			const refused = await register({ url: 'http://169.254.169.254/hook' });
			expect(refused.status).to.equal(403);
			expect(errorCode(refused)).to.equal('PRIVATE_NETWORK_REFUSED');

			const allowed = await register({
				url: 'http://127.0.0.1:9/hook',
				allowPrivateNetwork: true
			});
			expect(allowed.status).to.equal(200);
			const id = (allowed.json.result as { id: string }).id;
			await send(port, 'DELETE', '/webhooks/unregister', {
				token: ADMIN_TOKEN,
				body: JSON.stringify({ id })
			});
		});
	});
});

describe('daemon exposure limits across a restart (issue #1045)', function () {
	this.timeout(90_000);
	let root: string;
	let receiver: http.Server;
	const received: Array<{ payload: string; signature: unknown }> = [];

	before(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1045-restart-'));
		receiver = http.createServer((req, res) => {
			let payload = '';
			req.on('data', (c: Buffer) => (payload += c.toString()));
			req.on('end', () => {
				received.push({
					payload,
					signature: req.headers['x-webhook-signature']
				});
				res.end('ok');
			});
		});
		await new Promise<void>((resolve) =>
			receiver.listen(0, '127.0.0.1', resolve)
		);
	});

	after(async () => {
		await new Promise<void>((resolve) => receiver.close(() => resolve()));
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('signs deliveries with the registered secret after a restart, without the preimage', async () => {
		const dataDir = path.join(root, 'node');
		const secret = 'webhook-restart-secret';
		const receiverPort = (receiver.address() as AddressInfo).port;

		const first = await boot(dataDir);
		try {
			const reply = await send(first.port, 'POST', '/webhooks/register', {
				token: ADMIN_TOKEN,
				body: JSON.stringify({
					url: `http://127.0.0.1:${receiverPort}/hook`,
					events: ['payment:sent'],
					secret,
					allowPrivateNetwork: true
				})
			});
			expect(reply.status).to.equal(200);
		} finally {
			await first.daemon.stop();
		}

		const second = await boot(dataDir);
		try {
			const preimage = 'cd'.repeat(32);
			emitRelayed(second.daemon, 'payment:sent', {
				paymentHash: 'ab'.repeat(32),
				preimage,
				amountSats: 1000
			});
			const deadline = Date.now() + 5000;
			while (received.length === 0 && Date.now() < deadline) await sleep(20);
			expect(received).to.have.length(1);
			const { payload, signature } = received[0];
			const expected = crypto
				.createHmac('sha256', secret)
				.update(payload)
				.digest('hex');
			expect(signature).to.equal(`sha256=${expected}`);
			expect(payload).to.not.include(preimage);
			expect(JSON.parse(payload).data).to.deep.equal({
				paymentHash: 'ab'.repeat(32),
				amountSats: 1000
			});
		} finally {
			await second.daemon.stop();
		}
	});
});

describe('daemon limiter on auth-exempt routes (issue #1045)', function () {
	this.timeout(90_000);
	let root: string;
	let daemon: Daemon;
	let port: number;

	before(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1045-limit-'));
		({ daemon, port } = await boot(path.join(root, 'node'), {
			rateLimit: { maxRequests: 3, windowMs: 60_000 }
		}));
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('counts /health and /openapi.json against the bucket', async () => {
		for (let i = 0; i < 3; i++) {
			const route = i === 0 ? '/health' : '/openapi.json';
			expect((await send(port, 'GET', route)).status, route).to.equal(200);
		}
		const limited = await send(port, 'GET', '/openapi.json');
		expect(limited.status).to.equal(429);
		expect(errorCode(limited)).to.equal('RATE_LIMITED');
	});
});

describe('daemon credential length on a network bind (issue #1045)', function () {
	this.timeout(90_000);
	let root: string;

	before(() => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1045-bind-'));
	});

	after(() => {
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('refuses a short apiToken or apiKeys secret before creating the node', async () => {
		const dataDir = path.join(root, 'node');
		for (const extra of [
			{ apiToken: 'mysecret', apiKeys: [] },
			{
				apiKeys: [{ name: 'weak', key: 'short', scopes: ['readonly' as const] }]
			}
		]) {
			let refusal: { code?: string; message?: string } | undefined;
			try {
				const started = await boot(dataDir, {
					daemonHost: '0.0.0.0',
					...extra
				});
				await started.daemon.stop();
			} catch (err) {
				refusal = err as { code?: string; message?: string };
			}
			expect(refusal?.code).to.equal('INVALID_PARAMS');
			expect(refusal?.message).to.include('shorter than 16 characters');
		}
		expect(fs.existsSync(dataDir)).to.equal(false);
	});
});
