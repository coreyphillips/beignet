/**
 * Long-poll wait limits (issue #1404).
 *
 * POST /node/wait-ready, /channel/wait-ready and /payment/wait handed the
 * caller's timeoutMs straight to the node, and any number could be open at
 * once, so a readonly client could park thousands of sockets, timers and
 * node listeners for weeks.
 *
 * Chainless, like tests/cli/daemon-exposure-limits.test.ts. The node's wait
 * methods are stubbed so each test decides when a wait settles.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import * as sinon from 'sinon';
import { startDaemon } from '../../src/cli/daemon';

type Daemon = Awaited<ReturnType<typeof startDaemon>>;
type Reply = { status: number; json: Record<string, unknown> };

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ADMIN_TOKEN = 'wait-limits-admin-token';
const READONLY_KEY = 'wait-limits-readonly-key';
const CHANNEL_ID = 'ab'.repeat(32);
const PAYMENT_HASH = 'cd'.repeat(32);

const errorCode = (reply: Reply): string =>
	(reply.json.error as { code: string }).code;

/** POST on a socket of its own, so the caller can hang it up. */
function post(
	port: number,
	route: string,
	token: string,
	body: Record<string, unknown>
): { req: http.ClientRequest; reply: Promise<Reply> } {
	const payload = JSON.stringify(body);
	let req!: http.ClientRequest;
	const reply = new Promise<Reply>((resolve, reject) => {
		req = http.request(
			{
				host: '127.0.0.1',
				port,
				path: route,
				method: 'POST',
				agent: false,
				headers: {
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(payload)
				}
			},
			(res) => {
				let text = '';
				res.setEncoding('utf8');
				res.on('data', (c: string) => (text += c));
				res.on('end', () =>
					resolve({
						status: res.statusCode ?? 0,
						json: JSON.parse(text) as Record<string, unknown>
					})
				);
			}
		);
		req.on('error', reject);
		req.end(payload);
	});
	return { req, reply };
}

const sleep = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

async function waitUntil(condition: () => boolean): Promise<void> {
	const deadline = Date.now() + 5000;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('condition never held');
		await sleep(10);
	}
}

describe('daemon long-poll wait limits (issue #1404)', function () {
	this.timeout(90_000);
	let root: string;
	let daemon: Daemon;
	let port: number;

	before(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1404-'));
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic: MNEMONIC,
			dataDir: path.join(root, 'node'),
			daemonPort: 0,
			apiToken: ADMIN_TOKEN,
			apiKeys: [{ name: 'watcher', key: READONLY_KEY, scopes: ['readonly'] }]
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	afterEach(() => sinon.restore());

	after(async () => {
		await daemon.stop();
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('waits at most ten minutes whatever timeoutMs asks, and keeps the default when it is absent', async () => {
		const ready = sinon.stub(daemon.node, 'waitForReady').resolves();
		const channel = sinon.stub(daemon.node, 'waitForChannelReady').resolves();
		const payment = sinon
			.stub(daemon.node, 'waitForPayment')
			.resolves({} as never);

		for (const [timeoutMs, expected] of [
			[2 ** 31 - 1, 600_000],
			[5000, 5000],
			[undefined, undefined]
		]) {
			const replies = await Promise.all([
				post(port, '/node/wait-ready', READONLY_KEY, { timeoutMs }).reply,
				post(port, '/channel/wait-ready', READONLY_KEY, {
					channelId: CHANNEL_ID,
					timeoutMs
				}).reply,
				post(port, '/payment/wait', READONLY_KEY, {
					paymentHash: PAYMENT_HASH,
					timeoutMs
				}).reply
			]);
			for (const reply of replies) expect(reply.status).to.equal(200);
			expect(ready.lastCall.args[0], 'node').to.equal(expected);
			expect(channel.lastCall.args[1], 'channel').to.equal(expected);
			expect(payment.lastCall.args[1], 'payment').to.equal(expected);
		}
	});

	it('refuses a credential a seventeenth wait until the node settles one', async () => {
		const settle: Array<() => void> = [];
		const channel = sinon
			.stub(daemon.node, 'waitForChannelReady')
			.callsFake(() => new Promise<void>((resolve) => settle.push(resolve)));
		const body = { channelId: CHANNEL_ID };
		try {
			const parked = Array.from({ length: 16 }, () =>
				post(port, '/channel/wait-ready', READONLY_KEY, body)
			);
			await waitUntil(() => channel.callCount === 16);
			// Hanging up leaves the node's wait in place, so the slot stays taken.
			for (const wait of parked) {
				wait.reply.catch(() => undefined);
				wait.req.destroy();
			}

			// One count across the three wait routes. A short timeoutMs keeps
			// a failure here from parking the test.
			const refused = await post(port, '/payment/wait', READONLY_KEY, {
				paymentHash: PAYMENT_HASH,
				timeoutMs: 1
			}).reply;
			expect(refused.status).to.equal(429);
			expect(errorCode(refused)).to.equal('RATE_LIMITED');

			// Another credential has its own allowance.
			const admin = post(port, '/channel/wait-ready', ADMIN_TOKEN, body);
			await waitUntil(() => channel.callCount === 17);

			for (const resolve of settle.splice(0)) resolve();
			expect((await admin.reply).status).to.equal(200);

			const again = post(port, '/channel/wait-ready', READONLY_KEY, body);
			await waitUntil(() => channel.callCount === 18);
			for (const resolve of settle.splice(0)) resolve();
			expect((await again.reply).status).to.equal(200);
		} finally {
			for (const resolve of settle) resolve();
		}
	});
});
