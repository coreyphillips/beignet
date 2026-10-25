import * as http from 'http';
import * as crypto from 'crypto';
import { expect } from 'chai';
import {
	IWebhookStorage,
	WebhookDeliveryOptions,
	WebhookManager,
	webhookMetrics,
	webhookTargetRefusal
} from '../../src/cli/webhooks';
import { BeignetError } from '../../src/cli/errors';

interface ReceivedRequest {
	body: Record<string, unknown>;
	payload: string;
	headers: http.IncomingHttpHeaders;
	url: string | undefined;
}

describe('WebhookManager', () => {
	let manager: WebhookManager;
	let testServer: http.Server;
	let receivedRequests: ReceivedRequest[];
	let responseStatus: (request: ReceivedRequest) => number;
	let serverPort: number;

	async function waitForRequests(count: number): Promise<void> {
		const deadline = Date.now() + 4000;
		while (receivedRequests.length < count && Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 10));
		}
		expect(receivedRequests).to.have.length(count);
	}

	before((done) => {
		receivedRequests = [];
		testServer = http.createServer((req, res) => {
			const chunks: Buffer[] = [];
			req.on('data', (chunk: Buffer) => chunks.push(chunk));
			req.on('end', () => {
				const payload = Buffer.concat(chunks).toString();
				const request = {
					body: JSON.parse(payload),
					payload,
					headers: req.headers,
					url: req.url
				};
				receivedRequests.push(request);
				res.statusCode = responseStatus(request);
				res.end('OK');
			});
		});
		testServer.listen(0, '127.0.0.1', () => {
			const addr = testServer.address() as { port: number };
			serverPort = addr.port;
			done();
		});
	});

	after((done) => {
		testServer.close(done);
	});

	beforeEach(() => {
		manager = new WebhookManager();
		receivedRequests = [];
		responseStatus = (): number => 200;
	});

	afterEach(() => {
		manager.clear();
	});

	// 1. register() creates a webhook with unique ID
	it('register() creates a webhook with unique ID', () => {
		const reg = manager.register('http://localhost:9999/hook', [
			'payment:received'
		]);
		expect(reg.id).to.be.a('string');
		expect(reg.id).to.have.length(32); // 16 random bytes = 32 hex chars
		expect(reg.url).to.equal('http://localhost:9999/hook');
		expect(reg.events).to.deep.equal(['payment:received']);
		expect(reg.createdAt).to.be.a('number');

		// Second registration gets different ID
		const reg2 = manager.register('http://localhost:9999/hook2', [
			'channel:ready'
		]);
		expect(reg2.id).to.not.equal(reg.id);
	});

	// 2. register() throws if url is missing
	it('register() throws if url is missing', () => {
		expect(() => manager.register('', ['payment:received'])).to.throw(
			'url and at least one event type are required'
		);
	});

	// 3. register() throws if events is empty
	it('register() throws if events is empty', () => {
		expect(() => manager.register('http://localhost:9999/hook', [])).to.throw(
			'url and at least one event type are required'
		);
	});

	// 4. unregister() removes a registered webhook
	it('unregister() removes a registered webhook', () => {
		const reg = manager.register('http://localhost:9999/hook', [
			'payment:received'
		]);
		expect(manager.size).to.equal(1);
		const removed = manager.unregister(reg.id);
		expect(removed).to.be.true;
		expect(manager.size).to.equal(0);
	});

	// 5. unregister() returns false for unknown ID
	it('unregister() returns false for unknown ID', () => {
		const removed = manager.unregister('nonexistent-id');
		expect(removed).to.be.false;
	});

	// 6. list() returns all registrations
	it('list() returns all registrations', () => {
		manager.register('http://localhost:9999/hook1', ['payment:received']);
		manager.register('http://localhost:9999/hook2', ['channel:ready']);
		const list = manager.list();
		expect(list).to.have.length(2);
		expect(list[0].url).to.equal('http://localhost:9999/hook1');
		expect(list[1].url).to.equal('http://localhost:9999/hook2');
	});

	// 7. list() masks secret in response
	it('list() masks secret in response', () => {
		manager.register(
			'http://localhost:9999/hook',
			['payment:received'],
			'my-secret-key'
		);
		const list = manager.list();
		expect(list).to.have.length(1);
		expect(list[0].secret).to.equal('***');
	});

	// 8. dispatch() sends POST to matching webhook URLs
	it('dispatch() sends POST to matching webhook URLs', async () => {
		manager.register(`http://127.0.0.1:${serverPort}/hook`, [
			'payment:received'
		]);
		manager.dispatch('payment:received', { amount: 1000 });

		// Wait for async delivery
		await new Promise((r) => setTimeout(r, 300));

		expect(receivedRequests).to.have.length(1);
		expect(receivedRequests[0].body.event).to.equal('payment:received');
		expect(
			(receivedRequests[0].body.data as Record<string, unknown>).amount
		).to.equal(1000);
		expect(receivedRequests[0].body.timestamp).to.be.a('number');
		expect(receivedRequests[0].headers['content-type']).to.equal(
			'application/json'
		);
		expect(receivedRequests[0].headers['user-agent']).to.equal(
			'Beignet-Webhook/1.0'
		);
		expect(receivedRequests[0].headers['x-webhook-event']).to.equal(
			'payment:received'
		);
	});

	// 9. dispatch() only sends to webhooks matching event type
	it('dispatch() only sends to webhooks matching event type', async () => {
		manager.register(`http://127.0.0.1:${serverPort}/hook`, ['channel:ready']);
		manager.dispatch('payment:received', { amount: 500 });

		// Wait for async delivery
		await new Promise((r) => setTimeout(r, 300));

		expect(receivedRequests).to.have.length(0);
	});

	// 10. dispatch() includes HMAC-SHA256 signature when secret is configured
	it('dispatch() includes HMAC-SHA256 signature when secret is configured', async () => {
		const secret = 'test-webhook-secret';
		manager.register(
			`http://127.0.0.1:${serverPort}/hook`,
			['payment:received'],
			secret
		);
		manager.dispatch('payment:received', { amount: 2000 });

		// Wait for async delivery
		await new Promise((r) => setTimeout(r, 300));

		expect(receivedRequests).to.have.length(1);
		const sigHeader = receivedRequests[0].headers[
			'x-webhook-signature'
		] as string;
		expect(sigHeader).to.be.a('string');
		expect(sigHeader).to.match(/^sha256=[0-9a-f]{64}$/);

		// Verify the HMAC signature is correct
		const payload = JSON.stringify(receivedRequests[0].body);
		const expectedSig = crypto
			.createHmac('sha256', secret)
			.update(payload)
			.digest('hex');
		expect(sigHeader).to.equal(`sha256=${expectedSig}`);
	});

	// 11. dispatch() wildcard '*' matches all events
	it("dispatch() wildcard '*' matches all events", async () => {
		manager.register(`http://127.0.0.1:${serverPort}/hook`, ['*']);
		manager.dispatch('payment:received', { amount: 100 });

		// Wait for async delivery
		await new Promise((r) => setTimeout(r, 300));

		expect(receivedRequests).to.have.length(1);
		expect(receivedRequests[0].body.event).to.equal('payment:received');

		receivedRequests = [];
		manager.dispatch('channel:ready', { channelId: 'abc' });

		await new Promise((r) => setTimeout(r, 300));

		expect(receivedRequests).to.have.length(1);
		expect(receivedRequests[0].body.event).to.equal('channel:ready');
	});

	// 12. clear() removes all webhooks
	it('clear() removes all webhooks', () => {
		manager.register('http://localhost:9999/hook1', ['payment:received']);
		manager.register('http://localhost:9999/hook2', ['channel:ready']);
		expect(manager.size).to.equal(2);

		manager.clear();
		expect(manager.size).to.equal(0);
		expect(manager.list()).to.have.length(0);
	});

	describe('hold lifecycle delivery ordering', function () {
		this.timeout(6000);

		for (const terminalEvent of ['hold:cancelled', 'hold:settled']) {
			it(`finishes the accepted retry before delivering ${terminalEvent}`, async () => {
				manager.register(
					`http://127.0.0.1:${serverPort}/hook`,
					['*'],
					'secret'
				);
				responseStatus = (): number =>
					receivedRequests.length === 1 ? 500 : 200;
				const accepted = { paymentHash: 'invoice-a', heldAmountMsat: '1000' };
				manager.dispatch('hold:accepted', accepted);
				manager.dispatch(terminalEvent, { paymentHash: 'invoice-a' });
				accepted.heldAmountMsat = '2000';

				await waitForRequests(3);

				expect(
					receivedRequests.map((request) => request.body.event)
				).to.deep.equal(['hold:accepted', 'hold:accepted', terminalEvent]);
				expect(receivedRequests[1].payload).to.equal(
					receivedRequests[0].payload
				);
				expect(receivedRequests[1].headers['x-webhook-signature']).to.equal(
					receivedRequests[0].headers['x-webhook-signature']
				);
				expect(receivedRequests[1].body.data).to.deep.equal({
					paymentHash: 'invoice-a',
					heldAmountMsat: '1000'
				});
			});
		}

		it('continues to the terminal event after the accepted retry also fails', async () => {
			manager.register(`http://127.0.0.1:${serverPort}/hook`, ['*']);
			responseStatus = (request): number =>
				request.body.event === 'hold:accepted' ? 500 : 200;
			manager.dispatch('hold:accepted', { paymentHash: 'invoice-a' });
			manager.dispatch('hold:settled', { paymentHash: 'invoice-a' });

			await waitForRequests(3);

			expect(
				receivedRequests.map((request) => request.body.event)
			).to.deep.equal(['hold:accepted', 'hold:accepted', 'hold:settled']);
		});

		it('does not block other invoices or other event types behind a retry', async () => {
			manager.register(`http://127.0.0.1:${serverPort}/hook`, ['*']);
			responseStatus = (request): number =>
				request.body.event === 'hold:accepted' &&
				(request.body.data as { paymentHash: string }).paymentHash ===
					'invoice-a'
					? 500
					: 200;
			manager.dispatch('hold:accepted', { paymentHash: 'invoice-a' });
			manager.dispatch('hold:cancelled', { paymentHash: 'invoice-a' });
			manager.dispatch('hold:accepted', { paymentHash: 'invoice-b' });
			manager.dispatch('payment:received', { paymentHash: 'invoice-a' });

			await waitForRequests(3);

			expect(
				receivedRequests.map((request) => ({
					event: request.body.event,
					data: request.body.data
				}))
			).to.deep.include.members([
				{
					event: 'hold:accepted',
					data: { paymentHash: 'invoice-b' }
				},
				{
					event: 'payment:received',
					data: { paymentHash: 'invoice-a' }
				}
			]);
			expect(
				receivedRequests.some(
					(request) => request.body.event === 'hold:cancelled'
				)
			).to.be.false;

			await waitForRequests(5);
			expect(receivedRequests[4].body.event).to.equal('hold:cancelled');
		});

		it('does not block another registration for the same invoice', async () => {
			manager.register(`http://127.0.0.1:${serverPort}/slow`, ['*']);
			manager.register(`http://127.0.0.1:${serverPort}/fast`, ['*']);
			responseStatus = (request): number =>
				request.url === '/slow' && request.body.event === 'hold:accepted'
					? 500
					: 200;
			manager.dispatch('hold:accepted', { paymentHash: 'invoice-a' });
			manager.dispatch('hold:settled', { paymentHash: 'invoice-a' });

			await waitForRequests(3);

			expect(
				receivedRequests
					.filter((request) => request.url === '/fast')
					.map((request) => request.body.event)
			).to.deep.equal(['hold:accepted', 'hold:settled']);
			expect(
				receivedRequests.filter((request) => request.url === '/slow')
			).to.have.length(1);

			await waitForRequests(5);
			expect(receivedRequests[4].url).to.equal('/slow');
			expect(receivedRequests[4].body.event).to.equal('hold:settled');
		});

		for (const remove of ['unregister', 'clear'] as const) {
			it(`${remove} suppresses retries and queued events`, async () => {
				const registration = manager.register(
					`http://127.0.0.1:${serverPort}/hook`,
					['*']
				);
				responseStatus = (): number => 500;
				manager.dispatch('hold:accepted', { paymentHash: 'invoice-a' });
				manager.dispatch('hold:cancelled', { paymentHash: 'invoice-a' });
				await waitForRequests(1);

				if (remove === 'unregister') {
					manager.unregister(registration.id);
				} else {
					manager.clear();
				}
				await new Promise((resolve) => setTimeout(resolve, 2200));

				expect(receivedRequests).to.have.length(1);
			});
		}
	});

	describe('delivery targets and payloads (issue #1045)', () => {
		it('register() refuses a url that is not http or https', () => {
			for (const url of ['file:///etc/passwd', 'ftp://example.com/x', 'nope']) {
				expect(() => manager.register(url, ['*']), url)
					.to.throw(BeignetError)
					.with.property('code', 'INVALID_PARAMS');
			}
			expect(manager.size).to.equal(0);
		});

		it('webhookTargetRefusal refuses private hosts unless allowed', () => {
			for (const url of [
				'http://127.0.0.1:8080/hook',
				'http://localhost/hook',
				'http://169.254.169.254/latest',
				'http://10.1.2.3/hook',
				'http://[::1]/hook'
			]) {
				expect(webhookTargetRefusal(url, false)?.code, url).to.equal(
					'PRIVATE_NETWORK_REFUSED'
				);
				expect(webhookTargetRefusal(url, true), url).to.equal(null);
			}
			expect(
				webhookTargetRefusal('https://hooks.example.com/x', false)
			).to.equal(null);
			expect(webhookTargetRefusal('file:///etc/passwd', true)?.code).to.equal(
				'INVALID_PARAMS'
			);
		});

		it('dispatch() leaves the preimage out of the payload', async () => {
			manager.register(`http://127.0.0.1:${serverPort}/hook`, ['*']);
			manager.dispatch('payment:sent', {
				paymentHash: 'ab'.repeat(32),
				preimage: 'cd'.repeat(32),
				amountSats: 10
			});
			await waitForRequests(1);
			expect(receivedRequests[0].payload).to.not.include('cd'.repeat(32));
			expect(receivedRequests[0].body.data).to.deep.equal({
				paymentHash: 'ab'.repeat(32),
				amountSats: 10
			});
		});

		it('a secret kept by the storage still signs after a restart', async () => {
			const rows = new Map<
				string,
				{
					id: string;
					url: string;
					events: string[];
					secretHash?: string;
					createdAt: number;
				}
			>();
			let secrets: Record<string, string> | null = null;
			const storage: IWebhookStorage = {
				saveWebhook: (id, url, events, secretHash, createdAt) =>
					rows.set(id, { id, url, events, secretHash, createdAt: createdAt! }),
				deleteWebhook: (id) => rows.delete(id),
				deleteAllWebhooks: () => rows.clear(),
				loadAllWebhooks: () => [...rows.values()],
				saveWebhookSecrets: (s) => {
					secrets = { ...s };
				},
				loadWebhookSecrets: () => secrets
			};
			const secret = 'restart-secret';
			const first = new WebhookManager(storage);
			const kept = first.register(
				`http://127.0.0.1:${serverPort}/hook`,
				['*'],
				secret
			);
			const dropped = first.register(
				`http://127.0.0.1:${serverPort}/other`,
				['channel:ready'],
				'other-secret'
			);
			first.unregister(dropped.id);
			expect(secrets).to.deep.equal({ [kept.id]: secret });

			const restarted = new WebhookManager(storage);
			restarted.dispatch('channel:ready', { channelId: 'abc' });
			await waitForRequests(1);
			const expected = crypto
				.createHmac('sha256', secret)
				.update(receivedRequests[0].payload)
				.digest('hex');
			expect(receivedRequests[0].headers['x-webhook-signature']).to.equal(
				`sha256=${expected}`
			);
			restarted.clear();
			expect(secrets).to.deep.equal({});
		});

		it('unreadable secrets cost the signatures, not the registrations', () => {
			const storage: IWebhookStorage = {
				saveWebhook: () => undefined,
				deleteWebhook: () => undefined,
				deleteAllWebhooks: () => undefined,
				loadAllWebhooks: () => [
					{
						id: 'kept',
						url: 'https://hooks.example.com/x',
						events: ['*'],
						secretHash: 'ab'.repeat(32),
						createdAt: 1
					}
				],
				loadWebhookSecrets: () => {
					throw new SyntaxError('Unexpected token');
				}
			};
			const restored = new WebhookManager(storage);
			expect(restored.list().map((w) => w.id)).to.deep.equal(['kept']);
		});
	});
});

describe('WebhookManager delivery limits (issue #1865)', function () {
	this.timeout(10_000);

	interface Arrival {
		url: string;
		event: string;
		data: unknown;
		payload: string;
		res: http.ServerResponse;
	}

	let server: http.Server;
	let port: number;
	let arrivals: Arrival[];
	let held: Arrival[];
	let answer: (arrival: Arrival) => number | 'hold';
	let open: Map<string, number>;
	let peakOpen: Map<string, number>;
	let peakOpenTotal: number;
	let managers: WebhookManager[];
	let unhandled: unknown[];
	const onUnhandled = (reason: unknown): void => {
		unhandled.push(reason);
	};

	function openTotal(): number {
		return [...open.values()].reduce((sum, n) => sum + n, 0);
	}

	before((done) => {
		server = http.createServer((req, res) => {
			const url = req.url ?? '';
			open.set(url, (open.get(url) ?? 0) + 1);
			peakOpen.set(url, Math.max(peakOpen.get(url) ?? 0, open.get(url)!));
			peakOpenTotal = Math.max(peakOpenTotal, openTotal());
			res.on('close', () => open.set(url, open.get(url)! - 1));
			const chunks: Buffer[] = [];
			req.on('data', (chunk: Buffer) => chunks.push(chunk));
			req.on('end', () => {
				const payload = Buffer.concat(chunks).toString();
				const body = JSON.parse(payload) as { event: string; data: unknown };
				const arrival = {
					url,
					event: body.event,
					data: body.data,
					payload,
					res
				};
				arrivals.push(arrival);
				const status = answer(arrival);
				if (status === 'hold') {
					held.push(arrival);
				} else {
					res.statusCode = status;
					res.end();
				}
			});
		});
		server.listen(0, '127.0.0.1', () => {
			port = (server.address() as { port: number }).port;
			done();
		});
	});

	after((done) => {
		server.close(done);
	});

	beforeEach(() => {
		arrivals = [];
		held = [];
		answer = (): number => 200;
		open = new Map();
		peakOpen = new Map();
		peakOpenTotal = 0;
		managers = [];
		unhandled = [];
		process.on('unhandledRejection', onUnhandled);
	});

	afterEach(async () => {
		answer = (): number => 200;
		release(200);
		await Promise.all(managers.map((manager) => manager.stop()));
		// A rejection is reported a tick after it goes unhandled.
		await new Promise((resolve) => setImmediate(resolve));
		process.off('unhandledRejection', onUnhandled);
		expect(unhandled).to.deep.equal([]);
	});

	function create(options: WebhookDeliveryOptions): WebhookManager {
		const manager = new WebhookManager(undefined, options);
		managers.push(manager);
		return manager;
	}

	/** Answer every held request with `status`. */
	function release(status: number): void {
		for (const arrival of held.splice(0)) {
			if (arrival.res.destroyed) continue;
			arrival.res.statusCode = status;
			arrival.res.end();
		}
	}

	/** Poll `condition`, recording the manager's peak work along the way. */
	async function until(
		condition: () => boolean,
		manager?: WebhookManager,
		peak?: { active: number; queuedBytes: number }
	): Promise<void> {
		const deadline = Date.now() + 5000;
		for (;;) {
			if (manager && peak) {
				const stats = manager.deliveryStats();
				peak.active = Math.max(peak.active, stats.active);
				peak.queuedBytes = Math.max(peak.queuedBytes, stats.queuedBytes);
			}
			if (condition()) return;
			if (Date.now() > deadline) throw new Error('until timed out');
			await new Promise((resolve) => setTimeout(resolve, 2));
		}
	}

	/** Bytes of the payload dispatch() builds for `data`. */
	function payloadBytes(eventType: string, data: unknown): number {
		return Buffer.byteLength(
			JSON.stringify({ event: eventType, data, timestamp: Date.now() })
		);
	}

	const seq = (i: number): { seq: string } => ({
		seq: String(i).padStart(4, '0')
	});

	it('a slow recipient burst stays within the worker and byte ceilings', async () => {
		const size = payloadBytes('payment:received', seq(0));
		const manager = create({
			maxActiveDeliveries: 3,
			maxActivePerWebhook: 2,
			maxQueuedBytesPerWebhook: size * 8,
			maxQueuedBytes: size * 100
		});
		manager.register(`http://127.0.0.1:${port}/a`, ['*']);
		manager.register(`http://127.0.0.1:${port}/b`, ['*']);
		answer = (): 'hold' => 'hold';
		const peak = { active: 0, queuedBytes: 0 };

		for (let i = 0; i < 50; i++) manager.dispatch('payment:received', seq(i));

		await until(() => held.length === 3, manager, peak);
		// Settle any extra arrival before asserting none came.
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(held).to.have.length(3);
		expect(new Set(held.map((arrival) => arrival.url))).to.deep.equal(
			new Set(['/a', '/b'])
		);
		expect(manager.deliveryStats()).to.deep.include({
			active: 3,
			queued: 13,
			queuedBytes: size * 16,
			overflowed: 84,
			delivered: 0
		});

		answer = (): number => 200;
		release(200);
		await until(() => manager.deliveryStats().delivered === 16, manager, peak);

		expect(peak.active).to.be.at.most(3);
		expect(peak.queuedBytes).to.equal(size * 16);
		expect(peakOpenTotal).to.be.at.most(3);
		expect(peakOpen.get('/a')).to.be.at.most(2);
		expect(peakOpen.get('/b')).to.be.at.most(2);
		for (const url of ['/a', '/b']) {
			expect(
				arrivals
					.filter((arrival) => arrival.url === url)
					.map((arrival) => (arrival.data as { seq: string }).seq)
			).to.deep.equal([
				'0000',
				'0001',
				'0002',
				'0003',
				'0004',
				'0005',
				'0006',
				'0007'
			]);
		}
		expect(manager.deliveryStats()).to.deep.equal({
			active: 0,
			queued: 0,
			queuedBytes: 0,
			delivered: 16,
			failed: 0,
			overflowed: 84,
			discarded: 0
		});
	});

	it('a failing recipient burst retries each delivery once, with its payload, within the ceilings', async () => {
		const manager = create({
			maxActiveDeliveries: 8,
			maxActivePerWebhook: 2,
			retryDelayMs: 10
		});
		manager.register(`http://127.0.0.1:${port}/fail`, ['*'], 'secret');
		answer = (): number => 500;
		const peak = { active: 0, queuedBytes: 0 };

		for (let i = 0; i < 10; i++) manager.dispatch('payment:received', seq(i));
		await until(() => manager.deliveryStats().failed === 10, manager, peak);
		await new Promise((resolve) => setTimeout(resolve, 50));

		expect(peak.active).to.be.at.most(2);
		expect(peakOpen.get('/fail')).to.be.at.most(2);
		expect(arrivals).to.have.length(20);
		const attempts = new Map<string, number>();
		for (const arrival of arrivals) {
			attempts.set(arrival.payload, (attempts.get(arrival.payload) ?? 0) + 1);
		}
		expect([...attempts.values()]).to.deep.equal(new Array(10).fill(2));
		expect(manager.deliveryStats()).to.deep.include({
			active: 0,
			queued: 0,
			queuedBytes: 0,
			delivered: 0,
			failed: 10
		});
	});

	it('a backlog at one recipient neither starves another of workers nor of bytes', async () => {
		const size = payloadBytes('payment:received', seq(0));
		const manager = create({
			maxActiveDeliveries: 3,
			maxActivePerWebhook: 2,
			maxQueuedBytesPerWebhook: size * 5,
			maxQueuedBytes: size * 10
		});
		manager.register(`http://127.0.0.1:${port}/slow`, ['*']);
		manager.register(`http://127.0.0.1:${port}/fast`, ['*']);
		answer = (arrival): number | 'hold' =>
			arrival.url === '/slow' ? 'hold' : 200;

		for (let i = 0; i < 5; i++) manager.dispatch('payment:received', seq(i));
		await until(
			() => arrivals.filter((arrival) => arrival.url === '/fast').length === 5
		);
		// The slow backlog keeps its own bytes; the fast one's are released.
		expect(manager.deliveryStats().queuedBytes).to.equal(size * 5);

		for (let i = 5; i < 10; i++) manager.dispatch('payment:received', seq(i));
		await until(
			() => arrivals.filter((arrival) => arrival.url === '/fast').length === 10
		);

		expect(held).to.have.length(2);
		expect(held.every((arrival) => arrival.url === '/slow')).to.equal(true);
		expect(manager.deliveryStats()).to.deep.include({
			delivered: 10,
			overflowed: 5,
			queuedBytes: size * 5
		});
	});

	it('hold deliveries keep their order per payment hash with workers to spare', async () => {
		const manager = create({ maxActivePerWebhook: 4 });
		manager.register(`http://127.0.0.1:${port}/hook`, ['*']);
		answer = (arrival): number | 'hold' =>
			arrival.event === 'hold:accepted' &&
			(arrival.data as { paymentHash: string }).paymentHash === 'invoice-a'
				? 'hold'
				: 200;

		manager.dispatch('hold:accepted', { paymentHash: 'invoice-a' });
		manager.dispatch('hold:settled', { paymentHash: 'invoice-a' });
		manager.dispatch('hold:accepted', { paymentHash: 'invoice-b' });
		manager.dispatch('hold:settled', { paymentHash: 'invoice-b' });
		await until(() => arrivals.length === 3);
		await new Promise((resolve) => setTimeout(resolve, 50));

		const lifecycle = (hash: string): string[] =>
			arrivals
				.filter(
					(arrival) =>
						(arrival.data as { paymentHash: string }).paymentHash === hash
				)
				.map((arrival) => arrival.event);
		expect(lifecycle('invoice-a')).to.deep.equal(['hold:accepted']);
		expect(lifecycle('invoice-b')).to.deep.equal([
			'hold:accepted',
			'hold:settled'
		]);

		release(200);
		await until(() => arrivals.length === 4);
		expect(lifecycle('invoice-a')).to.deep.equal([
			'hold:accepted',
			'hold:settled'
		]);
	});

	it('unregister drops queued deliveries and does not retry the one in flight', async () => {
		const manager = create({ maxActivePerWebhook: 1, retryDelayMs: 10 });
		const registration = manager.register(`http://127.0.0.1:${port}/hook`, [
			'*'
		]);
		const size = payloadBytes('payment:received', seq(0));
		answer = (): 'hold' => 'hold';
		for (let i = 0; i < 3; i++) manager.dispatch('payment:received', seq(i));
		await until(() => held.length === 1);

		manager.unregister(registration.id);
		// The request already sent is left to finish, and keeps its bytes.
		expect(manager.deliveryStats()).to.deep.include({
			active: 1,
			queued: 0,
			queuedBytes: size,
			discarded: 2
		});

		release(500);
		await until(() => manager.deliveryStats().active === 0);
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(arrivals).to.have.length(1);
		expect(manager.deliveryStats()).to.deep.include({
			queuedBytes: 0,
			failed: 0,
			discarded: 3
		});
	});

	it('unregister ends a retry pause at once', async () => {
		const manager = create({ retryDelayMs: 60_000 });
		const registration = manager.register(`http://127.0.0.1:${port}/hook`, [
			'*'
		]);
		answer = (): number => 500;
		manager.dispatch('hold:accepted', { paymentHash: 'invoice-a' });
		manager.dispatch('hold:settled', { paymentHash: 'invoice-a' });
		await until(() => arrivals.length === 1);
		expect(manager.deliveryStats().active).to.equal(1);

		manager.unregister(registration.id);
		await until(() => manager.deliveryStats().active === 0);
		expect(arrivals).to.have.length(1);
		expect(manager.deliveryStats()).to.deep.include({
			queued: 0,
			queuedBytes: 0,
			discarded: 2
		});
	});

	it('stop() aborts requests in flight, drops the queue and ignores later dispatches', async () => {
		const manager = create({ maxActivePerWebhook: 1 });
		manager.register(`http://127.0.0.1:${port}/hook`, ['*']);
		answer = (): 'hold' => 'hold';
		manager.dispatch('payment:received', seq(0));
		manager.dispatch('payment:received', seq(1));
		await until(() => held.length === 1);

		const aborted = new Promise<void>((resolve) =>
			held[0].res.on('close', () => resolve())
		);
		await manager.stop();
		await aborted;
		expect(manager.deliveryStats()).to.deep.equal({
			active: 0,
			queued: 0,
			queuedBytes: 0,
			delivered: 0,
			failed: 0,
			overflowed: 0,
			discarded: 2
		});

		manager.dispatch('payment:received', seq(2));
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(arrivals).to.have.length(1);
		expect(manager.deliveryStats().queued).to.equal(0);
		expect(manager.list()).to.have.length(1);
	});

	it('an attempt that outlasts timeoutMs fails, and its retry follows', async () => {
		const manager = create({ timeoutMs: 100, retryDelayMs: 10 });
		manager.register(`http://127.0.0.1:${port}/hook`, ['*']);
		answer = (): 'hold' => 'hold';
		manager.dispatch('payment:received', seq(0));
		await until(() => manager.deliveryStats().failed === 1);
		expect(arrivals).to.have.length(2);
		expect(arrivals[1].payload).to.equal(arrivals[0].payload);
	});

	it('refused connections and unusable stored urls fail without an unhandled rejection', async () => {
		const closed = http.createServer();
		await new Promise<void>((resolve) =>
			closed.listen(0, '127.0.0.1', () => resolve())
		);
		const deadPort = (closed.address() as { port: number }).port;
		await new Promise((resolve) => closed.close(resolve));
		const storage: IWebhookStorage = {
			saveWebhook: () => undefined,
			deleteWebhook: () => undefined,
			deleteAllWebhooks: () => undefined,
			loadAllWebhooks: () => [
				{ id: 'ftp', url: 'ftp://example.com/x', events: ['*'], createdAt: 1 },
				{ id: 'bad', url: 'not a url', events: ['*'], createdAt: 1 },
				{
					id: 'refused',
					url: `http://127.0.0.1:${deadPort}/hook`,
					events: ['*'],
					createdAt: 1
				}
			]
		};
		const manager = new WebhookManager(storage, { retryDelayMs: 10 });
		managers.push(manager);
		manager.dispatch('payment:received', seq(0));
		await until(() => manager.deliveryStats().failed === 3);
		expect(manager.deliveryStats().active).to.equal(0);
	});

	it('webhookMetrics reports the stats in Prometheus text format', () => {
		const text = webhookMetrics({
			active: 1,
			queued: 2,
			queuedBytes: 300,
			delivered: 4,
			failed: 5,
			overflowed: 6,
			discarded: 7
		});
		for (const line of text.trim().split('\n')) {
			expect(
				line.startsWith('#') || /^[a-z_]+(\{[^}]*\})?\s+[\d.]+$/.test(line),
				line
			).to.equal(true);
		}
		expect(text).to.include('beignet_webhook_deliveries_active 1\n');
		expect(text).to.include('beignet_webhook_deliveries_queued 2\n');
		expect(text).to.include('beignet_webhook_queued_bytes 300\n');
		expect(text).to.include(
			'beignet_webhook_deliveries_total{outcome="overflow"} 6\n'
		);
		expect(text).to.include(
			'beignet_webhook_deliveries_total{outcome="discarded"} 7\n'
		);
	});
});
