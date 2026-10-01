import * as http from 'http';
import * as crypto from 'crypto';
import { expect } from 'chai';
import {
	IWebhookStorage,
	WebhookManager,
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
