/**
 * Event granularity (M4 batch 2b): the daemon relays invoice + channel
 * lifecycle events over SSE and webhooks, per-HTLC events are gated behind
 * the htlcEvents config flag, and the webhook wildcard covers all of them.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { expect } from 'chai';
import { getRelayedEvents } from '../../src/cli/daemon';
import { WebhookManager } from '../../src/cli/webhooks';

const NEW_EVENTS = [
	'invoice:settled',
	'channel:opening',
	'channel:pending-close',
	'channel:force-closing'
];
const HTLC_EVENTS = ['htlc:forwarded', 'htlc:fulfilled', 'htlc:failed'];
const BASE_EVENTS = [
	'payment:received',
	'payment:sent',
	'payment:failed',
	'channel:ready',
	'channel:closed',
	'peer:connect',
	'peer:disconnect',
	'node:ready'
];

describe('Event granularity (M4 batch 2b)', () => {
	describe('getRelayedEvents', () => {
		it('includes the original event set', () => {
			const events = getRelayedEvents();
			for (const e of BASE_EVENTS) {
				expect(events, e).to.include(e);
			}
		});

		it('includes the new invoice + channel lifecycle events', () => {
			const events = getRelayedEvents();
			for (const e of NEW_EVENTS) {
				expect(events, e).to.include(e);
			}
		});

		it('excludes htlc events by default (volume)', () => {
			const events = getRelayedEvents();
			for (const e of HTLC_EVENTS) {
				expect(events, e).to.not.include(e);
			}
			expect(getRelayedEvents(false)).to.deep.equal(events);
		});

		it('includes htlc events when htlcEvents is enabled', () => {
			const events = getRelayedEvents(true);
			for (const e of [...BASE_EVENTS, ...NEW_EVENTS, ...HTLC_EVENTS]) {
				expect(events, e).to.include(e);
			}
		});

		// node:error carries the reason a channel open failed (peer rejection,
		// funding failure, disconnect mid-open). Leaving it off the relay list
		// makes a failed open indistinguishable from one that never happened:
		// the pending channel disappears and no client is ever told why.
		it('relays node:error, with and without htlc events', () => {
			expect(getRelayedEvents()).to.include('node:error');
			expect(getRelayedEvents(true)).to.include('node:error');
		});
	});

	describe('daemon wiring', () => {
		const daemonSrc = fs.readFileSync(
			path.join(__dirname, '../../src/cli/daemon.ts'),
			'utf8'
		);

		it('SSE relay uses getRelayedEvents (htlcEvents-aware)', () => {
			const sseSection = daemonSrc.substring(
				daemonSrc.indexOf('// Wire up SSE events'),
				daemonSrc.lastIndexOf('return new Promise')
			);
			expect(sseSection).to.include('getRelayedEvents(opts.htlcEvents)');
			expect(sseSection).to.include('node.on(eventName');
		});

		it('webhooks dispatch the same event set as SSE', () => {
			const sseSection = daemonSrc.substring(
				daemonSrc.indexOf('// Wire up SSE events'),
				daemonSrc.lastIndexOf('return new Promise')
			);
			expect(sseSection).to.include('webhookManager.dispatch(eventName');
		});
	});

	describe('end-to-end relay chain (source wiring)', () => {
		const beignetNodeSrc = fs.readFileSync(
			path.join(__dirname, '../../src/cli/beignet-node.ts'),
			'utf8'
		);
		const lightningNodeSrc = fs.readFileSync(
			path.join(__dirname, '../../src/lightning/node/lightning-node.ts'),
			'utf8'
		);

		it('LightningNode emits every new event', () => {
			for (const e of [...NEW_EVENTS, ...HTLC_EVENTS]) {
				expect(lightningNodeSrc, e).to.include(`'${e}'`);
			}
		});

		it('BeignetNode relays every new event with JSON-safe payloads', () => {
			for (const e of [...NEW_EVENTS, ...HTLC_EVENTS]) {
				expect(beignetNodeSrc, `relay for ${e}`).to.match(
					new RegExp(`this\\.node\\.on\\(\\s*'${e}'`)
				);
				expect(beignetNodeSrc, `emit for ${e}`).to.include(`this.emit('${e}'`);
			}
		});
	});

	describe('webhook wildcard covers new events', () => {
		let manager: WebhookManager;
		let testServer: http.Server;
		let received: Array<{ body: Record<string, unknown> }>;
		let serverPort: number;

		before((done) => {
			received = [];
			testServer = http.createServer((req, res) => {
				const chunks: Buffer[] = [];
				req.on('data', (chunk: Buffer) => chunks.push(chunk));
				req.on('end', () => {
					received.push({
						body: JSON.parse(Buffer.concat(chunks).toString())
					});
					res.statusCode = 200;
					res.end('OK');
				});
			});
			testServer.listen(0, '127.0.0.1', () => {
				serverPort = (testServer.address() as { port: number }).port;
				done();
			});
		});

		after((done) => {
			testServer.close(done);
		});

		beforeEach(() => {
			manager = new WebhookManager();
			received = [];
		});

		it("a '*' registration receives every new event type", async () => {
			manager.register(`http://127.0.0.1:${serverPort}/hook`, ['*']);
			const all = [...NEW_EVENTS, ...HTLC_EVENTS];
			for (const e of all) {
				manager.dispatch(e, { test: e });
			}
			await new Promise((r) => setTimeout(r, 300));
			const deliveredEvents = received.map((r) => r.body.event);
			for (const e of all) {
				expect(deliveredEvents, e).to.include(e);
			}
		});

		it('an exact invoice:settled subscription receives only that event', async () => {
			manager.register(`http://127.0.0.1:${serverPort}/hook`, [
				'invoice:settled'
			]);
			manager.dispatch('invoice:settled', { paymentHash: 'ab' });
			manager.dispatch('channel:force-closing', { channelId: 'cd' });
			await new Promise((r) => setTimeout(r, 300));
			expect(received).to.have.length(1);
			expect(received[0].body.event).to.equal('invoice:settled');
		});
	});
});
