/**
 * Event granularity (M4 batch 2b): the daemon relays invoice + channel
 * lifecycle events over SSE and webhooks, per-HTLC events are gated behind
 * the htlcEvents config flag, and the webhook wildcard covers all of them.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { expect } from 'chai';
import { formatSseFrame, getRelayedEvents } from '../../src/cli/daemon';
import { WebhookManager } from '../../src/cli/webhooks';
import { BeignetNode, holdInvoiceEvent } from '../../src/cli/beignet-node';
import { EPaymentType } from '../../src/types/wallet';

const NEW_EVENTS = [
	'invoice:settled',
	'channel:opening',
	'channel:pending-close',
	'channel:force-closing',
	'channel:resolved',
	// The splice lifecycle (issue #760).
	'splice:complete',
	'splice:aborted',
	'splice:conflicted',
	'splice:reverted'
];
const HTLC_EVENTS = ['htlc:forwarded', 'htlc:fulfilled', 'htlc:failed'];
/**
 * Hold-invoice lifecycle (issue #746). One event per transition, and the
 * ACCEPTED edge is what a swap provider commits its own money on, so these are
 * never behind the htlcEvents gate that per-forward volume earned.
 */
const HOLD_EVENTS = ['hold:accepted', 'hold:settled', 'hold:cancelled'];
/** Recovery events LightningNode emits and BeignetNode relays JSON-safe. */
const RECOVERY_NODE_EVENTS = [
	'recovery:durable',
	'recovery:fenced',
	'recovery:backfill-lost',
	'recovery:reestablish-held'
];
/**
 * Recovery events that ORIGINATE in BeignetNode (like node:ready): the
 * daemon owns the barrier and the restore driver, so it bridges their
 * callbacks instead of relaying a LightningNode emission.
 */
const RECOVERY_DAEMON_EVENTS = [
	'recovery:capsule-retrieved',
	'recovery:guardian_unreachable',
	'recovery:restore-progress',
	'recovery:restored'
];
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

		it('relays the hold-invoice events, with and without htlc events', () => {
			for (const e of HOLD_EVENTS) {
				expect(getRelayedEvents(), e).to.include(e);
				expect(getRelayedEvents(true), e).to.include(e);
			}
		});

		// Low volume by construction, and the operator surface (degraded-state
		// badges, restore progress) rides them, so they are never gated.
		it('relays the recovery events, with and without htlc events', () => {
			for (const e of [...RECOVERY_NODE_EVENTS, ...RECOVERY_DAEMON_EVENTS]) {
				expect(getRelayedEvents(), e).to.include(e);
				expect(getRelayedEvents(true), e).to.include(e);
			}
		});
	});

	// On-chain events come from the WALLET, not the lightning node: the
	// wallet has reported transactionReceived/transactionConfirmed all along,
	// and until now nothing listened, so an on-chain receive changed
	// /transactions and said nothing. These pin the whole relay chain.
	describe('transaction events (wallet-sourced)', () => {
		const TX_EVENTS = [
			'transaction:received',
			'transaction:sent',
			'transaction:confirmed'
		];

		it('relays them, with and without htlc events', () => {
			for (const e of TX_EVENTS) {
				expect(getRelayedEvents(), e).to.include(e);
				expect(getRelayedEvents(true), e).to.include(e);
			}
		});

		it('BeignetNode wires the wallet message handler', () => {
			const src = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(src).to.include('onMessage: (key, data) => this.onWalletMessage');
			for (const e of TX_EVENTS) {
				expect(src, e).to.include(`'${e}'`);
			}
		});

		it('converts the wallet message to the wire shape and emits', () => {
			const emitted: Array<[string, Record<string, unknown>]> = [];
			const logged: string[] = [];
			const fake = {
				log: (_level: string, msg: string) => logged.push(msg),
				emit: (name: string, info: Record<string, unknown>) => {
					emitted.push([name, info]);
					return true;
				},
				toOnchainTxInfo: (BeignetNode.prototype as any).toOnchainTxInfo
			};
			const message = {
				transaction: {
					txid: 'a'.repeat(64),
					type: EPaymentType.received,
					value: 0.0005,
					fee: 0,
					satsPerByte: 0,
					address: 'bc1qexample',
					height: 0,
					timestamp: 1753900000000
				}
			};
			(BeignetNode.prototype as any).onWalletMessage.call(
				fake,
				'transactionReceived',
				message
			);
			expect(emitted).to.have.length(1);
			const [name, info] = emitted[0];
			expect(name).to.equal('transaction:received');
			expect(info.txid).to.equal('a'.repeat(64));
			expect(info.type).to.equal('received');
			expect(info.valueSats, 'BTC converted to sats').to.equal(50_000);
			expect(info.confirmed, 'height 0 is unconfirmed').to.equal(false);
			expect(logged).to.deep.equal(['Transaction received']);

			(BeignetNode.prototype as any).onWalletMessage.call(
				fake,
				'transactionConfirmed',
				{ transaction: { ...message.transaction, height: 908214 } }
			);
			expect(emitted).to.have.length(2);
			expect(emitted[1][0]).to.equal('transaction:confirmed');
			expect(emitted[1][1].confirmed).to.equal(true);

			(BeignetNode.prototype as any).onWalletMessage.call(
				fake,
				'transactionSent',
				{
					transaction: {
						...message.transaction,
						type: EPaymentType.sent,
						value: -0.0005,
						fee: 0.00000141
					}
				}
			);
			expect(emitted).to.have.length(3);
			expect(emitted[2][0]).to.equal('transaction:sent');
			expect(emitted[2][1].type).to.equal('sent');
			expect(emitted[2][1].feeSats).to.equal(141);

			// The keys not relayed stay silent rather than half-translated.
			(BeignetNode.prototype as any).onWalletMessage.call(
				fake,
				'connectedToElectrum',
				true
			);
			expect(emitted).to.have.length(3);
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

	describe('hold invoice event bridge', function () {
		this.timeout(20_000);
		let node: BeignetNode | undefined;
		let dataDir: string;

		before(async () => {
			dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-hold-events-'));
			node = await BeignetNode.create({
				network: 'regtest',
				dataDir,
				logLevel: 'info',
				electrumHost: '127.0.0.1',
				electrumPort: 65529,
				electrumTls: false,
				rapidGossipSync: false,
				autoGossipSync: false
			});
		});

		after(async () => {
			await node?.destroy();
			fs.rmSync(dataDir, { recursive: true, force: true });
		});

		it('relays each engine payload through the installed listeners as valid SSE JSON', () => {
			const paymentHash = Buffer.alloc(32, 0xab);
			const received: Array<[string, unknown]> = [];
			for (const event of HOLD_EVENTS) {
				node!.once(event, (data: unknown) => {
					const frame = formatSseFrame(event, data);
					expect(frame).to.match(new RegExp(`^event: ${event}\\ndata: `));
					received.push([event, JSON.parse(frame.split('\ndata: ')[1])]);
				});
			}
			node!.lightningNode.emit('hold:accepted', {
				paymentHash,
				state: 'ACCEPTED',
				heldAmountMsat: 5_000_000n,
				htlcCount: 2
			});
			node!.lightningNode.emit('hold:settled', {
				paymentHash,
				state: 'SETTLED',
				heldAmountMsat: 5_000_000n,
				htlcCount: 2
			});
			node!.lightningNode.emit('hold:cancelled', {
				paymentHash,
				reason: 'expiry-scan',
				heldAmountMsat: 5_000_000n,
				htlcsFailed: 2
			});
			const common = {
				paymentHash: 'ab'.repeat(32),
				heldAmountMsat: '5000000',
				htlcCount: 2
			};
			expect(received).to.deep.equal([
				['hold:accepted', { ...common, state: 'ACCEPTED' }],
				['hold:settled', { ...common, state: 'SETTLED' }],
				[
					'hold:cancelled',
					{ ...common, state: 'CANCELLED', reason: 'expiry-scan' }
				]
			]);
		});

		it('relays acceptance before a log listener synchronously cancels the invoice', () => {
			const paymentHash = 'cd'.repeat(32);
			node!.createHoldInvoice({ paymentHash, amountSats: 5_000 });
			const received: Array<[string, unknown]> = [];
			node!.once('hold:accepted', (data) =>
				received.push(['hold:accepted', data])
			);
			node!.once('hold:cancelled', (data) =>
				received.push(['hold:cancelled', data])
			);
			node!.once('log', () => node!.cancelHoldInvoice(paymentHash));
			// Inject the engine notification at the bridge boundary. The log
			// listener calls the real cancellation API on an open invoice.
			node!.lightningNode.emit('hold:accepted', {
				paymentHash: Buffer.from(paymentHash, 'hex'),
				state: 'ACCEPTED',
				heldAmountMsat: 5_000_000n,
				htlcCount: 1
			});
			expect(received).to.deep.equal([
				[
					'hold:accepted',
					{
						paymentHash,
						state: 'ACCEPTED',
						heldAmountMsat: '5000000',
						htlcCount: 1
					}
				],
				[
					'hold:cancelled',
					{
						paymentHash,
						state: 'CANCELLED',
						heldAmountMsat: '0',
						htlcCount: 0,
						reason: 'api'
					}
				]
			]);
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

		it('LightningNode emits, and BeignetNode relays, the node-origin recovery events', () => {
			for (const e of RECOVERY_NODE_EVENTS) {
				expect(lightningNodeSrc, e).to.include(`'${e}'`);
				expect(beignetNodeSrc, `relay for ${e}`).to.match(
					new RegExp(`this\\.node\\.on\\(\\s*'${e}'`)
				);
				expect(beignetNodeSrc, `emit for ${e}`).to.include(`this.emit('${e}'`);
			}
		});

		it('LightningNode emits, and BeignetNode relays, the hold-invoice events', () => {
			for (const e of HOLD_EVENTS) {
				expect(lightningNodeSrc, e).to.include(`'${e}'`);
				expect(beignetNodeSrc, `relay for ${e}`).to.match(
					new RegExp(`this\\.node\\.on\\(\\s*'${e}'`)
				);
				expect(beignetNodeSrc, `emit for ${e}`).to.include(`this.emit('${e}'`);
			}
		});

		// SSE JSON.stringifies the payload, and a consumer swaps this in for a
		// GET /invoices/held row: same field names, same JSON-safe types.
		it('relays a hold transition in the GET /invoices/held row shape', () => {
			const wire = holdInvoiceEvent({
				paymentHash: Buffer.alloc(32, 0xab),
				state: 'ACCEPTED',
				heldAmountMsat: 5_000_000n,
				htlcCount: 2
			});
			expect(() => JSON.stringify(wire)).to.not.throw();
			expect(wire).to.deep.equal({
				paymentHash: 'ab'.repeat(32),
				state: 'ACCEPTED',
				heldAmountMsat: '5000000',
				htlcCount: 2
			});
		});

		it('BeignetNode originates the daemon-side recovery events', () => {
			for (const e of RECOVERY_DAEMON_EVENTS) {
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
			const all = [...NEW_EVENTS, ...HTLC_EVENTS, ...HOLD_EVENTS];
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
