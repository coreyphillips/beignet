/**
 * cltvLimit on POST /invoice/pay and its siblings (issue #751).
 *
 * A swap provider paying the counterparty's invoice is only safe while every
 * HTLC of that payment expires before the on-chain refund opens: past it the
 * payee can hold, refund on chain, then settle over Lightning and be paid
 * twice. The invoice's own final delta is a floor, the route adds per-hop
 * deltas the sender cannot see, so the bound has to reach the engine's route
 * search. The engine already takes an absolute ceiling; this is the daemon
 * handing it a caller's height-relative one.
 *
 * Runs against a daemon over HTTP with the library node's send stubbed: the
 * check that matters is what the route hands the engine, and that a refusal
 * comes back as its own code rather than a generic failure.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import { getOpenApiSpec } from '../../src/cli/openapi';
import {
	IPaymentInfo,
	ISendPaymentOptions,
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { decode } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { Network } from '../../src/lightning/invoice/types';
import crypto from 'crypto';

/** An invoice from some other node: the daemon holds no record of its hash. */
function foreignInvoice(description: string): string {
	return encodeInvoice({
		network: Network.REGTEST,
		amountMsat: 1_000_000n,
		timestamp: Math.floor(Date.now() / 1000),
		paymentHash: crypto.randomBytes(32),
		paymentSecret: crypto.randomBytes(32),
		description,
		privateKey: crypto.randomBytes(32)
	});
}

type Reply = { status: number; json: Record<string, unknown> };

describe('POST /invoice/pay cltvLimit (issue #751)', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;
	let port: number;
	let inner: LightningNode;
	let bolt11 = '';
	const calls: ISendPaymentOptions[] = [];
	let refuse = false;

	const post = (route: string, body: Record<string, unknown>): Promise<Reply> =>
		new Promise((resolve, reject) => {
			const req = http.request(
				{
					host: '127.0.0.1',
					port,
					path: route,
					method: 'POST',
					headers: { 'content-type': 'application/json' }
				},
				(res) => {
					let raw = '';
					res.on('data', (c) => (raw += c));
					res.on('end', () =>
						resolve({
							status: res.statusCode ?? 0,
							json: JSON.parse(raw) as Record<string, unknown>
						})
					);
				}
			);
			req.on('error', reject);
			req.end(JSON.stringify(body));
		});

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-751-'));
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			dataDir,
			daemonPort: 0
		});
		port = (daemon.server.address() as AddressInfo).port;
		inner = (daemon.node as unknown as { node: LightningNode }).node;
		// The tip the bound is relative to, and the engine call the bound must
		// reach. A refused call throws the engine's own code; an accepted one
		// settles at once, the way a loopback payment does.
		inner.getCurrentBlockHeight = (): number => 1_000;
		inner.sendPayment = (
			invoice: string,
			_excluded?: Set<string>,
			maxFeeMsat?: bigint,
			amountMsat?: bigint,
			maxCltvExpiryHeight?: number
		): IPaymentInfo => {
			calls.push({ maxFeeMsat, amountMsat, maxCltvExpiryHeight });
			if (refuse) {
				throw new LightningPaymentError(
					LightningErrorCode.CLTV_EXCEEDS_MAX,
					'no route fits under maxCltvExpiryHeight'
				);
			}
			const decoded = decode(invoice);
			const info: IPaymentInfo = {
				paymentHash: decoded.paymentHash,
				amountMsat: decoded.amountMsat ?? 0n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now(),
				completedAt: Date.now()
			};
			inner.emit('payment:sent', info);
			return info;
		};
		bolt11 = foreignInvoice('cltv bound');
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	beforeEach(() => {
		calls.length = 0;
		refuse = false;
	});

	it('hands the engine the tip plus the limit as the absolute ceiling', async () => {
		const { status, json } = await post('/invoice/pay', {
			bolt11,
			cltvLimit: 144
		});
		expect(status, JSON.stringify(json)).to.equal(200);
		expect(calls).to.have.length(1);
		expect(calls[0].maxCltvExpiryHeight).to.equal(1_144);
	});

	it('leaves the engine unbounded when the field is absent', async () => {
		const { status } = await post('/invoice/pay', { bolt11 });
		expect(status).to.equal(200);
		expect(calls[0].maxCltvExpiryHeight).to.equal(undefined);
	});

	it('every sibling route carries the same bound', async () => {
		const safe = await post('/invoice/pay-safe', { bolt11, cltvLimit: 40 });
		expect(safe.status).to.equal(200);
		const retry = await post('/invoice/pay-retry', {
			bolt11,
			cltvLimit: 41,
			maxRetries: 0
		});
		expect(retry.status, JSON.stringify(retry.json)).to.equal(200);
		const async = await post('/invoice/pay-async', { bolt11, cltvLimit: 42 });
		expect(async.status, JSON.stringify(async.json)).to.equal(200);
		expect(calls.map((c) => c.maxCltvExpiryHeight)).to.deep.equal([
			1_040, 1_041, 1_042
		]);
	});

	it('refuses a limit that is not a positive integer before anything is reserved', async () => {
		for (const value of [0, -1, 1.5, 'abc', 2 ** 53]) {
			const { status, json } = await post('/invoice/pay', {
				bolt11,
				cltvLimit: value
			});
			expect(status, String(value)).to.equal(400);
			expect((json.error as { code: string }).code).to.equal('INVALID_PARAMS');
			expect((json.error as { message: string }).message).to.match(
				/cltvLimit must be a positive integer/
			);
		}
		expect(calls).to.have.length(0);
		// The refusal left no spend reservation behind: a plain pay still goes.
		const ok = await post('/invoice/pay', { bolt11 });
		expect(ok.status).to.equal(200);
	});

	it('refuses a bound while the tip is unknown, rather than guessing one', async () => {
		inner.getCurrentBlockHeight = (): number => 0;
		try {
			const { status, json } = await post('/invoice/pay', {
				bolt11,
				cltvLimit: 144
			});
			expect(status).to.equal(503);
			expect((json.error as { code: string }).code).to.equal(
				'CHAIN_NOT_SYNCED'
			);
			expect(calls).to.have.length(0);
		} finally {
			inner.getCurrentBlockHeight = (): number => 1_000;
		}
	});

	it('an engine refusal under the bound is CLTV_EXCEEDS_MAX, not a generic failure', async () => {
		refuse = true;
		// A hash of its own: pay-safe hands back any record the hash already
		// has, and the cases above settled the shared one.
		const refused = foreignInvoice('cltv bound refused');
		const { status, json } = await post('/invoice/pay', {
			bolt11: refused,
			cltvLimit: 10
		});
		expect(status).to.equal(409);
		expect((json.error as { code: string }).code).to.equal('CLTV_EXCEEDS_MAX');
		const safe = await post('/invoice/pay-safe', {
			bolt11: refused,
			cltvLimit: 10
		});
		expect(safe.status).to.equal(200);
		const info = safe.json.result as {
			status: string;
			failureDescription?: string;
		};
		expect(info.status).to.equal('FAILED');
		expect(info.failureDescription).to.match(/^\[CLTV_EXCEEDS_MAX\]/);
		const async = await post('/invoice/pay-async', {
			bolt11: refused,
			cltvLimit: 10
		});
		expect(async.status).to.equal(409);
		expect((async.json.error as { code: string }).code).to.equal(
			'CLTV_EXCEEDS_MAX'
		);
	});

	it('documents the field on every pay route so a caller can probe for it', () => {
		// pubky-swap reads GET /openapi.json at startup and drops submarine
		// swaps from its offer when /invoice/pay has no cltvLimit property.
		const spec = getOpenApiSpec() as unknown as {
			paths: Record<
				string,
				Record<
					string,
					{
						requestBody?: {
							content?: Record<
								string,
								{ schema?: { properties?: Record<string, unknown> } }
							>;
						};
					}
				>
			>;
		};
		for (const route of [
			'/invoice/pay',
			'/invoice/pay-safe',
			'/invoice/pay-async',
			'/invoice/pay-retry'
		]) {
			const schema =
				spec.paths[route].post.requestBody?.content?.['application/json']
					.schema;
			expect(schema?.properties, route).to.have.property('cltvLimit');
		}
	});
});
