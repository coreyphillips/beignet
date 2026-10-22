/**
 * Issue #1691: the BeignetNode methods that take a payment hash decoded it
 * with Buffer.from(hash, 'hex'), which stops at the first non-hex pair. A
 * typo decoded to a short buffer that matched nothing, so POST
 * /payment/cancel answered ok, POST /payment/metadata stored the metadata
 * under that buffer, and POST /payment/wait waited out its timeout. Each now
 * refuses anything but 64 hex characters as INVALID_PARAMS, the way the
 * channel methods refuse a malformed channel id (#1603).
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	IStartedDaemon,
	startDaemon,
	statusForErrorCode
} from '../../src/cli/daemon';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const PAYMENT_HASH = 'cd'.repeat(32);

/** Each decodes, unchecked, to a buffer that is not the hash the caller meant. */
const MALFORMED_HASHES: Array<[string, string]> = [
	['non-hex', 'zz'],
	['62 characters', 'cd'.repeat(31)],
	['a trailing character', PAYMENT_HASH + 'e'],
	['a typo in the last pair', 'cd'.repeat(31) + 'cz']
];

const ENGINE_METHODS = [
	'getPayment',
	'getPaymentProof',
	'getOutgoingHtlcs',
	'failPayment',
	'waitForPayment',
	'getInvoice',
	'setPaymentMetadata',
	'createInvoice',
	'cancelHoldInvoice',
	'listHeldHtlcs',
	'sendPaymentToRoute'
];

/** A BeignetNode whose engine fails the test if the hash guard is skipped. */
function guardedNode(): BeignetNode {
	const engine: Record<string, unknown> = {};
	for (const name of ENGINE_METHODS) {
		engine[name] = (): never =>
			expect.fail(`${name}: the hash guard was skipped`);
	}
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: engine,
		storage: {
			loadPayment: (): never =>
				expect.fail('loadPayment: the hash guard was skipped')
		},
		networkName: 'regtest'
	}) as unknown as BeignetNode;
}

const ROUTE_HOP = {
	pubkey: '02' + 'ab'.repeat(32),
	shortChannelId: '0'.repeat(16),
	amountToForwardMsat: '1000',
	outgoingCltvValue: 100
};

const METHODS: Array<[string, (bn: BeignetNode, hash: string) => unknown]> = [
	['getPayment', (bn, hash): unknown => bn.getPayment(hash)],
	['paymentOutcome', (bn, hash): unknown => bn.paymentOutcome(hash)],
	['getPaymentProof', (bn, hash): unknown => bn.getPaymentProof(hash)],
	['verifyPaymentProof', (bn, hash): unknown => bn.verifyPaymentProof(hash)],
	['cancelPayment', (bn, hash): unknown => bn.cancelPayment(hash)],
	['waitForPayment', (bn, hash): unknown => bn.waitForPayment(hash, 10)],
	['getInvoice', (bn, hash): unknown => bn.getInvoice(hash)],
	[
		'setPaymentMetadata',
		(bn, hash): unknown => bn.setPaymentMetadata(hash, { note: 'x' })
	],
	// These three checked inline with their own wording.
	[
		'createHoldInvoice',
		(bn, hash): unknown => bn.createHoldInvoice({ paymentHash: hash })
	],
	['cancelHoldInvoice', (bn, hash): unknown => bn.cancelHoldInvoice(hash)],
	[
		'sendToRoute',
		(bn, hash): unknown =>
			bn.sendToRoute(hash, {
				hops: [ROUTE_HOP] as unknown as Parameters<
					BeignetNode['sendToRoute']
				>[1]['hops']
			})
	]
];

describe('Issue #1691: payment methods refuse a malformed payment hash', () => {
	for (const [method, call] of METHODS) {
		for (const [label, hash] of MALFORMED_HASHES) {
			it(`${method} refuses ${label}`, async () => {
				try {
					await call(guardedNode(), hash);
				} catch (err: unknown) {
					expect(err).to.be.instanceOf(BeignetError);
					const code = (err as BeignetError).code;
					expect(code).to.equal(BeignetErrorCode.INVALID_PARAMS);
					expect(statusForErrorCode(code)).to.equal(400);
					expect((err as Error).message).to.equal(
						'paymentHash must be a 64-character hex payment hash'
					);
					return;
				}
				expect.fail(`${method}: expected a refusal`);
			});
		}
	}

	it('looks an uppercase hash up as the lowercase key it is stored under', () => {
		const seen: unknown[] = [];
		const bn = Object.assign(Object.create(BeignetNode.prototype), {
			node: {
				getPayment: (hash: Buffer): null => {
					seen.push(hash.toString('hex'));
					return null;
				},
				getInvoice: (hashHex: string): null => {
					seen.push(hashHex);
					return null;
				}
			},
			storage: {
				loadPayment: (hashHex: string): null => {
					seen.push(hashHex);
					return null;
				}
			}
		}) as unknown as BeignetNode;
		expect(bn.getPayment(PAYMENT_HASH.toUpperCase())).to.equal(null);
		expect(bn.getInvoice(PAYMENT_HASH.toUpperCase())).to.equal(null);
		expect(seen).to.deep.equal([PAYMENT_HASH, PAYMENT_HASH, PAYMENT_HASH]);
	});
});

function request(
	port: number,
	method: 'GET' | 'POST',
	route: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body === undefined ? '' : JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: route,
				method,
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(payload)
				}
			},
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
		req.end(payload);
	});
}

describe('Issue #1691: payment routes answer a malformed hash with 400', function () {
	this.timeout(30_000);

	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-payment-hash-'));
	let daemon: IStartedDaemon;
	let port: number;

	before(async () => {
		// Offline (unreachable Electrum): every case is refused before anything
		// needs a chain source.
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic: MNEMONIC,
			daemonPort: 0,
			dataDir: dir
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	/** Each route, and for a POST the rest of a body it would otherwise accept. */
	const ROUTES: Array<[string, Record<string, unknown>?]> = [
		['GET /payment'],
		['GET /payment/proof'],
		['GET /payment/verify-proof'],
		['GET /invoice'],
		['POST /payment/cancel', {}],
		['POST /payment/wait', { timeoutMs: 10 }],
		['POST /payment/metadata', { metadata: { note: 'x' } }],
		['POST /invoice/cancel-hold', {}]
	];

	for (const [route, rest] of ROUTES) {
		it(`${route} refuses every malformed hash as INVALID_PARAMS`, async () => {
			const routePath = route.split(' ')[1];
			for (const [label, hash] of MALFORMED_HASHES) {
				const res =
					rest === undefined
						? await request(
								port,
								'GET',
								`${routePath}?paymentHash=${encodeURIComponent(hash)}`
						  )
						: await request(port, 'POST', routePath, {
								paymentHash: hash,
								...rest
						  });
				expect(res.status, label).to.equal(400);
				expect(res.body.ok, label).to.equal(false);
				expect((res.body.error as { code: string }).code, label).to.equal(
					'INVALID_PARAMS'
				);
			}
		});
	}

	it('still answers a well-formed unknown hash as not found', async () => {
		const res = await request(
			port,
			'GET',
			`/payment?paymentHash=${PAYMENT_HASH}`
		);
		expect(res.status).to.equal(404);
	});
});
