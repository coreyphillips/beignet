/**
 * An exact fee cap on the blocking payment paths (issue #998): payInvoice,
 * payInvoiceSafe, POST /invoice/pay and POST /invoice/pay-safe take
 * maxFeeMsat alongside maxFeeSats, so a caller holding an exact quote
 * (estimatePayment's estimatedFeeMsat) can cap at it. maxFeeSats is
 * unchanged, and the two together are refused before anything is reserved.
 *
 * Offline suite: the node boots against an unreachable Electrum server and the
 * engine's sendPayment is stubbed, so nothing here needs a chain or a channel.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetNode } from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';

const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

type Internals = {
	node: {
		sendPayment: (...args: unknown[]) => unknown;
		emit: (event: string, info: unknown) => boolean;
	};
	_pendingSpendSats: number;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

const invoiceFrom = (
	amountSats: number,
	description: string
): { bolt11: string; paymentHash: string } => {
	const paymentHash = crypto.randomBytes(32);
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat: BigInt(amountSats) * 1000n,
			timestamp: Math.floor(Date.now() / 1000),
			paymentHash,
			paymentSecret: crypto.randomBytes(32),
			description,
			expiry: 3600,
			minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			privateKey: crypto
				.createHash('sha256')
				.update(Buffer.from(`payee-${description}`))
				.digest()
		}),
		paymentHash: paymentHash.toString('hex')
	};
};

/**
 * Replaces sendPayment with a recorder of the fee cap it was handed, and
 * settles each submission at once, as a real node would once it paid.
 */
const recordFeeCaps = (node: BeignetNode): Array<bigint | undefined> => {
	const caps: Array<bigint | undefined> = [];
	const engine = internals(node).node;
	engine.sendPayment = (...args: unknown[]): unknown => {
		caps.push(args[2] as bigint | undefined);
		const bolt11 = String(args[0]);
		setImmediate(() => {
			const hash = hashes.get(bolt11);
			if (!hash) return;
			engine.emit('payment:sent', {
				paymentHash: Buffer.from(hash, 'hex'),
				amountMsat: 1_000_000n,
				status: 'COMPLETED',
				direction: 'OUTGOING',
				createdAt: Date.now(),
				completedAt: Date.now()
			});
		});
		return { status: 'PENDING' };
	};
	return caps;
};

const hashes = new Map<string, string>();

const invoice = (description: string): string => {
	const { bolt11, paymentHash } = invoiceFrom(1_000, description);
	hashes.set(bolt11, paymentHash);
	return bolt11;
};

const refusalOf = async (attempt: Promise<unknown>): Promise<string> => {
	try {
		await attempt;
		return '';
	} catch (err: unknown) {
		return err instanceof Error ? err.message : String(err);
	}
};

describe('payInvoice exact fee cap (#998)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-max-fee-msat-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM
		});
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('still hands the engine maxFeeSats in msat', async () => {
		const caps = recordFeeCaps(node);
		await node.payInvoice(invoice('sats cap'), 5_000, 11);
		await node.payInvoice(invoice('no cap'), 5_000);
		expect(caps).to.deep.equal([11_000n, undefined]);
	});

	it('hands the engine an exact maxFeeMsat, as a number or a string', async () => {
		const caps = recordFeeCaps(node);
		// maxFeeSats, amountSats, metadata and cltvLimit left unset.
		const pass = [undefined, undefined, undefined, undefined] as const;
		await node.payInvoice(invoice('msat number'), 5_000, ...pass, 1024);
		await node.payInvoice(invoice('msat string'), 5_000, ...pass, '1024');
		await node.payInvoiceSafe(invoice('msat safe'), 5_000, ...pass, '0');
		expect(caps).to.deep.equal([1024n, 1024n, 0n]);
	});

	it('refuses both caps at once before reserving anything', async () => {
		const caps = recordFeeCaps(node);
		const bolt11 = invoice('both');

		expect(
			await refusalOf(
				node.payInvoice(bolt11, 5_000, 2, undefined, undefined, undefined, 1024)
			)
		).to.contain('mutually exclusive');
		const safe = await node.payInvoiceSafe(
			bolt11,
			5_000,
			2,
			undefined,
			undefined,
			undefined,
			1024
		);
		expect(safe.status).to.equal('FAILED');
		expect(safe.failureDescription).to.contain('[INVALID_PARAMS]');

		expect(caps).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('refuses a malformed maxFeeMsat before reserving anything', async () => {
		const caps = recordFeeCaps(node);
		const pass = [undefined, undefined, undefined, undefined] as const;
		for (const bad of [-1, 1.5, '1.5', '-1', '', 'abc']) {
			expect(
				await refusalOf(
					node.payInvoice(invoice(`bad ${bad}`), 5_000, ...pass, bad)
				)
			).to.contain('maxFeeMsat must be');
		}
		expect(caps).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});
});

describe('HTTP pay routes take maxFeeMsat (#998)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	const post = (
		route: string,
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: route,
					method: 'POST',
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
			req.write(payload);
			req.end();
		});

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-max-fee-api-'));
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			daemonPort: 0,
			...OFFLINE_ELECTRUM
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async () => {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('passes each cap through to the engine', async () => {
		const caps = recordFeeCaps(node);

		const sats = await post('/invoice/pay-safe', {
			bolt11: invoice('route sats'),
			maxFeeSats: 11
		});
		const msat = await post('/invoice/pay-safe', {
			bolt11: invoice('route msat'),
			maxFeeMsat: '1024'
		});
		const blocking = await post('/invoice/pay', {
			bolt11: invoice('route pay msat'),
			maxFeeMsat: 1024
		});

		for (const res of [sats, msat, blocking]) {
			expect((res.body.result as { status: string }).status).to.equal(
				'COMPLETED'
			);
		}
		expect(caps).to.deep.equal([11_000n, 1024n, 1024n]);
	});

	it('refuses both caps at once', async () => {
		const caps = recordFeeCaps(node);
		const body = {
			bolt11: invoice('route both'),
			maxFeeSats: 2,
			maxFeeMsat: 1024
		};

		const pay = await post('/invoice/pay', body);
		expect(pay.status).to.equal(400);
		expect((pay.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);

		const safe = await post('/invoice/pay-safe', body);
		const result = safe.body.result as {
			status: string;
			failureDescription: string;
		};
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.contain('[INVALID_PARAMS]');
		expect(caps).to.have.length(0);
	});
});
