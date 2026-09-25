/**
 * Routing fees inside the spending limits (issue #1008). Every Lightning pay
 * path (payInvoice, payInvoiceWithRetry, the queue, sendPaymentAsync,
 * sendKeysend, payOffer) sends under a fee cap: the caller's maxFeeSats /
 * maxFeeMsat, or a default of 1% of the amount with a 50 sat floor. The
 * per-payment limit and the daily ledger count the amount PLUS that cap at
 * admission, and the amount plus the fee actually paid at settlement.
 *
 * Before this the pay paths handed the engine no cap by default, and both
 * limits saw the invoice amount only, so a route hint carrying a u32
 * fee_base_msat of 0xffffffff routed a 4.29M sat fee past a 1 sat limit.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's senders are stubbed, so nothing here needs a chain or a
 * channel.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import {
	AsyncSpendClaim,
	BeignetNode,
	DEFAULT_MAX_FEE_FLOOR_SATS,
	DEFAULT_MAX_FEE_PPM,
	LogEntry,
	defaultMaxFeeMsat
} from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';
import { QueuedPayment } from '../../src/cli/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';

// Same rationale as tests/cli/async-payment-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const PUBKEY = '02' + '11'.repeat(32);

type StubbedEngine = {
	sendPayment: (...args: unknown[]) => unknown;
	sendKeysend: (opts: { maxFeeMsat?: bigint }) => unknown;
	requestInvoice: (...args: unknown[]) => Promise<unknown>;
	payBolt12Invoice: (...args: unknown[]) => unknown;
	hasHtlcInFlight: (paymentHash: Buffer) => boolean;
	emit: (event: string, info: unknown) => boolean;
};

type Internals = {
	node: StubbedEngine;
	_pendingSpendSats: number;
	_asyncSpendClaims: Map<string, AsyncSpendClaim[]>;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

/** Sats the claims of a hash still hold against the daily budget. */
const claimedSats = (node: BeignetNode, paymentHash: string): number =>
	(internals(node)._asyncSpendClaims.get(paymentHash) ?? [])
		.filter((claim) => claim.reserved)
		.reduce((total, claim) => total + claim.sats, 0);

/** An invoice from somebody else, which is what a payment path is given. */
const invoiceFrom = (
	amountSats: number | undefined,
	description: string
): { bolt11: string; paymentHash: string } => {
	const paymentHash = crypto.randomBytes(32);
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat:
				amountSats !== undefined ? BigInt(amountSats) * 1000n : undefined,
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

const hashes = new Map<string, string>();

/** A fixed-amount (or amountless) invoice whose hash the stubs can settle. */
const invoice = (
	amountSats: number | undefined,
	description: string
): string => {
	const { bolt11, paymentHash } = invoiceFrom(amountSats, description);
	hashes.set(bolt11, paymentHash);
	return bolt11;
};

/** The settlement report the engine emits, with whatever the record carries. */
type SettleFields = {
	amountMsat: bigint;
	sentMsat?: bigint;
	route?: {
		hops: never[];
		totalAmountMsat: bigint;
		totalFeeMsat: bigint;
		totalCltvDelta: number;
	};
};

const settle = (
	node: BeignetNode,
	paymentHash: string,
	fields: SettleFields
): void => {
	internals(node).node.emit('payment:sent', {
		paymentHash: Buffer.from(paymentHash, 'hex'),
		status: 'COMPLETED',
		direction: 'OUTGOING',
		createdAt: Date.now(),
		completedAt: Date.now(),
		...fields
	});
};

/**
 * Replaces sendPayment with a recorder of the fee cap it was handed. With
 * `settles`, each submission is settled at once at its amount, as a real node
 * would once it paid, so the blocking callers resolve.
 */
const recordCaps = (
	node: BeignetNode,
	opts: { settles?: boolean } = {}
): Array<bigint | undefined> => {
	const caps: Array<bigint | undefined> = [];
	const engine = internals(node).node;
	engine.sendPayment = (...args: unknown[]): unknown => {
		caps.push(args[2] as bigint | undefined);
		const bolt11 = String(args[0]);
		if (opts.settles) {
			setImmediate(() => {
				const hash = hashes.get(bolt11);
				if (hash) settle(node, hash, { amountMsat: 1_000_000n });
			});
		}
		return { status: 'PENDING' };
	};
	return caps;
};

/** Replaces sendKeysend with a recorder that completes inside the call. */
const recordKeysendCaps = (node: BeignetNode): Array<bigint | undefined> => {
	const caps: Array<bigint | undefined> = [];
	internals(node).node.sendKeysend = (opts): unknown => {
		caps.push(opts.maxFeeMsat);
		return {
			paymentHash: crypto.randomBytes(32),
			amountMsat: 1_000_000n,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: Date.now(),
			completedAt: Date.now()
		};
	};
	return caps;
};

/**
 * Stubs the payee half of an offer payment: the invoice request answers with
 * a fixed-amount BOLT 12 invoice, and the dispatch records its cap and
 * settles at once.
 */
const stubPayee = (
	node: BeignetNode,
	amountMsat: bigint,
	opts: { settles?: boolean } = {}
): { paymentHash: string; caps: Array<bigint | undefined> } => {
	const paymentHash = crypto.randomBytes(32);
	const payee = {
		paymentHash: paymentHash.toString('hex'),
		caps: [] as Array<bigint | undefined>
	};
	const engine = internals(node).node;
	engine.requestInvoice = async (): Promise<unknown> => ({
		paymentHash,
		amount: amountMsat,
		description: 'stubbed offer invoice',
		createdAt: BigInt(Math.floor(Date.now() / 1000)),
		nodeId: crypto.randomBytes(33)
	});
	engine.payBolt12Invoice = (...args: unknown[]): unknown => {
		payee.caps.push(args[2] as bigint | undefined);
		if (opts.settles) {
			setImmediate(() => settle(node, payee.paymentHash, { amountMsat }));
		}
		return { status: 'PENDING' };
	};
	return payee;
};

/** The message a payment attempt was refused with, or '' if it resolved. */
const refusalOf = async (attempt: () => unknown): Promise<string> => {
	try {
		await attempt();
		return '';
	} catch (err: unknown) {
		return err instanceof Error ? err.message : String(err);
	}
};

/** The queue entry once the queue has finished with it. */
const settledQueueEntry = async (
	node: BeignetNode,
	id: string
): Promise<QueuedPayment> => {
	for (let i = 0; i < 250; i++) {
		const entry = node.listQueue().find((e) => e.id === id);
		if (entry && entry.status !== 'queued' && entry.status !== 'dispatching') {
			return entry;
		}
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
	throw new Error(`queue entry ${id} never settled`);
};

const boot = (
	tmpDir: string,
	limits: { maxPaymentSats?: number; dailySpendLimitSats?: number } = {},
	logLevel: 'silent' | 'warn' = 'silent'
): Promise<BeignetNode> =>
	BeignetNode.create({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir: tmpDir,
		logLevel,
		rapidGossipSync: false,
		autoGossipSync: false,
		...limits,
		...OFFLINE_ELECTRUM
	});

describe('the default routing-fee cap (#1008)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fee-cap-'));
		node = await boot(tmpDir);
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('is 1% of the amount rounded up, and never below 50 sats', () => {
		expect(DEFAULT_MAX_FEE_PPM).to.equal(10_000);
		expect(DEFAULT_MAX_FEE_FLOOR_SATS).to.equal(50);
		// Below 5 000 sats the floor applies.
		expect(defaultMaxFeeMsat(1_000_000n).toString()).to.equal('50000');
		expect(defaultMaxFeeMsat(5_000_000n).toString()).to.equal('50000');
		expect(defaultMaxFeeMsat(0n).toString()).to.equal('50000');
		// Above it, 1%, rounded up to the msat rather than truncated.
		expect(defaultMaxFeeMsat(5_000_001n).toString()).to.equal('50001');
		expect(defaultMaxFeeMsat(1_000_000_000n).toString()).to.equal('10000000');
	});

	it('payInvoice sends under the floor for a small invoice and 1% for a large one', async () => {
		const caps = recordCaps(node, { settles: true });
		await node.payInvoice(invoice(1_000, 'floor'), 5_000);
		await node.payInvoice(invoice(100_000, 'percent'), 5_000);
		// Explicit caps still win, in either unit.
		await node.payInvoice(invoice(100_000, 'explicit sats'), 5_000, 7);
		const pass = [undefined, undefined, undefined, undefined] as const;
		await node.payInvoice(
			invoice(100_000, 'explicit msat'),
			5_000,
			...pass,
			123
		);
		expect(caps.map(String)).to.deep.equal(['50000', '1000000', '7000', '123']);
	});

	it('sizes the default on the amountSats override of an amountless invoice', async () => {
		const caps = recordCaps(node, { settles: true });
		await node.payInvoice(
			invoice(undefined, 'amountless'),
			5_000,
			undefined,
			100_000
		);
		expect(caps.map(String)).to.deep.equal(['1000000']);
	});

	it('sendPaymentAsync, payInvoiceWithRetry and the queue go through the same default', async () => {
		const caps = recordCaps(node, { settles: true });
		node.sendPaymentAsync(invoice(1_000, 'async floor'));
		node.sendPaymentAsync(invoice(100_000, 'async percent'));
		node.sendPaymentAsync(invoice(100_000, 'async explicit'), 7);
		await node.payInvoiceWithRetry(invoice(100_000, 'retry percent'));
		await node.payInvoiceWithRetry(invoice(100_000, 'retry explicit'), {
			maxFeeSats: 7
		});
		expect(caps.map(String)).to.deep.equal([
			'50000',
			'1000000',
			'7000',
			'1000000',
			'7000'
		]);

		// The queue dispatches through payInvoiceSafe. Its own capacity gate is
		// not under test, and an offline node has no channel to pass it with.
		(node as unknown as { canSend: () => { canSend: boolean } }).canSend = (): {
			canSend: boolean;
		} => ({ canSend: true });
		const queued = node.enqueuePayment(invoice(100_000, 'queued'), 1);
		const entry = await settledQueueEntry(node, queued.id);
		expect(entry.status).to.equal('completed');
		expect(String(caps[caps.length - 1])).to.equal('1000000');
	});

	it('sendKeysend and sendKeysendSafe send under the default too', async () => {
		const caps = recordKeysendCaps(node);
		await node.sendKeysend(PUBKEY, 1_000);
		await node.sendKeysend(PUBKEY, 100_000);
		await node.sendKeysend(PUBKEY, 100_000, 60_000, 3);
		await node.sendKeysendSafe(PUBKEY, 1_000);
		expect(caps.map(String)).to.deep.equal([
			'50000',
			'1000000',
			'3000',
			'50000'
		]);
	});

	it('payOffer sizes the default on the invoice the payee returns', async () => {
		const small = stubPayee(node, 1_000_000n, { settles: true });
		await node.payOffer(node.createOffer({ description: 'small' }).encoded!);
		const large = stubPayee(node, 100_000_000n, { settles: true });
		await node.payOffer(node.createOffer({ description: 'large' }).encoded!);
		const explicit = stubPayee(node, 100_000_000n, { settles: true });
		await node.payOffer(
			node.createOffer({ description: 'explicit' }).encoded!,
			undefined,
			5_000,
			7
		);
		expect(small.caps.map(String)).to.deep.equal(['50000']);
		expect(large.caps.map(String)).to.deep.equal(['1000000']);
		expect(explicit.caps.map(String)).to.deep.equal(['7000']);
	});
});

describe('amount plus fee cap at admission, amount plus fee at settlement (#1008)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	const pending = (): number => internals(node)._pendingSpendSats;
	const spent = (): number => node.getDailySpendInfo().spentSats;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fee-limits-'));
		node = await boot(tmpDir, {
			maxPaymentSats: 5_000,
			dailySpendLimitSats: 10_000
		});
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('refuses a 4 960 sat invoice with no cap given, and admits it under maxFeeSats 40', async () => {
		const caps = recordCaps(node);
		const bolt11 = invoice(4_960, 'just under');

		// 4 960 plus the 50 sat floor is 5 010: over the limit, and the
		// refusal says which of the two to lower.
		expect(await refusalOf(() => node.payInvoice(bolt11, 5_000))).to.equal(
			'Payment amount 4960 sats plus up to 50 sats in routing fees exceeds per-payment limit of 5000 sats; lower maxFeeSats or the amount'
		);
		expect(caps).to.have.length(0);
		expect(pending()).to.equal(0);

		// 4 960 plus 40 fits exactly.
		const paid = node.payInvoice(bolt11, 5_000, 40);
		expect(caps.map(String)).to.deep.equal(['40000']);
		expect(pending()).to.equal(5_000);
		expect(node.getDailySpendInfo().pendingSats).to.equal(5_000);
		settle(node, hashes.get(bolt11)!, { amountMsat: 4_990_000n });
		await paid;
		expect(spent()).to.equal(4_990);
		expect(pending()).to.equal(0);
	});

	it('refuses an amount over the limit on its own in the words it always used', async () => {
		recordCaps(node);
		const refusal = await refusalOf(() =>
			node.payInvoice(invoice(5_001, 'too big'), 5_000)
		);
		expect(refusal).to.equal(
			'Payment amount 5001 sats exceeds per-payment limit of 5000 sats'
		);
		expect(refusal).to.not.contain('routing fees');
	});

	it('sendPaymentAsync, sendKeysend and payOffer admit on amount plus cap too', async () => {
		const caps = recordCaps(node);
		const keysendCaps = recordKeysendCaps(node);
		const payee = stubPayee(node, 4_960_000n);
		const withFees =
			'Payment amount 4960 sats plus up to 50 sats in routing fees exceeds per-payment limit of 5000 sats; lower maxFeeSats or the amount';

		expect(
			await refusalOf(() => node.sendPaymentAsync(invoice(4_960, 'async')))
		).to.equal(withFees);
		expect(await refusalOf(() => node.sendKeysend(PUBKEY, 4_960))).to.equal(
			withFees
		);
		expect(
			await refusalOf(() =>
				node.payOffer(node.createOffer({ description: 'offer' }).encoded!)
			)
		).to.equal(withFees);
		expect(caps).to.have.length(0);
		expect(keysendCaps).to.have.length(0);
		expect(payee.caps).to.have.length(0);
		expect(pending()).to.equal(0);
	});

	it('the daily limit counts the cap, and the refusal breaks the request down', async () => {
		recordCaps(node);
		// 9 000 of the 10 000 sat day is spent, with no fee cap in the way.
		for (const description of ['first', 'second']) {
			const bolt11 = invoice(4_500, description);
			const paid = node.payInvoice(bolt11, 5_000, 0);
			settle(node, hashes.get(bolt11)!, { amountMsat: 4_500_000n });
			await paid;
		}
		expect(spent()).to.equal(9_000);

		// 990 sats would fit; 990 plus the 50 sat floor does not.
		const bolt11 = invoice(990, 'over with fees');
		expect(await refusalOf(() => node.payInvoice(bolt11, 5_000))).to.equal(
			'Daily spend limit exceeded. Limit: 10000 sats, spent: 9000 sats, remaining: 1000 sats, requested: 1040 sats (990 sats plus up to 50 sats in routing fees; lower maxFeeSats or the amount)'
		);
		expect(pending()).to.equal(0);

		const paid = node.payInvoice(bolt11, 5_000, 10);
		expect(pending()).to.equal(1_000);
		settle(node, hashes.get(bolt11)!, { amountMsat: 995_000n });
		await paid;
		expect(spent()).to.equal(9_995);
		expect(pending()).to.equal(0);
	});

	it('reserves the amount plus the cap while the payment is in flight', () => {
		recordCaps(node);
		const floor = invoice(1_000, 'floor');
		const { paymentHash } = node.sendPaymentAsync(floor);
		expect(claimedSats(node, paymentHash)).to.equal(1_050);
		expect(pending()).to.equal(1_050);

		const capped = node.sendPaymentAsync(invoice(2_000, 'capped'), 7);
		expect(claimedSats(node, capped.paymentHash)).to.equal(2_007);
		expect(pending()).to.equal(3_057);
		expect(node.getDailySpendInfo().pendingSats).to.equal(3_057);
	});

	it('charges the amount plus the fee actually paid and releases the reservation', () => {
		recordCaps(node);
		const { paymentHash } = node.sendPaymentAsync(invoice(1_000, 'settles'));
		expect(pending()).to.equal(1_050);

		// The record's amountMsat is the first-hop amount, fees included: the
		// route cost 20 sats of the 50 allowed.
		settle(node, paymentHash, { amountMsat: 1_020_000n });
		expect(spent()).to.equal(1_020);
		expect(node.getDailySpendInfo().lightningSats).to.equal(1_020);
		expect(pending()).to.equal(0);
		expect(internals(node)._asyncSpendClaims.size).to.equal(0);

		// A repeated terminal event must not count the payment twice.
		settle(node, paymentHash, { amountMsat: 1_020_000n });
		expect(spent()).to.equal(1_020);
	});

	it('charges sentMsat over amountMsat when the record carries it', () => {
		recordCaps(node);
		const { paymentHash } = node.sendPaymentAsync(invoice(1_000, 'mpp'), 100);
		expect(pending()).to.equal(1_100);

		// An MPP record: amountMsat is the invoice amount, its route the first
		// part only, and sentMsat the sum of the parts' first-hop amounts.
		settle(node, paymentHash, {
			amountMsat: 1_000_000n,
			sentMsat: 1_070_000n,
			route: {
				hops: [],
				totalAmountMsat: 500_000n,
				totalFeeMsat: 35_000n,
				totalCltvDelta: 40
			}
		});
		expect(spent()).to.equal(1_070);
		expect(pending()).to.equal(0);
	});

	it('falls back to the reservation for an MPP record written before sentMsat existed', () => {
		recordCaps(node);
		const { paymentHash } = node.sendPaymentAsync(
			invoice(1_000, 'old mpp'),
			100
		);
		expect(pending()).to.equal(1_100);

		// Its route (the first part) totals less than the invoice, and nothing
		// in the record says what the other parts cost: the reservation is
		// the only figure that covers every part.
		settle(node, paymentHash, {
			amountMsat: 1_000_000n,
			route: {
				hops: [],
				totalAmountMsat: 600_000n,
				totalFeeMsat: 5_000n,
				totalCltvDelta: 40
			}
		});
		expect(spent()).to.equal(1_100);
		expect(pending()).to.equal(0);
	});

	it('reserves nothing for an amountless invoice without an override, and the override plus the cap with one', () => {
		// An amountless invoice with no override has nothing to admit (the
		// engine refuses it); with an override it reserves that plus the cap.
		recordCaps(node);
		expect(
			node.sendPaymentAsync(invoice(undefined, 'nothing')).status
		).to.equal('PENDING');
		expect(pending()).to.equal(0);
		node.sendPaymentAsync(invoice(undefined, 'override'), undefined, 2_000);
		expect(pending()).to.equal(2_050);
	});
});

describe('a settlement above its reservation (#1008)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fee-over-'));
		node = await boot(tmpDir, { dailySpendLimitSats: 10_000 }, 'warn');
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('is charged in full and logged', () => {
		const warnings: LogEntry[] = [];
		node.on('log', (...args: unknown[]) => {
			const entry = args[0] as LogEntry;
			if (entry.level === 'warn') warnings.push(entry);
		});
		recordCaps(node);
		// The claim a version that reserved the amount alone left behind: the
		// explicit zero cap reproduces its shape.
		const { paymentHash } = node.sendPaymentAsync(
			invoice(1_000, 'old claim'),
			0
		);
		expect(internals(node)._pendingSpendSats).to.equal(1_000);

		settle(node, paymentHash, { amountMsat: 1_030_000n });
		expect(node.getDailySpendInfo().spentSats).to.equal(1_030);
		expect(internals(node)._pendingSpendSats).to.equal(0);
		const warning = warnings.find((entry) =>
			entry.message.includes('above its reservation')
		);
		expect(warning, 'the over-reservation warning').to.not.equal(undefined);
		expect(warning!.data).to.deep.include({
			paymentHash,
			reservedSats: 1_000,
			sentSats: 1_030
		});
	});
});

describe('validatePayment previews the fee cap (#1008)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	const check = (
		result: {
			checks: Array<{ name: string; status: string; message: string }>;
		},
		name: string
	): { status: string; message: string } => {
		const found = result.checks.find((c) => c.name === name);
		expect(found, `the ${name} check`).to.not.equal(undefined);
		return found!;
	};

	const post = (
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: '/invoice/validate',
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
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fee-validate-'));
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			daemonPort: 0,
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			...OFFLINE_ELECTRUM
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async () => {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('judges the per-payment limit on amount plus cap, the way payInvoice will', () => {
		const bolt11 = invoice(4_960, 'preview');
		const noCap = check(node.validatePayment(bolt11), 'MAX_PAYMENT');
		expect(noCap.status).to.equal('FAIL');
		expect(noCap.message).to.equal(
			'Amount 4960 sats plus up to 50 sats in routing fees exceeds per-payment limit of 5000 sats; lower maxFeeSats or the amount'
		);

		const capped = check(
			node.validatePayment(bolt11, undefined, 40),
			'MAX_PAYMENT'
		);
		expect(capped.status).to.equal('OK');
		expect(capped.message).to.contain('up to 40 sats in routing fees');

		// Over on the amount alone: the words it always used.
		const over = check(
			node.validatePayment(invoice(5_001, 'over')),
			'MAX_PAYMENT'
		);
		expect(over.message).to.equal(
			'Amount 5001 sats exceeds per-payment limit of 5000 sats'
		);
	});

	it('judges the daily limit on amount plus cap', () => {
		(
			node as unknown as {
				_recordSpend: (sats: number, source: 'lightning') => void;
			}
		)._recordSpend(9_000, 'lightning');
		const bolt11 = invoice(990, 'daily preview');
		const noCap = check(node.validatePayment(bolt11), 'DAILY_LIMIT');
		expect(noCap.status).to.equal('FAIL');
		expect(noCap.message).to.equal(
			'Amount 990 sats plus up to 50 sats in routing fees exceeds daily remaining of 1000 sats; lower maxFeeSats or the amount'
		);
		const capped = check(
			node.validatePayment(bolt11, undefined, 10),
			'DAILY_LIMIT'
		);
		expect(capped.status).to.equal('OK');
	});

	it('takes maxFeeSats over HTTP', async () => {
		const bolt11 = invoice(4_960, 'route preview');
		const noCap = await post({ bolt11 });
		const capped = await post({ bolt11, maxFeeSats: 40 });
		const checkOf = (
			res: { body: Record<string, unknown> },
			name: string
		): { status: string } =>
			(
				res.body.result as { checks: Array<{ name: string; status: string }> }
			).checks.find((c) => c.name === name)!;
		expect(checkOf(noCap, 'MAX_PAYMENT').status).to.equal('FAIL');
		expect(checkOf(capped, 'MAX_PAYMENT').status).to.equal('OK');
	});
});
