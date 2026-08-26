/**
 * BOLT 12 offer payment admission (issue #529): payOffer, and the
 * POST /offer/pay route on top of it, apply the same drain check, per-payment
 * and daily limits, pending-spend reservation and daily accounting as the
 * BOLT 11 paths — all keyed on the amount of the invoice the payee returns,
 * which is what payBolt12Invoice pays.
 *
 * Offline suite: the node boots against an unreachable Electrum server and the
 * payee half of the exchange (requestInvoice, payBolt12Invoice) is stubbed, so
 * nothing here needs a chain, a peer or a channel.
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

// Same rationale as tests/cli/async-payment-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

type StubbedEngine = {
	requestInvoice: (...args: unknown[]) => Promise<unknown>;
	payBolt12Invoice: (...args: unknown[]) => unknown;
	sendPayment: (...args: unknown[]) => unknown;
	emit: (event: string, info: unknown) => boolean;
};

type Internals = {
	node: StubbedEngine;
	_pendingSpendSats: number;
	_blockingPaymentHashes: Map<string, number>;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

/** The encoded offer a payer would be handed. */
const offerString = (node: BeignetNode, description: string): string =>
	node.createOffer({ description }).encoded!;

type Payee = {
	/** Payment hash of the invoice this payee answers with. */
	paymentHash: string;
	/** What each invoice request asked the payee for, in msat. */
	requests: Array<bigint | undefined>;
	/** Payment hashes payOffer handed to the engine to pay. */
	dispatched: string[];
};

/**
 * Stubs the payee half of an offer payment: the invoice request answers with a
 * fixed-amount BOLT 12 invoice, and the dispatch is recorded rather than routed.
 */
const stubPayee = (
	node: BeignetNode,
	amountMsat: bigint | undefined,
	opts: {
		/** Thrown by the dispatch, as a refused send does. */
		throws?: Error;
		/** Runs while the invoice request is still in flight. */
		duringRequest?: () => void;
		/** The hash to issue the invoice under; random by default. */
		paymentHash?: Buffer;
	} = {}
): Payee => {
	const paymentHash = opts.paymentHash ?? crypto.randomBytes(32);
	const payee: Payee = {
		paymentHash: paymentHash.toString('hex'),
		requests: [],
		dispatched: []
	};
	const engine = internals(node).node;
	engine.requestInvoice = async (...args: unknown[]): Promise<unknown> => {
		payee.requests.push((args[1] as { amount?: bigint } | undefined)?.amount);
		if (opts.duringRequest) opts.duringRequest();
		return {
			paymentHash,
			amount: amountMsat,
			description: 'stubbed offer invoice',
			createdAt: BigInt(Math.floor(Date.now() / 1000)),
			nodeId: crypto.randomBytes(33)
		};
	};
	engine.payBolt12Invoice = (...args: unknown[]): unknown => {
		payee.dispatched.push(
			(args[0] as { paymentHash: Buffer }).paymentHash.toString('hex')
		);
		if (opts.throws) throw opts.throws;
		return { status: 'PENDING' };
	};
	return payee;
};

/** Emits the engine event that settles a payment, as the real node would. */
const settle = (
	node: BeignetNode,
	paymentHash: string,
	amountSats: number,
	status: 'COMPLETED' | 'FAILED'
): void => {
	internals(node).node.emit(
		status === 'COMPLETED' ? 'payment:sent' : 'payment:failed',
		{
			paymentHash: Buffer.from(paymentHash, 'hex'),
			amountMsat: BigInt(amountSats) * 1000n,
			status,
			direction: 'OUTGOING',
			createdAt: Date.now(),
			completedAt: Date.now()
		}
	);
};

/** The message a payment attempt was refused with, or '' if it resolved. */
const refusalOf = async (attempt: Promise<unknown>): Promise<string> => {
	try {
		await attempt;
		return '';
	} catch (err: unknown) {
		return err instanceof Error ? err.message : String(err);
	}
};

/** Waits for state a payment in flight reaches a few microtasks from now. */
const waitFor = async (
	predicate: () => boolean,
	label: string
): Promise<void> => {
	for (let i = 0; i < 250; i++) {
		if (predicate()) return;
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
	throw new Error(`timed out waiting for ${label}`);
};

describe('payOffer admission and spend accounting (#529)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	const pending = (): number => internals(node)._pendingSpendSats;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-offer-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			...OFFLINE_ELECTRUM
		});
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('refuses a new offer payment while draining, without asking the payee', async () => {
		const payee = stubPayee(node, 1_000_000n);
		const offer = offerString(node, 'draining');
		node.setDraining(true);

		expect(await refusalOf(node.payOffer(offer))).to.contain(
			'Node is draining'
		);
		// A drained node does not go asking a payee for an invoice it may not pay.
		expect(payee.requests).to.have.length(0);
		expect(payee.dispatched).to.have.length(0);
		expect(pending()).to.equal(0);
	});

	it('refuses a drain that starts while the invoice request is in flight', async () => {
		const payee = stubPayee(node, 1_000_000n, {
			duringRequest: () => node.setDraining(true)
		});

		expect(
			await refusalOf(node.payOffer(offerString(node, 'drains mid-request')))
		).to.contain('Node is draining');
		// The request is a round trip to the payee, so the check before it is not
		// the one that keeps an HTLC in.
		expect(payee.requests).to.have.length(1);
		expect(payee.dispatched).to.have.length(0);
		expect(pending()).to.equal(0);
	});

	it('refuses an invoice over the per-payment limit', async () => {
		const payee = stubPayee(node, 5_001_000n);

		expect(
			await refusalOf(node.payOffer(offerString(node, 'too big')))
		).to.contain('Payment amount 5001 sats exceeds per-payment limit');
		expect(payee.dispatched).to.have.length(0);
		expect(pending()).to.equal(0);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);
	});

	it('limits the invoice the payee returned, not the amount the caller asked for', async () => {
		// The payee prices the offer and payBolt12Invoice pays that price, so
		// admitting the request's amountSats let a 1 sat request pay any invoice.
		const payee = stubPayee(node, 6_000_000n);

		expect(
			await refusalOf(node.payOffer(offerString(node, 'underpriced ask'), 1))
		).to.contain('Payment amount 6000 sats exceeds per-payment limit');
		// The request itself still carried what the caller asked for.
		expect(payee.requests).to.deep.equal([1_000n]);
		expect(payee.dispatched).to.have.length(0);
		expect(pending()).to.equal(0);
	});

	it('reserves the amount in flight so concurrent offer payments cannot overshoot the daily limit', async () => {
		const first = stubPayee(node, 4_000_000n);
		const firstPaid = node.payOffer(offerString(node, 'first'));
		await waitFor(() => pending() === 4_000, 'the first reservation');

		const second = stubPayee(node, 4_000_000n);
		const secondPaid = node.payOffer(offerString(node, 'second'));
		await waitFor(() => pending() === 8_000, 'the second reservation');
		// Nothing has settled, so the reported spend is still zero: it is the
		// reservation, not the spend, that has to refuse the third payment.
		expect(node.getDailySpendInfo().spentSats).to.equal(0);

		const third = stubPayee(node, 4_000_000n);
		expect(
			await refusalOf(node.payOffer(offerString(node, 'third')))
		).to.contain('Daily spend limit exceeded');
		expect(third.dispatched).to.have.length(0);

		settle(node, first.paymentHash, 4_000, 'COMPLETED');
		settle(node, second.paymentHash, 4_000, 'COMPLETED');
		await firstPaid;
		await secondPaid;
		expect(node.getDailySpendInfo().spentSats).to.equal(8_000);
		expect(pending()).to.equal(0);
	});

	it('records the spend once and drops the reservation on settlement', async () => {
		const payee = stubPayee(node, 3_000_000n);
		const paid = node.payOffer(offerString(node, 'settles'));
		await waitFor(() => pending() === 3_000, 'the reservation');
		expect(payee.dispatched).to.deep.equal([payee.paymentHash]);

		settle(node, payee.paymentHash, 3_000, 'COMPLETED');
		const info = await paid;
		expect(info.status).to.equal('COMPLETED');
		expect(pending()).to.equal(0);
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(node.getDailySpendInfo().lightningSats).to.equal(3_000);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);

		// A repeated terminal event must not count the payment twice.
		settle(node, payee.paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(pending()).to.equal(0);
	});

	it('releases the reservation when the payment fails', async () => {
		const payee = stubPayee(node, 3_000_000n);
		const paid = node.payOffer(offerString(node, 'fails'));
		await waitFor(() => pending() === 3_000, 'the reservation');

		settle(node, payee.paymentHash, 3_000, 'FAILED');
		expect(await refusalOf(paid)).to.contain('Payment failed');
		expect(pending()).to.equal(0);
		expect(node.getDailySpendInfo().spentSats).to.equal(0);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);
	});

	it('releases the reservation when the payment times out', async () => {
		stubPayee(node, 5_000_000n);
		const paid = node.payOffer(
			offerString(node, 'never settles'),
			undefined,
			50
		);

		expect(await refusalOf(paid)).to.contain('Payment timed out');
		// Half the daily allowance would otherwise stay reserved for the life of
		// the process, and refuse real payments once the counter passed the limit.
		expect(pending()).to.equal(0);
		expect(node.getDailySpendInfo().spentSats).to.equal(0);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);
	});

	it('releases the reservation when the engine refuses the dispatch', async () => {
		const payee = stubPayee(node, 5_000_000n, {
			throws: new Error('No route found')
		});

		expect(
			await refusalOf(node.payOffer(offerString(node, 'no route')))
		).to.contain('No route found');
		expect(payee.dispatched).to.have.length(1);
		expect(pending()).to.equal(0);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);

		// The budget is intact: a payment that never started holds no capacity,
		// so the retry is refused by the engine again rather than by the limit.
		expect(
			await refusalOf(node.payOffer(offerString(node, 'no route again')))
		).to.contain('No route found');
	});

	it('owns the hash it is paying, so the async ledger cannot charge the same settlement', async () => {
		// A payee that issued one preimage under a BOLT 11 invoice and again
		// under the offer's invoice. The async attempt's claim and payOffer's
		// own listener would otherwise both charge the single settlement.
		const paymentHash = crypto.randomBytes(32);
		internals(node).node.sendPayment = (): unknown => ({ status: 'PENDING' });
		node.sendPaymentAsync(
			encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 3_000_000n,
				timestamp: Math.floor(Date.now() / 1000),
				paymentHash,
				paymentSecret: crypto.randomBytes(32),
				description: 'same preimage, over BOLT 11',
				expiry: 3600,
				minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
				privateKey: crypto.createHash('sha256').update('payee').digest()
			})
		);
		expect(pending()).to.equal(3_000);

		const payee = stubPayee(node, 3_000_000n, { paymentHash });
		const paid = node.payOffer(
			offerString(node, 'same preimage, over BOLT 12')
		);
		await waitFor(() => pending() === 6_000, 'both reservations');

		settle(node, payee.paymentHash, 3_000, 'COMPLETED');
		await paid;
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		// The async attempt's HTLC is still out there and the engine reports
		// nothing further for a hash it has marked completed, so its claim goes
		// on holding budget rather than being handed back on this settlement.
		expect(pending()).to.equal(3_000);
		expect(internals(node)._blockingPaymentHashes.size).to.equal(0);
	});

	it('rounds a sub-satoshi invoice up instead of letting it skip the limits', async () => {
		const payee = stubPayee(node, 999n);
		const paid = node.payOffer(offerString(node, 'fractional'));
		await waitFor(() => pending() === 1, 'the rounded-up reservation');

		settle(node, payee.paymentHash, 1, 'COMPLETED');
		await paid;
		// Truncating 999 msat to 0 sats took the payment out of admission and out
		// of the accounting alike, so any number of them could be paid.
		expect(node.getDailySpendInfo().spentSats).to.equal(1);
		expect(pending()).to.equal(0);
	});
});

describe('POST /offer/pay admission (#529)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	const pending = (): number => internals(node)._pendingSpendSats;

	const post = (
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: '/offer/pay',
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

	const errorCode = (body: Record<string, unknown>): string =>
		(body.error as { code: string }).code;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-offer-api-'));
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

	it('answers 409 SERVICE_DRAINING while draining', async () => {
		const payee = stubPayee(node, 1_000_000n);
		const offer = offerString(node, 'route draining');
		node.setDraining(true);
		try {
			const res = await post({ offer });
			expect(res.status).to.equal(409);
			expect(errorCode(res.body)).to.equal('SERVICE_DRAINING');
			expect(payee.dispatched).to.have.length(0);
		} finally {
			node.setDraining(false);
		}
	});

	it('answers 403 SPENDING_LIMIT_EXCEEDED over the per-payment limit', async () => {
		const payee = stubPayee(node, 5_001_000n);

		const res = await post({ offer: offerString(node, 'route too big') });
		expect(res.status).to.equal(403);
		expect(errorCode(res.body)).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(payee.dispatched).to.have.length(0);
		expect(pending()).to.equal(0);
	});

	it('reserves an accepted payment against the daily budget', async () => {
		const first = stubPayee(node, 4_000_000n);
		const firstRes = post({ offer: offerString(node, 'route first') });
		await waitFor(() => pending() === 4_000, 'the first reservation');

		const second = stubPayee(node, 4_000_000n);
		const secondRes = post({ offer: offerString(node, 'route second') });
		await waitFor(() => pending() === 8_000, 'the second reservation');

		const third = stubPayee(node, 4_000_000n);
		const refused = await post({ offer: offerString(node, 'route third') });
		expect(refused.status).to.equal(403);
		expect(errorCode(refused.body)).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(third.dispatched).to.have.length(0);

		settle(node, first.paymentHash, 4_000, 'COMPLETED');
		settle(node, second.paymentHash, 4_000, 'COMPLETED');
		expect((await firstRes).body.ok).to.equal(true);
		expect((await secondRes).body.ok).to.equal(true);
		expect(node.getDailySpendInfo().spentSats).to.equal(8_000);
		expect(pending()).to.equal(0);
	});
});
