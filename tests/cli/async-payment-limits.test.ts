/**
 * Async payment admission (issue #526): sendPaymentAsync and the
 * POST /invoice/pay-async route apply drain mode, the per-payment and daily
 * spending limits, and the same pending-spend reservation payInvoice applies,
 * despite returning before the payment settles.
 *
 * Offline suite: the node boots against an unreachable Electrum server and the
 * engine's sendPayment is stubbed, so nothing here needs a chain or a channel.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import {
	AsyncSpendClaim,
	ASYNC_SPEND_CLAIM_TTL_MS,
	BeignetNode,
	MAX_ASYNC_SPEND_CLAIM_HASHES
} from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';

// Same rationale as tests/cli/agent-production-hardening.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

type StubbedEngine = {
	sendPayment: (...args: unknown[]) => unknown;
	emit: (event: string, info: unknown) => boolean;
	createInvoice: (options: { amountMsat?: bigint; description?: string }) => {
		bolt11: string;
		paymentHash: Buffer;
	};
};

type Internals = {
	node: StubbedEngine;
	_pendingSpendSats: number;
	_dailySpendResetTime: number;
	_asyncSpendClaims: Map<string, AsyncSpendClaim[]>;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

/** Sats every outstanding async claim for a hash still holds. */
const claimedSats = (node: BeignetNode, paymentHash: string): number =>
	(internals(node)._asyncSpendClaims.get(paymentHash) ?? []).reduce(
		(total, claim) => total + claim.sats,
		0
	);

/** Ages every outstanding claim past its window, as the clock would. */
const ageClaimsPastExpiry = (node: BeignetNode): void => {
	for (const claims of internals(node)._asyncSpendClaims.values()) {
		for (const claim of claims) claim.expiresAt = Date.now() - 1;
	}
};

/** Replaces sendPayment with a recorder; returns the recorded submissions. */
const stubSendPayment = (node: BeignetNode, throws?: Error): string[] => {
	const calls: string[] = [];
	internals(node).node.sendPayment = (...args: unknown[]): unknown => {
		calls.push(String(args[0]));
		if (throws) throw throws;
		return undefined;
	};
	return calls;
};

/**
 * A fixed-amount invoice for a msat amount that is not a whole satoshi, which
 * BeignetNode.createInvoice cannot express (it takes sats).
 */
const msatInvoice = (
	node: BeignetNode,
	amountMsat: bigint,
	description: string
): { bolt11: string; paymentHash: string } => {
	const result = internals(node).node.createInvoice({
		amountMsat,
		description
	});
	return {
		bolt11: result.bolt11,
		paymentHash: result.paymentHash.toString('hex')
	};
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

describe('sendPaymentAsync admission and spend accounting (#526)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-async-'));
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

	it('refuses a new payment while draining, without reaching the engine', () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = node.createInvoice(1_000, 'draining');
		node.setDraining(true);

		expect(() => node.sendPaymentAsync(bolt11)).to.throw('Node is draining');
		expect(calls).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('refuses a payment over the per-payment limit', () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = node.createInvoice(5_001, 'too big');

		expect(() => node.sendPaymentAsync(bolt11)).to.throw(
			'exceeds per-payment limit'
		);
		expect(calls).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('enforces the per-payment limit on the amount override of an amountless invoice', () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = node.createInvoice(undefined, 'amountless');

		expect(() => node.sendPaymentAsync(bolt11, undefined, 5_001)).to.throw(
			'exceeds per-payment limit'
		);
		expect(calls).to.have.length(0);
	});

	it('reserves the amount while pending so concurrent submissions cannot overshoot the daily limit', () => {
		const calls = stubSendPayment(node);
		const first = node.sendPaymentAsync(
			node.createInvoice(4_000, 'first').bolt11
		);
		const second = node.sendPaymentAsync(
			node.createInvoice(4_000, 'second').bolt11
		);
		expect(first.status).to.equal('PENDING');
		expect(second.status).to.equal('PENDING');
		expect(internals(node)._pendingSpendSats).to.equal(8_000);
		// Nothing has settled, so the reported spend is still zero: it is the
		// reservation, not the spend, that has to refuse the third payment.
		expect(node.getDailySpendInfo().spentSats).to.equal(0);

		const third = node.createInvoice(4_000, 'third').bolt11;
		expect(() => node.sendPaymentAsync(third)).to.throw(
			'Daily spend limit exceeded'
		);
		expect(calls).to.have.length(2);
	});

	it('records the spend once and drops the reservation on settlement', () => {
		stubSendPayment(node);
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(3_000, 'settles').bolt11
		);
		expect(internals(node)._pendingSpendSats).to.equal(3_000);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(internals(node)._pendingSpendSats).to.equal(0);
		const info = node.getDailySpendInfo();
		expect(info.spentSats).to.equal(3_000);
		expect(info.lightningSats).to.equal(3_000);

		// A repeated terminal event must not count the payment twice.
		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('keeps a failed payment claimed, because its HTLC can still settle', () => {
		stubSendPayment(node);
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(3_000, 'fails').bolt11
		);

		settle(node, paymentHash, 3_000, 'FAILED');
		// A failure report is not a retraction: cancelPayment() and both engine
		// sweeps mark a payment FAILED with its HTLC still out there.
		expect(internals(node)._pendingSpendSats).to.equal(3_000);
		expect(claimedSats(node, paymentHash)).to.equal(3_000);
		expect(node.getDailySpendInfo().spentSats).to.equal(0);
	});

	it('holds the daily budget a failed payment can still spend', () => {
		stubSendPayment(node);
		const cancelled = node.sendPaymentAsync(
			node.createInvoice(5_000, 'cancelled').bolt11
		);
		settle(node, cancelled.paymentHash, 5_000, 'FAILED');

		const second = node.sendPaymentAsync(
			node.createInvoice(5_000, 'second').bolt11
		);
		// Freeing the budget on the failure report let a caller cancel a live
		// payment and spend its whole allowance a second time.
		const third = node.createInvoice(5_000, 'third').bolt11;
		expect(() => node.sendPaymentAsync(third)).to.throw(
			'Daily spend limit exceeded'
		);

		settle(node, cancelled.paymentHash, 5_000, 'COMPLETED');
		settle(node, second.paymentHash, 5_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(10_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('releases a claim that has run out of time, not one that is merely old', () => {
		stubSendPayment(node);
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(5_000, 'expires').bolt11
		);
		settle(node, paymentHash, 5_000, 'FAILED');
		expect(internals(node)._pendingSpendSats).to.equal(5_000);

		ageClaimsPastExpiry(node);
		// Swept on the admission path, so the budget comes back with no timer
		// and no settlement — and only once the amount can no longer be spent.
		node.sendPaymentAsync(node.createInvoice(5_000, 'after expiry').bolt11);
		expect(internals(node)._pendingSpendSats).to.equal(5_000);
		expect(internals(node)._asyncSpendClaims.has(paymentHash)).to.equal(false);
	});

	it('holds a claim for one full daily window', () => {
		stubSendPayment(node);
		const before = Date.now();
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(1_000, 'ttl').bolt11
		);

		const [claim] = internals(node)._asyncSpendClaims.get(paymentHash)!;
		expect(claim.expiresAt).to.be.at.least(before + ASYNC_SPEND_CLAIM_TTL_MS);
		expect(claim.expiresAt).to.be.at.most(
			Date.now() + ASYNC_SPEND_CLAIM_TTL_MS
		);
	});

	it('releases the claim when the engine refuses the submission', () => {
		stubSendPayment(node, new Error('No route found'));
		const { bolt11 } = node.createInvoice(3_000, 'no route');

		expect(() => node.sendPaymentAsync(bolt11)).to.throw('No route found');
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(internals(node)._asyncSpendClaims.size).to.equal(0);
		// The budget is intact: a payment that never started holds no capacity.
		expect(() => node.sendPaymentAsync(bolt11)).to.throw('No route found');
	});

	it('limits a fixed-amount invoice by its own amount, not by the override', () => {
		const calls = stubSendPayment(node);
		// The engine pays the encoded 6 000 sats whatever the override says, so
		// admitting the payment on the override's word waves it past both limits.
		const { bolt11 } = node.createInvoice(6_000, 'fixed');

		expect(() => node.sendPaymentAsync(bolt11, undefined, 1)).to.throw(
			'exceeds per-payment limit'
		);
		// Zero is the worse case: it used to skip the checks altogether.
		expect(() => node.sendPaymentAsync(bolt11, undefined, 0)).to.throw(
			'exceeds per-payment limit'
		);
		expect(calls).to.have.length(0);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('reserves and records the encoded amount when the override understates it', () => {
		stubSendPayment(node);
		const { bolt11 } = node.createInvoice(3_000, 'understated');

		const { paymentHash } = node.sendPaymentAsync(bolt11, undefined, 1);
		expect(internals(node)._pendingSpendSats).to.equal(3_000);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
	});

	it('charges a payment that settles after it was reported failed', () => {
		stubSendPayment(node);
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(3_000, 'cancelled').bolt11
		);

		// What cancelPayment() does: the engine marks the payment failed, but
		// its HTLC is still live and the preimage can still arrive.
		settle(node, paymentHash, 3_000, 'FAILED');
		expect(node.getDailySpendInfo().spentSats).to.equal(0);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		// Exactly once, however many terminal events follow.
		settle(node, paymentHash, 3_000, 'COMPLETED');
		settle(node, paymentHash, 3_000, 'FAILED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('claims each dispatched attempt of a hash, and charges each settlement', () => {
		stubSendPayment(node);
		const { bolt11 } = node.createInvoice(3_000, 'retried');
		const { paymentHash } = node.sendPaymentAsync(bolt11);
		settle(node, paymentHash, 3_000, 'FAILED');

		// Two HTLCs can be out there for one hash, and either can settle, so
		// the retry claims alongside the first attempt rather than replacing it.
		node.sendPaymentAsync(bolt11);
		expect(claimedSats(node, paymentHash)).to.equal(6_000);
		expect(internals(node)._pendingSpendSats).to.equal(6_000);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(claimedSats(node, paymentHash)).to.equal(3_000);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(6_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
		// Nothing left to charge, however many terminal events follow.
		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(6_000);
	});

	it('keeps the live attempt claimed when a retry never leaves the node', () => {
		stubSendPayment(node);
		const { bolt11 } = node.createInvoice(3_000, 'refused retry');
		const { paymentHash } = node.sendPaymentAsync(bolt11);
		settle(node, paymentHash, 3_000, 'FAILED');

		// The retry dispatched nothing, so only its own claim goes: taking the
		// first attempt's with it lost a live HTLC's amount entirely.
		stubSendPayment(node, new Error('No route found'));
		expect(() => node.sendPaymentAsync(bolt11)).to.throw('No route found');
		expect(claimedSats(node, paymentHash)).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(3_000);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('rounds a sub-satoshi invoice up instead of letting it skip the limits', () => {
		stubSendPayment(node);
		const { bolt11, paymentHash } = msatInvoice(node, 999n, 'fractional');

		node.sendPaymentAsync(bolt11);
		// Truncating 999 msat to 0 sats took the invoice out of admission and
		// out of the accounting alike, so any number of them could be paid.
		expect(claimedSats(node, paymentHash)).to.equal(1);
		expect(internals(node)._pendingSpendSats).to.equal(1);

		settle(node, paymentHash, 1, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(1);
	});

	it('refuses a fractional amount whose rounded-up cost is over the limit', async () => {
		const calls = stubSendPayment(node);
		const { bolt11 } = msatInvoice(node, 5_000_001n, 'just over');

		expect(() => node.sendPaymentAsync(bolt11)).to.throw(
			'exceeds per-payment limit'
		);
		// payInvoice derives the same amount the same way.
		let blockingError = '';
		try {
			await node.payInvoice(bolt11, 5_000);
		} catch (err: unknown) {
			blockingError = err instanceof Error ? err.message : String(err);
		}
		expect(blockingError).to.contain('exceeds per-payment limit');
		expect(calls).to.have.length(0);
	});

	it('charges a failed async payment retried through payInvoice once', async () => {
		stubSendPayment(node);
		const { bolt11 } = node.createInvoice(3_000, 'blocking retry');
		const { paymentHash } = node.sendPaymentAsync(bolt11);
		settle(node, paymentHash, 3_000, 'FAILED');
		expect(claimedSats(node, paymentHash)).to.equal(3_000);

		// payInvoice owns the hash's accounting while it runs: the forwarding
		// handler in create() and its own listener otherwise both record the
		// one settlement.
		const retried = node.payInvoice(bolt11, 5_000);
		expect(internals(node)._asyncSpendClaims.has(paymentHash)).to.equal(false);
		settle(node, paymentHash, 3_000, 'COMPLETED');
		await retried;

		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(internals(node)._asyncSpendClaims.size).to.equal(0);
	});

	it('gives the claim back when the payInvoice retry does not settle', async () => {
		stubSendPayment(node);
		const { bolt11 } = node.createInvoice(3_000, 'failed blocking retry');
		const { paymentHash } = node.sendPaymentAsync(bolt11);
		settle(node, paymentHash, 3_000, 'FAILED');

		const retried = node.payInvoice(bolt11, 5_000);
		settle(node, paymentHash, 3_000, 'FAILED');
		let rejected = false;
		try {
			await retried;
		} catch {
			rejected = true;
		}
		expect(rejected).to.equal(true);
		expect(claimedSats(node, paymentHash)).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(3_000);

		settle(node, paymentHash, 3_000, 'COMPLETED');
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(internals(node)._pendingSpendSats).to.equal(0);
	});

	it('bounds the claim ledger, releasing the oldest hash and saying so', () => {
		const int = internals(node);
		const hashAt = (i: number): string => i.toString(16).padStart(64, '0');
		// Seeded directly: this is the ledger after a run of payments long
		// enough to outgrow the guard, and the path that fills it is covered
		// above. Every seeded claim is still well inside its window, so nothing
		// but the guard itself can drop one.
		const seeded = MAX_ASYNC_SPEND_CLAIM_HASHES + 9;
		for (let i = 0; i < seeded; i++) {
			int._asyncSpendClaims.set(hashAt(i), [
				{ sats: 1, expiresAt: Date.now() + ASYNC_SPEND_CLAIM_TTL_MS }
			]);
			int._pendingSpendSats += 1;
		}

		stubSendPayment(node);
		node.sendPaymentAsync(node.createInvoice(1, 'overflow').bolt11);

		expect(int._asyncSpendClaims.size).to.equal(MAX_ASYNC_SPEND_CLAIM_HASHES);
		// The oldest go first: they are the ones least able to still settle.
		expect(int._asyncSpendClaims.has(hashAt(0))).to.equal(false);
		expect(int._asyncSpendClaims.has(hashAt(seeded - 1))).to.equal(true);
		// A released claim gives its reservation back with it.
		expect(int._pendingSpendSats).to.equal(MAX_ASYNC_SPEND_CLAIM_HASHES);
	});

	it('counts a settlement that arrives after midnight UTC against the new day', () => {
		stubSendPayment(node);
		const { paymentHash } = node.sendPaymentAsync(
			node.createInvoice(3_000, 'past midnight').bolt11
		);
		// The daily window expired while the payment was in flight.
		internals(node)._dailySpendResetTime = Date.now() - 1;

		settle(node, paymentHash, 3_000, 'COMPLETED');
		// Recording into the expired day made the next reset erase the spend, so
		// whether it counted depended on a read-only call running first.
		expect(node.getDailySpendInfo().spentSats).to.equal(3_000);
		expect(node.getDailySpendInfo().resetsAt).to.be.greaterThan(Date.now());
	});

	it('leaves the accounting alone for an amountless invoice with no override', () => {
		stubSendPayment(node);
		const { bolt11 } = node.createInvoice(undefined, 'amountless');

		expect(node.sendPaymentAsync(bolt11).status).to.equal('PENDING');
		expect(internals(node)._pendingSpendSats).to.equal(0);
		expect(internals(node)._asyncSpendClaims.size).to.equal(0);
	});
});

describe('POST /invoice/pay-async admission (#526)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;
	let calls: string[];

	const post = (
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: '/invoice/pay-async',
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
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-async-api-'));
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
		calls = stubSendPayment(node);
	});

	after(async () => {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('answers 403 SPENDING_LIMIT_EXCEEDED over the per-payment limit', async () => {
		const { bolt11 } = node.createInvoice(5_001, 'too big');
		const res = await post({ bolt11 });
		expect(res.status).to.equal(403);
		expect((res.body.error as { code: string }).code).to.equal(
			'SPENDING_LIMIT_EXCEEDED'
		);
		expect(calls).to.have.length(0);
	});

	it('answers 409 SERVICE_DRAINING while draining', async () => {
		const { bolt11 } = node.createInvoice(1_000, 'draining');
		node.setDraining(true);
		try {
			const res = await post({ bolt11 });
			expect(res.status).to.equal(409);
			expect((res.body.error as { code: string }).code).to.equal(
				'SERVICE_DRAINING'
			);
			expect(calls).to.have.length(0);
		} finally {
			node.setDraining(false);
		}
	});

	it('reserves an accepted payment against the daily budget', async () => {
		const accepted = await post({
			bolt11: node.createInvoice(4_000, 'accepted').bolt11
		});
		expect(accepted.body.ok).to.equal(true);
		expect(calls).to.have.length(1);
		expect(internals(node)._pendingSpendSats).to.equal(4_000);

		const overshoot = await post({
			bolt11: node.createInvoice(4_000, 'overshoot').bolt11
		});
		expect(overshoot.body.ok).to.equal(true);
		const refused = await post({
			bolt11: node.createInvoice(4_000, 'refused').bolt11
		});
		expect(refused.status).to.equal(403);
		expect((refused.body.error as { code: string }).code).to.equal(
			'SPENDING_LIMIT_EXCEEDED'
		);
		expect(calls).to.have.length(2);
	});
});
