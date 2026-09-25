/**
 * Issue #977: the daily spend ledger lived in memory, and a settlement that
 * landed after its charger was gone was charged by nobody.
 *
 * BeignetNode charged a settled payment either through the payment:sent
 * listener of the blocking call that sent it, or through an async claim for a
 * fire-and-forget attempt; both lived in the process. A payment whose HTLC
 * settled after payInvoice gave up waiting (the listener removed, the record
 * left PENDING since #976) or after a restart was never charged, and every
 * restart started the day at zero although the limit resets at midnight UTC.
 * Now every Lightning pay path opens a claim at admission, the payment:sent
 * handler in create() is the one charger, and the ledger (counters and
 * claims) is persisted under DAILY_SPEND_STATE_KEY and reconciled at boot.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's senders are stubbed to leave a PENDING record, so nothing here
 * needs a chain or a channel. A restart is a destroy and a second boot on the
 * same dataDir. The engine persists its own records; the stubs do not, so a
 * case that needs a record on disk for the second boot writes it there.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	AsyncSpendClaim,
	BeignetNode,
	DAILY_SPEND_STATE_KEY,
	PersistedDailySpendState
} from '../../src/cli/beignet-node';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	IPaymentInfo,
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

// Same rationale as tests/cli/pay-invoice-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const LIMIT_SATS = 10_000;

const PUBKEY = '02' + '11'.repeat(32);

/** The engine behind the node, with what these tests stub, drive or read. */
type Engine = {
	payments: Map<string, IPaymentInfo>;
	sendPayment: (...args: unknown[]) => unknown;
	sendKeysend: (...args: unknown[]) => unknown;
	requestInvoice: (...args: unknown[]) => Promise<unknown>;
	payBolt12Invoice: (...args: unknown[]) => unknown;
	hasHtlcInFlight: (paymentHash: Buffer) => boolean;
	emit: (event: string, info: unknown) => boolean;
};

type Internals = {
	node: Engine;
	storage: SqliteStorage;
	_pendingSpendSats: number;
	_dailySpendResetTime: number;
	_asyncSpendClaims: Map<string, AsyncSpendClaim[]>;
	_persistSpendState: () => void;
	carryDaemonState: (from: SqliteStorage, to: SqliteStorage) => void;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

const engineOf = (node: BeignetNode): Engine => internals(node).node;

const boot = (dataDir: string): Promise<BeignetNode> =>
	BeignetNode.create({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir,
		logLevel: 'silent',
		rapidGossipSync: false,
		autoGossipSync: false,
		dailySpendLimitSats: LIMIT_SATS,
		...OFFLINE_ELECTRUM
	});

const spent = (node: BeignetNode): number => node.getDailySpendInfo().spentSats;

const pending = (node: BeignetNode): number =>
	internals(node)._pendingSpendSats;

/** Sats the claims of a hash still hold against the daily budget. */
const claimedSats = (node: BeignetNode, hashHex: string): number =>
	(internals(node)._asyncSpendClaims.get(hashHex) ?? [])
		.filter((claim) => claim.reserved)
		.reduce((total, claim) => total + claim.sats, 0);

/** The persisted ledger, as the next boot will read it. */
const storedLedger = (node: BeignetNode): PersistedDailySpendState | null => {
	const raw = internals(node).storage.loadMetadata(DAILY_SPEND_STATE_KEY);
	return raw === null ? null : (JSON.parse(raw) as PersistedDailySpendState);
};

/** Reserved sats the persisted row holds for a hash. */
const storedReservedSats = (node: BeignetNode, hashHex: string): number =>
	Object.entries(storedLedger(node)?.claims ?? {})
		.filter(([hash]) => hash === hashHex)
		.flatMap(([, list]) => list)
		.filter((claim) => claim.reserved)
		.reduce((total, claim) => total + claim.sats, 0);

/** An invoice from somebody else, which is what a payment path is given. */
const invoiceFrom = (
	amountSats: number,
	description: string
): { bolt11: string; paymentHash: Buffer; hashHex: string } => {
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
		paymentHash,
		hashHex: paymentHash.toString('hex')
	};
};

/** A PENDING OUTGOING record for the hash, as the engine's senders leave one. */
const pendingRecord = (
	paymentHash: Buffer,
	amountSats: number
): IPaymentInfo => ({
	paymentHash,
	amountMsat: BigInt(amountSats) * 1000n,
	status: PaymentStatus.PENDING,
	direction: PaymentDirection.OUTGOING,
	createdAt: Date.now()
});

/**
 * sendPayment that records a PENDING payment for the invoice's hash and
 * returns it, refusing a second send while one is PENDING as the engine does
 * (#975). With `throws`, refuses every send before any record exists.
 */
const stubSendPayment = (
	node: BeignetNode,
	opts: { throws?: Error } = {}
): void => {
	const engine = engineOf(node);
	engine.sendPayment = (...args: unknown[]): IPaymentInfo => {
		if (opts.throws) throw opts.throws;
		const decoded = decodeInvoice(String(args[0]));
		const hashHex = decoded.paymentHash.toString('hex');
		if (engine.payments.get(hashHex)?.status === PaymentStatus.PENDING) {
			throw new LightningPaymentError(
				LightningErrorCode.DUPLICATE_PAYMENT,
				'Payment already in flight for this invoice'
			);
		}
		const record = pendingRecord(
			decoded.paymentHash,
			Number((decoded.amountMsat ?? 0n) / 1000n)
		);
		engine.payments.set(hashHex, record);
		return record;
	};
};

/**
 * sendKeysend that records a payment for a fresh hash in the given status and
 * returns it. `emitInside` reports the settlement inside the call, before the
 * daemon knows the hash, as a synchronous settle would.
 */
const stubSendKeysend = (
	node: BeignetNode,
	amountSats: number,
	opts: {
		status?: PaymentStatus;
		emitInside?: boolean;
		throws?: Error;
	} = {}
): Buffer => {
	const paymentHash = crypto.randomBytes(32);
	const engine = engineOf(node);
	engine.sendKeysend = (): IPaymentInfo => {
		if (opts.throws) throw opts.throws;
		const record = pendingRecord(paymentHash, amountSats);
		record.status = opts.status ?? PaymentStatus.PENDING;
		if (record.status !== PaymentStatus.PENDING) {
			record.completedAt = Date.now();
		}
		engine.payments.set(paymentHash.toString('hex'), record);
		if (opts.emitInside) {
			engine.emit(
				record.status === PaymentStatus.COMPLETED
					? 'payment:sent'
					: 'payment:failed',
				record
			);
		}
		return record;
	};
	return paymentHash;
};

/**
 * The payee half of an offer payment: the invoice request answers with a
 * fixed-amount BOLT 12 invoice, and the dispatch records a PENDING payment for
 * its hash rather than routing anything.
 */
const stubPayee = (node: BeignetNode, amountSats: number): Buffer => {
	const paymentHash = crypto.randomBytes(32);
	const engine = engineOf(node);
	engine.requestInvoice = async (): Promise<unknown> => ({
		paymentHash,
		amount: BigInt(amountSats) * 1000n,
		description: 'stubbed offer invoice',
		createdAt: BigInt(Math.floor(Date.now() / 1000)),
		nodeId: crypto.randomBytes(33)
	});
	engine.payBolt12Invoice = (): IPaymentInfo => {
		const record = pendingRecord(paymentHash, amountSats);
		engine.payments.set(paymentHash.toString('hex'), record);
		return record;
	};
	return paymentHash;
};

/** The payee settles: the record completes and payment:sent fires, in the engine's order. */
const settle = (node: BeignetNode, paymentHash: Buffer): void => {
	const engine = engineOf(node);
	const record = engine.payments.get(paymentHash.toString('hex'));
	expect(record, 'the record the settlement completes').to.not.equal(undefined);
	record!.status = PaymentStatus.COMPLETED;
	record!.completedAt = Date.now();
	engine.emit('payment:sent', record);
};

/** The engine gives up: the record fails and payment:failed fires. */
const fail = (node: BeignetNode, paymentHash: Buffer): void => {
	const engine = engineOf(node);
	const record = engine.payments.get(paymentHash.toString('hex'));
	expect(record, 'the record the failure ends').to.not.equal(undefined);
	record!.status = PaymentStatus.FAILED;
	engine.emit('payment:failed', record);
};

/** A repeat of the terminal event, which must charge nothing more. */
const repeatSettle = (node: BeignetNode, paymentHash: Buffer): void => {
	const engine = engineOf(node);
	engine.emit('payment:sent', engine.payments.get(paymentHash.toString('hex')));
};

/** Writes the record to disk the way the engine persists its own. */
const persistRecord = (
	node: BeignetNode,
	paymentHash: Buffer,
	status: PaymentStatus
): void => {
	const hashHex = paymentHash.toString('hex');
	const record = engineOf(node).payments.get(hashHex);
	expect(record, 'the record to persist').to.not.equal(undefined);
	internals(node).storage.savePayment(hashHex, {
		...record!,
		status,
		...(status === PaymentStatus.COMPLETED ? { completedAt: Date.now() } : {})
	});
};

/** The code an attempt rejected with, or undefined if it resolved. */
const rejectionOf = async (
	attempt: Promise<unknown>
): Promise<string | undefined> => {
	try {
		await attempt;
		return undefined;
	} catch (err: unknown) {
		return (err as { code?: string }).code ?? 'ERROR';
	}
};

describe('Issue #977: the daily spend ledger survives a restart and charges every settled payment once', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-spend-977-'));
		node = await boot(tmpDir);
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	const restart = async (): Promise<void> => {
		await node.destroy();
		node = await boot(tmpDir);
	};

	describe('the ledger across a restart', () => {
		it("keeps the day's counters across a restart within the UTC day", async () => {
			const invoice = invoiceFrom(1_000, 'before the restart');
			stubSendPayment(node);
			const paid = node.payInvoice(invoice.bolt11, 5_000, 0);
			settle(node, invoice.paymentHash);
			await paid;
			expect(spent(node)).to.equal(1_000);
			const { resetsAt } = node.getDailySpendInfo();

			// What the next boot reads: the row the README describes.
			const ledger = storedLedger(node);
			expect(ledger).to.not.equal(null);
			expect(ledger).to.deep.equal({
				resetTime: resetsAt,
				totalSats: 1_000,
				lightningSats: 1_000,
				onchainSats: 0,
				claims: {}
			});

			await restart();
			// Before the fix the counters were per-process: every restart
			// started the day at zero.
			expect(spent(node)).to.equal(1_000);
			expect(node.getDailySpendInfo().lightningSats).to.equal(1_000);
			expect(node.getDailySpendInfo().onchainSats).to.equal(0);
			expect(node.getDailySpendInfo().resetsAt).to.equal(resetsAt);
			expect(pending(node)).to.equal(0);

			// The restored total is what the limit is judged against.
			const over = invoiceFrom(LIMIT_SATS - 999, 'over the restored total');
			expect(
				await rejectionOf(node.payInvoice(over.bolt11, 5_000, 0))
			).to.equal('SPENDING_LIMIT_EXCEEDED');
		});

		it('starts the day at zero when the stored day has ended', async () => {
			const invoice = invoiceFrom(1_000, 'yesterday');
			stubSendPayment(node);
			const paid = node.payInvoice(invoice.bolt11, 5_000, 0);
			settle(node, invoice.paymentHash);
			await paid;
			expect(spent(node)).to.equal(1_000);

			// The row as a boot on the next UTC day finds it.
			internals(node)._dailySpendResetTime = Date.now() - 1;
			internals(node)._persistSpendState();
			expect(storedLedger(node)?.totalSats).to.equal(1_000);

			await restart();
			expect(spent(node)).to.equal(0);
			expect(node.getDailySpendInfo().resetsAt).to.be.greaterThan(Date.now());
			expect(storedLedger(node)?.totalSats).to.equal(0);
		});

		it('carryDaemonState copies the ledger into the staged database of a capsule resume', async () => {
			const invoice = invoiceFrom(1_000, 'carried');
			stubSendPayment(node);
			const paid = node.payInvoice(invoice.bolt11, 5_000, 0);
			settle(node, invoice.paymentHash);
			await paid;

			const staged = new SqliteStorage(':memory:');
			staged.open();
			try {
				internals(node).carryDaemonState(internals(node).storage, staged);
				const carried = staged.loadMetadata(DAILY_SPEND_STATE_KEY);
				expect(carried).to.not.equal(null);
				expect(carried).to.equal(
					internals(node).storage.loadMetadata(DAILY_SPEND_STATE_KEY)
				);
				expect(
					(JSON.parse(carried!) as PersistedDailySpendState).totalSats
				).to.equal(1_000);
			} finally {
				staged.close();
			}
		});
	});

	describe('a settlement after the blocking listener is gone', () => {
		it('charges a settle that lands after payInvoice timed out with the HTLC still out, once', async () => {
			const invoice = invoiceFrom(1_000, 'held past the timeout');
			stubSendPayment(node);
			engineOf(node).hasHtlcInFlight = (hash): boolean =>
				hash.equals(invoice.paymentHash);

			expect(
				await rejectionOf(node.payInvoice(invoice.bolt11, 50, 0))
			).to.equal('PAYMENT_TIMEOUT');
			expect(node.getPayment(invoice.hashHex)?.status).to.equal('PENDING');
			expect(spent(node)).to.equal(0);
			// The HTLC can still spend the money, so its budget stays held.
			expect(pending(node)).to.equal(1_000);
			expect(claimedSats(node, invoice.hashHex)).to.equal(1_000);

			settle(node, invoice.paymentHash);
			// Before the fix the blocking listener was gone and the hash held
			// no async claim, so nobody charged this settle.
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);

			repeatSettle(node, invoice.paymentHash);
			expect(spent(node)).to.equal(1_000);
		});

		it('charges a claim restored at boot when the payee settles after the restart, once', async () => {
			const invoice = invoiceFrom(1_000, 'settles after the restart');
			stubSendPayment(node);
			engineOf(node).hasHtlcInFlight = (hash): boolean =>
				hash.equals(invoice.paymentHash);
			expect(
				await rejectionOf(node.payInvoice(invoice.bolt11, 50, 0))
			).to.equal('PAYMENT_TIMEOUT');
			expect(pending(node)).to.equal(1_000);
			expect(storedLedger(node)?.claims[invoice.hashHex]).to.have.length(1);
			// The engine persists its PENDING record; the stub does not.
			persistRecord(node, invoice.paymentHash, PaymentStatus.PENDING);

			await restart();
			// The record is PENDING, so the claim came back with its
			// reservation, for the settle to charge.
			expect(node.getPayment(invoice.hashHex)?.status).to.equal('PENDING');
			expect(spent(node)).to.equal(0);
			expect(pending(node)).to.equal(1_000);
			expect(claimedSats(node, invoice.hashHex)).to.equal(1_000);

			engineOf(node).hasHtlcInFlight = (hash): boolean =>
				hash.equals(invoice.paymentHash);
			settle(node, invoice.paymentHash);
			// Before the fix the claim lived in memory only, so this settle
			// was charged by nobody.
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
			expect(storedLedger(node)?.totalSats).to.equal(1_000);
			expect(storedLedger(node)?.claims).to.deep.equal({});

			repeatSettle(node, invoice.paymentHash);
			expect(spent(node)).to.equal(1_000);
		});

		it('releases the reservation when the engine gives up after the timeout, charging nothing', async () => {
			const invoice = invoiceFrom(1_000, 'gave up after the timeout');
			stubSendPayment(node);
			engineOf(node).hasHtlcInFlight = (hash): boolean =>
				hash.equals(invoice.paymentHash);
			expect(
				await rejectionOf(node.payInvoice(invoice.bolt11, 50, 0))
			).to.equal('PAYMENT_TIMEOUT');
			const held = node.getDailySpendInfo();
			expect(held.pendingSats).to.equal(1_000);
			expect(held.remainingSats).to.equal(LIMIT_SATS - 1_000);

			// The last HTLC failed back and the engine gave up. Its report
			// reaches only the handler in create(), the blocking listener
			// being gone, and nothing is in flight for the hash any more.
			engineOf(node).hasHtlcInFlight = (): boolean => false;
			fail(node, invoice.paymentHash);
			expect(node.getPayment(invoice.hashHex)?.status).to.equal('FAILED');
			expect(pending(node)).to.equal(0);
			expect(spent(node)).to.equal(0);
			const released = node.getDailySpendInfo();
			expect(released.pendingSats).to.equal(0);
			expect(released.remainingSats).to.equal(LIMIT_SATS);
			// The record stays in the row, unreserved.
			expect(Object.keys(storedLedger(node)?.claims ?? {})).to.include(
				invoice.hashHex
			);
			expect(storedReservedSats(node, invoice.hashHex)).to.equal(0);

			// sendPaymentAsync, which never had a listener, releases the same
			// way.
			const async = invoiceFrom(2_000, 'async gave up');
			expect(node.sendPaymentAsync(async.bolt11, 0).status).to.equal('PENDING');
			expect(pending(node)).to.equal(2_000);
			fail(node, async.paymentHash);
			expect(pending(node)).to.equal(0);
			expect(spent(node)).to.equal(0);
		});

		it('releases a claim restored at boot when the engine gives up after the restart', async () => {
			const invoice = invoiceFrom(1_000, 'gave up after the restart');
			stubSendPayment(node);
			engineOf(node).hasHtlcInFlight = (hash): boolean =>
				hash.equals(invoice.paymentHash);
			expect(
				await rejectionOf(node.payInvoice(invoice.bolt11, 50, 0))
			).to.equal('PAYMENT_TIMEOUT');
			persistRecord(node, invoice.paymentHash, PaymentStatus.PENDING);

			await restart();
			expect(pending(node)).to.equal(1_000);
			expect(node.getDailySpendInfo().remainingSats).to.equal(
				LIMIT_SATS - 1_000
			);

			// The give-up report after the restart: the real predicate finds
			// nothing out for the hash.
			fail(node, invoice.paymentHash);
			expect(pending(node)).to.equal(0);
			expect(spent(node)).to.equal(0);
			expect(node.getDailySpendInfo().remainingSats).to.equal(LIMIT_SATS);
			expect(storedReservedSats(node, invoice.hashHex)).to.equal(0);

			// The release is in the ledger: the next boot holds nothing.
			await restart();
			expect(pending(node)).to.equal(0);
			expect(node.getDailySpendInfo().remainingSats).to.equal(LIMIT_SATS);
		});
	});

	describe('boot reconciliation of the stored claims', () => {
		it('charges a claim whose payment completed while the process was down, and drops one whose payment failed with nothing out', async () => {
			const completed = invoiceFrom(1_000, 'completed while down');
			const failed = invoiceFrom(2_000, 'failed while down');
			stubSendPayment(node);
			expect(node.sendPaymentAsync(completed.bolt11, 0).status).to.equal(
				'PENDING'
			);
			expect(node.sendPaymentAsync(failed.bolt11, 0).status).to.equal(
				'PENDING'
			);
			expect(pending(node)).to.equal(3_000);
			expect(Object.keys(storedLedger(node)?.claims ?? {})).to.have.length(2);

			// What the engine persisted before the process died.
			persistRecord(node, completed.paymentHash, PaymentStatus.COMPLETED);
			persistRecord(node, failed.paymentHash, PaymentStatus.FAILED);

			await restart();
			// The settle landed while the process was down: charged at boot.
			// Before the fix the claims did not survive the restart and the
			// day started at zero.
			expect(spent(node)).to.equal(1_000);
			expect(node.getDailySpendInfo().lightningSats).to.equal(1_000);
			// The failed one can never settle: dropped, its budget not held.
			expect(pending(node)).to.equal(0);
			expect(internals(node)._asyncSpendClaims.size).to.equal(0);
			expect(storedLedger(node)?.claims).to.deep.equal({});

			// The charge is recorded with the ledger, so a further boot
			// charges nothing more.
			await restart();
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
		});

		it('charges a hash with two attempts once per settlement report, and never again at a later boot', async () => {
			const invoice = invoiceFrom(1_000, 'retried');
			stubSendPayment(node);
			expect(node.sendPaymentAsync(invoice.bolt11, 0).status).to.equal(
				'PENDING'
			);
			// The first attempt fails with its HTLC still out, so its claim
			// stays; the retry claims beside it.
			engineOf(node).hasHtlcInFlight = (): boolean => true;
			fail(node, invoice.paymentHash);
			expect(node.sendPaymentAsync(invoice.bolt11, 0).status).to.equal(
				'PENDING'
			);
			expect(pending(node)).to.equal(2_000);

			// One settlement per hash, and no re-send of a paid hash (#975):
			// the other attempt's reservation goes with the charge, its record
			// staying marked as belonging to a charged settlement.
			settle(node, invoice.paymentHash);
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
			expect(claimedSats(node, invoice.hashHex)).to.equal(0);
			persistRecord(node, invoice.paymentHash, PaymentStatus.COMPLETED);

			// The boot sees a completed hash with nothing left to charge and
			// restores the record without a reservation.
			await restart();
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
			expect(claimedSats(node, invoice.hashHex)).to.equal(0);

			await restart();
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
		});
	});

	describe('exactly once on every path', () => {
		it('payInvoice: the settle is charged once, before the caller resolves', async () => {
			const invoice = invoiceFrom(1_000, 'blocking');
			stubSendPayment(node);
			const paid = node.payInvoice(invoice.bolt11, 5_000, 0);
			expect(pending(node)).to.equal(1_000);
			let spentWhenResolved = -1;
			const resolved = paid.then(() => {
				spentWhenResolved = spent(node);
			});
			settle(node, invoice.paymentHash);
			await resolved;
			expect(spentWhenResolved).to.equal(1_000);
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
			expect(internals(node)._asyncSpendClaims.size).to.equal(0);

			repeatSettle(node, invoice.paymentHash);
			expect(spent(node)).to.equal(1_000);
		});

		it('sendKeysend: a keysend that settles later is charged once', async () => {
			const paymentHash = stubSendKeysend(node, 1_000);
			const paid = node.sendKeysend(PUBKEY, 1_000, 5_000, 0);
			// The reservation moved under the hash the engine chose.
			expect(pending(node)).to.equal(1_000);
			expect(claimedSats(node, paymentHash.toString('hex'))).to.equal(1_000);
			settle(node, paymentHash);
			await paid;
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);

			repeatSettle(node, paymentHash);
			expect(spent(node)).to.equal(1_000);
		});

		it('sendKeysend: a keysend settled inside the send is charged once, whether or not the engine reported it inside the call', async () => {
			const quiet = stubSendKeysend(node, 1_000, {
				status: PaymentStatus.COMPLETED
			});
			expect((await node.sendKeysend(PUBKEY, 1_000, 5_000, 0)).status).to.equal(
				'COMPLETED'
			);
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
			repeatSettle(node, quiet);
			expect(spent(node)).to.equal(1_000);

			// Reported inside the call: the handler in create() saw the event
			// before the claim carried this hash, and the send charges it.
			const reported = stubSendKeysend(node, 1_000, {
				status: PaymentStatus.COMPLETED,
				emitInside: true
			});
			expect((await node.sendKeysend(PUBKEY, 1_000, 5_000, 0)).status).to.equal(
				'COMPLETED'
			);
			expect(spent(node)).to.equal(2_000);
			expect(pending(node)).to.equal(0);
			repeatSettle(node, reported);
			expect(spent(node)).to.equal(2_000);
			expect(internals(node)._asyncSpendClaims.size).to.equal(0);
		});

		it('payOffer: the settle is charged once', async () => {
			const paymentHash = stubPayee(node, 1_000);
			const offer = node.createOffer({ description: 'charged once' }).encoded!;
			const paid = node.payOffer(offer, undefined, 5_000, 0);
			// The claim opens once the payee has priced the offer.
			while (pending(node) !== 1_000) {
				await new Promise((resolve) => setTimeout(resolve, 5));
			}
			settle(node, paymentHash);
			await paid;
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);

			repeatSettle(node, paymentHash);
			expect(spent(node)).to.equal(1_000);
		});

		it('sendPaymentAsync: the settle is charged once', async () => {
			const invoice = invoiceFrom(1_000, 'async');
			stubSendPayment(node);
			expect(node.sendPaymentAsync(invoice.bolt11, 0).status).to.equal(
				'PENDING'
			);
			expect(pending(node)).to.equal(1_000);
			settle(node, invoice.paymentHash);
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);

			repeatSettle(node, invoice.paymentHash);
			expect(spent(node)).to.equal(1_000);
		});

		it('a synchronous engine throw leaves nothing claimed, on every path', async () => {
			const invoice = invoiceFrom(1_000, 'refused');
			stubSendPayment(node, { throws: new Error('No route found') });
			expect(
				await rejectionOf(node.payInvoice(invoice.bolt11, 5_000, 0))
			).to.equal('NO_ROUTE');
			expect(() => node.sendPaymentAsync(invoice.bolt11, 0)).to.throw(
				'No route found'
			);

			stubSendKeysend(node, 1_000, { throws: new Error('No route found') });
			// A keysend refusal carries its code as an invoice's does (#991).
			expect(
				await rejectionOf(node.sendKeysend(PUBKEY, 1_000, 5_000, 0))
			).to.equal('NO_ROUTE');

			expect(spent(node)).to.equal(0);
			expect(pending(node)).to.equal(0);
			expect(internals(node)._asyncSpendClaims.size).to.equal(0);
			expect(storedLedger(node)?.claims).to.deep.equal({});
		});

		it('a definitive failure with nothing out releases the reservation and charges nothing', async () => {
			const invoice = invoiceFrom(1_000, 'fails');
			stubSendPayment(node);
			const paid = node.payInvoice(invoice.bolt11, 5_000, 0);
			expect(pending(node)).to.equal(1_000);
			fail(node, invoice.paymentHash);
			expect(await rejectionOf(paid)).to.equal('PAYMENT_FAILED');
			expect(pending(node)).to.equal(0);
			expect(spent(node)).to.equal(0);

			const paymentHash = stubSendKeysend(node, 1_000);
			const keysend = node.sendKeysend(PUBKEY, 1_000, 5_000, 0);
			expect(pending(node)).to.equal(1_000);
			fail(node, paymentHash);
			expect(await rejectionOf(keysend)).to.equal('PAYMENT_FAILED');
			expect(pending(node)).to.equal(0);
			expect(spent(node)).to.equal(0);

			// A ghost timeout, with nothing out, releases the same way.
			const ghost = invoiceFrom(1_000, 'ghost');
			expect(await rejectionOf(node.payInvoice(ghost.bolt11, 50, 0))).to.equal(
				'PAYMENT_TIMEOUT'
			);
			expect(pending(node)).to.equal(0);
			expect(spent(node)).to.equal(0);
			for (const claims of storedLedger(node)?.claims
				? Object.values(storedLedger(node)!.claims)
				: []) {
				expect(claims.some((claim) => claim.reserved)).to.equal(false);
			}
		});

		it('keeps the reservation of a payment that failed while its HTLC is still out', async () => {
			const invoice = invoiceFrom(1_000, 'cancelled with the HTLC out');
			stubSendPayment(node);
			engineOf(node).hasHtlcInFlight = (hash): boolean =>
				hash.equals(invoice.paymentHash);
			const paid = node.payInvoice(invoice.bolt11, 5_000, 0);
			fail(node, invoice.paymentHash);
			expect(await rejectionOf(paid)).to.equal('PAYMENT_FAILED');
			// The HTLC cannot be retracted: the budget stays held for it.
			expect(pending(node)).to.equal(1_000);
			expect(spent(node)).to.equal(0);

			settle(node, invoice.paymentHash);
			expect(spent(node)).to.equal(1_000);
			expect(pending(node)).to.equal(0);
		});
	});
});
