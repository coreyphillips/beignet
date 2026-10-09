/**
 * Issue #1403: GET /payments decrypted, parsed and sorted every payment row
 * on each call and applied limit last, so `?limit=1` cost the whole history.
 * Rows are now read newest first from a created_at index and decrypted only
 * as the page needs them, and every HTTP call is a page of at most 1000.
 *
 * Offline suite: the daemon boots against an unreachable Electrum server.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import Database from 'better-sqlite3';
import sinon from 'sinon';
import { startDaemon, IStartedDaemon } from '../../src/cli/daemon';
import { PaymentFilter, PaymentInfo } from '../../src/cli/types';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	decryptValue,
	encryptValue
} from '../../src/lightning/storage/encryption';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65528,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const ROUTE_TOKEN = 'payments-page-token';

/** More than one 1000-row page, and more than two 500-key index batches. */
const ROWS = 1_005;

const BASE_MS = 1_700_000_000_000;

const recordOf = (
	i: number,
	overrides: Partial<IPaymentInfo> = {}
): IPaymentInfo => ({
	paymentHash: crypto.randomBytes(32),
	amountMsat: BigInt(1_000 + i) * 1000n,
	status: i % 7 === 0 ? PaymentStatus.FAILED : PaymentStatus.COMPLETED,
	direction:
		i % 3 === 0 ? PaymentDirection.INCOMING : PaymentDirection.OUTGOING,
	// Three rows to a millisecond, so ties fall inside and across batches.
	createdAt: BASE_MS + Math.floor(i / 3),
	completedAt: BASE_MS + Math.floor(i / 3) + 10,
	metadata: { label: `row-${i}`, ...(i % 2 === 0 ? { even: 'yes' } : {}) },
	...overrides
});

const hex = (p: IPaymentInfo): string => p.paymentHash.toString('hex');

/** Counts row decodes: every payment row read passes through _dec once. */
const countDecodes = (
	storage: SqliteStorage
): { callCount: number; resetHistory(): void } =>
	sinon.spy(storage as unknown as { _dec: (v: string) => string }, '_dec');

/**
 * The listing as it was computed before #1403: every row, the live record
 * winning, sorted, filtered, then sliced. Ties go to the larger hash.
 */
const referenceListing = (
	rows: Array<{ paymentHash: string; payment: IPaymentInfo }>,
	live: IPaymentInfo[],
	filter: PaymentFilter = {}
): string[] => {
	const byHash = new Map<string, IPaymentInfo>();
	for (const r of rows) byHash.set(r.paymentHash, r.payment);
	for (const p of live) byHash.set(hex(p), p);
	let list = [...byHash]
		.sort(([ha, a], [hb, b]) =>
			a.createdAt !== b.createdAt
				? b.createdAt - a.createdAt
				: ha < hb
				? 1
				: ha > hb
				? -1
				: 0
		)
		.map(([, p]) => p);
	if (filter.status) list = list.filter((p) => p.status === filter.status);
	if (filter.direction) {
		list = list.filter((p) => p.direction === filter.direction);
	}
	if (filter.since !== undefined) {
		list = list.filter((p) => p.createdAt >= filter.since!);
	}
	if (filter.metadataKey !== undefined) {
		list = list.filter((p) =>
			filter.metadataValue !== undefined
				? p.metadata?.[filter.metadataKey!] === filter.metadataValue
				: p.metadata !== undefined && filter.metadataKey! in p.metadata
		);
	}
	if (filter.offset) list = list.slice(filter.offset);
	if (filter.limit) list = list.slice(0, filter.limit);
	return list.map(hex);
};

const request = (
	port: number,
	urlPath: string
): Promise<{ status: number; body: Record<string, unknown> }> =>
	new Promise((resolve, reject) => {
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: urlPath,
				method: 'GET',
				headers: { Authorization: `Bearer ${ROUTE_TOKEN}` }
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
					} catch (err) {
						reject(err);
					}
				});
			}
		);
		req.on('error', reject);
		req.end();
	});

describe('Payment rows are read newest first from the created_at index (issue #1403)', () => {
	let tmpDir: string;
	let dbPath: string;
	const key = crypto.randomBytes(32);

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-payments-index-'));
		dbPath = path.join(tmpDir, 'node.db');
	});

	afterEach(() => {
		sinon.restore();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('walks every row in index order across batches, decrypting none until loaded', () => {
		const storage = new SqliteStorage(dbPath, undefined, {
			encryptionKey: key
		});
		storage.open();
		try {
			for (let i = 0; i < ROWS; i++) {
				const p = recordOf(i);
				storage.savePayment(hex(p), p);
			}
			const all = storage.loadAllPayments();
			const decodes = countDecodes(storage);
			const refs = [...storage.paymentsNewestFirst()];
			expect(decodes.callCount, 'keys only').to.equal(0);
			expect(refs.map((r) => r.paymentHash)).to.deep.equal(
				referenceListing(all, [])
			);
			const since = BASE_MS + 100;
			expect(
				[...storage.paymentsNewestFirst(since)].map((r) => r.paymentHash)
			).to.deep.equal(referenceListing(all, [], { since }));
			expect(hex(refs[7].load()!)).to.equal(refs[7].paymentHash);
			expect(decodes.callCount).to.equal(1);
		} finally {
			storage.close();
		}
	});

	it('fills created_at for rows a schema 15 database already held', () => {
		const storage = new SqliteStorage(dbPath, undefined, {
			encryptionKey: key
		});
		storage.open();
		const saved = [0, 1, 2, 3, 4, 5].map((i) => recordOf(i * 50));
		for (const p of saved) storage.savePayment(hex(p), p);
		storage.close();

		const legacy = new Database(dbPath);
		legacy.exec(
			'DROP INDEX idx_payments_created_at; ' +
				'ALTER TABLE payments DROP COLUMN created_at; ' +
				'DELETE FROM schema_version WHERE version = 16'
		);
		legacy.close();

		const reopened = new SqliteStorage(dbPath, undefined, {
			encryptionKey: key
		});
		reopened.open();
		try {
			expect(reopened.getSchemaVersion()).to.equal(16);
			expect(
				[...reopened.paymentsNewestFirst()].map((r) => r.paymentHash)
			).to.deep.equal(
				[...saved].sort((a, b) => b.createdAt - a.createdAt).map(hex)
			);
		} finally {
			reopened.close();
		}
	});

	it('opens a schema 15 database holding a payment whose createdAt is not a number', () => {
		const storage = new SqliteStorage(dbPath, undefined, {
			encryptionKey: key
		});
		storage.open();
		const good = recordOf(1);
		const bad = recordOf(2);
		storage.savePayment(hex(good), good);
		storage.savePayment(hex(bad), bad);
		storage.close();

		const legacy = new Database(dbPath);
		const row = legacy
			.prepare('SELECT payment_json FROM payments WHERE payment_hash = ?')
			.get(hex(bad)) as { payment_json: string };
		const payload = JSON.parse(decryptValue(key, row.payment_json));
		payload.createdAt = {};
		legacy
			.prepare('UPDATE payments SET payment_json = ? WHERE payment_hash = ?')
			.run(encryptValue(key, JSON.stringify(payload)), hex(bad));
		legacy.exec(
			'DROP INDEX idx_payments_created_at; ' +
				'ALTER TABLE payments DROP COLUMN created_at; ' +
				'DELETE FROM schema_version WHERE version = 16'
		);
		legacy.close();

		const reopened = new SqliteStorage(dbPath, undefined, {
			encryptionKey: key
		});
		reopened.open();
		try {
			expect(
				[...reopened.paymentsNewestFirst()].map((r) => r.paymentHash)
			).to.deep.equal([hex(good)]);
		} finally {
			reopened.close();
		}
	});

	it('loads an undecodable row as null and reports it', () => {
		const corrupt: unknown[] = [];
		const storage = new SqliteStorage(dbPath, (err) => corrupt.push(err), {
			encryptionKey: key
		});
		storage.open();
		const good = recordOf(1);
		storage.savePayment(hex(good), good);
		storage.close();

		const raw = new Database(dbPath);
		raw
			.prepare(
				'INSERT INTO payments (payment_hash, payment_json, created_at) VALUES (?, ?, ?)'
			)
			.run('ab'.repeat(32), 'not json', BASE_MS + 99_999);
		raw.close();

		const reopened = new SqliteStorage(dbPath, (err) => corrupt.push(err), {
			encryptionKey: key
		});
		reopened.open();
		try {
			const refs = [...reopened.paymentsNewestFirst()];
			expect(refs.map((r) => r.paymentHash)).to.deep.equal([
				'ab'.repeat(32),
				hex(good)
			]);
			expect(refs[0].load()).to.equal(null);
			expect(corrupt).to.have.length(1);
			expect(hex(refs[1].load()!)).to.equal(hex(good));
		} finally {
			reopened.close();
		}
	});
});

describe('GET /payments reads one page of the history (issue #1403)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let daemon: IStartedDaemon;
	let port: number;
	let rows: Array<{ paymentHash: string; payment: IPaymentInfo }>;

	const storage = (): SqliteStorage => daemon.node.getStorage();
	const liveMap = (): Map<string, IPaymentInfo> =>
		(
			daemon.node.getNode() as unknown as {
				payments: Map<string, IPaymentInfo>;
			}
		).payments;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-payments-page-'));
		daemon = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM,
			daemonPort: 0,
			apiToken: ROUTE_TOKEN
		});
		port = (daemon.server.address() as AddressInfo).port;
		// Rows only, as the engine leaves them once it prunes its records.
		for (let i = 0; i < ROWS; i++) {
			const p = recordOf(i);
			storage().savePayment(hex(p), p);
		}
		rows = storage().loadAllPayments();
		expect(rows).to.have.length(ROWS);
		expect(liveMap().size, 'no live records yet').to.equal(0);
	});

	afterEach(() => {
		sinon.restore();
	});

	after(async () => {
		await daemon?.stop();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('decrypts only the rows on the page', () => {
		const node = daemon.node;
		const decodes = countDecodes(storage());

		expect(node.listPayments({ limit: 1 })[0].paymentHash).to.equal(
			referenceListing(rows, [])[0]
		);
		expect(decodes.callCount, 'limit=1').to.equal(1);

		decodes.resetHistory();
		expect(
			node.listPayments({ offset: 900, limit: 2 }).map((p) => p.paymentHash)
		).to.deep.equal(referenceListing(rows, [], { offset: 900, limit: 2 }));
		expect(decodes.callCount, 'offset=900&limit=2').to.equal(2);

		// A filter decrypts until its page fills, not to the end.
		decodes.resetHistory();
		const order = referenceListing(rows, []);
		const incoming = referenceListing(rows, [], {
			direction: 'INCOMING',
			limit: 2
		});
		expect(
			node
				.listPayments({ direction: 'INCOMING', limit: 2 })
				.map((p) => p.paymentHash)
		).to.deep.equal(incoming);
		expect(decodes.callCount).to.equal(order.indexOf(incoming[1]) + 1);
	});

	it('lists what a full read and sort listed, live records merged in', () => {
		const live = liveMap();
		const row = (i: number): IPaymentInfo =>
			rows.find((r) => r.payment.metadata?.label === `row-${i}`)!.payment;
		const mid = row(500);
		// Same millisecond as three rows, so the live/row tie-break is exercised.
		const liveOnly = recordOf(500, {
			metadata: { label: 'live-only', even: 'yes' }
		});
		const overRow: IPaymentInfo = {
			...row(10),
			metadata: { label: 'live' }
		};
		// A retry of an old hash: the live record is newer than its row.
		const retried: IPaymentInfo = {
			...row(20),
			status: PaymentStatus.PENDING,
			createdAt: mid.createdAt
		};
		delete retried.completedAt;
		const injected = [liveOnly, overRow, retried];
		for (const p of injected) live.set(hex(p), p);
		try {
			const filters: PaymentFilter[] = [
				{},
				{ limit: 10 },
				{ offset: 5, limit: 10 },
				{ offset: 490, limit: 40 },
				{ offset: ROWS },
				{ direction: 'INCOMING' },
				{ direction: 'INCOMING', offset: 3, limit: 4 },
				{ status: 'FAILED' },
				{ status: 'PENDING' },
				{ since: mid.createdAt },
				{ since: mid.createdAt, offset: 2, limit: 5 },
				{ metadataKey: 'even' },
				{ metadataKey: 'label', metadataValue: 'live' },
				{
					status: 'COMPLETED',
					direction: 'OUTGOING',
					since: BASE_MS + 20,
					metadataKey: 'even',
					offset: 1,
					limit: 7
				}
			];
			for (const filter of filters) {
				expect(
					daemon.node.listPayments(filter).map((p) => p.paymentHash),
					JSON.stringify(filter)
				).to.deep.equal(referenceListing(rows, injected, filter));
			}
			const listed = daemon.node.listPayments();
			expect(listed).to.have.length(ROWS + 1);
			const byHash = new Map<string, PaymentInfo>(
				listed.map((p) => [p.paymentHash, p])
			);
			expect(byHash.get(hex(overRow))?.metadata).to.deep.equal({
				label: 'live'
			});
			expect(byHash.get(hex(retried))?.status).to.equal('PENDING');
		} finally {
			for (const p of injected) live.delete(hex(p));
		}
	});

	it('answers at most 1000 without a limit, and pages on with offset', async () => {
		const first = await request(port, '/payments');
		expect(first.status).to.equal(200);
		const page = first.body.result as PaymentInfo[];
		expect(page.map((p) => p.paymentHash)).to.deep.equal(
			referenceListing(rows, [], { limit: 1000 })
		);

		const zero = await request(port, '/payments?limit=0');
		expect((zero.body.result as PaymentInfo[]).length).to.equal(1000);

		const rest = await request(port, '/payments?offset=1000');
		expect(
			(rest.body.result as PaymentInfo[]).map((p) => p.paymentHash)
		).to.deep.equal(referenceListing(rows, [], { offset: 1000 }));
	});

	it('refuses a limit over 1000', async () => {
		const res = await request(port, '/payments?limit=1001');
		expect(res.status).to.equal(400);
		expect((res.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);
	});
});
