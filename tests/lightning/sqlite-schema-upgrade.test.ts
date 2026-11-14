import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/payment-types';
import { FIXTURE } from './fixtures/sqlite-schema/values';

/**
 * Databases as shipped releases wrote them (one per schema version, made by
 * scripts/storage-fixture.ts from that release's own storage code), opened
 * with the current code.
 */
const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'sqlite-schema');
const CURRENT = SqliteStorage.CURRENT_SCHEMA_VERSION;

/** The first schema each fixture row's table exists in. */
const WALLET_DATA_SINCE = 8;
const OFFERS_SINCE = 10;
const WATCHTOWER_SINCE = 7;

interface IFixture {
	version: number;
	sql: string;
}

function listFixtures(): IFixture[] {
	const fixtures: IFixture[] = [];
	for (const name of fs.readdirSync(FIXTURE_DIR)) {
		const match = /^schema-(\d+)\.sql$/.exec(name);
		if (!match) continue;
		fixtures.push({
			version: Number(match[1]),
			sql: fs.readFileSync(path.join(FIXTURE_DIR, name), 'utf8')
		});
	}
	return fixtures.sort((a, b) => a.version - b.version);
}

const FIXTURES = listFixtures();

function build(directory: string, fixture: IFixture): string {
	const file = path.join(directory, 'node.db');
	const db = new Database(file);
	try {
		db.transaction(() => db.exec(fixture.sql))();
	} finally {
		db.close();
	}
	return file;
}

function rawVersion(file: string): number {
	const db = new Database(file, { readonly: true });
	try {
		const row = db
			.prepare('SELECT MAX(version) AS v FROM schema_version')
			.get() as { v: number | null };
		return row.v ?? 0;
	} finally {
		db.close();
	}
}

function rowCounts(file: string): Map<string, number> {
	const db = new Database(file, { readonly: true });
	try {
		const tables = db
			.prepare(
				"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_version'"
			)
			.all() as Array<{ name: string }>;
		return new Map(
			tables.map(({ name }) => [
				name,
				(db.prepare(`SELECT COUNT(*) AS n FROM ${name}`).get() as { n: number })
					.n
			])
		);
	} finally {
		db.close();
	}
}

/** Runs `fn` with every Database#exec passed through `hook` first. */
function withExecHook(
	hook: (db: Database.Database, sql: string) => void,
	fn: () => void
): void {
	const prototype = Database.prototype as Database.Database;
	const original = prototype.exec;
	prototype.exec = function (
		this: Database.Database,
		sql: string
	): Database.Database {
		hook(this, sql);
		return original.call(this, sql);
	};
	try {
		fn();
	} finally {
		prototype.exec = original;
	}
}

/**
 * Opens the fixture once to see which ALTERs its upgrade runs, then once per
 * ALTER with that one failing: the open must throw and leave schema_version
 * where the failing migration started. Returns the ALTERs.
 */
function failEachAlter(directory: string, fixture: IFixture): string[] {
	const alters: Array<{ sql: string; from: number }> = [];
	const file = build(fs.mkdtempSync(path.join(directory, 'clean-')), fixture);
	withExecHook(
		(db, sql) => {
			if (!/^\s*ALTER TABLE/i.test(sql)) return;
			const row = db
				.prepare('SELECT MAX(version) AS v FROM schema_version')
				.get() as { v: number | null };
			alters.push({ sql, from: row.v ?? 0 });
		},
		() => {
			const storage = new SqliteStorage(file);
			storage.open();
			storage.close();
		}
	);
	for (const alter of alters) {
		const broken = build(
			fs.mkdtempSync(path.join(directory, 'alter-')),
			fixture
		);
		const storage = new SqliteStorage(broken);
		withExecHook(
			(_db, sql) => {
				if (sql === alter.sql) throw new Error('injected ALTER failure');
			},
			() => {
				expect(() => storage.open(), alter.sql).to.throw(
					'injected ALTER failure'
				);
			}
		);
		storage.close();
		expect(rawVersion(broken), alter.sql).to.equal(alter.from);
	}
	return alters.map((alter) => alter.sql);
}

function hex(value: Buffer | null | undefined): string | undefined {
	return value ? value.toString('hex') : undefined;
}

describe('SqliteStorage upgrade from shipped schemas (#1999)', () => {
	let directory: string;

	beforeEach(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-schema-'));
	});

	afterEach(() => {
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('has a fixture for the schema before CURRENT_SCHEMA_VERSION', () => {
		const versions = FIXTURES.map((f) => f.version);
		expect(
			versions,
			`no fixture for schema ${CURRENT - 1}: write one with ` +
				'scripts/storage-fixture.ts from the code before the bump'
		).to.include(CURRENT - 1);
		expect(Math.max(...versions)).to.be.at.most(CURRENT);
	});

	it('requires exactly the columns a new database has', () => {
		const storage = new SqliteStorage(path.join(directory, 'new.db'));
		storage.open();
		storage.close();
		const db = new Database(path.join(directory, 'new.db'), {
			readonly: true
		});
		try {
			const tables = db
				.prepare(
					"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
				)
				.all() as Array<{ name: string }>;
			const actual: Record<string, string[]> = {};
			for (const { name } of tables) {
				actual[name] = (
					db.pragma(`table_info(${name})`) as Array<{ name: string }>
				)
					.map((c) => c.name)
					.filter((c) => !(name === 'channels' && c === 'channel_index'))
					.sort();
			}
			const required: Record<string, ReadonlyArray<string>> = SqliteStorage[
				'REQUIRED_COLUMNS'
			];
			const expected: Record<string, string[]> = {};
			for (const [table, columns] of Object.entries(required)) {
				expected[table] = [...columns].sort();
			}
			expect(actual).to.deep.equal(expected);
		} finally {
			db.close();
		}
	});

	for (const fixture of FIXTURES) {
		describe(`from schema ${fixture.version}`, () => {
			it('is at the schema version its file name says', () => {
				expect(rawVersion(build(directory, fixture))).to.equal(fixture.version);
			});

			it('opens at the current schema and reads every row back', () => {
				const file = build(directory, fixture);
				const before = rowCounts(file);
				const storage = new SqliteStorage(file);
				storage.open();
				try {
					expect(storage.getSchemaVersion()).to.equal(CURRENT);
					readsBack(storage, fixture.version);
					writesAfterUpgrade(storage);
				} finally {
					storage.close();
				}
				const after = rowCounts(file);
				for (const [table, count] of before) {
					const added = [
						'offers',
						'payments',
						'watchtower_updates',
						'peer_addresses'
					].includes(table)
						? 1
						: 0;
					expect(after.get(table), table).to.equal(count + added);
				}

				const reopened = new SqliteStorage(file);
				reopened.open();
				try {
					expect(reopened.getSchemaVersion()).to.equal(CURRENT);
					expect(reopened.loadAllChannels()).to.have.length(1);
				} finally {
					reopened.close();
				}
			});

			it('leaves the version where it was when an upgrade ALTER fails', () => {
				const alters = failEachAlter(directory, fixture);
				if (fixture.version >= WATCHTOWER_SINCE && fixture.version < 9) {
					expect(alters).to.include(
						'ALTER TABLE watchtower_updates ADD COLUMN blob_type INTEGER NOT NULL DEFAULT 2'
					);
				}
			});
		});
	}

	it('leaves a new database at version 0 when an ALTER fails', () => {
		const alters = failEachAlter(directory, { version: 0, sql: '' });
		expect(alters).to.include(
			'ALTER TABLE channels ADD COLUMN channel_index INTEGER DEFAULT 0'
		);
	});

	it('refuses to open a database recorded past a migration that did not take', () => {
		const fixture = FIXTURES.find((f) => f.version === 8);
		expect(fixture, 'schema 8 fixture').to.not.equal(undefined);
		const file = build(directory, fixture!);
		const db = new Database(file);
		for (let v = 9; v <= CURRENT; v++) {
			db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(v);
		}
		db.close();
		const storage = new SqliteStorage(file);
		try {
			expect(() => storage.open()).to.throw(
				/watchtower_updates\.blob_type.*refusing to open/
			);
		} finally {
			storage.close();
		}
	});

	it('refuses to open a current database that lost a column', () => {
		const file = path.join(directory, 'node.db');
		const storage = new SqliteStorage(file);
		storage.open();
		storage.close();
		const db = new Database(file);
		db.exec('ALTER TABLE offers DROP COLUMN async_hold');
		db.close();
		const reopened = new SqliteStorage(file);
		try {
			expect(() => reopened.open()).to.throw(
				`SQLite database at schema version ${CURRENT} is missing offers.async_hold`
			);
		} finally {
			reopened.close();
		}
	});
});

function readsBack(storage: SqliteStorage, version: number): void {
	const channels = storage.loadAllChannels();
	expect(channels).to.have.length(1);
	const [channel] = channels;
	expect(channel.channelId).to.equal(FIXTURE.channelId);
	expect(channel.peerPubkey).to.equal(FIXTURE.peerPubkey);
	expect(hex(channel.state.channelId)).to.equal(FIXTURE.channelId);
	expect(hex(channel.state.fundingTxid)).to.equal(FIXTURE.fundingTxid);
	expect(channel.state.state).to.equal(ChannelState.NORMAL);
	expect(channel.state.fundingSatoshis).to.equal(FIXTURE.fundingSatoshis);
	expect(channel.state.localBalanceMsat).to.equal(FIXTURE.localBalanceMsat);
	expect(channel.state.remoteBalanceMsat).to.equal(FIXTURE.remoteBalanceMsat);
	expect(channel.state.localCommitmentNumber).to.equal(
		FIXTURE.localCommitmentNumber
	);
	expect(channel.state.remoteCommitmentNumber).to.equal(
		FIXTURE.remoteCommitmentNumber
	);
	expect(storage.loadChannel(FIXTURE.channelId)?.peerPubkey).to.equal(
		FIXTURE.peerPubkey
	);
	expect(storage.loadChannelKeyIndex(FIXTURE.channelId)).to.equal(
		FIXTURE.channelIndex
	);
	expect(storage.loadAllPeerAddresses()).to.deep.equal([
		{
			pubkey: FIXTURE.peerPubkey,
			host: FIXTURE.peerHost,
			port: FIXTURE.peerPort
		}
	]);

	const payments = storage.loadAllPayments();
	expect(payments).to.have.length(1);
	const { payment } = payments[0];
	expect(payments[0].paymentHash).to.equal(FIXTURE.paymentHash);
	expect(hex(payment.paymentHash)).to.equal(FIXTURE.paymentHash);
	expect(hex(payment.preimage)).to.equal(FIXTURE.paymentPreimage);
	expect(payment.amountMsat).to.equal(FIXTURE.paymentAmountMsat);
	expect(payment.status).to.equal(PaymentStatus.COMPLETED);
	expect(payment.direction).to.equal(PaymentDirection.OUTGOING);
	expect(payment.createdAt).to.equal(FIXTURE.paymentCreatedAt);
	expect(payment.completedAt).to.equal(FIXTURE.paymentCompletedAt);
	expect(payment.metadata).to.deep.equal(FIXTURE.paymentMetadata);
	// The lookup columns schema 16 and 17 added are filled for the old row.
	const page = [
		...storage.paymentsNewestFirst(undefined, {
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			metadata: { key: 'label', value: 'fixture' }
		})
	];
	expect(page.map((ref) => [ref.paymentHash, ref.createdAt])).to.deep.equal([
		[FIXTURE.paymentHash, FIXTURE.paymentCreatedAt]
	]);
	expect(hex(storage.loadPreimage(FIXTURE.paymentHash))).to.equal(
		FIXTURE.paymentPreimage
	);
	expect(
		storage
			.loadAllPaymentSecrets()
			.map((s) => [s.paymentHashHex, hex(s.secret)])
	).to.deep.equal([[FIXTURE.invoiceHash, FIXTURE.invoiceSecret]]);

	const invoices = storage.loadAllInvoices();
	expect(invoices).to.have.length(1);
	expect(invoices[0].paymentHashHex).to.equal(FIXTURE.invoiceHash);
	expect(invoices[0].invoice).to.include({
		paymentHash: FIXTURE.invoiceHash,
		bolt11: FIXTURE.invoiceBolt11,
		amountMsat: FIXTURE.invoiceAmountMsat,
		description: FIXTURE.invoiceDescription,
		expiry: FIXTURE.invoiceExpiry,
		createdAt: FIXTURE.invoiceCreatedAt
	});

	expect(storage.loadMetadata(FIXTURE.metadataKey)).to.equal(
		FIXTURE.metadataValue
	);
	expect(storage.loadWalletData(FIXTURE.walletDataKey)).to.equal(
		version >= WALLET_DATA_SINCE ? FIXTURE.walletDataValue : null
	);

	const offers = storage.loadAllOffers();
	if (version >= OFFERS_SINCE) {
		expect(offers.map((o) => ({ ...o, pathId: hex(o.pathId) }))).to.deep.equal([
			{
				offerIdHex: FIXTURE.offerId,
				encoded: FIXTURE.offerEncoded,
				pathId: FIXTURE.offerPathId,
				createdAt: FIXTURE.offerCreatedAt,
				asyncHold: false
			}
		]);
	} else {
		expect(offers).to.deep.equal([]);
	}

	const sessions = storage.loadWatchtowerSessions();
	const updates = storage.loadPendingWatchtowerUpdates();
	if (version < WATCHTOWER_SINCE) {
		expect(sessions).to.deep.equal([]);
		expect(updates).to.deep.equal([]);
		return;
	}
	expect(sessions).to.have.length(1);
	expect(hex(sessions[0].sessionKey)).to.equal(FIXTURE.sessionKey);
	expect(sessions[0]).to.include({
		towerUri: FIXTURE.towerUri,
		towerPubkey: FIXTURE.towerPubkey,
		sessionId: FIXTURE.sessionId,
		blobType: FIXTURE.sessionBlobType,
		maxUpdates: FIXTURE.sessionMaxUpdates,
		sweepFeeRate: FIXTURE.sessionSweepFeeRate,
		seqNum: 1,
		lastApplied: 0,
		createdAt: FIXTURE.sessionCreatedAt,
		dialsWithSessionKey: false
	});
	expect(updates).to.have.length(1);
	expect(updates[0]).to.include({
		towerUri: FIXTURE.towerUri,
		channelId: FIXTURE.channelId,
		blobType: FIXTURE.sessionBlobType,
		hint: FIXTURE.updateHint,
		encryptedBlob: FIXTURE.updateBlob,
		seqNum: 1,
		acked: false,
		createdAt: FIXTURE.updateCreatedAt
	});
}

/** Every statement that names a column a migration added still runs. */
function writesAfterUpgrade(storage: SqliteStorage): void {
	const pubkey =
		'02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
	storage.savePeerAddress(pubkey, 'wss://peer.example/ln', 443, {
		type: 'ws',
		url: 'wss://peer.example/ln'
	});
	expect(
		storage.loadAllPeerAddresses().find((a) => a.pubkey === pubkey)?.transport
	).to.deep.equal({ type: 'ws', url: 'wss://peer.example/ln' });

	storage.saveOffer('ab'.repeat(32), 'lno1after', null, 1, true);
	expect(
		storage.loadAllOffers().find((o) => o.offerIdHex === 'ab'.repeat(32))
			?.asyncHold
	).to.equal(true);

	storage.addWatchtowerUpdate({
		towerUri: FIXTURE.towerUri,
		channelId: FIXTURE.channelId,
		blobType: 1,
		hint: 'cd'.repeat(16),
		encryptedBlob: 'ef'.repeat(32),
		seqNum: 2,
		acked: false,
		createdAt: 2
	});
	expect(
		storage.loadPendingWatchtowerUpdates().find((u) => u.seqNum === 2)?.blobType
	).to.equal(1);

	const paymentHash = '12'.repeat(32);
	storage.savePayment(paymentHash, {
		paymentHash: Buffer.from(paymentHash, 'hex'),
		amountMsat: 1000n,
		status: PaymentStatus.FAILED,
		direction: PaymentDirection.INCOMING,
		createdAt: FIXTURE.paymentCreatedAt + 1
	});
	expect(
		[
			...storage.paymentsNewestFirst(undefined, {
				status: PaymentStatus.FAILED
			})
		].map((ref) => ref.paymentHash)
	).to.deep.equal([paymentHash]);
}
