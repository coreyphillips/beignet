/**
 * Issue #1861: the SQLite loaders a lightning node walks at startup read a
 * whole history table with one all(), so every raw row (encrypted JSON on
 * an encrypted database) sat in memory beside its decoded copy. They now
 * read the table in rowid batches, which is the order the plain scan
 * returned, so the node's maps fill in the same order as before.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import type Database from 'better-sqlite3';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IInvoiceInfo } from '../../src/lightning/storage/types';

/** Two full batches of 500 and three rows more. */
const ROWS = 1203;

const sha256 = (data: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(data).digest();

const preimageOf = (i: number): Buffer => sha256(`history-preimage-${i}`);
const hashOf = (i: number): string => sha256(preimageOf(i)).toString('hex');

function dbOf(storage: SqliteStorage): Database.Database {
	return (storage as unknown as { db: Database.Database }).db;
}

function payment(
	i: number,
	direction: PaymentDirection,
	status: PaymentStatus
): IPaymentInfo {
	return {
		paymentHash: Buffer.from(hashOf(i), 'hex'),
		...(status === PaymentStatus.COMPLETED ? { preimage: preimageOf(i) } : {}),
		amountMsat: 50_000n,
		status,
		direction,
		createdAt: 1_700_000_000_000 + i,
		...(status === PaymentStatus.COMPLETED
			? { completedAt: 1_700_000_000_500 + i }
			: {})
	};
}

function invoice(i: number, extra: Partial<IInvoiceInfo> = {}): IInvoiceInfo {
	return {
		paymentHash: hashOf(i),
		bolt11: `lnbcrt-history-${i}`,
		amountMsat: 50_000n,
		expiry: 3600,
		createdAt: 1_700_000_000 + i,
		...extra
	};
}

/** Every per-payment table startup reads, ROWS rows each. */
function seed(storage: SqliteStorage, rows = ROWS): void {
	dbOf(storage).transaction(() => {
		for (let i = 0; i < rows; i++) {
			const hash = hashOf(i);
			storage.savePayment(
				hash,
				payment(i, PaymentDirection.INCOMING, PaymentStatus.COMPLETED)
			);
			storage.savePreimage(hash, preimageOf(i));
			storage.savePaymentSecret(hash, sha256(`secret-${i}`));
			storage.saveInvoice(hash, invoice(i));
			storage.saveHtlcPaymentMapping(`htlc-${i}`, hash);
			storage.saveHtlcSharedSecret(`htlc-${i}`, sha256(`shared-${i}`));
		}
	})();
}

/** The keys in the order the loaders' former unordered all() returned. */
function plainScanKeys(
	storage: SqliteStorage,
	table: string,
	key: string,
	value: string
): string[] {
	return dbOf(storage)
		.prepare(`SELECT ${key}, ${value} FROM ${table}`)
		.all()
		.map((row) => (row as Record<string, string>)[key]);
}

/** Records how many rows each batched history query returned, per table. */
function spyOnBatches(storage: SqliteStorage): Map<string, number[]> {
	const db = dbOf(storage);
	const batches = new Map<string, number[]>();
	const prepare = db.prepare.bind(db);
	db.prepare = ((sql: string) => {
		const statement = prepare(sql);
		const table = /^SELECT rowid, .* FROM (\w+)/.exec(sql)?.[1];
		if (!table) return statement;
		const all = statement.all.bind(statement);
		statement.all = ((...params: unknown[]) => {
			const rows = all(...params);
			batches.set(table, [...(batches.get(table) ?? []), rows.length]);
			return rows;
		}) as typeof statement.all;
		return statement;
	}) as typeof db.prepare;
	return batches;
}

describe('Startup history reads in batches (issue #1861)', () => {
	it('reads each history table a batch at a time, in the order a plain scan returns', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		seed(storage);
		// A re-save is a delete and insert, so the row moves to the end of
		// the scan; the batches have to follow it there.
		const moved = hashOf(3);
		storage.savePayment(
			moved,
			payment(3, PaymentDirection.OUTGOING, PaymentStatus.COMPLETED)
		);
		storage.saveInvoice(moved, invoice(3, { description: 'resaved' }));
		storage.savePreimage(moved, preimageOf(3));

		const batches = spyOnBatches(storage);
		const loaded = {
			payments: storage.loadAllPayments().map((row) => row.paymentHash),
			preimages: storage.loadAllPreimages().map((row) => row.paymentHash),
			payment_secrets: storage
				.loadAllPaymentSecrets()
				.map((row) => row.paymentHashHex),
			invoices: storage.loadAllInvoices().map((row) => row.paymentHashHex),
			htlc_payment_map: storage
				.loadAllHtlcPaymentMappings()
				.map((row) => row.key),
			htlc_shared_secrets: storage
				.loadAllHtlcSharedSecrets()
				.map((row) => row.key)
		};

		expect(loaded.payments).to.deep.equal(
			plainScanKeys(storage, 'payments', 'payment_hash', 'payment_json')
		);
		expect(loaded.payments[ROWS - 1]).to.equal(moved);
		expect(loaded.preimages).to.deep.equal(
			plainScanKeys(storage, 'preimages', 'payment_hash', 'preimage')
		);
		expect(loaded.payment_secrets).to.deep.equal(
			plainScanKeys(storage, 'payment_secrets', 'payment_hash_hex', 'secret')
		);
		expect(loaded.invoices).to.deep.equal(
			plainScanKeys(storage, 'invoices', 'payment_hash_hex', 'invoice_json')
		);
		expect(loaded.invoices[ROWS - 1]).to.equal(moved);
		expect(loaded.htlc_payment_map).to.deep.equal(
			plainScanKeys(storage, 'htlc_payment_map', 'htlc_key', 'payment_hash_hex')
		);
		expect(loaded.htlc_shared_secrets).to.deep.equal(
			plainScanKeys(storage, 'htlc_shared_secrets', 'key', 'secret')
		);
		for (const keys of Object.values(loaded)) {
			expect(new Set(keys).size).to.equal(ROWS);
		}
		for (const table of Object.keys(loaded)) {
			expect(batches.get(table), table).to.deep.equal([500, 500, 203]);
		}
		expect(storage.corruptRowCount()).to.equal(0);
		storage.close();
	});

	it('skips a corrupt row in a later batch and still loads the rows after it', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		seed(storage);
		const db = dbOf(storage);
		db.prepare(
			'UPDATE payments SET payment_json = ? WHERE payment_hash = ?'
		).run('{not json', hashOf(700));
		db.prepare('UPDATE preimages SET preimage = ? WHERE payment_hash = ?').run(
			'zz',
			hashOf(1100)
		);

		const payments = storage.loadAllPayments().map((row) => row.paymentHash);
		const preimages = storage.loadAllPreimages().map((row) => row.paymentHash);
		expect(payments).to.have.length(ROWS - 1);
		expect(payments).to.not.include(hashOf(700));
		expect(payments[ROWS - 2]).to.equal(hashOf(ROWS - 1));
		expect(preimages).to.have.length(ROWS - 1);
		expect(preimages).to.not.include(hashOf(1100));
		expect(preimages[ROWS - 2]).to.equal(hashOf(ROWS - 1));
		expect(storage.corruptRowCount()).to.equal(2);
		storage.close();
	});

	it('stops after an empty table and after a batch that fills exactly', () => {
		const empty = new SqliteStorage(':memory:');
		empty.open();
		const emptyBatches = spyOnBatches(empty);
		expect(empty.loadAllPayments()).to.deep.equal([]);
		expect(emptyBatches.get('payments')).to.deep.equal([0]);
		empty.close();

		const full = new SqliteStorage(':memory:');
		full.open();
		seed(full, 500);
		const fullBatches = spyOnBatches(full);
		expect(full.loadAllInvoices()).to.have.length(500);
		expect(fullBatches.get('invoices')).to.deep.equal([500, 0]);
		full.close();
	});
});

describe('Node restart over a history larger than a batch (issue #1861)', () => {
	const PAID = 1100;
	const UNREADABLE = 1150;
	const HELD = 1000;
	const HELD_SETTLED = 1001;
	const HELD_CANCELLED = 1002;

	function nodeConfig(): INodeConfig {
		const key = (label: string): Buffer => sha256(`history-node-${label}`);
		return {
			nodePrivateKey: key('node'),
			network: Network.REGTEST,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: {
				fundingPubkey: getPublicKey(key('funding')),
				revocationBasepoint: getPublicKey(key('revocation')),
				paymentBasepoint: getPublicKey(key('payment')),
				delayedPaymentBasepoint: getPublicKey(key('delayed')),
				htlcBasepoint: getPublicKey(key('htlc')),
				firstPerCommitmentPoint: Buffer.alloc(33)
			},
			perCommitmentSeed: key('commitment'),
			fundingPrivkey: key('funding')
		};
	}

	/** A payee's invoice for the hash at index i, as a payer would get it. */
	function foreignInvoice(i: number): string {
		const payeeKey = sha256('history-payee');
		return encodeInvoice({
			network: Network.REGTEST,
			paymentHash: Buffer.from(hashOf(i), 'hex'),
			paymentSecret: sha256(`payee-secret-${i}`),
			timestamp: Math.floor(Date.now() / 1000),
			description: 'history',
			minFinalCltvExpiry: 40,
			amountMsat: 50_000n,
			payeeNodeKey: getPublicKey(payeeKey),
			privateKey: payeeKey
		});
	}

	function sendError(node: LightningNode, i: number): unknown {
		try {
			node.sendPayment(foreignInvoice(i));
		} catch (err) {
			return err;
		}
		return undefined;
	}

	it('restores every row and keeps paid-hash refusal, hold state and preimages', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		seed(storage);
		storage.savePayment(
			hashOf(PAID),
			payment(PAID, PaymentDirection.OUTGOING, PaymentStatus.COMPLETED)
		);
		storage.savePayment(
			hashOf(UNREADABLE),
			payment(UNREADABLE, PaymentDirection.OUTGOING, PaymentStatus.COMPLETED)
		);
		dbOf(storage)
			.prepare('UPDATE payments SET payment_json = ? WHERE payment_hash = ?')
			.run('{not json', hashOf(UNREADABLE));
		storage.savePayment(
			hashOf(HELD),
			payment(HELD, PaymentDirection.INCOMING, PaymentStatus.PENDING)
		);
		storage.saveInvoice(hashOf(HELD), invoice(HELD, { hold: true }));
		storage.saveInvoice(
			hashOf(HELD_SETTLED),
			invoice(HELD_SETTLED, { hold: true })
		);
		storage.saveInvoice(
			hashOf(HELD_CANCELLED),
			invoice(HELD_CANCELLED, { hold: true, cancelledAt: Date.now() })
		);
		const expectedPayments = plainScanKeys(
			storage,
			'payments',
			'payment_hash',
			'payment_json'
		).filter((hash) => hash !== hashOf(UNREADABLE));

		const node = new LightningNode({ ...nodeConfig(), storage });
		node.on('node:error', () => {});
		const internals = node as unknown as {
			heldInvoiceHashes: Set<string>;
			preimages: Map<string, Buffer>;
			paymentSecrets: Map<string, Buffer>;
		};

		expect(
			node.listPayments().map((p) => p.paymentHash.toString('hex'))
		).to.deep.equal(expectedPayments);
		expect(node.listInvoices()).to.have.length(ROWS);

		const paid = sendError(node, PAID);
		expect(paid).to.be.instanceOf(LightningPaymentError);
		expect((paid as LightningPaymentError).code).to.equal(
			LightningErrorCode.DUPLICATE_PAYMENT
		);
		// Skipped at startup, so the send reads the row and refuses closed.
		expect((sendError(node, UNREADABLE) as Error).message).to.match(
			/^payment record could not be read/
		);

		expect(internals.heldInvoiceHashes.has(hashOf(HELD))).to.equal(true);
		expect(internals.heldInvoiceHashes.has(hashOf(HELD_SETTLED))).to.equal(
			false
		);
		expect(internals.heldInvoiceHashes.has(hashOf(HELD_CANCELLED))).to.equal(
			false
		);
		expect(internals.preimages.has(hashOf(HELD_CANCELLED))).to.equal(false);
		expect(internals.paymentSecrets.has(hashOf(HELD_CANCELLED))).to.equal(
			false
		);
		expect(internals.preimages.size).to.equal(ROWS - 1);
		expect(internals.paymentSecrets.size).to.equal(ROWS - 1);

		// The last batch reaches the channel manager too, so a monitor made
		// after this restart can still claim on chain.
		const known = (
			node.getChannelManager() as unknown as {
				_knownPreimages: Map<string, Buffer>;
			}
		)._knownPreimages;
		expect(known.get(hashOf(ROWS - 1))?.equals(preimageOf(ROWS - 1))).to.equal(
			true
		);

		node.destroy();
		storage.close();
	});
});
