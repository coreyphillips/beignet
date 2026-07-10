/**
 * Daemon on-chain wallet persistence.
 *
 * BeignetNode wires a TStorage adapter (src/cli/wallet-storage.ts) into
 * Wallet.create so IWalletData persists in the node's SQLite DB (wallet_data
 * table, schema v8). Rows are encrypted at rest when storageEncryption is on
 * (the default) and plaintext when it is off. A rebooted node must reload
 * wallet state from disk without Electrum.
 *
 * Electrum is intentionally unreachable throughout: persistence must not
 * depend on it, and a second boot proves state comes from disk.
 */

import { expect } from 'chai';
import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IUtxo } from '../../src/types/wallet';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ENC_PREFIX = 'enc1:';

const markerUtxo: IUtxo = {
	address: 'bcrt1qmarkeraddressxyz',
	index: 0,
	path: "m/84'/1'/0'/0/0",
	scriptHash: 'aa'.repeat(32),
	height: 100,
	tx_hash: 'bb'.repeat(32),
	tx_pos: 0,
	value: 12345,
	publicKey: 'cc'.repeat(33)
};

function createOffline(
	dataDir: string,
	storageEncryption?: boolean
): Promise<BeignetNode> {
	return BeignetNode.create({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir,
		logLevel: 'silent',
		rapidGossipSync: false,
		autoGossipSync: false,
		electrumHost: '127.0.0.1',
		electrumPort: 65528,
		electrumTls: false,
		...(storageEncryption === undefined ? {} : { storageEncryption })
	});
}

function readWalletRows(dbPath: string): Array<{ key: string; value: string }> {
	const db = new Database(dbPath, { readonly: true });
	try {
		return db.prepare('SELECT key, value FROM wallet_data').all() as Array<{
			key: string;
			value: string;
		}>;
	} finally {
		db.close();
	}
}

describe('Daemon on-chain wallet persistence', function () {
	this.timeout(180_000);

	it('SqliteStorage schema version is 8', () => {
		expect(SqliteStorage.CURRENT_SCHEMA_VERSION).to.equal(8);
	});

	describe('encrypted mode (default)', () => {
		let tmpDir: string;
		let dbPath: string;
		let walletId: string;

		before(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-persist-enc-'));
			dbPath = path.join(tmpDir, 'regtest.db');
		});

		after(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('boot writes encrypted wallet rows to disk', async () => {
			const node = await createOffline(tmpDir);
			try {
				const wallet = node.getWallet();
				walletId = wallet.id;
				// Ensure the initial (offline) refresh finished generating and
				// saving the index-0 address set before the markers are written.
				await wallet.refreshWallet({});
				await wallet.saveWalletData('balance', 4321);
				await wallet.saveWalletData('utxos', [markerUtxo]);
			} finally {
				await node.destroy();
			}

			const rows = readWalletRows(dbPath);
			expect(rows.length).to.be.greaterThan(0);
			// Keys stay plaintext (they are lookups) and embed wallet + network.
			const keys = rows.map((r) => r.key);
			expect(keys).to.include(`${walletId}-regtest-id`);
			expect(keys).to.include(`${walletId}-regtest-balance`);
			expect(keys).to.include(`${walletId}-regtest-addresses`);
			for (const row of rows) {
				expect(row.value.startsWith(ENC_PREFIX), row.key).to.equal(true);
			}
			// No plaintext leak of the marker UTXO address anywhere on disk
			// (including a leftover WAL file).
			let raw = fs.readFileSync(dbPath).toString('latin1');
			if (fs.existsSync(`${dbPath}-wal`)) {
				raw += fs.readFileSync(`${dbPath}-wal`).toString('latin1');
			}
			expect(raw.includes(markerUtxo.address)).to.equal(false);
		});

		it('recorded schema version is 8', () => {
			const db = new Database(dbPath, { readonly: true });
			try {
				const row = db
					.prepare('SELECT MAX(version) as v FROM schema_version')
					.get() as { v: number };
				expect(row.v).to.equal(8);
			} finally {
				db.close();
			}
		});

		it('a second boot reloads wallet state from disk without Electrum', async () => {
			const node = await createOffline(tmpDir);
			try {
				const wallet = node.getWallet();
				expect(wallet.id).to.equal(walletId);
				expect(wallet.data.balance).to.equal(4321);
				expect(wallet.data.utxos).to.deep.equal([markerUtxo]);
				// The address set generated on first boot survives the restart.
				const indexAddress = wallet.data.addressIndex.p2wpkh.address;
				expect(indexAddress).to.be.a('string').and.not.equal('');
				expect(
					Object.keys(wallet.data.addresses.p2wpkh).length
				).to.be.greaterThan(0);
			} finally {
				await node.destroy();
			}
		});
	});

	describe('plaintext mode (storageEncryption: false)', () => {
		let tmpDir: string;

		before(function () {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-persist-plain-'));
		});

		after(function () {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('persists wallet rows as plaintext JSON and reloads them', async () => {
			const node = await createOffline(tmpDir, false);
			let walletId = '';
			try {
				const wallet = node.getWallet();
				walletId = wallet.id;
				await wallet.saveWalletData('balance', 9876);
			} finally {
				await node.destroy();
			}

			const rows = readWalletRows(path.join(tmpDir, 'regtest.db'));
			expect(rows.length).to.be.greaterThan(0);
			for (const row of rows) {
				expect(row.value.startsWith(ENC_PREFIX), row.key).to.equal(false);
			}
			const balanceRow = rows.find(
				(r) => r.key === `${walletId}-regtest-balance`
			);
			expect(balanceRow).to.not.equal(undefined);
			expect(JSON.parse(balanceRow!.value)).to.equal(9876);

			const reboot = await createOffline(tmpDir, false);
			try {
				expect(reboot.getWallet().data.balance).to.equal(9876);
			} finally {
				await reboot.destroy();
			}
		});
	});
});
