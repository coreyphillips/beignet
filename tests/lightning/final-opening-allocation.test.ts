import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { wallet } from './helpers/final-opening';

describe('Original-device channel key allocation', () => {
	let dir: string;
	let file: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-allocation-'));
		file = path.join(dir, 'regtest.db');
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	it('allocates above the requested floor and earlier ordinary rows before derivation', () => {
		const original = SqliteStorage.createFinalWallet(file, wallet);
		try {
			original.saveChannelKeyIndex('18'.repeat(32), 18);
			const first = original.allocateFinalChannelKeyIndex(3);
			expect(first).to.be.greaterThan(18);
			expect(original.allocateFinalChannelKeyIndex(first)).to.equal(first + 1);
			expect(original.allocateFinalChannelKeyIndex(80)).to.equal(80);
		} finally {
			original.close();
		}
		const reboot = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(reboot.allocateFinalChannelKeyIndex(1)).to.equal(81);
		} finally {
			reboot.close();
		}
	});

	it('advances after a raw original database rollback and refuses a backup or ordinary store', async () => {
		const original = SqliteStorage.createFinalWallet(file, wallet);
		const disk = path.join(dir, 'old.db');
		const backup = path.join(dir, 'backup.db');
		try {
			expect(original.allocateFinalChannelKeyIndex(5)).to.equal(5);
			await original.backup(backup);
		} finally {
			original.close();
		}
		fs.copyFileSync(file, disk);
		const live = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(live.allocateFinalChannelKeyIndex(49)).to.equal(49);
		} finally {
			live.close();
		}
		fs.copyFileSync(disk, file);
		const rewind = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(rewind.allocateFinalChannelKeyIndex(1)).to.be.greaterThan(49);
		} finally {
			rewind.close();
		}
		const copy = SqliteStorage.openFinalWallet(backup, wallet);
		try {
			expect(() => copy.allocateFinalChannelKeyIndex(2)).to.throw();
		} finally {
			copy.close();
		}
		const ordinary = new SqliteStorage(path.join(dir, 'ordinary.db'));
		ordinary.open();
		try {
			expect(() => ordinary.allocateFinalChannelKeyIndex(2)).to.throw();
		} finally {
			ordinary.close();
		}
	});

	it('requires a top-level durable write and refuses exhausted or malformed BIP32 locators', () => {
		const store = SqliteStorage.createFinalWallet(file, wallet);
		try {
			const first = store.allocateFinalChannelKeyIndex(1);
			const db = (store as unknown as { db: Database.Database }).db;
			expect(() =>
				store.transaction(() => store.allocateFinalChannelKeyIndex(first + 1))
			).to.throw();
			db.pragma('query_only = ON');
			try {
				expect(() => store.allocateFinalChannelKeyIndex(first + 1)).to.throw();
			} finally {
				db.pragma('query_only = OFF');
			}
			for (const invalid of [-1, 0, 1.5, NaN, 0x80000000]) {
				expect(() => store.allocateFinalChannelKeyIndex(invalid)).to.throw();
			}
			expect(store.allocateFinalChannelKeyIndex(0x7fffffff)).to.equal(
				0x7fffffff
			);
			expect(() => store.allocateFinalChannelKeyIndex(1)).to.throw();
		} finally {
			store.close();
		}
	});
});
