import { expect } from 'chai';
import Database from 'better-sqlite3';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { alice, bob, peers } from './helpers/final-opening-signing';

describe('Replacing a final opening recovery backup', () => {
	let directory: string;
	let file: string;
	let wallets: ReturnType<typeof peers>;
	let exit: Buffer;
	let source: Database.Database;

	beforeEach(async () => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-final-backup-'));
		file = path.join(directory, 'backup.db');
		wallets = peers(directory);
		const { a, b, id, terms, bTerms } = wallets;
		const share = b.signFinalPeerCommitment(id, bTerms, bob.root, bob.index);
		exit = a.acceptFinalPeerCommitment(
			id,
			terms,
			alice.root,
			alice.index,
			share
		);
		a.saveWalletData('stage', 'before');
		await a.backup(file);
		a.saveWalletData('stage', 'after');
		source = (a as unknown as { db: Database.Database }).db;
	});
	afterEach(() => {
		wallets.a.close();
		wallets.b.close();
		fs.rmSync(directory, { recursive: true, force: true });
	});

	for (const [caseName, statement, both] of [
		[
			'an unexpected trigger silently skips candidates',
			'CREATE TRIGGER skip_candidate BEFORE INSERT ON final_opening_candidates BEGIN SELECT RAISE(IGNORE); END',
			true
		],
		[
			'a virtual table has shadow tables',
			'CREATE VIRTUAL TABLE extra_search USING fts5(body)',
			true
		],
		[
			'wallets have different application IDs',
			'PRAGMA application_id = 82304',
			false
		],
		['wallets have different user versions', 'PRAGMA user_version = 827', false]
	] as const) {
		it('preserves the saved exit and metadata when ' + caseName, async () => {
			source.exec(statement);
			if (both) {
				const raw = new Database(file, { fileMustExist: true });
				try {
					raw.exec(statement);
				} finally {
					raw.close();
				}
			}
			let refused = false;
			await wallets.a.backup(file).catch(() => {
				refused = true;
			});
			expect(refused).to.equal(true);
			const kept = SqliteStorage.openFinalWallet(file, alice.binding);
			try {
				expect(kept.loadFinalOpeningExit(wallets.id)).to.deep.equal(exit);
				expect(kept.loadWalletData('stage')).to.equal('before');
			} finally {
				kept.close();
			}
		});
	}

	it('preserves sparse rowids and the deleted autoincrement high-water mark on replacement', async () => {
		const { a } = wallets;
		a.saveWalletData('sparse', 'marker');
		source
			.prepare("UPDATE wallet_data SET rowid = ? WHERE key = 'sparse'")
			.run(441);
		source.exec(
			"INSERT INTO action_log (id, category, action, timestamp, data) VALUES (32, 'test', 'kept', 1, 'a'), (90, 'test', 'deleted', 2, 'b'); DELETE FROM action_log WHERE id = 90"
		);
		await a.backup(file);
		const kept = new Database(file, { fileMustExist: true });
		try {
			expect(
				kept
					.prepare("SELECT rowid FROM wallet_data WHERE key='sparse'")
					.pluck()
					.get()
			).to.equal(441);
			expect(
				kept.prepare('SELECT id FROM action_log ORDER BY id').pluck().all()
			).to.deep.equal([32]);
			expect(
				kept
					.prepare("SELECT seq FROM sqlite_sequence WHERE name='action_log'")
					.pluck()
					.get()
			).to.equal(90);
			expect(
				kept
					.prepare(
						"INSERT INTO action_log(category,action,timestamp,data) VALUES ('test','next',3,'c')"
					)
					.run().lastInsertRowid
			).to.equal(91);
		} finally {
			kept.close();
		}
	});
});
