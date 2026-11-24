import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

describe('Fresh regtest commitment update enrollment', () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'final-enroll-'));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('authenticates the update generation on every open and withholds unilateral exits from backups', async () => {
		const { binding } = generateFinalDaemonWallet(true);
		const file = path.join(dir, 'active.db');
		const copy = path.join(dir, 'backup.db');
		const original = SqliteStorage.createFinalWallet(file, binding);
		try {
			expect(original.canUpdateFinalCommitments).to.equal(true);
			original.assertFinalDaemonIdentity(binding.nodeId);
			await original.backup(copy);
		} finally {
			original.close();
		}
		const previousReader = { ...binding, finalCommitmentUpdates: false };
		for (const db of [file, copy])
			expect(() => SqliteStorage.openFinalWallet(db, previousReader)).to.throw(
				'binding'
			);
		const restored = SqliteStorage.openFinalWallet(copy, binding);
		try {
			expect(restored.canUpdateFinalCommitments).to.equal(false);
			expect(() => restored.loadFinalOpeningExit('00'.repeat(32))).to.throw(
				'original wallet device'
			);
			expect(() => restored.requestFinalOpeningExit('00'.repeat(32))).to.throw(
				'original wallet device'
			);
		} finally {
			restored.close();
		}
		const restart = SqliteStorage.openFinalWallet(file, binding);
		try {
			expect(restart.canUpdateFinalCommitments).to.equal(true);
		} finally {
			restart.close();
		}
	});

	it('keeps existing openings and supplied seeds out of the revocable format', () => {
		const { binding } = generateFinalDaemonWallet();
		const file = path.join(dir, 'old.db');
		const store = SqliteStorage.createFinalWallet(file, binding);
		try {
			expect(store.canUpdateFinalCommitments).to.equal(false);
		} finally {
			store.close();
		}
		const requested = { ...binding, finalCommitmentUpdates: true };
		expect(() => SqliteStorage.openFinalWallet(file, requested)).to.throw(
			'binding'
		);
		expect(() =>
			SqliteStorage.createFinalWallet(path.join(dir, 'fresh.db'), requested)
		).to.throw('freshly generated');
		expect(fs.existsSync(path.join(dir, 'fresh.db'))).to.equal(false);
	});
});
