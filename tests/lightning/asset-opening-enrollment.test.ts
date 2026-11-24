import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

describe('Fresh regtest asset opening wallet', () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-enroll-'));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('binds opening authority to generation three and the original device', async () => {
		const { binding } = generateFinalDaemonWallet(false, true);
		expect(binding.dualFundedAssets).to.equal(true);
		const file = path.join(dir, 'original.db');
		const copy = path.join(dir, 'copy.db');
		const active = SqliteStorage.createFinalWallet(file, binding);
		try {
			expect(active.canOpenDualFundedAssets).to.equal(true);
			expect(active.canUpdateFinalCommitments).to.equal(false);
			await active.backup(copy);
		} finally {
			active.close();
		}
		for (const db of [file, copy]) {
			for (const finalCommitmentUpdates of [false, true]) {
				const old = {
					...binding,
					finalCommitmentUpdates,
					dualFundedAssets: false
				};
				expect(() => SqliteStorage.openFinalWallet(db, old)).to.throw(
					/binding/
				);
			}
		}
		const restored = SqliteStorage.openFinalWallet(copy, binding);
		try {
			expect(restored.canOpenDualFundedAssets).to.equal(false);
		} finally {
			restored.close();
		}
		const original = SqliteStorage.openFinalWallet(file, binding);
		try {
			expect(original.canOpenDualFundedAssets).to.equal(true);
		} finally {
			original.close();
		}
	});

	it('keeps imported seeds, older enrollments, and conflicting generations out', () => {
		expect(() => generateFinalDaemonWallet(true, true)).to.throw();
		for (const updates of [false, true]) {
			const { binding } = generateFinalDaemonWallet(updates);
			const file = path.join(dir, String(updates) + '.db');
			const original = SqliteStorage.createFinalWallet(file, binding);
			try {
				expect(original.canOpenDualFundedAssets).to.equal(false);
			} finally {
				original.close();
			}
			const requested = {
				...binding,
				finalCommitmentUpdates: false,
				dualFundedAssets: true
			};
			expect(() => SqliteStorage.openFinalWallet(file, requested)).to.throw(
				/binding/
			);
			expect(() =>
				SqliteStorage.createFinalWallet(file + '.new', requested)
			).to.throw(/freshly generated/);
			expect(fs.existsSync(file + '.new')).to.equal(false);
		}
	});
});
