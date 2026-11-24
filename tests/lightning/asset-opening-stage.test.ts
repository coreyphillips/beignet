import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';

describe('Asset opening stage journal', () => {
	it('pins packet bytes and signing reservations across restart on the original device', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-open-stage-'));
		const file = path.join(dir, 'original.db'),
			copy = path.join(dir, 'copy.db');
		const { binding } = generateFinalDaemonWallet(false, true);
		const id = '6b'.repeat(32);
		let db = SqliteStorage.createFinalWallet(file, binding);
		try {
			await db.backup(copy);
			const packet = Buffer.from('the canonical first opening proposal');
			db.saveAssetOpenStage(id, 'proposal', packet);
			db.saveAssetOpenStage(id, 'proposal', Buffer.from(packet));
			db.reserveAssetOpenSignature(id, 'authorization', Buffer.alloc(32, 4));
			expect(() =>
				db.saveAssetOpenStage(id, 'proposal', Buffer.from('other'))
			).to.throw();
			db.close();
			db = SqliteStorage.openFinalWallet(file, binding);
			expect(db.listAssetOpenStages()).to.deep.equal([id]);
			expect(db.loadAssetOpenStage(id, 'proposal')).to.deep.equal(packet);
			db.reserveAssetOpenSignature(id, 'authorization', Buffer.alloc(32, 4));
			expect(() =>
				db.reserveAssetOpenSignature(id, 'authorization', Buffer.alloc(32, 5))
			).to.throw();
			expect(() =>
				db.saveAssetOpenStage(id, 'large', Buffer.alloc(4 * 1024 * 1024 + 1))
			).to.throw();
			db.saveAssetOpenStage(id, 'finished', Buffer.alloc(0));
			expect(db.listAssetOpenStages()).to.deep.equal([]);
			expect(db.loadAssetOpenStage(id, 'proposal')).to.equal(null);
			expect(() =>
				db.saveAssetOpenStage(id, 'late', Buffer.from([1]))
			).to.throw();
			expect(
				fs.readFileSync(file + '.opening-signer').includes(packet)
			).to.equal(false);
			const restored = SqliteStorage.openFinalWallet(copy, binding);
			try {
				expect(() =>
					restored.saveAssetOpenStage(id, 'proposal', packet)
				).to.throw();
			} finally {
				restored.close();
			}
			for (let i = 0; i < 8; i++) {
				db.saveAssetOpenStage(i.toString(16).padStart(64, '0'), 'meta', packet);
			}
			expect(() =>
				db.saveAssetOpenStage('dd'.repeat(32), 'proposal', packet)
			).to.throw();
			db.saveAssetOpenStage('0'.repeat(64), 'finished', Buffer.of(1));
			db.saveAssetOpenStage('dd'.repeat(32), 'proposal', packet);
			expect(db.listAssetOpenStages()).to.have.length(8);
		} finally {
			db.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
	it('reclaims retired proof bytes while an older wallet snapshot cannot reopen the attempt or its signer', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-open-retire-'));
		const file = path.join(dir, 'wallet.db'),
			before = path.join(dir, 'before.db');
		const { binding } = generateFinalDaemonWallet(false, true),
			id = '37'.repeat(32);
		let db = SqliteStorage.createFinalWallet(file, binding);
		try {
			db.saveAssetOpenStage(id, 'start', Buffer.from('terms'));
			db.close();
			fs.copyFileSync(file, before);
			db = SqliteStorage.openFinalWallet(file, binding);
			db.reserveAssetOpenSignature(id, 'authorization', Buffer.alloc(32, 4));
			db.saveAssetOpenStage(
				id,
				'our/authorization',
				Buffer.alloc(1024 * 1024, 91)
			);
			db.saveAssetOpenStage(id, 'peerNonce', Buffer.alloc(166, 33));
			const device = file + '.opening-signer',
				full = fs.statSync(device).size;
			db.saveAssetOpenStage(id, 'finished', Buffer.alloc(0));
			expect(db.loadAssetOpenStage(id, 'our/authorization')).to.equal(null);
			expect(fs.statSync(device).size).to.be.lessThan(full / 2);
			db.close();
			fs.copyFileSync(before, file);
			db = SqliteStorage.openFinalWallet(file, binding);
			expect(db.listAssetOpenStages()).to.deep.equal([]);
			expect(db.loadAssetOpenStage(id, 'peerNonce')).to.deep.equal(
				Buffer.alloc(166, 33)
			);
			expect(() =>
				db.saveAssetOpenStage(id, 'start', Buffer.from('replacement'))
			).to.throw();
			expect(() =>
				db.reserveAssetOpenSignature(id, 'authorization', Buffer.alloc(32, 5))
			).to.throw();
		} finally {
			db.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
