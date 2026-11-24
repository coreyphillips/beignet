import { expect } from 'chai';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { generateSide, fundReadyPair } from './helpers/final-update-pair';

describe('final device journal repair at backup', () => {
	it('preserves a device-ahead close and timeout receipt without a preceding public read', async function () {
		this.timeout(15000);
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'final-backup-'));
		const alice = generateSide(),
			bob = generateSide();
		const a = SqliteStorage.createFinalWallet(
			path.join(directory, 'alice.db'),
			alice.binding
		);
		const b = SqliteStorage.createFinalWallet(
			path.join(directory, 'bob.db'),
			bob.binding
		);
		const copy = path.join(directory, 'backup.db');
		let restored: SqliteStorage | undefined;
		try {
			const id = fundReadyPair(a, b, alice, bob),
				hash = Buffer.alloc(32, 41);
			const request = {
				start: true,
				script: Buffer.from('0014' + '44'.repeat(20), 'hex'),
				blockHeight: 200,
				feeratePerKw: 1000
			};
			const shutdown = a.finalSimpleCloseStep(id, alice.root, request)
				.messages[0];
			expect(a.finalHtlcTimedOut(id, hash, 0n, true)).to.equal(true);
			const db = a['db'];
			const before = db
				.prepare(
					'SELECT scope,sequence,record FROM final_lifecycle_log ORDER BY scope,sequence'
				)
				.all();
			expect(before.length).to.be.greaterThan(1);
			db.prepare('DELETE FROM final_lifecycle_log').run();
			await a.backup(copy);
			expect(
				db
					.prepare(
						'SELECT scope,sequence,record FROM final_lifecycle_log ORDER BY scope,sequence'
					)
					.all()
			).to.deep.equal(before);
			restored = SqliteStorage.openFinalWallet(copy, alice.binding);
			expect(restored.canUpdateFinalCommitments).to.equal(false);
			expect(restored.loadFinalSimpleClose(id)?.localShutdown).to.equal(
				shutdown.payload.toString('hex')
			);
			expect(
				restored['db']
					.prepare(
						'SELECT scope,sequence,record FROM final_lifecycle_log ORDER BY scope,sequence'
					)
					.all()
			).to.deep.equal(before);
			expect(() =>
				restored!.finalSimpleCloseStep(id, alice.root, request)
			).to.throw('original');
			expect(() => restored!.requestFinalOpeningExit(id)).to.throw('original');
			restored.close();
			restored = undefined;
			await a.backup(copy);
			expect(a.finalHtlcTimedOut(id, hash, 0n)).to.equal(true);
		} finally {
			restored?.close();
			a.close();
			b.close();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
