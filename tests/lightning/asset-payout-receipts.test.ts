import { Transaction } from 'bitcoinjs-lib';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { strict as assert } from 'assert';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';

describe('asset payout receipts on the enrolled device', () => {
	it('restores one immutable signed transaction and proof receipt per original-device payout', async () => {
		const dir = mkdtempSync(join(tmpdir(), 'restore-payout-receipts-'));
		const f = setupAssetSpliceProofs(dir, undefined, 5);
		const legacy = setupAssetSpliceProofs(
			mkdtempSync(join(dir, 'v4-')),
			undefined,
			4
		);
		const parent = new Transaction();
		parent.addInput(Buffer.alloc(32, 41), 0);
		for (let i = 0; i < 2; i++) parent.addOutput(Buffer.of(0x51), 12000);
		const sweep = (vout: number) => {
			const tx = new Transaction();
			tx.version = 2;
			tx.addInput(parent.getHash(), vout, 1);
			tx.addOutput(Buffer.of(0x51), 11700);
			tx.setWitness(0, [Buffer.alloc(64, 71 + vout)]);
			return tx;
		};
		try {
			const d = f.devices[0];
			const receipt = Buffer.from('confirmed proof material');
			const tx = sweep(0).toBuffer();
			const retained = (vout: number) =>
				d.store.assetOpeningPayoutReceipt(f.id, parent.getId(), vout);
			const save = (vout: number, raw: Buffer, evidence: Buffer) =>
				d.store.assetOpeningPayout(f.id, parent.getId(), raw, vout, evidence);
			assert.throws(() =>
				legacy.devices[0].store.assetOpeningPayout(
					legacy.id,
					parent.getId(),
					tx,
					0,
					receipt
				)
			);
			assert.throws(() => save(1, tx, receipt));
			assert.throws(() => save(0, tx, Buffer.alloc(0)));
			assert.equal(retained(0), null);
			assert.equal(retained(1), null);
			const other = Buffer.from('unexpected replacement');
			const results = await Promise.allSettled(
				[receipt, other].map((value) =>
					Promise.resolve().then(() => save(0, tx, value))
				)
			);
			assert.deepEqual(
				results.map((r) => r.status),
				['fulfilled', 'rejected']
			);
			assert.throws(() => save(0, sweep(1).toBuffer(), receipt));
			save(1, sweep(1).toBuffer(), other);
			d.store.close();
			d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
			assert.deepEqual(retained(0), { transaction: tx, receipt });
			assert.deepEqual(retained(1), {
				transaction: sweep(1).toBuffer(),
				receipt: other
			});
			save(0, tx, receipt);
			assert.throws(() => save(0, tx, other));
			assert.deepEqual(retained(0), { transaction: tx, receipt });
		} finally {
			for (const d of [...f.devices, ...legacy.devices]) d.store.close();
			rmSync(dir, { recursive: true, force: true });
		}
	});
	for (const generation of [4, 5] as const) {
		it('keeps payout receipts scoped to generation ' + generation, () => {
			const dir = mkdtempSync(join(tmpdir(), 'payout-receipts-'));
			const f = setupAssetSpliceProofs(dir, undefined, generation);
			try {
				const store = f.devices[0].store;
				const parent = 'c1'.repeat(32);
				const first = Buffer.from('01', 'hex'),
					second = Buffer.from('02', 'hex');
				if (generation === 4) {
					assert.deepEqual(
						store.assetOpeningPayout(f.id, parent, first),
						first
					);
					assert.throws(() =>
						store.assetOpeningPayout(f.id, parent, undefined, 0)
					);
					return;
				}
				assert.throws(() => store.assetOpeningPayout(f.id, parent, first));
				assert.throws(() => store.assetOpeningPayout(f.id, parent, first, -1));
				for (const [index, raw] of [first, second].entries())
					assert.deepEqual(
						store.assetOpeningPayout(f.id, parent, raw, index),
						raw
					);
				for (const [index, raw] of [first, second].entries())
					assert.deepEqual(
						store.assetOpeningPayout(f.id, parent, undefined, index),
						raw
					);
				assert.throws(() => store.assetOpeningPayout(f.id, parent, first, 1));
			} finally {
				for (const device of f.devices) device.store.close();
				rmSync(dir, { recursive: true, force: true });
			}
		});
	}
});
