import { strict as assert } from 'assert';
import { mkdtempSync, rmSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { performAssetChannelRestore } from '../../src/cli/restore';
import { writeBackupMac } from '../../src/cli/backup-mac';
import {
	acquireInstanceLock,
	releaseInstanceLock
} from '../../src/cli/instance-lock';
import { setupAssetSplicePeerTransport } from '../lightning/helpers/asset-splice-peer-transport';

describe('Offline restore of an asset channel on its original device', function () {
	this.timeout(60000);
	const mac = Buffer.alloc(32, 79);
	let dir: string;
	let pair: ReturnType<typeof setupAssetSplicePeerTransport>;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'asset-channel-restore-'));
		pair = setupAssetSplicePeerTransport(dir);
	});
	afterEach(() => {
		pair.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('recovers the adopted outpoint and device journal from frames before and after splicing', async () => {
		const frames = [join(dir, 'before.db'), join(dir, 'after.db')];
		const { devices, id } = pair.f;
		await devices[0].store.backup(frames[0]);
		await pair.start();
		await pair.drain();
		const txid = await pair.adopt();
		await devices[1].store.backup(frames[1]);
		for (const [side, device] of devices.entries()) {
			const frame = frames[side];
			await writeBackupMac(mac, frame);
			const expected = device.store.readAssetSpliceJournal(id);
			assert(expected.sequence > 0);
			const expectedOpening =
				device.store.loadFinalDaemonOpening(id)!.candidate;
			device.store.close();
			const inode = statSync(device.file).ino;
			const target = new Database(device.file);
			try {
				target.exec(
					"CREATE TABLE unrelated_data (value TEXT); INSERT INTO unrelated_data VALUES ('after backup')"
				);
				target
					.prepare('DELETE FROM final_opening_candidates WHERE channel_id=?')
					.run(id);
				target
					.prepare('DELETE FROM channel_key_indices WHERE channel_id=?')
					.run(id);
				target
					.prepare('DELETE FROM final_lifecycle_log WHERE channel_id=?')
					.run(id);
			} finally {
				target.close();
			}
			const restore = () =>
				performAssetChannelRestore(
					frame,
					device.file,
					join(dir, 'restore.lock'),
					device.party.binding,
					id,
					mac
				);
			const result = await restore();
			assert.equal(result.channelId, id);
			assert.equal(result.openingRestored, true);
			assert.equal(result.currentSequence, expected.sequence);
			assert.equal(result.snapshotSequence, side ? expected.sequence : 0);
			assert.equal((await restore()).openingRestored, false);
			assert.equal(statSync(device.file).ino, inode);
			device.store = SqliteStorage.openFinalWallet(
				device.file,
				device.party.binding
			);
			assert.deepEqual(
				device.store.loadFinalDaemonOpening(id)!.candidate,
				expectedOpening
			);
			assert.deepEqual(device.store.readAssetSpliceJournal(id), expected);
			assert.equal(
				device.store.loadAssetSpliceFundingInfo(id).active?.candidate
					.fundingTxid,
				txid
			);
			assert.deepEqual(
				device.store['db'].prepare('SELECT * FROM unrelated_data').all(),
				[{ value: 'after backup' }]
			);
		}
	});

	it('refuses unauthenticated frames, a busy wallet, a frame from another wallet and a copied destination', async () => {
		const { devices, id } = pair.f;
		const [local, other] = devices;
		const frame = join(dir, 'frame.db'),
			copy = join(dir, 'copy.db');
		const foreign = join(dir, 'foreign.db'),
			lock = join(dir, 'restore.lock');
		await local.store.backup(frame);
		await local.store.backup(copy);
		await other.store.backup(foreign);
		await writeBackupMac(mac, foreign);
		local.store.close();
		const attempt = (source = frame, target = local.file) =>
			performAssetChannelRestore(
				source,
				target,
				lock,
				local.party.binding,
				id,
				mac
			);
		await assert.rejects(attempt(), /MAC|authenticated/i);
		await writeBackupMac(Buffer.alloc(32, 83), frame);
		await assert.rejects(attempt(), /MAC|authenticated/i);
		await writeBackupMac(mac, frame);
		acquireInstanceLock(lock);
		try {
			await assert.rejects(attempt(), /lock|running/i);
		} finally {
			releaseInstanceLock(lock);
		}
		await assert.rejects(attempt(foreign), /lineage|binding|wallet|identity/i);
		await assert.rejects(attempt(frame, copy), /original|device/i);
		local.store = SqliteStorage.openFinalWallet(
			local.file,
			local.party.binding
		);
		assert(local.store.loadFinalDaemonOpening(id));
	});
});
