/**
 * #2151 step 1, item 10: an asset channel of a generation 6 wallet restores
 * from a snapshot (withAssetChannelRepair) and from a recovery frame
 * (repairAssetChannelFrame) as a generation 5 one does, and a plain channel
 * of the same wallet is refused by that restore (Step 7 restores by type).
 * Uses only names that exist on the base.
 */
import { strict as assert } from 'assert';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { deriveBackupMacKey, writeBackupMac } from '../../src/cli/backup-mac';
import { performAssetChannelRestore } from '../../src/cli/restore';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSplicePeerTransport } from '../lightning/helpers/asset-splice-peer-transport';
import { boundParticipant } from '../lightning/helpers/final-opening-signing';
import { fundReadyPair } from '../lightning/helpers/final-update-pair';

type Pair = ReturnType<typeof setupAssetSplicePeerTransport>;
type Device = Pair['f']['devices'][number];

function removeChannelRows(device: Device, id: string): void {
	const db = new Database(device.file);
	try {
		db.transaction(() => {
			for (const table of [
				'channel_key_indices',
				'final_lifecycle_log',
				'final_opening_candidates'
			])
				db.prepare('DELETE FROM ' + table + ' WHERE channel_id=?').run(id);
		})();
	} finally {
		db.close();
	}
}

describe('Asset channel restore in a generation 6 wallet (#2151 step 1, item 10)', function () {
	this.timeout(120000);
	let dir: string, pair: Pair | undefined;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'asset-conversion-restore-'));
		pair = undefined;
	});
	afterEach(() => {
		pair?.close();
		rmSync(dir, { recursive: true, force: true });
	});

	async function splicedPair(): Promise<{ spliced: Pair; txid: string }> {
		pair = setupAssetSplicePeerTransport(dir, undefined, 6);
		assert.equal(pair.f.devices[0].store.canUpdateFinalCommitments, true);
		await pair.start();
		await pair.drain();
		return { spliced: pair, txid: await pair.adopt() };
	}

	it('restores the asset channel from a snapshot and from a recovery frame', async () => {
		const { spliced, txid } = await splicedPair();
		const { devices, id } = spliced.f;
		const snapshot = join(dir, 'snapshot.db'),
			frame = join(dir, 'late.frame');
		const mac = Buffer.alloc(32, 79);
		await devices[0].store.backup(snapshot);
		await writeBackupMac(mac, snapshot);
		const sdk = Object.create(BeignetNode.prototype) as BeignetNode;
		Object.assign(sdk, {
			sqlite: () => devices[1].store,
			walletSeed: () => devices[1].seed
		});
		await sdk.backupAssetChannelFrame(id, frame);
		const sources = [
			{ file: snapshot, mac },
			{ file: frame, mac: deriveBackupMacKey(devices[1].seed) }
		];
		for (const [side, device] of devices.entries()) {
			const journal = device.store.readAssetSpliceJournal(id);
			const opening = device.store.loadFinalDaemonOpening(id)!.candidate;
			device.store.close();
			removeChannelRows(device, id);
			const restore = () =>
				performAssetChannelRestore(
					sources[side].file,
					device.file,
					join(dir, 'restore.lock'),
					device.party.binding,
					id,
					sources[side].mac
				);
			const result = await restore();
			assert.equal(result.channelId, id);
			assert.equal(result.openingRestored, true);
			assert.equal(result.currentSequence, journal.sequence);
			assert.equal((await restore()).openingRestored, false);
			device.store = SqliteStorage.openFinalWallet(
				device.file,
				device.party.binding
			);
			assert.deepEqual(
				device.store.loadFinalDaemonOpening(id)!.candidate,
				opening
			);
			assert.deepEqual(device.store.readAssetSpliceJournal(id), journal);
			assert.equal(
				device.store.loadAssetSpliceFundingInfo(id).active?.candidate
					.fundingTxid,
				txid
			);
		}
	});

	it('refuses to restore a plain channel of the same wallet through the asset channel restore', async () => {
		const { spliced } = await splicedPair();
		const { devices } = spliced.f;
		// The splice took key index 2 at start; the plain channel takes 3.
		const sides = devices.map((d) =>
			boundParticipant(d.party.root, 3, d.party.binding)
		);
		const plainId = fundReadyPair(
			devices[0].store,
			devices[1].store,
			sides[0],
			sides[1]
		);
		const snapshot = join(dir, 'plain.db');
		const mac = Buffer.alloc(32, 79);
		await devices[0].store.backup(snapshot);
		await writeBackupMac(mac, snapshot);
		devices[0].store.close();
		removeChannelRows(devices[0], plainId);
		await assert.rejects(
			performAssetChannelRestore(
				snapshot,
				devices[0].file,
				join(dir, 'restore.lock'),
				devices[0].party.binding,
				plainId,
				mac
			)
		);
		// The device still holds the plain channel's authorized exit, so the
		// wallet without its rows is refused at open; read the rows directly.
		const db = new Database(devices[0].file, { readonly: true });
		try {
			const opening = (id: string) =>
				!!db
					.prepare('SELECT 1 FROM final_opening_candidates WHERE channel_id=?')
					.get(id);
			assert.equal(opening(plainId), false);
			assert.equal(opening(spliced.f.id), true);
		} finally {
			db.close();
		}
	});
});
