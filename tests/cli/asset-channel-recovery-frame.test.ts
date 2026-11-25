import { strict as assert } from 'assert';
import { randomBytes } from 'crypto';
import {
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	lstatSync,
	writeFileSync
} from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import Database from 'better-sqlite3';
import { BeignetNode } from '../../src/cli/beignet-node';
import { deriveBackupMacKey } from '../../src/cli/backup-mac';
import {
	decodeFrame,
	encodeFrame,
	hashFrame
} from '../../src/lightning/recovery/frame-codec';
import {
	decryptFrame,
	deriveFrameKey,
	encryptFrame,
	frameAad
} from '../../src/lightning/recovery/journal';
import { hkdfKey } from '../../src/lightning/storage/encryption';
import {
	acquireInstanceLock,
	releaseInstanceLock
} from '../../src/cli/instance-lock';
import { performAssetChannelRestore } from '../../src/cli/restore';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSplicePeerTransport } from '../lightning/helpers/asset-splice-peer-transport';

type Device = ReturnType<
	typeof setupAssetSplicePeerTransport
>['f']['devices'][number];

function exportFrame(device: Device, id: string, path: string): Promise<void> {
	const sdk = Object.create(BeignetNode.prototype) as BeignetNode;
	Object.assign(sdk, {
		sqlite: () => device.store,
		walletSeed: () => device.seed
	});
	return sdk.backupAssetChannelFrame(id, path);
}

/** Read through the common codec and cryptographic primitives independently of the exporter. */
function inspectFrame(path: string, id: string, device: Device) {
	const bytes = readFileSync(path);
	assert.deepEqual(bytes.subarray(0, 8), Buffer.from('BGNACRF1'));
	const sequence = bytes.readBigUInt64BE(8),
		previous = bytes.subarray(16, 48),
		hash = bytes.subarray(48, 80),
		channel = Buffer.from(id, 'hex');
	const master = hkdfKey(
		deriveBackupMacKey(device.seed),
		'beignet-original-asset-channel-frame-v1'
	);
	const plaintext = decryptFrame(
		deriveFrameKey(master, channel, 1n),
		bytes.subarray(80),
		frameAad(channel, 1n, sequence, previous)
	);
	assert(hashFrame(plaintext).equals(hash));
	// The generic guardian restore path must not admit an original-device frame.
	assert.throws(() => decodeFrame(plaintext));
	const frame = decodeFrame(plaintext, { originalDevice: true });
	assert.equal(frame.version, 6);
	assert.equal(frame.writerEpoch, 1n);
	assert.equal(frame.sequence, sequence);
	assert.deepEqual(frame.previousFrameHash, previous);
	assert.equal(frame.durability, 'local');
	assert.deepEqual(frame.mutations, []);
	assert.deepEqual(frame.outboundMessages, []);
	assert.equal(frame.snapshot, undefined);
	const section = frame.originalDeviceChannel;
	assert(section);
	assert.deepEqual(
		Object.keys(section).sort(),
		[
			'channelId',
			'channelIndex',
			'fundingOutpoint',
			'openingNonces',
			'openingRecord',
			'spliceHash',
			'spliceSequence'
		].sort()
	);
	assert.equal(section.channelId, id);
	assert(!plaintext.includes(device.seed.toString('hex')));
	return { sequence, previous, hash, section, frame };
}

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

function channelRows(file: string, id: string): unknown[][] {
	const db = new Database(file, { readonly: true });
	try {
		return [
			'channel_key_indices',
			'final_lifecycle_log',
			'final_opening_candidates'
		].map((table) =>
			db
				.prepare(
					'SELECT * FROM ' + table + ' WHERE channel_id=? ORDER BY rowid'
				)
				.all(id)
		);
	} finally {
		db.close();
	}
}

describe('Original-device asset channel RecoveryFrame files', function () {
	this.timeout(90000);
	const unrelated = '78'.repeat(32);
	let dir: string, pair: ReturnType<typeof setupAssetSplicePeerTransport>;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'asset-splice-recovery-frame-'));
		pair = setupAssetSplicePeerTransport(dir, undefined, 5);
	});
	afterEach(() => {
		pair.close();
		rmSync(dir, { recursive: true, force: true });
	});

	it('recovers both live devices from a channel frame taken before or after the splice', async () => {
		const { devices, id } = pair.f;
		const files = [join(dir, 'early.frame'), join(dir, 'late.frame')];
		for (const d of devices)
			d.store['db']
				.prepare('INSERT INTO channel_key_indices VALUES (?, ?)')
				.run(unrelated, 0);
		await exportFrame(devices[0], id, files[0]);
		const early = inspectFrame(files[0], id, devices[0]);
		assert.equal(early.sequence, 1n);
		assert.deepEqual(early.previous, Buffer.alloc(32));
		assert.equal(early.section.spliceSequence, 0);
		const firstPeer = join(dir, 'first-peer.frame');
		await exportFrame(devices[1], id, firstPeer);
		const initialPeer = inspectFrame(firstPeer, id, devices[1]);
		await pair.start();
		await pair.drain();
		const txid = await pair.adopt();
		await exportFrame(devices[1], id, files[1]);
		const late = inspectFrame(files[1], id, devices[1]);
		assert.equal(late.sequence, initialPeer.sequence + 1n);
		assert.deepEqual(late.previous, initialPeer.hash);
		assert.equal(
			late.section.spliceSequence,
			devices[1].store.readAssetSpliceJournal(id).sequence
		);
		for (const [i, d] of devices.entries()) {
			const journal = d.store.readAssetSpliceJournal(id);
			const opening = d.store.loadFinalDaemonOpening(id)!.candidate;
			assert(journal.sequence > 0);
			assert.equal(statSync(files[i]).mode & 0o777, 0o600);
			assert(
				!readFileSync(files[i])
					.subarray(0, 16)
					.equals(Buffer.from('SQLite format 3\0'))
			);
			d.store['db']
				.prepare(
					'UPDATE channel_key_indices SET channel_index=103 WHERE channel_id=?'
				)
				.run(unrelated);
			d.store.close();
			removeChannelRows(d, id);
			const ino = statSync(d.file).ino;
			const restore = () =>
				performAssetChannelRestore(
					files[i],
					d.file,
					join(dir, 'restore.lock'),
					d.party.binding,
					id,
					deriveBackupMacKey(d.seed)
				);
			const result = await restore();
			assert.equal(result.channelId, id);
			assert.equal(result.openingRestored, true);
			assert('frameSequence' in result);
			assert.equal(
				result.frameSequence,
				i ? Number(late.sequence) : Number(early.sequence)
			);
			assert.equal(result.snapshotSequence, i ? journal.sequence : 0);
			assert.equal(result.currentSequence, journal.sequence);
			assert.equal((await restore()).openingRestored, false);
			assert.equal(statSync(d.file).ino, ino);
			d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
			assert.deepEqual(d.store.loadFinalDaemonOpening(id)!.candidate, opening);
			assert.deepEqual(d.store.readAssetSpliceJournal(id), journal);
			assert.equal(
				d.store.loadAssetSpliceFundingInfo(id).active?.candidate.fundingTxid,
				txid
			);
			assert.deepEqual(
				d.store['db']
					.prepare(
						'SELECT channel_index FROM channel_key_indices WHERE channel_id=?'
					)
					.get(unrelated),
				{ channel_index: 103 }
			);
		}
	});

	it('creates only fresh frame files and preserves the enrolled database and signer', async () => {
		const {
			id,
			devices: [local]
		} = pair.f;
		const path = join(dir, 'kept.frame'),
			alias = join(dir, 'alias.frame');
		await exportFrame(local, id, path);
		const original = readFileSync(path);
		const inode = statSync(local.file).ino;
		symlinkSync(path, alias);
		for (const destination of [
			path,
			alias,
			local.file,
			local.file + '.opening-signer'
		])
			await assert.rejects(exportFrame(local, id, destination));
		assert(lstatSync(alias).isSymbolicLink());
		assert.equal(statSync(local.file).ino, inode);
		assert.deepEqual(readFileSync(path), original);
		assert(local.store.loadFinalDaemonOpening(id));
	});

	it('rejects tampered bytes, wrong channel or device, a copied database, and active instance locks before repair', async () => {
		const { devices, id } = pair.f,
			[local, peer] = devices;
		const original = join(dir, 'original.frame'),
			damaged = join(dir, 'damaged.frame'),
			copy = join(dir, 'copied.db'),
			lock = join(dir, 'restore.lock');
		await exportFrame(local, id, original);
		const next = join(dir, 'next.frame');
		await pair.start();
		await pair.drain();
		await pair.adopt();
		await exportFrame(local, id, next);
		const prior = inspectFrame(original, id, local),
			later = inspectFrame(next, id, local);
		assert(later.section.spliceSequence > prior.section.spliceSequence);
		const key = deriveFrameKey(
			hkdfKey(
				deriveBackupMacKey(local.seed),
				'beignet-original-asset-channel-frame-v1'
			),
			Buffer.from(id, 'hex'),
			1n
		);
		const prefix = join(dir, 'unrecorded-prefix.frame'),
			link = join(dir, 'unrecorded-link.frame');
		for (const file of [prefix, link]) {
			// An intact GCM envelope under the correct fixture key still needs
			// the exact canonical hash issued by this device at this sequence.
			const previous = file === link ? Buffer.alloc(32, 0x35) : later.previous;
			const text = encodeFrame({
				...later.frame,
				previousFrameHash: previous,
				originalDeviceChannel:
					file === prefix
						? {
								...later.section,
								spliceHash: prior.section.spliceHash,
								spliceSequence: prior.section.spliceSequence
						  }
						: later.section
			});
			assert.doesNotThrow(() => decodeFrame(text, { originalDevice: true }));
			const seq = Buffer.alloc(8);
			seq.writeBigUInt64BE(later.sequence);
			const sealed = encryptFrame(
				key,
				text,
				frameAad(Buffer.from(id, 'hex'), 1n, later.sequence, previous),
				randomBytes(12)
			);
			writeFileSync(
				file,
				Buffer.concat([
					Buffer.from('BGNACRF1'),
					seq,
					previous,
					hashFrame(text),
					sealed
				])
			);
		}
		const encoded = readFileSync(original);
		const second = readFileSync(next);
		const reordered = join(dir, 'reordered.frame');
		writeFileSync(
			reordered,
			Buffer.concat([second.subarray(0, 80), encoded.subarray(80)])
		);
		const truncated = join(dir, 'truncated.frame');
		writeFileSync(truncated, encoded.subarray(0, -1));
		const corrupt = Buffer.from(encoded);
		corrupt[Math.floor(corrupt.length / 2)] ^= 8;
		writeFileSync(damaged, corrupt);
		await local.store.backup(copy);
		local.store.close();
		peer.store.close();
		removeChannelRows(local, id);
		removeChannelRows(peer, id);
		const empty = channelRows(local.file, id);
		assert.deepEqual(empty, [[], [], []]);
		const restore = (
			file = original,
			device = local,
			channel = id,
			destination = device.file,
			backupMacKey = deriveBackupMacKey(device.seed)
		) =>
			performAssetChannelRestore(
				file,
				destination,
				lock,
				device.party.binding,
				channel,
				backupMacKey
			);
		for (const file of [damaged, reordered, truncated, prefix, link]) {
			await assert.rejects(restore(file));
			assert.deepEqual(channelRows(local.file, id), empty);
		}
		assert.deepEqual(channelRows(local.file, id), empty);
		await assert.rejects(restore(original, local, unrelated));
		await assert.rejects(
			performAssetChannelRestore(
				original,
				local.file,
				lock,
				{
					...local.party.binding,
					assetSpliceRecovery: undefined,
					assetSplice: true
				},
				id,
				deriveBackupMacKey(local.seed)
			)
		);
		await assert.rejects(restore(original, peer));
		// Give the destination the exporting wallet's outer key as well. Its original
		// device anchor must still independently reject the other wallet and the copy.
		await assert.rejects(
			restore(original, peer, id, peer.file, deriveBackupMacKey(local.seed))
		);
		await assert.rejects(restore(original, local, id, copy));
		acquireInstanceLock(lock);
		try {
			await assert.rejects(restore(), /lock|running/i);
		} finally {
			releaseInstanceLock(lock);
		}
		assert.deepEqual(channelRows(local.file, id), empty);
		assert.deepEqual(channelRows(peer.file, id), empty);
	});
});
