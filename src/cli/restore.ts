/**
 * Offline database restore for the CLI (`beignet restore db <file>`).
 *
 * This is a LOCAL file operation, not a daemon call: the node must be stopped,
 * because copying a database under a live SQLite writer corrupts it. The
 * daemon-not-running guarantee comes from holding the same single-instance
 * lock BeignetNode acquires at startup for the whole copy, so a daemon can
 * neither be running nor start mid-restore.
 *
 * The database is encrypted at rest under a seed-derived key, so a restored
 * file is only readable by a node running with the same mnemonic. That key
 * gives no integrity (plaintext rows are accepted), so the backup must also
 * carry a MAC under the same seed (see backup-mac.ts).
 *
 * The MAC proves the backup is ours, not that it is current, so the channels
 * it brings back are held on the next boot (holdDbRestoredChannels).
 */

import { timingSafeEqual } from 'crypto';
import * as fs from 'fs';
import { acquireInstanceLock, releaseInstanceLock } from './instance-lock';
import { SECRET_FILE_MODE, tightenMode, writeFileAtomic } from './fs-utils';
import { backupMacPath, fileMac, readBackupMac } from './backup-mac';
import { ChannelState } from '../lightning/channel/types';
import { IStorageBackend } from '../lightning/storage/types';

/** First 16 bytes of every SQLite 3 database file. */
export const SQLITE_HEADER = Buffer.from('SQLite format 3\0', 'ascii');

/**
 * True when the file starts with the 16-byte SQLite 3 header. Guards against
 * restoring an SCB blob, a truncated copy, or an arbitrary file over the DB.
 */
export function isSqliteFile(filePath: string): boolean {
	let fd: number;
	try {
		fd = fs.openSync(filePath, 'r');
	} catch {
		return false;
	}
	try {
		const header = Buffer.alloc(SQLITE_HEADER.length);
		const read = fs.readSync(fd, header, 0, header.length, 0);
		return read === SQLITE_HEADER.length && header.equals(SQLITE_HEADER);
	} finally {
		fs.closeSync(fd);
	}
}

/** Safety-copy path for the database being overwritten by a restore. */
export function preRestoreBackupPath(
	dbPath: string,
	now: number = Date.now()
): string {
	return `${dbPath}.pre-restore-${now}`;
}

/**
 * Marker a restore leaves beside the database for the next boot. Its
 * presence is the signal; the contents are only reported.
 */
export function dbRestoreMarkerPath(dbPath: string): string {
	return `${dbPath}.restored`;
}

export interface IDbRestoreOptions {
	/** The wallet's backup MAC key (deriveBackupMacKey). */
	macKey: Buffer;
	/**
	 * Accept a backup with no MAC file, as made before backups were
	 * authenticated. A MAC file that is present must still match.
	 */
	allowUnauthenticated?: boolean;
	now?: number;
}

export interface IDbRestoreResult {
	dbPath: string;
	/** Where the pre-existing database was preserved; null if none existed. */
	preRestorePath: string | null;
	/** False only for a backup restored without a MAC. */
	authenticated: boolean;
}

/**
 * Copy an authenticated SQLite backup over the node's database file.
 *
 * The backup is copied next to the database and checked there, so the bytes
 * that are verified are the bytes that go live. Never destroys data: an
 * existing database (and its -wal/-shm sidecars, which belong to the OLD file
 * and would corrupt the restored one if left behind) is moved to a
 * pre-restore path first, and any failure throws before the live path is
 * touched.
 */
export async function restoreDbFile(
	backupFile: string,
	dbPath: string,
	opts: IDbRestoreOptions
): Promise<IDbRestoreResult> {
	const now = opts.now ?? Date.now();
	if (!fs.existsSync(backupFile)) {
		throw new Error(`Backup file not found: ${backupFile}`);
	}
	const expectedMac = readBackupMac(backupFile);
	if (!expectedMac && !opts.allowUnauthenticated) {
		throw new Error(
			`Backup is not authenticated: ${backupMacPath(backupFile)} not found. ` +
				'Backups made before this release have no MAC; restore one only if ' +
				'you are sure it was not modified, with --unauthenticated.'
		);
	}

	// Every copy made here is owner-only (issue #1004): copyFileSync gives the
	// destination the SOURCE's bits, so a backup an operator saved as 0644
	// would otherwise become a 0644 live database, and the pre-restore copy
	// keeps whatever an older release left on the file it came from.
	const staged = `${dbPath}.restoring`;
	fs.copyFileSync(backupFile, staged);
	tightenMode(staged, SECRET_FILE_MODE);
	const markerPath = dbRestoreMarkerPath(dbPath);
	let markerWritten = false;
	let preRestorePath: string | null = null;
	try {
		if (!isSqliteFile(staged)) {
			throw new Error(
				`Not a SQLite database (missing 'SQLite format 3' header): ${backupFile}`
			);
		}
		if (
			expectedMac &&
			!timingSafeEqual(await fileMac(opts.macKey, staged), expectedMac)
		) {
			throw new Error(
				`Backup MAC does not match: ${backupFile} was modified after it ` +
					'was made, or was made by a different wallet.'
			);
		}

		if (fs.existsSync(dbPath)) {
			preRestorePath = preRestoreBackupPath(dbPath, now);
			fs.copyFileSync(dbPath, preRestorePath);
			tightenMode(preRestorePath, SECRET_FILE_MODE);
		}
		// A marker write failure must leave the live WAL intact.
		// A marker already here belongs to an earlier restore that has not booted
		// yet, and its database is still the live one if this swap fails.
		const markerPending = fs.existsSync(markerPath);
		writeFileAtomic(
			markerPath,
			JSON.stringify({
				version: 1,
				restoredAt: now,
				backupFile,
				authenticated: expectedMac !== null
			})
		);
		markerWritten = !markerPending;
		// Stale WAL/SHM sidecars pair with the OLD database; replayed against the
		// restored file they corrupt it. Preserve them next to the pre-restore copy.
		for (const suffix of ['-wal', '-shm']) {
			const sidecar = `${dbPath}${suffix}`;
			if (fs.existsSync(sidecar)) {
				if (preRestorePath) {
					fs.renameSync(sidecar, `${preRestorePath}${suffix}`);
					tightenMode(`${preRestorePath}${suffix}`, SECRET_FILE_MODE);
				} else {
					fs.unlinkSync(sidecar);
				}
			}
		}
		fs.renameSync(staged, dbPath);
	} catch (err) {
		fs.rmSync(staged, { force: true });
		if (markerWritten) fs.rmSync(markerPath, { force: true });
		throw err;
	}
	return { dbPath, preRestorePath, authenticated: expectedMac !== null };
}

/**
 * Perform the offline DB restore while holding the wallet's single-instance
 * lock. Throws InstanceLockError when a live daemon holds the lock, so a
 * running node is never overwritten. Unlike daemon startup this stays
 * fail-closed on a lock recorded under another hostname (e.g. restore run
 * from the host against a container's data dir): liveness cannot be verified
 * from here, so the lock is refused rather than reclaimed.
 */
export async function performDbRestore(
	backupFile: string,
	dbPath: string,
	lockPath: string,
	opts: IDbRestoreOptions
): Promise<IDbRestoreResult> {
	acquireInstanceLock(lockPath);
	try {
		return await restoreDbFile(backupFile, dbPath, opts);
	} finally {
		releaseInstanceLock(lockPath);
	}
}

export interface IDbRestoreHold {
	/** Channels the hold was applied to. */
	held: number;
	/** When the restore ran, if the marker could be read. */
	restoredAt: number | null;
	/** False when unreadable rows kept the marker for the next boot. */
	markerCleared: boolean;
}

/**
 * On the first boot after a `restore db`, put every channel it brought back
 * under the recency hold a capsule restore gets (restoreRecencyUnproven).
 * Returns null when no restore is pending.
 *
 * A backup is a checkpoint, so its latest commitment may already be revoked
 * in the peer's view, and a peer can under-report compatible reestablish
 * counters while holding a newer state. The hold stops every broadcast of our
 * commitment the node would make on its own (HTLC deadline and error-driven
 * closes) and takes no new HTLCs, while the channel still resumes. Not
 * stateUncertain, which would have every peer force-close on reconnect even
 * when the backup was current.
 *
 * The marker is cleared only once every row decoded: a row this key cannot
 * read (a wrong mnemonic, say) would otherwise load unheld on a later boot.
 */
export function holdDbRestoredChannels(
	dbPath: string,
	storage: IStorageBackend
): IDbRestoreHold | null {
	const markerPath = dbRestoreMarkerPath(dbPath);
	if (!fs.existsSync(markerPath)) return null;
	let restoredAt: number | null = null;
	try {
		const marker = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
		if (typeof marker?.restoredAt === 'number') restoredAt = marker.restoredAt;
	} catch {
		// Presence alone requires the hold.
	}
	const corruptBefore = storage.corruptRowCount?.() ?? 0;
	let held = 0;
	for (const row of storage.loadAllChannels()) {
		// Terminal rows never reestablish and have nothing left to broadcast.
		if (
			row.state.state === ChannelState.CLOSED ||
			row.state.state === ChannelState.FORCE_CLOSED
		) {
			continue;
		}
		row.state.restoreRecencyUnproven = true;
		storage.saveChannel(row.channelId, row.state, row.peerPubkey);
		held++;
	}
	const markerCleared = (storage.corruptRowCount?.() ?? 0) === corruptBefore;
	if (markerCleared) fs.unlinkSync(markerPath);
	return { held, restoredAt, markerCleared };
}
