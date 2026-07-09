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
 * file is only readable by a node running with the same mnemonic.
 */

import * as fs from 'fs';
import { acquireInstanceLock, releaseInstanceLock } from './instance-lock';

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

export interface IDbRestoreResult {
	dbPath: string;
	/** Where the pre-existing database was preserved; null if none existed. */
	preRestorePath: string | null;
}

/**
 * Copy a validated SQLite backup over the node's database file.
 *
 * Never destroys data: an existing database (and its -wal/-shm sidecars,
 * which belong to the OLD file and would corrupt the restored one if left
 * behind) is moved to a pre-restore path first, and any failure throws before
 * the copy touches the live path.
 */
export function restoreDbFile(
	backupFile: string,
	dbPath: string,
	now: number = Date.now()
): IDbRestoreResult {
	if (!fs.existsSync(backupFile)) {
		throw new Error(`Backup file not found: ${backupFile}`);
	}
	if (!isSqliteFile(backupFile)) {
		throw new Error(
			`Not a SQLite database (missing 'SQLite format 3' header): ${backupFile}`
		);
	}

	let preRestorePath: string | null = null;
	if (fs.existsSync(dbPath)) {
		preRestorePath = preRestoreBackupPath(dbPath, now);
		fs.copyFileSync(dbPath, preRestorePath);
	}
	// Stale WAL/SHM sidecars pair with the OLD database; replayed against the
	// restored file they corrupt it. Preserve them next to the pre-restore copy.
	for (const suffix of ['-wal', '-shm']) {
		const sidecar = `${dbPath}${suffix}`;
		if (fs.existsSync(sidecar)) {
			if (preRestorePath) {
				fs.renameSync(sidecar, `${preRestorePath}${suffix}`);
			} else {
				fs.unlinkSync(sidecar);
			}
		}
	}
	fs.copyFileSync(backupFile, dbPath);
	return { dbPath, preRestorePath };
}

/**
 * Perform the offline DB restore while holding the wallet's single-instance
 * lock. Throws InstanceLockError when a live daemon holds the lock (the same
 * check BeignetNode.create performs), so a running node is never overwritten.
 */
export function performDbRestore(
	backupFile: string,
	dbPath: string,
	lockPath: string,
	now: number = Date.now()
): IDbRestoreResult {
	acquireInstanceLock(lockPath);
	try {
		return restoreDbFile(backupFile, dbPath, now);
	} finally {
		releaseInstanceLock(lockPath);
	}
}
