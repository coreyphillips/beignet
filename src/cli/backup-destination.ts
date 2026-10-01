/**
 * Where POST /backup may write (issue #1230).
 *
 * SQLite's backup API writes a database over whatever it is pointed at when
 * that file is empty or already a SQLite database: a previous backup, another
 * wallet's database, this node's live database, or its WAL after a truncating
 * checkpoint. So the destination is canonicalized first (symlinks resolved,
 * the stored case on a case-insensitive filesystem), the daemon's own files
 * are refused outright, and any other existing file needs an explicit
 * overwrite.
 */

import * as fs from 'fs';
import * as path from 'path';
import { backupMacPath } from './backup-mac';

export type BackupDestination = { path: string } | { refusal: string };

/**
 * The absolute path with every symlink resolved. A file that does not exist
 * yet keeps its name under its directory's canonical path; that directory
 * must exist, or this throws.
 */
function canonicalPath(p: string): string {
	const resolved = path.resolve(p);
	try {
		return fs.realpathSync.native(resolved);
	} catch {
		return path.join(
			fs.realpathSync.native(path.dirname(resolved)),
			path.basename(resolved)
		);
	}
}

/**
 * The canonical path to hand to the backup, or why it is refused.
 * `protectedPaths` are refused even with `overwrite`.
 */
export function resolveBackupDestination(
	destPath: string,
	protectedPaths: string[],
	overwrite: boolean
): BackupDestination {
	let target: string;
	try {
		target = canonicalPath(destPath);
	} catch {
		return {
			refusal: `Backup directory does not exist: ${path.dirname(
				path.resolve(destPath)
			)}`
		};
	}
	// The backup driver trims filenames before opening them.
	if (target !== target.trim()) {
		return { refusal: 'Backup filename must not start or end with whitespace' };
	}
	const stat = fs.statSync(target, { throwIfNoEntry: false });
	// A dangling symlink: SQLite would create whatever it points at.
	if (!stat && fs.lstatSync(target, { throwIfNoEntry: false })) {
		return { refusal: `destPath is a broken symlink: ${target}` };
	}
	for (const p of protectedPaths) {
		let own: string;
		try {
			own = canonicalPath(p);
		} catch {
			own = path.resolve(p);
		}
		if (own === target) {
			return { refusal: `Refusing to overwrite a daemon file: ${target}` };
		}
	}
	if (stat && !stat.isFile()) {
		return { refusal: `destPath is not a regular file: ${target}` };
	}
	if (stat && !overwrite) {
		return {
			refusal: `destPath already exists: ${target}. Pass overwrite: true to replace it`
		};
	}
	// The backup's MAC is written beside it and gets the same rule.
	const macPath = backupMacPath(target);
	const macStat = fs.lstatSync(macPath, { throwIfNoEntry: false });
	if (macStat && !macStat.isFile()) {
		return { refusal: `MAC path is not a regular file: ${macPath}` };
	}
	if (macStat && !overwrite) {
		return {
			refusal: `MAC path already exists: ${macPath}. Pass overwrite: true to replace it`
		};
	}
	return { path: target };
}
