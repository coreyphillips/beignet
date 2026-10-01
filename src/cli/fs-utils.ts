/**
 * File permission helpers for the secrets the CLI keeps on disk (issue #1004).
 *
 * ~/.beignet/config.json holds the wallet mnemonic and the API token, the data
 * directory holds the seed-encrypted database whose lookup columns (payment
 * hashes, channel ids, peer pubkeys, gossip) are plaintext, and the backups
 * and SCB exports are copies of it. Node's defaults create all of these under
 * the process umask, so on a typical 022 host every other local account could
 * read the seed. Everything here is owner-only: 0700 directories and 0600
 * files, set explicitly rather than trusted to the umask, and tightened after
 * the fact for anything an older release left readable.
 *
 * POSIX modes mean nothing on Windows, where ACLs govern access, so every
 * helper is a no-op there. A chmod can also fail on a read-only or foreign
 * filesystem (a bind mount, a network share); that is reported, never thrown,
 * so a permissions problem can never stop a node from starting.
 */

import * as fs from 'fs';

/** Owner read/write only: the mode for every file that holds secrets. */
export const SECRET_FILE_MODE = 0o600;
/** Owner only: the mode for every directory that holds such files. */
export const SECRET_DIR_MODE = 0o700;

/** True where POSIX permission bits govern access. */
export function fileModesApply(): boolean {
	return process.platform !== 'win32';
}

export interface ITightenResult {
	/** True when the path was looser than asked and the chmod succeeded. */
	changed: boolean;
	/** The permission bits found, when they were looser than asked. */
	previous?: number;
	/** Set when the path was looser than asked and the chmod failed. */
	error?: Error;
}

/**
 * Remove every permission bit outside `mode` from an existing path. A path
 * that is missing or already within `mode` is left alone and reported as
 * unchanged; a chmod failure is returned, never thrown, so the caller decides
 * whether the operator hears about it.
 */
export function tightenMode(filePath: string, mode: number): ITightenResult {
	if (!fileModesApply()) return { changed: false };
	let current: number;
	try {
		current = fs.statSync(filePath).mode & 0o777;
	} catch {
		return { changed: false };
	}
	if ((current & ~mode) === 0) return { changed: false };
	try {
		fs.chmodSync(filePath, mode);
		return { changed: true, previous: current };
	} catch (err) {
		return { changed: false, previous: current, error: err as Error };
	}
}

/**
 * Create `dir` (and any missing parent) owner-only, and tighten it when it
 * already existed: mkdir never changes the bits of a directory that is
 * already there, and one created by an earlier release under umask 022 is
 * 0755. Returns the tightening result so a caller with a logger can warn when
 * the chmod was refused.
 */
export function ensurePrivateDir(dir: string): ITightenResult {
	fs.mkdirSync(dir, { recursive: true, mode: SECRET_DIR_MODE });
	return tightenMode(dir, SECRET_DIR_MODE);
}

/**
 * Write through a temp file and rename, so a crash never leaves a torn file,
 * with an explicit mode. writeFileSync's own `mode` only applies to a file it
 * creates (rewriting an existing 0644 file leaves it 0644) and is masked by
 * the umask even then, so the temp file is chmod'ed before it takes the
 * target's place. The chmod is best effort for the same reason as
 * tightenMode: the content must land even where the filesystem ignores modes.
 */
export function writeFileAtomic(
	filePath: string,
	content: string,
	mode: number = SECRET_FILE_MODE
): void {
	const tmp = `${filePath}.tmp`;
	fs.writeFileSync(tmp, content, { mode });
	if (fileModesApply()) {
		try {
			fs.chmodSync(tmp, mode);
		} catch {
			// A filesystem without permission bits; the file is still written.
		}
	}
	fs.renameSync(tmp, filePath);
}
