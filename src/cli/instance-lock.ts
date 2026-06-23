/**
 * Single-instance lock for a wallet's data directory.
 *
 * Running two beignet instances on the same data dir is unsafe: they share one
 * node identity (so the peer keeps only one connection and churns the other,
 * producing a connect/disconnect storm) and one SQLite database (concurrent
 * writers risk corruption). This lock makes a second instance fail fast with a
 * clear error instead.
 *
 * The lock is a small JSON file created atomically with the `wx` (exclusive
 * create) flag. If the file already exists we check whether the recorded PID is
 * still alive: a live holder means "already running"; a dead holder means a
 * stale lock from a crashed run, which we reclaim. Hard kills (SIGKILL) leave a
 * stale lock, but the next start detects it via the liveness check — so no
 * manual cleanup is ever required.
 */

import * as fs from 'fs';
import * as os from 'os';

export interface ILockInfo {
	pid: number;
	hostname: string;
	createdAt: number;
}

/** Raised when another live instance already holds the lock. */
export class InstanceLockError extends Error {
	readonly holder: ILockInfo | null;
	constructor(message: string, holder: ILockInfo | null) {
		super(message);
		this.name = 'InstanceLockError';
		this.holder = holder;
	}
}

/** True if a process with this PID currently exists (signal 0 probes liveness). */
function isProcessAlive(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (err) {
		// EPERM: the process exists but we can't signal it — still alive.
		return (err as NodeJS.ErrnoException).code === 'EPERM';
	}
}

function readLock(lockPath: string): ILockInfo | null {
	try {
		const parsed = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
		if (typeof parsed?.pid === 'number') return parsed as ILockInfo;
	} catch {
		// Missing/corrupt lock file — treat as no valid holder.
	}
	return null;
}

/**
 * Acquire the lock at `lockPath`, creating parent state as needed. Throws
 * {@link InstanceLockError} if a live instance already holds it. Reclaims a
 * stale lock left by a crashed process. Pass `now` for deterministic tests.
 */
export function acquireInstanceLock(
	lockPath: string,
	now: number = Date.now()
): ILockInfo {
	const info: ILockInfo = {
		pid: process.pid,
		hostname: os.hostname(),
		createdAt: now
	};
	const payload = JSON.stringify(info);

	// At most two attempts: the second runs only after we clear a stale lock,
	// so a live competitor can never be silently overwritten.
	for (let attempt = 0; attempt < 2; attempt++) {
		try {
			const fd = fs.openSync(lockPath, 'wx'); // atomic: fails if it exists
			try {
				fs.writeSync(fd, payload);
			} finally {
				fs.closeSync(fd);
			}
			return info;
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;

			const holder = readLock(lockPath);
			if (holder && holder.pid !== process.pid && isProcessAlive(holder.pid)) {
				throw new InstanceLockError(
					`Another beignet instance (pid ${holder.pid} on ${holder.hostname}) is already ` +
						`using this wallet. Stop it first, or start with a different dataDir. Lock: ${lockPath}`,
					holder
				);
			}
			// Stale (crashed) or our own leftover lock — remove and retry once.
			try {
				fs.unlinkSync(lockPath);
			} catch {
				// Someone else won the race to clear it; the retry will re-evaluate.
			}
		}
	}

	// Reached only if a competitor recreated the lock between our unlink and
	// retry — treat as contended rather than forcing it.
	throw new InstanceLockError(
		`Could not acquire the instance lock at ${lockPath} (contended by another starting instance).`,
		readLock(lockPath)
	);
}

/**
 * Release the lock if (and only if) this process holds it. Safe to call on a
 * missing or foreign lock — it never removes another instance's lock.
 */
export function releaseInstanceLock(lockPath: string): void {
	try {
		const holder = readLock(lockPath);
		if (holder && holder.pid === process.pid) {
			fs.unlinkSync(lockPath);
		}
	} catch {
		// Best effort: a missing file or unlink race is fine.
	}
}
