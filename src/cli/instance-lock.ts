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
 *
 * The PID probe is only meaningful in our own PID namespace, so it applies
 * only when the recorded hostname matches ours. A lock recorded under a
 * different hostname (e.g. a recreated container on the same data dir, where
 * the old PID may now belong to an unrelated process) cannot be probed at all.
 * What happens then is the caller's choice via `reclaimForeignHost`: daemon
 * startup opts in and reclaims it as stale, while callers that must never
 * disturb a possibly-live instance elsewhere (offline DB restore) keep the
 * fail-closed default and refuse. Cross-host sharing of one data dir is not a
 * supported scenario — a PID probe could not arbitrate it either way.
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

interface ILockFile {
	/** Exact bytes on disk, kept so a removal can target the file we inspected. */
	raw: string;
	info: ILockInfo | null;
}

/** Null when the file is missing/unreadable; `info` null when it is corrupt. */
function readLockFile(lockPath: string): ILockFile | null {
	let raw: string;
	try {
		raw = fs.readFileSync(lockPath, 'utf8');
	} catch {
		return null;
	}
	try {
		const parsed = JSON.parse(raw);
		if (typeof parsed?.pid === 'number') return { raw, info: parsed };
	} catch {
		// Corrupt lock file — no valid holder, but keep the bytes.
	}
	return { raw, info: null };
}

/**
 * A hostname is comparable only when it is a non-empty string. Anything else
 * (missing, mangled, empty) counts as "same host", so the conservative PID
 * probe stays in charge and a possibly-live local holder is never clobbered.
 */
function isComparableHostname(h: unknown): h is string {
	return typeof h === 'string' && h.trim() !== '';
}

function isForeignHost(recorded: unknown, ours: string): boolean {
	return (
		isComparableHostname(recorded) &&
		isComparableHostname(ours) &&
		recorded !== ours
	);
}

/** Why a stale lock was reclaimed, reported via `onReclaim`. */
export type LockReclaimReason = 'dead-pid' | 'foreign-host';

export interface IAcquireLockOptions {
	/** Timestamp recorded in the lock; pass a fixed value for deterministic tests. */
	now?: number;
	/**
	 * Treat a lock recorded under a different hostname as stale and reclaim it
	 * (the PID probe proves nothing across a container recreate). Default
	 * false: without the opt-in a foreign-host lock is refused outright, since
	 * its liveness cannot be verified from here.
	 */
	reclaimForeignHost?: boolean;
	/** Invoked after acquisition for each stale holder whose lock was taken over. */
	onReclaim?: (holder: ILockInfo, reason: LockReclaimReason) => void;
}

/**
 * Acquire the lock at `lockPath`, creating parent state as needed. Throws
 * {@link InstanceLockError} if a live instance already holds it — or, unless
 * `reclaimForeignHost` is set, if the lock was recorded under another hostname
 * (unverifiable, so fail closed). Reclaims a stale lock left by a crashed
 * process, or a foreign-host lock when opted in.
 */
export function acquireInstanceLock(
	lockPath: string,
	opts: IAcquireLockOptions = {}
): ILockInfo {
	const { now = Date.now(), reclaimForeignHost = false, onReclaim } = opts;
	const info: ILockInfo = {
		pid: process.pid,
		hostname: os.hostname(),
		createdAt: now
	};
	const payload = JSON.stringify(info);
	const reclaimed: Array<{ holder: ILockInfo; reason: LockReclaimReason }> = [];

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
			// Notify only once the lock is ours: reporting earlier would sit
			// inside the inspect→remove window and widen that race.
			for (const r of reclaimed) onReclaim?.(r.holder, r.reason);
			return info;
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;

			const existing = readLockFile(lockPath);
			// Vanished between the create and the read — retry the create.
			if (existing === null) continue;

			const holder = existing.info;
			const foreign =
				holder !== null && isForeignHost(holder.hostname, info.hostname);
			if (holder) {
				if (foreign && !reclaimForeignHost) {
					throw new InstanceLockError(
						`The instance lock for this wallet was recorded on another host ` +
							`(pid ${holder.pid} on ${holder.hostname}), so its liveness cannot be ` +
							`verified from here. Stop that instance, or remove the lock file if you ` +
							`are certain it is stale. Lock: ${lockPath}`,
						holder
					);
				}
				if (
					!foreign &&
					holder.pid !== process.pid &&
					isProcessAlive(holder.pid)
				) {
					throw new InstanceLockError(
						`Another beignet instance (pid ${holder.pid} on ${holder.hostname}) is already ` +
							`using this wallet. Stop it first, or start with a different dataDir. Lock: ${lockPath}`,
						holder
					);
				}
			}

			// Stale (dead/foreign/own-leftover holder, or corrupt) — remove and
			// retry once, but only the exact bytes we inspected: if the file
			// changed underneath us another starter owns it now, so leave it in
			// place and let the retry re-evaluate the new holder.
			try {
				if (fs.readFileSync(lockPath, 'utf8') !== existing.raw) continue;
				fs.unlinkSync(lockPath);
			} catch {
				// Someone else won the race to clear it; the retry re-evaluates.
				continue;
			}
			// A takeover of another holder is reported (post-acquisition); our
			// own same-host leftover is not.
			if (holder && (foreign || holder.pid !== process.pid)) {
				reclaimed.push({
					holder,
					reason: foreign ? 'foreign-host' : 'dead-pid'
				});
			}
		}
	}

	// Reached only if a competitor recreated the lock between our unlink and
	// retry — treat as contended rather than forcing it.
	throw new InstanceLockError(
		`Could not acquire the instance lock at ${lockPath} (contended by another starting instance).`,
		readLockFile(lockPath)?.info ?? null
	);
}

/**
 * Release the lock if (and only if) this process holds it. Safe to call on a
 * missing or foreign lock — it never removes another instance's lock.
 */
export function releaseInstanceLock(lockPath: string): void {
	try {
		const holder = readLockFile(lockPath)?.info;
		// PID alone is ambiguous across hosts — require the hostname to match
		// too (an unverifiable hostname counts as ours, as on acquire).
		const ours =
			holder &&
			holder.pid === process.pid &&
			!isForeignHost(holder.hostname, os.hostname());
		if (ours) {
			fs.unlinkSync(lockPath);
		}
	} catch {
		// Best effort: a missing file or unlink race is fine.
	}
}
