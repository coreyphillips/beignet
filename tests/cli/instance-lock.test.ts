/**
 * Single-instance data-dir lock tests.
 *
 * Verifies that a second instance on the same data dir fails fast (preventing
 * the node-identity collision that churns peer connections + the SQLite
 * corruption risk), while a stale lock from a crashed run is reclaimed. The
 * PID probe only applies to locks recorded under our own hostname: a
 * foreign-hostname lock (recreated container, where the old PID may belong to
 * an unrelated process) is stale by definition and reclaimed.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	acquireInstanceLock,
	releaseInstanceLock,
	InstanceLockError,
	ILockInfo,
	LockReclaimReason
} from '../../src/cli/instance-lock';

// PID 1 (launchd/init) always exists; signal-0 to it is alive (or EPERM, which
// we also treat as alive). A huge PID is reliably dead.
const ALIVE_FOREIGN_PID = 1;
const DEAD_PID = 2_147_483_646;

describe('Instance lock', () => {
	let dir: string;
	let lockPath: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-lock-'));
		lockPath = path.join(dir, 'mainnet.lock');
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function writeLock(pid: number, hostname: string = os.hostname()): void {
		const info: ILockInfo = { pid, hostname, createdAt: 1 };
		fs.writeFileSync(lockPath, JSON.stringify(info));
	}

	it('acquires a free lock and records our pid', () => {
		const info = acquireInstanceLock(lockPath);
		expect(info.pid).to.equal(process.pid);
		expect(fs.existsSync(lockPath)).to.be.true;
		const onDisk = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
		expect(onDisk.pid).to.equal(process.pid);
	});

	it('refuses to start when a live same-host instance holds the lock', () => {
		writeLock(ALIVE_FOREIGN_PID);
		expect(() => acquireInstanceLock(lockPath)).to.throw(InstanceLockError);
		// The foreign lock must be left intact, not clobbered.
		expect(JSON.parse(fs.readFileSync(lockPath, 'utf8')).pid).to.equal(
			ALIVE_FOREIGN_PID
		);
	});

	it('reclaims a stale lock left by a crashed (dead) process', () => {
		writeLock(DEAD_PID);
		const reclaims: Array<{ holder: ILockInfo; reason: LockReclaimReason }> =
			[];
		const info = acquireInstanceLock(lockPath, Date.now(), (holder, reason) =>
			reclaims.push({ holder, reason })
		);
		expect(info.pid).to.equal(process.pid);
		expect(JSON.parse(fs.readFileSync(lockPath, 'utf8')).pid).to.equal(
			process.pid
		);
		expect(reclaims).to.have.length(1);
		expect(reclaims[0].reason).to.equal('dead-pid');
		expect(reclaims[0].holder.pid).to.equal(DEAD_PID);
	});

	// Regression for #440: after a container recreate the recorded pid may
	// belong to an unrelated live process in the new pid namespace. The
	// hostname mismatch must override the pid probe.
	it('reclaims a foreign-hostname lock even when its pid is alive here', () => {
		writeLock(ALIVE_FOREIGN_PID, 'dead-container-host');
		const reclaims: Array<{ holder: ILockInfo; reason: LockReclaimReason }> =
			[];
		const info = acquireInstanceLock(lockPath, Date.now(), (holder, reason) =>
			reclaims.push({ holder, reason })
		);
		expect(info.pid).to.equal(process.pid);
		expect(JSON.parse(fs.readFileSync(lockPath, 'utf8')).pid).to.equal(
			process.pid
		);
		expect(reclaims).to.have.length(1);
		expect(reclaims[0].reason).to.equal('foreign-host');
		expect(reclaims[0].holder.hostname).to.equal('dead-container-host');
	});

	it('still refuses when the lock has no hostname and its pid is alive', () => {
		// Conservative path: a mangled/missing hostname counts as same-host, so
		// the pid probe decides.
		fs.writeFileSync(
			lockPath,
			JSON.stringify({ pid: ALIVE_FOREIGN_PID, createdAt: 1 })
		);
		expect(() => acquireInstanceLock(lockPath)).to.throw(InstanceLockError);
	});

	it('reclaims its own leftover lock (same pid)', () => {
		acquireInstanceLock(lockPath);
		// A second acquire in the same process is our own lock — not a conflict.
		const info = acquireInstanceLock(lockPath);
		expect(info.pid).to.equal(process.pid);
	});

	it('reclaims a corrupt lock file', () => {
		fs.writeFileSync(lockPath, 'not json at all');
		const info = acquireInstanceLock(lockPath);
		expect(info.pid).to.equal(process.pid);
	});

	it('releases a lock we own', () => {
		acquireInstanceLock(lockPath);
		releaseInstanceLock(lockPath);
		expect(fs.existsSync(lockPath)).to.be.false;
	});

	it('never removes a foreign instance lock on release', () => {
		writeLock(ALIVE_FOREIGN_PID);
		releaseInstanceLock(lockPath);
		expect(fs.existsSync(lockPath)).to.be.true;
	});

	it('never removes a foreign-host lock on release, even with our pid', () => {
		writeLock(process.pid, 'other-host');
		releaseInstanceLock(lockPath);
		expect(fs.existsSync(lockPath)).to.be.true;
	});

	it('release is a no-op when no lock exists', () => {
		expect(() => releaseInstanceLock(lockPath)).to.not.throw();
	});

	it('a released lock can be re-acquired', () => {
		acquireInstanceLock(lockPath);
		releaseInstanceLock(lockPath);
		const info = acquireInstanceLock(lockPath);
		expect(info.pid).to.equal(process.pid);
	});
});
