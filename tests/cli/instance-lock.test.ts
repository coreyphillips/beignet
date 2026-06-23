/**
 * Single-instance data-dir lock tests.
 *
 * Verifies that a second instance on the same data dir fails fast (preventing
 * the node-identity collision that churns peer connections + the SQLite
 * corruption risk), while a stale lock from a crashed run is reclaimed.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	acquireInstanceLock,
	releaseInstanceLock,
	InstanceLockError,
	ILockInfo
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

	function writeForeignLock(pid: number): void {
		const info: ILockInfo = { pid, hostname: 'other-host', createdAt: 1 };
		fs.writeFileSync(lockPath, JSON.stringify(info));
	}

	it('acquires a free lock and records our pid', () => {
		const info = acquireInstanceLock(lockPath);
		expect(info.pid).to.equal(process.pid);
		expect(fs.existsSync(lockPath)).to.be.true;
		const onDisk = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
		expect(onDisk.pid).to.equal(process.pid);
	});

	it('refuses to start when a live foreign instance holds the lock', () => {
		writeForeignLock(ALIVE_FOREIGN_PID);
		expect(() => acquireInstanceLock(lockPath)).to.throw(InstanceLockError);
		// The foreign lock must be left intact, not clobbered.
		expect(JSON.parse(fs.readFileSync(lockPath, 'utf8')).pid).to.equal(
			ALIVE_FOREIGN_PID
		);
	});

	it('reclaims a stale lock left by a crashed (dead) process', () => {
		writeForeignLock(DEAD_PID);
		const info = acquireInstanceLock(lockPath);
		expect(info.pid).to.equal(process.pid);
		expect(JSON.parse(fs.readFileSync(lockPath, 'utf8')).pid).to.equal(
			process.pid
		);
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
		writeForeignLock(ALIVE_FOREIGN_PID);
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
