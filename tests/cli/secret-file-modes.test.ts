/**
 * Owner-only permissions on every file the CLI creates (issue #1004).
 *
 * saveConfig wrote ~/.beignet/config.json, mnemonic included, with no mode:
 * 0644 under the usual umask, readable by every other account on the host.
 * The data directory, the SQLite database (whose lookup columns are
 * plaintext), the instance lock, backups, restore copies and SCB exports were
 * created the same way. Each is now 0600 (0700 for directories), set
 * explicitly rather than trusted to the umask, and a config file an older
 * release left readable is tightened the next time it is read.
 *
 * Every assertion runs under a permissive umask (022) so a 0600 result proves
 * the code set the mode itself. POSIX bits mean nothing on Windows, where the
 * whole file is skipped.
 */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	loadConfig,
	removePidFile,
	saveConfig,
	writePidFile
} from '../../src/cli/config';
import {
	ensurePrivateDir,
	tightenMode,
	writeFileAtomic
} from '../../src/cli/fs-utils';
import {
	acquireInstanceLock,
	releaseInstanceLock
} from '../../src/cli/instance-lock';
import { restoreDbFile } from '../../src/cli/restore';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const
};

const modeOf = (p: string): number => fs.statSync(p).mode & 0o777;
const octal = (mode: number): string => '0' + mode.toString(8);

/**
 * Run `fn` with a permissive umask, restoring the previous one afterwards.
 * Mocha's parallel workers run one file at a time, so a temporary umask
 * cannot leak into another file's assertions.
 */
async function withUmask<T>(
	mask: number,
	fn: () => T | Promise<T>
): Promise<T> {
	const previous = process.umask(mask);
	try {
		return await fn();
	} finally {
		process.umask(previous);
	}
}

/** Everything written to stderr while `fn` runs. */
function captureStderr(fn: () => void): string {
	const original = process.stderr.write;
	let captured = '';
	process.stderr.write = ((chunk: string | Uint8Array): boolean => {
		captured += chunk.toString();
		return true;
	}) as typeof process.stderr.write;
	try {
		fn();
	} finally {
		process.stderr.write = original;
	}
	return captured;
}

describe('secret file modes (issue #1004)', function () {
	before(function () {
		if (process.platform === 'win32') this.skip();
	});

	describe('config directory and file', () => {
		const origHome = process.env.HOME;
		let tmpHome: string;
		let beignetDir: string;
		let configPath: string;

		beforeEach(() => {
			tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-modes-'));
			process.env.HOME = tmpHome;
			beignetDir = path.join(tmpHome, '.beignet');
			configPath = path.join(beignetDir, 'config.json');
		});

		afterEach(() => {
			process.env.HOME = origHome;
			fs.rmSync(tmpHome, { recursive: true, force: true });
		});

		it('saveConfig creates ~/.beignet 0700 and config.json 0600 under a 022 umask', async () => {
			const stderr = await withUmask(0o022, () =>
				captureStderr(() =>
					saveConfig({ mnemonic: MNEMONIC, network: 'regtest' })
				)
			);
			expect(octal(modeOf(beignetDir)), 'directory').to.equal('0700');
			expect(octal(modeOf(configPath)), 'config file').to.equal('0600');
			expect(fs.existsSync(`${configPath}.tmp`), 'temp file left').to.equal(
				false
			);
			expect(loadConfig().mnemonic).to.equal(MNEMONIC);
			// Nothing was loose, so nothing was announced.
			expect(stderr).to.equal('');
		});

		it('saveConfig over a 0644 config leaves it 0600 (writeFileSync keeps the old bits)', async () => {
			fs.mkdirSync(beignetDir, { recursive: true });
			fs.writeFileSync(configPath, '{}\n');
			fs.chmodSync(configPath, 0o644);
			await withUmask(0o022, () =>
				captureStderr(() => saveConfig({ network: 'regtest' }))
			);
			expect(octal(modeOf(configPath))).to.equal('0600');
		});

		it('loadConfig tightens a readable config and directory and says so once on stderr', async () => {
			// What a release before the fix left behind under umask 022.
			fs.mkdirSync(beignetDir, { recursive: true });
			fs.chmodSync(beignetDir, 0o755);
			fs.writeFileSync(
				configPath,
				JSON.stringify({ mnemonic: MNEMONIC, apiToken: 't' }) + '\n'
			);
			fs.chmodSync(configPath, 0o644);

			let loaded: ReturnType<typeof loadConfig> = {};
			const stderr = await withUmask(0o022, () =>
				captureStderr(() => {
					loaded = loadConfig();
				})
			);
			expect(loaded.mnemonic, 'the config still loads').to.equal(MNEMONIC);
			expect(octal(modeOf(beignetDir)), 'directory').to.equal('0700');
			expect(octal(modeOf(configPath)), 'config file').to.equal('0600');
			expect(stderr).to.include(
				`tightened permissions on ${configPath} (was 0644, now 0600)`
			);
			expect(stderr).to.include(
				`tightened permissions on ${beignetDir} (was 0755, now 0700)`
			);

			// Already tight: the next read is silent.
			expect(captureStderr(() => loadConfig())).to.equal('');
		});

		it('loadConfig with no config yet touches nothing and prints nothing', () => {
			expect(captureStderr(() => loadConfig())).to.equal('');
			expect(fs.existsSync(beignetDir)).to.equal(false);
		});

		it('the pid file is 0600', async () => {
			await withUmask(0o022, () => writePidFile(4242, 2112));
			try {
				expect(octal(modeOf(path.join(beignetDir, 'daemon.pid')))).to.equal(
					'0600'
				);
			} finally {
				removePidFile();
			}
		});

		it('beignet init writes a 0700 directory and a 0600 config from a 022 umask', async function () {
			// ts-node has to load the CLI and everything it imports in the child.
			this.timeout(120_000);
			const repoRoot = path.resolve(__dirname, '..', '..');
			// The child inherits this umask; the CLI has to restrict it itself.
			const result = await withUmask(
				0o022,
				() =>
					new Promise<{ code: number | null; stdout: string; stderr: string }>(
						(resolve) => {
							const child = spawn(
								process.execPath,
								[
									'-r',
									'ts-node/register',
									path.join('src', 'cli', 'cli.ts'),
									'init',
									'--network',
									'regtest'
								],
								{
									cwd: repoRoot,
									env: { ...process.env, HOME: tmpHome },
									stdio: ['ignore', 'pipe', 'pipe']
								}
							);
							let stdout = '';
							let stderr = '';
							child.stdout.on('data', (chunk: Buffer) => {
								stdout += chunk.toString();
							});
							child.stderr.on('data', (chunk: Buffer) => {
								stderr += chunk.toString();
							});
							const killer = setTimeout(() => {
								child.kill('SIGKILL');
								resolve({ code: null, stdout, stderr });
							}, 90_000);
							child.once('close', (code) => {
								clearTimeout(killer);
								resolve({ code, stdout, stderr });
							});
						}
					)
			);
			expect(result.code, `init failed. stderr: ${result.stderr}`).to.equal(0);
			const parsed = JSON.parse(result.stdout.trim().split('\n').pop()!);
			expect(parsed.ok, result.stdout).to.equal(true);
			expect(octal(modeOf(beignetDir)), 'directory').to.equal('0700');
			expect(octal(modeOf(configPath)), 'config file').to.equal('0600');
			expect(loadConfig().mnemonic).to.equal(parsed.result.mnemonic);
		});
	});

	describe('fs-utils', () => {
		let dir: string;

		beforeEach(() => {
			dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-fsutils-'));
		});

		afterEach(() => {
			fs.rmSync(dir, { recursive: true, force: true });
		});

		it('writeFileAtomic defaults to 0600, honours an explicit mode, and leaves no temp file', async () => {
			const secret = path.join(dir, 'secret');
			const shared = path.join(dir, 'shared');
			await withUmask(0o022, () => {
				writeFileAtomic(secret, 'a');
				writeFileAtomic(shared, 'b', 0o640);
			});
			expect(octal(modeOf(secret))).to.equal('0600');
			expect(octal(modeOf(shared))).to.equal('0640');
			expect(fs.readFileSync(secret, 'utf8')).to.equal('a');
			expect(fs.existsSync(`${secret}.tmp`)).to.equal(false);
		});

		it('writeFileAtomic rewriting a 0644 file leaves it 0600', async () => {
			const target = path.join(dir, 'existing');
			fs.writeFileSync(target, 'old');
			fs.chmodSync(target, 0o644);
			// A stale temp file from a crashed earlier write must not keep its
			// bits either.
			fs.writeFileSync(`${target}.tmp`, 'torn');
			fs.chmodSync(`${target}.tmp`, 0o644);
			await withUmask(0o022, () => writeFileAtomic(target, 'new'));
			expect(octal(modeOf(target))).to.equal('0600');
			expect(fs.readFileSync(target, 'utf8')).to.equal('new');
		});

		it('ensurePrivateDir creates 0700 and tightens an existing 0755 directory', async () => {
			const fresh = path.join(dir, 'a', 'b');
			const existing = path.join(dir, 'old');
			fs.mkdirSync(existing);
			fs.chmodSync(existing, 0o755);
			const results = await withUmask(0o022, () => ({
				fresh: ensurePrivateDir(fresh),
				existing: ensurePrivateDir(existing)
			}));
			expect(octal(modeOf(fresh))).to.equal('0700');
			expect(octal(modeOf(path.join(dir, 'a'))), 'created parent').to.equal(
				'0700'
			);
			expect(results.fresh).to.deep.equal({ changed: false });
			expect(octal(modeOf(existing))).to.equal('0700');
			expect(results.existing).to.deep.equal({
				changed: true,
				previous: 0o755
			});
		});

		it('tightenMode never loosens and reports a missing path as unchanged', () => {
			const readOnly = path.join(dir, 'ro');
			fs.writeFileSync(readOnly, 'x');
			fs.chmodSync(readOnly, 0o400);
			expect(tightenMode(readOnly, 0o600)).to.deep.equal({ changed: false });
			expect(octal(modeOf(readOnly))).to.equal('0400');
			expect(tightenMode(path.join(dir, 'missing'), 0o600)).to.deep.equal({
				changed: false
			});
		});
	});

	describe('data directory, database, lock, backups and exports', function () {
		this.timeout(60_000);
		let dir: string;

		beforeEach(() => {
			dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-modes-data-'));
		});

		afterEach(() => {
			fs.rmSync(dir, { recursive: true, force: true });
		});

		it('SqliteStorage opens the database 0600 with 0600 sidecars and writes 0600 backups', async () => {
			const dbPath = path.join(dir, 'regtest.db');
			const dest = path.join(dir, 'copy.db');
			await withUmask(0o022, async () => {
				const storage = new SqliteStorage(dbPath);
				storage.open();
				try {
					storage.saveMetadata('k', 'v');
					expect(octal(modeOf(dbPath)), 'database').to.equal('0600');
					for (const suffix of ['-wal', '-shm']) {
						const sidecar = `${dbPath}${suffix}`;
						if (fs.existsSync(sidecar)) {
							expect(octal(modeOf(sidecar)), suffix).to.equal('0600');
						}
					}
					await storage.backup(dest);
				} finally {
					storage.close();
				}
			});
			expect(octal(modeOf(dest)), 'backup').to.equal('0600');
		});

		it('SqliteStorage tightens a 0644 database left by an older release', async () => {
			const dbPath = path.join(dir, 'old.db');
			const seed = new SqliteStorage(dbPath);
			seed.open();
			seed.close();
			fs.chmodSync(dbPath, 0o644);
			await withUmask(0o022, () => {
				const storage = new SqliteStorage(dbPath);
				storage.open();
				storage.close();
			});
			expect(octal(modeOf(dbPath))).to.equal('0600');
		});

		it('the instance lock file is 0600', async () => {
			const lockPath = path.join(dir, 'regtest.lock');
			await withUmask(0o022, () => acquireInstanceLock(lockPath));
			try {
				expect(octal(modeOf(lockPath))).to.equal('0600');
			} finally {
				releaseInstanceLock(lockPath);
			}
		});

		it('restoreDbFile leaves the restored database and the pre-restore copy 0600', async () => {
			const backupFile = path.join(dir, 'backup.db');
			const dbPath = path.join(dir, 'live.db');
			for (const p of [backupFile, dbPath]) {
				const s = new SqliteStorage(p);
				s.open();
				s.close();
				// An operator's copy and an older release's live file: both 0644.
				fs.chmodSync(p, 0o644);
			}
			const result = await withUmask(0o022, () =>
				restoreDbFile(backupFile, dbPath, 1234)
			);
			expect(octal(modeOf(dbPath)), 'restored database').to.equal('0600');
			expect(result.preRestorePath).to.be.a('string');
			expect(
				octal(modeOf(result.preRestorePath!)),
				'pre-restore copy'
			).to.equal('0600');
			// The operator's own file is theirs to manage.
			expect(octal(modeOf(backupFile))).to.equal('0644');
		});

		it('BeignetNode.create tightens the data directory and creates the database, lock, backup and SCB export owner-only', async () => {
			// A data directory an older release created under umask 022.
			const dataDir = path.join(dir, 'wallet');
			fs.mkdirSync(dataDir);
			fs.chmodSync(dataDir, 0o755);
			const backupDest = path.join(dir, 'backup.db');

			await withUmask(0o022, async () => {
				const node = await BeignetNode.create({
					...OFFLINE,
					mnemonic: MNEMONIC,
					dataDir
				});
				try {
					expect(octal(modeOf(dataDir)), 'data directory').to.equal('0700');
					const dbPath = path.join(dataDir, 'regtest.db');
					expect(octal(modeOf(dbPath)), 'database').to.equal('0600');
					for (const suffix of ['-wal', '-shm']) {
						const sidecar = `${dbPath}${suffix}`;
						if (fs.existsSync(sidecar)) {
							expect(octal(modeOf(sidecar)), suffix).to.equal('0600');
						}
					}
					expect(
						octal(modeOf(path.join(dataDir, 'regtest.lock'))),
						'instance lock'
					).to.equal('0600');

					await node.backup(backupDest);
					expect(octal(modeOf(backupDest)), 'backup').to.equal('0600');

					const scb = node.exportStaticChannelBackup();
					expect(octal(modeOf(scb.path)), 'channels.scb').to.equal('0600');
					expect(fs.existsSync(`${scb.path}.tmp`)).to.equal(false);
				} finally {
					await node.destroy();
				}
			});
		});
	});
});
