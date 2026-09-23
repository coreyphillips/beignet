/**
 * Issue 402: Ctrl-C on `beignet start` must run the same graceful teardown
 * as POST /stop. The old handler called process.exit(0) directly, abandoning
 * an in-flight backup and leaving SQLite open. This spawns the real CLI,
 * waits for the node to come up, sends SIGINT and expects a clean exit 0
 * with the pid file removed. Boots offline (unreachable Electrum, regtest).
 *
 * Issue 968: the signal handlers must be in place before the CLI prints
 * `Node started`. A signal sent the moment the banner appears used to take
 * the default action and kill the process without the graceful teardown.
 */

import { expect } from 'chai';
import { ChildProcessByStdio, spawn } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { Readable } from 'stream';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Wraps process.stdout.write in the child and interrupts the process from
// inside the write that carries the banner, the earliest moment a
// supervisor watching stdout could react to it.
const SIGINT_ON_BANNER_PRELOAD = `
const originalWrite = process.stdout.write;
let fired = false;
process.stdout.write = function (chunk, ...rest) {
	const result = originalWrite.call(process.stdout, chunk, ...rest);
	if (!fired && String(chunk).includes('Node started')) {
		fired = true;
		process.kill(process.pid, 'SIGINT');
	}
	return result;
};
`;

function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const probe = net.createServer();
		probe.on('error', reject);
		probe.listen(0, '127.0.0.1', () => {
			const { port } = probe.address() as net.AddressInfo;
			probe.close(() => resolve(port));
		});
	});
}

function spawnStart(
	tmpDir: string,
	daemonPort: number,
	preloads: string[] = []
): ChildProcessByStdio<null, Readable, Readable> {
	const repoRoot = path.resolve(__dirname, '..', '..');
	const requires = ['ts-node/register', ...preloads].flatMap((m) => ['-r', m]);
	return spawn(
		process.execPath,
		[...requires, path.join('src', 'cli', 'cli.ts'), 'start'],
		{
			cwd: repoRoot,
			stdio: ['ignore', 'pipe', 'pipe'],
			env: {
				...process.env,
				HOME: tmpDir,
				BEIGNET_MNEMONIC: MNEMONIC,
				BEIGNET_NETWORK: 'regtest',
				BEIGNET_DATA_DIR: tmpDir,
				BEIGNET_ELECTRUM_HOST: '127.0.0.1',
				BEIGNET_ELECTRUM_PORT: '65529',
				BEIGNET_ELECTRUM_TLS: 'false',
				BEIGNET_DAEMON_PORT: String(daemonPort)
			}
		}
	);
}

describe('beignet start + SIGINT', function () {
	// ts-node compiles the CLI in the child, then a full node boots.
	this.timeout(120_000);

	it('shuts down gracefully and exits 0', async function () {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-sigint-'));
		const child = spawnStart(tmpDir, await freePort());

		let stdout = '';
		let stderr = '';
		child.stdout.on('data', (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.stderr.on('data', (chunk: Buffer) => {
			stderr += chunk.toString();
		});

		try {
			// Wait for the started banner, then interrupt.
			await new Promise<void>((resolve, reject) => {
				const deadline = setTimeout(() => {
					reject(
						new Error(`the CLI never reported startup. stderr: ${stderr}`)
					);
				}, 90_000);
				const check = (): void => {
					if (stdout.includes('Node started')) {
						clearTimeout(deadline);
						resolve();
					}
				};
				child.stdout.on('data', check);
				child.once('close', () => {
					clearTimeout(deadline);
					reject(new Error(`the CLI exited before startup. stderr: ${stderr}`));
				});
			});

			child.kill('SIGINT');

			// `close` rather than `exit`: exit can fire while stdio still drains.
			const result = await new Promise<{
				code: number | null;
				hung: boolean;
			}>((resolve) => {
				const killer = setTimeout(() => {
					child.kill('SIGKILL');
					resolve({ code: null, hung: true });
				}, 25_000);
				child.once('close', (code) => {
					clearTimeout(killer);
					resolve({ code, hung: false });
				});
			});

			expect(
				result.hung,
				`SIGINT did not terminate the CLI. stderr: ${stderr}`
			).to.equal(false);
			expect(
				result.code,
				`the CLI exited non-zero on SIGINT. stderr: ${stderr}`
			).to.equal(0);
			const pidPath = path.join(tmpDir, '.beignet', 'daemon.pid');
			expect(fs.existsSync(pidPath), 'the pid file must be removed').to.equal(
				false
			);
			// SQLite checkpoints and deletes the WAL when the handle closes. A
			// leftover -wal is the old bug: process.exit(0) before storage.close.
			const walPath = path.join(tmpDir, 'regtest.db-wal');
			expect(
				fs.existsSync(walPath),
				'the SQLite WAL must be checkpointed on shutdown'
			).to.equal(false);
		} finally {
			if (child.exitCode === null) child.kill('SIGKILL');
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it('shuts down gracefully on a SIGINT sent as the banner is written (#968)', async function () {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-sigint-'));
		const preloadPath = path.join(tmpDir, 'sigint-on-banner.js');
		fs.writeFileSync(preloadPath, SIGINT_ON_BANNER_PRELOAD);
		const child = spawnStart(tmpDir, await freePort(), [preloadPath]);

		let stdout = '';
		let stderr = '';
		child.stdout.on('data', (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.stderr.on('data', (chunk: Buffer) => {
			stderr += chunk.toString();
		});
		// Listen from the start: without the fix the child dies at the banner,
		// possibly before this side has read it.
		const closed = new Promise<{
			code: number | null;
			signal: NodeJS.Signals | null;
		}>((resolve) => {
			child.once('close', (code, signal) => resolve({ code, signal }));
		});

		try {
			// The child interrupts itself as it prints the banner. Wait for the
			// banner or an early exit, then for the shutdown to finish.
			await new Promise<void>((resolve, reject) => {
				const deadline = setTimeout(() => {
					reject(
						new Error(`the CLI never reported startup. stderr: ${stderr}`)
					);
				}, 90_000);
				const done = (): void => {
					clearTimeout(deadline);
					resolve();
				};
				child.stdout.on('data', () => {
					if (stdout.includes('Node started')) done();
				});
				void closed.then(done);
			});

			let killer: NodeJS.Timeout | undefined;
			const result = await Promise.race([
				closed.then((r) => ({ ...r, hung: false })),
				new Promise<{ code: null; signal: null; hung: boolean }>((resolve) => {
					killer = setTimeout(() => {
						child.kill('SIGKILL');
						resolve({ code: null, signal: null, hung: true });
					}, 25_000);
				})
			]);
			clearTimeout(killer);

			expect(
				result.hung,
				`SIGINT did not terminate the CLI. stderr: ${stderr}`
			).to.equal(false);
			expect(
				result.signal,
				`the CLI was killed by the signal instead of shutting down. stderr: ${stderr}`
			).to.equal(null);
			expect(
				result.code,
				`the CLI exited non-zero on SIGINT. stderr: ${stderr}`
			).to.equal(0);
			expect(stdout, 'the CLI must have printed the banner').to.include(
				'Node started'
			);
			const pidPath = path.join(tmpDir, '.beignet', 'daemon.pid');
			expect(fs.existsSync(pidPath), 'the pid file must be removed').to.equal(
				false
			);
			const walPath = path.join(tmpDir, 'regtest.db-wal');
			expect(
				fs.existsSync(walPath),
				'the SQLite WAL must be checkpointed on shutdown'
			).to.equal(false);
		} finally {
			if (child.exitCode === null) child.kill('SIGKILL');
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
});
