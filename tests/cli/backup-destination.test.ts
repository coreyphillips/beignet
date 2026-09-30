/**
 * POST /backup writes only where it should (issue #1230).
 *
 * SQLite's backup API replaces an empty file or any SQLite database it is
 * pointed at, the node's own live database included, and the route used to
 * forward any path without a `..` in it. The destination is now
 * canonicalized, the daemon's own files are refused, and an existing file
 * needs overwrite: true.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { resolveBackupDestination } from '../../src/cli/backup-destination';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const SQLITE_HEADER = 'SQLite format 3\u0000';

function post(
	port: number,
	route: string,
	body: Record<string, unknown>
): Promise<{
	status: number;
	body: { ok: boolean; error?: { code: string; message: string } };
}> {
	return new Promise((resolve, reject) => {
		const payload = JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: route,
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(payload)
				}
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () =>
					resolve({
						status: res.statusCode!,
						body: JSON.parse(Buffer.concat(chunks).toString())
					})
				);
			}
		);
		req.on('error', reject);
		req.write(payload);
		req.end();
	});
}

function header(file: string): string {
	return fs.readFileSync(file).subarray(0, 16).toString('latin1');
}

describe('Backup destination (issue #1230)', () => {
	describe('resolveBackupDestination', () => {
		let dir: string;

		beforeEach(() => {
			// realpath: macOS hands out /var/... for /private/var/...
			dir = fs.realpathSync(
				fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-backup-dest-'))
			);
		});

		afterEach(() => {
			fs.rmSync(dir, { recursive: true, force: true });
		});

		it('accepts a new file in an existing directory', () => {
			const dest = path.join(dir, 'new.db');
			expect(resolveBackupDestination(dest, [], false)).to.deep.equal({
				path: dest
			});
		});

		it('refuses a directory that does not exist', () => {
			const result = resolveBackupDestination(
				path.join(dir, 'missing', 'new.db'),
				[],
				false
			);
			expect(result)
				.to.have.property('refusal')
				.that.match(/does not exist/);
		});

		it('refuses an existing file unless overwrite is set', () => {
			const dest = path.join(dir, 'old.db');
			fs.writeFileSync(dest, '');
			expect(resolveBackupDestination(dest, [], false))
				.to.have.property('refusal')
				.that.match(/already exists/);
			expect(resolveBackupDestination(dest, [], true)).to.deep.equal({
				path: dest
			});
		});

		it('refuses a protected file even with overwrite, by any path to it', () => {
			const live = path.join(dir, 'regtest.db');
			fs.writeFileSync(live, '');
			const link = path.join(dir, 'link.db');
			fs.symlinkSync(live, link);
			const nested = path.join(dir, 'sub');
			fs.mkdirSync(nested);
			const cwd = process.cwd();
			process.chdir(nested);
			try {
				for (const dest of [live, link, path.join('..', 'regtest.db')]) {
					expect(resolveBackupDestination(dest, [live], true), dest)
						.to.have.property('refusal')
						.that.match(/daemon file/);
				}
			} finally {
				process.chdir(cwd);
			}
		});

		it('refuses a protected file that does not exist yet', () => {
			const wal = path.join(dir, 'regtest.db-wal');
			expect(resolveBackupDestination(wal, [wal], true))
				.to.have.property('refusal')
				.that.match(/daemon file/);
		});

		it('refuses a directory and a dangling symlink', () => {
			expect(resolveBackupDestination(dir, [], true))
				.to.have.property('refusal')
				.that.match(/not a regular file/);
			const dangling = path.join(dir, 'dangling.db');
			fs.symlinkSync(path.join(dir, 'nowhere.db'), dangling);
			expect(resolveBackupDestination(dangling, [], true))
				.to.have.property('refusal')
				.that.match(/broken symlink/);
		});
	});

	describe('POST /backup', function () {
		this.timeout(30_000);

		let home: string;
		let dataDir: string;
		let daemon: IStartedDaemon;
		let port: number;
		const origHome = process.env.HOME;

		before(async () => {
			home = fs.realpathSync(
				fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-backup-route-'))
			);
			// configPath() and pidPath() follow HOME on every call.
			process.env.HOME = home;
			fs.mkdirSync(path.join(home, '.beignet'));
			fs.writeFileSync(path.join(home, '.beignet', 'config.json'), '');
			dataDir = path.join(home, 'data');
			daemon = await startDaemon({
				electrumHost: '127.0.0.1',
				electrumPort: 65529,
				electrumTls: false,
				rapidGossipSync: false,
				autoGossipSync: false,
				logLevel: 'silent',
				network: 'regtest',
				mnemonic: MNEMONIC,
				daemonPort: 0,
				dataDir
			});
			port = (daemon.server.address() as AddressInfo).port;
		});

		after(async () => {
			await daemon.stop();
			process.env.HOME = origHome;
			fs.rmSync(home, { recursive: true, force: true });
		});

		it('refuses the live database, its WAL and the config even with overwrite', async () => {
			const live = path.join(dataDir, 'regtest.db');
			const link = path.join(home, 'looks-like-a-backup.db');
			fs.symlinkSync(live, link);
			for (const destPath of [
				live,
				`${live}-wal`,
				link,
				path.join(home, '.beignet', 'config.json')
			]) {
				const res = await post(port, '/backup', { destPath, overwrite: true });
				expect(res.status, destPath).to.equal(400);
				expect(res.body.error!.code).to.equal('INVALID_PARAMS');
				expect(res.body.error!.message).to.match(/daemon file/);
			}
			// An empty config.json is exactly what SQLite would have replaced.
			expect(
				fs.readFileSync(path.join(home, '.beignet', 'config.json'), 'utf8')
			).to.equal('');
		});

		it('writes a new file, and replaces an existing one only with overwrite', async () => {
			const dest = path.join(home, 'backup.db');
			const first = await post(port, '/backup', { destPath: dest });
			expect(first.status).to.equal(200);
			expect(header(dest)).to.equal(SQLITE_HEADER);

			const again = await post(port, '/backup', { destPath: dest });
			expect(again.status).to.equal(400);
			expect(again.body.error!.message).to.match(/already exists/);

			const replaced = await post(port, '/backup', {
				destPath: dest,
				overwrite: true
			});
			expect(replaced.status).to.equal(200);
			expect(header(dest)).to.equal(SQLITE_HEADER);
		});
	});
});
