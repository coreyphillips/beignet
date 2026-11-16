/**
 * Host extensions through the real CLI (docs/EXTENSIONS.md): `beignet start`
 * loads the modules BEIGNET_EXTENSIONS and --extension name, serves their
 * routes, and refuses to start on one it cannot load. Boots offline
 * (unreachable Electrum, regtest), like tests/cli/cli-sigint-exit.test.ts.
 */

import { expect } from 'chai';
import { ChildProcessByStdio, spawn } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { Readable } from 'stream';
import { assertDistCliFresh, DIST_CLI } from './helpers/dist-cli';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const PING = `exports.beignetExtension = ({ network, env }) => ({
	id: 'ping',
	version: env.PING_VERSION || '0.0.0',
	api: 1,
	routes: [{ method: 'GET', path: '/ping', scopes: ['readonly'], summary: 'Ping' }],
	attach(context) {
		return {
			handlers: {
				'GET /ping': () => ({
					pong: true,
					network,
					sameNetwork: context.network === network,
					hasWallet: typeof context.wallet.getBalance === 'function'
				})
			}
		};
	}
});
`;

const SECOND = `exports.beignetExtension = {
	id: 'second', version: '2.0.0', api: 1,
	attach() { return {}; }
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

function childEnv(
	tmpDir: string,
	daemonPort: number,
	extra: Record<string, string>
): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = {
		...process.env,
		HOME: tmpDir,
		BEIGNET_MNEMONIC: MNEMONIC,
		BEIGNET_NETWORK: 'regtest',
		BEIGNET_DATA_DIR: tmpDir,
		BEIGNET_ELECTRUM_HOST: '127.0.0.1',
		BEIGNET_ELECTRUM_PORT: '65529',
		BEIGNET_ELECTRUM_TLS: 'false',
		BEIGNET_DAEMON_PORT: String(daemonPort),
		...extra
	};
	// An extension named by the developer's own shell must not ride along.
	if (!('BEIGNET_EXTENSIONS' in extra)) delete env.BEIGNET_EXTENSIONS;
	return env;
}

function run(
	args: string[],
	env: NodeJS.ProcessEnv
): ChildProcessByStdio<null, Readable, Readable> {
	return spawn(process.execPath, [DIST_CLI, ...args], {
		cwd: path.resolve(__dirname, '..', '..'),
		stdio: ['ignore', 'pipe', 'pipe'],
		env
	});
}

/** Collect a child's output and resolve when it closes. */
function finished(
	child: ChildProcessByStdio<null, Readable, Readable>
): Promise<{ code: number | null; stdout: string; stderr: string }> {
	return new Promise((resolve) => {
		let stdout = '';
		let stderr = '';
		child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
		child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
		child.once('close', (code) => resolve({ code, stdout, stderr }));
	});
}

function get(port: number, route: string): Promise<Record<string, unknown>> {
	return new Promise((resolve, reject) => {
		http
			.get({ host: '127.0.0.1', port, path: route }, (res) => {
				let body = '';
				res.setEncoding('utf8');
				res.on('data', (chunk: string) => (body += chunk));
				res.on('end', () => {
					try {
						resolve(JSON.parse(body) as Record<string, unknown>);
					} catch (err) {
						reject(err as Error);
					}
				});
			})
			.on('error', reject);
	});
}

describe('beignet start with host extensions', function () {
	this.timeout(120_000);
	let tmpDir: string;
	let modules: string;

	before(assertDistCliFresh);

	before(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ext-cli-'));
		// realpath: macOS keeps its temporary directory behind a symlink.
		modules = fs.realpathSync(
			fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ext-cli-mod-'))
		);
		fs.writeFileSync(path.join(modules, 'ping.js'), PING, { mode: 0o600 });
		fs.writeFileSync(path.join(modules, 'second.js'), SECOND, { mode: 0o600 });
	});

	after(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
		fs.rmSync(modules, { recursive: true, force: true });
	});

	it('serves the extensions the environment and the flag name', async () => {
		const port = await freePort();
		const env = childEnv(tmpDir, port, {
			BEIGNET_EXTENSIONS: path.join(modules, 'ping.js'),
			PING_VERSION: '4.5.6'
		});
		const child = run(
			['start', '--extension', path.join(modules, 'second.js')],
			env
		);
		let stdout = '';
		let stderr = '';
		child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
		child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
		const closed = new Promise<number | null>((resolve) =>
			child.once('close', resolve)
		);
		try {
			await new Promise<void>((resolve, reject) => {
				const deadline = setTimeout(
					() => reject(new Error(`never started. stderr: ${stderr}`)),
					90_000
				);
				const check = (): void => {
					if (stdout.includes('Node started')) {
						clearTimeout(deadline);
						resolve();
					}
				};
				child.stdout.on('data', check);
				void closed.then(() => {
					clearTimeout(deadline);
					reject(new Error(`exited before startup. stdout: ${stdout}`));
				});
				check();
			});

			const ping = await get(port, '/x/ping/ping');
			expect(ping).to.deep.equal({
				ok: true,
				result: {
					pong: true,
					network: 'regtest',
					sameNetwork: true,
					hasWallet: true
				}
			});

			// The CLI command reads the same route.
			const listed = await finished(run(['extensions'], env));
			expect(listed.code, listed.stderr).to.equal(0);
			const { result } = JSON.parse(listed.stdout) as {
				result: {
					api: string;
					extensions: Array<{ id: string; version: string; state: string }>;
				};
			};
			expect(result.api).to.equal('beignet-extension-api/1');
			// The flag's extensions come first, then the environment's.
			expect(result.extensions.map((e) => [e.id, e.version])).to.deep.equal([
				['second', '2.0.0'],
				['ping', '4.5.6']
			]);
			for (const extension of result.extensions) {
				expect(['attached', 'ready']).to.include(extension.state);
			}
		} finally {
			child.kill('SIGINT');
			const killer = setTimeout(() => child.kill('SIGKILL'), 25_000);
			const code = await closed;
			clearTimeout(killer);
			expect(code, `stderr: ${stderr}`).to.equal(0);
		}
	});

	it('refuses to start on an extension it cannot load, and says which', async () => {
		const attempts: Array<[string[], Record<string, string>, RegExp]> = [
			[
				['start', '--extension', 'relative/ping.js'],
				{},
				/Extension relative\/ping\.js: the path must be absolute/
			],
			[
				['start'],
				{ BEIGNET_EXTENSIONS: path.join(modules, 'missing.js') },
				/missing\.js: no such file/
			]
		];
		for (const [args, extra, message] of attempts) {
			const outcome = await finished(
				run(args, childEnv(tmpDir, await freePort(), extra))
			);
			expect(outcome.code, outcome.stdout).to.equal(1);
			const answer = JSON.parse(outcome.stdout) as {
				ok: boolean;
				error: { code: string; message: string };
			};
			expect(answer.ok).to.equal(false);
			expect(answer.error.code).to.equal('START_FAILED');
			expect(answer.error.message).to.match(message);
		}
		// Nothing was left running or locked: the pid file never appeared.
		expect(
			fs.readdirSync(tmpDir).filter((name) => name.endsWith('.pid'))
		).to.deep.equal([]);
	});
});
