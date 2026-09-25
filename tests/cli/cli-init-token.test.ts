/**
 * `beignet init` mints an API token (issue #1005).
 *
 * init wrote only the mnemonic, the network and an optional alias, so the
 * daemon it set up ran with authentication off and any web page could drive
 * it. It now mints a 32-byte hex bearer token whenever the config carries no
 * credential, saves it (0600, issue #1004) and prints it once with a note on
 * how to send it. A config that already holds a token or named keys, or an
 * environment that supplies one, is left alone and nothing is printed.
 *
 * Spawns the real CLI with HOME redirected to a temporary directory, the way
 * tests/cli/secret-file-modes.test.ts does. The children run ts-node in
 * transpile-only mode: the CLI is type-checked by tsc:check already, and
 * type-checking its whole import graph again per spawn is what made a loaded
 * machine miss the deadline.
 */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** One CLI child; the first test below runs two of them in sequence. */
const SPAWN_DEADLINE_MS = 150_000;

type InitResult = {
	code: number | null;
	stdout: string;
	stderr: string;
	result: Record<string, unknown>;
};

function runInit(
	home: string,
	env: Record<string, string> = {}
): Promise<InitResult> {
	const repoRoot = path.resolve(__dirname, '..', '..');
	return new Promise((resolve) => {
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
				env: {
					...process.env,
					...env,
					HOME: home,
					TS_NODE_TRANSPILE_ONLY: '1'
				},
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
		const finish = (code: number | null): void => {
			let result: Record<string, unknown> = {};
			try {
				const last = stdout.trim().split('\n').pop() ?? '';
				result = (JSON.parse(last) as { result: Record<string, unknown> })
					.result;
			} catch {
				// The assertions below report the raw output.
			}
			resolve({ code, stdout, stderr, result });
		};
		const killer = setTimeout(() => {
			child.kill('SIGKILL');
			finish(null);
		}, SPAWN_DEADLINE_MS);
		child.once('close', (code) => {
			clearTimeout(killer);
			finish(code);
		});
	});
}

describe('beignet init mints an API token (issue #1005)', function () {
	// ts-node has to load the CLI and everything it imports in each child, and
	// the first test spawns two.
	this.timeout(2 * SPAWN_DEADLINE_MS + 30_000);
	let home: string;
	let configPath: string;
	const readConfig = (): Record<string, unknown> =>
		JSON.parse(fs.readFileSync(configPath, 'utf8')) as Record<string, unknown>;

	beforeEach(() => {
		home = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-init-1005-'));
		configPath = path.join(home, '.beignet', 'config.json');
	});

	afterEach(() => {
		fs.rmSync(home, { recursive: true, force: true });
	});

	it('a fresh init mints a 64-hex apiToken, prints it once and a second init keeps it', async () => {
		const first = await runInit(home);
		expect(first.code, `init failed. stderr: ${first.stderr}`).to.equal(0);
		expect(first.result.message, first.stdout).to.equal('Initialized');
		expect(first.result.apiToken, first.stdout).to.match(/^[0-9a-f]{64}$/);
		expect(String(first.result.note)).to.include('Authorization: Bearer');
		const saved = readConfig();
		expect(saved.apiToken).to.equal(first.result.apiToken);
		expect(saved.mnemonic).to.equal(first.result.mnemonic);
		if (process.platform !== 'win32') {
			expect((fs.statSync(configPath).mode & 0o777).toString(8)).to.equal(
				'600'
			);
		}

		const second = await runInit(home);
		expect(
			second.code,
			`second init failed. stderr: ${second.stderr}`
		).to.equal(0);
		expect(second.result.message).to.equal('Config already exists');
		expect(second.result.mnemonic).to.equal(first.result.mnemonic);
		// The token exists, so it is neither replaced nor shown again.
		expect(second.result).to.not.have.property('apiToken');
		expect(readConfig().apiToken).to.equal(first.result.apiToken);
	});

	it('a config that already has apiKeys gets no apiToken', async () => {
		fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
		fs.writeFileSync(
			configPath,
			JSON.stringify({
				apiKeys: [{ name: 'ops', key: 'opssecret', scopes: ['admin'] }]
			}) + '\n',
			{ mode: 0o600 }
		);
		const init = await runInit(home);
		expect(init.code, `init failed. stderr: ${init.stderr}`).to.equal(0);
		expect(init.result.message).to.equal('Initialized');
		expect(init.result).to.not.have.property('apiToken');
		const saved = readConfig();
		expect(saved).to.not.have.property('apiToken');
		expect(saved.mnemonic).to.equal(init.result.mnemonic);
		expect(saved.apiKeys).to.deep.equal([
			{ name: 'ops', key: 'opssecret', scopes: ['admin'] }
		]);
	});

	it('a config an older release wrote (mnemonic, no credential) gets a token on the next init', async () => {
		fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
		fs.writeFileSync(
			configPath,
			JSON.stringify({ mnemonic: MNEMONIC, network: 'regtest' }) + '\n',
			{ mode: 0o600 }
		);
		const init = await runInit(home);
		expect(init.code, `init failed. stderr: ${init.stderr}`).to.equal(0);
		expect(init.result.message).to.equal('Config already exists');
		expect(init.result.mnemonic).to.equal(MNEMONIC);
		expect(init.result.apiToken).to.match(/^[0-9a-f]{64}$/);
		const saved = readConfig();
		expect(saved.apiToken).to.equal(init.result.apiToken);
		expect(saved.mnemonic).to.equal(MNEMONIC);
	});

	it('a credential in the environment means no file token is minted', async () => {
		// A minted token would be shadowed by BEIGNET_API_TOKEN at start and
		// mislead whoever reads the init output.
		const init = await runInit(home, { BEIGNET_API_TOKEN: 'envtoken' });
		expect(init.code, `init failed. stderr: ${init.stderr}`).to.equal(0);
		expect(init.result.message).to.equal('Initialized');
		expect(init.result).to.not.have.property('apiToken');
		expect(readConfig()).to.not.have.property('apiToken');
	});
});
