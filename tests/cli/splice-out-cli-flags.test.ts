/**
 * CLI splice-out: trailing global flags never become the optional address
 * (issue #534 review, LFBW port #532 workstream 1A).
 *
 * `beignet channel splice-out <id> <sats> <feerate> --api-key k` read
 * filteredArgs[5] as the optional address, so the literal string --api-key
 * was sent to the daemon and the otherwise valid command was refused. The
 * command now resolves its positionals with the global flag/value pairs
 * removed. This spawns the real CLI (like cli-help-exit.test.ts) against an
 * offline daemon: the child's HOME points at a temp dir whose pid file names
 * the daemon's ephemeral port.
 */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const UNKNOWN_CHANNEL_ID = 'ab'.repeat(32);

const REPO_ROOT = path.resolve(__dirname, '..', '..');

function runCli(
	home: string,
	args: string[]
): Promise<{ stdout: string; code: number | null }> {
	return new Promise((resolve, reject) => {
		const child = spawn(
			process.execPath,
			['-r', 'ts-node/register', path.join('src', 'cli', 'cli.ts'), ...args],
			{
				cwd: REPO_ROOT,
				env: { ...process.env, HOME: home },
				stdio: ['ignore', 'pipe', 'pipe']
			}
		);
		let stdout = '';
		child.stdout.on('data', (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.stderr.on('data', () => {
			// Drained so a chatty child cannot block on a full pipe.
		});
		child.on('error', reject);
		child.on('close', (code) => resolve({ stdout, code }));
	});
}

describe('CLI splice-out with trailing global flags', function () {
	// Each child loads the CLI through ts-node.
	this.timeout(120_000);

	const dataDir = fs.mkdtempSync(
		path.join(os.tmpdir(), 'beignet-splice-out-cli-')
	);
	const home = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-cli-home-'));
	let daemon: IStartedDaemon;

	before(async () => {
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
		const port = (daemon.server.address() as AddressInfo).port;
		fs.mkdirSync(path.join(home, '.beignet'), { recursive: true });
		fs.writeFileSync(
			path.join(home, '.beignet', 'daemon.pid'),
			JSON.stringify({ pid: process.pid, port })
		);
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
		fs.rmSync(home, { recursive: true, force: true });
	});

	it('an omitted address plus --api-key does not send the flag as the address', async () => {
		const { stdout, code } = await runCli(home, [
			'channel',
			'splice-out',
			UNKNOWN_CHANNEL_ID,
			'50000',
			'2500',
			'--api-key',
			'whatever'
		]);
		const parsed = JSON.parse(stdout) as {
			ok: boolean;
			result?: { ok: boolean; error?: string };
			error?: { code: string; message: string };
		};
		// The regression sent "--api-key" as the address and the daemon
		// refused INVALID_PARAMS naming destinationAddress. Reaching the
		// channel lookup instead proves no address was sent. The refusal is a
		// failure envelope, so the command exits non-zero (issue #618): it
		// used to print the refusal and exit 0.
		expect(parsed.ok).to.equal(false);
		expect(parsed.error?.code).to.equal('CHANNEL_NOT_FOUND');
		expect(parsed.error?.message).to.include('Channel not found');
		expect(code).to.equal(1);
	});

	it('a present address is still sent when global flags trail it', async () => {
		const { stdout } = await runCli(home, [
			'channel',
			'splice-out',
			UNKNOWN_CHANNEL_ID,
			'50000',
			'2500',
			'not-an-address',
			'--api-key',
			'whatever'
		]);
		const parsed = JSON.parse(stdout) as {
			ok: boolean;
			error?: { code: string; message: string };
		};
		// The invalid address must reach the daemon: an INVALID_PARAMS refusal
		// naming destinationAddress proves the positional was forwarded, not
		// swallowed by the flag stripping.
		expect(parsed.ok).to.equal(false);
		expect(parsed.error?.code).to.equal('INVALID_PARAMS');
		expect(parsed.error?.message).to.include('destinationAddress');
	});
});
