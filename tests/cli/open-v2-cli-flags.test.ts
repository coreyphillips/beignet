/**
 * CLI channel open-v2: lease flags and positional hygiene (issue #532
 * workstream 1B).
 *
 * open-v2 read raw filteredArgs, the bug class the issue #534 review caught
 * on splice-out: with the optional feerate omitted, a trailing global flag
 * token became the feerate and the daemon refused an otherwise valid command.
 * The command now resolves positionals with both the global and its own
 * value flags stripped. The new flags drive the liquidity-ads buyer params:
 * --request-funds/--blockheight become requestFunds and --max-lease-rates
 * (JSON) becomes maxLeaseRates. Spawns the real CLI against an offline
 * daemon like splice-out-cli-flags.test.ts.
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

const PEER = '02' + 'ab'.repeat(32);

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

interface ICliResult {
	ok: boolean;
	error?: { code: string; message: string };
}

describe('CLI open-v2 lease flags', function () {
	// Each child loads the CLI through ts-node.
	this.timeout(120_000);

	const dataDir = fs.mkdtempSync(
		path.join(os.tmpdir(), 'beignet-open-v2-cli-')
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

	it('an omitted feerate plus a trailing flag is not read as the feerate', async () => {
		// The regression parsed '--api-key' with parseInt, sent NaN as
		// fundingFeeratePerkw and the daemon refused INVALID_PARAMS. Fixed,
		// the open reaches the peer lookup instead: a scrubbed internal
		// error, not a request refusal.
		const { stdout } = await runCli(home, [
			'channel',
			'open-v2',
			PEER,
			'100000',
			'--api-key',
			'whatever'
		]);
		const parsed = JSON.parse(stdout) as ICliResult;
		expect(parsed.ok).to.equal(false);
		expect(parsed.error?.code).to.not.equal('INVALID_PARAMS');
	});

	it('the lease flags reach the daemon as requestFunds', async () => {
		// --request-funds without --max-lease-rates must draw the library's
		// pairing refusal, which proves the flag crossed CLI -> daemon ->
		// BeignetNode -> library intact.
		const { stdout } = await runCli(home, [
			'channel',
			'open-v2',
			PEER,
			'100000',
			'--request-funds',
			'50000',
			'--blockheight',
			'100'
		]);
		const parsed = JSON.parse(stdout) as ICliResult;
		expect(parsed.ok).to.equal(false);
		expect(parsed.error?.code).to.equal('INVALID_PARAMS');
		expect(parsed.error?.message).to.include('maxLeaseRates');
	});

	it('lease flag tokens are never read as positionals', async () => {
		// With the feerate omitted, '--request-funds' sits where a raw index
		// read would take the feerate from; local-flag stripping must keep
		// the positional empty just as it does for the global flags.
		const { stdout } = await runCli(home, [
			'channel',
			'open-v2',
			PEER,
			'100000',
			'--request-funds',
			'50000',
			'--blockheight',
			'100',
			'--max-lease-rates',
			JSON.stringify({
				fundingWeightWitness: 1000,
				leaseFeeBasis: 100,
				leaseFeeBaseSat: 10000,
				channelFeeMaxBaseMsat: 5000,
				channelFeeMaxProportionalThousandths: 3
			})
		]);
		const parsed = JSON.parse(stdout) as ICliResult;
		// Everything validated; the open stopped at the unconnected peer.
		expect(parsed.ok).to.equal(false);
		expect(parsed.error?.code).to.not.equal('INVALID_PARAMS');
	});

	it('unparseable --max-lease-rates is refused locally', async () => {
		const { stdout, code } = await runCli(home, [
			'channel',
			'open-v2',
			PEER,
			'100000',
			'--max-lease-rates',
			'not-json'
		]);
		const parsed = JSON.parse(stdout) as ICliResult;
		expect(parsed.ok).to.equal(false);
		expect(parsed.error?.code).to.equal('INVALID_PARAMS');
		expect(parsed.error?.message).to.include('not valid JSON');
		expect(code).to.equal(1);
	});

	it('a failed /info surfaces as itself, not as a blockheight complaint', async () => {
		// Auth-enabled daemon, CLI with no credential: the automatic
		// blockheight lookup's GET /info comes back 401. Rewriting that into
		// "block height unavailable" hid the real problem (issue #536
		// review); the original refusal must reach the operator.
		const authDataDir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-open-v2-auth-')
		);
		const authHome = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-cli-auth-home-')
		);
		const authDaemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic: MNEMONIC,
			daemonPort: 0,
			dataDir: authDataDir,
			apiKeys: [{ name: 'ops', key: 'secret', scopes: ['admin'] }]
		});
		try {
			const authPort = (authDaemon.server.address() as AddressInfo).port;
			fs.mkdirSync(path.join(authHome, '.beignet'), { recursive: true });
			fs.writeFileSync(
				path.join(authHome, '.beignet', 'daemon.pid'),
				JSON.stringify({ pid: process.pid, port: authPort })
			);
			const { stdout, code } = await runCli(authHome, [
				'channel',
				'open-v2',
				PEER,
				'100000',
				'--request-funds',
				'50000'
			]);
			const parsed = JSON.parse(stdout) as ICliResult;
			expect(parsed.ok).to.equal(false);
			expect(parsed.error?.code).to.equal('UNAUTHORIZED');
			expect(parsed.error?.message ?? '').to.not.include('block height');
			expect(code).to.equal(1);
		} finally {
			await authDaemon.stop();
			fs.rmSync(authDataDir, { recursive: true, force: true });
			fs.rmSync(authHome, { recursive: true, force: true });
		}
	});

	it('--request-funds on an unsynced node demands an explicit --blockheight', async () => {
		// The offline daemon's tip is 0; request_funds carries the buyer's
		// blockheight, so the CLI refuses locally rather than sending a
		// height the seller would reject as stale.
		const { stdout, code } = await runCli(home, [
			'channel',
			'open-v2',
			PEER,
			'100000',
			'--request-funds',
			'50000'
		]);
		const parsed = JSON.parse(stdout) as ICliResult;
		expect(parsed.ok).to.equal(false);
		expect(parsed.error?.code).to.equal('INVALID_PARAMS');
		expect(parsed.error?.message).to.include('--blockheight');
		expect(code).to.equal(1);
	});
});
