/**
 * CLI direct funding: a local flag never becomes the optional amount (issue
 * #613, LFBW port #532 workstream 4D).
 *
 * `request` and `send` both end in an optional amount, so a raw positional read
 * turned `direct-funding request --host h` into an amount of "--host": NaN,
 * serialized as null, refused by the daemon as INVALID_PARAMS. Same shape as the
 * issue #534 splice-out bug, and the same fix, with the command's own value
 * flags stripped alongside the global ones. Spawns the real CLI against an
 * offline daemon, as splice-out-cli-flags.test.ts does.
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

const REPO_ROOT = path.resolve(__dirname, '..', '..');

interface ICliResult {
	ok: boolean;
	result?: Record<string, unknown>;
	error?: { code: string; message: string };
}

function runCli(home: string, args: string[]): Promise<ICliResult> {
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
		child.on('close', () => resolve(JSON.parse(stdout) as ICliResult));
	});
}

describe('CLI direct funding with trailing local flags', function () {
	// Each child loads the CLI through ts-node.
	this.timeout(120_000);

	const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-df-cli-'));
	const home = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-df-cli-home-'));
	let daemon: IStartedDaemon;
	let request: string;

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
		request = daemon.node.createDirectFundingRequest({}).request;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
		fs.rmSync(home, { recursive: true, force: true });
	});

	it('mints a request when the address flags follow the omitted amount', async () => {
		const parsed = await runCli(home, [
			'direct-funding',
			'request',
			'--host',
			'node.example',
			'--port',
			'9735'
		]);
		// The regression sent amountSats: null and the daemon refused it, so an
		// operator could not mint an open-amount request from the CLI at all.
		expect(parsed.ok).to.equal(true);
		expect(parsed.result?.request).to.be.a('string');
	});

	it('keeps a named amount when it is there', async () => {
		const parsed = await runCli(home, [
			'direct-funding',
			'request',
			'120000',
			'--host',
			'node.example'
		]);
		expect(parsed.ok).to.equal(true);
		expect(parsed.result?.request).to.be.a('string');
	});

	it('sends with no amount when only the fee ceiling follows the request', async () => {
		const parsed = await runCli(home, [
			'direct-funding',
			'send',
			request,
			'--max-total-fee',
			'1000'
		]);
		// AMOUNT_REQUIRED is the daemon reading an absent amount. The regression
		// read "--max-total-fee" as the amount and was refused INVALID_PARAMS
		// before the request was ever looked at.
		expect(parsed.error?.code).to.equal('AMOUNT_REQUIRED');
	});

	it('still forwards an amount that precedes the fee ceiling', async () => {
		const parsed = await runCli(home, [
			'direct-funding',
			'send',
			request,
			'50000',
			'--max-total-fee',
			'1000'
		]);
		// This wallet holds no coins, so reaching coin selection is what proves
		// the amount arrived.
		expect(parsed.error?.code).to.equal('NO_SUITABLE_UTXO');
	});
});
