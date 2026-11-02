/** CLI threshold validation must preserve the saved policy on invalid input. */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import type { ApiResponse, PrimariesInfo } from '../../src/cli/types';
import { PRIMARIES_STORAGE_KEY } from '../../src/lightning/liquidity/primaries';
import { assertDistCliFresh, DIST_CLI } from './helpers/dist-cli';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const REPO_ROOT = path.resolve(__dirname, '..', '..');

interface CliResult {
	exitCode: number | null;
	response: ApiResponse<PrimariesInfo>;
}

function runThreshold(preloadPath: string, value: string): Promise<CliResult> {
	const childEnv = { ...process.env };
	delete childEnv.BEIGNET_API_TOKEN;
	delete childEnv.BEIGNET_API_KEY;
	return new Promise((resolve, reject) => {
		const child = spawn(
			process.execPath,
			['-r', preloadPath, DIST_CLI, 'primaries', 'threshold', value],
			{
				cwd: REPO_ROOT,
				env: childEnv,
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
		child.on('error', reject);
		child.on('close', (exitCode) => {
			try {
				resolve({
					exitCode,
					response: JSON.parse(stdout) as ApiResponse<PrimariesInfo>
				});
			} catch {
				reject(
					new Error(
						`CLI exited ${exitCode} with invalid JSON: ${stdout}\n${stderr}`
					)
				);
			}
		});
	});
}

describe('CLI primaries threshold', function () {
	this.timeout(120_000);
	let tempDir: string;
	let preloadPath: string;
	let daemon: IStartedDaemon;

	before(assertDistCliFresh);

	before(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-primaries-cli-'));
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
			dataDir: path.join(tempDir, 'data')
		});
		const port = (daemon.server.address() as AddressInfo).port;
		const configPath = path.join(path.dirname(DIST_CLI), 'config.js');
		preloadPath = path.join(tempDir, 'cli-config.js');
		// Keep the real CLI and HTTP path while isolating the user's config.
		fs.writeFileSync(
			preloadPath,
			`const config = require(${JSON.stringify(configPath)});
config.getDaemonPort = () => ${port};
config.loadConfig = () => ({});
`
		);
	});

	beforeEach(() => {
		daemon.node.setPrimariesFillThreshold(1_000_000);
	});

	after(async () => {
		await daemon?.stop();
		if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
	});

	for (const value of [
		'10k',
		'banana',
		'NaN',
		'Infinity',
		'-Infinity',
		'1e309',
		'   ',
		'-1',
		'1.5',
		'9007199254740992'
	]) {
		it(`rejects ${JSON.stringify(
			value
		)} without changing the saved threshold`, async () => {
			const storage = daemon.node.getStorage();
			const savedBefore = storage.loadWalletData(PRIMARIES_STORAGE_KEY);
			const { exitCode, response } = await runThreshold(preloadPath, value);

			expect(exitCode).to.equal(1);
			expect(response.ok).to.equal(false);
			expect(response.error?.code).to.equal('INVALID_PARAMS');
			expect(daemon.node.listPrimaries().fillThresholdSat).to.equal(1_000_000);
			expect(storage.loadWalletData(PRIMARIES_STORAGE_KEY)).to.equal(
				savedBefore
			);
		});
	}

	for (const { value, expected } of [
		{ value: '250000', expected: 250_000 },
		{ value: '0', expected: 0 },
		{ value: 'none', expected: null }
	]) {
		it(`sets the threshold with ${JSON.stringify(value)}`, async () => {
			const { exitCode, response } = await runThreshold(preloadPath, value);

			expect(exitCode).to.equal(0);
			expect(response.ok).to.equal(true);
			expect(response.result?.fillThresholdSat).to.equal(expected);
			expect(daemon.node.listPrimaries().fillThresholdSat).to.equal(expected);
		});
	}
});
