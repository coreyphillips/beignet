/**
 * The JIT CLI commands with the LSP left out (issue #1922, step 2a).
 *
 * `invoice jit` and `jit quote` took the LSP as their first positional and
 * refused without it. Now a leading argument that is a node pubkey is the
 * LSP and everything after it shifts up; without one, the amount comes
 * first and the daemon steers the receive through the ranked primaries. The
 * cells spawn the built CLI against a daemon whose node methods are stubbed,
 * so what reaches the node is what is checked.
 */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as sinon from 'sinon';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import type { ApiResponse } from '../../src/cli/types';
import { assertDistCliFresh, DIST_CLI } from './helpers/dist-cli';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const LSP = '02' + 'ab'.repeat(32);

interface CliResult {
	exitCode: number | null;
	response: ApiResponse<Record<string, unknown>>;
}

function run(preloadPath: string, args: string[]): Promise<CliResult> {
	const childEnv = { ...process.env };
	delete childEnv.BEIGNET_API_TOKEN;
	delete childEnv.BEIGNET_API_KEY;
	return new Promise((resolve, reject) => {
		const child = spawn(
			process.execPath,
			['-r', preloadPath, DIST_CLI, ...args],
			{ cwd: REPO_ROOT, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] }
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
				resolve({ exitCode, response: JSON.parse(stdout) });
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

describe('CLI invoice jit and jit quote without an LSP', function () {
	this.timeout(120_000);
	let tempDir: string;
	let preloadPath: string;
	let daemon: IStartedDaemon;

	before(assertDistCliFresh);

	before(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-jit-cli-'));
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
			dataDir: tempDir
		});
		const port = (daemon.server.address() as AddressInfo).port;
		const configPath = path.join(path.dirname(DIST_CLI), 'config.js');
		preloadPath = path.join(tempDir, 'cli-config.js');
		fs.writeFileSync(
			preloadPath,
			`const config = require(${JSON.stringify(configPath)});
config.getDaemonPort = () => ${port};
config.loadConfig = () => ({});
`
		);
	});

	afterEach(() => sinon.restore());

	after(async () => {
		await daemon?.stop();
		if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it('invoice jit: a leading pubkey is the LSP, and without one the amount comes first', async () => {
		const create = sinon.stub(daemon.node, 'createJitInvoice').resolves({
			bolt11: 'lnbcrt1stub',
			paymentHash: 'aa'.repeat(32),
			amountSats: 5000,
			lspPubkey: LSP,
			flatFeeSat: 0,
			feePpm: 0,
			feeMode: 'skim'
		});
		const named = await run(preloadPath, [
			'invoice',
			'jit',
			LSP,
			'5000',
			'coffee',
			'--fee-mode',
			'hop'
		]);
		expect(named.exitCode).to.equal(0);
		expect(named.response.ok).to.equal(true);
		expect(create.firstCall.args[0]).to.include({
			lspPubkey: LSP,
			amountSats: 5000,
			description: 'coffee',
			feeMode: 'hop'
		});

		const steered = await run(preloadPath, [
			'invoice',
			'jit',
			'5000',
			'coffee'
		]);
		expect(steered.exitCode).to.equal(0);
		expect(create.secondCall.args[0]).to.include({
			amountSats: 5000,
			description: 'coffee'
		});
		expect(create.secondCall.args[0].lspPubkey).to.equal(undefined);
	});

	it("invoice jit without an LSP and without primaries is the daemon's refusal, not the CLI's", async () => {
		const { exitCode, response } = await run(preloadPath, [
			'invoice',
			'jit',
			'5000'
		]);
		expect(exitCode).to.equal(1);
		expect(response.ok).to.equal(false);
		expect(response.error?.code).to.equal('INVALID_PARAMS');
		expect(response.error?.message).to.match(
			/lspPubkey is required when no primaries/
		);
	});

	it('jit quote: the same optional leading pubkey', async () => {
		const quote = sinon.stub(daemon.node, 'getJitQuote').resolves({
			lspPubkey: LSP,
			amountSats: 5000,
			accepted: true,
			reason: null,
			flatFeeSat: 0,
			feePpm: 0,
			feeSats: 0,
			maxClientFundingSats: 1_000_000,
			fundingSats: 5000,
			withinCeilings: true,
			client: { maxFlatFeeSat: 10_000, maxFeePpm: 10_000 }
		});
		const named = await run(preloadPath, [
			'jit',
			'quote',
			LSP,
			'5000',
			'--target-inbound',
			'100'
		]);
		expect(named.exitCode).to.equal(0);
		expect(quote.firstCall.args[0]).to.include({
			lspPubkey: LSP,
			amountSats: 5000,
			targetRemainingInboundSat: 100
		});
		const steered = await run(preloadPath, ['jit', 'quote', '5000']);
		expect(steered.exitCode).to.equal(0);
		expect(quote.secondCall.args[0].lspPubkey).to.equal(undefined);
		expect(quote.secondCall.args[0].amountSats).to.equal(5000);
	});
});
