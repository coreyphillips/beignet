/**
 * #2151 step 1, item 2: `beignet init --network regtest --asset-conversion`
 * enrolls a generation 6 wallet. The spawned CLI and the in-process calls use
 * only names that exist on the base (the new flag travels as a loose
 * argument), so each test fails on its behaviour until generation 6 lands.
 */
import { expect } from 'chai';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { mnemonicToSeedSync } from 'bip39';
import { BeignetNode } from '../../src/cli/beignet-node';
import { daemonOptions } from '../../src/cli/daemon-options';
import {
	finalWalletBinding,
	provisionFinalConfig
} from '../../src/cli/final-wallet-init';
import type { BeignetConfig } from '../../src/cli/types';
import { deriveLightningKeysFromSeed } from '../../src/lightning/keys/wallet-keys';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { generateFinalGeneration } from '../lightning/helpers/final-generation';
import { assertDistCliFresh, DIST_CLI } from './helpers/dist-cli';

type Interruption = 'kill-signer';
const otherModes = [
	'--final-commitment-updates',
	'--dual-funded-assets',
	'--asset-splice',
	'--asset-splice-recovery'
];

// Kill the real CLI right after it links the canonical signer, leaving the
// pending init file of the generation it was asked for.
const interruptAtSigner = `
const fs = require('node:fs');
const path = require('node:path');
const link = fs.linkSync;
fs.linkSync = function(from, to) {
	const result = link.apply(fs, arguments);
	if (to === path.join(process.env.BEIGNET_DATA_DIR, 'regtest.db.opening-signer'))
		process.kill(process.pid, 'SIGKILL');
	return result;
};
`;

type Provision = (
	configFile: string,
	config: BeignetConfig,
	fallbackDir: (words: string) => string,
	makeConfig: (words: string, dataDir: string) => BeignetConfig,
	...flags: boolean[]
) => BeignetConfig;
const provision = provisionFinalConfig as Provision;
const bindingFor = finalWalletBinding as (
	words: string,
	generation: number
) => ReturnType<typeof finalWalletBinding>;

describe('Asset conversion wallet CLI initialization (#2151 step 1, item 2)', function () {
	this.timeout(150000);
	let home: string,
		dataDir: string,
		config: string,
		pending: string,
		db: string;
	let preload: string;
	before(assertDistCliFresh);
	beforeEach(() => {
		home = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-init-conversion-'));
		dataDir = path.join(home, 'wallet');
		config = path.join(home, '.beignet', 'config.json');
		pending = path.join(path.dirname(config), 'final-wallet-init.pending');
		db = path.join(dataDir, 'regtest.db');
		preload = path.join(home, 'interrupt.cjs');
		fs.mkdirSync(path.dirname(config), { mode: 0o700 });
		fs.writeFileSync(config, JSON.stringify({ dataDir }), { mode: 0o600 });
		fs.writeFileSync(preload, interruptAtSigner);
	});
	afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

	function init(
		flags: string[],
		fault?: Interruption,
		network = 'regtest',
		extraEnv: Record<string, string> = {}
	): { ok: boolean; signal: NodeJS.Signals | null; output: string } {
		const env = Object.fromEntries(
			Object.entries(process.env).filter(([k]) => !k.startsWith('BEIGNET_'))
		);
		const result = spawnSync(
			process.execPath,
			[
				...(fault ? ['-r', preload] : []),
				DIST_CLI,
				'init',
				'--network',
				network,
				...flags
			],
			{
				env: {
					...env,
					HOME: home,
					BEIGNET_DATA_DIR: dataDir,
					...extraEnv
				},
				encoding: 'utf8',
				timeout: 90000
			}
		);
		if (result.error) throw result.error;
		const lastLine = result.stdout.trim().split('\n').pop();
		let ok = false;
		try {
			ok =
				!!lastLine && JSON.parse(lastLine).ok === true && result.status === 0;
		} catch {
			ok = false;
		}
		return { ok, signal: result.signal, output: result.stdout + result.stderr };
	}
	const saved = () => JSON.parse(fs.readFileSync(config, 'utf8'));

	it('writes a pending version 6, then a config with assetConversion, and keeps the generation across retry', () => {
		expect(init(['--asset-conversion'], 'kill-signer').signal).to.equal(
			'SIGKILL'
		);
		expect(JSON.parse(fs.readFileSync(pending, 'utf8')).version).to.equal(6);
		expect(
			init(['--asset-splice-recovery']).ok,
			'another mode on retry'
		).to.equal(false);
		expect(init(['--final-taproot-wallet']).ok, 'plain mode on retry').to.equal(
			false
		);
		const retry = init(['--asset-conversion']);
		expect(retry.ok, retry.output).to.equal(true);
		expect(fs.existsSync(pending)).to.equal(false);
		const written = saved();
		expect(written.assetConversion).to.equal(true);
		expect(written.finalTaprootWallet).to.equal(true);
		expect(written.network).to.equal('regtest');
		for (const field of [
			'finalCommitmentUpdates',
			'dualFundedAssets',
			'assetSplice',
			'assetSpliceRecovery'
		])
			expect(written[field], field).to.equal(undefined);
		expect(daemonOptions(written, 0)).to.have.property('assetConversion', true);
		const store = SqliteStorage.openFinalWallet(
			db,
			bindingFor(written.mnemonic, 6)
		);
		try {
			expect(store.canSignFinalOpening).to.equal(true);
			expect(store.canUpdateFinalCommitments).to.equal(true);
			expect(store.canRecoverAssetSplice).to.equal(true);
		} finally {
			store.close();
		}
		expect(
			init(['--asset-splice-recovery']).ok,
			'mixed with the saved mode'
		).to.equal(false);
		expect(init(['--asset-conversion']).ok, 'rerun of the same mode').to.equal(
			true
		);
	});

	it('refuses the flag together with any other enrollment mode', () => {
		for (const other of otherModes) {
			const result = init(['--asset-conversion', other]);
			expect(result.ok, other).to.equal(false);
			expect(result.output, other).to.contain(
				'Select one final wallet enrollment mode'
			);
			expect(fs.existsSync(db), other).to.equal(false);
			expect(fs.existsSync(pending), other).to.equal(false);
		}
	});

	it('refuses mainnet and a supplied mnemonic', () => {
		const mainnet = init(['--asset-conversion'], undefined, 'mainnet');
		expect(mainnet.ok).to.equal(false);
		expect(mainnet.output).to.contain(
			'Final wallet initialization requires a new regtest mnemonic'
		);
		expect(saved().mnemonic).to.equal(undefined);
		const supplied = init(['--asset-conversion'], undefined, 'regtest', {
			BEIGNET_MNEMONIC:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
		});
		expect(supplied.ok).to.equal(false);
		expect(fs.existsSync(db)).to.equal(false);
	});
});

describe('Asset conversion enrollment in process (#2151 step 1, items 1 and 2)', function () {
	this.timeout(60000);
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-conversion-provision-')
		);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	it('binds only assetConversion for generation 6', () => {
		const { mnemonic } = generateFinalGeneration(6);
		const binding = bindingFor(mnemonic, 6);
		expect(binding).to.include({
			network: 'regtest',
			finalCommitmentUpdates: false,
			dualFundedAssets: false,
			assetSplice: false,
			assetSpliceRecovery: false,
			assetConversion: true
		});
		expect(bindingFor(mnemonic, 5)).to.not.have.property(
			'assetConversion',
			true
		);
	});

	function pendingWallet() {
		const fresh = generateFinalGeneration(6);
		const dataDir = path.join(dir, 'wallet');
		fs.mkdirSync(dataDir, { mode: 0o700 });
		SqliteStorage.createFinalWallet(
			path.join(dataDir, 'regtest.db'),
			fresh.binding
		).close();
		const configFile = path.join(dir, 'config.json');
		const pendingFile = path.join(dir, 'final-wallet-init.pending');
		fs.writeFileSync(
			pendingFile,
			JSON.stringify({
				version: 6,
				base: 'ab'.repeat(32),
				mnemonic: fresh.mnemonic,
				dataDir
			}),
			{ mode: 0o600 }
		);
		const config: BeignetConfig = {
			mnemonic: fresh.mnemonic,
			dataDir,
			network: 'regtest',
			finalTaprootWallet: true
		};
		return { configFile, pendingFile, config, dataDir };
	}
	const never = (): BeignetConfig => {
		throw new Error('A complete pending wallet is not regenerated');
	};

	it('completes a pending version 6 under its generation 6 config', () => {
		const { configFile, pendingFile, config, dataDir } = pendingWallet();
		const complete = { ...config, assetConversion: true } as BeignetConfig;
		expect(
			provision(
				configFile,
				complete,
				() => dataDir,
				never,
				false,
				false,
				false,
				false,
				true
			)
		).to.equal(complete);
		expect(fs.existsSync(pendingFile)).to.equal(false);
	});

	it('refuses a pending version 6 under a generation 5 config', () => {
		const { configFile, pendingFile, config, dataDir } = pendingWallet();
		const recovery = { ...config, assetSpliceRecovery: true };
		expect(() =>
			provision(
				configFile,
				recovery,
				() => dataDir,
				never,
				false,
				false,
				false,
				false,
				true
			)
		).to.throw('Wallet configuration changed during final initialization');
		expect(() =>
			provision(
				configFile,
				recovery,
				() => dataDir,
				never,
				false,
				false,
				false,
				true
			)
		).to.throw('Pending final wallet requires the original enrollment mode');
		expect(fs.existsSync(pendingFile)).to.equal(true);
	});
});

describe('Asset conversion daemon options (#2151 step 1, item 2)', function () {
	this.timeout(60000);
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-conversion-daemon-'));
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
	const offline = {
		network: 'regtest' as const,
		finalTaprootWallet: true,
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		autoBootstrap: false,
		autoReconnect: false,
		logLevel: 'silent' as const
	};
	async function refused(options: object): Promise<void> {
		let node: BeignetNode | undefined, error: unknown;
		try {
			node = await BeignetNode.create(
				options as Parameters<typeof BeignetNode.create>[0]
			);
		} catch (e) {
			error = e;
		} finally {
			await node?.destroy();
		}
		expect(error, JSON.stringify(options)).to.be.instanceOf(Error);
	}

	it('passes the config flag to the node, which enrolls and reopens a generation 6 original', async () => {
		const options = daemonOptions(
			{
				network: 'regtest',
				finalTaprootWallet: true,
				assetConversion: true
			} as BeignetConfig,
			0
		);
		expect(options).to.have.property('assetConversion', true);
		const fresh = await BeignetNode.create({
			...offline,
			...options,
			dataDir: dir
		});
		let words: string;
		try {
			words = fresh.getMnemonic();
			const store = (fresh as unknown as { sqlite(): SqliteStorage }).sqlite();
			expect(store.canUpdateFinalCommitments).to.equal(true);
			expect(store.canRecoverAssetSplice).to.equal(true);
			expect(
				(store as unknown as Record<string, unknown>).supportsAssetConversion
			).to.equal(true);
		} finally {
			await fresh.destroy();
		}
		const reopen = await BeignetNode.create({
			...offline,
			...options,
			dataDir: dir,
			mnemonic: words
		});
		try {
			expect(reopen.getInfo().nodeId).to.equal(
				deriveLightningKeysFromSeed(
					mnemonicToSeedSync(words),
					1
				).nodePublicKey.toString('hex')
			);
		} finally {
			await reopen.destroy();
		}
		await refused({
			...offline,
			dataDir: dir,
			mnemonic: words,
			assetSpliceRecovery: true
		});
		await refused({ ...offline, dataDir: dir, mnemonic: words });
	});

	it('refuses the mode with any other mode, without a final wallet, or off regtest', async () => {
		for (const other of [
			{ finalCommitmentUpdates: true },
			{ dualFundedAssets: true },
			{ assetSplice: true },
			{ assetSpliceRecovery: true },
			{ finalTaprootWallet: false },
			{ network: 'testnet' }
		])
			await refused({
				...offline,
				dataDir: path.join(dir, Object.keys(other)[0]),
				assetConversion: true,
				...other
			});
		await refused({
			...offline,
			dataDir: path.join(dir, 'bad'),
			assetConversion: 1
		});
		expect(
			fs.existsSync(path.join(dir, 'assetSpliceRecovery', 'regtest.db'))
		).to.equal(false);
	});
});
