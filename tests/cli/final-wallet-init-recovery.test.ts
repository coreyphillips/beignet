import { expect } from 'chai';
import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { mnemonicToSeedSync } from 'bip39';
import { BeignetNode } from '../../src/cli/beignet-node';
import { daemonOptions } from '../../src/cli/daemon-options';
import { deriveLightningKeysFromSeed } from '../../src/lightning/keys/wallet-keys';
import { assertDistCliFresh, DIST_CLI } from './helpers/dist-cli';

type Interruption = 'eacces' | 'kill' | 'kill-signer';
const importedWords =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const digest = (value: string): string =>
	createHash('sha256').update(value).digest('hex');

// Interrupt the real CLI at either file publication boundary. The child records
// only the pending mnemonic digest and, when applicable, the staged wallet inode.
const interruptPromotion = `
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const link = fs.linkSync;
fs.linkSync = function(from, to) {
	const result = link.apply(fs, arguments);
	if (process.env.INIT_TEST_FAULT === 'kill-signer' &&
		to === path.join(process.env.BEIGNET_DATA_DIR, 'regtest.db.opening-signer')) {
		const wallet = from.slice(0, -'.opening-signer'.length);
		fs.writeFileSync(path.join(process.env.HOME, 'staged-wallet-inode'), String(fs.statSync(wallet).ino));
		const pending = path.join(process.env.HOME, '.beignet', 'final-wallet-init.pending');
		const {mnemonic} = JSON.parse(fs.readFileSync(pending, 'utf8'));
		const digest = crypto.createHash('sha256').update(mnemonic).digest('hex');
		fs.writeFileSync(path.join(process.env.HOME, 'interrupted'), digest);
		process.kill(process.pid, 'SIGKILL');
	}
	return result;
};
const rename = fs.renameSync;
fs.renameSync = function(from, to) {
	if (to === path.join(process.env.HOME, '.beignet', 'config.json') &&
		fs.existsSync(path.join(process.env.BEIGNET_DATA_DIR, 'regtest.db.opening-signer'))) {
		const {mnemonic} = JSON.parse(fs.readFileSync(from, 'utf8'));
		const digest = crypto.createHash('sha256').update(mnemonic).digest('hex');
		fs.writeFileSync(path.join(process.env.HOME, 'interrupted'), digest);
		if (process.env.INIT_TEST_FAULT === 'kill') process.kill(process.pid, 'SIGKILL');
		throw Object.assign(new Error('Injected config publication failure'), {code: 'EACCES'});
	}
	return rename.apply(fs, arguments);
};
`;

describe('Final wallet CLI initialization recovery', function () {
	this.timeout(150000);
	let home: string, dataDir: string, config: string, pending: string;
	let db: string, signer: string, preload: string;
	before(assertDistCliFresh);
	beforeEach(() => {
		home = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-init-recovery-'));
		dataDir = path.join(home, 'wallet');
		config = path.join(home, '.beignet', 'config.json');
		pending = path.join(path.dirname(config), 'final-wallet-init.pending');
		db = path.join(dataDir, 'regtest.db');
		signer = db + '.opening-signer';
		preload = path.join(home, 'interrupt.cjs');
		fs.mkdirSync(path.dirname(config), { mode: 0o700 });
		fs.writeFileSync(config, JSON.stringify({ dataDir }), { mode: 0o600 });
		fs.writeFileSync(preload, interruptPromotion);
	});
	afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

	function init(
		fault?: Interruption,
		targetHome = home,
		updates = false,
		assets = false,
		splice = false,
		recovery = false
	): {
		ok: boolean;
		signal: NodeJS.Signals | null;
	} {
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
				'regtest',
				...(assets ? ['--dual-funded-assets'] : ['--final-taproot-wallet']),
				...(updates ? ['--final-commitment-updates'] : []),
				...(splice ? ['--asset-splice'] : []),
				...(recovery ? ['--asset-splice-recovery'] : [])
			],
			{
				env: {
					...env,
					HOME: targetHome,
					BEIGNET_DATA_DIR: path.join(targetHome, 'wallet'),
					INIT_TEST_FAULT: fault
				},
				encoding: 'utf8',
				timeout: 90000
			}
		);
		if (result.error) throw result.error;
		const lastLine = result.stdout.trim().split('\n').pop();
		const ok =
			!!lastLine && JSON.parse(lastLine).ok === true && result.status === 0;
		return { ok, signal: result.signal };
	}

	function interrupt(fault: Interruption): string {
		const outcome = init(fault);
		expect(outcome.ok).to.equal(false);
		expect(outcome.signal).to.equal(fault === 'eacces' ? null : 'SIGKILL');
		return fs.readFileSync(path.join(home, 'interrupted'), 'utf8');
	}

	for (const [fault, boundary] of [
		['eacces', 'config publication'],
		['kill', 'config publication'],
		['kill-signer', 'the first canonical signer link']
	] as const) {
		it(`starts the same enrolled wallet after ${fault} at ${boundary}`, async () => {
			const original = interrupt(fault);
			if (fault === 'kill-signer') expect(fs.existsSync(db)).to.equal(false);
			const dbInode =
				fault === 'kill-signer'
					? Number(
							fs.readFileSync(path.join(home, 'staged-wallet-inode'), 'utf8')
					  )
					: fs.statSync(db).ino;
			const signerInode = fs.statSync(signer).ino;
			expect(init().ok, 'init retry after interrupted publication').to.equal(
				true
			);
			const saved = JSON.parse(fs.readFileSync(config, 'utf8'));
			expect(digest(saved.mnemonic)).to.equal(original);
			expect(saved.finalTaprootWallet).to.equal(true);
			expect(fs.statSync(db).ino).to.equal(dbInode);
			expect(fs.statSync(signer).ino).to.equal(signerInode);
			expect(fs.existsSync(pending)).to.equal(false);
			const node = await BeignetNode.create({
				mnemonic: saved.mnemonic,
				network: saved.network,
				dataDir: saved.dataDir,
				finalTaprootWallet: saved.finalTaprootWallet,
				electrumHost: '127.0.0.1',
				electrumPort: 65529,
				electrumTls: false,
				autoBootstrap: false,
				autoReconnect: false,
				logLevel: 'silent'
			});
			try {
				const keys = deriveLightningKeysFromSeed(
					mnemonicToSeedSync(saved.mnemonic),
					1
				);
				expect(node.getInfo().nodeId).to.equal(
					keys.nodePublicKey.toString('hex')
				);
			} finally {
				await node.destroy();
			}
		});
	}

	it('preserves an unrelated original signer at an interrupted wallet link', () => {
		interrupt('kill-signer');
		const originalSignerInode = fs.statSync(signer).ino;
		const foreignHome = fs.mkdtempSync(path.join(home, 'other-'));
		expect(init(undefined, foreignHome).ok).to.equal(true);
		const foreignSigner = path.join(
			foreignHome,
			'wallet',
			'regtest.db.opening-signer'
		);
		const foreignInode = fs.statSync(foreignSigner).ino;
		fs.renameSync(signer, signer + '.saved');
		fs.linkSync(foreignSigner, signer);
		const foreignModified = fs.statSync(signer).mtimeMs;
		const originalModified = fs.statSync(signer + '.saved').mtimeMs;
		expect(init().ok).to.equal(false);
		expect(fs.existsSync(db)).to.equal(false);
		expect(fs.statSync(signer).ino).to.equal(foreignInode);
		expect(fs.statSync(signer + '.saved').ino).to.equal(originalSignerInode);
		expect(fs.statSync(signer).mtimeMs).to.equal(foreignModified);
		expect(fs.statSync(signer + '.saved').mtimeMs).to.equal(originalModified);
		expect(fs.existsSync(pending)).to.equal(true);
	});

	it('preserves a conflicting config and its interrupted original on retry', () => {
		interrupt('kill');
		const dbInode = fs.statSync(db).ino;
		const signerInode = fs.statSync(signer).ino;
		const unrelated = JSON.stringify({
			mnemonic: importedWords,
			network: 'regtest',
			dataDir,
			finalTaprootWallet: true
		});
		fs.writeFileSync(config, unrelated);
		expect(init().ok).to.equal(false);
		expect(digest(fs.readFileSync(config, 'utf8'))).to.equal(digest(unrelated));
		expect(fs.statSync(db).ino).to.equal(dbInode);
		expect(fs.statSync(signer).ino).to.equal(signerInode);
	});

	it('recovers a pending update-enabled original only with its original init mode', () => {
		const failed = init('kill', home, true);
		expect(failed.signal).to.equal('SIGKILL');
		expect(JSON.parse(fs.readFileSync(pending, 'utf8')).version).to.equal(2);
		expect(init().ok).to.equal(false);
		expect(init(undefined, home, true).ok).to.equal(true);
		expect(
			JSON.parse(fs.readFileSync(config, 'utf8')).finalCommitmentUpdates
		).to.equal(true);
		expect(fs.existsSync(pending)).to.equal(false);
	});
	it('restarts the same asset original after an interrupted init and refuses a changed generation', async () => {
		expect(init(undefined, home, true, true).ok).to.equal(false);
		expect(fs.existsSync(db)).to.equal(false);
		expect(init('kill-signer', home, false, true).signal).to.equal('SIGKILL');
		expect(JSON.parse(fs.readFileSync(pending, 'utf8')).version).to.equal(3);
		expect(init(undefined, home, true).ok).to.equal(false);
		expect(init(undefined, home, false, true).ok).to.equal(true);
		const saved = JSON.parse(fs.readFileSync(config, 'utf8'));
		expect(saved.dualFundedAssets).to.equal(true);
		expect(saved.finalCommitmentUpdates).to.equal(undefined);
		const opts = {
			...daemonOptions(saved, 0),
			network: 'regtest' as const,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			autoBootstrap: false,
			autoReconnect: false,
			logLevel: 'silent' as const
		};
		const node = await BeignetNode.create(opts);
		try {
			expect(node.getInfo().nodeId).to.equal(
				deriveLightningKeysFromSeed(
					mnemonicToSeedSync(saved.mnemonic),
					1
				).nodePublicKey.toString('hex')
			);
		} finally {
			await node.destroy();
		}
		expect(init(undefined, home, true).ok).to.equal(false);
	});
	it('retains the original asset splice enrollment through interrupted publication', async () => {
		expect(init(undefined, home, false, true, true).ok).to.equal(false);
		expect(fs.existsSync(db)).to.equal(false);
		expect(init('kill-signer', home, false, false, true).signal).to.equal(
			'SIGKILL'
		);
		expect(JSON.parse(fs.readFileSync(pending, 'utf8')).version).to.equal(4);
		expect(init(undefined, home, false, true).ok).to.equal(false);
		expect(init(undefined, home, false, false, true).ok).to.equal(true);
		const saved = JSON.parse(fs.readFileSync(config, 'utf8'));
		expect(saved.assetSplice).to.equal(true);
		expect(saved.dualFundedAssets).to.equal(undefined);
		const options = daemonOptions(saved, 0);
		expect(options.assetSplice).to.equal(true);
		const node = await BeignetNode.create({
			...options,
			network: 'regtest',
			autoBootstrap: false,
			autoReconnect: false,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			logLevel: 'silent'
		});
		try {
			expect(node.getInfo().nodeId).to.equal(
				deriveLightningKeysFromSeed(
					mnemonicToSeedSync(saved.mnemonic),
					1
				).nodePublicKey.toString('hex')
			);
		} finally {
			await node.destroy();
		}
	});
	it('enrolls a separate recovery-capable regtest wallet and preserves its generation across retry', () => {
		const enroll = (fault?: Interruption) =>
			init(fault, home, false, false, false, true);
		expect(init(undefined, home, false, false, true, true).ok).to.equal(false);
		expect(fs.existsSync(db)).to.equal(false);
		expect(enroll('kill-signer').signal).to.equal('SIGKILL');
		expect(JSON.parse(fs.readFileSync(pending, 'utf8')).version).to.equal(5);
		expect(init(undefined, home, false, false, true).ok).to.equal(false);
		expect(enroll().ok).to.equal(true);
		const saved = JSON.parse(fs.readFileSync(config, 'utf8'));
		expect(saved.assetSpliceRecovery).to.equal(true);
		expect(saved.assetSplice).to.equal(undefined);
		expect(daemonOptions(saved, 0)).to.have.property(
			'assetSpliceRecovery',
			true
		);
		expect(init(undefined, home, false, false, true).ok).to.equal(false);
	});

	it('cannot enroll a supplied pending mnemonic without its original device', () => {
		const original = interrupt('kill');
		expect(fs.existsSync(pending)).to.equal(true);
		if (process.platform !== 'win32') {
			expect(fs.statSync(pending).mode & 0o077).to.equal(0);
		}
		fs.renameSync(dataDir, path.join(home, 'original-device'));
		if (init().ok) {
			const saved = JSON.parse(fs.readFileSync(config, 'utf8'));
			expect(digest(saved.mnemonic)).not.to.equal(original);
		} else {
			expect(fs.existsSync(signer)).to.equal(false);
			expect(fs.existsSync(db)).to.equal(false);
		}
	});
});
