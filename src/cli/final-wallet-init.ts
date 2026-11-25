import { createHash, randomUUID } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { mnemonicToSeedSync, validateMnemonic } from 'bip39';
import { deriveLightningKeysFromSeed } from '../lightning/keys/wallet-keys';
import { deriveStorageKey } from '../lightning/storage/encryption';
import {
	assertUnusedWalletPath,
	finishStagedDaemonWallet,
	type IFinalWalletBinding
} from '../lightning/storage/final-wallet-format';
import { SIGNER_SUFFIX } from '../lightning/storage/final-opening-authority';
import {
	finalWalletGeneration,
	generateFinalDaemonWallet
} from '../lightning/storage/final-wallet-generation';
import { ensurePrivateDir } from './fs-utils';
import type { BeignetConfig } from './types';

interface Pending {
	version: ReturnType<typeof finalWalletGeneration>;
	base: string;
	mnemonic: string;
	dataDir: string;
}

function syncDir(dir: string): void {
	if (process.platform === 'win32') return;
	const fd = fs.openSync(dir, 'r');
	try {
		fs.fsyncSync(fd);
	} finally {
		fs.closeSync(fd);
	}
}

/** Publish complete seed material before making a wallet visible or retiring its recovery record. */
function publish(file: string, value: object, mnemonic?: string): void {
	const tag = mnemonic
		? createHash('sha256')
				.update('beignet-final-init-stage/' + mnemonic)
				.digest('hex')
		: randomUUID();
	const tmp = file + '.' + tag + '.tmp';
	if (mnemonic && fs.lstatSync(tmp, { throwIfNoEntry: false })) {
		// A kill before the rename can leave this seed-specific stage. Unlink its name
		// before a fresh exclusive create, without writing through a link.
		fs.unlinkSync(tmp);
	}
	const fd = fs.openSync(tmp, 'wx', 0o600);
	try {
		try {
			fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n');
			fs.fsyncSync(fd);
		} finally {
			fs.closeSync(fd);
		}
		fs.renameSync(tmp, file);
		syncDir(path.dirname(file));
	} finally {
		fs.rmSync(tmp, { force: true });
	}
}

function loadPending(file: string): Pending | undefined {
	const stat = fs.lstatSync(file, { throwIfNoEntry: false });
	if (!stat) return;
	if (
		!stat.isFile() ||
		stat.size > 16384 ||
		(process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
	)
		throw new Error('Invalid pending final wallet initialization');
	let p: Pending;
	try {
		p = JSON.parse(fs.readFileSync(file, 'utf8'));
	} catch {
		throw new Error('Invalid pending final wallet initialization');
	}
	if (
		!p ||
		Object.keys(p).sort().join(',') !== 'base,dataDir,mnemonic,version' ||
		![1, 2, 3, 4, 5].includes(p.version) ||
		typeof p.base !== 'string' ||
		!/^[a-f0-9]{64}$/.test(p.base) ||
		typeof p.mnemonic !== 'string' ||
		!validateMnemonic(p.mnemonic) ||
		typeof p.dataDir !== 'string' ||
		path.resolve(p.dataDir) !== p.dataDir
	)
		throw new Error('Invalid pending final wallet initialization');
	return p;
}

export function finalWalletBinding(
	words: string,
	generation: Pending['version']
): IFinalWalletBinding {
	const seed = mnemonicToSeedSync(words);
	return {
		network: 'regtest',
		finalCommitmentUpdates: generation === 2,
		dualFundedAssets: generation === 3,
		assetSplice: generation === 4,
		assetSpliceRecovery: generation === 5,
		nodeId: deriveLightningKeysFromSeed(seed, 1).nodePublicKey.toString('hex'),
		encryptionKey: deriveStorageKey(seed)
	};
}
function verifyEnrolledWallet(
	dataDir: string,
	words: string,
	generation: Pending['version']
): void {
	const { SqliteStorage } =
		require('../lightning/storage/sqlite-storage') as typeof import('../lightning/storage/sqlite-storage');
	const binding = finalWalletBinding(words, generation);
	const store = SqliteStorage.openFinalWallet(
		path.join(dataDir, 'regtest.db'),
		binding
	);
	try {
		store.assertFinalDaemonIdentity(binding.nodeId);
	} finally {
		store.close();
	}
}

/** Complete or recover the generated wallet without converting supplied entropy into a signer. */
export function provisionFinalConfig(
	configFile: string,
	config: BeignetConfig,
	fallbackDir: (words: string) => string,
	makeConfig: (words: string, dataDir: string) => BeignetConfig,
	updates = false,
	assets = false,
	assetSplice = false,
	assetSpliceRecovery = false
): BeignetConfig {
	const generation = finalWalletGeneration(
		updates,
		assets,
		assetSplice,
		assetSpliceRecovery
	);
	const dir = path.dirname(configFile);
	const pendingFile = path.join(dir, 'final-wallet-init.pending');
	const previous = loadPending(pendingFile);
	const base = createHash('sha256')
		.update(JSON.stringify([path.resolve(configFile), config]))
		.digest('hex');
	const target = process.env.BEIGNET_DATA_DIR || config.dataDir;
	const dataDirFor = (words: string): string =>
		path.resolve(target || fallbackDir(words));
	if (!previous && config.mnemonic) {
		verifyEnrolledWallet(
			dataDirFor(config.mnemonic),
			config.mnemonic,
			generation
		);
		return config;
	}
	let pending: Pending | undefined = previous;
	if (pending) {
		if (pending.version !== generation)
			throw new Error(
				'Pending final wallet requires the original enrollment mode'
			);
		const complete =
			config.finalTaprootWallet === true &&
			finalWalletGeneration(
				config.finalCommitmentUpdates,
				config.dualFundedAssets,
				config.assetSplice,
				config.assetSpliceRecovery
			) === generation &&
			config.network === 'regtest' &&
			config.mnemonic === pending.mnemonic &&
			config.dataDir === pending.dataDir;
		if (
			(!complete && (config.mnemonic !== undefined || base !== pending.base)) ||
			(target && path.resolve(target) !== pending.dataDir)
		)
			throw new Error(
				'Wallet configuration changed during final initialization'
			);
		const wallet = path.join(pending.dataDir, 'regtest.db');
		if (
			!complete &&
			!fs.lstatSync(wallet, { throwIfNoEntry: false }) &&
			fs.lstatSync(wallet + SIGNER_SUFFIX, { throwIfNoEntry: false })
		)
			finishStagedDaemonWallet(
				wallet,
				finalWalletBinding(pending.mnemonic, generation)
			);
		if (fs.lstatSync(wallet, { throwIfNoEntry: false })) {
			verifyEnrolledWallet(pending.dataDir, pending.mnemonic, generation);
			if (complete) {
				fs.unlinkSync(pendingFile);
				syncDir(dir);
				return config;
			}
		} else {
			if (complete) throw new Error('Enrolled final wallet is missing');
			assertUnusedWalletPath(wallet);
			// No installed wallet can use this pending seed. A retry may generate a new one.
			pending = undefined;
		}
	}
	if (!pending) {
		const fresh = generateFinalDaemonWallet(
			updates,
			assets,
			assetSplice,
			assetSpliceRecovery
		);
		const dataDir = dataDirFor(fresh.mnemonic);
		ensurePrivateDir(dataDir);
		const file = path.join(dataDir, 'regtest.db');
		assertUnusedWalletPath(file);
		pending = {
			version: generation,
			base,
			mnemonic: fresh.mnemonic,
			dataDir
		};
		publish(pendingFile, pending);
		const { SqliteStorage } =
			require('../lightning/storage/sqlite-storage') as typeof import('../lightning/storage/sqlite-storage');
		SqliteStorage.createFinalWallet(file, fresh.binding).close();
	}
	const result = makeConfig(pending.mnemonic, pending.dataDir);
	publish(configFile, result, pending.mnemonic);
	fs.unlinkSync(pendingFile);
	syncDir(dir);
	return result;
}
