import { expect } from 'chai';
import { rejects } from 'assert';
import { encodeScb } from '../../src/lightning/backup/scb';
import { mnemonicToSeedSync } from 'bip39';
import { entropyToMnemonic } from 'bip39';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { daemonOptions } from '../../src/cli/daemon-options';
import { deriveLightningKeysFromSeed } from '../../src/lightning/keys/wallet-keys';
import { deriveStorageKey } from '../../src/lightning/storage/encryption';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const offline = {
	network: 'regtest' as const,
	finalTaprootWallet: true,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	autoBootstrap: false,
	logLevel: 'silent' as const,
	autoReconnect: false
};
const importedWords = entropyToMnemonic(Buffer.alloc(16, 36));
function binding(
	mnemonic: string
): Parameters<typeof SqliteStorage.openFinalWallet>[1] {
	const seed = mnemonicToSeedSync(mnemonic);
	return {
		network: 'regtest',
		encryptionKey: deriveStorageKey(seed),
		nodeId: deriveLightningKeysFromSeed(seed, 1).nodePublicKey.toString('hex')
	};
}
async function refuses(run: () => Promise<BeignetNode>): Promise<void> {
	let error: unknown;
	let accidental: BeignetNode | undefined;
	try {
		accidental = await run();
	} catch (caught) {
		error = caught;
	} finally {
		await accidental?.destroy();
	}
	expect(error).to.be.instanceOf(Error);
}

describe('Fresh final wallet daemon admission', function () {
	this.timeout(30000);
	let dir: string, file: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-final-daemon-'));
		file = path.join(dir, 'regtest.db');
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	it('forwards the explicit final wallet setting from the CLI config', () => {
		expect(
			daemonOptions({ network: 'regtest', finalTaprootWallet: true }, 0)
				.finalTaprootWallet
		).to.equal(true);
	});

	it('creates an original from new entropy and reopens it under the exact node identity', async () => {
		const fresh = await BeignetNode.create({ ...offline, dataDir: dir });
		let words: string, nodeId: string;
		try {
			words = fresh.getMnemonic();
			nodeId = fresh.getInfo().nodeId;
			expect(nodeId).to.equal(binding(words).nodeId);
			expect(fs.existsSync(file + '.opening-signer')).to.equal(true);
		} finally {
			await fresh.destroy();
		}
		const reboot = await BeignetNode.create({
			...offline,
			dataDir: dir,
			mnemonic: words
		});
		try {
			expect(reboot.getInfo().nodeId).to.equal(nodeId);
		} finally {
			await reboot.destroy();
		}
		const copyDir = path.join(dir, 'recovery');
		fs.mkdirSync(copyDir);
		const store = SqliteStorage.openFinalWallet(file, binding(words));
		try {
			await store.backup(path.join(copyDir, 'regtest.db'));
		} finally {
			store.close();
		}
		await refuses(() =>
			BeignetNode.create({ ...offline, dataDir: copyDir, mnemonic: words })
		);
		expect(
			fs.existsSync(path.join(copyDir, 'regtest.db.opening-signer'))
		).to.equal(false);
		await refuses(() =>
			BeignetNode.create({ ...offline, dataDir: dir, mnemonic: importedWords })
		);
	});

	it('refuses SCB and guardian recovery on an enrolled original', async () => {
		const node = await BeignetNode.create({ ...offline, dataDir: dir });
		try {
			const scb = encodeScb(
				{ version: 1, network: 'bcrt', createdAt: 1, channels: [] },
				mnemonicToSeedSync(node.getMnemonic())
			);
			expect(() => node.exportStaticChannelBackup()).to.throw(/final/i);
			await rejects(() => node.restoreFromScb(scb), /final/i);
			await rejects(
				() => node.restoreFromGuardians(),
				/guardian restore only/i
			);
			await rejects(
				() => node.restoreFromCapsules(),
				/peer-storage mode only/i
			);
			expect(fs.existsSync(path.join(dir, 'channels.scb'))).to.equal(false);
		} finally {
			await node.destroy();
		}
	});

	it('refuses a supplied seed on empty storage, and an independently created signer without generation enrollment', async () => {
		await refuses(() =>
			BeignetNode.create({ ...offline, dataDir: dir, mnemonic: importedWords })
		);
		expect(fs.existsSync(file)).to.equal(false);
		expect(fs.existsSync(file + '.opening-signer')).to.equal(false);
		SqliteStorage.createFinalWallet(file, binding(importedWords)).close();
		await refuses(() =>
			BeignetNode.create({ ...offline, dataDir: dir, mnemonic: importedWords })
		);
	});

	it('refuses unsupported recovery or plaintext state before creating an authority', async () => {
		for (const config of [
			{ recoveryMode: 'peer-storage' as const },
			{ storageEncryption: false }
		]) {
			await refuses(() =>
				BeignetNode.create({ ...offline, dataDir: dir, ...config })
			);
			expect(fs.existsSync(file + '.opening-signer')).to.equal(false);
		}
	});
});
