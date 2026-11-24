import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import sinon from 'sinon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { writeBackupMac } from '../../src/cli/backup-mac';
import { performDbRestore } from '../../src/cli/restore';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { encodeScb } from '../../src/lightning/backup/scb';
import {
	encryptRecoveryCapsule,
	restoreFromRecoveryCapsule,
	restoreBestRecoveryCapsule
} from '../../src/lightning/recovery/capsule';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { makeNodeConfig } from './helpers/loopback-nodes';
import { wallet } from './helpers/final-opening';
import {
	basepointsOf,
	privAt,
	seedFor
} from './helpers/taproot-revoked-fixture';

const finalWalletError = /final.*(wallet|format)|wallet.*format/i;

async function rejection(run: () => Promise<unknown>): Promise<unknown> {
	try {
		await run();
	} catch (error) {
		return error;
	}
	return undefined;
}

describe('Final wallet admission at live and recovery entry points', () => {
	let directory: string;
	let file: string;

	beforeEach(() => {
		directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-final-admission-')
		);
		file = path.join(directory, 'regtest.db');
	});

	afterEach(() => {
		sinon.restore();
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('refuses injected final storage before the Lightning node reads custody or channels', () => {
		const store = SqliteStorage.createFinalWallet(file, wallet);
		const custody = sinon
			.stub(store, 'loadAllFforVouchers')
			.throws('read custody');
		try {
			const config = makeNodeConfig('final-boundary', 1, store);
			config.nodePrivateKey = privAt(seedFor(170), 0);
			expect(() => new LightningNode(config)).to.throw(finalWalletError);
			expect(custody.called).to.equal(false);
		} finally {
			store.close();
		}
	});

	it('refuses injected final storage before the daemon opens the backend', async () => {
		const store = SqliteStorage.createFinalWallet(file, wallet);
		const open = sinon.stub(store, 'open').throws('called open');
		try {
			const error = await rejection(() =>
				BeignetNode.create({ storage: store, network: 'regtest' })
			);
			expect(error).to.be.instanceOf(Error);
			expect((error as Error).message).to.match(finalWalletError);
			expect(open.called).to.equal(false);
		} finally {
			store.close();
		}
	});

	for (const selection of ['single', 'best']) {
		it(
			'refuses a legacy SCB-only capsule at the ' +
				selection +
				' restore entry point',
			() => {
				const store = SqliteStorage.createFinalWallet(file, wallet);
				const nodeSecret = privAt(seedFor(170), 0);
				const capsule = {
					version: 1 as const,
					encryptedScb: encodeScb(
						{ version: 1, network: 'regtest', createdAt: 1, channels: [] },
						nodeSecret
					),
					generation: 0n,
					writerEpoch: 0n,
					latestSequence: 0n,
					frameHash: Buffer.alloc(32),
					snapshotHash: Buffer.alloc(32),
					guardians: []
				};
				try {
					expect(() => {
						if (selection === 'single')
							return restoreFromRecoveryCapsule(capsule, store, nodeSecret);
						return restoreBestRecoveryCapsule(
							[encryptRecoveryCapsule(capsule, nodeSecret)],
							store,
							nodeSecret,
							{ scratchStorage: () => new MemoryStorage() }
						);
					}).to.throw(finalWalletError);
				} finally {
					store.close();
				}
			}
		);
	}

	for (const moved of [false, true]) {
		it(
			'preserves the final wallet ' +
				(moved
					? 'between the capsule swap renames'
					: 'before a staged capsule swap'),
			async () => {
				SqliteStorage.createFinalWallet(file, wallet).close();
				const staged = 'regtest.db.capsule-restore';
				const keep = 'regtest.db.pre-capsule-restore-test';
				const legacy = new SqliteStorage(path.join(directory, staged));
				legacy.open();
				legacy.close();
				const marker = path.join(directory, 'regtest.capsule-restore.json');
				fs.writeFileSync(
					marker,
					JSON.stringify({
						version: 1,
						tier: 2,
						stagedAt: 1,
						staged,
						keep,
						head: { writerEpoch: '0', latestSequence: '0' }
					})
				);
				if (moved) fs.renameSync(file, path.join(directory, keep));
				const build = sinon
					.stub(
						BeignetNode.prototype as unknown as { buildNode(): Promise<void> },
						'buildNode'
					)
					.throws('started legacy node');
				const error = await rejection(() =>
					BeignetNode.create({
						network: 'regtest',
						dataDir: directory,
						allowMultipleInstances: true
					})
				);
				expect(error).to.be.instanceOf(Error);
				expect((error as Error).message).to.match(finalWalletError);
				expect(build.called).to.equal(false);
				expect(fs.existsSync(marker)).to.equal(true);
				expect(fs.existsSync(path.join(directory, staged))).to.equal(true);
				expect(fs.existsSync(file)).to.equal(!moved);
				SqliteStorage.openFinalWallet(
					moved ? path.join(directory, keep) : file,
					wallet
				).close();
			}
		);
	}

	it('preserves the final wallet when offline restore receives an authenticated legacy backup', async () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		const backup = path.join(directory, 'backup.db');
		const legacy = new SqliteStorage(backup);
		legacy.open();
		legacy.close();
		const macKey = seedFor(180);
		await writeBackupMac(macKey, backup);
		const error = await rejection(() =>
			performDbRestore(backup, file, path.join(directory, 'regtest.lock'), {
				macKey
			})
		);
		expect(error).to.be.instanceOf(Error);
		expect((error as Error).message).to.match(finalWalletError);
		SqliteStorage.openFinalWallet(file, wallet).close();
		expect(fs.existsSync(file + '.restored')).to.equal(false);
	});

	it('preserves a closed final wallet when a legacy database backs up to its path', async () => {
		const target = SqliteStorage.createFinalWallet(file, wallet);
		target.saveWalletData('format-test', 'final-wallet-sentinel');
		target.close();
		const legacy = new SqliteStorage(path.join(directory, 'legacy.db'));
		try {
			legacy.open();
			const error = await rejection(() => legacy.backup(file));
			expect(error).to.be.instanceOf(Error);
			expect((error as Error).message).to.match(finalWalletError);
		} finally {
			legacy.close();
		}
		const reopened = SqliteStorage.openFinalWallet(file, wallet);
		try {
			expect(reopened.loadWalletData('format-test')).to.equal(
				'final-wallet-sentinel'
			);
		} finally {
			reopened.close();
		}
	});

	it('updates a backup of the same final identity and preserves foreign destinations', async () => {
		const source = SqliteStorage.createFinalWallet(file, wallet);
		const same = path.join(directory, 'same.db');
		try {
			await source.backup(same);
			source.saveWalletData('backup-test', 'second-backup');
			await source.backup(same);
			const latest = SqliteStorage.openFinalWallet(same, wallet);
			try {
				expect(latest.loadWalletData('backup-test')).to.equal('second-backup');
			} finally {
				latest.close();
			}
			for (const [index, binding] of [
				null,
				{ ...wallet, network: 'signet' as const },
				{
					...wallet,
					nodeId: basepointsOf(seedFor(200)).fundingPubkey.toString('hex')
				}
			].entries()) {
				const other = path.join(directory, 'other-' + index + '.db');
				const target = binding
					? SqliteStorage.createFinalWallet(other, binding)
					: new SqliteStorage(other);
				if (!binding) target.open();
				target.saveWalletData('backup-test', 'keep');
				target.close();
				const error = await rejection(() => source.backup(other));
				expect(error).to.be.instanceOf(Error);
				const reopened = binding
					? SqliteStorage.openFinalWallet(other, binding)
					: new SqliteStorage(other);
				try {
					if (!binding) reopened.open();
					expect(reopened.loadWalletData('backup-test')).to.equal('keep');
				} finally {
					reopened.close();
				}
			}
		} finally {
			source.close();
		}
	});
});
