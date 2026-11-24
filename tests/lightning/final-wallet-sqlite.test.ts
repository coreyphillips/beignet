import { expect } from 'chai';
import Database from 'better-sqlite3';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { FeatureFlags } from '../../src/lightning/features/flags';
import { isEncryptedValue } from '../../src/lightning/storage/encryption';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { basepointsOf, seedFor } from './helpers/taproot-revoked-fixture';

const wallet = {
	encryptionKey: seedFor(81),
	nodeId: basepointsOf(seedFor(82)).fundingPubkey.toString('hex'),
	network: 'regtest' as const
};
const peer = basepointsOf(seedFor(83)).fundingPubkey.toString('hex');

function openLegacy(file: string): void {
	const legacy = new SqliteStorage(file, undefined, {
		encryptionKey: wallet.encryptionKey
	});
	try {
		legacy.open();
	} finally {
		legacy.close();
	}
}

function changeSchema(file: string, sql: string): void {
	const db = new Database(file, { fileMustExist: true });
	try {
		db.exec(sql);
	} finally {
		db.close();
	}
}

describe('Final wallet SQLite format', () => {
	let directory: string;
	let file: string;

	beforeEach(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-final-wallet-'));
		file = path.join(directory, 'regtest.db');
	});

	afterEach(() => {
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('physically fences the legacy opener even before a channel exists', () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		const db = new Database(file, { readonly: true, fileMustExist: true });
		try {
			const columns = db.pragma('table_info(channels)') as { name: string }[];
			expect(columns.map((column) => column.name)).to.include(
				'channel_state_v2'
			);
			expect(columns.map((column) => column.name)).not.to.include('state_json');
		} finally {
			db.close();
		}
		expect(() => openLegacy(file)).to.throw();
		SqliteStorage.openFinalWallet(file, wallet).close();
	});

	it('requires the same key, Lightning node, and network when reopening an empty wallet', () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		for (const mismatch of [
			{ ...wallet, network: 'signet' as const },
			{ ...wallet, nodeId: peer },
			{ ...wallet, encryptionKey: seedFor(84) }
		]) {
			expect(() => SqliteStorage.openFinalWallet(file, mismatch)).to.throw();
		}
		SqliteStorage.openFinalWallet(file, wallet).close();
	});

	it('excludes a second SQLite writer for the life of the final wallet handle', () => {
		const created = SqliteStorage.createFinalWallet(file, wallet);
		const check = (): void => {
			const second = new Database(file, { timeout: 20, fileMustExist: true });
			try {
				expect(() => second.exec('BEGIN IMMEDIATE')).to.throw(/locked|busy/i);
			} finally {
				second.close();
			}
		};
		try {
			check();
		} finally {
			created.close();
		}
		const reopened = SqliteStorage.openFinalWallet(file, wallet);
		try {
			check();
		} finally {
			reopened.close();
		}
	});

	it('refuses a final column without a marker and a marker without the final column', () => {
		openLegacy(file);
		changeSchema(
			file,
			'ALTER TABLE channels RENAME COLUMN state_json TO channel_state_v2'
		);
		expect(() => SqliteStorage.openFinalWallet(file, wallet)).to.throw();
		expect(() => openLegacy(file)).to.throw();

		const other = path.join(directory, 'other.db');
		SqliteStorage.createFinalWallet(other, wallet).close();
		changeSchema(
			other,
			'ALTER TABLE channels RENAME COLUMN channel_state_v2 TO state_json'
		);
		expect(() => SqliteStorage.openFinalWallet(other, wallet)).to.throw();
		expect(() => openLegacy(other)).to.throw();
	});

	it('refuses an ambiguous schema containing both channel state columns', () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		changeSchema(file, 'ALTER TABLE channels ADD COLUMN state_json TEXT');
		expect(() => SqliteStorage.openFinalWallet(file, wallet)).to.throw();
		expect(() => openLegacy(file)).to.throw();
	});

	it('opens only an existing final wallet and creates only at an unused path', () => {
		expect(() => SqliteStorage.openFinalWallet(file, wallet)).to.throw();
		expect(fs.existsSync(file)).to.equal(false);
		fs.writeFileSync(file, '');
		expect(() => SqliteStorage.createFinalWallet(file, wallet)).to.throw();
		expect(fs.readFileSync(file).length).to.equal(0);
		openLegacy(file);
		const original = fs.readFileSync(file);
		expect(() => SqliteStorage.createFinalWallet(file, wallet)).to.throw();
		expect(() => SqliteStorage.openFinalWallet(file, wallet)).to.throw();
		expect(fs.readFileSync(file)).to.deep.equal(original);
		openLegacy(file);
	});

	it('preserves an existing final wallet and a dangling symlink target', () => {
		SqliteStorage.createFinalWallet(file, wallet).close();
		expect(() => SqliteStorage.createFinalWallet(file, wallet)).to.throw();
		SqliteStorage.openFinalWallet(file, wallet).close();

		const link = path.join(directory, 'link.db');
		const target = path.join(directory, 'absent.db');
		fs.symlinkSync(target, link);
		expect(() => SqliteStorage.createFinalWallet(link, wallet)).to.throw();
		expect(fs.readlinkSync(link)).to.equal(target);
		expect(fs.existsSync(target)).to.equal(false);
	});

	it('requires encrypted file storage', () => {
		for (const encryptionKey of [undefined, Buffer.alloc(31)]) {
			const options = { ...wallet, encryptionKey } as typeof wallet;
			expect(() => SqliteStorage.createFinalWallet(file, options)).to.throw();
			expect(fs.existsSync(file)).to.equal(false);
		}
		expect(() =>
			SqliteStorage.createFinalWallet(':memory:', wallet)
		).to.throw();
		expect(() => SqliteStorage.openFinalWallet(':memory:', wallet)).to.throw();
	});

	it('keeps ordinary states encrypted and preserves their types and fence in an online backup', async () => {
		const flags = FeatureFlags.empty();
		flags.setBit(80);
		const ordinary = createOpenerState({
			temporaryChannelId: seedFor(85),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: basepointsOf(seedFor(86)),
			localPerCommitmentSeed: seedFor(87)
		});
		const historical = {
			...ordinary,
			fundingVersion: 2 as const,
			channelType: flags.toBuffer()
		};
		const marked = {
			...historical,
			commitmentProfile: 'simple-taproot-final' as const
		};
		const first = seedFor(88).toString('hex');
		const second = seedFor(89).toString('hex');
		const storage = SqliteStorage.createFinalWallet(file, wallet);
		const copy = path.join(directory, 'backup.db');
		try {
			storage.saveChannel(first, ordinary, peer);
			storage.saveChannel(second, historical, peer);
			expect(() => storage.saveChannel(second, marked, peer)).to.throw();
			await storage.backup(copy);
		} finally {
			storage.close();
		}
		for (const location of [file, copy]) {
			expect(() => openLegacy(location)).to.throw();
			const db = new Database(location, { readonly: true });
			try {
				const rows = db
					.prepare('SELECT channel_state_v2 AS payload FROM channels')
					.all() as { payload: string }[];
				expect(rows).to.have.length(2);
				expect(rows.every(({ payload }) => isEncryptedValue(payload))).to.equal(
					true
				);
			} finally {
				db.close();
			}
			const reopened = SqliteStorage.openFinalWallet(location, wallet);
			try {
				expect(
					reopened.loadAllChannels().map((row) => row.channelId)
				).to.have.members([first, second]);
				expect(reopened.loadChannel(first)?.state.fundingSatoshis).to.equal(
					150_000n
				);
				const state = reopened.loadChannel(second)?.state;
				expect(state?.channelType).to.deep.equal(historical.channelType);
				expect(state).not.to.have.property('commitmentProfile');
			} finally {
				reopened.close();
			}
		}
	});
});
