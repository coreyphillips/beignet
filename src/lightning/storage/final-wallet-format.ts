import type Database from 'better-sqlite3';
import { loadBetterSqlite3 } from './sqlite-binding';
import { nodeFs } from '../../utils/node-builtins';
import { isValidPublicKey } from '../crypto/ecdh';
import { decryptValue, encryptValue, hkdfKey } from './encryption';

export interface IFinalWalletBinding {
	encryptionKey: Buffer;
	nodeId: string;
	network: 'mainnet' | 'testnet' | 'regtest' | 'signet';
}

const MARKER_KEY_INFO = 'beignet-final-wallet-format-v1';
const sidecars = ['-wal', '-shm', '-journal'];

export function finalWalletIdentity(
	path: string,
	binding: IFinalWalletBinding
): string {
	if (
		!path ||
		path.trim() !== path ||
		path === ':memory:' ||
		path.includes('\0')
	)
		throw new Error('A final wallet requires a database file');
	if (
		!Buffer.isBuffer(binding.encryptionKey) ||
		binding.encryptionKey.length !== 32
	)
		throw new Error('A final wallet requires a 32-byte encryption key');
	if (
		typeof binding.nodeId !== 'string' ||
		!/^(02|03)[0-9a-f]{64}$/.test(binding.nodeId) ||
		!isValidPublicKey(Buffer.from(binding.nodeId, 'hex'))
	)
		throw new Error('Invalid final wallet node ID');
	if (!['mainnet', 'testnet', 'regtest', 'signet'].includes(binding.network))
		throw new Error('Invalid final wallet network');
	return JSON.stringify([1, binding.nodeId, binding.network]);
}

export function assertUnusedWalletPath(path: string): void {
	const fs = nodeFs();
	for (const suffix of ['', ...sidecars]) {
		if (fs.lstatSync(path + suffix, { throwIfNoEntry: false }))
			throw new Error('Final wallet creation requires an unused database path');
	}
}

/**
 * Inspect a restore source or destination without migrating it. A complete
 * SQLite image has at least one 512-byte page. Short files have no schema.
 */
export function assertLegacyWalletFile(path: string): void {
	const status = nodeFs().statSync(path, { throwIfNoEntry: false });
	if (!status || status.size < 512) return;
	inspectWalletFile(path);
}

function inspectWalletFile(
	path: string,
	key?: Buffer,
	identity?: string
): void {
	const Sqlite = loadBetterSqlite3();
	const db = new Sqlite(path, {
		readonly: true,
		fileMustExist: true,
		timeout: 0
	});
	try {
		checkWalletFormat(db, key, identity);
	} finally {
		db.close();
	}
}

export function assertExistingWalletFile(path: string): void {
	const fs = nodeFs();
	if (!fs.lstatSync(path).isFile())
		throw new Error('Final wallet path must name a regular file');
	for (const suffix of sidecars) {
		const sidecar = fs.lstatSync(path + suffix, { throwIfNoEntry: false });
		if (sidecar && !sidecar.isFile())
			throw new Error('Invalid final wallet sidecar');
	}
}

function syncPath(path: string): void {
	const fs = nodeFs();
	const fd = fs.openSync(path, 'r');
	try {
		fs.fsyncSync(fd);
	} finally {
		fs.closeSync(fd);
	}
}

/** Publish the finished, closed SQLite image without replacing a racing creator. */
export function installFreshWallet(
	path: string,
	initialize: (file: string) => void
): void {
	assertUnusedWalletPath(path);
	const fs = nodeFs();
	const stage = fs.mkdtempSync(path + '.new-');
	const file = stage + '/wallet.db';
	try {
		initialize(file);
		syncPath(file);
		assertUnusedWalletPath(path);
		fs.linkSync(file, path);
		syncPath(stage + '/..');
	} finally {
		// This directory was created uniquely for this attempt.
		fs.rmSync(stage, { recursive: true, force: true });
	}
}

/**
 * A backup begun at an unused path must not race a new wallet into the same
 * file. Publish the completed image without replacement. Existing backups
 * retain SQLite's online update semantics after their format is checked.
 */
export async function backUpWalletFile(
	db: Database.Database,
	path: string,
	key?: Buffer,
	identity?: string
): Promise<void> {
	// The SQLite binding trims the path before opening it.
	const destination = path.trim();
	if (!destination || destination === ':memory:')
		throw new Error('Invalid backup filename');
	const fs = nodeFs();
	if (!fs.lstatSync(destination, { throwIfNoEntry: false })) {
		assertUnusedWalletPath(destination);
		const stage = fs.mkdtempSync(destination + '.backup-');
		const file = stage + '/wallet.db';
		try {
			await db.backup(file);
			if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
			syncPath(file);
			try {
				fs.linkSync(file, destination);
				syncPath(stage + '/..');
				return;
			} catch (error) {
				// A concurrent creator won. Validate its file before updating it.
				if (error.code !== 'EEXIST') throw error;
			}
		} finally {
			fs.rmSync(stage, { recursive: true, force: true });
		}
	}
	if (identity) {
		assertExistingWalletFile(destination);
		inspectWalletFile(destination, key, identity);
	} else {
		assertLegacyWalletFile(destination);
	}
	await db.backup(destination);
}

/** Called only on a private, freshly initialized database before publication. */
export function installWalletMarker(
	db: Database.Database,
	key: Buffer,
	identity: string
): void {
	db.transaction(() => {
		db.exec(`
			ALTER TABLE channels RENAME COLUMN state_json TO channel_state_v2;
			CREATE TABLE final_wallet_format (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				identity TEXT NOT NULL
			);
			CREATE TABLE final_opening_candidates (
				channel_id TEXT NOT NULL PRIMARY KEY,
				funding_outpoint TEXT NOT NULL UNIQUE,
				record_json TEXT NOT NULL,
				nonces_json TEXT NOT NULL
			);
		`);
		db.prepare(
			'INSERT INTO final_wallet_format (id, identity) VALUES (1, ?)'
		).run(encryptValue(hkdfKey(key, MARKER_KEY_INFO), identity));
	})();
}

export function checkWalletFormat(
	db: Database.Database,
	key?: Buffer,
	identity?: string
): void {
	const object = db.prepare(
		'SELECT type FROM sqlite_master WHERE name = ? COLLATE NOCASE'
	);
	const marker = object.get('final_wallet_format') as
		| { type: string }
		| undefined;
	const candidates = object.get('final_opening_candidates') as
		| { type: string }
		| undefined;
	const columns = db.pragma('table_info(channels)') as Array<{ name: string }>;
	const names = columns.map(({ name }) => name.toLowerCase());
	const final = names.includes('channel_state_v2');
	if (identity === undefined) {
		if (final || marker || candidates)
			throw new Error('Final wallet requires its bound opener');
		return;
	}
	if (
		!final ||
		names.includes('state_json') ||
		marker?.type !== 'table' ||
		candidates?.type !== 'table' ||
		!key
	)
		throw new Error('Invalid final wallet database format');
	const rows = db
		.prepare('SELECT id, identity FROM final_wallet_format LIMIT 2')
		.all() as Array<{ id: number; identity: string }>;
	if (
		rows.length !== 1 ||
		rows[0].id !== 1 ||
		decryptValue(hkdfKey(key, MARKER_KEY_INFO), rows[0].identity) !== identity
	)
		throw new Error('Final wallet binding does not match');
	const fields = db.pragma('table_info(final_opening_candidates)') as Array<{
		name: string;
		type: string;
		notnull: number;
		pk: number;
	}>;
	if (
		fields.length !== 4 ||
		!['channel_id', 'funding_outpoint', 'record_json', 'nonces_json'].every(
			(name) =>
				fields.some(
					(field) =>
						field.name === name &&
						field.type === 'TEXT' &&
						field.notnull === 1 &&
						field.pk === (name === 'channel_id' ? 1 : 0)
				)
		)
	)
		throw new Error('Invalid final opening candidate table');
	const indexes = db.pragma('index_list(final_opening_candidates)') as Array<{
		name: string;
		unique: number;
		partial: number;
	}>;
	const keys = new Set<string>();
	for (const index of indexes) {
		if (!index.unique || index.partial) continue;
		const indexedColumns = db
			.prepare('SELECT name FROM pragma_index_info(?)')
			.all(index.name) as Array<{ name: string }>;
		if (indexedColumns.length === 1) keys.add(indexedColumns[0].name);
	}
	if (!keys.has('channel_id') || !keys.has('funding_outpoint'))
		throw new Error('Invalid final opening candidate keys');
}
