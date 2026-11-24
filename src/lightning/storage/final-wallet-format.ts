import type Database from 'better-sqlite3';
import {
	SIGNER_SUFFIX,
	SIGNER_TABLE,
	protectOriginalBackupDestination,
	markOpeningBackup
} from './final-opening-authority';
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
	for (const suffix of [
		'',
		...sidecars,
		SIGNER_SUFFIX,
		...sidecars.map((s) => SIGNER_SUFFIX + s)
	]) {
		if (fs.lstatSync(path + suffix, { throwIfNoEntry: false }))
			throw new Error('Final wallet creation requires an unused database path');
	}
}

/**
 * Inspect a restore source or destination without migrating it. A complete
 * SQLite image has at least one 512-byte page. Short files have no schema.
 */
export function assertLegacyWalletFile(path: string): void {
	if (nodeFs().lstatSync(path + SIGNER_SUFFIX, { throwIfNoEntry: false }))
		throw new Error('An original final wallet requires its bound opener');
	const status = nodeFs().statSync(path, { throwIfNoEntry: false });
	if (!status || status.size < 512) return;
	const Sqlite = loadBetterSqlite3();
	const db = new Sqlite(path, {
		readonly: true,
		fileMustExist: true,
		timeout: 0
	});
	try {
		checkWalletFormat(db);
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

function syncDirectory(path: string): void {
	// Windows does not expose directory handles through fs.openSync.
	if (process.platform !== 'win32') syncPath(path);
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
		syncPath(file + SIGNER_SUFFIX);
		fs.linkSync(file + SIGNER_SUFFIX, path + SIGNER_SUFFIX);
		try {
			// Make the authority durable before the wallet can refer to it.
			syncDirectory(stage + '/..');
			fs.linkSync(file, path);
		} catch (error) {
			const ours = fs.statSync(file + SIGNER_SUFFIX, { bigint: true });
			const installed = fs.lstatSync(path + SIGNER_SUFFIX, {
				bigint: true,
				throwIfNoEntry: false
			});
			if (installed?.dev === ours.dev && installed.ino === ours.ino)
				fs.unlinkSync(path + SIGNER_SUFFIX);
			throw error;
		}
		syncDirectory(stage + '/..');
	} finally {
		// This directory was created uniquely for this attempt.
		fs.rmSync(stage, { recursive: true, force: true });
	}
}

type SchemaEntry = { type: string; name: string; sql: string | null };
type BackupTable = { name: string; type: string; wr: number };
const appendOnlyTrigger =
	"CREATE TRIGGER recovery_frames_append_only BEFORE UPDATE ON recovery_frames BEGIN SELECT RAISE(ABORT, 'recovery_frames is append-only'); END";

function quoteIdentifier(name: string): string {
	return '"' + name.replace(/"/g, '""') + '"';
}

/** Serialize comparison and replacement on the destination's own SQLite writer lock. */
function updateFinalBackup(
	destination: string,
	snapshot: Database.Database,
	key: Buffer,
	identity: string,
	lineage: string | null,
	checkProgress: (old: Database.Database, next: Database.Database) => void
): void {
	assertExistingWalletFile(destination);
	if (
		nodeFs().lstatSync(destination + SIGNER_SUFFIX, { throwIfNoEntry: false })
	)
		throw new Error('Cannot replace an original final wallet with a backup');
	const Sqlite = loadBetterSqlite3();
	const db = new Sqlite(destination, { fileMustExist: true });
	try {
		db.pragma('synchronous = FULL');
		db.prepare('ATTACH DATABASE ? AS snapshot').run(snapshot.name);
		db.transaction(() => {
			checkWalletFormat(db, key, identity);
			protectOriginalBackupDestination(db, destination, key, identity, lineage);
			checkProgress(db, snapshot);
			const schema = (name: 'main' | 'snapshot'): SchemaEntry[] =>
				db
					.prepare(
						`SELECT type,name,sql FROM ${name}.sqlite_schema ORDER BY type,name`
					)
					.all() as SchemaEntry[];
			const objects = schema('main');
			if (JSON.stringify(objects) !== JSON.stringify(schema('snapshot')))
				throw new Error('Cannot update backups with different SQLite schemas');
			for (const field of ['application_id', 'user_version']) {
				if (
					db.pragma('main.' + field, { simple: true }) !==
					db.pragma('snapshot.' + field, { simple: true })
				)
					throw new Error(
						'Cannot update backups with different SQLite headers'
					);
			}
			if (
				objects.some(
					(object) =>
						object.type === 'trigger' &&
						object.sql?.replace(/\s+/g, ' ').trim() !== appendOnlyTrigger
				)
			)
				throw new Error(
					'Cannot update a final backup with unsupported triggers'
				);
			const tables = db.pragma('main.table_list') as BackupTable[];
			if (
				tables.some(
					(table) =>
						!['table', 'view'].includes(table.type) ||
						(table.name.startsWith('sqlite_') &&
							!['sqlite_schema', 'sqlite_sequence'].includes(table.name))
				)
			)
				throw new Error(
					'Cannot update a final backup with unsupported SQLite tables'
				);
			// Preserve rowids, including gaps, and copy the sequence high-water marks last.
			for (const { name, wr, type } of tables) {
				if (type !== 'table' || name.startsWith('sqlite_')) continue;
				const table = quoteIdentifier(name);
				const fields = db
					.prepare('SELECT name FROM pragma_table_info(?, ?) ORDER BY cid')
					.all(name, 'main') as { name: string }[];
				const names = fields.map((f) => quoteIdentifier(f.name));
				if (!wr) names.unshift('rowid');
				const columns = names.join(',');
				db.exec(`DELETE FROM main.${table}`);
				const inserted = db
					.prepare(
						`INSERT INTO main.${table} (${columns}) SELECT ${columns} FROM snapshot.${table}`
					)
					.run();
				const total = db
					.prepare(`SELECT COUNT(*) AS count FROM snapshot.${table}`)
					.get() as { count: number };
				if (inserted.changes !== total.count)
					throw new Error('Incomplete final wallet backup table');
			}
			if (
				objects.some((o) => o.type === 'table' && o.name === 'sqlite_sequence')
			)
				db.exec(
					'DELETE FROM main.sqlite_sequence; INSERT INTO main.sqlite_sequence (rowid,name,seq) SELECT rowid,name,seq FROM snapshot.sqlite_sequence'
				);
			// Check the copied recovery records in the opposite direction before committing.
			checkProgress(snapshot, db);
		}).immediate();
	} finally {
		db.close();
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
	key: Buffer | undefined,
	identity: string | undefined,
	checkProgress: (old: Database.Database, next: Database.Database) => void
): Promise<void> {
	// The SQLite binding trims the path before opening it.
	const destination = path.trim();
	if (!destination || destination === ':memory:')
		throw new Error('Invalid backup filename');
	const fs = nodeFs();
	if (!identity || !key) {
		// Exclusive create prevents a racing final wallet installation even on
		// removable filesystems without hard links. SQLite handles the copy.
		if (!fs.lstatSync(destination, { throwIfNoEntry: false })) {
			assertUnusedWalletPath(destination);
			let reserved: import('fs').BigIntStats | undefined;
			try {
				const fd = fs.openSync(destination, 'wx', 0o600);
				try {
					reserved = fs.fstatSync(fd, { bigint: true });
				} finally {
					fs.closeSync(fd);
				}
			} catch (err) {
				if (err.code !== 'EEXIST') throw err;
			}
			if (reserved) {
				try {
					await db.backup(destination);
				} catch (err) {
					const current = fs.lstatSync(destination, {
						bigint: true,
						throwIfNoEntry: false
					});
					if (
						current?.dev === reserved.dev &&
						current.ino === reserved.ino &&
						current.size === 0n
					)
						fs.unlinkSync(destination);
					throw err;
				}
				return;
			}
		}
		assertLegacyWalletFile(destination);
		await db.backup(destination);
		return;
	}

	const stage = fs.mkdtempSync(destination + '.backup-');
	const file = stage + '/wallet.db';
	try {
		await db.backup(file);
		if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
		const Sqlite = loadBetterSqlite3();
		const backup = new Sqlite(file, { fileMustExist: true });
		try {
			// The role must be durable before publishing any externally visible copy.
			backup.pragma('journal_mode = DELETE');
			const lineage = markOpeningBackup(backup, key, identity);
			syncPath(file);
			if (!fs.lstatSync(destination, { throwIfNoEntry: false })) {
				assertUnusedWalletPath(destination);
				try {
					fs.linkSync(file, destination);
					syncDirectory(stage + '/..');
					return;
				} catch (err) {
					if (err.code !== 'EEXIST') throw err;
				}
			}
			updateFinalBackup(
				destination,
				backup,
				key,
				identity,
				lineage,
				checkProgress
			);
		} finally {
			backup.close();
		}
	} finally {
		fs.rmSync(stage, { recursive: true, force: true });
	}
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
	if (object.get(SIGNER_TABLE))
		throw new Error('An opening signer is separate from a wallet database');
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
