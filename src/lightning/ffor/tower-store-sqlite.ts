/**
 * Durable SQLite tower store (FFOR M7.0).
 *
 * Persists BOTH the settlement record and the full provisioning bundle so a
 * restarted tower rehydrates every epoch with no R involvement (spec §9.4,
 * restart contract). Mirrors src/lightning/storage/sqlite-storage.ts:
 * better-sqlite3, synchronous, prepared statements, WAL journal.
 *
 * DURABILITY-BEFORE-RETURN (spec §9.4 item 5, "package stored durably, then
 * release t_i"): the connection is opened WAL + synchronous=FULL, so every
 * committed write fsyncs the WAL before returning. Each save() is a single
 * INSERT OR REPLACE which auto-commits synchronously, so when save() returns
 * the row is durably on disk (survives power loss), and only then does the
 * caller (handleReleaseRequest) release the preimage.
 *
 * AT-REST ENCRYPTION is OUT OF SCOPE for M7.0. Like the node's own
 * SqliteStorage (preimages / payment_secrets / htlc_shared_secrets are stored
 * as plaintext hex), the provisioning JSON here holds the preimages and, for
 * option-(a) towers, the scoped revocation basepoint secret in plaintext. This
 * matches the node's existing secrets policy; encryption is a follow-up.
 */

import Database from 'better-sqlite3';
import {
	IFforTowerStore,
	IFforTowerRecord,
	IFforTowerProvisioning
} from './tower';
import {
	serializeTowerProvisioning,
	deserializeTowerProvisioning,
	serializeTowerRecord,
	deserializeTowerRecord
} from './tower-serialization';

export class SqliteTowerStore implements IFforTowerStore {
	private db: Database.Database;

	/**
	 * @param db A SQLite database file path (or ':memory:'), or an existing
	 *   better-sqlite3 connection to share with the node's own storage.
	 * @param opts.synchronous PRAGMA synchronous level. Defaults to FULL, which
	 *   is required for the durable-before-return guarantee; do not weaken it.
	 */
	constructor(
		db: string | Database.Database,
		opts?: { synchronous?: 'FULL' | 'NORMAL' }
	) {
		this.db = typeof db === 'string' ? new Database(db) : db;
		this.db.pragma('journal_mode = WAL');
		// FULL fsyncs the WAL on every commit → a returned save() is durable
		// even across power loss, satisfying persist-before-release (§9.4).
		this.db.pragma(`synchronous = ${opts?.synchronous ?? 'FULL'}`);
		this.db.pragma('busy_timeout = 5000');
		this._createTables();
	}

	private _createTables(): void {
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS ffor_tower_provisioning (
				epoch_id_hex TEXT PRIMARY KEY,
				prov_json TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS ffor_tower_records (
				epoch_id_hex TEXT PRIMARY KEY,
				record_json TEXT NOT NULL
			);
		`);
	}

	// ─────────────── records ───────────────

	save(record: IFforTowerRecord): void {
		const json = JSON.stringify(serializeTowerRecord(record));
		this.db
			.prepare(
				'INSERT OR REPLACE INTO ffor_tower_records (epoch_id_hex, record_json) VALUES (?, ?)'
			)
			.run(record.epochIdHex, json);
	}

	load(epochIdHex: string): IFforTowerRecord | null {
		const row = this.db
			.prepare(
				'SELECT record_json FROM ffor_tower_records WHERE epoch_id_hex = ?'
			)
			.get(epochIdHex) as { record_json: string } | undefined;
		if (!row) return null;
		return deserializeTowerRecord(JSON.parse(row.record_json));
	}

	// ─────────────── provisioning ───────────────

	saveProvisioning(provisioning: IFforTowerProvisioning): void {
		const epochIdHex = provisioning.epochId.toString('hex');
		const json = JSON.stringify(serializeTowerProvisioning(provisioning));
		this.db
			.prepare(
				'INSERT OR REPLACE INTO ffor_tower_provisioning (epoch_id_hex, prov_json) VALUES (?, ?)'
			)
			.run(epochIdHex, json);
	}

	loadProvisioning(epochIdHex: string): IFforTowerProvisioning | null {
		const row = this.db
			.prepare(
				'SELECT prov_json FROM ffor_tower_provisioning WHERE epoch_id_hex = ?'
			)
			.get(epochIdHex) as { prov_json: string } | undefined;
		if (!row) return null;
		return deserializeTowerProvisioning(JSON.parse(row.prov_json));
	}

	listEpochs(): string[] {
		const rows = this.db
			.prepare('SELECT epoch_id_hex FROM ffor_tower_provisioning')
			.all() as Array<{ epoch_id_hex: string }>;
		return rows.map((r) => r.epoch_id_hex);
	}

	/** Flush the WAL to the main db file (e.g. before a clean shutdown). */
	checkpoint(): void {
		this.db.pragma('wal_checkpoint(TRUNCATE)');
	}

	/** Close the underlying connection (only when this store owns it). */
	close(): void {
		this.db.close();
	}
}
