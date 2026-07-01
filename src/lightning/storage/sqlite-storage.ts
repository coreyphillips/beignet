/**
 * SQLite storage backend for Lightning node persistence.
 *
 * Uses better-sqlite3 for synchronous, transactional access.
 * All tables use WAL mode for concurrent reader support.
 */

import Database from 'better-sqlite3';
import { IStorageBackend, IInvoiceInfo } from './types';
import { IChannelState } from '../channel/channel-state';
import { IPaymentInfo } from '../node/types';
import { IChainMonitorState } from '../chain/chain-monitor';
import { IGraphChannel, IGraphNode } from '../gossip/types';
import {
	serializeChannelState,
	deserializeChannelState,
	serializePaymentInfo,
	deserializePaymentInfo,
	serializeChainMonitorState,
	deserializeChainMonitorState,
	serializeGraphChannel,
	deserializeGraphChannel,
	serializeGraphNode,
	deserializeGraphNode
} from './serialization';

export class SqliteStorage implements IStorageBackend {
	private db: Database.Database;
	private onCorruptRow?: (error: unknown) => void;

	/**
	 * @param dbPath Path to the SQLite database file (or ':memory:').
	 * @param onCorruptRow Optional callback invoked when a row fails to
	 *   deserialize during a `loadAll*` call. The corrupt row is skipped so the
	 *   node still starts, but the callback makes the (silent) data loss visible
	 *   to operators.
	 */
	constructor(dbPath: string, onCorruptRow?: (error: unknown) => void) {
		this.db = new Database(dbPath);
		this.onCorruptRow = onCorruptRow;
	}

	private reportCorruptRow(error: unknown): void {
		if (this.onCorruptRow) {
			this.onCorruptRow(error);
		}
	}

	open(opts?: { synchronous?: 'FULL' | 'NORMAL' }): void {
		this.db.pragma('journal_mode = WAL');
		this.db.pragma(`synchronous = ${opts?.synchronous ?? 'FULL'}`);
		this.db.pragma('foreign_keys = ON');
		this.db.pragma('busy_timeout = 5000');
		this._createTables();
	}

	/**
	 * Checkpoint the WAL file, flushing all pending writes to the main database.
	 */
	checkpoint(): void {
		this.db.pragma('wal_checkpoint(TRUNCATE)');
	}

	close(): void {
		this.db.close();
	}

	/**
	 * Create a backup of the database to the specified destination path.
	 * Uses SQLite's online backup API for a crash-safe copy.
	 */
	async backup(destPath: string): Promise<void> {
		await this.db.backup(destPath);
	}

	// ─── Schema ───

	/** Current schema version. Increment when adding migrations. */
	static readonly CURRENT_SCHEMA_VERSION = 2;

	private _createTables(): void {
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS channels (
				channel_id TEXT PRIMARY KEY,
				state_json TEXT NOT NULL,
				peer_pubkey TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS payments (
				payment_hash TEXT PRIMARY KEY,
				payment_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS preimages (
				payment_hash TEXT PRIMARY KEY,
				preimage TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS scid_mappings (
				scid_hex TEXT PRIMARY KEY,
				channel_id TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS htlc_payment_map (
				htlc_key TEXT PRIMARY KEY,
				payment_hash_hex TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS forwarded_htlcs (
				out_key TEXT PRIMARY KEY,
				in_channel_id TEXT NOT NULL,
				in_htlc_id TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS chain_monitors (
				channel_id TEXT PRIMARY KEY,
				state_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS gossip_channels (
				scid_hex TEXT PRIMARY KEY,
				channel_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS gossip_nodes (
				node_id_hex TEXT PRIMARY KEY,
				node_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS payment_secrets (
				payment_hash_hex TEXT PRIMARY KEY,
				secret TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS invoices (
				payment_hash_hex TEXT PRIMARY KEY,
				invoice_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS mission_control (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				data_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS peer_addresses (
				pubkey TEXT PRIMARY KEY,
				host TEXT NOT NULL,
				port INTEGER NOT NULL,
				last_connected INTEGER NOT NULL DEFAULT 0
			);

			CREATE TABLE IF NOT EXISTS channel_key_indices (
				channel_id TEXT PRIMARY KEY,
				channel_index INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS schema_version (
				version INTEGER PRIMARY KEY
			);

			CREATE TABLE IF NOT EXISTS metadata (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS htlc_shared_secrets (
				key TEXT PRIMARY KEY,
				secret TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS action_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				category TEXT NOT NULL,
				action TEXT NOT NULL,
				timestamp INTEGER NOT NULL,
				data TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_action_log_timestamp ON action_log(timestamp);
			CREATE INDEX IF NOT EXISTS idx_action_log_category ON action_log(category);

			CREATE TABLE IF NOT EXISTS webhooks (
				id TEXT PRIMARY KEY,
				url TEXT NOT NULL,
				events TEXT NOT NULL,
				secret_hash TEXT,
				created_at INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS payment_queue (
				id TEXT PRIMARY KEY,
				bolt11 TEXT NOT NULL,
				priority INTEGER NOT NULL,
				status TEXT NOT NULL,
				amount_sats INTEGER,
				max_fee_sats INTEGER,
				metadata TEXT,
				error TEXT,
				created_at INTEGER NOT NULL,
				completed_at INTEGER
			);
		`);

		// Run migrations
		this._runMigrations();
	}

	// ─── Channels ───

	saveChannel(id: string, state: IChannelState, peerPubkey: string): void {
		const serialized = serializeChannelState(state);
		const json = JSON.stringify(serialized);
		this.db
			.prepare(
				'INSERT OR REPLACE INTO channels (channel_id, state_json, peer_pubkey) VALUES (?, ?, ?)'
			)
			.run(id, json, peerPubkey);
	}

	loadChannel(id: string): { state: IChannelState; peerPubkey: string } | null {
		const row = this.db
			.prepare(
				'SELECT state_json, peer_pubkey FROM channels WHERE channel_id = ?'
			)
			.get(id) as { state_json: string; peer_pubkey: string } | undefined;
		if (!row) return null;
		return {
			state: deserializeChannelState(JSON.parse(row.state_json)),
			peerPubkey: row.peer_pubkey
		};
	}

	loadAllChannels(): Array<{
		channelId: string;
		state: IChannelState;
		peerPubkey: string;
	}> {
		const rows = this.db
			.prepare('SELECT channel_id, state_json, peer_pubkey FROM channels')
			.all() as Array<{
			channel_id: string;
			state_json: string;
			peer_pubkey: string;
		}>;
		const results: Array<{
			channelId: string;
			state: IChannelState;
			peerPubkey: string;
		}> = [];
		for (const row of rows) {
			try {
				results.push({
					channelId: row.channel_id,
					state: deserializeChannelState(JSON.parse(row.state_json)),
					peerPubkey: row.peer_pubkey
				});
			} catch (err) {
				// Skip corrupted row — node still starts with remaining data
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteChannel(id: string): void {
		this.db.prepare('DELETE FROM channels WHERE channel_id = ?').run(id);
	}

	// ─── Payments ───

	savePayment(paymentHash: string, payment: IPaymentInfo): void {
		const serialized = serializePaymentInfo(payment);
		const json = JSON.stringify(serialized);
		this.db
			.prepare(
				'INSERT OR REPLACE INTO payments (payment_hash, payment_json) VALUES (?, ?)'
			)
			.run(paymentHash, json);
	}

	loadPayment(paymentHash: string): IPaymentInfo | null {
		const row = this.db
			.prepare('SELECT payment_json FROM payments WHERE payment_hash = ?')
			.get(paymentHash) as { payment_json: string } | undefined;
		if (!row) return null;
		return deserializePaymentInfo(JSON.parse(row.payment_json));
	}

	loadAllPayments(): Array<{ paymentHash: string; payment: IPaymentInfo }> {
		const rows = this.db
			.prepare('SELECT payment_hash, payment_json FROM payments')
			.all() as Array<{ payment_hash: string; payment_json: string }>;
		const results: Array<{ paymentHash: string; payment: IPaymentInfo }> = [];
		for (const row of rows) {
			try {
				results.push({
					paymentHash: row.payment_hash,
					payment: deserializePaymentInfo(JSON.parse(row.payment_json))
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deletePayment(paymentHash: string): void {
		this.db
			.prepare('DELETE FROM payments WHERE payment_hash = ?')
			.run(paymentHash);
	}

	// ─── Preimages ───

	savePreimage(paymentHash: string, preimage: Buffer): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO preimages (payment_hash, preimage) VALUES (?, ?)'
			)
			.run(paymentHash, preimage.toString('hex'));
	}

	loadPreimage(paymentHash: string): Buffer | null {
		const row = this.db
			.prepare('SELECT preimage FROM preimages WHERE payment_hash = ?')
			.get(paymentHash) as { preimage: string } | undefined;
		if (!row) return null;
		return Buffer.from(row.preimage, 'hex');
	}

	loadAllPreimages(): Array<{ paymentHash: string; preimage: Buffer }> {
		const rows = this.db
			.prepare('SELECT payment_hash, preimage FROM preimages')
			.all() as Array<{ payment_hash: string; preimage: string }>;
		const results: Array<{ paymentHash: string; preimage: Buffer }> = [];
		for (const row of rows) {
			try {
				results.push({
					paymentHash: row.payment_hash,
					preimage: Buffer.from(row.preimage, 'hex')
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	// ─── SCID Mappings ───

	saveScidMapping(scidHex: string, channelId: Buffer): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO scid_mappings (scid_hex, channel_id) VALUES (?, ?)'
			)
			.run(scidHex, channelId.toString('hex'));
	}

	loadAllScidMappings(): Array<{ scidHex: string; channelId: Buffer }> {
		const rows = this.db
			.prepare('SELECT scid_hex, channel_id FROM scid_mappings')
			.all() as Array<{ scid_hex: string; channel_id: string }>;
		const results: Array<{ scidHex: string; channelId: Buffer }> = [];
		for (const row of rows) {
			try {
				results.push({
					scidHex: row.scid_hex,
					channelId: Buffer.from(row.channel_id, 'hex')
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	// ─── HTLC Payment Map ───

	saveHtlcPaymentMapping(key: string, paymentHashHex: string): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO htlc_payment_map (htlc_key, payment_hash_hex) VALUES (?, ?)'
			)
			.run(key, paymentHashHex);
	}

	loadAllHtlcPaymentMappings(): Array<{ key: string; paymentHashHex: string }> {
		const rows = this.db
			.prepare('SELECT htlc_key, payment_hash_hex FROM htlc_payment_map')
			.all() as Array<{ htlc_key: string; payment_hash_hex: string }>;
		const results: Array<{ key: string; paymentHashHex: string }> = [];
		for (const row of rows) {
			try {
				results.push({
					key: row.htlc_key,
					paymentHashHex: row.payment_hash_hex
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteHtlcPaymentMapping(key: string): void {
		this.db.prepare('DELETE FROM htlc_payment_map WHERE htlc_key = ?').run(key);
	}

	// ─── Forwarded HTLCs ───

	saveForwardedHtlc(
		outKey: string,
		inChannelId: Buffer,
		inHtlcId: bigint
	): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO forwarded_htlcs (out_key, in_channel_id, in_htlc_id) VALUES (?, ?, ?)'
			)
			.run(outKey, inChannelId.toString('hex'), inHtlcId.toString());
	}

	loadAllForwardedHtlcs(): Array<{
		outKey: string;
		inChannelId: Buffer;
		inHtlcId: bigint;
	}> {
		const rows = this.db
			.prepare('SELECT out_key, in_channel_id, in_htlc_id FROM forwarded_htlcs')
			.all() as Array<{
			out_key: string;
			in_channel_id: string;
			in_htlc_id: string;
		}>;
		const results: Array<{
			outKey: string;
			inChannelId: Buffer;
			inHtlcId: bigint;
		}> = [];
		for (const row of rows) {
			try {
				results.push({
					outKey: row.out_key,
					inChannelId: Buffer.from(row.in_channel_id, 'hex'),
					inHtlcId: BigInt(row.in_htlc_id)
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteForwardedHtlc(outKey: string): void {
		this.db
			.prepare('DELETE FROM forwarded_htlcs WHERE out_key = ?')
			.run(outKey);
	}

	// ─── Chain Monitors ───

	saveChainMonitor(channelId: string, state: IChainMonitorState): void {
		const json = serializeChainMonitorState(state);
		this.db
			.prepare(
				'INSERT OR REPLACE INTO chain_monitors (channel_id, state_json) VALUES (?, ?)'
			)
			.run(channelId, json);
	}

	loadChainMonitor(channelId: string): IChainMonitorState | null {
		const row = this.db
			.prepare('SELECT state_json FROM chain_monitors WHERE channel_id = ?')
			.get(channelId) as { state_json: string } | undefined;
		if (!row) return null;
		return deserializeChainMonitorState(row.state_json);
	}

	loadAllChainMonitors(): Array<{
		channelId: string;
		state: IChainMonitorState;
	}> {
		const rows = this.db
			.prepare('SELECT channel_id, state_json FROM chain_monitors')
			.all() as Array<{ channel_id: string; state_json: string }>;
		const results: Array<{ channelId: string; state: IChainMonitorState }> = [];
		for (const row of rows) {
			try {
				results.push({
					channelId: row.channel_id,
					state: deserializeChainMonitorState(row.state_json)
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	// ─── Gossip ───

	saveGossipChannel(scidHex: string, channel: IGraphChannel): void {
		const json = serializeGraphChannel(channel);
		this.db
			.prepare(
				'INSERT OR REPLACE INTO gossip_channels (scid_hex, channel_json) VALUES (?, ?)'
			)
			.run(scidHex, json);
	}

	deleteGossipChannel(scidHex: string): void {
		this.db
			.prepare('DELETE FROM gossip_channels WHERE scid_hex = ?')
			.run(scidHex);
	}

	loadAllGossipChannels(): IGraphChannel[] {
		const rows = this.db
			.prepare('SELECT channel_json FROM gossip_channels')
			.all() as Array<{ channel_json: string }>;
		const results: IGraphChannel[] = [];
		for (const row of rows) {
			try {
				results.push(deserializeGraphChannel(row.channel_json));
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	saveGossipNode(nodeIdHex: string, node: IGraphNode): void {
		const json = serializeGraphNode(node);
		this.db
			.prepare(
				'INSERT OR REPLACE INTO gossip_nodes (node_id_hex, node_json) VALUES (?, ?)'
			)
			.run(nodeIdHex, json);
	}

	loadAllGossipNodes(): IGraphNode[] {
		const rows = this.db
			.prepare('SELECT node_json FROM gossip_nodes')
			.all() as Array<{ node_json: string }>;
		const results: IGraphNode[] = [];
		for (const row of rows) {
			try {
				results.push(deserializeGraphNode(row.node_json));
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	// ─── Payment Secrets ───

	savePaymentSecret(paymentHashHex: string, secret: Buffer): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO payment_secrets (payment_hash_hex, secret) VALUES (?, ?)'
			)
			.run(paymentHashHex, secret.toString('hex'));
	}

	loadAllPaymentSecrets(): Array<{ paymentHashHex: string; secret: Buffer }> {
		const rows = this.db
			.prepare('SELECT payment_hash_hex, secret FROM payment_secrets')
			.all() as Array<{ payment_hash_hex: string; secret: string }>;
		const results: Array<{ paymentHashHex: string; secret: Buffer }> = [];
		for (const row of rows) {
			try {
				results.push({
					paymentHashHex: row.payment_hash_hex,
					secret: Buffer.from(row.secret, 'hex')
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deletePaymentSecret(paymentHashHex: string): void {
		this.db
			.prepare('DELETE FROM payment_secrets WHERE payment_hash_hex = ?')
			.run(paymentHashHex);
	}

	// ─── Invoices ───

	saveInvoice(paymentHashHex: string, invoice: IInvoiceInfo): void {
		const json = JSON.stringify({
			paymentHash: invoice.paymentHash,
			bolt11: invoice.bolt11,
			amountMsat:
				invoice.amountMsat !== undefined
					? invoice.amountMsat.toString()
					: undefined,
			description: invoice.description,
			expiry: invoice.expiry,
			createdAt: invoice.createdAt,
			hold: invoice.hold
		});
		this.db
			.prepare(
				'INSERT OR REPLACE INTO invoices (payment_hash_hex, invoice_json) VALUES (?, ?)'
			)
			.run(paymentHashHex, json);
	}

	loadAllInvoices(): Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> {
		const rows = this.db
			.prepare('SELECT payment_hash_hex, invoice_json FROM invoices')
			.all() as Array<{ payment_hash_hex: string; invoice_json: string }>;
		const results: Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> =
			[];
		for (const row of rows) {
			try {
				const parsed = JSON.parse(row.invoice_json);
				results.push({
					paymentHashHex: row.payment_hash_hex,
					invoice: {
						paymentHash: parsed.paymentHash,
						bolt11: parsed.bolt11,
						amountMsat:
							parsed.amountMsat !== undefined
								? BigInt(parsed.amountMsat)
								: undefined,
						description: parsed.description,
						expiry: parsed.expiry,
						createdAt: parsed.createdAt,
						hold: parsed.hold
					}
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteInvoice(paymentHashHex: string): void {
		this.db
			.prepare('DELETE FROM invoices WHERE payment_hash_hex = ?')
			.run(paymentHashHex);
	}

	// ─── Mission Control ───

	saveMissionControl(json: string): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO mission_control (id, data_json) VALUES (1, ?)'
			)
			.run(json);
	}

	loadMissionControl(): string | null {
		const row = this.db
			.prepare('SELECT data_json FROM mission_control WHERE id = 1')
			.get() as { data_json: string } | undefined;
		return row ? row.data_json : null;
	}

	// ─── Peer Addresses ───

	savePeerAddress(pubkey: string, host: string, port: number): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO peer_addresses (pubkey, host, port, last_connected) VALUES (?, ?, ?, ?)'
			)
			.run(pubkey, host, port, Date.now());
	}

	loadAllPeerAddresses(): Array<{
		pubkey: string;
		host: string;
		port: number;
	}> {
		const rows = this.db
			.prepare('SELECT pubkey, host, port FROM peer_addresses')
			.all() as Array<{ pubkey: string; host: string; port: number }>;
		return rows;
	}

	deletePeerAddress(pubkey: string): void {
		this.db.prepare('DELETE FROM peer_addresses WHERE pubkey = ?').run(pubkey);
	}

	// ─── Channel Key Indices ───

	saveChannelKeyIndex(channelId: string, channelIndex: number): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO channel_key_indices (channel_id, channel_index) VALUES (?, ?)'
			)
			.run(channelId, channelIndex);
	}

	loadChannelKeyIndex(channelId: string): number | null {
		const row = this.db
			.prepare(
				'SELECT channel_index FROM channel_key_indices WHERE channel_id = ?'
			)
			.get(channelId) as { channel_index: number } | undefined;
		return row ? row.channel_index : null;
	}

	loadNextChannelIndex(): number {
		const row = this.db
			.prepare('SELECT MAX(channel_index) as max_idx FROM channel_key_indices')
			.get() as { max_idx: number | null };
		return row && row.max_idx !== null ? row.max_idx + 1 : 1;
	}

	// ─── HTLC Shared Secrets ───

	saveHtlcSharedSecret(key: string, secret: Buffer): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO htlc_shared_secrets (key, secret) VALUES (?, ?)'
			)
			.run(key, secret.toString('hex'));
	}

	deleteHtlcSharedSecret(key: string): void {
		this.db.prepare('DELETE FROM htlc_shared_secrets WHERE key = ?').run(key);
	}

	loadAllHtlcSharedSecrets(): Array<{ key: string; secret: Buffer }> {
		const rows = this.db
			.prepare('SELECT key, secret FROM htlc_shared_secrets')
			.all() as Array<{ key: string; secret: string }>;
		const results: Array<{ key: string; secret: Buffer }> = [];
		for (const row of rows) {
			try {
				results.push({
					key: row.key,
					secret: Buffer.from(row.secret, 'hex')
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	// ─── Action Log ───

	saveActionLog(entry: {
		category: string;
		action: string;
		timestamp: number;
		data: string;
	}): void {
		this.db
			.prepare(
				'INSERT INTO action_log (category, action, timestamp, data) VALUES (?, ?, ?, ?)'
			)
			.run(entry.category, entry.action, entry.timestamp, entry.data);
		// Cap at 10k rows — delete oldest
		this.db
			.prepare(
				'DELETE FROM action_log WHERE id NOT IN (SELECT id FROM action_log ORDER BY id DESC LIMIT 10000)'
			)
			.run();
	}

	loadActionLog(options?: {
		category?: string;
		since?: number;
		limit?: number;
	}): Array<{
		category: string;
		action: string;
		timestamp: number;
		data: string;
	}> {
		let sql =
			'SELECT category, action, timestamp, data FROM action_log WHERE 1=1';
		const params: unknown[] = [];

		if (options?.category) {
			sql += ' AND category = ?';
			params.push(options.category);
		}
		if (options?.since !== undefined) {
			sql += ' AND timestamp >= ?';
			params.push(options.since);
		}

		sql += ' ORDER BY timestamp DESC';

		if (options?.limit !== undefined && options.limit > 0) {
			sql += ' LIMIT ?';
			params.push(options.limit);
		} else {
			sql += ' LIMIT 1000'; // default limit
		}

		return this.db.prepare(sql).all(...params) as Array<{
			category: string;
			action: string;
			timestamp: number;
			data: string;
		}>;
	}

	// ─── Schema Migrations ───

	getSchemaVersion(): number {
		try {
			const row = this.db
				.prepare('SELECT MAX(version) as v FROM schema_version')
				.get() as { v: number | null } | undefined;
			return row?.v ?? 0;
		} catch {
			// Table doesn't exist yet
			return 0;
		}
	}

	private _runMigrations(): void {
		const currentVersion = this.getSchemaVersion();
		const targetVersion = SqliteStorage.CURRENT_SCHEMA_VERSION;

		if (currentVersion >= targetVersion) return;

		// Migrations indexed by target version
		const migrations: Array<(db: Database.Database) => void> = [
			// Migration 0→1: Add peer_addresses, channel_key_indices tables
			// (tables already created in _createTables via CREATE IF NOT EXISTS)
			(db) => {
				// Ensure column exists on pre-existing channels table
				try {
					db.exec(
						'ALTER TABLE channels ADD COLUMN channel_index INTEGER DEFAULT 0'
					);
				} catch {
					// Column may already exist
				}
			},
			// Migration 1→2: Add webhooks and payment_queue tables
			// (tables already created in _createTables via CREATE IF NOT EXISTS)
			() => {
				// No-op — tables created by CREATE IF NOT EXISTS above
			}
		];

		for (let v = currentVersion; v < targetVersion; v++) {
			const migrate = migrations[v];
			if (migrate) {
				this.db.transaction(() => {
					migrate(this.db);
					this.db
						.prepare(
							'INSERT OR REPLACE INTO schema_version (version) VALUES (?)'
						)
						.run(v + 1);
				})();
			}
		}
	}

	// ─── Metadata ───

	saveMetadata(key: string, value: string): void {
		this.db
			.prepare('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)')
			.run(key, value);
	}

	loadMetadata(key: string): string | null {
		const row = this.db
			.prepare('SELECT value FROM metadata WHERE key = ?')
			.get(key) as { value: string } | undefined;
		return row ? row.value : null;
	}

	// ─── Transaction ───

	transaction<T>(fn: () => T): T {
		return this.db.transaction(fn)();
	}

	// ─── Webhooks (CLI layer persistence) ───

	saveWebhook(
		id: string,
		url: string,
		events: string[],
		secretHash?: string,
		createdAt?: number
	): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO webhooks (id, url, events, secret_hash, created_at) VALUES (?, ?, ?, ?, ?)'
			)
			.run(
				id,
				url,
				JSON.stringify(events),
				secretHash ?? null,
				createdAt ?? Date.now()
			);
	}

	deleteWebhook(id: string): void {
		this.db.prepare('DELETE FROM webhooks WHERE id = ?').run(id);
	}

	deleteAllWebhooks(): void {
		this.db.prepare('DELETE FROM webhooks').run();
	}

	loadAllWebhooks(): Array<{
		id: string;
		url: string;
		events: string[];
		secretHash?: string;
		createdAt: number;
	}> {
		const rows = this.db
			.prepare('SELECT id, url, events, secret_hash, created_at FROM webhooks')
			.all() as Array<{
			id: string;
			url: string;
			events: string;
			secret_hash: string | null;
			created_at: number;
		}>;
		const results: Array<{
			id: string;
			url: string;
			events: string[];
			secretHash?: string;
			createdAt: number;
		}> = [];
		for (const row of rows) {
			try {
				results.push({
					id: row.id,
					url: row.url,
					events: JSON.parse(row.events),
					secretHash: row.secret_hash ?? undefined,
					createdAt: row.created_at
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	// ─── Payment Queue (CLI layer persistence) ───

	saveQueueEntry(entry: {
		id: string;
		bolt11: string;
		priority: number;
		status: string;
		amountSats?: number;
		maxFeeSats?: number;
		metadata?: string;
		createdAt: number;
	}): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO payment_queue (id, bolt11, priority, status, amount_sats, max_fee_sats, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
			)
			.run(
				entry.id,
				entry.bolt11,
				entry.priority,
				entry.status,
				entry.amountSats ?? null,
				entry.maxFeeSats ?? null,
				entry.metadata ?? null,
				entry.createdAt
			);
	}

	updateQueueEntryStatus(
		id: string,
		status: string,
		error?: string,
		completedAt?: number
	): void {
		this.db
			.prepare(
				'UPDATE payment_queue SET status = ?, error = ?, completed_at = ? WHERE id = ?'
			)
			.run(status, error ?? null, completedAt ?? null, id);
	}

	deleteQueueEntry(id: string): void {
		this.db.prepare('DELETE FROM payment_queue WHERE id = ?').run(id);
	}

	loadAllQueueEntries(): Array<{
		id: string;
		bolt11: string;
		priority: number;
		status: string;
		amountSats?: number;
		maxFeeSats?: number;
		metadata?: string;
		error?: string;
		createdAt: number;
		completedAt?: number;
	}> {
		const rows = this.db
			.prepare(
				'SELECT id, bolt11, priority, status, amount_sats, max_fee_sats, metadata, error, created_at, completed_at FROM payment_queue ORDER BY priority ASC, created_at ASC'
			)
			.all() as Array<{
			id: string;
			bolt11: string;
			priority: number;
			status: string;
			amount_sats: number | null;
			max_fee_sats: number | null;
			metadata: string | null;
			error: string | null;
			created_at: number;
			completed_at: number | null;
		}>;
		return rows.map((row) => ({
			id: row.id,
			bolt11: row.bolt11,
			priority: row.priority,
			status: row.status,
			amountSats: row.amount_sats ?? undefined,
			maxFeeSats: row.max_fee_sats ?? undefined,
			metadata: row.metadata ?? undefined,
			error: row.error ?? undefined,
			createdAt: row.created_at,
			completedAt: row.completed_at ?? undefined
		}));
	}
}
