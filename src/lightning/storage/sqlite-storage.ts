/**
 * SQLite storage backend for Lightning node persistence.
 *
 * Uses better-sqlite3 for synchronous, transactional access.
 * All tables use WAL mode for concurrent reader support.
 */

import Database from 'better-sqlite3';
import {
	IStorageBackend,
	IInvoiceInfo,
	IPersistedChannelPolicy,
	IForwardingEvent,
	IForwardingEventFilter,
	IForwardingSummary
} from './types';
import { IWatchtowerSession, IWatchtowerUpdate } from '../watchtower/types';
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
import {
	encryptValue,
	decryptValue,
	isEncryptedValue,
	StorageEncryptedError
} from './encryption';

export class SqliteStorage implements IStorageBackend {
	private db: Database.Database;
	private onCorruptRow?: (error: unknown) => void;
	private encryptionKey?: Buffer;

	/**
	 * @param dbPath Path to the SQLite database file (or ':memory:').
	 * @param onCorruptRow Optional callback invoked when a row fails to
	 *   deserialize during a `loadAll*` call. The corrupt row is skipped so the
	 *   node still starts, but the callback makes the (silent) data loss visible
	 *   to operators.
	 * @param opts.encryptionKey Optional 32-byte key (see deriveStorageKey).
	 *   When set, sensitive payload columns are encrypted at rest with
	 *   AES-256-GCM; legacy plaintext rows remain readable and are rewritten
	 *   encrypted on open().
	 */
	constructor(
		dbPath: string,
		onCorruptRow?: (error: unknown) => void,
		opts?: { encryptionKey?: Buffer }
	) {
		this.db = new Database(dbPath);
		this.onCorruptRow = onCorruptRow;
		this.encryptionKey = opts?.encryptionKey;
	}

	private reportCorruptRow(error: unknown): void {
		// A missing encryption key is a configuration problem, not row
		// corruption - propagate instead of silently skipping every row.
		if (error instanceof StorageEncryptedError) {
			throw error;
		}
		if (this.onCorruptRow) {
			this.onCorruptRow(error);
		}
	}

	/** Encrypt a sensitive payload value when an encryption key is configured. */
	private _enc(value: string): string {
		return this.encryptionKey ? encryptValue(this.encryptionKey, value) : value;
	}

	/**
	 * Decrypt a sensitive payload value. Plaintext (pre-encryption) rows pass
	 * through unchanged so migration is lazy-safe. Encrypted rows without a
	 * configured key fail with a clear error rather than returning garbage.
	 */
	private _dec(value: string): string {
		if (!isEncryptedValue(value)) return value;
		if (!this.encryptionKey) {
			throw new StorageEncryptedError();
		}
		return decryptValue(this.encryptionKey, value);
	}

	open(opts?: { synchronous?: 'FULL' | 'NORMAL' }): void {
		this.db.pragma('journal_mode = WAL');
		this.db.pragma(`synchronous = ${opts?.synchronous ?? 'FULL'}`);
		this.db.pragma('foreign_keys = ON');
		this.db.pragma('busy_timeout = 5000');
		this._createTables();
		if (this.encryptionKey) {
			this._encryptExistingData();
		}
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
	static readonly CURRENT_SCHEMA_VERSION = 9;

	/**
	 * Row cap for forwarding_events: bounds DB growth on busy routing nodes.
	 * Oldest rows are pruned on insert once the cap is exceeded. Instance
	 * property (not a constant) so tests can exercise pruning with a small cap.
	 */
	forwardingEventsMaxRows = 100_000;

	/**
	 * Sensitive payload columns encrypted at rest when an encryptionKey is set.
	 * Primary-key/lookup columns are never encrypted (they appear in WHERE
	 * clauses); public or non-secret tables (gossip, mission control, peer
	 * addresses, scid mappings, action log, ...) are excluded.
	 */
	private static readonly ENCRYPTED_COLUMNS: ReadonlyArray<{
		table: string;
		pk: string;
		columns: string[];
	}> = [
		{ table: 'channels', pk: 'channel_id', columns: ['state_json'] },
		{ table: 'payments', pk: 'payment_hash', columns: ['payment_json'] },
		{ table: 'preimages', pk: 'payment_hash', columns: ['preimage'] },
		{
			table: 'htlc_payment_map',
			pk: 'htlc_key',
			columns: ['payment_hash_hex']
		},
		{
			table: 'forwarded_htlcs',
			pk: 'out_key',
			columns: ['in_channel_id', 'in_htlc_id']
		},
		{ table: 'chain_monitors', pk: 'channel_id', columns: ['state_json'] },
		{ table: 'payment_secrets', pk: 'payment_hash_hex', columns: ['secret'] },
		{ table: 'htlc_shared_secrets', pk: 'key', columns: ['secret'] },
		{ table: 'invoices', pk: 'payment_hash_hex', columns: ['invoice_json'] },
		{
			table: 'channel_key_indices',
			pk: 'channel_id',
			columns: ['channel_index']
		},
		// Opaque per-peer blobs (BOLT 1 peer storage). The sender encrypts them
		// itself, but they are still user data we should not leak from a stolen
		// database file.
		{ table: 'peer_storage_blobs', pk: 'peer_pubkey', columns: ['blob'] },
		// Watchtower session keys are per-session Noise identities; the justice
		// blobs are already ciphertext but still reveal breach hints, so both are
		// encrypted at rest.
		{
			table: 'watchtower_sessions',
			pk: 'session_id',
			columns: ['session_key']
		},
		{ table: 'watchtower_updates', pk: 'id', columns: ['encrypted_blob'] },
		// On-chain wallet state (addresses, UTXOs, transactions, balance) is
		// privacy-sensitive: a stolen DB file must not reveal the wallet's
		// holdings or address set.
		{ table: 'wallet_data', pk: 'key', columns: ['value'] }
	];

	/**
	 * Rewrite any plaintext rows in the sensitive tables as encrypted values,
	 * in a single transaction. Idempotent: rows already carrying the 'enc1:'
	 * prefix are skipped, so reopening an already-encrypted database is a no-op.
	 */
	private _encryptExistingData(): void {
		const key = this.encryptionKey;
		if (!key) return;
		this.db.transaction(() => {
			for (const { table, pk, columns } of SqliteStorage.ENCRYPTED_COLUMNS) {
				const rows = this.db
					.prepare(`SELECT ${pk}, ${columns.join(', ')} FROM ${table}`)
					.all() as Array<Record<string, unknown>>;
				for (const row of rows) {
					const updates: string[] = [];
					const params: unknown[] = [];
					for (const col of columns) {
						const raw = row[col];
						if (raw === null || raw === undefined) continue;
						// channel_key_indices stores integers; encrypt their string form
						const text = typeof raw === 'string' ? raw : String(raw);
						if (isEncryptedValue(text)) continue;
						updates.push(`${col} = ?`);
						params.push(encryptValue(key, text));
					}
					if (updates.length === 0) continue;
					params.push(row[pk]);
					this.db
						.prepare(
							`UPDATE ${table} SET ${updates.join(', ')} WHERE ${pk} = ?`
						)
						.run(...params);
				}
			}
		})();
	}

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

			CREATE TABLE IF NOT EXISTS channel_policies (
				channel_id TEXT PRIMARY KEY,
				policy_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS peer_storage_blobs (
				peer_pubkey TEXT PRIMARY KEY,
				blob TEXT NOT NULL,
				received_at INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS forwarding_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				settled_at INTEGER NOT NULL,
				in_channel_id TEXT NOT NULL,
				out_channel_id TEXT NOT NULL,
				in_scid TEXT,
				out_scid TEXT,
				amount_in_msat TEXT NOT NULL,
				amount_out_msat TEXT NOT NULL,
				fee_msat TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_forwarding_events_settled_at ON forwarding_events(settled_at);

			CREATE TABLE IF NOT EXISTS watchtower_sessions (
				session_id TEXT PRIMARY KEY,
				tower_uri TEXT NOT NULL,
				tower_pubkey TEXT NOT NULL,
				session_key TEXT NOT NULL,
				blob_type INTEGER NOT NULL,
				max_updates INTEGER NOT NULL,
				sweep_fee_rate TEXT NOT NULL,
				seq_num INTEGER NOT NULL,
				last_applied INTEGER NOT NULL,
				created_at INTEGER NOT NULL,
				dials_with_session_key INTEGER NOT NULL DEFAULT 0
			);
			CREATE INDEX IF NOT EXISTS idx_watchtower_sessions_tower ON watchtower_sessions(tower_uri);

			CREATE TABLE IF NOT EXISTS watchtower_updates (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				tower_uri TEXT NOT NULL,
				channel_id TEXT NOT NULL,
				hint TEXT NOT NULL,
				encrypted_blob TEXT NOT NULL,
				seq_num INTEGER NOT NULL,
				acked INTEGER NOT NULL,
				created_at INTEGER NOT NULL,
				blob_type INTEGER NOT NULL DEFAULT 2
			);
			CREATE INDEX IF NOT EXISTS idx_watchtower_updates_pending ON watchtower_updates(tower_uri, acked);

			CREATE TABLE IF NOT EXISTS wallet_data (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
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
			.run(id, this._enc(json), peerPubkey);
	}

	loadChannel(id: string): { state: IChannelState; peerPubkey: string } | null {
		const row = this.db
			.prepare(
				'SELECT state_json, peer_pubkey FROM channels WHERE channel_id = ?'
			)
			.get(id) as { state_json: string; peer_pubkey: string } | undefined;
		if (!row) return null;
		return {
			state: deserializeChannelState(JSON.parse(this._dec(row.state_json))),
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
					state: deserializeChannelState(JSON.parse(this._dec(row.state_json))),
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
			.run(paymentHash, this._enc(json));
	}

	loadPayment(paymentHash: string): IPaymentInfo | null {
		const row = this.db
			.prepare('SELECT payment_json FROM payments WHERE payment_hash = ?')
			.get(paymentHash) as { payment_json: string } | undefined;
		if (!row) return null;
		return deserializePaymentInfo(JSON.parse(this._dec(row.payment_json)));
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
					payment: deserializePaymentInfo(
						JSON.parse(this._dec(row.payment_json))
					)
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
			.run(paymentHash, this._enc(preimage.toString('hex')));
	}

	loadPreimage(paymentHash: string): Buffer | null {
		const row = this.db
			.prepare('SELECT preimage FROM preimages WHERE payment_hash = ?')
			.get(paymentHash) as { preimage: string } | undefined;
		if (!row) return null;
		return Buffer.from(this._dec(row.preimage), 'hex');
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
					preimage: Buffer.from(this._dec(row.preimage), 'hex')
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
			.run(key, this._enc(paymentHashHex));
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
					paymentHashHex: this._dec(row.payment_hash_hex)
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
			.run(
				outKey,
				this._enc(inChannelId.toString('hex')),
				this._enc(inHtlcId.toString())
			);
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
					inChannelId: Buffer.from(this._dec(row.in_channel_id), 'hex'),
					inHtlcId: BigInt(this._dec(row.in_htlc_id))
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
			.run(channelId, this._enc(json));
	}

	loadChainMonitor(channelId: string): IChainMonitorState | null {
		const row = this.db
			.prepare('SELECT state_json FROM chain_monitors WHERE channel_id = ?')
			.get(channelId) as { state_json: string } | undefined;
		if (!row) return null;
		return deserializeChainMonitorState(this._dec(row.state_json));
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
					state: deserializeChainMonitorState(this._dec(row.state_json))
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
			.run(paymentHashHex, this._enc(secret.toString('hex')));
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
					secret: Buffer.from(this._dec(row.secret), 'hex')
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
			hold: invoice.hold,
			cancelledAt: invoice.cancelledAt
		});
		this.db
			.prepare(
				'INSERT OR REPLACE INTO invoices (payment_hash_hex, invoice_json) VALUES (?, ?)'
			)
			.run(paymentHashHex, this._enc(json));
	}

	loadAllInvoices(): Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> {
		const rows = this.db
			.prepare('SELECT payment_hash_hex, invoice_json FROM invoices')
			.all() as Array<{ payment_hash_hex: string; invoice_json: string }>;
		const results: Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> =
			[];
		for (const row of rows) {
			try {
				const parsed = JSON.parse(this._dec(row.invoice_json));
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
						hold: parsed.hold,
						cancelledAt: parsed.cancelledAt
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
			.run(
				channelId,
				this.encryptionKey ? this._enc(String(channelIndex)) : channelIndex
			);
	}

	/** Decode a channel_index cell: plaintext INTEGER or encrypted TEXT. */
	private _decodeChannelIndex(value: number | string): number {
		return typeof value === 'number' ? value : Number(this._dec(value));
	}

	loadChannelKeyIndex(channelId: string): number | null {
		const row = this.db
			.prepare(
				'SELECT channel_index FROM channel_key_indices WHERE channel_id = ?'
			)
			.get(channelId) as { channel_index: number | string } | undefined;
		return row ? this._decodeChannelIndex(row.channel_index) : null;
	}

	loadNextChannelIndex(): number {
		// Encrypted cells are TEXT, so SQL MAX() would compare ciphertext;
		// decode in JS instead (one small row per channel)
		const rows = this.db
			.prepare('SELECT channel_index FROM channel_key_indices')
			.all() as Array<{ channel_index: number | string }>;
		let maxIdx: number | null = null;
		for (const row of rows) {
			const idx = this._decodeChannelIndex(row.channel_index);
			if (maxIdx === null || idx > maxIdx) maxIdx = idx;
		}
		return maxIdx !== null ? maxIdx + 1 : 1;
	}

	// ─── HTLC Shared Secrets ───

	saveHtlcSharedSecret(key: string, secret: Buffer): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO htlc_shared_secrets (key, secret) VALUES (?, ?)'
			)
			.run(key, this._enc(secret.toString('hex')));
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
					secret: Buffer.from(this._dec(row.secret), 'hex')
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
			},
			// Migration 2->3: encryption-at-rest rollout. Structurally a no-op;
			// the data rewrite happens in _encryptExistingData() during open()
			// whenever an encryptionKey is provided (lazy-safe for plaintext rows)
			() => {
				// No-op
			},
			// Migration 3->4: channel_policies table (routing-policy overrides).
			// Created via CREATE IF NOT EXISTS above. Kept plaintext: the policy
			// is broadcast publicly in channel_update gossip, nothing sensitive.
			(): void => {
				// No-op
			},
			// Migration 4->5: peer_storage_blobs table (BOLT 1 peer storage).
			// Created via CREATE IF NOT EXISTS above; the blob column is in
			// ENCRYPTED_COLUMNS so it is encrypted at rest when a key is set.
			(): void => {
				// No-op
			},
			// Migration 5->6: forwarding_events table (settled-forward ledger).
			// Created via CREATE IF NOT EXISTS above. Kept plaintext: rows are
			// operator analytics on already-settled relays (channel ids, amounts,
			// timestamps; no keys, preimages or secrets), and the since/until/
			// channel filters need SQL WHERE clauses on the raw columns, which
			// encrypted values would break.
			(): void => {
				// No-op
			},
			// Migration 6->7: watchtower_sessions + watchtower_updates tables
			// (created via CREATE IF NOT EXISTS above; session_key + encrypted_blob
			// are in ENCRYPTED_COLUMNS so they are encrypted at rest when a key is
			// set).
			(): void => {
				// No-op
			},
			// Migration 7->8: wallet_data table (on-chain IWalletData key/value
			// persistence). Created via CREATE IF NOT EXISTS above; the value
			// column is in ENCRYPTED_COLUMNS so it is encrypted at rest when a
			// key is set.
			(): void => {
				// No-op
			},
			// Migration 8->9: per-blob-type watchtower sessions.
			// watchtower_updates.blob_type routes each update to a session of the
			// matching type; pre-existing rows default to 2 (ALTRUIST_COMMIT), the
			// only type old clients ever negotiated. watchtower_sessions.
			// dials_with_session_key records which Noise key the tower keyed the
			// session to; pre-existing rows used the node identity key (0).
			(db): void => {
				try {
					db.exec(
						'ALTER TABLE watchtower_updates ADD COLUMN blob_type INTEGER NOT NULL DEFAULT 2'
					);
				} catch {
					// Column may already exist (fresh DBs create it in _createTables)
				}
				try {
					db.exec(
						'ALTER TABLE watchtower_sessions ADD COLUMN dials_with_session_key INTEGER NOT NULL DEFAULT 0'
					);
				} catch {
					// Column may already exist
				}
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

	// ─── On-chain Wallet Data ───
	// Key/value persistence for the on-chain wallet's IWalletData. Values are
	// JSON strings, encrypted at rest when a key is set (see ENCRYPTED_COLUMNS).

	saveWalletData(key: string, value: string): void {
		this.db
			.prepare('INSERT OR REPLACE INTO wallet_data (key, value) VALUES (?, ?)')
			.run(key, this._enc(value));
	}

	loadWalletData(key: string): string | null {
		const row = this.db
			.prepare('SELECT value FROM wallet_data WHERE key = ?')
			.get(key) as { value: string } | undefined;
		return row ? this._dec(row.value) : null;
	}

	// ─── Channel Routing Policies ───
	// Stored plaintext: the policy is public data (broadcast in channel_update).

	saveChannelPolicy(channelId: string, policy: IPersistedChannelPolicy): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO channel_policies (channel_id, policy_json) VALUES (?, ?)'
			)
			.run(channelId, JSON.stringify(policy));
	}

	loadAllChannelPolicies(): Array<{
		channelId: string;
		policy: IPersistedChannelPolicy;
	}> {
		const rows = this.db
			.prepare('SELECT channel_id, policy_json FROM channel_policies')
			.all() as Array<{ channel_id: string; policy_json: string }>;
		const results: Array<{
			channelId: string;
			policy: IPersistedChannelPolicy;
		}> = [];
		for (const row of rows) {
			try {
				results.push({
					channelId: row.channel_id,
					policy: JSON.parse(row.policy_json) as IPersistedChannelPolicy
				});
			} catch (err) {
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteChannelPolicy(channelId: string): void {
		this.db
			.prepare('DELETE FROM channel_policies WHERE channel_id = ?')
			.run(channelId);
	}

	// ─── Peer Storage Blobs (BOLT 1 option_provide_storage) ───
	// One blob per peer, newest wins. Stored base64 and encrypted at rest
	// (see ENCRYPTED_COLUMNS): opaque user data, not ours to inspect.

	savePeerStorageBlob(
		peerPubkey: string,
		blob: Buffer,
		receivedAt: number
	): void {
		this.db
			.prepare(
				'INSERT OR REPLACE INTO peer_storage_blobs (peer_pubkey, blob, received_at) VALUES (?, ?, ?)'
			)
			.run(peerPubkey, this._enc(blob.toString('base64')), receivedAt);
	}

	loadPeerStorageBlob(
		peerPubkey: string
	): { blob: Buffer; receivedAt: number } | null {
		const row = this.db
			.prepare(
				'SELECT blob, received_at FROM peer_storage_blobs WHERE peer_pubkey = ?'
			)
			.get(peerPubkey) as { blob: string; received_at: number } | undefined;
		if (!row) return null;
		return {
			blob: Buffer.from(this._dec(row.blob), 'base64'),
			receivedAt: row.received_at
		};
	}

	deletePeerStorageBlob(peerPubkey: string): void {
		this.db
			.prepare('DELETE FROM peer_storage_blobs WHERE peer_pubkey = ?')
			.run(peerPubkey);
	}

	// ─── Watchtower (LND altruist client) ───
	// session_key + encrypted_blob are encrypted at rest (see ENCRYPTED_COLUMNS).

	saveWatchtowerSession(session: IWatchtowerSession, sessionKey: Buffer): void {
		this.db
			.prepare(
				`INSERT OR REPLACE INTO watchtower_sessions
					(session_id, tower_uri, tower_pubkey, session_key, blob_type,
					 max_updates, sweep_fee_rate, seq_num, last_applied, created_at,
					 dials_with_session_key)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
			)
			.run(
				session.sessionId,
				session.towerUri,
				session.towerPubkey,
				this._enc(sessionKey.toString('base64')),
				session.blobType,
				session.maxUpdates,
				session.sweepFeeRate,
				session.seqNum,
				session.lastApplied,
				session.createdAt,
				session.dialsWithSessionKey ? 1 : 0
			);
	}

	loadWatchtowerSessions(): Array<IWatchtowerSession & { sessionKey: Buffer }> {
		const rows = this.db
			.prepare('SELECT * FROM watchtower_sessions')
			.all() as Array<Record<string, unknown>>;
		return rows.map((r) => ({
			sessionId: r.session_id as string,
			towerUri: r.tower_uri as string,
			towerPubkey: r.tower_pubkey as string,
			sessionKey: Buffer.from(this._dec(r.session_key as string), 'base64'),
			blobType: r.blob_type as number,
			maxUpdates: r.max_updates as number,
			sweepFeeRate: r.sweep_fee_rate as string,
			seqNum: r.seq_num as number,
			lastApplied: r.last_applied as number,
			createdAt: r.created_at as number,
			dialsWithSessionKey: (r.dials_with_session_key as number) === 1
		}));
	}

	setWatchtowerSessionProgress(
		sessionId: string,
		seqNum: number,
		lastApplied: number
	): void {
		this.db
			.prepare(
				'UPDATE watchtower_sessions SET seq_num = ?, last_applied = ? WHERE session_id = ?'
			)
			.run(seqNum, lastApplied, sessionId);
	}

	deleteWatchtowerTower(towerUri: string): void {
		this.db.transaction(() => {
			this.db
				.prepare('DELETE FROM watchtower_sessions WHERE tower_uri = ?')
				.run(towerUri);
			this.db
				.prepare('DELETE FROM watchtower_updates WHERE tower_uri = ?')
				.run(towerUri);
		})();
	}

	addWatchtowerUpdate(update: IWatchtowerUpdate): number {
		const info = this.db
			.prepare(
				`INSERT INTO watchtower_updates
					(tower_uri, channel_id, hint, encrypted_blob, seq_num, acked,
					 created_at, blob_type)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
			)
			.run(
				update.towerUri,
				update.channelId,
				update.hint,
				this._enc(update.encryptedBlob),
				update.seqNum,
				update.acked ? 1 : 0,
				update.createdAt,
				update.blobType
			);
		return Number(info.lastInsertRowid);
	}

	loadPendingWatchtowerUpdates(): Array<IWatchtowerUpdate & { id: number }> {
		const rows = this.db
			.prepare(
				'SELECT * FROM watchtower_updates WHERE acked = 0 ORDER BY id ASC'
			)
			.all() as Array<Record<string, unknown>>;
		return rows.map((r) => ({
			id: r.id as number,
			towerUri: r.tower_uri as string,
			channelId: r.channel_id as string,
			blobType: r.blob_type as number,
			hint: r.hint as string,
			encryptedBlob: this._dec(r.encrypted_blob as string),
			seqNum: r.seq_num as number,
			acked: (r.acked as number) === 1,
			createdAt: r.created_at as number
		}));
	}

	markWatchtowerUpdateAcked(id: number, seqNum: number): void {
		this.db
			.prepare(
				'UPDATE watchtower_updates SET acked = 1, seq_num = ? WHERE id = ?'
			)
			.run(seqNum, id);
	}

	// ─── Forwarding Events (settled-forward ledger) ───
	// Stored plaintext (see migration 5->6 note): operator analytics, and the
	// filters/index need SQL access to the raw columns.

	saveForwardingEvent(event: Omit<IForwardingEvent, 'id'>): void {
		this.db
			.prepare(
				`INSERT INTO forwarding_events
					(settled_at, in_channel_id, out_channel_id, in_scid, out_scid,
					 amount_in_msat, amount_out_msat, fee_msat)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
			)
			.run(
				event.settledAt,
				event.inChannelId,
				event.outChannelId,
				event.inScid ?? null,
				event.outScid ?? null,
				event.amountInMsat.toString(),
				event.amountOutMsat.toString(),
				event.feeMsat.toString()
			);
		// Cap the ledger (default 100k rows), pruning oldest first
		this.db
			.prepare(
				'DELETE FROM forwarding_events WHERE id NOT IN (SELECT id FROM forwarding_events ORDER BY id DESC LIMIT ?)'
			)
			.run(this.forwardingEventsMaxRows);
	}

	listForwardingEvents(filter?: IForwardingEventFilter): IForwardingEvent[] {
		let sql =
			'SELECT id, settled_at, in_channel_id, out_channel_id, in_scid, out_scid, amount_in_msat, amount_out_msat, fee_msat FROM forwarding_events WHERE 1=1';
		const params: unknown[] = [];
		if (filter?.since !== undefined) {
			sql += ' AND settled_at >= ?';
			params.push(filter.since);
		}
		if (filter?.until !== undefined) {
			sql += ' AND settled_at <= ?';
			params.push(filter.until);
		}
		if (filter?.channelId !== undefined) {
			sql += ' AND (in_channel_id = ? OR out_channel_id = ?)';
			params.push(filter.channelId, filter.channelId);
		}
		// Newest first; id breaks same-millisecond ties deterministically
		sql += ' ORDER BY settled_at DESC, id DESC';
		// Default limit bounds response size; the table itself is already capped
		sql += ' LIMIT ?';
		params.push(
			filter?.limit !== undefined && filter.limit > 0 ? filter.limit : 1000
		);
		if (filter?.offset !== undefined && filter.offset > 0) {
			sql += ' OFFSET ?';
			params.push(filter.offset);
		}
		const rows = this.db.prepare(sql).all(...params) as Array<{
			id: number;
			settled_at: number;
			in_channel_id: string;
			out_channel_id: string;
			in_scid: string | null;
			out_scid: string | null;
			amount_in_msat: string;
			amount_out_msat: string;
			fee_msat: string;
		}>;
		return rows.map((row) => ({
			id: row.id,
			settledAt: row.settled_at,
			inChannelId: row.in_channel_id,
			outChannelId: row.out_channel_id,
			inScid: row.in_scid ?? undefined,
			outScid: row.out_scid ?? undefined,
			amountInMsat: BigInt(row.amount_in_msat),
			amountOutMsat: BigInt(row.amount_out_msat),
			feeMsat: BigInt(row.fee_msat)
		}));
	}

	getForwardingSummary(options?: { since?: number }): IForwardingSummary {
		// Accumulate in JS bigints: SQL SUM over the TEXT msat columns would
		// coerce to floats and lose precision above 2^53
		let sql =
			'SELECT amount_out_msat, fee_msat FROM forwarding_events WHERE 1=1';
		const params: unknown[] = [];
		if (options?.since !== undefined) {
			sql += ' AND settled_at >= ?';
			params.push(options.since);
		}
		let count = 0;
		let volumeOutMsat = 0n;
		let feesEarnedMsat = 0n;
		for (const row of this.db.prepare(sql).iterate(...params)) {
			const r = row as { amount_out_msat: string; fee_msat: string };
			count++;
			volumeOutMsat += BigInt(r.amount_out_msat);
			feesEarnedMsat += BigInt(r.fee_msat);
		}
		return { count, volumeOutMsat, feesEarnedMsat };
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
