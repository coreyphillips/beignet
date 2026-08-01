/**
 * The reference guardian's transactional store (docs/RECOVERY-GUARDIAN-WIRE.md
 * section 5, spec 5.5 durability rules).
 *
 * This is deliberately its OWN SQLite database, not the node's
 * IStorageBackend: a guardian is a separate role, usually a separate machine,
 * and its schema versions independently of the wallet's.
 *
 * Two properties of the wire contract live here rather than in the state
 * machine:
 *
 * - Per-namespace linearization is DATABASE-enforced, not an in-process
 *   mutex: every mutating verb runs inside one BEGIN IMMEDIATE transaction,
 *   so validation reads and the resulting writes are a single serialized
 *   unit even if a second process opens the same store file.
 * - Durability before acknowledgment: WAL mode with synchronous = FULL makes
 *   every commit fsync before control returns, so a receipt or certificate
 *   is on disk before the caller can possibly observe it. The state machine
 *   forms responses only from data a committed transaction produced.
 *
 * All u64 protocol integers (epochs, sequences, issuedAt) are stored as
 * 8-byte big-endian BLOBs: exact wire bytes, no signed-integer truncation at
 * 2^63, and memcmp order equals numeric order so range scans stay correct.
 */

import Database from 'better-sqlite3';

export function u64be(value: bigint): Buffer {
	if (value < 0n || value > 0xffffffffffffffffn) {
		throw new Error(`u64 out of range: ${value}`);
	}
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(value);
	return buf;
}

export function readU64be(buf: Buffer): bigint {
	if (buf.length !== 8) {
		throw new Error(`u64 blob must be 8 bytes, got ${buf.length}`);
	}
	return buf.readBigUInt64BE(0);
}

export interface IGuardianNamespaceRow {
	recoveryId: Buffer;
	guardianSetId: Buffer;
	/** 192-byte canonical STATE; null only for a checkpointless tombstone. */
	state: Buffer | null;
	possiblyStale: boolean;
	/** The root-signed registration (origin proof, wire 5.1); null = tombstone. */
	registrationState: Buffer | null;
	registrationSignature: Buffer | null;
	registrationReceiptIssuedAt: Buffer | null;
	registrationReceiptSignature: Buffer | null;
	/** Cumulative receipt over `state`, stored exactly as last returned. */
	receiptIssuedAt: Buffer | null;
	receiptSignature: Buffer | null;
}

export interface IGuardianRecordRow {
	recoveryId: Buffer;
	sequence: Buffer;
	epoch: Buffer;
	previousHash: Buffer;
	frameHash: Buffer;
	ciphertextHash: Buffer;
	ciphertext: Buffer;
	writerSignature: Buffer;
}

export interface IGuardianEpochRow {
	recoveryId: Buffer;
	epoch: Buffer;
	writerPublicKey: Buffer;
	/** Takeover artifacts; all null for the registration epoch. */
	certSupersededState: Buffer | null;
	certIssuedAt: Buffer | null;
	certSignature: Buffer | null;
	receiptState: Buffer | null;
	receiptIssuedAt: Buffer | null;
	receiptSignature: Buffer | null;
}

export interface IGuardianOrphanRow {
	recoveryId: Buffer;
	epoch: Buffer;
	sequence: Buffer;
	frameHash: Buffer;
	ciphertextHash: Buffer;
	reason: string;
}

interface INamespaceDbRow {
	recovery_id: Buffer;
	guardian_set_id: Buffer;
	state: Buffer | null;
	possibly_stale: number;
	registration_state: Buffer | null;
	registration_signature: Buffer | null;
	registration_receipt_issued_at: Buffer | null;
	registration_receipt_signature: Buffer | null;
	receipt_issued_at: Buffer | null;
	receipt_signature: Buffer | null;
}

interface IRecordDbRow {
	recovery_id: Buffer;
	sequence: Buffer;
	epoch: Buffer;
	previous_hash: Buffer;
	frame_hash: Buffer;
	ciphertext_hash: Buffer;
	ciphertext: Buffer;
	writer_signature: Buffer;
}

interface IEpochDbRow {
	recovery_id: Buffer;
	epoch: Buffer;
	writer_public_key: Buffer;
	cert_superseded_state: Buffer | null;
	cert_issued_at: Buffer | null;
	cert_signature: Buffer | null;
	receipt_state: Buffer | null;
	receipt_issued_at: Buffer | null;
	receipt_signature: Buffer | null;
}

interface IOrphanDbRow {
	recovery_id: Buffer;
	epoch: Buffer;
	sequence: Buffer;
	frame_hash: Buffer;
	ciphertext_hash: Buffer;
	reason: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS guardian_namespaces (
	recovery_id BLOB PRIMARY KEY,
	guardian_set_id BLOB NOT NULL,
	state BLOB,
	possibly_stale INTEGER NOT NULL DEFAULT 0,
	registration_state BLOB,
	registration_signature BLOB,
	registration_receipt_issued_at BLOB,
	registration_receipt_signature BLOB,
	receipt_issued_at BLOB,
	receipt_signature BLOB
);
CREATE TABLE IF NOT EXISTS guardian_records (
	recovery_id BLOB NOT NULL,
	sequence BLOB NOT NULL,
	epoch BLOB NOT NULL,
	previous_hash BLOB NOT NULL,
	frame_hash BLOB NOT NULL,
	ciphertext_hash BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	writer_signature BLOB NOT NULL,
	PRIMARY KEY (recovery_id, sequence)
);
CREATE TABLE IF NOT EXISTS guardian_orphan_records (
	recovery_id BLOB NOT NULL,
	epoch BLOB NOT NULL,
	sequence BLOB NOT NULL,
	previous_hash BLOB NOT NULL,
	frame_hash BLOB NOT NULL,
	ciphertext_hash BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	writer_signature BLOB NOT NULL,
	archived_at BLOB NOT NULL,
	reason TEXT NOT NULL,
	PRIMARY KEY (recovery_id, epoch, sequence)
);
CREATE TABLE IF NOT EXISTS guardian_epochs (
	recovery_id BLOB NOT NULL,
	epoch BLOB NOT NULL,
	writer_public_key BLOB NOT NULL,
	cert_superseded_state BLOB,
	cert_issued_at BLOB,
	cert_signature BLOB,
	receipt_state BLOB,
	receipt_issued_at BLOB,
	receipt_signature BLOB,
	PRIMARY KEY (recovery_id, epoch)
);
`;

export class GuardianStore {
	private readonly db: Database.Database;
	private readonly txImmediate: Database.Transaction<
		(fn: () => unknown) => unknown
	>;
	private readonly txDeferred: Database.Transaction<
		(fn: () => unknown) => unknown
	>;

	constructor(path: string) {
		this.db = new Database(path);
		// Durability pragmas, deliberately (spec 5.5 "durable BEFORE the
		// response leaves"): WAL + synchronous FULL fsyncs the WAL on every
		// commit, so a transaction that returned control has reached disk. A
		// crash after commit can therefore never lose an acknowledged record,
		// and a crash before commit loses the whole transaction atomically.
		this.db.pragma('journal_mode = WAL');
		this.db.pragma('synchronous = FULL');
		this.db.pragma('busy_timeout = 5000');
		this.db.exec(SCHEMA);
		this.txImmediate = this.db.transaction((fn: () => unknown) => fn());
		this.txDeferred = this.db.transaction((fn: () => unknown) => fn());
	}

	close(): void {
		this.db.close();
	}

	/**
	 * Run a mutating unit inside BEGIN IMMEDIATE: the write lock is taken up
	 * front, so validation reads and the writes they authorize are one
	 * serialized unit against any other writer, in this process or another.
	 */
	write<T>(fn: () => T): T {
		return this.txImmediate.immediate(fn) as T;
	}

	/** Run a read-only unit inside one snapshot-consistent transaction. */
	read<T>(fn: () => T): T {
		return this.txDeferred.deferred(fn) as T;
	}

	// ─────────────── namespaces ───────────────

	private namespaceFromDb(row: INamespaceDbRow): IGuardianNamespaceRow {
		return {
			recoveryId: row.recovery_id,
			guardianSetId: row.guardian_set_id,
			state: row.state,
			possiblyStale: row.possibly_stale !== 0,
			registrationState: row.registration_state,
			registrationSignature: row.registration_signature,
			registrationReceiptIssuedAt: row.registration_receipt_issued_at,
			registrationReceiptSignature: row.registration_receipt_signature,
			receiptIssuedAt: row.receipt_issued_at,
			receiptSignature: row.receipt_signature
		};
	}

	getNamespace(recoveryId: Buffer): IGuardianNamespaceRow | null {
		const row = this.db
			.prepare('SELECT * FROM guardian_namespaces WHERE recovery_id = ?')
			.get(recoveryId) as INamespaceDbRow | undefined;
		return row ? this.namespaceFromDb(row) : null;
	}

	listNamespaces(): IGuardianNamespaceRow[] {
		const rows = this.db
			.prepare('SELECT * FROM guardian_namespaces ORDER BY recovery_id')
			.all() as INamespaceDbRow[];
		return rows.map((row) => this.namespaceFromDb(row));
	}

	insertNamespace(row: IGuardianNamespaceRow): void {
		this.db
			.prepare(
				`INSERT INTO guardian_namespaces (
					recovery_id, guardian_set_id, state, possibly_stale,
					registration_state, registration_signature,
					registration_receipt_issued_at, registration_receipt_signature,
					receipt_issued_at, receipt_signature
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
			)
			.run(
				row.recoveryId,
				row.guardianSetId,
				row.state,
				row.possiblyStale ? 1 : 0,
				row.registrationState,
				row.registrationSignature,
				row.registrationReceiptIssuedAt,
				row.registrationReceiptSignature,
				row.receiptIssuedAt,
				row.receiptSignature
			);
	}

	/** Re-anchor a tombstoned namespace on a fresh root-signed registration. */
	reanchorNamespace(row: IGuardianNamespaceRow): void {
		this.db
			.prepare(
				`UPDATE guardian_namespaces SET
					guardian_set_id = ?, state = ?, possibly_stale = ?,
					registration_state = ?, registration_signature = ?,
					registration_receipt_issued_at = ?, registration_receipt_signature = ?,
					receipt_issued_at = ?, receipt_signature = ?
				WHERE recovery_id = ?`
			)
			.run(
				row.guardianSetId,
				row.state,
				row.possiblyStale ? 1 : 0,
				row.registrationState,
				row.registrationSignature,
				row.registrationReceiptIssuedAt,
				row.registrationReceiptSignature,
				row.receiptIssuedAt,
				row.receiptSignature,
				row.recoveryId
			);
	}

	/** Advance state and the cumulative receipt over it, atomically. */
	updateNamespaceState(
		recoveryId: Buffer,
		state: Buffer,
		receiptIssuedAt: Buffer,
		receiptSignature: Buffer
	): void {
		this.db
			.prepare(
				`UPDATE guardian_namespaces
				SET state = ?, receipt_issued_at = ?, receipt_signature = ?
				WHERE recovery_id = ?`
			)
			.run(state, receiptIssuedAt, receiptSignature, recoveryId);
	}

	setPossiblyStale(recoveryId: Buffer, possiblyStale: boolean): void {
		this.db
			.prepare(
				'UPDATE guardian_namespaces SET possibly_stale = ? WHERE recovery_id = ?'
			)
			.run(possiblyStale ? 1 : 0, recoveryId);
	}

	/**
	 * No internally consistent checkpoint survives (wire 5.10 step 1):
	 * without the stored registration there is no checkpoint at all. The row
	 * stays behind as a possibly_stale tombstone so a later re-registration
	 * re-anchors REPAIR rather than silently minting a fresh namespace.
	 */
	tombstoneNamespace(recoveryId: Buffer): void {
		this.db
			.prepare(
				`UPDATE guardian_namespaces SET
					state = NULL, possibly_stale = 1,
					registration_state = NULL, registration_signature = NULL,
					registration_receipt_issued_at = NULL,
					registration_receipt_signature = NULL,
					receipt_issued_at = NULL, receipt_signature = NULL
				WHERE recovery_id = ?`
			)
			.run(recoveryId);
	}

	// ─────────────── records ───────────────

	private recordFromDb(row: IRecordDbRow): IGuardianRecordRow {
		return {
			recoveryId: row.recovery_id,
			sequence: row.sequence,
			epoch: row.epoch,
			previousHash: row.previous_hash,
			frameHash: row.frame_hash,
			ciphertextHash: row.ciphertext_hash,
			ciphertext: row.ciphertext,
			writerSignature: row.writer_signature
		};
	}

	getRecord(recoveryId: Buffer, sequence: Buffer): IGuardianRecordRow | null {
		const row = this.db
			.prepare(
				'SELECT * FROM guardian_records WHERE recovery_id = ? AND sequence = ?'
			)
			.get(recoveryId, sequence) as IRecordDbRow | undefined;
		return row ? this.recordFromDb(row) : null;
	}

	insertRecord(row: IGuardianRecordRow): void {
		this.db
			.prepare(
				`INSERT INTO guardian_records (
					recovery_id, sequence, epoch, previous_hash, frame_hash,
					ciphertext_hash, ciphertext, writer_signature
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
			)
			.run(
				row.recoveryId,
				row.sequence,
				row.epoch,
				row.previousHash,
				row.frameHash,
				row.ciphertextHash,
				row.ciphertext,
				row.writerSignature
			);
	}

	listRecordsAfter(
		recoveryId: Buffer,
		fromExclusive: Buffer,
		limit: number
	): IGuardianRecordRow[] {
		const rows = this.db
			.prepare(
				`SELECT * FROM guardian_records
				WHERE recovery_id = ? AND sequence > ?
				ORDER BY sequence LIMIT ?`
			)
			.all(recoveryId, fromExclusive, limit) as IRecordDbRow[];
		return rows.map((row) => this.recordFromDb(row));
	}

	/** Lazy in-order iteration for the open-time verification walk. */
	iterateRecords(recoveryId: Buffer): IterableIterator<IGuardianRecordRow> {
		const iterator = this.db
			.prepare(
				'SELECT * FROM guardian_records WHERE recovery_id = ? ORDER BY sequence'
			)
			.iterate(recoveryId) as IterableIterator<IRecordDbRow>;
		const mapRow = this.recordFromDb.bind(this);
		return (function* (): IterableIterator<IGuardianRecordRow> {
			for (const row of iterator) yield mapRow(row);
		})();
	}

	/**
	 * Move every stored record above a sequence into the orphan archive
	 * (wire 5.7 truncation, 5.10 rollback): retained for auditing, excluded
	 * from GET_STATE and from every state the guardian signs.
	 */
	archiveRecordsAbove(
		recoveryId: Buffer,
		sequenceExclusive: Buffer,
		reason: string,
		archivedAt: Buffer
	): number {
		const moved = this.db
			.prepare(
				`INSERT OR REPLACE INTO guardian_orphan_records (
					recovery_id, epoch, sequence, previous_hash, frame_hash,
					ciphertext_hash, ciphertext, writer_signature, archived_at, reason
				)
				SELECT recovery_id, epoch, sequence, previous_hash, frame_hash,
					ciphertext_hash, ciphertext, writer_signature, ?, ?
				FROM guardian_records WHERE recovery_id = ? AND sequence > ?`
			)
			.run(archivedAt, reason, recoveryId, sequenceExclusive).changes;
		this.db
			.prepare(
				'DELETE FROM guardian_records WHERE recovery_id = ? AND sequence > ?'
			)
			.run(recoveryId, sequenceExclusive);
		return moved;
	}

	/**
	 * Sweep structurally malformed record rows into the orphan archive.
	 * Malformed means the wrong STORAGE CLASS as well as the wrong width:
	 * these are ordinary (non-STRICT) tables, so BLOB affinity does not
	 * guarantee the BLOB storage class, and a same-length TEXT value passes
	 * a bare length() check while decoding to no Buffer at all. TEXT also
	 * sorts BEFORE every BLOB, so such a row dodges the blob-keyed range
	 * deletes; this shape sweep, mirroring the in-process validators
	 * exactly, is what keeps rollback idempotent: a damaged row can never
	 * survive to re-fail verification on the next open.
	 */
	archiveMalformedRecords(
		recoveryId: Buffer,
		reason: string,
		archivedAt: Buffer
	): number {
		const bad = (column: string, width: number): string =>
			`(typeof(${column}) != 'blob' OR length(${column}) != ${width})`;
		const predicate = `(
			${bad('sequence', 8)} OR ${bad('epoch', 8)} OR
			${bad('previous_hash', 32)} OR ${bad('frame_hash', 32)} OR
			${bad('ciphertext_hash', 32)} OR ${bad('writer_signature', 64)} OR
			typeof(ciphertext) != 'blob' OR length(ciphertext) < 1
		)`;
		const moved = this.db
			.prepare(
				`INSERT OR REPLACE INTO guardian_orphan_records (
					recovery_id, epoch, sequence, previous_hash, frame_hash,
					ciphertext_hash, ciphertext, writer_signature, archived_at, reason
				)
				SELECT recovery_id, epoch, sequence, previous_hash, frame_hash,
					ciphertext_hash, ciphertext, writer_signature, ?, ?
				FROM guardian_records WHERE recovery_id = ? AND ${predicate}`
			)
			.run(archivedAt, reason, recoveryId).changes;
		this.db
			.prepare(
				`DELETE FROM guardian_records WHERE recovery_id = ? AND ${predicate}`
			)
			.run(recoveryId);
		return moved;
	}

	/** The epoch-row counterpart of archiveMalformedRecords. */
	deleteMalformedEpochs(recoveryId: Buffer): number {
		const bad = (column: string, width: number): string =>
			`(typeof(${column}) != 'blob' OR length(${column}) != ${width})`;
		const badNullable = (column: string, width: number): string =>
			`(${column} IS NOT NULL AND ${bad(column, width)})`;
		return this.db
			.prepare(
				`DELETE FROM guardian_epochs WHERE recovery_id = ? AND (
					${bad('epoch', 8)} OR ${bad('writer_public_key', 32)} OR
					${badNullable('cert_superseded_state', 192)} OR
					${badNullable('cert_issued_at', 8)} OR
					${badNullable('cert_signature', 64)} OR
					${badNullable('receipt_state', 192)} OR
					${badNullable('receipt_issued_at', 8)} OR
					${badNullable('receipt_signature', 64)}
				)`
			)
			.run(recoveryId).changes;
	}

	/**
	 * Restore a namespace primary key that corruption re-pointed at the
	 * wrong 32-byte value. The records and epochs tables carry their own
	 * recovery_id and were never re-keyed, so only the namespace row moves.
	 */
	rekeyNamespace(fromRecoveryId: Buffer, toRecoveryId: Buffer): void {
		this.db
			.prepare(
				'UPDATE guardian_namespaces SET recovery_id = ? WHERE recovery_id = ?'
			)
			.run(toRecoveryId, fromRecoveryId);
	}

	/** Replace a registration receipt whose stored artifact failed to verify. */
	updateRegistrationReceipt(
		recoveryId: Buffer,
		issuedAt: Buffer,
		signature: Buffer
	): void {
		this.db
			.prepare(
				`UPDATE guardian_namespaces
				SET registration_receipt_issued_at = ?, registration_receipt_signature = ?
				WHERE recovery_id = ?`
			)
			.run(issuedAt, signature, recoveryId);
	}

	listOrphans(recoveryId: Buffer): IGuardianOrphanRow[] {
		const rows = this.db
			.prepare(
				`SELECT recovery_id, epoch, sequence, frame_hash, ciphertext_hash, reason
				FROM guardian_orphan_records WHERE recovery_id = ?
				ORDER BY epoch, sequence`
			)
			.all(recoveryId) as IOrphanDbRow[];
		return rows.map((row) => ({
			recoveryId: row.recovery_id,
			epoch: row.epoch,
			sequence: row.sequence,
			frameHash: row.frame_hash,
			ciphertextHash: row.ciphertext_hash,
			reason: row.reason
		}));
	}

	// ─────────────── epochs ───────────────

	private epochFromDb(row: IEpochDbRow): IGuardianEpochRow {
		return {
			recoveryId: row.recovery_id,
			epoch: row.epoch,
			writerPublicKey: row.writer_public_key,
			certSupersededState: row.cert_superseded_state,
			certIssuedAt: row.cert_issued_at,
			certSignature: row.cert_signature,
			receiptState: row.receipt_state,
			receiptIssuedAt: row.receipt_issued_at,
			receiptSignature: row.receipt_signature
		};
	}

	getEpoch(recoveryId: Buffer, epoch: Buffer): IGuardianEpochRow | null {
		const row = this.db
			.prepare(
				'SELECT * FROM guardian_epochs WHERE recovery_id = ? AND epoch = ?'
			)
			.get(recoveryId, epoch) as IEpochDbRow | undefined;
		return row ? this.epochFromDb(row) : null;
	}

	listEpochs(recoveryId: Buffer): IGuardianEpochRow[] {
		const rows = this.db
			.prepare(
				'SELECT * FROM guardian_epochs WHERE recovery_id = ? ORDER BY epoch'
			)
			.all(recoveryId) as IEpochDbRow[];
		return rows.map((row) => this.epochFromDb(row));
	}

	insertEpoch(row: IGuardianEpochRow): void {
		this.db
			.prepare(
				`INSERT INTO guardian_epochs (
					recovery_id, epoch, writer_public_key,
					cert_superseded_state, cert_issued_at, cert_signature,
					receipt_state, receipt_issued_at, receipt_signature
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
			)
			.run(
				row.recoveryId,
				row.epoch,
				row.writerPublicKey,
				row.certSupersededState,
				row.certIssuedAt,
				row.certSignature,
				row.receiptState,
				row.receiptIssuedAt,
				row.receiptSignature
			);
	}

	deleteEpochsAbove(recoveryId: Buffer, epochExclusive: Buffer): void {
		this.db
			.prepare(
				'DELETE FROM guardian_epochs WHERE recovery_id = ? AND epoch > ?'
			)
			.run(recoveryId, epochExclusive);
	}

	deleteAllRecords(
		recoveryId: Buffer,
		reason: string,
		archivedAt: Buffer
	): void {
		this.archiveRecordsAbove(recoveryId, u64be(0n), reason, archivedAt);
	}

	deleteAllEpochs(recoveryId: Buffer): void {
		this.db
			.prepare('DELETE FROM guardian_epochs WHERE recovery_id = ?')
			.run(recoveryId);
	}
}
