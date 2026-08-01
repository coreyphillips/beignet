/**
 * The reference guardian (docs/RECOVERY-GUARDIAN-WIRE.md section 5): a
 * per-namespace linearized state machine over the transactional store in
 * guardian-store.ts.
 *
 * The contract this file exists to honor, mechanically:
 *
 * - One state machine per recovery_id, no interleaving: every mutating verb
 *   validates and commits inside a single BEGIN IMMEDIATE transaction, so
 *   serialization is enforced by the database, not by an in-process mutex.
 * - Durable before acknowledgment: the record, the state transition, and the
 *   EXACT receipt or certificate the response will carry are committed in
 *   that same transaction; the response object is only assembled after the
 *   transaction has returned, from the bytes it persisted.
 * - Idempotent replays return the STORED artifact, never a re-signed
 *   equivalent: a fresh issuedAt would break mechanical idempotency.
 * - A store that cannot prove itself intact refuses ordinary writes until
 *   rollback-then-replay repair (wire 5.10) reaches a target state supported
 *   by a threshold bundle of quorum evidence; writer possession alone never
 *   re-enters writability.
 *
 * Where this module and the wire specification disagree, the wire
 * specification wins and this module has a bug.
 */

import { createHash } from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	CRASH_V1_PROFILE,
	GUARDIAN_PROTOCOL_VERSION,
	GuardianState,
	LogHead,
	acquireTranscriptHash,
	computeGuardianSetId,
	isGenesisLogHead,
	parseStateBytes,
	receiptTranscriptHash,
	recordTranscriptHash,
	registerTranscriptHash,
	signTranscript,
	stateBytes,
	statesEqual,
	takeoverTranscriptHash,
	verifyTranscript,
	xOnlyFromSecret
} from './guardian-wire';
import {
	GuardianStore,
	IGuardianEpochRow,
	IGuardianNamespaceRow,
	IGuardianOrphanRow,
	IGuardianRecordRow,
	readU64be,
	u64be
} from './guardian-store';

/** Protocol status codes (wire spec section 7). */
export enum GuardianStatus {
	OK = 0,
	OK_DUPLICATE = 1,
	ERR_UNSUPPORTED_VERSION = 10,
	ERR_MALFORMED = 11,
	ERR_UNKNOWN_NODE = 12,
	ERR_UNKNOWN_SET = 13,
	ERR_ALREADY_REGISTERED = 14,
	ERR_EPOCH_SUPERSEDED = 20,
	ERR_SEQUENCE_GAP = 21,
	ERR_PREV_HASH_MISMATCH = 22,
	ERR_BAD_SIGNATURE = 23,
	ERR_CAS_FAILED = 24,
	ERR_CONFLICT = 25,
	ERR_INSUFFICIENT_CERTS = 26,
	ERR_CERT_MISMATCH = 27,
	ERR_EPOCH_REGRESSION = 28,
	ERR_HEAD_UNKNOWN = 29,
	ERR_STORE_UNCERTAIN = 30,
	ERR_RATE_LIMITED = 31,
	ERR_TOO_LARGE = 32,
	ERR_INTERNAL = 50
}

// ─────────────── wire objects, decoded (wire spec section 6) ───────────────

export interface IGuardianReceipt {
	protocolVersion: number;
	guardianSetId: Buffer;
	guardianId: Buffer;
	state: GuardianState;
	issuedAt: bigint;
	signature: Buffer;
}

export interface IGuardianTakeoverCertificate {
	protocolVersion: number;
	guardianSetId: Buffer;
	guardianId: Buffer;
	supersededState: GuardianState;
	newEpoch: bigint;
	newWriterPublicKey: Buffer;
	issuedAt: bigint;
	signature: Buffer;
}

/** The Record message; ciphertextHash is computed, never carried. */
export interface IGuardianRecord {
	protocolVersion: number;
	guardianSetId: Buffer;
	recoveryId: Buffer;
	epoch: bigint;
	sequence: bigint;
	previousHash: Buffer;
	frameHash: Buffer;
	ciphertext: Buffer;
	writerSignature: Buffer;
}

export interface IGuardianRegisterNodeRequest {
	protocolVersion: number;
	guardianSetId: Buffer;
	initialState: GuardianState;
	rootSignature: Buffer;
}

export interface IGuardianRegisterNodeResponse {
	status: GuardianStatus;
	detail?: string;
	receipt?: IGuardianReceipt;
	current?: GuardianState;
}

export interface IGuardianPutStateRequest {
	record: IGuardianRecord;
}

export interface IGuardianPutStateResponse {
	status: GuardianStatus;
	detail?: string;
	receipt?: IGuardianReceipt;
	current?: GuardianState;
}

export interface IGuardianGetHeadRequest {
	protocolVersion: number;
	guardianSetId: Buffer;
	recoveryId: Buffer;
}

export interface IGuardianGetHeadResponse {
	status: GuardianStatus;
	detail?: string;
	state?: GuardianState;
	receipt?: IGuardianReceipt;
	certificates?: IGuardianTakeoverCertificate[];
	possiblyStale?: boolean;
	registration?: IGuardianRegisterNodeRequest;
}

export interface IGuardianGetStateRequest {
	protocolVersion: number;
	guardianSetId: Buffer;
	recoveryId: Buffer;
	/** Exclusive; 0 starts from the origin. */
	fromSequence: bigint;
	/** 0 means "guardian default". */
	maxRecords: number;
}

export interface IGuardianGetStateResponse {
	status: GuardianStatus;
	detail?: string;
	records?: IGuardianRecord[];
	hasMore?: boolean;
	possiblyStale?: boolean;
}

export interface IGuardianAcquireEpochRequest {
	protocolVersion: number;
	guardianSetId: Buffer;
	expectedState: GuardianState;
	newEpoch: bigint;
	newWriterPublicKey: Buffer;
	rootSignature: Buffer;
	newWriterSignature: Buffer;
}

export interface IGuardianAcquireEpochResponse {
	status: GuardianStatus;
	detail?: string;
	certificate?: IGuardianTakeoverCertificate;
	receipt?: IGuardianReceipt;
	current?: GuardianState;
	certificates?: IGuardianTakeoverCertificate[];
}

export interface IGuardianSyncRecordRequest {
	record: IGuardianRecord;
}

export interface IGuardianSyncRecordResponse {
	status: GuardianStatus;
	detail?: string;
	receipt?: IGuardianReceipt;
}

export interface IGuardianSyncEpochRequest {
	certificates: IGuardianTakeoverCertificate[];
}

export interface IGuardianSyncEpochResponse {
	status: GuardianStatus;
	detail?: string;
	certificate?: IGuardianTakeoverCertificate;
	receipt?: IGuardianReceipt;
}

export interface IGuardianInfoResponse {
	guardianId: Buffer;
	minProtocolVersion: number;
	maxProtocolVersion: number;
	guardianSetIds: Buffer[];
	maxCiphertextBytes: number;
	maxRecordsPerGet: number;
	rateLimitPerMinute: number;
}

/**
 * Repair evidence intake (wire 5.10 step 5). This is a local operator or
 * restore-tool API, not a signed wire verb: the artifacts themselves are
 * self-authenticating, so anyone holding them may supply them.
 */
export interface IGuardianRepairEvidenceRequest {
	recoveryId: Buffer;
	/** The quorum-evidenced target the replayed state must equal, byte-exact. */
	target: GuardianState;
	receipts: IGuardianReceipt[];
	certificates: IGuardianTakeoverCertificate[];
}

export interface IGuardianRepairEvidenceResponse {
	status: GuardianStatus;
	detail?: string;
	current?: GuardianState;
}

export interface IGuardianAlarm {
	/**
	 * EMPTY for a store-level alarm: when the recovery_id cell itself is
	 * not a 32-byte BLOB, there is no namespace identity to attribute the
	 * damage to, and fabricating one would be worse than saying so.
	 */
	recoveryId: Buffer;
	status: GuardianStatus;
	detail: string;
}

export interface IReferenceGuardianConfig {
	/** SQLite database path, or ':memory:' for tests. */
	path: string;
	/** 32-byte guardian signing secret; its x-only pubkey is guardianId. */
	guardianSecret: Buffer;
	/** The crash-v1 member set (three x-only keys), own key included. */
	members: Buffer[];
	/** Advertised ciphertext limit; the 16 MiB protocol cap bounds it. */
	maxCiphertextBytes?: number;
	/** Advertised GET_STATE page limit; the protocol caps it at 256. */
	maxRecordsPerGet?: number;
	/** Unix milliseconds; injectable so tests pin issuedAt. */
	clock?: () => bigint;
	/** Crash-fault-model breaches and store rollbacks surface here. */
	onAlarm?: (alarm: IGuardianAlarm) => void;
}

const MAX_CIPHERTEXT_PROTOCOL_CAP = 16 * 1024 * 1024;
const MAX_RECORDS_PER_GET_PROTOCOL_CAP = 256;
const U64_MAX = 0xffffffffffffffffn;
const ZERO32 = Buffer.alloc(32);

function sha256(data: Buffer): Buffer {
	return createHash('sha256').update(data).digest();
}

function validU64(value: bigint): boolean {
	return typeof value === 'bigint' && value >= 0n && value <= U64_MAX;
}

function isLen(buf: Buffer, length: number): boolean {
	return Buffer.isBuffer(buf) && buf.length === length;
}

function logHeadsEqual(a: LogHead, b: LogHead): boolean {
	return (
		a.sequence === b.sequence &&
		a.recordEpoch === b.recordEpoch &&
		a.frameHash.equals(b.frameHash) &&
		a.ciphertextHash.equals(b.ciphertextHash)
	);
}

/**
 * Non-throwing u64 read for PERSISTED bytes. The open-time verifier judges
 * stored data; stored data must never escape it as an exception, or one
 * malformed column would stop the repair path instead of entering it
 * (wire 5.10 repairs per namespace). The parameter is unknown ON PURPOSE:
 * these are ordinary, non-STRICT SQLite tables, so BLOB affinity does not
 * guarantee the BLOB storage class, and a TEXT value of length eight would
 * pass a bare length check and then throw on readBigUInt64BE.
 */
function tryReadU64(value: unknown): bigint | null {
	if (!Buffer.isBuffer(value) || value.length !== 8) return null;
	return value.readBigUInt64BE(0);
}

/** Structural (width-only) validity of a stored record row. */
function recordRowProblem(row: IGuardianRecordRow): string | null {
	if (!isLen(row.sequence, 8)) return 'sequence column malformed';
	if (!isLen(row.epoch, 8)) return 'epoch column malformed';
	if (!isLen(row.previousHash, 32)) return 'previous hash column malformed';
	if (!isLen(row.frameHash, 32)) return 'frame hash column malformed';
	if (!isLen(row.ciphertextHash, 32)) return 'ciphertext hash column malformed';
	if (!isLen(row.writerSignature, 64))
		return 'writer signature column malformed';
	if (!Buffer.isBuffer(row.ciphertext) || row.ciphertext.length === 0) {
		return 'ciphertext column malformed';
	}
	return null;
}

/**
 * Structural (width-only) validity of a stored epoch row. Deliberately
 * mirrors the SQL predicate of deleteMalformedEpochs: every row this filter
 * rejects, the rollback sweep can also remove, so a damaged row never
 * survives to re-fail verification on the next open. Mixed null and present
 * artifact columns are NOT flagged here; applyTakeover fails those on the
 * walk, where the ordinary range delete reaches them.
 */
function epochRowProblem(row: IGuardianEpochRow): string | null {
	if (!isLen(row.epoch, 8)) return 'epoch column malformed';
	if (!isLen(row.writerPublicKey, 32)) return 'writer key column malformed';
	if (
		row.certSupersededState !== null &&
		!isLen(row.certSupersededState, 192)
	) {
		return 'superseded state column malformed';
	}
	if (row.certIssuedAt !== null && !isLen(row.certIssuedAt, 8)) {
		return 'certificate issuedAt column malformed';
	}
	if (row.certSignature !== null && !isLen(row.certSignature, 64)) {
		return 'certificate signature column malformed';
	}
	if (row.receiptState !== null && !isLen(row.receiptState, 192)) {
		return 'receipt state column malformed';
	}
	if (row.receiptIssuedAt !== null && !isLen(row.receiptIssuedAt, 8)) {
		return 'receipt issuedAt column malformed';
	}
	if (row.receiptSignature !== null && !isLen(row.receiptSignature, 64)) {
		return 'receipt signature column malformed';
	}
	return null;
}

function tryParseState(buf: Buffer | null): GuardianState | null {
	if (!buf) return null;
	try {
		return parseStateBytes(buf);
	} catch {
		return null;
	}
}

interface IErr {
	status: GuardianStatus;
	detail: string;
}

function err(status: GuardianStatus, detail: string): IErr {
	return { status, detail };
}

export class ReferenceGuardian {
	readonly guardianId: Buffer;
	readonly guardianSetId: Buffer;
	private readonly store: GuardianStore;
	private readonly secret: Buffer;
	private readonly members: Buffer[];
	private readonly required: number;
	private readonly maxCiphertextBytes: number;
	private readonly maxRecordsPerGet: number;
	private readonly clock: () => bigint;
	private readonly onAlarm?: (alarm: IGuardianAlarm) => void;
	/**
	 * Namespaces this process refuses to serve or touch: a stored
	 * guardian_set_id that is not the configured one (misconfiguration or
	 * column rot; either way nothing under it is provably ours), or a
	 * verification pass that failed in a way the non-throwing walk could not
	 * classify (I/O errors). Quarantine is deliberately NON-destructive and
	 * per namespace: every verb answers ERR_STORE_UNCERTAIN, nothing is
	 * rolled back or archived, and one damaged namespace can never prevent
	 * the guardian from starting or serving its healthy ones.
	 */
	private readonly quarantined = new Set<string>();

	constructor(config: IReferenceGuardianConfig) {
		if (
			!isLen(config.guardianSecret, 32) ||
			!ecc.isPrivate(config.guardianSecret)
		) {
			throw new Error('guardianSecret must be a valid 32-byte secp256k1 key');
		}
		this.secret = Buffer.from(config.guardianSecret);
		this.guardianId = xOnlyFromSecret(this.secret);
		// computeGuardianSetId enforces crash-v1, distinctness, and that every
		// member is a real x-only point.
		this.guardianSetId = computeGuardianSetId({
			...CRASH_V1_PROFILE,
			guardianIds: config.members
		});
		this.members = config.members.map((m) => Buffer.from(m));
		this.required = CRASH_V1_PROFILE.required;
		if (!this.members.some((m) => m.equals(this.guardianId))) {
			throw new Error('guardianSecret does not belong to the member set');
		}
		const maxCiphertext =
			config.maxCiphertextBytes ?? MAX_CIPHERTEXT_PROTOCOL_CAP;
		if (
			!Number.isInteger(maxCiphertext) ||
			maxCiphertext < 1 ||
			maxCiphertext > MAX_CIPHERTEXT_PROTOCOL_CAP
		) {
			throw new Error(
				'maxCiphertextBytes must be within the 16 MiB protocol cap'
			);
		}
		this.maxCiphertextBytes = maxCiphertext;
		const maxRecords =
			config.maxRecordsPerGet ?? MAX_RECORDS_PER_GET_PROTOCOL_CAP;
		if (
			!Number.isInteger(maxRecords) ||
			maxRecords < 1 ||
			maxRecords > MAX_RECORDS_PER_GET_PROTOCOL_CAP
		) {
			throw new Error('maxRecordsPerGet must be between 1 and 256');
		}
		this.maxRecordsPerGet = maxRecords;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
		this.onAlarm = config.onAlarm;
		this.store = new GuardianStore(config.path);
		try {
			this.verifyStoreAtOpen();
		} catch (error) {
			this.store.close();
			throw error;
		}
	}

	close(): void {
		this.store.close();
	}

	/** Discovery (wire 5.8); nothing here is signed or load-bearing. */
	info(): IGuardianInfoResponse {
		return {
			guardianId: Buffer.from(this.guardianId),
			minProtocolVersion: GUARDIAN_PROTOCOL_VERSION,
			maxProtocolVersion: GUARDIAN_PROTOCOL_VERSION,
			guardianSetIds: [Buffer.from(this.guardianSetId)],
			maxCiphertextBytes: this.maxCiphertextBytes,
			maxRecordsPerGet: this.maxRecordsPerGet,
			rateLimitPerMinute: 0
		};
	}

	/** Orphan-archive audit view (never served by GET_STATE). */
	listOrphanedRecords(recoveryId: Buffer): IGuardianOrphanRow[] {
		return this.store.listOrphans(recoveryId);
	}

	// ─────────────── shared helpers ───────────────

	private alarm(
		recoveryId: Buffer,
		status: GuardianStatus,
		detail: string
	): void {
		if (this.onAlarm) {
			this.onAlarm({ recoveryId: Buffer.from(recoveryId), status, detail });
		}
	}

	/**
	 * Report damage that cannot be attributed to an addressable namespace:
	 * the recovery_id cell itself is not a 32-byte BLOB, so there is no key
	 * to quarantine by and no Buffer to hand to consumers. The row is left
	 * untouched; it is unreachable by every verb anyway, because no 32-byte
	 * key can ever match it.
	 */
	private storeAlarm(detail: string): void {
		if (this.onAlarm) {
			this.onAlarm({
				recoveryId: Buffer.alloc(0),
				status: GuardianStatus.ERR_STORE_UNCERTAIN,
				detail
			});
		}
	}

	private safeVerify(hash: Buffer, signature: Buffer, key: Buffer): boolean {
		try {
			return verifyTranscript(hash, signature, key);
		} catch {
			return false;
		}
	}

	private quarantineGate(recoveryId: Buffer): IErr | null {
		if (!this.quarantined.has(recoveryId.toString('hex'))) return null;
		return err(
			GuardianStatus.ERR_STORE_UNCERTAIN,
			'namespace is quarantined; resolve the guardian store or configuration'
		);
	}

	private versionAndSetProblem(
		protocolVersion: number,
		guardianSetId: Buffer
	): IErr | null {
		if (protocolVersion !== GUARDIAN_PROTOCOL_VERSION) {
			return err(
				GuardianStatus.ERR_UNSUPPORTED_VERSION,
				`protocol_version ${protocolVersion} outside supported range 1..1`
			);
		}
		if (
			!isLen(guardianSetId, 32) ||
			!guardianSetId.equals(this.guardianSetId)
		) {
			return err(
				GuardianStatus.ERR_UNKNOWN_SET,
				'guardian_set_id is not served by this guardian'
			);
		}
		return null;
	}

	private stateShapeProblem(state: GuardianState): string | null {
		if (!isLen(state.recoveryId, 32)) return 'recovery_id must be 32 bytes';
		if (!validU64(state.lease.epoch) || state.lease.epoch === 0n) {
			return 'lease epoch must be a nonzero u64';
		}
		if (!isLen(state.lease.writerPublicKey, 32)) {
			return 'writer public key must be 32 bytes';
		}
		if (
			!validU64(state.origin.firstSequence) ||
			state.origin.firstSequence === 0n
		) {
			return 'origin firstSequence must be a nonzero u64';
		}
		if (!isLen(state.origin.previousHash, 32)) {
			return 'origin previousHash must be 32 bytes';
		}
		if (
			!validU64(state.logHead.sequence) ||
			!validU64(state.logHead.recordEpoch)
		) {
			return 'log head integers must be u64';
		}
		if (
			!isLen(state.logHead.frameHash, 32) ||
			!isLen(state.logHead.ciphertextHash, 32)
		) {
			return 'log head hashes must be 32 bytes';
		}
		return null;
	}

	private cloneState(state: GuardianState): GuardianState {
		return parseStateBytes(stateBytes(state));
	}

	private signReceipt(state: GuardianState): {
		issuedAt: bigint;
		signature: Buffer;
	} {
		const issuedAt = this.clock();
		const hash = receiptTranscriptHash(
			this.guardianSetId,
			this.guardianId,
			state,
			issuedAt
		);
		return { issuedAt, signature: signTranscript(hash, this.secret) };
	}

	private signCertificate(
		supersededState: GuardianState,
		newEpoch: bigint,
		newWriterPublicKey: Buffer
	): { issuedAt: bigint; signature: Buffer } {
		const issuedAt = this.clock();
		const hash = takeoverTranscriptHash(
			this.guardianSetId,
			this.guardianId,
			supersededState,
			newEpoch,
			newWriterPublicKey,
			issuedAt
		);
		return { issuedAt, signature: signTranscript(hash, this.secret) };
	}

	private toReceipt(
		state: GuardianState,
		issuedAt: bigint,
		signature: Buffer
	): IGuardianReceipt {
		return {
			protocolVersion: GUARDIAN_PROTOCOL_VERSION,
			guardianSetId: Buffer.from(this.guardianSetId),
			guardianId: Buffer.from(this.guardianId),
			state,
			issuedAt,
			signature: Buffer.from(signature)
		};
	}

	private storedReceipt(ns: IGuardianNamespaceRow): IGuardianReceipt {
		if (!ns.state || !ns.receiptIssuedAt || !ns.receiptSignature) {
			throw new Error('namespace has no stored receipt');
		}
		return this.toReceipt(
			parseStateBytes(ns.state),
			readU64be(ns.receiptIssuedAt),
			ns.receiptSignature
		);
	}

	private certificateFromEpochRow(
		row: IGuardianEpochRow
	): IGuardianTakeoverCertificate {
		if (!row.certSupersededState || !row.certIssuedAt || !row.certSignature) {
			throw new Error('epoch row carries no takeover certificate');
		}
		return {
			protocolVersion: GUARDIAN_PROTOCOL_VERSION,
			guardianSetId: Buffer.from(this.guardianSetId),
			guardianId: Buffer.from(this.guardianId),
			supersededState: parseStateBytes(row.certSupersededState),
			newEpoch: readU64be(row.epoch),
			newWriterPublicKey: Buffer.from(row.writerPublicKey),
			issuedAt: readU64be(row.certIssuedAt),
			signature: Buffer.from(row.certSignature)
		};
	}

	private listCertificates(recoveryId: Buffer): IGuardianTakeoverCertificate[] {
		return this.store
			.listEpochs(recoveryId)
			.filter((row) => row.certSignature !== null)
			.map((row) => this.certificateFromEpochRow(row));
	}

	/** The state a takeover certificate fixes: new lease over the old head. */
	private postTakeoverState(cert: IGuardianTakeoverCertificate): GuardianState {
		return {
			recoveryId: Buffer.from(cert.supersededState.recoveryId),
			lease: {
				epoch: cert.newEpoch,
				writerPublicKey: Buffer.from(cert.newWriterPublicKey)
			},
			origin: {
				firstSequence: cert.supersededState.origin.firstSequence,
				previousHash: Buffer.from(cert.supersededState.origin.previousHash)
			},
			logHead: {
				sequence: cert.supersededState.logHead.sequence,
				frameHash: Buffer.from(cert.supersededState.logHead.frameHash),
				ciphertextHash: Buffer.from(
					cert.supersededState.logHead.ciphertextHash
				),
				recordEpoch: cert.supersededState.logHead.recordEpoch
			}
		};
	}

	// ─────────────── REGISTER_NODE (wire 5.1) ───────────────

	register(
		request: IGuardianRegisterNodeRequest
	): IGuardianRegisterNodeResponse {
		try {
			const gate = this.versionAndSetProblem(
				request.protocolVersion,
				request.guardianSetId
			);
			if (gate) return gate;
			const state = request.initialState;
			const shape = this.stateShapeProblem(state);
			if (shape) return err(GuardianStatus.ERR_MALFORMED, shape);
			if (!ecc.isXOnlyPoint(state.recoveryId)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'recovery_id is not a valid x-only point'
				);
			}
			if (!ecc.isXOnlyPoint(state.lease.writerPublicKey)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'writer public key is not a valid x-only point'
				);
			}
			// Registration never claims records the guardian does not hold.
			if (!isGenesisLogHead(state.logHead)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'registration log head must be genesis'
				);
			}
			// A fresh chain begins where the journal begins: sequence 1 has no
			// predecessor, so a nonzero previousHash there is incoherent.
			if (
				state.origin.firstSequence === 1n &&
				!state.origin.previousHash.equals(ZERO32)
			) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'origin at firstSequence 1 requires a zero previousHash'
				);
			}
			if (!isLen(request.rootSignature, 64)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'root signature must be 64 bytes'
				);
			}
			const transcript = registerTranscriptHash(this.guardianSetId, state);
			if (
				!this.safeVerify(transcript, request.rootSignature, state.recoveryId)
			) {
				return err(
					GuardianStatus.ERR_BAD_SIGNATURE,
					'root signature over the REGISTER transcript failed'
				);
			}

			const quarantine = this.quarantineGate(state.recoveryId);
			if (quarantine) return quarantine;
			const stateBuf = stateBytes(state);
			const outcome = this.store.write(() => {
				const ns = this.store.getNamespace(state.recoveryId);
				if (ns && ns.registrationState) {
					if (ns.registrationState.equals(stateBuf)) {
						return { kind: 'duplicate' as const, ns };
					}
					return { kind: 'already' as const, ns };
				}
				// Fresh namespace, or a checkpointless tombstone re-anchoring on a
				// root-signed registration (wire 5.10 step 1): the tombstone keeps
				// possibly_stale, so writability still needs quorum evidence.
				const receipt = this.signReceipt(state);
				const row: IGuardianNamespaceRow = {
					recoveryId: Buffer.from(state.recoveryId),
					guardianSetId: Buffer.from(this.guardianSetId),
					state: stateBuf,
					possiblyStale: ns ? ns.possiblyStale : false,
					registrationState: stateBuf,
					registrationSignature: Buffer.from(request.rootSignature),
					registrationReceiptIssuedAt: u64be(receipt.issuedAt),
					registrationReceiptSignature: receipt.signature,
					receiptIssuedAt: u64be(receipt.issuedAt),
					receiptSignature: receipt.signature
				};
				if (ns) {
					this.store.reanchorNamespace(row);
					this.store.deleteAllEpochs(state.recoveryId);
				} else {
					this.store.insertNamespace(row);
				}
				this.store.insertEpoch({
					recoveryId: Buffer.from(state.recoveryId),
					epoch: u64be(state.lease.epoch),
					writerPublicKey: Buffer.from(state.lease.writerPublicKey),
					certSupersededState: null,
					certIssuedAt: null,
					certSignature: null,
					receiptState: null,
					receiptIssuedAt: null,
					receiptSignature: null
				});
				return { kind: 'ok' as const, receipt };
			});

			if (outcome.kind === 'duplicate') {
				const ns = outcome.ns;
				return {
					status: GuardianStatus.OK_DUPLICATE,
					receipt: this.toReceipt(
						parseStateBytes(ns.registrationState as Buffer),
						readU64be(ns.registrationReceiptIssuedAt as Buffer),
						ns.registrationReceiptSignature as Buffer
					)
				};
			}
			if (outcome.kind === 'already') {
				return {
					status: GuardianStatus.ERR_ALREADY_REGISTERED,
					detail: 'a differing registration exists for this recovery_id',
					current: parseStateBytes(outcome.ns.state as Buffer)
				};
			}
			return {
				status: GuardianStatus.OK,
				receipt: this.toReceipt(
					state,
					outcome.receipt.issuedAt,
					outcome.receipt.signature
				)
			};
		} catch (error) {
			return this.internalError(error);
		}
	}

	// ─────────────── PUT_STATE and SYNC_RECORD (wire 5.2, 5.6) ───────────────

	putState(request: IGuardianPutStateRequest): IGuardianPutStateResponse {
		return this.appendRecord(request.record, false);
	}

	/**
	 * SYNC_RECORD acceptance is identical to PUT_STATE because records are
	 * self-authenticating; the difference is that it stays available while
	 * the store is possibly_stale, because it IS the repair channel. It only
	 * ever appends at the current state; there is no insert-behind-head.
	 */
	syncRecord(request: IGuardianSyncRecordRequest): IGuardianSyncRecordResponse {
		const result = this.appendRecord(request.record, true);
		const response: IGuardianSyncRecordResponse = { status: result.status };
		if (result.detail !== undefined) response.detail = result.detail;
		if (result.receipt) response.receipt = result.receipt;
		return response;
	}

	private appendRecord(
		record: IGuardianRecord,
		isSync: boolean
	): IGuardianPutStateResponse {
		try {
			const gate = this.versionAndSetProblem(
				record.protocolVersion,
				record.guardianSetId
			);
			if (gate) return gate;
			if (!isLen(record.recoveryId, 32)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'recovery_id must be 32 bytes'
				);
			}
			if (!validU64(record.epoch) || record.epoch === 0n) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'record epoch must be a nonzero u64'
				);
			}
			if (!validU64(record.sequence) || record.sequence === 0n) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'sequence 0 never carries a record'
				);
			}
			if (!isLen(record.previousHash, 32) || !isLen(record.frameHash, 32)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'record hashes must be 32 bytes'
				);
			}
			if (!isLen(record.writerSignature, 64)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'writer signature must be 64 bytes'
				);
			}
			if (
				!Buffer.isBuffer(record.ciphertext) ||
				record.ciphertext.length === 0
			) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'record ciphertext is missing'
				);
			}
			if (record.ciphertext.length > this.maxCiphertextBytes) {
				return err(
					GuardianStatus.ERR_TOO_LARGE,
					`ciphertext exceeds the advertised limit of ${this.maxCiphertextBytes} bytes`
				);
			}
			const ciphertextHash = sha256(record.ciphertext);
			const quarantine = this.quarantineGate(record.recoveryId);
			if (quarantine) return quarantine;

			return this.store.write(() => {
				const ns = this.store.getNamespace(record.recoveryId);
				if (!ns) {
					return err(
						GuardianStatus.ERR_UNKNOWN_NODE,
						'recovery_id not registered'
					);
				}
				if (!ns.registrationState || !ns.state) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'no internally consistent checkpoint; re-register to re-anchor repair'
					);
				}
				if (!isSync && ns.possiblyStale) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'store is possibly stale; repair through SYNC verbs and quorum evidence'
					);
				}
				const state = parseStateBytes(ns.state);

				// Idempotency and conflict detection against the occupied slot.
				if (
					!isGenesisLogHead(state.logHead) &&
					record.sequence >= state.origin.firstSequence &&
					record.sequence <= state.logHead.sequence
				) {
					const stored = this.store.getRecord(
						record.recoveryId,
						u64be(record.sequence)
					);
					if (!stored) {
						throw new Error(
							`stored log is missing sequence ${record.sequence} inside its own range`
						);
					}
					const identical =
						readU64be(stored.epoch) === record.epoch &&
						stored.previousHash.equals(record.previousHash) &&
						stored.frameHash.equals(record.frameHash) &&
						stored.ciphertextHash.equals(ciphertextHash) &&
						stored.ciphertext.equals(record.ciphertext);
					if (identical) {
						// The signature must still verify under the writer key of
						// the epoch that governed this record.
						const epochRow = this.store.getEpoch(
							record.recoveryId,
							stored.epoch
						);
						if (!epochRow) {
							throw new Error('stored record references an unknown epoch');
						}
						const transcript = recordTranscriptHash(this.guardianSetId, {
							recoveryId: record.recoveryId,
							epoch: record.epoch,
							sequence: record.sequence,
							previousHash: record.previousHash,
							frameHash: record.frameHash,
							ciphertextHash
						});
						if (
							!this.safeVerify(
								transcript,
								record.writerSignature,
								epochRow.writerPublicKey
							)
						) {
							return err(
								GuardianStatus.ERR_BAD_SIGNATURE,
								'writer signature over the RECORD transcript failed'
							);
						}
						return {
							status: GuardianStatus.OK_DUPLICATE,
							receipt: this.storedReceipt(ns)
						};
					}
					if (readU64be(stored.epoch) === record.epoch) {
						this.alarm(
							record.recoveryId,
							GuardianStatus.ERR_CONFLICT,
							`differing record at occupied (epoch ${record.epoch}, sequence ${record.sequence})`
						);
						return err(
							GuardianStatus.ERR_CONFLICT,
							'a different record occupies this (epoch, sequence); crash-fault model breach'
						);
					}
					// A different epoch at an occupied sequence falls through to the
					// ordinary acceptance rules for a deterministic 20 or 21.
				}

				if (record.epoch !== state.lease.epoch) {
					return {
						...err(
							GuardianStatus.ERR_EPOCH_SUPERSEDED,
							record.epoch < state.lease.epoch
								? 'record epoch is fenced'
								: 'record epoch is ahead of the lease; repair the guardian with SYNC_EPOCH first'
						),
						current: state
					};
				}
				const transcript = recordTranscriptHash(this.guardianSetId, {
					recoveryId: record.recoveryId,
					epoch: record.epoch,
					sequence: record.sequence,
					previousHash: record.previousHash,
					frameHash: record.frameHash,
					ciphertextHash
				});
				if (
					!this.safeVerify(
						transcript,
						record.writerSignature,
						state.lease.writerPublicKey
					)
				) {
					return err(
						GuardianStatus.ERR_BAD_SIGNATURE,
						'writer signature over the RECORD transcript failed'
					);
				}
				const genesis = isGenesisLogHead(state.logHead);
				const expectedSequence = genesis
					? state.origin.firstSequence
					: state.logHead.sequence + 1n;
				const expectedPrevious = genesis
					? state.origin.previousHash
					: state.logHead.frameHash;
				if (record.sequence !== expectedSequence) {
					return {
						...err(
							GuardianStatus.ERR_SEQUENCE_GAP,
							`expected sequence ${expectedSequence}`
						),
						current: state
					};
				}
				if (!record.previousHash.equals(expectedPrevious)) {
					return {
						...err(
							GuardianStatus.ERR_PREV_HASH_MISMATCH,
							'previousHash does not extend the current head'
						),
						current: state
					};
				}

				this.store.insertRecord({
					recoveryId: Buffer.from(record.recoveryId),
					sequence: u64be(record.sequence),
					epoch: u64be(record.epoch),
					previousHash: Buffer.from(record.previousHash),
					frameHash: Buffer.from(record.frameHash),
					ciphertextHash,
					ciphertext: Buffer.from(record.ciphertext),
					writerSignature: Buffer.from(record.writerSignature)
				});
				const newState: GuardianState = {
					recoveryId: state.recoveryId,
					lease: state.lease,
					origin: state.origin,
					logHead: {
						sequence: record.sequence,
						frameHash: Buffer.from(record.frameHash),
						ciphertextHash,
						recordEpoch: record.epoch
					}
				};
				const receipt = this.signReceipt(newState);
				this.store.updateNamespaceState(
					record.recoveryId,
					stateBytes(newState),
					u64be(receipt.issuedAt),
					receipt.signature
				);
				return {
					status: GuardianStatus.OK,
					receipt: this.toReceipt(newState, receipt.issuedAt, receipt.signature)
				};
			});
		} catch (error) {
			return this.internalError(error);
		}
	}

	// ─────────────── GET_HEAD (wire 5.3) ───────────────

	getHead(request: IGuardianGetHeadRequest): IGuardianGetHeadResponse {
		try {
			const gate = this.versionAndSetProblem(
				request.protocolVersion,
				request.guardianSetId
			);
			if (gate) return gate;
			if (!isLen(request.recoveryId, 32)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'recovery_id must be 32 bytes'
				);
			}
			const quarantine = this.quarantineGate(request.recoveryId);
			if (quarantine) return quarantine;
			return this.store.read(() => {
				const ns = this.store.getNamespace(request.recoveryId);
				if (!ns) {
					return err(
						GuardianStatus.ERR_UNKNOWN_NODE,
						'recovery_id not registered'
					);
				}
				if (!ns.registrationState || !ns.state) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'no internally consistent checkpoint; re-register to re-anchor repair'
					);
				}
				return {
					status: GuardianStatus.OK,
					state: parseStateBytes(ns.state),
					receipt: this.storedReceipt(ns),
					certificates: this.listCertificates(request.recoveryId),
					possiblyStale: ns.possiblyStale,
					registration: {
						protocolVersion: GUARDIAN_PROTOCOL_VERSION,
						guardianSetId: Buffer.from(ns.guardianSetId),
						initialState: parseStateBytes(ns.registrationState),
						rootSignature: Buffer.from(ns.registrationSignature as Buffer)
					}
				};
			});
		} catch (error) {
			return this.internalError(error);
		}
	}

	// ─────────────── GET_STATE (wire 5.4) ───────────────

	getState(request: IGuardianGetStateRequest): IGuardianGetStateResponse {
		try {
			const gate = this.versionAndSetProblem(
				request.protocolVersion,
				request.guardianSetId
			);
			if (gate) return gate;
			if (!isLen(request.recoveryId, 32)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'recovery_id must be 32 bytes'
				);
			}
			if (!validU64(request.fromSequence)) {
				return err(GuardianStatus.ERR_MALFORMED, 'from_sequence must be a u64');
			}
			if (
				!Number.isInteger(request.maxRecords) ||
				request.maxRecords < 0 ||
				request.maxRecords > 0xffffffff
			) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'max_records must be a uint32'
				);
			}
			const limit =
				request.maxRecords === 0
					? this.maxRecordsPerGet
					: Math.min(request.maxRecords, this.maxRecordsPerGet);
			const quarantine = this.quarantineGate(request.recoveryId);
			if (quarantine) return quarantine;
			return this.store.read(() => {
				const ns = this.store.getNamespace(request.recoveryId);
				if (!ns) {
					return err(
						GuardianStatus.ERR_UNKNOWN_NODE,
						'recovery_id not registered'
					);
				}
				if (!ns.registrationState || !ns.state) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'no internally consistent checkpoint; re-register to re-anchor repair'
					);
				}
				const rows = this.store.listRecordsAfter(
					request.recoveryId,
					u64be(request.fromSequence),
					limit + 1
				);
				const hasMore = rows.length > limit;
				const page = hasMore ? rows.slice(0, limit) : rows;
				return {
					status: GuardianStatus.OK,
					records: page.map((row) => ({
						protocolVersion: GUARDIAN_PROTOCOL_VERSION,
						guardianSetId: Buffer.from(this.guardianSetId),
						recoveryId: Buffer.from(row.recoveryId),
						epoch: readU64be(row.epoch),
						sequence: readU64be(row.sequence),
						previousHash: Buffer.from(row.previousHash),
						frameHash: Buffer.from(row.frameHash),
						ciphertext: Buffer.from(row.ciphertext),
						writerSignature: Buffer.from(row.writerSignature)
					})),
					hasMore,
					possiblyStale: ns.possiblyStale
				};
			});
		} catch (error) {
			return this.internalError(error);
		}
	}

	// ─────────────── ACQUIRE_EPOCH (wire 5.5) ───────────────

	acquireEpoch(
		request: IGuardianAcquireEpochRequest
	): IGuardianAcquireEpochResponse {
		try {
			const gate = this.versionAndSetProblem(
				request.protocolVersion,
				request.guardianSetId
			);
			if (gate) return gate;
			const expected = request.expectedState;
			const shape = this.stateShapeProblem(expected);
			if (shape) return err(GuardianStatus.ERR_MALFORMED, shape);
			if (!ecc.isXOnlyPoint(request.newWriterPublicKey)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'new writer public key is not a valid x-only point'
				);
			}
			if (
				!isLen(request.rootSignature, 64) ||
				!isLen(request.newWriterSignature, 64)
			) {
				return err(GuardianStatus.ERR_MALFORMED, 'signatures must be 64 bytes');
			}
			if (
				!validU64(request.newEpoch) ||
				request.newEpoch !== expected.lease.epoch + 1n
			) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'newEpoch must equal expectedState.lease.epoch + 1'
				);
			}
			const transcript = acquireTranscriptHash(
				this.guardianSetId,
				expected,
				request.newEpoch,
				request.newWriterPublicKey
			);
			if (
				!this.safeVerify(transcript, request.rootSignature, expected.recoveryId)
			) {
				return err(
					GuardianStatus.ERR_BAD_SIGNATURE,
					'root signature over the ACQUIRE transcript failed'
				);
			}
			if (
				!this.safeVerify(
					transcript,
					request.newWriterSignature,
					request.newWriterPublicKey
				)
			) {
				return err(
					GuardianStatus.ERR_BAD_SIGNATURE,
					'new writer signature over the ACQUIRE transcript failed'
				);
			}
			const quarantine = this.quarantineGate(expected.recoveryId);
			if (quarantine) return quarantine;

			return this.store.write(() => {
				const ns = this.store.getNamespace(expected.recoveryId);
				if (!ns) {
					return err(
						GuardianStatus.ERR_UNKNOWN_NODE,
						'recovery_id not registered'
					);
				}
				if (!ns.registrationState || !ns.state) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'no internally consistent checkpoint; re-register to re-anchor repair'
					);
				}
				if (ns.possiblyStale) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'store is possibly stale; repair through SYNC verbs and quorum evidence'
					);
				}
				const current = parseStateBytes(ns.state);
				const expectedBuf = stateBytes(expected);

				const epochRow = this.store.getEpoch(
					expected.recoveryId,
					u64be(request.newEpoch)
				);
				if (epochRow) {
					if (!epochRow.writerPublicKey.equals(request.newWriterPublicKey)) {
						return {
							...err(
								GuardianStatus.ERR_EPOCH_SUPERSEDED,
								'this epoch is bound to a different writer key; first writer wins'
							),
							current,
							certificates: this.listCertificates(expected.recoveryId)
						};
					}
					if (
						epochRow.certSupersededState &&
						epochRow.certSupersededState.equals(expectedBuf) &&
						epochRow.certIssuedAt &&
						epochRow.certSignature &&
						epochRow.receiptState &&
						epochRow.receiptIssuedAt &&
						epochRow.receiptSignature
					) {
						return {
							status: GuardianStatus.OK_DUPLICATE,
							certificate: this.certificateFromEpochRow(epochRow),
							receipt: this.toReceipt(
								parseStateBytes(epochRow.receiptState),
								readU64be(epochRow.receiptIssuedAt),
								epochRow.receiptSignature
							)
						};
					}
					// Same key but not a stored acquisition replay (for example the
					// registration epoch): fall through to the CAS for a
					// deterministic rejection.
				}

				if (!statesEqual(expected, current)) {
					return {
						...err(
							GuardianStatus.ERR_CAS_FAILED,
							'expectedState does not match the stored state byte-exactly'
						),
						current,
						certificates: this.listCertificates(expected.recoveryId)
					};
				}

				const cert = this.signCertificate(
					current,
					request.newEpoch,
					request.newWriterPublicKey
				);
				const newState: GuardianState = {
					recoveryId: current.recoveryId,
					lease: {
						epoch: request.newEpoch,
						writerPublicKey: Buffer.from(request.newWriterPublicKey)
					},
					origin: current.origin,
					logHead: current.logHead
				};
				const receipt = this.signReceipt(newState);
				this.store.insertEpoch({
					recoveryId: Buffer.from(expected.recoveryId),
					epoch: u64be(request.newEpoch),
					writerPublicKey: Buffer.from(request.newWriterPublicKey),
					certSupersededState: stateBytes(current),
					certIssuedAt: u64be(cert.issuedAt),
					certSignature: cert.signature,
					receiptState: stateBytes(newState),
					receiptIssuedAt: u64be(receipt.issuedAt),
					receiptSignature: receipt.signature
				});
				this.store.updateNamespaceState(
					expected.recoveryId,
					stateBytes(newState),
					u64be(receipt.issuedAt),
					receipt.signature
				);
				return {
					status: GuardianStatus.OK,
					certificate: {
						protocolVersion: GUARDIAN_PROTOCOL_VERSION,
						guardianSetId: Buffer.from(this.guardianSetId),
						guardianId: Buffer.from(this.guardianId),
						supersededState: current,
						newEpoch: request.newEpoch,
						newWriterPublicKey: Buffer.from(request.newWriterPublicKey),
						issuedAt: cert.issuedAt,
						signature: Buffer.from(cert.signature)
					},
					receipt: this.toReceipt(newState, receipt.issuedAt, receipt.signature)
				};
			});
		} catch (error) {
			return this.internalError(error);
		}
	}

	// ─────────────── SYNC_EPOCH (wire 5.7) ───────────────

	syncEpoch(request: IGuardianSyncEpochRequest): IGuardianSyncEpochResponse {
		try {
			const certs = request.certificates;
			if (!Array.isArray(certs) || certs.length === 0) {
				return err(GuardianStatus.ERR_MALFORMED, 'certificate bundle is empty');
			}
			if (certs.length > CRASH_V1_PROFILE.total) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'more certificates than guardians in the set'
				);
			}
			for (const cert of certs) {
				const shape = this.stateShapeProblem(cert.supersededState);
				if (shape) return err(GuardianStatus.ERR_MALFORMED, shape);
				if (!isLen(cert.guardianId, 32)) {
					return err(
						GuardianStatus.ERR_MALFORMED,
						'guardianId must be 32 bytes'
					);
				}
				if (!isLen(cert.newWriterPublicKey, 32)) {
					return err(
						GuardianStatus.ERR_MALFORMED,
						'new writer public key must be 32 bytes'
					);
				}
				if (!isLen(cert.signature, 64)) {
					return err(
						GuardianStatus.ERR_MALFORMED,
						'signature must be 64 bytes'
					);
				}
				if (!validU64(cert.newEpoch) || cert.newEpoch === 0n) {
					return err(
						GuardianStatus.ERR_MALFORMED,
						'newEpoch must be a nonzero u64'
					);
				}
				if (!validU64(cert.issuedAt)) {
					return err(GuardianStatus.ERR_MALFORMED, 'issuedAt must be a u64');
				}
			}
			const reference = certs[0];
			const referenceSuperseded = stateBytes(reference.supersededState);

			// Step 1: identical protocol_version, guardian_set_id, recovery_id,
			// superseded STATE, newEpoch and newWriterPublicKey everywhere.
			for (const cert of certs) {
				if (
					cert.protocolVersion !== reference.protocolVersion ||
					!cert.guardianSetId.equals(reference.guardianSetId) ||
					!stateBytes(cert.supersededState).equals(referenceSuperseded) ||
					cert.newEpoch !== reference.newEpoch ||
					!cert.newWriterPublicKey.equals(reference.newWriterPublicKey)
				) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'certificates disagree about the takeover'
					);
				}
			}
			if (reference.protocolVersion !== GUARDIAN_PROTOCOL_VERSION) {
				return err(
					GuardianStatus.ERR_UNSUPPORTED_VERSION,
					`protocol_version ${reference.protocolVersion} outside supported range 1..1`
				);
			}
			// Step 2: the set is served here.
			if (!reference.guardianSetId.equals(this.guardianSetId)) {
				return err(
					GuardianStatus.ERR_UNKNOWN_SET,
					'guardian_set_id is not served by this guardian'
				);
			}
			// Step 3: every signer is a distinct member of the committed set.
			for (const cert of certs) {
				if (!this.members.some((m) => m.equals(cert.guardianId))) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'certificate signer is not a member of the guardian set'
					);
				}
			}
			for (let i = 0; i < certs.length; i++) {
				for (let j = i + 1; j < certs.length; j++) {
					if (certs[i].guardianId.equals(certs[j].guardianId)) {
						return err(
							GuardianStatus.ERR_CERT_MISMATCH,
							'duplicate certificate signer'
						);
					}
				}
			}
			// Step 4: every signature verifies over the TAKEOVER transcript.
			for (const cert of certs) {
				const transcript = takeoverTranscriptHash(
					this.guardianSetId,
					cert.guardianId,
					cert.supersededState,
					cert.newEpoch,
					cert.newWriterPublicKey,
					cert.issuedAt
				);
				if (!this.safeVerify(transcript, cert.signature, cert.guardianId)) {
					return err(
						GuardianStatus.ERR_BAD_SIGNATURE,
						'certificate signature failed'
					);
				}
			}
			// Step 5: threshold.
			if (certs.length < this.required) {
				return err(
					GuardianStatus.ERR_INSUFFICIENT_CERTS,
					`takeover requires ${this.required} distinct certificates`
				);
			}
			// Step 6: epoch continuity inside the bundle.
			if (reference.newEpoch !== reference.supersededState.lease.epoch + 1n) {
				return err(
					GuardianStatus.ERR_CERT_MISMATCH,
					'newEpoch must equal the certified lease epoch + 1'
				);
			}

			const certified = reference.supersededState;
			const recoveryId = certified.recoveryId;
			const quarantine = this.quarantineGate(recoveryId);
			if (quarantine) return quarantine;

			return this.store.write(() => {
				const ns = this.store.getNamespace(recoveryId);
				if (!ns) {
					return err(
						GuardianStatus.ERR_UNKNOWN_NODE,
						'recovery_id not registered'
					);
				}
				if (!ns.registrationState || !ns.state) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'no internally consistent checkpoint; re-register to re-anchor repair'
					);
				}
				const local = parseStateBytes(ns.state);
				if (
					local.origin.firstSequence !== certified.origin.firstSequence ||
					!local.origin.previousHash.equals(certified.origin.previousHash)
				) {
					this.alarm(
						recoveryId,
						GuardianStatus.ERR_CONFLICT,
						'certified origin conflicts with the root-committed origin'
					);
					return err(
						GuardianStatus.ERR_CONFLICT,
						'certified origin conflicts with the root-committed origin'
					);
				}
				// Step 7: a guardian already at or beyond newEpoch rejects.
				if (local.lease.epoch > certified.lease.epoch) {
					return err(
						GuardianStatus.ERR_EPOCH_REGRESSION,
						'bundle is older than the local lease'
					);
				}
				if (
					local.lease.epoch === certified.lease.epoch &&
					!local.lease.writerPublicKey.equals(certified.lease.writerPublicKey)
				) {
					this.alarm(
						recoveryId,
						GuardianStatus.ERR_CONFLICT,
						'two writer keys certified for one epoch'
					);
					return err(
						GuardianStatus.ERR_CONFLICT,
						'certified lease conflicts with the local lease at the same epoch'
					);
				}
				// Step 8: the local log must contain the certified head.
				const head = certified.logHead;
				if (!logHeadsEqual(local.logHead, head)) {
					if (local.logHead.sequence < head.sequence) {
						return err(
							GuardianStatus.ERR_HEAD_UNKNOWN,
							'local log is behind the certified head; repair with SYNC_RECORD first'
						);
					}
					if (!isGenesisLogHead(head)) {
						const stored = this.store.getRecord(
							recoveryId,
							u64be(head.sequence)
						);
						if (!stored) {
							throw new Error(
								'stored log is missing the certified sequence inside its own range'
							);
						}
						if (
							!stored.frameHash.equals(head.frameHash) ||
							!stored.ciphertextHash.equals(head.ciphertextHash) ||
							readU64be(stored.epoch) !== head.recordEpoch
						) {
							this.alarm(
								recoveryId,
								GuardianStatus.ERR_CONFLICT,
								`certified head conflicts with the stored record at sequence ${head.sequence}`
							);
							return err(
								GuardianStatus.ERR_CONFLICT,
								'certified head conflicts with a stored record'
							);
						}
					}
				}

				// Adopt: discard the minority tail above the certified head into
				// the orphan archive, fix the superseded final state, advance the
				// lease, and issue this guardian's own certificate now.
				this.store.archiveRecordsAbove(
					recoveryId,
					u64be(head.sequence),
					'sync-epoch-truncation',
					u64be(this.clock())
				);
				const ownCert = this.signCertificate(
					certified,
					reference.newEpoch,
					reference.newWriterPublicKey
				);
				const newState: GuardianState = {
					recoveryId: Buffer.from(recoveryId),
					lease: {
						epoch: reference.newEpoch,
						writerPublicKey: Buffer.from(reference.newWriterPublicKey)
					},
					origin: local.origin,
					logHead: head
				};
				const receipt = this.signReceipt(newState);
				this.store.insertEpoch({
					recoveryId: Buffer.from(recoveryId),
					epoch: u64be(reference.newEpoch),
					writerPublicKey: Buffer.from(reference.newWriterPublicKey),
					certSupersededState: stateBytes(certified),
					certIssuedAt: u64be(ownCert.issuedAt),
					certSignature: ownCert.signature,
					receiptState: stateBytes(newState),
					receiptIssuedAt: u64be(receipt.issuedAt),
					receiptSignature: receipt.signature
				});
				this.store.updateNamespaceState(
					recoveryId,
					stateBytes(newState),
					u64be(receipt.issuedAt),
					receipt.signature
				);
				return {
					status: GuardianStatus.OK,
					certificate: {
						protocolVersion: GUARDIAN_PROTOCOL_VERSION,
						guardianSetId: Buffer.from(this.guardianSetId),
						guardianId: Buffer.from(this.guardianId),
						supersededState: certified,
						newEpoch: reference.newEpoch,
						newWriterPublicKey: Buffer.from(reference.newWriterPublicKey),
						issuedAt: ownCert.issuedAt,
						signature: Buffer.from(ownCert.signature)
					},
					receipt: this.toReceipt(newState, receipt.issuedAt, receipt.signature)
				};
			});
		} catch (error) {
			return this.internalError(error);
		}
	}

	// ─────────────── repair evidence (wire 5.10 step 5) ───────────────

	submitRepairEvidence(
		request: IGuardianRepairEvidenceRequest
	): IGuardianRepairEvidenceResponse {
		try {
			if (!isLen(request.recoveryId, 32)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'recovery_id must be 32 bytes'
				);
			}
			const target = request.target;
			const shape = this.stateShapeProblem(target);
			if (shape) return err(GuardianStatus.ERR_MALFORMED, shape);
			if (!target.recoveryId.equals(request.recoveryId)) {
				return err(
					GuardianStatus.ERR_MALFORMED,
					'target state belongs to a different recovery_id'
				);
			}
			const signers = new Set<string>();
			for (const receipt of request.receipts) {
				if (
					receipt.protocolVersion !== GUARDIAN_PROTOCOL_VERSION ||
					!isLen(receipt.guardianSetId, 32) ||
					!receipt.guardianSetId.equals(this.guardianSetId)
				) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'receipt is not for this guardian set'
					);
				}
				if (
					!isLen(receipt.guardianId, 32) ||
					!this.members.some((m) => m.equals(receipt.guardianId))
				) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'receipt signer is not a member of the guardian set'
					);
				}
				const receiptShape = this.stateShapeProblem(receipt.state);
				if (receiptShape)
					return err(GuardianStatus.ERR_MALFORMED, receiptShape);
				if (!validU64(receipt.issuedAt) || !isLen(receipt.signature, 64)) {
					return err(GuardianStatus.ERR_MALFORMED, 'receipt fields malformed');
				}
				if (!statesEqual(receipt.state, target)) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'receipt does not cover the target state'
					);
				}
				const transcript = receiptTranscriptHash(
					this.guardianSetId,
					receipt.guardianId,
					receipt.state,
					receipt.issuedAt
				);
				if (
					!this.safeVerify(transcript, receipt.signature, receipt.guardianId)
				) {
					return err(
						GuardianStatus.ERR_BAD_SIGNATURE,
						'receipt signature failed'
					);
				}
				signers.add(receipt.guardianId.toString('hex'));
			}
			for (const cert of request.certificates) {
				if (
					cert.protocolVersion !== GUARDIAN_PROTOCOL_VERSION ||
					!isLen(cert.guardianSetId, 32) ||
					!cert.guardianSetId.equals(this.guardianSetId)
				) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'certificate is not for this guardian set'
					);
				}
				if (
					!isLen(cert.guardianId, 32) ||
					!this.members.some((m) => m.equals(cert.guardianId))
				) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'certificate signer is not a member of the guardian set'
					);
				}
				const certShape = this.stateShapeProblem(cert.supersededState);
				if (certShape) return err(GuardianStatus.ERR_MALFORMED, certShape);
				if (
					!validU64(cert.newEpoch) ||
					!validU64(cert.issuedAt) ||
					!isLen(cert.newWriterPublicKey, 32) ||
					!isLen(cert.signature, 64)
				) {
					return err(
						GuardianStatus.ERR_MALFORMED,
						'certificate fields malformed'
					);
				}
				if (!statesEqual(this.postTakeoverState(cert), target)) {
					return err(
						GuardianStatus.ERR_CERT_MISMATCH,
						'certificate does not fix the target state'
					);
				}
				const transcript = takeoverTranscriptHash(
					this.guardianSetId,
					cert.guardianId,
					cert.supersededState,
					cert.newEpoch,
					cert.newWriterPublicKey,
					cert.issuedAt
				);
				if (!this.safeVerify(transcript, cert.signature, cert.guardianId)) {
					return err(
						GuardianStatus.ERR_BAD_SIGNATURE,
						'certificate signature failed'
					);
				}
				signers.add(cert.guardianId.toString('hex'));
			}
			if (signers.size < this.required) {
				return err(
					GuardianStatus.ERR_INSUFFICIENT_CERTS,
					`quorum evidence requires ${this.required} distinct guardians; got ${signers.size}`
				);
			}
			const quarantine = this.quarantineGate(request.recoveryId);
			if (quarantine) return quarantine;

			return this.store.write(() => {
				const ns = this.store.getNamespace(request.recoveryId);
				if (!ns) {
					return err(
						GuardianStatus.ERR_UNKNOWN_NODE,
						'recovery_id not registered'
					);
				}
				if (!ns.registrationState || !ns.state) {
					return err(
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'no internally consistent checkpoint; re-register to re-anchor repair'
					);
				}
				if (!ns.possiblyStale) {
					return { status: GuardianStatus.OK, detail: 'store was not stale' };
				}
				const current = parseStateBytes(ns.state);
				if (!statesEqual(current, target)) {
					return {
						...err(
							GuardianStatus.ERR_CAS_FAILED,
							'replayed state does not match the quorum target; continue SYNC repair'
						),
						current
					};
				}
				this.store.setPossiblyStale(request.recoveryId, false);
				return { status: GuardianStatus.OK };
			});
		} catch (error) {
			return this.internalError(error);
		}
	}

	// ─────────────── open-time verification (wire 5.10 steps 1-3) ───────────────

	/**
	 * Prove every namespace internally consistent before serving anything:
	 * chain continuity from the root-committed origin, epoch continuity
	 * through this guardian's own stored certificates, and every signature.
	 * A namespace that fails rolls back to its last verifying checkpoint and
	 * refuses ordinary writes until quorum evidence lifts it (5.10); one that
	 * cannot even anchor at a stored registration becomes a tombstone.
	 */
	private verifyStoreAtOpen(): void {
		for (const ns of this.store.listNamespaces()) {
			// The identity cell itself is untrusted: a non-STRICT table can
			// hold an INTEGER or TEXT where the 32-byte BLOB belongs, and any
			// Buffer operation on such a value throws OUTSIDE the containment
			// below. Validate it before touching it; a row whose identity is
			// unreadable is reported at store level and left untouched (it is
			// unreachable by every verb, since no 32-byte key can match it).
			if (!isLen(ns.recoveryId, 32)) {
				this.storeAlarm(
					'namespace row has a malformed recovery_id storage class or width; left untouched'
				);
				continue;
			}
			const recoveryId = ns.recoveryId;
			const key = recoveryId.toString('hex');
			try {
				if (
					!isLen(ns.guardianSetId, 32) ||
					!ns.guardianSetId.equals(this.guardianSetId)
				) {
					// Misconfiguration or column rot; nothing under this
					// namespace is provably ours either way, so quarantine it
					// UNTOUCHED: a healthy store opened under the wrong
					// configuration must not be rolled back, archived, or
					// tombstoned by mistake.
					this.quarantined.add(key);
					this.alarm(
						recoveryId,
						GuardianStatus.ERR_STORE_UNCERTAIN,
						'namespace is not registered under this guardian set; quarantined untouched'
					);
					continue;
				}
				this.store.write(() => this.verifyNamespaceAtOpen(ns));
			} catch (error) {
				// The walk and rollback are non-throwing over persisted bytes;
				// anything that still escapes (I/O failure, disk full) contains
				// to THIS namespace instead of stopping the guardian.
				const message = error instanceof Error ? error.message : String(error);
				this.quarantined.add(key);
				this.alarm(
					recoveryId,
					GuardianStatus.ERR_STORE_UNCERTAIN,
					`namespace verification could not complete (${message}); quarantined`
				);
			}
		}
	}

	private verifyNamespaceAtOpen(ns: IGuardianNamespaceRow): void {
		const recoveryId = ns.recoveryId;
		const regState = tryParseState(ns.registrationState);
		const registrationValid =
			regState !== null &&
			ns.registrationSignature !== null &&
			isLen(ns.registrationSignature, 64) &&
			regState.recoveryId.equals(recoveryId) &&
			regState.lease.epoch >= 1n &&
			regState.origin.firstSequence >= 1n &&
			isGenesisLogHead(regState.logHead) &&
			this.safeVerify(
				registerTranscriptHash(this.guardianSetId, regState),
				ns.registrationSignature,
				regState.recoveryId
			);
		if (!registrationValid || regState === null) {
			// Wire 5.10 step 1: without the stored registration there is no
			// checkpoint at all.
			const hadAnything = ns.state !== null || ns.registrationState !== null;
			this.store.deleteAllRecords(recoveryId, 'rollback', u64be(this.clock()));
			this.store.deleteAllEpochs(recoveryId);
			this.store.tombstoneNamespace(recoveryId);
			if (hadAnything) {
				this.alarm(
					recoveryId,
					GuardianStatus.ERR_STORE_UNCERTAIN,
					'registration missing or invalid; namespace tombstoned with no checkpoint'
				);
			}
			return;
		}

		// The registration receipt is an issued artifact the duplicate path
		// returns verbatim; prove it, or replace it and go uncertain. An
		// unverifiable stored receipt would otherwise survive startup and be
		// handed to the next byte-identical REGISTER_NODE.
		const regReceiptIssuedAt = tryReadU64(ns.registrationReceiptIssuedAt);
		const regReceiptValid =
			regReceiptIssuedAt !== null &&
			ns.registrationReceiptSignature !== null &&
			isLen(ns.registrationReceiptSignature, 64) &&
			this.safeVerify(
				receiptTranscriptHash(
					this.guardianSetId,
					this.guardianId,
					regState,
					regReceiptIssuedAt
				),
				ns.registrationReceiptSignature,
				this.guardianId
			);
		if (!regReceiptValid) {
			// The EXACT original artifact can no longer be proven. Issue an
			// honest replacement over the same initial state and treat the
			// store as uncertain until quorum evidence says otherwise:
			// duplicates must return a VERIFYING receipt, and both a rotten
			// signature and a permanent internal error are worse than a
			// replacement plus an alarm and the stale gate.
			const replacement = this.signReceipt(regState);
			this.store.updateRegistrationReceipt(
				recoveryId,
				u64be(replacement.issuedAt),
				replacement.signature
			);
			this.store.setPossiblyStale(recoveryId, true);
			this.alarm(
				recoveryId,
				GuardianStatus.ERR_STORE_UNCERTAIN,
				'stored registration receipt could not be verified; replacement issued, namespace uncertain'
			);
		}

		const declared = tryParseState(ns.state);
		const declaredValid =
			declared !== null &&
			declared.recoveryId.equals(recoveryId) &&
			declared.origin.firstSequence === regState.origin.firstSequence &&
			declared.origin.previousHash.equals(regState.origin.previousHash) &&
			declared.lease.epoch >= regState.lease.epoch;
		const walkTarget = declaredValid ? declared : null;

		const failure = this.walkNamespace(ns, regState, walkTarget);
		if (!failure) return;
		this.rollbackToCheckpoint(ns, regState, failure.checkpoint, failure.reason);
	}

	/**
	 * Replay the stored history against the state machine's own rules.
	 * Returns null when everything through the declared state verifies, or
	 * the last good checkpoint when something does not.
	 */
	private walkNamespace(
		ns: IGuardianNamespaceRow,
		regState: GuardianState,
		walkTarget: GuardianState | null
	): { checkpoint: GuardianState; reason: string } | null {
		const recoveryId = ns.recoveryId;
		let sim = this.cloneState(regState);
		// Rows whose column WIDTHS are wrong cannot even be decoded, and their
		// blob sort position is meaningless; they are filtered out here so the
		// walk judges what remains, and their mere existence fails the
		// namespace at the end (the rollback's shape sweep removes them, so
		// the failure does not recur on the next open).
		let malformedRows = false;
		const fail = (
			reason: string
		): { checkpoint: GuardianState; reason: string } => ({
			checkpoint: sim,
			reason
		});

		const epochRows: IGuardianEpochRow[] = [];
		for (const row of this.store.listEpochs(recoveryId)) {
			if (epochRowProblem(row)) malformedRows = true;
			else epochRows.push(row);
		}
		if (
			epochRows.length === 0 ||
			tryReadU64(epochRows[0].epoch) !== regState.lease.epoch ||
			!epochRows[0].writerPublicKey.equals(regState.lease.writerPublicKey) ||
			epochRows[0].certSignature !== null
		) {
			return fail('registration epoch row missing or corrupt');
		}
		const pending = epochRows.slice(1);

		const applyTakeover = (
			row: IGuardianEpochRow
		): { checkpoint: GuardianState; reason: string } | null => {
			const rowEpoch = readU64be(row.epoch);
			if (walkTarget && rowEpoch > walkTarget.lease.epoch) {
				return fail('epoch row beyond the declared lease');
			}
			const superseded = tryParseState(row.certSupersededState);
			if (
				superseded === null ||
				row.certIssuedAt === null ||
				row.certSignature === null ||
				row.receiptState === null ||
				row.receiptIssuedAt === null ||
				row.receiptSignature === null
			) {
				return fail('takeover epoch row is missing its artifacts');
			}
			if (
				!superseded.recoveryId.equals(recoveryId) ||
				superseded.origin.firstSequence !== sim.origin.firstSequence ||
				!superseded.origin.previousHash.equals(sim.origin.previousHash) ||
				!logHeadsEqual(superseded.logHead, sim.logHead) ||
				superseded.lease.epoch < sim.lease.epoch ||
				rowEpoch !== superseded.lease.epoch + 1n ||
				(superseded.lease.epoch === sim.lease.epoch &&
					!superseded.lease.writerPublicKey.equals(sim.lease.writerPublicKey))
			) {
				return fail('takeover certificate does not extend the replayed state');
			}
			const certHash = takeoverTranscriptHash(
				this.guardianSetId,
				this.guardianId,
				superseded,
				rowEpoch,
				row.writerPublicKey,
				readU64be(row.certIssuedAt)
			);
			if (!this.safeVerify(certHash, row.certSignature, this.guardianId)) {
				return fail('stored takeover certificate signature failed');
			}
			const post: GuardianState = {
				recoveryId: Buffer.from(recoveryId),
				lease: {
					epoch: rowEpoch,
					writerPublicKey: Buffer.from(row.writerPublicKey)
				},
				origin: sim.origin,
				logHead: sim.logHead
			};
			const receiptState = tryParseState(row.receiptState);
			if (receiptState === null || !statesEqual(receiptState, post)) {
				return fail('stored takeover receipt covers the wrong state');
			}
			const receiptHash = receiptTranscriptHash(
				this.guardianSetId,
				this.guardianId,
				post,
				readU64be(row.receiptIssuedAt)
			);
			if (
				!this.safeVerify(receiptHash, row.receiptSignature, this.guardianId)
			) {
				return fail('stored takeover receipt signature failed');
			}
			sim = post;
			return null;
		};

		for (const record of this.store.iterateRecords(recoveryId)) {
			if (recordRowProblem(record)) {
				malformedRows = true;
				continue;
			}
			const sequence = readU64be(record.sequence);
			const recordEpoch = readU64be(record.epoch);
			if (walkTarget && sequence > walkTarget.logHead.sequence) {
				return fail('stored records extend beyond the declared head');
			}
			while (recordEpoch > sim.lease.epoch) {
				const next = pending.shift();
				if (!next) return fail('record epoch has no takeover certificate');
				const problem = applyTakeover(next);
				if (problem) return problem;
			}
			if (recordEpoch !== sim.lease.epoch) {
				return fail('record epoch below the lease current at its position');
			}
			const genesis = isGenesisLogHead(sim.logHead);
			const expectedSequence = genesis
				? sim.origin.firstSequence
				: sim.logHead.sequence + 1n;
			const expectedPrevious = genesis
				? sim.origin.previousHash
				: sim.logHead.frameHash;
			if (sequence !== expectedSequence) return fail('sequence gap in the log');
			if (!record.previousHash.equals(expectedPrevious)) {
				return fail('previous hash chain break');
			}
			if (!sha256(record.ciphertext).equals(record.ciphertextHash)) {
				return fail('record ciphertext does not match its stored hash');
			}
			const transcript = recordTranscriptHash(this.guardianSetId, {
				recoveryId,
				epoch: recordEpoch,
				sequence,
				previousHash: record.previousHash,
				frameHash: record.frameHash,
				ciphertextHash: record.ciphertextHash
			});
			if (
				!this.safeVerify(
					transcript,
					record.writerSignature,
					sim.lease.writerPublicKey
				)
			) {
				return fail('record writer signature failed');
			}
			sim = {
				recoveryId: sim.recoveryId,
				lease: sim.lease,
				origin: sim.origin,
				logHead: {
					sequence,
					frameHash: Buffer.from(record.frameHash),
					ciphertextHash: Buffer.from(record.ciphertextHash),
					recordEpoch
				}
			};
		}
		for (const next of pending) {
			const problem = applyTakeover(next);
			if (problem) return problem;
		}

		if (!walkTarget) {
			return fail('declared state missing or unparseable');
		}
		if (!statesEqual(sim, walkTarget)) {
			return fail('replayed history stops short of the declared state');
		}
		const receiptIssuedAt = tryReadU64(ns.receiptIssuedAt);
		if (
			receiptIssuedAt === null ||
			ns.receiptSignature === null ||
			!isLen(ns.receiptSignature, 64) ||
			!this.safeVerify(
				receiptTranscriptHash(
					this.guardianSetId,
					this.guardianId,
					walkTarget,
					receiptIssuedAt
				),
				ns.receiptSignature,
				this.guardianId
			)
		) {
			return fail('stored cumulative receipt does not verify');
		}
		if (malformedRows) {
			return fail('structurally malformed rows present alongside the chain');
		}
		return null;
	}

	private rollbackToCheckpoint(
		ns: IGuardianNamespaceRow,
		regState: GuardianState,
		checkpoint: GuardianState,
		reason: string
	): void {
		const recoveryId = ns.recoveryId;
		this.store.archiveRecordsAbove(
			recoveryId,
			u64be(checkpoint.logHead.sequence),
			'rollback',
			u64be(this.clock())
		);
		// Shape sweeps: rows with malformed column widths sort arbitrarily and
		// can dodge the range operations above; removing them here is what
		// keeps this rollback IDEMPOTENT instead of re-failing on every open.
		this.store.archiveMalformedRecords(
			recoveryId,
			'rollback',
			u64be(this.clock())
		);
		this.store.deleteEpochsAbove(recoveryId, u64be(checkpoint.lease.epoch));
		this.store.deleteMalformedEpochs(recoveryId);
		// The registration epoch row is derived from the root-signed
		// registration itself; if it was the damaged part, rebuild it.
		const regRow = this.store.getEpoch(recoveryId, u64be(regState.lease.epoch));
		if (
			checkpoint.lease.epoch === regState.lease.epoch &&
			(!regRow ||
				!regRow.writerPublicKey.equals(regState.lease.writerPublicKey) ||
				regRow.certSignature !== null)
		) {
			this.store.deleteAllEpochs(recoveryId);
			this.store.insertEpoch({
				recoveryId: Buffer.from(recoveryId),
				epoch: u64be(regState.lease.epoch),
				writerPublicKey: Buffer.from(regState.lease.writerPublicKey),
				certSupersededState: null,
				certIssuedAt: null,
				certSignature: null,
				receiptState: null,
				receiptIssuedAt: null,
				receiptSignature: null
			});
		}
		const receipt = this.signReceipt(checkpoint);
		this.store.updateNamespaceState(
			recoveryId,
			stateBytes(checkpoint),
			u64be(receipt.issuedAt),
			receipt.signature
		);
		this.store.setPossiblyStale(recoveryId, true);
		this.alarm(
			recoveryId,
			GuardianStatus.ERR_STORE_UNCERTAIN,
			`store rolled back to sequence ${checkpoint.logHead.sequence}, epoch ${checkpoint.lease.epoch}: ${reason}`
		);
	}

	private internalError(error: unknown): IErr {
		const message = error instanceof Error ? error.message : String(error);
		return err(GuardianStatus.ERR_INTERNAL, message);
	}
}
