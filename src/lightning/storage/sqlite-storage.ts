import { encodeSpliceLockedMessage } from '../message/splice';
import { Transaction } from 'bitcoinjs-lib';
import { isDeepStrictEqual } from 'util';
import { assetSpliceFundingExits } from './asset-splice-funding-exits';
import {
	publishableAssetSpliceEvidence,
	type AssetSpliceExitEvent
} from './asset-splice-exit-proofs';
import type { IAssetSpliceLockEvent } from '../channel/asset-splice-lock';
import {
	assetSpliceAttemptId,
	assetWalletInputState,
	checkedWalletInputs,
	currentAssetWalletParent,
	type AssetWalletInputEvent
} from './asset-splice-wallet-inputs';
import { FinalSpliceSession } from '../channel/final-splice-session';
import {
	finalSpliceAttempts,
	releasedFinalSpliceFunding,
	selectFinalFunding,
	type FinalSpliceEvent,
	type IFinalSpliceAttempt
} from '../channel/final-splice-state';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import {
	FinalDeviceJournal,
	type IFinalJournalHead,
	checkFinalLifecycleBackup
} from './final-device-journal';
import {
	driveFinalSimpleClose,
	matchFinalSimpleCloseSpend,
	type IFinalSimpleCloseState,
	type IFinalCloseRequest
} from './final-simple-close';
/**
 * SQLite storage backend for Lightning node persistence.
 *
 * Uses better-sqlite3 for synchronous, transactional access.
 * All tables use WAL mode for concurrent reader support.
 */

import {
	normalizeIrohEndpointId,
	validateIrohRelayUrl
} from '../transport/iroh';
import { parseWebSocketUrl } from '../transport/websocket';
import type { IPeerTransportOptions } from '../transport/duplex-transport';
import type { IFforVoucherArchive } from '../ffor/voucher-archive';
import type { ICompositeSpliceRecord } from '../channel/composite-splice-record';
import { validateCompositeSpliceRecord } from '../channel/composite-splice-record';
import {
	fforVoucherArchiveId,
	mergeFforVoucherArchive,
	validateFforVoucherArchive
} from '../ffor/voucher-archive';
import type Database from 'better-sqlite3';
import type { BIP32Interface } from 'bip32';
import type { IFinalOpeningTerms } from '../channel/final-opening-commitment';
import {
	canonicalAssetOpeningEvidence,
	storedOpeningCommitment,
	type IAssetOpeningEvidence
} from './asset-opening-evidence';
import {
	prepareAssetWitnessRelease,
	recordOpeningFunding,
	type FinalFundingWitnessSigner
} from './final-opening-funding';
import {
	canonicalTerms,
	signOpening,
	verifyOpeningSigning
} from './final-opening-signing';
import type { IChannelReestablishMessage } from '../message/channel-reestablish';
import {
	decodeTxSignaturesMessage,
	encodeTxSignaturesMessage
} from '../message/interactive-tx';
import {
	withFunding,
	finalFundingLedgers,
	fundingAdmission,
	spliceBlocksFinalUpdates,
	signFundingBatch,
	receiveFundingBatch,
	receiveFundingRevoke,
	fundingReestablish,
	receiveFundingReestablish,
	type IFundingLedger
} from './final-funding-updates';
import { MessageType } from '../message/types';
import {
	FinalUpdateProtocolError,
	FinalUpdateDataLossError,
	finalOfferedHtlc,
	stageFinalLedgerUpdate,
	initialFinalLedger,
	finalResolutionStates,
	finalLedgerDeliveries,
	validateUpdateLimits,
	finalLedgerSnapshot,
	type IFinalUpdateLimits,
	type IFinalLedgerState,
	type IFinalUpdateContext
} from './final-channel-updates';
import {
	recoveryOpening,
	finalJournalHistory,
	currentFinalJournal,
	appendFinalJournal,
	preserveFinalJournal,
	verifyFinalJournal
} from './final-update-journal';
import { decodeChannelReadyMessage } from '../message/channel-funding';
import {
	requireSameReadyPromise,
	makeReadyPayload,
	preservesReconnectNonce,
	readyKeys,
	readyVerificationNonce,
	requireReadySession,
	verifyReady,
	verifyReadyNonce,
	verifyStoredReadiness
} from './final-opening-ready';
import { Feature, FeatureFlags } from '../features/flags';
import {
	validateAssetOpening,
	validateFinalOpening
} from './final-opening-candidate';
import type { IFinalOpeningCandidate } from './final-opening-candidate';
import {
	decodeOpeningNonces,
	localOpeningTxComplete,
	recordPeerTxComplete,
	type IFinalOpeningNonces,
	type IFinalOpeningSession
} from './final-opening-nonces';
import {
	FinalOpeningAuthority,
	installOpeningAuthority
} from './final-opening-authority';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { loadBetterSqlite3 } from './sqlite-binding';
import { takeFinalDaemonGeneration } from './final-wallet-generation';
import { finalWalletStorage } from './wallet-format-guard';
import {
	assertExistingWalletFile,
	backUpWalletFile,
	checkWalletFormat,
	finalWalletIdentity,
	installFreshWallet,
	installWalletMarker,
	type IFinalWalletBinding
} from './final-wallet-format';

import { hmacSha256, sha256 } from '../crypto/provider';
import { nodeFs } from '../../utils/node-builtins';
import type {
	IStorageBackend,
	IGossipRowPage,
	IInvoiceInfo,
	IPersistedChannelPolicy,
	IForwardingEvent,
	IForwardingEventFilter,
	IForwardingSummary,
	IRecoveryOutboxMessage,
	IRecoveryOutboxStoredMessage,
	IStoredRecoveryFrame,
	IStoredRecoveryFrameHeader,
	RecoveryOutboxDisposition
} from './types';
import { CorruptRecoveryRowError } from './types';
import type {
	IWatchtowerSession,
	IWatchtowerUpdate
} from '../watchtower/types';
import type { IAuxiliaryCommitmentData } from '../channel/auxiliary';
import { auxiliaryRevokedViewsToStore } from '../channel/auxiliary-revoked';
import type { IChannelState } from '../channel/channel-state';
import type { IHtlcSnapshotEntry } from '../channel/types';
import {
	deserializeAuxiliaryCommitmentView,
	serializeAuxiliaryCommitmentView
} from './auxiliary-serialization';
import {
	attachStoredRevokedHtlcSnapshots,
	unsavedRevokedHtlcSnapshots
} from '../channel/htlc-snapshots';
import type { IPaymentInfo } from '../node/payment-types';
import type { IChainMonitorState } from '../chain/chain-monitor';
import type { IGraphChannel, IGraphNode } from '../gossip/types';
import type { ISerializedChannelState } from './serialization';
import { UnsupportedCommitmentProfileError } from '../channel/commitment-profile';
import {
	serializeChannelState,
	deserializeChannelState,
	channelRowFromStore,
	channelRowToStore,
	serializeHtlcSnapshotEntries,
	deserializeHtlcSnapshotEntries,
	serializePaymentInfo,
	deserializePaymentInfo,
	serializeChainMonitorState,
	deserializeChainMonitorState,
	serializeGraphChannel,
	deserializeGraphChannel,
	serializeGraphNode,
	deserializeGraphNode,
	serializeInvoiceInfo,
	deserializeInvoiceInfo,
	serializedChannelCarriesAssetState
} from './serialization';
import {
	ENC_PREFIX,
	encryptValue,
	decryptValue,
	hkdfKey,
	isEncryptedValue,
	StorageEncryptedError
} from './encryption';

const boundWallet = Symbol('final wallet binding');

/** Owner read/write only: the mode for a file holding this wallet's data. */
const OWNER_ONLY_FILE_MODE = 0o600;

/** Payment keys read per query by paymentsNewestFirst. */
const PAYMENT_KEY_BATCH = 500;

/** Rows read per query by _rowsInBatches. */
const HISTORY_ROW_BATCH = 500;

/** Derives the key payments.metadata_tags are computed under. */
const METADATA_TAG_INFO = 'beignet-payment-metadata-tag-v1';

/** Hex characters kept of each metadata tag's HMAC. */
const METADATA_TAG_HEX = 32;

const QUEUE_COLUMNS =
	'id, bolt11, priority, status, amount_sats, max_fee_sats, metadata, error, created_at, completed_at';
/** A payment_queue row the queue no longer dispatches. */
const QUEUE_FINISHED = "status NOT IN ('queued', 'dispatching')";
/** When a row finished; idx_payment_queue_finished indexes this expression. */
const QUEUE_FINISHED_AT = 'COALESCE(completed_at, created_at)';

/** A payment_queue row, as the CLI payment queue stores it. */
export interface IQueueEntryRow {
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
}

/** A payment row's key from paymentsNewestFirst; load() decodes the row. */
export interface IStoredPaymentRef {
	paymentHash: string;
	createdAt: number;
	/** Null when the row is gone or cannot be decoded. */
	load(): IPaymentInfo | null;
}

interface IRevokedHtlcSnapshotRow {
	channel_id: string;
	commitment_number: string;
	htlcs_json: string;
}

interface IFinalDaemonOpening {
	candidate: IFinalOpeningCandidate;
	session: IFinalOpeningSession;
	funding?: Buffer;
	exitToBroadcast?: Buffer;
	readyExchanged?: true;
}

interface IFinalOpeningRecord {
	candidate: IFinalOpeningCandidate;
	nonces: IFinalOpeningNonces;
	nonceKey: Buffer;
}

interface IFinalOpeningRow {
	channel_id: string;
	funding_outpoint: string;
	record_json: string;
	nonces_json: string;
}

/** What paymentsNewestFirst tests a row on besides its age. */
export interface IPaymentRowMatch {
	status?: string;
	direction?: string;
	/** A metadata key the payment holds, holding this value when one is set. */
	metadata?: { key: string; value?: string };
}

/**
 * chmod `filePath` to 0600 when it exists and any group/other bit is set.
 * Never throws: a missing sidecar and a filesystem that refuses chmod both
 * leave the file as it is.
 */
function restrictFileMode(filePath: string): void {
	const fs = nodeFs();
	try {
		const current = fs.statSync(filePath).mode & 0o777;
		if ((current & ~OWNER_ONLY_FILE_MODE) !== 0) {
			fs.chmodSync(filePath, OWNER_ONLY_FILE_MODE);
		}
	} catch {
		// Missing sidecar, or a filesystem without permission bits.
	}
}

function columnNames(db: Database.Database, table: string): Set<string> {
	const rows = db.pragma(`table_info(${table})`) as Array<{ name: string }>;
	return new Set(rows.map((row) => row.name));
}

/** Issue #2098, step 7: the fields that mark a forward with an asset leg. */
type ForwardingAuxiliaryFields = Pick<
	IForwardingEvent,
	| 'auxiliary'
	| 'inAuxiliaryAmount'
	| 'inWireAmountMsat'
	| 'outAuxiliaryAmount'
	| 'outWireAmountMsat'
	| 'nextHopScid'
>;

/**
 * Issue #2098, step 7: what marks a forward with an asset leg, as the
 * forwarding_events.auxiliary_json column holds it: bigints as decimal
 * strings. Undefined, and the column NULL, for an ordinary forward.
 */
function forwardingAuxiliaryToJson(
	event: Omit<IForwardingEvent, 'id'>
): string | undefined {
	if (event.auxiliary !== true) return undefined;
	return JSON.stringify({
		inAuxiliaryAmount: event.inAuxiliaryAmount?.toString(),
		inWireAmountMsat: event.inWireAmountMsat?.toString(),
		outAuxiliaryAmount: event.outAuxiliaryAmount?.toString(),
		outWireAmountMsat: event.outWireAmountMsat?.toString(),
		nextHopScid: event.nextHopScid
	});
}

/** The fields forwardingAuxiliaryToJson stored, read back. */
function forwardingAuxiliaryFromJson(
	json: string | null
): ForwardingAuxiliaryFields {
	if (json === null) return {};
	const stored = JSON.parse(json) as Record<string, unknown>;
	const amount = (key: string): bigint | undefined =>
		typeof stored[key] === 'string' ? BigInt(stored[key] as string) : undefined;
	const fields: ForwardingAuxiliaryFields = { auxiliary: true };
	const inUnits = amount('inAuxiliaryAmount');
	if (inUnits !== undefined) fields.inAuxiliaryAmount = inUnits;
	const inWire = amount('inWireAmountMsat');
	if (inWire !== undefined) fields.inWireAmountMsat = inWire;
	const outUnits = amount('outAuxiliaryAmount');
	if (outUnits !== undefined) fields.outAuxiliaryAmount = outUnits;
	const outWire = amount('outWireAmountMsat');
	if (outWire !== undefined) fields.outWireAmountMsat = outWire;
	if (typeof stored.nextHopScid === 'string') {
		fields.nextHopScid = stored.nextHopScid;
	}
	return fields;
}

/**
 * Add a column an older release's table lacks. A fresh database already has
 * it (_createTables), so the ALTER runs only when it is missing, and any
 * error it throws rolls the migration back rather than recording it done.
 */
function addColumnIfMissing(
	db: Database.Database,
	table: string,
	column: string,
	definition: string
): void {
	if (columnNames(db, table).has(column)) return;
	db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

/** A recovery_frames row as read; a header query leaves out the last two. */
interface IRecoveryFrameRow {
	sequence: unknown;
	writer_epoch: unknown;
	frame_hash: unknown;
	previous_hash: unknown;
	ciphertext?: unknown;
	created_at?: unknown;
}

// Decode EXACTLY or throw: SQLite column affinity does not enforce types, so
// a physically corrupt row (TEXT in a BLOB column, a float or string
// sequence) would otherwise be coerced into plausible bytes that chain
// verification then runs over (issue #317). Frame corruption always
// propagates; it is never routed through reportCorruptRow's skip path.
function frameRowLabel(row: IRecoveryFrameRow): string {
	return `recovery frame row ${String(row.sequence)}`;
}

function frameRowInt(
	row: IRecoveryFrameRow,
	value: unknown,
	field: string,
	min: number
): number {
	if (
		typeof value !== 'number' ||
		!Number.isSafeInteger(value) ||
		value < min
	) {
		throw new CorruptRecoveryRowError(
			`${frameRowLabel(row)}: ${field} is not an integer >= ${min}`
		);
	}
	return value;
}

function frameRowHash(
	row: IRecoveryFrameRow,
	value: unknown,
	field: string
): Buffer {
	if (!Buffer.isBuffer(value) || value.length !== 32) {
		throw new CorruptRecoveryRowError(
			`${frameRowLabel(row)}: ${field} is not a 32-byte buffer`
		);
	}
	return Buffer.from(value);
}

function decodeRecoveryFrameHeader(
	row: IRecoveryFrameRow
): IStoredRecoveryFrameHeader {
	return {
		sequence: frameRowInt(row, row.sequence, 'sequence', 1),
		writerEpoch: frameRowInt(row, row.writer_epoch, 'writer_epoch', 1),
		frameHash: frameRowHash(row, row.frame_hash, 'frame_hash'),
		previousFrameHash: frameRowHash(row, row.previous_hash, 'previous_hash')
	};
}

function decodeRecoveryFrameRow(row: IRecoveryFrameRow): IStoredRecoveryFrame {
	if (!Buffer.isBuffer(row.ciphertext) || row.ciphertext.length === 0) {
		throw new CorruptRecoveryRowError(
			`${frameRowLabel(row)}: ciphertext is not a non-empty buffer`
		);
	}
	return {
		...decodeRecoveryFrameHeader(row),
		ciphertext: Buffer.from(row.ciphertext),
		createdAt: frameRowInt(row, row.created_at, 'created_at', 0)
	};
}

function validateSecondPoint(
	point: string | undefined,
	terms: IFinalOpeningTerms
): void {
	if (
		point !== undefined &&
		(typeof point !== 'string' ||
			!/^(02|03)[a-f0-9]{64}$/.test(point) ||
			!isValidPublicKey(Buffer.from(point, 'hex')) ||
			point === terms.remoteBasepoints.firstPerCommitmentPoint)
	)
		throw new Error('Invalid negotiated second per-commitment point');
}

function preservesOpeningFields<T extends object>(older: T, newer: T): boolean {
	return (Object.keys(older) as (keyof T)[]).every(
		(field) => JSON.stringify(older[field]) === JSON.stringify(newer[field])
	);
}

export class SqliteStorage implements IStorageBackend {
	finalSpliceSession(id: string, root: BIP32Interface): FinalSpliceSession {
		if (!this.canUpdateFinalCommitments || this.db.inTransaction)
			throw new Error(
				'Splice requires the original update wallet and a top-level commit'
			);
		return new FinalSpliceSession(
			id,
			this,
			root,
			this.finalJournal(),
			this.requireOpeningAuthority(),
			() => this.readFinalSpliceAttempts(id).slice(-1)[0]
		);
	}
	private finalJournal(): FinalDeviceJournal {
		if (
			(!this.updateWallet && this.finalGeneration !== 4) ||
			!this.walletIdentity ||
			!this.encryptionKey
		)
			throw new Error('Final journal requires an enrolled wallet');
		return new FinalDeviceJournal(
			this.db,
			this.encryptionKey,
			this.walletIdentity,
			this.openingAuthority
		);
	}

	private db: Database.Database;
	private readonly dbPath: string;
	private readonly walletIdentity?: string;
	private readonly updateWallet: boolean;
	private readonly finalGeneration?: number;
	private openingAuthority: FinalOpeningAuthority | null = null;
	/** Public negotiation history excludes the local exit template, which later revocations can supersede. */
	loadFinalSpliceAttempts(id: string) {
		return this.readFinalSpliceAttempts(id).map(({ candidate, ...attempt }) => {
			if (!candidate) return { ...attempt, candidate: undefined };
			const { localExit: _exit, ...status } = candidate;
			return { ...attempt, candidate: status };
		});
	}
	private readFinalSpliceAttempts(id: string): IFinalSpliceAttempt[] {
		if (!this.updateWallet) return [];
		this.requireCurrentFinalDevice();
		const head = this.finalJournal().read<FinalSpliceEvent>('splice', id);
		return finalSpliceAttempts(id, head.records);
	}

	private assetWalletInputHistory(channelId: string) {
		return this.readAssetSpliceJournal<
			AssetWalletInputEvent | AssetSpliceExitEvent | IAssetSpliceLockEvent
		>(channelId);
	}
	reserveAssetSpliceWalletInputs(
		channelId: string,
		attempt: string,
		parent: string,
		selected: readonly string[]
	): void {
		this.assertAssetSpliceAuthority(this.requireOpeningAuthority());
		assetSpliceAttemptId(attempt);
		const inputs = checkedWalletInputs(selected);
		const opening = this.loadFinalDaemonOpening(channelId);
		if (
			!opening?.funding ||
			!opening.session.assetEvidence ||
			opening.exitToBroadcast
		)
			throw new Error('Asset splice requires a live funded opening');
		const base =
			Transaction.fromBuffer(opening.funding).getId() +
			':' +
			opening.candidate.fundingOutputIndex;
		const head = this.assetWalletInputHistory(channelId);
		const phases = head.records.filter(
			(r): r is AssetSpliceExitEvent =>
				r.kind === 'exit-proofs' ||
				r.kind === 'funding-reserved' ||
				r.kind === 'funding-released'
		);
		const exits = publishableAssetSpliceEvidence(phases, channelId);
		if (
			currentAssetWalletParent(head.records, exits, channelId, base) !==
				parent ||
			inputs.includes(parent)
		)
			throw new Error(
				'Asset splice wallet reservation differs from active funding'
			);
		const existing = assetWalletInputState(head.records).attempts.get(attempt);
		if (existing) {
			if (
				existing.aborted ||
				existing.parent !== parent ||
				!isDeepStrictEqual(existing.inputs, inputs)
			)
				throw new Error('Asset splice wallet input reservation changed');
			return;
		}
		const reserved = this.loadFinalSpliceWalletOutpoints();
		if (inputs.some((input) => reserved.has(input)))
			throw new Error('Wallet input is reserved by another asset splice');
		this.appendAssetSpliceEvent(channelId, head, {
			kind: 'wallet-inputs',
			attempt,
			parent,
			inputs
		} satisfies AssetWalletInputEvent);
	}
	releaseAssetSpliceWalletInputs(channelId: string, attempt: string): void {
		this.assertAssetSpliceAuthority(this.requireOpeningAuthority());
		assetSpliceAttemptId(attempt);
		const head = this.assetWalletInputHistory(channelId);
		const { attempts, irreversible, signedParents } = assetWalletInputState(
			head.records
		);
		const prior = attempts.get(attempt);
		if (
			!prior ||
			(!prior.aborted &&
				(signedParents.has(prior.parent) ||
					prior.inputs.some((input) => irreversible.has(input))))
		)
			throw new Error(
				'Cannot release an unknown or signed asset splice wallet input'
			);
		if (!prior.aborted)
			this.appendAssetSpliceEvent(channelId, head, {
				kind: 'wallet-inputs-aborted',
				attempt
			} satisfies AssetWalletInputEvent);
	}

	loadFinalSpliceWalletOutpoints(): Set<string> {
		const reserved = new Set<string>();
		if (this.finalGeneration === 4) {
			for (const c of this.loadFinalOpenings()) {
				if (!this.loadAssetOpeningEvidence(c.channelId)) continue;
				for (const input of assetWalletInputState(
					this.assetWalletInputHistory(c.channelId).records
				).reserved)
					reserved.add(input);
			}
			return reserved;
		}
		if (!this.canUpdateFinalCommitments) return reserved;
		for (const c of this.loadFinalOpenings()) {
			for (const a of this.readFinalSpliceAttempts(c.channelId)) {
				if (a.aborted !== undefined) continue;
				for (const input of a.intent.inputs)
					reserved.add(
						Transaction.fromHex(input.prevTxHex).getId() + ':' + input.vout
					);
			}
		}
		return reserved;
	}

	loadFinalActiveFunding(id: string): IFinalFundingReference | null {
		const opening = this.loadFinalDaemonOpening(id);
		if (!opening?.funding) return null;
		const c = opening.candidate;
		return selectFinalFunding(
			{
				fundingTxHex: c.fundingTxHex,
				fundingOutputIndex: c.fundingOutputIndex,
				localFundingPubkey: c.localFundingPubkey,
				remoteFundingPubkey: c.remoteFundingPubkey,
				localFundingKeyIndex: opening.session.channelKeyIndex
			},
			this.readFinalSpliceAttempts(id)
		);
	}

	get [finalWalletStorage](): boolean {
		return this.walletIdentity !== undefined;
	}
	private get channelStateColumn(): 'state_json' | 'channel_state_v2' {
		return this.walletIdentity ? 'channel_state_v2' : 'state_json';
	}
	private onCorruptRow?: (error: unknown) => void;
	private unreadableAssetChannels: string[] = [];
	private encryptionKey?: Buffer;
	/**
	 * Without a storage key the payment rows are plaintext anyway, so a fixed
	 * key stands in. A row written that way is tagged again under the
	 * storage key when one is first set (_fillPaymentLookupColumns).
	 */
	private readonly metadataTagKey: Buffer;
	private corruptRowsSeen = 0;
	/** Prepared statements by SQL text, filled by _stmt. */
	private readonly statements = new Map<string, Database.Statement>();

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
		opts?: { encryptionKey?: Buffer; [boundWallet]?: string }
	) {
		const Sqlite = loadBetterSqlite3();
		this.walletIdentity = opts?.[boundWallet];
		this.finalGeneration =
			this.walletIdentity && JSON.parse(this.walletIdentity)[0];
		this.updateWallet = this.finalGeneration === 2;
		this.db = this.walletIdentity
			? new Sqlite(dbPath, { fileMustExist: true, timeout: 0 })
			: new Sqlite(dbPath);
		this.dbPath = dbPath;
		this.onCorruptRow = onCorruptRow;
		this.encryptionKey = opts?.encryptionKey;
		this.metadataTagKey = hkdfKey(
			opts?.encryptionKey ?? Buffer.alloc(32),
			METADATA_TAG_INFO
		);
		// Before open() switches on WAL: SQLite creates the -wal and -shm
		// sidecars with the database file's own bits, so tightening the main
		// file first covers them from the start.
		if (!this.walletIdentity) this._restrictFileModes();
	}

	/** Initialize a separate physical format for a newly generated wallet. */
	static createFinalWallet(
		dbPath: string,
		binding: IFinalWalletBinding
	): SqliteStorage {
		const identity = finalWalletIdentity(dbPath, binding);
		const daemonGenerated = takeFinalDaemonGeneration(binding);
		if (
			(binding.finalCommitmentUpdates ||
				binding.dualFundedAssets ||
				binding.assetSplice) &&
			!daemonGenerated
		)
			throw new Error(
				'This enrollment requires a freshly generated original wallet'
			);
		installFreshWallet(dbPath, (stagedPath) => {
			const staged = new SqliteStorage(stagedPath, undefined, binding);
			try {
				staged.open();
				installWalletMarker(staged.db, binding.encryptionKey, identity);
				installOpeningAuthority(
					stagedPath,
					dbPath,
					staged.db,
					binding.encryptionKey,
					identity,
					daemonGenerated
				);
				staged.checkpoint();
			} finally {
				staged.close();
			}
		});
		return SqliteStorage.openFinalWallet(dbPath, binding);
	}

	/** Reopen a wallet with its authenticated node identity, chain and storage key. */
	static openFinalWallet(
		dbPath: string,
		binding: IFinalWalletBinding
	): SqliteStorage {
		const identity = finalWalletIdentity(dbPath, binding);
		assertExistingWalletFile(dbPath);
		const storage = new SqliteStorage(dbPath, undefined, {
			encryptionKey: Buffer.from(binding.encryptionKey),
			[boundWallet]: identity
		});
		try {
			storage.open();
			storage.openingAuthority = FinalOpeningAuthority.open(
				storage.db,
				dbPath,
				binding.encryptionKey,
				identity
			);
			if (storage.finalGeneration === 4) {
				const journal = storage.finalJournal();
				for (const c of storage.loadFinalOpenings())
					journal.reconcile(c.channelId);
			}
			storage.reconcileFinalUpdateOpenings();
			storage.reconcileFinalExitRequests();
			if (storage.canOpenDualFundedAssets) {
				storage.openingAuthority!.assertEnforceableExits((id) =>
					storage.openingExitBytes(id)
				);
				storage.reconcileAssetOpeningWitnesses();
				storage.openingAuthority!.compactRetiredAssetStages();
			}
			return storage;
		} catch (error) {
			storage.close();
			throw error;
		}
	}

	/**
	 * Owner-only permissions on the database file and its WAL/shm sidecars
	 * (issue #1004). Values are encrypted at rest, but the lookup columns
	 * (payment hashes, channel ids, peer pubkeys, gossip, the action log) are
	 * plaintext, and better-sqlite3 creates the file under the process umask,
	 * 0644 on a typical host. Only a file looser than 0600 is touched, so a
	 * deliberately read-only database stays read-only. Best effort: a chmod
	 * refused by a read-only or foreign filesystem must not stop the node,
	 * and this class has no logger to warn through; the CLI's umask and the
	 * data-directory check in BeignetNode carry the operator-facing signal.
	 * POSIX bits mean nothing on Windows, so nothing is done there.
	 */
	private _restrictFileModes(): void {
		if (this.dbPath === ':memory:' || process.platform === 'win32') return;
		for (const suffix of ['', '-wal', '-shm']) {
			restrictFileMode(`${this.dbPath}${suffix}`);
		}
	}

	/**
	 * True when a secret written here cannot be read out of the stored
	 * artifact: either an encryption key is configured, or the database is
	 * purely in memory and has no file to steal. Consulted by the writer
	 * lease (recovery 5.6), which refuses to persist its signing key into a
	 * file-backed database with no key configured.
	 */
	secretsEncryptedAtRest(): boolean {
		return this.encryptionKey !== undefined || this.dbPath === ':memory:';
	}

	private reportCorruptRow(error: unknown): void {
		// A missing encryption key is a configuration problem, not row
		// corruption - propagate instead of silently skipping every row.
		if (error instanceof StorageEncryptedError) {
			throw error;
		}
		this.corruptRowsSeen++;
		if (this.onCorruptRow) {
			this.onCorruptRow(error);
		}
	}

	/** Rows skipped by the forgiving loaders since open (issue #317). */
	corruptRowCount(): number {
		return this.corruptRowsSeen;
	}

	/**
	 * The asset channel rows the last loadAllChannels skipped because they
	 * did not decode, as channel id hex. A skipped asset channel is neither
	 * run nor watched, so startup reads this and refuses instead of going on
	 * without it.
	 */
	unreadableAssetChannelIds(): string[] {
		return [...this.unreadableAssetChannels];
	}

	/**
	 * Decode a hex payload column EXACTLY or throw. Buffer.from(s, 'hex')
	 * silently truncates at the first malformed byte, so a corrupt column
	 * would otherwise be coerced into a short (or empty) buffer instead of
	 * being counted as corrupt (issue #317). Callers sit inside the per-row
	 * try/catch, so at runtime the row is still skipped and counted;
	 * recovery-critical readers refuse via corruptRowCount.
	 */
	private _hexColumn(value: string, label: string): Buffer {
		if (value.length === 0 || !/^([0-9a-f]{2})*$/i.test(value)) {
			throw new CorruptRecoveryRowError(`${label} is not valid hex`);
		}
		return Buffer.from(value, 'hex');
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

	/**
	 * The statement for a fixed SQL string, prepared on first use. better-
	 * sqlite3 does not cache, so prepare() parses and plans the SQL on every
	 * call. SQL built from per-call filters or IN lists, and the passes
	 * open() runs once, go to db.prepare, so the map stays bounded. Nothing
	 * iterate()s a cached statement: an iterator left unfinished keeps it
	 * busy, and every later call on it throws.
	 */
	private _stmt(sql: string): Database.Statement {
		let statement = this.statements.get(sql);
		if (!statement) {
			statement = this.db.prepare(sql);
			this.statements.set(sql, statement);
		}
		return statement;
	}

	/**
	 * Every row of a table that only grows with history, in rowid order (the
	 * order a plain scan returns), read a batch at a time. A loader that
	 * decodes as it goes then never holds every raw row beside its decoded
	 * copy (issue #1861). Each batch is a whole all(), so no statement is
	 * left busy while the caller decodes or reports a corrupt row.
	 */
	private *_rowsInBatches<T>(table: string, columns: string): Generator<T> {
		const first = this._stmt(
			`SELECT rowid, ${columns} FROM ${table} ORDER BY rowid LIMIT ?`
		);
		const next = this._stmt(
			`SELECT rowid, ${columns} FROM ${table} WHERE rowid > ? ` +
				'ORDER BY rowid LIMIT ?'
		);
		let rows = first.all(HISTORY_ROW_BATCH) as Array<T & { rowid: number }>;
		for (;;) {
			for (const row of rows) yield row;
			if (rows.length < HISTORY_ROW_BATCH) return;
			const after = rows[rows.length - 1].rowid;
			rows = next.all(after, HISTORY_ROW_BATCH) as Array<T & { rowid: number }>;
		}
	}

	open(opts?: { synchronous?: 'FULL' | 'NORMAL' }): void {
		// Installing the final format happens only in a private staging file. A
		// bound open checks the complete format before any migration or rewrite.
		if (this.walletIdentity) {
			if (opts?.synchronous === 'NORMAL')
				throw new Error('Final wallet requires full synchronous writes');
			this.db.pragma('locking_mode = EXCLUSIVE');
			this.db
				.transaction(() => {
					checkWalletFormat(this.db, this.encryptionKey, this.walletIdentity);
					if (this.getSchemaVersion() !== SqliteStorage.CURRENT_SCHEMA_VERSION)
						throw new Error('Unsupported final wallet schema version');
					this._checkRequiredColumns();
				})
				.exclusive();
			this.db.pragma('journal_mode = WAL');
			this.db.pragma('synchronous = FULL');
			this.db.pragma('foreign_keys = ON');
			this.loadAllChannels();
			this.readFinalOpenings((candidate, record) => {
				if (this.updateWallet)
					verifyFinalJournal(this.db, candidate.channelId, record.nonceKey);
			});
			this._restrictFileModes();
			return;
		}
		checkWalletFormat(this.db);
		this.db.pragma('journal_mode = WAL');
		this.db.pragma(`synchronous = ${opts?.synchronous ?? 'FULL'}`);
		this.db.pragma('foreign_keys = ON');
		this.db.pragma('busy_timeout = 5000');
		this._createTables();
		this._fillPaymentLookupColumns();
		if (this.encryptionKey) {
			this._encryptExistingData();
			this._scrubMigratedPlaintext();
		}
		// The sidecars exist now; any left by an older release are tightened.
		this._restrictFileModes();
	}

	/**
	 * Checkpoint the WAL file, flushing all pending writes to the main database.
	 */
	checkpoint(): void {
		this.db.pragma('wal_checkpoint(TRUNCATE)');
	}

	close(): void {
		this.openingAuthority?.close();
		this.openingAuthority = null;
		this.db.close();
		this.statements.clear();
	}

	/**
	 * Create a backup of the database to the specified destination path.
	 * Uses SQLite's online backup API for a crash-safe copy.
	 */
	async backup(destPath: string): Promise<void> {
		this.reconcileFinalExitRequests();
		if (this.updateWallet || this.finalGeneration === 4) {
			const journal = this.finalJournal();
			for (const candidate of this.loadFinalOpenings())
				journal.reconcile(candidate.channelId);
		}
		await backUpWalletFile(
			this.db,
			destPath,
			this.encryptionKey,
			this.walletIdentity,
			(old, next) => this.checkOpeningBackupProgress(old, next)
		);
		// A backup is a copy of this database, plaintext lookup columns
		// included, created by SQLite under the process umask (issue #1004).
		if (process.platform !== 'win32') restrictFileMode(destPath);
	}

	/** A backup may add either peer's artifacts in any order, but must preserve every released byte. */
	private checkOpeningBackupProgress(
		old: Database.Database,
		next: Database.Database
	): void {
		if (this.updateWallet || this.finalGeneration === 4)
			checkFinalLifecycleBackup(old, next);
		if (this.updateWallet) preserveFinalJournal(old, next);
		const read = (
			db: Database.Database,
			row: IFinalOpeningRow
		): IFinalOpeningRecord =>
			this.readFinalOpening(row, (id) => {
				const index = db
					.prepare(
						'SELECT channel_index FROM channel_key_indices WHERE channel_id=?'
					)
					.get(id) as { channel_index: number | string } | undefined;
				return index ? this._decodeChannelIndex(index.channel_index) : null;
			});
		const select =
			'SELECT channel_id, funding_outpoint, record_json, nonces_json FROM final_opening_candidates';
		const find = next.prepare(select + ' WHERE channel_id=?');
		for (const row of old
			.prepare(select)
			.iterate() as Iterable<IFinalOpeningRow>) {
			const incoming = find.get(row.channel_id) as IFinalOpeningRow | undefined;
			if (!incoming)
				throw new Error('Cannot remove a final opening from its backup');
			const before = read(old, row);
			const after = read(next, incoming);
			const { signing, localReconnect, peerReconnect, ...promises } =
				before.nonces;
			if (
				JSON.stringify(before.candidate) !== JSON.stringify(after.candidate) ||
				!preservesOpeningFields(promises, after.nonces) ||
				!preservesReconnectNonce(localReconnect, after.nonces.localReconnect) ||
				!preservesReconnectNonce(peerReconnect, after.nonces.peerReconnect) ||
				(signing &&
					(!after.nonces.signing ||
						!preservesOpeningFields(signing, after.nonces.signing)))
			)
				throw new Error('Cannot roll back an opening recovery artifact');
		}
	}

	private finalOpeningKey(channelId: string, outpoint: string): Buffer {
		if (!this.walletIdentity || !this.encryptionKey)
			throw new Error('Final opening candidates require a bound final wallet');
		return hkdfKey(
			this.encryptionKey,
			JSON.stringify([
				'beignet-final-opening-candidate-v1',
				this.walletIdentity,
				channelId,
				outpoint
			])
		);
	}

	private readFinalOpening(
		row: IFinalOpeningRow,
		getIndex: (id: string) => number | null = (id) =>
			this.loadChannelKeyIndex(id)
	): IFinalOpeningRecord {
		const key = this.finalOpeningKey(row.channel_id, row.funding_outpoint);
		const plaintext = decryptValue(key, row.record_json);
		const candidate: IFinalOpeningCandidate = JSON.parse(plaintext);
		const nonceKey = this.openingNonceKey(key, plaintext);
		const nonces = decodeOpeningNonces(
			candidate.channelId,
			decryptValue(nonceKey, row.nonces_json)
		);
		const evidence = nonces.session?.assetEvidence;
		if (evidence !== undefined) {
			if (
				(this.finalGeneration !== 3 && this.finalGeneration !== 4) ||
				(this.finalGeneration === 3 &&
					nonces.session?.updateLimits !== undefined) ||
				JSON.stringify(canonicalAssetOpeningEvidence(evidence)) !==
					JSON.stringify(evidence)
			)
				throw new Error('Invalid stored asset opening evidence');
		}
		const { encoded, fundingOutpoint } = evidence
			? validateAssetOpening(
					candidate,
					Buffer.from(evidence.fundingRoot, 'hex')
			  )
			: validateFinalOpening(candidate);
		if (
			candidate.channelId !== row.channel_id ||
			fundingOutpoint !== row.funding_outpoint ||
			encoded !== plaintext
		)
			throw new Error('Invalid stored final opening candidate');
		if (nonces.session !== undefined) {
			const session = nonces.session;
			if (
				!session ||
				Object.keys(session).some(
					(k) =>
						![
							'channelKeyIndex',
							'peer',
							'terms',
							'assetEvidence',
							'updateLimits',
							'remoteSecondPerCommitmentPoint'
						].includes(k)
				) ||
				!session.terms ||
				!Number.isSafeInteger(session.channelKeyIndex) ||
				session.channelKeyIndex < 0 ||
				session.channelKeyIndex > 0x7fffffff ||
				session.peer === JSON.parse(this.walletIdentity!)[1] ||
				(nonces.signing &&
					canonicalTerms(nonces.signing.terms) !==
						canonicalTerms(session.terms)) ||
				!/^(02|03)[a-f0-9]{64}$/.test(session.peer) ||
				!isValidPublicKey(Buffer.from(session.peer, 'hex')) ||
				getIndex(candidate.channelId) !== session.channelKeyIndex
			)
				throw new Error('Invalid stored opening session');
			if (session.updateLimits !== undefined)
				validateUpdateLimits(session.updateLimits);
			validateSecondPoint(
				session.remoteSecondPerCommitmentPoint,
				session.terms
			);
			storedOpeningCommitment(candidate, session.terms, 'local', evidence);
			storedOpeningCommitment(candidate, session.terms, 'remote', evidence);
		}
		if (nonces.signing !== undefined)
			verifyOpeningSigning(candidate, nonces, getIndex(candidate.channelId));
		verifyStoredReadiness(
			nonces,
			candidate.channelId,
			FeatureFlags.fromBuffer(
				Buffer.from(candidate.channelType, 'hex')
			).hasFeature(Feature.SCID_ALIAS)
		);
		return { candidate, nonces, nonceKey };
	}

	private openingNonceKey(key: Buffer, encoded: string): Buffer {
		return hkdfKey(
			key,
			'beignet-final-opening-nonces-v1/' +
				sha256(Buffer.from(encoded)).toString('hex')
		);
	}

	/** Stream and authenticate every reservation, including on startup. */
	private readFinalOpenings(
		visit?: (
			candidate: IFinalOpeningCandidate,
			record: IFinalOpeningRecord
		) => void
	): void {
		if (!this.walletIdentity)
			throw new Error('Final opening candidates require a bound final wallet');
		const rows = this.db
			.prepare(
				'SELECT channel_id, funding_outpoint, record_json, nonces_json FROM final_opening_candidates ORDER BY channel_id'
			)
			.iterate() as Iterable<IFinalOpeningRow>;
		for (const row of rows) {
			const record = this.readFinalOpening(row);
			visit?.(record.candidate, record);
		}
	}

	private assertNoFinalOpeningConflict(id: string, state: IChannelState): void {
		const reservedId = this._stmt(
			'SELECT 1 FROM final_opening_candidates WHERE channel_id IN (?, ?, ?)'
		).get(
			id,
			state.channelId?.toString('hex') ?? null,
			state.temporaryChannelId.toString('hex')
		);
		if (reservedId)
			throw new Error('Channel id already reserved for a final opening');

		const outpoints = new Set<string>();
		const add = (hash: Buffer | null, index: number): void => {
			if (hash)
				outpoints.add(
					Buffer.from(hash).reverse().toString('hex') + ':' + index
				);
		};
		add(state.fundingTxid, state.fundingOutputIndex);
		add(state.spliceFundingTxid, state.spliceFundingOutputIndex);
		if (state.spliceInFlight)
			add(
				state.spliceInFlight.spliceTxid,
				state.spliceInFlight.newFundingOutputIndex
			);
		if (state.v2InFlight)
			add(state.v2InFlight.fundingTxid, state.v2InFlight.fundingOutputIndex);
		for (const attempt of state.v2PreviousAttempts ?? [])
			add(attempt.fundingTxid, attempt.fundingOutputIndex);
		for (const watch of state.preSpliceSpendWatches ?? [])
			outpoints.add(watch.txid + ':' + watch.outputIndex);
		for (const reverted of state.revertedSplices ?? [])
			outpoints.add(reverted.spliceTxid + ':' + reverted.newFundingOutputIndex);
		const reserved = this._stmt(
			'SELECT 1 FROM final_opening_candidates WHERE funding_outpoint = ?'
		);
		for (const outpoint of outpoints) {
			if (reserved.get(outpoint))
				throw new Error(
					'Channel funding outpoint already reserved for a final opening'
				);
		}
	}

	/** Remember the first unsigned candidate before beginning any signing session. */
	get canSignFinalOpening(): boolean {
		return this.openingAuthority !== null;
	}

	/** Original-device authority of the dedicated asset opening generation. */
	get canOpenDualFundedAssets(): boolean {
		return (
			(this.finalGeneration === 3 || this.finalGeneration === 4) &&
			this.canSignFinalOpening
		);
	}

	/** The original wallet can authorize new records for its asset funding views. */
	get canSpliceDualFundedAssets(): boolean {
		return this.finalGeneration === 4 && this.canSignFinalOpening;
	}

	/** Bind a funding signature, including a replay, to the live signer for this journal. */
	assertAssetSpliceAuthority(authority: FinalOpeningAuthority): void {
		if (
			!this.canSpliceDualFundedAssets ||
			this.db.inTransaction ||
			authority !== this.requireOpeningAuthority()
		)
			throw new Error(
				'Asset splice signing requires this original wallet device outside a transaction'
			);
		authority.assertDaemonEnrollment();
	}

	private assetSpliceJournal(channelId: string): FinalDeviceJournal {
		if (
			this.finalGeneration !== 4 ||
			!this.loadFinalOpeningSession(channelId)?.assetEvidence
		)
			throw new Error(
				'Asset splice history requires an enrolled asset channel'
			);
		return this.finalJournal();
	}

	readAssetSpliceJournal<T = unknown>(channelId: string) {
		return this.assetSpliceJournal(channelId).read<T>(
			'asset-splice',
			channelId
		);
	}

	appendAssetSpliceEvent<T>(
		channelId: string,
		head: IFinalJournalHead,
		event: T
	) {
		if (!this.canSpliceDualFundedAssets || this.db.inTransaction)
			throw new Error(
				'Asset splice history requires the original wallet device outside a transaction'
			);
		// Reject information that JSON would drop before recording an irreversible device claim.
		const encoded = JSON.stringify(event);
		if (encoded === undefined || event === null || typeof event !== 'object')
			throw new Error('Expected a JSON asset splice event');
		const snapshot = JSON.parse(encoded) as T;
		if (!isDeepStrictEqual(event, snapshot))
			throw new Error('Asset splice event must preserve its exact JSON fields');
		return this.assetSpliceJournal(channelId).append(
			'asset-splice',
			channelId,
			head,
			snapshot
		);
	}

	private assetStageAuthority(): FinalOpeningAuthority {
		if (!this.canOpenDualFundedAssets || this.db.inTransaction)
			throw new Error(
				'Asset opening stages require their enrolled original device outside a transaction'
			);
		return this.requireOpeningAuthority();
	}

	saveAssetOpenStage(id: string, field: string, bytes: Buffer): void {
		this.assetStageAuthority().saveAssetOpenStage(id, field, bytes);
	}
	loadAssetOpenStage(id: string, field: string): Buffer | null {
		return this.assetStageAuthority().loadAssetOpenStage(id, field);
	}
	listAssetOpenStages(): string[] {
		return this.assetStageAuthority().listAssetOpenStages();
	}
	reserveAssetOpenSignature(
		id: string,
		field: string,
		digest: string | Buffer
	): void {
		this.assetStageAuthority().reserveAssetOpenSignature(id, field, digest);
	}

	/** A copied wallet cannot prove that a backup commitment remains unrevoked. */
	get canUpdateFinalCommitments(): boolean {
		return this.updateWallet && this.canSignFinalOpening;
	}

	private requireCurrentFinalDevice(): void {
		if (
			(this.updateWallet || this.finalGeneration === 4) &&
			!this.canSignFinalOpening
		)
			throw new Error('Current commitment requires the original wallet device');
	}

	loadFinalOpeningSession(channelId: string): IFinalOpeningSession | null {
		return this.finalOpeningRecord(channelId)?.nonces.session ?? null;
	}

	rememberFinalOpeningSession(
		candidate: IFinalOpeningCandidate,
		peer: string,
		terms: IFinalOpeningTerms,
		channelKeyIndex: number,
		remoteSecondPerCommitmentPoint?: string,
		updateLimits?: IFinalUpdateLimits
	): void {
		this.rememberOpeningSession(
			candidate,
			peer,
			terms,
			channelKeyIndex,
			remoteSecondPerCommitmentPoint,
			updateLimits
		);
	}

	rememberAssetOpeningSession(
		candidate: IFinalOpeningCandidate,
		peer: string,
		terms: IFinalOpeningTerms,
		channelKeyIndex: number,
		remoteSecondPerCommitmentPoint: string,
		evidence: IAssetOpeningEvidence,
		updateLimits?: IFinalUpdateLimits
	): void {
		if (!this.canOpenDualFundedAssets)
			throw new Error('Asset opening requires its enrolled original device');
		this.rememberOpeningSession(
			candidate,
			peer,
			terms,
			channelKeyIndex,
			remoteSecondPerCommitmentPoint,
			this.canSpliceDualFundedAssets ? updateLimits : undefined,
			canonicalAssetOpeningEvidence(evidence)
		);
	}

	loadAssetOpeningEvidence(channelId: string): IAssetOpeningEvidence | null {
		return this.loadFinalOpeningSession(channelId)?.assetEvidence ?? null;
	}

	private rememberOpeningSession(
		candidate: IFinalOpeningCandidate,
		peer: string,
		terms: IFinalOpeningTerms,
		channelKeyIndex: number,
		remoteSecondPerCommitmentPoint?: string,
		updateLimits?: IFinalUpdateLimits,
		assetEvidence?: IAssetOpeningEvidence
	): void {
		if (
			!/^(02|03)[0-9a-f]{64}$/.test(peer) ||
			!isValidPublicKey(Buffer.from(peer, 'hex')) ||
			peer === JSON.parse(this.walletIdentity ?? '[]')[1]
		)
			throw new Error('Invalid final opening peer identity');
		storedOpeningCommitment(candidate, terms, 'local', assetEvidence);
		storedOpeningCommitment(candidate, terms, 'remote', assetEvidence);
		validateSecondPoint(remoteSecondPerCommitmentPoint, terms);
		if (updateLimits !== undefined) validateUpdateLimits(updateLimits);
		const session = {
			...(assetEvidence && { assetEvidence }),
			...(updateLimits && { updateLimits }),
			peer,
			terms: JSON.parse(canonicalTerms(terms)) as IFinalOpeningTerms,
			channelKeyIndex,
			...(remoteSecondPerCommitmentPoint !== undefined && {
				remoteSecondPerCommitmentPoint
			})
		};
		this.reserveFinalCandidate(candidate, session);
	}

	rememberFinalOpening(candidate: IFinalOpeningCandidate): void {
		this.reserveFinalCandidate(candidate);
	}

	private reserveFinalCandidate(
		candidate: IFinalOpeningCandidate,
		session?: IFinalOpeningSession
	): void {
		if (this.db.inTransaction)
			throw new Error('Final opening reservation requires a top-level commit');
		const evidence = session?.assetEvidence;
		const { encoded, fundingOutpoint } = evidence
			? validateAssetOpening(
					candidate,
					Buffer.from(evidence.fundingRoot, 'hex')
			  )
			: validateFinalOpening(candidate);
		const { channelId } = candidate;
		const key = this.finalOpeningKey(channelId, fundingOutpoint);
		this.db
			.transaction(() => {
				const existing = this.loadFinalOpening(channelId);
				if (existing) {
					if (JSON.stringify(existing) !== encoded)
						throw new Error(
							'A different final opening candidate is already reserved'
						);
					if (
						session &&
						JSON.stringify(this.loadFinalOpeningSession(channelId)) !==
							JSON.stringify(session)
					)
						throw new Error(
							'Opening session differs from its original reservation'
						);
					return;
				}
				const authority = this.requireOpeningAuthority();
				if (session) {
					authority.requireAllocatedChannelKey(session.channelKeyIndex);
					if (
						this.loadAllChannelKeyIndices().some((row) =>
							row.channelId === channelId
								? row.channelIndex !== session.channelKeyIndex
								: row.channelIndex === session.channelKeyIndex
						)
					)
						throw new Error('Opening key locator is already assigned');
					authority.claim(
						'opening/session/' + channelId,
						sha256(Buffer.from(JSON.stringify(session))).toString('hex')
					);
					authority.claim(
						'commitment/key/' + session.channelKeyIndex,
						channelId
					);
					this.saveChannelKeyIndex(channelId, session.channelKeyIndex);
				}
				const inserted = this._stmt(
					'INSERT INTO final_opening_candidates (channel_id, funding_outpoint, record_json, nonces_json) VALUES (?, ?, ?, ?)'
				).run(
					channelId,
					fundingOutpoint,
					encryptValue(key, encoded),
					encryptValue(
						this.openingNonceKey(key, encoded),
						JSON.stringify(session ? { session } : {})
					)
				);
				if (
					inserted.changes !== 1 ||
					JSON.stringify(this.loadFinalOpening(channelId)) !== encoded
				)
					throw new Error('Final opening candidate was not written');
				// Channel outpoints are in encrypted state, including pending v2
				// attempts and splices. Check every row before committing this slot.
				this.loadAllChannels();
				authority.bindCandidate(
					channelId,
					fundingOutpoint,
					sha256(Buffer.from(encoded)).toString('hex')
				);
			})
			.immediate();
	}

	/** Read and authenticate the complete unsigned candidate against its indexed outpoint. */
	loadFinalOpening(channelId: string): IFinalOpeningCandidate | null {
		return this.finalOpeningRecord(channelId)?.candidate ?? null;
	}

	/** Discover the remembered openings after a restart, before any live channel exists. */
	loadFinalOpenings(): IFinalOpeningCandidate[] {
		const candidates: IFinalOpeningCandidate[] = [];
		this.readFinalOpenings((candidate) => candidates.push(candidate));
		return candidates;
	}

	private finalOpeningRecord(channelId: string): IFinalOpeningRecord | null {
		if (!this.walletIdentity)
			throw new Error('Final opening candidates require a bound final wallet');
		if (typeof channelId !== 'string' || !/^[0-9a-f]{64}$/.test(channelId))
			throw new Error('Invalid final opening channel id');
		const row = this._stmt(
			'SELECT channel_id, funding_outpoint, record_json, nonces_json FROM final_opening_candidates WHERE channel_id = ?'
		).get(channelId) as IFinalOpeningRow | undefined;
		return row ? this.readFinalOpening(row) : null;
	}

	/** An editable turn advertises only verification nonces. The device can reproduce
	 * the promise if this exact transaction closes the interactive exchange.
	 */
	previewFinalOpeningTxComplete(
		candidate: IFinalOpeningCandidate,
		fundingKey: Buffer,
		keyIndex: number
	): Buffer {
		return this.previewOpeningNonce(
			candidate,
			validateFinalOpening(candidate),
			fundingKey,
			keyIndex
		);
	}

	previewAssetOpeningTxComplete(
		candidate: IFinalOpeningCandidate,
		fundingRoot: Buffer,
		fundingKey: Buffer,
		keyIndex: number
	): Buffer {
		if (!this.canOpenDualFundedAssets)
			throw new Error('Asset opening requires its enrolled original device');
		return this.previewOpeningNonce(
			candidate,
			validateAssetOpening(candidate, fundingRoot),
			fundingKey,
			keyIndex
		);
	}

	private previewOpeningNonce(
		candidate: IFinalOpeningCandidate,
		checked: ReturnType<typeof validateFinalOpening>,
		fundingKey: Buffer,
		keyIndex: number
	): Buffer {
		const authority = this.requireOpeningAuthority();
		authority.requireAllocatedChannelKey(keyIndex);
		const { encoded, fundingOutpoint } = checked;
		const key = this.finalOpeningKey(candidate.channelId, fundingOutpoint);
		const context = authority.nonceContext(this.openingNonceKey(key, encoded));
		return localOpeningTxComplete(
			{},
			candidate.channelId,
			candidate.localFundingPubkey,
			fundingKey,
			context,
			hkdfKey(context, 'beignet-editable-opening-turn-v1')
		);
	}

	/** Return the exact tx_complete payload after its nonce reservation commits. */
	finalOpeningTxComplete(channelId: string, fundingPrivateKey: Buffer): Buffer {
		return this.updateOpeningNonces(
			channelId,
			(nonces, candidate, nonceKey) => {
				if (
					getPublicKey(fundingPrivateKey).toString('hex') !==
					candidate.localFundingPubkey
				)
					throw new Error('Opening funding key does not match');
				if (!this.openingAuthority && nonces.local)
					return Buffer.from(nonces.local.payload, 'hex');
				const authority = this.requireOpeningAuthority();
				const slot = 'tx_complete/local/' + channelId;
				const transcript = nonceKey.toString('hex');
				const context = authority.nonceContext(nonceKey);
				const cached = authority.claim(slot, transcript);
				if (cached) {
					const local = decodeOpeningNonces(
						channelId,
						cached.toString('utf8')
					).local;
					if (
						!local ||
						(nonces.local &&
							JSON.stringify(nonces.local) !== JSON.stringify(local))
					)
						throw new Error(
							'Original opening nonce reservation disagrees with wallet'
						);
					nonces.local = local;
				}
				const payload = localOpeningTxComplete(
					nonces,
					channelId,
					candidate.localFundingPubkey,
					fundingPrivateKey,
					context,
					hkdfKey(context, 'beignet-editable-opening-turn-v1')
				);
				authority.finish(
					slot,
					transcript,
					Buffer.from(JSON.stringify({ local: nonces.local }))
				);
				return payload;
			}
		);
	}

	/** Reserve the actual BIP32 index in both original-device and wallet storage before key derivation. */
	allocateFinalChannelKeyIndex(minimum: number): number {
		if (
			this.db.inTransaction ||
			!Number.isSafeInteger(minimum) ||
			minimum < 1 ||
			minimum > 0x7fffffff
		)
			throw new Error(
				'Opening keys require a valid minimum and a top-level commit'
			);
		const authority = this.requireOpeningAuthority();
		return this.db
			.transaction(() => {
				const prior = this.loadMetadata('channel_key_index_allocated');
				if (
					prior !== null &&
					(!/^(0|[1-9][0-9]{0,9})$/.test(prior) || Number(prior) > 0x7fffffff)
				)
					throw new Error('Invalid wallet channel key allocation');
				const floor = this.loadMetadata('channel_key_index_floor');
				if (
					floor !== null &&
					(!/^(0|[1-9][0-9]{0,9})$/.test(floor) || Number(floor) > 0x7fffffff)
				)
					throw new Error('Invalid wallet channel key index floor');
				const index = authority.allocateChannelKey(
					Math.max(
						minimum,
						this.loadNextChannelIndex(),
						Number(prior) + 1,
						Number(floor)
					)
				);
				this.saveMetadata('channel_key_index_allocated', String(index));
				if (this.loadMetadata('channel_key_index_allocated') !== String(index))
					throw new Error('Opening channel key allocation was not written');
				return index;
			})
			.immediate();
	}

	assertFinalDaemonIdentity(nodeId: string): void {
		if (
			this.walletIdentity !==
			JSON.stringify([this.finalGeneration, nodeId, 'regtest'])
		)
			throw new Error('Expected the enrolled regtest final wallet identity');
		const authority = this.requireOpeningAuthority();
		authority.assertDaemonEnrollment();
		authority.assertEnforceableExits((id) => this.openingExitBytes(id));
	}

	private requireOpeningAuthority(): FinalOpeningAuthority {
		if (!this.openingAuthority)
			throw new Error(
				'New opening signatures require the original wallet device'
			);
		return this.openingAuthority;
	}

	loadFinalLocalTxComplete(channelId: string): Buffer | null {
		const local = this.finalOpeningRecord(channelId)?.nonces.local;
		return local ? Buffer.from(local.payload, 'hex') : null;
	}

	rememberFinalPeerTxComplete(channelId: string, payload: Buffer): void {
		this.updateOpeningNonces(channelId, (nonces, candidate, nonceKey) => {
			const before = nonces.peer;
			recordPeerTxComplete(nonces, channelId, payload);
			if (!this.openingAuthority && before === nonces.peer) return;
			const authority = this.requireOpeningAuthority();
			const slot = 'tx_complete/peer/' + candidate.channelId;
			const transcript = sha256(Buffer.concat([nonceKey, payload])).toString(
				'hex'
			);
			authority.claim(slot, transcript);
			authority.finish(slot, transcript, payload);
		});
	}

	loadFinalPeerTxComplete(channelId: string): Buffer | null {
		const peer = this.finalOpeningRecord(channelId)?.nonces.peer;
		return peer === undefined ? null : Buffer.from(peer, 'hex');
	}

	signFinalPeerCommitment(
		channelId: string,
		terms: IFinalOpeningTerms,
		keys: BIP32Interface,
		channelKeyIndex: number
	): Buffer {
		return this.openingCommitment(channelId, terms, keys, channelKeyIndex);
	}

	acceptFinalPeerCommitment(
		channelId: string,
		terms: IFinalOpeningTerms,
		keys: BIP32Interface,
		channelKeyIndex: number,
		payload: Buffer
	): Buffer {
		if (!Buffer.isBuffer(payload))
			throw new Error('Missing peer opening commitment');
		return this.openingCommitment(
			channelId,
			terms,
			keys,
			channelKeyIndex,
			payload
		);
	}

	private openingCommitment(
		channelId: string,
		terms: IFinalOpeningTerms,
		keys: BIP32Interface,
		index: number,
		payload?: Buffer
	): Buffer {
		this.requireCurrentFinalDevice();
		return this.updateOpeningNonces(
			channelId,
			(nonces, candidate, nonceKey) => {
				if (payload && this.openingSuperseded({ candidate, nonces, nonceKey }))
					throw new Error('Opening exit was superseded by a later commitment');
				const current = this.loadChannelKeyIndex(channelId);
				if (
					(current !== null && current !== index) ||
					this.loadAllChannelKeyIndices().some(
						(row) => row.channelId !== channelId && row.channelIndex === index
					)
				)
					throw new Error(
						'Opening channel key index belongs to another derivation'
					);
				const result = signOpening(
					candidate,
					nonces,
					nonceKey,
					terms,
					keys,
					index,
					this.walletIdentity!,
					this.openingAuthority,
					payload
				);
				if (current === null) {
					this.saveChannelKeyIndex(channelId, index);
					if (this.loadChannelKeyIndex(channelId) !== index)
						throw new Error('Opening channel key index was not written');
				}
				return result;
			}
		);
	}

	loadFinalPeerCommitment(channelId: string): Buffer | null {
		const hex = this.finalOpeningRecord(channelId)?.nonces.signing?.outgoing;
		return hex === undefined ? null : Buffer.from(hex, 'hex');
	}

	loadFinalOpeningExit(channelId: string): Buffer | null {
		this.requireCurrentFinalDevice();
		const r = this.finalOpeningRecord(channelId);
		if (r && this.openingSuperseded(r))
			throw new Error('Opening exit was superseded by a later commitment');
		return this.openingExitBytes(channelId);
	}

	private retainedAssetFundingExits(record: IFinalOpeningRecord): string[] {
		if (this.finalGeneration !== 4 || !record.nonces.session?.assetEvidence)
			return [];
		const { channelId, fundingTxHex, fundingOutputIndex } = record.candidate;
		const { records } = this.finalJournal().read<AssetSpliceExitEvent>(
			'asset-splice',
			channelId
		);
		return assetSpliceFundingExits(
			records,
			channelId,
			Transaction.fromHex(fundingTxHex).getId(),
			fundingOutputIndex,
			record.nonces.session.assetEvidence.fundingRoot,
			record.nonces.signing?.exit
		);
	}

	private openingSuperseded(record: IFinalOpeningRecord): boolean {
		return (
			this.retainedAssetFundingExits(record).length > 0 ||
			!!this.latestFinalUpdate(record)?.local.height ||
			(this.canUpdateFinalCommitments &&
				this.readFinalSpliceAttempts(record.candidate.channelId).some(
					(a) => !!a.adopted
				))
		);
	}

	private openingExitBytes(channelId: string): Buffer | null {
		const hex = this.finalOpeningRecord(channelId)?.nonces.signing?.exit;
		return hex === undefined ? null : Buffer.from(hex, 'hex');
	}

	private latestFinalUpdate(
		record: IFinalOpeningRecord
	): IFinalLedgerState | null {
		if (!this.canUpdateFinalCommitments) return null;
		const state =
			currentFinalJournal(
				this.db,
				this.requireOpeningAuthority(),
				record.candidate.channelId,
				record.nonceKey
			)?.state ?? null;
		if (state?.dataLoss) throw new FinalUpdateDataLossError();
		return state;
	}

	private availableFundingExits(record: IFinalOpeningRecord) {
		const opening = record.nonces.signing?.exit;
		if (!opening) return [];
		const retained = this.retainedAssetFundingExits(record);
		let exits = retained.length ? retained : [opening];
		if (this.canUpdateFinalCommitments && record.nonces.session?.updateLimits) {
			const existing = this.latestFinalUpdate(record);
			if (existing || (record.nonces.localReady && record.nonces.peerReady)) {
				const ctx = this.finalUpdateContext(record);
				const state = existing ?? this.initialUpdateState(ctx);
				const attempts = this.readFinalSpliceAttempts(
					record.candidate.channelId
				);
				const released = new Set(
					attempts.map((a) => releasedFinalSpliceFunding(a)?.fundingTxHex)
				);
				const views = finalFundingLedgers(ctx, state, attempts);
				const all = [
					...views.map((v) => v.s),
					state,
					...Object.values(state.alternatives ?? {})
				];
				const latest = Math.max(...all.map((s) => s.local.height));
				exits = [
					...new Set(
						all
							.filter(
								(s) =>
									s.local.height === latest &&
									(!s.funding || released.has(s.funding.fundingTxHex))
							)
							.map((s) => s.local.tx)
					)
				];
			}
		}
		return exits.map((hex) => {
			const exit = Buffer.from(hex, 'hex');
			return { exit, fundingTxid: Transaction.fromBuffer(exit).ins[0].hash };
		});
	}

	loadFinalFundingExits(id: string) {
		this.requireCurrentFinalDevice();
		const record = this.finalOpeningRecord(id);
		return record ? this.availableFundingExits(record) : [];
	}

	private selectedFinalExit(
		record: IFinalOpeningRecord,
		requested?: string | null,
		fundingTxid?: Buffer,
		fundingOutputIndex?: number
	): string {
		const exits = this.availableFundingExits(record);
		if (fundingOutputIndex !== undefined && !fundingTxid)
			throw new Error('A funding output index requires its transaction ID');
		const matches = exits.filter((e) =>
			fundingTxid
				? e.fundingTxid.equals(fundingTxid) &&
				  (fundingOutputIndex === undefined ||
						Transaction.fromBuffer(e.exit).ins[0].index === fundingOutputIndex)
				: !requested || sha256(e.exit).toString('hex') === requested
		);
		if (this.finalGeneration === 4 && matches.length > 1)
			throw new Error(
				'Select the matching asset funding outpoint for this exit'
			);
		const match = matches[0];
		if (!match)
			throw new Error(
				'Requested exit does not match a current funding commitment'
			);
		return match.exit.toString('hex');
	}

	private finalUpdateContext(record: IFinalOpeningRecord): IFinalUpdateContext {
		return {
			...record,
			identity: this.walletIdentity!,
			authority: this.requireOpeningAuthority()
		};
	}

	private initialUpdateState(ctx: IFinalUpdateContext): IFinalLedgerState {
		const id = ctx.candidate.channelId;
		for (const side of ['local', 'peer'] as const)
			ctx.authority.requireReconnectPromise(
				'channel-reestablish/' + side + '/' + id,
				ctx.nonces[side === 'local' ? 'localReconnect' : 'peerReconnect']
			);
		return initialFinalLedger(ctx.candidate, ctx.nonces);
	}

	private updateFinalLedger<T>(
		id: string,
		change: (views: IFundingLedger[]) => T,
		access: 'commitment' | 'reestablish' | 'delivery' = 'commitment'
	): T {
		if (!this.canUpdateFinalCommitments || this.db.inTransaction)
			throw new Error(
				'Final updates require an original update wallet and a top-level commit'
			);
		return this.db
			.transaction(() => {
				const record = this.finalOpeningRecord(id);
				if (!record?.nonces.session?.updateLimits)
					throw new Error('Missing negotiated final HTLC limits');
				if (access !== 'delivery' && this.finalExitRequested(id, record.nonces))
					throw new Error('Final channel close already requested');
				const ctx = this.finalUpdateContext(record);
				const previous = currentFinalJournal(
					this.db,
					ctx.authority,
					id,
					ctx.nonceKey
				);
				const state = previous?.state ?? this.initialUpdateState(ctx);
				const before = JSON.stringify(state);
				const attempts = this.readFinalSpliceAttempts(id);
				if (access === 'commitment' && attempts.some(spliceBlocksFinalUpdates))
					throw new Error(
						'Final channel is quiescent during splice negotiation'
					);
				const views = finalFundingLedgers(
					ctx,
					state,
					attempts,
					access === 'reestablish'
				);
				if (
					access === 'commitment' &&
					views.some((v) => v.s.awaitingFundingNonce)
				)
					throw new Error(
						'Waiting for the peer verification nonce for its funded splice'
					);
				if (views.some((v) => v.s.dataLoss) || state.dataLoss)
					throw new FinalUpdateDataLossError();
				if (
					this.finalSimpleCloseLocked(id) &&
					(access === 'commitment' ||
						(access === 'reestablish' &&
							views.some((v) => v.s.waiting.length || v.s.inFlight)))
				)
					throw new Error('Final simple close already locked');
				const result = change(views);
				if (views.some((v) => v.s.dataLoss)) state.dataLoss = true;
				if (JSON.stringify(state) !== before)
					appendFinalJournal(
						this.db,
						ctx.authority,
						id,
						ctx.nonceKey,
						previous,
						state,
						access === 'delivery'
					);
				return result;
			})
			.immediate();
	}

	private finalUpdateView(id: string) {
		if (!this.canUpdateFinalCommitments) return null;
		const record = this.finalOpeningRecord(id);
		if (
			!record?.nonces.session?.updateLimits ||
			!record.nonces.peerReady ||
			!record.nonces.localReady
		)
			return null;
		const ctx = this.finalUpdateContext(record);
		const state =
			this.latestFinalUpdate(record) ?? this.initialUpdateState(ctx);
		const attempts = this.readFinalSpliceAttempts(id);
		return {
			ctx,
			state,
			attempts,
			views: finalFundingLedgers(ctx, state, attempts)
		};
	}

	loadFinalOfferedHtlc(id: string, htlcId: bigint) {
		const view = this.finalUpdateView(id);
		if (!view) return null;
		for (const { s } of view.views) {
			const match = finalOfferedHtlc(s, htlcId);
			if (match) return match;
		}
		return null;
	}

	loadFinalUpdateStatus(id: string) {
		const view = this.finalUpdateView(id);
		return view ? fundingAdmission(view.views) : null;
	}

	loadFinalResolutionStates(id: string) {
		const view = this.finalUpdateView(id);
		if (!view) return null;
		const rawHistory = () =>
			finalJournalHistory(this.db, id, view.ctx.nonceKey);
		const primary = finalResolutionStates(view.ctx, view.state, rawHistory());
		const all = [primary];
		for (const [txid, slot] of Object.entries(view.state.alternatives ?? {})) {
			const history = function* () {
				for (const root of rawHistory())
					if (root.alternatives?.[txid]) yield root.alternatives[txid];
			};
			all.push(
				finalResolutionStates(
					withFunding(view.ctx, slot.funding!),
					slot,
					history()
				)
			);
		}
		const selected = view.views[0].ctx.funding;
		const current = all.find(
			(a) => a.local.funding?.fundingTxHex === selected?.fundingTxHex
		)!;
		const revoked = all.flatMap((v) => v.revoked);
		const secrets = new Map(revoked.map((v) => [v.height, v.secret!]));
		const remote = all
			.flatMap((v) => v.remote)
			.filter((tx) => {
				const secret = secrets.get(tx.height);
				if (!secret) return true;
				revoked.push({ ...tx, secret });
				return false;
			});
		const latest = all.reduce(
			(h, v) => (v.local.height > h ? v.local.height : h),
			0n
		);
		if (current.local.height !== latest)
			throw new Error('Selected funding has no unrevoked local commitment');
		const released = new Set(
			view.attempts.map((a) => releasedFinalSpliceFunding(a)?.fundingTxHex)
		);
		return {
			...current,
			locals: all
				.map((v) => v.local)
				.filter(
					(v) =>
						v.height === latest &&
						(!v.funding || released.has(v.funding.fundingTxHex))
				),
			remote,
			revoked,
			preimages: [
				...new Map(
					all
						.flatMap((v) => v.preimages)
						.map((preimage) => [preimage.toString('hex'), preimage])
				).values()
			]
		};
	}

	loadFinalCommitmentSnapshot(id: string) {
		const view = this.finalUpdateView(id);
		return view
			? finalLedgerSnapshot(view.views[0].ctx, view.views[0].s)
			: null;
	}

	stageFinalHtlcUpdate(
		id: string,
		direction: 'local' | 'peer',
		type: MessageType,
		payload: Buffer
	): void {
		this.updateFinalLedger(id, (views) => {
			if (
				type === MessageType.UPDATE_ADD_HTLC &&
				(direction === 'local'
					? this.finalSimpleCloseStarted(id)
					: this.finalPeerSimpleShutdownReceived(id))
			)
				throw new Error('Final channel shutdown forbids new HTLCs');
			for (const { ctx, s } of views)
				stageFinalLedgerUpdate(ctx, s, direction, type, payload);
		});
	}

	signFinalUpdateCommitment(id: string, root: BIP32Interface): Buffer {
		return this.updateFinalLedger(id, (views) => {
			if (views.length !== 1)
				throw new Error('Final commitment requires a funding batch');
			return signFundingBatch(views, root)[0];
		});
	}

	signFinalUpdateCommitmentBatch(id: string, root: BIP32Interface): Buffer[] {
		return this.updateFinalLedger(id, (views) => signFundingBatch(views, root));
	}

	acceptFinalUpdateCommitment(
		id: string,
		root: BIP32Interface,
		payload: Buffer
	): Buffer {
		return this.acceptFinalUpdateCommitmentBatch(id, root, [payload]);
	}

	acceptFinalUpdateCommitmentBatch(
		id: string,
		root: BIP32Interface,
		payloads: Buffer[]
	): Buffer {
		return this.updateFinalLedger(id, (views) =>
			receiveFundingBatch(views, root, payloads)
		);
	}

	acceptFinalUpdateRevocation(id: string, payload: Buffer): void {
		this.updateFinalLedger(id, (views) => receiveFundingRevoke(views, payload));
	}

	finalUpdateReestablish(id: string, root: BIP32Interface) {
		return this.updateFinalLedger(
			id,
			(views) => fundingReestablish(views, root),
			'reestablish'
		);
	}

	acceptFinalUpdateReestablish(
		id: string,
		root: BIP32Interface,
		msg: IChannelReestablishMessage
	) {
		const splice = msg.myCurrentFundingLocked
			? this.finalSpliceSession(id, root)
			: undefined;
		const result = this.updateFinalLedger(
			id,
			(views) => {
				const attempts = this.readFinalSpliceAttempts(id);
				const pending = attempts.find(
					(a) => a.aborted === undefined && !a.adopted && a.candidate
				);
				const locked = msg.myCurrentFundingLocked;
				const child =
					pending?.candidate &&
					Transaction.fromHex(pending.candidate.funding.fundingTxHex).getHash();
				if (locked) {
					const original = Transaction.fromHex(
						views[0].ctx.candidate.fundingTxHex
					).getHash();
					if (
						locked.retransmitFlags !== 0 ||
						(!locked.txid.equals(original) &&
							!attempts.some((a) => {
								const ref = releasedFinalSpliceFunding(a);
								return (
									ref &&
									locked.txid.equals(
										Transaction.fromHex(ref.fundingTxHex).getHash()
									)
								);
							}))
					)
						throw new FinalUpdateProtocolError(
							'Peer named an unknown locked funding transaction'
						);
				}
				const lock = !!(
					locked &&
					pending?.funded &&
					locked.txid.equals(child!)
				);
				const covered =
					lock &&
					pending!.localLock === Buffer.from(child!).reverse().toString('hex')
						? views.filter(
								(v) =>
									v.ctx.funding?.fundingTxHex ===
									pending!.candidate!.funding.fundingTxHex
						  )
						: views;
				const needsWitnesses = !!(child && msg.nextFundingTxid?.equals(child));
				// A peer requesting its interactive funding signatures may still advertise only the parent.
				const expected = needsWitnesses
					? covered.filter(
							(v) =>
								!v.ctx.funding ||
								v.ctx.funding.fundingTxHex !==
									pending!.candidate!.funding.fundingTxHex ||
								msg.nextLocalNonces?.some((n) => n.fundingTxid.equals(child!))
					  )
					: covered;
				if (!expected.length)
					throw new Error('Missing active reconnect funding');
				const incomplete = attempts.some(spliceBlocksFinalUpdates);
				const missing = expected.length !== covered.length;
				const frames = receiveFundingReestablish(
					expected,
					root,
					msg,
					missing || incomplete
				);
				for (const v of covered) {
					if (expected.includes(v)) delete v.s.awaitingFundingNonce;
					else v.s.awaitingFundingNonce = true;
				}
				const dataLoss = expected.some((v) => v.s.dataLoss);
				if (lock && !dataLoss && !pending!.peerLock) {
					splice!.receive({
						type: MessageType.SPLICE_LOCKED,
						payload: encodeSpliceLockedMessage({
							channelId: msg.channelId,
							fundingTxid: child!
						})
					});
				}
				return { frames, dataLoss };
			},
			'reestablish'
		);
		if (result.dataLoss) throw new FinalUpdateDataLossError();
		return result.frames;
	}

	loadFinalUpdateDeliveries(id: string) {
		const view = this.finalUpdateView(id);
		return view ? finalLedgerDeliveries(view.views[0].s) : [];
	}

	ackFinalUpdateDelivery(id: string, deliveryId: bigint): void {
		this.updateFinalLedger(
			id,
			(views) => {
				for (const { s } of views)
					s.deliveries = s.deliveries.filter(
						(d) => BigInt(d.update.ordinal) !== deliveryId
					);
			},
			'delivery'
		);
	}

	/** Prepare the immutable height-one promise after the chain watcher confirms funding. */
	finalOpeningChannelReady(channelId: string, root: BIP32Interface): Buffer {
		return this.updateOpeningNonces(channelId, (state, _candidate, key) => {
			requireReadySession(state, true);
			if (this.finalExitRequested(channelId, state))
				throw new Error('Opening exit already requested');
			if (state.localReady) return Buffer.from(state.localReady, 'hex');
			const authority = this.requireOpeningAuthority();
			const keys = readyKeys(root, state, this.walletIdentity!);
			const payload = makeReadyPayload(
				channelId,
				keys,
				authority.nonceContext(key)
			);
			verifyReady(state, channelId, payload, true, true);
			const alias = decodeChannelReadyMessage(payload).shortChannelId!;
			if (
				this.loadAllChannels().some(
					({ state: channel }) =>
						channel.scidAlias?.equals(alias) ||
						channel.shortChannelId?.equals(alias)
				)
			)
				throw new Error('Local channel_ready alias is in use');
			authority.claim(
				'channel-ready/alias/' + alias.toString('hex'),
				channelId
			);
			state.localReady = payload.toString('hex');
			return payload;
		});
	}

	rememberFinalPeerChannelReady(
		channelId: string,
		payload: Buffer,
		requireAlias = false
	): void {
		this.updateOpeningNonces(channelId, (state, candidate, key) => {
			verifyReady(
				state,
				channelId,
				payload,
				false,
				requireAlias ||
					FeatureFlags.fromBuffer(
						Buffer.from(candidate.channelType, 'hex')
					).hasFeature(Feature.SCID_ALIAS)
			);
			if (state.peerReady) {
				requireSameReadyPromise(Buffer.from(state.peerReady, 'hex'), payload);
				return;
			}
			if (this.finalExitRequested(channelId, state))
				throw new Error('Opening exit already requested');
			const authority = this.requireOpeningAuthority();
			const slot = 'channel-ready/peer/' + channelId;
			const transcript = key.toString('hex');
			const first = authority.claim(slot, transcript) ?? payload;
			requireSameReadyPromise(first, payload);
			authority.finish(slot, transcript, first);
			state.peerReady = first.toString('hex');
		});
	}

	/** Record finality only after the watched, confirmed spend reaches the ordinary irrevocable depth. */
	finalHtlcTimedOut(
		id: string,
		paymentHash: Buffer,
		htlcId: bigint,
		record = false
	): boolean {
		if (!this.canUpdateFinalCommitments) return false;
		const key = htlcId.toString() + '/' + paymentHash.toString('hex');
		const journal = this.finalJournal();
		const head = journal.read<string>('htlc-timeout', id);
		if (head.records.includes(key)) return true;
		if (!record) return false;
		journal.append('htlc-timeout', id, head, key);
		return true;
	}

	/** Keep the fee inputs and exact child witness selected on this original. */
	finalSponsoredClaim(
		channelId: string,
		template: string,
		signed?: string
	): Buffer | null {
		if (!this.canUpdateFinalCommitments || !/^[a-f0-9]{64}$/.test(template))
			throw new Error(
				'Final claim sponsorship requires the original update wallet'
			);
		return this.db
			.transaction(() => {
				const journal = this.finalJournal();
				const head = journal.read<{ template: string; raw: string }>(
					'output-claim',
					channelId
				);
				const retained = head.records.find((r) => r.template === template);
				if (retained) return Buffer.from(retained.raw, 'hex');
				if (!signed) return null;
				journal.append('output-claim', channelId, head, {
					template,
					raw: signed
				});
				return Buffer.from(signed, 'hex');
			})
			.immediate();
	}

	loadFinalSimpleClose(id: string): IFinalSimpleCloseState | null {
		if (!this.updateWallet) return null;
		const { records } = this.finalJournal().read<IFinalSimpleCloseState>(
			'simple-close',
			id
		);
		return records[records.length - 1] ?? null;
	}

	finalSimpleCloseStarted(id: string): boolean {
		return !!this.loadFinalSimpleClose(id);
	}

	finalPeerSimpleShutdownReceived(id: string): boolean {
		return !!this.loadFinalSimpleClose(id)?.peerShutdown;
	}

	finalSimpleCloseLocked(id: string): boolean {
		return (
			this.updateWallet &&
			(!!this.openingAuthority?.lifecycleEntry('simple-close-lock/' + id) ||
				!!this.loadFinalSimpleClose(id)?.locked)
		);
	}

	matchFinalSimpleCloseSpend(
		id: string,
		rawTx: Buffer,
		_root: BIP32Interface
	): boolean {
		return matchFinalSimpleCloseSpend(this.loadFinalSimpleClose(id), rawTx);
	}

	finalSimpleCloseTransactions(id: string): Buffer[] {
		const close = this.loadFinalSimpleClose(id);
		const all = [
			close?.localTransaction,
			close?.peerTransaction,
			...(close?.priorTransactions ?? [])
		];
		return [...new Set(all)]
			.filter((hex): hex is string => !!hex)
			.map((hex) => Buffer.from(hex, 'hex'));
	}

	finalSimpleCloseStep(
		id: string,
		root: BIP32Interface,
		request: IFinalCloseRequest
	): ReturnType<typeof driveFinalSimpleClose> {
		if (!this.canUpdateFinalCommitments)
			throw new Error(
				'Final close requires the original update-capable wallet'
			);
		if (this.db.inTransaction)
			throw new Error('Final close requires a top-level wallet commit');
		return this.db
			.transaction(() => {
				const row = this.finalOpeningRecord(id);
				const authority = this.requireOpeningAuthority();
				if (
					!row?.nonces.session ||
					!row.nonces.localReady ||
					!row.nonces.peerReady ||
					!row.nonces.signing?.fundingTransaction ||
					this.finalExitRequested(id, row.nonces)
				)
					throw new Error('Funding is unavailable for cooperative close');
				const journal = this.finalJournal();
				const head = journal.read<IFinalSimpleCloseState>('simple-close', id);
				const previous = JSON.stringify(
					head.records[head.records.length - 1] ?? {}
				);
				const state = JSON.parse(previous) as IFinalSimpleCloseState;
				const view = this.loadFinalUpdateStatus(id);
				if (!view) throw new Error('Missing final channel commitment view');
				const active = this.loadFinalActiveFunding(id);
				if (!active)
					throw new Error('Ambiguous final funding during cooperative close');
				const result = driveFinalSimpleClose(
					id,
					active,
					row.nonces,
					authority.nonceContext(row.nonceKey),
					authority,
					root,
					this.walletIdentity!,
					state,
					view,
					request
				);
				if (JSON.stringify(state) !== previous)
					journal.append('simple-close', id, head, state);
				return result;
			})
			.immediate();
	}

	loadFinalLocalChannelReady(channelId: string): Buffer | null {
		const hex = this.finalOpeningRecord(channelId)?.nonces.localReady;
		return hex ? Buffer.from(hex, 'hex') : null;
	}

	loadFinalPeerChannelReady(channelId: string): Buffer | null {
		const hex = this.finalOpeningRecord(channelId)?.nonces.peerReady;
		return hex ? Buffer.from(hex, 'hex') : null;
	}

	/** Inspect the height-one promises once both ready messages are known. A funded
	 * reconnect supersedes ready in its direction even when the first ready arrives
	 * late. Its retransmission must never roll a signer back to the older promise.
	 */
	loadFinalCommitmentOneNonces(
		channelId: string
	): { local: Buffer; peer: Buffer } | null {
		const state = this.finalOpeningRecord(channelId)?.nonces;
		if (
			!state?.localReady ||
			!state.peerReady ||
			this.finalExitRequested(channelId, state)
		)
			return null;
		const promised = (ready: string, reconnect?: { nonce: string }): Buffer =>
			reconnect
				? Buffer.from(reconnect.nonce, 'hex')
				: decodeChannelReadyMessage(Buffer.from(ready, 'hex')).nextLocalNonce!;
		return {
			local: promised(state.localReady, state.localReconnect),
			peer: promised(state.peerReady, state.peerReconnect)
		};
	}

	/** Each funded reconnect advances a separate device-backed generation for commitment one. */
	renewFinalReestablishNonce(channelId: string, root: BIP32Interface): Buffer {
		return this.updateOpeningNonces(channelId, (state, _candidate, key) => {
			requireReadySession(state, true);
			if (this.finalExitRequested(channelId, state))
				throw new Error('Opening exit already requested');
			const authority = this.requireOpeningAuthority();
			const context = authority.nonceContext(key);
			const keys = readyKeys(root, state, this.walletIdentity!);
			state.localReconnect = authority.advanceReestablishNonce(
				'channel-reestablish/local/' + channelId,
				key.toString('hex'),
				state.localReconnect,
				(generation) => {
					const nonce = Buffer.from(
						readyVerificationNonce(context, keys.fundingPrivkey, generation)
					);
					verifyReadyNonce(state, nonce, true);
					return nonce;
				}
			);
			return Buffer.from(state.localReconnect.nonce, 'hex');
		});
	}

	rememberFinalPeerReestablishNonce(channelId: string, nonce: Buffer): void {
		this.updateOpeningNonces(channelId, (state, _candidate, key) => {
			requireReadySession(state, false);
			if (this.finalExitRequested(channelId, state))
				throw new Error('Opening exit already requested');
			verifyReadyNonce(state, nonce, false);
			const authority = this.requireOpeningAuthority();
			state.peerReconnect = authority.advanceReestablishNonce(
				'channel-reestablish/peer/' + channelId,
				key.toString('hex'),
				state.peerReconnect,
				() => nonce
			);
		});
	}

	loadFinalLocalReestablishNonce(channelId: string): Buffer | null {
		const r = this.finalOpeningRecord(channelId)?.nonces.localReconnect;
		return r ? Buffer.from(r.nonce, 'hex') : null;
	}

	loadFinalPeerReestablishNonce(channelId: string): Buffer | null {
		const r = this.finalOpeningRecord(channelId)?.nonces.peerReconnect;
		return r ? Buffer.from(r.nonce, 'hex') : null;
	}

	private finalExitRequested(
		channelId: string,
		state: IFinalOpeningNonces
	): boolean {
		if (state.signing?.exitRequested) return true;
		return !!this.openingAuthority?.exitRequest(channelId);
	}

	/** A retained immutable opening makes device-repaired update states usable even after a much earlier wallet-only rollback. */
	private reconcileFinalUpdateOpenings(): void {
		if (!this.canUpdateFinalCommitments) return;
		const ids = this.db
			.prepare('SELECT channel_id FROM final_opening_candidates')
			.all() as { channel_id: string }[];
		for (const { channel_id: id } of ids) {
			const record = this.finalOpeningRecord(id)!;
			const latest = currentFinalJournal(
				this.db,
				this.requireOpeningAuthority(),
				id,
				record.nonceKey
			);
			if (
				!latest ||
				(record.nonces.peerReady &&
					record.nonces.localReady &&
					record.nonces.signing?.fundingTransaction)
			)
				continue;
			const recovery = recoveryOpening(this.db, id, record.nonceKey);
			if (!recovery)
				throw new Error(
					'Device commitment log is missing the opening required for recovery'
				);
			this.updateOpeningNonces(id, (nonces) => {
				for (const [field, value] of Object.entries(recovery)) {
					if (field === 'signing')
						nonces.signing = { ...recovery.signing!, ...nonces.signing };
					else if (!(field in nonces))
						Object.assign(nonces, { [field]: value });
				}
			});
		}
	}

	/** Complete a device-first close after a crash and enroll wallet-only requests
	 * made by the preceding final wallet version before it can emit readiness.
	 */
	private reconcileFinalExitRequests(): void {
		const authority = this.openingAuthority;
		if (!authority) return;
		const pending: string[] = [];
		const ids = this.db
			.prepare('SELECT channel_id FROM final_opening_candidates')
			.all() as { channel_id: string }[];
		for (const { channel_id: id } of ids) {
			const record = this.finalOpeningRecord(id)!;
			const signing = record.nonces.signing;
			if (!signing?.exit || !signing.fundingLocal) continue;
			if (!signing.exitRequested && !authority.exitRequest(id)) {
				if (this.canUpdateFinalCommitments)
					currentFinalJournal(this.db, authority, id, record.nonceKey);
				continue;
			}
			const exit = this.selectedFinalExit(
				record,
				authority.chosenFundingExit(id)
			);
			if (signing.exitRequested) {
				if (!authority.exitRequest(id)) authority.recordExitRequest(id, exit);
			} else {
				const requested = authority.chosenFundingExit(id);
				if (requested) {
					if (requested !== sha256(Buffer.from(exit, 'hex')).toString('hex'))
						throw new Error(
							'Original exit request disagrees with its signed exit'
						);
					pending.push(id);
				}
			}
		}
		for (const id of pending) this.requestFinalOpeningExit(id);
	}

	/** Persist the operator's request before broadcasting the already signed exit. */
	requestFinalOpeningExit(
		channelId: string,
		fundingTxid?: Buffer,
		fundingOutputIndex?: number
	): Buffer {
		this.requireCurrentFinalDevice();
		return this.updateOpeningNonces(channelId, (state, candidate, nonceKey) => {
			const signing = state.signing;
			if (!state.session || !signing?.exit || !signing.fundingLocal)
				throw new Error('Opening has not released its funding witnesses');
			const exit = this.selectedFinalExit(
				{ candidate, nonces: state, nonceKey },
				this.openingAuthority?.chosenFundingExit(channelId),
				fundingTxid,
				fundingOutputIndex
			);
			if (!this.openingAuthority?.exitRequest(channelId))
				this.openingAuthority?.recordExitRequest(channelId, exit);
			if (
				(this.canUpdateFinalCommitments || this.canSpliceDualFundedAssets) &&
				fundingTxid
			)
				this.openingAuthority!.recordFundingExitChoice(
					channelId,
					sha256(Buffer.from(exit, 'hex')).toString('hex')
				);
			signing.exitRequested = true;
			return Buffer.from(exit, 'hex');
		});
	}

	private daemonOpening(
		record: IFinalOpeningRecord | null
	): IFinalDaemonOpening | null {
		if (!record?.nonces.session) return null;
		const { signing, session } = record.nonces;
		return {
			candidate: record.candidate,
			session,
			...(record.nonces.localReady &&
				record.nonces.peerReady && { readyExchanged: true }),
			...(signing?.fundingTransaction && {
				funding: Buffer.from(signing.fundingTransaction, 'hex')
			}),
			...(((!this.updateWallet && this.finalGeneration !== 4) ||
				this.canSignFinalOpening) &&
				signing?.exit &&
				this.finalExitRequested(record.candidate.channelId, record.nonces) && {
					exitToBroadcast: Buffer.from(
						this.selectedFinalExit(
							record,
							this.openingAuthority?.chosenFundingExit(
								record.candidate.channelId
							)
						),
						'hex'
					)
				})
		};
	}

	loadFinalDaemonOpening(channelId: string): IFinalDaemonOpening | null {
		return this.daemonOpening(this.finalOpeningRecord(channelId));
	}

	loadFinalDaemonOpenings(): IFinalDaemonOpening[] {
		const ids: string[] = [];
		this.readFinalOpenings((candidate) => ids.push(candidate.channelId));
		const results: IFinalDaemonOpening[] = [];
		// Selecting the enforceable exit may reconcile entries from the device journal.
		// Close the candidate iterator before opening its write transaction.
		for (const id of ids) {
			const opening = this.loadFinalDaemonOpening(id);
			if (opening) results.push(opening);
		}
		return results;
	}

	loadFinalOpeningTerms(channelId: string): IFinalOpeningTerms | null {
		return this.finalOpeningRecord(channelId)?.nonces.signing?.terms ?? null;
	}

	/** Return our exact opening tx_signatures only after the wallet release has committed. */
	finalOpeningTxSignatures(
		channelId: string,
		sign: FinalFundingWitnessSigner
	): Buffer {
		return this.updateOpeningNonces(channelId, (state, candidate, key) =>
			recordOpeningFunding(candidate, state, key, this.openingAuthority, {
				sign
			})
		);
	}

	assetOpeningPayout(id: string, parent: string, raw?: Buffer): Buffer | null {
		if (
			!this.canOpenDualFundedAssets ||
			!/^[0-9a-f]{64}$/.test(id) ||
			!/^[0-9a-f]{64}$/.test(parent)
		)
			throw new Error('Asset payout requires the original wallet');
		const auth = this.requireOpeningAuthority(),
			slot = 'asset-payout/' + id + '/' + parent;
		if (raw) {
			if (raw.length > 400_000)
				throw new Error('Asset payout exceeds standard weight');
			auth.commitLifecycleEntry(slot, raw.toString('hex'));
		}
		const retained = auth.lifecycleEntry(slot);
		return retained ? Buffer.from(retained, 'hex') : null;
	}

	prepareAssetOpeningWitnesses(channelId: string) {
		if (!this.canOpenDualFundedAssets || this.db.inTransaction)
			throw new Error(
				'Asset funding witnesses require the enrolled original device outside a transaction'
			);
		const record = this.finalOpeningRecord(channelId);
		if (!record) throw new Error('Unknown asset opening candidate');
		return prepareAssetWitnessRelease(
			record.candidate,
			record.nonces,
			record.nonceKey,
			this.requireOpeningAuthority()
		);
	}

	storeAssetOpeningWitnesses(channelId: string, witnesses: Buffer[][]): Buffer {
		if (!this.canOpenDualFundedAssets)
			throw new Error('Asset opening requires its enrolled original device');
		return this.updateOpeningNonces(channelId, (state, candidate, key) => {
			if (!state.session?.assetEvidence)
				throw new Error('Missing asset opening proof material');
			return recordOpeningFunding(
				candidate,
				state,
				key,
				this.openingAuthority,
				{ witnesses }
			);
		});
	}

	/** A peer can broadcast the funding transaction and disconnect before returning its tx_signatures. */
	rememberObservedAssetFunding(id: string, tx: Transaction): void {
		const record = this.finalOpeningRecord(id);
		if (
			!this.canOpenDualFundedAssets ||
			!record?.nonces.session?.assetEvidence ||
			!record.nonces.signing?.fundingLocal
		)
			throw new Error('Missing original asset funding authorization');
		const { candidate } = record;
		const unsigned = tx.clone();
		for (let i = 0; i < unsigned.ins.length; i++) unsigned.setWitness(i, []);
		if (unsigned.toHex() !== candidate.fundingTxHex)
			throw new Error(
				'Observed funding transaction differs from the asset opening'
			);
		const packet = (local: boolean) =>
			encodeTxSignaturesMessage({
				channelId: Buffer.from(id, 'hex'),
				txid: tx.getHash(),
				witnesses: tx.ins
					.filter((_input, i) => candidate.inputs[i].isLocal === local)
					.map((input) => input.witness)
			});
		if (packet(true).toString('hex') !== record.nonces.signing.fundingLocal)
			throw new Error(
				'Observed funding transaction differs from the released wallet witnesses'
			);
		this.rememberFinalPeerTxSignatures(id, packet(false));
	}

	/** A process cut can leave the original device ahead of the wallet's last SQLite commit. */
	private reconcileAssetOpeningWitnesses(): void {
		const authority = this.requireOpeningAuthority();
		const ids: string[] = [];
		this.readFinalOpenings((candidate, state) => {
			if (state.nonces.session?.assetEvidence) ids.push(candidate.channelId);
		});
		for (const id of ids) {
			const saved = this.finalOpeningRecord(id)!.nonces.signing;
			for (const field of ['fundingLocal', 'fundingPeer'] as const) {
				const raw = authority.fundingWitnessResult(id, field);
				if (saved?.[field]) {
					if (raw?.toString('hex') !== saved[field])
						throw new Error(
							'Asset funding witness differs from the original device'
						);
				} else if (raw) {
					if (field === 'fundingPeer')
						this.rememberFinalPeerTxSignatures(id, raw);
					else
						this.storeAssetOpeningWitnesses(
							id,
							decodeTxSignaturesMessage(raw, { taproot: true }).witnesses
						);
				}
			}
		}
	}

	rememberFinalPeerTxSignatures(channelId: string, payload: Buffer): void {
		this.updateOpeningNonces(channelId, (state, candidate, key) =>
			recordOpeningFunding(candidate, state, key, this.openingAuthority, {
				peer: payload
			})
		);
	}

	loadFinalLocalTxSignatures(channelId: string): Buffer | null {
		const value =
			this.finalOpeningRecord(channelId)?.nonces.signing?.fundingLocal;
		return value === undefined ? null : Buffer.from(value, 'hex');
	}

	loadFinalPeerTxSignatures(channelId: string): Buffer | null {
		const value =
			this.finalOpeningRecord(channelId)?.nonces.signing?.fundingPeer;
		return value === undefined ? null : Buffer.from(value, 'hex');
	}

	loadFinalFundingTransaction(channelId: string): Buffer | null {
		const value =
			this.finalOpeningRecord(channelId)?.nonces.signing?.fundingTransaction;
		return value === undefined ? null : Buffer.from(value, 'hex');
	}

	private updateOpeningNonces<T>(
		channelId: string,
		update: (
			nonces: IFinalOpeningNonces,
			candidate: IFinalOpeningCandidate,
			nonceKey: Buffer
		) => T
	): T {
		if (this.db.inTransaction)
			throw new Error('Opening nonces require a top-level commit');
		return this.db
			.transaction(() => {
				const record = this.finalOpeningRecord(channelId);
				if (!record) throw new Error('Unknown final opening candidate');
				const before = JSON.stringify(record.nonces);
				const result = update(record.nonces, record.candidate, record.nonceKey);
				const after = JSON.stringify(record.nonces);
				if (before !== after) {
					const written = this._stmt(
						'UPDATE final_opening_candidates SET nonces_json = ? WHERE channel_id = ?'
					).run(encryptValue(record.nonceKey, after), channelId);
					if (
						written.changes !== 1 ||
						JSON.stringify(this.finalOpeningRecord(channelId)?.nonces) !== after
					)
						throw new Error('Opening nonce reservation was not written');
				}
				return result;
			})
			.immediate();
	}

	// ─── Schema ───

	/**
	 * Current schema version. Increment when adding migrations, and commit a
	 * fixture of the schema before it (scripts/storage-fixture.ts).
	 */
	static readonly CURRENT_SCHEMA_VERSION = 21;

	/**
	 * The columns this class reads and writes, by table: a new database's,
	 * less channels.channel_index (migration 0->1), which nothing reads.
	 * open() refuses a database that lacks one after its migrations, so a
	 * migration that did not take fails there instead of in whichever
	 * statement first names the column. sqlite-schema-upgrade.test.ts keeps
	 * this list equal to what _createTables and the migrations build.
	 */
	private static readonly REQUIRED_COLUMNS: Readonly<
		Record<string, ReadonlyArray<string>>
	> = {
		action_log: ['id', 'category', 'action', 'timestamp', 'data'],
		announced_peer_addresses: [
			'pubkey',
			'announcement_timestamp',
			'addresses_json'
		],
		chain_monitors: ['channel_id', 'state_json'],
		channel_key_indices: ['channel_id', 'channel_index'],
		channel_policies: ['channel_id', 'policy_json'],
		channels: ['channel_id', 'state_json', 'peer_pubkey'],
		composite_splices: ['id', 'record_json'],
		encryption_scrub_pending: ['id'],
		ffor_vouchers: ['id', 'record_json'],
		forwarded_htlcs: ['out_key', 'in_channel_id', 'in_htlc_id'],
		forwarding_events: [
			'id',
			'settled_at',
			'in_channel_id',
			'out_channel_id',
			'in_scid',
			'out_scid',
			'amount_in_msat',
			'amount_out_msat',
			'fee_msat',
			'auxiliary_json'
		],
		gossip_channels: ['scid_hex', 'channel_json'],
		gossip_nodes: ['node_id_hex', 'node_json'],
		htlc_payment_map: ['htlc_key', 'payment_hash_hex'],
		htlc_shared_secrets: ['key', 'secret'],
		invoice_path_ids: ['payment_hash_hex', 'path_id'],
		invoices: ['payment_hash_hex', 'invoice_json'],
		metadata: ['key', 'value'],
		mission_control: ['id', 'data_json'],
		offers: ['offer_id', 'encoded', 'path_id', 'created_at', 'async_hold'],
		payment_queue: [
			'id',
			'bolt11',
			'priority',
			'status',
			'amount_sats',
			'max_fee_sats',
			'metadata',
			'error',
			'created_at',
			'completed_at'
		],
		payment_secrets: ['payment_hash_hex', 'secret'],
		payments: [
			'payment_hash',
			'payment_json',
			'created_at',
			'status',
			'direction',
			'metadata_tags'
		],
		peer_addresses: [
			'pubkey',
			'host',
			'port',
			'last_connected',
			'transport_json'
		],
		peer_storage_blobs: ['peer_pubkey', 'blob', 'received_at'],
		preimages: ['payment_hash', 'preimage'],
		recovery_frames: [
			'sequence',
			'writer_epoch',
			'frame_hash',
			'previous_hash',
			'ciphertext',
			'created_at'
		],
		recovery_meta: ['key', 'value'],
		recovery_outbox: [
			'id',
			'peer_pubkey',
			'channel_id',
			'message_type',
			'wire_message',
			'disposition',
			'frame_sequence',
			'created_at'
		],
		revoked_htlc_snapshots: ['channel_id', 'commitment_number', 'htlcs_json'],
		auxiliary_revoked_commitments: [
			'channel_id',
			'commitment_number',
			'view_json'
		],
		schema_version: ['version'],
		scid_mappings: ['scid_hex', 'channel_id'],
		wallet_data: ['key', 'value'],
		watchtower_sessions: [
			'session_id',
			'tower_uri',
			'tower_pubkey',
			'session_key',
			'blob_type',
			'max_updates',
			'sweep_fee_rate',
			'seq_num',
			'last_applied',
			'created_at',
			'dials_with_session_key'
		],
		watchtower_updates: [
			'id',
			'tower_uri',
			'channel_id',
			'hint',
			'encrypted_blob',
			'seq_num',
			'acked',
			'created_at',
			'blob_type'
		],
		webhooks: ['id', 'url', 'events', 'secret_hash', 'created_at']
	};

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
		{ table: 'revoked_htlc_snapshots', pk: 'rowid', columns: ['htlcs_json'] },
		{
			table: 'auxiliary_revoked_commitments',
			pk: 'rowid',
			columns: ['view_json']
		},
		{ table: 'payments', pk: 'payment_hash', columns: ['payment_json'] },
		{ table: 'ffor_vouchers', pk: 'id', columns: ['record_json'] },
		{ table: 'composite_splices', pk: 'id', columns: ['record_json'] },
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
		// Retained outbound wire bytes (recovery outbox): signed commitment
		// material that reveals channel activity and balances to anyone reading
		// the database file.
		{ table: 'recovery_outbox', pk: 'id', columns: ['wire_message'] },
		// On-chain wallet state (addresses, UTXOs, transactions, balance) is
		// privacy-sensitive: a stolen DB file must not reveal the wallet's
		// holdings or address set.
		{ table: 'wallet_data', pk: 'key', columns: ['value'] },
		// A BOLT 12 offer is made to be shared, but the set of offers a node
		// issued is still its payment identity, and path_id is the secret that
		// authenticates invoice_requests arriving over the offer's blinded
		// paths (null for offers without one; null columns are skipped by the
		// encryption rollout).
		{ table: 'offers', pk: 'offer_id', columns: ['encoded', 'path_id'] },
		// The expected path_id of an issued BOLT 12 invoice is the secret that
		// authenticates the incoming payment (the BOLT 12 analogue of a
		// payment secret), so it gets the same at-rest protection.
		{
			table: 'invoice_path_ids',
			pk: 'payment_hash_hex',
			columns: ['path_id']
		},
		// Recovery journal metadata, which from Phase 5 on holds the WRITER
		// LEASE: the private half of the ephemeral writer key that signs
		// guardian records. That is signing material and must never sit in
		// plaintext in a stolen database file.
		{ table: 'recovery_meta', pk: 'key', columns: ['value'] },
		// Node metadata: the swap, held-forward, FFOR witness and issuer
		// ledgers, JIT receive intents and held HTLCs. No keys, but swap
		// amounts, payment hashes and peer identities.
		{ table: 'metadata', pk: 'key', columns: ['value'] }
	];

	/**
	 * Rewrite any plaintext rows in the sensitive tables as encrypted values,
	 * in a single transaction. Idempotent: rows already carrying the 'enc1:'
	 * prefix are skipped, so reopening an already-encrypted database is a no-op.
	 * Rewriting any row marks a scrub pending (see _scrubMigratedPlaintext).
	 *
	 * Every open with a key runs this, so SQL picks the candidates: a row comes
	 * back only when one of its columns is not NULL and does not start with
	 * the prefix. An encrypted database then selects nothing, rather than
	 * reading every sensitive value into JS to skip it. The filter keeps every
	 * row the per-column check below would rewrite: substr() reads an INTEGER
	 * or REAL as its text, which never starts with the prefix, and a BLOB as
	 * bytes, which never equal TEXT, so such rows still come back, and that
	 * check still decides.
	 */
	private _encryptExistingData(): void {
		const key = this.encryptionKey;
		if (!key) return;
		this.db.transaction(() => {
			let rewritten = false;
			for (const { table, pk, columns } of SqliteStorage.ENCRYPTED_COLUMNS) {
				const plaintext = columns.map(
					(col) => `(${col} IS NOT NULL AND substr(${col}, 1, ?) IS NOT ?)`
				);
				const rows = this.db
					.prepare(
						`SELECT ${pk}, ${columns.join(', ')} FROM ${table} ` +
							`WHERE ${plaintext.join(' OR ')}`
					)
					.all(
						...columns.flatMap(() => [ENC_PREFIX.length, ENC_PREFIX])
					) as Array<Record<string, unknown>>;
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
					rewritten = true;
				}
			}
			// Committed with the rewrite, so a crash before the scrub still
			// leaves it pending for the next open.
			if (rewritten) {
				this.db.exec(
					'INSERT OR IGNORE INTO encryption_scrub_pending (id) VALUES (1)'
				);
			}
		})();
	}

	/**
	 * Remove the plaintext an encryption pass replaced, if a scrub is pending.
	 * UPDATE leaves the old plaintext in freed pages. secure_delete would
	 * clear only what the pass frees, not free pages left by earlier
	 * plaintext writes, so VACUUM rebuilds the file. The checkpoint then
	 * copies it from the WAL over the old pages and empties the WAL. A full
	 * disk can fail the VACUUM and a reader on another connection can hold
	 * the checkpoint back. Neither should stop the open, so the marker stays
	 * and the next open tries again.
	 */
	private _scrubMigratedPlaintext(): void {
		const pending = this.db
			.prepare('SELECT 1 FROM encryption_scrub_pending')
			.get();
		if (!pending) return;
		try {
			this.db.exec('VACUUM');
		} catch {
			return;
		}
		const [{ busy }] = this.db.pragma('wal_checkpoint(TRUNCATE)') as Array<{
			busy: number;
		}>;
		if (busy === 0) this.db.exec('DELETE FROM encryption_scrub_pending');
	}

	/**
	 * Set a payment row's lookup columns where they are missing: every row
	 * from before schema 16 or 17, and any an older release wrote since.
	 * With a key, a plaintext row is filled again as well: it was written
	 * without the key, so its metadata tags are under the fixed one, and the
	 * encryption pass after this rewrites it, so that happens once. A row
	 * that cannot be decoded keeps NULL, which leaves it out of
	 * paymentsNewestFirst as the loadAll* readers skip it, and is tried
	 * again on the next open.
	 */
	private _fillPaymentLookupColumns(): void {
		const stale = ['created_at IS NULL', 'status IS NULL'];
		const params: unknown[] = [];
		if (this.encryptionKey) {
			stale.push('substr(payment_json, 1, ?) IS NOT ?');
			params.push(ENC_PREFIX.length, ENC_PREFIX);
		}
		const rows = this.db
			.prepare(
				'SELECT payment_hash, payment_json FROM payments ' +
					`WHERE ${stale.join(' OR ')}`
			)
			.all(...params) as Array<{ payment_hash: string; payment_json: string }>;
		if (rows.length === 0) return;
		const update = this.db.prepare(
			'UPDATE payments SET created_at = ?, status = ?, direction = ?, ' +
				'metadata_tags = ? WHERE payment_hash = ?'
		);
		this.db.transaction(() => {
			for (const row of rows) {
				let payment: IPaymentInfo;
				try {
					payment = deserializePaymentInfo(
						JSON.parse(this._dec(row.payment_json))
					);
				} catch (err) {
					// Without the key no other row decodes either.
					if (err instanceof StorageEncryptedError) return;
					continue;
				}
				// A row whose timestamp is not a number is left as one that
				// cannot be decoded; binding it would throw out of open().
				const createdAt: unknown = payment.createdAt;
				if (typeof createdAt !== 'number' || !Number.isFinite(createdAt)) {
					continue;
				}
				update.run(...this._paymentLookupColumns(payment), row.payment_hash);
			}
		})();
	}

	/**
	 * The plaintext columns a payment row is found by: created_at, status,
	 * direction and metadata_tags. A status or direction that is not text
	 * (only a damaged row holds one) is stored as NULL, as binding it would
	 * throw.
	 */
	private _paymentLookupColumns(
		payment: IPaymentInfo
	): [number, string | null, string | null, string | null] {
		const text = (value: unknown): string | null =>
			typeof value === 'string' ? value : null;
		return [
			payment.createdAt,
			text(payment.status),
			text(payment.direction),
			this._metadataTags(payment.metadata)
		];
	}

	/**
	 * A tag for each metadata key, and for each key with its value, space
	 * separated. Tags are keyed HMACs, so a stolen file shows which payments
	 * share a label but not what the label says.
	 */
	private _metadataTags(metadata: unknown): string | null {
		if (!metadata || typeof metadata !== 'object') return null;
		const tags: string[] = [];
		for (const [key, value] of Object.entries(metadata)) {
			tags.push(this._metadataTag(key));
			if (typeof value === 'string') tags.push(this._metadataTag(key, value));
		}
		return tags.length > 0 ? tags.join(' ') : null;
	}

	private _metadataTag(key: string, value?: string): string {
		return hmacSha256(
			this.metadataTagKey,
			Buffer.from(JSON.stringify(value === undefined ? [key] : [key, value]))
		)
			.toString('hex')
			.slice(0, METADATA_TAG_HEX);
	}

	private _createTables(): void {
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS channels (
				channel_id TEXT PRIMARY KEY,
				state_json TEXT NOT NULL,
				peer_pubkey TEXT NOT NULL
			);

			-- The HTLCs of each remote commitment a channel signed, which a
			-- penalty needs once they leave the live state. Kept out of the
			-- channel row, so a save writes only the commitments it adds.
			CREATE TABLE IF NOT EXISTS revoked_htlc_snapshots (
				channel_id TEXT NOT NULL,
				commitment_number TEXT NOT NULL,
				htlcs_json TEXT NOT NULL,
				PRIMARY KEY (channel_id, commitment_number)
			);

			-- The asset side of each revoked commitment of the peer on an asset
			-- channel (issue #2093), which a penalty needs. Empty on a node
			-- without asset channels.
			CREATE TABLE IF NOT EXISTS auxiliary_revoked_commitments (
				channel_id TEXT NOT NULL,
				commitment_number TEXT NOT NULL,
				view_json TEXT NOT NULL,
				PRIMARY KEY (channel_id, commitment_number)
			);

			CREATE TABLE IF NOT EXISTS ffor_vouchers (
				id TEXT PRIMARY KEY,
				record_json TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS composite_splices (
				id TEXT PRIMARY KEY,
				record_json TEXT NOT NULL
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

			CREATE TABLE IF NOT EXISTS announced_peer_addresses (
				pubkey TEXT PRIMARY KEY,
				announcement_timestamp INTEGER NOT NULL,
				addresses_json TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS channel_key_indices (
				channel_id TEXT PRIMARY KEY,
				channel_index INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS schema_version (
				version INTEGER PRIMARY KEY
			);

			CREATE TABLE IF NOT EXISTS offers (
				offer_id TEXT PRIMARY KEY,
				encoded TEXT NOT NULL,
				path_id TEXT,
				created_at INTEGER NOT NULL,
				async_hold INTEGER NOT NULL DEFAULT 0
			);

			CREATE TABLE IF NOT EXISTS invoice_path_ids (
				payment_hash_hex TEXT PRIMARY KEY,
				path_id TEXT NOT NULL
			);

			CREATE TABLE IF NOT EXISTS recovery_outbox (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				peer_pubkey TEXT NOT NULL,
				channel_id TEXT,
				message_type INTEGER NOT NULL,
				wire_message TEXT NOT NULL,
				disposition TEXT NOT NULL,
				frame_sequence INTEGER,
				created_at INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_recovery_outbox_channel
				ON recovery_outbox(channel_id, id);

			CREATE TABLE IF NOT EXISTS recovery_frames (
				sequence INTEGER PRIMARY KEY,
				writer_epoch INTEGER NOT NULL,
				frame_hash BLOB NOT NULL,
				previous_hash BLOB NOT NULL,
				ciphertext BLOB NOT NULL,
				created_at INTEGER NOT NULL
			);
			-- Frames are APPEND-ONLY at the storage layer: nothing in the
			-- protocol ever rewrites a stored frame (compaction deletes below
			-- the base, appends insert), so an UPDATE is always tampering or
			-- corruption and is refused where it happens instead of surfacing
			-- as an unverifiable chain later.
			CREATE TRIGGER IF NOT EXISTS recovery_frames_append_only
				BEFORE UPDATE ON recovery_frames
			BEGIN
				SELECT RAISE(ABORT, 'recovery_frames is append-only');
			END;

			CREATE TABLE IF NOT EXISTS recovery_meta (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
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
			-- A start reads the active rows and the newest finished ones,
			-- however long the history (issue #1866).
			CREATE INDEX IF NOT EXISTS idx_payment_queue_status ON payment_queue(status);
			CREATE INDEX IF NOT EXISTS idx_payment_queue_finished
				ON payment_queue(COALESCE(completed_at, created_at), id);

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
				fee_msat TEXT NOT NULL,
				auxiliary_json TEXT
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

			-- One row while freed pages or the WAL may still hold plaintext
			-- the encryption pass replaced (see _scrubMigratedPlaintext).
			CREATE TABLE IF NOT EXISTS encryption_scrub_pending (
				id INTEGER PRIMARY KEY
			);
		`);

		// Run migrations
		this._runMigrations();
		this._checkRequiredColumns();
	}

	/**
	 * CREATE TABLE IF NOT EXISTS never adds a column to a table an older
	 * release created, so a column only a migration adds is missing for good
	 * once that migration is recorded without it.
	 */
	private _checkRequiredColumns(): void {
		const missing: string[] = [];
		for (const [table, required] of Object.entries(
			SqliteStorage.REQUIRED_COLUMNS
		)) {
			const present = columnNames(this.db, table);
			for (const column of required) {
				const expected =
					table === 'channels' && column === 'state_json'
						? this.channelStateColumn
						: column;
				if (!present.has(expected)) missing.push(`${table}.${expected}`);
			}
		}
		if (missing.length > 0) {
			throw new Error(
				`SQLite database at schema version ${this.getSchemaVersion()} ` +
					`is missing ${missing.join(', ')}; refusing to open it`
			);
		}
	}

	// ─── Channels ───

	saveChannel(id: string, state: IChannelState, peerPubkey: string): void {
		const json = JSON.stringify(
			channelRowToStore(serializeChannelState(state, { htlcHistory: 'none' }))
		);
		const history = unsavedRevokedHtlcSnapshots(state, this);
		const revokedViews = auxiliaryRevokedViewsToStore(state);
		// The size of the store of revoked views, where a host has asked for
		// it, is kept current by what this write adds. A write inside a
		// transaction of the caller may yet be rolled back, so there the
		// size is let go and counted again when it is next asked for.
		let sized = revokedViews ? this._auxiliaryRevokedSizes.get(id) : undefined;
		if (sized && this.db.inTransaction) {
			this._auxiliaryRevokedSizes.delete(id);
			sized = undefined;
		}
		let addedRows = 0;
		let addedBytes = 0;
		this.db.transaction(() => {
			if (this.walletIdentity) this.assertNoFinalOpeningConflict(id, state);
			this._stmt(
				`INSERT OR REPLACE INTO channels (channel_id, ${this.channelStateColumn}, peer_pubkey) VALUES (?, ?, ?)`
			).run(id, this._enc(json), peerPubkey);
			if (revokedViews) {
				const keep = this._stmt(
					'INSERT OR REPLACE INTO auxiliary_revoked_commitments ' +
						'(channel_id, commitment_number, view_json) VALUES (?, ?, ?)'
				);
				const present = this._stmt(
					'SELECT LENGTH(CAST(view_json AS BLOB)) AS bytes ' +
						'FROM auxiliary_revoked_commitments ' +
						'WHERE channel_id = ? AND commitment_number = ?'
				);
				for (const [commitmentNumber, view] of revokedViews) {
					const value = this._enc(serializeAuxiliaryCommitmentView(view));
					if (sized) {
						const replaced = present.get(id, commitmentNumber.toString()) as
							| { bytes: number }
							| undefined;
						addedRows += replaced ? 0 : 1;
						addedBytes += Buffer.byteLength(value) - (replaced?.bytes ?? 0);
					}
					keep.run(id, commitmentNumber.toString(), value);
				}
			}
			if (!history?.size) return;
			const insert = this._stmt(
				'INSERT OR REPLACE INTO revoked_htlc_snapshots ' +
					'(channel_id, commitment_number, htlcs_json) VALUES (?, ?, ?)'
			);
			for (const [commitmentNumber, entries] of history) {
				if (entries.length === 0) continue;
				insert.run(
					id,
					commitmentNumber,
					this._enc(JSON.stringify(serializeHtlcSnapshotEntries(entries)))
				);
			}
		})();
		if (sized) {
			sized.rows += addedRows;
			sized.bytes += addedBytes;
		}
	}

	/** The size of the store of revoked views of each channel a host asked about. */
	private _auxiliaryRevokedSizes = new Map<
		string,
		{ rows: number; bytes: number }
	>();

	/**
	 * The rows and the bytes of the store of revoked views of one channel.
	 * The table is counted the first time a channel is asked about; from
	 * then on each write of a view keeps the answer current, so asking
	 * costs nothing however large the store has grown.
	 */
	auxiliaryRevokedCommitmentsSize(channelId: string): {
		rows: number;
		bytes: number;
	} {
		let size = this._auxiliaryRevokedSizes.get(channelId);
		if (!size) {
			const counted = this._stmt(
				'SELECT COUNT(*) AS n, ' +
					'COALESCE(SUM(LENGTH(CAST(view_json AS BLOB))), 0) AS bytes ' +
					'FROM auxiliary_revoked_commitments WHERE channel_id = ?'
			).get(channelId) as { n: number; bytes: number };
			size = { rows: counted.n, bytes: counted.bytes };
			// What is counted inside a transaction may yet be rolled back.
			if (!this.db.inTransaction) {
				this._auxiliaryRevokedSizes.set(channelId, size);
			}
		}
		return { rows: size.rows, bytes: size.bytes };
	}

	loadAuxiliaryRevokedCommitment(
		channelId: string,
		commitmentNumber: bigint
	): IAuxiliaryCommitmentData | null {
		const row = this._stmt(
			'SELECT view_json FROM auxiliary_revoked_commitments ' +
				'WHERE channel_id = ? AND commitment_number = ?'
		).get(channelId, commitmentNumber.toString()) as
			| { view_json: string }
			| undefined;
		return row
			? deserializeAuxiliaryCommitmentView(this._dec(row.view_json))
			: null;
	}

	revokedHtlcSnapshotStore(): object {
		// Through a wrapper such as the CLI's node storage view this still
		// returns the instance, which is what saveChannel marks against.
		return this;
	}

	private _decodeChannelJson(value: string): unknown {
		const text = this.walletIdentity
			? decryptValue(this.encryptionKey!, value)
			: this._dec(value);
		return JSON.parse(text);
	}

	loadChannel(id: string): { state: IChannelState; peerPubkey: string } | null {
		const row = this._stmt(
			`SELECT ${this.channelStateColumn} AS state_json, peer_pubkey FROM channels WHERE channel_id = ?`
		).get(id) as { state_json: string; peer_pubkey: string } | undefined;
		if (!row) return null;
		const state = deserializeChannelState(
			channelRowFromStore(this._decodeChannelJson(row.state_json))
		);
		const history = this._readRevokedHtlcSnapshots(
			this._stmt(
				'SELECT channel_id, commitment_number, htlcs_json ' +
					'FROM revoked_htlc_snapshots WHERE channel_id = ? ' +
					'ORDER BY length(commitment_number), commitment_number'
			).all(id) as IRevokedHtlcSnapshotRow[]
		);
		this._attachRevokedHtlcSnapshots(state, history.get(id));
		return { state, peerPubkey: row.peer_pubkey };
	}

	loadAllChannels(): Array<{
		channelId: string;
		state: IChannelState;
		peerPubkey: string;
	}> {
		const rows = this._stmt(
			`SELECT channel_id, ${this.channelStateColumn} AS state_json, peer_pubkey FROM channels`
		).all() as Array<{
			channel_id: string;
			state_json: string;
			peer_pubkey: string;
		}>;
		const history = this._readRevokedHtlcSnapshots(
			this._stmt(
				'SELECT channel_id, commitment_number, htlcs_json ' +
					'FROM revoked_htlc_snapshots ' +
					'ORDER BY channel_id, length(commitment_number), commitment_number'
			).all() as IRevokedHtlcSnapshotRow[]
		);
		const results: Array<{
			channelId: string;
			state: IChannelState;
			peerPubkey: string;
		}> = [];
		const unreadableAssetChannels: string[] = [];
		for (const row of rows) {
			let parsed: unknown;
			try {
				parsed = this._decodeChannelJson(row.state_json);
				const state = deserializeChannelState(channelRowFromStore(parsed));
				if (this.walletIdentity)
					this.assertNoFinalOpeningConflict(row.channel_id, state);
				this._attachRevokedHtlcSnapshots(state, history.get(row.channel_id));
				results.push({
					channelId: row.channel_id,
					state,
					peerPubkey: row.peer_pubkey
				});
			} catch (err) {
				if (
					this.walletIdentity ||
					err instanceof UnsupportedCommitmentProfileError
				)
					throw err;
				// An asset channel row that parses but does not decode is
				// remembered by id before it is skipped: startup refuses to
				// run without it (see unreadableAssetChannelIds).
				if (serializedChannelCarriesAssetState(parsed)) {
					unreadableAssetChannels.push(row.channel_id);
				}
				// Skip corrupted row — node still starts with remaining data
				this.reportCorruptRow(err);
			}
		}
		this.unreadableAssetChannels = unreadableAssetChannels;
		return results;
	}

	/**
	 * Decode snapshot rows, grouped by channel. A row that does not decode is
	 * skipped and counted, as a channel row is, so recovery-critical readers
	 * refuse rather than carry a history with a hole in it.
	 */
	private _readRevokedHtlcSnapshots(
		rows: IRevokedHtlcSnapshotRow[]
	): Map<string, Map<string, IHtlcSnapshotEntry[]>> {
		const byChannel = new Map<string, Map<string, IHtlcSnapshotEntry[]>>();
		for (const row of rows) {
			let entries: IHtlcSnapshotEntry[];
			try {
				entries = deserializeHtlcSnapshotEntries(
					JSON.parse(this._dec(row.htlcs_json))
				);
			} catch (err) {
				this.reportCorruptRow(err);
				continue;
			}
			let history = byChannel.get(row.channel_id);
			if (!history) {
				history = new Map();
				byChannel.set(row.channel_id, history);
			}
			history.set(row.commitment_number, entries);
		}
		return byChannel;
	}

	/**
	 * Give a loaded channel its stored snapshots. A row the 18->19 migration
	 * could not read still carries its own, which attaching keeps.
	 */
	private _attachRevokedHtlcSnapshots(
		state: IChannelState,
		stored: Map<string, IHtlcSnapshotEntry[]> | undefined
	): void {
		attachStoredRevokedHtlcSnapshots(
			state,
			stored,
			this,
			!this.db.inTransaction
		);
	}

	deleteChannel(id: string): void {
		if (
			this.walletIdentity &&
			this._stmt(
				'SELECT 1 FROM final_opening_candidates WHERE channel_id = ?'
			).get(id)
		)
			throw new Error('Channel belongs to a reserved final opening');
		// Drop the channel's retained outbound bytes and HTLC snapshots with
		// it: retransmission and penalties both need the channel row too.
		this.db.transaction(() => {
			this._stmt('DELETE FROM channels WHERE channel_id = ?').run(id);
			this._stmt('DELETE FROM revoked_htlc_snapshots WHERE channel_id = ?').run(
				id
			);
			this._stmt(
				'DELETE FROM auxiliary_revoked_commitments WHERE channel_id = ?'
			).run(id);
			this._stmt('DELETE FROM recovery_outbox WHERE channel_id = ?').run(id);
		})();
		this._auxiliaryRevokedSizes.delete(id);
	}

	// ─── Composite splice records (issue #1922) ───

	saveCompositeSplice(record: ICompositeSpliceRecord): void {
		const valid = validateCompositeSpliceRecord(record);
		this._stmt(
			'INSERT OR REPLACE INTO composite_splices (id, record_json) VALUES (?, ?)'
		).run(valid.id, this._enc(JSON.stringify(valid)));
	}

	loadCompositeSplice(id: string): ICompositeSpliceRecord | null {
		const row = this._stmt(
			'SELECT record_json FROM composite_splices WHERE id = ?'
		).get(id) as { record_json: string } | undefined;
		if (!row) return null;
		const record = validateCompositeSpliceRecord(
			JSON.parse(this._dec(row.record_json))
		);
		if (record.id !== id) throw new Error('Composite splice row key mismatch');
		return record;
	}

	loadAllCompositeSplices(): ICompositeSpliceRecord[] {
		const rows = this._stmt(
			'SELECT id, record_json FROM composite_splices ORDER BY id'
		).all() as { id: string; record_json: string }[];
		return rows.map((row) => {
			const record = validateCompositeSpliceRecord(
				JSON.parse(this._dec(row.record_json))
			);
			if (record.id !== row.id)
				throw new Error('Composite splice row key mismatch');
			return record;
		});
	}

	deleteCompositeSplice(id: string): void {
		this._stmt('DELETE FROM composite_splices WHERE id = ?').run(id);
	}

	saveFforVoucher(record: IFforVoucherArchive): void {
		const id = fforVoucherArchiveId(record);
		const merged = mergeFforVoucherArchive(this.loadFforVoucher(id), record);
		this._stmt(
			'INSERT OR REPLACE INTO ffor_vouchers (id, record_json) VALUES (?, ?)'
		).run(id, this._enc(JSON.stringify(merged)));
	}

	loadFforVoucher(id: string): IFforVoucherArchive | null {
		const row = this._stmt(
			'SELECT record_json FROM ffor_vouchers WHERE id = ?'
		).get(id) as { record_json: string } | undefined;
		if (!row) return null;
		const record = validateFforVoucherArchive(
			JSON.parse(this._dec(row.record_json))
		);
		if (fforVoucherArchiveId(record) !== id)
			throw new Error('FFOR archive row key mismatch');
		return record;
	}

	loadAllFforVouchers(): IFforVoucherArchive[] {
		const rows = this._stmt(
			'SELECT id, record_json FROM ffor_vouchers ORDER BY id'
		).all() as { id: string; record_json: string }[];
		return rows.map((row) => {
			const record = validateFforVoucherArchive(
				JSON.parse(this._dec(row.record_json))
			);
			if (fforVoucherArchiveId(record) !== row.id)
				throw new Error('FFOR archive row key mismatch');
			return record;
		});
	}

	// ─── Payments ───

	savePayment(paymentHash: string, payment: IPaymentInfo): void {
		const serialized = serializePaymentInfo(payment);
		const json = JSON.stringify(serialized);
		this._stmt(
			'INSERT OR REPLACE INTO payments (payment_hash, payment_json, ' +
				'created_at, status, direction, metadata_tags) ' +
				'VALUES (?, ?, ?, ?, ?, ?)'
		).run(paymentHash, this._enc(json), ...this._paymentLookupColumns(payment));
	}

	loadPayment(paymentHash: string): IPaymentInfo | null {
		const row = this._stmt(
			'SELECT payment_json FROM payments WHERE payment_hash = ?'
		).get(paymentHash) as { payment_json: string } | undefined;
		if (!row) return null;
		return deserializePaymentInfo(JSON.parse(this._dec(row.payment_json)));
	}

	loadAllPayments(): Array<{ paymentHash: string; payment: IPaymentInfo }> {
		const results: Array<{ paymentHash: string; payment: IPaymentInfo }> = [];
		for (const row of this._rowsInBatches<{
			payment_hash: string;
			payment_json: string;
		}>('payments', 'payment_hash, payment_json')) {
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

	/**
	 * Every payment row, newest first by created_at then payment_hash, read
	 * from the index a batch of keys at a time. Nothing is decrypted until a
	 * ref's load() is called, so a reader that stops at a page, or skips
	 * rows to reach it, pays only for the rows it loads (issue #1403). A
	 * match is tested on the lookup columns during the same walk, so rows it
	 * leaves out are not decrypted either (issue #1459). A row that cannot be
	 * decoded loads as null and is reported as the loadAll* readers report
	 * one.
	 */
	*paymentsNewestFirst(
		since?: number,
		match: IPaymentRowMatch = {}
	): Generator<IStoredPaymentRef> {
		const load = (paymentHash: string): IPaymentInfo | null => {
			const row = this._stmt(
				'SELECT payment_json FROM payments WHERE payment_hash = ?'
			).get(paymentHash) as { payment_json: string } | undefined;
			if (!row) return null;
			try {
				return deserializePaymentInfo(JSON.parse(this._dec(row.payment_json)));
			} catch (err) {
				this.reportCorruptRow(err);
				return null;
			}
		};
		const matching = ['created_at IS NOT NULL'];
		const matchParams: unknown[] = [];
		if (since !== undefined) {
			matching.push('created_at >= ?');
			matchParams.push(since);
		}
		if (match.status !== undefined) {
			matching.push('status = ?');
			matchParams.push(match.status);
		}
		if (match.direction !== undefined) {
			matching.push('direction = ?');
			matchParams.push(match.direction);
		}
		if (match.metadata) {
			// Tags are fixed-length hex between spaces, so a substring the
			// length of one tag can only be a whole tag.
			matching.push('instr(metadata_tags, ?) > 0');
			matchParams.push(
				this._metadataTag(match.metadata.key, match.metadata.value)
			);
		}
		let after: [number, string] | undefined;
		for (;;) {
			const where = [...matching];
			const params = [...matchParams];
			if (after) {
				where.push('(created_at, payment_hash) < (?, ?)');
				params.push(...after);
			}
			const rows = this.db
				.prepare(
					'SELECT payment_hash, created_at FROM payments ' +
						`WHERE ${where.join(' AND ')} ` +
						'ORDER BY created_at DESC, payment_hash DESC LIMIT ?'
				)
				.all(...params, PAYMENT_KEY_BATCH) as Array<{
				payment_hash: string;
				created_at: number;
			}>;
			for (const row of rows) {
				yield {
					paymentHash: row.payment_hash,
					createdAt: row.created_at,
					load: (): IPaymentInfo | null => load(row.payment_hash)
				};
			}
			if (rows.length < PAYMENT_KEY_BATCH) return;
			const last = rows[rows.length - 1];
			after = [last.created_at, last.payment_hash];
		}
	}

	/**
	 * The hashes of the payment rows with this status and direction, read
	 * from the lookup columns alone, so no row is decrypted (issue #1675).
	 * A row that cannot be decoded holds NULL there and is left out, as the
	 * loadAll* readers skip it.
	 */
	paymentHashesWith(match: { status: string; direction: string }): Set<string> {
		const hashes = this._stmt(
			'SELECT payment_hash FROM payments WHERE status = ? AND direction = ?'
		)
			.pluck()
			.all(match.status, match.direction) as string[];
		return new Set(hashes);
	}

	deletePayment(paymentHash: string): void {
		this._stmt('DELETE FROM payments WHERE payment_hash = ?').run(paymentHash);
	}

	// ─── Preimages ───

	savePreimage(paymentHash: string, preimage: Buffer): void {
		this._stmt(
			'INSERT OR REPLACE INTO preimages (payment_hash, preimage) VALUES (?, ?)'
		).run(paymentHash, this._enc(preimage.toString('hex')));
	}

	loadPreimage(paymentHash: string): Buffer | null {
		const row = this._stmt(
			'SELECT preimage FROM preimages WHERE payment_hash = ?'
		).get(paymentHash) as { preimage: string } | undefined;
		if (!row) return null;
		return Buffer.from(this._dec(row.preimage), 'hex');
	}

	loadAllPreimages(): Array<{ paymentHash: string; preimage: Buffer }> {
		const results: Array<{ paymentHash: string; preimage: Buffer }> = [];
		for (const row of this._rowsInBatches<{
			payment_hash: string;
			preimage: string;
		}>('preimages', 'payment_hash, preimage')) {
			try {
				results.push({
					paymentHash: row.payment_hash,
					preimage: this._hexColumn(
						this._dec(row.preimage),
						`preimage row ${row.payment_hash}`
					)
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deletePreimage(paymentHash: string): void {
		this._stmt('DELETE FROM preimages WHERE payment_hash = ?').run(paymentHash);
	}

	// ─── SCID Mappings ───

	saveScidMapping(scidHex: string, channelId: Buffer): void {
		this._stmt(
			'INSERT OR REPLACE INTO scid_mappings (scid_hex, channel_id) VALUES (?, ?)'
		).run(scidHex, channelId.toString('hex'));
	}

	loadAllScidMappings(): Array<{ scidHex: string; channelId: Buffer }> {
		const rows = this._stmt(
			'SELECT scid_hex, channel_id FROM scid_mappings'
		).all() as Array<{ scid_hex: string; channel_id: string }>;
		const results: Array<{ scidHex: string; channelId: Buffer }> = [];
		for (const row of rows) {
			try {
				results.push({
					scidHex: row.scid_hex,
					channelId: this._hexColumn(
						row.channel_id,
						`scid mapping row ${row.scid_hex}`
					)
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
		this._stmt(
			'INSERT OR REPLACE INTO htlc_payment_map (htlc_key, payment_hash_hex) VALUES (?, ?)'
		).run(key, this._enc(paymentHashHex));
	}

	loadAllHtlcPaymentMappings(): Array<{ key: string; paymentHashHex: string }> {
		const results: Array<{ key: string; paymentHashHex: string }> = [];
		for (const row of this._rowsInBatches<{
			htlc_key: string;
			payment_hash_hex: string;
		}>('htlc_payment_map', 'htlc_key, payment_hash_hex')) {
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
		this._stmt('DELETE FROM htlc_payment_map WHERE htlc_key = ?').run(key);
	}

	// ─── Forwarded HTLCs ───

	saveForwardedHtlc(
		outKey: string,
		inChannelId: Buffer,
		inHtlcId: bigint
	): void {
		this._stmt(
			'INSERT OR REPLACE INTO forwarded_htlcs (out_key, in_channel_id, in_htlc_id) VALUES (?, ?, ?)'
		).run(
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
		const rows = this._stmt(
			'SELECT out_key, in_channel_id, in_htlc_id FROM forwarded_htlcs'
		).all() as Array<{
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
					inChannelId: this._hexColumn(
						this._dec(row.in_channel_id),
						`forwarded htlc row ${row.out_key}`
					),
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
		this._stmt('DELETE FROM forwarded_htlcs WHERE out_key = ?').run(outKey);
	}

	// ─── Chain Monitors ───

	saveChainMonitor(channelId: string, state: IChainMonitorState): void {
		const json = serializeChainMonitorState(state);
		this._stmt(
			'INSERT OR REPLACE INTO chain_monitors (channel_id, state_json) VALUES (?, ?)'
		).run(channelId, this._enc(json));
	}

	loadChainMonitor(channelId: string): IChainMonitorState | null {
		const row = this._stmt(
			'SELECT state_json FROM chain_monitors WHERE channel_id = ?'
		).get(channelId) as { state_json: string } | undefined;
		if (!row) return null;
		return deserializeChainMonitorState(this._dec(row.state_json));
	}

	loadAllChainMonitors(): Array<{
		channelId: string;
		state: IChainMonitorState;
	}> {
		const rows = this._stmt(
			'SELECT channel_id, state_json FROM chain_monitors'
		).all() as Array<{ channel_id: string; state_json: string }>;
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
		this._stmt(
			'INSERT OR REPLACE INTO gossip_channels (scid_hex, channel_json) VALUES (?, ?)'
		).run(scidHex, json);
	}

	deleteGossipChannel(scidHex: string): void {
		this._stmt('DELETE FROM gossip_channels WHERE scid_hex = ?').run(scidHex);
	}

	loadAllGossipChannels(): IGraphChannel[] {
		const rows = this._stmt(
			'SELECT channel_json FROM gossip_channels'
		).all() as Array<{ channel_json: string }>;
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

	loadGossipChannelsAfter(
		afterRowid: number,
		limit: number
	): IGossipRowPage<IGraphChannel> {
		const rows = this._stmt(
			'SELECT rowid, channel_json FROM gossip_channels WHERE rowid > ? ORDER BY rowid LIMIT ?'
		).all(afterRowid, limit) as Array<{ rowid: number; channel_json: string }>;
		const results: IGraphChannel[] = [];
		for (const row of rows) {
			try {
				results.push(deserializeGraphChannel(row.channel_json));
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return {
			rows: results,
			cursor:
				rows.length > 0 ? Number(rows[rows.length - 1].rowid) : afterRowid,
			done: rows.length < limit
		};
	}

	saveGossipNode(nodeIdHex: string, node: IGraphNode): void {
		const json = serializeGraphNode(node);
		this._stmt(
			'INSERT OR REPLACE INTO gossip_nodes (node_id_hex, node_json) VALUES (?, ?)'
		).run(nodeIdHex, json);
	}

	deleteGossipNode(nodeIdHex: string): void {
		this._stmt('DELETE FROM gossip_nodes WHERE node_id_hex = ?').run(nodeIdHex);
	}

	loadAllGossipNodes(): IGraphNode[] {
		const rows = this._stmt(
			'SELECT node_json FROM gossip_nodes'
		).all() as Array<{ node_json: string }>;
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

	loadGossipNodesAfter(
		afterRowid: number,
		limit: number
	): IGossipRowPage<IGraphNode> {
		const rows = this._stmt(
			'SELECT rowid, node_json FROM gossip_nodes WHERE rowid > ? ORDER BY rowid LIMIT ?'
		).all(afterRowid, limit) as Array<{ rowid: number; node_json: string }>;
		const results: IGraphNode[] = [];
		for (const row of rows) {
			try {
				results.push(deserializeGraphNode(row.node_json));
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return {
			rows: results,
			cursor:
				rows.length > 0 ? Number(rows[rows.length - 1].rowid) : afterRowid,
			done: rows.length < limit
		};
	}

	// ─── Payment Secrets ───

	savePaymentSecret(paymentHashHex: string, secret: Buffer): void {
		this._stmt(
			'INSERT OR REPLACE INTO payment_secrets (payment_hash_hex, secret) VALUES (?, ?)'
		).run(paymentHashHex, this._enc(secret.toString('hex')));
	}

	loadAllPaymentSecrets(): Array<{ paymentHashHex: string; secret: Buffer }> {
		const results: Array<{ paymentHashHex: string; secret: Buffer }> = [];
		for (const row of this._rowsInBatches<{
			payment_hash_hex: string;
			secret: string;
		}>('payment_secrets', 'payment_hash_hex, secret')) {
			try {
				results.push({
					paymentHashHex: row.payment_hash_hex,
					secret: this._hexColumn(
						this._dec(row.secret),
						`payment secret row ${row.payment_hash_hex}`
					)
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deletePaymentSecret(paymentHashHex: string): void {
		this._stmt('DELETE FROM payment_secrets WHERE payment_hash_hex = ?').run(
			paymentHashHex
		);
	}

	// ─── BOLT 12 Invoice Path IDs ───
	// The expected blinded-path path_id of an issued BOLT 12 invoice: the
	// receive-side authentication secret (BOLT 12 analogue of a payment
	// secret). Persisted in the same transaction as the preimage so the
	// fail-closed receive check keeps working across restarts.

	saveInvoicePathId(paymentHashHex: string, pathId: Buffer): void {
		this._stmt(
			'INSERT OR REPLACE INTO invoice_path_ids (payment_hash_hex, path_id) VALUES (?, ?)'
		).run(paymentHashHex, this._enc(pathId.toString('hex')));
	}

	loadAllInvoicePathIds(): Array<{ paymentHashHex: string; pathId: Buffer }> {
		const rows = this._stmt(
			'SELECT payment_hash_hex, path_id FROM invoice_path_ids'
		).all() as Array<{ payment_hash_hex: string; path_id: string }>;
		const results: Array<{ paymentHashHex: string; pathId: Buffer }> = [];
		for (const row of rows) {
			try {
				results.push({
					paymentHashHex: row.payment_hash_hex,
					pathId: this._hexColumn(
						this._dec(row.path_id),
						`invoice path id row ${row.payment_hash_hex}`
					)
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteInvoicePathId(paymentHashHex: string): void {
		this._stmt('DELETE FROM invoice_path_ids WHERE payment_hash_hex = ?').run(
			paymentHashHex
		);
	}

	// ─── Invoices ───

	saveInvoice(paymentHashHex: string, invoice: IInvoiceInfo): void {
		const json = JSON.stringify(serializeInvoiceInfo(invoice));
		this._stmt(
			'INSERT OR REPLACE INTO invoices (payment_hash_hex, invoice_json) VALUES (?, ?)'
		).run(paymentHashHex, this._enc(json));
	}

	loadAllInvoices(): Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> {
		const results: Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> =
			[];
		for (const row of this._rowsInBatches<{
			payment_hash_hex: string;
			invoice_json: string;
		}>('invoices', 'payment_hash_hex, invoice_json')) {
			try {
				results.push({
					paymentHashHex: row.payment_hash_hex,
					invoice: deserializeInvoiceInfo(
						JSON.parse(this._dec(row.invoice_json))
					)
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteInvoice(paymentHashHex: string): void {
		this._stmt('DELETE FROM invoices WHERE payment_hash_hex = ?').run(
			paymentHashHex
		);
	}

	// ─── Mission Control ───

	saveMissionControl(json: string): void {
		this._stmt(
			'INSERT OR REPLACE INTO mission_control (id, data_json) VALUES (1, ?)'
		).run(json);
	}

	loadMissionControl(): string | null {
		const row = this._stmt(
			'SELECT data_json FROM mission_control WHERE id = 1'
		).get() as { data_json: string } | undefined;
		return row ? row.data_json : null;
	}

	// ─── Peer Addresses ───

	savePeerAddress(
		pubkey: string,
		host: string,
		port: number,
		transport?: IPeerTransportOptions
	): void {
		this._stmt(
			'INSERT OR REPLACE INTO peer_addresses (pubkey, host, port, last_connected, transport_json) VALUES (?, ?, ?, ?, ?)'
		).run(
			pubkey,
			host,
			port,
			Date.now(),
			transport ? JSON.stringify(transport) : null
		);
	}

	loadAllPeerAddresses(): Array<{
		pubkey: string;
		host: string;
		port: number;
		transport?: IPeerTransportOptions;
	}> {
		const rows = this._stmt(
			'SELECT pubkey, host, port, transport_json FROM peer_addresses'
		).all() as Array<{
			pubkey: string;
			host: string;
			port: number;
			transport_json: string | null;
		}>;
		return rows.flatMap(({ transport_json, ...row }) => {
			if (!transport_json) return [row];
			try {
				const transport = JSON.parse(transport_json) as IPeerTransportOptions;
				if (!transport || !['tcp', 'ws', 'iroh'].includes(transport.type))
					throw new Error('Invalid stored peer transport');
				if (transport.type === 'iroh') {
					normalizeIrohEndpointId(transport.endpointId ?? row.host);
					if (row.port !== 0) throw new Error('Invalid stored Iroh port');
					if (transport.relayUrl !== undefined)
						validateIrohRelayUrl(transport.relayUrl);
				}
				if (transport.type === 'ws' && transport.url !== undefined)
					parseWebSocketUrl(transport.url);
				return [{ ...row, transport }];
			} catch (error) {
				this.reportCorruptRow(error);
				return [];
			}
		});
	}

	deletePeerAddress(pubkey: string): void {
		this._stmt('DELETE FROM peer_addresses WHERE pubkey = ?').run(pubkey);
	}

	// ─── Announced Peer Addresses ───

	saveAnnouncedPeerAddresses(
		pubkey: string,
		timestamp: number,
		addresses: Array<{ host: string; port: number }>
	): void {
		this._stmt(
			'INSERT OR REPLACE INTO announced_peer_addresses (pubkey, announcement_timestamp, addresses_json) VALUES (?, ?, ?)'
		).run(pubkey, timestamp, JSON.stringify(addresses));
	}

	loadAllAnnouncedPeerAddresses(): Array<{
		pubkey: string;
		timestamp: number;
		addresses: Array<{ host: string; port: number }>;
	}> {
		const rows = this._stmt(
			'SELECT pubkey, announcement_timestamp, addresses_json FROM announced_peer_addresses'
		).all() as Array<{
			pubkey: string;
			announcement_timestamp: number;
			addresses_json: string;
		}>;
		return rows.map((row) => ({
			pubkey: row.pubkey,
			timestamp: row.announcement_timestamp,
			addresses: JSON.parse(row.addresses_json) as Array<{
				host: string;
				port: number;
			}>
		}));
	}

	// ─── Channel Key Indices ───

	/** Only a signed candidate makes a locator immutable in the ordinary index table. */
	private protectOpeningKeyIndex(channelId: string, index: number): void {
		const rows = this._stmt(
			'SELECT k.channel_id, k.channel_index FROM channel_key_indices k JOIN final_opening_candidates f ON f.channel_id = k.channel_id'
		).iterate() as Iterable<{
			channel_id: string;
			channel_index: number | string;
		}>;
		for (const row of rows) {
			const sameChannel = row.channel_id === channelId;
			const sameIndex = this._decodeChannelIndex(row.channel_index) === index;
			if (sameChannel === sameIndex) continue;
			const record = this.finalOpeningRecord(row.channel_id);
			if (record?.nonces.session || record?.nonces.signing)
				throw new Error(
					'Cannot reassign a reserved or signed opening channel key index'
				);
		}
	}

	saveChannelKeyIndex(channelId: string, channelIndex: number): void {
		if (this.walletIdentity)
			this.protectOpeningKeyIndex(channelId, channelIndex);
		this._stmt(
			'INSERT OR REPLACE INTO channel_key_indices (channel_id, channel_index) VALUES (?, ?)'
		).run(
			channelId,
			this.encryptionKey ? this._enc(String(channelIndex)) : channelIndex
		);
	}

	/** Decode a channel_index cell: plaintext INTEGER or encrypted TEXT. */
	private _decodeChannelIndex(value: number | string): number {
		const decoded =
			typeof value === 'number' ? value : Number(this._dec(value));
		// Strict: Number() turns a corrupt cell into NaN, which would ride a
		// snapshot as null and silently lose the derivation high-water mark
		// (issue #317). Key indices are safety-critical; fail loudly.
		if (!Number.isSafeInteger(decoded) || decoded < 0) {
			throw new CorruptRecoveryRowError(
				'channel key index is not a non-negative integer'
			);
		}
		return decoded;
	}

	loadChannelKeyIndex(channelId: string): number | null {
		const row = this._stmt(
			'SELECT channel_index FROM channel_key_indices WHERE channel_id = ?'
		).get(channelId) as { channel_index: number | string } | undefined;
		return row ? this._decodeChannelIndex(row.channel_index) : null;
	}

	loadAllChannelKeyIndices(): Array<{
		channelId: string;
		channelIndex: number;
	}> {
		const rows = this._stmt(
			'SELECT channel_id, channel_index FROM channel_key_indices'
		).all() as Array<{ channel_id: string; channel_index: number | string }>;
		return rows.map((row) => ({
			channelId: row.channel_id,
			channelIndex: this._decodeChannelIndex(row.channel_index)
		}));
	}

	loadNextChannelIndex(): number {
		// Encrypted cells are TEXT, so SQL MAX() would compare ciphertext;
		// decode in JS instead (one small row per channel)
		const rows = this._stmt(
			'SELECT channel_index FROM channel_key_indices'
		).all() as Array<{ channel_index: number | string }>;
		let maxIdx: number | null = null;
		for (const row of rows) {
			const idx = this._decodeChannelIndex(row.channel_index);
			if (maxIdx === null || idx > maxIdx) maxIdx = idx;
		}
		return maxIdx !== null ? maxIdx + 1 : 1;
	}

	hasChannelKeyIndices(): boolean {
		// Existence only: no cell is decoded, so an encrypted row counts the
		// same as a plain one and a row at index 0 is told apart from none.
		const row = this._stmt(
			'SELECT 1 AS present FROM channel_key_indices LIMIT 1'
		).get() as { present: number } | undefined;
		return row !== undefined;
	}

	// ─── HTLC Shared Secrets ───

	saveHtlcSharedSecret(key: string, secret: Buffer): void {
		this._stmt(
			'INSERT OR REPLACE INTO htlc_shared_secrets (key, secret) VALUES (?, ?)'
		).run(key, this._enc(secret.toString('hex')));
	}

	deleteHtlcSharedSecret(key: string): void {
		this._stmt('DELETE FROM htlc_shared_secrets WHERE key = ?').run(key);
	}

	loadAllHtlcSharedSecrets(): Array<{ key: string; secret: Buffer }> {
		const results: Array<{ key: string; secret: Buffer }> = [];
		for (const row of this._rowsInBatches<{
			key: string;
			secret: string;
		}>('htlc_shared_secrets', 'key, secret')) {
			try {
				results.push({
					key: row.key,
					secret: this._hexColumn(
						this._dec(row.secret),
						`htlc shared secret row ${row.key}`
					)
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
		this.db.transaction(() => {
			this._stmt(
				'INSERT INTO action_log (category, action, timestamp, data) VALUES (?, ?, ?, ?)'
			).run(entry.category, entry.action, entry.timestamp, entry.data);
			// Cap at 10k rows, pruning oldest first
			this._pruneOldestRows('action_log', 10_000);
		})();
	}

	/**
	 * Delete all but the newest `cap` rows (by id) of an append-only log table.
	 * Runs on every insert. COUNT(*) reads the smallest index rather than the
	 * rows, and the delete visits only the rows it removes, so at the cap an
	 * insert costs one index count and a single-row delete.
	 */
	private _pruneOldestRows(
		table: 'action_log' | 'forwarding_events',
		cap: number
	): void {
		const { n } = this._stmt(`SELECT COUNT(*) AS n FROM ${table}`).get() as {
			n: number;
		};
		if (n <= cap) return;
		this._stmt(
			`DELETE FROM ${table} WHERE id <= (SELECT id FROM ${table} ORDER BY id LIMIT 1 OFFSET ?)`
		).run(n - cap - 1);
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
			(db): void => {
				addColumnIfMissing(
					db,
					'channels',
					'channel_index',
					'INTEGER DEFAULT 0'
				);
			},
			// Migration 1→2: Add webhooks and payment_queue tables
			// (tables already created in _createTables via CREATE IF NOT EXISTS)
			(): void => {
				// No-op — tables created by CREATE IF NOT EXISTS above
			},
			// Migration 2->3: encryption-at-rest rollout. Structurally a no-op;
			// the data rewrite happens in _encryptExistingData() during open()
			// whenever an encryptionKey is provided (lazy-safe for plaintext rows)
			(): void => {
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
				addColumnIfMissing(
					db,
					'watchtower_updates',
					'blob_type',
					'INTEGER NOT NULL DEFAULT 2'
				);
				addColumnIfMissing(
					db,
					'watchtower_sessions',
					'dials_with_session_key',
					'INTEGER NOT NULL DEFAULT 0'
				);
			},
			// Migration 9->10: offers table (BOLT 12 offer persistence, so a
			// shared offer survives a restart instead of dying with the
			// process). Created via CREATE IF NOT EXISTS above; encoded and
			// path_id are in ENCRYPTED_COLUMNS so they are encrypted at rest
			// when a key is set.
			(): void => {
				// No-op
			},
			// Migration 10->11: invoice_path_ids table (expected path_id of an
			// issued BOLT 12 invoice, persisted so receive-side authentication
			// survives a restart; created via CREATE IF NOT EXISTS above, the
			// path_id column encrypted at rest via ENCRYPTED_COLUMNS) and
			// offers.async_hold (an async-hold offer must keep issuing LSP
			// hold payment paths after a restart).
			(db): void => {
				addColumnIfMissing(
					db,
					'offers',
					'async_hold',
					'INTEGER NOT NULL DEFAULT 0'
				);
			},
			// Migration 11->12: recovery_outbox table (Recovery Protocol phase 1,
			// docs/RECOVERY-PROTOCOL.md 5.2). Created via CREATE IF NOT EXISTS
			// above; wire_message is in ENCRYPTED_COLUMNS, since the retained bytes
			// are signed commitment material that reveals channel activity.
			(): void => {
				// No-op
			},
			// Migration 12->13: recovery_frames + recovery_meta tables (Recovery
			// Protocol phase 2, docs/RECOVERY-PROTOCOL.md 5.3). Created via CREATE
			// IF NOT EXISTS above. ciphertext is NOT in ENCRYPTED_COLUMNS: frames
			// arrive already AEAD-encrypted with the per-epoch frame key.
			(): void => {
				// No-op
			}, // Migration 13->14: ffor_vouchers is created above.
			(): void => {
				/* No data is inferred for legacy missing outcomes. */
			},
			// Migration 14->15: retain the selected peer transport across restarts.
			(db): void => {
				db.exec('ALTER TABLE peer_addresses ADD COLUMN transport_json TEXT');
			},
			// Migration 15->16: payments.created_at, indexed, so a page of
			// payments is read newest first without decrypting the whole table
			// to sort it (issue #1403). It is a plaintext lookup column: the
			// hash beside it is already one, and the action log holds recent
			// payments' hashes and times in plaintext. open() fills it for
			// older rows.
			(db): void => {
				db.exec('ALTER TABLE payments ADD COLUMN created_at INTEGER');
				db.exec(
					'CREATE INDEX idx_payments_created_at ON payments(created_at, payment_hash)'
				);
			},
			// Migration 16->17: lookup columns tested during that index walk, so
			// a filtered page does not decrypt the rows it leaves out (issue
			// #1459). Status and direction are plaintext: the action log holds
			// recent payments' outcomes in plaintext beside their hashes.
			// Metadata is not, only keyed tags of it. open() fills them for
			// older rows.
			(db): void => {
				db.exec('ALTER TABLE payments ADD COLUMN status TEXT');
				db.exec('ALTER TABLE payments ADD COLUMN direction TEXT');
				db.exec('ALTER TABLE payments ADD COLUMN metadata_tags TEXT');
			},
			// Migration 17->18: one scrub for every existing database (issue
			// #1490). Older releases encrypted rows without scrubbing the pages
			// the plaintext was freed from, and left no marker, so with nothing
			// left to rewrite no later pass would schedule it. Marked without a
			// key too: only a keyed open scrubs, so the marker waits for one. A
			// new database has no freed plaintext.
			(db): void => {
				if (currentVersion === 0) return;
				db.exec(
					'INSERT OR IGNORE INTO encryption_scrub_pending (id) VALUES (1)'
				);
			},
			// Migration 18->19: revoked-commitment HTLC snapshots leave the
			// channel row for revoked_htlc_snapshots (issue #1670), so a save no
			// longer rewrites the channel's whole history. A row that cannot be
			// moved here keeps them: loading still finds them, and the channel's
			// next save moves them. A plaintext row rewritten under a key leaves
			// its old bytes in freed pages, so that schedules the scrub.
			(db): void => {
				const rows = db
					.prepare('SELECT channel_id, state_json, peer_pubkey FROM channels')
					.all() as Array<{
					channel_id: string;
					state_json: string;
					peer_pubkey: string;
				}>;
				let scrub = false;
				for (const row of rows) {
					try {
						const serialized = JSON.parse(
							this._dec(row.state_json)
						) as ISerializedChannelState;
						if (
							serialized.revokedHtlcSnapshots === undefined &&
							!serialized.compactHtlcHistory?.snapshots?.length
						) {
							continue;
						}
						this.saveChannel(
							row.channel_id,
							deserializeChannelState(serialized),
							row.peer_pubkey
						);
					} catch {
						continue;
					}
					if (this.encryptionKey && !isEncryptedValue(row.state_json)) {
						scrub = true;
					}
				}
				if (scrub) {
					db.exec(
						'INSERT OR IGNORE INTO encryption_scrub_pending (id) VALUES (1)'
					);
				}
			},
			// Migration 19->20: composite_splices (issue #1922) is created above.
			(): void => {
				// No-op
			},
			// Migration 20->21: forwarding_events.auxiliary_json, what marks a
			// forward with an asset leg (issue #2098, step 7): NULL for every
			// ordinary forward, so the rows before it read as they were. Kept
			// plaintext, as the table is: units, carriers and a short channel
			// id are figures of a settled relay like its amounts. A build
			// before it opens the database (it runs no migration at or above
			// its own version, and its required columns are all here), lists
			// such a forward as an ordinary one at what its legs were worth,
			// and writes its own rows with the column NULL.
			(db): void => {
				addColumnIfMissing(db, 'forwarding_events', 'auxiliary_json', 'TEXT');
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
		// 18->19 saves channels through _stmt; dropping what the migrations
		// cached leaves only statements prepared against the final schema.
		this.statements.clear();
	}

	// ─── Metadata ───
	// Values are encrypted at rest when a key is set (see ENCRYPTED_COLUMNS).

	saveMetadata(key: string, value: string): void {
		this._stmt(
			'INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)'
		).run(key, this._enc(value));
	}

	loadMetadata(key: string): string | null {
		const row = this._stmt('SELECT value FROM metadata WHERE key = ?').get(
			key
		) as { value: string } | undefined;
		return row ? this._dec(row.value) : null;
	}

	loadMetadataByPrefix(prefix: string): Array<{ key: string; value: string }> {
		if (!prefix) throw new Error('metadata prefix must not be empty');
		// A key range rather than LIKE, which would read _ and % in the prefix
		// as wildcards and fold case. Keys compare bytewise, so the range ends
		// at the prefix with its last character raised by one.
		const end =
			prefix.slice(0, -1) +
			String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
		const rows = this._stmt(
			'SELECT key, value FROM metadata WHERE key >= ? AND key < ? ORDER BY key'
		).all(prefix, end) as Array<{ key: string; value: string }>;
		return rows.map((row) => ({ key: row.key, value: this._dec(row.value) }));
	}

	deleteMetadata(key: string): void {
		this._stmt('DELETE FROM metadata WHERE key = ?').run(key);
	}

	// ─── On-chain Wallet Data ───
	// Key/value persistence for the on-chain wallet's IWalletData. Values are
	// JSON strings, encrypted at rest when a key is set (see ENCRYPTED_COLUMNS).

	saveWalletData(key: string, value: string): void {
		this._stmt(
			'INSERT OR REPLACE INTO wallet_data (key, value) VALUES (?, ?)'
		).run(key, this._enc(value));
	}

	loadWalletData(key: string): string | null {
		const row = this._stmt('SELECT value FROM wallet_data WHERE key = ?').get(
			key
		) as { value: string } | undefined;
		return row ? this._dec(row.value) : null;
	}

	// ─── Channel Routing Policies ───
	// Stored plaintext: the policy is public data (broadcast in channel_update).

	saveChannelPolicy(channelId: string, policy: IPersistedChannelPolicy): void {
		this._stmt(
			'INSERT OR REPLACE INTO channel_policies (channel_id, policy_json) VALUES (?, ?)'
		).run(channelId, JSON.stringify(policy));
	}

	loadAllChannelPolicies(): Array<{
		channelId: string;
		policy: IPersistedChannelPolicy;
	}> {
		const rows = this._stmt(
			'SELECT channel_id, policy_json FROM channel_policies'
		).all() as Array<{ channel_id: string; policy_json: string }>;
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
		this._stmt('DELETE FROM channel_policies WHERE channel_id = ?').run(
			channelId
		);
	}

	// ─── Peer Storage Blobs (BOLT 1 option_provide_storage) ───
	// One blob per peer, newest wins. Stored base64 and encrypted at rest
	// (see ENCRYPTED_COLUMNS): opaque user data, not ours to inspect.

	savePeerStorageBlob(
		peerPubkey: string,
		blob: Buffer,
		receivedAt: number
	): void {
		this._stmt(
			'INSERT OR REPLACE INTO peer_storage_blobs (peer_pubkey, blob, received_at) VALUES (?, ?, ?)'
		).run(peerPubkey, this._enc(blob.toString('base64')), receivedAt);
	}

	loadPeerStorageBlob(
		peerPubkey: string
	): { blob: Buffer; receivedAt: number } | null {
		const row = this._stmt(
			'SELECT blob, received_at FROM peer_storage_blobs WHERE peer_pubkey = ?'
		).get(peerPubkey) as { blob: string; received_at: number } | undefined;
		if (!row) return null;
		return {
			blob: Buffer.from(this._dec(row.blob), 'base64'),
			receivedAt: row.received_at
		};
	}

	deletePeerStorageBlob(peerPubkey: string): void {
		this._stmt('DELETE FROM peer_storage_blobs WHERE peer_pubkey = ?').run(
			peerPubkey
		);
	}

	// ─── BOLT 12 Offers ───

	saveOffer(
		offerIdHex: string,
		encoded: string,
		pathId: Buffer | null,
		createdAt: number,
		asyncHold?: boolean
	): void {
		// The offer id is a deterministic merkle over the TLVs, so re-creating
		// an identical offer hits the same primary key. INSERT OR REPLACE reset
		// created_at and could null out a stored path_id, silently downgrading
		// the offer's blinded-path authentication; the upsert preserves both.
		this._stmt(
			`INSERT INTO offers (offer_id, encoded, path_id, created_at, async_hold)
				 VALUES (?, ?, ?, ?, ?)
				 ON CONFLICT(offer_id) DO UPDATE SET
					encoded = excluded.encoded,
					path_id = COALESCE(excluded.path_id, offers.path_id),
					async_hold = excluded.async_hold`
		).run(
			offerIdHex,
			this._enc(encoded),
			pathId ? this._enc(pathId.toString('hex')) : null,
			createdAt,
			asyncHold ? 1 : 0
		);
	}

	loadAllOffers(): Array<{
		offerIdHex: string;
		encoded: string;
		pathId: Buffer | null;
		createdAt: number;
		asyncHold: boolean;
	}> {
		const rows = this._stmt(
			'SELECT offer_id, encoded, path_id, created_at, async_hold FROM offers'
		).all() as Array<{
			offer_id: string;
			encoded: string;
			path_id: string | null;
			created_at: number;
			async_hold: number;
		}>;
		const results: Array<{
			offerIdHex: string;
			encoded: string;
			pathId: Buffer | null;
			createdAt: number;
			asyncHold: boolean;
		}> = [];
		for (const row of rows) {
			try {
				results.push({
					offerIdHex: row.offer_id,
					encoded: this._dec(row.encoded),
					pathId: row.path_id
						? this._hexColumn(
								this._dec(row.path_id),
								`offer row ${row.offer_id}`
						  )
						: null,
					createdAt: row.created_at,
					asyncHold: !!row.async_hold
				});
			} catch (err) {
				// Skip corrupted row
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	deleteOffer(offerIdHex: string): void {
		this._stmt('DELETE FROM offers WHERE offer_id = ?').run(offerIdHex);
	}

	// ─── Recovery Outbox (docs/RECOVERY-PROTOCOL.md 5.2) ───
	// Rows are written INSIDE the same transaction as the state that makes the
	// message necessary; the socket write happens only after that transaction
	// commits. wire_message is encrypted at rest (see ENCRYPTED_COLUMNS).

	saveOutboxMessage(message: IRecoveryOutboxMessage): number {
		const result = this._stmt(
			`INSERT INTO recovery_outbox
					(peer_pubkey, channel_id, message_type, wire_message, disposition,
					 frame_sequence, created_at)
				 VALUES (?, ?, ?, ?, ?, NULL, ?)`
		).run(
			message.peerId,
			message.channelId ?? null,
			message.messageType,
			this._enc(message.wireMessage.toString('hex')),
			message.disposition,
			Date.now()
		);
		return Number(result.lastInsertRowid);
	}

	loadOutboxMessages(channelId?: string): IRecoveryOutboxStoredMessage[] {
		const rows = (
			channelId
				? this._stmt(
						'SELECT * FROM recovery_outbox WHERE channel_id = ? ORDER BY id ASC'
				  ).all(channelId)
				: this._stmt('SELECT * FROM recovery_outbox ORDER BY id ASC').all()
		) as Array<{
			id: number;
			peer_pubkey: string;
			channel_id: string | null;
			message_type: number;
			wire_message: string;
			disposition: string;
			frame_sequence: number | null;
			created_at: number;
		}>;

		const results: IRecoveryOutboxStoredMessage[] = [];
		for (const row of rows) {
			try {
				// Strict hex: Buffer.from(s, 'hex') silently truncates at the
				// first bad byte, so a corrupt wire_message would otherwise be
				// coerced into a short retransmission instead of being counted
				// as corrupt (issue #317).
				const wireHex = this._dec(row.wire_message);
				if (!/^([0-9a-f]{2})*$/i.test(wireHex)) {
					throw new CorruptRecoveryRowError(
						`outbox row ${row.id}: wire_message is not valid hex`
					);
				}
				results.push({
					id: row.id,
					peerId: row.peer_pubkey,
					channelId: row.channel_id ?? undefined,
					messageType: row.message_type,
					wireMessage: Buffer.from(wireHex, 'hex'),
					disposition: row.disposition as RecoveryOutboxDisposition,
					frameSequence: row.frame_sequence,
					createdAt: row.created_at
				});
			} catch (err) {
				// A row we cannot decrypt or decode can only ever be used to
				// retransmit garbage; skip it and fall back to reconstructing the
				// retransmission from channel state.
				this.reportCorruptRow(err);
			}
		}
		return results;
	}

	countOutboxMessages(channelId: string): number {
		const row = this._stmt(
			'SELECT COUNT(*) as n FROM recovery_outbox WHERE channel_id = ?'
		).get(channelId) as { n: number };
		return row.n;
	}

	setOutboxDisposition(
		id: number,
		disposition: RecoveryOutboxDisposition
	): void {
		this._stmt('UPDATE recovery_outbox SET disposition = ? WHERE id = ?').run(
			disposition,
			id
		);
	}

	deleteOutboxMessages(channelId: string, messageTypes?: number[]): void {
		if (messageTypes && messageTypes.length > 0) {
			const placeholders = messageTypes.map(() => '?').join(', ');
			this.db
				.prepare(
					`DELETE FROM recovery_outbox
					 WHERE channel_id = ? AND message_type IN (${placeholders})`
				)
				.run(channelId, ...messageTypes);
			return;
		}
		this._stmt('DELETE FROM recovery_outbox WHERE channel_id = ?').run(
			channelId
		);
	}

	pruneOutboxMessages(channelId: string, keepNewest: number): void {
		this._stmt(
			`DELETE FROM recovery_outbox
				 WHERE channel_id = ? AND id NOT IN (
					 SELECT id FROM recovery_outbox
					 WHERE channel_id = ? ORDER BY id DESC LIMIT ?
				 )`
		).run(channelId, channelId, keepNewest);
	}

	// ─── Recovery Journal (docs/RECOVERY-PROTOCOL.md 5.3) ───
	// Frames are appended INSIDE the transaction of the transition they record.
	// ciphertext is already AEAD-encrypted with the per-epoch frame key, so no
	// storage-key layer applies here (see the interface comment).

	saveRecoveryFrame(frame: IStoredRecoveryFrame): void {
		this._stmt(
			`INSERT INTO recovery_frames
					(sequence, writer_epoch, frame_hash, previous_hash, ciphertext,
					 created_at)
				 VALUES (?, ?, ?, ?, ?, ?)`
		).run(
			frame.sequence,
			frame.writerEpoch,
			frame.frameHash,
			frame.previousFrameHash,
			frame.ciphertext,
			frame.createdAt
		);
	}

	loadRecoveryFrames(afterSequence?: number): IStoredRecoveryFrame[] {
		const rows = (
			afterSequence != null
				? this._stmt(
						'SELECT * FROM recovery_frames WHERE sequence > ? ORDER BY sequence ASC'
				  ).all(afterSequence)
				: this._stmt(
						'SELECT * FROM recovery_frames ORDER BY sequence ASC'
				  ).all()
		) as IRecoveryFrameRow[];
		return rows.map(decodeRecoveryFrameRow);
	}

	loadRecoveryFrame(sequence: number): IStoredRecoveryFrame | null {
		const row = this._stmt(
			'SELECT * FROM recovery_frames WHERE sequence = ?'
		).get(sequence) as IRecoveryFrameRow | undefined;
		return row ? decodeRecoveryFrameRow(row) : null;
	}

	loadRecoveryFrameHeader(sequence: number): IStoredRecoveryFrameHeader | null {
		// created_at is stored after the ciphertext, so selecting it would
		// still walk the blob's overflow pages.
		const row = this._stmt(
			`SELECT sequence, writer_epoch, frame_hash, previous_hash
				 FROM recovery_frames WHERE sequence = ?`
		).get(sequence) as IRecoveryFrameRow | undefined;
		return row ? decodeRecoveryFrameHeader(row) : null;
	}

	setOutboxFrameSequence(ids: number[], frameSequence: number): void {
		if (ids.length === 0) return;
		const placeholders = ids.map(() => '?').join(', ');
		this.db
			.prepare(
				`UPDATE recovery_outbox SET frame_sequence = ?
				 WHERE id IN (${placeholders})`
			)
			.run(frameSequence, ...ids);
	}

	deleteRecoveryFramesBelow(sequence: number): void {
		this._stmt('DELETE FROM recovery_frames WHERE sequence < ?').run(sequence);
	}

	// value is encrypted at rest (see ENCRYPTED_COLUMNS): from Phase 5 the
	// writer lease keeps its signing secret here.
	getRecoveryMeta(key: string): string | null {
		const row = this._stmt('SELECT value FROM recovery_meta WHERE key = ?').get(
			key
		) as { value: string } | undefined;
		return row ? this._dec(row.value) : null;
	}

	setRecoveryMeta(key: string, value: string): void {
		this._stmt(
			'INSERT OR REPLACE INTO recovery_meta (key, value) VALUES (?, ?)'
		).run(key, this._enc(value));
	}

	recoveryFrameStats(): {
		count: number;
		minSequence: number;
		maxSequence: number;
	} | null {
		const row = this._stmt(
			'SELECT COUNT(*) AS count, MIN(sequence) AS min, MAX(sequence) AS max FROM recovery_frames'
		).get() as { count: number; min: number | null; max: number | null };
		if (!row.count) return null;
		return {
			count: row.count,
			minSequence: row.min!,
			maxSequence: row.max!
		};
	}

	listRecoveryMetaKeys(): string[] {
		return (
			this._stmt('SELECT key FROM recovery_meta').all() as Array<{
				key: string;
			}>
		).map((row) => row.key);
	}

	deleteRecoveryMeta(key: string): void {
		this._stmt('DELETE FROM recovery_meta WHERE key = ?').run(key);
	}

	// ─── Watchtower (LND altruist client) ───
	// session_key + encrypted_blob are encrypted at rest (see ENCRYPTED_COLUMNS).

	saveWatchtowerSession(session: IWatchtowerSession, sessionKey: Buffer): void {
		this._stmt(
			`INSERT OR REPLACE INTO watchtower_sessions
					(session_id, tower_uri, tower_pubkey, session_key, blob_type,
					 max_updates, sweep_fee_rate, seq_num, last_applied, created_at,
					 dials_with_session_key)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		).run(
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
		const rows = this._stmt('SELECT * FROM watchtower_sessions').all() as Array<
			Record<string, unknown>
		>;
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
		this._stmt(
			'UPDATE watchtower_sessions SET seq_num = ?, last_applied = ? WHERE session_id = ?'
		).run(seqNum, lastApplied, sessionId);
	}

	deleteWatchtowerTower(towerUri: string): void {
		this.db.transaction(() => {
			this._stmt('DELETE FROM watchtower_sessions WHERE tower_uri = ?').run(
				towerUri
			);
			this._stmt('DELETE FROM watchtower_updates WHERE tower_uri = ?').run(
				towerUri
			);
		})();
	}

	addWatchtowerUpdate(update: IWatchtowerUpdate): number {
		const info = this._stmt(
			`INSERT INTO watchtower_updates
					(tower_uri, channel_id, hint, encrypted_blob, seq_num, acked,
					 created_at, blob_type)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		).run(
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
		const rows = this._stmt(
			'SELECT * FROM watchtower_updates WHERE acked = 0 ORDER BY id ASC'
		).all() as Array<Record<string, unknown>>;
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
		this._stmt(
			'UPDATE watchtower_updates SET acked = 1, seq_num = ? WHERE id = ?'
		).run(seqNum, id);
	}

	// ─── Forwarding Events (settled-forward ledger) ───
	// Stored plaintext (see migration 5->6 note): operator analytics, and the
	// filters/index need SQL access to the raw columns.

	saveForwardingEvent(event: Omit<IForwardingEvent, 'id'>): void {
		this.db.transaction(() => {
			this._stmt(
				`INSERT INTO forwarding_events
						(settled_at, in_channel_id, out_channel_id, in_scid, out_scid,
						 amount_in_msat, amount_out_msat, fee_msat, auxiliary_json)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
			).run(
				event.settledAt,
				event.inChannelId,
				event.outChannelId,
				event.inScid ?? null,
				event.outScid ?? null,
				event.amountInMsat.toString(),
				event.amountOutMsat.toString(),
				event.feeMsat.toString(),
				forwardingAuxiliaryToJson(event) ?? null
			);
			// Cap the ledger (default 100k rows), pruning oldest first
			this._pruneOldestRows('forwarding_events', this.forwardingEventsMaxRows);
		})();
	}

	listForwardingEvents(filter?: IForwardingEventFilter): IForwardingEvent[] {
		let sql =
			'SELECT id, settled_at, in_channel_id, out_channel_id, in_scid, out_scid, amount_in_msat, amount_out_msat, fee_msat, auxiliary_json FROM forwarding_events WHERE 1=1';
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
			auxiliary_json: string | null;
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
			feeMsat: BigInt(row.fee_msat),
			...forwardingAuxiliaryFromJson(row.auxiliary_json)
		}));
	}

	getForwardingSummary(options?: { since?: number }): IForwardingSummary {
		// Accumulate in JS bigints: SQL SUM over the TEXT msat columns would
		// coerce to floats and lose precision above 2^53
		let sql =
			'SELECT amount_out_msat, fee_msat, auxiliary_json IS NOT NULL AS marked FROM forwarding_events WHERE 1=1';
		const params: unknown[] = [];
		if (options?.since !== undefined) {
			sql += ' AND settled_at >= ?';
			params.push(options.since);
		}
		// Issue #2098, step 7: a forward with an asset leg counts apart, at
		// what its legs were worth; no bitcoin total counts it.
		const totals = { count: 0, volumeOutMsat: 0n, feesEarnedMsat: 0n };
		const marked = { count: 0, volumeOutMsat: 0n, feesEarnedMsat: 0n };
		for (const row of this.db.prepare(sql).iterate(...params)) {
			const r = row as {
				amount_out_msat: string;
				fee_msat: string;
				marked: number;
			};
			const into = r.marked ? marked : totals;
			into.count++;
			into.volumeOutMsat += BigInt(r.amount_out_msat);
			into.feesEarnedMsat += BigInt(r.fee_msat);
		}
		return marked.count > 0 ? { ...totals, auxiliary: marked } : totals;
	}

	// ─── Transaction ───

	transaction<T>(fn: () => T): T {
		return this.db.transaction(fn)();
	}

	inTransaction(): boolean {
		return this.db.inTransaction;
	}

	// ─── Webhooks (CLI layer persistence) ───

	saveWebhook(
		id: string,
		url: string,
		events: string[],
		secretHash?: string,
		createdAt?: number
	): void {
		this._stmt(
			'INSERT OR REPLACE INTO webhooks (id, url, events, secret_hash, created_at) VALUES (?, ?, ?, ?, ?)'
		).run(
			id,
			url,
			JSON.stringify(events),
			secretHash ?? null,
			createdAt ?? Date.now()
		);
	}

	deleteWebhook(id: string): void {
		this._stmt('DELETE FROM webhooks WHERE id = ?').run(id);
	}

	deleteAllWebhooks(): void {
		this._stmt('DELETE FROM webhooks').run();
	}

	loadAllWebhooks(): Array<{
		id: string;
		url: string;
		events: string[];
		secretHash?: string;
		createdAt: number;
	}> {
		const rows = this._stmt(
			'SELECT id, url, events, secret_hash, created_at FROM webhooks'
		).all() as Array<{
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
		this._stmt(
			'INSERT OR REPLACE INTO payment_queue (id, bolt11, priority, status, amount_sats, max_fee_sats, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
		).run(
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
		this._stmt(
			'UPDATE payment_queue SET status = ?, error = ?, completed_at = ? WHERE id = ?'
		).run(status, error ?? null, completedAt ?? null, id);
	}

	deleteQueueEntry(id: string): void {
		this._stmt('DELETE FROM payment_queue WHERE id = ?').run(id);
	}

	loadAllQueueEntries(): IQueueEntryRow[] {
		return this._queueRows(
			`SELECT ${QUEUE_COLUMNS} FROM payment_queue ORDER BY priority ASC, created_at ASC`
		);
	}

	/** The rows still 'queued' or 'dispatching', in loadAllQueueEntries order. */
	loadActiveQueueEntries(): IQueueEntryRow[] {
		return this._queueRows(
			`SELECT ${QUEUE_COLUMNS} FROM payment_queue WHERE status IN ('queued', 'dispatching') ORDER BY priority ASC, created_at ASC`
		);
	}

	/**
	 * Up to limit finished rows (any status but 'queued' and 'dispatching'),
	 * the most recently finished first: by completed_at, or created_at for a
	 * row without one, then by id. With before, the rows after that finished
	 * row in this order, and none when no finished row has that id.
	 */
	loadQueueHistory(limit: number, before?: string): IQueueEntryRow[] {
		if (before === undefined) {
			return this._queueRows(
				`SELECT ${QUEUE_COLUMNS} FROM payment_queue WHERE ${QUEUE_FINISHED} ORDER BY ${QUEUE_FINISHED_AT} DESC, id DESC LIMIT ?`,
				limit
			);
		}
		// The <= term alone is what lets SQLite seek the index to the
		// cursor; the OR that settles a tie on the time does not.
		return this._queueRows(
			`SELECT ${QUEUE_COLUMNS} FROM payment_queue, (SELECT ${QUEUE_FINISHED_AT} AS cursor_at, id AS cursor_id FROM payment_queue WHERE id = ? AND ${QUEUE_FINISHED}) WHERE ${QUEUE_FINISHED} AND ${QUEUE_FINISHED_AT} <= cursor_at AND (${QUEUE_FINISHED_AT} < cursor_at OR id < cursor_id) ORDER BY ${QUEUE_FINISHED_AT} DESC, id DESC LIMIT ?`,
			before,
			limit
		);
	}

	loadQueueEntry(id: string): IQueueEntryRow | undefined {
		return this._queueRows(
			`SELECT ${QUEUE_COLUMNS} FROM payment_queue WHERE id = ?`,
			id
		)[0];
	}

	private _queueRows(sql: string, ...params: unknown[]): IQueueEntryRow[] {
		const rows = this._stmt(sql).all(...params) as Array<{
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
