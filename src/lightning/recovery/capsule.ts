/**
 * Recovery Capsule over BOLT 1 peer_storage (docs/RECOVERY-PROTOCOL.md 5.4,
 * Phase 3).
 *
 * peer_storage carries a CAPSULE, not the journal: BOLT 1 caps the blob at
 * 65531 bytes, stores only the latest one, lets providers rate-limit
 * persistence, and explicitly warns not to expect the latest blob back. The
 * capsule therefore always carries enough for Tier 1 emergency recovery (the
 * encrypted SCB) plus a locator for the real replicated state: the journal
 * tip, the retained base snapshot hash and, from Phase 4, guardian
 * descriptors. For small wallets the complete stored journal often FITS
 * inline, which makes exact Tier 2 restore possible from peer_storage alone
 * with zero new infrastructure; when it does not fit, the capsule degrades
 * gracefully to SCB + locator.
 *
 * Encryption: AES-256-GCM under HKDF(nodeSecret, 'beignet-recovery-capsule-v1')
 * (info string verified non-colliding with 3.6 and the 5.3 journal strings),
 * so a seed-restored node re-derives the key from its identity secret alone.
 * The inner SCB is itself encodeScb output keyed by the SAME node secret, so
 * the capsule is fully self-contained: nothing beyond the seed-derived node
 * key is needed to use either tier. The encrypted blob starts with the
 * 4-byte magic 'bRC1' so restore code can cheaply recognize capsule blobs
 * among retrieved peer-storage blobs, which may be stale, foreign or garbage.
 *
 * Inline Tier 2 state is the journal AS STORED: the AEAD-encrypted frame rows
 * plus the recovery_meta the verifier needs. Restore installs them into an
 * empty database and then runs the exact Phase 2 machinery
 * (loadVerifiedFrames + reconstructFromFrames), so every tamper, reorder,
 * gap, truncation and deleted-base check applies to capsule restores too, and
 * the rebuilt tables are byte-identical by the same property the journal
 * tests prove.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { hkdfKey } from '../storage/encryption';
import { IStorageBackend, IStoredRecoveryFrame } from '../storage/types';
import { IStaticChannelBackup, decodeScb } from '../backup/scb';
import { PEER_STORAGE_MAX_BYTES } from '../message/peer-storage';
import { getPublicKey } from '../crypto/ecdh';
import {
	JOURNAL_META_KEYS,
	assertEmptyTarget,
	assertFramesReconstructable,
	assertNoJournalResidue,
	deriveRecoveryMasterKey,
	journalSupported,
	reconstructFromFrames,
	verifyFrameChain
} from './journal';
import { withStorageTransaction } from '../storage/transaction';
import { RecoveryFrame, VerifiedRecoveryChain } from './types';

/**
 * A capsule whose CONTENT could not replay (the chain verified, but a
 * table write it implies is invalid, e.g. a constraint violation). Raised
 * during PREVALIDATION, by replaying the candidate into a caller-supplied
 * scratch backend BEFORE anything touches the real target: replaying on
 * the target itself could never tell a content defect apart from a broken
 * target disk, since both surface as the same storage exception. With the
 * defect proven on the scratch, every error the real install raises is a
 * TARGET problem and propagates.
 */
export class CapsuleReplayError extends Error {
	readonly cause: unknown;
	constructor(cause: unknown) {
		super(
			`recovery capsule content failed to replay: ${
				cause instanceof Error ? cause.message : String(cause)
			}`
		);
		this.name = 'CapsuleReplayError';
		this.cause = cause;
	}
}

export interface ICapsuleRestoreOptions {
	/**
	 * Factory for a FRESH, empty storage backend used to dry-run the
	 * candidate's reconstruction before the real target is written (see
	 * CapsuleReplayError). Supply an in-memory backend (e.g.
	 * `() => new SqliteStorage(':memory:')`, opened). Kept injectable so
	 * the recovery core stays free of a concrete backend dependency.
	 * OPTIONAL for the single-capsule restore (a throw is a throw there);
	 * REQUIRED by restoreBestRecoveryCapsule whenever the target supports
	 * Tier 2, because its candidate/Tier-1 fallback contract depends on
	 * classifying content defects, and without a dry-run a replay failure
	 * on the real target cannot be told apart from a broken database.
	 */
	scratchStorage?: () => IStorageBackend;
}

/**
 * A synthetic, KNOWN-GOOD frame set exercising the same operations a real
 * replay performs: a current-schema snapshot writing the main safety
 * tables, plus one delta replayed through RecoveryManager.commit. If the
 * validator backend cannot replay THIS, the validator is broken, not the
 * capsule.
 */
function knownGoodProbeFrames(): VerifiedRecoveryChain {
	const snapshot: RecoveryFrame = {
		version: 1,
		writerEpoch: 1n,
		sequence: 1n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 0,
		mutations: [],
		outboundMessages: [],
		snapshot: {
			schemaVersion: '2',
			channels: [],
			keyIndices: [{ channelId: 'aa'.repeat(32), channelIndex: 1 }],
			chainMonitors: [],
			preimages: [
				{ paymentHash: 'bb'.repeat(32), preimage: Buffer.alloc(32, 1) }
			],
			payments: [],
			paymentSecrets: [
				{ paymentHash: 'bb'.repeat(32), secret: Buffer.alloc(32, 3) }
			],
			htlcPaymentMappings: [{ key: 'probe:0', paymentHash: 'bb'.repeat(32) }],
			forwardedHtlcs: [
				{
					outKey: 'probe:offered-0',
					inChannelId: Buffer.alloc(32, 4),
					inHtlcId: 0n
				}
			],
			htlcSharedSecrets: [{ key: 'probe:0', secret: Buffer.alloc(32, 5) }],
			invoices: [],
			invoicePathIds: [
				{ paymentHash: 'bb'.repeat(32), pathId: Buffer.alloc(32, 6) }
			],
			forwardingEvents: [],
			outbox: []
		}
	};
	const delta: RecoveryFrame = {
		version: 1,
		writerEpoch: 1n,
		sequence: 2n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 0,
		mutations: [
			{
				type: 'payment_preimage',
				paymentHash: 'cc'.repeat(32),
				preimage: Buffer.alloc(32, 2)
			}
		],
		outboundMessages: []
	};
	return [snapshot, delta] as VerifiedRecoveryChain;
}

/**
 * Dry-run the candidate's replay on a scratch backend (see options).
 *
 * The validator is PROBED first by replaying a synthetic KNOWN-GOOD frame
 * set on its own fresh scratch instance, exercising the reads, table
 * writes and transaction completion a real replay needs: a generic
 * backend exception cannot prove whether the capsule content or the
 * validator's own storage failed, so a validator that cannot replay
 * known-good content propagates its failure RAW (infrastructure broken)
 * instead of laundering it into a candidate defect. Only a CANDIDATE
 * replay failing on a validator that just proved itself against the same
 * operations is typed as CapsuleReplayError.
 */
function assertReplaysOnScratch(
	frames: VerifiedRecoveryChain,
	scratchStorage: () => IStorageBackend
): void {
	const scratch = scratchStorage();
	try {
		try {
			// The candidate replay runs TRANSACTIONALLY, so a failure rolls
			// the scratch back to empty and the health probe below runs on
			// the very same instance whose failure is being classified.
			withStorageTransaction(scratch, () => {
				reconstructFromFrames(scratch, frames);
			});
			return;
		} catch (candidateErr) {
			// Prove THIS instance against known-good content exercising the
			// same reads, table writes and transaction completion. If the
			// backend cannot replay that either, the validator is broken:
			// the RAW candidate error propagates (never a capsule defect).
			try {
				withStorageTransaction(scratch, () => {
					reconstructFromFrames(scratch, knownGoodProbeFrames());
				});
			} catch {
				throw candidateErr;
			}
			// The backend just proved healthy on the identical operation
			// set: the candidate's failure is its CONTENT.
			throw new CapsuleReplayError(candidateErr);
		}
	} finally {
		(scratch as { close?: () => void }).close?.();
	}
}

const CAPSULE_HKDF_INFO = 'beignet-recovery-capsule-v1';
const CAPSULE_MAGIC = 'bRC1';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const ZERO_HASH = Buffer.alloc(32);

/** Wire budget for the encrypted capsule blob (distributePeerStorage framing). */
export const CAPSULE_MAX_BYTES = PEER_STORAGE_MAX_BYTES - 8;

/**
 * A recoverable transport credential (wire spec 2.4). Safe to carry here
 * precisely because the whole capsule is encrypted under the seed-derived
 * capsule key: storage peers never see credentials, and a seed restore
 * recovers them together with the endpoints they unlock.
 */
export type GuardianAuth =
	| { type: 'bearer'; token: string }
	| { type: 'macaroon'; macaroon: string }
	| { type: 'tor-v3-client-auth'; privateKey: string };

/**
 * How to reach one guardian (Phase 4). Shape fixed now so the capsule format
 * does not break when guardians arrive: transports follow the section 12
 * decision record, onion-HTTP and clearnet HTTPS both first-class, and a
 * Tor-enabled wallet prefers the onion endpoint.
 */
export interface GuardianDescriptor {
	/** Guardian identity pubkey, hex. */
	guardianId: string;
	transports: Array<{
		type: 'onion-http' | 'https' | 'local-http';
		url: string;
	}>;
	/**
	 * Transport credential for guardians whose transport requires one
	 * (wire 2.4): non-local transports MANDATE authentication, so the
	 * credential must survive catastrophic restoration or the records
	 * behind it are unreachable exactly when they matter. Optional and
	 * additive; Phase 3 capsules without it stay valid.
	 */
	auth?: GuardianAuth;
}

export interface RecoveryCapsule {
	version: 1;
	/** encodeScb output: always sufficient for Tier 1 emergency recovery. */
	encryptedScb: string;
	/** Journal locator: the latest locally durable head (zeros when none). */
	writerEpoch: bigint;
	latestSequence: bigint;
	frameHash: Buffer;
	/**
	 * Frame hash of the retained base snapshot. Zeros mean "no verified base
	 * snapshot claim": either no journal exists yet, or the capsule composed
	 * degraded (allowInline false after a failed re-base) and deliberately
	 * did not read the frame store. Consumers (guardian retrieval, external
	 * Tier 2 storage from Phase 4 on) must treat zeros as unavailable, never
	 * as a real hash.
	 */
	snapshotHash: Buffer;
	/** How to find the real replicated state (empty until Phase 4). */
	guardians: GuardianDescriptor[];
	/** Full stored journal (frames + meta), present only when it fits. */
	inlineRecoveryState?: Buffer;
}

/** JSON shape inside the encrypted capsule payload. */
interface IEncodedCapsule {
	version: 1;
	encryptedScb: string;
	writerEpoch: string;
	latestSequence: string;
	frameHash: string;
	snapshotHash: string;
	guardians: GuardianDescriptor[];
	inlineRecoveryState?: string;
}

/** JSON shape of the inline Tier 2 payload: the journal exactly as stored. */
interface IEncodedInlineState {
	meta: {
		tipSequence: string;
		tipHash: string;
		writerEpoch: string;
		lastSnapshot: string;
	};
	frames: Array<{
		sequence: number;
		writerEpoch: number;
		frameHash: string;
		previousFrameHash: string;
		ciphertext: string;
		createdAt: number;
	}>;
}

export function deriveCapsuleKey(nodeSecret: Buffer): Buffer {
	return hkdfKey(nodeSecret, CAPSULE_HKDF_INFO);
}

function encodeCapsule(capsule: RecoveryCapsule): Buffer {
	const encoded: IEncodedCapsule = {
		version: capsule.version,
		encryptedScb: capsule.encryptedScb,
		writerEpoch: capsule.writerEpoch.toString(),
		latestSequence: capsule.latestSequence.toString(),
		frameHash: capsule.frameHash.toString('hex'),
		snapshotHash: capsule.snapshotHash.toString('hex'),
		guardians: capsule.guardians
	};
	if (capsule.inlineRecoveryState) {
		encoded.inlineRecoveryState =
			capsule.inlineRecoveryState.toString('base64');
	}
	return Buffer.from(JSON.stringify(encoded), 'utf8');
}

function decodeCapsule(plaintext: Buffer): RecoveryCapsule {
	const encoded = JSON.parse(plaintext.toString('utf8')) as IEncodedCapsule;
	if (encoded.version !== 1) {
		throw new Error(`Unsupported recovery capsule version: ${encoded.version}`);
	}
	const capsule: RecoveryCapsule = {
		version: 1,
		encryptedScb: encoded.encryptedScb,
		writerEpoch: BigInt(encoded.writerEpoch),
		latestSequence: BigInt(encoded.latestSequence),
		frameHash: Buffer.from(encoded.frameHash, 'hex'),
		snapshotHash: Buffer.from(encoded.snapshotHash, 'hex'),
		guardians: encoded.guardians ?? []
	};
	if (encoded.inlineRecoveryState != null) {
		capsule.inlineRecoveryState = Buffer.from(
			encoded.inlineRecoveryState,
			'base64'
		);
	}
	return capsule;
}

/** Encrypt a capsule: 'bRC1' || iv || authTag || ciphertext. */
export function encryptRecoveryCapsule(
	capsule: RecoveryCapsule,
	nodeSecret: Buffer
): Buffer {
	const key = deriveCapsuleKey(nodeSecret);
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv('aes-256-gcm', key, iv);
	cipher.setAAD(Buffer.from(CAPSULE_HKDF_INFO, 'ascii'));
	const ciphertext = Buffer.concat([
		cipher.update(encodeCapsule(capsule)),
		cipher.final()
	]);
	return Buffer.concat([
		Buffer.from(CAPSULE_MAGIC, 'ascii'),
		iv,
		cipher.getAuthTag(),
		ciphertext
	]);
}

/**
 * Decrypt a candidate capsule blob. Returns null for anything that is not a
 * valid capsule under this node's key: retrieved peer-storage blobs may be
 * stale, foreign, or garbage, and the restore flow's job is to scan many
 * candidates and keep the valid ones, not to crash on the first bad blob.
 */
export function decodeRecoveryCapsuleBlob(
	blob: Buffer,
	nodeSecret: Buffer
): RecoveryCapsule | null {
	if (
		blob.length < CAPSULE_MAGIC.length + IV_LENGTH + TAG_LENGTH ||
		blob.toString('ascii', 0, CAPSULE_MAGIC.length) !== CAPSULE_MAGIC
	) {
		return null;
	}
	const iv = blob.subarray(
		CAPSULE_MAGIC.length,
		CAPSULE_MAGIC.length + IV_LENGTH
	);
	const tag = blob.subarray(
		CAPSULE_MAGIC.length + IV_LENGTH,
		CAPSULE_MAGIC.length + IV_LENGTH + TAG_LENGTH
	);
	const ciphertext = blob.subarray(
		CAPSULE_MAGIC.length + IV_LENGTH + TAG_LENGTH
	);
	try {
		const decipher = createDecipheriv(
			'aes-256-gcm',
			deriveCapsuleKey(nodeSecret),
			iv
		);
		decipher.setAAD(Buffer.from(CAPSULE_HKDF_INFO, 'ascii'));
		decipher.setAuthTag(tag);
		const plaintext = Buffer.concat([
			decipher.update(ciphertext),
			decipher.final()
		]);
		return decodeCapsule(plaintext);
	} catch {
		return null;
	}
}

/**
 * Raw head comparator over decrypted candidates: highest (writerEpoch,
 * latestSequence). This does NOT validate inline journals; the restore flow
 * must use restoreBestRecoveryCapsule, which selects only among candidates
 * whose hash chain fully verifies (spec 5.4) and fails closed on conflicting
 * equal heads.
 */
export function selectRecoveryCapsule(
	capsules: RecoveryCapsule[]
): RecoveryCapsule | null {
	let best: RecoveryCapsule | null = null;
	for (const capsule of capsules) {
		if (
			!best ||
			capsule.writerEpoch > best.writerEpoch ||
			(capsule.writerEpoch === best.writerEpoch &&
				capsule.latestSequence > best.latestSequence)
		) {
			best = capsule;
		}
	}
	return best;
}

export interface IComposeCapsuleOptions {
	/**
	 * Storage holding the journal to describe (and inline when it fits).
	 * Omit, or pass a storage with no journal tip, for an SCB-only capsule.
	 */
	storage?: IStorageBackend;
	/** encodeScb output for the node's current channels. */
	encryptedScb: string;
	guardians?: GuardianDescriptor[];
	/** Node identity secret; the capsule key re-derives from it. */
	nodeSecret: Buffer;
	/** Budget for the encrypted blob. Default CAPSULE_MAX_BYTES. */
	maxBytes?: number;
	/**
	 * Permit inlining the journal (default true). Callers pass false when the
	 * pre-compose re-base FAILED: an internally valid chain can still be
	 * STALE relative to the live tables (a failed snapshot write leaves the
	 * old chain fully verifiable), and staleness is exactly what chain
	 * verification cannot see. The locator head fields still go out.
	 */
	allowInline?: boolean;
}

export interface IComposedCapsule {
	/** Encrypted, magic-prefixed blob, ready for distributePeerStorage. */
	blob: Buffer;
	capsule: RecoveryCapsule;
	/** Whether the full journal fit inline (Tier 2 from peer_storage alone). */
	inline: boolean;
	/** Set when a journal existed but failed verification and was dropped. */
	inlineError?: string;
}

/**
 * Compose and encrypt the current capsule. Tries the full inline journal
 * first; if the encrypted blob would not fit the peer-storage budget, falls
 * back to SCB + locator (spec 5.4: oversized state degrades gracefully).
 * A journal that fails verification is never inlined either: restore PREFERS
 * Tier 2, so replicating a broken chain would be strictly worse than SCB +
 * locator (the failure is reported via inlineError). Throws only when even
 * the SCB-only capsule is oversized, which mirrors distributePeerStorage's
 * own loud failure on oversized blobs.
 */
export function composeRecoveryCapsule(
	options: IComposeCapsuleOptions
): IComposedCapsule {
	const maxBytes = options.maxBytes ?? CAPSULE_MAX_BYTES;
	const storage = options.storage;
	const tipSequence = storage?.getRecoveryMeta?.(JOURNAL_META_KEYS.tipSequence);
	const tipHash = storage?.getRecoveryMeta?.(JOURNAL_META_KEYS.tipHash);
	const writerEpoch = storage?.getRecoveryMeta?.(JOURNAL_META_KEYS.writerEpoch);
	const lastSnapshot = storage?.getRecoveryMeta?.(
		JOURNAL_META_KEYS.lastSnapshot
	);

	const capsule: RecoveryCapsule = {
		version: 1,
		encryptedScb: options.encryptedScb,
		writerEpoch: writerEpoch != null ? BigInt(writerEpoch) : 0n,
		latestSequence: tipSequence != null ? BigInt(tipSequence) : 0n,
		frameHash: tipHash != null ? Buffer.from(tipHash, 'hex') : ZERO_HASH,
		snapshotHash: ZERO_HASH,
		guardians: options.guardians ?? []
	};

	let frames: IStoredRecoveryFrame[] = [];
	if (
		options.allowInline !== false &&
		storage &&
		tipSequence != null &&
		lastSnapshot != null
	) {
		frames = storage.loadRecoveryFrames?.() ?? [];
		const base = frames.find((row) => String(row.sequence) === lastSnapshot);
		if (base) capsule.snapshotHash = base.frameHash;
	}

	let inlineError: string | undefined;
	if (frames.length > 0) {
		try {
			verifyFrameChain(
				frames,
				{
					tipSequence: tipSequence ?? null,
					tipHash: tipHash ?? null,
					lastSnapshotSequence: lastSnapshot ?? null
				},
				deriveRecoveryMasterKey(options.nodeSecret),
				getPublicKey(options.nodeSecret)
			);
		} catch (err) {
			inlineError = err instanceof Error ? err.message : String(err);
			frames = [];
		}
	}

	if (frames.length > 0) {
		const inlineState: IEncodedInlineState = {
			meta: {
				tipSequence: tipSequence!,
				tipHash: tipHash ?? ZERO_HASH.toString('hex'),
				writerEpoch: writerEpoch ?? '1',
				lastSnapshot: lastSnapshot!
			},
			frames: frames.map((row) => ({
				sequence: row.sequence,
				writerEpoch: row.writerEpoch,
				frameHash: row.frameHash.toString('hex'),
				previousFrameHash: row.previousFrameHash.toString('hex'),
				ciphertext: row.ciphertext.toString('base64'),
				createdAt: row.createdAt
			}))
		};
		const withInline: RecoveryCapsule = {
			...capsule,
			inlineRecoveryState: Buffer.from(JSON.stringify(inlineState), 'utf8')
		};
		const blob = encryptRecoveryCapsule(withInline, options.nodeSecret);
		if (blob.length <= maxBytes) {
			return { blob, capsule: withInline, inline: true };
		}
	}

	const blob = encryptRecoveryCapsule(capsule, options.nodeSecret);
	if (blob.length > maxBytes) {
		throw new Error(
			`recovery capsule oversized even without inline state: ${blob.length} > ${maxBytes} bytes`
		);
	}
	return { blob, capsule, inline: false, inlineError };
}

export interface ICapsuleRestoreResult {
	/** 2 = exact state reconstructed from the inline journal; 1 = SCB only. */
	tier: 1 | 2;
	/** Decoded Tier 1 backup, always present and already authenticated. */
	scb: IStaticChannelBackup;
	/** Tier 2: frames verified and replayed into the target. */
	framesApplied: number;
}

/** Parse an inline Tier 2 payload back into stored rows plus chain metadata. */
function parseInlineState(inline: Buffer): {
	encoded: IEncodedInlineState;
	rows: IStoredRecoveryFrame[];
} {
	let encoded: IEncodedInlineState;
	try {
		encoded = JSON.parse(inline.toString('utf8')) as IEncodedInlineState;
	} catch {
		throw new Error('recovery capsule inline state is not valid JSON');
	}
	if (!Array.isArray(encoded.frames) || encoded.frames.length === 0) {
		throw new Error('recovery capsule inline state carries no frames');
	}
	return {
		encoded,
		rows: encoded.frames.map((row) => ({
			sequence: row.sequence,
			writerEpoch: row.writerEpoch,
			frameHash: Buffer.from(row.frameHash, 'hex'),
			previousFrameHash: Buffer.from(row.previousFrameHash, 'hex'),
			ciphertext: Buffer.from(row.ciphertext, 'base64'),
			createdAt: row.createdAt
		}))
	};
}

/**
 * Verify a capsule's inline journal COMPLETELY, without touching any
 * storage: the full Phase 2 chain verification (verifyFrameChain) over the
 * inline rows and metadata, plus the head binding: the chain must end
 * exactly at the head the capsule advertises, or the payload is not the
 * journal this capsule described (stale or spliced). Throws on the first
 * violation; returns the decoded frames on success.
 */
function verifyInlineJournal(
	capsule: RecoveryCapsule,
	nodeSecret: Buffer
): {
	encoded: IEncodedInlineState;
	rows: IStoredRecoveryFrame[];
	frames: VerifiedRecoveryChain;
} {
	const { encoded, rows } = parseInlineState(capsule.inlineRecoveryState!);
	const frames = verifyFrameChain(
		rows,
		{
			tipSequence: encoded.meta.tipSequence,
			tipHash: encoded.meta.tipHash,
			lastSnapshotSequence: encoded.meta.lastSnapshot
		},
		deriveRecoveryMasterKey(nodeSecret),
		getPublicKey(nodeSecret)
	);
	const last = frames[frames.length - 1];
	const lastRow = rows[rows.length - 1];
	if (
		last.sequence !== capsule.latestSequence ||
		last.writerEpoch !== capsule.writerEpoch ||
		!lastRow.frameHash.equals(capsule.frameHash)
	) {
		throw new Error(
			'recovery capsule head does not match its inline journal (stale or spliced payload)'
		);
	}
	// Schema compatibility is part of CANDIDATE validation, not something
	// discovered after the target was written: a structurally valid capsule
	// whose base snapshot this release cannot restore must be rejected
	// here, so restoreBestRecoveryCapsule treats it as a candidate defect
	// (falling back to other replicas or the Tier 1 SCB) and
	// restoreFromRecoveryCapsule throws before its first target write.
	assertFramesReconstructable(frames);
	return { encoded, rows, frames };
}

/**
 * Restore from a decrypted capsule into an EMPTY target database.
 *
 * Tier 2 path (inline journal present and the target supports frames): the
 * inline journal is verified COMPLETELY before anything touches the target
 * (verifyInlineJournal: the exact Phase 2 chain checks plus the capsule head
 * binding and schema compatibility). The frame rows, the journal metadata
 * AND the reconstruction replay then run inside ONE transaction: chain
 * verification cannot prove the content REPLAYS (a constraint violation
 * only surfaces when the tables are written), so a replay failure must
 * roll the whole install back and leave the target exactly as it was,
 * never half-populated.
 *
 * Tier 1 path (no inline state): the decoded SCB is returned for
 * recoverFromStaticChannelBackup, exactly like a plain SCB restore.
 */
export function restoreFromRecoveryCapsule(
	capsule: RecoveryCapsule,
	target: IStorageBackend,
	nodeSecret: Buffer,
	options: ICapsuleRestoreOptions = {}
): ICapsuleRestoreResult {
	// Authenticates the Tier 1 material up front: wrong-key or tampered SCBs
	// fail here before anything touches the target.
	const scb = decodeScb(capsule.encryptedScb, nodeSecret);

	if (!capsule.inlineRecoveryState || !journalSupported(target)) {
		return { tier: 1, scb, framesApplied: 0 };
	}

	// Validate the candidate COMPLETELY before the first write to the
	// target: chain and schema, then (when a scratch backend is supplied)
	// a full dry-run replay, so a content defect surfaces as the typed
	// CapsuleReplayError while the target is still untouched. Refuse a
	// target already carrying journal state: the metadata writes below
	// would silently overwrite another journal.
	const validated = verifyInlineJournal(capsule, nodeSecret);
	if (options.scratchStorage) {
		assertReplaysOnScratch(validated.frames, options.scratchStorage);
	}
	// The dry-run handed the decoded frames to FOREIGN code (the scratch
	// backend); a hostile or buggy adapter mutating a Buffer argument must
	// not alter what the target replays, so the install re-decodes a fresh
	// frame graph from the authenticated rows.
	const { encoded, rows, frames } = options.scratchStorage
		? verifyInlineJournal(capsule, nodeSecret)
		: validated;
	assertNoJournalResidue(target);

	// ONE shared transaction for the frames, the metadata AND the replay:
	// the inner reconstruction units (applySnapshot, the per-frame
	// RecoveryManager commits) JOIN it through withStorageTransaction
	// instead of nesting, which IStorageBackend does not promise. Any
	// throw rolls the whole install back and PROPAGATES: the candidate's
	// content was already proven (or, without a scratch, is at least never
	// silently degraded), so a failure here means the TARGET is broken,
	// not the capsule.
	withStorageTransaction(target, () => {
		for (const row of rows) {
			target.saveRecoveryFrame!(row);
		}
		target.setRecoveryMeta!(
			JOURNAL_META_KEYS.tipSequence,
			encoded.meta.tipSequence
		);
		target.setRecoveryMeta!(JOURNAL_META_KEYS.tipHash, encoded.meta.tipHash);
		target.setRecoveryMeta!(
			JOURNAL_META_KEYS.writerEpoch,
			encoded.meta.writerEpoch
		);
		target.setRecoveryMeta!(
			JOURNAL_META_KEYS.lastSnapshot,
			encoded.meta.lastSnapshot
		);
		reconstructFromFrames(target, frames);
	});
	return { tier: 2, scb, framesApplied: frames.length };
}

export interface IBestCapsuleRestore extends ICapsuleRestoreResult {
	/** The winning capsule. */
	capsule: RecoveryCapsule;
	/** The highest head seen among ALL decrypted candidates. When the
	 *  restored tier or head is below this, newer state existed somewhere
	 *  and could not be validated; integrations should surface that. */
	newestSeenHead: { writerEpoch: bigint; latestSequence: bigint };
	/** Decrypted candidates that were not used (invalid or superseded). */
	rejectedCandidates: number;
}

/**
 * The spec 5.4 restore rule as ONE validated operation: decrypt every
 * candidate blob, keep the ones that parse under this node's key, and
 * restore the highest (writerEpoch, latestSequence) whose inline hash chain
 * FULLY validates, falling back to the highest candidate's SCB (Tier 1)
 * when no inline journal validates. Selection never trusts an unvalidated
 * candidate, and nothing touches the target until its candidate has been
 * verified end to end.
 *
 * Equal (writerEpoch, latestSequence) with DIFFERING head hashes is a
 * conflict this phase cannot adjudicate (writer fencing arrives in Phase
 * 5): two seed-identical writers advanced independently from the same
 * state. Fail closed; an operator who knows which device was authoritative
 * can restore that specific capsule via restoreFromRecoveryCapsule.
 */
export function restoreBestRecoveryCapsule(
	blobs: Buffer[],
	target: IStorageBackend,
	nodeSecret: Buffer,
	options: ICapsuleRestoreOptions = {}
): IBestCapsuleRestore {
	const candidates = blobs
		.map((blob) => decodeRecoveryCapsuleBlob(blob, nodeSecret))
		.filter((c): c is RecoveryCapsule => c !== null);
	if (candidates.length === 0) {
		throw new Error(
			`no recovery capsule among ${blobs.length} candidate blobs`
		);
	}
	// Highest head first.
	const sorted = [...candidates].sort((a, b) => {
		if (a.writerEpoch !== b.writerEpoch) {
			return a.writerEpoch > b.writerEpoch ? -1 : 1;
		}
		if (a.latestSequence !== b.latestSequence) {
			return a.latestSequence > b.latestSequence ? -1 : 1;
		}
		return 0;
	});
	const newestSeenHead = {
		writerEpoch: sorted[0].writerEpoch,
		latestSequence: sorted[0].latestSequence
	};

	// A dirty target is refused ONCE, loudly, before any candidate is
	// tried: with the install rolled back on failure, a per-candidate
	// throw now reads as a candidate defect, and a pre-populated database
	// must not be silently degraded through every candidate into a Tier 1
	// answer. Dirty means EITHER reconstructed application tables OR any
	// recovery journal residue (stored frames, journal metadata): the
	// install writes both.
	if (journalSupported(target)) {
		// The candidate/Tier-1 fallback CONTRACT depends on classifying
		// content defects, and only the dry-run can do that: without a
		// scratch, a replay failure on the real target is indistinguishable
		// from a broken database, so selection refuses to run rather than
		// choose between aborting on bad content and masking bad disks.
		if (!options.scratchStorage) {
			throw new Error(
				'restoreBestRecoveryCapsule requires options.scratchStorage ' +
					'when the target supports Tier 2 restoration'
			);
		}
		assertEmptyTarget(target);
		assertNoJournalResidue(target);
	}

	for (let i = 0; i < sorted.length; ) {
		// One group of candidates claiming the same (epoch, sequence).
		let j = i;
		while (
			j < sorted.length &&
			sorted[j].writerEpoch === sorted[i].writerEpoch &&
			sorted[j].latestSequence === sorted[i].latestSequence
		) {
			j++;
		}
		const group = sorted.slice(i, j);
		for (const other of group) {
			if (!other.frameHash.equals(group[0].frameHash)) {
				throw new Error(
					`conflicting recovery capsule heads at epoch ${group[0].writerEpoch} sequence ${group[0].latestSequence}: two histories share the same height, refusing to choose`
				);
			}
		}
		// Same head, same hash: a peer may hold a degraded SCB + locator
		// twin, or a damaged copy of the inline journal. EVERY replica of
		// this nonconflicting head gets its turn before the head is given up
		// on; which peer's blob happened to arrive first must not decide the
		// outcome. Candidate-level defects (broken inline chain, broken SCB)
		// move on to the next replica; only when the whole group is
		// exhausted does the next-lower head get its turn (spec 5.4: highest
		// WHOSE HASH CHAIN VALIDATES).
		if (journalSupported(target)) {
			for (const candidate of group) {
				if (!candidate.inlineRecoveryState) continue;
				try {
					verifyInlineJournal(candidate, nodeSecret);
					decodeScb(candidate.encryptedScb, nodeSecret);
				} catch {
					continue;
				}
				// The typed replay error is a CANDIDATE defect, raised by the
				// dry-run BEFORE the target was written, so trying the next
				// replica (or falling through to Tier 1) is safe. Everything
				// else the restore throws is a TARGET problem (the install
				// transaction has rolled it back, but the database is
				// broken or dirty) and degrading it to a Tier 1 answer
				// would mask that, so it propagates.
				let result: ICapsuleRestoreResult;
				try {
					result = restoreFromRecoveryCapsule(
						candidate,
						target,
						nodeSecret,
						options
					);
				} catch (err) {
					if (!(err instanceof CapsuleReplayError)) throw err;
					continue;
				}
				return {
					...result,
					capsule: candidate,
					newestSeenHead,
					rejectedCandidates: candidates.length - 1
				};
			}
		}
		i = j;
	}

	// No inline journal validated at any height: Tier 1 from the highest
	// head whose SCB authenticates. channel_reestablish and the DLP path
	// remain the safety net, exactly as for a plain SCB restore.
	for (const candidate of sorted) {
		let scb: IStaticChannelBackup;
		try {
			scb = decodeScb(candidate.encryptedScb, nodeSecret);
		} catch {
			continue;
		}
		return {
			tier: 1,
			scb,
			framesApplied: 0,
			capsule: candidate,
			newestSeenHead,
			rejectedCandidates: candidates.length - 1
		};
	}
	throw new Error(
		'no recovery capsule candidate validates: every inline journal failed verification and no SCB decodes'
	);
}
