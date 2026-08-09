/**
 * RecoveryJournal: the append-only, node-wide, hash-chained journal of every
 * safety-critical transition (docs/RECOVERY-PROTOCOL.md 5.3, Phase 2).
 *
 * Frames are appended INSIDE the storage transaction of the transition they
 * record, via RecoveryManager.commit: a transition and its frame are one
 * atomic unit, and a journal failure rolls the transition back. The chain is
 * SHA-256 over each frame's plaintext, linked through previousFrameHash; the
 * payload is AEAD-encrypted (AES-256-GCM) with a per-epoch key whose
 * associated data binds (nodeId, writerEpoch, sequence, previousFrameHash),
 * so a frame cannot be transplanted across epochs or positions.
 *
 * Honest scoping of the hash chain, per the spec: it detects tampering and
 * reordering relative to a known tip. It does NOT by itself prevent rollback;
 * a stale replica can serve a truncated but internally valid chain.
 * Anti-rollback comes from the externally anchored head (guardian receipts,
 * Phase 4+). Until then, the tip in recovery_meta gives the local process
 * truncation detection and channel_reestablish remains the safety net.
 *
 * Snapshots and compaction: every snapshotIntervalFrames deltas the journal
 * emits a full-state snapshot frame (all safety-critical tables, spec 5.3)
 * and prunes the deltas below it. Reconstruction is snapshot + later deltas,
 * replayed through the SAME RecoveryManager code path that produced the
 * originals, which is what makes the rebuilt tables byte-identical.
 */

import { createCipheriv, createDecipheriv } from 'crypto';
import { WIRE_SAFETY_POLICY_VERSION } from '../channel/channel-actions';
import { deriveFrameIv } from './guardian-wire';
import { hkdfKey } from '../storage/encryption';
import { IStorageBackend, IStoredRecoveryFrame } from '../storage/types';
import {
	isStorageTransactionActive,
	withStorageTransaction
} from '../storage/transaction';
import { decodeFrame, encodeFrame, hashFrame } from './frame-codec';
import { RecoveryManager } from './recovery-manager';
import {
	IRecoveryJournalSink,
	RecoveryCriticality,
	RecoveryDurability,
	RecoveryFrame,
	RecoveryMutation,
	RecoveryOutboundMessage,
	RecoverySnapshot,
	VerifiedRecoveryChain
} from './types';

const IV_LENGTH = 12;
const TAG_LENGTH = 16;
/** 32 zero bytes: previousFrameHash of the first frame in a chain. */
const GENESIS_HASH = Buffer.alloc(32);

/** recovery_meta keys owned by the journal. */
const META_TIP_SEQUENCE = 'journal_tip_sequence';
const META_TIP_HASH = 'journal_tip_hash';
const META_WRITER_EPOCH = 'journal_writer_epoch';
const META_LAST_SNAPSHOT = 'journal_last_snapshot_sequence';
const META_DELTA_BYTES = 'journal_delta_bytes_since_snapshot';
/**
 * The newest snapshot frame WRITTEN, which is not always the newest snapshot
 * pruned to. Snapshot cadence is measured against this; the verified base
 * (META_LAST_SNAPSHOT) only moves when compaction actually runs.
 */
const META_LAST_SNAPSHOT_WRITTEN = 'journal_last_snapshot_written';
/**
 * Snapshot content versioning. '2' = snapshots carry the WHOLE
 * channel_key_indices table, including entries whose channel was deleted
 * (the high-water mark that prevents key reuse). Snapshots written before
 * this omitted them, so a guardian head compacted by an older release can
 * restore a reset key index; snapshotSchemaRepair() closes that on the
 * first startup of a release that knows better.
 */
const META_SNAPSHOT_SCHEMA = 'journal_snapshot_schema';
export const SNAPSHOT_SCHEMA_VERSION = '2';
/**
 * The EXACT marker strings this release knows how to migrate from. An
 * absent or empty marker (a journal written before versioning existed)
 * is also migratable. Anything else, including malformed numerics such
 * as '-1', '1e0', '0x1' or '01', is either a future release's marker or
 * corruption; both are unknowable and must refuse, never migrate.
 */
const MIGRATABLE_SNAPSHOT_SCHEMAS = new Set(['1']);

/**
 * The one compatibility predicate, shared by the journal's local-marker
 * checks and by reconstruction's authenticated-snapshot check: absent or
 * empty (pre-versioning legacy), the current version, or an exact known
 * older version. Everything else is a future release or corruption.
 */
function snapshotSchemaKnown(marker: string | null | undefined): boolean {
	if (marker == null || marker === '') return true;
	if (marker === SNAPSHOT_SCHEMA_VERSION) return true;
	return MIGRATABLE_SNAPSHOT_SCHEMAS.has(marker);
}
/**
 * Monotonic record that this journal has written at least one `quorum` frame
 * (Phase 6, spec 5.8). Only ever set, never cleared: it is the writer's own
 * memory of a promise it made to every future restore of this chain.
 */
const META_DURABILITY_FLOOR = 'journal_durability_floor';
/**
 * Compaction pruned frames the quorum had not received, so those frames exist
 * nowhere: not locally, and not at any guardian that could have served a
 * repair. Set once, never cleared, because it records something irreversible
 * about the NAMESPACE rather than a condition that can improve.
 */
const META_BACKFILL_LOST = 'journal_backfill_lost';
/**
 * How far replication has provably got (written by GuardianReplicator; owned
 * here so the journal's own checks and the replicator share one constant).
 */
export const META_REPLICATED_THROUGH = 'guardian_replicated_through';
/**
 * The frame hash the replication watermark was receipted AT (written by
 * GuardianReplicator beside guardian_replicated_through). Binds the
 * watermark to a specific history instead of a bare height: a positive
 * watermark is only ever trusted when this hash exists and resolves against
 * the retained frame store (see resolveWatermarkAnchor).
 */
export const META_REPLICATED_THROUGH_HASH = 'guardian_replicated_through_hash';

/**
 * The frame hash a watermark at `sequence` must have been receipted at, from
 * the retained store alone, or null when the store cannot prove one.
 *
 * Two rows can prove it: the stored frame at `sequence` itself, or, when
 * compaction legitimately pruned that frame, the retained BASE snapshot at
 * `sequence + 1` whose cleartext previousFrameHash names exactly the frame
 * that was pruned. The successor row only counts when it IS the recorded
 * base (META_LAST_SNAPSHOT): a gap that is not the recorded base is a
 * damaged store, not a compacted one. previousFrameHash is trustworthy
 * without decryption because it is bound into the frame's AEAD associated
 * data and verified by every full chain verification.
 */
export function resolveWatermarkAnchor(
	storage: IStorageBackend,
	sequence: bigint
): Buffer | null {
	if (sequence < 1n) return null;
	const rows = storage.loadRecoveryFrames?.(Number(sequence) - 1) ?? [];
	if (rows.length === 0) return null;
	const first = rows[0];
	const firstSequence = BigInt(first.sequence);
	if (firstSequence === sequence) return first.frameHash;
	if (firstSequence !== sequence + 1n) return null;
	const base = storage.getRecoveryMeta?.(META_LAST_SNAPSHOT);
	if (base == null || !/^[1-9]\d*$/.test(base)) return null;
	if (BigInt(base) !== firstSequence) return null;
	return first.previousFrameHash;
}

/**
 * Every recovery_meta key that only ever exists because FRAMES existed. A
 * store with ZERO frames must carry none of them: any survivor means the
 * frames were destroyed around it, and rewriting from "fresh" would fork
 * the chain from every replica still holding the erased history. The
 * writer epoch is deliberately NOT here: lease acquisition legitimately
 * records it before the first frame is ever written.
 */
const FRAME_DERIVED_META_KEYS = [
	META_TIP_SEQUENCE,
	META_TIP_HASH,
	META_LAST_SNAPSHOT,
	META_DELTA_BYTES,
	META_LAST_SNAPSHOT_WRITTEN,
	META_SNAPSHOT_SCHEMA,
	META_DURABILITY_FLOOR,
	META_BACKFILL_LOST
] as const;

/** Every journal-owned key, for restore-target emptiness checks. */
const JOURNAL_META_RESIDUE_KEYS = [
	...FRAME_DERIVED_META_KEYS,
	META_WRITER_EPOCH
] as const;

/**
 * The recovery_meta keys that may legitimately exist BEFORE a journal's
 * first frame, WITH the exact value shapes they may legitimately hold:
 * lease acquisition and namespace registration run ahead of the first
 * commit, and the node's startup repair marker is written before restore,
 * but only as the bare 'owed' sentinel (a numeric receipt target implies
 * frames existed, so it can never precede frame 1). Everything else
 * present over an EMPTY frame store, and every allowed key holding a
 * value outside its legitimate shape, is residue of destroyed history.
 * The scan refuses BY PRESENCE: an explicitly stored empty string is
 * presence, not absence.
 */
const isJsonObject = (value: string): boolean => {
	try {
		const parsed: unknown = JSON.parse(value);
		return parsed !== null && typeof parsed === 'object';
	} catch {
		return false;
	}
};
const EMPTY_STORE_ALLOWED_META: ReadonlyMap<
	string,
	(value: string) => boolean
> = new Map([
	[META_WRITER_EPOCH, (value: string): boolean => /^[1-9]\d*$/.test(value)],
	// The lease and the pending records are JSON artifacts; a value their
	// loaders could never parse is residue or corruption, not a
	// legitimate pre-frame state.
	['writer_lease_v1', isJsonObject],
	['restore_pending_acquisition_v1', isJsonObject],
	['guardian_pending_registration_v1', isJsonObject],
	['startup_repair_tail', (value: string): boolean => value === 'owed']
]);

/**
 * The journal's recovery_meta keys, exported for the capsule (spec 5.4),
 * which snapshots them alongside the stored frames so a restore can install
 * a verifiable journal into an empty database.
 */
export const JOURNAL_META_KEYS = {
	tipSequence: META_TIP_SEQUENCE,
	tipHash: META_TIP_HASH,
	writerEpoch: META_WRITER_EPOCH,
	lastSnapshot: META_LAST_SNAPSHOT,
	lastSnapshotWritten: META_LAST_SNAPSHOT_WRITTEN,
	durabilityFloor: META_DURABILITY_FLOOR,
	backfillLost: META_BACKFILL_LOST
} as const;

/** Deltas between full-state snapshot frames. */
const DEFAULT_SNAPSHOT_INTERVAL_FRAMES = 256;
/** Delta plaintext bytes between snapshots (spec 5.3: N frames OR M bytes). */
const DEFAULT_SNAPSHOT_INTERVAL_BYTES = 4 * 1024 * 1024;
/** Frames compaction will hold back for a lagging replica before forcing. */
const DEFAULT_MAX_RETAINED_FRAME_GAP = 1024;

export interface IRecoveryJournalOptions {
	/**
	 * The durability mode the writer is operating under (spec 5.8, Phase 6).
	 * Stamped onto every frame this journal writes, which is what lets a
	 * restore PROVE that the state it recovered covers everything a peer could
	 * have seen. Omit for a journal-only node that configured no mode; its
	 * frames carry no declaration, which reads exactly like `local`.
	 */
	durability?: RecoveryDurability;
	/**
	 * Called when a configured downgrade away from `quorum` is refused because
	 * the journal already contains quorum frames (see stickyQuorum below).
	 * Purely for operator visibility; the refusal is not optional.
	 */
	onDurabilityRefused?: (detail: string) => void;
	/**
	 * The lowest frame sequence that must SURVIVE compaction, because a
	 * replica still needs it (Phase 6). Guardians hold an immutable chain from
	 * a root-committed origin and accept only `logHead.sequence + 1`
	 * (docs/RECOVERY-GUARDIAN-WIRE.md, ORIGIN is "IMMUTABLE... never changing
	 * for the life of the namespace"), so a frame pruned before it replicated
	 * can never be delivered: that guardian sits one behind forever, every
	 * later record is refused with a sequence gap, and in quorum mode every
	 * barrier on the node blocks permanently.
	 *
	 * Return `replicatedThrough() + 1`. Omit for a journal with no replicas,
	 * which compacts exactly as it did before Phase 6.
	 */
	retainFrom?: () => bigint;
	/**
	 * Ceiling on the SEQUENCE GAP compaction will hold back waiting for a
	 * replica, after which it prunes anyway. Without it a permanently dead
	 * guardian would grow the journal without bound. Default 1024 outside
	 * quorum mode, and NO ceiling at all in quorum mode.
	 *
	 * A gap rather than a frame count, and the distinction is deliberate: past
	 * compactions mean the retained rows are at most the gap, never more, so
	 * measuring the gap trips the ceiling no later than counting rows would.
	 *
	 * The asymmetry between the modes is the important part. Crossing the
	 * ceiling deletes frames that, by definition, `required` guardians never
	 * accepted, so they exist nowhere: no guardian can repair another from
	 * records none of them hold. The namespace is then finished, because the
	 * origin is immutable and every guardian behind that point refuses every
	 * later record with a sequence gap. Under a quorum barrier that is not a
	 * degraded node, it is a permanently frozen one. Unbounded disk is
	 * recoverable; a dead namespace is not. Quorum mode also throttles itself
	 * while the quorum is behind, which is exactly the pressure the ceiling
	 * exists to relieve in the other modes, so setting one here is opting in
	 * to destroying the namespace and must be explicit.
	 */
	maxRetainedFrameGap?: number;
	/** Compaction pruned frames a replica had not yet received. */
	onCompactionForced?: (detail: string) => void;
	/**
	 * Reader for the ACTIVE writer-lease epoch, injected by the owner
	 * (import-cycle-free: the lease module imports from this one). When
	 * present, every frame's epoch must EQUAL the lease epoch; a mismatch
	 * means guardians would receipt ciphertext under an epoch a restore
	 * later reconstructs differently, making the receipted frame
	 * undecryptable. Return null when no lease exists; throw on a corrupt
	 * lease to refuse the write.
	 */
	activeLeaseEpoch?: () => bigint | null;
	/** Append a snapshot frame after this many delta frames. Default 256. */
	snapshotIntervalFrames?: number;
	/**
	 * Append a snapshot frame once this many delta plaintext bytes have
	 * accumulated since the last snapshot, whichever of the two limits trips
	 * first. Default 4 MiB. Bounds journal growth when individual transitions
	 * are large (a busy channel's full state per frame).
	 */
	snapshotIntervalBytes?: number;
}

/**
 * Derive the recovery master key from the node's root secret
 * (spec 5.3 key derivation; info strings verified non-colliding with 3.6).
 */
export function deriveRecoveryMasterKey(secret: Buffer): Buffer {
	return hkdfKey(secret, 'beignet-recovery-v1');
}

/** Per-epoch frame key: HKDF(master, info || nodeId || writerEpoch). */
export function deriveFrameKey(
	masterKey: Buffer,
	nodeId: Buffer,
	writerEpoch: bigint
): Buffer {
	const epoch = Buffer.alloc(8);
	epoch.writeBigUInt64BE(writerEpoch);
	return hkdfKey(
		masterKey,
		'beignet-recovery-frame-v1' + nodeId.toString('hex') + epoch.toString('hex')
	);
}

/** AAD binding a frame to its node, epoch, position and predecessor. */
export function frameAad(
	nodeId: Buffer,
	writerEpoch: bigint,
	sequence: bigint,
	previousFrameHash: Buffer
): Buffer {
	const numbers = Buffer.alloc(16);
	numbers.writeBigUInt64BE(writerEpoch, 0);
	numbers.writeBigUInt64BE(sequence, 8);
	return Buffer.concat([nodeId, numbers, previousFrameHash]);
}

/**
 * Encrypt one frame under an EXPLICIT 96-bit IV. From wire spec revision 4
 * the journal derives it deterministically (deriveFrameIv over recovery_id,
 * epoch, sequence and frame hash) instead of drawing it from the CSPRNG: a
 * VM snapshot rollback that replays RNG state can repeat a random IV under
 * the same key across DIFFERENT plaintexts, while the deterministic form
 * can only collide by encrypting the identical plaintext at the identical
 * position, which is harmless. The IV travels with the ciphertext, so
 * frames written before the switch stay decryptable forever.
 */
export function encryptFrame(
	frameKey: Buffer,
	plaintext: Buffer,
	aad: Buffer,
	iv: Buffer
): Buffer {
	if (iv.length !== IV_LENGTH) {
		throw new Error(`Frame IV must be ${IV_LENGTH} bytes, got ${iv.length}`);
	}
	const cipher = createCipheriv('aes-256-gcm', frameKey, iv);
	cipher.setAAD(aad);
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}

export function decryptFrame(
	frameKey: Buffer,
	payload: Buffer,
	aad: Buffer
): Buffer {
	if (payload.length < IV_LENGTH + TAG_LENGTH) {
		throw new Error('Recovery frame ciphertext is truncated');
	}
	const iv = payload.subarray(0, IV_LENGTH);
	const tag = payload.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
	const ciphertext = payload.subarray(IV_LENGTH + TAG_LENGTH);
	const decipher = createDecipheriv('aes-256-gcm', frameKey, iv);
	decipher.setAAD(aad);
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * True when the backend can persist journal frames. Compaction
 * (deleteRecoveryFramesBelow) is required, not optional: verification demands
 * the first retained frame BE the recorded snapshot, which only holds when
 * snapshots actually prune the deltas below them.
 */
export function journalSupported(storage: IStorageBackend): boolean {
	return (
		typeof storage.saveRecoveryFrame === 'function' &&
		typeof storage.loadRecoveryFrames === 'function' &&
		typeof storage.deleteRecoveryFramesBelow === 'function' &&
		typeof storage.getRecoveryMeta === 'function' &&
		typeof storage.setRecoveryMeta === 'function' &&
		// Snapshots must be able to carry EVERY key-index row, deleted
		// channels included: a backend that can only enumerate live
		// channels would hand reconstruction a reset next-index and reopen
		// key reuse, so it does not get a journal at all.
		typeof storage.loadAllChannelKeyIndices === 'function' &&
		// The write gate's empty-store scan must be able to see EVERY
		// metadata key: a backend that cannot enumerate cannot reveal
		// unknown residue of destroyed history, so it does not get a
		// journal either.
		typeof storage.listRecoveryMetaKeys === 'function' &&
		// Compaction that destroys the replication watermark's anchor must
		// be able to RESET the watermark keys atomically; a backend that
		// cannot delete metadata would leave a positive mark behind that
		// resolves against nothing, permanently refusing every later write.
		typeof storage.deleteRecoveryMeta === 'function'
	);
}

/**
 * What the journal's newest frame declares about the mode it was written
 * under. `unreadable` is kept distinct from `absent` because they justify
 * different conclusions: nothing was ever written, versus something was and we
 * cannot see what.
 */
export type TipDurability =
	| { tip: 'absent' }
	| { tip: 'present'; durability: RecoveryDurability | undefined }
	| { tip: 'unreadable'; reason: string };

/** Read the durability declaration off the newest stored frame. */
export function readTipDurability(
	storage: IStorageBackend,
	masterKey: Buffer,
	nodeId: Buffer
): TipDurability {
	const tipSequence = storage.getRecoveryMeta?.(META_TIP_SEQUENCE);
	if (tipSequence == null) return { tip: 'absent' };
	// Only the tip row: sequence > tip-1 is exactly the newest frame.
	const rows = storage.loadRecoveryFrames?.(Number(BigInt(tipSequence) - 1n));
	const row = rows?.[rows.length - 1];
	if (!row) {
		return { tip: 'unreadable', reason: `no stored frame at ${tipSequence}` };
	}
	try {
		const writerEpoch = BigInt(row.writerEpoch);
		const plaintext = decryptFrame(
			deriveFrameKey(masterKey, nodeId, writerEpoch),
			row.ciphertext,
			frameAad(nodeId, writerEpoch, BigInt(row.sequence), row.previousFrameHash)
		);
		return { tip: 'present', durability: decodeFrame(plaintext).durability };
	} catch (error) {
		return {
			tip: 'unreadable',
			reason: error instanceof Error ? error.message : String(error)
		};
	}
}

/**
 * Decide the mode this journal will actually stamp, enforcing the ONE rule
 * that keeps the wire-safety proof honest: quorum is STICKY.
 *
 * A restore concludes "this state is exact, resume the channels" from a
 * certified head frame that declares `quorum`. That conclusion is only valid
 * if every frame ABOVE the head was barriered too, because an unbarriered
 * frame could have put state on the wire that the head does not contain. The
 * cheapest way to guarantee that is to forbid the transition entirely: once a
 * chain contains a quorum frame, every later frame in that chain is quorum as
 * well. Upgrades are free and need no rule, since they only add barriers.
 *
 * Evidence comes from two independent places, and either one is enough:
 * the newest frame's own declaration, and a monotonic recovery_meta floor
 * written in the same transaction as the first quorum frame. Two sources
 * because each covers the other's blind spot: a locally corrupted tip frame
 * may still be intact at the guardians (so the tip alone can be lost), and a
 * meta row is not part of the authenticated chain (so meta alone is weaker
 * evidence). An unreadable tip with no floor is deliberately NOT treated as
 * quorum: freezing a node whose journal is merely damaged would time out live
 * HTLCs, and that node's chain cannot be verified by a restorer anyway.
 *
 * The practical consequence to document for operators: to leave quorum mode
 * you start a new namespace, you do not flip a config value.
 */
function resolveDurability(
	storage: IStorageBackend,
	masterKey: Buffer,
	nodeId: Buffer,
	configured: RecoveryDurability | undefined,
	onRefused?: (detail: string) => void
): RecoveryDurability | undefined {
	if (configured === 'quorum') return 'quorum';
	const floor = storage.getRecoveryMeta?.(META_DURABILITY_FLOOR);
	const tip = readTipDurability(storage, masterKey, nodeId);
	const sticky =
		floor === 'quorum' ||
		(tip.tip === 'present' && tip.durability === 'quorum');
	if (!sticky) return configured;
	onRefused?.(
		`this journal already contains quorum frames, so the configured durability ` +
			`'${String(
				configured ?? 'none'
			)}' is refused and the writer stays in quorum mode; ` +
			`a certified head that reads 'quorum' must never be followed by an unbarriered frame`
	);
	return 'quorum';
}

/**
 * Has this database ever promised quorum durability?
 *
 * Callable WITHOUT constructing a journal, which is the point: the sticky
 * rule is enforced inside RecoveryJournal, so a run that builds no journal at
 * all (recovery disabled, or a backend without frame support) escapes it
 * entirely. Such a node keeps operating its channels while appending nothing,
 * so its state advances past a certified head that still reads 'quorum', and
 * a later restore of that chain would claim an exactness it does not have.
 * The node asks this at construction so it can refuse instead.
 *
 * The frame check is skipped when the backend cannot serve frames, which is
 * also the only case where the meta floor is the sole evidence available.
 */
export function chainPromisedQuorum(
	storage: IStorageBackend,
	masterKey: Buffer,
	nodeId: Buffer
): boolean {
	if (storage.getRecoveryMeta?.(META_DURABILITY_FLOOR) === 'quorum')
		return true;
	if (typeof storage.loadRecoveryFrames !== 'function') return false;
	const tip = readTipDurability(storage, masterKey, nodeId);
	return tip.tip === 'present' && tip.durability === 'quorum';
}

/**
 * Has compaction ever pruned frames the quorum never received? Returns the
 * recorded detail, or null.
 *
 * Journal free, like chainPromisedQuorum and for the same reason: the fact
 * outlives the object that recorded it and has to be readable by a barrier and
 * an operator surface that hold no journal. It is also the reason the fact is
 * PERSISTED at all. Before this, a forced prune was a log line, and the next
 * process start could not tell a permanently dead namespace from a guardian
 * set that was merely unreachable, which is precisely the pair a node must
 * distinguish: one waits, and the other never will.
 */
export function chainLostBackfill(storage: IStorageBackend): string | null {
	return storage.getRecoveryMeta?.(META_BACKFILL_LOST) ?? null;
}

/**
 * The highest frame sequence this database can SHOW, or null when the
 * journal's own bookkeeping and the frames on disk disagree.
 *
 * A replication watermark is only ever a statement about frames this device
 * can produce, so this is the ceiling one has to be checked against. The
 * recorded tip and the newest stored ROW must agree on sequence AND frame
 * hash: rows are AEAD bound to (nodeId, epoch, sequence, previousFrameHash),
 * so anyone without the frame key can DELETE frames but never forge a higher
 * one, and deletion is exactly the rollback this is looking for.
 *
 * Callable without a journal object and without the frame key, because the
 * caller that needs it holds neither, and cheap enough for startup: one meta
 * read and one row, no decryption and no chain walk.
 */
export function storedTipSequence(storage: IStorageBackend): bigint | null {
	const tip = storage.getRecoveryMeta?.(META_TIP_SEQUENCE);
	const tipHash = storage.getRecoveryMeta?.(META_TIP_HASH);
	const empty = (storage.loadRecoveryFrames?.(0) ?? []).length === 0;
	if (tip == null || tipHash == null || !/^\d+$/.test(tip)) {
		// A virgin database is the only honest reading of "no tip", so a frame
		// underneath one means the bookkeeping does not describe the frames.
		return empty ? 0n : null;
	}
	const sequence = BigInt(tip);
	if (sequence === 0n) return empty ? 0n : null;
	// Only the tip row: sequence > tip-1 is exactly the newest frame.
	const rows = storage.loadRecoveryFrames?.(Number(sequence) - 1) ?? [];
	const row = rows[rows.length - 1];
	if (!row || BigInt(row.sequence) !== sequence) return null;
	return row.frameHash.equals(Buffer.from(tipHash, 'hex')) ? sequence : null;
}

export class RecoveryJournal implements IRecoveryJournalSink {
	private readonly storage: IStorageBackend;
	private readonly masterKey: Buffer;
	private readonly nodeId: Buffer;
	private readonly recoveryId: Buffer;
	private readonly snapshotInterval: number;
	private readonly snapshotIntervalBytes: number;
	/** The mode every frame this journal writes declares (spec 5.8). */
	private readonly durability: RecoveryDurability | undefined;
	private readonly retainFrom: (() => bigint) | undefined;
	/** null means no ceiling: the prune is never forced. */
	private readonly maxRetainedFrameGap: number | null;
	private readonly onCompactionForced: ((detail: string) => void) | undefined;
	/** Set once this run's first append has re-based the chain (see appendFrame). */
	private rebasedThisRun = false;
	/** One-shot: the write boundary validated the stored schema marker. */
	private writeSchemaChecked = false;
	/**
	 * The highest tip sequence this run has OBSERVED in storage. Only ever
	 * raised at check time (never on our own writes, so a rolled-back
	 * transaction cannot wedge it): a stored tip below it, or a vanished
	 * tip after it moved past zero, means the store was rewritten under
	 * this writer's feet.
	 */
	private tipFloor = 0n;
	/**
	 * The exact tip this run last WROTE successfully, cleared by
	 * onCommitRollback when the surrounding transaction failed: the next
	 * write requires the stored tip to still BE this tip, so frames or
	 * metadata destroyed under a live writer refuse the next commit
	 * instead of silently re-basing.
	 */
	private lastWrittenTip: { sequence: bigint; hashHex: string } | null = null;
	/**
	 * The first retained sequence this run VERIFIED (one-shot) or produced
	 * (compaction). Together with the tip and the primary key's uniqueness,
	 * an exact count against this minimum proves the retained chain lost
	 * nothing: not its tail, not an interior frame, and not its prefix.
	 */
	private expectedRetainedMin: bigint | null = null;
	/**
	 * The highest writer epoch this run has observed or written. The epoch
	 * defaulting to 1 when its record is missing is only safe on a journal
	 * that never had one: after that, a vanished or regressed epoch means
	 * the next frame would encrypt under the wrong key while guardians
	 * receipt it under the active lease epoch, leaving a receipted frame a
	 * restore cannot decrypt.
	 */
	private epochFloor = 1n;
	/** Injected reader for the active writer-lease epoch (cycle-free). */
	private readonly activeLeaseEpoch?: () => bigint | null;

	/**
	 * @param recoveryId The guardian namespace (wire spec 1.1): the x-only
	 *   recovery root public key. It keys the DETERMINISTIC frame IV
	 *   (wire 3.2) and is deliberately NOT the Lightning node id: every
	 *   other IV input is visible in a stored record, so a node-id-keyed IV
	 *   would let anyone test a candidate Lightning identity against a
	 *   record and break unlinkability.
	 */
	constructor(
		storage: IStorageBackend,
		masterKey: Buffer,
		nodeId: Buffer,
		recoveryId: Buffer,
		options: IRecoveryJournalOptions = {}
	) {
		if (!journalSupported(storage)) {
			throw new Error('Storage backend does not support the recovery journal');
		}
		if (recoveryId.length !== 32) {
			throw new Error('recoveryId must be 32 bytes (x-only recovery root)');
		}
		this.storage = storage;
		this.masterKey = masterKey;
		this.nodeId = nodeId;
		this.recoveryId = recoveryId;
		this.snapshotInterval =
			options.snapshotIntervalFrames ?? DEFAULT_SNAPSHOT_INTERVAL_FRAMES;
		this.snapshotIntervalBytes =
			options.snapshotIntervalBytes ?? DEFAULT_SNAPSHOT_INTERVAL_BYTES;
		this.durability = resolveDurability(
			storage,
			masterKey,
			nodeId,
			options.durability,
			options.onDurabilityRefused
		);
		this.retainFrom = options.retainFrom;
		// `this.durability` is already resolved above, sticky rule included, so
		// a chain that was forced into quorum mode also loses the ceiling.
		this.maxRetainedFrameGap =
			options.maxRetainedFrameGap ??
			(this.durability === 'quorum' ? null : DEFAULT_MAX_RETAINED_FRAME_GAP);
		this.onCompactionForced = options.onCompactionForced;
		this.activeLeaseEpoch = options.activeLeaseEpoch;
	}

	/** The mode this journal stamps on its frames, after the sticky rule. */
	getDurability(): RecoveryDurability | undefined {
		return this.durability;
	}

	/**
	 * Snapshot of every mutable in-memory field, taken when a write attempt
	 * BEGINS. The journal owns its own attempt lifecycle: the checkpoint is
	 * discarded when the surrounding transaction commits and fully restored
	 * when it rolls back OR when the attempt's own guards refuse, so a
	 * failure can neither erase evidence (a refusal must not clear the
	 * expected tip) nor leave phantoms (a rolled-back re-base must not stay
	 * marked as re-based, a rolled-back interval snapshot must not keep a
	 * raised floor).
	 */
	private writeAttemptCheckpoint: {
		lastWrittenTip: { sequence: bigint; hashHex: string } | null;
		tipFloor: bigint;
		epochFloor: bigint;
		expectedRetainedMin: bigint | null;
		rebasedThisRun: boolean;
		writeSchemaChecked: boolean;
	} | null = null;

	private beginWriteAttempt(): void {
		// The floors captured here are RAISED to what durable storage holds
		// at this instant, BEFORE the attempt writes anything: an
		// observation of pre-transaction state is a fact about disk, and a
		// later rollback of the attempt must not un-know it (that is
		// exactly how a failed write let a lost journal restart at frame 1).
		let durableTip = 0n;
		const tipSeq = this.storage.getRecoveryMeta!(META_TIP_SEQUENCE);
		if (tipSeq != null && /^\d+$/.test(tipSeq)) durableTip = BigInt(tipSeq);
		let durableEpoch = 1n;
		const epochRaw = this.storage.getRecoveryMeta!(META_WRITER_EPOCH);
		if (epochRaw != null && /^[1-9]\d*$/.test(epochRaw)) {
			durableEpoch = BigInt(epochRaw);
		}
		const maxBig = (a: bigint, b: bigint): bigint => (a > b ? a : b);
		this.writeAttemptCheckpoint = {
			lastWrittenTip: this.lastWrittenTip,
			tipFloor: maxBig(this.tipFloor, durableTip),
			epochFloor: maxBig(this.epochFloor, durableEpoch),
			expectedRetainedMin: this.expectedRetainedMin,
			rebasedThisRun: this.rebasedThisRun,
			writeSchemaChecked: this.writeSchemaChecked
		};
	}

	private settleWriteAttempt(committed: boolean): void {
		const checkpoint = this.writeAttemptCheckpoint;
		this.writeAttemptCheckpoint = null;
		if (committed || !checkpoint) return;
		this.lastWrittenTip = checkpoint.lastWrittenTip;
		this.tipFloor = checkpoint.tipFloor;
		this.epochFloor = checkpoint.epochFloor;
		this.expectedRetainedMin = checkpoint.expectedRetainedMin;
		this.rebasedThisRun = checkpoint.rebasedThisRun;
		this.writeSchemaChecked = checkpoint.writeSchemaChecked;
	}

	/**
	 * The surrounding commit COMMITTED: the attempt's state is now durable,
	 * so the checkpoint is discarded.
	 */
	onCommitCommitted(): void {
		this.settleWriteAttempt(true);
	}

	/**
	 * The surrounding commit ROLLED BACK (or failed before reaching the
	 * journal at all, in which case no checkpoint exists and this is a
	 * no-op): restore every in-memory field to its pre-attempt value. This
	 * is deliberately a full restore, never a clear: clearing evidence on
	 * a refusal is exactly how a forked frame 1 slipped past a retry.
	 */
	onCommitRollback(): void {
		this.settleWriteAttempt(false);
	}

	/**
	 * Journal one transition. Runs INSIDE RecoveryManager.commit's storage
	 * transaction: the frame commits with the transition or not at all, and
	 * the tip in recovery_meta always matches the last committed frame.
	 *
	 * The tip is read from recovery_meta on every append rather than cached:
	 * inside the transaction the read is consistent, and a rollback discards
	 * the tip update with everything else, so there is no cache to un-poison.
	 *
	 * A journal that has never written (no tip) starts with a BOOTSTRAP
	 * snapshot instead of a delta: the node may carry state that predates
	 * journaling, and deltas alone could never rebuild it. The snapshot is
	 * taken after this transition's mutations have applied (commit order), so
	 * it already contains their effects and the delta itself is not appended;
	 * reconstruction applies a snapshot and only the frames AFTER it.
	 *
	 * The FIRST append of each process run over an existing journal also
	 * snapshots instead of appending a delta. The journal is opt-in config, so
	 * the tables may have drifted while it was disabled; a delta would chain
	 * cleanly onto the stale tip and reconstruction would then verify and
	 * silently miss the drift. Re-basing on the current tables (this
	 * transition's effects included, exactly like bootstrap) makes a clean
	 * verification mean a complete one again, whatever happened between runs.
	 */
	appendFrame(
		mutations: RecoveryMutation[],
		outboundMessages: RecoveryOutboundMessage[]
	): bigint {
		// The attempt lifecycle is the journal's own: checkpoint everything
		// mutable NOW; the manager signals commit or rollback afterwards.
		this.beginWriteAttempt();
		const tipSequence = this.storage.getRecoveryMeta!(META_TIP_SEQUENCE);
		if (tipSequence == null) {
			// The bootstrap snapshot CONTAINS this transition's effects, so the
			// snapshot frame is the one that carries it.
			this.appendSnapshotFrame(1n, GENESIS_HASH);
			this.rebasedThisRun = true;
			return 1n;
		}
		if (!this.rebasedThisRun) {
			const rebaseSequence = BigInt(tipSequence) + 1n;
			this.appendSnapshotFrame(
				rebaseSequence,
				Buffer.from(
					this.storage.getRecoveryMeta!(META_TIP_HASH) ??
						GENESIS_HASH.toString('hex'),
					'hex'
				)
			);
			this.rebasedThisRun = true;
			return rebaseSequence;
		}

		const sequence = BigInt(tipSequence) + 1n;
		const previousFrameHash = Buffer.from(
			this.storage.getRecoveryMeta!(META_TIP_HASH) ??
				GENESIS_HASH.toString('hex'),
			'hex'
		);
		const { frameHash, plaintextBytes } = this.writeFrame({
			version: 1,
			writerEpoch: this.writerEpoch(),
			sequence,
			previousFrameHash,
			timestamp: Date.now(),
			mutations,
			outboundMessages
		});

		// Snapshot on whichever bound trips first (spec 5.3): N delta frames
		// or M bytes of delta plaintext since the last snapshot.
		// Cadence follows snapshots WRITTEN, not the verified base: a base held
		// back for a lagging replica would otherwise read as "no snapshot for
		// ages" and fire one on every single append.
		const lastSnapshot = BigInt(
			this.storage.getRecoveryMeta!(META_LAST_SNAPSHOT_WRITTEN) ??
				this.storage.getRecoveryMeta!(META_LAST_SNAPSHOT) ??
				'0'
		);
		const deltaBytes =
			Number(this.storage.getRecoveryMeta!(META_DELTA_BYTES) ?? '0') +
			plaintextBytes;
		this.storage.setRecoveryMeta!(META_DELTA_BYTES, String(deltaBytes));
		if (
			sequence - lastSnapshot >= BigInt(this.snapshotInterval) ||
			deltaBytes >= this.snapshotIntervalBytes
		) {
			this.appendSnapshotFrame(sequence + 1n, frameHash);
		}
		return sequence;
	}

	/** The sequence the next appended frame will take (1 on bootstrap). */
	nextSequence(): bigint {
		const tip = this.storage.getRecoveryMeta!(META_TIP_SEQUENCE);
		return tip == null ? 1n : BigInt(tip) + 1n;
	}

	/** The journal tip, or null when nothing has been journaled. */
	getTip(): { sequence: bigint; frameHash: Buffer } | null {
		const sequence = this.storage.getRecoveryMeta!(META_TIP_SEQUENCE);
		const hash = this.storage.getRecoveryMeta!(META_TIP_HASH);
		if (sequence == null || hash == null) return null;
		return { sequence: BigInt(sequence), frameHash: Buffer.from(hash, 'hex') };
	}

	/**
	 * Decrypt and verify the stored chain against the recorded tip.
	 *
	 * Detects: a tampered payload (AEAD failure), a reordered or transplanted
	 * frame (AAD sequence binding plus previousFrameHash linkage), a frame
	 * whose plaintext does not match its recorded hash, a gap in the sequence,
	 * and a truncated tail (chain ends below the recorded tip). Throws on the
	 * first violation; returns the decoded frames on success.
	 */
	loadVerifiedFrames(): VerifiedRecoveryChain {
		return verifyFrameChain(
			this.storage.loadRecoveryFrames!(),
			{
				tipSequence: this.storage.getRecoveryMeta!(META_TIP_SEQUENCE),
				tipHash: this.storage.getRecoveryMeta!(META_TIP_HASH),
				lastSnapshotSequence: this.storage.getRecoveryMeta!(META_LAST_SNAPSHOT)
			},
			this.masterKey,
			this.nodeId
		);
	}

	/**
	 * Re-base the chain on the current tables NOW, in its own transaction,
	 * instead of waiting for this run's first append to do it. Called before
	 * the first capsule of a run is composed (spec 5.4): a journal left stale
	 * by a recovery-disabled period must never be replicated, or the capsule's
	 * SCB and its inline Tier 2 journal would describe different points in
	 * time and a restore inside the refresh-throttle window would resurrect
	 * the stale state. Idempotent per run; appendFrame's own per-run re-base
	 * is skipped once this ran. Throws when the frame store cannot accept the
	 * snapshot (corrupt metadata); callers degrade to an SCB-only capsule.
	 */
	prepareForReplication(): void {
		if (this.rebasedThisRun) return;
		this.assertOwnsTransaction('prepareForReplication');
		// This path OWNS its transaction, so it owns the attempt lifecycle
		// too: a rollback restores every in-memory field (a failed re-base
		// must not leave rebasedThisRun true or a phantom written tip).
		this.beginWriteAttempt();
		try {
			this.storage.transaction(() => {
				const tipSequence = this.storage.getRecoveryMeta!(META_TIP_SEQUENCE);
				if (tipSequence == null) {
					this.appendSnapshotFrame(1n, GENESIS_HASH);
				} else {
					this.appendSnapshotFrame(
						BigInt(tipSequence) + 1n,
						Buffer.from(
							this.storage.getRecoveryMeta!(META_TIP_HASH) ??
								GENESIS_HASH.toString('hex'),
							'hex'
						)
					);
				}
			});
		} catch (err) {
			this.settleWriteAttempt(false);
			throw err;
		}
		this.settleWriteAttempt(true);
		this.rebasedThisRun = true;
	}

	// ─────────────── internals ───────────────

	private writerEpoch(): bigint {
		const stored = this.storage.getRecoveryMeta!(META_WRITER_EPOCH);
		const lease = this.activeLeaseEpoch?.() ?? null;
		if (stored == null) {
			// Defaulting to 1 is only safe on a journal that never HAD an
			// epoch: with a lease active, or after a higher epoch was
			// observed, a missing record means it was destroyed.
			if (lease != null || this.epochFloor > 1n) {
				throw new Error(
					'recovery: the journal writer epoch record is missing; ' +
						'refusing to write'
				);
			}
			return 1n;
		}
		if (!/^[1-9]\d*$/.test(stored)) {
			throw new Error(
				`recovery: the journal writer epoch record ('${stored}') is ` +
					`malformed; refusing to write`
			);
		}
		const epoch = BigInt(stored);
		if (epoch < this.epochFloor) {
			throw new Error(
				`recovery: the journal writer epoch regressed (${epoch} after ` +
					`${this.epochFloor}); refusing to write`
			);
		}
		if (lease != null && epoch !== lease) {
			throw new Error(
				`recovery: the journal writer epoch (${epoch}) does not match ` +
					`the active lease epoch (${lease}); refusing to write`
			);
		}
		this.epochFloor = epoch;
		return epoch;
	}

	/**
	 * ONE-SHOT compatibility gate at the TRUE write boundary: every delta,
	 * bootstrap snapshot, per-run re-base, interval snapshot, schema-repair
	 * snapshot and replication re-base funnels through writeFrame, so this
	 * is the one place a rewrite of the journal can be refused before it
	 * begins. Two independent sources must both agree:
	 *
	 * 1. The LOCAL marker (fast, but unauthenticated recovery_meta: with it
	 *    removed, a future journal would read as migratable legacy).
	 * 2. The AUTHENTICATED retained base: the newest decodable snapshot
	 *    among the stored frames declares, under the frame AEAD, which
	 *    schema actually wrote this journal. Re-basing over a future base
	 *    and compacting it away would destroy state this release cannot
	 *    even read completely.
	 *
	 * Frames this run writes afterwards are current-schema by construction,
	 * so one check per run suffices.
	 */
	private assertSchemaCompatibleForWrite(): void {
		if (this.writeSchemaChecked) return;
		this.assertSnapshotSchemaMigratable(
			this.storage.getRecoveryMeta!(META_SNAPSHOT_SCHEMA)
		);
		// FULL chain verification, not just decryption: the rewrite this
		// gate protects will COMPACT whatever it re-bases over, so the
		// stored chain must prove sequence continuity, hash linkage, AEAD
		// integrity and binding to the recorded tip in BOTH directions (a
		// recorded tip without frames, and frames without a recorded tip,
		// are both an emptied or truncated journal, not a fresh one). Any
		// row this release cannot decrypt OR decode fails verification,
		// which is exactly right: an AEAD-valid future frame must not be
		// skipped in favor of an older readable snapshot and compacted
		// away. A truly fresh journal (no frames AND no metadata) passes.
		let frames: VerifiedRecoveryChain;
		try {
			frames = this.loadVerifiedFrames();
		} catch (err) {
			throw new Error(
				`recovery: the stored journal fails verification (${
					err instanceof Error ? err.message : String(err)
				}); refusing to rewrite it`
			);
		}
		// The VERIFIED chain is the authority for what this run may build
		// on: the retained span it proves is what every later write must
		// still find, and the highest epoch it contains is a floor no
		// metadata deletion can lower (a rebase under a lower epoch would
		// compact real history into a chain a receipted restore cannot
		// decrypt).
		if (frames.length > 0) {
			this.expectedRetainedMin = frames[0].sequence;
			for (const frame of frames) {
				if (frame.writerEpoch > this.epochFloor) {
					this.epochFloor = frame.writerEpoch;
				}
			}
		} else {
			this.expectedRetainedMin = null;
		}
		let sawSnapshot = frames.length === 0;
		for (let i = frames.length - 1; i >= 0 && !sawSnapshot; i--) {
			if (!frames[i].snapshot) continue;
			sawSnapshot = true;
			const declared = frames[i].snapshot!.schemaVersion;
			if (!snapshotSchemaKnown(declared)) {
				throw new Error(
					`recovery: the journal's retained base snapshot declares ` +
						`schema '${declared}', which is not one this release can ` +
						`migrate; refusing to rewrite the journal`
				);
			}
		}
		if (!sawSnapshot) {
			// Frames exist but none of them is a snapshot: the base
			// invariant (first retained frame IS the base snapshot) is
			// broken, so nothing sound can be built on top.
			throw new Error(
				'recovery: no base snapshot among the stored frames; ' +
					'refusing to rewrite the journal'
			);
		}
		this.writeSchemaChecked = true;
	}

	/**
	 * Cheap invariants revalidated at EVERY write, unlike the one-shot
	 * chain verification: a store rewritten DURING this process (frames or
	 * tip metadata deleted, tip hash swapped, watermark left dangling)
	 * must refuse the next commit, not silently re-base and fork from the
	 * replicas holding the erased history.
	 */
	private assertWriteInvariants(): void {
		const tipSeq = this.storage.getRecoveryMeta!(META_TIP_SEQUENCE);
		const tipHash = this.storage.getRecoveryMeta!(META_TIP_HASH);
		if ((tipSeq != null) !== (tipHash != null)) {
			throw new Error(
				'recovery: journal tip metadata is partial; refusing to write'
			);
		}
		// The strongest invariant first: whatever this run last wrote must
		// still be EXACTLY the stored tip (a rolled-back commit clears the
		// record via onCommitRollback, so a legitimate retry is not
		// refused).
		if (
			this.lastWrittenTip !== null &&
			(tipSeq == null ||
				BigInt(tipSeq) !== this.lastWrittenTip.sequence ||
				tipHash !== this.lastWrittenTip.hashHex)
		) {
			throw new Error(
				`recovery: the journal tip changed outside this writer (wrote ` +
					`${this.lastWrittenTip.sequence}, found ${tipSeq ?? 'nothing'}); ` +
					`refusing to write`
			);
		}
		if (tipSeq == null) {
			if (this.tipFloor > 0n) {
				throw new Error(
					`recovery: the journal tip (last observed at ${this.tipFloor}) ` +
						`disappeared; refusing to write`
				);
			}
			// A genuinely fresh journal: no frames, and no metadata beyond
			// what legitimately precedes the first frame, each holding a
			// value inside its legitimate shape. PRESENCE is what is
			// checked: an explicitly stored empty value is still residue.
			const validateAllowed = (key: string): void => {
				const validate = EMPTY_STORE_ALLOWED_META.get(key);
				if (!validate) {
					throw new Error(
						`recovery: the frame store is empty but recovery ` +
							`metadata ('${key}') survives; refusing to write`
					);
				}
				const value = this.storage.getRecoveryMeta!(key);
				if (value == null || !validate(value)) {
					throw new Error(
						`recovery: pre-frame recovery metadata ('${key}') holds ` +
							`an illegitimate value; refusing to write`
					);
				}
			};
			const listed = this.storage.listRecoveryMetaKeys?.();
			if (listed !== undefined) {
				for (const key of listed) {
					validateAllowed(key);
				}
			} else {
				// A non-enumerating backend cannot reveal unknown residue,
				// but every key this codebase writes is still checked: the
				// disallowed ones for absence, the allowed ones for their
				// exact legitimate value shape.
				for (const key of [
					...FRAME_DERIVED_META_KEYS,
					META_REPLICATED_THROUGH,
					META_REPLICATED_THROUGH_HASH
				]) {
					if (this.storage.getRecoveryMeta!(key) != null) {
						throw new Error(
							`recovery: the frame store is empty but recovery ` +
								`metadata ('${key}') survives; refusing to write`
						);
					}
				}
				for (const [key, validate] of EMPTY_STORE_ALLOWED_META) {
					const value = this.storage.getRecoveryMeta!(key);
					if (value != null && !validate(value)) {
						throw new Error(
							`recovery: pre-frame recovery metadata ('${key}') ` +
								`holds an illegitimate value; refusing to write`
						);
					}
				}
			}
			if (this.recoveryFrameCount() > 0) {
				throw new Error(
					'recovery: frames exist without a recorded tip; refusing to write'
				);
			}
			return;
		}
		const sequence = BigInt(tipSeq);
		if (sequence < this.tipFloor) {
			throw new Error(
				`recovery: the journal tip moved backwards (${sequence} after ` +
					`${this.tipFloor}); refusing to write`
			);
		}
		// The replication watermark is a PROMISE about frames guardians
		// hold; it can never legitimately exceed the local tip, and letting
		// a raised one stand would release the next frames without any
		// receipt behind them.
		const watermark = this.storage.getRecoveryMeta!(META_REPLICATED_THROUGH);
		if (
			watermark != null &&
			(!/^\d+$/.test(watermark) || BigInt(watermark) > sequence)
		) {
			throw new Error(
				`recovery: the replication watermark ('${watermark}') exceeds ` +
					`the journal tip ${sequence}; refusing to write`
			);
		}
		// The recorded tip must be BACKED by its stored rows, exactly and
		// CONTIGUOUSLY, against the span the VERIFIED chain established:
		// the primary key makes sequences unique, so a matching minimum,
		// maximum and exact count prove the retained chain lost nothing (a
		// deleted tail, a deleted PREFIX, or a deleted middle frame all
		// fail here on the very next write instead of after a restart).
		const stats = this.recoveryFrameSpan();
		const expectedMin = this.expectedRetainedMin;
		if (
			stats == null ||
			expectedMin == null ||
			BigInt(stats.minSequence) !== expectedMin ||
			BigInt(stats.maxSequence) !== sequence ||
			BigInt(stats.count) !== sequence - expectedMin + 1n
		) {
			throw new Error(
				`recovery: the stored frames do not match the recorded tip ` +
					`${sequence}; refusing to write`
			);
		}
		const tipRow = this.loadFrameRow(sequence);
		if (
			tipRow == null ||
			!tipRow.frameHash.equals(Buffer.from(tipHash!, 'hex'))
		) {
			throw new Error(
				`recovery: the stored frames do not match the recorded tip ` +
					`${sequence}; refusing to write`
			);
		}
		// AUTHENTICATE the tip row's content, not just its bookkeeping: a
		// frame-hash column is only a claim until the ciphertext behind it
		// decrypts and hashes to it (the storage layer additionally refuses
		// UPDATEs on frame rows outright).
		let tipPlaintext: Buffer;
		try {
			const tipEpoch = BigInt(tipRow.writerEpoch);
			tipPlaintext = decryptFrame(
				deriveFrameKey(this.masterKey, this.nodeId, tipEpoch),
				tipRow.ciphertext,
				frameAad(this.nodeId, tipEpoch, sequence, tipRow.previousFrameHash)
			);
		} catch {
			throw new Error(
				`recovery: the tip frame ${sequence} fails authentication; ` +
					`refusing to write`
			);
		}
		if (!hashFrame(tipPlaintext).equals(tipRow.frameHash)) {
			throw new Error(
				`recovery: the tip frame ${sequence} does not match its ` +
					`recorded hash; refusing to write`
			);
		}
		// The watermark is a receipt for THIS history, not for a height: a
		// recorded receipted-frame hash must resolve against the retained
		// store, either at the stored frame itself or, when compaction
		// legitimately pruned it, at the retained base snapshot's
		// previousFrameHash. A hash that resolves nowhere, or to a different
		// frame, means the receipts belong to a chain this store no longer
		// holds. A watermark WITHOUT a hash is not validated here: it is
		// already untrusted (replicatedThrough reads it as 0), and refusing
		// it would brick journals written before the binding existed.
		if (watermark != null) {
			const receipted = BigInt(watermark);
			const receiptedHash = this.storage.getRecoveryMeta!(
				META_REPLICATED_THROUGH_HASH
			);
			if (receiptedHash != null && receipted >= 1n) {
				const anchor = resolveWatermarkAnchor(this.storage, receipted);
				if (anchor == null || anchor.toString('hex') !== receiptedHash) {
					throw new Error(
						`recovery: the stored frame at the replication watermark ` +
							`${receipted} is not the receipted frame; refusing to write`
					);
				}
			}
		}
		this.tipFloor = sequence;
	}

	/** One stored frame row by exact sequence, null when absent. */
	private loadFrameRow(sequence: bigint): IStoredRecoveryFrame | null {
		const rows = this.storage.loadRecoveryFrames!(Number(sequence) - 1);
		if (rows.length === 0 || BigInt(rows[0].sequence) !== sequence) {
			return null;
		}
		return rows[0];
	}

	/** Row count of the frame store (stats API when available). */
	private recoveryFrameCount(): number {
		const stats = this.storage.recoveryFrameStats?.();
		if (stats !== undefined) return stats?.count ?? 0;
		return this.storage.loadRecoveryFrames!().length;
	}

	/** Span statistics of the frame store, null when empty. */
	private recoveryFrameSpan(): {
		count: number;
		minSequence: number;
		maxSequence: number;
	} | null {
		const stats = this.storage.recoveryFrameStats?.();
		if (stats !== undefined) return stats;
		const rows = this.storage.loadRecoveryFrames!();
		if (rows.length === 0) return null;
		return {
			count: rows.length,
			minSequence: rows[0].sequence,
			maxSequence: rows[rows.length - 1].sequence
		};
	}

	/** Encode, hash, encrypt and store one frame; advance the tip. */
	private writeFrame(frame: RecoveryFrame): {
		frameHash: Buffer;
		plaintextBytes: number;
	} {
		// One-shot verification first: it establishes the verified span and
		// epoch floor the per-write invariants then hold every write to.
		this.assertSchemaCompatibleForWrite();
		this.assertWriteInvariants();
		// The frame's epoch was computed BEFORE the verified chain could
		// raise the floor (callers evaluate writerEpoch() while building
		// the frame), so it is re-validated here: writing below the chain's
		// own epoch would compact real history into frames a receipted
		// restore cannot decrypt.
		if (frame.writerEpoch < this.epochFloor) {
			throw new Error(
				`recovery: frame epoch ${frame.writerEpoch} is below the ` +
					`verified chain's epoch ${this.epochFloor}; refusing to write`
			);
		}
		// Stamped here rather than at each construction site so that deltas,
		// bootstrap snapshots, per-run re-base snapshots and interval snapshots
		// all carry the same declaration; a snapshot that omitted it would be a
		// certified head that says nothing about what its writer promised.
		if (this.durability) {
			frame.durability = this.durability;
			// Only quorum frames carry a policy stamp, because only they make a
			// claim about which messages waited. Local and async-remote frames
			// keep exactly the bytes they had before.
			if (this.durability === 'quorum') {
				frame.durabilityPolicy = WIRE_SAFETY_POLICY_VERSION;
			}
		}
		const plaintext = encodeFrame(frame);
		const frameHash = hashFrame(plaintext);
		const key = deriveFrameKey(this.masterKey, this.nodeId, frame.writerEpoch);
		const aad = frameAad(
			this.nodeId,
			frame.writerEpoch,
			frame.sequence,
			frame.previousFrameHash
		);
		// Deterministic IV (wire 3.2): namespace-bound, RNG-rollback-proof,
		// and collision-free except for the identical plaintext at the
		// identical position, which re-encrypts identically.
		const iv = deriveFrameIv(
			this.recoveryId,
			frame.writerEpoch,
			frame.sequence,
			frameHash
		);
		this.storage.saveRecoveryFrame!({
			sequence: Number(frame.sequence),
			writerEpoch: Number(frame.writerEpoch),
			frameHash,
			previousFrameHash: frame.previousFrameHash,
			ciphertext: encryptFrame(key, plaintext, aad, iv),
			createdAt: frame.timestamp
		});
		this.storage.setRecoveryMeta!(META_TIP_SEQUENCE, frame.sequence.toString());
		this.storage.setRecoveryMeta!(META_TIP_HASH, frameHash.toString('hex'));
		this.lastWrittenTip = {
			sequence: frame.sequence,
			hashHex: frameHash.toString('hex')
		};
		// A bootstrap (or first-ever) write establishes the retained span.
		if (this.expectedRetainedMin == null) {
			this.expectedRetainedMin = frame.sequence;
		}
		// The floor rides the SAME transaction as the frame that raises it, so
		// a chain can never contain a durable quorum frame without the record
		// that forbids a later downgrade.
		if (
			this.durability === 'quorum' &&
			this.storage.getRecoveryMeta!(META_DURABILITY_FLOOR) !== 'quorum'
		) {
			this.storage.setRecoveryMeta!(META_DURABILITY_FLOOR, 'quorum');
		}
		if (this.storage.getRecoveryMeta!(META_WRITER_EPOCH) == null) {
			this.storage.setRecoveryMeta!(
				META_WRITER_EPOCH,
				frame.writerEpoch.toString()
			);
		}
		return { frameHash, plaintextBytes: plaintext.length };
	}

	/**
	 * Append a full-state snapshot frame and prune the deltas below it
	 * (spec 5.3, snapshots and compaction). Runs inside the caller's
	 * transaction: the tables it reads already include the current
	 * transition's writes, so the snapshot is exact as of this sequence.
	 */
	/**
	 * One-time snapshot-content repair (see META_SNAPSHOT_SCHEMA). A head
	 * compacted by an older release omitted deleted channels' key-index
	 * rows; append a fresh full snapshot so the guardian head regains the
	 * burned indices, and record coverage so this runs once. Returns the
	 * snapshot's sequence for receipt gating, or null when already covered
	 * or when nothing was ever journaled (the first real snapshot will
	 * carry the full table by construction).
	 */
	snapshotSchemaRepair(): bigint | null {
		const marker = this.storage.getRecoveryMeta!(META_SNAPSHOT_SCHEMA);
		if (marker === SNAPSHOT_SCHEMA_VERSION) return null;
		this.assertSnapshotSchemaMigratable(marker);
		const tip = this.storage.getRecoveryMeta!(META_TIP_SEQUENCE);
		const tipHash = this.storage.getRecoveryMeta!(META_TIP_HASH);
		if (tip == null || tipHash == null) {
			// Nothing written yet: the first real snapshot stamps the
			// current schema itself, so there is nothing to repair.
			return null;
		}
		const sequence = BigInt(tip) + 1n;
		// ATOMIC: the snapshot frame, its tip advance, the compaction
		// metadata and the schema marker land together or roll back
		// together. A partial write (frame stored, tip metadata stale)
		// would leave the whole journal unverifiable, which is strictly
		// worse than the gap this repair closes. The attempt lifecycle is
		// owned here too: a rollback restores every in-memory field.
		this.assertOwnsTransaction('snapshotSchemaRepair');
		this.beginWriteAttempt();
		try {
			this.storage.transaction(() => {
				this.appendSnapshotFrame(sequence, Buffer.from(tipHash, 'hex'));
				this.storage.setRecoveryMeta!(
					META_SNAPSHOT_SCHEMA,
					SNAPSHOT_SCHEMA_VERSION
				);
			});
		} catch (err) {
			this.settleWriteAttempt(false);
			throw err;
		}
		this.settleWriteAttempt(true);
		return sequence;
	}

	/**
	 * Read-only probe: would snapshotSchemaRepair() act on this journal?
	 * Lets the caller persist its repair intent BEFORE the marker or any
	 * other trigger is consumed. This is ALSO the fail-closed compatibility
	 * gate, and it must run before any restore mutation: restoration can
	 * journal deletions, and a journal write that triggers a snapshot
	 * would stamp the current schema over a marker this release never
	 * validated, silently downgrading a future release's journal.
	 */
	needsSnapshotSchemaRepair(): boolean {
		const marker = this.storage.getRecoveryMeta!(META_SNAPSHOT_SCHEMA);
		this.assertSnapshotSchemaMigratable(marker);
		if (this.storage.getRecoveryMeta!(META_TIP_SEQUENCE) == null) {
			// No frames yet: the bootstrap snapshot will be current-schema.
			return false;
		}
		return marker !== SNAPSHOT_SCHEMA_VERSION;
	}

	/**
	 * Only the current marker, an EXACT known-older marker, or no marker at
	 * all may proceed. A higher or unrecognized marker was written by a
	 * newer release whose snapshot shape this build cannot reproduce;
	 * compacting with our shape and rewriting the marker would
	 * destructively downgrade the journal. Malformed markers are just as
	 * unknowable. Fail closed, journal untouched.
	 */
	private assertSnapshotSchemaMigratable(
		marker: string | null | undefined
	): void {
		if (snapshotSchemaKnown(marker)) return;
		throw new Error(
			`recovery: journal snapshot schema '${marker}' is not one ` +
				`this release can migrate; refusing to rewrite the journal`
		);
	}

	private appendSnapshotFrame(
		sequence: bigint,
		previousFrameHash: Buffer
	): void {
		this.writeFrame({
			version: 1,
			writerEpoch: this.writerEpoch(),
			sequence,
			previousFrameHash,
			timestamp: Date.now(),
			mutations: [],
			outboundMessages: [],
			snapshot: this.captureSnapshot()
		});
		// Cadence is measured against snapshots WRITTEN. The verified base only
		// moves when the deltas below it are actually pruned, which a lagging
		// replica can postpone (see compactTo).
		this.storage.setRecoveryMeta!(
			META_LAST_SNAPSHOT_WRITTEN,
			sequence.toString()
		);
		this.storage.setRecoveryMeta!(META_DELTA_BYTES, '0');
		// Every snapshot this release writes carries the whole key-index
		// table, so it IS current-schema by construction; stamping here
		// means a fresh journal is never seen as needing the repair.
		this.storage.setRecoveryMeta!(
			META_SNAPSHOT_SCHEMA,
			SNAPSHOT_SCHEMA_VERSION
		);
		this.compactTo(sequence);
	}

	/**
	 * Prune below a snapshot, unless a replica still needs frames down there.
	 *
	 * The base the chain verifies against (META_LAST_SNAPSHOT) advances only
	 * when the prune runs, so verifyFrameChain's "first retained frame IS the
	 * recorded base snapshot" invariant holds either way: either we pruned to
	 * this snapshot and it is now the base, or we kept everything and the
	 * previous base is still the first retained frame. A snapshot left
	 * unpruned mid-chain costs nothing at restore time, since
	 * reconstructFromFrames replays from the NEWEST snapshot it finds.
	 */
	private compactTo(snapshotSequence: bigint): void {
		const floor = this.retainFrom?.();
		if (floor !== undefined && floor < snapshotSequence) {
			const ceiling = this.maxRetainedFrameGap;
			const held = snapshotSequence - floor;
			if (ceiling === null || held <= BigInt(ceiling)) return;
			// Nothing behind this point is coming back, from anywhere. The
			// floor is the QUORUM watermark, so the frames about to go were
			// accepted by fewer than `required` guardians and no guardian can
			// repair another from records none of them hold. The origin is
			// immutable and every guardian behind this point refuses every
			// later record with a sequence gap, so the namespace is finished:
			// a new one needs a new node identity or operator deletion at every
			// guardian, which is not something the writer can do for itself.
			const detail =
				`compaction pruned to frame ${snapshotSequence} while the quorum had ` +
				`only reached frame ${
					floor - 1n
				}: the ${held} frame gap exceeded the ` +
				`${ceiling} frame retention ceiling, so those frames now exist nowhere ` +
				`and no guardian behind that point can ever be backfilled. This ` +
				`recovery namespace is finished; a new one needs a new node identity ` +
				`or operator deletion at every guardian`;
			// Recorded BEFORE the delete and inside the caller's transaction, so
			// a compaction that rolls back cannot leave a node believing it lost
			// a backfill it still has. Set once: the first loss is the one that
			// killed the namespace.
			if (this.storage.getRecoveryMeta!(META_BACKFILL_LOST) == null) {
				this.storage.setRecoveryMeta!(META_BACKFILL_LOST, detail);
			}
			this.onCompactionForced?.(detail);
		}
		// A prune that reaches past watermark + 1 destroys the watermark's
		// anchor: neither the receipted frame nor a base snapshot naming it
		// survives, so the binding can never be evaluated again. Reset BOTH
		// keys atomically (a bare positive height would otherwise linger,
		// resolvable by nothing) and record the loss: the pruned frames were
		// never receipted by the quorum, so no guardian behind that point can
		// ever be backfilled. This branch is reachable only through forced
		// compaction (which recorded the loss above) or a writer with no
		// retention floor at all; the normal floor holds the prune at
		// watermark + 1, where the base snapshot still anchors the mark.
		const watermarkRaw = this.storage.getRecoveryMeta!(META_REPLICATED_THROUGH);
		if (
			watermarkRaw != null &&
			/^\d+$/.test(watermarkRaw) &&
			BigInt(watermarkRaw) > 0n &&
			BigInt(watermarkRaw) < snapshotSequence - 1n
		) {
			if (this.storage.getRecoveryMeta!(META_BACKFILL_LOST) == null) {
				this.storage.setRecoveryMeta!(
					META_BACKFILL_LOST,
					`compaction pruned to frame ${snapshotSequence} past the ` +
						`replication watermark ${watermarkRaw}: frames the guardians ` +
						`never received now exist nowhere, so no guardian behind ` +
						`that point can ever be backfilled`
				);
			}
			this.storage.deleteRecoveryMeta!(META_REPLICATED_THROUGH);
			this.storage.deleteRecoveryMeta!(META_REPLICATED_THROUGH_HASH);
		}
		this.storage.deleteRecoveryFramesBelow!(Number(snapshotSequence));
		this.storage.setRecoveryMeta!(
			META_LAST_SNAPSHOT,
			snapshotSequence.toString()
		);
		// The prune moved the retained minimum; the per-write span check
		// holds every later write to exactly this.
		this.expectedRetainedMin = snapshotSequence;
	}

	/**
	 * Retry a compaction that a lagging replica held back. Called after the
	 * replication watermark advances; a no-op when nothing is outstanding.
	 */
	compact(): void {
		const written = this.storage.getRecoveryMeta!(META_LAST_SNAPSHOT_WRITTEN);
		if (written == null) return;
		const base = BigInt(
			this.storage.getRecoveryMeta!(META_LAST_SNAPSHOT) ?? '0'
		);
		const target = BigInt(written);
		if (target <= base) return;
		this.assertOwnsTransaction('compact');
		this.beginWriteAttempt();
		try {
			this.storage.transaction(() => this.compactTo(target));
		} catch (err) {
			this.settleWriteAttempt(false);
			throw err;
		}
		this.settleWriteAttempt(true);
	}

	/**
	 * Journal writes settle durability (and, through the barrier, wire
	 * releases) at their OWN commit boundary. Joining an outer transaction
	 * would settle before the real commit: an outer rollback then leaves
	 * no frame while everything downstream already believed there was one.
	 */
	private assertOwnsTransaction(operation: string): void {
		if (isStorageTransactionActive(this.storage)) {
			throw new Error(
				`recovery: ${operation} cannot run inside an outer storage ` +
					`transaction; journal durability settles at its own commit`
			);
		}
	}

	/** Serialize every safety-critical table (see RecoverySnapshot). */
	private captureSnapshot(): RecoverySnapshot {
		const storage = this.storage;
		const channels = storage.loadAllChannels();
		return {
			// Authenticated by the frame: restoration re-derives the local
			// schema marker from here, since recovery_meta does not ride
			// frames and would otherwise be lost with the device.
			schemaVersion: SNAPSHOT_SCHEMA_VERSION,
			channels: channels.map((c) => ({
				channelId: c.channelId,
				state: c.state,
				peerPubkey: c.peerPubkey
			})),
			// The WHOLE index table, not just live channels' entries: a
			// deleted channel's index row is the high-water mark that keeps
			// the next open from reusing its keys, and a snapshot composed
			// after the deletion is the only carrier a reconstruction has.
			// journalSupported() made the enumeration mandatory.
			keyIndices: storage.loadAllChannelKeyIndices!(),
			chainMonitors: storage.loadAllChainMonitors(),
			preimages: storage.loadAllPreimages(),
			payments: storage.loadAllPayments(),
			paymentSecrets: storage.loadAllPaymentSecrets().map((s) => ({
				paymentHash: s.paymentHashHex,
				secret: s.secret
			})),
			htlcPaymentMappings: storage.loadAllHtlcPaymentMappings().map((m) => ({
				key: m.key,
				paymentHash: m.paymentHashHex
			})),
			forwardedHtlcs: storage.loadAllForwardedHtlcs(),
			htlcSharedSecrets: storage.loadAllHtlcSharedSecrets(),
			invoices: storage.loadAllInvoices().map((i) => ({
				paymentHash: i.paymentHashHex,
				invoice: i.invoice
			})),
			invoicePathIds: (storage.loadAllInvoicePathIds?.() ?? []).map((i) => ({
				paymentHash: i.paymentHashHex,
				pathId: i.pathId
			})),
			// listForwardingEvents returns newest first; the snapshot keeps
			// insertion order so replaying it reproduces the ledger exactly.
			forwardingEvents: (storage.listForwardingEvents?.() ?? [])
				.slice()
				.reverse()
				.map(({ id: _id, ...event }) => event),
			outbox: (storage.loadOutboxMessages?.() ?? []).map((row) => ({
				peerId: row.peerId,
				channelId: row.channelId,
				messageType: row.messageType,
				wireMessage: row.wireMessage,
				disposition: row.disposition,
				frameSequence: row.frameSequence
			}))
		};
	}
}

/** The journal metadata a chain verification runs against. */
export interface IFrameChainMeta {
	tipSequence: string | null;
	tipHash: string | null;
	lastSnapshotSequence: string | null;
}

/**
 * Decrypt and verify a stored frame chain against its recorded metadata.
 * Pure function over (rows, meta): the journal's own loadVerifiedFrames and
 * the capsule's inline-journal validation (spec 5.4) both run EXACTLY these
 * checks, so a capsule candidate is held to the same standard as local disk.
 *
 * Detects: a tampered payload (AEAD failure), a reordered or transplanted
 * frame (AAD sequence binding plus previousFrameHash linkage), a frame whose
 * plaintext does not match its recorded hash, a gap in the sequence, a
 * truncated tail against the recorded tip, and a first retained frame that
 * is not the recorded base snapshot. Throws on the first violation.
 */
export function verifyFrameChain(
	rows: IStoredRecoveryFrame[],
	meta: IFrameChainMeta,
	masterKey: Buffer,
	nodeId: Buffer
): VerifiedRecoveryChain {
	const frames: RecoveryFrame[] = [];
	let previousHash: Buffer | null = null;
	let previousSequence: bigint | null = null;

	for (const row of rows) {
		const sequence = BigInt(row.sequence);
		const writerEpoch = BigInt(row.writerEpoch);
		if (previousSequence != null && sequence !== previousSequence + 1n) {
			throw new Error(
				`Recovery journal gap: frame ${previousSequence} is followed by ${sequence}`
			);
		}
		// The first loaded frame may follow compaction, so its predecessor
		// hash cannot be checked against a loaded frame; every later one is.
		if (previousHash != null && !row.previousFrameHash.equals(previousHash)) {
			throw new Error(
				`Recovery journal chain break at frame ${sequence}: previous hash mismatch`
			);
		}
		const key = deriveFrameKey(masterKey, nodeId, writerEpoch);
		const aad = frameAad(nodeId, writerEpoch, sequence, row.previousFrameHash);
		let plaintext: Buffer;
		try {
			plaintext = decryptFrame(key, row.ciphertext, aad);
		} catch {
			throw new Error(
				`Recovery journal frame ${sequence} failed authentication (tampered, reordered, or wrong key)`
			);
		}
		if (!hashFrame(plaintext).equals(row.frameHash)) {
			throw new Error(
				`Recovery journal frame ${sequence} hash mismatch (stored hash does not cover this payload)`
			);
		}
		const frame = decodeFrame(plaintext);
		if (
			frame.sequence !== sequence ||
			frame.writerEpoch !== writerEpoch ||
			!frame.previousFrameHash.equals(row.previousFrameHash)
		) {
			throw new Error(
				`Recovery journal frame ${sequence} header mismatch between row and payload`
			);
		}
		frames.push(frame);
		previousHash = row.frameHash;
		previousSequence = sequence;
	}

	// The tip fields are written together, so they must survive together: a
	// journal carrying one without the other is not a fresh journal, it is
	// one whose metadata was partially destroyed, and treating it as
	// tip-less would let the next rewrite re-base from genesis and fork
	// from every replica still holding the erased history.
	if ((meta.tipSequence != null) !== (meta.tipHash != null)) {
		throw new Error(
			'Recovery journal metadata is partial: tip sequence and tip hash ' +
				'must both be present or both be absent'
		);
	}
	const tip =
		meta.tipSequence != null && meta.tipHash != null
			? {
					sequence: BigInt(meta.tipSequence),
					frameHash: Buffer.from(meta.tipHash, 'hex')
			  }
			: null;
	if (!tip && frames.length === 0 && meta.lastSnapshotSequence != null) {
		// Same reasoning for the base record: it only ever exists because
		// frames did.
		throw new Error(
			'Recovery journal truncated: a base snapshot is recorded but no ' +
				'frames exist'
		);
	}
	if (tip) {
		if (frames.length === 0) {
			throw new Error(
				'Recovery journal truncated: a tip is recorded but no frames exist'
			);
		}
		const last = frames[frames.length - 1];
		if (
			last.sequence !== tip.sequence ||
			!previousHash!.equals(tip.frameHash)
		) {
			throw new Error(
				`Recovery journal truncated: chain ends at ${last.sequence}, recorded tip is ${tip.sequence}`
			);
		}
	} else if (frames.length > 0) {
		throw new Error('Recovery journal has frames but no recorded tip');
	}

	// The retained base MUST be the recorded snapshot. Compaction leaves
	// exactly one snapshot as the first frame; without this check, deleting
	// that snapshot yields a contiguous, fully authenticated suffix of
	// deltas that verifies cleanly and then reconstructs an INCOMPLETE
	// database from an empty base. An authenticated chain is not enough;
	// it must also start where the metadata says the state starts.
	if (frames.length > 0) {
		const first = frames[0];
		if (!first.snapshot) {
			throw new Error(
				`Recovery journal is missing its retained base snapshot at frame ${first.sequence}`
			);
		}
		if (
			meta.lastSnapshotSequence == null ||
			first.sequence !== BigInt(meta.lastSnapshotSequence)
		) {
			throw new Error(
				`Recovery journal base snapshot mismatch: loaded ${first.sequence}, expected ${meta.lastSnapshotSequence}`
			);
		}
	}

	return frames as VerifiedRecoveryChain;
}

/**
 * Assert that a decoded frame set's base snapshot (the NEWEST snapshot, the
 * one a reconstruction builds from) may be restored by THIS release. Unlike
 * the write boundary's migration rule, restoration is STRICT: only the
 * exact current schema passes.
 *
 * - A FUTURE schema would deserialize with this release's shape and
 *   silently drop whatever that shape added.
 * - A LEGACY snapshot (absent or pre-2 declaration) is refused too, and
 *   deliberately so, even though a LOCAL journal of the same vintage is
 *   migratable: local migration is safe because the original
 *   channel_key_indices TABLE still holds deleted channels' burned
 *   high-water marks and the repair re-snapshots them. A remote snapshot
 *   from that era has already OMITTED those rows; rebuilding from it and
 *   then stamping the result current would launder the gap into a schema-2
 *   journal and permit key-index reuse. There is nothing to migrate FROM,
 *   so the only safe disposition is refusal (the SCB tier remains the
 *   fallback).
 *
 * Shared by reconstructFromFrames and the capsule's candidate
 * prevalidation, so an incompatible capsule is rejected BEFORE anything
 * touches the restore target.
 */
export function assertFramesReconstructable(frames: RecoveryFrame[]): void {
	let snapshot: RecoveryFrame['snapshot'];
	for (let i = frames.length - 1; i >= 0; i--) {
		if (frames[i].snapshot) {
			snapshot = frames[i].snapshot;
			break;
		}
	}
	// No snapshot at all: reconstructFromFrames has its own refusal for
	// that shape, and a capsule chain without one fails the base binding.
	if (!snapshot) return;
	const declared = snapshot.schemaVersion;
	if (declared === SNAPSHOT_SCHEMA_VERSION) return;
	if (
		declared == null ||
		declared === '' ||
		MIGRATABLE_SNAPSHOT_SCHEMAS.has(declared)
	) {
		throw new Error(
			`recovery: the base snapshot predates schema ` +
				`${SNAPSHOT_SCHEMA_VERSION}: snapshots from that era omit deleted ` +
				`channels' burned key indices, and rebuilding from one could ` +
				`reuse a deleted channel's keys; refusing to reconstruct`
		);
	}
	throw new Error(
		`recovery: the base snapshot declares schema '${declared}', ` +
			`which this release cannot restore; refusing to reconstruct`
	);
}

/**
 * Rebuild every safety-critical table from a verified frame sequence
 * (spec 5.3, deterministic reconstruction).
 *
 * The LAST snapshot frame is the base: its tables are written directly. Every
 * frame after it replays through RecoveryManager.commit on the target, i.e.
 * through the EXACT code path that produced the original writes (applyMutation
 * plus insertOutboxRow with its same-kind supersede and row cap), which is
 * what makes the rebuilt tables byte-identical rather than merely equivalent.
 *
 * Frames at or below the snapshot's sequence are ignored: the snapshot
 * already contains their effects.
 */
export function reconstructFromFrames(
	target: IStorageBackend,
	frames: RecoveryFrame[],
	options: { maxOutboxRowsPerChannel?: number } = {}
): void {
	let snapshotIndex = -1;
	for (let i = frames.length - 1; i >= 0; i--) {
		if (frames[i].snapshot) {
			snapshotIndex = i;
			break;
		}
	}
	// A journal ALWAYS begins with a snapshot (bootstrap or compaction base),
	// so a frame set without one is a suffix of deltas whose base was lost:
	// replaying it into an empty database would produce an authenticated but
	// INCOMPLETE state. Fail closed.
	if (snapshotIndex < 0) {
		throw new Error(
			'Recovery reconstruction requires an authenticated base snapshot'
		);
	}
	// The snapshot's AUTHENTICATED schema declaration gates the restore;
	// the local marker cannot stand in for it because it does not survive
	// the loss of the device.
	assertFramesReconstructable(frames);
	const snapshotSchema = frames[snapshotIndex].snapshot!.schemaVersion;
	// The target must be empty: applySnapshot and replay only insert and
	// replace, so rows already present that the journal never mentions would
	// silently survive into the "reconstructed" state.
	assertEmptyTarget(target);
	applySnapshot(target, frames[snapshotIndex].snapshot!);

	const manager = new RecoveryManager(target, {
		maxOutboxRowsPerChannel: options.maxOutboxRowsPerChannel
	});
	for (let i = snapshotIndex + 1; i < frames.length; i++) {
		const frame = frames[i];
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: frame.mutations,
			outboundMessages: frame.outboundMessages
		});
		if (!result.committed) {
			throw new Error(
				`Reconstruction failed replaying frame ${frame.sequence}: ${result.error?.message}`
			);
		}
		// Preserve outbox provenance: the live path stamps rows with the
		// frame that carried their insert, and replaying THAT frame is what
		// just re-inserted them.
		const ids = result.released
			.map((r) => r.id)
			.filter((id): id is number => id != null);
		if (ids.length && target.setOutboxFrameSequence) {
			target.setOutboxFrameSequence(ids, Number(frame.sequence));
		}
	}
	// Reinstall the schema marker FROM the authenticated snapshot: local
	// metadata died with the lost device, and leaving the restored journal
	// marker-less would read as pre-versioning legacy, letting this or a
	// future boot migrate content it never validated. A pre-field snapshot
	// installs nothing, which is exactly the legacy shape it is.
	if (snapshotSchema != null && snapshotSchema !== '') {
		target.setRecoveryMeta?.(META_SNAPSHOT_SCHEMA, snapshotSchema);
	}
}

/**
 * Throw when the target holds ANY recovery journal state: stored frames, or
 * any of the journal's recovery_meta keys. assertEmptyTarget covers the
 * reconstructed application tables; a restore destination must ALSO be
 * clean of journal residue, or an install would silently overwrite another
 * journal's metadata (and a failed attempt could leave its frames behind).
 */
export function assertNoJournalResidue(target: IStorageBackend): void {
	// ALL stored rows, with no lower bound: loadRecoveryFrames(0) reads
	// strictly-greater-than and would miss a sequence-0 residue row, which
	// then survives the install and leaves the restored journal
	// unverifiable.
	if ((target.loadRecoveryFrames?.() ?? []).length > 0) {
		throw new Error(
			'Recovery restore requires a target with no stored recovery frames'
		);
	}
	// ALL recovery metadata, not just the journal's own keys: a restore
	// target must be a fresh database, and any surviving control record (a
	// writer lease, a startup repair marker) belongs to a previous life the
	// restore would otherwise resurrect alongside the new one. Backends
	// that can enumerate the table are checked exhaustively; the rest fall
	// back to every key this codebase writes.
	const listedKeys = target.listRecoveryMetaKeys?.();
	if (listedKeys !== undefined) {
		if (listedKeys.length > 0) {
			throw new Error(
				`Recovery restore requires a target with no recovery metadata ` +
					`('${listedKeys[0]}' is set)`
			);
		}
		return;
	}
	const residueKeys: readonly string[] = [
		...JOURNAL_META_RESIDUE_KEYS,
		'writer_lease_v1',
		'restore_pending_acquisition_v1',
		META_REPLICATED_THROUGH,
		META_REPLICATED_THROUGH_HASH,
		'guardian_pending_registration_v1',
		'startup_repair_tail'
	];
	for (const key of residueKeys) {
		// PRESENCE is residue: an explicitly stored empty value (a corrupt
		// or cleared-but-not-deleted record) still belongs to the previous
		// life and must not survive into the restored one.
		if (target.getRecoveryMeta?.(key) != null) {
			throw new Error(
				`Recovery restore requires a target with no recovery metadata ` +
					`('${key}' is set)`
			);
		}
	}
}

/** Throw when the reconstruction target already holds journaled state. */
export function assertEmptyTarget(target: IStorageBackend): void {
	const dirty =
		target.loadAllChannels().length > 0 ||
		// Key indices are safety-critical residue too: an orphaned row
		// surviving a restore shifts the next channel's derivation index.
		(target.loadAllChannelKeyIndices?.() ?? []).length > 0 ||
		target.loadAllChainMonitors().length > 0 ||
		target.loadAllPreimages().length > 0 ||
		target.loadAllPayments().length > 0 ||
		target.loadAllPaymentSecrets().length > 0 ||
		target.loadAllHtlcPaymentMappings().length > 0 ||
		target.loadAllForwardedHtlcs().length > 0 ||
		target.loadAllHtlcSharedSecrets().length > 0 ||
		target.loadAllInvoices().length > 0 ||
		(target.loadAllInvoicePathIds?.() ?? []).length > 0 ||
		(target.listForwardingEvents?.() ?? []).length > 0 ||
		(target.loadOutboxMessages?.() ?? []).length > 0;
	if (dirty) {
		throw new Error(
			'Recovery reconstruction requires an EMPTY target database'
		);
	}
}

function applySnapshot(
	target: IStorageBackend,
	snapshot: RecoverySnapshot
): void {
	// Joins the caller's transaction when one is active (a capsule install
	// wraps the whole restore in one); opens its own otherwise.
	withStorageTransaction(target, () => {
		for (const c of snapshot.channels) {
			target.saveChannel(c.channelId, c.state, c.peerPubkey);
		}
		for (const k of snapshot.keyIndices) {
			target.saveChannelKeyIndex(k.channelId, k.channelIndex);
		}
		for (const m of snapshot.chainMonitors) {
			target.saveChainMonitor(m.channelId, m.state);
		}
		for (const p of snapshot.preimages) {
			target.savePreimage(p.paymentHash, p.preimage);
		}
		for (const p of snapshot.payments) {
			target.savePayment(p.paymentHash, p.payment);
		}
		for (const s of snapshot.paymentSecrets) {
			target.savePaymentSecret(s.paymentHash, s.secret);
		}
		for (const m of snapshot.htlcPaymentMappings) {
			target.saveHtlcPaymentMapping(m.key, m.paymentHash);
		}
		for (const f of snapshot.forwardedHtlcs) {
			target.saveForwardedHtlc(f.outKey, f.inChannelId, f.inHtlcId);
		}
		for (const s of snapshot.htlcSharedSecrets) {
			target.saveHtlcSharedSecret(s.key, s.secret);
		}
		for (const i of snapshot.invoices) {
			target.saveInvoice(i.paymentHash, i.invoice);
		}
		for (const i of snapshot.invoicePathIds) {
			target.saveInvoicePathId?.(i.paymentHash, i.pathId);
		}
		for (const event of snapshot.forwardingEvents) {
			target.saveForwardingEvent?.(event);
		}
		for (const row of snapshot.outbox) {
			const { frameSequence, ...message } = row;
			const id = target.saveOutboxMessage?.(message);
			if (id != null && frameSequence != null) {
				target.setOutboxFrameSequence?.([id], frameSequence);
			}
		}
	});
}
