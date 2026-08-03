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
import { deriveFrameIv } from './guardian-wire';
import { hkdfKey } from '../storage/encryption';
import { IStorageBackend, IStoredRecoveryFrame } from '../storage/types';
import { decodeFrame, encodeFrame, hashFrame } from './frame-codec';
import { RecoveryManager } from './recovery-manager';
import {
	IRecoveryJournalSink,
	RecoveryCriticality,
	RecoveryDurability,
	RecoveryFrame,
	RecoveryMutation,
	RecoveryOutboundMessage,
	RecoverySnapshot
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
 * Monotonic record that this journal has written at least one `quorum` frame
 * (Phase 6, spec 5.8). Only ever set, never cleared: it is the writer's own
 * memory of a promise it made to every future restore of this chain.
 */
const META_DURABILITY_FLOOR = 'journal_durability_floor';

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
	durabilityFloor: META_DURABILITY_FLOOR
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
	 * guardian would grow the journal without bound. Default 1024.
	 *
	 * A gap rather than a frame count, and the distinction is deliberate: past
	 * compactions mean the retained rows are at most the gap, never more, so
	 * measuring the gap trips the ceiling no later than counting rows would.
	 * Crossing it orphans every guardian behind the watermark, not one lagging
	 * replica, and the namespace then has to be re-provisioned; that is why
	 * the default is high and the event that reports it says so.
	 */
	maxRetainedFrameGap?: number;
	/** Compaction pruned frames a replica had not yet received. */
	onCompactionForced?: (detail: string) => void;
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
function frameAad(
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
		typeof storage.setRecoveryMeta === 'function'
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
	private readonly maxRetainedFrameGap: number;
	private readonly onCompactionForced: ((detail: string) => void) | undefined;
	/** Set once this run's first append has re-based the chain (see appendFrame). */
	private rebasedThisRun = false;

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
		this.maxRetainedFrameGap =
			options.maxRetainedFrameGap ?? DEFAULT_MAX_RETAINED_FRAME_GAP;
		this.onCompactionForced = options.onCompactionForced;
	}

	/** The mode this journal stamps on its frames, after the sticky rule. */
	getDurability(): RecoveryDurability | undefined {
		return this.durability;
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
	loadVerifiedFrames(): RecoveryFrame[] {
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
		this.rebasedThisRun = true;
	}

	// ─────────────── internals ───────────────

	private writerEpoch(): bigint {
		const epoch = this.storage.getRecoveryMeta!(META_WRITER_EPOCH);
		return epoch == null ? 1n : BigInt(epoch);
	}

	/** Encode, hash, encrypt and store one frame; advance the tip. */
	private writeFrame(frame: RecoveryFrame): {
		frameHash: Buffer;
		plaintextBytes: number;
	} {
		// Stamped here rather than at each construction site so that deltas,
		// bootstrap snapshots, per-run re-base snapshots and interval snapshots
		// all carry the same declaration; a snapshot that omitted it would be a
		// certified head that says nothing about what its writer promised.
		if (this.durability) frame.durability = this.durability;
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
			const held = snapshotSequence - floor;
			if (held <= BigInt(this.maxRetainedFrameGap)) return;
			// Nothing behind this point is coming back on its own. Be exact
			// about the cost: the floor is the QUORUM watermark, so crossing
			// the ceiling orphans every guardian that has not caught up, not
			// one lagging replica, and the namespace has to be re-provisioned
			// from a fresh registration. The alternative is a journal that
			// grows without bound behind a guardian set that is simply gone,
			// so the ceiling is deliberately high rather than absent.
			this.onCompactionForced?.(
				`compaction pruned to frame ${snapshotSequence} while the quorum had ` +
					`only reached frame ${
						floor - 1n
					}: the ${held} frame gap exceeded the ` +
					`${this.maxRetainedFrameGap} frame retention ceiling, so every guardian ` +
					`behind that point can no longer be backfilled and this namespace has ` +
					`to be re-provisioned`
			);
		}
		this.storage.deleteRecoveryFramesBelow!(Number(snapshotSequence));
		this.storage.setRecoveryMeta!(
			META_LAST_SNAPSHOT,
			snapshotSequence.toString()
		);
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
		this.storage.transaction(() => this.compactTo(target));
	}

	/** Serialize every safety-critical table (see RecoverySnapshot). */
	private captureSnapshot(): RecoverySnapshot {
		const storage = this.storage;
		const channels = storage.loadAllChannels();
		return {
			channels: channels.map((c) => ({
				channelId: c.channelId,
				state: c.state,
				peerPubkey: c.peerPubkey
			})),
			keyIndices: channels
				.map((c) => ({
					channelId: c.channelId,
					channelIndex: storage.loadChannelKeyIndex(c.channelId)
				}))
				.filter(
					(k): k is { channelId: string; channelIndex: number } =>
						k.channelIndex != null
				),
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
): RecoveryFrame[] {
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

	const tip =
		meta.tipSequence != null && meta.tipHash != null
			? {
					sequence: BigInt(meta.tipSequence),
					frameHash: Buffer.from(meta.tipHash, 'hex')
			  }
			: null;
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

	return frames;
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
}

/** Throw when the reconstruction target already holds journaled state. */
function assertEmptyTarget(target: IStorageBackend): void {
	const dirty =
		target.loadAllChannels().length > 0 ||
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
	target.transaction(() => {
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
