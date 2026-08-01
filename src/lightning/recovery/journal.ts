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
 * The journal's recovery_meta keys, exported for the capsule (spec 5.4),
 * which snapshots them alongside the stored frames so a restore can install
 * a verifiable journal into an empty database.
 */
export const JOURNAL_META_KEYS = {
	tipSequence: META_TIP_SEQUENCE,
	tipHash: META_TIP_HASH,
	writerEpoch: META_WRITER_EPOCH,
	lastSnapshot: META_LAST_SNAPSHOT
} as const;

/** Deltas between full-state snapshot frames. */
const DEFAULT_SNAPSHOT_INTERVAL_FRAMES = 256;
/** Delta plaintext bytes between snapshots (spec 5.3: N frames OR M bytes). */
const DEFAULT_SNAPSHOT_INTERVAL_BYTES = 4 * 1024 * 1024;

export interface IRecoveryJournalOptions {
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

export class RecoveryJournal implements IRecoveryJournalSink {
	private readonly storage: IStorageBackend;
	private readonly masterKey: Buffer;
	private readonly nodeId: Buffer;
	private readonly recoveryId: Buffer;
	private readonly snapshotInterval: number;
	private readonly snapshotIntervalBytes: number;
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
		const lastSnapshot = BigInt(
			this.storage.getRecoveryMeta!(META_LAST_SNAPSHOT) ?? '0'
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
		this.storage.setRecoveryMeta!(META_LAST_SNAPSHOT, sequence.toString());
		this.storage.setRecoveryMeta!(META_DELTA_BYTES, '0');
		this.storage.deleteRecoveryFramesBelow!(Number(sequence));
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
