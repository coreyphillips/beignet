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

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { hkdfKey } from '../storage/encryption';
import { IStorageBackend } from '../storage/types';
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

/** Deltas between full-state snapshot frames. */
const DEFAULT_SNAPSHOT_INTERVAL_FRAMES = 256;

export interface IRecoveryJournalOptions {
	/** Append a snapshot frame after this many delta frames. Default 256. */
	snapshotIntervalFrames?: number;
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

export function encryptFrame(
	frameKey: Buffer,
	plaintext: Buffer,
	aad: Buffer
): Buffer {
	const iv = randomBytes(IV_LENGTH);
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

/** True when the backend can persist journal frames (all methods present). */
export function journalSupported(storage: IStorageBackend): boolean {
	return (
		typeof storage.saveRecoveryFrame === 'function' &&
		typeof storage.loadRecoveryFrames === 'function' &&
		typeof storage.getRecoveryMeta === 'function' &&
		typeof storage.setRecoveryMeta === 'function'
	);
}

export class RecoveryJournal implements IRecoveryJournalSink {
	private readonly storage: IStorageBackend;
	private readonly masterKey: Buffer;
	private readonly nodeId: Buffer;
	private readonly snapshotInterval: number;

	constructor(
		storage: IStorageBackend,
		masterKey: Buffer,
		nodeId: Buffer,
		options: IRecoveryJournalOptions = {}
	) {
		if (!journalSupported(storage)) {
			throw new Error('Storage backend does not support the recovery journal');
		}
		this.storage = storage;
		this.masterKey = masterKey;
		this.nodeId = nodeId;
		this.snapshotInterval =
			options.snapshotIntervalFrames ?? DEFAULT_SNAPSHOT_INTERVAL_FRAMES;
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
			return 1n;
		}

		const sequence = BigInt(tipSequence) + 1n;
		const previousFrameHash = Buffer.from(
			this.storage.getRecoveryMeta!(META_TIP_HASH) ??
				GENESIS_HASH.toString('hex'),
			'hex'
		);
		const frameHash = this.writeFrame({
			version: 1,
			writerEpoch: this.writerEpoch(),
			sequence,
			previousFrameHash,
			timestamp: Date.now(),
			mutations,
			outboundMessages
		});

		const lastSnapshot = BigInt(
			this.storage.getRecoveryMeta!(META_LAST_SNAPSHOT) ?? '0'
		);
		if (sequence - lastSnapshot >= BigInt(this.snapshotInterval)) {
			this.appendSnapshotFrame(sequence + 1n, frameHash);
		}
		return sequence;
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
		const stored = this.storage.loadRecoveryFrames!();
		const frames: RecoveryFrame[] = [];
		let previousHash: Buffer | null = null;
		let previousSequence: bigint | null = null;

		for (const row of stored) {
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
			const key = deriveFrameKey(this.masterKey, this.nodeId, writerEpoch);
			const aad = frameAad(
				this.nodeId,
				writerEpoch,
				sequence,
				row.previousFrameHash
			);
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
			if (frame.sequence !== sequence || frame.writerEpoch !== writerEpoch) {
				throw new Error(
					`Recovery journal frame ${sequence} header mismatch between row and payload`
				);
			}
			frames.push(frame);
			previousHash = row.frameHash;
			previousSequence = sequence;
		}

		const tip = this.getTip();
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

		return frames;
	}

	// ─────────────── internals ───────────────

	private writerEpoch(): bigint {
		const epoch = this.storage.getRecoveryMeta!(META_WRITER_EPOCH);
		return epoch == null ? 1n : BigInt(epoch);
	}

	/** Encode, hash, encrypt and store one frame; advance the tip. */
	private writeFrame(frame: RecoveryFrame): Buffer {
		const plaintext = encodeFrame(frame);
		const frameHash = hashFrame(plaintext);
		const key = deriveFrameKey(this.masterKey, this.nodeId, frame.writerEpoch);
		const aad = frameAad(
			this.nodeId,
			frame.writerEpoch,
			frame.sequence,
			frame.previousFrameHash
		);
		this.storage.saveRecoveryFrame!({
			sequence: Number(frame.sequence),
			writerEpoch: Number(frame.writerEpoch),
			frameHash,
			previousFrameHash: frame.previousFrameHash,
			ciphertext: encryptFrame(key, plaintext, aad),
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
		return frameHash;
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
		this.storage.deleteRecoveryFramesBelow?.(Number(sequence));
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
			outbox: (storage.loadOutboxMessages?.() ?? []).map((row) => ({
				peerId: row.peerId,
				channelId: row.channelId,
				messageType: row.messageType,
				wireMessage: row.wireMessage,
				disposition: row.disposition
			}))
		};
	}
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
	if (snapshotIndex >= 0) {
		applySnapshot(target, frames[snapshotIndex].snapshot!);
	}

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
		for (const row of snapshot.outbox) {
			target.saveOutboxMessage?.(row);
		}
	});
}
