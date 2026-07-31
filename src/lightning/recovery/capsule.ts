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
	RecoveryJournal,
	deriveRecoveryMasterKey,
	journalSupported,
	reconstructFromFrames
} from './journal';

const CAPSULE_HKDF_INFO = 'beignet-recovery-capsule-v1';
const CAPSULE_MAGIC = 'bRC1';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const ZERO_HASH = Buffer.alloc(32);

/** Wire budget for the encrypted capsule blob (distributePeerStorage framing). */
export const CAPSULE_MAX_BYTES = PEER_STORAGE_MAX_BYTES - 8;

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
}

export interface RecoveryCapsule {
	version: 1;
	/** encodeScb output: always sufficient for Tier 1 emergency recovery. */
	encryptedScb: string;
	/** Journal locator: the latest locally durable head (zeros when none). */
	writerEpoch: bigint;
	latestSequence: bigint;
	frameHash: Buffer;
	/** Frame hash of the retained base snapshot (zeros when none). */
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
 * Pick the best capsule from decrypted candidates: highest (writerEpoch,
 * latestSequence), per the restore rule in spec 5.4. Ties are fine; any of
 * the tied capsules describes the same head.
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
}

export interface IComposedCapsule {
	/** Encrypted, magic-prefixed blob, ready for distributePeerStorage. */
	blob: Buffer;
	capsule: RecoveryCapsule;
	/** Whether the full journal fit inline (Tier 2 from peer_storage alone). */
	inline: boolean;
}

/**
 * Compose and encrypt the current capsule. Tries the full inline journal
 * first; if the encrypted blob would not fit the peer-storage budget, falls
 * back to SCB + locator (spec 5.4: oversized state degrades gracefully).
 * Throws only when even the SCB-only capsule is oversized, which mirrors
 * distributePeerStorage's own loud failure on oversized blobs.
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
	if (storage && tipSequence != null && lastSnapshot != null) {
		frames = storage.loadRecoveryFrames?.() ?? [];
		const base = frames.find((row) => String(row.sequence) === lastSnapshot);
		if (base) capsule.snapshotHash = base.frameHash;
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
	return { blob, capsule, inline: false };
}

export interface ICapsuleRestoreResult {
	/** 2 = exact state reconstructed from the inline journal; 1 = SCB only. */
	tier: 1 | 2;
	/** Decoded Tier 1 backup, always present and already authenticated. */
	scb: IStaticChannelBackup;
	/** Tier 2: frames verified and replayed into the target. */
	framesApplied: number;
}

/**
 * Restore from a decrypted capsule into an EMPTY target database.
 *
 * Tier 2 path (inline journal present and the target supports frames):
 * install the stored frame rows and journal metadata, then run the exact
 * Phase 2 verification and reconstruction (loadVerifiedFrames +
 * reconstructFromFrames). The capsule's own head fields must match the
 * installed chain's tip; a mismatch means the inline payload is not the
 * journal this capsule described, and the restore fails closed. On ANY
 * tier 2 throw the target must be discarded; partial installs are not
 * cleaned up.
 *
 * Tier 1 path (no inline state): the decoded SCB is returned for
 * recoverFromStaticChannelBackup, exactly like a plain SCB restore.
 */
export function restoreFromRecoveryCapsule(
	capsule: RecoveryCapsule,
	target: IStorageBackend,
	nodeSecret: Buffer
): ICapsuleRestoreResult {
	// Authenticates the Tier 1 material up front: wrong-key or tampered SCBs
	// fail here before anything touches the target.
	const scb = decodeScb(capsule.encryptedScb, nodeSecret);

	if (!capsule.inlineRecoveryState || !journalSupported(target)) {
		return { tier: 1, scb, framesApplied: 0 };
	}

	let inline: IEncodedInlineState;
	try {
		inline = JSON.parse(
			capsule.inlineRecoveryState.toString('utf8')
		) as IEncodedInlineState;
	} catch {
		throw new Error('recovery capsule inline state is not valid JSON');
	}
	if (!Array.isArray(inline.frames) || inline.frames.length === 0) {
		throw new Error('recovery capsule inline state carries no frames');
	}

	target.transaction(() => {
		for (const row of inline.frames) {
			target.saveRecoveryFrame!({
				sequence: row.sequence,
				writerEpoch: row.writerEpoch,
				frameHash: Buffer.from(row.frameHash, 'hex'),
				previousFrameHash: Buffer.from(row.previousFrameHash, 'hex'),
				ciphertext: Buffer.from(row.ciphertext, 'base64'),
				createdAt: row.createdAt
			});
		}
		target.setRecoveryMeta!(
			JOURNAL_META_KEYS.tipSequence,
			inline.meta.tipSequence
		);
		target.setRecoveryMeta!(JOURNAL_META_KEYS.tipHash, inline.meta.tipHash);
		target.setRecoveryMeta!(
			JOURNAL_META_KEYS.writerEpoch,
			inline.meta.writerEpoch
		);
		target.setRecoveryMeta!(
			JOURNAL_META_KEYS.lastSnapshot,
			inline.meta.lastSnapshot
		);
	});

	const journal = new RecoveryJournal(
		target,
		deriveRecoveryMasterKey(nodeSecret),
		getPublicKey(nodeSecret)
	);
	const frames = journal.loadVerifiedFrames();
	const last = frames[frames.length - 1];
	// The capsule binds the chain: its head fields are the recency anchor the
	// restore selected on, so the installed chain must END there.
	if (
		last.sequence !== capsule.latestSequence ||
		last.writerEpoch !== capsule.writerEpoch ||
		!hashOfLastFrame(target).equals(capsule.frameHash)
	) {
		throw new Error(
			'recovery capsule head does not match its inline journal (stale or spliced payload)'
		);
	}
	reconstructFromFrames(target, frames);
	return { tier: 2, scb, framesApplied: frames.length };
}

/** Stored hash of the highest-sequence frame row in the target. */
function hashOfLastFrame(target: IStorageBackend): Buffer {
	const rows = target.loadRecoveryFrames!();
	return rows.length ? rows[rows.length - 1].frameHash : ZERO_HASH;
}
