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
	deriveRecoveryMasterKey,
	journalSupported,
	reconstructFromFrames,
	verifyFrameChain
} from './journal';
import { RecoveryFrame } from './types';

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
	frames: RecoveryFrame[];
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
	return { encoded, rows, frames };
}

/**
 * Restore from a decrypted capsule into an EMPTY target database.
 *
 * Tier 2 path (inline journal present and the target supports frames): the
 * inline journal is verified COMPLETELY before anything touches the target
 * (verifyInlineJournal: the exact Phase 2 chain checks plus the capsule head
 * binding). Only then are the stored frame rows and journal metadata
 * installed and the deltas replayed through reconstructFromFrames. On ANY
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

	// Validate the candidate COMPLETELY before the first write to the target.
	const { encoded, rows, frames } = verifyInlineJournal(capsule, nodeSecret);

	target.transaction(() => {
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
	});
	reconstructFromFrames(target, frames);
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
	nodeSecret: Buffer
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
				// Throws from here PROPAGATE: after a candidate validated,
				// failures are target integrity problems (dirty database,
				// write errors), not candidate defects, and trying another
				// blob against a half-written target would be wrong.
				const result = restoreFromRecoveryCapsule(
					candidate,
					target,
					nodeSecret
				);
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
