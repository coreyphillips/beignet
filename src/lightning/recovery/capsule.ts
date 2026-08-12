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
import {
	CorruptRecoveryRowError,
	IStorageBackend,
	IStoredRecoveryFrame
} from '../storage/types';
import { IStaticChannelBackup, decodeScb } from '../backup/scb';
import { PEER_STORAGE_MAX_BYTES } from '../message/peer-storage';
import { getPublicKey } from '../crypto/ecdh';
import {
	JOURNAL_META_KEYS,
	SNAPSHOT_SCHEMA_VERSION,
	assertEmptyTarget,
	assertFramesReconstructable,
	assertNoJournalResidue,
	decodeStoredHashHex,
	deriveRecoveryMasterKey,
	journalSupported,
	reconstructFromFrames,
	verifyFrameChain
} from './journal';
import { withStorageTransaction } from '../storage/transaction';
import {
	RecoveryFrame,
	RecoveryMutation,
	RecoverySnapshot,
	VerifiedRecoveryChain
} from './types';
import { createOpenerState, IChannelState } from '../channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../channel/types';
import { MonitorState } from '../chain/types';
import { PaymentDirection, PaymentStatus } from '../node/types';

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
 * Every mutation discriminant the probe's delta frames carry, and every
 * snapshot table its base frame populates. These are Records over the REAL
 * union types, so adding a mutation variant or a snapshot field breaks this
 * file's compilation until the probe is extended to exercise it: the probe
 * classifies validator health, and an operation it silently skips is an
 * operation whose backend failure gets laundered into a capsule defect.
 * A test additionally asserts the probe frames really carry each entry.
 */
export const PROBE_MUTATION_COVERAGE: Record<RecoveryMutation['type'], true> = {
	channel_state: true,
	channel_key_index: true,
	chain_monitor: true,
	payment_preimage: true,
	htlc_payment_mapping: true,
	delete_htlc_payment_mapping: true,
	htlc_shared_secret: true,
	delete_htlc_shared_secret: true,
	forwarded_htlc: true,
	delete_forwarded_htlc: true,
	payment_state: true,
	payment_secret: true,
	delete_payment_secret: true,
	delete_payment: true,
	delete_preimage: true,
	invoice_state: true,
	delete_invoice: true,
	invoice_path_id: true,
	delete_invoice_path_id: true,
	forwarding_event: true,
	channel_closed: true,
	outbox_supersede: true
};
export const PROBE_SNAPSHOT_COVERAGE: Record<
	Exclude<keyof RecoverySnapshot, 'schemaVersion'>,
	true
> = {
	channels: true,
	keyIndices: true,
	chainMonitors: true,
	preimages: true,
	payments: true,
	paymentSecrets: true,
	htlcPaymentMappings: true,
	forwardedHtlcs: true,
	htlcSharedSecrets: true,
	invoices: true,
	invoicePathIds: true,
	forwardingEvents: true,
	outbox: true
};

const PROBE_CHANNEL_ID = 'dd'.repeat(32);
const PROBE_HASH = 'bb'.repeat(32);

/**
 * A serializable channel state built by the production constructor, so the
 * probe's channel row can never rot against the serializer's field set the
 * way a handcrafted literal would.
 */
function probeChannelState(): IChannelState {
	const point = getPublicKey(Buffer.alloc(32, 7));
	const state = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 8),
		fundingSatoshis: 1_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: {
			fundingPubkey: point,
			revocationBasepoint: point,
			paymentBasepoint: point,
			delayedPaymentBasepoint: point,
			htlcBasepoint: point,
			firstPerCommitmentPoint: point
		},
		localPerCommitmentSeed: Buffer.alloc(32, 9)
	});
	state.channelId = Buffer.from(PROBE_CHANNEL_ID, 'hex');
	return state;
}

function probeOutboxMessage(): {
	peerId: string;
	channelId: string;
	messageType: number;
	wireMessage: Buffer;
	disposition: 'pending_send';
} {
	return {
		peerId: getPublicKey(Buffer.alloc(32, 7)).toString('hex'),
		channelId: PROBE_CHANNEL_ID,
		messageType: 136,
		wireMessage: Buffer.from([0]),
		disposition: 'pending_send'
	};
}

/**
 * A synthetic, KNOWN-GOOD frame set exercising EVERY operation a real
 * replay can invoke: a current-schema snapshot populating all thirteen
 * tables, one delta carrying every save-side mutation variant plus an
 * outbox insert, and one delta carrying every delete-side variant against
 * rows the earlier frames wrote. If the validator backend cannot replay
 * THIS, the validator is broken, not the capsule; an operation missing
 * here would let that backend's failure on it masquerade as a capsule
 * content defect (see PROBE_MUTATION_COVERAGE / PROBE_SNAPSHOT_COVERAGE).
 */
export function knownGoodProbeFrames(): VerifiedRecoveryChain {
	const snapshot: RecoveryFrame = {
		version: 1,
		writerEpoch: 1n,
		sequence: 1n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 0,
		mutations: [],
		outboundMessages: [],
		snapshot: {
			schemaVersion: SNAPSHOT_SCHEMA_VERSION,
			channels: [
				{
					channelId: PROBE_CHANNEL_ID,
					state: probeChannelState(),
					peerPubkey: getPublicKey(Buffer.alloc(32, 7)).toString('hex')
				}
			],
			keyIndices: [{ channelId: 'aa'.repeat(32), channelIndex: 1 }],
			chainMonitors: [
				{
					channelId: PROBE_CHANNEL_ID,
					state: {
						monitorState: MonitorState.WATCHING,
						commitmentBroadcast: null,
						trackedOutputs: [],
						currentBlockHeight: 0
					}
				}
			],
			preimages: [{ paymentHash: PROBE_HASH, preimage: Buffer.alloc(32, 1) }],
			payments: [
				{
					paymentHash: PROBE_HASH,
					payment: {
						paymentHash: Buffer.from(PROBE_HASH, 'hex'),
						amountMsat: 1n,
						status: PaymentStatus.COMPLETED,
						direction: PaymentDirection.OUTGOING,
						createdAt: 0
					}
				}
			],
			paymentSecrets: [
				{ paymentHash: PROBE_HASH, secret: Buffer.alloc(32, 3) }
			],
			htlcPaymentMappings: [{ key: 'probe:0', paymentHash: PROBE_HASH }],
			forwardedHtlcs: [
				{
					outKey: 'probe:offered-0',
					inChannelId: Buffer.alloc(32, 4),
					inHtlcId: 0n
				}
			],
			htlcSharedSecrets: [{ key: 'probe:0', secret: Buffer.alloc(32, 5) }],
			invoices: [
				{
					paymentHash: PROBE_HASH,
					invoice: {
						paymentHash: PROBE_HASH,
						bolt11: 'lnbcrt1probe',
						expiry: 3600,
						createdAt: 0
					}
				}
			],
			invoicePathIds: [
				{ paymentHash: PROBE_HASH, pathId: Buffer.alloc(32, 6) }
			],
			forwardingEvents: [
				{
					settledAt: 1,
					inChannelId: PROBE_CHANNEL_ID,
					outChannelId: PROBE_CHANNEL_ID,
					amountInMsat: 2n,
					amountOutMsat: 1n,
					feeMsat: 1n
				}
			],
			outbox: [{ ...probeOutboxMessage(), frameSequence: 1 }]
		}
	};
	// Every save-side variant, plus the outbox insert path (which also
	// drives the reconstruct loop's frame stamping on the released row).
	const saves: RecoveryFrame = {
		version: 1,
		writerEpoch: 1n,
		sequence: 2n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 0,
		mutations: [
			{
				type: 'channel_state',
				channelId: PROBE_CHANNEL_ID,
				state: probeChannelState(),
				peerPubkey: getPublicKey(Buffer.alloc(32, 7)).toString('hex')
			},
			{
				type: 'channel_key_index',
				channelId: 'aa'.repeat(32),
				channelIndex: 2
			},
			{
				type: 'chain_monitor',
				channelId: PROBE_CHANNEL_ID,
				state: {
					monitorState: MonitorState.WATCHING,
					commitmentBroadcast: null,
					trackedOutputs: [],
					currentBlockHeight: 1
				}
			},
			{
				type: 'payment_preimage',
				paymentHash: 'cc'.repeat(32),
				preimage: Buffer.alloc(32, 2)
			},
			{
				type: 'htlc_payment_mapping',
				htlcKey: 'probe:1',
				paymentHash: PROBE_HASH
			},
			{
				type: 'htlc_shared_secret',
				key: 'probe:1',
				secret: Buffer.alloc(32, 10)
			},
			{
				type: 'forwarded_htlc',
				outKey: 'probe:offered-1',
				inChannelId: Buffer.alloc(32, 4),
				inHtlcId: 1n
			},
			{
				type: 'payment_state',
				paymentHash: PROBE_HASH,
				payment: {
					paymentHash: Buffer.from(PROBE_HASH, 'hex'),
					amountMsat: 1n,
					status: PaymentStatus.COMPLETED,
					direction: PaymentDirection.OUTGOING,
					createdAt: 0
				}
			},
			{
				type: 'payment_secret',
				paymentHash: PROBE_HASH,
				secret: Buffer.alloc(32, 3)
			},
			{
				type: 'invoice_state',
				paymentHash: PROBE_HASH,
				invoice: {
					paymentHash: PROBE_HASH,
					bolt11: 'lnbcrt1probe',
					expiry: 3600,
					createdAt: 0
				}
			},
			{
				type: 'invoice_path_id',
				paymentHash: PROBE_HASH,
				pathId: Buffer.alloc(32, 6)
			},
			{
				type: 'forwarding_event',
				event: {
					settledAt: 2,
					inChannelId: PROBE_CHANNEL_ID,
					outChannelId: PROBE_CHANNEL_ID,
					amountInMsat: 2n,
					amountOutMsat: 1n,
					feeMsat: 1n
				}
			}
		],
		outboundMessages: [
			probeOutboxMessage(),
			// A second row under a DIFFERENT message type, the target of the
			// deletes frame's FILTERED outbox_supersede.
			{ ...probeOutboxMessage(), messageType: 133 }
		]
	};
	// Every delete-side variant, each against a row frames 1 or 2 wrote, so
	// the deletes genuinely execute instead of no-oping on absent rows.
	const deletes: RecoveryFrame = {
		version: 1,
		writerEpoch: 1n,
		sequence: 3n,
		previousFrameHash: Buffer.alloc(32),
		timestamp: 0,
		mutations: [
			{ type: 'delete_htlc_payment_mapping', htlcKey: 'probe:1' },
			{ type: 'delete_htlc_shared_secret', key: 'probe:1' },
			{ type: 'delete_forwarded_htlc', outKey: 'probe:offered-1' },
			{ type: 'delete_payment_secret', paymentHash: PROBE_HASH },
			{ type: 'delete_payment', paymentHash: PROBE_HASH },
			{ type: 'delete_preimage', paymentHash: 'cc'.repeat(32) },
			{ type: 'delete_invoice', paymentHash: PROBE_HASH },
			{ type: 'delete_invoice_path_id', paymentHash: PROBE_HASH },
			// The FILTERED outbox deletion is a distinct storage path (the
			// message-type list reaches a different SQL shape), so it is
			// exercised separately from the unfiltered sweep below, against
			// the type-133 row frame 2 inserted for exactly this purpose.
			{
				type: 'outbox_supersede',
				channelId: PROBE_CHANNEL_ID,
				messageTypes: [133]
			},
			{ type: 'outbox_supersede', channelId: PROBE_CHANNEL_ID },
			{ type: 'channel_closed', channelId: PROBE_CHANNEL_ID }
		],
		outboundMessages: []
	};
	return [snapshot, saves, deletes] as VerifiedRecoveryChain;
}

/** Forces a deliberate rollback of a probe that SUCCEEDED (never surfaced). */
class ProbeRollback extends Error {}

/**
 * Dry-run the candidate's replay on a scratch backend (see options).
 *
 * A candidate failure alone proves nothing: a generic backend exception
 * cannot say whether the capsule content or the validator's own storage
 * failed, and a TRANSIENT storage hiccup must not be laundered into a
 * permanent content verdict. So a first-attempt failure is retried on an
 * INDEPENDENTLY FRESH instance, which is first PROVED against a synthetic
 * known-good frame set exercising every operation a real replay can invoke
 * (that probe is deliberately rolled back so the instance stays empty),
 * and then handed the candidate again. When the candidate REPRODUCES its
 * failure there, one more probe runs TO COMMIT on the same instance: the
 * rolled-back probe never exercised successful transaction completion, and
 * a backend whose commit path is broken fails candidates for reasons that
 * are its own. Only a candidate failing on an instance that proved BOTH
 * the operation surface and the commit is typed as content; every other
 * combination propagates the RAW candidate error (validator broken), and
 * a candidate that replays cleanly on the proven instance was a transient
 * first failure (the dry-run's question is answered: proceed).
 *
 * Every attempt decodes a FRESH authenticated frame graph via the injected
 * factory: the frames are handed to FOREIGN adapter code (the scratch
 * backend), and a hostile or buggy adapter mutating a Buffer during the
 * first attempt must not poison the retry into a false content verdict.
 */
function assertReplaysOnScratch(
	decodeFrames: () => VerifiedRecoveryChain,
	scratchStorage: () => IStorageBackend
): void {
	const scratch = scratchStorage();
	let candidateErr: unknown;
	try {
		withStorageTransaction(scratch, () => {
			reconstructFromFrames(scratch, decodeFrames());
		});
		return;
	} catch (err) {
		candidateErr = err;
	} finally {
		(scratch as { close?: () => void }).close?.();
	}
	const fresh = scratchStorage();
	try {
		try {
			withStorageTransaction(fresh, () => {
				reconstructFromFrames(fresh, knownGoodProbeFrames());
				// Roll the successful probe back so the candidate replay
				// below runs on the SAME, still-empty, just-proven instance.
				throw new ProbeRollback();
			});
		} catch (probeErr) {
			if (!(probeErr instanceof ProbeRollback)) {
				throw candidateErr;
			}
		}
		try {
			withStorageTransaction(fresh, () => {
				reconstructFromFrames(fresh, decodeFrames());
			});
		} catch (repeatedErr) {
			// Reproduced on the proven instance. Before this is called
			// content, the backend must also COMPLETE a commit: the
			// instance is empty again (the candidate rolled back), so the
			// probe re-runs without the deliberate rollback. A commit that
			// fails here is broken validator infrastructure; the raw
			// candidate error propagates instead of a content verdict.
			try {
				withStorageTransaction(fresh, () => {
					reconstructFromFrames(fresh, knownGoodProbeFrames());
				});
			} catch {
				throw candidateErr;
			}
			throw new CapsuleReplayError(repeatedErr);
		}
		// The first failure did not reproduce: transient validator
		// infrastructure, and the content is proven replayable.
		return;
	} finally {
		(fresh as { close?: () => void }).close?.();
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
		/**
		 * The set-once namespace-loss marker (journal META_BACKFILL_LOST).
		 * Travels in the capsule because no frame can reconstruct it: it is
		 * the only journal meta row with no frame-borne fallback, so a
		 * restore that drops it would report a dead namespace as healthy
		 * (issue #314). Absent when the namespace never lost backfill.
		 */
		backfillLost?: string;
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
	const backfillLost = storage?.getRecoveryMeta?.(
		JOURNAL_META_KEYS.backfillLost
	);
	// Strict decode: a corrupt stored marker row must not compose an inline
	// capsule this module's own decoder refuses (issue #317 rule, matching
	// the tip-hash check below).
	if (backfillLost != null) {
		assertBackfillLostShape(backfillLost, 'stored');
	}

	const capsule: RecoveryCapsule = {
		version: 1,
		encryptedScb: options.encryptedScb,
		writerEpoch: writerEpoch != null ? BigInt(writerEpoch) : 0n,
		latestSequence: tipSequence != null ? BigInt(tipSequence) : 0n,
		// Strict decode: a corrupt stored tip hash must not be replicated to
		// guardians as the anti-rollback locator (issue #317).
		frameHash:
			tipHash != null
				? decodeStoredHashHex(tipHash, 'journal tip hash')
				: ZERO_HASH,
		snapshotHash: ZERO_HASH,
		guardians: options.guardians ?? []
	};

	let inlineError: string | undefined;
	let frames: IStoredRecoveryFrame[] = [];
	if (
		options.allowInline !== false &&
		storage &&
		tipSequence != null &&
		lastSnapshot != null
	) {
		// A frame row that does not decode makes loadRecoveryFrames throw;
		// degrade to SCB plus locator, matching the contract that a journal
		// which fails verification is never inlined.
		try {
			frames = storage.loadRecoveryFrames?.() ?? [];
			const base = frames.find((row) => String(row.sequence) === lastSnapshot);
			if (base) capsule.snapshotHash = base.frameHash;
		} catch (err) {
			inlineError = err instanceof Error ? err.message : String(err);
			frames = [];
		}
	}
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
		if (backfillLost != null) {
			inlineState.meta.backfillLost = backfillLost;
		}
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

/**
 * Decode canonical padded base64 or throw. Buffer.from(s, 'base64') silently
 * drops invalid characters and tolerates truncation; the composer always
 * writes toString('base64'), so a round-trip compare accepts exactly what was
 * written and nothing else (issue #317).
 */
function decodeStrictBase64(value: unknown, field: string): Buffer {
	if (typeof value !== 'string' || value.length === 0) {
		throw new CorruptRecoveryRowError(`${field} is not a base64 string`);
	}
	const decoded = Buffer.from(value, 'base64');
	if (decoded.length === 0 || decoded.toString('base64') !== value) {
		throw new CorruptRecoveryRowError(`${field} is not canonical base64`);
	}
	return decoded;
}

/** Assert a frame field is an integer within range, or throw. */
function inlineInt(value: unknown, field: string, min: number): number {
	if (
		typeof value !== 'number' ||
		!Number.isSafeInteger(value) ||
		value < min
	) {
		throw new CorruptRecoveryRowError(`${field} is not an integer >= ${min}`);
	}
	return value;
}

/**
 * Ceiling on the inline backfill-lost detail string. The two detail strings
 * compactTo writes are a few hundred characters; the bound is defense in
 * depth against a corrupt row, not a security boundary (the capsule is
 * AEAD-sealed under the node secret).
 */
const INLINE_BACKFILL_LOST_MAX_LENGTH = 4096;

/**
 * Assert a backfill-lost marker is a non-empty bounded string, or throw.
 * Shared by compose and decode so the two sides cannot drift: a stored row
 * the decoder would refuse must never compose into an inline capsule.
 */
function assertBackfillLostShape(value: unknown, context: string): void {
	if (
		typeof value !== 'string' ||
		value.length === 0 ||
		value.length > INLINE_BACKFILL_LOST_MAX_LENGTH
	) {
		throw new CorruptRecoveryRowError(
			`${context} backfill-lost marker is not a non-empty string`
		);
	}
}

/** Assert a meta field is a positive decimal string, or throw. */
function inlineMetaNumeric(value: unknown, field: string): string {
	if (typeof value !== 'string' || !/^[1-9]\d*$/.test(value)) {
		throw new CorruptRecoveryRowError(`${field} is not a positive integer`);
	}
	return value;
}

/**
 * Parse an inline Tier 2 payload back into stored rows plus chain metadata.
 *
 * Every field is decoded EXACTLY or refused: the rows this returns are what
 * chain verification runs over and what a restore writes into the target, so
 * a coerced field (truncated hex, non-canonical base64, a stringly-typed
 * sequence) must surface as corruption here rather than flow onward
 * (issue #317).
 */
function parseInlineState(inline: Buffer): {
	encoded: IEncodedInlineState;
	rows: IStoredRecoveryFrame[];
} {
	let parsed: unknown;
	try {
		parsed = JSON.parse(inline.toString('utf8'));
	} catch {
		throw new Error('recovery capsule inline state is not valid JSON');
	}
	const candidate = parsed as IEncodedInlineState;
	if (!Array.isArray(candidate.frames) || candidate.frames.length === 0) {
		throw new Error('recovery capsule inline state carries no frames');
	}
	const meta = candidate.meta;
	if (typeof meta !== 'object' || meta == null) {
		throw new CorruptRecoveryRowError('inline state meta is missing');
	}
	if (typeof meta.tipHash !== 'string') {
		throw new CorruptRecoveryRowError('inline tip hash is not a string');
	}
	decodeStoredHashHex(meta.tipHash, 'inline tip hash');
	// Present-but-malformed is corruption, absent is a healthy namespace (or
	// an older capsule). The marker is not frame-derived, so unlike the
	// writer epoch it cannot be bound to the verified chain; the AEAD seal
	// over the whole capsule is its integrity boundary.
	if (meta.backfillLost !== undefined) {
		assertBackfillLostShape(meta.backfillLost, 'inline');
	}
	const encoded: IEncodedInlineState = {
		meta: {
			tipSequence: inlineMetaNumeric(meta.tipSequence, 'inline tip sequence'),
			tipHash: meta.tipHash,
			writerEpoch: inlineMetaNumeric(meta.writerEpoch, 'inline writer epoch'),
			lastSnapshot: inlineMetaNumeric(
				meta.lastSnapshot,
				'inline snapshot sequence'
			),
			...(meta.backfillLost !== undefined
				? { backfillLost: meta.backfillLost }
				: {})
		},
		frames: candidate.frames
	};
	return {
		encoded,
		rows: encoded.frames.map((row, index) => {
			const label = `inline frame ${index}`;
			if (
				typeof row.frameHash !== 'string' ||
				typeof row.previousFrameHash !== 'string'
			) {
				throw new CorruptRecoveryRowError(
					`${label}: frame hash is not a string`
				);
			}
			return {
				sequence: inlineInt(row.sequence, `${label}: sequence`, 1),
				writerEpoch: inlineInt(row.writerEpoch, `${label}: writerEpoch`, 1),
				frameHash: decodeStoredHashHex(row.frameHash, `${label}: frameHash`),
				previousFrameHash: decodeStoredHashHex(
					row.previousFrameHash,
					`${label}: previousFrameHash`
				),
				ciphertext: decodeStrictBase64(row.ciphertext, `${label}: ciphertext`),
				createdAt: inlineInt(row.createdAt, `${label}: createdAt`, 0)
			};
		})
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
	// The inline metadata epoch is INSTALLED into the target's recovery_meta,
	// so it must be the verified chain's epoch, not a free-floating value
	// parseInlineState only syntax-checked (issue #317). The chain and head
	// checks above never read it; without this bind a tampered epoch would
	// restore at Tier 2 and every frame the restored journal writes would
	// carry it.
	if (BigInt(encoded.meta.writerEpoch) !== last.writerEpoch) {
		throw new Error(
			'recovery capsule inline metadata does not match its verified chain (writer epoch)'
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
		// Every dry-run attempt decodes its OWN authenticated frame graph:
		// the frames reach foreign adapter code, and a mutation during one
		// attempt must not leak into the next.
		assertReplaysOnScratch(
			() => verifyInlineJournal(capsule, nodeSecret).frames,
			options.scratchStorage
		);
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
		// The backfill-lost marker is irreversible namespace state with no
		// frame-borne fallback; dropping it here would let the restored node
		// open channels into a namespace that can never durably record them
		// and settle durability waits with the wrong reason (issue #314).
		// Install-if-present only: assertNoJournalResidue proved the target
		// empty, so this is exactly the marker's set-once contract.
		if (encoded.meta.backfillLost !== undefined) {
			target.setRecoveryMeta!(
				JOURNAL_META_KEYS.backfillLost,
				encoded.meta.backfillLost
			);
		}
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
 * Peek whether an authenticated candidate's inline state carries the
 * backfill-lost marker. Selection-only ordering hint: within a
 * nonconflicting same-head group a marker-bearing replica must be tried
 * before a marker-less twin (an older composer at the same head), or
 * arrival order would decide whether the restored namespace remembers it
 * lost backfill (issue #314). Full validation still happens in
 * verifyInlineJournal; a candidate this misjudges just sorts differently
 * and is verified or refused exactly as before.
 */
function inlineCarriesBackfillLost(capsule: RecoveryCapsule): boolean {
	if (!capsule.inlineRecoveryState) return false;
	try {
		const parsed = JSON.parse(
			capsule.inlineRecoveryState.toString('utf8')
		) as IEncodedInlineState;
		return typeof parsed?.meta?.backfillLost === 'string';
	} catch {
		return false;
	}
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
			// A replica carrying the irreversible backfill-lost marker gets
			// its turn before a marker-less twin at the same head, so which
			// peer's blob happened to arrive first cannot decide whether the
			// marker survives the restore (issue #314).
			const ordered = [
				...group.filter((c) => inlineCarriesBackfillLost(c)),
				...group.filter((c) => !inlineCarriesBackfillLost(c))
			];
			for (const candidate of ordered) {
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
