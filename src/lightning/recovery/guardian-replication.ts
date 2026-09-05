/**
 * Node-side guardian wiring (docs/RECOVERY-PROTOCOL.md 5.5 and 5.6,
 * Phase 5): establishing the namespace, and replicating journal frames to
 * the guardian set as signed records.
 *
 * Two jobs, deliberately separated:
 *
 * - Establishing ownership. A node with guardians configured may NEVER
 *   conclude "register fresh" from local state: a lost genesis lease and a
 *   node that never enabled guardians are indistinguishable on disk (see
 *   WriterLeaseLoad). So the decision is made by ASKING the set: only a
 *   read quorum reporting the namespace unknown authorizes REGISTER_NODE.
 *   A namespace that already exists means restore or takeover, which is
 *   the restore driver's job, and no quorum means stay quarantined.
 * - Replicating records. Journal frames are already the ciphertext the
 *   guardian stores (wire 3.2), so replication signs the RECORD transcript
 *   over the frame's own position and hashes and fans the record out. This
 *   is BEST EFFORT by design: Phase 5 replicates, Phase 6 adds the quorum
 *   barriers that make an irreversible transition wait for its receipts.
 *   Replication failure here therefore degrades durability, never
 *   correctness, and never blocks a channel.
 */

import { createHash } from 'crypto';
import { IStorageBackend, IStoredRecoveryFrame } from '../storage/types';
import {
	GuardianState,
	genesisLogHead,
	parseStateBytes,
	recordTranscriptHash,
	registerTranscriptHash,
	signTranscript,
	stateBytes,
	statesEqual,
	xOnlyFromSecret
} from './guardian-wire';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	GuardianStatus,
	IGuardianRecord,
	IGuardianReceipt,
	IGuardianRegisterNodeRequest,
	IGuardianRotateSetRequest,
	IGuardianGetHeadResponse
} from './guardian';
import {
	IBoundGuardianClient,
	IGuardianSetContext,
	boundFanOut,
	countReceiptQuorum,
	verifyGuardianBindings,
	verifyGuardianReceipt,
	verifyGuardianRotation,
	IGuardianFanOutResult
} from './guardian-client';
import {
	JOURNAL_META_KEYS,
	chainLostBackfill,
	storedTipSequence,
	resolveWatermarkAnchor,
	META_REPLICATED_THROUGH,
	META_REPLICATED_THROUGH_HASH
} from './journal';
import {
	IWriterLeaseKeys,
	generateWriterKey,
	loadWriterLease,
	prepareWriterLease,
	requireEncryptedSecretStorage
} from './writer-lease';

/** A registration already sent to at least one guardian (see below). */
const META_PENDING_REGISTRATION = 'guardian_pending_registration_v1';
/** The namespace generation (wire 5.9); absent reads as 1. */
export const META_GENERATION = JOURNAL_META_KEYS.generation;
/** The configured guardian set as it stands, JSON entries (a rotation moves it). */
export const META_GUARDIAN_SET = 'guardian_set_v1';

export const REPLICATION_META_KEYS = {
	replicatedThrough: META_REPLICATED_THROUGH,
	replicatedThroughHash: META_REPLICATED_THROUGH_HASH,
	pendingRegistration: META_PENDING_REGISTRATION,
	generation: META_GENERATION,
	guardianSet: META_GUARDIAN_SET
} as const;

/**
 * A stored registration attempt is unreadable. Like a corrupt acquisition,
 * this is NEVER equivalent to "no attempt": a guardian may already have
 * registered the namespace under the key it described, and only the
 * byte-identical registration can complete that.
 */
export class CorruptPendingRegistrationError extends Error {
	constructor(message: string) {
		super(`pending registration is corrupt: ${message}`);
		this.name = 'CorruptPendingRegistrationError';
	}
}

interface IPersistedRegistrationV1 {
	version: 1;
	initialState: string;
	writerSecret: string;
	writerPublicKey: string;
}

function decodeRegistrationHex(
	value: unknown,
	bytes: number,
	field: string
): Buffer {
	if (typeof value !== 'string' || value.length !== bytes * 2) {
		throw new CorruptPendingRegistrationError(
			`${field} is not ${bytes} hex bytes`
		);
	}
	if (!/^[0-9a-f]*$/i.test(value)) {
		throw new CorruptPendingRegistrationError(`${field} is not hexadecimal`);
	}
	return Buffer.from(value, 'hex');
}

function sha256(data: Buffer): Buffer {
	return createHash('sha256').update(data).digest();
}

/**
 * What asking the guardian set concluded about this namespace. Every
 * outcome except `registered` is a REFUSAL to invent state locally.
 */
export type NamespaceDecision =
	/** The namespace was rotated away from this set (wire 5.11): follow it. */
	| { outcome: 'rotated'; rotation: IGuardianRotateSetRequest }
	| { outcome: 'already-held'; lease: IWriterLeaseKeys }
	| { outcome: 'registered'; lease: IWriterLeaseKeys }
	| {
			/** The namespace exists remotely: restore or ACQUIRE_EPOCH, never register. */
			outcome: 'exists-remotely';
			states: GuardianState[];
	  }
	| {
			/** Fewer than `required` guardians answered: no fencing, no recency. */
			outcome: 'no-quorum';
			responded: number;
	  }
	| {
			/** Guardians disagree about whether the namespace exists at all. */
			outcome: 'inconsistent';
			detail: string;
	  };

export interface IGuardianReplicationConfig {
	storage: IStorageBackend;
	/** Guardians bound to the identities they must prove they hold. */
	guardians: IBoundGuardianClient[];
	/** The committed set: id plus member keys, for verifying receipts. */
	context: IGuardianSetContext;
	/** Distinct receipts that make a record durable (2 in crash-v1). */
	required: number;
	/** Namespace authority: signs registration, never records (wire 1.1). */
	recoveryRoot: { rootSecret: Buffer; recoveryId: Buffer };
	/** Injectable for tests; unix milliseconds. */
	clock?: () => bigint;
	/** Replication and namespace events, for operator visibility. */
	onEvent?: (event: IGuardianReplicationEvent) => void;
	/** Persisting the lease into unencrypted storage, opted into explicitly. */
	allowUnencryptedSecrets?: boolean;
	/**
	 * How many records may be in flight to ONE guardian at a time (Phase 6).
	 * Spec 5.3: "Appends are pipelined. The writer streams frames to each
	 * guardian in sequence order without waiting for the previous receipt."
	 * Default 8; 1 makes the stream strictly sequential.
	 */
	pipelineWindow?: number;
	/**
	 * Prefix for the replication watermark keys, so a SECOND replicator can
	 * run over the same journal without touching the live one's bookkeeping:
	 * a rotation (guardian-rotation.ts) backfills the incoming set under a
	 * prefix and moves the watermark to the main keys at the switch.
	 */
	metaKeyPrefix?: string;
	/**
	 * The generation this replicator registers and signs under, when it is
	 * not the journal's current one: a rotation registers the incoming set
	 * at generation + 1 before the journal records the switch.
	 */
	generationOverride?: bigint;
}

export interface IGuardianReplicationEvent {
	type:
		| 'namespace:registered'
		| 'namespace:exists'
		| 'namespace:no-quorum'
		| 'namespace:inconsistent'
		| 'record:replicated'
		| 'record:under-replicated'
		| 'record:rejected'
		| 'record:conflict'
		| 'writer:fenced'
		| 'writer:supersession-unproven';
	detail: string;
	sequence?: bigint;
	/** Distinct verified receipts a record collected. */
	receipts?: number;
}

export interface IReplicationResult {
	/**
	 * `fenced` is TERMINAL and is the async-mode hard-freeze signal from
	 * spec 5.6: another device took the epoch while this one was running, so
	 * this writer must stop before any further channel activity. Startup
	 * confirmation protects a device that is starting; only this protects a
	 * device that was already running when it was superseded.
	 */
	outcome: 'replicated' | 'under-replicated' | 'fenced';
	/** Frames attempted in this pass. */
	attempted: number;
	/** Frames that reached `required` distinct verified receipts. */
	durable: number;
	/** Highest sequence that reached the quorum, contiguously from the start. */
	replicatedThrough: bigint;
	/** On `fenced`: the newer state, proven by a verified receipt. */
	verifiedCurrentState?: GuardianState;
	/** On `fenced`: this namespace was rotated to another set (wire 5.9). */
	rotatedTo?: IGuardianRotateSetRequest;
	/** On `fenced`: the epoch this node believed it held. */
	localEpoch?: bigint;
}

/** Frames one guardian may hold in flight at once (spec 5.3, pipelining). */
const DEFAULT_PIPELINE_WINDOW = 8;

/**
 * What one guardian's stream achieved: the highest sequence it PROVED it
 * holds, and the highest it merely reported. Only the proven one counts
 * toward a quorum; the reported one exists to re-anchor the stream after an
 * out-of-order arrival, because a gap rejection is unsigned (wire 4.2 returns
 * `current` without a receipt) and can therefore steer but never certify.
 */
interface IGuardianStreamResult {
	/** Verified receipt head, or null when nothing was proven. */
	provenThrough: bigint | null;
	/** Any epoch rejection seen, which triggers the supersession check. */
	sawSupersession: boolean;
	/** A retired-set answer seen, which triggers the rotation check (wire 5.11). */
	sawRetired: boolean;
	/** A guardian holding a DIFFERENT record at one of our sequences. */
	conflictAt: bigint | null;
	requests: number;
}

export class GuardianReplicator {
	private readonly config: IGuardianReplicationConfig;
	private readonly clock: () => bigint;
	private readonly pipelineWindow: number;

	private verifiedBindings: Set<string> | null = null;
	/**
	 * Single-flight over replicatePending. Two overlapping passes would fan
	 * the same records out twice and, worse, race the watermark: each computes
	 * its own contiguous prefix from the value it read at entry, so the slower
	 * one can write a LOWER mark over the faster one's. Under Phase 6 that is
	 * a released barrier being forgotten across a restart.
	 */
	private inFlight: Promise<IReplicationResult> | null = null;

	/** The bookkeeping keys, prefixed for a rotation's incoming replicator. */
	private get keys(): {
		replicatedThrough: string;
		replicatedThroughHash: string;
		pendingRegistration: string;
	} {
		const prefix = this.config.metaKeyPrefix ?? '';
		return {
			replicatedThrough: prefix + META_REPLICATED_THROUGH,
			replicatedThroughHash: prefix + META_REPLICATED_THROUGH_HASH,
			pendingRegistration: prefix + META_PENDING_REGISTRATION
		};
	}

	constructor(config: IGuardianReplicationConfig) {
		if (config.guardians.length === 0) {
			throw new Error('guardian replication needs at least one guardian');
		}
		if (config.required < 1 || config.required > config.guardians.length) {
			throw new Error('required quorum is outside the configured guardian set');
		}
		this.config = config;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
		this.pipelineWindow = Math.max(
			1,
			config.pipelineWindow ?? DEFAULT_PIPELINE_WINDOW
		);
	}

	/**
	 * Prove every endpoint is the guardian it claims to be before any of its
	 * answers count. Quorums are over DISTINCT guardians, and a URL is not
	 * an identity.
	 */
	private async ensureBindings(): Promise<Set<string>> {
		if (this.verifiedBindings) return this.verifiedBindings;
		this.verifiedBindings = await verifyGuardianBindings(
			this.config.guardians,
			this.config.context
		);
		return this.verifiedBindings;
	}

	private emit(event: IGuardianReplicationEvent): void {
		this.config.onEvent?.(event);
	}

	/**
	 * Read a persisted registration attempt, or null when none exists. A
	 * stored-but-unreadable attempt THROWS, for the same reason a corrupt
	 * acquisition does: concluding "none" would generate a NEW writer key,
	 * and a guardian that already accepted the old one would leave this
	 * device permanently unable to write under the genesis lease it holds.
	 */
	private loadPendingRegistration(): {
		initialState: GuardianState;
		writer: { secret: Buffer; publicKey: Buffer };
	} | null {
		const raw = this.config.storage.getRecoveryMeta?.(
			this.keys.pendingRegistration
		);
		if (raw == null) return null;
		let parsed: IPersistedRegistrationV1;
		try {
			parsed = JSON.parse(raw) as IPersistedRegistrationV1;
		} catch {
			throw new CorruptPendingRegistrationError(
				'stored blob is not valid JSON'
			);
		}
		if (typeof parsed !== 'object' || parsed === null) {
			throw new CorruptPendingRegistrationError('stored blob is not an object');
		}
		if (parsed.version !== 1) {
			throw new CorruptPendingRegistrationError(
				`unsupported stored version ${String(parsed.version)}`
			);
		}
		const secret = decodeRegistrationHex(
			parsed.writerSecret,
			32,
			'writerSecret'
		);
		const publicKey = decodeRegistrationHex(
			parsed.writerPublicKey,
			32,
			'writerPublicKey'
		);
		if (!ecc.isPrivate(secret)) {
			throw new CorruptPendingRegistrationError(
				'writer secret is not a valid secp256k1 scalar'
			);
		}
		if (!xOnlyFromSecret(secret).equals(publicKey)) {
			throw new CorruptPendingRegistrationError(
				'writer public key does not belong to the writer secret'
			);
		}
		const initialState = parseStateBytes(
			decodeRegistrationHex(parsed.initialState, 192, 'initialState')
		);
		if (!initialState.lease.writerPublicKey.equals(publicKey)) {
			throw new CorruptPendingRegistrationError(
				'the registered state names a different writer key'
			);
		}
		if (!initialState.recoveryId.equals(this.config.recoveryRoot.recoveryId)) {
			throw new CorruptPendingRegistrationError(
				'the registered state belongs to a different recovery namespace'
			);
		}
		return { initialState, writer: { secret, publicKey } };
	}

	private savePendingRegistration(
		initialState: GuardianState,
		writer: { secret: Buffer; publicKey: Buffer }
	): void {
		// Holds a signing key, so it gets the lease's storage protection.
		requireEncryptedSecretStorage(
			this.config.storage,
			this.config.allowUnencryptedSecrets
		);
		const payload: IPersistedRegistrationV1 = {
			version: 1,
			initialState: stateBytes(initialState).toString('hex'),
			writerSecret: writer.secret.toString('hex'),
			writerPublicKey: writer.publicKey.toString('hex')
		};
		this.config.storage.setRecoveryMeta?.(
			this.keys.pendingRegistration,
			JSON.stringify(payload)
		);
	}

	/**
	 * The origin this namespace must be registered with (wire 4.1): a fresh
	 * journal starts at sequence 1 with a zero predecessor; a node enabling
	 * guardians MID-JOURNAL registers its retained base position instead, so
	 * the node-wide journal numbering carries over without renumbering.
	 */
	/**
	 * The namespace generation this set carries (wire 5.9): 1 until a
	 * rotation has raised it, read from the journal's metadata so a
	 * restart and a rotation agree.
	 */
	generation(): bigint {
		if (this.config.generationOverride !== undefined) {
			return this.config.generationOverride;
		}
		const raw = this.config.storage.getRecoveryMeta?.(META_GENERATION);
		if (raw == null) return 1n;
		try {
			const value = BigInt(raw);
			return value >= 1n ? value : 1n;
		} catch {
			return 1n;
		}
	}

	private chainOrigin(): { firstSequence: bigint; previousHash: Buffer } {
		const storage = this.config.storage;
		const frames = storage.loadRecoveryFrames?.() ?? [];
		if (frames.length === 0) {
			return { firstSequence: 1n, previousHash: Buffer.alloc(32) };
		}
		const base = frames[0];
		return {
			firstSequence: BigInt(base.sequence),
			previousHash: Buffer.from(base.previousFrameHash)
		};
	}

	/**
	 * A rotation a guardian attached to its head, IF it is evidence: root
	 * signed over THIS set's prefix and above the generation this journal
	 * carries (wire 5.11). Unsigned attachments are claims, and only the
	 * root can move a namespace. The judgement is verifyGuardianRotation,
	 * the same one the restore driver applies, over the same rule the
	 * guardian applies to its own marker.
	 */
	private verifiedRotation(
		response:
			| { rotation?: IGuardianRotateSetRequest; generation?: bigint }
			| undefined
	): IGuardianRotateSetRequest | null {
		return verifyGuardianRotation(
			response,
			this.config.context,
			this.config.recoveryRoot.recoveryId,
			this.generation()
		);
	}

	/**
	 * Establish ownership of the namespace, asking the guardian set rather
	 * than inferring from local state (spec 5.6, 5.7). Registration happens
	 * ONLY when a read quorum reports the namespace unknown.
	 */
	async ensureNamespace(): Promise<NamespaceDecision> {
		const held = loadWriterLease(this.config.storage);
		if (held.state === 'present') {
			return { outcome: 'already-held', lease: held.lease };
		}

		const verified = await this.ensureBindings();
		const recoveryId = this.config.recoveryRoot.recoveryId;
		const heads = await boundFanOut(this.config.guardians, (client) =>
			client.getHead(recoveryId)
		);
		// A rotation on ANY head redirects before anything else is decided:
		// the live chain is with the incoming set, and registering, restoring
		// or taking over here would act on a retired namespace (wire 5.9).
		for (const entry of heads) {
			const rotation = this.verifiedRotation(entry.result);
			if (rotation) {
				this.emit({
					type: 'namespace:exists',
					detail: `this namespace was rotated to generation ${rotation.generation}; following it`
				});
				return { outcome: 'rotated', rotation };
			}
		}
		// Two DIFFERENT kinds of evidence, and conflating them is dangerous.
		//
		// RECENCY (what the current head and owner are) requires a guardian
		// that can prove its store intact, so possibly_stale answers are
		// excluded: an uncertain store cannot establish what is current.
		//
		// EXISTENCE (whether this namespace was ever registered) does NOT.
		// A possibly_stale guardian holding a valid signed registration still
		// proves the namespace exists, because a receipt remains a true
		// statement about what that guardian stored even after a rollback
		// (wire 4.2). Ignoring it would let two unknown guardians authorize a
		// SECOND GENESIS for a namespace that already exists.
		const allAnswered = heads.filter((entry) => entry.result !== undefined);
		const answered = allAnswered.filter(
			(entry) => entry.result?.possiblyStale !== true
		);
		// Negative answers carry no signature, so they count by BOUND identity,
		// and only for endpoints that PROVED that identity through INFO.
		const unknown = new Set(
			answered
				.filter(
					(entry) => entry.result?.status === GuardianStatus.ERR_UNKNOWN_NODE
				)
				.map((entry) => (entry.guardianId as Buffer).toString('hex'))
				.filter((id) => verified.has(id))
		);
		// EXISTENCE IS EVALUATED FIRST, before any quorum gate. A namespace
		// that provably exists can never be re-registered, no matter how few
		// guardians are reachable, and answering no-quorum here would be both
		// less informative and, with a stale holder beside two unknowns, one
		// refactor away from authorizing a second genesis.
		// Existence evidence spans STALE guardians too, and every piece of it
		// must be signed: a receipt that verifies under a member key, is
		// signed by the endpoint's bound identity, covers the state beside
		// it, and names this namespace. An unsigned state is not evidence of
		// anything.
		const existing = allAnswered.filter((entry) => {
			const response = entry.result;
			if (!response || response.status !== GuardianStatus.OK) return false;
			const state = response.state;
			const receipt = response.receipt;
			if (!state || !receipt) return false;
			if (!verifyGuardianReceipt(receipt, this.config.context)) return false;
			if (!receipt.guardianId.equals(entry.guardianId as Buffer)) return false;
			if (!statesEqual(receipt.state, state)) return false;
			return state.recoveryId.equals(recoveryId);
		});
		const other = answered.filter(
			(entry) =>
				entry.result?.status !== GuardianStatus.ERR_UNKNOWN_NODE &&
				entry.result?.status !== GuardianStatus.OK
		);

		// A registration this device already sent may be the very thing those
		// guardians are holding. That is a PARTIAL REGISTRATION, not someone
		// else's namespace, and it is completed by re-sending the
		// byte-identical request, never by a restore.
		const pendingRegistration = this.loadPendingRegistration();
		const existingStates = existing.map(
			(entry) => entry.result?.state as GuardianState
		);
		const ourPartial =
			pendingRegistration !== null &&
			existingStates.length > 0 &&
			existingStates.every((state) =>
				statesEqual(state, pendingRegistration.initialState)
			);
		if (existing.length > 0 && !ourPartial) {
			// The namespace exists, proven by at least one signed state, and
			// it is not this device's half-finished registration. Restore or
			// takeover decides what happens next; registering over it would be
			// a second genesis. This holds even when the only guardian that
			// knows is possibly_stale: it cannot tell us what is CURRENT, but
			// it can prove the namespace is not free.
			this.emit({
				type: 'namespace:exists',
				detail: `${existing.length} guardians already serve this namespace`
			});
			return { outcome: 'exists-remotely', states: existingStates };
		}

		// Nothing proves the namespace exists. Registering is only safe with
		// a RECENCY quorum, which excludes uncertain stores.
		const distinct = new Set(
			answered.map((entry) => (entry.guardianId as Buffer).toString('hex'))
		);
		if (distinct.size < this.config.required) {
			this.emit({
				type: 'namespace:no-quorum',
				detail: `only ${distinct.size} of ${this.config.guardians.length} distinct guardians answered usefully`
			});
			return { outcome: 'no-quorum', responded: distinct.size };
		}
		if (!ourPartial && unknown.size < this.config.required) {
			const detail =
				other.length > 0
					? `guardians answered with status ${other
							.map((entry) => entry.result?.status)
							.join(', ')}`
					: 'no quorum agrees the namespace is unknown';
			this.emit({ type: 'namespace:inconsistent', detail });
			return { outcome: 'inconsistent', detail };
		}

		// A quorum says the namespace does not exist: this is first setup.
		// An attempt already sent is RESUMED with its original key, because
		// only the byte-identical registration is idempotent (wire 5.1): a
		// guardian that accepted the first one is permanently bound to that
		// writer key, and a fresh key would be a different, rejected genesis
		// that this device could never write under.
		const resumed = pendingRegistration;
		const writer = resumed ? resumed.writer : generateWriterKey();
		const initialState: GuardianState = resumed
			? resumed.initialState
			: {
					recoveryId: Buffer.from(recoveryId),
					lease: { epoch: 1n, writerPublicKey: writer.publicKey },
					origin: this.chainOrigin(),
					logHead: genesisLogHead()
			  };
		if (!resumed) {
			// Persisted BEFORE the request leaves, exactly as an acquisition is.
			this.savePendingRegistration(initialState, writer);
		} else {
			this.emit({
				type: 'namespace:registered',
				detail: `resuming the registration of epoch 1 with its original writer key`
			});
		}
		const generation = this.generation();
		const request: IGuardianRegisterNodeRequest = {
			protocolVersion: 1,
			guardianSetId: Buffer.from(this.config.context.guardianSetId),
			guardianMembers: this.config.context.members.map((m) => Buffer.from(m)),
			initialState,
			rootSignature: signTranscript(
				registerTranscriptHash(
					this.config.context.guardianSetId,
					initialState,
					generation
				),
				this.config.recoveryRoot.rootSecret
			),
			generation
		};
		const registrations = await boundFanOut(this.config.guardians, (client) =>
			client.register(request)
		);
		const accepted = countReceiptQuorum(
			registrations.map((entry) => ({
				client: entry.client,
				result: entry.result,
				error: entry.error
			})),
			this.config.context,
			// Byte-identical or nothing: only an exact match proves the
			// guardian registered THIS state, with this writer key, this
			// recovery id, and this origin. Shape checks would accept a
			// receipt for someone else's genesis.
			(state) => statesEqual(state, initialState)
		);
		if (accepted < this.config.required) {
			const detail = `registration reached ${accepted} of ${this.config.required} required guardians`;
			this.emit({ type: 'namespace:inconsistent', detail });
			return { outcome: 'inconsistent', detail };
		}

		// The lease is persisted only after a quorum acknowledged the
		// registration: a lease nobody granted must never exist on disk. The
		// pending record retires in the SAME transaction, so the writer key
		// is never absent from storage while a guardian is bound to it.
		const lease: IWriterLeaseKeys = {
			epoch: 1n,
			writerSecret: writer.secret,
			writerPublicKey: writer.publicKey,
			guardianCertificates: [],
			confirmedAt: this.clock()
		};
		// prepareWriterLease validates and encodes OUTSIDE the transaction, so
		// promotion needs no reentrant transaction support from the backend:
		// IStorageBackend.transaction does not document reentrancy, and
		// relying on SQLite's savepoint behaviour would make this correct only
		// for one backend.
		const writeLease = prepareWriterLease(this.config.storage, lease, {
			allowUnencryptedSecrets: this.config.allowUnencryptedSecrets
		});
		this.config.storage.transaction(() => {
			writeLease(this.config.storage);
			this.config.storage.deleteRecoveryMeta?.(this.keys.pendingRegistration);
		});
		this.emit({
			type: 'namespace:registered',
			detail: `namespace registered with ${accepted} guardians at origin sequence ${initialState.origin.firstSequence}`,
			receipts: accepted
		});
		return { outcome: 'registered', lease };
	}

	/**
	 * Register this namespace with THIS replicator's set under an existing
	 * lease (wire 5.9 step 2): a rotation re-registers the current writer's
	 * epoch and key with the incoming set at the incoming generation, with
	 * the retained chain origin. Never touches the primary lease or the
	 * primary pending-registration record. Returns the accepting quorum.
	 */
	async registerExisting(lease: IWriterLeaseKeys): Promise<{
		accepted: number;
		initialState: GuardianState;
	}> {
		await this.ensureBindings();
		const recoveryId = this.config.recoveryRoot.recoveryId;
		const initialState: GuardianState = {
			recoveryId: Buffer.from(recoveryId),
			lease: {
				epoch: lease.epoch,
				writerPublicKey: Buffer.from(lease.writerPublicKey)
			},
			origin: this.chainOrigin(),
			logHead: genesisLogHead()
		};
		const generation = this.generation();
		const request: IGuardianRegisterNodeRequest = {
			protocolVersion: 1,
			guardianSetId: Buffer.from(this.config.context.guardianSetId),
			guardianMembers: this.config.context.members.map((m) => Buffer.from(m)),
			initialState,
			rootSignature: signTranscript(
				registerTranscriptHash(
					this.config.context.guardianSetId,
					initialState,
					generation
				),
				this.config.recoveryRoot.rootSecret
			),
			generation
		};
		const registrations = await boundFanOut(this.config.guardians, (client) =>
			client.register(request)
		);
		const accepted = countReceiptQuorum(
			registrations.map((entry) => ({
				client: entry.client,
				result: entry.result,
				error: entry.error
			})),
			this.config.context,
			(state) => statesEqual(state, initialState)
		);
		this.emit({
			type: 'namespace:registered',
			detail: `re-registered under generation ${generation} with ${accepted} guardians at origin sequence ${initialState.origin.firstSequence}`,
			receipts: accepted
		});
		return { accepted, initialState };
	}

	/** Sign one journal frame as a guardian record (wire 4.2 RECORD). */
	signRecord(
		frame: IStoredRecoveryFrame,
		lease: IWriterLeaseKeys
	): IGuardianRecord {
		const ciphertextHash = sha256(frame.ciphertext);
		const fields = {
			recoveryId: this.config.recoveryRoot.recoveryId,
			epoch: lease.epoch,
			sequence: BigInt(frame.sequence),
			previousHash: frame.previousFrameHash,
			frameHash: frame.frameHash,
			ciphertextHash
		};
		return {
			protocolVersion: 1,
			guardianSetId: Buffer.from(this.config.context.guardianSetId),
			recoveryId: Buffer.from(this.config.recoveryRoot.recoveryId),
			epoch: lease.epoch,
			sequence: BigInt(frame.sequence),
			previousHash: Buffer.from(frame.previousFrameHash),
			frameHash: Buffer.from(frame.frameHash),
			ciphertext: Buffer.from(frame.ciphertext),
			writerSignature: signTranscript(
				recordTranscriptHash(this.config.context.guardianSetId, fields),
				lease.writerSecret
			)
		};
	}

	/**
	 * The highest sequence provably replicated to a quorum, or 0.
	 *
	 * A corrupt value reads as 0 rather than throwing. This is called on every
	 * barrier evaluation and inside the send path; a SyntaxError escaping here
	 * would take down a channel transition over a bookkeeping row. Reading 0
	 * is the safe direction: it re-offers records the guardians already hold,
	 * which they answer idempotently with OK_DUPLICATE.
	 */
	replicatedThrough(): bigint {
		const storage = this.config.storage;
		const raw = storage.getRecoveryMeta?.(this.keys.replicatedThrough);
		if (raw == null) return 0n;
		if (!/^\d+$/.test(raw)) return 0n;
		let value: bigint;
		try {
			value = BigInt(raw);
		} catch {
			return 0n;
		}
		// A positive watermark is only ever trusted when its recorded
		// receipted-frame hash exists AND resolves against the retained
		// store (the stored frame itself, or the retained base snapshot's
		// previousFrameHash when compaction pruned exactly that frame): a
		// replaced chain at the same height has NOT been receipted, and
		// answering with the inherited watermark would release its messages
		// without one. A missing hash is equally untrusted; every writer of
		// the watermark binds it, so absence means the mark predates the
		// binding or survived something that destroyed it. Reading 0 is the
		// safe direction (re-offering is idempotent; a divergent chain is
		// then refused by the guardians at its occupied sequences), and it
		// self-heals: the next successful pass re-raises and re-binds.
		if (value >= 1n) {
			const boundHash = storage.getRecoveryMeta?.(
				this.keys.replicatedThroughHash
			);
			if (boundHash == null) return 0n;
			const anchor = resolveWatermarkAnchor(storage, value);
			if (anchor == null || anchor.toString('hex') !== boundHash) {
				return 0n;
			}
		}
		return value;
	}

	/**
	 * Why this namespace can never advance again, or null.
	 *
	 * Read from the journal's own metadata rather than tracked in memory,
	 * because the fact is irreversible and has to survive the process that
	 * discovered it. Exposed here so a barrier, which already holds the
	 * replicator, needs nothing else wired to it.
	 */
	namespaceLostBackfill(): string | null {
		return chainLostBackfill(this.config.storage);
	}

	/**
	 * Why the persisted watermark cannot be trusted, or null when it can.
	 *
	 * The watermark survives in recovery_meta while the frames underneath it
	 * can be rolled back, restored in part or repaired, and a mark above the
	 * local tip is then a claim about records this device cannot even show.
	 * provenHead already refuses a RECEIPT whose head is above our tip, for
	 * exactly this reason, but that check is structurally unreachable here: a
	 * pass whose watermark already exceeds the tip loads no frames at all, so
	 * no receipt is ever examined and the mark stands unchallenged forever.
	 *
	 * Asked ONCE, at barrier construction, never per evaluation.
	 *
	 * Reads the RAW stored mark, not replicatedThrough(): the trusted read
	 * already degrades an unresolvable mark to zero for release purposes,
	 * and going through it here would silently wave through exactly the
	 * rolled-back stores this check exists to refuse LOUDLY at startup.
	 *
	 * A ZERO (or unparseable, which reads as zero) watermark is never
	 * refused. It releases nothing, so there is nothing to refuse, and
	 * refusing it would freeze a node whose journal is merely damaged, which
	 * is the same trade resolveDurability makes for an unreadable tip.
	 */
	watermarkExceedingJournal(): string | null {
		const raw = this.config.storage.getRecoveryMeta?.(
			this.keys.replicatedThrough
		);
		if (raw == null || !/^\d+$/.test(raw)) return null;
		const watermark = BigInt(raw);
		if (watermark === 0n) return null;
		const tip = storedTipSequence(this.config.storage);
		if (tip == null) {
			return (
				`the replication watermark is ${watermark} but this journal's ` +
				`recorded tip does not match the frames on disk`
			);
		}
		if (watermark > tip) {
			return (
				`the replication watermark is ${watermark} but the journal only ` +
				`holds frames through ${tip}, so the log was rolled back or ` +
				`restored underneath a mark that survived it`
			);
		}
		return null;
	}

	/**
	 * Advance the watermark, never retreat it.
	 *
	 * The read and the write share one transaction so a concurrent pass cannot
	 * interleave between them, and the value written is the MAX: a pass that
	 * started earlier and finished later must not overwrite a higher mark with
	 * the lower one it computed from a stale entry snapshot.
	 */
	private raiseWatermark(value: bigint): bigint {
		const storage = this.config.storage;
		let stored = value;
		storage.transaction(() => {
			const current = this.replicatedThrough();
			if (value <= current) {
				stored = current;
				return;
			}
			// Bind the watermark to the HISTORY it receipts, not just a
			// height: the receipt verification above proved the guardian
			// head names our stored frame, so record which frame that was.
			// A later chain replacement at the same height then fails the
			// binding instead of inheriting the receipts. Height and hash
			// are ONE atomic pair; a raise whose target has no resolvable
			// anchor is REFUSED outright, because an unbound positive mark
			// is exactly the fail-open the binding exists to close.
			const anchor = resolveWatermarkAnchor(storage, value);
			if (anchor == null) {
				stored = current;
				return;
			}
			storage.setRecoveryMeta?.(this.keys.replicatedThrough, value.toString());
			storage.setRecoveryMeta?.(
				this.keys.replicatedThroughHash,
				anchor.toString('hex')
			);
		});
		return stored;
	}

	/**
	 * The head this receipt PROVES a guardian holds, or null.
	 *
	 * Everything about the binding here is load-bearing, because this number
	 * is what a Phase 6 barrier releases wire messages on. A receipt is only
	 * evidence about OUR chain when it verifies under a committed member key,
	 * names THIS recovery namespace, and was issued while the guardian agreed
	 * we are the current writer. And where the head lands on a frame we hold,
	 * the frame hashes must agree: a guardian holding a different record at
	 * that position has not stored ours, however valid its signature is.
	 *
	 * Without these checks a validly signed receipt over a different
	 * namespace at a higher sequence would release the barrier.
	 */
	private provenHead(
		receipt: IGuardianReceipt | undefined,
		lease: IWriterLeaseKeys,
		framesBySequence: Map<bigint, IStoredRecoveryFrame>,
		expectedGuardianId: Buffer,
		tip: bigint
	): { head: bigint; conflictAt: bigint | null } | null {
		if (!receipt) return null;
		if (!verifyGuardianReceipt(receipt, this.config.context)) return null;
		// The quorum is over DISTINCT guardians and this pass collects one head
		// per ENDPOINT, so the receipt has to be signed by the guardian this
		// endpoint proved it is through INFO. Without the check one endpoint
		// satisfies a 2-of-3 on its own by replaying another guardian's
		// genuine receipt beside its own.
		if (!receipt.guardianId.equals(expectedGuardianId)) return null;
		const state = receipt.state;
		if (!state.recoveryId.equals(this.config.recoveryRoot.recoveryId)) {
			return null;
		}
		if (state.lease.epoch !== lease.epoch) return null;
		if (!state.lease.writerPublicKey.equals(lease.writerPublicKey)) return null;
		const head = state.logHead.sequence;
		// A guardian cannot hold a record we never wrote, so a head above our
		// tip is not evidence about our chain at all. REFUSE it rather than
		// clamp it down to the tip: clamping turns a guardian that is ahead of
		// a locally rolled-back journal into proof of frames this device
		// cannot even show, and the frame-hash check below cannot help,
		// because a head we do not hold is not in the map to compare against.
		if (head > tip) return null;
		// A genesis head certifies nothing and binds to nothing.
		if (head === 0n) return { head, conflictAt: null };
		// EVERY positive head must bind to OUR history before it counts
		// toward a quorum: the receipt's signed hash is compared against the
		// frame this pass loaded, or, when the head sits below the loaded
		// window or was legitimately compacted, against the same anchor the
		// watermark trusts (the stored row, or the retained base snapshot's
		// previousFrameHash). A head that resolves to NOTHING is not
		// evidence; a head that resolves to a DIFFERENT hash is a receipt
		// for a foreign history and must never raise our watermark, however
		// valid its signature is. Without this, a compacted position let a
		// foreign receipt through unchecked, and raiseWatermark would then
		// launder it by re-binding the height to OUR local hash.
		const ours = framesBySequence.get(head);
		const expected =
			ours?.frameHash ?? resolveWatermarkAnchor(this.config.storage, head);
		if (expected == null) return null;
		if (!state.logHead.frameHash.equals(expected)) {
			return { head: 0n, conflictAt: head };
		}
		return { head, conflictAt: null };
	}

	/**
	 * Stream this pass's records to ONE guardian, in sequence order, without
	 * waiting for each receipt (spec 5.3: "Appends are pipelined").
	 *
	 * The guardian is linearized and order sensitive: it accepts only
	 * `logHead.sequence + 1` and refuses anything else with an unsigned gap
	 * error carrying its current position. Independent HTTP requests can
	 * therefore land out of order, so the window re-anchors on whatever
	 * position the guardian reports and, if a round makes no forward progress,
	 * narrows to strictly sequential. Nothing is lost either way, because a
	 * refused record changes no state and receipts are cumulative: only the
	 * furthest response of a burst has to be believed.
	 */
	private async streamToGuardian(
		entry: IBoundGuardianClient,
		frames: IStoredRecoveryFrame[],
		lease: IWriterLeaseKeys,
		framesBySequence: Map<bigint, IStoredRecoveryFrame>,
		tip: bigint
	): Promise<IGuardianStreamResult> {
		const result: IGuardianStreamResult = {
			provenThrough: null,
			sawSupersession: false,
			sawRetired: false,
			conflictAt: null,
			requests: 0
		};
		let window = this.pipelineWindow;
		let cursor = 0;
		let lastReported: bigint | null = null;
		// Strictly bounded: every round either advances the cursor or narrows
		// the window, and a round that does neither twice stops the stream.
		const maxRounds = frames.length + this.pipelineWindow + 1;

		for (let round = 0; round < maxRounds && cursor < frames.length; round++) {
			const batch = frames.slice(cursor, cursor + window);
			result.requests += batch.length;
			const responses = await Promise.all(
				batch.map(async (frame) => {
					try {
						return await entry.client.putState(this.signRecord(frame, lease));
					} catch {
						return undefined;
					}
				})
			);

			let reported: bigint | null = null;
			for (const response of responses) {
				if (!response) continue;
				if (response.status === GuardianStatus.ERR_EPOCH_SUPERSEDED) {
					result.sawSupersession = true;
				}
				if (response.status === GuardianStatus.ERR_SET_RETIRED) {
					result.sawRetired = true;
				}
				const proven = this.provenHead(
					response.receipt,
					lease,
					framesBySequence,
					entry.expectedGuardianId,
					tip
				);
				if (proven?.conflictAt != null) {
					result.conflictAt = proven.conflictAt;
					continue;
				}
				if (proven) {
					if (
						result.provenThrough == null ||
						proven.head > result.provenThrough
					) {
						result.provenThrough = proven.head;
					}
					if (reported == null || proven.head > reported)
						reported = proven.head;
					continue;
				}
				// Unsigned steering only. A gap or previous-hash rejection tells
				// us where the guardian actually is; it certifies nothing.
				const current = response.current;
				if (
					current &&
					current.recoveryId.equals(this.config.recoveryRoot.recoveryId)
				) {
					const at = current.logHead.sequence;
					if (reported == null || at > reported) reported = at;
				}
			}

			if (result.sawSupersession) return result;
			if (reported == null) return result;
			const next = frames.findIndex(
				(frame) => BigInt(frame.sequence) > (reported as bigint)
			);
			if (next < 0) {
				cursor = frames.length;
				break;
			}
			if (next <= cursor) {
				if (window === 1 && lastReported === reported) return result;
				window = 1;
			}
			lastReported = reported;
			cursor = next;
		}
		return result;
	}

	/**
	 * Replicate every journal frame above the replication high-water mark.
	 *
	 * The pass is single flight, streams to each guardian in parallel and each
	 * guardian's records in pipelined sequence order, and derives the new
	 * watermark from CUMULATIVE receipts: a receipt for head S certifies every
	 * record from the origin through S (wire spec, "receipts are cumulative"),
	 * so the quorum head is simply the `required`-th highest proven head.
	 * There is no per-record round trip and no per-record accounting.
	 *
	 * Never throws into the caller's path: a failure to reach the quorum
	 * degrades durability, and in quorum mode the barrier is what turns that
	 * into a hold. Replication itself never blocks a channel.
	 */
	async replicatePending(lease: IWriterLeaseKeys): Promise<IReplicationResult> {
		if (this.inFlight) return this.inFlight;
		const pass = this.runReplicationPass(lease).finally(() => {
			this.inFlight = null;
		});
		this.inFlight = pass;
		return pass;
	}

	private async runReplicationPass(
		lease: IWriterLeaseKeys
	): Promise<IReplicationResult> {
		const storage = this.config.storage;
		const from = this.replicatedThrough();
		const frames = (storage.loadRecoveryFrames?.(Number(from)) ?? []).filter(
			(frame) => BigInt(frame.sequence) > from
		);
		if (frames.length === 0) {
			return {
				outcome: 'replicated',
				attempted: 0,
				durable: 0,
				replicatedThrough: from
			};
		}
		// An endpoint that has not proved which guardian it is cannot be
		// counted toward a quorum, and must not be able to fence us either.
		await this.ensureBindings();

		const framesBySequence = new Map<bigint, IStoredRecoveryFrame>();
		for (const frame of frames) {
			framesBySequence.set(BigInt(frame.sequence), frame);
		}
		const tip = BigInt(frames[frames.length - 1].sequence);

		const streams = await Promise.all(
			this.config.guardians.map((entry) =>
				this.streamToGuardian(entry, frames, lease, framesBySequence, tip)
			)
		);

		for (const stream of streams) {
			if (stream.conflictAt != null) {
				this.emit({
					type: 'record:conflict',
					detail:
						`a guardian holds a DIFFERENT record at sequence ${stream.conflictAt}; ` +
						`its receipts are not evidence for this chain`,
					sequence: stream.conflictAt
				});
			}
		}

		if (streams.some((stream) => stream.sawRetired)) {
			const rotated = await this.resolveRotation(tip);
			if (rotated) return rotated;
		}
		if (streams.some((stream) => stream.sawSupersession)) {
			const fenced = await this.resolveSupersession(lease, tip);
			if (fenced) return fenced;
		}

		// Cumulative receipts collapse the whole pass to one order statistic:
		// the highest sequence that `required` distinct guardians have proven
		// they hold. Guardians are distinct by construction here, since
		// verifyGuardianBindings refuses duplicate members.
		const heads = streams
			.map((stream) => stream.provenThrough)
			.filter((head): head is bigint => head != null)
			.sort((a, b) => (a === b ? 0 : a > b ? -1 : 1));
		let quorumHead =
			heads.length >= this.config.required
				? heads[this.config.required - 1]
				: from;
		// provenHead already refuses a head above our tip, so this cannot lift
		// the mark; it is a belt on the braces. It must never clamp UPWARD,
		// which would turn an over-reporting guardian into proof of our tip.
		if (quorumHead > tip) quorumHead = tip;
		if (quorumHead < from) quorumHead = from;

		const replicatedThrough = this.raiseWatermark(quorumHead);
		const durable = Number(
			replicatedThrough > from ? replicatedThrough - from : 0n
		);

		if (replicatedThrough >= tip) {
			this.emit({
				type: 'record:replicated',
				detail: `records through ${replicatedThrough} are durable at ${this.config.required} guardians`,
				sequence: replicatedThrough,
				receipts: heads.length
			});
			return {
				outcome: 'replicated',
				attempted: frames.length,
				durable,
				replicatedThrough
			};
		}
		this.emit({
			type: 'record:under-replicated',
			detail:
				`records are durable only through ${replicatedThrough} of ${tip}; ` +
				`${heads.length} of ${this.config.guardians.length} guardians answered with proof`,
			sequence: tip,
			receipts: heads.length
		});
		return {
			outcome: 'under-replicated',
			attempted: frames.length,
			durable,
			replicatedThrough
		};
	}

	/**
	 * A guardian said our epoch is superseded. Decide whether that is true.
	 *
	 * ERR_EPOCH_SUPERSEDED is an UNSIGNED status, so on its own it is a claim
	 * by one endpoint. Fencing is permanent and, under Phase 6, node wide: it
	 * stops revoke_and_ack, fulfill and splice on every channel. So the fence
	 * requires the same evidence the startup gate requires, a signed state
	 * naming a HIGHER epoch. Without it the pass reports the disagreement and
	 * continues, which is the difference between one misbehaving endpoint
	 * costing us a log line and costing us the node.
	 */
	/**
	 * A guardian said this namespace was rotated away. ERR_SET_RETIRED is an
	 * unsigned status; the fence needs the root-signed rotation from a head
	 * (wire 5.11). With it, this device is a stale writer and must freeze.
	 */
	private async resolveRotation(
		sequence: bigint
	): Promise<IReplicationResult | null> {
		let heads: Array<IGuardianFanOutResult<IGuardianGetHeadResponse>>;
		try {
			heads = await boundFanOut(this.config.guardians, (client) =>
				client.getHead(this.config.recoveryRoot.recoveryId)
			);
		} catch {
			return null;
		}
		for (const entry of heads) {
			const rotation = this.verifiedRotation(entry.result);
			if (rotation) {
				this.emit({
					type: 'writer:fenced',
					detail: `this namespace was rotated to generation ${rotation.generation} by another device; replication stopped and the writer must freeze`,
					sequence
				});
				return {
					outcome: 'fenced',
					attempted: 0,
					durable: 0,
					replicatedThrough: this.replicatedThrough(),
					rotatedTo: rotation
				};
			}
		}
		return null;
	}

	private async resolveSupersession(
		lease: IWriterLeaseKeys,
		sequence: bigint
	): Promise<IReplicationResult | null> {
		let proof: { states: GuardianState[] };
		try {
			proof = await this.confirmOwnership(lease);
		} catch (error) {
			this.emit({
				type: 'writer:supersession-unproven',
				detail:
					`a guardian rejected our epoch but ownership could not be checked ` +
					`(${error instanceof Error ? error.message : String(error)}); ` +
					`not fencing on an unsigned claim`,
				sequence
			});
			return null;
		}
		const newer = proof.states.find((state) => state.lease.epoch > lease.epoch);
		if (!newer) {
			this.emit({
				type: 'writer:supersession-unproven',
				detail:
					`a guardian rejected our epoch but no signed state names a higher one; ` +
					`not fencing on an unsigned claim`,
				sequence
			});
			return null;
		}
		this.emit({
			type: 'writer:fenced',
			detail:
				`epoch ${lease.epoch} was superseded by epoch ${newer.lease.epoch}; ` +
				'replication stopped and the writer must freeze',
			sequence
		});
		return {
			outcome: 'fenced',
			attempted: 0,
			durable: 0,
			replicatedThrough: this.replicatedThrough(),
			verifiedCurrentState: newer,
			localEpoch: lease.epoch
		};
	}

	/**
	 * Confirm that the guardian set still recognizes THIS lease as the
	 * current writer (spec 5.6 startup rule). Returns the number of distinct
	 * guardians whose signed state names this exact (epoch, writer key); the
	 * caller compares it against the required quorum and decides whether to
	 * leave quarantine.
	 */
	async confirmOwnership(lease: IWriterLeaseKeys): Promise<{
		confirming: number;
		superseded: boolean;
		states: GuardianState[];
		/** The namespace was rotated away from this set: fence (wire 5.9). */
		rotated?: IGuardianRotateSetRequest;
	}> {
		await this.ensureBindings();
		const heads = await boundFanOut(this.config.guardians, (client) =>
			client.getHead(this.config.recoveryRoot.recoveryId)
		);
		const states: GuardianState[] = [];
		const confirming = new Set<string>();
		let superseded = false;
		let rotated: IGuardianRotateSetRequest | undefined;
		for (const entry of heads) {
			const response = entry.result;
			const rotation = this.verifiedRotation(response);
			if (rotation) {
				rotated = rotation;
				superseded = true;
				continue;
			}
			if (!response || response.status !== GuardianStatus.OK) continue;
			// An uncertain store cannot confirm ownership (wire 5.3).
			if (response.possiblyStale === true) continue;
			const state = response.state;
			const receipt = response.receipt;
			if (!state || !receipt) continue;
			// The receipt is what makes the state evidence rather than a claim.
			if (!verifyGuardianReceipt(receipt, this.config.context)) continue;
			// And it must be signed by the guardian this endpoint is bound to.
			if (!receipt.guardianId.equals(entry.guardianId as Buffer)) continue;
			// A receipt over state A returned beside an unsigned state B makes
			// B nothing at all: the signature must cover the state being used,
			// and that state must be THIS namespace. The startup gate releases
			// peer connections on this answer, so an unbound state here would
			// let a node act on something no guardian ever signed.
			if (!statesEqual(receipt.state, state)) continue;
			if (!state.recoveryId.equals(this.config.recoveryRoot.recoveryId)) {
				continue;
			}
			states.push(state);
			if (
				state.lease.epoch === lease.epoch &&
				state.lease.writerPublicKey.equals(lease.writerPublicKey)
			) {
				confirming.add(receipt.guardianId.toString('hex'));
			} else if (state.lease.epoch > lease.epoch) {
				superseded = true;
			}
		}
		return {
			confirming: confirming.size,
			superseded,
			states,
			...(rotated ? { rotated } : {})
		};
	}
}

/** The journal meta key replication reads to know where the log starts. */
export const REPLICATION_JOURNAL_KEYS = JOURNAL_META_KEYS;
