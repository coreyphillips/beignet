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
	IGuardianRegisterNodeRequest
} from './guardian';
import {
	IBoundGuardianClient,
	IGuardianSetContext,
	boundFanOut,
	countReceiptQuorum,
	verifyGuardianBindings,
	verifyGuardianReceipt
} from './guardian-client';
import { JOURNAL_META_KEYS } from './journal';
import {
	IWriterLeaseKeys,
	generateWriterKey,
	loadWriterLease,
	requireEncryptedSecretStorage,
	saveWriterLease
} from './writer-lease';

/** How far replication has provably got, for catch-up after a restart. */
const META_REPLICATED_THROUGH = 'guardian_replicated_through';
/** A registration already sent to at least one guardian (see below). */
const META_PENDING_REGISTRATION = 'guardian_pending_registration_v1';

export const REPLICATION_META_KEYS = {
	replicatedThrough: META_REPLICATED_THROUGH,
	pendingRegistration: META_PENDING_REGISTRATION
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
		| 'writer:fenced';
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
	/** On `fenced`: the epoch this node believed it held. */
	localEpoch?: bigint;
}

export class GuardianReplicator {
	private readonly config: IGuardianReplicationConfig;
	private readonly clock: () => bigint;

	private verifiedBindings: Set<string> | null = null;

	constructor(config: IGuardianReplicationConfig) {
		if (config.guardians.length === 0) {
			throw new Error('guardian replication needs at least one guardian');
		}
		if (config.required < 1 || config.required > config.guardians.length) {
			throw new Error('required quorum is outside the configured guardian set');
		}
		this.config = config;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
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
			META_PENDING_REGISTRATION
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
			META_PENDING_REGISTRATION,
			JSON.stringify(payload)
		);
	}

	/**
	 * The origin this namespace must be registered with (wire 4.1): a fresh
	 * journal starts at sequence 1 with a zero predecessor; a node enabling
	 * guardians MID-JOURNAL registers its retained base position instead, so
	 * the node-wide journal numbering carries over without renumbering.
	 */
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
		// A possibly_stale guardian cannot prove its store intact (wire 5.3),
		// so it never counts toward a decision about what exists.
		const answered = heads.filter(
			(entry) =>
				entry.result !== undefined && entry.result.possiblyStale !== true
		);
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
		const existing = answered.filter(
			(entry) =>
				entry.result?.status === GuardianStatus.OK && entry.result.state
		);
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
			// The namespace exists and it is not this device's half-finished
			// registration. Restore or takeover decides what happens next;
			// registering over it would be a second genesis.
			this.emit({
				type: 'namespace:exists',
				detail: `${existing.length} guardians already serve this namespace`
			});
			return { outcome: 'exists-remotely', states: existingStates };
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
		const request: IGuardianRegisterNodeRequest = {
			protocolVersion: 1,
			guardianSetId: Buffer.from(this.config.context.guardianSetId),
			initialState,
			rootSignature: signTranscript(
				registerTranscriptHash(this.config.context.guardianSetId, initialState),
				this.config.recoveryRoot.rootSecret
			)
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
		this.config.storage.transaction(() => {
			saveWriterLease(this.config.storage, lease, {
				allowUnencryptedSecrets: this.config.allowUnencryptedSecrets
			});
			this.config.storage.deleteRecoveryMeta?.(META_PENDING_REGISTRATION);
		});
		this.emit({
			type: 'namespace:registered',
			detail: `namespace registered with ${accepted} guardians at origin sequence ${initialState.origin.firstSequence}`,
			receipts: accepted
		});
		return { outcome: 'registered', lease };
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

	/** The highest sequence provably replicated to a quorum, or 0. */
	replicatedThrough(): bigint {
		const raw = this.config.storage.getRecoveryMeta?.(META_REPLICATED_THROUGH);
		return raw == null ? 0n : BigInt(raw);
	}

	/**
	 * Replicate every journal frame above the replication high-water mark.
	 * Best effort: a frame that fails to reach the quorum stops the mark
	 * from advancing (durability is only claimed for a CONTIGUOUS prefix,
	 * since a receipt is cumulative over the chain it certifies), but never
	 * throws into the caller's path. Phase 6 turns this into a barrier.
	 */
	async replicatePending(lease: IWriterLeaseKeys): Promise<IReplicationResult> {
		const storage = this.config.storage;
		const from = this.replicatedThrough();
		const frames = (storage.loadRecoveryFrames?.(Number(from)) ?? []).filter(
			(frame) => BigInt(frame.sequence) > from
		);
		let durable = 0;
		let contiguousThrough = from;
		let contiguous = true;

		for (const frame of frames) {
			const sequence = BigInt(frame.sequence);
			const record = this.signRecord(frame, lease);
			const results = await boundFanOut(this.config.guardians, (client) =>
				client.putState(record)
			);
			// A definitive epoch rejection is TERMINAL, not noise: another
			// device holds the lease, so this writer must stop before it does
			// anything else (spec 5.6 async-mode hard freeze). The newer state
			// is then proven through a signed GET_HEAD rather than taken from
			// the rejection itself.
			if (
				results.some(
					(entry) =>
						entry.result?.status === GuardianStatus.ERR_EPOCH_SUPERSEDED
				)
			) {
				const proof = await this.confirmOwnership(lease);
				const newer = proof.states.find(
					(state) => state.lease.epoch > lease.epoch
				);
				this.emit({
					type: 'writer:fenced',
					detail:
						`epoch ${lease.epoch} was superseded` +
						(newer ? ` by epoch ${newer.lease.epoch}` : '') +
						'; replication stopped and the writer must freeze',
					sequence
				});
				if (contiguousThrough > from) {
					storage.setRecoveryMeta?.(
						META_REPLICATED_THROUGH,
						contiguousThrough.toString()
					);
				}
				return {
					outcome: 'fenced',
					attempted: frames.indexOf(frame) + 1,
					durable,
					replicatedThrough: contiguousThrough,
					verifiedCurrentState: newer,
					localEpoch: lease.epoch
				};
			}
			const rejected = results.filter(
				(entry) =>
					entry.result !== undefined &&
					entry.result.status !== GuardianStatus.OK &&
					entry.result.status !== GuardianStatus.OK_DUPLICATE
			);
			for (const entry of rejected) {
				this.emit({
					type: 'record:rejected',
					detail: `guardian rejected record with status ${entry.result?.status}`,
					sequence
				});
			}
			const receipts = countReceiptQuorum(
				results.map((entry) => ({
					client: entry.client,
					result: entry.result,
					error: entry.error
				})),
				this.config.context,
				(state) => state.logHead.sequence >= sequence
			);
			if (receipts >= this.config.required) {
				durable += 1;
				if (contiguous) contiguousThrough = sequence;
				this.emit({
					type: 'record:replicated',
					detail: `record ${sequence} durable at ${receipts} guardians`,
					sequence,
					receipts
				});
			} else {
				contiguous = false;
				this.emit({
					type: 'record:under-replicated',
					detail: `record ${sequence} reached only ${receipts} of ${this.config.required} guardians`,
					sequence,
					receipts
				});
			}
		}

		if (contiguousThrough > from) {
			storage.setRecoveryMeta?.(
				META_REPLICATED_THROUGH,
				contiguousThrough.toString()
			);
		}
		return {
			outcome:
				contiguous && durable === frames.length
					? 'replicated'
					: 'under-replicated',
			attempted: frames.length,
			durable,
			replicatedThrough: contiguousThrough
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
	}> {
		await this.ensureBindings();
		const heads = await boundFanOut(this.config.guardians, (client) =>
			client.getHead(this.config.recoveryRoot.recoveryId)
		);
		const states: GuardianState[] = [];
		const confirming = new Set<string>();
		let superseded = false;
		for (const entry of heads) {
			const response = entry.result;
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
		return { confirming: confirming.size, superseded, states };
	}
}

/** The journal meta key replication reads to know where the log starts. */
export const REPLICATION_JOURNAL_KEYS = JOURNAL_META_KEYS;
