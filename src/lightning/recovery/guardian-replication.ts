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
	recordTranscriptHash,
	registerTranscriptHash,
	signTranscript
} from './guardian-wire';
import {
	GuardianStatus,
	IGuardianRecord,
	IGuardianRegisterNodeRequest
} from './guardian';
import {
	GuardianClient,
	IGuardianSetContext,
	countReceiptQuorum,
	guardianFanOut,
	verifyGuardianReceipt
} from './guardian-client';
import { JOURNAL_META_KEYS } from './journal';
import {
	IWriterLeaseKeys,
	generateWriterKey,
	loadWriterLease,
	saveWriterLease
} from './writer-lease';

/** How far replication has provably got, for catch-up after a restart. */
const META_REPLICATED_THROUGH = 'guardian_replicated_through';

export const REPLICATION_META_KEYS = {
	replicatedThrough: META_REPLICATED_THROUGH
} as const;

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
	clients: GuardianClient[];
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
		| 'record:rejected';
	detail: string;
	sequence?: bigint;
	/** Distinct verified receipts a record collected. */
	receipts?: number;
}

export interface IReplicationResult {
	/** Frames attempted in this pass. */
	attempted: number;
	/** Frames that reached `required` distinct verified receipts. */
	durable: number;
	/** Highest sequence that reached the quorum, contiguously from the start. */
	replicatedThrough: bigint;
}

export class GuardianReplicator {
	private readonly config: IGuardianReplicationConfig;
	private readonly clock: () => bigint;

	constructor(config: IGuardianReplicationConfig) {
		if (config.clients.length === 0) {
			throw new Error('guardian replication needs at least one client');
		}
		if (config.required < 1 || config.required > config.clients.length) {
			throw new Error('required quorum is outside the configured client set');
		}
		this.config = config;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
	}

	private emit(event: IGuardianReplicationEvent): void {
		this.config.onEvent?.(event);
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

		const recoveryId = this.config.recoveryRoot.recoveryId;
		const heads = await guardianFanOut(this.config.clients, (client) =>
			client.getHead(recoveryId)
		);
		const answered = heads.filter((entry) => entry.result !== undefined);
		if (answered.length < this.config.required) {
			this.emit({
				type: 'namespace:no-quorum',
				detail: `only ${answered.length} of ${this.config.clients.length} guardians answered`
			});
			return { outcome: 'no-quorum', responded: answered.length };
		}

		const unknown = answered.filter(
			(entry) => entry.result?.status === GuardianStatus.ERR_UNKNOWN_NODE
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

		if (existing.length > 0) {
			// The namespace exists. Restore or takeover decides what happens
			// next; registering over it would be a second genesis.
			this.emit({
				type: 'namespace:exists',
				detail: `${existing.length} guardians already serve this namespace`
			});
			return {
				outcome: 'exists-remotely',
				states: existing.map((entry) => entry.result?.state as GuardianState)
			};
		}
		if (unknown.length < this.config.required) {
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
		const writer = generateWriterKey();
		const initialState: GuardianState = {
			recoveryId: Buffer.from(recoveryId),
			lease: { epoch: 1n, writerPublicKey: writer.publicKey },
			origin: this.chainOrigin(),
			logHead: genesisLogHead()
		};
		const request: IGuardianRegisterNodeRequest = {
			protocolVersion: 1,
			guardianSetId: Buffer.from(this.config.context.guardianSetId),
			initialState,
			rootSignature: signTranscript(
				registerTranscriptHash(this.config.context.guardianSetId, initialState),
				this.config.recoveryRoot.rootSecret
			)
		};
		const registrations = await guardianFanOut(this.config.clients, (client) =>
			client.register(request)
		);
		const accepted = countReceiptQuorum(
			registrations.map((entry) => ({
				client: entry.client,
				result: entry.result,
				error: entry.error
			})),
			this.config.context,
			(state) => state.lease.epoch === 1n && state.logHead.sequence === 0n
		);
		if (accepted < this.config.required) {
			const detail = `registration reached ${accepted} of ${this.config.required} required guardians`;
			this.emit({ type: 'namespace:inconsistent', detail });
			return { outcome: 'inconsistent', detail };
		}

		// The lease is persisted only after a quorum acknowledged the
		// registration: a lease nobody granted must never exist on disk.
		const lease: IWriterLeaseKeys = {
			epoch: 1n,
			writerSecret: writer.secret,
			writerPublicKey: writer.publicKey,
			guardianCertificates: [],
			confirmedAt: this.clock()
		};
		saveWriterLease(this.config.storage, lease, {
			allowUnencryptedSecrets: this.config.allowUnencryptedSecrets
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
			const results = await guardianFanOut(this.config.clients, (client) =>
				client.putState(record)
			);
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
		const heads = await guardianFanOut(this.config.clients, (client) =>
			client.getHead(this.config.recoveryRoot.recoveryId)
		);
		const states: GuardianState[] = [];
		const confirming = new Set<string>();
		let superseded = false;
		for (const entry of heads) {
			const response = entry.result;
			if (!response || response.status !== GuardianStatus.OK) continue;
			const state = response.state;
			const receipt = response.receipt;
			if (!state || !receipt) continue;
			// The receipt is what makes the state evidence rather than a claim.
			if (!verifyGuardianReceipt(receipt, this.config.context)) continue;
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
