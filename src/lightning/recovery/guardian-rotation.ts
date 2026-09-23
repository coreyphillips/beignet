/**
 * Guardian-set rotation, the writer side (docs/RECOVERY-GUARDIAN-WIRE.md
 * 5.9, issue #701).
 *
 * The current writer moves its namespace to an incoming set without a gap
 * in the journal and without a pause in the channels:
 *
 *   1. persist the INTENT (incoming set, generation g+1) before any network
 *      contact, so a crash resumes rather than forgets;
 *   2. REGISTER the namespace with the incoming set under the CURRENT lease
 *      (same epoch, same writer key) at generation g+1, with the retained
 *      chain origin; the incoming set's log head is genesis;
 *   3. BACKFILL: replicate the retained journal to the incoming set, under
 *      its own bookkeeping keys, until a quorum holds the tip; the outgoing
 *      set keeps receiving frames meanwhile, so the live barrier never
 *      waits on a set that is not ready. A journal with no frames yet has
 *      nothing to backfill, and both sets must first prove the namespace
 *      holds nothing either (issue #862);
 *   4. SWITCH in one transaction: generation, configured set, and the
 *      watermark become the incoming set's (an empty journal has no
 *      watermark to move); the caller re-points the barrier, the gate and
 *      the capsule locators at the incoming set;
 *   5. RETIRE the outgoing set with ROTATE_SET, retried until at least one
 *      member accepts (a restore device that only knows the outgoing set
 *      finds the rotation there).
 *
 * Sequence numbering never resets, so a frame committed in the instant of
 * the switch simply replicates to the incoming set as the next record.
 */

import { IStorageBackend } from '../storage/types';
import {
	CRASH_V1_PROFILE,
	computeGuardianSetId,
	rotateTranscriptHash,
	signTranscript
} from './guardian-wire';
import { JOURNAL_META_KEYS, storedTipSequence } from './journal';
import {
	GuardianReplicator,
	IGuardianReplicationEvent,
	REPLICATION_META_KEYS
} from './guardian-replication';
import {
	GuardianClient,
	IBoundGuardianClient,
	IGuardianSetContext,
	boundFanOut
} from './guardian-client';
import { GuardianStatus, IGuardianRotateSetRequest } from './guardian';
import { IWriterLeaseKeys } from './writer-lease';
import { GuardianDescriptor } from './capsule';
import {
	IGuardianConfigEntry,
	IParsedGuardian,
	guardianDescriptorFor
} from './assembly';
import {
	decodeRotateSetRequest,
	encodeRotateSetRequest
} from './guardian-proto';

export const ROTATION_META_KEYS = {
	/** The intent (wire 5.9 step 1): JSON, present from step 1 to the switch. */
	pending: 'guardian_rotation_pending_v1',
	/** The retirement still owed to the outgoing set: JSON, present after the switch until accepted. */
	retirePending: 'guardian_retire_pending_v1'
} as const;

export interface IRotationIntent {
	version: 1;
	generation: string;
	entries: IGuardianConfigEntry[];
}

export interface IRetirePending {
	version: 1;
	/** Hex of the encoded RotateSetRequest for the outgoing set. */
	request: string;
	/** The outgoing set's entries, so a restart can rebuild its clients. */
	entries: IGuardianConfigEntry[];
}

export interface IRotationEvent {
	type:
		| 'rotation:intent'
		| 'rotation:registered'
		| 'rotation:backfill'
		| 'rotation:switched'
		| 'rotation:retired'
		| 'rotation:retire-pending';
	detail: string;
	generation?: string;
}

export class RotationRefusedError extends Error {
	constructor(
		readonly reason:
			| 'in-progress'
			| 'no-quorum'
			| 'not-catching-up'
			| 'same-set'
			| 'malformed'
			/**
			 * This journal has no frames but a guardian set holds records in
			 * the namespace: the journal was lost, not unused. Restore, never
			 * rotate (issue #862).
			 */
			| 'journal-behind',
		message: string
	) {
		super(message);
		this.name = 'RotationRefusedError';
	}
}

/** One set as the rotation sees it: its parsed entries and bound clients. */
export interface IRotationSet {
	guardians: IParsedGuardian[];
	bound: IBoundGuardianClient[];
	context: IGuardianSetContext;
}

export interface IGuardianRotationConfig {
	storage: IStorageBackend;
	recoveryRoot: { rootSecret: Buffer; recoveryId: Buffer };
	/** The current, confirmed lease; carried over unchanged. */
	lease: IWriterLeaseKeys;
	outgoing: IRotationSet;
	incoming: IRotationSet;
	required: number;
	clock?: () => bigint;
	onEvent?: (event: IRotationEvent) => void;
	onReplicationEvent?: (event: IGuardianReplicationEvent) => void;
	allowUnencryptedSecrets?: boolean;
	/** Backfill passes before giving up on a set that is not catching up. */
	maxBackfillPasses?: number;
}

export interface IRotationResult {
	generation: bigint;
	/** The replicator for the incoming set on the main bookkeeping keys. */
	replicator: GuardianReplicator;
	descriptors: GuardianDescriptor[];
	entries: IGuardianConfigEntry[];
}

export function entryOf(parsed: IParsedGuardian): IGuardianConfigEntry {
	const entry: IGuardianConfigEntry = {
		guardianId: parsed.guardianId.toString('hex'),
		url: parsed.url
	};
	if (parsed.auth) entry.auth = parsed.auth;
	return entry;
}

export function readGeneration(storage: IStorageBackend): bigint {
	const raw = storage.getRecoveryMeta?.(JOURNAL_META_KEYS.generation);
	if (raw == null) return 1n;
	try {
		const value = BigInt(raw);
		return value >= 1n ? value : 1n;
	} catch {
		return 1n;
	}
}

/** The configured set the journal carries, once a rotation has moved it. */
export function readGuardianSet(
	storage: IStorageBackend
): IGuardianConfigEntry[] | null {
	const raw = storage.getRecoveryMeta?.(REPLICATION_META_KEYS.guardianSet);
	if (raw == null) return null;
	try {
		const parsed = JSON.parse(raw) as unknown;
		if (!Array.isArray(parsed)) return null;
		return parsed as IGuardianConfigEntry[];
	} catch {
		return null;
	}
}

export function readRotationIntent(
	storage: IStorageBackend
): IRotationIntent | null {
	const raw = storage.getRecoveryMeta?.(ROTATION_META_KEYS.pending);
	if (raw == null) return null;
	try {
		const parsed = JSON.parse(raw) as IRotationIntent;
		return parsed.version === 1 ? parsed : null;
	} catch {
		return null;
	}
}

export function readRetirePending(
	storage: IStorageBackend
): IRetirePending | null {
	const raw = storage.getRecoveryMeta?.(ROTATION_META_KEYS.retirePending);
	if (raw == null) return null;
	try {
		const parsed = JSON.parse(raw) as IRetirePending;
		return parsed.version === 1 ? parsed : null;
	} catch {
		return null;
	}
}

export class GuardianRotation {
	private readonly config: IGuardianRotationConfig;
	private readonly clock: () => bigint;

	constructor(config: IGuardianRotationConfig) {
		this.config = config;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
		if (config.incoming.guardians.length !== CRASH_V1_PROFILE.total) {
			throw new RotationRefusedError(
				'malformed',
				`the incoming set must have exactly ${CRASH_V1_PROFILE.total} guardians`
			);
		}
		if (
			config.incoming.context.guardianSetId.equals(
				config.outgoing.context.guardianSetId
			)
		) {
			throw new RotationRefusedError(
				'same-set',
				'the incoming set is the configured set'
			);
		}
	}

	private emit(
		type: IRotationEvent['type'],
		detail: string,
		generation?: bigint
	): void {
		try {
			this.config.onEvent?.({
				type,
				detail,
				...(generation !== undefined
					? { generation: generation.toString() }
					: {})
			});
		} catch {
			// An observer's failure is never the rotation's.
		}
	}

	private prefix(generation: bigint): string {
		return `rotation:${generation}:`;
	}

	/** Steps 1 to 4. Returns once the incoming set holds the tip and the switch is durable. */
	async rotate(): Promise<IRotationResult> {
		const storage = this.config.storage;
		const current = readGeneration(storage);
		const entries = this.config.incoming.guardians.map(entryOf);
		const existing = readRotationIntent(storage);
		let generation: bigint;
		if (existing) {
			const sameSet =
				existing.entries.length === entries.length &&
				existing.entries.every(
					(e, i) => e.guardianId === entries[i].guardianId
				);
			if (!sameSet) {
				throw new RotationRefusedError(
					'in-progress',
					`a rotation to another set (generation ${existing.generation}) is already in progress; finish or resume it first`
				);
			}
			generation = BigInt(existing.generation);
		} else {
			generation = current + 1n;
			const intent: IRotationIntent = {
				version: 1,
				generation: generation.toString(),
				entries
			};
			storage.setRecoveryMeta!(
				ROTATION_META_KEYS.pending,
				JSON.stringify(intent)
			);
		}
		this.emit(
			'rotation:intent',
			`rotating to generation ${generation}`,
			generation
		);

		// Step 2: the incoming set under the current lease, on prefixed keys.
		const incoming = new GuardianReplicator({
			storage,
			guardians: this.config.incoming.bound,
			context: this.config.incoming.context,
			required: this.config.required,
			recoveryRoot: this.config.recoveryRoot,
			clock: this.clock,
			onEvent: this.config.onReplicationEvent,
			allowUnencryptedSecrets: this.config.allowUnencryptedSecrets,
			metaKeyPrefix: this.prefix(generation),
			generationOverride: generation
		});
		const registered = await incoming.registerExisting(this.config.lease);
		if (registered.accepted < this.config.required) {
			throw new RotationRefusedError(
				'no-quorum',
				`only ${registered.accepted} of the incoming set accepted the registration; ${this.config.required} are needed`
			);
		}
		this.emit(
			'rotation:registered',
			`${registered.accepted} incoming guardians registered the namespace at origin ${registered.initialState.origin.firstSequence}`,
			generation
		);

		// Step 3: backfill until the incoming quorum holds the journal tip.
		const maxPasses = this.config.maxBackfillPasses ?? 64;
		let through = 0n;
		let stalled = 0;
		for (let pass = 0; pass < maxPasses; pass++) {
			const result = await incoming.replicatePending(this.config.lease);
			const tip = this.tip();
			if (result.outcome === 'fenced') {
				throw new RotationRefusedError(
					'no-quorum',
					'the incoming set reports a newer writer; refusing to rotate a superseded lease'
				);
			}
			this.emit(
				'rotation:backfill',
				`incoming set durable through ${result.replicatedThrough} of ${tip}`,
				generation
			);
			if (result.replicatedThrough >= tip) {
				through = result.replicatedThrough;
				break;
			}
			stalled = result.replicatedThrough > through ? 0 : stalled + 1;
			through = result.replicatedThrough;
			if (stalled >= 3) {
				throw new RotationRefusedError(
					'not-catching-up',
					`the incoming set stopped advancing at ${through} of ${tip}`
				);
			}
		}
		if (through < this.tip()) {
			throw new RotationRefusedError(
				'not-catching-up',
				`the incoming set is at ${through}, the journal at ${this.tip()}, after ${maxPasses} passes`
			);
		}

		// A journal with no frames had nothing to backfill, and locally it
		// looks exactly like one whose frames were lost. Only the guardians
		// can tell the two apart, so the switch waits on both sets proving
		// the namespace holds nothing (issue #862).
		const prefix = this.prefix(generation);
		const genesis = this.journalAtGenesis(prefix);
		if (genesis) await this.proveNamespaceEmpty(incoming);

		// Step 4: the switch, and the retirement owed to the outgoing set.
		const retire = this.retireRequest(generation);
		const retirePending: IRetirePending = {
			version: 1,
			request: encodeRotateSetRequest(retire).toString('hex'),
			entries: this.config.outgoing.guardians.map(entryOf)
		};
		storage.transaction(() => {
			// Re-tested inside the transaction: a first frame committed while
			// the sets were being asked ends the genesis case, and the switch
			// then needs the watermark like any other.
			if (!(genesis && this.journalAtGenesis(prefix))) {
				// The mark is copied only if it is the TRUSTED one (bound to a
				// frame this store holds) and covers the tip; a torn or
				// unanchored copy never becomes the main watermark.
				const mark = storage.getRecoveryMeta!(
					prefix + REPLICATION_META_KEYS.replicatedThrough
				);
				const markHash = storage.getRecoveryMeta!(
					prefix + REPLICATION_META_KEYS.replicatedThroughHash
				);
				const localTip = storedTipSequence(storage);
				const trusted = incoming.replicatedThrough();
				if (
					mark == null ||
					markHash == null ||
					!/^\d+$/.test(mark) ||
					BigInt(mark) !== trusted ||
					localTip == null ||
					trusted < localTip
				) {
					const found = mark ?? 'none';
					const tip = localTip ?? 'unverifiable';
					throw new RotationRefusedError(
						'not-catching-up',
						`the incoming watermark (${found}) does not cover this journal's tip ${tip}; the rotation stays pending, and a retry backfills again`
					);
				}
				storage.setRecoveryMeta!(REPLICATION_META_KEYS.replicatedThrough, mark);
				storage.setRecoveryMeta!(
					REPLICATION_META_KEYS.replicatedThroughHash,
					markHash
				);
			}
			// At genesis nothing was receipted and nothing is owed: the zero
			// watermark is ABSENCE (raiseWatermark cannot bind below 1, and a
			// watermark row over an empty frame store is residue), so none is
			// written.
			storage.deleteRecoveryMeta?.(
				prefix + REPLICATION_META_KEYS.replicatedThrough
			);
			storage.deleteRecoveryMeta?.(
				prefix + REPLICATION_META_KEYS.replicatedThroughHash
			);
			storage.deleteRecoveryMeta?.(
				prefix + REPLICATION_META_KEYS.pendingRegistration
			);
			storage.setRecoveryMeta!(
				JOURNAL_META_KEYS.generation,
				generation.toString()
			);
			storage.setRecoveryMeta!(
				REPLICATION_META_KEYS.guardianSet,
				JSON.stringify(entries)
			);
			storage.setRecoveryMeta!(
				ROTATION_META_KEYS.retirePending,
				JSON.stringify(retirePending)
			);
			storage.deleteRecoveryMeta?.(ROTATION_META_KEYS.pending);
		});
		this.emit(
			'rotation:switched',
			`generation ${generation}; the incoming set carries the journal`,
			generation
		);

		const replicator = new GuardianReplicator({
			storage,
			guardians: this.config.incoming.bound,
			context: this.config.incoming.context,
			required: this.config.required,
			recoveryRoot: this.config.recoveryRoot,
			clock: this.clock,
			onEvent: this.config.onReplicationEvent,
			allowUnencryptedSecrets: this.config.allowUnencryptedSecrets
		});
		return {
			generation,
			replicator,
			descriptors: this.config.incoming.guardians.map(guardianDescriptorFor),
			entries
		};
	}

	/** Step 5, for this rotation's outgoing set. */
	async retireOutgoing(): Promise<number> {
		return retireOutgoingSet(
			this.config.storage,
			this.config.outgoing.bound,
			(event) => this.config.onEvent?.(event)
		);
	}

	private retireRequest(generation: bigint): IGuardianRotateSetRequest {
		const newMembers = this.config.incoming.context.members.map((m) =>
			Buffer.from(m)
		);
		const newGuardianSetId = computeGuardianSetId({
			...CRASH_V1_PROFILE,
			guardianIds: newMembers
		});
		const outgoingSetId = Buffer.from(
			this.config.outgoing.context.guardianSetId
		);
		const fields = {
			recoveryId: Buffer.from(this.config.recoveryRoot.recoveryId),
			newGuardianSetId,
			generation,
			newMembers
		};
		const byId = new Map(
			this.config.incoming.guardians.map((g) => [
				g.guardianId.toString('hex'),
				g
			])
		);
		return {
			protocolVersion: 1,
			guardianSetId: outgoingSetId,
			recoveryId: fields.recoveryId,
			newGuardianSetId,
			generation,
			newMembers,
			rootSignature: signTranscript(
				rotateTranscriptHash(outgoingSetId, fields),
				this.config.recoveryRoot.rootSecret
			),
			newTransports: newMembers.map((member) => {
				const parsed = byId.get(member.toString('hex'));
				const descriptor = parsed ? guardianDescriptorFor(parsed) : null;
				return descriptor
					? {
							type: descriptor.transports[0].type,
							url: descriptor.transports[0].url
					  }
					: { type: '', url: '' };
			})
		};
	}

	private tip(): bigint {
		const raw = this.config.storage.getRecoveryMeta?.(
			JOURNAL_META_KEYS.tipSequence
		);
		return raw != null ? BigInt(raw) : 0n;
	}

	/**
	 * This journal has never written a frame: no tip record, no watermark
	 * (main, or the incoming set's), and no frame row. Any one of them
	 * surviving means frames existed, and that store is not at genesis
	 * whatever its tip reads.
	 */
	private journalAtGenesis(prefix: string): boolean {
		const storage = this.config.storage;
		const keys = [
			JOURNAL_META_KEYS.tipSequence,
			JOURNAL_META_KEYS.tipHash,
			REPLICATION_META_KEYS.replicatedThrough,
			REPLICATION_META_KEYS.replicatedThroughHash,
			prefix + REPLICATION_META_KEYS.replicatedThrough,
			prefix + REPLICATION_META_KEYS.replicatedThroughHash
		];
		if (keys.some((key) => storage.getRecoveryMeta!(key) != null)) {
			return false;
		}
		return storedTipSequence(storage) === 0n;
	}

	/**
	 * Prove, from both sets, that the namespace holds nothing before an
	 * empty journal switches (issue #862). A store that lost its frames but
	 * kept its lease looks exactly like an unused one, and switching it
	 * would retire the outgoing set that holds the real history. Each set
	 * must confirm this lease with enough members to meet every write
	 * quorum (n - required + 1), and no signed head may be past genesis.
	 */
	private async proveNamespaceEmpty(
		incoming: GuardianReplicator
	): Promise<void> {
		const outgoing = new GuardianReplicator({
			storage: this.config.storage,
			guardians: this.config.outgoing.bound,
			context: this.config.outgoing.context,
			required: this.config.required,
			recoveryRoot: this.config.recoveryRoot,
			clock: this.clock,
			onEvent: this.config.onReplicationEvent,
			allowUnencryptedSecrets: this.config.allowUnencryptedSecrets
		});
		const sets: Array<[string, GuardianReplicator, number]> = [
			['outgoing', outgoing, this.config.outgoing.bound.length],
			['incoming', incoming, this.config.incoming.bound.length]
		];
		for (const [name, replicator, size] of sets) {
			const proof = await replicator.confirmOwnership(this.config.lease);
			if (proof.superseded || proof.rotated) {
				throw new RotationRefusedError(
					'no-quorum',
					`the ${name} set reports a newer writer or a rotation of this namespace; refusing to rotate`
				);
			}
			const held = proof.states.reduce(
				(max, state) =>
					state.logHead.sequence > max ? state.logHead.sequence : max,
				0n
			);
			if (held > 0n) {
				throw new RotationRefusedError(
					'journal-behind',
					`the ${name} set holds this namespace through ${held} but this journal has no frames; restore instead of rotating`
				);
			}
			const needed = size - this.config.required + 1;
			if (proof.confirming < needed) {
				throw new RotationRefusedError(
					'no-quorum',
					`only ${proof.confirming} of the ${name} set confirmed the namespace is empty; ${needed} are needed to rule out records this journal lost`
				);
			}
		}
	}
}

/**
 * Present the persisted retirement to the outgoing set (wire 5.9 step 5).
 * Any member accepting (OK or OK_DUPLICATE) discharges it: a restore device
 * reading that member finds the rotation. Returns how many accepted; 0 leaves
 * the retirement pending for a later attempt.
 */
export async function retireOutgoingSet(
	storage: IStorageBackend,
	outgoing: IBoundGuardianClient[],
	onEvent?: (event: IRotationEvent) => void
): Promise<number> {
	const pending = readRetirePending(storage);
	if (!pending) return 0;
	const request = decodeRotateSetRequest(Buffer.from(pending.request, 'hex'));
	const answers = await boundFanOut(outgoing, (client: GuardianClient) =>
		client.rotateSet(request)
	);
	const accepted = answers.filter(
		(entry) =>
			entry.result?.status === GuardianStatus.OK ||
			entry.result?.status === GuardianStatus.OK_DUPLICATE
	).length;
	if (accepted > 0) {
		storage.deleteRecoveryMeta?.(ROTATION_META_KEYS.retirePending);
		onEvent?.({
			type: 'rotation:retired',
			detail: `${accepted} outgoing guardians retired the namespace`,
			generation: request.generation.toString()
		});
	} else {
		onEvent?.({
			type: 'rotation:retire-pending',
			detail: `no outgoing guardian accepted the retirement yet (${answers
				.map((a) => a.result?.status ?? a.error?.message ?? 'no answer')
				.join(', ')})`,
			generation: request.generation.toString()
		});
	}
	return accepted;
}

/** The state a rotation left behind, for status surfaces. */
export function describeRotation(storage: IStorageBackend): {
	generation: string;
	pending: IRotationIntent | null;
	retirePending: boolean;
	guardianSet: IGuardianConfigEntry[] | null;
} {
	return {
		generation: readGeneration(storage).toString(),
		pending: readRotationIntent(storage),
		retirePending: readRetirePending(storage) !== null,
		guardianSet: readGuardianSet(storage)
	};
}
