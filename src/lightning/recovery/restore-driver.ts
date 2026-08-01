/**
 * The restore driver (docs/RECOVERY-PROTOCOL.md 5.7, Phase 5): turning a
 * seed plus a guardian set back into a running node.
 *
 * The order of operations is the whole point, and it is not negotiable:
 *
 * ```text
 * read heads from all reachable guardians (need `required` responses)
 *       |
 * reconcile the highest quorum-consistent head
 *       |
 * repair laggards: SYNC_RECORD for records, SYNC_EPOCH for takeovers
 *       |
 * ACQUIRE_EPOCH(expectedState): CAS takeover, retried IDEMPOTENTLY
 *       |
 * FENCE IS NOW IN PLACE
 *       |
 * download, verify against the certified head, reconstruct, persist lease
 * ```
 *
 * Fence before restore, never the reverse (5.7). The invariant precisely:
 * NO DOWNLOADED STATE IS INSTALLED OR USED FOR LOCAL RECONSTRUCTION before
 * the takeover fixes the superseded epoch's final head. Records ARE fetched
 * earlier than that, because repairing a lagging guardian means relaying
 * records to it, and without that repair the CAS can never assemble a
 * quorum at all; those records are relayed, never installed. If
 * reconstruction ran first, a still-live old device could certify one more
 * state between this device's fetch and its acquisition, and the restored
 * node would hold a stale head while believing it is current.
 *
 * Every refusal in here is deliberate. Adopting a head lower than a
 * committed one, taking over without a quorum, or treating one guardian's
 * word as proof would each trade a provable state for a plausible one, and
 * this protocol exists precisely to refuse that trade.
 */

import { IStorageBackend, IStoredRecoveryFrame } from '../storage/types';
import {
	GuardianState,
	parseStateBytes,
	stateBytes,
	statesEqual
} from './guardian-wire';
import {
	GuardianStatus,
	IGuardianAcquireEpochRequest,
	IGuardianRecord,
	IGuardianTakeoverCertificate
} from './guardian';
import {
	GuardianClient,
	IBoundGuardianClient,
	IGuardianSetContext,
	boundFanOut,
	verifyGuardianBindings,
	verifyGuardianCertificate,
	verifyGuardianReceipt
} from './guardian-client';
import {
	JOURNAL_META_KEYS,
	deriveRecoveryMasterKey,
	reconstructFromFrames,
	verifyFrameChain
} from './journal';
import { RecoveryFrame } from './types';
import {
	IWriterLeaseKeys,
	generateWriterKey,
	saveWriterLease,
	signAcquisition
} from './writer-lease';

/** Where an interrupted acquisition is remembered (see IPendingAcquisition). */
const META_PENDING_ACQUISITION = 'restore_pending_acquisition_v1';

export const RESTORE_META_KEYS = {
	pendingAcquisition: META_PENDING_ACQUISITION
} as const;

/**
 * A restore refused. Every one of these is a state where continuing would
 * mean asserting something the protocol cannot prove.
 */
export class RestoreRefusedError extends Error {
	readonly reason:
		| 'no-quorum'
		| 'unknown-namespace'
		| 'conflict'
		| 'cas-exhausted'
		| 'head-unverifiable';

	constructor(reason: RestoreRefusedError['reason'], message: string) {
		super(message);
		this.name = 'RestoreRefusedError';
		this.reason = reason;
	}
}

export interface IRestoreDriverConfig {
	/** The EMPTY database the restored node will run on. */
	target: IStorageBackend;
	/** Guardians bound to the identities they must prove they hold. */
	guardians: IBoundGuardianClient[];
	context: IGuardianSetContext;
	required: number;
	recoveryRoot: { rootSecret: Buffer; recoveryId: Buffer };
	/** The node identity secret: derives the journal master key. */
	nodeSecret: Buffer;
	/** Node id as the journal's AAD binding uses it. */
	nodeId: Buffer;
	clock?: () => bigint;
	onEvent?: (event: IRestoreEvent) => void;
	/** Records per GET_STATE page; the protocol caps this at 256. */
	pageSize?: number;
	/** CAS rounds before giving up. Each round retries the SAME request. */
	maxCasAttempts?: number;
	allowUnencryptedSecrets?: boolean;
}

export interface IRestoreEvent {
	type:
		| 'heads:read'
		| 'head:adopted'
		| 'guardian:repaired'
		| 'epoch:acquired'
		| 'epoch:cas-retry'
		| 'epoch:resumed'
		| 'epoch:abandoned'
		| 'frames:downloaded'
		| 'restore:complete';
	detail: string;
}

export interface IRestoreResult {
	/** The lease this device now holds, already persisted. */
	lease: IWriterLeaseKeys;
	/** The superseded epoch's final head, fixed by the takeover. */
	certifiedState: GuardianState;
	/** Certificates proving the takeover, from `required` distinct guardians. */
	certificates: IGuardianTakeoverCertificate[];
	/** Frames downloaded and replayed. */
	framesApplied: number;
	/** Guardians repaired before the CAS could assemble its quorum. */
	guardiansRepaired: number;
}

interface IHeadReading {
	client: GuardianClient;
	guardianId: Buffer;
	state: GuardianState;
	certificates: IGuardianTakeoverCertificate[];
	possiblyStale: boolean;
}

interface IPendingAttempt {
	expectedState: GuardianState;
	newEpoch: bigint;
	writer: { secret: Buffer; publicKey: Buffer };
}

/**
 * An acquisition already sent to at least one guardian, persisted BEFORE
 * the request goes out.
 *
 * An acquisition stops being a local decision the moment a guardian accepts
 * it: that guardian is now bound to this exact (epoch, writer key), and the
 * only way to finish the takeover is to present the IDENTICAL request
 * again, which the protocol answers idempotently with the stored
 * certificate. Generating a fresh key on retry instead would strand the
 * accepted epoch and chase the log upward one guardian at a time, burning
 * an epoch per attempt and never assembling a quorum.
 */
interface IPersistedAcquisitionV1 {
	version: 1;
	expectedState: string;
	newEpoch: string;
	writerSecret: string;
	writerPublicKey: string;
}

export class RestoreDriver {
	private readonly config: IRestoreDriverConfig;
	private readonly clock: () => bigint;
	private readonly pageSize: number;
	private readonly maxCasAttempts: number;
	private verifiedBindings: Set<string> | null = null;

	constructor(config: IRestoreDriverConfig) {
		if (config.required < 1 || config.required > config.guardians.length) {
			throw new Error('required quorum is outside the configured guardian set');
		}
		this.config = config;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
		this.pageSize = Math.min(config.pageSize ?? 64, 256);
		this.maxCasAttempts = config.maxCasAttempts ?? 4;
	}

	private emit(type: IRestoreEvent['type'], detail: string): void {
		this.config.onEvent?.({ type, detail });
	}

	private async ensureBindings(): Promise<Set<string>> {
		if (this.verifiedBindings) return this.verifiedBindings;
		this.verifiedBindings = await verifyGuardianBindings(
			this.config.guardians,
			this.config.context
		);
		return this.verifiedBindings;
	}

	// ─────────────── pending acquisition ───────────────

	private loadPending(): IPendingAttempt | null {
		const raw = this.config.target.getRecoveryMeta?.(META_PENDING_ACQUISITION);
		if (raw == null) return null;
		let parsed: IPersistedAcquisitionV1;
		try {
			parsed = JSON.parse(raw) as IPersistedAcquisitionV1;
		} catch {
			return null;
		}
		if (parsed.version !== 1) return null;
		try {
			return {
				expectedState: parseStateBytes(
					Buffer.from(parsed.expectedState, 'hex')
				),
				newEpoch: BigInt(parsed.newEpoch),
				writer: {
					secret: Buffer.from(parsed.writerSecret, 'hex'),
					publicKey: Buffer.from(parsed.writerPublicKey, 'hex')
				}
			};
		} catch {
			return null;
		}
	}

	private savePending(attempt: IPendingAttempt): void {
		const payload: IPersistedAcquisitionV1 = {
			version: 1,
			expectedState: stateBytes(attempt.expectedState).toString('hex'),
			newEpoch: attempt.newEpoch.toString(),
			writerSecret: attempt.writer.secret.toString('hex'),
			writerPublicKey: attempt.writer.publicKey.toString('hex')
		};
		this.config.target.setRecoveryMeta?.(
			META_PENDING_ACQUISITION,
			JSON.stringify(payload)
		);
	}

	private clearPending(): void {
		this.config.target.deleteRecoveryMeta?.(META_PENDING_ACQUISITION);
	}

	// ─────────────── head reading and reconciliation ───────────────

	/**
	 * Step 1: read heads. A guardian counts toward the read set only when it
	 * answers with a receipt that VERIFIES under a member key, covers the
	 * state it accompanies, is signed by the identity this endpoint is bound
	 * to, and is not flagged possibly_stale. A possibly_stale guardian
	 * cannot prove its store intact (wire 5.3): it may be a repair target,
	 * but it is never evidence of recency.
	 */
	private async readHeads(): Promise<{
		readings: IHeadReading[];
		stale: IHeadReading[];
	}> {
		const verified = await this.ensureBindings();
		const recoveryId = this.config.recoveryRoot.recoveryId;
		const responses = await boundFanOut(this.config.guardians, (client) =>
			client.getHead(recoveryId)
		);
		const answered = responses.filter((entry) => entry.result !== undefined);
		if (answered.length < this.config.required) {
			throw new RestoreRefusedError(
				'no-quorum',
				`only ${answered.length} of ${this.config.guardians.length} guardians answered; ` +
					'without a quorum there is no fencing and no recency proof'
			);
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
		if (unknown.size >= this.config.required) {
			throw new RestoreRefusedError(
				'unknown-namespace',
				'the guardian set does not serve this namespace; there is nothing to restore'
			);
		}

		const readings: IHeadReading[] = [];
		const stale: IHeadReading[] = [];
		const counted = new Set<string>();
		for (const entry of answered) {
			const response = entry.result;
			if (!response || response.status !== GuardianStatus.OK) continue;
			if (!response.state || !response.receipt) continue;
			if (!verifyGuardianReceipt(response.receipt, this.config.context)) {
				continue;
			}
			if (!statesEqual(response.receipt.state, response.state)) continue;
			if (!response.receipt.guardianId.equals(entry.guardianId as Buffer)) {
				continue;
			}
			const reading: IHeadReading = {
				client: entry.client,
				guardianId: entry.guardianId as Buffer,
				state: response.state,
				certificates: (response.certificates ?? []).filter((cert) =>
					verifyGuardianCertificate(cert, this.config.context)
				),
				possiblyStale: response.possiblyStale === true
			};
			if (reading.possiblyStale) {
				stale.push(reading);
				continue;
			}
			const key = reading.guardianId.toString('hex');
			if (counted.has(key)) continue;
			counted.add(key);
			readings.push(reading);
		}
		if (readings.length < this.config.required) {
			throw new RestoreRefusedError(
				'no-quorum',
				`only ${readings.length} distinct guardians returned a verifiable, ` +
					`non-stale head (${stale.length} were possibly stale)`
			);
		}
		this.emit(
			'heads:read',
			`${readings.length} usable heads, ${stale.length} possibly stale`
		);
		return { readings, stale };
	}

	/**
	 * Step 6 of 5.7: two distinct records at one position, or certificates
	 * that disagree about one epoch, are outside the crash-fault model. Halt
	 * and surface them; take no channel action.
	 */
	private assertNoConflict(readings: IHeadReading[]): void {
		// Records are compared by their OWN position (recordEpoch, sequence),
		// not by the guardian's current lease, which legitimately differs from
		// the record epoch after a takeover.
		const byPosition = new Map<string, GuardianState>();
		for (const reading of readings) {
			const head = reading.state.logHead;
			if (head.sequence === 0n) continue;
			const key = `${head.recordEpoch}:${head.sequence}`;
			const seen = byPosition.get(key);
			if (
				seen &&
				(!seen.logHead.frameHash.equals(head.frameHash) ||
					!seen.logHead.ciphertextHash.equals(head.ciphertextHash))
			) {
				throw new RestoreRefusedError(
					'conflict',
					`two distinct records at epoch ${head.recordEpoch} sequence ${head.sequence}; ` +
						'outside the crash-fault model, halting the restore'
				);
			}
			if (!seen) byPosition.set(key, reading.state);
		}
		const byEpoch = new Map<string, IGuardianTakeoverCertificate>();
		for (const reading of readings) {
			for (const cert of reading.certificates) {
				const key = cert.newEpoch.toString();
				const seen = byEpoch.get(key);
				if (
					seen &&
					(!stateBytes(seen.supersededState).equals(
						stateBytes(cert.supersededState)
					) ||
						// Two valid certificates granting ONE epoch to different
						// writer keys is exactly the conflict this check exists for.
						!seen.newWriterPublicKey.equals(cert.newWriterPublicKey))
				) {
					throw new RestoreRefusedError(
						'conflict',
						`conflicting takeover certificates for epoch ${cert.newEpoch}; ` +
							'outside the crash-fault model, halting the restore'
					);
				}
				if (!seen) byEpoch.set(key, cert);
			}
		}
	}

	/**
	 * Every certificate any guardian returned, grouped by the takeover it
	 * describes and deduplicated by signer. A bundle is only a bundle when
	 * `required` DISTINCT guardians certified the same takeover, and no
	 * single reading is guaranteed to carry the whole thing.
	 */
	private certificateBundles(
		readings: IHeadReading[]
	): IGuardianTakeoverCertificate[][] {
		const groups = new Map<string, Map<string, IGuardianTakeoverCertificate>>();
		for (const reading of readings) {
			for (const cert of reading.certificates) {
				const key = [
					cert.newEpoch.toString(),
					cert.newWriterPublicKey.toString('hex'),
					stateBytes(cert.supersededState).toString('hex')
				].join('|');
				const bySigner = groups.get(key) ?? new Map();
				bySigner.set(cert.guardianId.toString('hex'), cert);
				groups.set(key, bySigner);
			}
		}
		return [...groups.values()].map((bySigner) => [...bySigner.values()]);
	}

	/**
	 * Step 2, exactly as specified: within one epoch adopt the highest valid
	 * record head, even when it was not quorum-receipted, because a frame
	 * that never reached quorum is still a state the writer produced and
	 * reestablish reconciles it. ACROSS epochs adopt the highest epoch
	 * BACKED BY A QUORUM OF TAKEOVER CERTIFICATES: a single guardian sitting
	 * at a higher epoch proves only that it accepted an acquisition, which a
	 * partially completed takeover also produces.
	 */
	private selectHead(readings: IHeadReading[]): IHeadReading {
		const certifiedEpochs = new Set<string>();
		for (const bundle of this.certificateBundles(readings)) {
			if (bundle.length >= this.config.required) {
				certifiedEpochs.add(bundle[0].newEpoch.toString());
			}
		}
		const lowestEpoch = readings.reduce(
			(min, reading) =>
				reading.state.lease.epoch < min ? reading.state.lease.epoch : min,
			readings[0].state.lease.epoch
		);
		// An epoch is established when a quorum certified it, or when it is
		// simply the epoch the set is already at (the genesis case, where no
		// takeover certificate exists at all).
		const eligible = readings.filter(
			(reading) =>
				reading.state.lease.epoch === lowestEpoch ||
				certifiedEpochs.has(reading.state.lease.epoch.toString())
		);
		const pool = eligible.length > 0 ? eligible : readings;
		const highest = pool.reduce(
			(max, reading) =>
				reading.state.lease.epoch > max ? reading.state.lease.epoch : max,
			pool[0].state.lease.epoch
		);
		const atEpoch = pool.filter(
			(reading) => reading.state.lease.epoch === highest
		);
		return atEpoch.reduce((best, candidate) =>
			candidate.state.logHead.sequence > best.state.logHead.sequence
				? candidate
				: best
		);
	}

	/**
	 * Step 3: repair laggards until `required` guardians share the adopted
	 * head. Certificate bundles are assembled across ALL readings, since a
	 * single guardian's response need not carry the whole quorum.
	 */
	private async repairLaggards(
		readings: IHeadReading[],
		stale: IHeadReading[],
		target: IHeadReading
	): Promise<number> {
		let repaired = 0;
		const bundles = this.certificateBundles(readings);
		const forEpoch = (epoch: bigint): IGuardianTakeoverCertificate[] =>
			bundles.find(
				(bundle) =>
					bundle[0].newEpoch === epoch && bundle.length >= this.config.required
			) ?? [];
		// Stale guardians are repair TARGETS too: bringing them back is how a
		// set recovers, even though their word never counted as recency.
		for (const reading of [...readings, ...stale]) {
			if (statesEqual(reading.state, target.state)) continue;
			if (reading.state.lease.epoch < target.state.lease.epoch) {
				const bundle = forEpoch(target.state.lease.epoch);
				if (bundle.length >= this.config.required) {
					await reading.client.syncEpoch(bundle);
				}
			}
			if (reading.state.logHead.sequence < target.state.logHead.sequence) {
				const missing = await this.downloadRecords(
					target.client,
					reading.state.logHead.sequence,
					target.state.logHead.sequence
				);
				for (const record of missing) {
					const response = await reading.client.syncRecord(record);
					if (
						response.status !== GuardianStatus.OK &&
						response.status !== GuardianStatus.OK_DUPLICATE
					) {
						break;
					}
				}
			}
			const after = await reading.client.getHead(
				this.config.recoveryRoot.recoveryId
			);
			if (
				after.status === GuardianStatus.OK &&
				after.state &&
				statesEqual(after.state, target.state)
			) {
				repaired += 1;
				this.emit(
					'guardian:repaired',
					`a lagging guardian was brought to sequence ${target.state.logHead.sequence}`
				);
			}
		}
		return repaired;
	}

	/** Paged GET_STATE download over (from, through]. */
	private async downloadRecords(
		client: GuardianClient,
		fromExclusive: bigint,
		through: bigint
	): Promise<IGuardianRecord[]> {
		const records: IGuardianRecord[] = [];
		let cursor = fromExclusive;
		while (cursor < through) {
			const page = await client.getState(
				this.config.recoveryRoot.recoveryId,
				cursor,
				this.pageSize
			);
			const batch = page.records ?? [];
			if (batch.length === 0) break;
			for (const record of batch) {
				if (record.sequence > through) break;
				records.push(record);
				cursor = record.sequence;
			}
			if (!page.hasMore) break;
		}
		return records;
	}

	/** Verified certificates for one EXACT acquisition, by distinct signer. */
	private collectCertificates(
		results: Array<{
			guardianId?: Buffer;
			result?: {
				status: GuardianStatus;
				certificate?: IGuardianTakeoverCertificate;
			};
		}>,
		attempt: IPendingAttempt
	): IGuardianTakeoverCertificate[] {
		const bySigner = new Map<string, IGuardianTakeoverCertificate>();
		for (const entry of results) {
			const response = entry.result;
			if (!response) continue;
			if (
				response.status !== GuardianStatus.OK &&
				response.status !== GuardianStatus.OK_DUPLICATE
			) {
				continue;
			}
			const cert = response.certificate;
			if (!cert || !verifyGuardianCertificate(cert, this.config.context)) {
				continue;
			}
			if (!statesEqual(cert.supersededState, attempt.expectedState)) continue;
			if (cert.newEpoch !== attempt.newEpoch) continue;
			if (!cert.newWriterPublicKey.equals(attempt.writer.publicKey)) continue;
			if (entry.guardianId && !cert.guardianId.equals(entry.guardianId)) {
				continue;
			}
			bySigner.set(cert.guardianId.toString('hex'), cert);
		}
		return [...bySigner.values()];
	}

	/**
	 * Steps 4 and 5: the CAS takeover. An attempt is PERSISTED before it is
	 * sent and RETRIED IDENTICALLY, because once a guardian accepts an
	 * acquisition it is bound to that exact (epoch, writer key) and answers
	 * the repeat with its stored certificate. Only evidence that a DIFFERENT
	 * acquisition reached quorum retires a pending one.
	 */
	private async acquireEpoch(
		target: IHeadReading,
		readings: IHeadReading[],
		stale: IHeadReading[]
	): Promise<{
		lease: IWriterLeaseKeys;
		certifiedState: GuardianState;
		certificates: IGuardianTakeoverCertificate[];
		repaired: number;
		source: IHeadReading;
	}> {
		let expected = target;
		let pool = readings;
		let stalePool = stale;
		let repaired = 0;
		let pending = this.loadPending();
		if (pending) {
			this.emit(
				'epoch:resumed',
				`resuming the acquisition of epoch ${pending.newEpoch} with its original writer key`
			);
		}

		for (let attempt = 1; attempt <= this.maxCasAttempts; attempt++) {
			repaired += await this.repairLaggards(pool, stalePool, expected);
			if (!pending) {
				pending = {
					expectedState: expected.state,
					newEpoch: expected.state.lease.epoch + 1n,
					writer: generateWriterKey()
				};
				// Persisted BEFORE the request leaves: a crash after one
				// guardian accepts must not lose the key it is now bound to.
				this.savePending(pending);
			}
			const request: IGuardianAcquireEpochRequest = {
				protocolVersion: 1,
				guardianSetId: Buffer.from(this.config.context.guardianSetId),
				expectedState: pending.expectedState,
				newEpoch: pending.newEpoch,
				newWriterPublicKey: pending.writer.publicKey,
				...signAcquisition(
					this.config.context.guardianSetId,
					pending.expectedState,
					pending.newEpoch,
					pending.writer,
					this.config.recoveryRoot.rootSecret
				)
			};
			const results = await boundFanOut(this.config.guardians, (client) =>
				client.acquireEpoch(request)
			);
			const certificates = this.collectCertificates(results, pending);
			if (certificates.length >= this.config.required) {
				const lease: IWriterLeaseKeys = {
					epoch: pending.newEpoch,
					writerSecret: pending.writer.secret,
					writerPublicKey: pending.writer.publicKey,
					guardianCertificates: certificates,
					confirmedAt: this.clock()
				};
				this.clearPending();
				this.emit(
					'epoch:acquired',
					`epoch ${pending.newEpoch} acquired with ${certificates.length} certificates over sequence ${pending.expectedState.logHead.sequence}`
				);
				const certified = pending.expectedState;
				const source =
					pool.find((reading) => statesEqual(reading.state, certified)) ??
					expected;
				return {
					lease,
					certifiedState: certified,
					certificates,
					repaired,
					source
				};
			}

			this.emit(
				'epoch:cas-retry',
				`attempt ${attempt} collected ${certificates.length} of ${this.config.required} certificates`
			);
			const refreshed = await this.readHeads();
			this.assertNoConflict(refreshed.readings);
			pool = refreshed.readings;
			stalePool = refreshed.stale;
			expected = this.selectHead(pool);
			// A pending acquisition is kept and retried VERBATIM while any
			// guardian might be bound to it, which is what makes a partial
			// acceptance recoverable. It is retired in exactly two cases.
			const attemptSoFar = pending as IPendingAttempt;
			// One: a quorum-certified takeover superseded it, so it can never
			// complete no matter how often it is retried.
			const superseded = this.certificateBundles(pool).some(
				(bundle) =>
					bundle.length >= this.config.required &&
					(bundle[0].newEpoch > attemptSoFar.newEpoch ||
						(bundle[0].newEpoch === attemptSoFar.newEpoch &&
							!bundle[0].newWriterPublicKey.equals(
								attemptSoFar.writer.publicKey
							)))
			);
			// Two: NOTHING is bound to it (no certificate collected, and no
			// guardian is sitting at its epoch and key), while the reconciled
			// head has moved on. That is the still-live-old-writer case: the
			// CAS guard is simply stale, nobody accepted the attempt, and
			// re-targeting costs no epoch that anyone acknowledged.
			const acceptedSomewhere =
				certificates.length > 0 ||
				pool.some(
					(reading) =>
						reading.state.lease.epoch === attemptSoFar.newEpoch &&
						reading.state.lease.writerPublicKey.equals(
							attemptSoFar.writer.publicKey
						)
				);
			const guardMoved = !statesEqual(
				expected.state,
				attemptSoFar.expectedState
			);
			if (superseded || (!acceptedSomewhere && guardMoved)) {
				this.emit(
					'epoch:abandoned',
					superseded
						? `epoch ${attemptSoFar.newEpoch} was won by another writer; starting a new acquisition`
						: `the guard for epoch ${attemptSoFar.newEpoch} is stale and no guardian accepted it; re-targeting`
				);
				this.clearPending();
				pending = null;
			}
		}
		throw new RestoreRefusedError(
			'cas-exhausted',
			`the takeover could not assemble ${this.config.required} certificates in ${this.maxCasAttempts} attempts`
		);
	}

	/**
	 * Restore this node from the guardian set. The target database must be
	 * empty; the returned lease is already persisted, so the node that comes
	 * up on this database is the fenced current writer.
	 */
	async restore(): Promise<IRestoreResult> {
		const { readings, stale } = await this.readHeads();
		this.assertNoConflict(readings);
		const target = this.selectHead(readings);
		this.emit(
			'head:adopted',
			`adopted epoch ${target.state.lease.epoch} sequence ${target.state.logHead.sequence}`
		);

		// FENCE FIRST. Nothing below this line may install downloaded state.
		const acquired = await this.acquireEpoch(target, readings, stale);
		const certified = acquired.certifiedState;

		// Download from a guardian known to hold the CERTIFIED head, which is
		// not necessarily the one whose head was adopted first.
		const records = await this.downloadRecords(
			acquired.source.client,
			0n,
			certified.logHead.sequence
		);
		const last = records[records.length - 1];
		if (
			certified.logHead.sequence > 0n &&
			(!last ||
				last.sequence !== certified.logHead.sequence ||
				!last.frameHash.equals(certified.logHead.frameHash))
		) {
			throw new RestoreRefusedError(
				'head-unverifiable',
				`the downloaded log ends at ${
					last?.sequence ?? 0n
				}, not at the certified head ${certified.logHead.sequence}`
			);
		}
		this.emit(
			'frames:downloaded',
			`${records.length} records through sequence ${certified.logHead.sequence}`
		);

		const rows: IStoredRecoveryFrame[] = records.map((record) => ({
			sequence: Number(record.sequence),
			writerEpoch: Number(record.epoch),
			frameHash: Buffer.from(record.frameHash),
			previousFrameHash: Buffer.from(record.previousHash),
			ciphertext: Buffer.from(record.ciphertext),
			createdAt: Number(this.clock())
		}));
		// The chain is verified against the CERTIFIED head, not against
		// whatever the download happened to contain.
		const frames: RecoveryFrame[] = verifyFrameChain(
			rows,
			{
				tipSequence: certified.logHead.sequence.toString(),
				tipHash: certified.logHead.frameHash.toString('hex'),
				lastSnapshotSequence: String(rows[0]?.sequence ?? 0)
			},
			deriveRecoveryMasterKey(this.config.nodeSecret),
			this.config.nodeId
		);

		const targetStorage = this.config.target;
		targetStorage.transaction(() => {
			for (const row of rows) targetStorage.saveRecoveryFrame!(row);
			targetStorage.setRecoveryMeta!(
				JOURNAL_META_KEYS.tipSequence,
				certified.logHead.sequence.toString()
			);
			targetStorage.setRecoveryMeta!(
				JOURNAL_META_KEYS.tipHash,
				certified.logHead.frameHash.toString('hex')
			);
			targetStorage.setRecoveryMeta!(
				JOURNAL_META_KEYS.lastSnapshot,
				String(rows[0]?.sequence ?? 0)
			);
		});
		reconstructFromFrames(targetStorage, frames);
		// The lease is written LAST and carries the new epoch, so the journal
		// stamps every subsequent frame under the epoch this device owns.
		saveWriterLease(targetStorage, acquired.lease, {
			allowUnencryptedSecrets: this.config.allowUnencryptedSecrets
		});
		this.emit(
			'restore:complete',
			`restored ${frames.length} frames under epoch ${acquired.lease.epoch}`
		);
		return {
			lease: acquired.lease,
			certifiedState: certified,
			certificates: acquired.certificates,
			framesApplied: frames.length,
			guardiansRepaired: acquired.repaired
		};
	}
}
