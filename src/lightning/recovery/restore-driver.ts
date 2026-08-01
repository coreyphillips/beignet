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
 * ACQUIRE_EPOCH(expectedState): CAS takeover, refetch and retry on failure
 *       |
 * FENCE IS NOW IN PLACE, and only now download frames
 *       |
 * verify the chain against the certified head, reconstruct, persist lease
 * ```
 *
 * Fence before restore, never the reverse (5.7). If reconstruction happened
 * first, a still-live old device could certify one more state between this
 * device's fetch and its acquisition, and the restored node would hold a
 * stale head while believing it is current. With the CAS first, the
 * superseded epoch's head is immutable before a single frame is downloaded,
 * so what gets reconstructed is provably the final certified state of the
 * old epoch.
 *
 * Every refusal in here is deliberate. Adopting a head lower than a
 * committed one, registering over a live namespace, or taking over without
 * a quorum would each trade a provable state for a plausible one, and this
 * protocol exists precisely to refuse that trade.
 */

import { IStorageBackend, IStoredRecoveryFrame } from '../storage/types';
import { GuardianState, statesEqual, stateBytes } from './guardian-wire';
import {
	GuardianStatus,
	IGuardianRecord,
	IGuardianTakeoverCertificate
} from './guardian';
import {
	GuardianClient,
	IGuardianSetContext,
	guardianFanOut,
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
	clients: GuardianClient[];
	context: IGuardianSetContext;
	required: number;
	recoveryRoot: { rootSecret: Buffer; recoveryId: Buffer };
	/** The node identity secret: derives the journal master key. */
	nodeSecret: Buffer;
	/** x-only or compressed node id, as the journal's AAD binding uses it. */
	nodeId: Buffer;
	clock?: () => bigint;
	onEvent?: (event: IRestoreEvent) => void;
	/** Records per GET_STATE page; the protocol caps this at 256. */
	pageSize?: number;
	/** CAS attempts before giving up (each refetches the newer head). */
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
	state: GuardianState;
	certificates: IGuardianTakeoverCertificate[];
}

export class RestoreDriver {
	private readonly config: IRestoreDriverConfig;
	private readonly clock: () => bigint;
	private readonly pageSize: number;
	private readonly maxCasAttempts: number;

	constructor(config: IRestoreDriverConfig) {
		if (config.required < 1 || config.required > config.clients.length) {
			throw new Error('required quorum is outside the configured client set');
		}
		this.config = config;
		this.clock = config.clock ?? ((): bigint => BigInt(Date.now()));
		this.pageSize = Math.min(config.pageSize ?? 64, 256);
		this.maxCasAttempts = config.maxCasAttempts ?? 4;
	}

	private emit(type: IRestoreEvent['type'], detail: string): void {
		this.config.onEvent?.({ type, detail });
	}

	/**
	 * Step 1: read heads. Proceed only with `required` responses, because any
	 * commit quorum intersects any read set of that size, so the highest
	 * committed head is always visible among them (5.7 step 1).
	 */
	private async readHeads(): Promise<IHeadReading[]> {
		const recoveryId = this.config.recoveryRoot.recoveryId;
		const responses = await guardianFanOut(this.config.clients, (client) =>
			client.getHead(recoveryId)
		);
		const answered = responses.filter((entry) => entry.result !== undefined);
		if (answered.length < this.config.required) {
			throw new RestoreRefusedError(
				'no-quorum',
				`only ${answered.length} of ${this.config.clients.length} guardians answered; ` +
					'without a quorum there is no fencing and no recency proof'
			);
		}
		const unknown = answered.filter(
			(entry) => entry.result?.status === GuardianStatus.ERR_UNKNOWN_NODE
		);
		if (unknown.length >= this.config.required) {
			throw new RestoreRefusedError(
				'unknown-namespace',
				'the guardian set does not serve this namespace; there is nothing to restore'
			);
		}
		const readings: IHeadReading[] = [];
		for (const entry of answered) {
			const response = entry.result;
			if (!response || response.status !== GuardianStatus.OK) continue;
			if (!response.state || !response.receipt) continue;
			// A head is evidence only when its receipt verifies under a member
			// key of the committed set: an unsigned claim is just a claim.
			if (!verifyGuardianReceipt(response.receipt, this.config.context)) {
				continue;
			}
			if (!statesEqual(response.receipt.state, response.state)) continue;
			readings.push({
				client: entry.client,
				state: response.state,
				certificates: (response.certificates ?? []).filter((cert) =>
					verifyGuardianCertificate(cert, this.config.context)
				)
			});
		}
		if (readings.length < this.config.required) {
			throw new RestoreRefusedError(
				'head-unverifiable',
				`only ${readings.length} guardians returned a verifiable head`
			);
		}
		this.emit(
			'heads:read',
			`${readings.length} verifiable heads from ${answered.length} responses`
		);
		return readings;
	}

	/**
	 * Step 6 of 5.7, checked before anything is adopted: two distinct records
	 * at the same position, or conflicting certificates for one epoch, are
	 * outside the crash-fault model. Halt and surface both artifacts; take no
	 * channel action.
	 */
	private assertNoConflict(readings: IHeadReading[]): void {
		const bySequence = new Map<string, GuardianState>();
		for (const reading of readings) {
			const head = reading.state.logHead;
			if (head.sequence === 0n) continue;
			const key = `${reading.state.lease.epoch}:${head.sequence}`;
			const seen = bySequence.get(key);
			if (
				seen &&
				(!seen.logHead.frameHash.equals(head.frameHash) ||
					!seen.logHead.ciphertextHash.equals(head.ciphertextHash))
			) {
				throw new RestoreRefusedError(
					'conflict',
					`two distinct records at epoch ${reading.state.lease.epoch} sequence ${head.sequence}; ` +
						'outside the crash-fault model, halting the restore'
				);
			}
			if (!seen) bySequence.set(key, reading.state);
		}
		const byEpoch = new Map<string, IGuardianTakeoverCertificate>();
		for (const reading of readings) {
			for (const cert of reading.certificates) {
				const key = `${cert.newEpoch}`;
				const seen = byEpoch.get(key);
				if (
					seen &&
					!stateBytes(seen.supersededState).equals(
						stateBytes(cert.supersededState)
					)
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
	 * Step 2: adopt the highest head. Higher-than-committed is safe (a frame
	 * that never reached quorum is still a state the writer produced, and
	 * reestablish reconciles it with the peer); adopting anything LOWER than
	 * a committed head never is.
	 */
	private selectHead(readings: IHeadReading[]): IHeadReading {
		return readings.reduce((best, candidate) => {
			if (candidate.state.lease.epoch !== best.state.lease.epoch) {
				return candidate.state.lease.epoch > best.state.lease.epoch
					? candidate
					: best;
			}
			return candidate.state.logHead.sequence > best.state.logHead.sequence
				? candidate
				: best;
		});
	}

	/**
	 * Step 3: repair laggards until `required` guardians share the adopted
	 * head. Without this the CAS can never assemble a quorum: a lagging
	 * guardian rejects the adopted state, and an up-to-date one rejects the
	 * lower one as a rollback (5.7 worked example).
	 */
	private async repairLaggards(
		readings: IHeadReading[],
		target: IHeadReading
	): Promise<number> {
		let repaired = 0;
		for (const reading of readings) {
			if (statesEqual(reading.state, target.state)) continue;
			// Epoch first: a guardian that missed a takeover cannot accept
			// records written under the newer epoch (wire 5.6).
			if (reading.state.lease.epoch < target.state.lease.epoch) {
				const bundle = target.certificates.filter(
					(cert) => cert.newEpoch === target.state.lease.epoch
				);
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

	/**
	 * Steps 4 and 5: CAS takeover against the reconciled head, refetching
	 * and retrying when a guardian reports a newer state. Success means
	 * `required` distinct guardians certified the superseded epoch's FINAL
	 * head, so it is immutable from here on.
	 */
	private async acquireEpoch(
		target: IHeadReading,
		readings: IHeadReading[]
	): Promise<{
		lease: IWriterLeaseKeys;
		certifiedState: GuardianState;
		certificates: IGuardianTakeoverCertificate[];
		repaired: number;
	}> {
		let expected = target;
		let pool = readings;
		let repaired = 0;
		for (let attempt = 1; attempt <= this.maxCasAttempts; attempt++) {
			repaired += await this.repairLaggards(pool, expected);
			const writer = generateWriterKey();
			const newEpoch = expected.state.lease.epoch + 1n;
			const signatures = signAcquisition(
				this.config.context.guardianSetId,
				expected.state,
				newEpoch,
				writer,
				this.config.recoveryRoot.rootSecret
			);
			const request = {
				protocolVersion: 1,
				guardianSetId: Buffer.from(this.config.context.guardianSetId),
				expectedState: expected.state,
				newEpoch,
				newWriterPublicKey: writer.publicKey,
				...signatures
			};
			const results = await guardianFanOut(this.config.clients, (client) =>
				client.acquireEpoch(request)
			);
			const certificates: IGuardianTakeoverCertificate[] = [];
			const signers = new Set<string>();
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
				if (!statesEqual(cert.supersededState, expected.state)) continue;
				const key = cert.guardianId.toString('hex');
				if (signers.has(key)) continue;
				signers.add(key);
				certificates.push(cert);
			}
			if (certificates.length >= this.config.required) {
				const lease: IWriterLeaseKeys = {
					epoch: newEpoch,
					writerSecret: writer.secret,
					writerPublicKey: writer.publicKey,
					guardianCertificates: certificates,
					confirmedAt: this.clock()
				};
				this.emit(
					'epoch:acquired',
					`epoch ${newEpoch} acquired with ${certificates.length} certificates over sequence ${expected.state.logHead.sequence}`
				);
				return {
					lease,
					certifiedState: expected.state,
					certificates,
					repaired
				};
			}
			// CAS failed: someone holds a newer state. Refetch, reconcile, retry.
			this.emit(
				'epoch:cas-retry',
				`attempt ${attempt} collected ${certificates.length} of ${this.config.required} certificates; refetching`
			);
			pool = await this.readHeads();
			this.assertNoConflict(pool);
			expected = this.selectHead(pool);
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
		const readings = await this.readHeads();
		this.assertNoConflict(readings);
		const target = this.selectHead(readings);
		this.emit(
			'head:adopted',
			`adopted epoch ${target.state.lease.epoch} sequence ${target.state.logHead.sequence}`
		);

		// FENCE FIRST. Nothing below this line may run before the takeover.
		const acquired = await this.acquireEpoch(target, readings);
		const certified = acquired.certifiedState;

		const records = await this.downloadRecords(
			target.client,
			0n,
			certified.logHead.sequence
		);
		if (BigInt(records.length) < certified.logHead.sequence - 0n) {
			// A short download cannot be silently accepted: the certified head
			// says what must exist.
			const last = records[records.length - 1];
			if (!last || last.sequence !== certified.logHead.sequence) {
				throw new RestoreRefusedError(
					'head-unverifiable',
					`download ended at ${
						last?.sequence ?? 0n
					} but the certified head is ${certified.logHead.sequence}`
				);
			}
		}
		const last = records[records.length - 1];
		if (
			!last ||
			last.sequence !== certified.logHead.sequence ||
			!last.frameHash.equals(certified.logHead.frameHash)
		) {
			throw new RestoreRefusedError(
				'head-unverifiable',
				'the downloaded log does not end at the certified head'
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
