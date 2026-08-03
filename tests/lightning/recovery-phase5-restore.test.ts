/**
 * Recovery Protocol phase 5: the restore driver
 * (docs/RECOVERY-PROTOCOL.md 5.7).
 *
 * What these tests hold the driver to:
 * - The order: fence BEFORE download. The takeover fixes the superseded
 *   epoch's final head, so what is reconstructed is provably that state.
 * - The divergent-head worked example: one guardian unreachable, one
 *   stale, head reconciled, laggard repaired through SYNC_RECORD, CAS
 *   succeeding on the repaired quorum.
 * - Every refusal: no read quorum, an unknown namespace, and a
 *   crash-fault-model breach all halt instead of guessing.
 * - The restored database is byte-identical to the lost one, and the node
 *   that comes up on it is the fenced current writer.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianTransportError,
	IGuardianReplicationEvent,
	GuardianState,
	GuardianStatus,
	IBoundGuardianClient,
	IRestoreEvent,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	RESTORE_META_KEYS,
	RestoreDriver,
	RestoreRefusedError,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	genesisLogHead,
	generateWriterKey,
	loadWriterLease,
	nodeGuardianTransport,
	registerTranscriptHash,
	signAcquisition,
	signTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { serializePaymentInfo } from '../../src/lightning/storage/serialization';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p5-restore-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };
const NODE_SECRET = sha('p5-restore-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

let now = 2_000_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	client: GuardianClient;
	id: Buffer;
}

/** Guardians bound to the identity each endpoint must prove it holds. */
function bind(served: IServed[]): IBoundGuardianClient[] {
	return served.map((entry) => ({
		client: entry.client,
		expectedGuardianId: entry.id
	}));
}

async function serve(index: number): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	return {
		guardian,
		server,
		id: GUARDIAN_IDS[index],
		client: new GuardianClient({
			url: `http://127.0.0.1:${port}`,
			guardianSetId: SET_ID
		})
	};
}

async function shutdown(served: IServed[]): Promise<void> {
	for (const entry of served) {
		try {
			await entry.server.close();
		} catch {
			// already closed by the test
		}
		entry.guardian.close();
	}
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

/** Deterministic dump of the safety-critical tables a restore must rebuild. */
function dumpTables(storage: IStorageBackend): string {
	const bigintSafe = (_k: string, v: unknown): unknown =>
		typeof v === 'bigint' ? `${v.toString()}n` : v;
	return JSON.stringify({
		preimages: storage
			.loadAllPreimages()
			.map((p) => [p.paymentHash, p.preimage.toString('hex')])
			.sort(),
		payments: storage
			.loadAllPayments()
			.map((p) => [
				p.paymentHash,
				JSON.stringify(serializePaymentInfo(p.payment), bigintSafe)
			])
			.sort(),
		secrets: storage
			.loadAllPaymentSecrets()
			.map((s) => [s.paymentHashHex, s.secret.toString('hex')])
			.sort()
	});
}

function liveNode(transitions: number): {
	storage: SqliteStorage;
	manager: RecoveryManager;
} {
	const storage = openStorage();
	const journal = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(NODE_SECRET),
		NODE_ID,
		ROOT.recoveryId
	);
	const manager = new RecoveryManager(storage, { journal });
	for (let i = 0; i < transitions; i++) {
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, i + 1).toString('hex'),
						preimage: Buffer.alloc(32, i + 1)
					},
					{
						type: 'payment_secret',
						paymentHash: Buffer.alloc(32, i + 1).toString('hex'),
						secret: Buffer.alloc(32, 200 - i)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
	}
	return { storage, manager };
}

function replicatorFor(
	storage: SqliteStorage,
	guardians: IBoundGuardianClient[]
): GuardianReplicator {
	return new GuardianReplicator({
		storage,
		guardians,
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock
	});
}

function driverFor(
	target: IStorageBackend,
	guardians: IBoundGuardianClient[],
	events: IRestoreEvent[] = []
): RestoreDriver {
	return new RestoreDriver({
		target,
		guardians,
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		nodeSecret: NODE_SECRET,
		nodeId: NODE_ID,
		clock,
		pageSize: 2,
		onEvent: (event): void => {
			events.push(event);
		}
	});
}

describe('Recovery phase 5: restore driver', () => {
	it('fences first, then rebuilds the database byte-identically', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(3);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const expectedDump = dumpTables(live.storage);

		// The device is lost. A fresh install restores from the guardians.
		const events: IRestoreEvent[] = [];
		const target = openStorage();
		const driver = driverFor(target, bind(served), events);
		const result = await driver.restore();

		// The fence landed BEFORE the download: the events are ordered, and
		// the guardians now serve the new epoch.
		const order = events.map((e) => e.type);
		expect(order.indexOf('epoch:acquired')).to.be.lessThan(
			order.indexOf('frames:downloaded')
		);
		expect(result.lease.epoch).to.equal(lease.epoch + 1n);
		expect(result.certificates.length).to.be.at.least(
			CRASH_V1_PROFILE.required
		);
		expect(result.framesApplied).to.be.greaterThan(0);

		// The restored database matches the lost one, and the lease persisted.
		expect(dumpTables(target)).to.equal(expectedDump);
		const restoredLease = loadWriterLease(target);
		expect(restoredLease.state).to.equal('present');
		expect(
			(restoredLease as { state: 'present'; lease: IWriterLeaseKeys }).lease
				.epoch
		).to.equal(result.lease.epoch);

		// The old writer is fenced everywhere: its next append is refused.
		const staleFrame = live.storage.loadRecoveryFrames()[0];
		const staleRecord = rep.signRecord(staleFrame, lease);
		const refused = await clients[0].putState({
			...staleRecord,
			sequence: BigInt(live.storage.loadRecoveryFrames().length + 1),
			epoch: lease.epoch
		});
		expect(refused.status).to.equal(GuardianStatus.ERR_EPOCH_SUPERSEDED);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('reconciles a divergent head: one guardian unreachable, one stale', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		// The 5.7 worked example: frame N reached G1 and G2; G3 was offline.
		const frames = live.storage.loadRecoveryFrames();
		for (const frame of frames.slice(0, frames.length - 1)) {
			const record = rep.signRecord(frame, lease);
			for (const client of clients) await client.putState(record);
		}
		const lastFrame = frames[frames.length - 1];
		const lastRecord = rep.signRecord(lastFrame, lease);
		expect((await clients[0].putState(lastRecord)).status).to.equal(
			GuardianStatus.OK
		);
		expect((await clients[1].putState(lastRecord)).status).to.equal(
			GuardianStatus.OK
		);

		// At restore time G1 is unreachable: the read set is G2 (head N) and
		// G3 (head N-1). Without SYNC_RECORD repair the CAS could never
		// assemble a quorum.
		await served[0].server.close();
		const events: IRestoreEvent[] = [];
		const target = openStorage();
		const driver = driverFor(target, bind(served), events);
		const result = await driver.restore();

		expect(result.certifiedState.logHead.sequence).to.equal(
			BigInt(lastFrame.sequence)
		);
		expect(result.guardiansRepaired).to.be.at.least(1);
		expect(events.some((e) => e.type === 'guardian:repaired')).to.equal(true);
		// The repaired guardian holds the adopted head and the new epoch.
		const g3 = await clients[2].getHead(ROOT.recoveryId);
		const g3State = g3.state as GuardianState;
		expect(g3State.logHead.sequence).to.equal(BigInt(lastFrame.sequence));
		expect(g3State.lease.epoch).to.equal(result.lease.epoch);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('retries the CAS when the old writer certifies a state mid-restore', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);

		// The takeover race (spec 5.7): a competing device acquires the epoch
		// between this driver's head read and its own acquisition, so the
		// first CAS must fail and the retry must land on the NEWER state.
		const target = openStorage();
		const events: IRestoreEvent[] = [];
		const driver = driverFor(target, bind(served), events);
		const stolen = await clients[0].getHead(ROOT.recoveryId);
		const stolenState = stolen.state as GuardianState;
		const competitor = generateWriterKey();
		for (const client of clients) {
			await client.acquireEpoch({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				expectedState: stolenState,
				newEpoch: stolenState.lease.epoch + 1n,
				newWriterPublicKey: competitor.publicKey,
				...signAcquisition(
					SET_ID,
					stolenState,
					stolenState.lease.epoch + 1n,
					competitor,
					ROOT.rootSecret
				)
			});
		}

		const result = await driver.restore();
		// The restore took the epoch ABOVE the competitor's, never below it.
		expect(result.lease.epoch).to.equal(stolenState.lease.epoch + 2n);
		expect(result.certifiedState.logHead.sequence).to.equal(
			stolenState.logHead.sequence
		);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('picks up a record the old writer appended mid-restore', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const headBefore = (await served[0].client.getHead(ROOT.recoveryId))
			.state as GuardianState;

		// The acceptance criterion from #190: the still-live old writer
		// APPENDS a new record and gets quorum receipts for it between the
		// restore's first head read and its acquisition. The CAS against the
		// older head must fail, the refetch must find N+1, and the restored
		// database must CONTAIN that record.
		let raced = false;
		const target = openStorage();
		const events: IRestoreEvent[] = [];
		const driver = new RestoreDriver({
			target,
			guardians: bind(served),
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			nodeSecret: NODE_SECRET,
			nodeId: NODE_ID,
			clock,
			pageSize: 2,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		const originalReadHeads = (
			driver as unknown as { readHeads: () => Promise<unknown> }
		).readHeads.bind(driver);
		(driver as unknown as { readHeads: () => Promise<unknown> }).readHeads =
			async (): Promise<unknown> => {
				const readings = await originalReadHeads();
				if (!raced) {
					raced = true;
					// The old device is still alive and commits one more
					// transition, replicating it to a quorum.
					live.manager.commit({
						criticality: RecoveryCriticality.SafetyCritical,
						mutations: [
							{
								type: 'payment_preimage',
								paymentHash: Buffer.alloc(32, 55).toString('hex'),
								preimage: Buffer.alloc(32, 55)
							}
						],
						outboundMessages: []
					});
					const appended = await rep.replicatePending(lease);
					expect(appended.durable).to.be.greaterThan(0);
				}
				return readings;
			};

		const result = await driver.restore();
		// The CAS against the stale head failed and the retry landed on the
		// head that now includes the raced record.
		expect(events.some((e) => e.type === 'epoch:cas-retry')).to.equal(true);
		expect(
			result.certifiedState.logHead.sequence > headBefore.logHead.sequence
		).to.equal(true);
		// The restored database contains the record appended mid-restore.
		expect(dumpTables(target)).to.equal(dumpTables(live.storage));
		expect(
			target
				.loadAllPreimages()
				.some((p) => p.paymentHash === Buffer.alloc(32, 55).toString('hex'))
		).to.equal(true);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('refuses without a read quorum, and for an unknown namespace', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(1);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);

		// Two guardians down: one response is below the read set, so there is
		// no recency proof and the takeover must be refused (5.7 step 5).
		await served[1].server.close();
		await served[2].server.close();
		const beforeRefusal = (await served[0].client.getHead(ROOT.recoveryId))
			.state as GuardianState;
		const target = openStorage();
		try {
			await driverFor(target, bind(served)).restore();
			expect.fail('a sub-quorum restore must be refused');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('no-quorum');
		}
		expect(loadWriterLease(target).state).to.equal('missing');
		// Refused BEFORE the CAS, not after: the reachable guardian still
		// holds the old writer's epoch, and no takeover certificate exists.
		const afterRefusal = await served[0].client.getHead(ROOT.recoveryId);
		const afterState = afterRefusal.state as GuardianState;
		expect(afterState.lease.epoch).to.equal(beforeRefusal.lease.epoch);
		expect(
			afterState.lease.writerPublicKey.equals(
				beforeRefusal.lease.writerPublicKey
			)
		).to.equal(true);
		expect(
			(afterRefusal.certificates ?? []).some(
				(cert) => cert.newEpoch > beforeRefusal.lease.epoch
			)
		).to.equal(false);
		await shutdown(served);

		// A namespace nobody serves has nothing to restore.
		const fresh = await Promise.all([serve(0), serve(1), serve(2)]);
		const emptyTarget = openStorage();
		try {
			await driverFor(emptyTarget, bind(fresh)).restore();
			expect.fail('restoring an unregistered namespace must be refused');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal(
				'unknown-namespace'
			);
		}
		await shutdown(fresh);
		live.storage.close();
		target.close();
		emptyTarget.close();
	});

	it('finishes a partial acquisition with the SAME key instead of chasing epochs', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);
		const beforeEpoch = (
			(await served[0].client.getHead(ROOT.recoveryId)).state as GuardianState
		).lease.epoch;

		// G1 accepts the acquisition; G2 and G3 lose only the ACQUIRE
		// exchange (reads still work, so the head read succeeds). Regenerating
		// the writer key on retry would strand the epoch G1 accepted and chase
		// the log upward one guardian at a time, never forming a quorum.
		let blockAcquire = true;
		const flaky = (index: number): IBoundGuardianClient => ({
			expectedGuardianId: served[index].id,
			client: new GuardianClient({
				url: served[index].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (blockAcquire && url.endsWith('/acquire_epoch')) {
						throw new GuardianTransportError('acquire lost in transit');
					}
					return nodeGuardianTransport()(url, init);
				}
			})
		});
		const guardians: IBoundGuardianClient[] = [
			{ expectedGuardianId: served[0].id, client: served[0].client },
			flaky(1),
			flaky(2)
		];

		const target = openStorage();
		try {
			await driverFor(target, guardians).restore();
			expect.fail('the takeover cannot complete against one guardian');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}

		// The attempt is remembered, key and all, and G1 is bound to it.
		const pendingRaw = target.getRecoveryMeta!(
			RESTORE_META_KEYS.pendingAcquisition
		);
		expect(
			pendingRaw,
			'the acquisition was persisted before it was sent'
		).to.not.equal(null);
		const pending = JSON.parse(pendingRaw as string) as {
			newEpoch: string;
			writerPublicKey: string;
		};
		expect(BigInt(pending.newEpoch)).to.equal(beforeEpoch + 1n);
		const g1After = (
			(await served[0].client.getHead(ROOT.recoveryId)).state as GuardianState
		).lease;
		expect(g1After.epoch).to.equal(beforeEpoch + 1n);
		expect(g1After.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);

		// A NEW driver resumes once the acquire path works again: the SAME
		// epoch and key are retried, G1 answers OK_DUPLICATE, the quorum
		// forms, and no extra epoch was consumed.
		blockAcquire = false;
		const resumeEvents: IRestoreEvent[] = [];
		const result = await driverFor(target, guardians, resumeEvents).restore();
		expect(resumeEvents.some((e) => e.type === 'epoch:resumed')).to.equal(true);
		expect(result.lease.epoch).to.equal(beforeEpoch + 1n);
		expect(result.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition)
		).to.equal(null);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('repairs a guardian that missed the takeover and discards its superseded tail', async () => {
		// Phase 5 acceptance (docs/RECOVERY-PROTOCOL.md 9): a lagging guardian
		// adopts the certified takeover head through SYNC_EPOCH and discards
		// the uncommitted superseded-epoch tail sitting above it. The tail is
		// the dangerous half: one guardian holding a record no quorum ever
		// acknowledged must never pull a restore above the certified head.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const certifiedHead = (await served[0].client.getHead(ROOT.recoveryId))
			.state as GuardianState;

		// The dying writer lands ONE more transition on G3 alone: a
		// sub-threshold tail under the epoch that is about to be superseded.
		const tailHash = Buffer.alloc(32, 77).toString('hex');
		expect(
			live.manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: tailHash,
						preimage: Buffer.alloc(32, 77)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const frames = live.storage.loadRecoveryFrames();
		const tailFrame = frames[frames.length - 1];
		const tailRecord = rep.signRecord(tailFrame, lease);
		expect((await served[2].client.putState(tailRecord)).status).to.equal(
			GuardianStatus.OK
		);

		// G3 goes dark, so the takeover reaches G1 and G2 only.
		await served[2].server.close();
		const firstTarget = openStorage();
		const first = await driverFor(firstTarget, bind(served)).restore();
		expect(first.certifiedState.logHead.sequence).to.equal(
			certifiedHead.logHead.sequence
		);

		// G3 comes back at the superseded epoch, still holding its tail.
		const revived = new GuardianHttpServer({ guardian: served[2].guardian });
		const revivedPort = await revived.listen(0);
		const revivedClient = new GuardianClient({
			url: `http://127.0.0.1:${revivedPort}`,
			guardianSetId: SET_ID
		});
		const before = (await revivedClient.getHead(ROOT.recoveryId))
			.state as GuardianState;
		expect(before.lease.epoch).to.equal(certifiedHead.lease.epoch);
		expect(before.logHead.sequence).to.equal(
			certifiedHead.logHead.sequence + 1n
		);

		// The next restore reads all three heads. G3 is AHEAD by sequence and
		// BEHIND by epoch: SYNC_EPOCH must fix its head at the certified one.
		const events: IRestoreEvent[] = [];
		const target = openStorage();
		const result = await driverFor(
			target,
			[
				...bind(served.slice(0, 2)),
				{ client: revivedClient, expectedGuardianId: served[2].id }
			],
			events
		).restore();

		expect(result.certifiedState.logHead.sequence).to.equal(
			certifiedHead.logHead.sequence
		);
		expect(result.guardiansRepaired).to.be.at.least(1);
		const after = (await revivedClient.getHead(ROOT.recoveryId))
			.state as GuardianState;
		expect(after.logHead.sequence).to.equal(certifiedHead.logHead.sequence);
		expect(after.lease.epoch).to.equal(result.lease.epoch);

		// The tail was archived, not served, and never reached the restore.
		const orphans = served[2].guardian.listOrphanedRecords(ROOT.recoveryId);
		expect(orphans.length).to.equal(1);
		expect(orphans[0].reason).to.equal('sync-epoch-truncation');
		expect(orphans[0].frameHash.equals(tailRecord.frameHash)).to.equal(true);
		const servedAbove = await revivedClient.getState(
			ROOT.recoveryId,
			certifiedHead.logHead.sequence
		);
		expect(servedAbove.records ?? []).to.have.length(0);
		expect(
			live.storage.loadAllPreimages().some((p) => p.paymentHash === tailHash)
		).to.equal(true);
		expect(
			target.loadAllPreimages().some((p) => p.paymentHash === tailHash)
		).to.equal(false);

		await revived.close();
		await shutdown(served);
		live.storage.close();
		firstTarget.close();
		target.close();
	});

	it('adopts a higher epoch only when a quorum certified it', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const shared = (await served[0].client.getHead(ROOT.recoveryId))
			.state as GuardianState;

		// ONE guardian accepts an acquisition nobody else saw. Its higher
		// epoch is not proof that the epoch was acquired: it is exactly what a
		// half-finished takeover leaves behind, so it must not be adopted.
		const orphanWriter = generateWriterKey();
		const orphan = await served[2].client.acquireEpoch({
			protocolVersion: 1,
			guardianSetId: SET_ID,
			expectedState: shared,
			newEpoch: shared.lease.epoch + 1n,
			newWriterPublicKey: orphanWriter.publicKey,
			...signAcquisition(
				SET_ID,
				shared,
				shared.lease.epoch + 1n,
				orphanWriter,
				ROOT.rootSecret
			)
		});
		expect(orphan.status).to.equal(GuardianStatus.OK);

		const target = openStorage();
		const result = await driverFor(target, bind(served)).restore();
		// The restore built on the epoch the SET agreed on, not on the orphan.
		expect(result.certifiedState.lease.epoch).to.equal(shared.lease.epoch);
		expect(result.lease.epoch).to.equal(shared.lease.epoch + 1n);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('does not count a possibly-stale guardian toward the read set', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(3);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);

		// G1 damages its store and confesses (possibly_stale); G3 is down.
		// Two answers arrive, but only ONE proves recency, so the takeover
		// must be refused rather than built on an uncertain head.
		const stale = served[0].guardian.listOrphanedRecords(ROOT.recoveryId);
		expect(stale.length).to.equal(0);
		served[0].guardian.close();
		const damaged = new ReferenceGuardian({
			path: ':memory:',
			guardianSecret: GUARDIAN_SECRETS[0],
			members: GUARDIAN_IDS,
			clock
		});
		// A fresh empty store for G1: it now knows nothing of the namespace.
		served[0].guardian = damaged;
		await served[2].server.close();
		const target = openStorage();
		try {
			await driverFor(target, bind(served)).restore();
			expect.fail('an unusable read set must refuse the restore');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
		}
		damaged.close();
		await served[1].server.close();
		served[1].guardian.close();
		try {
			await served[0].server.close();
		} catch {
			// already closed
		}
		served[2].guardian.close();
		live.storage.close();
		target.close();
	});

	it('resumes after a crash between the takeover and lease promotion', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(3);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);
		const expectedDump = dumpTables(live.storage);

		// Crash AFTER the CAS grants the epoch but BEFORE the lease is
		// durable, by failing the installation transaction. The writer key
		// for a granted epoch must survive in the pending record, and the
		// partially applied install must roll back completely.
		const target = openStorage();
		let failInstall = true;
		const brittle = new Proxy(target, {
			get(t, prop, receiver): unknown {
				if (prop === 'saveRecoveryFrame' && failInstall) {
					return (row: unknown): void => {
						t.saveRecoveryFrame!(row as never);
						throw new Error('crash during installation');
					};
				}
				const value = Reflect.get(t, prop, receiver);
				return typeof value === 'function' ? value.bind(t) : value;
			}
		}) as IStorageBackend;

		const firstEvents: IRestoreEvent[] = [];
		try {
			await driverFor(brittle, bind(served), firstEvents).restore();
			expect.fail('the installation was supposed to fail');
		} catch (error) {
			expect((error as Error).message).to.contain('crash during installation');
		}
		expect(firstEvents.some((e) => e.type === 'epoch:acquired')).to.equal(true);
		// The key for the granted epoch is still on disk...
		const pendingRaw = target.getRecoveryMeta!(
			RESTORE_META_KEYS.pendingAcquisition
		);
		expect(pendingRaw, 'the pending key survived the crash').to.not.equal(null);
		const pending = JSON.parse(pendingRaw as string) as {
			newEpoch: string;
			writerPublicKey: string;
		};
		// ...no lease exists yet, and the install rolled back entirely.
		expect(loadWriterLease(target).state).to.equal('missing');
		expect(target.loadRecoveryFrames()).to.have.length(0);
		expect(target.loadAllPreimages()).to.have.length(0);

		// A NEW driver on the same database resumes: same epoch and key, no
		// duplicate frames, byte-identical tables, and the pending record
		// retires only once the lease exists.
		failInstall = false;
		const resumeEvents: IRestoreEvent[] = [];
		const result = await driverFor(
			target,
			bind(served),
			resumeEvents
		).restore();
		expect(resumeEvents.some((e) => e.type === 'epoch:resumed')).to.equal(true);
		expect(result.lease.epoch).to.equal(BigInt(pending.newEpoch));
		expect(result.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(dumpTables(target)).to.equal(expectedDump);
		expect(loadWriterLease(target).state).to.equal('present');
		expect(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition)
		).to.equal(null);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('starts post-restore replication after the certified head', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(3);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);

		const target = openStorage();
		const restored = await driverFor(target, bind(served)).restore();
		const certifiedSequence = restored.certifiedState.logHead.sequence;
		expect(certifiedSequence > 0n).to.equal(true);

		// The takeover certificates prove a quorum held the log through the
		// certified head, so replication must resume AFTER it. Starting from
		// zero would re-sign historical frames under the new epoch, which the
		// guardians reject at an occupied sequence: the watermark would never
		// advance and every append would resend the whole journal.
		const events: IGuardianReplicationEvent[] = [];
		const resumed = new GuardianReplicator({
			storage: target,
			guardians: bind(served),
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			clock,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		expect(resumed.replicatedThrough()).to.equal(certifiedSequence);

		// Nothing new: no requests, no rejections, no re-sent history.
		const idle = await resumed.replicatePending(restored.lease);
		expect(idle.attempted).to.equal(0);
		expect(idle.outcome).to.equal('replicated');
		expect(events).to.have.length(0);

		// One new transition under the acquired epoch replicates normally.
		const restoredJournal = new RecoveryJournal(
			target,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId
		);
		const restoredManager = new RecoveryManager(target, {
			journal: restoredJournal
		});
		expect(
			restoredManager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, 66).toString('hex'),
						preimage: Buffer.alloc(32, 66)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);

		const next = await resumed.replicatePending(restored.lease);
		expect(next.attempted).to.be.greaterThan(0);
		expect(next.durable).to.equal(next.attempted);
		expect(next.replicatedThrough > certifiedSequence).to.equal(true);
		// No historical frame was ever rejected or under-replicated.
		expect(
			events.filter(
				(e) =>
					e.type === 'record:rejected' || e.type === 'record:under-replicated'
			)
		).to.have.length(0);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('does not call one holder plus two unknowns an unregistered namespace', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(1);
		// Only G1 ever learns about the namespace: a partially replicated
		// registration, NOT an empty guardian set. Reporting nothing-to-restore
		// here would invite a second genesis over a live namespace.
		const root = ROOT;
		const writer = generateWriterKey();
		const initialState: GuardianState = {
			recoveryId: root.recoveryId,
			lease: { epoch: 1n, writerPublicKey: writer.publicKey },
			origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
			logHead: genesisLogHead()
		};
		expect(
			(
				await served[0].client.register({
					protocolVersion: 1,
					guardianSetId: SET_ID,
					initialState,
					rootSignature: signTranscript(
						registerTranscriptHash(SET_ID, initialState),
						root.rootSecret
					)
				})
			).status
		).to.equal(GuardianStatus.OK);

		const target = openStorage();
		try {
			await driverFor(target, bind(served)).restore();
			expect.fail('an inconsistent namespace must not restore');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			// The refusal must NOT be unknown-namespace: something holds it.
			expect((error as RestoreRefusedError).reason).to.equal('no-quorum');
		}
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('marks every restored channel StateUncertain inside the install', async () => {
		// Guardian replication is best effort until the Phase 6 barriers, so
		// the certified head can trail what the lost device actually did with
		// its peers: a restored channel must come back with its commitment
		// broadcast forbidden, and Phase 5 deliberately has NO way to skip
		// the marking; only a Phase 6 verified provenance proof will.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		// The channel exists BEFORE the journal's bootstrap snapshot, so the
		// snapshot carries it and the restore rebuilds it.
		const chanSeed = crypto
			.createHash('sha256')
			.update(Buffer.from('restore-status-channel'))
			.digest();
		const basepointKeys = Array.from({ length: 6 }, (_, i) =>
			crypto
				.createHash('sha256')
				.update(chanSeed)
				.update(Buffer.from([i]))
				.digest()
		);
		const channelState = createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xc5),
			fundingSatoshis: 500_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: {
				fundingPubkey: getPublicKey(basepointKeys[0]),
				revocationBasepoint: getPublicKey(basepointKeys[1]),
				paymentBasepoint: getPublicKey(basepointKeys[2]),
				delayedPaymentBasepoint: getPublicKey(basepointKeys[3]),
				htlcBasepoint: getPublicKey(basepointKeys[4]),
				firstPerCommitmentPoint: getPublicKey(basepointKeys[5])
			},
			localPerCommitmentSeed: crypto
				.createHash('sha256')
				.update(Buffer.from('restore-status-seed'))
				.digest()
		});
		expect(channelState.stateUncertain).to.equal(undefined);
		const channelId = Buffer.alloc(32, 0xc5).toString('hex');
		storage.saveChannel(channelId, channelState, '02'.padEnd(66, 'ab'));

		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId
		);
		const manager = new RecoveryManager(storage, { journal });
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 0xaa).toString('hex'),
					preimage: Buffer.alloc(32, 0xaa)
				}
			],
			outboundMessages: []
		});
		const rep = replicatorFor(storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);

		// Device lost; a fresh install restores from the guardians.
		const target = openStorage();
		const driver = driverFor(target, bind(served));
		await driver.restore();

		const restored = target.loadChannel(channelId);
		expect(restored).to.not.equal(null);
		expect(restored!.state.stateUncertain).to.equal(true);
		// And the source never had the flag: it is the restore that adds it.
		expect(storage.loadChannel(channelId)!.state.stateUncertain).to.equal(
			undefined
		);
		await shutdown(served);
		storage.close();
		target.close();
	});

	it('halts on a crash-fault-model breach instead of guessing', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const frames = live.storage.loadRecoveryFrames();

		// Two DIFFERENT records at the same (epoch, sequence): a Byzantine
		// writer or guardian, outside the model this protocol assumes.
		const honest = rep.signRecord(frames[0], lease);
		expect((await clients[0].putState(honest)).status).to.equal(
			GuardianStatus.OK
		);
		expect((await clients[1].putState(honest)).status).to.equal(
			GuardianStatus.OK
		);
		const forkedFrame = {
			...frames[0],
			frameHash: sha('a-forked-frame'),
			ciphertext: Buffer.concat([frames[0].ciphertext, Buffer.from([0xff])])
		};
		const forked = rep.signRecord(forkedFrame, lease);
		expect((await clients[2].putState(forked)).status).to.equal(
			GuardianStatus.OK
		);

		const target = openStorage();
		try {
			await driverFor(target, bind(served)).restore();
			expect.fail('a divergent record at one position must halt the restore');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('conflict');
		}
		// Nothing was written to the target: no channel action, no lease.
		expect(loadWriterLease(target).state).to.equal('missing');
		expect(target.loadRecoveryFrames()).to.have.length(0);
		await shutdown(served);
		live.storage.close();
		target.close();
	});
});
