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
	GuardianRotation,
	GuardianTransportError,
	GuardianVerbName,
	IGuardianReplicationEvent,
	IParsedGuardian,
	GuardianState,
	GuardianStatus,
	IBoundGuardianClient,
	IGuardianGetHeadResponse,
	IGuardianRecord,
	IRestoreEvent,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	REPLICATION_META_KEYS,
	RESTORE_META_KEYS,
	RestoreDriver,
	RestoreRefusedError,
	RestoreRotatedError,
	computeGuardianSetId,
	decodeAcquireEpochRequest,
	decodePutStateRequest,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	dispatchGuardianVerb,
	encodeGuardianInfo,
	genesisLogHead,
	generateWriterKey,
	GUARDIAN_HOST_DEFAULT_MAX_CIPHERTEXT_BYTES,
	GUARDIAN_RECORD_OVERHEAD_BYTES,
	GUARDIAN_REGISTRATION_BYTES,
	JOURNAL_META_KEYS,
	META_LAST_SNAPSHOT_GROUP,
	loadWriterLease,
	nodeGuardianTransport,
	registerTranscriptHash,
	rotateTranscriptHash,
	signAcquisition,
	signTranscript,
	stateBytes,
	takeoverTranscriptHash,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { serializePaymentInfo } from '../../src/lightning/storage/serialization';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
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
const JOURNAL_KEYS = {
	masterKey: deriveRecoveryMasterKey(NODE_SECRET),
	nodeId: NODE_ID
};

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

async function serve(
	index: number,
	maxCiphertextBytes?: number,
	maxContentBytes?: number
): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock,
		maxCiphertextBytes,
		maxContentBytes
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
		clock,
		journalKeys: JOURNAL_KEYS
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

type WriterKey = ReturnType<typeof generateWriterKey>;

/** One guardian grants the epoch after `lease` to `writer` over its head. */
async function grantNext(
	client: GuardianClient,
	lease: IWriterLeaseKeys,
	writer: WriterKey
): Promise<GuardianState> {
	const guard = (await client.getHead(ROOT.recoveryId)).state as GuardianState;
	const response = await client.acquireEpoch({
		protocolVersion: 1,
		guardianSetId: SET_ID,
		expectedState: guard,
		newEpoch: lease.epoch + 1n,
		newWriterPublicKey: writer.publicKey,
		...signAcquisition(SET_ID, guard, lease.epoch + 1n, writer, ROOT.rootSecret)
	});
	expect(response.status).to.equal(GuardianStatus.OK);
	return guard;
}

/** The acquisition record a restore persists before it sends the request. */
function persistPending(
	target: IStorageBackend,
	guard: GuardianState,
	writer: WriterKey
): void {
	target.setRecoveryMeta!(
		RESTORE_META_KEYS.pendingAcquisition,
		JSON.stringify({
			version: 1,
			expectedState: stateBytes(guard).toString('hex'),
			newEpoch: (guard.lease.epoch + 1n).toString(),
			writerSecret: writer.secret.toString('hex'),
			writerPublicKey: writer.publicKey.toString('hex')
		})
	);
}

/**
 * A second device restores through `members` and stores one more record
 * under the epoch it took. Returns its database.
 */
async function takeOverAndAppend(
	members: IServed[],
	n: number
): Promise<SqliteStorage> {
	const storage = openStorage();
	const restored = await driverFor(storage, bind(members)).restore();
	const manager = new RecoveryManager(storage, {
		journal: new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId
		)
	});
	expect(
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, n).toString('hex'),
					preimage: Buffer.alloc(32, n)
				}
			],
			outboundMessages: []
		}).committed
	).to.equal(true);
	const pass = await replicatorFor(storage, bind(members)).replicatePending(
		restored.lease
	);
	expect(pass.outcome).to.equal('replicated');
	return storage;
}

/** Each guardian's lease epoch and log sequence. */
async function headsOf(
	clients: GuardianClient[]
): Promise<{ epochs: bigint[]; sequences: bigint[] }> {
	const states = await Promise.all(
		clients.map(
			async (client) =>
				(await client.getHead(ROOT.recoveryId)).state as GuardianState
		)
	);
	return {
		epochs: states.map((state) => state.lease.epoch),
		sequences: states.map((state) => state.logHead.sequence)
	};
}

/** A binding for `entry` whose every request is lost in transit. */
function unreachable(entry: IServed): IBoundGuardianClient {
	return {
		expectedGuardianId: entry.id,
		client: new GuardianClient({
			url: entry.client.url,
			guardianSetId: SET_ID,
			transport: async (): Promise<{ status: number; body: Buffer }> => {
				throw new GuardianTransportError('guardian unreachable');
			}
		})
	};
}

describe('Recovery phase 5: restore driver', () => {
	it('fences first, then rebuilds the database byte-identically', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('restores through a backend that refuses nested transactions', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(3);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);
		const expectedDump = dumpTables(live.storage);

		// IStorageBackend does not promise reentrant transactions. Emulate
		// a strictly non-reentrant backend: the whole install (frames,
		// metadata, replay, lease) must share ONE transaction instead of
		// opening a BEGIN per reconstruction unit inside the outer one.
		const real = openStorage();
		let inTransaction = false;
		const strict = new Proxy(real, {
			get(target, prop, receiver): unknown {
				if (prop === 'transaction') {
					return <T>(fn: () => T): T => {
						if (inTransaction) {
							throw new Error('nested transaction refused');
						}
						inTransaction = true;
						try {
							return target.transaction(fn);
						} finally {
							inTransaction = false;
						}
					};
				}
				const value = Reflect.get(target, prop, receiver);
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as unknown as IStorageBackend;

		const driver = driverFor(strict, bind(served));
		const result = await driver.restore();

		expect(result.framesApplied).to.be.greaterThan(0);
		expect(dumpTables(real)).to.equal(expectedDump);
		const restoredLease = loadWriterLease(real);
		expect(restoredLease.state).to.equal('present');
		await shutdown(served);
		live.storage.close();
		real.close();
	});

	it('reconciles a divergent head: one guardian unreachable, one stale', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('retries the CAS when the old writer certifies a state mid-restore', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('picks up a record the old writer appended mid-restore', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('refuses without a read quorum, and for an unknown namespace', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('refuses a target without journal support BEFORE fencing the writer', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(1);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);
		const before = (await served[0].client.getHead(ROOT.recoveryId))
			.state as GuardianState;

		// A target missing the path_id pair cannot continue the journal
		// (#316): acquiring the epoch for it would fence the working device
		// in exchange for an uninstallable database.
		const base = openStorage();
		const stripped = new Proxy(base, {
			get(target, prop, receiver): unknown {
				if (prop === 'saveInvoicePathId' || prop === 'loadAllInvoicePathIds') {
					return undefined;
				}
				const value = Reflect.get(target, prop, receiver);
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as unknown as IStorageBackend;
		try {
			await driverFor(stripped, bind(served)).restore();
			expect.fail('an unsupported target must be refused');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal(
				'target-unsupported'
			);
		}
		// Refused before ANY takeover traffic: the old writer's epoch stands
		// and no certificate for a successor exists.
		const after = await served[0].client.getHead(ROOT.recoveryId);
		const afterState = after.state as GuardianState;
		expect(afterState.lease.epoch).to.equal(before.lease.epoch);
		expect(
			afterState.lease.writerPublicKey.equals(before.lease.writerPublicKey)
		).to.equal(true);
		expect(
			(after.certificates ?? []).some(
				(cert) => cert.newEpoch > before.lease.epoch
			)
		).to.equal(false);
		await shutdown(served);
		live.storage.close();
		base.close();
	});

	it('finishes a partial acquisition with the SAME key instead of chasing epochs', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('keeps a held acquisition key despite later certificates from another namespace', async function (): Promise<void> {
		this.timeout(20_000);
		const served = GUARDIAN_SECRETS.map((guardianSecret, index) => {
			const guardian = new ReferenceGuardian({
				path: ':memory:',
				guardianSecret,
				members: GUARDIAN_IDS,
				clock
			});
			return {
				guardian,
				expectedGuardianId: GUARDIAN_IDS[index],
				client: new GuardianClient({
					url: 'http://guardian.example',
					guardianSetId: SET_ID,
					transport: async (
						url,
						init
					): Promise<{ status: number; body: Buffer }> => ({
						status: 200,
						body:
							init.method === 'GET'
								? encodeGuardianInfo(guardian)
								: dispatchGuardianVerb(
										guardian,
										url.split('/').pop() as GuardianVerbName,
										init.body!
								  )
					})
				})
			};
		});
		const live = liveNode(1);
		const rep = replicatorFor(live.storage, served);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		const guard = await grantNext(served[0].client, lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);

		const foreignRoot = deriveRecoveryRoot(sha('p5-restore-foreign-node'));
		const foreignWriter = generateWriterKey();
		const foreignState: GuardianState = {
			...guard,
			recoveryId: foreignRoot.recoveryId,
			lease: { epoch: 2n, writerPublicKey: foreignWriter.publicKey },
			logHead: genesisLogHead()
		};
		const originalHeads = served.map((entry) =>
			entry.client.getHead.bind(entry.client)
		);
		for (const [index, entry] of served.entries()) {
			const issuedAt = clock();
			const certificate = {
				protocolVersion: 1,
				guardianSetId: SET_ID,
				guardianId: entry.expectedGuardianId,
				supersededState: foreignState,
				newEpoch: 3n,
				newWriterPublicKey: foreignWriter.publicKey,
				issuedAt,
				signature: signTranscript(
					takeoverTranscriptHash(
						SET_ID,
						entry.expectedGuardianId,
						foreignState,
						3n,
						foreignWriter.publicKey,
						issuedAt
					),
					GUARDIAN_SECRETS[index]
				)
			};
			entry.client.getHead = async (
				recoveryId: Buffer
			): Promise<IGuardianGetHeadResponse> => {
				const head = await originalHeads[index](recoveryId);
				return {
					...head,
					certificates: [...(head.certificates ?? []), certificate]
				};
			};
		}

		const events: IRestoreEvent[] = [];
		const result = await driverFor(target, served, events).restore();
		expect(events.some((event) => event.type === 'epoch:abandoned')).to.equal(
			false
		);
		expect(result.lease.epoch).to.equal(2n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			true
		);
		for (const [index, entry] of served.entries()) {
			entry.client.getHead = originalHeads[index];
		}
		const later = openStorage();
		expect((await driverFor(later, served).restore()).lease.epoch).to.equal(3n);

		for (const entry of served) entry.guardian.close();
		live.storage.close();
		target.close();
		later.close();
	});

	it('completes a takeover that raced a live append once the third guardian returns', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1040. G3 missed frame N and is down. The live writer's frame
		// N+1 reaches G1 before this restore's ACQUIRE(N) does, and G2 grants
		// the ACQUIRE before N+1 arrives there. While G3 is away no takeover
		// can form: G2 has fixed N as the old epoch's final head, and only G3
		// could say whether N+1 reached a quorum.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const frames = live.storage.loadRecoveryFrames();
		for (const frame of frames.slice(0, frames.length - 1)) {
			const record = rep.signRecord(frame, lease);
			for (const client of clients) await client.putState(record);
		}
		const guardRecord = rep.signRecord(frames[frames.length - 1], lease);
		for (const client of clients.slice(0, 2)) {
			expect((await client.putState(guardRecord)).status).to.equal(
				GuardianStatus.OK
			);
		}
		const guard = (await clients[1].getHead(ROOT.recoveryId))
			.state as GuardianState;
		const expectedDump = dumpTables(live.storage);
		await served[2].server.close();

		const tailHash = Buffer.alloc(32, 88).toString('hex');
		let tailRecord: ReturnType<typeof rep.signRecord> | undefined;
		const target = openStorage();
		const racing = driverFor(target, bind(served));
		const originalReadHeads = (
			racing as unknown as { readHeads: () => Promise<unknown> }
		).readHeads.bind(racing);
		(racing as unknown as { readHeads: () => Promise<unknown> }).readHeads =
			async (): Promise<unknown> => {
				const readings = await originalReadHeads();
				if (!tailRecord) {
					live.manager.commit({
						criticality: RecoveryCriticality.SafetyCritical,
						mutations: [
							{
								type: 'payment_preimage',
								paymentHash: tailHash,
								preimage: Buffer.alloc(32, 88)
							}
						],
						outboundMessages: []
					});
					const all = live.storage.loadRecoveryFrames();
					tailRecord = rep.signRecord(all[all.length - 1], lease);
					expect((await clients[0].putState(tailRecord)).status).to.equal(
						GuardianStatus.OK
					);
				}
				return readings;
			};
		try {
			await racing.restore();
			expect.fail('no takeover can form while G3 is down');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}
		const pending = JSON.parse(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition) as string
		) as { newEpoch: string; writerPublicKey: string };
		const g2 = (await clients[1].getHead(ROOT.recoveryId))
			.state as GuardianState;
		expect(g2.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(g2.logHead.sequence).to.equal(guard.logHead.sequence);
		expect((await clients[1].putState(tailRecord!)).status).to.equal(
			GuardianStatus.ERR_EPOCH_SUPERSEDED
		);
		const g1 = (await clients[0].getHead(ROOT.recoveryId))
			.state as GuardianState;
		expect(g1.logHead.sequence).to.equal(guard.logHead.sequence + 1n);

		// G3 returns, still one frame short of the guard. Repairing it to
		// G1's head would leave no guardian able to grant the attempt G2 is
		// bound to; repairing it to the attempt's own guard completes it.
		const revived = new GuardianHttpServer({ guardian: served[2].guardian });
		const revivedPort = await revived.listen(0);
		const revivedClient = new GuardianClient({
			url: `http://127.0.0.1:${revivedPort}`,
			guardianSetId: SET_ID
		});
		const result = await driverFor(target, [
			...bind(served.slice(0, 2)),
			{ client: revivedClient, expectedGuardianId: served[2].id }
		]).restore();

		expect(result.lease.epoch).to.equal(BigInt(pending.newEpoch));
		expect(result.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(result.certifiedState.logHead.sequence).to.equal(
			guard.logHead.sequence
		);
		expect(
			result.certifiedState.logHead.frameHash.equals(guard.logHead.frameHash)
		).to.equal(true);
		const g3 = (await revivedClient.getHead(ROOT.recoveryId))
			.state as GuardianState;
		expect(g3.lease.epoch).to.equal(result.lease.epoch);
		expect(g3.logHead.sequence).to.equal(guard.logHead.sequence);
		// N+1 reached G1 alone, so it is a minority tail and not restored.
		expect(dumpTables(target)).to.equal(expectedDump);
		expect(
			target.loadAllPreimages().some((p) => p.paymentHash === tailHash)
		).to.equal(false);

		await revived.close();
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('keeps an attempt an unreachable guardian may hold instead of granting its epoch to a new key', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1227. G1 accepts the acquisition and drops off; the live
		// writer then moves G2 past the guard. No reachable guardian holds
		// the attempt, but G1 may, so a fresh key for the same epoch would
		// be certified beside G1's and halt every later restore.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const guard = (await clients[0].getHead(ROOT.recoveryId))
			.state as GuardianState;
		const expectedDump = dumpTables(live.storage);

		const acquireLost = (index: number): IBoundGuardianClient => ({
			expectedGuardianId: served[index].id,
			client: new GuardianClient({
				url: served[index].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (url.endsWith('/acquire_epoch')) {
						throw new GuardianTransportError('acquire lost in transit');
					}
					return nodeGuardianTransport()(url, init);
				}
			})
		});
		const target = openStorage();
		try {
			await driverFor(target, [
				{ expectedGuardianId: served[0].id, client: clients[0] },
				acquireLost(1),
				acquireLost(2)
			]).restore();
			expect.fail('the takeover cannot complete against one guardian');
		} catch (error) {
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}
		const pending = JSON.parse(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition) as string
		) as { newEpoch: string; writerPublicKey: string };
		const epoch = BigInt(pending.newEpoch);
		expect(epoch).to.equal(guard.lease.epoch + 1n);

		await served[0].server.close();
		live.manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 77).toString('hex'),
					preimage: Buffer.alloc(32, 77)
				}
			],
			outboundMessages: []
		});
		const all = live.storage.loadRecoveryFrames();
		expect(
			(await clients[1].putState(rep.signRecord(all[all.length - 1], lease)))
				.status
		).to.equal(GuardianStatus.OK);

		// The reachable view moved to G2's head and nothing there holds the
		// attempt. It is kept anyway, and G3 is left at its guard.
		const events: IRestoreEvent[] = [];
		try {
			await driverFor(target, bind(served), events).restore();
			expect.fail('the attempt G1 may hold must not be abandoned');
		} catch (error) {
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(false);
		const kept = JSON.parse(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition) as string
		) as { newEpoch: string; writerPublicKey: string };
		expect(kept).to.deep.equal(pending);
		for (const client of clients.slice(1)) {
			const head = await client.getHead(ROOT.recoveryId);
			for (const cert of head.certificates ?? []) {
				if (cert.newEpoch !== epoch) continue;
				expect(cert.newWriterPublicKey.toString('hex')).to.equal(
					pending.writerPublicKey
				);
			}
		}

		// G1 returns and completes the attempt with G3, over the guard.
		const revived = new GuardianHttpServer({ guardian: served[0].guardian });
		const revivedPort = await revived.listen(0);
		const revivedClient = new GuardianClient({
			url: `http://127.0.0.1:${revivedPort}`,
			guardianSetId: SET_ID
		});
		const result = await driverFor(target, [
			{ client: revivedClient, expectedGuardianId: served[0].id },
			...bind(served.slice(1))
		]).restore();
		expect(result.lease.epoch).to.equal(epoch);
		expect(result.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(result.certifiedState.logHead.sequence).to.equal(
			guard.logHead.sequence
		);
		// The record G2 alone took is a minority tail and not restored.
		expect(dumpTables(target)).to.equal(expectedDump);

		await revived.close();
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('keeps an attempt a member left out of the configured guardians may hold', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1255. As in #1227, G1 accepts the acquisition and G2 moves
		// past the guard, but the resume configures only G2 and G3. G1 is
		// still a committed member, so its possible grant still counts.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const guard = (await clients[0].getHead(ROOT.recoveryId))
			.state as GuardianState;
		const expectedDump = dumpTables(live.storage);

		const acquireLost = (index: number): IBoundGuardianClient => ({
			expectedGuardianId: served[index].id,
			client: new GuardianClient({
				url: served[index].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (url.endsWith('/acquire_epoch')) {
						throw new GuardianTransportError('acquire lost in transit');
					}
					return nodeGuardianTransport()(url, init);
				}
			})
		});
		const target = openStorage();
		try {
			await driverFor(target, [
				{ expectedGuardianId: served[0].id, client: clients[0] },
				acquireLost(1),
				acquireLost(2)
			]).restore();
			expect.fail('the takeover cannot complete against one guardian');
		} catch (error) {
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}
		const pending = JSON.parse(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition) as string
		) as { newEpoch: string; writerPublicKey: string };
		const epoch = BigInt(pending.newEpoch);
		expect(epoch).to.equal(guard.lease.epoch + 1n);

		live.manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 78).toString('hex'),
					preimage: Buffer.alloc(32, 78)
				}
			],
			outboundMessages: []
		});
		const all = live.storage.loadRecoveryFrames();
		expect(
			(await clients[1].putState(rep.signRecord(all[all.length - 1], lease)))
				.status
		).to.equal(GuardianStatus.OK);

		const events: IRestoreEvent[] = [];
		try {
			await driverFor(target, bind(served.slice(1)), events).restore();
			expect.fail('the attempt G1 may hold must not be abandoned');
		} catch (error) {
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(false);
		const kept = JSON.parse(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition) as string
		) as { newEpoch: string; writerPublicKey: string };
		expect(kept).to.deep.equal(pending);
		for (const client of clients) {
			const head = await client.getHead(ROOT.recoveryId);
			for (const cert of head.certificates ?? []) {
				if (cert.newEpoch !== epoch) continue;
				expect(cert.newWriterPublicKey.toString('hex')).to.equal(
					pending.writerPublicKey
				);
			}
		}

		// With G1 configured again the attempt completes over its guard.
		const result = await driverFor(target, bind(served)).restore();
		expect(result.lease.epoch).to.equal(epoch);
		expect(result.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(result.certifiedState.logHead.sequence).to.equal(
			guard.logHead.sequence
		);
		expect(dumpTables(target)).to.equal(expectedDump);

		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('moves a held attempt to the head a quorum advanced to, keeping its key', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1256. G1 accepts the acquisition over N and drops off; the
		// live writer then takes both G2 and G3 to N+1, so no quorum can
		// ever grant the attempt over N again.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const guard = (await clients[0].getHead(ROOT.recoveryId))
			.state as GuardianState;

		const acquireLost = (index: number): IBoundGuardianClient => ({
			expectedGuardianId: served[index].id,
			client: new GuardianClient({
				url: served[index].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (url.endsWith('/acquire_epoch')) {
						throw new GuardianTransportError('acquire lost in transit');
					}
					return nodeGuardianTransport()(url, init);
				}
			})
		});
		const target = openStorage();
		try {
			await driverFor(target, [
				{ expectedGuardianId: served[0].id, client: clients[0] },
				acquireLost(1),
				acquireLost(2)
			]).restore();
			expect.fail('the takeover cannot complete against one guardian');
		} catch (error) {
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}
		const pending = JSON.parse(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition) as string
		) as { newEpoch: string; writerPublicKey: string };
		const epoch = BigInt(pending.newEpoch);
		expect(epoch).to.equal(guard.lease.epoch + 1n);

		await served[0].server.close();
		live.manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 79).toString('hex'),
					preimage: Buffer.alloc(32, 79)
				}
			],
			outboundMessages: []
		});
		const all = live.storage.loadRecoveryFrames();
		const tail = rep.signRecord(all[all.length - 1], lease);
		for (const client of clients.slice(1)) {
			expect((await client.putState(tail)).status).to.equal(GuardianStatus.OK);
		}

		// Every member is back. The attempt keeps its epoch and key and is
		// granted over N+1, which the restore therefore includes.
		const revived = new GuardianHttpServer({ guardian: served[0].guardian });
		const revivedPort = await revived.listen(0);
		const revivedClient = new GuardianClient({
			url: `http://127.0.0.1:${revivedPort}`,
			guardianSetId: SET_ID
		});
		const members: IBoundGuardianClient[] = [
			{ client: revivedClient, expectedGuardianId: served[0].id },
			...bind(served.slice(1))
		];
		const events: IRestoreEvent[] = [];
		const result = await driverFor(target, members, events).restore();
		expect(events.some((e) => e.type === 'epoch:retargeted')).to.equal(true);
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(false);
		expect(result.lease.epoch).to.equal(epoch);
		expect(result.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(result.certifiedState.logHead.sequence).to.equal(
			guard.logHead.sequence + 1n
		);
		expect(dumpTables(target)).to.equal(dumpTables(live.storage));
		for (const client of [revivedClient, ...clients.slice(1)]) {
			const head = await client.getHead(ROOT.recoveryId);
			for (const cert of head.certificates ?? []) {
				if (cert.newEpoch !== epoch) continue;
				expect(cert.newWriterPublicKey.toString('hex')).to.equal(
					pending.writerPublicKey
				);
			}
		}

		// G1 still holds its certificate over N. A later restore reads it
		// beside the quorum's over N+1, follows the quorum, and brings G1 up
		// to N+1 under it (issue #1268), so all three grant the next epoch.
		const later = openStorage();
		const next = await driverFor(later, members).restore();
		expect(next.lease.epoch).to.equal(epoch + 1n);
		expect(next.certifiedState.logHead.sequence).to.equal(
			guard.logHead.sequence + 1n
		);
		expect(next.certificates.length).to.equal(3);
		expect(dumpTables(later)).to.equal(dumpTables(live.storage));

		await revived.close();
		await shutdown(served);
		live.storage.close();
		target.close();
		later.close();
	});

	it('restores a takeover an old-writer append split between a retargeted round', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1268. G1 grants the attempt over N; the live writer takes
		// G2 and G3 to N+1, and the retargeted round is split by one more
		// append landing on G3 between G2's grant and its own: G1 granted
		// over N, G2 over N+1, G3 still under the old lease at N+2.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const guard = (await clients[0].getHead(ROOT.recoveryId))
			.state as GuardianState;

		const acquireLost = (index: number): IBoundGuardianClient => ({
			expectedGuardianId: served[index].id,
			client: new GuardianClient({
				url: served[index].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (url.endsWith('/acquire_epoch')) {
						throw new GuardianTransportError('acquire lost in transit');
					}
					return nodeGuardianTransport()(url, init);
				}
			})
		});
		const target = openStorage();
		try {
			await driverFor(target, [
				{ expectedGuardianId: served[0].id, client: clients[0] },
				acquireLost(1),
				acquireLost(2)
			]).restore();
			expect.fail('the takeover cannot complete against one guardian');
		} catch (error) {
			expect((error as RestoreRefusedError).reason).to.equal('cas-exhausted');
		}
		const pending = JSON.parse(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition) as string
		) as { newEpoch: string; writerPublicKey: string };
		const epoch = BigInt(pending.newEpoch);

		const append = (n: number): IGuardianRecord => {
			live.manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, n).toString('hex'),
						preimage: Buffer.alloc(32, n)
					}
				],
				outboundMessages: []
			});
			const all = live.storage.loadRecoveryFrames();
			return rep.signRecord(all[all.length - 1], lease);
		};
		const tail = append(81);
		for (const client of clients.slice(1)) {
			expect((await client.putState(tail)).status).to.equal(GuardianStatus.OK);
		}
		const certifiedDump = dumpTables(live.storage);
		const late = append(82);

		// G3 takes the late append just before it handles the retargeted
		// round, after G2 has already granted over N+1.
		let injected = false;
		const splitting: IBoundGuardianClient = {
			expectedGuardianId: served[2].id,
			client: new GuardianClient({
				url: served[2].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (
						url.endsWith('/acquire_epoch') &&
						!injected &&
						decodeAcquireEpochRequest(init.body as Buffer).expectedState.logHead
							.sequence ===
							guard.logHead.sequence + 1n
					) {
						injected = true;
						expect(
							served[2].guardian.putState({ record: late }).status
						).to.equal(GuardianStatus.OK);
					}
					return nodeGuardianTransport()(url, init);
				}
			})
		};
		const events: IRestoreEvent[] = [];
		const result = await driverFor(
			target,
			[...bind(served.slice(0, 2)), splitting],
			events
		).restore();
		expect(injected).to.equal(true);
		expect(events.some((e) => e.type === 'epoch:retargeted')).to.equal(true);
		expect(result.lease.epoch).to.equal(epoch);
		expect(result.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		expect(result.certifiedState.logHead.sequence).to.equal(
			guard.logHead.sequence + 1n
		);
		expect(dumpTables(target)).to.equal(certifiedDump);

		// Every guardian is on the new lease over N+1, and G3's N+2, which
		// never reached a quorum, is gone from its log.
		for (const client of clients) {
			const head = await client.getHead(ROOT.recoveryId);
			const state = head.state as GuardianState;
			expect(state.lease.epoch).to.equal(epoch);
			expect(state.lease.writerPublicKey.toString('hex')).to.equal(
				pending.writerPublicKey
			);
			expect(state.logHead.sequence).to.equal(guard.logHead.sequence + 1n);
		}
		const above = await clients[2].getState(
			ROOT.recoveryId,
			guard.logHead.sequence + 1n,
			8
		);
		expect(above.records ?? []).to.have.length(0);

		// The set is whole again: all three grant the next takeover.
		const later = openStorage();
		const next = await driverFor(later, bind(served)).restore();
		expect(next.lease.epoch).to.equal(epoch + 1n);
		expect(next.certificates.length).to.equal(3);
		expect(dumpTables(later)).to.equal(certifiedDump);

		await shutdown(served);
		live.storage.close();
		target.close();
		later.close();
	});

	it('abandons a resumed attempt a later takeover fenced', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1426. Every member granted the attempt over N before it was
		// promoted. Another device then took the next epoch on G1 and G3 and
		// stored N+1 there. All three still replay their grant of the
		// attempt, which must not become a lease the quorum already fenced.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		const guard = await grantNext(clients[0], lease, writer);
		await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);

		const other = await takeOverAndAppend([served[0], served[2]], 85);
		const n = guard.logHead.sequence;
		expect(await headsOf(clients)).to.deep.equal({
			epochs: [lease.epoch + 2n, lease.epoch + 1n, lease.epoch + 2n],
			sequences: [n + 1n, n, n + 1n]
		});

		const events: IRestoreEvent[] = [];
		const result = await driverFor(target, bind(served), events).restore();
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(true);
		expect(result.lease.epoch).to.equal(lease.epoch + 3n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			false
		);
		expect(result.certifiedState.logHead.sequence).to.equal(n + 1n);
		expect(dumpTables(target)).to.equal(dumpTables(other));

		await shutdown(served);
		live.storage.close();
		target.close();
		other.close();
	});

	it('abandons a resumed split grant a later takeover fenced', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1426 over a split grant (issue #1268): G1 granted the
		// attempt over N, G2 and G3 over N+1. Another device then took the
		// next epoch on G1 and G3 and stored N+2 there. G2 still holds the
		// attempt over N+1, which a split completion would download from.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		await grantNext(clients[0], lease, writer);
		live.manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 86).toString('hex'),
					preimage: Buffer.alloc(32, 86)
				}
			],
			outboundMessages: []
		});
		const all = live.storage.loadRecoveryFrames();
		const tail = rep.signRecord(all[all.length - 1], lease);
		for (const client of clients.slice(1)) {
			expect((await client.putState(tail)).status).to.equal(GuardianStatus.OK);
		}
		const guard = await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);

		const other = await takeOverAndAppend([served[0], served[2]], 87);
		const n = guard.logHead.sequence;
		expect(await headsOf(clients)).to.deep.equal({
			epochs: [lease.epoch + 2n, lease.epoch + 1n, lease.epoch + 2n],
			sequences: [n + 1n, n, n + 1n]
		});

		const events: IRestoreEvent[] = [];
		const result = await driverFor(target, bind(served), events).restore();
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(true);
		expect(result.lease.epoch).to.equal(lease.epoch + 3n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			false
		);
		expect(result.certifiedState.logHead.sequence).to.equal(n + 1n);
		expect(dumpTables(target)).to.equal(dumpTables(other));

		await shutdown(served);
		live.storage.close();
		target.close();
		other.close();
	});

	it('abandons a resumed attempt fenced by a takeover a possibly-stale guardian signed', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1470. As above, but G3 now reports possibly_stale. Its head
		// proves no recency, yet its signed grant is half of the quorum that
		// fenced the attempt, and of the one that repairs G2 up to N+1.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		const guard = await grantNext(clients[0], lease, writer);
		await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);

		const other = await takeOverAndAppend([served[0], served[2]], 88);
		const n = guard.logHead.sequence;

		// A possibly-stale guardian refuses every acquisition (wire 5.3).
		const staleG3 = new Proxy(clients[2], {
			get(t, prop, receiver): unknown {
				if (prop === 'getHead') {
					return async (id: Buffer): Promise<unknown> => ({
						...(await t.getHead(id)),
						possiblyStale: true
					});
				}
				if (prop === 'acquireEpoch') {
					return async (): Promise<unknown> => ({
						status: GuardianStatus.ERR_STORE_UNCERTAIN
					});
				}
				const value = Reflect.get(t, prop, receiver);
				return typeof value === 'function' ? value.bind(t) : value;
			}
		});
		const events: IRestoreEvent[] = [];
		const result = await driverFor(
			target,
			[
				...bind(served.slice(0, 2)),
				{ client: staleG3, expectedGuardianId: served[2].id }
			],
			events
		).restore();
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(true);
		expect(result.lease.epoch).to.equal(lease.epoch + 3n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			false
		);
		expect(result.certifiedState.logHead.sequence).to.equal(n + 1n);
		expect(dumpTables(target)).to.equal(dumpTables(other));
		expect(await headsOf(clients.slice(0, 2))).to.deep.equal({
			epochs: [lease.epoch + 3n, lease.epoch + 3n],
			sequences: [n + 1n, n + 1n]
		});

		await shutdown(served);
		live.storage.close();
		target.close();
		other.close();
	});

	it('completes a resumed split grant whose quorum needs a possibly-stale signer', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1498. G2 granted the attempt over N and now reports
		// possibly_stale, G1 granted it over N+1, and G3 is still under the
		// old lease at N+2. Only G2's signed grant completes the quorum.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		await grantNext(clients[1], lease, writer);

		const append = (n: number): IGuardianRecord => {
			live.manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, n).toString('hex'),
						preimage: Buffer.alloc(32, n)
					}
				],
				outboundMessages: []
			});
			const all = live.storage.loadRecoveryFrames();
			return rep.signRecord(all[all.length - 1], lease);
		};
		const tail = append(93);
		for (const client of [clients[0], clients[2]]) {
			expect((await client.putState(tail)).status).to.equal(GuardianStatus.OK);
		}
		const certifiedDump = dumpTables(live.storage);
		const guard = await grantNext(clients[0], lease, writer);
		expect((await clients[2].putState(append(94))).status).to.equal(
			GuardianStatus.OK
		);
		const target = openStorage();
		persistPending(target, guard, writer);
		const n = guard.logHead.sequence;

		// A possibly-stale guardian refuses every acquisition (wire 5.3).
		const staleG2 = new Proxy(clients[1], {
			get(t, prop, receiver): unknown {
				if (prop === 'getHead') {
					return async (id: Buffer): Promise<unknown> => ({
						...(await t.getHead(id)),
						possiblyStale: true
					});
				}
				if (prop === 'acquireEpoch') {
					return async (): Promise<unknown> => ({
						status: GuardianStatus.ERR_STORE_UNCERTAIN
					});
				}
				const value = Reflect.get(t, prop, receiver);
				return typeof value === 'function' ? value.bind(t) : value;
			}
		});
		const result = await driverFor(target, [
			bind(served)[0],
			{ client: staleG2, expectedGuardianId: served[1].id },
			bind(served)[2]
		]).restore();
		expect(result.lease.epoch).to.equal(lease.epoch + 1n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			true
		);
		expect(result.certifiedState.logHead.sequence).to.equal(n);
		expect(dumpTables(target)).to.equal(certifiedDump);

		// G3 is on the new lease over N+1, and its N+2, which never reached
		// a quorum, is gone from its log.
		const head = (await clients[2].getHead(ROOT.recoveryId))
			.state as GuardianState;
		expect(head.lease.epoch).to.equal(lease.epoch + 1n);
		expect(head.lease.writerPublicKey.equals(writer.publicKey)).to.equal(true);
		expect(head.logHead.sequence).to.equal(n);
		const above = await clients[2].getState(ROOT.recoveryId, n, 8);
		expect(above.records ?? []).to.have.length(0);

		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('abandons a resumed attempt a takeover fenced after the heads were read', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1471. Every member granted the attempt over N, and the heads
		// read show nothing newer. Before the round reaches any guardian,
		// another device takes the next epoch on G1 and G3 and stores N+1
		// there. All three replay their grant of the attempt regardless.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		const guard = await grantNext(clients[0], lease, writer);
		await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);
		const n = guard.logHead.sequence;

		let taken: Promise<SqliteStorage> | undefined;
		const takeover = (): Promise<SqliteStorage> =>
			(taken ??= takeOverAndAppend([served[0], served[2]], 89));
		const afterRead = (entry: IServed): IBoundGuardianClient => {
			const client = new GuardianClient({
				url: entry.client.url,
				guardianSetId: SET_ID
			});
			const acquire = client.acquireEpoch.bind(client);
			client.acquireEpoch = async (request): ReturnType<typeof acquire> => {
				await takeover();
				return acquire(request);
			};
			return { client, expectedGuardianId: entry.id };
		};
		const events: IRestoreEvent[] = [];
		const result = await driverFor(
			target,
			[served[1], served[0], served[2]].map(afterRead),
			events
		).restore();
		expect(taken).to.not.equal(undefined);
		const other = await (taken as Promise<SqliteStorage>);
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(true);
		expect(result.lease.epoch).to.equal(lease.epoch + 3n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			false
		);
		expect(result.certifiedState.logHead.sequence).to.equal(n + 1n);
		expect(dumpTables(target)).to.equal(dumpTables(other));

		// The restored lease is the live one: its next record reaches a quorum.
		const manager = new RecoveryManager(target, {
			journal: new RecoveryJournal(
				target,
				deriveRecoveryMasterKey(NODE_SECRET),
				NODE_ID,
				ROOT.recoveryId
			)
		});
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, 90).toString('hex'),
						preimage: Buffer.alloc(32, 90)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const pass = await replicatorFor(target, bind(served)).replicatePending(
			result.lease
		);
		expect(pass.outcome).to.equal('replicated');

		await shutdown(served);
		live.storage.close();
		target.close();
		other.close();
	});

	it('abandons a resumed split grant a takeover fenced during its repair', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1471 over a split grant: G1 granted the attempt over N, G2
		// and G3 over N+1, and the heads read show nothing newer. Before G1
		// is repaired up to N+1, another device takes the next epoch on G1
		// and G3 and stores N+2 there.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		await grantNext(clients[0], lease, writer);
		live.manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 91).toString('hex'),
					preimage: Buffer.alloc(32, 91)
				}
			],
			outboundMessages: []
		});
		const all = live.storage.loadRecoveryFrames();
		const tail = rep.signRecord(all[all.length - 1], lease);
		for (const client of clients.slice(1)) {
			expect((await client.putState(tail)).status).to.equal(GuardianStatus.OK);
		}
		const guard = await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);
		const n = guard.logHead.sequence;

		let taken: Promise<SqliteStorage> | undefined;
		const afterRead = (entry: IServed): IBoundGuardianClient => {
			const client = new GuardianClient({
				url: entry.client.url,
				guardianSetId: SET_ID
			});
			const sync = client.syncRecord.bind(client);
			client.syncRecord = async (...args): ReturnType<typeof sync> => {
				await (taken ??= takeOverAndAppend([served[0], served[2]], 92));
				return sync(...args);
			};
			return { client, expectedGuardianId: entry.id };
		};
		const events: IRestoreEvent[] = [];
		const result = await driverFor(
			target,
			served.map(afterRead),
			events
		).restore();
		expect(taken).to.not.equal(undefined);
		const other = await (taken as Promise<SqliteStorage>);
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(true);
		expect(result.lease.epoch).to.equal(lease.epoch + 3n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			false
		);
		expect(result.certifiedState.logHead.sequence).to.equal(n + 1n);
		expect(dumpTables(target)).to.equal(dumpTables(other));

		await shutdown(served);
		live.storage.close();
		target.close();
		other.close();
	});

	it('keeps a resumed attempt while a signer of the takeover past it is unreachable', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1502. Every member granted the attempt over N, then another
		// device took the next epoch on G1 and G3 and stored N+1 there. With
		// G3 unreachable only G1's grant of that epoch shows, and G1 and G2
		// still replay their grants of the attempt.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		const guard = await grantNext(clients[0], lease, writer);
		await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);
		const pending = target.getRecoveryMeta!(
			RESTORE_META_KEYS.pendingAcquisition
		);
		const other = await takeOverAndAppend([served[0], served[2]], 95);
		const n = guard.logHead.sequence;

		const refused: IRestoreEvent[] = [];
		try {
			await driverFor(
				target,
				[...bind([served[1], served[0]]), unreachable(served[2])],
				refused
			).restore();
			expect.fail('the attempt may be fenced by a takeover G3 signed');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('no-quorum');
		}
		expect(
			refused.some(
				(e) => e.type === 'epoch:acquired' || e.type === 'epoch:abandoned'
			)
		).to.equal(false);
		expect(loadWriterLease(target).state).to.equal('missing');
		expect(target.loadRecoveryFrames()).to.have.length(0);
		expect(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition)
		).to.equal(pending);

		// Once G3 answers, the takeover's quorum shows and the restore
		// acquires over N+1 with a lease that can replicate.
		const events: IRestoreEvent[] = [];
		const result = await driverFor(target, bind(served), events).restore();
		expect(events.some((e) => e.type === 'epoch:abandoned')).to.equal(true);
		expect(result.lease.epoch).to.equal(lease.epoch + 3n);
		expect(result.certifiedState.logHead.sequence).to.equal(n + 1n);
		expect(dumpTables(target)).to.equal(dumpTables(other));
		const manager = new RecoveryManager(target, {
			journal: new RecoveryJournal(
				target,
				deriveRecoveryMasterKey(NODE_SECRET),
				NODE_ID,
				ROOT.recoveryId
			)
		});
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, 96).toString('hex'),
						preimage: Buffer.alloc(32, 96)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const pass = await replicatorFor(target, bind(served)).replicatePending(
			result.lease
		);
		expect(pass.outcome).to.equal('replicated');

		await shutdown(served);
		live.storage.close();
		target.close();
		other.close();
	});

	it('keeps a resumed attempt a takeover after the head read may have fenced', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1502 over #1471. The heads read show nothing newer than the
		// attempt. Before the round reaches any guardian, another device
		// takes the next epoch on G1 and G3 and stores N+1 there. G3 is
		// unreachable from here, so the re-read shows only G1's grant of it.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		const guard = await grantNext(clients[0], lease, writer);
		await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);
		const pending = target.getRecoveryMeta!(
			RESTORE_META_KEYS.pendingAcquisition
		);

		let taken: Promise<SqliteStorage> | undefined;
		const afterRead = (entry: IServed): IBoundGuardianClient => {
			const client = new GuardianClient({
				url: entry.client.url,
				guardianSetId: SET_ID
			});
			const acquire = client.acquireEpoch.bind(client);
			client.acquireEpoch = async (request): ReturnType<typeof acquire> => {
				await (taken ??= takeOverAndAppend([served[0], served[2]], 97));
				return acquire(request);
			};
			return { client, expectedGuardianId: entry.id };
		};
		const events: IRestoreEvent[] = [];
		try {
			await driverFor(
				target,
				[afterRead(served[1]), afterRead(served[0]), unreachable(served[2])],
				events
			).restore();
			expect.fail('the attempt may be fenced by a takeover G3 signed');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('no-quorum');
		}
		expect(taken).to.not.equal(undefined);
		const other = await (taken as Promise<SqliteStorage>);
		expect(
			events.some(
				(e) => e.type === 'epoch:acquired' || e.type === 'epoch:abandoned'
			)
		).to.equal(false);
		expect(loadWriterLease(target).state).to.equal('missing');
		expect(target.loadRecoveryFrames()).to.have.length(0);
		expect(
			target.getRecoveryMeta!(RESTORE_META_KEYS.pendingAcquisition)
		).to.equal(pending);

		await shutdown(served);
		live.storage.close();
		target.close();
		other.close();
	});

	it('completes a resumed attempt past which every member shows only a partial takeover', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// Issue #1502's boundary. Every member granted the attempt over N,
		// and G1 alone then granted the next epoch to another key. G2 and G3
		// answer at the attempt, so that takeover has no quorum to hide.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const expectedDump = dumpTables(live.storage);
		const writer = generateWriterKey();
		const guard = await grantNext(clients[0], lease, writer);
		await grantNext(clients[1], lease, writer);
		await grantNext(clients[2], lease, writer);
		await grantNext(
			clients[0],
			{ ...lease, epoch: lease.epoch + 1n },
			generateWriterKey()
		);
		const target = openStorage();
		persistPending(target, guard, writer);

		const result = await driverFor(target, bind(served)).restore();
		expect(result.lease.epoch).to.equal(lease.epoch + 1n);
		expect(result.lease.writerPublicKey.equals(writer.publicKey)).to.equal(
			true
		);
		expect(result.certifiedState.logHead.sequence).to.equal(
			guard.logHead.sequence
		);
		expect(dumpTables(target)).to.equal(expectedDump);

		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('follows a rotation that reaches the source while a split takeover completes', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// G1 granted the pending attempt over N and G2 over N+1, with G3
		// still under the old lease at N+1. The rotation lands on G2 after
		// every head was read, while G3 is being repaired.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		await grantNext(clients[0], lease, writer);
		live.manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 84).toString('hex'),
					preimage: Buffer.alloc(32, 84)
				}
			],
			outboundMessages: []
		});
		const all = live.storage.loadRecoveryFrames();
		const tail = rep.signRecord(all[all.length - 1], lease);
		for (const client of clients.slice(1)) {
			expect((await client.putState(tail)).status).to.equal(GuardianStatus.OK);
		}
		const guard = await grantNext(clients[1], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);

		const incoming = [
			GUARDIAN_IDS[1],
			GUARDIAN_IDS[2],
			xOnlyFromSecret(sha('p5-restore-guardian-4'))
		];
		const fields = {
			recoveryId: ROOT.recoveryId,
			newGuardianSetId: computeGuardianSetId({
				...CRASH_V1_PROFILE,
				guardianIds: incoming
			}),
			generation: 2n,
			newMembers: incoming
		};
		const rotation = {
			protocolVersion: 1,
			guardianSetId: SET_ID,
			...fields,
			rootSignature: signTranscript(
				rotateTranscriptHash(SET_ID, fields),
				ROOT.rootSecret
			),
			newTransports: incoming.map((id) => ({
				type: 'https',
				url: `https://${id.toString('hex').slice(0, 8)}.example`
			}))
		};
		let retired = false;
		const repairing: IBoundGuardianClient = {
			expectedGuardianId: served[2].id,
			client: new GuardianClient({
				url: served[2].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (url.endsWith('/sync_epoch') && !retired) {
						retired = true;
						expect(served[1].guardian.rotateSet(rotation).status).to.equal(
							GuardianStatus.OK
						);
					}
					return nodeGuardianTransport()(url, init);
				}
			})
		};
		try {
			await driverFor(target, [
				...bind(served.slice(0, 2)),
				repairing
			]).restore();
			expect.fail('a retired set must not complete the takeover');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRotatedError);
		}
		expect(retired).to.equal(true);
		expect(loadWriterLease(target).state).to.equal('missing');
		expect(target.loadRecoveryFrames()).to.have.length(0);
		await shutdown(served);
		live.storage.close();
		target.close();
	});

	it('halts a split takeover whose lower head is off the certified chain', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// G1 granted the pending attempt over its own record at sequence 1,
		// G2 over sequence 2 of a log with another record at 1. Both name
		// the same lease and key, but they are two different histories.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(1);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const fork = liveNode(0);
		for (const n of [91, 92]) {
			fork.manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, n).toString('hex'),
						preimage: Buffer.alloc(32, n)
					}
				],
				outboundMessages: []
			});
		}
		const [own] = live.storage.loadRecoveryFrames();
		expect(
			(await clients[0].putState(rep.signRecord(own, lease))).status
		).to.equal(GuardianStatus.OK);
		for (const client of clients.slice(1)) {
			for (const frame of fork.storage.loadRecoveryFrames()) {
				expect(
					(await client.putState(rep.signRecord(frame, lease))).status
				).to.equal(GuardianStatus.OK);
			}
		}
		const writer = generateWriterKey();
		await grantNext(clients[0], lease, writer);
		const guard = await grantNext(clients[1], lease, writer);
		const target = openStorage();
		persistPending(target, guard, writer);

		try {
			await driverFor(target, bind(served)).restore();
			expect.fail('two histories under one takeover must halt the restore');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('conflict');
		}
		expect(loadWriterLease(target).state).to.equal('missing');
		expect(target.loadRecoveryFrames()).to.have.length(0);
		await shutdown(served);
		live.storage.close();
		fork.storage.close();
		target.close();
	});

	it('repairs a guardian that missed the takeover and discards its superseded tail', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('adopts a higher epoch only when a quorum certified it', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('does not count a possibly-stale guardian toward the read set', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('resumes after a crash between the takeover and lease promotion', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('starts post-restore replication after the certified head', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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
		// The mark is only trusted when BOUND to the history it receipts, so
		// the install must write the certified head's frame hash beside it;
		// without the binding the strict read above would report zero and
		// every pass would re-offer the whole restored journal.
		expect(
			target.getRecoveryMeta!(REPLICATION_META_KEYS.replicatedThroughHash)
		).to.equal(restored.certifiedState.logHead.frameHash.toString('hex'));
		// And the mark is a statement about frames this database can SHOW. The
		// install writes the watermark and the journal tip to the same
		// certified head in one transaction, so a quorum barrier built over a
		// restored database must not read it as a rolled-back log.
		expect(resumed.watermarkExceedingJournal()).to.equal(null);

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

	it('does not call one holder plus two unknowns an unregistered namespace', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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
					guardianMembers: GUARDIAN_IDS,
					generation: 1n,
					initialState,
					rootSignature: signTranscript(
						registerTranscriptHash(SET_ID, initialState, 1n),
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

	it('marks every restored channel StateUncertain inside the install', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('halts on a crash-fault-model breach instead of guessing', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('halts when a quorum fixed a lower head than another grant of the same key', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		// G1 and G3 grant one key over N; G2, after one more append, grants
		// the same key over N+1. The quorum over N fixes one final head and
		// G1 with G2 another, so the epoch has two (issue #1268).
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const writer = generateWriterKey();
		const grant = async (index: number): Promise<void> => {
			const guard = (await clients[index].getHead(ROOT.recoveryId))
				.state as GuardianState;
			const response = await clients[index].acquireEpoch({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				expectedState: guard,
				newEpoch: lease.epoch + 1n,
				newWriterPublicKey: writer.publicKey,
				...signAcquisition(
					SET_ID,
					guard,
					lease.epoch + 1n,
					writer,
					ROOT.rootSecret
				)
			});
			expect(response.status).to.equal(GuardianStatus.OK);
		};
		await grant(0);
		await grant(2);
		live.manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 83).toString('hex'),
					preimage: Buffer.alloc(32, 83)
				}
			],
			outboundMessages: []
		});
		const all = live.storage.loadRecoveryFrames();
		const tail = rep.signRecord(all[all.length - 1], lease);
		expect((await clients[1].putState(tail)).status).to.equal(
			GuardianStatus.OK
		);
		await grant(1);

		const target = openStorage();
		try {
			await driverFor(target, bind(served)).restore();
			expect.fail('two final heads for one epoch must halt the restore');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('conflict');
		}
		expect(loadWriterLease(target).state).to.equal('missing');
		expect(target.loadRecoveryFrames()).to.have.length(0);

		// A possibly-stale G3 proves no recency, but its signed grant over N
		// still completes the lower quorum.
		const staleG3 = new Proxy(clients[2], {
			get(t, prop, receiver): unknown {
				if (prop === 'getHead') {
					return async (id: Buffer): Promise<unknown> => ({
						...(await t.getHead(id)),
						possiblyStale: true
					});
				}
				const value = Reflect.get(t, prop, receiver);
				return typeof value === 'function' ? value.bind(t) : value;
			}
		});
		const staleTarget = openStorage();
		try {
			await driverFor(staleTarget, [
				...bind(served.slice(0, 2)),
				{ client: staleG3, expectedGuardianId: served[2].id }
			]).restore();
			expect.fail('a stale guardian still certifies the lower head');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('conflict');
		}
		expect(staleTarget.loadRecoveryFrames()).to.have.length(0);

		// With G3 away the quorum over N is out of sight, so a restore runs
		// and takes G1 up to N+1. G1 still serves its grant over N, so the
		// conflict is found again once G3 is back.
		const partial = openStorage();
		await driverFor(partial, bind(served.slice(0, 2))).restore();
		expect(
			((await clients[0].getHead(ROOT.recoveryId)).state as GuardianState)
				.logHead.sequence
		).to.equal(tail.sequence);
		const again = openStorage();
		try {
			await driverFor(again, bind(served)).restore();
			expect.fail('the quorum over N still fixes a second final head');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('conflict');
		}
		await shutdown(served);
		live.storage.close();
		target.close();
		staleTarget.close();
		partial.close();
		again.close();
	});
});

describe('Recovery phase 5: restore past the guardian record limit (issue #1102)', () => {
	it('restores 20k completed payments whose snapshot outgrew the 4 MiB record limit', async function (): Promise<void> {
		this.timeout(120_000);
		const PAID = 10_000;
		const served = await Promise.all(
			[0, 1, 2].map((i) => serve(i, GUARDIAN_HOST_DEFAULT_MAX_CIPHERTEXT_BYTES))
		);
		const storage = openStorage();
		const hashOf = (tag: number, i: number): string => {
			const hash = Buffer.alloc(32, tag);
			hash.writeUInt32BE(i, 0);
			return hash.toString('hex');
		};
		const record = (hash: string, direction: PaymentDirection): IPaymentInfo =>
			({
				paymentHash: Buffer.from(hash, 'hex'),
				amountMsat: 1_000_000n,
				status: PaymentStatus.COMPLETED,
				direction,
				createdAt: 1_700_000_000_000
			}) as IPaymentInfo;
		storage.transaction(() => {
			for (let i = 0; i < PAID; i++) {
				const sent = hashOf(3, i);
				storage.savePayment(sent, {
					...record(sent, PaymentDirection.OUTGOING),
					preimage: Buffer.alloc(32, 3)
				});
				const received = hashOf(8, i);
				storage.savePayment(
					received,
					record(received, PaymentDirection.INCOMING)
				);
				storage.savePreimage(received, Buffer.alloc(32, 8));
			}
		});
		const rep = replicatorFor(storage, bind(served));
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{ maxFrameCiphertextBytes: (): number => rep.maxRecordBytes() }
		);
		const manager = new RecoveryManager(storage, { journal });
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: hashOf(4, 0),
						preimage: Buffer.alloc(32, 4)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
		const rows = storage.loadRecoveryFrames();
		expect(rows.length).to.be.greaterThan(1);
		for (const row of rows) {
			expect(row.ciphertext.length).to.be.at.most(
				GUARDIAN_HOST_DEFAULT_MAX_CIPHERTEXT_BYTES
			);
		}

		const decision = await rep.ensureNamespace();
		const pass = await rep.replicatePending(
			(decision as { lease: IWriterLeaseKeys }).lease
		);
		expect(pass.outcome).to.equal('replicated');
		expect(pass.replicatedThrough).to.equal(BigInt(rows.length));
		const expectedDump = dumpTables(storage);

		const target = openStorage();
		await driverFor(target, bind(served)).restore();
		expect(dumpTables(target)).to.equal(expectedDump);
		// What the double-pay guard and the paid-hash refusal read.
		for (let i = 0; i < PAID; i++) {
			expect(target.loadPayment(hashOf(3, i))).to.include({
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING
			});
			expect(target.loadPayment(hashOf(8, i))).to.include({
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.INCOMING
			});
		}
		await shutdown(served);
		storage.close();
		target.close();
	});
});

describe('Recovery phase 5: guardian storage shrinks (issue #1028)', () => {
	function commitTransition(manager: RecoveryManager, i: number): void {
		expect(
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: Buffer.alloc(32, i + 1).toString('hex'),
						preimage: Buffer.alloc(32, i + 1)
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
	}

	it('frees guardian records below a snapshot every guardian holds and still restores exactly', async function (): Promise<void> {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{
				snapshotIntervalFrames: 4,
				retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		commitTransition(manager, 0);
		rep = replicatorFor(storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		for (let i = 1; i <= 24; i++) {
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}

		const base = BigInt(
			storage.getRecoveryMeta!(JOURNAL_META_KEYS.lastSnapshot)!
		);
		expect(base > 8n).to.equal(true);
		for (const entry of served) {
			const page = await entry.client.getState(ROOT.recoveryId, 0n);
			const first = page.records![0].sequence;
			// Freed up to a snapshot the writer compacted to, never past its base.
			expect(first > 4n).to.equal(true);
			expect(first <= base).to.equal(true);
			expect(entry.guardian.contentBytes()).to.equal(
				entry.guardian.auditContentBytes()
			);
		}

		const expectedDump = dumpTables(storage);
		const target = openStorage();
		await driverFor(target, bind(served)).restore();
		expect(dumpTables(target)).to.equal(expectedDump);
		await shutdown(served);
		storage.close();
		target.close();
	});

	it('delivers a floor in the pass that makes it eligible', async function (): Promise<void> {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{
				snapshotIntervalFrames: 4,
				retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		commitTransition(manager, 0);
		rep = replicatorFor(storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const base = (): string =>
			storage.getRecoveryMeta!(JOURNAL_META_KEYS.lastSnapshot)!;
		const initial = base();
		// No pass follows the one that replicates the new snapshot, as when a
		// restart writes the next snapshot at its first transition. Compaction
		// runs after the pass, as the node's durable-advance hook runs it.
		for (let i = 1; base() === initial; i++) {
			expect(i).to.be.below(20);
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}
		for (const entry of served) {
			const page = await entry.client.getState(ROOT.recoveryId, 0n);
			expect(String(page.records![0].sequence)).to.equal(base());
		}
		await shutdown(served);
		storage.close();
	});

	/** A client for `entry` whose `verbs` fail whenever `drop` says so. */
	function dropping(
		entry: IServed,
		drop: (body: Buffer) => boolean,
		verbs = ['/put_state'],
		maxResponseBytes?: number
	): IBoundGuardianClient {
		const transport = nodeGuardianTransport();
		return {
			expectedGuardianId: entry.id,
			client: new GuardianClient({
				url: entry.client.url,
				guardianSetId: SET_ID,
				maxResponseBytes,
				transport: (url, init) =>
					verbs.some((verb) => url.endsWith(verb)) && drop(init.body as Buffer)
						? Promise.reject(new Error('dropped'))
						: transport(url, init)
			})
		};
	}

	it('frees nothing a lagging guardian needs, so a restore without a quorum member repairs it', async function (): Promise<void> {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{
				snapshotIntervalFrames: 4,
				retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		commitTransition(manager, 0);
		let lagging = false;
		rep = replicatorFor(storage, [
			...bind(served.slice(0, 2)),
			dropping(served[2], () => lagging, ['/put_state', '/sync_record'])
		]);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		lagging = true;
		for (let i = 1; i <= 16; i++) {
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}

		const behind = (await served[2].client.getHead(ROOT.recoveryId)).state!
			.logHead.sequence;
		for (const entry of served.slice(0, 2)) {
			const page = await entry.client.getState(ROOT.recoveryId, 0n);
			expect(page.records![0].sequence <= behind + 1n).to.equal(true);
		}
		// Only the one current guardian and the laggard are left.
		await served[0].server.close();
		const expectedDump = dumpTables(storage);
		const target = openStorage();
		const result = await driverFor(target, bind(served)).restore();
		expect(result.guardiansRepaired).to.be.at.least(1);
		expect(dumpTables(target)).to.equal(expectedDump);
		await shutdown(served);
		storage.close();
		target.close();
	});

	it('catches up a guardian that missed passes, so floors resume', async function (): Promise<void> {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{
				snapshotIntervalFrames: 4,
				retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		commitTransition(manager, 0);
		let lagging = false;
		rep = replicatorFor(storage, [
			...bind(served.slice(0, 2)),
			dropping(served[2], () => lagging)
		]);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		// Longer than one pass relays, and past snapshots the journal then
		// compacts away, so only the peers still hold what it missed.
		lagging = true;
		for (let i = 1; i <= 10; i++) {
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}
		lagging = false;
		for (let i = 11; i <= 24; i++) {
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}

		for (const entry of served) {
			const head = (await entry.client.getHead(ROOT.recoveryId)).state!.logHead
				.sequence;
			expect(head).to.equal(rep.replicatedThrough());
			const page = await entry.client.getState(ROOT.recoveryId, 0n);
			expect(page.records![0].sequence > 1n).to.equal(true);
		}
		await shutdown(served);
		storage.close();
	});

	it('catches up a laggard even when each pass adds as much as one window', async function (): Promise<void> {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{
				snapshotIntervalFrames: 4,
				retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		commitTransition(manager, 0);
		let lagging = false;
		rep = new GuardianReplicator({
			storage,
			guardians: [
				...bind(served.slice(0, 2)),
				dropping(served[2], () => lagging)
			],
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			clock,
			journalKeys: JOURNAL_KEYS,
			pipelineWindow: 1
		});
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		lagging = true;
		for (let i = 1; i <= 4; i++) {
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}
		lagging = false;
		for (let i = 5; i <= 16; i++) {
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}

		for (const entry of served) {
			const head = (await entry.client.getHead(ROOT.recoveryId)).state!.logHead
				.sequence;
			expect(head).to.equal(rep.replicatedThrough());
			const page = await entry.client.getState(ROOT.recoveryId, 0n);
			expect(page.records![0].sequence > 1n).to.equal(true);
		}
		await shutdown(served);
		storage.close();
	});

	it("carries the incoming set's proven floor through a rotation", async function (): Promise<void> {
		this.timeout(30_000);
		const outgoing = await Promise.all([serve(0), serve(1), serve(2)]);
		const secrets = [4, 5, 6].map((i) => sha(`p5-restore-guardian-${i}`));
		const ids = secrets.map((secret) => xOnlyFromSecret(secret));
		const context = {
			guardianSetId: computeGuardianSetId({
				...CRASH_V1_PROFILE,
				guardianIds: ids
			}),
			members: ids
		};
		const incoming: IServed[] = await Promise.all(
			secrets.map(async (secret, i) => {
				const guardian = new ReferenceGuardian({
					path: ':memory:',
					guardianSecret: secret,
					members: ids,
					clock
				});
				const server = new GuardianHttpServer({ guardian });
				const port = await server.listen(0);
				return {
					guardian,
					server,
					id: ids[i],
					client: new GuardianClient({
						url: `http://127.0.0.1:${port}`,
						guardianSetId: context.guardianSetId
					})
				};
			})
		);
		const setOf = (served: IServed[]): IParsedGuardian[] =>
			served.map((entry) => ({ guardianId: entry.id, url: entry.client.url }));
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(outgoing));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);

		const result = await new GuardianRotation({
			storage: live.storage,
			recoveryRoot: ROOT,
			lease,
			outgoing: {
				guardians: setOf(outgoing),
				bound: bind(outgoing),
				context: CONTEXT
			},
			incoming: { guardians: setOf(incoming), bound: bind(incoming), context },
			required: CRASH_V1_PROFILE.required,
			clock,
			journalKeys: JOURNAL_KEYS
		}).rotate();
		expect(result.replicator.retainFloor(lease)?.sequence).to.equal(1n);
		await shutdown([...outgoing, ...incoming]);
		live.storage.close();
	});

	it('keeps a proven floor across a restart that writes the next snapshot', async function (): Promise<void> {
		this.timeout(20_000);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journalFor = (): RecoveryJournal =>
			new RecoveryJournal(
				storage,
				deriveRecoveryMasterKey(NODE_SECRET),
				NODE_ID,
				ROOT.recoveryId,
				{
					snapshotIntervalFrames: 1,
					retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
				}
			);
		const journal = journalFor();
		const manager = new RecoveryManager(storage, { journal });
		for (let i = 0; i < 3; i++) commitTransition(manager, i);
		// Full once the frames written so far are stored.
		const quota =
			GUARDIAN_REGISTRATION_BYTES +
			storage
				.loadRecoveryFrames()
				.reduce(
					(total, frame) =>
						total + GUARDIAN_RECORD_OVERHEAD_BYTES + frame.ciphertext.length,
					0
				);
		const served = await Promise.all(
			[0, 1, 2].map((i) => serve(i, undefined, quota))
		);
		let dropFloors = true;
		const guardians = served.map((entry) =>
			dropping(
				entry,
				(body) =>
					dropFloors && decodePutStateRequest(body).retainFloor !== undefined
			)
		);
		rep = replicatorFor(storage, guardians);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		// The floor this pass proves reaches no guardian.
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		journal.compact();
		for (const entry of served) {
			expect(entry.guardian.contentBytes()).to.equal(quota);
		}

		// The restart writes its next snapshot before any pass runs.
		dropFloors = false;
		rep = replicatorFor(storage, guardians);
		commitTransition(
			new RecoveryManager(storage, { journal: journalFor() }),
			3
		);
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		for (const entry of served) {
			expect(entry.guardian.contentBytes()).to.be.below(quota);
		}
		await shutdown(served);
		storage.close();
	});

	it('frees a set a floorless writer filled once a restart re-bases above it (issue #1206)', async function (): Promise<void> {
		this.timeout(20_000);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journalFor = (): RecoveryJournal =>
			new RecoveryJournal(
				storage,
				deriveRecoveryMasterKey(NODE_SECRET),
				NODE_ID,
				ROOT.recoveryId,
				{
					snapshotIntervalFrames: 2,
					retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
				}
			);
		const journal = journalFor();
		const manager = new RecoveryManager(storage, { journal });
		for (let i = 0; i < 6; i++) commitTransition(manager, i);
		const quota =
			GUARDIAN_REGISTRATION_BYTES +
			storage
				.loadRecoveryFrames()
				.reduce(
					(total, frame) =>
						total + GUARDIAN_RECORD_OVERHEAD_BYTES + frame.ciphertext.length,
					0
				);
		const served = await Promise.all(
			[0, 1, 2].map((i) => serve(i, undefined, quota))
		);
		// A release before retain floors: no journal keys, so it names none.
		rep = new GuardianReplicator({
			storage,
			guardians: bind(served),
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			clock
		});
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		journal.compact();
		const held = rep.replicatedThrough();
		for (const entry of served) {
			expect(entry.guardian.contentBytes()).to.equal(quota);
		}

		// The upgraded writer restarts, and its first transition re-bases
		// above every record the full guardians hold. Its response cap fits
		// a record but not a page of them.
		const floors: bigint[] = [];
		rep = replicatorFor(
			storage,
			served.map((entry) =>
				dropping(
					entry,
					(body) => {
						const floor = decodePutStateRequest(body).retainFloor;
						if (floor) floors.push(floor.sequence);
						return false;
					},
					undefined,
					2_000
				)
			)
		);
		commitTransition(
			new RecoveryManager(storage, { journal: journalFor() }),
			6
		);
		expect(storage.getRecoveryMeta!(JOURNAL_META_KEYS.lastSnapshot)).to.equal(
			String(held + 1n)
		);
		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('replicated');
		expect(result.replicatedThrough > held).to.equal(true);
		// The first floor names a snapshot the full guardians already held.
		expect(floors[0] > 1n && floors[0] <= held).to.equal(true);
		for (const entry of served) {
			expect(entry.guardian.contentBytes()).to.be.below(quota);
			const page = await entry.client.getState(ROOT.recoveryId, 0n);
			expect(page.records![0].sequence > 1n).to.equal(true);
		}

		const expectedDump = dumpTables(storage);
		const target = openStorage();
		await driverFor(target, bind(served)).restore();
		expect(dumpTables(target)).to.equal(expectedDump);
		await shutdown(served);
		storage.close();
		target.close();
	});

	it('frees a set that filled while one guardian was away (issue #1206)', async function (): Promise<void> {
		this.timeout(30_000);
		const quota = GUARDIAN_REGISTRATION_BYTES + 9_000;
		const served = await Promise.all(
			[0, 1, 2].map((i) => serve(i, undefined, quota))
		);
		const storage = openStorage();
		let rep: GuardianReplicator | null = null;
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(NODE_SECRET),
			NODE_ID,
			ROOT.recoveryId,
			{
				snapshotIntervalFrames: 2,
				retainFrom: (): bigint => (rep ? rep.replicatedThrough() + 1n : 1n)
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		commitTransition(manager, 0);
		let away = false;
		// A window of one relays little a pass, so the returning guardian is
		// still below the journal's base when the others refuse.
		rep = new GuardianReplicator({
			storage,
			guardians: [
				...bind(served.slice(0, 2)),
				dropping(served[2], () => away, ['/put_state', '/sync_record'])
			],
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			clock,
			journalKeys: JOURNAL_KEYS,
			pipelineWindow: 1
		});
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		let i = 1;
		for (; i <= 4; i++) {
			commitTransition(manager, i);
			await rep.replicatePending(lease);
			journal.compact();
		}
		const floor = rep.retainFloor(lease)!.sequence;
		expect(floor > 1n).to.equal(true);

		// Floors pause while a guardian is away, so the other two fill.
		away = true;
		for (; ; i++) {
			expect(i).to.be.below(60);
			commitTransition(manager, i);
			const result = await rep.replicatePending(lease);
			journal.compact();
			if (result.outcome === 'under-replicated') break;
		}
		const full = rep.replicatedThrough();

		away = false;
		let result = await rep.replicatePending(lease);
		for (let pass = 0; result.outcome !== 'replicated'; pass++) {
			expect(pass).to.be.below(10);
			commitTransition(manager, ++i);
			result = await rep.replicatePending(lease);
			journal.compact();
		}
		expect(result.replicatedThrough > full).to.equal(true);
		expect(rep.retainFloor(lease)!.sequence > floor).to.equal(true);
		for (const entry of served.slice(0, 2)) {
			expect(entry.guardian.contentBytes()).to.be.below(quota);
		}
		await shutdown(served);
		storage.close();
	});

	it('names no floor from snapshot metadata that cannot name a record', async function (): Promise<void> {
		this.timeout(20_000);
		for (const sequence of ['0', '-1']) {
			const served = await Promise.all([serve(0), serve(1), serve(2)]);
			const live = liveNode(2);
			const rep = replicatorFor(live.storage, bind(served));
			const decision = await rep.ensureNamespace();
			const lease = (decision as { lease: IWriterLeaseKeys }).lease;
			live.storage.setRecoveryMeta!(
				META_LAST_SNAPSHOT_GROUP,
				JSON.stringify({
					sequence,
					groupEnd: '2',
					frameHash: sha('group').toString('hex')
				})
			);
			expect((await rep.replicatePending(lease)).outcome).to.equal(
				'replicated'
			);
			commitTransition(live.manager, 10);
			expect((await rep.replicatePending(lease)).outcome).to.equal(
				'replicated'
			);
			expect(rep.retainFloor(lease)).to.equal(undefined);
			await shutdown(served);
			live.storage.close();
		}
	});

	it('names no floor from a group whose first frame is not a snapshot', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		// Both ends name the delta at 2, exactly as the journal holds it.
		const delta =
			live.storage.loadRecoveryFrames!()[1].frameHash.toString('hex');
		live.storage.setRecoveryMeta!(
			META_LAST_SNAPSHOT_GROUP,
			JSON.stringify({
				sequence: '2',
				groupEnd: '2',
				frameHash: delta,
				endHash: delta
			})
		);
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		expect(rep.retainFloor(lease)).to.equal(undefined);
		await shutdown(served);
		live.storage.close();
	});

	it('names no floor from a group whose last frame is not the one it names', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const [snapshot, next] = live.storage.loadRecoveryFrames!();
		const group = (endHash: Buffer): string =>
			JSON.stringify({
				sequence: '1',
				groupEnd: '1',
				frameHash: snapshot.frameHash.toString('hex'),
				endHash: endHash.toString('hex')
			});
		// A group that ran through frame 2, its groupEnd damaged to 1.
		live.storage.setRecoveryMeta!(
			META_LAST_SNAPSHOT_GROUP,
			group(next.frameHash)
		);
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		expect(rep.retainFloor(lease)).to.equal(undefined);

		live.storage.setRecoveryMeta!(
			META_LAST_SNAPSHOT_GROUP,
			group(snapshot.frameHash)
		);
		commitTransition(live.manager, 10);
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		expect(rep.retainFloor(lease)?.sequence).to.equal(1n);
		await shutdown(served);
		live.storage.close();
	});

	it('reports a guardian whose quota refuses records, once per episode', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([
			serve(0),
			serve(1),
			serve(2, undefined, GUARDIAN_REGISTRATION_BYTES + 100)
		]);
		const live = liveNode(2);
		const events: IGuardianReplicationEvent[] = [];
		const rep = new GuardianReplicator({
			storage: live.storage,
			guardians: bind(served),
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			clock,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const refusals = (): IGuardianReplicationEvent[] =>
			events.filter((e) => e.type === 'record:quota-refused');

		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		expect(refusals()).to.have.length(1);
		expect(refusals()[0].detail).to.contain(GUARDIAN_IDS[2].toString('hex'));

		commitTransition(live.manager, 50);
		await rep.replicatePending(lease);
		expect(refusals()).to.have.length(1);
		await shutdown(served);
		live.storage.close();
	});
});
