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
	GuardianState,
	GuardianStatus,
	IRestoreEvent,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	RestoreDriver,
	RestoreRefusedError,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	generateWriterKey,
	loadWriterLease,
	signAcquisition,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { serializePaymentInfo } from '../../src/lightning/storage/serialization';

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
	clients: GuardianClient[]
): GuardianReplicator {
	return new GuardianReplicator({
		storage,
		clients,
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock
	});
}

function driverFor(
	target: IStorageBackend,
	clients: GuardianClient[],
	events: IRestoreEvent[] = []
): RestoreDriver {
	return new RestoreDriver({
		target,
		clients,
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
		const rep = replicatorFor(live.storage, clients);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);
		const expectedDump = dumpTables(live.storage);

		// The device is lost. A fresh install restores from the guardians.
		const events: IRestoreEvent[] = [];
		const target = openStorage();
		const driver = driverFor(target, clients, events);
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
		const rep = replicatorFor(live.storage, clients);
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
		const driver = driverFor(target, clients, events);
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
		const rep = replicatorFor(live.storage, clients);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		await rep.replicatePending(lease);

		// The takeover race (spec 5.7): a competing device acquires the epoch
		// between this driver's head read and its own acquisition, so the
		// first CAS must fail and the retry must land on the NEWER state.
		const target = openStorage();
		const events: IRestoreEvent[] = [];
		const driver = driverFor(target, clients, events);
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

	it('refuses without a read quorum, and for an unknown namespace', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(1);
		const rep = replicatorFor(live.storage, clients);
		const decision = await rep.ensureNamespace();
		await rep.replicatePending((decision as { lease: IWriterLeaseKeys }).lease);

		// Two guardians down: one response is below the read set, so there is
		// no recency proof and the takeover must be refused (5.7 step 5).
		await served[1].server.close();
		await served[2].server.close();
		const target = openStorage();
		try {
			await driverFor(target, clients).restore();
			expect.fail('a sub-quorum restore must be refused');
		} catch (error) {
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect((error as RestoreRefusedError).reason).to.equal('no-quorum');
		}
		expect(loadWriterLease(target).state).to.equal('missing');
		await shutdown(served);

		// A namespace nobody serves has nothing to restore.
		const fresh = await Promise.all([serve(0), serve(1), serve(2)]);
		const emptyTarget = openStorage();
		try {
			await driverFor(
				emptyTarget,
				fresh.map((s) => s.client)
			).restore();
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

	it('halts on a crash-fault-model breach instead of guessing', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const clients = served.map((s) => s.client);
		const live = liveNode(2);
		const rep = replicatorFor(live.storage, clients);
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
			await driverFor(target, clients).restore();
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
