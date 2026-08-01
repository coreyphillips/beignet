/**
 * Recovery Protocol phase 5: node-side guardian wiring
 * (docs/RECOVERY-PROTOCOL.md 5.5, 5.6).
 *
 * The properties under test:
 * - Registration is decided by ASKING the guardian set. Local absence never
 *   authorizes it, an existing namespace routes to restore instead, and no
 *   quorum means no registration at all.
 * - A node enabling guardians mid-journal registers its RETAINED BASE as
 *   the chain origin (wire 4.1), so journal numbering carries over.
 * - The lease is persisted only after a quorum acknowledges the
 *   registration: a lease nobody granted must never exist on disk.
 * - Journal frames replicate as signed records the guardian accepts,
 *   durability is claimed only for a contiguous quorum-receipted prefix,
 *   and replication resumes from the high-water mark after a restart.
 * - Ownership confirmation reports what the SET says, including being
 *   superseded by a later epoch.
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
	IBoundGuardianClient,
	IGuardianReplicationEvent,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	generateWriterKey,
	loadWriterLease,
	signAcquisition,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p5-rep-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };
const NODE_SECRET = sha('p5-rep-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

let now = 1_900_000_000_000n;
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
	const client = new GuardianClient({
		url: `http://127.0.0.1:${port}`,
		guardianSetId: SET_ID
	});
	return { guardian, server, client, id: GUARDIAN_IDS[index] };
}

async function shutdown(served: IServed[]): Promise<void> {
	for (const entry of served) {
		await entry.server.close();
		entry.guardian.close();
	}
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

/** A journaled storage with `count` committed transitions. */
function journaledStorage(count: number): {
	storage: SqliteStorage;
	journal: RecoveryJournal;
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
	for (let i = 0; i < count; i++) {
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, i + 1).toString('hex'),
					preimage: Buffer.alloc(32, i + 1)
				}
			],
			outboundMessages: []
		});
		expect(result.committed).to.equal(true);
	}
	return { storage, journal, manager };
}

function replicator(
	storage: SqliteStorage,
	guardians: IBoundGuardianClient[],
	events: IGuardianReplicationEvent[] = []
): GuardianReplicator {
	return new GuardianReplicator({
		storage,
		guardians,
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock,
		onEvent: (event): void => {
			events.push(event);
		}
	});
}

describe('Recovery phase 5: namespace establishment', () => {
	it('registers only when a quorum reports the namespace unknown', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(2);
		const events: IGuardianReplicationEvent[] = [];
		const rep = replicator(storage, bind(served), events);

		const decision = await rep.ensureNamespace();
		expect(decision.outcome).to.equal('registered');
		expect(events.some((e) => e.type === 'namespace:registered')).to.equal(
			true
		);

		// The lease exists only because a quorum acknowledged it.
		const lease = loadWriterLease(storage);
		expect(lease.state).to.equal('present');
		const held = (lease as { state: 'present'; lease: IWriterLeaseKeys }).lease;
		expect(held.epoch).to.equal(1n);
		expect(held.confirmedAt).to.not.equal(null);

		// Every guardian serves the namespace at genesis now.
		for (const entry of served) {
			const head = await entry.client.getHead(ROOT.recoveryId);
			expect(head.status).to.equal(GuardianStatus.OK);
			expect((head.state as GuardianState).lease.epoch).to.equal(1n);
			expect((head.state as GuardianState).logHead.sequence).to.equal(0n);
		}

		// Re-running is a no-op: the held lease answers without asking.
		const again = await rep.ensureNamespace();
		expect(again.outcome).to.equal('already-held');
		await shutdown(served);
		storage.close();
	});

	it('registers a mid-journal node at its retained base, not at sequence 1', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		// A node that journaled for a while BEFORE enabling guardians: the
		// retained base is where its log actually starts (wire 4.1).
		const { storage } = journaledStorage(4);
		const frames = storage.loadRecoveryFrames();
		const base = frames[0];
		expect(base.sequence).to.be.greaterThan(0);

		const rep = replicator(storage, bind(served));
		expect((await rep.ensureNamespace()).outcome).to.equal('registered');

		const head = await served[0].client.getHead(ROOT.recoveryId);
		const state = head.state as GuardianState;
		expect(state.origin.firstSequence).to.equal(BigInt(base.sequence));
		expect(state.origin.previousHash.equals(base.previousFrameHash)).to.equal(
			true
		);
		await shutdown(served);
		storage.close();
	});

	it('refuses to register when the namespace already exists remotely', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const first = journaledStorage(1);
		const firstRep = replicator(first.storage, bind(served));
		expect((await firstRep.ensureNamespace()).outcome).to.equal('registered');

		// A SECOND device with the same seed but no local lease must not
		// register a second genesis over the live namespace.
		const second = journaledStorage(1);
		const events: IGuardianReplicationEvent[] = [];
		const secondRep = replicator(second.storage, bind(served), events);
		const decision = await secondRep.ensureNamespace();
		expect(decision.outcome).to.equal('exists-remotely');
		expect(events.some((e) => e.type === 'namespace:exists')).to.equal(true);
		expect(loadWriterLease(second.storage).state).to.equal('missing');
		await shutdown(served);
		first.storage.close();
		second.storage.close();
	});

	it('refuses to register without a read quorum', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		// Two guardians down leaves one answering: below the 2-of-3 read set,
		// so there is no fencing and no recency proof (spec 5.7 step 5).
		await served[1].server.close();
		await served[2].server.close();
		const { storage } = journaledStorage(1);
		const events: IGuardianReplicationEvent[] = [];
		const rep = replicator(storage, bind(served), events);
		const decision = await rep.ensureNamespace();
		expect(decision.outcome).to.equal('no-quorum');
		expect((decision as { responded: number }).responded).to.equal(1);
		expect(events.some((e) => e.type === 'namespace:no-quorum')).to.equal(true);
		expect(loadWriterLease(storage).state).to.equal('missing');

		await served[0].server.close();
		for (const entry of served) entry.guardian.close();
		storage.close();
	});
});

describe('Recovery phase 5: record replication', () => {
	it('replicates journal frames as records a quorum receipts', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage, manager } = journaledStorage(3);
		const events: IGuardianReplicationEvent[] = [];
		const rep = replicator(storage, bind(served), events);
		const decision = await rep.ensureNamespace();
		expect(decision.outcome).to.equal('registered');
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		const first = await rep.replicatePending(lease);
		expect(first.attempted).to.be.greaterThan(0);
		expect(first.durable).to.equal(first.attempted);
		expect(rep.replicatedThrough()).to.equal(first.replicatedThrough);
		expect(
			events.filter((e) => e.type === 'record:replicated').length
		).to.equal(first.durable);

		// The guardians hold exactly the journal, and their head matches the
		// journal tip.
		const page = await served[0].client.getState(ROOT.recoveryId, 0n);
		expect(page.records).to.have.length(first.attempted);
		const head = await served[0].client.getHead(ROOT.recoveryId);
		expect((head.state as GuardianState).logHead.sequence).to.equal(
			first.replicatedThrough
		);

		// A second pass with nothing new is a no-op.
		const idle = await rep.replicatePending(lease);
		expect(idle.attempted).to.equal(0);

		// New transitions replicate incrementally from the high-water mark.
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, 99).toString('hex'),
					preimage: Buffer.alloc(32, 99)
				}
			],
			outboundMessages: []
		});
		const next = await rep.replicatePending(lease);
		expect(next.attempted).to.equal(1);
		expect(next.durable).to.equal(1);
		expect(next.replicatedThrough > first.replicatedThrough).to.equal(true);
		await shutdown(served);
		storage.close();
	});

	it('keeps the high-water mark honest when the quorum is not reached', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(2);
		const rep = replicator(storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		// Two guardians down: records still reach one, which is not durable.
		await served[1].server.close();
		await served[2].server.close();
		const events: IGuardianReplicationEvent[] = [];
		const degraded = new GuardianReplicator({
			storage,
			guardians: bind(served),
			context: CONTEXT,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot: ROOT,
			clock,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		const result = await degraded.replicatePending(lease);
		expect(result.attempted).to.be.greaterThan(0);
		expect(result.durable).to.equal(0);
		// Durability is CLAIMED only where it was proven: the mark stays put.
		expect(result.replicatedThrough).to.equal(0n);
		expect(degraded.replicatedThrough()).to.equal(0n);
		expect(events.some((e) => e.type === 'record:under-replicated')).to.equal(
			true
		);

		await served[0].server.close();
		for (const entry of served) entry.guardian.close();
		storage.close();
	});

	it('reports ownership confirmation and being superseded', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(1);
		const rep = replicator(storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		const confirmed = await rep.confirmOwnership(lease);
		expect(confirmed.confirming).to.equal(3);
		expect(confirmed.superseded).to.equal(false);

		// Another device takes the epoch: this lease is now fenced, and the
		// startup gate must see that before touching any channel.
		const head = await served[0].client.getHead(ROOT.recoveryId);
		const state = head.state as GuardianState;
		const newWriter = generateWriterKey();
		for (const entry of served) {
			const acquired = await entry.client.acquireEpoch({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				expectedState: state,
				newEpoch: state.lease.epoch + 1n,
				newWriterPublicKey: newWriter.publicKey,
				...signAcquisition(
					SET_ID,
					state,
					state.lease.epoch + 1n,
					newWriter,
					ROOT.rootSecret
				)
			});
			expect(acquired.status).to.equal(GuardianStatus.OK);
		}
		const afterTakeover = await rep.confirmOwnership(lease);
		expect(afterTakeover.confirming).to.equal(0);
		expect(afterTakeover.superseded).to.equal(true);
		await shutdown(served);
		storage.close();
	});

	it('treats a superseded epoch as a terminal fenced outcome', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage, manager } = journaledStorage(1);
		const events: IGuardianReplicationEvent[] = [];
		const rep = replicator(storage, bind(served), events);
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');

		// Another device takes the epoch while this one is still RUNNING.
		// Startup confirmation cannot help here: only the replication path
		// can notice, and spec 5.6 makes a definitive epoch rejection a hard
		// freeze signal rather than a retryable error.
		const head = (await served[0].client.getHead(ROOT.recoveryId))
			.state as GuardianState;
		const newWriter = generateWriterKey();
		for (const entry of served) {
			await entry.client.acquireEpoch({
				protocolVersion: 1,
				guardianSetId: SET_ID,
				expectedState: head,
				newEpoch: head.lease.epoch + 1n,
				newWriterPublicKey: newWriter.publicKey,
				...signAcquisition(
					SET_ID,
					head,
					head.lease.epoch + 1n,
					newWriter,
					ROOT.rootSecret
				)
			});
		}

		manager.commit({
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
		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('fenced');
		expect(result.localEpoch).to.equal(lease.epoch);
		// The newer state is PROVEN through a signed head, not taken from the
		// rejection itself.
		expect(result.verifiedCurrentState).to.not.equal(undefined);
		expect((result.verifiedCurrentState as GuardianState).lease.epoch).to.equal(
			lease.epoch + 1n
		);
		expect(events.some((e) => e.type === 'writer:fenced')).to.equal(true);
		// Durability already proven is not retracted by the freeze.
		expect(result.replicatedThrough).to.equal(rep.replicatedThrough());
		await shutdown(served);
		storage.close();
	});

	it('signs records the guardian accepts under the lease key alone', async () => {
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(1);
		const rep = replicator(storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;
		const frame = storage.loadRecoveryFrames()[0];

		// The record carries the frame's own bytes and position.
		const record = rep.signRecord(frame, lease);
		expect(record.sequence).to.equal(BigInt(frame.sequence));
		expect(record.ciphertext.equals(frame.ciphertext)).to.equal(true);
		expect(record.frameHash.equals(frame.frameHash)).to.equal(true);
		expect((await served[0].client.putState(record)).status).to.equal(
			GuardianStatus.OK
		);

		// A record signed by anything other than the lease key is refused.
		const strangerKey = generateWriterKey();
		const impostor: IWriterLeaseKeys = {
			...lease,
			writerSecret: strangerKey.secret,
			writerPublicKey: strangerKey.publicKey
		};
		const forged = rep.signRecord(frame, impostor);
		expect((await served[1].client.putState(forged)).status).to.equal(
			GuardianStatus.ERR_BAD_SIGNATURE
		);
		await shutdown(served);
		storage.close();
	});
});
