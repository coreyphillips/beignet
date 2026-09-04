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
	GuardianTransportError,
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
	genesisLogHead,
	generateWriterKey,
	REPLICATION_META_KEYS,
	decodeGetHeadResponse,
	encodeGetHeadResponse,
	loadWriterLease,
	nodeGuardianTransport,
	registerTranscriptHash,
	signAcquisition,
	signTranscript,
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
	it('registers only when a quorum reports the namespace unknown', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('registers a mid-journal node at its retained base, not at sequence 1', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('refuses to register when the namespace already exists remotely', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('resumes a partial registration with the SAME writer key', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(1);

		// G1 accepts the registration; G2 and G3 lose it. Generating a fresh
		// key on the next attempt would leave this device permanently unable
		// to write under the genesis lease G1 already granted, because only a
		// byte-identical REGISTER_NODE is idempotent (wire 5.1).
		let blockRegister = true;
		const flaky = (index: number): IBoundGuardianClient => ({
			expectedGuardianId: served[index].id,
			client: new GuardianClient({
				url: served[index].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					if (blockRegister && url.endsWith('/register_node')) {
						throw new GuardianTransportError('registration lost in transit');
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

		const first = await replicator(storage, guardians).ensureNamespace();
		expect(first.outcome).to.equal('inconsistent');
		// No lease was written, but the attempt and its key were remembered.
		expect(loadWriterLease(storage).state).to.equal('missing');
		const pendingRaw = storage.getRecoveryMeta!(
			REPLICATION_META_KEYS.pendingRegistration
		);
		expect(
			pendingRaw,
			'the registration was persisted before it was sent'
		).to.not.equal(null);
		const pending = JSON.parse(pendingRaw as string) as {
			writerPublicKey: string;
		};
		const g1 = (await served[0].client.getHead(ROOT.recoveryId))
			.state as GuardianState;
		expect(g1.lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);

		// A NEW replicator resumes once registration works again: same key,
		// G1 answers OK_DUPLICATE, the quorum forms, epoch stays 1.
		blockRegister = false;
		const second = await replicator(storage, guardians).ensureNamespace();
		expect(second.outcome).to.equal('registered');
		const lease = (second as { lease: IWriterLeaseKeys }).lease;
		expect(lease.epoch).to.equal(1n);
		expect(lease.writerPublicKey.toString('hex')).to.equal(
			pending.writerPublicKey
		);
		// The pending record retires with the lease, in one transaction.
		expect(
			storage.getRecoveryMeta!(REPLICATION_META_KEYS.pendingRegistration)
		).to.equal(null);
		for (const entry of served) {
			const head = (await entry.client.getHead(ROOT.recoveryId))
				.state as GuardianState;
			expect(head.lease.writerPublicKey.equals(lease.writerPublicKey)).to.equal(
				true
			);
		}
		await shutdown(served);
		storage.close();
	});

	it('lets a possibly-stale holder veto a fresh registration', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const first = journaledStorage(1);
		// G1 alone holds the namespace, and it reports possibly_stale: it
		// cannot tell anyone what is CURRENT, but its signed state still
		// proves the namespace is not free.
		const initialState: GuardianState = {
			recoveryId: ROOT.recoveryId,
			lease: { epoch: 1n, writerPublicKey: generateWriterKey().publicKey },
			origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
			logHead: genesisLogHead()
		};
		expect(
			(
				await served[0].client.register({
					protocolVersion: 1,
					guardianSetId: SET_ID,
					guardianMembers: GUARDIAN_IDS,
					initialState,
					rootSignature: signTranscript(
						registerTranscriptHash(SET_ID, initialState),
						ROOT.rootSecret
					)
				})
			).status
		).to.equal(GuardianStatus.OK);

		// G1 confesses an uncertain store while keeping its signed state and
		// receipt; G2 and G3 never saw the namespace. Without the existence
		// veto, those two unknowns would form a quorum and authorize a SECOND
		// GENESIS over a namespace that already exists.
		const staleG1: IBoundGuardianClient = {
			expectedGuardianId: served[0].id,
			client: new GuardianClient({
				url: served[0].client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					const response = await nodeGuardianTransport()(url, init);
					if (!url.endsWith('/get_head')) return response;
					const decoded = decodeGetHeadResponse(response.body);
					return {
						status: response.status,
						body: encodeGetHeadResponse({ ...decoded, possiblyStale: true })
					};
				}
			})
		};
		const guardians: IBoundGuardianClient[] = [
			staleG1,
			{ expectedGuardianId: served[1].id, client: served[1].client },
			{ expectedGuardianId: served[2].id, client: served[2].client }
		];

		const second = journaledStorage(1);
		const decision = await replicator(
			second.storage,
			guardians
		).ensureNamespace();
		expect(decision.outcome).to.equal('exists-remotely');
		expect(loadWriterLease(second.storage).state).to.equal('missing');
		// And nobody re-registered it: G2 still knows nothing.
		expect((await served[1].client.getHead(ROOT.recoveryId)).status).to.equal(
			GuardianStatus.ERR_UNKNOWN_NODE
		);
		await shutdown(served);
		first.storage.close();
		second.storage.close();
	});

	it('refuses to register without a read quorum', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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
	it('replicates journal frames as records a quorum receipts', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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
		// Phase 6: receipts are cumulative, so a pass reports the HEAD it made
		// durable ONCE rather than one event per frame. A per-frame event would
		// imply a per-frame round trip, which is exactly what pipelined appends
		// exist to avoid (spec 5.3).
		const durableEvents = events.filter((e) => e.type === 'record:replicated');
		expect(durableEvents.length).to.equal(1);
		expect(durableEvents[0].sequence).to.equal(first.replicatedThrough);

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

	it('keeps the high-water mark honest when the quorum is not reached', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('reports ownership confirmation and being superseded', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('treats a superseded epoch as a terminal fenced outcome', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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

	it('never counts a receipt that does not cover the state beside it', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { storage } = journaledStorage(1);
		const rep = replicator(storage, bind(served));
		const decision = await rep.ensureNamespace();
		const lease = (decision as { lease: IWriterLeaseKeys }).lease;

		// A guardian answers with a VALID receipt over state A while the
		// response body carries a different state B. B is signed by nobody,
		// so it must not confirm anything: the startup gate releases peer
		// connections on this answer.
		const honest = await served[0].client.getHead(ROOT.recoveryId);
		const forgedState: GuardianState = {
			...(honest.state as GuardianState),
			lease: {
				epoch: (honest.state as GuardianState).lease.epoch,
				writerPublicKey: generateWriterKey().publicKey
			}
		};
		const lying: IBoundGuardianClient[] = served.map((entry) => ({
			expectedGuardianId: entry.id,
			client: new GuardianClient({
				url: entry.client.url,
				guardianSetId: SET_ID,
				transport: async (
					url,
					init
				): Promise<{ status: number; body: Buffer }> => {
					const response = await nodeGuardianTransport()(url, init);
					if (!url.endsWith('/get_head')) return response;
					const decoded = decodeGetHeadResponse(response.body);
					// Keep the real receipt; swap the accompanying state.
					return {
						status: response.status,
						body: encodeGetHeadResponse({ ...decoded, state: forgedState })
					};
				}
			})
		}));
		const confirmed = await replicator(storage, lying).confirmOwnership({
			...lease,
			writerPublicKey: forgedState.lease.writerPublicKey
		});
		expect(confirmed.confirming).to.equal(0);
		await shutdown(served);
		storage.close();
	});

	it('signs records the guardian accepts under the lease key alone', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
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
