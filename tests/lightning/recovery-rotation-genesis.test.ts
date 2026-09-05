/**
 * Following a rotation never registers a fresh genesis (issue #722).
 *
 * A rotation's writer registers the incoming set before it retires the
 * outgoing one, so the incoming set always holds the namespace by the time
 * a follower reaches it. An incoming set that answers unknown-namespace
 * anyway is a guardian-side fault (the registration never landed, or the
 * rotation named the wrong set), and before this fix the boot follow loop
 * treated it as first setup: it registered an empty history on the set that
 * was supposed to hold the migrated one. Now a set reached by following a
 * rotation is decided with `following: true`, a quorum of unknowns there is
 * `unavailable` / `rotation-target-empty`, and nothing is registered.
 *
 * Cases:
 *  - the incoming set is fresh: refused, nothing registered, the guardians
 *    still answer unknown afterwards;
 *  - the same set decided as a first-boot set (no rotation followed) still
 *    registers, so the flag is what changes the answer;
 *  - an incoming set that does hold the namespace is told to restore, so
 *    `following` blocks only the genesis, never the takeover;
 *  - at the replicator, `allowGenesis: false` answers `not-held` with its
 *    event, and `exists-remotely` is untouched by it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianStatus,
	IBoundGuardianClient,
	IGuardianReplicationEvent,
	IGuardianRotateSetRequest,
	IParsedGuardian,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	buildGuardianRecovery,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	loadWriterLease,
	rotateTranscriptHash,
	signTranscript,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3, 4].map((i) =>
	sha(`p722-genesis-guardian-${i}`)
);
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
/** The outgoing set: guardians 1, 2, 3. The incoming set: 2, 3, 4. */
const OLD_MEMBERS = [GUARDIAN_IDS[0], GUARDIAN_IDS[1], GUARDIAN_IDS[2]];
const NEW_MEMBERS = [GUARDIAN_IDS[1], GUARDIAN_IDS[2], GUARDIAN_IDS[3]];
const OLD_SET = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: OLD_MEMBERS
});
const NEW_SET = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: NEW_MEMBERS
});
const OLD_CONTEXT = { guardianSetId: OLD_SET, members: OLD_MEMBERS };
const NEW_CONTEXT = { guardianSetId: NEW_SET, members: NEW_MEMBERS };
const NODE_SECRET = sha('p722-genesis-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

let now = 2_300_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	id: Buffer;
	url: string;
}

async function serve(index: number, members: Buffer[]): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members,
		clock
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	return {
		guardian,
		server,
		id: GUARDIAN_IDS[index],
		url: `http://127.0.0.1:${port}`
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

function bind(served: IServed[], setId: Buffer): IBoundGuardianClient[] {
	return served.map((entry) => ({
		client: new GuardianClient({ url: entry.url, guardianSetId: setId }),
		expectedGuardianId: entry.id
	}));
}

function parsed(served: IServed[]): IParsedGuardian[] {
	return served.map((entry) => ({ guardianId: entry.id, url: entry.url }));
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

/** A live writer with a short journal, on `storage`. */
function liveNode(
	storage: SqliteStorage,
	transitions: number
): RecoveryManager {
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
					}
				],
				outboundMessages: []
			}).committed
		).to.equal(true);
	}
	return manager;
}

/** Register the namespace on `served` (under `context`) from a live writer. */
async function seed(
	served: IServed[],
	context: { guardianSetId: Buffer; members: Buffer[] },
	generationOverride?: bigint,
	events: IGuardianReplicationEvent[] = []
): Promise<SqliteStorage> {
	const storage = openStorage();
	liveNode(storage, 2);
	const rep = new GuardianReplicator({
		storage,
		guardians: bind(served, context.guardianSetId),
		context,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock,
		onEvent: (event): void => {
			events.push(event);
		},
		generationOverride
	});
	const decision = await rep.ensureNamespace();
	expect(decision.outcome).to.equal('registered');
	if (decision.outcome !== 'registered') throw new Error('unreachable');
	const pass = await rep.replicatePending(decision.lease);
	expect(pass.outcome).to.equal('replicated');
	return storage;
}

/** A root-signed rotation of the outgoing set to the served incoming one. */
function rotation(incoming: IServed[]): IGuardianRotateSetRequest {
	const fields = {
		recoveryId: ROOT.recoveryId,
		newGuardianSetId: NEW_SET,
		generation: 2n,
		newMembers: NEW_MEMBERS
	};
	return {
		protocolVersion: 1,
		guardianSetId: OLD_SET,
		...fields,
		rootSignature: signTranscript(
			rotateTranscriptHash(OLD_SET, fields),
			ROOT.rootSecret
		),
		newTransports: incoming.map((entry) => ({
			type: 'local-http',
			url: entry.url
		}))
	};
}

function retire(entry: IServed, request: IGuardianRotateSetRequest): void {
	const answer = entry.guardian.rotateSet(request);
	expect(answer.status, answer.detail).to.equal(GuardianStatus.OK);
}

/** What the incoming guardians say about the namespace, straight from store. */
function incomingHeads(incoming: IServed[]): GuardianStatus[] {
	return incoming.map(
		(entry) =>
			entry.guardian.getHead({
				protocolVersion: 1,
				guardianSetId: NEW_SET,
				recoveryId: ROOT.recoveryId
			}).status
	);
}

describe('Following a rotation never registers a fresh genesis (issue #722)', () => {
	it('an incoming set that holds nothing is refused as rotation-target-empty, and stays empty', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all([
			serve(0, OLD_MEMBERS),
			serve(1, OLD_MEMBERS),
			serve(2, OLD_MEMBERS)
		]);
		// The incoming set never received the writer's registration: three
		// fresh guardians that know the set and nothing else.
		const incoming = await Promise.all([
			serve(1, NEW_MEMBERS),
			serve(2, NEW_MEMBERS),
			serve(3, NEW_MEMBERS)
		]);
		const live = await seed(outgoing, OLD_CONTEXT);
		const target = openStorage();
		try {
			for (const entry of outgoing) retire(entry, rotation(incoming));

			// Hop 1: the outgoing set hands over the rotation.
			const first = await buildGuardianRecovery({
				storage: target,
				nodeSecret: NODE_SECRET,
				durability: 'quorum',
				guardians: parsed(outgoing),
				clock
			});
			expect(first.kind).to.equal('rotated');
			if (first.kind !== 'rotated') return;
			expect(first.entries.map((e) => e.guardianId)).to.deep.equal(
				NEW_MEMBERS.map((m) => m.toString('hex'))
			);

			// Hop 2, as the boot loop does it: the followed set is decided
			// with `following: true`.
			const followed: IParsedGuardian[] = first.entries.map((entry) => ({
				guardianId: Buffer.from(entry.guardianId, 'hex'),
				url: entry.url!
			}));
			expect(incomingHeads(incoming)).to.deep.equal([
				GuardianStatus.ERR_UNKNOWN_NODE,
				GuardianStatus.ERR_UNKNOWN_NODE,
				GuardianStatus.ERR_UNKNOWN_NODE
			]);
			const second = await buildGuardianRecovery({
				storage: target,
				nodeSecret: NODE_SECRET,
				durability: 'quorum',
				guardians: followed,
				clock,
				following: true
			});
			expect(second.kind).to.equal('unavailable');
			if (second.kind !== 'unavailable') return;
			expect(second.outcome).to.equal('rotation-target-empty');
			expect(second.detail).to.match(/following a rotation/);

			// Nothing was registered: the incoming guardians still answer
			// unknown, and the device holds no lease it could write under.
			expect(incomingHeads(incoming)).to.deep.equal([
				GuardianStatus.ERR_UNKNOWN_NODE,
				GuardianStatus.ERR_UNKNOWN_NODE,
				GuardianStatus.ERR_UNKNOWN_NODE
			]);
			expect(loadWriterLease(target).state).to.equal('missing');

			// The contrast: the SAME set decided as a first-boot set (no
			// rotation followed) is first setup and registers. The flag is
			// what distinguishes the two, which is why the follow loop must
			// set it on every hop.
			const asFirstBoot = await buildGuardianRecovery({
				storage: target,
				nodeSecret: NODE_SECRET,
				durability: 'quorum',
				guardians: followed,
				clock
			});
			expect(asFirstBoot.kind).to.equal('run');
			expect(incomingHeads(incoming)).to.deep.equal([
				GuardianStatus.OK,
				GuardianStatus.OK,
				GuardianStatus.OK
			]);
		} finally {
			target.close();
			live.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('an incoming set that holds the namespace is told to restore: following blocks only the genesis', async function (): Promise<void> {
		this.timeout(20_000);
		const incoming = await Promise.all([
			serve(1, NEW_MEMBERS),
			serve(2, NEW_MEMBERS),
			serve(3, NEW_MEMBERS)
		]);
		// The writer's rotation registered the incoming set at generation 2
		// before retiring the outgoing one (wire 5.9), so a follower finds
		// the namespace there.
		const live = await seed(incoming, NEW_CONTEXT, 2n);
		const target = openStorage();
		try {
			const decision = await buildGuardianRecovery({
				storage: target,
				nodeSecret: NODE_SECRET,
				durability: 'quorum',
				guardians: parsed(incoming),
				clock,
				following: true
			});
			expect(decision.kind).to.equal('restore-required');
			expect(loadWriterLease(target).state).to.equal('missing');
		} finally {
			target.close();
			live.close();
			await shutdown(incoming);
		}
	});

	it('at the replicator, allowGenesis: false answers not-held with its event and leaves exists-remotely alone', async function (): Promise<void> {
		this.timeout(20_000);
		const fresh = await Promise.all([
			serve(1, NEW_MEMBERS),
			serve(2, NEW_MEMBERS),
			serve(3, NEW_MEMBERS)
		]);
		const held = await Promise.all([
			serve(0, OLD_MEMBERS),
			serve(1, OLD_MEMBERS),
			serve(2, OLD_MEMBERS)
		]);
		const live = await seed(held, OLD_CONTEXT);
		const target = openStorage();
		const events: IGuardianReplicationEvent[] = [];
		const replicatorFor = (
			served: IServed[],
			context: { guardianSetId: Buffer; members: Buffer[] }
		): GuardianReplicator =>
			new GuardianReplicator({
				storage: target,
				guardians: bind(served, context.guardianSetId),
				context,
				required: CRASH_V1_PROFILE.required,
				recoveryRoot: ROOT,
				clock,
				onEvent: (event): void => {
					events.push(event);
				}
			});
		try {
			const refused = await replicatorFor(fresh, NEW_CONTEXT).ensureNamespace({
				allowGenesis: false
			});
			expect(refused.outcome).to.equal('not-held');
			expect(events.map((e) => e.type)).to.include('namespace:not-held');
			expect(events.map((e) => e.type)).to.not.include('namespace:registered');
			expect(incomingHeads(fresh)).to.deep.equal([
				GuardianStatus.ERR_UNKNOWN_NODE,
				GuardianStatus.ERR_UNKNOWN_NODE,
				GuardianStatus.ERR_UNKNOWN_NODE
			]);
			expect(loadWriterLease(target).state).to.equal('missing');

			const exists = await replicatorFor(held, OLD_CONTEXT).ensureNamespace({
				allowGenesis: false
			});
			expect(exists.outcome).to.equal('exists-remotely');

			// And the default still registers on a fresh set: first setup.
			const registered = await replicatorFor(
				fresh,
				NEW_CONTEXT
			).ensureNamespace();
			expect(registered.outcome).to.equal('registered');
		} finally {
			target.close();
			live.close();
			await shutdown(fresh);
			await shutdown(held);
		}
	});
});
