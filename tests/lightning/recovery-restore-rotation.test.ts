/**
 * The restore driver follows a guardian-set rotation instead of advancing
 * the retired set (wire 5.9 step 5, 5.11; issue #714).
 *
 * A rotation is accepted by as few as ONE outgoing member, and the protocol
 * relies on a later client discovering that member's root-signed rotation
 * and following it. Before #714 the driver discarded the rotation on every
 * head it read and ignored ERR_SET_RETIRED while acquiring an epoch, so
 * with one of three outgoing guardians retired it acquired epoch 2 on the
 * other two and left the outgoing set split across generations. These
 * tests hold the driver to the acceptance list of the issue:
 *
 * - exactly one outgoing guardian retired: the restore reports the
 *   incoming set and sends NO epoch or state mutation to the other two;
 * - all three retired: the same structured outcome, never cas-exhausted;
 * - a retirement that commits after the boot decision said
 *   restore-required but before restore() runs, and one that commits
 *   between the head read and the takeover request (ERR_SET_RETIRED);
 * - invalid evidence (bad signature, wrong set binding, non-increasing
 *   generation, malformed object) cannot fence a valid restore;
 * - the same outcome from evidence persisted across a guardian restart,
 *   and the replication client reads that evidence to the same verdict.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianStatus,
	IBoundGuardianClient,
	IGuardianGetHeadResponse,
	IGuardianRotateSetRequest,
	IRestoreEvent,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	RESTORE_META_KEYS,
	RestoreDriver,
	RestoreRefusedError,
	RestoreRotatedError,
	buildGuardianRecovery,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	loadWriterLease,
	rotateTranscriptHash,
	rotationEvidenceProblem,
	signTranscript,
	verifyGuardianRotation,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3, 4].map((i) =>
	sha(`p714-restore-guardian-${i}`)
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
const CONTEXT = { guardianSetId: OLD_SET, members: OLD_MEMBERS };
const NODE_SECRET = sha('p714-restore-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const OTHER_ROOT = deriveRecoveryRoot(sha('p714-other-node-secret'));
const NODE_ID = getPublicKey(NODE_SECRET);
const NEW_TRANSPORTS = NEW_MEMBERS.map((m) => ({
	type: 'https',
	url: `https://${m.toString('hex').slice(0, 8)}.example`
}));

let now = 2_100_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	client: GuardianClient;
	id: Buffer;
	url: string;
}

function bind(served: IServed[]): IBoundGuardianClient[] {
	return served.map((entry) => ({
		client: entry.client,
		expectedGuardianId: entry.id
	}));
}

async function serve(index: number, file = ':memory:'): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: file,
		guardianSecret: GUARDIAN_SECRETS[index],
		members: OLD_MEMBERS,
		clock
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	const url = `http://127.0.0.1:${port}`;
	return {
		guardian,
		server,
		id: GUARDIAN_IDS[index],
		url,
		client: new GuardianClient({ url, guardianSetId: OLD_SET })
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
	target: SqliteStorage,
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

/** A root-signed rotation of the outgoing set to the incoming one. */
function rotation(
	overrides: {
		generation?: bigint;
		guardianSetId?: Buffer;
		signer?: typeof ROOT;
		newMembers?: Buffer[];
		newGuardianSetId?: Buffer;
	} = {}
): IGuardianRotateSetRequest {
	const setId = overrides.guardianSetId ?? OLD_SET;
	const fields = {
		recoveryId: ROOT.recoveryId,
		newGuardianSetId: overrides.newGuardianSetId ?? NEW_SET,
		generation: overrides.generation ?? 2n,
		newMembers: overrides.newMembers ?? NEW_MEMBERS
	};
	return {
		protocolVersion: 1,
		guardianSetId: setId,
		...fields,
		rootSignature: signTranscript(
			rotateTranscriptHash(setId, fields),
			(overrides.signer ?? ROOT).rootSecret
		),
		newTransports: NEW_TRANSPORTS
	};
}

/** Register the namespace on the outgoing set and replicate a short journal. */
async function seed(served: IServed[]): Promise<{
	live: { storage: SqliteStorage; manager: RecoveryManager };
	lease: IWriterLeaseKeys;
}> {
	const live = liveNode(3);
	const rep = replicatorFor(live.storage, bind(served));
	const decision = await rep.ensureNamespace();
	expect(decision.outcome).to.equal('registered');
	const lease = (decision as { lease: IWriterLeaseKeys }).lease;
	const pass = await rep.replicatePending(lease);
	expect(pass.outcome).to.equal('replicated');
	return { live, lease };
}

function retire(entry: IServed, request = rotation()): void {
	const answer = entry.guardian.rotateSet(request);
	expect(answer.status, answer.detail).to.equal(GuardianStatus.OK);
}

/** Every outgoing guardian's head, straight from its store. */
function heads(served: IServed[]): IGuardianGetHeadResponse[] {
	return served.map((entry) =>
		entry.guardian.getHead({
			protocolVersion: 1,
			guardianSetId: OLD_SET,
			recoveryId: ROOT.recoveryId
		})
	);
}

function snapshot(served: IServed[]): string[] {
	return heads(served).map((head) =>
		JSON.stringify({
			status: head.status,
			epoch: head.state?.lease.epoch.toString(),
			writer: head.state?.lease.writerPublicKey.toString('hex'),
			sequence: head.state?.logHead.sequence.toString(),
			certificates: head.certificates?.length ?? 0,
			generation: head.generation?.toString(),
			rotated: head.rotation !== undefined
		})
	);
}

async function expectRotated(
	run: Promise<unknown>
): Promise<RestoreRotatedError> {
	let error: unknown;
	try {
		await run;
	} catch (err) {
		error = err;
	}
	expect(error, 'the restore must refuse').to.be.instanceOf(
		RestoreRotatedError
	);
	const rotated = error as RestoreRotatedError;
	expect(rotated.reason).to.equal('rotated');
	expect(rotated.generation).to.equal(2n);
	expect(rotated.rotation.newGuardianSetId.equals(NEW_SET)).to.equal(true);
	expect(rotated.entries).to.deep.equal(
		NEW_MEMBERS.map((m, i) => ({
			guardianId: m.toString('hex'),
			url: NEW_TRANSPORTS[i].url
		}))
	);
	return rotated;
}

/** The mutations a restore would leave behind, none of which may exist. */
function expectUntouched(
	served: IServed[],
	before: string[],
	target: SqliteStorage,
	events: IRestoreEvent[]
): void {
	expect(snapshot(served)).to.deep.equal(before);
	for (const head of heads(served)) {
		expect(head.state!.lease.epoch).to.equal(1n);
		expect(head.certificates ?? []).to.deep.equal([]);
	}
	expect(events.map((e) => e.type)).to.not.include.members([
		'epoch:acquired',
		'epoch:cas-retry',
		'guardian:repaired',
		'head:adopted',
		'frames:downloaded'
	]);
	expect(events.map((e) => e.type)).to.include('set:rotated');
	expect(target.getRecoveryMeta(RESTORE_META_KEYS.pendingAcquisition)).to.equal(
		null
	);
	expect(loadWriterLease(target).state).to.equal('missing');
	expect(target.loadRecoveryFrames()).to.deep.equal([]);
}

describe('Restore follows a guardian rotation (#714)', () => {
	it('with exactly one of three outgoing guardians retired, reports the incoming set and mutates nothing on the other two', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { live } = await seed(served);
		try {
			// One accepted retirement is the whole protocol's acceptance
			// case (wire 5.9 step 5): guardians 2 and 3 never heard of it.
			retire(served[0]);
			const before = snapshot(served);
			expect(heads(served).map((h) => h.rotation !== undefined)).to.deep.equal([
				true,
				false,
				false
			]);

			const events: IRestoreEvent[] = [];
			const target = openStorage();
			await expectRotated(driverFor(target, bind(served), events).restore());
			// The outgoing epochs stay [1, 1, 1]: no takeover reached the two
			// guardians that would have granted one.
			expectUntouched(served, before, target, events);
			target.close();
		} finally {
			await shutdown(served);
			live.storage.close();
		}
	});

	it('with every outgoing guardian retired, reports the rotation, not cas-exhausted', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { live } = await seed(served);
		try {
			for (const entry of served) retire(entry);
			const before = snapshot(served);
			const events: IRestoreEvent[] = [];
			const target = openStorage();
			const error = await expectRotated(
				driverFor(target, bind(served), events).restore()
			);
			expect(error).to.be.instanceOf(RestoreRefusedError);
			expect(error.reason).to.not.equal('cas-exhausted');
			expectUntouched(served, before, target, events);
			target.close();
		} finally {
			await shutdown(served);
			live.storage.close();
		}
	});

	it('covers a retirement that commits after restore-required but before restore()', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { live } = await seed(served);
		const target = openStorage();
		try {
			// The boot decision on the outgoing set, made BEFORE the rotation.
			const decision = await buildGuardianRecovery({
				storage: target,
				nodeSecret: NODE_SECRET,
				durability: 'quorum',
				guardians: served.map((entry) => ({
					guardianId: entry.id,
					url: entry.url
				})),
				clock
			});
			expect(decision.kind).to.equal('restore-required');
			if (decision.kind !== 'restore-required') return;

			// The writer's rotation lands on one outgoing member in between.
			retire(served[2]);
			const before = snapshot(served);

			const events: IRestoreEvent[] = [];
			await expectRotated(
				decision.buildRestoreDriver((event) => events.push(event)).restore()
			);
			expectUntouched(served, before, target, events);
		} finally {
			target.close();
			await shutdown(served);
			live.storage.close();
		}
	});

	it('re-reads and verifies the rotation when ACQUIRE_EPOCH answers ERR_SET_RETIRED, instead of outvoting it', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { live } = await seed(served);
		const target = openStorage();
		try {
			// The retirement commits AFTER the head read and BEFORE the
			// takeover request reaches guardian 1: the head read saw no
			// rotation, and guardian 1 answers the acquisition ERR_SET_RETIRED
			// while guardians 2 and 3 grant it. Before #714 those two were a
			// quorum and the restore completed on the retired set.
			const client = served[0].client;
			const acquire = client.acquireEpoch.bind(client);
			let landed = false;
			client.acquireEpoch = async (request): ReturnType<typeof acquire> => {
				if (!landed) {
					landed = true;
					retire(served[0]);
				}
				return acquire(request);
			};
			const events: IRestoreEvent[] = [];
			await expectRotated(driverFor(target, bind(served), events).restore());
			expect(landed).to.equal(true);
			expect(events.map((e) => e.type)).to.not.include.members([
				'epoch:acquired',
				'frames:downloaded',
				'restore:complete'
			]);
			// Nothing was installed on the target: no lease, no frames, and
			// the attempt bound to the retired set is not kept for a resume
			// against the incoming one.
			expect(loadWriterLease(target).state).to.equal('missing');
			expect(target.loadRecoveryFrames()).to.deep.equal([]);
			expect(
				target.getRecoveryMeta(RESTORE_META_KEYS.pendingAcquisition)
			).to.equal(null);
		} finally {
			target.close();
			await shutdown(served);
			live.storage.close();
		}
	});

	it('invalid rotation evidence cannot fence a valid restore', async function (): Promise<void> {
		this.timeout(40_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const { live, lease } = await seed(served);
		try {
			const forged = (
				name: string,
				value: IGuardianRotateSetRequest
			): { name: string; value: IGuardianRotateSetRequest } => ({
				name,
				value
			});
			const variants = [
				forged('signed by another root', rotation({ signer: OTHER_ROOT })),
				forged(
					'bound to another outgoing set',
					rotation({ guardianSetId: NEW_SET })
				),
				forged('at a non-increasing generation', rotation({ generation: 1n })),
				forged(
					'naming members that do not hash to the incoming set id',
					rotation({ newGuardianSetId: sha('not the members hash') })
				),
				forged('with a malformed member list', {
					...rotation(),
					newMembers: NEW_MEMBERS.slice(0, 2)
				}),
				forged('with a malformed signature', {
					...rotation(),
					rootSignature: Buffer.alloc(10, 7)
				}),
				forged('that is not an object at all', {
					...rotation(),
					newMembers: 'not-a-list' as unknown as Buffer[]
				})
			];
			// Every guardian attaches the forgery to every head it serves; a
			// driver that believed any of them would refuse a restore that is
			// entirely valid. Each restore succeeds and takes the next epoch,
			// so the guardians themselves are never touched by the forgeries.
			let epoch = lease.epoch;
			for (const variant of variants) {
				const restores: Array<() => void> = [];
				for (const entry of served) {
					const client = entry.client;
					const getHead = client.getHead.bind(client);
					client.getHead = async (
						recoveryId: Buffer
					): Promise<IGuardianGetHeadResponse> => ({
						...(await getHead(recoveryId)),
						rotation: variant.value
					});
					restores.push(() => {
						client.getHead = getHead;
					});
				}
				const target = openStorage();
				const events: IRestoreEvent[] = [];
				try {
					const result = await driverFor(
						target,
						bind(served),
						events
					).restore();
					expect(result.lease.epoch, variant.name).to.equal(epoch + 1n);
					epoch = result.lease.epoch;
					expect(
						events.map((e) => e.type),
						variant.name
					).to.not.include('set:rotated');
				} finally {
					for (const restore of restores) restore();
					target.close();
				}
			}
		} finally {
			await shutdown(served);
			live.storage.close();
		}
	});

	it('gives the same result from evidence persisted across a guardian restart, and the replication client agrees', async function (): Promise<void> {
		this.timeout(20_000);
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-p714-'));
		const files = [0, 1, 2].map((i) => path.join(dir, `guardian-${i}.sqlite`));
		let served = await Promise.all(files.map((file, i) => serve(i, file)));
		const { live } = await seed(served);
		try {
			retire(served[1]);
			const before = snapshot(served);
			// Every guardian restarts from its file; the marker is what the
			// reopened guardian validates (wire 5.11) and serves.
			await shutdown(served);
			served = await Promise.all(files.map((file, i) => serve(i, file)));
			expect(snapshot(served)).to.deep.equal(before);

			const events: IRestoreEvent[] = [];
			const target = openStorage();
			await expectRotated(driverFor(target, bind(served), events).restore());
			expectUntouched(served, before, target, events);

			// The replication client's boot decision reads the same evidence
			// through the same judgement, to the same generation.
			const rep = replicatorFor(target, bind(served));
			const decision = await rep.ensureNamespace();
			expect(decision.outcome).to.equal('rotated');
			expect(
				(decision as { rotation: IGuardianRotateSetRequest }).rotation
					.generation
			).to.equal(2n);
			expect(snapshot(served)).to.deep.equal(before);
			target.close();
		} finally {
			await shutdown(served);
			live.storage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe('Rotation evidence: one judgement for guardian, replicator and restore (#714)', () => {
	const binding = {
		guardianSetId: OLD_SET,
		recoveryId: ROOT.recoveryId,
		generation: 1n
	};

	it('accepts a rotation that binds, hashes, increases and verifies', () => {
		expect(rotationEvidenceProblem(rotation(), binding)).to.equal(null);
		expect(
			verifyGuardianRotation(
				{ rotation: rotation(), generation: 1n },
				CONTEXT,
				ROOT.recoveryId,
				1n
			)
		).to.not.equal(null);
	});

	it('names the first rule each forgery breaks', () => {
		const cases: Array<[string, IGuardianRotateSetRequest, RegExp]> = [
			[
				'another outgoing set',
				rotation({ guardianSetId: NEW_SET }),
				/another guardian set/
			],
			[
				'another root',
				rotation({ signer: OTHER_ROOT }),
				/root signature failed/
			],
			[
				'a non-increasing generation',
				rotation({ generation: 1n }),
				/does not exceed/
			],
			[
				'members that do not hash',
				rotation({ newGuardianSetId: sha('x') }),
				/do not hash/
			],
			[
				'this set as the incoming set',
				rotation({ newMembers: OLD_MEMBERS, newGuardianSetId: OLD_SET }),
				/names this set/
			],
			[
				'a short member list',
				{ ...rotation(), newMembers: NEW_MEMBERS.slice(0, 2) },
				/new_members malformed/
			],
			[
				'a short signature',
				{ ...rotation(), rootSignature: Buffer.alloc(3) },
				/root signature failed/
			]
		];
		for (const [name, value, problem] of cases) {
			expect(rotationEvidenceProblem(value, binding), name).to.match(problem);
			expect(
				verifyGuardianRotation(
					{ rotation: value },
					CONTEXT,
					ROOT.recoveryId,
					1n
				),
				name
			).to.equal(null);
		}
		expect(
			rotationEvidenceProblem(
				null as unknown as IGuardianRotateSetRequest,
				binding
			)
		).to.match(/not an object/);
	});

	it("raises the floor to the answer's own generation and to the caller's", () => {
		const evidence = rotation({ generation: 2n });
		// A guardian reporting generation 2 beside a rotation at 2 contradicts
		// itself; a caller already at generation 2 has nothing to follow.
		expect(
			verifyGuardianRotation(
				{ rotation: evidence, generation: 2n },
				CONTEXT,
				ROOT.recoveryId,
				1n
			)
		).to.equal(null);
		expect(
			verifyGuardianRotation(
				{ rotation: evidence },
				CONTEXT,
				ROOT.recoveryId,
				2n
			)
		).to.equal(null);
		expect(
			verifyGuardianRotation(
				{ rotation: evidence, generation: 1n },
				CONTEXT,
				ROOT.recoveryId,
				1n
			)
		).to.not.equal(null);
		expect(
			verifyGuardianRotation(undefined, CONTEXT, ROOT.recoveryId, 1n)
		).to.equal(null);
	});
});
