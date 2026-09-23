/**
 * A guardian-set rotation on a journal that has written nothing yet
 * (issue #862).
 *
 * An unused wallet has no frames, so the backfill has nothing to send and
 * the incoming set never records a watermark: "nothing receipted" is the
 * ABSENCE of the watermark keys, never a stored 0. Before this fix the
 * switch read that absence as a vanished watermark and refused every such
 * rotation, after the intent was already written; the journal's empty-store
 * guard then read the intent as residue of destroyed history and refused
 * every later write, so the wallet could never persist a channel again.
 *
 * Now the switch at genesis runs only after BOTH sets prove the namespace
 * head is genesis (a lost journal looks exactly like an unused one on
 * disk), and the rotation's metadata may precede the first frame.
 *
 * Cases:
 *  - A1: a genesis switch; the first frame then commits and replicates to
 *    the incoming set;
 *  - A2: a registration without a quorum keeps the intent (wire 5.9) and
 *    does not block the first frame;
 *  - A3: that intent resumes to a completed rotation;
 *  - A4: with frames, a watermark missing at the switch is still refused;
 *  - A5 and A6: an outgoing or incoming set that holds history this
 *    journal lost refuses as journal-behind, with no switch and no
 *    retirement;
 *  - A7: a torn incoming watermark over an empty journal is refused;
 *  - A8: a first frame committed while the rotation starts takes the
 *    normal switch;
 *  - A9: an outgoing set that cannot confirm the namespace is empty
 *    refuses the genesis switch.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianRotation,
	IParsedGuardian,
	IRotationEvent,
	IWriterLeaseKeys,
	REPLICATION_META_KEYS,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	RotationRefusedError,
	bindGuardianSet,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	readGeneration,
	readGuardianSet,
	readRetirePending,
	readRotationIntent,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3, 4].map((i) => sha(`p862-guardian-${i}`));
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
const NODE_SECRET = sha('p862-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

const PREFIX = 'rotation:2:';

let now = 2_486_200_000_000n;
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

/** Put the same guardian (and its store) back on the network, on a new port. */
async function reserve(entry: IServed): Promise<IServed> {
	const server = new GuardianHttpServer({ guardian: entry.guardian });
	const port = await server.listen(0);
	return { ...entry, server, url: `http://127.0.0.1:${port}` };
}

async function closeServers(served: IServed[]): Promise<void> {
	for (const entry of served) {
		try {
			await entry.server.close();
		} catch {
			// already closed by the test
		}
	}
}

async function shutdown(served: IServed[]): Promise<void> {
	await closeServers(served);
	for (const entry of served) entry.guardian.close();
}

function parsed(served: IServed[]): IParsedGuardian[] {
	return served.map((entry) => ({ guardianId: entry.id, url: entry.url }));
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function journaled(storage: SqliteStorage): RecoveryManager {
	const journal = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(NODE_SECRET),
		NODE_ID,
		ROOT.recoveryId
	);
	return new RecoveryManager(storage, { journal });
}

function commitOne(
	manager: RecoveryManager,
	fill: number
): ReturnType<RecoveryManager['commit']> {
	return manager.commit({
		criticality: RecoveryCriticality.SafetyCritical,
		mutations: [
			{
				type: 'payment_preimage',
				paymentHash: Buffer.alloc(32, fill).toString('hex'),
				preimage: Buffer.alloc(32, fill)
			}
		],
		outboundMessages: []
	});
}

function replicatorFor(
	storage: SqliteStorage,
	served: IServed[]
): GuardianReplicator {
	const { context, bound } = bindGuardianSet(parsed(served), {});
	return new GuardianReplicator({
		storage,
		guardians: bound,
		context,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock
	});
}

/** Register the namespace with `outgoing`, as a first boot does. */
async function registered(
	storage: SqliteStorage,
	outgoing: IServed[]
): Promise<{ lease: IWriterLeaseKeys; replicator: GuardianReplicator }> {
	const replicator = replicatorFor(storage, outgoing);
	const decision = await replicator.ensureNamespace();
	expect(decision.outcome).to.equal('registered');
	if (decision.outcome !== 'registered') throw new Error('unreachable');
	return { lease: decision.lease, replicator };
}

function rotationFor(
	storage: SqliteStorage,
	lease: IWriterLeaseKeys,
	outgoing: IServed[],
	incoming: IServed[],
	onEvent?: (event: IRotationEvent) => void
): GuardianRotation {
	const out = parsed(outgoing);
	const inc = parsed(incoming);
	return new GuardianRotation({
		storage,
		recoveryRoot: ROOT,
		lease,
		outgoing: { guardians: out, ...bindGuardianSet(out, {}) },
		incoming: { guardians: inc, ...bindGuardianSet(inc, {}) },
		required: CRASH_V1_PROFILE.required,
		clock,
		onEvent
	});
}

async function refusal(
	promise: Promise<unknown>
): Promise<RotationRefusedError> {
	try {
		await promise;
	} catch (error) {
		expect(error, String(error)).to.be.instanceOf(RotationRefusedError);
		return error as RotationRefusedError;
	}
	throw new Error('the rotation was expected to be refused, and it switched');
}

/** Everything but the lease, the epoch and (optionally) the intent: a lost journal. */
function loseJournal(storage: SqliteStorage, keepIntent: boolean): void {
	storage.deleteRecoveryFramesBelow!(Number.MAX_SAFE_INTEGER);
	const keep = new Set(['writer_lease_v1', 'journal_writer_epoch']);
	if (keepIntent) keep.add('guardian_rotation_pending_v1');
	for (const key of storage.listRecoveryMetaKeys!()) {
		if (!keep.has(key)) storage.deleteRecoveryMeta!(key);
	}
	expect(storage.loadRecoveryFrames!()).to.have.length(0);
}

/** What a set's guardians say straight from their stores. */
function heads(
	served: IServed[],
	setId: Buffer
): Array<{ sequence: bigint | null; rotated: boolean }> {
	return served.map((entry) => {
		const head = entry.guardian.getHead({
			protocolVersion: 1,
			guardianSetId: setId,
			recoveryId: ROOT.recoveryId
		});
		return {
			sequence: head.state ? head.state.logHead.sequence : null,
			rotated: head.rotation !== undefined
		};
	});
}

function watermarkKeys(storage: SqliteStorage): string[] {
	return storage.listRecoveryMetaKeys!()
		.filter(
			(key) =>
				key.startsWith('rotation:') ||
				key.startsWith(REPLICATION_META_KEYS.replicatedThrough)
		)
		.sort();
}

const hexOf = (ids: Buffer[]): string[] => ids.map((id) => id.toString('hex'));

describe('Guardian rotation on an empty journal (issue #862)', () => {
	it('A1: switches an unused wallet, and its first frame journals and replicates to the incoming set', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			const manager = journaled(storage);
			expect(storage.loadRecoveryFrames!()).to.have.length(0);

			const rotation = rotationFor(storage, lease, outgoing, incoming);
			const result = await rotation.rotate();
			expect(result.generation).to.equal(2n);
			expect(readRotationIntent(storage)).to.equal(null);
			expect(readGeneration(storage)).to.equal(2n);
			expect(readGuardianSet(storage)!.map((e) => e.guardianId)).to.deep.equal(
				hexOf(NEW_MEMBERS)
			);
			expect(readRetirePending(storage)).to.not.equal(null);
			// Nothing was receipted, so no watermark exists anywhere: the zero
			// watermark is absence, and a stored one over an empty store is
			// residue.
			expect(watermarkKeys(storage)).to.deep.equal([]);

			// Generation, set and the owed retirement all sit on a frame-less
			// store, and the first frame still commits.
			const first = commitOne(manager, 1);
			expect(first.committed, String(first.error?.message)).to.equal(true);

			expect(await rotation.retireOutgoing()).to.be.greaterThan(0);
			expect(readRetirePending(storage)).to.equal(null);
			expect(heads(outgoing, OLD_SET).every((h) => h.rotated)).to.equal(true);

			const pass = await result.replicator.replicatePending(lease);
			expect(pass.outcome).to.equal('replicated');
			expect(pass.replicatedThrough).to.equal(1n);
			expect(heads(incoming, NEW_SET).map((h) => h.sequence)).to.deep.equal([
				1n,
				1n,
				1n
			]);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A2: a rotation refused on an empty journal stays pending without blocking the first frame', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			const manager = journaled(storage);
			// The incoming set is gone: its ports refuse.
			await closeServers(incoming);
			const refused = await refusal(
				rotationFor(storage, lease, outgoing, incoming).rotate()
			);
			expect(refused.reason).to.equal('no-quorum');
			// Kept by design (wire 5.9): a restart resumes it.
			expect(readRotationIntent(storage)).to.not.equal(null);
			expect(readGeneration(storage)).to.equal(1n);

			const first = commitOne(manager, 2);
			expect(first.committed, String(first.error?.message)).to.equal(true);
			expect(storage.loadRecoveryFrames!()).to.have.length(1);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A3: a rotation refused on an empty journal resumes to completion', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const offline = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		let incoming = offline;
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			const manager = journaled(storage);
			await closeServers(offline);
			const refused = await refusal(
				rotationFor(storage, lease, outgoing, offline).rotate()
			);
			expect(refused.reason).to.equal('no-quorum');
			const intent = readRotationIntent(storage);
			expect(intent).to.not.equal(null);

			// The same guardians come back (new addresses): the persisted
			// intent is resumed, not replaced.
			incoming = await Promise.all(offline.map(reserve));
			const events: IRotationEvent[] = [];
			const result = await rotationFor(
				storage,
				lease,
				outgoing,
				incoming,
				(e) => events.push(e)
			).rotate();
			expect(result.generation).to.equal(2n);
			expect(events[0].type).to.equal('rotation:intent');
			expect(events[0].generation).to.equal(intent!.generation);
			expect(readRotationIntent(storage)).to.equal(null);
			expect(readGeneration(storage)).to.equal(2n);

			const first = commitOne(manager, 3);
			expect(first.committed, String(first.error?.message)).to.equal(true);
			const pass = await result.replicator.replicatePending(lease);
			expect(pass.replicatedThrough).to.equal(1n);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A4: with frames, a watermark missing at the switch is still refused', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			const manager = journaled(storage);
			expect(commitOne(manager, 4).committed).to.equal(true);
			expect(commitOne(manager, 5).committed).to.equal(true);
			// The backfill reaches the tip, then the mark disappears before
			// the switch reads it.
			const refused = await refusal(
				rotationFor(storage, lease, outgoing, incoming, (event) => {
					if (event.type === 'rotation:backfill') {
						storage.deleteRecoveryMeta!(
							PREFIX + REPLICATION_META_KEYS.replicatedThrough
						);
					}
				}).rotate()
			);
			expect(refused.reason).to.equal('not-catching-up');
			expect(refused.message).to.match(/does not cover this journal's tip 2/);
			expect(refused.message).to.not.match(/vanished/);
			expect(readRotationIntent(storage)).to.not.equal(null);
			expect(readGeneration(storage)).to.equal(1n);
			expect(readRetirePending(storage)).to.equal(null);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A5: an outgoing set that holds history this journal lost refuses as journal-behind, and is not retired', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease, replicator } = await registered(storage, outgoing);
			const manager = journaled(storage);
			expect(commitOne(manager, 6).committed).to.equal(true);
			expect(commitOne(manager, 7).committed).to.equal(true);
			expect(
				(await replicator.replicatePending(lease)).replicatedThrough
			).to.equal(2n);
			// The frames and every frame-derived key are destroyed; the lease
			// and the epoch survive, exactly like a wallet that never wrote.
			loseJournal(storage, false);

			const refused = await refusal(
				rotationFor(storage, lease, outgoing, incoming).rotate()
			);
			expect(refused.reason).to.equal('journal-behind');
			expect(refused.message).to.match(
				/outgoing set holds this namespace through 2/
			);
			expect(refused.message).to.match(/restore instead of rotating/);
			expect(readGeneration(storage)).to.equal(1n);
			expect(readRetirePending(storage)).to.equal(null);
			expect(readRotationIntent(storage)).to.not.equal(null);
			expect(watermarkKeys(storage)).to.deep.equal([]);
			// The set holding the real history is never retired.
			expect(heads(outgoing, OLD_SET)).to.deep.equal([
				{ sequence: 2n, rotated: false },
				{ sequence: 2n, rotated: false },
				{ sequence: 2n, rotated: false }
			]);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A6: an incoming set that holds history this journal lost refuses as journal-behind', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			const manager = journaled(storage);
			expect(commitOne(manager, 8).committed).to.equal(true);
			expect(commitOne(manager, 9).committed).to.equal(true);
			// A first attempt backfills 1..2 to the incoming set, then stops
			// short of the switch.
			const first = await refusal(
				rotationFor(storage, lease, outgoing, incoming, (event) => {
					if (event.type === 'rotation:backfill') {
						storage.deleteRecoveryMeta!(
							PREFIX + REPLICATION_META_KEYS.replicatedThrough
						);
					}
				}).rotate()
			);
			expect(first.reason).to.equal('not-catching-up');
			expect(heads(incoming, NEW_SET).map((h) => h.sequence)).to.deep.equal([
				2n,
				2n,
				2n
			]);
			// The journal is lost; the intent survives it.
			loseJournal(storage, true);

			const refused = await refusal(
				rotationFor(storage, lease, outgoing, incoming).rotate()
			);
			expect(refused.reason).to.equal('journal-behind');
			expect(refused.message).to.match(
				/incoming set holds this namespace through 2/
			);
			expect(readGeneration(storage)).to.equal(1n);
			expect(readRetirePending(storage)).to.equal(null);
			expect(readRotationIntent(storage)).to.not.equal(null);
			expect(heads(outgoing, OLD_SET).some((h) => h.rotated)).to.equal(false);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A7: a torn incoming watermark over an empty journal is refused, not copied', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			storage.setRecoveryMeta!(
				PREFIX + REPLICATION_META_KEYS.replicatedThrough,
				'3'
			);
			storage.setRecoveryMeta!(
				PREFIX + REPLICATION_META_KEYS.replicatedThroughHash,
				'aa'.repeat(32)
			);
			const refused = await refusal(
				rotationFor(storage, lease, outgoing, incoming).rotate()
			);
			expect(refused.reason).to.equal('not-catching-up');
			expect(readGeneration(storage)).to.equal(1n);
			expect(readRetirePending(storage)).to.equal(null);
			expect(
				storage.getRecoveryMeta!(REPLICATION_META_KEYS.replicatedThrough)
			).to.equal(null);
			expect(
				storage.getRecoveryMeta!(REPLICATION_META_KEYS.replicatedThroughHash)
			).to.equal(null);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A8: a first frame committed as the rotation starts takes the normal switch', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			const manager = journaled(storage);
			let concurrent: ReturnType<RecoveryManager['commit']> | null = null;
			// The hook is synchronous: it runs after the intent is written and
			// before the registration reads the chain origin.
			const result = await rotationFor(
				storage,
				lease,
				outgoing,
				incoming,
				(event) => {
					if (event.type === 'rotation:intent') {
						concurrent = commitOne(manager, 10);
					}
				}
			).rotate();
			expect(concurrent).to.not.equal(null);
			const committed = concurrent as unknown as ReturnType<
				RecoveryManager['commit']
			>;
			expect(committed.committed, String(committed.error?.message)).to.equal(
				true
			);
			expect(result.generation).to.equal(2n);
			const frames = storage.loadRecoveryFrames!();
			expect(frames).to.have.length(1);
			expect(
				storage.getRecoveryMeta!(REPLICATION_META_KEYS.replicatedThrough)
			).to.equal('1');
			expect(
				storage.getRecoveryMeta!(REPLICATION_META_KEYS.replicatedThroughHash)
			).to.equal(frames[0].frameHash.toString('hex'));
			expect(
				watermarkKeys(storage).filter((key) => key.startsWith('rotation:'))
			).to.deep.equal([]);
			expect(heads(incoming, NEW_SET).map((h) => h.sequence)).to.deep.equal([
				1n,
				1n,
				1n
			]);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});

	it('A9: an outgoing set that cannot confirm the namespace is empty refuses the genesis switch', async function (): Promise<void> {
		this.timeout(20_000);
		const outgoing = await Promise.all(
			[0, 1, 2].map((i) => serve(i, OLD_MEMBERS))
		);
		const incoming = await Promise.all(
			[1, 2, 3].map((i) => serve(i, NEW_MEMBERS))
		);
		const storage = openStorage();
		try {
			const { lease } = await registered(storage, outgoing);
			// One outgoing guardian answers: a write quorum of the other two
			// could hold records this journal lost, and nobody can say.
			await closeServers(outgoing.slice(1));
			const refused = await refusal(
				rotationFor(storage, lease, outgoing, incoming).rotate()
			);
			expect(refused.reason).to.equal('no-quorum');
			expect(refused.message).to.match(/outgoing set/);
			expect(readGeneration(storage)).to.equal(1n);
			expect(readRetirePending(storage)).to.equal(null);
			expect(readRotationIntent(storage)).to.not.equal(null);
		} finally {
			storage.close();
			await shutdown(outgoing);
			await shutdown(incoming);
		}
	});
});
