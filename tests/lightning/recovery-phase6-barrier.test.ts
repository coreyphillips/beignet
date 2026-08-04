/**
 * Recovery Protocol phase 6, part 3: the durability barrier itself
 * (docs/RECOVERY-PROTOCOL.md 5.8 and 9).
 *
 * The four acceptance properties from section 9, stated as invariants:
 *
 * 1. In quorum mode nothing is released until its frame is quorum durable.
 * 2. Guardian latency does not stall non-critical work: local and
 *    async-remote never hold anything, and neither does a frame already
 *    below the watermark.
 * 3. Appends pipeline and receipts are cumulative. A delayed receipt for
 *    frame N adds no per-frame round trip, and a single advance at or above
 *    N releases every waiter at or below it.
 * 4. A timeout FREEZES. Silence from the quorum is never permission, and no
 *    path anywhere turns a timeout into a release.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	BarrierOutcome,
	CRASH_V1_PROFILE,
	DurabilityBarrier,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	GuardianState,
	IBoundGuardianClient,
	IDurabilityBarrierEvent,
	IWriterLeaseKeys,
	JOURNAL_META_KEYS,
	REPLICATION_META_KEYS,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	computeGuardianSetId,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	generateWriterKey,
	nodeGuardianTransport,
	signAcquisition,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`p6-barrier-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };
const NODE_SECRET = sha('p6-barrier-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);

let now = 2_210_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	client: GuardianClient;
	id: Buffer;
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

function bind(served: IServed[]): IBoundGuardianClient[] {
	return served.map((entry) => ({
		client: entry.client,
		expectedGuardianId: entry.id
	}));
}

async function shutdown(served: IServed[]): Promise<void> {
	for (const entry of served) {
		try {
			await entry.server.close();
			entry.guardian.close();
		} catch {
			// Already closed by the test.
		}
	}
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

interface IHarness {
	storage: SqliteStorage;
	journal: RecoveryJournal;
	manager: RecoveryManager;
}

function journaled(storage: SqliteStorage): IHarness {
	const journal = new RecoveryJournal(
		storage,
		deriveRecoveryMasterKey(NODE_SECRET),
		NODE_ID,
		ROOT.recoveryId,
		{ durability: 'quorum' }
	);
	return {
		storage,
		journal,
		manager: new RecoveryManager(storage, { journal })
	};
}

/** Commit one journaled transition and return the frame it landed in. */
function commit(harness: IHarness, tag: number): bigint {
	const result = harness.manager.commit({
		criticality: RecoveryCriticality.SafetyCritical,
		mutations: [
			{
				type: 'payment_preimage',
				paymentHash: Buffer.alloc(32, tag).toString('hex'),
				preimage: Buffer.alloc(32, tag)
			}
		],
		outboundMessages: []
	});
	expect(result.committed).to.equal(true);
	expect(result.frameSequence).to.not.equal(null);
	return result.frameSequence as bigint;
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

async function waitFor(
	condition: () => boolean,
	timeoutMs = 8_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('waitFor timed out');
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

/** An endpoint whose put_state calls can be held open on demand. */
function gateable(
	entry: IServed,
	blocked: () => boolean
): IBoundGuardianClient {
	return {
		expectedGuardianId: entry.id,
		client: new GuardianClient({
			url: entry.client.url,
			guardianSetId: SET_ID,
			transport: async (
				url,
				init
			): Promise<{ status: number; body: Buffer }> => {
				if (url.endsWith('/put_state')) {
					while (blocked()) {
						await new Promise((resolve) => setTimeout(resolve, 10));
					}
				}
				return nodeGuardianTransport()(url, init);
			}
		})
	};
}

// ─────────────── Tests ───────────────

describe('Recovery phase 6: the barrier holds only what it must', () => {
	it('local and async-remote release synchronously and hold NOTHING', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 7);

		for (const mode of ['local', 'async-remote'] as const) {
			const barrier = new DurabilityBarrier({
				durability: mode,
				replicator: rep,
				lease: (): IWriterLeaseKeys => lease
			});
			expect(barrier.enforcing).to.equal(false);
			// The synchronous question the dispatch path asks first. If this
			// ever returned false outside quorum mode, every loopback test in
			// the suite would start deferring its sends.
			expect(barrier.isReleased(sequence)).to.equal(true);
			expect(barrier.isReleased(sequence + 1000n)).to.equal(true);
			const outcome = await barrier.whenReleased(sequence + 1000n);
			expect(outcome.released).to.equal(true);
			expect((outcome as { reason: string }).reason).to.equal('not-required');
			barrier.stop();
		}
		await shutdown(served);
		storage.close();
	});

	it('quorum mode releases a frame already below the watermark INLINE', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 1);
		await rep.replicatePending(lease);

		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease
		});
		expect(barrier.enforcing).to.equal(true);
		// No promise, no deferral, no reordering risk: the common case stays on
		// the synchronous path.
		expect(barrier.isReleased(sequence)).to.equal(true);
		barrier.stop();
		await shutdown(served);
		storage.close();
	});

	it('quorum mode HOLDS a frame the quorum has not stored yet', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		let blocked = true;
		const guardians = served.map((entry) => gateable(entry, () => blocked));
		const rep = replicatorFor(storage, guardians);
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 2);

		const events: IDurabilityBarrierEvent[] = [];
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 6_000,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		expect(barrier.isReleased(sequence)).to.equal(false);

		let outcome: BarrierOutcome | null = null;
		void barrier.whenReleased(sequence).then((result) => {
			outcome = result;
		});
		await waitFor(() => events.some((e) => e.type === 'barrier:waiting'));
		// Nothing may resolve while the guardians are held.
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(outcome).to.equal(null);

		blocked = false;
		await waitFor(() => outcome !== null);
		expect((outcome as unknown as BarrierOutcome).released).to.equal(true);
		expect(barrier.watermark() >= sequence).to.equal(true);
		barrier.stop();
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: one receipt releases every barrier below it', () => {
	it('a single advance frees waiters from MANY frames at once', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		let blocked = true;
		const guardians = served.map((entry) => gateable(entry, () => blocked));
		const rep = replicatorFor(storage, guardians);
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;

		// Commits keep landing while the first receipt is outstanding: the
		// barrier holds MESSAGES, never appends.
		const sequences = [3, 4, 5, 6].map((tag) => commit(harness, tag));
		const events: IDurabilityBarrierEvent[] = [];
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 8_000,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		const settled: Array<BarrierOutcome | null> = sequences.map(() => null);
		sequences.forEach((sequence, index) => {
			void barrier.whenReleased(sequence).then((outcome) => {
				settled[index] = outcome;
			});
		});
		await waitFor(
			() => events.filter((e) => e.type === 'barrier:waiting').length === 4
		);

		blocked = false;
		await waitFor(() => settled.every((entry) => entry !== null));
		for (const outcome of settled) {
			expect((outcome as unknown as BarrierOutcome).released).to.equal(true);
		}
		// ONE advance did it, not one per frame. That is the cumulative receipt
		// rule: a receipt for head S certifies the whole prefix through S.
		const advances = events.filter((e) => e.type === 'barrier:durable');
		expect(advances.length).to.equal(1);
		expect(advances[0].sequence).to.equal(sequences[sequences.length - 1]);
		barrier.stop();
		await shutdown(served);
		storage.close();
	});

	it('a burst of commits shares ONE replication pass, not one per waiter', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 8_000
		});

		let passes = 0;
		const realReplicate = rep.replicatePending.bind(rep);
		(
			rep as unknown as { replicatePending: typeof rep.replicatePending }
		).replicatePending = async (
			held: IWriterLeaseKeys
		): ReturnType<typeof realReplicate> => {
			passes += 1;
			return realReplicate(held);
		};

		const waits: Array<Promise<BarrierOutcome>> = [];
		for (let i = 0; i < 6; i++) {
			waits.push(barrier.whenReleased(commit(harness, 20 + i)));
		}
		const outcomes = await Promise.all(waits);
		for (const outcome of outcomes) expect(outcome.released).to.equal(true);
		// Six waiters, well under six passes. A per-waiter pass would be the
		// per-frame round trip pipelining exists to remove.
		expect(passes).to.be.lessThan(6);
		barrier.stop();
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: a timeout freezes, it does not proceed', () => {
	it('an unreachable quorum REFUSES the message rather than letting it go', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 8);

		// Every guardian goes dark AFTER the namespace exists, which is the
		// realistic outage: the node owns the namespace and simply cannot
		// reach anyone to prove anything.
		await shutdown(served);

		const events: IDurabilityBarrierEvent[] = [];
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 300,
			retryDelayMs: 50,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		const outcome = await barrier.whenReleased(sequence);
		expect(outcome.released).to.equal(false);
		expect((outcome as { reason: string }).reason).to.equal('timeout');
		expect(events.some((e) => e.type === 'barrier:timeout')).to.equal(true);
		// The watermark never moved, so a later attempt is held too. Silence
		// does not accumulate into permission.
		expect(barrier.isReleased(sequence)).to.equal(false);
		barrier.stop();
		storage.close();
	});

	it('a timeout leaves LATER frames held, never released by the passage of time', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const first = commit(harness, 11);
		await shutdown(served);
		const second = commit(harness, 12);

		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 250,
			retryDelayMs: 50
		});
		const [a, b] = await Promise.all([
			barrier.whenReleased(first),
			barrier.whenReleased(second)
		]);
		expect(a.released).to.equal(false);
		expect(b.released).to.equal(false);
		barrier.stop();
		storage.close();
	});

	it('an unsettled lease is never a reason to release', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const sequence = commit(harness, 13);

		const events: IDurabilityBarrierEvent[] = [];
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			// Ownership never settles: a node that cannot prove it owns the
			// namespace cannot prove anything is durable either.
			lease: (): IWriterLeaseKeys | null => null,
			timeoutMs: 250,
			retryDelayMs: 50,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		const outcome = await barrier.whenReleased(sequence);
		expect(outcome.released).to.equal(false);
		expect((outcome as { reason: string }).reason).to.equal('timeout');
		expect(events.some((e) => e.type === 'barrier:unreachable')).to.equal(true);
		barrier.stop();
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: a fenced writer never releases again', () => {
	it('a proven takeover refuses every held message and freezes FIRST', async function (): Promise<void> {
		// Real guardians over real TCP: the default 2s is not enough under
		// full-suite load, and a load-sensitive timeout is a flaky test.
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		commit(harness, 14);
		await rep.replicatePending(lease);

		// A second device genuinely takes the epoch, exactly as a restore does.
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
		const stranded = commit(harness, 15);

		const order: string[] = [];
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 8_000,
			retryDelayMs: 50
		});
		barrier.onFenced((): void => {
			order.push('freeze');
		});
		const outcome = await barrier.whenReleased(stranded);
		order.push('refused');

		expect(outcome.released).to.equal(false);
		expect((outcome as { reason: string }).reason).to.equal('fenced');
		// The transport must be shut before anything is handed back, or a
		// release could still reach a socket that is open.
		expect(order).to.deep.equal(['freeze', 'refused']);
		// Fencing is permanent: nothing reopens it.
		expect(barrier.isReleased(stranded)).to.equal(false);
		expect(barrier.snapshot().fenced).to.equal(true);
		const later = await barrier.whenReleased(stranded + 1n);
		expect((later as { reason: string }).reason).to.equal('fenced');
		barrier.stop();
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: a watermark speaks only for frames we hold', () => {
	it('a quorum barrier REFUSES to build over a watermark above the tip', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 41);
		await rep.replicatePending(lease);
		expect(rep.replicatedThrough()).to.equal(sequence);

		// The frames can be rolled back, restored in part or repaired while
		// the mark in recovery_meta survives. Nothing in a replication pass
		// notices: a pass whose watermark already exceeds the tip loads no
		// frames, examines no receipt, and reports success.
		storage.setRecoveryMeta(
			REPLICATION_META_KEYS.replicatedThrough,
			String(sequence + 1000n)
		);
		expect(
			() =>
				new DurabilityBarrier({
					durability: 'quorum',
					replicator: rep,
					lease: (): IWriterLeaseKeys => lease
				})
		).to.throw(/rolled back or restored underneath/);

		await shutdown(served);
		storage.close();
	});

	it('a truncated frame table is refused even with the mark below the tip', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 42);
		await rep.replicatePending(lease);

		// The tip row itself is gone while the bookkeeping still names it. The
		// mark is not above the recorded tip, so only cross-checking the tip
		// against the ROW catches this.
		storage.deleteRecoveryFramesBelow(Number(sequence) + 1);
		expect(
			() =>
				new DurabilityBarrier({
					durability: 'quorum',
					replicator: rep,
					lease: (): IWriterLeaseKeys => lease
				})
		).to.throw(/does not match the frames on disk/);

		await shutdown(served);
		storage.close();
	});

	it('a weaker mode REPORTS the same inconsistency and keeps running', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 43);
		await rep.replicatePending(lease);
		storage.setRecoveryMeta(
			REPLICATION_META_KEYS.replicatedThrough,
			String(sequence + 500n)
		);

		const events: IDurabilityBarrierEvent[] = [];
		const barrier = new DurabilityBarrier({
			durability: 'async-remote',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			onEvent: (event): void => {
				events.push(event);
			}
		});
		expect(barrier.enforcing).to.equal(false);
		expect(events.map((e) => e.type)).to.deep.equal(['barrier:unreachable']);
		// Never written DOWN. raiseWatermark is monotone by design, and
		// lowering it would repair nothing: a guardian genuinely holding
		// records above our tip refuses a re-offer with a sequence gap anyway.
		expect(
			storage.getRecoveryMeta(REPLICATION_META_KEYS.replicatedThrough)
		).to.equal(String(sequence + 500n));

		barrier.stop();
		await shutdown(served);
		storage.close();
	});

	it('a fresh database and a mid-journal enablement both build', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const fresh = openStorage();
		const freshRep = replicatorFor(fresh, bind(served));
		const empty = new DurabilityBarrier({
			durability: 'quorum',
			replicator: freshRep,
			lease: (): IWriterLeaseKeys | null => null
		});
		expect(empty.isReleased(1n)).to.equal(false);
		empty.stop();
		fresh.close();

		// Frames already journaled, guardians only being enabled now: there is
		// no watermark at all, which releases nothing and refuses nothing.
		const midJournal = openStorage();
		const harness = journaled(midJournal);
		commit(harness, 44);
		commit(harness, 45);
		const midRep = replicatorFor(midJournal, bind(served));
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: midRep,
			lease: (): IWriterLeaseKeys | null => null
		});
		expect(barrier.watermark()).to.equal(0n);
		barrier.stop();
		midJournal.close();
		await shutdown(served);
	});
});

describe('Recovery phase 6: a namespace that can never advance says so', () => {
	it('refuses IMMEDIATELY with its own reason, not on the timeout', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 51);

		const events: IDurabilityBarrierEvent[] = [];
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			// Long enough that a timeout would be obvious in the elapsed time.
			timeoutMs: 60_000,
			retryDelayMs: 50,
			backfillLost: (): boolean => true,
			onEvent: (event): void => {
				events.push(event);
			}
		});

		const started = Date.now();
		const outcome = await barrier.whenReleased(sequence);
		expect(outcome.released).to.equal(false);
		expect((outcome as { reason: string }).reason).to.equal('backfill-lost');
		expect(Date.now() - started).to.be.lessThan(2_000);
		expect(events.map((e) => e.type)).to.contain('barrier:backfill-lost');
		expect(barrier.snapshot().backfillLost).to.equal(true);
		// A different fact from a fence, with a different remedy, so the two
		// must never be folded into one another.
		expect(barrier.snapshot().fenced).to.equal(false);

		barrier.stop();
		await shutdown(served);
		storage.close();
	});

	it('settles a waiter already parked when the loss is discovered', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		await rep.ensureNamespace();
		const sequence = commit(harness, 52);

		let lost = false;
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			// No lease yet, so nothing can release and the waiter genuinely parks.
			lease: (): IWriterLeaseKeys | null => null,
			timeoutMs: 60_000,
			retryDelayMs: 25,
			backfillLost: (): boolean => lost
		});

		const waiting = barrier.whenReleased(sequence + 100n);
		await new Promise((resolve) => setTimeout(resolve, 100));
		lost = true;

		// Ended by the pump noticing, not by its own timer 60s later.
		const outcome = await waiting;
		expect(outcome.released).to.equal(false);
		expect((outcome as { reason: string }).reason).to.equal('backfill-lost');

		barrier.stop();
		await shutdown(served);
		storage.close();
	});

	it('reads the loss straight out of the journal with nothing wired', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		commit(harness, 53);
		storage.setRecoveryMeta(
			JOURNAL_META_KEYS.backfillLost,
			'a previous run pruned past the ceiling'
		);

		// No backfillLost predicate supplied: the fact is irreversible and
		// lives in the journal, so it must survive the process that found it.
		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 1_000
		});
		expect(barrier.namespaceLost).to.equal(true);

		barrier.stop();
		await shutdown(served);
		storage.close();
	});
});

describe('Recovery phase 6: no frame is not permission', () => {
	it('an unattributed transition is refused, synchronously and on the wait', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const harness = journaled(storage);
		const rep = replicatorFor(storage, bind(served));
		const lease = ((await rep.ensureNamespace()) as { lease: IWriterLeaseKeys })
			.lease;
		const sequence = commit(harness, 61);
		await rep.replicatePending(lease);

		const barrier = new DurabilityBarrier({
			durability: 'quorum',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease,
			timeoutMs: 1_000,
			retryDelayMs: 50
		});
		// The frame that IS named releases, so the refusal below is about
		// attribution and not about the watermark.
		expect(barrier.isReleased(sequence)).to.equal(true);

		// A null sequence names nothing the guardians could have receipted, so
		// no receipt can ever release it and answering yes would be a message
		// going out on no evidence at all.
		expect(barrier.isReleased(null)).to.equal(false);
		const outcome = await barrier.whenReleased(null);
		expect(outcome.released).to.equal(false);
		expect((outcome as { reason: string }).reason).to.equal('missing-frame');

		// And the weaker modes are untouched: they hold nothing, ever.
		const relaxed = new DurabilityBarrier({
			durability: 'async-remote',
			replicator: rep,
			lease: (): IWriterLeaseKeys => lease
		});
		expect(relaxed.isReleased(null)).to.equal(true);
		relaxed.stop();

		barrier.stop();
		await shutdown(served);
		storage.close();
	});
});
