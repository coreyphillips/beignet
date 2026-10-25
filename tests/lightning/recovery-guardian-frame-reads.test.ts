/**
 * Guardian replication reads journal frames by sequence (issue #1862).
 *
 * A replication pass used to load every frame above the watermark before
 * sending the first record, and the origin and retain-floor helpers loaded
 * whole frame tails to look at one or two rows. Each now asks the store for
 * the rows it needs, so a pass holds one pipeline window per guardian however
 * far behind the set is. What a guardian receives must not shrink with it:
 * every frame of the backlog, in order, verifiable as one chain.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	CRASH_V1_PROFILE,
	GuardianClient,
	GuardianReplicator,
	GuardianVerbName,
	IBoundGuardianClient,
	IGuardianRecord,
	IWriterLeaseKeys,
	JOURNAL_META_KEYS,
	META_LAST_SNAPSHOT_GROUP,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	computeGuardianSetId,
	decodePutStateRequest,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	dispatchGuardianVerb,
	encodeGuardianInfo,
	verifyFrameChain,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { firstStoredSequenceAfter } from '../../src/lightning/recovery/frame-reads';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import type {
	IStorageBackend,
	IStoredRecoveryFrame,
	IStoredRecoveryFrameHeader
} from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`frame-reads-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));
const SET_ID = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: GUARDIAN_IDS
});
const CONTEXT = { guardianSetId: SET_ID, members: GUARDIAN_IDS };
const NODE_SECRET = sha('frame-reads-node-secret');
const ROOT = deriveRecoveryRoot(NODE_SECRET);
const NODE_ID = getPublicKey(NODE_SECRET);
const MASTER_KEY = deriveRecoveryMasterKey(NODE_SECRET);
const JOURNAL_KEYS = { masterKey: MASTER_KEY, nodeId: NODE_ID };

let now = 2_400_000_000_000n;
const clock = (): bigint => ++now;

interface IGuardianUnderTest {
	guardian: ReferenceGuardian;
	bound: IBoundGuardianClient;
	/** Every record sequence this guardian was sent, in arrival order. */
	sent: bigint[];
}

/**
 * A real guardian behind an in-process transport, recording what it is sent.
 * While `down()` holds, every record sent to it fails in transit.
 */
function guardianAt(
	index: number,
	onPut?: (sequence: bigint) => void,
	down?: () => boolean
): IGuardianUnderTest {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock
	});
	const sent: bigint[] = [];
	const client = new GuardianClient({
		url: `http://guardian-${index}.example`,
		guardianSetId: SET_ID,
		transport: async (url, init): Promise<{ status: number; body: Buffer }> => {
			if (init.method === 'GET') {
				return { status: 200, body: encodeGuardianInfo(guardian) };
			}
			const verb = url.split('/').pop() as GuardianVerbName;
			const body = init.body as Buffer;
			if (verb === 'put_state') {
				if (down?.()) throw new Error('guardian unreachable');
				const sequence = decodePutStateRequest(body).record.sequence;
				sent.push(sequence);
				onPut?.(sequence);
			}
			return { status: 200, body: dispatchGuardianVerb(guardian, verb, body) };
		}
	});
	return {
		guardian,
		bound: { client, expectedGuardianId: GUARDIAN_IDS[index] },
		sent
	};
}

function guardianSet(onPut?: (sequence: bigint) => void): IGuardianUnderTest[] {
	return [0, 1, 2].map((index) => guardianAt(index, onPut));
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function commitPreimage(manager: RecoveryManager, index: number): void {
	const preimage = sha(`frame-reads-preimage-${index}`);
	expect(
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha(preimage.toString('hex')).toString('hex'),
					preimage
				}
			],
			outboundMessages: []
		}).committed
	).to.equal(true);
}

function journaled(
	commits: number,
	options: ConstructorParameters<typeof RecoveryJournal>[4] = {}
): {
	storage: SqliteStorage;
	journal: RecoveryJournal;
	manager: RecoveryManager;
} {
	const storage = openStorage();
	const journal = new RecoveryJournal(
		storage,
		MASTER_KEY,
		NODE_ID,
		ROOT.recoveryId,
		options
	);
	const manager = new RecoveryManager(storage, { journal });
	for (let i = 0; i < commits; i++) commitPreimage(manager, i);
	return { storage, journal, manager };
}

function replicatorFor(
	storage: IStorageBackend,
	guardians: IGuardianUnderTest[],
	{ pipelineWindow = 8, floors = true } = {}
): GuardianReplicator {
	return new GuardianReplicator({
		storage,
		guardians: guardians.map((entry) => entry.bound),
		context: CONTEXT,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: ROOT,
		clock,
		// Without the journal keys no retain floor is named, so guardians
		// keep every record they were sent.
		journalKeys: floors ? JOURNAL_KEYS : undefined,
		pipelineWindow
	});
}

async function registered(rep: GuardianReplicator): Promise<IWriterLeaseKeys> {
	const decision = await rep.ensureNamespace();
	expect(decision.outcome).to.equal('registered');
	return (decision as { lease: IWriterLeaseKeys }).lease;
}

interface IFrameReads {
	/** loadRecoveryFrames calls: each returns every frame above its bound. */
	ranges: number;
	rows: number;
	headers: number;
	/** The most ciphertext any single call returned. */
	largestAnswerBytes: number;
}

/** Count every frame read the storage serves from here on. */
function countFrameReads(storage: SqliteStorage): IFrameReads {
	const counts: IFrameReads = {
		ranges: 0,
		rows: 0,
		headers: 0,
		largestAnswerBytes: 0
	};
	const answered = (frames: IStoredRecoveryFrame[]): void => {
		const bytes = frames.reduce((sum, f) => sum + f.ciphertext.length, 0);
		counts.largestAnswerBytes = Math.max(counts.largestAnswerBytes, bytes);
	};
	const loadFrames = storage.loadRecoveryFrames.bind(storage);
	const loadFrame = storage.loadRecoveryFrame.bind(storage);
	const loadHeader = storage.loadRecoveryFrameHeader.bind(storage);
	storage.loadRecoveryFrames = (
		afterSequence?: number
	): IStoredRecoveryFrame[] => {
		counts.ranges++;
		const frames = loadFrames(afterSequence);
		answered(frames);
		return frames;
	};
	storage.loadRecoveryFrame = (
		sequence: number
	): IStoredRecoveryFrame | null => {
		counts.rows++;
		const frame = loadFrame(sequence);
		if (frame) answered([frame]);
		return frame;
	};
	storage.loadRecoveryFrameHeader = (
		sequence: number
	): IStoredRecoveryFrameHeader | null => {
		counts.headers++;
		return loadHeader(sequence);
	};
	return counts;
}

/** Every record a guardian holds for this namespace, page by page. */
async function recordsHeld(
	entry: IGuardianUnderTest
): Promise<IGuardianRecord[]> {
	const records: IGuardianRecord[] = [];
	for (;;) {
		const after = records.length ? records[records.length - 1].sequence : 0n;
		const page = await entry.bound.client.getState(ROOT.recoveryId, after);
		records.push(...(page.records ?? []));
		if (!page.hasMore) return records;
	}
}

function asStoredFrame(record: IGuardianRecord): IStoredRecoveryFrame {
	return {
		sequence: Number(record.sequence),
		writerEpoch: Number(record.epoch),
		frameHash: record.frameHash,
		previousFrameHash: record.previousHash,
		ciphertext: record.ciphertext,
		createdAt: 0
	};
}

/**
 * The guardian holds exactly `stored`, in order, and what it holds verifies
 * as the journal's chain through its recorded tip.
 */
async function expectHoldsJournal(
	entry: IGuardianUnderTest,
	storage: SqliteStorage,
	stored: IStoredRecoveryFrame[]
): Promise<void> {
	const records = await recordsHeld(entry);
	expect(records.map((r) => r.sequence)).to.deep.equal(
		stored.map((f) => BigInt(f.sequence))
	);
	records.forEach((record, i) =>
		expect(record.frameHash.equals(stored[i].frameHash)).to.equal(true)
	);
	const verified = verifyFrameChain(
		records.map(asStoredFrame),
		{
			tipSequence: storage.getRecoveryMeta(JOURNAL_META_KEYS.tipSequence),
			tipHash: storage.getRecoveryMeta(JOURNAL_META_KEYS.tipHash),
			lastSnapshotSequence: storage.getRecoveryMeta(
				JOURNAL_META_KEYS.lastSnapshot
			)
		},
		MASTER_KEY,
		NODE_ID
	);
	expect(verified).to.have.length(stored.length);
}

function deleteFrame(storage: SqliteStorage, sequence: number): void {
	(storage as unknown as { db: { exec(sql: string): void } }).db.exec(
		`DELETE FROM recovery_frames WHERE sequence = ${sequence}`
	);
}

describe('Guardian replication reads frames by sequence (issue #1862)', () => {
	it('streams a 96-commit backlog one frame per read, and every guardian holds all of it in order', async function (): Promise<void> {
		this.timeout(60_000);
		// Nothing compacts, so the whole journal is the backlog.
		const { storage } = journaled(96, { retainFrom: (): bigint => 1n });
		const stored = storage.loadRecoveryFrames();
		const tip = BigInt(stored[stored.length - 1].sequence);
		const largestFrame = Math.max(...stored.map((f) => f.ciphertext.length));
		const guardians = guardianSet();
		const rep = replicatorFor(storage, guardians, { floors: false });
		const lease = await registered(rep);

		const reads = countFrameReads(storage);
		const result = await rep.replicatePending(lease);
		const counted = { ...reads };
		expect(result.outcome).to.equal('replicated');
		expect(result.replicatedThrough).to.equal(tip);
		expect(result.attempted).to.equal(stored.length);

		// No read returned more than one frame, and every row read went out
		// as a record. The pass used to start with one read returning every
		// stored byte.
		expect(counted.ranges, 'no range loads').to.equal(0);
		expect(counted.largestAnswerBytes).to.be.at.most(largestFrame);
		const sent = guardians.reduce((sum, entry) => sum + entry.sent.length, 0);
		expect(counted.rows).to.equal(sent);

		// Complete, ordered coverage: every guardian holds exactly the
		// journal, and the chain it holds verifies frame by frame.
		for (const entry of guardians) {
			await expectHoldsJournal(entry, storage, stored);
		}
		storage.close();
	});

	it('checks a snapshot group from its snapshot row and its last header before naming it the floor', async () => {
		const { storage } = journaled(20, {
			snapshotIntervalFrames: 4,
			retainFrom: (): bigint => 1n
		});
		const group = JSON.parse(
			storage.getRecoveryMeta(META_LAST_SNAPSHOT_GROUP)!
		) as { sequence: string };
		expect(Number(group.sequence)).to.be.greaterThan(1);
		const guardians = guardianSet();
		const rep = replicatorFor(storage, guardians);
		const lease = await registered(rep);

		const reads = countFrameReads(storage);
		expect((await rep.replicatePending(lease)).outcome).to.equal('replicated');
		const counted = { ...reads };
		expect(rep.retainFloor(lease)?.sequence).to.equal(BigInt(group.sequence));
		expect(counted.ranges, 'no range loads').to.equal(0);
		// Beyond the records sent, one row: the snapshot the check decrypts.
		const sent = guardians.reduce((sum, entry) => sum + entry.sent.length, 0);
		expect(counted.rows).to.equal(sent + 1);
		for (const entry of guardians) {
			const records = await recordsHeld(entry);
			expect(String(records[0].sequence)).to.equal(group.sequence);
		}
		storage.close();
	});

	it('registers a mid-journal origin from one header read', async () => {
		const { storage } = journaled(10, { snapshotIntervalFrames: 4 });
		const base = storage.loadRecoveryFrames()[0];
		expect(base.sequence).to.be.greaterThan(1);
		const guardians = guardianSet();
		const rep = replicatorFor(storage, guardians);

		const reads = countFrameReads(storage);
		await registered(rep);
		expect(reads).to.deep.include({ ranges: 0, rows: 0, headers: 1 });

		const head = await guardians[0].bound.client.getHead(ROOT.recoveryId);
		expect(head.state!.origin.firstSequence).to.equal(BigInt(base.sequence));
		expect(
			head.state!.origin.previousHash.equals(base.previousFrameHash)
		).to.equal(true);
		storage.close();
	});

	it('brings a guardian that missed a pass up from its peers, then streams it the backlog frame by frame', async function (): Promise<void> {
		this.timeout(60_000);
		const { storage, manager } = journaled(10, {
			retainFrom: (): bigint => 1n
		});
		let lagging = false;
		const guardians = [0, 1, 2].map((index) =>
			guardianAt(index, undefined, () => index === 2 && lagging)
		);
		const rep = replicatorFor(storage, guardians, { floors: false });
		const lease = await registered(rep);
		lagging = true;
		expect((await rep.replicatePending(lease)).replicatedThrough).to.equal(10n);
		lagging = false;
		expect((await recordsHeld(guardians[2])).length).to.equal(0);

		// The next pass starts above the watermark, where the lagging
		// guardian answers with a gap at its own head.
		for (let i = 10; i < 30; i++) commitPreimage(manager, i);
		const stored = storage.loadRecoveryFrames();
		const largestFrame = Math.max(...stored.map((f) => f.ciphertext.length));
		const sentBefore = guardians.map((entry) => entry.sent.length);
		const reads = countFrameReads(storage);
		const result = await rep.replicatePending(lease);
		const counted = { ...reads };
		expect(result.replicatedThrough).to.equal(30n);
		expect(counted.ranges, 'no range loads').to.equal(0);
		expect(counted.largestAnswerBytes).to.be.at.most(largestFrame);
		const sent = guardians.reduce(
			(sum, entry, index) => sum + entry.sent.length - sentBefore[index],
			0
		);
		expect(counted.rows).to.equal(sent);
		// The gap came from the peers, the backlog from the journal: the
		// lagging guardian holds the whole chain, in order.
		for (const entry of guardians) {
			await expectHoldsJournal(entry, storage, stored);
		}
		storage.close();
	});

	it('ends the stream at a frame compacted during the pass rather than skipping past it', async () => {
		let floor = 1n;
		const { storage, journal } = journaled(12, {
			snapshotIntervalFrames: 4,
			retainFrom: (): bigint => floor
		});
		const newestSnapshot = BigInt(
			storage.getRecoveryMeta(JOURNAL_META_KEYS.lastSnapshotWritten)!
		);
		expect(newestSnapshot > 3n).to.equal(true);
		let compacted = false;
		// Once frames 1 and 2 are on their way, the journal prunes below its
		// newest snapshot, as a forced prune would.
		const guardians = guardianSet((sequence) => {
			if (compacted || sequence !== 2n) return;
			compacted = true;
			floor = newestSnapshot;
			journal.compact();
		});
		const rep = replicatorFor(storage, guardians, { pipelineWindow: 2 });
		const lease = await registered(rep);

		const first = await rep.replicatePending(lease);
		expect(compacted).to.equal(true);
		expect(storage.loadRecoveryFrames()[0].sequence).to.equal(
			Number(newestSnapshot)
		);
		// Nothing past the hole was sent, and frame 2's anchor is gone, so
		// no watermark binds to it.
		for (const entry of guardians) {
			expect(entry.sent).to.deep.equal([1n, 2n]);
		}
		expect(first.outcome).to.equal('under-replicated');
		expect(first.replicatedThrough).to.equal(0n);
		expect(rep.replicatedThrough()).to.equal(0n);

		// A retry starts at the retained base, which every guardian refuses
		// as a gap, and still claims nothing.
		const retry = await rep.replicatePending(lease);
		expect(retry.replicatedThrough).to.equal(0n);
		for (const entry of guardians) {
			const head = await entry.bound.client.getHead(ROOT.recoveryId);
			expect(head.state!.logHead.sequence).to.equal(2n);
		}
		storage.close();
	});

	it('sends nothing past a missing interior frame', async () => {
		const { storage } = journaled(10, { retainFrom: (): bigint => 1n });
		const tip = storage.recoveryFrameStats()!.maxSequence;
		deleteFrame(storage, 6);
		const guardians = guardianSet();
		const rep = replicatorFor(storage, guardians);
		const lease = await registered(rep);

		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('under-replicated');
		expect(result.replicatedThrough).to.equal(5n);
		for (const entry of guardians) {
			expect(entry.sent.every((sequence) => sequence < 6n)).to.equal(true);
			const records = await recordsHeld(entry);
			expect(records.map((r) => Number(r.sequence))).to.deep.equal([
				1, 2, 3, 4, 5
			]);
		}
		expect(tip).to.be.greaterThan(6);
		storage.close();
	});

	it('names the first sequence after a position from the span, never stepping over a hole', () => {
		const storage = openStorage();
		const reads = countFrameReads(storage);
		expect(firstStoredSequenceAfter(storage, 0n)).to.equal(null);
		for (let sequence = 5; sequence <= 9; sequence++) {
			storage.saveRecoveryFrame({
				sequence,
				writerEpoch: 1,
				frameHash: Buffer.alloc(32, sequence),
				previousFrameHash: Buffer.alloc(32, sequence - 1),
				ciphertext: Buffer.alloc(64, sequence),
				createdAt: 0
			});
		}
		deleteFrame(storage, 7);
		expect(firstStoredSequenceAfter(storage, 0n)).to.equal(5n);
		expect(firstStoredSequenceAfter(storage, 4n)).to.equal(5n);
		expect(firstStoredSequenceAfter(storage, 5n)).to.equal(6n);
		expect(firstStoredSequenceAfter(storage, 6n), 'names the hole').to.equal(
			7n
		);
		expect(firstStoredSequenceAfter(storage, 8n)).to.equal(9n);
		expect(firstStoredSequenceAfter(storage, 9n)).to.equal(null);
		expect(firstStoredSequenceAfter(storage, 20n)).to.equal(null);
		expect(reads).to.deep.include({ ranges: 0, rows: 0, headers: 0 });
		storage.close();
	});

	it('replicates from a backend without point reads with one range load per pass', async () => {
		const { storage } = journaled(40, { retainFrom: (): bigint => 1n });
		const tip = BigInt(storage.recoveryFrameStats()!.maxSequence);
		const hidden = new Set([
			'loadRecoveryFrame',
			'loadRecoveryFrameHeader',
			'recoveryFrameStats'
		]);
		// An older adapter: journalSupported() never required these.
		const legacy = new Proxy(storage, {
			get(target, key, receiver): unknown {
				if (typeof key === 'string' && hidden.has(key)) return undefined;
				const value = Reflect.get(target, key, receiver) as unknown;
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as IStorageBackend;
		const guardians = guardianSet();
		const rep = replicatorFor(legacy, guardians);
		const lease = await registered(rep);

		const reads = countFrameReads(storage);
		const result = await rep.replicatePending(lease);
		expect(result.outcome).to.equal('replicated');
		expect(result.replicatedThrough).to.equal(tip);
		// The backlog load, the watermark read and raise, and the floor's
		// two frames: a handful, not one per record.
		expect(reads.ranges).to.be.at.most(8);
		for (const entry of guardians) {
			expect((await recordsHeld(entry)).length).to.equal(Number(tip));
		}
		storage.close();
	});
});
