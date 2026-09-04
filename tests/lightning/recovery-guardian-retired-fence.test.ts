/**
 * The retirement fence is judged INSIDE the write transaction (wire 5.11,
 * issue #711).
 *
 * A retired-marker check made in a read transaction before the write lock
 * is a time-of-check to time-of-use race: ROTATE_SET can commit between
 * that read and BEGIN IMMEDIATE, and the stale write then commits into a
 * namespace that should refuse everything. These tests use two database
 * connections on one store file and pin, per mutating verb:
 *
 * - a write that commits before the rotation is part of the retired
 *   snapshot, on both connections and across a restart;
 * - a write after the rotation answers ERR_SET_RETIRED from either
 *   connection;
 * - a write that VALIDATES before the rotation but takes the write lock
 *   after it answers ERR_SET_RETIRED and commits nothing;
 * - the same, under a real cross-thread lock wait behind the retirement
 *   transaction itself;
 * - the precedence of retirement over every verdict the row would
 *   otherwise yield, and of quarantine over retirement.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Worker } from 'worker_threads';
import Database from 'better-sqlite3';
import {
	CRASH_V1_PROFILE,
	GuardianState,
	GuardianStatus,
	GuardianStore,
	IGuardianAcquireEpochRequest,
	IGuardianAlarm,
	IGuardianGetHeadResponse,
	IGuardianReceipt,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	IGuardianRotateSetRequest,
	IGuardianTakeoverCertificate,
	ReferenceGuardian,
	acquireTranscriptHash,
	computeGuardianSetId,
	deriveRecoveryRoot,
	encodeRotateSetRequest,
	genesisLogHead,
	receiptTranscriptHash,
	recordTranscriptHash,
	registerTranscriptHash,
	rotateTranscriptHash,
	signTranscript,
	statesEqual,
	takeoverTranscriptHash,
	xOnlyFromSecret
} from '../../src/lightning/recovery';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

const SECRETS = [1, 2, 3, 4].map((i) => sha(`fence-guardian-${i}`));
const IDS = SECRETS.map((s) => xOnlyFromSecret(s));
/** The outgoing set: guardians 1, 2, 3. The incoming set: 2, 3, 4. */
const OLD_MEMBERS = [IDS[0], IDS[1], IDS[2]];
const NEW_MEMBERS = [IDS[1], IDS[2], IDS[3]];
const OLD_SET = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: OLD_MEMBERS
});
const NEW_SET = computeGuardianSetId({
	...CRASH_V1_PROFILE,
	guardianIds: NEW_MEMBERS
});
const ROOT = deriveRecoveryRoot(sha('fence-node-secret'));
const OTHER_ROOT = deriveRecoveryRoot(sha('fence-other-node'));
const WRITER = {
	secret: sha('fence-writer'),
	pub: xOnlyFromSecret(sha('fence-writer'))
};
const WRITER_2 = {
	secret: sha('fence-writer-2'),
	pub: xOnlyFromSecret(sha('fence-writer-2'))
};
/** The guardian under test is guardian 2 (index 1), a member of both sets. */
const UNDER_TEST = 1;
/** The other two outgoing members sign the quorum artifacts. */
const QUORUM = [0, 2];
const RETIRED_DETAIL = /rotated to another guardian set/;

let now = 1_900_000_000_000n;
const clock = (): bigint => ++now;

function guardianFor(
	file: string,
	members: Buffer[] = OLD_MEMBERS,
	onAlarm?: (alarm: IGuardianAlarm) => void
): ReferenceGuardian {
	return new ReferenceGuardian({
		path: file,
		guardianSecret: SECRETS[UNDER_TEST],
		members,
		clock,
		onAlarm
	});
}

function registration(
	generation: bigint,
	root = ROOT
): IGuardianRegisterNodeRequest {
	const initialState: GuardianState = {
		recoveryId: root.recoveryId,
		lease: { epoch: 3n, writerPublicKey: WRITER.pub },
		origin: { firstSequence: 1n, previousHash: Buffer.alloc(32) },
		logHead: genesisLogHead()
	};
	return {
		protocolVersion: 1,
		guardianSetId: OLD_SET,
		guardianMembers: OLD_MEMBERS,
		initialState,
		rootSignature: signTranscript(
			registerTranscriptHash(OLD_SET, initialState, generation),
			root.rootSecret
		),
		generation
	};
}

function record(
	sequence: bigint,
	previousHash: Buffer,
	opts: { epoch?: bigint; root?: typeof ROOT } = {}
): IGuardianRecord {
	const epoch = opts.epoch ?? 3n;
	const root = opts.root ?? ROOT;
	const ciphertext = sha(`ct-${sequence}`);
	const frameHash = sha(`fh-${sequence}`);
	return {
		protocolVersion: 1,
		guardianSetId: OLD_SET,
		recoveryId: root.recoveryId,
		epoch,
		sequence,
		previousHash,
		frameHash,
		ciphertext,
		writerSignature: signTranscript(
			recordTranscriptHash(OLD_SET, {
				recoveryId: root.recoveryId,
				epoch,
				sequence,
				previousHash,
				frameHash,
				ciphertextHash: sha256(ciphertext)
			}),
			WRITER.secret
		)
	};
}

/** The first record of the seeded chain, and the one every write test appends. */
const FIRST = record(1n, Buffer.alloc(32));
const SECOND = record(2n, FIRST.frameHash);

function rotation(): IGuardianRotateSetRequest {
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
		newTransports: NEW_MEMBERS.map((m) => ({
			type: 'https',
			url: `https://${m.toString('hex').slice(0, 8)}.example`
		}))
	};
}
const ROTATION = rotation();
const ROTATION_BYTES = encodeRotateSetRequest(ROTATION);

function acquire(expectedState: GuardianState): IGuardianAcquireEpochRequest {
	const newEpoch = expectedState.lease.epoch + 1n;
	const hash = acquireTranscriptHash(
		OLD_SET,
		expectedState,
		newEpoch,
		WRITER_2.pub
	);
	return {
		protocolVersion: 1,
		guardianSetId: OLD_SET,
		expectedState,
		newEpoch,
		newWriterPublicKey: WRITER_2.pub,
		rootSignature: signTranscript(hash, ROOT.rootSecret),
		newWriterSignature: signTranscript(hash, WRITER_2.secret)
	};
}

/** A quorum takeover bundle from the two other outgoing members. */
function takeoverBundle(
	supersededState: GuardianState
): IGuardianTakeoverCertificate[] {
	const newEpoch = supersededState.lease.epoch + 1n;
	return QUORUM.map((index) => {
		const issuedAt = clock();
		return {
			protocolVersion: 1,
			guardianSetId: OLD_SET,
			guardianId: IDS[index],
			supersededState,
			newEpoch,
			newWriterPublicKey: WRITER_2.pub,
			issuedAt,
			signature: signTranscript(
				takeoverTranscriptHash(
					OLD_SET,
					IDS[index],
					supersededState,
					newEpoch,
					WRITER_2.pub,
					issuedAt
				),
				SECRETS[index]
			)
		};
	});
}

/** Quorum receipts over a target state from the two other outgoing members. */
function quorumReceipts(state: GuardianState): IGuardianReceipt[] {
	return QUORUM.map((index) => {
		const issuedAt = clock();
		return {
			protocolVersion: 1,
			guardianSetId: OLD_SET,
			guardianId: IDS[index],
			state,
			issuedAt,
			signature: signTranscript(
				receiptTranscriptHash(OLD_SET, IDS[index], state, issuedAt),
				SECRETS[index]
			)
		};
	});
}

function head(g: ReferenceGuardian): IGuardianGetHeadResponse {
	return g.getHead({
		protocolVersion: 1,
		guardianSetId: OLD_SET,
		recoveryId: ROOT.recoveryId
	});
}

function stateOf(g: ReferenceGuardian): GuardianState {
	const answer = head(g);
	expect(answer.status, answer.detail).to.equal(GuardianStatus.OK);
	return answer.state as GuardianState;
}

/** Register the namespace and append the first record. */
function seed(g: ReferenceGuardian): void {
	expect(g.register(registration(1n)).status).to.equal(GuardianStatus.OK);
	expect(g.putState({ record: FIRST }).status).to.equal(GuardianStatus.OK);
}

function markPossiblyStale(file: string): void {
	const raw = new Database(file);
	raw.prepare('UPDATE guardian_namespaces SET possibly_stale = 1').run();
	raw.close();
}

function storedRotation(file: string): Buffer | null {
	const raw = new Database(file);
	const row = raw
		.prepare('SELECT rotation FROM guardian_namespaces WHERE recovery_id = ?')
		.get(ROOT.recoveryId) as { rotation: Buffer | null } | undefined;
	raw.close();
	return row ? row.rotation : null;
}

/**
 * Run `hook` once, on this connection, after the verb has finished every
 * validation it does outside the store and immediately before it takes
 * the write lock. This is the exact window the issue names: the write
 * has been validated against a pre-rotation snapshot, and whatever the
 * hook commits on ANOTHER connection is what the write's BEGIN IMMEDIATE
 * then serializes behind.
 */
function interposeBeforeWriteLock(
	g: ReferenceGuardian,
	hook: () => void
): () => number {
	const store = (g as unknown as { store: GuardianStore }).store;
	const original = store.write.bind(store);
	let fired = 0;
	store.write = <T>(fn: () => T): T => {
		if (fired++ === 0) hook();
		return original(fn);
	};
	return () => fired;
}

interface IStatus {
	status: GuardianStatus;
	detail?: string;
}

interface IVerbCase {
	name: string;
	/** Store preparation after the seed, if the verb needs one. */
	prepare?: (file: string) => void;
	/** The verb, built from the seeded head state. */
	apply: (g: ReferenceGuardian, current: GuardianState) => IStatus;
	/** What the verb answers when it runs BEFORE the rotation. */
	before: GuardianStatus;
	/** What a run before the rotation leaves in the retired snapshot. */
	committed: (after: IGuardianGetHeadResponse) => void;
}

const VERBS: IVerbCase[] = [
	{
		name: 'record submission (PUT_STATE)',
		apply: (g): IStatus => g.putState({ record: SECOND }),
		before: GuardianStatus.OK,
		committed: (after): void => {
			expect(after.state!.logHead.sequence).to.equal(2n);
		}
	},
	{
		name: 'synchronization (SYNC_RECORD)',
		apply: (g): IStatus => g.syncRecord({ record: SECOND }),
		before: GuardianStatus.OK,
		committed: (after): void => {
			expect(after.state!.logHead.sequence).to.equal(2n);
		}
	},
	{
		name: 'lease acquisition (ACQUIRE_EPOCH)',
		apply: (g, current): IStatus => g.acquireEpoch(acquire(current)),
		before: GuardianStatus.OK,
		committed: (after): void => {
			expect(after.state!.lease.epoch).to.equal(4n);
			expect(after.state!.lease.writerPublicKey.equals(WRITER_2.pub)).to.equal(
				true
			);
		}
	},
	{
		name: 'takeover application (SYNC_EPOCH)',
		apply: (g, current): IStatus =>
			g.syncEpoch({ certificates: takeoverBundle(current) }),
		before: GuardianStatus.OK,
		committed: (after): void => {
			expect(after.state!.lease.epoch).to.equal(4n);
		}
	},
	{
		name: 'repair evidence (possibly_stale lift)',
		prepare: markPossiblyStale,
		apply: (g, current): IStatus =>
			g.submitRepairEvidence({
				recoveryId: ROOT.recoveryId,
				target: current,
				receipts: quorumReceipts(current),
				certificates: []
			}),
		before: GuardianStatus.OK,
		committed: (after): void => {
			expect(after.possiblyStale).to.equal(false);
		}
	},
	{
		name: 'registration (REGISTER_NODE replay)',
		apply: (g): IStatus => g.register(registration(1n)),
		before: GuardianStatus.OK_DUPLICATE,
		committed: (after): void => {
			expect(after.state!.logHead.sequence).to.equal(1n);
		}
	}
];

function expectRetired(answer: IStatus, label: string): void {
	expect(answer.status, `${label}: ${answer.detail ?? ''}`).to.equal(
		GuardianStatus.ERR_SET_RETIRED
	);
	expect(answer.detail ?? '').to.match(RETIRED_DETAIL);
}

function expectRetiredSnapshot(
	answer: IGuardianGetHeadResponse,
	expected: GuardianState,
	possiblyStale: boolean
): void {
	expect(answer.status, answer.detail).to.equal(GuardianStatus.OK);
	expect(statesEqual(answer.state as GuardianState, expected)).to.equal(true);
	expect(answer.possiblyStale).to.equal(possiblyStale);
	expect(answer.generation).to.equal(1n);
	expect(answer.rotation, 'the rotation rides GET_HEAD').to.not.equal(
		undefined
	);
	expect(
		encodeRotateSetRequest(answer.rotation!).equals(ROTATION_BYTES)
	).to.equal(true);
}

describe('guardian retirement fence (#711): two connections, one store', () => {
	let dir: string;
	let file: string;
	let open: ReferenceGuardian[];

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-fence-'));
		file = path.join(dir, 'guardian.sqlite');
		open = [];
	});

	afterEach(() => {
		for (const g of open) {
			try {
				g.close();
			} catch {
				// already closed by the test
			}
		}
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function connect(): ReferenceGuardian {
		const g = guardianFor(file);
		open.push(g);
		return g;
	}

	for (const verb of VERBS) {
		describe(verb.name, () => {
			it('committed before the rotation, it is part of the retired snapshot on both connections and after a restart', () => {
				const a = connect();
				const b = connect();
				seed(a);
				verb.prepare?.(file);
				const current = stateOf(a);

				const write = verb.apply(b, current);
				expect(write.status, write.detail).to.equal(verb.before);
				const retire = a.rotateSet(ROTATION);
				expect(retire.status, retire.detail).to.equal(GuardianStatus.OK);

				const fromA = head(a);
				const fromB = head(b);
				expect(fromA.status).to.equal(GuardianStatus.OK);
				expect(fromB.status).to.equal(GuardianStatus.OK);
				verb.committed(fromA);
				verb.committed(fromB);
				expect(
					statesEqual(
						fromA.state as GuardianState,
						fromB.state as GuardianState
					)
				).to.equal(true);
				expect(fromA.rotation).to.not.equal(undefined);
				expect(fromB.rotation).to.not.equal(undefined);

				// Restart: the same snapshot, the same fence.
				a.close();
				b.close();
				const reopened = connect();
				const after = head(reopened);
				expect(after.status).to.equal(GuardianStatus.OK);
				verb.committed(after);
				expect(
					encodeRotateSetRequest(after.rotation!).equals(ROTATION_BYTES)
				).to.equal(true);
				expectRetired(
					verb.apply(reopened, after.state as GuardianState),
					'after restart'
				);
			});

			it('after the rotation, it answers ERR_SET_RETIRED from either connection and commits nothing', () => {
				const a = connect();
				const b = connect();
				seed(a);
				verb.prepare?.(file);
				const current = stateOf(a);
				const stale = head(a).possiblyStale === true;

				expect(a.rotateSet(ROTATION).status).to.equal(GuardianStatus.OK);
				expectRetired(verb.apply(b, current), 'other connection');
				expectRetired(verb.apply(a, current), 'rotating connection');
				expectRetiredSnapshot(head(a), current, stale);
				expectRetiredSnapshot(head(b), current, stale);
			});

			it('validated before the rotation but locked after it, it answers ERR_SET_RETIRED and commits nothing', () => {
				const a = connect();
				const b = connect();
				seed(a);
				verb.prepare?.(file);
				const current = stateOf(a);
				const stale = head(a).possiblyStale === true;

				// Connection B validates the write against the live namespace,
				// then, in the instant before its BEGIN IMMEDIATE, connection A
				// retires the namespace and commits.
				const fired = interposeBeforeWriteLock(b, () => {
					const retire = a.rotateSet(ROTATION);
					expect(retire.status, retire.detail).to.equal(GuardianStatus.OK);
				});
				const answer = verb.apply(b, current);
				expect(fired(), 'the write reached its transaction').to.equal(1);
				expectRetired(answer, 'raced write');

				// Nothing of the write survived the rotation, on either connection.
				expectRetiredSnapshot(head(a), current, stale);
				expectRetiredSnapshot(head(b), current, stale);
			});
		});
	}

	it('registration never re-anchors a retired tombstone: the rotation marker survives', () => {
		const a = connect();
		seed(a);
		expect(a.rotateSet(ROTATION).status).to.equal(GuardianStatus.OK);
		a.close();

		// Lose the registration proof: the open-time verifier tombstones the
		// namespace (no checkpoint at all), and the rotation stays beside it.
		const raw = new Database(file);
		raw
			.prepare('UPDATE guardian_namespaces SET registration_signature = ?')
			.run(Buffer.alloc(64));
		raw.close();

		const alarms: IGuardianAlarm[] = [];
		const reopened = guardianFor(file, OLD_MEMBERS, (alarm) =>
			alarms.push(alarm)
		);
		open.push(reopened);
		expect(
			alarms.some((al) => al.status === GuardianStatus.ERR_STORE_UNCERTAIN)
		).to.equal(true);
		expect(head(reopened).status).to.equal(GuardianStatus.ERR_STORE_UNCERTAIN);
		expect(storedRotation(file)!.equals(ROTATION_BYTES)).to.equal(true);

		// A root-signed registration would re-anchor an ordinary tombstone
		// (wire 5.10 step 1) and rewrite the row with no rotation. A RETIRED
		// tombstone refuses: the fence is permanent, not a column a later
		// write may overwrite.
		expectRetired(reopened.register(registration(1n)), 'tombstone re-anchor');
		expect(storedRotation(file)!.equals(ROTATION_BYTES)).to.equal(true);
		expect(head(reopened).status).to.equal(GuardianStatus.ERR_STORE_UNCERTAIN);
	});

	it('a writer blocked behind the retirement transaction itself sees the marker once it holds the lock', async () => {
		const a = connect();
		seed(a);
		const current = stateOf(a);
		const b = connect();

		// A second THREAD takes BEGIN IMMEDIATE on the store, writes the
		// retirement marker exactly as ROTATE_SET's transaction does, signals,
		// holds the lock for a while, then commits. Connection B's write on
		// this thread starts while the lock is held: its validation runs
		// against the pre-rotation snapshot, its BEGIN IMMEDIATE waits on the
		// busy handler, and it acquires the lock only after the rotation is
		// durable.
		const flags = new Int32Array(new SharedArrayBuffer(8));
		const worker = new Worker(
			[
				"const { workerData } = require('worker_threads');",
				'const Database = require(workerData.sqlite);',
				'const flags = new Int32Array(workerData.flags);',
				'const db = new Database(workerData.file);',
				"db.pragma('busy_timeout = 5000');",
				"db.exec('BEGIN IMMEDIATE');",
				"db.prepare('UPDATE guardian_namespaces SET rotation = ? WHERE recovery_id = ?')",
				'  .run(Buffer.from(workerData.rotation), Buffer.from(workerData.recoveryId));',
				'Atomics.store(flags, 0, 1);',
				'Atomics.notify(flags, 0);',
				'Atomics.wait(flags, 1, 0, workerData.holdMs);',
				"db.exec('COMMIT');",
				'db.close();'
			].join('\n'),
			{
				eval: true,
				workerData: {
					sqlite: require.resolve('better-sqlite3'),
					flags: flags.buffer,
					file,
					rotation: ROTATION_BYTES,
					recoveryId: ROOT.recoveryId,
					holdMs: 400
				}
			}
		);
		const exited = new Promise<number>((resolve, reject) => {
			worker.once('error', reject);
			worker.once('exit', resolve);
		});
		try {
			// Until the worker holds the write lock with the marker pending.
			expect(Atomics.wait(flags, 0, 0, 10_000)).to.not.equal('timed-out');

			const answer = b.putState({ record: SECOND });
			expectRetired(answer, 'write behind the retirement transaction');
		} finally {
			Atomics.store(flags, 1, 1);
			Atomics.notify(flags, 1);
			expect(await exited).to.equal(0);
		}

		expectRetiredSnapshot(head(a), current, false);
		expectRetiredSnapshot(head(b), current, false);
		expect(b.syncRecord({ record: SECOND }).status).to.equal(
			GuardianStatus.ERR_SET_RETIRED
		);
	});

	it('restart preserves the fence for every mutating verb', () => {
		const a = connect();
		seed(a);
		const current = stateOf(a);
		expect(a.rotateSet(ROTATION).status).to.equal(GuardianStatus.OK);
		a.close();

		const reopened = connect();
		expectRetiredSnapshot(head(reopened), current, false);
		for (const verb of VERBS) {
			if (verb.prepare) continue;
			expectRetired(verb.apply(reopened, current), verb.name);
		}
		markPossiblyStale(file);
		const repair = VERBS.find((verb) => verb.prepare === markPossiblyStale)!;
		expectRetired(repair.apply(reopened, current), repair.name);
		expectRetiredSnapshot(head(reopened), current, true);
		// The retirement transaction stays idempotent across the restart.
		expect(reopened.rotateSet(ROTATION).status).to.equal(
			GuardianStatus.OK_DUPLICATE
		);
	});
});

describe('guardian retirement fence (#711): precedence over other verdicts', () => {
	let dir: string;
	let file: string;
	let g: ReferenceGuardian;
	let current: GuardianState;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-guardian-fence-'));
		file = path.join(dir, 'guardian.sqlite');
		g = guardianFor(file);
		seed(g);
		current = stateOf(g);
		expect(g.rotateSet(ROTATION).status).to.equal(GuardianStatus.OK);
	});

	afterEach(() => {
		try {
			g.close();
		} catch {
			// already closed by the test
		}
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('retirement beats an idempotent replay', () => {
		// Before the rotation these were OK_DUPLICATE (the stored artifact).
		expectRetired(g.putState({ record: FIRST }), 'PUT_STATE replay');
		expectRetired(g.syncRecord({ record: FIRST }), 'SYNC_RECORD replay');
		expectRetired(g.register(registration(1n)), 'REGISTER replay');
	});

	it('retirement beats a stale epoch, an ahead epoch, and a sequence gap', () => {
		expectRetired(
			g.putState({ record: record(2n, FIRST.frameHash, { epoch: 2n }) }),
			'fenced epoch'
		);
		expectRetired(
			g.putState({ record: record(2n, FIRST.frameHash, { epoch: 4n }) }),
			'ahead epoch'
		);
		expectRetired(
			g.putState({ record: record(5n, FIRST.frameHash) }),
			'sequence gap'
		);
		expectRetired(
			g.putState({ record: record(2n, sha('not-the-head')) }),
			'previous hash mismatch'
		);
	});

	it('retirement beats a lease CAS mismatch and an old takeover bundle', () => {
		const wrong: GuardianState = { ...current, logHead: genesisLogHead() };
		expectRetired(g.acquireEpoch(acquire(wrong)), 'CAS mismatch');
		const older: GuardianState = {
			...current,
			lease: { epoch: 2n, writerPublicKey: WRITER.pub }
		};
		expectRetired(
			g.syncEpoch({ certificates: takeoverBundle(older) }),
			'bundle older than the local lease'
		);
		expectRetired(
			g.syncEpoch({ certificates: takeoverBundle(current) }),
			'a valid bundle'
		);
	});

	it('retirement beats an uncertain store', () => {
		markPossiblyStale(file);
		expectRetired(g.putState({ record: SECOND }), 'PUT_STATE on a stale store');
		expectRetired(g.acquireEpoch(acquire(current)), 'ACQUIRE on a stale store');
		expectRetired(g.syncRecord({ record: SECOND }), 'SYNC on a stale store');
		expectRetired(
			g.submitRepairEvidence({
				recoveryId: ROOT.recoveryId,
				target: current,
				receipts: quorumReceipts(current),
				certificates: []
			}),
			'repair evidence on a stale store'
		);
		expectRetiredSnapshot(head(g), current, true);
	});

	it('an unregistered namespace is unknown, not retired', () => {
		expect(
			g.putState({ record: record(1n, Buffer.alloc(32), { root: OTHER_ROOT }) })
				.status
		).to.equal(GuardianStatus.ERR_UNKNOWN_NODE);
	});

	it('quarantine beats retirement: a row that is not provably ours answers uncertain', () => {
		g.close();
		const raw = new Database(file);
		raw
			.prepare('UPDATE guardian_namespaces SET guardian_set_id = ?')
			.run(NEW_SET);
		raw.close();

		const alarms: IGuardianAlarm[] = [];
		const reopened = guardianFor(file, OLD_MEMBERS, (alarm) =>
			alarms.push(alarm)
		);
		try {
			expect(alarms.map((al) => al.status)).to.include(
				GuardianStatus.ERR_STORE_UNCERTAIN
			);
			for (const verb of VERBS) {
				expect(verb.apply(reopened, current).status, verb.name).to.equal(
					GuardianStatus.ERR_STORE_UNCERTAIN
				);
			}
			expect(head(reopened).status).to.equal(
				GuardianStatus.ERR_STORE_UNCERTAIN
			);
			// Quarantine is non-destructive: the marker is still there.
			expect(storedRotation(file)!.equals(ROTATION_BYTES)).to.equal(true);
		} finally {
			reopened.close();
		}
	});
});
