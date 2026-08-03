/**
 * Recovery Protocol phase 6, part 1: the durability declaration a frame
 * carries, and the compaction floor a replica depends on
 * (docs/RECOVERY-PROTOCOL.md 5.3, 5.8 and 9).
 *
 * The invariants under test:
 *
 * 1. A journal with no configured mode writes exactly the bytes it wrote
 *    before phase 6, so existing chains keep verifying and keep their hashes.
 * 2. Every frame a configured journal writes declares its mode, deltas and
 *    snapshots alike, and the declaration survives the codec byte for byte.
 * 3. An unrecognised declaration is a corrupt frame, never a tolerated
 *    unknown: the restore path reads this field to decide whether a channel
 *    may resume.
 * 4. Quorum is STICKY. A chain that contains a quorum frame can never be
 *    followed by an unbarriered one, because a certified head reading
 *    'quorum' is exactly what tells a restore its state is complete.
 * 5. RecoveryManager.commit reports the frame its transition landed in, which
 *    is the sequence a barrier waits on.
 * 6. Compaction never prunes a frame a replica still needs. Guardians hold an
 *    immutable chain from a root-committed origin, so a pruned-before-
 *    replicated frame wedges that guardian permanently.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	JOURNAL_META_KEYS,
	RecoveryCriticality,
	RecoveryDurability,
	RecoveryFrame,
	RecoveryJournal,
	RecoveryManager,
	decodeFrame,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	encodeFrame,
	readTipDurability,
	reconstructFromFrames
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ─────────────── Fixtures ───────────────

function sha(value: string): Buffer {
	return crypto.createHash('sha256').update(value).digest();
}

const NODE_SECRET = sha('phase6-durability-node');
const NODE_ID = getPublicKey(NODE_SECRET);
const MASTER_KEY = deriveRecoveryMasterKey(NODE_SECRET);
const ROOT = deriveRecoveryRoot(NODE_SECRET);

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

interface IJournalFixture {
	storage: SqliteStorage;
	journal: RecoveryJournal;
	manager: RecoveryManager;
	refusals: string[];
	forced: string[];
}

function makeJournal(
	options: {
		storage?: SqliteStorage;
		durability?: RecoveryDurability;
		retainFrom?: () => bigint;
		maxRetainedFrames?: number;
		snapshotIntervalFrames?: number;
	} = {}
): IJournalFixture {
	const storage = options.storage ?? openStorage();
	const refusals: string[] = [];
	const forced: string[] = [];
	const journal = new RecoveryJournal(
		storage,
		MASTER_KEY,
		NODE_ID,
		ROOT.recoveryId,
		{
			durability: options.durability,
			retainFrom: options.retainFrom,
			maxRetainedFrames: options.maxRetainedFrames,
			snapshotIntervalFrames: options.snapshotIntervalFrames,
			onDurabilityRefused: (detail): void => {
				refusals.push(detail);
			},
			onCompactionForced: (detail): void => {
				forced.push(detail);
			}
		}
	);
	return {
		storage,
		journal,
		manager: new RecoveryManager(storage, { journal }),
		refusals,
		forced
	};
}

/**
 * Flip a byte of the newest frame's ciphertext in place. saveRecoveryFrame
 * only ever inserts, so damage has to go straight at the row.
 */
function damageTipFrame(storage: SqliteStorage): void {
	const rows = storage.loadRecoveryFrames();
	const tip = rows[rows.length - 1];
	const damaged = Buffer.from(tip.ciphertext);
	damaged[damaged.length - 1] ^= 0xff;
	(
		storage as unknown as {
			db: { prepare: (sql: string) => { run: (...args: unknown[]) => void } };
		}
	).db
		.prepare('UPDATE recovery_frames SET ciphertext = ? WHERE sequence = ?')
		.run(damaged, tip.sequence);
}

/** One journaled transition; returns the frame sequence it landed in. */
function commitOne(manager: RecoveryManager, tag: number): bigint | null {
	const result = manager.commit({
		criticality: RecoveryCriticality.SafetyCritical,
		mutations: [
			{
				type: 'payment_preimage',
				paymentHash: sha(`hash-${tag}`).toString('hex'),
				preimage: sha(`preimage-${tag}`)
			}
		],
		outboundMessages: []
	});
	expect(result.committed).to.equal(true);
	return result.frameSequence;
}

function loadFrames(storage: IStorageBackend): RecoveryFrame[] {
	return new RecoveryJournal(
		storage,
		MASTER_KEY,
		NODE_ID,
		ROOT.recoveryId
	).loadVerifiedFrames();
}

// ─────────────── Tests ───────────────

describe('Recovery phase 6: the durability a frame declares', () => {
	it('a journal with no configured mode writes frames that carry NO declaration', () => {
		const fixture = makeJournal();
		commitOne(fixture.manager, 1);
		commitOne(fixture.manager, 2);

		const frames = loadFrames(fixture.storage);
		expect(frames.length).to.be.greaterThan(0);
		for (const frame of frames) {
			expect(frame.durability).to.equal(undefined);
		}
		// The whole point of the optional key: a frame without a declaration
		// encodes to the same bytes it did before phase 6, so pre-existing
		// chains keep their hashes and keep verifying.
		const reEncoded = encodeFrame(frames[0]);
		expect(JSON.parse(reEncoded.toString('utf8')).durability).to.equal(
			undefined
		);
		fixture.storage.close();
	});

	it('every frame a configured journal writes declares the mode, snapshots included', () => {
		const fixture = makeJournal({
			durability: 'quorum',
			snapshotIntervalFrames: 2
		});
		for (let i = 0; i < 6; i++) commitOne(fixture.manager, i);

		const frames = loadFrames(fixture.storage);
		const snapshots = frames.filter((frame) => frame.snapshot !== undefined);
		expect(snapshots.length).to.be.greaterThan(0);
		for (const frame of frames) {
			expect(frame.durability).to.equal('quorum');
		}
		fixture.storage.close();
	});

	it('the declaration survives the codec byte for byte, so the frame hash is stable', () => {
		const fixture = makeJournal({ durability: 'async-remote' });
		commitOne(fixture.manager, 1);
		const rows = fixture.storage.loadRecoveryFrames();
		const frames = loadFrames(fixture.storage);

		for (let i = 0; i < frames.length; i++) {
			const reEncoded = encodeFrame(frames[i]);
			expect(decodeFrame(reEncoded).durability).to.equal('async-remote');
			// Re-encoding a decoded frame must reproduce the stored hash, or
			// the chain would break the first time anything round trips.
			expect(
				crypto
					.createHash('sha256')
					.update(reEncoded)
					.digest()
					.equals(rows[i].frameHash)
			).to.equal(true);
		}
		fixture.storage.close();
	});

	it('an UNRECOGNISED declaration is rejected as corruption, never silently dropped', () => {
		const fixture = makeJournal({ durability: 'quorum' });
		commitOne(fixture.manager, 1);
		const frames = loadFrames(fixture.storage);
		const encoded = JSON.parse(encodeFrame(frames[0]).toString('utf8'));
		encoded.durability = 'best-effort';

		expect(() =>
			decodeFrame(Buffer.from(JSON.stringify(encoded), 'utf8'))
		).to.throw(/durability/);
		fixture.storage.close();
	});
});

describe('Recovery phase 6: quorum is sticky', () => {
	it('a configured downgrade is REFUSED once the chain contains a quorum frame', () => {
		const storage = openStorage();
		const first = makeJournal({ storage, durability: 'quorum' });
		commitOne(first.manager, 1);
		expect(first.journal.getDurability()).to.equal('quorum');
		expect(first.refusals.length).to.equal(0);

		// A second run of the same node with the config flipped back.
		const second = makeJournal({ storage, durability: 'async-remote' });
		expect(second.journal.getDurability()).to.equal('quorum');
		expect(second.refusals.length).to.equal(1);
		expect(second.refusals[0]).to.contain('quorum');

		commitOne(second.manager, 2);
		for (const frame of loadFrames(storage)) {
			expect(frame.durability).to.equal('quorum');
		}
		storage.close();
	});

	it('the refusal stands on the META FLOOR alone when the tip frame is unreadable', () => {
		const storage = openStorage();
		const first = makeJournal({ storage, durability: 'quorum' });
		commitOne(first.manager, 1);
		expect(storage.getRecoveryMeta(JOURNAL_META_KEYS.durabilityFloor)).to.equal(
			'quorum'
		);

		// Corrupt the tip frame's payload. The floor is the other half of the
		// evidence precisely for this case.
		damageTipFrame(storage);
		expect(readTipDurability(storage, MASTER_KEY, NODE_ID).tip).to.equal(
			'unreadable'
		);

		const second = makeJournal({ storage, durability: 'local' });
		expect(second.journal.getDurability()).to.equal('quorum');
		storage.close();
	});

	it('the refusal stands on the TIP FRAME alone when the floor is missing', () => {
		const storage = openStorage();
		const first = makeJournal({ storage, durability: 'quorum' });
		commitOne(first.manager, 1);
		storage.deleteRecoveryMeta(JOURNAL_META_KEYS.durabilityFloor);
		expect(storage.getRecoveryMeta(JOURNAL_META_KEYS.durabilityFloor)).to.equal(
			null
		);

		const second = makeJournal({ storage, durability: 'local' });
		expect(second.journal.getDurability()).to.equal('quorum');
		storage.close();
	});

	it('an UPGRADE into quorum needs no rule, since it only adds barriers', () => {
		const storage = openStorage();
		const first = makeJournal({ storage, durability: 'async-remote' });
		commitOne(first.manager, 1);

		const second = makeJournal({ storage, durability: 'quorum' });
		expect(second.journal.getDurability()).to.equal('quorum');
		expect(second.refusals.length).to.equal(0);
		storage.close();
	});

	it('a damaged tip with NO quorum history does not freeze an ordinary journal', () => {
		const storage = openStorage();
		const first = makeJournal({ storage, durability: 'async-remote' });
		commitOne(first.manager, 1);
		damageTipFrame(storage);

		// Fail-closed here would time out live HTLCs on a node that never
		// promised anything, and a chain this damaged cannot be verified by a
		// restorer anyway.
		const second = makeJournal({ storage, durability: 'async-remote' });
		expect(second.journal.getDurability()).to.equal('async-remote');
		storage.close();
	});
});

describe('Recovery phase 6: naming the frame a barrier waits on', () => {
	it('commit reports the sequence its transition actually landed in', () => {
		const fixture = makeJournal({ durability: 'quorum' });
		const first = commitOne(fixture.manager, 1);
		const second = commitOne(fixture.manager, 2);
		const third = commitOne(fixture.manager, 3);

		expect(first).to.equal(1n);
		expect(second).to.equal(2n);
		expect(third).to.equal(3n);
		expect(fixture.journal.getTip()?.sequence).to.equal(3n);
		fixture.storage.close();
	});

	it('an unjournaled or Reconstructable commit reports no frame at all', () => {
		const storage = openStorage();
		const plain = new RecoveryManager(storage);
		const unjournaled = plain.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('plain').toString('hex'),
					preimage: sha('plain-preimage')
				}
			],
			outboundMessages: []
		});
		expect(unjournaled.committed).to.equal(true);
		expect(unjournaled.frameSequence).to.equal(null);

		const fixture = makeJournal({ durability: 'quorum' });
		const reconstructable = fixture.manager.commit({
			criticality: RecoveryCriticality.Reconstructable,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('recon').toString('hex'),
					preimage: sha('recon-preimage')
				}
			],
			outboundMessages: []
		});
		expect(reconstructable.committed).to.equal(true);
		expect(reconstructable.frameSequence).to.equal(null);

		storage.close();
		fixture.storage.close();
	});
});

describe('Recovery phase 6: compaction never outruns a replica', () => {
	it('holds the prune back while a replica still needs frames below the snapshot', () => {
		const replicatedThrough = 0n;
		const fixture = makeJournal({
			durability: 'quorum',
			snapshotIntervalFrames: 2,
			retainFrom: (): bigint => replicatedThrough + 1n
		});
		for (let i = 0; i < 6; i++) commitOne(fixture.manager, i);

		// Nothing replicated, so nothing may be pruned: a guardian accepts only
		// logHead.sequence + 1, and a frame deleted before it got there can
		// never be delivered.
		const rows = fixture.storage.loadRecoveryFrames();
		expect(rows[0].sequence).to.equal(1);
		// The verified base stayed where the retained frames start, so the
		// chain still verifies even though newer snapshots exist above it.
		expect(loadFrames(fixture.storage).length).to.equal(rows.length);
		expect(fixture.forced.length).to.equal(0);
		fixture.storage.close();
	});

	it('prunes as soon as the replica catches up, and the chain still verifies', () => {
		let replicatedThrough = 0n;
		const fixture = makeJournal({
			durability: 'quorum',
			snapshotIntervalFrames: 2,
			retainFrom: (): bigint => replicatedThrough + 1n
		});
		for (let i = 0; i < 6; i++) commitOne(fixture.manager, i);
		const before = fixture.storage.loadRecoveryFrames().length;

		replicatedThrough = BigInt(fixture.journal.getTip()!.sequence);
		fixture.journal.compact();

		const after = fixture.storage.loadRecoveryFrames();
		expect(after.length).to.be.lessThan(before);
		expect(after[0].sequence).to.equal(
			Number(fixture.storage.getRecoveryMeta(JOURNAL_META_KEYS.lastSnapshot))
		);
		expect(loadFrames(fixture.storage).length).to.equal(after.length);
		fixture.storage.close();
	});

	it('a chain carrying an UNPRUNED snapshot still reconstructs byte-identically', () => {
		const replicatedThrough = 0n;
		const fixture = makeJournal({
			durability: 'quorum',
			snapshotIntervalFrames: 2,
			retainFrom: (): bigint => replicatedThrough + 1n
		});
		for (let i = 0; i < 6; i++) commitOne(fixture.manager, i);

		const source = fixture.storage;
		const sourcePreimages = source
			.loadAllPreimages()
			.map((row) => `${row.paymentHash}:${row.preimage.toString('hex')}`)
			.sort();

		const target = openStorage();
		reconstructFromFrames(target, loadFrames(source));
		const rebuilt = target
			.loadAllPreimages()
			.map((row) => `${row.paymentHash}:${row.preimage.toString('hex')}`)
			.sort();

		expect(rebuilt).to.deep.equal(sourcePreimages);
		source.close();
		target.close();
	});

	it('forces the prune past the retention ceiling and REPORTS the lost backfill', () => {
		const fixture = makeJournal({
			durability: 'quorum',
			snapshotIntervalFrames: 2,
			maxRetainedFrames: 3,
			retainFrom: (): bigint => 1n
		});
		for (let i = 0; i < 10; i++) commitOne(fixture.manager, i);

		expect(fixture.forced.length).to.be.greaterThan(0);
		expect(fixture.forced[0]).to.contain('re-provisioned');
		const rows = fixture.storage.loadRecoveryFrames();
		expect(rows[0].sequence).to.be.greaterThan(1);
		expect(loadFrames(fixture.storage).length).to.equal(rows.length);
		fixture.storage.close();
	});

	it('a journal with no replica compacts exactly as it did before phase 6', () => {
		const fixture = makeJournal({ snapshotIntervalFrames: 2 });
		for (let i = 0; i < 6; i++) commitOne(fixture.manager, i);

		const rows = fixture.storage.loadRecoveryFrames();
		expect(rows[0].sequence).to.equal(
			Number(fixture.storage.getRecoveryMeta(JOURNAL_META_KEYS.lastSnapshot))
		);
		expect(rows[0].sequence).to.be.greaterThan(1);
		fixture.storage.close();
	});
});
