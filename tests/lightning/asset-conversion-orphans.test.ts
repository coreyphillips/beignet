/**
 * #2151 Step 4a, amendment v2.2 (B1 and B2): quiet holds only for a record
 * that a live attempt owns. An odd count of the scope that no live attempt
 * holds is an orphan: it is withdrawn when it is met, at a quiet read or in
 * `start` or `assess`, and it never makes the channel quiet, since nothing
 * is signed in this build. A failure is reported once.
 *
 * The first two groups are the diff review's proofs (findings 1 and 2):
 * - a crash restart whose sweep cannot list the scope leaves the record
 *   open with no live attempt;
 * - a record whose append and re-read both fail is pulled in by a later
 *   read, again with no live attempt.
 * The third group pins guards the site audit listed as green with no test
 * (G1 to G3, the sweep's outer wrap and the strict reader with planted rows).
 * The fourth pins the order of an end and its report when a send throws
 * (amendments B4 and B5).
 *
 * Amendment v2.4 adds the recheck's proofs: the host hears each
 * pre-restart attempt's end exactly once (D1, R1 and R3), a copy that
 * cannot convert never runs the orphan rule (D2), and the four guards the
 * v2.2 mutation table left green get a test each (K12, K13, K14 and K17).
 */
import { expect } from 'chai';
import { createHash } from 'crypto';
import path from 'path';
import sinon from 'sinon';
import type Database from 'better-sqlite3';
import type { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import { MessageType } from '../../src/lightning/message/types';
import { checkedConversionAttempts } from '../../src/lightning/storage/final-conversion-attempt';
import { FinalDeviceJournal } from '../../src/lightning/storage/final-device-journal';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { plainTypePair, scratch } from './helpers/channel-type-pairs';
import { deviceAuthority } from './helpers/channel-type-record';
import {
	ATTEMPT_SCOPE,
	ATTEMPT_TEXTS,
	attemptEvents,
	attemptRowCount,
	attemptStorage,
	conversionQuiet,
	type ConversionAttemptEvent,
	type IConversionAttemptFields
} from './helpers/conversion-attempts';
import {
	abandoned,
	abortText,
	attemptOf,
	conversionDeps,
	conversionPair,
	FENCE,
	held,
	parentHeight,
	roleOf,
	settleOnce,
	startConversion,
	stfu,
	storeTerms,
	stubConversionDescription,
	stubProposal,
	tick,
	track,
	txAbort,
	updateRound,
	type IConversionPair
} from './helpers/conversion-managers';

const REF = Buffer.alloc(8, 0x4b);
/** ASSET_CONVERSION_TEXTS.held. */
const HELD = 'A conversion of this channel is in progress';
const OTHER_ATTEMPT = 'Another conversion of this channel is in progress';
const {
	notRecorded: NOT_RECORDED,
	withdrawalFailed: WITHDRAWAL_FAILED,
	restart: RESTART,
	invalid: INVALID
} = ATTEMPT_TEXTS;
const LOCKED = 'database is locked';
const IO = 'disk I/O error';
/** startFinalSplice's refusal past the quiet gate, for a side with no peer. */
const NO_SPLICE =
	'Final splice requires live funding and negotiated quiescence and splicing';
const EXPIRED = 'Asset conversion agreement has expired';

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();
type TermsOptions = Parameters<typeof storeTerms>[2];

/** Every host member answers at once; terms come from each side's own store. */
function clean(p: IConversionPair, terms: TermsOptions = {}): void {
	for (const i of [0, 1] as const) {
		const h = p.hosts[i];
		h.verify = (): unknown => true;
		h.abandon = (): unknown => undefined;
		h.propose = (): unknown => stubProposal(i);
		h.describe = (ctx, _proposals, bitcoin): unknown =>
			stubConversionDescription(ctx, h.termsFor(ctx), bitcoin);
		h.prepare = (ctx, proposals, bitcoin, layoutDigest): unknown =>
			h.planFor(ctx, proposals, bitcoin, layoutDigest);
		p.feerateEstimates[i] = async (): Promise<number> => 1000;
		h.terms = (ctx, request): ReturnType<typeof storeTerms> =>
			storeTerms(p.stores[i], ctx.channelId, {
				...terms,
				reference: request.reference
			});
	}
}

/** Side `I` starts a conversion and the link runs until idle. */
async function run(
	p: IConversionPair,
	I: 0 | 1
): Promise<ReturnType<typeof track>> {
	const start = track(
		startConversion(p.managers[I], p.channelId, { reference: REF })
	);
	await p.settle();
	await start.done;
	return start;
}

/** The scope's events of side i since row `from`, a withdrawal shown by its reason. */
const kindsSince = (p: IConversionPair, i: 0 | 1, from: number): string[] =>
	attemptEvents(p.stores[i], p.id)
		.slice(from)
		.map((e: ConversionAttemptEvent) =>
			e.kind === 'conversion-withdrawn' ? e.reason : e.kind
		);
const rows = (p: IConversionPair, i: 0 | 1): number =>
	attemptRowCount(p.stores[i], p.id);

/** Side i's reports from now on, with the channel each names. */
function reportsOf(manager: ChannelManager): [string, string][] {
	const out: [string, string][] = [];
	manager.on('error', (id: Buffer | null, reason: string): void => {
		out.push([id ? id.toString('hex') : String(id), reason]);
	});
	return out;
}

/** Make the sweep's listing (its one GROUP BY) on `store` throw, once. */
function failListing(store: SqliteStorage): {
	count: () => number;
	restore: () => void;
} {
	const db = (store as unknown as { db: Database.Database }).db;
	const prepare = db.prepare.bind(db);
	let listings = 0;
	const stub = sinon.stub(db, 'prepare').callsFake(((sql: string) => {
		if (sql.includes('GROUP BY channel_id') && listings++ === 0)
			throw new Error(LOCKED);
		return prepare(sql);
	}) as typeof db.prepare);
	return { count: () => listings, restore: () => stub.restore() };
}

/** Make side i's device commits of the scope throw before the commit, `times` times. */
function failCommits(
	p: IConversionPair,
	i: 0 | 1,
	times: number
): { failures: () => number } {
	const authority = deviceAuthority(p.stores[i]);
	const commit = authority.commitLifecycleEntry.bind(authority);
	let failed = 0;
	sinon
		.stub(authority, 'commitLifecycleEntry')
		.callsFake((slot: string, value: string) => {
			if (slot.startsWith(ATTEMPT_SCOPE + '/') && failed < times) {
				failed++;
				throw new Error('device commit failed');
			}
			commit(slot, value);
		});
	return { failures: () => failed };
}

/**
 * Both sides pass their own layout_ack (held on the link), then the opener
 * crashes and its rebuilt manager's sweep cannot list the scope: the
 * record stays open with no live attempt. Returns the opener's row count
 * before the attempt, its reports from the rebuild on, its host's abandon
 * count and the context its host verified.
 */
async function strand(p: IConversionPair): Promise<{
	side: 0 | 1;
	base: number;
	reports: [string, string][];
	told: number;
	ctx: unknown;
}> {
	const side = p.opener;
	const base = rows(p, side);
	p.link.hold('asset_splice:4');
	expect((await run(p, 0)).error, 'start').to.equal(undefined);
	expect(rows(p, side) - base, 'recorded').to.equal(1);
	const verified = p.hosts[side].calls('verifyConversionTerms');
	const ctx = verified[verified.length - 1].args[0];
	const told = abandoned(p, side).length;
	const listing = failListing(p.stores[side]);
	p.link.clearRules();
	p.link.held.splice(0);
	p.crash(side);
	const reports = reportsOf(p.managers[side]);
	await settleOnce();
	listing.restore();
	expect(listing.count(), 'the listing ran and failed').to.equal(1);
	expect(held(p.managers[side], p.id), 'no live attempt').to.equal(false);
	return { side, base, reports, told, ctx };
}

/**
 * Make side i's scope reads through the device journal throw while `on()`
 * holds, only for side i's database (`on` is asked only for those reads).
 */
function failReads(
	p: IConversionPair,
	i: 0 | 1,
	on: () => boolean
): { count: () => number } {
	const db = (p.stores[i] as unknown as { db: Database.Database }).db;
	const read = FinalDeviceJournal.prototype.read;
	let failed = 0;
	sinon.stub(FinalDeviceJournal.prototype, 'read').callsFake(function (
		this: FinalDeviceJournal,
		...args: unknown[]
	) {
		if (
			args[0] === ATTEMPT_SCOPE &&
			(this as unknown as { db: unknown }).db === db &&
			on()
		) {
			failed++;
			throw new Error(IO);
		}
		return (read as (...a: unknown[]) => unknown).apply(this, args);
	} as typeof read);
	return { count: () => failed };
}

/**
 * Side i's next device commit of the scope lands and then throws (the
 * wallet row is not written), and every scope read of side i fails until
 * `stop()`: the row is on the device only. `stop()` restores every stub.
 */
function deviceOnlyNextWrite(
	p: IConversionPair,
	i: 0 | 1
): { landed: () => boolean; stop: () => void } {
	let failing = false;
	let done = false;
	const authority = deviceAuthority(p.stores[i]);
	const commit = authority.commitLifecycleEntry.bind(authority);
	sinon
		.stub(authority, 'commitLifecycleEntry')
		.callsFake((slot: string, value: string) => {
			commit(slot, value);
			if (slot.startsWith(ATTEMPT_SCOPE + '/') && !done) {
				done = true;
				failing = true;
				throw new Error(IO);
			}
		});
	failReads(p, i, () => failing);
	return {
		landed: () => done,
		stop: (): void => {
			failing = false;
			sinon.restore();
		}
	};
}

/** Pause side i's prepareConversion until the returned release runs. */
function gatePrepare(
	p: IConversionPair,
	i: 0 | 1
): { reached: () => boolean; release: () => void } {
	let reached = false;
	let open!: () => void;
	const gate = new Promise<void>((done) => (open = done));
	const prepare = p.hosts[i].prepare as (...a: unknown[]) => unknown;
	p.hosts[i].prepare = (...args: unknown[]): unknown => {
		reached = true;
		return gate.then(() => prepare(...args));
	};
	return { reached: () => reached, release: () => open() };
}

/**
 * Attempt 1 of `side` writes its record to the device only (its wallet
 * insert and every re-read fail), so it ends unrecorded as far as it knows.
 * Returns the side's row count before it.
 */
async function deviceOnlyRecord(
	p: IConversionPair,
	side: 0 | 1
): Promise<number> {
	const base = rows(p, side);
	const told = abandoned(p, side).length;
	const write = deviceOnlyNextWrite(p, side);
	await run(p, 0);
	await p.settle();
	write.stop();
	expect(write.landed(), 'the device commit ran').to.equal(true);
	expect(held(p.managers[side], p.id), 'attempt 1 is over').to.equal(false);
	expect(abandoned(p, side).slice(told), 'its end').to.deep.equal([
		NOT_RECORDED
	]);
	expect(rows(p, side) - base, 'not in the wallet').to.equal(0);
	return base;
}

/** A valid attempt record for direct writes on `store`'s channel `id`. */
function sampleRecord(
	store: SqliteStorage,
	id: string,
	peer: string,
	attempt = 'a1'.repeat(32)
): IConversionAttemptFields {
	const current = store.loadFinalChannelType(id)!;
	return {
		attempt,
		peer,
		isInitiator: true,
		isOpener: roleOf(store, id) === 'opener',
		giver: 'opener',
		direction: current.type === 'plain' ? 'to-asset' : 'to-plain',
		parent: {
			txid: current.funding.txid,
			outputIndex: current.funding.outputIndex,
			stateNumber: parentHeight(store, id, current.type).toString(),
			type: current.type,
			channelType: current.channelType
		},
		termsDigest: 'b2'.repeat(32),
		layoutDigest: 'c3'.repeat(32),
		planDigest: 'd4'.repeat(32),
		agreement: 'e5'.repeat(32),
		keyIndex: 7
	};
}

type Send = (peer: string, type: number, payload: Buffer) => void;
/** Make side i's conversion sends of tx_abort throw; returns the undo. */
function failAbortSends(p: IConversionPair, i: 0 | 1): () => void {
	const deps = conversionDeps(p.managers[i]);
	const send = deps.send as Send;
	deps.send = (peer: string, type: number, payload: Buffer): void => {
		if (type === MessageType.TX_ABORT) throw new Error('the send failed');
		send(peer, type, payload);
	};
	return () => (deps.send = send);
}

/** Append an event to the scope through the device journal, past the writers. */
function plant(store: SqliteStorage, id: string, event: unknown): void {
	const journal = (
		store as unknown as { finalJournal(): FinalDeviceJournal }
	).finalJournal();
	const { sequence, hash } = journal.read<unknown>(ATTEMPT_SCOPE, id);
	journal.append(ATTEMPT_SCOPE, id, { sequence, hash }, event);
}

describe('Asset conversion orphans (#2151 step 4a, amendments B1 and B2)', function () {
	this.timeout(240000);
	const s = scratch('conversion-orphans-');
	let clock: sinon.SinonFakeTimers | undefined;
	const fresh = async (
		options?: Parameters<typeof conversionPair>[2]
	): Promise<IConversionPair> => {
		const p = await conversionPair(s, 'plain', options);
		clean(p);
		return p;
	};
	afterEach(() => {
		clock?.restore();
		clock = undefined;
		sinon.restore();
	});
	after(() => s.release());

	describe('A sweep whose listing fails (diff review finding 1)', () => {
		it('F1: withdraws the orphan at the next quiet read, reads not quiet, reports the listing failure once and tells the host once', async () => {
			const p = await fresh();
			const { side, base, reports, told, ctx } = await strand(p);
			const m = p.managers[side];
			expect(rows(p, side) - base, 'open after the sweep').to.equal(1);
			const reads = [0, 1, 2].map(() => conversionQuiet(m, p.id));
			expect(reads, 'not quiet').to.deep.equal([false, false, false]);
			expect(
				kindsSince(p, side, base),
				'withdrawn at the first read'
			).to.deep.equal(['conversion-attempt', RESTART]);
			await settleOnce();
			expect(reports, 'the listing failure, once').to.deep.equal([
				[p.id, WITHDRAWAL_FAILED + LOCKED]
			]);
			const calls = p.hosts[side].calls('abandonConversion').slice(told);
			expect(
				calls.map((c) => c.args),
				'the host hears the end once, with the rebuilt context'
			).to.deep.equal([[ctx, RESTART]]);
			await p.reconnect();
			await updateRound(p);
			await settleOnce();
			expect(reports, 'nothing more').to.have.length(1);
			expect(abandoned(p, side).slice(told), 'no second call').to.deep.equal([
				RESTART
			]);
		});

		it('F1b: lets the side fail and fulfil the HTLCs the peer adds afterwards', async () => {
			const p = await fresh();
			const { side } = await strand(p);
			await p.reconnect();
			await settleOnce();
			const peer = (1 - side) as 0 | 1;
			const preimages = [0x31, 0x32].map((b) => Buffer.alloc(32, b));
			for (const preimage of preimages) {
				const added = await Promise.resolve(
					p.managers[peer].addHtlc(
						p.channelId,
						1_000_000n,
						sha256(preimage),
						600_000 + 100,
						Buffer.alloc(1366)
					)
				).catch((e: Error) => ({ ok: false, error: e.message }));
				expect(
					(added as { ok?: boolean }).ok,
					'the peer adds an HTLC'
				).to.equal(true);
				await p.settle();
			}
			const view = (
				p.stores[side] as unknown as {
					finalUpdateView(id: string): {
						views: { s: { locked: { htlcs: unknown[] } } }[];
					} | null;
				}
			).finalUpdateView(p.id);
			expect(view?.views[0].s.locked.htlcs.length, 'locked in').to.equal(2);
			const m = p.managers[side];
			const failed = m.failHtlc(p.channelId, 0n, Buffer.alloc(32));
			const fulfilled = m.fulfillHtlc(p.channelId, 1n, preimages[1]);
			expect({
				fail: failed.ok ? 'ok' : failed.error,
				fulfil: fulfilled.ok ? 'ok' : fulfilled.error
			}).to.deep.equal({ fail: 'ok', fulfil: 'ok' });
			await p.settle();
			expect(HELD).to.be.a('string');
		});

		for (const where of ['start', 'assess'] as const)
			it(`F1c: withdraws the orphan in ${where}, and the new conversion goes on to the fence`, async () => {
				const p = await fresh();
				const { side, base, reports, told } = await strand(p);
				await p.reconnect();
				expect(rows(p, side) - base, 'open before the ' + where).to.equal(1);
				const I = where === 'start' ? side : ((1 - side) as 0 | 1);
				const start = await run(p, I);
				expect(start.error, 'not ' + OTHER_ATTEMPT).to.equal(undefined);
				expect(kindsSince(p, side, base)).to.deep.equal([
					'conversion-attempt',
					RESTART,
					'conversion-attempt',
					FENCE
				]);
				await settleOnce();
				expect(reports, 'the listing failure, once').to.deep.equal([
					[p.id, WITHDRAWAL_FAILED + LOCKED]
				]);
				expect(abandoned(p, side).slice(told)).to.deep.equal([RESTART, FENCE]);
			});

		it('F1d: reports an orphan withdrawal that fails once, reads not quiet throughout, and withdraws it at a later read', async () => {
			const p = await fresh();
			const { side, base, reports, told } = await strand(p);
			const m = p.managers[side];
			const commits = failCommits(p, side, 2);
			const reads = [0, 1, 2].map(() => conversionQuiet(m, p.id));
			expect(reads, 'not quiet').to.deep.equal([false, false, false]);
			expect(commits.failures(), 'two reads failed to withdraw').to.equal(2);
			expect(
				kindsSince(p, side, base),
				'the third read withdrew it'
			).to.deep.equal(['conversion-attempt', RESTART]);
			await settleOnce();
			expect(reports, 'each failure once').to.deep.equal([
				[p.id, WITHDRAWAL_FAILED + LOCKED],
				[p.id, WITHDRAWAL_FAILED + 'device commit failed']
			]);
			expect(abandoned(p, side).slice(told), 'one host call').to.deep.equal([
				RESTART
			]);
		});

		it('F1e: tells the host once when the first read of the orphan fails, its next withdrawal fails and a third succeeds', async () => {
			const p = await fresh();
			const { side, base, reports, told, ctx } = await strand(p);
			const m = p.managers[side];
			const read = FinalDeviceJournal.prototype.read;
			let reads = 0;
			sinon.stub(FinalDeviceJournal.prototype, 'read').callsFake(function (
				this: FinalDeviceJournal,
				...args: unknown[]
			) {
				if (args[0] === ATTEMPT_SCOPE && reads++ === 0)
					throw new Error('disk I/O error');
				return (read as (...a: unknown[]) => unknown).apply(this, args);
			} as typeof read);
			const commits = failCommits(p, side, 1);
			const quiet = [0, 1, 2].map(() => conversionQuiet(m, p.id));
			expect(quiet, 'not quiet').to.deep.equal([false, false, false]);
			expect(
				commits.failures(),
				"the second read's withdrawal failed"
			).to.equal(1);
			expect(
				kindsSince(p, side, base),
				'the third read withdrew it'
			).to.deep.equal(['conversion-attempt', RESTART]);
			await settleOnce();
			expect(
				reports,
				'the listing and the first failure, once each'
			).to.deep.equal([
				[p.id, WITHDRAWAL_FAILED + LOCKED],
				[p.id, WITHDRAWAL_FAILED + 'disk I/O error']
			]);
			const calls = p.hosts[side].calls('abandonConversion').slice(told);
			expect(
				calls.map((c) => c.args),
				'the host hears the end once, once the record is read'
			).to.deep.equal([[ctx, RESTART]]);
		});

		it("T24: builds the manager when the sweep's listing throws, which the sweep contains (green on the base)", async () => {
			const p = await fresh();
			const side = p.opener;
			p.link.hold('asset_splice:4');
			expect((await run(p, 0)).error, 'start').to.equal(undefined);
			const listing = failListing(p.stores[side]);
			const old = p.managers[side];
			p.link.clearRules();
			p.link.held.splice(0);
			expect(
				() => p.crash(side),
				'the constructor never throws'
			).to.not.throw();
			listing.restore();
			expect(listing.count(), 'the listing ran and failed').to.equal(1);
			expect(p.managers[side], 'rebuilt').to.not.equal(old);
			await settleOnce();
			await p.reconnect();
		});
	});

	describe('A record pulled in after its append and its re-read failed (diff review finding 2)', () => {
		it('F2: withdraws the pulled-in orphan at the next quiet read, which reads not quiet, and the store error is reported once', async () => {
			const p = await fresh();
			const side = p.opener;
			const base = rows(p, side);
			const told = abandoned(p, side).length;
			// The record's wallet insert fails after its device commit, and every
			// read of the scope (which would pull the device-ahead row in) fails
			// too until the attempt is over.
			let failing = false;
			const authority = deviceAuthority(p.stores[side]);
			const commit = authority.commitLifecycleEntry.bind(authority);
			let records = 0;
			sinon
				.stub(authority, 'commitLifecycleEntry')
				.callsFake((slot: string, value: string) => {
					commit(slot, value);
					if (slot.startsWith(ATTEMPT_SCOPE + '/') && records++ === 0) {
						failing = true;
						throw new Error('disk I/O error');
					}
				});
			const read = FinalDeviceJournal.prototype.read;
			sinon.stub(FinalDeviceJournal.prototype, 'read').callsFake(function (
				this: FinalDeviceJournal,
				...args: unknown[]
			) {
				if (failing && args[0] === ATTEMPT_SCOPE)
					throw new Error('disk I/O error');
				return (read as (...a: unknown[]) => unknown).apply(this, args);
			} as typeof read);
			await run(p, 0);
			await p.settle();
			failing = false;
			sinon.restore();
			const m = p.managers[side];
			expect(held(m, p.id), 'the attempt is over').to.equal(false);
			expect(abandoned(p, side).slice(told), 'its end').to.deep.equal([
				NOT_RECORDED
			]);
			expect(rows(p, side) - base, 'not in the wallet').to.equal(0);
			expect(conversionQuiet(m, p.id), 'not quiet yet').to.equal(false);
			const reports = reportsOf(m);
			// A backup reconciles every final opening first, which pulls the
			// device-ahead row in.
			await p.stores[side].backup(path.join(s.dir(), 'backup.db'));
			expect(rows(p, side) - base, 'pulled in').to.equal(1);
			expect(conversionQuiet(m, p.id), 'not quiet').to.equal(false);
			expect(kindsSince(p, side, base), 'withdrawn at that read').to.deep.equal(
				['conversion-attempt', RESTART]
			);
			await updateRound(p);
			await settleOnce();
			expect(
				p.errors[side].filter((e) => e.includes('disk I/O error')),
				'the store error, once'
			).to.have.length(1);
			expect(reports, 'nothing more reported').to.deep.equal([]);
			expect(
				abandoned(p, side).slice(told),
				'no second host call'
			).to.deep.equal([NOT_RECORDED]);
		});
	});

	describe('Guards with no test before (diff review mutation gaps, amendment B2)', () => {
		it('G1 (T23): a start right after a failed withdrawal, with no quiet read between, withdraws it first and goes on', async () => {
			const p = await fresh();
			const base = rows(p, 0);
			p.link.hold('asset_splice:4');
			expect((await run(p, 0)).error, 'first').to.equal(undefined);
			// Side 0's first withdrawal fails before its device commit; the store
			// then recovers.
			const commits = failCommits(p, 0, 1);
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect(commits.failures(), 'the withdrawal failed once').to.equal(1);
			expect(rows(p, 0) - base, 'still odd').to.equal(1);
			// No quiet read: the next start is the first reader.
			const second = await run(p, 0);
			expect(second.error, 'not ' + OTHER_ATTEMPT).to.equal(undefined);
			expect(kindsSince(p, 0, base)).to.deep.equal([
				'conversion-attempt',
				FENCE,
				'conversion-attempt',
				FENCE
			]);
		});

		it('G2 (S14 and T28): a manager built over a generation 5 store runs no conversion-attempt query', async () => {
			const p = await fresh({ generations: [5, 5] });
			const db = (p.stores[0] as unknown as { db: Database.Database }).db;
			const spy = sinon.spy(db, 'prepare');
			p.crash(0);
			await settleOnce();
			conversionQuiet(p.managers[0], p.id);
			const sql = spy.args
				.map((a: unknown[]) => String(a[0]))
				.filter((q: string) => q.includes(ATTEMPT_SCOPE));
			expect(sql, 'no conversion-attempt query').to.deep.equal([]);
		});

		it('G3 (T9): terms that expire while prepareConversion waits are neither recorded nor acknowledged (fake clock)', async () => {
			const p = await fresh();
			// The terms expire 8 s from now; side 0's prepare answers after 9 s.
			clean(p, { expiresAt: Math.floor(Date.now() / 1000) + 8 });
			let called = false;
			const prepare = p.hosts[0].prepare;
			p.hosts[0].prepare = (...args: unknown[]): unknown => {
				called = true;
				return new Promise((done) =>
					setTimeout(
						() => done((prepare as (...a: unknown[]) => unknown)(...args)),
						9000
					)
				);
			};
			const base = rows(p, 0);
			const mark = p.link.sent.length;
			clock = sinon.useFakeTimers({
				now: Date.now(),
				toFake: ['Date', 'setTimeout', 'clearTimeout']
			});
			const start = track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			);
			await p.settle();
			await start.done;
			expect(start.error, 'start').to.equal(undefined);
			expect(called, 'prepare was reached').to.equal(true);
			await tick(p, clock, 9500);
			const fromSide0 = p.link.sent.slice(mark).filter((m) => m.from === 0);
			expect(
				fromSide0.filter((m) => m.name === 'asset_splice:4'),
				"side 0's layout_ack"
			).to.have.length(0);
			expect(
				fromSide0.filter((m) => m.name === 'TX_ABORT').map(abortText),
				'the recheck refused it'
			).to.deep.equal([EXPIRED]);
			expect(rows(p, 0) - base, 'no record').to.equal(0);
		});

		describe('The strict reader with planted rows (S16 and S17)', () => {
			const stores = (): {
				store: SqliteStorage;
				id: string;
				record: IConversionAttemptFields;
			} => {
				const pair = plainTypePair(s, 0, 6);
				const store = pair.stores[0];
				return {
					store,
					id: pair.id,
					record: sampleRecord(store, pair.id, pair.sides[1].binding.nodeId)
				};
			};
			const withdrawal = (
				attempt: string,
				reason: string
			): ConversionAttemptEvent => ({
				kind: 'conversion-withdrawn',
				attempt,
				reason
			});

			it(`refuses a scope whose alternation is broken: "${INVALID}"`, () => {
				const { record } = stores();
				const r = { kind: 'conversion-attempt', ...record };
				const w = withdrawal(record.attempt, FENCE);
				expect(checkedConversionAttempts([r, w]), 'control').to.have.length(2);
				for (const [what, events] of [
					['two records in a row', [r, r]],
					['a withdrawal first', [w]],
					[
						'a withdrawal of another attempt',
						[r, withdrawal('f6'.repeat(32), FENCE)]
					],
					['two withdrawals in a row', [r, w, w]]
				] as const)
					expect(() => checkedConversionAttempts(events), what).to.throw(
						INVALID
					);
			});

			it(`refuses a stored reason that is not canonical: "${INVALID}"`, () => {
				const { record } = stores();
				const r = { kind: 'conversion-attempt', ...record };
				for (const [what, reason] of [
					['a needless escape', '\\x41'],
					['a raw control byte', 'line\nbreak'],
					['an escape in upper case', '\\xC3\\xA9'],
					['201 bytes', 'r'.repeat(201)]
				] as const)
					expect(
						() =>
							checkedConversionAttempts([
								r,
								withdrawal(record.attempt, reason)
							]),
						what
					).to.throw(INVALID);
			});

			for (const [what, second] of [
				['a second record right after the first', 'record'],
				['a withdrawal with a reason that is not canonical', 'reason']
			] as const)
				it(`refuses every reader and writer of a scope planted with ${what}`, () => {
					const { store, id, record } = stores();
					const storage = attemptStorage(store);
					plant(store, id, { kind: 'conversion-attempt', ...record });
					plant(
						store,
						id,
						second === 'record'
							? { kind: 'conversion-attempt', ...record }
							: withdrawal(record.attempt, '\\x41')
					);
					expect(attemptRowCount(store, id), 'planted').to.equal(2);
					expect(() => storage.openConversionAttempt(id), 'open').to.throw(
						INVALID
					);
					expect(
						() => storage.recordConversionAttempt(id, record),
						'record'
					).to.throw(INVALID);
					expect(
						() =>
							storage.withdrawConversionAttempt(id, 1, record.attempt, FENCE),
						'withdraw'
					).to.throw(INVALID);
					expect(attemptRowCount(store, id), 'nothing written').to.equal(2);
				});
		});
	});

	describe('An end before its report when a send throws (amendments B4 and B5)', () => {
		const PEER_TEXT = 'The peer ends it';
		/** Side 0 is past its layout_ack; the peer's tx_abort comes in and side 0's echo throws. */
		async function echoThrows(
			p: IConversionPair,
			atReport: (reason: string) => void,
			quiet: () => void = (): void => undefined
		): Promise<number> {
			const base = rows(p, 0);
			p.link.hold('asset_splice:4');
			expect((await run(p, 0)).error, 'start').to.equal(undefined);
			quiet();
			const m = p.managers[0];
			m.on('error', (_id: Buffer | null, reason: string) => atReport(reason));
			const undo = failAbortSends(p, 0);
			try {
				m.handleMessage(
					p.nodeIds[1],
					MessageType.TX_ABORT,
					encodeTxAbortMessage({
						channelId: p.channelId,
						data: Buffer.from(PEER_TEXT)
					})
				);
			} catch {
				// The send's error may reach the caller; the end must not wait on it.
			} finally {
				undo();
			}
			return base;
		}

		it("B4: ends the attempt when its echo of the peer's tx_abort cannot be sent, and the withdrawal stands", async () => {
			const p = await fresh();
			const base = await echoThrows(p, () => undefined);
			const m = p.managers[0];
			expect(attemptOf(m, p.id), 'ended').to.equal(undefined);
			expect(held(m, p.id)).to.equal(false);
			expect(kindsSince(p, 0, base)).to.deep.equal([
				'conversion-attempt',
				PEER_TEXT
			]);
			expect(conversionQuiet(m, p.id), 'not quiet').to.equal(false);
			expect(abandoned(p, 0), 'one end').to.deep.equal([PEER_TEXT]);
		});

		it('B4: reports a failed withdrawal after that end', async () => {
			const p = await fresh();
			const live: boolean[] = [];
			await echoThrows(
				p,
				(reason) => {
					if (reason.startsWith(WITHDRAWAL_FAILED))
						live.push(attemptOf(p.managers[0], p.id) !== undefined);
				},
				// The withdrawal fails, not the record.
				() => failCommits(p, 0, 1)
			);
			expect(live, 'reported once, the attempt already ended').to.deep.equal([
				false
			]);
		});

		it('B5: a deadline whose tx_abort cannot be sent ends the attempt before it reports (fake clock)', async () => {
			const p = await fresh({
				quiescenceTimeoutMs: 5000,
				config: [{}, { quiescenceTimeoutMs: 60_000 }]
			});
			p.link.hold('asset_splice:4');
			const m = p.managers[0];
			const live: boolean[] = [];
			m.on('error', (_id: Buffer | null, reason: string) => {
				if (reason.includes('the send failed'))
					live.push(attemptOf(m, p.id) !== undefined);
			});
			const undo = failAbortSends(p, 0);
			try {
				clock = sinon.useFakeTimers({
					now: Date.now(),
					toFake: ['Date', 'setTimeout', 'clearTimeout']
				});
				expect((await run(p, 0)).error, 'start').to.equal(undefined);
				expect(held(m, p.id), 'laid-out').to.equal(true);
				await tick(p, clock, 5100);
			} finally {
				undo();
			}
			expect(live, 'reported once, the attempt already ended').to.deep.equal([
				false
			]);
			expect(held(m, p.id)).to.equal(false);
		});
	});

	describe('The host hears each pre-restart end once (amendment D1)', () => {
		it('R1: tells the host the end of a record the sweep listed but could not read, once an orphan read learns its attempt', async () => {
			const p = await fresh();
			const side = p.opener;
			const base = rows(p, side);
			p.link.hold('asset_splice:4');
			expect((await run(p, 0)).error, 'start').to.equal(undefined);
			const verified = p.hosts[side].calls('verifyConversionTerms');
			const ctx = verified[verified.length - 1].args[0];
			const told = abandoned(p, side).length;
			p.link.clearRules();
			p.link.held.splice(0);
			// The sweep's GROUP BY works; its first read of the scope throws.
			let first = true;
			const reads = failReads(p, side, () => {
				const now = first;
				first = false;
				return now;
			});
			p.crash(side);
			const reports = reportsOf(p.managers[side]);
			await settleOnce();
			sinon.restore();
			expect(reads.count(), "the sweep's read failed").to.equal(1);
			expect(reports, 'the sweep reports it').to.deep.equal([
				[p.id, WITHDRAWAL_FAILED + IO]
			]);
			expect(rows(p, side) - base, 'still open').to.equal(1);
			const m = p.managers[side];
			expect(conversionQuiet(m, p.id), 'not quiet').to.equal(false);
			expect(kindsSince(p, side, base)).to.deep.equal([
				'conversion-attempt',
				RESTART
			]);
			await settleOnce();
			await settleOnce();
			const calls = p.hosts[side].calls('abandonConversion').slice(told);
			expect(
				calls.map((c) => c.args),
				'the host hears the end of the pre-crash attempt once'
			).to.deep.equal([[ctx, RESTART]]);
		});

		it('R3: after a listing failure, a pulled-in record of an attempt this process ended tells the host only once', async () => {
			const p = await fresh();
			const { side, base, told } = await strand(p);
			// The first quiet read meets the pre-crash orphan, tells the host and withdraws it.
			expect(conversionQuiet(p.managers[side], p.id)).to.equal(false);
			await settleOnce();
			expect(abandoned(p, side).slice(told), 'the orphan').to.deep.equal([
				RESTART
			]);
			await p.reconnect();
			const base2 = base + 2;
			expect(rows(p, side), 'withdrawn').to.equal(base2);
			const write = deviceOnlyNextWrite(p, side);
			await run(p, 0);
			await p.settle();
			write.stop();
			await settleOnce();
			expect(rows(p, side) - base2, 'attempt 2 not in the wallet').to.equal(0);
			expect(
				abandoned(p, side).slice(told),
				'the orphan, then attempt 2'
			).to.deep.equal([RESTART, NOT_RECORDED]);
			await p.stores[side].backup(path.join(s.dir(), 'backup-r3.db'));
			expect(rows(p, side) - base2, 'pulled in').to.equal(1);
			expect(conversionQuiet(p.managers[side], p.id), 'not quiet').to.equal(
				false
			);
			await settleOnce();
			await settleOnce();
			expect(
				abandoned(p, side).slice(told),
				'attempt 2 is told once'
			).to.deep.equal([RESTART, NOT_RECORDED]);
		});
	});

	describe('A copy that cannot convert (amendment D2)', () => {
		it('D2: a generation 6 copy restored with an odd count reads not quiet, and its splice start neither reads the scope nor withdraws nor reports', async () => {
			const t = plainTypePair(s);
			const p = await conversionPair(s, 'plain', {
				existing: {
					id: t.id,
					stores: t.stores,
					roots: t.sides.map((side) => side.root),
					nodeIds: [t.sides[0].binding.nodeId, t.sides[1].binding.nodeId]
				}
			});
			clean(p);
			const side = p.opener;
			const base = rows(p, side);
			p.link.hold('asset_splice:4');
			expect((await run(p, 0)).error, 'start').to.equal(undefined);
			expect(rows(p, side) - base, 'recorded').to.equal(1);
			const file = path.join(s.dir(), 'copy.db');
			await p.stores[side].backup(file);
			const copy = SqliteStorage.openFinalWallet(file, t.sides[side].binding);
			const original = p.stores[side];
			s.closing(() => original.close());
			expect(copy.supportsAssetConversion, 'generation 6').to.equal(true);
			expect(copy.canConvertAssetChannels, 'not the original').to.equal(false);
			expect(
				attemptRowCount(copy, p.id) - base,
				'restored with the record open'
			).to.equal(1);
			const scope = copy as unknown as Record<
				| 'conversionAttemptRows'
				| 'openConversionAttempt'
				| 'withdrawConversionAttempt',
				(...a: unknown[]) => unknown
			>;
			const spies = (
				[
					'conversionAttemptRows',
					'openConversionAttempt',
					'withdrawConversionAttempt'
				] as const
			).map((name) => sinon.spy(scope, name));
			const mark = p.errors[side].length;
			p.link.clearRules();
			p.link.held.splice(0);
			p.crash(side, { afterCrash: () => (p.stores[side] = copy) });
			await settleOnce();
			const m = p.managers[side];
			let refused: string | undefined;
			try {
				m.startFinalSplice(p.channelId, {} as never);
			} catch (e) {
				refused = (e as Error).message;
			}
			expect(refused, 'past the quiet gate').to.equal(NO_SPLICE);
			expect(conversionQuiet(m, p.id), 'not quiet').to.equal(false);
			await settleOnce();
			expect(
				{
					calls: spies.map((spy) => spy.callCount),
					reports: p.errors[side]
						.slice(mark)
						.filter((e) => e.startsWith(WITHDRAWAL_FAILED))
				},
				'no COUNT, no read of the record, no withdrawal and no report'
			).to.deep.equal({ calls: [0, 0, 0], reports: [] });
			expect(attemptRowCount(copy, p.id) - base, 'still open').to.equal(1);
		});
	});

	describe('Guards the v2.2 mutation table left green (K12, K13, K14 and K17)', () => {
		it("K12 (O12): an orphan's report and host call wait for a microtask, never inside the quiet read", async () => {
			const p = await fresh();
			const { side, reports, told } = await strand(p);
			const m = p.managers[side];
			expect(reports, 'nothing yet').to.deep.equal([]);
			expect(conversionQuiet(m, p.id)).to.equal(false);
			const sync = {
				reports: reports.length,
				host: abandoned(p, side).length - told
			};
			await settleOnce();
			expect(sync, 'nothing inside the read').to.deep.equal({
				reports: 0,
				host: 0
			});
			expect(reports, 'then the listing failure').to.deep.equal([
				[p.id, WITHDRAWAL_FAILED + LOCKED]
			]);
			expect(abandoned(p, side).length - told, 'then the host').to.equal(1);
		});

		it('K13 (O13): an orphan on the device only, pulled in while the next attempt waits on prepare, is withdrawn at the record and that attempt reaches the fence', async () => {
			const p = await fresh();
			const side = p.opener;
			const base = await deviceOnlyRecord(p, side);
			const gate = gatePrepare(p, side);
			const second = track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			);
			await p.settle();
			await second.done;
			expect(second.error, 'second start').to.equal(undefined);
			expect(gate.reached(), "the side's prepare waits").to.equal(true);
			await p.stores[side].backup(path.join(s.dir(), 'backup-k13.db'));
			expect(rows(p, side) - base, 'pulled in by the backup').to.equal(1);
			gate.release();
			await p.settle();
			await settleOnce();
			expect(kindsSince(p, side, base)).to.deep.equal([
				'conversion-attempt',
				RESTART,
				'conversion-attempt',
				FENCE
			]);
		});

		it('K14 (O14): an orphan whose withdrawal is on the device only is resolved by the read that pulls it in, with no report', async () => {
			const p = await fresh();
			const side = p.opener;
			const peer = (1 - side) as 0 | 1;
			const base = rows(p, side);
			p.link.hold('asset_splice:4');
			expect((await run(p, 0)).error, 'start').to.equal(undefined);
			const told = abandoned(p, side).length;
			// The peer's tx_abort: the side's withdrawal lands on the device only.
			const write = deviceOnlyNextWrite(p, side);
			p.managers[side].handleMessage(
				p.nodeIds[peer],
				MessageType.TX_ABORT,
				txAbort(p.channelId, 'The peer ends it')
			);
			write.stop();
			expect(write.landed(), 'the device commit ran').to.equal(true);
			expect(rows(p, side) - base, 'the wallet holds the record only').to.equal(
				1
			);
			expect(abandoned(p, side).slice(told), 'ended').to.deep.equal([
				'The peer ends it'
			]);
			const told2 = abandoned(p, side).length;
			// Crash, and the rebuilt sweep cannot list: the record is an orphan.
			const listing = failListing(p.stores[side]);
			p.link.clearRules();
			p.link.held.splice(0);
			p.crash(side);
			const reports = reportsOf(p.managers[side]);
			await settleOnce();
			listing.restore();
			expect(listing.count(), 'the listing ran and failed').to.equal(1);
			expect(rows(p, side) - base, 'still odd').to.equal(1);
			expect(conversionQuiet(p.managers[side], p.id), 'not quiet').to.equal(
				false
			);
			expect(rows(p, side) - base, 'the withdrawal pulled in').to.equal(2);
			await settleOnce();
			expect(reports, 'the listing failure only').to.deep.equal([
				[p.id, WITHDRAWAL_FAILED + LOCKED]
			]);
			expect(abandoned(p, side).slice(told2), 'no host call').to.deep.equal([]);
			expect(kindsSince(p, side, base)).to.deep.equal([
				'conversion-attempt',
				'The peer ends it'
			]);
		});

		it("K17 (O17): a draining acceptor whose answer to the peer's tx_abort cannot be sent still ends at once", async () => {
			const p = await fresh();
			// Side 0 initiates; its STFU waits on the link, so side 1 stays accepted.
			p.link.hold({ from: 0, name: 'STFU' });
			expect((await run(p, 0)).error, 'start').to.equal(undefined);
			const m1 = p.managers[1];
			expect(attemptOf(m1, p.id)?.state, 'accepted').to.equal('accepted');
			// stfu(0) before the acceptor's own: the acceptor fails into draining.
			m1.handleMessage(
				p.nodeIds[0],
				MessageType.STFU,
				stfu(p.channelId, false)
			);
			await settleOnce();
			expect(attemptOf(m1, p.id)?.state, 'draining').to.equal('draining');
			const undo = failAbortSends(p, 1);
			try {
				m1.handleMessage(
					p.nodeIds[0],
					MessageType.TX_ABORT,
					txAbort(p.channelId, 'The initiator ends it')
				);
			} catch {
				// The send's error may reach the caller; the end must not wait on it.
			} finally {
				undo();
			}
			expect(attemptOf(m1, p.id), 'ended at once').to.equal(undefined);
			expect(held(m1, p.id)).to.equal(false);
			p.link.clearRules();
			p.link.held.splice(0);
		});
	});
});
