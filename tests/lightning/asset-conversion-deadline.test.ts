/**
 * #2151 Step 4a, contract section 8, the deadline file: the attempt deadline
 * and the phase bound run at once, outside the attempt's queue (section 1
 * and amendments A2, A8 and A9), so an attempt ends on time while a host
 * call or a barrier waits; and the two awaits after `propose` that had no
 * state check (section 1.3).
 *
 * One plain pair serves every test. Side 0 runs with a 5 s deadline, below
 * the 15 s host bound, and is the side whose host or barrier waits; side 1
 * keeps the default 60 s, so its own deadline never ends the attempt first.
 * After each test both sides disconnect and reconnect, which ends whatever
 * a failed test left behind.
 */
import { expect } from 'chai';
import { createHash } from 'crypto';
import sinon from 'sinon';
import { MessageType } from '../../src/lightning/message/types';
import { scratch } from './helpers/channel-type-pairs';
import {
	attemptEvents,
	attemptRowCount,
	type ConversionAttemptEvent
} from './helpers/conversion-attempts';
import {
	abandoned,
	abortText,
	agreeOnTerms,
	allocatedKeyIndex,
	attemptOf,
	conversionDeps,
	hangBarrier,
	held,
	sharedPair,
	startConversion,
	stubConversionDescription,
	stubProposal,
	tick,
	track,
	txAbort,
	type IConversionAttemptView,
	type IConversionPair
} from './helpers/conversion-managers';

const TIMED_OUT = 'Asset conversion timed out';
const WITHDRAWN = 'Asset conversion withdrawn';
const DEADLINE_MS = 5_000;
/** When a waiting host call finally answers: after the deadline, before the host bound. */
const LATE_MS = 6_000;
const PHASE_BOUND_MS = 15_000;
const REF = Buffer.alloc(8, 0x4a);

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();
const fakeClock = (): sinon.SinonFakeTimers =>
	sinon.useFakeTimers({
		now: Date.now(),
		toFake: ['Date', 'setTimeout', 'clearTimeout']
	});

/** The texts of the tx_abort messages side `from` put on the link since `mark`. */
const abortsFrom = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from && m.name === 'TX_ABORT')
		.map(abortText);
const sentNames = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from)
		.map((m) => m.name);
/** The tx_abort messages side 0 delivered to side 1 since `mark`. */
const abortsDelivered = (p: IConversionPair, mark: number): number =>
	p.link.delivered
		.slice(mark)
		.filter((m) => m.from === 0 && m.name === 'TX_ABORT').length;

/** Where side 0 stood when its waiting call was made. */
interface IHang {
	made: boolean;
	/** The host log's length then. */
	log: number;
	/** The link's send count then. */
	sent: number;
	/** Side 0's allocated key index then. */
	keys: number;
}
function newHang(): IHang {
	return { made: false, log: -1, sent: -1, keys: -1 };
}
function markHang(p: IConversionPair, hang: IHang): void {
	if (hang.made) return;
	hang.made = true;
	hang.log = p.hostLog.length;
	hang.sent = p.link.sent.length;
	hang.keys = allocatedKeyIndex(p.stores[0]);
}
/** A host answer that arrives LATE_MS after the call (fake timers installed). */
function lateAnswer<T>(
	p: IConversionPair,
	hang: IHang,
	answer: () => T
): Promise<T> {
	markHang(p, hang);
	return new Promise<T>((done) => setTimeout(() => done(answer()), LATE_MS));
}

/** Undo what a test changed on the shared pair. */
function clean(p: IConversionPair): void {
	p.link.clearRules();
	p.link.held.splice(0);
	p.hostLog.splice(0);
	p.errors[0].splice(0);
	p.errors[1].splice(0);
	p.recycled[0].splice(0);
	p.recycled[1].splice(0);
	agreeOnTerms(p);
	for (const i of [0, 1] as const) {
		const h = p.hosts[i];
		h.verify = (): unknown => true;
		h.abandon = (): unknown => undefined;
		h.propose = (): unknown => stubProposal(i);
		h.describe = (ctx, _proposals, bitcoin): unknown =>
			stubConversionDescription(ctx, h.termsFor(ctx), bitcoin);
		h.prepare = (_ctx, _proposals, _bitcoin, layoutDigest): unknown => ({
			digest: sha256(layoutDigest)
		});
		p.feerateEstimates[i] = async (): Promise<number> => 1000;
	}
}

/** Side `I` starts; returns the tracked start once the link is idle. */
async function begin(
	p: IConversionPair,
	I: 0 | 1
): Promise<ReturnType<typeof track>> {
	agreeOnTerms(p);
	const start = track(
		startConversion(p.managers[I], p.channelId, { reference: REF })
	);
	await p.settle();
	return start;
}

describe('Asset conversion bounds that run at once (#2151 step 4a, section 8 deadline file)', function () {
	this.timeout(120000);
	const s = scratch('conversion-deadline-');
	const shared = sharedPair(s, 'plain', {
		quiescenceTimeoutMs: DEADLINE_MS,
		config: [{}, { quiescenceTimeoutMs: 60_000 }]
	});
	let used = false;
	const pair = (): Promise<IConversionPair> => {
		used = true;
		return shared();
	};
	let clock: sinon.SinonFakeTimers | undefined;
	const undo: (() => void)[] = [];
	afterEach(async () => {
		clock?.restore();
		clock = undefined;
		for (const u of undo.splice(0).reverse()) u();
		if (!used) return;
		const p = await shared();
		p.link.clearRules();
		p.link.held.splice(0);
		p.disconnect();
		await p.reconnect();
	});
	after(() => s.release());

	describe('A host that answers after the deadline (test 1 and A9)', () => {
		type Wait =
			| 'the estimate'
			| 'proposeConversion'
			| 'describeConversion'
			| 'prepareConversion';
		/** Make side 0's call `wait` answer late; every other call answers at once. */
		const install = (p: IConversionPair, wait: Wait, hang: IHang): void => {
			const h = p.hosts[0];
			switch (wait) {
				case 'the estimate':
					// The estimate of propose's floor (1040), not start's or assess's.
					p.feerateEstimates[0] = async (): Promise<number> => {
						const state = attemptOf(p.managers[0], p.id)?.state;
						return state === 'quiescing' || state === 'quiesced'
							? lateAnswer(p, hang, () => 1000)
							: 1000;
					};
					return;
				case 'proposeConversion':
					h.propose = (): unknown => lateAnswer(p, hang, () => stubProposal(0));
					return;
				case 'describeConversion':
					h.describe = (ctx, _proposals, bitcoin): unknown =>
						lateAnswer(p, hang, () =>
							stubConversionDescription(ctx, h.termsFor(ctx), bitcoin)
						);
					return;
				case 'prepareConversion':
					h.prepare = (_ctx, _proposals, _bitcoin, layoutDigest): unknown =>
						lateAnswer(p, hang, () => ({ digest: sha256(layoutDigest) }));
			}
		};
		const waits: Wait[] = [
			'the estimate',
			'proposeConversion',
			'describeConversion',
			'prepareConversion'
		];
		for (const wait of waits)
			for (const side of ['I', 'A'] as const)
				it(`ends with "${TIMED_OUT}" at the deadline while ${side}'s ${wait} waits, and ignores the late answer`, async () => {
					const p = await pair();
					clean(p);
					const I = side === 'I' ? 0 : 1;
					const rows = attemptRowCount(p.stores[0], p.id);
					const hang = newHang();
					install(p, wait, hang);
					clock = fakeClock();
					const mark = p.link.sent.length;
					const delivered = p.link.delivered.length;
					const start = await begin(p, I);
					expect(hang.made, `${side}'s ${wait} was called`).to.equal(true);

					await tick(p, clock, DEADLINE_MS - 100);
					expect(abortsFrom(p, 0, mark), 'before the deadline').to.deep.equal(
						[]
					);
					expect(held(p.managers[0], p.id), 'held before').to.equal(true);
					await tick(p, clock, 200);
					expect(
						abortsFrom(p, 0, mark),
						'within 100 ms of the deadline, not at the 15 s host bound'
					).to.deep.equal([TIMED_OUT]);
					expect(abandoned(p, 0), 'the end').to.deep.equal([TIMED_OUT]);
					expect([
						held(p.managers[0], p.id),
						held(p.managers[1], p.id)
					]).to.deep.equal([false, false]);
					expect(abortsDelivered(p, delivered), 'the peer sees one').to.equal(
						1
					);

					// The late answer, at 6 s, is ignored.
					await tick(p, clock, LATE_MS - DEADLINE_MS + 500);
					expect(
						sentNames(p, 0, hang.sent),
						'sent after the wait'
					).to.deep.equal(['TX_ABORT']);
					expect(
						p.hostLog
							.slice(hang.log)
							.filter((c) => c.side === 0)
							.map((c) => c.name),
						'host calls after the wait'
					).to.deep.equal(['abandonConversion']);
					expect(allocatedKeyIndex(p.stores[0]), 'no key').to.equal(hang.keys);
					expect(abandoned(p, 0), 'one end').to.deep.equal([TIMED_OUT]);
					expect(attemptRowCount(p.stores[0], p.id), 'no record').to.equal(
						rows
					);
					await start.done;
					expect(start.error).to.equal(undefined);
				});

		it(`ends a start whose own estimate waits with "${WITHDRAWN}" at the deadline and sends nothing (control, green on the base)`, async () => {
			const p = await pair();
			clean(p);
			const hang = newHang();
			// The estimate in start (395), outside the queue.
			p.feerateEstimates[0] = async (): Promise<number> =>
				attemptOf(p.managers[0], p.id)?.state === 'starting'
					? lateAnswer(p, hang, () => 1000)
					: 1000;
			clock = fakeClock();
			const mark = p.link.sent.length;
			const start = await begin(p, 0);
			expect(hang.made, 'the estimate was called').to.equal(true);
			await tick(p, clock, DEADLINE_MS - 100);
			expect(held(p.managers[0], p.id), 'held before').to.equal(true);
			await tick(p, clock, 200);
			expect(held(p.managers[0], p.id), 'ended at the deadline').to.equal(
				false
			);
			await tick(p, clock, LATE_MS - DEADLINE_MS + 500);
			await start.done;
			expect(start.error).to.equal(WITHDRAWN);
			expect(sentNames(p, 0, mark), 'nothing sent').to.deep.equal([]);
			expect(abandoned(p, 0), 'no host verified it').to.deep.equal([]);
		});
	});

	/** The barriers amendment A8 names: propose's (1062) and the layout steps' (1164). */
	const BARRIERS: [
		string,
		'I' | 'A',
		(a: IConversionAttemptView) => boolean
	][] = [
		[
			"propose's barrier",
			'I',
			(a): boolean => a.state === 'quiescing' && !!a.proposal && !a.snapshot
		],
		[
			"propose's barrier",
			'A',
			(a): boolean => a.state === 'quiesced' && !!a.proposal && !a.snapshot
		],
		["the layout steps' barrier", 'I', (a): boolean => a.state === 'laid-out'],
		["the layout steps' barrier", 'A', (a): boolean => a.state === 'laid-out']
	];
	/** Hang side 0's barrier at `which`, marking the hang when it begins. */
	const hangAt = (
		p: IConversionPair,
		which: (a: IConversionAttemptView) => boolean,
		hang: IHang
	): void => {
		undo.push(
			hangBarrier(p, 0, (a) => {
				const yes = which(a);
				if (yes) markHang(p, hang);
				return yes;
			})
		);
	};

	describe('A barrier that never resolves (test 2 and A8)', () => {
		for (const [where, side, which] of BARRIERS)
			it(`ends with "${TIMED_OUT}" at the deadline while ${side}'s ${where} never resolves`, async () => {
				const p = await pair();
				clean(p);
				const I = side === 'I' ? 0 : 1;
				const rows = attemptRowCount(p.stores[0], p.id);
				const hang = newHang();
				hangAt(p, which, hang);
				clock = fakeClock();
				const mark = p.link.sent.length;
				const delivered = p.link.delivered.length;
				await begin(p, I);
				expect(hang.made, `${side}'s ${where} was reached`).to.equal(true);
				await tick(p, clock, DEADLINE_MS - 100);
				expect(abortsFrom(p, 0, mark), 'before the deadline').to.deep.equal([]);
				await tick(p, clock, 200);
				expect(
					abortsFrom(p, 0, mark),
					'within 100 ms of the deadline'
				).to.deep.equal([TIMED_OUT]);
				expect(abandoned(p, 0)).to.deep.equal([TIMED_OUT]);
				expect([
					held(p.managers[0], p.id),
					held(p.managers[1], p.id)
				]).to.deep.equal([false, false]);
				expect(abortsDelivered(p, delivered), 'the peer sees one').to.equal(1);
				expect(sentNames(p, 0, hang.sent)).to.deep.equal(['TX_ABORT']);
				expect(
					allocatedKeyIndex(p.stores[0]),
					'no key after the wait'
				).to.equal(hang.keys);
				expect(attemptRowCount(p.stores[0], p.id), 'no record').to.equal(rows);
			});
	});

	describe('The phase bound runs at once (test 3, S1 and A2)', () => {
		for (const [where, side, which] of BARRIERS)
			it(`ends and disconnects at the deadline plus 15 s when ${side}'s ${where} never resolves and the echo never comes`, async () => {
				const p = await pair();
				clean(p);
				const I = side === 'I' ? 0 : 1;
				const hang = newHang();
				hangAt(p, which, hang);
				// The peer's echo of side 0's tx_abort waits on the link.
				p.link.hold({ from: 1, name: 'TX_ABORT' });
				clock = fakeClock();
				const mark = p.link.sent.length;
				await begin(p, I);
				expect(hang.made, `${side}'s ${where} was reached`).to.equal(true);
				await tick(p, clock, DEADLINE_MS + 100);
				expect(abortsFrom(p, 0, mark), 'the deadline').to.deep.equal([
					TIMED_OUT
				]);
				expect(
					held(p.managers[0], p.id),
					'aborting, waiting for the echo'
				).to.equal(true);
				expect(abortsFrom(p, 1, mark), 'the echo, held').to.deep.equal([
					TIMED_OUT
				]);
				await tick(p, clock, PHASE_BOUND_MS - 200);
				expect(p.recycled[0], 'before the phase bound').to.deep.equal([]);
				expect(held(p.managers[0], p.id)).to.equal(true);
				await tick(p, clock, 200);
				expect(
					p.recycled[0],
					'disconnected within 100 ms of the deadline plus 15 s'
				).to.deep.equal([p.nodeIds[1]]);
				expect(held(p.managers[0], p.id), 'held').to.equal(false);
				expect(abandoned(p, 0)).to.deep.equal([TIMED_OUT]);
				expect(abortsFrom(p, 0, mark), 'one tx_abort').to.deep.equal([
					TIMED_OUT
				]);
			});
	});

	describe('The state check after each propose (test 4, section 1.3)', () => {
		const ENDS = 'The peer ends this attempt';
		for (const side of ['I', 'A'] as const)
			it(`allocates no key and sends no ${
				side === 'I' ? 'splice_init' : 'splice_ack or layout'
			} when an end lands in the hop after ${side}'s propose returns`, async () => {
				const p = await pair();
				clean(p);
				const I = side === 'I' ? 0 : 1;
				const state = side === 'I' ? 'quiescing' : 'quiesced';
				const deps = conversionDeps(p.managers[0]);
				const busy = deps.busy as (id: string) => boolean;
				let fired = false;
				// propose's last precondition read: its proposal is in, its snapshot
				// not yet. The peer's tx_abort reaches side 0 in the next microtask,
				// ahead of the handler's continuation after `await propose`.
				deps.busy = (id: string): boolean => {
					const a = attemptOf(p.managers[0], id);
					if (!fired && a?.state === state && !!a.proposal && !a.snapshot) {
						fired = true;
						queueMicrotask(() =>
							p.managers[0].handleMessage(
								p.nodeIds[1],
								MessageType.TX_ABORT,
								txAbort(p.channelId, ENDS)
							)
						);
					}
					return busy(id);
				};
				undo.push(() => (deps.busy = busy));
				const keys = allocatedKeyIndex(p.stores[0]);
				const mark = p.link.sent.length;
				await begin(p, I);
				expect(fired, "the end was delivered after propose's checks").to.equal(
					true
				);
				expect(abandoned(p, 0), 'the end').to.deep.equal([ENDS]);
				expect(allocatedKeyIndex(p.stores[0]), 'no key').to.equal(keys);
				const sent = sentNames(p, 0, mark);
				if (side === 'I')
					expect(sent, 'no splice_init').to.not.include('SPLICE');
				else {
					expect(sent, 'no splice_ack').to.not.include('SPLICE_ACK');
					expect(sent, 'no layout').to.not.include('asset_splice:0');
				}
			});
	});

	describe('A held link (test 5) and a send that throws (A9)', () => {
		it('ends an attempt held in laid-out at the deadline and writes the withdrawal before its tx_abort', async () => {
			const p = await pair();
			clean(p);
			const base = attemptRowCount(p.stores[0], p.id);
			const atAbort: number[] = [];
			const tap = (m: { from: 0 | 1; name: string }): void => {
				if (m.from === 0 && m.name === 'TX_ABORT')
					atAbort.push(attemptRowCount(p.stores[0], p.id) - base);
			};
			p.link.taps.push(tap);
			undo.push(() => p.link.taps.splice(p.link.taps.indexOf(tap), 1));
			// Both layout_acks wait on the link: both sides stay in laid-out.
			p.link.hold('asset_splice:4');
			clock = fakeClock();
			const mark = p.link.sent.length;
			await begin(p, 0);
			expect(
				p.link.held.map((m) => m.from + ':' + m.name).sort(),
				'both layout_acks held'
			).to.deep.equal(['0:asset_splice:4', '1:asset_splice:4']);
			await tick(p, clock, DEADLINE_MS - 100);
			expect(abortsFrom(p, 0, mark), 'before the deadline').to.deep.equal([]);
			await tick(p, clock, 200);
			expect(abortsFrom(p, 0, mark), 'the deadline').to.deep.equal([TIMED_OUT]);
			expect(abandoned(p, 0)).to.deep.equal([TIMED_OUT]);
			expect(atAbort, 'rows when the tx_abort left').to.deep.equal([2]);
			const events = attemptEvents(p.stores[0], p.id).slice(base);
			expect(events.map((e) => e.kind)).to.deep.equal([
				'conversion-attempt',
				'conversion-withdrawn'
			]);
			const [record, withdrawal] = events as [
				ConversionAttemptEvent & { kind: 'conversion-attempt' },
				ConversionAttemptEvent & { kind: 'conversion-withdrawn' }
			];
			expect(withdrawal).to.deep.equal({
				kind: 'conversion-withdrawn',
				attempt: record.attempt,
				reason: TIMED_OUT
			});
		});

		it('still ends at the deadline when its tx_abort cannot be sent, with nothing escaping the timer and one report', async () => {
			const p = await pair();
			clean(p);
			p.link.hold('asset_splice:4');
			const deps = conversionDeps(p.managers[0]);
			const send = deps.send as (
				peer: string,
				type: number,
				payload: Buffer
			) => void;
			deps.send = (peer: string, type: number, payload: Buffer): void => {
				if (type === MessageType.TX_ABORT) throw new Error('the send failed');
				send(peer, type, payload);
			};
			undo.push(() => (deps.send = send));
			clock = fakeClock();
			await begin(p, 0);
			expect(held(p.managers[0], p.id), 'laid-out').to.equal(true);
			await tick(p, clock, DEADLINE_MS - 100);
			// Booleans, not the attempt: a parallel worker cannot send its BigInts.
			const live = (): boolean => attemptOf(p.managers[0], p.id) !== undefined;
			expect(live(), 'before the deadline').to.equal(true);
			// tickAsync rethrows what a timer throws: nothing may escape.
			await tick(p, clock, 200);
			expect(live(), 'ended at the deadline').to.equal(false);
			expect(held(p.managers[0], p.id)).to.equal(false);
			expect(abandoned(p, 0), 'one end').to.have.length(1);
			expect(
				p.errors[0].filter((e) => e.includes('the send failed')),
				'reported once'
			).to.have.length(1);
		});
	});
});
