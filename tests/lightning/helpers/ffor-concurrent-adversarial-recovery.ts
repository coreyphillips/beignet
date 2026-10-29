/**
 * FFOR concurrent receive, version 1: adversarial recovery review of PR #1301
 * (docs/specs/CONCURRENT-RECEIVE.md sections 3, 4, 7 and 8; base
 * section 7.5.5).
 *
 * This module holds the fixtures the review's files share. The cases are
 * split over three files so mocha --parallel can spread them:
 *   tests/lightning/ffor-concurrent-adversarial-recovery-cut-rounds.test.ts (1a, 1b)
 *   tests/lightning/ffor-concurrent-adversarial-recovery-crash-explorer.test.ts (1c, 1d, 6a)
 *   tests/lightning/ffor-concurrent-adversarial-recovery-holds-persistence.test.ts (2, 3, 5a, 4, 5b, 6b, 7)
 *
 * Two HONEST nodes, and everything that can go wrong between them without
 * either one cheating: a cut connection, a restart, a lost or crossing
 * message, a failed durable write, a row that predates a message.
 *
 * Most cases check recovery invariants. The defects the review
 * found in PR #1301 are fixed and their cases assert the fixed behaviour.
 * Cases titled PIN record a known defect that is NOT this PR's to fix, by
 * asserting what happens today, with the issue that tracks it: the
 * assertion fails, visibly, on the day that issue is fixed, and the case is
 * then rewritten to the outcome the spec requires (stated in its comment).
 *
 * Replay ordering (#1300) and signing over a withheld update (#1303) are
 * fixed and checked beside live voucher books. Remaining known-defect pins:
 *
 *   PIN [#1293 item 1]  S's setup timer crossing R's stfu
 *
 * Harness: tests/lightning/helpers/ffor-concurrent-pair.ts (two
 * ChannelManagers in loopback, a Link with per-direction holds, restart by
 * serialize / deserialize).
 *
 * Environment knobs, for a longer run than the default:
 *   FFOR_EXHAUSTIVE=1   every interrupt at every boundary in section 1a
 *                       (default: every other boundary of a round, with
 *                       one of the four interrupts, both rotating) and
 *                       every message boundary and durable write in
 *                       sections 1b and 1c (default: every eighteenth)
 *   FFOR_SEEDS=a-b      explorer seeds (default 1-3 per mode)
 *   FFOR_TRACE=1        print every explorer schedule
 */

import { expect } from 'chai';
import { Channel } from '../../../src/lightning/channel/channel';
import { hasPendingHtlcs } from '../../../src/lightning/channel/htlc-policy';
import {
	ChannelState,
	HtlcState,
	receivedAddIrrevocablyCommitted
} from '../../../src/lightning/channel/types';
import { MessageType } from '../../../src/lightning/message/types';
import { Feature } from '../../../src/lightning/features/flags';
import { FforState } from '../../../src/lightning/ffor/types';
import {
	activate,
	AMOUNTS,
	balances,
	channel,
	createPair,
	expectVouchersCarried,
	FUNDING_SATOSHIS,
	IPair,
	manager,
	offer,
	ordinaryHtlcs,
	other,
	record,
	restart,
	settleSlot,
	Side,
	snapshot,
	vouchers,
	why
} from './ffor-concurrent-pair';
import { onPersist } from './channel-persistence';

const BUDGET = AMOUNTS.reduce((a, b) => a + b, 0n);
export const S_START = (FUNDING_SATOSHIS - 200_000n) * 1000n;
export const S_AFTER_BOOK = S_START - BUDGET;
export const R_START = 200_000_000n;
export const ALL = [1, 2, 3];
export const SIDES: Side[] = ['S', 'R'];

export function activePair(): IPair {
	const pair = createPair({ pushSat: 200_000n });
	activate(pair, AMOUNTS, true);
	pair.link.log.length = 0;
	return pair;
}

/**
 * A socket that dies after `n` more messages: the first n (counted over
 * both directions, in the order they are sent) arrive, everything after is
 * lost. Neither side knows until `interrupt`.
 */
export function cutAfter(pair: IPair, n: number): void {
	let seen = 0;
	pair.link.drop = (): boolean => seen++ >= n;
}

export type Interrupt =
	| 'disconnect'
	| 'restart S'
	| 'restart R'
	| 'restart both';
export const INTERRUPTS: Interrupt[] = [
	'disconnect',
	'restart S',
	'restart R',
	'restart both'
];

/** The connection is noticed dead; the named sides also restart. */
export function interrupt(pair: IPair, how: Interrupt): void {
	pair.link.disconnect();
	pair.link.drop = null;
	if (how === 'restart S' || how === 'restart both') restart(pair, 'S');
	if (how === 'restart R' || how === 'restart both') restart(pair, 'R');
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	pair.link.log.length = 0;
}

/** Stop or resume advertising option_ff_concurrent on one side. */
export function advertise(pair: IPair, side: Side, on: boolean): void {
	const flags =
		side === 'S' ? pair.sConfig.localFeatures : pair.rConfig.localFeatures;
	if (on) flags.setOptional(Feature.OPTION_FF_CONCURRENT);
	else flags.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
}

export function sentBy(pair: IPair, side: Side): number[] {
	return pair.link.log.filter((e) => e.from === side).map((e) => e.type);
}

/** Both channels NORMAL and no wire error since the log was last cleared. */
export function expectAlive(pair: IPair, label: string): void {
	expect(pair.link.types(), `${label} ${why(pair)}`).to.not.include(
		MessageType.ERROR
	);
	expect(pair.sChannel.getState(), `${label} S ${why(pair)}`).to.equal(
		ChannelState.NORMAL
	);
	expect(pair.rChannel.getState(), `${label} R ${why(pair)}`).to.equal(
		ChannelState.NORMAL
	);
}

/** The quiescence gate, read as the engine reads it. */
function hasPending(ch: Channel): boolean {
	return hasPendingHtlcs(ch.getFullState());
}

/** Nothing owed on either side: no HTLC mid-flight, no update unsigned. */
export function expectSettled(pair: IPair, label: string): void {
	for (const side of SIDES) {
		const ch = channel(pair, side);
		expect(hasPending(ch), `${label} ${side} pending`).to.equal(false);
		expect(
			ch.getFullState().pendingLocalUpdates.length,
			`${label} ${side} queued updates`
		).to.equal(0);
	}
	const b = balances(pair);
	expect(b.s, `${label} S's balance, both books`).to.equal(b.rViewOfS);
	expect(b.r, `${label} R's balance, both books`).to.equal(b.sViewOfR);
}

export function expectActiveUnchanged(
	pair: IPair,
	hAct: Buffer,
	label: string
): void {
	for (const side of SIDES) {
		const f = record(channel(pair, side));
		expect(f.state, `${label} ${side} epoch state`).to.equal(FforState.ACTIVE);
		expect(f.hAct!.equals(hAct), `${label} ${side} H_act`).to.equal(true);
		expect(f.concurrentVersion, `${label} ${side} version`).to.equal(1);
		expect(f.activationMismatch, `${label} ${side} mismatch`).to.equal(false);
		expect(
			vouchers(channel(pair, side)).map(([, st]) => st),
			`${label} ${side} vouchers`
		).to.deep.equal([
			HtlcState.COMMITTED,
			HtlcState.COMMITTED,
			HtlcState.COMMITTED
		]);
	}
	expectVouchersCarried(pair, ALL, label);
}

export function expectClosed(pair: IPair, label: string): void {
	for (const side of SIDES) {
		expect(
			FforState[record(channel(pair, side)).state],
			`${label} ${side} epoch ${why(pair)}`
		).to.equal('CLOSED');
		expect(vouchers(channel(pair, side)), `${label} ${side}`).to.deep.equal([]);
	}
}

/**
 * Whether a side has an unsigned tail behind an outstanding signed round.
 * The reconnect replay preserves the signed prefix before this tail (#1300).
 */
export function prone1300(pair: IPair): boolean {
	for (const side of SIDES) {
		const ch = channel(pair, side);
		const st = ch.getFullState();
		// The outstanding commitment_signed may cover none of our own updates
		// (it answered the peer's), so the signed count alone does not say.
		if (
			ch.isAwaitingRemoteRevocation() &&
			st.pendingLocalUpdates.length > st.pendingLocalUpdatesSignedCount
		) {
			return true;
		}
	}
	return false;
}

/** Copy the issued round so later updates cannot alter the expectation. */
export function signedRound(ch: Channel): {
	number: bigint;
	covered: number;
	signature: string | null;
	htlcSignatures: string[];
	updates: { type: number; payload: string }[];
} {
	const state = ch.getFullState();
	return {
		number: state.remoteCommitmentNumber,
		covered: state.pendingLocalUpdatesSignedCount,
		signature: state.lastSentCommitmentSigned?.toString('hex') ?? null,
		htlcSignatures: state.lastSentHtlcSignatures.map((s) => s.toString('hex')),
		updates: state.pendingLocalUpdates
			.slice(0, state.pendingLocalUpdatesSignedCount)
			.map((u) => ({ type: u.type, payload: u.payload.toString('hex') }))
	};
}

/** An application that issues no update behind an unrevoked commitment (#1300). */
function idle(pair: IPair, side: Side): boolean {
	const ch = channel(pair, side);
	return (
		ch.getState() === ChannelState.NORMAL && !ch.isAwaitingRemoteRevocation()
	);
}

// ─────────────── Scenarios, cut or crashed and then finished ───────────────

interface IFlight {
	offerer: Side;
	id: bigint;
	preimage: Buffer;
	amount: bigint;
	intent: 'fulfil' | 'fail';
}

interface ICtx {
	flights: IFlight[];
	wantClose: boolean;
}

interface IScenario {
	name: string;
	mode: 'active' | 'draining';
	/** Runs to completion before the fault is armed. */
	setup: (pair: IPair, ctx: ICtx) => void;
	/** Runs with the fault armed; a step a dead link refuses is skipped. */
	steps: (pair: IPair, ctx: ICtx) => void;
}

function scOffer(
	pair: IPair,
	ctx: ICtx,
	side: Side,
	amount: bigint,
	intent: 'fulfil' | 'fail'
): void {
	if (!idle(pair, side)) return;
	const o = offer(pair, side, amount);
	if (!o.result.ok) return;
	ctx.flights.push({
		offerer: side,
		id: o.id,
		preimage: o.preimage,
		amount,
		intent
	});
}

/** Settle every received ordinary HTLC that is irrevocably committed. */
function scSettle(pair: IPair, ctx: ICtx): boolean {
	let acted = false;
	for (const receiver of SIDES) {
		for (const [key, e] of channel(pair, receiver).getFullState().htlcs) {
			if (!key.startsWith('received-') || e.fforVoucher === true) continue;
			if (!receivedAddIrrevocablyCommitted(e)) continue;
			if (!idle(pair, receiver)) continue;
			const f = ctx.flights.find(
				(x) => x.offerer === other(receiver) && x.id === e.id
			);
			if (!f) continue;
			const res =
				f.intent === 'fulfil'
					? manager(pair, receiver).fulfillHtlc(
							pair.channelId,
							f.id,
							f.preimage
					  )
					: manager(pair, receiver).failHtlc(
							pair.channelId,
							f.id,
							Buffer.alloc(292)
					  );
			if (res.ok) acted = true;
		}
	}
	return acted;
}

function scClose(pair: IPair, ctx: ICtx): boolean {
	if (!ctx.wantClose) return false;
	if (!idle(pair, 'R')) return false;
	if (record(pair.rChannel).state !== FforState.ACTIVE) return false;
	if (record(pair.rChannel).closeSent) return false;
	return pair.rManager.closeFforEpoch(pair.channelId).ok;
}

export const SCENARIOS: IScenario[] = [
	{
		name: 'ordinary payments both ways beside the vouchers',
		mode: 'active',
		setup: (): void => undefined,
		steps: (pair, ctx): void => {
			scOffer(pair, ctx, 'S', 5_000_000n, 'fulfil');
			scOffer(pair, ctx, 'R', 3_000_000n, 'fail');
			scSettle(pair, ctx);
			scOffer(pair, ctx, 'R', 2_000_000n, 'fulfil');
			scSettle(pair, ctx);
		}
	},
	{
		name: 'the book retires with ordinary HTLCs in flight and more arriving',
		mode: 'draining',
		setup: (pair, ctx): void => {
			scOffer(pair, ctx, 'S', 5_000_000n, 'fulfil');
			scOffer(pair, ctx, 'R', 3_000_000n, 'fulfil');
			settleSlot(pair, 2);
		},
		steps: (pair, ctx): void => {
			ctx.wantClose = true;
			scClose(pair, ctx);
			scSettle(pair, ctx);
			scOffer(pair, ctx, 'R', 1_000_000n, 'fulfil');
			scOffer(pair, ctx, 'S', 4_000_000n, 'fail');
			scSettle(pair, ctx);
		}
	}
];

/** Finish what the scenario wanted, then check the end state exactly. */
function finishAndCheck(
	pair: IPair,
	ctx: ICtx,
	scenario: IScenario,
	hAct: Buffer,
	label: string
): void {
	for (let round = 0; round < 12; round++) {
		const closed = scClose(pair, ctx);
		const settled = scSettle(pair, ctx);
		if (!closed && !settled) break;
	}
	expectAlive(pair, label);
	expect(ordinaryHtlcs(pair.sChannel), `${label} ${why(pair)}`).to.deep.equal(
		[]
	);
	expect(ordinaryHtlcs(pair.rChannel), `${label} ${why(pair)}`).to.deep.equal(
		[]
	);
	expectSettled(pair, label);
	let toR = 0n;
	for (const f of ctx.flights) {
		if (!pair.events[f.offerer].fulfilled.includes(f.id)) continue;
		toR += f.offerer === 'S' ? f.amount : -f.amount;
	}
	let s = S_AFTER_BOOK - toR;
	let r = R_START + toR;
	if (scenario.mode === 'draining') {
		s += AMOUNTS[0] + AMOUNTS[2];
		r += AMOUNTS[1];
		expectClosed(pair, label);
	} else {
		expectActiveUnchanged(pair, hAct, label);
	}
	expect(balances(pair), label).to.deep.equal({
		s,
		r,
		sViewOfR: r,
		rViewOfS: s
	});
}

/** Run a scenario with the socket dying after `n` messages. */
export function runCut(scenario: IScenario, n: number, how: Interrupt): number {
	const pair = activePair();
	const hAct = Buffer.from(record(pair.rChannel).hAct!);
	const ctx: ICtx = { flights: [], wantClose: false };
	scenario.setup(pair, ctx);
	pair.link.log.length = 0;
	let seen = 0;
	pair.link.drop = (): boolean => seen++ >= n;
	scenario.steps(pair, ctx);
	const label = `${scenario.name}; cut after ${n} messages; ${how}`;
	if (seen > n) {
		interrupt(pair, how);
		pair.link.reconnect();
	} else {
		pair.link.drop = null;
	}
	finishAndCheck(pair, ctx, scenario, hAct, label);
	return seen;
}

export type CrashWhen =
	| 'before the write'
	| 'after the write, before its sends';

/**
 * Run a scenario and kill one side at its k-th durable write: either the
 * write does not happen, or it lands and nothing after it leaves. The side
 * restarts from the last row that did land, not from memory.
 */
export function runCrash(
	scenario: IScenario,
	victim: Side,
	k: number,
	when: CrashWhen
): { writes: number; crashed: boolean } {
	const pair = activePair();
	const hAct = Buffer.from(record(pair.rChannel).hAct!);
	const ctx: ICtx = { flights: [], wantClose: false };
	scenario.setup(pair, ctx);
	pair.link.log.length = 0;
	let writes = 0;
	let crashed = false;
	let row = snapshot(pair, victim);
	onPersist(manager(pair, victim), () => {
		if (crashed) return;
		if (writes === k && when === 'before the write') {
			crashed = true;
			pair.link.drop = (): boolean => true;
			return;
		}
		row = snapshot(pair, victim);
		if (writes === k) {
			crashed = true;
			pair.link.drop = (): boolean => true;
		}
		writes++;
	});
	scenario.steps(pair, ctx);
	const label = `${scenario.name}; ${victim} dies at write ${k}, ${when}`;
	if (crashed) {
		pair.link.disconnect();
		pair.link.drop = null;
		restart(pair, victim, row);
		pair.sErrors.length = 0;
		pair.rErrors.length = 0;
		pair.link.log.length = 0;
		pair.link.reconnect();
	}
	finishAndCheck(pair, ctx, scenario, hAct, label);
	return { writes, crashed };
}

// ─────────────── Schedule explorer ───────────────

export type ExploreMode = 'none' | 'active' | 'draining';

function rng(seed: number): () => number {
	let a = seed >>> 0;
	return (): number => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

interface IExploreResult {
	/** Cuts taken while a side met issue #1300's precondition. */
	proneCuts: number;
	cuts: number;
}

/**
 * A seeded random walk over deliveries, ordinary adds and settles in both
 * directions, the close of the book, cuts and restarts, with every message
 * delivered one at a time in per-direction FIFO order (so messages cross).
 * Then everything is delivered and settled, and the end state is checked
 * exactly.
 *
 * With `avoid1300` the application issues no update behind an unrevoked
 * commitment_signed, and no cut is taken while the drain has put one there,
 * so no schedule meets issue #1300's precondition.
 */
export function explore(
	seed: number,
	mode: ExploreMode,
	avoid1300: boolean
): IExploreResult {
	const rand = rng(seed);
	const pick = (n: number): number => Math.floor(rand() * n);
	const pair = createPair({ pushSat: 200_000n });
	if (mode !== 'none') activate(pair, AMOUNTS, true);
	if (mode === 'draining') settleSlot(pair, 2);
	const hAct =
		mode === 'none' ? null : Buffer.from(record(pair.rChannel).hAct!);
	pair.link.log.length = 0;
	pair.link.holdAt = (): boolean => true;
	const trace: string[] = [];
	const flights: Array<IFlight & { settled: null | 'fulfil' | 'fail' }> = [];
	const result: IExploreResult = { proneCuts: 0, cuts: 0 };
	let closeOk = false;
	const dead = (): boolean =>
		pair.sChannel.getState() === ChannelState.ERRORED ||
		pair.rChannel.getState() === ChannelState.ERRORED ||
		pair.link.types().includes(MessageType.ERROR);
	const fail = (what: string): never => {
		throw new Error(
			`seed ${seed} (${mode}): ${what}; cuts taken on issue #1300's precondition: ${
				result.proneCuts
			}\n${trace.join('\n')}\n${JSON.stringify({
				sErrors: pair.sErrors,
				rErrors: pair.rErrors,
				inFlight: { S: pair.link.inFlight('S'), R: pair.link.inFlight('R') }
			})}`
		);
	};
	const deliver = (from: Side): boolean => {
		const q = pair.link.inFlight(from);
		if (q.length === 0) return false;
		trace.push(`deliver ${from}:${q[0]}`);
		pair.link.release(from, 1);
		return true;
	};
	const busy = (side: Side): boolean =>
		avoid1300 && channel(pair, side).isAwaitingRemoteRevocation();
	const tryOffer = (side: Side): void => {
		if (busy(side)) return;
		const amount = BigInt(1_000_000 + pick(3) * 1_000_000);
		const o = offer(pair, side, amount);
		trace.push(`offer ${side} ${o.id} ${o.result.ok ? 'ok' : o.result.error}`);
		if (o.result.ok) {
			flights.push({
				offerer: side,
				id: o.id,
				preimage: o.preimage,
				amount,
				intent: 'fulfil',
				settled: null
			});
		}
	};
	const trySettle = (
		f: IFlight & { settled: null | 'fulfil' | 'fail' },
		how: 'fulfil' | 'fail'
	): void => {
		const receiver = other(f.offerer);
		if (!pair.events[receiver].forwarded.includes(f.id)) return;
		if (channel(pair, receiver).getState() !== ChannelState.NORMAL) return;
		if (busy(receiver)) return;
		const res =
			how === 'fulfil'
				? manager(pair, receiver).fulfillHtlc(pair.channelId, f.id, f.preimage)
				: manager(pair, receiver).failHtlc(
						pair.channelId,
						f.id,
						Buffer.alloc(292)
				  );
		trace.push(
			`${how} ${receiver} ${f.id} ${res.ok ? 'ok' : res.error ?? 'refused'}`
		);
		if (res.ok) f.settled = how;
	};
	const tryClose = (): void => {
		if (closeOk || mode !== 'draining') return;
		if (pair.rChannel.getState() !== ChannelState.NORMAL) return;
		if (record(pair.rChannel).state !== FforState.ACTIVE) return;
		if (busy('R')) return;
		const res = pair.rManager.closeFforEpoch(pair.channelId);
		trace.push(`close ${res.ok ? 'ok' : res.error}`);
		if (res.ok) closeOk = true;
	};
	const cut = (): void => {
		const prone = prone1300(pair);
		if (avoid1300 && prone) {
			trace.push('cut skipped (#1300 precondition)');
			return;
		}
		const how = INTERRUPTS[pick(INTERRUPTS.length)];
		trace.push(
			`cut: ${how}${
				prone ? ' ON #1300 PRECONDITION' : ''
			}; lost S:[${pair.link.inFlight('S')}] R:[${pair.link.inFlight('R')}]`
		);
		result.cuts++;
		if (prone) result.proneCuts++;
		pair.link.disconnect();
		if (how === 'restart S' || how === 'restart both') restart(pair, 'S');
		if (how === 'restart R' || how === 'restart both') restart(pair, 'R');
		pair.link.reconnect();
	};
	const steps = 60 + pick(60);
	for (let i = 0; i < steps && !dead(); i++) {
		const roll = pick(100);
		if (roll < 28) deliver('S') || deliver('R');
		else if (roll < 56) deliver('R') || deliver('S');
		else if (roll < 62) tryOffer('S');
		else if (roll < 68) tryOffer('R');
		else if (roll < 82) {
			const open = flights.filter((f) => f.settled === null);
			if (open.length > 0) {
				trySettle(open[pick(open.length)], pick(4) === 0 ? 'fail' : 'fulfil');
			}
		} else if (roll < 88) tryClose();
		else cut();
	}
	// Quiesce: deliver everything, settle everything, until nothing moves.
	for (let round = 0; round < 60 && !dead(); round++) {
		let moved = false;
		while (!dead() && (deliver('S') || deliver('R'))) moved = true;
		if (dead()) break;
		if (mode === 'draining' && !closeOk) {
			tryClose();
			moved = moved || closeOk;
		}
		for (const f of flights) {
			if (f.settled !== null) continue;
			trySettle(f, 'fulfil');
			if (f.settled !== null) moved = true;
		}
		if (
			!moved &&
			pair.link.inFlight('S').length === 0 &&
			pair.link.inFlight('R').length === 0
		) {
			break;
		}
	}
	if (dead()) fail('channel failed');
	if (process.env.FFOR_TRACE) console.log(trace.join('\n'));
	if (pair.sChannel.getState() !== ChannelState.NORMAL) fail('S not NORMAL');
	if (pair.rChannel.getState() !== ChannelState.NORMAL) fail('R not NORMAL');
	const stuck = flights.filter((f) => f.settled === null);
	if (stuck.length > 0) {
		fail(`wedged: ${stuck.length} HTLC(s) never became settleable`);
	}
	if (
		ordinaryHtlcs(pair.sChannel).length + ordinaryHtlcs(pair.rChannel).length
	) {
		fail(
			`wedged: HTLCs remain S:${ordinaryHtlcs(pair.sChannel)} R:${ordinaryHtlcs(
				pair.rChannel
			)}`
		);
	}
	for (const side of SIDES) {
		const ch = channel(pair, side);
		if (hasPending(ch) || ch.getFullState().pendingLocalUpdates.length) {
			fail(`wedged: ${side} still has pending updates`);
		}
	}
	let toR = 0n;
	for (const f of flights) {
		if (f.settled !== 'fulfil') continue;
		toR += f.offerer === 'S' ? f.amount : -f.amount;
	}
	let s = S_START - toR;
	let r = R_START + toR;
	if (mode === 'active') s -= BUDGET;
	if (mode === 'draining') {
		s -= AMOUNTS[1];
		r += AMOUNTS[1];
	}
	const b = balances(pair);
	const got = JSON.stringify(b, (_k, v) =>
		typeof v === 'bigint' ? `${v}` : v
	);
	if (b.s !== s || b.r !== r || b.sViewOfR !== r || b.rViewOfS !== s) {
		fail(`balances ${got}, expected s=${s} r=${r}`);
	}
	if (mode === 'active') {
		try {
			expectActiveUnchanged(pair, hAct!, `seed ${seed}`);
		} catch (err) {
			fail((err as Error).message);
		}
	}
	if (mode === 'draining') {
		for (const side of SIDES) {
			if (record(channel(pair, side)).state !== FforState.CLOSED) {
				fail(
					`${side} epoch is ${
						FforState[record(channel(pair, side)).state]
					}, not CLOSED`
				);
			}
			if (vouchers(channel(pair, side)).length > 0)
				fail(`${side} keeps vouchers`);
		}
	}
	return result;
}

// ─────────────── The drain hold fixture ───────────────

/**
 * R is DRAINING with its drain round lost on the wire; S comes back from a
 * row that predates ff_close (ACTIVE, no close). `settled` are the slots S
 * settled before that row. One ordinary HTLC from S is committed on the
 * channel throughout.
 *
 * How S gets there honestly: a restore from a backup or Recovery Capsule
 * taken between the last commitment round and ff_close, or a store that
 * acknowledged the DRAINING write and lost it. The commitment numbers of
 * that row are current, so BOLT 2's reestablish sees nothing wrong.
 */
export function sLostTheClose(settled: number[]): {
	pair: IPair;
	inbound: ReturnType<typeof offer>;
	backup: string;
} {
	const pair = activePair();
	const inbound = offer(pair, 'S', 6_000_000n);
	expect(inbound.result.ok, inbound.result.error).to.equal(true);
	for (const k of settled) settleSlot(pair, k);
	const backup = snapshot(pair, 'S');
	pair.link.drop = (from, type): boolean =>
		from === 'R' && type !== MessageType.FF_CLOSE;
	const closed = pair.rManager.closeFforEpoch(pair.channelId);
	expect(closed.ok, closed.error).to.equal(true);
	expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
	pair.link.drop = null;
	restart(pair, 'S', backup);
	expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
	expect(record(pair.sChannel).closeWire).to.equal(null);
	pair.link.log.length = 0;
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	return { pair, inbound, backup };
}

/** The balances once slot 2 is fulfilled and slots 1 and 3 failed. */
export function drained(toR: bigint): {
	s: bigint;
	r: bigint;
	sViewOfR: bigint;
	rViewOfS: bigint;
} {
	const s = S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2] - toR;
	const r = R_START + AMOUNTS[1] + toR;
	return { s, r, sViewOfR: r, rViewOfS: s };
}
