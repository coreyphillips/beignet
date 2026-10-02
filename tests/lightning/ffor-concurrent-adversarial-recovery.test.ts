/**
 * FFOR concurrent receive, version 1: adversarial recovery review of PR #1301
 * (specs/CONCURRENT-RECEIVE.md sections 3, 4, 7 and 8; base section 7.5.5).
 *
 * Two HONEST nodes, and everything that can go wrong between them without
 * either one cheating: a cut connection, a restart, a lost or crossing
 * message, a failed durable write, a row that predates a message.
 *
 * Every test passes. Most pin an attack that held. The defects the review
 * found in PR #1301 are fixed and their cases assert the fixed behaviour.
 * Cases titled PIN record a known defect that is NOT this PR's to fix, by
 * asserting what happens today, with the issue that tracks it: the
 * assertion fails, visibly, on the day that issue is fixed, and the case is
 * then rewritten to the outcome the spec requires (stated in its comment).
 *
 *   PIN [#1300]         the reestablish replay-order bug, shown beside a
 *                       live voucher book
 *   PIN [#1303]         one failed durable write, then a write that lands
 *   PIN [#1293 item 1]  S's setup timer crossing R's stfu
 *   PIN [PR 2 of #1283] the interim CLOSED rule when every voucher was
 *                       redeemed while ACTIVE
 *
 * Harness: helpers/ffor-concurrent-pair.ts (two ChannelManagers in loopback,
 * a Link with per-direction holds, restart by serialize / deserialize).
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
import * as bitcoin from 'bitcoinjs-lib';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	HtlcState,
	receivedAddIrrevocablyCommitted
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { FforState } from '../../src/lightning/ffor/types';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
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
	pay,
	record,
	restart,
	settleSlot,
	Side,
	snapshot,
	terms,
	TIP,
	vouchers,
	why
} from './helpers/ffor-concurrent-pair';

const BUDGET = AMOUNTS.reduce((a, b) => a + b, 0n);
const S_START = (FUNDING_SATOSHIS - 200_000n) * 1000n;
const S_AFTER_BOOK = S_START - BUDGET;
const R_START = 200_000_000n;
const ALL = [1, 2, 3];
const SIDES: Side[] = ['S', 'R'];

function activePair(): IPair {
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
function cutAfter(pair: IPair, n: number): void {
	let seen = 0;
	pair.link.drop = (): boolean => seen++ >= n;
}

type Interrupt = 'disconnect' | 'restart S' | 'restart R' | 'restart both';
const INTERRUPTS: Interrupt[] = [
	'disconnect',
	'restart S',
	'restart R',
	'restart both'
];

/** The connection is noticed dead; the named sides also restart. */
function interrupt(pair: IPair, how: Interrupt): void {
	pair.link.disconnect();
	pair.link.drop = null;
	if (how === 'restart S' || how === 'restart both') restart(pair, 'S');
	if (how === 'restart R' || how === 'restart both') restart(pair, 'R');
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	pair.link.log.length = 0;
}

/** Stop or resume advertising option_ff_concurrent on one side. */
function advertise(pair: IPair, side: Side, on: boolean): void {
	const flags =
		side === 'S' ? pair.sConfig.localFeatures : pair.rConfig.localFeatures;
	if (on) flags.setOptional(Feature.OPTION_FF_CONCURRENT);
	else flags.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
}

function sentBy(pair: IPair, side: Side): number[] {
	return pair.link.log.filter((e) => e.from === side).map((e) => e.type);
}

/** Both channels NORMAL and no wire error since the log was last cleared. */
function expectAlive(pair: IPair, label: string): void {
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

/** Channel.hasPendingHtlcs is private; the suites read it as the engine does. */
function hasPending(ch: Channel): boolean {
	return (ch as unknown as { hasPendingHtlcs(): boolean }).hasPendingHtlcs();
}

/** Nothing owed on either side: no HTLC mid-flight, no update unsigned. */
function expectSettled(pair: IPair, label: string): void {
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

function expectActiveUnchanged(pair: IPair, hAct: Buffer, label: string): void {
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

function expectClosed(pair: IPair, label: string): void {
	for (const side of SIDES) {
		expect(
			FforState[record(channel(pair, side)).state],
			`${label} ${side} epoch ${why(pair)}`
		).to.equal('CLOSED');
		expect(vouchers(channel(pair, side)), `${label} ${side}`).to.deep.equal([]);
	}
}

/**
 * Whether a side has updates queued behind a commitment_signed the peer has
 * not revoked: the precondition of issue #1300 (reestablish replays them
 * ahead of that commitment_signed).
 */
function prone1300(pair: IPair): boolean {
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

const SCENARIOS: IScenario[] = [
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
function runCut(scenario: IScenario, n: number, how: Interrupt): number {
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

type CrashWhen = 'before the write' | 'after the write, before its sends';

/**
 * Run a scenario and kill one side at its k-th durable write: either the
 * write does not happen, or it lands and nothing after it leaves. The side
 * restarts from the last row that did land, not from memory.
 */
function runCrash(
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
	manager(pair, victim).on('channel:persist', () => {
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

type ExploreMode = 'none' | 'active' | 'draining';

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
function explore(
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
function sLostTheClose(settled: number[]): {
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
function drained(toR: bigint): {
	s: bigint;
	r: bigint;
	sViewOfR: bigint;
	rViewOfS: bigint;
} {
	const s = S_AFTER_BOOK + AMOUNTS[0] + AMOUNTS[2] - toR;
	const r = R_START + AMOUNTS[1] + toR;
	return { s, r, sViewOfR: r, rViewOfS: s };
}

describe('FFOR concurrent receive: adversarial recovery review of PR #1301', function () {
	this.timeout(900_000);

	// ───────────────────────────────────────────────────────────────────
	// Attack 1: the crash matrix over one ordinary round beside the
	// vouchers, in ACTIVE. All 144 cases hold (FFOR_EXHAUSTIVE=1); the
	// default run takes 18 of them.
	// ───────────────────────────────────────────────────────────────────
	describe('1a. ACTIVE: an ordinary round cut at every message boundary', () => {
		const AMOUNT = 7_000_000n;
		const PHASES = ['add', 'fulfil', 'fail'] as const;
		for (const offerer of SIDES) {
			const receiver = other(offerer);
			for (const phase of PHASES) {
				// add -> commitment_signed -> revoke_and_ack ->
				// commitment_signed -> revoke_and_ack: five messages, so six
				// boundaries (0 = nothing arrives, 5 = the cut falls after).
				for (let n = 0; n <= 5; n++) {
					// By default every other boundary of a round, with one
					// interrupt, both rotating so that the six rounds between
					// them meet every boundary and all four interrupts;
					// FFOR_EXHAUSTIVE=1 takes all four at every boundary.
					const round = SIDES.indexOf(offerer) + PHASES.indexOf(phase);
					if (!process.env.FFOR_EXHAUSTIVE && (n + round) % 2 !== 0) {
						continue;
					}
					const rotation = (n >> 1) + round;
					const interrupts = process.env.FFOR_EXHAUSTIVE
						? INTERRUPTS
						: [INTERRUPTS[rotation % INTERRUPTS.length]];
					for (const how of interrupts) {
						it(`${offerer} offers; the ${phase} round is cut after ${n} of 5 messages; ${how}`, () => {
							const pair = activePair();
							const hAct = Buffer.from(record(pair.rChannel).hAct!);
							let add: ReturnType<typeof offer>;
							const settle = (): void => {
								const res =
									phase === 'fail'
										? manager(pair, receiver).failHtlc(
												pair.channelId,
												add.id,
												Buffer.alloc(292)
										  )
										: manager(pair, receiver).fulfillHtlc(
												pair.channelId,
												add.id,
												add.preimage
										  );
								expect(res.ok, `${res.error} ${why(pair)}`).to.equal(true);
							};
							if (phase === 'add') {
								cutAfter(pair, n);
								add = offer(pair, offerer, AMOUNT);
								expect(add.result.ok, add.result.error).to.equal(true);
								interrupt(pair, how);
								pair.link.reconnect();
								expectAlive(pair, 'add round resumed');
								// The add is irrevocably committed on both sides.
								expect(
									ordinaryHtlcs(channel(pair, receiver)),
									why(pair)
								).to.deep.equal([`received-${add.id}`]);
								expect(ordinaryHtlcs(channel(pair, offerer))).to.deep.equal([
									`offered-${add.id}`
								]);
								expectActiveUnchanged(pair, hAct, 'add round resumed');
								settle();
							} else {
								add = offer(pair, offerer, AMOUNT);
								expect(add.result.ok, add.result.error).to.equal(true);
								cutAfter(pair, n);
								settle();
								interrupt(pair, how);
								pair.link.reconnect();
							}
							expectAlive(pair, 'resolved');
							expect(ordinaryHtlcs(pair.sChannel), why(pair)).to.deep.equal([]);
							expect(ordinaryHtlcs(pair.rChannel), why(pair)).to.deep.equal([]);
							expectSettled(pair, 'resolved');
							const moved = phase === 'fail' ? 0n : AMOUNT;
							const toR = offerer === 'S' ? moved : -moved;
							expect(balances(pair)).to.deep.equal({
								s: S_AFTER_BOOK - toR,
								r: R_START + toR,
								sViewOfR: R_START + toR,
								rViewOfS: S_AFTER_BOOK - toR
							});
							expectActiveUnchanged(pair, hAct, 'resolved');
							// The channel carries on.
							pay(pair, 'S', 1_000_000n);
							pay(pair, 'R', 1_000_000n);
							expectAlive(pair, 'traffic afterwards');
							expectActiveUnchanged(pair, hAct, 'traffic afterwards');
						});
					}
				}
			}
		}
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 1, DRAINING: the close, the drain and ordinary traffic, cut at
	// the message boundaries of the whole exchange. The side still alive
	// keeps working on the dead socket, so its retransmissions cross the
	// other side's after the reconnect. FFOR_EXHAUSTIVE=1 takes every
	// boundary for every interrupt.
	// ───────────────────────────────────────────────────────────────────
	describe('1b. scenarios cut at message boundaries', () => {
		const stride = process.env.FFOR_EXHAUSTIVE ? 1 : 18;
		for (const scenario of SCENARIOS) {
			INTERRUPTS.forEach((how, offset) => {
				it(`${scenario.name}: cut after a message (stride ${stride}); ${how}`, () => {
					const total = runCut(scenario, 1_000_000, how);
					expect(total).to.be.greaterThan(10);
					const failures: string[] = [];
					// Each interrupt starts four boundaries later, so the four of
					// them spread over the boundaries when striding.
					for (let n = (offset * 4) % stride; n < total; n += stride) {
						try {
							runCut(scenario, n, how);
						} catch (err) {
							failures.push(
								`cut after ${n}: ${(err as Error).message.slice(0, 600)}`
							);
						}
					}
					expect(failures, failures.join('\n\n')).to.deep.equal([]);
					console.log(`        (${total} message boundaries in the scenario)`);
				});
			});
		}
	});

	// ───────────────────────────────────────────────────────────────────
	// Attacks 1 and 5: a crash at a durable write, restarted from the last
	// row that landed rather than from memory. Every eighteenth write by
	// default; FFOR_EXHAUSTIVE=1 takes every one.
	// ───────────────────────────────────────────────────────────────────
	describe('1c. a crash at a durable write, restarted from the row on disk', () => {
		const stride = process.env.FFOR_EXHAUSTIVE ? 1 : 18;
		for (const scenario of SCENARIOS) {
			for (const victim of SIDES) {
				it(`${scenario.name}: ${victim} dies at its writes (stride ${stride})`, () => {
					const whole = runCrash(
						scenario,
						victim,
						1_000_000,
						'before the write'
					);
					expect(whole.crashed).to.equal(false);
					expect(whole.writes).to.be.greaterThan(4);
					const failures: string[] = [];
					for (let k = 0; k < whole.writes; k += stride) {
						for (const when of [
							'before the write',
							'after the write, before its sends'
						] as CrashWhen[]) {
							try {
								const res = runCrash(scenario, victim, k, when);
								expect(res.crashed).to.equal(true);
							} catch (err) {
								failures.push(
									`write ${k}, ${when}: ${(err as Error).message.slice(0, 600)}`
								);
							}
						}
					}
					expect(failures, failures.join('\n\n')).to.deep.equal([]);
					console.log(`        (${whole.writes} durable writes by ${victim})`);
				});
			}
		}
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 1, randomized: crossing messages, cuts and restarts.
	// ───────────────────────────────────────────────────────────────────
	describe('1d. schedule explorer, clear of issue #1300', () => {
		const [first, last] = (process.env.FFOR_SEEDS ?? '1-3')
			.split('-')
			.map(Number);
		for (const mode of ['none', 'active', 'draining'] as ExploreMode[]) {
			for (let seed = first; seed <= (last ?? first); seed++) {
				it(`${mode} seed ${seed}`, () => {
					const res = explore(seed, mode, true);
					expect(res.proneCuts).to.equal(0);
				});
			}
		}
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 6, issue #1300 in a concurrent epoch. Pre-existing: the same
	// replay order fails a channel with no epoch at all (the issue's own
	// repro). Not this PR's to fix, so the two cases below PIN what happens
	// today. When #1300 is fixed their last assertions fail; replace them
	// with the required outcome each comment names.
	// ───────────────────────────────────────────────────────────────────
	describe('6a. issue #1300 beside a live voucher book', () => {
		it('PIN [#1300] ACTIVE: R settles an HTLC behind its own unrevoked commitment_signed, the connection drops, and the reestablish fails the channel', () => {
			const pair = activePair();
			const inbound = offer(pair, 'S', 4_000_000n);
			expect(inbound.result.ok, inbound.result.error).to.equal(true);
			// R's add and its commitment_signed are lost with the socket; R,
			// which has not noticed yet, also fulfils the HTLC S offered.
			pair.link.drop = (): boolean => true;
			const out = offer(pair, 'R', 2_000_000n);
			expect(out.result.ok, out.result.error).to.equal(true);
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(prone1300(pair)).to.equal(true);
			interrupt(pair, 'disconnect');
			pair.link.reconnect();
			// Required once #1300 is fixed: both channels NORMAL, no wire
			// error, the epoch ACTIVE with its three vouchers
			// (expectAlive, expectActiveUnchanged). Today:
			expect(pair.link.types()).to.include(MessageType.ERROR);
			expect(pair.sErrors.join('|')).to.match(/Invalid commitment signature/);
			expect(pair.sChannel.getState()).to.equal(ChannelState.ERRORED);
			// The failure removed nothing: every voucher is still in the
			// commitments both sides hold.
			expect(vouchers(pair.sChannel).length).to.equal(3);
			expect(vouchers(pair.rChannel).length).to.equal(3);
		});

		it('PIN [#1300] DRAINING: the drain is issued behind an unrevoked commitment_signed, the connection drops, and the reestablish fails the channel', () => {
			const pair = activePair();
			settleSlot(pair, 2);
			// S's acknowledgement is in flight while R sends an ordinary add;
			// that add's commitment_signed, and all that follows, is lost.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.holdAt = null;
			pair.link.drop = (from): boolean => from === 'R';
			const out = offer(pair, 'R', 2_000_000n);
			expect(out.result.ok, out.result.error).to.equal(true);
			// The acknowledgement arrives: the drain is queued behind R's
			// unrevoked commitment_signed.
			pair.link.release('S');
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			expect(prone1300(pair)).to.equal(true);
			interrupt(pair, 'disconnect');
			pair.link.reconnect();
			// Required once #1300 is fixed: both channels NORMAL, no wire
			// error, the book CLOSED on both sides (expectAlive,
			// expectClosed). Today:
			expect(pair.link.types()).to.include(MessageType.ERROR);
			expect(pair.sErrors.join('|')).to.match(/Invalid commitment signature/);
			expect(pair.sChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(vouchers(pair.sChannel).length).to.equal(3);
		});

		it('every explorer failure with the avoidance off was cut on the #1300 precondition', () => {
			// The same walk, but the application stacks updates behind an
			// unrevoked commitment and cuts fall anywhere. Schedules fail; the
			// claim pinned here is that none fails WITHOUT a cut on the
			// precondition, in any mode, with or without an epoch.
			const failed: string[] = [];
			const unexplained: string[] = [];
			for (const mode of ['none', 'active', 'draining'] as ExploreMode[]) {
				for (let seed = 1; seed <= 6; seed++) {
					try {
						explore(seed, mode, false);
					} catch (err) {
						const text = (err as Error).message;
						failed.push(`${mode}/${seed}`);
						if (/precondition: 0\n/.test(text)) unexplained.push(text);
					}
				}
			}
			expect(unexplained, unexplained.join('\n\n')).to.deep.equal([]);
			// Not vacuous: the bug is hit, epoch or no epoch.
			expect(failed.some((f) => f.startsWith('none/'))).to.equal(true);
			expect(failed.some((f) => !f.startsWith('none/'))).to.equal(true);
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 2: the drain hold.
	// ───────────────────────────────────────────────────────────────────
	describe('2. the drain hold (R DRAINING, S reestablishes short of DRAINING)', () => {
		// CONCURRENT-RECEIVE.md section 3: "A close transition MAY briefly
		// serialize new ordinary adds, but MUST permit existing ordinary
		// fulfill/fail and commitment progress." Section 8: "Continue safe
		// fulfill/fail/replay work needed for existing obligations."
		//
		// handleReestablish parks the retransmission chain (updates and their
		// commitment_signed) until S's ff_close_ack returns, and the channel
		// is back in NORMAL meanwhile. Review round 1 of PR #1301 found that
		// nothing serialized NEW messages behind the parked chain: anything R
		// sent in that window reached S ahead of a commitment_signed that was
		// signed before it, and S failed the channel with "Invalid commitment
		// signature". Fixed: while the chain is held, every update,
		// commitment_signed and revoke_and_ack R would send joins the chain
		// (Channel.fforHoldStream, asked by the manager for every batch), and
		// a new add of R's is refused. The three shapes found, then the
		// baseline double fault the same gate closes (issue #1304).
		it('R fulfils an ordinary HTLC while its chain is held: the fulfil waits behind the chain, and both commit when the acknowledgement returns', () => {
			const { pair, inbound } = sLostTheClose([2]);
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			// R's chain is parked: only ff_close has left.
			expect(sentBy(pair, 'R')).to.deep.equal([
				MessageType.CHANNEL_REESTABLISH,
				MessageType.FF_CLOSE
			]);
			expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
			// An existing obligation: R holds the preimage of S's HTLC. It is
			// taken, and reported as owed to the wire, not as sent.
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(settle.sendsHeld).to.equal(true);
			expect(
				sentBy(pair, 'R'),
				'nothing left ahead of the chain'
			).to.deep.equal([MessageType.CHANNEL_REESTABLISH, MessageType.FF_CLOSE]);
			// S's acknowledgement arrives and the chain is released, the
			// fulfil of the ordinary HTLC after the commitment_signed that was
			// made before it.
			pair.link.release('S');
			const fromR = pair.link.log.filter((e) => e.from === 'R');
			const held = fromR.findIndex(
				(e) => e.type === MessageType.COMMITMENT_SIGNED
			);
			const late = fromR.findIndex(
				(e) =>
					e.type === MessageType.UPDATE_FULFILL_HTLC &&
					e.payload.readBigUInt64BE(32) === inbound.id
			);
			expect(held).to.be.greaterThan(-1);
			expect(late, 'behind the held commitment_signed').to.be.greaterThan(held);
			expectAlive(pair, 'chain released');
			expectClosed(pair, 'chain released');
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
			expect(balances(pair)).to.deep.equal(drained(6_000_000n));
		});

		it('R offers an ordinary HTLC while its chain is held: the add is refused locally, nothing leaves, and it is taken again once the chain is released', () => {
			const { pair, inbound } = sLostTheClose([2]);
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			// Serializing the add behind the close transition is allowed
			// (section 3), and this transition may not end on this connection.
			const out = offer(pair, 'R', 2_000_000n);
			expect(out.result.ok).to.equal(false);
			expect(out.result.error).to.match(
				/no new add while the close of the voucher book is being recovered/
			);
			expect(sentBy(pair, 'R')).to.deep.equal([
				MessageType.CHANNEL_REESTABLISH,
				MessageType.FF_CLOSE
			]);
			expect(ordinaryHtlcs(pair.rChannel), 'no entry for it').to.deep.equal([
				`received-${inbound.id}`
			]);
			pair.rErrors.length = 0;
			pair.link.release('S');
			expectAlive(pair, 'chain released');
			expectClosed(pair, 'chain released');
			const again = offer(pair, 'R', 2_000_000n);
			expect(again.result.ok, again.result.error).to.equal(true);
			expectAlive(pair, 'an add after the release');
			expect(ordinaryHtlcs(pair.sChannel)).to.include(`received-${again.id}`);
		});

		it("S forwards a payment to R while R's chain is held: R's revoke_and_ack waits behind the held commitment_signed", () => {
			const { pair } = sLostTheClose([2]);
			// S has answered the reestablish; R's retransmitted ff_close is
			// still in flight when S, ACTIVE and concurrent, adds an HTLC.
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.FF_CLOSE;
			pair.link.reconnect();
			pair.link.holdAt = null;
			const add = offer(pair, 'S', 2_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			// R took S's commitment_signed and revoked for it, in its state.
			// On the wire there is still ff_close and nothing else.
			expect(pair.link.inFlight('R')).to.deep.equal([MessageType.FF_CLOSE]);
			pair.link.release('R');
			// S's acknowledgement released the chain: the commitment_signed
			// made before S's add, then the revoke_and_ack that admits it.
			const fromR = sentBy(pair, 'R');
			const signed = fromR.indexOf(MessageType.COMMITMENT_SIGNED);
			const revoked = fromR.indexOf(MessageType.REVOKE_AND_ACK);
			expect(signed).to.be.greaterThan(-1);
			expect(revoked, 'behind the held commitment_signed').to.be.greaterThan(
				signed
			);
			expectAlive(pair, 'chain released');
			expectClosed(pair, 'chain released');
			expect(ordinaryHtlcs(pair.rChannel)).to.include(`received-${add.id}`);
			expect(pair.events.R.forwarded, 'the add is committed').to.include(
				add.id
			);
		});

		it("S fulfils an HTLC of R's while R's chain is held: the round completes behind the chain", () => {
			// The peer's settle is the third thing R answers with a
			// revoke_and_ack. R's own HTLC is in flight from before the close.
			const pair = activePair();
			const out = offer(pair, 'R', 3_000_000n);
			expect(out.result.ok, out.result.error).to.equal(true);
			settleSlot(pair, 2);
			const backup = snapshot(pair, 'S');
			pair.link.drop = (from, type): boolean =>
				from === 'R' && type !== MessageType.FF_CLOSE;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.drop = null;
			restart(pair, 'S', backup);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.FF_CLOSE;
			pair.link.reconnect();
			pair.link.holdAt = null;
			const settle = pair.sManager.fulfillHtlc(
				pair.channelId,
				out.id,
				out.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(pair.link.inFlight('R')).to.deep.equal([MessageType.FF_CLOSE]);
			pair.link.release('R');
			expectAlive(pair, 'chain released');
			expectClosed(pair, 'chain released');
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
			expect(pair.events.R.fulfilled).to.include(out.id);
		});

		it('control: with nothing sent in the window, the same hold releases cleanly', () => {
			const { pair, inbound } = sLostTheClose([2]);
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			pair.link.release('S');
			expectAlive(pair, 'chain released');
			expectClosed(pair, 'chain released');
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(balances(pair)).to.deep.equal(drained(6_000_000n));
			expectSettled(pair, 'after the drain');
		});

		it('the reverse: S is DRAINING and R comes back from a row before its ff_close; nothing fails, traffic flows, and a second close ends the book', () => {
			const pair = activePair();
			settleSlot(pair, 2);
			const backup = snapshot(pair, 'R');
			pair.link.drop = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.drop = null;
			restart(pair, 'R', backup);
			expect(record(pair.rChannel).closeSent).to.equal(false);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.reconnect();
			// S replays an acknowledgement R has no close for; R reports it
			// and neither channel fails.
			expect(pair.rErrors.join('|')).to.match(/without ff_close/);
			expectAlive(pair, 'reconnected');
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			// R's close signs the same bytes again; S answers with the same ack.
			const again = pair.rManager.closeFforEpoch(pair.channelId);
			expect(again.ok, again.error).to.equal(true);
			expectAlive(pair, 'closed');
			expectClosed(pair, 'closed');
			expect(balances(pair)).to.deep.equal(drained(0n));
			expectSettled(pair, 'closed');
		});

		it('an earlier state: S comes back from a row that predates the activation (ABORTED on reconnect); R still drains, is paid for the settled slot, and the channel carries on', () => {
			const pair = createPair({ pushSat: 200_000n });
			let row: string | null = null;
			pair.sManager.on('channel:persist', () => {
				if (record(pair.sChannel).state === FforState.VOUCHERS_COMMITTED) {
					row = snapshot(pair, 'S');
				}
			});
			activate(pair, AMOUNTS, true);
			expect(row).to.not.equal(null);
			settleSlot(pair, 2);
			pair.link.drop = (from, type): boolean =>
				from === 'R' && type !== MessageType.FF_CLOSE;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.drop = null;
			restart(pair, 'S', row!);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.reconnect();
			expectAlive(pair, 'reconnected');
			expect(FforState[record(pair.sChannel).state]).to.equal('ABORTED');
			expect(FforState[record(pair.rChannel).state]).to.equal('CLOSED');
			expect(vouchers(pair.sChannel)).to.deep.equal([]);
			expect(vouchers(pair.rChannel)).to.deep.equal([]);
			expect(balances(pair)).to.deep.equal(drained(0n));
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectSettled(pair, 'afterwards');
		});

		describe('a second fault while holding loses and duplicates nothing', () => {
			it('the connection drops again before the acknowledgement arrives', () => {
				const { pair, inbound } = sLostTheClose([2]);
				pair.link.holdAt = (from, type): boolean =>
					from === 'S' && type === MessageType.FF_CLOSE_ACK;
				pair.link.reconnect();
				pair.link.holdAt = null;
				expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
				// The acknowledgement dies with the socket.
				interrupt(pair, 'disconnect');
				pair.link.reconnect();
				expectAlive(pair, 'second reconnect');
				expectClosed(pair, 'second reconnect');
				// One chain, once: three voucher updates.
				const fromR = sentBy(pair, 'R');
				expect(
					fromR.filter((t) => t === MessageType.UPDATE_FAIL_HTLC).length
				).to.equal(2);
				expect(
					fromR.filter((t) => t === MessageType.UPDATE_FULFILL_HTLC).length
				).to.equal(1);
				const settle = pair.rManager.fulfillHtlc(
					pair.channelId,
					inbound.id,
					inbound.preimage
				);
				expect(settle.ok, settle.error).to.equal(true);
				expect(balances(pair)).to.deep.equal(drained(6_000_000n));
				expectSettled(pair, 'second reconnect');
			});

			it('S loses the close a second time (the same old row again)', () => {
				const { pair, inbound, backup } = sLostTheClose([2]);
				pair.link.holdAt = (from, type): boolean =>
					from === 'S' && type === MessageType.FF_CLOSE_ACK;
				pair.link.reconnect();
				pair.link.holdAt = null;
				pair.link.disconnect();
				restart(pair, 'S', backup);
				pair.link.log.length = 0;
				pair.link.reconnect();
				expectAlive(pair, 'second hold released');
				expectClosed(pair, 'second hold released');
				const settle = pair.rManager.fulfillHtlc(
					pair.channelId,
					inbound.id,
					inbound.preimage
				);
				expect(settle.ok, settle.error).to.equal(true);
				expect(balances(pair)).to.deep.equal(drained(6_000_000n));
				expectSettled(pair, 'second hold released');
			});

			for (const how of ['restart R', 'restart both'] as Interrupt[]) {
				it(`${how} while holding`, () => {
					const { pair, inbound } = sLostTheClose([2]);
					pair.link.holdAt = (from, type): boolean =>
						from === 'S' && type === MessageType.FF_CLOSE_ACK;
					pair.link.reconnect();
					pair.link.holdAt = null;
					interrupt(pair, how);
					pair.link.reconnect();
					expectAlive(pair, 'after the restart');
					expectClosed(pair, 'after the restart');
					const settle = pair.rManager.fulfillHtlc(
						pair.channelId,
						inbound.id,
						inbound.preimage
					);
					expect(settle.ok, settle.error).to.equal(true);
					expect(balances(pair)).to.deep.equal(drained(6_000_000n));
					expectSettled(pair, 'after the restart');
				});
			}
		});

		describe("S's re-issued acknowledgement differs from the one R holds", () => {
			/**
			 * S's row predates a settlement as well as the close: the
			 * acknowledgement it signs again marks slot 2 unsettled, R's marks
			 * it settled. R answers "ff_close_ack differs" and keeps holding.
			 */
			function differingAck(): {
				pair: IPair;
				inbound: ReturnType<typeof offer>;
			} {
				const pair = activePair();
				const inbound = offer(pair, 'S', 6_000_000n);
				expect(inbound.result.ok, inbound.result.error).to.equal(true);
				const backup = snapshot(pair, 'S');
				settleSlot(pair, 2);
				pair.link.drop = (from, type): boolean =>
					from === 'R' && type !== MessageType.FF_CLOSE;
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				pair.link.drop = null;
				restart(pair, 'S', backup);
				pair.link.log.length = 0;
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				pair.link.reconnect();
				expect(pair.rErrors.join('|')).to.match(/ff_close_ack differs/);
				expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
				expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
				return { pair, inbound };
			}

			it('the hold is not released on this connection; the next reconnect drains, and R is paid for the slot it holds a preimage for', () => {
				// As in baseline: the wedge lasts until the next reestablish,
				// where S reports DRAINING and no hold applies.
				const { pair, inbound } = differingAck();
				expect(sentBy(pair, 'R')).to.not.include(MessageType.COMMITMENT_SIGNED);
				expect(vouchers(pair.sChannel).length).to.equal(3);
				interrupt(pair, 'disconnect');
				pair.link.reconnect();
				expectAlive(pair, 'second reconnect');
				expectClosed(pair, 'second reconnect');
				const settle = pair.rManager.fulfillHtlc(
					pair.channelId,
					inbound.id,
					inbound.preimage
				);
				expect(settle.ok, settle.error).to.equal(true);
				expect(balances(pair)).to.deep.equal(drained(6_000_000n));
			});

			// Section 3: new work that cannot proceed is rejected. Review
			// round 1 of PR #1301 found that both sides answered ok and put
			// updates on the wire that R could not sign for the rest of the
			// connection (its only commitment_signed is parked). Fixed on R,
			// the side that knows: the differing acknowledgement puts the
			// epoch in dispute, durably, and while the chain stays held R
			// refuses its own new adds and its own settles, as a channel
			// awaiting reestablish does. S cannot know its acknowledgement was
			// refused; what it sends is taken and answered behind the chain,
			// and commits at the reconnect.
			it('the epoch is in dispute: R refuses its own adds and settles into the wedge, the host is told once, and the record keeps it across a restart', () => {
				const pair = activePair();
				const enforce: Buffer[] = [];
				pair.rManager.on('ffor:enforce', (id: Buffer) => enforce.push(id));
				const inbound = offer(pair, 'S', 6_000_000n);
				expect(inbound.result.ok, inbound.result.error).to.equal(true);
				const backup = snapshot(pair, 'S');
				settleSlot(pair, 2);
				pair.link.drop = (from, type): boolean =>
					from === 'R' && type !== MessageType.FF_CLOSE;
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				pair.link.drop = null;
				restart(pair, 'S', backup);
				pair.link.log.length = 0;
				expect(record(pair.rChannel).activationMismatch).to.equal(false);
				expect(enforce.length).to.equal(0);
				pair.link.reconnect();
				expect(pair.rErrors.join('|')).to.match(/ff_close_ack differs/);
				expect(record(pair.rChannel).activationMismatch).to.equal(true);
				expect(enforce.length, "'ffor:enforce' on R").to.equal(1);
				expect(enforce[0].equals(pair.channelId)).to.equal(true);

				const fromR = offer(pair, 'R', 1_000_000n);
				expect(fromR.result.ok).to.equal(false);
				expect(fromR.result.error).to.match(
					/no new add while the epoch is in dispute/
				);
				const settle = pair.rManager.fulfillHtlc(
					pair.channelId,
					inbound.id,
					inbound.preimage
				);
				expect(settle.ok).to.equal(false);
				expect(settle.error).to.match(
					/no settle until the channel reestablishes/
				);
				const fail = pair.rManager.failHtlc(
					pair.channelId,
					inbound.id,
					Buffer.alloc(292)
				);
				expect(fail.ok).to.equal(false);
				// Nothing of R's stream is on the wire, and nothing was queued:
				// the inbound HTLC is as it was.
				expect(sentBy(pair, 'R')).to.deep.equal([
					MessageType.CHANNEL_REESTABLISH,
					MessageType.FF_CLOSE
				]);
				expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([
					`received-${inbound.id}`
				]);
				expect(prone1300(pair), 'nothing queued behind the chain').to.equal(
					false
				);
				// The same differing acknowledgement again announces nothing new.
				const again = pair.link.log.find(
					(e) => e.from === 'S' && e.type === MessageType.FF_CLOSE_ACK
				)!;
				pair.rManager.handleMessage(
					pair.sPub,
					MessageType.FF_CLOSE_ACK,
					again.payload
				);
				expect(enforce.length).to.equal(1);
				expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);

				// The dispute is on the record, and survives R's restart.
				restart(pair, 'R');
				expect(record(pair.rChannel).activationMismatch).to.equal(true);
			});

			it("S cannot know: its add into the wedge is taken by R and answered behind the chain, and it commits at the reconnect with R's settle and the drain", () => {
				const { pair, inbound } = differingAck();
				const fromS = offer(pair, 'S', 1_000_000n);
				expect(fromS.result.ok, fromS.result.error).to.equal(true);
				// R holds the add and has revoked for it in its own state, but
				// nothing of R's has left: no revoke_and_ack overtakes the chain.
				expect(
					pair.rChannel.getFullState().htlcs.has(`received-${fromS.id}`)
				).to.equal(true);
				expect(sentBy(pair, 'R')).to.not.include(MessageType.REVOKE_AND_ACK);
				expect(sentBy(pair, 'R')).to.not.include(MessageType.COMMITMENT_SIGNED);
				expect(pair.events.R.forwarded).to.not.include(fromS.id);
				expectAlive(pair, 'in the wedge');
				// The reconnect ends the wedge: S reports DRAINING, no hold
				// applies, and the retransmission carries the chain and R's
				// revoke_and_ack in the order R made them.
				interrupt(pair, 'disconnect');
				pair.link.reconnect();
				expectAlive(pair, 'second reconnect');
				expectClosed(pair, 'second reconnect');
				expect(pair.events.R.forwarded, "S's add commits").to.include(fromS.id);
				// R's settle, refused in the wedge, goes through now.
				const settle = pair.rManager.fulfillHtlc(
					pair.channelId,
					inbound.id,
					inbound.preimage
				);
				expect(settle.ok, settle.error).to.equal(true);
				const other2 = pair.rManager.fulfillHtlc(
					pair.channelId,
					fromS.id,
					fromS.preimage
				);
				expect(other2.ok, other2.error).to.equal(true);
				expect(balances(pair)).to.deep.equal(drained(7_000_000n));
				expectSettled(pair, 'after the wedge');
			});

			it('a differing acknowledgement after the book has CLOSED records no dispute: every voucher is already resolved', () => {
				const pair = activePair();
				const enforce: Buffer[] = [];
				pair.rManager.on('ffor:enforce', (id: Buffer) => enforce.push(id));
				settleSlot(pair, 2);
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				expectClosed(pair, 'closed');
				const other2 = Buffer.from(
					record(pair.rChannel).closeAckWire!.subarray(2)
				);
				other2[other2.length - 1] ^= 1;
				pair.rErrors.length = 0;
				pair.rManager.handleMessage(
					pair.sPub,
					MessageType.FF_CLOSE_ACK,
					other2
				);
				expect(pair.rErrors.join('|')).to.match(/ff_close_ack differs/);
				expect(record(pair.rChannel).activationMismatch).to.equal(false);
				expect(enforce.length).to.equal(0);
				pair.rErrors.length = 0;
				pay(pair, 'R', 1_000_000n);
				expectAlive(pair, 'afterwards');
			});

			it('control: a baseline epoch answers a differing acknowledgement as before, with no dispute recorded', () => {
				const pair = createPair({ pushSat: 200_000n });
				activate(pair, AMOUNTS, false);
				const backup = snapshot(pair, 'S');
				settleSlot(pair, 2);
				pair.link.drop = (from, type): boolean =>
					from === 'R' && type !== MessageType.FF_CLOSE;
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				pair.link.drop = null;
				restart(pair, 'S', backup);
				pair.link.log.length = 0;
				pair.rErrors.length = 0;
				pair.link.reconnect();
				expect(pair.rErrors.join('|')).to.match(/ff_close_ack differs/);
				expect(record(pair.rChannel).activationMismatch).to.equal(false);
				expect(sentBy(pair, 'R')).to.not.include(MessageType.COMMITMENT_SIGNED);
				interrupt(pair, 'disconnect');
				pair.link.reconnect();
				expectAlive(pair, 'second reconnect');
				expectClosed(pair, 'second reconnect');
			});
		});

		it('R restarts from the row its DRAINING write left (drain queued, nothing signed) and S lost the close: the commitment_signed the reestablish tail signs waits behind the held updates, in a concurrent and in a baseline epoch (#1304)', () => {
			// A double fault: R dies between the DRAINING write and the
			// commitment_signed, AND S's row predates ff_close. The chain R
			// holds then has no commitment_signed in it, so the auto-sign that
			// follows every reestablish signs over the held updates. It used to
			// send that signature ahead of them, in a baseline epoch as well
			// (issue #1304); the same gate now puts it behind them.
			const outcomes: string[] = [];
			for (const concurrent of [true, false]) {
				const pair = createPair({ pushSat: 200_000n });
				activate(pair, AMOUNTS, concurrent);
				settleSlot(pair, 2);
				const backup = snapshot(pair, 'S');
				let row: string | null = null;
				pair.rManager.on('channel:persist', () => {
					if (
						row === null &&
						record(pair.rChannel).state === FforState.DRAINING
					) {
						row = snapshot(pair, 'R');
					}
				});
				pair.link.drop = (from, type): boolean =>
					from === 'R' && type !== MessageType.FF_CLOSE;
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				pair.link.drop = null;
				restart(pair, 'S', backup);
				restart(pair, 'R', row!);
				const st = pair.rChannel.getFullState();
				expect(st.pendingLocalUpdates.length).to.equal(3);
				expect(st.pendingLocalUpdatesSignedCount).to.equal(0);
				pair.link.log.length = 0;
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				pair.link.reconnect();
				// The three voucher updates, then the one commitment_signed.
				const fromR = sentBy(pair, 'R').filter(
					(t) =>
						t === MessageType.UPDATE_FULFILL_HTLC ||
						t === MessageType.UPDATE_FAIL_HTLC ||
						t === MessageType.COMMITMENT_SIGNED
				);
				expect(fromR.length, `concurrent=${concurrent}`).to.equal(4);
				expect(fromR[3]).to.equal(MessageType.COMMITMENT_SIGNED);
				outcomes.push(
					`concurrent=${concurrent}: S ${
						ChannelState[pair.sChannel.getState()]
					} ${FforState[record(pair.sChannel).state]}, R ${
						ChannelState[pair.rChannel.getState()]
					} ${FforState[record(pair.rChannel).state]}, ${pair.sErrors.join(
						'; '
					)}`
				);
				expect(balances(pair), `concurrent=${concurrent}`).to.deep.equal(
					drained(0n)
				);
			}
			expect(outcomes).to.deep.equal([
				'concurrent=true: S NORMAL CLOSED, R NORMAL CLOSED, ',
				'concurrent=false: S NORMAL CLOSED, R NORMAL CLOSED, '
			]);
		});

		it('in quorum mode the released chain waits for the frame its release wrote, then leaves in order, and nothing is refused for want of a frame', async () => {
			// Recovery Protocol 5.8: a commitment_signed, a revoke_and_ack or
			// an update_fulfill_htlc leaves only against the persist that
			// authorized it, and a batch that sends one with no persist ahead
			// is refused outright. The release therefore leads with a persist
			// of its own, and what R made while holding rides behind it.
			const pair = activePair();
			const waiting: Array<
				(outcome: { released: boolean; reason: string }) => void
			> = [];
			const barrier = {
				enforcing: true,
				open: true,
				isReleased(): boolean {
					return this.open;
				},
				whenReleased(): Promise<{ released: boolean; reason: string }> {
					if (this.open) {
						return Promise.resolve({ released: true, reason: '' });
					}
					return new Promise((resolve) => waiting.push(resolve));
				}
			};
			pair.rConfig.durabilityBarrier = barrier;
			restart(pair, 'R');
			const frozen: string[] = [];
			pair.rManager.on(
				'transition:frozen',
				(_peer: string, _id: string, reason: string) => frozen.push(reason)
			);
			pair.link.reconnect();
			settleSlot(pair, 2);
			const backup = snapshot(pair, 'S');
			pair.link.drop = (from, type): boolean =>
				from === 'R' && type !== MessageType.FF_CLOSE;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.drop = null;
			restart(pair, 'S', backup);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			// S adds while R's ff_close is in flight; R answers behind its chain.
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.FF_CLOSE;
			pair.link.reconnect();
			pair.link.holdAt = null;
			const add = offer(pair, 'S', 2_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			// From here R's frames are not yet quorum durable.
			barrier.open = false;
			pair.link.release('R');
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			// The acknowledgement came back and the chain is released, but it
			// is parked behind the frame of its own persist: nothing left.
			expect(sentBy(pair, 'R')).to.not.include(MessageType.COMMITMENT_SIGNED);
			expect(sentBy(pair, 'R')).to.not.include(MessageType.REVOKE_AND_ACK);
			expect(waiting.length, 'one batch waits on the barrier').to.equal(1);
			barrier.open = true;
			for (const resolve of waiting.splice(0)) {
				resolve({ released: true, reason: '' });
			}
			for (let i = 0; i < 10; i++) {
				await new Promise<void>((resolve) => setImmediate(resolve));
			}
			expect(frozen, 'no batch was refused').to.deep.equal([]);
			const fromR = sentBy(pair, 'R');
			const signed = fromR.indexOf(MessageType.COMMITMENT_SIGNED);
			expect(signed).to.be.greaterThan(-1);
			expect(fromR.indexOf(MessageType.REVOKE_AND_ACK)).to.be.greaterThan(
				signed
			);
			expectAlive(pair, 'chain released');
			expectClosed(pair, 'chain released');
			expect(pair.events.R.forwarded).to.include(add.id);
		});

		it('PIN [#1300] a settle waiting behind the held chain, then the connection drops before the acknowledgement: the reconnect replays it ahead of the commitment_signed that does not cover it', () => {
			// What waits behind the chain is, in the channel's state, an update
			// queued behind an unrevoked commitment_signed: issue #1300's
			// precondition, here as anywhere. Not this PR's to fix. Required
			// once #1300 is fixed: no wire error, both channels NORMAL, the
			// book CLOSED (expectAlive, expectClosed). Today:
			const { pair, inbound } = sLostTheClose([2]);
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(prone1300(pair)).to.equal(true);
			// The acknowledgement dies with the socket; S holds the close now.
			interrupt(pair, 'disconnect');
			pair.link.reconnect();
			expect(pair.link.types()).to.include(MessageType.ERROR);
			expect(pair.sErrors.join('|')).to.match(/Invalid commitment signature/);
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 3: acknowledgement loss.
	// ───────────────────────────────────────────────────────────────────
	describe('3. ff_activate_ack lost: R ACTIVATING, S ACTIVE and already sending', () => {
		for (const how of INTERRUPTS) {
			it(`S has an ordinary add and its commitment_signed queued; ${how}; the ack leads the replay and nothing fails`, () => {
				const pair = createPair({ pushSat: 200_000n });
				// The ack and everything S sends after it die with the socket.
				let dead = false;
				pair.link.drop = (from, type): boolean => {
					if (from === 'S' && type === MessageType.FF_ACTIVATE_ACK) dead = true;
					return dead;
				};
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, { concurrent: true })
				);
				expect(res.ok, res.error).to.equal(true);
				expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
				expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
				const add = offer(pair, 'S', 7_000_000n);
				expect(add.result.ok, add.result.error).to.equal(true);
				const hAct = Buffer.from(record(pair.sChannel).hAct!);
				interrupt(pair, how);
				// Restarted or not, R is still ACTIVATING with the version it
				// selected at ff_accept.
				expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
				expect(record(pair.rChannel).concurrentVersion).to.equal(1);
				pair.link.reconnect();
				const fromS = sentBy(pair, 'S');
				expect(fromS.indexOf(MessageType.FF_ACTIVATE_ACK)).to.be.greaterThan(
					-1
				);
				expect(fromS.indexOf(MessageType.FF_ACTIVATE_ACK)).to.be.lessThan(
					fromS.indexOf(MessageType.UPDATE_ADD_HTLC)
				);
				expectAlive(pair, 'ack replayed');
				expectActiveUnchanged(pair, hAct, 'ack replayed');
				expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([
					`received-${add.id}`
				]);
				const settle = pair.rManager.fulfillHtlc(
					pair.channelId,
					add.id,
					add.preimage
				);
				expect(settle.ok, settle.error).to.equal(true);
				expect(balances(pair)).to.deep.equal({
					s: S_AFTER_BOOK - 7_000_000n,
					r: R_START + 7_000_000n,
					sViewOfR: R_START + 7_000_000n,
					rViewOfS: S_AFTER_BOOK - 7_000_000n
				});
				expectSettled(pair, 'settled');
			});
		}

		it('the connection drops a second time before the replayed ack arrives: still no update reaches an ACTIVATING R', () => {
			const pair = createPair({ pushSat: 200_000n });
			let dead = false;
			const loseTheAck = (from: Side, type: number): boolean => {
				if (from === 'S' && type === MessageType.FF_ACTIVATE_ACK) dead = true;
				return dead;
			};
			pair.link.drop = loseTheAck;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			const add = offer(pair, 'S', 7_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			const hAct = Buffer.from(record(pair.sChannel).hAct!);
			interrupt(pair, 'disconnect');
			// The replayed ack is lost again, with what follows it.
			dead = false;
			pair.link.drop = loseTheAck;
			pair.link.reconnect();
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
			expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
			interrupt(pair, 'restart both');
			pair.link.reconnect();
			expectAlive(pair, 'third connection');
			expectActiveUnchanged(pair, hAct, 'third connection');
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([
				`received-${add.id}`
			]);
		});

		// Base section 7.5.4: "ACTIVE is on disk before the ack leaves", and
		// the manager's own comment for a failed write: "nothing that
		// transition authorizes may follow it".
		//
		// handleFforActivate has already moved S's record to ACTIVE and ended
		// S's quiescence in memory when the write fails. The ack is withheld,
		// so R stays ACTIVATING and quiescent. Review round 1 of PR #1301
		// found that S's concurrent epoch admitted ordinary adds there: when
		// the failure was transient (the next write lands), an add S sent
		// before the node's deferred disconnect reached R, which failed the
		// channel ("update_add_htlc after your stfu"). A baseline S is frozen
		// in ACTIVE and refuses the add locally (the control below).
		//
		// Fixed: a concurrent S originates nothing until the dispatch has put
		// its ff_activate_ack on the wire.
		it("S's ACTIVE write fails once: S, ACTIVE only in memory with its ack withheld, refuses its own add, and takes it again once the reconnect has replayed the ack", () => {
			const pair = createPair({ pushSat: 200_000n });
			let blocked = 0;
			let failed = 0;
			pair.sManager.on(
				'channel:persist',
				(ev: { request?: { committed: boolean } }) => {
					if (
						failed === 0 &&
						record(pair.sChannel).state === FforState.ACTIVE &&
						ev.request
					) {
						ev.request.committed = false;
						failed++;
					}
				}
			);
			pair.sManager.on('transition:blocked', () => blocked++);
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			expect(blocked).to.equal(1);
			expect(pair.link.types()).to.not.include(MessageType.FF_ACTIVATE_ACK);
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
			// Before the forced disconnect (deferred by setImmediate in the
			// node), S originates a payment to R. The write would land now.
			pair.link.log.length = 0;
			const add = offer(pair, 'S', 2_000_000n);
			expect(add.result.ok).to.equal(false);
			expect(add.result.error).to.match(
				/no add until ff_activate_ack has been sent/
			);
			expect(sentBy(pair, 'S')).to.deep.equal([]);
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([]);
			pair.sErrors.length = 0;
			expectAlive(pair, 'after the refused add');
			// The disconnect the node forces, and the reconnect: R reports
			// ACTIVATING, S replays the ack ahead of everything, and from then
			// on S's ordinary traffic is taken.
			interrupt(pair, 'disconnect');
			pair.link.reconnect();
			expect(sentBy(pair, 'S')).to.include(MessageType.FF_ACTIVATE_ACK);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			expectAlive(pair, 'ack replayed');
			pay(pair, 'S', 2_000_000n);
			expectAlive(pair, 'an ordinary payment of S');
		});

		it("the ack is replayed but its write fails again: S still originates nothing, and R's channel survives", () => {
			const pair = createPair({ pushSat: 200_000n });
			let failing = true;
			pair.sManager.on(
				'channel:persist',
				(ev: { request?: { committed: boolean } }) => {
					if (
						failing &&
						record(pair.sChannel).state === FforState.ACTIVE &&
						ev.request
					) {
						ev.request.committed = false;
					}
				}
			);
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			interrupt(pair, 'disconnect');
			pair.link.log.length = 0;
			pair.link.reconnect();
			// The reestablish persist failed too: the replayed ack is withheld.
			expect(sentBy(pair, 'S')).to.not.include(MessageType.FF_ACTIVATE_ACK);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
			failing = false;
			const add = offer(pair, 'S', 2_000_000n);
			expect(add.result.ok).to.equal(false);
			expect(sentBy(pair, 'S')).to.not.include(MessageType.UPDATE_ADD_HTLC);
			expect(pair.rChannel.getState()).to.not.equal(ChannelState.ERRORED);
			expect(pair.link.types()).to.not.include(MessageType.ERROR);
		});

		it('a restarted S does not know whether its ack left: it originates nothing until the reestablish has settled it', () => {
			const pair = createPair({ pushSat: 200_000n });
			let dead = false;
			pair.link.drop = (from, type): boolean => {
				if (from === 'S' && type === MessageType.FF_ACTIVATE_ACK) dead = true;
				return dead;
			};
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
			pair.link.drop = null;
			restart(pair, 'S');
			const internal = pair.sChannel as unknown as {
				_fforActivateAckUnsent: boolean;
			};
			expect(internal._fforActivateAckUnsent, 'from the record').to.equal(true);
			pair.link.log.length = 0;
			pair.link.reconnect();
			expect(internal._fforActivateAckUnsent, 'the replay left').to.equal(
				false
			);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			pay(pair, 'S', 2_000_000n);
			expectAlive(pair, 'after the replay');
			// And when R already holds the ack, the reestablish clears it with
			// nothing replayed.
			restart(pair, 'S');
			pair.link.log.length = 0;
			pair.link.reconnect();
			expect(sentBy(pair, 'S')).to.not.include(MessageType.FF_ACTIVATE_ACK);
			pay(pair, 'S', 1_000_000n);
			expectAlive(pair, 'after a second restart');
		});

		it('control: a baseline S whose ACTIVE write fails once refuses the add locally and the channel survives', () => {
			const pair = createPair({ pushSat: 200_000n });
			let failed = 0;
			pair.sManager.on(
				'channel:persist',
				(ev: { request?: { committed: boolean } }) => {
					if (
						failed === 0 &&
						record(pair.sChannel).state === FforState.ACTIVE &&
						ev.request
					) {
						ev.request.committed = false;
						failed++;
					}
				}
			);
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS)
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.log.length = 0;
			const add = offer(pair, 'S', 2_000_000n);
			expect(add.result.ok).to.equal(false);
			expectAlive(pair, 'after the refused add');
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 5 (failed writes): pre-existing and not FFOR, issue #1303. One
	// transient failed write withholds an update; the next batch on the same
	// connection signs over it. Reproduced on origin/master at fc0184e4 on a
	// channel with no epoch. Concurrent ordinary traffic inherits it. A PIN
	// of what happens today: when #1303 is fixed the last assertion fails,
	// and the required outcome is that neither channel is ERRORED.
	// ───────────────────────────────────────────────────────────────────
	describe('5a. a single failed write, then a write that lands', () => {
		it('PIN [#1303, no epoch needed] the fulfil is withheld, the auto-sign that follows signs over it and the peer fails the channel', () => {
			const outcomes: string[] = [];
			for (const withEpoch of [false, true]) {
				const pair = createPair({ pushSat: 200_000n });
				if (withEpoch) activate(pair, AMOUNTS, true);
				const add = offer(pair, 'S', 2_000_000n);
				expect(add.result.ok, add.result.error).to.equal(true);
				let failed = 0;
				pair.rManager.on(
					'channel:persist',
					(ev: { request?: { committed: boolean } }) => {
						if (failed === 0 && ev.request) {
							ev.request.committed = false;
							failed++;
						}
					}
				);
				pair.link.log.length = 0;
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				const res = pair.rManager.fulfillHtlc(
					pair.channelId,
					add.id,
					add.preimage
				);
				expect(res.sendsWithheld).to.equal(true);
				outcomes.push(
					`epoch=${withEpoch}: S ${ChannelState[pair.sChannel.getState()]}, R ${
						ChannelState[pair.rChannel.getState()]
					}, ${pair.sErrors.join('; ')}`
				);
			}
			// Required once #1303 is fixed: no line says ERRORED. Today both do,
			// with and without an epoch.
			expect(outcomes.length).to.equal(2);
			for (const outcome of outcomes) {
				expect(outcome).to.match(
					/S ERRORED, R ERRORED, Invalid commitment signature/
				);
			}
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 4: the capability hold.
	// ───────────────────────────────────────────────────────────────────
	describe('4. the capability hold', () => {
		// Section 8: "An observed incompatible reconnect holds new admission
		// without changing the persisted mode ... restore support or use safe
		// retirement or enforcement." The PR's own test pins that the hold
		// "lasts through a later disconnect until a compatible init".
		//
		// Review round 1 of PR #1301 found the hold was memory only, so a
		// restart of either side forgot an observed incompatible init. Fixed:
		// it is a field of the epoch record, written only while it stands,
		// persisted by the reestablish that observed it and judged afresh by
		// every later one.
		it('S restarts after an incompatible reconnect, R still away: the hold survives the restart and S starts no delegated settlement', () => {
			const pair = activePair();
			pair.link.disconnect();
			advertise(pair, 'R', false);
			pair.link.reconnect();
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
				/capability hold/
			);
			// R goes away. S is still holding, as the PR pins.
			pair.link.disconnect();
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
				/capability hold/
			);
			// S restarts. Nothing about R's capabilities has changed.
			restart(pair, 'S');
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			expect(
				pair.sChannel.fforSettlementRefusal(1, TIP),
				'the hold must survive the restart'
			).to.match(/capability hold/);
			// R comes back with the capability: the hold lifts, on the record
			// too, and stays lifted across another restart.
			advertise(pair, 'R', true);
			pair.link.reconnect();
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
			expect(record(pair.sChannel).capabilityHold).to.equal(undefined);
			restart(pair, 'S');
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
		});

		it('R restarts after an incompatible reconnect: the hold survives the restart and R exposes no voucher invoice', () => {
			const pair = activePair();
			pair.link.disconnect();
			advertise(pair, 'S', false);
			pair.link.reconnect();
			expect(pair.rChannel.fforAdmissionHold()).to.match(/did not advertise/);
			pair.link.disconnect();
			expect(pair.rChannel.fforAdmissionHold()).to.match(/did not advertise/);
			restart(pair, 'R');
			// createFforVoucherInvoice asks exactly this before exposing a slot.
			expect(
				pair.rChannel.fforAdmissionHold(),
				'the hold must survive the restart'
			).to.match(/did not advertise/);
		});

		it('the hold is written by the reestablish that observes it, although that reestablish sends nothing, and only while it stands', () => {
			const pair = activePair();
			const row = (side: Side): { ffor: Record<string, unknown> } =>
				JSON.parse(snapshot(pair, side));
			expect('capabilityHold' in row('S').ffor).to.equal(false);
			expect('capabilityHold' in row('R').ffor).to.equal(false);
			pair.link.disconnect();
			advertise(pair, 'R', false);
			let persists = 0;
			pair.sManager.on('channel:persist', () => persists++);
			pair.link.log.length = 0;
			pair.link.reconnect();
			// Nothing but the two channel_reestablish messages crossed.
			expect(pair.link.types()).to.deep.equal([
				MessageType.CHANNEL_REESTABLISH,
				MessageType.CHANNEL_REESTABLISH
			]);
			expect(persists, 'S wrote the hold').to.be.greaterThan(0);
			expect(row('S').ffor.capabilityHold).to.equal(true);
			// The mode is untouched (section 8).
			expect(row('S').ffor.concurrentVersion).to.equal(1);
			// The same incompatible reconnect again changes nothing and writes
			// nothing.
			pair.link.disconnect();
			persists = 0;
			pair.link.reconnect();
			expect(persists).to.equal(0);
			// A compatible one lifts it and removes the field.
			pair.link.disconnect();
			advertise(pair, 'R', true);
			pair.link.reconnect();
			expect(persists, 'S wrote the lift').to.be.greaterThan(0);
			expect('capabilityHold' in row('S').ffor).to.equal(false);
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
		});

		it('a baseline epoch never carries the field, whatever a connection advertises', () => {
			const pair = createPair({ pushSat: 200_000n });
			activate(pair, AMOUNTS, false);
			pair.link.disconnect();
			advertise(pair, 'R', false);
			let persists = 0;
			pair.sManager.on('channel:persist', () => persists++);
			pair.link.reconnect();
			expect(persists).to.equal(0);
			for (const side of SIDES) {
				const ffor = JSON.parse(snapshot(pair, side)).ffor;
				expect('capabilityHold' in ffor, side).to.equal(false);
				expect('concurrentVersion' in ffor, side).to.equal(false);
			}
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
		});

		describe('it holds new admission only', () => {
			for (const offerer of SIDES) {
				for (const n of [0, 2, 4]) {
					it(`an add round of ${offerer}'s cut after ${n} of 5 messages resumes and completes under the hold, and the HTLC still settles`, () => {
						const pair = activePair();
						const hAct = Buffer.from(record(pair.rChannel).hAct!);
						cutAfter(pair, n);
						const add = offer(pair, offerer, 7_000_000n);
						expect(add.result.ok, add.result.error).to.equal(true);
						interrupt(pair, 'restart both');
						advertise(pair, other(offerer), false);
						pair.link.reconnect();
						expectAlive(pair, 'replayed under the hold');
						for (const side of SIDES) {
							expect(channel(pair, side).fforAdmissionHold()).to.match(
								/did not advertise/
							);
						}
						// The replayed add is not "new": it commits.
						expect(ordinaryHtlcs(channel(pair, other(offerer)))).to.deep.equal([
							`received-${add.id}`
						]);
						// New admission is refused on both sides.
						for (const side of SIDES) {
							expect(offer(pair, side, 1_000_000n).result.ok).to.equal(false);
						}
						pair.sErrors.length = 0;
						pair.rErrors.length = 0;
						const settle = manager(pair, other(offerer)).fulfillHtlc(
							pair.channelId,
							add.id,
							add.preimage
						);
						expect(settle.ok, settle.error).to.equal(true);
						expectSettled(pair, 'settled under the hold');
						const toR = offerer === 'S' ? 7_000_000n : -7_000_000n;
						expect(balances(pair).r).to.equal(R_START + toR);
						expectActiveUnchanged(pair, hAct, 'settled under the hold');
						// A compatible reconnect lifts it.
						pair.link.disconnect();
						advertise(pair, other(offerer), true);
						pair.link.reconnect();
						pay(pair, 'S', 1_000_000n);
						pay(pair, 'R', 1_000_000n);
						expectAlive(pair, 'after the hold');
					});
				}
			}

			it('the drain and the close run under the hold, cut mid-drain and resumed', () => {
				const pair = activePair();
				settleSlot(pair, 2);
				// The drain's commitment_signed and everything after is lost.
				let dead = false;
				pair.link.drop = (from, type): boolean => {
					if (
						record(pair.rChannel).state === FforState.DRAINING &&
						from === 'R' &&
						type === MessageType.COMMITMENT_SIGNED
					) {
						dead = true;
					}
					return dead;
				};
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				interrupt(pair, 'restart both');
				advertise(pair, 'S', false);
				pair.link.reconnect();
				expectAlive(pair, 'drain under the hold');
				expectClosed(pair, 'drain under the hold');
				expect(balances(pair)).to.deep.equal(drained(0n));
			});
		});

		describe('the production read of the peer init (no test seam)', () => {
			/**
			 * A PeerManager stand-in that answers getPeer the way the real one
			 * does: the registered Peer for a connected pubkey (its init
			 * already exchanged), undefined for anything else. sendToPeer
			 * throws, which sends the manager down its message:outbound
			 * fallback, where the Link is listening.
			 */
			function attachPeers(
				mgr: ChannelManager,
				remote: () => FeatureFlags | null | undefined
			): void {
				const stub = {
					onMessage: (): void => undefined,
					getPeer: (): unknown => {
						const features = remote();
						if (features === undefined) return undefined;
						return {
							getState: (): string => 'ready',
							getRemoteInit: (): unknown =>
								features === null ? null : { features }
						};
					},
					sendToPeer: (): void => {
						throw new Error('not connected');
					}
				};
				mgr.setFforPeerFeatureSource(null);
				mgr.attachToPeerManager(stub as unknown as PeerManager);
			}

			it('reads getPeer(pubkey).getRemoteInit().features at each reestablish: compatible, unregistered, init not recorded, incompatible, compatible again', () => {
				const pair = createPair({ pushSat: 200_000n });
				let seenByS: FeatureFlags | null | undefined =
					pair.rConfig.localFeatures;
				attachPeers(pair.sManager, () => seenByS);
				attachPeers(pair.rManager, () => pair.sConfig.localFeatures);
				// Negotiation itself runs on the production read.
				activate(pair, AMOUNTS, true);
				pair.link.disconnect();
				pair.link.reconnect();
				expect(pair.sChannel.fforAdmissionHold()).to.equal(null);
				expect(pair.rChannel.fforAdmissionHold()).to.equal(null);
				pay(pair, 'S', 1_000_000n);
				// A reestablish dispatched with no registered peer.
				pair.link.disconnect();
				seenByS = undefined;
				pair.link.reconnect();
				expect(pair.sChannel.fforAdmissionHold()).to.match(/did not advertise/);
				expect(pair.rChannel.fforAdmissionHold()).to.equal(null);
				// A registered peer whose init is not recorded.
				pair.link.disconnect();
				seenByS = null;
				pair.link.reconnect();
				expect(pair.sChannel.fforAdmissionHold()).to.match(/did not advertise/);
				// An init without the extension.
				pair.link.disconnect();
				const without = FeatureFlags.empty();
				without.setOptional(Feature.QUIESCE);
				without.setOptional(Feature.OPTION_FF_RECEIVE);
				seenByS = without;
				pair.link.reconnect();
				expect(pair.sChannel.fforAdmissionHold()).to.match(/did not advertise/);
				expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
					/capability hold/
				);
				// And back.
				pair.link.disconnect();
				seenByS = pair.rConfig.localFeatures;
				pair.link.reconnect();
				expect(pair.sChannel.fforAdmissionHold()).to.equal(null);
				expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
				pay(pair, 'S', 1_000_000n);
				pay(pair, 'R', 1_000_000n);
				expectAlive(pair, 'production read');
			});
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 5: persistence of the selected version.
	// ───────────────────────────────────────────────────────────────────
	describe('5b. the selected version through SqliteStorage at every step', () => {
		/** Freeze the setup just after the first message matching. */
		function setupUntil(
			stop: ((from: Side, type: number) => boolean) | null
		): IPair {
			const pair = createPair({ pushSat: 200_000n });
			let dead = false;
			if (stop) {
				pair.link.drop = (from, type): boolean => {
					if (dead) return true;
					if (stop(from, type)) dead = true;
					return dead;
				};
			}
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			return pair;
		}

		const STEPS: Array<{
			name: string;
			stop: ((from: Side, type: number) => boolean) | null;
			s: [string, 0 | 1] | null;
			r: [string, 0 | 1];
		}> = [
			{
				name: 'ff_init sent, never delivered',
				stop: (from, type) => from === 'R' && type === MessageType.FF_INIT,
				s: null,
				r: ['NEGOTIATING', 0]
			},
			{
				name: 'ff_accept sent, never delivered',
				stop: (from, type) => from === 'S' && type === MessageType.FF_ACCEPT,
				s: ['NEGOTIATING', 1],
				r: ['NEGOTIATING', 0]
			},
			{
				name: 'echo adopted, mid voucher round',
				stop: (from, type) =>
					from === 'S' && type === MessageType.COMMITMENT_SIGNED,
				s: ['NEGOTIATING', 1],
				r: ['NEGOTIATING', 1]
			},
			{
				name: 'VOUCHERS_COMMITTED, the stfu of R never delivered',
				stop: (from, type) => from === 'R' && type === MessageType.STFU,
				s: ['VOUCHERS_COMMITTED', 1],
				r: ['VOUCHERS_COMMITTED', 1]
			},
			{
				name: 'ACTIVATING, the ack never delivered',
				stop: (from, type) =>
					from === 'S' && type === MessageType.FF_ACTIVATE_ACK,
				s: ['ACTIVE', 1],
				r: ['ACTIVATING', 1]
			},
			{ name: 'ACTIVE', stop: null, s: ['ACTIVE', 1], r: ['ACTIVE', 1] }
		];

		for (const encrypted of [false, true]) {
			for (const step of STEPS) {
				it(`${step.name}: both rows survive SQLite${
					encrypted ? ' (encrypted at rest)' : ''
				} with the version, the transcript and no dispute`, () => {
					const pair = setupUntil(step.stop);
					const storage = new SqliteStorage(
						':memory:',
						undefined,
						encrypted ? { encryptionKey: Buffer.alloc(32, 7) } : undefined
					);
					storage.open();
					try {
						for (const side of SIDES) {
							const want = side === 'S' ? step.s : step.r;
							const ch = channel(pair, side);
							if (want === null) {
								expect(ch.getFforEpoch()).to.equal(null);
								continue;
							}
							expect(FforState[record(ch).state]).to.equal(want[0]);
							expect(record(ch).concurrentVersion ?? 0).to.equal(want[1]);
							const id = `${side}-${pair.channelId.toString('hex')}`;
							const before = JSON.stringify(
								serializeChannelState(ch.getFullState())
							);
							storage.saveChannel(id, ch.getFullState(), 'peer');
							const loaded = storage.loadChannel(id)!;
							expect(
								JSON.stringify(serializeChannelState(loaded.state)),
								`${side} row`
							).to.equal(before);
							const f = loaded.state.ffor!;
							expect(f.concurrentVersion ?? 0).to.equal(want[1]);
							expect(f.params.concurrentVersion).to.equal(1);
							expect(f.activationMismatch).to.equal(false);
							expect(f.initWire.equals(record(ch).initWire)).to.equal(true);
						}
					} finally {
						storage.close();
					}
				});
			}
		}

		it('a channel restarted from SQLite rows in ACTIVE with traffic in flight, and again mid-drain, finishes exactly', () => {
			const pair = activePair();
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const viaSqlite = (side: Side): string => {
				const id = `${side}-row`;
				storage.saveChannel(id, channel(pair, side).getFullState(), 'peer');
				return JSON.stringify(
					serializeChannelState(storage.loadChannel(id)!.state)
				);
			};
			try {
				const hAct = Buffer.from(record(pair.rChannel).hAct!);
				const fromS = offer(pair, 'S', 5_000_000n);
				expect(fromS.result.ok, fromS.result.error).to.equal(true);
				cutAfter(pair, 2);
				const fromR = offer(pair, 'R', 3_000_000n);
				expect(fromR.result.ok, fromR.result.error).to.equal(true);
				pair.link.disconnect();
				pair.link.drop = null;
				restart(pair, 'S', viaSqlite('S'));
				restart(pair, 'R', viaSqlite('R'));
				pair.link.log.length = 0;
				pair.link.reconnect();
				expectAlive(pair, 'from SQLite, ACTIVE');
				expectActiveUnchanged(pair, hAct, 'from SQLite, ACTIVE');
				settleSlot(pair, 2);
				// Mid-drain: R's commitment_signed for the drain is lost.
				let dead = false;
				pair.link.drop = (from, type): boolean => {
					if (
						record(pair.rChannel).state === FforState.DRAINING &&
						from === 'R' &&
						type === MessageType.COMMITMENT_SIGNED
					) {
						dead = true;
					}
					return dead;
				};
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				pair.link.disconnect();
				pair.link.drop = null;
				restart(pair, 'S', viaSqlite('S'));
				restart(pair, 'R', viaSqlite('R'));
				pair.link.log.length = 0;
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				pair.link.reconnect();
				expectAlive(pair, 'from SQLite, DRAINING');
				expectClosed(pair, 'from SQLite, DRAINING');
				for (const side of SIDES) {
					expect(record(channel(pair, side)).concurrentVersion).to.equal(1);
				}
				const a = pair.rManager.fulfillHtlc(
					pair.channelId,
					fromS.id,
					fromS.preimage
				);
				expect(a.ok, a.error).to.equal(true);
				const b = pair.sManager.fulfillHtlc(
					pair.channelId,
					fromR.id,
					fromR.preimage
				);
				expect(b.ok, b.error).to.equal(true);
				expect(balances(pair)).to.deep.equal(drained(2_000_000n));
				expectSettled(pair, 'from SQLite');
			} finally {
				storage.close();
			}
		});

		describe('a restart at any setup step before ACTIVATING aborts on both sides, leaves no voucher behind and never becomes a baseline epoch', () => {
			for (const step of STEPS.slice(0, 4)) {
				for (const how of INTERRUPTS) {
					it(`${step.name}; ${how}`, () => {
						const pair = setupUntil(step.stop);
						const epochId = Buffer.from(record(pair.rChannel).epochId);
						interrupt(pair, how);
						pair.link.reconnect();
						const label = `${step.name}; ${how}`;
						expectAlive(pair, label);
						// When ff_accept never arrived, R holds no book: the voucher
						// adds S replays are ordinary HTLCs to it, for payments it
						// does not know. Its node fails those back, as here.
						for (const key of ordinaryHtlcs(pair.rChannel)) {
							expect(record(pair.rChannel).acceptWire, label).to.equal(null);
							const res = pair.rManager.failHtlc(
								pair.channelId,
								BigInt(key.split('-')[1]),
								Buffer.alloc(292)
							);
							expect(res.ok, `${label} ${res.error}`).to.equal(true);
						}
						for (const side of SIDES) {
							const f = channel(pair, side).getFforEpoch();
							expect(channel(pair, side).fforIsFrozen(), label).to.equal(false);
							expect(vouchers(channel(pair, side)), label).to.deep.equal([]);
							if (f === null) continue;
							expect(FforState[f.state], `${label} ${side}`).to.equal(
								'ABORTED'
							);
						}
						expect(ordinaryHtlcs(pair.sChannel), label).to.deep.equal([]);
						expect(ordinaryHtlcs(pair.rChannel), label).to.deep.equal([]);
						// The channel is an ordinary channel again, and exact.
						pair.sErrors.length = 0;
						pair.rErrors.length = 0;
						pay(pair, 'S', 1_000_000n);
						pay(pair, 'R', 1_000_000n);
						expectSettled(pair, label);
						expect(balances(pair).s, label).to.equal(S_START);
						expect(balances(pair).r, label).to.equal(R_START);
						// The epoch id is spent: no retry under it, of either kind.
						for (const concurrent of [true, false]) {
							const again = pair.rManager.initiateFforEpoch(
								pair.channelId,
								terms(AMOUNTS, {
									epochId,
									...(concurrent ? { concurrent } : {})
								})
							);
							expect(again.ok, label).to.equal(false);
						}
						// A fresh concurrent epoch then runs.
						pair.sErrors.length = 0;
						pair.rErrors.length = 0;
						activate(pair, AMOUNTS, true);
						expectVouchersCarried(pair, ALL, label);
					});
				}
			}
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// Attack 6: the received-removal window of #1291 with vouchers.
	// ───────────────────────────────────────────────────────────────────
	describe('6b. the received-removal window (#1291) beside vouchers', () => {
		/** The commitment a force close would broadcast, or the refusal. */
		function planClose(
			pair: IPair,
			side: Side
		): { ok: boolean; error?: string; outputs: number } {
			const mgr = manager(pair, side) as unknown as {
				signerFor(channel: Channel, htlc: boolean): unknown;
			};
			const ch = channel(pair, side) as unknown as {
				prepareForceClose(signer: unknown): {
					ok: boolean;
					error?: string;
					commitmentTx?: Buffer;
				};
			};
			const plan = ch.prepareForceClose(
				mgr.signerFor(channel(pair, side), true)
			);
			return {
				ok: plan.ok,
				error: plan.error,
				outputs: plan.commitmentTx
					? bitcoin.Transaction.fromBuffer(plan.commitmentTx).outs.length
					: 0
			};
		}

		it('ACTIVE: R removed an ordinary HTLC and S went quiet after its revoke_and_ack; R can force close on the commitment S signed, vouchers and the removed HTLC included', () => {
			const pair = activePair();
			const whole = planClose(pair, 'R');
			expect(whole.ok, whole.error).to.equal(true);
			const add = offer(pair, 'S', 50_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			const withHtlc = planClose(pair, 'R');
			expect(withHtlc.ok, withHtlc.error).to.equal(true);
			expect(withHtlc.outputs).to.equal(whole.outputs + 1);
			// fulfil, commitment_signed, revoke_and_ack arrive; S's
			// commitment_signed does not.
			cutAfter(pair, 3);
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				add.id,
				add.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			pair.link.drop = null;
			expect(ordinaryHtlcs(pair.rChannel)).to.deep.equal([]);
			expect(pair.rChannel.getFullState().signedLocalRemovals?.length).to.equal(
				1
			);
			const inWindow = planClose(pair, 'R');
			expect(inWindow.ok, inWindow.error).to.equal(true);
			expect(inWindow.outputs).to.equal(withHtlc.outputs);
			expect(vouchers(pair.rChannel).length).to.equal(3);
			// And the reconnect closes the window with the book untouched.
			const hAct = Buffer.from(record(pair.rChannel).hAct!);
			interrupt(pair, 'restart R');
			expect(pair.rChannel.getFullState().signedLocalRemovals?.length).to.equal(
				1
			);
			pair.link.reconnect();
			expectAlive(pair, 'window closed');
			expectActiveUnchanged(pair, hAct, 'window closed');
			expect(
				pair.rChannel.getFullState().signedLocalRemovals ?? []
			).to.deep.equal([]);
			expect(balances(pair).r).to.equal(R_START + 50_000_000n);
		});

		it('DRAINING: every voucher removal opens the window; R can force close inside it with ordinary HTLCs present, is not CLOSED early, and the reconnect finishes', () => {
			const pair = activePair();
			settleSlot(pair, 2);
			const fromS = offer(pair, 'S', 40_000_000n);
			const fromR = offer(pair, 'R', 30_000_000n);
			expect(fromS.result.ok, fromS.result.error).to.equal(true);
			expect(fromR.result.ok, fromR.result.error).to.equal(true);
			const before = planClose(pair, 'R');
			expect(before.ok, before.error).to.equal(true);
			// S's commitment_signed after its revoke_and_ack is lost.
			let dead = false;
			pair.link.drop = (from, type): boolean => {
				if (
					record(pair.sChannel).state === FforState.DRAINING &&
					from === 'S' &&
					type === MessageType.COMMITMENT_SIGNED
				) {
					dead = true;
				}
				return dead;
			};
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.drop = null;
			// The vouchers left R's map with S's revoke; R's own commitment
			// still carries all three, and the epoch is not CLOSED yet.
			expect(vouchers(pair.rChannel)).to.deep.equal([]);
			expect(pair.rChannel.getFullState().signedLocalRemovals?.length).to.equal(
				3
			);
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			const inWindow = planClose(pair, 'R');
			expect(inWindow.ok, inWindow.error).to.equal(true);
			expect(inWindow.outputs).to.equal(before.outputs);
			interrupt(pair, 'restart both');
			pair.link.reconnect();
			expectAlive(pair, 'window closed');
			expectClosed(pair, 'window closed');
			expect(ordinaryHtlcs(pair.rChannel).length).to.equal(2);
			const after = planClose(pair, 'R');
			expect(after.ok, after.error).to.equal(true);
			expect(after.outputs).to.equal(before.outputs - 3);
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// Attacks 7 and 8: epoch lifecycle under traffic, and quiescence.
	// ───────────────────────────────────────────────────────────────────
	describe('7. epoch lifecycle under traffic', () => {
		it('operator abort by R mid-setup: the add the barrier refused is taken right after, and the unwind still completes', () => {
			const pair = createPair({ pushSat: 200_000n });
			// S's revoke_and_ack for the voucher round is in flight.
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.REVOKE_AND_ACK;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.holdAt = null;
			expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
			expect(record(pair.rChannel).concurrentVersion).to.equal(1);
			const refused = offer(pair, 'R', 2_000_000n);
			expect(refused.result.ok).to.equal(false);
			expect(refused.result.error).to.match(/no ordinary add while the setup/);
			const aborted = pair.rManager.abortFforEpoch(pair.channelId);
			expect(aborted.ok, aborted.error).to.equal(true);
			// Retried at once, with the round still open.
			const retried = offer(pair, 'R', 2_000_000n);
			expect(retried.result.ok, retried.result.error).to.equal(true);
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.log.length = 0;
			pair.link.release('S');
			expectAlive(pair, 'aborted');
			for (const side of SIDES) {
				expect(FforState[record(channel(pair, side)).state]).to.equal(
					'ABORTED'
				);
				expect(vouchers(channel(pair, side)), why(pair)).to.deep.equal([]);
			}
			expect(ordinaryHtlcs(pair.sChannel)).to.deep.equal([
				`received-${retried.id}`
			]);
			const settle = pair.sManager.fulfillHtlc(
				pair.channelId,
				retried.id,
				retried.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expectSettled(pair, 'aborted');
			expect(balances(pair).s).to.equal(S_START + 2_000_000n);
			// The channel is idle again: a new concurrent epoch runs.
			activate(pair, AMOUNTS, true);
		});

		it("S's setup timer fires mid voucher round: both abort, the vouchers unwind, traffic resumes, a new epoch runs", () => {
			const pair = createPair({ pushSat: 200_000n });
			// R's revoke_and_ack and commitment_signed are in flight: S is
			// still NEGOTIATING when its timer fires.
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.REVOKE_AND_ACK;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.holdAt = null;
			expect(record(pair.sChannel).state).to.equal(FforState.NEGOTIATING);
			const timedOut = pair.sManager.fforSetupTimeout(pair.channelId);
			expect(timedOut.ok, timedOut.error).to.equal(true);
			// S's own add is refused no longer; R's waits for nothing either.
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.log.length = 0;
			pair.link.release('R');
			expectAlive(pair, 'timed out');
			for (const side of SIDES) {
				expect(FforState[record(channel(pair, side)).state]).to.equal(
					'ABORTED'
				);
				expect(vouchers(channel(pair, side)), why(pair)).to.deep.equal([]);
			}
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectSettled(pair, 'timed out');
			expect(balances(pair).s).to.equal(S_START);
			activate(pair, AMOUNTS, true);
		});

		// Issue #1293 item 1, unchanged by this PR and not specific to the
		// concurrent profile: the second pass of the loop is a baseline
		// request and fails the same way. A PIN of what happens today: when
		// #1293 item 1 is fixed the last assertion fails, and the required
		// outcome is that no line says ERRORED, quiescing or stfu.
		it("PIN [#1293 item 1, pre-existing] S's setup timer fires in VOUCHERS_COMMITTED while R's stfu is in flight: S answers the stale stfu and stays quiescent, and the next ordinary add fails the channel", () => {
			const outcomes: string[] = [];
			for (const concurrent of [true, false]) {
				const pair = createPair({ pushSat: 200_000n });
				// S's last revoke_and_ack is in flight: S has seen the round
				// end, R has not, so R's stfu is still to come.
				pair.link.holdAt = (from, type): boolean =>
					from === 'S' && type === MessageType.REVOKE_AND_ACK;
				const res = pair.rManager.initiateFforEpoch(
					pair.channelId,
					terms(AMOUNTS, concurrent ? { concurrent: true } : {})
				);
				expect(res.ok, res.error).to.equal(true);
				pair.link.holdAt = null;
				expect(record(pair.sChannel).state).to.equal(
					FforState.VOUCHERS_COMMITTED
				);
				const timedOut = pair.sManager.fforSetupTimeout(pair.channelId);
				expect(timedOut.ok, timedOut.error).to.equal(true);
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				pair.link.log.length = 0;
				pair.link.release('S');
				const fromS = offer(pair, 'S', 1_000_000n);
				const fromR = offer(pair, 'R', 1_000_000n);
				outcomes.push(
					`concurrent=${concurrent}: S ${
						ChannelState[pair.sChannel.getState()]
					}, R ${ChannelState[pair.rChannel.getState()]}; S add: ${
						fromS.result.ok ? 'ok' : fromS.result.error
					}; R add: ${fromR.result.ok ? 'ok' : fromR.result.error}`
				);
			}
			expect(outcomes).to.deep.equal([
				'concurrent=true: S ERRORED, R ERRORED; S add: Cannot add HTLC: channel is quiescing; R add: ok',
				'concurrent=false: S ERRORED, R ERRORED; S add: Cannot add HTLC: channel is quiescing; R add: ok'
			]);
		});

		it('CLOSED, then a new epoch at once: refused locally while an ordinary HTLC is in flight (nothing sent, no id spent), accepted once the channel is idle', () => {
			const pair = activePair();
			const inFlight = offer(pair, 'S', 5_000_000n);
			expect(inFlight.result.ok, inFlight.result.error).to.equal(true);
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			expectClosed(pair, 'first epoch');
			pair.link.log.length = 0;
			const early = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(early.ok).to.equal(false);
			expect(early.error).to.match(/must carry no HTLCs/);
			expect(pair.link.types()).to.deep.equal([]);
			expectClosed(pair, 'still the first epoch');
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inFlight.id,
				inFlight.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			const firstBase = record(pair.rChannel).sHtlcIdBase!;
			activate(pair, AMOUNTS, true);
			// Section 1.2: offered ids continue past the first book's range.
			expect(record(pair.rChannel).sHtlcIdBase! > firstBase + 2n).to.equal(
				true
			);
			expectVouchersCarried(pair, ALL, 'second epoch');
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			interrupt(pair, 'restart both');
			pair.link.reconnect();
			expectAlive(pair, 'second epoch reconnected');
			expectVouchersCarried(pair, ALL, 'second epoch reconnected');
		});

		it("S's ordinary add crosses R's ff_init: S refuses the setup, nothing wedges, the HTLC settles and the next setup runs", () => {
			const pair = createPair({ pushSat: 200_000n });
			// S's add and its commitment_signed are in flight when R asks.
			pair.link.holdAt = (from): boolean => from === 'S';
			const crossing = offer(pair, 'S', 3_000_000n);
			expect(crossing.result.ok, crossing.result.error).to.equal(true);
			pair.link.holdAt = null;
			const res = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(res.ok, res.error).to.equal(true);
			pair.link.log.length = 0;
			pair.link.release('S');
			expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
			expect(pair.link.types()).to.not.include(MessageType.ERROR);
			expect(pair.sChannel.getFforEpoch()).to.equal(null);
			expect(FforState[record(pair.rChannel).state]).to.equal('ABORTED');
			expect(vouchers(pair.rChannel)).to.deep.equal([]);
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				crossing.id,
				crossing.preimage
			);
			expect(settle.ok, `${settle.error} ${why(pair)}`).to.equal(true);
			expectSettled(pair, 'crossed');
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			activate(pair, AMOUNTS, true);
		});

		it('PIN [PR 2 of #1283] DRAINING with no voucher left (every slot redeemed while ACTIVE, as PR 2 will allow): neither side reaches CLOSED until an ordinary round passes, and no new epoch can start before it', () => {
			// The interim CLOSED rule has no round boundary at which CLOSED can
			// be declared here, and R has no caller that redeems while ACTIVE
			// until PR 2 of #1283, whose terminal slot records replace the
			// rule. Pinned so PR 2 inherits a test: the epoch is not stuck for
			// good, but it is stuck until unrelated traffic happens. Required
			// then: both sides CLOSED at the acknowledgement.
			const pair = activePair();
			const base = record(pair.rChannel).sHtlcIdBase!;
			const guard = pair.rChannel as unknown as {
				_fforInternalSettle: boolean;
			};
			for (let k = 1; k <= 3; k++) {
				const t = record(pair.sChannel).preimages[k - 1];
				expect(pair.rManager.fforAddPreimage(pair.channelId, t).ok).to.equal(
					true
				);
				guard._fforInternalSettle = true;
				const res = pair.rManager.fulfillHtlc(
					pair.channelId,
					base + BigInt(k - 1),
					t
				);
				guard._fforInternalSettle = false;
				expect(res.ok, res.error).to.equal(true);
			}
			expect(vouchers(pair.rChannel)).to.deep.equal([]);
			expect(vouchers(pair.sChannel)).to.deep.equal([]);
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			for (const side of SIDES) {
				expect(FforState[record(channel(pair, side)).state]).to.equal(
					'DRAINING'
				);
			}
			const blocked = pair.rManager.initiateFforEpoch(
				pair.channelId,
				terms(AMOUNTS, { concurrent: true })
			);
			expect(blocked.ok).to.equal(false);
			expect(blocked.error).to.match(/already in progress/);
			// A reconnect does not close it either.
			interrupt(pair, 'restart both');
			pair.link.reconnect();
			for (const side of SIDES) {
				expect(FforState[record(channel(pair, side)).state]).to.equal(
					'DRAINING'
				);
			}
			// One ordinary payment supplies the boundary.
			pay(pair, 'S', 1_000_000n);
			expectClosed(pair, 'after an unrelated payment');
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			activate(pair, AMOUNTS, true);
		});
	});
});
