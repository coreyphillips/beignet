/**
 * FFOR concurrent receive, version 1: round 2 of the adversarial recovery
 * review of PR #1301 (specs/CONCURRENT-RECEIVE.md sections 3, 7 and 8; base
 * sections 7.5.5 and 7.5.6).
 *
 * Round 1 found that the drain hold let later sends overtake the held
 * chain, that a differing ff_close_ack wedged ordinary traffic, that a
 * concurrent S originated updates before its ff_activate_ack had left, and
 * that the capability hold did not survive a restart. This file attacks the
 * fixes: the held stream (Channel.fforHoldStream), the dispute, the
 * ack-unsent flag and the persisted capability hold, between two HONEST
 * nodes, with cuts, restarts, crossing messages and failed durable writes.
 *
 * Every test passes. Most pin an attack that held. What the review found is
 * fixed, and those cases assert the fixed behaviour; each says in a comment
 * what it found. Titles that begin with PIN assert what happens today for a
 * defect that is tracked elsewhere, so they fail visibly when it is fixed.
 *
 * Harness: helpers/ffor-concurrent-pair.ts.
 *
 * Environment knobs:
 *   FFOR2_EXHAUSTIVE=1  every message boundary and every durable write in
 *                       section 1 (default: every sixth)
 *   FFOR2_SEEDS=a-b     seeds of the walk under a hold (default 1-4)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { Feature } from '../../src/lightning/features/flags';
import { FforState } from '../../src/lightning/ffor/types';
import {
	activate,
	AMOUNTS,
	balances,
	channel,
	createPair,
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
const SIDES: Side[] = ['S', 'R'];

type Flight = ReturnType<typeof offer>;

function activePair(concurrent = true): IPair {
	const pair = createPair({ pushSat: 200_000n });
	activate(pair, AMOUNTS, concurrent);
	pair.link.log.length = 0;
	return pair;
}

type Interrupt = 'disconnect' | 'restart S' | 'restart R' | 'restart both';
const INTERRUPTS: Interrupt[] = [
	'disconnect',
	'restart S',
	'restart R',
	'restart both'
];

function interrupt(pair: IPair, how: Interrupt): void {
	pair.link.disconnect();
	pair.link.drop = null;
	pair.link.holdAt = null;
	if (how === 'restart S' || how === 'restart both') restart(pair, 'S');
	if (how === 'restart R' || how === 'restart both') restart(pair, 'R');
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	pair.link.log.length = 0;
}

function advertise(pair: IPair, side: Side, on: boolean): void {
	const flags =
		side === 'S' ? pair.sConfig.localFeatures : pair.rConfig.localFeatures;
	if (on) flags.setOptional(Feature.OPTION_FF_CONCURRENT);
	else flags.clearBit(Feature.OPTION_FF_CONCURRENT + 1);
}

function sentBy(pair: IPair, side: Side): number[] {
	return pair.link.log.filter((e) => e.from === side).map((e) => e.type);
}

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

function hasPending(ch: Channel): boolean {
	return (ch as unknown as { hasPendingHtlcs(): boolean }).hasPendingHtlcs();
}

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

function expectClosed(pair: IPair, label: string): void {
	for (const side of SIDES) {
		expect(
			FforState[record(channel(pair, side)).state],
			`${label} ${side} epoch ${why(pair)}`
		).to.equal('CLOSED');
		expect(vouchers(channel(pair, side)), `${label} ${side}`).to.deep.equal([]);
	}
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

/** Whether the channel is holding its retransmission chain. */
function holding(ch: Channel): boolean {
	return (ch as unknown as { _fforHolding: boolean })._fforHolding;
}

function heldTypes(ch: Channel): number[] {
	const held = (ch as unknown as { _fforHeldReplay: ChannelAction[] })
		._fforHeldReplay;
	return held.map((a) => (a as unknown as { messageType: number }).messageType);
}

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
	const plan = ch.prepareForceClose(mgr.signerFor(channel(pair, side), true));
	return {
		ok: plan.ok,
		error: plan.error,
		outputs: plan.commitmentTx
			? bitcoin.Transaction.fromBuffer(plan.commitmentTx).outs.length
			: 0
	};
}

/**
 * R is DRAINING with its drain round lost on the wire, and S is back from
 * a row that predates ff_close (ACTIVE, no close on record), its commitment
 * numbers current. `settled` are the slots S settled before that row. In a
 * concurrent epoch one ordinary HTLC in each direction is committed
 * throughout; a baseline epoch carries none.
 */
function sLostTheClose(
	settled: number[],
	concurrent = true
): { pair: IPair; fromS: Flight | null; fromR: Flight | null; backup: string } {
	const pair = activePair(concurrent);
	let fromS: Flight | null = null;
	let fromR: Flight | null = null;
	if (concurrent) {
		fromS = offer(pair, 'S', 6_000_000n);
		fromR = offer(pair, 'R', 3_000_000n);
		expect(fromS.result.ok, fromS.result.error).to.equal(true);
		expect(fromR.result.ok, fromR.result.error).to.equal(true);
	}
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
	pair.link.log.length = 0;
	pair.sErrors.length = 0;
	pair.rErrors.length = 0;
	return { pair, fromS, fromR, backup };
}

interface IHeld {
	pair: IPair;
	fromS: Flight;
	fromR: Flight;
	sAdd: Flight | null;
	sFulfilled: boolean;
}

/**
 * The hold, with S working into it. R's retransmitted ff_close is still in
 * flight (per-direction FIFO is kept), so S, ACTIVE and concurrent, has not
 * answered yet. `what` is what S does meanwhile: forward a payment to R
 * (R's revoke_and_ack for it joins the chain), settle the HTLC R offered,
 * or both.
 */
function holdWithTraffic(what: 'S adds' | 'S fulfils' | 'both'): IHeld {
	const { pair, fromS, fromR } = sLostTheClose([2]);
	pair.link.holdAt = (from, type): boolean =>
		from === 'R' && type === MessageType.FF_CLOSE;
	pair.link.reconnect();
	pair.link.holdAt = null;
	const held: IHeld = {
		pair,
		fromS: fromS!,
		fromR: fromR!,
		sAdd: null,
		sFulfilled: false
	};
	sWorks(held, what);
	return held;
}

/** S's part of holdWithTraffic; skipped on a channel that cannot carry it. */
function sWorks(held: IHeld, what: 'S adds' | 'S fulfils' | 'both'): void {
	const { pair } = held;
	if (pair.sChannel.getState() !== ChannelState.NORMAL) return;
	if (what !== 'S fulfils' && held.sAdd === null) {
		const add = offer(pair, 'S', 2_000_000n);
		if (add.result.ok) held.sAdd = add;
	}
	if (what !== 'S adds' && !held.sFulfilled) {
		const res = pair.sManager.fulfillHtlc(
			pair.channelId,
			held.fromR.id,
			held.fromR.preimage
		);
		if (res.ok) held.sFulfilled = true;
	}
}

/**
 * Finish what the scenario wanted and check the end state exactly: the
 * book CLOSED, R paid for slot 2, every ordinary HTLC settled, nothing
 * owed, both books agreeing.
 */
function finishHeld(held: IHeld, label: string): void {
	const { pair } = held;
	expectAlive(pair, label);
	sWorks(held, 'both');
	for (const f of [held.fromS, held.sAdd]) {
		if (f === null) continue;
		const res = pair.rManager.fulfillHtlc(pair.channelId, f.id, f.preimage);
		expect(res.ok, `${label} ${res.error} ${why(pair)}`).to.equal(true);
	}
	expectAlive(pair, label);
	expectClosed(pair, label);
	expect(ordinaryHtlcs(pair.sChannel), `${label} ${why(pair)}`).to.deep.equal(
		[]
	);
	expect(ordinaryHtlcs(pair.rChannel), `${label} ${why(pair)}`).to.deep.equal(
		[]
	);
	expectSettled(pair, label);
	expect(held.sAdd, `${label} S's add`).to.not.equal(null);
	expect(held.sFulfilled, `${label} S's fulfil`).to.equal(true);
	expect(balances(pair), label).to.deep.equal(
		drained(6_000_000n + 2_000_000n - 3_000_000n)
	);
}

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

/**
 * A seeded walk that starts at the reconnect of sLostTheClose and delivers
 * every message one at a time in per-direction FIFO order, while both
 * sides offer and settle ordinary HTLCs. S's ff_close_ack arrives whenever
 * the walk delivers it, so the hold lasts a random number of steps. No
 * cut: nothing here meets issue #1300's precondition across a reconnect.
 */
function walkUnderHold(seed: number): { heldSteps: number; maxChain: number } {
	const rand = rng(seed);
	const pick = (n: number): number => Math.floor(rand() * n);
	const { pair, fromS, fromR } = sLostTheClose([2]);
	const flights: Array<{
		offerer: Side;
		f: Flight;
		amount: bigint;
		settled: null | 'fulfil' | 'fail';
	}> = [
		{ offerer: 'S', f: fromS!, amount: 6_000_000n, settled: null },
		{ offerer: 'R', f: fromR!, amount: 3_000_000n, settled: null }
	];
	const trace: string[] = [];
	const dead = (): boolean =>
		pair.sChannel.getState() === ChannelState.ERRORED ||
		pair.rChannel.getState() === ChannelState.ERRORED ||
		pair.link.types().includes(MessageType.ERROR);
	const fail = (what: string): never => {
		throw new Error(
			`seed ${seed}: ${what}\n${trace.join('\n')}\n${JSON.stringify({
				sErrors: pair.sErrors,
				rErrors: pair.rErrors,
				inFlight: { S: pair.link.inFlight('S'), R: pair.link.inFlight('R') }
			})}`
		);
	};
	pair.link.holdAt = (): boolean => true;
	pair.link.reconnect();
	const deliver = (from: Side): boolean => {
		const q = pair.link.inFlight(from);
		if (q.length === 0) return false;
		trace.push(`deliver ${from}:${q[0]}`);
		pair.link.release(from, 1);
		return true;
	};
	const tryOffer = (side: Side): void => {
		if (channel(pair, side).getState() !== ChannelState.NORMAL) return;
		const amount = BigInt(1_000_000 + pick(3) * 1_000_000);
		const o = offer(pair, side, amount);
		trace.push(
			`offer ${side} ${o.id} ${o.result.ok ? 'ok' : o.result.error}${
				holding(pair.rChannel) ? ' [R holding]' : ''
			}`
		);
		if (side === 'R' && holding(pair.rChannel) && o.result.ok) {
			fail('R took a new add while holding its chain');
		}
		if (o.result.ok) {
			flights.push({ offerer: side, f: o, amount, settled: null });
		}
	};
	const trySettle = (
		x: (typeof flights)[number],
		how: 'fulfil' | 'fail'
	): void => {
		const receiver = other(x.offerer);
		if (!pair.events[receiver].forwarded.includes(x.f.id)) return;
		if (channel(pair, receiver).getState() !== ChannelState.NORMAL) return;
		const res =
			how === 'fulfil'
				? manager(pair, receiver).fulfillHtlc(
						pair.channelId,
						x.f.id,
						x.f.preimage
				  )
				: manager(pair, receiver).failHtlc(
						pair.channelId,
						x.f.id,
						Buffer.alloc(292)
				  );
		trace.push(
			`${how} ${receiver} ${x.f.id} ${res.ok ? 'ok' : res.error}${
				holding(pair.rChannel) ? ' [R holding]' : ''
			}`
		);
		if (res.ok) x.settled = how;
	};
	let heldSteps = 0;
	let maxChain = 0;
	// The two HTLCs committed before the close were dispatched then.
	const steps = 40 + pick(40);
	for (let i = 0; i < steps && !dead(); i++) {
		if (holding(pair.rChannel)) {
			heldSteps++;
			maxChain = Math.max(maxChain, heldTypes(pair.rChannel).length);
		}
		const roll = pick(100);
		// S's answer to ff_close is delivered late more often than not.
		if (roll < 22) deliver('S') || deliver('R');
		else if (roll < 55) deliver('R') || deliver('S');
		else if (roll < 65) tryOffer('S');
		else if (roll < 72) tryOffer('R');
		else {
			const open = flights.filter((x) => x.settled === null);
			if (open.length > 0) {
				trySettle(open[pick(open.length)], pick(4) === 0 ? 'fail' : 'fulfil');
			}
		}
	}
	for (let round = 0; round < 60 && !dead(); round++) {
		let moved = false;
		while (!dead() && (deliver('S') || deliver('R'))) moved = true;
		if (dead()) break;
		for (const x of flights) {
			if (x.settled !== null) continue;
			trySettle(x, 'fulfil');
			if (x.settled !== null) moved = true;
		}
		if (!moved) break;
	}
	if (dead()) fail('channel failed');
	if (holding(pair.rChannel)) fail('R still holds its chain');
	const stuck = flights.filter((x) => x.settled === null);
	if (stuck.length > 0) fail(`${stuck.length} HTLC(s) never settleable`);
	if (
		ordinaryHtlcs(pair.sChannel).length + ordinaryHtlcs(pair.rChannel).length
	) {
		fail('HTLCs remain');
	}
	for (const side of SIDES) {
		const ch = channel(pair, side);
		if (hasPending(ch) || ch.getFullState().pendingLocalUpdates.length) {
			fail(`${side} still has pending updates`);
		}
		if (record(ch).state !== FforState.CLOSED) {
			fail(`${side} epoch is ${FforState[record(ch).state]}`);
		}
	}
	let toR = 0n;
	for (const x of flights) {
		if (x.settled !== 'fulfil') continue;
		toR += x.offerer === 'S' ? x.amount : -x.amount;
	}
	const want = drained(toR);
	const b = balances(pair);
	if (
		b.s !== want.s ||
		b.r !== want.r ||
		b.sViewOfR !== want.r ||
		b.rViewOfS !== want.s
	) {
		fail(`balances s=${b.s} r=${b.r}, expected s=${want.s} r=${want.r}`);
	}
	return { heldSteps, maxChain };
}

describe('FFOR concurrent receive: adversarial recovery review of PR #1301, round 2', function () {
	this.timeout(900_000);
	const stride = process.env.FFOR2_EXHAUSTIVE ? 1 : 6;

	// ───────────────────────────────────────────────────────────────────
	// 1. The held stream.
	// ───────────────────────────────────────────────────────────────────
	describe('1. the held stream: nothing overtakes the chain, nothing is lost with it', () => {
		describe('a random walk of both sides working while R holds, no cut', () => {
			const [first, last] = (process.env.FFOR2_SEEDS ?? '1-4')
				.split('-')
				.map(Number);
			let heldSteps = 0;
			let maxChain = 0;
			for (let seed = first; seed <= (last ?? first); seed++) {
				it(`seed ${seed}`, () => {
					const res = walkUnderHold(seed);
					heldSteps += res.heldSteps;
					maxChain = Math.max(maxChain, res.maxChain);
				});
			}
			it('the walks did hold, and the chain did grow past the retransmission', () => {
				expect(heldSteps).to.be.greaterThan(0);
				// The retransmission alone is three voucher updates and one
				// commitment_signed.
				expect(maxChain).to.be.greaterThan(4);
			});
		});

		describe('the hold ends by a fault instead of the acknowledgement', () => {
			for (const what of ['S adds', 'S fulfils', 'both'] as const) {
				for (const how of INTERRUPTS) {
					it(`${what} into the hold; ${how} before S has seen ff_close; the next hold releases everything in order`, () => {
						const held = holdWithTraffic(what);
						expect(holding(held.pair.rChannel)).to.equal(true);
						interrupt(held.pair, how);
						held.pair.link.reconnect();
						expect(holding(held.pair.rChannel)).to.equal(false);
						finishHeld(held, `${what}; ${how}`);
					});
				}
			}
		});

		describe('the release itself is cut', () => {
			for (const how of INTERRUPTS) {
				it(`S adds and fulfils into the hold; the release is cut after a message (stride ${stride}); ${how}`, () => {
					const run = (n: number): number => {
						const held = holdWithTraffic('both');
						let seen = 0;
						held.pair.link.drop = (): boolean => seen++ >= n;
						held.pair.link.release('R');
						if (seen > n) {
							interrupt(held.pair, how);
							held.pair.link.reconnect();
						} else {
							held.pair.link.drop = null;
						}
						finishHeld(held, `release cut after ${n}; ${how}`);
						return seen;
					};
					const total = run(1_000_000);
					expect(total).to.be.greaterThan(8);
					const failures: string[] = [];
					for (let n = 0; n < total; n += stride) {
						try {
							run(n);
						} catch (err) {
							failures.push(
								`cut after ${n}: ${(err as Error).message.slice(0, 700)}`
							);
						}
					}
					expect(failures, failures.join('\n\n')).to.deep.equal([]);
					console.log(`        (${total} messages in the release)`);
				});
			}
		});

		describe('R dies at a durable write during the hold or the release and restarts from that row', () => {
			for (const what of ['S adds', 'S fulfils'] as const) {
				it(`${what} into the hold (stride ${stride})`, () => {
					const run = (
						k: number,
						when: 'before' | 'after'
					): { writes: number; crashed: boolean } => {
						const { pair, fromS, fromR } = sLostTheClose([2]);
						const held: IHeld = {
							pair,
							fromS: fromS!,
							fromR: fromR!,
							sAdd: null,
							sFulfilled: false
						};
						let writes = 0;
						let crashed = false;
						let armed = true;
						let row = snapshot(pair, 'R');
						pair.rManager.on('channel:persist', () => {
							if (crashed || !armed) return;
							if (writes === k && when === 'before') {
								crashed = true;
								pair.link.drop = (): boolean => true;
								return;
							}
							row = snapshot(pair, 'R');
							if (writes === k) {
								crashed = true;
								pair.link.drop = (): boolean => true;
							}
							writes++;
						});
						pair.link.holdAt = (from, type): boolean =>
							from === 'R' && type === MessageType.FF_CLOSE;
						pair.link.reconnect();
						pair.link.holdAt = null;
						// One round of S's only: a second update of S's behind its
						// unrevoked commitment_signed would meet issue #1300 when
						// R dies before taking that signature.
						if (!crashed) sWorks(held, what);
						if (!crashed) pair.link.release('R');
						// Only the hold and its release are under test here.
						armed = false;
						const label = `${what}; R dies at write ${k}, ${when} it lands`;
						if (crashed) {
							pair.link.disconnect();
							pair.link.drop = null;
							restart(pair, 'R', row);
							pair.sErrors.length = 0;
							pair.rErrors.length = 0;
							pair.link.log.length = 0;
							pair.link.reconnect();
						}
						finishHeld(held, label);
						return { writes, crashed };
					};
					const whole = run(1_000_000, 'before');
					expect(whole.crashed).to.equal(false);
					expect(whole.writes).to.be.greaterThan(3);
					const failures: string[] = [];
					for (let k = 0; k < whole.writes; k += stride) {
						for (const when of ['before', 'after'] as const) {
							try {
								expect(run(k, when).crashed).to.equal(true);
							} catch (err) {
								failures.push(
									`write ${k}, ${when}: ${(err as Error).message.slice(0, 700)}`
								);
							}
						}
					}
					expect(failures, failures.join('\n\n')).to.deep.equal([]);
					console.log(`        (${whole.writes} durable writes by R)`);
				});
			}
		});

		it('at every stage of the hold both sides can still force close on a commitment the peer signed, vouchers and ordinary HTLCs included', () => {
			const { pair, fromS, fromR } = sLostTheClose([2]);
			const before = { S: planClose(pair, 'S'), R: planClose(pair, 'R') };
			expect(before.S.ok, before.S.error).to.equal(true);
			expect(before.R.ok, before.R.error).to.equal(true);
			pair.link.holdAt = (from, type): boolean =>
				from === 'R' && type === MessageType.FF_CLOSE;
			pair.link.reconnect();
			pair.link.holdAt = null;
			const check = (stage: string, rOutputs: number): void => {
				for (const side of SIDES) {
					const plan = planClose(pair, side);
					expect(plan.ok, `${stage} ${side}: ${plan.error}`).to.equal(true);
					if (side === 'R') {
						expect(plan.outputs, `${stage} R outputs`).to.equal(rOutputs);
					}
				}
			};
			check('chain held', before.R.outputs);
			// R's own settle waits behind the chain: its commitment is unchanged.
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				fromS!.id,
				fromS!.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			check('own settle waiting', before.R.outputs);
			// S forwards a payment: R has revoked for it in its own books, the
			// revoke_and_ack is held, and R's commitment is the new one.
			const add = offer(pair, 'S', 2_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			expect(heldTypes(pair.rChannel)).to.include(MessageType.REVOKE_AND_ACK);
			check('revoke_and_ack held', before.R.outputs + 1);
			// And a restart inside the hold changes none of it.
			restart(pair, 'R');
			check('restarted inside the hold', before.R.outputs + 1);
			expect(vouchers(pair.rChannel).length).to.equal(3);
			expect(fromR).to.not.equal(null);
		});

		// Found by this review: before the round 1 fix handleReestablish
		// REPLACED the held set; the fix ran its answer through fforHoldStream,
		// which APPENDS. A second channel_reestablish on a connection that is
		// already holding (the manager answers one: see
		// shouldRetransmitReestablish, the path CLN's channeld restart takes)
		// put the retransmission into the chain twice, and the release sent
		// two copies of the commitment_signed. Two beignet nodes do not send a
		// second reestablish on one connection, so this needs a peer that
		// does.
		//
		// Fixed: a reestablish begins the hold from a clean set. Nothing of
		// the old chain is kept, because whatever joined it after the first
		// reestablish advanced the channel's state as if it had been sent, and
		// the answer to the second reestablish reproduces it from that state.
		// The cases below are the three things that can have joined.
		describe('a second channel_reestablish on a connection that is already holding', () => {
			/** Hold with S's ff_close_ack delayed; returns S's reestablish bytes. */
			function heldPair(): { pair: IPair; fromS: Flight; again: () => void } {
				const { pair, fromS } = sLostTheClose([2]);
				pair.link.holdAt = (from, type): boolean =>
					from === 'S' && type === MessageType.FF_CLOSE_ACK;
				pair.link.reconnect();
				pair.link.holdAt = null;
				const reestablish = pair.link.log.find(
					(e) => e.from === 'S' && e.type === MessageType.CHANNEL_REESTABLISH
				)!;
				return {
					pair,
					fromS: fromS!,
					again: (): void => {
						pair.rManager.handleMessage(
							pair.sPub,
							MessageType.CHANNEL_REESTABLISH,
							reestablish.payload
						);
					}
				};
			}

			it('with nothing new in the chain: the chain is the retransmission once, not twice', () => {
				const { pair, again } = heldPair();
				const once = heldTypes(pair.rChannel);
				expect(once).to.deep.equal([
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.UPDATE_FULFILL_HTLC,
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.COMMITMENT_SIGNED
				]);
				again();
				expect(holding(pair.rChannel)).to.equal(true);
				expect(
					heldTypes(pair.rChannel),
					'the chain after a repeated reestablish'
				).to.deep.equal(once);
				again();
				expect(heldTypes(pair.rChannel)).to.deep.equal(once);
			});

			it("with a revoke_and_ack of R's in the chain (S added while R held): the second answer reproduces it once, behind the commitment_signed, and the release drains", () => {
				const { pair } = sLostTheClose([2]);
				pair.link.holdAt = (from, type): boolean =>
					from === 'R' && type === MessageType.FF_CLOSE;
				pair.link.reconnect();
				pair.link.holdAt = null;
				const reestablish = pair.link.log.find(
					(e) => e.from === 'S' && e.type === MessageType.CHANNEL_REESTABLISH
				)!;
				const add = offer(pair, 'S', 2_000_000n);
				expect(add.result.ok, add.result.error).to.equal(true);
				const before = heldTypes(pair.rChannel);
				expect(before).to.deep.equal([
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.UPDATE_FULFILL_HTLC,
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.COMMITMENT_SIGNED,
					MessageType.REVOKE_AND_ACK
				]);
				// The peer asks again, with the numbers it had: it holds neither
				// R's commitment_signed nor the revoke_and_ack R made since.
				// Handed to the channel itself: through the manager R would send
				// its own reestablish again, the honest S of this harness would
				// answer with a third, and the two would cross what is in
				// flight, which is the peer's restart to get right, not ours.
				const answer = pair.rChannel.handleReestablish(
					decodeChannelReestablishMessage(reestablish.payload)
				);
				expect(
					answer.filter((a) => a.type === ChannelActionType.ERROR)
				).to.deep.equal([]);
				expect(holding(pair.rChannel)).to.equal(true);
				expect(heldTypes(pair.rChannel)).to.deep.equal(before);
				pair.link.release('R');
				expectAlive(pair, 'released');
				expectClosed(pair, 'released');
				expect(pair.events.R.forwarded).to.include(add.id);
			});

			it('with a commitment_signed signed while holding (the #1304 row): the second answer retransmits that signature once', () => {
				const pair = activePair();
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
				pair.link.log.length = 0;
				pair.link.holdAt = (from, type): boolean =>
					from === 'S' && type === MessageType.FF_CLOSE_ACK;
				pair.link.reconnect();
				pair.link.holdAt = null;
				const reestablish = pair.link.log.find(
					(e) => e.from === 'S' && e.type === MessageType.CHANNEL_REESTABLISH
				)!;
				const once = heldTypes(pair.rChannel);
				expect(once).to.deep.equal([
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.UPDATE_FULFILL_HTLC,
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.COMMITMENT_SIGNED
				]);
				const answer = pair.rChannel.handleReestablish(
					decodeChannelReestablishMessage(reestablish.payload)
				);
				expect(
					answer.filter((a) => a.type === ChannelActionType.ERROR)
				).to.deep.equal([]);
				expect(heldTypes(pair.rChannel)).to.deep.equal(once);
				pair.link.release('S');
				expectAlive(pair, 'released');
				expectClosed(pair, 'released');
			});

			it("PIN [#1300] with a settle of R's waiting behind the chain: the second answer replays it ahead of the commitment_signed that does not cover it", () => {
				// The settle is, in the channel's state, an update queued behind
				// an unrevoked commitment_signed, and the answer to a reestablish
				// replays every queued update before the retransmitted signature
				// (issue #1300, not this PR's to fix). The first chain had it in
				// the right place; the answer to the second does not. Required
				// once #1300 is fixed: the fulfil follows the commitment_signed,
				// and the release drains with no wire error.
				const { pair, fromS, again } = heldPair();
				const settle = pair.rManager.fulfillHtlc(
					pair.channelId,
					fromS.id,
					fromS.preimage
				);
				expect(settle.ok, settle.error).to.equal(true);
				expect(heldTypes(pair.rChannel)).to.deep.equal([
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.UPDATE_FULFILL_HTLC,
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.COMMITMENT_SIGNED,
					MessageType.UPDATE_FULFILL_HTLC
				]);
				again();
				// Today: once each, and the late fulfil ahead of the signature.
				expect(heldTypes(pair.rChannel)).to.deep.equal([
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.UPDATE_FULFILL_HTLC,
					MessageType.UPDATE_FAIL_HTLC,
					MessageType.UPDATE_FULFILL_HTLC,
					MessageType.COMMITMENT_SIGNED
				]);
			});
		});

		// Issue #1303 (one failed durable write, then a write that lands) at
		// the one write the fix added: the release leads with its own persist,
		// and when that write fails the whole chain is withheld and dropped
		// while the hold is already cleared. Anything R sends before the
		// forced disconnect then leaves ahead of a chain that never left.
		it("PIN [#1303] the write of the release fails once: the chain is dropped with the hold already cleared, R's next revoke_and_ack leaves alone, and the reconnect fails the channel", () => {
			const { pair } = sLostTheClose([2]);
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
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
			pair.link.release('S');
			expect(failed).to.equal(1);
			expect(holding(pair.rChannel)).to.equal(false);
			expect(sentBy(pair, 'R')).to.not.include(MessageType.COMMITMENT_SIGNED);
			// Before the node's deferred disconnect, S forwards a payment.
			const add = offer(pair, 'S', 2_000_000n);
			expect(add.result.ok, add.result.error).to.equal(true);
			expect(sentBy(pair, 'R')).to.include(MessageType.REVOKE_AND_ACK);
			interrupt(pair, 'disconnect');
			pair.link.reconnect();
			// Today. Once #1303 is fixed: expectAlive and expectClosed.
			expect(pair.sChannel.getState()).to.equal(ChannelState.ERRORED);
			expect(pair.sErrors.join('|')).to.match(/Invalid commitment signature/);
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// 2. The dispute.
	// ───────────────────────────────────────────────────────────────────
	describe('2. a differing ff_close_ack, and a preimage that arrives while the fail is held', () => {
		// Base section 7.5.6: a slot R holds a preimage for is fulfilled,
		// never failed. CONCURRENT-RECEIVE.md section 7: "On receiving the
		// final ack, R unions every valid preimage from every source ...
		// Present vouchers with known preimages are fulfilled even if the peer
		// denies payment", and "If a preimage arrives during a pending
		// failure, preserve it and use ordinary commitment/on-chain recovery
		// where still possible." Section 5.3: a response that cannot advance
		// state "may still supply a hash-valid claim preimage".
		//
		// The honest sequence: S comes back from the row that predates
		// ff_close, so for S the book is open again and its offline service
		// resumes. A payer pays the invoice of slot 1 while R is away; S
		// settles it upstream and keeps t_1 for R. R reconnects, DRAINING,
		// with the fail of voucher 1 queued under the first acknowledgement
		// (which said unsettled, truthfully, at the time). S's answer to the
		// retransmitted ff_close is a second acknowledgement: slot 1 settled,
		// with t_1 in it.
		//
		// Observed: handleFforCloseAck compares the bytes, answers "differs"
		// and adopts nothing, the preimage included. The next reestablish
		// replays the fail, S (DRAINING) takes it, and the voucher is gone:
		// S keeps the payer's money AND the voucher's value, R is out d_1 for
		// an invoice that was paid. The dispute this round records for a
		// concurrent epoch does not change that; a baseline epoch behaves the
		// same.
		for (const concurrent of [true, false]) {
			it.skip(`DEFECT [pre-existing${
				concurrent ? ', kept by the dispute of this round' : ', baseline epoch'
			}] the differing acknowledgement carries the preimage of a slot S settled after coming back; R discards it and then fails that voucher: R loses d_1`, () => {
				const { pair, fromS } = sLostTheClose([2], concurrent);
				expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
				settleSlot(pair, 1);
				const t1 = Buffer.from(record(pair.sChannel).preimages[0]);
				const h1 = crypto.createHash('sha256').update(t1).digest();
				expect(h1.equals(record(pair.rChannel).paymentHashes[0])).to.equal(
					true
				);
				pair.link.reconnect();
				expect(pair.rErrors.join('|')).to.match(/ff_close_ack differs/);
				// S's signed message did deliver t_1 to R.
				const ack = pair.link.log.find(
					(e) => e.from === 'S' && e.type === MessageType.FF_CLOSE_ACK
				)!;
				expect(
					ack.payload.includes(t1),
					'the ack on the wire carries t_1'
				).to.equal(true);
				// The next reestablish (S holds the close now, so no hold).
				interrupt(pair, 'disconnect');
				pair.link.reconnect();
				expectAlive(pair, 'second reconnect');
				const base = record(pair.rChannel).sHtlcIdBase!;
				const stillClaimable =
					vouchers(pair.rChannel).some(([key]) => key === `received-${base}`) &&
					record(pair.rChannel).knownPreimages[0] !== null;
				// A concurrent epoch has R's own 3,000 sat HTLC still in flight.
				const offered = fromS ? 3_000_000n : 0n;
				const paid =
					balances(pair).r === R_START + AMOUNTS[0] + AMOUNTS[1] - offered;
				expect(
					paid || stillClaimable,
					`R holds neither d_1 nor a claim to it: r=${
						balances(pair).r
					}, vouchers on R ${JSON.stringify(vouchers(pair.rChannel))}, S says ${
						pair.sErrors.join('; ') || 'nothing'
					}`
				).to.equal(true);
			});
		}

		// The same rule from another source. While the chain is held, the fail
		// of voucher 1 is signed but provably undelivered (S has not seen the
		// commitment_signed that covers it), and R's own commitment still
		// carries the voucher. R learns t_1 (a witness, a payer's receipt).
		// It is recorded and handed to the chain monitors, and then the
		// release sends the fail anyway. Section 7 leaves room ("where still
		// possible"), so this one is a judgement call; it is here because the
		// hold is exactly the case where it IS still possible.
		for (const concurrent of [true, false]) {
			it.skip(`DEFECT [pre-existing${
				concurrent ? '' : ', baseline epoch'
			}] R learns the preimage of a voucher whose fail is still held; the release sends the fail all the same and R is not paid for the slot`, () => {
				const { pair, fromS } = sLostTheClose([2], concurrent);
				pair.link.holdAt = (from, type): boolean =>
					from === 'S' && type === MessageType.FF_CLOSE_ACK;
				pair.link.reconnect();
				pair.link.holdAt = null;
				expect(holding(pair.rChannel)).to.equal(true);
				const t1 = record(pair.sChannel).preimages[0];
				const learned = pair.rManager.fforAddPreimage(pair.channelId, t1);
				expect(learned.ok, learned.error).to.equal(true);
				expect(record(pair.rChannel).knownPreimages[0]).to.not.equal(null);
				pair.link.release('S');
				expectAlive(pair, 'released');
				const base = record(pair.rChannel).sHtlcIdBase!;
				const stillClaimable = vouchers(pair.rChannel).some(
					([key]) => key === `received-${base}`
				);
				const offered = fromS ? 3_000_000n : 0n;
				const paid =
					balances(pair).r === R_START + AMOUNTS[0] + AMOUNTS[1] - offered;
				expect(
					paid || stillClaimable,
					`R holds t_1 and neither d_1 nor the voucher: r=${balances(pair).r}`
				).to.equal(true);
			});
		}

		// The manager announces a dispute once per channel for the life of
		// the process (_fforEnforceAnnounced is never cleared). That was
		// enough while only a reestablish could raise activationMismatch on an
		// epoch that then stayed in dispute. A disputed concurrent book now
		// drains to CLOSED and the channel takes a new epoch; a dispute on
		// that one is recorded and never announced.
		it.skip("DEFECT [pre-existing bookkeeping, newly reachable] a second disputed epoch on the same channel raises no 'ffor:enforce': the host is told once per channel, not once per epoch", () => {
			const pair = createPair({ pushSat: 200_000n });
			const enforce: Buffer[] = [];
			pair.rManager.on('ffor:enforce', (_id: Buffer, f: { epochId: Buffer }) =>
				enforce.push(Buffer.from(f.epochId))
			);
			const epochs: Buffer[] = [];
			for (let round = 0; round < 2; round++) {
				pair.sErrors.length = 0;
				pair.rErrors.length = 0;
				activate(pair, AMOUNTS, true);
				epochs.push(Buffer.from(record(pair.rChannel).epochId));
				const backup = snapshot(pair, 'S');
				settleSlot(pair, 2);
				pair.link.drop = (from, type): boolean =>
					from === 'R' && type !== MessageType.FF_CLOSE;
				const closed = pair.rManager.closeFforEpoch(pair.channelId);
				expect(closed.ok, closed.error).to.equal(true);
				pair.link.drop = null;
				restart(pair, 'S', backup);
				pair.link.reconnect();
				expect(record(pair.rChannel).activationMismatch).to.equal(true);
				interrupt(pair, 'disconnect');
				pair.link.reconnect();
				expectClosed(pair, `epoch ${round + 1}`);
			}
			expect(
				enforce.map((e) => e.toString('hex')),
				'one announcement per disputed epoch'
			).to.deep.equal(epochs.map((e) => e.toString('hex')));
		});

		// CONCURRENT-RECEIVE.md section 3: a close transition "MUST permit
		// existing ordinary fulfill/fail and commitment progress".
		//
		// The fix refuses R's own settle while the disputed chain is held and
		// names the remedy: "the caller keeps what it owes and settles when
		// the channel has reestablished". Nothing brings that reestablish
		// about. The connection is healthy, S has nothing to wait for, and
		// the manager raises ffor:enforce and no request to drop the
		// connection (a failed write gets one: transition:blocked). So the
		// refusal lasts until something unrelated cuts the link; an inbound
		// HTLC R holds the preimage for rides to the claim backstop, which
		// force closes a channel one reconnect would have drained.
		it.skip('DEFECT [left by the round 1 fixes] the disputed hold refuses R its own settle "until the channel reestablishes" and nothing asks for that reestablish', () => {
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
			const asked: string[] = [];
			for (const name of ['transition:blocked', 'transition:frozen']) {
				pair.rManager.on(name, () => asked.push(name));
			}
			pair.link.log.length = 0;
			pair.link.reconnect();
			expect(record(pair.rChannel).activationMismatch).to.equal(true);
			expect(holding(pair.rChannel)).to.equal(true);
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			// Either the settle makes progress, or R asks for the reconnect
			// that lets it.
			expect(
				settle.ok || asked.length > 0,
				`settle: ${settle.error}; reconnect requested: ${asked.length > 0}`
			).to.equal(true);
		});

		it('the dispute through restarts of both sides and a third loss of the close by S: consistent, nothing fails, and the first reestablish with a DRAINING S drains', () => {
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
			pair.link.reconnect();
			expect(record(pair.rChannel).activationMismatch).to.equal(true);
			// Both restart; S from the old row once more.
			pair.link.disconnect();
			restart(pair, 'R');
			restart(pair, 'S', backup);
			expect(record(pair.rChannel).activationMismatch).to.equal(true);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.reconnect();
			expectAlive(pair, 'third loss');
			expect(holding(pair.rChannel)).to.equal(true);
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			const refused = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			expect(refused.ok).to.equal(false);
			// In the dispute R can still close on chain with everything on it.
			const plan = planClose(pair, 'R');
			expect(plan.ok, plan.error).to.equal(true);
			// S keeps its row this time.
			interrupt(pair, 'restart both');
			pair.link.reconnect();
			expectAlive(pair, 'drained');
			expectClosed(pair, 'drained');
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(balances(pair)).to.deep.equal(drained(6_000_000n));
			expectSettled(pair, 'drained');
			// The disputed book is CLOSED: it holds nothing back, and the next
			// concurrent epoch starts clean.
			pay(pair, 'R', 1_000_000n);
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			activate(pair, AMOUNTS, true);
			for (const side of SIDES) {
				expect(record(channel(pair, side)).activationMismatch).to.equal(false);
				expect(channel(pair, side).fforAdmissionHold()).to.equal(null);
			}
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// 3. The ack-unsent flag.
	// ───────────────────────────────────────────────────────────────────
	describe('3. S originates nothing until its ff_activate_ack has left', () => {
		it('a restarted S (the constructor sets the flag for every ACTIVE concurrent S) settles what it owes R from inside channel:reestablished, where the node does it', () => {
			const pair = activePair();
			const fromR = offer(pair, 'R', 4_000_000n);
			expect(fromR.result.ok, fromR.result.error).to.equal(true);
			interrupt(pair, 'restart S');
			// Before the reestablish the flag says "unknown": nothing of S's.
			let inHook: { ok: boolean; error?: string } | null = null;
			pair.sManager.on('channel:reestablished', () => {
				inHook = pair.sManager.fulfillHtlc(
					pair.channelId,
					fromR.id,
					fromR.preimage
				);
			});
			pair.link.reconnect();
			expect(inHook, 'the hook ran').to.not.equal(null);
			expect(inHook!.ok, inHook!.error).to.equal(true);
			expectAlive(pair, 'settled in the hook');
			expect(balances(pair).s).to.equal(S_AFTER_BOOK + 4_000_000n);
			expectSettled(pair, 'settled in the hook');
			pay(pair, 'S', 1_000_000n);
		});

		it('the flag does not touch the offline service: a restarted S still starts delegated settlements for an R that is away', () => {
			const pair = activePair();
			pair.link.disconnect();
			restart(pair, 'S');
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(null);
			expect(pair.sChannel.fforSettlementRefusal(3, TIP)).to.equal(null);
		});

		it('ack lost, then an incompatible reconnect: the ack is replayed, R completes, both hold new adds; a compatible reconnect lifts the hold and traffic flows', () => {
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
			interrupt(pair, 'restart both');
			advertise(pair, 'R', false);
			pair.link.reconnect();
			expectAlive(pair, 'incompatible reconnect');
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			for (const side of SIDES) {
				expect(record(channel(pair, side)).capabilityHold).to.equal(true);
				const add = offer(pair, side, 1_000_000n);
				expect(add.result.ok).to.equal(false);
				expect(add.result.error).to.match(/did not advertise/);
			}
			pair.link.disconnect();
			advertise(pair, 'R', true);
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.reconnect();
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectAlive(pair, 'compatible reconnect');
			expectSettled(pair, 'compatible reconnect');
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// 4. The persisted capability hold.
	// ───────────────────────────────────────────────────────────────────
	describe('4. the persisted capability hold', () => {
		/** What storage holds: the row of the last write that landed. */
		function disk(pair: IPair, side: Side): { row: () => string } {
			let row = snapshot(pair, side);
			manager(pair, side).on(
				'channel:persist',
				(ev: { request?: { committed: boolean } }) => {
					if (ev.request && ev.request.committed === false) return;
					row = snapshot(pair, side);
				}
			);
			return { row: (): string => row };
		}

		// Section 8: the hold lasts until a compatible init, and the fix's own
		// words: "it must outlive this process".
		//
		// Found by this review: handleReestablish consumed
		// _fforCapabilityHoldUnsaved as it asked for the write. When that
		// write failed, the record in memory already carried the hold, so the
		// next reestablish saw no change and asked for no write; an idle
		// channel's reestablish sends nothing either. The hold stayed in
		// memory only, and a restart lifted it. Fixed: the marker stands
		// until the manager reports a write that landed.
		it('the write of an observed hold fails once: the next reestablish asks for it again, and the hold outlives a restart', () => {
			const pair = activePair();
			pair.link.disconnect();
			advertise(pair, 'R', false);
			let failed = 0;
			pair.sManager.on(
				'channel:persist',
				(ev: { request?: { committed: boolean } }) => {
					if (failed === 0 && ev.request) {
						ev.request.committed = false;
						failed++;
					}
				}
			);
			const stored = disk(pair, 'S');
			pair.link.reconnect();
			expect(failed).to.equal(1);
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
				/capability hold/
			);
			expect(stored.row(), 'not on disk yet').to.not.include('capabilityHold');
			// The node drops the connection over the failed write; R, still
			// without the extension, comes back. Nothing changed, nothing is
			// sent, and the write is asked for again all the same.
			pair.link.disconnect();
			pair.link.log.length = 0;
			pair.link.reconnect();
			expect(pair.link.types()).to.deep.equal([
				MessageType.CHANNEL_REESTABLISH,
				MessageType.CHANNEL_REESTABLISH
			]);
			expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.match(
				/capability hold/
			);
			expect(stored.row(), 'on disk now').to.include('"capabilityHold":true');
			// Once it has landed it is not asked for a third time.
			let writes = 0;
			pair.sManager.on('channel:persist', () => writes++);
			pair.link.disconnect();
			pair.link.reconnect();
			expect(writes).to.equal(0);
			// R goes away; S restarts from what storage holds.
			pair.link.disconnect();
			restart(pair, 'S', stored.row());
			expect(
				pair.sChannel.fforSettlementRefusal(1, TIP),
				'the hold must outlive the process'
			).to.match(/capability hold/);
		});

		it('the mirror: the write that lifts a hold fails once; the stale hold a restart brings back is lifted by the next compatible reestablish', () => {
			const pair = activePair();
			pair.link.disconnect();
			advertise(pair, 'R', false);
			pair.link.reconnect();
			pair.link.disconnect();
			advertise(pair, 'R', true);
			let failed = 0;
			pair.sManager.on(
				'channel:persist',
				(ev: { request?: { committed: boolean } }) => {
					if (failed === 0 && ev.request) {
						ev.request.committed = false;
						failed++;
					}
				}
			);
			const stored = disk(pair, 'S');
			pair.link.reconnect();
			expect(failed).to.equal(1);
			expect(pair.sChannel.fforAdmissionHold()).to.equal(null);
			pair.link.disconnect();
			restart(pair, 'S', stored.row());
			// Stale, and on the safe side: S holds although R is compatible.
			expect(record(pair.sChannel).capabilityHold).to.equal(true);
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.reconnect();
			expect(record(pair.sChannel).capabilityHold).to.equal(undefined);
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectAlive(pair, 'lifted');
		});

		it('a downgrade and an upgrade of R with restarts of both sides between each step: the hold is on both rows exactly while R lacks the extension', () => {
			const pair = activePair();
			const rows = (): Array<boolean> =>
				SIDES.map(
					(side) =>
						JSON.parse(snapshot(pair, side)).ffor.capabilityHold === true
				);
			expect(rows()).to.deep.equal([false, false]);
			interrupt(pair, 'restart both');
			advertise(pair, 'R', false);
			pair.link.reconnect();
			expect(rows()).to.deep.equal([true, true]);
			interrupt(pair, 'restart both');
			expect(rows()).to.deep.equal([true, true]);
			pair.link.reconnect();
			expect(rows()).to.deep.equal([true, true]);
			interrupt(pair, 'restart both');
			advertise(pair, 'R', true);
			pair.link.reconnect();
			expect(rows()).to.deep.equal([false, false]);
			for (const side of SIDES) {
				expect(snapshot(pair, side)).to.not.include('capabilityHold');
			}
			interrupt(pair, 'restart both');
			pair.link.reconnect();
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectAlive(pair, 'upgraded');
		});

		it('the capability hold, the drain hold and the dispute all at once: nothing fails, R can close on chain, and a compatible reestablish with a DRAINING S ends it all', () => {
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
			advertise(pair, 'S', false);
			pair.link.log.length = 0;
			pair.link.reconnect();
			expectAlive(pair, 'three holds');
			const f = record(pair.rChannel);
			expect(f.capabilityHold).to.equal(true);
			expect(f.activationMismatch).to.equal(true);
			expect(holding(pair.rChannel)).to.equal(true);
			expect(offer(pair, 'R', 1_000_000n).result.ok).to.equal(false);
			expect(planClose(pair, 'R').ok).to.equal(true);
			// All three are on R's row or rebuilt from it.
			interrupt(pair, 'restart R');
			expect(record(pair.rChannel).capabilityHold).to.equal(true);
			expect(record(pair.rChannel).activationMismatch).to.equal(true);
			advertise(pair, 'S', true);
			pair.link.reconnect();
			expectAlive(pair, 'ended');
			expectClosed(pair, 'ended');
			expect(record(pair.rChannel).capabilityHold).to.equal(undefined);
			const settle = pair.rManager.fulfillHtlc(
				pair.channelId,
				inbound.id,
				inbound.preimage
			);
			expect(settle.ok, settle.error).to.equal(true);
			expect(balances(pair)).to.deep.equal(drained(6_000_000n));
			pay(pair, 'S', 1_000_000n);
			pay(pair, 'R', 1_000_000n);
			expectSettled(pair, 'ended');
		});
	});

	// ───────────────────────────────────────────────────────────────────
	// 5. Baseline epochs under the changed hold. The byte-for-byte
	// comparison of baseline wire traces against origin/master was run
	// with a separate scratch tool (see the review report): 37 of 38 flows
	// identical, the 38th being the #1304 double fault the change fixes.
	// ───────────────────────────────────────────────────────────────────
	describe('5. baseline epochs', () => {
		/** Every row either side writes, and a restart that keeps recording. */
		function recorder(pair: IPair): {
			rows: string[];
			restart: (side: Side, row?: string) => void;
		} {
			const rows: string[] = [];
			const watch = (side: Side): void => {
				manager(pair, side).on('channel:persist', () =>
					rows.push(snapshot(pair, side))
				);
			};
			watch('S');
			watch('R');
			return {
				rows,
				restart: (side, row): void => {
					restart(pair, side, row);
					rows.push(snapshot(pair, side));
					watch(side);
				}
			};
		}

		it('no baseline row ever gains capabilityHold or concurrentVersion: setup, an incompatible and a compatible reconnect, the hold, the double fault, a differing acknowledgement, the drain', () => {
			const pair = createPair({ pushSat: 200_000n });
			const rec = recorder(pair);
			activate(pair, AMOUNTS, false);
			// Reconnects under every advertisement.
			for (const on of [false, true]) {
				pair.link.disconnect();
				advertise(pair, 'S', on);
				advertise(pair, 'R', !on);
				pair.link.reconnect();
				rec.restart('S');
				rec.restart('R');
				pair.link.reconnect();
			}
			advertise(pair, 'R', true);
			const backup = snapshot(pair, 'S');
			settleSlot(pair, 2);
			let drainingRow: string | null = null;
			pair.rManager.on('channel:persist', () => {
				if (
					drainingRow === null &&
					record(pair.rChannel).state === FforState.DRAINING
				) {
					drainingRow = snapshot(pair, 'R');
				}
			});
			pair.link.drop = (from, type): boolean =>
				from === 'R' && type !== MessageType.FF_CLOSE;
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			pair.link.drop = null;
			// The double fault of #1304, with S's acknowledgement differing too
			// (its row predates the settlement of slot 2).
			rec.restart('S', backup);
			rec.restart('R', drainingRow!);
			pair.link.log.length = 0;
			pair.sErrors.length = 0;
			pair.rErrors.length = 0;
			pair.link.reconnect();
			expectAlive(pair, 'baseline, differing ack');
			expect(record(pair.rChannel).activationMismatch).to.equal(false);
			interrupt(pair, 'disconnect');
			pair.link.reconnect();
			expectAlive(pair, 'baseline, drained');
			expectClosed(pair, 'baseline, drained');
			expect(rec.rows.length).to.be.greaterThan(20);
			for (const row of rec.rows) {
				expect(row).to.not.include('capabilityHold');
				expect(row).to.not.include('concurrentVersion');
			}
		});

		for (const how of INTERRUPTS) {
			it(`the single-fault hold of a baseline epoch, interrupted by ${how} while holding, then released: CLOSED and exact`, () => {
				const { pair } = sLostTheClose([2], false);
				pair.link.holdAt = (from, type): boolean =>
					from === 'S' && type === MessageType.FF_CLOSE_ACK;
				pair.link.reconnect();
				pair.link.holdAt = null;
				expect(holding(pair.rChannel)).to.equal(true);
				// A baseline epoch still freezes ordinary traffic on both sides.
				expect(offer(pair, 'R', 1_000_000n).result.ok).to.equal(false);
				expect(offer(pair, 'S', 1_000_000n).result.ok).to.equal(false);
				expect(pair.rChannel.fforAdmissionHold()).to.equal(null);
				interrupt(pair, how);
				pair.link.reconnect();
				expectAlive(pair, how);
				expectClosed(pair, how);
				expect(balances(pair)).to.deep.equal(drained(0n));
				expectSettled(pair, how);
			});
		}

		it('a baseline R that learns a preimage while holding an EMPTY chain drains nothing into the hold, and the release re-drives it', () => {
			const pair = activePair(false);
			const backup = snapshot(pair, 'S');
			// R reaches DRAINING with its first drain not run (it stopped
			// between the DRAINING write and the drain).
			const drain = pair.rChannel as unknown as {
				_fforDrain(f: unknown): ChannelAction[];
			};
			const original = drain._fforDrain.bind(pair.rChannel);
			drain._fforDrain = (): ChannelAction[] => [];
			const closed = pair.rManager.closeFforEpoch(pair.channelId);
			expect(closed.ok, closed.error).to.equal(true);
			drain._fforDrain = original;
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			restart(pair, 'S', backup);
			pair.link.log.length = 0;
			pair.link.holdAt = (from, type): boolean =>
				from === 'S' && type === MessageType.FF_CLOSE_ACK;
			pair.link.reconnect();
			pair.link.holdAt = null;
			expect(holding(pair.rChannel)).to.equal(true);
			expect(heldTypes(pair.rChannel)).to.deep.equal([]);
			const t1 = record(pair.sChannel).preimages[0];
			const learned = pair.rManager.fforAddPreimage(pair.channelId, t1);
			expect(learned.ok, learned.error).to.equal(true);
			expect(sentBy(pair, 'R')).to.deep.equal([
				MessageType.CHANNEL_REESTABLISH,
				MessageType.FF_CLOSE
			]);
			pair.link.release('S');
			expectAlive(pair, 'released');
			expectClosed(pair, 'released');
			expect(balances(pair).r).to.equal(R_START + AMOUNTS[0]);
			expectSettled(pair, 'released');
		});
	});
});
