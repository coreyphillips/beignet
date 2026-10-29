/**
 * FFOR concurrent receive, version 1: adversarial recovery review of PR #1301,
 * sections 1a and 1b: an ordinary round in ACTIVE cut at every message
 * boundary, and the scenarios cut at message boundaries.
 *
 * What the review covers, the PIN convention and the FFOR_* environment knobs
 * are described in
 * tests/lightning/helpers/ffor-concurrent-adversarial-recovery.ts.
 */

import { expect } from 'chai';
import {
	balances,
	channel,
	manager,
	offer,
	ordinaryHtlcs,
	other,
	pay,
	record,
	why
} from './helpers/ffor-concurrent-pair';
import {
	S_AFTER_BOOK,
	R_START,
	SIDES,
	activePair,
	cutAfter,
	INTERRUPTS,
	interrupt,
	expectAlive,
	expectSettled,
	expectActiveUnchanged,
	SCENARIOS,
	runCut
} from './helpers/ffor-concurrent-adversarial-recovery';

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
});
