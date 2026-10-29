/**
 * FFOR concurrent receive, version 1: adversarial recovery review of PR #1301,
 * sections 1c, 1d and 6a: a crash at a durable write restarted from the row on
 * disk, the schedule explorer, and issue #1300 beside a live voucher book.
 *
 * What the review covers, the PIN convention and the FFOR_* environment knobs
 * are described in
 * tests/lightning/helpers/ffor-concurrent-adversarial-recovery.ts.
 */

import { expect } from 'chai';
import { MessageType } from '../../src/lightning/message/types';
import { FforState } from '../../src/lightning/ffor/types';
import {
	balances,
	offer,
	record,
	settleSlot
} from './helpers/ffor-concurrent-pair';
import {
	S_AFTER_BOOK,
	R_START,
	SIDES,
	activePair,
	interrupt,
	expectAlive,
	expectSettled,
	expectActiveUnchanged,
	expectClosed,
	prone1300,
	SCENARIOS,
	CrashWhen,
	runCrash,
	ExploreMode,
	explore,
	drained
} from './helpers/ffor-concurrent-adversarial-recovery';

describe('FFOR concurrent receive: adversarial recovery review of PR #1301', function () {
	this.timeout(900_000);

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
	describe('1d. schedule explorer with signed prefixes and unsigned tails', () => {
		const [first, last] = (process.env.FFOR_SEEDS ?? '1-3')
			.split('-')
			.map(Number);
		for (const mode of ['none', 'active', 'draining'] as ExploreMode[]) {
			for (let seed = first; seed <= (last ?? first); seed++) {
				it(`${mode} seed ${seed}`, () => {
					explore(seed, mode, false);
				});
			}
		}
	});

	// ───────────────────────────────────────────────────────────────────
	// Ordered reconnect replay (#1300) beside a live voucher book.
	// Covered updates and their original signature precede the unsigned tail.
	// ───────────────────────────────────────────────────────────────────
	describe('6a. issue #1300 beside a live voucher book', () => {
		it('ACTIVE: R settles an HTLC behind its own unrevoked commitment_signed, and reconnect preserves the book and completes both payments', () => {
			const pair = activePair();
			const hAct = Buffer.from(record(pair.rChannel).hAct!);
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
			expectAlive(pair, 'reconnected');
			expectActiveUnchanged(pair, hAct, 'reconnected');
			expect(pair.sErrors).to.deep.equal([]);
			expect(pair.rErrors).to.deep.equal([]);
			const complete = pair.sManager.fulfillHtlc(
				pair.channelId,
				out.id,
				out.preimage
			);
			expect(complete.ok, complete.error).to.equal(true);
			expectSettled(pair, 'both payments completed');
			expectActiveUnchanged(pair, hAct, 'both payments completed');
			expect(balances(pair)).to.deep.equal({
				s: S_AFTER_BOOK - 2_000_000n,
				r: R_START + 2_000_000n,
				sViewOfR: R_START + 2_000_000n,
				rViewOfS: S_AFTER_BOOK - 2_000_000n
			});
		});

		it('DRAINING: the drain is issued behind an unrevoked commitment_signed, and reconnect closes the book with the channel open', () => {
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
			expectAlive(pair, 'reconnected');
			expectClosed(pair, 'reconnected');
			expect(pair.sErrors).to.deep.equal([]);
			expect(pair.rErrors).to.deep.equal([]);
			const complete = pair.sManager.fulfillHtlc(
				pair.channelId,
				out.id,
				out.preimage
			);
			expect(complete.ok, complete.error).to.equal(true);
			expectSettled(pair, 'ordinary payment completed');
			expect(balances(pair)).to.deep.equal(drained(-2_000_000n));
		});

		it('every explorer schedule recovers when cuts can cross a signed prefix and unsigned tail', () => {
			const failed: string[] = [];
			for (const mode of ['none', 'active', 'draining'] as ExploreMode[]) {
				for (let seed = 1; seed <= 6; seed++) {
					try {
						explore(seed, mode, false);
					} catch (err) {
						const text = (err as Error).message;
						failed.push(`${mode}/${seed}: ${text}`);
					}
				}
			}
			expect(failed, failed.join('\n\n')).to.deep.equal([]);
		});
	});
});
