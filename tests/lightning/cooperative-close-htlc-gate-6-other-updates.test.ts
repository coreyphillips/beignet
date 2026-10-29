/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 6: other updates in flight: crossing removals, a deferred signature,
 * an empty signature, an update_fee round.
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import { expect } from 'chai';
import { writableState } from './helpers/writable-state';
import {
	FLAVORS,
	HTLC_MSAT,
	Side,
	policiesFor,
	onePolicyFor,
	fewBoundariesFor,
	FULFILL,
	SIG,
	RAA,
	offer,
	remove,
	makeFundedPair,
	after,
	START,
	problemsOf,
	expectNoProblems,
	deliverRound,
	INITIATORS,
	startShutdown,
	initiatorName
} from './helpers/cooperative-close-htlc-gate';

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

	// ───────────── 6. other updates in flight ─────────────

	describe('6. other updates in flight beside a shutdown', function () {
		it('two removals crossing each other, one in each direction', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const initiator of INITIATORS) {
					for (const policy of policiesFor(flavor)) {
						const tag = `two-way-${flavor}-${initiator}`;
						const t = makeFundedPair(tag, flavor);
						const ab = offer(t, 'A', HTLC_MSAT);
						const ba = offer(t, 'B', 7_000_000n);
						t.wire.manual(true);
						remove(t, ab, 'fulfil');
						remove(t, ba, 'fail');
						startShutdown(t, initiator);
						t.wire.drain(policy.make());
						problems.push(
							...problemsOf(t, after(START, ab, 'fulfil')).map(
								(p) =>
									`[${flavor}, shutdown from ${initiatorName(initiator)}, ${
										policy.name
									}] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		it('two removals back to back, the second behind an unrevoked signature', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const initiator of INITIATORS) {
					for (const policy of policiesFor(flavor)) {
						const tag = `back-to-back-${flavor}-${initiator}`;
						const t = makeFundedPair(tag, flavor);
						const first = offer(t, 'A', HTLC_MSAT);
						const second = offer(t, 'A', 7_000_000n);
						t.wire.manual(true);
						remove(t, first, 'fulfil');
						remove(t, second, 'fulfil');
						// The second fulfil left without a signature: the first
						// one is still unrevoked.
						expect(t.wire.pendingTypes('B')).to.deep.equal([
							FULFILL,
							SIG,
							FULFILL
						]);
						startShutdown(t, initiator);
						t.wire.drain(policy.make());
						problems.push(
							...problemsOf(
								t,
								after(after(START, first, 'fulfil'), second, 'fulfil')
							).map(
								(p) =>
									`[${flavor}, shutdown from ${initiatorName(initiator)}, ${
										policy.name
									}] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		it('a signature that covers no update still has to be revoked for before the close', function () {
			// The stale needsCommitment of issue #1305 produces exactly this: a
			// commitment_signed with nothing new in it, in flight, with no
			// HTLC and no staged fee beside it.
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const initiator of INITIATORS) {
					for (const policy of policiesFor(flavor)) {
						const t = makeFundedPair(
							`empty-sig-${flavor}-${initiator}`,
							flavor
						);
						t.wire.manual(true);
						writableState(t.aChannel()).needsCommitment = true;
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						expect(t.A().autoSignAndSendCommitment(t.channelId).ok).to.equal(
							true
						);
						expect(t.wire.pendingTypes('A')).to.deep.equal([SIG]);
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						startShutdown(t, initiator);
						t.wire.drain(policy.make());
						problems.push(
							...problemsOf(t, START).map(
								(p) =>
									`[${flavor}, shutdown from ${initiatorName(initiator)}, ${
										policy.name
									}] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		const feeRound: Array<{ from: Side; type: string }> = [
			{ from: 'A', type: 'UPDATE_FEE' },
			{ from: 'A', type: SIG },
			{ from: 'B', type: RAA },
			{ from: 'B', type: SIG },
			{ from: 'A', type: RAA }
		];

		for (const flavor of FLAVORS) {
			it(`${flavor}: an update_fee round crossed by a shutdown at its boundaries still closes`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const k of fewBoundariesFor(flavor)) {
						for (const policy of onePolicyFor(flavor, k)) {
							const tag = `fee-${flavor}-${initiator}-${k}`;
							const t = makeFundedPair(tag, flavor);
							t.wire.manual(true);
							const r = t.A().updateChannelFee(t.channelId, 600);
							expect(r.ok, r.error).to.equal(true);
							deliverRound(t, feeRound, k);
							startShutdown(t, initiator);
							t.wire.drain(policy.make());
							problems.push(
								...problemsOf(t, START).map(
									(p) =>
										`[shutdown from ${initiatorName(
											initiator
										)}, ${k} of 5 delivered, ${policy.name}] ${p}`
								)
							);
						}
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an update_fee at the unchanged rate crossed by a shutdown still closes`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const k of fewBoundariesFor(flavor)) {
						for (const policy of policiesFor(flavor)) {
							const t = makeFundedPair(
								`same-fee-${flavor}-${initiator}-${k}-${policy.name}`,
								flavor
							);
							t.wire.manual(true);
							const rate = t.aChannel().getFullState().localConfig.feeratePerKw;
							expect(t.A().updateChannelFee(t.channelId, rate).ok).to.equal(
								true
							);
							deliverRound(t, feeRound, k);
							startShutdown(t, initiator);
							t.wire.drain(policy.make());
							problems.push(
								...problemsOf(t, START).map(
									(p) => `[${initiator}, ${k} delivered, ${policy.name}] ${p}`
								)
							);
						}
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an unchanged fee awaiting the peer's signature survives restart and reconnect before closing`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const restarted of [null, 'A', 'B'] as Array<Side | null>) {
						const t = makeFundedPair(
							`same-fee-restart-${flavor}-${initiator}-${restarted}`,
							flavor
						);
						t.wire.manual(true);
						const rate = t.aChannel().getFullState().localConfig.feeratePerKw;
						expect(t.A().updateChannelFee(t.channelId, rate).ok).to.equal(true);
						deliverRound(t, feeRound, 3);
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						startShutdown(t, initiator);
						t.wire.cut();
						if (restarted) t.wire.restart(restarted, true);
						expect(t.aChannel().closingBlockedBy()).to.equal('pending updates');
						t.wire.reconnect(false);
						problems.push(
							...problemsOf(t, START, { reconnected: true }).map(
								(p) => `[${initiator}, restart ${restarted}] ${p}`
							)
						);
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an update_fee the peer already signed is not staged again on reconnect and the close finishes`, function () {
				const problems: string[] = [];
				for (const initiator of INITIATORS) {
					for (const when of ['before', 'after']) {
						for (const restarted of [null, 'A', 'B'] as Array<Side | null>) {
							const t = makeFundedPair(
								`fee-replay-${flavor}-${initiator}-${when}-${restarted}`,
								flavor
							);
							t.wire.manual(true);
							expect(t.A().updateChannelFee(t.channelId, 600).ok).to.equal(
								true
							);
							deliverRound(t, feeRound, 2);
							if (when === 'before') startShutdown(t, initiator);
							t.wire.cut();
							if (restarted) t.wire.restart(restarted, true);
							t.wire.reconnect(true);
							expect(t.wire.replay.A).to.not.include('UPDATE_FEE');
							if (when === 'after') startShutdown(t, initiator);
							t.wire.drain(policiesFor(flavor)[0].make());
							problems.push(
								...problemsOf(t, START, { reconnected: true }).map(
									(p) =>
										`[${initiator}, ${when} cut, restart ${restarted}] ${p}`
								)
							);
							if (
								t.bChannel().getFullState().pendingFeeratePerKw !== undefined
							) {
								problems.push(
									'the acceptor still stages a fee the opener will not sign'
								);
							}
						}
					}
				}
				expectNoProblems(problems);
			});

			it(`${flavor}: an update_fee whose commitment was lost is still replayed before closing`, function () {
				const t = makeFundedPair(`fee-lost-${flavor}`, flavor);
				t.wire.manual(true);
				expect(t.A().updateChannelFee(t.channelId, 600).ok).to.equal(true);
				expect(t.wire.step('A')).to.equal('UPDATE_FEE');
				t.wire.cut();
				t.wire.reconnect(true);
				expect(t.wire.replay.A.slice(0, 2)).to.deep.equal(['UPDATE_FEE', SIG]);
				startShutdown(t, 'B');
				t.wire.drain(policiesFor(flavor)[0].make());
				expectNoProblems(problemsOf(t, START, { reconnected: true }));
			});

			it(`${flavor}: an update_fee crossing the peer's commitment completes before closing`, function () {
				const problems: string[] = [];
				for (const sameRate of [false, true]) {
					for (const initiator of INITIATORS) {
						for (const policy of policiesFor(flavor)) {
							const t = makeFundedPair(
								`fee-cross-${flavor}-${sameRate}-${initiator}-${policy.name}`,
								flavor
							);
							t.wire.manual(true);
							const h = offer(t, 'B', HTLC_MSAT);
							const rate = sameRate
								? t.aChannel().getFullState().localConfig.feeratePerKw
								: 600;
							expect(t.A().updateChannelFee(t.channelId, rate).ok).to.equal(
								true
							);
							startShutdown(t, initiator);
							t.wire.drain(policy.make());
							remove(t, h, 'fulfil');
							t.wire.drain(policy.make());
							problems.push(...problemsOf(t, after(START, h, 'fulfil')));
						}
					}
				}
				expectNoProblems(problems);
			});
		}
	});
});
