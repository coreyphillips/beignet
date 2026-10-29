/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 8: the predicate itself, and every signing stage against it.
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import { expect } from 'chai';
import { ChannelState, HtlcState } from '../../src/lightning/channel/types';
import {
	ChannelActionType,
	ChannelErrorCode
} from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { writableState } from './helpers/writable-state';
import {
	Flavor,
	HTLC_MSAT,
	Side,
	other,
	scriptOf,
	IPair,
	ALTERNATING,
	SIG,
	RAA,
	SHUTDOWN,
	REMOVALS,
	chanOf,
	offer,
	offerEntry,
	remove,
	shutdown,
	makeFundedPair,
	START,
	problemsOf,
	expectNoProblems,
	removalRound,
	deliverRound
} from './helpers/cooperative-close-htlc-gate';

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

	// ───────────── 8. the predicate itself ─────────────

	describe('8. what counts as not empty', function () {
		const blocked = (t: IPair): Record<Side, string | null> => ({
			A: t.aChannel().closingBlockedBy(),
			B: t.bChannel().closingBlockedBy()
		});
		const HTLCS = 'pending HTLCs';
		const UPDATES = 'pending updates';

		for (const kind of REMOVALS) {
			it(`a ${kind}: every step of the removal round, on both sides`, function () {
				const t = makeFundedPair(`predicate-${kind}`);
				expect(blocked(t)).to.deep.equal({ A: null, B: null });
				t.wire.manual(true);
				const h = offer(t, 'A', HTLC_MSAT);
				// The add round: an entry on each side that has seen the add.
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: null });
				t.wire.drain(ALTERNATING.make());
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				remove(t, h, kind);
				const round = removalRound(h, kind);
				const entryOf = (side: Side): string | undefined =>
					[...chanOf(t, side).getFullState().htlcs.values()][0]?.state;
				const keptOf = (side: Side): number =>
					chanOf(t, side).getFullState().signedLocalRemovals?.length ?? 0;
				const removed = kind === 'fulfil' ? 'FULFILLED' : 'FAILED';

				// Sent, nothing delivered: the old count saw B's entry no more.
				expect(entryOf('A')).to.equal('COMMITTED');
				expect(entryOf('B')).to.equal(removed);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round, 1); // the update reaches A
				expect(entryOf('A')).to.equal(removed);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round.slice(1), 1); // B's signature reaches A
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round.slice(2), 1); // A's revoke_and_ack reaches B
				// B's entry is gone and its amount is on a balance, but the
				// commitment B holds still carries the output.
				expect(entryOf('B')).to.equal(undefined);
				expect(keptOf('B')).to.equal(1);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: HTLCS });

				deliverRound(t, round.slice(3), 1); // A's signature reaches B
				// B has sent the last message of the round and is empty; A is
				// not until that revoke_and_ack arrives.
				expect(keptOf('B')).to.equal(0);
				expect(entryOf('A')).to.equal(removed);
				expect(blocked(t)).to.deep.equal({ A: HTLCS, B: null });

				deliverRound(t, round.slice(4), 1); // B's revoke_and_ack reaches A
				expect(blocked(t)).to.deep.equal({ A: null, B: null });
				expect(t.errors, t.errors.join('; ')).to.have.length(0);
			});
		}

		it("refuses the non-opener's update_fee with the channel's code", function () {
			const t = makeFundedPair('fee-non-opener');
			const r = t.B().updateChannelFee(t.channelId, 600);
			expect(r.ok).to.equal(false);
			expect(r.error).to.equal('Only opener can update fee');
			expect(r.code).to.equal(ChannelErrorCode.NOT_PERMITTED);
		});

		it('an update_fee: every step of its round, including the signature the peer still owes at the new rate', function () {
			const t = makeFundedPair('predicate-fee');
			t.wire.manual(true);
			expect(t.A().updateChannelFee(t.channelId, 600).ok).to.equal(true);
			// A staged it and signed; B has seen nothing.
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: null });
			expect(t.wire.step('A')).to.equal('UPDATE_FEE');
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: UPDATES });
			expect(t.wire.step('A')).to.equal(SIG);
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: UPDATES });
			expect(t.wire.step('B')).to.equal(RAA);
			// A's rate is promoted and nothing is staged any more, but the
			// commitment A holds is still signed at the old rate.
			const a = t.aChannel().getFullState();
			expect(a.pendingFeeratePerKw).to.equal(undefined);
			expect(a.localConfig.feeratePerKw).to.equal(600);
			expect(a.lastSignedCommitFeeratePerKw).to.not.equal(600);
			expect(t.aChannel().isAwaitingRemoteRevocation()).to.equal(false);
			expect(t.aChannel().needsCommitment()).to.equal(false);
			expect(blocked(t)).to.deep.equal({ A: UPDATES, B: UPDATES });
			expect(t.wire.step('B')).to.equal(SIG);
			expect(a.lastSignedCommitFeeratePerKw).to.equal(600);
			expect(blocked(t)).to.deep.equal({ A: null, B: UPDATES });
			expect(t.wire.step('A')).to.equal(RAA);
			expect(blocked(t)).to.deep.equal({ A: null, B: null });
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
		});

		it('each kind of pending update blocks on its own', function () {
			const t = makeFundedPair('predicate-each');
			const c = t.aChannel();
			const state = writableState(c);
			expect(c.closingBlockedBy()).to.equal(null);
			/** Set one thing, read the gate, put it back. */
			const withOnly = (set: () => void, undo: () => void): string | null => {
				set();
				const got = c.closingBlockedBy();
				undo();
				expect(c.closingBlockedBy(), 'restored').to.equal(null);
				return got;
			};
			const kept = { ...offerEntry(), state: HtlcState.FULFILLED };
			expect(
				withOnly(
					() => (state.signedLocalRemovals = [kept]),
					() => (state.signedLocalRemovals = undefined)
				),
				'a kept removal'
			).to.equal(HTLCS);
			expect(
				withOnly(
					() => (state.needsCommitment = true),
					() => (state.needsCommitment = false)
				),
				'a signature we owe (the stale flag of #1305 included)'
			).to.equal(UPDATES);
			const revoked = state.remoteRevocationNumber;
			expect(
				withOnly(
					() => (state.remoteCommitmentNumber += 1n),
					() => (state.remoteCommitmentNumber -= 1n)
				),
				'a commitment of ours the peer has not revoked for'
			).to.equal(UPDATES);
			expect(state.remoteRevocationNumber).to.equal(revoked);
			expect(
				withOnly(
					() =>
						state.pendingLocalUpdates.push({
							type: MessageType.UPDATE_FEE,
							payload: Buffer.alloc(0)
						}),
					() => state.pendingLocalUpdates.pop()
				),
				'an update the peer has not acknowledged'
			).to.equal(UPDATES);
			// A staged update_fee on a row that predates the signed-rate record.
			const signedRate = state.lastSignedCommitFeeratePerKw;
			expect(signedRate).to.equal(state.localConfig.feeratePerKw);
			expect(
				withOnly(
					() => {
						state.lastSignedCommitFeeratePerKw = undefined;
						state.pendingFeeratePerKw = 600;
					},
					() => {
						state.lastSignedCommitFeeratePerKw = signedRate;
						state.pendingFeeratePerKw = undefined;
					}
				),
				'a staged update_fee'
			).to.equal(UPDATES);
			expect(
				withOnly(
					() => (state.lastSignedCommitFeeratePerKw = signedRate! + 1),
					() => (state.lastSignedCommitFeeratePerKw = signedRate)
				),
				'a commitment still signed at the previous feerate'
			).to.equal(UPDATES);
			expect(
				withOnly(
					() => (state.pendingLeaseBlockheight = 100),
					() => (state.pendingLeaseBlockheight = undefined)
				),
				'a staged update_blockheight'
			).to.equal(UPDATES);
			const signedHeight = state.lastSignedCommitLeaseBlockheight;
			expect(
				withOnly(
					() => (state.lastSignedCommitLeaseBlockheight = 100),
					() => (state.lastSignedCommitLeaseBlockheight = signedHeight)
				),
				'a commitment still signed at the previous lease blockheight'
			).to.equal(UPDATES);
		});

		for (const flavor of ['legacy', 'simple'] as Flavor[]) {
			it(`${flavor}: every signing stage refuses while a removal is in flight, at each step of it`, function () {
				const sign = (): Buffer => {
					throw new Error('a closing signature was asked for');
				};
				const problems: string[] = [];
				for (let k = 0; k <= 4; k++) {
					const t = makeFundedPair(`stages-${flavor}-${k}`, flavor);
					const h = offer(t, 'A', HTLC_MSAT);
					t.wire.manual(true);
					remove(t, h, 'fulfil');
					deliverRound(t, removalRound(h, 'fulfil'), k);
					shutdown(t, 'A');
					shutdown(t, 'B');
					// Each side has the other's shutdown; the round is where it was.
					for (const side of ['A', 'B'] as Side[]) {
						const queued = t.wire.pendingTypes(side);
						expect(queued[queued.length - 1]).to.equal(SHUTDOWN);
						const c = chanOf(t, side);
						writableState(c).remoteShutdownScript = scriptOf(other(side));
					}
					for (const side of ['A', 'B'] as Side[]) {
						const c = chanOf(t, side);
						const blockedBy = c.closingBlockedBy();
						// After four deliveries B has sent the last message of the
						// round and is empty; every other (side, step) is not.
						if (blockedBy === null) {
							if (!(side === 'B' && k === 4)) {
								problems.push(`[${k}] ${side} reads as empty`);
							}
							continue;
						}
						const before = c.getState();
						const id = t.channelId;
						const scripts = {
							closerScriptPubkey: scriptOf(other(side)),
							closeeScriptPubkey: scriptOf(side)
						};
						type Stage = () => Array<{ type: string }>;
						const stages: Array<[string, Stage]> = [
							[
								'proposeClosingFee',
								(): ReturnType<Stage> => c.proposeClosingFee(sign)
							],
							[
								'handleClosingSigned',
								(): ReturnType<Stage> =>
									c.handleClosingSigned(
										{
											channelId: id,
											feeSatoshis: 171n,
											signature: Buffer.alloc(64)
										},
										sign,
										(): boolean => true
									)
							],
							[
								'sendClosingComplete',
								(): ReturnType<Stage> => c.sendClosingComplete(171n, 0, sign)
							],
							[
								'handleClosingComplete',
								(): ReturnType<Stage> =>
									c.handleClosingComplete(
										{
											channelId: id,
											...scripts,
											feeSatoshis: 171n,
											locktime: 0,
											closerAndCloseeSig: Buffer.alloc(64)
										},
										(): boolean => true,
										sign
									)
							],
							[
								'handleClosingSig',
								(): ReturnType<Stage> => {
									// Only NEGOTIATING_CLOSING reaches this stage, and
									// nothing enters a channel there, so it takes a row
									// from before the gate to arrive with an entry.
									const state = writableState(c);
									state.state = ChannelState.NEGOTIATING_CLOSING;
									try {
										return c.handleClosingSig(
											{
												channelId: id,
												closerScriptPubkey: scriptOf(side),
												closeeScriptPubkey: scriptOf(other(side)),
												feeSatoshis: 171n,
												locktime: 0,
												closerAndCloseeSig: Buffer.alloc(64)
											},
											(): boolean => true
										);
									} finally {
										state.state = before;
									}
								}
							]
						];
						for (const [name, run] of stages) {
							let outcome: string;
							try {
								const actions = run();
								const error = actions.find(
									(a) => a.type === ChannelActionType.ERROR
								) as { message: string } | undefined;
								outcome =
									actions.length === 1 && error
										? error.message
										: `actions ${actions.map((a) => a.type).join(',')}`;
							} catch (err) {
								outcome = (err as Error).message;
							}
							const expected = new RegExp(`: ${blockedBy}$`);
							if (!expected.test(outcome) || c.getState() !== before) {
								problems.push(
									`[${k}] ${side} ${name} with ${blockedBy}: ${outcome}; state ${before} -> ${c.getState()}`
								);
							}
						}
					}
				}
				expectNoProblems(problems);
			});
		}

		it('beginClosingNegotiationIfReady moves only an empty SHUTTING_DOWN channel that has the peer shutdown', function () {
			const t = makeFundedPair('predicate-begin');
			// NORMAL: not its business.
			expect(t.aChannel().beginClosingNegotiationIfReady()).to.equal(false);
			expect(t.aChannel().getState()).to.equal(ChannelState.NORMAL);
			t.wire.manual(true);
			shutdown(t, 'A');
			// Empty, but the peer has not answered.
			expect(t.aChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			expect(t.aChannel().closingBlockedBy()).to.equal(null);
			expect(t.aChannel().beginClosingNegotiationIfReady()).to.equal(false);
			expect(t.aChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			t.wire.drain(ALTERNATING.make());
			expectNoProblems(problemsOf(t, START));
			// CLOSED: not its business either.
			expect(t.aChannel().beginClosingNegotiationIfReady()).to.equal(false);
			expect(t.aChannel().getState()).to.equal(ChannelState.CLOSED);
		});
	});
});
