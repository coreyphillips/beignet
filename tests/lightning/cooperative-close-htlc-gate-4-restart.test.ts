/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 4: a restart from the persisted row with a removal in flight, and a
 * row written by the old close path.
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import { ChannelState } from '../../src/lightning/channel/types';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import { writableState } from './helpers/writable-state';
import {
	Flavor,
	FLAVORS,
	HTLC_MSAT,
	Side,
	other,
	ALTERNATING,
	FULL,
	EVERY_BOUNDARY,
	fewBoundariesFor,
	Removal,
	REMOVALS,
	chanOf,
	offer,
	remove,
	shutdown,
	makeFundedPair,
	after,
	START,
	problemsOf,
	expectNoProblems,
	removalRound,
	deliverRound,
	who,
	shuttingDownWithHtlc
} from './helpers/cooperative-close-htlc-gate';

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

	// ───────────── 4. restart in SHUTTING_DOWN with a removal in flight ─────────────

	describe('4. a restart in SHUTTING_DOWN with a removal in flight', function () {
		/**
		 * As section 3, but one side comes back from the last row its manager
		 * asked to persist (serialize, deserialize, a fresh manager). The
		 * side that only answered the shutdown has not necessarily persisted
		 * since, so its row can still say NORMAL: the peer's retransmitted
		 * shutdown brings it back.
		 */
		const restarted = (
			flavor: Flavor,
			kind: Removal,
			offerer: Side,
			side: Side,
			k: number
		): string[] => {
			const tag = `restart-${flavor}-${kind}-${offerer}-${side}-${k}`;
			const { t, h } = shuttingDownWithHtlc(tag, flavor, offerer, other(side));
			t.wire.manual(true);
			remove(t, h, kind);
			deliverRound(t, removalRound(h, kind), k);
			t.wire.restart(side, true);
			const label = (p: string): string =>
				`[${k} of 5 delivered, ${side} restarts] ${p}`;
			t.wire.reconnect(true);
			t.wire.drain(ALTERNATING.make());
			return problemsOf(t, after(START, h, kind), { reconnected: true }).map(
				label
			);
		};

		for (const flavor of FLAVORS) {
			for (const kind of flavor === 'legacy'
				? REMOVALS
				: (['fulfil'] as Removal[])) {
				for (const offerer of ['A', 'B'] as Side[]) {
					it(`${flavor}: ${kind} of an HTLC offered by ${who(
						offerer
					)}, either side restarting at the boundaries of the round`, function () {
						const problems: string[] = [];
						for (const side of ['A', 'B'] as Side[]) {
							for (const k of fewBoundariesFor(flavor)) {
								problems.push(...restarted(flavor, kind, offerer, side, k));
							}
						}
						expectNoProblems(problems);
					});
				}
			}
		}

		it('a shutdown that crossed the removal, then a restart of either side from its row', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const side of ['A', 'B'] as Side[]) {
					for (const k of FULL ? EVERY_BOUNDARY : [0, 3]) {
						const tag = `restart-cross-${flavor}-${side}-${k}`;
						const t = makeFundedPair(tag, flavor);
						const h = offer(t, 'A', HTLC_MSAT);
						t.wire.manual(true);
						remove(t, h, 'fulfil');
						deliverRound(t, removalRound(h, 'fulfil'), k);
						shutdown(t, 'A');
						// A's shutdown and whatever it queued behind arrive; B's
						// answers are lost with the restart.
						while (t.wire.step('A') !== null);
						t.wire.restart(side, true);
						t.wire.reconnect(true);
						t.wire.drain(ALTERNATING.make());
						problems.push(
							...problemsOf(t, after(START, h, 'fulfil'), {
								reconnected: true
							}).map(
								(p) => `[${flavor}, ${k} of 5 delivered, ${side} restarts] ${p}`
							)
						);
					}
				}
			}
			expectNoProblems(problems);
		});

		it('a row written before this gate existed: NEGOTIATING_CLOSING with the removal still in flight goes back to SHUTTING_DOWN and finishes it', function () {
			const problems: string[] = [];
			for (const flavor of FLAVORS) {
				for (const k of FULL ? [0, 1, 2, 3, 4] : [1, 3]) {
					const tag = `old-row-${flavor}-${k}`;
					const { t, h } = shuttingDownWithHtlc(tag, flavor, 'A', 'A');
					t.wire.manual(true);
					remove(t, h, 'fulfil');
					deliverRound(t, removalRound(h, 'fulfil'), k);
					// What the old close path had persisted by now: the shutdown
					// exchange saw no PENDING or COMMITTED entry and moved on.
					for (const side of ['A', 'B'] as Side[]) {
						const state = writableState(chanOf(t, side));
						state.state = ChannelState.NEGOTIATING_CLOSING;
						t.wire.rows[side] = JSON.stringify(serializeChannelState(state));
					}
					t.wire.restart('A', true);
					t.wire.restart('B', true);
					t.wire.reconnect(true);
					for (const side of ['A', 'B'] as Side[]) {
						const c = chanOf(t, side);
						if (
							c.closingBlockedBy() !== null &&
							c.getState() !== ChannelState.SHUTTING_DOWN
						) {
							problems.push(
								`[${flavor}, ${k} of 5 delivered] ${side} resumed in ${c.getState()} with ${c.closingBlockedBy()}`
							);
						}
					}
					t.wire.drain(ALTERNATING.make());
					problems.push(
						...problemsOf(t, after(START, h, 'fulfil'), {
							reconnected: true
						}).map((p) => `[${flavor}, ${k} of 5 delivered] ${p}`)
					);
				}
			}
			expectNoProblems(problems);
		});
	});
});
