/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 3: the removal round cut by a disconnect while SHUTTING_DOWN, then
 * reestablished (the reported [fulfil, signature, shutdown] replay among them).
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import { expect } from 'chai';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	Flavor,
	FLAVORS,
	Side,
	INamedPolicy,
	onePolicyFor,
	fewBoundariesFor,
	FULFILL,
	SIG,
	SHUTDOWN,
	Removal,
	REMOVALS,
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

	// ───────────── 3. the removal round is cut by a disconnect ─────────────

	describe('3. the removal round is cut while SHUTTING_DOWN, then reestablished', function () {
		it('the reported route: fulfil and its signature lost, replayed as [fulfil, signature, shutdown]', function () {
			const { t, h } = shuttingDownWithHtlc(
				'lost-reported',
				'legacy',
				'A',
				'B'
			);
			t.wire.cut();
			remove(t, h, 'fulfil');
			t.wire.reconnect();
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, SHUTDOWN]);
			// A holds the preimage either way.
			expect(t.fulfilled.A).to.have.length(1);
			expectNoProblems(
				problemsOf(t, after(START, h, 'fulfil'), { reconnected: true })
			);
		});

		for (const flavor of FLAVORS) {
			it(`PIN (same on master): ${flavor}, no HTLC at all, the connection drops during the negotiation`, function () {
				const t = makeFundedPair(`pin-reconnect-${flavor}`, flavor);
				t.wire.manual(true);
				shutdown(t, 'A');
				expect(t.wire.step('A')).to.equal(SHUTDOWN);
				expect(t.wire.step('B')).to.equal(SHUTDOWN);
				expect(t.aChannel().getState()).to.equal(
					ChannelState.NEGOTIATING_CLOSING
				);
				expect(t.bChannel().getState()).to.equal(
					ChannelState.NEGOTIATING_CLOSING
				);
				// The first closing signatures are lost with the connection.
				t.wire.cut();
				t.wire.reconnect(false);
				expectNoProblems(problemsOf(t, START, { reconnected: true }));
				expect(t.errors).to.deep.equal(
					flavor === 'legacy'
						? ['B: Unexpected closing_signed']
						: flavor === 'simple'
						? [
								'A: closing_sig without a pending closing_complete',
								'B: closing_sig without a pending closing_complete'
						  ]
						: []
				);
			});
		}

		const lost = (
			flavor: Flavor,
			kind: Removal,
			offerer: Side,
			k: number,
			policy: INamedPolicy
		): string[] => {
			const tag = `lost-${flavor}-${kind}-${offerer}-${k}`;
			const { t, h } = shuttingDownWithHtlc(tag, flavor, offerer, offerer);
			t.wire.manual(true);
			remove(t, h, kind);
			deliverRound(t, removalRound(h, kind), k);
			// Everything still on the wire is lost with the connection.
			t.wire.cut();
			t.wire.reconnect(true);
			t.wire.drain(policy.make());
			return problemsOf(t, after(START, h, kind), { reconnected: true }).map(
				(p) => `[${k} of 5 delivered before the cut, ${policy.name}] ${p}`
			);
		};

		for (const flavor of FLAVORS) {
			for (const kind of REMOVALS) {
				for (const offerer of ['A', 'B'] as Side[]) {
					it(`${flavor}: ${kind} of an HTLC offered by ${who(
						offerer
					)}, cut at the boundaries of the round`, function () {
						const problems: string[] = [];
						for (const k of fewBoundariesFor(flavor)) {
							for (const policy of onePolicyFor(flavor, k)) {
								problems.push(...lost(flavor, kind, offerer, k, policy));
							}
						}
						expectNoProblems(problems);
					});
				}
			}
		}
	});
});
