/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 1, simple: a shutdown crossing a fulfil or a fail at each boundary of
 * its round. The other two flavors have sibling files of their own.
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import {
	Flavor,
	Side,
	policiesFor,
	boundariesFor,
	REMOVALS,
	expectNoProblems,
	INITIATORS,
	who,
	initiatorName,
	crossing
} from './helpers/cooperative-close-htlc-gate';

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

	// ───────────── 1. shutdown crossing a removal in flight ─────────────

	describe('1. a shutdown that crosses a removal in flight', function () {
		// One flavor per file, so the section spreads over three workers.
		for (const flavor of ['simple'] as Flavor[]) {
			describe(flavor, function () {
				for (const kind of REMOVALS) {
					for (const offerer of ['A', 'B'] as Side[]) {
						for (const initiator of INITIATORS) {
							it(`${kind} of an HTLC offered by ${who(
								offerer
							)}, shutdown from ${initiatorName(
								initiator
							)}: the boundaries of the round, across delivery orders`, function () {
								const problems: string[] = [];
								for (const k of boundariesFor(flavor)) {
									for (const policy of policiesFor(flavor)) {
										problems.push(
											...crossing(flavor, kind, offerer, initiator, k, policy)
										);
									}
								}
								expectNoProblems(problems);
							});
						}
					}
				}
			});
		}
	});
});
