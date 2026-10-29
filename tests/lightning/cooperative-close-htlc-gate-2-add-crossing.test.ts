/**
 * Cooperative close starts only once the channel is really empty (issue #1307),
 * section 2: a shutdown crossing an add: the add completes, the close waits,
 * then pays in full.
 *
 * The harness, what every case checks and the CLOSE_GATE_FULL and
 * CLOSE_GATE_SEEDS knobs are described in
 * tests/lightning/helpers/cooperative-close-htlc-gate.ts.
 */

import { ChannelState } from '../../src/lightning/channel/types';
import {
	sha256,
	Flavor,
	FLAVORS,
	HTLC_MSAT,
	Side,
	other,
	INamedPolicy,
	onePolicyFor,
	fewBoundariesFor,
	ONION,
	ADD,
	SIG,
	RAA,
	Removal,
	REMOVALS,
	mgr,
	offer,
	settleableId,
	remove,
	makeFundedPair,
	after,
	START,
	stateName,
	problemsOf,
	expectNoProblems,
	deliverRound,
	Initiator,
	INITIATORS,
	startShutdown,
	who,
	initiatorName
} from './helpers/cooperative-close-htlc-gate';

describe('cooperative close waits for every HTLC to be resolved (issue #1307)', function () {
	this.timeout(120_000);

	// ───────────── 2. shutdown crossing an add in flight ─────────────

	describe('2. a shutdown that crosses an add in flight', function () {
		const addRound = (from: Side): Array<{ from: Side; type: string }> => [
			{ from, type: ADD },
			{ from, type: SIG },
			{ from: other(from), type: RAA },
			{ from: other(from), type: SIG },
			{ from, type: RAA }
		];

		/**
		 * BOLT 2: no new add once shutdown is sent, but an add already sent
		 * must complete. The add leaves, `k` messages of its round are
		 * delivered, the shutdown starts. The channel has to wait in
		 * SHUTTING_DOWN with the HTLC committed on both sides, and close at
		 * full value once the HTLC is removed.
		 */
		const crossing = (
			flavor: Flavor,
			kind: Removal,
			offerer: Side,
			initiator: Initiator,
			k: number,
			policy: INamedPolicy
		): string[] => {
			const tag = `add-${flavor}-${kind}-${offerer}-${initiator}-${k}`;
			const label = (p: string): string =>
				`[${k} of 5 delivered, ${policy.name}, then ${kind}] ${p}`;
			const t = makeFundedPair(tag, flavor);
			t.wire.manual(true);
			const h = offer(t, offerer, HTLC_MSAT);
			deliverRound(t, addRound(offerer), k);
			startShutdown(t, initiator);
			t.wire.drain(policy.make());

			const early = problemsOf(t, START, { closed: false });
			const a = stateName(t.aChannel());
			const b = stateName(t.bChannel());
			if (
				a !== ChannelState.SHUTTING_DOWN ||
				b !== ChannelState.SHUTTING_DOWN
			) {
				early.push(
					`with the HTLC still live the channel must wait in SHUTTING_DOWN: A is ${a}, B is ${b}`
				);
			}
			if (settleableId(t, h) === null) {
				early.push('the add sent before the shutdown was not committed');
			}
			if (t.closingSends.length > 0) {
				early.push('a closing signature left while the HTLC was live');
			}
			if (early.length > 0) return early.map(label);

			// New adds are refused from here on.
			for (const side of ['A', 'B'] as Side[]) {
				const r = mgr(t, side).addHtlc(
					t.channelId,
					1_000_000n,
					sha256(Buffer.from(`${tag}-late-${side}`)),
					900,
					ONION
				);
				if (r.ok) early.push(`${side} could still add an HTLC after shutdown`);
			}
			t.errors.length = 0;
			if (early.length > 0) return early.map(label);

			remove(t, h, kind);
			t.wire.drain(policy.make());
			return problemsOf(t, after(START, h, kind)).map(label);
		};

		for (const flavor of FLAVORS) {
			describe(flavor, function () {
				for (const offerer of ['A', 'B'] as Side[]) {
					for (const initiator of INITIATORS) {
						it(`add from ${who(offerer)}, shutdown from ${initiatorName(
							initiator
						)}: the add completes, the close waits, then pays in full`, function () {
							const problems: string[] = [];
							// The removal that follows alternates with the boundary and
							// the delivery order, so both are covered throughout.
							for (const k of fewBoundariesFor(flavor)) {
								onePolicyFor(flavor, k).forEach((policy, i) => {
									const kind = REMOVALS[(k + i) % 2];
									problems.push(
										...crossing(flavor, kind, offerer, initiator, k, policy)
									);
								});
							}
							expectNoProblems(problems);
						});
					}
				}
			});
		}
	});
});
