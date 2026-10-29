/**
 * PR #1306 review regressions, section 1, live seeds (part 1 of 3).
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import {
	runFlow,
	collectDump,
	seedsOf,
	seedRange,
	runSeeds,
	describeFailures
} from './helpers/replay-order-review';

const dump = collectDump('live-1');

describe('reestablish replay order: review recovery regressions', function () {
	this.timeout(900_000);

	if (process.env.REPLAY_ORDER_DEBUG) {
		// REPLAY_ORDER_DEBUG=<seed> [REPLAY_ORDER_DEBUG_MODE=row|taproot]
		// with --grep "debug one seed" prints one flow's script and outcome.
		it('debug one seed', function () {
			const mode = process.env.REPLAY_ORDER_DEBUG_MODE;
			const r = runFlow(Number(process.env.REPLAY_ORDER_DEBUG), {
				rowRestarts: mode === 'row',
				taproot: mode === 'taproot',
				...(mode === 'taproot' ? { fee: false } : {})
			});
			// eslint-disable-next-line no-console
			console.log(r.failure, '\n', r.script.join(' '));
		});
	}

	describe('1. seeded flows converge', function () {
		it('random traffic, cuts, live restarts and partial replays (part 1 of 3)', function () {
			const { from, count } = seedRange(
				1,
				seedsOf('REPLAY_ORDER_SEEDS', 120),
				1,
				3
			);
			// REPLAY_ORDER_SEEDS below the part count leaves this part no seeds.
			if (count === 0) this.skip();
			const r = runSeeds('live', from, count, {}, dump);
			// The flows must actually reach the code under review.
			expect(
				r.affected,
				'flows with a later update behind a signature'
			).to.be.greaterThan(count / 20);
			expect(r.failures.length, describeFailures(r.failures)).to.equal(0);
		});
	});
});
