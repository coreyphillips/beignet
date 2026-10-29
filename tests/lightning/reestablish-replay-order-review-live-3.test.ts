/**
 * PR #1306 review regressions, section 1, live seeds (part 3 of 3).
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import {
	collectDump,
	seedsOf,
	seedRange,
	runSeeds,
	describeFailures
} from './helpers/replay-order-review';

const dump = collectDump('live-3');

describe('reestablish replay order: review recovery regressions', function () {
	this.timeout(900_000);

	describe('1. seeded flows converge', function () {
		it('random traffic, cuts, live restarts and partial replays (part 3 of 3)', function () {
			const { from, count } = seedRange(
				1,
				seedsOf('REPLAY_ORDER_SEEDS', 120),
				3,
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
