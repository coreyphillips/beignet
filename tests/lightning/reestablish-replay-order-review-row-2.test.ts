/**
 * PR #1306 review regressions, section 1, row seeds (part 2 of 3).
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

const dump = collectDump('row-2');

describe('reestablish replay order: review recovery regressions', function () {
	this.timeout(900_000);

	describe('1. seeded flows converge', function () {
		it('the same with restarts from the last persisted row (part 2 of 3)', function () {
			const { from, count } = seedRange(
				10_001,
				seedsOf('REPLAY_ORDER_SEEDS', 120),
				2,
				3
			);
			// REPLAY_ORDER_SEEDS below the part count leaves this part no seeds.
			if (count === 0) this.skip();
			const r = runSeeds('row', from, count, { rowRestarts: true }, dump);
			expect(r.failures.length, describeFailures(r.failures)).to.equal(0);
		});
	});
});
