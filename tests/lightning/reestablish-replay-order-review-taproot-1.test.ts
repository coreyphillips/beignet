/**
 * PR #1306 review regressions, section 1, taproot seeds (part 1 of 2).
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

const dump = collectDump('taproot-1');

describe('reestablish replay order: review recovery regressions', function () {
	this.timeout(900_000);

	describe('1. seeded flows converge', function () {
		it('option_taproot (part 1 of 2)', function () {
			const { from, count } = seedRange(
				20_001,
				seedsOf('REPLAY_ORDER_TAPROOT_SEEDS', 20),
				1,
				2
			);
			// REPLAY_ORDER_SEEDS below the part count leaves this part no seeds.
			if (count === 0) this.skip();
			const r = runSeeds(
				'taproot',
				from,
				count,
				{ taproot: true, fee: false },
				dump
			);
			expect(r.failures.length, describeFailures(r.failures)).to.equal(0);
		});
	});
});
