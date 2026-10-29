/**
 * PR #1306 review regressions, section 6, option_taproot prefixes.
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import {
	collectDump,
	everyPrefix,
	SHAPES
} from './helpers/replay-order-review';

const { prefixStats } = collectDump('taproot-prefix');

describe('reestablish replay order: review targeted regressions', function () {
	this.timeout(300_000);

	describe('6. option_taproot: every delivered prefix', function () {
		for (const shape of SHAPES.filter((s) =>
			['add-add', 'fulfil-fail'].includes(s.tag)
		)) {
			it(`${shape.tag}: every schedule up to five deliveries converges`, function () {
				const r = everyPrefix(shape, 5, true);
				prefixStats[`taproot-${shape.tag}`] = {
					schedules: r.schedules,
					retransmits: r.retransmits,
					affected: r.affected,
					failures: r.failures.length
				};
				expect(r.retransmits).to.be.greaterThan(0);
				expect(r.failures, r.failures.join('\n')).to.have.length(0);
			});
		}
	});
});
