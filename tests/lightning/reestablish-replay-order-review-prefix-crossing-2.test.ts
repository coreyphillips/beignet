/**
 * PR #1306 review regressions, section 2, every delivered prefix (crossing,
 * part 2 of 2: B's message delivered first).
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import {
	collectDump,
	everyPrefix,
	shapesFor
} from './helpers/replay-order-review';

const { prefixStats } = collectDump('prefix-crossing-2');

describe('reestablish replay order: review recovery regressions', function () {
	this.timeout(900_000);

	describe('2. every delivered prefix of a round, peer revoke_and_ack delivered or lost', function () {
		for (const shape of shapesFor('prefix-crossing')) {
			it(`${shape.tag}: every schedule up to six deliveries converges (part 2 of 2)`, function () {
				const r = everyPrefix(shape, 6, false, 'B');
				prefixStats[shape.tag] = {
					schedules: r.schedules,
					retransmits: r.retransmits,
					affected: r.affected,
					failures: r.failures.length
				};
				expect(r.schedules).to.be.greaterThan(3);
				expect(
					r.retransmits,
					'schedules with a retransmitted signature'
				).to.be.greaterThan(0);
				expect(r.failures, r.failures.join('\n')).to.have.length(0);
			});
		}
	});
});
