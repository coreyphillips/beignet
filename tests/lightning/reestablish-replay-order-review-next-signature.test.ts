/**
 * PR #1306 review regressions, section 10, the next signature.
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import {
	ADD,
	FULFILL,
	SIG,
	RAA,
	offer,
	settle,
	makeFundedPair,
	queueOf,
	expectLevel,
	expectStillUsable
} from './helpers/replay-order-review';

describe('reestablish replay order: review targeted regressions', function () {
	this.timeout(300_000);

	describe('10. the signature that follows the retransmitted one', function () {
		it('covers exactly the later updates, and the peer revoke_and_ack for it empties the queue', function () {
			const t = makeFundedPair('next-sig');
			const inbound = offer(t, 'B', 2_000_000n);
			expectLevel(t);
			t.wire.cut();
			const covered = offer(t, 'A', 1_000_000n);
			const later = offer(t, 'A', 1_500_000n);
			settle(t, 'A', inbound);
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, ADD, FULFILL],
				signed: 1
			});

			t.wire.reconnect({ manual: true });
			expect(t.wire.replay.A).to.deep.equal([ADD, SIG, ADD, FULFILL]);
			for (let i = 0; i < 4; i++) expect(t.wire.step('A')).to.equal(true);
			// Nothing more leaves A until the peer revokes.
			expect(t.wire.pendingTypes('A')).to.deep.equal([]);
			expect(t.aChannel().needsCommitment()).to.equal(true);
			expect(t.wire.pendingTypes('B')).to.deep.equal([RAA, SIG]);
			expect(t.wire.step('B')).to.equal(true);
			// The covered add is acknowledged; the next signature is out and
			// covers the two later updates, no more and no less.
			expect(queueOf(t.aChannel())).to.deep.equal({
				types: [ADD, FULFILL],
				signed: 2
			});
			expect(t.wire.pendingTypes('A')).to.deep.equal([SIG]);
			expect(t.aChannel().needsCommitment()).to.equal(false);
			t.wire.manual(false);
			expectLevel(t);
			expect(t.fulfilled.B).to.have.length(1);
			settle(t, 'B', covered);
			settle(t, 'B', later);
			expectLevel(t);
			expect(t.fulfilled.A).to.have.length(2);
			expectStillUsable(t);
		});
	});
});
