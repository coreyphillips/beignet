/**
 * PR #1306 review regressions, section 5, the splice pending-lock batch.
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import {
	IPair,
	ADD,
	FULFILL,
	SIG,
	offer,
	settle,
	queueOf,
	expectLevel,
	expectStillUsable,
	makePendingLockPair,
	BATCH,
	commitmentTraffic
} from './helpers/replay-order-review';

describe('reestablish replay order: review targeted regressions', function () {
	this.timeout(300_000);

	describe('5. splice pending-lock batch', function () {
		const lockAndCheck = (t: IPair): void => {
			t.A().sendSpliceLocked(t.channelId);
			t.B().sendSpliceLocked(t.channelId);
			expectLevel(t);
			expectStillUsable(t);
		};

		it('fulfil, batch, fulfil from the non-initiator, cached batch', function () {
			const t = makePendingLockPair('splice-fulfils');
			const h1 = offer(t, 'A', 4_000_000n);
			const h2 = offer(t, 'A', 5_000_000n);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			t.wire.cut();
			settle(t, 'B', h1);
			settle(t, 'B', h2);
			expect(queueOf(t.bChannel())).to.deep.equal({
				types: [FULFILL, FULFILL],
				signed: 1
			});
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.B)).to.deep.equal([
				FULFILL,
				BATCH,
				SIG,
				SIG,
				FULFILL
			]);
			expect(t.fulfilled.A).to.have.length(2);
			lockAndCheck(t);
		});

		it('cached batch, both sides crossing: add, batch, add each way', function () {
			const t = makePendingLockPair('splice-crossing');
			t.wire.cut();
			const a1 = offer(t, 'A', 1_000_000n);
			const a2 = offer(t, 'A', 2_000_000n);
			const b1 = offer(t, 'B', 1_500_000n);
			const b2 = offer(t, 'B', 2_500_000n);
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.A)).to.deep.equal([
				ADD,
				BATCH,
				SIG,
				SIG,
				ADD
			]);
			expect(commitmentTraffic(t.wire.replay.B)).to.deep.equal([
				ADD,
				BATCH,
				SIG,
				SIG,
				ADD
			]);
			settle(t, 'B', a1);
			settle(t, 'B', a2);
			settle(t, 'A', b1);
			settle(t, 'A', b2);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			lockAndCheck(t);
		});

		it('a rebuilt batch with nothing behind it converges (same on master)', function () {
			const t = makePendingLockPair('splice-rebuilt-control');
			t.wire.cut();
			const only = offer(t, 'A', 1_000_000n);
			t.wire.restartA();
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(commitmentTraffic(t.wire.replay.A)).to.deep.equal([
				ADD,
				BATCH,
				SIG,
				SIG
			]);
			settle(t, 'B', only);
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			lockAndCheck(t);
		});
	});
});
