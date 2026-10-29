/**
 * PR #1306 review regressions, section 8, removals beside a shutdown.
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	sha256,
	FUNDING_SATOSHIS,
	IPair,
	FULFILL,
	SIG,
	IPayment,
	offer,
	settle,
	makeFundedPair,
	expectLevel
} from './helpers/replay-order-review';

describe('reestablish replay order: review targeted regressions', function () {
	this.timeout(300_000);

	describe('8. shutdown: removals in flight beside a shutdown', function () {
		const B_SCRIPT = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			sha256(Buffer.from('shutdown-script-b')).subarray(0, 20)
		]);
		const A_SCRIPT = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			sha256(Buffer.from('shutdown-script-a')).subarray(0, 20)
		]);
		const shuttingDown = (
			tag: string,
			htlcs: number
		): { t: IPair; hs: IPayment[] } => {
			const t = makeFundedPair(tag);
			const hs: IPayment[] = [];
			for (let i = 0; i < htlcs; i++) {
				hs.push(offer(t, 'A', BigInt(4_000_000 + i * 1_000_000)));
			}
			expectLevel(t);
			expect(t.B().initiateShutdown(t.channelId, B_SCRIPT).ok).to.equal(true);
			expect(t.aChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			expect(t.bChannel().getState()).to.equal(ChannelState.SHUTTING_DOWN);
			return { t, hs };
		};
		/**
		 * No transaction either side broadcasts may leave an HTLC's value out
		 * of every output. The closing fee here is under 200 sat; the HTLCs
		 * are 4000 sat and more.
		 */
		const expectNothingBurned = (t: IPair): void => {
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(t.broadcasts.A.length + t.broadcasts.B.length).to.be.greaterThan(
				0
			);
			expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
			for (const raw of [...t.broadcasts.A, ...t.broadcasts.B]) {
				const tx = bitcoin.Transaction.fromBuffer(raw);
				const paid = tx.outs.reduce((sum, o) => sum + BigInt(o.value), 0n);
				expect(
					FUNDING_SATOSHIS - paid < 1_000n,
					`a broadcast transaction pays out ${paid} of ${FUNDING_SATOSHIS} sat: ${
						FUNDING_SATOSHIS - paid
					} sat left to fees while ${
						t.bChannel().getFullState().htlcs.size
					} fulfilled HTLC(s) sit unresolved`
				).to.equal(true);
			}
		};

		it('a lost fulfil and covering signature finish before the retransmitted shutdown closes', function () {
			const { t, hs } = shuttingDown('shutdown-covered', 1);
			t.wire.cut();
			settle(t, 'B', hs[0]);
			t.wire.reconnect();
			expect(t.wire.replay.B).to.deep.equal([FULFILL, SIG, 'SHUTDOWN']);
			// A holds the preimage either way.
			expect(t.fulfilled.A).to.have.length(1);
			expectNothingBurned(t);
		});

		it('two lost fulfils with a signature between them finish before cooperative close', function () {
			const { t, hs } = shuttingDown('shutdown-later', 2);
			t.wire.cut();
			settle(t, 'B', hs[0]);
			settle(t, 'B', hs[1]);
			t.wire.reconnect();
			expectNothingBurned(t);
		});

		it('a shutdown crossing an in-flight fulfil preserves its value in cooperative close', function () {
			const t = makeFundedPair('shutdown-live-race');
			const h = offer(t, 'A', 4_000_000n);
			expectLevel(t);
			t.wire.manual(true);
			settle(t, 'B', h);
			expect(t.wire.pendingTypes('B')).to.deep.equal([FULFILL, SIG]);
			expect(t.A().initiateShutdown(t.channelId, A_SCRIPT).ok).to.equal(true);
			// A's shutdown reaches B while B's fulfil is still on the wire.
			expect(t.wire.step('A')).to.equal(true);
			t.wire.manual(false);
			expect(t.fulfilled.A).to.have.length(1);
			expectNothingBurned(t);
		});
	});
});
