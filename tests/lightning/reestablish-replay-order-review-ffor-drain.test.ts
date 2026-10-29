/**
 * PR #1306 review regressions, section 7, the FFOR drain hold.
 * The suite is split by section and seed range so that no one mocha file
 * holds it; the harness is helpers/replay-order-review.ts.
 */

import { expect } from 'chai';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { FforState, IFforEpochRecord } from '../../src/lightning/ffor/types';
import {
	sha256,
	IPair,
	makePair,
	ONION,
	FULFILL,
	FAIL,
	SIG,
	RAA,
	queueOf,
	expectLevel
} from './helpers/replay-order-review';

describe('reestablish replay order: review targeted regressions', function () {
	this.timeout(300_000);

	describe('7. FFOR drain (section 7.5.5 hold)', function () {
		const TIP = 795_000;
		const AMOUNTS = [994_000n, 546_250n, 49_749_000n];
		const record = (c: Channel): IFforEpochRecord => {
			const f = c.getFforEpoch();
			expect(f, 'epoch record').to.not.equal(null);
			return f!;
		};

		/** As the author's helper: R's drain cut in two, none of it delivered. */
		const drainInTwoHalves = (tag: string): IPair => {
			const t = makePair(tag);
			t.A().handleNewBlock(TIP);
			t.B().handleNewBlock(TIP);
			const started = t.B().initiateFforEpoch(t.channelId, {
				voucherAmountsMsat: AMOUNTS,
				minPaymentMsat: 400_000n,
				settlementDeadline: 798_992,
				voucherExpiry: 800_000,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 5000
			});
			expect(started.ok, started.error).to.equal(true);
			expect(record(t.aChannel()).state).to.equal(FforState.ACTIVE);
			expect(record(t.bChannel()).state).to.equal(FforState.ACTIVE);

			const r = t.bChannel();
			const vouchers = [...r.getFullState().htlcs.values()]
				.filter((h) => h.fforVoucher === true)
				.sort((x, y) => Number(x.id - y.id));
			expect(vouchers).to.have.length(AMOUNTS.length);
			const last = vouchers[vouchers.length - 1];
			const failHtlc = r.failHtlc.bind(r);
			let holdBack = true;
			r.failHtlc = ((id: bigint, ...rest: unknown[]) =>
				holdBack && id === last.id
					? [
							{
								type: ChannelActionType.ERROR,
								message: 'held back by the test'
							}
					  ]
					: (failHtlc as (...a: unknown[]) => unknown)(
							id,
							...rest
					  )) as typeof r.failHtlc;

			t.wire.dropWhen(
				(from, type) =>
					from === 'B' &&
					(type === MessageType.UPDATE_FULFILL_HTLC ||
						type === MessageType.UPDATE_FAIL_HTLC ||
						type === MessageType.COMMITMENT_SIGNED)
			);
			expect(t.B().closeFforEpoch(t.channelId).ok).to.equal(true);
			expect(record(t.aChannel()).state).to.equal(FforState.DRAINING);
			expect(record(r).state).to.equal(FforState.DRAINING);
			expect(queueOf(r)).to.deep.equal({ types: [FAIL, FAIL], signed: 2 });

			holdBack = false;
			const preimage = record(t.aChannel()).preimages[AMOUNTS.length - 1];
			expect(t.B().fforAddPreimage(t.channelId, preimage).ok).to.equal(true);
			expect(queueOf(r)).to.deep.equal({
				types: [FAIL, FAIL, FULFILL],
				signed: 2
			});
			t.wire.cut();
			return t;
		};
		const forgetClose = (t: IPair): void => {
			const s = record(t.aChannel());
			s.state = FforState.ACTIVE;
			s.closeWire = null;
			s.closeAckWire = null;
			s.settledBitmap = null;
			s.closeProcessed = false;
		};
		const expectDrained = (t: IPair): void => {
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(record(t.aChannel()).state).to.equal(FforState.CLOSED);
			expect(record(t.bChannel()).state).to.equal(FforState.CLOSED);
			expect(t.aChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getFullState().htlcs.size).to.equal(0);
			expect(t.bChannel().getBalances().localMsat).to.equal(
				AMOUNTS[AMOUNTS.length - 1]
			);
			expectLevel(t);
		};
		const drainOf = (t: IPair): string[] =>
			t.wire.delivered.filter((m) =>
				[`B:${FAIL}`, `B:${FULFILL}`, `B:${SIG}`, `B:${RAA}`].includes(m)
			);

		it('held, the connection dies before ff_close_ack returns, held again: the release keeps the order', function () {
			const t = drainInTwoHalves('ffor-hold-twice');
			forgetClose(t);
			// ff_close reaches S, whose ack is lost with the connection.
			t.wire.reconnect({ manual: true });
			expect(
				t.wire.replay.B.filter((m) => [FAIL, FULFILL, SIG, RAA].includes(m))
			).to.deep.equal([]);
			while (t.wire.step('B'));
			expect(t.wire.pendingTypes('A')).to.include('FF_CLOSE_ACK');
			t.wire.cut();
			t.wire.manual(false);
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(drainOf(t).slice(0, 4)).to.deep.equal([
				`B:${FAIL}`,
				`B:${FAIL}`,
				`B:${SIG}`,
				`B:${FULFILL}`
			]);
			expectDrained(t);
		});

		it('held after R restarts from its row: the release keeps the order', function () {
			const t = drainInTwoHalves('ffor-hold-restart');
			forgetClose(t);
			t.wire.restartB();
			t.wire.reconnect();
			expect(t.errors, t.errors.join('; ')).to.have.length(0);
			expect(
				t.wire.replay.B.filter((m) => [FAIL, FULFILL, SIG, RAA].includes(m))
			).to.deep.equal([]);
			expect(drainOf(t).slice(0, 4)).to.deep.equal([
				`B:${FAIL}`,
				`B:${FAIL}`,
				`B:${SIG}`,
				`B:${FULFILL}`
			]);
			expectDrained(t);
		});

		it('in DRAINING nothing but the drain can enter the queue, so no update outside the held set can overtake a held signature', function () {
			const t = drainInTwoHalves('ffor-queue-types');
			const r = t.bChannel();
			const before = queueOf(r).types.length;
			expect(
				r
					.addHtlc(1_000_000n, sha256(t.nextPreimage()), 900, ONION)
					.some((a) => a.type === ChannelActionType.ERROR)
			).to.equal(true);
			const voucher = [...r.getFullState().htlcs.values()].find(
				(h) => h.fforVoucher === true
			);
			if (voucher) {
				expect(
					r
						.failMalformedHtlc(voucher.id, sha256(ONION), 0xc005)
						.some((a) => a.type === ChannelActionType.ERROR)
				).to.equal(true);
			}
			expect(queueOf(r).types.length).to.equal(before);
			expect(
				queueOf(r).types.every((m) => m === FAIL || m === FULFILL)
			).to.equal(true);
		});
	});
});
