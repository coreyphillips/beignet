/**
 * The settlement peer's opt-in (issue #729): a node whose host did not opt
 * in refuses every ff_init with a signed abort; one that opted in refuses a
 * book above its budget, an epoch longer than it offers, or fee terms
 * below its floor, and accepts within them. The library default (no
 * policy) answers on any terms inside the voucher horizon, which binds
 * every S (issue #1019).
 */

import { expect } from 'chai';
import { Channel } from '../../src/lightning/channel/channel';
import {
	FforAbortReason,
	FforState,
	IFforSettlePolicy
} from '../../src/lightning/ffor/types';
import {
	AMOUNTS,
	D_DEADLINE,
	FEE_BASE,
	FEE_PPM,
	TIP,
	T_EXP,
	createWorld,
	record
} from './helpers/ffor-world';

function start(
	w: ReturnType<typeof createWorld>,
	overrides: Partial<{
		feeBaseMsat: number;
		feeProportionalMillionths: number;
		voucherExpiry: number;
	}> = {}
): { ok: boolean; error?: string } {
	return w.r.startFforEpoch(w.srHex, {
		voucherAmountsMsat: AMOUNTS,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: FEE_BASE,
		feeProportionalMillionths: FEE_PPM,
		...overrides
	});
}

describe('FFOR settlement peer opt-in (issue #729)', function () {
	this.timeout(30_000);

	it('a peer that did not opt in refuses every ff_init with a signed abort', () => {
		const w = createWorld({ sExtra: { fforSettle: { enabled: false } } });
		expect(start(w).ok).to.equal(true);
		expect(record(w.r, w.srHex).state).to.equal(FforState.ABORTED);
		expect(record(w.r, w.srHex).abortReason).to.equal(
			FforAbortReason.TERMS_REFUSED
		);
		expect(w.s.getFforEpoch(w.srHex)).to.equal(null);
	});

	it('an opted-in peer enforces its budget, epoch length and fee floors', () => {
		const budget = AMOUNTS.reduce((a, b) => a + b, 0n);
		const tooSmall = createWorld({
			sExtra: { fforSettle: { enabled: true, maxBudgetMsat: budget - 1n } }
		});
		expect(start(tooSmall).ok).to.equal(true);
		expect(record(tooSmall.r, tooSmall.srHex).state).to.equal(
			FforState.ABORTED
		);

		const tooLong = createWorld({
			sExtra: { fforSettle: { enabled: true, maxEpochBlocks: 100 } }
		});
		expect(start(tooLong).ok).to.equal(true);
		expect(record(tooLong.r, tooLong.srHex).state).to.equal(FforState.ABORTED);

		const floor = createWorld({
			sExtra: { fforSettle: { enabled: true, minFeeBaseMsat: FEE_BASE + 1 } }
		});
		expect(start(floor).ok).to.equal(true);
		expect(record(floor.r, floor.srHex).state).to.equal(FforState.ABORTED);

		const fine = createWorld({
			sExtra: {
				fforSettle: {
					enabled: true,
					maxBudgetMsat: budget,
					maxEpochBlocks: T_EXP - TIP,
					minFeeBaseMsat: FEE_BASE,
					minFeeProportionalMillionths: FEE_PPM
				}
			}
		});
		expect(start(fine).ok).to.equal(true);
		expect(record(fine.s, fine.srHex).state).to.equal(FforState.ACTIVE);
		expect(record(fine.r, fine.srHex).state).to.equal(FforState.ACTIVE);
	});

	it('every S refuses an epoch past the voucher horizon, whatever its policy (issue #1019)', () => {
		const horizon = TIP + Channel.MAX_HTLC_CLTV_EXPIRY_DELTA;
		const cases: Array<{
			label: string;
			settle?: IFforSettlePolicy;
			voucherExpiry: number;
		}> = [
			{ label: 'no policy', voucherExpiry: 0xfffffffe },
			{
				label: 'the documented opt-in',
				settle: { enabled: true },
				voucherExpiry: horizon + 1
			},
			{
				label: 'a longer maxEpochBlocks',
				settle: { enabled: true, maxEpochBlocks: 0xffffffff },
				voucherExpiry: horizon + 1
			}
		];
		for (const c of cases) {
			const w = createWorld(
				c.settle ? { sExtra: { fforSettle: c.settle } } : {}
			);
			expect(start(w, { voucherExpiry: c.voucherExpiry }).ok).to.equal(true);
			expect(record(w.r, w.srHex).state, c.label).to.equal(FforState.ABORTED);
			expect(record(w.r, w.srHex).abortReason, c.label).to.equal(
				FforAbortReason.TERMS_REFUSED
			);
			expect(w.s.getFforEpoch(w.srHex), c.label).to.equal(null);
			const sChannel = w.s.getChannelManager().getChannel(w.srChannelId)!;
			expect(sChannel.getFullState().htlcs.size, c.label).to.equal(0);
			expect(w.errors.s.join('\n'), c.label).to.include('voucher horizon');
		}

		const edge = createWorld({ sExtra: { fforSettle: { enabled: true } } });
		expect(start(edge, { voucherExpiry: horizon }).ok).to.equal(true);
		expect(record(edge.s, edge.srHex).state).to.equal(FforState.ACTIVE);
	});
});
