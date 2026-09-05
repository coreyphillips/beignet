/**
 * The settlement peer's opt-in (issue #729): a node whose host did not opt
 * in refuses every ff_init with a signed abort; one that opted in refuses a
 * book above its budget, an epoch longer than it offers, or fee terms
 * below its floor, and accepts within them. The library default (no
 * policy) answers on any terms, so every existing suite is unchanged.
 */

import { expect } from 'chai';
import { FforAbortReason, FforState } from '../../src/lightning/ffor/types';
import {
	AMOUNTS,
	D_DEADLINE,
	FEE_BASE,
	FEE_PPM,
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
					maxEpochBlocks: T_EXP - 790_000,
					minFeeBaseMsat: FEE_BASE,
					minFeeProportionalMillionths: FEE_PPM
				}
			}
		});
		expect(start(fine).ok).to.equal(true);
		expect(record(fine.s, fine.srHex).state).to.equal(FforState.ACTIVE);
		expect(record(fine.r, fine.srHex).state).to.equal(FforState.ACTIVE);
	});
});
