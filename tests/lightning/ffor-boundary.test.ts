/**
 * FFOR M6: boundary epochs (spec §8 limits + §11.4 exhaustion behavior).
 *
 * Multi-payment epochs AT the limits:
 * - exactly K payments accepted, a K+1th attempt fails cleanly upstream;
 * - budget exhausted TO THE MSAT, the next payment rejected;
 * - min_payment edge: exactly min accepted, 1 msat below rejected;
 * - voucher dust-floor edge (amount clears min but v_i lands below floor);
 * - settlement at height D-1 accepted, at D rejected (§8: height < D);
 * - upstream-expiry safety delta edge (height < expiry - delta);
 * - §11.4: every rejection fails upstream with temporary_node_failure
 *   (beignet's minimum rung; hold+wake fallback is separate machinery).
 */

import { expect } from 'chai';
import {
	createTriple,
	goOffline,
	reconnectSR,
	pay,
	FUNDING_SATOSHIS
} from './ffor-m6-harness';
import { FforEpochState } from '../../src/lightning/ffor/types';
import { FFOR_SETTLEMENT_SAFETY_DELTA } from '../../src/lightning/ffor/types';

describe('FFOR M6: boundary epochs (§8/§11.4)', function () {
	it('accepts exactly K payments; a K+1th attempt fails cleanly and the epoch still reconciles', function () {
		const t = createTriple({ prefix: 'bound-k', params: { maxPayments: 3 } });
		goOffline(t);
		pay(t, t.hashes[0], 1_000_000n);
		pay(t, t.hashes[1], 1_000_000n);
		pay(t, t.hashes[2], 1_000_000n);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(3);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(3);

		// K+1: every hash is consumed — a retry on any of them fails upstream
		// (there IS no K+1th hash; the slot budget is exactly K).
		pay(t, t.hashes[2], 1_000_000n);
		expect(t.pFailed).to.have.length(1);
		expect(t.pFulfilled).to.have.length(3);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(3);
		expect(
			t.sErrors.some((e) => e.includes('duplicate delegated payment')),
			t.sErrors.join('; ')
		).to.equal(true);

		// The boundary epoch reconciles normally.
		reconnectSR(t);
		expect(
			t.rChannel.getFforEpoch()!.state,
			t.rErrors.concat(t.sErrors).join('; ')
		).to.equal(FforEpochState.FF_CLOSED);
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok).to.equal(true);
		const vSum = 3n * (1_000_000n - 6_000n); // fee = 1000 + 0.5%
		expect(t.rChannel.getBalances().localMsat).to.equal(vSum);
	});

	it('accepts a budget exhausted TO THE MSAT; the next payment is rejected', function () {
		// fee(a) = 1000 + a * 5000 / 1e6. Choose amounts whose voucher sum hits
		// the budget EXACTLY: v = a - fee(a). For a = 10,051,000:
		// fee = 1000 + 50,255 = 51,255; v = 9,999,745.
		// Budget = v1 + v2 exactly, with two identical payments.
		const a = 10_051_000n;
		const fee = 1000n + (a * 5000n) / 1_000_000n;
		const v = a - fee;
		const t = createTriple({
			prefix: 'bound-budget',
			params: { budgetMsat: 2n * v, maxPayments: 3 }
		});
		goOffline(t);
		pay(t, t.hashes[0], a);
		pay(t, t.hashes[1], a);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(2);

		// Budget is now exhausted to the msat: the smallest acceptable payment
		// (v_3 >= dust floor) must be rejected on the cumulative check.
		pay(t, t.hashes[2], 1_000_000n);
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('exceeds budget_msat')),
			t.sErrors.join('; ')
		).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(2);

		// Reconcile: R is credited exactly the budget.
		reconnectSR(t);
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok).to.equal(true);
		expect(t.rChannel.getBalances().localMsat).to.equal(2n * v);
		expect(t.sChannel.getBalances().localMsat).to.equal(
			FUNDING_SATOSHIS * 1000n - 2n * v
		);
	});

	it('min_payment edge: 1 msat below min rejected, exactly min accepted', function () {
		const min = 1_000_000n;
		const t = createTriple({
			prefix: 'bound-min',
			params: { minPaymentMsat: min }
		});
		goOffline(t);
		// 1 msat below: rejected, hash NOT consumed. The rejected HTLC is
		// deliberately FRACTIONAL-msat: failing it upstream exercises the
		// sub-satoshi removal-round parity of the commitment builder.
		pay(t, t.hashes[0], min - 1n);
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('below min_payment_msat')),
			t.sErrors.join('; ')
		).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(0);
		// Exactly min: accepted, on the SAME hash (rejection left it usable).
		pay(t, t.hashes[0], min);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(1);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(1);
	});

	it('fractional-msat settlement: non-whole-satoshi delegated payments settle and reconcile exactly', function () {
		// FFOR settlement composes with fractional-msat HTLC amounts end to
		// end: fractional upstream HTLCs, fractional vouchers (BOLT 3 keeps
		// the sub-satoshi remainder with the offerer), and a fractional
		// rejected payment failed upstream mid-epoch.
		const t = createTriple({ prefix: 'bound-frac', params: { maxPayments: 3 } });
		goOffline(t);
		const a1 = 1_000_001n; // v1 = 1,000,001 - (1000 + 5000) = 994,001
		const a2 = 2_345_679n; // v2 = 2,345,679 - (1000 + 11,728) = 2,332,951
		pay(t, t.hashes[0], a1);
		pay(t, t.hashes[1], a2);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
		// A fractional below-min duplicate-hash part fails cleanly mid-epoch.
		pay(t, t.hashes[1], a2);
		expect(t.pFailed).to.have.length(1);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(2);
		reconnectSR(t);
		expect(
			t.rChannel.getFforEpoch()!.state,
			t.rErrors.concat(t.sErrors).join('; ')
		).to.equal(FforEpochState.FF_CLOSED);
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok).to.equal(true);
		const v1 = a1 - (1000n + (a1 * 5000n) / 1_000_000n);
		const v2 = a2 - (1000n + (a2 * 5000n) / 1_000_000n);
		expect(t.rChannel.getBalances().localMsat).to.equal(v1 + v2);
		expect(t.sChannel.getBalances().localMsat).to.equal(
			FUNDING_SATOSHIS * 1000n - v1 - v2
		);
	});

	it('voucher dust-floor edge: amount clears min but v_i would be trimmed', function () {
		// dust floor (anchors) = max(dustLimit) * 1000 = 354,000 msat. A steep
		// 60% proportional skim makes a min-clearing payment trim: fee(500k) =
		// 1000 + 300,000 -> v = 199,000 < 354,000 -> §8 trim rejection.
		const t = createTriple({
			prefix: 'bound-dust',
			params: { feeProportionalMillionths: 600_000 }
		});
		goOffline(t);
		pay(t, t.hashes[0], 600_000n); // v = 600,000-361,000 = 239,000 < 354,000
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('below the voucher dust floor')),
			t.sErrors.join('; ')
		).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(0);
		// The hash stays consumable: an amount whose voucher clears the floor
		// settles. 890,000: fee = 1000 + 534,000 -> v = 355,000 >= 354,000.
		pay(t, t.hashes[0], 890_000n);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(1);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(1);
	});

	it('settlement at height D-1 accepted, at D rejected (§8: height < D)', function () {
		const D = 1000;
		const t = createTriple({
			prefix: 'bound-d',
			params: { settlementDeadline: D, maxPayments: 3 }
		});
		goOffline(t);
		// Height D-1: still inside the epoch window.
		t.sManager.handleNewBlock(D - 1);
		pay(t, t.hashes[0], 1_000_000n, D + FFOR_SETTLEMENT_SAFETY_DELTA + 100);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(1);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(1);
		// Height D: at the deadline — rejected.
		t.sManager.handleNewBlock(D);
		pay(t, t.hashes[1], 1_000_000n, D + FFOR_SETTLEMENT_SAFETY_DELTA + 100);
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('settlement_deadline')),
			t.sErrors.join('; ')
		).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.lastSeq).to.equal(1);
	});

	it('upstream-expiry safety delta edge: height < expiry - delta strictly', function () {
		const t = createTriple({
			prefix: 'bound-delta',
			params: { settlementDeadline: 2000, voucherExpiry: 3008, maxPayments: 3 }
		});
		goOffline(t);
		const h = 900;
		t.sManager.handleNewBlock(h);
		// expiry = h + delta: height == expiry - delta -> rejected (not <).
		pay(t, t.hashes[0], 1_000_000n, h + FFOR_SETTLEMENT_SAFETY_DELTA);
		expect(t.pFailed).to.have.length(1);
		expect(
			t.sErrors.some((e) => e.includes('safety delta')),
			t.sErrors.join('; ')
		).to.equal(true);
		// expiry = h + delta + 1: height < expiry - delta -> accepted.
		pay(t, t.hashes[0], 1_000_000n, h + FFOR_SETTLEMENT_SAFETY_DELTA + 1);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(1);
	});

	it('§11.4: exhaustion failures go upstream as temporary_node_failure', function () {
		const t = createTriple({
			prefix: 'bound-fail',
			params: { maxPayments: 1 }
		});
		const failReasons: Buffer[] = [];
		t.pManager.on('htlc:failed', (_c: Buffer, _id: bigint, reason?: Buffer) => {
			if (reason) failReasons.push(reason);
		});
		goOffline(t);
		pay(t, t.hashes[0], 1_000_000n);
		expect(t.pFulfilled).to.have.length(1);
		// Exhausted (K = 1): the next delegated payment fails upstream with
		// temporary_node_failure (§11.4 minimum rung).
		pay(t, t.hashes[0], 1_000_000n);
		expect(t.pFailed).to.have.length(1);
		expect(
			failReasons.some((r) =>
				r.toString('utf8').includes('temporary_node_failure')
			),
			failReasons.map((r) => r.toString('utf8')).join('; ')
		).to.equal(true);
	});
});
