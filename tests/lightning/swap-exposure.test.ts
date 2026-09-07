/**
 * Swap exposure policy (issue #737, phase 2): every refusal reason, the
 * per-state counting rules, and the optional balance check.
 */

import { expect } from 'chai';
import {
	ISwapExposurePolicy,
	ISwapRecord,
	SwapState,
	evaluateSwapExposure,
	isSwapExposure,
	validateSwapExposurePolicy
} from '../../src/lightning/swaps';

const policy: ISwapExposurePolicy = {
	minSwapSat: 10_000n,
	maxSwapSat: 1_000_000n,
	maxTotalExposureSat: 2_000_000n,
	maxConcurrentSwaps: 3,
	feeReserveSat: 50_000n,
	fundingFeeRateCeilingSatPerVbyte: 100
};

function row(
	state: SwapState,
	onchainSat: bigint,
	direction: 'reverse' | 'submarine' = 'reverse',
	extra: Partial<ISwapRecord> = {}
): ISwapRecord {
	return {
		id: `${state}-${onchainSat}-${Math.random()}`,
		state,
		direction,
		peerNodeIdHex: '02' + '11'.repeat(32),
		paymentHashHex: 'ab'.repeat(32),
		claimPubkeyHex: '02' + '22'.repeat(32),
		refundPubkeyHex: '02' + '33'.repeat(32),
		refundHeight: 1000,
		outputScriptHex: '0020' + '44'.repeat(32),
		address: 'bcrt1q',
		network: 'regtest',
		onchainSat: onchainSat.toString(),
		invoiceMsat: (onchainSat * 1000n).toString(),
		totalFeeSat: '0',
		minerFeeSat: '0',
		createdAt: 1,
		createdHeight: 900,
		updatedAt: 1,
		fundingAttempts: 0,
		refundBumps: 0,
		...extra
	};
}

describe('Swap exposure policy (issue #737 phase 2)', function () {
	it('validates the policy shape', function () {
		validateSwapExposurePolicy(policy);
		expect(() =>
			validateSwapExposurePolicy({ ...policy, minSwapSat: 0n })
		).to.throw(/minSwapSat/);
		expect(() =>
			validateSwapExposurePolicy({ ...policy, maxSwapSat: 1n })
		).to.throw(/maxSwapSat/);
		expect(() =>
			validateSwapExposurePolicy({ ...policy, maxTotalExposureSat: 1n })
		).to.throw(/maxTotalExposureSat/);
		expect(() =>
			validateSwapExposurePolicy({ ...policy, maxConcurrentSwaps: 0 })
		).to.throw(/maxConcurrentSwaps/);
		expect(() =>
			validateSwapExposurePolicy({
				...policy,
				fundingFeeRateCeilingSatPerVbyte: 0
			})
		).to.throw(/fundingFeeRateCeilingSatPerVbyte/);
	});

	it('admits within the caps and reserves amount plus fee', function () {
		const verdict = evaluateSwapExposure(policy, {
			direction: 'reverse',
			amountSat: 100_000n,
			estimatedFundingFeeSat: 500n,
			live: []
		});
		expect(verdict).to.deep.equal({ ok: true, reservedSat: 100_500n });
	});

	it('refuses below the minimum and above the maximum', function () {
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 9_999n,
				live: []
			})
		).to.include({ ok: false, reason: 'below-min' });
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 1_000_001n,
				live: []
			})
		).to.include({ ok: false, reason: 'above-max' });
	});

	it('refuses a fee rate above the ceiling', function () {
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 100_000n,
				feeRateSatPerVbyte: 101,
				live: []
			})
		).to.include({ ok: false, reason: 'fee-rate' });
	});

	it('counts every unresolved row toward concurrency, terminal rows never', function () {
		const live = [row('CREATED', 1n), row('CREATED', 1n)];
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 100_000n,
				live
			})
		).to.include({ ok: true });
		live.push(row('HELD', 1n));
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 100_000n,
				live
			})
		).to.include({ ok: false, reason: 'concurrency' });
	});

	it('counts principal at risk from HELD onward for reverse and PAYING onward for submarine', function () {
		expect(isSwapExposure(row('CREATED', 1n))).to.equal(false);
		for (const state of [
			'HELD',
			'FUNDING',
			'FUNDING_BROADCAST',
			'FUNDED',
			'CLAIMED',
			'REFUND_PENDING'
		] as const) {
			expect(isSwapExposure(row(state, 1n)), state).to.equal(true);
		}
		for (const state of [
			'SETTLED',
			'REFUNDED',
			'CANCELLED',
			'FAILED'
		] as const) {
			expect(isSwapExposure(row(state, 1n)), state).to.equal(false);
		}
		// EXPOSED stays counted until a confirmed resolution has been verified
		// this session.
		expect(isSwapExposure(row('EXPOSED', 1n))).to.equal(true);
		expect(
			isSwapExposure(
				row('EXPOSED', 1n, 'reverse', {
					resolution: {
						kind: 'refund',
						txid: 'aa',
						confirmations: 2,
						verifiedThisSession: true
					}
				})
			)
		).to.equal(false);
		expect(
			isSwapExposure(
				row('EXPOSED', 1n, 'reverse', {
					resolution: {
						kind: 'refund',
						txid: 'aa',
						confirmations: 2,
						verifiedThisSession: false
					}
				})
			)
		).to.equal(true);
		// Policy depth: one confirmation is not three.
		const shallow = row('EXPOSED', 1n, 'reverse', {
			resolution: {
				kind: 'refund',
				txid: 'aa',
				confirmations: 1,
				verifiedThisSession: true
			}
		});
		expect(isSwapExposure(shallow, 3)).to.equal(true);
		expect(isSwapExposure(shallow, 1)).to.equal(false);
		expect(
			isSwapExposure(
				row('EXPOSED', 1n, 'reverse', {
					resolution: {
						kind: 'refund',
						txid: 'aa',
						confirmations: 3,
						verifiedThisSession: true
					}
				}),
				3
			)
		).to.equal(false);
		expect(isSwapExposure(row('CREATED', 1n, 'submarine'))).to.equal(false);
		expect(isSwapExposure(row('FUNDED', 1n, 'submarine'))).to.equal(false);
		for (const state of [
			'PAYING',
			'PAYMENT_UNRESOLVED',
			'PREIMAGE_KNOWN',
			'CLAIM_BROADCAST'
		] as const) {
			expect(isSwapExposure(row(state, 1n, 'submarine')), state).to.equal(true);
		}
	});

	it('refuses when the exposed total plus the candidate exceeds the cap', function () {
		const live = [row('FUNDED', 1_000_000n), row('CREATED', 1_000_000n)];
		// CREATED does not count: 1_000_000 + 900_000 fits.
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 900_000n,
				live
			})
		).to.include({ ok: true });
		live[1] = row('HELD', 1_000_000n);
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 900_000n,
				live
			})
		).to.include({ ok: false, reason: 'exposure' });
	});

	it('checks the fee reserve only when a balance is supplied', function () {
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 100_000n,
				estimatedFundingFeeSat: 1_000n,
				live: [],
				availableBalanceSat: 150_999n
			})
		).to.include({ ok: false, reason: 'insufficient-balance' });
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 100_000n,
				estimatedFundingFeeSat: 1_000n,
				live: [],
				availableBalanceSat: 151_000n
			})
		).to.include({ ok: true });
		expect(
			evaluateSwapExposure(policy, {
				direction: 'reverse',
				amountSat: 100_000n,
				estimatedFundingFeeSat: 1_000n,
				live: []
			})
		).to.include({ ok: true });
	});
});
