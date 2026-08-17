import { expect } from 'chai';
import {
	SPLICE_TX_BASE_WEIGHT,
	SHARED_FUNDING_INPUT_WEIGHT,
	P2WPKH_INPUT_WEIGHT,
	P2WPKH_DUST_LIMIT,
	outputWeight,
	estimateSpliceTxWeight,
	spliceFeeSats,
	dualFundingContributionWeight,
	dualFundingTopUpWeight,
	DUAL_FUNDING_INPUT_WEIGHT
} from '../../src/lightning/channel/splice-weight';

describe('Splice weight estimation', function () {
	it('exposes the standard weight constants', function () {
		expect(SPLICE_TX_BASE_WEIGHT).to.equal(42);
		expect(SHARED_FUNDING_INPUT_WEIGHT).to.equal(386);
		expect(P2WPKH_INPUT_WEIGHT).to.equal(272);
		expect(P2WPKH_DUST_LIMIT).to.equal(294n);
	});

	it('computes output weight from script length', function () {
		expect(outputWeight(22)).to.equal(124); // P2WPKH
		expect(outputWeight(34)).to.equal(172); // P2WSH / P2TR
	});

	it('estimates a splice-out tx (shared input, new funding + P2WPKH destination)', function () {
		const weight = estimateSpliceTxWeight({
			walletInputCount: 0,
			destinationScriptLen: 22
		});
		// 42 + 386 + 172 (funding) + 124 (destination)
		expect(weight).to.equal(724);
	});

	it('estimates a splice-in tx (1 wallet input + change)', function () {
		const weight = estimateSpliceTxWeight({
			walletInputCount: 1,
			changeScriptLen: 22
		});
		// 42 + 386 + 272 + 172 + 124
		expect(weight).to.equal(996);
	});

	it('scales with wallet input count', function () {
		const one = estimateSpliceTxWeight({
			walletInputCount: 1,
			changeScriptLen: 22
		});
		const three = estimateSpliceTxWeight({
			walletInputCount: 3,
			changeScriptLen: 22
		});
		expect(three - one).to.equal(2 * P2WPKH_INPUT_WEIGHT);
	});

	it('computes fees with ceiling rounding', function () {
		expect(spliceFeeSats(724, 253)).to.equal(184n); // ceil(183.172)
		expect(spliceFeeSats(996, 253)).to.equal(252n); // ceil(251.988)
		expect(spliceFeeSats(1000, 1000)).to.equal(1000n);
		// The old fixed 800-WU estimate undercounted splice-in (996+) and
		// overcounted splice-out (724).
		expect(
			estimateSpliceTxWeight({ walletInputCount: 1, changeScriptLen: 22 })
		).to.be.greaterThan(800);
		expect(
			estimateSpliceTxWeight({ walletInputCount: 0, destinationScriptLen: 22 })
		).to.be.lessThan(800);
	});

	describe('dual-funding contribution weight', function () {
		it('prices our v2 open share, with the initiator surcharge', function () {
			// Cushioned inputs (320) + change output (140), plus the common
			// fields and the shared funding output (240) for the initiator.
			expect(dualFundingContributionWeight(0, false)).to.equal(140);
			expect(dualFundingContributionWeight(1, false)).to.equal(460);
			expect(dualFundingContributionWeight(0, true)).to.equal(380);
			expect(dualFundingContributionWeight(1, true)).to.equal(700);
			expect(
				dualFundingContributionWeight(3, true) -
					dualFundingContributionWeight(1, true)
			).to.equal(640);
		});

		// Issue #380: the splice estimator cannot size a v2 open contribution.
		// It carries a shared 2-of-2 funding input this transaction has no
		// equivalent of, so it over-reserves at low input counts and UNDER-
		// reserves past the crossover, which is where the open aborted as
		// underfunded.
		it('crosses the splice estimate at 8 inputs as initiator', function () {
			const splice = (n: number): number =>
				estimateSpliceTxWeight({ walletInputCount: n, changeScriptLen: 22 });
			expect(dualFundingContributionWeight(7, true)).to.be.lessThan(splice(7));
			expect(dualFundingContributionWeight(8, true)).to.be.greaterThan(
				splice(8)
			);
		});

		it('charges a top-up only the marginal per-input weight', function () {
			// The fixed terms cancel in the difference, so the top-up weight is
			// role-independent and equals the per-input weight times the count.
			for (const initiator of [true, false]) {
				for (const [n, k] of [
					[1, 1],
					[3, 2],
					[7, 5]
				]) {
					expect(
						dualFundingContributionWeight(n + k, initiator) -
							dualFundingContributionWeight(n, initiator)
					).to.equal(dualFundingTopUpWeight(k));
				}
			}
			expect(dualFundingTopUpWeight(0)).to.equal(0);
			expect(dualFundingTopUpWeight(1)).to.equal(DUAL_FUNDING_INPUT_WEIGHT);
			expect(dualFundingTopUpWeight(4)).to.equal(1280);
		});

		it('crosses the splice estimate at 13 inputs as acceptor', function () {
			const splice = (n: number): number =>
				estimateSpliceTxWeight({ walletInputCount: n, changeScriptLen: 22 });
			expect(dualFundingContributionWeight(12, false)).to.be.lessThan(
				splice(12)
			);
			expect(dualFundingContributionWeight(13, false)).to.be.greaterThan(
				splice(13)
			);
		});
	});
});
