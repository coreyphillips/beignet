import { expect } from 'chai';
import {
	SPLICE_TX_BASE_WEIGHT,
	SHARED_FUNDING_INPUT_WEIGHT,
	P2WPKH_INPUT_WEIGHT,
	P2WPKH_DUST_LIMIT,
	outputWeight,
	estimateSpliceTxWeight,
	spliceFeeSats
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
});
