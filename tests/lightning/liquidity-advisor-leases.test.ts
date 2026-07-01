/**
 * M3.4 — LiquidityAdvisor liquidity-ads helpers (quoteLeases, suggestLeaseRates,
 * BUY_LEASE recommendation).
 */

import { expect } from 'chai';
import {
	LiquidityAdvisor,
	RecommendationType,
	IChannelSnapshot
} from '../../src/lightning/advisor/liquidity-advisor';
import { ILeaseRates } from '../../src/lightning/gossip/types';
import { computeLeaseFeeSat } from '../../src/lightning/channel/liquidity-ads';

const CHEAP: ILeaseRates = {
	fundingWeightWitness: 500,
	leaseFeeBasis: 20,
	leaseFeeBaseSat: 200,
	channelFeeMaxBaseMsat: 1000,
	channelFeeMaxProportionalThousandths: 5
};
const PRICEY: ILeaseRates = {
	fundingWeightWitness: 2000,
	leaseFeeBasis: 200,
	leaseFeeBaseSat: 2000,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 10
};

describe('LiquidityAdvisor liquidity ads (M3.4)', function () {
	const advisor = new LiquidityAdvisor();

	it('quotes lease offers cheapest-first with correct fees', function () {
		const quotes = advisor.quoteLeases(
			[
				{ sellerNodeId: 'pricey', leaseRates: PRICEY },
				{ sellerNodeId: 'cheap', leaseRates: CHEAP }
			],
			1_000_000n,
			2000
		);

		expect(quotes).to.have.length(2);
		// Cheapest first.
		expect(quotes[0].offer.sellerNodeId).to.equal('cheap');
		expect(quotes[1].offer.sellerNodeId).to.equal('pricey');
		// Fee matches the pure computation.
		expect(quotes[0].feeSats).to.equal(
			computeLeaseFeeSat(CHEAP, 1_000_000n, 2000)
		);
		expect(quotes[0].feeRatePct).to.be.greaterThan(0);
		expect(quotes[0].feeSats < quotes[1].feeSats).to.be.true;
	});

	it('suggests sane default lease rates a seller can advertise', function () {
		const rates = advisor.suggestLeaseRates();
		expect(rates.leaseFeeBaseSat).to.be.greaterThan(0);
		expect(rates.leaseFeeBasis).to.be.greaterThan(0);
		// Overrides are honoured.
		const custom = advisor.suggestLeaseRates({ leaseFeeBaseSat: 1234 });
		expect(custom.leaseFeeBaseSat).to.equal(1234);
	});

	it('recommends BUY_LEASE when all channels are inbound-starved', function () {
		const channels: IChannelSnapshot[] = [
			{
				channelId: 'a',
				state: 'NORMAL',
				localBalanceMsat: 1_000_000_000n,
				remoteBalanceMsat: 0n, // no inbound
				capacitySats: 1_000_000,
				peerPubkey: '02'.padEnd(66, '0')
			}
		];
		const snap = advisor.analyze(channels);
		const hasBuyLease = snap.recommendations.some(
			(r) => r.type === RecommendationType.BUY_LEASE
		);
		expect(hasBuyLease).to.be.true;
	});
});
