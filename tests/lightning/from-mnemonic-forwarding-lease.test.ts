/**
 * LightningNode.fromMnemonic threads the forwarding fee policy and the lease
 * seller policy into the constructor (issue #532 workstream 1B).
 *
 * The constructor has accepted forwardingFeeBaseMsat /
 * forwardingFeePropMillionths / forwardingCltvDelta / leaseRates all along,
 * but the static factory silently dropped them, so a daemon built through
 * fromMnemonic could never configure either. The observable ends: the
 * private forwarding fields the channel_update builders read, and the
 * option_will_fund feature bit a seller policy raises (a CLN buyer refuses
 * to request funds from a peer that does not advertise it).
 */

import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const RATES = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 10000,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 3
};

interface INodeInternals {
	forwardingFeeBaseMsat: number;
	forwardingFeePropMillionths: number;
	forwardingCltvDelta: number;
	localFeatures: FeatureFlags;
}

describe('fromMnemonic forwarding and lease config', () => {
	it('forwards the fee trio and leaseRates to the constructor', () => {
		const node = LightningNode.fromMnemonic(MNEMONIC, {
			network: Network.REGTEST,
			forwardingFeeBaseMsat: 500,
			forwardingFeePropMillionths: 250,
			forwardingCltvDelta: 99,
			leaseRates: RATES
		});
		try {
			const cast = node as unknown as INodeInternals;
			expect(cast.forwardingFeeBaseMsat).to.equal(500);
			expect(cast.forwardingFeePropMillionths).to.equal(250);
			expect(cast.forwardingCltvDelta).to.equal(99);
			expect(cast.localFeatures.hasFeature(Feature.OPTION_WILL_FUND)).to.equal(
				true
			);
		} finally {
			node.destroy();
		}
	});

	it('keeps the library defaults and no will_fund bit when omitted', () => {
		const node = LightningNode.fromMnemonic(MNEMONIC, {
			network: Network.REGTEST
		});
		try {
			const cast = node as unknown as INodeInternals;
			expect(cast.forwardingFeeBaseMsat).to.equal(1000);
			expect(cast.forwardingFeePropMillionths).to.equal(1);
			expect(cast.forwardingCltvDelta).to.equal(40);
			expect(cast.localFeatures.hasFeature(Feature.OPTION_WILL_FUND)).to.equal(
				false
			);
		} finally {
			node.destroy();
		}
	});
});
