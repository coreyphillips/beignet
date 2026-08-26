/**
 * A configured liquidity ads seller publishes its rates in node_announcement
 * (issue #539, bLIP-0051).
 *
 * The option_will_fund feature bit alone told buyers we sell but not at what
 * price, so anything pricing from the gossip ad skipped the node or requested
 * blind. The announcement now carries the lease_rates TLV (node_ann_tlvs
 * type 1) holding exactly the rates will_fund signs; a non-seller emits no
 * TLV and no bit.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import { ILeaseRates } from '../../src/lightning/gossip/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

const RATES: ILeaseRates = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 500,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 10
};

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k = (i: number): Buffer =>
		getPublicKey(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	return {
		fundingPubkey: k(0),
		revocationBasepoint: k(1),
		paymentBasepoint: k(2),
		delayedPaymentBasepoint: k(3),
		htlcBasepoint: k(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(leaseRates?: ILeaseRates): LightningNode {
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(crypto.randomBytes(32)),
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: crypto.randomBytes(32),
		leaseRates
	});
}

function announce(node: LightningNode): Buffer {
	const payload = (
		node as unknown as {
			buildNodeAnnouncement: (t: number) => Buffer | null;
		}
	).buildNodeAnnouncement(1_700_000_000);
	expect(payload, 'node_announcement built').to.not.be.null;
	return payload!;
}

describe('node_announcement lease_rates TLV (issue #539)', () => {
	it('a seller round-trips its exact rates and the will_fund bit', () => {
		const node = makeNode(RATES);
		try {
			const decoded = decodeNodeAnnouncementMessage(announce(node));
			expect(decoded.leaseRates, 'lease_rates TLV present').to.deep.equal(
				RATES
			);
			const feats = FeatureFlags.fromBuffer(decoded.features);
			expect(feats.hasFeature(Feature.OPTION_WILL_FUND)).to.equal(true);
		} finally {
			node.destroy();
		}
	});

	it('a non-seller emits neither the TLV nor the bit', () => {
		const node = makeNode(undefined);
		try {
			const decoded = decodeNodeAnnouncementMessage(announce(node));
			expect(decoded.leaseRates).to.equal(undefined);
			const feats = FeatureFlags.fromBuffer(decoded.features);
			expect(feats.hasFeature(Feature.OPTION_WILL_FUND)).to.equal(false);
		} finally {
			node.destroy();
		}
	});
});
