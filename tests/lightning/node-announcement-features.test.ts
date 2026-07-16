/**
 * Regression (S-7.M2): node_announcement must advertise the features we actually
 * support, not just large_channels.
 *
 * Remote nodes make routing decisions (onion-message relay, route blinding) from
 * the graph. An almost-empty node_announcement features field made CLN/eclair/LDK
 * refuse to route onion messages to us, leaving BOLT 12 offers unreachable to
 * non-direct peers. The node_announcement now carries the same feature set as
 * our init message.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

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

describe('S-7.M2: node_announcement features', () => {
	it('advertises our real feature set (onion messages, route blinding, ...)', () => {
		const seed = crypto.randomBytes(32);
		const node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			network: Network.REGTEST,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: makeBasepoints(seed),
			perCommitmentSeed: crypto.randomBytes(32),
			fundingPrivkey: crypto.randomBytes(32)
		});

		const payload = (
			node as unknown as {
				buildNodeAnnouncement: (t: number) => Buffer | null;
			}
		).buildNodeAnnouncement(1_700_000_000);
		expect(payload, 'node_announcement built').to.not.be.null;

		const decoded = decodeNodeAnnouncementMessage(payload!);
		const feats = FeatureFlags.fromBuffer(decoded.features);

		// The graph-relevant features are present (not an almost-empty field).
		expect(feats.hasFeature(Feature.ONION_MESSAGES), 'onion_messages').to.be
			.true;
		expect(feats.hasFeature(Feature.GOSSIP_QUERIES), 'gossip_queries').to.be
			.true;
		expect(feats.hasFeature(Feature.PAYMENT_SECRET), 'payment_secret').to.be
			.true;
		// And it is not the old ~empty advertisement.
		expect(feats.listSetBits().length).to.be.greaterThan(3);

		node.destroy();
	});
});
