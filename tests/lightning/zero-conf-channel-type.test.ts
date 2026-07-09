/**
 * Zero-conf channel_type gating + default feature advertising.
 *
 * option_zeroconf and option_dual_fund are advertised in defaultFeatures(),
 * so peers may PROPOSE a zero_conf channel type. Accepting one commits us to
 * minimum_depth 0 (BOLT 2), which we only extend to trusted peers: an
 * untrusted proposal must be rejected on both the v1 and v2 open paths.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`zeroconf-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeOpener(): Channel {
	return new Channel(
		createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 500_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(1)),
			localPerCommitmentSeed: makeSeed(101)
		})
	);
}

function makeAcceptor(temporaryChannelId: Buffer): Channel {
	return new Channel(
		createAcceptorState({
			temporaryChannelId,
			fundingSatoshis: 500_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(makeSeed(2)),
			localPerCommitmentSeed: makeSeed(102),
			remoteBasepoints: makeBasepoints(makeSeed(1)),
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
}

function zeroConfChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	flags.setCompulsory(Feature.ZERO_CONF);
	return flags.toBuffer();
}

function payloadOf(actions: ReturnType<Channel['initiateOpen']>): Buffer {
	const send = actions.find((a) => 'payload' in a) as { payload: Buffer };
	expect(send, 'expected a send-message action').to.exist;
	return send.payload;
}

describe('Zero-conf channel_type gating', function () {
	it('rejects a zero_conf channel type from an untrusted peer', function () {
		const open = decodeOpenChannelMessage(
			payloadOf(makeOpener().initiateOpen())
		);
		open.channelType = zeroConfChannelType();

		const actions = makeAcceptor(open.temporaryChannelId).handleOpenChannel(
			open
		);
		expect(actions[0].type).to.equal(ChannelActionType.ERROR);
		expect((actions[0] as { message: string }).message).to.include(
			'trusted peer'
		);
	});

	it('accepts a zero_conf channel type from a trusted peer with minimum_depth 0', function () {
		const open = decodeOpenChannelMessage(
			payloadOf(makeOpener().initiateOpen())
		);
		open.channelType = zeroConfChannelType();

		const acceptor = makeAcceptor(open.temporaryChannelId);
		// Mirror ChannelManager's trusted-peer wiring before handleOpenChannel.
		const state = acceptor.getFullState();
		state.trustedPeer = true;
		state.zeroConfEnabled = true;
		state.minimumDepth = 0;

		const accept = decodeAcceptChannelMessage(
			payloadOf(acceptor.handleOpenChannel(open))
		);
		expect(accept.minimumDepth).to.equal(0);
	});
});

describe('Default feature advertising (dual_fund + zero_conf)', function () {
	it('defaultFeatures() advertises option_dual_fund (bit 28/29) as optional', function () {
		const flags = LightningNode.defaultFeatures();
		expect(flags.hasFeature(Feature.DUAL_FUND)).to.be.true;
		expect(flags.isCompulsory(Feature.DUAL_FUND)).to.be.false;
	});

	it('defaultFeatures() advertises option_zeroconf (bit 50/51) as optional', function () {
		const flags = LightningNode.defaultFeatures();
		expect(flags.hasFeature(Feature.ZERO_CONF)).to.be.true;
		expect(flags.isCompulsory(Feature.ZERO_CONF)).to.be.false;
	});
});
