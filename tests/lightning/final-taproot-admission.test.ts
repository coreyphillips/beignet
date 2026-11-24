import { expect } from 'chai';
import { AddressInfo, Server } from 'net';
import { decodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	createAcceptorState,
	createOpenerState
} from '../../src/lightning/channel/channel-state';
import {
	DEFAULT_CHANNEL_CONFIG,
	isAnchorChannel,
	isOverlayChannel,
	isTaprootChannel,
	validateV2ChannelType
} from '../../src/lightning/channel/types';
import {
	Feature,
	FeatureFlags,
	hasUnsupportedRequiredFeatures
} from '../../src/lightning/features/flags';
import {
	decodeOpenChannelMessage,
	encodeOpenChannelMessage
} from '../../src/lightning/message/channel-open';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { makeNodeConfig } from './helpers/ffor-world';
import {
	basepointsOf,
	configOf,
	seedFor
} from './helpers/taproot-revoked-fixture';
import { expectWireRefusal } from './helpers/open-refusal';
import { makeAssetChannel, referenceProvider } from './helpers/auxiliary-pair';
import { THROWING } from './helpers/untouchable-provider';

function flags(...bits: number[]): FeatureFlags {
	const bitmap = FeatureFlags.empty();
	for (const bit of bits) bitmap.setBit(bit);
	return bitmap;
}

// The Simple Taproot BOLT assigns final 80/81 and staging 180/181.
// An implementation can preserve either persisted format independently of
// which new channels it currently admits.
const tempId = seedFor(801);
const base = {
	temporaryChannelId: tempId,
	fundingSatoshis: 500_000n,
	pushMsat: 0n,
	localConfig: DEFAULT_CHANNEL_CONFIG,
	localBasepoints: basepointsOf(seedFor(802)),
	localPerCommitmentSeed: seedFor(803)
};
function newAcceptor(): Channel {
	return new Channel(
		createAcceptorState({
			...base,
			remoteBasepoints: basepointsOf(seedFor(804)),
			remoteConfig: DEFAULT_CHANNEL_CONFIG
		})
	);
}
function proposedOpen(
	channelType: Buffer
): ReturnType<typeof decodeOpenChannelMessage> {
	const opener = new Channel(createOpenerState(base));
	const send = opener
		.initiateOpen()
		.find((action) => action.type === ChannelActionType.SEND_MESSAGE);
	if (!send || send.type !== ChannelActionType.SEND_MESSAGE)
		throw new Error('Missing open_channel');
	return { ...decodeOpenChannelMessage(send.payload), channelType };
}

describe('Final Taproot channel admission', function () {
	for (const mode of ['ordinary', 'staging', 'overlay']) {
		it(`keeps the configured ${mode} init on its supported channel profiles`, function () {
			const requested = LightningNode.defaultFeatures();
			if (mode === 'staging') requested.setOptional(Feature.OPTION_TAPROOT);
			requested.setBit(80);
			requested.setBit(81);
			const node = new LightningNode(
				makeNodeConfig(805, undefined, {
					localFeatures: requested,
					auxiliaryChannels: mode === 'overlay' ? THROWING : undefined
				})
			);
			try {
				const local = node.getLocalFeatures();
				expect(local.hasBit(80)).to.equal(false);
				expect(local.hasBit(81)).to.equal(false);
				expect(local.hasFeature(Feature.OPTION_TAPROOT)).to.equal(
					mode !== 'ordinary'
				);
				expect(local.hasFeature(Feature.OPTION_TAPROOT_OVERLAY)).to.equal(
					mode === 'overlay'
				);
				expect(local.hasFeature(Feature.SIMPLE_CLOSE)).to.equal(
					mode === 'ordinary'
				);
				expect(hasUnsupportedRequiredFeatures(local, flags(81))).to.deep.equal(
					[]
				);
				expect(hasUnsupportedRequiredFeatures(local, flags(80))).to.deep.equal([
					80
				]);
			} finally {
				node.destroy();
			}
		});
	}

	it('keeps caller feature vectors reusable and masks live writes to both final bits', function () {
		const configured = LightningNode.defaultFeatures();
		configured.setOptional(Feature.OPTION_SIMPLE_TAPROOT);
		const node = new LightningNode(
			makeNodeConfig(811, undefined, { localFeatures: configured })
		);
		try {
			expect(configured.hasBit(81)).to.equal(true);
			const advertised = node.getLocalFeatures();
			advertised.setCompulsory(Feature.OPTION_SIMPLE_TAPROOT);
			advertised.setOptional(Feature.OPTION_SIMPLE_TAPROOT);
			expect(advertised.hasFeature(Feature.OPTION_SIMPLE_TAPROOT)).to.equal(
				false
			);
			expect(
				hasUnsupportedRequiredFeatures(advertised, flags(80))
			).to.deep.equal([80]);
			expect(
				hasUnsupportedRequiredFeatures(advertised, configured)
			).to.deep.equal([]);
			configured.setBit(179);
			expect(advertised.hasBit(179)).to.equal(true);
			expect(advertised.listSetBits()).to.include(179).and.not.include(81);
			advertised.setBit(177);
			expect(configured.hasBit(177)).to.equal(true);
			expect(node.getLocalFeatures().hasBit(177)).to.equal(true);
			advertised.clearBit(177);
			expect(node.getLocalFeatures().hasBit(177)).to.equal(false);
		} finally {
			node.destroy();
		}
	});

	it('sends its supported live features in the next handshake and node announcement', async function () {
		const config = { enableNetworking: true, autoReconnect: false };
		const node = new LightningNode(makeNodeConfig(812, undefined, config));
		const observer = new LightningNode(makeNodeConfig(813, undefined, config));
		try {
			const live = node.getLocalFeatures();
			live.setBit(81);
			live.setBit(177);
			await node.listen(0, '127.0.0.1');
			const manager = node.getPeerManager() as unknown as { server: Server };
			const { port } = manager.server.address() as AddressInfo;
			await observer.connectPeer(node.getNodeId(), '127.0.0.1', port);
			const seen = observer
				.getPeerManager()!
				.getPeer(node.getNodeId())!
				.getRemoteInit()!.features;
			const payload = (
				node as unknown as { buildNodeAnnouncement(timestamp: number): Buffer }
			).buildNodeAnnouncement(123456);
			const announced = FeatureFlags.fromBuffer(
				decodeNodeAnnouncementMessage(payload).features
			);
			for (const features of [seen, announced]) {
				expect(features.hasFeature(Feature.OPTION_SIMPLE_TAPROOT)).to.equal(
					false
				);
				expect(features.hasBit(177)).to.equal(true);
			}
		} finally {
			observer.destroy();
			node.destroy();
		}
	});

	for (const [label, bits] of [
		['final', [80]],
		['optional final', [81]],
		['static and final', [Feature.STATIC_REMOTE_KEY, 80]],
		['staging and optional final', [Feature.OPTION_TAPROOT, 81]],
		['asset and final', [Feature.OPTION_TAPROOT_OVERLAY, 80]]
	] as const) {
		const type = flags(...bits).toBuffer();
		it(`declines a ${label} v1 proposal before changing channel state`, function () {
			const channel = newAcceptor();
			const before = JSON.stringify(
				serializeChannelState(channel.getFullState())
			);
			const actions = channel.handleOpenChannel(proposedOpen(type));
			expectWireRefusal(actions, tempId, /[Tt]aproot/);
			expect(
				JSON.stringify(serializeChannelState(channel.getFullState()))
			).to.equal(before);
			expect(validateV2ChannelType(type)).to.be.a('string');
		});

		it(`declines a ${label} v1 proposal before allocating a channel or consulting its provider`, function () {
			let keyCalls = 0;
			let providerCalls = 0;
			const manager = new ChannelManager({
				...configOf(seedFor(806), false),
				channelKeyDeriver: (): never => {
					keyCalls++;
					throw new Error('Unexpected key derivation');
				},
				auxiliaryChannels: {
					...THROWING,
					resolveIncoming: (): undefined => {
						providerCalls++;
						return undefined;
					}
				}
			});
			try {
				const replies: Array<{ type: number; payload: Buffer }> = [];
				manager.on('message:outbound', (_peer, wireType, payload) =>
					replies.push({ type: wireType, payload })
				);
				manager.on('error', () => {});
				const peer = base.localBasepoints.fundingPubkey.toString('hex');
				const next = manager.nextChannelIndex;
				manager.handleMessage(
					peer,
					MessageType.OPEN_CHANNEL,
					encodeOpenChannelMessage(proposedOpen(type))
				);
				expect(keyCalls).to.equal(0);
				expect(providerCalls).to.equal(0);
				expect(replies.map((r) => r.type)).to.deep.equal([MessageType.ERROR]);
				const refusal = decodeErrorMessage(replies[0].payload);
				expect(refusal.channelId).to.deep.equal(tempId);
				expect(refusal.data.toString('ascii')).to.match(/[Tt]aproot/);
				expect(manager.nextChannelIndex).to.equal(next);
				expect(manager.listChannels()).to.have.length(0);
			} finally {
				manager.detachFromPeerManager();
			}
		});
	}

	it('retains the type and commitment rules of historically stored mixed bitmaps', function () {
		for (const [known, taproot, anchor, overlay] of [
			[Feature.STATIC_REMOTE_KEY, false, false, false],
			[Feature.OPTION_TAPROOT, true, true, false],
			[Feature.OPTION_TAPROOT_OVERLAY, true, true, true]
		] as const) {
			const channel = newAcceptor();
			const type = flags(known, 80).toBuffer();
			const state = overlay
				? makeAssetChannel(channel, referenceProvider(), 10n, 20n, type)
				: { ...channel.getFullState(), channelType: type };
			const restored = deserializeChannelState(serializeChannelState(state));
			expect(restored.channelType).to.deep.equal(state.channelType);
			expect(isTaprootChannel(restored.channelType)).to.equal(taproot);
			expect(isAnchorChannel(restored.channelType)).to.equal(anchor);
			expect(isOverlayChannel(restored.channelType)).to.equal(overlay);
		}
	});
});
