/**
 * Per-message own-channel checks on inbound gossip (issue #1677).
 *
 * Every channel_update asks whether its scid names one of our channels, and
 * every node_announcement whether its node is a channel peer. Both used to
 * scan the whole channel list, two or three times per message, which for a
 * node with many channels made a graph sync cost minutes of CPU. They now
 * read an index ChannelManager rebuilds only when its channels or their
 * scids change, so these tests pin both halves: gossip never touches the
 * channel list, and the index still sees every real scid write and removal.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as secp from '@noble/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	encodeChannelUpdateMessage,
	encodeNodeAnnouncementMessage
} from '../../src/lightning/gossip/messages';
import {
	signChannelUpdate,
	signNodeAnnouncement
} from '../../src/lightning/gossip/validation';
import {
	ADDRESS_TYPE_IPV4,
	IChannelUpdateMessage
} from '../../src/lightning/gossip/types';

function validPriv(): Buffer {
	let k: Buffer;
	do {
		k = crypto.randomBytes(32);
	} while (!secp.utils.isValidPrivateKey(k));
	return k;
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

function makeNode(
	nodePrivateKey: Buffer,
	enableNetworking = false
): LightningNode {
	const node = new LightningNode({
		nodePrivateKey,
		channelBasepoints: makeBasepoints(),
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: validPriv(),
		network: Network.REGTEST,
		enableNetworking
	});
	node.on('node:error', () => {});
	return node;
}

type TManagerMaps = {
	channels: Map<string, Channel>;
	tempChannels: Map<string, Channel>;
	channelPeers: Map<string, string>;
};

/** A private NORMAL channel to `peer`, with no scid unless one is given. */
function addChannel(
	cm: ChannelManager,
	peer: string,
	scidAlias: Buffer | null = null
): Channel {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.announceChannel = false;
	state.scidAlias = scidAlias;
	const channel = new Channel(state);
	const maps = cm as unknown as TManagerMaps;
	maps.channels.set(state.channelId.toString('hex'), channel);
	maps.channelPeers.set(state.channelId.toString('hex'), peer);
	return channel;
}

/** A channel_update for `scid` in the direction `signer` authors. */
function makeUpdate(
	scid: Buffer,
	signer: Buffer,
	other: Buffer,
	feeBaseMsat = 1000,
	messageFlags = 1
): Buffer {
	const msg: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags,
		channelFlags:
			Buffer.compare(getPublicKey(signer), getPublicKey(other)) < 0 ? 0 : 1,
		cltvExpiryDelta: 80,
		htlcMinimumMsat: 1000n,
		feeBaseMsat,
		feeProportionalMillionths: 150,
		htlcMaximumMsat: 900_000_000n
	};
	msg.signature = signChannelUpdate(encodeChannelUpdateMessage(msg), signer);
	return encodeChannelUpdateMessage(msg);
}

function makeNodeAnnouncement(privkey: Buffer, port: number): Buffer {
	const payload = encodeNodeAnnouncementMessage({
		signature: Buffer.alloc(64),
		features: Buffer.alloc(0),
		timestamp: Math.floor(Date.now() / 1000),
		nodeId: getPublicKey(privkey),
		rgbColor: Buffer.from([0, 0, 0]),
		alias: Buffer.alloc(32),
		addresses: [{ type: ADDRESS_TYPE_IPV4, host: '203.0.113.7', port }]
	});
	signNodeAnnouncement(payload, privkey).copy(payload, 0);
	return payload;
}

function feed(node: LightningNode, type: number, payload: Buffer): void {
	(
		node as unknown as {
			handleGossipMessage(p: string, t: number, b: Buffer): void;
		}
	).handleGossipMessage('aa'.repeat(33), type, payload);
}

/** Counts listChannels calls and channel state reads until restored. */
function spyOnChannelReads(cm: ChannelManager): {
	listChannels: number;
	getFullState: number;
	restore(): void;
} {
	const counts = { listChannels: 0, getFullState: 0, restore: (): void => {} };
	const listChannels = cm.listChannels;
	cm.listChannels = function (this: ChannelManager): Channel[] {
		counts.listChannels++;
		return listChannels.call(this);
	};
	const getFullState = Channel.prototype.getFullState;
	Channel.prototype.getFullState = function (this: Channel) {
		counts.getFullState++;
		return getFullState.call(this);
	};
	counts.restore = (): void => {
		cm.listChannels = listChannels;
		Channel.prototype.getFullState = getFullState;
	};
	return counts;
}

describe('Own-channel gossip checks (issue #1677)', function () {
	it('handles foreign channel updates without scanning the channel list, and still adopts our peer policy', async function () {
		const ourKey = validPriv();
		const node = makeNode(ourKey);
		const cm = node.getChannelManager();
		const peerKey = validPriv();
		const ownScid = crypto.randomBytes(8);
		for (let i = 0; i < 499; i++) {
			addChannel(
				cm,
				getPublicKey(validPriv()).toString('hex'),
				crypto.randomBytes(8)
			);
		}
		const own = addChannel(cm, getPublicKey(peerKey).toString('hex'), ownScid);

		const spy = spyOnChannelReads(cm);
		let foreignStateReads = 0;
		try {
			for (let i = 0; i < 100; i++) {
				feed(
					node,
					MessageType.CHANNEL_UPDATE,
					makeUpdate(crypto.randomBytes(8), validPriv(), validPriv())
				);
			}
			await node.flushGossip();
			foreignStateReads = spy.getFullState;
			feed(
				node,
				MessageType.CHANNEL_UPDATE,
				makeUpdate(ownScid, peerKey, ourKey, 4242)
			);
		} finally {
			spy.restore();
		}

		expect(spy.listChannels).to.equal(0);
		// One index build reads each channel once; a scan per message would
		// read them 200 times over.
		expect(foreignStateReads).to.equal(500);
		expect(own.getFullState().remoteForwardingPolicy?.feeBaseMsat).to.equal(
			4242
		);
		node.destroy();
	});

	it('sees an scid set after the index was built, and forgets a voided channel', function () {
		const ourKey = validPriv();
		const node = makeNode(ourKey);
		const cm = node.getChannelManager();
		const peerKey = validPriv();
		addChannel(
			cm,
			getPublicKey(validPriv()).toString('hex'),
			crypto.randomBytes(8)
		);
		const channel = addChannel(cm, getPublicKey(peerKey).toString('hex'));

		// Build the index before the channel has any scid.
		feed(
			node,
			MessageType.CHANNEL_UPDATE,
			makeUpdate(crypto.randomBytes(8), validPriv(), validPriv())
		);

		channel.handleAnnouncementDepthReached(
			800_000,
			7,
			getPublicKey(ourKey),
			getPublicKey(peerKey),
			() => {
				throw new Error('a private channel signs no announcement');
			}
		);
		const scid = channel.getShortChannelId()!;
		expect(scid).to.not.equal(null);
		feed(
			node,
			MessageType.CHANNEL_UPDATE,
			makeUpdate(scid, peerKey, ourKey, 3210)
		);
		expect(channel.getFullState().remoteForwardingPolicy?.feeBaseMsat).to.equal(
			3210
		);

		expect(cm.voidChannel(channel.getChannelId()!)).to.equal(true);
		expect(cm.getChannelsByScid(scid)).to.have.length(0);
		node.destroy();
	});

	it("captures a channel peer's node_announcement without scanning the channel list", async function () {
		const node = makeNode(validPriv(), true);
		const cm = node.getChannelManager();
		const peerKey = validPriv();
		const pendingKey = validPriv();
		for (let i = 0; i < 50; i++) {
			addChannel(cm, getPublicKey(validPriv()).toString('hex'));
		}
		addChannel(cm, getPublicKey(peerKey).toString('hex'));
		// A pending open has no channel id yet, so its peer is not a channel
		// peer for address capture.
		const pendingHex = getPublicKey(pendingKey).toString('hex');
		const pending = new Channel(
			createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(),
				localPerCommitmentSeed: crypto.randomBytes(32)
			})
		);
		const maps = cm as unknown as TManagerMaps;
		const tempHex = pending.getTemporaryChannelId().toString('hex');
		maps.tempChannels.set(tempHex, pending);
		maps.channelPeers.set(tempHex, pendingHex);

		const captured = (
			node as unknown as {
				announcedPeerAddresses: Map<string, unknown>;
			}
		).announcedPeerAddresses;
		const spy = spyOnChannelReads(cm);
		try {
			feed(
				node,
				MessageType.NODE_ANNOUNCEMENT,
				makeNodeAnnouncement(peerKey, 9735)
			);
			feed(
				node,
				MessageType.NODE_ANNOUNCEMENT,
				makeNodeAnnouncement(pendingKey, 9736)
			);
			await node.flushGossip();
		} finally {
			spy.restore();
		}

		expect(spy.listChannels).to.equal(0);
		expect(captured.has(getPublicKey(peerKey).toString('hex'))).to.equal(true);
		expect(captured.has(pendingHex)).to.equal(false);
		expect(
			cm.hasChannelWithPeer(getPublicKey(peerKey).toString('hex'))
		).to.equal(true);
		expect(cm.hasChannelWithPeer(pendingHex)).to.equal(false);
		node.destroy();
	});

	it("holds a channel peer's unknown private updates without scanning the channel list", async function () {
		const node = makeNode(validPriv());
		const cm = node.getChannelManager();
		for (let i = 0; i < 499; i++) {
			addChannel(
				cm,
				getPublicKey(validPriv()).toString('hex'),
				crypto.randomBytes(8)
			);
		}
		// feed() delivers from this peer.
		const peer = 'aa'.repeat(33);
		addChannel(cm, peer);

		const spy = spyOnChannelReads(cm);
		const getChannelsByPeer = cm.getChannelsByPeer;
		let byPeerScans = 0;
		cm.getChannelsByPeer = function (
			this: ChannelManager,
			pubkey: string
		): Channel[] {
			byPeerScans++;
			return getChannelsByPeer.call(this, pubkey);
		};
		try {
			for (let i = 0; i < 100; i++) {
				feed(
					node,
					MessageType.CHANNEL_UPDATE,
					makeUpdate(crypto.randomBytes(8), validPriv(), validPriv(), 1000, 3)
				);
			}
			await node.flushGossip();
		} finally {
			spy.restore();
			cm.getChannelsByPeer = getChannelsByPeer;
		}

		expect(byPeerScans).to.equal(0);
		expect(spy.listChannels).to.equal(0);
		expect(spy.getFullState).to.equal(500);
		const held = (
			node as unknown as {
				earlyPeerUpdates: Map<string, Map<string, Buffer>>;
			}
		).earlyPeerUpdates;
		// One slot for the peer's one channel.
		expect(held.get(peer)?.size).to.equal(1);
		node.destroy();
	});
});
