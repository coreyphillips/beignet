/**
 * Two-node loopback harness shared by the swap-provider prerequisite tests
 * (issue #737). The same shape lives inline in hold-invoices.test.ts and a
 * dozen siblings; this copy takes a seed tag so parallel test files never
 * collide on node identities.
 *
 * The "chain" is a random 32-byte funding txid and handleFundingConfirmed on
 * both sides; nothing is verified. Messages go straight from one node's
 * 'message:outbound' into the other's handlePeerMessage: no sockets, no Noise.
 */

import crypto from 'crypto';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../../src/lightning/node/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../../src/lightning/gossip/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';

export function makeSeed(tag: string, id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`${tag}-seed-${id}`))
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

export function makeNodeConfig(
	tag: string,
	seedId: number,
	storage?: SqliteStorage
): INodeConfig {
	const seed = makeSeed(tag, seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	const config: INodeConfig = {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(tag, seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret
	};
	if (storage) config.storage = storage;
	return config;
}

export function createNode(
	tag: string,
	seedId: number,
	storage?: SqliteStorage,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode({
		...makeNodeConfig(tag, seedId, storage),
		...extra
	});
	node.on('error', () => {});
	return node;
}

export function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

export function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

export function scidForIndex(i: number): Buffer {
	return encodeShortChannelId({ block: 500, txIndex: i + 1, outputIndex: 0 });
}

/**
 * Publish direct alice->bob channels on Alice's graph (one per channelId,
 * cltvExpiryDelta 40) and register the SCIDs so she can dispatch over them.
 */
export function buildGraph(
	alice: LightningNode,
	bob: LightningNode,
	channelIds: Buffer[],
	htlcMaximumMsat = 1_000_000_000n
): void {
	const alicePubkey = Buffer.from(alice.getNodeId(), 'hex');
	const bobPubkey = Buffer.from(bob.getNodeId(), 'hex');
	const aliceIsNode1 = Buffer.compare(alicePubkey, bobPubkey) < 0;
	const nodeId1 = aliceIsNode1 ? alicePubkey : bobPubkey;
	const nodeId2 = aliceIsNode1 ? bobPubkey : alicePubkey;

	channelIds.forEach((channelId, i) => {
		const scid = scidForIndex(i);
		const announcement: IChannelAnnouncementMessage = {
			nodeSignature1: Buffer.alloc(64),
			nodeSignature2: Buffer.alloc(64),
			bitcoinSignature1: Buffer.alloc(64),
			bitcoinSignature2: Buffer.alloc(64),
			features: Buffer.alloc(0),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			nodeId1,
			nodeId2,
			bitcoinKey1: Buffer.alloc(33, 2),
			bitcoinKey2: Buffer.alloc(33, 3)
		};
		alice.getGraph().addChannelAnnouncement(announcement);

		const update1: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: 0,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat
		};
		alice.getGraph().applyChannelUpdate(update1);
		alice.getGraph().applyChannelUpdate({ ...update1, channelFlags: 1 });

		alice.registerChannelScid(channelId, scid);
	});
}

export function makeExternalHash(): { preimage: Buffer; hash: Buffer } {
	const preimage = crypto.randomBytes(32);
	const hash = crypto.createHash('sha256').update(preimage).digest();
	return { preimage, hash };
}

/** cltv_expiry of the (single) received HTLC parked on the receiver. */
export function parkedCltvExpiry(
	bob: LightningNode,
	channelId: Buffer
): number {
	const state = bob.getChannelManager().getChannel(channelId)!.getFullState();
	for (const [key, htlc] of state.htlcs) {
		if (key.startsWith('received-')) return htlc.cltvExpiry;
	}
	throw new Error('no received HTLC on channel');
}
