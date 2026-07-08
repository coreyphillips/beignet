/**
 * Private-channel peer forwarding policy retention.
 *
 * The graph drops channel_updates without a prior channel_announcement, so a
 * PRIVATE channel's policy could never be stored — invoice route hints and
 * blinded-path payment_relay then advertised OUR forwarding defaults as the
 * peer's policy, and payments failed with fee_insufficient /
 * incorrect_cltv_expiry whenever the peer's real fees differed.
 *
 * A signature-verified channel_update the peer sends us directly is now
 * retained on the channel state (IChannelState.remoteForwardingPolicy,
 * persisted) and used by getPrivateChannelRoutingHints and
 * buildBlindedPaymentPaths ahead of our defaults.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { Network } from '../../src/lightning/invoice/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelUpdateMessage } from '../../src/lightning/gossip/types';
import { encodeChannelUpdateMessage } from '../../src/lightning/gossip/messages';
import { signChannelUpdate } from '../../src/lightning/gossip/validation';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`peer-policy-${id}`))
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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
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
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret
	};
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

/** channel_update for the PEER→alice direction, signed with `nodePrivkey`. */
function makePeerUpdate(
	scid: Buffer,
	direction: number,
	nodePrivkey: Buffer,
	opts?: {
		timestamp?: number;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
		cltvExpiryDelta?: number;
	}
): { msg: IChannelUpdateMessage; payload: Buffer } {
	const msg: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: Buffer.alloc(32, 0x06),
		shortChannelId: scid,
		timestamp: opts?.timestamp ?? Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: direction,
		cltvExpiryDelta: opts?.cltvExpiryDelta ?? 80,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: opts?.feeBaseMsat ?? 2500,
		feeProportionalMillionths: opts?.feeProportionalMillionths ?? 150,
		htlcMaximumMsat: 900_000_000n
	};
	const unsigned = encodeChannelUpdateMessage(msg);
	msg.signature = signChannelUpdate(unsigned, nodePrivkey);
	const payload = encodeChannelUpdateMessage(msg);
	return { msg, payload };
}

describe('Private-channel peer forwarding policy', function () {
	function setup(): {
		alice: LightningNode;
		bob: LightningNode;
		channelId: Buffer;
		scid: Buffer;
		bobDirection: number;
		bobNodePrivkey: Buffer;
	} {
		const aliceCfg = makeNodeConfig(1);
		const bobCfg = makeNodeConfig(2);
		const alice = new LightningNode(aliceCfg);
		const bob = new LightningNode(bobCfg);
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);

		const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);

		// Private channel: no announcement, no real SCID in the graph — give it
		// the alias the peer would use to route to alice.
		const scid = crypto.randomBytes(8);
		const state = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		state.scidAlias = scid;

		// Direction bit: the update author is the LEXICOGRAPHICALLY ordered side.
		const aliceId = Buffer.from(alice.getNodeId(), 'hex');
		const bobId = Buffer.from(bob.getNodeId(), 'hex');
		const bobDirection = Buffer.compare(aliceId, bobId) < 0 ? 1 : 0;

		return {
			alice,
			bob,
			channelId,
			scid,
			bobDirection,
			bobNodePrivkey: bobCfg.nodePrivateKey
		};
	}

	it('adopts a signature-verified direct channel_update and uses it in route hints', function () {
		const { alice, channelId, scid, bobDirection, bobNodePrivkey } = setup();

		const { payload } = makePeerUpdate(scid, bobDirection, bobNodePrivkey, {
			feeBaseMsat: 2500,
			feeProportionalMillionths: 150,
			cltvExpiryDelta: 80
		});
		alice.handlePeerMessage(
			'', // sender identity is not what authenticates the update
			MessageType.CHANNEL_UPDATE,
			payload
		);

		const state = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		expect(state.remoteForwardingPolicy, 'policy adopted').to.exist;
		expect(state.remoteForwardingPolicy!.feeBaseMsat).to.equal(2500);
		expect(state.remoteForwardingPolicy!.feeProportionalMillionths).to.equal(
			150
		);
		expect(state.remoteForwardingPolicy!.cltvExpiryDelta).to.equal(80);

		// Route hints now carry the PEER's policy, not our defaults.
		const hints = (
			alice as unknown as {
				getPrivateChannelRoutingHints(): Array<
					Array<{
						feeBaseMsat: number;
						feeProportionalMillionths: number;
						cltvExpiryDelta: number;
					}>
				>;
			}
		).getPrivateChannelRoutingHints();
		expect(hints.length).to.equal(1);
		expect(hints[0][0].feeBaseMsat).to.equal(2500);
		expect(hints[0][0].feeProportionalMillionths).to.equal(150);
		expect(hints[0][0].cltvExpiryDelta).to.equal(80);
	});

	it('uses the peer policy in blinded-path payment_relay', function () {
		const { alice, scid, bobDirection, bobNodePrivkey } = setup();
		void scid;

		const { payload } = makePeerUpdate(scid, bobDirection, bobNodePrivkey, {
			feeBaseMsat: 3210,
			feeProportionalMillionths: 42,
			cltvExpiryDelta: 96
		});
		alice.handlePeerMessage('', MessageType.CHANNEL_UPDATE, payload);

		const paths = (
			alice as unknown as {
				buildBlindedPaymentPaths(
					asyncHold: boolean,
					numHops: number
				): Array<{
					payInfo: {
						feeBaseMsat: number;
						feeProportionalMillionths: number;
						cltvExpiryDelta: number;
					};
				}>;
			}
		).buildBlindedPaymentPaths(false, 2);
		expect(paths.length).to.be.gte(1);
		expect(paths[0].payInfo.feeBaseMsat).to.equal(3210);
		expect(paths[0].payInfo.feeProportionalMillionths).to.equal(42);
		expect(paths[0].payInfo.cltvExpiryDelta).to.equal(96);
	});

	it('rejects an update not signed by the channel peer', function () {
		const { alice, channelId, scid, bobDirection } = setup();

		// Signed by a THIRD party's key: must be ignored.
		const mallory = crypto
			.createHash('sha256')
			.update(Buffer.from('mallory'))
			.digest();
		const { payload } = makePeerUpdate(scid, bobDirection, mallory);
		alice.handlePeerMessage('', MessageType.CHANNEL_UPDATE, payload);

		const state = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		expect(state.remoteForwardingPolicy ?? null).to.equal(null);
	});

	it('ignores our own update echoed back (wrong direction bit)', function () {
		const { alice, channelId, scid, bobDirection, bobNodePrivkey } = setup();

		// Peer's key but OUR direction: the signer check must reject it.
		const { payload } = makePeerUpdate(scid, bobDirection ^ 1, bobNodePrivkey);
		alice.handlePeerMessage('', MessageType.CHANNEL_UPDATE, payload);

		const state = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		expect(state.remoteForwardingPolicy ?? null).to.equal(null);
	});

	it('keeps only the newest policy by timestamp', function () {
		const { alice, channelId, scid, bobDirection, bobNodePrivkey } = setup();
		const now = Math.floor(Date.now() / 1000);

		const first = makePeerUpdate(scid, bobDirection, bobNodePrivkey, {
			timestamp: now,
			feeBaseMsat: 5000
		});
		alice.handlePeerMessage('', MessageType.CHANNEL_UPDATE, first.payload);

		// An OLDER update must not replace the stored policy.
		const older = makePeerUpdate(scid, bobDirection, bobNodePrivkey, {
			timestamp: now - 100,
			feeBaseMsat: 1
		});
		alice.handlePeerMessage('', MessageType.CHANNEL_UPDATE, older.payload);

		const state = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		expect(state.remoteForwardingPolicy!.feeBaseMsat).to.equal(5000);

		// A NEWER one does.
		const newer = makePeerUpdate(scid, bobDirection, bobNodePrivkey, {
			timestamp: now + 100,
			feeBaseMsat: 7777
		});
		alice.handlePeerMessage('', MessageType.CHANNEL_UPDATE, newer.payload);
		expect(state.remoteForwardingPolicy!.feeBaseMsat).to.equal(7777);
	});

	it('persists the policy across a serialize/deserialize round-trip', function () {
		const { alice, channelId, scid, bobDirection, bobNodePrivkey } = setup();

		const { payload } = makePeerUpdate(scid, bobDirection, bobNodePrivkey, {
			feeBaseMsat: 1234,
			feeProportionalMillionths: 55,
			cltvExpiryDelta: 72
		});
		alice.handlePeerMessage('', MessageType.CHANNEL_UPDATE, payload);

		const state = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		const restored = deserializeChannelState(serializeChannelState(state));
		expect(restored.remoteForwardingPolicy).to.deep.equal(
			state.remoteForwardingPolicy
		);
	});
});
