/**
 * Trusted channel opens: zero-conf toward a peer in the trusted set
 * (openChannel opts.trusted / LightningNode.openChannel(..., trusted)).
 *
 * The zero_conf channel type (BOLT 2 feature 50) rides the wire, the trusted
 * acceptor answers minimum_depth 0, and both sides fast-track channel_ready
 * so the channel is NORMAL before the funding tx confirms. Every other
 * parameter, the channel reserve included, stays standard BOLT 2.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`trusted-open-seed-${id}`))
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

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey
	};
}

describe('Trusted channel opens (zero-conf, v1 path)', function () {
	const aliceConfig = makeConfig(1);
	const bobConfig = makeConfig(2);
	const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
	const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

	function createConnectedManagerPair(): {
		alice: ChannelManager;
		bob: ChannelManager;
	} {
		const alice = new ChannelManager(aliceConfig);
		const bob = new ChannelManager(bobConfig);
		alice.on('error', () => {});
		bob.on('error', () => {});
		alice.on(
			'message:outbound',
			(peerPubkey: string, type: number, payload: Buffer) => {
				if (peerPubkey === bobPubkey) {
					bob.handleMessage(alicePubkey, type, payload);
				}
			}
		);
		bob.on(
			'message:outbound',
			(peerPubkey: string, type: number, payload: Buffer) => {
				if (peerPubkey === alicePubkey) {
					alice.handleMessage(bobPubkey, type, payload);
				}
			}
		);
		return { alice, bob };
	}

	function trustedPair(): { alice: ChannelManager; bob: ChannelManager } {
		const pair = createConnectedManagerPair();
		pair.alice.addTrustedPeer(bobPubkey);
		pair.bob.addTrustedPeer(alicePubkey);
		return pair;
	}

	it('throws when the peer is not in the trusted set', function () {
		const { alice } = createConnectedManagerPair();
		expect(() =>
			alice.openChannel(bobPubkey, 1_000_000n, undefined, undefined, {
				trusted: true
			})
		).to.throw('not in the trusted set');
	});

	it('open_channel carries zero_conf + scid_alias, private, standard reserve', function () {
		const { alice, bob } = createConnectedManagerPair();
		alice.addTrustedPeer(bobPubkey);
		bob.addTrustedPeer(alicePubkey);

		let openPayload: Buffer | null = null;
		alice.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type === MessageType.OPEN_CHANNEL) openPayload = payload;
			}
		);

		const channel = alice.openChannel(
			bobPubkey,
			1_000_000n,
			undefined,
			undefined,
			{ trusted: true }
		);

		expect(openPayload).to.not.be.null;
		const open = decodeOpenChannelMessage(openPayload!);
		// The reserve is untouched by trust: the standard 1% formula.
		expect(open.channelReserveSatoshis).to.equal(10_000n);
		expect(open.channelType).to.exist;
		const bits = FeatureFlags.fromBuffer(open.channelType!);
		expect(bits.hasFeature(Feature.ZERO_CONF)).to.be.true;
		// BOLT 9: option_zeroconf depends on option_scid_alias; the vector must
		// carry its transitive dependencies.
		expect(bits.hasFeature(Feature.SCID_ALIAS)).to.be.true;
		// BOLT 2: a channel_type carrying option_scid_alias must not be
		// announced, so the open goes out private on both the wire and our own
		// record of it.
		expect(open.channelFlags & 0x01).to.equal(0);
		expect(channel.getFullState().announceChannel).to.be.false;
	});

	it('trusted acceptor answers minimum_depth 0; reserves stay standard', function () {
		const { alice, bob } = trustedPair();

		const channel = alice.openChannel(
			bobPubkey,
			1_000_000n,
			undefined,
			undefined,
			{ trusted: true }
		);

		const openerState = channel.getFullState();
		expect(openerState.state).to.equal(ChannelState.SENT_ACCEPT);
		expect(openerState.minimumDepth).to.equal(0);
		// The acceptor's accept_channel advertised the standard reserve back.
		expect(openerState.remoteConfig.channelReserveSatoshis).to.equal(10_000n);

		const bobChannel = bob.getTempChannel(openerState.temporaryChannelId);
		expect(bobChannel).to.exist;
		const acceptorState = bobChannel!.getFullState();
		expect(acceptorState.zeroConfEnabled).to.be.true;
		expect(acceptorState.minimumDepth).to.equal(0);
		expect(acceptorState.localConfig.channelReserveSatoshis).to.equal(10_000n);
		// The acceptor recorded the private announce_channel bit from the wire.
		expect(acceptorState.announceChannel).to.be.false;
	});

	it('an untrusted acceptor rejects the zero_conf proposal', function () {
		const { alice, bob } = createConnectedManagerPair();
		// Only alice declares trust; bob does not trust alice.
		alice.addTrustedPeer(bobPubkey);

		const errors: string[] = [];
		bob.on('error', (_cid: unknown, msg: string) => errors.push(msg));

		const channel = alice.openChannel(
			bobPubkey,
			1_000_000n,
			undefined,
			undefined,
			{ trusted: true }
		);

		// Bob rejected the proposal, so alice never received accept_channel.
		expect(channel.getFullState().state).to.equal(ChannelState.SENT_OPEN);
		expect(errors.some((e) => /trusted peer/.test(e))).to.be.true;
	});

	it('trust-set membership alone does not change an ordinary open', function () {
		// Bob trusts alice, but alice opens a NORMAL channel (no zero_conf
		// type). Bob must treat it exactly like any other open: a real
		// confirmation depth and no zero-conf fast-track. A stale trusted-peer
		// entry must never widen into special validation for every inbound open.
		const { alice, bob } = createConnectedManagerPair();
		bob.addTrustedPeer(alicePubkey);

		const channel = alice.openChannel(bobPubkey, 1_000_000n);
		const openerState = channel.getFullState();
		expect(openerState.state).to.equal(ChannelState.SENT_ACCEPT);
		// The acceptor answered with its normal confirmation depth.
		expect(openerState.minimumDepth).to.equal(3);

		const bobChannel = bob.getTempChannel(openerState.temporaryChannelId);
		expect(bobChannel).to.exist;
		const acceptorState = bobChannel!.getFullState();
		expect(acceptorState.trustedPeer).to.be.true;
		expect(acceptorState.zeroConfEnabled).to.be.false;
		expect(acceptorState.minimumDepth).to.equal(3);
	});

	it('rejects a zero_conf accept_channel with a nonzero minimum_depth', function () {
		// BOLT 2: for option_zeroconf the accepter MUST set minimum_depth 0. A
		// disagreement is surfaced as an error, not silently ignored. Capture a
		// real accept_channel from a wired pair, then replay a tampered copy
		// against an UNWIRED opener (no loopback) still in SENT_OPEN.
		const wired = trustedPair();
		let acceptPayload: Buffer | null = null;
		wired.bob.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type === MessageType.ACCEPT_CHANNEL) acceptPayload = payload;
			}
		);
		wired.alice.openChannel(bobPubkey, 1_000_000n, undefined, undefined, {
			trusted: true
		});
		expect(acceptPayload).to.not.be.null;

		const lonely = new ChannelManager(aliceConfig);
		lonely.on('error', () => {});
		lonely.addTrustedPeer(bobPubkey);
		const channel = lonely.openChannel(
			bobPubkey,
			1_000_000n,
			undefined,
			undefined,
			{ trusted: true }
		);
		expect(channel.getFullState().state).to.equal(ChannelState.SENT_OPEN);

		const tampered = decodeAcceptChannelMessage(acceptPayload!);
		tampered.temporaryChannelId = channel.getTemporaryChannelId();
		tampered.minimumDepth = 3;

		const actions = channel.handleAcceptChannel(tampered);
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as
			| { message: string }
			| undefined;
		expect(err, 'tampered accept rejected').to.exist;
		expect(err!.message).to.include('minimum_depth');
	});

	it('both sides reach NORMAL before the funding tx confirms', function () {
		const { alice, bob } = trustedPair();

		const channel = alice.openChannel(
			bobPubkey,
			1_000_000n,
			undefined,
			undefined,
			{ trusted: true }
		);

		const fundingTxid = crypto.randomBytes(32);
		const channelId = alice.createFunding(
			channel,
			fundingTxid,
			0,
			crypto.randomBytes(64)
		)!;
		expect(channelId).to.not.be.null;

		// No handleFundingConfirmed on either side: zero-conf means the
		// funding_signed / channel_ready exchange alone brings the channel up.
		const aliceChannel = alice.getChannel(channelId)!;
		const bobChannel = bob.getChannel(channelId)!;
		expect(aliceChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(bobChannel.getState()).to.equal(ChannelState.NORMAL);
	});

	it('a normal open is unaffected: 1% reserve and confirmation wait', function () {
		const { alice } = createConnectedManagerPair();

		let openPayload: Buffer | null = null;
		alice.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type === MessageType.OPEN_CHANNEL) openPayload = payload;
			}
		);

		const channel = alice.openChannel(bobPubkey, 1_000_000n);
		expect(openPayload).to.not.be.null;
		const open = decodeOpenChannelMessage(openPayload!);
		expect(open.channelReserveSatoshis).to.equal(10_000n); // 1% of 1M
		const bits = open.channelType
			? FeatureFlags.fromBuffer(open.channelType)
			: FeatureFlags.empty();
		expect(bits.hasFeature(Feature.ZERO_CONF)).to.be.false;
		expect(bits.hasFeature(Feature.SCID_ALIAS)).to.be.false;
		// Ordinary opens keep announcing.
		expect(open.channelFlags & 0x01).to.equal(1);
		expect(channel.getFullState().zeroConfEnabled).to.be.false;
	});

	it('zero-conf flags survive a serialization round-trip', function () {
		const { alice } = trustedPair();
		const channel = alice.openChannel(
			bobPubkey,
			1_000_000n,
			undefined,
			undefined,
			{ trusted: true }
		);
		const state = channel.getFullState();
		const restored = deserializeChannelState(serializeChannelState(state));
		expect(restored.zeroConfEnabled).to.be.true;
		expect(restored.trustedPeer).to.be.true;
		expect(restored.minimumDepth).to.equal(0);
	});
});

describe('Trusted channel payments (LightningNode level)', function () {
	function nodeSeed(id: number): Buffer {
		return crypto
			.createHash('sha256')
			.update(Buffer.from(`trusted-pay-seed-${id}`))
			.digest();
	}

	function makeNodeConfig(seedId: number): INodeConfig {
		const seed = nodeSeed(seedId);
		return {
			nodePrivateKey: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from('node-identity'))
				.digest(),
			network: Network.REGTEST,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: makeBasepoints(seed),
			perCommitmentSeed: nodeSeed(seedId + 100),
			fundingPrivkey: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([0]))
				.digest(),
			// Secret behind makeBasepoints' htlcBasepoint (keys[4]): without it
			// per-HTLC signatures use a fallback key and the peer rejects them.
			htlcBasepointSecret: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([4]))
				.digest()
		};
	}

	function nodePair(): {
		alice: LightningNode;
		bob: LightningNode;
		channelId: Buffer;
	} {
		const alice = new LightningNode(makeNodeConfig(1));
		const bob = new LightningNode(makeNodeConfig(2));
		for (const n of [alice, bob]) {
			n.on('error', () => {});
			n.on('node:error', () => {});
		}
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === bob.getNodeId()) {
				bob.handlePeerMessage(alice.getNodeId(), t, p);
			}
		});
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === alice.getNodeId()) {
				alice.handlePeerMessage(bob.getNodeId(), t, p);
			}
		});
		alice.addTrustedPeer(bob.getNodeId());
		bob.addTrustedPeer(alice.getNodeId());
		const channel = alice.openChannel(
			bob.getNodeId(),
			1_000_000n,
			undefined,
			undefined,
			false,
			true
		);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		return { alice, bob, channelId };
	}

	it('the legacy openZeroConfChannel routes through the trusted open path', function () {
		// The old helper went straight to a v1 open_channel, which violates
		// BOLT 2 once option_dual_fund is negotiated. It now delegates to
		// openChannel(..., trusted), inheriting the v1/v2 routing, the
		// zero_conf + scid_alias channel type, and the private announce bit.
		const alice = new LightningNode(makeNodeConfig(1));
		const bob = new LightningNode(makeNodeConfig(2));
		for (const n of [alice, bob]) {
			n.on('error', () => {});
			n.on('node:error', () => {});
		}
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === bob.getNodeId()) {
				bob.handlePeerMessage(alice.getNodeId(), t, p);
			}
		});
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === alice.getNodeId()) {
				alice.handlePeerMessage(bob.getNodeId(), t, p);
			}
		});
		alice.addTrustedPeer(bob.getNodeId());
		bob.addTrustedPeer(alice.getNodeId());

		const channel = alice.openZeroConfChannel(bob.getNodeId(), 1_000_000n)!;
		const st = channel.getFullState();
		expect(st.zeroConfEnabled).to.be.true;
		expect(st.minimumDepth).to.equal(0);
		expect(st.announceChannel).to.be.false;
		const bits = FeatureFlags.fromBuffer(st.channelType!);
		expect(bits.hasFeature(Feature.ZERO_CONF)).to.be.true;
		expect(bits.hasFeature(Feature.SCID_ALIAS)).to.be.true;

		// An untrusted peer now throws (the routed path validates trust up
		// front) instead of the old emit-error-and-return-null behavior.
		const carol = new LightningNode(makeNodeConfig(3));
		carol.on('error', () => {});
		expect(() =>
			carol.openZeroConfChannel(alice.getNodeId(), 1_000_000n)
		).to.throw('not in the trusted set');
	});

	it('a trusted open fails clearly when zero-conf features are not negotiated', function () {
		// BOLT 2: do not propose channel-type features the peer never
		// negotiated. A node whose own init lacks option_zeroconf/scid_alias
		// (stand-in for an older peer in a mixed-version deployment) must
		// refuse up front, not send a proposal the peer rejects opaquely.
		const bare = LightningNode.defaultFeatures();
		bare.clearBit(Feature.ZERO_CONF);
		bare.clearBit(Feature.ZERO_CONF + 1);
		const alice = new LightningNode({
			...makeNodeConfig(1),
			localFeatures: bare
		});
		alice.on('error', () => {});
		const peer = getPublicKey(crypto.randomBytes(32)).toString('hex');
		alice.addTrustedPeer(peer);
		expect(() =>
			alice.openChannel(peer, 1_000_000n, undefined, undefined, false, true)
		).to.throw('did not negotiate option_zeroconf');
	});

	it('a payment settles before the funding tx confirms', function () {
		const { alice, bob, channelId } = nodePair();
		// Neither side has seen a confirmation.
		expect(
			alice.getChannelManager().getChannel(channelId)!.getState()
		).to.equal(ChannelState.NORMAL);
		expect(bob.getChannelManager().getChannel(channelId)!.getState()).to.equal(
			ChannelState.NORMAL
		);

		const inv = bob.createInvoice({
			amountMsat: 100_000_000n,
			description: 'zero-conf pay'
		});
		const res = alice.sendPayment(inv.bolt11);
		expect(res.status).to.equal(PaymentStatus.COMPLETED);
	});

	it('payments still route after the channel is announced in the graph', function () {
		// Companion to the standalone pathfinding regression test: the trusted
		// zero-conf channel keeps routing once announced.
		const { alice, bob, channelId } = nodePair();
		const aBuf = Buffer.from(alice.getNodeId(), 'hex');
		const bBuf = Buffer.from(bob.getNodeId(), 'hex');
		const [n1, n2] =
			Buffer.compare(aBuf, bBuf) < 0 ? [aBuf, bBuf] : [bBuf, aBuf];
		const scid = encodeShortChannelId({
			block: 20_045,
			txIndex: 1,
			outputIndex: 0
		});
		for (const n of [alice, bob]) {
			const g = n.getGraph();
			g.addChannelAnnouncement({
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: scid,
				nodeId1: n1,
				nodeId2: n2,
				bitcoinKey1: Buffer.alloc(33, 2),
				bitcoinKey2: Buffer.alloc(33, 3)
			});
			const base = {
				signature: Buffer.alloc(64),
				chainHash: REGTEST_CHAIN_HASH,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				htlcMaximumMsat: 500_000_000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1
			};
			g.applyChannelUpdate({ ...base });
			g.applyChannelUpdate({ ...base, channelFlags: 1 });
			const ch = n.getChannelManager().getChannel(channelId);
			if (ch) ch.getFullState().shortChannelId = scid;
			n.registerChannelScid(channelId, scid);
		}

		const inv = bob.createInvoice({
			amountMsat: 100_000_000n,
			description: 'after announcement'
		});
		const res = alice.sendPayment(inv.bolt11);
		expect(res.status).to.equal(PaymentStatus.COMPLETED);
	});
});
