/**
 * EXPERIMENTAL zero-reserve extension: 0 sat channel_reserve on both sides of
 * a v1 open between trusted beignet peers that both advertise the
 * experimental_zero_reserve init capability.
 *
 * This deliberately extends BOLT 2 (the spec floors the reserve at the dust
 * limit), which is why every gate is explicit: trusted set membership, the
 * capability on both sides, and an exact-0 carve-out in validation. Nothing
 * changes for ordinary opens.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decodeOpenChannelMessage } from '../../src/lightning/message/channel-open';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { MessageType } from '../../src/lightning/message/types';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`zero-reserve-seed-${id}`))
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

function makeConfig(
	seedId: number,
	extra: Partial<IChannelManagerConfig> = {}
): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		...extra
	};
}

describe('Experimental zero-reserve opens (ChannelManager level)', function () {
	const aliceConfig = makeConfig(1);
	const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
	const bobSeedId = 2;
	const bobPubkey =
		makeConfig(bobSeedId).localBasepoints.fundingPubkey.toString('hex');

	function pair(bobExtra: Partial<IChannelManagerConfig> = {}): {
		alice: ChannelManager;
		bob: ChannelManager;
	} {
		const alice = new ChannelManager(aliceConfig);
		const bob = new ChannelManager(makeConfig(bobSeedId, bobExtra));
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

	function openZeroReserve(
		alice: ChannelManager
	): ReturnType<ChannelManager['openChannel']> {
		return alice.openChannel(bobPubkey, 1_000_000n, undefined, undefined, {
			zeroReserve: true
		});
	}

	it('advertises a 0 reserve and the trusted acceptor reciprocates', function () {
		const { alice, bob } = pair();
		alice.addTrustedPeer(bobPubkey);
		bob.addTrustedPeer(alicePubkey);

		let openPayload: Buffer | null = null;
		alice.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type === MessageType.OPEN_CHANNEL) openPayload = payload;
			}
		);

		const channel = openZeroReserve(alice);

		const open = decodeOpenChannelMessage(openPayload!);
		expect(open.channelReserveSatoshis).to.equal(0n);
		// zeroReserve implies trusted: the zero_conf channel type rides along.
		expect(
			FeatureFlags.fromBuffer(open.channelType!).hasFeature(Feature.ZERO_CONF)
		).to.be.true;

		const openerState = channel.getFullState();
		expect(openerState.state).to.equal(ChannelState.SENT_ACCEPT);
		expect(openerState.zeroReserve).to.be.true;
		expect(openerState.localConfig.channelReserveSatoshis).to.equal(0n);
		// The acceptor answered with a 0 reserve of its own.
		expect(openerState.remoteConfig.channelReserveSatoshis).to.equal(0n);

		const bobChannel = bob.getTempChannel(openerState.temporaryChannelId)!;
		const acceptorState = bobChannel.getFullState();
		expect(acceptorState.zeroReserve).to.be.true;
		expect(acceptorState.localConfig.channelReserveSatoshis).to.equal(0n);
	});

	it('throws without trust', function () {
		const { alice } = pair();
		expect(() => openZeroReserve(alice)).to.throw('not in the trusted set');
	});

	it('throws when our own config disables the extension', function () {
		const alice = new ChannelManager(
			makeConfig(1, { experimentalZeroReserve: false })
		);
		alice.on('error', () => {});
		alice.addTrustedPeer(bobPubkey);
		expect(() => openZeroReserve(alice)).to.throw('experimental_zero_reserve');
	});

	it('an untrusted acceptor rejects a 0 reserve', function () {
		const { alice, bob } = pair();
		alice.addTrustedPeer(bobPubkey);
		// bob does NOT trust alice.
		const errors: string[] = [];
		bob.on('error', (_cid: unknown, msg: string) => errors.push(msg));

		const channel = openZeroReserve(alice);
		expect(channel.getFullState().state).to.equal(ChannelState.SENT_OPEN);
		expect(errors.length).to.be.greaterThan(0);
	});

	it('an acceptor with the extension disabled rejects a 0 reserve', function () {
		const { alice, bob } = pair({ experimentalZeroReserve: false });
		alice.addTrustedPeer(bobPubkey);
		bob.addTrustedPeer(alicePubkey);
		const errors: string[] = [];
		bob.on('error', (_cid: unknown, msg: string) => errors.push(msg));

		const channel = openZeroReserve(alice);
		expect(channel.getFullState().state).to.equal(ChannelState.SENT_OPEN);
		// The gate never arms, so the 0 reserve fails the plain BOLT 2 check.
		expect(
			errors.some((e) => /channel_reserve/.test(e)),
			`reserve rejection reported (got: ${errors.join(' | ')})`
		).to.be.true;
	});

	it('a plain trusted open between capable peers keeps the standard reserve', function () {
		const { alice, bob } = pair();
		alice.addTrustedPeer(bobPubkey);
		bob.addTrustedPeer(alicePubkey);

		const channel = alice.openChannel(
			bobPubkey,
			1_000_000n,
			undefined,
			undefined,
			{ trusted: true }
		);
		const st = channel.getFullState();
		expect(st.zeroReserve ?? false).to.be.false;
		expect(st.remoteConfig.channelReserveSatoshis).to.equal(10_000n);
	});

	it('zeroReserve survives a serialization round-trip', function () {
		const { alice, bob } = pair();
		alice.addTrustedPeer(bobPubkey);
		bob.addTrustedPeer(alicePubkey);
		const channel = openZeroReserve(alice);
		const restored = deserializeChannelState(
			serializeChannelState(channel.getFullState())
		);
		expect(restored.zeroReserve).to.be.true;
		expect(restored.localConfig.channelReserveSatoshis).to.equal(0n);
	});
});

describe('Experimental zero-reserve lifecycle (LightningNode level)', function () {
	function nodeSeed(id: number): Buffer {
		return crypto
			.createHash('sha256')
			.update(Buffer.from(`zero-reserve-node-seed-${id}`))
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
			true,
			true // zeroReserve
		);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		return { alice, bob, channelId };
	}

	it('a payment below the old 1% reserve floor settles', function () {
		const { alice, bob, channelId } = nodePair();
		expect(
			alice.getChannelManager().getChannel(channelId)!.getState()
		).to.equal(ChannelState.NORMAL);

		// 997k of 1M: leaves alice ~3k sats, far under the 10k (1%) reserve a
		// standard open enforces. Only possible with a 0 sat reserve; the
		// remaining balance covers the opener's commitment fee and anchors.
		const inv = bob.createInvoice({
			amountMsat: 997_000_000n,
			description: 'spend past the old reserve'
		});
		const res = alice.sendPayment(inv.bolt11);
		expect(res.status).to.equal(PaymentStatus.COMPLETED);
	});

	it('the receiver can spend the whole balance back (no reserve either side)', function () {
		const { alice, bob } = nodePair();
		const inv = bob.createInvoice({
			amountMsat: 900_000_000n,
			description: 'load the far side'
		});
		expect(alice.sendPayment(inv.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);

		// Bob, the acceptor, now spends every sat back: an acceptor holds no
		// commitment-fee obligation, so with a 0 reserve nothing is held back.
		const inv2 = alice.createInvoice({
			amountMsat: 900_000_000n,
			description: 'and all the way back'
		});
		expect(bob.sendPayment(inv2.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('force-close still works from the drained state', function () {
		const { alice, bob, channelId } = nodePair();
		const inv = bob.createInvoice({
			amountMsat: 997_000_000n,
			description: 'drain'
		});
		expect(alice.sendPayment(inv.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);

		// The drained opener can still exit unilaterally: the stored commitment
		// signature must rebuild and sign at the near-zero balance.
		const dest = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			crypto.randomBytes(20)
		]);
		const result = alice.forceCloseChannel(channelId, dest);
		expect(result.ok, result.error ?? '').to.be.true;
	});

	it('splice-out quote on a zero-reserve channel holds nothing back', function () {
		const { alice, channelId } = nodePair();
		const quote = alice.spliceQuote(channelId, 'out', 253);
		// A standard channel reports the peer-imposed reserve here (10k on 1M);
		// the zero-reserve channel reports 0 and the whole local balance is
		// spendable less the splice fee.
		expect(quote.reserveSats).to.equal(0);
		expect(quote.spendableSats).to.equal(1_000_000);
		expect(quote.maxAmountSats).to.equal(1_000_000 - quote.feeSats);
	});

	it('zeroReserve peers get option_dual_fund withheld from init', function () {
		const alice = new LightningNode(makeNodeConfig(1));
		const peer = getPublicKey(crypto.randomBytes(32)).toString('hex');
		const base = LightningNode.defaultFeatures();
		expect(base.hasFeature(Feature.DUAL_FUND)).to.be.true;
		expect(base.hasFeature(Feature.EXPERIMENTAL_ZERO_RESERVE)).to.be.true;

		// Unmarked peer: features pass through untouched.
		expect(alice.initFeaturesFor(peer, base).hasFeature(Feature.DUAL_FUND)).to
			.be.true;

		// Marked peer: DUAL_FUND withheld (a zero reserve is v1-only and BOLT 2
		// forbids open_channel once dual_fund is negotiated), capability kept.
		alice.markZeroReservePeer(peer);
		const filtered = alice.initFeaturesFor(peer, base);
		expect(filtered.hasFeature(Feature.DUAL_FUND)).to.be.false;
		expect(filtered.hasFeature(Feature.EXPERIMENTAL_ZERO_RESERVE)).to.be.true;
		// The shared instance was not mutated.
		expect(base.hasFeature(Feature.DUAL_FUND)).to.be.true;

		alice.unmarkZeroReservePeer(peer);
		expect(alice.initFeaturesFor(peer, base).hasFeature(Feature.DUAL_FUND)).to
			.be.true;
	});

	it('a node with the extension disabled does not advertise the capability', function () {
		// The constructor clears the bit from the feature set it was given; a
		// fresh default set carries it.
		const features = LightningNode.defaultFeatures();
		expect(features.hasFeature(Feature.EXPERIMENTAL_ZERO_RESERVE)).to.be.true;
		const node = new LightningNode({
			...makeNodeConfig(3),
			localFeatures: features,
			experimentalZeroReserve: false
		});
		void node;
		expect(features.hasFeature(Feature.EXPERIMENTAL_ZERO_RESERVE)).to.be.false;
	});
});
