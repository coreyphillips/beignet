/**
 * option_wumbo (large_channels, bit 18): the largeChannels config flag lifts
 * the BOLT 2 2^24 sat funding cap to MAX_WUMBO_FUNDING_SATOSHIS, gated on the
 * peer having advertised the bit in its init features. Covers cap enforcement
 * and lifting on both the opener and acceptor roles, feature-bit gating and
 * advertising, and the splice growth checks.
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
	MAX_FUNDING_SATOSHIS,
	MAX_WUMBO_FUNDING_SATOSHIS
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { validateOpenChannelParams } from '../../src/lightning/channel/validation';
import { IOpenChannelMessage } from '../../src/lightning/message/channel-open';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';

const WUMBO_FUNDING = 20_000_000n; // above 2^24, below the wumbo ceiling

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`wumbo-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
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
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		htlcBasepointSecret
	};
}

function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyB) {
				managerB.handleMessage(pubkeyA, type, payload);
			}
		}
	);
	managerB.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyA) {
				managerA.handleMessage(pubkeyB, type, payload);
			}
		}
	);
}

function wumboFeatures(): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.LARGE_CHANNELS);
	return flags;
}

/**
 * Loopback managers have no real PeerManager, so maxFundingForPeer sees no
 * peer init. This fake supplies the peer's advertised init features while
 * sendToPeer throws, which routes messages through the same 'message:outbound'
 * loopback as a manager without a PeerManager.
 */
type FakeRemoteInit = { features: FeatureFlags };

function fakePeerManager(features: FeatureFlags): unknown {
	return {
		getPeer: (): { getRemoteInit: () => FakeRemoteInit } => ({
			getRemoteInit: (): FakeRemoteInit => ({ features })
		}),
		sendToPeer: (): never => {
			throw new Error('loopback');
		}
	};
}

describe('option_wumbo (large_channels)', function () {
	const aliceConfig = makeConfig(1);
	const bobConfig = makeConfig(2);
	const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
	const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

	describe('validateOpenChannelParams cap', function () {
		function openMsg(fundingSatoshis: bigint): IOpenChannelMessage {
			const bp = makeBasepoints(makeSeed(9));
			return {
				chainHash: Buffer.alloc(32),
				temporaryChannelId: Buffer.alloc(32),
				fundingSatoshis,
				pushMsat: 0n,
				dustLimitSatoshis: 354n,
				maxHtlcValueInFlightMsat: 500_000_000n,
				channelReserveSatoshis: 10_000n,
				htlcMinimumMsat: 1_000n,
				feeratePerKw: 253,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: bp.fundingPubkey,
				revocationBasepoint: bp.revocationBasepoint,
				paymentBasepoint: bp.paymentBasepoint,
				delayedPaymentBasepoint: bp.delayedPaymentBasepoint,
				htlcBasepoint: bp.htlcBasepoint,
				firstPerCommitmentPoint: bp.fundingPubkey,
				channelFlags: 0x01
			};
		}

		it('rejects funding above 2^24 sat with the default cap', function () {
			const err = validateOpenChannelParams(openMsg(WUMBO_FUNDING));
			expect(err).to.include('exceeds maximum');
			expect(err).to.include(String(MAX_FUNDING_SATOSHIS));
		});

		it('accepts the same funding when the cap is lifted', function () {
			const err = validateOpenChannelParams(
				openMsg(WUMBO_FUNDING),
				MAX_WUMBO_FUNDING_SATOSHIS
			);
			expect(err).to.equal(null);
		});

		it('still rejects funding above the 10 BTC wumbo ceiling', function () {
			const err = validateOpenChannelParams(
				openMsg(MAX_WUMBO_FUNDING_SATOSHIS + 1n),
				MAX_WUMBO_FUNDING_SATOSHIS
			);
			expect(err).to.include('exceeds maximum');
		});
	});

	describe('opener role', function () {
		it('rejects a wumbo open when largeChannels is off', function () {
			const alice = new ChannelManager(aliceConfig);
			const bob = new ChannelManager(bobConfig);
			connectManagers(alice, alicePubkey, bob, bobPubkey);

			const errors: string[] = [];
			alice.on('error', (_id: Buffer | null, message: string) =>
				errors.push(message)
			);

			const channel = alice.openChannel(bobPubkey, WUMBO_FUNDING);
			expect(channel.getState()).to.equal(ChannelState.NONE);
			expect(errors.some((e) => e.includes('exceeds maximum'))).to.equal(true);
		});

		it('rejects a wumbo open when the peer did not advertise the bit', function () {
			const alice = new ChannelManager({
				...aliceConfig,
				largeChannels: true
			});
			const bob = new ChannelManager(bobConfig);
			connectManagers(alice, alicePubkey, bob, bobPubkey);
			// Peer init present but WITHOUT large_channels.
			(alice as unknown as { peerManager: unknown }).peerManager =
				fakePeerManager(FeatureFlags.empty());

			const errors: string[] = [];
			alice.on('error', (_id: Buffer | null, message: string) =>
				errors.push(message)
			);

			const channel = alice.openChannel(bobPubkey, WUMBO_FUNDING);
			expect(channel.getState()).to.equal(ChannelState.NONE);
			expect(errors.some((e) => e.includes('exceeds maximum'))).to.equal(true);
		});

		it('opens a wumbo channel through to NORMAL when both sides negotiated the bit', function () {
			const alice = new ChannelManager({
				...aliceConfig,
				largeChannels: true
			});
			const bob = new ChannelManager({ ...bobConfig, largeChannels: true });
			connectManagers(alice, alicePubkey, bob, bobPubkey);
			(alice as unknown as { peerManager: unknown }).peerManager =
				fakePeerManager(wumboFeatures());
			(bob as unknown as { peerManager: unknown }).peerManager =
				fakePeerManager(wumboFeatures());

			const errors: string[] = [];
			alice.on('error', (_id: Buffer | null, m: string) => errors.push(m));
			bob.on('error', (_id: Buffer | null, m: string) => errors.push(m));

			const channel = alice.openChannel(bobPubkey, WUMBO_FUNDING);
			expect(channel.getState()).to.equal(ChannelState.SENT_ACCEPT);

			const fundingTxid = crypto.randomBytes(32);
			const channelId = alice.createFunding(
				channel,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);

			expect(errors).to.deep.equal([]);
			expect(alice.getChannel(channelId)!.getState()).to.equal(
				ChannelState.NORMAL
			);
			expect(bob.getChannel(channelId)!.getState()).to.equal(
				ChannelState.NORMAL
			);
		});
	});

	describe('acceptor role', function () {
		it('rejects an incoming wumbo open when largeChannels is off', function () {
			const alice = new ChannelManager({
				...aliceConfig,
				largeChannels: true
			});
			const bob = new ChannelManager(bobConfig);
			connectManagers(alice, alicePubkey, bob, bobPubkey);
			(alice as unknown as { peerManager: unknown }).peerManager =
				fakePeerManager(wumboFeatures());

			const bobErrors: string[] = [];
			bob.on('error', (_id: Buffer | null, m: string) => bobErrors.push(m));

			const channel = alice.openChannel(bobPubkey, WUMBO_FUNDING);
			// Alice sent the open (her cap was lifted); Bob refused to accept it.
			expect(channel.getState()).to.equal(ChannelState.SENT_OPEN);
			expect(bobErrors.some((e) => e.includes('exceeds maximum'))).to.equal(
				true
			);
		});

		it('rejects an incoming wumbo open when the (spoofing) peer never advertised the bit', function () {
			const alice = new ChannelManager({
				...aliceConfig,
				largeChannels: true
			});
			const bob = new ChannelManager({ ...bobConfig, largeChannels: true });
			connectManagers(alice, alicePubkey, bob, bobPubkey);
			(alice as unknown as { peerManager: unknown }).peerManager =
				fakePeerManager(wumboFeatures());
			// Bob has the flag on, but Alice's init did not advertise the bit.
			(bob as unknown as { peerManager: unknown }).peerManager =
				fakePeerManager(FeatureFlags.empty());

			const bobErrors: string[] = [];
			bob.on('error', (_id: Buffer | null, m: string) => bobErrors.push(m));

			alice.openChannel(bobPubkey, WUMBO_FUNDING);
			expect(bobErrors.some((e) => e.includes('exceeds maximum'))).to.equal(
				true
			);
		});
	});

	describe('feature-bit advertising', function () {
		function nodeConfigFeatures(largeChannels: boolean): FeatureFlags {
			const seed = makeSeed(50);
			const flags = LightningNode.defaultFeatures();
			const node = new LightningNode({
				nodePrivateKey: crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from('node-identity'))
					.digest(),
				network: Network.REGTEST,
				channelBasepoints: makeBasepoints(seed),
				perCommitmentSeed: makeSeed(150),
				fundingPrivkey: crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([0]))
					.digest(),
				localFeatures: flags,
				largeChannels
			});
			node.on('node:error', () => {});
			node.destroy();
			return flags;
		}

		it('advertises large_channels in init features only when enabled', function () {
			expect(
				nodeConfigFeatures(true).hasFeature(Feature.LARGE_CHANNELS)
			).to.equal(true);
			expect(
				nodeConfigFeatures(false).hasFeature(Feature.LARGE_CHANNELS)
			).to.equal(false);
		});
	});

	describe('splice growth cap', function () {
		function normalChannel(fundingSatoshis: bigint): Channel {
			const seed = makeSeed(60);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(160)
			});
			state.state = ChannelState.NORMAL;
			state.channelId = crypto.randomBytes(32);
			state.localBalanceMsat = fundingSatoshis * 1000n;
			return new Channel(state);
		}

		it('rejects a splice-in that would exceed the default cap', function () {
			const channel = normalChannel(16_000_000n);
			const actions = channel.initiateSplice(1_000_000n, 500);
			const error = actions.find((a) => a.type === ChannelActionType.ERROR) as
				| { type: ChannelActionType; message: string }
				| undefined;
			expect(error).to.exist;
			expect(error!.message).to.include('exceeds maximum');
		});

		it('allows the same splice-in when the cap is lifted', function () {
			const channel = normalChannel(16_000_000n);
			channel.setMaxFundingSatoshis(MAX_WUMBO_FUNDING_SATOSHIS);
			const actions = channel.initiateSplice(1_000_000n, 500);
			expect(actions.some((a) => a.type === ChannelActionType.ERROR)).to.equal(
				false
			);
		});
	});
});
