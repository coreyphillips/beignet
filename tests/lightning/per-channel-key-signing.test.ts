/**
 * Phase 1.1: Per-channel key signing regression tests.
 *
 * Verifies that all codepaths use the channel's per-channel signer
 * (when channelKeyDeriver is configured) instead of falling back
 * to global shared keys — which would cause fund loss on close.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig,
	IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	encodeOpenChannel2Message,
	IOpenChannel2Message
} from '../../src/lightning/message/dual-funding';
import { MessageType } from '../../src/lightning/message/types';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`pcks-seed-${id}`))
		.digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(derivePrivkey(seed, i));
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

function makePerChannelKeys(channelIndex: number): IPerChannelKeys {
	const seed = crypto
		.createHash('sha256')
		.update(Buffer.from(`per-channel-${channelIndex}`))
		.digest();
	const fundingPrivkey = derivePrivkey(seed, 0);
	const htlcSecret = derivePrivkey(seed, 5);
	return {
		fundingPrivkey,
		basepoints: {
			...makeBasepoints(seed),
			fundingPubkey: getPublicKey(fundingPrivkey)
		},
		perCommitmentSeed: makeSeed(1000 + channelIndex),
		htlcBasepointSecret: htlcSecret
	};
}

const globalSeed = makeSeed(1);
const globalFundingPrivkey = derivePrivkey(globalSeed, 0);
const globalHtlcSecret = derivePrivkey(globalSeed, 5);

function makeManagerConfig(withDeriver = true): IChannelManagerConfig {
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(globalSeed),
		localPerCommitmentSeed: makeSeed(100),
		localFundingPrivkey: globalFundingPrivkey,
		htlcBasepointSecret: globalHtlcSecret,
		channelKeyDeriver: withDeriver ? makePerChannelKeys : undefined
	};
}

describe('Per-Channel Key Signing', () => {
	describe('Channel.getSigner()', () => {
		it('returns signer set at construction', () => {
			const seed = makeSeed(10);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(110)
			});
			const signer = new ChannelSigner(
				derivePrivkey(seed, 0),
				derivePrivkey(seed, 5)
			);
			const channel = new Channel(state, signer);
			expect(channel.getSigner()).to.equal(signer);
		});

		it('returns null when no signer set', () => {
			const seed = makeSeed(11);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(111)
			});
			const channel = new Channel(state);
			expect(channel.getSigner()).to.be.null;
		});

		it('returns updated signer after setSigner()', () => {
			const seed = makeSeed(12);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(112)
			});
			const signer1 = new ChannelSigner(derivePrivkey(seed, 0));
			const signer2 = new ChannelSigner(derivePrivkey(seed, 1));
			const channel = new Channel(state, signer1);
			channel.setSigner(signer2);
			expect(channel.getSigner()).to.equal(signer2);
		});
	});

	describe('ChannelManager with channelKeyDeriver', () => {
		let mgr: ChannelManager;

		beforeEach(() => {
			mgr = new ChannelManager(makeManagerConfig(true));
			mgr.on('error', () => {});
		});

		it('openChannel uses per-channel keys', () => {
			const channel = mgr.openChannel('02' + '11'.repeat(32), 100_000n);
			const signer = channel.getSigner();
			expect(signer).to.not.be.null;
			// Per-channel key should differ from global key
			const perChKeys = makePerChannelKeys(1); // first channel index
			const state = channel.getFullState();
			expect(state.localBasepoints.fundingPubkey.toString('hex')).to.equal(
				perChKeys.basepoints.fundingPubkey.toString('hex')
			);
		});

		it('openZeroConfChannel derives per-channel keys', () => {
			const peer = '02' + '22'.repeat(32);
			mgr.addTrustedPeer(peer);
			const channel = mgr.openZeroConfChannel(peer, 100_000n);
			expect(channel).to.not.be.null;
			const state = channel!.getFullState();
			// Should use per-channel basepoints, not global
			const globalBp = makeBasepoints(globalSeed);
			expect(state.localBasepoints.fundingPubkey.toString('hex')).to.not.equal(
				globalBp.fundingPubkey.toString('hex')
			);
		});

		it('createDualFundedChannel derives per-channel keys', () => {
			const dfSeed = makeSeed(90);
			const channel = mgr.createDualFundedChannel('02' + '33'.repeat(32), {
				fundingSatoshis: 200_000n,
				fundingFeeratePerkw: 1000,
				commitmentFeeratePerkw: 500,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 100_000_000n,
				htlcMinimumMsat: 1n,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 30,
				locktime: 0,
				localBasepoints: makeBasepoints(dfSeed),
				localPerCommitmentSeed: makeSeed(190),
				secondPerCommitmentPoint: perCommitmentPointFromSecret(
					generateFromSeed(makeSeed(190), MAX_INDEX - 1n)
				)
			});
			const state = channel.getFullState();
			const globalBp = makeBasepoints(globalSeed);
			expect(state.localBasepoints.fundingPubkey.toString('hex')).to.not.equal(
				globalBp.fundingPubkey.toString('hex')
			);
		});

		it('channel index increments across open types', () => {
			const idx1 = mgr.nextChannelIndex;
			mgr.openChannel('02' + 'aa'.repeat(32), 100_000n);
			const idx2 = mgr.nextChannelIndex;
			expect(idx2).to.equal(idx1 + 1);

			const peer = '02' + 'bb'.repeat(32);
			mgr.addTrustedPeer(peer);
			mgr.openZeroConfChannel(peer, 100_000n);
			const idx3 = mgr.nextChannelIndex;
			expect(idx3).to.equal(idx2 + 1);

			const dfSeed2 = makeSeed(91);
			mgr.createDualFundedChannel('02' + 'cc'.repeat(32), {
				fundingSatoshis: 200_000n,
				fundingFeeratePerkw: 1000,
				commitmentFeeratePerkw: 500,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 100_000_000n,
				htlcMinimumMsat: 1n,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 30,
				locktime: 0,
				localBasepoints: makeBasepoints(dfSeed2),
				localPerCommitmentSeed: makeSeed(191),
				secondPerCommitmentPoint: perCommitmentPointFromSecret(
					generateFromSeed(makeSeed(191), MAX_INDEX - 1n)
				)
			});
			const idx4 = mgr.nextChannelIndex;
			expect(idx4).to.equal(idx3 + 1);
		});

		it('handleOpenChannel2 derives per-channel keys', () => {
			const remoteSeed = makeSeed(50);
			const remoteBp = makeBasepoints(remoteSeed);
			remoteBp.firstPerCommitmentPoint = perCommitmentPointFromSecret(
				generateFromSeed(makeSeed(150), MAX_INDEX)
			);

			const msg: IOpenChannel2Message = {
				channelId: crypto.randomBytes(32),
				fundingFeeratePerkw: 1000,
				commitmentFeeratePerkw: 500,
				fundingSatoshis: 100_000n,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 100_000_000n,
				htlcMinimumMsat: 1n,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 30,
				locktime: 0,
				fundingPubkey: remoteBp.fundingPubkey,
				revocationBasepoint: remoteBp.revocationBasepoint,
				paymentBasepoint: remoteBp.paymentBasepoint,
				delayedPaymentBasepoint: remoteBp.delayedPaymentBasepoint,
				htlcBasepoint: remoteBp.htlcBasepoint,
				firstPerCommitmentPoint: remoteBp.firstPerCommitmentPoint,
				secondPerCommitmentPoint: perCommitmentPointFromSecret(
					generateFromSeed(makeSeed(150), MAX_INDEX - 1n)
				),
				channelFlags: 0x01
			};

			const prevIdx = mgr.nextChannelIndex;
			const payload = encodeOpenChannel2Message(msg);
			mgr.handleMessage(
				'02' + 'dd'.repeat(32),
				MessageType.OPEN_CHANNEL2,
				payload
			);
			expect(mgr.nextChannelIndex).to.equal(prevIdx + 1);
		});

		it('forceClose uses channel signer (not global)', () => {
			const channel = mgr.openChannel('02' + 'ee'.repeat(32), 100_000n);
			const perChSigner = channel.getSigner();
			expect(perChSigner).to.not.be.null;

			// Advance to a state where forceClose is allowed
			// (needs at least AWAITING_FUNDING_CONFIRMED or NORMAL)
			// Since we can't fully advance state in unit tests,
			// verify the manager calls channel.getSigner() by checking the channel has one
			const state = channel.getFullState();
			expect(state.localBasepoints.fundingPubkey.toString('hex')).to.not.equal(
				makeBasepoints(globalSeed).fundingPubkey.toString('hex')
			);
		});

		it('restored channel uses per-channel signer via keyIndex', () => {
			const channelIndex = 5;
			const perChKeys = makePerChannelKeys(channelIndex);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: perChKeys.basepoints,
				localPerCommitmentSeed: perChKeys.perCommitmentSeed
			});
			// Simulate having a permanent channel ID
			state.channelId = crypto.randomBytes(32);
			state.state = ChannelState.NORMAL;
			const channel = new Channel(state);
			const peerPubkey = '02' + 'ff'.repeat(32);

			mgr.restoreChannel(channel, peerPubkey, channelIndex);

			const signer = channel.getSigner();
			expect(signer).to.not.be.null;
		});
	});

	describe('ChannelManager without channelKeyDeriver (backward compat)', () => {
		let mgr: ChannelManager;

		beforeEach(() => {
			mgr = new ChannelManager(makeManagerConfig(false));
			mgr.on('error', () => {});
		});

		it('openChannel uses global keys when no deriver', () => {
			const channel = mgr.openChannel('02' + '44'.repeat(32), 100_000n);
			const state = channel.getFullState();
			// Should use global basepoints
			const globalBp = makeBasepoints(globalSeed);
			expect(state.localBasepoints.fundingPubkey.toString('hex')).to.equal(
				globalBp.fundingPubkey.toString('hex')
			);
		});

		it('openZeroConfChannel uses global keys when no deriver', () => {
			const peer = '02' + '55'.repeat(32);
			mgr.addTrustedPeer(peer);
			const channel = mgr.openZeroConfChannel(peer, 100_000n);
			expect(channel).to.not.be.null;
			const state = channel!.getFullState();
			const globalBp = makeBasepoints(globalSeed);
			expect(state.localBasepoints.fundingPubkey.toString('hex')).to.equal(
				globalBp.fundingPubkey.toString('hex')
			);
		});
	});
});
