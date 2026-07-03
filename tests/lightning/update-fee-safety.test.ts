import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	ChannelRole,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { ShaChainStore } from '../../src/lightning/keys/shachain';
import { IUpdateFeeMessage } from '../../src/lightning/message/channel-update';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

function createTestChannel(
	openerBalanceMsat: bigint,
	reserveSats = 10_000n,
	initialFeeratePerKw = 2000
): Channel {
	const seed = crypto.randomBytes(32);
	const state: IChannelState = {
		channelId: crypto.randomBytes(32),
		temporaryChannelId: crypto.randomBytes(32),
		state: ChannelState.NORMAL,
		role: ChannelRole.ACCEPTOR, // We are acceptor, so remote is opener
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localBalanceMsat: 500_000_000n,
		remoteBalanceMsat: openerBalanceMsat, // opener's balance in msat
		localPerCommitmentSeed: seed,
		localCommitmentNumber: 0n,
		remoteCommitmentNumber: 0n,
		localConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			channelReserveSatoshis: reserveSats
		},
		remoteConfig: {
			...DEFAULT_CHANNEL_CONFIG,
			channelReserveSatoshis: reserveSats,
			feeratePerKw: initialFeeratePerKw
		},
		localBasepoints: {
			fundingPubkey: crypto.randomBytes(33),
			revocationBasepoint: crypto.randomBytes(33),
			paymentBasepoint: crypto.randomBytes(33),
			delayedPaymentBasepoint: crypto.randomBytes(33),
			htlcBasepoint: crypto.randomBytes(33),
			firstPerCommitmentPoint: crypto.randomBytes(33)
		},
		remoteBasepoints: {
			fundingPubkey: crypto.randomBytes(33),
			revocationBasepoint: crypto.randomBytes(33),
			paymentBasepoint: crypto.randomBytes(33),
			delayedPaymentBasepoint: crypto.randomBytes(33),
			htlcBasepoint: crypto.randomBytes(33),
			firstPerCommitmentPoint: crypto.randomBytes(33)
		},
		htlcs: new Map(),
		shaChainStore: new ShaChainStore(),
		fundingTxid: crypto.randomBytes(32),
		fundingOutputIndex: 0,
		minimumDepth: 3,
		remoteCurrentPerCommitmentPoint: null,
		remoteNextPerCommitmentPoint: null,
		localHtlcCounter: 0n,
		remoteCommitmentSignature: crypto.randomBytes(64),
		remoteHtlcSignatures: [],
		channelType: null,
		localChannelReady: false,
		remoteChannelReady: false,
		localShutdownScript: null,
		remoteShutdownScript: null,
		lastSentCommitmentSigned: null,
		lastSentPartialSignatureWithNonce: null,
		lastSentHtlcSignatures: [],
		lastSentRevokeSecret: null,
		lastSentRevokeNextPoint: null,
		preReestablishState: null,
		lastProposedClosingFeeSat: null,
		closingFeeMin: null,
		closingFeeMax: null,
		theirLastClosingFeeSat: null,
		shortChannelId: null,
		fundingConfirmationHeight: 0,
		fundingTxIndex: 0,
		announcementSigsSent: false,
		announcementSigsReceived: false,
		remoteAnnouncementNodeSig: null,
		remoteAnnouncementBitcoinSig: null,
		localAnnouncementNodeSig: null,
		localAnnouncementBitcoinSig: null,
		announceChannel: true,
		scidAlias: null,
		remoteScidAlias: null,
		zeroConfEnabled: false,
		trustedPeer: false,
		quiescenceState: 'NORMAL',
		quiescenceInitiator: false,
		spliceFundingTxid: null,
		spliceFundingOutputIndex: 0,
		preSpliceState: null,
		fundingVersion: 1,
		dualFundingSession: null,
		commitmentFeeratePerkw: 0,
		fundingLocktime: 0,
		fundingBroadcastHeight: 0,
		pendingLocalUpdates: [],
		pendingLocalUpdatesSignedCount: 0
	};

	return new Channel(state);
}

describe('update_fee Balance Drain Protection', () => {
	it('rejects fee that would drain opener below reserve', () => {
		// Opener has 3,000 sats (3,000,000 msat), reserve is 1,000 sats
		// Available for fees: 3,000 - 1,000 = 2,000 sats = 2,000,000 msat
		// Initial feeratePerKw = 2000, so 10x cap = 20,000
		const channel = createTestChannel(3_000_000n, 1_000n, 2000);

		// fee = floor(724 * 4000 / 1000) = 2896 sats
		// newFee * 1000 = 2,896,000 > 2,000,000 available msat => drain
		// 4000 < 2000 * 10 = 20000 => passes 10x check
		const msg: IUpdateFeeMessage = {
			channelId: crypto.randomBytes(32),
			feeratePerKw: 4000
		};

		const actions = channel.handleUpdateFee(msg);
		expect(actions.length).to.equal(1);
		expect(actions[0].type).to.equal(ChannelActionType.ERROR);
		expect((actions[0] as any).message).to.include('drain');
	});

	it('accepts fee within opener balance', () => {
		// Opener has 500,000 sats (500,000,000 msat), reserve is 10,000 sats
		// Available: 500,000,000 - 10,000,000 = 490,000,000 msat
		// Initial feeratePerKw = 1000, so 10x cap = 10,000
		const channel = createTestChannel(500_000_000n, 10_000n, 1000);

		// fee = floor(724 * 1000 / 1000) = 724 sats
		// newFee * 1000 = 724,000 << 490,000,000 => well within budget
		const msg: IUpdateFeeMessage = {
			channelId: crypto.randomBytes(32),
			feeratePerKw: 1000
		};

		const actions = channel.handleUpdateFee(msg);
		expect(actions.length).to.equal(0);
	});

	it('accounts for in-flight HTLC count in fee calc', () => {
		// Opener has 30,000 sats (30,000,000 msat), reserve 10,000 sats
		// Available for fees: 30,000,000 - 10,000,000 = 20,000,000 msat
		// Initial feeratePerKw = 2000
		const channel = createTestChannel(30_000_000n, 10_000n, 2000);

		// Add 2 active HTLCs to increase the commitment weight
		const state = (channel as any)._state as IChannelState;
		state.htlcs.set('offered-0', {
			id: 0n,
			direction: HtlcDirection.OFFERED,
			amountMsat: 1_000_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366),
			state: HtlcState.PENDING
		});
		state.htlcs.set('offered-1', {
			id: 1n,
			direction: HtlcDirection.OFFERED,
			amountMsat: 1_000_000n,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366),
			state: HtlcState.COMMITTED
		});

		// With 2 HTLCs, weight = 724 + 172*2 = 1068
		// At feeratePerKw = 2000: fee = floor(1068 * 2000 / 1000) = 2136 sats
		// 2,136,000 < 20,000,000 msat => accepted
		const msg: IUpdateFeeMessage = {
			channelId: crypto.randomBytes(32),
			feeratePerKw: 2000
		};
		const actions = channel.handleUpdateFee(msg);
		expect(actions.length).to.equal(0);

		// After first call, remoteConfig.feeratePerKw is set to 2000
		// Now try a high fee with HTLCs:
		// feeratePerKw = 19000, 19000 < 2000 * 10 = 20000 => passes 10x check
		// fee = floor(1068 * 19000 / 1000) = floor(20292) = 20292 sats
		// 20,292,000 > 20,000,000 => drain!
		const msg2: IUpdateFeeMessage = {
			channelId: crypto.randomBytes(32),
			feeratePerKw: 19000
		};
		const actions2 = channel.handleUpdateFee(msg2);
		expect(actions2.length).to.equal(1);
		expect(actions2[0].type).to.equal(ChannelActionType.ERROR);
	});

	it('accounts for anchor channel higher base weight', () => {
		// Opener has 30,000 sats (30,000,000 msat), reserve 10,000 sats
		// Available: 30,000,000 - 10,000,000 = 20,000,000 msat
		// Initial feeratePerKw = 2000
		const channel = createTestChannel(30_000_000n, 10_000n, 2000);

		// Set channel type to anchor (bit 22 = ANCHOR_ZERO_FEE_HTLC)
		const state = (channel as any)._state as IChannelState;
		const flags = new FeatureFlags();
		flags.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		state.channelType = flags.toBuffer();

		// With anchors, base weight = 1124 (vs 724)
		// At feeratePerKw = 18000: fee = floor(1124 * 18000 / 1000) = 20232 sats
		// 20,232,000 > 20,000,000 msat => drain!
		// 18000 < 2000 * 10 = 20000 => passes 10x check
		//
		// The same rate with non-anchor: floor(724 * 18000 / 1000) = 13032 (within budget)
		// With anchor: 20232 (exceeds budget)
		const msg: IUpdateFeeMessage = {
			channelId: crypto.randomBytes(32),
			feeratePerKw: 18000
		};

		const actions = channel.handleUpdateFee(msg);
		expect(actions.length).to.equal(1);
		expect(actions[0].type).to.equal(ChannelActionType.ERROR);
		expect((actions[0] as any).message).to.include('drain');
	});
});

describe('update_fee dust re-trim protection', () => {
	function addCommittedHtlc(channel: Channel, amountMsat: bigint): void {
		const state = (channel as any)._state as IChannelState;
		const id = state.localHtlcCounter++;
		state.htlcs.set(`received-${id}`, {
			id,
			amountMsat,
			paymentHash: crypto.randomBytes(32),
			cltvExpiry: 1000,
			onionRoutingPacket: Buffer.alloc(1366),
			direction: HtlcDirection.RECEIVED,
			state: HtlcState.COMMITTED
		});
	}

	it('rejects an update_fee that would trim an in-flight HTLC (non-anchor)', () => {
		// Non-anchor: trim threshold = dust_limit + success-tx fee, which rises
		// with the feerate. A 10,000-sat received HTLC is untrimmed at 2000
		// sat/kw (threshold ~1760 sat) but trimmed at 20000 sat/kw (threshold
		// ~14414 sat) — its full value would burn into the commitment fee.
		const channel = createTestChannel(500_000_000n, 10_000n, 2000);
		addCommittedHtlc(channel, 10_000_000n);

		const actions = channel.handleUpdateFee({
			channelId: crypto.randomBytes(32),
			feeratePerKw: 20_000
		});
		expect(actions.length).to.equal(1);
		expect(actions[0].type).to.equal(ChannelActionType.ERROR);
		expect((actions[0] as any).message).to.include('dust HTLC exposure');
	});

	it('accepts the same update_fee when no in-flight HTLC would be trimmed', () => {
		const channel = createTestChannel(500_000_000n, 10_000n, 2000);
		// 50,000 sats stays above the 20000 sat/kw threshold (~14414 sat).
		addCommittedHtlc(channel, 50_000_000n);

		const actions = channel.handleUpdateFee({
			channelId: crypto.randomBytes(32),
			feeratePerKw: 20_000
		});
		expect(actions.find((a) => a.type === ChannelActionType.ERROR)).to.not
			.exist;
		expect(
			((channel as any)._state as IChannelState).pendingFeeratePerKw
		).to.equal(20_000);
	});

	it('anchor channels are immune (zero-fee second-level txs)', () => {
		const channel = createTestChannel(500_000_000n, 10_000n, 2000);
		const state = (channel as any)._state as IChannelState;
		const flags = new FeatureFlags();
		flags.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		state.channelType = flags.toBuffer();
		// Trimmed threshold is the static dust limit regardless of rate, so a
		// 10,000-sat HTLC can never be re-trimmed by a fee hike.
		addCommittedHtlc(channel, 10_000_000n);

		const actions = channel.handleUpdateFee({
			channelId: crypto.randomBytes(32),
			feeratePerKw: 20_000
		});
		expect(actions.find((a) => a.type === ChannelActionType.ERROR)).to.not
			.exist;
	});

	it('the opener self-limit rejects proposing a trimming feerate', () => {
		const channel = createTestChannel(500_000_000n, 10_000n, 2000);
		const state = (channel as any)._state as IChannelState;
		state.role = ChannelRole.OPENER;
		state.localConfig.feeratePerKw = 2000;
		state.localBalanceMsat = 500_000_000n;
		addCommittedHtlc(channel, 10_000_000n);

		const actions = channel.updateFee(20_000);
		expect(actions.length).to.equal(1);
		expect(actions[0].type).to.equal(ChannelActionType.ERROR);
		expect((actions[0] as any).message).to.include('dust HTLC exposure');
	});
});
