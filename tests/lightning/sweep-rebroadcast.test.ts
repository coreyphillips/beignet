import { expect } from 'chai';
import {
	OutputStatus,
	OutputType,
	MonitorState,
	ChainActionType
} from '../../src/lightning/chain/types';
import {
	ChainMonitor,
	IChainMonitorState
} from '../../src/lightning/chain/chain-monitor';
import crypto from 'crypto';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import {
	ChannelRole,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ShaChainStore } from '../../src/lightning/keys/shachain';

function makeMinimalChannelState(): IChannelState {
	const seed = crypto.randomBytes(32);
	return {
		channelId: crypto.randomBytes(32),
		temporaryChannelId: crypto.randomBytes(32),
		state: ChannelState.NORMAL,
		role: ChannelRole.OPENER,
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localBalanceMsat: 50_000_000n,
		remoteBalanceMsat: 50_000_000n,
		localPerCommitmentSeed: seed,
		localCommitmentNumber: 0n,
		remoteCommitmentNumber: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG },
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
		remoteCommitmentSignature: null,
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
		lastSentWasRevoke: null,
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
}

describe('Sweep Re-broadcast', () => {
	it('re-broadcasts after 6 blocks in SPEND_BROADCAST', () => {
		const state: IChainMonitorState = {
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			trackedOutputs: [
				{
					txid: 'a'.repeat(64),
					outputIndex: 0,
					amount: 50000n,
					outputType: OutputType.TO_LOCAL,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					broadcastHeight: 100,
					originalFeeRate: 10,
					sweepTxHex: 'deadbeef'
				}
			],
			currentBlockHeight: 100
		};
		const chanState = makeMinimalChannelState();
		const m = ChainMonitor.restore(
			state,
			chanState,
			Buffer.alloc(22),
			10,
			crypto.randomBytes(32),
			crypto.randomBytes(32)
		);

		// Advance 5 blocks -- no re-broadcast
		let actions = m.handleNewBlock(105);
		const rebuilds = actions.filter(
			(a) => a.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds.length).to.equal(0);

		// Advance to 6 blocks -- should trigger rebuild sweep
		actions = m.handleNewBlock(106);
		const rebuilds2 = actions.filter(
			(a) => a.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds2.length).to.equal(1);
	});

	it('re-broadcast increases fee rate by 1.5x', () => {
		const state: IChainMonitorState = {
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			trackedOutputs: [
				{
					txid: 'b'.repeat(64),
					outputIndex: 0,
					amount: 50000n,
					outputType: OutputType.TO_LOCAL,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					broadcastHeight: 100,
					originalFeeRate: 10,
					sweepTxHex: 'deadbeef'
				}
			],
			currentBlockHeight: 100
		};
		const chanState = makeMinimalChannelState();
		const m = ChainMonitor.restore(
			state,
			chanState,
			Buffer.alloc(22),
			10,
			crypto.randomBytes(32),
			crypto.randomBytes(32)
		);

		const actions = m.handleNewBlock(106);
		const rebuilds = actions.filter(
			(a) => a.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds.length).to.equal(1);
		// Fee rate should be 10 * 1.5 = 15
		expect((rebuilds[0] as any).feeRatePerVbyte).to.equal(15);
	});

	it('fee bump cap allows reaching the live rate above 10x original', () => {
		// A sweep built at a stale-low rate (originalFeeRate 5) must still be
		// able to reach the KNOWN live network rate (here 100) — the runaway cap
		// is max(10x original, live), not a hard 10x original that would strand
		// the sweep at 50 while the mempool demands 100.
		const state: IChainMonitorState = {
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			trackedOutputs: [
				{
					txid: 'c'.repeat(64),
					outputIndex: 0,
					amount: 500000n,
					outputType: OutputType.TO_LOCAL,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					broadcastHeight: 100,
					originalFeeRate: 5,
					sweepTxHex: 'deadbeef',
					currentFeeRate: 100
				}
			],
			currentBlockHeight: 100
		};
		const chanState = makeMinimalChannelState();
		const m = ChainMonitor.restore(
			state,
			chanState,
			Buffer.alloc(22),
			100, // live network rate
			crypto.randomBytes(32),
			crypto.randomBytes(32)
		);

		const actions = m.handleNewBlock(106);
		const rebuilds = actions.filter(
			(a) => a.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds.length).to.equal(1);
		// min(max(100*1.5, live=100), max(5*10=50, live=100)) = min(150, 100) = 100
		expect((rebuilds[0] as any).feeRatePerVbyte).to.equal(100);
	});

	it('fee bump still capped at 10x original when the live rate is low', () => {
		// Anti-runaway: when the live rate does NOT exceed 10x the build-time
		// rate, the cap remains 10x original so a compounding 1.5x can't
		// overpay far beyond the market.
		const state: IChainMonitorState = {
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			trackedOutputs: [
				{
					txid: 'c'.repeat(64),
					outputIndex: 0,
					amount: 500000n,
					outputType: OutputType.TO_LOCAL,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					broadcastHeight: 100,
					originalFeeRate: 5,
					sweepTxHex: 'deadbeef',
					currentFeeRate: 100
				}
			],
			currentBlockHeight: 100
		};
		const chanState = makeMinimalChannelState();
		const m = ChainMonitor.restore(
			state,
			chanState,
			Buffer.alloc(22),
			10, // live rate below 10x original (=50)
			crypto.randomBytes(32),
			crypto.randomBytes(32)
		);

		const actions = m.handleNewBlock(106);
		const rebuilds = actions.filter(
			(a) => a.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds.length).to.equal(1);
		// min(max(100*1.5, live=10), max(5*10=50, live=10)) = min(150, 50) = 50
		expect((rebuilds[0] as any).feeRatePerVbyte).to.equal(50);
	});

	it('confirmed sweep (SPEND_CONFIRMED) is not re-broadcast', () => {
		const state: IChainMonitorState = {
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			trackedOutputs: [
				{
					txid: 'd'.repeat(64),
					outputIndex: 0,
					amount: 50000n,
					outputType: OutputType.TO_LOCAL,
					status: OutputStatus.SPEND_CONFIRMED,
					confirmationHeight: 100,
					broadcastHeight: 94,
					originalFeeRate: 10,
					resolutionTxid: 'e'.repeat(64)
				}
			],
			currentBlockHeight: 100
		};
		const chanState = makeMinimalChannelState();
		const m = ChainMonitor.restore(
			state,
			chanState,
			Buffer.alloc(22),
			10,
			crypto.randomBytes(32),
			crypto.randomBytes(32)
		);

		const actions = m.handleNewBlock(106);
		const rebuilds = actions.filter(
			(a) => a.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds.length).to.equal(0);
	});

	it('re-broadcast stops once spend is confirmed', () => {
		const state: IChainMonitorState = {
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			trackedOutputs: [
				{
					txid: 'f'.repeat(64),
					outputIndex: 0,
					amount: 50000n,
					outputType: OutputType.TO_LOCAL,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					broadcastHeight: 100,
					originalFeeRate: 10,
					sweepTxHex: 'deadbeef'
				}
			],
			currentBlockHeight: 100
		};
		const chanState = makeMinimalChannelState();
		const m = ChainMonitor.restore(
			state,
			chanState,
			Buffer.alloc(22),
			10,
			crypto.randomBytes(32),
			crypto.randomBytes(32)
		);

		// Block 106 triggers rebuild sweep
		let actions = m.handleNewBlock(106);
		expect(
			actions.filter((a) => a.type === ChainActionType.REBUILD_SWEEP).length
		).to.be.greaterThan(0);

		// Get tracked outputs and verify broadcastHeight was updated
		const outputs = m.getTrackedOutputs();
		expect(outputs[0].broadcastHeight).to.equal(106);

		// Simulate the sweep being confirmed by calling handleOutputSpent
		// This transitions the output to SPEND_CONFIRMED
		const fakeTx = { getId: () => 'g'.repeat(64), ins: [] } as any;
		m.handleOutputSpent('f'.repeat(64), 0, fakeTx, 107);

		// Now at block 112 (6 blocks after re-broadcast at 106), no re-broadcast
		actions = m.handleNewBlock(112);
		const rebuilds = actions.filter(
			(a) => a.type === ChainActionType.REBUILD_SWEEP
		);
		expect(rebuilds.length).to.equal(0);
	});
});
