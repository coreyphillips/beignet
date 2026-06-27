/**
 * Phase 2: Chain Reliability Tests
 *
 * Tests for:
 * 1. ElectrumBackend block subscription forwarding
 * 2. ChainMonitor save/restore roundtrip
 * 3. secondPerCommitmentPoint validity
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	MonitorState,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { generateFromSeed } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';

/**
 * Build a minimal mock Electrum object that satisfies ElectrumBackend's
 * usage without requiring a real connection.
 */
function createMockElectrum(initialHeight = 100): any {
	return {
		onReceive: null as any,
		subscribeToHeader: async () => ({
			isErr: () => false,
			value: { height: initialHeight }
		}),
		subscribeToAddresses: async () => ({ isErr: () => false }),
		getAddressScriptHashesHistory: async () => ({
			isErr: () => false,
			value: { data: [] }
		}),
		getTransactions: async () => ({
			isErr: () => false,
			value: { data: [] }
		}),
		getTransactionMerkle: async () => ({
			isErr: () => false,
			value: { pos: 0 }
		}),
		broadcastTransaction: async () => ({
			isErr: () => false,
			value: 'txid'
		})
	};
}

/**
 * Create a minimal IChannelState for ChainMonitor tests.
 */
function createMinimalChannelState(): any {
	const seed = crypto.randomBytes(32);
	const privkey = crypto.randomBytes(32);
	const pubkey = getPublicKey(privkey);
	const basepoints = {
		fundingPubkey: pubkey,
		revocationBasepoint: pubkey,
		paymentBasepoint: pubkey,
		delayedPaymentBasepoint: pubkey,
		htlcBasepoint: pubkey,
		firstPerCommitmentPoint: pubkey
	};

	return createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints,
		localPerCommitmentSeed: seed
	});
}

describe('Phase 2: Chain Reliability', () => {
	// ──────────────────────────────────────────────────────
	// 1. ElectrumBackend block subscription forwarding
	// ──────────────────────────────────────────────────────
	describe('ElectrumBackend block subscription', () => {
		it('should forward initial block height from subscribeToHeader', async () => {
			let receivedHeight = 0;
			const mockElectrum = createMockElectrum(100);
			const backend = new ElectrumBackend(mockElectrum as any);
			await backend.subscribeToHeaders((h) => {
				receivedHeight = h;
			});
			expect(receivedHeight).to.equal(100);
		});

		it('should forward ongoing block notifications via chained onReceive', async () => {
			const heights: number[] = [];
			const mockElectrum = createMockElectrum(100);
			const backend = new ElectrumBackend(mockElectrum as any);
			await backend.subscribeToHeaders((h) => {
				heights.push(h);
			});
			// Initial height should already be captured
			expect(heights).to.include(100);
			// Simulate a new block arriving via the Electrum subscription
			mockElectrum.onReceive([{ height: 101 }]);
			expect(heights).to.include(101);
			expect(heights).to.have.length(2);
		});

		it('should chain onto existing onReceive without losing it', async () => {
			let prevCalled = false;
			const mockElectrum = createMockElectrum(100);
			mockElectrum.onReceive = (_data: unknown) => {
				prevCalled = true;
			};
			const backend = new ElectrumBackend(mockElectrum as any);
			let receivedHeight = 0;
			await backend.subscribeToHeaders((h) => {
				receivedHeight = h;
			});
			// Simulate a new block: should call both the previous onReceive and the new one
			mockElectrum.onReceive([{ height: 102 }]);
			expect(prevCalled).to.be.true;
			expect(receivedHeight).to.equal(102);
		});

		it('should handle non-header data in onReceive gracefully', async () => {
			const heights: number[] = [];
			const mockElectrum = createMockElectrum(100);
			const backend = new ElectrumBackend(mockElectrum as any);
			await backend.subscribeToHeaders((h) => {
				heights.push(h);
			});
			// Send non-array data -- should not crash or fire callback
			mockElectrum.onReceive('not-an-array');
			// Send array without height -- should not fire callback
			mockElectrum.onReceive([{ something: 'else' }]);
			// Only the initial height should be recorded
			expect(heights).to.deep.equal([100]);
		});

		it('should forward multiple sequential block notifications', async () => {
			const heights: number[] = [];
			const mockElectrum = createMockElectrum(500);
			const backend = new ElectrumBackend(mockElectrum as any);
			await backend.subscribeToHeaders((h) => {
				heights.push(h);
			});
			mockElectrum.onReceive([{ height: 501 }]);
			mockElectrum.onReceive([{ height: 502 }]);
			mockElectrum.onReceive([{ height: 503 }]);
			expect(heights).to.deep.equal([500, 501, 502, 503]);
		});
	});

	// ──────────────────────────────────────────────────────
	// 2. ChainMonitor save/restore roundtrip
	// ──────────────────────────────────────────────────────
	describe('ChainMonitor save/restore', () => {
		it('should roundtrip WATCHING state via getFullState/restore', () => {
			const channelState = createMinimalChannelState();
			const destinationScript = Buffer.alloc(22, 0xab);
			const revocationSecret = crypto.randomBytes(32);
			const paymentPrivkey = crypto.randomBytes(32);

			const monitor = new ChainMonitor(
				channelState,
				destinationScript,
				10, // feeRatePerVbyte
				revocationSecret,
				paymentPrivkey
			);

			const saved = monitor.getFullState();
			const restored = ChainMonitor.restore(
				saved,
				channelState,
				destinationScript,
				10,
				revocationSecret,
				paymentPrivkey
			);

			expect(restored.getState()).to.equal(MonitorState.WATCHING);
			expect(restored.getTrackedOutputs()).to.have.length(0);
			expect(restored.isFullyResolved()).to.be.false;
		});

		it('should preserve currentBlockHeight through save/restore', () => {
			const channelState = createMinimalChannelState();
			const destinationScript = Buffer.alloc(22, 0xab);
			const revocationSecret = crypto.randomBytes(32);
			const paymentPrivkey = crypto.randomBytes(32);

			const monitor = new ChainMonitor(
				channelState,
				destinationScript,
				10,
				revocationSecret,
				paymentPrivkey
			);

			// Advance block height via handleNewBlock
			monitor.handleNewBlock(750);

			const saved = monitor.getFullState();
			expect(saved.currentBlockHeight).to.equal(750);

			const restored = ChainMonitor.restore(
				saved,
				channelState,
				destinationScript,
				10,
				revocationSecret,
				paymentPrivkey
			);

			const restoredState = restored.getFullState();
			expect(restoredState.currentBlockHeight).to.equal(750);
		});

		it('should preserve tracked outputs and monitor state through save/restore', () => {
			const channelState = createMinimalChannelState();
			const destinationScript = Buffer.alloc(22, 0xab);
			const revocationSecret = crypto.randomBytes(32);
			const paymentPrivkey = crypto.randomBytes(32);

			// Manually construct a saved state with tracked outputs
			const savedState = {
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: 'OUR_COMMITMENT' as any,
					txid: 'abc123',
					blockHeight: 600,
					commitmentNumber: 1n,
					trackedOutputs: []
				},
				trackedOutputs: [
					{
						txid: 'abc123',
						outputIndex: 0,
						amount: 500_000n,
						outputType: OutputType.TO_LOCAL,
						status: OutputStatus.CONFIRMED,
						confirmationHeight: 600
					},
					{
						txid: 'abc123',
						outputIndex: 1,
						amount: 300_000n,
						outputType: OutputType.TO_REMOTE,
						status: OutputStatus.SPEND_CONFIRMED,
						confirmationHeight: 601,
						resolutionTxid: 'def456'
					}
				],
				currentBlockHeight: 650
			};

			const restored = ChainMonitor.restore(
				savedState as any,
				channelState,
				destinationScript,
				10,
				revocationSecret,
				paymentPrivkey
			);

			expect(restored.getState()).to.equal(MonitorState.RESOLVING);
			const outputs = restored.getTrackedOutputs();
			expect(outputs).to.have.length(2);
			expect(outputs[0].outputType).to.equal(OutputType.TO_LOCAL);
			expect(outputs[0].status).to.equal(OutputStatus.CONFIRMED);
			expect(outputs[1].resolutionTxid).to.equal('def456');
		});

		it('should preserve FULLY_RESOLVED state through save/restore', () => {
			const channelState = createMinimalChannelState();
			const destinationScript = Buffer.alloc(22, 0xab);
			const revocationSecret = crypto.randomBytes(32);
			const paymentPrivkey = crypto.randomBytes(32);

			const savedState = {
				monitorState: MonitorState.FULLY_RESOLVED,
				commitmentBroadcast: null,
				trackedOutputs: [],
				currentBlockHeight: 999
			};

			const restored = ChainMonitor.restore(
				savedState,
				channelState,
				destinationScript,
				10,
				revocationSecret,
				paymentPrivkey
			);

			expect(restored.getState()).to.equal(MonitorState.FULLY_RESOLVED);
			expect(restored.isFullyResolved()).to.be.true;
			expect(restored.getFullState().currentBlockHeight).to.equal(999);
		});
	});

	// ──────────────────────────────────────────────────────
	// 3. secondPerCommitmentPoint validity
	// ──────────────────────────────────────────────────────
	describe('secondPerCommitmentPoint validity', () => {
		const MAX_INDEX = 0xffffffffffffn;

		it('should derive valid secondPerCommitmentPoint from seed', () => {
			const seed = crypto.randomBytes(32);
			const secondSecret = generateFromSeed(seed, MAX_INDEX - 1n);
			const point = perCommitmentPointFromSecret(secondSecret);
			expect(point).to.have.length(33);
			expect(point[0] === 0x02 || point[0] === 0x03).to.be.true;
		});

		it('should derive different points for different indices', () => {
			const seed = crypto.randomBytes(32);
			const first = perCommitmentPointFromSecret(
				generateFromSeed(seed, MAX_INDEX)
			);
			const second = perCommitmentPointFromSecret(
				generateFromSeed(seed, MAX_INDEX - 1n)
			);
			expect(first.equals(second)).to.be.false;
		});

		it('should derive deterministic points from the same seed and index', () => {
			const seed = crypto.randomBytes(32);
			const pointA = perCommitmentPointFromSecret(
				generateFromSeed(seed, MAX_INDEX - 1n)
			);
			const pointB = perCommitmentPointFromSecret(
				generateFromSeed(seed, MAX_INDEX - 1n)
			);
			expect(pointA.equals(pointB)).to.be.true;
		});
	});
});
