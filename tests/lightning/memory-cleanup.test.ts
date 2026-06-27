/**
 * Memory Cleanup Tests
 *
 * Tests that long-lived node components can prune stale data:
 * - MissionControl.prune() removes decayed penalties
 * - ElectrumBackend.unsubscribeScriptHash() removes tracked entries
 * - ChainWatcher.removeWatchedFunding() removes closed channel watches
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { MissionControl } from '../../src/lightning/gossip/mission-control';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';
import { ChainWatcher } from '../../src/lightning/chain/chain-watcher';

// ─────────────── Helpers ───────────────

function makeInstantElectrum(): Record<string, unknown> {
	return {
		subscribeToHeader: () =>
			Promise.resolve({ isErr: () => false, value: { height: 100 } }),
		subscribeToAddresses: () =>
			Promise.resolve({ isErr: () => false, value: {} }),
		getAddressScriptHashesHistory: () =>
			Promise.resolve({ isErr: () => false, value: { data: [] } }),
		getTransactions: () =>
			Promise.resolve({ isErr: () => false, value: { data: [] } }),
		getTransactionMerkle: () => Promise.resolve({ pos: 0 }),
		broadcastTransaction: () =>
			Promise.resolve({ isErr: () => false, value: 'txid' }),
		onReceive: () => {}
	};
}

describe('Memory Cleanup — MissionControl.prune()', () => {
	it('should prune entries with no failures (success-only)', () => {
		const mc = new MissionControl();
		mc.recordSuccess('channel-a');
		mc.recordSuccess('channel-b');
		expect(mc.size).to.equal(2);

		const pruned = mc.prune();
		expect(pruned).to.equal(2);
		expect(mc.size).to.equal(0);
	});

	it('should prune entries whose penalty decayed below threshold', () => {
		const mc = new MissionControl({
			failurePenaltyBaseMsat: 100,
			penaltyHalfLifeMs: 1 // very fast decay
		});
		mc.recordFailure('channel-a');

		// Wait for decay
		return new Promise<void>((resolve) =>
			setTimeout(() => {
				const pruned = mc.prune(1);
				expect(pruned).to.equal(1);
				expect(mc.size).to.equal(0);
				resolve();
			}, 50)
		);
	});

	it('should not prune entries with high active penalty', () => {
		const mc = new MissionControl({
			failurePenaltyBaseMsat: 1_000_000,
			penaltyHalfLifeMs: 3_600_000
		});
		mc.recordFailure('channel-a');

		const pruned = mc.prune(1);
		expect(pruned).to.equal(0);
		expect(mc.size).to.equal(1);
	});

	it('should return count of pruned entries', () => {
		const mc = new MissionControl();
		mc.recordSuccess('a');
		mc.recordSuccess('b');
		mc.recordSuccess('c');
		mc.recordFailure('d'); // not pruned (has active penalty)

		const pruned = mc.prune();
		expect(pruned).to.equal(3);
		expect(mc.size).to.equal(1);
	});
});

describe('Memory Cleanup — ElectrumBackend.unsubscribeScriptHash()', () => {
	it('should remove a tracked script hash', async () => {
		const backend = new ElectrumBackend(makeInstantElectrum() as never, 5_000);
		await backend.subscribeToScriptHash('aabb', () => {});
		backend.stopReconnectMonitor();

		expect(backend.unsubscribeScriptHash('aabb')).to.be.true;
		expect(backend.unsubscribeScriptHash('aabb')).to.be.false;
	});

	it('should return false for unknown script hash', () => {
		const backend = new ElectrumBackend(makeInstantElectrum() as never, 5_000);
		expect(backend.unsubscribeScriptHash('nonexistent')).to.be.false;
	});
});

describe('Memory Cleanup — ChainWatcher.removeWatchedFunding()', () => {
	it('should remove a watched funding entry', () => {
		const channelId = crypto.randomBytes(32);

		// Minimal mock for ChannelManager (just needs to be an EventEmitter)
		const mockCm =
			new EventEmitter() as unknown as import('../../src/lightning/channel/channel-manager').ChannelManager;
		(mockCm as unknown as { listChannels: () => never[] }).listChannels =
			() => [];

		const mockBackend = {
			subscribeToHeaders: async () => {},
			subscribeToScriptHash: async () => {},
			getScriptHashHistory: async () => [],
			getTransaction: async () => Buffer.alloc(0),
			broadcastTransaction: async () => 'txid'
		};

		const watcher = new ChainWatcher({
			backend: mockBackend,
			channelManager: mockCm
		});

		// Manually set a watched funding entry via the internal map
		(
			watcher as unknown as { watchedFundings: Map<string, unknown> }
		).watchedFundings.set(channelId.toString('hex'), {
			channelId,
			txid: 'abc',
			outputIndex: 0,
			minimumDepth: 3,
			scriptHash: 'def',
			confirmed: false,
			confirmationHeight: 0,
			announcementTriggered: false
		});

		expect(watcher.removeWatchedFunding(channelId)).to.be.true;
		expect(watcher.removeWatchedFunding(channelId)).to.be.false;
	});
});
