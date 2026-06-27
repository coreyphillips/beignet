/**
 * Phase 4: Chain Watcher tests.
 *
 * Verifies the ChainWatcher bridge between IChainBackend and ChannelManager:
 * - computeScriptHash utility
 * - Funding confirmation detection
 * - Block height advancement
 * - Transaction broadcast
 * - Output spend detection
 * - ChannelManager event wiring
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		const priv = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(getPublicKey(priv));
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

/** Mock chain backend for testing */
class MockChainBackend implements IChainBackend {
	private headerCallbacks: Array<(height: number) => void> = [];
	private scriptHashCallbacks: Map<string, Array<() => void>> = new Map();
	private scriptHashHistory: Map<
		string,
		Array<{ txid: string; height: number }>
	> = new Map();
	private transactions: Map<string, Buffer> = new Map();
	private broadcastedTxs: string[] = [];

	// Control methods
	simulateNewBlock(height: number): void {
		for (const cb of this.headerCallbacks) {
			cb(height);
		}
	}

	simulateScriptHashChange(scriptHash: string): void {
		const callbacks = this.scriptHashCallbacks.get(scriptHash);
		if (callbacks) {
			for (const cb of callbacks) {
				cb();
			}
		}
	}

	setHistory(
		scriptHash: string,
		history: Array<{ txid: string; height: number }>
	): void {
		this.scriptHashHistory.set(scriptHash, history);
	}

	setTransaction(txid: string, rawTx: Buffer): void {
		this.transactions.set(txid, rawTx);
	}

	getBroadcastedTxs(): string[] {
		return this.broadcastedTxs;
	}

	// IChainBackend implementation
	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		this.headerCallbacks.push(onNewBlock);
	}

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		const existing = this.scriptHashCallbacks.get(scriptHash) || [];
		existing.push(onChange);
		this.scriptHashCallbacks.set(scriptHash, existing);
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this.scriptHashHistory.get(scriptHash) || [];
	}

	async getTransaction(txid: string): Promise<Buffer> {
		const tx = this.transactions.get(txid);
		if (!tx) throw new Error(`Transaction not found: ${txid}`);
		return tx;
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcastedTxs.push(rawTxHex);
		// Compute txid from the raw transaction
		const txBuf = Buffer.from(rawTxHex, 'hex');
		const hash = crypto
			.createHash('sha256')
			.update(crypto.createHash('sha256').update(txBuf).digest())
			.digest();
		return Buffer.from(hash).reverse().toString('hex');
	}
}

describe('Phase 4: Chain Watcher', () => {
	describe('computeScriptHash', () => {
		it('should compute Electrum-style script hash', () => {
			// Known test vector: P2PKH script for a known address
			const scriptPubkey = Buffer.from(
				'76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac',
				'hex'
			);
			const hash = computeScriptHash(scriptPubkey);
			expect(hash).to.be.a('string');
			expect(hash).to.have.lengthOf(64); // 32 bytes hex
		});

		it('should produce different hashes for different scripts', () => {
			const script1 = Buffer.from('0014' + '00'.repeat(20), 'hex');
			const script2 = Buffer.from('0014' + 'ff'.repeat(20), 'hex');
			expect(computeScriptHash(script1)).to.not.equal(
				computeScriptHash(script2)
			);
		});

		it('should reverse the SHA256 hash bytes', () => {
			const scriptPubkey = Buffer.from('0014aabbccdd', 'hex');
			const sha256 = crypto.createHash('sha256').update(scriptPubkey).digest();
			const expected = Buffer.from(sha256).reverse().toString('hex');
			expect(computeScriptHash(scriptPubkey)).to.equal(expected);
		});
	});

	describe('ChainWatcher lifecycle', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(() => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			// Absorb ChannelManager errors
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should start and subscribe to block headers', async () => {
			await watcher.start();
			expect(watcher.getCurrentBlockHeight()).to.equal(0);

			backend.simulateNewBlock(100);
			expect(watcher.getCurrentBlockHeight()).to.equal(100);
		});

		it('should not start twice', async () => {
			await watcher.start();
			await watcher.start(); // should be no-op
		});

		it('should emit block events on new blocks', async () => {
			await watcher.start();
			const heights: number[] = [];
			watcher.on('block', (h) => heights.push(h));

			backend.simulateNewBlock(100);
			backend.simulateNewBlock(101);

			expect(heights).to.deep.equal([100, 101]);
		});

		it('should track current block height', async () => {
			await watcher.start();

			backend.simulateNewBlock(500);
			expect(watcher.getCurrentBlockHeight()).to.equal(500);

			backend.simulateNewBlock(501);
			expect(watcher.getCurrentBlockHeight()).to.equal(501);
		});
	});

	describe('Funding confirmation detection', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should detect funding confirmation at minimum depth', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 3, scriptPubkey);

			// Set current block height
			backend.simulateNewBlock(100);

			// Simulate the funding tx appearing in history at height 98
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);

			// Trigger the script hash callback
			let confirmed = false;
			watcher.on('funding:confirmed', (cid: Buffer) => {
				if (cid.equals(channelId)) confirmed = true;
			});

			backend.simulateScriptHashChange(scriptHash);

			// Wait for async callback to complete
			await new Promise((resolve) => setTimeout(resolve, 50));

			// 100 - 98 + 1 = 3 confirmations = minimumDepth
			expect(confirmed).to.be.true;
		});

		it('should not confirm before minimum depth', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 6, scriptPubkey);

			backend.simulateNewBlock(100);
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);

			let confirmed = false;
			watcher.on('funding:confirmed', () => {
				confirmed = true;
			});

			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			// 100 - 98 + 1 = 3, but minimumDepth = 6
			expect(confirmed).to.be.false;
		});

		it('should confirm when more blocks arrive', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 3, scriptPubkey);

			backend.simulateNewBlock(99);
			backend.setHistory(scriptHash, [{ txid, height: 99 }]);

			let confirmed = false;
			watcher.on('funding:confirmed', () => {
				confirmed = true;
			});

			// At height 99, confirmations = 1, need 3
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(confirmed).to.be.false;

			// At height 101, confirmations = 3
			backend.simulateNewBlock(101);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(confirmed).to.be.true;
		});

		it('recheckAllWatches() detects a confirmation missed while disconnected', async () => {
			// Reproduces the real bug: the funding confirmed on-chain but no
			// new-block / script-hash event was delivered (subscriptions failed to
			// establish during an Electrum outage), so the channel stayed stuck.
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 3, scriptPubkey);
			backend.simulateNewBlock(100); // sets current height; history still empty

			let confirmed = false;
			watcher.on('funding:confirmed', (cid: Buffer) => {
				if (cid.equals(channelId)) confirmed = true;
			});

			// Funding is now 3-deep on-chain, but NO event delivers it.
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);
			await new Promise((resolve) => setTimeout(resolve, 30));
			expect(confirmed, 'no event delivered → still unconfirmed').to.be.false;

			// The safety-net re-check (also fired on reconnect) picks it up.
			watcher.recheckAllWatches();
			await new Promise((resolve) => setTimeout(resolve, 30));
			expect(confirmed, 'recheckAllWatches detected the missed confirmation').to
				.be.true;
		});

		it('should not confirm unconfirmed transactions (height=0)', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 1, scriptPubkey);
			backend.simulateNewBlock(100);

			// height=0 means unconfirmed
			backend.setHistory(scriptHash, [{ txid, height: 0 }]);

			let confirmed = false;
			watcher.on('funding:confirmed', () => {
				confirmed = true;
			});

			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(confirmed).to.be.false;
		});
	});

	describe('Transaction broadcast', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should broadcast transactions via the backend', async () => {
			const rawTx = crypto.randomBytes(200);
			const txid = await watcher.broadcastTransaction(rawTx);

			expect(txid).to.be.a('string');
			expect(txid).to.have.lengthOf(64);
			expect(backend.getBroadcastedTxs()).to.have.lengthOf(1);
			expect(backend.getBroadcastedTxs()[0]).to.equal(rawTx.toString('hex'));
		});

		it('should emit broadcast:success event', async () => {
			const rawTx = crypto.randomBytes(200);
			let emittedTxid: string | null = null;
			watcher.on('broadcast:success', (t: string) => {
				emittedTxid = t;
			});

			await watcher.broadcastTransaction(rawTx);
			expect(emittedTxid).to.not.be.null;
		});

		it('should forward ChannelManager broadcast:tx events', async () => {
			const rawTx = crypto.randomBytes(200);
			// Channel manager emits broadcast:tx
			channelManager.emit('broadcast:tx', rawTx);

			// Wait for the async broadcast
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(backend.getBroadcastedTxs()).to.have.lengthOf(1);
		});
	});

	describe('ChannelManager event wiring', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should emit error when watch:funding fires with no matching channel', () => {
			let errorEmitted = false;
			watcher.on('error', () => {
				errorEmitted = true;
			});

			const txid = crypto.randomBytes(32);
			channelManager.emit('watch:funding', txid, 0, 3);

			expect(errorEmitted).to.be.true;
		});

		it('should emit watch:output:requested when ChannelManager emits watch:output', () => {
			let requested = false;
			watcher.on('watch:output:requested', () => {
				requested = true;
			});

			channelManager.emit('watch:output', 'abc123', 1);

			expect(requested).to.be.true;
		});
	});

	describe('Output spend detection', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should detect when a watched output is spent', async () => {
			const watchedTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchOutput(watchedTxid, 0, scriptPubkey);

			// Create a spending transaction
			const spendTx = new bitcoin.Transaction();
			spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
			spendTx.addOutput(scriptPubkey, 50000);
			const spendTxid = spendTx.getId();
			const spendRawTx = spendTx.toBuffer();

			backend.setHistory(scriptHash, [
				{ txid: watchedTxid, height: 100 }, // original tx
				{ txid: spendTxid, height: 101 } // spending tx
			]);
			backend.setTransaction(spendTxid, spendRawTx);

			let spentEmitted = false;
			watcher.on('output:spent', () => {
				spentEmitted = true;
			});

			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(spentEmitted).to.be.true;
		});
	});

	describe('LightningNode integration', () => {
		it('should accept chainBackend in INodeConfig', () => {
			const {
				LightningNode
			} = require('../../src/lightning/node/lightning-node');

			const seed = crypto.randomBytes(32);
			const basepoints = makeBasepoints(seed);
			const mockBackend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => ''
			};

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32),
				chainBackend: mockBackend
			});

			expect(node.getChainWatcher()).to.not.be.null;
			node.destroy();
		});

		it('restoreChainWatches watches the funding of a FORCE_CLOSED channel with no monitor', async () => {
			const {
				LightningNode
			} = require('../../src/lightning/node/lightning-node');
			const {
				createOpenerState
			} = require('../../src/lightning/channel/channel-state');
			const { Channel } = require('../../src/lightning/channel/channel');
			const {
				ChannelState,
				DEFAULT_CHANNEL_CONFIG
			} = require('../../src/lightning/channel/types');

			const seed = crypto.randomBytes(32);
			const basepoints = makeBasepoints(seed);
			const mockBackend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => ''
			};
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32),
				chainBackend: mockBackend
			});

			// A channel force-closed in a previous session whose monitor was never
			// persisted: it must still get a funding watch (the spend detection
			// lazily creates the monitor and schedules the sweeps). Skipping it
			// orphans the CSV-locked funds.
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.state = ChannelState.FORCE_CLOSED;
			state.channelId = crypto.randomBytes(32);
			state.fundingTxid = crypto.randomBytes(32);
			state.fundingOutputIndex = 0;
			state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
			const channel = new Channel(state);
			node.getChannelManager().restoreChannel(channel, 'cafe'.repeat(16));

			await node.restoreChainWatches();

			const watcher = node.getChainWatcher()!;
			const watched = (watcher as any).watchedFundings as Map<string, unknown>;
			expect(watched.has(state.channelId.toString('hex')), 'funding watched').to
				.be.true;
			node.destroy();
		});

		it('should not create ChainWatcher when no backend provided', () => {
			const {
				LightningNode
			} = require('../../src/lightning/node/lightning-node');

			const seed = crypto.randomBytes(32);
			const basepoints = makeBasepoints(seed);

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});

			expect(node.getChainWatcher()).to.be.null;
			node.destroy();
		});
	});
});
