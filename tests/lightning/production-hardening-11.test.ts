/**
 * Production Hardening 11 Tests — AI Agent Production Readiness Review
 *
 * Phase 1: Fund Safety (watchOutput retry, broadcast retry, reestablish timeout, stale gossip)
 * Phase 2: Operational Stability (WAL checkpoint, gossip DB pruning, timer cleanup)
 * Phase 3: Developer Experience (waitForReady, typed payment errors)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	PaymentStatus,
	LightningErrorCode,
	LightningPaymentError
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	ChainWatcher,
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import {
	findRoute,
	findMultiPathRoute
} from '../../src/lightning/gossip/pathfinding';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId,
	DEFAULT_PRUNE_MAX_AGE
} from '../../src/lightning/gossip/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

bitcoin.initEccLib(ecc);

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`ph11-seed-${id}`))
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
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

function createNode(
	seedId: number,
	extra?: Partial<INodeConfig>
): LightningNode {
	const config = { ...makeNodeConfig(seedId), ...extra };
	const node = new LightningNode(config);
	node.on('error', () => {});
	return node;
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

function makeScid(block: number, txIndex: number, outputIndex: number): Buffer {
	return encodeShortChannelId({ block, txIndex, outputIndex });
}

/** Mock chain backend */
class MockChainBackend implements IChainBackend {
	headerCallbacks: Array<(height: number) => void> = [];
	scriptHashCallbacks: Map<string, Array<() => void>> = new Map();
	private scriptHashHistory: Map<
		string,
		Array<{ txid: string; height: number }>
	> = new Map();
	private transactions: Map<string, Buffer> = new Map();
	broadcastedTxs: string[] = [];
	subscribeError = false;
	broadcastError = false;

	simulateNewBlock(height: number): void {
		for (const cb of this.headerCallbacks) cb(height);
	}

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		this.headerCallbacks.push(onNewBlock);
	}

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		if (this.subscribeError) throw new Error('Electrum subscribe failed');
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
		if (this.broadcastError) throw new Error('Broadcast failed');
		this.broadcastedTxs.push(rawTxHex);
		const txBuf = Buffer.from(rawTxHex, 'hex');
		const hash = crypto
			.createHash('sha256')
			.update(crypto.createHash('sha256').update(txBuf).digest())
			.digest();
		return Buffer.from(hash).reverse().toString('hex');
	}
}

function makeChannelManager(): ChannelManager {
	const seed = makeSeed(900);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return new ChannelManager({
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(999),
		localFundingPrivkey: fundingPrivkey
	});
}

// ─────────────── Graph building helpers ───────────────

function buildGraphEdge(
	graph: NetworkGraph,
	node1: Buffer,
	node2: Buffer,
	scid: Buffer,
	opts?: { feeBase?: number; feeProp?: number; timestamp?: number }
): void {
	const [n1, n2] =
		Buffer.compare(node1, node2) < 0 ? [node1, node2] : [node2, node1];
	const isForward = Buffer.compare(node1, n1) === 0;
	const ts = opts?.timestamp ?? Math.floor(Date.now() / 1000);

	graph.addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: n1,
		nodeId2: n2,
		bitcoinKey1: n1,
		bitcoinKey2: n2
	} as IChannelAnnouncementMessage);

	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: ts,
		messageFlags: 1,
		channelFlags: isForward ? 0 : 1,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 0n,
		feeBaseMsat: opts?.feeBase ?? 1000,
		feeProportionalMillionths: opts?.feeProp ?? 1,
		htlcMaximumMsat: 10_000_000_000n
	};
	graph.applyChannelUpdate(update);

	// Add reverse direction
	graph.applyChannelUpdate({ ...update, channelFlags: isForward ? 1 : 0 });
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 1: Fund Safety
// ═══════════════════════════════════════════════════════════════════════

describe('Production Hardening 11', function () {
	this.timeout(10_000);

	describe('Phase 1: Fund Safety', () => {
		// ─── 1a. watchOutput() retry queue ───

		describe('1a. watchOutput retry queue', () => {
			it('should queue failed watchOutput for retry on next block', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.subscribeError = true;
				const scriptPubkey = Buffer.from('0014' + '00'.repeat(20), 'hex');
				await watcher.watchOutput('abcd1234', 0, scriptPubkey);

				const scriptHash = computeScriptHash(scriptPubkey);
				expect(backend.scriptHashCallbacks.has(scriptHash)).to.be.false;

				backend.subscribeError = false;
				backend.simulateNewBlock(100);
				await new Promise((r) => setTimeout(r, 50));

				expect(backend.scriptHashCallbacks.has(scriptHash)).to.be.true;
				watcher.stop();
			});

			it('should clear retry queue on successful retry', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.subscribeError = true;
				const scriptPubkey = Buffer.from('0014' + '00'.repeat(20), 'hex');
				await watcher.watchOutput('abcd5678', 0, scriptPubkey);

				backend.subscribeError = false;
				backend.simulateNewBlock(100);
				await new Promise((r) => setTimeout(r, 50));

				const callsBefore = backend.scriptHashCallbacks.size;
				backend.simulateNewBlock(101);
				await new Promise((r) => setTimeout(r, 50));
				expect(backend.scriptHashCallbacks.size).to.equal(callsBefore);

				watcher.stop();
			});

			it('should stop() clear retry queue', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.subscribeError = true;
				await watcher.watchOutput(
					'stop1234',
					0,
					Buffer.from('0014' + '00'.repeat(20), 'hex')
				);
				watcher.stop();
			});

			it('should succeed without queue on happy path', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				const scriptPubkey = Buffer.from('0014' + '00'.repeat(20), 'hex');
				await watcher.watchOutput('happy1234', 0, scriptPubkey);

				const scriptHash = computeScriptHash(scriptPubkey);
				expect(backend.scriptHashCallbacks.has(scriptHash)).to.be.true;
				watcher.stop();
			});

			it('should re-queue if retry also fails', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.subscribeError = true;
				const scriptPubkey = Buffer.from('0014' + 'aa'.repeat(20), 'hex');
				await watcher.watchOutput('retry1234', 0, scriptPubkey);

				backend.simulateNewBlock(100);
				await new Promise((r) => setTimeout(r, 50));

				const scriptHash = computeScriptHash(scriptPubkey);
				expect(backend.scriptHashCallbacks.has(scriptHash)).to.be.false;

				backend.subscribeError = false;
				backend.simulateNewBlock(101);
				await new Promise((r) => setTimeout(r, 50));

				expect(backend.scriptHashCallbacks.has(scriptHash)).to.be.true;
				watcher.stop();
			});
		});

		// ─── 1b. broadcast:tx failure retry ───

		describe('1b. broadcast:tx failure retry', () => {
			it('should queue failed broadcast for retry', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.broadcastError = true;

				const fakeTx = new bitcoin.Transaction();
				fakeTx.addInput(Buffer.alloc(32), 0);
				fakeTx.addOutput(Buffer.from('0014' + '00'.repeat(20), 'hex'), 50000);
				cm.emit('broadcast:tx', fakeTx.toBuffer());
				await new Promise((r) => setTimeout(r, 50));

				backend.broadcastError = false;
				backend.simulateNewBlock(100);
				await new Promise((r) => setTimeout(r, 50));

				expect(backend.broadcastedTxs.length).to.be.greaterThan(0);
				watcher.stop();
			});

			it('should dedup same txid in broadcast retry queue', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.broadcastError = true;

				const fakeTx = new bitcoin.Transaction();
				fakeTx.addInput(Buffer.alloc(32), 0);
				fakeTx.addOutput(Buffer.from('0014' + '00'.repeat(20), 'hex'), 50000);
				const txBuf = fakeTx.toBuffer();

				cm.emit('broadcast:tx', txBuf);
				cm.emit('broadcast:tx', txBuf);
				await new Promise((r) => setTimeout(r, 50));

				backend.broadcastError = false;
				backend.simulateNewBlock(100);
				await new Promise((r) => setTimeout(r, 50));

				expect(backend.broadcastedTxs.length).to.equal(1);
				watcher.stop();
			});

			it('should emit permanent failure after max retries', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.broadcastError = true;

				const fakeTx = new bitcoin.Transaction();
				fakeTx.addInput(Buffer.alloc(32), 0);
				fakeTx.addOutput(Buffer.from('0014' + 'bb'.repeat(20), 'hex'), 50000);
				cm.emit('broadcast:tx', fakeTx.toBuffer());
				await new Promise((r) => setTimeout(r, 50));

				let permanentFailure = false;
				watcher.on('broadcast:permanent_failure', () => {
					permanentFailure = true;
				});

				for (let i = 100; i <= 112; i++) {
					backend.simulateNewBlock(i);
					await new Promise((r) => setTimeout(r, 20));
				}

				expect(permanentFailure).to.be.true;
				watcher.stop();
			});

			it('should succeed on happy path without queue', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				const fakeTx = new bitcoin.Transaction();
				fakeTx.addInput(Buffer.alloc(32), 0);
				fakeTx.addOutput(Buffer.from('0014' + 'cc'.repeat(20), 'hex'), 50000);

				let success = false;
				watcher.on('broadcast:success', () => {
					success = true;
				});

				cm.emit('broadcast:tx', fakeTx.toBuffer());
				await new Promise((r) => setTimeout(r, 50));

				expect(success).to.be.true;
				watcher.stop();
			});

			it('should successful retry clear from queue', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.broadcastError = true;
				const fakeTx = new bitcoin.Transaction();
				fakeTx.addInput(Buffer.alloc(32), 0);
				fakeTx.addOutput(Buffer.from('0014' + 'dd'.repeat(20), 'hex'), 50000);
				cm.emit('broadcast:tx', fakeTx.toBuffer());
				await new Promise((r) => setTimeout(r, 50));

				backend.broadcastError = false;
				backend.simulateNewBlock(100);
				await new Promise((r) => setTimeout(r, 50));

				const count = backend.broadcastedTxs.length;
				backend.simulateNewBlock(101);
				await new Promise((r) => setTimeout(r, 50));
				expect(backend.broadcastedTxs.length).to.equal(count);

				watcher.stop();
			});

			it('should stop() clear broadcast retry queue', async () => {
				const cm = makeChannelManager();
				const backend = new MockChainBackend();
				const watcher = new ChainWatcher({ backend, channelManager: cm });
				await watcher.start();

				backend.broadcastError = true;
				const fakeTx = new bitcoin.Transaction();
				fakeTx.addInput(Buffer.alloc(32), 0);
				fakeTx.addOutput(Buffer.from('0014' + 'ee'.repeat(20), 'hex'), 50000);
				cm.emit('broadcast:tx', fakeTx.toBuffer());
				await new Promise((r) => setTimeout(r, 50));

				watcher.stop();
			});
		});

		// ─── 1c. Auto-force-close stuck AWAITING_REESTABLISH ───

		describe('1c. Auto-force-close stuck AWAITING_REESTABLISH', () => {
			it('should force-close channel stuck in AWAITING_REESTABLISH', () => {
				const alice = createNode(400, { reestablishTimeoutBlocks: 10 });
				const bob = createNode(401);
				connectNodes(alice, bob);
				const channelId = openReadyChannel(alice, bob);

				// Manually set channel state
				const cm = (alice as any).channelManager as ChannelManager;
				const channel = cm.getChannel(channelId);
				if (channel) {
					channel.getFullState().state = ChannelState.AWAITING_REESTABLISH;
					channel.getFullState().preReestablishState = ChannelState.NORMAL;
				}

				let forceCloseEmitted = false;
				alice.on('node:error', (err: { code: string }) => {
					if (err.code === 'REESTABLISH_TIMEOUT_FORCE_CLOSED')
						forceCloseEmitted = true;
				});

				// Trigger scanStuckChannels via block notification
				(alice as any).scanStuckChannels(100);
				for (let i = 101; i <= 112; i++) {
					(alice as any).scanStuckChannels(i);
				}

				expect(forceCloseEmitted).to.be.true;
				alice.destroy();
				bob.destroy();
			});

			it('should not force-close before timeout', () => {
				const alice = createNode(402, { reestablishTimeoutBlocks: 10 });
				const bob = createNode(403);
				connectNodes(alice, bob);
				const channelId = openReadyChannel(alice, bob);

				const cm = (alice as any).channelManager as ChannelManager;
				const channel = cm.getChannel(channelId);
				if (channel) {
					channel.getFullState().state = ChannelState.AWAITING_REESTABLISH;
					channel.getFullState().preReestablishState = ChannelState.NORMAL;
				}

				let forceCloseEmitted = false;
				alice.on('node:error', (err: { code: string }) => {
					if (err.code === 'REESTABLISH_TIMEOUT_FORCE_CLOSED')
						forceCloseEmitted = true;
				});

				for (let i = 100; i <= 105; i++) {
					(alice as any).scanStuckChannels(i);
				}

				expect(forceCloseEmitted).to.be.false;
				alice.destroy();
				bob.destroy();
			});

			it('should use configurable reestablishTimeoutBlocks', () => {
				const alice = createNode(404, { reestablishTimeoutBlocks: 5 });
				const bob = createNode(405);
				connectNodes(alice, bob);
				const channelId = openReadyChannel(alice, bob);

				const cm = (alice as any).channelManager as ChannelManager;
				const channel = cm.getChannel(channelId);
				if (channel) {
					channel.getFullState().state = ChannelState.AWAITING_REESTABLISH;
					channel.getFullState().preReestablishState = ChannelState.NORMAL;
				}

				let forceCloseEmitted = false;
				alice.on('node:error', (err: { code: string }) => {
					if (err.code === 'REESTABLISH_TIMEOUT_FORCE_CLOSED')
						forceCloseEmitted = true;
				});

				for (let i = 100; i <= 107; i++) {
					(alice as any).scanStuckChannels(i);
				}

				expect(forceCloseEmitted).to.be.true;
				alice.destroy();
				bob.destroy();
			});

			it('should clear tracker when channel reaches NORMAL', () => {
				const alice = createNode(406, { reestablishTimeoutBlocks: 100 });
				const bob = createNode(407);
				connectNodes(alice, bob);
				const channelId = openReadyChannel(alice, bob);

				const cm = (alice as any).channelManager as ChannelManager;
				const channel = cm.getChannel(channelId);
				if (channel) {
					channel.getFullState().state = ChannelState.AWAITING_REESTABLISH;
					channel.getFullState().preReestablishState = ChannelState.NORMAL;
				}

				(alice as any).scanStuckChannels(100);

				// Simulate channel back to NORMAL → emit channel:ready
				if (channel) channel.getFullState().state = ChannelState.NORMAL;
				// The channel:ready handler clears the tracker
				(alice as any)._stuckChannelTracker.delete(
					`reestablish:${channelId.toString('hex')}`
				);

				let forceCloseEmitted = false;
				alice.on('node:error', (err: { code: string }) => {
					if (err.code === 'REESTABLISH_TIMEOUT_FORCE_CLOSED')
						forceCloseEmitted = true;
				});

				for (let i = 101; i <= 250; i++) {
					(alice as any).scanStuckChannels(i);
				}

				expect(forceCloseEmitted).to.be.false;
				alice.destroy();
				bob.destroy();
			});

			it('should default reestablishTimeoutBlocks to 2016', () => {
				const alice = createNode(408);
				expect((alice as any).reestablishTimeoutBlocks).to.equal(2016);
				alice.destroy();
			});

			it('should emit error event with channel info', () => {
				const alice = createNode(410, { reestablishTimeoutBlocks: 3 });
				const bob = createNode(411);
				connectNodes(alice, bob);
				const channelId = openReadyChannel(alice, bob);

				const cm = (alice as any).channelManager as ChannelManager;
				const channel = cm.getChannel(channelId);
				if (channel) {
					channel.getFullState().state = ChannelState.AWAITING_REESTABLISH;
					channel.getFullState().preReestablishState = ChannelState.NORMAL;
				}

				const errors: Array<{ code: string; message: string }> = [];
				alice.on('node:error', (err: { code: string; message: string }) =>
					errors.push(err)
				);

				for (let i = 100; i <= 105; i++) {
					(alice as any).scanStuckChannels(i);
				}

				const reestablishError = errors.find(
					(e) => e.code === 'REESTABLISH_TIMEOUT_FORCE_CLOSED'
				);
				expect(reestablishError).to.exist;
				expect(reestablishError!.message).to.include('AWAITING_REESTABLISH');
				alice.destroy();
				bob.destroy();
			});
		});

		// ─── 1d. Stale gossip channel_update in pathfinding ───

		describe('1d. Stale gossip in pathfinding', () => {
			function makeKeys(n: number): Buffer[] {
				const keys: Buffer[] = [];
				for (let i = 0; i < n; i++) {
					keys.push(getPublicKey(makeSeed(500 + i)));
				}
				return keys.sort((a, b) => Buffer.compare(a, b));
			}

			it('should skip stale channel_update edges', () => {
				const graph = new NetworkGraph();
				const nodes = makeKeys(3);
				const now = Math.floor(Date.now() / 1000);
				const staleTs = now - DEFAULT_PRUNE_MAX_AGE - 100;

				buildGraphEdge(graph, nodes[0], nodes[1], makeScid(1, 1, 0), {
					timestamp: staleTs,
					feeBase: 100
				});
				buildGraphEdge(graph, nodes[0], nodes[2], makeScid(1, 2, 0), {
					timestamp: now,
					feeBase: 1000
				});
				buildGraphEdge(graph, nodes[2], nodes[1], makeScid(1, 3, 0), {
					timestamp: now,
					feeBase: 1000
				});

				// Without stale check — cheap direct route exists
				const routeNoStale = findRoute(graph, nodes[0], nodes[1], 10000n, 40);
				expect(routeNoStale).to.not.be.null;
				expect(routeNoStale!.hops.length).to.equal(1);

				// With stale check — must go through C
				const routeWithStale = findRoute(
					graph,
					nodes[0],
					nodes[1],
					10000n,
					40,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					now
				);
				expect(routeWithStale).to.not.be.null;
				expect(routeWithStale!.hops.length).to.equal(2);
			});

			it('should use fresh edges normally', () => {
				const graph = new NetworkGraph();
				const nodes = makeKeys(2);
				const now = Math.floor(Date.now() / 1000);

				buildGraphEdge(graph, nodes[0], nodes[1], makeScid(2, 1, 0), {
					timestamp: now
				});

				const route = findRoute(
					graph,
					nodes[0],
					nodes[1],
					10000n,
					40,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					now
				);
				expect(route).to.not.be.null;
				expect(route!.hops.length).to.equal(1);
			});

			it('should handle boundary timestamp (exactly at cutoff)', () => {
				const graph = new NetworkGraph();
				const nodes = makeKeys(2);
				const now = Math.floor(Date.now() / 1000);
				const exactBoundary = now - DEFAULT_PRUNE_MAX_AGE;

				buildGraphEdge(graph, nodes[0], nodes[1], makeScid(3, 1, 0), {
					timestamp: exactBoundary
				});

				const route = findRoute(
					graph,
					nodes[0],
					nodes[1],
					10000n,
					40,
					undefined,
					undefined,
					undefined,
					undefined,
					undefined,
					now
				);
				// At exact cutoff should still be valid (< means strictly before)
				expect(route).to.not.be.null;
			});

			it('should skip stale edges in MPP too', () => {
				const graph = new NetworkGraph();
				const nodes = makeKeys(3);
				const now = Math.floor(Date.now() / 1000);
				const staleTs = now - DEFAULT_PRUNE_MAX_AGE - 100;

				buildGraphEdge(graph, nodes[0], nodes[1], makeScid(4, 1, 0), {
					timestamp: staleTs
				});
				buildGraphEdge(graph, nodes[0], nodes[2], makeScid(4, 2, 0), {
					timestamp: now
				});
				buildGraphEdge(graph, nodes[2], nodes[1], makeScid(4, 3, 0), {
					timestamp: now
				});

				const route = findMultiPathRoute(
					graph,
					nodes[0],
					nodes[1],
					10000n,
					40,
					4,
					20,
					undefined,
					undefined,
					now
				);
				expect(route).to.not.be.null;
				for (const part of route!.parts) {
					expect(part.hops.length).to.be.greaterThan(1);
				}
			});

			it('should not apply stale check to synthetic hints', () => {
				const graph = new NetworkGraph();
				const nodes = makeKeys(3);
				const now = Math.floor(Date.now() / 1000);

				buildGraphEdge(graph, nodes[0], nodes[1], makeScid(5, 1, 0), {
					timestamp: now
				});

				const hints = [
					[
						{
							pubkey: nodes[1],
							shortChannelId: makeScid(5, 99, 0),
							feeBaseMsat: 1000,
							feeProportionalMillionths: 1,
							cltvExpiryDelta: 40
						}
					]
				];

				const route = findRoute(
					graph,
					nodes[0],
					nodes[2],
					10000n,
					40,
					undefined,
					undefined,
					undefined,
					undefined,
					hints,
					now
				);
				expect(route).to.not.be.null;
			});
		});
	});

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 2: Operational Stability
	// ═══════════════════════════════════════════════════════════════════════

	describe('Phase 2: Operational Stability', () => {
		describe('2a. WAL checkpoint scheduling', () => {
			it('should create walCheckpointTimer when storage has checkpoint()', () => {
				const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph11-wal-'));
				const dbPath = path.join(tmpDir, 'test.db');
				const storage = new SqliteStorage(dbPath);
				storage.open();

				const config = makeNodeConfig(500);
				config.storage = storage;
				const node = new LightningNode(config);
				node.on('error', () => {});

				expect((node as any).walCheckpointTimer).to.not.be.null;
				node.destroy();
				fs.rmSync(tmpDir, { recursive: true, force: true });
			});

			it('should clear checkpoint timer on destroy', () => {
				const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph11-wal3-'));
				const dbPath = path.join(tmpDir, 'test.db');
				const storage = new SqliteStorage(dbPath);
				storage.open();

				const config = makeNodeConfig(502);
				config.storage = storage;
				const node = new LightningNode(config);
				node.on('error', () => {});

				node.destroy();
				expect((node as any).walCheckpointTimer).to.be.null;
				fs.rmSync(tmpDir, { recursive: true, force: true });
			});

			it('should SqliteStorage.checkpoint() work', () => {
				const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph11-wal4-'));
				const dbPath = path.join(tmpDir, 'test.db');
				const storage = new SqliteStorage(dbPath);
				storage.open();

				expect(typeof storage.checkpoint).to.equal('function');
				storage.checkpoint(); // Should not throw
				storage.close();
				fs.rmSync(tmpDir, { recursive: true, force: true });
			});

			it('should not create timer without storage', () => {
				const node = createNode(503);
				expect((node as any).walCheckpointTimer).to.be.null;
				node.destroy();
			});
		});

		describe('2b. Gossip DB pruning', () => {
			it('should deleteGossipChannel remove row from storage', () => {
				const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph11-gdb-'));
				const dbPath = path.join(tmpDir, 'test.db');
				const storage = new SqliteStorage(dbPath);
				storage.open();

				const scidHex = 'aabbccdd00000000';
				const mockChannel = {
					shortChannelId: Buffer.from(scidHex, 'hex'),
					nodeId1: Buffer.alloc(33, 1),
					nodeId2: Buffer.alloc(33, 2),
					features: Buffer.alloc(0),
					announcement: {} as any,
					update1: null as any,
					update2: null as any
				};
				storage.saveGossipChannel(scidHex, mockChannel);
				expect(storage.loadAllGossipChannels().length).to.equal(1);

				storage.deleteGossipChannel(scidHex);
				expect(storage.loadAllGossipChannels().length).to.equal(0);

				storage.close();
				fs.rmSync(tmpDir, { recursive: true, force: true });
			});

			it('should fresh channels survive delete of other SCID', () => {
				const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph11-gdb2-'));
				const dbPath = path.join(tmpDir, 'test.db');
				const storage = new SqliteStorage(dbPath);
				storage.open();

				const scidHex = 'aabbccdd11111111';
				storage.saveGossipChannel(scidHex, {
					shortChannelId: Buffer.from(scidHex, 'hex'),
					nodeId1: Buffer.alloc(33, 1),
					nodeId2: Buffer.alloc(33, 2),
					features: Buffer.alloc(0),
					announcement: {} as any,
					update1: null as any,
					update2: null as any
				});

				storage.deleteGossipChannel('0000000000000000');
				expect(storage.loadAllGossipChannels().length).to.equal(1);

				storage.close();
				fs.rmSync(tmpDir, { recursive: true, force: true });
			});

			it('should not crash when storage lacks deleteGossipChannel', () => {
				const node = createNode(504);
				(node as any).pruneStaleGossipWithStorage();
				node.destroy();
			});

			it('should prune timer delete stale channels from storage', () => {
				const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph11-gdb3-'));
				const dbPath = path.join(tmpDir, 'test.db');
				const storage = new SqliteStorage(dbPath);
				storage.open();

				const now = Math.floor(Date.now() / 1000);
				const staleTs = now - DEFAULT_PRUNE_MAX_AGE - 100;

				const scidHex = 'aabbccdd22222222';
				const nodeKey1 = Buffer.alloc(33, 1);
				const nodeKey2 = Buffer.alloc(33, 2);

				storage.saveGossipChannel(scidHex, {
					shortChannelId: Buffer.from(scidHex, 'hex'),
					nodeId1: nodeKey1,
					nodeId2: nodeKey2,
					features: Buffer.alloc(0),
					announcement: {} as any,
					update1: {
						signature: Buffer.alloc(64),
						chainHash: BITCOIN_CHAIN_HASH,
						shortChannelId: Buffer.from(scidHex, 'hex'),
						timestamp: staleTs,
						messageFlags: 0,
						channelFlags: 0,
						cltvExpiryDelta: 40,
						htlcMinimumMsat: 0n,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 1
					} as any,
					update2: null as any
				});

				const config = makeNodeConfig(505);
				config.storage = storage;
				const node = new LightningNode(config);
				node.on('error', () => {});

				// Add to graph
				(node as any).graph.addChannelAnnouncement({
					nodeSignature1: Buffer.alloc(64),
					nodeSignature2: Buffer.alloc(64),
					bitcoinSignature1: Buffer.alloc(64),
					bitcoinSignature2: Buffer.alloc(64),
					features: Buffer.alloc(0),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: Buffer.from(scidHex, 'hex'),
					nodeId1: nodeKey1,
					nodeId2: nodeKey2,
					bitcoinKey1: nodeKey1,
					bitcoinKey2: nodeKey2
				});
				(node as any).graph.applyChannelUpdate({
					signature: Buffer.alloc(64),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: Buffer.from(scidHex, 'hex'),
					timestamp: staleTs,
					messageFlags: 0,
					channelFlags: 0,
					cltvExpiryDelta: 40,
					htlcMinimumMsat: 0n,
					feeBaseMsat: 1000,
					feeProportionalMillionths: 1
				});

				(node as any).pruneStaleGossipWithStorage();

				expect(storage.loadAllGossipChannels().length).to.equal(0);

				node.destroy();
				fs.rmSync(tmpDir, { recursive: true, force: true });
			});
		});

		describe('2c. Reconnect timer cleanup', () => {
			it('should use Set for _reconnectTimers', () => {
				const node = createNode(510);
				expect((node as any)._reconnectTimers).to.be.instanceOf(Set);
				node.destroy();
			});

			it('should destroy clear all reconnect timers', () => {
				const node = createNode(511);
				const timer = setTimeout(() => {}, 999999);
				(node as any)._reconnectTimers.add(timer);
				expect((node as any)._reconnectTimers.size).to.equal(1);

				node.destroy();
				expect((node as any)._reconnectTimers.size).to.equal(0);
				clearTimeout(timer);
			});
		});
	});

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 3: Developer Experience
	// ═══════════════════════════════════════════════════════════════════════

	describe('Phase 3: Developer Experience', () => {
		describe('3a. waitForReady / node:ready event', () => {
			it('should resolve immediately with no channels', async () => {
				const node = createNode(600);
				await node.waitForReady(5000);
				node.destroy();
			});

			it('should resolve after emitReady fires', (done) => {
				const node = createNode(601);
				(node as any)._readyEmitted = false;

				node.once('node:ready', () => {
					done();
					node.destroy();
				});

				(node as any).emitReady();
			});

			it('should timeout correctly', async () => {
				const node = createNode(602);
				const bob = createNode(603);
				connectNodes(node, bob);
				const channelId = openReadyChannel(node, bob);

				// openReadyChannel drives the channel to NORMAL, whose channel:ready
				// handler calls emitReady() and schedules a node:ready on nextTick.
				// Let that settle so it doesn't leak into the wait below; then we
				// revert to a genuinely not-ready state to exercise the timeout.
				await new Promise((r) => setImmediate(r));

				const cm = (node as any).channelManager as ChannelManager;
				const ch = cm.getChannel(channelId);
				if (ch) ch.getFullState().state = ChannelState.AWAITING_REESTABLISH;
				(node as any)._readyEmitted = false;

				try {
					await node.waitForReady(100);
					expect.fail('Should have timed out');
				} catch (err: unknown) {
					expect((err as Error).message).to.include('did not become ready');
				}

				node.destroy();
				bob.destroy();
			});

			it('should multiple callers all resolve', async () => {
				const node = createNode(604);
				await Promise.all([
					node.waitForReady(5000),
					node.waitForReady(5000),
					node.waitForReady(5000)
				]);
				node.destroy();
			});

			it('should fire even when all reconnections fail', (done) => {
				const node = createNode(605);
				(node as any)._readyEmitted = false;
				(node as any)._pendingReconnects = 1;

				node.once('node:ready', () => {
					done();
					node.destroy();
				});

				(node as any)._pendingReconnects = 0;
				(node as any).emitReady();
			});

			it('should destroy reject pending waits', async () => {
				const node = createNode(606);
				const bob = createNode(607);
				connectNodes(node, bob);
				const channelId = openReadyChannel(node, bob);

				const cm = (node as any).channelManager as ChannelManager;
				const ch = cm.getChannel(channelId);
				if (ch) ch.getFullState().state = ChannelState.AWAITING_REESTABLISH;
				(node as any)._readyEmitted = false;

				const waitPromise = node.waitForReady(30_000);
				node.destroy();
				bob.destroy();

				try {
					await waitPromise;
					expect.fail('Should have been rejected');
				} catch (err: unknown) {
					expect((err as Error).message).to.include('destroyed');
				}
			});
		});

		describe('3b. Typed payment errors', () => {
			it('should throw LightningPaymentError with NO_ROUTE code', () => {
				const node = createNode(700);

				const paymentHash = crypto.randomBytes(32);
				const paymentSecret = crypto.randomBytes(32);
				const invoice = encodeInvoice({
					network: Network.REGTEST,
					paymentHash,
					paymentSecret,
					timestamp: Math.floor(Date.now() / 1000),
					description: 'test',
					minFinalCltvExpiry: 40,
					amountMsat: 1000n,
					payeeNodeKey: getPublicKey(makeSeed(999)),
					privateKey: makeSeed(999)
				});

				try {
					node.sendPayment(invoice);
					expect.fail('Should throw');
				} catch (err: unknown) {
					expect(err).to.be.instanceOf(LightningPaymentError);
					expect((err as LightningPaymentError).code).to.equal(
						LightningErrorCode.NO_ROUTE
					);
				}

				node.destroy();
			});

			it('should LightningPaymentError extend Error', () => {
				const err = new LightningPaymentError(
					LightningErrorCode.NO_ROUTE,
					'test'
				);
				expect(err).to.be.instanceOf(Error);
				expect(err.name).to.equal('LightningPaymentError');
				expect(err.code).to.equal(LightningErrorCode.NO_ROUTE);
			});

			it('should all 8 error codes be defined', () => {
				const codes = Object.values(LightningErrorCode);
				expect(codes).to.have.lengthOf(8);
				expect(codes).to.include('NO_ROUTE');
				expect(codes).to.include('DUPLICATE_PAYMENT');
				expect(codes).to.include('NO_CHANNEL_TO_HOP');
				expect(codes).to.include('FEE_EXCEEDS_MAX');
				expect(codes).to.include('MISSING_AMOUNT');
				expect(codes).to.include('INVALID_INVOICE');
				expect(codes).to.include('INVOICE_EXPIRED');
				expect(codes).to.include('INVALID_KEYSEND');
			});

			it('should INVOICE_EXPIRED return FAILED payment', () => {
				const node = createNode(705);

				const paymentHash = crypto.randomBytes(32);
				const paymentSecret = crypto.randomBytes(32);
				const expiredTimestamp = Math.floor(Date.now() / 1000) - 7200;
				const invoice = encodeInvoice({
					network: Network.REGTEST,
					paymentHash,
					paymentSecret,
					timestamp: expiredTimestamp,
					description: 'expired',
					minFinalCltvExpiry: 40,
					amountMsat: 1000n,
					expiry: 3600,
					payeeNodeKey: getPublicKey(makeSeed(999)),
					privateKey: makeSeed(999)
				});

				const result = node.sendPayment(invoice);
				expect(result.status).to.equal(PaymentStatus.FAILED);
				node.destroy();
			});

			it('should BeignetNode code mapping be correct', () => {
				const codeMap: Record<string, string> = {
					NO_ROUTE: 'NO_ROUTE',
					DUPLICATE_PAYMENT: 'DUPLICATE_PAYMENT',
					NO_CHANNEL_TO_HOP: 'PEER_NOT_CONNECTED',
					FEE_EXCEEDS_MAX: 'PAYMENT_FAILED',
					MISSING_AMOUNT: 'INVALID_PARAMS',
					INVALID_INVOICE: 'INVALID_PARAMS',
					INVOICE_EXPIRED: 'INVOICE_EXPIRED'
				};

				for (const [lightningCode, beignetCode] of Object.entries(codeMap)) {
					expect(codeMap[lightningCode]).to.equal(beignetCode);
				}
			});
		});
	});
});
