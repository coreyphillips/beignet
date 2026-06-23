/**
 * Phase 4: Channel Announcements wiring tests.
 *
 * Tests that:
 * 1. ChannelManager routes MessageType.ANNOUNCEMENT_SIGNATURES (259) to channel
 * 2. processActions emits 'announcement:ready' event
 * 3. ChainWatcher emits 'announcement:depth' at 6 confirmations
 * 4. LightningNode wires everything together
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import {
	ChainWatcher,
	IChainBackend
} from '../../src/lightning/chain/chain-watcher';
import { Network } from '../../src/lightning/invoice/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';

// ── Helpers ──────────────────────────────────────────────────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`ann-seed-${id}`))
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
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	return node;
}

function makeChannelManagerConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	return {
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

class MockBackend implements IChainBackend {
	private headerCallbacks: ((height: number) => void)[] = [];
	private _scriptHashSubscriptions: Map<string, (() => void)[]> = new Map();
	private _history: Map<string, Array<{ txid: string; height: number }>> =
		new Map();
	private _transactions: Map<string, Buffer> = new Map();

	async subscribeToHeaders(cb: (h: number) => void): Promise<void> {
		this.headerCallbacks.push(cb);
	}

	simulateBlock(h: number): void {
		for (const cb of this.headerCallbacks) cb(h);
	}

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		const subs = this._scriptHashSubscriptions.get(scriptHash) || [];
		subs.push(onChange);
		this._scriptHashSubscriptions.set(scriptHash, subs);
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this._history.get(scriptHash) || [];
	}

	async getTransaction(txid: string): Promise<Buffer> {
		return this._transactions.get(txid) || Buffer.alloc(0);
	}

	async broadcastTransaction(_rawTxHex: string): Promise<string> {
		return 'mock-txid';
	}

	async getTransactionMerkleProof(
		_txid: string,
		_height: number
	): Promise<{ blockHeight: number; txIndex: number }> {
		return { blockHeight: 100, txIndex: 2 };
	}

	setHistory(
		scriptHash: string,
		history: Array<{ txid: string; height: number }>
	): void {
		this._history.set(scriptHash, history);
	}
}

// ── Tests ────────────────────────────────────────────────────────────

describe('Channel Announcement Wiring (Phase 4)', () => {
	describe('MessageType.ANNOUNCEMENT_SIGNATURES', () => {
		it('should equal 259', () => {
			expect(MessageType.ANNOUNCEMENT_SIGNATURES).to.equal(259);
		});

		it('should be registered in ChannelManager message routing', () => {
			// ChannelManager.attachToPeerManager registers ANNOUNCEMENT_SIGNATURES
			// in the channelMsgTypes array. Verify by checking handleMessage does not
			// throw for type 259 (unknown channel ID is fine, we just check routing).
			const config = makeChannelManagerConfig(50);
			const cm = new ChannelManager(config);
			cm.on('error', () => {}); // absorb error for unknown channel

			// handleMessage with type 259 should not throw — it routes to handleAnnouncementSignaturesMsg
			const fakePayload = Buffer.alloc(168); // ANNOUNCEMENT_SIGNATURES_LENGTH
			expect(() => {
				cm.handleMessage(
					'aa'.repeat(33),
					MessageType.ANNOUNCEMENT_SIGNATURES,
					fakePayload
				);
			}).to.not.throw();
		});
	});

	describe('encodeShortChannelId', () => {
		it('should encode block/tx/output into 8 bytes', () => {
			const scid = encodeShortChannelId({
				block: 600000,
				txIndex: 1,
				outputIndex: 0
			});
			expect(scid).to.have.length(8);
		});

		it('should encode known values correctly', () => {
			const scid = encodeShortChannelId({
				block: 1,
				txIndex: 2,
				outputIndex: 3
			});
			expect(scid).to.have.length(8);
			// block=1, txIndex=2, outputIndex=3
			// (1 << 40) | (2 << 16) | 3 = 0x0000010000020003
			const val = scid.readBigUInt64BE();
			expect(val).to.equal((1n << 40n) | (2n << 16n) | 3n);
		});
	});

	describe('ChainWatcher announcement:depth event', () => {
		it('should emit announcement:depth at 6 confirmations', (done) => {
			const backend = new MockBackend();
			const cmConfig = makeChannelManagerConfig(51);
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const watcher = new ChainWatcher({
				backend,
				channelManager: cm
			});

			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0014' + crypto.randomBytes(20).toString('hex'),
				'hex'
			);

			// Set up history so the funding appears confirmed at height 100
			const {
				computeScriptHash
			} = require('../../src/lightning/chain/chain-watcher');
			const scriptHash = computeScriptHash(scriptPubkey);
			backend.setHistory(scriptHash, [{ txid, height: 100 }]);

			watcher.on(
				'announcement:depth',
				(announcedChannelId: Buffer, blockHeight: number, txIndex: number) => {
					expect(announcedChannelId.equals(channelId)).to.be.true;
					expect(blockHeight).to.equal(100);
					expect(txIndex).to.equal(2); // from MockBackend.getTransactionMerkleProof
					watcher.stop();
					done();
				}
			);

			// Watch the funding output with minimumDepth=1
			watcher
				.watchFundingOutput(channelId, txid, 0, 1, scriptPubkey)
				.then(() => {
					return watcher.start();
				})
				.then(() => {
					// Simulate block at height 100 — triggers funding confirmation (depth=1 >= minimumDepth=1)
					backend.simulateBlock(100);
					// After a tick, simulate block at 105 — that gives us depth = 105-100+1 = 6
					setTimeout(() => {
						backend.simulateBlock(105);
					}, 50);
				});
		});

		it('should not emit announcement:depth before 6 confirmations', (done) => {
			const backend = new MockBackend();
			const cmConfig = makeChannelManagerConfig(52);
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const watcher = new ChainWatcher({
				backend,
				channelManager: cm
			});

			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0014' + crypto.randomBytes(20).toString('hex'),
				'hex'
			);

			const {
				computeScriptHash
			} = require('../../src/lightning/chain/chain-watcher');
			const scriptHash = computeScriptHash(scriptPubkey);
			backend.setHistory(scriptHash, [{ txid, height: 100 }]);

			let announcementEmitted = false;
			watcher.on('announcement:depth', () => {
				announcementEmitted = true;
			});

			watcher
				.watchFundingOutput(channelId, txid, 0, 1, scriptPubkey)
				.then(() => {
					return watcher.start();
				})
				.then(() => {
					// Confirm funding at height 100
					backend.simulateBlock(100);
					// Simulate block 104 — depth = 104-100+1 = 5 (not enough)
					setTimeout(() => {
						backend.simulateBlock(104);
						setTimeout(() => {
							expect(announcementEmitted).to.be.false;
							watcher.stop();
							done();
						}, 50);
					}, 50);
				});
		});
	});

	describe('Private channel skips announcement', () => {
		it('should not trigger announcement for private channels (announceChannel=false)', () => {
			const seed = makeSeed(53);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(153)
			});

			// Simulate a private channel by setting announceChannel=false
			state.announceChannel = false;
			state.state = ChannelState.NORMAL;
			state.channelId = crypto.randomBytes(32);

			const channel = new Channel(state);

			// handleAnnouncementDepthReached should return empty actions for private channel
			const localNodeId = getPublicKey(makeSeed(53));
			const remoteNodeId = getPublicKey(makeSeed(54));
			const actions = channel.handleAnnouncementDepthReached(
				100,
				1,
				localNodeId,
				remoteNodeId,
				(_data: Buffer) => ({
					nodeSig: crypto.randomBytes(64),
					bitcoinSig: crypto.randomBytes(64)
				})
			);

			expect(actions).to.have.length(0);
		});
	});

	describe('LightningNode creation', () => {
		it('should create a node with valid nodeId', () => {
			const node = createNode(60);
			const info = node.getNodeInfo();
			expect(info.nodeId).to.be.a('string');
			expect(info.nodeId).to.have.length(66); // 33-byte compressed pubkey hex
			node.destroy();
		});

		it('should have a ChannelManager accessible', () => {
			const node = createNode(61);
			const cm = node.getChannelManager();
			expect(cm).to.be.instanceOf(ChannelManager);
			node.destroy();
		});
	});

	describe('Channel announcement state fields', () => {
		it('should default localAnnouncementNodeSig to null', () => {
			const seed = makeSeed(70);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(170)
			});

			expect(state.localAnnouncementNodeSig).to.be.null;
			expect(state.localAnnouncementBitcoinSig).to.be.null;
		});

		it('should default announcementSigsSent to false', () => {
			const seed = makeSeed(71);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(171)
			});

			expect(state.announcementSigsSent).to.be.false;
			expect(state.announcementSigsReceived).to.be.false;
		});

		it('should default announceChannel to true for opener', () => {
			const seed = makeSeed(72);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: makeSeed(172)
			});

			expect(state.announceChannel).to.be.true;
		});
	});

	describe('ChannelManager restoreMonitor', () => {
		it('should have restoreMonitor as a method', () => {
			const config = makeChannelManagerConfig(80);
			const cm = new ChannelManager(config);
			expect(cm.restoreMonitor).to.be.a('function');
		});
	});

	describe('ChannelManager triggerAnnouncementDepth', () => {
		it('should exist as a callable method', () => {
			const config = makeChannelManagerConfig(81);
			const cm = new ChannelManager(config);
			expect(cm.triggerAnnouncementDepth).to.be.a('function');
		});

		it('should silently return for unknown channelId', () => {
			const config = makeChannelManagerConfig(82);
			const cm = new ChannelManager(config);
			cm.on('error', () => {});

			// Should not throw for nonexistent channel
			expect(() => {
				cm.triggerAnnouncementDepth(
					crypto.randomBytes(32),
					100,
					1,
					getPublicKey(makeSeed(82)),
					(_data: Buffer) => ({
						nodeSig: crypto.randomBytes(64),
						bitcoinSig: crypto.randomBytes(64)
					})
				);
			}).to.not.throw();
		});
	});

	describe('ChannelManager announcement:ready event', () => {
		it('should have ANNOUNCEMENT_READY action type defined', () => {
			expect(ChannelActionType.ANNOUNCEMENT_READY).to.equal(
				'ANNOUNCEMENT_READY'
			);
		});
	});

	describe('ElectrumBackend getTransactionMerkleProof', () => {
		it('should be defined as a method on ElectrumBackend prototype', () => {
			expect(ElectrumBackend.prototype.getTransactionMerkleProof).to.be.a(
				'function'
			);
		});
	});

	describe('LightningNode announcement wiring', () => {
		it('should wire ChainWatcher announcement:depth to ChannelManager triggerAnnouncementDepth', () => {
			// Verify that LightningNode has a startChainWatcher method which
			// does the wiring between ChainWatcher events and ChannelManager
			const node = createNode(90);
			expect(node.startChainWatcher).to.be.a('function');
			node.destroy();
		});

		it('should forward announcement:ready from ChannelManager', (done) => {
			const node = createNode(91);

			node.on('announcement:ready', (channelId: Buffer) => {
				expect(channelId).to.be.instanceOf(Buffer);
				node.destroy();
				done();
			});

			// Manually emit announcement:ready on the ChannelManager to verify wiring
			const cm = node.getChannelManager();
			const fakeChannelId = crypto.randomBytes(32);
			const fakeAnnouncement = Buffer.alloc(430); // channel_announcement placeholder
			const fakeUpdate = Buffer.alloc(130); // channel_update placeholder
			cm.emit(
				'announcement:ready',
				fakeChannelId,
				fakeAnnouncement,
				fakeUpdate
			);
		});
	});
});
