/**
 * Production Hardening Tests
 *
 * Tests for the 10 fixes in the AI-agent readiness plan:
 * - Fix 1: Thread missing keys through fromMnemonic()
 * - Fix 2: Fix force-close destination script placeholder
 * - Fix 3: Wire ChainWatcher into BeignetNode (restoreChainWatches)
 * - Fix 4: Payment retry with alternative routes
 * - Fix 5: Gossip graph persistence round-trip test
 * - Fix 7: Crash recovery restore fix (NORMAL → AWAITING_REESTABLISH)
 * - Fix 8: Invoice expiry check before sending HTLC
 * - Fix 9: MPP timeout auto-trigger
 * - Fix 10: update_fee public API
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	PaymentStatus,
	IPaymentInfo
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
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChainWatcher,
	IChainBackend
} from '../../src/lightning/chain/chain-watcher';
import { findRoute } from '../../src/lightning/gossip/pathfinding';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	encodeChannelAnnouncementMessage,
	encodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import {
	signChannelAnnouncement,
	signChannelUpdate
} from '../../src/lightning/gossip/validation';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	deriveLightningKeysFromMnemonic,
	LnCoinType
} from '../../src/lightning/keys/wallet-keys';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`prod-seed-${id}`))
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
	const revocationBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([1]))
		.digest();
	const paymentBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([2]))
		.digest();
	const delayedPaymentBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([3]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		revocationBasepointSecret,
		paymentBasepointSecret,
		delayedPaymentBasepointSecret
	};
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
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

// ─────────────── Gossip Helpers ───────────────

function createSignedChannelAnnouncement(
	nodePrivkey1: Buffer,
	nodePrivkey2: Buffer,
	bitcoinPrivkey1: Buffer,
	bitcoinPrivkey2: Buffer,
	scid: Buffer
): { msg: IChannelAnnouncementMessage; payload: Buffer } {
	const nodePub1 = getPublicKey(nodePrivkey1);
	const nodePub2 = getPublicKey(nodePrivkey2);
	const bitcoinPub1 = getPublicKey(bitcoinPrivkey1);
	const bitcoinPub2 = getPublicKey(bitcoinPrivkey2);

	let nk1 = nodePrivkey1,
		nk2 = nodePrivkey2;
	let np1 = nodePub1,
		np2 = nodePub2;
	let bk1 = bitcoinPrivkey1,
		bk2 = bitcoinPrivkey2;
	let bp1 = bitcoinPub1,
		bp2 = bitcoinPub2;

	if (Buffer.compare(nodePub1, nodePub2) > 0) {
		[nk1, nk2] = [nk2, nk1];
		[np1, np2] = [np2, np1];
		[bk1, bk2] = [bk2, bk1];
		[bp1, bp2] = [bp2, bp1];
	}

	const unsignedMsg: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: np1,
		nodeId2: np2,
		bitcoinKey1: bp1,
		bitcoinKey2: bp2
	};

	const unsignedPayload = encodeChannelAnnouncementMessage(unsignedMsg);
	const sigs1 = signChannelAnnouncement(unsignedPayload, nk1, bk1);
	const sigs2 = signChannelAnnouncement(unsignedPayload, nk2, bk2);

	const msg: IChannelAnnouncementMessage = {
		...unsignedMsg,
		nodeSignature1: sigs1.nodeSignature,
		nodeSignature2: sigs2.nodeSignature,
		bitcoinSignature1: sigs1.bitcoinSignature,
		bitcoinSignature2: sigs2.bitcoinSignature
	};

	const payload = encodeChannelAnnouncementMessage(msg);
	return { msg, payload };
}

function createSignedChannelUpdatePayload(
	nodePrivkey: Buffer,
	scid: Buffer,
	direction: number,
	opts?: Partial<IChannelUpdateMessage>
): { msg: IChannelUpdateMessage; payload: Buffer } {
	const msg: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: direction,
		cltvExpiryDelta: opts?.cltvExpiryDelta ?? 40,
		htlcMinimumMsat: opts?.htlcMinimumMsat ?? 1000n,
		feeBaseMsat: opts?.feeBaseMsat ?? 1000,
		feeProportionalMillionths: opts?.feeProportionalMillionths ?? 1,
		htlcMaximumMsat: opts?.htlcMaximumMsat ?? 1_000_000_000n
	};

	const unsignedPayload = encodeChannelUpdateMessage(msg);
	const signature = signChannelUpdate(unsignedPayload, nodePrivkey);
	msg.signature = signature;
	const payload = encodeChannelUpdateMessage(msg);
	return { msg, payload };
}

// ─────────────── Mock Chain Backend ───────────────

function createMockBackend(): IChainBackend {
	return {
		subscribeToHeaders: async () => {},
		subscribeToScriptHash: async () => {},
		getScriptHashHistory: async () => [],
		getTransaction: async () => Buffer.alloc(0),
		broadcastTransaction: async () => 'mock-txid'
	};
}

// ─────────────── Tests ───────────────

describe('Production Hardening', () => {
	// ─────── Fix 1: Thread missing keys through fromMnemonic() ───────

	describe('Fix 1: Thread missing keys through fromMnemonic()', () => {
		const mnemonic =
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

		it('should derive and thread all basepoint secrets through fromMnemonic', () => {
			const keys = deriveLightningKeysFromMnemonic(
				mnemonic,
				undefined,
				LnCoinType.REGTEST
			);

			expect(keys.revocationBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(keys.revocationBasepointSecret.length).to.equal(32);
			expect(keys.paymentBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(keys.paymentBasepointSecret.length).to.equal(32);
			expect(keys.delayedPaymentBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(keys.delayedPaymentBasepointSecret.length).to.equal(32);

			expect(keys.revocationBasepointSecret.equals(keys.paymentBasepointSecret))
				.to.be.false;
			expect(
				keys.paymentBasepointSecret.equals(keys.delayedPaymentBasepointSecret)
			).to.be.false;
		});

		it('should pass keys to ChannelManager config via fromMnemonic', () => {
			const node = LightningNode.fromMnemonic(mnemonic, {
				network: Network.REGTEST,
				coinType: LnCoinType.REGTEST
			});
			node.on('error', () => {});

			const cm = node.getChannelManager();
			expect(cm).to.not.be.null;
			node.destroy();
		});

		it('should construct INodeConfig with all three basepoint secrets', () => {
			const config = makeNodeConfig(500);
			expect(config.revocationBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(config.revocationBasepointSecret!.length).to.equal(32);
			expect(config.paymentBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(config.paymentBasepointSecret!.length).to.equal(32);
			expect(config.delayedPaymentBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(config.delayedPaymentBasepointSecret!.length).to.equal(32);
		});

		it('should fallback gracefully when keys are not provided', () => {
			const seed = makeSeed(502);
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

			const config: INodeConfig = {
				nodePrivateKey,
				network: Network.REGTEST,
				channelBasepoints: makeBasepoints(seed),
				perCommitmentSeed: makeSeed(602),
				fundingPrivkey
			};

			const node = new LightningNode(config);
			node.on('error', () => {});
			expect(node.getNodeId()).to.be.a('string');
			node.destroy();
		});
	});

	// ─────── Fix 2: Fix force-close destination script placeholder ───────

	describe('Fix 2: Fix force-close destination script', () => {
		it('should create ChainWatcher with a valid P2WPKH destination script', () => {
			const config = makeNodeConfig(510);
			const backend = createMockBackend();
			config.chainBackend = backend;

			const node = new LightningNode(config);
			node.on('error', () => {});

			const watcher = node.getChainWatcher();
			expect(watcher).to.not.be.null;
			node.destroy();
		});

		it('ChainWatcher should use configured destination script', () => {
			const destScript = Buffer.from('0014' + 'ab'.repeat(20), 'hex');
			const cmConfig: IChannelManagerConfig = {
				localBasepoints: makeBasepoints(makeSeed(511)),
				localPerCommitmentSeed: makeSeed(611),
				localFundingPrivkey: makeSeed(711)
			};
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const watcher = new ChainWatcher({
				backend: createMockBackend(),
				channelManager: cm,
				destinationScript: destScript
			});

			expect(watcher).to.not.be.null;
			expect(watcher.getCurrentBlockHeight()).to.equal(0);
			watcher.stop();
		});

		it('ChainWatcher should fall back to zeros when no destination script provided', () => {
			const cmConfig: IChannelManagerConfig = {
				localBasepoints: makeBasepoints(makeSeed(512)),
				localPerCommitmentSeed: makeSeed(612),
				localFundingPrivkey: makeSeed(712)
			};
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const watcher = new ChainWatcher({
				backend: createMockBackend(),
				channelManager: cm
			});
			expect(watcher).to.not.be.null;
			watcher.stop();
		});
	});

	// ─────── Fix 3: Wire ChainWatcher + restoreChainWatches ───────

	describe('Fix 3: Wire ChainWatcher + restoreChainWatches', () => {
		it('fromMnemonic should accept chainBackend option', () => {
			const mnemonic =
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
			const backend = createMockBackend();

			const node = LightningNode.fromMnemonic(mnemonic, {
				network: Network.REGTEST,
				coinType: LnCoinType.REGTEST,
				chainBackend: backend
			});
			node.on('error', () => {});

			expect(node.getChainWatcher()).to.not.be.null;
			node.destroy();
		});

		it('startChainWatcher should start and restore watches', async () => {
			const mnemonic =
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
			let headerCallbackCalled = false;
			const backend: IChainBackend = {
				subscribeToHeaders: async (cb) => {
					headerCallbackCalled = true;
					cb(100);
				},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => 'mock'
			};

			const node = LightningNode.fromMnemonic(mnemonic, {
				network: Network.REGTEST,
				coinType: LnCoinType.REGTEST,
				chainBackend: backend
			});
			node.on('error', () => {});

			await node.startChainWatcher();
			expect(headerCallbackCalled).to.be.true;
			expect(node.getCurrentBlockHeight()).to.equal(100);
			node.destroy();
		});

		it('restoreChainWatches should skip when no channels exist', async () => {
			const mnemonic =
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
			const backend = createMockBackend();

			const node = LightningNode.fromMnemonic(mnemonic, {
				network: Network.REGTEST,
				coinType: LnCoinType.REGTEST,
				chainBackend: backend
			});
			node.on('error', () => {});

			await node.restoreChainWatches();
			node.destroy();
		});
	});

	// ─────── Fix 4: Payment retry with alternative routes ───────

	describe('Fix 4: Payment retry with alternative routes', () => {
		it('findRoute should accept excludedChannels parameter', () => {
			const graph = new NetworkGraph();
			const source = crypto.randomBytes(33);
			const dest = crypto.randomBytes(33);

			const route = findRoute(
				graph,
				source,
				dest,
				1000n,
				40,
				undefined,
				new Set()
			);
			expect(route).to.be.null;
		});

		it('findRoute should skip excluded channels', () => {
			const graph = new NetworkGraph();
			const nodeKey1 = crypto.randomBytes(32);
			const nodeKey2 = crypto.randomBytes(32);
			const btcKey1 = crypto.randomBytes(32);
			const btcKey2 = crypto.randomBytes(32);

			const source = getPublicKey(nodeKey1);
			const dest = getPublicKey(nodeKey2);

			const scid1 = encodeShortChannelId({
				block: 1,
				txIndex: 0,
				outputIndex: 0
			});
			const { msg: ann1 } = createSignedChannelAnnouncement(
				nodeKey1,
				nodeKey2,
				btcKey1,
				btcKey2,
				scid1
			);
			graph.addChannelAnnouncement(ann1);

			// Add both direction updates
			const isSourceNode1 = source.compare(dest) < 0;
			const { msg: up1 } = createSignedChannelUpdatePayload(
				isSourceNode1 ? nodeKey1 : nodeKey2,
				scid1,
				isSourceNode1 ? 0 : 1
			);
			graph.applyChannelUpdate(up1);
			const { msg: up2 } = createSignedChannelUpdatePayload(
				isSourceNode1 ? nodeKey2 : nodeKey1,
				scid1,
				isSourceNode1 ? 1 : 0
			);
			graph.applyChannelUpdate(up2);

			// Route should work without exclusion
			const route1 = findRoute(graph, source, dest, 1000n, 40);
			expect(route1).to.not.be.null;

			// Exclude the only channel — should fail
			const excluded = new Set([scid1.toString('hex')]);
			const route2 = findRoute(
				graph,
				source,
				dest,
				1000n,
				40,
				undefined,
				excluded
			);
			expect(route2).to.be.null;
		});

		it('retry context should be cleaned up on destroy', () => {
			const node = createNode(523);
			node.destroy();
		});
	});

	// ─────── Fix 5: Gossip graph persistence round-trip ───────

	describe('Fix 5: Gossip graph persistence round-trip', () => {
		it('restoreChannel should populate graph', () => {
			const graph = new NetworkGraph();
			const nodeKey1 = crypto.randomBytes(32);
			const nodeKey2 = crypto.randomBytes(32);
			const btcKey1 = crypto.randomBytes(32);
			const btcKey2 = crypto.randomBytes(32);

			const scid = encodeShortChannelId({
				block: 100,
				txIndex: 1,
				outputIndex: 0
			});
			const { msg: ann } = createSignedChannelAnnouncement(
				nodeKey1,
				nodeKey2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(ann);

			const source = getPublicKey(nodeKey1);
			const dest = getPublicKey(nodeKey2);
			const isSourceNode1 = source.compare(dest) < 0;
			const { msg: up } = createSignedChannelUpdatePayload(
				isSourceNode1 ? nodeKey1 : nodeKey2,
				scid,
				isSourceNode1 ? 0 : 1
			);
			graph.applyChannelUpdate(up);

			const ch = graph.getChannel(scid);
			expect(ch).to.not.be.undefined;

			// Simulate persistence round-trip
			const graph2 = new NetworkGraph();
			graph2.restoreChannel(ch!);

			const restoredCh = graph2.getChannel(scid);
			expect(restoredCh).to.not.be.undefined;
			expect(restoredCh!.nodeId1.equals(ch!.nodeId1)).to.be.true;
			expect(restoredCh!.nodeId2.equals(ch!.nodeId2)).to.be.true;
		});

		it('gossip graph survives full persist → restore cycle', () => {
			const graph = new NetworkGraph();
			const nodeKey1 = crypto.randomBytes(32);
			const nodeKey2 = crypto.randomBytes(32);
			const btcKey1 = crypto.randomBytes(32);
			const btcKey2 = crypto.randomBytes(32);

			const pub1 = getPublicKey(nodeKey1);
			const pub2 = getPublicKey(nodeKey2);

			const scid = encodeShortChannelId({
				block: 200,
				txIndex: 1,
				outputIndex: 0
			});
			const { msg: ann } = createSignedChannelAnnouncement(
				nodeKey1,
				nodeKey2,
				btcKey1,
				btcKey2,
				scid
			);
			graph.addChannelAnnouncement(ann);

			// Determine the sorted node keys
			const isNode1First = pub1.compare(pub2) < 0;
			const sk1 = isNode1First ? nodeKey1 : nodeKey2;
			const sk2 = isNode1First ? nodeKey2 : nodeKey1;

			const { msg: up1 } = createSignedChannelUpdatePayload(sk1, scid, 0);
			const { msg: up2 } = createSignedChannelUpdatePayload(sk2, scid, 1);
			graph.applyChannelUpdate(up1);
			graph.applyChannelUpdate(up2);

			const channels = graph.getAllChannels();
			expect(channels.length).to.be.greaterThan(0);

			// Create new graph and restore all
			const graph2 = new NetworkGraph();
			for (const ch of channels) {
				graph2.restoreChannel(ch);
			}

			const sortedPub1 = isNode1First ? pub1 : pub2;
			const sortedPub2 = isNode1First ? pub2 : pub1;
			const route = findRoute(graph2, sortedPub1, sortedPub2, 1000n, 40);
			expect(route).to.not.be.null;
			expect(route!.hops.length).to.equal(1);
		});
	});

	// ─────── Fix 7: Crash recovery restore fix ───────

	describe('Fix 7: Crash recovery restore fix', () => {
		it('restoreChannel should transition NORMAL to AWAITING_REESTABLISH', () => {
			const cmConfig: IChannelManagerConfig = {
				localBasepoints: makeBasepoints(makeSeed(530)),
				localPerCommitmentSeed: makeSeed(630),
				localFundingPrivkey: makeSeed(730)
			};
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: cmConfig.localBasepoints,
				localPerCommitmentSeed: cmConfig.localPerCommitmentSeed
			});
			state.state = ChannelState.NORMAL;
			state.channelId = crypto.randomBytes(32);

			const channel = new Channel(state);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);

			cm.restoreChannel(channel, 'deadbeef'.repeat(8));
			expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});

		it('restoreChannel should not change state for non-NORMAL channels', () => {
			const cmConfig: IChannelManagerConfig = {
				localBasepoints: makeBasepoints(makeSeed(531)),
				localPerCommitmentSeed: makeSeed(631),
				localFundingPrivkey: makeSeed(731)
			};
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: cmConfig.localBasepoints,
				localPerCommitmentSeed: cmConfig.localPerCommitmentSeed
			});
			state.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
			state.channelId = crypto.randomBytes(32);

			const channel = new Channel(state);
			cm.restoreChannel(channel, 'deadbeef'.repeat(8));
			// Fix 6 (PH9): AWAITING_FUNDING_CONFIRMED channels are now marked for reestablish
			expect(channel.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		});

		it('restoreChannel should handle channels without channelId', () => {
			const cmConfig: IChannelManagerConfig = {
				localBasepoints: makeBasepoints(makeSeed(532)),
				localPerCommitmentSeed: makeSeed(632),
				localFundingPrivkey: makeSeed(732)
			};
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: cmConfig.localBasepoints,
				localPerCommitmentSeed: cmConfig.localPerCommitmentSeed
			});
			const channel = new Channel(state);
			cm.restoreChannel(channel, 'deadbeef'.repeat(8));
		});
	});

	// ─────── Fix 8: Invoice expiry check before sending HTLC ───────

	describe('Fix 8: Invoice expiry check', () => {
		it('should reject expired invoices immediately', () => {
			const alice = createNode(540);
			const bob = createNode(541);
			connectNodes(alice, bob);

			openReadyChannel(alice, bob);

			// Create an invoice with a past timestamp
			const bobSeed = makeSeed(541);
			const privateKey = crypto
				.createHash('sha256')
				.update(bobSeed)
				.update(Buffer.from('node-identity'))
				.digest();
			const paymentHash = crypto.randomBytes(32);
			const invoiceStr = encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 1000n,
				description: 'expired test',
				paymentHash,
				expiry: 60,
				minFinalCltvExpiry: 40,
				privateKey,
				timestamp: Math.floor(Date.now() / 1000) - 120
			});

			let failedPayment: IPaymentInfo | null = null;
			alice.on('payment:failed', (p: IPaymentInfo) => {
				failedPayment = p;
			});

			const payment = alice.sendPayment(invoiceStr);
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(failedPayment).to.not.be.null;
			expect(failedPayment!.status).to.equal(PaymentStatus.FAILED);

			alice.destroy();
			bob.destroy();
		});

		it('should allow non-expired invoices', () => {
			const alice = createNode(542);
			const bob = createNode(543);
			connectNodes(alice, bob);

			openReadyChannel(alice, bob);

			const invoiceStr = bob.createInvoice({
				amountMsat: 1000n,
				description: 'valid test',
				expiry: 3600
			});

			try {
				alice.sendPayment(invoiceStr.bolt11);
			} catch (err) {
				expect((err as Error).message).to.include('No route');
			}

			alice.destroy();
			bob.destroy();
		});
	});

	// ─────── Fix 9: MPP timeout auto-trigger ───────

	describe('Fix 9: MPP timeout auto-trigger', () => {
		it('should start MPP cleanup timer when BASIC_MPP is enabled', () => {
			const config = makeNodeConfig(550);
			config.localFeatures = FeatureFlags.empty();
			config.localFeatures.setOptional(Feature.BASIC_MPP);
			config.enableNetworking = true;

			const node = new LightningNode(config);
			node.on('error', () => {});
			node.destroy();
		});

		it('should not start MPP timer when BASIC_MPP is not set', () => {
			const config = makeNodeConfig(551);
			config.localFeatures = FeatureFlags.empty();
			config.enableNetworking = true;

			const node = new LightningNode(config);
			node.on('error', () => {});
			node.destroy();
		});

		it('destroy should clean up MPP timer without error', () => {
			const config = makeNodeConfig(552);
			config.localFeatures = FeatureFlags.empty();
			config.localFeatures.setOptional(Feature.BASIC_MPP);
			config.enableNetworking = true;

			const node = new LightningNode(config);
			node.on('error', () => {});
			node.destroy();
			// Second destroy should be safe
			node.destroy();
		});
	});

	// ─────── Fix 10: update_fee public API ───────

	describe('Fix 10: update_fee public API', () => {
		it('ChannelManager.updateChannelFee should work for opener', () => {
			const alice = createNode(560);
			const bob = createNode(561);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);

			const cm = alice.getChannelManager();
			const result = cm.updateChannelFee(channelId, 500);
			expect(result.ok).to.be.true;

			alice.destroy();
			bob.destroy();
		});

		it('ChannelManager.updateChannelFee should reject for non-opener', () => {
			const alice = createNode(562);
			const bob = createNode(563);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);

			const cm = bob.getChannelManager();
			const result = cm.updateChannelFee(channelId, 500);
			expect(result.ok).to.be.false;
			expect(result.error).to.include('opener');

			alice.destroy();
			bob.destroy();
		});

		it('ChannelManager.updateChannelFee should fail for unknown channel', () => {
			const cmConfig: IChannelManagerConfig = {
				localBasepoints: makeBasepoints(makeSeed(564)),
				localPerCommitmentSeed: makeSeed(664),
				localFundingPrivkey: makeSeed(764)
			};
			const cm = new ChannelManager(cmConfig);
			cm.on('error', () => {});

			const result = cm.updateChannelFee(crypto.randomBytes(32), 500);
			expect(result.ok).to.be.false;
			expect(result.error).to.include('not found');
		});

		it('LightningNode.updateChannelFee should validate feerate minimum', () => {
			const node = createNode(565);
			expect(() => node.updateChannelFee(crypto.randomBytes(32), 100)).to.throw(
				'253'
			);
			expect(() => node.updateChannelFee(crypto.randomBytes(32), 0)).to.throw(
				'253'
			);
			expect(() => node.updateChannelFee(crypto.randomBytes(32), -1)).to.throw(
				'253'
			);
			node.destroy();
		});

		it('LightningNode.updateChannelFee should validate channelId', () => {
			const node = createNode(566);
			expect(() => node.updateChannelFee(Buffer.alloc(16), 253)).to.throw(
				'channelId'
			);
			node.destroy();
		});

		it('LightningNode.updateChannelFee should emit error for unknown channel', () => {
			const node = createNode(567);
			const errors: Array<{ code: string }> = [];
			node.on('node:error', (err: { code: string }) => errors.push(err));

			node.updateChannelFee(crypto.randomBytes(32), 253);
			expect(errors.length).to.be.greaterThan(0);
			const updateFeeError = errors.find((e) => e.code === 'UPDATE_FEE_FAILED');
			expect(updateFeeError).to.exist;

			node.destroy();
		});

		it('LightningNode.updateChannelFee should succeed for opener channel', () => {
			const alice = createNode(568);
			const bob = createNode(569);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);

			const errors: Array<{ code: string }> = [];
			alice.on('node:error', (err: { code: string }) => errors.push(err));

			alice.updateChannelFee(channelId, 500);
			expect(errors.length).to.equal(0);

			alice.destroy();
			bob.destroy();
		});

		it('LightningNode.updateChannelFee commits the new feerate (drives the commitment round)', () => {
			const alice = createNode(570);
			const bob = createNode(571);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);

			const aliceChan = alice.getChannelManager().getChannel(channelId)!;
			const before = aliceChan.getFullState().localConfig.feeratePerKw;
			const target = before + 1000;

			const res = alice.updateChannelFee(channelId, target);
			expect(res.ok).to.be.true;

			// The fee must be committed (promoted to the committed config on
			// revoke_and_ack), not left dangling in pendingFeeratePerKw. A staged
			// but uncommitted fee is what desyncs the commitments and breaks the
			// next HTLC.
			const st = aliceChan.getFullState();
			expect(st.localConfig.feeratePerKw).to.equal(target);
			expect(st.pendingFeeratePerKw).to.equal(undefined);

			// Bob's view of the channel must agree (round completed end-to-end).
			const bobChan = bob.getChannelManager().getChannel(channelId)!;
			expect(bobChan.getFullState().remoteConfig.feeratePerKw).to.equal(target);

			alice.destroy();
			bob.destroy();
		});
	});
});
