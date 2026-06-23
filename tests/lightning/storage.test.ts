import { expect } from 'chai';
import crypto from 'crypto';
import {
	serializeChannelState,
	deserializeChannelState,
	serializePaymentInfo,
	deserializePaymentInfo,
	serializeChainMonitorState,
	deserializeChainMonitorState,
	serializeGraphChannel,
	deserializeGraphChannel,
	serializeGraphNode,
	deserializeGraphNode,
	serializeShaChainEntries,
	deserializeShaChainStore
} from '../../src/lightning/storage/serialization';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	DEFAULT_CHANNEL_CONFIG,
	ChannelState,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import {
	ShaChainStore,
	MAX_INDEX,
	generateFromSeed
} from '../../src/lightning/keys/shachain';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	PaymentStatus,
	PaymentDirection,
	IPaymentInfo
} from '../../src/lightning/node/types';
import { IChainMonitorState } from '../../src/lightning/chain/chain-monitor';
import { MonitorState } from '../../src/lightning/chain/types';
import {
	IGraphChannel,
	IGraphNode,
	IChannelAnnouncementMessage
} from '../../src/lightning/gossip/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
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
		firstPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(makeSeed(99), MAX_INDEX)
		)
	};
}

function createTestChannelState() {
	const seed = makeSeed(1);
	const commitSeed = makeSeed(3);
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: commitSeed
	});
	state.state = ChannelState.NORMAL;
	state.channelId = crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.localCommitmentNumber = 5n;
	state.remoteCommitmentNumber = 3n;
	state.localBalanceMsat = 800_000_000n;
	state.remoteBalanceMsat = 200_000_000n;
	state.localHtlcCounter = 2n;
	state.remoteBasepoints = makeBasepoints(makeSeed(2));
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints.firstPerCommitmentPoint;
	return state;
}

describe('Storage Layer', function () {
	describe('Serialization Round-trips', function () {
		it('should round-trip IChannelState', function () {
			const state = createTestChannelState();

			// Add an HTLC
			state.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});

			const serialized = serializeChannelState(state);
			const deserialized = deserializeChannelState(serialized);

			expect(deserialized.channelId!.equals(state.channelId!)).to.be.true;
			expect(deserialized.fundingSatoshis).to.equal(state.fundingSatoshis);
			expect(deserialized.localBalanceMsat).to.equal(state.localBalanceMsat);
			expect(deserialized.localCommitmentNumber).to.equal(
				state.localCommitmentNumber
			);
			expect(deserialized.state).to.equal(state.state);
			expect(deserialized.role).to.equal(state.role);
			expect(deserialized.htlcs.size).to.equal(1);
			const htlc = deserialized.htlcs.get('offered-0')!;
			expect(htlc.id).to.equal(0n);
			expect(htlc.amountMsat).to.equal(50_000_000n);
			expect(htlc.direction).to.equal(HtlcDirection.OFFERED);
		});

		it('should round-trip ShaChainStore', function () {
			const store = new ShaChainStore();
			const seed = makeSeed(1);
			store.addSecret(MAX_INDEX, generateFromSeed(seed, MAX_INDEX));
			store.addSecret(MAX_INDEX - 1n, generateFromSeed(seed, MAX_INDEX - 1n));

			const data = serializeShaChainEntries(store);
			const restored = deserializeShaChainStore(data);

			expect(restored.getKnownCount()).to.equal(2n);
			const secret = restored.getSecret(MAX_INDEX);
			expect(secret).to.not.be.null;
			expect(secret!.equals(generateFromSeed(seed, MAX_INDEX))).to.be.true;
		});

		it('should round-trip IPaymentInfo', function () {
			const payment: IPaymentInfo = {
				paymentHash: crypto.randomBytes(32),
				preimage: crypto.randomBytes(32),
				amountMsat: 100_000n,
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.INCOMING,
				createdAt: Date.now(),
				completedAt: Date.now()
			};

			const serialized = serializePaymentInfo(payment);
			const deserialized = deserializePaymentInfo(serialized);

			expect(deserialized.paymentHash.equals(payment.paymentHash)).to.be.true;
			expect(deserialized.preimage!.equals(payment.preimage!)).to.be.true;
			expect(deserialized.amountMsat).to.equal(payment.amountMsat);
			expect(deserialized.status).to.equal(PaymentStatus.COMPLETED);
			expect(deserialized.direction).to.equal(PaymentDirection.INCOMING);
		});

		it('should round-trip IChainMonitorState', function () {
			const state: IChainMonitorState = {
				monitorState: MonitorState.WATCHING,
				commitmentBroadcast: null,
				trackedOutputs: [],
				currentBlockHeight: 100
			};

			const json = serializeChainMonitorState(state);
			const deserialized = deserializeChainMonitorState(json);

			expect(deserialized.monitorState).to.equal(MonitorState.WATCHING);
			expect(deserialized.currentBlockHeight).to.equal(100);
		});

		it('should round-trip IGraphChannel', function () {
			const nodeId1 = getPublicKey(makeSeed(1));
			const nodeId2 = getPublicKey(makeSeed(2));
			// Ensure nodeId1 < nodeId2
			const [n1, n2] =
				Buffer.compare(nodeId1, nodeId2) < 0
					? [nodeId1, nodeId2]
					: [nodeId2, nodeId1];

			const ann: IChannelAnnouncementMessage = {
				nodeSignature1: crypto.randomBytes(64),
				nodeSignature2: crypto.randomBytes(64),
				bitcoinSignature1: crypto.randomBytes(64),
				bitcoinSignature2: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: Buffer.from('0000010000020003', 'hex'),
				nodeId1: n1,
				nodeId2: n2,
				bitcoinKey1: getPublicKey(makeSeed(3)),
				bitcoinKey2: getPublicKey(makeSeed(4))
			};

			const channel: IGraphChannel = {
				shortChannelId: ann.shortChannelId,
				nodeId1: n1,
				nodeId2: n2,
				features: Buffer.alloc(0),
				announcement: ann
			};

			const json = serializeGraphChannel(channel);
			const deserialized = deserializeGraphChannel(json);

			expect(deserialized.shortChannelId.equals(channel.shortChannelId)).to.be
				.true;
			expect(deserialized.nodeId1.equals(n1)).to.be.true;
			expect(deserialized.nodeId2.equals(n2)).to.be.true;
		});

		it('should round-trip IGraphNode', function () {
			const nodeId = getPublicKey(makeSeed(1));
			const node: IGraphNode = {
				nodeId,
				channels: new Set(['abc123', 'def456'])
			};

			const json = serializeGraphNode(node);
			const deserialized = deserializeGraphNode(json);

			expect(deserialized.nodeId.equals(nodeId)).to.be.true;
			expect(deserialized.channels.has('abc123')).to.be.true;
			expect(deserialized.channels.has('def456')).to.be.true;
		});
	});

	describe('SQLite CRUD', function () {
		let storage: SqliteStorage;

		beforeEach(function () {
			storage = new SqliteStorage(':memory:');
			storage.open();
		});

		afterEach(function () {
			storage.close();
		});

		it('should save and load a channel', function () {
			const state = createTestChannelState();
			const channelId = state.channelId!.toString('hex');
			storage.saveChannel(channelId, state, 'peer123');

			const loaded = storage.loadChannel(channelId);
			expect(loaded).to.not.be.null;
			expect(loaded!.peerPubkey).to.equal('peer123');
			expect(loaded!.state.fundingSatoshis).to.equal(1_000_000n);
		});

		it('should return null for non-existent channel', function () {
			expect(storage.loadChannel('nonexistent')).to.be.null;
		});

		it('should delete a channel', function () {
			const state = createTestChannelState();
			const channelId = state.channelId!.toString('hex');
			storage.saveChannel(channelId, state, 'peer123');
			storage.deleteChannel(channelId);
			expect(storage.loadChannel(channelId)).to.be.null;
		});

		it('should load all channels', function () {
			const state1 = createTestChannelState();
			const state2 = createTestChannelState();
			state2.channelId = crypto.randomBytes(32);

			storage.saveChannel(state1.channelId!.toString('hex'), state1, 'peer1');
			storage.saveChannel(state2.channelId!.toString('hex'), state2, 'peer2');

			const all = storage.loadAllChannels();
			expect(all).to.have.length(2);
		});

		it('should save and load a payment', function () {
			const payment: IPaymentInfo = {
				paymentHash: crypto.randomBytes(32),
				amountMsat: 50_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now()
			};
			const hashHex = payment.paymentHash.toString('hex');
			storage.savePayment(hashHex, payment);

			const loaded = storage.loadPayment(hashHex);
			expect(loaded).to.not.be.null;
			expect(loaded!.amountMsat).to.equal(50_000n);
			expect(loaded!.status).to.equal(PaymentStatus.PENDING);
		});

		it('should save and load a preimage', function () {
			const preimage = crypto.randomBytes(32);
			const hash = crypto
				.createHash('sha256')
				.update(preimage)
				.digest()
				.toString('hex');
			storage.savePreimage(hash, preimage);

			const loaded = storage.loadPreimage(hash);
			expect(loaded).to.not.be.null;
			expect(loaded!.equals(preimage)).to.be.true;
		});

		it('should save and load SCID mappings', function () {
			const channelId = crypto.randomBytes(32);
			storage.saveScidMapping('abc123', channelId);

			const all = storage.loadAllScidMappings();
			expect(all).to.have.length(1);
			expect(all[0].scidHex).to.equal('abc123');
			expect(all[0].channelId.equals(channelId)).to.be.true;
		});

		it('should save and load HTLC payment mappings', function () {
			storage.saveHtlcPaymentMapping('ch1:offered-0', 'hash123');
			const all = storage.loadAllHtlcPaymentMappings();
			expect(all).to.have.length(1);
			expect(all[0].key).to.equal('ch1:offered-0');
			expect(all[0].paymentHashHex).to.equal('hash123');
		});

		it('should save and load forwarded HTLCs', function () {
			const inChannelId = crypto.randomBytes(32);
			storage.saveForwardedHtlc('out-key-1', inChannelId, 5n);

			const all = storage.loadAllForwardedHtlcs();
			expect(all).to.have.length(1);
			expect(all[0].outKey).to.equal('out-key-1');
			expect(all[0].inChannelId.equals(inChannelId)).to.be.true;
			expect(all[0].inHtlcId).to.equal(5n);
		});

		it('should save and load chain monitors', function () {
			const state: IChainMonitorState = {
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: null,
				trackedOutputs: [],
				currentBlockHeight: 500
			};
			storage.saveChainMonitor('ch1', state);

			const loaded = storage.loadChainMonitor('ch1');
			expect(loaded).to.not.be.null;
			expect(loaded!.monitorState).to.equal(MonitorState.RESOLVING);
			expect(loaded!.currentBlockHeight).to.equal(500);
		});

		it('should save and load gossip channels', function () {
			const nodeId1 = getPublicKey(makeSeed(1));
			const nodeId2 = getPublicKey(makeSeed(2));
			const [n1, n2] =
				Buffer.compare(nodeId1, nodeId2) < 0
					? [nodeId1, nodeId2]
					: [nodeId2, nodeId1];

			const channel: IGraphChannel = {
				shortChannelId: Buffer.from('0000010000020003', 'hex'),
				nodeId1: n1,
				nodeId2: n2,
				features: Buffer.alloc(0),
				announcement: {
					nodeSignature1: crypto.randomBytes(64),
					nodeSignature2: crypto.randomBytes(64),
					bitcoinSignature1: crypto.randomBytes(64),
					bitcoinSignature2: crypto.randomBytes(64),
					features: Buffer.alloc(0),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: Buffer.from('0000010000020003', 'hex'),
					nodeId1: n1,
					nodeId2: n2,
					bitcoinKey1: getPublicKey(makeSeed(3)),
					bitcoinKey2: getPublicKey(makeSeed(4))
				}
			};

			storage.saveGossipChannel('0000010000020003', channel);
			const all = storage.loadAllGossipChannels();
			expect(all).to.have.length(1);
			expect(all[0].shortChannelId.equals(channel.shortChannelId)).to.be.true;
		});

		it('should save and load gossip nodes', function () {
			const nodeId = getPublicKey(makeSeed(1));
			const node: IGraphNode = {
				nodeId,
				channels: new Set(['scid1'])
			};

			storage.saveGossipNode(nodeId.toString('hex'), node);
			const all = storage.loadAllGossipNodes();
			expect(all).to.have.length(1);
			expect(all[0].nodeId.equals(nodeId)).to.be.true;
			expect(all[0].channels.has('scid1')).to.be.true;
		});

		it('should support transactions', function () {
			storage.transaction(() => {
				storage.savePreimage('hash1', crypto.randomBytes(32));
				storage.savePreimage('hash2', crypto.randomBytes(32));
			});

			const all = storage.loadAllPreimages();
			expect(all).to.have.length(2);
		});

		it('should update existing records (upsert)', function () {
			const state = createTestChannelState();
			const channelId = state.channelId!.toString('hex');
			storage.saveChannel(channelId, state, 'peer1');

			// Update balance and save again
			state.localBalanceMsat = 500_000_000n;
			storage.saveChannel(channelId, state, 'peer1');

			const loaded = storage.loadChannel(channelId);
			expect(loaded!.state.localBalanceMsat).to.equal(500_000_000n);

			// Only one record
			const all = storage.loadAllChannels();
			expect(all).to.have.length(1);
		});
	});

	describe('ShaChainStore restore', function () {
		it('should restore and verify secrets', function () {
			const seed = makeSeed(1);
			const store = new ShaChainStore();

			// Add 10 secrets
			for (let i = 0n; i < 10n; i++) {
				const idx = MAX_INDEX - i;
				store.addSecret(idx, generateFromSeed(seed, idx));
			}

			// Restore
			const entries = store.getEntries();
			const knownCount = store.getKnownCount();
			const restored = ShaChainStore.restore(entries, knownCount);

			expect(restored.getKnownCount()).to.equal(10n);

			// Verify all secrets can still be derived
			for (let i = 0n; i < 10n; i++) {
				const idx = MAX_INDEX - i;
				const secret = restored.getSecret(idx);
				expect(secret).to.not.be.null;
				expect(secret!.equals(generateFromSeed(seed, idx))).to.be.true;
			}
		});
	});

	describe('NetworkGraph restore', function () {
		it('should restore channels via restoreChannel', function () {
			const {
				NetworkGraph
			} = require('../../src/lightning/gossip/network-graph');
			const graph = new NetworkGraph();

			const nodeId1 = getPublicKey(makeSeed(1));
			const nodeId2 = getPublicKey(makeSeed(2));
			const [n1, n2] =
				Buffer.compare(nodeId1, nodeId2) < 0
					? [nodeId1, nodeId2]
					: [nodeId2, nodeId1];

			const channel: IGraphChannel = {
				shortChannelId: Buffer.from('0000010000020003', 'hex'),
				nodeId1: n1,
				nodeId2: n2,
				features: Buffer.alloc(0),
				announcement: {
					nodeSignature1: crypto.randomBytes(64),
					nodeSignature2: crypto.randomBytes(64),
					bitcoinSignature1: crypto.randomBytes(64),
					bitcoinSignature2: crypto.randomBytes(64),
					features: Buffer.alloc(0),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: Buffer.from('0000010000020003', 'hex'),
					nodeId1: n1,
					nodeId2: n2,
					bitcoinKey1: getPublicKey(makeSeed(3)),
					bitcoinKey2: getPublicKey(makeSeed(4))
				}
			};

			graph.restoreChannel(channel);
			expect(graph.getChannelCount()).to.equal(1);
			expect(graph.getNodeCount()).to.equal(2);

			const loaded = graph.getChannel(channel.shortChannelId);
			expect(loaded).to.not.be.undefined;
			expect(loaded.shortChannelId.equals(channel.shortChannelId)).to.be.true;
		});
	});
});
