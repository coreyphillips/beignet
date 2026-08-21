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
	makeSignedChannelKeys,
	makeSignedChannelAnnouncement,
	makeSignedChannelUpdate,
	makeSignedNodeAnnouncement
} from './helpers/signed-gossip';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
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
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage
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

		// H1 fund-safety: the lessor's isLessor/leaseExpiry drive the CLTV lock on our
		// to_local script. If they don't survive a serialize→restore round-trip, the
		// rebuilt commitment differs from the one the peer signed, the cached remote
		// signature no longer validates, and our whole balance becomes unbroadcastable.
		// This asserts BOTH the fields AND the resulting commitment are byte-identical
		// across a round-trip — the generalized "rebuild byte-parity" invariant.
		it('persists lessor lease fields so the rebuilt commitment is byte-identical (H1)', function () {
			const state = createTestChannelState();
			state.isLessor = true;
			state.leaseExpiry = 850_000;

			const point = perCommitmentPointFromSecret(
				generateFromSeed(
					state.localPerCommitmentSeed,
					MAX_INDEX - state.localCommitmentNumber
				)
			);
			const before = buildLocalCommitment(state, point).result.tx.toHex();

			const restored = deserializeChannelState(serializeChannelState(state));
			expect(restored.isLessor, 'isLessor survives').to.equal(true);
			expect(restored.leaseExpiry, 'leaseExpiry survives').to.equal(850_000);

			const after = buildLocalCommitment(restored, point).result.tx.toHex();
			expect(after, 'rebuilt commitment is byte-identical').to.equal(before);

			// Guard: the lease lock actually changes the commitment, so the test is
			// meaningful — a non-lessor rebuild must differ.
			const nonLessor = deserializeChannelState(serializeChannelState(state));
			nonLessor.isLessor = false;
			nonLessor.leaseExpiry = undefined;
			const unlocked = buildLocalCommitment(nonLessor, point).result.tx.toHex();
			expect(
				unlocked,
				'lease lock materially affects the commitment'
			).to.not.equal(before);
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

		function makeGraphChannelFixture(): IGraphChannel {
			const nodeId1 = getPublicKey(makeSeed(1));
			const nodeId2 = getPublicKey(makeSeed(2));
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
			const update: IChannelUpdateMessage = {
				signature: crypto.randomBytes(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: ann.shortChannelId,
				timestamp: 1000,
				messageFlags: 0x01,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 1_000_000_000n
			};
			return {
				shortChannelId: ann.shortChannelId,
				nodeId1: n1,
				nodeId2: n2,
				features: Buffer.alloc(0),
				announcement: ann,
				update1: update
			};
		}

		it('resolves legacy rows without provenance flags by signature verification at restore (eager mode)', function () {
			// Pre-#340 rows carry no flags and may hold zero-signature RGS
			// messages (a verified update persisted the whole channel), so
			// absence is resolved by verifying the canonical re-encoding at the
			// restore boundary, never trusted.
			const invalid = makeGraphChannelFixture();
			const restoredInvalid = deserializeGraphChannel(
				serializeGraphChannel(invalid)
			);
			// Deserialize invents nothing.
			expect(restoredInvalid.announcementVerified).to.be.undefined;
			expect(restoredInvalid.update1Verified).to.be.undefined;
			const graphInvalid = new NetworkGraph(BITCOIN_CHAIN_HASH, {
				eagerVerify: true
			});
			graphInvalid.restoreChannel(restoredInvalid);
			const chInvalid = graphInvalid.getChannel(
				restoredInvalid.shortChannelId
			)!;
			expect(chInvalid.announcementVerified).to.be.false;
			expect(chInvalid.update1Verified).to.be.false;

			// A genuinely signed legacy row resolves verified.
			const scid = Buffer.from('0000010000020003', 'hex');
			const keys = makeSignedChannelKeys();
			const { msg: annMsg } = makeSignedChannelAnnouncement(scid, keys);
			const { msg: updMsg } = makeSignedChannelUpdate(
				scid,
				keys.nodeKey1,
				0,
				1000
			);
			const legacy: IGraphChannel = {
				shortChannelId: scid,
				nodeId1: annMsg.nodeId1,
				nodeId2: annMsg.nodeId2,
				features: Buffer.alloc(0),
				announcement: annMsg,
				update1: updMsg
			};
			const restoredValid = deserializeGraphChannel(
				serializeGraphChannel(legacy)
			);
			const graphValid = new NetworkGraph(BITCOIN_CHAIN_HASH, {
				eagerVerify: true
			});
			graphValid.restoreChannel(restoredValid);
			const chValid = graphValid.getChannel(scid)!;
			expect(chValid.announcementVerified).to.be.true;
			expect(chValid.update1Verified).to.be.true;
			// No update2 in the row: no flag is invented for it.
			expect(chValid.update2Verified).to.be.undefined;

			// Node announcements resolve the same way.
			const signedNode = makeSignedNodeAnnouncement(keys.nodeKey1, 1000);
			const goodNode: IGraphNode = {
				nodeId: signedNode.msg.nodeId,
				announcement: signedNode.msg,
				channels: new Set(['abc123'])
			};
			const restoredGoodNode = deserializeGraphNode(
				serializeGraphNode(goodNode)
			);
			expect(restoredGoodNode.announcementVerified).to.be.undefined;
			graphValid.restoreNode(restoredGoodNode);
			expect(graphValid.getNode(signedNode.msg.nodeId)!.announcementVerified).to
				.be.true;

			const badAnn: INodeAnnouncementMessage = {
				signature: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				timestamp: 1000,
				nodeId: getPublicKey(makeSeed(1)),
				rgbColor: Buffer.from([255, 0, 0]),
				alias: Buffer.alloc(32),
				addresses: []
			};
			const badNode: IGraphNode = {
				nodeId: badAnn.nodeId,
				announcement: badAnn,
				channels: new Set()
			};
			graphValid.restoreNode(badNode);
			expect(graphValid.getNode(badAnn.nodeId)!.announcementVerified).to.be
				.false;
		});

		it('marks unresolved legacy rows deferred at restore in lazy mode (issue #443)', function () {
			// The lazy default moves the signature work off the boot path: an
			// unresolved flag gains the deferred marker (its boolean stays
			// unset, so truthiness checks read unverified) and is verified only
			// when a consumer asks for the entry, with the same outcome eager
			// restore would have produced. Explicit booleans are untouched and
			// no marker is invented for a message that is not in the row.
			const legacy = makeGraphChannelFixture();
			legacy.update1Verified = true;
			const restored = deserializeGraphChannel(serializeGraphChannel(legacy));
			const graph = new NetworkGraph();
			graph.restoreChannel(restored);
			const ch = graph.getChannel(restored.shortChannelId)!;
			expect(ch.announcementVerified).to.equal(undefined);
			expect(ch.announcementVerifyDeferred).to.equal(true);
			expect(ch.update1Verified).to.be.true;
			expect(ch.update1VerifyDeferred).to.equal(undefined);
			expect(ch.update2Verified).to.be.undefined;
			expect(ch.update2VerifyDeferred).to.be.undefined;

			// An eager graph resolves a deferred row left by a lazy run, so a
			// lazy-to-eager migration never holds deferred entries post-boot.
			const eager = new NetworkGraph(BITCOIN_CHAIN_HASH, {
				eagerVerify: true
			});
			const again = deserializeGraphChannel(serializeGraphChannel(ch));
			eager.restoreChannel(again);
			const resolved = eager.getChannel(again.shortChannelId)!;
			// The fixture's announcement carries garbage signatures: unservable.
			expect(resolved.announcementVerified).to.be.false;
			expect(resolved.announcementVerifyDeferred).to.equal(undefined);

			// A row carrying garbage in a verified field (a custom storage
			// adapter, or the string encoding of a pre-release build) resolves
			// at the boundary like a legacy row instead of being trusted.
			const tainted = deserializeGraphChannel(serializeGraphChannel(legacy));
			(
				tainted as unknown as { announcementVerified: string }
			).announcementVerified = 'deferred';
			const lazyGraph = new NetworkGraph();
			lazyGraph.restoreChannel(tainted);
			const sanitized = lazyGraph.getChannel(tainted.shortChannelId)!;
			expect(sanitized.announcementVerified).to.equal(undefined);
			expect(sanitized.announcementVerifyDeferred).to.equal(true);
		});

		it('round-trips explicit provenance flags', function () {
			// Mixed provenance happens in production: a verified update applied
			// to an RGS-primed (unverified) channel is persisted whole.
			const channel = makeGraphChannelFixture();
			channel.announcementVerified = false;
			channel.update1Verified = true;
			const restored = deserializeGraphChannel(serializeGraphChannel(channel));
			expect(restored.announcementVerified).to.be.false;
			expect(restored.update1Verified).to.be.true;

			// Lazy intake persists deferred markers (with the boolean flags
			// unset); they must survive a restart as-is so boot never
			// re-verifies them (issue #443).
			const deferred = makeGraphChannelFixture();
			deferred.announcementVerifyDeferred = true;
			deferred.update1VerifyDeferred = true;
			const restoredDeferred = deserializeGraphChannel(
				serializeGraphChannel(deferred)
			);
			expect(restoredDeferred.announcementVerified).to.equal(undefined);
			expect(restoredDeferred.announcementVerifyDeferred).to.equal(true);
			expect(restoredDeferred.update1VerifyDeferred).to.equal(true);

			const nodeAnn: INodeAnnouncementMessage = {
				signature: crypto.randomBytes(64),
				features: Buffer.alloc(0),
				timestamp: 1000,
				nodeId: getPublicKey(makeSeed(1)),
				rgbColor: Buffer.from([255, 0, 0]),
				alias: Buffer.alloc(32),
				addresses: []
			};
			const node: IGraphNode = {
				nodeId: nodeAnn.nodeId,
				announcement: nodeAnn,
				channels: new Set(['abc123']),
				announcementVerified: false
			};
			const restoredNode = deserializeGraphNode(serializeGraphNode(node));
			expect(restoredNode.announcementVerified).to.be.false;
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

		it('does not resurrect legacy zero-signature RGS rows as servable after restart', function () {
			// Pre-#340 sequence: RGS primed the channel (zero-sig announcement),
			// a later signature-verified update persisted the WHOLE row without
			// provenance flags. After restart the announcement must stay
			// unservable while the genuinely signed update resolves verified.
			const scid = Buffer.from('0000640000010000', 'hex'); // block 100
			const keys = makeSignedChannelKeys();
			const nodeId1 = getPublicKey(keys.nodeKey1);
			const nodeId2 = getPublicKey(keys.nodeKey2);
			const zeroSigAnn: IChannelAnnouncementMessage = {
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scid,
				nodeId1,
				nodeId2,
				bitcoinKey1: Buffer.alloc(33),
				bitcoinKey2: Buffer.alloc(33)
			};
			const { msg: signedUpd } = makeSignedChannelUpdate(
				scid,
				keys.nodeKey1,
				0,
				1000
			);
			const legacyRow: IGraphChannel = {
				shortChannelId: scid,
				nodeId1,
				nodeId2,
				features: Buffer.alloc(0),
				announcement: zeroSigAnn,
				update1: signedUpd
			};

			storage.saveGossipChannel(scid.toString('hex'), legacyRow);
			const loaded = storage.loadAllGossipChannels();
			expect(loaded).to.have.length(1);

			const graph = new NetworkGraph(BITCOIN_CHAIN_HASH, {
				eagerVerify: true
			});
			graph.restoreChannel(loaded[0]);
			const ch = graph.getChannel(scid)!;
			expect(ch.announcementVerified).to.be.false;
			expect(ch.update1Verified).to.be.true;
			// Never advertised, never served.
			expect(graph.getChannelsByBlockRange(100, 5)).to.have.length(0);
			const served = graph.getGossipMessagesForChannels([scid]);
			expect(served.announcements).to.have.length(0);
			expect(served.updates).to.have.length(0);

			// Lazy restore reaches the same end state through the serve path:
			// the row restores deferred, gets advertised once, then the first
			// query resolves the zero-signature announcement unservable, and
			// the whole channel (signed update included, its endpoints being
			// unauthenticated) is withheld and drops out of later ranges.
			const lazy = new NetworkGraph();
			lazy.restoreChannel(storage.loadAllGossipChannels()[0]);
			const lazyCh = lazy.getChannel(scid)!;
			expect(lazyCh.announcementVerifyDeferred).to.equal(true);
			expect(lazy.getChannelsByBlockRange(100, 5)).to.have.length(1);
			const lazyServed = lazy.getGossipMessagesForChannels([scid]);
			expect(lazyServed.announcements).to.have.length(0);
			expect(lazyServed.updates).to.have.length(0);
			expect(lazyCh.announcementVerified).to.be.false;
			expect(lazyCh.update1VerifyDeferred).to.equal(true);
			expect(lazy.getChannelsByBlockRange(100, 5)).to.have.length(0);
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
			expect(loaded!.shortChannelId.equals(channel.shortChannelId)).to.be.true;
		});
	});
});
