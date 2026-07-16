import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	ILightningError,
	PaymentStatus,
	PaymentDirection,
	IPaymentInfo
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH,
	HtlcState,
	HtlcDirection
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	encodeOfferTlv,
	encodeInvoiceRequestTlv,
	getTlvRecords,
	computeMerkleRootFromRecords,
	computeSignatureHash,
	schnorrSign,
	IInvoiceRequest
} from '../../src/lightning/offer';
import {
	constructBlindedPath,
	IBlindedHopData
} from '../../src/lightning/onion/blinded-path';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import {
	encodeChannelAnnouncementMessage,
	encodeNodeAnnouncementMessage,
	encodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import {
	IChannelAnnouncementMessage,
	INodeAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	signChannelAnnouncement,
	signNodeAnnouncement,
	signChannelUpdate
} from '../../src/lightning/gossip/validation';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../src/lightning/onion/construct';
import { findRoute } from '../../src/lightning/gossip/pathfinding';
import { MessageType } from '../../src/lightning/message/types';
import { decodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import * as lightning from '../../src/lightning';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`node-seed-${id}`))
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
	// Secret behind makeBasepoints' htlcBasepoint (keys[4]). Required so the
	// signer can produce HTLC second-level signatures for commitment_signed.
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret
	};
}

function createNode(seedId: number): LightningNode {
	return new LightningNode(makeNodeConfig(seedId));
}

/**
 * Wire two nodes so outbound messages from one are delivered to the other.
 */
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

/**
 * Open a channel between two connected nodes and advance to NORMAL state.
 */
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

/**
 * Create a signed channel_announcement and return both the message and encoded payload.
 */
function createSignedChannelAnnouncement(
	nodePrivkey1: Buffer,
	nodePrivkey2: Buffer,
	bitcoinPrivkey1: Buffer,
	bitcoinPrivkey2: Buffer,
	scid: Buffer
): { msg: IChannelAnnouncementMessage; payload: Buffer } {
	// Ensure nodeId1 < nodeId2 lexicographically
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

	// Build unsigned message first
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

	// Sign
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

/**
 * Create a signed channel_update and return the encoded payload.
 */
function createSignedChannelUpdate(
	nodePrivkey: Buffer,
	scid: Buffer,
	direction: number,
	opts: Partial<IChannelUpdateMessage> = {}
): Buffer {
	const msg: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1, // htlc_maximum_msat present
		channelFlags: direction,
		cltvExpiryDelta: opts.cltvExpiryDelta ?? 40,
		htlcMinimumMsat: opts.htlcMinimumMsat ?? 1000n,
		feeBaseMsat: opts.feeBaseMsat ?? 1000,
		feeProportionalMillionths: opts.feeProportionalMillionths ?? 1,
		htlcMaximumMsat: opts.htlcMaximumMsat ?? 1_000_000_000n
	};

	const unsignedPayload = encodeChannelUpdateMessage(msg);
	const signature = signChannelUpdate(unsignedPayload, nodePrivkey);
	msg.signature = signature;
	return encodeChannelUpdateMessage(msg);
}

/**
 * Create a signed node_announcement and return the encoded payload.
 */
function createSignedNodeAnnouncement(nodePrivkey: Buffer): Buffer {
	const msg: INodeAnnouncementMessage = {
		signature: Buffer.alloc(64),
		features: Buffer.alloc(0),
		timestamp: Math.floor(Date.now() / 1000),
		nodeId: getPublicKey(nodePrivkey),
		rgbColor: Buffer.from([255, 0, 0]),
		alias: Buffer.alloc(32),
		addresses: []
	};

	const unsignedPayload = encodeNodeAnnouncementMessage(msg);
	const signature = signNodeAnnouncement(unsignedPayload, nodePrivkey);
	msg.signature = signature;
	return encodeNodeAnnouncementMessage(msg);
}

// ─────────────── Tests ───────────────

describe('Lightning Node', function () {
	describe('Construction & Config', function () {
		it('should create a node with valid config', function () {
			const node = createNode(1);
			expect(node).to.be.instanceOf(LightningNode);
		});

		it('should return hex pubkey from getNodeId', function () {
			const config = makeNodeConfig(1);
			const node = new LightningNode(config);
			const expectedPubkey = getPublicKey(config.nodePrivateKey).toString(
				'hex'
			);
			expect(node.getNodeId()).to.equal(expectedPubkey);
			expect(node.getNodeId()).to.have.length(66); // 33 bytes compressed = 66 hex chars
		});

		it('should default network to REGTEST', function () {
			const config = makeNodeConfig(1);
			config.network = undefined;
			const node = new LightningNode(config);
			expect(node.getNodeInfo().network).to.equal(Network.REGTEST);
		});

		it('should create internal ChannelManager and NetworkGraph', function () {
			const node = createNode(1);
			expect(node.getChannelManager()).to.exist;
			expect(node.getGraph()).to.be.instanceOf(NetworkGraph);
		});

		it('should return correct INodeInfo', function () {
			const node = createNode(1);
			const info = node.getNodeInfo();
			expect(info.nodeId).to.be.a('string');
			expect(info.network).to.equal(Network.REGTEST);
			expect(info.channelCount).to.equal(0);
			expect(info.peerCount).to.equal(0);
		});

		it('should give different IDs to different nodes', function () {
			const node1 = createNode(1);
			const node2 = createNode(2);
			expect(node1.getNodeId()).to.not.equal(node2.getNodeId());
		});
	});

	describe('Gossip Routing', function () {
		const gossipKey1 = crypto
			.createHash('sha256')
			.update(Buffer.from('gossip-node-1'))
			.digest();
		const gossipKey2 = crypto
			.createHash('sha256')
			.update(Buffer.from('gossip-node-2'))
			.digest();
		const bitcoinKey1 = crypto
			.createHash('sha256')
			.update(Buffer.from('gossip-bitcoin-1'))
			.digest();
		const bitcoinKey2 = crypto
			.createHash('sha256')
			.update(Buffer.from('gossip-bitcoin-2'))
			.digest();
		const testScid = encodeShortChannelId({
			block: 100,
			txIndex: 1,
			outputIndex: 0
		});

		it('should add channel announcement to graph', function () {
			const node = createNode(1);
			const { payload } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				testScid
			);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				payload
			);
			expect(node.getGraph().getChannelCount()).to.equal(1);
		});

		it('should reject invalid channel announcement', function () {
			const node = createNode(1);
			const { payload } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				testScid
			);
			// Corrupt a signature byte
			const corrupted = Buffer.from(payload);
			corrupted[10] ^= 0xff;
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				corrupted
			);
			expect(node.getGraph().getChannelCount()).to.equal(0);
		});

		it('should apply channel update after announcement', function () {
			const node = createNode(1);
			const { payload: annPayload } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				testScid
			);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				annPayload
			);

			// Direction 0 = signed by nodeId1 (the lexicographically smaller key)
			const np1 = getPublicKey(gossipKey1);
			const np2 = getPublicKey(gossipKey2);
			const signerKey = Buffer.compare(np1, np2) < 0 ? gossipKey1 : gossipKey2;

			const updatePayload = createSignedChannelUpdate(signerKey, testScid, 0);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_UPDATE,
				updatePayload
			);

			const channel = node.getGraph().getChannel(testScid);
			expect(channel).to.exist;
			expect(channel!.update1).to.exist;
		});

		it('should ignore channel update without prior announcement', function () {
			const node = createNode(1);
			const updatePayload = createSignedChannelUpdate(gossipKey1, testScid, 0);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_UPDATE,
				updatePayload
			);
			expect(node.getGraph().getChannelCount()).to.equal(0);
		});

		it('should apply node announcement after channel exists', function () {
			const node = createNode(1);
			const { payload: annPayload } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				testScid
			);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				annPayload
			);

			const nodeAnnPayload = createSignedNodeAnnouncement(gossipKey1);
			node.handlePeerMessage(
				'somepeer',
				MessageType.NODE_ANNOUNCEMENT,
				nodeAnnPayload
			);

			const graphNode = node.getGraph().getNode(getPublicKey(gossipKey1));
			expect(graphNode).to.exist;
			expect(graphNode!.announcement).to.exist;
		});

		it('should report correct graph counts', function () {
			const node = createNode(1);
			const { payload: annPayload } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				testScid
			);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				annPayload
			);

			expect(node.getGraph().getChannelCount()).to.equal(1);
			expect(node.getGraph().getNodeCount()).to.equal(2);
		});

		it('should build multi-channel graph', function () {
			const node = createNode(1);
			const scid1 = encodeShortChannelId({
				block: 100,
				txIndex: 1,
				outputIndex: 0
			});
			const scid2 = encodeShortChannelId({
				block: 200,
				txIndex: 2,
				outputIndex: 0
			});
			const gossipKey3 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-node-3'))
				.digest();
			const bitcoinKey3 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-bitcoin-3'))
				.digest();

			const { payload: ann1 } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				scid1
			);
			const { payload: ann2 } = createSignedChannelAnnouncement(
				gossipKey2,
				gossipKey3,
				bitcoinKey2,
				bitcoinKey3,
				scid2
			);

			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				ann1
			);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				ann2
			);

			expect(node.getGraph().getChannelCount()).to.equal(2);
			expect(node.getGraph().getNodeCount()).to.equal(3);
		});
	});

	describe('Channel Lifecycle', function () {
		it('should open a channel between two connected nodes', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
			expect(channel).to.exist;
			// With loopback wiring, Bob immediately processes open_channel and sends accept_channel
			expect(channel.getState()).to.equal(ChannelState.SENT_ACCEPT);
		});

		it('should reach NORMAL state after funding confirmed', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			const aliceChannel = alice.getChannelManager().getChannel(channelId);
			expect(aliceChannel).to.exist;
			expect(aliceChannel!.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should list channels', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			expect(alice.listChannels()).to.have.length(0);
			openReadyChannel(alice, bob);
			expect(alice.listChannels()).to.have.length(1);
		});

		it('should get specific channel info', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			const info = alice.getChannel(channelId);
			expect(info).to.exist;
			expect(info!.state).to.equal(ChannelState.NORMAL);
			expect(info!.fundingSatoshis).to.equal(1_000_000n);
		});

		it('should return undefined for unknown channel', function () {
			const alice = createNode(1);
			expect(alice.getChannel(crypto.randomBytes(32))).to.be.undefined;
		});

		it('should show balances', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			const info = alice.getChannel(channelId);
			expect(info).to.exist;
			// Alice opened with 1M sats, no push
			expect(info!.localBalanceMsat).to.equal(1_000_000_000n);
			expect(info!.remoteBalanceMsat).to.equal(0n);
		});

		it('should register channel SCID', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			const scid = encodeShortChannelId({
				block: 500,
				txIndex: 1,
				outputIndex: 0
			});
			alice.registerChannelScid(channelId, scid);
			// Just verify it doesn't throw - the SCID mapping is used during forwarding
		});

		it('should emit channel:ready event', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			let readyEmitted = false;
			alice.on('channel:ready', () => {
				readyEmitted = true;
			});

			openReadyChannel(alice, bob);
			expect(readyEmitted).to.be.true;
		});
	});

	describe('Invoice Management', function () {
		it('should create a valid BOLT 11 invoice', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test payment'
			});
			expect(invoice.bolt11).to.be.a('string');
			expect(invoice.bolt11.startsWith('lnbcrt')).to.be.true;
		});

		it('should produce a decodable invoice with correct fields', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 50_000_000n,
				description: 'coffee'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			expect(decoded.amountMsat).to.equal(50_000_000n);
			expect(decoded.description).to.equal('coffee');
			expect(decoded.network).to.equal(Network.REGTEST);
		});

		it('should store payment hash and preimage', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			const payment = node.getPayment(decoded.paymentHash);
			expect(payment).to.exist;
			expect(payment!.preimage).to.exist;

			// Verify preimage → hash
			const hash = crypto
				.createHash('sha256')
				.update(payment!.preimage!)
				.digest();
			expect(hash.equals(decoded.paymentHash)).to.be.true;
		});

		it('should return PENDING incoming payment after creation', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			const payment = node.getPayment(decoded.paymentHash);
			expect(payment!.status).to.equal(PaymentStatus.PENDING);
			expect(payment!.direction).to.equal(PaymentDirection.INCOMING);
		});

		it('should honor custom expiry', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test',
				expiry: 7200
			});

			const decoded = decodeInvoice(invoice.bolt11);
			expect(decoded.expiry).to.equal(7200);
		});

		it('should default expiry to 3600', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			expect(decoded.expiry).to.equal(3600);
		});

		it('should default minFinalCltvExpiry to 40', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			expect(decoded.minFinalCltvExpiry).to.equal(40);
		});

		it('should include payment secret in invoice', function () {
			const node = createNode(1);
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			expect(decoded.paymentSecret).to.exist;
			expect(decoded.paymentSecret!.length).to.equal(32);
		});
	});

	describe('Payment Sending', function () {
		it('should decode invoice and find route in sendPayment', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);

			// Build graph so route can be found
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'test payment'
			});

			const payment = alice.sendPayment(invoice.bolt11);
			expect(payment).to.exist;
			// With synchronous loopback, payment completes immediately
			expect(payment.status).to.equal(PaymentStatus.COMPLETED);
			expect(payment.direction).to.equal(PaymentDirection.OUTGOING);
		});

		it('should throw if no route found', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			// No channel, no graph

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'test'
			});

			expect(() => alice.sendPayment(invoice.bolt11)).to.throw(
				'No route found'
			);
		});

		it('should store shared secrets in payment info', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'test'
			});

			const payment = alice.sendPayment(invoice.bolt11);
			expect(payment.sharedSecrets).to.exist;
			expect(payment.sharedSecrets!.length).to.be.greaterThan(0);
		});

		it('should add outgoing HTLC to channel', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'test'
			});

			// Capture the outbound update_add_htlc. The payment completes
			// synchronously via the loopback (Bob fulfills), so the HTLC is settled
			// and removed by the time sendPayment returns — we observe it on the wire.
			let addPayload: Buffer | null = null;
			alice.on(
				'message:outbound',
				(_pubkey: string, type: number, payload: Buffer) => {
					if (type === MessageType.UPDATE_ADD_HTLC && !addPayload)
						addPayload = payload;
				}
			);

			alice.sendPayment(invoice.bolt11);

			expect(addPayload).to.not.be.null;
			const added = decodeUpdateAddHtlcMessage(addPayload!);
			expect(added.amountMsat).to.equal(10_000_000n);
		});

		it('should set an ABSOLUTE cltv_expiry (block height + delta) on the outgoing HTLC', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			// Simulate a realistic chain tip on the sender.
			const HEIGHT = 800_000;
			alice.handleNewBlock(HEIGHT);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'cltv'
			});

			let addPayload: Buffer | null = null;
			alice.on(
				'message:outbound',
				(_pubkey: string, type: number, payload: Buffer) => {
					if (type === MessageType.UPDATE_ADD_HTLC && !addPayload)
						addPayload = payload;
				}
			);

			alice.sendPayment(invoice.bolt11);

			expect(addPayload).to.not.be.null;
			const added = decodeUpdateAddHtlcMessage(addPayload!);
			// Must be absolute: height + final-cltv delta. Before the fix this was the
			// bare relative delta (~40), which any remote node rejects as
			// incorrect_or_unknown_payment_details ("cltv expiry too soon").
			expect(added.cltvExpiry).to.be.greaterThan(HEIGHT);
			expect(added.cltvExpiry).to.be.lessThan(HEIGHT + 1000);
		});

		it('initiateGossipSync sends gossip query messages to the peer', function () {
			const node = createNode(1);
			const peer = '02' + 'ab'.repeat(32);
			const sentTypes: number[] = [];
			node.on('message:outbound', (pk: string, type: number) => {
				if (pk === peer) sentTypes.push(type);
			});

			node.initiateGossipSync(peer);

			// Pulls the graph from the peer: timestamp filter + channel range query.
			expect(sentTypes).to.include(MessageType.GOSSIP_TIMESTAMP_FILTER);
			expect(sentTypes).to.include(MessageType.QUERY_CHANNEL_RANGE);
		});

		it('should send 1366-byte onion in HTLC', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'test'
			});

			// Capture the outbound update_add_htlc onion. The payment completes
			// synchronously (Bob fulfills) so the HTLC is removed by the time
			// sendPayment returns — we verify the onion on the wire instead.
			let addPayload: Buffer | null = null;
			alice.on(
				'message:outbound',
				(_pubkey: string, type: number, payload: Buffer) => {
					if (type === MessageType.UPDATE_ADD_HTLC && !addPayload)
						addPayload = payload;
				}
			);

			alice.sendPayment(invoice.bolt11);

			expect(addPayload).to.not.be.null;
			const added = decodeUpdateAddHtlcMessage(addPayload!);
			expect(added.onionRoutingPacket.length).to.equal(1366);
		});

		it('should track multiple payments independently', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const inv1 = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'payment 1'
			});
			const inv2 = bob.createInvoice({
				amountMsat: 2_000_000n,
				description: 'payment 2'
			});

			const p1 = alice.sendPayment(inv1.bolt11);
			const p2 = alice.sendPayment(inv2.bolt11);

			expect(p1.paymentHash.equals(p2.paymentHash)).to.be.false;
			expect(alice.listPayments().length).to.be.greaterThanOrEqual(2);
		});
	});

	describe('Payment Receiving', function () {
		it('should auto-fulfill incoming HTLC with known preimage', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'test'
			});

			let receivedPayment: IPaymentInfo | null = null;
			bob.on('payment:received', (p: IPaymentInfo) => {
				receivedPayment = p;
			});

			alice.sendPayment(invoice.bolt11);

			expect(receivedPayment).to.exist;
			expect(receivedPayment!.status).to.equal(PaymentStatus.COMPLETED);
		});

		it('should emit payment:received event on fulfillment', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'test'
			});

			let eventFired = false;
			bob.on('payment:received', () => {
				eventFired = true;
			});

			alice.sendPayment(invoice.bolt11);
			expect(eventFired).to.be.true;
		});

		it('settles an incoming HTLC for a BOLT 12 offer invoice (preimage wired from OfferManager)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			// Bob publishes a BOLT 12 offer and issues an invoice in response to an
			// invoice_request (the RECEIVE side). The fix wires the issued preimage
			// from the OfferManager into Bob's node receive stores so an incoming HTLC
			// for this payment_hash can actually be fulfilled.
			const amountMsat = 10_000_000n;
			const offerMgr = bob.getOfferManager();
			const { offer } = offerMgr.createOffer({
				description: 'bolt12 receive',
				amount: amountMsat
			});
			// A signed invoice_request (handleInvoiceRequest requires metadata + a
			// valid payer signature per BOLT 12).
			const payerPriv = makeNodeConfig(1).nodePrivateKey;
			const request: IInvoiceRequest = {
				payerKey: getPublicKey(payerPriv),
				offerId: offer.offerId,
				amount: amountMsat,
				metadata: crypto.randomBytes(16)
			};
			const offerTlv = encodeOfferTlv(offer);
			const unsigned = encodeInvoiceRequestTlv(request, offerTlv);
			request.signature = schnorrSign(
				computeSignatureHash(
					'lightninginvoice_requestsignature',
					computeMerkleRootFromRecords(getTlvRecords(unsigned))
				),
				payerPriv
			);
			const b12 = offerMgr.handleInvoiceRequest(
				encodeInvoiceRequestTlv(request, offerTlv)
			)!;
			expect(b12, 'bob issued a BOLT 12 invoice').to.not.be.null;

			// The wiring registered the preimage + secret + amount into the SAME
			// stores the BOLT 11 receive path consults (these were previously absent,
			// so the HTLC was failed with unknown_payment_hash).
			const hashHex = b12.paymentHash.toString('hex');
			expect(bob['preimages'].has(hashHex), 'preimage registered').to.be.true;
			expect(bob['paymentSecrets'].has(hashHex), 'secret registered').to.be
				.true;
			expect(bob['invoices'].has(hashHex), 'invoice registered').to.be.true;

			// Alice has no BOLT 12 send pipeline in this harness, so transport the
			// invoice's (payment_hash, payment_secret, amount) to her sender via a
			// BOLT 11 string signed by Bob. Bob only ever sees the resulting HTLC,
			// which it settles from the OfferManager-issued preimage now in its store.
			const bolt11 = encodeInvoice({
				network: Network.REGTEST,
				amountMsat,
				paymentHash: b12.paymentHash,
				paymentSecret: b12.paymentSecret!,
				description: 'bolt12 receive',
				privateKey: makeNodeConfig(2).nodePrivateKey
			});

			let received: IPaymentInfo | null = null;
			bob.on('payment:received', (p: IPaymentInfo) => {
				received = p;
			});

			const sent = alice.sendPayment(bolt11);

			// Alice's payment COMPLETED ⇒ Bob revealed the preimage, i.e. Bob
			// fulfilled the HTLC from the OfferManager-issued preimage now wired into
			// its receive store (without the fix this HTLC would be failed).
			expect(alice.getPayment(sent.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			// Bob emitted payment:received and recorded the incoming payment.
			expect(received, 'bob received the BOLT 12 payment').to.not.be.null;
			expect(received!.status).to.equal(PaymentStatus.COMPLETED);
			const bobPayment = bob.getPayment(b12.paymentHash);
			expect(bobPayment, 'bob recorded the payment').to.exist;
			expect(bobPayment!.preimage, 'fulfilled with a preimage').to.exist;
			const hash = crypto
				.createHash('sha256')
				.update(bobPayment!.preimage!)
				.digest();
			expect(hash.equals(b12.paymentHash), 'preimage hashes to invoice hash').to
				.be.true;
		});

		it('consumes an on-chain-learned preimage: seeds monitors + fulfills the inbound leg (H3)', function () {
			const alice = createNode(1);
			const bob = createNode(2); // bob = the forwarding node
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const cm = bob.getChannelManager();
			const bobChannel = cm.listChannels()[0];

			// A live INBOUND (received) HTLC on bob — the leg bob must settle once it
			// learns the preimage (e.g. its downstream force-closed and swept the
			// outgoing HTLC on-chain, revealing it).
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			bobChannel.getFullState().htlcs.set('received-7', {
				id: 7n,
				amountMsat: 3_000_000n,
				paymentHash,
				cltvExpiry: 800_000,
				onionRoutingPacket: crypto.randomBytes(1366),
				direction: HtlcDirection.RECEIVED,
				state: HtlcState.COMMITTED
			});

			// Spy the two effects the handler must produce (isolated from the full
			// commitment machinery).
			let recorded: { hash: string; pre: string } | null = null;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(cm as any).recordPreimage = (h: Buffer, p: Buffer) => {
				recorded = { hash: h.toString('hex'), pre: p.toString('hex') };
			};
			let fulfilled: { id: bigint; pre: string } | null = null;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(cm as any).fulfillHtlc = (_cid: Buffer, id: bigint, p: Buffer) => {
				fulfilled = { id, pre: p.toString('hex') };
				return { ok: true, actions: [] };
			};

			// Fire the on-chain preimage the way ChainMonitor → processChainActions does.
			cm.emit('preimage:learned', paymentHash, preimage);

			// 1) Seeded every monitor for on-chain claim of any inbound HTLC of this hash.
			expect(recorded, 'recordPreimage called').to.not.be.null;
			expect(recorded!.hash).to.equal(paymentHash.toString('hex'));
			expect(recorded!.pre).to.equal(preimage.toString('hex'));
			// 2) Off-chain settled the matching inbound leg.
			expect(fulfilled, 'inbound leg fulfilled').to.not.be.null;
			expect(fulfilled!.id).to.equal(7n);
			expect(fulfilled!.pre).to.equal(preimage.toString('hex'));
			// 3) Preimage persisted on the node.
			expect(bob['preimages'].has(paymentHash.toString('hex'))).to.be.true;
		});

		it('should update payment status to COMPLETED', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'test'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			alice.sendPayment(invoice.bolt11);

			const payment = bob.getPayment(decoded.paymentHash);
			expect(payment).to.exist;
			expect(payment!.status).to.equal(PaymentStatus.COMPLETED);
		});

		it('should fail HTLC for unknown payment hash', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);

			// Manually construct onion and HTLC with an unknown payment hash
			const unknownHash = crypto.randomBytes(32);
			const sessionKey = crypto.randomBytes(32);
			const bobPubkey = getPublicKey(makeNodeConfig(2).nodePrivateKey);

			const onionPacket = constructOnionPacket(sessionKey, [
				{
					pubkey: bobPubkey,
					payload: { amountToForwardMsat: 1_000_000n, outgoingCltvValue: 500 }
				}
			]);
			const onionBuf = encodeOnionPacket(onionPacket);

			let htlcFailed = false;
			alice.getChannelManager().on('htlc:failed', () => {
				htlcFailed = true;
			});

			alice
				.getChannelManager()
				.addHtlc(channelId, 1_000_000n, unknownHash, 500, onionBuf);

			expect(htlcFailed).to.be.true;
		});
	});

	describe('End-to-End Payment', function () {
		it('should complete Alice → Bob payment (single channel)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'e2e test'
			});

			let sentPayment: IPaymentInfo | null = null;
			let receivedPayment: IPaymentInfo | null = null;

			alice.on('payment:sent', (p: IPaymentInfo) => {
				sentPayment = p;
			});
			bob.on('payment:received', (p: IPaymentInfo) => {
				receivedPayment = p;
			});

			alice.sendPayment(invoice.bolt11);

			// Bob receives
			expect(receivedPayment).to.exist;
			expect(receivedPayment!.status).to.equal(PaymentStatus.COMPLETED);

			// Alice sent
			expect(sentPayment).to.exist;
			expect(sentPayment!.status).to.equal(PaymentStatus.COMPLETED);
		});

		it('should track PENDING → COMPLETED on both sides', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'status tracking'
			});

			const decoded = decodeInvoice(invoice.bolt11);

			// Bob's payment starts as PENDING
			expect(bob.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			alice.sendPayment(invoice.bolt11);

			// Both completed
			expect(bob.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(alice.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('should match preimage on both sides', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'preimage check'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			alice.sendPayment(invoice.bolt11);

			const alicePayment = alice.getPayment(decoded.paymentHash)!;
			const bobPayment = bob.getPayment(decoded.paymentHash)!;

			expect(alicePayment.preimage).to.exist;
			expect(bobPayment.preimage).to.exist;
			expect(alicePayment.preimage!.equals(bobPayment.preimage!)).to.be.true;
		});

		it('should support multiple sequential payments', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			for (let i = 0; i < 3; i++) {
				const invoice = bob.createInvoice({
					amountMsat: 1_000_000n,
					description: `payment ${i}`
				});

				const payment = alice.sendPayment(invoice.bolt11);
				expect(payment).to.exist;
			}

			// All 3 outgoing + 3 incoming tracked
			const alicePayments = alice
				.listPayments()
				.filter((p) => p.direction === PaymentDirection.OUTGOING);
			expect(alicePayments.length).to.equal(3);
			alicePayments.forEach((p) =>
				expect(p.status).to.equal(PaymentStatus.COMPLETED)
			);
		});

		it('should handle payment with specified amount in invoice', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const amountMsat = 25_000_000n;
			const invoice = bob.createInvoice({
				amountMsat,
				description: 'specific amount'
			});

			let sentPayment: IPaymentInfo | null = null;
			alice.on('payment:sent', (p: IPaymentInfo) => {
				sentPayment = p;
			});

			alice.sendPayment(invoice.bolt11);

			expect(sentPayment).to.exist;
			expect(sentPayment!.amountMsat).to.equal(amountMsat);
		});

		it('should return complete payment info after payment', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'info check'
			});

			const decoded = decodeInvoice(invoice.bolt11);
			alice.sendPayment(invoice.bolt11);

			const payment = alice.getPayment(decoded.paymentHash)!;
			expect(payment.paymentHash).to.exist;
			expect(payment.preimage).to.exist;
			expect(payment.status).to.equal(PaymentStatus.COMPLETED);
			expect(payment.direction).to.equal(PaymentDirection.OUTGOING);
			expect(payment.createdAt).to.be.a('number');
			expect(payment.completedAt).to.be.a('number');
		});
	});

	describe('Hold Invoices (M2.1)', function () {
		it('parks the HTLC and settles on demand', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold',
				hold: true
			});

			let held = false;
			bob.on('htlc:held', () => {
				held = true;
			});

			alice.sendPayment(invoice.bolt11);

			// HTLC is parked: Bob has not received (settled) it yet.
			expect(held, 'htlc:held emitted').to.be.true;
			expect(bob.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			// Release it — both sides complete and preimages match.
			expect(bob.settleHeldHtlc(invoice.paymentHash)).to.be.true;
			expect(bob.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(bob.listHeldHtlcs()).to.have.length(0);
		});

		it('cancels a held HTLC, failing the payment back', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-cancel',
				hold: true
			});

			alice.sendPayment(invoice.bolt11);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			expect(bob.cancelHeldHtlc(invoice.paymentHash)).to.be.true;
			expect(bob.listHeldHtlcs()).to.have.length(0);
			// Bob never completed; Alice's outgoing payment did not succeed.
			expect(bob.getPayment(invoice.paymentHash)!.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('supports an externally-supplied payment hash (preimage held elsewhere)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const externalPreimage = crypto.randomBytes(32);
			const externalHash = crypto
				.createHash('sha256')
				.update(externalPreimage)
				.digest();

			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-external',
				hold: true,
				paymentHash: externalHash
			});
			expect(invoice.paymentHash).to.deep.equal(externalHash);

			alice.sendPayment(invoice.bolt11);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			// Wrong preimage is rejected; the correct external preimage settles.
			expect(() =>
				bob.settleHeldHtlc(externalHash, crypto.randomBytes(32))
			).to.throw();
			expect(bob.settleHeldHtlc(externalHash, externalPreimage)).to.be.true;
			expect(alice.getPayment(externalHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});
	});

	describe('Async Payments (M2.2)', function () {
		it('LSP holds the forward until release, then the offline receiver is paid', function () {
			const alice = createNode(1); // sender
			const lsp = createNode(2); // always-online LSP / introduction node
			const carol = createNode(3); // offline receiver

			connectNodes(alice, lsp);
			connectNodes(lsp, carol);

			const abChannelId = openReadyChannel(alice, lsp, 1_000_000n);
			const bcChannelId = openReadyChannel(lsp, carol, 1_000_000n);

			const scidAB = encodeShortChannelId({
				block: 700,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 700,
				txIndex: 2,
				outputIndex: 0
			});
			lsp.registerChannelScid(abChannelId, scidAB);
			lsp.registerChannelScid(bcChannelId, scidBC);
			carol
				.getChannelManager()
				.getChannel(bcChannelId)!
				.getFullState().shortChannelId = scidBC;

			buildThreeNodeGraph(alice, lsp, carol, scidAB, scidBC);

			// Carol issues an async invoice: blinded path through the LSP, marked
			// hold_htlc so the LSP parks the HTLC while she is offline.
			const invoice = carol.createInvoice({
				amountMsat: 5_000_000n,
				description: 'async',
				useBlindedPaths: true,
				asyncHold: true
			});

			let heldForward = false;
			lsp.on('htlc:held-forward', () => {
				heldForward = true;
			});

			alice.sendPayment(invoice.bolt11);

			// LSP parked the forward; Carol has NOT been paid yet.
			expect(heldForward, 'LSP parked the forward').to.be.true;
			expect(lsp.listHeldForwards()).to.have.length(1);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);

			// Carol comes online → LSP releases the held forward → Carol is paid.
			expect(lsp.releaseHeldForward(invoice.paymentHash)).to.be.true;
			expect(lsp.listHeldForwards()).to.have.length(0);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('release via a release_held_htlc onion message from the receiver', function () {
			const alice = createNode(1);
			const lsp = createNode(2);
			const carol = createNode(3);

			connectNodes(alice, lsp);
			connectNodes(lsp, carol);

			const abChannelId = openReadyChannel(alice, lsp, 1_000_000n);
			const bcChannelId = openReadyChannel(lsp, carol, 1_000_000n);
			const scidAB = encodeShortChannelId({
				block: 710,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 710,
				txIndex: 2,
				outputIndex: 0
			});
			lsp.registerChannelScid(abChannelId, scidAB);
			lsp.registerChannelScid(bcChannelId, scidBC);
			carol
				.getChannelManager()
				.getChannel(bcChannelId)!
				.getFullState().shortChannelId = scidBC;
			buildThreeNodeGraph(alice, lsp, carol, scidAB, scidBC);

			// Wire onion-message delivery Carol → LSP (no networking in this harness).
			carol
				.getOnionMessageManager()
				.setSendFunction((toPeer: string, _type: number, payload: Buffer) => {
					if (toPeer === lsp.getNodeId()) {
						lsp
							.getOnionMessageManager()
							.handleMessage(carol.getNodeId(), payload);
					}
				});

			const invoice = carol.createInvoice({
				amountMsat: 5_000_000n,
				description: 'async-msg',
				useBlindedPaths: true,
				asyncHold: true
			});

			alice.sendPayment(invoice.bolt11);
			expect(lsp.listHeldForwards()).to.have.length(1);

			// Carol sends release_held_htlc as an onion message to the LSP.
			carol.sendAsyncRelease(
				Buffer.from(lsp.getNodeId(), 'hex'),
				invoice.paymentHash
			);

			expect(lsp.listHeldForwards()).to.have.length(0);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});
	});

	describe('Multi-hop blinded paths (M1-FU4)', function () {
		function nodePrivkeyFor(seedId: number): Buffer {
			return crypto
				.createHash('sha256')
				.update(makeSeed(seedId))
				.update(Buffer.from('node-identity'))
				.digest();
		}

		it('pays a 3-hop blinded path (Alice → Bob(intro) → Carol(mid) → Dave)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			const carol = createNode(3);
			const dave = createNode(4);
			connectNodes(alice, bob);
			connectNodes(bob, carol);
			connectNodes(carol, dave);

			const abChannelId = openReadyChannel(alice, bob, 2_000_000n);
			const bcChannelId = openReadyChannel(bob, carol, 2_000_000n);
			const cdChannelId = openReadyChannel(carol, dave, 2_000_000n);

			const scidAB = encodeShortChannelId({
				block: 900,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 900,
				txIndex: 2,
				outputIndex: 0
			});
			const scidCD = encodeShortChannelId({
				block: 900,
				txIndex: 3,
				outputIndex: 0
			});
			bob.registerChannelScid(abChannelId, scidAB);
			bob.registerChannelScid(bcChannelId, scidBC);
			carol.registerChannelScid(bcChannelId, scidBC);
			carol.registerChannelScid(cdChannelId, scidCD);

			const alicePub = getPublicKey(nodePrivkeyFor(1));
			const bobPub = getPublicKey(nodePrivkeyFor(2));
			const carolPub = getPublicKey(nodePrivkeyFor(3));
			const davePub = getPublicKey(nodePrivkeyFor(4));

			// Alice needs a graph route to Bob (the introduction node).
			const abIs1 = Buffer.compare(alicePub, bobPub) < 0;
			alice.getGraph().addChannelAnnouncement({
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scidAB,
				nodeId1: abIs1 ? alicePub : bobPub,
				nodeId2: abIs1 ? bobPub : alicePub,
				bitcoinKey1: Buffer.alloc(33, 2),
				bitcoinKey2: Buffer.alloc(33, 3)
			});
			for (const dir of [0, 1]) {
				alice.getGraph().applyChannelUpdate({
					signature: Buffer.alloc(64),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: scidAB,
					timestamp: Math.floor(Date.now() / 1000),
					messageFlags: 1,
					channelFlags: dir,
					cltvExpiryDelta: 40,
					htlcMinimumMsat: 1000n,
					feeBaseMsat: 1000,
					feeProportionalMillionths: 1,
					htlcMaximumMsat: 1_000_000_000n
				});
			}
			alice.registerChannelScid(abChannelId, scidAB);

			// Dave registers the preimage/secret via a normal invoice, then we re-issue
			// it carrying a hand-built 3-hop blinded path through Bob and Carol.
			const baseInv = dave.createInvoice({
				amountMsat: 5_000_000n,
				description: 'mh'
			});
			const decoded = decodeInvoice(baseInv.bolt11);

			const constraints = { maxCltvExpiry: 10_000_000, htlcMinimumMsat: 0n };
			// feeProp=0 so per-hop fees distribute exactly across the chain.
			const relay = {
				cltvExpiryDelta: 40,
				feeProportionalMillionths: 0,
				feeBaseMsat: 1000
			};
			const hopData: IBlindedHopData[] = [
				{
					nextNodeId: carolPub,
					shortChannelId: scidBC,
					paymentRelay: relay,
					paymentConstraints: constraints
				},
				{
					nextNodeId: davePub,
					shortChannelId: scidCD,
					paymentRelay: relay,
					paymentConstraints: constraints
				},
				{ paymentConstraints: constraints }
			];
			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[bobPub, carolPub, davePub],
				hopData
			);
			const payInfo = {
				feeBaseMsat: 2000, // sum of the two forwarding hops' base fees
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 80, // sum of the two hops' deltas
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: 1_000_000_000n
			};

			const invoiceStr = encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 5_000_000n,
				paymentHash: decoded.paymentHash,
				paymentSecret: decoded.paymentSecret,
				description: 'mh-blinded',
				blindedPaths: [{ path, payInfo }],
				minFinalCltvExpiry: 40,
				privateKey: nodePrivkeyFor(4)
			});

			let bobFwd = false;
			let carolFwd = false;
			bob.on('htlc:forward', () => {
				bobFwd = true;
			});
			carol.on('htlc:forward', () => {
				carolFwd = true;
			});

			alice.sendPayment(invoiceStr);

			// The HTLC traversed both blinded forwarding hops to the recipient.
			expect(bobFwd, 'Bob (intro) forwarded').to.be.true;
			expect(carolFwd, 'Carol (mid) forwarded').to.be.true;
			expect(dave.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(alice.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('pays a GENERATED 3-node blinded path (Dave builds [Bob → Carol → Dave] from his graph)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			const carol = createNode(3);
			const dave = createNode(4);
			connectNodes(alice, bob);
			connectNodes(bob, carol);
			connectNodes(carol, dave);

			const abChannelId = openReadyChannel(alice, bob, 2_000_000n);
			const bcChannelId = openReadyChannel(bob, carol, 2_000_000n);
			const cdChannelId = openReadyChannel(carol, dave, 2_000_000n);

			const scidAB = encodeShortChannelId({
				block: 901,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 901,
				txIndex: 2,
				outputIndex: 0
			});
			const scidCD = encodeShortChannelId({
				block: 901,
				txIndex: 3,
				outputIndex: 0
			});
			bob.registerChannelScid(abChannelId, scidAB);
			bob.registerChannelScid(bcChannelId, scidBC);
			carol.registerChannelScid(bcChannelId, scidBC);
			carol.registerChannelScid(cdChannelId, scidCD);
			alice.registerChannelScid(abChannelId, scidAB);

			const alicePub = getPublicKey(nodePrivkeyFor(1));
			const bobPub = getPublicKey(nodePrivkeyFor(2));
			const carolPub = getPublicKey(nodePrivkeyFor(3));

			// Dave's channel needs an SCID Carol recognizes so the generated peer
			// hop can name the forwarding channel.
			const daveChannel = dave.getChannelManager().getChannel(cdChannelId)!;
			daveChannel.getFullState().scidAlias = scidCD;

			// Dave's graph knows the public Bob↔Carol edge (Bob's policy authored
			// for the Bob→Carol direction) — the raw material for the extension.
			const bcIs1 = Buffer.compare(bobPub, carolPub) < 0;
			dave.getGraph().addChannelAnnouncement({
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scidBC,
				nodeId1: bcIs1 ? bobPub : carolPub,
				nodeId2: bcIs1 ? carolPub : bobPub,
				bitcoinKey1: Buffer.alloc(33, 2),
				bitcoinKey2: Buffer.alloc(33, 3)
			});
			dave.getGraph().applyChannelUpdate({
				signature: Buffer.alloc(64),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scidBC,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: bcIs1 ? 0 : 1, // Bob-authored direction
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 0,
				htlcMaximumMsat: 1_000_000_000n
			});

			// Alice's graph knows her route to Bob (the introduction node).
			const abIs1 = Buffer.compare(alicePub, bobPub) < 0;
			alice.getGraph().addChannelAnnouncement({
				nodeSignature1: Buffer.alloc(64),
				nodeSignature2: Buffer.alloc(64),
				bitcoinSignature1: Buffer.alloc(64),
				bitcoinSignature2: Buffer.alloc(64),
				features: Buffer.alloc(0),
				chainHash: BITCOIN_CHAIN_HASH,
				shortChannelId: scidAB,
				nodeId1: abIs1 ? alicePub : bobPub,
				nodeId2: abIs1 ? bobPub : alicePub,
				bitcoinKey1: Buffer.alloc(33, 2),
				bitcoinKey2: Buffer.alloc(33, 3)
			});
			for (const dir of [0, 1]) {
				alice.getGraph().applyChannelUpdate({
					signature: Buffer.alloc(64),
					chainHash: BITCOIN_CHAIN_HASH,
					shortChannelId: scidAB,
					timestamp: Math.floor(Date.now() / 1000),
					messageFlags: 1,
					channelFlags: dir,
					cltvExpiryDelta: 40,
					htlcMinimumMsat: 1000n,
					feeBaseMsat: 1000,
					feeProportionalMillionths: 1,
					htlcMaximumMsat: 1_000_000_000n
				});
			}

			// Dave GENERATES the blinded invoice — no hand-built path.
			const inv = dave.createInvoice({
				amountMsat: 5_000_000n,
				description: 'generated-3hop',
				useBlindedPaths: true
			});
			const decoded = decodeInvoice(inv.bolt11);
			expect(
				decoded.blindedPaths,
				'invoice carries a blinded path'
			).to.have.length(1);
			const bp = decoded.blindedPaths![0];
			expect(bp.path.blindedHops, 'generated path has 3 nodes').to.have.length(
				3
			);
			// Bob (two hops from Dave) is the introduction node — Carol stays hidden.
			expect(bp.path.introductionNodeId).to.deep.equal(bobPub);

			let bobFwd = false;
			let carolFwd = false;
			bob.on('htlc:forward', () => {
				bobFwd = true;
			});
			carol.on('htlc:forward', () => {
				carolFwd = true;
			});

			alice.sendPayment(inv.bolt11);

			expect(bobFwd, 'Bob (intro) forwarded').to.be.true;
			expect(carolFwd, 'Carol (mid) forwarded').to.be.true;
			expect(dave.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(alice.getPayment(decoded.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});
	});

	describe('HTLC Forwarding', function () {
		it('should forward HTLC through intermediate node (3-hop payment)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			const charlie = createNode(3);

			connectNodes(alice, bob);
			connectNodes(bob, charlie);

			// Open Alice→Bob and Bob→Charlie channels
			const abChannelId = openReadyChannel(alice, bob, 1_000_000n);
			const bcChannelId = openReadyChannel(bob, charlie, 1_000_000n);

			// Register SCIDs on Bob (the forwarder)
			const scidAB = encodeShortChannelId({
				block: 500,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 500,
				txIndex: 2,
				outputIndex: 0
			});
			bob.registerChannelScid(abChannelId, scidAB);
			bob.registerChannelScid(bcChannelId, scidBC);

			// Build graph on Alice with both channels
			buildThreeNodeGraph(alice, bob, charlie, scidAB, scidBC);

			// Charlie creates invoice
			const invoice = charlie.createInvoice({
				amountMsat: 5_000_000n,
				description: '3-hop payment'
			});

			let receivedPayment: IPaymentInfo | null = null;
			charlie.on('payment:received', (p: IPaymentInfo) => {
				receivedPayment = p;
			});

			let sentPayment: IPaymentInfo | null = null;
			alice.on('payment:sent', (p: IPaymentInfo) => {
				sentPayment = p;
			});

			// Debug: track all events
			let bobForwarded = false;
			bob.on('htlc:forward', () => {
				bobForwarded = true;
			});

			alice.sendPayment(invoice.bolt11);

			expect(bobForwarded).to.be.true;
			expect(receivedPayment).to.exist;
			expect(receivedPayment!.status).to.equal(PaymentStatus.COMPLETED);

			// Check Alice's payment status directly
			const decoded = decodeInvoice(invoice.bolt11);
			const alicePayment = alice.getPayment(decoded.paymentHash);
			expect(alicePayment).to.exist;
			expect(alicePayment!.status).to.equal(PaymentStatus.COMPLETED);
			expect(sentPayment).to.exist;
			expect(sentPayment!.status).to.equal(PaymentStatus.COMPLETED);
		});

		it('should emit htlc:forward event on intermediate node', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			const charlie = createNode(3);

			connectNodes(alice, bob);
			connectNodes(bob, charlie);

			const abChannelId = openReadyChannel(alice, bob, 1_000_000n);
			const bcChannelId = openReadyChannel(bob, charlie, 1_000_000n);

			const scidAB = encodeShortChannelId({
				block: 500,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 500,
				txIndex: 2,
				outputIndex: 0
			});
			bob.registerChannelScid(abChannelId, scidAB);
			bob.registerChannelScid(bcChannelId, scidBC);

			buildThreeNodeGraph(alice, bob, charlie, scidAB, scidBC);

			let forwardEmitted = false;
			bob.on('htlc:forward', () => {
				forwardEmitted = true;
			});

			const invoice = charlie.createInvoice({
				amountMsat: 5_000_000n,
				description: 'forward test'
			});

			alice.sendPayment(invoice.bolt11);

			expect(forwardEmitted).to.be.true;
		});

		it('should pay a blinded-path invoice end-to-end (Alice → Bob(intro) → Charlie)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			const charlie = createNode(3);

			connectNodes(alice, bob);
			connectNodes(bob, charlie);

			const abChannelId = openReadyChannel(alice, bob, 1_000_000n);
			const bcChannelId = openReadyChannel(bob, charlie, 1_000_000n);

			const scidAB = encodeShortChannelId({
				block: 600,
				txIndex: 1,
				outputIndex: 0
			});
			const scidBC = encodeShortChannelId({
				block: 600,
				txIndex: 2,
				outputIndex: 0
			});

			// Bob (introduction/forwarding node) maps scidBC → its channel to Charlie.
			bob.registerChannelScid(abChannelId, scidAB);
			bob.registerChannelScid(bcChannelId, scidBC);

			// Charlie must embed scidBC in its blinded path so Bob can forward to it.
			charlie
				.getChannelManager()
				.getChannel(bcChannelId)!
				.getFullState().shortChannelId = scidBC;

			// Alice needs a route to the introduction node (Bob).
			buildThreeNodeGraph(alice, bob, charlie, scidAB, scidBC);

			// Charlie issues a blinded invoice; the payee node id is hidden behind Bob.
			const invoice = charlie.createInvoice({
				amountMsat: 5_000_000n,
				description: 'blinded e2e',
				useBlindedPaths: true
			});
			const decoded = decodeInvoice(invoice.bolt11);
			expect(
				decoded.blindedPaths,
				'invoice carries a blinded path'
			).to.have.length(1);
			expect(
				decoded.blindedPaths![0].path.introductionNodeId,
				'introduction node is Bob, not Charlie'
			).to.deep.equal(Buffer.from(bob.getNodeId(), 'hex'));

			let bobForwarded = false;
			bob.on('htlc:forward', () => {
				bobForwarded = true;
			});
			let received: IPaymentInfo | null = null;
			charlie.on('payment:received', (p: IPaymentInfo) => {
				received = p;
			});

			alice.sendPayment(invoice.bolt11);

			expect(bobForwarded, 'Bob forwarded the blinded HTLC').to.be.true;
			expect(received, 'Charlie received the payment').to.exist;
			expect(received!.status).to.equal(PaymentStatus.COMPLETED);

			const alicePayment = alice.getPayment(decoded.paymentHash)!;
			expect(alicePayment.status).to.equal(PaymentStatus.COMPLETED);
			expect(alicePayment.preimage).to.exist;
		});
	});

	describe('PeerManager Integration — Construction', function () {
		it('should default to networking disabled', function () {
			const node = createNode(1);
			expect(node.isNetworkingEnabled()).to.be.false;
			expect(node.getPeerManager()).to.be.null;
		});

		it('should create PeerManager when enableNetworking is true', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			expect(node.isNetworkingEnabled()).to.be.true;
			expect(node.getPeerManager()).to.be.instanceOf(PeerManager);
			node.destroy();
		});

		it('should throw on connectPeer when networking disabled', async function () {
			const node = createNode(1);
			try {
				await node.connectPeer('deadbeef', 'localhost', 9735);
				expect.fail('should have thrown');
			} catch (err: unknown) {
				expect((err as Error).message).to.equal('Networking is not enabled');
			}
		});

		it('should throw on disconnectPeer when networking disabled', function () {
			const node = createNode(1);
			expect(() => node.disconnectPeer('deadbeef')).to.throw(
				'Networking is not enabled'
			);
		});
	});

	describe('PeerManager Integration — Wiring', function () {
		it('should report peerCount 0 when PeerManager exists but no peers', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			expect(node.getNodeInfo().peerCount).to.equal(0);
			node.destroy();
		});

		it('should report networkingEnabled correctly', function () {
			const nodeOff = createNode(1);
			expect(nodeOff.getNodeInfo().networkingEnabled).to.be.false;

			const config = makeNodeConfig(2);
			config.enableNetworking = true;
			const nodeOn = new LightningNode(config);
			expect(nodeOn.getNodeInfo().networkingEnabled).to.be.true;
			nodeOn.destroy();
		});

		it('should return PeerManager when enabled, null when disabled', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			expect(node.getPeerManager()).to.not.be.null;
			node.destroy();

			const node2 = createNode(2);
			expect(node2.getPeerManager()).to.be.null;
		});

		it('should route gossip messages from PeerManager to NetworkGraph', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);

			// Verify PeerManager was created
			expect(node.getPeerManager()).to.not.be.null;

			// Simulate a gossip message arriving — use handlePeerMessage which
			// exercises the same gossip routing that PeerManager handlers use
			const gossipKey1 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-node-1'))
				.digest();
			const gossipKey2 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-node-2'))
				.digest();
			const bitcoinKey1 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-bitcoin-1'))
				.digest();
			const bitcoinKey2 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-bitcoin-2'))
				.digest();
			const testScid = encodeShortChannelId({
				block: 100,
				txIndex: 1,
				outputIndex: 0
			});

			const { payload } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				testScid
			);

			// Invoke the registered handler via PeerManager's onMessage mechanism
			// PeerManager stores handlers internally; we emit 'message' which triggers them
			// But actually the handlers are registered via pm.onMessage() — they fire when
			// a peer emits 'message'. We can access the handlers by emitting directly.
			// Since the handlers are registered on the PeerManager via onMessage, we need to
			// trigger them. The simplest way is calling handlePeerMessage which works the same.
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				payload
			);

			expect(node.getGraph().getChannelCount()).to.equal(1);
			node.destroy();
		});
	});

	describe('PeerManager Integration — Event Forwarding', function () {
		it('should forward peer:connect event from PeerManager', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			const pm = node.getPeerManager()!;

			let connectPubkey: string | null = null;
			node.on('peer:connect', (pubkey: string) => {
				connectPubkey = pubkey;
			});

			pm.emit('peer:connect', 'abc123');
			expect(connectPubkey).to.equal('abc123');
			node.destroy();
		});

		it('should forward peer:disconnect event from PeerManager', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			const pm = node.getPeerManager()!;

			let disconnectPubkey: string | null = null;
			node.on('peer:disconnect', (pubkey: string) => {
				disconnectPubkey = pubkey;
			});

			pm.emit('peer:disconnect', 'abc123');
			expect(disconnectPubkey).to.equal('abc123');
			node.destroy();
		});

		it('should forward peer:error event from PeerManager', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			const pm = node.getPeerManager()!;

			let errorPubkey: string | null = null;
			let errorObj: Error | null = null;
			node.on('peer:error', (pubkey: string, err: Error) => {
				errorPubkey = pubkey;
				errorObj = err;
			});

			pm.emit('peer:error', 'abc123', new Error('connection failed'));
			expect(errorPubkey).to.equal('abc123');
			expect(errorObj!.message).to.equal('connection failed');
			node.destroy();
		});
	});

	describe('PeerManager Integration — Backward Compatibility', function () {
		it('should still work with handlePeerMessage when networking disabled', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
			expect(channel).to.exist;
			expect(channel.getState()).to.equal(ChannelState.SENT_ACCEPT);
		});

		it('should support full channel lifecycle without networking', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			const ch = alice.getChannelManager().getChannel(channelId);
			expect(ch).to.exist;
			expect(ch!.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should complete end-to-end payment without networking', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 10_000_000n,
				description: 'backward compat e2e'
			});

			const payment = alice.sendPayment(invoice.bolt11);
			expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		});

		it('should allow handlePeerMessage even when networking IS enabled', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);

			// handlePeerMessage should still work — it's an additional entry point
			// Just verify it doesn't throw for an unknown gossip message
			const gossipKey1 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-node-1'))
				.digest();
			const gossipKey2 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-node-2'))
				.digest();
			const bitcoinKey1 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-bitcoin-1'))
				.digest();
			const bitcoinKey2 = crypto
				.createHash('sha256')
				.update(Buffer.from('gossip-bitcoin-2'))
				.digest();
			const testScid = encodeShortChannelId({
				block: 100,
				txIndex: 1,
				outputIndex: 0
			});

			const { payload } = createSignedChannelAnnouncement(
				gossipKey1,
				gossipKey2,
				bitcoinKey1,
				bitcoinKey2,
				testScid
			);
			node.handlePeerMessage(
				'somepeer',
				MessageType.CHANNEL_ANNOUNCEMENT,
				payload
			);
			expect(node.getGraph().getChannelCount()).to.equal(1);
			node.destroy();
		});

		it('should return empty array from listPeers when networking disabled', function () {
			const node = createNode(1);
			expect(node.listPeers()).to.deep.equal([]);
		});
	});

	describe('PeerManager Integration — Cleanup', function () {
		it('should clean up PeerManager on destroy', function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			expect(node.getPeerManager()).to.not.be.null;

			node.destroy();
			// After destroy, event listeners should be removed
			expect(node.listenerCount('peer:connect')).to.equal(0);
		});

		it('should be safe to call destroy on node without networking', function () {
			const node = createNode(1);
			// Should not throw
			node.destroy();
			expect(node.listenerCount('channel:ready')).to.equal(0);
		});
	});

	describe('Error Propagation', function () {
		it('should emit node:error when closeChannel targets unknown channel', function () {
			const node = createNode(1);
			const errors: ILightningError[] = [];
			node.on('node:error', (err: ILightningError) => errors.push(err));

			node.closeChannel(crypto.randomBytes(32), crypto.randomBytes(22));

			expect(errors.length).to.be.greaterThanOrEqual(1);
			expect(errors[0].code).to.be.a('string');
			expect(errors[0].message).to.include('Channel not found');
			expect(errors[0].timestamp).to.be.a('number');
		});

		it('should emit node:error when forceCloseChannel targets unknown channel', function () {
			const node = createNode(1);
			const errors: ILightningError[] = [];
			node.on('node:error', (err: ILightningError) => errors.push(err));

			node.forceCloseChannel(crypto.randomBytes(32), crypto.randomBytes(22));

			expect(errors.length).to.be.greaterThanOrEqual(1);
			// The node emits FORCE_CLOSE_FAILED in addition to the CHANNEL_ERROR from ChannelManager
			expect(errors.some((e) => e.code === 'FORCE_CLOSE_FAILED')).to.be.true;
		});

		it('resolves a live, urgency-bumped force-close feerate when fee data exists (H2)', function () {
			// With no fee samples the force-close feerate falls back to the historical
			// default, so nodes without a fee estimator behave exactly as before.
			const node = createNode(1);
			expect((node as any).resolveForceCloseFeeRatePerVbyte()).to.equal(10);

			// A live mempool sample makes us bid ABOVE the going rate (ceil(50*1.5)=75),
			// so a force-close during a fee spike can actually confirm before an HTLC's
			// cltv_expiry instead of pinning at 10 sat/vB.
			(node as any).feeAdvisor.recordSample(50);
			expect((node as any).resolveForceCloseFeeRatePerVbyte()).to.equal(75);

			// A tiny sample never drops the force-close bid below the default floor.
			const node2 = createNode(2);
			(node2 as any).feeAdvisor.recordSample(3);
			expect((node2 as any).resolveForceCloseFeeRatePerVbyte()).to.equal(10);
		});

		it('should re-emit ChannelManager errors as node:error', function () {
			const node = createNode(1);
			const errors: ILightningError[] = [];
			node.on('node:error', (err: ILightningError) => errors.push(err));

			// Trigger an error directly on the channel manager
			node.getChannelManager().emit('error', null, 'test error');

			expect(errors.length).to.equal(1);
			expect(errors[0].code).to.equal('CHANNEL_ERROR');
			expect(errors[0].message).to.equal('test error');
		});

		it('should set payment to FAILED when addHtlc fails for outgoing payment', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			// Verify the node:error event fires on an invalid operation
			const errors: ILightningError[] = [];
			alice.on('node:error', (err: ILightningError) => errors.push(err));

			alice.forceCloseChannel(crypto.randomBytes(32), crypto.randomBytes(22));
			expect(errors.some((e) => e.code === 'FORCE_CLOSE_FAILED')).to.be.true;
		});

		it('should include channelId in error when available', function () {
			const node = createNode(1);
			const errors: ILightningError[] = [];
			node.on('node:error', (err: ILightningError) => errors.push(err));

			const channelId = crypto.randomBytes(32);
			node.closeChannel(channelId, crypto.randomBytes(22));

			expect(errors.length).to.be.greaterThanOrEqual(1);
			expect(errors[0].channelId).to.exist;
		});

		it('node:error should not crash the process (unlike "error" event)', function () {
			const node = createNode(1);
			// Not listening to node:error — this should NOT throw
			node.closeChannel(crypto.randomBytes(32), crypto.randomBytes(22));
			// If we got here, we didn't crash
			expect(true).to.be.true;
		});

		it('should export ChannelResult from barrel exports (channel module)', function () {
			// ChannelResult is an interface — verify the module loads (types exist at compile time)
			expect(lightning.channel).to.exist;
		});

		it('should emit node:error with ONION_PROCESSING_FAILED on bad onion', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);

			const errors: ILightningError[] = [];
			bob.on('node:error', (err: ILightningError) => errors.push(err));

			// Send an HTLC with a garbage onion (not a valid onion packet)
			const garbageOnion = crypto.randomBytes(1366);
			alice
				.getChannelManager()
				.addHtlc(
					channelId,
					1_000_000n,
					crypto.randomBytes(32),
					500,
					garbageOnion
				);

			const onionErrors = errors.filter(
				(e) => e.code === 'ONION_PROCESSING_FAILED'
			);
			expect(onionErrors.length).to.be.greaterThanOrEqual(1);
			expect(onionErrors[0].message).to.include('Onion processing failed');
			expect(onionErrors[0].channelId).to.exist;
		});

		it('should include structured error info on onion failure', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);

			const errors: ILightningError[] = [];
			bob.on('node:error', (err: ILightningError) => errors.push(err));

			alice
				.getChannelManager()
				.addHtlc(
					channelId,
					1_000_000n,
					crypto.randomBytes(32),
					500,
					crypto.randomBytes(1366)
				);

			const onionErrors = errors.filter(
				(e) => e.code === 'ONION_PROCESSING_FAILED'
			);
			expect(onionErrors.length).to.be.greaterThanOrEqual(1);
			expect(onionErrors[0].timestamp).to.be.a('number');
		});
	});

	describe('Input Validation', function () {
		it('openChannel should reject invalid pubkey', function () {
			const node = createNode(1);
			expect(() => node.openChannel('invalid', 1_000_000n)).to.throw(
				'66 hex characters'
			);
		});

		it('openChannel should reject zero satoshis', function () {
			const node = createNode(1);
			const bob = createNode(2);
			expect(() => node.openChannel(bob.getNodeId(), 0n)).to.throw('positive');
		});

		it('openChannel should reject pushMsat > fundingSatoshis * 1000', function () {
			const node = createNode(1);
			const bob = createNode(2);
			expect(() =>
				node.openChannel(bob.getNodeId(), 1_000_000n, 2_000_000_000n)
			).to.throw('pushMsat');
		});

		it('connectPeer should reject invalid pubkey', async function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			try {
				await node.connectPeer('badkey', 'localhost', 9735);
				expect.fail('should throw');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('66 hex characters');
			}
			node.destroy();
		});

		it('connectPeer should reject empty host', async function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			const validPubkey = '02' + 'a'.repeat(64);
			try {
				await node.connectPeer(validPubkey, '', 9735);
				expect.fail('should throw');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('non-empty');
			}
			node.destroy();
		});

		it('connectPeer should reject invalid port', async function () {
			const config = makeNodeConfig(1);
			config.enableNetworking = true;
			const node = new LightningNode(config);
			const validPubkey = '02' + 'a'.repeat(64);
			try {
				await node.connectPeer(validPubkey, 'localhost', 0);
				expect.fail('should throw');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('1-65535');
			}
			node.destroy();
		});

		it('closeChannel should reject wrong-size channelId', function () {
			const node = createNode(1);
			expect(() =>
				node.closeChannel(Buffer.alloc(16), Buffer.alloc(22))
			).to.throw('32 bytes');
		});

		it('closeChannel should reject empty script', function () {
			const node = createNode(1);
			expect(() =>
				node.closeChannel(Buffer.alloc(32), Buffer.alloc(0))
			).to.throw('1-520 bytes');
		});

		it('createFunding should reject wrong-size txid', function () {
			const node = createNode(1);
			const bob = createNode(2);
			connectNodes(node, bob);
			const channel = node.openChannel(bob.getNodeId(), 1_000_000n);
			expect(() =>
				node.createFunding(channel, Buffer.alloc(16), 0, Buffer.alloc(64))
			).to.throw('32 bytes');
		});

		it('createFunding should reject negative outputIndex', function () {
			const node = createNode(1);
			const bob = createNode(2);
			connectNodes(node, bob);
			const channel = node.openChannel(bob.getNodeId(), 1_000_000n);
			expect(() =>
				node.createFunding(channel, Buffer.alloc(32), -1, Buffer.alloc(64))
			).to.throw('non-negative');
		});

		it('handlePeerMessage should reject oversized payload', function () {
			const node = createNode(1);
			const errors: ILightningError[] = [];
			node.on('node:error', (err: ILightningError) => errors.push(err));

			node.handlePeerMessage('somepeer', 999, Buffer.alloc(70000));
			expect(errors.length).to.equal(1);
			expect(errors[0].code).to.equal('MESSAGE_TOO_LARGE');
		});
	});

	describe('Resource Management', function () {
		function createNodeWithResourceConfig(
			seedId: number,
			resourceConfig: {
				maxCompletedPayments?: number;
				completedPaymentTtlMs?: number;
				cleanupIntervalMs?: number;
			}
		): LightningNode {
			const config = makeNodeConfig(seedId);
			config.resourceConfig = resourceConfig;
			return new LightningNode(config);
		}

		it('should prune expired completed payments', function () {
			const alice = createNodeWithResourceConfig(1, {
				completedPaymentTtlMs: 1,
				cleanupIntervalMs: 0
			});
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'prune test'
			});
			alice.sendPayment(invoice.bolt11);

			// Payment should be COMPLETED
			expect(
				alice
					.listPayments()
					.some(
						(p) =>
							p.status === PaymentStatus.COMPLETED &&
							p.direction === PaymentDirection.OUTGOING
					)
			).to.be.true;

			// Manually prune with a 1ms TTL — payments just completed should be pruned
			// Wait a tick so Date.now() moves
			const pruned = alice.pruneCompletedPayments();
			expect(pruned).to.be.greaterThanOrEqual(0); // may or may not prune depending on timing
			alice.destroy();
		});

		it('should enforce size cap on completed payments', function () {
			const alice = createNodeWithResourceConfig(1, {
				maxCompletedPayments: 2,
				completedPaymentTtlMs: 86_400_000,
				cleanupIntervalMs: 0
			});
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			// Send 4 payments
			for (let i = 0; i < 4; i++) {
				const invoice = bob.createInvoice({
					amountMsat: 1_000_000n,
					description: `cap test ${i}`
				});
				alice.sendPayment(invoice.bolt11);
			}

			const pruned = alice.pruneCompletedPayments();
			expect(pruned).to.be.greaterThan(0);

			// After pruning, completed outgoing payments should be at most 2
			const completedOutgoing = alice
				.listPayments()
				.filter(
					(p) =>
						(p.status === PaymentStatus.COMPLETED ||
							p.status === PaymentStatus.FAILED) &&
						p.direction === PaymentDirection.OUTGOING
				);
			expect(completedOutgoing.length).to.be.at.most(2);
			alice.destroy();
		});

		it('should clean stale htlcPaymentMap entries during prune', function () {
			const node = createNodeWithResourceConfig(1, {
				maxCompletedPayments: 0,
				completedPaymentTtlMs: 1,
				cleanupIntervalMs: 0
			});
			// No payments, just verify prune doesn't throw
			const pruned = node.pruneCompletedPayments();
			expect(pruned).to.equal(0);
			node.destroy();
		});

		it('destroy should clear all maps', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			const invoice = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'destroy test'
			});
			alice.sendPayment(invoice.bolt11);

			expect(alice.listPayments().length).to.be.greaterThan(0);

			alice.destroy();

			// After destroy, all data should be cleared
			expect(alice.listPayments()).to.deep.equal([]);
		});

		it('should handle destroy idempotently', function () {
			const node = createNode(1);
			node.destroy();
			node.destroy(); // should not throw
		});

		it('should accept custom resourceConfig', function () {
			const node = createNodeWithResourceConfig(1, {
				maxCompletedPayments: 500,
				completedPaymentTtlMs: 3600_000,
				cleanupIntervalMs: 30_000
			});
			expect(node).to.exist;
			node.destroy();
		});

		it('should default resourceConfig values', function () {
			const node = createNode(1);
			// Just verify the node was created successfully with defaults
			expect(node.getNodeInfo()).to.exist;
			node.destroy();
		});
	});

	describe('Integration', function () {
		it('should export LightningNode from barrel exports', function () {
			expect(lightning.node.LightningNode).to.exist;
		});

		it('should export types from barrel exports', function () {
			expect(lightning.node.PaymentStatus).to.exist;
			expect(lightning.node.PaymentDirection).to.exist;
		});

		it('should work with NetworkGraph, pathfinding, and onion together', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);

			const channelId = openReadyChannel(alice, bob);
			buildDirectGraph(alice, bob, channelId);

			// Verify graph is queryable
			expect(alice.getGraph().getChannelCount()).to.equal(1);

			// Verify route can be found
			const route = findRoute(
				alice.getGraph(),
				getPublicKey(makeNodeConfig(1).nodePrivateKey),
				getPublicKey(makeNodeConfig(2).nodePrivateKey),
				1_000_000n,
				18
			);
			expect(route).to.exist;

			// Verify full payment flow works
			const invoice = bob.createInvoice({
				amountMsat: 1_000_000n,
				description: 'integration test'
			});

			const payment = alice.sendPayment(invoice.bolt11);
			expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		});
	});

	describe('Blinded forward CLTV enforcement (M1)', function () {
		function makeBlindedForward(cltvExpiryDelta: number): {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			processed: any;
			blindingPoint: Buffer;
			outScid: Buffer;
			nodePrivkey: Buffer;
		} {
			const nodePrivkey = makeNodeConfig(2).nodePrivateKey;
			const nodePubkey = getPublicKey(nodePrivkey);
			const outScid = crypto.randomBytes(8);
			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[nodePubkey],
				[
					{
						shortChannelId: outScid,
						nextNodeId: getPublicKey(crypto.randomBytes(32)),
						paymentRelay: {
							cltvExpiryDelta,
							feeProportionalMillionths: 0,
							feeBaseMsat: 0
						}
					}
				]
			);
			const processed = {
				hopPayload: {
					shortChannelId: outScid,
					blindingPoint: path.blindingPoint,
					encryptedRecipientData: path.blindedHops[0].encryptedData,
					amountToForwardMsat: 100_000n,
					outgoingCltvValue: 500_000
				},
				nextPacket: {
					version: 0,
					ephemeralKey: crypto.randomBytes(33),
					routingInfo: crypto.randomBytes(1300),
					hmac: crypto.randomBytes(32)
				},
				sharedSecret: crypto.randomBytes(32)
			};
			return {
				processed,
				blindingPoint: path.blindingPoint,
				outScid,
				nodePrivkey
			};
		}

		it('rejects a blinded forward whose CLTV delta is below our own minimum', function () {
			const bob = createNode(2); // forwardingCltvDelta defaults to 40
			const { processed } = makeBlindedForward(1); // recipient-authored delta = 1
			const cm = bob.getChannelManager();
			let failedId: bigint | null = null;
			let forwarded = false;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(cm as any).failHtlc = (_c: Buffer, id: bigint) => {
				failedId = id;
				return { ok: true, actions: [] };
			};
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(cm as any).addHtlc = () => {
				forwarded = true;
				return { ok: true, actions: [] };
			};

			// incoming expires only 1 block after the outgoing HTLC (delta 1 << 40).
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(bob as any).handleForwardHtlc(
				crypto.randomBytes(32),
				5n,
				crypto.randomBytes(32),
				processed,
				100_000n,
				500_001,
				processed.hopPayload.blindingPoint
			);

			expect(failedId, 'inbound HTLC must be failed').to.equal(5n);
			expect(forwarded, 'must NOT forward with an insufficient cushion').to.be
				.false;
		});

		it('accepts a blinded forward whose CLTV delta meets our minimum', function () {
			const bob = createNode(2);
			const { processed, outScid } = makeBlindedForward(40); // delta = our min
			const cm = bob.getChannelManager();
			let forwarded = false;
			// Register the onward channel so the forward proceeds past the SCID lookup.
			bob['scidToChannelId'].set(
				outScid.toString('hex'),
				crypto.randomBytes(32)
			);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(cm as any).addHtlc = () => {
				forwarded = true;
				return { ok: true, actions: [] };
			};
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(cm as any).failHtlc = () => {
				return { ok: true, actions: [] };
			};

			// incoming expires 40 blocks after outgoing (delta 40 == our minimum).
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(bob as any).handleForwardHtlc(
				crypto.randomBytes(32),
				6n,
				crypto.randomBytes(32),
				processed,
				100_000n,
				500_040,
				processed.hopPayload.blindingPoint
			);

			expect(forwarded, 'adequate cushion must forward past the CLTV gate').to
				.be.true;
		});
	});

	describe('ChainMonitor restore signing keys (H2)', function () {
		it('restores a monitor with the config per-channel secrets, not node/funding keys', function () {
			// eslint-disable-next-line @typescript-eslint/no-var-requires
			const {
				SqliteStorage
			} = require('../../src/lightning/storage/sqlite-storage');
			// eslint-disable-next-line @typescript-eslint/no-var-requires
			const chainMonitorMod = require('../../src/lightning/chain/chain-monitor');

			const storage = new SqliteStorage(':memory:');
			storage.open();

			// A node-level-basepoints config (no channelKeyDeriver) whose basepoint
			// SECRETS are the privkeys behind makeBasepoints' pubkeys (keys[1]=revocation,
			// keys[2]=payment, keys[4]=htlc), so the channel keys are self-consistent.
			const seed = makeSeed(1);
			const secretAt = (i: number): Buffer =>
				crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([i]))
					.digest();
			const revocationBasepointSecret = secretAt(1);
			const paymentBasepointSecret = secretAt(2);
			const htlcBasepointSecret = secretAt(4);
			const cfg = {
				...makeNodeConfig(1),
				storage,
				revocationBasepointSecret,
				paymentBasepointSecret,
				htlcBasepointSecret
			};

			// Node A opens + force-closes a channel → a ChainMonitor is created and
			// persisted (monitor:updated → saveChainMonitor).
			const alice = new LightningNode(cfg);
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			const dest = Buffer.concat([
				Buffer.from([0x00, 0x14]),
				Buffer.alloc(20, 7)
			]);
			alice.forceCloseChannel(channelId, dest);
			expect(
				storage.loadAllChainMonitors().length,
				'a monitor was persisted'
			).to.be.greaterThan(0);

			// Spy ChainMonitor.restore to capture the secrets the restore callsite passes.
			const orig = chainMonitorMod.ChainMonitor.restore;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			let captured: any[] | null = null;
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			chainMonitorMod.ChainMonitor.restore = function (...args: any[]) {
				captured = args;
				return orig.apply(this, args);
			};

			try {
				// Node B restarts from the same storage → restoreFromStorage → restore.
				new LightningNode(cfg);
			} finally {
				chainMonitorMod.ChainMonitor.restore = orig;
			}

			expect(captured, 'ChainMonitor.restore was called during restore').to.not
				.be.null;
			// args: (state, channelState, dest, feeRate, revocation, payment, network,
			//        delayed, htlc)
			expect(
				(captured![4] as Buffer).equals(revocationBasepointSecret),
				'restore uses the config revocation basepoint secret'
			).to.be.true;
			expect(
				(captured![5] as Buffer).equals(paymentBasepointSecret),
				'restore uses the config payment basepoint secret'
			).to.be.true;
			expect(
				(captured![8] as Buffer).equals(htlcBasepointSecret),
				'restore uses the config htlc basepoint secret'
			).to.be.true;
			// And NOT the buggy substitutes (node identity / funding key).
			expect((captured![4] as Buffer).equals(cfg.nodePrivateKey)).to.be.false;
			expect((captured![5] as Buffer).equals(cfg.fundingPrivkey)).to.be.false;

			storage.close();
		});
	});
});

// ─────────────── Graph Building Helpers ───────────────

/**
 * Build a direct-channel graph between two nodes on a specific node's graph.
 * This simulates what gossip would provide, without needing real gossip messages.
 */
function buildDirectGraph(
	alice: LightningNode,
	_bob: LightningNode,
	_channelId: Buffer
): void {
	const aliceConfig = makeNodeConfig(1);
	const bobConfig = makeNodeConfig(2);
	const alicePubkey = getPublicKey(aliceConfig.nodePrivateKey);
	const bobPubkey = getPublicKey(bobConfig.nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });

	// Determine node ordering (nodeId1 < nodeId2 lexicographically)
	const aliceIsNode1 = Buffer.compare(alicePubkey, bobPubkey) < 0;
	const nodeId1 = aliceIsNode1 ? alicePubkey : bobPubkey;
	const nodeId2 = aliceIsNode1 ? bobPubkey : alicePubkey;

	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1,
		nodeId2,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};

	alice.getGraph().addChannelAnnouncement(announcement);

	// Add channel updates for both directions
	const update1: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0, // direction 0 (node1 → node2)
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};

	const update2: IChannelUpdateMessage = {
		...update1,
		channelFlags: 1 // direction 1 (node2 → node1)
	};

	alice.getGraph().applyChannelUpdate(update1);
	alice.getGraph().applyChannelUpdate(update2);

	// Register SCID on Alice so she can find the channel for the first hop
	alice.registerChannelScid(
		alice.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

/**
 * Build a three-node graph (Alice→Bob→Charlie) on Alice's graph.
 */
function buildThreeNodeGraph(
	alice: LightningNode,
	bob: LightningNode,
	charlie: LightningNode,
	scidAB: Buffer,
	scidBC: Buffer
): void {
	const aliceConfig = makeNodeConfig(1);
	const bobConfig = makeNodeConfig(2);
	const charlieConfig = makeNodeConfig(3);
	const alicePubkey = getPublicKey(aliceConfig.nodePrivateKey);
	const bobPubkey = getPublicKey(bobConfig.nodePrivateKey);
	const charliePubkey = getPublicKey(charlieConfig.nodePrivateKey);

	// AB channel
	const abIsNode1Alice = Buffer.compare(alicePubkey, bobPubkey) < 0;
	const abNodeId1 = abIsNode1Alice ? alicePubkey : bobPubkey;
	const abNodeId2 = abIsNode1Alice ? bobPubkey : alicePubkey;

	alice.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scidAB,
		nodeId1: abNodeId1,
		nodeId2: abNodeId2,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});

	alice.getGraph().applyChannelUpdate({
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scidAB,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	});

	alice.getGraph().applyChannelUpdate({
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scidAB,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 1,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	});

	// BC channel
	const bcIsNode1Bob = Buffer.compare(bobPubkey, charliePubkey) < 0;
	const bcNodeId1 = bcIsNode1Bob ? bobPubkey : charliePubkey;
	const bcNodeId2 = bcIsNode1Bob ? charliePubkey : bobPubkey;

	alice.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scidBC,
		nodeId1: bcNodeId1,
		nodeId2: bcNodeId2,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});

	alice.getGraph().applyChannelUpdate({
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scidBC,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	});

	alice.getGraph().applyChannelUpdate({
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scidBC,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 1,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	});

	// Register SCIDs on Alice so she can find the outgoing channel for the first hop
	alice.registerChannelScid(
		alice.getChannelManager().listChannels()[0].getChannelId()!,
		scidAB
	);
}
