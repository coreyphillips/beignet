import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`agent-review-seed-${id}`))
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

function createNode(seedId: number): LightningNode {
	return new LightningNode(makeNodeConfig(seedId));
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

describe('Agent Review: Routing Hints', () => {
	it('should include a hint even for fully-announced public channels', () => {
		// A freshly-announced public channel often hasn't propagated to the payer's
		// gossip view yet, so we include a hint regardless of announcement status —
		// otherwise the invoice is unpayable until gossip catches up.
		const alice = createNode(301);
		const bob = createNode(302);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		// Alice's channel defaults to announceChannel=true (initiator default)
		const channels = alice.getChannelManager().listChannels();
		const ch = channels.find((c) => c.getChannelId()?.equals(channelId));
		expect(ch).to.exist;
		const state = ch!.getFullState();
		expect(state.announceChannel).to.be.true;
		// Mark it FULLY ANNOUNCED — we still emit a hint for reliability.
		(state as any).announcementSigsSent = true;
		(state as any).announcementSigsReceived = true;
		(state as any).shortChannelId = Buffer.from('0000010000010001', 'hex');

		const inv = alice.createInvoice({ description: 'test', amountMsat: 1000n });
		const decoded = decodeInvoice(inv.bolt11);
		expect(decoded.routingHints).to.exist;
		expect(decoded.routingHints!.length).to.equal(1);
		expect(decoded.routingHints![0][0].pubkey.toString('hex')).to.equal(
			bob.getNodeId()
		);
	});

	it('should include private (unannounced) channels in routing hints', () => {
		const alice = createNode(303);
		const bob = createNode(304);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		// Make it a private channel
		const channels = alice.getChannelManager().listChannels();
		const ch = channels.find((c) => c.getChannelId()?.equals(channelId));
		(ch!.getFullState() as any).announceChannel = false;

		// Assign a SCID so the routing hint can be generated
		(ch!.getFullState() as any).shortChannelId = Buffer.from(
			'0000010000010001',
			'hex'
		);

		const inv = alice.createInvoice({ description: 'test', amountMsat: 1000n });
		const decoded = decodeInvoice(inv.bolt11);
		expect(decoded.routingHints).to.exist;
		expect(decoded.routingHints!.length).to.be.greaterThan(0);
	});

	it('should include hints for both public (announced) and private channels', () => {
		const alice = createNode(305);
		const bob = createNode(306);
		const carol = createNode(307);
		connectNodes(alice, bob);
		connectNodes(alice, carol);

		// Open two channels
		const publicChannelId = openReadyChannel(alice, bob, 1_000_000n);
		const privateChannelId = openReadyChannel(alice, carol, 500_000n);

		const channels = alice.getChannelManager().listChannels();

		// Public channel — announceChannel=true (default for initiator), fully announced.
		const pubCh = channels.find(
			(c) => c.getChannelId()?.equals(publicChannelId)
		);
		expect(pubCh!.getFullState().announceChannel).to.be.true;
		(pubCh!.getFullState() as any).announcementSigsSent = true;
		(pubCh!.getFullState() as any).announcementSigsReceived = true;
		(pubCh!.getFullState() as any).shortChannelId = Buffer.from(
			'0000010000010001',
			'hex'
		);

		// Private channel — set announceChannel=false
		const privCh = channels.find(
			(c) => c.getChannelId()?.equals(privateChannelId)
		);
		(privCh!.getFullState() as any).announceChannel = false;
		(privCh!.getFullState() as any).shortChannelId = Buffer.from(
			'0000020000010001',
			'hex'
		);

		const inv = alice.createInvoice({ description: 'test', amountMsat: 1000n });
		const decoded = decodeInvoice(inv.bolt11);

		// Both channels produce a hint now (public hints guard against gossip lag).
		expect(decoded.routingHints).to.exist;
		expect(decoded.routingHints!.length).to.equal(2);
		const hintPeers = decoded.routingHints!.map((h) =>
			h[0].pubkey.toString('hex')
		);
		expect(hintPeers).to.include.members([bob.getNodeId(), carol.getNodeId()]);
	});

	it("should use the PEER's alias for private channels without confirmed SCID", () => {
		// BOLT 2: the sender of an alias in channel_ready "MUST always recognize the
		// alias as a short_channel_id for incoming HTLCs", so the peer resolves the
		// alias IT generated, which we store as remoteScidAlias. Our own scidAlias
		// is what WE resolve, so a hint naming it points at nothing the peer must
		// honour. The two are set to different values here so the direction is
		// actually proven rather than coincidentally satisfied.
		const alice = createNode(308);
		const bob = createNode(309);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		const channels = alice.getChannelManager().listChannels();
		const ch = channels.find((c) => c.getChannelId()?.equals(channelId));
		const state = ch!.getFullState() as any;
		state.announceChannel = false;
		state.shortChannelId = null;
		state.scidAlias = Buffer.from('00000a0000050003', 'hex');
		state.remoteScidAlias = Buffer.from('00000b0000060004', 'hex');

		const inv = alice.createInvoice({ description: 'test', amountMsat: 1000n });
		const decoded = decodeInvoice(inv.bolt11);
		expect(decoded.routingHints).to.exist;
		expect(decoded.routingHints!.length).to.equal(1);
		expect(decoded.routingHints![0][0].shortChannelId.toString('hex')).to.equal(
			'00000b0000060004'
		);
	});

	it("uses the peer's published policy (fee/CLTV) for the hint when the channel is public", () => {
		// The peer is the forwarding node for the [peer → us] hop, so the hint must
		// advertise the peer's REAL policy (from gossip), not our own forwarding
		// defaults — otherwise the peer rejects the HTLC (incorrect_cltv_expiry / fee).
		const alice = createNode(311);
		const bob = createNode(312);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		const ch = alice
			.getChannelManager()
			.listChannels()
			.find((c) => c.getChannelId()?.equals(channelId))!;
		const scid = Buffer.from('0000010000010001', 'hex');
		(ch.getFullState() as any).shortChannelId = scid;

		// Inject bob's published policy into alice's graph with distinctive values.
		const bobPub = Buffer.from(bob.getNodeId(), 'hex');
		const alicePub = Buffer.from(alice.getNodeId(), 'hex');
		const bobIsNode1 = Buffer.compare(bobPub, alicePub) < 0;
		const [n1, n2] = bobIsNode1 ? [bobPub, alicePub] : [alicePub, bobPub];
		const bobUpdate = {
			cltvExpiryDelta: 80,
			feeBaseMsat: 1234,
			feeProportionalMillionths: 5
		};
		(alice.getGraph() as any)._channels.set(scid.toString('hex'), {
			shortChannelId: scid,
			nodeId1: n1,
			nodeId2: n2,
			update1: bobIsNode1 ? bobUpdate : undefined,
			update2: bobIsNode1 ? undefined : bobUpdate
		});

		const inv = alice.createInvoice({ description: 'test', amountMsat: 1000n });
		const hop = decodeInvoice(inv.bolt11).routingHints![0][0];
		expect(hop.pubkey.toString('hex')).to.equal(bob.getNodeId());
		expect(hop.cltvExpiryDelta).to.equal(80);
		expect(hop.feeBaseMsat).to.equal(1234);
		expect(hop.feeProportionalMillionths).to.equal(5);
		alice.destroy();
		bob.destroy();
	});
});

describe('Agent Review: Channel Info', () => {
	it('should expose isPrivate=false for announced channels', () => {
		const alice = createNode(310);
		const bob = createNode(311);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob);

		const channels = alice.listChannels();
		expect(channels.length).to.be.greaterThan(0);
		expect(channels[0].isPrivate).to.be.false;
	});

	it('should expose isPrivate=true for unannounced channels', () => {
		const alice = createNode(312);
		const bob = createNode(313);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		// Set to private
		const mgr = alice.getChannelManager();
		const ch = mgr
			.listChannels()
			.find((c) => c.getChannelId()?.equals(channelId))!;
		(ch.getFullState() as any).announceChannel = false;

		const channels = alice.listChannels();
		const info = channels.find((c) => c.channelId.equals(channelId));
		expect(info).to.exist;
		expect(info!.isPrivate).to.be.true;
	});

	it('should expose localReserveMsat and remoteReserveMsat', () => {
		const alice = createNode(314);
		const bob = createNode(315);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob);

		const channels = alice.listChannels();
		expect(channels.length).to.be.greaterThan(0);
		const info = channels[0];
		// Reserves should be populated (default 10_000 sats = 10_000_000 msat)
		expect(info.localReserveMsat).to.exist;
		expect(info.localReserveMsat).to.be.a('bigint');
		expect(info.remoteReserveMsat).to.exist;
		expect(info.remoteReserveMsat).to.be.a('bigint');
	});
});

describe('Agent Review: descriptionHash Invoice', () => {
	it('should create invoice with descriptionHash', () => {
		const alice = createNode(316);
		const longDescription =
			'This is a very long structured metadata blob from an AI agent';
		const descHash = crypto
			.createHash('sha256')
			.update(longDescription)
			.digest();

		const result = alice.createInvoice({
			descriptionHash: descHash,
			amountMsat: 50000n
		});
		expect(result.bolt11).to.be.a('string');

		const decoded = decodeInvoice(result.bolt11);
		expect(decoded.description).to.be.undefined;
		expect(decoded.descriptionHash).to.exist;
		expect(decoded.descriptionHash!.equals(descHash)).to.be.true;
	});

	it('should reject invoice with both description and descriptionHash', () => {
		const alice = createNode(317);
		const descHash = crypto.randomBytes(32);

		expect(() => {
			alice.createInvoice({
				description: 'test',
				descriptionHash: descHash,
				amountMsat: 1000n
			});
		}).to.throw('Cannot specify both description and descriptionHash');
	});

	it('should reject invoice with neither description nor descriptionHash', () => {
		const alice = createNode(318);

		expect(() => {
			alice.createInvoice({ amountMsat: 1000n });
		}).to.throw('Must specify either description or descriptionHash');
	});
});

describe('Agent Review: Force Close Txid', () => {
	it('should return commitmentTxid on force close', () => {
		const alice = createNode(319);
		const bob = createNode(320);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		const destinationScript = Buffer.alloc(22);
		destinationScript[0] = 0x00; // witness version
		destinationScript[1] = 0x14; // push 20 bytes
		crypto.randomBytes(20).copy(destinationScript, 2);

		const result = alice.forceCloseChannel(channelId, destinationScript);
		expect(result.ok).to.be.true;
		expect(result.commitmentTxid).to.be.a('string');
		expect(result.commitmentTxid!.length).to.equal(64);
		// Verify it's a valid hex string
		expect(/^[0-9a-f]{64}$/.test(result.commitmentTxid!)).to.be.true;
	});

	it('should return ok:false for invalid channel', () => {
		const alice = createNode(321);
		const fakeChannelId = crypto.randomBytes(32);
		const destinationScript = Buffer.alloc(22);

		const result = alice.forceCloseChannel(fakeChannelId, destinationScript);
		expect(result.ok).to.be.false;
		expect(result.commitmentTxid).to.be.undefined;
	});
});
