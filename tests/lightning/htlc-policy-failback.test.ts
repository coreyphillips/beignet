/**
 * Issues 410/411: OUR-policy refusals of update_add_htlc cost one HTLC, not
 * the channel, and dispositions defer while the channel is quiescing.
 *
 * BOLT 2 ("Bounding exposure to trimmed in-flight HTLCs"): the receiver of an
 * HTLC that pushes dust exposure over the ceiling SHOULD fail it once it's
 * committed and SHOULD NOT reveal a preimage. The far-future CLTV horizon is
 * our policy with the same shape (expiry_too_far). Both formerly failed the
 * whole channel with a wire error.
 *
 * The quiescence interlock: "MUST NOT send an update message after stfu", so
 * an add that crossed our own stfu commits while we are quiescing and its
 * disposition (fulfill, fail, fail-back) is parked until quiescence ends.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { QuiescenceState } from '../../src/lightning/channel/quiescence';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	TEMPORARY_CHANNEL_FAILURE,
	EXPIRY_TOO_FAR
} from '../../src/lightning/onion/types';
import { MessageType } from '../../src/lightning/message/types';

// ─────────────── Harness (mirrors hold-invoices.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`policy-failback-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
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
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest()
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
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

function buildGraph(
	alice: LightningNode,
	bob: LightningNode,
	channelIds: Buffer[]
): void {
	const alicePubkey = Buffer.from(alice.getNodeId(), 'hex');
	const bobPubkey = Buffer.from(bob.getNodeId(), 'hex');
	const aliceIsNode1 = Buffer.compare(alicePubkey, bobPubkey) < 0;
	const nodeId1 = aliceIsNode1 ? alicePubkey : bobPubkey;
	const nodeId2 = aliceIsNode1 ? bobPubkey : alicePubkey;

	channelIds.forEach((channelId, i) => {
		const scid = encodeShortChannelId({
			block: 500,
			txIndex: i + 1,
			outputIndex: 0
		});
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
		const update1: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: 0,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		};
		alice.getGraph().applyChannelUpdate(update1);
		alice.getGraph().applyChannelUpdate({ ...update1, channelFlags: 1 });
		alice.registerChannelScid(channelId, scid);
	});
}

function settleTicks(rounds = 6): Promise<void> {
	return (async () => {
		for (let i = 0; i < rounds; i++) {
			await new Promise<void>((resolve) => setImmediate(resolve));
		}
	})();
}

describe('Policy fail-backs and quiescence parking (issues 410/411)', function () {
	this.timeout(20_000);

	it('fails a dust-exposure breach back with temporary_channel_failure, not the channel', function () {
		const alice = createNode(1);
		const bob = createNode(2);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		// A conformant sender's own outbound dust cap fires before the
		// receiver's ceiling ever can, so simulate a peer that does not share
		// our policy: disable ALICE's local dust classification only. Bob's
		// side still computes honestly.
		const aliceChannel = alice.getChannelManager().getChannel(channelId)!;
		(aliceChannel as unknown as { _isDustHtlc: () => boolean })._isDustHtlc =
			() => false;

		// 14 x 350_000 msat parked hold-invoice HTLCs = 4_900_000 msat of
		// in-flight dust, under the 5_000_000 ceiling.
		const dustAmount = 350_000n;
		for (let i = 0; i < 14; i++) {
			const preimage = crypto.randomBytes(32);
			const hash = crypto.createHash('sha256').update(preimage).digest();
			const inv = bob.createInvoice({
				amountMsat: dustAmount,
				description: `dust-${i}`,
				hold: true,
				paymentHash: hash
			});
			alice.sendPayment(inv.bolt11);
			expect(
				alice.getPayment(hash)!.status,
				`hold payment ${i} parked`
			).to.equal(PaymentStatus.PENDING);
		}
		expect(bob.listHeldHtlcs()).to.have.length(14);

		// The 15th dust HTLC pushes exposure to 5_250_000 msat. BOLT 2: fail
		// it once committed, reveal no preimage, keep the channel.
		const inv15 = bob.createInvoice({
			amountMsat: dustAmount,
			description: 'dust-over'
		});
		alice.sendPayment(inv15.bolt11);

		const failed = alice.getPayment(inv15.paymentHash)!;
		expect(failed.status).to.equal(PaymentStatus.FAILED);
		expect(failed.failureCode).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(bob.getPayment(inv15.paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(bob.listHeldHtlcs(), 'prior holds untouched').to.have.length(14);

		const bobChannel = bob.getChannelManager().getChannel(channelId)!;
		expect(bobChannel.getState(), 'the channel survives').to.equal(
			ChannelState.NORMAL
		);

		// A non-dust payment on the same channel still settles.
		const invBig = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'non-dust'
		});
		alice.sendPayment(invBig.bolt11);
		expect(alice.getPayment(invBig.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('fails a far-future CLTV back with expiry_too_far, not the channel', function () {
		const alice = createNode(3);
		const bob = createNode(4);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);

		// Our own payer caps a route's total CLTV at 2016 blocks, so a
		// conformant sender can never build an expiry 5040 past the
		// receiver's height. The horizon defends against a sender whose
		// expiry sits unreasonably far beyond OUR view of the chain, which is
		// exactly a height skew: Alice builds absolute expiries from her tip,
		// Bob's tip is far behind it.
		alice.handleNewBlock(6_000);
		bob.handleNewBlock(500);

		const invFar = bob.createInvoice({
			amountMsat: 1_000_000n,
			description: 'expiry-too-far'
		});
		alice.sendPayment(invFar.bolt11);

		const failed = alice.getPayment(invFar.paymentHash)!;
		expect(failed.status).to.equal(PaymentStatus.FAILED);
		expect(failed.failureCode).to.equal(EXPIRY_TOO_FAR);

		const bobChannel = bob.getChannelManager().getChannel(channelId)!;
		expect(bobChannel.getState(), 'the channel survives').to.equal(
			ChannelState.NORMAL
		);

		// With the views level again, the same channel still settles.
		bob.handleNewBlock(6_000);
		const invOk = bob.createInvoice({
			amountMsat: 1_000_000n,
			description: 'expiry-fine'
		});
		alice.sendPayment(invOk.bolt11);
		expect(alice.getPayment(invOk.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('parks the disposition of an add that crossed our stfu and settles it after reestablish', async function () {
		const alice = createNode(5);
		const bob = createNode(6);

		// Loopback with a cut switch, a reestablish gate, and an stfu drop so
		// Bob's handshake never completes (Alice never learns of it).
		const cut = { val: false };
		const gate = { hold: false, queue: [] as Array<() => void> };
		const route = (from: LightningNode, to: LightningNode): void => {
			from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
				if (cut.val) return;
				if (pk !== to.getNodeId()) return;
				if (t === MessageType.STFU) return;
				if (gate.hold) {
					gate.queue.push(() => to.handlePeerMessage(from.getNodeId(), t, p));
					return;
				}
				to.handlePeerMessage(from.getNodeId(), t, p);
			});
		};
		route(alice, bob);
		route(bob, alice);

		const channelId = openReadyChannel(alice, bob);
		buildGraph(alice, bob, [channelId]);
		const bobChannel = bob.getChannelManager().getChannel(channelId)!;

		// Bob quiesces; the stfu is dropped, so Alice keeps sending.
		expect(bob.getChannelManager().initiateQuiescence(channelId).ok).to.be.true;
		expect(bobChannel.getQuiescenceState()).to.equal(QuiescenceState.SENT_STFU);

		// The crossing add commits while Bob quiesces: Bob must not send any
		// update message, so the settle is parked and the payer stays PENDING.
		const inv = bob.createInvoice({
			amountMsat: 1_000_000n,
			description: 'crossing'
		});
		alice.sendPayment(inv.bolt11);
		expect(alice.getPayment(inv.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(bobChannel.getQuiescenceState()).to.equal(QuiescenceState.SENT_STFU);

		// The quiescence watchdog's remedy is a disconnect. Cycle the
		// connection: quiescence dies with it, reestablish resumes the
		// channel, and the parked disposition drains.
		cut.val = true;
		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		await settleTicks();
		cut.val = false;
		gate.hold = true;
		alice.getChannelManager().handlePeerReconnected(bob.getNodeId());
		bob.getChannelManager().handlePeerReconnected(alice.getNodeId());
		while (gate.queue.length > 0) {
			gate.queue.shift()!();
		}
		gate.hold = false;
		await settleTicks();

		expect(bobChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(bobChannel.getQuiescenceState()).to.equal(QuiescenceState.NORMAL);
		expect(
			alice.getPayment(inv.paymentHash)!.status,
			'the parked settle drained after reestablish'
		).to.equal(PaymentStatus.COMPLETED);
	});
});
