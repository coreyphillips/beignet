/**
 * Hold invoice end-to-end tests over the two-node loopback harness.
 *
 * Covers the M4 user API surface semantics at the library level:
 * park on pay (payer stays PENDING), settle-with-preimage, cancel,
 * wrong-preimage rejection, MPP parts parking/settling together,
 * restart persistence of parked HTLCs, and the CLTV-safety auto-cancel
 * (a parked HTLC must never ride into its on-chain timeout).
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
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

// ─────────────── Harness (mirrors node.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`hold-invoice-seed-${id}`))
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

function makeNodeConfig(seedId: number, storage?: SqliteStorage): INodeConfig {
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
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	const config: INodeConfig = {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret
	};
	if (storage) config.storage = storage;
	return config;
}

function createNode(seedId: number, storage?: SqliteStorage): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage));
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

/**
 * Publish direct alice->bob channels on Alice's graph (one per channelId)
 * and register the SCIDs so she can dispatch over them.
 */
function buildGraph(
	alice: LightningNode,
	bob: LightningNode,
	channelIds: Buffer[],
	htlcMaximumMsat = 1_000_000_000n
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
			htlcMaximumMsat
		};
		alice.getGraph().applyChannelUpdate(update1);
		alice.getGraph().applyChannelUpdate({ ...update1, channelFlags: 1 });

		alice.registerChannelScid(channelId, scid);
	});
}

function makeExternalHash(): { preimage: Buffer; hash: Buffer } {
	const preimage = crypto.randomBytes(32);
	const hash = crypto.createHash('sha256').update(preimage).digest();
	return { preimage, hash };
}

/** cltv_expiry of the (single) received HTLC parked on the receiver. */
function parkedCltvExpiry(bob: LightningNode, channelId: Buffer): number {
	const state = bob.getChannelManager().getChannel(channelId)!.getFullState();
	for (const [key, htlc] of state.htlcs) {
		if (key.startsWith('received-')) return htlc.cltvExpiry;
	}
	throw new Error('no received HTLC on channel');
}

// ─────────────── Tests ───────────────

describe('Hold Invoices (M4 batch 1)', function () {
	describe('park / settle / cancel with a caller-supplied hash', function () {
		it('parks the HTLC (payer PENDING), settles with the preimage (payer COMPLETED)', function () {
			const alice = createNode(1);
			const bob = createNode(2);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const { preimage, hash } = makeExternalHash();
			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-flow',
				hold: true,
				paymentHash: hash
			});
			expect(invoice.paymentHash).to.deep.equal(hash);
			expect(bob.listHoldInvoices()).to.have.length(1);
			expect(bob.listHoldInvoices()[0].state).to.equal('OPEN');

			alice.sendPayment(invoice.bolt11);

			// Parked, not settled: both sides still PENDING.
			expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
			expect(bob.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
			expect(bob.listHeldHtlcs()).to.have.length(1);
			const held = bob.listHoldInvoices()[0];
			expect(held.state).to.equal('ACCEPTED');
			expect(held.heldAmountMsat).to.equal(5_000_000n);
			expect(held.htlcCount).to.equal(1);

			// Wrong preimage is rejected and nothing is released.
			expect(() => bob.settleHeldHtlc(hash, crypto.randomBytes(32))).to.throw(
				/preimage does not match/
			);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			// Correct preimage settles every parked HTLC.
			expect(bob.settleHeldHtlc(hash, preimage)).to.be.true;
			expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.COMPLETED);
			expect(alice.getPayment(hash)!.preimage).to.deep.equal(preimage);
			expect(bob.getPayment(hash)!.status).to.equal(PaymentStatus.COMPLETED);
			expect(bob.listHeldHtlcs()).to.have.length(0);
			expect(bob.listHoldInvoices()[0].state).to.equal('SETTLED');
		});

		it('cancels a parked HTLC: payer fails, invoice is CANCELLED', function () {
			const alice = createNode(3);
			const bob = createNode(4);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const { hash } = makeExternalHash();
			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-cancel',
				hold: true,
				paymentHash: hash
			});

			alice.sendPayment(invoice.bolt11);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			const result = bob.cancelHoldInvoice(hash);
			expect(result).to.deep.equal({ htlcsFailed: 1 });
			expect(bob.listHeldHtlcs()).to.have.length(0);
			expect(bob.listHoldInvoices()[0].state).to.equal('CANCELLED');
			expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);
			expect(bob.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);
		});

		it('cancels an unpaid hold invoice; a later payment attempt fails', function () {
			const alice = createNode(5);
			const bob = createNode(6);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const { hash } = makeExternalHash();
			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-cancel-early',
				hold: true,
				paymentHash: hash
			});

			expect(bob.cancelHoldInvoice(hash)).to.deep.equal({ htlcsFailed: 0 });
			expect(bob.listHoldInvoices()[0].state).to.equal('CANCELLED');
			// Cancelling again reports nothing to cancel.
			expect(bob.cancelHoldInvoice(hash)).to.equal(null);

			// The HTLC is failed on arrival instead of parking.
			alice.sendPayment(invoice.bolt11);
			expect(bob.listHeldHtlcs()).to.have.length(0);
			expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);
		});
	});

	describe('MPP', function () {
		it('parks all MPP parts and settles them together', function () {
			// The payer-side auto-split cannot be capacity-forced in this direct
			// two-node harness (the invoice's own routing hints advertise
			// unbounded capacity, so single-path always wins pathfinding; the
			// auto-split machinery is covered by mpp-sending.test.ts). Dispatch
			// two explicit parts instead: same hash/secret, totalMsat above each
			// part, exercising the real BOLT 4 MPP receive path on the holder.
			const alice = createNode(7);
			const bob = createNode(8);
			connectNodes(alice, bob);
			const ch1 = openReadyChannel(alice, bob, 100_000n);
			const ch2 = openReadyChannel(alice, bob, 100_000n);
			buildGraph(alice, bob, [ch1, ch2], 100_000_000n);

			const { preimage, hash } = makeExternalHash();
			const totalMsat = 90_000_000n;
			const invoice = bob.createInvoice({
				amountMsat: totalMsat,
				description: 'hold-mpp',
				hold: true,
				paymentHash: hash
			});
			const paymentSecret = invoice.paymentSecret;
			const bobPubkey = Buffer.from(bob.getNodeId(), 'hex');

			[ch1, ch2].forEach((_channelId, i) => {
				const scid = encodeShortChannelId({
					block: 500,
					txIndex: i + 1,
					outputIndex: 0
				});
				alice.sendPaymentToRoute(
					{
						hops: [
							{
								pubkey: bobPubkey,
								shortChannelId: scid,
								amountToForwardMsat: totalMsat / 2n,
								outgoingCltvValue: 40
							}
						]
					},
					hash,
					40,
					paymentSecret,
					totalMsat
				);
			});

			const held = bob.listHoldInvoices()[0];
			expect(held.state).to.equal('ACCEPTED');
			expect(held.htlcCount).to.equal(2);
			expect(held.heldAmountMsat).to.equal(totalMsat);
			expect(bob.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);
			expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.PENDING);

			// One settle call releases every part.
			expect(bob.settleHeldHtlc(hash, preimage)).to.be.true;
			expect(bob.listHeldHtlcs()).to.have.length(0);
			expect(bob.getPayment(hash)!.status).to.equal(PaymentStatus.COMPLETED);
			expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.COMPLETED);
			expect(bob.listHoldInvoices()[0].state).to.equal('SETTLED');

			// Both HTLCs are fulfilled on their channels (no lingering parts).
			for (const ch of [ch1, ch2]) {
				const st = bob.getChannelManager().getChannel(ch)!.getFullState();
				for (const [key, htlc] of st.htlcs) {
					if (key.startsWith('received-')) {
						expect(htlc.state).to.not.equal('COMMITTED');
					}
				}
			}
		});
	});

	describe('restart persistence', function () {
		it('parked HTLCs and the hold flag survive a reload from storage', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const alice = createNode(9);
			const bob = createNode(10, storage);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const { hash } = makeExternalHash();
			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-restart',
				hold: true,
				paymentHash: hash
			});
			alice.sendPayment(invoice.bolt11);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			// Reload a fresh node from the same storage: the HTLC is still parked
			// and the hash is still armed for parking (heldInvoiceHashes rebuilt).
			const bob2 = createNode(10, storage);
			expect(bob2.listHeldHtlcs()).to.have.length(1);
			expect(bob2.listHeldHtlcs()[0].paymentHash).to.deep.equal(hash);
			expect(bob2.listHeldHtlcs()[0].amountMsat).to.equal(5_000_000n);
			const held = bob2.listHoldInvoices();
			expect(held).to.have.length(1);
			expect(held[0].state).to.equal('ACCEPTED');
			storage.close();
		});

		it('a cancelled hold invoice stays cancelled after reload', function () {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const alice = createNode(11);
			const bob = createNode(12, storage);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const { hash } = makeExternalHash();
			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-cancel-restart',
				hold: true,
				paymentHash: hash
			});
			alice.sendPayment(invoice.bolt11);
			expect(bob.cancelHoldInvoice(hash)).to.deep.equal({ htlcsFailed: 1 });

			const bob2 = createNode(12, storage);
			expect(bob2.listHeldHtlcs()).to.have.length(0);
			const held = bob2.listHoldInvoices();
			expect(held).to.have.length(1);
			expect(held[0].state).to.equal('CANCELLED');
			// Not re-armed: cancelling again reports nothing to cancel.
			expect(bob2.cancelHoldInvoice(hash)).to.equal(null);
			storage.close();
		});
	});

	describe('CLTV-safety auto-cancel', function () {
		it('fails a parked HTLC off-chain before its expiry margin', function () {
			const alice = createNode(13);
			const bob = createNode(14);
			connectNodes(alice, bob);
			// Anchor block heights so HTLC CLTVs are comfortably above zero.
			alice.handleNewBlock(1000);
			bob.handleNewBlock(1000);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const { hash } = makeExternalHash();
			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-cltv',
				hold: true,
				paymentHash: hash
			});
			alice.sendPayment(invoice.bolt11);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			const cltvExpiry = parkedCltvExpiry(bob, channelId);
			expect(cltvExpiry).to.be.greaterThan(1000);

			// One block before the 18-block safety margin: still parked.
			bob.handleNewBlock(cltvExpiry - 19);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			// At the margin the sweeper cancels it off-chain: payer fails,
			// channel stays open (no force-close, no on-chain timeout race).
			bob.handleNewBlock(cltvExpiry - 18);
			expect(bob.listHeldHtlcs()).to.have.length(0);
			expect(bob.listHoldInvoices()[0].state).to.equal('CANCELLED');
			expect(alice.getPayment(hash)!.status).to.equal(PaymentStatus.FAILED);
			expect(
				bob.getChannelManager().getChannel(channelId)!.getState()
			).to.equal(ChannelState.NORMAL);
		});

		it('does not force-close for an internally-generated hold preimage (cancels instead)', function () {
			// The node knows the preimage for a hold invoice it generated itself.
			// The claim-backstop force-close must NOT fire for a parked hold: the
			// operator never released the payment, so claiming it on-chain would
			// settle without consent. The held sweeper cancels at the same margin.
			const alice = createNode(15);
			const bob = createNode(16);
			connectNodes(alice, bob);
			alice.handleNewBlock(1000);
			bob.handleNewBlock(1000);
			const channelId = openReadyChannel(alice, bob);
			buildGraph(alice, bob, [channelId]);

			const invoice = bob.createInvoice({
				amountMsat: 5_000_000n,
				description: 'hold-internal-cltv',
				hold: true
			});
			alice.sendPayment(invoice.bolt11);
			expect(bob.listHeldHtlcs()).to.have.length(1);

			const cltvExpiry = parkedCltvExpiry(bob, channelId);
			bob.handleNewBlock(cltvExpiry - 18);

			expect(bob.listHeldHtlcs()).to.have.length(0);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.FAILED
			);
			expect(
				bob.getChannelManager().getChannel(channelId)!.getState()
			).to.equal(ChannelState.NORMAL);
		});
	});
});
