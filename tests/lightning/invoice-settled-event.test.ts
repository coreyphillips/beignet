/**
 * invoice:settled + HTLC event granularity (M4 batch 2b):
 * - invoice:settled fires when an invoice WE issued is paid (single-part and
 *   hold-invoice settle), with the invoice's bolt11 attached
 * - invoice:settled does NOT fire for keysend (spontaneous receive, no invoice)
 * - htlc:fulfilled / htlc:failed re-emitted at the LightningNode level
 * - htlc:forwarded is a settled forward (not emitted on direct receives)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, IPaymentInfo } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
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

// ─────────────── Helpers (loopback harness, mirrors keysend.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`invoice-settled-seed-${id}`))
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
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
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

function buildDirectGraph(
	alice: LightningNode,
	bob: LightningNode,
	aliceSeedId: number,
	bobSeedId: number
): void {
	const aliceConfig = makeNodeConfig(aliceSeedId);
	const bobConfig = makeNodeConfig(bobSeedId);
	const alicePubkey = getPublicKey(aliceConfig.nodePrivateKey);
	const bobPubkey = getPublicKey(bobConfig.nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });

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
	const update2: IChannelUpdateMessage = {
		...update1,
		channelFlags: 1
	};

	alice.getGraph().applyChannelUpdate(update1);
	alice.getGraph().applyChannelUpdate(update2);

	alice.registerChannelScid(
		alice.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

function setupPair(
	aliceSeedId: number,
	bobSeedId: number
): { alice: LightningNode; bob: LightningNode; channelId: Buffer } {
	const alice = createNode(aliceSeedId);
	const bob = createNode(bobSeedId);
	connectNodes(alice, bob);
	const channelId = openReadyChannel(alice, bob);
	buildDirectGraph(alice, bob, aliceSeedId, bobSeedId);
	return { alice, bob, channelId };
}

// ─────────────── invoice:settled ───────────────

describe('invoice:settled event (M4 batch 2b)', () => {
	it('fires on the payee when an invoice it issued is paid', () => {
		const { alice, bob } = setupPair(1, 2);

		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'settled-event'
		});

		const settled: Array<{
			paymentHash: Buffer;
			bolt11: string;
			amountMsat: bigint;
		}> = [];
		let received: IPaymentInfo | undefined;
		bob.on('invoice:settled', (data) => settled.push(data));
		bob.on('payment:received', (info: IPaymentInfo) => {
			received = info;
		});

		alice.sendPayment(invoice.bolt11);

		expect(received, 'payment:received still fires').to.not.be.undefined;
		expect(settled).to.have.length(1);
		expect(settled[0].paymentHash.equals(invoice.paymentHash)).to.equal(true);
		expect(settled[0].bolt11).to.equal(invoice.bolt11);
		expect(settled[0].amountMsat).to.equal(5_000_000n);
	});

	it('does NOT fire for a keysend receive (payment:received only)', () => {
		const { alice, bob } = setupPair(3, 4);

		let settledFired = false;
		let received: IPaymentInfo | undefined;
		bob.on('invoice:settled', () => {
			settledFired = true;
		});
		bob.on('payment:received', (info: IPaymentInfo) => {
			received = info;
		});

		alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50_000n
		});

		expect(received, 'keysend receive fires payment:received').to.not.be
			.undefined;
		expect(received!.metadata?._keysend).to.equal('true');
		expect(settledFired, 'no invoice:settled for keysend').to.equal(false);
	});

	it('fires when a hold invoice is settled, not while the HTLC is parked', () => {
		const { alice, bob } = setupPair(5, 6);

		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'hold-settled-event',
			hold: true,
			paymentHash: hash
		});

		const settled: Array<{ paymentHash: Buffer }> = [];
		bob.on('invoice:settled', (data) => settled.push(data));

		alice.sendPayment(invoice.bolt11);
		expect(settled, 'parked HTLC is not settled yet').to.have.length(0);

		expect(bob.settleHeldHtlc(hash, preimage)).to.equal(true);
		expect(settled).to.have.length(1);
		expect(settled[0].paymentHash.equals(hash)).to.equal(true);
	});
});

// ─────────────── HTLC-level events ───────────────

describe('htlc events at the LightningNode level (M4 batch 2b)', () => {
	it('emits htlc:fulfilled on the payer when its offered HTLC settles', () => {
		const { alice, bob, channelId } = setupPair(7, 8);

		const fulfilled: Array<{ channelId: Buffer; htlcId: bigint }> = [];
		alice.on('htlc:fulfilled', (data) => fulfilled.push(data));

		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'htlc-fulfilled-event'
		});
		alice.sendPayment(invoice.bolt11);

		expect(fulfilled).to.have.length(1);
		expect(fulfilled[0].channelId.equals(channelId)).to.equal(true);
		expect(fulfilled[0].htlcId).to.equal(0n);
	});

	it('emits htlc:failed on the payer when its HTLC is failed back', () => {
		const { alice, bob, channelId } = setupPair(9, 10);

		const failed: Array<{ channelId: Buffer; htlcId: bigint }> = [];
		alice.on('htlc:failed', (data) => failed.push(data));

		// Hold invoice: the HTLC parks on bob, then cancel fails it back.
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'htlc-failed-event',
			hold: true,
			paymentHash: hash
		});
		alice.sendPayment(invoice.bolt11);
		expect(failed).to.have.length(0);

		bob.cancelHoldInvoice(hash);
		expect(failed).to.have.length(1);
		expect(failed[0].channelId.equals(channelId)).to.equal(true);
	});

	it('does not emit htlc:forwarded for a direct receive (forwards only)', () => {
		const { alice, bob } = setupPair(11, 12);

		let forwarded = false;
		bob.on('htlc:forwarded', () => {
			forwarded = true;
		});
		alice.on('htlc:forwarded', () => {
			forwarded = true;
		});

		const invoice = bob.createInvoice({
			amountMsat: 5_000_000n,
			description: 'no-forward-event'
		});
		alice.sendPayment(invoice.bolt11);

		expect(forwarded).to.equal(false);
	});
});
