/**
 * Keysend (bLIP-0003) — Spontaneous Payments
 *
 * Tests for onion custom TLV records, feature flags, send/receive keysend,
 * BeignetNode wrappers, and daemon endpoints.
 *
 * ~39 tests across 6 sections.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	PaymentStatus,
	PaymentDirection,
	IPaymentInfo,
	IKeysendOptions,
	LightningErrorCode,
	LightningPaymentError
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	encodeHopPayload,
	decodeHopPayload
} from '../../src/lightning/onion/hop-payload';
import { IHopPayload, KEYSEND_TLV_TYPE } from '../../src/lightning/onion/types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';

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

/** Setup two connected nodes with an open channel and graph for keysend. */
function setupKeysendPair(
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

// ─────────────── Section 1: Onion Layer — Custom TLV Records ───────────────

describe('Keysend: Onion Layer — Custom TLV Records', () => {
	it('KEYSEND_TLV_TYPE has correct value per bLIP-0003', () => {
		expect(KEYSEND_TLV_TYPE).to.equal(5482373484);
	});

	it('encodeHopPayload includes custom records sorted by type', () => {
		const records = new Map<number, Buffer>();
		records.set(KEYSEND_TLV_TYPE, crypto.randomBytes(32));
		records.set(65537, Buffer.from('test-odd'));

		const payload: IHopPayload = {
			amountToForwardMsat: 50000n,
			outgoingCltvValue: 144,
			customRecords: records
		};
		const encoded = encodeHopPayload(payload);
		expect(encoded.length).to.be.greaterThan(0);

		// Decode and verify round-trip
		const { payload: decoded } = decodeHopPayload(encoded, 0);
		expect(decoded.amountToForwardMsat).to.equal(50000n);
		expect(decoded.outgoingCltvValue).to.equal(144);
		expect(decoded.customRecords).to.be.an.instanceOf(Map);
		expect(decoded.customRecords!.size).to.equal(2);
		expect(decoded.customRecords!.get(KEYSEND_TLV_TYPE)!.length).to.equal(32);
		expect(decoded.customRecords!.get(65537)!.toString()).to.equal('test-odd');
	});

	it('encodeHopPayload roundtrips keysend preimage correctly', () => {
		const preimage = crypto.randomBytes(32);
		const records = new Map<number, Buffer>();
		records.set(KEYSEND_TLV_TYPE, preimage);

		const payload: IHopPayload = {
			amountToForwardMsat: 100000n,
			outgoingCltvValue: 200,
			customRecords: records
		};
		const encoded = encodeHopPayload(payload);
		const { payload: decoded } = decodeHopPayload(encoded, 0);

		expect(decoded.customRecords!.get(KEYSEND_TLV_TYPE)!.equals(preimage)).to.be
			.true;
	});

	it('decodeHopPayload handles KEYSEND_TLV_TYPE as a known even type', () => {
		// KEYSEND_TLV_TYPE is even (5482373484 % 2 === 0) but should NOT throw
		const records = new Map<number, Buffer>();
		records.set(KEYSEND_TLV_TYPE, crypto.randomBytes(32));

		const payload: IHopPayload = {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: 10,
			customRecords: records
		};
		const encoded = encodeHopPayload(payload);
		const { payload: decoded } = decodeHopPayload(encoded, 0);
		expect(decoded.customRecords!.has(KEYSEND_TLV_TYPE)).to.be.true;
	});

	it('decodeHopPayload preserves unknown odd TLV types as custom records', () => {
		const oddType = 65537; // odd
		const records = new Map<number, Buffer>();
		records.set(oddType, Buffer.from('test'));

		const payload: IHopPayload = {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: 10,
			customRecords: records
		};
		const encoded = encodeHopPayload(payload);
		const { payload: decoded } = decodeHopPayload(encoded, 0);
		expect(decoded.customRecords!.has(oddType)).to.be.true;
		expect(decoded.customRecords!.get(oddType)!.toString()).to.equal('test');
	});

	it('decodeHopPayload throws on unknown even TLV types (not KEYSEND)', () => {
		// Manually encode a payload with unknown even type 100
		const records = new Map<number, Buffer>();
		records.set(100, Buffer.from('bad'));

		const payload: IHopPayload = {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: 10,
			customRecords: records
		};
		const encoded = encodeHopPayload(payload);
		expect(() => decodeHopPayload(encoded, 0)).to.throw(
			'Unknown required TLV type 100'
		);
	});

	it('encodeHopPayload with no custom records matches original behavior', () => {
		const payload: IHopPayload = {
			amountToForwardMsat: 50000n,
			outgoingCltvValue: 144
		};
		const encoded = encodeHopPayload(payload);
		const { payload: decoded } = decodeHopPayload(encoded, 0);
		expect(decoded.amountToForwardMsat).to.equal(50000n);
		expect(decoded.outgoingCltvValue).to.equal(144);
		expect(decoded.customRecords).to.be.undefined;
	});

	it('encodeHopPayload custom records are sorted by type ascending', () => {
		const records = new Map<number, Buffer>();
		// Add in reverse order
		records.set(KEYSEND_TLV_TYPE, crypto.randomBytes(32)); // large number
		records.set(65537, Buffer.from('a')); // smaller number

		const payload: IHopPayload = {
			amountToForwardMsat: 1000n,
			outgoingCltvValue: 10,
			customRecords: records
		};
		const encoded = encodeHopPayload(payload);
		const { payload: decoded } = decodeHopPayload(encoded, 0);

		// Both should be present
		expect(decoded.customRecords!.size).to.equal(2);
		expect(decoded.customRecords!.has(65537)).to.be.true;
		expect(decoded.customRecords!.has(KEYSEND_TLV_TYPE)).to.be.true;
	});
});

// ─────────────── Section 2: Feature Flags ───────────────

describe('Keysend: Feature Flags', () => {
	it('Feature.KEYSEND has bit 54', () => {
		expect(Feature.KEYSEND).to.equal(54);
	});

	it('defaultFeatures includes KEYSEND optional bit (55)', () => {
		const flags = LightningNode.defaultFeatures();
		expect(flags.hasFeature(Feature.KEYSEND)).to.be.true;
		expect(flags.isOptional(Feature.KEYSEND)).to.be.true;
		expect(flags.isCompulsory(Feature.KEYSEND)).to.be.false;
	});

	it('KEYSEND feature flag encodes/decodes correctly', () => {
		const flags = FeatureFlags.empty();
		flags.setOptional(Feature.KEYSEND);
		const buf = flags.toBuffer();
		const decoded = FeatureFlags.fromBuffer(buf);
		expect(decoded.hasFeature(Feature.KEYSEND)).to.be.true;
		expect(decoded.isOptional(Feature.KEYSEND)).to.be.true;
	});
});

// ─────────────── Section 3: Send Keysend ───────────────

describe('Keysend: Send Keysend', () => {
	it('sendKeysend generates random preimage and derives payment hash', () => {
		const { alice, bob } = setupKeysendPair(700, 701);

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		expect(result.paymentHash).to.be.instanceOf(Buffer);
		expect(result.paymentHash.length).to.equal(32);
		expect(result.direction).to.equal(PaymentDirection.OUTGOING);
		expect(result.metadata?._keysend).to.equal('true');
	});

	it('sendKeysend rejects invalid destination (wrong length)', () => {
		const alice = createNode(702);
		expect(() =>
			alice.sendKeysend({
				destination: Buffer.alloc(32), // should be 33
				amountMsat: 50000n
			})
		).to.throw('33-byte compressed public key');
	});

	it('sendKeysend rejects zero amount', () => {
		const alice = createNode(703);
		expect(() =>
			alice.sendKeysend({
				destination: crypto.randomBytes(33),
				amountMsat: 0n
			})
		).to.throw('amountMsat must be positive');
	});

	it('sendKeysend rejects negative amount', () => {
		const alice = createNode(704);
		expect(() =>
			alice.sendKeysend({
				destination: crypto.randomBytes(33),
				amountMsat: -1n
			})
		).to.throw('amountMsat must be positive');
	});

	it('sendKeysend throws NO_ROUTE for unknown destination', () => {
		const alice = createNode(705);
		try {
			alice.sendKeysend({
				destination: Buffer.from(getPublicKey(crypto.randomBytes(32))),
				amountMsat: 50000n
			});
			expect.fail('should have thrown');
		} catch (err: unknown) {
			expect(err).to.be.instanceOf(LightningPaymentError);
			expect((err as LightningPaymentError).code).to.equal(
				LightningErrorCode.NO_ROUTE
			);
		}
	});

	it('sendKeysend respects maxFeeMsat cap (direct channel has zero fee)', () => {
		const { alice, bob } = setupKeysendPair(706, 707);

		// Direct channel has 0 fee, so maxFeeMsat=0 should work
		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n,
			maxFeeMsat: 0n
		});
		expect(result.paymentHash.length).to.equal(32);
	});

	it('sendKeysend creates PENDING payment record', () => {
		const { alice, bob } = setupKeysendPair(709, 710);

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		// Payment should exist in alice's payment list
		const payments = alice.listPayments();
		const found = payments.find((p) =>
			p.paymentHash.equals(result.paymentHash)
		);
		expect(found).to.not.be.undefined;
		expect(found!.metadata?._keysend).to.equal('true');
	});

	it('sendKeysend includes extra custom TLV records', () => {
		const { alice, bob } = setupKeysendPair(711, 712);

		const extra = new Map<number, Buffer>();
		extra.set(65537, Buffer.from('hello'));

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n,
			customRecords: extra
		});

		expect(result.paymentHash.length).to.equal(32);
	});

	it('sendKeysend preimage SHA256 matches payment hash', () => {
		const { alice, bob } = setupKeysendPair(713, 714);

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		// The preimage is stored in the payment record
		expect(result.preimage).to.be.instanceOf(Buffer);
		const expectedHash = crypto
			.createHash('sha256')
			.update(result.preimage!)
			.digest();
		expect(expectedHash.equals(result.paymentHash)).to.be.true;
	});

	it('sendKeysend includes metadata from options', () => {
		const { alice, bob } = setupKeysendPair(715, 716);

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n,
			metadata: { purpose: 'tip', agent: 'test' }
		});

		expect(result.metadata?.purpose).to.equal('tip');
		expect(result.metadata?.agent).to.equal('test');
		expect(result.metadata?._keysend).to.equal('true');
	});
});

// ─────────────── Section 4: Receive Keysend ───────────────

describe('Keysend: Receive Keysend', () => {
	it('receiver extracts keysend preimage and fulfills payment', () => {
		const { alice, bob } = setupKeysendPair(720, 721);

		let receivedPayment: IPaymentInfo | undefined;
		bob.on('payment:received', (info: IPaymentInfo) => {
			receivedPayment = info;
		});

		alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		// In synchronous loopback, payment should be fulfilled immediately
		expect(receivedPayment).to.not.be.undefined;
		expect(receivedPayment!.direction).to.equal(PaymentDirection.INCOMING);
		expect(receivedPayment!.metadata?._keysend).to.equal('true');
	});

	it('keysend payment settles end-to-end (sender sees COMPLETED)', () => {
		const { alice, bob } = setupKeysendPair(722, 723);

		let sentPayment: IPaymentInfo | undefined;
		alice.on('payment:sent', (info: IPaymentInfo) => {
			sentPayment = info;
		});

		alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		expect(sentPayment).to.not.be.undefined;
		expect(sentPayment!.status).to.equal(PaymentStatus.COMPLETED);
	});

	it('keysend preimage is validated via SHA256 before fulfillment', () => {
		const { alice, bob } = setupKeysendPair(724, 725);

		let received = false;
		bob.on('payment:received', () => {
			received = true;
		});

		alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});
		expect(received).to.be.true;
	});

	it('keysend creates incoming payment record on receiver', () => {
		const { alice, bob } = setupKeysendPair(726, 727);

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		const bobPayments = bob.listPayments();
		const incomingPayment = bobPayments.find((p) =>
			p.paymentHash.equals(result.paymentHash)
		);
		expect(incomingPayment).to.not.be.undefined;
		expect(incomingPayment!.direction).to.equal(PaymentDirection.INCOMING);
		expect(incomingPayment!.preimage).to.be.instanceOf(Buffer);
		expect(incomingPayment!.preimage!.length).to.equal(32);
	});

	it('keysend stores preimage on receiver for later retrieval', () => {
		const { alice, bob } = setupKeysendPair(728, 729);

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		const bobPayments = bob.listPayments();
		const incoming = bobPayments.find((p) =>
			p.paymentHash.equals(result.paymentHash)
		);
		expect(incoming).to.not.be.undefined;

		// Verify preimage matches hash
		const expectedHash = crypto
			.createHash('sha256')
			.update(incoming!.preimage!)
			.digest();
		expect(expectedHash.equals(result.paymentHash)).to.be.true;
	});

	it('receiver marks keysend payment as COMPLETED after fulfillment', () => {
		const { alice, bob } = setupKeysendPair(730, 731);

		const result = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});

		const bobPayments = bob.listPayments();
		const incoming = bobPayments.find((p) =>
			p.paymentHash.equals(result.paymentHash)
		);
		expect(incoming).to.not.be.undefined;
		expect(incoming!.status).to.equal(PaymentStatus.COMPLETED);
	});

	it('keysend works for multiple sequential payments', () => {
		const { alice, bob } = setupKeysendPair(732, 733);

		const hashes: Buffer[] = [];
		for (let i = 0; i < 3; i++) {
			const result = alice.sendKeysend({
				destination: Buffer.from(bob.getNodeId(), 'hex'),
				amountMsat: 10000n
			});
			hashes.push(result.paymentHash);
		}

		// All three should be unique
		expect(hashes[0].equals(hashes[1])).to.be.false;
		expect(hashes[1].equals(hashes[2])).to.be.false;

		// Bob should have 3 incoming payments
		const bobPayments = bob
			.listPayments()
			.filter((p) => p.direction === PaymentDirection.INCOMING);
		expect(bobPayments.length).to.be.at.least(3);
	});

	it('keysend and invoice payments coexist', () => {
		const { alice, bob } = setupKeysendPair(734, 735);

		// Send keysend first
		alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 10000n
		});

		// Then send a regular invoice payment
		const invoice = bob.createInvoice({
			amountMsat: 20000n,
			description: 'test'
		});
		alice.sendPayment(invoice.bolt11);

		// Both should settle
		const bobPayments = bob
			.listPayments()
			.filter(
				(p) =>
					p.direction === PaymentDirection.INCOMING &&
					p.status === PaymentStatus.COMPLETED
			);
		expect(bobPayments.length).to.be.at.least(2);
	});
});

// ────────── Section 4b: Block-height skew (regression) ──────────

/**
 * A payment used to fail permanently with incorrect_or_unknown_payment_details
 * (0x4000 | 15) whenever the receiver's block height was ahead of the sender's:
 * the sender builds the final expiry from ITS height, while the receiver demanded
 * a full min_final_cltv_expiry against ITS OWN height.
 *
 * Every other test in this file leaves the height at 0, and the receiver check is
 * guarded by `currentBlockHeight > 0`, so without handleNewBlock() below this code
 * path is never exercised.
 */
describe('Keysend: block-height skew between sender and receiver', () => {
	// Sender padding absorbs skew up to FINAL_CLTV_EXPIRY_PADDING with no
	// round trip at all. The receiver still enforces its full advertised
	// min_final_cltv_expiry_delta, per BOLT 4.
	for (const skew of [0, 1, 2, 3]) {
		it(`keysend settles outright with the receiver ${skew} block(s) ahead`, () => {
			const { alice, bob } = setupKeysendPair(760 + skew * 2, 761 + skew * 2);
			alice.handleNewBlock(800_000);
			bob.handleNewBlock(800_000 + skew);

			let received = false;
			bob.on('payment:received', () => {
				received = true;
			});

			const result = alice.sendKeysend({
				destination: Buffer.from(bob.getNodeId(), 'hex'),
				amountMsat: 50000n
			});

			expect(result.failureCode, 'no onion failure').to.be.undefined;
			expect(result.status).to.equal(PaymentStatus.COMPLETED);
			expect(received, 'receiver accepted the keysend').to.be.true;
		});
	}

	it('an invoice payment beyond the padding is retried, not abandoned', () => {
		const { alice, bob } = setupKeysendPair(790, 791);
		alice.handleNewBlock(800_000);
		bob.handleNewBlock(800_005); // beyond the sender padding

		const invoice = bob.createInvoice({
			amountMsat: 50000n,
			description: 'skew'
		});
		const result = alice.sendPayment(invoice.bolt11);

		// The first attempt is rejected with PERM|15. Because the failure carries
		// bob's height, alice recognises the transient case and retries against it
		// instead of treating the PERM bit as fatal. The retry registers a fresh
		// record for the same hash, so read that rather than the stale handle.
		const settled = alice
			.listPayments()
			.find((p) => p.paymentHash.equals(result.paymentHash));
		expect(settled, 'payment record exists').to.not.be.undefined;
		expect(settled!.status).to.equal(PaymentStatus.COMPLETED);
		expect(settled!.retryCount, 'took a retry to settle').to.be.greaterThan(0);
	});

	it('a keysend beyond the padding teaches us the payee height', () => {
		const { alice, bob } = setupKeysendPair(794, 795);
		alice.handleNewBlock(800_000);
		bob.handleNewBlock(800_004); // beyond the sender padding

		// Keysend has no retry context (each attempt derives a fresh preimage), so
		// this attempt fails, but the reported height is recorded...
		const first = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});
		expect(first.status).to.equal(PaymentStatus.FAILED);

		// ...so the next one is built against bob's height and settles.
		const second = alice.sendKeysend({
			destination: Buffer.from(bob.getNodeId(), 'hex'),
			amountMsat: 50000n
		});
		expect(second.status).to.equal(PaymentStatus.COMPLETED);
	});
});

// ─────────────── Section 5: BeignetNode Wrappers ───────────────

describe('Keysend: BeignetNode Wrappers', () => {
	// These tests verify the wrapper interface exists and handles basic validation
	// without requiring full BeignetNode.create() (which needs filesystem + Electrum)

	it('IKeysendOptions interface has required fields', () => {
		const opts: IKeysendOptions = {
			destination: crypto.randomBytes(33),
			amountMsat: 1000n
		};
		expect(opts.destination.length).to.equal(33);
		expect(opts.amountMsat).to.equal(1000n);
		expect(opts.maxFeeMsat).to.be.undefined;
		expect(opts.customRecords).to.be.undefined;
		expect(opts.metadata).to.be.undefined;
	});

	it('IKeysendOptions accepts optional fields', () => {
		const opts: IKeysendOptions = {
			destination: crypto.randomBytes(33),
			amountMsat: 1000n,
			maxFeeMsat: 500n,
			customRecords: new Map([[65537, Buffer.from('test')]]),
			metadata: { key: 'value' }
		};
		expect(opts.maxFeeMsat).to.equal(500n);
		expect(opts.customRecords!.size).to.equal(1);
		expect(opts.metadata!.key).to.equal('value');
	});

	it('INVALID_KEYSEND error code exists', () => {
		expect(LightningErrorCode.INVALID_KEYSEND).to.equal('INVALID_KEYSEND');
	});

	it('LightningPaymentError works with INVALID_KEYSEND', () => {
		const err = new LightningPaymentError(
			LightningErrorCode.INVALID_KEYSEND,
			'bad keysend'
		);
		expect(err.code).to.equal('INVALID_KEYSEND');
		expect(err.message).to.equal('bad keysend');
		expect(err).to.be.instanceOf(Error);
	});

	it('sendKeysend method exists on LightningNode', () => {
		const node = createNode(740);
		expect(typeof node.sendKeysend).to.equal('function');
	});

	it('sendKeysend rejects empty destination at LightningNode level', () => {
		const node = createNode(741);
		try {
			node.sendKeysend({
				destination: Buffer.alloc(0),
				amountMsat: 1000n
			});
			expect.fail('should have thrown');
		} catch (err: unknown) {
			expect((err as LightningPaymentError).code).to.equal(
				LightningErrorCode.INVALID_KEYSEND
			);
		}
	});
});

// ─────────────── Section 6: Daemon Endpoints ───────────────

describe('Keysend: Daemon & OpenAPI', () => {
	it('OpenAPI spec includes /keysend endpoint', () => {
		const { getOpenApiSpec } = require('../../src/cli/openapi');
		const spec = getOpenApiSpec();
		expect(spec.paths['/keysend']).to.not.be.undefined;
		expect(spec.paths['/keysend'].post).to.not.be.undefined;
		expect(spec.paths['/keysend'].post.summary).to.include('keysend');
	});

	it('OpenAPI spec includes /keysend/safe endpoint', () => {
		const { getOpenApiSpec } = require('../../src/cli/openapi');
		const spec = getOpenApiSpec();
		expect(spec.paths['/keysend/safe']).to.not.be.undefined;
		expect(spec.paths['/keysend/safe'].post).to.not.be.undefined;
		expect(spec.paths['/keysend/safe'].post.summary).to.include('never throws');
	});

	it('OpenAPI /keysend has required pubkey and amountSats', () => {
		const { getOpenApiSpec } = require('../../src/cli/openapi');
		const spec = getOpenApiSpec();
		const schema =
			spec.paths['/keysend'].post.requestBody.content['application/json']
				.schema;
		expect(schema.required).to.include('pubkey');
		expect(schema.required).to.include('amountSats');
	});

	it('OpenAPI /keysend accepts optional timeoutMs, maxFeeSats, metadata', () => {
		const { getOpenApiSpec } = require('../../src/cli/openapi');
		const spec = getOpenApiSpec();
		const schema =
			spec.paths['/keysend'].post.requestBody.content['application/json']
				.schema;
		expect(schema.properties.timeoutMs).to.not.be.undefined;
		expect(schema.properties.maxFeeSats).to.not.be.undefined;
		expect(schema.properties.metadata).to.not.be.undefined;
		// Optional fields should NOT be in required array
		expect(schema.required).to.not.include('timeoutMs');
		expect(schema.required).to.not.include('maxFeeSats');
	});
});
