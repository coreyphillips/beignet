/**
 * Blinded relay correctness regression tests (BOLT 4 route blinding).
 *
 * Covers two audit findings:
 * - S-4.M1: a blinded relay must compute amt_to_forward with the spec's
 *   ceiling-inverted formula. Charging the proportional fee on the incoming
 *   amount forwards a few msat short and the downstream node fails the HTLC.
 * - S-4.M2: every failure at a node inside a blinded route must surface as
 *   invalid_onion_blinding (update_fail_malformed_htlc at a hop whose
 *   blinding point arrived in update_add_htlc; a normally encrypted error at
 *   the introduction node), never the real failure code.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	constructBlindedPath,
	IBlindedHopData
} from '../../src/lightning/onion/blinded-path';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { decodeUpdateFailMalformedHtlcMessage } from '../../src/lightning/message/channel-update';
import { INVALID_ONION_BLINDING } from '../../src/lightning/onion/types';

// ─────────────── Helpers (mirrors node.test.ts) ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`blinded-relay-seed-${id}`))
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

function nodePrivkeyFor(seedId: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(makeSeed(seedId))
		.update(Buffer.from('node-identity'))
		.digest();
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: nodePrivkeyFor(seedId),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		// Secret behind makeBasepoints' htlcBasepoint (keys[4]) so the signer
		// can produce HTLC second-level signatures for commitment_signed.
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

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === b.getNodeId()) b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
		if (pk === a.getNodeId()) a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	amount = 2_000_000n
): Buffer {
	const ch = alice.openChannel(bob.getNodeId(), amount);
	const txid = crypto.randomBytes(32);
	const channelId = alice.createFunding(ch, txid, 0, crypto.randomBytes(64))!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

/** Give the payer a graph edge to the introduction node. */
function addGraphEdge(
	node: LightningNode,
	scid: Buffer,
	pubA: Buffer,
	pubB: Buffer
): void {
	const is1 = Buffer.compare(pubA, pubB) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: is1 ? pubA : pubB,
		nodeId2: is1 ? pubB : pubA,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const dir of [0, 1]) {
		node.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
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
}

const CONSTRAINTS = { maxCltvExpiry: 10_000_000, htlcMinimumMsat: 0n };

/**
 * Alice → Bob(intro) → Carol(recipient), with a proportional relay fee at
 * Bob authored by Carol into the blinded path.
 */
function buildTwoHopBlinded(opts: { registerOutScid: boolean }): {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	invoiceStr: string;
	paymentHash: Buffer;
} {
	const alice = createNode(1);
	const bob = createNode(2);
	const carol = createNode(3);
	connectNodes(alice, bob);
	connectNodes(bob, carol);

	const abChannelId = openReadyChannel(alice, bob);
	const bcChannelId = openReadyChannel(bob, carol);

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
	alice.registerChannelScid(abChannelId, scidAB);
	bob.registerChannelScid(abChannelId, scidAB);
	if (opts.registerOutScid) {
		bob.registerChannelScid(bcChannelId, scidBC);
		carol.registerChannelScid(bcChannelId, scidBC);
	}

	const alicePub = getPublicKey(nodePrivkeyFor(1));
	const bobPub = getPublicKey(nodePrivkeyFor(2));
	const carolPub = getPublicKey(nodePrivkeyFor(3));
	addGraphEdge(alice, scidAB, alicePub, bobPub);

	// Carol registers the preimage/secret via a normal invoice, then we
	// re-issue it carrying the blinded path through Bob.
	const baseInv = carol.createInvoice({
		amountMsat: 1_000_000n,
		description: 'blinded-relay'
	});
	const decoded = decodeInvoice(baseInv.bolt11);

	// 1000 ppm proportional relay fee: 1_000_000 msat forwards need the
	// ceiling-inverted formula to come out exact.
	const relay = {
		cltvExpiryDelta: 40,
		feeProportionalMillionths: 1000,
		feeBaseMsat: 0
	};
	const hopData: IBlindedHopData[] = [
		{
			nextNodeId: carolPub,
			shortChannelId: scidBC,
			paymentRelay: relay,
			paymentConstraints: CONSTRAINTS
		},
		{ paymentConstraints: CONSTRAINTS }
	];
	const path = constructBlindedPath(
		crypto.randomBytes(32),
		[bobPub, carolPub],
		hopData
	);
	const payInfo = {
		feeBaseMsat: 0,
		feeProportionalMillionths: 1000,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 0n,
		htlcMaximumMsat: 1_000_000_000n
	};

	const invoiceStr = encodeInvoice({
		network: Network.REGTEST,
		amountMsat: 1_000_000n,
		paymentHash: decoded.paymentHash,
		paymentSecret: decoded.paymentSecret,
		description: 'blinded-relay',
		blindedPaths: [{ path, payInfo }],
		minFinalCltvExpiry: 40,
		privateKey: nodePrivkeyFor(3)
	});

	return { alice, bob, carol, invoiceStr, paymentHash: decoded.paymentHash };
}

describe('Blinded relay correctness (S-4.M1 / S-4.M2)', function () {
	it('forwards the exact spec amount through a proportional-fee blinded hop (S-4.M1)', function () {
		const { alice, bob, carol, invoiceStr, paymentHash } = buildTwoHopBlinded({
			registerOutScid: true
		});

		// Capture the amount Bob actually forwards to Carol.
		let forwardedMsat: bigint | undefined;
		bob.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
			if (pk === carol.getNodeId() && type === MessageType.UPDATE_ADD_HTLC) {
				forwardedMsat = payload.readBigUInt64BE(40); // 32 channel_id + 8 id
			}
		});

		alice.sendPayment(invoiceStr);

		// Sender pays 1_000_000 + 1000 ppm = 1_001_000 msat at the intro node.
		// amt_to_forward = ceil((1_001_000 - 0) * 1e6 / 1_001_000) = 1_000_000.
		// The old incoming-amount formula forwarded 999_999 (one msat short).
		expect(forwardedMsat).to.equal(1_000_000n);
		expect(alice.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(carol.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('returns invalid_onion_blinding from the introduction node on a local failure (S-4.M2)', function () {
		// Bob cannot resolve the onward SCID (never registered): previously
		// UNKNOWN_NEXT_PEER leaked through the blinded route.
		const { alice, invoiceStr, paymentHash } = buildTwoHopBlinded({
			registerOutScid: false
		});

		try {
			alice.sendPayment(invoiceStr);
		} catch {
			// retries may exhaust with NO_ROUTE; the failure code is recorded
		}

		expect(alice.getPayment(paymentHash)!.failureCode).to.equal(
			INVALID_ONION_BLINDING
		);
	});

	it('fails with update_fail_malformed_htlc at a mid blinded hop and converts downstream failures at the intro node (S-4.M2)', function () {
		// Alice → Bob(intro) → Carol(mid) → Dave, but Carol cannot resolve the
		// onward SCID. Carol got her blinding point in update_add_htlc, so she
		// MUST send update_fail_malformed_htlc/invalid_onion_blinding; Bob must
		// convert it into an encrypted invalid_onion_blinding for Alice.
		const alice = createNode(1);
		const bob = createNode(2);
		const carol = createNode(3);
		const dave = createNode(4);
		connectNodes(alice, bob);
		connectNodes(bob, carol);
		connectNodes(carol, dave);

		const abChannelId = openReadyChannel(alice, bob);
		const bcChannelId = openReadyChannel(bob, carol);
		openReadyChannel(carol, dave);

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
		alice.registerChannelScid(abChannelId, scidAB);
		bob.registerChannelScid(abChannelId, scidAB);
		bob.registerChannelScid(bcChannelId, scidBC);
		carol.registerChannelScid(bcChannelId, scidBC);
		// scidCD deliberately NOT registered on Carol.

		const alicePub = getPublicKey(nodePrivkeyFor(1));
		const bobPub = getPublicKey(nodePrivkeyFor(2));
		const carolPub = getPublicKey(nodePrivkeyFor(3));
		const davePub = getPublicKey(nodePrivkeyFor(4));
		addGraphEdge(alice, scidAB, alicePub, bobPub);

		const baseInv = dave.createInvoice({
			amountMsat: 1_000_000n,
			description: 'mid-fail'
		});
		const decoded = decodeInvoice(baseInv.bolt11);

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
				paymentConstraints: CONSTRAINTS
			},
			{
				nextNodeId: davePub,
				shortChannelId: scidCD,
				paymentRelay: relay,
				paymentConstraints: CONSTRAINTS
			},
			{ paymentConstraints: CONSTRAINTS }
		];
		const path = constructBlindedPath(
			crypto.randomBytes(32),
			[bobPub, carolPub, davePub],
			hopData
		);
		const payInfo = {
			feeBaseMsat: 2000,
			feeProportionalMillionths: 0,
			cltvExpiryDelta: 80,
			htlcMinimumMsat: 0n,
			htlcMaximumMsat: 1_000_000_000n
		};
		const invoiceStr = encodeInvoice({
			network: Network.REGTEST,
			amountMsat: 1_000_000n,
			paymentHash: decoded.paymentHash,
			paymentSecret: decoded.paymentSecret,
			description: 'mid-fail',
			blindedPaths: [{ path, payInfo }],
			minFinalCltvExpiry: 40,
			privateKey: nodePrivkeyFor(4)
		});

		// Capture Carol's update_fail_malformed_htlc back to Bob.
		let malformedCode: number | undefined;
		let malformedSha: Buffer | undefined;
		let carolOnionIn: Buffer | undefined;
		bob.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
			if (pk === carol.getNodeId() && type === MessageType.UPDATE_ADD_HTLC) {
				// onion_routing_packet: 32 channel_id + 8 id + 8 amount + 32 hash + 4 cltv
				carolOnionIn = payload.subarray(84, 84 + 1366);
			}
		});
		carol.on(
			'message:outbound',
			(pk: string, type: number, payload: Buffer) => {
				if (
					pk === bob.getNodeId() &&
					type === MessageType.UPDATE_FAIL_MALFORMED_HTLC
				) {
					const msg = decodeUpdateFailMalformedHtlcMessage(payload);
					malformedCode = msg.failureCode;
					malformedSha = msg.sha256OfOnion;
				}
			}
		);

		try {
			alice.sendPayment(invoiceStr);
		} catch {
			// retries may exhaust with NO_ROUTE; the failure code is recorded
		}

		expect(malformedCode, 'mid hop sent update_fail_malformed_htlc').to.equal(
			INVALID_ONION_BLINDING
		);
		expect(carolOnionIn, 'captured the onion Carol received').to.not.equal(
			undefined
		);
		expect(
			malformedSha!.equals(
				crypto.createHash('sha256').update(carolOnionIn!).digest()
			),
			'sha256_of_onion matches the onion Carol received'
		).to.equal(true);
		// Bob converted the malformed failure into an encrypted
		// invalid_onion_blinding for Alice.
		expect(alice.getPayment(decoded.paymentHash)!.failureCode).to.equal(
			INVALID_ONION_BLINDING
		);
	});

	it('fails with update_fail_malformed_htlc when a blinded HTLC carries an unparseable onion (S-4.M2)', function () {
		const alice = createNode(11);
		const bob = createNode(12);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		let malformedCode: number | undefined;
		let malformedSha: Buffer | undefined;
		bob.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
			if (
				pk === alice.getNodeId() &&
				type === MessageType.UPDATE_FAIL_MALFORMED_HTLC
			) {
				const msg = decodeUpdateFailMalformedHtlcMessage(payload);
				malformedCode = msg.failureCode;
				malformedSha = msg.sha256OfOnion;
			}
		});

		// A well-formed blinding point but a garbage onion: Bob is a mid blinded
		// hop (blinding point arrived in update_add_htlc) and cannot parse the
		// onion, so the failure MUST be invalid_onion_blinding via
		// update_fail_malformed_htlc, not invalid_onion_hmac.
		const garbageOnion = crypto.randomBytes(1366);
		garbageOnion[0] = 0; // valid version byte so decode reaches the HMAC check
		alice
			.getChannelManager()
			.addHtlc(
				channelId,
				10_000n,
				crypto.randomBytes(32),
				800_000,
				garbageOnion,
				getPublicKey(crypto.randomBytes(32))
			);

		expect(malformedCode).to.equal(INVALID_ONION_BLINDING);
		expect(
			malformedSha!.equals(
				crypto.createHash('sha256').update(garbageOnion).digest()
			),
			'sha256_of_onion matches the received onion'
		).to.equal(true);
	});
});
