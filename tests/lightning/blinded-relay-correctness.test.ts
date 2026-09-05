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

function createNode(
	seedId: number,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode({ ...makeNodeConfig(seedId), ...extra });
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

interface IRelayTerms {
	cltvExpiryDelta: number;
	feeProportionalMillionths: number;
	feeBaseMsat: number;
}

/**
 * Alice → Bob(intro) → Carol(recipient), with a relay fee at Bob authored by
 * Carol into the blinded path. Bob's own policy defaults to what the path
 * pays (a forwarding node refuses a path that understates its policy since
 * #721); `bobConfig` overrides it, and `issue()` mints a further invoice with
 * a fresh path so one world can carry several payments.
 */
function buildTwoHopBlinded(opts: {
	registerOutScid: boolean;
	relay?: IRelayTerms;
	bobConfig?: Partial<INodeConfig>;
}): {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	bcChannelId: Buffer;
	invoiceStr: string;
	paymentHash: Buffer;
	issue: (relay?: IRelayTerms) => { invoiceStr: string; paymentHash: Buffer };
} {
	// 1000 ppm proportional relay fee: 1_000_000 msat forwards need the
	// ceiling-inverted formula to come out exact.
	const defaultRelay: IRelayTerms = {
		cltvExpiryDelta: 40,
		feeProportionalMillionths: 1000,
		feeBaseMsat: 0
	};
	const alice = createNode(1);
	const bob = createNode(2, {
		forwardingFeeBaseMsat: (opts.relay ?? defaultRelay).feeBaseMsat,
		forwardingFeePropMillionths: (opts.relay ?? defaultRelay)
			.feeProportionalMillionths,
		...opts.bobConfig
	});
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
	const issue = (
		relay: IRelayTerms = opts.relay ?? defaultRelay
	): { invoiceStr: string; paymentHash: Buffer } => {
		const baseInv = carol.createInvoice({
			amountMsat: 1_000_000n,
			description: 'blinded-relay'
		});
		const decoded = decodeInvoice(baseInv.bolt11);
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
		// One relay hop, so the aggregate payinfo is the hop's own terms.
		const payInfo = {
			feeBaseMsat: relay.feeBaseMsat,
			feeProportionalMillionths: relay.feeProportionalMillionths,
			cltvExpiryDelta: relay.cltvExpiryDelta,
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
		return { invoiceStr, paymentHash: decoded.paymentHash };
	};

	const first = issue();
	return {
		alice,
		bob,
		carol,
		bcChannelId,
		invoiceStr: first.invoiceStr,
		paymentHash: first.paymentHash,
		issue
	};
}

/** Pay and swallow the retry-exhaustion throw; the failure code is recorded. */
function tryPay(alice: LightningNode, invoiceStr: string): void {
	try {
		alice.sendPayment(invoiceStr);
	} catch {
		// retries may exhaust with NO_ROUTE; the failure code is recorded
	}
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
		// The hand-built relay below is base fee only; the forwarding nodes
		// charge exactly that so the #721 fee gate is not what fails here.
		const bob = createNode(2, { forwardingFeePropMillionths: 0 });
		const carol = createNode(3, { forwardingFeePropMillionths: 0 });
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

describe('Blinded relay fee versus forwarding policy (#721)', function () {
	const POLICY: IRelayTerms = {
		cltvExpiryDelta: 40,
		feeProportionalMillionths: 1,
		feeBaseMsat: 1000
	};
	const sleep = (ms: number): Promise<void> =>
		new Promise((resolve) => setTimeout(resolve, ms));

	it('refuses a blinded path whose relay fee understates our policy', function () {
		// Carol authors a free relay at Bob; Bob's policy charges 1000 + 1 ppm.
		const { alice, bob, carol, invoiceStr, paymentHash } = buildTwoHopBlinded({
			registerOutScid: true,
			relay: {
				cltvExpiryDelta: 40,
				feeProportionalMillionths: 0,
				feeBaseMsat: 0
			},
			bobConfig: {
				forwardingFeeBaseMsat: 1000,
				forwardingFeePropMillionths: 1
			}
		});
		let carolSawAdd = false;
		bob.on('message:outbound', (pk: string, type: number) => {
			if (pk === carol.getNodeId() && type === MessageType.UPDATE_ADD_HTLC) {
				carolSawAdd = true;
			}
		});

		tryPay(alice, invoiceStr);

		expect(carolSawAdd, 'Bob must not forward a short relay').to.be.false;
		expect(alice.getPayment(paymentHash)!.failureCode).to.equal(
			INVALID_ONION_BLINDING
		);
		expect(carol.getPayment(paymentHash)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('forwards a blinded path authored from our advertised policy', function () {
		const { alice, carol, invoiceStr, paymentHash } = buildTwoHopBlinded({
			registerOutScid: true,
			relay: POLICY
		});
		alice.sendPayment(invoiceStr);
		expect(alice.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(carol.getPayment(paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('honours the previous policy for the grace window after a fee increase, then refuses', async function () {
		const { alice, bob, carol, bcChannelId, issue } = buildTwoHopBlinded({
			registerOutScid: true,
			relay: POLICY,
			// Wide enough for the in-window payment's own setup (invoice, path,
			// route) to land inside it on a loaded box; the test sleeps past it.
			bobConfig: { forwardingPolicyGraceMs: 1000 }
		});
		// Bob raises his base fee after Carol authored her paths at 1000.
		bob.setChannelPolicy(bcChannelId, { feeBaseMsat: 5000 });

		const inWindow = issue(POLICY);
		alice.sendPayment(inWindow.invoiceStr);
		expect(
			carol.getPayment(inWindow.paymentHash)!.status,
			'a path from the previous policy forwards inside the window'
		).to.equal(PaymentStatus.COMPLETED);

		await sleep(1100);
		const afterWindow = issue(POLICY);
		tryPay(alice, afterWindow.invoiceStr);
		expect(
			alice.getPayment(afterWindow.paymentHash)!.failureCode,
			'the same terms are refused once the window closes'
		).to.equal(INVALID_ONION_BLINDING);

		const current = issue({ ...POLICY, feeBaseMsat: 5000 });
		alice.sendPayment(current.invoiceStr);
		expect(carol.getPayment(current.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('a fee cut takes effect at once and closes an open window', function () {
		const { alice, bob, carol, bcChannelId, issue } = buildTwoHopBlinded({
			registerOutScid: true,
			relay: POLICY
		});
		bob.setChannelPolicy(bcChannelId, { feeBaseMsat: 5000 }); // opens a window
		bob.setChannelPolicy(bcChannelId, { feeBaseMsat: 2000 }); // a cut closes it

		const stale = issue(POLICY); // 1000: below 2000, and the window is gone
		tryPay(alice, stale.invoiceStr);
		expect(alice.getPayment(stale.paymentHash)!.failureCode).to.equal(
			INVALID_ONION_BLINDING
		);

		const fresh = issue({ ...POLICY, feeBaseMsat: 2000 });
		alice.sendPayment(fresh.invoiceStr);
		expect(carol.getPayment(fresh.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('with the window disabled a fee increase refuses outstanding paths at once', function () {
		const { alice, bob, bcChannelId, issue } = buildTwoHopBlinded({
			registerOutScid: true,
			relay: POLICY,
			bobConfig: { forwardingPolicyGraceMs: 0 }
		});
		bob.setChannelPolicy(bcChannelId, { feeProportionalMillionths: 500 });
		const stale = issue(POLICY);
		tryPay(alice, stale.invoiceStr);
		expect(alice.getPayment(stale.paymentHash)!.failureCode).to.equal(
			INVALID_ONION_BLINDING
		);
	});
});
