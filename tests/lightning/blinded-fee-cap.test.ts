/**
 * The blinded-path fee is payee-written and must be capped (issue #1001).
 *
 * An invoice's blinded_payinfo carries a fee_base_msat and a
 * fee_proportional_millionths that the PAYEE chose, decoded as raw u32s.
 * findRouteToBlindedPath adds that fee to the amount routed to the
 * introduction node, but the grafted route reported only the public hops'
 * fees as totalFeeMsat (0 over a direct channel), so sendPayment's fee cap
 * never saw it, payBolt12Invoice had no cap at all, and a hostile payee
 * could take any amount as "fee" from a payer that had set an explicit
 * maxFeeMsat.
 *
 * Alice -> Bob (introduction node) -> Carol (recipient) over real loopback
 * channels. For BOLT 11 Carol writes the largest fee the encoding allows;
 * for BOLT 12 Carol's own offer manager issues the invoice, whose path
 * introduces at Bob with Bob's real relay terms.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	LightningErrorCode,
	LightningPaymentError,
	PaymentStatus
} from '../../src/lightning/node/types';
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
import {
	encodeOfferTlv,
	encodeInvoiceRequestTlv,
	getTlvRecords,
	computeMerkleRootFromRecords,
	computeSignatureHash,
	schnorrSign,
	IInvoiceRequest,
	IBolt12Invoice
} from '../../src/lightning/offer';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`blinded-fee-cap-seed-${id}`))
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
	from: LightningNode,
	to: LightningNode,
	amountSats: bigint
): Buffer {
	const ch = from.openChannel(to.getNodeId(), amountSats);
	const txid = crypto.randomBytes(32);
	const channelId = from.createFunding(ch, txid, 0, crypto.randomBytes(64))!;
	from.handleFundingConfirmed(channelId);
	to.handleFundingConfirmed(channelId);
	return channelId;
}

/** A public edge to the introduction node that can carry the hostile amount. */
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
			htlcMaximumMsat: 10_000_000_000n
		});
	}
}

const CONSTRAINTS = { maxCltvExpiry: 10_000_000, htlcMinimumMsat: 0n };

const AMOUNT_MSAT = 1_000_000n;
/** The largest fee the u32 payinfo fields can express. */
const HOSTILE_RELAY = {
	cltvExpiryDelta: 40,
	feeProportionalMillionths: 0xffffffff,
	feeBaseMsat: 0xffffffff
};
/** What findRouteToBlindedPath adds at the introduction node for AMOUNT_MSAT. */
const HOSTILE_FEE_MSAT =
	BigInt(HOSTILE_RELAY.feeBaseMsat) +
	(AMOUNT_MSAT * BigInt(HOSTILE_RELAY.feeProportionalMillionths)) / 1_000_000n;

interface IWorld {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	scidBC: Buffer;
	bobPub: Buffer;
	carolPub: Buffer;
	/** update_add_htlc amounts Alice put on the wire. */
	aliceAdds: bigint[];
	destroy: () => void;
}

/**
 * Alice -> Bob(intro) -> Carol(recipient). Bob's forwarding policy is what
 * the invoice's path will state, so he does not refuse a path that
 * understates it (#721); Alice's channel to Bob is large enough to carry the
 * hostile amount, so what refuses a payment is the cap, not the router.
 */
function buildWorld(bobPolicy: {
	feeBaseMsat: number;
	feeProportionalMillionths: number;
}): IWorld {
	const alice = createNode(1);
	const bob = createNode(2, {
		forwardingFeeBaseMsat: bobPolicy.feeBaseMsat,
		forwardingFeePropMillionths: bobPolicy.feeProportionalMillionths
	});
	const carol = createNode(3);
	connectNodes(alice, bob);
	connectNodes(bob, carol);

	const abChannelId = openReadyChannel(alice, bob, 10_000_000n);
	const bcChannelId = openReadyChannel(bob, carol, 2_000_000n);

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
	bob.registerChannelScid(bcChannelId, scidBC);
	carol.registerChannelScid(bcChannelId, scidBC);

	const alicePub = getPublicKey(nodePrivkeyFor(1));
	const bobPub = getPublicKey(nodePrivkeyFor(2));
	const carolPub = getPublicKey(nodePrivkeyFor(3));
	addGraphEdge(alice, scidAB, alicePub, bobPub);

	const aliceAdds: bigint[] = [];
	alice.on('message:outbound', (_pk: string, type: number, payload: Buffer) => {
		if (type === MessageType.UPDATE_ADD_HTLC) {
			aliceAdds.push(payload.readBigUInt64BE(40)); // 32 channel_id + 8 id
		}
	});

	return {
		alice,
		bob,
		carol,
		scidBC,
		bobPub,
		carolPub,
		aliceAdds,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			carol.destroy();
		}
	};
}

/** Carol's BOLT 11 invoice with a path through Bob at the hostile terms. */
function buildHostileWorld(): IWorld & {
	invoiceStr: string;
	paymentHash: Buffer;
} {
	const world = buildWorld(HOSTILE_RELAY);
	const { carol, scidBC, bobPub, carolPub } = world;
	const baseInv = carol.createInvoice({
		amountMsat: AMOUNT_MSAT,
		description: 'hostile blinded fee'
	});
	const decoded = decodeInvoice(baseInv.bolt11);
	const hopData: IBlindedHopData[] = [
		{
			nextNodeId: carolPub,
			shortChannelId: scidBC,
			paymentRelay: HOSTILE_RELAY,
			paymentConstraints: CONSTRAINTS
		},
		{ paymentConstraints: CONSTRAINTS }
	];
	const path = constructBlindedPath(
		crypto.randomBytes(32),
		[bobPub, carolPub],
		hopData
	);
	const invoiceStr = encodeInvoice({
		network: Network.REGTEST,
		amountMsat: AMOUNT_MSAT,
		paymentHash: decoded.paymentHash,
		paymentSecret: decoded.paymentSecret,
		description: 'hostile blinded fee',
		blindedPaths: [
			{
				path,
				payInfo: {
					feeBaseMsat: HOSTILE_RELAY.feeBaseMsat,
					feeProportionalMillionths: HOSTILE_RELAY.feeProportionalMillionths,
					cltvExpiryDelta: HOSTILE_RELAY.cltvExpiryDelta,
					htlcMinimumMsat: 0n,
					htlcMaximumMsat: 100_000_000_000n
				}
			}
		],
		minFinalCltvExpiry: 40,
		privateKey: nodePrivkeyFor(3)
	});
	return { ...world, invoiceStr, paymentHash: decoded.paymentHash };
}

/**
 * Carol issues a BOLT 12 invoice exactly as her onion-message handler would.
 * Carol is unannounced with Bob as her only peer, so the invoice's payment
 * path introduces at Bob and states Bob's relay terms as Carol knows them.
 */
function issueBolt12Invoice(
	carol: LightningNode,
	payerSeedId: number,
	amountMsat: bigint
): IBolt12Invoice {
	const payerPriv = nodePrivkeyFor(payerSeedId);
	const offerMgr = carol.getOfferManager();
	const { offer } = offerMgr.createOffer({
		description: 'blinded fee cap',
		amount: amountMsat
	});
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
	const invoice = offerMgr.handleInvoiceRequest(
		encodeInvoiceRequestTlv(request, offerTlv)
	);
	expect(invoice, 'carol issued a BOLT 12 invoice').to.not.be.null;
	return invoice!;
}

describe('Blinded-path fee cap on BOLT 11 payments (issue #1001)', function () {
	it('refuses a payee-written blinded fee over the cap before any HTLC leaves', function () {
		const { alice, invoiceStr, paymentHash, aliceAdds, destroy } =
			buildHostileWorld();
		try {
			let error: unknown;
			try {
				alice.sendPayment(invoiceStr, undefined, 1_000n);
			} catch (err) {
				error = err;
			}
			expect(error, 'the send was refused').to.be.instanceOf(
				LightningPaymentError
			);
			expect((error as LightningPaymentError).code).to.equal(
				LightningErrorCode.FEE_EXCEEDS_MAX
			);
			// Refused, not attempted: nothing on the wire, no record, nothing
			// for a retry to redispatch.
			expect(aliceAdds, 'no update_add_htlc left alice').to.have.length(0);
			expect(alice.getPayment(paymentHash)).to.be.undefined;
			expect(
				(
					alice as unknown as { paymentRetryContexts: Map<string, unknown> }
				).paymentRetryContexts.has(paymentHash.toString('hex')),
				'no retry context'
			).to.equal(false);
		} finally {
			destroy();
		}
	});

	it('a cap one msat under the real fee refuses, the real fee itself pays and is reported', function () {
		const { alice, carol, invoiceStr, paymentHash, aliceAdds, destroy } =
			buildHostileWorld();
		try {
			expect(() =>
				alice.sendPayment(invoiceStr, undefined, HOSTILE_FEE_MSAT - 1n)
			).to.throw('Route fee exceeds maximum');
			expect(aliceAdds, 'the refusal sent nothing').to.have.length(0);

			const payment = alice.sendPayment(
				invoiceStr,
				undefined,
				HOSTILE_FEE_MSAT
			);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(aliceAdds.map(String)).to.deep.equal([
				String(AMOUNT_MSAT + HOSTILE_FEE_MSAT)
			]);
			expect(payment.route?.totalFeeMsat).to.equal(HOSTILE_FEE_MSAT);
			expect(carol.getPayment(paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		} finally {
			destroy();
		}
	});

	it('pays the payee-written fee uncapped when no cap is given (a default cap is a separate PR)', function () {
		const { alice, invoiceStr, aliceAdds, destroy } = buildHostileWorld();
		try {
			const payment = alice.sendPayment(invoiceStr);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			// 8_589_934_590 msat of fee on a 1_000_000 msat payment: paid, and
			// now at least visible on the record instead of reported as 0.
			expect(aliceAdds.map(String)).to.deep.equal([
				String(AMOUNT_MSAT + HOSTILE_FEE_MSAT)
			]);
			expect(payment.route?.totalFeeMsat).to.equal(HOSTILE_FEE_MSAT);
		} finally {
			destroy();
		}
	});
});

describe('Blinded-path fee cap on BOLT 12 payments (issue #1001)', function () {
	// Carol writes Bob's default relay terms into the path: 1000 msat base
	// and 1 ppm, which on 50_000 msat is a 1000 msat blinded fee. The
	// public leg is our own channel to Bob, which costs nothing, so the
	// whole fee is the payee's and the route used to report 0.
	const amountMsat = 50_000n;
	const blindedFeeMsat = 1_000n;
	const defaultPolicy = { feeBaseMsat: 1000, feeProportionalMillionths: 1 };

	it('a cap one msat under the payee-written blinded fee refuses; the fee itself pays and is reported', function () {
		const world = buildWorld(defaultPolicy);
		const { alice, carol, aliceAdds } = world;
		try {
			const invoice = issueBolt12Invoice(carol, 1, amountMsat);
			expect(
				Buffer.from(invoice.paths![0].introductionNodeId).equals(world.bobPub),
				'the path introduces at bob, so alice grafts onto it'
			).to.equal(true);
			expect(invoice.blindedPayInfo![0].feeBaseMsat).to.equal(1000);

			expect(() =>
				alice.payBolt12Invoice(invoice, undefined, blindedFeeMsat - 1n)
			).to.throw('Route fee exceeds maximum');
			expect(aliceAdds, 'the refusal sent nothing').to.have.length(0);
			expect(alice.getPayment(invoice.paymentHash)).to.be.undefined;

			const payment = alice.payBolt12Invoice(
				invoice,
				undefined,
				blindedFeeMsat
			);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(aliceAdds.map(String)).to.deep.equal([
				String(amountMsat + blindedFeeMsat)
			]);
			expect(payment.route?.totalFeeMsat).to.equal(blindedFeeMsat);
			expect(carol.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		} finally {
			world.destroy();
		}
	});

	it('skips a path over the cap for a cheaper one the invoice also advertises', function () {
		const world = buildWorld(defaultPolicy);
		const { alice, aliceAdds } = world;
		try {
			const invoice = issueBolt12Invoice(world.carol, 1, amountMsat);
			// The same path twice: first priced at the largest fee the
			// encoding allows, then at its real terms.
			invoice.paths = [invoice.paths![0], invoice.paths![0]];
			invoice.blindedPayInfo = [
				{
					...invoice.blindedPayInfo![0],
					feeBaseMsat: 0xffffffff,
					feeProportionalMillionths: 0xffffffff,
					htlcMaximumMsat: 100_000_000_000n
				},
				invoice.blindedPayInfo![0]
			];
			const payment = alice.payBolt12Invoice(
				invoice,
				undefined,
				blindedFeeMsat
			);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(
				aliceAdds.map(String),
				'only the cheaper path was tried'
			).to.deep.equal([String(amountMsat + blindedFeeMsat)]);
			expect(payment.route?.totalFeeMsat).to.equal(blindedFeeMsat);
		} finally {
			world.destroy();
		}
	});

	it('pays the payee-written fee uncapped when no cap is given (a default cap is a separate PR)', function () {
		const world = buildWorld(defaultPolicy);
		const { alice } = world;
		try {
			const invoice = issueBolt12Invoice(world.carol, 1, amountMsat);
			const payment = alice.payBolt12Invoice(invoice);
			expect(payment.status, payment.failureReason ?? '').to.equal(
				PaymentStatus.COMPLETED
			);
			expect(payment.route?.totalFeeMsat).to.equal(blindedFeeMsat);
		} finally {
			world.destroy();
		}
	});
});
