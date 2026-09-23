/**
 * Issue #975: sendPayment paid a hash again whose outgoing payment had
 * already completed, or whose offered HTLC was still live.
 *
 * The dedup check refused a second payment only while the record was
 * PENDING. A COMPLETED record was overwritten by a fresh PENDING one and a
 * new HTLC went out, so paying the same invoice twice paid twice (BOLT 11
 * lets the payee accept it, and any hop that learned the preimage on the
 * first route can claim the new HTLC). A record FAILED by a wall clock
 * (failPayment on a timeout) while its HTLC was still offered got a second
 * HTLC beside the first, which could still settle.
 *
 * The senders now judge the hash from what its HTLCs did: a known preimage
 * or a COMPLETED record refuses as completed, an HTLC that is still out
 * refuses as in flight, and the durable row (or, without storage, the set
 * of pruned paid hashes) answers for a record pruned from memory. A failed
 * HTLC does not count as in flight, so the retry that re-enters sendPayment
 * right after the peer's update_fail_htlc is not refused. sendPaymentToRoute,
 * the explicit-route entry behind POST /payment/send-to-route, runs the same
 * check, except that only an OUTGOING PENDING record counts as in flight
 * there (a circular rebalance sends to its own fresh invoice), and a part of
 * an MPP set is admitted beside the parts already out, since that is what an
 * HTLC set is; a paid hash refuses a part all the same.
 *
 * Issue #990 bounds that part waiver: a part is refused once the amounts of
 * the HTLCs still out for the hash reach the set's total_msat, since the
 * payee fulfils every part once it holds the total, so a part beyond that
 * overpays. The view carries first-hop amounts, fee inclusive, so the bound
 * is conservative: a legitimate last part is refused only when the fees
 * already paid on the earlier parts reach its amount.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	LightningErrorCode,
	LightningPaymentError,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import { TEMPORARY_NODE_FAILURE } from '../../src/lightning/onion/types';
import { IBolt12Invoice } from '../../src/lightning/offer/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const UPDATE_ADD_HTLC = 128;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`repay-seed-${id}`))
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
			.digest()
	};
}

function createNode(
	seedId: number,
	storage?: SqliteStorage,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode({
		...makeNodeConfig(seedId),
		...(storage ? { storage } : {}),
		...extra
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** Two nodes wired back to back with one ready channel from alice to bob. */
const CHANNEL_SCID = encodeShortChannelId({
	block: 500,
	txIndex: 1,
	outputIndex: 0
});

function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

function setupPair(
	aliceSeed: number,
	bobSeed: number,
	aliceExtra: Partial<INodeConfig> = {}
): { alice: LightningNode; bob: LightningNode } {
	const alice = createNode(aliceSeed, undefined, aliceExtra);
	const bob = createNode(bobSeed);
	wire(alice, bob);

	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	alice.registerChannelScid(channelId, CHANNEL_SCID);
	return { alice, bob };
}

/**
 * Alice -> Bob -> Charlie, one ready channel per link, Bob forwarding for a
 * 500 msat base fee. A two-hop route from Alice carries a first-hop amount
 * above what Charlie receives, which is what the issue #990 bound reads.
 */
const CHANNEL_SCID_BC = encodeShortChannelId({
	block: 500,
	txIndex: 2,
	outputIndex: 0
});

function setupChain(
	aliceSeed: number,
	bobSeed: number,
	charlieSeed: number
): { alice: LightningNode; bob: LightningNode; charlie: LightningNode } {
	const alice = createNode(aliceSeed);
	const bob = createNode(bobSeed);
	const charlie = createNode(charlieSeed);
	wire(alice, bob);
	wire(bob, charlie);

	const openReady = (
		opener: LightningNode,
		acceptor: LightningNode,
		scid: Buffer
	): Buffer => {
		const channel = opener.openChannel(acceptor.getNodeId(), 1_000_000n);
		const channelId = opener.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		opener.handleFundingConfirmed(channelId);
		acceptor.handleFundingConfirmed(channelId);
		opener.registerChannelScid(channelId, scid);
		acceptor.registerChannelScid(channelId, scid);
		return channelId;
	};
	openReady(alice, bob, CHANNEL_SCID);
	const bcChannelId = openReady(bob, charlie, CHANNEL_SCID_BC);
	bob.setChannelPolicy(bcChannelId, {
		feeBaseMsat: 500,
		feeProportionalMillionths: 0
	});
	for (const node of [alice, bob, charlie]) node.handleNewBlock(1000);
	return { alice, bob, charlie };
}

/** The two-hop route from Alice to Charlie: Bob is paid firstHopMsat and
 * forwards finalMsat, so Alice's channel carries the fee on top. */
function routeViaBob(
	bob: LightningNode,
	charlie: LightningNode,
	firstHopMsat: bigint,
	finalMsat: bigint
): Parameters<LightningNode['sendPaymentToRoute']>[0] {
	return {
		hops: [
			{
				pubkey: Buffer.from(bob.getNodeId(), 'hex'),
				shortChannelId: CHANNEL_SCID,
				amountToForwardMsat: firstHopMsat,
				outgoingCltvValue: 80
			},
			{
				pubkey: Buffer.from(charlie.getNodeId(), 'hex'),
				shortChannelId: CHANNEL_SCID_BC,
				amountToForwardMsat: finalMsat,
				outgoingCltvValue: 40
			}
		]
	};
}

/** The one-hop route to bob over the pair's channel, as a rebalance or a
 * POST /payment/send-to-route caller would hand it in. */
function routeToBob(
	bob: LightningNode,
	amountMsat: bigint
): Parameters<LightningNode['sendPaymentToRoute']>[0] {
	return {
		hops: [
			{
				pubkey: Buffer.from(bob.getNodeId(), 'hex'),
				shortChannelId: CHANNEL_SCID,
				amountToForwardMsat: amountMsat,
				outgoingCltvValue: 40
			}
		]
	};
}

/**
 * An invoice signed by bob for a hash bob holds no invoice for: bob fails
 * the HTLC permanently (incorrect_or_unknown_payment_details), so the
 * payment ends FAILED with nothing out.
 */
function foreignInvoice(bobSeed: number, bob: LightningNode): string {
	return encodeInvoice({
		network: Network.REGTEST,
		paymentHash: crypto.randomBytes(32),
		paymentSecret: crypto.randomBytes(32),
		timestamp: Math.floor(Date.now() / 1000),
		description: 'unknown to bob',
		minFinalCltvExpiry: 40,
		amountMsat: 50_000n,
		payeeNodeKey: Buffer.from(bob.getNodeId(), 'hex'),
		privateKey: makeNodeConfig(bobSeed).nodePrivateKey
	});
}

/** The code of whatever a send throws: null when it did not throw. */
function codeOf(send: () => unknown): string | null | undefined {
	try {
		send();
		return null;
	} catch (err) {
		return err instanceof LightningPaymentError ? err.code : undefined;
	}
}

/** Counts the update_add_htlc messages alice sends from now on. */
function countAdds(alice: LightningNode): () => number {
	let adds = 0;
	alice.on('message:outbound', (_pubkey: string, type: number) => {
		if (type === UPDATE_ADD_HTLC) adds++;
	});
	return () => adds;
}

/** The error a refused send throws, or undefined when it was not refused. */
function refusal(send: () => unknown): LightningPaymentError | undefined {
	try {
		send();
		return undefined;
	} catch (err) {
		expect(err, 'a typed payment error').to.be.instanceOf(
			LightningPaymentError
		);
		return err as LightningPaymentError;
	}
}

function expectDuplicate(
	err: LightningPaymentError | undefined,
	message: RegExp
): void {
	expect(err, 'the send was refused').to.not.be.undefined;
	expect(err!.code).to.equal(LightningErrorCode.DUPLICATE_PAYMENT);
	expect(err!.message).to.match(message);
}

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

describe('Issue #975: a hash is not paid again', () => {
	it('refuses to pay an invoice whose payment completed, and offers no HTLC', () => {
		const { alice, bob } = setupPair(930, 931);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'once'
		});
		const adds = countAdds(alice);

		const first = alice.sendPayment(invoice.bolt11);
		expect(first.status, 'the loopback payment completed').to.equal(
			PaymentStatus.COMPLETED
		);
		expect(adds()).to.equal(1);
		const hash = invoice.paymentHash;
		const viewBefore = alice.getOutgoingHtlcs(hash);
		expect(viewBefore.preimage, 'the view knows the preimage').to.not.be
			.undefined;

		// Before the fix this went through: a fresh PENDING record replaced
		// the COMPLETED one and a second update_add_htlc left for bob.
		expectDuplicate(
			refusal(() => alice.sendPayment(invoice.bolt11)),
			/already completed/
		);
		expect(adds(), 'no second HTLC was offered').to.equal(1);
		expect(alice.getOutgoingHtlcs(hash).htlcs.length).to.equal(
			viewBefore.htlcs.length
		);
		const record = alice.getPayment(hash);
		expect(record?.status, 'the record is still COMPLETED').to.equal(
			PaymentStatus.COMPLETED
		);
		expect(record?.preimage && sha256(record.preimage).equals(hash)).to.equal(
			true
		);

		// The same rule guards the BOLT 12 sender, which had its own copy of
		// the PENDING-only check.
		expectDuplicate(
			refusal(() =>
				alice.payBolt12Invoice({
					paymentHash: hash,
					amount: 50_000n,
					nodeId: Buffer.from(bob.getNodeId(), 'hex')
				} as unknown as IBolt12Invoice)
			),
			/already completed/
		);
		expect(adds()).to.equal(1);

		alice.destroy();
		bob.destroy();
	});

	it('refuses while an HTLC is still offered although the record was failed by the clock', () => {
		const { alice, bob } = setupPair(932, 933);
		// Bob holds the HTLC: the payee never settles.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(bob as any).handleFinalHopHtlc = (): void => {};
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'held'
		});
		const adds = countAdds(alice);

		const sent = alice.sendPayment(invoice.bolt11);
		expect(sent.status).to.equal(PaymentStatus.PENDING);
		expect(adds()).to.equal(1);

		// What BeignetNode.payInvoice does at its timeout.
		alice.failPayment(invoice.paymentHash, 'timed out');
		expect(alice.getPayment(invoice.paymentHash)?.status).to.equal(
			PaymentStatus.FAILED
		);
		const view = alice.getOutgoingHtlcs(invoice.paymentHash);
		expect(
			view.htlcs.some((h) => h.state === 'offered'),
			'the HTLC is still out'
		).to.equal(true);
		expect(view.resolved).to.equal(false);

		// Before the fix a second HTLC went out beside the live one.
		expectDuplicate(
			refusal(() => alice.sendPayment(invoice.bolt11)),
			/already in flight/
		);
		expect(adds(), 'no second HTLC was offered').to.equal(1);
		expect(alice.getOutgoingHtlcs(invoice.paymentHash).htlcs.length).to.equal(
			1
		);

		alice.destroy();
		bob.destroy();
	});

	it('does not refuse the retry that follows the peer failing the HTLC', () => {
		const { alice, bob } = setupPair(934, 935);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const b = bob as any;
		const accept = b.handleFinalHopHtlc as (...args: unknown[]) => unknown;
		let attempts = 0;
		// The first HTLC comes back with a temporary failure, which the
		// retry path answers by re-entering sendPayment at once, before the
		// removal round for the failed HTLC has completed. The second is
		// accepted.
		b.handleFinalHopHtlc = (...args: unknown[]): unknown => {
			attempts++;
			if (attempts > 1) return accept.apply(bob, args);
			const [channelId, htlcId] = args as [Buffer, bigint];
			const sharedSecret = b.receivedHtlcSharedSecrets.get(
				`${channelId.toString('hex')}:${htlcId}`
			);
			b.channelManager.failHtlc(
				channelId,
				htlcId,
				createFailureMessage(sharedSecret, TEMPORARY_NODE_FAILURE)
			);
			return undefined;
		};
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'retried'
		});
		const adds = countAdds(alice);

		alice.sendPayment(invoice.bolt11);

		expect(attempts, 'the retry was dispatched').to.equal(2);
		expect(adds()).to.equal(2);
		const record = alice.getPayment(invoice.paymentHash);
		expect(record?.status).to.equal(PaymentStatus.COMPLETED);
		expect(record?.retryCount).to.equal(1);

		alice.destroy();
		bob.destroy();
	});

	it('refuses a hash whose completed record was pruned from memory but is still on disk', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(936, storage);
		const bob = createNode(937);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'pruned'
		});
		const hash = invoice.paymentHash;
		const hashHex = hash.toString('hex');
		const preimage = crypto.randomBytes(32);
		const row = (
			direction: PaymentDirection,
			status: PaymentStatus,
			withPreimage: boolean
		): IPaymentInfo => ({
			paymentHash: hash,
			...(withPreimage ? { preimage } : {}),
			amountMsat: 50_000n,
			status,
			direction,
			createdAt: Date.now() - 2_000,
			completedAt: Date.now() - 1_000
		});

		// Seeded after construction: the constructor restores storage into
		// memory, and the point is a row that memory no longer holds.
		storage.savePayment(
			hashHex,
			row(PaymentDirection.OUTGOING, PaymentStatus.COMPLETED, false)
		);
		expect(alice.getPayment(hash), 'memory holds nothing').to.equal(undefined);
		expectDuplicate(
			refusal(() => alice.sendPayment(invoice.bolt11)),
			/already completed/
		);

		// A FAILED row that recorded the preimage (a late fulfil after the
		// clock failed it) was paid too.
		storage.savePayment(
			hashHex,
			row(PaymentDirection.OUTGOING, PaymentStatus.FAILED, true)
		);
		expectDuplicate(
			refusal(() => alice.sendPayment(invoice.bolt11)),
			/already completed/
		);

		// A failed attempt with no preimage can be sent again: the send gets
		// as far as routing (which fails here for want of a channel).
		storage.savePayment(
			hashHex,
			row(PaymentDirection.OUTGOING, PaymentStatus.FAILED, false)
		);
		const retried = refusal(() => alice.sendPayment(invoice.bolt11));
		expect(retried?.code).to.not.equal(LightningErrorCode.DUPLICATE_PAYMENT);

		// This node's own invoice for the hash is not a payment it made.
		storage.savePayment(
			hashHex,
			row(PaymentDirection.INCOMING, PaymentStatus.COMPLETED, true)
		);
		const own = refusal(() => alice.sendPayment(invoice.bolt11));
		expect(own?.code).to.not.equal(LightningErrorCode.DUPLICATE_PAYMENT);

		// A settle whose COMPLETED record commit failed: the preimage row
		// (committed first) beside a PENDING OUTGOING record was paid too.
		storage.savePayment(
			hashHex,
			row(PaymentDirection.OUTGOING, PaymentStatus.PENDING, false)
		);
		storage.savePreimage(hashHex, preimage);
		expectDuplicate(
			refusal(() => alice.sendPayment(invoice.bolt11)),
			/already completed/
		);
		// The same preimage row beside this node's own invoice is not.
		storage.savePayment(
			hashHex,
			row(PaymentDirection.INCOMING, PaymentStatus.PENDING, true)
		);
		expect(codeOf(() => alice.sendPayment(invoice.bolt11))).to.not.equal(
			LightningErrorCode.DUPLICATE_PAYMENT
		);

		alice.destroy();
		bob.destroy();
	});

	it('does not read the preimage of its own invoice as a payment made', () => {
		const alice = createNode(938);
		const own = alice.createInvoice({
			amountMsat: 50_000n,
			description: 'mine'
		});
		const hash = decodeInvoice(own.bolt11).paymentHash;
		expect(hash.equals(own.paymentHash)).to.equal(true);

		// The view reports a preimage only for a hash this node offered an
		// HTLC for or holds an OUTGOING record for.
		const view = alice.getOutgoingHtlcs(hash);
		expect(view.preimage).to.equal(undefined);
		expect(view.status).to.equal(null);
		expect(view.htlcs).to.have.lengthOf(0);

		// The refusal a self-payment gets is the one it always got, from the
		// invoice's own INCOMING PENDING record, not "already completed".
		expectDuplicate(
			refusal(() => alice.sendPayment(own.bolt11)),
			/already in flight/
		);

		alice.destroy();
	});

	it('refuses sendPaymentToRoute for a hash whose payment completed', () => {
		const { alice, bob } = setupPair(940, 941);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'route once'
		});
		const adds = countAdds(alice);
		expect(alice.sendPayment(invoice.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(adds()).to.equal(1);

		// The explicit-route entry had no dedup at all: before the fix this
		// overwrote the COMPLETED record and offered a second HTLC.
		expectDuplicate(
			refusal(() =>
				alice.sendPaymentToRoute(
					routeToBob(bob, 50_000n),
					invoice.paymentHash,
					40,
					invoice.paymentSecret,
					50_000n
				)
			),
			/already completed/
		);
		expect(adds(), 'no second HTLC was offered').to.equal(1);
		expect(alice.getPayment(invoice.paymentHash)?.status).to.equal(
			PaymentStatus.COMPLETED
		);

		alice.destroy();
		bob.destroy();
	});

	it('admits the parts of an MPP set through sendPaymentToRoute, and refuses a single-part re-send and a part for a paid hash', () => {
		const { alice, bob } = setupPair(948, 949);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		const totalMsat = 40_000n;
		// A hold invoice parks the parts: the set stays out and PENDING.
		const held = bob.createInvoice({
			amountMsat: totalMsat,
			description: 'hold-mpp',
			hold: true,
			paymentHash: hash
		});
		const adds = countAdds(alice);
		const sendPart = (
			part: bigint,
			total: bigint | undefined
		): string | null | undefined =>
			codeOf(() =>
				alice.sendPaymentToRoute(
					routeToBob(bob, part),
					hash,
					40,
					held.paymentSecret,
					total
				)
			);

		// Two halves of one set, the second while the first is offered.
		expect(sendPart(totalMsat / 2n, totalMsat)).to.equal(null);
		expect(sendPart(totalMsat / 2n, totalMsat)).to.equal(null);
		expect(adds(), 'both parts went out').to.equal(2);
		const view = alice.getOutgoingHtlcs(hash);
		expect(view.htlcs.filter((h) => h.state === 'offered')).to.have.lengthOf(2);
		expect(view.status).to.equal(PaymentStatus.PENDING);

		// A single-part send for the hash (no total, or a total the final hop
		// receives whole) is a second payment beside a live one: refused.
		expectDuplicate(
			refusal(() =>
				alice.sendPaymentToRoute(
					routeToBob(bob, totalMsat),
					hash,
					40,
					held.paymentSecret
				)
			),
			/already in flight/
		);
		expectDuplicate(
			refusal(() =>
				alice.sendPaymentToRoute(
					routeToBob(bob, totalMsat),
					hash,
					40,
					held.paymentSecret,
					totalMsat
				)
			),
			/already in flight/
		);
		expect(adds()).to.equal(2);

		// A part for a hash whose payment completed is refused: the part
		// waiver covers in flight only, never paid.
		const paid = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'paid'
		});
		expect(alice.sendPayment(paid.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(adds()).to.equal(3);
		expectDuplicate(
			refusal(() =>
				alice.sendPaymentToRoute(
					routeToBob(bob, 10_000n),
					paid.paymentHash,
					40,
					paid.paymentSecret,
					50_000n
				)
			),
			/already completed/
		);
		expect(adds()).to.equal(3);

		alice.destroy();
		bob.destroy();
	});

	it("refuses a third part once the two parts out reach the set's total, and offers no third HTLC", () => {
		const { alice, bob } = setupPair(950, 951);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		const totalMsat = 40_000n;
		const held = bob.createInvoice({
			amountMsat: totalMsat,
			description: 'hold-mpp-bound',
			hold: true,
			paymentHash: hash
		});
		const adds = countAdds(alice);
		const sendPart = (part: bigint): LightningPaymentError | undefined =>
			refusal(() =>
				alice.sendPaymentToRoute(
					routeToBob(bob, part),
					hash,
					40,
					held.paymentSecret,
					totalMsat
				)
			);

		expect(sendPart(totalMsat / 2n)).to.be.undefined;
		expect(sendPart(totalMsat / 2n)).to.be.undefined;
		expect(adds(), 'the set went out').to.equal(2);

		// The parts out already reach total_msat: bob fulfils every part
		// once he holds the total, so a third part would be paid on top of
		// the set. Before the fix the part waiver admitted it (issue #990).
		expectDuplicate(sendPart(10_000n), /already in flight/);
		expect(adds(), 'no third HTLC was offered').to.equal(2);
		const view = alice.getOutgoingHtlcs(hash);
		expect(view.htlcs.filter((h) => h.state === 'offered')).to.have.lengthOf(2);
		expect(view.status).to.equal(PaymentStatus.PENDING);

		// The set itself is untouched: settling it fulfils every part and
		// completes the payment.
		expect(bob.settleHeldHtlc(hash, preimage), 'every part fulfilled').to.equal(
			true
		);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(alice.hasHtlcInFlight(hash)).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it("admits the last part of a set while the parts out are below the set's total", () => {
		const { alice, bob } = setupPair(952, 953);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		const totalMsat = 40_000n;
		const held = bob.createInvoice({
			amountMsat: totalMsat,
			description: 'hold-mpp-three',
			hold: true,
			paymentHash: hash
		});
		const adds = countAdds(alice);
		const sendPart = (part: bigint): LightningPaymentError | undefined =>
			refusal(() =>
				alice.sendPaymentToRoute(
					routeToBob(bob, part),
					hash,
					40,
					held.paymentSecret,
					totalMsat
				)
			);

		// Three parts: the third goes out with 30000 of the 40000 already
		// out. The bound is on the amount out, not on the number of parts,
		// and this pins that a set below its total keeps taking parts.
		expect(sendPart(15_000n)).to.be.undefined;
		expect(sendPart(15_000n)).to.be.undefined;
		expect(sendPart(10_000n), 'the last part is admitted').to.be.undefined;
		expect(adds()).to.equal(3);

		expect(bob.settleHeldHtlc(hash, preimage), 'every part fulfilled').to.equal(
			true
		);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(alice.hasHtlcInFlight(hash)).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('bounds a part by the first-hop amounts of the parts out, fee included', () => {
		const { alice, bob, charlie } = setupChain(954, 955, 956);
		const preimage = crypto.randomBytes(32);
		const hash = sha256(preimage);
		const totalMsat = 40_000n;
		const held = charlie.createInvoice({
			amountMsat: totalMsat,
			description: 'hold-mpp-fee',
			hold: true,
			paymentHash: hash
		});
		const adds = countAdds(alice);
		const sendPart = (
			firstHopMsat: bigint,
			finalMsat: bigint,
			invoice: { paymentHash: Buffer; paymentSecret: Buffer } = held,
			total: bigint = totalMsat
		): LightningPaymentError | undefined =>
			refusal(() =>
				alice.sendPaymentToRoute(
					routeViaBob(bob, charlie, firstHopMsat, finalMsat),
					invoice.paymentHash,
					40,
					invoice.paymentSecret,
					total
				)
			);
		const heldByCharlie = (h: Buffer): bigint | undefined =>
			charlie.getHeldInvoiceSnapshot(h)?.committedMsat;

		// Part 1 pays bob 1000 msat to forward 20000: alice's channel
		// carries 21000, and that is what the view reports.
		expect(sendPart(21_000n, 20_000n)).to.be.undefined;
		expect(adds()).to.equal(1);
		expect(
			alice.getOutgoingHtlcs(hash).htlcs.map((h) => h.amountMsat)
		).to.deep.equal([21_000n]);
		expect(heldByCharlie(hash)).to.equal(20_000n);

		// Part 2, 19000 for a 500 msat fee: the 21000 out is below the
		// total although it carries a fee, so the part is admitted.
		expect(sendPart(19_500n, 19_000n)).to.be.undefined;
		expect(adds()).to.equal(2);
		expect(heldByCharlie(hash)).to.equal(39_000n);

		// The bound's cost, documented rather than required: the first-hop
		// amounts out sum to 40500, at the total, while charlie holds 39000.
		// The legitimate 1000 msat last part is refused, since the 1500 msat
		// of fees already paid reach its amount. A node that recorded the
		// parts' final amounts would admit it.
		expectDuplicate(sendPart(1_500n, 1_000n), /already in flight/);
		expect(adds()).to.equal(2);
		expect(heldByCharlie(hash)).to.equal(39_000n);

		// The re-send the issue describes: a caller that hands the route
		// total (amount plus fees) in as totalMsat classifies as a part. The
		// first send goes out with nothing out for the hash; the channel
		// then carries that same route total, so the re-send is refused.
		const whole = charlie.createInvoice({
			amountMsat: totalMsat,
			description: 'route total as totalMsat',
			hold: true,
			paymentHash: sha256(crypto.randomBytes(32))
		});
		expect(sendPart(41_000n, 40_000n, whole, 41_000n)).to.be.undefined;
		expect(adds()).to.equal(3);
		expect(heldByCharlie(whole.paymentHash)).to.equal(40_000n);
		expectDuplicate(
			sendPart(41_000n, 40_000n, whole, 41_000n),
			/already in flight/
		);
		expect(adds(), 'the re-send offered nothing').to.equal(3);

		alice.destroy();
		bob.destroy();
		charlie.destroy();
	});

	it("does not refuse a circular rebalance's send to this node's own fresh invoice", () => {
		const { alice, bob } = setupPair(942, 943);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		// What rebalance does: its own invoice, whose record is INCOMING
		// PENDING and whose preimage this node knows, sent along an explicit
		// route through sendPaymentToRoute.
		const own = alice.createInvoice({
			amountMsat: 50_000n,
			description: 'beignet circular rebalance'
		});
		expect(alice.getPayment(own.paymentHash)?.status).to.equal(
			PaymentStatus.PENDING
		);
		const adds = countAdds(alice);

		const code = codeOf(() =>
			alice.sendPaymentToRoute(
				routeToBob(bob, 50_000n),
				own.paymentHash,
				40,
				own.paymentSecret,
				50_000n
			)
		);
		expect(code, 'not refused as a duplicate').to.not.equal(
			LightningErrorCode.DUPLICATE_PAYMENT
		);
		expect(adds(), 'the HTLC went out').to.equal(1);

		alice.destroy();
		bob.destroy();
	});

	it('refuses a paid hash after its record was pruned on a node without storage, and still retries a pruned failed one', async () => {
		const { alice, bob } = setupPair(944, 945, {
			resourceConfig: { completedPaymentTtlMs: 0 }
		});
		const adds = countAdds(alice);

		const paid = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'paid then pruned'
		});
		expect(alice.sendPayment(paid.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(adds()).to.equal(1);
		await new Promise((r) => setTimeout(r, 20));
		expect(alice.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(alice.getPayment(paid.paymentHash), 'record pruned').to.equal(
			undefined
		);
		expect(
			alice.getOutgoingHtlcs(paid.paymentHash).preimage,
			'preimage pruned with it'
		).to.equal(undefined);

		// No storage row to answer from: the pruned paid hashes are what
		// refuse here. Before the fix the send went out again.
		expectDuplicate(
			refusal(() => alice.sendPayment(paid.bolt11)),
			/already completed/
		);
		expect(adds(), 'no second HTLC was offered').to.equal(1);

		// A pruned FAILED hash stays retryable: the HTLC goes out again.
		const failed = foreignInvoice(945, bob);
		const failedHash = decodeInvoice(failed).paymentHash;
		expect(alice.sendPayment(failed).status).to.equal(PaymentStatus.FAILED);
		expect(adds()).to.equal(2);
		await new Promise((r) => setTimeout(r, 20));
		expect(alice.pruneCompletedPayments()).to.be.greaterThan(0);
		expect(alice.getPayment(failedHash)).to.equal(undefined);
		expect(codeOf(() => alice.sendPayment(failed))).to.not.equal(
			LightningErrorCode.DUPLICATE_PAYMENT
		);
		expect(adds(), 'the failed hash was sent again').to.equal(3);

		alice.destroy();
		bob.destroy();
	});

	it('fails a send closed when its durable record cannot be read', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const { alice, bob } = (() => {
			const a = createNode(946, storage);
			const b = createNode(947);
			return { alice: a, bob: b };
		})();
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'unreadable'
		});
		const adds = countAdds(alice);
		// What better-sqlite3 throws once the database is closed.
		storage.loadPayment = (): never => {
			throw new TypeError('The database connection is not open');
		};

		let thrown: unknown;
		try {
			alice.sendPayment(invoice.bolt11);
		} catch (err) {
			thrown = err;
		}
		expect(thrown).to.be.instanceOf(Error);
		expect(thrown).to.not.be.instanceOf(LightningPaymentError);
		expect((thrown as Error).message).to.match(
			/^payment record could not be read: The database connection is not open/
		);
		expect(adds(), 'nothing went out').to.equal(0);
		expect(alice.getPayment(invoice.paymentHash)).to.equal(undefined);

		alice.destroy();
		bob.destroy();
	});
});
