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
 * refuses as in flight, and the durable row is read for a record pruned
 * from memory. A failed HTLC does not count as in flight, so the retry
 * that re-enters sendPayment right after the peer's update_fail_htlc is not
 * refused.
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

function createNode(seedId: number, storage?: SqliteStorage): LightningNode {
	const node = new LightningNode({
		...makeNodeConfig(seedId),
		...(storage ? { storage } : {})
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** Two nodes wired back to back with one ready channel from alice to bob. */
function setupPair(
	aliceSeed: number,
	bobSeed: number
): { alice: LightningNode; bob: LightningNode } {
	const alice = createNode(aliceSeed);
	const bob = createNode(bobSeed);

	alice.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === bob.getNodeId()) {
			bob.handlePeerMessage(alice.getNodeId(), type, payload);
		}
	});
	bob.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === alice.getNodeId()) {
			alice.handlePeerMessage(bob.getNodeId(), type, payload);
		}
	});

	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	alice.registerChannelScid(
		channelId,
		encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 })
	);
	return { alice, bob };
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

		// Whatever else refuses a self-payment, it is not "already completed".
		const err = refusal(() => alice.sendPayment(own.bolt11));
		expect(err?.message ?? '').to.not.match(/already completed/);

		alice.destroy();
	});
});
