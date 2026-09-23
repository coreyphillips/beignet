/**
 * Issue #976: the engine's own wall clocks failed a payment whose HTLC could
 * still settle.
 *
 * sendPaymentAsync's timeout and the expired-invoice scanner called
 * failPayment on a PENDING record regardless of what its HTLCs were doing.
 * BOLT 2 has no way to retract an update_add_htlc, so the record read FAILED
 * while the HTLC was still out, and a payee who settled after the clock
 * turned it back into COMPLETED. Both now go through
 * failPaymentUnlessInFlight: a record with an HTLC still 'offered' (or
 * 'onchain-pending') stays PENDING, and only a ghost, a PENDING record with
 * nothing out for it, is failed as before.
 *
 * Loopback pair, as in repay-completed-hash.test.ts: bob holds alice's HTLC
 * on a hold invoice and settles it when the test says so.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	IPaymentRetryContext,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`timeout-in-flight-seed-${id}`))
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

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

const CHANNEL_SCID = encodeShortChannelId({
	block: 500,
	txIndex: 1,
	outputIndex: 0
});

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
	alice.registerChannelScid(channelId, CHANNEL_SCID);
	return { alice, bob };
}

/** The hashes of the payment:sent and payment:failed events a node emits from now on. */
function recordEvents(node: LightningNode): {
	sent: string[];
	failed: string[];
} {
	const sent: string[] = [];
	const failed: string[] = [];
	node.on('payment:sent', (info: IPaymentInfo) =>
		sent.push(info.paymentHash.toString('hex'))
	);
	node.on('payment:failed', (info: IPaymentInfo) =>
		failed.push(info.paymentHash.toString('hex'))
	);
	return { sent, failed };
}

/** The message a wait rejected with, or '' if it resolved. */
async function rejectionOf(wait: Promise<unknown>): Promise<string> {
	try {
		await wait;
		return '';
	} catch (err: unknown) {
		return err instanceof Error ? err.message : String(err);
	}
}

/**
 * A BOLT 11 encoding of the same hash issued two hours ago with a one-hour
 * expiry: what the expiry scanner decodes from the retry context.
 */
function expiredEncoding(
	paymentHash: Buffer,
	paymentSecret: Buffer,
	payeeSeed: number
): string {
	return encodeInvoice({
		network: Network.REGTEST,
		paymentHash,
		paymentSecret,
		timestamp: Math.floor(Date.now() / 1000) - 7200,
		expiry: 3600,
		description: 'expired',
		minFinalCltvExpiry: 40,
		amountMsat: 50_000n,
		privateKey: makeNodeConfig(payeeSeed).nodePrivateKey
	});
}

type Internals = {
	paymentRetryContexts: Map<string, IPaymentRetryContext>;
	payments: Map<string, IPaymentInfo>;
	scanExpiredPendingPayments: () => void;
};
const internals = (node: LightningNode): Internals =>
	node as unknown as Internals;

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

describe('Issue #976: a wall clock does not fail a payment whose HTLC is still out', () => {
	it('sendPaymentAsync times out with the HTLC held, leaves the record PENDING, and the payment completes when bob settles', async () => {
		const { alice, bob } = setupPair(960, 961);
		const events = recordEvents(alice);
		// Bob parks the HTLC on a hold invoice: the payee settles when told.
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'held',
			hold: true
		});
		const hash = invoice.paymentHash;

		const message = await rejectionOf(
			alice.sendPaymentAsync(invoice.bolt11, 50)
		);
		expect(message).to.equal(
			'Payment timed out after 50ms; an HTLC is still in flight and the payment stays PENDING until it resolves'
		);
		// Before the fix failPayment ran at the timeout: the record read
		// FAILED and payment:failed fired while bob still held the HTLC.
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		expect(alice.hasHtlcInFlight(hash)).to.equal(true);
		expect(events.failed).to.deep.equal([]);
		expect(events.sent).to.deep.equal([]);

		expect(bob.settleHeldHtlc(hash), 'bob settled the held HTLC').to.equal(
			true
		);
		const record = alice.getPayment(hash);
		expect(record?.status).to.equal(PaymentStatus.COMPLETED);
		expect(record?.preimage && sha256(record.preimage).equals(hash)).to.equal(
			true
		);
		expect(events.sent).to.deep.equal([hash.toString('hex')]);
		expect(events.failed).to.deep.equal([]);
		expect(alice.hasHtlcInFlight(hash)).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('sendPaymentAsync times out on a ghost record, with nothing out for it, and fails it as before', async () => {
		const { alice, bob } = setupPair(962, 963);
		const events = recordEvents(alice);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'ghost'
		});
		const hash = invoice.paymentHash;
		const hashHex = hash.toString('hex');
		// A send that records the payment and offers nothing.
		const record: IPaymentInfo = {
			paymentHash: hash,
			amountMsat: 50_000n,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now()
		};
		(alice as unknown as { sendPayment: () => IPaymentInfo }).sendPayment =
			(): IPaymentInfo => {
				internals(alice).payments.set(hashHex, record);
				return record;
			};

		const message = await rejectionOf(
			alice.sendPaymentAsync(invoice.bolt11, 50)
		);
		expect(message).to.equal('Payment timed out after 50ms');
		expect(alice.hasHtlcInFlight(hash)).to.equal(false);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.FAILED);
		expect(alice.getPayment(hash)?.failureReason).to.equal(
			'No resolution within the 50ms wait window'
		);
		expect(events.failed).to.deep.equal([hashHex]);

		alice.destroy();
		bob.destroy();
	});

	it('the expiry scanner leaves an expired invoice PENDING while its HTLC is out, and the payment completes when bob settles', () => {
		const { alice, bob } = setupPair(964, 965);
		const events = recordEvents(alice);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'held past expiry',
			hold: true
		});
		const hash = invoice.paymentHash;
		const hashHex = hash.toString('hex');

		expect(alice.sendPayment(invoice.bolt11).status).to.equal(
			PaymentStatus.PENDING
		);
		expect(alice.hasHtlcInFlight(hash)).to.equal(true);
		// The invoice expires while bob holds the HTLC: the scanner reads the
		// expiry from the retry context's invoice string.
		const contexts = internals(alice).paymentRetryContexts;
		const context = contexts.get(hashHex);
		expect(context, 'the send left a retry context').to.not.equal(undefined);
		context!.invoiceStr = expiredEncoding(hash, invoice.paymentSecret, 965);

		internals(alice).scanExpiredPendingPayments();

		// Before the fix the scanner failed it here, HTLC or no HTLC.
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		expect(contexts.has(hashHex), 'the retry context is kept').to.equal(true);
		expect(events.failed).to.deep.equal([]);

		expect(bob.settleHeldHtlc(hash)).to.equal(true);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(events.sent).to.deep.equal([hashHex]);
		expect(events.failed).to.deep.equal([]);

		alice.destroy();
		bob.destroy();
	});

	it('the expiry scanner still fails an expired invoice with nothing out for it', () => {
		const alice = createNode(966);
		const events = recordEvents(alice);
		const hash = crypto.randomBytes(32);
		const hashHex = hash.toString('hex');
		internals(alice).payments.set(hashHex, {
			paymentHash: hash,
			amountMsat: 50_000n,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now() - 7200_000
		});
		const contexts = internals(alice).paymentRetryContexts;
		contexts.set(hashHex, {
			invoiceStr: expiredEncoding(hash, crypto.randomBytes(32), 967),
			excludedChannels: new Set(),
			retryCount: 0,
			maxRetries: 2
		} as unknown as IPaymentRetryContext);
		expect(alice.hasHtlcInFlight(hash)).to.equal(false);

		internals(alice).scanExpiredPendingPayments();

		const record = alice.getPayment(hash);
		expect(record?.status).to.equal(PaymentStatus.FAILED);
		expect(record?.failureReason).to.equal(
			'Invoice expired while the payment was still pending'
		);
		expect(contexts.has(hashHex)).to.equal(false);
		expect(events.failed).to.deep.equal([hashHex]);

		alice.destroy();
	});
});
