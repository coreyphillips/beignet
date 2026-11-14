/**
 * BOLT 11 `m` field / BOLT 4 payment_metadata (TLV 16), issue #1998.
 *
 * The payer returns the invoice's metadata in every HTLC's final payload,
 * and a beignet invoice issued with metadata is paid only by HTLCs that
 * carry the same bytes.
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
import type { IHopPayload } from '../../src/lightning/onion/types';
import {
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	ROUTING_INFO_LENGTH
} from '../../src/lightning/onion/types';
import {
	decodeHopPayload,
	encodeHopPayload
} from '../../src/lightning/onion/hop-payload';
import {
	constructOnionPacket,
	onionPayloadBytes
} from '../../src/lightning/onion/construct';
import { Network } from '../../src/lightning/invoice/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import type { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Feature } from '../../src/lightning/features/flags';
import { MessageType } from '../../src/lightning/message/types';
import type { IRoute } from '../../src/lightning/gossip/types';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`payment-metadata-seed-${id}`))
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
	const hash = (tag: Buffer): Buffer =>
		crypto.createHash('sha256').update(seed).update(tag).digest();
	return {
		nodePrivateKey: hash(Buffer.from('node-identity')),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: hash(Buffer.from([0])),
		htlcBasepointSecret: hash(Buffer.from([4]))
	};
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
	amount = 1_000_000n
): Buffer {
	const ch = alice.openChannel(bob.getNodeId(), amount);
	const channelId = alice.createFunding(
		ch,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

/** Every final payload the node's receive path is handed. */
function captureFinalPayloads(node: LightningNode): IHopPayload[] {
	const seen: IHopPayload[] = [];
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const n = node as any;
	const original = n.handleFinalHopHtlc.bind(n);
	n.handleFinalHopHtlc = (...args: unknown[]): void => {
		seen.push(args[4] as IHopPayload);
		original(...args);
	};
	return seen;
}

/** The same invoice signed again by its payee with a different `m` field. */
function resignWithMetadata(
	bolt11: string,
	payeePrivkey: Buffer,
	metadata: Buffer | undefined
): string {
	const inv = decodeInvoice(bolt11);
	return encodeInvoice({
		network: inv.network,
		amountMsat: inv.amountMsat,
		timestamp: inv.timestamp,
		paymentHash: inv.paymentHash,
		paymentSecret: inv.paymentSecret,
		description: inv.description,
		expiry: inv.expiry,
		minFinalCltvExpiry: inv.minFinalCltvExpiry,
		routingHints: inv.routingHints,
		featureBits: inv.featureBits,
		payeeNodeKey: inv.payeeNodeKey,
		metadata,
		privateKey: payeePrivkey
	});
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 50));

describe('payment_metadata (BOLT 11 m field, onion TLV 16) (#1998)', function () {
	describe('hop payload codec', function () {
		const finalPayload: IHopPayload = {
			amountToForwardMsat: 25_000_000n,
			outgoingCltvValue: 800_123,
			paymentSecret: Buffer.alloc(32, 7),
			totalMsat: 50_000_000n,
			paymentMetadata: Buffer.from('0102abcdef', 'hex')
		};

		it('writes record 16 in type order and decodes it back', function () {
			const encoded = encodeHopPayload(finalPayload);
			// type 8 (payment_data, 32 + 4 bytes), then type 16 (5 bytes)
			const record16 = Buffer.from('10050102abcdef', 'hex');
			const at = encoded.indexOf(record16);
			expect(at, 'record 16 present').to.be.greaterThan(0);
			expect(at, 'record 16 is the last record').to.equal(
				encoded.length - record16.length
			);

			const { payload, bytesRead } = decodeHopPayload(encoded, 0);
			expect(bytesRead).to.equal(encoded.length);
			expect(payload.paymentMetadata).to.deep.equal(
				finalPayload.paymentMetadata
			);
			expect(payload.paymentSecret).to.deep.equal(finalPayload.paymentSecret);
			expect(payload.totalMsat).to.equal(finalPayload.totalMsat);
			expect(payload.customRecords).to.equal(undefined);
		});

		it('keeps an empty record 16 distinct from an absent one', function () {
			const withEmpty = decodeHopPayload(
				encodeHopPayload({ ...finalPayload, paymentMetadata: Buffer.alloc(0) }),
				0
			).payload;
			expect(withEmpty.paymentMetadata).to.deep.equal(Buffer.alloc(0));
			const without = decodeHopPayload(
				encodeHopPayload({ ...finalPayload, paymentMetadata: undefined }),
				0
			).payload;
			expect(without).to.not.have.property('paymentMetadata');
		});
	});

	describe('onion size', function () {
		const hop = (
			paymentMetadata?: Buffer
		): { pubkey: Buffer; payload: IHopPayload } => ({
			pubkey: getPublicKey(crypto.randomBytes(32)),
			payload: {
				amountToForwardMsat: 1000n,
				outgoingCltvValue: 500,
				paymentSecret: Buffer.alloc(32, 1),
				totalMsat: 1000n,
				paymentMetadata
			} as IHopPayload
		});

		it('counts each payload with its HMAC', function () {
			const h = hop(Buffer.alloc(10));
			expect(onionPayloadBytes([h.payload])).to.equal(
				encodeHopPayload(h.payload).length + 32
			);
		});

		it('refuses to build an onion whose payloads exceed the routing info', function () {
			expect(() =>
				constructOnionPacket(crypto.randomBytes(32), [hop(Buffer.alloc(1300))])
			).to.throw(/payment onion holds 1300/);
			// The largest metadata that fits one hop still builds, one more
			// byte does not.
			let n = 0;
			while (
				onionPayloadBytes([hop(Buffer.alloc(n + 1)).payload]) <=
				ROUTING_INFO_LENGTH
			) {
				n++;
			}
			expect(() =>
				constructOnionPacket(crypto.randomBytes(32), [hop(Buffer.alloc(n))])
			).to.not.throw();
			expect(() =>
				constructOnionPacket(crypto.randomBytes(32), [hop(Buffer.alloc(n + 1))])
			).to.throw(/payment onion holds 1300/);
		});
	});

	describe('createInvoice', function () {
		it('writes the m field and feature bit 49, and records the bytes', function () {
			const bob = new LightningNode(makeNodeConfig(1));
			const metadata = Buffer.from('opaque recipient state');
			const created = bob.createInvoice({
				description: 'metadata invoice',
				amountMsat: 1_000_000n,
				paymentMetadata: metadata
			});
			const inv = decodeInvoice(created.bolt11);
			expect(inv.metadata).to.deep.equal(metadata);
			expect(inv.featureBits!.isOptional(Feature.PAYMENT_METADATA)).to.equal(
				true
			);
			expect(inv.featureBits!.hasBit(Feature.PAYMENT_METADATA)).to.equal(false);
			expect(
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				(bob as any).invoices.get(created.paymentHash.toString('hex'))
					.paymentMetadata
			).to.equal(metadata.toString('hex'));

			const plain = decodeInvoice(
				bob.createInvoice({ description: 'plain', amountMsat: 1000n }).bolt11
			);
			expect(plain.metadata).to.equal(undefined);
			expect(plain.featureBits!.hasFeature(Feature.PAYMENT_METADATA)).to.equal(
				false
			);
			bob.destroy();
		});

		it('refuses empty or oversized metadata before registering anything', function () {
			const bob = new LightningNode(makeNodeConfig(2));
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const secrets = (bob as any).paymentSecrets as Map<string, Buffer>;
			expect(() =>
				bob.createInvoice({
					description: 'x',
					paymentMetadata: Buffer.alloc(0)
				})
			).to.throw(/paymentMetadata must be 1 to 639 bytes/);
			expect(() =>
				bob.createInvoice({
					description: 'x',
					paymentMetadata: Buffer.alloc(640)
				})
			).to.throw(/paymentMetadata must be 1 to 639 bytes/);
			expect(secrets.size).to.equal(0);
			const largest = bob.createInvoice({
				description: 'x',
				paymentMetadata: Buffer.alloc(639, 9)
			});
			expect(decodeInvoice(largest.bolt11).metadata).to.deep.equal(
				Buffer.alloc(639, 9)
			);
			bob.destroy();
		});
	});

	describe('two beignet nodes', function () {
		let alice: LightningNode;
		let bob: LightningNode;
		const bobPrivkey = makeNodeConfig(11).nodePrivateKey;

		beforeEach(function () {
			alice = new LightningNode(makeNodeConfig(10));
			bob = new LightningNode(makeNodeConfig(11));
			connectNodes(alice, bob);
		});

		afterEach(function () {
			alice.destroy();
			bob.destroy();
		});

		it('a single-path payment carries the metadata and settles', async function () {
			openReadyChannel(alice, bob);
			const seen = captureFinalPayloads(bob);
			const metadata = crypto.randomBytes(48);
			const invoice = bob.createInvoice({
				description: 'single path',
				amountMsat: 20_000_000n,
				paymentMetadata: metadata
			});

			alice.sendPayment(invoice.bolt11);
			await settle();

			expect(seen).to.have.length(1);
			expect(seen[0].paymentMetadata).to.deep.equal(metadata);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(bob.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('every MPP part carries the same metadata and the set settles', async function () {
			openReadyChannel(alice, bob, 200_000n);
			openReadyChannel(alice, bob, 200_000n);
			const seen = captureFinalPayloads(bob);
			const metadata = crypto.randomBytes(100);
			const invoice = bob.createInvoice({
				description: 'mpp',
				amountMsat: 250_000_000n,
				paymentMetadata: metadata
			});

			alice.sendPayment(invoice.bolt11);
			await settle();

			expect(seen.length, 'the payment was split').to.be.at.least(2);
			for (const payload of seen) {
				expect(payload.paymentMetadata).to.deep.equal(metadata);
				expect(payload.totalMsat).to.equal(250_000_000n);
			}
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			const received = bob.getPayment(invoice.paymentHash)!;
			expect(received.status).to.equal(PaymentStatus.COMPLETED);
			expect(received.settledHtlcs).to.have.length(seen.length);
		});

		it('fails an HTLC whose metadata differs from or omits the invoice m field', async function () {
			openReadyChannel(alice, bob);
			const seen = captureFinalPayloads(bob);
			const metadata = Buffer.from('the real metadata');
			const invoice = bob.createInvoice({
				description: 'tamper target',
				amountMsat: 20_000_000n,
				paymentMetadata: metadata
			});

			for (const altered of [Buffer.from('the fake metadata'), undefined]) {
				const forged = resignWithMetadata(invoice.bolt11, bobPrivkey, altered);
				const failed = alice.sendPayment(forged);
				await settle();
				const record = alice.getPayment(failed.paymentHash)!;
				expect(record.status).to.equal(PaymentStatus.FAILED);
				expect(record.failureCode).to.equal(
					INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
				);
				expect(bob.getPayment(invoice.paymentHash)!.status).to.equal(
					PaymentStatus.PENDING
				);
			}
			expect(seen.map((p) => p.paymentMetadata)).to.deep.equal([
				Buffer.from('the fake metadata'),
				undefined
			]);

			// The genuine invoice still pays.
			alice.sendPayment(invoice.bolt11);
			await settle();
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(bob.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('ignores record 16 for an invoice issued without metadata', async function () {
			openReadyChannel(alice, bob);
			const seen = captureFinalPayloads(bob);
			const invoice = bob.createInvoice({
				description: 'no metadata',
				amountMsat: 20_000_000n
			});
			const withM = resignWithMetadata(
				invoice.bolt11,
				bobPrivkey,
				Buffer.from('unasked for')
			);

			alice.sendPayment(withM);
			await settle();

			expect(seen[0].paymentMetadata).to.deep.equal(Buffer.from('unasked for'));
			expect(bob.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it('refuses metadata that cannot fit the onion before any HTLC leaves', async function () {
			openReadyChannel(alice, bob);
			let adds = 0;
			alice.on('message:outbound', (_pk: string, type: number) => {
				if (type === MessageType.UPDATE_ADD_HTLC) adds++;
			});

			// A payee twelve hops past bob, reached through the invoice's
			// routing hints, with the largest m field BOLT 11 allows: the route
			// is found, but its payloads cannot share 1300 bytes (eleven hops
			// still fit).
			const relays = Array.from({ length: 11 }, () =>
				getPublicKey(crypto.randomBytes(32))
			);
			const payeePrivkey = crypto.randomBytes(32);
			const forwarders = [Buffer.from(bob.getNodeId(), 'hex'), ...relays];
			const paymentHash = crypto.randomBytes(32);
			const bolt11 = encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 10_000_000n,
				paymentHash,
				paymentSecret: crypto.randomBytes(32),
				description: 'long route',
				minFinalCltvExpiry: 18,
				routingHints: [
					forwarders.map((pubkey, i) => ({
						pubkey,
						shortChannelId: Buffer.from([0, 0, 1, 0, 0, i + 1, 0, 0]),
						feeBaseMsat: 0,
						feeProportionalMillionths: 0,
						cltvExpiryDelta: 18
					}))
				],
				metadata: Buffer.alloc(639, 1),
				payeeNodeKey: getPublicKey(payeePrivkey),
				privateKey: payeePrivkey
			});

			let thrown: unknown;
			try {
				alice.sendPayment(bolt11);
			} catch (err) {
				thrown = err;
			}
			expect(thrown).to.be.instanceOf(LightningPaymentError);
			expect((thrown as LightningPaymentError).code).to.equal(
				LightningErrorCode.NO_ROUTE
			);
			expect((thrown as Error).message).to.match(
				/payment_metadata is 639 bytes/
			);
			await settle();
			expect(adds).to.equal(0);
			expect(alice.getPayment(paymentHash)).to.equal(undefined);
			expect(
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				(alice as any).paymentRetryContexts.has(paymentHash.toString('hex'))
			).to.equal(false);
		});

		it('refuses an MPP split with a part that cannot fit before any part leaves', function () {
			openReadyChannel(alice, bob);
			let adds = 0;
			alice.on('message:outbound', (_pk: string, type: number) => {
				if (type === MessageType.UPDATE_ADD_HTLC) adds++;
			});
			const hop = (pubkey: Buffer, amount: bigint): IRoute['hops'][number] => ({
				pubkey,
				shortChannelId: crypto.randomBytes(8),
				amountToForwardMsat: amount,
				outgoingCltvValue: 18,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 18
			});
			const part = (hops: IRoute['hops']): IRoute => ({
				hops,
				totalAmountMsat: hops[0].amountToForwardMsat,
				totalCltvDelta: 18,
				totalFeeMsat: 0n
			});
			const bobKey = Buffer.from(bob.getNodeId(), 'hex');
			const carolKey = getPublicKey(crypto.randomBytes(32));
			const paymentSecret = crypto.randomBytes(32);
			// The largest metadata a one-hop part can carry: the first part
			// fits, the second needs room for an extra hop and does not.
			let size = 0;
			while (
				onionPayloadBytes([
					{
						amountToForwardMsat: 1_000_000n,
						outgoingCltvValue: 18,
						paymentSecret,
						totalMsat: 2_000_000n,
						paymentMetadata: Buffer.alloc(size + 1)
					}
				]) <= ROUTING_INFO_LENGTH
			) {
				size++;
			}
			const paymentHash = crypto.randomBytes(32);
			expect(() =>
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				(alice as any).sendPaymentMpp(
					'lnbcrt1unused',
					{
						paymentHash,
						paymentSecret,
						paymentMetadata: Buffer.alloc(size),
						amountMsat: 2_000_000n
					},
					{
						parts: [
							part([hop(bobKey, 1_000_000n)]),
							part([hop(bobKey, 1_000_000n), hop(carolKey, 1_000_000n)])
						],
						totalAmountMsat: 2_000_000n,
						totalFeeMsat: 0n
					},
					18
				)
			).to.throw(new RegExp(`payment_metadata is ${size} bytes`));
			expect(adds).to.equal(0);
			expect(alice.getPayment(paymentHash)).to.equal(undefined);
		});
	});
});
