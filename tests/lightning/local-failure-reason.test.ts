/**
 * Local payment failures must say WHY.
 *
 * A payment that fails before its HTLC ever reaches the network has no onion
 * failure to decrypt, so failureCode is undefined. That used to be the whole
 * story: the daemon logged a lone `failureCode: undefined`, which reads like a
 * decoding bug rather than "your peer is unreachable". The reason was available
 * all along, since ChannelManager.addHtlc returns it, and was being discarded.
 *
 * failureReason carries it, and is deliberately distinct from failureCode so a
 * local failure can never be mistaken for a remote one.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	serializePaymentInfo,
	deserializePaymentInfo
} from '../../src/lightning/storage/serialization';
import { PaymentDirection } from '../../src/lightning/node/types';

// Node construction mirrors tests/lightning/forwarding-history.test.ts: the
// basepoints must be derived from the same secrets the node signs with, or the
// funding handshake never completes on the acceptor side.
function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`local-failure-seed-${id}`))
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

let seedCounter = 0;

function makeNode(): LightningNode {
	const seedId = seedCounter++;
	const seed = makeSeed(seedId);
	const derive = (label: string | number[]): Buffer =>
		crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from(label as never))
			.digest();

	const node = new LightningNode({
		nodePrivateKey: derive('node-identity'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 1000),
		fundingPrivkey: derive([0]),
		htlcBasepointSecret: derive([4])
	});
	node.on('node:error', () => {
		/* ignore */
	});
	return node;
}

describe('Local payment failure reasons', function () {
	let node: LightningNode;

	beforeEach(function () {
		node = makeNode();
	});

	afterEach(function () {
		node.destroy();
	});

	describe('failPayment', function () {
		function pendingPayment(target: LightningNode): Buffer {
			const paymentHash = crypto.randomBytes(32);
			(target as any).payments.set(paymentHash.toString('hex'), {
				paymentHash,
				amountMsat: 1_000_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now()
			});
			return paymentHash;
		}

		it('records the caller supplied reason', function () {
			const paymentHash = pendingPayment(node);

			node.failPayment(paymentHash, 'Peer not found for channel: abcd');

			const payment = node.getPayment(paymentHash)!;
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(payment.failureCode, 'a local failure has no onion code').to.be
				.undefined;
			expect(payment.failureReason).to.equal(
				'Peer not found for channel: abcd'
			);
		});

		it('falls back to a generic reason rather than leaving nothing', function () {
			const paymentHash = pendingPayment(node);

			node.failPayment(paymentHash);

			expect(node.getPayment(paymentHash)!.failureReason).to.equal(
				'Payment failed locally'
			);
		});

		it('emits payment:failed carrying the reason', function (done) {
			const paymentHash = pendingPayment(node);

			node.on('payment:failed', (info) => {
				try {
					expect(info.failureReason).to.equal('Stuck payment swept');
					done();
				} catch (err) {
					done(err);
				}
			});

			node.failPayment(paymentHash, 'Stuck payment swept');
		});

		it('does not overwrite a real onion failure code', function () {
			// A remote failure already explains itself. failureReason exists for the
			// case where nothing else does, so it must not paper over a real code.
			const paymentHash = crypto.randomBytes(32);
			(node as any).payments.set(paymentHash.toString('hex'), {
				paymentHash,
				amountMsat: 1_000_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				failureCode: 0x400a,
				createdAt: Date.now()
			});

			node.failPayment(paymentHash, 'should not appear');

			const payment = node.getPayment(paymentHash)!;
			expect(payment.failureCode).to.equal(0x400a);
			expect(payment.failureReason).to.be.undefined;
		});
	});

	describe('HTLC that never leaves the node', function () {
		/** alice with a real channel to bob, wired in-process. */
		function twoNodes(): {
			alice: LightningNode;
			bob: LightningNode;
		} {
			const alice = makeNode();
			const bob = makeNode();
			for (const [from, to] of [
				[alice, bob],
				[bob, alice]
			] as const) {
				from.on(
					'message:outbound',
					(pubkey: string, type: number, payload: Buffer) => {
						if (pubkey === to.getNodeId()) {
							to.handlePeerMessage(from.getNodeId(), type, payload);
						}
					}
				);
			}
			const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			return { alice, bob };
		}

		it('reports the addHtlc error instead of a bare undefined code', function () {
			// This is the reported production shape: the route resolves, but the
			// HTLC cannot be added locally because the peer is unreachable. There is
			// no onion failure to decrypt, so without failureReason the daemon logs
			// `failureCode: undefined` and nothing else.
			const { alice, bob } = twoNodes();
			try {
				const invoice = bob.createInvoice({
					amountMsat: 100_000n,
					description: 'local-fail'
				});

				(alice as any).channelManager.addHtlc = () => ({
					ok: false,
					actions: [],
					error: 'Peer not found for channel: deadbeef'
				});

				const failures: Array<{
					failureCode?: number;
					failureReason?: string;
				}> = [];
				alice.on('payment:failed', (info) => failures.push(info));

				alice.sendPayment(invoice.bolt11);

				expect(failures, 'payment:failed must fire').to.have.length(1);
				expect(failures[0].failureCode, 'no HTLC reached the network').to.be
					.undefined;
				expect(failures[0].failureReason).to.equal(
					'Peer not found for channel: deadbeef'
				);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});

		it('still explains itself when addHtlc gives no error string', function () {
			const { alice, bob } = twoNodes();
			try {
				const invoice = bob.createInvoice({
					amountMsat: 100_000n,
					description: 'local-fail-bare'
				});

				(alice as any).channelManager.addHtlc = () => ({
					ok: false,
					actions: []
				});

				const failures: Array<{ failureReason?: string }> = [];
				alice.on('payment:failed', (info) => failures.push(info));

				alice.sendPayment(invoice.bolt11);

				expect(failures).to.have.length(1);
				expect(failures[0].failureReason).to.equal(
					'Local failure: could not add HTLC to the channel'
				);
			} finally {
				alice.destroy();
				bob.destroy();
			}
		});
	});

	describe('persistence', function () {
		it('survives a serialize/deserialize round trip', function () {
			// Without this the reason is lost on restart and the payment reads as a
			// bare FAILED with no explanation, which is the state being fixed.
			const original = {
				paymentHash: crypto.randomBytes(32),
				amountMsat: 1_000_000n,
				status: PaymentStatus.FAILED,
				direction: PaymentDirection.OUTGOING,
				failureReason: 'Peer not found for channel: abcd',
				createdAt: Date.now(),
				completedAt: Date.now()
			};

			const restored = deserializePaymentInfo(serializePaymentInfo(original));

			expect(restored.failureReason).to.equal(
				'Peer not found for channel: abcd'
			);
		});
	});
});
