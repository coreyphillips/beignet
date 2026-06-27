/**
 * Phase 2: TLV Onion Payloads + Payment Secret (BOLT 4) tests.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	encodeHopPayload,
	decodeHopPayload,
	encodeTruncatedUint,
	decodeTruncatedUint
} from '../../src/lightning/onion/hop-payload';
import { IHopPayload } from '../../src/lightning/onion/types';
import {
	constructOnionPacket,
	encodeOnionPacket,
	decodeOnionPacket
} from '../../src/lightning/onion/construct';
import {
	processOnionPacket,
	isFinalHop
} from '../../src/lightning/onion/process';
import { computeSharedSecrets } from '../../src/lightning/onion/sphinx-crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Feature } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: crypto.randomBytes(33),
		revocationBasepoint: crypto.randomBytes(33),
		paymentBasepoint: crypto.randomBytes(33),
		delayedPaymentBasepoint: crypto.randomBytes(33),
		htlcBasepoint: crypto.randomBytes(33),
		firstPerCommitmentPoint: crypto.randomBytes(33)
	};
}

describe('TLV Onion Payloads + Payment Secret (BOLT 4)', function () {
	describe('encodeHopPayload / decodeHopPayload', function () {
		it('should encode and decode payload without payment_data (backward compatible)', function () {
			const payload: IHopPayload = {
				amountToForwardMsat: 50_000n,
				outgoingCltvValue: 144,
				shortChannelId: Buffer.from('0000000000000001', 'hex')
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded, bytesRead } = decodeHopPayload(encoded, 0);

			expect(decoded.amountToForwardMsat).to.equal(50_000n);
			expect(decoded.outgoingCltvValue).to.equal(144);
			expect(decoded.shortChannelId).to.not.be.undefined;
			expect(decoded.shortChannelId!.toString('hex')).to.equal(
				'0000000000000001'
			);
			expect(decoded.paymentSecret).to.be.undefined;
			expect(decoded.totalMsat).to.be.undefined;
			expect(bytesRead).to.equal(encoded.length);
		});

		it('should encode and decode payload with payment_data (TLV type 8)', function () {
			const secret = crypto.randomBytes(32);
			const payload: IHopPayload = {
				amountToForwardMsat: 100_000n,
				outgoingCltvValue: 40,
				paymentSecret: secret,
				totalMsat: 100_000n
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded, bytesRead } = decodeHopPayload(encoded, 0);

			expect(decoded.amountToForwardMsat).to.equal(100_000n);
			expect(decoded.outgoingCltvValue).to.equal(40);
			expect(decoded.shortChannelId).to.be.undefined;
			expect(decoded.paymentSecret).to.not.be.undefined;
			expect(decoded.paymentSecret!.equals(secret)).to.be.true;
			expect(decoded.totalMsat).to.equal(100_000n);
			expect(bytesRead).to.equal(encoded.length);
		});

		it('should encode payment_data with default totalMsat from amountToForwardMsat', function () {
			const secret = crypto.randomBytes(32);
			const payload: IHopPayload = {
				amountToForwardMsat: 75_000n,
				outgoingCltvValue: 20,
				paymentSecret: secret
				// totalMsat not set — should default to amountToForwardMsat
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded } = decodeHopPayload(encoded, 0);

			expect(decoded.paymentSecret!.equals(secret)).to.be.true;
			expect(decoded.totalMsat).to.equal(75_000n);
		});

		it('should encode TLV types in strictly increasing order (2, 4, 6, 8)', function () {
			const secret = crypto.randomBytes(32);
			const payload: IHopPayload = {
				amountToForwardMsat: 1000n,
				outgoingCltvValue: 10,
				shortChannelId: Buffer.alloc(8),
				paymentSecret: secret,
				totalMsat: 1000n
			};

			const encoded = encodeHopPayload(payload);
			// Skip the length prefix byte(s) and parse TLV types
			const { value: payloadLen, bytesRead: lenBytes } = decodeBigSize(
				encoded,
				0
			);
			let offset = lenBytes;
			const payloadEnd = offset + Number(payloadLen);
			const types: number[] = [];
			while (offset < payloadEnd) {
				const { value: tlvType, bytesRead: typBytes } = decodeBigSize(
					encoded,
					offset
				);
				offset += typBytes;
				const { value: tlvLen, bytesRead: lenB } = decodeBigSize(
					encoded,
					offset
				);
				offset += lenB + Number(tlvLen);
				types.push(Number(tlvType));
			}
			expect(types).to.deep.equal([2, 4, 6, 8]);
		});

		it('should handle payment_data with large totalMsat', function () {
			const secret = crypto.randomBytes(32);
			const payload: IHopPayload = {
				amountToForwardMsat: 500_000n,
				outgoingCltvValue: 100,
				paymentSecret: secret,
				totalMsat: 1_000_000_000_000n // 1M sats
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded } = decodeHopPayload(encoded, 0);

			expect(decoded.totalMsat).to.equal(1_000_000_000_000n);
		});

		it('should not include type 8 when paymentSecret is not set', function () {
			const payload: IHopPayload = {
				amountToForwardMsat: 1000n,
				outgoingCltvValue: 10
			};

			const encoded = encodeHopPayload(payload);
			// Verify type 8 is not present by decoding and checking
			const { payload: decoded } = decodeHopPayload(encoded, 0);
			expect(decoded.paymentSecret).to.be.undefined;
			expect(decoded.totalMsat).to.be.undefined;
		});

		it('should handle zero totalMsat in payment_data', function () {
			const secret = crypto.randomBytes(32);
			const payload: IHopPayload = {
				amountToForwardMsat: 1000n,
				outgoingCltvValue: 10,
				paymentSecret: secret,
				totalMsat: 0n
			};

			const encoded = encodeHopPayload(payload);
			const { payload: decoded } = decodeHopPayload(encoded, 0);
			expect(decoded.paymentSecret!.equals(secret)).to.be.true;
			expect(decoded.totalMsat).to.equal(0n);
		});
	});

	describe('truncated uint encoding', function () {
		it('should encode and decode various values', function () {
			const values = [0n, 1n, 255n, 256n, 65535n, 100_000n, 1_000_000_000_000n];
			for (const v of values) {
				const encoded = encodeTruncatedUint(v);
				const decoded = decodeTruncatedUint(encoded);
				expect(decoded).to.equal(v, `Round-trip failed for ${v}`);
			}
		});

		it('should use minimal encoding (no leading zeros)', function () {
			expect(encodeTruncatedUint(255n).length).to.equal(1);
			expect(encodeTruncatedUint(256n).length).to.equal(2);
			expect(encodeTruncatedUint(0n).length).to.equal(0);
		});
	});

	describe('Onion construction with payment_secret', function () {
		it('should construct and process a multi-hop onion with payment_secret on final hop', function () {
			const sessionKey = crypto.randomBytes(32);
			const secret = crypto.randomBytes(32);

			// 3 hops: intermediate → intermediate → final
			const hops: { pubkey: Buffer; payload: IHopPayload }[] = [];
			const privkeys: Buffer[] = [];
			for (let i = 0; i < 3; i++) {
				const priv = crypto.randomBytes(32);
				// Use proper EC public key derivation
				const { getPublicKey } = require('../../src/lightning/crypto/ecdh');
				const pub = getPublicKey(priv);
				privkeys.push(priv);

				const isFinal = i === 2;
				const payload: IHopPayload = {
					amountToForwardMsat: BigInt(100_000 - i * 10),
					outgoingCltvValue: 144 - i * 10
				};
				if (!isFinal) {
					payload.shortChannelId = Buffer.alloc(8);
					payload.shortChannelId.writeUInt32BE(i + 1, 4);
				} else {
					payload.paymentSecret = secret;
					payload.totalMsat = 100_000n;
				}
				hops.push({ pubkey: pub, payload });
			}

			const packet = constructOnionPacket(sessionKey, hops);
			const encodedBuf = encodeOnionPacket(packet);

			// Process at each hop
			let currentPacket = decodeOnionPacket(encodedBuf);
			for (let i = 0; i < 3; i++) {
				const result = processOnionPacket(currentPacket, privkeys[i]);

				if (i < 2) {
					// Intermediate: should have SCID, no payment_secret
					expect(result.hopPayload.shortChannelId).to.not.be.undefined;
					expect(result.hopPayload.paymentSecret).to.be.undefined;
					expect(isFinalHop(result.nextPacket)).to.be.false;
					currentPacket = result.nextPacket;
				} else {
					// Final: should have payment_secret, no SCID
					expect(result.hopPayload.shortChannelId).to.be.undefined;
					expect(result.hopPayload.paymentSecret).to.not.be.undefined;
					expect(result.hopPayload.paymentSecret!.equals(secret)).to.be.true;
					expect(result.hopPayload.totalMsat).to.equal(100_000n);
					expect(isFinalHop(result.nextPacket)).to.be.true;
				}
			}
		});

		it('should produce correct filler with variable-size final hop (payment_data)', function () {
			// The payment_data TLV makes the final hop payload larger.
			// Verify that the onion still constructs and processes correctly.
			const sessionKey = crypto.randomBytes(32);
			const secret = crypto.randomBytes(32);
			const { getPublicKey } = require('../../src/lightning/crypto/ecdh');

			const priv1 = crypto.randomBytes(32);
			const priv2 = crypto.randomBytes(32);
			const pub1 = getPublicKey(priv1);
			const pub2 = getPublicKey(priv2);

			const hops = [
				{
					pubkey: pub1,
					payload: {
						amountToForwardMsat: 50_000n,
						outgoingCltvValue: 144,
						shortChannelId: Buffer.from('0000000100000001', 'hex')
					} as IHopPayload
				},
				{
					pubkey: pub2,
					payload: {
						amountToForwardMsat: 49_000n,
						outgoingCltvValue: 40,
						paymentSecret: secret,
						totalMsat: 49_000n
					} as IHopPayload
				}
			];

			const packet = constructOnionPacket(sessionKey, hops);
			const encodedBuf = encodeOnionPacket(packet);

			// First hop processes
			const decoded = decodeOnionPacket(encodedBuf);
			const result1 = processOnionPacket(decoded, priv1);
			expect(result1.hopPayload.shortChannelId).to.not.be.undefined;
			expect(result1.hopPayload.paymentSecret).to.be.undefined;
			expect(isFinalHop(result1.nextPacket)).to.be.false;

			// Second hop processes
			const result2 = processOnionPacket(result1.nextPacket, priv2);
			expect(result2.hopPayload.paymentSecret!.equals(secret)).to.be.true;
			expect(result2.hopPayload.totalMsat).to.equal(49_000n);
			expect(isFinalHop(result2.nextPacket)).to.be.true;
		});

		it('should compute shared secrets correctly with payment_secret payload', function () {
			const sessionKey = crypto.randomBytes(32);
			const { getPublicKey } = require('../../src/lightning/crypto/ecdh');

			const priv = crypto.randomBytes(32);
			const pub = getPublicKey(priv);

			const { sharedSecrets } = computeSharedSecrets(sessionKey, [pub]);
			expect(sharedSecrets).to.have.length(1);
			expect(sharedSecrets[0]).to.have.length(32);
		});
	});

	describe('LightningNode payment secret integration', function () {
		function createTestNode(): LightningNode {
			return new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: makeBasepoints(),
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});
		}

		it('should include PAYMENT_SECRET in default features', function () {
			const features = LightningNode.defaultFeatures();
			expect(features.hasFeature(Feature.PAYMENT_SECRET)).to.be.true;
			expect(features.isCompulsory(Feature.PAYMENT_SECRET)).to.be.true;
		});

		it('should store payment secret when creating invoice', function () {
			const node = createTestNode();
			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test payment'
			});

			// Decode the invoice to get the payment hash
			const { decode } = require('../../src/lightning/invoice/decode');
			const decoded = decode(invoice.bolt11);

			expect(decoded.paymentSecret).to.not.be.undefined;
			expect(decoded.paymentSecret).to.have.length(32);

			// Verify that the node stored the payment secret
			const payment = node.getPayment(decoded.paymentHash);
			expect(payment).to.not.be.undefined;

			node.destroy();
		});

		it('should clean up paymentSecrets on destroy', function () {
			const node = createTestNode();
			node.createInvoice({ amountMsat: 1000n, description: 'test' });
			// No direct way to check map size from outside, but destroy should not throw
			node.destroy();
		});
	});
});

// Helper: decodeBigSize for TLV type ordering test
function decodeBigSize(
	buf: Buffer,
	offset: number
): { value: bigint; bytesRead: number } {
	const first = buf[offset];
	if (first < 0xfd) {
		return { value: BigInt(first), bytesRead: 1 };
	} else if (first === 0xfd) {
		return { value: BigInt(buf.readUInt16BE(offset + 1)), bytesRead: 3 };
	} else if (first === 0xfe) {
		return { value: BigInt(buf.readUInt32BE(offset + 1)), bytesRead: 5 };
	} else {
		return { value: buf.readBigUInt64BE(offset + 1), bytesRead: 9 };
	}
}
