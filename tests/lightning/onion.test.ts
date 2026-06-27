/**
 * BOLT 4: Onion Routing — Tests
 *
 * Tests for Sphinx crypto primitives, hop payload encoding/decoding,
 * onion packet construction/processing, failure handling, and barrel exports.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	// Types & constants
	IHopPayload,
	IOnionPacket,
	ONION_PACKET_LENGTH,
	ROUTING_INFO_LENGTH,
	ONION_VERSION,
	HOP_DATA_LEGACY_LENGTH,
	INVALID_ONION_VERSION,
	INVALID_ONION_HMAC,
	INVALID_ONION_KEY,
	AMOUNT_BELOW_MINIMUM,
	FEE_INSUFFICIENT,
	INCORRECT_CLTV_EXPIRY,
	EXPIRY_TOO_SOON,
	UNKNOWN_NEXT_PEER,
	TEMPORARY_CHANNEL_FAILURE,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	FINAL_INCORRECT_CLTV_EXPIRY,
	FINAL_INCORRECT_HTLC_AMOUNT,
	// Sphinx crypto
	generateSharedSecret,
	computeBlindingFactor,
	deriveHopKeys,
	generateCipherStream,
	computeSharedSecrets,
	// Hop payload
	encodeTruncatedUint,
	decodeTruncatedUint,
	encodeHopPayload,
	decodeHopPayload,
	// Construction
	generateFiller,
	constructOnionPacket,
	encodeOnionPacket,
	decodeOnionPacket,
	// Processing
	processOnionPacket,
	isFinalHop,
	// Failures
	encodeFailurePayload,
	createFailureMessage,
	wrapFailureMessage,
	decryptFailureMessage,
	decodeFailureCode
} from '../../src/lightning/onion';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';

// ── Helpers ─────────────────────────────────────────────────────────

function randomPrivkey(): Buffer {
	let key: Buffer;
	do {
		key = crypto.randomBytes(32);
	} while (key[0] === 0); // Avoid degenerate keys
	return key;
}

function makeSCID(block: number, tx: number, output: number): Buffer {
	return encodeShortChannelId({ block, txIndex: tx, outputIndex: output });
}

/**
 * Create a multi-hop test route with N intermediate hops + 1 final hop.
 */
function createTestRoute(hopCount: number): {
	sessionKey: Buffer;
	hopKeys: Buffer[];
	hopPubkeys: Buffer[];
	hops: { pubkey: Buffer; payload: IHopPayload }[];
} {
	const sessionKey = randomPrivkey();
	const hopKeys: Buffer[] = [];
	const hopPubkeys: Buffer[] = [];

	for (let i = 0; i < hopCount; i++) {
		const key = randomPrivkey();
		hopKeys.push(key);
		hopPubkeys.push(getPublicKey(key));
	}

	const baseAmount = 1000000n; // 1M msat
	const baseCltv = 500;

	const hops: { pubkey: Buffer; payload: IHopPayload }[] = [];
	for (let i = 0; i < hopCount; i++) {
		const isFinal = i === hopCount - 1;
		hops.push({
			pubkey: hopPubkeys[i],
			payload: {
				amountToForwardMsat: baseAmount - BigInt(i) * 1000n,
				outgoingCltvValue: baseCltv - i * 10,
				...(isFinal ? {} : { shortChannelId: makeSCID(700000 + i, i + 1, 0) })
			}
		});
	}

	return { sessionKey, hopKeys, hopPubkeys, hops };
}

// ── Sphinx Crypto ───────────────────────────────────────────────────

describe('BOLT 4: Onion Routing', () => {
	describe('Sphinx Crypto', () => {
		it('should generate deterministic shared secrets', () => {
			const sessionKey = randomPrivkey();
			const hopKey = randomPrivkey();
			const hopPub = getPublicKey(hopKey);

			const ss1 = generateSharedSecret(sessionKey, hopPub);
			const ss2 = generateSharedSecret(sessionKey, hopPub);
			expect(ss1.equals(ss2)).to.be.true;
			expect(ss1.length).to.equal(32);
		});

		it('should produce different shared secrets for different session keys', () => {
			const hopKey = randomPrivkey();
			const hopPub = getPublicKey(hopKey);

			const ss1 = generateSharedSecret(randomPrivkey(), hopPub);
			const ss2 = generateSharedSecret(randomPrivkey(), hopPub);
			expect(ss1.equals(ss2)).to.be.false;
		});

		it('should produce different shared secrets for different hop pubkeys', () => {
			const sessionKey = randomPrivkey();
			const pub1 = getPublicKey(randomPrivkey());
			const pub2 = getPublicKey(randomPrivkey());

			const ss1 = generateSharedSecret(sessionKey, pub1);
			const ss2 = generateSharedSecret(sessionKey, pub2);
			expect(ss1.equals(ss2)).to.be.false;
		});

		it('should compute deterministic blinding factors', () => {
			const ephKey = getPublicKey(randomPrivkey());
			const ss = crypto.randomBytes(32);

			const bf1 = computeBlindingFactor(ephKey, ss);
			const bf2 = computeBlindingFactor(ephKey, ss);
			expect(bf1.equals(bf2)).to.be.true;
			expect(bf1.length).to.equal(32);
		});

		it('should produce different blinding factors for different inputs', () => {
			const ephKey = getPublicKey(randomPrivkey());
			const ss1 = crypto.randomBytes(32);
			const ss2 = crypto.randomBytes(32);

			const bf1 = computeBlindingFactor(ephKey, ss1);
			const bf2 = computeBlindingFactor(ephKey, ss2);
			expect(bf1.equals(bf2)).to.be.false;
		});

		it('should derive 5 distinct 32-byte hop keys', () => {
			const ss = crypto.randomBytes(32);
			const keys = deriveHopKeys(ss);

			expect(keys.rho.length).to.equal(32);
			expect(keys.mu.length).to.equal(32);
			expect(keys.pad.length).to.equal(32);
			expect(keys.um.length).to.equal(32);
			expect(keys.ammag.length).to.equal(32);

			// All keys should be different
			const allKeys = [keys.rho, keys.mu, keys.pad, keys.um, keys.ammag];
			for (let i = 0; i < allKeys.length; i++) {
				for (let j = i + 1; j < allKeys.length; j++) {
					expect(allKeys[i].equals(allKeys[j])).to.be.false;
				}
			}
		});

		it('should derive deterministic hop keys', () => {
			const ss = crypto.randomBytes(32);
			const keys1 = deriveHopKeys(ss);
			const keys2 = deriveHopKeys(ss);
			expect(keys1.rho.equals(keys2.rho)).to.be.true;
			expect(keys1.mu.equals(keys2.mu)).to.be.true;
		});

		it('should generate cipher stream of correct length', () => {
			const key = crypto.randomBytes(32);
			const stream = generateCipherStream(key, 1300);
			expect(stream.length).to.equal(1300);
		});

		it('should generate deterministic cipher streams', () => {
			const key = crypto.randomBytes(32);
			const s1 = generateCipherStream(key, 100);
			const s2 = generateCipherStream(key, 100);
			expect(s1.equals(s2)).to.be.true;
		});

		it('should generate different cipher streams for different keys', () => {
			const s1 = generateCipherStream(crypto.randomBytes(32), 100);
			const s2 = generateCipherStream(crypto.randomBytes(32), 100);
			expect(s1.equals(s2)).to.be.false;
		});

		it('should compute shared secrets for a multi-hop path', () => {
			const sessionKey = randomPrivkey();
			const hops = [randomPrivkey(), randomPrivkey(), randomPrivkey()].map(
				(k) => getPublicKey(k)
			);

			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hops
			);

			expect(sharedSecrets.length).to.equal(3);
			expect(ephemeralKeys.length).to.equal(3);

			// All shared secrets should be different
			for (let i = 0; i < sharedSecrets.length; i++) {
				expect(sharedSecrets[i].length).to.equal(32);
				for (let j = i + 1; j < sharedSecrets.length; j++) {
					expect(sharedSecrets[i].equals(sharedSecrets[j])).to.be.false;
				}
			}
		});

		it('should have first ephemeral key equal to sessionKey pubkey', () => {
			const sessionKey = randomPrivkey();
			const hops = [randomPrivkey(), randomPrivkey()].map((k) =>
				getPublicKey(k)
			);

			const { ephemeralKeys } = computeSharedSecrets(sessionKey, hops);
			const expectedPub = getPublicKey(sessionKey);
			expect(ephemeralKeys[0].equals(expectedPub)).to.be.true;
		});

		it('should produce all different ephemeral keys', () => {
			const sessionKey = randomPrivkey();
			const hops = [randomPrivkey(), randomPrivkey(), randomPrivkey()].map(
				(k) => getPublicKey(k)
			);

			const { ephemeralKeys } = computeSharedSecrets(sessionKey, hops);
			for (let i = 0; i < ephemeralKeys.length; i++) {
				for (let j = i + 1; j < ephemeralKeys.length; j++) {
					expect(ephemeralKeys[i].equals(ephemeralKeys[j])).to.be.false;
				}
			}
		});

		it('should have consistent shared secrets between sender and hop', () => {
			// The shared secret that the sender derives for hop N must equal
			// the shared secret that hop N derives when it processes the onion
			const sessionKey = randomPrivkey();
			const hop1Key = randomPrivkey();
			const hop1Pub = getPublicKey(hop1Key);

			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				[hop1Pub]
			);

			// The hop derives the same shared secret using its private key and the ephemeral key
			const hopDerivedSecret = generateSharedSecret(hop1Key, ephemeralKeys[0]);
			expect(sharedSecrets[0].equals(hopDerivedSecret)).to.be.true;
		});

		it('should have consistent shared secrets at second hop', () => {
			const sessionKey = randomPrivkey();
			const hop1Key = randomPrivkey();
			const hop2Key = randomPrivkey();
			const hops = [getPublicKey(hop1Key), getPublicKey(hop2Key)];

			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hops
			);

			// Hop 2 receives ephemeralKeys[1] and derives shared secret with its private key
			const hop2DerivedSecret = generateSharedSecret(hop2Key, ephemeralKeys[1]);
			expect(sharedSecrets[1].equals(hop2DerivedSecret)).to.be.true;
		});
	});

	// ── Hop Payload ─────────────────────────────────────────────────

	describe('Hop Payload', () => {
		describe('Truncated Uint', () => {
			it('should encode 0 as empty buffer', () => {
				const buf = encodeTruncatedUint(0n);
				expect(buf.length).to.equal(0);
			});

			it('should decode empty buffer as 0', () => {
				expect(decodeTruncatedUint(Buffer.alloc(0))).to.equal(0n);
			});

			it('should encode 1 as 1 byte', () => {
				const buf = encodeTruncatedUint(1n);
				expect(buf.length).to.equal(1);
				expect(buf[0]).to.equal(1);
			});

			it('should encode 255 as 1 byte', () => {
				const buf = encodeTruncatedUint(255n);
				expect(buf.length).to.equal(1);
				expect(buf[0]).to.equal(255);
			});

			it('should encode 256 as 2 bytes', () => {
				const buf = encodeTruncatedUint(256n);
				expect(buf.length).to.equal(2);
				expect(buf[0]).to.equal(1);
				expect(buf[1]).to.equal(0);
			});

			it('should round-trip large values', () => {
				const value = 0x0123456789abcdefn;
				const buf = encodeTruncatedUint(value);
				expect(decodeTruncatedUint(buf)).to.equal(value);
			});

			it('should round-trip 1000 (0x03E8) as 2 bytes', () => {
				const buf = encodeTruncatedUint(1000n);
				expect(buf.length).to.equal(2);
				expect(decodeTruncatedUint(buf)).to.equal(1000n);
			});

			it('should round-trip values > 32-bit', () => {
				const value = 5000000000n;
				const buf = encodeTruncatedUint(value);
				expect(decodeTruncatedUint(buf)).to.equal(value);
			});
		});

		describe('Encode/Decode', () => {
			it('should round-trip an intermediate hop payload', () => {
				const scid = makeSCID(700000, 1, 0);
				const payload: IHopPayload = {
					amountToForwardMsat: 500000n,
					outgoingCltvValue: 144,
					shortChannelId: scid
				};
				const encoded = encodeHopPayload(payload);
				const { payload: decoded, bytesRead } = decodeHopPayload(encoded, 0);

				expect(decoded.amountToForwardMsat).to.equal(500000n);
				expect(decoded.outgoingCltvValue).to.equal(144);
				expect(decoded.shortChannelId).to.not.be.undefined;
				expect(decoded.shortChannelId!.equals(scid)).to.be.true;
				expect(bytesRead).to.equal(encoded.length);
			});

			it('should round-trip a final hop payload (no short_channel_id)', () => {
				const payload: IHopPayload = {
					amountToForwardMsat: 1000000n,
					outgoingCltvValue: 40
				};
				const encoded = encodeHopPayload(payload);
				const { payload: decoded, bytesRead } = decodeHopPayload(encoded, 0);

				expect(decoded.amountToForwardMsat).to.equal(1000000n);
				expect(decoded.outgoingCltvValue).to.equal(40);
				expect(decoded.shortChannelId).to.be.undefined;
				expect(bytesRead).to.equal(encoded.length);
			});

			it('should have TLV types in ascending order', () => {
				const payload: IHopPayload = {
					amountToForwardMsat: 100n,
					outgoingCltvValue: 10,
					shortChannelId: makeSCID(1, 1, 0)
				};
				const encoded = encodeHopPayload(payload);

				// Skip BigSize length prefix, then read first TLV type
				// The first byte after length should be type 2
				const lengthPrefixSize = encoded[0] < 0xfd ? 1 : 3;
				expect(encoded[lengthPrefixSize]).to.equal(2); // First TLV type
			});

			it('should encode final hop payload smaller than intermediate', () => {
				const intermediate: IHopPayload = {
					amountToForwardMsat: 1000n,
					outgoingCltvValue: 144,
					shortChannelId: makeSCID(1, 1, 0)
				};
				const final_: IHopPayload = {
					amountToForwardMsat: 1000n,
					outgoingCltvValue: 144
				};

				const intEncoded = encodeHopPayload(intermediate);
				const finEncoded = encodeHopPayload(final_);
				expect(finEncoded.length).to.be.lessThan(intEncoded.length);
			});

			it('should handle large amounts (> 32-bit)', () => {
				const payload: IHopPayload = {
					amountToForwardMsat: 5000000000000n, // 5 trillion msat
					outgoingCltvValue: 200
				};
				const encoded = encodeHopPayload(payload);
				const { payload: decoded } = decodeHopPayload(encoded, 0);
				expect(decoded.amountToForwardMsat).to.equal(5000000000000n);
			});

			it('should decode from a non-zero offset', () => {
				const payload: IHopPayload = {
					amountToForwardMsat: 42n,
					outgoingCltvValue: 10
				};
				const encoded = encodeHopPayload(payload);
				const padded = Buffer.concat([Buffer.alloc(5), encoded]);
				const { payload: decoded, bytesRead } = decodeHopPayload(padded, 5);
				expect(decoded.amountToForwardMsat).to.equal(42n);
				expect(bytesRead).to.equal(encoded.length);
			});
		});
	});

	// ── Onion Construction ──────────────────────────────────────────

	describe('Onion Construction', () => {
		it('should construct a single-hop packet of correct size', () => {
			const { sessionKey, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);

			expect(packet.version).to.equal(ONION_VERSION);
			expect(packet.ephemeralKey.length).to.equal(33);
			expect(packet.routingInfo.length).to.equal(ROUTING_INFO_LENGTH);
			expect(packet.hmac.length).to.equal(32);
		});

		it('should construct a 2-hop packet', () => {
			const { sessionKey, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);

			expect(packet.routingInfo.length).to.equal(ROUTING_INFO_LENGTH);
			expect(packet.hmac.length).to.equal(32);
		});

		it('should construct a 3-hop packet', () => {
			const { sessionKey, hops } = createTestRoute(3);
			const packet = constructOnionPacket(sessionKey, hops);

			expect(packet.routingInfo.length).to.equal(ROUTING_INFO_LENGTH);
		});

		it('should construct a 5-hop packet', () => {
			const { sessionKey, hops } = createTestRoute(5);
			const packet = constructOnionPacket(sessionKey, hops);

			expect(packet.routingInfo.length).to.equal(ROUTING_INFO_LENGTH);
		});

		it('should produce different routing info for different hop counts', () => {
			const hops2 = createTestRoute(2);
			const hops3 = createTestRoute(3);

			const p2 = constructOnionPacket(hops2.sessionKey, hops2.hops);
			const p3 = constructOnionPacket(hops3.sessionKey, hops3.hops);
			expect(p2.routingInfo.equals(p3.routingInfo)).to.be.false;
		});

		it('should set version to 0', () => {
			const { sessionKey, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);
			expect(packet.version).to.equal(0);
		});

		it('should use first ephemeral key as session pubkey', () => {
			const { sessionKey, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);
			expect(packet.ephemeralKey.equals(getPublicKey(sessionKey))).to.be.true;
		});

		it('should throw on empty hops', () => {
			expect(() => constructOnionPacket(randomPrivkey(), [])).to.throw(
				'At least one hop'
			);
		});

		it('should generate filler of correct length', () => {
			const { sessionKey, hops } = createTestRoute(3);
			const hopPubkeys = hops.map((h) => h.pubkey);
			const { sharedSecrets } = computeSharedSecrets(sessionKey, hopPubkeys);
			const payloadSizes = hops.map((h) => encodeHopPayload(h.payload).length);

			const filler = generateFiller(sharedSecrets, payloadSizes);
			// Filler covers hops 0..n-2, each contributing (payloadSize + 32) bytes
			let expectedLen = 0;
			for (let i = 0; i < hops.length - 1; i++) {
				expectedLen += payloadSizes[i] + 32;
			}
			expect(filler.length).to.equal(expectedLen);
		});

		it('should generate deterministic filler', () => {
			const { sessionKey, hops } = createTestRoute(3);
			const hopPubkeys = hops.map((h) => h.pubkey);
			const { sharedSecrets } = computeSharedSecrets(sessionKey, hopPubkeys);
			const payloadSizes = hops.map((h) => encodeHopPayload(h.payload).length);

			const f1 = generateFiller(sharedSecrets, payloadSizes);
			const f2 = generateFiller(sharedSecrets, payloadSizes);
			expect(f1.equals(f2)).to.be.true;
		});

		it('should serialize/deserialize onion packet round-trip', () => {
			const { sessionKey, hops } = createTestRoute(3);
			const packet = constructOnionPacket(sessionKey, hops);
			const encoded = encodeOnionPacket(packet);

			expect(encoded.length).to.equal(ONION_PACKET_LENGTH);

			const decoded = decodeOnionPacket(encoded);
			expect(decoded.version).to.equal(packet.version);
			expect(decoded.ephemeralKey.equals(packet.ephemeralKey)).to.be.true;
			expect(decoded.routingInfo.equals(packet.routingInfo)).to.be.true;
			expect(decoded.hmac.equals(packet.hmac)).to.be.true;
		});

		it('should reject deserializing wrong-size buffer', () => {
			expect(() => decodeOnionPacket(Buffer.alloc(100))).to.throw('1366 bytes');
		});

		it('should produce non-zero HMAC for constructed packets', () => {
			const { sessionKey, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);
			expect(packet.hmac.equals(Buffer.alloc(32))).to.be.false;
		});

		it('should produce consistent packets (deterministic)', () => {
			const { sessionKey, hops } = createTestRoute(2);
			const p1 = constructOnionPacket(sessionKey, hops);
			const p2 = constructOnionPacket(sessionKey, hops);
			expect(p1.routingInfo.equals(p2.routingInfo)).to.be.true;
			expect(p1.hmac.equals(p2.hmac)).to.be.true;
		});

		it('should encode version byte at position 0', () => {
			const { sessionKey, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);
			const encoded = encodeOnionPacket(packet);
			expect(encoded[0]).to.equal(0);
		});

		it('should encode ephemeral key at positions 1-33', () => {
			const { sessionKey, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);
			const encoded = encodeOnionPacket(packet);
			const ephKey = encoded.subarray(1, 34);
			expect(ephKey.equals(packet.ephemeralKey)).to.be.true;
		});

		it('should encode HMAC at positions 1334-1365', () => {
			const { sessionKey, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);
			const encoded = encodeOnionPacket(packet);
			const hmac = encoded.subarray(1334, 1366);
			expect(hmac.equals(packet.hmac)).to.be.true;
		});
	});

	// ── Onion Processing ────────────────────────────────────────────

	describe('Onion Processing', () => {
		it('should process a single-hop packet to reveal final payload', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);

			const result = processOnionPacket(packet, hopKeys[0]);
			expect(result.hopPayload.amountToForwardMsat).to.equal(
				hops[0].payload.amountToForwardMsat
			);
			expect(result.hopPayload.outgoingCltvValue).to.equal(
				hops[0].payload.outgoingCltvValue
			);
			expect(result.hopPayload.shortChannelId).to.be.undefined; // Final hop
		});

		it('should detect final hop (zero HMAC) after single-hop processing', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);

			const result = processOnionPacket(packet, hopKeys[0]);
			expect(isFinalHop(result.nextPacket)).to.be.true;
		});

		it('should process first hop of multi-hop and reveal correct payload', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(3);
			const packet = constructOnionPacket(sessionKey, hops);

			const result = processOnionPacket(packet, hopKeys[0]);
			expect(result.hopPayload.amountToForwardMsat).to.equal(
				hops[0].payload.amountToForwardMsat
			);
			expect(result.hopPayload.outgoingCltvValue).to.equal(
				hops[0].payload.outgoingCltvValue
			);
			expect(result.hopPayload.shortChannelId).to.not.be.undefined;
			expect(
				result.hopPayload.shortChannelId!.equals(
					hops[0].payload.shortChannelId!
				)
			).to.be.true;
		});

		it('should not show final hop on intermediate hops', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(3);
			const packet = constructOnionPacket(sessionKey, hops);

			const result = processOnionPacket(packet, hopKeys[0]);
			expect(isFinalHop(result.nextPacket)).to.be.false;
		});

		it('should process full 2-hop pipeline', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);

			// Hop 1: intermediate
			const r1 = processOnionPacket(packet, hopKeys[0]);
			expect(r1.hopPayload.amountToForwardMsat).to.equal(
				hops[0].payload.amountToForwardMsat
			);
			expect(r1.hopPayload.shortChannelId).to.not.be.undefined;
			expect(isFinalHop(r1.nextPacket)).to.be.false;

			// Hop 2: final
			const r2 = processOnionPacket(r1.nextPacket, hopKeys[1]);
			expect(r2.hopPayload.amountToForwardMsat).to.equal(
				hops[1].payload.amountToForwardMsat
			);
			expect(r2.hopPayload.shortChannelId).to.be.undefined;
			expect(isFinalHop(r2.nextPacket)).to.be.true;
		});

		it('should process full 3-hop pipeline', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(3);
			const packet = constructOnionPacket(sessionKey, hops);

			const r1 = processOnionPacket(packet, hopKeys[0]);
			expect(r1.hopPayload.amountToForwardMsat).to.equal(
				hops[0].payload.amountToForwardMsat
			);
			expect(isFinalHop(r1.nextPacket)).to.be.false;

			const r2 = processOnionPacket(r1.nextPacket, hopKeys[1]);
			expect(r2.hopPayload.amountToForwardMsat).to.equal(
				hops[1].payload.amountToForwardMsat
			);
			expect(isFinalHop(r2.nextPacket)).to.be.false;

			const r3 = processOnionPacket(r2.nextPacket, hopKeys[2]);
			expect(r3.hopPayload.amountToForwardMsat).to.equal(
				hops[2].payload.amountToForwardMsat
			);
			expect(isFinalHop(r3.nextPacket)).to.be.true;
		});

		it('should process full 5-hop pipeline', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(5);
			const packet = constructOnionPacket(sessionKey, hops);

			let current: IOnionPacket = packet;
			for (let i = 0; i < 5; i++) {
				const result = processOnionPacket(current, hopKeys[i]);
				expect(result.hopPayload.amountToForwardMsat).to.equal(
					hops[i].payload.amountToForwardMsat
				);
				expect(result.hopPayload.outgoingCltvValue).to.equal(
					hops[i].payload.outgoingCltvValue
				);

				if (i < 4) {
					expect(result.hopPayload.shortChannelId).to.not.be.undefined;
					expect(isFinalHop(result.nextPacket)).to.be.false;
				} else {
					expect(result.hopPayload.shortChannelId).to.be.undefined;
					expect(isFinalHop(result.nextPacket)).to.be.true;
				}
				current = result.nextPacket;
			}
		});

		it('should reject tampered routing info (HMAC failure)', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);

			// Tamper with routing info
			packet.routingInfo[0] ^= 0xff;

			expect(() => processOnionPacket(packet, hopKeys[0])).to.throw(
				'HMAC verification failed'
			);
		});

		it('should reject tampered HMAC', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);

			// Tamper with HMAC
			packet.hmac[0] ^= 0xff;

			expect(() => processOnionPacket(packet, hopKeys[0])).to.throw(
				'HMAC verification failed'
			);
		});

		it('should reject wrong private key', () => {
			const { sessionKey, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);

			const wrongKey = randomPrivkey();
			expect(() => processOnionPacket(packet, wrongKey)).to.throw(
				'HMAC verification failed'
			);
		});

		it('should reject invalid onion version', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(1);
			const packet = constructOnionPacket(sessionKey, hops);
			packet.version = 1;

			expect(() => processOnionPacket(packet, hopKeys[0])).to.throw(
				'Invalid onion version'
			);
		});

		it('should preserve amounts and CLTVs at each hop', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(3);
			const packet = constructOnionPacket(sessionKey, hops);

			let current: IOnionPacket = packet;
			for (let i = 0; i < 3; i++) {
				const result = processOnionPacket(current, hopKeys[i]);
				const expected = hops[i].payload;
				expect(result.hopPayload.amountToForwardMsat).to.equal(
					expected.amountToForwardMsat
				);
				expect(result.hopPayload.outgoingCltvValue).to.equal(
					expected.outgoingCltvValue
				);
				current = result.nextPacket;
			}
		});

		it('should produce valid next packet at each intermediate hop', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(3);
			const packet = constructOnionPacket(sessionKey, hops);

			const r1 = processOnionPacket(packet, hopKeys[0]);
			expect(r1.nextPacket.version).to.equal(ONION_VERSION);
			expect(r1.nextPacket.ephemeralKey.length).to.equal(33);
			expect(r1.nextPacket.routingInfo.length).to.equal(ROUTING_INFO_LENGTH);

			const r2 = processOnionPacket(r1.nextPacket, hopKeys[1]);
			expect(r2.nextPacket.version).to.equal(ONION_VERSION);
			expect(r2.nextPacket.ephemeralKey.length).to.equal(33);
		});

		it('should blind ephemeral key between hops', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);

			const r1 = processOnionPacket(packet, hopKeys[0]);
			// Next ephemeral key should be different from the first
			expect(r1.nextPacket.ephemeralKey.equals(packet.ephemeralKey)).to.be
				.false;
		});

		it('should serialize and deserialize between hops', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(2);
			const packet = constructOnionPacket(sessionKey, hops);

			// Serialize, deserialize, then process
			const encoded = encodeOnionPacket(packet);
			const decoded = decodeOnionPacket(encoded);

			const r1 = processOnionPacket(decoded, hopKeys[0]);
			expect(r1.hopPayload.amountToForwardMsat).to.equal(
				hops[0].payload.amountToForwardMsat
			);

			const r2 = processOnionPacket(r1.nextPacket, hopKeys[1]);
			expect(r2.hopPayload.amountToForwardMsat).to.equal(
				hops[1].payload.amountToForwardMsat
			);
			expect(isFinalHop(r2.nextPacket)).to.be.true;
		});

		it('isFinalHop should return false for non-zero HMAC', () => {
			const packet: IOnionPacket = {
				version: 0,
				ephemeralKey: Buffer.alloc(33, 2),
				routingInfo: Buffer.alloc(1300),
				hmac: crypto.randomBytes(32)
			};
			expect(isFinalHop(packet)).to.be.false;
		});

		it('isFinalHop should return true for zero HMAC', () => {
			const packet: IOnionPacket = {
				version: 0,
				ephemeralKey: Buffer.alloc(33, 2),
				routingInfo: Buffer.alloc(1300),
				hmac: Buffer.alloc(32)
			};
			expect(isFinalHop(packet)).to.be.true;
		});
	});

	// ── Failure Handling ────────────────────────────────────────────

	describe('Failure Handling', () => {
		it('should encode failure payload as 256 bytes', () => {
			const payload = encodeFailurePayload(TEMPORARY_CHANNEL_FAILURE);
			expect(payload.length).to.equal(256);
			expect(payload.readUInt16BE(0)).to.equal(TEMPORARY_CHANNEL_FAILURE);
		});

		it('should encode failure with data', () => {
			const data = Buffer.from('test data');
			const payload = encodeFailurePayload(FEE_INSUFFICIENT, data);
			expect(payload.length).to.equal(256);
			expect(payload.readUInt16BE(0)).to.equal(FEE_INSUFFICIENT);
			expect(payload.subarray(2, 2 + data.length).equals(data)).to.be.true;
		});

		it('should reject oversized failure data', () => {
			const tooLarge = Buffer.alloc(255); // 2 + 255 > 256
			expect(() => encodeFailurePayload(0, tooLarge)).to.throw('too large');
		});

		it('should create a 290-byte failure message', () => {
			const ss = crypto.randomBytes(32);
			const msg = createFailureMessage(ss, UNKNOWN_NEXT_PEER);
			expect(msg.length).to.equal(290);
		});

		it('should wrap and unwrap failure at single hop', () => {
			const sessionKey = randomPrivkey();
			const hopKey = randomPrivkey();
			const hopPub = getPublicKey(hopKey);

			const { sharedSecrets } = computeSharedSecrets(sessionKey, [hopPub]);

			// Hop creates failure using its derived shared secret
			const hopSecret = generateSharedSecret(hopKey, getPublicKey(sessionKey));
			const msg = createFailureMessage(hopSecret, TEMPORARY_CHANNEL_FAILURE);

			// Sender decrypts
			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(0);
			expect(result!.failure.failureCode).to.equal(TEMPORARY_CHANNEL_FAILURE);
		});

		it('should handle multi-hop wrap/unwrap correctly', () => {
			const { sessionKey, hopKeys, hopPubkeys } = createTestRoute(3);
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hopPubkeys
			);

			// Failure originates at hop 2 (index 2)
			const hop2Secret = generateSharedSecret(hopKeys[2], ephemeralKeys[2]);
			let msg = createFailureMessage(
				hop2Secret,
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);

			// Hop 1 wraps
			const hop1Secret = generateSharedSecret(hopKeys[1], ephemeralKeys[1]);
			msg = wrapFailureMessage(hop1Secret, msg);

			// Hop 0 wraps
			const hop0Secret = generateSharedSecret(hopKeys[0], ephemeralKeys[0]);
			msg = wrapFailureMessage(hop0Secret, msg);

			// Sender decrypts
			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(2);
			expect(result!.failure.failureCode).to.equal(
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);
		});

		it('should identify correct origin hop in 5-hop route', () => {
			const { sessionKey, hopKeys, hopPubkeys } = createTestRoute(5);
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hopPubkeys
			);

			// Failure at hop 3
			const failHopIdx = 3;
			const failHopSecret = generateSharedSecret(
				hopKeys[failHopIdx],
				ephemeralKeys[failHopIdx]
			);
			let msg = createFailureMessage(failHopSecret, EXPIRY_TOO_SOON);

			// Wrap backwards through hops 2, 1, 0
			for (let i = failHopIdx - 1; i >= 0; i--) {
				const hopSecret = generateSharedSecret(hopKeys[i], ephemeralKeys[i]);
				msg = wrapFailureMessage(hopSecret, msg);
			}

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(failHopIdx);
			expect(result!.failure.failureCode).to.equal(EXPIRY_TOO_SOON);
		});

		it('should return null for tampered message', () => {
			const { sessionKey, hopKeys, hopPubkeys } = createTestRoute(2);
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hopPubkeys
			);

			const hopSecret = generateSharedSecret(hopKeys[0], ephemeralKeys[0]);
			const msg = createFailureMessage(hopSecret, TEMPORARY_CHANNEL_FAILURE);

			// Tamper
			msg[10] ^= 0xff;

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.be.null;
		});

		it('should preserve failure data through encode/decode', () => {
			const { sessionKey, hopKeys, hopPubkeys } = createTestRoute(1);
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hopPubkeys
			);

			const failData = Buffer.from([0x01, 0x02, 0x03, 0x04]);
			const hopSecret = generateSharedSecret(hopKeys[0], ephemeralKeys[0]);
			const msg = createFailureMessage(
				hopSecret,
				AMOUNT_BELOW_MINIMUM,
				failData
			);

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.failure.failureCode).to.equal(AMOUNT_BELOW_MINIMUM);
			expect(result!.failure.failureData.equals(failData)).to.be.true;
		});

		it('should decode known failure codes', () => {
			expect(decodeFailureCode(INVALID_ONION_VERSION).name).to.equal(
				'invalid_onion_version'
			);
			expect(decodeFailureCode(INVALID_ONION_HMAC).name).to.equal(
				'invalid_onion_hmac'
			);
			expect(decodeFailureCode(INVALID_ONION_KEY).name).to.equal(
				'invalid_onion_key'
			);
			expect(decodeFailureCode(AMOUNT_BELOW_MINIMUM).name).to.equal(
				'amount_below_minimum'
			);
			expect(decodeFailureCode(FEE_INSUFFICIENT).name).to.equal(
				'fee_insufficient'
			);
			expect(decodeFailureCode(INCORRECT_CLTV_EXPIRY).name).to.equal(
				'incorrect_cltv_expiry'
			);
			expect(decodeFailureCode(EXPIRY_TOO_SOON).name).to.equal(
				'expiry_too_soon'
			);
			expect(decodeFailureCode(UNKNOWN_NEXT_PEER).name).to.equal(
				'unknown_next_peer'
			);
			expect(decodeFailureCode(TEMPORARY_CHANNEL_FAILURE).name).to.equal(
				'temporary_channel_failure'
			);
			expect(
				decodeFailureCode(INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS).name
			).to.equal('incorrect_or_unknown_payment_details');
			expect(decodeFailureCode(FINAL_INCORRECT_CLTV_EXPIRY).name).to.equal(
				'final_incorrect_cltv_expiry'
			);
			expect(decodeFailureCode(FINAL_INCORRECT_HTLC_AMOUNT).name).to.equal(
				'final_incorrect_htlc_amount'
			);
		});

		it('should indicate channel_update presence for relevant codes', () => {
			expect(decodeFailureCode(AMOUNT_BELOW_MINIMUM).hasChannelUpdate).to.be
				.true;
			expect(decodeFailureCode(FEE_INSUFFICIENT).hasChannelUpdate).to.be.true;
			expect(decodeFailureCode(INCORRECT_CLTV_EXPIRY).hasChannelUpdate).to.be
				.true;
			expect(decodeFailureCode(EXPIRY_TOO_SOON).hasChannelUpdate).to.be.true;
			expect(decodeFailureCode(TEMPORARY_CHANNEL_FAILURE).hasChannelUpdate).to
				.be.true;
		});

		it('should indicate no channel_update for node-level failures', () => {
			expect(decodeFailureCode(INVALID_ONION_VERSION).hasChannelUpdate).to.be
				.false;
			expect(decodeFailureCode(UNKNOWN_NEXT_PEER).hasChannelUpdate).to.be.false;
			expect(
				decodeFailureCode(INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS).hasChannelUpdate
			).to.be.false;
			expect(decodeFailureCode(FINAL_INCORRECT_CLTV_EXPIRY).hasChannelUpdate).to
				.be.false;
		});

		it('should handle unknown failure codes', () => {
			const result = decodeFailureCode(9999);
			expect(result.name).to.include('unknown');
			expect(result.hasChannelUpdate).to.be.false;
		});
	});

	// ── Integration ─────────────────────────────────────────────────

	describe('Integration', () => {
		it('should export all types from barrel', () => {
			// Types are compile-time only, but constants prove the export works
			expect(ONION_PACKET_LENGTH).to.equal(1366);
			expect(ROUTING_INFO_LENGTH).to.equal(1300);
			expect(ONION_VERSION).to.equal(0);
			expect(HOP_DATA_LEGACY_LENGTH).to.equal(32);
		});

		it('should export all functions from barrel', () => {
			expect(typeof generateSharedSecret).to.equal('function');
			expect(typeof computeBlindingFactor).to.equal('function');
			expect(typeof deriveHopKeys).to.equal('function');
			expect(typeof generateCipherStream).to.equal('function');
			expect(typeof computeSharedSecrets).to.equal('function');
			expect(typeof encodeTruncatedUint).to.equal('function');
			expect(typeof decodeTruncatedUint).to.equal('function');
			expect(typeof encodeHopPayload).to.equal('function');
			expect(typeof decodeHopPayload).to.equal('function');
			expect(typeof constructOnionPacket).to.equal('function');
			expect(typeof encodeOnionPacket).to.equal('function');
			expect(typeof decodeOnionPacket).to.equal('function');
			expect(typeof processOnionPacket).to.equal('function');
			expect(typeof isFinalHop).to.equal('function');
			expect(typeof createFailureMessage).to.equal('function');
			expect(typeof wrapFailureMessage).to.equal('function');
			expect(typeof decryptFailureMessage).to.equal('function');
			expect(typeof decodeFailureCode).to.equal('function');
		});

		it('should be accessible via lightning.onion namespace', async () => {
			const lightning = await import('../../src/lightning');
			expect(lightning.onion).to.not.be.undefined;
			expect(typeof lightning.onion.constructOnionPacket).to.equal('function');
			expect(typeof lightning.onion.processOnionPacket).to.equal('function');
		});

		it('should end-to-end: construct → process at each hop → verify', () => {
			const { sessionKey, hopKeys, hops } = createTestRoute(4);
			const packet = constructOnionPacket(sessionKey, hops);

			let current: IOnionPacket = packet;
			for (let i = 0; i < 4; i++) {
				const result = processOnionPacket(current, hopKeys[i]);
				const expected = hops[i].payload;

				expect(result.hopPayload.amountToForwardMsat).to.equal(
					expected.amountToForwardMsat
				);
				expect(result.hopPayload.outgoingCltvValue).to.equal(
					expected.outgoingCltvValue
				);

				if (i < 3) {
					expect(result.hopPayload.shortChannelId).to.not.be.undefined;
					expect(
						result.hopPayload.shortChannelId!.equals(expected.shortChannelId!)
					).to.be.true;
					expect(isFinalHop(result.nextPacket)).to.be.false;
				} else {
					expect(result.hopPayload.shortChannelId).to.be.undefined;
					expect(isFinalHop(result.nextPacket)).to.be.true;
				}
				current = result.nextPacket;
			}
		});

		it('should end-to-end with failure: construct → fail at hop → unwrap', () => {
			const { sessionKey, hopKeys, hopPubkeys, hops } = createTestRoute(3);
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hopPubkeys
			);
			const packet = constructOnionPacket(sessionKey, hops);

			// Process hops 0 and 1 successfully (advance to hop 2)
			const r1 = processOnionPacket(packet, hopKeys[0]);
			processOnionPacket(r1.nextPacket, hopKeys[1]);

			// Hop 2 (final) fails: incorrect payment details
			const hop2Secret = generateSharedSecret(hopKeys[2], ephemeralKeys[2]);
			let failMsg = createFailureMessage(
				hop2Secret,
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);

			// Wrap back through hops 1 and 0
			const hop1Secret = generateSharedSecret(hopKeys[1], ephemeralKeys[1]);
			failMsg = wrapFailureMessage(hop1Secret, failMsg);
			const hop0Secret = generateSharedSecret(hopKeys[0], ephemeralKeys[0]);
			failMsg = wrapFailureMessage(hop0Secret, failMsg);

			// Sender decrypts
			const result = decryptFailureMessage(sharedSecrets, failMsg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(2);
			expect(result!.failure.failureCode).to.equal(
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);
		});

		it('should map IRouteHop to onion hops correctly', () => {
			// Simulate what a payment flow would do: take route hops from
			// the pathfinder and map them to onion construction input
			const hopKeys = [randomPrivkey(), randomPrivkey(), randomPrivkey()];
			const hopPubkeys = hopKeys.map((k) => getPublicKey(k));

			const routeHops = [
				{
					pubkey: hopPubkeys[0],
					shortChannelId: makeSCID(700000, 1, 0),
					amountToForwardMsat: 1001000n,
					outgoingCltvValue: 560
				},
				{
					pubkey: hopPubkeys[1],
					shortChannelId: makeSCID(700001, 2, 0),
					amountToForwardMsat: 1000000n,
					outgoingCltvValue: 520
				},
				{
					pubkey: hopPubkeys[2],
					shortChannelId: makeSCID(700002, 3, 0),
					amountToForwardMsat: 1000000n,
					outgoingCltvValue: 480
				}
			];

			// Map to onion hops: final hop has no shortChannelId
			const onionHops = routeHops.map((hop, i) => ({
				pubkey: hop.pubkey,
				payload: {
					amountToForwardMsat: hop.amountToForwardMsat,
					outgoingCltvValue: hop.outgoingCltvValue,
					...(i < routeHops.length - 1
						? { shortChannelId: hop.shortChannelId }
						: {})
				} as IHopPayload
			}));

			const sessionKey = randomPrivkey();
			const packet = constructOnionPacket(sessionKey, onionHops);

			// Process each hop
			let current: IOnionPacket = packet;
			for (let i = 0; i < 3; i++) {
				const result = processOnionPacket(current, hopKeys[i]);
				expect(result.hopPayload.amountToForwardMsat).to.equal(
					routeHops[i].amountToForwardMsat
				);
				expect(result.hopPayload.outgoingCltvValue).to.equal(
					routeHops[i].outgoingCltvValue
				);
				current = result.nextPacket;
			}
			expect(isFinalHop(current)).to.be.true;
		});

		it('should handle failure at intermediate hop in end-to-end flow', () => {
			const { sessionKey, hopKeys, hopPubkeys, hops } = createTestRoute(4);
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				hopPubkeys
			);
			const packet = constructOnionPacket(sessionKey, hops);

			// Process hop 0 successfully (advance state)
			processOnionPacket(packet, hopKeys[0]);

			// Hop 1 fails: fee insufficient
			const failData = Buffer.alloc(8);
			failData.writeBigUInt64BE(500000n); // Include amount
			const hop1Secret = generateSharedSecret(hopKeys[1], ephemeralKeys[1]);
			let failMsg = createFailureMessage(
				hop1Secret,
				FEE_INSUFFICIENT,
				failData
			);

			// Wrap through hop 0
			const hop0Secret = generateSharedSecret(hopKeys[0], ephemeralKeys[0]);
			failMsg = wrapFailureMessage(hop0Secret, failMsg);

			const result = decryptFailureMessage(sharedSecrets, failMsg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(1);
			expect(result!.failure.failureCode).to.equal(FEE_INSUFFICIENT);
			expect(result!.failure.failureData.length).to.equal(8);
		});
	});
});
