/**
 * Tests for BOLT 7.5: Onion Messages (Phase 8)
 *
 * Tests cover:
 * - Type 513 encode/decode round-trips
 * - Onion message construction (single-hop, multi-hop)
 * - Onion message construction with reply path
 * - Message processing (intermediate forwarding, final delivery)
 * - Rate limiting
 * - OnionMessageManager event emission
 * - Reply via blinded path
 * - Integration with existing onion/blinding infrastructure
 * - Error handling (malformed messages, unknown TLVs)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	encodeOnionMessage,
	decodeOnionMessage,
	encodeOnionMessagePayload,
	decodeOnionMessagePayload,
	encodeBlindedPathTlv,
	decodeBlindedPathTlv
} from '../../src/lightning/onion-message/codec';
import {
	constructOnionMessagePacket,
	constructOnionMessage,
	constructSimpleOnionMessage,
	constructMultiHopOnionMessage,
	constructReplyOnionMessage
} from '../../src/lightning/onion-message/construct';
import { processOnionMessage } from '../../src/lightning/onion-message/process';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import {
	IOnionMessage,
	IOnionMessagePayload,
	ONION_MESSAGE_PACKET_LENGTH,
	ONION_MESSAGE_TYPE,
	TLV_REPLY_PATH,
	TLV_ENCRYPTED_RECIPIENT_DATA,
	TLV_MESSAGE_DATA_BASE
} from '../../src/lightning/onion-message/types';
import {
	IBlindedPath,
	constructBlindedPath,
	processBlindedHop
} from '../../src/lightning/onion/blinded-path';
import { deriveBlindingKeyChain } from '../../src/lightning/onion/blinding';
import { MessageType } from '../../src/lightning/message/types';
import { Feature } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';

function generateKeyPair(): { privkey: Buffer; pubkey: Buffer } {
	let privkey: Buffer;
	do {
		privkey = crypto.randomBytes(32);
	} while (privkey[0] === 0); // Avoid zero private key
	const pubkey = getPublicKey(privkey);
	return { privkey, pubkey };
}

describe('Onion Messages (Phase 8)', () => {
	// ── Constants ────────────────────────────────────────

	describe('Constants', () => {
		it('should define ONION_MESSAGE_TYPE as 513', () => {
			expect(ONION_MESSAGE_TYPE).to.equal(513);
		});

		it('should define ONION_MESSAGE_PACKET_LENGTH as 1366', () => {
			expect(ONION_MESSAGE_PACKET_LENGTH).to.equal(1366);
		});

		it('should define TLV constants', () => {
			expect(TLV_REPLY_PATH).to.equal(2);
			expect(TLV_ENCRYPTED_RECIPIENT_DATA).to.equal(4);
			expect(TLV_MESSAGE_DATA_BASE).to.equal(64);
		});

		it('should have ONION_MESSAGE in MessageType enum', () => {
			expect(MessageType.ONION_MESSAGE).to.equal(513);
		});

		it('should have ONION_MESSAGES in Feature enum', () => {
			expect(Feature.ONION_MESSAGES).to.equal(38);
		});
	});

	// ── Codec: Wire Encode/Decode ────────────────────────

	describe('Codec: Wire Encode/Decode', () => {
		it('should encode and decode an onion_message round-trip', () => {
			const kp = generateKeyPair();
			const onionPacket = crypto.randomBytes(ONION_MESSAGE_PACKET_LENGTH);
			const msg: IOnionMessage = {
				blindingPoint: kp.pubkey,
				onionRoutingPacket: onionPacket
			};

			const encoded = encodeOnionMessage(msg);
			expect(encoded.length).to.equal(33 + 2 + ONION_MESSAGE_PACKET_LENGTH);

			const decoded = decodeOnionMessage(encoded);
			expect(decoded.blindingPoint.equals(kp.pubkey)).to.be.true;
			expect(decoded.onionRoutingPacket.equals(onionPacket)).to.be.true;
		});

		it('should reject blinding_point with wrong length', () => {
			expect(() =>
				encodeOnionMessage({
					blindingPoint: Buffer.alloc(32),
					onionRoutingPacket: Buffer.alloc(ONION_MESSAGE_PACKET_LENGTH)
				})
			).to.throw('blinding_point must be 33 bytes');
		});

		it('should reject onion_routing_packet with wrong length', () => {
			const kp = generateKeyPair();
			expect(() =>
				encodeOnionMessage({
					blindingPoint: kp.pubkey,
					onionRoutingPacket: Buffer.alloc(100)
				})
			).to.throw('onion_routing_packet must be 1366 bytes');
		});

		it('should reject truncated wire message', () => {
			expect(() => decodeOnionMessage(Buffer.alloc(10))).to.throw('too short');
		});

		it('should reject wire message with truncated packet', () => {
			const buf = Buffer.alloc(40);
			buf.writeUInt16BE(1366, 33);
			expect(() => decodeOnionMessage(buf)).to.throw('truncated');
		});
	});

	// ── Codec: Payload TLV Encode/Decode ─────────────────

	describe('Codec: Payload TLV Encode/Decode', () => {
		it('should encode and decode empty payload', () => {
			const payload: IOnionMessagePayload = { messageTlvs: new Map() };
			const encoded = encodeOnionMessagePayload(payload);
			const { payload: decoded, bytesRead } =
				decodeOnionMessagePayload(encoded);

			expect(bytesRead).to.equal(encoded.length);
			expect(decoded.messageTlvs.size).to.equal(0);
			expect(decoded.replyPath).to.be.undefined;
			expect(decoded.encryptedRecipientData).to.be.undefined;
		});

		it('should encode and decode payload with message TLVs', () => {
			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('hello'));
			msgData.set(65, Buffer.from('world'));

			const payload: IOnionMessagePayload = { messageTlvs: msgData };
			const encoded = encodeOnionMessagePayload(payload);
			const { payload: decoded } = decodeOnionMessagePayload(encoded);

			expect(decoded.messageTlvs.size).to.equal(2);
			expect(decoded.messageTlvs.get(64)!.toString()).to.equal('hello');
			expect(decoded.messageTlvs.get(65)!.toString()).to.equal('world');
		});

		it('should encode and decode payload with encrypted_recipient_data', () => {
			const data = crypto.randomBytes(64);
			const payload: IOnionMessagePayload = {
				encryptedRecipientData: data,
				messageTlvs: new Map()
			};
			const encoded = encodeOnionMessagePayload(payload);
			const { payload: decoded } = decodeOnionMessagePayload(encoded);

			expect(decoded.encryptedRecipientData!.equals(data)).to.be.true;
		});

		it('should reject message TLV type below minimum', () => {
			const payload: IOnionMessagePayload = {
				messageTlvs: new Map([[10, Buffer.from('bad')]])
			};
			expect(() => encodeOnionMessagePayload(payload)).to.throw(
				'below minimum'
			);
		});

		it('should preserve TLV ordering (ascending by type)', () => {
			const msgData = new Map<number, Buffer>();
			msgData.set(100, Buffer.from('b'));
			msgData.set(64, Buffer.from('a'));
			msgData.set(200, Buffer.from('c'));

			const payload: IOnionMessagePayload = { messageTlvs: msgData };
			const encoded = encodeOnionMessagePayload(payload);
			const { payload: decoded } = decodeOnionMessagePayload(encoded);

			const keys = [...decoded.messageTlvs.keys()];
			expect(keys).to.deep.equal([64, 100, 200]);
		});

		it('should handle unknown odd TLV types gracefully', () => {
			// Manually build a buffer with TLV type 7 (odd, ignorable)
			const tlvType7 = Buffer.from([0x03, 0x07, 0x02, 0x41, 0x42]); // len=3, type=7, len=2, 'AB'
			const { payload: decoded } = decodeOnionMessagePayload(tlvType7, 0);
			// Should not throw, and should not have TLV 7 in messageTlvs (below 64)
			expect(decoded.messageTlvs.size).to.equal(0);
		});

		it('should reject unknown even TLV types', () => {
			// TLV type 6 (even, required, unknown)
			const bad = Buffer.from([0x03, 0x06, 0x01, 0x42]); // len=3, type=6, len=1, 'B'
			expect(() => decodeOnionMessagePayload(bad, 0)).to.throw(
				'Unknown required TLV type 6'
			);
		});
	});

	// ── Codec: Blinded Path TLV ──────────────────────────

	describe('Codec: Blinded Path TLV', () => {
		it('should encode and decode a blinded path round-trip', () => {
			const kp1 = generateKeyPair();
			const kp2 = generateKeyPair();
			const kp3 = generateKeyPair();

			const path: IBlindedPath = {
				introductionNodeId: kp1.pubkey,
				blindingPoint: kp2.pubkey,
				blindedHops: [
					{ blindedNodeId: kp3.pubkey, encryptedData: crypto.randomBytes(50) },
					{ blindedNodeId: kp1.pubkey, encryptedData: crypto.randomBytes(30) }
				]
			};

			const encoded = encodeBlindedPathTlv(path);
			const decoded = decodeBlindedPathTlv(encoded);

			expect(decoded.introductionNodeId.equals(kp1.pubkey)).to.be.true;
			expect(decoded.blindingPoint.equals(kp2.pubkey)).to.be.true;
			expect(decoded.blindedHops.length).to.equal(2);
			expect(decoded.blindedHops[0].blindedNodeId.equals(kp3.pubkey)).to.be
				.true;
			expect(
				decoded.blindedHops[0].encryptedData.equals(
					path.blindedHops[0].encryptedData
				)
			).to.be.true;
			expect(decoded.blindedHops[1].blindedNodeId.equals(kp1.pubkey)).to.be
				.true;
			expect(
				decoded.blindedHops[1].encryptedData.equals(
					path.blindedHops[1].encryptedData
				)
			).to.be.true;
		});

		it('should handle blinded path with single hop', () => {
			const kp1 = generateKeyPair();
			const kp2 = generateKeyPair();

			const path: IBlindedPath = {
				introductionNodeId: kp1.pubkey,
				blindingPoint: kp2.pubkey,
				blindedHops: [
					{ blindedNodeId: kp1.pubkey, encryptedData: crypto.randomBytes(20) }
				]
			};

			const encoded = encodeBlindedPathTlv(path);
			const decoded = decodeBlindedPathTlv(encoded);

			expect(decoded.blindedHops.length).to.equal(1);
		});

		it('should reject truncated blinded path', () => {
			expect(() => decodeBlindedPathTlv(Buffer.alloc(10))).to.throw(
				'truncated'
			);
		});
	});

	// ── Codec: Payload with Reply Path ───────────────────

	describe('Codec: Payload with Reply Path', () => {
		it('should encode and decode payload with reply path', () => {
			const kp1 = generateKeyPair();
			const kp2 = generateKeyPair();

			const replyPath: IBlindedPath = {
				introductionNodeId: kp1.pubkey,
				blindingPoint: kp2.pubkey,
				blindedHops: [
					{ blindedNodeId: kp1.pubkey, encryptedData: crypto.randomBytes(40) }
				]
			};

			const payload: IOnionMessagePayload = {
				replyPath,
				messageTlvs: new Map([[64, Buffer.from('test-data')]])
			};

			const encoded = encodeOnionMessagePayload(payload);
			const { payload: decoded } = decodeOnionMessagePayload(encoded);

			expect(decoded.replyPath).to.not.be.undefined;
			expect(decoded.replyPath!.introductionNodeId.equals(kp1.pubkey)).to.be
				.true;
			expect(decoded.replyPath!.blindingPoint.equals(kp2.pubkey)).to.be.true;
			expect(decoded.replyPath!.blindedHops.length).to.equal(1);
			expect(decoded.messageTlvs.get(64)!.toString()).to.equal('test-data');
		});
	});

	// ── Construction: Single Hop ─────────────────────────

	describe('Construction: Single Hop', () => {
		it('should construct a single-hop onion message', () => {
			const dest = generateKeyPair();
			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('hello destination'));

			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);

			expect(msg.blindingPoint.length).to.equal(33);
			expect(msg.onionRoutingPacket.length).to.equal(
				ONION_MESSAGE_PACKET_LENGTH
			);
		});

		it('should construct single-hop message processable by destination', () => {
			const dest = generateKeyPair();
			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('secret message'));

			const sessionKey = crypto.randomBytes(32);
			const msg = constructSimpleOnionMessage(dest.pubkey, msgData, sessionKey);

			const result = processOnionMessage(msg.onionRoutingPacket, dest.privkey);

			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(64)!.toString()).to.equal(
					'secret message'
				);
			}
		});

		it('should construct message with custom session key', () => {
			const dest = generateKeyPair();
			const sessionKey = crypto.randomBytes(32);
			const expectedBlindingPoint = getPublicKey(sessionKey);

			const msg = constructSimpleOnionMessage(
				dest.pubkey,
				new Map(),
				sessionKey
			);
			expect(msg.blindingPoint.equals(expectedBlindingPoint)).to.be.true;
		});
	});

	// ── Construction: Multi-Hop ──────────────────────────

	describe('Construction: Multi-Hop', () => {
		it('should construct a multi-hop onion message', () => {
			const node1 = generateKeyPair();
			const node2 = generateKeyPair();
			const dest = generateKeyPair();

			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('multi-hop message'));

			const msg = constructMultiHopOnionMessage(
				[node1.pubkey, node2.pubkey],
				dest.pubkey,
				msgData
			);

			expect(msg.blindingPoint.length).to.equal(33);
			expect(msg.onionRoutingPacket.length).to.equal(
				ONION_MESSAGE_PACKET_LENGTH
			);
		});

		it('should construct a two-hop message where first hop can peel a layer', () => {
			const node1 = generateKeyPair();
			const dest = generateKeyPair();

			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('two-hop test'));

			const sessionKey = crypto.randomBytes(32);
			const msg = constructMultiHopOnionMessage(
				[node1.pubkey],
				dest.pubkey,
				msgData,
				sessionKey
			);

			// First node peels a layer
			const result = processOnionMessage(msg.onionRoutingPacket, node1.privkey);
			expect(result.type).to.equal('forward');
		});

		it('should deliver message after peeling through all intermediate hops', () => {
			const node1 = generateKeyPair();
			const dest = generateKeyPair();

			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('end-to-end'));

			const sessionKey = crypto.randomBytes(32);
			const msg = constructMultiHopOnionMessage(
				[node1.pubkey],
				dest.pubkey,
				msgData,
				sessionKey
			);

			// First hop peels
			const result1 = processOnionMessage(
				msg.onionRoutingPacket,
				node1.privkey
			);
			expect(result1.type).to.equal('forward');

			if (result1.type === 'forward') {
				// Destination processes
				const result2 = processOnionMessage(
					result1.nextOnionMessage.onionRoutingPacket,
					dest.privkey
				);
				expect(result2.type).to.equal('delivery');
				if (result2.type === 'delivery') {
					expect(result2.payload.messageTlvs.get(64)!.toString()).to.equal(
						'end-to-end'
					);
				}
			}
		});
	});

	// ── Construction: With Reply Path ────────────────────

	describe('Construction: With Reply Path', () => {
		it('should construct a message with reply path', () => {
			const dest = generateKeyPair();
			const replyNode = generateKeyPair();

			const replyPath: IBlindedPath = {
				introductionNodeId: replyNode.pubkey,
				blindingPoint: generateKeyPair().pubkey,
				blindedHops: [
					{
						blindedNodeId: replyNode.pubkey,
						encryptedData: crypto.randomBytes(30)
					}
				]
			};

			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('need reply'));

			const msg = constructSimpleOnionMessage(dest.pubkey, msgData, undefined, {
				replyPath
			});

			const result = processOnionMessage(msg.onionRoutingPacket, dest.privkey);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.replyPath).to.not.be.undefined;
				expect(
					result.payload.replyPath!.introductionNodeId.equals(replyNode.pubkey)
				).to.be.true;
				expect(result.payload.messageTlvs.get(64)!.toString()).to.equal(
					'need reply'
				);
			}
		});
	});

	// ── Processing ───────────────────────────────────────

	describe('Processing', () => {
		it('should detect final delivery (zero HMAC)', () => {
			const dest = generateKeyPair();
			const msg = constructSimpleOnionMessage(
				dest.pubkey,
				new Map([[64, Buffer.from('final')]])
			);

			const result = processOnionMessage(msg.onionRoutingPacket, dest.privkey);
			expect(result.type).to.equal('delivery');
		});

		it('should reject invalid onion version', () => {
			const dest = generateKeyPair();
			const msg = constructSimpleOnionMessage(dest.pubkey, new Map());

			// Corrupt version byte
			const corrupted = Buffer.from(msg.onionRoutingPacket);
			corrupted[0] = 0x01; // Invalid version

			expect(() => processOnionMessage(corrupted, dest.privkey)).to.throw(
				'Invalid onion version'
			);
		});

		it('should reject corrupted HMAC', () => {
			const dest = generateKeyPair();
			const msg = constructSimpleOnionMessage(dest.pubkey, new Map());

			// Corrupt HMAC (last 32 bytes of the 1366-byte packet)
			const corrupted = Buffer.from(msg.onionRoutingPacket);
			corrupted[1334] ^= 0xff;

			expect(() => processOnionMessage(corrupted, dest.privkey)).to.throw(
				'HMAC verification failed'
			);
		});

		it('should fail to process with wrong private key', () => {
			const dest = generateKeyPair();
			const wrongKey = generateKeyPair();
			const msg = constructSimpleOnionMessage(dest.pubkey, new Map());

			expect(() =>
				processOnionMessage(msg.onionRoutingPacket, wrongKey.privkey)
			).to.throw();
		});

		it('should handle empty message TLVs in delivery', () => {
			const dest = generateKeyPair();
			const msg = constructSimpleOnionMessage(dest.pubkey, new Map());

			const result = processOnionMessage(msg.onionRoutingPacket, dest.privkey);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.size).to.equal(0);
			}
		});

		it('should preserve multiple TLV types through onion', () => {
			const dest = generateKeyPair();
			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('type64'));
			msgData.set(66, Buffer.from('type66'));
			msgData.set(100, Buffer.from('type100'));

			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);
			const result = processOnionMessage(msg.onionRoutingPacket, dest.privkey);

			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.size).to.equal(3);
				expect(result.payload.messageTlvs.get(64)!.toString()).to.equal(
					'type64'
				);
				expect(result.payload.messageTlvs.get(66)!.toString()).to.equal(
					'type66'
				);
				expect(result.payload.messageTlvs.get(100)!.toString()).to.equal(
					'type100'
				);
			}
		});
	});

	// ── constructOnionMessagePacket ──────────────────────

	describe('constructOnionMessagePacket', () => {
		it('should produce a 1366-byte packet', () => {
			const dest = generateKeyPair();
			const payload = encodeOnionMessagePayload({ messageTlvs: new Map() });
			const sessionKey = crypto.randomBytes(32);

			const packet = constructOnionMessagePacket(sessionKey, [
				{ pubkey: dest.pubkey, payload }
			]);
			expect(packet.length).to.equal(ONION_MESSAGE_PACKET_LENGTH);
		});

		it('should reject empty hops', () => {
			const sessionKey = crypto.randomBytes(32);
			expect(() => constructOnionMessagePacket(sessionKey, [])).to.throw(
				'At least one hop'
			);
		});

		it('should reject more than 20 hops', () => {
			const sessionKey = crypto.randomBytes(32);
			const hops = Array.from({ length: 21 }, () => ({
				pubkey: generateKeyPair().pubkey,
				payload: encodeOnionMessagePayload({ messageTlvs: new Map() })
			}));
			expect(() => constructOnionMessagePacket(sessionKey, hops)).to.throw(
				'Too many hops'
			);
		});
	});

	// ── constructOnionMessage ────────────────────────────

	describe('constructOnionMessage', () => {
		it('should produce valid IOnionMessage', () => {
			const dest = generateKeyPair();
			const payload = encodeOnionMessagePayload({ messageTlvs: new Map() });
			const sessionKey = crypto.randomBytes(32);

			const msg = constructOnionMessage(sessionKey, [dest.pubkey], [payload]);
			expect(msg.blindingPoint.length).to.equal(33);
			expect(msg.onionRoutingPacket.length).to.equal(
				ONION_MESSAGE_PACKET_LENGTH
			);
		});

		it('should reject mismatched path/payloads lengths', () => {
			const sessionKey = crypto.randomBytes(32);
			expect(() =>
				constructOnionMessage(sessionKey, [generateKeyPair().pubkey], [])
			).to.throw('same length');
		});
	});

	// ── Rate Limiting ────────────────────────────────────

	describe('Rate Limiting', () => {
		it('should allow messages within rate limit', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey, {
				maxPerWindow: 5,
				windowMs: 60000
			});

			// Set up a send function
			const sent: { peer: string; type: number; payload: Buffer }[] = [];
			mgr.setSendFunction((peer, type, payload) => {
				sent.push({ peer, type, payload });
			});

			// Add error handler to absorb
			mgr.on('message:error', () => {});

			// Simulate 5 messages from a peer
			const dest = generateKeyPair();
			const wireMsg = encodeOnionMessage(
				constructSimpleOnionMessage(dest.pubkey, new Map())
			);

			for (let i = 0; i < 5; i++) {
				mgr.handleMessage('peer1', wireMsg);
			}

			// The 5 messages should not be rate-limited
			// (they may produce errors due to processing, but that's OK — rate limit check happens first)
		});

		it('should block messages exceeding rate limit', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey, {
				maxPerWindow: 3,
				windowMs: 60000
			});
			mgr.on('message:error', () => {}); // absorb

			const errors: Error[] = [];
			mgr.on('message:error', (_peer: string, err: Error) => {
				errors.push(err);
			});

			const dest = generateKeyPair();
			const wireMsg = encodeOnionMessage(
				constructSimpleOnionMessage(dest.pubkey, new Map())
			);

			// Send 5 messages (limit is 3)
			for (let i = 0; i < 5; i++) {
				mgr.handleMessage('peer1', wireMsg);
			}

			// At least 2 should be rate-limited
			const rateLimitErrors = errors.filter((e) =>
				e.message.includes('Rate limit')
			);
			expect(rateLimitErrors.length).to.equal(2);

			mgr.destroy();
		});

		it('should track rate limits per peer independently', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey, {
				maxPerWindow: 2,
				windowMs: 60000
			});
			mgr.on('message:error', () => {}); // absorb

			const errors: { peer: string; err: Error }[] = [];
			mgr.on('message:error', (peer: string, err: Error) => {
				errors.push({ peer, err });
			});

			const dest = generateKeyPair();
			const wireMsg = encodeOnionMessage(
				constructSimpleOnionMessage(dest.pubkey, new Map())
			);

			// 3 messages from peer1 (limit is 2)
			for (let i = 0; i < 3; i++) {
				mgr.handleMessage('peer1', wireMsg);
			}
			// 2 messages from peer2 (within limit)
			for (let i = 0; i < 2; i++) {
				mgr.handleMessage('peer2', wireMsg);
			}

			const peer1RateLimited = errors.filter(
				(e) => e.peer === 'peer1' && e.err.message.includes('Rate limit')
			);
			const peer2RateLimited = errors.filter(
				(e) => e.peer === 'peer2' && e.err.message.includes('Rate limit')
			);

			expect(peer1RateLimited.length).to.equal(1);
			expect(peer2RateLimited.length).to.equal(0);

			mgr.destroy();
		});

		it('should clear rate limits', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey, {
				maxPerWindow: 1,
				windowMs: 60000
			});
			mgr.on('message:error', () => {}); // absorb

			const dest = generateKeyPair();
			const wireMsg = encodeOnionMessage(
				constructSimpleOnionMessage(dest.pubkey, new Map())
			);

			mgr.handleMessage('peer1', wireMsg);
			mgr.handleMessage('peer1', wireMsg); // rate limited

			mgr.clearRateLimits();

			// After clearing, should be allowed again
			const errors: Error[] = [];
			mgr.on('message:error', (_peer: string, err: Error) => {
				if (err.message.includes('Rate limit')) {
					errors.push(err);
				}
			});

			mgr.handleMessage('peer1', wireMsg);
			const rateLimitErrors = errors.filter((e) =>
				e.message.includes('Rate limit')
			);
			expect(rateLimitErrors.length).to.equal(0);

			mgr.destroy();
		});

		it('should allow updating rate limit config', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey, {
				maxPerWindow: 5,
				windowMs: 1000
			});

			expect(mgr.getRateLimitConfig().maxPerWindow).to.equal(5);
			expect(mgr.getRateLimitConfig().windowMs).to.equal(1000);

			mgr.setRateLimitConfig({ maxPerWindow: 20 });
			expect(mgr.getRateLimitConfig().maxPerWindow).to.equal(20);
			expect(mgr.getRateLimitConfig().windowMs).to.equal(1000);

			mgr.destroy();
		});
	});

	// ── OnionMessageManager Events ───────────────────────

	describe('OnionMessageManager Events', () => {
		it('should emit message:received on final delivery', () => {
			const dest = generateKeyPair();
			const mgr = new OnionMessageManager(dest.privkey);
			mgr.on('message:error', () => {}); // absorb

			const received: IOnionMessagePayload[] = [];
			mgr.on(
				'message:received',
				(_from: string, payload: IOnionMessagePayload) => {
					received.push(payload);
				}
			);

			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('event-test'));
			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);
			const wirePayload = encodeOnionMessage(msg);

			mgr.handleMessage('somepeer', wirePayload);

			expect(received.length).to.equal(1);
			expect(received[0].messageTlvs.get(64)!.toString()).to.equal(
				'event-test'
			);

			mgr.destroy();
		});

		it('should emit message:error on malformed message', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey);

			const errors: Error[] = [];
			mgr.on('message:error', (_from: string, err: Error) => {
				errors.push(err);
			});

			mgr.handleMessage('badpeer', Buffer.alloc(5));

			expect(errors.length).to.equal(1);
			expect(errors[0].message).to.include('too short');

			mgr.destroy();
		});

		it('should emit message:error on HMAC failure', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const dest = generateKeyPair();
			const mgr = new OnionMessageManager(nodePrivkey);

			const errors: Error[] = [];
			mgr.on('message:error', (_from: string, err: Error) => {
				errors.push(err);
			});

			// Build a valid-looking message but for wrong key
			const msg = constructSimpleOnionMessage(dest.pubkey, new Map());
			const wirePayload = encodeOnionMessage(msg);

			mgr.handleMessage('peer1', wirePayload);

			expect(errors.length).to.equal(1);

			mgr.destroy();
		});

		it('should invoke TLV handlers for received messages', () => {
			const dest = generateKeyPair();
			const mgr = new OnionMessageManager(dest.privkey);
			mgr.on('message:error', () => {}); // absorb

			const handlerCalls: { from: string; type: number; data: Buffer }[] = [];
			mgr.registerTlvHandler(64, (from, type, data) => {
				handlerCalls.push({ from, type, data });
			});

			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('tlv-handler-test'));
			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);
			const wirePayload = encodeOnionMessage(msg);

			mgr.handleMessage('sender1', wirePayload);

			expect(handlerCalls.length).to.equal(1);
			expect(handlerCalls[0].from).to.equal('sender1');
			expect(handlerCalls[0].type).to.equal(64);
			expect(handlerCalls[0].data.toString()).to.equal('tlv-handler-test');

			mgr.destroy();
		});

		it('should allow unregistering TLV handlers', () => {
			const dest = generateKeyPair();
			const mgr = new OnionMessageManager(dest.privkey);
			mgr.on('message:error', () => {}); // absorb

			let called = false;
			mgr.registerTlvHandler(64, () => {
				called = true;
			});
			mgr.unregisterTlvHandler(64);

			const msg = constructSimpleOnionMessage(
				dest.pubkey,
				new Map([[64, Buffer.from('x')]])
			);
			mgr.handleMessage('peer', encodeOnionMessage(msg));

			expect(called).to.be.false;

			mgr.destroy();
		});
	});

	// ── Manager: Sending ─────────────────────────────────

	describe('Manager: Sending', () => {
		it('should send a simple onion message', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey);

			const sent: { peer: string; type: number }[] = [];
			mgr.setSendFunction((peer, type) => {
				sent.push({ peer, type });
			});

			const dest = generateKeyPair();
			mgr.sendOnionMessage(dest.pubkey, new Map([[64, Buffer.from('hi')]]));

			expect(sent.length).to.equal(1);
			expect(sent[0].peer).to.equal(dest.pubkey.toString('hex'));
			expect(sent[0].type).to.equal(513);

			mgr.destroy();
		});

		it('should throw if send function not configured', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey);

			const dest = generateKeyPair();
			expect(() => mgr.sendOnionMessage(dest.pubkey, new Map())).to.throw(
				'Send function not configured'
			);

			mgr.destroy();
		});

		it('should send multi-hop message to first hop', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey);

			const sent: { peer: string; type: number }[] = [];
			mgr.setSendFunction((peer, type) => {
				sent.push({ peer, type });
			});

			const node1 = generateKeyPair();
			const dest = generateKeyPair();
			mgr.sendMultiHopOnionMessage([node1.pubkey], dest.pubkey, new Map());

			expect(sent.length).to.equal(1);
			expect(sent[0].peer).to.equal(node1.pubkey.toString('hex'));

			mgr.destroy();
		});

		it('should emit message:send event', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey);
			mgr.setSendFunction(() => {});

			const events: { peer: string; type: number }[] = [];
			mgr.on('message:send', (peer: string, type: number) => {
				events.push({ peer, type });
			});

			const dest = generateKeyPair();
			mgr.sendOnionMessage(dest.pubkey, new Map());

			expect(events.length).to.equal(1);
			expect(events[0].type).to.equal(513);

			mgr.destroy();
		});
	});

	// ── Reply Path Integration ───────────────────────────

	describe('Reply Path Integration', () => {
		it('should construct a reply message using blinded path', () => {
			const replyDest = generateKeyPair();
			const blindingSecret = crypto.randomBytes(32);

			// Construct a blinded path to replyDest
			const replyPath = constructBlindedPath(
				blindingSecret,
				[replyDest.pubkey],
				[
					{
						/* final hop - no nextNodeId */
					}
				]
			);

			const replyData = new Map<number, Buffer>();
			replyData.set(64, Buffer.from('reply data'));

			const reply = constructReplyOnionMessage(replyPath, replyData);
			expect(reply.blindingPoint.length).to.equal(33);
			expect(reply.onionRoutingPacket.length).to.equal(
				ONION_MESSAGE_PACKET_LENGTH
			);
		});

		it('should deliver the message body over a 1-hop reply path (S-4.M9)', () => {
			// In a 1-hop reply path the introduction node IS the recipient. The
			// reply's message TLVs must land in the intro hop's payload; dropping
			// them made every BOLT 12 invoice reply over such a path arrive empty.
			const replyDest = generateKeyPair();
			const blindingSecret = crypto.randomBytes(32);

			const replyPath = constructBlindedPath(
				blindingSecret,
				[replyDest.pubkey],
				[
					{
						/* final hop - no nextNodeId */
					}
				]
			);

			const replyData = new Map<number, Buffer>();
			replyData.set(64, Buffer.from('reply body'));

			const reply = constructReplyOnionMessage(replyPath, replyData);
			const result = processOnionMessage(
				reply.onionRoutingPacket,
				replyDest.privkey
			);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(64)).to.not.be.undefined;
				expect(result.payload.messageTlvs.get(64)!.toString()).to.equal(
					'reply body'
				);
			}
		});

		it('should reject reply path with no blinded hops', () => {
			const kp = generateKeyPair();
			const emptyPath: IBlindedPath = {
				introductionNodeId: kp.pubkey,
				blindingPoint: kp.pubkey,
				blindedHops: []
			};

			expect(() => constructReplyOnionMessage(emptyPath, new Map())).to.throw(
				'at least one blinded hop'
			);
		});
	});

	// ── Feature Flags ────────────────────────────────────

	describe('Feature Flags', () => {
		it('should include ONION_MESSAGES in default features', () => {
			const features = LightningNode.defaultFeatures();
			expect(features.hasFeature(Feature.ONION_MESSAGES)).to.be.true;
			expect(features.isOptional(Feature.ONION_MESSAGES)).to.be.true;
		});
	});

	// ── Integration with Blinding ────────────────────────

	describe('Integration with Blinding', () => {
		it('should derive consistent blinding key chain', () => {
			const blindingSecret = crypto.randomBytes(32);
			const node1 = generateKeyPair();
			const node2 = generateKeyPair();
			const node3 = generateKeyPair();

			const { blindingKeys, sharedSecrets } = deriveBlindingKeyChain(
				blindingSecret,
				[node1.pubkey, node2.pubkey, node3.pubkey]
			);

			expect(blindingKeys.length).to.equal(3);
			expect(sharedSecrets.length).to.equal(3);

			// Each blinding key should be 33 bytes (compressed pubkey)
			for (const key of blindingKeys) {
				expect(key.length).to.equal(33);
			}
			// Each shared secret should be 32 bytes
			for (const ss of sharedSecrets) {
				expect(ss.length).to.equal(32);
			}
		});

		it('should process a blinded hop and get next blinding key', () => {
			const blindingSecret = crypto.randomBytes(32);
			const node1 = generateKeyPair();
			const node2 = generateKeyPair();

			const path = constructBlindedPath(
				blindingSecret,
				[node1.pubkey, node2.pubkey],
				[{ nextNodeId: node2.pubkey }, {}]
			);

			// Process at node1
			const result = processBlindedHop(
				path.blindingPoint,
				node1.privkey,
				path.blindedHops[0].encryptedData
			);

			expect(result.hopData.nextNodeId).to.not.be.undefined;
			expect(result.hopData.nextNodeId!.equals(node2.pubkey)).to.be.true;
			expect(result.nextBlindingKey.length).to.equal(33);
		});
	});

	// ── Error Handling ───────────────────────────────────

	describe('Error Handling', () => {
		it('should handle zero-length wire payload gracefully', () => {
			expect(() => decodeOnionMessage(Buffer.alloc(0))).to.throw();
		});

		it('should reject constructing with empty path and payloads', () => {
			const sessionKey = crypto.randomBytes(32);
			expect(() => constructOnionMessage(sessionKey, [], [])).to.throw(
				'At least one hop'
			);
		});

		it('should handle large message TLV data', () => {
			const dest = generateKeyPair();
			const largeData = crypto.randomBytes(500);
			const msgData = new Map<number, Buffer>();
			msgData.set(64, largeData);

			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);
			const result = processOnionMessage(msg.onionRoutingPacket, dest.privkey);

			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(64)!.equals(largeData)).to.be
					.true;
			}
		});

		it('should handle binary message data', () => {
			const dest = generateKeyPair();
			const binaryData = Buffer.alloc(256);
			for (let i = 0; i < 256; i++) binaryData[i] = i;

			const msgData = new Map<number, Buffer>();
			msgData.set(64, binaryData);

			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);
			const result = processOnionMessage(msg.onionRoutingPacket, dest.privkey);

			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(64)!.equals(binaryData)).to.be
					.true;
			}
		});

		it('should emit message:error from manager on process failure', () => {
			const nodeKp = generateKeyPair();
			const mgr = new OnionMessageManager(nodeKp.privkey);

			const errors: Error[] = [];
			mgr.on('message:error', (_peer: string, err: Error) => {
				errors.push(err);
			});

			// Valid-looking wire encoding but for a different key
			const otherDest = generateKeyPair();
			const msg = constructSimpleOnionMessage(otherDest.pubkey, new Map());
			const wirePayload = encodeOnionMessage(msg);

			mgr.handleMessage('badpeer', wirePayload);
			expect(errors.length).to.equal(1);

			mgr.destroy();
		});
	});

	// ── Manager: Forwarding ──────────────────────────────

	describe('Manager: Forwarding', () => {
		it('should emit message:forwarded for intermediate hops', () => {
			const node1 = generateKeyPair();
			const dest = generateKeyPair();
			const mgr = new OnionMessageManager(node1.privkey);

			const forwarded: string[] = [];
			mgr.on('message:forwarded', (_from: string, nextNode: string) => {
				forwarded.push(nextNode);
			});
			mgr.on('message:error', () => {}); // absorb

			const sent: Buffer[] = [];
			mgr.setSendFunction((_peer, _type, payload) => {
				sent.push(payload);
			});

			// Build a multi-hop message where node1 is an intermediate
			const msgData = new Map<number, Buffer>();
			msgData.set(64, Buffer.from('forward me'));
			const msg = constructMultiHopOnionMessage(
				[node1.pubkey],
				dest.pubkey,
				msgData
			);
			const wirePayload = encodeOnionMessage(msg);

			mgr.handleMessage('sender', wirePayload);

			expect(forwarded.length).to.equal(1);
			expect(sent.length).to.equal(1); // Should have forwarded the message

			mgr.destroy();
		});
	});

	// ── Manager: Destroy/Cleanup ─────────────────────────

	describe('Manager: Destroy/Cleanup', () => {
		it('should clean up all state on destroy', () => {
			const nodePrivkey = generateKeyPair().privkey;
			const mgr = new OnionMessageManager(nodePrivkey);
			mgr.setSendFunction(() => {});

			let handlerCalled = false;
			mgr.registerTlvHandler(64, () => {
				handlerCalled = true;
			});

			mgr.destroy();

			// After destroy, sending should fail (sendFunction cleared)
			const dest = generateKeyPair();
			expect(() => mgr.sendOnionMessage(dest.pubkey, new Map())).to.throw(
				'Send function not configured'
			);

			// TLV handlers should be cleared
			expect(handlerCalled).to.be.false;
		});
	});

	// ── LightningNode Integration ────────────────────────

	describe('LightningNode Integration', () => {
		function createTestNode(): LightningNode {
			const kp = generateKeyPair();
			const node = new LightningNode({
				nodePrivateKey: kp.privkey,
				channelBasepoints: {
					fundingPubkey: getPublicKey(crypto.randomBytes(32)),
					revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
					paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
					delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
					htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
					firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
				},
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});
			// Absorb errors
			node.on('error', () => {});
			node.on('node:error', () => {});
			return node;
		}

		it('should expose getOnionMessageManager()', () => {
			const node = createTestNode();
			const mgr = node.getOnionMessageManager();
			expect(mgr).to.be.instanceOf(OnionMessageManager);
			node.destroy();
		});

		it('should expose sendOnionMessage()', () => {
			const node = createTestNode();
			const dest = generateKeyPair();

			// Without networking, sending through PeerManager won't work,
			// but the method should exist and the OnionMessageManager should process it
			const mgr = node.getOnionMessageManager();
			const sent: Buffer[] = [];
			mgr.setSendFunction((_peer, _type, payload) => {
				sent.push(payload);
			});

			node.sendOnionMessage(
				dest.pubkey,
				new Map([[64, Buffer.from('from-node')]])
			);
			expect(sent.length).to.equal(1);

			node.destroy();
		});

		it('should emit onion:received when a message is received', () => {
			const nodeKp = generateKeyPair();
			const node = new LightningNode({
				nodePrivateKey: nodeKp.privkey,
				channelBasepoints: {
					fundingPubkey: getPublicKey(crypto.randomBytes(32)),
					revocationBasepoint: getPublicKey(crypto.randomBytes(32)),
					paymentBasepoint: getPublicKey(crypto.randomBytes(32)),
					delayedPaymentBasepoint: getPublicKey(crypto.randomBytes(32)),
					htlcBasepoint: getPublicKey(crypto.randomBytes(32)),
					firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
				},
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});
			node.on('error', () => {});
			node.on('node:error', () => {});

			const received: IOnionMessagePayload[] = [];
			node.on('onion:received', (payload: IOnionMessagePayload) => {
				received.push(payload);
			});

			// Construct a message for this node
			const msg = constructSimpleOnionMessage(
				getPublicKey(nodeKp.privkey),
				new Map([[64, Buffer.from('node-event-test')]])
			);
			const wirePayload = encodeOnionMessage(msg);

			// Route through handlePeerMessage
			node.handlePeerMessage(
				'somepeer',
				MessageType.ONION_MESSAGE,
				wirePayload
			);

			expect(received.length).to.equal(1);
			expect(received[0].messageTlvs.get(64)!.toString()).to.equal(
				'node-event-test'
			);

			node.destroy();
		});

		it('should emit node:error on onion message processing failure', () => {
			const node = createTestNode();

			const errors: { code: string }[] = [];
			node.on('node:error', (err: { code: string }) => {
				errors.push(err);
			});

			// Send a malformed onion message
			node.handlePeerMessage(
				'peer1',
				MessageType.ONION_MESSAGE,
				Buffer.alloc(5)
			);

			expect(errors.length).to.be.greaterThan(0);
			expect(errors.some((e) => e.code === 'ONION_MESSAGE_ERROR')).to.be.true;

			node.destroy();
		});
	});
});
