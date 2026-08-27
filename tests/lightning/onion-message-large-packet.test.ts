/**
 * Tests for the BOLT 4 large onion message form (issue #552).
 *
 * Onion messages have exactly two on-wire sizes: the 1366-byte standard
 * packet (1300-byte routing info) and the 32834-byte large form
 * (32768-byte routing info), auto-selected from the hop payloads alone
 * so packet length leaks at most one bit. These tests pin:
 * - form selection at the 1300/1301 needed-bytes boundary
 * - large-form construct -> peel round trips (single and multi hop)
 * - relay size preservation (a forwarded onion keeps the inbound size)
 * - the overflow throw past the large form
 * - wire codec whitelists in both directions
 * - the previously corrupt 1269-1300 window now yields a valid onion
 * - manager end-to-end delivery and reply with large payloads
 * - payment onions stay pinned at exactly 1366
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	encodeOnionMessage,
	decodeOnionMessage,
	encodeOnionMessagePayload
} from '../../src/lightning/onion-message/codec';
import {
	constructOnionMessagePacket,
	constructSimpleOnionMessage,
	constructReplyOnionMessage
} from '../../src/lightning/onion-message/construct';
import { processOnionMessage } from '../../src/lightning/onion-message/process';
import { OnionMessageManager } from '../../src/lightning/onion-message/manager';
import { ONION_MESSAGE_PACKET_LENGTH } from '../../src/lightning/onion-message/types';
import { constructBlindedPath } from '../../src/lightning/onion/blinded-path';
import {
	encodeOnionPacket,
	decodeOnionPacket
} from '../../src/lightning/onion/construct';
import { processOnionPacket } from '../../src/lightning/onion/process';
import {
	LARGE_ONION_PACKET_LENGTH,
	LARGE_ROUTING_INFO_LENGTH,
	ONION_VERSION,
	ROUTING_INFO_LENGTH
} from '../../src/lightning/onion/types';

function generateKeyPair(): { privkey: Buffer; pubkey: Buffer } {
	let privkey: Buffer;
	do {
		privkey = crypto.randomBytes(32);
	} while (privkey[0] === 0);
	const pubkey = getPublicKey(privkey);
	return { privkey, pubkey };
}

describe('Onion Messages: BOLT 4 large form', () => {
	describe('Constants', () => {
		it('defines the large form sizes', () => {
			expect(LARGE_ROUTING_INFO_LENGTH).to.equal(32768);
			expect(LARGE_ONION_PACKET_LENGTH).to.equal(32834);
		});
	});

	describe('Form selection boundary', () => {
		it('single hop: 1268-byte payload fills the standard form exactly', () => {
			const dest = generateKeyPair();
			const packet = constructOnionMessagePacket(crypto.randomBytes(32), [
				{ pubkey: dest.pubkey, payload: Buffer.alloc(1268) }
			]);
			expect(packet.length).to.equal(ONION_MESSAGE_PACKET_LENGTH);
		});

		it('single hop: 1269-byte payload selects the large form', () => {
			const dest = generateKeyPair();
			const packet = constructOnionMessagePacket(crypto.randomBytes(32), [
				{ pubkey: dest.pubkey, payload: Buffer.alloc(1269) }
			]);
			expect(packet.length).to.equal(LARGE_ONION_PACKET_LENGTH);
		});

		it('multi hop: needed bytes at exactly 1300 keep the standard form', () => {
			const a = generateKeyPair();
			const b = generateKeyPair();
			// 600 + 32 + 636 + 32 = 1300
			const packet = constructOnionMessagePacket(crypto.randomBytes(32), [
				{ pubkey: a.pubkey, payload: Buffer.alloc(600) },
				{ pubkey: b.pubkey, payload: Buffer.alloc(636) }
			]);
			expect(packet.length).to.equal(ONION_MESSAGE_PACKET_LENGTH);
		});

		it('multi hop: one byte past 1300 selects the large form', () => {
			const a = generateKeyPair();
			const b = generateKeyPair();
			// 600 + 32 + 637 + 32 = 1301
			const packet = constructOnionMessagePacket(crypto.randomBytes(32), [
				{ pubkey: a.pubkey, payload: Buffer.alloc(600) },
				{ pubkey: b.pubkey, payload: Buffer.alloc(637) }
			]);
			expect(packet.length).to.equal(LARGE_ONION_PACKET_LENGTH);
		});

		it('throws by name when payloads exceed the large form', () => {
			const dest = generateKeyPair();
			expect(() =>
				constructOnionMessagePacket(crypto.randomBytes(32), [
					{ pubkey: dest.pubkey, payload: Buffer.alloc(33000) }
				])
			).to.throw(
				'Onion message payloads need 33032 bytes, exceeding the large form (32768)'
			);
		});
	});

	describe('Large-form round trips', () => {
		it('single hop: ~2000-byte TLV delivers over a 32834-byte packet', () => {
			const dest = generateKeyPair();
			const data = crypto.randomBytes(2000);
			const msgData = new Map<number, Buffer>();
			msgData.set(65, data);

			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);
			expect(msg.onionRoutingPacket.length).to.equal(LARGE_ONION_PACKET_LENGTH);

			const result = processOnionMessage(
				msg.onionRoutingPacket,
				dest.privkey,
				msg.blindingPoint
			);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(65)!.equals(data)).to.be.true;
			}
		});

		it('blinded two-hop: large onion peels at each hop and delivers', () => {
			const mid = generateKeyPair();
			const dest = generateKeyPair();
			const data = crypto.randomBytes(2000);
			const msgData = new Map<number, Buffer>();
			msgData.set(65, data);

			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[mid.pubkey, dest.pubkey],
				[{ nextNodeId: dest.pubkey }, {}]
			);
			const msg = constructReplyOnionMessage(path, msgData);
			expect(msg.onionRoutingPacket.length).to.equal(LARGE_ONION_PACKET_LENGTH);

			const atMid = processOnionMessage(
				msg.onionRoutingPacket,
				mid.privkey,
				msg.blindingPoint
			);
			expect(atMid.type).to.equal('forward');
			if (atMid.type !== 'forward') return;
			expect(atMid.nextNodeId.equals(dest.pubkey)).to.be.true;
			// Relay size preservation: the forwarded onion keeps the large form.
			expect(atMid.nextOnionMessage.onionRoutingPacket.length).to.equal(
				LARGE_ONION_PACKET_LENGTH
			);

			const atDest = processOnionMessage(
				atMid.nextOnionMessage.onionRoutingPacket,
				dest.privkey,
				atMid.nextOnionMessage.blindingPoint
			);
			expect(atDest.type).to.equal('delivery');
			if (atDest.type === 'delivery') {
				expect(atDest.payload.messageTlvs.get(65)!.equals(data)).to.be.true;
			}
		});

		it('blinded two-hop: small onion forwards at the standard size', () => {
			const mid = generateKeyPair();
			const dest = generateKeyPair();
			const msgData = new Map<number, Buffer>();
			msgData.set(65, Buffer.from('small'));

			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[mid.pubkey, dest.pubkey],
				[{ nextNodeId: dest.pubkey }, {}]
			);
			const msg = constructReplyOnionMessage(path, msgData);
			expect(msg.onionRoutingPacket.length).to.equal(
				ONION_MESSAGE_PACKET_LENGTH
			);

			const atMid = processOnionMessage(
				msg.onionRoutingPacket,
				mid.privkey,
				msg.blindingPoint
			);
			expect(atMid.type).to.equal('forward');
			if (atMid.type === 'forward') {
				expect(atMid.nextOnionMessage.onionRoutingPacket.length).to.equal(
					ONION_MESSAGE_PACKET_LENGTH
				);
			}
		});

		it('the 1269-1300 window (formerly silent corruption) verifies end to end', () => {
			// Find a TLV value length whose encoded final-hop payload lands in
			// 1269-1300 bytes: the payload still fit the 1300-byte buffer, but
			// payload + 32-byte HMAC did not, so the HMAC copy silently
			// truncated into a corrupt 1366-byte onion before the large form.
			const dest = generateKeyPair();
			let chosen: number | null = null;
			for (let v = 1180; v <= 1300; v++) {
				const encoded = encodeOnionMessagePayload({
					messageTlvs: new Map([[65, Buffer.alloc(v)]])
				});
				if (encoded.length >= 1269 && encoded.length <= 1300) {
					chosen = v;
					break;
				}
			}
			expect(chosen).to.not.be.null;

			const data = crypto.randomBytes(chosen!);
			const msgData = new Map<number, Buffer>();
			msgData.set(65, data);
			const msg = constructSimpleOnionMessage(dest.pubkey, msgData);
			expect(msg.onionRoutingPacket.length).to.equal(LARGE_ONION_PACKET_LENGTH);

			const result = processOnionMessage(
				msg.onionRoutingPacket,
				dest.privkey,
				msg.blindingPoint
			);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(65)!.equals(data)).to.be.true;
			}
		});
	});

	describe('Wire codec whitelists', () => {
		it('encodes and decodes the large form round-trip', () => {
			const kp = generateKeyPair();
			const packet = crypto.randomBytes(LARGE_ONION_PACKET_LENGTH);
			const encoded = encodeOnionMessage({
				blindingPoint: kp.pubkey,
				onionRoutingPacket: packet
			});
			expect(encoded.length).to.equal(33 + 2 + LARGE_ONION_PACKET_LENGTH);
			expect(encoded.readUInt16BE(33)).to.equal(LARGE_ONION_PACKET_LENGTH);

			const decoded = decodeOnionMessage(encoded);
			expect(decoded.blindingPoint.equals(kp.pubkey)).to.be.true;
			expect(decoded.onionRoutingPacket.equals(packet)).to.be.true;
		});

		it('encode rejects a packet that is neither form', () => {
			const kp = generateKeyPair();
			expect(() =>
				encodeOnionMessage({
					blindingPoint: kp.pubkey,
					onionRoutingPacket: Buffer.alloc(5000)
				})
			).to.throw('onion_routing_packet must be 1366 or 32834 bytes, got 5000');
		});

		it('decode rejects a len field that is neither form', () => {
			const buf = Buffer.alloc(35 + 5000);
			buf.writeUInt16BE(5000, 33);
			expect(() => decodeOnionMessage(buf)).to.throw(
				'onion_routing_packet len must be 1366 or 32834, got 5000'
			);
		});

		it('decodeOnionPacket accepts 32834 and rejects other sizes', () => {
			const decoded = decodeOnionPacket(
				Buffer.alloc(LARGE_ONION_PACKET_LENGTH)
			);
			expect(decoded.routingInfo.length).to.equal(LARGE_ROUTING_INFO_LENGTH);
			expect(() => decodeOnionPacket(Buffer.alloc(5000))).to.throw(
				'Onion packet must be 1366 or 32834 bytes, got 5000'
			);
		});

		it('encodeOnionPacket rejects a routing info that is neither form', () => {
			const kp = generateKeyPair();
			expect(() =>
				encodeOnionPacket({
					version: ONION_VERSION,
					ephemeralKey: kp.pubkey,
					routingInfo: Buffer.alloc(1301),
					hmac: Buffer.alloc(32)
				})
			).to.throw('Onion packet routing info must be 1300 or 32768 bytes');
		});
	});

	describe('Manager end to end', () => {
		it('delivers a large message through a forwarding hop and replies large', () => {
			const sender = generateKeyPair();
			const relay = generateKeyPair();
			const dest = generateKeyPair();
			const senderMgr = new OnionMessageManager(sender.privkey);
			const relayMgr = new OnionMessageManager(relay.privkey);
			const destMgr = new OnionMessageManager(dest.privkey);
			const byId = new Map<string, OnionMessageManager>([
				[sender.pubkey.toString('hex'), senderMgr],
				[relay.pubkey.toString('hex'), relayMgr],
				[dest.pubkey.toString('hex'), destMgr]
			]);
			const wireSizes: number[] = [];
			for (const [self, mgr] of [
				[sender, senderMgr],
				[relay, relayMgr],
				[dest, destMgr]
			] as const) {
				mgr.setSendFunction((peer, _type, payload) => {
					wireSizes.push(payload.length);
					byId.get(peer)?.handleMessage(self.pubkey.toString('hex'), payload);
				});
			}

			const forwarded: string[] = [];
			relayMgr.on('message:forwarded', (_f: string, next: string) =>
				forwarded.push(next)
			);
			const outbound = crypto.randomBytes(2000);
			const replyBody = crypto.randomBytes(1500);
			const replies: Buffer[] = [];
			destMgr.registerTlvHandler(65, (_f, _t, data, replyPath) => {
				expect(data.equals(outbound)).to.be.true;
				expect(replyPath).to.exist;
				destMgr.sendReply(replyPath!, new Map([[66, replyBody]]));
			});
			senderMgr.registerTlvHandler(66, (_f, _t, data) => {
				replies.push(data);
			});

			// The reply path terminates at the sender directly; in this loopback
			// wiring every manager can reach every other by real node id.
			const replyPath = constructBlindedPath(
				crypto.randomBytes(32),
				[sender.pubkey],
				[{}]
			);
			senderMgr.sendMultiHopOnionMessage(
				[relay.pubkey],
				dest.pubkey,
				new Map([[65, outbound]]),
				{ replyPath }
			);

			expect(forwarded).to.deep.equal([dest.pubkey.toString('hex')]);
			// Outbound leg: sender emit + relay forward, both the large wire size;
			// reply leg: destination emit, also large (1500-byte TLV).
			expect(wireSizes).to.deep.equal([
				33 + 2 + LARGE_ONION_PACKET_LENGTH,
				33 + 2 + LARGE_ONION_PACKET_LENGTH,
				33 + 2 + LARGE_ONION_PACKET_LENGTH
			]);
			expect(replies.length).to.equal(1);
			expect(replies[0].equals(replyBody)).to.be.true;

			senderMgr.destroy();
			relayMgr.destroy();
			destMgr.destroy();
		});
	});

	describe('Payment onions stay pinned at 1366', () => {
		it('processOnionPacket refuses a large-form routing info by name', () => {
			const kp = generateKeyPair();
			expect(() =>
				processOnionPacket(
					{
						version: ONION_VERSION,
						ephemeralKey: kp.pubkey,
						routingInfo: Buffer.alloc(LARGE_ROUTING_INFO_LENGTH),
						hmac: Buffer.alloc(32)
					},
					kp.privkey
				)
			).to.throw('Payment onion routing info must be 1300 bytes');
		});

		it('keeps the standard constants unchanged', () => {
			expect(ROUTING_INFO_LENGTH).to.equal(1300);
			expect(ONION_MESSAGE_PACKET_LENGTH).to.equal(1366);
		});
	});
});
