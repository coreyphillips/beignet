/**
 * BOLT 4 LOW-severity hardening batch (2026-07-15 review):
 *  - onion-message routing_info seeded from the pad-key stream, not zeros;
 *  - hop-payload length 0/1 rejected as invalid_onion_payload + TLV order/dup
 *    enforced;
 *  - MPP: a part whose total_msat disagrees with the set is failed;
 *  - blinded-path encrypted_recipient_data path_id (type 6) round-trips and is
 *    surfaced on final delivery;
 *  - BOLT 11 encodeTaggedField rejects a > 1023-word field instead of
 *    corrupting the length.
 * (The invoice cleartext-hints-with-blinded opt-in and MPP wiring are covered
 * by the node-level suites; here we cover the self-contained codecs.)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { encodeTaggedField } from '../../src/lightning/invoice/words';
import {
	encodeHopPayload,
	decodeHopPayload
} from '../../src/lightning/onion/hop-payload';
import { encodeBigSize } from '../../src/lightning/message/codec';
import {
	encodeBlindedHopData,
	decodeBlindedHopData
} from '../../src/lightning/onion/blinded-path';
import { constructOnionMessagePacket } from '../../src/lightning/onion-message/construct';
import { processOnionMessage } from '../../src/lightning/onion-message/process';
import { encodeOnionMessagePayload } from '../../src/lightning/onion-message/codec';
import { decodeOnionPacket } from '../../src/lightning/onion/construct';
import { ROUTING_INFO_LENGTH } from '../../src/lightning/onion/types';
import {
	computeSharedSecrets,
	deriveHopKeys,
	generateCipherStream,
	generateKey
} from '../../src/lightning/onion/sphinx-crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

describe('BOLT 4 LOW hardening batch', function () {
	describe('BOLT 11 encodeTaggedField overflow', function () {
		it('rejects a data field longer than 1023 words instead of corrupting it', function () {
			const ok = new Array(1023).fill(0);
			expect(() => encodeTaggedField(1, ok)).to.not.throw();
			const tooBig = new Array(1024).fill(0);
			expect(() => encodeTaggedField(1, tooBig)).to.throw(/1023/);
		});
	});

	describe('hop-payload validation', function () {
		it('round-trips a normal TLV hop payload', function () {
			const encoded = encodeHopPayload({
				amountToForwardMsat: 1000n,
				outgoingCltvValue: 700,
				shortChannelId: crypto.randomBytes(8)
			});
			const { payload } = decodeHopPayload(encoded, 0);
			expect(payload.amountToForwardMsat).to.equal(1000n);
			expect(payload.outgoingCltvValue).to.equal(700);
		});

		it('rejects a payload of length 0 or 1 as invalid_onion_payload', function () {
			// length prefix 0
			expect(() => decodeHopPayload(Buffer.from([0x00]), 0)).to.throw(
				/invalid_onion_payload/
			);
			// length prefix 1 + one content byte
			expect(() => decodeHopPayload(Buffer.from([0x01, 0x02]), 0)).to.throw(
				/invalid_onion_payload/
			);
		});

		it('rejects out-of-order (or duplicate) TLV types', function () {
			// A hand-built payload with TLV type 4 BEFORE type 2 (misordered).
			const t4 = Buffer.concat([
				encodeBigSize(4n),
				encodeBigSize(1n),
				Buffer.from([0x2c])
			]);
			const t2 = Buffer.concat([
				encodeBigSize(2n),
				encodeBigSize(1n),
				Buffer.from([0x01])
			]);
			const body = Buffer.concat([t4, t2]);
			const payload = Buffer.concat([encodeBigSize(BigInt(body.length)), body]);
			expect(() => decodeHopPayload(payload, 0)).to.throw(
				/out of order|invalid_onion_payload/
			);
		});
	});

	describe('encrypted_recipient_data path_id (type 6)', function () {
		it('round-trips a path_id', function () {
			const pathId = crypto.randomBytes(32);
			const decoded = decodeBlindedHopData(encodeBlindedHopData({ pathId }));
			expect(decoded.pathId!.equals(pathId)).to.equal(true);
		});

		it('keeps next_node_id and path_id independent', function () {
			const nextNodeId = Buffer.concat([
				Buffer.from([0x02]),
				crypto.randomBytes(32)
			]);
			const pathId = crypto.randomBytes(16);
			const decoded = decodeBlindedHopData(
				encodeBlindedHopData({ nextNodeId, pathId })
			);
			expect(decoded.nextNodeId!.equals(nextNodeId)).to.equal(true);
			expect(decoded.pathId!.equals(pathId)).to.equal(true);
		});
	});

	describe('onion-message routing_info pad stream (BOLT 4)', function () {
		// For a 1-hop message the packet's unused tail is init[j] ^ rho[shift+j],
		// where init is the initial routing_info fill and shift = payload + hmac.
		// Recovering the tail and XORing the rho stream back out exposes exactly
		// which stream seeded the packet, letting us pin the key derivation.
		function buildAndRecoverInitTail(
			sessionKey: Buffer,
			destPriv: Buffer
		): {
			recovered: Buffer;
			padFromSession: Buffer;
			padFromHopSecret: Buffer;
		} {
			const destPub = getPublicKey(destPriv);
			const payload = encodeOnionMessagePayload({
				messageTlvs: new Map([[65, Buffer.from('ping')]])
			});
			const packetBuf = constructOnionMessagePacket(sessionKey, [
				{ pubkey: destPub, payload }
			]);
			const packet = decodeOnionPacket(packetBuf);

			const { sharedSecrets } = computeSharedSecrets(sessionKey, [destPub]);
			const keys = deriveHopKeys(sharedSecrets[0]);
			const rho = generateCipherStream(keys.rho, ROUTING_INFO_LENGTH);
			const shift = payload.length + 32;
			const tailLen = ROUTING_INFO_LENGTH - shift;

			const recovered = Buffer.alloc(tailLen);
			for (let j = 0; j < tailLen; j++) {
				recovered[j] = packet.routingInfo[shift + j] ^ rho[shift + j];
			}
			return {
				recovered,
				padFromSession: generateCipherStream(
					generateKey('pad', sessionKey),
					tailLen
				),
				padFromHopSecret: generateCipherStream(keys.pad, tailLen)
			};
		}

		it('seeds routing_info from the SESSION-key pad stream, not zeros or a hop secret', function () {
			const sessionKey = crypto.randomBytes(32);
			const destPriv = crypto.randomBytes(32);
			const { recovered, padFromSession, padFromHopSecret } =
				buildAndRecoverInitTail(sessionKey, destPriv);

			// Spec derivation: generate_key("pad", session_key).
			expect(recovered.equals(padFromSession)).to.equal(true);
			// NOT zeros (would leak hop count to every hop)...
			expect(recovered.equals(Buffer.alloc(recovered.length))).to.equal(false);
			// ...and NOT keyed from the first hop's shared secret (the first hop
			// knows that secret and could regenerate the stream to locate the
			// padding boundary).
			expect(recovered.equals(padFromHopSecret)).to.equal(false);
		});

		it('round-trips: the destination still receives the message', function () {
			const sessionKey = crypto.randomBytes(32);
			const destPriv = crypto.randomBytes(32);
			const destPub = getPublicKey(destPriv);
			const payload = encodeOnionMessagePayload({
				messageTlvs: new Map([[65, Buffer.from('ping')]])
			});
			const packetBuf = constructOnionMessagePacket(sessionKey, [
				{ pubkey: destPub, payload }
			]);
			const result = processOnionMessage(packetBuf, destPriv);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(65)!.toString()).to.equal('ping');
			}
		});
	});

	describe('encodeHopPayload record ordering', function () {
		it('encodes a custom record with a low type in strict TLV order', function () {
			// A custom (odd) type below the fixed types used to be appended after
			// type 8/10/12, producing a misordered stream our own hardened decoder
			// rejects. The encoder now sorts the full record set.
			const encoded = encodeHopPayload({
				amountToForwardMsat: 1000n,
				outgoingCltvValue: 700,
				paymentSecret: crypto.randomBytes(32),
				totalMsat: 1000n,
				customRecords: new Map([[7, Buffer.from([0xaa])]])
			});
			const { payload } = decodeHopPayload(encoded, 0);
			expect(payload.amountToForwardMsat).to.equal(1000n);
			expect(
				payload.customRecords!.get(7)!.equals(Buffer.from([0xaa]))
			).to.equal(true);
		});
	});
});
