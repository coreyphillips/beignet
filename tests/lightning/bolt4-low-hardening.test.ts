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
});
