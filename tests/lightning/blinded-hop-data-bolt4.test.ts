/**
 * M1-FU3 — encrypted_recipient_data is real BOLT 4 TLV (interop-capable).
 *
 * Proves the blinded hop data is a TLV stream with the spec types (scid=2,
 * next_node_id=4, payment_relay=10, payment_constraints=12, padding=1) and
 * truncated integers — so an LND/CLN introduction node can parse it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	encodeBlindedHopData,
	decodeBlindedHopData,
	IBlindedHopData
} from '../../src/lightning/onion/blinded-path';
import { decodeTlvStream } from '../../src/lightning/message/tlv';

describe('BOLT 4 encrypted_recipient_data TLV (M1-FU3)', function () {
	it('encodes a payment hop as a parseable TLV stream with spec types', function () {
		const scid = crypto.randomBytes(8);
		const data: IBlindedHopData = {
			shortChannelId: scid,
			paymentRelay: {
				cltvExpiryDelta: 144,
				feeProportionalMillionths: 250,
				feeBaseMsat: 1000
			},
			paymentConstraints: {
				maxCltvExpiry: 800500,
				htlcMinimumMsat: 1n
			}
		};

		const encoded = encodeBlindedHopData(data);
		// A generic TLV decoder must parse it (proves it's a valid TLV stream).
		const { records } = decodeTlvStream(encoded);
		const types = records.map((r) => Number(r.type));
		expect(types).to.deep.equal([2, 10, 12]); // scid, payment_relay, constraints

		// short_channel_id is verbatim 8 bytes.
		expect(records[0].value).to.deep.equal(scid);

		// Round-trips losslessly.
		const back = decodeBlindedHopData(encoded);
		expect(back.shortChannelId).to.deep.equal(scid);
		expect(back.paymentRelay).to.deep.equal(data.paymentRelay);
		expect(back.paymentConstraints!.maxCltvExpiry).to.equal(800500);
		expect(back.paymentConstraints!.htlcMinimumMsat).to.equal(1n);
	});

	it('uses next_node_id (type 4) for onion-message hops', function () {
		const nextNodeId = crypto.randomBytes(33);
		const encoded = encodeBlindedHopData({ nextNodeId });
		const { records } = decodeTlvStream(encoded);
		expect(records.map((r) => Number(r.type))).to.deep.equal([4]);
		expect(records[0].value).to.deep.equal(nextNodeId);
		expect(decodeBlindedHopData(encoded).nextNodeId).to.deep.equal(nextNodeId);
	});

	it('truncates integers minimally (fee_base 0 → empty, large htlc_min)', function () {
		const zeroFee = encodeBlindedHopData({
			paymentRelay: {
				cltvExpiryDelta: 40,
				feeProportionalMillionths: 0,
				feeBaseMsat: 0
			}
		});
		const { records: r1 } = decodeTlvStream(zeroFee);
		// payment_relay value = u16(2) + u32(4) + tu32(0 bytes) = 6.
		expect(r1[0].value.length).to.equal(6);
		expect(decodeBlindedHopData(zeroFee).paymentRelay!.feeBaseMsat).to.equal(0);

		const bigMin = encodeBlindedHopData({
			paymentConstraints: {
				maxCltvExpiry: 900000,
				htlcMinimumMsat: 4_294_967_296n // > u32, needs 5 bytes
			}
		});
		const back = decodeBlindedHopData(bigMin);
		expect(back.paymentConstraints!.htlcMinimumMsat).to.equal(4_294_967_296n);
	});

	it('keeps the beignet hold_htlc marker (custom odd type, ignorable)', function () {
		const encoded = encodeBlindedHopData({
			shortChannelId: crypto.randomBytes(8),
			holdHtlc: true
		});
		// Decodes as a valid TLV stream; the hold marker is a high odd type.
		const { records } = decodeTlvStream(encoded);
		expect(records.some((r) => r.type === 65537n)).to.be.true;
		expect(decodeBlindedHopData(encoded).holdHtlc).to.equal(true);
	});

	it('ignores unknown odd TLV records (forward-compatible)', function () {
		const base = encodeBlindedHopData({ shortChannelId: crypto.randomBytes(8) });
		// Append an unknown odd TLV after scid(type 2): type 7, len 2, value 0xaabb.
		const extra = Buffer.from([0x07, 0x02, 0xaa, 0xbb]);
		const withExtra = Buffer.concat([base, extra]);
		const back = decodeBlindedHopData(withExtra);
		expect(back.shortChannelId).to.exist;
	});
});
