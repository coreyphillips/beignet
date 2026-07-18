/**
 * BOLT 1: TLV stream test vectors (Appendix B).
 *
 * Stream-level rules (truncation, canonical BigSize, strict ordering,
 * unknown-even rejection) are asserted directly against decodeTlvStream.
 * The n1/n2 namespaces are artificial spec constructs with no production
 * decoder, so a small test-local interpreter maps decoded records to typed
 * values (tu64 minimality, fixed lengths, point validity) — those content
 * rules are what the n1-specific vectors exercise.
 */

import { expect } from 'chai';
import {
	decodeTlvStream,
	ITlvRecord
} from '../../../src/lightning/message/tlv';
import { decodeTruncatedUint } from '../../../src/lightning/onion/hop-payload';
import { isValidPublicKey } from '../../../src/lightning/crypto/ecdh';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IInvalidCase {
	stream: string;
	reason: string;
}

interface IValidN1Case {
	stream: string;
	values: {
		tlv1?: { amount_msat: string };
		tlv2?: { scid: string };
		tlv3?: { node_id: string; amount_msat_1: string; amount_msat_2: string };
		tlv4?: { cltv_delta: number };
	};
}

interface ITlvVectors {
	namespaces: { n1: string[]; n2: string[] };
	invalid_any_namespace: IInvalidCase[];
	invalid_either_namespace: IInvalidCase[];
	invalid_n1: IInvalidCase[];
	valid_ignored: { stream: string; explanation: string }[];
	valid_n1: IValidN1Case[];
	invalid_ordering_n1: IInvalidCase[];
	invalid_ordering_n2: IInvalidCase[];
}

const v = loadVectors<ITlvVectors>('bolt01/tlv-stream.json');

const n1Types = new Set(v.namespaces.n1.map((t) => BigInt(t)));
const n2Types = new Set(v.namespaces.n2.map((t) => BigInt(t)));

/** "BLOCKxTXxOUT" → 8-byte short_channel_id (block u24 | txindex u24 | output u16). */
function scidToBuffer(scid: string): Buffer {
	const [block, tx, out] = scid.split('x').map((p) => Number(p));
	const buf = Buffer.alloc(8);
	buf.writeUIntBE(block, 0, 3);
	buf.writeUIntBE(tx, 3, 3);
	buf.writeUInt16BE(out, 6);
	return buf;
}

/** tu64 content rules: at most 8 bytes, no leading zero byte (minimality). */
function decodeTu64(value: Buffer, field: string): bigint {
	if (value.length > 8) {
		throw new Error(`${field}: greater than tu64 encoding length`);
	}
	if (value.length > 0 && value[0] === 0) {
		throw new Error(`${field}: encoding is not minimal`);
	}
	return decodeTruncatedUint(value);
}

interface IN1Values {
	tlv1?: { amountMsat: bigint };
	tlv2?: { scid: Buffer };
	tlv3?: { nodeId: Buffer; amountMsat1: bigint; amountMsat2: bigint };
	tlv4?: { cltvDelta: number };
}

/** Test-local n1 namespace interpreter over the generic TLV stream decoder. */
function decodeN1(stream: Buffer): IN1Values {
	const { records } = decodeTlvStream(stream, 0, n1Types);
	const out: IN1Values = {};
	for (const r of records as ITlvRecord[]) {
		if (r.type === 1n) {
			out.tlv1 = { amountMsat: decodeTu64(r.value, 'n1 tlv1 amount_msat') };
		} else if (r.type === 2n) {
			if (r.value.length !== 8) {
				throw new Error('n1 tlv2: wrong encoding length for short_channel_id');
			}
			out.tlv2 = { scid: r.value };
		} else if (r.type === 3n) {
			if (r.value.length !== 49) {
				throw new Error('n1 tlv3: wrong encoding length');
			}
			const nodeId = r.value.subarray(0, 33);
			if (!isValidPublicKey(Buffer.from(nodeId))) {
				throw new Error('n1 tlv3: node_id is not a valid point');
			}
			out.tlv3 = {
				nodeId: Buffer.from(nodeId),
				amountMsat1: r.value.readBigUInt64BE(33),
				amountMsat2: r.value.readBigUInt64BE(41)
			};
		} else if (r.type === 254n) {
			if (r.value.length !== 2) {
				throw new Error('n1 tlv4: wrong encoding length for cltv_delta');
			}
			out.tlv4 = { cltvDelta: r.value.readUInt16BE(0) };
		}
	}
	return out;
}

describe('BOLT 1: TLV stream conformance', function () {
	describe('decoding failures in any namespace', function () {
		for (const c of v.invalid_any_namespace) {
			it(`rejects 0x${c.stream} (${c.reason})`, function () {
				const stream = hexToBuffer(c.stream);
				expect(() => decodeTlvStream(stream, 0, n1Types)).to.throw();
				expect(() => decodeTlvStream(stream, 0, n2Types)).to.throw();
			});
		}
	});

	describe('unknown even types fail in either namespace', function () {
		for (const c of v.invalid_either_namespace) {
			it(`rejects 0x${c.stream} (${c.reason})`, function () {
				const stream = hexToBuffer(c.stream);
				expect(() => decodeTlvStream(stream, 0, n1Types)).to.throw(
					/Unknown required TLV type/
				);
				expect(() => decodeTlvStream(stream, 0, n2Types)).to.throw(
					/Unknown required TLV type/
				);
			});
		}
	});

	describe('n1-specific decoding failures', function () {
		for (const c of v.invalid_n1) {
			it(`rejects 0x${c.stream} (${c.reason})`, function () {
				expect(() => decodeN1(hexToBuffer(c.stream))).to.throw();
			});
		}
	});

	describe('valid streams with only unknown odd types decode and are ignored', function () {
		for (const c of v.valid_ignored) {
			it(`accepts 0x${c.stream || '(empty)'} (${c.explanation})`, function () {
				const stream = hexToBuffer(c.stream);
				expect(decodeN1(stream)).to.deep.equal({});
				expect(() => decodeTlvStream(stream, 0, n2Types)).to.not.throw();
			});
		}
	});

	describe('valid n1 streams decode to the spec values', function () {
		for (const c of v.valid_n1) {
			it(`decodes 0x${c.stream}`, function () {
				const decoded = decodeN1(hexToBuffer(c.stream));
				if (c.values.tlv1) {
					expect(decoded.tlv1?.amountMsat).to.equal(
						BigInt(c.values.tlv1.amount_msat)
					);
				}
				if (c.values.tlv2) {
					expect(bufferToHex(decoded.tlv2?.scid as Buffer)).to.equal(
						bufferToHex(scidToBuffer(c.values.tlv2.scid))
					);
				}
				if (c.values.tlv3) {
					expect(bufferToHex(decoded.tlv3?.nodeId as Buffer)).to.equal(
						c.values.tlv3.node_id
					);
					expect(decoded.tlv3?.amountMsat1).to.equal(
						BigInt(c.values.tlv3.amount_msat_1)
					);
					expect(decoded.tlv3?.amountMsat2).to.equal(
						BigInt(c.values.tlv3.amount_msat_2)
					);
				}
				if (c.values.tlv4) {
					expect(decoded.tlv4?.cltvDelta).to.equal(c.values.tlv4.cltv_delta);
				}
			});
		}
	});

	describe('ordering and duplicate failures', function () {
		for (const c of v.invalid_ordering_n1) {
			it(`rejects 0x${c.stream} in n1 (${c.reason})`, function () {
				expect(() =>
					decodeTlvStream(hexToBuffer(c.stream), 0, n1Types)
				).to.throw(/not in order/);
			});
		}
		for (const c of v.invalid_ordering_n2) {
			it(`rejects 0x${c.stream} in n2 (${c.reason})`, function () {
				expect(() =>
					decodeTlvStream(hexToBuffer(c.stream), 0, n2Types)
				).to.throw(/not in order/);
			});
		}
	});
});
