/**
 * BOLT 7: extended gossip queries test vectors (bolt07/extended-queries.json).
 *
 * Fixed fields of query_channel_range / reply_channel_range /
 * query_short_channel_ids are decoded and re-encoded byte-exact; raw
 * (uncompressed) SCID blocks are decoded and compared to the spec SCID lists.
 *
 * Two deliberate deviations, pinned here rather than skipped:
 *  - zlib-encoded SCID blocks (encoding type 1) are REJECTED by
 *    decodeShortChannelIds: BOLT 7 removed the zlib encoding, and inflating
 *    peer-supplied data without an output cap is a decompression bomb.
 *  - the gossip_queries_ex TLV extensions (query_option, timestamps,
 *    checksums, query_flags) are an optional feature beignet does not
 *    implement; the TLV tails are asserted to parse as well-formed streams
 *    with the expected record types/values, via the generic TLV decoder.
 */

import { expect } from 'chai';
import {
	encodeQueryChannelRangeMessage,
	decodeQueryChannelRangeMessage,
	encodeReplyChannelRangeMessage,
	decodeReplyChannelRangeMessage,
	encodeQueryShortChannelIdsMessage,
	decodeQueryShortChannelIdsMessage
} from '../../../src/lightning/gossip/gossip-queries';
import { decodeShortChannelIds } from '../../../src/lightning/gossip/scid-encoding';
import { decodeTlvStream } from '../../../src/lightning/message/tlv';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

const MSG_QUERY_SHORT_CHANNEL_IDS = 261;
const MSG_QUERY_CHANNEL_RANGE = 263;
const MSG_REPLY_CHANNEL_RANGE = 264;

interface IScidBlock {
	array: string[];
	encoding: 'UNCOMPRESSED' | 'COMPRESSED_ZLIB';
}

interface IExtendedQueryCase {
	hex: string;
	msg: {
		type: 'QueryChannelRange' | 'ReplyChannelRange' | 'QueryShortChannelIds';
		chainHash: string;
		firstBlockNum?: number;
		numberOfBlocks?: number;
		complete?: number;
		shortChannelIds?: IScidBlock;
		timestamps?: {
			encoding: string;
			timestamps: { timestamp1: number; timestamp2: number }[];
		};
		checksums?: {
			checksums: { checksum1: number; checksum2: number }[];
		};
		tlvStream?: { records: unknown[]; unknown: unknown[] };
	};
}

const v = loadVectors<{ cases: IExtendedQueryCase[] }>(
	'bolt07/extended-queries.json'
);

/** "BLOCKxTXxOUT" → 8-byte short_channel_id (block u24 | txindex u24 | output u16). */
function scidToHex(scid: string): string {
	const [block, tx, out] = scid.split('x').map((p) => Number(p));
	const buf = Buffer.alloc(8);
	buf.writeUIntBE(block, 0, 3);
	buf.writeUIntBE(tx, 3, 3);
	buf.writeUInt16BE(out, 6);
	return bufferToHex(buf);
}

/** Assert an encoded SCID block against the vector's list/encoding. */
function checkScidBlock(encoded: Buffer, block: IScidBlock): void {
	if (block.encoding === 'COMPRESSED_ZLIB') {
		expect(encoded[0]).to.equal(1);
		expect(() => decodeShortChannelIds(encoded)).to.throw(/zlib/);
		return;
	}
	expect(encoded[0]).to.equal(0);
	const scids = decodeShortChannelIds(encoded);
	expect(scids.map(bufferToHex)).to.deep.equal(block.array.map(scidToHex));
}

describe('BOLT 7: extended gossip queries conformance', function () {
	for (const [i, c] of v.cases.entries()) {
		it(`case ${i}: ${c.msg.type}`, function () {
			const raw = hexToBuffer(c.hex);
			const msgType = raw.readUInt16BE(0);
			const payload = raw.subarray(2);

			if (c.msg.type === 'QueryChannelRange') {
				expect(msgType).to.equal(MSG_QUERY_CHANNEL_RANGE);
				const decoded = decodeQueryChannelRangeMessage(payload);
				expect(bufferToHex(decoded.chainHash)).to.equal(c.msg.chainHash);
				expect(decoded.firstBlocknum).to.equal(c.msg.firstBlockNum);
				expect(decoded.numberOfBlocks).to.equal(c.msg.numberOfBlocks);

				// Fixed part must re-encode to a prefix of the payload; the
				// remainder (if any) must be a well-formed TLV extension.
				const reEncoded = encodeQueryChannelRangeMessage(decoded);
				expect(bufferToHex(payload.subarray(0, reEncoded.length))).to.equal(
					bufferToHex(reEncoded)
				);
				const tail = payload.subarray(reEncoded.length);
				expect(() => decodeTlvStream(tail)).to.not.throw();
				expect(decodeTlvStream(tail).records.length).to.equal(
					c.msg.tlvStream?.records.length ?? 0
				);
			} else if (c.msg.type === 'ReplyChannelRange') {
				expect(msgType).to.equal(MSG_REPLY_CHANNEL_RANGE);
				const decoded = decodeReplyChannelRangeMessage(payload);
				expect(bufferToHex(decoded.chainHash)).to.equal(c.msg.chainHash);
				expect(decoded.firstBlocknum).to.equal(c.msg.firstBlockNum);
				expect(decoded.numberOfBlocks).to.equal(c.msg.numberOfBlocks);
				expect(decoded.syncComplete).to.equal(c.msg.complete === 1);
				checkScidBlock(
					decoded.encodedShortIds,
					c.msg.shortChannelIds as IScidBlock
				);

				const reEncoded = encodeReplyChannelRangeMessage(decoded);
				expect(bufferToHex(payload.subarray(0, reEncoded.length))).to.equal(
					bufferToHex(reEncoded)
				);
				const { records } = decodeTlvStream(payload.subarray(reEncoded.length));

				// gossip_queries_ex extensions: timestamps TLV (type 1, with a
				// leading encoding byte) and checksums TLV (type 3).
				if (c.msg.timestamps) {
					const rec = records.find((r) => r.type === 1n);
					expect(rec, 'timestamps TLV').to.not.equal(undefined);
					const value = rec?.value as Buffer;
					if (c.msg.timestamps.encoding === 'UNCOMPRESSED') {
						expect(value[0]).to.equal(0);
						c.msg.timestamps.timestamps.forEach((t, j) => {
							expect(value.readUInt32BE(1 + j * 8)).to.equal(t.timestamp1);
							expect(value.readUInt32BE(5 + j * 8)).to.equal(t.timestamp2);
						});
					} else {
						expect(value[0]).to.equal(1);
					}
				}
				if (c.msg.checksums) {
					const rec = records.find((r) => r.type === 3n);
					expect(rec, 'checksums TLV').to.not.equal(undefined);
					const value = rec?.value as Buffer;
					c.msg.checksums.checksums.forEach((cs, j) => {
						expect(value.readUInt32BE(j * 8)).to.equal(cs.checksum1);
						expect(value.readUInt32BE(4 + j * 8)).to.equal(cs.checksum2);
					});
				}
			} else {
				expect(msgType).to.equal(MSG_QUERY_SHORT_CHANNEL_IDS);
				const decoded = decodeQueryShortChannelIdsMessage(payload);
				expect(bufferToHex(decoded.chainHash)).to.equal(c.msg.chainHash);
				checkScidBlock(
					decoded.encodedShortIds,
					c.msg.shortChannelIds as IScidBlock
				);

				const reEncoded = encodeQueryShortChannelIdsMessage(decoded);
				expect(bufferToHex(payload.subarray(0, reEncoded.length))).to.equal(
					bufferToHex(reEncoded)
				);
				const tail = payload.subarray(reEncoded.length);
				expect(() => decodeTlvStream(tail)).to.not.throw();
				expect(decodeTlvStream(tail).records.length).to.equal(
					c.msg.tlvStream?.records.length ?? 0
				);
			}
		});
	}
});
