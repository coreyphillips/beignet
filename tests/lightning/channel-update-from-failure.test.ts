/**
 * Tests for extractChannelUpdate from BOLT 4 failure messages.
 *
 * Verifies correct extraction of embedded channel_update payloads from
 * various failure types, including prefix stripping and edge cases.
 */

import { expect } from 'chai';
import { extractChannelUpdate } from '../../src/lightning/onion/failures';
import {
	FEE_INSUFFICIENT,
	UNKNOWN_NEXT_PEER,
	TEMPORARY_CHANNEL_FAILURE
} from '../../src/lightning/onion/types';

describe('Channel Update Extraction from Failure Messages', () => {
	it('extracts channel_update from FEE_INSUFFICIENT failure data', () => {
		// FEE_INSUFFICIENT: 8 bytes htlc_msat + 2-byte len + channel_update
		const htlcMsat = Buffer.alloc(8);
		htlcMsat.writeBigUInt64BE(1000000n);
		const channelUpdatePayload = Buffer.alloc(64, 0xab); // 64 bytes of fake update
		const lenBuf = Buffer.alloc(2);
		lenBuf.writeUInt16BE(channelUpdatePayload.length);
		const failureData = Buffer.concat([htlcMsat, lenBuf, channelUpdatePayload]);

		const result = extractChannelUpdate(FEE_INSUFFICIENT, failureData);
		expect(result).to.not.be.null;
		expect(result!.length).to.equal(64);
		expect(result!.equals(channelUpdatePayload)).to.be.true;
	});

	it('returns null for UNKNOWN_NEXT_PEER (no embedded update)', () => {
		const failureData = Buffer.alloc(32, 0xff);
		const result = extractChannelUpdate(UNKNOWN_NEXT_PEER, failureData);
		expect(result).to.be.null;
	});

	it('returns null for truncated/empty failure data', () => {
		// FEE_INSUFFICIENT needs 8-byte offset + 2-byte len minimum
		expect(extractChannelUpdate(FEE_INSUFFICIENT, Buffer.alloc(0))).to.be.null;
		expect(extractChannelUpdate(FEE_INSUFFICIENT, Buffer.alloc(2))).to.be.null;
		// TEMPORARY_CHANNEL_FAILURE needs at least 2-byte len
		expect(extractChannelUpdate(TEMPORARY_CHANNEL_FAILURE, Buffer.alloc(1))).to
			.be.null;
	});

	it('strips 2-byte type prefix (0x0102) if present', () => {
		// TEMPORARY_CHANNEL_FAILURE: 2-byte len + channel_update
		const rawPayload = Buffer.alloc(32, 0xcd); // 32 bytes of actual update data
		const withPrefix = Buffer.concat([
			Buffer.from([0x01, 0x02]), // type 258 prefix
			rawPayload
		]);
		const lenBuf = Buffer.alloc(2);
		lenBuf.writeUInt16BE(withPrefix.length); // len includes the prefix
		const failureData = Buffer.concat([lenBuf, withPrefix]);

		const result = extractChannelUpdate(TEMPORARY_CHANNEL_FAILURE, failureData);
		expect(result).to.not.be.null;
		expect(result!.length).to.equal(32);
		expect(result!.equals(rawPayload)).to.be.true;
	});
});
