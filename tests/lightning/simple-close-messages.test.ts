/**
 * option_simple_close: closing_complete (40) / closing_sig (41) codecs.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	IClosingCompleteMessage,
	encodeClosingCompleteMessage,
	decodeClosingCompleteMessage,
	encodeClosingSigMessage,
	decodeClosingSigMessage
} from '../../src/lightning/message/channel-close';
import {
	MessageType,
	messageTypeName,
	isRequiredMessageType
} from '../../src/lightning/message/types';
import { encodeTlvStream } from '../../src/lightning/message/tlv';

const P2WPKH_A = Buffer.from('0014' + 'aa'.repeat(20), 'hex');
const P2WPKH_B = Buffer.from('0014' + 'bb'.repeat(20), 'hex');

function baseMsg(): IClosingCompleteMessage {
	return {
		channelId: crypto.randomBytes(32),
		closerScriptPubkey: P2WPKH_A,
		closeeScriptPubkey: P2WPKH_B,
		feeSatoshis: 1234n,
		locktime: 850_000,
		closerAndCloseeSig: crypto.randomBytes(64)
	};
}

/** Rebuild the fixed (pre-TLV) prefix of an encoded simple-close message. */
function fixedPrefix(msg: IClosingCompleteMessage): Buffer {
	const fixed = Buffer.alloc(
		32 +
			2 +
			msg.closerScriptPubkey.length +
			2 +
			msg.closeeScriptPubkey.length +
			8 +
			4
	);
	let o = 0;
	msg.channelId.copy(fixed, o);
	o += 32;
	fixed.writeUInt16BE(msg.closerScriptPubkey.length, o);
	o += 2;
	msg.closerScriptPubkey.copy(fixed, o);
	o += msg.closerScriptPubkey.length;
	fixed.writeUInt16BE(msg.closeeScriptPubkey.length, o);
	o += 2;
	msg.closeeScriptPubkey.copy(fixed, o);
	o += msg.closeeScriptPubkey.length;
	fixed.writeBigUInt64BE(msg.feeSatoshis, o);
	o += 8;
	fixed.writeUInt32BE(msg.locktime, o);
	return fixed;
}

describe('option_simple_close message codecs', function () {
	it('registers types 40/41 with names', function () {
		expect(MessageType.CLOSING_COMPLETE).to.equal(40);
		expect(MessageType.CLOSING_SIG).to.equal(41);
		expect(messageTypeName(40)).to.equal('CLOSING_COMPLETE');
		expect(messageTypeName(41)).to.equal('CLOSING_SIG');
		expect(isRequiredMessageType(40)).to.equal(true);
		expect(isRequiredMessageType(41)).to.equal(false);
	});

	it('round-trips each single-sig variant', function () {
		const variants: Array<Partial<IClosingCompleteMessage>> = [
			{ closerOutputOnlySig: crypto.randomBytes(64) },
			{ closeeOutputOnlySig: crypto.randomBytes(64) },
			{ closerAndCloseeSig: crypto.randomBytes(64) }
		];
		for (const v of variants) {
			const msg = { ...baseMsg(), closerAndCloseeSig: undefined, ...v };
			const decoded = decodeClosingCompleteMessage(
				encodeClosingCompleteMessage(msg)
			);
			expect(decoded.channelId.equals(msg.channelId)).to.equal(true);
			expect(decoded.closerScriptPubkey.equals(P2WPKH_A)).to.equal(true);
			expect(decoded.closeeScriptPubkey.equals(P2WPKH_B)).to.equal(true);
			expect(decoded.feeSatoshis).to.equal(1234n);
			expect(decoded.locktime).to.equal(850_000);
			for (const key of [
				'closerOutputOnlySig',
				'closeeOutputOnlySig',
				'closerAndCloseeSig'
			] as const) {
				if (msg[key]) {
					expect(decoded[key]!.equals(msg[key]!)).to.equal(true);
				} else {
					expect(decoded[key]).to.equal(undefined);
				}
			}
		}
	});

	it('round-trips a two-sig closing_complete (TLVs 1 and 3)', function () {
		const msg = {
			...baseMsg(),
			closerOutputOnlySig: crypto.randomBytes(64),
			closerAndCloseeSig: crypto.randomBytes(64)
		};
		const decoded = decodeClosingCompleteMessage(
			encodeClosingCompleteMessage(msg)
		);
		expect(
			decoded.closerOutputOnlySig!.equals(msg.closerOutputOnlySig!)
		).to.equal(true);
		expect(
			decoded.closerAndCloseeSig!.equals(msg.closerAndCloseeSig!)
		).to.equal(true);
		expect(decoded.closeeOutputOnlySig).to.equal(undefined);
	});

	it('closing_sig uses the same layout', function () {
		const msg = baseMsg();
		const decoded = decodeClosingSigMessage(encodeClosingSigMessage(msg));
		expect(
			decoded.closerAndCloseeSig!.equals(msg.closerAndCloseeSig!)
		).to.equal(true);
	});

	it('rejects encoding without any signature', function () {
		const msg = { ...baseMsg(), closerAndCloseeSig: undefined };
		expect(() => encodeClosingCompleteMessage(msg)).to.throw(
			/at least one signature/
		);
	});

	it('rejects encoding a non-64-byte signature', function () {
		const msg = { ...baseMsg(), closerAndCloseeSig: crypto.randomBytes(63) };
		expect(() => encodeClosingCompleteMessage(msg)).to.throw(/64 bytes/);
	});

	it('rejects decoding with no signature TLV', function () {
		const msg = baseMsg();
		expect(() => decodeClosingCompleteMessage(fixedPrefix(msg))).to.throw(
			/no closing signature/
		);
	});

	it('rejects a short signature TLV on decode', function () {
		const msg = baseMsg();
		const tlv = encodeTlvStream([{ type: 3n, value: crypto.randomBytes(32) }]);
		expect(() =>
			decodeClosingCompleteMessage(Buffer.concat([fixedPrefix(msg), tlv]))
		).to.throw(/64 bytes/);
	});

	it('rejects an unknown even TLV type', function () {
		const msg = baseMsg();
		const tlv = encodeTlvStream([
			{ type: 3n, value: crypto.randomBytes(64) },
			{ type: 4n, value: Buffer.from([1]) }
		]);
		expect(() =>
			decodeClosingCompleteMessage(Buffer.concat([fixedPrefix(msg), tlv]))
		).to.throw(/Unknown required TLV/);
	});

	it('ignores an unknown odd TLV type', function () {
		const msg = baseMsg();
		const tlv = encodeTlvStream([
			{ type: 3n, value: crypto.randomBytes(64) },
			{ type: 5n, value: Buffer.from([1, 2, 3]) }
		]);
		const decoded = decodeClosingCompleteMessage(
			Buffer.concat([fixedPrefix(msg), tlv])
		);
		expect(decoded.closerAndCloseeSig).to.exist;
	});

	it('rejects out-of-order TLVs', function () {
		const msg = baseMsg();
		// Hand-build a misordered stream (encodeTlvStream would refuse).
		const rec3 = Buffer.concat([Buffer.from([3, 64]), crypto.randomBytes(64)]);
		const rec1 = Buffer.concat([Buffer.from([1, 64]), crypto.randomBytes(64)]);
		expect(() =>
			decodeClosingCompleteMessage(
				Buffer.concat([fixedPrefix(msg), rec3, rec1])
			)
		).to.throw(/not in order/);
	});

	it('rejects truncated payloads', function () {
		const msg = baseMsg();
		const encoded = encodeClosingCompleteMessage(msg);
		expect(() =>
			decodeClosingCompleteMessage(encoded.subarray(0, 30))
		).to.throw(/too short/);
		// Cut inside the closee script
		expect(() =>
			decodeClosingCompleteMessage(encoded.subarray(0, 32 + 2 + 22 + 2 + 5))
		).to.throw(/exceeds payload/);
	});

	it('handles an empty closee script (closer_output_only case)', function () {
		const msg: IClosingCompleteMessage = {
			...baseMsg(),
			closeeScriptPubkey: Buffer.alloc(0),
			closerAndCloseeSig: undefined,
			closerOutputOnlySig: crypto.randomBytes(64)
		};
		const decoded = decodeClosingCompleteMessage(
			encodeClosingCompleteMessage(msg)
		);
		expect(decoded.closeeScriptPubkey.length).to.equal(0);
	});
});
