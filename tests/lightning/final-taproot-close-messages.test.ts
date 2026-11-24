import { expect } from 'chai';
import {
	decodeClosingCompleteMessage,
	decodeClosingSigMessage,
	encodeClosingCompleteMessage,
	encodeClosingSigMessage
} from '../../src/lightning/message/channel-close';

// Eclair v0.14.0 LightningMessageCodecsSpec, "encode/decode closing messages".
// https://github.com/ACINQ/eclair/blob/ec8c63b215b98148887237e3f050342a6ca61f4c/eclair-core/src/test/scala/fr/acinq/eclair/wire/protocol/LightningMessageCodecsSpec.scala
// Pinned BOLT requires TLV 22 in closing_sig. Eclair's standalone codec examples
// for the signature records omit it. Check the complete BOLT message here.
// https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/bolt-simple-taproot.md#closing_sig-extensions
const hex = (s: string): Buffer => Buffer.from(s, 'hex');
const id = '58a00a6f14e69a2e97b18cf76f755c8551fea9947cf7b6ece9d641013eba5f86';
const nonce1 =
	'52682593fd0783ea60657ed2d118e8f958c4a7a198237749b6729eccf963be1bc559531ec4b83bcfc42009cd08f7e95747146cec2fd09571b3fa76656e3012a4c97a';
const nonce2 =
	'585b2fe8ca7a969bbda11ee9cbc95386abfddcc901967f84da4011c2a7cb5ada1dae51bdcd93a8b2933fcec7b2cda5a3f43ea2d0a29eb126bd329d4735d5389fe703';
const nonce3 =
	'19bed0825ceb5acf504cddea72e37a75505290a22850c183725963edfe2dfb9f26e27180b210c05635987b80b3de3b7d01732653565b9f25ec23f7aff26122e00bff';
const nextNonce = 'ab'.repeat(66);
const base = {
	channelId: hex(id),
	closerScriptPubkey: hex('deadbeef'),
	closeeScriptPubkey: hex('d43db3ef1234'),
	feeSatoshis: 1105n,
	locktime: 0
};
const prefix = id + '0004deadbeef0006d43db3ef1234000000000000045100000000';
const opt = { finalTaproot: true };
const variants = [
	{
		field: 'closerOutputOnlyPartialSig',
		tag: '05',
		sig: '01'.repeat(32),
		nonce: nonce1
	},
	{
		field: 'closeeOutputOnlyPartialSig',
		tag: '06',
		sig: '02'.repeat(32),
		nonce: nonce2
	},
	{
		field: 'closerAndCloseePartialSig',
		tag: '07',
		sig: '03'.repeat(32),
		nonce: nonce3
	}
] as const;
const codecs = [
	{
		name: 'closing_complete',
		encode: encodeClosingCompleteMessage,
		decode: decodeClosingCompleteMessage
	},
	{
		name: 'closing_sig',
		encode: encodeClosingSigMessage,
		decode: decodeClosingSigMessage
	}
] as const;

describe('Final Taproot simple-close message codecs', () => {
	for (const codec of codecs) {
		const complete = codec.name === 'closing_complete';
		const nonceFields = complete ? {} : { nextCloseeNonce: hex(nextNonce) };
		const nonceRecord = complete ? '' : '1642' + nextNonce;
		const record = (v: (typeof variants)[number]): string =>
			complete ? v.tag + '62' + v.sig + v.nonce : v.tag + '20' + v.sig;

		for (const v of variants) {
			it(`${codec.name} encodes and decodes ${v.field}`, () => {
				const value = hex(complete ? v.sig + v.nonce : v.sig);
				const msg = { ...base, [v.field]: value, ...nonceFields };
				const wire = hex(prefix + record(v) + nonceRecord);
				expect(codec.encode(msg, opt)).to.deep.equal(wire);
				expect(codec.decode(wire, opt)).to.deep.equal(msg);
				expect(
					codec.decode(hex(wire.toString('hex') + '1901cd'), opt)
				).to.deep.equal(msg);
			});
		}

		it(`${codec.name} enforces signature widths and canonical TLV streams`, () => {
			for (const v of variants) {
				const size = complete ? 98 : 32;
				for (const len of [size - 1, size + 1]) {
					const wrong = Buffer.alloc(len);
					expect(() =>
						codec.encode({ ...base, [v.field]: wrong, ...nonceFields }, opt)
					).to.throw();
					expect(() =>
						codec.decode(
							hex(
								prefix +
									v.tag +
									len.toString(16) +
									'00'.repeat(len) +
									nonceRecord
							),
							opt
						)
					).to.throw();
				}
			}
			const sig = record(variants[0]);
			for (const tail of [
				sig + sig + nonceRecord,
				'fd0005' + sig.slice(2) + nonceRecord,
				sig + nonceRecord + '1800',
				(sig + nonceRecord).slice(0, -2)
			]) {
				expect(() => codec.decode(hex(prefix + tail), opt)).to.throw();
			}
			expect(() =>
				codec.decode(hex(prefix + nonceRecord + '1900'), opt)
			).to.throw();
			expect(() => codec.encode({ ...base, ...nonceFields }, opt)).to.throw();
		});

		it(`${codec.name} refuses ECDSA signatures in final mode and preserves ordinary framing`, () => {
			const partial = variants[0];
			for (const [tag, name] of [
				['01', 'closerOutputOnlySig'],
				['02', 'closeeOutputOnlySig'],
				['03', 'closerAndCloseeSig']
			]) {
				const plain = tag + '40' + 'ab'.repeat(64);
				const ecdsa = { ...base, [name]: Buffer.alloc(64, 0xab) };
				expect(codec.encode(ecdsa)).to.deep.equal(hex(prefix + plain));
				expect(
					codec.decode(hex(prefix + plain + '0501aa0701bb'))
				).to.deep.equal(ecdsa);
				expect(() => codec.decode(hex(prefix + plain + '0600'))).to.throw();
				expect(() =>
					codec.decode(hex(prefix + plain + '1642' + nextNonce))
				).to.throw();
				for (const extra of ['', record(partial)]) {
					expect(() =>
						codec.decode(hex(prefix + plain + extra + nonceRecord), opt)
					).to.throw();
				}
				expect(() =>
					codec.encode(
						{
							...ecdsa,
							[partial.field]: hex(
								complete ? partial.sig + partial.nonce : partial.sig
							),
							...nonceFields
						},
						opt
					)
				).to.throw();
			}
		});

		it(`${codec.name} rejects a short channel id and respects the Lightning payload limit`, () => {
			const v = variants[0];
			const msg = {
				...base,
				[v.field]: hex(complete ? v.sig + v.nonce : v.sig),
				...nonceFields
			};
			expect(() =>
				codec.encode({ ...msg, channelId: Buffer.alloc(31) }, opt)
			).to.throw();
			expect(() =>
				codec.encode({ ...msg, channelId: Buffer.alloc(33) }, opt)
			).to.throw();
			const records = hex(record(v) + nonceRecord);
			const size = 65533 - 48 - records.length;
			const large = {
				...msg,
				closerScriptPubkey: Buffer.alloc(size),
				closeeScriptPubkey: Buffer.alloc(0)
			};
			const encoded = codec.encode(large, opt);
			expect(encoded).to.have.length(65533);
			expect(codec.decode(encoded, opt)).to.deep.equal(large);
			expect(() =>
				codec.encode(
					{ ...large, closerScriptPubkey: Buffer.alloc(size + 1) },
					opt
				)
			).to.throw();
			// One extra valid framing byte in closer_scriptpubkey, with its length updated.
			const oversized = Buffer.concat([
				encoded.subarray(0, 34),
				Buffer.alloc(1),
				encoded.subarray(34)
			]);
			oversized.writeUInt16BE(size + 1, 32);
			expect(() => codec.decode(oversized, opt)).to.throw();
		});
	}

	it('allows either single-output proposal alongside a two-output proposal', () => {
		for (const single of [variants[0], variants[1]]) {
			const both = variants[2];
			const msg = {
				...base,
				[single.field]: hex(single.sig + single.nonce),
				[both.field]: hex(both.sig + both.nonce)
			};
			const wire = hex(
				prefix +
					single.tag +
					'62' +
					single.sig +
					single.nonce +
					'0762' +
					both.sig +
					both.nonce
			);
			expect(encodeClosingCompleteMessage(msg, opt)).to.deep.equal(wire);
			expect(decodeClosingCompleteMessage(wire, opt)).to.deep.equal(msg);
		}
	});

	it('rejects proposals that drop each output in a different signed variant', () => {
		for (const fields of [variants.slice(0, 2), variants]) {
			const msg = Object.fromEntries(
				fields.map((v) => [v.field, hex(v.sig + v.nonce)])
			);
			expect(() =>
				encodeClosingCompleteMessage({ ...base, ...msg }, opt)
			).to.throw();
			const wire =
				prefix + fields.map((v) => v.tag + '62' + v.sig + v.nonce).join('');
			expect(() => decodeClosingCompleteMessage(hex(wire), opt)).to.throw();
		}
	});

	it('takes the next nonce only on closing_sig, where exactly one signature must be present', () => {
		const [closer, closee] = variants;
		const complete = {
			...base,
			[closer.field]: hex(closer.sig + closer.nonce),
			nextCloseeNonce: hex(nextNonce)
		};
		expect(() => encodeClosingCompleteMessage(complete, opt)).to.throw();
		expect(() =>
			decodeClosingCompleteMessage(
				hex(prefix + '0562' + closer.sig + closer.nonce + '1642' + nextNonce),
				opt
			)
		).to.throw();
		const sig = { ...base, [closer.field]: hex(closer.sig) };
		const one = prefix + '0520' + closer.sig;
		expect(() => encodeClosingSigMessage(sig, opt)).to.throw();
		expect(() => decodeClosingSigMessage(hex(one), opt)).to.throw();
		for (const len of [65, 67]) {
			expect(() =>
				encodeClosingSigMessage(
					{ ...sig, nextCloseeNonce: Buffer.alloc(len) },
					opt
				)
			).to.throw();
			expect(() =>
				decodeClosingSigMessage(
					hex(one + '16' + len.toString(16) + '00'.repeat(len)),
					opt
				)
			).to.throw();
		}
		const two = {
			...sig,
			[closee.field]: hex(closee.sig),
			nextCloseeNonce: hex(nextNonce)
		};
		expect(() => encodeClosingSigMessage(two, opt)).to.throw();
		expect(() =>
			decodeClosingSigMessage(
				hex(one + '0620' + closee.sig + '1642' + nextNonce),
				opt
			)
		).to.throw();
	});
});
