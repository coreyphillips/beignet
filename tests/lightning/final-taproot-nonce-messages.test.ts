import { expect } from 'chai';
import {
	decodeRevokeAndAckMessage,
	encodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import {
	decodeChannelReestablishMessage,
	encodeChannelReestablishMessage
} from '../../src/lightning/message/channel-reestablish';
import { FforState } from '../../src/lightning/ffor/types';

// Wire layouts from Eclair v0.14.0, LightningMessageCodecsSpec (lines 172-173, 183-184).
// https://github.com/ACINQ/eclair/blob/ec8c63b215b98148887237e3f050342a6ca61f4c/eclair-core/src/test/scala/fr/acinq/eclair/wire/protocol/LightningMessageCodecsSpec.scala
// The funding hashes below are in wire order. Eclair's fixture reverses its
// display-order TxId.value before concatenating it with the 66 nonce bytes.
const hex = (s: string): Buffer => Buffer.from(s, 'hex');
const channelId = Buffer.alloc(32, 0x11);
const secret = Buffer.alloc(32, 0x22);
const point = Buffer.concat([Buffer.of(3), Buffer.alloc(32, 0x44)]);
const revoke = {
	channelId,
	perCommitmentSecret: secret,
	nextPerCommitmentPoint: point
};
const reconnect = {
	channelId,
	nextCommitmentNumber: 0x0001020304050607n,
	nextRevocationNumber: 0x0809aabbccddeeffn,
	yourLastPerCommitmentSecret: secret,
	myCurrentPerCommitmentPoint: point
};
const revokeBase = Buffer.concat([channelId, secret, point]);
const reconnectBase = Buffer.concat([
	channelId,
	hex('00010203040506070809aabbccddeeff'),
	secret,
	point
]);

const firstTxid = hex(
	'1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100'
);
const nextTxid = hex(
	'3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120'
);
// Framing tests use opaque bytes just as the reference codec does.
const firstNonce = Buffer.alloc(66, 0x55);
const nextNonce = Buffer.alloc(66, 0x66);
const current = Buffer.alloc(66, 0x77);
const entries = [
	{ fundingTxid: firstTxid, nonce: firstNonce },
	{ fundingTxid: nextTxid, nonce: nextNonce }
];
const firstPair = Buffer.concat([firstTxid, firstNonce]);
const nextPair = Buffer.concat([nextTxid, nextNonce]);
const one = Buffer.concat([hex('1662'), firstPair]);
const two = Buffer.concat([hex('16c4'), firstPair, nextPair]);
const staging = Buffer.concat([hex('0442'), nextNonce]);
const currentRecord = Buffer.concat([hex('1842'), current]);
const finalTaproot = { finalTaproot: true };

interface INonceFields {
	nextLocalNonce?: Buffer;
	nextLocalNonces?: typeof entries;
}

const codecs = [
	{
		name: 'revoke_and_ack',
		base: revokeBase,
		encode: (fields: INonceFields): Buffer =>
			encodeRevokeAndAckMessage({ ...revoke, ...fields }),
		decode: decodeRevokeAndAckMessage
	},
	{
		name: 'channel_reestablish',
		base: reconnectBase,
		encode: (fields: INonceFields): Buffer =>
			encodeChannelReestablishMessage({ ...reconnect, ...fields }),
		decode: decodeChannelReestablishMessage
	}
];

describe('Final Taproot commitment nonce messages', function () {
	for (const codec of codecs) {
		describe(codec.name, function () {
			for (const [count, record] of [
				[1, one],
				[2, two]
			] as const) {
				it(`matches TLV 22 with ${count} funding entries`, function () {
					const list = entries.slice(0, count);
					const expected = Buffer.concat([codec.base, record]);
					expect(codec.encode({ nextLocalNonces: list })).to.deep.equal(
						expected
					);
					expect(
						codec.decode(expected, finalTaproot).nextLocalNonces
					).to.deep.equal(list);
				});
			}

			it('decodes a canonical BigSize length and ignores an unknown odd record', function () {
				const third = {
					fundingTxid: Buffer.alloc(32, 0x08),
					nonce: Buffer.alloc(66, 0x88)
				};
				const list = [...entries, third];
				const expected = Buffer.concat([
					codec.base,
					hex('16fd0126'),
					firstPair,
					nextPair,
					third.fundingTxid,
					third.nonce
				]);
				expect(codec.encode({ nextLocalNonces: list })).to.deep.equal(expected);
				expect(
					codec.decode(Buffer.concat([expected, hex('1901ab')]), finalTaproot)
						.nextLocalNonces
				).to.deep.equal(list);
			});

			it('writes only nonce lists that fit the transport frame', function () {
				const list = Array.from({ length: 668 }, (_, index) => {
					const fundingTxid = Buffer.alloc(32);
					fundingTxid.writeUInt32LE(index);
					return { fundingTxid, nonce: nextNonce };
				});
				const max = codec.encode({ nextLocalNonces: list.slice(0, 667) });
				expect(max.length).to.equal(codec.base.length + 4 + 667 * 98);
				expect(() => codec.encode({ nextLocalNonces: list })).to.throw();
				if (codec.name === 'channel_reestablish') {
					expect(() =>
						encodeChannelReestablishMessage({
							...reconnect,
							nextLocalNonces: list.slice(0, 667),
							currentCommitNonce: current
						})
					).to.throw();
				}
			});

			it('checks the transport limit including unknown odd records and the message type', function () {
				for (const length of [65_532, 65_533, 65_534]) {
					// Four bytes for the padding TLV, 1-byte type and 3-byte BigSize length.
					const padding = Buffer.alloc(
						length - codec.base.length - one.length - 4
					);
					const prefix = hex('19fd0000');
					prefix.writeUInt16BE(padding.length, 2);
					const raw = Buffer.concat([codec.base, one, prefix, padding]);
					if (length === 65_534) {
						expect(() => codec.decode(raw, finalTaproot)).to.throw();
					} else {
						expect(
							codec.decode(raw, finalTaproot).nextLocalNonces
						).to.deep.equal(entries.slice(0, 1));
					}
				}
			});

			it('preserves ordinary and staging encodings and decoded shapes by default', function () {
				expect(codec.encode({})).to.deep.equal(codec.base);
				const plain = codec.decode(codec.base);
				expect(plain).not.to.have.property('nextLocalNonces');
				expect(plain).not.to.have.property('currentCommitNonce');
				const legacy = Buffer.concat([codec.base, staging]);
				expect(codec.encode({ nextLocalNonce: nextNonce })).to.deep.equal(
					legacy
				);
				expect(codec.decode(legacy).nextLocalNonce).to.deep.equal(nextNonce);
				expect(() => codec.decode(Buffer.concat([codec.base, one]))).to.throw();
			});

			it('refuses a staging nonce when reading final-profile messages', function () {
				for (const tail of [staging, Buffer.concat([staging, one])]) {
					expect(() =>
						codec.decode(Buffer.concat([codec.base, tail]), finalTaproot)
					).to.throw();
				}
				expect(() =>
					codec.encode({ nextLocalNonce: firstNonce, nextLocalNonces: entries })
				).to.throw();
			});

			it('refuses empty lists, duplicate funding hashes and wrong field widths when writing', function () {
				const invalid = [
					[],
					[entries[0], { ...entries[1], fundingTxid: Buffer.from(firstTxid) }]
				];
				for (const size of [31, 33])
					invalid.push([
						{ fundingTxid: Buffer.alloc(size), nonce: firstNonce }
					]);
				for (const size of [65, 67])
					invalid.push([{ fundingTxid: firstTxid, nonce: Buffer.alloc(size) }]);
				for (const list of invalid)
					expect(() => codec.encode({ nextLocalNonces: list })).to.throw();
			});

			it('refuses empty, truncated, trailing, duplicate and noncanonical records when reading', function () {
				const invalid = [
					hex('1600'),
					Buffer.concat([hex('1661'), firstPair.subarray(1)]),
					Buffer.concat([hex('1663'), firstPair, hex('00')]),
					one.subarray(0, -1),
					Buffer.concat([hex('16c4'), firstPair, firstTxid, nextNonce]),
					Buffer.concat([one, one]),
					Buffer.concat([hex('fd001662'), firstPair]),
					Buffer.concat([hex('16fd0062'), firstPair]),
					Buffer.concat([hex('1700'), one]),
					Buffer.concat([one, hex('1a00')])
				];
				for (const tail of invalid) {
					expect(() =>
						codec.decode(Buffer.concat([codec.base, tail]), finalTaproot)
					).to.throw();
				}
			});
		});
	}

	it('refuses a final revoke_and_ack without TLV 22', function () {
		expect(() =>
			decodeRevokeAndAckMessage(revokeBase, finalTaproot)
		).to.throw();
	});

	it('refuses a final revoke_and_ack carrying only an unrelated odd TLV', function () {
		const wire = Buffer.concat([revokeBase, hex('1901ab')]);
		expect(() => decodeRevokeAndAckMessage(wire, finalTaproot)).to.throw();
	});

	it('accepts an ordinary revoke_and_ack without TLV 22', function () {
		expect(decodeRevokeAndAckMessage(revokeBase)).to.deep.equal({
			...revoke,
			nextLocalNonce: undefined
		});
	});

	it('reads and writes the opening reconnect current commitment nonce on its own', function () {
		const expected = Buffer.concat([reconnectBase, currentRecord]);
		expect(
			encodeChannelReestablishMessage({
				...reconnect,
				currentCommitNonce: current
			})
		).to.deep.equal(expected);
		expect(
			decodeChannelReestablishMessage(expected, finalTaproot).currentCommitNonce
		).to.deep.equal(current);
		expect(() => decodeChannelReestablishMessage(expected)).to.throw();
		expect(() =>
			decodeRevokeAndAckMessage(
				Buffer.concat([revokeBase, currentRecord]),
				finalTaproot
			)
		).to.throw();
	});

	it('checks TLV 24 lengths and disallows staging plus a current commitment nonce', function () {
		for (const size of [0, 65, 67]) {
			const nonce = Buffer.alloc(size);
			expect(() =>
				encodeChannelReestablishMessage({
					...reconnect,
					currentCommitNonce: nonce
				})
			).to.throw();
			const raw = Buffer.concat([reconnectBase, Buffer.of(24, size), nonce]);
			expect(() =>
				decodeChannelReestablishMessage(raw, finalTaproot)
			).to.throw();
		}
		expect(() =>
			encodeChannelReestablishMessage({
				...reconnect,
				nextLocalNonce: nextNonce,
				currentCommitNonce: current
			})
		).to.throw();
	});

	it('writes next_funding, locked funding, nonce entries, current nonce and FFOR in canonical order', function () {
		const ffor = {
			epochId: Buffer.alloc(32, 0x99),
			state: FforState.ACTIVE,
			lastSeq: 0x1234,
			activationHash: Buffer.alloc(32, 0xaa)
		};
		const message = {
			...reconnect,
			nextFundingTxid: nextTxid,
			nextFundingRetransmitFlags: 1,
			myCurrentFundingLocked: { txid: firstTxid, retransmitFlags: 0 },
			nextLocalNonces: entries,
			currentCommitNonce: current,
			ffor
		};
		const expected = Buffer.concat([
			reconnectBase,
			hex('0121'),
			nextTxid,
			hex('01'),
			hex('0521'),
			firstTxid,
			hex('00'),
			two,
			currentRecord,
			hex('fdd6d943'),
			ffor.epochId,
			Buffer.of(ffor.state),
			hex('1234'),
			ffor.activationHash
		]);
		expect(encodeChannelReestablishMessage(message)).to.deep.equal(expected);
		expect(
			decodeChannelReestablishMessage(expected, finalTaproot)
		).to.deep.equal(message);
	});
});
