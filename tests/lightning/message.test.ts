import { expect } from 'chai';
import {
	encodeBigSize,
	decodeBigSize,
	encodeMessage,
	decodeMessage
} from '../../src/lightning/message/codec';
import {
	encodeTlvRecord,
	encodeTlvStream,
	decodeTlvStream,
	findTlvRecord,
	ITlvRecord
} from '../../src/lightning/message/tlv';
import {
	MessageType,
	isRequiredMessageType,
	messageTypeName
} from '../../src/lightning/message/types';
import {
	encodeInitMessage,
	decodeInitMessage
} from '../../src/lightning/message/init';
import {
	encodeErrorMessage,
	decodeErrorMessage,
	createError,
	createConnectionError,
	isConnectionError,
	getErrorText,
	ALL_CHANNELS
} from '../../src/lightning/message/error';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

describe('Lightning Messages', function () {
	describe('BigSize Encoding (BOLT 1 Test Vectors)', function () {
		// BOLT 1 Appendix A: BigSize encoding test vectors
		const encodingTests: Array<{ value: bigint; hex: string }> = [
			{ value: 0n, hex: '00' },
			{ value: 252n, hex: 'fc' },
			{ value: 253n, hex: 'fd00fd' },
			{ value: 65535n, hex: 'fdffff' },
			{ value: 65536n, hex: 'fe00010000' },
			{ value: 4294967295n, hex: 'feffffffff' },
			{ value: 4294967296n, hex: 'ff0000000100000000' },
			{ value: 18446744073709551615n, hex: 'ffffffffffffffffff' }
		];

		for (const { value, hex } of encodingTests) {
			it(`Should encode ${value} as 0x${hex}`, function () {
				const encoded = encodeBigSize(value);
				expect(encoded.toString('hex')).to.equal(hex);
			});
		}

		for (const { value, hex } of encodingTests) {
			it(`Should decode 0x${hex} as ${value}`, function () {
				const buf = Buffer.from(hex, 'hex');
				const result = decodeBigSize(buf);
				expect(result.value).to.equal(value);
				expect(result.bytesRead).to.equal(buf.length);
			});
		}

		// Non-canonical encodings should be rejected
		const nonCanonicalTests: Array<{ hex: string; desc: string }> = [
			{ hex: 'fd00fc', desc: '253-encoded value < 253' },
			{ hex: 'fe0000ffff', desc: '65536-encoded value < 65536' },
			{
				hex: 'ff00000000ffffffff',
				desc: '4294967296-encoded value < 4294967296'
			}
		];

		for (const { hex, desc } of nonCanonicalTests) {
			it(`Should reject non-canonical: ${desc} (0x${hex})`, function () {
				const buf = Buffer.from(hex, 'hex');
				expect(() => decodeBigSize(buf)).to.throw('non-canonical');
			});
		}

		// Truncation errors
		const truncationTests: Array<{ hex: string; desc: string }> = [
			{ hex: 'fd00', desc: 'truncated 2-byte value' },
			{ hex: 'feffff', desc: 'truncated 4-byte value' },
			{ hex: 'ffffffffff', desc: 'truncated 8-byte value' },
			{ hex: 'fd', desc: 'prefix only (fd)' },
			{ hex: 'fe', desc: 'prefix only (fe)' },
			{ hex: 'ff', desc: 'prefix only (ff)' }
		];

		for (const { hex, desc } of truncationTests) {
			it(`Should reject truncated: ${desc} (0x${hex})`, function () {
				const buf = Buffer.from(hex, 'hex');
				expect(() => decodeBigSize(buf)).to.throw('unexpected end');
			});
		}

		it('Should reject empty buffer', function () {
			expect(() => decodeBigSize(Buffer.alloc(0))).to.throw('unexpected end');
		});

		it('Should reject negative BigSize values', function () {
			expect(() => encodeBigSize(-1n)).to.throw('non-negative');
		});

		it('Should decode with offset', function () {
			// Prefix bytes + BigSize value
			const prefix = Buffer.from([0xaa, 0xbb]);
			const bigsize = encodeBigSize(1000n);
			const buf = Buffer.concat([prefix, bigsize]);

			const result = decodeBigSize(buf, 2);
			expect(result.value).to.equal(1000n);
		});
	});

	describe('Message Framing', function () {
		it('Should encode a message with type and payload', function () {
			const payload = Buffer.from([0x01, 0x02, 0x03]);
			const msg = encodeMessage(16, payload);

			expect(msg.length).to.equal(5);
			expect(msg.readUInt16BE(0)).to.equal(16);
			expect(msg.subarray(2).equals(payload)).to.be.true;
		});

		it('Should decode a message', function () {
			const raw = Buffer.from([0x00, 0x10, 0x01, 0x02, 0x03]);
			const { type, payload } = decodeMessage(raw);

			expect(type).to.equal(16);
			expect(payload.equals(Buffer.from([0x01, 0x02, 0x03]))).to.be.true;
		});

		it('Should handle empty payload', function () {
			const msg = encodeMessage(17, Buffer.alloc(0));
			const { type, payload } = decodeMessage(msg);

			expect(type).to.equal(17);
			expect(payload.length).to.equal(0);
		});

		it('Should roundtrip encode/decode', function () {
			const originalType = 256;
			const originalPayload = Buffer.from('channel_announcement data');

			const encoded = encodeMessage(originalType, originalPayload);
			const { type, payload } = decodeMessage(encoded);

			expect(type).to.equal(originalType);
			expect(payload.equals(originalPayload)).to.be.true;
		});

		it('Should reject message type out of range', function () {
			expect(() => encodeMessage(-1, Buffer.alloc(0))).to.throw();
			expect(() => encodeMessage(65536, Buffer.alloc(0))).to.throw();
		});

		it('Should reject too-short message', function () {
			expect(() => decodeMessage(Buffer.alloc(1))).to.throw('too short');
		});
	});

	describe('TLV Streams', function () {
		it('Should encode a single TLV record', function () {
			const record: ITlvRecord = {
				type: 1n,
				value: Buffer.from([0xaa, 0xbb])
			};
			const encoded = encodeTlvRecord(record);

			// type=1 (1 byte) + length=2 (1 byte) + value (2 bytes) = 4 bytes
			expect(encoded.length).to.equal(4);
			expect(encoded[0]).to.equal(1); // type
			expect(encoded[1]).to.equal(2); // length
			expect(encoded[2]).to.equal(0xaa);
			expect(encoded[3]).to.equal(0xbb);
		});

		it('Should encode a TLV stream', function () {
			const records: ITlvRecord[] = [
				{ type: 1n, value: Buffer.from([0x01]) },
				{ type: 3n, value: Buffer.from([0x02, 0x03]) }
			];
			const encoded = encodeTlvStream(records);
			const { records: decoded } = decodeTlvStream(encoded);

			expect(decoded.length).to.equal(2);
			expect(decoded[0].type).to.equal(1n);
			expect(decoded[0].value.equals(Buffer.from([0x01]))).to.be.true;
			expect(decoded[1].type).to.equal(3n);
			expect(decoded[1].value.equals(Buffer.from([0x02, 0x03]))).to.be.true;
		});

		it('Should decode an empty TLV stream', function () {
			const { records, bytesRead } = decodeTlvStream(Buffer.alloc(0));
			expect(records.length).to.equal(0);
			expect(bytesRead).to.equal(0);
		});

		it('Should reject out-of-order TLV records in encoding', function () {
			const records: ITlvRecord[] = [
				{ type: 3n, value: Buffer.alloc(0) },
				{ type: 1n, value: Buffer.alloc(0) }
			];
			expect(() => encodeTlvStream(records)).to.throw('strictly increasing');
		});

		it('Should reject duplicate TLV types in encoding', function () {
			const records: ITlvRecord[] = [
				{ type: 1n, value: Buffer.alloc(0) },
				{ type: 1n, value: Buffer.alloc(0) }
			];
			expect(() => encodeTlvStream(records)).to.throw('strictly increasing');
		});

		it('Should reject out-of-order TLV records in decoding', function () {
			// Manually construct out-of-order: type=3, len=0, type=1, len=0
			const data = Buffer.from([0x03, 0x00, 0x01, 0x00]);
			expect(() => decodeTlvStream(data)).to.throw('not in order');
		});

		it('Should reject unknown even (required) TLV types', function () {
			const records: ITlvRecord[] = [
				{ type: 2n, value: Buffer.alloc(0) } // even = required
			];
			const encoded = encodeTlvStream(records);

			const knownTypes = new Set<bigint>([0n]); // 2n is not known
			expect(() => decodeTlvStream(encoded, 0, knownTypes)).to.throw(
				'Unknown required TLV type'
			);
		});

		it('Should skip unknown odd (optional) TLV types', function () {
			const records: ITlvRecord[] = [
				{ type: 1n, value: Buffer.from([0x01]) }, // odd = optional
				{ type: 3n, value: Buffer.from([0x02]) }
			];
			const encoded = encodeTlvStream(records);

			const knownTypes = new Set<bigint>([0n]); // neither 1n nor 3n known
			// Should not throw — odd types are optional
			const { records: decoded } = decodeTlvStream(encoded, 0, knownTypes);
			expect(decoded.length).to.equal(2);
		});

		it('Should reject truncated TLV value', function () {
			// type=1, length=5, but only 2 bytes of value
			const data = Buffer.from([0x01, 0x05, 0xaa, 0xbb]);
			expect(() => decodeTlvStream(data)).to.throw('only');
		});

		it('Should handle TLV records with large type numbers', function () {
			const records: ITlvRecord[] = [
				{ type: 1000n, value: Buffer.from([0x42]) }
			];
			const encoded = encodeTlvStream(records);
			const { records: decoded } = decodeTlvStream(encoded);

			expect(decoded.length).to.equal(1);
			expect(decoded[0].type).to.equal(1000n);
			expect(decoded[0].value.equals(Buffer.from([0x42]))).to.be.true;
		});

		describe('findTlvRecord', function () {
			it('Should find an existing record', function () {
				const records: ITlvRecord[] = [
					{ type: 1n, value: Buffer.from([0x01]) },
					{ type: 3n, value: Buffer.from([0x03]) }
				];

				const found = findTlvRecord(records, 3n);
				expect(found).to.not.be.undefined;
				expect(found!.equals(Buffer.from([0x03]))).to.be.true;
			});

			it('Should return undefined for missing record', function () {
				const records: ITlvRecord[] = [
					{ type: 1n, value: Buffer.from([0x01]) }
				];
				expect(findTlvRecord(records, 99n)).to.be.undefined;
			});
		});
	});

	describe('Message Types', function () {
		it('Should have correct INIT type value', function () {
			expect(MessageType.INIT).to.equal(16);
		});

		it('Should have correct ERROR type value', function () {
			expect(MessageType.ERROR).to.equal(17);
		});

		it('Should have correct channel message types', function () {
			expect(MessageType.OPEN_CHANNEL).to.equal(32);
			expect(MessageType.ACCEPT_CHANNEL).to.equal(33);
			expect(MessageType.FUNDING_CREATED).to.equal(34);
			expect(MessageType.FUNDING_SIGNED).to.equal(35);
			expect(MessageType.CHANNEL_READY).to.equal(36);
		});

		it('Should have correct HTLC message types', function () {
			expect(MessageType.UPDATE_ADD_HTLC).to.equal(128);
			expect(MessageType.UPDATE_FULFILL_HTLC).to.equal(130);
			expect(MessageType.COMMITMENT_SIGNED).to.equal(132);
			expect(MessageType.REVOKE_AND_ACK).to.equal(133);
		});

		it('Should have correct gossip message types', function () {
			expect(MessageType.CHANNEL_ANNOUNCEMENT).to.equal(256);
			expect(MessageType.NODE_ANNOUNCEMENT).to.equal(257);
			expect(MessageType.CHANNEL_UPDATE).to.equal(258);
		});

		it('Should identify required (even) message types', function () {
			expect(isRequiredMessageType(MessageType.INIT)).to.be.true; // 16
			expect(isRequiredMessageType(MessageType.PING)).to.be.true; // 18
			expect(isRequiredMessageType(MessageType.OPEN_CHANNEL)).to.be.true; // 32
		});

		it('Should identify optional (odd) message types', function () {
			expect(isRequiredMessageType(MessageType.ERROR)).to.be.false; // 17
			expect(isRequiredMessageType(MessageType.ACCEPT_CHANNEL)).to.be.false; // 33
			expect(isRequiredMessageType(MessageType.WARNING)).to.be.false; // 1
		});

		it('Should return message type name', function () {
			expect(messageTypeName(16)).to.equal('INIT');
			expect(messageTypeName(17)).to.equal('ERROR');
			expect(messageTypeName(99999)).to.equal('UNKNOWN(99999)');
		});
	});

	describe('Init Message', function () {
		it('Should encode and decode an init with no features', function () {
			const msg = {
				features: FeatureFlags.empty()
			};
			const encoded = encodeInitMessage(msg);
			const decoded = decodeInitMessage(encoded);

			expect(decoded.features.toBuffer().length).to.equal(0);
		});

		it('Should encode and decode an init with features', function () {
			const features = FeatureFlags.empty();
			features.setOptional(Feature.STATIC_REMOTE_KEY);
			features.setOptional(Feature.TLV_ONION);

			const msg = { features };
			const encoded = encodeInitMessage(msg);
			const decoded = decodeInitMessage(encoded);

			expect(decoded.features.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
			expect(decoded.features.hasFeature(Feature.TLV_ONION)).to.be.true;
			expect(decoded.features.hasFeature(Feature.BASIC_MPP)).to.be.false;
		});

		it('Should encode and decode an init with networks', function () {
			// Bitcoin mainnet chain hash
			const mainnetHash = Buffer.from(
				'6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000',
				'hex'
			);

			const msg = {
				features: FeatureFlags.empty(),
				networks: [mainnetHash]
			};
			const encoded = encodeInitMessage(msg);
			const decoded = decodeInitMessage(encoded);

			expect(decoded.networks).to.not.be.undefined;
			expect(decoded.networks!.length).to.equal(1);
			expect(decoded.networks![0].equals(mainnetHash)).to.be.true;
		});

		it('Should handle globalfeatures merge', function () {
			// Manually construct init with both globalfeatures and features set
			// globalfeatures: byte 0x01 (bit 0 set)
			// features: byte 0x02 (bit 1 set)
			const gflen = Buffer.alloc(2);
			gflen.writeUInt16BE(1);
			const gf = Buffer.from([0x01]);
			const flen = Buffer.alloc(2);
			flen.writeUInt16BE(1);
			const f = Buffer.from([0x02]);
			const payload = Buffer.concat([gflen, gf, flen, f]);

			const decoded = decodeInitMessage(payload);
			// Both bits should be set (OR of globalfeatures and features)
			expect(decoded.features.hasBit(0)).to.be.true;
			expect(decoded.features.hasBit(1)).to.be.true;
		});

		it('Should reject too-short init payload', function () {
			expect(() => decodeInitMessage(Buffer.alloc(2))).to.throw('too short');
		});
	});

	describe('Error Message', function () {
		it('Should encode and decode an error message', function () {
			const channelId = Buffer.alloc(32, 0x42);
			const msg = createError(channelId, 'something went wrong');

			const encoded = encodeErrorMessage(msg);
			const decoded = decodeErrorMessage(encoded);

			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(getErrorText(decoded)).to.equal('something went wrong');
		});

		it('Should encode and decode a connection-level error', function () {
			const msg = createConnectionError('fatal protocol error');

			const encoded = encodeErrorMessage(msg);
			const decoded = decodeErrorMessage(encoded);

			expect(isConnectionError(decoded)).to.be.true;
			expect(decoded.channelId.equals(ALL_CHANNELS)).to.be.true;
			expect(getErrorText(decoded)).to.equal('fatal protocol error');
		});

		it('Should identify channel-specific errors', function () {
			const channelId = Buffer.alloc(32, 0xff);
			const msg = createError(channelId, 'channel error');
			expect(isConnectionError(msg)).to.be.false;
		});

		it('Should handle empty error data', function () {
			const msg = {
				channelId: ALL_CHANNELS,
				data: Buffer.alloc(0)
			};
			const encoded = encodeErrorMessage(msg);
			const decoded = decodeErrorMessage(encoded);

			expect(decoded.data.length).to.equal(0);
			expect(getErrorText(decoded)).to.equal('');
		});

		it('Should reject invalid channel ID length', function () {
			const msg = {
				channelId: Buffer.alloc(16), // Too short
				data: Buffer.from('test')
			};
			expect(() => encodeErrorMessage(msg)).to.throw('32 bytes');
		});

		it('Should reject too-short error payload', function () {
			expect(() => decodeErrorMessage(Buffer.alloc(20))).to.throw('too short');
		});

		it('Should roundtrip encode/decode', function () {
			const channelId = Buffer.alloc(32);
			for (let i = 0; i < 32; i++) channelId[i] = i;
			const text = 'The channel cannot proceed due to invalid state';

			const msg = createError(channelId, text);
			const encoded = encodeErrorMessage(msg);
			const decoded = decodeErrorMessage(encoded);

			expect(decoded.channelId.equals(channelId)).to.be.true;
			expect(getErrorText(decoded)).to.equal(text);
		});
	});

	describe('Feature Flags', function () {
		it('Should set and check individual bits', function () {
			const flags = FeatureFlags.empty();
			expect(flags.hasBit(0)).to.be.false;

			flags.setBit(0);
			expect(flags.hasBit(0)).to.be.true;

			flags.setBit(15);
			expect(flags.hasBit(15)).to.be.true;
			expect(flags.hasBit(14)).to.be.false;
		});

		it('Should clear bits', function () {
			const flags = FeatureFlags.empty();
			flags.setBit(5);
			expect(flags.hasBit(5)).to.be.true;

			flags.clearBit(5);
			expect(flags.hasBit(5)).to.be.false;
		});

		it('Should set optional features (odd bits)', function () {
			const flags = FeatureFlags.empty();
			flags.setOptional(Feature.STATIC_REMOTE_KEY); // bit 13

			expect(flags.hasBit(13)).to.be.true; // odd bit set
			expect(flags.hasBit(12)).to.be.false; // even bit not set
			expect(flags.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
			expect(flags.isOptional(Feature.STATIC_REMOTE_KEY)).to.be.true;
			expect(flags.isCompulsory(Feature.STATIC_REMOTE_KEY)).to.be.false;
		});

		it('Should set compulsory features (even bits)', function () {
			const flags = FeatureFlags.empty();
			flags.setCompulsory(Feature.TLV_ONION); // bit 8

			expect(flags.hasBit(8)).to.be.true;
			expect(flags.hasBit(9)).to.be.false;
			expect(flags.hasFeature(Feature.TLV_ONION)).to.be.true;
			expect(flags.isCompulsory(Feature.TLV_ONION)).to.be.true;
			expect(flags.isOptional(Feature.TLV_ONION)).to.be.false;
		});

		it('Should serialize to buffer and back', function () {
			const flags = FeatureFlags.empty();
			flags.setOptional(Feature.STATIC_REMOTE_KEY); // bit 13
			flags.setOptional(Feature.TLV_ONION); // bit 9

			const buf = flags.toBuffer();
			const restored = FeatureFlags.fromBuffer(buf);

			expect(restored.hasFeature(Feature.STATIC_REMOTE_KEY)).to.be.true;
			expect(restored.hasFeature(Feature.TLV_ONION)).to.be.true;
			expect(restored.hasFeature(Feature.BASIC_MPP)).to.be.false;
		});

		it('Should trim leading zero bytes in serialization', function () {
			const flags = FeatureFlags.empty();
			flags.setBit(0); // Only bit 0 set
			const buf = flags.toBuffer();
			expect(buf.length).to.equal(1);
			expect(buf[0]).to.equal(1);
		});

		it('Should handle empty flags', function () {
			const flags = FeatureFlags.empty();
			const buf = flags.toBuffer();
			expect(buf.length).to.equal(0);
		});

		it('Should list set bits', function () {
			const flags = FeatureFlags.empty();
			flags.setBit(0);
			flags.setBit(5);
			flags.setBit(13);

			const bits = flags.listSetBits();
			expect(bits).to.deep.equal([0, 5, 13]);
		});

		it('Should report maxBit correctly', function () {
			const flags = FeatureFlags.empty();
			expect(flags.maxBit()).to.equal(-1);

			flags.setBit(7);
			expect(flags.maxBit()).to.equal(7);

			flags.setBit(15);
			expect(flags.maxBit()).to.equal(15);
		});

		it('Should check feature compatibility', function () {
			const local = FeatureFlags.empty();
			local.setOptional(Feature.STATIC_REMOTE_KEY);

			const remote = FeatureFlags.empty();
			remote.setCompulsory(Feature.STATIC_REMOTE_KEY);

			// We know about STATIC_REMOTE_KEY, so compatible
			const knownFeatures = new Set([Feature.STATIC_REMOTE_KEY]);
			expect(remote.isCompatible(remote, knownFeatures)).to.be.true;
		});

		it('Should reject incompatible features', function () {
			const remote = FeatureFlags.empty();
			remote.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC); // bit 22

			// We don't know this feature
			const knownFeatures = new Set([Feature.STATIC_REMOTE_KEY]);
			expect(remote.isCompatible(remote, knownFeatures)).to.be.false;
		});

		it('Should handle high bit numbers', function () {
			const flags = FeatureFlags.empty();
			flags.setBit(100);
			expect(flags.hasBit(100)).to.be.true;
			expect(flags.hasBit(99)).to.be.false;

			const buf = flags.toBuffer();
			const restored = FeatureFlags.fromBuffer(buf);
			expect(restored.hasBit(100)).to.be.true;
		});

		it('Should reject negative bit position', function () {
			const flags = FeatureFlags.empty();
			expect(() => flags.setBit(-1)).to.throw('non-negative');
		});
	});
});
