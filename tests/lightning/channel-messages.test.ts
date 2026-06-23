import { expect } from 'chai';
import crypto from 'crypto';
import {
	encodeOpenChannelMessage,
	decodeOpenChannelMessage,
	IOpenChannelMessage,
	encodeAcceptChannelMessage,
	decodeAcceptChannelMessage,
	IAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	encodeFundingCreatedMessage,
	decodeFundingCreatedMessage,
	IFundingCreatedMessage,
	encodeFundingSignedMessage,
	decodeFundingSignedMessage,
	IFundingSignedMessage,
	encodeChannelReadyMessage,
	decodeChannelReadyMessage,
	IChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import {
	encodeUpdateAddHtlcMessage,
	decodeUpdateAddHtlcMessage,
	IUpdateAddHtlcMessage,
	encodeUpdateFulfillHtlcMessage,
	decodeUpdateFulfillHtlcMessage,
	IUpdateFulfillHtlcMessage,
	encodeUpdateFailHtlcMessage,
	decodeUpdateFailHtlcMessage,
	IUpdateFailHtlcMessage,
	encodeUpdateFailMalformedHtlcMessage,
	decodeUpdateFailMalformedHtlcMessage,
	IUpdateFailMalformedHtlcMessage,
	encodeUpdateFeeMessage,
	decodeUpdateFeeMessage,
	IUpdateFeeMessage
} from '../../src/lightning/message/channel-update';
import {
	encodeCommitmentSignedMessage,
	decodeCommitmentSignedMessage,
	ICommitmentSignedMessage,
	encodeRevokeAndAckMessage,
	decodeRevokeAndAckMessage,
	IRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import {
	encodeShutdownMessage,
	decodeShutdownMessage,
	IShutdownMessage,
	encodeClosingSignedMessage,
	decodeClosingSignedMessage,
	IClosingSignedMessage
} from '../../src/lightning/message/channel-close';
import {
	encodeChannelReestablishMessage,
	decodeChannelReestablishMessage,
	IChannelReestablishMessage
} from '../../src/lightning/message/channel-reestablish';

function randomBytes(n: number): Buffer {
	return crypto.randomBytes(n);
}

// Generate a fake compressed public key (0x02 prefix + 32 random bytes)
function fakePubkey(): Buffer {
	const buf = Buffer.alloc(33);
	buf[0] = 0x02;
	crypto.randomBytes(32).copy(buf, 1);
	return buf;
}

function fakeSig(): Buffer {
	return randomBytes(64);
}

describe('BOLT 2 Channel Messages', function () {
	// ─────────────── open_channel ───────────────
	describe('open_channel', function () {
		function makeOpenChannel(): IOpenChannelMessage {
			return {
				chainHash: Buffer.alloc(32, 0x06),
				temporaryChannelId: randomBytes(32),
				fundingSatoshis: 1000000n,
				pushMsat: 500000000n,
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 500000000n,
				channelReserveSatoshis: 10000n,
				htlcMinimumMsat: 1000n,
				feeratePerKw: 253,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: fakePubkey(),
				revocationBasepoint: fakePubkey(),
				paymentBasepoint: fakePubkey(),
				delayedPaymentBasepoint: fakePubkey(),
				htlcBasepoint: fakePubkey(),
				firstPerCommitmentPoint: fakePubkey(),
				channelFlags: 0x01
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeOpenChannel();
			const encoded = encodeOpenChannelMessage(msg);
			const decoded = decodeOpenChannelMessage(encoded);

			expect(decoded.chainHash).to.deep.equal(msg.chainHash);
			expect(decoded.temporaryChannelId).to.deep.equal(msg.temporaryChannelId);
			expect(decoded.fundingSatoshis).to.equal(msg.fundingSatoshis);
			expect(decoded.pushMsat).to.equal(msg.pushMsat);
			expect(decoded.dustLimitSatoshis).to.equal(msg.dustLimitSatoshis);
			expect(decoded.maxHtlcValueInFlightMsat).to.equal(
				msg.maxHtlcValueInFlightMsat
			);
			expect(decoded.channelReserveSatoshis).to.equal(
				msg.channelReserveSatoshis
			);
			expect(decoded.htlcMinimumMsat).to.equal(msg.htlcMinimumMsat);
			expect(decoded.feeratePerKw).to.equal(msg.feeratePerKw);
			expect(decoded.toSelfDelay).to.equal(msg.toSelfDelay);
			expect(decoded.maxAcceptedHtlcs).to.equal(msg.maxAcceptedHtlcs);
			expect(decoded.fundingPubkey).to.deep.equal(msg.fundingPubkey);
			expect(decoded.revocationBasepoint).to.deep.equal(
				msg.revocationBasepoint
			);
			expect(decoded.paymentBasepoint).to.deep.equal(msg.paymentBasepoint);
			expect(decoded.delayedPaymentBasepoint).to.deep.equal(
				msg.delayedPaymentBasepoint
			);
			expect(decoded.htlcBasepoint).to.deep.equal(msg.htlcBasepoint);
			expect(decoded.firstPerCommitmentPoint).to.deep.equal(
				msg.firstPerCommitmentPoint
			);
			expect(decoded.channelFlags).to.equal(msg.channelFlags);
		});

		it('should encode exactly 319 bytes without TLV', function () {
			const msg = makeOpenChannel();
			const encoded = encodeOpenChannelMessage(msg);
			expect(encoded.length).to.equal(319);
		});

		it('should roundtrip with upfront_shutdown_script TLV', function () {
			const msg = makeOpenChannel();
			msg.upfrontShutdownScript = randomBytes(25);
			const encoded = encodeOpenChannelMessage(msg);
			const decoded = decodeOpenChannelMessage(encoded);
			expect(decoded.upfrontShutdownScript).to.deep.equal(
				msg.upfrontShutdownScript
			);
		});

		it('should roundtrip with channel_type TLV', function () {
			const msg = makeOpenChannel();
			msg.channelType = Buffer.from([0x01, 0x02]);
			const encoded = encodeOpenChannelMessage(msg);
			const decoded = decodeOpenChannelMessage(encoded);
			expect(decoded.channelType).to.deep.equal(msg.channelType);
		});

		it('should roundtrip with both TLVs', function () {
			const msg = makeOpenChannel();
			msg.upfrontShutdownScript = randomBytes(22);
			msg.channelType = Buffer.from([0x03]);
			const encoded = encodeOpenChannelMessage(msg);
			const decoded = decodeOpenChannelMessage(encoded);
			expect(decoded.upfrontShutdownScript).to.deep.equal(
				msg.upfrontShutdownScript
			);
			expect(decoded.channelType).to.deep.equal(msg.channelType);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(100);
			expect(() => decodeOpenChannelMessage(payload)).to.throw('too short');
		});

		it('should decode known byte values', function () {
			// Build a known payload manually
			const buf = Buffer.alloc(319);
			let offset = 0;

			const chainHash = Buffer.alloc(32, 0xaa);
			chainHash.copy(buf, offset);
			offset += 32;

			const tempId = Buffer.alloc(32, 0xbb);
			tempId.copy(buf, offset);
			offset += 32;

			buf.writeBigUInt64BE(100000n, offset);
			offset += 8; // funding_satoshis
			buf.writeBigUInt64BE(0n, offset);
			offset += 8; // push_msat
			buf.writeBigUInt64BE(546n, offset);
			offset += 8; // dust_limit
			buf.writeBigUInt64BE(1000000000n, offset);
			offset += 8; // max_htlc_value_in_flight
			buf.writeBigUInt64BE(1000n, offset);
			offset += 8; // channel_reserve
			buf.writeBigUInt64BE(1n, offset);
			offset += 8; // htlc_minimum
			buf.writeUInt32BE(5000, offset);
			offset += 4; // feerate_per_kw
			buf.writeUInt16BE(6, offset);
			offset += 2; // to_self_delay
			buf.writeUInt16BE(30, offset);
			offset += 2; // max_accepted_htlcs

			// 6 pubkeys + channel_flags
			const pk = Buffer.alloc(33, 0x02);
			for (let i = 0; i < 6; i++) {
				pk.copy(buf, offset);
				offset += 33;
			}
			buf[offset] = 0x00; // channel_flags

			const decoded = decodeOpenChannelMessage(buf);
			expect(decoded.fundingSatoshis).to.equal(100000n);
			expect(decoded.pushMsat).to.equal(0n);
			expect(decoded.dustLimitSatoshis).to.equal(546n);
			expect(decoded.feeratePerKw).to.equal(5000);
			expect(decoded.toSelfDelay).to.equal(6);
			expect(decoded.maxAcceptedHtlcs).to.equal(30);
			expect(decoded.channelFlags).to.equal(0);
		});
	});

	// ─────────────── accept_channel ───────────────
	describe('accept_channel', function () {
		function makeAcceptChannel(): IAcceptChannelMessage {
			return {
				temporaryChannelId: randomBytes(32),
				dustLimitSatoshis: 546n,
				maxHtlcValueInFlightMsat: 500000000n,
				channelReserveSatoshis: 10000n,
				htlcMinimumMsat: 1000n,
				minimumDepth: 3,
				toSelfDelay: 144,
				maxAcceptedHtlcs: 483,
				fundingPubkey: fakePubkey(),
				revocationBasepoint: fakePubkey(),
				paymentBasepoint: fakePubkey(),
				delayedPaymentBasepoint: fakePubkey(),
				htlcBasepoint: fakePubkey(),
				firstPerCommitmentPoint: fakePubkey()
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeAcceptChannel();
			const encoded = encodeAcceptChannelMessage(msg);
			const decoded = decodeAcceptChannelMessage(encoded);

			expect(decoded.temporaryChannelId).to.deep.equal(msg.temporaryChannelId);
			expect(decoded.dustLimitSatoshis).to.equal(msg.dustLimitSatoshis);
			expect(decoded.maxHtlcValueInFlightMsat).to.equal(
				msg.maxHtlcValueInFlightMsat
			);
			expect(decoded.channelReserveSatoshis).to.equal(
				msg.channelReserveSatoshis
			);
			expect(decoded.htlcMinimumMsat).to.equal(msg.htlcMinimumMsat);
			expect(decoded.minimumDepth).to.equal(msg.minimumDepth);
			expect(decoded.toSelfDelay).to.equal(msg.toSelfDelay);
			expect(decoded.maxAcceptedHtlcs).to.equal(msg.maxAcceptedHtlcs);
			expect(decoded.fundingPubkey).to.deep.equal(msg.fundingPubkey);
			expect(decoded.firstPerCommitmentPoint).to.deep.equal(
				msg.firstPerCommitmentPoint
			);
		});

		it('should encode exactly 270 bytes without TLV', function () {
			const msg = makeAcceptChannel();
			const encoded = encodeAcceptChannelMessage(msg);
			expect(encoded.length).to.equal(270);
		});

		it('should roundtrip with TLVs', function () {
			const msg = makeAcceptChannel();
			msg.upfrontShutdownScript = randomBytes(34);
			msg.channelType = Buffer.from([0x05]);
			const encoded = encodeAcceptChannelMessage(msg);
			const decoded = decodeAcceptChannelMessage(encoded);
			expect(decoded.upfrontShutdownScript).to.deep.equal(
				msg.upfrontShutdownScript
			);
			expect(decoded.channelType).to.deep.equal(msg.channelType);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(100);
			expect(() => decodeAcceptChannelMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── funding_created ───────────────
	describe('funding_created', function () {
		function makeFundingCreated(): IFundingCreatedMessage {
			return {
				temporaryChannelId: randomBytes(32),
				fundingTxid: randomBytes(32),
				fundingOutputIndex: 0,
				signature: fakeSig()
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeFundingCreated();
			const encoded = encodeFundingCreatedMessage(msg);
			const decoded = decodeFundingCreatedMessage(encoded);

			expect(decoded.temporaryChannelId).to.deep.equal(msg.temporaryChannelId);
			expect(decoded.fundingTxid).to.deep.equal(msg.fundingTxid);
			expect(decoded.fundingOutputIndex).to.equal(msg.fundingOutputIndex);
			expect(decoded.signature).to.deep.equal(msg.signature);
		});

		it('should encode exactly 130 bytes', function () {
			const msg = makeFundingCreated();
			const encoded = encodeFundingCreatedMessage(msg);
			expect(encoded.length).to.equal(130);
		});

		it('should handle non-zero output index', function () {
			const msg = makeFundingCreated();
			msg.fundingOutputIndex = 65535;
			const encoded = encodeFundingCreatedMessage(msg);
			const decoded = decodeFundingCreatedMessage(encoded);
			expect(decoded.fundingOutputIndex).to.equal(65535);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeFundingCreatedMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── funding_signed ───────────────
	describe('funding_signed', function () {
		function makeFundingSigned(): IFundingSignedMessage {
			return {
				channelId: randomBytes(32),
				signature: fakeSig()
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeFundingSigned();
			const encoded = encodeFundingSignedMessage(msg);
			const decoded = decodeFundingSignedMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.signature).to.deep.equal(msg.signature);
		});

		it('should encode exactly 96 bytes', function () {
			const msg = makeFundingSigned();
			const encoded = encodeFundingSignedMessage(msg);
			expect(encoded.length).to.equal(96);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeFundingSignedMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── channel_ready ───────────────
	describe('channel_ready', function () {
		function makeChannelReady(): IChannelReadyMessage {
			return {
				channelId: randomBytes(32),
				secondPerCommitmentPoint: fakePubkey()
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeChannelReady();
			const encoded = encodeChannelReadyMessage(msg);
			const decoded = decodeChannelReadyMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.secondPerCommitmentPoint).to.deep.equal(
				msg.secondPerCommitmentPoint
			);
		});

		it('should encode exactly 65 bytes without TLV', function () {
			const msg = makeChannelReady();
			const encoded = encodeChannelReadyMessage(msg);
			expect(encoded.length).to.equal(65);
		});

		it('should roundtrip with short_channel_id TLV', function () {
			const msg = makeChannelReady();
			msg.shortChannelId = randomBytes(8);
			const encoded = encodeChannelReadyMessage(msg);
			const decoded = decodeChannelReadyMessage(encoded);
			expect(decoded.shortChannelId).to.deep.equal(msg.shortChannelId);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(30);
			expect(() => decodeChannelReadyMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── update_add_htlc ───────────────
	describe('update_add_htlc', function () {
		function makeUpdateAddHtlc(): IUpdateAddHtlcMessage {
			return {
				channelId: randomBytes(32),
				id: 42n,
				amountMsat: 50000000n,
				paymentHash: randomBytes(32),
				cltvExpiry: 500000,
				onionRoutingPacket: randomBytes(1366)
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeUpdateAddHtlc();
			const encoded = encodeUpdateAddHtlcMessage(msg);
			const decoded = decodeUpdateAddHtlcMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.id).to.equal(msg.id);
			expect(decoded.amountMsat).to.equal(msg.amountMsat);
			expect(decoded.paymentHash).to.deep.equal(msg.paymentHash);
			expect(decoded.cltvExpiry).to.equal(msg.cltvExpiry);
			expect(decoded.onionRoutingPacket).to.deep.equal(msg.onionRoutingPacket);
		});

		it('should encode exactly 1450 bytes', function () {
			const msg = makeUpdateAddHtlc();
			const encoded = encodeUpdateAddHtlcMessage(msg);
			expect(encoded.length).to.equal(1450);
		});

		it('should handle id=0', function () {
			const msg = makeUpdateAddHtlc();
			msg.id = 0n;
			const encoded = encodeUpdateAddHtlcMessage(msg);
			const decoded = decodeUpdateAddHtlcMessage(encoded);
			expect(decoded.id).to.equal(0n);
		});

		it('should handle max u64 id', function () {
			const msg = makeUpdateAddHtlc();
			msg.id = 18446744073709551615n;
			const encoded = encodeUpdateAddHtlcMessage(msg);
			const decoded = decodeUpdateAddHtlcMessage(encoded);
			expect(decoded.id).to.equal(18446744073709551615n);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(100);
			expect(() => decodeUpdateAddHtlcMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── update_fulfill_htlc ───────────────
	describe('update_fulfill_htlc', function () {
		function makeUpdateFulfillHtlc(): IUpdateFulfillHtlcMessage {
			return {
				channelId: randomBytes(32),
				id: 7n,
				paymentPreimage: randomBytes(32)
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeUpdateFulfillHtlc();
			const encoded = encodeUpdateFulfillHtlcMessage(msg);
			const decoded = decodeUpdateFulfillHtlcMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.id).to.equal(msg.id);
			expect(decoded.paymentPreimage).to.deep.equal(msg.paymentPreimage);
		});

		it('should encode exactly 72 bytes', function () {
			const msg = makeUpdateFulfillHtlc();
			const encoded = encodeUpdateFulfillHtlcMessage(msg);
			expect(encoded.length).to.equal(72);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeUpdateFulfillHtlcMessage(payload)).to.throw(
				'too short'
			);
		});
	});

	// ─────────────── update_fail_htlc ───────────────
	describe('update_fail_htlc', function () {
		function makeUpdateFailHtlc(): IUpdateFailHtlcMessage {
			return {
				channelId: randomBytes(32),
				id: 3n,
				reason: randomBytes(256)
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeUpdateFailHtlc();
			const encoded = encodeUpdateFailHtlcMessage(msg);
			const decoded = decodeUpdateFailHtlcMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.id).to.equal(msg.id);
			expect(decoded.reason).to.deep.equal(msg.reason);
		});

		it('should encode with correct length prefix', function () {
			const msg = makeUpdateFailHtlc();
			const encoded = encodeUpdateFailHtlcMessage(msg);
			// 32 (channel_id) + 8 (id) + 2 (len) + 256 (reason)
			expect(encoded.length).to.equal(298);
		});

		it('should handle empty reason', function () {
			const msg = makeUpdateFailHtlc();
			msg.reason = Buffer.alloc(0);
			const encoded = encodeUpdateFailHtlcMessage(msg);
			const decoded = decodeUpdateFailHtlcMessage(encoded);
			expect(decoded.reason.length).to.equal(0);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(30);
			expect(() => decodeUpdateFailHtlcMessage(payload)).to.throw('too short');
		});

		it('should throw if reason length exceeds payload', function () {
			const buf = Buffer.alloc(42);
			// channel_id + id = 40 bytes, then len = 9999
			buf.writeUInt16BE(9999, 40);
			expect(() => decodeUpdateFailHtlcMessage(buf)).to.throw(
				'exceeds payload'
			);
		});
	});

	// ─────────────── update_fail_malformed_htlc ───────────────
	describe('update_fail_malformed_htlc', function () {
		function makeUpdateFailMalformedHtlc(): IUpdateFailMalformedHtlcMessage {
			return {
				channelId: randomBytes(32),
				id: 5n,
				sha256OfOnion: randomBytes(32),
				failureCode: 0x8000
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeUpdateFailMalformedHtlc();
			const encoded = encodeUpdateFailMalformedHtlcMessage(msg);
			const decoded = decodeUpdateFailMalformedHtlcMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.id).to.equal(msg.id);
			expect(decoded.sha256OfOnion).to.deep.equal(msg.sha256OfOnion);
			expect(decoded.failureCode).to.equal(msg.failureCode);
		});

		it('should encode exactly 74 bytes', function () {
			const msg = makeUpdateFailMalformedHtlc();
			const encoded = encodeUpdateFailMalformedHtlcMessage(msg);
			expect(encoded.length).to.equal(74);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeUpdateFailMalformedHtlcMessage(payload)).to.throw(
				'too short'
			);
		});
	});

	// ─────────────── update_fee ───────────────
	describe('update_fee', function () {
		function makeUpdateFee(): IUpdateFeeMessage {
			return {
				channelId: randomBytes(32),
				feeratePerKw: 12500
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeUpdateFee();
			const encoded = encodeUpdateFeeMessage(msg);
			const decoded = decodeUpdateFeeMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.feeratePerKw).to.equal(msg.feeratePerKw);
		});

		it('should encode exactly 36 bytes', function () {
			const msg = makeUpdateFee();
			const encoded = encodeUpdateFeeMessage(msg);
			expect(encoded.length).to.equal(36);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(20);
			expect(() => decodeUpdateFeeMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── commitment_signed ───────────────
	describe('commitment_signed', function () {
		function makeCommitmentSigned(numHtlcs: number): ICommitmentSignedMessage {
			const htlcSignatures: Buffer[] = [];
			for (let i = 0; i < numHtlcs; i++) {
				htlcSignatures.push(fakeSig());
			}
			return {
				channelId: randomBytes(32),
				signature: fakeSig(),
				htlcSignatures
			};
		}

		it('should roundtrip with 0 HTLCs', function () {
			const msg = makeCommitmentSigned(0);
			const encoded = encodeCommitmentSignedMessage(msg);
			const decoded = decodeCommitmentSignedMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.signature).to.deep.equal(msg.signature);
			expect(decoded.htlcSignatures).to.have.length(0);
		});

		it('should roundtrip with 5 HTLCs', function () {
			const msg = makeCommitmentSigned(5);
			const encoded = encodeCommitmentSignedMessage(msg);
			const decoded = decodeCommitmentSignedMessage(encoded);

			expect(decoded.htlcSignatures).to.have.length(5);
			for (let i = 0; i < 5; i++) {
				expect(decoded.htlcSignatures[i]).to.deep.equal(msg.htlcSignatures[i]);
			}
		});

		it('should encode correct length with HTLCs', function () {
			const msg = makeCommitmentSigned(3);
			const encoded = encodeCommitmentSignedMessage(msg);
			// 32 + 64 + 2 + 3*64 = 290
			expect(encoded.length).to.equal(290);
		});

		it('should handle max 483 HTLCs', function () {
			const msg = makeCommitmentSigned(483);
			const encoded = encodeCommitmentSignedMessage(msg);
			const decoded = decodeCommitmentSignedMessage(encoded);
			expect(decoded.htlcSignatures).to.have.length(483);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeCommitmentSignedMessage(payload)).to.throw(
				'too short'
			);
		});

		it('should throw if HTLC sigs truncated', function () {
			// Create a valid header claiming 5 HTLCs but with no sig data
			const buf = Buffer.alloc(98);
			buf.writeUInt16BE(5, 96); // num_htlcs = 5
			expect(() => decodeCommitmentSignedMessage(buf)).to.throw(
				'too short for 5 HTLCs'
			);
		});

		it('should roundtrip the splice funding_txid TLV (type 1)', function () {
			const msg = makeCommitmentSigned(0);
			msg.fundingTxid = randomBytes(32);
			const encoded = encodeCommitmentSignedMessage(msg);
			// 98 fixed + TLV (type 1, len 32) header (2) + 32 value
			expect(encoded.length).to.equal(98 + 2 + 32);
			const decoded = decodeCommitmentSignedMessage(encoded);
			expect(decoded.fundingTxid).to.deep.equal(msg.fundingTxid);
		});

		it('should roundtrip funding_txid TLV alongside HTLC sigs', function () {
			const msg = makeCommitmentSigned(3);
			msg.fundingTxid = randomBytes(32);
			const decoded = decodeCommitmentSignedMessage(
				encodeCommitmentSignedMessage(msg)
			);
			expect(decoded.htlcSignatures).to.have.length(3);
			expect(decoded.fundingTxid).to.deep.equal(msg.fundingTxid);
		});

		it('should decode a legacy commitment_signed with no funding_txid', function () {
			const decoded = decodeCommitmentSignedMessage(
				encodeCommitmentSignedMessage(makeCommitmentSigned(2))
			);
			expect(decoded.fundingTxid).to.be.undefined;
		});

		it('should reject a malformed funding_txid length on encode', function () {
			const msg = makeCommitmentSigned(0);
			msg.fundingTxid = randomBytes(16);
			expect(() => encodeCommitmentSignedMessage(msg)).to.throw('32 bytes');
		});

		it('should decode known byte values', function () {
			const channelId = Buffer.alloc(32, 0xcc);
			const sig = Buffer.alloc(64, 0xdd);
			const htlcSig = Buffer.alloc(64, 0xee);

			const buf = Buffer.alloc(98 + 64);
			channelId.copy(buf, 0);
			sig.copy(buf, 32);
			buf.writeUInt16BE(1, 96);
			htlcSig.copy(buf, 98);

			const decoded = decodeCommitmentSignedMessage(buf);
			expect(decoded.channelId).to.deep.equal(channelId);
			expect(decoded.signature).to.deep.equal(sig);
			expect(decoded.htlcSignatures).to.have.length(1);
			expect(decoded.htlcSignatures[0]).to.deep.equal(htlcSig);
		});
	});

	// ─────────────── revoke_and_ack ───────────────
	describe('revoke_and_ack', function () {
		function makeRevokeAndAck(): IRevokeAndAckMessage {
			return {
				channelId: randomBytes(32),
				perCommitmentSecret: randomBytes(32),
				nextPerCommitmentPoint: fakePubkey()
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeRevokeAndAck();
			const encoded = encodeRevokeAndAckMessage(msg);
			const decoded = decodeRevokeAndAckMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.perCommitmentSecret).to.deep.equal(
				msg.perCommitmentSecret
			);
			expect(decoded.nextPerCommitmentPoint).to.deep.equal(
				msg.nextPerCommitmentPoint
			);
		});

		it('should encode exactly 97 bytes', function () {
			const msg = makeRevokeAndAck();
			const encoded = encodeRevokeAndAckMessage(msg);
			expect(encoded.length).to.equal(97);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeRevokeAndAckMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── shutdown ───────────────
	describe('shutdown', function () {
		function makeShutdown(): IShutdownMessage {
			return {
				channelId: randomBytes(32),
				scriptPubkey: randomBytes(25) // typical P2PKH length
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeShutdown();
			const encoded = encodeShutdownMessage(msg);
			const decoded = decodeShutdownMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.scriptPubkey).to.deep.equal(msg.scriptPubkey);
		});

		it('should encode with correct length prefix', function () {
			const msg = makeShutdown();
			const encoded = encodeShutdownMessage(msg);
			// 32 + 2 + 25 = 59
			expect(encoded.length).to.equal(59);
		});

		it('should handle P2WPKH scriptpubkey', function () {
			const msg = makeShutdown();
			msg.scriptPubkey = randomBytes(22); // P2WPKH
			const encoded = encodeShutdownMessage(msg);
			const decoded = decodeShutdownMessage(encoded);
			expect(decoded.scriptPubkey).to.deep.equal(msg.scriptPubkey);
		});

		it('should handle P2WSH scriptpubkey', function () {
			const msg = makeShutdown();
			msg.scriptPubkey = randomBytes(34); // P2WSH
			const encoded = encodeShutdownMessage(msg);
			const decoded = decodeShutdownMessage(encoded);
			expect(decoded.scriptPubkey).to.deep.equal(msg.scriptPubkey);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(20);
			expect(() => decodeShutdownMessage(payload)).to.throw('too short');
		});

		it('should throw if scriptpubkey length exceeds payload', function () {
			const buf = Buffer.alloc(34);
			buf.writeUInt16BE(9999, 32);
			expect(() => decodeShutdownMessage(buf)).to.throw('exceeds payload');
		});
	});

	// ─────────────── closing_signed ───────────────
	describe('closing_signed', function () {
		function makeClosingSigned(): IClosingSignedMessage {
			return {
				channelId: randomBytes(32),
				feeSatoshis: 1000n,
				signature: fakeSig()
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeClosingSigned();
			const encoded = encodeClosingSignedMessage(msg);
			const decoded = decodeClosingSignedMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.feeSatoshis).to.equal(msg.feeSatoshis);
			expect(decoded.signature).to.deep.equal(msg.signature);
		});

		it('should encode exactly 104 bytes', function () {
			const msg = makeClosingSigned();
			const encoded = encodeClosingSignedMessage(msg);
			expect(encoded.length).to.equal(104);
		});

		it('should handle zero fee', function () {
			const msg = makeClosingSigned();
			msg.feeSatoshis = 0n;
			const encoded = encodeClosingSignedMessage(msg);
			const decoded = decodeClosingSignedMessage(encoded);
			expect(decoded.feeSatoshis).to.equal(0n);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeClosingSignedMessage(payload)).to.throw('too short');
		});
	});

	// ─────────────── channel_reestablish ───────────────
	describe('channel_reestablish', function () {
		function makeChannelReestablish(): IChannelReestablishMessage {
			return {
				channelId: randomBytes(32),
				nextCommitmentNumber: 5n,
				nextRevocationNumber: 4n,
				yourLastPerCommitmentSecret: randomBytes(32),
				myCurrentPerCommitmentPoint: fakePubkey()
			};
		}

		it('should roundtrip encode/decode', function () {
			const msg = makeChannelReestablish();
			const encoded = encodeChannelReestablishMessage(msg);
			const decoded = decodeChannelReestablishMessage(encoded);

			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.nextCommitmentNumber).to.equal(msg.nextCommitmentNumber);
			expect(decoded.nextRevocationNumber).to.equal(msg.nextRevocationNumber);
			expect(decoded.yourLastPerCommitmentSecret).to.deep.equal(
				msg.yourLastPerCommitmentSecret
			);
			expect(decoded.myCurrentPerCommitmentPoint).to.deep.equal(
				msg.myCurrentPerCommitmentPoint
			);
		});

		it('should encode exactly 113 bytes', function () {
			const msg = makeChannelReestablish();
			const encoded = encodeChannelReestablishMessage(msg);
			expect(encoded.length).to.equal(113);
		});

		it('should handle initial state (numbers at 1)', function () {
			const msg = makeChannelReestablish();
			msg.nextCommitmentNumber = 1n;
			msg.nextRevocationNumber = 0n;
			const encoded = encodeChannelReestablishMessage(msg);
			const decoded = decodeChannelReestablishMessage(encoded);
			expect(decoded.nextCommitmentNumber).to.equal(1n);
			expect(decoded.nextRevocationNumber).to.equal(0n);
		});

		it('should throw on truncated payload', function () {
			const payload = Buffer.alloc(50);
			expect(() => decodeChannelReestablishMessage(payload)).to.throw(
				'too short'
			);
		});

		it('should roundtrip next_funding TLV (splice resumption, current spec type 1)', function () {
			const msg = makeChannelReestablish();
			msg.nextFundingTxid = randomBytes(32);
			msg.nextFundingRetransmitFlags = 1;
			const encoded = encodeChannelReestablishMessage(msg);
			// 113 fixed + TLV header (type 1, len 33) + 32 txid + 1 flags byte.
			// MUST be type 1/33 bytes: CLN v25.12+ hard-rejects the legacy even
			// type 0 TLV as "bad reestablish msg".
			expect(encoded.length).to.equal(113 + 2 + 33);
			expect(encoded[113]).to.equal(1); // TLV type 1
			expect(encoded[114]).to.equal(33); // TLV length
			const decoded = decodeChannelReestablishMessage(encoded);
			expect(decoded.nextFundingTxid).to.deep.equal(msg.nextFundingTxid);
			expect(decoded.nextFundingRetransmitFlags).to.equal(1);
		});

		it('should decode the legacy type-0 next_funding_txid TLV (old merged-spec peers)', function () {
			const msg = makeChannelReestablish();
			const base = encodeChannelReestablishMessage(msg);
			const txid = randomBytes(32);
			const tlv = Buffer.concat([Buffer.from([0, 32]), txid]);
			const decoded = decodeChannelReestablishMessage(
				Buffer.concat([base, tlv])
			);
			expect(decoded.nextFundingTxid).to.deep.equal(txid);
		});

		it('should decode a legacy 113-byte payload with no nextFundingTxid', function () {
			const msg = makeChannelReestablish();
			const decoded = decodeChannelReestablishMessage(
				encodeChannelReestablishMessage(msg)
			);
			expect(decoded.nextFundingTxid).to.be.undefined;
		});

		it('should reject a malformed next_funding_txid length on encode', function () {
			const msg = makeChannelReestablish();
			msg.nextFundingTxid = Buffer.alloc(16);
			expect(() => encodeChannelReestablishMessage(msg)).to.throw('32 bytes');
		});

		it('should decode a CLN v25.12+ type-1 next_funding TLV (txid + retransmit flags)', function () {
			const msg = makeChannelReestablish();
			const base = encodeChannelReestablishMessage(msg);
			const txid = randomBytes(32);
			// TLV type 1, length 33: txid ++ retransmit_flags (bit 0 set)
			const tlv = Buffer.concat([
				Buffer.from([1, 33]),
				txid,
				Buffer.from([0x01])
			]);
			const decoded = decodeChannelReestablishMessage(
				Buffer.concat([base, tlv])
			);
			expect(decoded.nextFundingTxid).to.deep.equal(txid);
			expect(decoded.nextFundingRetransmitFlags).to.equal(1);
		});

		it('should ignore unknown odd reestablish TLVs (e.g. CLN my_current_funding_locked)', function () {
			const msg = makeChannelReestablish();
			const base = encodeChannelReestablishMessage(msg);
			// Unknown odd TLV type 5 with a 32-byte payload must not break decoding.
			const tlv = Buffer.concat([Buffer.from([5, 32]), randomBytes(32)]);
			const decoded = decodeChannelReestablishMessage(
				Buffer.concat([base, tlv])
			);
			expect(decoded.channelId).to.deep.equal(msg.channelId);
			expect(decoded.nextFundingTxid).to.be.undefined;
		});
	});
});
