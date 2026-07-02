/**
 * FFOR (specs/ffor-offline-receive.md) — M1 wire codec tests:
 * round-trips for every epoch-setup message (TLV presence/absence combos),
 * node-key signature sign/verify (reject on tampered body), and unknown-TLV
 * tolerance consistent with beignet's TLV conventions (odd = skip, even = fail).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	FF_INIT_TYPE,
	FF_ACCEPT_TYPE,
	IFforInitMessage,
	IFforAcceptMessage,
	encodeFforInitMessage,
	decodeFforInitMessage,
	encodeFforAcceptMessage,
	decodeFforAcceptMessage,
	encodeFforInvoicesMessage,
	decodeFforInvoicesMessage,
	encodeFforEscapeSigsMessage,
	decodeFforEscapeSigsMessage,
	encodeFforBeginMessage,
	decodeFforBeginMessage,
	encodeFforEndMessage,
	decodeFforEndMessage,
	encodeFforErrorMessage,
	decodeFforErrorMessage,
	decodeFforHeader,
	fforMessageDigest,
	signFforMessage,
	verifyFforMessageSignature
} from '../../src/lightning/ffor/messages';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeTlvRecord } from '../../src/lightning/message/tlv';

const channelId = Buffer.alloc(32, 0xcc);
const epochId = Buffer.alloc(32, 0xee);

function point(fill: number): Buffer {
	return Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, fill)]);
}

function baseInit(overrides?: Partial<IFforInitMessage>): IFforInitMessage {
	return {
		channelId,
		epochId,
		variant: 1,
		budgetMsat: 500_000_000n,
		maxPayments: 3,
		minPaymentMsat: 400_000n,
		settlementDeadline: 900_000,
		voucherExpiry: 901_008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 100,
		escapeGranularityMsat: 0n,
		rPerCommitmentPoints: [point(1), point(2), point(3)],
		signature: Buffer.alloc(64, 0x77),
		...overrides
	};
}

describe('FFOR messages (M1 codecs)', function () {
	describe('ff_init (55001)', function () {
		it('round-trips a variant A init (no TLVs)', function () {
			const msg = baseInit();
			const decoded = decodeFforInitMessage(encodeFforInitMessage(msg));

			expect(decoded.channelId.equals(channelId)).to.equal(true);
			expect(decoded.epochId.equals(epochId)).to.equal(true);
			expect(decoded.variant).to.equal(1);
			expect(decoded.budgetMsat).to.equal(500_000_000n);
			expect(decoded.maxPayments).to.equal(3);
			expect(decoded.minPaymentMsat).to.equal(400_000n);
			expect(decoded.settlementDeadline).to.equal(900_000);
			expect(decoded.voucherExpiry).to.equal(901_008);
			expect(decoded.feeBaseMsat).to.equal(1000);
			expect(decoded.feeProportionalMillionths).to.equal(100);
			expect(decoded.escapeGranularityMsat).to.equal(0n);
			expect(decoded.rPerCommitmentPoints).to.have.length(3);
			expect(decoded.rPerCommitmentPoints[2].equals(point(3))).to.equal(true);
			expect(decoded.paymentHashes).to.equal(undefined);
			expect(decoded.towerNodeId).to.equal(undefined);
			expect(decoded.towerUri).to.equal(undefined);
			expect(decoded.signature.equals(Buffer.alloc(64, 0x77))).to.equal(true);
		});

		it('round-trips a variant B init with all TLVs', function () {
			const hashes = [
				crypto.randomBytes(32),
				crypto.randomBytes(32),
				crypto.randomBytes(32)
			];
			const towerNodeId = point(0xab);
			const msg = baseInit({
				variant: 2,
				escapeGranularityMsat: 50_000_000n,
				paymentHashes: hashes,
				towerNodeId,
				towerUri: 'https://tower.example:9911/ø'
			});
			const decoded = decodeFforInitMessage(encodeFforInitMessage(msg));

			expect(decoded.variant).to.equal(2);
			expect(decoded.escapeGranularityMsat).to.equal(50_000_000n);
			expect(decoded.paymentHashes).to.have.length(3);
			for (let i = 0; i < 3; i++) {
				expect(decoded.paymentHashes![i].equals(hashes[i])).to.equal(true);
			}
			expect(decoded.towerNodeId!.equals(towerNodeId)).to.equal(true);
			expect(decoded.towerUri).to.equal('https://tower.example:9911/ø');
		});

		it('handles u64 values above 2^32', function () {
			const msg = baseInit({
				budgetMsat: 0x1_2345_6789_abcdn,
				minPaymentMsat: 0x1_0000_0001n
			});
			const decoded = decodeFforInitMessage(encodeFforInitMessage(msg));
			expect(decoded.budgetMsat).to.equal(0x1_2345_6789_abcdn);
			expect(decoded.minPaymentMsat).to.equal(0x1_0000_0001n);
		});

		it('skips an unknown ODD TLV (beignet TLV convention)', function () {
			const encoded = encodeFforInitMessage(baseInit());
			// Splice an unknown odd TLV (type 7) into the TLV region — i.e. just
			// before the final 64-byte signature.
			const extra = encodeTlvRecord({ type: 7n, value: Buffer.from([1, 2]) });
			const spliced = Buffer.concat([
				encoded.subarray(0, encoded.length - 64),
				extra,
				encoded.subarray(encoded.length - 64)
			]);
			const decoded = decodeFforInitMessage(spliced);
			expect(decoded.maxPayments).to.equal(3);
		});

		it('rejects an unknown EVEN TLV', function () {
			const encoded = encodeFforInitMessage(baseInit());
			const extra = encodeTlvRecord({ type: 6n, value: Buffer.from([1]) });
			const spliced = Buffer.concat([
				encoded.subarray(0, encoded.length - 64),
				extra,
				encoded.subarray(encoded.length - 64)
			]);
			expect(() => decodeFforInitMessage(spliced)).to.throw(
				'Unknown required TLV type: 6'
			);
		});

		it('rejects a payment_hashes TLV that is not a multiple of 32', function () {
			const encoded = encodeFforInitMessage(baseInit());
			const extra = encodeTlvRecord({ type: 1n, value: Buffer.alloc(31) });
			const spliced = Buffer.concat([
				encoded.subarray(0, encoded.length - 64),
				extra,
				encoded.subarray(encoded.length - 64)
			]);
			expect(() => decodeFforInitMessage(spliced)).to.throw('multiple of 32');
		});

		it('rejects a truncated payload', function () {
			const encoded = encodeFforInitMessage(baseInit());
			expect(() => decodeFforInitMessage(encoded.subarray(0, 100))).to.throw(
				'too short'
			);
		});

		it('rejects a payload truncated inside the points array', function () {
			const encoded = encodeFforInitMessage(baseInit());
			// Chop one point + keep less than a signature's worth after it.
			expect(() =>
				decodeFforInitMessage(encoded.subarray(0, encoded.length - 64 - 20))
			).to.throw();
		});
	});

	describe('ff_accept (55003)', function () {
		it('round-trips with the variant A hash TLV', function () {
			const hashes = [crypto.randomBytes(32), crypto.randomBytes(32)];
			const msg: IFforAcceptMessage = {
				channelId,
				epochId,
				sCommitmentNumber: 42n,
				paymentHashes: hashes,
				signature: Buffer.alloc(64, 0x11)
			};
			const decoded = decodeFforAcceptMessage(encodeFforAcceptMessage(msg));
			expect(decoded.sCommitmentNumber).to.equal(42n);
			expect(decoded.paymentHashes).to.have.length(2);
			expect(decoded.paymentHashes![1].equals(hashes[1])).to.equal(true);
			expect(decoded.signature.equals(Buffer.alloc(64, 0x11))).to.equal(true);
		});

		it('round-trips without the hash TLV (variant B accept)', function () {
			const msg: IFforAcceptMessage = {
				channelId,
				epochId,
				sCommitmentNumber: 0n,
				signature: Buffer.alloc(64)
			};
			const decoded = decodeFforAcceptMessage(encodeFforAcceptMessage(msg));
			expect(decoded.sCommitmentNumber).to.equal(0n);
			expect(decoded.paymentHashes).to.equal(undefined);
		});
	});

	describe('ff_invoices (55005)', function () {
		it('round-trips multiple length-prefixed invoice strings', function () {
			const invoices = ['lnbc1invoiceone', 'lnbc1invoicetwo', ''];
			const decoded = decodeFforInvoicesMessage(
				encodeFforInvoicesMessage({ channelId, epochId, invoices })
			);
			expect(decoded.invoices).to.deep.equal(invoices);
			expect(decoded.channelId.equals(channelId)).to.equal(true);
		});

		it('rejects a truncated invoice body', function () {
			const encoded = encodeFforInvoicesMessage({
				channelId,
				epochId,
				invoices: ['lnbc1abcdef']
			});
			expect(() =>
				decodeFforInvoicesMessage(encoded.subarray(0, encoded.length - 3))
			).to.throw('truncated');
		});
	});

	describe('ff_escape_sigs (55009)', function () {
		it('round-trips escape sigs without the reserved HTLC sigs', function () {
			const escapeSigs = [Buffer.alloc(64, 1), Buffer.alloc(64, 2)];
			const decoded = decodeFforEscapeSigsMessage(
				encodeFforEscapeSigsMessage({ channelId, epochId, escapeSigs })
			);
			expect(decoded.escapeSigs).to.have.length(2);
			expect(decoded.escapeSigs[1].equals(Buffer.alloc(64, 2))).to.equal(true);
			expect(decoded.escapeHtlcSigs).to.equal(undefined);
		});

		it('round-trips escape sigs with the reserved HTLC sigs', function () {
			const escapeSigs = [Buffer.alloc(64, 1), Buffer.alloc(64, 2)];
			const escapeHtlcSigs = [Buffer.alloc(64, 3), Buffer.alloc(64, 4)];
			const decoded = decodeFforEscapeSigsMessage(
				encodeFforEscapeSigsMessage({
					channelId,
					epochId,
					escapeSigs,
					escapeHtlcSigs
				})
			);
			expect(decoded.escapeHtlcSigs).to.have.length(2);
			expect(decoded.escapeHtlcSigs![0].equals(Buffer.alloc(64, 3))).to.equal(
				true
			);
		});

		it('rejects mismatched HTLC sig count on encode', function () {
			expect(() =>
				encodeFforEscapeSigsMessage({
					channelId,
					epochId,
					escapeSigs: [Buffer.alloc(64)],
					escapeHtlcSigs: [Buffer.alloc(64), Buffer.alloc(64)]
				})
			).to.throw('!= num_escapes');
		});
	});

	describe('ff_begin / ff_end / ff_error', function () {
		it('round-trips ff_begin', function () {
			const decoded = decodeFforBeginMessage(
				encodeFforBeginMessage({
					channelId,
					epochId,
					epochStartHeight: 899_999
				})
			);
			expect(decoded.epochStartHeight).to.equal(899_999);
			expect(decoded.epochId.equals(epochId)).to.equal(true);
		});

		it('round-trips ff_end (header only)', function () {
			const encoded = encodeFforEndMessage({ channelId, epochId });
			expect(encoded.length).to.equal(64);
			const decoded = decodeFforEndMessage(encoded);
			expect(decoded.channelId.equals(channelId)).to.equal(true);
			expect(decoded.epochId.equals(epochId)).to.equal(true);
		});

		it('round-trips ff_error with utf8 data', function () {
			const decoded = decodeFforErrorMessage(
				encodeFforErrorMessage({
					channelId,
					epochId,
					data: Buffer.from('budget too big ✗', 'utf8')
				})
			);
			expect(decoded.data.toString('utf8')).to.equal('budget too big ✗');
		});

		it('decodeFforHeader routes any FFOR message by its 64-byte prefix', function () {
			const header = decodeFforHeader(
				encodeFforBeginMessage({ channelId, epochId, epochStartHeight: 1 })
			);
			expect(header.channelId.equals(channelId)).to.equal(true);
			expect(header.epochId.equals(epochId)).to.equal(true);
		});
	});

	describe('node-key signatures (✍ messages)', function () {
		const nodeKey = crypto.createHash('sha256').update('ffor-node').digest();
		const nodeId = getPublicKey(nodeKey);

		it('signs and verifies ff_init', function () {
			const payload = signFforMessage(
				FF_INIT_TYPE,
				encodeFforInitMessage(baseInit({ signature: Buffer.alloc(64) })),
				nodeKey
			);
			expect(
				verifyFforMessageSignature(FF_INIT_TYPE, payload, nodeId)
			).to.equal(true);
			// The decoded signature is the payload's final 64 bytes.
			const decoded = decodeFforInitMessage(payload);
			expect(
				decoded.signature.equals(payload.subarray(payload.length - 64))
			).to.equal(true);
		});

		it('signs and verifies ff_accept', function () {
			const payload = signFforMessage(
				FF_ACCEPT_TYPE,
				encodeFforAcceptMessage({
					channelId,
					epochId,
					sCommitmentNumber: 7n,
					paymentHashes: [crypto.randomBytes(32)],
					signature: Buffer.alloc(64)
				}),
				nodeKey
			);
			expect(
				verifyFforMessageSignature(FF_ACCEPT_TYPE, payload, nodeId)
			).to.equal(true);
		});

		it('rejects a tampered body byte', function () {
			const payload = signFforMessage(
				FF_INIT_TYPE,
				encodeFforInitMessage(baseInit({ signature: Buffer.alloc(64) })),
				nodeKey
			);
			const tampered = Buffer.from(payload);
			tampered[70] ^= 0x01; // flip a bit in the fixed fields
			expect(
				verifyFforMessageSignature(FF_INIT_TYPE, tampered, nodeId)
			).to.equal(false);
		});

		it('rejects a tampered signature', function () {
			const payload = signFforMessage(
				FF_INIT_TYPE,
				encodeFforInitMessage(baseInit({ signature: Buffer.alloc(64) })),
				nodeKey
			);
			const tampered = Buffer.from(payload);
			tampered[tampered.length - 1] ^= 0x01;
			expect(
				verifyFforMessageSignature(FF_INIT_TYPE, tampered, nodeId)
			).to.equal(false);
		});

		it('rejects verification against the wrong node id', function () {
			const payload = signFforMessage(
				FF_INIT_TYPE,
				encodeFforInitMessage(baseInit({ signature: Buffer.alloc(64) })),
				nodeKey
			);
			const otherId = getPublicKey(
				crypto.createHash('sha256').update('other').digest()
			);
			expect(
				verifyFforMessageSignature(FF_INIT_TYPE, payload, otherId)
			).to.equal(false);
		});

		it('digest covers the type and every body byte EXCEPT the final 64', function () {
			const a = encodeFforInitMessage(
				baseInit({ signature: Buffer.alloc(64) })
			);
			const b = encodeFforInitMessage(
				baseInit({ signature: Buffer.alloc(64, 0xff) })
			);
			// Different signature slots, identical digests.
			expect(
				fforMessageDigest(FF_INIT_TYPE, a).equals(
					fforMessageDigest(FF_INIT_TYPE, b)
				)
			).to.equal(true);
			// A different message TYPE over the same body yields a different digest.
			expect(
				fforMessageDigest(FF_INIT_TYPE, a).equals(
					fforMessageDigest(FF_ACCEPT_TYPE, a)
				)
			).to.equal(false);
		});
	});
});
