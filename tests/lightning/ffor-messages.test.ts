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
	verifyFforMessageSignature,
	FF_SETTLEMENT_TYPE,
	IFforSettlementMessage,
	encodeFforSettlementMessage,
	decodeFforSettlementMessage,
	encodeFforReconcileMessage,
	decodeFforReconcileMessage,
	encodeFforReconcileAckMessage,
	decodeFforReconcileAckMessage,
	encodeFforRevokeBatchMessage,
	decodeFforRevokeBatchMessage
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

	// ─────────────── M2: settlement + reconciliation codecs ───────────────

	describe('ff_accept TLV 7 (s_htlc_id_base, prototype extension)', function () {
		it('round-trips alongside the variant A hash TLV', function () {
			const msg: IFforAcceptMessage = {
				channelId,
				epochId,
				sCommitmentNumber: 42n,
				paymentHashes: [crypto.randomBytes(32)],
				sHtlcIdBase: 17n,
				signature: Buffer.alloc(64, 0x11)
			};
			const decoded = decodeFforAcceptMessage(encodeFforAcceptMessage(msg));
			expect(decoded.sHtlcIdBase).to.equal(17n);
			expect(decoded.paymentHashes).to.have.length(1);
		});
	});

	describe('ff_settlement (55013)', function () {
		function baseSettlement(
			overrides?: Partial<IFforSettlementMessage>
		): IFforSettlementMessage {
			return {
				channelId,
				epochId,
				seq: 2,
				paymentHash: Buffer.alloc(32, 0xaa),
				htlcAmountMsat: 550_000n,
				voucherAmountMsat: 546_250n,
				rCommitmentNumber: 44n,
				commitmentSig: Buffer.alloc(64, 0x01),
				htlcSigs: [Buffer.alloc(64, 0x02), Buffer.alloc(64, 0x03)],
				signature: Buffer.alloc(64, 0x77),
				...overrides
			};
		}

		it('round-trips with every TLV (seq-1 style package)', function () {
			const msg = baseSettlement({
				seq: 1,
				htlcSigs: [Buffer.alloc(64, 0x02)],
				revocationSecretN0: Buffer.alloc(32, 0x0a),
				preimage: Buffer.alloc(32, 0x0a),
				upstreamScid: Buffer.alloc(8, 0x05)
			});
			const decoded = decodeFforSettlementMessage(
				encodeFforSettlementMessage(msg)
			);
			expect(decoded.seq).to.equal(1);
			expect(decoded.htlcAmountMsat).to.equal(550_000n);
			expect(decoded.voucherAmountMsat).to.equal(546_250n);
			expect(decoded.rCommitmentNumber).to.equal(44n);
			expect(decoded.commitmentSig.equals(Buffer.alloc(64, 0x01))).to.equal(
				true
			);
			expect(decoded.htlcSigs).to.have.length(1);
			expect(
				decoded.revocationSecretN0!.equals(Buffer.alloc(32, 0x0a))
			).to.equal(true);
			expect(decoded.preimage!.equals(Buffer.alloc(32, 0x0a))).to.equal(true);
			expect(decoded.upstreamScid!.equals(Buffer.alloc(8, 0x05))).to.equal(
				true
			);
		});

		it('round-trips without optional TLVs (seq > 1, variant B style)', function () {
			const decoded = decodeFforSettlementMessage(
				encodeFforSettlementMessage(baseSettlement())
			);
			expect(decoded.seq).to.equal(2);
			expect(decoded.htlcSigs).to.have.length(2);
			expect(decoded.htlcSigs[1].equals(Buffer.alloc(64, 0x03))).to.equal(true);
			expect(decoded.revocationSecretN0).to.equal(undefined);
			expect(decoded.preimage).to.equal(undefined);
			expect(decoded.upstreamScid).to.equal(undefined);
		});

		it('enforces num_htlc_sigs == seq on encode (§9.1 re-signs every voucher)', function () {
			expect(() =>
				encodeFforSettlementMessage(
					baseSettlement({ seq: 3 }) // 2 sigs, seq 3
				)
			).to.throw('num_htlc_sigs');
		});

		it('signs and verifies; rejects a tampered body', function () {
			const nodeKey = crypto.createHash('sha256').update('pkg-key').digest();
			const nodeId = getPublicKey(nodeKey);
			const payload = signFforMessage(
				FF_SETTLEMENT_TYPE,
				encodeFforSettlementMessage(
					baseSettlement({ signature: Buffer.alloc(64) })
				),
				nodeKey
			);
			expect(
				verifyFforMessageSignature(FF_SETTLEMENT_TYPE, payload, nodeId)
			).to.equal(true);
			const tampered = Buffer.from(payload);
			tampered[66] ^= 0x01; // flip a bit inside `seq`
			expect(
				verifyFforMessageSignature(FF_SETTLEMENT_TYPE, tampered, nodeId)
			).to.equal(false);
		});

		it('rejects truncation inside htlc_sigs', function () {
			const encoded = encodeFforSettlementMessage(baseSettlement());
			expect(() =>
				decodeFforSettlementMessage(encoded.subarray(0, encoded.length - 70))
			).to.throw();
		});
	});

	describe('ff_reconcile (55015)', function () {
		it('round-trips', function () {
			const pt = Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 0x44)]);
			const decoded = decodeFforReconcileMessage(
				encodeFforReconcileMessage({
					channelId,
					epochId,
					newCommitmentNumber: 43n,
					commitmentSig: Buffer.alloc(64, 0x09),
					htlcSigs: [Buffer.alloc(64, 0x0b)],
					rNextPerCommitmentPoint: pt
				})
			);
			expect(decoded.newCommitmentNumber).to.equal(43n);
			expect(decoded.commitmentSig.equals(Buffer.alloc(64, 0x09))).to.equal(
				true
			);
			expect(decoded.htlcSigs).to.have.length(1);
			expect(decoded.rNextPerCommitmentPoint.equals(pt)).to.equal(true);
		});

		it('round-trips a zero-settlement reconcile (no htlc sigs)', function () {
			const pt = Buffer.concat([Buffer.from([3]), Buffer.alloc(32, 0x45)]);
			const decoded = decodeFforReconcileMessage(
				encodeFforReconcileMessage({
					channelId,
					epochId,
					newCommitmentNumber: 44n,
					commitmentSig: Buffer.alloc(64),
					htlcSigs: [],
					rNextPerCommitmentPoint: pt
				})
			);
			expect(decoded.htlcSigs).to.have.length(0);
			expect(decoded.rNextPerCommitmentPoint.equals(pt)).to.equal(true);
		});
	});

	describe('ff_reconcile_ack (55017)', function () {
		const pt = Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 0x66)]);

		it('round-trips with both conditional secrets', function () {
			const decoded = decodeFforReconcileAckMessage(
				encodeFforReconcileAckMessage({
					channelId,
					epochId,
					sNextPerCommitmentPoint: pt,
					revocationSecretN0: Buffer.alloc(32, 0x0c),
					revocationSecretN0Plus1: Buffer.alloc(32, 0x0d)
				})
			);
			expect(decoded.sNextPerCommitmentPoint.equals(pt)).to.equal(true);
			expect(
				decoded.revocationSecretN0!.equals(Buffer.alloc(32, 0x0c))
			).to.equal(true);
			expect(
				decoded.revocationSecretN0Plus1!.equals(Buffer.alloc(32, 0x0d))
			).to.equal(true);
		});

		it('round-trips with no TLVs (j > 0, no escapes)', function () {
			const decoded = decodeFforReconcileAckMessage(
				encodeFforReconcileAckMessage({
					channelId,
					epochId,
					sNextPerCommitmentPoint: pt
				})
			);
			expect(decoded.revocationSecretN0).to.equal(undefined);
			expect(decoded.revocationSecretN0Plus1).to.equal(undefined);
		});
	});

	describe('ff_revoke_batch (55019)', function () {
		it('round-trips a batch of secrets', function () {
			const secrets = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];
			const decoded = decodeFforRevokeBatchMessage(
				encodeFforRevokeBatchMessage({ channelId, epochId, secrets })
			);
			expect(decoded.secrets).to.have.length(2);
			expect(decoded.secrets[1].equals(Buffer.alloc(32, 2))).to.equal(true);
		});

		it('rejects truncation inside the secrets', function () {
			const encoded = encodeFforRevokeBatchMessage({
				channelId,
				epochId,
				secrets: [Buffer.alloc(32, 1)]
			});
			expect(() =>
				decodeFforRevokeBatchMessage(encoded.subarray(0, encoded.length - 4))
			).to.throw('truncated');
		});
	});
});
