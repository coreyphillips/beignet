/**
 * BOLT 12: signature/merkle test vectors (bolt12/signature-test.json).
 *
 * Cases 1-3 pin the leaf/nonce/branch merkle construction over the spec's
 * n1 TLV streams; case 4 decodes a real invoice_request, recomputes its
 * merkle root and tagged signature hash, and verifies the BIP-340 schnorr
 * signature against the payer id.
 */

import { expect } from 'chai';
import {
	decodeTlvStream,
	findTlvRecord
} from '../../../src/lightning/message/tlv';
import {
	computeMerkleRootFromRecords,
	computeSignatureHash
} from '../../../src/lightning/offer/merkle';
import {
	schnorrVerify,
	toXOnlyPubkey
} from '../../../src/lightning/offer/schnorr';
import { decodeNoChecksum } from '../../../src/lightning/offer/bech32-nochecksum';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

const SIGNATURE_TLV_TYPE = 240n;

interface ISignatureCase {
	comment: string;
	tlv: string;
	'first-tlv': string;
	merkle: string;
	bolt12?: string;
	signature_tag?: string;
	'H(signature_tag,merkle)'?: string;
	signature?: string;
}

const v = loadVectors<{ cases: ISignatureCase[] }>('bolt12/signature.json');

/**
 * Reassemble each n1 case's full TLV stream: the vector names only the
 * first record; the spec's n1 streams (tlv1=1000, tlv2=1x2x3, tlv3=point
 * with amounts 1,2) accumulate one record per case.
 */
const N1_RECORDS = [
	'010203e8',
	'02080000010000020003',
	'03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002'
];

describe('BOLT 12: signature and merkle conformance', function () {
	v.cases.forEach((c, i) => {
		if (!c.bolt12) {
			it(`computes the merkle root: ${c.comment}`, function () {
				const stream = hexToBuffer(N1_RECORDS.slice(0, i + 1).join(''));
				expect(bufferToHex(stream.subarray(0, 4))).to.equal(
					c['first-tlv'].slice(0, 8)
				);
				const { records } = decodeTlvStream(stream);
				expect(bufferToHex(computeMerkleRootFromRecords(records))).to.equal(
					c.merkle
				);
			});
			return;
		}

		const bolt12 = c.bolt12;
		it(`verifies the invoice_request signature: ${c.comment.slice(
			0,
			60
		)}`, function () {
			const { hrp, data } = decodeNoChecksum(bolt12);
			expect(hrp).to.equal('lnr');
			const { records } = decodeTlvStream(data);

			// The merkle root covers every record except the signature.
			const signing = records.filter((r) => r.type !== SIGNATURE_TLV_TYPE);
			const root = computeMerkleRootFromRecords(signing);
			expect(bufferToHex(root)).to.equal(c.merkle);

			const sigHash = computeSignatureHash(c.signature_tag as string, root);
			expect(bufferToHex(sigHash)).to.equal(c['H(signature_tag,merkle)']);

			const payerId = findTlvRecord(records, 88n) as Buffer;
			const signature = findTlvRecord(records, SIGNATURE_TLV_TYPE) as Buffer;
			expect(bufferToHex(signature)).to.equal(c.signature);
			expect(
				schnorrVerify(sigHash, toXOnlyPubkey(payerId), signature)
			).to.equal(true);
		});
	});
});
