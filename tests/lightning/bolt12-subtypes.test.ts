/**
 * S-4.H4 regression: BOLT 12 subtype layouts and string encoding.
 *
 * Before this fix beignet's offers/invreqs/invoices interoperated only with
 * beignet itself:
 * - `[...*blinded_path]` / `[...*blinded_payinfo]` arrays carried a 1-byte
 *   count prefix the spec does not use (the array fills the TLV length);
 * - `blinded_payinfo` put a u16 features-length placeholder between
 *   htlc_minimum_msat and htlc_maximum_msat and never serialized features
 *   (spec: flen + features come AFTER htlc_maximum_msat);
 * - decoders assumed a 33-byte first_node_id, mis-parsing the 9-byte
 *   sciddir_or_pubkey scid-dir form (including the onion-message reply_path
 *   decoder);
 * - strings were encoded WITH a bech32m checksum, but BOLT 12 strings use the
 *   bech32 character set with NO checksum (and allow `+` continuation), so
 *   every beignet string was unreadable by CLN and vice versa.
 *
 * Live-CLN validated (docker cln, regtest): a beignet offer carrying a 2-hop
 * blinded path decodes at CLN as `valid: true` with all path fields parsed,
 * and the CLN offer pinned below decodes in beignet.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	encodeBlindedPath,
	decodeBlindedPath,
	encodeBlindedPaths,
	decodeBlindedPaths,
	encodeBlindedPayInfo,
	decodeBlindedPayInfo,
	encodeBlindedPayInfos,
	decodeBlindedPayInfos,
	IBlindedPath,
	IBlindedPayInfo
} from '../../src/lightning/onion/blinded-path';
import {
	encodeBlindedPathTlv,
	decodeBlindedPathTlv
} from '../../src/lightning/onion-message/codec';
import {
	encodeNoChecksum,
	decodeNoChecksum
} from '../../src/lightning/offer/bech32-nochecksum';
import { encodeOffer } from '../../src/lightning/offer/encode';
import { decodeOffer } from '../../src/lightning/offer/decode';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const pub = (): Buffer => getPublicKey(crypto.randomBytes(32));

/**
 * A real offer created by the docker CLN node
 * (`lightning-cli offer 5000msat "beignet-h4-fixture"`), pinned so the
 * cross-implementation decode keeps working offline.
 */
const CLN_OFFER =
	'lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqgfcszsjvfjkjemwv46z66p594nxj7r5w4ex293pqtfuw72kf7htzyed62lkkcn8lkw9wxmptz7t8d2j5tylfg7ere4h5';
const CLN_NODE_ID =
	'02d3c779564faeb1132dd2bf6b6267fd9c571b6158bcb3b552a2c9f4a3d91e6b7a';

function makePath(numHops: number): IBlindedPath {
	const blindedHops: Array<{ blindedNodeId: Buffer; encryptedData: Buffer }> =
		[];
	for (let i = 0; i < numHops; i++) {
		blindedHops.push({
			blindedNodeId: pub(),
			encryptedData: crypto.randomBytes(30 + i)
		});
	}
	return { introductionNodeId: pub(), blindingPoint: pub(), blindedHops };
}

describe('S-4.H4: BOLT 12 subtype layouts', function () {
	describe('blinded_path arrays ([...*blinded_path])', function () {
		it('carry NO count prefix: array bytes are the concatenated paths', function () {
			const paths = [makePath(1), makePath(2)];
			const encoded = encodeBlindedPaths(paths);
			expect(
				encoded.equals(
					Buffer.concat([
						encodeBlindedPath(paths[0]),
						encodeBlindedPath(paths[1])
					])
				)
			).to.equal(true);
			// First byte is the first path's sciddir_or_pubkey discriminator
			// (0x02/0x03), NOT a count.
			expect([0x02, 0x03]).to.include(encoded[0]);

			const decoded = decodeBlindedPaths(encoded);
			expect(decoded).to.have.length(2);
			expect(decoded[1].blindedHops).to.have.length(2);
			expect(
				decoded[0].introductionNodeId.equals(paths[0].introductionNodeId)
			).to.equal(true);
		});

		it('decodes the 9-byte sciddir_or_pubkey scid-dir first_node_id form', function () {
			// direction byte 0x01 + 8-byte short_channel_id
			const scidDir = Buffer.concat([
				Buffer.from([0x01]),
				crypto.randomBytes(8)
			]);
			const path: IBlindedPath = {
				introductionNodeId: scidDir,
				blindingPoint: pub(),
				blindedHops: [
					{ blindedNodeId: pub(), encryptedData: crypto.randomBytes(24) }
				]
			};
			const encoded = encodeBlindedPath(path);
			const { path: decoded, offset } = decodeBlindedPath(encoded, 0);
			expect(offset).to.equal(encoded.length);
			expect(decoded.introductionNodeId.equals(scidDir)).to.equal(true);
			expect(
				decoded.blindedHops[0].encryptedData.equals(
					path.blindedHops[0].encryptedData
				)
			).to.equal(true);
		});

		it('rejects an invalid sciddir_or_pubkey discriminator', function () {
			const bogus = Buffer.concat([
				Buffer.from([0x80]),
				crypto.randomBytes(32)
			]);
			expect(() =>
				encodeBlindedPath({
					introductionNodeId: bogus,
					blindingPoint: pub(),
					blindedHops: []
				})
			).to.throw(/sciddir_or_pubkey/);
			expect(() => decodeBlindedPath(bogus, 0)).to.throw(/discriminator/);
		});
	});

	describe('blinded_payinfo', function () {
		it('matches the spec byte layout exactly (flen + features AFTER htlc_maximum_msat)', function () {
			const info: IBlindedPayInfo = {
				feeBaseMsat: 1000,
				feeProportionalMillionths: 250,
				cltvExpiryDelta: 144,
				htlcMinimumMsat: 1n,
				htlcMaximumMsat: 100_000_000n,
				features: Buffer.from([0x02, 0x00])
			};
			const expected = Buffer.alloc(30);
			expected.writeUInt32BE(1000, 0); // fee_base_msat
			expected.writeUInt32BE(250, 4); // fee_proportional_millionths
			expected.writeUInt16BE(144, 8); // cltv_expiry_delta
			expected.writeBigUInt64BE(1n, 10); // htlc_minimum_msat
			expected.writeBigUInt64BE(100_000_000n, 18); // htlc_maximum_msat
			expected.writeUInt16BE(2, 26); // flen
			expected[28] = 0x02; // features
			expected[29] = 0x00;
			expect(encodeBlindedPayInfo(info).equals(expected)).to.equal(true);

			const { info: decoded, offset } = decodeBlindedPayInfo(expected, 0);
			expect(offset).to.equal(30);
			expect(decoded.htlcMaximumMsat).to.equal(100_000_000n);
			expect(decoded.features!.equals(Buffer.from([0x02, 0x00]))).to.equal(
				true
			);
		});

		it('arrays carry NO count prefix and round-trip mixed feature lengths', function () {
			const a: IBlindedPayInfo = {
				feeBaseMsat: 1,
				feeProportionalMillionths: 2,
				cltvExpiryDelta: 3,
				htlcMinimumMsat: 4n,
				htlcMaximumMsat: 5n
			};
			const b: IBlindedPayInfo = { ...a, features: crypto.randomBytes(5) };
			const encoded = encodeBlindedPayInfos([a, b]);
			expect(encoded.length).to.equal(28 + 33);
			const decoded = decodeBlindedPayInfos(encoded);
			expect(decoded).to.have.length(2);
			expect(decoded[0].features).to.equal(undefined);
			expect(decoded[1].features!.equals(b.features!)).to.equal(true);
		});
	});

	describe('onion-message reply_path codec', function () {
		it('is byte-identical to the shared BOLT 4 codec and handles scid-dir form', function () {
			const path = makePath(2);
			expect(
				encodeBlindedPathTlv(path).equals(encodeBlindedPath(path))
			).to.equal(true);

			const scidPath: IBlindedPath = {
				...makePath(1),
				introductionNodeId: Buffer.concat([
					Buffer.from([0x00]),
					crypto.randomBytes(8)
				])
			};
			const decoded = decodeBlindedPathTlv(encodeBlindedPathTlv(scidPath));
			expect(
				decoded.introductionNodeId.equals(scidPath.introductionNodeId)
			).to.equal(true);
		});
	});

	describe('BOLT 12 string encoding (bech32 charset, NO checksum)', function () {
		it('round-trips and produces no trailing checksum', function () {
			const data = crypto.randomBytes(50);
			const s = encodeNoChecksum('lno', data);
			// ceil(50*8/5) = 80 data chars after 'lno1' — nothing more.
			expect(s.length).to.equal(4 + 80);
			const back = decodeNoChecksum(s);
			expect(back.hrp).to.equal('lno');
			expect(back.data.equals(data)).to.equal(true);
		});

		it('accepts + continuation with whitespace (BOLT 12 splitting)', function () {
			const data = crypto.randomBytes(40);
			const s = encodeNoChecksum('lni', data);
			const split = `${s.slice(0, 20)}+\n  ${s.slice(20, 45)}+ ${s.slice(45)}`;
			const back = decodeNoChecksum(split);
			expect(back.data.equals(data)).to.equal(true);
		});

		it('decodes a REAL CLN offer (pinned from docker cln)', function () {
			const offer = decodeOffer(CLN_OFFER);
			expect(offer.description).to.equal('beignet-h4-fixture');
			expect(offer.amount).to.equal(5000n);
			expect(offer.issuerId!.toString('hex')).to.equal(CLN_NODE_ID);
		});

		it('an offer with blinded paths round-trips through the string layer', function () {
			const offer = {
				description: 'h4 layout check',
				amount: 10_000n,
				issuerId: pub(),
				paths: [makePath(2)]
			};
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const decoded = decodeOffer(encodeOffer(offer as any));
			expect(decoded.description).to.equal('h4 layout check');
			expect(decoded.paths).to.have.length(1);
			expect(decoded.paths![0].blindedHops).to.have.length(2);
		});
	});
});
