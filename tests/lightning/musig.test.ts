/**
 * MuSig2 (BIP327) wrapper correctness.
 *
 * Pins the crypto backend to the official BIP327 key-aggregation test vectors,
 * and validates the full taproot 2-of-2 signing pipeline end-to-end: an
 * INDEPENDENT BIP340 Schnorr verifier (@bitcoinerlab/secp256k1) must accept the
 * MuSig2-aggregated signature for the taproot-tweaked output key. If that holds,
 * key aggregation, nonce handling, partial signing/aggregation and the BIP341
 * key-spend tweak are all correct.
 */

import { expect } from 'chai';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import {
	musig,
	deriveTaprootFundingKey,
	generateNonce,
	aggregateNonces,
	startSigningSession,
	partialSign,
	partialVerify,
	aggregatePartialSigs
} from '../../src/lightning/crypto/musig';

const hex = (s: string): Buffer => Buffer.from(s, 'hex');

describe('MuSig2 (BIP327) wrapper', function () {
	describe('key aggregation — official BIP327 vectors', function () {
		// BIP327 key_agg_vectors.json public keys.
		const X1 = hex(
			'02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'
		);
		const X2 = hex(
			'03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'
		);
		const X3 = hex(
			'023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66'
		);

		const aggXOnly = (keys: Buffer[]): string =>
			Buffer.from(musig.getXOnlyPubkey(musig.keyAgg(keys))).toString('hex');

		it('aggregates [X1, X2, X3]', function () {
			expect(aggXOnly([X1, X2, X3])).to.equal(
				'90539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c'
			);
		});

		it('aggregates [X3, X2, X1] (order matters)', function () {
			expect(aggXOnly([X3, X2, X1])).to.equal(
				'6204de8b083426dc6eaf9502d27024d53fc826bf7d2012148a0575435df54b2b'
			);
		});

		it('aggregates [X1, X1, X1]', function () {
			expect(aggXOnly([X1, X1, X1])).to.equal(
				'b436e3bad62b8cd409969a224731c193d051162d8c5ae8b109306127da3aa935'
			);
		});

		it('aggregates [X1, X1, X2, X2]', function () {
			expect(aggXOnly([X1, X1, X2, X2])).to.equal(
				'69bc22bfa5d106306e48a20679de1d7389386124d07571d0d872686028c26a3e'
			);
		});
	});

	describe('taproot funding key + 2-of-2 signing', function () {
		const sk1 = crypto.randomBytes(32);
		const sk2 = crypto.randomBytes(32);
		const pk1 = Buffer.from(ecc.pointFromScalar(sk1, true)!);
		const pk2 = Buffer.from(ecc.pointFromScalar(sk2, true)!);

		it('derives a deterministic, order-independent taproot funding key', function () {
			const a = deriveTaprootFundingKey(pk1, pk2);
			const b = deriveTaprootFundingKey(pk2, pk1);
			expect(a.outputKey.equals(b.outputKey)).to.be.true;
			expect(a.outputKey).to.have.length(32);
			expect(a.internalKey).to.have.length(32);
			// Output key differs from the untweaked internal key (BIP341 tweak applied).
			expect(a.outputKey.equals(a.internalKey)).to.be.false;
		});

		it('co-signs a sighash; the aggregate sig verifies under BIP340 for the output key', function () {
			const { tweak, outputKey } = deriveTaprootFundingKey(pk1, pk2);
			const msg = crypto.randomBytes(32); // stand-in for a commitment sighash

			// Each party generates a single-use nonce (keep the exact object).
			const pubNonce1 = generateNonce({
				publicKey: pk1,
				secretKey: sk1,
				sessionId: crypto.randomBytes(32),
				msg
			});
			const pubNonce2 = generateNonce({
				publicKey: pk2,
				secretKey: sk2,
				sessionId: crypto.randomBytes(32),
				msg
			});

			const aggNonce = aggregateNonces([
				Buffer.from(pubNonce1),
				Buffer.from(pubNonce2)
			]);
			const session = startSigningSession(aggNonce, msg, pk1, pk2, tweak);

			const ps1 = partialSign({
				secretKey: sk1,
				publicNonce: pubNonce1,
				sessionKey: session
			});
			const ps2 = partialSign({
				secretKey: sk2,
				publicNonce: pubNonce2,
				sessionKey: session
			});

			// Each side verifies the other's partial signature.
			expect(
				partialVerify({
					sig: ps2,
					publicKey: pk2,
					publicNonce: Buffer.from(pubNonce2),
					sessionKey: session
				})
			).to.be.true;

			const finalSig = aggregatePartialSigs([ps1, ps2], session);
			expect(finalSig).to.have.length(64);

			// Independent BIP340 verification against the taproot output key.
			expect(ecc.verifySchnorr(msg, outputKey, finalSig)).to.be.true;
			// Wrong message must fail.
			expect(ecc.verifySchnorr(crypto.randomBytes(32), outputKey, finalSig)).to
				.be.false;
		});
	});
});
