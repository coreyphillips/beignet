/**
 * Taproot (option_taproot) funding output: build + spend.
 *
 * Validates the funding output end-to-end: build the 2-of-2 MuSig2 key-spend
 * P2TR, construct a transaction spending it, compute the BIP341 key-spend
 * sighash, co-sign with MuSig2, and confirm the aggregated signature is a valid
 * BIP340 key-spend witness for the funding output key.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import {
	createTaprootFundingScript,
	buildTaprootKeySpendWitness,
	taprootKeySpendSighash
} from '../../src/lightning/script/funding-taproot';
import {
	deriveTaprootFundingKey,
	generateNonce,
	aggregateNonces,
	startSigningSession,
	partialSign,
	aggregatePartialSigs
} from '../../src/lightning/crypto/musig';
import {
	isTaprootChannel,
	isAnchorChannel
} from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

describe('option_taproot channel type', function () {
	it('isTaprootChannel detects the OPTION_TAPROOT bit', function () {
		const flags = FeatureFlags.empty();
		flags.setCompulsory(Feature.OPTION_TAPROOT);
		const channelType = flags.toBuffer();
		expect(isTaprootChannel(channelType)).to.be.true;
		// Simple taproot channels carry ONLY the taproot bit on the wire — the
		// anchor bit (22) is NOT literally present...
		expect(
			FeatureFlags.fromBuffer(channelType).hasFeature(
				Feature.ANCHOR_ZERO_FEE_HTLC
			)
		).to.be.false;
		// ...but taproot IMPLIES anchor-style commitments, so isAnchorChannel is
		// true (every internal anchor branch must still fire for taproot channels).
		expect(isAnchorChannel(channelType)).to.be.true;
	});

	it('isTaprootChannel is false for null/empty/anchor channel types', function () {
		expect(isTaprootChannel(null)).to.be.false;
		expect(isTaprootChannel(Buffer.alloc(0))).to.be.false;
		const anchor = FeatureFlags.empty();
		anchor.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
		expect(isTaprootChannel(anchor.toBuffer())).to.be.false;
	});

	it('OPTION_TAPROOT occupies the LND staging bits 180/181', function () {
		// LND v0.20 advertises simple-taproot-chans-x at bit 181 (staging);
		// final bits 80/81 are reserved but not yet activated by any node.
		expect(Feature.OPTION_TAPROOT).to.equal(180);
		const opt = FeatureFlags.empty();
		opt.setOptional(Feature.OPTION_TAPROOT); // sets bit 181
		expect(opt.hasBit(181)).to.be.true;
		expect(opt.hasFeature(Feature.OPTION_TAPROOT)).to.be.true;
	});
});

describe('Taproot funding output (option_taproot)', function () {
	const sk1 = crypto.randomBytes(32);
	const sk2 = crypto.randomBytes(32);
	const pk1 = Buffer.from(ecc.pointFromScalar(sk1, true)!);
	const pk2 = Buffer.from(ecc.pointFromScalar(sk2, true)!);

	it('produces a valid P2TR funding output (OP_1 <32-byte key>) + bech32m address', function () {
		const f = createTaprootFundingScript(pk1, pk2, bitcoin.networks.regtest);
		expect(f.p2trOutput).to.have.length(34);
		expect(f.p2trOutput[0]).to.equal(0x51); // OP_1
		expect(f.p2trOutput[1]).to.equal(0x20); // push 32
		expect(f.p2trOutput.subarray(2)).to.deep.equal(f.outputKey);
		expect(f.address.startsWith('bcrt1p')).to.be.true;
		// Order-independent.
		const g = createTaprootFundingScript(pk2, pk1, bitcoin.networks.regtest);
		expect(g.p2trOutput.equals(f.p2trOutput)).to.be.true;
	});

	it('rejects non-33-byte funding pubkeys', function () {
		expect(() => createTaprootFundingScript(pk1.subarray(1), pk2)).to.throw(
			'33 bytes'
		);
	});

	it('is spendable via a co-signed MuSig2 key-spend (valid BIP340 witness sig)', function () {
		const funding = createTaprootFundingScript(
			pk1,
			pk2,
			bitcoin.networks.regtest
		);
		const fundingValue = 1_000_000;

		// A transaction spending the funding output.
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(Buffer.alloc(32, 1), 0); // funding outpoint (fake txid)
		tx.addOutput(funding.p2trOutput, fundingValue - 200);

		// BIP341 key-spend sighash over the single taproot input.
		const sighash = taprootKeySpendSighash(
			tx,
			0,
			[funding.p2trOutput],
			[fundingValue]
		);

		// MuSig2 co-signing with the same taproot tweak used for the funding key.
		const { tweak, outputKey } = deriveTaprootFundingKey(pk1, pk2);
		const n1 = generateNonce({
			publicKey: pk1,
			secretKey: sk1,
			sessionId: crypto.randomBytes(32),
			msg: sighash
		});
		const n2 = generateNonce({
			publicKey: pk2,
			secretKey: sk2,
			sessionId: crypto.randomBytes(32),
			msg: sighash
		});
		const aggNonce = aggregateNonces([Buffer.from(n1), Buffer.from(n2)]);
		const session = startSigningSession(aggNonce, sighash, pk1, pk2, tweak);
		const ps1 = partialSign({
			secretKey: sk1,
			publicNonce: n1,
			sessionKey: session
		});
		const ps2 = partialSign({
			secretKey: sk2,
			publicNonce: n2,
			sessionKey: session
		});
		const finalSig = aggregatePartialSigs([ps1, ps2], session);

		// The aggregated signature is a valid BIP340 key-spend for the output key.
		expect(ecc.verifySchnorr(sighash, outputKey, finalSig)).to.be.true;
		expect(outputKey.equals(funding.outputKey)).to.be.true;

		// Attach the witness (single 64-byte sig for SIGHASH_DEFAULT).
		const witness = buildTaprootKeySpendWitness(finalSig);
		tx.ins[0].witness = witness;
		expect(tx.ins[0].witness).to.have.length(1);
		expect(tx.ins[0].witness[0]).to.have.length(64);
	});
});
