/**
 * option_taproot commitment outputs (M4.4): structural checks.
 *
 * Validates the to_local / to_remote taproot output construction (P2TR shape,
 * NUMS internal key, leaf scripts, control-block sizes). Real on-chain
 * spendability is proven separately on regtest (interop/taproot-commitment-spend).
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootToLocalDelayScript,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	TAPROOT_NUMS_KEY,
	toXOnly
} from '../../src/lightning/script/commitment-taproot';

const key = (): Buffer =>
	Buffer.from(ecc.pointFromScalar(crypto.randomBytes(32), true)!);

describe('option_taproot commitment outputs', function () {
	it("NUMS internal key matches LND's TaprootNUMSKey (x-only, 32 bytes)", function () {
		expect(TAPROOT_NUMS_KEY).to.have.length(32);
		// LND's "Lightning Simple Taproot" generator (x-only of compressed
		// 02dca094...), NOT the generic BIP341 H point — required for commitment
		// byte-parity with LND (verified live vs lnd v0.20).
		expect(TAPROOT_NUMS_KEY.toString('hex')).to.equal(
			'dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279'
		);
	});

	it('toXOnly strips the parity byte from a compressed key', function () {
		const k = key();
		expect(toXOnly(k)).to.deep.equal(k.subarray(1));
		expect(toXOnly(k)).to.have.length(32);
	});

	it('to_local is a P2TR with delay+revoke leaves and depth-1 control blocks', function () {
		const out = buildTaprootToLocalOutput(
			key(),
			key(),
			144,
			bitcoin.networks.regtest
		);
		// scriptPubKey: OP_1 (0x51) push-32 (0x20) <output key>.
		expect(out.output).to.have.length(34);
		expect(out.output[0]).to.equal(0x51);
		expect(out.output[1]).to.equal(0x20);
		expect(out.output.subarray(2)).to.deep.equal(out.outputKey);
		expect(out.outputKey).to.have.length(32);
		expect(out.address.startsWith('bcrt1p')).to.be.true;
		// Two-leaf tree → each control block is 33 (internal key + parity) + 32
		// (one sibling hash) = 65 bytes.
		expect(out.delay.controlBlock).to.have.length(65);
		expect(out.revoke.controlBlock).to.have.length(65);
		// The control block's internal key matches NUMS.
		expect(out.delay.controlBlock.subarray(1, 33)).to.deep.equal(
			TAPROOT_NUMS_KEY
		);
	});

	it('to_remote is a single-leaf P2TR with a depth-0 control block', function () {
		const out = buildTaprootToRemoteOutput(key(), bitcoin.networks.regtest);
		expect(out.output).to.have.length(34);
		expect(out.address.startsWith('bcrt1p')).to.be.true;
		// Single leaf → control block is just 33 bytes (no sibling).
		expect(out.spend.controlBlock).to.have.length(33);
	});

	it('delay leaf encodes <key> CHECKSIG <delay> CSV DROP', function () {
		const k = key();
		const asm = bitcoin.script.toASM(buildTaprootToLocalDelayScript(k, 144));
		expect(asm).to.include('OP_CHECKSIG');
		expect(asm).to.include('OP_CHECKSEQUENCEVERIFY');
		expect(asm).to.include('OP_DROP');
		expect(asm.startsWith(toXOnly(k).toString('hex'))).to.be.true;
	});

	it('offered/received HTLC outputs use the revocation key as internal key + 2 leaves', function () {
		const revoke = key();
		const offered = buildTaprootOfferedHtlcOutput(
			revoke,
			key(),
			key(),
			crypto.randomBytes(32),
			bitcoin.networks.regtest
		);
		expect(offered.output).to.have.length(34);
		expect(offered.internalKey).to.deep.equal(toXOnly(revoke));
		// Internal key in each control block is the revocation key (key-path = breach).
		expect(offered.success.controlBlock.subarray(1, 33)).to.deep.equal(
			toXOnly(revoke)
		);
		expect(offered.timeout.controlBlock).to.have.length(65);
		expect(offered.merkleRoot).to.have.length(32);

		const received = buildTaprootReceivedHtlcOutput(
			revoke,
			key(),
			key(),
			crypto.randomBytes(32),
			500000,
			bitcoin.networks.regtest
		);
		// Received timeout leaf carries the CLTV check.
		const timeoutAsm = bitcoin.script.toASM(received.timeout.script);
		expect(timeoutAsm).to.include('OP_CHECKLOCKTIMEVERIFY');
		// Success leaves check the preimage size + hash.
		expect(bitcoin.script.toASM(received.success.script)).to.include('OP_SIZE');
		expect(bitcoin.script.toASM(offered.success.script)).to.include(
			'OP_HASH160'
		);
	});
});
