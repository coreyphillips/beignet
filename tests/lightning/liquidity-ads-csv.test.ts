/**
 * M3.3 — on-chain lease enforcement: the lessor's to_local script + sweep.
 *
 * Encoding follows LND's script-enforced lease (LeaseCommitScriptToSelf): the
 * normal to_self_delay CSV is kept and an absolute `<lease_expiry>
 * OP_CHECKLOCKTIMEVERIFY OP_DROP` is prepended to the delay branch, so the
 * lessor cannot reclaim its funds before the lease expires.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { buildToLocalScript } from '../../src/lightning/script/commitment';
import {
	buildHtlcOutputScript,
	buildHtlcSuccessTx
} from '../../src/lightning/script/htlc';
import {
	buildToLocalSweepTx,
	buildToLocalDelayedWitness,
	buildSecondLevelSweepTx
} from '../../src/lightning/chain/sweep';
import { computeLeaseExpiry } from '../../src/lightning/channel/liquidity-ads';

describe('Liquidity ads lessor on-chain lock (M3.3)', function () {
	const revocationPubkey = crypto.randomBytes(33);
	const delayedPubkey = crypto.randomBytes(33);
	const leaseExpiry = computeLeaseExpiry(800000); // 804032

	it('plain to_local has no CLTV; leased to_local prepends the lease CLTV', function () {
		const plain = buildToLocalScript(revocationPubkey, delayedPubkey, 144);
		const leased = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			144,
			leaseExpiry
		);
		expect(leased.equals(plain)).to.be.false;

		const ops = bitcoin.script.decompile(leased)!;
		// Expected ELSE branch order: <lease_expiry> CLTV DROP <to_self_delay> CSV DROP <key>
		const cltvIdx = ops.indexOf(bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY);
		const csvIdx = ops.indexOf(bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY);
		expect(cltvIdx).to.be.greaterThan(0);
		expect(csvIdx).to.be.greaterThan(cltvIdx); // CLTV comes before CSV
		// The value pushed before CLTV is the absolute lease_expiry.
		expect(bitcoin.script.number.decode(ops[cltvIdx - 1] as Buffer)).to.equal(
			leaseExpiry
		);
		// The value pushed before CSV is still the to_self_delay.
		expect(bitcoin.script.number.decode(ops[csvIdx - 1] as Buffer)).to.equal(
			144
		);
	});

	it('exactly matches the hand-built LeaseCommitScriptToSelf layout', function () {
		const leased = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			144,
			leaseExpiry
		);
		const expected = bitcoin.script.compile([
			bitcoin.opcodes.OP_IF,
			revocationPubkey,
			bitcoin.opcodes.OP_ELSE,
			bitcoin.script.number.encode(leaseExpiry),
			bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
			bitcoin.opcodes.OP_DROP,
			bitcoin.script.number.encode(144),
			bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
			bitcoin.opcodes.OP_DROP,
			delayedPubkey,
			bitcoin.opcodes.OP_ENDIF,
			bitcoin.opcodes.OP_CHECKSIG
		]);
		expect(leased.equals(expected)).to.be.true;
	});

	it('the lessor sweep sets nLockTime = lease_expiry (CLTV enforced)', function () {
		const witnessScript = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			144,
			leaseExpiry
		);
		const tx = buildToLocalSweepTx({
			commitmentTxid: crypto.randomBytes(32).toString('hex'),
			outputIndex: 0,
			amount: 100_000n,
			witnessScript,
			toSelfDelay: 144,
			destinationScript: bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!,
			feeSatoshis: 500n,
			leaseExpiry
		});
		expect(tx.locktime).to.equal(leaseExpiry);
		// Input sequence is the CSV (144), not 0xffffffff, so locktime is enforced.
		expect(tx.ins[0].sequence).to.equal(144);
		// Witness still selects the delayed (OP_ELSE) branch.
		const witness = buildToLocalDelayedWitness(crypto.randomBytes(72), witnessScript);
		expect(witness[witness.length - 1].equals(witnessScript)).to.be.true;
	});

	it('lessor second-level HTLC output also prepends the lease CLTV', function () {
		const plain = buildHtlcOutputScript(revocationPubkey, delayedPubkey, 144);
		const leased = buildHtlcOutputScript(
			revocationPubkey,
			delayedPubkey,
			144,
			leaseExpiry
		);
		expect(leased.equals(plain)).to.be.false;
		const ops = bitcoin.script.decompile(leased)!;
		const cltvIdx = ops.indexOf(bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY);
		const csvIdx = ops.indexOf(bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY);
		expect(cltvIdx).to.be.greaterThan(0);
		expect(csvIdx).to.be.greaterThan(cltvIdx);
		expect(bitcoin.script.number.decode(ops[cltvIdx - 1] as Buffer)).to.equal(
			leaseExpiry
		);
	});

	it('buildHtlcSuccessTx output carries the lease CLTV for the lessor', function () {
		const leasedTx = buildHtlcSuccessTx(
			crypto.randomBytes(32).toString('hex'),
			0,
			100_000n,
			revocationPubkey,
			delayedPubkey,
			144,
			500n,
			false,
			leaseExpiry
		);
		const plainTx = buildHtlcSuccessTx(
			crypto.randomBytes(32).toString('hex'),
			0,
			100_000n,
			revocationPubkey,
			delayedPubkey,
			144,
			500n,
			false
		);
		// The second-level OUTPUT (P2WSH of the leased script) differs.
		const leasedOut = leasedTx.outs[0].script;
		const plainOut = plainTx.outs[0].script;
		expect(leasedOut.equals(plainOut)).to.be.false;
		// And its witness program == sha256 of the leased output script.
		const expected = bitcoin.payments.p2wsh({
			redeem: {
				output: buildHtlcOutputScript(revocationPubkey, delayedPubkey, 144, leaseExpiry)
			}
		}).output!;
		expect(leasedOut.equals(expected)).to.be.true;
	});

	it('second-level sweep sets nLockTime = lease_expiry for the lessor', function () {
		const witnessScript = buildHtlcOutputScript(
			revocationPubkey,
			delayedPubkey,
			144,
			leaseExpiry
		);
		const tx = buildSecondLevelSweepTx({
			htlcTxid: crypto.randomBytes(32).toString('hex'),
			outputIndex: 0,
			amount: 90_000n,
			witnessScript,
			toSelfDelay: 144,
			destinationScript: bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!,
			feeSatoshis: 500n,
			leaseExpiry
		});
		expect(tx.locktime).to.equal(leaseExpiry);
		expect(tx.ins[0].sequence).to.equal(144);
	});

	it('a non-leased sweep keeps nLockTime = 0', function () {
		const witnessScript = buildToLocalScript(revocationPubkey, delayedPubkey, 144);
		const tx = buildToLocalSweepTx({
			commitmentTxid: crypto.randomBytes(32).toString('hex'),
			outputIndex: 0,
			amount: 100_000n,
			witnessScript,
			toSelfDelay: 144,
			destinationScript: bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!,
			feeSatoshis: 500n
		});
		expect(tx.locktime).to.equal(0);
	});
});
