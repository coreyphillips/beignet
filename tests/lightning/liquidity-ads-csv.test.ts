/**
 * On-chain lease enforcement (bLIP-0051, CLN model): the lessor's to_local is a
 * PURE CSV lock. The CSV number becomes max(to_self_delay, lease_csv), where
 * lease_csv = lease_expiry - the blockheight agreed at open. No CLTV clause; the
 * sweep sets no nLockTime. Second-level HTLC outputs are NEVER lease-locked
 * (CLN's htlc_tx has no lease param). Validated live against CLN.
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
	buildToLocalDelayedWitness
} from '../../src/lightning/chain/sweep';
import { leaseCsvBlocks } from '../../src/lightning/channel/liquidity-ads';

describe('Liquidity ads lessor on-chain lock (CLN CSV model)', function () {
	const revocationPubkey = crypto.randomBytes(33);
	const delayedPubkey = crypto.randomBytes(33);
	const toSelfDelay = 144;
	// At open, lease_csv = LEASE_DURATION_BLOCKS = 4032 (> to_self_delay).
	const leaseCsv = leaseCsvBlocks(804032, 800000)!;

	it('leaseCsvBlocks derives lease_expiry - agreed_blockheight', function () {
		expect(leaseCsv).to.equal(4032);
		// Legacy state with no agreed blockheight falls back to the duration.
		expect(leaseCsvBlocks(804032, undefined)).to.equal(4032);
		// Non-lease channel.
		expect(leaseCsvBlocks(undefined, 800000)).to.be.undefined;
	});

	it('plain to_local uses the to_self_delay CSV; leased raises it to lease_csv', function () {
		const plain = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay
		);
		const leased = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay,
			leaseCsv
		);
		expect(leased.equals(plain)).to.be.false;

		const ops = bitcoin.script.decompile(leased)!;
		// No CLTV anywhere (pure CSV, CLN model).
		expect(ops.indexOf(bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY)).to.equal(-1);
		const csvIdx = ops.indexOf(bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY);
		expect(csvIdx).to.be.greaterThan(0);
		// The CSV number is max(to_self_delay, lease_csv) = 4032.
		expect(bitcoin.script.number.decode(ops[csvIdx - 1] as Buffer)).to.equal(
			Math.max(toSelfDelay, leaseCsv)
		);
	});

	it('the CSV number is max(to_self_delay, lease_csv)', function () {
		// A lease shorter than the delay keeps the delay.
		const shortLease = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			2016,
			144
		);
		const ops = bitcoin.script.decompile(shortLease)!;
		const csvIdx = ops.indexOf(bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY);
		expect(bitcoin.script.number.decode(ops[csvIdx - 1] as Buffer)).to.equal(
			2016
		);
	});

	it('exactly matches CLN bitcoin_wscript_to_local', function () {
		const leased = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay,
			leaseCsv
		);
		const expected = bitcoin.script.compile([
			bitcoin.opcodes.OP_IF,
			revocationPubkey,
			bitcoin.opcodes.OP_ELSE,
			bitcoin.script.number.encode(Math.max(toSelfDelay, leaseCsv)),
			bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
			bitcoin.opcodes.OP_DROP,
			delayedPubkey,
			bitcoin.opcodes.OP_ENDIF,
			bitcoin.opcodes.OP_CHECKSIG
		]);
		expect(leased.equals(expected)).to.be.true;
	});

	it('the lessor sweep sets input sequence = the lease CSV, no nLockTime', function () {
		const witnessScript = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay,
			leaseCsv
		);
		const csv = Math.max(toSelfDelay, leaseCsv);
		const tx = buildToLocalSweepTx({
			commitmentTxid: crypto.randomBytes(32).toString('hex'),
			outputIndex: 0,
			amount: 100_000n,
			witnessScript,
			toSelfDelay: csv, // caller passes the effective CSV
			destinationScript: bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!,
			feeSatoshis: 500n
		});
		// Pure CSV: no nLockTime, input sequence is the CSV.
		expect(tx.locktime).to.equal(0);
		expect(tx.ins[0].sequence).to.equal(csv);
		const witness = buildToLocalDelayedWitness(
			crypto.randomBytes(72),
			witnessScript
		);
		expect(witness[witness.length - 1].equals(witnessScript)).to.be.true;
	});

	it('second-level HTLC outputs are NEVER lease-locked (CLN)', function () {
		// buildHtlcOutputScript has no lease param; a lessor HTLC-success tx
		// output equals the plain second-level output.
		const plain = buildHtlcOutputScript(revocationPubkey, delayedPubkey, 144);
		const ops = bitcoin.script.decompile(plain)!;
		expect(ops.indexOf(bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY)).to.equal(-1);

		const tx = buildHtlcSuccessTx(
			crypto.randomBytes(32).toString('hex'),
			0,
			100_000n,
			revocationPubkey,
			delayedPubkey,
			144,
			500n,
			false
		);
		const expected = bitcoin.payments.p2wsh({
			redeem: { output: plain }
		}).output!;
		expect(tx.outs[0].script.equals(expected)).to.be.true;
	});

	it('a non-leased sweep keeps input sequence = to_self_delay and no nLockTime', function () {
		const witnessScript = buildToLocalScript(
			revocationPubkey,
			delayedPubkey,
			toSelfDelay
		);
		const tx = buildToLocalSweepTx({
			commitmentTxid: crypto.randomBytes(32).toString('hex'),
			outputIndex: 0,
			amount: 100_000n,
			witnessScript,
			toSelfDelay,
			destinationScript: bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!,
			feeSatoshis: 500n
		});
		expect(tx.locktime).to.equal(0);
		expect(tx.ins[0].sequence).to.equal(toSelfDelay);
	});
});
