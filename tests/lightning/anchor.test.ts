/**
 * Phase 6: Anchor output tests.
 *
 * Verifies:
 * - Anchor script construction
 * - to_remote anchor script (P2WSH with 1-block CSV)
 * - Commitment tx with anchors has 2 extra 330-sat outputs
 * - to_remote is P2WSH (not P2WPKH) when anchors active
 * - HTLC txs have zero fee when anchor mode active
 * - Non-anchor mode unaffected (backward compat)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	buildAnchorScript,
	buildToRemoteAnchorScript,
	buildAnchorOutput,
	buildToRemoteAnchorOutput,
	ANCHOR_OUTPUT_VALUE,
	ANCHOR_TOTAL_COST
} from '../../src/lightning/script/anchor';
import {
	buildCommitmentTx,
	calculateObscuredCommitmentNumber
} from '../../src/lightning/script/commitment';
import {
	buildHtlcSuccessTx,
	buildHtlcTimeoutTx
} from '../../src/lightning/script/htlc';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

bitcoin.initEccLib(ecc);

function makeKeys(): { privkey: Buffer; pubkey: Buffer } {
	const privkey = crypto.randomBytes(32);
	return { privkey, pubkey: getPublicKey(privkey) };
}

describe('Phase 6: Anchor Outputs', () => {
	describe('Anchor script', () => {
		it('should build a valid anchor script', () => {
			const { pubkey } = makeKeys();
			const script = buildAnchorScript(pubkey);

			expect(script).to.be.an.instanceOf(Buffer);
			expect(script.length).to.be.greaterThan(0);

			// Script should contain the pubkey
			expect(script.includes(pubkey)).to.be.true;
			// Script should contain OP_CHECKSIG (0xac)
			expect(script.includes(Buffer.from([0xac]))).to.be.true;
			// Script should contain OP_CHECKSEQUENCEVERIFY (0xb2)
			expect(script.includes(Buffer.from([0xb2]))).to.be.true;
		});

		it('should produce different scripts for different pubkeys', () => {
			const { pubkey: pk1 } = makeKeys();
			const { pubkey: pk2 } = makeKeys();

			const script1 = buildAnchorScript(pk1);
			const script2 = buildAnchorScript(pk2);

			expect(script1.equals(script2)).to.be.false;
		});

		it('should build a valid P2WSH anchor output', () => {
			const { pubkey } = makeKeys();
			const { script, witnessScript } = buildAnchorOutput(pubkey);

			// Output script should be P2WSH (34 bytes: OP_0 <32-byte hash>)
			expect(script).to.have.lengthOf(34);
			expect(script[0]).to.equal(0x00); // OP_0
			expect(script[1]).to.equal(0x20); // 32-byte push

			// Verify P2WSH: SHA256(witnessScript) matches the hash in the output
			const hash = crypto.createHash('sha256').update(witnessScript).digest();
			expect(script.subarray(2).equals(hash)).to.be.true;
		});
	});

	describe('to_remote anchor script', () => {
		it('should build a P2WSH to_remote script with 1-block CSV', () => {
			const { pubkey } = makeKeys();
			const script = buildToRemoteAnchorScript(pubkey);

			expect(script).to.be.an.instanceOf(Buffer);
			expect(script.length).to.be.greaterThan(0);

			// Should contain the pubkey
			expect(script.includes(pubkey)).to.be.true;
			// Should contain OP_CHECKSIGVERIFY (0xad)
			expect(script.includes(Buffer.from([0xad]))).to.be.true;
			// Should contain OP_CHECKSEQUENCEVERIFY (0xb2)
			expect(script.includes(Buffer.from([0xb2]))).to.be.true;
		});

		it('should produce a P2WSH output', () => {
			const { pubkey } = makeKeys();
			const { script, witnessScript } = buildToRemoteAnchorOutput(pubkey);

			// Output should be P2WSH
			expect(script).to.have.lengthOf(34);
			expect(script[0]).to.equal(0x00);
			expect(script[1]).to.equal(0x20);

			const hash = crypto.createHash('sha256').update(witnessScript).digest();
			expect(script.subarray(2).equals(hash)).to.be.true;
		});
	});

	describe('Constants', () => {
		it('should define ANCHOR_OUTPUT_VALUE as 330', () => {
			expect(Number(ANCHOR_OUTPUT_VALUE)).to.equal(330);
		});

		it('should define ANCHOR_TOTAL_COST as 660', () => {
			expect(Number(ANCHOR_TOTAL_COST)).to.equal(660);
		});
	});

	describe('Commitment tx with anchors', () => {
		const local = makeKeys();
		const remote = makeKeys();
		const revocation = makeKeys();
		const localDelayed = makeKeys();

		const baseParams = {
			fundingTxid: crypto.randomBytes(32).toString('hex'),
			fundingOutputIndex: 0,
			fundingAmount: 1_000_000n,
			obscuredCommitmentNumber: calculateObscuredCommitmentNumber(
				local.pubkey,
				remote.pubkey,
				0n
			),
			localAmount: 500_000n,
			revocationPubkey: revocation.pubkey,
			localDelayedPubkey: localDelayed.pubkey,
			toSelfDelay: 144,
			remoteAmount: 499_340n, // 500_000 - 660 (anchor cost from opener)
			remotePaymentPubkey: remote.pubkey
		};

		it('should have 2 extra anchor outputs when useAnchors=true', () => {
			const withAnchors = buildCommitmentTx({
				...baseParams,
				useAnchors: true,
				localFundingPubkey: local.pubkey,
				remoteFundingPubkey: remote.pubkey
			});

			const withoutAnchors = buildCommitmentTx({
				...baseParams,
				useAnchors: false
			});

			// Should have 2 more outputs (local anchor + remote anchor)
			expect(withAnchors.tx.outs.length).to.equal(
				withoutAnchors.tx.outs.length + 2
			);
		});

		it('should have anchor outputs with 330 satoshi value', () => {
			const result = buildCommitmentTx({
				...baseParams,
				useAnchors: true,
				localFundingPubkey: local.pubkey,
				remoteFundingPubkey: remote.pubkey
			});

			expect(result.outputMap.anchorLocal).to.not.be.undefined;
			expect(result.outputMap.anchorRemote).to.not.be.undefined;

			const anchorLocalValue =
				result.tx.outs[result.outputMap.anchorLocal!].value;
			const anchorRemoteValue =
				result.tx.outs[result.outputMap.anchorRemote!].value;

			expect(anchorLocalValue).to.equal(330);
			expect(anchorRemoteValue).to.equal(330);
		});

		it('should have P2WSH to_remote output when anchors active', () => {
			const result = buildCommitmentTx({
				...baseParams,
				useAnchors: true,
				localFundingPubkey: local.pubkey,
				remoteFundingPubkey: remote.pubkey
			});

			expect(result.outputMap.toRemote).to.not.be.undefined;
			const toRemoteOutput = result.tx.outs[result.outputMap.toRemote!];

			// P2WSH is 34 bytes: OP_0 <32-byte hash>
			expect(toRemoteOutput.script).to.have.lengthOf(34);
			expect(toRemoteOutput.script[0]).to.equal(0x00);
			expect(toRemoteOutput.script[1]).to.equal(0x20);

			// Should return toRemoteScript
			expect(result.toRemoteScript).to.not.be.undefined;
		});

		it('should have P2WPKH to_remote output when anchors NOT active', () => {
			const result = buildCommitmentTx({
				...baseParams,
				useAnchors: false
			});

			expect(result.outputMap.toRemote).to.not.be.undefined;
			const toRemoteOutput = result.tx.outs[result.outputMap.toRemote!];

			// P2WPKH is 22 bytes: OP_0 <20-byte hash>
			expect(toRemoteOutput.script).to.have.lengthOf(22);
			expect(toRemoteOutput.script[0]).to.equal(0x00);
			expect(toRemoteOutput.script[1]).to.equal(0x14);

			// Should not return toRemoteScript
			expect(result.toRemoteScript).to.be.undefined;
		});

		it('should not have anchor fields when anchors NOT active', () => {
			const result = buildCommitmentTx({
				...baseParams,
				useAnchors: false
			});

			expect(result.outputMap.anchorLocal).to.be.undefined;
			expect(result.outputMap.anchorRemote).to.be.undefined;
		});

		it('should include anchor outputs in BIP 69 sorting', () => {
			const result = buildCommitmentTx({
				...baseParams,
				useAnchors: true,
				localFundingPubkey: local.pubkey,
				remoteFundingPubkey: remote.pubkey
			});

			// Verify outputs are sorted by value (anchors at 330 should be first)
			const values = result.tx.outs.map((o) => o.value);
			for (let i = 0; i < values.length - 1; i++) {
				expect(values[i]).to.be.at.most(values[i + 1]);
			}
		});
	});

	describe('HTLC txs with zero-fee (anchor mode)', () => {
		const revocation = makeKeys();
		const localDelayed = makeKeys();

		it('should have zero fee in HTLC-success tx when zeroFee=true', () => {
			const htlcAmount = 50_000n;
			const fee = 5_000n;

			const txWithFee = buildHtlcSuccessTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				htlcAmount,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				fee
			);

			const txZeroFee = buildHtlcSuccessTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				htlcAmount,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				fee,
				true // zeroFee
			);

			// With fee: output = htlcAmount - fee
			expect(txWithFee.outs[0].value).to.equal(Number(htlcAmount - fee));
			// Zero fee: output = htlcAmount (full amount)
			expect(txZeroFee.outs[0].value).to.equal(Number(htlcAmount));
		});

		it('should have zero fee in HTLC-timeout tx when zeroFee=true', () => {
			const htlcAmount = 50_000n;
			const fee = 5_000n;

			const txWithFee = buildHtlcTimeoutTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				htlcAmount,
				500_000,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				fee
			);

			const txZeroFee = buildHtlcTimeoutTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				htlcAmount,
				500_000,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				fee,
				true // zeroFee
			);

			expect(txWithFee.outs[0].value).to.equal(Number(htlcAmount - fee));
			expect(txZeroFee.outs[0].value).to.equal(Number(htlcAmount));
		});

		it('should use sequence=1 for HTLC-success when zeroFee=true', () => {
			const tx = buildHtlcSuccessTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				50_000n,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				0n,
				true
			);

			expect(tx.ins[0].sequence).to.equal(1);
		});

		it('should use sequence=0 for HTLC-success when zeroFee=false', () => {
			const tx = buildHtlcSuccessTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				50_000n,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				5_000n
			);

			// BOLT 3: HTLC second-level txin sequence is 0 for non-anchor channels
			// (1 only for option_anchors).
			expect(tx.ins[0].sequence).to.equal(0);
		});

		it('should use sequence=1 for HTLC-timeout when zeroFee=true', () => {
			const tx = buildHtlcTimeoutTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				50_000n,
				500_000,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				0n,
				true
			);

			expect(tx.ins[0].sequence).to.equal(1);
		});

		it('should use sequence=0 for HTLC-timeout when zeroFee=false', () => {
			const tx = buildHtlcTimeoutTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				50_000n,
				500_000,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				5_000n
			);

			// BOLT 3: HTLC second-level txin sequence is 0 for non-anchor channels.
			expect(tx.ins[0].sequence).to.equal(0);
		});

		it('should still have correct locktime for HTLC-success (0) with zeroFee', () => {
			const tx = buildHtlcSuccessTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				50_000n,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				0n,
				true
			);

			expect(tx.locktime).to.equal(0);
		});

		it('should still have correct locktime for HTLC-timeout with zeroFee', () => {
			const cltvExpiry = 500_000;
			const tx = buildHtlcTimeoutTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				50_000n,
				cltvExpiry,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				0n,
				true
			);

			expect(tx.locktime).to.equal(cltvExpiry);
		});
	});

	describe('Backward compatibility', () => {
		it('should not affect non-anchor commitment tx structure', () => {
			const remote = makeKeys();
			const revocation = makeKeys();
			const localDelayed = makeKeys();

			const result = buildCommitmentTx({
				fundingTxid: crypto.randomBytes(32).toString('hex'),
				fundingOutputIndex: 0,
				fundingAmount: 1_000_000n,
				obscuredCommitmentNumber: 0n,
				localAmount: 500_000n,
				revocationPubkey: revocation.pubkey,
				localDelayedPubkey: localDelayed.pubkey,
				toSelfDelay: 144,
				remoteAmount: 500_000n,
				remotePaymentPubkey: remote.pubkey
			});

			// Should have exactly 2 outputs (to_local + to_remote)
			expect(result.tx.outs).to.have.lengthOf(2);
			expect(result.outputMap.anchorLocal).to.be.undefined;
			expect(result.outputMap.anchorRemote).to.be.undefined;
		});

		it('should not change HTLC tx behavior without zeroFee param', () => {
			const revocation = makeKeys();
			const localDelayed = makeKeys();

			const tx = buildHtlcSuccessTx(
				crypto.randomBytes(32).toString('hex'),
				0,
				50_000n,
				revocation.pubkey,
				localDelayed.pubkey,
				144,
				5_000n
			);

			// Non-anchor (no zeroFee): BOLT 3 txin sequence is 0
			expect(tx.ins[0].sequence).to.equal(0);
			// Should deduct fee
			expect(tx.outs[0].value).to.equal(45_000);
		});
	});
});
