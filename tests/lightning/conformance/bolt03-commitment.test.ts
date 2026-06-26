/**
 * BOLT 3 Appendix C: Commitment & HTLC Transaction Test Vectors (non-anchor).
 *
 * Asserts the signing-independent, byte-exact primitives the spec fixes:
 *   - funding witness script
 *   - commitment-number obscuring (into locktime + input sequence)
 *   - to_local witness script
 *   - offered / received HTLC witness scripts
 *   - the full unsigned commitment-tx structure (version, input, ordered
 *     outputs with exact values + scripts) for the no-HTLC case
 *
 * The spec's `output commit_tx` is fully signed; signatures (RFC6979 over a
 * 2-of-2 multisig) are out of scope here, so the structural check compares
 * everything except the witness stack.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { createFundingScript } from '../../../src/lightning/script/funding';
import {
	buildCommitmentTx,
	buildToLocalScript,
	calculateObscuredCommitmentNumber
} from '../../../src/lightning/script/commitment';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript
} from '../../../src/lightning/script/htlc';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IHtlcScriptCase {
	name: string;
	direction: 'offered' | 'received';
	preimage: string;
	cltv_expiry?: number;
	wscript: string;
}

interface ICommitmentVectors {
	keys: {
		funding_txid_internal: string;
		funding_output_index: number;
		funding_amount_satoshi: number;
		commitment_number: number;
		obscuring_factor: string;
		local_delay: number;
		local_funding_pubkey: string;
		remote_funding_pubkey: string;
		funding_wscript: string;
		local_payment_basepoint: string;
		remote_payment_basepoint: string;
		local_htlcpubkey: string;
		remote_htlcpubkey: string;
		local_delayedpubkey: string;
		local_revocation_pubkey: string;
		to_remote_pubkey: string;
		to_local_wscript: string;
	};
	htlc_scripts: IHtlcScriptCase[];
	no_htlc_commitment: {
		to_local_amount: number;
		to_remote_amount: number;
		output_commit_tx: string;
	};
}

const v = loadVectors<ICommitmentVectors>('bolt03/commitment.json');
const k = v.keys;
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

describe('BOLT 3 Appendix C: commitment & HTLC script conformance', function () {
	it('funding witness script', function () {
		const { witnessScript } = createFundingScript(
			hexToBuffer(k.local_funding_pubkey),
			hexToBuffer(k.remote_funding_pubkey)
		);
		expect(bufferToHex(witnessScript)).to.equal(k.funding_wscript);
	});

	it('obscured commitment number (factor XOR number)', function () {
		const obscured = calculateObscuredCommitmentNumber(
			hexToBuffer(k.local_payment_basepoint),
			hexToBuffer(k.remote_payment_basepoint),
			BigInt(k.commitment_number)
		);
		const expected =
			BigInt('0x' + k.obscuring_factor) ^ BigInt(k.commitment_number);
		expect(obscured).to.equal(expected);
	});

	it('to_local witness script', function () {
		const script = buildToLocalScript(
			hexToBuffer(k.local_revocation_pubkey),
			hexToBuffer(k.local_delayedpubkey),
			k.local_delay
		);
		expect(bufferToHex(script)).to.equal(k.to_local_wscript);
	});

	for (const tc of v.htlc_scripts) {
		it(`${tc.name} witness script`, function () {
			const paymentHash = sha256(hexToBuffer(tc.preimage));
			const script =
				tc.direction === 'offered'
					? buildOfferedHtlcScript(
							hexToBuffer(k.local_revocation_pubkey),
							hexToBuffer(k.local_htlcpubkey),
							hexToBuffer(k.remote_htlcpubkey),
							paymentHash,
							false
					  )
					: buildReceivedHtlcScript(
							hexToBuffer(k.local_revocation_pubkey),
							hexToBuffer(k.local_htlcpubkey),
							hexToBuffer(k.remote_htlcpubkey),
							paymentHash,
							tc.cltv_expiry!,
							false
					  );
			expect(bufferToHex(script)).to.equal(tc.wscript);
		});
	}

	it('no-HTLC commitment tx structure (unsigned, vs spec signed tx)', function () {
		const obscured = calculateObscuredCommitmentNumber(
			hexToBuffer(k.local_payment_basepoint),
			hexToBuffer(k.remote_payment_basepoint),
			BigInt(k.commitment_number)
		);

		const { tx } = buildCommitmentTx({
			fundingTxid: k.funding_txid_internal,
			fundingOutputIndex: k.funding_output_index,
			fundingAmount: BigInt(k.funding_amount_satoshi),
			obscuredCommitmentNumber: obscured,
			localAmount: BigInt(v.no_htlc_commitment.to_local_amount),
			remoteAmount: BigInt(v.no_htlc_commitment.to_remote_amount),
			revocationPubkey: hexToBuffer(k.local_revocation_pubkey),
			localDelayedPubkey: hexToBuffer(k.local_delayedpubkey),
			toSelfDelay: k.local_delay,
			remotePaymentPubkey: hexToBuffer(k.to_remote_pubkey),
			useAnchors: false
		});

		const spec = bitcoin.Transaction.fromHex(
			v.no_htlc_commitment.output_commit_tx
		);

		// Version + locktime (locktime encodes the lower bits of the obscured number)
		expect(tx.version).to.equal(spec.version);
		expect(tx.locktime).to.equal(spec.locktime);

		// Single funding input with the obscured sequence + correct prevout
		expect(tx.ins.length).to.equal(1);
		expect(spec.ins.length).to.equal(1);
		expect(bufferToHex(tx.ins[0].hash)).to.equal(bufferToHex(spec.ins[0].hash));
		expect(tx.ins[0].index).to.equal(spec.ins[0].index);
		expect(tx.ins[0].sequence).to.equal(spec.ins[0].sequence);

		// Ordered outputs: exact values + scriptPubKeys (to_local, to_remote)
		expect(tx.outs.length).to.equal(spec.outs.length);
		for (let i = 0; i < spec.outs.length; i++) {
			expect(tx.outs[i].value, `output ${i} value`).to.equal(spec.outs[i].value);
			expect(bufferToHex(tx.outs[i].script), `output ${i} script`).to.equal(
				bufferToHex(spec.outs[i].script)
			);
		}
	});
});
