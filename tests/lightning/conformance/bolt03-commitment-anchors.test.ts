/**
 * BOLT 3 Appendix F: Commitment & HTLC Transaction Test Vectors (anchors).
 *
 * Each case rebuilds the commitment with buildCommitmentTx({useAnchors}) and
 * compares it output-by-output against the spec's signed tx: version,
 * locktime, funding input (obscured sequence), and every output's value and
 * scriptPubKey (anchor outputs, P2WSH 1-CSV to_remote, HTLC outputs, dust
 * trimming per the case's DustLimitSatoshis, and the BOLT 3 cltv tie-break
 * for identical offered-HTLC outputs in the last case).
 *
 * Amount derivation follows the appendix note: LocalBalance/RemoteBalance are
 * balances BEFORE subtracting the commit fee and both anchors (funder =
 * local). fee = FeePerKw * (1124 + 172 * untrimmed_htlcs) / 1000; second
 * stage HTLC txs are zero-fee (option_anchors_zero_fee_htlc_tx, so the HTLC
 * trim threshold is the dust limit alone).
 *
 * Signatures: signing nonces are implementation-specific, but verification is
 * deterministic — every RemoteSigHex (SIGHASH_ALL on the commitment, 0x83 =
 * SINGLE|ANYONECANPAY on each HTLC tx) is verified against the BIP-143
 * sighash of the locally rebuilt transaction, proving the remote signatures
 * bind to exactly the transactions beignet constructs.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { createFundingScript } from '../../../src/lightning/script/funding';
import {
	buildCommitmentTx,
	calculateObscuredCommitmentNumber,
	IHtlcOutput
} from '../../../src/lightning/script/commitment';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript,
	buildHtlcSuccessTx,
	buildHtlcTimeoutTx
} from '../../../src/lightning/script/htlc';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IHtlcDef {
	id: number;
	direction: 'offered' | 'received';
	amount_msat: number;
	expiry: number;
	preimage: string;
}

interface IAnchorCase {
	Name: string;
	LocalBalance: number;
	RemoteBalance: number;
	DustLimitSatoshis: number;
	FeePerKw: number;
	UseTestHtlcs: boolean;
	HtlcDescs: { RemoteSigHex: string; ResolutionTxHex: string }[];
	ExpectedCommitmentTxHex: string;
	RemoteSigHex: string;
	HtlcIds: number[];
}

interface IAnchorVectors {
	setup: {
		funding_txid_internal: string;
		funding_output_index: number;
		funding_amount_satoshi: number;
		commitment_number: number;
		local_delay: number;
		local_funding_pubkey: string;
		remote_funding_pubkey: string;
		local_payment_basepoint: string;
		remote_payment_basepoint: string;
		local_htlcpubkey: string;
		remote_htlcpubkey: string;
		local_delayedpubkey: string;
		local_revocation_pubkey: string;
		to_remote_pubkey: string;
		htlcs: IHtlcDef[];
	};
	cases: IAnchorCase[];
}

const v = loadVectors<IAnchorVectors>('bolt03/commitment-anchors.json');
const s = v.setup;

const ANCHORS_COMMIT_WEIGHT_BASE = 1124n;
const ANCHORS_COMMIT_WEIGHT_PER_HTLC = 172n;
const ANCHOR_VALUE_TOTAL = 660n; // two 330-sat anchors, funded by the funder
const SIGHASH_SINGLE_ANYONECANPAY = 0x83;

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

const fundingWscript = createFundingScript(
	hexToBuffer(s.local_funding_pubkey),
	hexToBuffer(s.remote_funding_pubkey)
).witnessScript;

const obscured = calculateObscuredCommitmentNumber(
	hexToBuffer(s.local_payment_basepoint),
	hexToBuffer(s.remote_payment_basepoint),
	BigInt(s.commitment_number)
);

/** Verify a spec DER signature against a BIP-143 sighash. */
function verifySig(
	sigHex: string,
	hashType: number,
	sighash: Buffer,
	pubkey: Buffer
): boolean {
	const { signature } = bitcoin.script.signature.decode(
		Buffer.concat([hexToBuffer(sigHex), Buffer.of(hashType)])
	);
	return ecc.verify(sighash, pubkey, signature);
}

/** Build the anchors-variant witness script for one of the setup HTLCs. */
function htlcWitnessScript(h: IHtlcDef): Buffer {
	const paymentHash = sha256(hexToBuffer(h.preimage));
	return h.direction === 'offered'
		? buildOfferedHtlcScript(
				hexToBuffer(s.local_revocation_pubkey),
				hexToBuffer(s.local_htlcpubkey),
				hexToBuffer(s.remote_htlcpubkey),
				paymentHash,
				true
		  )
		: buildReceivedHtlcScript(
				hexToBuffer(s.local_revocation_pubkey),
				hexToBuffer(s.local_htlcpubkey),
				hexToBuffer(s.remote_htlcpubkey),
				paymentHash,
				h.expiry,
				true
		  );
}

/** Assert structural equality (everything but witnesses) of two transactions. */
function expectSameStructure(
	tx: bitcoin.Transaction,
	spec: bitcoin.Transaction,
	label: string
): void {
	expect(tx.version, `${label} version`).to.equal(spec.version);
	expect(tx.locktime, `${label} locktime`).to.equal(spec.locktime);
	expect(tx.ins.length, `${label} input count`).to.equal(spec.ins.length);
	for (let i = 0; i < spec.ins.length; i++) {
		expect(bufferToHex(tx.ins[i].hash), `${label} input ${i} hash`).to.equal(
			bufferToHex(spec.ins[i].hash)
		);
		expect(tx.ins[i].index, `${label} input ${i} index`).to.equal(
			spec.ins[i].index
		);
		expect(tx.ins[i].sequence, `${label} input ${i} sequence`).to.equal(
			spec.ins[i].sequence
		);
	}
	expect(tx.outs.length, `${label} output count`).to.equal(spec.outs.length);
	for (let i = 0; i < spec.outs.length; i++) {
		expect(tx.outs[i].value, `${label} output ${i} value`).to.equal(
			spec.outs[i].value
		);
		expect(
			bufferToHex(tx.outs[i].script),
			`${label} output ${i} script`
		).to.equal(bufferToHex(spec.outs[i].script));
	}
}

describe('BOLT 3 Appendix F: anchor commitment conformance', function () {
	for (const c of v.cases) {
		it(`${c.Name}`, function () {
			const dust = BigInt(c.DustLimitSatoshis);
			const activeHtlcs = c.HtlcIds.map(
				(id) => s.htlcs.find((h) => h.id === id) as IHtlcDef
			);
			const htlcOutputs: IHtlcOutput[] = activeHtlcs.map((h) => ({
				script: htlcWitnessScript(h),
				amount: BigInt(h.amount_msat) / 1000n,
				cltvExpiry: h.expiry,
				paymentHash: sha256(hexToBuffer(h.preimage))
			}));

			// Zero-fee second stage: the HTLC trim threshold is the dust limit.
			const untrimmed = htlcOutputs.filter((h) => h.amount >= dust).length;
			const weight =
				ANCHORS_COMMIT_WEIGHT_BASE +
				ANCHORS_COMMIT_WEIGHT_PER_HTLC * BigInt(untrimmed);
			const fee = (BigInt(c.FeePerKw) * weight) / 1000n;
			const localAmount =
				BigInt(c.LocalBalance) / 1000n - fee - ANCHOR_VALUE_TOTAL;
			const remoteAmount = BigInt(c.RemoteBalance) / 1000n;

			const { tx, outputMap } = buildCommitmentTx({
				fundingTxid: s.funding_txid_internal,
				fundingOutputIndex: s.funding_output_index,
				fundingAmount: BigInt(s.funding_amount_satoshi),
				obscuredCommitmentNumber: obscured,
				localAmount,
				remoteAmount,
				revocationPubkey: hexToBuffer(s.local_revocation_pubkey),
				localDelayedPubkey: hexToBuffer(s.local_delayedpubkey),
				toSelfDelay: s.local_delay,
				remotePaymentPubkey: hexToBuffer(s.to_remote_pubkey),
				htlcOutputs,
				dustLimitSatoshis: dust,
				feeRatePerKw: BigInt(c.FeePerKw),
				useAnchors: true,
				localFundingPubkey: hexToBuffer(s.local_funding_pubkey),
				remoteFundingPubkey: hexToBuffer(s.remote_funding_pubkey)
			});

			const spec = bitcoin.Transaction.fromHex(c.ExpectedCommitmentTxHex);
			expectSameStructure(tx, spec, 'commitment');

			// The remote commitment signature must verify against OUR rebuilt
			// tx's BIP-143 sighash (2-of-2 funding witness script).
			const commitSighash = tx.hashForWitnessV0(
				0,
				fundingWscript,
				s.funding_amount_satoshi,
				bitcoin.Transaction.SIGHASH_ALL
			);
			expect(
				verifySig(
					c.RemoteSigHex,
					bitcoin.Transaction.SIGHASH_ALL,
					commitSighash,
					hexToBuffer(s.remote_funding_pubkey)
				),
				'remote commitment signature'
			).to.equal(true);

			// HtlcDescs are ordered by commitment output index; outputMap maps
			// each back to its HTLC definition.
			expect(c.HtlcDescs.length).to.equal(outputMap.htlcs.length);
			const commitTxid = spec.getId();

			for (let n = 0; n < c.HtlcDescs.length; n++) {
				const desc = c.HtlcDescs[n];
				const outputIndex = outputMap.htlcs[n];
				const h = activeHtlcs[outputMap.htlcOriginalIndices[n]];
				const amountSat = BigInt(h.amount_msat) / 1000n;

				const htlcTx =
					h.direction === 'received'
						? buildHtlcSuccessTx(
								commitTxid,
								outputIndex,
								amountSat,
								hexToBuffer(s.local_revocation_pubkey),
								hexToBuffer(s.local_delayedpubkey),
								s.local_delay,
								0n,
								true
						  )
						: buildHtlcTimeoutTx(
								commitTxid,
								outputIndex,
								amountSat,
								h.expiry,
								hexToBuffer(s.local_revocation_pubkey),
								hexToBuffer(s.local_delayedpubkey),
								s.local_delay,
								0n,
								true
						  );

				const specHtlcTx = bitcoin.Transaction.fromHex(desc.ResolutionTxHex);
				expectSameStructure(htlcTx, specHtlcTx, `htlc ${h.id} tx`);

				// Anchors: remote HTLC signatures use SINGLE|ANYONECANPAY over
				// the commitment HTLC output's witness script.
				const htlcSighash = htlcTx.hashForWitnessV0(
					0,
					htlcWitnessScript(h),
					Number(amountSat),
					SIGHASH_SINGLE_ANYONECANPAY
				);
				expect(
					verifySig(
						desc.RemoteSigHex,
						SIGHASH_SINGLE_ANYONECANPAY,
						htlcSighash,
						hexToBuffer(s.remote_htlcpubkey)
					),
					`remote signature for htlc ${h.id}`
				).to.equal(true);
			}
		});
	}
});
