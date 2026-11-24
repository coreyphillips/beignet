import { expect } from 'chai';
import { crypto, Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../../src/utils/ecc';
import { calculateCommitmentFee } from '../../../src/lightning/channel/commitment-builder';
import {
	startCommitmentSigningSession,
	taprootCommitmentSighash,
	verifyPartialCommitmentSig
} from '../../../src/lightning/channel/commitment-musig';
import { ANCHOR_TOTAL_COST } from '../../../src/lightning/script/anchor';
import {
	type IHtlcOutput,
	buildCommitmentTx,
	calculateObscuredCommitmentNumber
} from '../../../src/lightning/script/commitment';
import {
	type ITaprootLeafSpend,
	buildTaprootAnchorOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput
} from '../../../src/lightning/script/commitment-taproot';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import {
	buildTaprootHtlcSuccessTx,
	buildTaprootHtlcTimeoutTx,
	tapleafHash,
	taprootHtlcLeafSighash
} from '../../../src/lightning/script/htlc-taproot';
import { hexToBuffer as hex } from './helpers';
import scripts from './vectors/bolt03/simple-taproot-scripts.json';
import vectors from './vectors/bolt03/simple-taproot-transactions.json';

// Public transaction data from Eclair v0.14.0, as consumed by TestVectorsSpec.scala.
// https://github.com/ACINQ/eclair/blob/ec8c63b215b98148887237e3f050342a6ca61f4c/eclair-core/src/test/resources/bolt3-tx-test-vectors-simple-taproot-commitment-format.json
// Upstream SHA-256 f0ff6d1f6b646b875ca4922da297a2fa7da86ed6857b1450f56788c42ea5a16e.
// These three signed transactions also match the pinned BOLT script fixture's source.
const params = scripts.keys;
const localFunding = hex(params.local_funding_pubkey);
const remoteFunding = hex(params.remote_funding_pubkey);
const delayed = hex(params.derived_local_delayed_pubkey);
const payment = hex(params.derived_remote_payment_pubkey);
const revocation = hex(params.derived_revocation_pubkey);
const localHtlc = hex(params.derived_local_htlc_pubkey);
const remoteHtlc = hex(params.derived_remote_htlc_pubkey);
const delay = scripts.csv_delay;
const fundingTx = Transaction.fromHex(vectors.funding_tx_hex);
const funding = createTaprootFundingScript(localFunding, remoteFunding);
const obscured = calculateObscuredCommitmentNumber(
	hex(vectors.local_payment_basepoint),
	hex(vectors.remote_payment_basepoint),
	BigInt(vectors.commit_height)
);

type Htlc = NonNullable<(typeof vectors.transactions)[number]['htlcs']>[number];

function htlcOutput(
	htlc: Htlc
): IHtlcOutput & { htlc: Htlc; leaf: ITaprootLeafSpend } {
	const paymentHash = crypto.sha256(hex(htlc.preimage));
	const keys = [revocation, localHtlc, remoteHtlc, paymentHash] as const;
	const tree = htlc.incoming
		? buildTaprootReceivedHtlcOutput(...keys, htlc.expiry, undefined, 'final')
		: buildTaprootOfferedHtlcOutput(...keys, undefined, 'final');
	return {
		htlc,
		paymentHash,
		amount: BigInt(htlc.amount_msat) / 1000n,
		cltvExpiry: htlc.expiry,
		script: tree.output,
		taprootScript: tree.output,
		leaf: htlc.incoming ? tree.success : tree.timeout
	};
}

describe('BOLT 3 final Taproot commitment and HTLC transactions', () => {
	for (const vector of vectors.transactions) {
		it(vector.name, () => {
			const expected = Transaction.fromHex(vector.expected_commitment_tx_hex);
			const dust = BigInt(
				vector.dust_limit_satoshis ?? vectors.dust_limit_satoshis
			);
			const htlcOutputs = (vector.htlcs ?? []).map(htlcOutput);
			const count = htlcOutputs.filter(
				(output) => output.amount >= dust
			).length;
			const fee = calculateCommitmentFee(vector.fee_per_kw, count, true, true);
			const { tx, outputMap } = buildCommitmentTx({
				fundingTxid: fundingTx.getHash().toString('hex'),
				fundingOutputIndex: 0,
				fundingAmount: BigInt(fundingTx.outs[0].value),
				obscuredCommitmentNumber: obscured,
				localAmount:
					BigInt(vector.local_balance_msat) / 1000n - fee - ANCHOR_TOTAL_COST,
				remoteAmount: BigInt(vector.remote_balance_msat) / 1000n,
				toSelfDelay: delay,
				revocationPubkey: revocation,
				localDelayedPubkey: delayed,
				remotePaymentPubkey: payment,
				localFundingPubkey: localFunding,
				remoteFundingPubkey: remoteFunding,
				useAnchors: true,
				dustLimitSatoshis: dust,
				htlcOutputs,
				taprootToLocalScript: buildTaprootToLocalOutput(
					revocation,
					delayed,
					delay,
					undefined,
					'final'
				).output,
				taprootToRemoteScript: buildTaprootToRemoteOutput(
					payment,
					undefined,
					'final'
				).output,
				taprootAnchorLocalScript: buildTaprootAnchorOutput(delayed).output,
				taprootAnchorRemoteScript: buildTaprootAnchorOutput(payment).output
			});

			expect(funding.p2trOutput).to.deep.equal(fundingTx.outs[0].script);
			expect(tx.getId()).to.equal(expected.getId());
			const digest = taprootCommitmentSighash(
				tx,
				funding.p2trOutput,
				fundingTx.outs[0].value
			);
			const remoteNonce = hex(vector.remote_nonce);
			const session = startCommitmentSigningSession(
				digest,
				localFunding,
				remoteFunding,
				hex(vector.local_nonce),
				remoteNonce
			);
			expect(
				verifyPartialCommitmentSig(
					session,
					hex(vector.remote_partial_sig),
					remoteFunding,
					remoteNonce
				)
			).to.equal(true);
			const [aggregateSignature] = expected.ins[0].witness;
			expect(
				ecc.verifySchnorr(digest, funding.outputKey, aggregateSignature)
			).to.equal(true);
			tx.setWitness(0, [aggregateSignature]);
			expect(tx.toHex()).to.equal(vector.expected_commitment_tx_hex);

			const resolutions = vector.htlc_descs ?? [];
			expect(outputMap.htlcs).to.have.length(resolutions.length);
			for (const [i, desc] of resolutions.entries()) {
				const index = outputMap.htlcs[i];
				const { htlc, amount, leaf } =
					htlcOutputs[outputMap.htlcOriginalIndices[i]];
				const input = [tx.getId(), index, amount] as const;
				const output = [
					revocation,
					delayed,
					delay,
					undefined,
					'final'
				] as const;
				const child = htlc.incoming
					? buildTaprootHtlcSuccessTx(...input, ...output)
					: buildTaprootHtlcTimeoutTx(...input, htlc.expiry, ...output);
				const [remoteSig, localSig] = Transaction.fromHex(
					desc.resolution_tx_hex
				).ins[0].witness;
				expect(remoteSig).to.deep.equal(
					Buffer.concat([hex(desc.remote_partial_sig_hex), Buffer.of(0x83)])
				);
				expect(localSig).to.have.length(64);
				const prevout = tx.outs[index];
				const remoteDigest = taprootHtlcLeafSighash(
					child,
					prevout.script,
					prevout.value,
					leaf.script
				);
				const localDigest = child.hashForWitnessV1(
					0,
					[prevout.script],
					[prevout.value],
					Transaction.SIGHASH_DEFAULT,
					tapleafHash(leaf.script)
				);
				expect(
					ecc.verifySchnorr(
						remoteDigest,
						remoteHtlc.subarray(1),
						remoteSig.subarray(0, 64)
					)
				).to.equal(true);
				expect(
					ecc.verifySchnorr(localDigest, localHtlc.subarray(1), localSig)
				).to.equal(true);
				const preimage = htlc.incoming ? [hex(htlc.preimage)] : [];
				child.setWitness(0, [
					remoteSig,
					localSig,
					...preimage,
					leaf.script,
					leaf.controlBlock
				]);
				expect(child.toHex()).to.equal(desc.resolution_tx_hex);
			}
		});
	}
});
