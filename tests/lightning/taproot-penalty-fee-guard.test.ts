/**
 * Regression: the taproot penalty (justice) builder must not hand bitcoinjs a
 * negative output value when the fee exceeds what the batch is worth.
 *
 * buildAndSignPenalty summed its input values into a JavaScript `number`, the
 * only aggregate on-chain amount in the file not kept in bigint, and it was
 * also the only one with no `totalIn > fee` check. `addOutput` typeforces a
 * non-negative Satoshi, so an unaffordable batch threw.
 *
 * The deadline split makes that worse than a single lost sweep: an HTLC input
 * near its cltv_expiry gets its OWN penalty tx, so a small, expiring HTLC threw
 * before the batched penalty holding their to_local was ever built. The whole
 * breach remedy went with it.
 */

import { expect } from 'chai';
import { OutputType, ITrackedOutput } from '../../src/lightning/chain/types';
import {
	resolveRevokedCommitmentOutputs,
	IResolvedOutput
} from '../../src/lightning/chain/output-resolver';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { estimatePenaltyTxFee } from '../../src/lightning/script/revocation';
import {
	NETWORK,
	privAt,
	revokedTaprootSetup,
	trackedFor,
	emptyRevokedTx
} from './helpers/taproot-revoked-fixture';

const CURRENT_HEIGHT = 700;

function resolve(
	state: IChannelState,
	aliceSeed: Buffer,
	destScript: Buffer,
	tracked: ITrackedOutput[],
	feeRatePerVbyte: number
): IResolvedOutput[] {
	return resolveRevokedCommitmentOutputs(
		state,
		tracked,
		1n,
		emptyRevokedTx(),
		destScript,
		feeRatePerVbyte,
		privAt(aliceSeed, 1), // revocation basepoint secret
		privAt(aliceSeed, 2), // payment privkey
		NETWORK,
		CURRENT_HEIGHT
	);
}

describe('taproot penalty fee guard', function () {
	this.timeout(20_000);

	it('does not throw when the fee exceeds the whole batch', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		expect(() => {
			resolve(
				state,
				aliceSeed,
				destScript,
				trackedFor(50_000n, 20_000n),
				100_000 // ruinous feerate
			);
		}, 'an unaffordable penalty batch must not throw').to.not.throw();
	});

	it('builds the penalty at an affordable feerate', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		const resolved = resolve(
			state,
			aliceSeed,
			destScript,
			trackedFor(1_000_000n, 400_000n),
			5
		);

		expect(resolved.length, 'both penalty inputs resolved').to.equal(2);
		for (const r of resolved) {
			expect(r.spendTx, 'each input has a penalty spend').to.exist;
			expect(
				r.spendTx!.outs[0].value,
				'the penalty output is positive'
			).to.be.greaterThan(0);
		}
	});

	it('an unaffordable expiring HTLC no longer takes the to_local penalty with it', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		// The HTLC is near expiry so the deadline split gives it its own penalty
		// tx, and it is far too small to pay for one. Their to_local is large and
		// is what the batched penalty must still claim.
		const tracked = trackedFor(2_000_000n, 300n);

		const resolved = resolve(state, aliceSeed, destScript, tracked, 50);

		const toLocal = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.TO_LOCAL
		);
		expect(
			toLocal,
			'the batched to_local penalty was still built, which is what the throw prevented'
		).to.exist;
		expect(toLocal!.spendTx, 'and it carries a real spend').to.exist;

		const htlc = resolved.find(
			(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
		);
		// Reported as declined (tracked, no spend) rather than dropped silently, so
		// the caller can retry it once fees fall.
		expect(htlc?.spendTx, 'the unaffordable HTLC produced no penalty').to.equal(
			undefined
		);
	});

	it('skips an unaffordable batch entirely rather than building a dust penalty', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		// Both inputs together cannot cover the fee.
		const resolved = resolve(
			state,
			aliceSeed,
			destScript,
			trackedFor(400n, 300n, CURRENT_HEIGHT + 5000),
			50
		);

		// Both inputs come back reported as declined, and neither carries a spend:
		// nothing unbroadcastable is produced, and the caller can still retry them.
		expect(resolved, 'both inputs are reported').to.have.length(2);
		for (const r of resolved) {
			expect(r.spendTx, 'with no spend built').to.equal(undefined);
		}
	});

	it('accumulates every input of a batched penalty into one output', function () {
		const { state, aliceSeed, destScript } = revokedTaprootSetup();

		// A far-off expiry keeps the HTLC out of the urgent split, so both inputs
		// share one penalty tx and the accumulator is exercised across them.
		const resolved = resolve(
			state,
			aliceSeed,
			destScript,
			trackedFor(1_000_000n, 400_000n, CURRENT_HEIGHT + 5000),
			5
		);

		expect(resolved.length, 'both inputs resolved').to.equal(2);
		const tx = resolved[0].spendTx!;
		expect(
			resolved[1].spendTx,
			'both share the same batched penalty tx'
		).to.equal(tx);
		expect(tx.ins.length, 'the batch spends both outputs').to.equal(2);

		const totalIn = 1_000_000 + 400_000;
		expect(
			tx.outs[0].value,
			'the output is the SUM of both inputs minus the fee, not just one'
		).to.be.greaterThan(totalIn - 50_000);
		expect(tx.outs[0].value, 'and it does pay a fee').to.be.lessThan(totalIn);

		// The estimate exists to clear min-relay, so check that property against
		// the serialized size rather than settling for "some fee was deducted".
		// The tx is fully witnessed at this point, so virtualSize is the real one.
		const actualFee = totalIn - tx.outs[0].value;
		const requiredFee = Math.ceil(tx.virtualSize() * 5);
		expect(
			actualFee,
			'the fee covers the requested rate at the tx it actually produced'
		).to.be.at.least(requiredFee);
	});

	it('returns a whole-satoshi fee for a fractional feerate', function () {
		// estimatePenaltyTxFee is exported and takes an arbitrary number.
		// Rounding vbytes before applying the rate left a fractional fee, which
		// the witness-v0 affordability check cannot convert to bigint. Assert on
		// the estimator directly so the case does not depend on whether a
		// particular batch happens to have an even vbyte count.
		const witnessScripts = new Map<number, Buffer>([
			[0, Buffer.alloc(83)],
			[1, Buffer.alloc(139)]
		]);

		for (const rate of [0.3, 1.7, 2.5, 3.33]) {
			const fee = estimatePenaltyTxFee([0, 1], witnessScripts, rate);
			expect(
				Number.isInteger(fee),
				`fee for ${rate} sat/vB is a whole number of satoshis`
			).to.equal(true);
			expect(
				() => BigInt(fee),
				`BigInt(${fee}) is representable`
			).to.not.throw();
		}
	});

	it('prices a larger destination script into the fee', function () {
		const witnessScripts = new Map<number, Buffer>([[0, Buffer.alloc(83)]]);
		const p2wpkh = Buffer.alloc(22);
		const p2tr = Buffer.alloc(34);

		const feeP2wpkh = estimatePenaltyTxFee([0], witnessScripts, 10, p2wpkh);
		const feeP2tr = estimatePenaltyTxFee([0], witnessScripts, 10, p2tr);

		// 12 extra script bytes at 10 sat/vB.
		expect(feeP2tr - feeP2wpkh).to.equal(120);
		expect(
			estimatePenaltyTxFee([0], witnessScripts, 10),
			'omitting the script keeps the P2WPKH default'
		).to.equal(feeP2wpkh);
	});
});
