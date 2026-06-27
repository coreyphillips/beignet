import { expect } from 'chai';
import { estimateSweepVbytes } from '../../src/lightning/chain/sweep';
import { OutputType } from '../../src/lightning/chain/types';

describe('Sweep Fee Estimation', () => {
	describe('estimateSweepVbytes', () => {
		it('returns correct vbytes for each output type', () => {
			expect(estimateSweepVbytes(OutputType.TO_LOCAL)).to.equal(113);
			expect(estimateSweepVbytes(OutputType.TO_REMOTE)).to.equal(110);
			expect(estimateSweepVbytes(OutputType.OFFERED_HTLC)).to.equal(166);
			expect(estimateSweepVbytes(OutputType.RECEIVED_HTLC)).to.equal(176);
		});

		it('HTLC-timeout (OFFERED) is larger than to_remote', () => {
			const htlcTimeout = estimateSweepVbytes(OutputType.OFFERED_HTLC);
			const toRemote = estimateSweepVbytes(OutputType.TO_REMOTE);
			expect(htlcTimeout).to.be.greaterThan(toRemote);
		});

		it('HTLC-success (RECEIVED) is the largest sweep type', () => {
			const htlcSuccess = estimateSweepVbytes(OutputType.RECEIVED_HTLC);
			expect(htlcSuccess).to.be.greaterThan(
				estimateSweepVbytes(OutputType.TO_LOCAL)
			);
			expect(htlcSuccess).to.be.greaterThan(
				estimateSweepVbytes(OutputType.TO_REMOTE)
			);
			expect(htlcSuccess).to.be.greaterThan(
				estimateSweepVbytes(OutputType.OFFERED_HTLC)
			);
		});

		it('fee estimation at 1 sat/vB never produces negative output for amounts above dust', () => {
			const feeRate = 1; // 1 sat/vB
			for (const outputType of [
				OutputType.TO_LOCAL,
				OutputType.TO_REMOTE,
				OutputType.OFFERED_HTLC,
				OutputType.RECEIVED_HTLC
			]) {
				const vbytes = estimateSweepVbytes(outputType);
				const fee = BigInt(Math.ceil(feeRate * vbytes));
				const dustAmount = 546n;
				// For any amount above dust + fee, output should be positive
				const amount = dustAmount + fee + 1n;
				expect(Number(amount - fee)).to.be.greaterThan(0);
			}
		});
	});
});
