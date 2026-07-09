/**
 * Fee-estimator sanity clamp: every IFeeEstimator sample that feeds LN
 * operations is capped at MAX_FEE_RATE_SAT_PER_VBYTE and floored to 1 sat/vB,
 * with a structured 'fee'/'estimate_clamped' warning when adjusted.
 * Non-positive samples pass through as the estimator's "unavailable" signal.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	clampFeeRateSatPerVbyte,
	MAX_FEE_RATE_SAT_PER_VBYTE,
	IStructuredLog
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fee-clamp-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(estimatedFee: number): LightningNode {
	const seed = makeSeed(1);
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(101),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		feeEstimator: {
			estimateFee: async (): Promise<number> => estimatedFee
		}
	});
	node.on('node:error', () => {});
	return node;
}

describe('Fee estimator sanity clamp', function () {
	describe('clampFeeRateSatPerVbyte boundaries', function () {
		it('passes sane values through unchanged', function () {
			expect(clampFeeRateSatPerVbyte(1)).to.equal(1);
			expect(clampFeeRateSatPerVbyte(25.5)).to.equal(25.5);
			expect(clampFeeRateSatPerVbyte(MAX_FEE_RATE_SAT_PER_VBYTE)).to.equal(
				MAX_FEE_RATE_SAT_PER_VBYTE
			);
		});

		it('caps values above the maximum', function () {
			expect(clampFeeRateSatPerVbyte(MAX_FEE_RATE_SAT_PER_VBYTE + 1)).to.equal(
				MAX_FEE_RATE_SAT_PER_VBYTE
			);
			expect(clampFeeRateSatPerVbyte(1_000_000)).to.equal(
				MAX_FEE_RATE_SAT_PER_VBYTE
			);
			expect(clampFeeRateSatPerVbyte(Infinity)).to.equal(
				MAX_FEE_RATE_SAT_PER_VBYTE
			);
		});

		it('floors positive sub-1 values to 1', function () {
			expect(clampFeeRateSatPerVbyte(0.4)).to.equal(1);
			expect(clampFeeRateSatPerVbyte(0.999)).to.equal(1);
		});

		it('passes unavailable-signals (<= 0, NaN) through unchanged', function () {
			expect(clampFeeRateSatPerVbyte(-1)).to.equal(-1);
			expect(clampFeeRateSatPerVbyte(0)).to.equal(0);
			expect(Number.isNaN(clampFeeRateSatPerVbyte(NaN))).to.equal(true);
		});

		it('fires the onClamp callback only when adjusted', function () {
			const calls: Array<{ original: number; clamped: number }> = [];
			const record = (original: number, clamped: number): void => {
				calls.push({ original, clamped });
			};
			clampFeeRateSatPerVbyte(10, record);
			expect(calls).to.deep.equal([]);
			clampFeeRateSatPerVbyte(9999, record);
			expect(calls).to.deep.equal([
				{ original: 9999, clamped: MAX_FEE_RATE_SAT_PER_VBYTE }
			]);
		});
	});

	describe('LightningNode integration', function () {
		it('clamps an absurd estimator sample and logs a structured warning', async function () {
			const node = makeNode(1_000_000);
			const logs: IStructuredLog[] = [];
			node.on('log', (log: IStructuredLog) => logs.push(log));

			await (
				node as unknown as { checkAndUpdateFees(): Promise<void> }
			).checkAndUpdateFees();

			const clampLog = logs.find(
				(l) => l.category === 'fee' && l.action === 'estimate_clamped'
			);
			expect(clampLog).to.exist;
			expect(clampLog!.data.original).to.equal(1_000_000);
			expect(clampLog!.data.clamped).to.equal(MAX_FEE_RATE_SAT_PER_VBYTE);
			// The advisor's live rate reflects the clamped sample, not the raw one.
			expect(
				(
					node as unknown as {
						feeAdvisor: { getCurrentRate(): number };
					}
				).feeAdvisor.getCurrentRate()
			).to.equal(MAX_FEE_RATE_SAT_PER_VBYTE);
			node.destroy();
		});

		it('floors a fractional estimator sample to 1 sat/vB', async function () {
			const node = makeNode(0.25);
			const logs: IStructuredLog[] = [];
			node.on('log', (log: IStructuredLog) => logs.push(log));

			await (
				node as unknown as { checkAndUpdateFees(): Promise<void> }
			).checkAndUpdateFees();

			const clampLog = logs.find(
				(l) => l.category === 'fee' && l.action === 'estimate_clamped'
			);
			expect(clampLog).to.exist;
			expect(clampLog!.data.clamped).to.equal(1);
			node.destroy();
		});

		it('does not warn for a sane estimator sample', async function () {
			const node = makeNode(12);
			const logs: IStructuredLog[] = [];
			node.on('log', (log: IStructuredLog) => logs.push(log));

			await (
				node as unknown as { checkAndUpdateFees(): Promise<void> }
			).checkAndUpdateFees();

			expect(
				logs.some(
					(l) => l.category === 'fee' && l.action === 'estimate_clamped'
				)
			).to.equal(false);
			node.destroy();
		});
	});
});
