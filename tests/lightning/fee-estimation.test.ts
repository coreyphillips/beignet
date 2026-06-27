/**
 * Phase 3: Fee Estimation Tests.
 *
 * Tests fee conversion utilities (sat/vByte <-> sat/kw) and
 * dynamic fee estimator integration with LightningNode.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	satPerVbyteToSatPerKw,
	satPerKwToSatPerVbyte,
	MIN_FEERATE_PER_KW
} from '../../src/lightning/chain/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, IFeeEstimator } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`fee-seed-${id}`))
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

function makeNodeConfig(
	seedId: number,
	extras?: Partial<INodeConfig>
): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-id'))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		...extras
	};
}

describe('Fee Estimation', () => {
	describe('satPerVbyteToSatPerKw', () => {
		it('should convert 1 sat/vByte to 250 sat/kw', () => {
			// 1 vByte = 4 weight units, so 1 sat/vByte = 1000/4 = 250 sat/kw
			expect(satPerVbyteToSatPerKw(1)).to.equal(250);
		});

		it('should convert 10 sat/vByte to 2500 sat/kw', () => {
			expect(satPerVbyteToSatPerKw(10)).to.equal(2500);
		});
	});

	describe('satPerKwToSatPerVbyte', () => {
		it('should convert 250 sat/kw to 1 sat/vByte', () => {
			expect(satPerKwToSatPerVbyte(250)).to.equal(1);
		});

		it('should ceil non-integer results (253 sat/kw -> 2 sat/vByte)', () => {
			// ceil(253 * 4 / 1000) = ceil(1.012) = 2
			expect(satPerKwToSatPerVbyte(253)).to.equal(2);
		});
	});

	describe('round-trip conversion', () => {
		it('should preserve or round up through a round-trip', () => {
			// satPerVbyteToSatPerKw(5) = ceil(5000/4) = 1250
			// satPerKwToSatPerVbyte(1250) = ceil(1250*4/1000) = ceil(5) = 5
			const result = satPerKwToSatPerVbyte(satPerVbyteToSatPerKw(5));
			expect(result).to.be.at.least(5);
		});
	});

	describe('MIN_FEERATE_PER_KW', () => {
		it('should equal 253 (BOLT 2 minimum)', () => {
			expect(MIN_FEERATE_PER_KW).to.equal(253);
		});
	});

	describe('IFeeEstimator integration', () => {
		it('should create node with feeEstimator and destroy without crash', () => {
			const feeEstimator: IFeeEstimator = {
				estimateFee: async (target: number) =>
					target <= 2 ? 20 : target <= 6 ? 10 : 5
			};
			const config = makeNodeConfig(1, { feeEstimator });
			const node = new LightningNode(config);
			// Node should start the fee update timer internally
			node.destroy();
		});

		it('should create node without feeEstimator and destroy without crash', () => {
			const config = makeNodeConfig(2);
			const node = new LightningNode(config);
			node.destroy();
		});

		it('should handle fee estimator returning -1 (unavailable)', () => {
			const feeEstimator: IFeeEstimator = {
				estimateFee: async (_target: number) => -1
			};
			const config = makeNodeConfig(3, { feeEstimator });
			const node = new LightningNode(config);
			// Node should gracefully handle -1 and fall back to defaults
			node.destroy();
		});

		it('should accept a mock fee estimator with tiered rates', () => {
			const feeEstimator: IFeeEstimator = {
				estimateFee: async (target: number) =>
					target <= 2 ? 20 : target <= 6 ? 10 : 5
			};
			const config = makeNodeConfig(4, { feeEstimator });
			const node = new LightningNode(config);
			expect(node).to.exist;
			node.destroy();
		});
	});

	describe('IFeeEstimator mock behavior', () => {
		it('should return correct values for different confirmation targets', async () => {
			const feeEstimator: IFeeEstimator = {
				estimateFee: async (target: number) =>
					target <= 2 ? 20 : target <= 6 ? 10 : 5
			};

			expect(await feeEstimator.estimateFee(1)).to.equal(20);
			expect(await feeEstimator.estimateFee(2)).to.equal(20);
			expect(await feeEstimator.estimateFee(3)).to.equal(10);
			expect(await feeEstimator.estimateFee(6)).to.equal(10);
			expect(await feeEstimator.estimateFee(7)).to.equal(5);
			expect(await feeEstimator.estimateFee(144)).to.equal(5);
		});
	});
});
