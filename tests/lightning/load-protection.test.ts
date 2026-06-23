import { expect } from 'chai';
import crypto from 'crypto';
import { PeerRateLimiter } from '../../src/lightning/node/rate-limiter';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`load-seed-${id}`))
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

describe('Load Protection — Phase 7', () => {
	describe('PeerRateLimiter unit tests', () => {
		it('should have size 0 when newly created', () => {
			const limiter = new PeerRateLimiter();
			expect(limiter.size).to.equal(0);
		});

		it('should succeed on first tryConsume for a new peer', () => {
			const limiter = new PeerRateLimiter();
			const result = limiter.tryConsume('peer-aaa');
			expect(result).to.be.true;
		});

		it('should increase size after first consume', () => {
			const limiter = new PeerRateLimiter();
			limiter.tryConsume('peer-aaa');
			expect(limiter.size).to.equal(1);
			limiter.tryConsume('peer-bbb');
			expect(limiter.size).to.equal(2);
		});

		it('should allow burst up to maxTokens', () => {
			const limiter = new PeerRateLimiter({
				maxHtlcsPerSecond: 5,
				burstMultiplier: 2
			});
			const peer = 'abc123';
			// maxTokens = 5 * 2 = 10
			for (let i = 0; i < 10; i++) {
				expect(limiter.tryConsume(peer)).to.be.true;
			}
			// 11th should fail (burst exhausted)
			expect(limiter.tryConsume(peer)).to.be.false;
		});

		it('should reject after burst is exhausted (sustained over-rate)', () => {
			const limiter = new PeerRateLimiter({
				maxHtlcsPerSecond: 3,
				burstMultiplier: 1
			});
			const peer = 'overrate-peer';
			// Capacity = 3 * 1 = 3
			expect(limiter.tryConsume(peer)).to.be.true;
			expect(limiter.tryConsume(peer)).to.be.true;
			expect(limiter.tryConsume(peer)).to.be.true;
			// 4th should fail
			expect(limiter.tryConsume(peer)).to.be.false;
			expect(limiter.tryConsume(peer)).to.be.false;
		});

		it('should remove a peer bucket with removePeer', () => {
			const limiter = new PeerRateLimiter();
			limiter.tryConsume('peer-x');
			limiter.tryConsume('peer-y');
			expect(limiter.size).to.equal(2);
			limiter.removePeer('peer-x');
			expect(limiter.size).to.equal(1);
			limiter.removePeer('peer-y');
			expect(limiter.size).to.equal(0);
		});

		it('should remove all buckets with clear()', () => {
			const limiter = new PeerRateLimiter();
			limiter.tryConsume('peer-1');
			limiter.tryConsume('peer-2');
			limiter.tryConsume('peer-3');
			expect(limiter.size).to.equal(3);
			limiter.clear();
			expect(limiter.size).to.equal(0);
		});

		it('should respect custom config with low maxHtlcsPerSecond', () => {
			const limiter = new PeerRateLimiter({
				maxHtlcsPerSecond: 2,
				burstMultiplier: 1
			});
			const peer = 'low-rate-peer';
			// Capacity = 2 * 1 = 2
			expect(limiter.tryConsume(peer)).to.be.true;
			expect(limiter.tryConsume(peer)).to.be.true;
			expect(limiter.tryConsume(peer)).to.be.false;
		});
	});

	describe('Node integration tests', () => {
		it('should create LightningNode with maxTotalInFlightHtlcs config', () => {
			const config = makeNodeConfig(300, { maxTotalInFlightHtlcs: 500 });
			const node = new LightningNode(config);
			node.on('error', () => {});
			expect(node).to.be.instanceOf(LightningNode);
			node.destroy();
		});

		it('should create LightningNode with rateLimitConfig', () => {
			const config = makeNodeConfig(301, {
				rateLimitConfig: { maxHtlcsPerSecond: 10, burstMultiplier: 3 }
			});
			const node = new LightningNode(config);
			node.on('error', () => {});
			expect(node).to.be.instanceOf(LightningNode);
			node.destroy();
		});

		it('should return 0 for getTotalInFlightHtlcCount on a fresh node', () => {
			const config = makeNodeConfig(302);
			const node = new LightningNode(config);
			node.on('error', () => {});
			expect(node.getTotalInFlightHtlcCount()).to.equal(0);
			node.destroy();
		});
	});
});
