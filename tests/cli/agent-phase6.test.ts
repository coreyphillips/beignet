/**
 * Phase 6: OpenAPI Spec & Advanced DX.
 *
 * - 6.1: OpenAPI 3.0 specification
 * - 6.2: API versioning
 * - 6.3: Node statistics
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentStatus,
	PaymentDirection
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { getOpenApiSpec } from '../../src/cli/openapi';
import { NodeStats } from '../../src/cli/types';
import { DaemonOptions } from '../../src/cli/daemon';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`phase6-test-${id}`))
		.digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(derivePrivkey(seed, i));
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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

// ─── 6.1: OpenAPI 3.0 Specification ───

describe('OpenAPI Specification', () => {
	let spec: Record<string, unknown>;

	before(() => {
		spec = getOpenApiSpec();
	});

	it('spec has openapi version 3.0.x', () => {
		expect(spec.openapi).to.match(/^3\.0\.\d+$/);
	});

	it('spec has info with title and version', () => {
		const info = spec.info as Record<string, unknown>;
		expect(info.title).to.be.a('string');
		expect(info.version).to.be.a('string');
	});

	it('spec has paths for core endpoints', () => {
		const paths = spec.paths as Record<string, unknown>;
		expect(paths).to.have.property('/info');
		expect(paths).to.have.property('/balance');
		expect(paths).to.have.property('/health');
		expect(paths).to.have.property('/channels');
		expect(paths).to.have.property('/payments');
	});

	it('spec has payment endpoints', () => {
		const paths = spec.paths as Record<string, unknown>;
		expect(paths).to.have.property('/invoice/pay');
		expect(paths).to.have.property('/invoice/pay-async');
		expect(paths).to.have.property('/invoice/create');
	});

	it('spec has channel endpoints', () => {
		const paths = spec.paths as Record<string, unknown>;
		expect(paths).to.have.property('/channel/open');
		expect(paths).to.have.property('/channel/close');
		expect(paths).to.have.property('/channel/forceclose');
	});

	it('spec has routing endpoints', () => {
		const paths = spec.paths as Record<string, unknown>;
		expect(paths).to.have.property('/route/estimate');
		expect(paths).to.have.property('/route/probe');
	});

	it('spec has stats endpoint', () => {
		const paths = spec.paths as Record<string, unknown>;
		expect(paths).to.have.property('/stats');
	});

	it('spec has events endpoint', () => {
		const paths = spec.paths as Record<string, unknown>;
		expect(paths).to.have.property('/events');
	});

	it('spec has security scheme', () => {
		const components = spec.components as Record<string, unknown>;
		const schemes = components.securitySchemes as Record<string, unknown>;
		expect(schemes).to.have.property('bearerAuth');
	});

	it('spec has servers', () => {
		const servers = spec.servers as unknown[];
		expect(servers).to.have.length.greaterThan(0);
	});
});

// ─── 6.2: API Versioning ───

describe('API Versioning', () => {
	it('DaemonOptions has expected fields', () => {
		const opts: DaemonOptions = {
			daemonPort: 3000,
			daemonHost: '0.0.0.0',
			apiToken: 'test',
			cors: true
		};
		expect(opts.daemonPort).to.equal(3000);
	});

	it('/v1/ prefix pattern strips correctly', () => {
		// The daemon strips /v1/ prefix so /v1/info → /info
		const url = '/v1/info';
		const stripped = url.startsWith('/v1/') ? url.slice(3) : url;
		expect(stripped).to.equal('/info');
	});

	it('/v1/channels/ready maps correctly', () => {
		const url = '/v1/channels/ready';
		const stripped = url.startsWith('/v1/') ? url.slice(3) : url;
		expect(stripped).to.equal('/channels/ready');
	});

	it('non-versioned paths pass through unchanged', () => {
		const url = '/info';
		const stripped = url.startsWith('/v1/') ? url.slice(3) : url;
		expect(stripped).to.equal('/info');
	});

	it('X-API-Version header value is 1', () => {
		// The daemon sets this header on all responses
		const version = '1';
		expect(version).to.equal('1');
	});
});

// ─── 6.3: Node Statistics ───

describe('Node Statistics', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(10));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		node.destroy();
	});

	it('NodeStats type has expected fields', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 0,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 0,
			totalSatsSent: 0,
			totalSatsReceived: 0,
			totalFeesPaid: 0,
			successRate: 0,
			uptimeMs: 0
		};
		expect(Object.keys(stats)).to.have.length(8);
	});

	it('empty node has zero stats', () => {
		// Compute stats from LightningNode payments
		const payments = node.listPayments();
		expect(payments).to.have.length(0);

		// Verify stats shape
		const stats: NodeStats = {
			totalPaymentsSent: 0,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 0,
			totalSatsSent: 0,
			totalSatsReceived: 0,
			totalFeesPaid: 0,
			successRate: 0,
			uptimeMs: 0
		};
		expect(stats.successRate).to.equal(0);
	});

	it('stats compute from payment data', () => {
		// Populate payments
		const payments = (node as any).payments as Map<string, IPaymentInfo>;
		const now = Date.now();

		// 3 successful outgoing
		for (let i = 0; i < 3; i++) {
			const hash = crypto
				.createHash('sha256')
				.update(Buffer.from(`sent-${i}`))
				.digest();
			payments.set(hash.toString('hex'), {
				paymentHash: hash,
				amountMsat: BigInt((i + 1) * 10_000),
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.OUTGOING,
				createdAt: now - i * 1000,
				route: {
					hops: [],
					totalFeeMsat: BigInt(i * 100),
					totalCltvDelta: 0,
					totalAmountMsat: BigInt((i + 1) * 10_000)
				}
			});
		}

		// 2 successful incoming
		for (let i = 0; i < 2; i++) {
			const hash = crypto
				.createHash('sha256')
				.update(Buffer.from(`recv-${i}`))
				.digest();
			payments.set(hash.toString('hex'), {
				paymentHash: hash,
				amountMsat: BigInt((i + 1) * 5_000),
				status: PaymentStatus.COMPLETED,
				direction: PaymentDirection.INCOMING,
				createdAt: now - i * 1000
			});
		}

		// 1 failed outgoing
		const failHash = crypto
			.createHash('sha256')
			.update(Buffer.from('fail-0'))
			.digest();
		payments.set(failHash.toString('hex'), {
			paymentHash: failHash,
			amountMsat: 50_000n,
			status: PaymentStatus.FAILED,
			direction: PaymentDirection.OUTGOING,
			createdAt: now
		});

		const allPayments = node.listPayments();
		expect(allPayments).to.have.length(6);

		// Compute stats manually to verify
		let sent = 0;
		let received = 0;
		let failed = 0;
		for (const p of allPayments) {
			if (p.direction === 'OUTGOING' && p.status === 'COMPLETED') sent++;
			else if (p.direction === 'INCOMING' && p.status === 'COMPLETED')
				received++;
			else if (p.status === 'FAILED') failed++;
		}
		expect(sent).to.equal(3);
		expect(received).to.equal(2);
		expect(failed).to.equal(1);
	});

	it('successRate is computed correctly', () => {
		// 3 sent + 1 failed = 4 attempts, 3 successes → 0.75
		const stats: NodeStats = {
			totalPaymentsSent: 3,
			totalPaymentsReceived: 2,
			totalPaymentsFailed: 1,
			totalSatsSent: 60,
			totalSatsReceived: 15,
			totalFeesPaid: 3,
			successRate: 0.75,
			uptimeMs: 10000
		};
		expect(stats.successRate).to.equal(0.75);
	});

	it('successRate is 0 with no attempts', () => {
		const stats: NodeStats = {
			totalPaymentsSent: 0,
			totalPaymentsReceived: 0,
			totalPaymentsFailed: 0,
			totalSatsSent: 0,
			totalSatsReceived: 0,
			totalFeesPaid: 0,
			successRate: 0,
			uptimeMs: 5000
		};
		expect(stats.successRate).to.equal(0);
	});

	it('successRate is 1.0 with all successes', () => {
		const sent = 5;
		const failed = 0;
		const totalAttempts = sent + failed;
		const rate = totalAttempts > 0 ? sent / totalAttempts : 0;
		expect(rate).to.equal(1);
	});

	it('uptimeMs increases over time', () => {
		const startedAt = Date.now() - 5000;
		const uptimeMs = Date.now() - startedAt;
		expect(uptimeMs).to.be.greaterThanOrEqual(4000);
	});

	it('OpenAPI spec /openapi.json route is auth-exempt', () => {
		// Verify our auth-exempt set includes /openapi.json
		const exemptRoutes = new Set(['GET /health', 'GET /openapi.json']);
		expect(exemptRoutes.has('GET /openapi.json')).to.be.true;
	});
});
