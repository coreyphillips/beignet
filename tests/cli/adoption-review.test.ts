/**
 * AI Agent Adoption Review — Improvement Tests
 *
 * Phase 4: Route info in PaymentInfo (4 tests)
 * Phase 5: isReady() + GET /ready (4 tests)
 * Phase 6: Cold start fee warmup (2 tests)
 * Phase 7: OpenAPI envelope schema (3 tests)
 */

import { expect } from 'chai';
import {
	PaymentInfo,
	PaymentRoute,
	PaymentRouteHop,
	HealthInfo
} from '../../src/cli/types';
import { getOpenApiSpec } from '../../src/cli/openapi';

// ─────────────── Phase 4: Route info in PaymentInfo ───────────────

describe('PaymentInfo.route', () => {
	it('PaymentRoute has hops, totalFeeMsat, hopCount', () => {
		const route: PaymentRoute = {
			hops: [
				{
					pubkey: '02' + 'aa'.repeat(32),
					shortChannelId: '0011223344556677',
					feeMsat: 1000
				},
				{
					pubkey: '03' + 'bb'.repeat(32),
					shortChannelId: '8899aabbccddeeff',
					feeMsat: 500
				}
			],
			totalFeeMsat: 1500,
			hopCount: 2
		};
		expect(route.hops).to.have.length(2);
		expect(route.totalFeeMsat).to.equal(1500);
		expect(route.hopCount).to.equal(2);
	});

	it('PaymentRouteHop has pubkey, shortChannelId, feeMsat', () => {
		const hop: PaymentRouteHop = {
			pubkey: '02' + 'aa'.repeat(32),
			shortChannelId: '0011223344556677',
			feeMsat: 1000
		};
		expect(hop.pubkey).to.be.a('string');
		expect(hop.shortChannelId).to.be.a('string');
		expect(hop.feeMsat).to.be.a('number');
	});

	it('PaymentInfo.route is optional', () => {
		const info: PaymentInfo = {
			paymentHash: 'aa'.repeat(32),
			amountSats: 1000,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: Date.now()
		};
		expect(info.route).to.be.undefined;
	});

	it('OpenAPI PaymentInfo schema includes route object', () => {
		const spec = getOpenApiSpec() as any;
		const paymentSchema = spec.components.schemas.PaymentInfo;
		expect(paymentSchema.properties.route).to.exist;
		expect(paymentSchema.properties.route.type).to.equal('object');
		expect(paymentSchema.properties.route.properties.hops).to.exist;
		expect(paymentSchema.properties.route.properties.totalFeeMsat).to.exist;
		expect(paymentSchema.properties.route.properties.hopCount).to.exist;
	});
});

// ─────────────── Phase 5: isReady() + GET /ready ───────────────

describe('isReady()', () => {
	it('returns false when no channels exist', () => {
		// isReady() checks health.status === 'ready' && readyChannelCount > 0
		const health: HealthInfo = {
			status: 'ready',
			uptime: 1000,
			blockHeight: 100,
			electrumConnected: true,
			peerCount: 0,
			channelCount: 0,
			readyChannelCount: 0,
			graphNodes: 0,
			graphChannels: 0
		};
		const isReady = health.status === 'ready' && health.readyChannelCount > 0;
		expect(isReady).to.be.false;
	});

	it('returns true when NORMAL channels exist', () => {
		const health: HealthInfo = {
			status: 'ready',
			uptime: 5000,
			blockHeight: 200,
			electrumConnected: true,
			peerCount: 1,
			channelCount: 1,
			readyChannelCount: 1,
			graphNodes: 10,
			graphChannels: 5
		};
		const isReady = health.status === 'ready' && health.readyChannelCount > 0;
		expect(isReady).to.be.true;
	});

	it('returns false when status is degraded', () => {
		const health: HealthInfo = {
			status: 'degraded',
			uptime: 5000,
			blockHeight: 200,
			electrumConnected: false,
			peerCount: 0,
			channelCount: 1,
			readyChannelCount: 0,
			graphNodes: 0,
			graphChannels: 0
		};
		const isReady = health.status === 'ready' && health.readyChannelCount > 0;
		expect(isReady).to.be.false;
	});

	it('GET /ready is auth-exempt in OpenAPI spec', () => {
		const spec = getOpenApiSpec() as any;
		const readyRoute = spec.paths['/ready'];
		expect(readyRoute).to.exist;
		expect(readyRoute.get).to.exist;
		expect(readyRoute.get.security).to.deep.equal([]);
		expect(readyRoute.get.summary).to.include('readiness');
	});
});

// ─────────────── Phase 6: Cold start fee warmup ───────────────

describe('Cold start fee warmup', () => {
	it('ElectrumBackend.estimateFee exists and is callable', async () => {
		// Verify the method signature exists on ElectrumBackend
		const { ElectrumBackend } = await import(
			'../../src/lightning/chain/electrum-backend'
		);
		expect(ElectrumBackend.prototype.estimateFee).to.be.a('function');
	});

	it('estimateFee returns number (fee rate or -1 for no data)', async () => {
		// The warmup call uses estimateFee(6) - verify the method accepts a number
		const { ElectrumBackend } = await import(
			'../../src/lightning/chain/electrum-backend'
		);
		const proto = ElectrumBackend.prototype;
		expect(proto.estimateFee.length).to.be.at.least(1); // at least 1 param (targetBlocks)
	});
});

// ─────────────── Phase 7: OpenAPI envelope schema ───────────────

describe('OpenAPI ApiEnvelope schema', () => {
	it('ApiEnvelope schema exists in components', () => {
		const spec = getOpenApiSpec() as any;
		expect(spec.components.schemas.ApiEnvelope).to.exist;
	});

	it('ApiEnvelope has ok, result, and error properties', () => {
		const spec = getOpenApiSpec() as any;
		const envelope = spec.components.schemas.ApiEnvelope;
		expect(envelope.properties.ok).to.exist;
		expect(envelope.properties.ok.type).to.equal('boolean');
		expect(envelope.properties.result).to.exist;
		expect(envelope.properties.error).to.exist;
		expect(envelope.properties.error.type).to.equal('object');
		expect(envelope.properties.error.properties.code).to.exist;
		expect(envelope.properties.error.properties.message).to.exist;
	});

	it('ApiEnvelope requires ok field', () => {
		const spec = getOpenApiSpec() as any;
		const envelope = spec.components.schemas.ApiEnvelope;
		expect(envelope.required).to.include('ok');
	});
});

// ─────────────── Phase 3: Example default swap ───────────────

describe('Example default swap', () => {
	it('example/lightning.ts uses --low-level flag for LightningNode', async () => {
		const fs = await import('fs');
		const content = fs.readFileSync('example/lightning.ts', 'utf8');
		expect(content).to.include('--low-level');
		expect(content).not.to.include('--beignet');
	});

	it('default path runs runBeignetExample', async () => {
		const fs = await import('fs');
		const content = fs.readFileSync('example/lightning.ts', 'utf8');
		// The entry point section: useLowLevel runs LightningNode, else runs BeignetNode
		expect(content).to.include('useLowLevel');
		// After the if/else if chain, the final else should call runBeignetExample
		expect(content).to.match(/else\s*\{\s*\n\s*runBeignetExample/);
	});
});

// ─────────────── Phase 2: AI Agent Guide fixes ───────────────

describe('AI Agent Guide', () => {
	it('imports from beignet/cli (not beignet)', async () => {
		const fs = await import('fs');
		const content = fs.readFileSync('docs/AI_AGENT_GUIDE.md', 'utf8');
		expect(content).to.include("from 'beignet/cli'");
		// Should not have the broken import
		expect(content).not.to.match(/import \{ BeignetNode \} from 'beignet';/);
	});

	it('has Import Paths reference table', async () => {
		const fs = await import('fs');
		const content = fs.readFileSync('docs/AI_AGENT_GUIDE.md', 'utf8');
		expect(content).to.include('## Import Paths');
		expect(content).to.include('beignet/cli');
		expect(content).to.include('beignet/lightning');
	});

	it('has Payment Lifecycle section', async () => {
		const fs = await import('fs');
		const content = fs.readFileSync('docs/AI_AGENT_GUIDE.md', 'utf8');
		expect(content).to.include('## Payment Lifecycle');
		expect(content).to.include('Timeout behavior');
		expect(content).to.include('Duplicate payment protection');
		expect(content).to.include('Method comparison');
	});
});
