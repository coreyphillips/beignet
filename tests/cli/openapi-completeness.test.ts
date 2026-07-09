/**
 * OpenAPI Spec Completeness Tests
 *
 * Verifies that the OpenAPI spec documents all daemon routes
 * and includes all necessary component schemas.
 */

import { expect } from 'chai';
import { getOpenApiSpec } from '../../src/cli/openapi';

describe('OpenAPI Spec Completeness', () => {
	const raw = getOpenApiSpec();
	const spec = raw as Record<string, unknown> & {
		paths: Record<string, Record<string, unknown>>;
		components: {
			schemas: Record<string, unknown>;
			securitySchemes: Record<string, unknown>;
		};
		security: unknown[];
	};

	it('should return valid OpenAPI 3.0.3 spec', () => {
		expect(spec.openapi).to.equal('3.0.3');
		expect(spec.info).to.have.property('title');
		expect(spec.info).to.have.property('version');
	});

	// ─────────────── Route Coverage ───────────────

	const expectedRoutes = [
		'/info',
		'/balance',
		'/health',
		'/peers',
		'/channels',
		'/channels/ready',
		'/payments',
		'/invoices',
		'/invoice/create',
		'/invoice',
		'/invoice/decode',
		'/invoice/pay',
		'/invoice/pay-async',
		'/invoice/pay-safe',
		'/channel/open',
		'/channel/open-and-wait',
		'/channel/close',
		'/channel/forceclose',
		'/channel/update-commitment-feerate',
		'/channel/update-fee',
		'/channel/connect-and-open',
		'/channel',
		'/peer/connect',
		'/peer/disconnect',
		'/payment/cancel',
		'/payment',
		'/offer/create',
		'/offer/decode',
		'/offers',
		'/route/estimate',
		'/route/probe',
		'/backup',
		'/backup/scb',
		'/send',
		'/stats',
		'/events',
		'/stop',
		// New routes:
		'/address/new',
		'/wallet/refresh',
		'/mnemonic',
		'/peers/bootstrap',
		'/peers/connect-seeds',
		'/trusted-peer/add',
		'/trusted-peer/remove',
		'/trusted-peers',
		'/channel/open-zeroconf',
		'/channel/open-v2',
		'/channel/splice-in',
		'/channel/splice-out',
		'/channel/wait-ready',
		'/payment/wait',
		'/payment/metadata',
		'/can-send',
		'/can-receive',
		'/offer/pay',
		'/transactions',
		'/utxos',
		'/fees/estimates'
	];

	for (const route of expectedRoutes) {
		it(`should document route ${route}`, () => {
			expect(spec.paths, `Missing OpenAPI route: ${route}`).to.have.property(
				route
			);
		});
	}

	// ─────────────── Schema Coverage ───────────────

	const expectedSchemas = [
		'NodeInfo',
		'BalanceInfo',
		'HealthInfo',
		'PeerInfo',
		'ChannelInfo',
		'PaymentInfo',
		'InvoiceInfo',
		'OfferInfo',
		'NodeStats',
		'RouteEstimate',
		'TxInfo',
		'SpliceResult',
		'BootstrapPeerInfo',
		'TrustedPeerInfo',
		'OnchainTxInfo',
		'UtxoInfo',
		'OnchainFees'
	];

	for (const schema of expectedSchemas) {
		it(`should include component schema ${schema}`, () => {
			expect(
				spec.components.schemas,
				`Missing schema: ${schema}`
			).to.have.property(schema);
		});
	}

	// ─────────────── Auth-Exempt Routes ───────────────

	it('/health should have security: [] override', () => {
		const healthGet = spec.paths['/health'] as Record<
			string,
			Record<string, unknown>
		>;
		expect(healthGet.get).to.have.property('security');
		expect(healthGet.get.security).to.deep.equal([]);
	});

	// ─────────────── ChannelInfo State Enum ───────────────

	it('ChannelInfo.state should have enum values', () => {
		const channelSchema = spec.components.schemas.ChannelInfo as Record<
			string,
			unknown
		>;
		const properties = channelSchema.properties as Record<
			string,
			Record<string, unknown>
		>;
		expect(properties.state).to.have.property('enum');
		const stateEnum = properties.state.enum as string[];
		expect(stateEnum).to.include('NORMAL');
		expect(stateEnum).to.include('AWAITING_FUNDING_CONFIRMED');
		expect(stateEnum).to.include('FORCE_CLOSED');
	});

	// ─────────────── Security Scheme ───────────────

	it('should define bearerAuth security scheme', () => {
		expect(spec.components.securitySchemes).to.have.property('bearerAuth');
	});

	it('should have global security requirement', () => {
		expect(spec.security).to.deep.equal([{ bearerAuth: [] }]);
	});

	// ─────────────── bodyContent Record<> type handling ───────────────

	it('metadata fields should use additionalProperties schema', () => {
		const payRoute = spec.paths['/invoice/pay'] as Record<
			string,
			Record<string, unknown>
		>;
		const requestBody = payRoute.post.requestBody as Record<string, unknown>;
		const content = requestBody.content as Record<
			string,
			Record<string, unknown>
		>;
		const schema = content['application/json'].schema as Record<
			string,
			unknown
		>;
		const properties = schema.properties as Record<
			string,
			Record<string, unknown>
		>;
		expect(properties.metadata).to.have.property('additionalProperties');
	});
});
