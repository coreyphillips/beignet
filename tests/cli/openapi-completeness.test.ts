/**
 * OpenAPI Spec Completeness Tests
 *
 * Verifies that the OpenAPI spec documents all daemon routes
 * and includes all necessary component schemas.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
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

	it('info.version is the package version', () => {
		const pkg = JSON.parse(
			fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf8')
		) as { version: string };
		expect((spec.info as { version: string }).version).to.equal(pkg.version);
	});

	// ─────────────── Route Coverage ───────────────

	// Every route key in daemon.ts source, read the same way as the scope and
	// CLI-parity drift tests, so a route added to the daemon fails here until
	// the spec describes it. Covers the routes dispatched outside the routes map
	// (/stop, /events, /metrics) because their keys are literals there too.
	function daemonRouteKeys(): string[] {
		const daemonSrc = fs.readFileSync(
			path.join(__dirname, '../../src/cli/daemon.ts'),
			'utf8'
		);
		const keys = new Set<string>();
		const re = /'((?:GET|POST|DELETE) \/[^']+)'/g;
		let m: RegExpExecArray | null;
		while ((m = re.exec(daemonSrc)) !== null) {
			keys.add(m[1]);
		}
		return [...keys];
	}

	// The document does not list the route that serves it.
	const UNDOCUMENTED_ROUTES = new Set(['GET /openapi.json']);

	it('documents every daemon route with its method', () => {
		const routeKeys = daemonRouteKeys();
		// A scan that stops matching must not pass by finding nothing.
		expect(routeKeys).to.include('GET /info');
		const missing = routeKeys.filter((key) => {
			if (UNDOCUMENTED_ROUTES.has(key)) return false;
			const [method, routePath] = key.split(' ');
			return !spec.paths[routePath]?.[method.toLowerCase()];
		});
		expect(
			missing,
			`daemon routes missing from src/cli/openapi.ts: ${missing.join(', ')}`
		).to.deep.equal([]);
	});

	// ─────────────── Schema Coverage ───────────────

	const expectedSchemas = [
		'NodeInfo',
		'ListenerProblem',
		'BalanceInfo',
		'HealthInfo',
		'PeerInfo',
		'ChannelInfo',
		'CloseStatus',
		'ChannelPolicy',
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
		'OnchainFees',
		'ForwardingEvent',
		'ForwardingSummary',
		'GraphInfo',
		'GraphChannelPolicy',
		'GraphChannelInfo',
		'GraphNodeInfo',
		'RouteHop',
		'RouteQueryResult',
		'RebalancePlan',
		'AdvisorRecommendations',
		'RebalanceResult',
		'RebalanceExecutionSummary',
		'HoldInvoiceInfo',
		'WatchtowerInfo',
		'BoostResult',
		'BoostableTransactions',
		'ConsolidateResult',
		'DescriptorsInfo',
		'DirectFundingConfig',
		'DirectFundingSendResult',
		'JitStatus',
		'JitQuote'
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
