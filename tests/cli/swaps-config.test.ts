/**
 * BEIGNET_SWAP_* resolution and the daemon surface of the reverse swap
 * provider (issue #737): the exact-string switch, integerEnv for every
 * number, the field-by-field merge, the node-config translation, the
 * routes' scope classification, the relayed events and the OpenAPI paths.
 */

import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';
import { getRouteScopes } from '../../src/cli/auth';
import { getRelayedEvents } from '../../src/cli/daemon';
import { getOpenApiSpec } from '../../src/cli/openapi';

const VARS = [
	'BEIGNET_SWAPS',
	'BEIGNET_SWAP_FLAT_FEE_SAT',
	'BEIGNET_SWAP_FEE_PPM',
	'BEIGNET_SWAP_MIN_SAT',
	'BEIGNET_SWAP_MAX_SAT',
	'BEIGNET_SWAP_MAX_EXPOSURE_SAT',
	'BEIGNET_SWAP_MAX_CONCURRENT',
	'BEIGNET_SWAP_REFUND_DELTA_BLOCKS',
	'BEIGNET_SWAP_FUNDING_CONFS',
	'BEIGNET_SWAP_RESOLUTION_CONFS'
];

describe('resolveConfig swaps (issue #737)', () => {
	afterEach(() => {
		for (const v of VARS) delete process.env[v];
	});

	it('is undefined when nothing sets it', () => {
		expect(resolveConfig({}).swaps).to.equal(undefined);
	});

	it('resolves the role and every term from the environment', () => {
		process.env.BEIGNET_SWAPS = 'true';
		process.env.BEIGNET_SWAP_FLAT_FEE_SAT = '250';
		process.env.BEIGNET_SWAP_FEE_PPM = '1500';
		process.env.BEIGNET_SWAP_MIN_SAT = '20000';
		process.env.BEIGNET_SWAP_MAX_SAT = '500000';
		process.env.BEIGNET_SWAP_MAX_EXPOSURE_SAT = '2000000';
		process.env.BEIGNET_SWAP_MAX_CONCURRENT = '4';
		process.env.BEIGNET_SWAP_REFUND_DELTA_BLOCKS = '200';
		process.env.BEIGNET_SWAP_FUNDING_CONFS = '2';
		process.env.BEIGNET_SWAP_RESOLUTION_CONFS = '6';
		expect(resolveConfig({}).swaps).to.deep.equal({
			enabled: true,
			flatFeeSat: 250,
			feePpm: 1500,
			minSat: 20000,
			maxSat: 500000,
			maxExposureSat: 2000000,
			maxConcurrent: 4,
			refundDeltaBlocks: 200,
			fundingConfs: 2,
			resolutionConfs: 6
		});
	});

	it('only an exact true switches the role on; anything else is not on', () => {
		process.env.BEIGNET_SWAPS = '1';
		expect(resolveConfig({}).swaps).to.equal(undefined);
		process.env.BEIGNET_SWAPS = 'false';
		expect(resolveConfig({}).swaps).to.deep.equal({ enabled: false });
	});

	it('a partly numeric term resolves to NaN so startup refuses it by name', () => {
		process.env.BEIGNET_SWAP_MAX_SAT = '10k';
		expect(Number.isNaN(resolveConfig({}).swaps!.maxSat)).to.equal(true);
	});

	it('merges field by field: flag over env over file', () => {
		process.env.BEIGNET_SWAPS = 'true';
		process.env.BEIGNET_SWAP_FEE_PPM = '1500';
		const merged = resolveConfig({ swaps: { feePpm: 5 } }).swaps;
		expect(merged).to.deep.equal({ enabled: true, feePpm: 5 });
	});
});

describe('swap daemon surface (issue #737)', () => {
	it('classifies every route: reads are readonly, cancel is admin only', () => {
		expect(getRouteScopes('GET /swaps/status')).to.deep.equal(['readonly']);
		expect(getRouteScopes('GET /swaps')).to.deep.equal(['readonly']);
		expect(getRouteScopes('POST /swaps/cancel')).to.deep.equal([]);
	});

	it('relays every swap event to SSE and webhooks', () => {
		const events = getRelayedEvents();
		for (const evt of [
			'swap:created',
			'swap:held',
			'swap:funding',
			'swap:funded',
			'swap:claimed',
			'swap:settled',
			'swap:refund-broadcast',
			'swap:refunded',
			'swap:hold-cancelled',
			'swap:exposed',
			'swap:failed'
		]) {
			expect(events, evt).to.include(evt);
		}
	});

	it('documents the routes and schemas in the OpenAPI spec', () => {
		const spec = getOpenApiSpec() as {
			paths: Record<string, Record<string, { tags: string[] }>>;
			components: { schemas: Record<string, unknown> };
		};
		expect(spec.paths['/swaps/status'].get.tags).to.deep.equal(['Swaps']);
		expect(spec.paths['/swaps'].get.tags).to.deep.equal(['Swaps']);
		expect(spec.paths['/swaps/cancel'].post.tags).to.deep.equal(['Swaps']);
		expect(spec.components.schemas.SwapsStatus).to.be.an('object');
		expect(spec.components.schemas.SwapRecord).to.be.an('object');
	});
});
