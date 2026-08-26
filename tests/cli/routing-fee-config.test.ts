/**
 * BEIGNET_FEE_BASE_MSAT / BEIGNET_FEE_PPM / BEIGNET_CLTV_DELTA resolution,
 * offline (issue #532 workstream 1B).
 *
 * The trio feeds the node-wide channel_update defaults, so the merge must
 * keep a configured 0 (free routing is a real policy) and must never let a
 * partially numeric value through: parseInt would read '0.5' as 0 and '10m'
 * as 10, silently advertising a policy the operator never wrote. integerEnv
 * turns those into NaN instead, which daemon startup refuses by name.
 */

import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';

describe('resolveConfig routing fee policy', () => {
	afterEach(() => {
		delete process.env.BEIGNET_FEE_BASE_MSAT;
		delete process.env.BEIGNET_FEE_PPM;
		delete process.env.BEIGNET_CLTV_DELTA;
	});

	it('is undefined when nothing sets it, so the library defaults rule', () => {
		const resolved = resolveConfig({});
		expect(resolved.routingFeeBaseMsat).to.equal(undefined);
		expect(resolved.routingFeePpm).to.equal(undefined);
		expect(resolved.routingCltvDelta).to.equal(undefined);
	});

	it('resolves whole integers from the env vars', () => {
		process.env.BEIGNET_FEE_BASE_MSAT = '500';
		process.env.BEIGNET_FEE_PPM = '250';
		process.env.BEIGNET_CLTV_DELTA = '99';
		const resolved = resolveConfig({});
		expect(resolved.routingFeeBaseMsat).to.equal(500);
		expect(resolved.routingFeePpm).to.equal(250);
		expect(resolved.routingCltvDelta).to.equal(99);
	});

	it('keeps a configured 0 (free routing), the ?? not || distinction', () => {
		process.env.BEIGNET_FEE_BASE_MSAT = '0';
		process.env.BEIGNET_FEE_PPM = '0';
		const resolved = resolveConfig({});
		expect(resolved.routingFeeBaseMsat).to.equal(0);
		expect(resolved.routingFeePpm).to.equal(0);
	});

	it('keeps a CLI-flag 0 over a non-zero env value', () => {
		process.env.BEIGNET_FEE_PPM = '250';
		const resolved = resolveConfig({ routingFeePpm: 0 });
		expect(resolved.routingFeePpm).to.equal(0);
	});

	it('surfaces partially numeric env values as NaN for startup to refuse', () => {
		for (const junk of ['0.5', '10m', '600_000', '1e3', ' 12x ']) {
			process.env.BEIGNET_FEE_BASE_MSAT = junk;
			process.env.BEIGNET_FEE_PPM = junk;
			process.env.BEIGNET_CLTV_DELTA = junk;
			const resolved = resolveConfig({});
			expect(Number.isNaN(resolved.routingFeeBaseMsat), junk).to.equal(true);
			expect(Number.isNaN(resolved.routingFeePpm), junk).to.equal(true);
			expect(Number.isNaN(resolved.routingCltvDelta), junk).to.equal(true);
		}
	});

	it('treats an empty or whitespace env value as unset', () => {
		process.env.BEIGNET_CLTV_DELTA = '  ';
		const resolved = resolveConfig({});
		expect(resolved.routingCltvDelta).to.equal(undefined);
	});

	it('prefers the CLI flag over the env var', () => {
		process.env.BEIGNET_FEE_BASE_MSAT = '500';
		const resolved = resolveConfig({ routingFeeBaseMsat: 900 });
		expect(resolved.routingFeeBaseMsat).to.equal(900);
	});
});
