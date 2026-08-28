/**
 * BEIGNET_JIT_* resolution, offline (issue #532 workstream 3B).
 *
 * Two roles share one config block. `enabled` decides whether this node
 * fronts channel funding with its own coins for peers, so it follows the
 * exact-string rule (only 'true'/'false' count, anything else falls back to
 * the safe direction, off). The fork wrote `=== 'true'`, which reads
 * BEIGNET_JIT_RECEIVE=1 as an explicit false: same outcome by accident, and
 * the opposite outcome for a variable whose safe direction were ON.
 *
 * The four fee fields go through integerEnv, so '5.5' or '10k' resolves to
 * NaN rather than 5 or 10 and daemon startup refuses it by name. A fee that
 * silently becomes a different number is a price nobody wrote.
 */

import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';

const VARS = [
	'BEIGNET_JIT_RECEIVE',
	'BEIGNET_JIT_FLAT_FEE_SAT',
	'BEIGNET_JIT_FEE_PPM',
	'BEIGNET_JIT_MAX_FLAT_FEE_SAT',
	'BEIGNET_JIT_MAX_FEE_PPM'
];

describe('resolveConfig jitReceive', () => {
	afterEach(() => {
		for (const v of VARS) delete process.env[v];
	});

	it('is undefined when nothing sets it', () => {
		expect(resolveConfig({}).jitReceive).to.equal(undefined);
	});

	it('resolves the LSP role and its fee from the environment', () => {
		process.env.BEIGNET_JIT_RECEIVE = 'true';
		process.env.BEIGNET_JIT_FLAT_FEE_SAT = '250';
		process.env.BEIGNET_JIT_FEE_PPM = '1500';
		expect(resolveConfig({}).jitReceive).to.deep.equal({
			enabled: true,
			flatFeeSat: 250,
			feePpm: 1500
		});
	});

	it('keeps a configured zero fee, which is a real policy', () => {
		process.env.BEIGNET_JIT_RECEIVE = 'true';
		process.env.BEIGNET_JIT_FLAT_FEE_SAT = '0';
		process.env.BEIGNET_JIT_FEE_PPM = '0';
		expect(resolveConfig({}).jitReceive).to.deep.equal({
			enabled: true,
			flatFeeSat: 0,
			feePpm: 0
		});
	});

	it('resolves the client ceilings without the LSP role', () => {
		process.env.BEIGNET_JIT_MAX_FLAT_FEE_SAT = '500';
		process.env.BEIGNET_JIT_MAX_FEE_PPM = '2000';
		expect(resolveConfig({}).jitReceive).to.deep.equal({
			maxFlatFeeSat: 500,
			maxFeePpm: 2000
		});
	});

	it('honours an explicit false', () => {
		process.env.BEIGNET_JIT_RECEIVE = 'false';
		expect(resolveConfig({}).jitReceive).to.deep.equal({ enabled: false });
	});

	it('ignores anything that is not exactly true or false', () => {
		for (const junk of ['1', 'TRUE', 'yes', 'on', '']) {
			process.env.BEIGNET_JIT_RECEIVE = junk;
			expect(resolveConfig({}).jitReceive, junk).to.equal(undefined);
		}
	});

	it('surfaces a partly numeric fee as NaN, not as a truncated number', () => {
		for (const [raw, field] of [
			['5.5', 'flatFeeSat'],
			['10k', 'flatFeeSat'],
			[' 12 000', 'flatFeeSat']
		] as const) {
			process.env.BEIGNET_JIT_FLAT_FEE_SAT = raw;
			const resolved = resolveConfig({}).jitReceive;
			expect(resolved, raw).to.not.equal(undefined);
			expect(Number.isNaN(resolved![field]), raw).to.equal(true);
		}
	});

	it('prefers the CLI flag over the environment', () => {
		process.env.BEIGNET_JIT_RECEIVE = 'true';
		process.env.BEIGNET_JIT_FEE_PPM = '9999';
		const flag = { enabled: false, feePpm: 10 };
		expect(resolveConfig({ jitReceive: flag }).jitReceive).to.deep.equal(flag);
	});
});
