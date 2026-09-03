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

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';

const VARS = [
	'BEIGNET_JIT_RECEIVE',
	'BEIGNET_JIT_FLAT_FEE_SAT',
	'BEIGNET_JIT_FEE_PPM',
	'BEIGNET_JIT_MAX_FLAT_FEE_SAT',
	'BEIGNET_JIT_MAX_FEE_PPM',
	'BEIGNET_JIT_MAX_CLIENT_FUNDING_SAT',
	'BEIGNET_JIT_MAX_CONCURRENT_FUNDINGS',
	'BEIGNET_JIT_MAX_TOTAL_FUNDING_SAT'
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

	// Issue #665: the LSP role fronts this node's coins, and until these had
	// a daemon surface an operator got the library defaults with no way to
	// see or change them.
	it('resolves the exposure caps of the LSP role', () => {
		process.env.BEIGNET_JIT_RECEIVE = 'true';
		process.env.BEIGNET_JIT_MAX_CLIENT_FUNDING_SAT = '400000';
		process.env.BEIGNET_JIT_MAX_CONCURRENT_FUNDINGS = '2';
		process.env.BEIGNET_JIT_MAX_TOTAL_FUNDING_SAT = '5000000';
		expect(resolveConfig({}).jitReceive).to.deep.equal({
			enabled: true,
			maxClientFundingSats: 400_000,
			maxConcurrentFundings: 2,
			maxTotalFundingSats: 5_000_000
		});
	});

	it('leaves an unset cap out, so the library default keeps answering', () => {
		process.env.BEIGNET_JIT_MAX_CONCURRENT_FUNDINGS = '1';
		expect(resolveConfig({}).jitReceive).to.deep.equal({
			maxConcurrentFundings: 1
		});
	});

	it('surfaces a partly numeric cap as NaN, not as a truncated number', () => {
		process.env.BEIGNET_JIT_MAX_CLIENT_FUNDING_SAT = '1m';
		const resolved = resolveConfig({}).jitReceive;
		expect(Number.isNaN(resolved?.maxClientFundingSats)).to.equal(true);
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

	// Per FIELD, not per block. The LFBW app sets BEIGNET_JIT_RECEIVE and the
	// two LSP fee variables on every daemon it spawns; a whole-block `??` gave
	// that env all five fields, so a client ceiling in config.json vanished and
	// the higher built-in default came back on a node whose owner had lowered
	// it (issue #614).
	describe('layer merge', () => {
		const origHome = process.env.HOME;
		let tmpDir: string;

		before(() => {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-jit-cfg-'));
			fs.mkdirSync(path.join(tmpDir, '.beignet'), { recursive: true });
			fs.writeFileSync(
				path.join(tmpDir, '.beignet', 'config.json'),
				JSON.stringify({
					jitReceive: { enabled: true, flatFeeSat: 9, maxFlatFeeSat: 100 }
				})
			);
			process.env.HOME = tmpDir;
		});

		after(() => {
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		});

		it('keeps the config file fields the environment does not name', () => {
			process.env.BEIGNET_JIT_RECEIVE = 'false';
			process.env.BEIGNET_JIT_FEE_PPM = '1500';
			expect(resolveConfig({}).jitReceive).to.deep.equal({
				enabled: false, // env wins the field it names
				flatFeeSat: 9, // file keeps the one it does not
				feePpm: 1500,
				maxFlatFeeSat: 100 // and the client ceiling survives
			});
		});

		it('merges an exposure cap from the environment over the file', () => {
			process.env.BEIGNET_JIT_MAX_CONCURRENT_FUNDINGS = '1';
			expect(resolveConfig({}).jitReceive).to.deep.equal({
				enabled: true,
				flatFeeSat: 9,
				maxFlatFeeSat: 100,
				maxConcurrentFundings: 1
			});
		});

		it('lets the CLI flag win one field without taking the rest', () => {
			process.env.BEIGNET_JIT_FEE_PPM = '1500';
			expect(
				resolveConfig({ jitReceive: { feePpm: 7 } }).jitReceive
			).to.deep.equal({
				enabled: true,
				flatFeeSat: 9,
				feePpm: 7,
				maxFlatFeeSat: 100
			});
		});

		it('reads the config file alone when nothing else is set', () => {
			expect(resolveConfig({}).jitReceive).to.deep.equal({
				enabled: true,
				flatFeeSat: 9,
				maxFlatFeeSat: 100
			});
		});
	});
});
