/**
 * The config to daemon-options mapping (src/cli/daemon-options.ts).
 *
 * A field this mapping forgets fails silently in the one way nothing reports:
 * the env var is accepted, resolveConfig parses and bounds-checks it, the
 * daemon starts, and the role is simply off. BEIGNET_SWAPS was dropped that
 * way from issue #737 (0.15.0) and BEIGNET_GUARDIAN_SERVE from issue #699, so
 * `beignet start` could never serve a swap or host a guardian however it was
 * configured, and GET /swaps/status answered enabled:false with no reason why.
 *
 * The last test is the structural guard: every config field the daemon also
 * accepts as an option has to be forwarded, or be listed here as deliberately
 * held back.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { daemonOptions } from '../../src/cli/daemon-options';
import { resolveConfig } from '../../src/cli/config';
import { startDaemon } from '../../src/cli/daemon';
import { BeignetConfig } from '../../src/cli/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const SWAP_VARS = [
	'BEIGNET_SWAPS',
	'BEIGNET_SWAP_FLAT_FEE_SAT',
	'BEIGNET_SWAP_FEE_PPM',
	'BEIGNET_SWAP_MIN_SAT',
	'BEIGNET_SWAP_MAX_SAT',
	'BEIGNET_SWAP_MAX_EXPOSURE_SAT',
	'BEIGNET_SWAP_MAX_CONCURRENT',
	'BEIGNET_SWAP_SUBMARINE',
	'BEIGNET_GUARDIAN_SERVE',
	'BEIGNET_GUARDIAN_MAX_SETS'
];

/** An offline config literal: no Electrum, no gossip, nothing to reach. */
function offlineConfig(over: Partial<BeignetConfig> = {}): BeignetConfig {
	return {
		mnemonic: MNEMONIC,
		network: 'regtest',
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		logLevel: 'silent',
		...over
	} as BeignetConfig;
}

describe('daemon options from config', () => {
	afterEach(() => {
		for (const v of SWAP_VARS) delete process.env[v];
	});

	it('forwards the swap provider policy', () => {
		const opts = daemonOptions(
			offlineConfig({
				swaps: {
					enabled: true,
					flatFeeSat: 500,
					feePpm: 2_500,
					minSat: 25_000,
					maxSat: 1_000_000,
					maxExposureSat: 2_000_000,
					maxConcurrent: 3,
					submarine: true
				}
			}),
			0
		);
		expect(opts.swaps?.enabled).to.equal(true);
		expect(opts.swaps?.maxExposureSat).to.equal(2_000_000);
		expect(opts.swaps?.submarine).to.equal(true);
	});

	it('forwards guardian hosting and the connection settings', () => {
		const opts = daemonOptions(
			offlineConfig({
				guardianServe: true,
				guardianToken: 'tok',
				guardianMaxSets: 9,
				autoBootstrap: false,
				connectTimeoutMs: 7_000
			}),
			0
		);
		expect(opts.guardianServe).to.equal(true);
		expect(opts.guardianToken).to.equal('tok');
		expect(opts.guardianMaxSets).to.equal(9);
		expect(opts.autoBootstrap).to.equal(false);
		expect(opts.connectTimeoutMs).to.equal(7_000);
	});

	it('carries the environment through resolveConfig and into the options', () => {
		process.env.BEIGNET_SWAPS = 'true';
		process.env.BEIGNET_SWAP_MAX_SAT = '750000';
		process.env.BEIGNET_GUARDIAN_SERVE = 'true';
		const config = resolveConfig({});
		expect(config.swaps?.enabled, 'config').to.equal(true);
		const opts = daemonOptions(config, 0);
		expect(opts.swaps?.enabled, 'options').to.equal(true);
		expect(opts.swaps?.maxSat).to.equal(750_000);
		expect(opts.guardianServe).to.equal(true);
	});

	it('leaves an unset role off rather than inventing a default', () => {
		const opts = daemonOptions(offlineConfig(), 0);
		expect(opts.swaps).to.equal(undefined);
		expect(opts.guardianServe).to.equal(undefined);
	});

	it('forwards every config field the daemon accepts as an option', () => {
		// Parsed from the sources: a new config field wired into DaemonOptions
		// but forgotten here has to fail somewhere, and this is the only place
		// that can see it.
		const fields = (file: string, name: string): Set<string> => {
			const src = fs.readFileSync(
				path.join(__dirname, '../../src/cli', file),
				'utf8'
			);
			const head = src.indexOf(`export interface ${name}`);
			let i = src.indexOf('{', head) + 1;
			let depth = 1;
			let top = '';
			while (depth > 0) {
				const ch = src[i];
				if (ch === '{') depth += 1;
				else if (ch === '}') depth -= 1;
				else if (depth === 1) top += ch;
				i += 1;
			}
			return new Set(
				[...top.matchAll(/^\s*(?:readonly\s+)?([A-Za-z_]\w*)\??\s*:/gm)].map(
					(m) => m[1]
				)
			);
		};

		const config = fields('types.ts', 'BeignetConfig');
		const accepted = new Set([
			...fields('daemon.ts', 'DaemonOptions'),
			...fields('beignet-node.ts', 'BeignetNodeOptions')
		]);
		const forwarded = new Set(Object.keys(daemonOptions(offlineConfig(), 0)));
		// Deliberately held back, with the reason:
		const held = new Set([
			// The FFOR issuer, witness and settlement roles (their env vars are
			// not documented for the CLI yet); wire them with that surface.
			'fforIssuer',
			'fforWitness',
			'fforSettle'
		]);

		const missing = [...config].filter(
			(k) => accepted.has(k) && !forwarded.has(k) && !held.has(k)
		);
		expect(config.size, 'parsed BeignetConfig').to.be.greaterThan(20);
		expect(
			missing,
			`not forwarded to the daemon: ${missing.join(', ')}`
		).to.deep.equal([]);
	});
});

describe('a daemon started from those options serves swaps', function () {
	this.timeout(60_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>> | null = null;
	let port = 0;

	beforeEach(() => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-swap-opts-'));
	});

	afterEach(async () => {
		if (daemon) await daemon.stop();
		daemon = null;
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('reports the configured role on GET /swaps/status', async () => {
		const config = offlineConfig({
			dataDir,
			listenPort: 0,
			swaps: {
				enabled: true,
				flatFeeSat: 500,
				feePpm: 2_500,
				minSat: 25_000,
				maxSat: 1_000_000,
				maxExposureSat: 2_000_000,
				maxConcurrent: 3
			}
		});
		daemon = await startDaemon({
			...daemonOptions(config, 0),
			// Gossip is the one thing an offline boot cannot do quickly.
			rapidGossipSync: false,
			autoGossipSync: false
		});
		port = (daemon.server.address() as AddressInfo).port;

		const body = await new Promise<Record<string, never>>((resolve, reject) => {
			http
				.get({ host: '127.0.0.1', port, path: '/swaps/status' }, (res) => {
					let raw = '';
					res.on('data', (c) => (raw += c));
					res.on('end', () => resolve(JSON.parse(raw)));
				})
				.on('error', reject);
		});
		const result = (body as { result?: Record<string, unknown> }).result;
		expect(result?.enabled, JSON.stringify(body)).to.equal(true);
		expect((result?.limits as { maxSwapSat?: number })?.maxSwapSat).to.equal(
			1_000_000
		);
	});
});
