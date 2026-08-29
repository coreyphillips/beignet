#!/usr/bin/env node
/**
 * Run the two infrastructure-free unit suites at the same time.
 *
 * They are independent processes with no shared fixture, and neither saturates
 * the machine on its own: measured on 8 cores, test:lightning at the mocha
 * default of 7 workers uses 259s of CPU over 57s of wall clock, i.e. roughly
 * half the box, because each worker spends a large share of its time waiting
 * rather than computing. Running them in sequence leaves most of the machine
 * idle for most of the run.
 *
 * Measured on 8 cores (master e1e7118 plus the test:cli --parallel change):
 *
 *   test:lightning alone      55.6s   6211 passing
 *   test:cli alone            50.5s   1359 passing
 *   both, this script         77.1s   7570 passing
 *
 * Against the scripts as they shipped before this change (test:cli serial at
 * 140.0s), the same two suites in sequence were 195.6s.
 *
 * test:chaos is deliberately NOT here, and that is a measured decision rather
 * than an oversight. Its cases carry real wall-clock budgets that do not care
 * how loaded the box is: chaosWait defaults to 15s (helpers/chaos-harness.ts),
 * the quorum barrier to 20s, and helpers/chaos-quorum.ts's waitFor to 10s.
 * Sharing the machine ate one of them. Running all three concurrently failed
 * on the second attempt with
 *
 *   refusal then kill: a barrier timeout freezes, and dying frozen still
 *   resumes exactly:  Error: chaosWait timed out with the victim alive
 *
 * while the same suite passes 30/30 on its own, twice. A flaky gate is worse
 * than a slow one, so chaos keeps the box to itself: run `npm run test:chaos`
 * separately.
 *
 * Worker split. More workers is not better: each mocha worker re-transpiles the
 * src tree independently with no cross-process cache, so raising --jobs buys
 * overlap at about 15s of extra CPU per worker. Measured on the lightning
 * suite, wall clock is flat from 4 to 7 workers and then degrades (jobs 12 =
 * 66s, jobs 16 = 82s). The split below keeps the total near the core count
 * rather than double it: on 8 cores that is 4 workers for lightning and 3
 * for cli.
 *
 * Output is captured per suite rather than interleaved, because two mocha
 * reporters writing to one terminal is unreadable. A failing suite prints its
 * own tail so the failure is actionable without a re-run.
 */

// Plain CommonJS, matching scripts/wait-for-electrum.js: the scripts directory
// is not compiled, and the package has no "type": "module".
/* eslint-disable @typescript-eslint/no-var-requires */
const { spawn } = require('child_process');
const os = require('os');
const path = require('path');

const cpus = os.cpus().length || 4;
const share = (fraction, cap) =>
	Math.max(1, Math.min(cap, Math.round(cpus * fraction)));

const MOCHA = path.join(
	__dirname,
	'..',
	'node_modules',
	'.bin',
	process.platform === 'win32' ? 'mocha.cmd' : 'mocha'
);

const SUITES = [
	{
		name: 'lightning',
		expected: 6211,
		args: [
			'--exit',
			'--parallel',
			'--jobs',
			String(share(0.5, 8)),
			'--timeout',
			'20000',
			'-r',
			'ts-node/register',
			'--ignore',
			'tests/lightning/interop/**',
			'--ignore',
			'tests/lightning/recovery-phase7-*.test.ts',
			'tests/lightning/**/*.test.ts'
		]
	},
	{
		name: 'cli',
		expected: 1359,
		args: [
			'--exit',
			'--parallel',
			'--jobs',
			String(share(0.35, 6)),
			'--timeout',
			'20000',
			'-r',
			'ts-node/register',
			'--ignore',
			'tests/cli/daemon-security.test.ts',
			'--ignore',
			'tests/cli/daemon-integration.test.ts',
			'tests/cli/**/*.test.ts'
		]
	}
];

function run(suite) {
	return new Promise((resolve) => {
		const started = Date.now();
		const child = spawn(MOCHA, suite.args, {
			cwd: path.join(__dirname, '..'),
			stdio: ['ignore', 'pipe', 'pipe']
		});
		let out = '';
		child.stdout.on('data', (c) => {
			out += c.toString();
		});
		child.stderr.on('data', (c) => {
			out += c.toString();
		});
		child.on('error', (err) => {
			resolve({ suite, code: 1, out: String(err), seconds: 0, passing: null });
		});
		child.on('close', (code) => {
			const seconds = (Date.now() - started) / 1000;
			const match = out.match(/(\d+) passing/);
			const passing = match ? Number(match[1]) : null;
			const label = code === 0 ? 'ok  ' : 'FAIL';
			// eslint-disable-next-line no-console
			console.log(
				`${label} ${suite.name.padEnd(10)} ${seconds
					.toFixed(1)
					.padStart(6)}s  ${passing === null ? '?' : passing} passing`
			);
			resolve({ suite, code, out, seconds, passing });
		});
	});
}

async function main() {
	const started = Date.now();
	// eslint-disable-next-line no-console
	console.log(
		`Running ${SUITES.length} suites concurrently on ${cpus} cores: ` +
			SUITES.map(
				(s) => `${s.name}(${s.args[s.args.indexOf('--jobs') + 1]})`
			).join(' ')
	);

	const results = await Promise.all(SUITES.map(run));
	const wall = (Date.now() - started) / 1000;

	const failed = results.filter((r) => r.code !== 0);
	for (const r of failed) {
		// eslint-disable-next-line no-console
		console.log(`\n===== ${r.suite.name} output (tail) =====`);
		// eslint-disable-next-line no-console
		console.log(r.out.split('\n').slice(-80).join('\n'));
	}

	// A suite can exit 0 while having quietly stopped running tests, so the count
	// is checked too. The repo has no .only and no skipped tests, which is what
	// makes these numbers a usable invariant. The comparison is "at least", so
	// adding tests needs no change here; only losing them trips it, and then the
	// floor in SUITES is meant to be updated deliberately rather than silently.
	const short = results.filter(
		(r) => r.code === 0 && (r.passing === null || r.passing < r.suite.expected)
	);
	for (const r of short) {
		// eslint-disable-next-line no-console
		console.log(
			r.passing === null
				? `\nWARNING ${r.suite.name}: exited 0 but no "N passing" line was ` +
						`found. The reporter output was not what this script expects.`
				: `\nWARNING ${r.suite.name}: ${r.passing} passing, expected at least ` +
						`${r.suite.expected}. Either tests were silently elided, or the ` +
						`floor in scripts/run-suites.js needs updating on purpose.`
		);
	}

	// eslint-disable-next-line no-console
	console.log(`\ntotal ${wall.toFixed(1)}s`);
	process.exit(failed.length || short.length ? 1 : 0);
}

main();
