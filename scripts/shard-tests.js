#!/usr/bin/env node
/**
 * Run `test:lightning` as N shards, one CI job each.
 *
 *   node scripts/shard-tests.js --shards 4 --shard 2   run shard 2 of 4
 *   node scripts/shard-tests.js --shards 4 --list      print every shard's files
 *   node scripts/shard-tests.js --shards 4 --verify    exit 1 unless every file
 *                                                      lands exactly once
 *   node scripts/shard-tests.js --regtest              run the files the shards
 *                                                      leave to the regtest job
 *   node scripts/shard-tests.js --update <report.json> rewrite the duration map
 *                                                      from a mocha json report
 *
 * The file set, the ignores and the mocha flags are read from the
 * `test:lightning` script in package.json, so a shard runs exactly what that
 * script would run on the same files. Files are resolved with mocha's own
 * collect-files, so the set is mocha's, not an approximation of its globbing.
 *
 * Shards are filled from scripts/test-durations.json, heaviest file first, each
 * to the shard with the least time so far. A file the map does not list weighs
 * UNLISTED_SECONDS, so a new file is placed rather than dropped. Ties break on
 * path, so the assignment depends only on the file set and the map.
 *
 * A shard passes mocha an explicit file list, heaviest first. Mocha dispatches
 * files to workers in argument order and does not dedupe spec arguments, so
 * the list must never mix a glob with files it also matches.
 *
 * To refresh the map: run the suite with `--reporter json --reporter-option
 * output=report.json` added, then `node scripts/shard-tests.js --update
 * report.json`.
 */

// Plain CommonJS, matching scripts/run-suites.js: the scripts directory is not
// compiled, and the package has no "type": "module".
/* eslint-disable @typescript-eslint/no-var-requires */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const collectFiles = require('mocha/lib/cli/collect-files');

const ROOT = path.join(__dirname, '..');
const DURATIONS = path.join(__dirname, 'test-durations.json');
const MOCHA = path.join(
	ROOT,
	'node_modules',
	'.bin',
	process.platform === 'win32' ? 'mocha.cmd' : 'mocha'
);

/**
 * In the test:lightning set but not in any shard: the regtest job runs them,
 * since they need its bitcoind and Electrum (wallet-funding-provider throws
 * when CI is set and the stack is unreachable).
 */
const REGTEST_FILES = [
	'tests/lightning/integration/wallet-funding-provider.test.ts'
];

const UNLISTED_SECONDS = 10;
/** Load and transpile cost of a file, on top of its reported test time. */
const PER_FILE_SECONDS = 2;

function lightningScript() {
	const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json')));
	const tokens = pkg.scripts['test:lightning']
		.match(/'[^']*'|\S+/g)
		.map((t) => t.replace(/^'|'$/g, ''));
	if (tokens[0] !== 'npx' || tokens[1] !== 'mocha') {
		throw new Error('test:lightning no longer starts with `npx mocha`');
	}
	const flags = [];
	const ignore = [];
	const spec = [];
	for (let i = 2; i < tokens.length; i++) {
		if (tokens[i] === '--ignore') ignore.push(tokens[++i]);
		else if (tokens[i].endsWith('.ts')) spec.push(tokens[i]);
		else flags.push(tokens[i]);
	}
	return { flags, ignore, spec };
}

function lightningFiles() {
	const { ignore, spec } = lightningScript();
	const cwd = process.cwd();
	process.chdir(ROOT);
	try {
		const { files } = collectFiles({
			ignore,
			extension: ['ts'],
			file: [],
			recursive: false,
			sort: true,
			spec
		});
		return files.map((f) => path.relative(ROOT, f).split(path.sep).join('/'));
	} finally {
		process.chdir(cwd);
	}
}

function plan(shards) {
	const durations = JSON.parse(fs.readFileSync(DURATIONS, 'utf8'));
	const weight = (f) => (durations[f] ?? UNLISTED_SECONDS) + PER_FILE_SECONDS;
	const files = lightningFiles()
		.filter((f) => !REGTEST_FILES.includes(f))
		.sort((a, b) => weight(b) - weight(a) || (a < b ? -1 : 1));
	const out = Array.from({ length: shards }, () => ({ files: [], seconds: 0 }));
	for (const f of files) {
		let best = 0;
		for (let i = 1; i < shards; i++) {
			if (out[i].seconds < out[best].seconds) best = i;
		}
		out[best].files.push(f);
		out[best].seconds += weight(f);
	}
	return out;
}

function verify(shards) {
	const all = lightningFiles();
	const placed = new Map(all.map((f) => [f, []]));
	const problems = [];
	plan(shards).forEach((s, i) => {
		for (const f of s.files) {
			if (!placed.has(f))
				problems.push(`${f}: in shard ${i + 1} but not in test:lightning`);
			else placed.get(f).push(`shard ${i + 1}`);
		}
	});
	for (const f of REGTEST_FILES) {
		if (!placed.has(f))
			problems.push(
				`${f}: listed for the regtest job but not in test:lightning`
			);
		else placed.get(f).push('regtest');
	}
	for (const [f, where] of placed) {
		if (where.length !== 1) {
			problems.push(
				`${f}: in ${where.length === 0 ? 'no shard' : where.join(' and ')}`
			);
		}
	}
	if (problems.length > 0) {
		console.error(problems.join('\n'));
		process.exit(1);
	}
	console.log(
		`${all.length} test:lightning files: ${
			all.length - REGTEST_FILES.length
		} across ${shards} shards, ${
			REGTEST_FILES.length
		} in the regtest job, each once`
	);
}

function run(files) {
	const { flags } = lightningScript();
	const r = spawnSync(MOCHA, [...flags, ...files], {
		cwd: ROOT,
		stdio: 'inherit'
	});
	if (r.error) throw r.error;
	process.exit(r.status ?? 1);
}

function update(report) {
	const json = JSON.parse(fs.readFileSync(report, 'utf8'));
	const totals = {};
	for (const t of json.tests) {
		const f = path.relative(ROOT, t.file).split(path.sep).join('/');
		totals[f] = (totals[f] ?? 0) + (t.duration ?? 0) / 1000;
	}
	const sorted = {};
	for (const f of Object.keys(totals).sort()) sorted[f] = Math.round(totals[f]);
	fs.writeFileSync(DURATIONS, `${JSON.stringify(sorted, null, '\t')}\n`);
	console.log(`wrote ${Object.keys(sorted).length} files to ${DURATIONS}`);
}

function arg(name) {
	const i = process.argv.indexOf(name);
	return i === -1 ? undefined : process.argv[i + 1];
}

function main() {
	if (process.argv.includes('--update')) return update(arg('--update'));
	if (process.argv.includes('--regtest')) return run(REGTEST_FILES);
	const shards = Number(arg('--shards'));
	if (!Number.isInteger(shards) || shards < 1) {
		throw new Error('--shards <n> is required');
	}
	if (process.argv.includes('--verify')) return verify(shards);
	const planned = plan(shards);
	if (process.argv.includes('--list')) {
		planned.forEach((s, i) => {
			console.log(
				`shard ${i + 1}: ${s.files.length} files, ~${Math.round(s.seconds)}s`
			);
			for (const f of s.files) console.log(`  ${f}`);
		});
		return;
	}
	const shard = Number(arg('--shard'));
	if (!Number.isInteger(shard) || shard < 1 || shard > shards) {
		throw new Error(`--shard must be 1 to ${shards}`);
	}
	const { files, seconds } = planned[shard - 1];
	console.log(
		`shard ${shard} of ${shards}: ${files.length} files, ~${Math.round(
			seconds
		)}s of reported test time`
	);
	run(files);
}

main();
