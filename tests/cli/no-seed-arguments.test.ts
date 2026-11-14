/**
 * No script, example or CLI command takes a seed phrase as a command-line
 * argument (issues #2024, #2065). An argument lands in the shell history, in
 * the process list for every local user while the command runs, and in
 * terminal scrollback. The CLI reads the mnemonic from the config file or
 * BEIGNET_MNEMONIC, and the README examples from BEIGNET_MNEMONIC.
 *
 * Mostly a source scan: scripts/ and the CLI's usage text cannot be exercised
 * as one command each, and the detector is checked against the script it
 * replaced. The two example REPLs are run for real, with wallet creation
 * intercepted, because a line scan cannot follow argv into a mnemonic built
 * across several lines.
 */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assertDistCliFresh } from './helpers/dist-cli';

const ROOT = path.resolve(__dirname, '..', '..');

/** A usage line or flag that names a seed as an argument. */
const SEED_ARGUMENT =
	/<\s*(mnemonic|seed|words)\b[^>]*>|--(mnemonic|seed|seed-phrase|words)\b/i;
/** A mnemonic built from the process arguments. */
const SEED_FROM_ARGV =
	/\bmnemonic\w*\s*[:=][^;\n]*\b(process\.argv|argv|args|positional|filteredArgs)\b/i;

/** A placeholder standing for seed words, as in `<YOUR MNEMONIC>`. */
const SEED_PLACEHOLDER = /<[^>]*\b(mnemonic|seed|words)\b[^>]*>/i;

function offendingLines(source: string): string[] {
	return source
		.split('\n')
		.filter((line) => SEED_ARGUMENT.test(line) || SEED_FROM_ARGV.test(line));
}

/**
 * Lines of the example docs that hand an example a seed: a placeholder in a
 * command or a flag-table row, or a quoted argument to `npm run example` that
 * is not an option's value.
 */
function exampleDocProblems(doc: string): string[] {
	return doc.split('\n').filter((line) => {
		const runs = /\bnpm run example\b/.test(line);
		if (!runs && !/^\s*\|/.test(line)) return false;
		if (SEED_PLACEHOLDER.test(line)) return true;
		return runs && line.replace(/--[\w-]+\s+"[^"]*"/g, '').includes('"');
	});
}

function scriptFiles(dir: string): string[] {
	const out: string[] = [];
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) out.push(...scriptFiles(full));
		else if (/\.(ts|js|cjs|mjs|sh)$/.test(entry.name)) out.push(full);
	}
	return out;
}

describe('no seed phrase on the command line', () => {
	it('catches the shape of the removed force-close script', () => {
		const removed = [
			' *   npx ts-node scripts/force-close-stuck-channel.ts <mnemonic...> <channelIdHex> \\',
			"\tconst mnemonic = positional.slice(0, -1).join(' ');"
		].join('\n');
		expect(offendingLines(removed)).to.have.length(2);
		expect(offendingLines("const m = parseFlag('--mnemonic');")).to.have.length(
			1
		);
	});

	it('takes no seed argument in any script under scripts/ or example/', () => {
		const found: string[] = [];
		const files = ['scripts', 'example'].flatMap((dir) =>
			scriptFiles(path.join(ROOT, dir))
		);
		for (const file of files) {
			for (const line of offendingLines(fs.readFileSync(file, 'utf8'))) {
				found.push(`${path.relative(ROOT, file)}: ${line.trim()}`);
			}
		}
		expect(found).to.deep.equal([]);
	});

	it('takes no seed argument in any CLI command or usage text', () => {
		const cli = fs.readFileSync(
			path.join(ROOT, 'src', 'cli', 'cli.ts'),
			'utf8'
		);
		expect(offendingLines(cli)).to.deep.equal([]);
		// Nothing on the command line becomes the mnemonic the config resolves.
		expect(cli).to.not.match(/cliFlags\.mnemonic\s*=/);
		expect(cli).to.not.match(/resolveConfig\(\s*\{[^}]*\bmnemonic\b/);
	});

	it('is not taught by the CLI README', () => {
		const readme = fs.readFileSync(
			path.join(ROOT, 'src', 'cli', 'README.md'),
			'utf8'
		);
		const usage = readme
			.split('\n')
			.filter((line) => /^\s*(\$ )?(npx )?beignet\b/.test(line));
		expect(usage.filter((line) => SEED_ARGUMENT.test(line))).to.deep.equal([]);
	});

	it('catches the example usage the docs used to teach', () => {
		const removed = [
			'npm run example:lightning -- "<YOUR MNEMONIC>" mainnet --alias "Beignet Lightning"',
			'Pass a mnemonic to reuse a wallet: `npm run example -- "abandon abandon ... about"`.',
			'| `<12 or 24 words>` | Reuse a mnemonic, as bare positional args (default generates one) |'
		].join('\n');
		expect(exampleDocProblems(removed)).to.have.length(3);
		expect(
			exampleDocProblems(
				'npm run example:lightning -- mainnet --alias "Beignet Lightning"'
			)
		).to.deep.equal([]);
	});

	it('is not taught by the README or the example walkthrough', () => {
		const found: string[] = [];
		for (const doc of ['README.md', path.join('example', 'REPL_TESTING.md')]) {
			const text = fs.readFileSync(path.join(ROOT, doc), 'utf8');
			for (const line of exampleDocProblems(text)) {
				found.push(`${doc}: ${line.trim()}`);
			}
		}
		expect(found).to.deep.equal([]);
	});
});

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/**
 * Replaces the factory an example hands its mnemonic to. The stub records the
 * mnemonic in a file and ends the process, so nothing reaches the network.
 */
const CREATE_PROBE = `
const fs = require('fs');
const target = require(process.env.SEED_PROBE_MODULE)[process.env.SEED_PROBE_CLASS];
target.create = async (options) => {
	fs.writeFileSync(process.env.SEED_PROBE_OUT, JSON.stringify({ mnemonic: options.mnemonic }));
	process.exit(0);
};
`;

/** Each README example and the class whose create() receives the mnemonic. */
const EXAMPLES = [
	{
		entry: path.join('example', 'index.ts'),
		module: path.join(ROOT, 'src', 'wallet', 'index.ts'),
		className: 'Wallet'
	},
	{
		// Imports beignet/cli, which resolves to the build.
		entry: path.join('example', 'lightning.ts'),
		module: path.join(ROOT, 'dist', 'cli', 'beignet-node.js'),
		className: 'BeignetNode'
	}
];

// As in .mocharc.js: Node's own type stripping would bypass ts-node.
const NO_STRIP = ['--no-strip-types', '--no-experimental-strip-types'].find(
	(flag) => process.allowedNodeEnvironmentFlags.has(flag)
);

describe('example REPLs take no seed phrase on the command line', function () {
	// Each run loads the example through ts-node, and the on-chain one all of
	// src: a few seconds alone, far longer beside the parallel suite.
	this.timeout(60_000);

	let tmp: string;
	let probe: string;
	let runs = 0;

	before(() => {
		assertDistCliFresh();
		tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'no-seed-example-'));
		probe = path.join(tmp, 'probe.js');
		fs.writeFileSync(probe, CREATE_PROBE);
	});

	after(() => fs.rmSync(tmp, { recursive: true, force: true }));

	async function run(
		example: (typeof EXAMPLES)[number],
		args: string[],
		mnemonic?: string
	): Promise<{ code: number | null; output: string; created?: string }> {
		const out = path.join(tmp, `created-${++runs}.json`);
		const env: NodeJS.ProcessEnv = {
			...process.env,
			HOME: tmp,
			SEED_PROBE_MODULE: example.module,
			SEED_PROBE_CLASS: example.className,
			SEED_PROBE_OUT: out,
			// tsconfig sets allowJs, so ts-node would transpile all of dist/
			// again (about 18 s) when the Lightning example imports beignet.
			TS_NODE_IGNORE: '(?:^|/)node_modules/,(?:^|/)dist/'
		};
		delete env.BEIGNET_MNEMONIC;
		if (mnemonic) env.BEIGNET_MNEMONIC = mnemonic;
		const child = spawn(
			process.execPath,
			[
				...(NO_STRIP ? [NO_STRIP] : []),
				'-r',
				'ts-node/register',
				'-r',
				probe,
				example.entry,
				...args
			],
			{ cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] }
		);
		let output = '';
		child.stdout.on('data', (chunk) => (output += chunk));
		child.stderr.on('data', (chunk) => (output += chunk));
		const code = await new Promise<number | null>((resolve) =>
			child.on('close', resolve)
		);
		const created = fs.existsSync(out)
			? (JSON.parse(fs.readFileSync(out, 'utf8')) as { mnemonic: string })
					.mnemonic
			: undefined;
		return { code, output, created };
	}

	for (const example of EXAMPLES) {
		describe(example.entry, () => {
			it('refuses a mnemonic passed as an argument, without echoing it', async () => {
				const result = await run(example, [MNEMONIC, 'regtest']);
				expect(result.created, result.output).to.equal(undefined);
				expect(result.code, result.output).to.equal(1);
				expect(result.output).to.include('BEIGNET_MNEMONIC');
				expect(result.output).to.not.include('abandon');
			});

			it('creates the wallet from BEIGNET_MNEMONIC without printing it', async () => {
				const result = await run(example, ['regtest'], MNEMONIC);
				expect(result.created, result.output).to.equal(MNEMONIC);
				expect(result.code, result.output).to.equal(0);
				expect(result.output).to.not.include('abandon');
			});
		});
	}
});
