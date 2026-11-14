/**
 * No script or CLI command takes a seed phrase as a command-line argument
 * (issue #2024). An argument lands in the shell history, in the process list
 * for every local user while the command runs, and in terminal scrollback.
 * The CLI reads the mnemonic from the config file or BEIGNET_MNEMONIC.
 *
 * A source scan: scripts/ and the CLI's usage text cannot be exercised as one
 * command each, and the detector is checked against the script it replaced.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..', '..');

/** A usage line or flag that names a seed as an argument. */
const SEED_ARGUMENT =
	/<\s*(mnemonic|seed|words)\b[^>]*>|--(mnemonic|seed|seed-phrase|words)\b/i;
/** A mnemonic built from the process arguments. */
const SEED_FROM_ARGV =
	/\bmnemonic\w*\s*[:=][^;\n]*\b(process\.argv|argv|args|positional|filteredArgs)\b/i;

function offendingLines(source: string): string[] {
	return source
		.split('\n')
		.filter((line) => SEED_ARGUMENT.test(line) || SEED_FROM_ARGV.test(line));
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

	it('takes no seed argument in any script under scripts/', () => {
		const found: string[] = [];
		for (const file of scriptFiles(path.join(ROOT, 'scripts'))) {
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
});
