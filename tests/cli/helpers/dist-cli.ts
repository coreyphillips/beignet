/**
 * The built CLI, for tests that spawn `beignet` as a real child process.
 *
 * Loading src/cli/cli.ts through ts-node cost 10-12 s per child, against
 * about 0.4 s for the compiled file, and those spawns were most of the CLI
 * suite's time (issue #605). The compiled file is also what `bin` ships. A
 * spawning file calls assertDistCliFresh() in a `before` hook, so a missing or
 * out-of-date build fails there by name instead of testing old code.
 */

import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');

/** Absolute path of the compiled CLI entry: spawn it with process.execPath. */
export const DIST_CLI = path.join(REPO_ROOT, 'dist', 'cli', 'cli.js');

/** undefined until checked, then null when fresh or the failure message. */
let verdict: string | null | undefined;

function checkDistCli(): string | null {
	let builtAt: number;
	try {
		builtAt = fs.statSync(DIST_CLI).mtimeMs;
	} catch {
		return 'dist/cli/cli.js is missing: run `npm run build` before test:cli';
	}
	// The whole tree, not just src/cli: the CLI imports the library.
	const src = path.join(REPO_ROOT, 'src');
	let newest: { file: string; mtimeMs: number } | undefined;
	let newer = 0;
	for (const file of fs.readdirSync(src, {
		encoding: 'utf8',
		recursive: true
	})) {
		if (!file.endsWith('.ts')) continue;
		const { mtimeMs } = fs.statSync(path.join(src, file));
		if (mtimeMs <= builtAt) continue;
		newer++;
		if (!newest || mtimeMs > newest.mtimeMs) newest = { file, mtimeMs };
	}
	if (!newest) return null;
	const rest = newer - 1;
	const others = rest
		? ` and ${rest} other src file${rest === 1 ? '' : 's'}`
		: '';
	return (
		'dist/cli/cli.js is stale: run `npm run build` before test:cli ' +
		`(${path.join('src', newest.file)}${others} changed after the last build)`
	);
}

/**
 * Throws when dist/cli/cli.js is missing or older than any .ts file under
 * src/. The stat walk runs once per process and its verdict is reused.
 */
export function assertDistCliFresh(): void {
	if (verdict === undefined) verdict = checkDistCli();
	if (verdict !== null) throw new Error(verdict);
}
