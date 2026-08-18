/**
 * Regression: `beignet --help` must exit.
 *
 * It printed the help text and then hung forever, because a module-level
 * setInterval in src/utils/electrum.ts started an Electrum connection poll at
 * import time and nothing ever cleared or unref'd it. The first command a new
 * user runs had to be killed. This spawns the real CLI rather than asserting on
 * that one timer, so any future load-time handle is caught the same way.
 */

import { expect } from 'chai';
import { spawn } from 'child_process';
import * as path from 'path';

describe('beignet --help', function () {
	// ts-node has to load the CLI and everything it imports in the child.
	this.timeout(120_000);

	it('prints the help text and exits', async function () {
		const repoRoot = path.resolve(__dirname, '..', '..');
		const child = spawn(
			process.execPath,
			['-r', 'ts-node/register', path.join('src', 'cli', 'cli.ts'), '--help'],
			{ cwd: repoRoot, stdio: ['ignore', 'pipe', 'pipe'] }
		);

		let stdout = '';
		let stderr = '';
		child.stdout.on('data', (chunk: Buffer) => {
			stdout += chunk.toString();
		});
		child.stderr.on('data', (chunk: Buffer) => {
			stderr += chunk.toString();
		});

		// `close` rather than `exit`: exit can fire while stdout and stderr are
		// still draining, which would let the assertions below read a partial
		// help text. The kill deadline sits comfortably under the mocha timeout,
		// so a regression reports what actually happened instead of an opaque
		// suite timeout.
		const result = await new Promise<{
			code: number | null;
			hung: boolean;
		}>((resolve) => {
			const killer = setTimeout(() => {
				child.kill('SIGKILL');
				resolve({ code: null, hung: true });
			}, 90_000);
			child.once('close', (code) => {
				clearTimeout(killer);
				resolve({ code, hung: false });
			});
		});

		expect(
			result.hung,
			`the CLI printed help and never exited. stderr: ${stderr}`
		).to.equal(false);
		expect(result.code, `the CLI exited non-zero. stderr: ${stderr}`).to.equal(
			0
		);
		expect(stdout).to.include('beignet - AI-friendly Bitcoin + Lightning CLI');
	});
});
