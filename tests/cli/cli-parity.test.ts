/**
 * CLI <-> daemon parity (M4 batch 2b): every daemon route must be reachable
 * from a CLI command. The check is source-derived so a new route added to
 * daemon.ts without a CLI wrapper fails this suite.
 */

import * as fs from 'fs';
import * as path from 'path';
import { expect } from 'chai';

const daemonSrc = fs.readFileSync(
	path.join(__dirname, '../../src/cli/daemon.ts'),
	'utf8'
);
const cliSrc = fs.readFileSync(
	path.join(__dirname, '../../src/cli/cli.ts'),
	'utf8'
);

/**
 * Routes that intentionally have no CLI command (documented in
 * src/cli/README.md):
 * - GET /events: SSE stream for long-lived HTTP consumers; CLI users register
 *   webhooks instead.
 * - GET /openapi.json: machine-readable API discovery for HTTP clients.
 * - POST /channel/update-fee: deprecated alias of
 *   /channel/update-commitment-feerate, which has the CLI command.
 */
const INTENTIONALLY_NO_CLI = new Set([
	'/events',
	'/openapi.json',
	'/channel/update-fee'
]);

/** All route paths declared in the daemon routes map (plus special routes). */
function daemonRoutePaths(): string[] {
	const paths = new Set<string>();
	const re = /'(GET|POST|DELETE) (\/[^']+)'/g;
	let m: RegExpExecArray | null;
	while ((m = re.exec(daemonSrc)) !== null) {
		paths.add(m[2]);
	}
	// /stop and /events are handled outside the routes map
	paths.add('/stop');
	paths.add('/events');
	paths.add('/metrics');
	return [...paths];
}

/**
 * All daemon paths the CLI can hit: string/template literals passed to
 * httpRequest plus the raw /metrics request, normalized by stripping query
 * strings and template interpolations.
 */
function cliRequestPaths(): Set<string> {
	const paths = new Set<string>();
	const literalRe = /['"`](\/[a-z0-9\-/_.]*)[?'"`$]/gi;
	let m: RegExpExecArray | null;
	while ((m = literalRe.exec(cliSrc)) !== null) {
		const p = m[1].replace(/\/$/, '');
		if (p.length > 1) paths.add(p);
	}
	return paths;
}

describe('CLI parity with daemon routes (M4 batch 2b)', () => {
	it('every daemon route has a CLI command (or a documented exception)', () => {
		const cliPaths = cliRequestPaths();
		const missing = daemonRoutePaths().filter(
			(p) => !INTENTIONALLY_NO_CLI.has(p) && !cliPaths.has(p)
		);
		expect(
			missing,
			`daemon routes without a CLI command: ${missing.join(', ')}`
		).to.deep.equal([]);
	});

	it('documented exceptions are not silently wrapped (keep the list honest)', () => {
		const cliPaths = cliRequestPaths();
		for (const p of INTENTIONALLY_NO_CLI) {
			expect(
				cliPaths.has(p),
				`${p} now has a CLI wrapper; update this list`
			).to.equal(false);
		}
	});

	describe('new commands are dispatched and documented in help', () => {
		const topLevel = [
			'keysend',
			'liquidity',
			'fees',
			'spend-limit',
			'logs',
			'can-send',
			'can-receive',
			'wallet',
			'node',
			'webhooks',
			'queue',
			'ready'
		];
		const subcommands = [
			// invoice
			"'validate'",
			"'pay-safe'",
			"'pay-async'",
			// payment
			"'cancel'",
			"'wait'",
			"'proof'",
			"'verify-proof'",
			"'estimate'",
			"'metadata'",
			// route
			"'probe'",
			// channel
			"'update-commitment-feerate'",
			"'health'",
			"'suggestions'",
			"'connect-and-open'",
			"'open-and-wait'",
			"'wait-ready'",
			"'policy'",
			// offer
			"'decode'",
			// webhooks
			"'register'",
			"'unregister'"
		];

		it('top-level commands have switch cases', () => {
			for (const cmd of topLevel) {
				expect(cliSrc, cmd).to.include(`case '${cmd}':`);
			}
		});

		it('subcommands have switch cases', () => {
			for (const sub of subcommands) {
				expect(cliSrc, sub).to.include(`case ${sub}:`);
			}
		});

		it('help text mentions the new commands', () => {
			const helpStart = cliSrc.indexOf('function printHelp');
			const help = cliSrc.substring(helpStart);
			for (const cmd of [
				'keysend',
				'liquidity',
				'spend-limit',
				'can-send',
				'can-receive',
				'wallet refresh',
				'node uri',
				'node wait-ready',
				'webhooks register',
				'queue add',
				'invoice validate',
				'invoice pay-safe',
				'invoice pay-async',
				'payment cancel',
				'payment wait',
				'payment proof',
				'payment verify-proof',
				'payment estimate',
				'payment metadata',
				'route estimate',
				'route probe',
				'offer decode',
				'channel update-commitment-feerate',
				'channel health',
				'channel suggestions',
				'channel connect-and-open',
				'channel open-and-wait',
				'channel wait-ready',
				'channel ready',
				'channel policy'
			]) {
				expect(help, cmd).to.include(cmd);
			}
		});

		it('--htlc-events start flag is wired and documented', () => {
			expect(cliSrc).to.include("hasFlag('--htlc-events')");
			expect(cliSrc).to.include('htlcEvents: config.htlcEvents');
			expect(cliSrc).to.include('--htlc-events ');
		});
	});
});
