/**
 * Daemon log level configuration (M6 leveled logging) — offline tests.
 *
 * Covers resolveConfig precedence and validation for logLevel:
 * CLI flag > BEIGNET_LOG_LEVEL env var > config file, with invalid values
 * ignored so a typo can never crash the daemon or enable unexpected output.
 */

import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';

describe('resolveConfig logLevel', () => {
	afterEach(() => {
		delete process.env.BEIGNET_LOG_LEVEL;
	});

	it('resolves logLevel from the CLI flag', () => {
		const resolved = resolveConfig({ logLevel: 'debug' });
		expect(resolved.logLevel).to.equal('debug');
	});

	it('resolves logLevel from BEIGNET_LOG_LEVEL env var', () => {
		process.env.BEIGNET_LOG_LEVEL = 'warn';
		const resolved = resolveConfig({});
		expect(resolved.logLevel).to.equal('warn');
	});

	it('prefers the CLI flag over the env var', () => {
		process.env.BEIGNET_LOG_LEVEL = 'warn';
		const resolved = resolveConfig({ logLevel: 'error' });
		expect(resolved.logLevel).to.equal('error');
	});

	it('accepts every valid level', () => {
		const levels = ['debug', 'info', 'warn', 'error', 'silent'] as const;
		for (const level of levels) {
			const resolved = resolveConfig({ logLevel: level });
			expect(resolved.logLevel).to.equal(level);
		}
	});

	it('ignores an invalid env var value', () => {
		process.env.BEIGNET_LOG_LEVEL = 'verbose';
		const resolved = resolveConfig({});
		expect(resolved.logLevel).to.equal(undefined);
	});

	it('ignores an invalid CLI flag value', () => {
		const resolved = resolveConfig({
			logLevel: 'loud' as unknown as 'debug'
		});
		expect(resolved.logLevel).to.equal(undefined);
	});
});
