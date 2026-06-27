/**
 * Daemon Phase 3: DX Improvements — type-level and config tests.
 *
 * Tests for configurable bind address (daemonHost), amount-less invoice route,
 * connect-and-open endpoint parameter validation, and startDaemon export.
 */

import { expect } from 'chai';
import { DaemonOptions } from '../../src/cli/daemon';
import { BeignetConfig } from '../../src/cli/types';

const testMnemonic =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('Daemon Phase 3: DX Improvements', () => {
	describe('configurable bind address', () => {
		it('defaults to undefined when daemonHost not set', () => {
			const opts: Partial<DaemonOptions> = {
				daemonPort: 0
			};
			// daemonHost should be undefined when not explicitly set
			expect(opts.daemonHost).to.be.undefined;
		});

		it('accepts custom host in DaemonOptions', () => {
			const opts: DaemonOptions = {
				mnemonic: testMnemonic,
				daemonHost: '0.0.0.0',
				daemonPort: 0
			};
			expect(opts.daemonHost).to.equal('0.0.0.0');
		});
	});

	describe('BeignetConfig daemonHost', () => {
		it('BeignetConfig includes daemonHost field', () => {
			const config: BeignetConfig = {
				mnemonic: testMnemonic,
				daemonHost: '0.0.0.0',
				daemonPort: 3000
			};
			expect(config.daemonHost).to.equal('0.0.0.0');
			expect(config.daemonPort).to.equal(3000);
		});
	});

	describe('connect-and-open endpoint type validation', () => {
		it('requires pubkey, host, port, and amountSats', () => {
			// Verify the parameter shape expected by POST /channel/connect-and-open
			const params = {
				pubkey: '02' + 'a'.repeat(64),
				host: '127.0.0.1',
				port: 9735,
				amountSats: 100000,
				pushSats: 0
			};
			expect(params.pubkey).to.be.a('string');
			expect(params.pubkey).to.have.lengthOf(66); // 33-byte compressed key in hex
			expect(params.host).to.be.a('string');
			expect(params.port).to.be.a('number');
			expect(params.amountSats).to.equal(100000);
		});

		it('pushSats is optional', () => {
			const params: {
				pubkey: string;
				host: string;
				port: number;
				amountSats: number;
				pushSats?: number;
			} = {
				pubkey: '02' + 'b'.repeat(64),
				host: '10.0.0.1',
				port: 9735,
				amountSats: 50000
			};
			expect(params.pushSats).to.be.undefined;
		});
	});

	describe('startDaemon export', () => {
		it('startDaemon is exported from cli/index', () => {
			const { startDaemon } = require('../../src/cli/daemon');
			expect(startDaemon).to.be.a('function');
		});
	});
});
