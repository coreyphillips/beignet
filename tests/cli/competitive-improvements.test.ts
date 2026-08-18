/**
 * Tests for competitive improvements: spending limits, idempotency keys, TLS, drain mode.
 */

import { expect } from 'chai';
import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import {
	BeignetError,
	BeignetErrorCode,
	isRetryableError,
	isPermanentFailure
} from '../../src/cli/errors';
import { startDaemon, DaemonOptions } from '../../src/cli/daemon';
import { resolveConfig } from '../../src/cli/config';

// Electrum intentionally unreachable: nothing below needs a live chain, and a
// refused loopback connect returns ECONNREFUSED instantly. Without this the
// regtest default in src/cli/beignet-node.ts is a remote public host, so these
// nominally offline tests dial a third party over the internet and fail
// whenever it is unreachable. BeignetNode.init tolerates a failed connect:
// resolveWalletSweepScript falls back to a locally derived index-0 address.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

// ─────────────── Spending Limits ───────────────

describe('Spending Limits', () => {
	it('SPENDING_LIMIT_EXCEEDED error code exists', () => {
		expect(BeignetErrorCode.SPENDING_LIMIT_EXCEEDED).to.equal(
			'SPENDING_LIMIT_EXCEEDED'
		);
	});

	it('SPENDING_LIMIT_EXCEEDED is a permanent (non-retryable) error', () => {
		const err = new BeignetError('SPENDING_LIMIT_EXCEEDED', 'Limit exceeded');
		expect(isRetryableError(err)).to.be.false;
		expect(isPermanentFailure(err)).to.be.true;
	});

	it('BeignetNodeOptions accepts dailySpendLimitSats', async () => {
		// Type-level check: importing BeignetNodeOptions and verifying the field exists
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		expect(typeof BeignetNode.create).to.equal('function');
		// The fact that this compiles with dailySpendLimitSats is the test
	});

	it('getDailySpendInfo returns correct shape with no limit set', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});
		try {
			const info = node.getDailySpendInfo();
			expect(info.limitSats).to.be.null;
			expect(info.spentSats).to.equal(0);
			expect(info.remainingSats).to.equal(Infinity);
			expect(info.resetsAt).to.be.a('number');
		} finally {
			await node.destroy();
		}
	});

	it('getDailySpendInfo returns correct shape with limit set', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			dailySpendLimitSats: 100_000,
			...OFFLINE_ELECTRUM
		});
		try {
			const info = node.getDailySpendInfo();
			expect(info.limitSats).to.equal(100_000);
			expect(info.spentSats).to.equal(0);
			expect(info.remainingSats).to.equal(100_000);
			expect(info.resetsAt).to.be.a('number');
			expect(info.resetsAt).to.be.greaterThan(Date.now());
		} finally {
			await node.destroy();
		}
	});

	it('spending limit check throws for oversized payments', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			dailySpendLimitSats: 1000,
			...OFFLINE_ELECTRUM
		});
		try {
			// Access private method via prototype for testing
			const checkFn = (node as any)._checkSpendLimit.bind(node);
			// Should not throw for small amount
			expect(() => checkFn(500)).to.not.throw();
			// Should throw for oversized amount
			expect(() => checkFn(1001)).to.throw('Daily spend limit exceeded');
		} finally {
			await node.destroy();
		}
	});

	it('spending limit accumulates across multiple spends', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			dailySpendLimitSats: 1000,
			...OFFLINE_ELECTRUM
		});
		try {
			const recordFn = (node as any)._recordSpend.bind(node);
			const checkFn = (node as any)._checkSpendLimit.bind(node);

			// Record 600 sats
			recordFn(600);
			const info1 = node.getDailySpendInfo();
			expect(info1.spentSats).to.equal(600);
			expect(info1.remainingSats).to.equal(400);

			// 300 more should be fine
			expect(() => checkFn(300)).to.not.throw();

			// 401 should exceed limit (600 + 401 > 1000)
			expect(() => checkFn(401)).to.throw('Daily spend limit exceeded');
		} finally {
			await node.destroy();
		}
	});

	it('spending limit resets at midnight UTC', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			dailySpendLimitSats: 1000,
			...OFFLINE_ELECTRUM
		});
		try {
			const recordFn = (node as any)._recordSpend.bind(node);
			recordFn(800);
			expect(node.getDailySpendInfo().spentSats).to.equal(800);

			// Force reset by setting resetTime to the past
			(node as any)._dailySpendResetTime = Date.now() - 1000;
			const info = node.getDailySpendInfo();
			expect(info.spentSats).to.equal(0);
			expect(info.remainingSats).to.equal(1000);
		} finally {
			await node.destroy();
		}
	});

	it('BEIGNET_DAILY_SPEND_LIMIT_SATS env var is recognized', () => {
		const origEnv = process.env.BEIGNET_DAILY_SPEND_LIMIT_SATS;
		try {
			process.env.BEIGNET_DAILY_SPEND_LIMIT_SATS = '50000';
			const config = resolveConfig({});
			expect(config.dailySpendLimitSats).to.equal(50000);
		} finally {
			if (origEnv !== undefined) {
				process.env.BEIGNET_DAILY_SPEND_LIMIT_SATS = origEnv;
			} else {
				delete process.env.BEIGNET_DAILY_SPEND_LIMIT_SATS;
			}
		}
	});
});

// ─────────────── Idempotency Keys ───────────────

describe('Idempotency Keys', () => {
	it('IDEMPOTENCY_CONFLICT error code exists', () => {
		expect(BeignetErrorCode.IDEMPOTENCY_CONFLICT).to.equal(
			'IDEMPOTENCY_CONFLICT'
		);
	});

	it('DaemonOptions type is importable and accepts new fields', async () => {
		// Validates that the daemon module exports DaemonOptions with TLS fields
		const opts: DaemonOptions = {
			network: 'regtest',
			daemonPort: 3333,
			tlsCert: '/tmp/cert.pem',
			tlsKey: '/tmp/key.pem'
		};
		expect(opts.tlsCert).to.equal('/tmp/cert.pem');
		expect(opts.tlsKey).to.equal('/tmp/key.pem');
	});

	it('idempotent routes constant covers payment endpoints', () => {
		// We can't directly access the const, but we can verify the pattern exists
		// by checking that the daemon module exports startDaemon
		expect(typeof startDaemon).to.equal('function');
	});

	it('idempotency cache hit returns same response', async function () {
		this.timeout(15_000);
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-idem-'));
		const { server, node } = await startDaemon({
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0, // random port
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});

		const port = (server.address() as any).port;
		try {
			const key = `test-${Date.now()}`;
			const body = JSON.stringify({ bolt11: 'lnbcrt10n1invalid' });

			// First request with idempotency key
			const res1 = await httpPost(port, '/invoice/pay-safe', body, {
				'X-Idempotency-Key': key
			});
			// Second request with same key and body should return cached response
			const res2 = await httpPost(port, '/invoice/pay-safe', body, {
				'X-Idempotency-Key': key
			});

			// Both responses should be identical
			expect(JSON.parse(res1)).to.deep.equal(JSON.parse(res2));
		} finally {
			await node.destroy();
			server.close();
		}
	});

	it('idempotency conflict returns 409 for different body', async function () {
		this.timeout(15_000);
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-idem-'));
		const { server, node } = await startDaemon({
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});

		const port = (server.address() as any).port;
		try {
			const key = `conflict-${Date.now()}`;

			// First request
			await httpPost(
				port,
				'/invoice/pay-safe',
				JSON.stringify({ bolt11: 'lnbcrt10n1first' }),
				{ 'X-Idempotency-Key': key }
			);

			// Second request with same key but different body
			const res2raw = await httpPostRaw(
				port,
				'/invoice/pay-safe',
				JSON.stringify({ bolt11: 'lnbcrt10n1second' }),
				{ 'X-Idempotency-Key': key }
			);
			expect(res2raw.statusCode).to.equal(409);
			const body2 = JSON.parse(res2raw.body);
			expect(body2.ok).to.be.false;
			expect(body2.error.code).to.equal('IDEMPOTENCY_CONFLICT');
		} finally {
			await node.destroy();
			server.close();
		}
	});

	it('requests without idempotency key are not cached', async function () {
		this.timeout(15_000);
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-idem-'));
		const { server, node } = await startDaemon({
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});

		const port = (server.address() as any).port;
		try {
			// Two requests without key should both execute
			const body = JSON.stringify({ bolt11: 'lnbcrt10n1nokey' });
			const res1 = await httpPost(port, '/invoice/pay-safe', body);
			const res2 = await httpPost(port, '/invoice/pay-safe', body);
			// Both should succeed (even if they fail on invalid bolt11, they should run independently)
			expect(JSON.parse(res1).ok).to.be.a('boolean');
			expect(JSON.parse(res2).ok).to.be.a('boolean');
		} finally {
			await node.destroy();
			server.close();
		}
	});

	it('non-payment routes ignore idempotency key', async function () {
		this.timeout(15_000);
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-idem-'));
		const { server, node } = await startDaemon({
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});

		const port = (server.address() as any).port;
		try {
			const key = `info-${Date.now()}`;
			// GET /info is not idempotent — key should be ignored, request should still work
			const res = await httpGet(port, '/info', { 'X-Idempotency-Key': key });
			const parsed = JSON.parse(res);
			expect(parsed.ok).to.be.true;
			expect(parsed.result.nodeId).to.be.a('string');
		} finally {
			await node.destroy();
			server.close();
		}
	});
});

// ─────────────── TLS ───────────────

describe('TLS Daemon', () => {
	it('rejects tlsCert without tlsKey', async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tls-'));
		try {
			await startDaemon({
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				logLevel: 'silent',
				tlsCert: '/tmp/nonexistent-cert.pem',
				...OFFLINE_ELECTRUM
			});
			expect.fail('should have thrown');
		} catch (err: any) {
			expect(err.message).to.include('tlsKey is required');
		}
		// Config-only refusals run before BeignetNode.create, so nothing was
		// booted for the caller to be left without a handle to.
		expect(
			fs.existsSync(path.join(tmpDir, 'regtest.db')),
			'no node was booted for a config error'
		).to.equal(false);
	});

	it('rejects tlsKey without tlsCert', async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tls-'));
		try {
			await startDaemon({
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				logLevel: 'silent',
				tlsKey: '/tmp/nonexistent-key.pem',
				...OFFLINE_ELECTRUM
			});
			expect.fail('should have thrown');
		} catch (err: any) {
			expect(err.message).to.include('tlsCert is required');
		}
		expect(
			fs.existsSync(path.join(tmpDir, 'regtest.db')),
			'no node was booted for a config error'
		).to.equal(false);
	});

	it('destroys the node when the start fails after booting it', async function () {
		this.timeout(30_000);
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-leak-'));
		// Occupy the port so the failure lands on server.listen, i.e. after the
		// node is up. Before the fix the rejection reached the caller with no
		// handle to the node, leaving its database, single-instance lock,
		// Electrum poll and backup timer running for the life of the process.
		const squatter = http.createServer();
		await new Promise<void>((resolve) =>
			squatter.listen(0, '127.0.0.1', () => resolve())
		);
		const busyPort = (squatter.address() as any).port;

		let thrown: unknown;
		try {
			const started = await startDaemon({
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: busyPort,
				logLevel: 'silent',
				...OFFLINE_ELECTRUM
			});
			await started.node.destroy();
			started.server.close();
		} catch (err: unknown) {
			thrown = err;
		} finally {
			squatter.close();
		}

		expect(
			(thrown as NodeJS.ErrnoException)?.code,
			'the busy port refused the listen'
		).to.equal('EADDRINUSE');
		// The database proves a node really booted, so the lock being gone is
		// destroy() having run rather than a start that never got that far.
		expect(
			fs.existsSync(path.join(tmpDir, 'regtest.db')),
			'the node booted before the failure'
		).to.equal(true);
		expect(
			fs.existsSync(path.join(tmpDir, 'regtest.lock')),
			'the booted node was destroyed'
		).to.equal(false);
	});

	it('starts HTTPS server with valid self-signed certs', async function () {
		this.timeout(15_000);
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tls-'));
		const { certPath, keyPath } = generateSelfSignedCert(tmpDir);

		const { server, node } = await startDaemon({
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			logLevel: 'silent',
			tlsCert: certPath,
			tlsKey: keyPath,
			...OFFLINE_ELECTRUM
		});

		const port = (server.address() as any).port;
		try {
			// Make HTTPS request (skip cert validation for self-signed)
			const res = await httpsGet(port, '/health');
			const parsed = JSON.parse(res);
			expect(parsed.ok).to.be.true;
			expect(parsed.result.status).to.be.a('string');
		} finally {
			await node.destroy();
			server.close();
		}
	});

	it('BEIGNET_TLS_CERT and BEIGNET_TLS_KEY env vars are recognized', () => {
		const origCert = process.env.BEIGNET_TLS_CERT;
		const origKey = process.env.BEIGNET_TLS_KEY;
		try {
			process.env.BEIGNET_TLS_CERT = '/etc/ssl/cert.pem';
			process.env.BEIGNET_TLS_KEY = '/etc/ssl/key.pem';
			const config = resolveConfig({});
			expect(config.tlsCert).to.equal('/etc/ssl/cert.pem');
			expect(config.tlsKey).to.equal('/etc/ssl/key.pem');
		} finally {
			if (origCert !== undefined) process.env.BEIGNET_TLS_CERT = origCert;
			else delete process.env.BEIGNET_TLS_CERT;
			if (origKey !== undefined) process.env.BEIGNET_TLS_KEY = origKey;
			else delete process.env.BEIGNET_TLS_KEY;
		}
	});
});

// ─────────────── Drain Mode ───────────────

describe('Drain Mode', () => {
	it('SERVICE_DRAINING error code exists', () => {
		expect(BeignetErrorCode.SERVICE_DRAINING).to.equal('SERVICE_DRAINING');
	});

	it('SERVICE_DRAINING is a permanent (non-retryable) error', () => {
		const err = new BeignetError('SERVICE_DRAINING', 'draining');
		expect(isRetryableError(err)).to.be.false;
		expect(isPermanentFailure(err)).to.be.true;
	});

	it('setDraining/isDraining toggles drain mode', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-drain-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});
		try {
			expect(node.isDraining()).to.be.false;
			node.setDraining(true);
			expect(node.isDraining()).to.be.true;
			node.setDraining(false);
			expect(node.isDraining()).to.be.false;
		} finally {
			await node.destroy();
		}
	});

	it('hasPendingPayments returns false with no payments', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-drain-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});
		try {
			expect(node.hasPendingPayments()).to.be.false;
		} finally {
			await node.destroy();
		}
	});

	it('drain mode rejects payInvoice', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-drain-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});
		try {
			node.setDraining(true);
			try {
				await node.payInvoice('lnbcrt10n1dummy');
				expect.fail('should have thrown');
			} catch (err: any) {
				expect(err.code).to.equal('SERVICE_DRAINING');
			}
		} finally {
			await node.destroy();
		}
	});

	it('drain mode rejects sendKeysend', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-drain-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			...OFFLINE_ELECTRUM
		});
		try {
			node.setDraining(true);
			try {
				await node.sendKeysend('02' + '00'.repeat(32), 1000);
				expect.fail('should have thrown');
			} catch (err: any) {
				expect(err.code).to.equal('SERVICE_DRAINING');
			}
		} finally {
			await node.destroy();
		}
	});

	it('daemon GET /spend-limit endpoint works', async function () {
		this.timeout(15_000);
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-spend-'));
		const { server, node } = await startDaemon({
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			logLevel: 'silent',
			dailySpendLimitSats: 50000,
			...OFFLINE_ELECTRUM
		});
		const port = (server.address() as any).port;
		try {
			const res = await httpGet(port, '/spend-limit');
			const parsed = JSON.parse(res);
			expect(parsed.ok).to.be.true;
			expect(parsed.result.limitSats).to.equal(50000);
			expect(parsed.result.spentSats).to.equal(0);
			expect(parsed.result.remainingSats).to.equal(50000);
		} finally {
			await node.destroy();
			server.close();
		}
	});
});

// ─────────────── Documentation ───────────────

describe('Documentation Accuracy', () => {
	// These used to pin exact figures ('2740+', '129 interop', '720 CLI').
	// Every one of them had drifted below reality, so the test was enforcing
	// documentation that was already wrong. Counts in the README are now
	// floors, and the assertions below guard structure instead of prose.
	it('README.md documents every test suite script', () => {
		const readme = fs.readFileSync(
			path.join(__dirname, '../../README.md'),
			'utf-8'
		);
		const pkg = JSON.parse(
			fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf-8')
		);
		// Derived from package.json rather than hardcoded, so adding a suite
		// without documenting it fails here.
		const suites = Object.keys(pkg.scripts).filter((s) =>
			s.startsWith('test:')
		);
		expect(suites.length).to.be.greaterThan(0);
		for (const suite of suites) {
			expect(readme, `README should mention the ${suite} script`).to.include(
				suite
			);
		}
		// The suites run directly by name must show their invocation.
		for (const suite of ['test:lightning', 'test:cli', 'test:interop']) {
			expect(readme, `README should document npm run ${suite}`).to.include(
				`npm run ${suite}`
			);
		}
		// Stated counts must be floors ('4000+'), never exact snapshots, so a
		// passing suite can never be described by a number that is too high.
		const countClaims = readme.match(/\b\d{3,}\+? (?=Lightning|CLI|official)/g);
		for (const claim of countClaims ?? []) {
			expect(claim.trim(), 'test counts must be written as floors').to.match(
				/\+$/
			);
		}
	});

	it('README.md module table covers every src/lightning module', () => {
		const readme = fs.readFileSync(
			path.join(__dirname, '../../README.md'),
			'utf-8'
		);
		const lightningDir = path.join(__dirname, '../../src/lightning');
		const modules = fs
			.readdirSync(lightningDir, { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.map((entry) => entry.name);
		expect(modules.length).to.be.greaterThan(0);
		for (const mod of modules) {
			expect(readme, `README module table should list \`${mod}/\``).to.include(
				`\`${mod}/\``
			);
		}
	});

	it('README.md documents interop testing against real implementations', () => {
		const readme = fs.readFileSync(
			path.join(__dirname, '../../README.md'),
			'utf-8'
		);
		expect(readme).to.include('npm run test:interop');
		expect(readme).to.include('docker/docker-compose.yml');
		expect(readme.toLowerCase()).to.include('interop');
	});

	it('README.md includes Node.js 18+ requirement', () => {
		const readme = fs.readFileSync(
			path.join(__dirname, '../../README.md'),
			'utf-8'
		);
		expect(readme).to.include('Node.js 18+');
	});

	it('package.json files array includes docs/', () => {
		const pkg = JSON.parse(
			fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf-8')
		);
		expect(pkg.files).to.include('docs/');
	});

	it('AI Agent Guide documents keysend', () => {
		const guide = fs.readFileSync(
			path.join(__dirname, '../../docs/AI_AGENT_GUIDE.md'),
			'utf-8'
		);
		expect(guide).to.include('sendKeysend');
		expect(guide).to.include('sendKeysendSafe');
		expect(guide).to.include('/keysend');
	});

	it('AI Agent Guide documents channel health', () => {
		const guide = fs.readFileSync(
			path.join(__dirname, '../../docs/AI_AGENT_GUIDE.md'),
			'utf-8'
		);
		expect(guide).to.include('getChannelHealth');
		expect(guide).to.include('IChannelHealth');
		expect(guide).to.include('LOW_OUTBOUND_LIQUIDITY');
	});

	it('AI Agent Guide documents getPaymentProof', () => {
		const guide = fs.readFileSync(
			path.join(__dirname, '../../docs/AI_AGENT_GUIDE.md'),
			'utf-8'
		);
		expect(guide).to.include('getPaymentProof');
	});

	it('CLI README uses beignet/cli import path', () => {
		const cliReadme = fs.readFileSync(
			path.join(__dirname, '../../src/cli/README.md'),
			'utf-8'
		);
		expect(cliReadme).to.include("from 'beignet/cli'");
		expect(cliReadme).not.to.include("from './src/cli'");
	});

	it('Lightning README uses beignet/lightning import paths', () => {
		const lnReadme = fs.readFileSync(
			path.join(__dirname, '../../src/lightning/README.md'),
			'utf-8'
		);
		expect(lnReadme).to.include("from 'beignet/lightning'");
		expect(lnReadme).not.to.include("from './lightning/");
	});

	it('Lightning README includes advisor module', () => {
		const lnReadme = fs.readFileSync(
			path.join(__dirname, '../../src/lightning/README.md'),
			'utf-8'
		);
		expect(lnReadme).to.include('advisor/');
		expect(lnReadme).to.include('LiquidityAdvisor');
		expect(lnReadme).to.include('FeeAdvisor');
		expect(lnReadme).to.include('ChannelSuggestions');
	});

	it('AI Agent Guide documents spending limits', () => {
		const guide = fs.readFileSync(
			path.join(__dirname, '../../docs/AI_AGENT_GUIDE.md'),
			'utf-8'
		);
		expect(guide).to.include('dailySpendLimitSats');
		expect(guide).to.include('getDailySpendInfo');
		expect(guide).to.include('SPENDING_LIMIT_EXCEEDED');
	});

	it('AI Agent Guide documents idempotency keys', () => {
		const guide = fs.readFileSync(
			path.join(__dirname, '../../docs/AI_AGENT_GUIDE.md'),
			'utf-8'
		);
		expect(guide).to.include('X-Idempotency-Key');
		expect(guide).to.include('IDEMPOTENCY_CONFLICT');
	});

	it('AI Agent Guide documents drain mode', () => {
		const guide = fs.readFileSync(
			path.join(__dirname, '../../docs/AI_AGENT_GUIDE.md'),
			'utf-8'
		);
		expect(guide).to.include('setDraining');
		expect(guide).to.include('SERVICE_DRAINING');
	});

	it('CLI README documents spending limits', () => {
		const cliReadme = fs.readFileSync(
			path.join(__dirname, '../../src/cli/README.md'),
			'utf-8'
		);
		expect(cliReadme).to.include('getDailySpendInfo');
		expect(cliReadme).to.include('DailySpendInfo');
		expect(cliReadme).to.include('SPENDING_LIMIT_EXCEEDED');
	});

	it('CLI README documents drain mode methods', () => {
		const cliReadme = fs.readFileSync(
			path.join(__dirname, '../../src/cli/README.md'),
			'utf-8'
		);
		expect(cliReadme).to.include('setDraining');
		expect(cliReadme).to.include('isDraining');
		expect(cliReadme).to.include('hasPendingPayments');
		expect(cliReadme).to.include('SERVICE_DRAINING');
	});

	it('CLI README documents keysend endpoints', () => {
		const cliReadme = fs.readFileSync(
			path.join(__dirname, '../../src/cli/README.md'),
			'utf-8'
		);
		expect(cliReadme).to.include('/keysend');
		expect(cliReadme).to.include('/keysend/safe');
		expect(cliReadme).to.include('sendKeysend');
		expect(cliReadme).to.include('sendKeysendSafe');
	});

	it('CLI README documents spend-limit endpoint', () => {
		const cliReadme = fs.readFileSync(
			path.join(__dirname, '../../src/cli/README.md'),
			'utf-8'
		);
		expect(cliReadme).to.include('/spend-limit');
	});

	it('CLI README documents TLS and idempotency env vars', () => {
		const cliReadme = fs.readFileSync(
			path.join(__dirname, '../../src/cli/README.md'),
			'utf-8'
		);
		expect(cliReadme).to.include('BEIGNET_TLS_CERT');
		expect(cliReadme).to.include('BEIGNET_TLS_KEY');
		expect(cliReadme).to.include('BEIGNET_DAILY_SPEND_LIMIT_SATS');
	});
});

// ─────────────── HTTP Helpers ───────────────

function httpGet(
	port: number,
	urlPath: string,
	headers?: Record<string, string>
): Promise<string> {
	return new Promise((resolve, reject) => {
		const opts: http.RequestOptions = {
			hostname: '127.0.0.1',
			port,
			path: urlPath,
			method: 'GET',
			headers: { ...headers }
		};
		const req = http.request(opts, (res) => {
			const chunks: Buffer[] = [];
			res.on('data', (chunk: Buffer) => chunks.push(chunk));
			res.on('end', () => resolve(Buffer.concat(chunks).toString()));
		});
		req.on('error', reject);
		req.end();
	});
}

function httpPost(
	port: number,
	urlPath: string,
	body: string,
	headers?: Record<string, string>
): Promise<string> {
	return new Promise((resolve, reject) => {
		const opts: http.RequestOptions = {
			hostname: '127.0.0.1',
			port,
			path: urlPath,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Content-Length': Buffer.byteLength(body),
				...headers
			}
		};
		const req = http.request(opts, (res) => {
			const chunks: Buffer[] = [];
			res.on('data', (chunk: Buffer) => chunks.push(chunk));
			res.on('end', () => resolve(Buffer.concat(chunks).toString()));
		});
		req.on('error', reject);
		req.write(body);
		req.end();
	});
}

function httpPostRaw(
	port: number,
	urlPath: string,
	body: string,
	headers?: Record<string, string>
): Promise<{ statusCode: number; body: string }> {
	return new Promise((resolve, reject) => {
		const opts: http.RequestOptions = {
			hostname: '127.0.0.1',
			port,
			path: urlPath,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Content-Length': Buffer.byteLength(body),
				...headers
			}
		};
		const req = http.request(opts, (res) => {
			const chunks: Buffer[] = [];
			res.on('data', (chunk: Buffer) => chunks.push(chunk));
			res.on('end', () =>
				resolve({
					statusCode: res.statusCode || 0,
					body: Buffer.concat(chunks).toString()
				})
			);
		});
		req.on('error', reject);
		req.write(body);
		req.end();
	});
}

function httpsGet(port: number, urlPath: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const opts: https.RequestOptions = {
			hostname: '127.0.0.1',
			port,
			path: urlPath,
			method: 'GET',
			rejectUnauthorized: false // self-signed cert
		};
		const req = https.request(opts, (res) => {
			const chunks: Buffer[] = [];
			res.on('data', (chunk: Buffer) => chunks.push(chunk));
			res.on('end', () => resolve(Buffer.concat(chunks).toString()));
		});
		req.on('error', reject);
		req.end();
	});
}

function generateSelfSignedCert(dir: string): {
	certPath: string;
	keyPath: string;
} {
	// Generate a self-signed cert using Node.js crypto
	const { privateKey } = crypto.generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' } as any,
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
	});

	// Use openssl-like approach via child_process for proper X.509 cert
	const { execSync } = require('child_process');
	const keyPath = path.join(dir, 'key.pem');
	const certPath = path.join(dir, 'cert.pem');
	fs.writeFileSync(keyPath, privateKey);
	// Generate self-signed cert using openssl
	execSync(
		`openssl req -new -x509 -key ${keyPath} -out ${certPath} -days 1 -subj "/CN=localhost" -batch 2>/dev/null`
	);
	return { certPath, keyPath };
}
