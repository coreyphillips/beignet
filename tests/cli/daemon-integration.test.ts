/**
 * Daemon Integration Tests — Tests that require a running Electrum server.
 *
 * Extracted from:
 * - beignet-node.test.ts: "HTTP Route Fixes" (6 tests)
 * - agent-reliability-3.test.ts: pay-async, cancel, balance daemon tests (3 tests)
 * - agent-dx-3.test.ts: update-fee daemon test (1 test)
 *
 * Run with: npm run test:integration
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as http from 'http';
import * as net from 'net';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { startDaemon } from '../../src/cli/daemon';

function isElectrumAvailable(
	host = '127.0.0.1',
	port = 60001,
	timeoutMs = 5000
): Promise<boolean> {
	return new Promise((resolve) => {
		const sock = net.createConnection({ host, port }, () => {
			const req =
				JSON.stringify({
					id: 1,
					method: 'server.version',
					params: ['test', '1.4']
				}) + '\n';
			sock.write(req);
		});
		let data = '';
		sock.on('data', (chunk: Buffer) => {
			data += chunk.toString();
			if (data.includes('\n')) {
				try {
					const resp = JSON.parse(data.trim());
					sock.destroy();
					resolve(resp.result !== undefined);
				} catch {
					sock.destroy();
					resolve(false);
				}
			}
		});
		sock.on('error', () => resolve(false));
		sock.setTimeout(timeoutMs, () => {
			sock.destroy();
			resolve(false);
		});
	});
}

function httpGet(
	port: number,
	urlPath: string
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		http
			.get({ hostname: '127.0.0.1', port, path: urlPath }, (res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			})
			.on('error', reject);
	});
}

function httpPost(
	port: number,
	urlPath: string,
	payload: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const data = JSON.stringify(payload);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: urlPath,
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(data)
				}
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			}
		);
		req.on('error', reject);
		req.write(data);
		req.end();
	});
}

function httpRequest(
	port: number,
	method: string,
	urlPath: string,
	body?: unknown
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const data = body ? JSON.stringify(body) : '';
		const hdrs: Record<string, string | number> = {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength(data)
		};
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: urlPath,
				method,
				headers: hdrs
			},
			(res) => {
				let buf = '';
				res.on('data', (chunk: string) => {
					buf += chunk;
				});
				res.on('end', () => {
					try {
						resolve({ status: res.statusCode!, body: JSON.parse(buf) });
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			}
		);
		req.on('error', reject);
		if (data) req.write(data);
		req.end();
	});
}

const testMnemonic =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

let skipAll = false;

before(async function () {
	this.timeout(10000);
	skipAll = !(await isElectrumAvailable());
});

// ─────────────── HTTP Route Fixes (from beignet-node.test.ts) ───────────────

describe('HTTP Route Fixes', () => {
	let tmpDir: string;
	const origHome = process.env.HOME;

	beforeEach(function () {
		if (skipAll) this.skip();
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-route-'));
		process.env.HOME = tmpDir;
	});

	afterEach(() => {
		if (!skipAll) {
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it('GET /channel?channelId=abc uses query parameter', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/channel?channelId=aabbccdd');
			expect(resp.body.ok).to.be.false;
			expect((resp.body.error as { code: string }).code).to.equal('NOT_FOUND');
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /payment?paymentHash=abc uses query parameter', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/payment?paymentHash=aabbccdd');
			expect(resp.body.ok).to.be.false;
			expect((resp.body.error as { code: string }).code).to.equal('NOT_FOUND');
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /channel without channelId returns INVALID_PARAMS', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/channel');
			expect(resp.body.ok).to.be.false;
			expect((resp.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /payment without paymentHash returns INVALID_PARAMS', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/payment');
			expect(resp.body.ok).to.be.false;
			expect((resp.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /invoices route exists', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/invoices');
			expect(resp.status).to.equal(200);
			expect(resp.body.ok).to.be.true;
			expect(resp.body.result).to.be.an('array');
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('daemon /invoice/pay accepts maxFeeSats and amountSats in body', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await new Promise<{
				status: number;
				body: Record<string, unknown>;
			}>((resolve, reject) => {
				const payload = JSON.stringify({
					bolt11: 'lnbc1invalid',
					maxFeeSats: 100,
					amountSats: 5000
				});
				const req = http.request(
					{
						hostname: '127.0.0.1',
						port: addr.port,
						path: '/invoice/pay',
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'Content-Length': Buffer.byteLength(payload)
						}
					},
					(res) => {
						const chunks: Buffer[] = [];
						res.on('data', (chunk: Buffer) => chunks.push(chunk));
						res.on('end', () => {
							try {
								resolve({
									status: res.statusCode!,
									body: JSON.parse(Buffer.concat(chunks).toString())
								});
							} catch {
								resolve({ status: res.statusCode!, body: {} });
							}
						});
					}
				);
				req.on('error', reject);
				req.write(payload);
				req.end();
			});
			expect(resp.body.ok).to.be.false;
			expect((resp.body.error as { code: string }).code).to.not.equal(
				'INVALID_PARAMS'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);
});

// ─────────────── pay-async daemon (from agent-reliability-3.test.ts) ───────────────

describe('Daemon: sendPaymentAsync route', () => {
	it('daemon POST /invoice/pay-async delegates to BeignetNode.sendPaymentAsync', async function () {
		if (skipAll) return this.skip();
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-payasync-'));
		const origHome = process.env.HOME;
		process.env.HOME = tmpDir;

		try {
			const { server, node } = await startDaemon({
				mnemonic: testMnemonic,
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				electrumHost: '127.0.0.1',
				electrumPort: 60001,
				electrumTls: false
			});
			const addr = server.address() as { port: number };
			try {
				const resp = await httpPost(addr.port, '/invoice/pay-async', {});
				expect(resp.body.ok).to.be.false;
				expect((resp.body.error as { code: string }).code).to.equal(
					'INVALID_PARAMS'
				);

				const resp2 = await httpPost(addr.port, '/invoice/pay-async', {
					bolt11: 'invalid'
				});
				expect(resp2.body.ok).to.be.false;
				expect((resp2.body.error as { code: string }).code).to.equal(
					'PAYMENT_FAILED'
				);
			} finally {
				await node.destroy();
				server.close();
			}
		} finally {
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	}).timeout(30000);
});

// ─────────────── cancel daemon (from agent-reliability-3.test.ts) ───────────────

describe('Daemon: cancelPayment route', () => {
	it('daemon POST /payment/cancel route exists and validates input', async function () {
		if (skipAll) return this.skip();
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-cancel-'));
		const origHome = process.env.HOME;
		process.env.HOME = tmpDir;

		try {
			const { server, node } = await startDaemon({
				mnemonic: testMnemonic,
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				electrumHost: '127.0.0.1',
				electrumPort: 60001,
				electrumTls: false
			});
			const addr = server.address() as { port: number };
			try {
				const resp = await httpPost(addr.port, '/payment/cancel', {});
				expect(resp.body.ok).to.be.false;
				expect((resp.body.error as { code: string }).code).to.equal(
					'INVALID_PARAMS'
				);

				const hash = crypto.randomBytes(32).toString('hex');
				const resp2 = await httpPost(addr.port, '/payment/cancel', {
					paymentHash: hash
				});
				expect(resp2.body.ok).to.be.true;
			} finally {
				await node.destroy();
				server.close();
			}
		} finally {
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	}).timeout(30000);
});

// ─────────────── balance daemon (from agent-reliability-3.test.ts) ───────────────

describe('Daemon: getBalance unsettledSats', () => {
	it('GET /balance returns unsettledSats in response', async function () {
		if (skipAll) return this.skip();
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-balance-'));
		const origHome = process.env.HOME;
		process.env.HOME = tmpDir;

		try {
			const { server, node } = await startDaemon({
				mnemonic: testMnemonic,
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				electrumHost: '127.0.0.1',
				electrumPort: 60001,
				electrumTls: false
			});
			const addr = server.address() as { port: number };
			try {
				const resp = await httpGet(addr.port, '/balance');
				expect(resp.status).to.equal(200);
				expect(resp.body.ok).to.be.true;
				const result = resp.body.result as Record<string, unknown>;
				expect(result).to.have.property('unsettledSats');
				expect(typeof result.unsettledSats).to.equal('number');
				expect(result.unsettledSats).to.equal(0);
				expect(result).to.have.property('onchain');
				expect(result).to.have.property('lightning');
				expect(result).to.have.property('total');
			} finally {
				await node.destroy();
				server.close();
			}
		} finally {
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	}).timeout(30000);
});

// ─────────────── update-fee daemon (from agent-dx-3.test.ts) ───────────────

describe('Daemon: updateChannelFee route', () => {
	it('daemon POST /channel/update-fee delegates to BeignetNode', async function () {
		this.timeout(30_000);
		if (skipAll) return this.skip();
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-dx3-'));
		const origHome = process.env.HOME;
		process.env.HOME = tmpDir;

		try {
			const { server, node } = await startDaemon({
				mnemonic: testMnemonic,
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				electrumHost: '127.0.0.1',
				electrumPort: 60001,
				electrumTls: false
			});
			const addr = server.address() as { port: number };

			try {
				const channelId = 'aa'.repeat(32);
				const resp = await httpRequest(
					addr.port,
					'POST',
					'/channel/update-fee',
					{
						channelId,
						feeratePerKw: 500
					}
				);

				expect(resp.status).to.equal(200);

				const resp2 = await httpRequest(
					addr.port,
					'POST',
					'/channel/update-fee',
					{}
				);
				expect(resp2.body.ok).to.be.false;
				expect((resp2.body.error as { code: string }).code).to.equal(
					'INVALID_PARAMS'
				);

				// Primary route name: /channel/update-fee is a deprecated alias
				const resp3 = await httpRequest(
					addr.port,
					'POST',
					'/channel/update-commitment-feerate',
					{
						channelId,
						feeratePerKw: 500
					}
				);
				expect(resp3.status).to.equal(200);
			} finally {
				await node.destroy();
				server.close();
			}
		} finally {
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
});

// ─────────────── On-chain routes (transactions, utxos, fee estimates) ───────────────

describe('Daemon: on-chain routes', () => {
	let tmpDir: string;
	const origHome = process.env.HOME;

	beforeEach(function () {
		if (skipAll) this.skip();
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-onchain-'));
		process.env.HOME = tmpDir;
	});

	afterEach(() => {
		if (!skipAll) {
			process.env.HOME = origHome;
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it('GET /transactions returns array and validates limit', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/transactions');
			expect(resp.status).to.equal(200);
			expect(resp.body.ok).to.be.true;
			expect(resp.body.result).to.be.an('array');

			const limited = await httpGet(addr.port, '/transactions?limit=0');
			expect(limited.body.ok).to.be.true;
			expect(limited.body.result).to.deep.equal([]);

			const bad = await httpGet(addr.port, '/transactions?limit=abc');
			expect(bad.body.ok).to.be.false;
			expect((bad.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);

			const negative = await httpGet(addr.port, '/transactions?limit=-1');
			expect(negative.body.ok).to.be.false;
			expect((negative.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /utxos returns array', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/utxos');
			expect(resp.status).to.equal(200);
			expect(resp.body.ok).to.be.true;
			expect(resp.body.result).to.be.an('array');
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /fees/estimates route exists', async () => {
		const { server, node } = await startDaemon({
			mnemonic: testMnemonic,
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/fees/estimates');
			if (resp.body.ok) {
				const fees = resp.body.result as Record<string, unknown>;
				expect(fees.fast).to.be.a('number');
				expect(fees.normal).to.be.a('number');
				expect(fees.slow).to.be.a('number');
				expect(fees.minimum).to.be.a('number');
			} else {
				// Regtest electrum may have no fee estimation data; the route
				// must still resolve (anything but a routing 404).
				expect((resp.body.error as { code: string }).code).to.not.equal(
					'NOT_FOUND'
				);
			}
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);
});
