import { expect } from 'chai';
import * as http from 'http';
import * as net from 'net';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { parseBody, startDaemon } from '../../src/cli/daemon';
import { resolveConfig } from '../../src/cli/config';
import { Readable } from 'stream';
import { IncomingMessage } from 'http';

function isElectrumAvailable(
	host = '127.0.0.1',
	port = 60001,
	timeoutMs = 5000
): Promise<boolean> {
	return new Promise((resolve) => {
		const sock = net.createConnection({ host, port }, () => {
			// Send a real Electrum protocol version negotiation
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

/** Create a fake IncomingMessage from a Buffer for testing parseBody */
function createFakeRequest(body: Buffer): IncomingMessage {
	const readable = new Readable({
		read() {
			this.push(body);
			this.push(null);
		}
	});
	// Cast to IncomingMessage — parseBody only uses .on('data')/on('end')
	return readable as unknown as IncomingMessage;
}

// ─────────────── parseBody Tests ───────────────

describe('parseBody', () => {
	it('rejects bodies exceeding 1MB', async () => {
		const bigBody = Buffer.alloc(1_048_577, 'a'); // 1MB + 1 byte
		const req = createFakeRequest(bigBody);
		try {
			await parseBody(req);
			expect.fail('Should have thrown');
		} catch (err: unknown) {
			expect(err).to.be.instanceOf(Error);
			expect((err as { code?: string }).code).to.equal('BODY_TOO_LARGE');
		}
	});

	it('accepts bodies under 1MB', async () => {
		const smallBody = Buffer.from(JSON.stringify({ hello: 'world' }));
		const req = createFakeRequest(smallBody);
		const result = await parseBody(req);
		expect(result).to.deep.equal({ hello: 'world' });
	});

	it('body size limit returns BODY_TOO_LARGE error code', async () => {
		const bigBody = Buffer.alloc(2_000_000, 'x');
		const req = createFakeRequest(bigBody);
		try {
			await parseBody(req);
			expect.fail('Should have thrown');
		} catch (err: unknown) {
			expect((err as { code?: string }).code).to.equal('BODY_TOO_LARGE');
			expect((err as { message?: string }).message).to.include('1048576');
		}
	});
});

// ─────────────── Auth Middleware Tests (real HTTP server) ───────────────

describe('Daemon auth middleware', () => {
	let tmpDir: string;
	const origHome = process.env.HOME;
	let skipAll = false;

	before(async function () {
		this.timeout(10000);
		skipAll = !(await isElectrumAvailable());
	});

	beforeEach(function () {
		if (skipAll) this.skip();
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-auth-'));
		process.env.HOME = tmpDir;
	});

	afterEach(() => {
		if (skipAll) return;
		process.env.HOME = origHome;
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	function httpGet(
		port: number,
		urlPath: string,
		headers?: Record<string, string>
	): Promise<{ status: number; body: Record<string, unknown> }> {
		return new Promise((resolve, reject) => {
			const req = http.get(
				{ hostname: '127.0.0.1', port, path: urlPath, headers },
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
		});
	}

	function httpPost(
		port: number,
		urlPath: string,
		body: Record<string, unknown>,
		headers?: Record<string, string>
	): Promise<{ status: number; body: Record<string, unknown> }> {
		return new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const hdrs: Record<string, string | number> = {
				'Content-Type': 'application/json',
				'Content-Length': Buffer.byteLength(payload),
				...headers
			};
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: urlPath,
					method: 'POST',
					headers: hdrs
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
	}

	it('daemon returns 401 when apiToken configured but no header sent', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0, // OS-assigned port
			apiToken: 'secret123',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/info');
			expect(resp.status).to.equal(401);
			expect(resp.body.ok).to.be.false;
			expect((resp.body.error as { code: string }).code).to.equal(
				'UNAUTHORIZED'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('daemon returns 401 when apiToken configured and wrong token sent', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'secret123',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/info', {
				Authorization: 'Bearer wrongtoken'
			});
			expect(resp.status).to.equal(401);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('daemon returns 200 when apiToken configured and correct token sent', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'secret123',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/info', {
				Authorization: 'Bearer secret123'
			});
			expect(resp.status).to.equal(200);
			expect(resp.body.ok).to.be.true;
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('daemon allows all requests when no apiToken configured (backward compat)', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/info');
			expect(resp.status).to.equal(200);
			expect(resp.body.ok).to.be.true;
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /mnemonic returns error when no apiToken configured', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/mnemonic');
			expect(resp.body.ok).to.be.false;
			expect((resp.body.error as { code: string }).code).to.equal(
				'MNEMONIC_REQUIRES_AUTH'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /mnemonic works when apiToken configured and correct token sent', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'mytoken',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/mnemonic', {
				Authorization: 'Bearer mytoken'
			});
			expect(resp.body.ok).to.be.true;
			expect((resp.body.result as { mnemonic: string }).mnemonic).to.include(
				'abandon'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('POST /stop requires auth when apiToken configured', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'stoptoken',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpPost(addr.port, '/stop', {});
			expect(resp.status).to.equal(401);
			expect(resp.body.ok).to.be.false;
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('401 response uses correct JSON envelope format', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'envelope',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/info');
			expect(resp.status).to.equal(401);
			expect(resp.body).to.have.property('ok', false);
			expect(resp.body).to.have.property('error');
			const err = resp.body.error as { code: string; message: string };
			expect(err).to.have.property('code', 'UNAUTHORIZED');
			expect(err).to.have.property('message').that.is.a('string');
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('auth header parsing is case-insensitive for Bearer prefix', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'casetest',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			// Test with "BEARER" (uppercase)
			const resp = await httpGet(addr.port, '/info', {
				Authorization: 'BEARER casetest'
			});
			expect(resp.status).to.equal(200);
			expect(resp.body.ok).to.be.true;
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('failed auth attempts are throttled by the rate limiter', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'brute-target',
			rateLimit: { maxRequests: 5, windowMs: 60_000 },
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			// Each guess must consume budget: the limiter runs before auth.
			for (let i = 0; i < 5; i++) {
				const resp = await httpGet(addr.port, '/info', {
					Authorization: 'Bearer wrong-guess'
				});
				expect(resp.status).to.equal(401);
			}
			const throttled = await httpGet(addr.port, '/info', {
				Authorization: 'Bearer wrong-guess'
			});
			expect(throttled.status).to.equal(429);
			expect((throttled.body.error as { code: string }).code).to.equal(
				'RATE_LIMITED'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('varying the Authorization header does not mint fresh rate-limit buckets', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'bucket-target',
			rateLimit: { maxRequests: 5, windowMs: 60_000 },
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			// A distinct token per request previously keyed a distinct bucket,
			// so a brute forcer never saw a 429. All guesses from one peer
			// must now share the same budget.
			for (let i = 0; i < 5; i++) {
				const resp = await httpGet(addr.port, '/info', {
					Authorization: `Bearer distinct-guess-${i}`
				});
				expect(resp.status).to.equal(401);
			}
			const throttled = await httpGet(addr.port, '/info', {
				Authorization: 'Bearer distinct-guess-final'
			});
			expect(throttled.status).to.equal(429);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('SSE endpoint auth failures are throttled by the rate limiter', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'sse-target',
			rateLimit: { maxRequests: 5, windowMs: 60_000 },
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			for (let i = 0; i < 5; i++) {
				const resp = await httpGet(addr.port, '/events', {
					Authorization: 'Bearer wrong-guess'
				});
				expect(resp.status).to.equal(401);
			}
			const throttled = await httpGet(addr.port, '/events', {
				Authorization: 'Bearer wrong-guess'
			});
			expect(throttled.status).to.equal(429);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /health does not require authentication', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'healthtest',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			// No auth header — should still return 200 because /health is exempt
			const resp = await httpGet(addr.port, '/health');
			expect(resp.status).to.equal(200);
			expect(resp.body.ok).to.be.true;
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /metrics requires auth (it reports balances), metricsPublic opts out', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'metricstest',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const noAuth = await httpGet(addr.port, '/metrics');
			expect(noAuth.status).to.equal(401);
			const withAuth = await httpGet(addr.port, '/metrics', {
				Authorization: 'Bearer metricstest'
			});
			expect(withAuth.status).to.equal(200);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('GET /metrics is open when metricsPublic is set', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'metricspublic',
			metricsPublic: true,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const resp = await httpGet(addr.port, '/metrics');
			expect(resp.status).to.equal(200);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('refuses a non-loopback bind without authentication', async () => {
		try {
			await startDaemon({
				mnemonic:
					'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				daemonHost: '0.0.0.0',
				electrumHost: '127.0.0.1',
				electrumPort: 60001,
				electrumTls: false
			});
			expect.fail('Should have refused the bind');
		} catch (err: unknown) {
			expect((err as { code?: string }).code).to.equal('INVALID_PARAMS');
			expect((err as Error).message).to.include('authentication');
		}
	}).timeout(30000);

	it('refuses wildcard CORS without authentication', async () => {
		try {
			await startDaemon({
				mnemonic:
					'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				cors: true,
				electrumHost: '127.0.0.1',
				electrumPort: 60001,
				electrumTls: false
			});
			expect.fail('Should have refused wildcard CORS');
		} catch (err: unknown) {
			expect((err as { code?: string }).code).to.equal('INVALID_PARAMS');
			expect((err as Error).message).to.include('CORS');
		}
	}).timeout(30000);

	it('CORS preflight allows DELETE (watchtower and webhook routes use it)', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'corstest',
			cors: true,
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		try {
			const allowMethods = await new Promise<string>((resolve, reject) => {
				const req = http.request(
					{
						hostname: '127.0.0.1',
						port: addr.port,
						path: '/webhooks/unregister',
						method: 'OPTIONS'
					},
					(res) => {
						res.resume();
						resolve(String(res.headers['access-control-allow-methods'] ?? ''));
					}
				);
				req.on('error', reject);
				req.end();
			});
			expect(allowMethods).to.include('DELETE');
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('maps error envelopes to HTTP statuses and rejects bad input', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'statustest',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false
		});
		const addr = server.address() as { port: number };
		const auth = { Authorization: 'Bearer statustest' };
		try {
			// NaN would bind into SQL and silently match nothing: reject it.
			const badSince = await httpGet(addr.port, '/forwards?since=abc', auth);
			expect(badSince.status).to.equal(400);
			expect((badSince.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);

			const badAmount = await httpGet(
				addr.port,
				'/can-send?amountSats=abc',
				auth
			);
			expect(badAmount.status).to.equal(400);

			const goodAmount = await httpGet(
				addr.port,
				'/can-send?amountSats=1000',
				auth
			);
			expect(goodAmount.status).to.equal(200);

			// The audit/history and advisor routes validate too.
			const badWindow = await httpGet(addr.port, '/stats?window=abc', auth);
			expect(badWindow.status).to.equal(400);
			const badCount = await httpGet(
				addr.port,
				'/channel/suggestions?count=abc',
				auth
			);
			expect(badCount.status).to.equal(400);
			const badLogsSince = await httpGet(addr.port, '/logs?since=abc', auth);
			expect(badLogsSince.status).to.equal(400);
			const badLogsLimit = await httpGet(addr.port, '/logs?limit=1.5', auth);
			expect(badLogsLimit.status).to.equal(400);

			// A returned failure envelope carries its mapped status too.
			const notFound = await httpGet(
				addr.port,
				`/invoice?paymentHash=${'ab'.repeat(32)}`,
				auth
			);
			expect(notFound.status).to.equal(404);

			// Fractional sats used to throw an uncaught RangeError at BigInt()
			// and surface as a 200 INTERNAL_ERROR.
			const fractional = await httpPost(
				addr.port,
				'/channel/open',
				{ pubkey: '02' + 'ab'.repeat(32), amountSats: 1.5 },
				auth
			);
			expect(fractional.status).to.equal(400);
			expect((fractional.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('rejects malformed JSON bodies with 400 instead of treating them as empty', async () => {
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'jsontest',
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
				const payload = '{"bolt11": "lnbc1..';
				const req = http.request(
					{
						hostname: '127.0.0.1',
						port: addr.port,
						path: '/invoice/pay',
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'Content-Length': Buffer.byteLength(payload),
							Authorization: 'Bearer jsontest'
						}
					},
					(res) => {
						const chunks: Buffer[] = [];
						res.on('data', (c: Buffer) => chunks.push(c));
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
			expect(resp.status).to.equal(400);
			expect((resp.body.error as { code: string }).code).to.equal(
				'INVALID_JSON'
			);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);

	it('answers mistyped offer and invoice pastes with 400 and the parser message, not a scrubbed 500', async () => {
		const errorLines: string[] = [];
		const captureLogger = {
			debug: (): void => {},
			info: (): void => {},
			warn: (): void => {},
			error: (message: string): void => {
				errorLines.push(message);
			}
		};
		const { server, node } = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: 'decodetest',
			electrumHost: '127.0.0.1',
			electrumPort: 60001,
			electrumTls: false,
			logger: captureLogger
		});
		const addr = server.address() as { port: number };
		const auth = { Authorization: 'Bearer decodetest' };
		try {
			const badOffer = await httpPost(
				addr.port,
				'/offer/decode',
				{ offer: 'lno1garbage' },
				auth
			);
			expect(badOffer.status).to.equal(400);
			const offerErr = badOffer.body.error as {
				code: string;
				message: string;
			};
			expect(offerErr.code).to.equal('INVALID_OFFER');
			expect(offerErr.message).to.include('Invalid offer:');
			expect(offerErr.message).to.not.include('Internal server error');

			const badInvoice = await httpPost(
				addr.port,
				'/invoice/decode',
				{ bolt11: 'lnbc1garbage' },
				auth
			);
			expect(badInvoice.status).to.equal(400);
			const invoiceErr = badInvoice.body.error as {
				code: string;
				message: string;
			};
			expect(invoiceErr.code).to.equal('INVALID_INVOICE');
			expect(invoiceErr.message).to.include('Invalid invoice:');
			expect(invoiceErr.message).to.not.include('Internal server error');

			// A typo is user input, not a daemon bug: nothing may reach the
			// log as an unhandled server fault.
			const unhandled = errorLines.filter((m) => m.includes('Unhandled error'));
			expect(unhandled).to.deep.equal([]);
		} finally {
			await node.destroy();
			server.close();
		}
	}).timeout(30000);
});

// ─────────────── Config apiToken Tests ───────────────

describe('Config apiToken', () => {
	let tmpDir: string;
	const origHome = process.env.HOME;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-config-'));
		process.env.HOME = tmpDir;
	});

	afterEach(() => {
		process.env.HOME = origHome;
		delete process.env.BEIGNET_API_TOKEN;
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('resolveConfig reads BEIGNET_API_TOKEN from env', () => {
		process.env.BEIGNET_API_TOKEN = 'envtoken';
		const config = resolveConfig({});
		expect(config.apiToken).to.equal('envtoken');
	});

	it('resolveConfig prefers CLI flag over env for apiToken', () => {
		process.env.BEIGNET_API_TOKEN = 'envtoken';
		const config = resolveConfig({ apiToken: 'cliflag' });
		expect(config.apiToken).to.equal('cliflag');
	});
});
