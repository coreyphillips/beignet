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
