/**
 * A malformed request target or Host header must never crash the daemon
 * (issue #1003).
 *
 * The request handler parsed the target against `http://<Host header>`, as
 * the first statement, above every try/catch. A Host the URL parser refuses
 * ("a b", "[::1", "a:b:c") threw ERR_INVALID_URL there, the async handler's
 * rejection was unhandled, and Node's default (--unhandled-rejections=throw)
 * terminated the process: one unauthenticated TCP request killed the node.
 *
 * Runs against a chainless daemon over a raw socket, because http.request
 * refuses to send the Host values that matter. The daemon reads only the path
 * and the query, so the Host header is not a base any more and such requests
 * answer 200; a target the parser refuses on its own ("//[") answers 400. A
 * plain request afterwards proves the process survived.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import { ILogger } from '../../src/logger';

type Reply = { status: number; json: Record<string, unknown> };

describe('daemon malformed request target and Host header (issue #1003)', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;
	let port: number;
	const errors: string[] = [];
	const logger: ILogger = {
		debug: () => {},
		info: () => {},
		warn: () => {},
		error: (message: string) => {
			errors.push(message);
		}
	};

	/** Write the bytes as given and hand back everything the server answers. */
	const raw = (request: string): Promise<string> =>
		new Promise((resolve, reject) => {
			const socket = net.createConnection({ host: '127.0.0.1', port });
			let data = '';
			socket.setEncoding('utf8');
			socket.on('data', (chunk: string) => (data += chunk));
			socket.on('error', reject);
			socket.on('close', () => resolve(data));
			socket.on('connect', () => socket.write(request));
		});

	const get = (route: string): Promise<Reply> =>
		new Promise((resolve, reject) => {
			const req = http.request(
				{ host: '127.0.0.1', port, path: route, method: 'GET' },
				(res) => {
					let body = '';
					res.on('data', (c) => (body += c));
					res.on('end', () =>
						resolve({
							status: res.statusCode ?? 0,
							json: JSON.parse(body) as Record<string, unknown>
						})
					);
				}
			);
			req.on('error', reject);
			req.end();
		});

	const statusOf = (response: string): number =>
		Number(/^HTTP\/1\.1 (\d{3})/.exec(response)?.[1] ?? 0);
	const bodyOf = (response: string): Record<string, unknown> =>
		JSON.parse(response.slice(response.indexOf('\r\n\r\n') + 4)) as Record<
			string,
			unknown
		>;

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1003-'));
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			logger,
			network: 'regtest',
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			dataDir,
			daemonPort: 0
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	beforeEach(() => {
		errors.length = 0;
	});

	for (const host of ['a b', '[::1', 'a:b:c']) {
		it(`answers GET /health with Host "${host}" and stays up`, async () => {
			const response = await raw(
				`GET /health HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`
			);
			expect(statusOf(response), response).to.equal(200);
			expect(bodyOf(response).ok).to.equal(true);
			const after = await get('/health');
			expect(after.status).to.equal(200);
			expect(daemon.server.listening).to.equal(true);
		});
	}

	it('answers a request target the URL parser refuses with 400 and stays up', async () => {
		const response = await raw(
			'GET //[ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
		);
		expect(statusOf(response), response).to.equal(400);
		const body = bodyOf(response);
		expect(body.ok).to.equal(false);
		expect((body.error as { code: string }).code).to.equal('INVALID_PARAMS');
		const after = await get('/health');
		expect(after.status).to.equal(200);
	});

	it('answers a throw outside the route catch with 500, logs it and stays up', async () => {
		// GET /metrics renders outside the routes' try/catch; a throw there
		// used to reject out of the handler the same way the URL parse did.
		const node = daemon.node as unknown as { getMetrics: () => string };
		const original = node.getMetrics;
		node.getMetrics = (): string => {
			throw new Error('metrics exploded');
		};
		try {
			const { status, json } = await get('/metrics');
			expect(status).to.equal(500);
			expect(json.ok).to.equal(false);
			expect((json.error as { code: string }).code).to.equal('INTERNAL_ERROR');
			expect(errors.some((m) => m.includes('metrics exploded'))).to.equal(true);
			expect(errors.some((m) => m.includes('GET /metrics'))).to.equal(true);
		} finally {
			node.getMetrics = original;
		}
		const after = await get('/health');
		expect(after.status).to.equal(200);
	});
});
