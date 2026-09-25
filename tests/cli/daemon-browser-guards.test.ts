/**
 * Browser guards while authentication is off (issue #1005).
 *
 * The default install bound 127.0.0.1 with no token, and any web page could
 * drive it: fetch() in no-cors mode posts a text/plain body with no
 * preflight, and parseBody JSON-parsed it whatever the Content-Type said;
 * nothing read Origin or Sec-Fetch-Site; nothing held Host to the bound
 * address, so a DNS name rebound to 127.0.0.1 let the page read the answers.
 *
 * With no credential configured the daemon now refuses a body that is not
 * application/json (415 UNSUPPORTED_MEDIA_TYPE), a foreign Origin or a
 * cross-site fetch (403 CROSS_SITE_REQUEST_REFUSED) and a Host that is not
 * its loopback name (421 HOST_NOT_ALLOWED), ahead of the rate limiter and
 * the auth middleware, on every route but OPTIONS. With a credential
 * configured the guards do not run: the same requests are refused by auth,
 * which a browser cannot satisfy cross-site, and non-browser clients keep
 * their old freedom.
 *
 * Chainless, like tests/cli/daemon-bad-host.test.ts: an unreachable
 * Electrum, daemonPort 0, and the routes used here are local operations.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import {
	AUTH_OFF_WARNING,
	DaemonOptions,
	hostNameOfHeader,
	isAllowedHostHeader,
	isJsonContentType,
	isLoopbackBindHost,
	isWildcardBindHost,
	startDaemon
} from '../../src/cli/daemon';
import { ILogger } from '../../src/logger';

type Reply = { status: number; json: Record<string, unknown> };
type Daemon = Awaited<ReturnType<typeof startDaemon>>;

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const TOKEN = 'browser-guards-token';

const errorCode = (reply: Reply): string =>
	(reply.json.error as { code: string }).code;

/** An http.request with exactly the headers given (Node adds only Host). */
function send(
	port: number,
	method: string,
	route: string,
	headers: Record<string, string> = {},
	body?: string
): Promise<Reply> {
	return new Promise((resolve, reject) => {
		const outgoing: Record<string, string | number> = { ...headers };
		if (body !== undefined)
			outgoing['Content-Length'] = Buffer.byteLength(body);
		const req = http.request(
			{ host: '127.0.0.1', port, path: route, method, headers: outgoing },
			(res) => {
				let data = '';
				res.on('data', (c) => (data += c));
				res.on('end', () =>
					resolve({
						status: res.statusCode ?? 0,
						json: data ? (JSON.parse(data) as Record<string, unknown>) : {}
					})
				);
			}
		);
		req.on('error', reject);
		if (body !== undefined) req.write(body);
		req.end();
	});
}

/** Write the bytes as given and hand back everything the server answers. */
function raw(port: number, request: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		let data = '';
		socket.setEncoding('utf8');
		socket.on('data', (chunk: string) => (data += chunk));
		socket.on('error', reject);
		socket.on('close', () => resolve(data));
		socket.on('connect', () => socket.write(request));
	});
}

const statusOf = (response: string): number =>
	Number(/^HTTP\/1\.[01] (\d{3})/.exec(response)?.[1] ?? 0);
const bodyOf = (response: string): Record<string, unknown> =>
	JSON.parse(response.slice(response.indexOf('\r\n\r\n') + 4)) as Record<
		string,
		unknown
	>;

function collectingLogger(warnings: string[]): ILogger {
	return {
		debug: (): void => {},
		info: (): void => {},
		warn: (message: string): void => {
			warnings.push(message);
		},
		error: (): void => {}
	};
}

async function boot(
	dataDir: string,
	logger: ILogger,
	extra: Partial<DaemonOptions>
): Promise<{ daemon: Daemon; port: number }> {
	const daemon = await startDaemon({
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		rapidGossipSync: false,
		autoGossipSync: false,
		logLevel: 'silent',
		logger,
		network: 'regtest',
		mnemonic: MNEMONIC,
		dataDir,
		daemonPort: 0,
		...extra
	});
	return { daemon, port: (daemon.server.address() as AddressInfo).port };
}

describe('daemon browser guards while authentication is off (issue #1005)', function () {
	this.timeout(60_000);
	let root: string;
	let open: Daemon;
	let openPort: number;
	const openWarnings: string[] = [];
	let cors: Daemon;
	let corsPort: number;
	let authed: Daemon;
	let authedPort: number;
	const authedWarnings: string[] = [];

	before(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1005-'));
		({ daemon: open, port: openPort } = await boot(
			path.join(root, 'open'),
			collectingLogger(openWarnings),
			{}
		));
		({ daemon: cors, port: corsPort } = await boot(
			path.join(root, 'cors'),
			collectingLogger([]),
			{ cors: 'https://app.example' }
		));
		({ daemon: authed, port: authedPort } = await boot(
			path.join(root, 'authed'),
			collectingLogger(authedWarnings),
			{ apiToken: TOKEN }
		));
	});

	after(async () => {
		await Promise.all([open.stop(), cors.stop(), authed.stop()]);
		fs.rmSync(root, { recursive: true, force: true });
	});

	describe('no credential configured', () => {
		const invoiceCount = async (): Promise<number> => {
			const reply = await send(openPort, 'GET', '/invoices');
			expect(reply.status).to.equal(200);
			return (reply.json.result as unknown[]).length;
		};

		it('refuses a text/plain body with 415 UNSUPPORTED_MEDIA_TYPE and creates nothing', async () => {
			// What fetch() in no-cors mode sends: no preflight, text/plain.
			const reply = await send(
				openPort,
				'POST',
				'/invoice/create',
				{ 'Content-Type': 'text/plain;charset=UTF-8' },
				JSON.stringify({ amountSats: 1000, description: 'csrf' })
			);
			expect(reply.status).to.equal(415);
			expect(reply.json.ok).to.equal(false);
			expect(errorCode(reply)).to.equal('UNSUPPORTED_MEDIA_TYPE');
			expect(await invoiceCount()).to.equal(0);
		});

		it('refuses a body with no Content-Type at all with 415', async () => {
			// A Blob body from fetch() carries no Content-Type header.
			const reply = await send(
				openPort,
				'POST',
				'/invoice/create',
				{},
				JSON.stringify({ amountSats: 1000 })
			);
			expect(reply.status).to.equal(415);
			expect(errorCode(reply)).to.equal('UNSUPPORTED_MEDIA_TYPE');
			expect(await invoiceCount()).to.equal(0);
		});

		it('accepts application/json with a media type parameter, any case', async () => {
			const reply = await send(
				openPort,
				'POST',
				'/invoice/create',
				{ 'Content-Type': 'Application/JSON; charset=utf-8' },
				JSON.stringify({ amountSats: 1000, description: 'plain client' })
			);
			expect(reply.status, JSON.stringify(reply.json)).to.equal(200);
			expect(reply.json.ok).to.equal(true);
			expect(await invoiceCount()).to.equal(1);
		});

		it('a request without a body needs no Content-Type', async () => {
			// GET carries none; a bodyless POST reaches the route and is refused
			// there for its missing parameter, not by the guard.
			const balance = await send(openPort, 'GET', '/balance');
			expect(balance.status).to.equal(200);
			const decode = await send(openPort, 'POST', '/invoice/decode');
			expect(decode.status).to.equal(400);
			expect(errorCode(decode)).to.equal('INVALID_PARAMS');
		});

		it('refuses a foreign Origin with 403 CROSS_SITE_REQUEST_REFUSED', async () => {
			const reply = await send(openPort, 'GET', '/balance', {
				Origin: 'https://evil.example'
			});
			expect(reply.status).to.equal(403);
			expect(reply.json.ok).to.equal(false);
			expect(errorCode(reply)).to.equal('CROSS_SITE_REQUEST_REFUSED');
		});

		it('refuses the opaque Origin "null" a sandboxed page sends', async () => {
			const reply = await send(openPort, 'GET', '/balance', {
				Origin: 'null'
			});
			expect(reply.status).to.equal(403);
			expect(errorCode(reply)).to.equal('CROSS_SITE_REQUEST_REFUSED');
		});

		it('refuses Sec-Fetch-Site: cross-site without an Origin (an <img> or a navigation)', async () => {
			const reply = await send(openPort, 'GET', '/balance', {
				'Sec-Fetch-Site': 'cross-site'
			});
			expect(reply.status).to.equal(403);
			expect(errorCode(reply)).to.equal('CROSS_SITE_REQUEST_REFUSED');
		});

		it('lets Sec-Fetch-Site none, same-origin and same-site through', async () => {
			for (const site of ['none', 'same-origin', 'same-site']) {
				const reply = await send(openPort, 'GET', '/balance', {
					'Sec-Fetch-Site': site
				});
				expect(reply.status, site).to.equal(200);
			}
		});

		it('refuses a text/plain body ahead of the Origin check, whatever the order of the headers', async () => {
			// One refusal is enough; the body is read by nobody.
			const reply = await send(
				openPort,
				'POST',
				'/send',
				{ Origin: 'https://evil.example', 'Content-Type': 'text/plain' },
				JSON.stringify({ address: 'bcrt1qexample', amountSats: 500000 })
			);
			expect(reply.status).to.equal(415);
		});

		it('covers the auth-exempt routes and the SSE stream too', async () => {
			for (const route of ['/health', '/ready', '/openapi.json', '/events']) {
				const reply = await send(openPort, 'GET', route, {
					Origin: 'https://evil.example'
				});
				expect(reply.status, route).to.equal(403);
				expect(errorCode(reply), route).to.equal('CROSS_SITE_REQUEST_REFUSED');
			}
			// A plain client, with no Origin, still reaches them.
			const health = await send(openPort, 'GET', '/health');
			expect(health.status).to.equal(200);
		});

		it('OPTIONS with a foreign Origin still answers 204', async () => {
			const reply = await send(openPort, 'OPTIONS', '/invoice/create', {
				Origin: 'https://evil.example',
				'Access-Control-Request-Method': 'POST'
			});
			expect(reply.status).to.equal(204);
		});

		it('refuses a Host that is not the loopback name with 421 HOST_NOT_ALLOWED', async () => {
			for (const host of [
				'attacker.example',
				`attacker.example:${openPort}`,
				'127.0.0.1.attacker.example',
				'localhost.attacker.example',
				'10.0.0.5',
				'0.0.0.0'
			]) {
				const response = await raw(
					openPort,
					`GET /balance HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`
				);
				expect(statusOf(response), host).to.equal(421);
				const body = bodyOf(response);
				expect(body.ok, host).to.equal(false);
				expect((body.error as { code: string }).code, host).to.equal(
					'HOST_NOT_ALLOWED'
				);
			}
		});

		it('accepts localhost, 127.0.0.0/8 and [::1], with or without a port', async () => {
			for (const host of [
				`localhost:${openPort}`,
				`127.0.0.1:${openPort}`,
				`[::1]:${openPort}`,
				'localhost',
				'LOCALHOST',
				'127.0.0.1',
				'127.5.6.7',
				'[::1]'
			]) {
				const response = await raw(
					openPort,
					`GET /balance HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`
				);
				expect(statusOf(response), host).to.equal(200);
				expect(bodyOf(response).ok, host).to.equal(true);
			}
		});

		it('accepts an HTTP/1.0 request with no Host on a loopback bind', async () => {
			const response = await raw(
				openPort,
				'GET /balance HTTP/1.0\r\nConnection: close\r\n\r\n'
			);
			expect(statusOf(response), response).to.equal(200);
			expect(bodyOf(response).ok).to.equal(true);
		});

		it('logs the auth-off warning once at boot', () => {
			expect(
				openWarnings.filter((m) => m === AUTH_OFF_WARNING)
			).to.have.lengthOf(1);
		});
	});

	describe('cors origin configured, no credential', () => {
		it('lets the configured Origin through, cross-site fetch included', async () => {
			// A browser sends both headers for a page at the configured origin.
			const reply = await send(corsPort, 'GET', '/balance', {
				Origin: 'https://app.example',
				'Sec-Fetch-Site': 'cross-site'
			});
			expect(reply.status).to.equal(200);
			expect(reply.json.ok).to.equal(true);
		});

		it('still refuses any other Origin', async () => {
			for (const origin of [
				'https://evil.example',
				'https://app.example.evil',
				'http://app.example',
				'https://APP.example'
			]) {
				const reply = await send(corsPort, 'GET', '/balance', {
					Origin: origin
				});
				expect(reply.status, origin).to.equal(403);
				expect(errorCode(reply), origin).to.equal('CROSS_SITE_REQUEST_REFUSED');
			}
		});
	});

	describe('credential configured', () => {
		it('a text/plain body is refused by auth, not by the guard', async () => {
			const reply = await send(
				authedPort,
				'POST',
				'/invoice/create',
				{ 'Content-Type': 'text/plain' },
				JSON.stringify({ amountSats: 1000 })
			);
			expect(reply.status).to.equal(401);
			expect(errorCode(reply)).to.equal('UNAUTHORIZED');
		});

		it('a foreign Origin is refused by auth, not by the guard', async () => {
			const reply = await send(authedPort, 'GET', '/balance', {
				Origin: 'https://evil.example'
			});
			expect(reply.status).to.equal(401);
			expect(errorCode(reply)).to.equal('UNAUTHORIZED');
		});

		it('a foreign Host is refused by auth, not by the guard', async () => {
			const response = await raw(
				authedPort,
				'GET /balance HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n'
			);
			expect(statusOf(response)).to.equal(401);
		});

		it('a bearer client keeps its freedom: text/plain body and any Origin reach the route', async () => {
			const create = await send(
				authedPort,
				'POST',
				'/invoice/create',
				{
					Authorization: `Bearer ${TOKEN}`,
					'Content-Type': 'text/plain',
					Origin: 'https://evil.example'
				},
				JSON.stringify({ amountSats: 1000 })
			);
			expect(create.status, JSON.stringify(create.json)).to.equal(200);
			expect(create.json.ok).to.equal(true);
			const health = await send(authedPort, 'GET', '/health', {
				Origin: 'https://evil.example'
			});
			expect(health.status).to.equal(200);
		});

		it('does not log the auth-off warning', () => {
			expect(
				authedWarnings.filter((m) => m === AUTH_OFF_WARNING)
			).to.deep.equal([]);
		});
	});

	describe('helpers', () => {
		it('isJsonContentType accepts application/json with parameters, any case', () => {
			expect(isJsonContentType('application/json')).to.equal(true);
			expect(isJsonContentType('application/json; charset=utf-8')).to.equal(
				true
			);
			expect(isJsonContentType('Application/JSON;charset=UTF-8')).to.equal(
				true
			);
			expect(isJsonContentType(' application/json ')).to.equal(true);
			expect(isJsonContentType('text/plain')).to.equal(false);
			expect(isJsonContentType('application/x-www-form-urlencoded')).to.equal(
				false
			);
			expect(isJsonContentType('multipart/form-data; boundary=x')).to.equal(
				false
			);
			expect(isJsonContentType('application/json-patch+json')).to.equal(false);
			expect(isJsonContentType('')).to.equal(false);
			expect(isJsonContentType(undefined)).to.equal(false);
		});

		it('hostNameOfHeader strips the port and the brackets and refuses junk', () => {
			expect(hostNameOfHeader('localhost')).to.equal('localhost');
			expect(hostNameOfHeader('LocalHost:2112')).to.equal('localhost');
			expect(hostNameOfHeader('127.0.0.1:2112')).to.equal('127.0.0.1');
			expect(hostNameOfHeader('[::1]')).to.equal('::1');
			expect(hostNameOfHeader('[::1]:2112')).to.equal('::1');
			expect(hostNameOfHeader('example.com')).to.equal('example.com');
			for (const junk of ['a b', '[::1', 'a:b:c', '[::1]x', '[nope]', '']) {
				expect(hostNameOfHeader(junk), junk).to.equal(null);
			}
		});

		it('isAllowedHostHeader holds a loopback bind to loopback names', () => {
			for (const bind of ['127.0.0.1', 'localhost', '::1']) {
				expect(isAllowedHostHeader('localhost:2112', bind), bind).to.equal(
					true
				);
				expect(isAllowedHostHeader('127.0.0.1', bind), bind).to.equal(true);
				expect(isAllowedHostHeader('[::1]:2112', bind), bind).to.equal(true);
				expect(isAllowedHostHeader(undefined, bind), bind).to.equal(true);
				expect(isAllowedHostHeader('example.com', bind), bind).to.equal(false);
				expect(isAllowedHostHeader('127.example.com', bind), bind).to.equal(
					false
				);
				expect(isAllowedHostHeader('a b', bind), bind).to.equal(false);
			}
		});

		it('isAllowedHostHeader accepts a concrete non-loopback bind by its own name only', () => {
			expect(isAllowedHostHeader('192.168.1.5:2112', '192.168.1.5')).to.equal(
				true
			);
			expect(isAllowedHostHeader('localhost', '192.168.1.5')).to.equal(true);
			expect(isAllowedHostHeader('192.168.1.6', '192.168.1.5')).to.equal(false);
			expect(isAllowedHostHeader(undefined, '192.168.1.5')).to.equal(false);
			expect(isAllowedHostHeader('node.internal', 'node.internal')).to.equal(
				true
			);
			expect(isAllowedHostHeader('[fd00::5]:2112', 'fd00::5')).to.equal(true);
		});

		it('recognises the wildcard and loopback bind addresses', () => {
			for (const wild of ['0.0.0.0', '::', '[::]', '0:0:0:0:0:0:0:0']) {
				expect(isWildcardBindHost(wild), wild).to.equal(true);
				expect(isLoopbackBindHost(wild), wild).to.equal(false);
			}
			for (const loop of ['127.0.0.1', '127.9.9.9', 'localhost', '::1']) {
				expect(isLoopbackBindHost(loop), loop).to.equal(true);
				expect(isWildcardBindHost(loop), loop).to.equal(false);
			}
			expect(isLoopbackBindHost('127.example.com')).to.equal(false);
			expect(isLoopbackBindHost('192.168.1.5')).to.equal(false);
		});
	});
});
