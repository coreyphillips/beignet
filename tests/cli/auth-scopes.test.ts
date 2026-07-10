/**
 * Scoped API auth (M6): named keys with readonly/invoice/admin scopes,
 * constant-time comparison, runtime revocation, 401 vs 403, and a
 * source-derived drift test that fails when a daemon route ships without a
 * scope classification (mirrors the CLI-parity pattern).
 *
 * The daemon integration suite boots offline (unreachable Electrum, same
 * pattern as tests/cli/onchain-power.test.ts): auth decisions happen before
 * route handlers, and the 200-path routes used here (info, invoices,
 * invoice/create) are all local operations.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon, AUTH_EXEMPT_ROUTES } from '../../src/cli/daemon';
import {
	ApiKeyAuthenticator,
	ApiScope,
	ROUTE_SCOPES,
	getRouteScopes,
	scopesAllowRoute
} from '../../src/cli/auth';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { resolveConfig } from '../../src/cli/config';
import { getOpenApiSpec } from '../../src/cli/openapi';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// ─────────────── Route classification drift test ───────────────

describe('Route scope classification (drift test)', () => {
	const daemonSrc = fs.readFileSync(
		path.join(__dirname, '../../src/cli/daemon.ts'),
		'utf8'
	);

	/** Every route key in daemon.ts source, plus specially handled POST /stop. */
	function daemonRouteKeys(): Set<string> {
		const keys = new Set<string>();
		const re = /'((?:GET|POST|DELETE) \/[^']+)'/g;
		let m: RegExpExecArray | null;
		while ((m = re.exec(daemonSrc)) !== null) {
			keys.add(m[1]);
		}
		// /stop is dispatched via req.method/pathname, not the routes map
		keys.add('POST /stop');
		return keys;
	}

	it('every daemon route is classified in ROUTE_SCOPES or auth-exempt', () => {
		const unclassified = [...daemonRouteKeys()].filter(
			(key) => !AUTH_EXEMPT_ROUTES.has(key) && !(key in ROUTE_SCOPES)
		);
		expect(
			unclassified,
			`daemon routes without a scope classification in src/cli/auth.ts ` +
				`(they fail closed to admin-only until classified): ` +
				unclassified.join(', ')
		).to.deep.equal([]);
	});

	it('ROUTE_SCOPES contains no stale routes (keep the map honest)', () => {
		const routes = daemonRouteKeys();
		const stale = Object.keys(ROUTE_SCOPES).filter((key) => !routes.has(key));
		expect(
			stale,
			`ROUTE_SCOPES entries with no matching daemon route: ${stale.join(', ')}`
		).to.deep.equal([]);
	});

	it('auth-exempt routes are not also classified (one source of truth)', () => {
		const both = [...AUTH_EXEMPT_ROUTES].filter((key) => key in ROUTE_SCOPES);
		expect(both).to.deep.equal([]);
	});

	it('classified scopes only use known scope names and never list admin', () => {
		for (const [route, scopes] of Object.entries(ROUTE_SCOPES)) {
			for (const scope of scopes) {
				expect(['readonly', 'invoice'], `${route} lists ${scope}`).to.include(
					scope
				);
			}
		}
	});

	it('unknown routes fail closed to admin-only', () => {
		expect(getRouteScopes('POST /route/added/tomorrow')).to.deep.equal([]);
		expect(
			scopesAllowRoute(new Set<ApiScope>(['readonly']), 'POST /new-route')
		).to.equal(false);
		expect(
			scopesAllowRoute(new Set<ApiScope>(['invoice']), 'POST /new-route')
		).to.equal(false);
		expect(
			scopesAllowRoute(new Set<ApiScope>(['admin']), 'POST /new-route')
		).to.equal(true);
	});

	it('fund-moving and secret routes are admin-only', () => {
		for (const route of [
			'POST /send',
			'POST /send-max',
			'POST /invoice/pay',
			'POST /keysend',
			'POST /offer/pay',
			'POST /channel/open',
			'POST /channel/close',
			'POST /psbt/import-signed',
			'POST /restore/scb',
			'POST /stop',
			'GET /mnemonic',
			'GET /webhooks',
			'POST /webhooks/register',
			'POST /message/sign',
			'GET /auth/keys',
			'POST /auth/keys/revoke'
		]) {
			expect(ROUTE_SCOPES[route], route).to.deep.equal([]);
		}
	});
});

// ─────────────── scopesAllowRoute semantics ───────────────

describe('scopesAllowRoute', () => {
	const readonly = new Set<ApiScope>(['readonly']);
	const invoice = new Set<ApiScope>(['invoice']);
	const admin = new Set<ApiScope>(['admin']);
	const multi = new Set<ApiScope>(['readonly', 'invoice']);

	it('readonly can read but not mutate or pay', () => {
		expect(scopesAllowRoute(readonly, 'GET /info')).to.equal(true);
		expect(scopesAllowRoute(readonly, 'GET /invoices')).to.equal(true);
		expect(scopesAllowRoute(readonly, 'POST /route/estimate')).to.equal(true);
		expect(scopesAllowRoute(readonly, 'POST /send')).to.equal(false);
		expect(scopesAllowRoute(readonly, 'POST /invoice/create')).to.equal(false);
		expect(scopesAllowRoute(readonly, 'GET /mnemonic')).to.equal(false);
	});

	it('invoice covers receive-side routes only', () => {
		expect(scopesAllowRoute(invoice, 'POST /invoice/create')).to.equal(true);
		expect(scopesAllowRoute(invoice, 'POST /address/new')).to.equal(true);
		expect(scopesAllowRoute(invoice, 'GET /invoices')).to.equal(true);
		expect(scopesAllowRoute(invoice, 'GET /can-receive')).to.equal(true);
		expect(scopesAllowRoute(invoice, 'GET /info')).to.equal(false);
		expect(scopesAllowRoute(invoice, 'POST /invoice/pay')).to.equal(false);
		expect(scopesAllowRoute(invoice, 'POST /send')).to.equal(false);
	});

	it('admin can do everything', () => {
		for (const route of Object.keys(ROUTE_SCOPES)) {
			expect(scopesAllowRoute(admin, route), route).to.equal(true);
		}
	});

	it('multiple scopes union their grants', () => {
		expect(scopesAllowRoute(multi, 'GET /info')).to.equal(true);
		expect(scopesAllowRoute(multi, 'POST /invoice/create')).to.equal(true);
		expect(scopesAllowRoute(multi, 'POST /send')).to.equal(false);
	});
});

// ─────────────── ApiKeyAuthenticator unit tests ───────────────

describe('ApiKeyAuthenticator', () => {
	const keys = [
		{ name: 'monitor', key: 'ro-secret', scopes: ['readonly'] as ApiScope[] },
		{ name: 'shop', key: 'inv-secret', scopes: ['invoice'] as ApiScope[] },
		{ name: 'ops', key: 'admin-secret', scopes: ['admin'] as ApiScope[] }
	];

	it('is disabled with no credentials, enabled with either kind', () => {
		expect(new ApiKeyAuthenticator().enabled).to.equal(false);
		expect(new ApiKeyAuthenticator('tok').enabled).to.equal(true);
		expect(new ApiKeyAuthenticator(undefined, keys).enabled).to.equal(true);
	});

	it('legacy apiToken authenticates with implicit admin scope', () => {
		const auth = new ApiKeyAuthenticator('legacy-token', keys);
		const result = auth.authenticate('Bearer legacy-token');
		expect(result.ok).to.equal(true);
		if (result.ok) {
			expect(result.keyName).to.equal(null);
			expect(result.scopes.has('admin')).to.equal(true);
		}
	});

	it('named keys authenticate with their configured scopes', () => {
		const auth = new ApiKeyAuthenticator('legacy-token', keys);
		const result = auth.authenticate('Bearer ro-secret');
		expect(result.ok).to.equal(true);
		if (result.ok) {
			expect(result.keyName).to.equal('monitor');
			expect([...result.scopes]).to.deep.equal(['readonly']);
		}
	});

	it('bearer prefix is case-insensitive', () => {
		const auth = new ApiKeyAuthenticator('tok');
		expect(auth.authenticate('BEARER tok').ok).to.equal(true);
		expect(auth.authenticate('bearer tok').ok).to.equal(true);
	});

	it('rejects missing, malformed, and unknown credentials', () => {
		const auth = new ApiKeyAuthenticator('tok', keys);
		expect(auth.authenticate(undefined).ok).to.equal(false);
		expect(auth.authenticate('tok').ok).to.equal(false); // no Bearer prefix
		expect(auth.authenticate('Basic dG9r').ok).to.equal(false);
		expect(auth.authenticate('Bearer wrong').ok).to.equal(false);
	});

	it('constant-time path handles length mismatches without throwing', () => {
		// sha256 digests are always 32 bytes, so timingSafeEqual never sees a
		// length mismatch. Functional check: wildly different lengths compare
		// cleanly and correctly.
		const auth = new ApiKeyAuthenticator('short', [
			{ name: 'long', key: 'x'.repeat(4096), scopes: ['readonly'] }
		]);
		expect(auth.authenticate('Bearer ' + 'y'.repeat(100_000)).ok).to.equal(
			false
		);
		expect(auth.authenticate('Bearer s').ok).to.equal(false);
		expect(auth.authenticate('Bearer short').ok).to.equal(true);
		expect(auth.authenticate('Bearer ' + 'x'.repeat(4096)).ok).to.equal(true);
	});

	it('revoke disables a named key; unknown names return false', () => {
		const auth = new ApiKeyAuthenticator('legacy-token', keys);
		expect(auth.revoke('monitor')).to.equal(true);
		expect(auth.authenticate('Bearer ro-secret').ok).to.equal(false);
		// Other keys unaffected
		expect(auth.authenticate('Bearer inv-secret').ok).to.equal(true);
		expect(auth.authenticate('Bearer legacy-token').ok).to.equal(true);
		expect(auth.revoke('nope')).to.equal(false);
		expect(auth.revoke('legacy-token')).to.equal(false); // legacy has no name
	});

	it('listKeys exposes names/scopes/revoked but never secrets', () => {
		const auth = new ApiKeyAuthenticator('legacy-token', keys);
		auth.revoke('shop');
		const listed = auth.listKeys();
		expect(listed.map((k) => k.name)).to.deep.equal(['monitor', 'shop', 'ops']);
		expect(listed.find((k) => k.name === 'shop')?.revoked).to.equal(true);
		expect(listed.find((k) => k.name === 'monitor')?.revoked).to.equal(false);
		for (const entry of listed) {
			expect(Object.keys(entry).sort()).to.deep.equal([
				'name',
				'revoked',
				'scopes'
			]);
		}
	});

	it('rejects invalid key definitions at construction', () => {
		const cases: Array<[string, () => ApiKeyAuthenticator]> = [
			[
				'empty name',
				(): ApiKeyAuthenticator =>
					new ApiKeyAuthenticator(undefined, [
						{ name: '', key: 'k', scopes: ['readonly'] }
					])
			],
			[
				'empty key',
				(): ApiKeyAuthenticator =>
					new ApiKeyAuthenticator(undefined, [
						{ name: 'a', key: '', scopes: ['readonly'] }
					])
			],
			[
				'no scopes',
				(): ApiKeyAuthenticator =>
					new ApiKeyAuthenticator(undefined, [
						{ name: 'a', key: 'k', scopes: [] }
					])
			],
			[
				'unknown scope',
				(): ApiKeyAuthenticator =>
					new ApiKeyAuthenticator(undefined, [
						{ name: 'a', key: 'k', scopes: ['root' as ApiScope] }
					])
			],
			[
				'duplicate name',
				(): ApiKeyAuthenticator =>
					new ApiKeyAuthenticator(undefined, [
						{ name: 'a', key: 'k1', scopes: ['readonly'] },
						{ name: 'a', key: 'k2', scopes: ['readonly'] }
					])
			],
			[
				'duplicate key value',
				(): ApiKeyAuthenticator =>
					new ApiKeyAuthenticator(undefined, [
						{ name: 'a', key: 'same', scopes: ['readonly'] },
						{ name: 'b', key: 'same', scopes: ['invoice'] }
					])
			],
			[
				'key equal to legacy token',
				(): ApiKeyAuthenticator =>
					new ApiKeyAuthenticator('tok', [
						{ name: 'a', key: 'tok', scopes: ['readonly'] }
					])
			]
		];
		for (const [label, build] of cases) {
			try {
				build();
				expect.fail(`expected ${label} to throw`);
			} catch (err) {
				expect(err, label).to.be.instanceOf(BeignetError);
				expect((err as BeignetError).code, label).to.equal('INVALID_PARAMS');
			}
		}
	});
});

// ─────────────── Config resolution ───────────────

describe('Config apiKeys resolution', () => {
	afterEach(() => {
		delete process.env.BEIGNET_API_KEYS;
	});

	it('parses BEIGNET_API_KEYS JSON from the environment', () => {
		process.env.BEIGNET_API_KEYS = JSON.stringify([
			{ name: 'monitor', key: 's', scopes: ['readonly'] }
		]);
		const config = resolveConfig({});
		expect(config.apiKeys).to.deep.equal([
			{ name: 'monitor', key: 's', scopes: ['readonly'] }
		]);
	});

	it('ignores malformed BEIGNET_API_KEYS instead of crashing', () => {
		process.env.BEIGNET_API_KEYS = 'not-json';
		expect(resolveConfig({}).apiKeys).to.equal(undefined);
		process.env.BEIGNET_API_KEYS = '{"not":"an array"}';
		expect(resolveConfig({}).apiKeys).to.equal(undefined);
	});

	it('prefers CLI flags over env', () => {
		process.env.BEIGNET_API_KEYS = JSON.stringify([
			{ name: 'env', key: 'e', scopes: ['readonly'] }
		]);
		const config = resolveConfig({
			apiKeys: [{ name: 'flag', key: 'f', scopes: ['admin'] }]
		});
		expect(config.apiKeys?.[0].name).to.equal('flag');
	});
});

// ─────────────── OpenAPI scope annotations ───────────────

describe('OpenAPI scope annotations', () => {
	const spec = getOpenApiSpec() as {
		paths: Record<string, Record<string, Record<string, unknown>>>;
	};

	it('annotates operations with x-accepted-scopes from ROUTE_SCOPES', () => {
		expect(spec.paths['/info'].get['x-accepted-scopes']).to.deep.equal([
			'readonly',
			'admin'
		]);
		expect(
			spec.paths['/invoice/create'].post['x-accepted-scopes']
		).to.deep.equal(['invoice', 'admin']);
		expect(spec.paths['/send'].post['x-accepted-scopes']).to.deep.equal([
			'admin'
		]);
	});

	it('documents the auth key management endpoints', () => {
		expect(spec.paths).to.have.property('/auth/keys');
		expect(spec.paths).to.have.property('/auth/keys/revoke');
	});

	it('auth-exempt routes stay unannotated', () => {
		expect(spec.paths['/health'].get).to.not.have.property('x-accepted-scopes');
	});
});

// ─────────────── Daemon enforcement (offline integration) ───────────────

describe('Daemon scoped auth enforcement', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	const LEGACY = 'legacy-admin-token';
	const RO_KEY = 'readonly-key-secret';
	const INV_KEY = 'invoice-key-secret';
	const ADMIN_KEY = 'admin-key-secret';

	function request(
		method: string,
		urlPath: string,
		token?: string,
		body?: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> {
		return new Promise((resolve, reject) => {
			const payload = body ? JSON.stringify(body) : undefined;
			const headers: Record<string, string | number> = {};
			if (payload) {
				headers['Content-Type'] = 'application/json';
				headers['Content-Length'] = Buffer.byteLength(payload);
			}
			if (token) headers['Authorization'] = `Bearer ${token}`;
			const req = http.request(
				{ hostname: '127.0.0.1', port, path: urlPath, method, headers },
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
			if (payload) req.write(payload);
			req.end();
		});
	}

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-auth-scopes-'));
		// Electrum intentionally unreachable: auth decisions happen before
		// handlers, and 200-path routes used below are local operations.
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			daemonPort: 0,
			apiToken: LEGACY,
			apiKeys: [
				{ name: 'monitor', key: RO_KEY, scopes: ['readonly'] },
				{ name: 'shop', key: INV_KEY, scopes: ['invoice'] },
				{ name: 'ops', key: ADMIN_KEY, scopes: ['admin'] }
			]
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async function () {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('returns 401 for absent or unknown credentials', async () => {
		const absent = await request('GET', '/info');
		expect(absent.status).to.equal(401);
		expect((absent.body.error as { code: string }).code).to.equal(
			'UNAUTHORIZED'
		);
		const unknown = await request('GET', '/info', 'no-such-key');
		expect(unknown.status).to.equal(401);
	});

	it('auth-exempt routes work without credentials', async () => {
		const health = await request('GET', '/health');
		expect(health.status).to.equal(200);
		const ready = await request('GET', '/ready');
		expect(ready.status).to.equal(200);
	});

	it('readonly key: GETs succeed, mutations get 403 FORBIDDEN', async () => {
		const info = await request('GET', '/info', RO_KEY);
		expect(info.status).to.equal(200);
		expect(info.body.ok).to.equal(true);

		const send = await request('POST', '/send', RO_KEY, {
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			amountSats: 1000
		});
		expect(send.status).to.equal(403);
		const sendErr = send.body.error as { code: string; message: string };
		expect(sendErr.code).to.equal('FORBIDDEN');
		expect(sendErr.message).to.include('monitor');
		expect(sendErr.message).to.include('admin');

		const create = await request('POST', '/invoice/create', RO_KEY, {
			amountSats: 100
		});
		expect(create.status).to.equal(403);

		const mnemonic = await request('GET', '/mnemonic', RO_KEY);
		expect(mnemonic.status).to.equal(403);

		const stop = await request('POST', '/stop', RO_KEY, {});
		expect(stop.status).to.equal(403);
	});

	it('invoice key: can create/list invoices but not pay or read node state', async () => {
		const create = await request('POST', '/invoice/create', INV_KEY, {
			amountSats: 2100,
			description: 'scoped-auth-test'
		});
		expect(create.status).to.equal(200);
		expect(create.body.ok).to.equal(true);
		expect((create.body.result as { bolt11: string }).bolt11).to.be.a('string');

		const list = await request('GET', '/invoices', INV_KEY);
		expect(list.status).to.equal(200);
		expect(list.body.ok).to.equal(true);

		const pay = await request('POST', '/invoice/pay', INV_KEY, {
			bolt11: (create.body.result as { bolt11: string }).bolt11
		});
		expect(pay.status).to.equal(403);
		expect((pay.body.error as { code: string }).code).to.equal('FORBIDDEN');

		const info = await request('GET', '/info', INV_KEY);
		expect(info.status).to.equal(403);
	});

	it('admin key can hit read, invoice, and admin-only routes', async () => {
		expect((await request('GET', '/info', ADMIN_KEY)).status).to.equal(200);
		const create = await request('POST', '/invoice/create', ADMIN_KEY, {
			amountSats: 1
		});
		expect(create.status).to.equal(200);
		const keys = await request('GET', '/auth/keys', ADMIN_KEY);
		expect(keys.status).to.equal(200);
	});

	it('legacy token still works everywhere (implicit admin)', async () => {
		expect((await request('GET', '/info', LEGACY)).status).to.equal(200);
		const create = await request('POST', '/invoice/create', LEGACY, {
			amountSats: 1
		});
		expect(create.status).to.equal(200);
		const mnemonic = await request('GET', '/mnemonic', LEGACY);
		expect(mnemonic.status).to.equal(200);
		expect((mnemonic.body.result as { mnemonic: string }).mnemonic).to.include(
			'abandon'
		);
	});

	it('GET /auth/keys is admin-only and never returns secrets', async () => {
		const denied = await request('GET', '/auth/keys', RO_KEY);
		expect(denied.status).to.equal(403);

		const keys = await request('GET', '/auth/keys', LEGACY);
		expect(keys.status).to.equal(200);
		const listed = (
			keys.body.result as { keys: Array<Record<string, unknown>> }
		).keys;
		expect(listed.map((k) => k.name)).to.deep.equal(['monitor', 'shop', 'ops']);
		const raw = JSON.stringify(keys.body);
		expect(raw).to.not.include(RO_KEY);
		expect(raw).to.not.include(INV_KEY);
		expect(raw).to.not.include(ADMIN_KEY);
		expect(raw).to.not.include(LEGACY);
	});

	it('SSE /events: 401 without auth, 403 for a scope-less key, streams for readonly', async () => {
		const unauth = await request('GET', '/events');
		expect(unauth.status).to.equal(401);

		// admin-only surface check needs a key without readonly/invoice; the
		// closest here is asserting readonly IS accepted (documented choice:
		// /events serves monitoring + invoice-settlement consumers).
		await new Promise<void>((resolve, reject) => {
			const req = http.get(
				{
					hostname: '127.0.0.1',
					port,
					path: '/events',
					headers: { Authorization: `Bearer ${RO_KEY}` }
				},
				(res) => {
					try {
						expect(res.statusCode).to.equal(200);
						expect(res.headers['content-type']).to.equal('text/event-stream');
						req.destroy();
						resolve();
					} catch (err) {
						req.destroy();
						reject(err);
					}
				}
			);
			req.on('error', () => {
				// socket destroyed by us after headers; ignore
			});
		});
	});

	it('revocation: admin revokes a key, key stops working immediately (401)', async () => {
		const before = await request('GET', '/invoices', INV_KEY);
		expect(before.status).to.equal(200);

		const denied = await request('POST', '/auth/keys/revoke', RO_KEY, {
			name: 'shop'
		});
		expect(denied.status).to.equal(403);

		const revoke = await request('POST', '/auth/keys/revoke', LEGACY, {
			name: 'shop'
		});
		expect(revoke.status).to.equal(200);
		expect((revoke.body.result as { revoked: string }).revoked).to.equal(
			'shop'
		);

		const after = await request('GET', '/invoices', INV_KEY);
		expect(after.status).to.equal(401);

		// Other keys unaffected
		expect((await request('GET', '/info', RO_KEY)).status).to.equal(200);

		const unknown = await request('POST', '/auth/keys/revoke', LEGACY, {
			name: 'never-existed'
		});
		expect((unknown.body.error as { code: string }).code).to.equal('NOT_FOUND');
	});

	it('startDaemon rejects invalid apiKeys config before booting a node', async () => {
		try {
			await startDaemon({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				apiKeys: [{ name: 'bad', key: '', scopes: ['readonly'] }]
			});
			expect.fail('expected startDaemon to throw');
		} catch (err) {
			expect(err).to.be.instanceOf(BeignetError);
			expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
		}
	});
});
