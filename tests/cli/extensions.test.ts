/**
 * Host extensions (docs/EXTENSIONS.md).
 *
 * The contract in three layers: the description checks and the storage view
 * on their own, the host that carries an extension across node builds, and
 * a daemon serving an extension's routes and events beside its own.
 *
 * Chainless, like tests/cli/daemon-exposure-limits.test.ts: an unreachable
 * Electrum, daemonPort 0, and nothing here needs a chain.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetNode } from '../../src/cli/beignet-node';
import { DaemonOptions, startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import {
	EXTENSION_API,
	EXTENSION_API_VERSION,
	EXTENSION_MAX_BODY_BYTES,
	ExtensionError,
	ExtensionHost,
	IBeignetExtension,
	IExtensionAttachment,
	IExtensionBuild,
	IExtensionContext,
	IExtensionInfo,
	carryExtensionRows,
	extensionRefusal,
	extensionStorageView,
	validateExtensions,
	withExtensionOperations
} from '../../src/cli/extension';
import {
	extensionPathsFromEnv,
	loadExtensions
} from '../../src/cli/extension-loader';
import { getOpenApiSpec } from '../../src/cli/openapi';
import { ROUTES } from '../../src/cli/routes';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import type { Wallet } from '../../src/wallet';

type Daemon = Awaited<ReturnType<typeof startDaemon>>;
type Reply = {
	status: number;
	json: {
		ok?: boolean;
		result?: unknown;
		error?: {
			code: string;
			message: string;
			extension?: { id: string; code: string; details?: unknown };
		};
	};
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ADMIN_TOKEN = 'extensions-admin-token';
const READONLY_KEY = 'extensions-readonly-key';
const INVOICE_KEY = 'extensions-invoice-key';

const sleep = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

function send(
	port: number,
	method: string,
	route: string,
	options: {
		token?: string;
		body?: unknown;
		headers?: Record<string, string>;
	} = {}
): Promise<Reply> {
	return new Promise((resolve, reject) => {
		const headers: Record<string, string | number> = { ...options.headers };
		if (options.token) headers['Authorization'] = `Bearer ${options.token}`;
		const payload =
			options.body === undefined ? undefined : JSON.stringify(options.body);
		if (payload !== undefined) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
		const req = http.request(
			{ host: '127.0.0.1', port, path: route, method, headers },
			(res) => {
				let body = '';
				res.setEncoding('utf8');
				res.on('data', (chunk: string) => (body += chunk));
				res.on('end', () => {
					let json: Reply['json'] = {};
					try {
						json = JSON.parse(body) as Reply['json'];
					} catch {
						// The assertions below read the status in that case.
					}
					resolve({ status: res.statusCode ?? 0, json });
				});
			}
		);
		req.on('error', reject);
		if (payload !== undefined) req.write(payload);
		req.end();
	});
}

/** Open GET /events and collect the frames that arrive. */
function openEvents(
	port: number,
	token: string
): Promise<{ frames: string[]; close: () => void }> {
	return new Promise((resolve, reject) => {
		const frames: string[] = [];
		const req = http.request(
			{
				host: '127.0.0.1',
				port,
				path: '/events',
				method: 'GET',
				headers: { Authorization: `Bearer ${token}` },
				agent: false
			},
			(res) => {
				res.setEncoding('utf8');
				res.on('data', (chunk: string) => frames.push(chunk));
				resolve({ frames, close: () => req.destroy() });
			}
		);
		req.on('error', reject);
		req.end();
	});
}

async function boot(
	dataDir: string,
	extra: Partial<DaemonOptions> = {}
): Promise<{ daemon: Daemon; port: number }> {
	const daemon = await startDaemon({
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		rapidGossipSync: false,
		autoGossipSync: false,
		logLevel: 'silent',
		network: 'regtest',
		mnemonic: MNEMONIC,
		dataDir,
		daemonPort: 0,
		apiToken: ADMIN_TOKEN,
		apiKeys: [
			{ name: 'watcher', key: READONLY_KEY, scopes: ['readonly'] },
			{ name: 'till', key: INVOICE_KEY, scopes: ['invoice'] }
		],
		...extra
	});
	return { daemon, port: (daemon.server.address() as AddressInfo).port };
}

/** What the demo extension records about its own life, for the assertions. */
interface IDemoLog {
	contexts: IExtensionContext[];
	started: number;
	stops: string[];
	runs: Array<{ key: string; idempotencyKey?: string }>;
	/** Whether a write made inside stop('shutdown') landed. */
	wroteInStop?: boolean;
}

function demoExtension(log: IDemoLog, id = 'demo'): IBeignetExtension {
	return {
		id,
		version: '1.2.3',
		api: EXTENSION_API_VERSION,
		events: ['tick'],
		routes: [
			{
				method: 'GET',
				path: '/status',
				scopes: ['readonly'],
				summary: 'Status'
			},
			{ method: 'POST', path: '/echo', summary: 'Echo the body' },
			{
				method: 'POST',
				path: '/spend',
				idempotent: true,
				summary: 'Count a run',
				requestSchema: { type: 'object' },
				responseSchema: { type: 'object' }
			},
			{ method: 'POST', path: '/refuse', summary: 'Refuse with a code' },
			{ method: 'POST', path: '/fault', summary: 'Throw a plain error' },
			{
				method: 'POST',
				path: '/large',
				maxBodyBytes: 2 * 1024 * 1024,
				summary: 'Take a body past the default limit'
			},
			{ method: 'POST', path: '/store', summary: 'Write a row' },
			{ method: 'POST', path: '/emit', summary: 'Emit an event' },
			{ method: 'DELETE', path: '/store', summary: 'Delete a row' }
		],
		attach(context): IExtensionAttachment {
			log.contexts.push(context);
			return {
				handlers: {
					'GET /status': ({ query }) => ({
						generation: context.generation,
						network: context.network,
						hasWallet: typeof context.wallet.getBalance === 'function',
						asked: query.get('q')
					}),
					'POST /echo': ({ body }) => body,
					'POST /spend': ({ idempotencyKey }) => {
						log.runs.push({ key: 'spend', idempotencyKey });
						return { runs: log.runs.length };
					},
					'POST /refuse': () => {
						throw new ExtensionError('NOT_ENOUGH', 'Not enough of it', 409, {
							needed: '12',
							held: '5'
						});
					},
					'POST /fault': () => {
						throw new Error('secret detail that must not leak');
					},
					'POST /large': ({ body }) => ({
						bytes: String(body.blob).length
					}),
					'POST /store': ({ body }) => {
						context.storage.set(String(body.key), String(body.value));
						return { stored: context.storage.get(String(body.key)) };
					},
					'DELETE /store': ({ query }) => {
						context.storage.delete(String(query.get('key')));
						return undefined;
					},
					'POST /emit': ({ body }) => {
						context.emit(String(body.event), { n: body.n });
						return { emitted: true };
					}
				},
				start: (): void => {
					log.started++;
				},
				stop: (reason): void => {
					log.stops.push(reason);
					if (reason === 'shutdown') {
						try {
							context.storage.set('stopped-at', 'shutdown');
							log.wroteInStop = true;
						} catch {
							log.wroteInStop = false;
						}
					}
				},
				status: () => ({ generation: context.generation })
			};
		}
	};
}

const newLog = (): IDemoLog => ({
	contexts: [],
	started: 0,
	stops: [],
	runs: []
});

const refusalOf = (fn: () => unknown): BeignetError => {
	try {
		fn();
	} catch (err) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	throw new Error('expected a refusal');
};

const minimal = (over: Record<string, unknown> = {}): IBeignetExtension =>
	({
		id: 'demo',
		version: '1',
		api: EXTENSION_API_VERSION,
		attach: () => ({}),
		...over
	}) as unknown as IBeignetExtension;

describe('host extensions: the description', () => {
	it('accepts a complete description', () => {
		expect(() => validateExtensions([demoExtension(newLog())])).not.to.throw();
		expect(() => validateExtensions([])).not.to.throw();
	});

	it('refuses each malformed field with INVALID_PARAMS that names it', () => {
		const cases: Array<[string, Record<string, unknown>, RegExp]> = [
			['an uppercase id', { id: 'Demo' }, /id "Demo" is not valid/],
			['a one-letter id', { id: 'a' }, /is not valid/],
			['an id with a slash', { id: 'a/b' }, /is not valid/],
			['no version', { version: '' }, /must state its version/],
			['another contract', { api: 2 }, /built for extension API 2/],
			['no attach', { attach: undefined }, /no attach function/],
			[
				'a PUT route',
				{ routes: [{ method: 'PUT', path: '/a', summary: 's' }] },
				/is not GET, POST or DELETE/
			],
			[
				'a path with a parameter',
				{ routes: [{ method: 'GET', path: '/a/:id', summary: 's' }] },
				/route path "\/a\/:id" is not valid/
			],
			[
				'a path that climbs',
				{ routes: [{ method: 'GET', path: '/../info', summary: 's' }] },
				/is not valid/
			],
			[
				'a route twice',
				{
					routes: [
						{ method: 'GET', path: '/a', summary: 's' },
						{ method: 'GET', path: '/a', summary: 's' }
					]
				},
				/declares GET \/a twice/
			],
			[
				'no summary',
				{ routes: [{ method: 'GET', path: '/a' }] },
				/needs a summary/
			],
			[
				'the admin scope',
				{
					routes: [
						{ method: 'GET', path: '/a', summary: 's', scopes: ['admin'] }
					]
				},
				/scopes may list only readonly and invoice/
			],
			[
				'an idempotent GET',
				{
					routes: [
						{ method: 'GET', path: '/a', summary: 's', idempotent: true }
					]
				},
				/not a POST, so it cannot be idempotent/
			],
			[
				'a body limit past the ceiling',
				{
					routes: [
						{
							method: 'POST',
							path: '/a',
							summary: 's',
							maxBodyBytes: EXTENSION_MAX_BODY_BYTES + 1
						}
					]
				},
				/maxBodyBytes must be an integer/
			],
			[
				'an event with a colon',
				{ events: ['a:b'] },
				/event "a:b" is not valid/
			],
			['an event twice', { events: ['a', 'a'] }, /declares event a twice/]
		];
		for (const [label, over, message] of cases) {
			const err = refusalOf(() => validateExtensions([minimal(over)]));
			expect(err.code, label).to.equal('INVALID_PARAMS');
			expect(err.message, label).to.match(message);
		}
	});

	it('refuses two extensions with one id', () => {
		const err = refusalOf(() => validateExtensions([minimal(), minimal()]));
		expect(err.message).to.match(/"demo" is listed twice/);
	});

	it('reads a refusal by shape, and nothing else as one', () => {
		expect(
			extensionRefusal(new ExtensionError('NOPE', 'no', 404, { a: 1 }))
		).to.deep.equal({
			code: 'NOPE',
			message: 'no',
			status: 404,
			details: { a: 1 }
		});
		// Another copy of the class, or no class at all.
		const foreign = Object.assign(new Error('gone'), {
			extensionCode: 'GONE',
			status: 410
		});
		expect(extensionRefusal(foreign)).to.deep.equal({
			code: 'GONE',
			message: 'gone',
			status: 410
		});
		// A status outside the contract falls back to 400, never to a 2xx.
		const odd = Object.assign(new Error('x'), {
			extensionCode: 'ODD',
			status: 200
		});
		expect(extensionRefusal(odd)?.status).to.equal(400);
		expect(extensionRefusal(new Error('plain'))).to.equal(null);
		expect(
			extensionRefusal(Object.assign(new Error('x'), { extensionCode: 'bad' }))
		).to.equal(null);
		expect(extensionRefusal('a string')).to.equal(null);
	});

	it("keeps /x/ free of the daemon's own routes", () => {
		expect(
			ROUTES.filter((route) => route.path.startsWith('/x/'))
		).to.deep.equal([]);
	});

	it('adds operations to the OpenAPI document only when there are extensions', () => {
		const spec = getOpenApiSpec();
		expect(withExtensionOperations(spec, [])).to.equal(spec);
		const merged = withExtensionOperations(spec, [demoExtension(newLog())]) as {
			paths: Record<string, Record<string, Record<string, unknown>>>;
		};
		expect(
			merged.paths['/x/demo/status'].get['x-accepted-scopes']
		).to.deep.equal(['readonly', 'admin']);
		expect(
			merged.paths['/x/demo/echo'].post['x-accepted-scopes']
		).to.deep.equal(['admin']);
		expect(merged.paths['/x/demo/spend'].post['x-idempotent']).to.equal(true);
		// Two methods on one path, and the daemon's own paths untouched.
		expect(Object.keys(merged.paths['/x/demo/store']).sort()).to.deep.equal([
			'delete',
			'post'
		]);
		expect(merged.paths['/info']).to.equal(
			(spec.paths as Record<string, unknown>)['/info']
		);
		expect(
			Object.keys(spec.paths as Record<string, unknown>).some((p) =>
				p.startsWith('/x/')
			)
		).to.equal(false);
	});
});

describe('host extensions: the storage view', () => {
	let storage: SqliteStorage;

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});

	afterEach(() => {
		storage.close();
	});

	it('keeps each extension to its own keys', () => {
		const a = extensionStorageView('alpha', () => storage).storage;
		const b = extensionStorageView('beta', () => storage).storage;
		a.set('k', 'from-a');
		b.set('k', 'from-b');
		a.set('list/1', 'one');
		a.set('list/2', 'two');
		storage.saveMetadata('blockHeight', '7');
		expect(a.get('k')).to.equal('from-a');
		expect(b.get('k')).to.equal('from-b');
		expect(storage.loadMetadata('x/alpha/k')).to.equal('from-a');
		expect(a.list('list/')).to.deep.equal([
			{ key: 'list/1', value: 'one' },
			{ key: 'list/2', value: 'two' }
		]);
		expect(a.list('').map((row) => row.key)).to.deep.equal([
			'k',
			'list/1',
			'list/2'
		]);
		a.delete('k');
		expect(a.get('k')).to.equal(null);
		expect(b.get('k')).to.equal('from-b');
		// An id that is a prefix of another does not see its rows.
		const al = extensionStorageView('al', () => storage).storage;
		expect(al.list('')).to.deep.equal([]);
	});

	it('undoes every write of a transaction that throws', () => {
		const { storage: view } = extensionStorageView('alpha', () => storage);
		view.set('kept', '1');
		expect(() =>
			view.transaction(() => {
				view.set('kept', '2');
				view.set('new', '1');
				throw new Error('halfway');
			})
		).to.throw('halfway');
		expect(view.get('kept')).to.equal('1');
		expect(view.get('new')).to.equal(null);
		expect(view.transaction(() => view.get('kept'))).to.equal('1');
	});

	it('refuses keys that could leave the namespace or break the scan', () => {
		const { storage: view } = extensionStorageView('alpha', () => storage);
		expect(() => view.set('', 'v')).to.throw(TypeError);
		expect(() => view.get('a\u0000b')).to.throw(TypeError);
		expect(() => view.set('k', 5 as unknown as string)).to.throw(TypeError);
		expect(() => view.set('k'.repeat(513), 'v')).to.throw(TypeError);
	});

	it('throws on every call once fenced, and follows a replaced database', () => {
		let current = storage;
		const view = extensionStorageView('alpha', () => current);
		view.storage.set('k', 'old-db');
		const next = new SqliteStorage(':memory:');
		next.open();
		try {
			current = next;
			expect(view.storage.get('k')).to.equal(null);
			view.storage.set('k', 'new-db');
			expect(next.loadMetadata('x/alpha/k')).to.equal('new-db');
			expect(storage.loadMetadata('x/alpha/k')).to.equal('old-db');
			view.fence();
			for (const call of [
				(): unknown => view.storage.get('k'),
				(): unknown => view.storage.set('k', 'late'),
				(): unknown => view.storage.delete('k'),
				(): unknown => view.storage.list(''),
				(): unknown => view.storage.transaction(() => 1)
			]) {
				expect(call).to.throw('The database connection is not open');
			}
			expect(next.loadMetadata('x/alpha/k')).to.equal('new-db');
		} finally {
			next.close();
		}
	});

	it('carries every extension row into another database, and only those', () => {
		const target = new SqliteStorage(':memory:');
		target.open();
		try {
			extensionStorageView('alpha', () => storage).storage.set('a', '1');
			extensionStorageView('beta', () => storage).storage.set('b', '2');
			storage.saveMetadata('blockHeight', '7');
			expect(carryExtensionRows(storage, target)).to.equal(2);
			expect(target.loadMetadataByPrefix('x/')).to.deep.equal([
				{ key: 'x/alpha/a', value: '1' },
				{ key: 'x/beta/b', value: '2' }
			]);
			expect(target.loadMetadata('blockHeight')).to.equal(null);
			expect(carryExtensionRows(target, storage)).to.equal(2);
		} finally {
			target.close();
		}
	});

	it('BeignetNode carries extension rows into the staged database of a restore', () => {
		const target = new SqliteStorage(':memory:');
		target.open();
		try {
			storage.saveMetadata('x/assets/proof/1', 'the only copy');
			const node = Object.create(BeignetNode.prototype) as {
				storage: SqliteStorage;
				networkName: string;
				carryDaemonState: (from: SqliteStorage, to: SqliteStorage) => void;
			};
			node.storage = storage;
			node.networkName = 'regtest';
			node.carryDaemonState(storage, target);
			expect(target.loadMetadata('x/assets/proof/1')).to.equal('the only copy');
		} finally {
			target.close();
		}
	});
});

describe('host extensions: the host across node builds', () => {
	let storage: SqliteStorage;
	let logs: Array<{ level: string; message: string }>;

	const build = (): IExtensionBuild => ({
		network: 'regtest',
		dataDir: undefined,
		wallet: {} as Wallet,
		storage: () => storage
	});

	const host = (
		extensions: IBeignetExtension[],
		over: { stopTimeoutMs?: number; attachTimeoutMs?: number } = {}
	): ExtensionHost =>
		new ExtensionHost(extensions, {
			engineVersion: '9.9.9',
			log: (level, message) => logs.push({ level, message }),
			...over
		});

	const only = (h: ExtensionHost): IExtensionInfo => h.describe()[0];

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
		logs = [];
	});

	afterEach(() => {
		storage.close();
	});

	it('attaches, starts and reports an extension', async () => {
		const log = newLog();
		const h = host([demoExtension(log)]);
		expect(only(h).state).to.equal('pending');
		expect(only(h).generation).to.equal(0);
		await h.attach(build());
		expect(only(h).state).to.equal('attached');
		expect(log.contexts[0].generation).to.equal(1);
		expect(log.contexts[0].engineVersion).to.equal('9.9.9');
		h.startInBackground();
		await h.started;
		const info = only(h);
		expect(info.state).to.equal('ready');
		expect(info.generation).to.equal(1);
		expect(info.status).to.deep.equal({ generation: 1 });
		expect(info.events).to.deep.equal(['demo:tick']);
		expect(info.routes[0]).to.deep.equal({
			method: 'GET',
			path: '/x/demo/status',
			scopes: ['readonly', 'admin'],
			idempotent: false
		});
		expect(log.started).to.equal(1);
	});

	it('contains an attach() that throws, and serves the others', async () => {
		const log = newLog();
		const broken = minimal({
			id: 'broken',
			routes: [{ method: 'GET', path: '/a', summary: 's' }],
			attach: () => {
				throw new Error('no database for me');
			}
		});
		const h = host([broken, demoExtension(log)]);
		await h.attach(build());
		const [first, second] = h.describe();
		expect(first.state).to.equal('failed');
		expect(first.error).to.equal('attach: no database for me');
		expect(second.state).to.equal('attached');
		const err = refusalOf(() => h.handler('broken', 'GET /a'));
		expect(err.code).to.equal('EXTENSION_UNAVAILABLE');
		expect(err.message).to.match(/failed: attach: no database for me/);
		expect(h.handler('demo', 'POST /echo')).to.be.a('function');
		expect(logs.some((entry) => entry.level === 'error')).to.equal(true);
	});

	it('fails an attachment whose handlers do not match its routes', async () => {
		const missing = minimal({
			routes: [{ method: 'GET', path: '/a', summary: 's' }],
			attach: () => ({ handlers: {} })
		});
		const h1 = host([missing]);
		await h1.attach(build());
		expect(only(h1).error).to.equal('attach: no handler for GET /a');

		const extra = minimal({
			attach: () => ({ handlers: { 'GET /hidden': () => 1 } })
		});
		const h2 = host([extra]);
		await h2.attach(build());
		expect(only(h2).error).to.equal(
			'attach: handler for an undeclared route: GET /hidden'
		);
	});

	it('fails an extension whose start() throws, stops it and closes its routes', async () => {
		const stops: string[] = [];
		const h = host([
			minimal({
				routes: [{ method: 'GET', path: '/a', summary: 's' }],
				attach: () => ({
					handlers: { 'GET /a': () => 1 },
					start: () => {
						throw new Error('port taken');
					},
					stop: (reason: string) => {
						stops.push(reason);
					}
				})
			})
		]);
		await h.attach(build());
		await h.start();
		expect(only(h).state).to.equal('failed');
		expect(only(h).error).to.equal('start: port taken');
		expect(stops).to.deep.equal(['shutdown']);
		expect(() => h.handler('demo', 'GET /a')).to.throw(/failed: start/);
	});

	it('gives up on an attach() that does not answer, and stops it when it does', async () => {
		let release: (attachment: IExtensionAttachment) => void = () => undefined;
		const stops: string[] = [];
		const h = host(
			[
				minimal({
					attach: () =>
						new Promise<IExtensionAttachment>((resolve) => {
							release = resolve;
						})
				})
			],
			{ attachTimeoutMs: 20 }
		);
		await h.attach(build());
		expect(only(h).state).to.equal('failed');
		expect(only(h).error).to.match(/attach\(\) did not finish within 20 ms/);
		release({ stop: (reason) => void stops.push(reason) });
		await sleep(5);
		expect(stops).to.deep.equal(['shutdown']);
	});

	it('fences a generation for a rebuild and attaches the next one', async () => {
		const log = newLog();
		const seen: Array<[string, unknown]> = [];
		const h = host([demoExtension(log)]);
		h.onEvent((event, data) => seen.push([event, data]));
		await h.attach(build());
		await h.start();
		const first = log.contexts[0];
		first.storage.set('k', 'v');
		first.emit('tick', { n: 1 });

		h.fenceForRebuild();
		// Synchronously: nothing of the old generation lands from here on.
		expect(() => first.storage.set('k', 'late')).to.throw(
			'The database connection is not open'
		);
		first.emit('tick', { n: 2 });
		expect(only(h).state).to.equal('stopped');
		expect(() => h.handler('demo', 'POST /echo')).to.throw(/is stopped/);

		await h.attach(build());
		await h.start();
		expect(log.stops).to.deep.equal(['rebuild']);
		expect(log.contexts).to.have.length(2);
		const second = log.contexts[1];
		expect(second.generation).to.equal(2);
		expect(second.storage.get('k')).to.equal('v');
		expect(only(h).state).to.equal('ready');
		expect(only(h).generation).to.equal(2);
		second.emit('tick', { n: 3 });
		expect(seen).to.deep.equal([
			['demo:tick', { n: 1 }],
			['demo:tick', { n: 3 }]
		]);
		// The first generation stays fenced.
		expect(() => first.storage.get('k')).to.throw();
	});

	it('waits for the stop hooks of one generation before attaching the next', async () => {
		const order: string[] = [];
		let generation = 0;
		const h = host([
			minimal({
				attach: () => {
					const mine = ++generation;
					order.push(`attach ${mine}`);
					return {
						stop: async (): Promise<void> => {
							await sleep(30);
							order.push(`stopped ${mine}`);
						}
					};
				}
			})
		]);
		await h.attach(build());
		h.fenceForRebuild();
		await h.attach(build());
		expect(order).to.deep.equal(['attach 1', 'stopped 1', 'attach 2']);
	});

	it('drops an undeclared event with a warning', async () => {
		const log = newLog();
		const seen: string[] = [];
		const h = host([demoExtension(log)]);
		h.onEvent((event) => seen.push(event));
		await h.attach(build());
		log.contexts[0].emit('payment', {});
		log.contexts[0].emit('tick', {});
		expect(seen).to.deep.equal(['demo:tick']);
		expect(
			logs.filter((entry) => entry.message.includes('undeclared event'))
		).to.have.length(1);
	});

	it('runs stop hooks with the storage open on shutdown, then fences', async () => {
		const log = newLog();
		const h = host([demoExtension(log)]);
		await h.attach(build());
		await h.start();
		await h.shutdown();
		expect(log.stops).to.deep.equal(['shutdown']);
		expect(log.wroteInStop).to.equal(true);
		expect(storage.loadMetadata('x/demo/stopped-at')).to.equal('shutdown');
		expect(() => log.contexts[0].storage.get('k')).to.throw();
		expect(only(h).state).to.equal('stopped');
		// Idempotent, and nothing attaches after it.
		await h.shutdown();
		await h.attach(build());
		expect(log.contexts).to.have.length(1);
		expect(log.stops).to.deep.equal(['shutdown']);
	});

	it('fences at once when the node is destroyed, without waiting for stop', async () => {
		const log = newLog();
		const h = host([demoExtension(log)]);
		await h.attach(build());
		h.abort();
		// Synchronously: the view is closed before the hook could write.
		expect(() => log.contexts[0].storage.get('k')).to.throw(
			'The database connection is not open'
		);
		expect(log.stops).to.deep.equal(['shutdown']);
		expect(log.wroteInStop).to.equal(false);
		expect(storage.loadMetadata('x/demo/stopped-at')).to.equal(null);
		expect(only(h).state).to.equal('stopped');
		expect(() => h.handler('demo', 'POST /echo')).to.throw(/is stopped/);
		await h.shutdown();
		expect(log.stops).to.deep.equal(['shutdown']);
	});

	it('moves on from a stop() that hangs or throws', async () => {
		const hangs = minimal({
			id: 'hangs',
			attach: () => ({ stop: () => new Promise<void>(() => undefined) })
		});
		const throws = minimal({
			id: 'throws',
			attach: () => ({
				stop: () => {
					throw new Error('already gone');
				}
			})
		});
		const h = host([hangs, throws], { stopTimeoutMs: 20 });
		await h.attach(build());
		const began = Date.now();
		await h.shutdown();
		expect(Date.now() - began).to.be.lessThan(2_000);
		expect(logs.map((entry) => entry.message)).to.include.members([
			'Extension stop timed out',
			'Extension stop failed'
		]);
	});
});

describe('host extensions: loading from disk', () => {
	let dir: string;

	const write = (name: string, source: string, mode = 0o600): string => {
		const file = path.join(dir, name);
		fs.writeFileSync(file, source, { mode });
		fs.chmodSync(file, mode);
		return file;
	};

	const VALID = `exports.beignetExtension = {
		id: 'ondisk', version: '0.1.0', api: 1,
		attach() { return {}; }
	};`;

	const rejection = async (files: string[]): Promise<BeignetError> => {
		try {
			await loadExtensions(files, { network: 'regtest', env: {} });
		} catch (err) {
			expect(err).to.be.instanceOf(BeignetError);
			expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
			return err as BeignetError;
		}
		throw new Error('expected a refusal');
	};

	before(() => {
		// realpath, because the loader compares resolved paths (macOS keeps
		// its temporary directory behind a symlink).
		dir = fs.realpathSync(
			fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ext-load-'))
		);
	});

	after(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('reads BEIGNET_EXTENSIONS as a comma separated list', () => {
		expect(extensionPathsFromEnv(undefined)).to.deep.equal([]);
		expect(extensionPathsFromEnv('')).to.deep.equal([]);
		expect(extensionPathsFromEnv(' /a/b.js , /c/d.js,')).to.deep.equal([
			'/a/b.js',
			'/c/d.js'
		]);
	});

	it('loads a module that exports the extension', async () => {
		const [extension] = await loadExtensions([write('valid.js', VALID)], {
			network: 'regtest',
			env: {}
		});
		expect(extension.id).to.equal('ondisk');
	});

	it('calls a factory with the network, the environment and the versions', async () => {
		const file = write(
			'factory.js',
			`exports.beignetExtension = async (ctx) => ({
				id: 'made', version: ctx.env.DEMO_VERSION + '-' + ctx.network,
				api: ctx.api, attach() { return {}; },
				events: [typeof ctx.engineVersion === 'string' ? 'ok' : 'bad']
			});`
		);
		const [extension] = await loadExtensions([file], {
			network: 'testnet',
			env: { DEMO_VERSION: '7' }
		});
		expect(extension.version).to.equal('7-testnet');
		expect(extension.events).to.deep.equal(['ok']);
	});

	it('refuses a relative path, a missing file and a directory', async () => {
		expect((await rejection(['relative.js'])).message).to.match(
			/the path must be absolute/
		);
		expect((await rejection([path.join(dir, 'missing.js')])).message).to.match(
			/no such file/
		);
		expect((await rejection([dir])).message).to.match(/not a file/);
	});

	it('refuses a file or a directory other users can write', async function () {
		if (process.platform === 'win32') this.skip();
		const loose = write('loose.js', VALID, 0o622);
		expect((await rejection([loose])).message).to.match(
			/writable by its group or by everyone/
		);
		const shared = path.join(dir, 'shared');
		fs.mkdirSync(shared);
		fs.chmodSync(shared, 0o777);
		const inside = path.join(shared, 'ext.js');
		fs.writeFileSync(inside, VALID, { mode: 0o600 });
		expect((await rejection([inside])).message).to.match(
			/shared is writable by its group or by everyone/
		);
	});

	it('checks the file a symlink points at', async function () {
		if (process.platform === 'win32') this.skip();
		const target = write('target-loose.js', VALID, 0o666);
		const link = path.join(dir, 'link.js');
		fs.symlinkSync(target, link);
		expect((await rejection([link])).message).to.match(/writable by/);
	});

	it('refuses a module that does not load, exports nothing, or describes nothing valid', async () => {
		expect(
			(await rejection([write('throws.js', `throw new Error('boom');`)]))
				.message
		).to.match(/could not be loaded \(boom\)/);
		expect(
			(await rejection([write('empty.js', `exports.other = 1;`)])).message
		).to.match(/does not export beignetExtension/);
		expect(
			(
				await rejection([
					write(
						'factory-throws.js',
						`exports.beignetExtension = () => { throw new Error('no env'); };`
					)
				])
			).message
		).to.match(/beignetExtension\(\) failed \(no env\)/);
		expect(
			(
				await rejection([
					write('badid.js', `exports.beignetExtension = { id: 'X' };`)
				])
			).message
		).to.match(/id "X" is not valid/);
	});

	it('refuses one file listed twice', async () => {
		const file = write('twice.js', VALID);
		expect((await rejection([file, file])).message).to.match(/listed twice/);
	});
});

describe('host extensions: a daemon serving one', function () {
	this.timeout(90_000);
	let root: string;
	let daemon: Daemon;
	let port: number;
	let log: IDemoLog;

	before(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ext-'));
		log = newLog();
		({ daemon, port } = await boot(path.join(root, 'main'), {
			extensions: [demoExtension(log)]
		}));
		await daemon.node.extensionHost?.started;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('reports the extension on GET /extensions, to a readonly key too', async () => {
		const reply = await send(port, 'GET', '/extensions', {
			token: READONLY_KEY
		});
		expect(reply.status).to.equal(200);
		const result = reply.json.result as {
			api: string;
			extensions: IExtensionInfo[];
		};
		expect(result.api).to.equal(EXTENSION_API);
		expect(result.extensions).to.have.length(1);
		expect(result.extensions[0]).to.include({
			id: 'demo',
			version: '1.2.3',
			state: 'ready',
			generation: 1
		});
		expect(result.extensions[0].status).to.deep.equal({ generation: 1 });
		expect(log.started).to.equal(1);
	});

	it('serves a route under /x/<id>, with the wallet, the query and the envelope', async () => {
		const reply = await send(port, 'GET', '/x/demo/status?q=hello', {
			token: ADMIN_TOKEN
		});
		expect(reply.status).to.equal(200);
		expect(reply.json).to.deep.equal({
			ok: true,
			result: {
				generation: 1,
				network: 'regtest',
				hasWallet: true,
				asked: 'hello'
			}
		});
		// The versioned prefix reaches it as it reaches the daemon's own.
		const versioned = await send(port, 'GET', '/v1/x/demo/status', {
			token: ADMIN_TOKEN
		});
		expect(versioned.status).to.equal(200);
		const echoed = await send(port, 'POST', '/x/demo/echo', {
			token: ADMIN_TOKEN,
			body: { a: [1, 2], b: 'c' }
		});
		expect(echoed.json).to.deep.equal({
			ok: true,
			result: { a: [1, 2], b: 'c' }
		});
	});

	it('answers null for a handler that returns nothing', async () => {
		const reply = await send(port, 'DELETE', '/x/demo/store?key=none', {
			token: ADMIN_TOKEN
		});
		expect(reply.status).to.equal(200);
		expect(reply.json).to.deep.equal({ ok: true, result: null });
	});

	it('requires a credential, and holds each route to the scopes it declared', async () => {
		const anonymous = await send(port, 'GET', '/x/demo/status');
		expect(anonymous.status).to.equal(401);
		// Declared readonly: the readonly key may, the invoice key may not.
		expect(
			(await send(port, 'GET', '/x/demo/status', { token: READONLY_KEY }))
				.status
		).to.equal(200);
		const invoice = await send(port, 'GET', '/x/demo/status', {
			token: INVOICE_KEY
		});
		expect(invoice.status).to.equal(403);
		expect(invoice.json.error?.message).to.match(/accepted: readonly, admin/);
		// No scopes declared: admin only.
		const readonly = await send(port, 'POST', '/x/demo/echo', {
			token: READONLY_KEY,
			body: {}
		});
		expect(readonly.status).to.equal(403);
		expect(readonly.json.error?.code).to.equal('FORBIDDEN');
		expect(readonly.json.error?.message).to.match(/accepted: admin\)/);
	});

	it('answers 404 for a path the extension did not declare', async () => {
		for (const [method, route] of [
			['GET', '/x/demo/nothing'],
			['GET', '/x/demo/echo'],
			['GET', '/x/other/status'],
			['GET', '/x/demo']
		]) {
			const reply = await send(port, method, route, { token: ADMIN_TOKEN });
			expect(reply.status, `${method} ${route}`).to.equal(404);
			expect(reply.json.error?.code).to.equal('NOT_FOUND');
		}
		// And admin only, like any route in no table.
		const readonly = await send(port, 'GET', '/x/demo/nothing', {
			token: READONLY_KEY
		});
		expect(readonly.status).to.equal(403);
	});

	it('answers an ExtensionError with its status, EXTENSION_ERROR and its own code', async () => {
		const reply = await send(port, 'POST', '/x/demo/refuse', {
			token: ADMIN_TOKEN,
			body: {}
		});
		expect(reply.status).to.equal(409);
		expect(reply.json).to.deep.equal({
			ok: false,
			error: {
				code: 'EXTENSION_ERROR',
				message: 'Not enough of it',
				extension: {
					id: 'demo',
					code: 'NOT_ENOUGH',
					details: { needed: '12', held: '5' }
				}
			}
		});
	});

	it('answers any other throw as a scrubbed 500', async () => {
		const reply = await send(port, 'POST', '/x/demo/fault', {
			token: ADMIN_TOKEN,
			body: {}
		});
		expect(reply.status).to.equal(500);
		expect(reply.json.error?.code).to.equal('INTERNAL_ERROR');
		expect(JSON.stringify(reply.json)).not.to.include('secret detail');
	});

	it('runs a keyed request once, hands the key to the handler, and refuses a key elsewhere', async () => {
		const headers = { 'X-Idempotency-Key': 'spend-1' };
		const before = log.runs.length;
		const first = await send(port, 'POST', '/x/demo/spend', {
			token: ADMIN_TOKEN,
			body: { amount: '5' },
			headers
		});
		const second = await send(port, 'POST', '/x/demo/spend', {
			token: ADMIN_TOKEN,
			body: { amount: '5' },
			headers
		});
		expect(first.status).to.equal(200);
		expect(second.json).to.deep.equal(first.json);
		expect(log.runs.length).to.equal(before + 1);
		expect(log.runs[before].idempotencyKey).to.equal('spend-1');
		// The same key with another body is a conflict.
		const conflict = await send(port, 'POST', '/x/demo/spend', {
			token: ADMIN_TOKEN,
			body: { amount: '6' },
			headers
		});
		expect(conflict.status).to.equal(409);
		expect(conflict.json.error?.code).to.equal('IDEMPOTENCY_CONFLICT');
		// Without a key the handler sees none.
		await send(port, 'POST', '/x/demo/spend', {
			token: ADMIN_TOKEN,
			body: {}
		});
		expect(log.runs[log.runs.length - 1].idempotencyKey).to.equal(undefined);
		// A route that did not declare it refuses the header and runs nothing.
		const refused = await send(port, 'POST', '/x/demo/echo', {
			token: ADMIN_TOKEN,
			body: {},
			headers
		});
		expect(refused.status).to.equal(400);
		expect(refused.json.error?.message).to.match(
			/does not honour X-Idempotency-Key/
		);
	});

	it('applies the body limit each route asked for', async () => {
		const blob = 'x'.repeat(1_500_000);
		const large = await send(port, 'POST', '/x/demo/large', {
			token: ADMIN_TOKEN,
			body: { blob }
		});
		expect(large.status).to.equal(200);
		expect(large.json.result).to.deep.equal({ bytes: 1_500_000 });
		const refused = await send(port, 'POST', '/x/demo/echo', {
			token: ADMIN_TOKEN,
			body: { blob }
		});
		expect(refused.status).to.equal(413);
		expect(refused.json.error?.code).to.equal('BODY_TOO_LARGE');
		const past = await send(port, 'POST', '/x/demo/large', {
			token: ADMIN_TOKEN,
			body: { blob: 'x'.repeat(2_200_000) }
		});
		expect(past.status).to.equal(413);
	});

	it('writes rows under x/<id>/ in the node database', async () => {
		const reply = await send(port, 'POST', '/x/demo/store', {
			token: ADMIN_TOKEN,
			body: { key: 'asset/1', value: 'held' }
		});
		expect(reply.json.result).to.deep.equal({ stored: 'held' });
		expect(daemon.node.getStorage().loadMetadata('x/demo/asset/1')).to.equal(
			'held'
		);
	});

	it('relays a declared event on GET /events as <id>:<name>', async () => {
		const stream = await openEvents(port, READONLY_KEY);
		try {
			await send(port, 'POST', '/x/demo/emit', {
				token: ADMIN_TOKEN,
				body: { event: 'tick', n: 4 }
			});
			await send(port, 'POST', '/x/demo/emit', {
				token: ADMIN_TOKEN,
				body: { event: 'undeclared', n: 5 }
			});
			for (let i = 0; i < 50 && !stream.frames.join('').includes('tick'); i++) {
				await sleep(20);
			}
			const text = stream.frames.join('');
			expect(text).to.include('event: demo:tick\ndata: {"n":4}\n\n');
			expect(text).not.to.include('undeclared');
		} finally {
			stream.close();
		}
	});

	it('lists the routes in the OpenAPI document it serves', async () => {
		const reply = await send(port, 'GET', '/openapi.json');
		const spec = reply.json as unknown as {
			paths: Record<string, Record<string, Record<string, unknown>>>;
		};
		expect(spec.paths['/x/demo/spend'].post.summary).to.equal('Count a run');
		expect(spec.paths['/x/demo/spend'].post['x-extension']).to.deep.equal({
			id: 'demo',
			version: '1.2.3'
		});
		expect(spec.paths['/extensions'].get).to.be.an('object');
	});

	it('attaches again after an in-process rebuild, on the rows it left', async () => {
		// The steps of a capsule resume (BeignetNode's Tier 2 install), minus
		// the file swap: tear the node down, open the database, build again.
		const internals = daemon.node as unknown as {
			_bootOpts: unknown;
			_resuming: boolean;
			teardownNodeForRestart: () => void;
			openSqliteStorage: (opts: unknown) => void;
			prepareRecovery: (opts: unknown) => Promise<void>;
			buildNode: (opts: unknown) => Promise<void>;
		};
		const first = log.contexts[log.contexts.length - 1];
		internals._resuming = true;
		internals.teardownNodeForRestart();
		expect(() => first.storage.set('late', 'write')).to.throw(
			'The database connection is not open'
		);
		const held = await send(port, 'GET', '/x/demo/status', {
			token: ADMIN_TOKEN
		});
		expect(held.status).to.equal(503);
		expect(held.json.error?.code).to.equal('NODE_RESTORE_PENDING');

		internals.openSqliteStorage(internals._bootOpts);
		await internals.prepareRecovery(internals._bootOpts);
		await internals.buildNode(internals._bootOpts);
		internals._resuming = false;
		await daemon.node.extensionHost?.started;

		expect(log.stops).to.deep.equal(['rebuild']);
		const reply = await send(port, 'GET', '/x/demo/status', {
			token: ADMIN_TOKEN
		});
		expect(reply.status).to.equal(200);
		expect((reply.json.result as { generation: number }).generation).to.equal(
			2
		);
		const second = log.contexts[log.contexts.length - 1];
		expect(second).not.to.equal(first);
		expect(second.storage.get('asset/1')).to.equal('held');
		expect(second.storage.get('late')).to.equal(null);
		const listed = await send(port, 'GET', '/extensions', {
			token: ADMIN_TOKEN
		});
		expect(
			(listed.json.result as { extensions: IExtensionInfo[] }).extensions[0]
		).to.include({ state: 'ready', generation: 2 });
	});
});

describe('host extensions: a daemon and an extension that breaks', function () {
	this.timeout(90_000);
	let root: string;

	before(() => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ext-broken-'));
	});

	after(() => {
		fs.rmSync(root, { recursive: true, force: true });
	});

	it('boots, serves the wallet and reports the failure', async () => {
		const broken = minimal({
			id: 'broken',
			routes: [{ method: 'GET', path: '/status', summary: 's' }],
			attach: () => {
				throw new Error('cannot read my rows');
			}
		});
		const log = newLog();
		const { daemon, port } = await boot(path.join(root, 'broken'), {
			extensions: [broken, demoExtension(log)]
		});
		try {
			const health = await send(port, 'GET', '/health');
			expect(health.status).to.equal(200);
			const balance = await send(port, 'GET', '/balance', {
				token: ADMIN_TOKEN
			});
			expect(balance.status).to.equal(200);
			const listed = await send(port, 'GET', '/extensions', {
				token: ADMIN_TOKEN
			});
			const [first, second] = (
				listed.json.result as { extensions: IExtensionInfo[] }
			).extensions;
			expect(first).to.include({
				id: 'broken',
				state: 'failed',
				error: 'attach: cannot read my rows'
			});
			expect(second.id).to.equal('demo');
			expect(['attached', 'ready']).to.include(second.state);
			const route = await send(port, 'GET', '/x/broken/status', {
				token: ADMIN_TOKEN
			});
			expect(route.status).to.equal(503);
			expect(route.json.error?.code).to.equal('EXTENSION_UNAVAILABLE');
			expect(
				(await send(port, 'GET', '/x/demo/status', { token: ADMIN_TOKEN }))
					.status
			).to.equal(200);
		} finally {
			await daemon.stop();
		}
		// The working extension was stopped with the storage still open.
		expect(log.stops).to.deep.equal(['shutdown']);
		expect(log.wroteInStop).to.equal(true);
	});

	it('refuses to start on a description it cannot serve, with nothing left held', async () => {
		const dataDir = path.join(root, 'refused');
		const attempts: Array<[IBeignetExtension[], RegExp]> = [
			[[minimal({ id: 'Bad' })], /id "Bad" is not valid/],
			[[minimal(), minimal()], /listed twice/],
			[
				[minimal({ id: 'channel' })],
				/id "channel" is the prefix of the node's own events/
			]
		];
		for (const [extensions, message] of attempts) {
			let caught: unknown;
			try {
				const started = await boot(dataDir, { extensions });
				await started.daemon.stop();
			} catch (err) {
				caught = err;
			}
			expect(caught).to.be.instanceOf(BeignetError);
			expect((caught as BeignetError).code).to.equal('INVALID_PARAMS');
			expect((caught as BeignetError).message).to.match(message);
		}
		// The instance lock was never taken, so the same directory starts.
		const { daemon, port } = await boot(dataDir);
		try {
			const listed = await send(port, 'GET', '/extensions', {
				token: ADMIN_TOKEN
			});
			expect(listed.json.result).to.deep.equal({
				api: EXTENSION_API,
				extensions: []
			});
			const none = await send(port, 'GET', '/x/demo/status', {
				token: ADMIN_TOKEN
			});
			expect(none.status).to.equal(404);
		} finally {
			await daemon.stop();
		}
	});
});
