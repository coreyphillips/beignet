/**
 * Issue #1603: eight channel methods decoded the caller's channel id with
 * Buffer.from(id, 'hex'), which stops at the first non-hex pair. A typo, a
 * short id or a trailing character decoded to some other byte string, so a
 * lookup could answer about another channel and a policy or fee update could
 * land on one, all with a 200. Each now refuses anything but 64 hex characters
 * as INVALID_PARAMS, the way the close and splice paths already did (#463,
 * #469).
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	IStartedDaemon,
	startDaemon,
	statusForErrorCode
} from '../../src/cli/daemon';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const CHANNEL_ID = 'cd'.repeat(32);

/** Each decodes, unchecked, to a buffer that is not the id the caller meant. */
const MALFORMED_IDS: Array<[string, string]> = [
	['non-hex', 'zz'],
	['62 characters', 'cd'.repeat(31)],
	['a trailing character', CHANNEL_ID + 'e'],
	['a typo in the last pair', 'cd'.repeat(31) + 'cz']
];

const ENGINE_METHODS = [
	'rebroadcastClose',
	'getChannel',
	'getChannelHealth',
	'getChannelManager',
	'updateChannelFee',
	'setChannelPolicy',
	'getChannelPolicy',
	'waitForChannelReady',
	'listChannels',
	'rebalanceChannel'
];

/** A BeignetNode whose engine fails the test if the id guard is skipped. */
function guardedNode(): BeignetNode {
	const engine: Record<string, unknown> = {};
	for (const name of ENGINE_METHODS) {
		engine[name] = (): never =>
			expect.fail(`${name}: the id guard was skipped`);
	}
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: engine,
		networkName: 'regtest'
	}) as unknown as BeignetNode;
}

const METHODS: Array<[string, (bn: BeignetNode, id: string) => unknown]> = [
	['rebroadcastClose', (bn, id): unknown => bn.rebroadcastClose(id)],
	['getChannel', (bn, id): unknown => bn.getChannel(id)],
	['getChannelHealth', (bn, id): unknown => bn.getChannelHealth(id)],
	['getChannelDiagnostics', (bn, id): unknown => bn.getChannelDiagnostics(id)],
	['updateChannelFee', (bn, id): unknown => bn.updateChannelFee(id, 253)],
	[
		'updateChannelPolicy',
		(bn, id): unknown => bn.updateChannelPolicy(id, { feeBaseMsat: 1 })
	],
	['getChannelPolicy', (bn, id): unknown => bn.getChannelPolicy(id)],
	['waitForChannelReady', (bn, id): unknown => bn.waitForChannelReady(id, 10)],
	// Issue #1653: these checked inline with their own wording.
	['fforEpoch', (bn, id): unknown => bn.fforEpoch(id)],
	['forceCloseChannel', (bn, id): unknown => bn.forceCloseChannel(id)],
	[
		'rebalanceChannel (from)',
		(bn, id): unknown => bn.rebalanceChannel(id, CHANNEL_ID, 1000, 10)
	],
	[
		'rebalanceChannel (to)',
		(bn, id): unknown => bn.rebalanceChannel(CHANNEL_ID, id, 1000, 10)
	]
];

describe('Issue #1603: channel methods refuse a malformed channel id', () => {
	for (const [method, call] of METHODS) {
		for (const [label, id] of MALFORMED_IDS) {
			it(`${method} refuses ${label}`, async () => {
				try {
					await call(guardedNode(), id);
				} catch (err: unknown) {
					expect(err).to.be.instanceOf(BeignetError);
					const code = (err as BeignetError).code;
					expect(code).to.equal(BeignetErrorCode.INVALID_PARAMS);
					expect(statusForErrorCode(code)).to.equal(400);
					expect((err as Error).message).to.match(
						/^\w+ must be a 64-character hex channel id$/
					);
					return;
				}
				expect.fail(`${method}: expected a refusal`);
			});
		}
	}

	it('passes a well-formed id through as its 32 bytes, any case', () => {
		const seen: Buffer[] = [];
		const bn = Object.assign(Object.create(BeignetNode.prototype), {
			node: {
				getChannel: (id: Buffer): null => {
					seen.push(id);
					return null;
				}
			}
		}) as unknown as BeignetNode;
		expect(bn.getChannel(CHANNEL_ID)).to.equal(null);
		expect(bn.getChannel(CHANNEL_ID.toUpperCase())).to.equal(null);
		expect(seen.map((id) => id.toString('hex'))).to.deep.equal([
			CHANNEL_ID,
			CHANNEL_ID
		]);
	});

	it("keeps updateChannelPolicy's 'all' sentinel", () => {
		let target: unknown;
		const bn = Object.assign(Object.create(BeignetNode.prototype), {
			node: {
				listChannels: (): unknown[] => [],
				setChannelPolicy: (id: unknown): void => {
					target = id;
				}
			}
		}) as unknown as BeignetNode;
		expect(bn.updateChannelPolicy('all', { feeBaseMsat: 1 })).to.deep.equal({
			updated: 0,
			policies: []
		});
		expect(target).to.equal('all');
	});
});

/**
 * Every `Buffer.from(` in the source whose first argument names a channel id,
 * as `line: argument`. requireChannelIdHex decodes its parameter `value`, so
 * the helper itself never matches. A short channel id is a different thing.
 */
function rawChannelIdDecodes(source: string): string[] {
	const hits: string[] = [];
	const decode = /Buffer\.from\(\s*((?:[\w$]+[!?]?\.)*([\w$]+))(?![\w$.([])/g;
	for (const m of source.matchAll(decode)) {
		if (!/channelid/i.test(m[2]) || /^shortchannelid/i.test(m[2])) continue;
		const line = source.slice(0, m.index).split('\n').length;
		hits.push(`${line}: ${m[1]}`);
	}
	return hits;
}

describe('Issue #1653: beignet-node.ts decodes channel ids only through requireChannelIdHex', () => {
	it('has no raw Buffer.from of a channel id', () => {
		const source = fs.readFileSync(
			path.join(__dirname, '../../src/cli/beignet-node.ts'),
			'utf8'
		);
		expect(rawChannelIdDecodes(source)).to.deep.equal([]);
	});

	it('catches an inline decode reintroduced', () => {
		const planted = [
			"const a = Buffer.from(channelId, 'hex');",
			'const b = Buffer.from(',
			'\tbody.toChannelId,',
			"\t'hex'",
			');',
			"const c = Buffer.from(params?.channelIdHex as string, 'hex');",
			"const d = Buffer.from(h.shortChannelId, 'hex');",
			"const e = Buffer.from(value, 'hex');"
		].join('\n');
		expect(rawChannelIdDecodes(planted)).to.deep.equal([
			'1: channelId',
			'2: body.toChannelId',
			'6: params?.channelIdHex'
		]);
	});
});

function request(
	port: number,
	method: 'GET' | 'POST',
	route: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body === undefined ? '' : JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: route,
				method,
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
		req.end(payload);
	});
}

describe('Issue #1603: channel routes answer a malformed id with 400', function () {
	this.timeout(30_000);

	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-channel-id-'));
	let daemon: IStartedDaemon;
	let port: number;

	before(async () => {
		// Offline (unreachable Electrum): every case is refused before anything
		// needs a chain source.
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic: MNEMONIC,
			daemonPort: 0,
			dataDir: dir
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	/** Each route, and for a POST the rest of a body it would otherwise accept. */
	const ROUTES: Array<[string, Record<string, unknown>?]> = [
		['POST /channel/rebroadcast-close', {}],
		['GET /channel'],
		['GET /channel/health'],
		['GET /channel/diagnostics'],
		['POST /channel/update-fee', { feeratePerKw: 253 }],
		['POST /channel/update-commitment-feerate', { feeratePerKw: 253 }],
		['POST /channel/update-policy', { feeBaseMsat: 1 }],
		['GET /channel/policy'],
		['POST /channel/wait-ready', { timeoutMs: 10 }]
	];

	for (const [route, rest] of ROUTES) {
		it(`${route} refuses every malformed id as INVALID_PARAMS`, async () => {
			const routePath = route.split(' ')[1];
			for (const [label, id] of MALFORMED_IDS) {
				const res =
					rest === undefined
						? await request(
								port,
								'GET',
								`${routePath}?channelId=${encodeURIComponent(id)}`
						  )
						: await request(port, 'POST', routePath, {
								channelId: id,
								...rest
						  });
				expect(res.status, label).to.equal(400);
				expect(res.body.ok, label).to.equal(false);
				expect((res.body.error as { code: string }).code, label).to.equal(
					'INVALID_PARAMS'
				);
			}
		});
	}

	it('still answers a well-formed unknown id as not found', async () => {
		const res = await request(
			port,
			'GET',
			`/channel/health?channelId=${CHANNEL_ID}`
		);
		expect(res.status).to.equal(404);
	});
});
