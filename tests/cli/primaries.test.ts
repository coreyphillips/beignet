/**
 * Ranked receive primaries on BeignetNode and the daemon (issue #1922,
 * step 1): the routes, their scopes, the INVALID_PARAMS refusals, a restart,
 * and the per-primary balance the read API reports.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import { scopesAllowRoute } from '../../src/cli/auth';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { getOpenApiSpec } from '../../src/cli/openapi';
import type { PrimariesInfo } from '../../src/cli/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	mnemonic: MNEMONIC,
	daemonPort: 0
};

const A = '02' + 'aa'.repeat(32);
const B = '03' + 'bb'.repeat(32);
const C = '02' + 'cc'.repeat(32);

function httpCall(
	port: number,
	method: 'GET' | 'POST',
	route: string,
	body?: unknown
): Promise<{ status: number; json: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				host: '127.0.0.1',
				port,
				path: route,
				method,
				headers: { 'content-type': 'application/json' }
			},
			(res) => {
				let raw = '';
				res.on('data', (c) => (raw += c));
				res.on('end', () =>
					resolve({ status: res.statusCode ?? 0, json: JSON.parse(raw) })
				);
			}
		);
		req.on('error', reject);
		req.end(body === undefined ? undefined : JSON.stringify(body));
	});
}

describe('primaries routes (issue #1922)', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;
	let port: number;

	const call = (
		method: 'GET' | 'POST',
		route: string,
		body?: unknown
	): ReturnType<typeof httpCall> => httpCall(port, method, route, body);

	const resultOf = (json: Record<string, unknown>): PrimariesInfo =>
		json.result as PrimariesInfo;

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-primaries-'));
		daemon = await startDaemon({ ...OFFLINE, dataDir });
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('starts empty', async () => {
		const { status, json } = await call('GET', '/primaries');
		expect(status).to.equal(200);
		expect(resultOf(json)).to.deep.equal({
			fillThresholdSat: null,
			primaries: [],
			receiveTarget: null
		});
	});

	it('adds, ranks, reorders and removes, answering with the whole list', async () => {
		await call('POST', '/primaries/add', {
			pubkey: A,
			host: '10.0.0.1',
			port: 9735
		});
		await call('POST', '/primaries/add', {
			pubkey: C,
			uri: `${C}@ws://lsp.example:9736`
		});
		const added = await call('POST', '/primaries/add', { pubkey: B, rank: 1 });
		expect(added.status).to.equal(200);
		expect(resultOf(added.json).primaries.map((p) => p.pubkey)).to.deep.equal([
			B,
			A,
			C
		]);

		const reordered = await call('POST', '/primaries/reorder', {
			order: [A, C, B]
		});
		expect(resultOf(reordered.json).primaries.map((p) => p.rank)).to.deep.equal(
			[1, 2, 3]
		);
		expect(
			resultOf(reordered.json).primaries.map((p) => p.pubkey)
		).to.deep.equal([A, C, B]);

		const removed = await call('POST', '/primaries/remove', { pubkey: C });
		expect(resultOf(removed.json).primaries.map((p) => p.pubkey)).to.deep.equal(
			[A, B]
		);

		const set = await call('POST', '/primaries/threshold', {
			fillThresholdSat: 1_000_000
		});
		const info = resultOf(set.json);
		expect(info.fillThresholdSat).to.equal(1_000_000);
		// No channels on this node, so A, the first ranked, is below the threshold.
		expect(info.receiveTarget).to.equal(A);
		expect(info.primaries[0]).to.deep.equal({
			pubkey: A,
			rank: 1,
			host: '10.0.0.1',
			port: 9735,
			uri: null,
			thresholdSat: 1_000_000,
			balanceSat: 0,
			channelCount: 0,
			belowThreshold: true,
			isReceiveTarget: true,
			selectionOrder: 1
		});
		expect(info.primaries[1].isReceiveTarget).to.equal(false);
	});

	it('refuses bad input with 400 INVALID_PARAMS and changes nothing', async () => {
		const before = resultOf((await call('GET', '/primaries')).json);
		const cases: Array<[string, unknown]> = [
			['/primaries/add', { pubkey: 'zz' }],
			['/primaries/add', {}],
			['/primaries/add', { pubkey: A }],
			['/primaries/add', { pubkey: C, host: 'h', port: 70000 }],
			['/primaries/add', { pubkey: C, host: 'h', port: 1.5 }],
			['/primaries/add', { pubkey: C, rank: 9 }],
			['/primaries/remove', { pubkey: C }],
			['/primaries/reorder', { order: [A] }],
			['/primaries/reorder', {}],
			['/primaries/threshold', { fillThresholdSat: -1 }],
			['/primaries/threshold', { fillThresholdSat: 1.5 }],
			['/primaries/threshold', { fillThresholdSat: '1000' }],
			['/primaries/threshold', {}]
		];
		for (const [route, body] of cases) {
			const { status, json } = await call('POST', route, body);
			const label = `${route} ${JSON.stringify(body)}`;
			expect(status, label).to.equal(400);
			expect((json.error as { code: string }).code, label).to.equal(
				'INVALID_PARAMS'
			);
		}
		expect(resultOf((await call('GET', '/primaries')).json)).to.deep.equal(
			before
		);
	});

	it('keeps the list and the threshold across a restart', async () => {
		await daemon.stop();
		daemon = await startDaemon({ ...OFFLINE, dataDir });
		port = (daemon.server.address() as AddressInfo).port;
		const info = resultOf((await call('GET', '/primaries')).json);
		expect(info.fillThresholdSat).to.equal(1_000_000);
		expect(info.primaries.map((p) => p.pubkey)).to.deep.equal([A, B]);
		expect(info.primaries[0].host).to.equal('10.0.0.1');
	});

	it('reads with readonly and writes with admin only', () => {
		const readonly = new Set(['readonly' as const]);
		const invoice = new Set(['invoice' as const]);
		expect(scopesAllowRoute(readonly, 'GET /primaries')).to.equal(true);
		for (const route of [
			'POST /primaries/add',
			'POST /primaries/remove',
			'POST /primaries/reorder',
			'POST /primaries/threshold'
		]) {
			expect(scopesAllowRoute(readonly, route), route).to.equal(false);
			expect(scopesAllowRoute(invoice, route), route).to.equal(false);
		}
	});

	it('is in the OpenAPI spec', () => {
		const paths = getOpenApiSpec().paths as Record<string, unknown>;
		for (const p of [
			'/primaries',
			'/primaries/add',
			'/primaries/remove',
			'/primaries/reorder',
			'/primaries/threshold'
		]) {
			expect(paths, p).to.have.property(p);
		}
	});
});

describe('BeignetNode.listPrimaries balances (issue #1922)', () => {
	interface FakeChannel {
		id: string;
		peer: string;
		localSats: number;
		usable: boolean;
	}

	/** A node over a fake channel manager and an in-memory wallet-data store. */
	function nodeWith(channels: FakeChannel[]): BeignetNode {
		const data = new Map<string, string>();
		const node = Object.create(BeignetNode.prototype) as BeignetNode;
		const fields = node as unknown as Record<string, unknown>;
		fields.storage = {
			saveWalletData: (k: string, v: string): void => {
				data.set(k, v);
			},
			loadWalletData: (k: string): string | null => data.get(k) ?? null
		};
		const manager = {
			listChannels: (): unknown[] =>
				channels.map((ch) => ({
					acceptsNewHtlcs: (lookThrough: boolean): boolean =>
						lookThrough && ch.usable,
					getChannelId: (): Buffer => Buffer.from(ch.id, 'hex'),
					getFullState: (): { localBalanceMsat: bigint } => ({
						localBalanceMsat: BigInt(ch.localSats) * 1000n
					})
				})),
			getPeerForChannel: (id: Buffer): string | undefined =>
				channels.find((ch) => ch.id === id.toString('hex'))?.peer
		};
		fields.node = { getChannelManager: (): typeof manager => manager };
		return node;
	}

	it('sums usable channels per primary and levels B and C under a full A', () => {
		const node = nodeWith([
			{ id: '01', peer: A, localSats: 1_500_000, usable: true },
			{ id: '02', peer: A, localSats: 500_000, usable: true },
			{ id: '03', peer: B, localSats: 1_000_000, usable: true },
			{ id: '04', peer: C, localSats: 1_000_000, usable: true },
			// Not usable: closing, held, or unproven. Its balance is not counted.
			{ id: '05', peer: B, localSats: 9_000_000, usable: false }
		]);
		node.addPrimary({ pubkey: A });
		node.addPrimary({ pubkey: B });
		node.addPrimary({ pubkey: C });
		const info = node.setPrimariesFillThreshold(1_000_000);
		expect(
			info.primaries.map((p) => [
				p.balanceSat,
				p.channelCount,
				p.selectionOrder
			])
		).to.deep.equal([
			[2_000_000, 2, 3],
			[1_000_000, 1, 1],
			[1_000_000, 1, 2]
		]);
		expect(info.receiveTarget).to.equal(B);
		expect(info.primaries.filter((p) => p.isReceiveTarget)).to.have.length(1);
	});

	it('targets a primary with no channel once the first is full', () => {
		const node = nodeWith([
			{ id: '01', peer: A, localSats: 1_000_000, usable: true }
		]);
		node.addPrimary({ pubkey: A });
		node.addPrimary({ pubkey: B });
		const info = node.setPrimariesFillThreshold(1_000_000);
		expect(info.receiveTarget).to.equal(B);
		expect(info.primaries[1]).to.include({ balanceSat: 0, channelCount: 0 });
	});

	it('throws INVALID_PARAMS as a BeignetError', () => {
		const node = nodeWith([]);
		for (const fn of [
			(): unknown => node.addPrimary({ pubkey: 'nope' }),
			(): unknown => node.addPrimary({ pubkey: A, host: 'h', port: 0 }),
			(): unknown => node.setPrimariesFillThreshold(-1),
			(): unknown => node.removePrimary(A),
			(): unknown => node.reorderPrimaries([B])
		]) {
			let error: unknown;
			try {
				fn();
			} catch (err) {
				error = err;
			}
			expect(error).to.be.instanceOf(BeignetError);
			expect((error as BeignetError).code).to.equal('INVALID_PARAMS');
		}
		node.addPrimary({ pubkey: A });
		expect(() => node.addPrimary({ pubkey: A })).to.throw(BeignetError);
	});
});
