/**
 * FFOR daemon surface (issue #729): the routes exist and answer empty on a
 * node with no epoch, the witness and issuer roles switch on from options
 * (and the issuer refuses to start without the witness), the receiver
 * routes validate their parameters, and every route is in the OpenAPI
 * spec (the umbrel manager probes it).
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import { resolveConfig } from '../../src/cli/config';

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

function tmpDir(tag: string): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), `beignet-ffor-${tag}-`));
}

function portOf(daemon: IStartedDaemon): number {
	return (daemon.server.address() as AddressInfo).port;
}

function request(
	port: number,
	method: string,
	urlPath: string,
	body?: unknown
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {};
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
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

describe('FFOR surface: configuration (issue #729)', () => {
	it('parses the BEIGNET_FFOR_* switches exactly, with their limits', () => {
		const saved = { ...process.env };
		try {
			process.env.BEIGNET_FFOR_SETTLE = 'true';
			process.env.BEIGNET_FFOR_MAX_BUDGET_MSAT = '5000000000';
			process.env.BEIGNET_FFOR_MAX_EPOCH_BLOCKS = '2016';
			process.env.BEIGNET_FFOR_FEE_BASE_MSAT = '1000';
			process.env.BEIGNET_FFOR_FEE_PPM = '5000';
			process.env.BEIGNET_FFOR_WITNESS = 'true';
			process.env.BEIGNET_FFOR_WITNESS_MAX_MAILBOXES = '8';
			process.env.BEIGNET_FFOR_ISSUER = 'true';
			const cfg = resolveConfig({}) as Record<string, unknown>;
			expect(cfg.fforSettle).to.deep.equal({
				enabled: true,
				maxBudgetMsat: '5000000000',
				maxEpochBlocks: 2016,
				feeBaseMsat: 1000,
				feePpm: 5000
			});
			expect(cfg.fforWitness).to.deep.equal({
				enabled: true,
				maxMailboxes: 8,
				maxBytes: undefined
			});
			expect(cfg.fforIssuer).to.equal(true);
			// A typo is not an opt-in.
			process.env.BEIGNET_FFOR_SETTLE = 'yes';
			process.env.BEIGNET_FFOR_WITNESS = 'on';
			process.env.BEIGNET_FFOR_ISSUER = '1';
			const off = resolveConfig({}) as Record<string, unknown>;
			expect(off.fforSettle).to.equal(undefined);
			expect(off.fforWitness).to.equal(undefined);
			expect(off.fforIssuer).to.equal(undefined);
		} finally {
			process.env = saved;
		}
	});

	it('refuses the issuer without the witness it is co-hosted with', async function () {
		this.timeout(30_000);
		const dir = tmpDir('issuer');
		let error: unknown = null;
		try {
			const daemon = await startDaemon({
				...OFFLINE,
				dataDir: dir,
				fforIssuer: true
			});
			await daemon.stop();
		} catch (e) {
			error = e;
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
		expect(error).to.be.instanceOf(BeignetError);
		expect((error as BeignetError).message).to.match(/needs fforWitness/);
	});
});

describe('FFOR surface: routes on a node with no epoch (issue #729)', () => {
	let daemon: IStartedDaemon;
	let dir: string;

	before(async function () {
		this.timeout(30_000);
		dir = tmpDir('routes');
		daemon = await startDaemon({
			...OFFLINE,
			dataDir: dir,
			fforWitness: { enabled: true, maxMailboxes: 4 },
			fforIssuer: true
		});
	});

	after(async function () {
		this.timeout(30_000);
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('lists no epochs and no settlements', async () => {
		for (const route of ['/ffor/epochs', '/ffor/settlements']) {
			const res = await request(portOf(daemon), 'GET', route);
			expect(res.status, route).to.equal(200);
			expect(res.body.result, route).to.deep.equal([]);
		}
	});

	it('reports the witness and issuer roles it runs', async () => {
		const witness = await request(
			portOf(daemon),
			'GET',
			'/ffor/witness/status'
		);
		expect(witness.body.result).to.deep.equal({ enabled: true, mailboxes: [] });
		const issuer = await request(portOf(daemon), 'GET', '/ffor/issuer/status');
		expect(issuer.body.result).to.deep.equal({ enabled: true, manifests: [] });
	});

	it('validates the receiver routes before touching any channel', async () => {
		const port = portOf(daemon);
		const epoch = await request(port, 'GET', '/ffor/epoch');
		expect(epoch.status).to.equal(400);
		const unknown = await request(
			port,
			'GET',
			'/ffor/epoch?channelId=' + 'ab'.repeat(32)
		);
		expect(unknown.status).to.equal(404);
		const start = await request(port, 'POST', '/ffor/epoch/start', {
			channelId: 'zz',
			voucherAmountsMsat: ['1000']
		});
		expect(start.status).to.equal(400);
		expect((start.body.error as { message: string }).message).to.match(
			/channelId/
		);
		const invoice = await request(port, 'POST', '/ffor/invoice', {
			channelId: 'ab'.repeat(32),
			k: 1
		});
		expect(invoice.status).to.equal(404);
		const preimage = await request(port, 'POST', '/ffor/preimage', {
			channelId: 'ab'.repeat(32),
			preimage: 'nope'
		});
		expect(preimage.status).to.equal(404);
		const offer = await request(port, 'POST', '/ffor/issuer/offer', {
			issuerNodeId: 'not-a-key',
			description: 'x'
		});
		expect(offer.status).to.equal(400);
		const enforce = await request(port, 'POST', '/ffor/enforce', {});
		expect(enforce.status).to.equal(400);
	});

	it('creates a path-terminal issuer offer for a stock payer', async () => {
		const issuer = daemon.node.getNode().getNodeId();
		const res = await request(portOf(daemon), 'POST', '/ffor/issuer/offer', {
			issuerNodeId: issuer,
			description: 'ffor slots',
			amountMsat: '1000000',
			quantityMax: 3
		});
		expect(res.status).to.equal(200);
		const result = res.body.result as { offerId: string; encoded: string };
		expect(result.offerId).to.match(/^[0-9a-f]{64}$/);
		expect(result.encoded).to.match(/^lno1/);
	});

	it('is in the OpenAPI spec the umbrel manager probes', async () => {
		const res = await request(portOf(daemon), 'GET', '/openapi.json');
		expect(res.status).to.equal(200);
		const paths = Object.keys(
			(res.body as { paths: Record<string, unknown> }).paths
		);
		for (const route of [
			'/ffor/epochs',
			'/ffor/epoch/start',
			'/ffor/invoice',
			'/ffor/recover',
			'/ffor/enforce',
			'/ffor/witness/status',
			'/ffor/issuer/status'
		]) {
			expect(paths, route).to.include(route);
		}
	});
});
