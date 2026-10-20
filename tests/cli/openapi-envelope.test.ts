/**
 * Issue #1616: the spec described each success payload as the whole HTTP
 * body, while the daemon answers { ok: true, result }. GET /peers documented
 * an array at the root, so a validator built from the spec rejected every
 * real reply. Each 2xx JSON schema now describes the envelope, with the
 * payload under result.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { getOpenApiSpec } from '../../src/cli/openapi';
import { OnchainSweepInfo } from '../../src/cli/onchain-sweep';

type Schema = Record<string, unknown>;
type Operation = {
	requestBody?: { content?: Record<string, { schema?: Schema }> };
	responses?: Record<string, { content?: Record<string, { schema?: Schema }> }>;
};

const spec = getOpenApiSpec() as unknown as {
	paths: Record<string, Record<string, Operation>>;
	components: { schemas: Record<string, Schema> };
};

function successSchema(route: string, method = 'get'): Schema {
	const schema =
		spec.paths[route][method].responses?.['200']?.content?.['application/json']
			?.schema;
	expect(schema, `${method.toUpperCase()} ${route}`).to.exist;
	return schema as Schema;
}

function typeOf(value: unknown): string {
	if (value === null) return 'null';
	if (Array.isArray(value)) return 'array';
	if (typeof value === 'number' && Number.isInteger(value)) return 'integer';
	return typeof value;
}

/** Covers the keywords the checked schemas use; returns each mismatch's path. */
function validate(schema: Schema, value: unknown, at = '$'): string[] {
	if (typeof schema.$ref === 'string') {
		const name = schema.$ref.split('/').pop() as string;
		return validate(spec.components.schemas[name], value, at);
	}
	if (value === null && schema.nullable === true) return [];
	const type = schema.type as string | undefined;
	const actual = typeOf(value);
	if (
		type !== undefined &&
		actual !== type &&
		!(type === 'number' && actual === 'integer')
	) {
		return [`${at}: expected ${type}, got ${actual}`];
	}
	const problems: string[] = [];
	if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
		problems.push(`${at}: ${JSON.stringify(value)} not in enum`);
	}
	if (actual === 'object') {
		const obj = value as Record<string, unknown>;
		for (const key of (schema.required as string[] | undefined) ?? []) {
			if (!(key in obj)) problems.push(`${at}: missing ${key}`);
		}
		const props = (schema.properties ?? {}) as Record<string, Schema>;
		for (const [key, sub] of Object.entries(props)) {
			if (key in obj) problems.push(...validate(sub, obj[key], `${at}.${key}`));
		}
		if (schema.additionalProperties === false) {
			for (const key of Object.keys(obj)) {
				if (!(key in props)) problems.push(`${at}: unexpected ${key}`);
			}
		}
	}
	if (actual === 'array' && schema.items) {
		(value as unknown[]).forEach((item, i) =>
			problems.push(...validate(schema.items as Schema, item, `${at}[${i}]`))
		);
	}
	return problems;
}

describe('Issue #1616: OpenAPI success schemas describe the envelope', () => {
	it('every 2xx JSON response requires ok: true and result', () => {
		const bare: string[] = [];
		for (const [route, ops] of Object.entries(spec.paths)) {
			for (const [method, op] of Object.entries(ops)) {
				for (const [status, response] of Object.entries(op.responses ?? {})) {
					const schema = response.content?.['application/json']?.schema;
					if (!status.startsWith('2') || !schema) continue;
					const props = schema.properties as Record<string, Schema> | undefined;
					const ok =
						schema.type === 'object' &&
						(schema.required as string[] | undefined)?.includes('ok') &&
						(schema.required as string[]).includes('result') &&
						JSON.stringify(props?.ok?.enum) === '[true]' &&
						props?.result !== undefined;
					if (!ok) bare.push(`${method.toUpperCase()} ${route} ${status}`);
				}
			}
		}
		expect(bare).to.deep.equal([]);
	});

	it('puts the payload under result exactly once', () => {
		expect(
			(successSchema('/peers').properties as Record<string, Schema>).result
		).to.deep.equal({
			type: 'array',
			items: { $ref: '#/components/schemas/PeerInfo' }
		});
		expect(
			(successSchema('/info').properties as Record<string, Schema>).result
		).to.deep.equal({ $ref: '#/components/schemas/NodeInfo' });
	});

	// Issue #1624: 55 routes documented a 200 with a description and no
	// content, so a generated client had no type for the reply at all.
	it('every 2xx response documents a body', () => {
		const bodiless: string[] = [];
		for (const [route, ops] of Object.entries(spec.paths)) {
			for (const [method, op] of Object.entries(ops)) {
				for (const [status, response] of Object.entries(op.responses ?? {})) {
					if (status.startsWith('2') && !response.content) {
						bodiless.push(`${method.toUpperCase()} ${route} ${status}`);
					}
				}
			}
		}
		expect(bodiless).to.deep.equal([]);
	});

	it('leaves request bodies unwrapped', () => {
		const body =
			spec.paths['/l402/fetch'].post.requestBody?.content?.['application/json']
				?.schema;
		expect(body?.required).to.deep.equal(['url', 'maxPriceSats']);
	});
});

function request(
	port: number,
	route: string,
	method = 'GET',
	body?: unknown
): Promise<{ status: number; body: unknown }> {
	const payload = body === undefined ? undefined : JSON.stringify(body);
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: route,
				method,
				// Node frames a DELETE body only when the length is given.
				headers: {
					'Content-Type': 'application/json',
					...(payload === undefined
						? {}
						: { 'Content-Length': Buffer.byteLength(payload) })
				}
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () =>
					resolve({
						status: res.statusCode!,
						body: JSON.parse(Buffer.concat(chunks).toString())
					})
				);
			}
		);
		req.on('error', reject);
		req.end(payload);
	});
}

describe('Issue #1616: daemon replies validate against the spec', function () {
	this.timeout(30_000);

	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-openapi-env-'));
	let daemon: IStartedDaemon;
	let port: number;

	before(async () => {
		// Offline (unreachable Electrum): both routes answer from local state.
		daemon = await startDaemon({
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			network: 'regtest',
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			daemonPort: 0,
			dataDir: dir
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('GET /peers: an array reply', async () => {
		const res = await request(port, '/peers');
		expect(res.status).to.equal(200);
		expect(res.body).to.deep.equal({ ok: true, result: [] });
		const schema = successSchema('/peers');
		expect(validate(schema, res.body)).to.deep.equal([]);
		expect(validate(schema, [])).to.deep.equal([
			'$: expected object, got array'
		]);
	});

	it('GET /info: an object reply', async () => {
		const res = await request(port, '/info');
		expect(res.status).to.equal(200);
		const body = res.body as { ok: unknown; result: Record<string, unknown> };
		expect(body.ok).to.equal(true);
		const schema = successSchema('/info');
		expect(validate(schema, body)).to.deep.equal([]);
		// NodeInfo requires nothing, so an envelope read as a NodeInfo would
		// pass too: a bad field under result shows the payload is what is read.
		const bad = { ...body, result: { ...body.result, blockHeight: 'tip' } };
		expect(validate(schema, bad)).to.deep.equal([
			'$.result.blockHeight: expected integer, got string'
		]);
	});

	// Issue #1625: the payload schema was { removed: 'boolean' }, a property
	// name where a keyword belongs, so it constrained nothing.
	it('DELETE /offer: the removal reply', async () => {
		const created = await request(port, '/offer/create', 'POST', {
			description: 'openapi removal'
		});
		expect(created.status).to.equal(200);
		const { offerId } = (created.body as { result: { offerId: string } })
			.result;
		const res = await request(port, `/offer?offerId=${offerId}`, 'DELETE');
		expect(res.status).to.equal(200);
		expect(res.body).to.deep.equal({ ok: true, result: { removed: true } });
		const schema = successSchema('/offer', 'delete');
		expect(validate(schema, res.body)).to.deep.equal([]);
		expect(
			validate(schema, { ok: true, result: { removed: 'yes' } })
		).to.deep.equal(['$.result.removed: expected boolean, got string']);
		expect(validate(schema, { ok: true, result: {} })).to.deep.equal([
			'$.result: missing removed'
		]);
	});

	// Issue #1624: both replies were documented with no body.
	it('GET /can-send: a capability read', async () => {
		const res = await request(port, '/can-send?amountSats=1');
		expect(res.status).to.equal(200);
		expect(res.body).to.deep.equal({
			ok: true,
			result: { canSend: false, availableSats: 0 }
		});
		const schema = successSchema('/can-send');
		expect(validate(schema, res.body)).to.deep.equal([]);
		expect(
			validate(schema, {
				ok: true,
				result: { canSend: 'no', availableSats: 0 }
			})
		).to.deep.equal(['$.result.canSend: expected boolean, got string']);
	});

	it('DELETE /webhooks/unregister: a mutation reply', async () => {
		const registered = await request(port, '/webhooks/register', 'POST', {
			url: 'http://127.0.0.1:9/hook',
			events: ['payment:received'],
			allowPrivateNetwork: true
		});
		expect(registered.status).to.equal(200);
		const { id } = (registered.body as { result: { id: string } }).result;
		const res = await request(port, '/webhooks/unregister', 'DELETE', { id });
		expect(res.status).to.equal(200);
		expect(res.body).to.deep.equal({
			ok: true,
			result: { unregistered: true }
		});
		const schema = successSchema('/webhooks/unregister', 'delete');
		expect(validate(schema, res.body)).to.deep.equal([]);
		expect(validate(schema, { ok: true, result: {} })).to.deep.equal([
			'$.result: missing unregistered'
		]);
	});

	// Issue #1651: OnchainTxInfo omitted source and channelId, so a client
	// generated from it dropped both from close payouts and sweeps.
	it('GET /transactions: close payout and sweep records', async () => {
		const address = bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(
				'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
				'hex'
			),
			network: bitcoin.networks.regtest
		});
		const sweep: OnchainSweepInfo = {
			requestId: 'openapi-sweep-1651',
			address: address.address!,
			status: 'submitted',
			debitSats: 10000,
			amountSats: 9800,
			feeSats: 200,
			satsPerVbyte: 1.4,
			txid: 'cd'.repeat(32),
			createdAt: 1
		};
		type Sweeps = { list: () => OnchainSweepInfo[] };
		const internals = daemon.node as unknown as {
			node: { listExternalClosePayments: () => unknown[] };
			onchainSweeps: () => Sweeps;
		};
		const listCloses = internals.node.listExternalClosePayments;
		const onchainSweeps = internals.onchainSweeps;
		let res: { status: number; body: unknown };
		try {
			internals.node.listExternalClosePayments = (): unknown[] => [
				{
					channelId: 'ef'.repeat(32),
					txid: 'ab'.repeat(32),
					scriptHex: address.output!.toString('hex'),
					amountSats: 99800,
					feeSats: 200,
					networkFeeSats: 200,
					satsPerVbyte: 1.2,
					timestamp: 2,
					confirmationHeight: 100
				}
			];
			internals.onchainSweeps = (): Sweeps => ({
				list: (): OnchainSweepInfo[] => [sweep]
			});
			res = await request(port, '/transactions');
		} finally {
			internals.node.listExternalClosePayments = listCloses;
			internals.onchainSweeps = onchainSweeps;
		}
		expect(res.status).to.equal(200);
		const body = res.body as { result: Array<Record<string, unknown>> };
		expect(body.result.map((tx) => tx.source)).to.deep.equal([
			'cooperative-close',
			'onchain-sweep'
		]);
		expect(validate(successSchema('/transactions'), body)).to.deep.equal([]);
		// The spec leaves objects open, so only a closed copy shows a field
		// the schema does not list.
		const closed = {
			...spec.components.schemas.OnchainTxInfo,
			additionalProperties: false
		};
		const problems = body.result.flatMap((tx, i) =>
			validate(closed, tx, `$.result[${i}]`)
		);
		expect(problems).to.deep.equal([]);
	});

	// Issue #1650: each route wrapped the engine's in-band refusal in
	// success(), so a refusal answered 200 ok:true with ok:false inside.
	describe('Issue #1650: an engine refusal is a failure envelope', () => {
		const channelId = 'ab'.repeat(32);
		const issuerNodeId = '02' + 'cd'.repeat(32);
		type Stubbed = Record<string, (...args: unknown[]) => unknown>;
		const cases: Array<{
			route: string;
			method: 'POST' | 'GET';
			stub: string;
			body?: Record<string, unknown>;
			refused: Record<string, unknown>;
			accepted: Record<string, unknown>;
			code: string;
			status: number;
		}> = [
			{
				route: '/channel/update-commitment-feerate',
				method: 'POST',
				stub: 'updateChannelFee',
				body: { channelId, feeratePerKw: 1000 },
				refused: { ok: false, error: 'Only opener can update fee' },
				accepted: { ok: true },
				code: 'UPDATE_FEE_FAILED',
				status: 409
			},
			{
				route: '/channel/update-fee',
				method: 'POST',
				stub: 'updateChannelFee',
				body: { channelId, feeratePerKw: 1000 },
				refused: { ok: false, error: 'Only opener can update fee' },
				accepted: { ok: true },
				code: 'UPDATE_FEE_FAILED',
				status: 409
			},
			{
				route: '/ffor/enforce',
				method: 'POST',
				stub: 'fforEnforce',
				body: { channelId },
				refused: {
					ok: false,
					error: 'Cannot force close: wrong state',
					preimagesKnown: 1
				},
				accepted: {
					ok: true,
					commitmentTxid: 'ef'.repeat(32),
					preimagesKnown: 1
				},
				// /channel/forceclose's code, which keeps the 500 default (#474).
				code: 'FORCE_CLOSE_FAILED',
				status: 500
			},
			{
				route: `/ffor/issuer/issued?channelId=${channelId}&issuerNodeId=${issuerNodeId}`,
				method: 'GET',
				stub: 'fforIssuedSlots',
				refused: {
					ok: false,
					numSlots: 0,
					issued: '',
					slots: [],
					error: 'unknown mailbox'
				},
				accepted: {
					ok: true,
					numSlots: 3,
					issued: '00',
					slots: [],
					error: null
				},
				code: 'FFOR_REFUSED',
				status: 400
			}
		];

		for (const c of cases) {
			const pathname = c.route.split('?')[0];
			it(`${c.method} ${pathname}`, async () => {
				const node = daemon.node as unknown as Stubbed;
				const original = node[c.stub];
				let answer = c.refused;
				node[c.stub] = (): unknown =>
					c.method === 'GET' ? Promise.resolve(answer) : answer;
				try {
					const refused = await request(port, c.route, c.method, c.body);
					expect(refused.status).to.equal(c.status);
					expect(refused.body).to.deep.equal({
						ok: false,
						error: { code: c.code, message: c.refused.error }
					});

					answer = c.accepted;
					const accepted = await request(port, c.route, c.method, c.body);
					expect(accepted.status).to.equal(200);
					const body = accepted.body as {
						ok: boolean;
						result: Record<string, unknown>;
					};
					expect(body.ok).to.equal(true);
					expect(body.result).to.not.have.any.keys('ok', 'error');
					const schema = successSchema(pathname, c.method.toLowerCase());
					expect(validate(schema, body)).to.deep.equal([]);
				} finally {
					node[c.stub] = original;
				}
			});
		}
	});
});
