/**
 * Issue #1616: the spec described each success payload as the whole HTTP
 * body, while the daemon answers { ok: true, result }. GET /peers documented
 * an array at the root, so a validator built from the spec rejected every
 * real reply. Each 2xx JSON schema now describes the envelope, with the
 * payload under result.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { getOpenApiSpec } from '../../src/cli/openapi';

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
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: route,
				method,
				headers: { 'Content-Type': 'application/json' }
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
		req.end(body === undefined ? undefined : JSON.stringify(body));
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
});
