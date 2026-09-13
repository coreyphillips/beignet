/**
 * minFinalCltvExpiry on POST /invoice/create-hold (issue #744).
 *
 * A hold invoice is usually the Lightning leg of a swap, and the swap is only
 * atomic while that leg outlives the on-chain one. Left on the node default,
 * an on-chain refund that times out later than the incoming HTLC lets the
 * payer reclaim its sats over Lightning and still claim the contract, so the
 * delta has to reach the route, not just the library.
 *
 * Everything here runs against a daemon over HTTP because the field was
 * already accepted by the library node and dropped by the handler: the check
 * that matters is the bolt11 the route hands back.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import { getOpenApiSpec } from '../../src/cli/openapi';
import { decode } from '../../src/lightning/invoice/decode';

const PAYMENT_HASH = 'ab'.repeat(32);

describe('POST /invoice/create-hold final CLTV', function () {
	this.timeout(30_000);
	let dataDir: string;
	let daemon: Awaited<ReturnType<typeof startDaemon>>;
	let port: number;

	const createHold = (
		body: Record<string, unknown>
	): Promise<{ status: number; json: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const req = http.request(
				{
					host: '127.0.0.1',
					port,
					path: '/invoice/create-hold',
					method: 'POST',
					headers: { 'content-type': 'application/json' }
				},
				(res) => {
					let raw = '';
					res.on('data', (c) => (raw += c));
					res.on('end', () =>
						resolve({
							status: res.statusCode ?? 0,
							json: JSON.parse(raw) as Record<string, unknown>
						})
					);
				}
			);
			req.on('error', reject);
			req.end(JSON.stringify(body));
		});

	const bolt11Of = async (body: Record<string, unknown>): Promise<string> => {
		const { status, json } = await createHold(body);
		expect(status, JSON.stringify(json)).to.equal(200);
		return (json.result as { bolt11: string }).bolt11;
	};

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-744-'));
		daemon = await startDaemon({
			// Nothing here needs a chain, and a refused loopback connect returns
			// instantly where a real host would be dialled over the internet.
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
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

	it('puts the requested delta in the invoice c tag', async () => {
		const bolt11 = await bolt11Of({
			paymentHash: PAYMENT_HASH,
			amountSats: 1_000,
			description: 'swap leg',
			minFinalCltvExpiry: 200
		});
		expect(decode(bolt11).minFinalCltvExpiry).to.equal(200);
		expect(decode(bolt11).paymentHash.toString('hex')).to.equal(PAYMENT_HASH);
	});

	it('leaves the node default when the field is absent', async () => {
		const bolt11 = await bolt11Of({
			paymentHash: 'cd'.repeat(32),
			amountSats: 1_000
		});
		expect(decode(bolt11).minFinalCltvExpiry).to.equal(40);
	});

	// The same bounds POST /invoice/create applies: the value goes straight
	// into the c tag, and an absurd one is a valid invoice nobody will pay.
	it('refuses a delta no sender would ever pay', async () => {
		for (const value of [0, -1, 2017, 1.5]) {
			const { status, json } = await createHold({
				paymentHash: 'ef'.repeat(32),
				amountSats: 1_000,
				minFinalCltvExpiry: value
			});
			expect(status, String(value)).to.equal(400);
			expect((json.error as { code: string }).code).to.equal('INVALID_PARAMS');
			expect((json.error as { message: string }).message).to.match(
				/minFinalCltvExpiry must be an integer between 1 and 2016/
			);
		}
	});

	// Issue #770: the delta was advertised and never enforced, and the listing
	// dropped the realised expiry, so a provider could verify neither.
	it('lists the enforced delta and the realised expiry on GET /invoices/held', async () => {
		const hash = '12'.repeat(32);
		await bolt11Of({
			paymentHash: hash,
			amountSats: 1_000,
			description: 'swap leg',
			minFinalCltvExpiry: 200
		});
		const rows = await new Promise<Array<Record<string, unknown>>>(
			(resolve, reject) => {
				http
					.get({ host: '127.0.0.1', port, path: '/invoices/held' }, (res) => {
						let raw = '';
						res.on('data', (c) => (raw += c));
						res.on('end', () =>
							resolve(
								(JSON.parse(raw) as { result: Array<Record<string, unknown>> })
									.result
							)
						);
					})
					.on('error', reject);
			}
		);
		const row = rows.find((r) => r.paymentHash === hash);
		expect(row, 'the hold invoice is listed').to.not.equal(undefined);
		expect(row!.state).to.equal('OPEN');
		expect(row!.minFinalCltvExpiry).to.equal(200);
		// Nothing parked yet: the realised expiry is null, not absent.
		expect(row!.earliestExpiry).to.equal(null);
		expect(row!.cancelHeight).to.equal(null);
		expect(row!.cancelMarginBlocks).to.equal(18);
		for (const key of [
			'minFinalCltvExpiry',
			'earliestExpiry',
			'cancelMarginBlocks',
			'cancelHeight'
		]) {
			expect(Object.keys(row!), key).to.include(key);
		}
		const defaulted = rows.find((r) => r.paymentHash === 'cd'.repeat(32));
		expect(defaulted!.minFinalCltvExpiry, 'the node default').to.equal(40);

		const spec = getOpenApiSpec() as unknown as {
			components: {
				schemas: Record<string, { properties?: Record<string, unknown> }>;
			};
		};
		expect(
			Object.keys(spec.components.schemas.HoldInvoiceInfo.properties ?? {})
		).to.include.members([
			'minFinalCltvExpiry',
			'earliestExpiry',
			'cancelMarginBlocks',
			'cancelHeight'
		]);
	});

	it('documents the field so a caller can probe for it', () => {
		// pubky-swap reads GET /openapi.json at startup and stops advertising
		// reverse swaps when the field is missing, so an undocumented but
		// working parameter is still a provider that will not serve.
		const spec = getOpenApiSpec() as unknown as {
			paths: Record<
				string,
				Record<
					string,
					{
						requestBody?: {
							content?: Record<
								string,
								{ schema?: { properties?: Record<string, unknown> } }
							>;
						};
					}
				>
			>;
		};
		const schema =
			spec.paths['/invoice/create-hold'].post.requestBody?.content?.[
				'application/json'
			].schema;
		expect(Object.keys(schema?.properties ?? {})).to.include(
			'minFinalCltvExpiry'
		);
	});
});
