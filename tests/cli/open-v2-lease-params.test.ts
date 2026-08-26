/**
 * POST /channel/open-v2 requestFunds/maxLeaseRates admission (issue #532
 * workstream 1B).
 *
 * The route passes the liquidity-ads buyer params through to
 * BeignetNode.openChannelV2, which owns the JSON-edge shape and range checks
 * (a fractional requestedSats would throw an uncaught RangeError in BigInt,
 * and a bad maxLeaseRates field would only surface inside the lease fee math
 * AFTER open_channel2 went out). The requestFunds-requires-maxLeaseRates
 * pairing stays with the library, whose InvalidRequestError the wrapper maps
 * to INVALID_PARAMS. Offline daemon: requests that pass validation stop at
 * the unconnected peer, a scrubbed 500, which is the proof the params were
 * admitted.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// A well-formed compressed-pubkey string; the open stops at the peer lookup,
// which is a map miss, so the point does not need to be on the curve.
const PEER = '02' + 'ab'.repeat(32);

const RATES = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 10000,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 3
};

function post(
	port: number,
	body: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: '/channel/open-v2',
				method: 'POST',
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
		req.write(payload);
		req.end();
	});
}

function errorMessage(body: Record<string, unknown>): string {
	return String((body.error as { message?: unknown } | undefined)?.message);
}

describe('POST /channel/open-v2 lease params', function () {
	this.timeout(30_000);

	const dataDir = fs.mkdtempSync(
		path.join(os.tmpdir(), 'beignet-open-v2-lease-')
	);
	let daemon: IStartedDaemon;
	let port: number;

	before(async () => {
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
			dataDir
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	it('refuses requestFunds without maxLeaseRates (the library rule)', async () => {
		const res = await post(port, {
			pubkey: PEER,
			amountSats: 100_000,
			requestFunds: { requestedSats: 50_000, blockheight: 100 }
		});
		expect(res.status).to.equal(400);
		expect(errorMessage(res.body)).to.include('maxLeaseRates');
	});

	it('refuses a non-object requestFunds before it can TypeError', async () => {
		for (const bad of [null, 42, 'lots']) {
			const res = await post(port, {
				pubkey: PEER,
				amountSats: 100_000,
				requestFunds: bad,
				maxLeaseRates: RATES
			});
			expect(res.status, JSON.stringify(bad)).to.equal(400);
			expect(errorMessage(res.body)).to.include('requestFunds');
		}
	});

	it('refuses a fractional, negative or non-numeric requestedSats', async () => {
		for (const bad of [0.5, -1, 0, '50000']) {
			const res = await post(port, {
				pubkey: PEER,
				amountSats: 100_000,
				requestFunds: { requestedSats: bad, blockheight: 100 },
				maxLeaseRates: RATES
			});
			expect(res.status, JSON.stringify(bad)).to.equal(400);
			expect(errorMessage(res.body)).to.include('requestFunds.requestedSats');
		}
	});

	it('refuses a blockheight outside u32, zero included', async () => {
		for (const bad of [0, -1, 1.5, 0x1_0000_0000]) {
			const res = await post(port, {
				pubkey: PEER,
				amountSats: 100_000,
				requestFunds: { requestedSats: 50_000, blockheight: bad },
				maxLeaseRates: RATES
			});
			expect(res.status, JSON.stringify(bad)).to.equal(400);
			expect(errorMessage(res.body)).to.include('requestFunds.blockheight');
		}
	});

	it('refuses a non-object maxLeaseRates', async () => {
		const res = await post(port, {
			pubkey: PEER,
			amountSats: 100_000,
			requestFunds: { requestedSats: 50_000, blockheight: 100 },
			maxLeaseRates: 42
		});
		expect(res.status).to.equal(400);
		expect(errorMessage(res.body)).to.include('maxLeaseRates');
	});

	it('refuses a lease field outside its wire width', async () => {
		const res = await post(port, {
			pubkey: PEER,
			amountSats: 100_000,
			requestFunds: { requestedSats: 50_000, blockheight: 100 },
			maxLeaseRates: { ...RATES, fundingWeightWitness: 0x1_0000 }
		});
		expect(res.status).to.equal(400);
		expect(errorMessage(res.body)).to.include('fundingWeightWitness');
	});

	it('admits well-formed lease params (stops at the unconnected peer)', async () => {
		const res = await post(port, {
			pubkey: PEER,
			amountSats: 100_000,
			requestFunds: { requestedSats: 50_000, blockheight: 100 },
			maxLeaseRates: RATES
		});
		// Everything the route and BeignetNode validate passed; the open then
		// failed on the peer lookup, which is not a request refusal.
		expect(res.status).to.not.equal(400);
	});

	it('leaves the legacy body (no lease params) unchanged', async () => {
		const res = await post(port, {
			pubkey: PEER,
			amountSats: 100_000
		});
		expect(res.status).to.not.equal(400);
	});
});
