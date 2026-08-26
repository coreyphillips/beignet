/**
 * Daemon splice-out address passthrough (issue #534, LFBW port #532
 * workstream 1A).
 *
 * The LFBW app's "address send" posts an optional `address` to the splice-out
 * route so channel funds pay a third party directly in one splice transaction,
 * no wallet hop. The route used to destructure exactly {channelId, amountSats,
 * feeratePerkw}, silently dropping the field, so a caller's external
 * destination was replaced by the wallet default: the splice succeeded but the
 * funds landed in the wrong place. These tests pin the passthrough at the HTTP
 * boundary: a bad or foreign-network address is refused before any splice
 * machinery runs, a decodable one reaches the channel lookup, and requests
 * without the field behave exactly as before.
 *
 * Boots offline (unreachable Electrum, the recovery-surface pattern): every
 * case here resolves before anything needs a chain source.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Well-formed 32-byte channel id that no channel on the fresh node carries, so
// a request that clears validation lands on the channel lookup and nothing
// deeper runs.
const UNKNOWN_CHANNEL_ID = 'ab'.repeat(32);

// secp256k1 generator point, compressed: a valid pubkey for address fixtures.
const PUBKEY = Buffer.from(
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);
const REGTEST_ADDRESS = bitcoin.payments.p2wpkh({
	pubkey: PUBKEY,
	network: bitcoin.networks.regtest
}).address!;
// BIP173 mainnet P2WPKH test vector: a valid address for the WRONG network.
const MAINNET_ADDRESS = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';

function request(
	port: number,
	body: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: '/channel/splice-out',
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

describe('Daemon splice-out address passthrough', function () {
	this.timeout(30_000);

	const dir = fs.mkdtempSync(
		path.join(os.tmpdir(), 'beignet-splice-out-addr-')
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
			dataDir: dir
		});
		port = (daemon.server.address() as AddressInfo).port;
	});

	after(async () => {
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('refuses an address this network cannot decode as INVALID_PARAMS', async () => {
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: 50_000,
			feeratePerkw: 2500,
			address: 'not-an-address'
		});
		// The refusal proves the field is forwarded at all: before the
		// passthrough the route dropped `address` and this request sailed on to
		// the channel lookup as if none was given.
		expect(res.status).to.equal(400);
		expect(res.body.ok).to.equal(false);
		const error = res.body.error as { code: string; message: string };
		expect(error.code).to.equal('INVALID_PARAMS');
		expect(error.message).to.include('destinationAddress');
	});

	it('refuses a provided empty address instead of paying the wallet', async () => {
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: 50_000,
			feeratePerkw: 2500,
			address: ''
		});
		// Before the guard an empty string failed spliceOut's truthy check and
		// silently fell back to the wallet destination (issue #534 review):
		// funds moved, but not where the caller pointed.
		expect(res.status).to.equal(400);
		expect(res.body.ok).to.equal(false);
		const error = res.body.error as { code: string; message: string };
		expect(error.code).to.equal('INVALID_PARAMS');
		expect(error.message).to.include('destinationAddress');
	});

	it('refuses a non-string address', async () => {
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: 50_000,
			feeratePerkw: 2500,
			address: 42
		});
		expect(res.status).to.equal(400);
		expect(res.body.ok).to.equal(false);
		const error = res.body.error as { code: string; message: string };
		expect(error.code).to.equal('INVALID_PARAMS');
		expect(error.message).to.include('destinationAddress');
	});

	it('refuses a mainnet address on a regtest node (network binding)', async () => {
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: 50_000,
			feeratePerkw: 2500,
			address: MAINNET_ADDRESS
		});
		expect(res.status).to.equal(400);
		expect(res.body.ok).to.equal(false);
		const error = res.body.error as { code: string; message: string };
		expect(error.code).to.equal('INVALID_PARAMS');
		expect(error.message).to.include('destinationAddress');
	});

	it('lets a decodable address through to the channel lookup', async () => {
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: 50_000,
			feeratePerkw: 2500,
			address: REGTEST_ADDRESS
		});
		// The library reports an unknown channel in-band ({ok:false}), not as a
		// thrown error, so the HTTP layer answers 200: reaching it proves the
		// address decoded and the request proceeded past validation.
		expect(res.status).to.equal(200);
		expect(res.body.ok).to.equal(true);
		const result = res.body.result as { ok: boolean; error?: string };
		expect(result.ok).to.equal(false);
		expect(result.error).to.include('Channel not found');
	});

	it('behaves exactly as before when address is omitted', async () => {
		const res = await request(port, {
			channelId: UNKNOWN_CHANNEL_ID,
			amountSats: 50_000,
			feeratePerkw: 2500
		});
		expect(res.status).to.equal(200);
		expect(res.body.ok).to.equal(true);
		const result = res.body.result as { ok: boolean; error?: string };
		expect(result.ok).to.equal(false);
		expect(result.error).to.include('Channel not found');
	});
});
