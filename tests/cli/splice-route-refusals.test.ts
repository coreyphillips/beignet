/**
 * A refused splice is a failure envelope, not a 200 (issue #618).
 *
 * Both splice routes wrapped the engine's in-band SpliceResult in success(),
 * so `{"ok":true,"result":{"ok":false,"error":"Channel not found"}}` came back
 * with a 200. That is a third envelope shape beside the documented two, and
 * the only one where a failure is indistinguishable from a success to a client
 * that reads the envelope and stops there: the LFBW app read a refused
 * splice-in as a splice that worked, and `beignet channel splice-in` printed
 * the refusal and exited 0.
 *
 * The route boundary now converts the refusal the way fundingOrRefuse already
 * converts the thrown ones. Route cases boot the daemon offline (unreachable
 * Electrum): with no channels, every splice refuses on the channel lookup.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import {
	IStartedDaemon,
	startDaemon,
	statusForErrorCode
} from '../../src/cli/daemon';
import { spliceRefusalError } from '../../src/cli/beignet-node';
import { BeignetErrorCode } from '../../src/cli/errors';
import { SpliceRefusalCode } from '../../src/lightning/node/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const UNKNOWN_CHANNEL_ID = 'ab'.repeat(32);

function request(
	port: number,
	route: string,
	body: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: route,
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

describe('Splice routes answer a refusal as a failure', function () {
	this.timeout(30_000);

	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-splice-refusal-'));
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

	for (const route of ['/channel/splice-in', '/channel/splice-out']) {
		it(`${route} answers an unknown channel 404 CHANNEL_NOT_FOUND`, async () => {
			const res = await request(port, route, {
				channelId: UNKNOWN_CHANNEL_ID,
				amountSats: 50_000,
				feeratePerkw: 2500
			});
			expect(res.status).to.equal(404);
			expect(res.body.ok).to.equal(false);
			const error = res.body.error as { code: string; message: string };
			expect(error.code).to.equal('CHANNEL_NOT_FOUND');
			expect(error.message).to.include('Channel not found');
			// The refusal must not also arrive as a payload: a client reading
			// `result` on a failure is reading a shape that no longer exists.
			expect(res.body.result).to.equal(undefined);
		});

		it(`${route} still answers a missing field 400 INVALID_PARAMS`, async () => {
			const res = await request(port, route, {
				channelId: UNKNOWN_CHANNEL_ID,
				feeratePerkw: 2500
			});
			expect(res.status).to.equal(400);
			const error = res.body.error as { code: string };
			expect(error.code).to.equal('INVALID_PARAMS');
		});
	}
});

describe('spliceRefusalError', () => {
	it('maps every refusal code to a status that is not a node fault', () => {
		// Object.values over the enum: a code added without a mapping fails
		// here rather than reaching a caller as a generic 500.
		for (const code of Object.values(SpliceRefusalCode)) {
			const err = spliceRefusalError({ ok: false, error: 'nope', code });
			expect(err, code).to.not.equal(null);
			expect(err!.message).to.equal('nope');
			const status = statusForErrorCode(err!.code);
			expect(status, `${code} -> ${err!.code}`).to.be.lessThan(500);
		}
	});

	it('names the specific code, not one bucket for all of them', () => {
		const cases: Array<[SpliceRefusalCode, BeignetErrorCode, number]> = [
			[
				SpliceRefusalCode.CHANNEL_NOT_FOUND,
				BeignetErrorCode.CHANNEL_NOT_FOUND,
				404
			],
			[SpliceRefusalCode.INVALID_PARAMS, BeignetErrorCode.INVALID_PARAMS, 400],
			[
				SpliceRefusalCode.INSUFFICIENT_BALANCE,
				BeignetErrorCode.INSUFFICIENT_BALANCE,
				409
			],
			[
				SpliceRefusalCode.FUNDING_PROVIDER_REQUIRED,
				BeignetErrorCode.FUNDING_PROVIDER_REQUIRED,
				409
			],
			[
				SpliceRefusalCode.SPLICING_NOT_NEGOTIATED,
				BeignetErrorCode.SPLICING_NOT_NEGOTIATED,
				409
			],
			[SpliceRefusalCode.SPLICE_REFUSED, BeignetErrorCode.SPLICE_REFUSED, 409]
		];
		for (const [refusal, expected, status] of cases) {
			const err = spliceRefusalError({
				ok: false,
				error: 'nope',
				code: refusal
			});
			expect(err!.code, refusal).to.equal(expected);
			expect(statusForErrorCode(err!.code), refusal).to.equal(status);
		}
	});

	it('leaves a started splice alone', () => {
		expect(spliceRefusalError({ ok: true })).to.equal(null);
	});

	it('refuses an untyped refusal rather than passing it as a success', () => {
		// An engine older than the codes, or one that grew a refusal arm
		// without one: the answer is still a failure, never a 200.
		const err = spliceRefusalError({
			ok: false,
			error: 'something went wrong'
		});
		expect(err!.code).to.equal(BeignetErrorCode.SPLICE_REFUSED);
		expect(err!.message).to.equal('something went wrong');
		const bare = spliceRefusalError({ ok: false });
		expect(bare!.code).to.equal(BeignetErrorCode.SPLICE_REFUSED);
		expect(bare!.message).to.equal('Splice refused');
	});
});
