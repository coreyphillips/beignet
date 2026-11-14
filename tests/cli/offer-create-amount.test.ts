/**
 * Issue #2040: POST /offer/create took amountSats: 0 and returned an offer
 * carrying offer_amount = 0, which BOLT 12 readers (decodeOffer included)
 * refuse to answer. Every offer the route returns must decode.
 *
 * Offline suite: an unreachable Electrum is enough, offers are local state.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { decodeOffer } from '../../src/lightning/offer';

type Reply = {
	status: number;
	body: {
		ok: boolean;
		result?: { offerId: string; encoded?: string };
		error?: { code: string; message: string };
	};
};

function post(port: number, route: string, body: unknown): Promise<Reply> {
	const payload = JSON.stringify(body);
	return new Promise((resolve, reject) => {
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

describe('Issue #2040: POST /offer/create never returns an unanswerable offer', function () {
	this.timeout(30_000);

	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-2040-'));
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

	it('refuses amountSats 0 with INVALID_PARAMS and stores nothing', async () => {
		const before = daemon.node.listOffers().length;
		const res = await post(port, '/offer/create', {
			description: 'any amount',
			amountSats: 0
		});
		expect(res.status).to.equal(400);
		expect(res.body.ok).to.equal(false);
		expect(res.body.error?.code).to.equal('INVALID_PARAMS');
		expect(res.body.error?.message).to.equal(
			'amountSats must be a positive integer number of satoshis; omit it for an offer that takes any amount'
		);
		expect(daemon.node.listOffers()).to.have.length(before);
	});

	it('refuses negative and fractional amounts', async () => {
		for (const amountSats of [-1, 0.5, 1.5]) {
			const res = await post(port, '/offer/create', {
				description: 'bad amount',
				amountSats
			});
			expect(res.status, String(amountSats)).to.equal(400);
			expect(res.body.error?.code).to.equal('INVALID_PARAMS');
		}
	});

	it('every accepted amount, issuer and expiry combination decodes', async () => {
		const amounts = [
			undefined,
			1,
			2_100_000_000_000_000,
			Number.MAX_SAFE_INTEGER
		];
		const issuers = [undefined, 'beignet'];
		const expiries = [undefined, 1, 3600, Number.MAX_SAFE_INTEGER];
		let checked = 0;
		for (const amountSats of amounts) {
			for (const issuer of issuers) {
				for (const expirySecs of expiries) {
					const label = JSON.stringify({ amountSats, issuer, expirySecs });
					const description = `round trip ${checked}`;
					const nowBefore = BigInt(Math.floor(Date.now() / 1000));
					const res = await post(port, '/offer/create', {
						description,
						amountSats,
						issuer,
						expirySecs
					});
					const nowAfter = BigInt(Math.floor(Date.now() / 1000));
					expect(res.status, label).to.equal(200);
					const { offerId, encoded } = res.body.result!;
					expect(encoded, label).to.be.a('string');

					const offer = decodeOffer(encoded!);
					expect(offer.offerId.toString('hex'), label).to.equal(offerId);
					expect(offer.description, label).to.equal(description);
					expect(offer.amount, label).to.equal(
						amountSats === undefined ? undefined : BigInt(amountSats) * 1000n
					);
					expect(offer.issuer, label).to.equal(issuer);
					if (expirySecs === undefined) {
						expect(offer.absoluteExpiry, label).to.equal(undefined);
					} else {
						const at = offer.absoluteExpiry!;
						expect(at >= nowBefore + BigInt(expirySecs), label).to.equal(true);
						expect(at <= nowAfter + BigInt(expirySecs), label).to.equal(true);
					}
					checked++;
				}
			}
		}
		expect(checked).to.equal(amounts.length * issuers.length * expiries.length);
	});
});
