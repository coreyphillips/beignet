import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import {
	OnchainSweepInfo,
	OnchainSweepRequest
} from '../../src/cli/onchain-sweep';

describe('Durable sweep HTTP boundary', function () {
	this.timeout(30000);
	let daemon: IStartedDaemon;
	let directory: string;
	let port: number;
	const requestId = 'http-sweep-request';
	const info: OnchainSweepInfo = {
		requestId,
		address: 'destination',
		status: 'prepared',
		debitSats: 10000,
		amountSats: 9800,
		feeSats: 200,
		createdAt: 1
	};

	function request(
		method: string,
		route: string,
		body?: unknown,
		key = 'admin-test-key'
	): Promise<{
		status: number;
		body: { result?: unknown; error?: { code: string } };
	}> {
		return new Promise((resolve, reject) => {
			const payload = body === undefined ? undefined : JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					method,
					path: route,
					headers: {
						Authorization: `Bearer ${key}`,
						'Content-Type': 'application/json',
						...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
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
						} catch (error) {
							reject(error);
						}
					});
				}
			);
			req.on('error', reject);
			req.end(payload);
		});
	}

	before(async () => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sweep-http-'));
		daemon = await startDaemon({
			mnemonic:
				'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
			network: 'regtest',
			dataDir: directory,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			logLevel: 'silent',
			daemonPort: 0,
			apiKeys: [
				{ name: 'admin', key: 'admin-test-key', scopes: ['admin'] },
				{ name: 'reader', key: 'readonly-test-key', scopes: ['readonly'] }
			]
		});
		port = (daemon.server.address() as AddressInfo).port;
	});
	after(async () => {
		await daemon?.stop();
		if (directory) fs.rmSync(directory, { recursive: true, force: true });
	});

	it('refuses incomplete review input and missing request identities before signing', async () => {
		for (const suffix of ['prepare', 'submit', 'cancel']) {
			const result = await request('POST', `/onchain/sweep/${suffix}`, {});
			expect(result.status).to.equal(400);
			expect(result.body.error?.code).to.equal('INVALID_PARAMS');
		}
		const unknown = await request(
			'GET',
			`/onchain/sweep?requestId=${requestId}`
		);
		expect(unknown.status).to.equal(404);
		expect(unknown.body.error?.code).to.equal('NOT_FOUND');
	});

	it('allows status reads but refuses all sweep mutations for a readonly key', async () => {
		for (const suffix of ['prepare', 'submit', 'cancel']) {
			const result = await request(
				'POST',
				`/onchain/sweep/${suffix}`,
				{ requestId },
				'readonly-test-key'
			);
			expect(result.status).to.equal(403);
		}
		const original = daemon.node.getOnchainSweep;
		try {
			daemon.node.getOnchainSweep = (id) => {
				expect(id).to.equal(requestId);
				return info;
			};
			const result = await request(
				'GET',
				`/onchain/sweep?requestId=${requestId}`,
				undefined,
				'readonly-test-key'
			);
			expect(result.status).to.equal(200);
			expect(result.body.result).to.deep.equal(info);
		} finally {
			daemon.node.getOnchainSweep = original;
		}
	});

	it('forwards the reviewed input set and exact debit and fee cap intact', async () => {
		const review: OnchainSweepRequest = {
			requestId,
			address: 'destination',
			satsPerVbyte: 2.25,
			inputOutpoints: [{ txid: 'ab'.repeat(32), vout: 3 }],
			debitSats: 10000,
			maxFeeSats: 250
		};
		const original = daemon.node.prepareOnchainSweep;
		try {
			daemon.node.prepareOnchainSweep = async (input) => {
				expect(input).to.deep.equal(review);
				return info;
			};
			const result = await request('POST', '/onchain/sweep/prepare', review);
			expect(result.status).to.equal(200);
			expect(result.body.result).to.deep.equal(info);
		} finally {
			daemon.node.prepareOnchainSweep = original;
		}
	});

	it('submits and cancels by the existing identity', async () => {
		const originalSubmit = daemon.node.submitOnchainSweep;
		const originalCancel = daemon.node.cancelOnchainSweep;
		try {
			daemon.node.submitOnchainSweep = async (id) => {
				expect(id).to.equal(requestId);
				return { ...info, status: 'submitted' };
			};
			daemon.node.cancelOnchainSweep = async (id) => {
				expect(id).to.equal(requestId);
				return { ...info, status: 'cancelled' };
			};
			for (const suffix of ['submit', 'cancel']) {
				const result = await request('POST', `/onchain/sweep/${suffix}`, {
					requestId
				});
				expect(result.status).to.equal(200);
			}
		} finally {
			daemon.node.submitOnchainSweep = originalSubmit;
			daemon.node.cancelOnchainSweep = originalCancel;
		}
	});
});
