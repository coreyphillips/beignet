/**
 * On-chain power endpoints: /send-max, /tx/bump-fee, /tx/boost,
 * /transactions/boostable, /consolidate.
 *
 * Offline suite: the node boots against an unreachable Electrum server (same
 * pattern as tests/lightning/scb.test.ts), so it exercises input validation,
 * NOT_BOOSTABLE / NOTHING_TO_CONSOLIDATE error paths, and daemon route
 * wiring. Successful broadcast paths need a live Electrum + bitcoind; the
 * underlying wallet primitives (setupRbf/setupCpfp/sendMax) are covered
 * against regtest in tests/boost.test.ts.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// A valid regtest bech32 address (also used by tests/boost.test.ts).
const REGTEST_ADDRESS = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const UNKNOWN_TXID = 'ab'.repeat(32);

function httpJson(
	port: number,
	method: string,
	urlPath: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: urlPath,
				method,
				headers: payload
					? {
							'Content-Type': 'application/json',
							'Content-Length': Buffer.byteLength(payload)
					  }
					: {}
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
		if (payload) req.write(payload);
		req.end();
	});
}

async function expectBeignetError(
	promise: Promise<unknown>,
	code: string
): Promise<BeignetError> {
	try {
		await promise;
	} catch (e) {
		expect(e).to.be.instanceOf(BeignetError);
		expect((e as BeignetError).code).to.equal(code);
		return e as BeignetError;
	}
	throw new Error(`Expected BeignetError ${code} but the call succeeded`);
}

describe('On-chain power endpoints', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-onchain-power-'));
		// Electrum intentionally unreachable: only validation paths run here.
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			daemonPort: 0
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async function () {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	describe('BeignetNode methods', () => {
		it('exposes the five power methods', () => {
			expect(node.sendMaxOnchain).to.be.a('function');
			expect(node.bumpFeeOnchain).to.be.a('function');
			expect(node.boostOnchain).to.be.a('function');
			expect(node.listBoostableTransactions).to.be.a('function');
			expect(node.consolidateUtxos).to.be.a('function');
		});

		it('creates the wallet with RBF enabled so bump-fee can apply', () => {
			// canBoost() only reports rbf when the wallet-level flag is set, and
			// sends must signal BIP 125 to be replaceable at all.
			expect(node.getWallet().rbf).to.equal(true);
		});

		it('sendMaxOnchain rejects an invalid address', async () => {
			await expectBeignetError(
				node.sendMaxOnchain('not-an-address'),
				BeignetErrorCode.INVALID_PARAMS
			);
		});

		it('sendMaxOnchain rejects a mainnet address on regtest', async () => {
			await expectBeignetError(
				node.sendMaxOnchain('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
				BeignetErrorCode.INVALID_PARAMS
			);
		});

		it('sendMaxOnchain rejects a non-positive fee rate', async () => {
			await expectBeignetError(
				node.sendMaxOnchain(REGTEST_ADDRESS, 0),
				BeignetErrorCode.INVALID_PARAMS
			);
			await expectBeignetError(
				node.sendMaxOnchain(REGTEST_ADDRESS, -2),
				BeignetErrorCode.INVALID_PARAMS
			);
		});

		it('sendMaxOnchain fails cleanly with no UTXOs', async () => {
			const e = await expectBeignetError(
				node.sendMaxOnchain(REGTEST_ADDRESS, 2),
				BeignetErrorCode.SEND_FAILED
			);
			expect(e.message).to.include('No UTXOs');
		});

		it('bumpFeeOnchain rejects a malformed txid', async () => {
			await expectBeignetError(
				node.bumpFeeOnchain('nothex', 5),
				BeignetErrorCode.INVALID_PARAMS
			);
		});

		it('bumpFeeOnchain requires satsPerVbyte', async () => {
			await expectBeignetError(
				node.bumpFeeOnchain(UNKNOWN_TXID, undefined as unknown as number),
				BeignetErrorCode.INVALID_PARAMS
			);
		});

		it('bumpFeeOnchain reports NOT_BOOSTABLE for an unknown tx', async () => {
			const e = await expectBeignetError(
				node.bumpFeeOnchain(UNKNOWN_TXID, 5),
				BeignetErrorCode.NOT_BOOSTABLE
			);
			expect(e.message).to.include('not boostable');
		});

		it('boostOnchain rejects a non-positive fee rate', async () => {
			await expectBeignetError(
				node.boostOnchain(UNKNOWN_TXID, 0),
				BeignetErrorCode.INVALID_PARAMS
			);
		});

		it('boostOnchain reports NOT_BOOSTABLE for an unknown tx', async () => {
			await expectBeignetError(
				node.boostOnchain(UNKNOWN_TXID),
				BeignetErrorCode.NOT_BOOSTABLE
			);
		});

		it('listBoostableTransactions returns empty rbf/cpfp lists', () => {
			const boostable = node.listBoostableTransactions();
			expect(boostable.rbf).to.deep.equal([]);
			expect(boostable.cpfp).to.deep.equal([]);
		});

		it('consolidateUtxos reports NOTHING_TO_CONSOLIDATE without 2+ UTXOs', async () => {
			const e = await expectBeignetError(
				node.consolidateUtxos(),
				BeignetErrorCode.NOTHING_TO_CONSOLIDATE
			);
			expect(e.message).to.include('need at least 2');
		});

		it('consolidateUtxos validates the fee rate before anything else', async () => {
			await expectBeignetError(
				node.consolidateUtxos(-1),
				BeignetErrorCode.INVALID_PARAMS
			);
		});
	});

	describe('daemon routes', () => {
		it('POST /send-max requires an address', async () => {
			const res = await httpJson(port, 'POST', '/send-max', {});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		});

		it('POST /send-max validates the address', async () => {
			const res = await httpJson(port, 'POST', '/send-max', {
				address: 'garbage'
			});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		});

		it('POST /tx/bump-fee requires txid and satsPerVbyte', async () => {
			const missingBoth = await httpJson(port, 'POST', '/tx/bump-fee', {});
			expect(missingBoth.body.ok).to.equal(false);
			expect((missingBoth.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
			const missingFee = await httpJson(port, 'POST', '/tx/bump-fee', {
				txid: UNKNOWN_TXID
			});
			expect(missingFee.body.ok).to.equal(false);
			expect((missingFee.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		});

		it('POST /tx/bump-fee reports NOT_BOOSTABLE for an unknown tx', async () => {
			const res = await httpJson(port, 'POST', '/tx/bump-fee', {
				txid: UNKNOWN_TXID,
				satsPerVbyte: 5
			});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'NOT_BOOSTABLE'
			);
		});

		it('POST /tx/boost requires a txid', async () => {
			const res = await httpJson(port, 'POST', '/tx/boost', {});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		});

		it('POST /tx/boost reports NOT_BOOSTABLE for an unknown tx', async () => {
			const res = await httpJson(port, 'POST', '/tx/boost', {
				txid: UNKNOWN_TXID
			});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'NOT_BOOSTABLE'
			);
		});

		it('GET /transactions/boostable returns rbf/cpfp arrays', async () => {
			const res = await httpJson(port, 'GET', '/transactions/boostable');
			expect(res.body.ok).to.equal(true);
			const result = res.body.result as { rbf: unknown[]; cpfp: unknown[] };
			expect(result.rbf).to.be.an('array');
			expect(result.cpfp).to.be.an('array');
		});

		it('POST /consolidate reports NOTHING_TO_CONSOLIDATE without UTXOs', async () => {
			const res = await httpJson(port, 'POST', '/consolidate', {});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'NOTHING_TO_CONSOLIDATE'
			);
		});

		it('POST /consolidate validates the fee rate', async () => {
			const res = await httpJson(port, 'POST', '/consolidate', {
				satsPerVbyte: 0
			});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'INVALID_PARAMS'
			);
		});
	});
});
