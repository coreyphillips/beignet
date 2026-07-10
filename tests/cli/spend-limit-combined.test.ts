/**
 * Combined LN + on-chain daily spend limit, UTXO freeze routes, address
 * labels and descriptor export at the daemon level.
 *
 * Offline suite (same pattern as tests/cli/onchain-power.test.ts): the node
 * boots against an unreachable Electrum server. On-chain sends are made
 * possible offline by injecting fake wallet UTXOs (signing only needs the
 * derivation path) and stubbing electrum.broadcastTransaction.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { Wallet } from '../../src/wallet';
import { EAddressType, IUtxo } from '../../src/types';
import { ok } from '../../src/utils';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// A valid regtest bech32 address (also used by tests/boost.test.ts).
const REGTEST_ADDRESS = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';
const TXID_A = '33'.repeat(32);
const TXID_B = '44'.repeat(32);
const DAILY_LIMIT = 10_000;

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

/** Fabricates a UTXO paying to one of the wallet's own derived addresses. */
const injectUtxo = (
	wallet: Wallet,
	txid: string,
	value: number,
	addressIndex = 0
): IUtxo => {
	const source =
		addressIndex === 0
			? wallet.data.addressIndex[EAddressType.p2wpkh]
			: Object.values(wallet.data.addresses[EAddressType.p2wpkh]).find(
					(a) => a.index === addressIndex
			  );
	if (!source?.address) throw new Error('No derived address available.');
	const utxo: IUtxo = {
		address: source.address,
		index: source.index,
		path: source.path,
		scriptHash: source.scriptHash,
		height: 0,
		tx_hash: txid,
		tx_pos: 0,
		value,
		publicKey: source.publicKey
	};
	wallet.data.utxos.push(utxo);
	wallet.data.balance += value;
	return utxo;
};

describe('Combined daily spend limit + onchain controls (daemon)', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;
	let wallet: Wallet;
	let broadcastCount = 0;

	const spendLimit = async (): Promise<Record<string, number>> => {
		const res = await httpJson(port, 'GET', '/spend-limit');
		expect(res.body.ok).to.equal(true);
		return res.body.result as Record<string, number>;
	};

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-spend-limit-'));
		// Electrum intentionally unreachable: broadcasts are stubbed below.
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
			daemonPort: 0,
			dailySpendLimitSats: DAILY_LIMIT
		}));
		port = (server.address() as AddressInfo).port;
		wallet = (node as unknown as { wallet: Wallet }).wallet;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		injectUtxo(wallet, TXID_A, 60_000);
		injectUtxo(wallet, TXID_B, 40_000, 1);
		// Stub the broadcast: sends succeed without a network.
		wallet.electrum.broadcastTransaction = async (): Promise<
			ReturnType<typeof ok<string>>
		> => {
			broadcastCount += 1;
			return ok('stubbed');
		};
		// consolidate needs a fresh address, which normally requires Electrum.
		node.getNewAddress = async (): Promise<string> =>
			wallet.data.addressIndex[EAddressType.p2wpkh].address;
	});

	after(async function () {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	describe('GET /spend-limit breakdown', () => {
		it('starts at zero with all breakdown fields present', async () => {
			const info = await spendLimit();
			expect(info.limitSats).to.equal(DAILY_LIMIT);
			expect(info.totalSats).to.equal(0);
			expect(info.lightningSats).to.equal(0);
			expect(info.onchainSats).to.equal(0);
			expect(info.spentSats).to.equal(0); // back-compat field
			expect(info.remainingSats).to.equal(DAILY_LIMIT);
		});
	});

	describe('POST /send counts against the budget', () => {
		it('records amount + fee as onchain spend', async () => {
			const res = await httpJson(port, 'POST', '/send', {
				address: REGTEST_ADDRESS,
				amountSats: 3000,
				satsPerVbyte: 2
			});
			expect(res.body.ok).to.equal(true);
			expect(broadcastCount).to.equal(1);
			const info = await spendLimit();
			// amount + fee: strictly greater than the amount alone.
			expect(info.onchainSats).to.be.greaterThan(3000);
			expect(info.onchainSats).to.be.lessThan(3000 + 2000);
			expect(info.lightningSats).to.equal(0);
			expect(info.totalSats).to.equal(info.onchainSats);
			expect(info.spentSats).to.equal(info.totalSats);
			expect(info.remainingSats).to.equal(DAILY_LIMIT - info.totalSats);
		});

		it('rejects a send exceeding the remaining budget and records nothing', async () => {
			const before = await spendLimit();
			const broadcastsBefore = broadcastCount;
			const res = await httpJson(port, 'POST', '/send', {
				address: REGTEST_ADDRESS,
				amountSats: before.remainingSats + 1,
				satsPerVbyte: 2
			});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'SPENDING_LIMIT_EXCEEDED'
			);
			expect(broadcastCount).to.equal(broadcastsBefore);
			const after = await spendLimit();
			expect(after.totalSats).to.equal(before.totalSats);
		});
	});

	describe('POST /send-max checks the computed sweep before broadcast', () => {
		it('rejects a sweep larger than the remaining budget without broadcasting', async () => {
			const before = await spendLimit();
			const broadcastsBefore = broadcastCount;
			// The wallet holds 100k sats; far above the remaining budget.
			const res = await httpJson(port, 'POST', '/send-max', {
				address: REGTEST_ADDRESS,
				satsPerVbyte: 2
			});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'SPENDING_LIMIT_EXCEEDED'
			);
			expect(broadcastCount).to.equal(broadcastsBefore);
			const after = await spendLimit();
			expect(after.totalSats).to.equal(before.totalSats);
		});
	});

	describe('excluded operations', () => {
		it('consolidate (self-pay) is NOT counted', async () => {
			const before = await spendLimit();
			const res = await httpJson(port, 'POST', '/consolidate', {
				satsPerVbyte: 2
			});
			expect(res.body.ok).to.equal(true);
			const after = await spendLimit();
			expect(after.totalSats).to.equal(before.totalSats);
			expect(after.onchainSats).to.equal(before.onchainSats);
		});

		it('bump-fee never touches the budget (fee-only, excluded by design)', async () => {
			const before = await spendLimit();
			const res = await httpJson(port, 'POST', '/tx/bump-fee', {
				txid: 'ab'.repeat(32),
				satsPerVbyte: 5
			});
			// Unknown tx: NOT_BOOSTABLE. The path contains no spend recording.
			expect(res.body.ok).to.equal(false);
			const after = await spendLimit();
			expect(after.totalSats).to.equal(before.totalSats);
		});
	});

	describe('LN and onchain share ONE budget', () => {
		it('rejects a Lightning payment that exceeds the remaining combined budget', async () => {
			const before = await spendLimit();
			const invoice = node.createInvoice(
				before.remainingSats + 1,
				'over budget'
			);
			const res = await httpJson(port, 'POST', '/invoice/pay', {
				bolt11: invoice.bolt11
			});
			expect(res.body.ok).to.equal(false);
			expect((res.body.error as { code: string }).code).to.equal(
				'SPENDING_LIMIT_EXCEEDED'
			);
		});

		it('lightning spends land in lightningSats of the same budget', async () => {
			// A real LN settlement needs a live channel; record directly to
			// verify the shared-counter accounting.
			const before = await spendLimit();
			(
				node as unknown as {
					_recordSpend: (n: number, s: 'lightning' | 'onchain') => void;
				}
			)._recordSpend(500, 'lightning');
			const after = await spendLimit();
			expect(after.lightningSats).to.equal(before.lightningSats + 500);
			expect(after.onchainSats).to.equal(before.onchainSats);
			expect(after.totalSats).to.equal(before.totalSats + 500);
			expect(after.remainingSats).to.equal(before.remainingSats - 500);
		});
	});

	describe('UTXO freeze/unfreeze routes', () => {
		it('GET /utxos exposes the frozen flag', async () => {
			const res = await httpJson(port, 'GET', '/utxos');
			expect(res.body.ok).to.equal(true);
			const utxos = res.body.result as Array<Record<string, unknown>>;
			expect(utxos.length).to.be.greaterThan(0);
			for (const utxo of utxos) {
				expect(utxo.frozen).to.equal(false);
			}
		});

		it('freezes and unfreezes via the daemon', async () => {
			const freeze = await httpJson(port, 'POST', '/utxo/freeze', {
				txid: TXID_B,
				index: 0
			});
			expect(freeze.body.ok).to.equal(true);
			expect((freeze.body.result as { frozen: string }).frozen).to.equal(
				`${TXID_B}:0`
			);
			const utxos = (await httpJson(port, 'GET', '/utxos')).body
				.result as Array<{ txid: string; frozen: boolean }>;
			const target = utxos.find((u) => u.txid === TXID_B);
			expect(target?.frozen).to.equal(true);
			const unfreeze = await httpJson(port, 'POST', '/utxo/unfreeze', {
				txid: TXID_B,
				index: 0
			});
			expect(unfreeze.body.ok).to.equal(true);
		});

		it('validates freeze parameters', async () => {
			const missing = await httpJson(port, 'POST', '/utxo/freeze', {});
			expect(missing.body.ok).to.equal(false);
			const unknown = await httpJson(port, 'POST', '/utxo/unfreeze', {
				txid: 'ab'.repeat(32),
				index: 0
			});
			expect(unknown.body.ok).to.equal(false);
		});
	});

	describe('address label routes', () => {
		it('sets, lists and clears labels', async () => {
			const set = await httpJson(port, 'POST', '/address/label', {
				address: REGTEST_ADDRESS,
				label: 'test label'
			});
			expect(set.body.ok).to.equal(true);
			const list = await httpJson(port, 'GET', '/address/labels');
			expect(list.body.ok).to.equal(true);
			expect(list.body.result).to.deep.equal({
				[REGTEST_ADDRESS]: 'test label'
			});
			const clear = await httpJson(port, 'POST', '/address/label', {
				address: REGTEST_ADDRESS,
				label: ''
			});
			expect(clear.body.ok).to.equal(true);
			const empty = await httpJson(port, 'GET', '/address/labels');
			expect(empty.body.result).to.deep.equal({});
		});

		it('rejects an invalid address', async () => {
			const res = await httpJson(port, 'POST', '/address/label', {
				address: 'nope',
				label: 'x'
			});
			expect(res.body.ok).to.equal(false);
		});
	});

	describe('GET /wallet/descriptors', () => {
		it('returns checksummed descriptors without private keys', async () => {
			const res = await httpJson(port, 'GET', '/wallet/descriptors');
			expect(res.body.ok).to.equal(true);
			const info = res.body.result as {
				fingerprint: string;
				descriptors: Array<{ external: string; internal: string }>;
			};
			expect(info.fingerprint).to.match(/^[0-9a-f]{8}$/);
			expect(info.descriptors).to.have.length(4);
			for (const d of info.descriptors) {
				expect(d.external).to.match(/#[a-z0-9]{8}$/);
			}
			expect(JSON.stringify(res.body)).to.not.contain('prv');
		});
	});
});

describe('New routes are auth-covered', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-authcov-'));
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
			daemonPort: 0,
			apiToken: 'sekret-token'
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async function () {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('rejects unauthenticated access to every new route', async () => {
		const routes: Array<[string, string]> = [
			['GET', '/wallet/descriptors'],
			['GET', '/address/labels'],
			['POST', '/address/label'],
			['POST', '/utxo/freeze'],
			['POST', '/utxo/unfreeze'],
			['GET', '/spend-limit']
		];
		for (const [method, route] of routes) {
			const res = await httpJson(port, method, route, {});
			expect(res.status, `${method} ${route}`).to.equal(401);
			expect((res.body.error as { code: string }).code).to.equal(
				'UNAUTHORIZED'
			);
		}
	});
});
