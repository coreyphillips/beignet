/**
 * Regression test for issue #1656: every batched Electrum call slept
 * batchDelay after its last batch too, the UTXO listing waited for each
 * batch's answer before sending the next, and a refresh pinged the server
 * before each of its steps.
 *
 * Fully OFFLINE: the client helpers are stubbed with a fake server that
 * accepts the connect and records when each request was sent.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	createConsoleLogger,
	createMemoryStorage,
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IAddress,
	TUnspentAddressScriptHashData,
	Wallet
} from '../../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65524,
		tcp: 65524,
		protocol: EProtocol.tcp
	}
};

/** What Electrum asks the server to decide whether it still answers. */
const LIVENESS_SCRIPT_HASH =
	'77ca78f9a84b48041ad71f7cc6ff6c33460c25f0cb99f558f9813ed9e63727dd';

type TFakeClock = {
	now: number;
	tick: (ms: number) => number;
	tickAsync: (ms: number) => Promise<number>;
	restore: () => void;
};

const useFakeClock = (toFake: string[]): TFakeClock =>
	(
		sinon as unknown as {
			useFakeTimers: (opts: { now: number; toFake: string[] }) => TFakeClock;
		}
	).useFakeTimers({ now: Date.now(), toFake });

const createGate = (): { promise: Promise<void>; release: () => void } => {
	let release = (): void => {};
	const promise = new Promise<void>((resolve) => {
		release = (): void => resolve();
	});
	return { promise, release };
};

const fakeAddress = (index: number): IAddress => ({
	index,
	path: `m/84'/1'/0'/0/${index}`,
	address: `address-${index}`,
	scriptHash: index.toString(16).padStart(64, '0'),
	publicKey: ''
});

type TBatch<T> = { key: string; data: T[] };
/** The UTXO listing sends its batch keyed by script hash. */
type TUtxoBatch = { key: string; data: Record<string, IAddress> };

describe('Electrum batch pacing and connection checks (#1656)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let pings: number;

	beforeEach(async function () {
		pings = 0;
		let peer: { host: string; port: number; protocol: EProtocol } | undefined;
		sinon.stub(electrumHelpers, 'getConnectedPeer').callsFake(() => peer);
		sinon.stub(electrumHelpers, 'start').callsFake(async () => {
			peer = { host: '127.0.0.1', port: 65524, protocol: EProtocol.tcp };
			return { error: false, data: 'connected' };
		});
		sinon.stub(electrumHelpers, 'stop').callsFake(async () => {
			peer = undefined;
			return { error: false, data: 'stopped' };
		});
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashBalance')
			.callsFake(async ({ scriptHash }: { scriptHash: string }) => {
				if (scriptHash === LIVENESS_SCRIPT_HASH) pings += 1;
				return { error: false, data: { confirmed: 0, unconfirmed: 0 } };
			});
		sinon
			.stub(electrumHelpers, 'subscribeHeader')
			.resolves({ error: false, data: { height: 100, hex: '00'.repeat(80) } });
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.resolves({ error: false, data: null });
		sinon
			.stub(electrumHelpers, 'getFeeEstimate')
			.resolves({ error: false, data: 0.0001 });

		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh, EAddressType.p2tr],
			electrumOptions,
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: true,
			logger: createConsoleLogger('silent'),
			storage: createMemoryStorage()
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		wallet.electrum.stopConnectionPolling();
		const connected = await wallet.connectToElectrum();
		if (connected.isErr()) throw connected.error;
		expect(wallet.electrum.connectedToElectrum).to.equal(true);
	});

	afterEach(async function () {
		await wallet?.stop();
		sinon.restore();
	});

	it('sleeps between transaction batches, never after the last one', async function () {
		const clock = useFakeClock(['setTimeout', 'clearTimeout']);
		try {
			const start = clock.now;
			const sentAt: number[] = [];
			sinon
				.stub(electrumHelpers, 'getTransactions')
				.callsFake(
					async ({ txHashes }: { txHashes: TBatch<{ tx_hash: string }> }) => {
						sentAt.push(clock.now - start);
						return {
							error: false,
							data: txHashes.data.map((h) => ({
								data: h,
								param: h.tx_hash,
								result: { txid: h.tx_hash }
							}))
						};
					}
				);
			wallet.electrum.batchLimit = 2;
			expect(wallet.electrum.batchDelay).to.equal(50);

			let settled = false;
			const single = wallet.electrum
				.getTransactions({ txHashes: [{ tx_hash: 'aa' }] })
				.finally(() => (settled = true));
			await clock.tickAsync(0);
			expect(settled, 'a single batch has nothing to wait for').to.equal(true);
			expect((await single).isOk()).to.equal(true);

			sentAt.length = 0;
			settled = false;
			const three = wallet.electrum
				.getTransactions({
					txHashes: ['aa', 'bb', 'cc', 'dd', 'ee'].map((tx_hash) => ({
						tx_hash
					}))
				})
				.finally(() => (settled = true));
			await clock.tickAsync(100);
			expect(sentAt, 'paced by batchDelay').to.deep.equal([0, 50, 100]);
			expect(settled, 'answered once the last batch is').to.equal(true);
			const res = await three;
			if (res.isErr()) throw res.error;
			expect(res.value.data).to.have.length(5);
		} finally {
			clock.restore();
		}
	});

	it('sends every UTXO batch without waiting for the answers', async function () {
		const clock = useFakeClock(['setTimeout', 'clearTimeout']);
		try {
			const start = clock.now;
			const sentAt: number[] = [];
			const answer = createGate();
			sinon
				.stub(electrumHelpers, 'listUnspentAddressScriptHashes')
				.callsFake(async ({ scriptHashes }: { scriptHashes: TUtxoBatch }) => {
					sentAt.push(clock.now - start);
					await answer.promise;
					return {
						error: false,
						data: Object.values(scriptHashes.data).map((a) => ({
							data: a,
							param: a.scriptHash,
							result: [{ tx_hash: 'ab'.repeat(32), tx_pos: a.index, value: 1 }]
						}))
					};
				});
			const addresses: TUnspentAddressScriptHashData = {};
			for (let i = 0; i < 60; i++) {
				const address = fakeAddress(i);
				addresses[address.scriptHash] = address;
			}
			expect(wallet.electrum.batchLimit).to.equal(20);

			const listing = wallet.electrum.listUnspentAddressScriptHashes({
				addresses
			});
			await clock.tickAsync(100);
			expect(sentAt, 'three batches, none answered yet').to.deep.equal([
				0, 50, 100
			]);

			answer.release();
			await clock.tickAsync(0);
			const res = await listing;
			if (res.isErr()) throw res.error;
			expect(res.value.balance).to.equal(60);
			expect(
				res.value.utxos.map((u) => u.tx_pos),
				'in batch order'
			).to.deep.equal([...Array(60).keys()]);
		} finally {
			clock.restore();
		}
	});

	it('pings at most once per refresh while the server keeps answering', async function () {
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => ({
					error: false,
					data: scriptHashes.data.map((a) => ({
						data: a,
						param: a.scriptHash,
						result: []
					}))
				})
			);
		sinon
			.stub(electrumHelpers, 'listUnspentAddressScriptHashes')
			.callsFake(async ({ scriptHashes }: { scriptHashes: TUtxoBatch }) => ({
				error: false,
				data: Object.values(scriptHashes.data).map((a) => ({
					data: a,
					param: a.scriptHash,
					result: []
				}))
			}));
		wallet.electrum.batchDelay = 0;
		const clock = useFakeClock(['Date']);
		try {
			const first = await wallet.refreshWallet();
			expect(first.isOk(), first.isErr() ? first.error.message : '').to.equal(
				true
			);
			expect(pings, 'one ping, before the first step').to.equal(1);

			pings = 0;
			const warm = await wallet.refreshWallet();
			expect(warm.isOk()).to.equal(true);
			expect(pings, 'the last refresh was answered').to.equal(0);

			pings = 0;
			clock.tick(5000);
			const idle = await wallet.refreshWallet();
			expect(idle.isOk()).to.equal(true);
			expect(pings, 'nothing answered for five seconds').to.equal(1);
		} finally {
			clock.restore();
		}
	});
});
