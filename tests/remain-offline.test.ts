/**
 * A wallet created with remainOffline opens no connection. Every
 * rn-electrum-client helper is wrapped to record its calls, because a helper
 * that finds no client dials a random peer of its own, and fetch is wrapped
 * to catch a fee lookup over HTTP. Runs in its own process in CI: a wallet
 * another test file left running would show up in the recorded calls.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	createMemoryStorage,
	EAddressType,
	EProtocol,
	Network,
	Wallet
} from '../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Reading the connected peer opens nothing.
const HARMLESS = new Set(['getConnectedPeer']);

describe('remainOffline', function () {
	this.timeout(30000);

	const helperCalls: string[] = [];
	const fetchCalls: string[] = [];
	const originals = new Map<string, unknown>();
	const originalFetch = globalThis.fetch;

	before(() => {
		for (const [name, fn] of Object.entries(electrumHelpers)) {
			if (typeof fn !== 'function') continue;
			originals.set(name, fn);
			electrumHelpers[name] = (...args: unknown[]): unknown => {
				if (!HARMLESS.has(name)) helperCalls.push(name);
				return (fn as (...a: unknown[]) => unknown)(...args);
			};
		}
		globalThis.fetch = (async (input: unknown) => {
			fetchCalls.push(String(input));
			throw new Error('fetch is not allowed offline');
		}) as typeof fetch;
	});

	after(() => {
		for (const [name, fn] of originals) electrumHelpers[name] = fn;
		globalThis.fetch = originalFetch;
	});

	beforeEach(() => {
		helperCalls.length = 0;
		fetchCalls.length = 0;
	});

	const create = async (network: Network): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'offline',
			network,
			storage: createMemoryStorage(),
			remainOffline: true,
			electrumOptions: {
				net,
				tls,
				servers: {
					host: '127.0.0.1',
					ssl: 50002,
					tcp: 50001,
					protocol: EProtocol.tcp
				}
			}
		});
		if (res.isErr()) throw res.error;
		return res.value;
	};

	it('creates, refreshes and stops without a request', async () => {
		const wallet = await create(Network.bitcoin);
		try {
			expect(wallet.remainOffline).to.equal(true);
			expect(wallet.electrum.isDisconnected).to.equal(true);
			expect(wallet.electrum['connectionPollingInterval']).to.equal(null);

			const refreshed = await wallet.refreshWallet({});
			expect(refreshed.isErr()).to.equal(true);
			// The refresh still derives the first addresses before it stops.
			expect(wallet.data.addressIndex[EAddressType.p2wpkh].address).to.match(
				/^bc1q/
			);
			expect(wallet.refreshFailed).to.equal(true);
		} finally {
			await wallet.stop();
		}
		expect(helperCalls).to.deep.equal([]);
		expect(fetchCalls).to.deep.equal([]);
	});

	it('refuses every call that needs a server', async () => {
		const wallet = await create(Network.bitcoin);
		try {
			const address = await wallet.getAddress();
			expect((await wallet.connectToElectrum()).isErr()).to.equal(true);
			expect((await wallet.electrum.connectToElectrum({})).isErr()).to.equal(
				true
			);
			expect((await wallet.checkElectrumConnection()).isErr()).to.equal(true);
			expect((await wallet.broadcastTransaction('00')).isErr()).to.equal(true);
			expect((await wallet.fetchAddressBalance(address)).isErr()).to.equal(
				true
			);
			expect((await wallet.fetchAddressesBalance([address])).isErr()).to.equal(
				true
			);
			expect((await wallet.fetchAddressHistory(address)).isErr()).to.equal(
				true
			);
			expect((await wallet.refreshUtxos({})).isErr()).to.equal(true);
			expect((await wallet.electrum.subscribeToAddresses()).isErr()).to.equal(
				true
			);
			expect(
				await wallet.electrum.getScriptPubKeyHistory('0014' + '00'.repeat(20))
			).to.deep.equal([]);
			let merkle: unknown;
			try {
				await wallet.electrum.getTransactionMerkle({
					tx_hash: '00'.repeat(32),
					height: 1
				});
			} catch (e) {
				merkle = e;
			}
			expect(merkle).to.be.an('error');
			// Fee estimates stay as they are rather than go to mempool.space.
			const before = wallet.feeEstimates;
			expect(await wallet.fetchFeeEstimates()).to.deep.equal(before);
			expect(await wallet.fetchFeeEstimatesFromHttp()).to.deep.equal(before);
			expect(await wallet.fetchFallbackFeeEstimates()).to.deep.equal(before);
			const updated = await wallet.updateFeeEstimates(true);
			if (updated.isErr()) throw updated.error;
			expect(updated.value).to.deep.equal(before);
			wallet.electrum.startConnectionPolling();
			expect(wallet.electrum['connectionPollingInterval']).to.equal(null);
		} finally {
			await wallet.stop();
		}
		expect(helperCalls).to.deep.equal([]);
		expect(fetchCalls).to.deep.equal([]);
	});

	it('stays offline across a network switch', async () => {
		const wallet = await create(Network.bitcoin);
		try {
			const switched = await wallet.switchNetwork(Network.testnet);
			if (switched.isErr()) throw switched.error;
			expect(wallet.network).to.equal(Network.testnet);
			expect(wallet.remainOffline).to.equal(true);
			expect(wallet.electrum.isDisconnected).to.equal(true);
			expect((await wallet.connectToElectrum()).isErr()).to.equal(true);
		} finally {
			await wallet.stop();
		}
		expect(helperCalls).to.deep.equal([]);
		expect(fetchCalls).to.deep.equal([]);
	});
});
