/**
 * Regression test for issue #1811: an address request whose gap scan was
 * still waiting on history when a refresh extended the address maps judged
 * its gap against addresses it had never checked, and answered the used
 * receive index it started from.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port, the
 * connection reads as answered recently, and the client helpers answer
 * history from a fixed set of used script hashes.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IAddress,
	IWalletData,
	ok,
	Result,
	Wallet
} from '../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
const ELECTRUM_PORT = 65529;

type TBatch<T> = { key: string; data: T[] };

describe('an address request during a refresh (#1811)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	const used = new Set<string>();
	// Holds the next history request until released.
	let holdNext = false;
	let held: Promise<void> | undefined;
	let release = (): void => undefined;

	const receiveAt = async (
		from: number,
		amount: number
	): Promise<IAddress[]> => {
		const res = await wallet.generateAddresses({
			addressAmount: amount,
			changeAddressAmount: 0,
			addressIndex: from,
			addressType: EAddressType.p2wpkh
		});
		if (res.isErr()) throw res.error;
		return Object.values(res.value.addresses);
	};

	beforeEach(async () => {
		used.clear();
		holdNext = false;
		held = undefined;
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			gapLimitOptions: {
				lookBehind: 2,
				lookAhead: 2,
				lookBehindChange: 2,
				lookAheadChange: 2
			},
			electrumOptions: {
				net,
				tls,
				servers: {
					host: '127.0.0.1',
					ssl: ELECTRUM_PORT,
					tcp: ELECTRUM_PORT,
					protocol: EProtocol.tcp
				}
			},
			disableRefreshOnCreate: true,
			storage: {
				setData: async <K extends keyof IWalletData>(
					_key: string,
					_value: IWalletData[K]
				): Promise<Result<boolean>> => ok(true)
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;

		wallet.electrum.stopConnectionPolling();
		wallet.electrum.connectedToElectrum = true;
		wallet.electrum.batchDelay = 0;
		sinon.stub(wallet.electrum, 'answeredRecently').returns(true);
		sinon.stub(wallet.electrum, 'isConnected').resolves(true);
		sinon.stub(wallet, 'updateFeeEstimates').resolves(ok(wallet.feeEstimates));
		sinon.stub(wallet, 'refreshUtxos').resolves(ok({ utxos: [], balance: 0 }));
		sinon.stub(wallet, 'updateTransactions').resolves(ok(undefined));
		sinon.stub(wallet.electrum, 'subscribeToAddresses').resolves(ok('ok'));
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => {
					if (holdNext) {
						holdNext = false;
						held = new Promise<void>((resolve) => {
							release = resolve;
						});
						await held;
					}
					return {
						error: false,
						data: scriptHashes.data.map((a) => ({
							data: a,
							param: a.scriptHash,
							result: used.has(a.scriptHash)
								? [{ tx_hash: 'ab'.repeat(32), height: 1 }]
								: []
						}))
					};
				}
			);

		// The first refresh stores the initial windows, with nothing used.
		const first = await wallet.refreshWallet();
		if (first.isErr()) throw first.error;
		expect(wallet.data.addressIndex.p2wpkh.index).to.equal(0);
		for (const a of await receiveAt(0, 5)) used.add(a.scriptHash);
	});

	afterEach(async () => {
		release();
		sinon.restore();
		await wallet?.stop();
	});

	it('answers the index the refresh selected, not the used one it started from', async () => {
		holdNext = true;
		const pending = wallet.getNextAvailableAddress();
		while (!held) await new Promise((resolve) => setImmediate(resolve));

		const refreshed = await wallet.refreshWallet();
		if (refreshed.isErr()) throw refreshed.error;
		expect(wallet.data.addressIndex.p2wpkh.index).to.equal(5);

		release();
		const res = await pending;
		if (res.isErr()) throw res.error;
		expect(res.value.addressIndex.index).to.equal(5);
		expect(res.value.addressIndex.address).to.equal(
			wallet.data.addressIndex.p2wpkh.address
		);
		expect(res.value.lastUsedAddressIndex.index).to.equal(4);
		expect(res.value.changeAddressIndex.index).to.equal(0);
	});

	it('checks addresses stored past its window before trusting the gap', async () => {
		// Stored before this scan, as by a refresh or a wider gap limit.
		for (const a of await receiveAt(2, 5)) {
			wallet.data.addresses.p2wpkh[a.scriptHash] = { ...a };
		}

		const res = await wallet.getNextAvailableAddress();
		if (res.isErr()) throw res.error;
		expect(res.value.addressIndex.index).to.equal(5);
		expect(res.value.lastUsedAddressIndex.index).to.equal(4);
	});
});
