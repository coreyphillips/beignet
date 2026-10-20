/**
 * Regression for issue #1642: most Wallet writes threw away the Result of
 * saveWalletData, so a write the storage adapter refused left memory and
 * storage disagreeing and told nobody. The next start loaded the old copy.
 *
 * Fully OFFLINE: the Electrum server is an unreachable local port and the
 * create-time refresh is disabled.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	createConsoleLogger,
	EAvailableNetworks,
	EProtocol,
	err,
	getWalletDataStorageKey,
	IFormattedTransaction,
	IWallet,
	IWalletData,
	ok,
	Result,
	TMessageDataMap,
	TStorage,
	TStorageWriteFailure,
	TWalletDataKeys,
	Wallet
} from '../src';
import { getDefaultSendTransaction } from '../src/shapes/wallet';
import { TEST_MNEMONIC } from './constants';

const WALLET_NAME = 'writefailurewallet';
const NETWORK = EAvailableNetworks.regtest;
const TXID = 'ab'.repeat(32);

const storageKey = (key: TWalletDataKeys): string =>
	getWalletDataStorageKey(WALLET_NAME, NETWORK, key);

// Unreachable on purpose: this test must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65523,
		tcp: 65523,
		protocol: EProtocol.tcp
	}
};

/**
 * JSON-serializing in-memory storage. A write to a key in `refused` answers
 * Err and leaves the stored value as it was.
 */
const memoryStorage = (): {
	storage: Required<TStorage>;
	store: Map<string, string>;
	refused: Set<TWalletDataKeys>;
} => {
	const store = new Map<string, string>();
	const refused = new Set<TWalletDataKeys>();
	const storage: Required<TStorage> = {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> => {
			const raw = store.get(key);
			if (raw === undefined) return ok(undefined as unknown as IWalletData[K]);
			return ok(JSON.parse(raw));
		},
		setData: async <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			if ([...refused].some((k) => key === storageKey(k))) {
				return err('storage is full');
			}
			store.set(key, JSON.stringify(value));
			return ok(true);
		}
	};
	return { storage, store, refused };
};

const stored = (store: Map<string, string>, key: TWalletDataKeys): unknown => {
	const raw = store.get(storageKey(key));
	return raw === undefined ? undefined : JSON.parse(raw);
};

const transaction = (txid: string): IFormattedTransaction =>
	({
		txid,
		height: 0,
		value: 0.0001,
		exists: true
	}) as unknown as IFormattedTransaction;

describe('Wallet writes that storage refuses (issue #1642)', function () {
	this.timeout(60000);

	const created: Wallet[] = [];
	let reports: TStorageWriteFailure[];

	const create = async (
		storage: TStorage,
		extra: Partial<IWallet> = {}
	): Promise<Result<Wallet>> => {
		const res = await Wallet.create({
			mnemonic: TEST_MNEMONIC,
			network: NETWORK,
			name: WALLET_NAME,
			electrumOptions,
			storage,
			disableRefreshOnCreate: true,
			logger: createConsoleLogger('silent'),
			onMessage: <K extends keyof TMessageDataMap>(
				key: K,
				data: TMessageDataMap[K]
			): void => {
				if (key === 'storageWriteFailed') {
					reports.push(data as TStorageWriteFailure);
				}
			},
			...extra
		});
		if (res.isOk()) created.push(res.value);
		return res;
	};

	const open = async (storage: TStorage): Promise<Wallet> => {
		const res = await create(storage);
		if (res.isErr()) throw res.error;
		return res.value;
	};

	const expectReported = (key: TWalletDataKeys): void => {
		expect(reports).to.deep.equal([
			{ key, storageKey: storageKey(key), error: 'storage is full' }
		]);
	};

	beforeEach(function () {
		reports = [];
	});

	afterEach(async function () {
		await Promise.all(created.splice(0).map((wallet) => wallet.stop()));
	});

	it('refuses to create a wallet whose id cannot be saved', async function () {
		const { storage, refused } = memoryStorage();
		refused.add('id');

		const res = await create(storage);

		expect(res.isErr()).to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.contain('Unable to save the wallet id');
		expect(res.error.message).to.contain('storage is full');
	});

	it('reports a refused scrub of the stored send at startup', async function () {
		const { storage, store, refused } = memoryStorage();
		await open(storage);
		const left = {
			...getDefaultSendTransaction(),
			outputs: [{ address: 'bcrt1qrecipient', value: 1000, index: 0 }]
		};
		store.set(storageKey('transaction'), JSON.stringify(left));
		refused.add('transaction');
		reports = [];

		const wallet = await open(storage);

		expect(wallet.data.transaction.outputs).to.deep.equal([]);
		expectReported('transaction');
	});

	it('fails a new receive address whose index cannot be saved, and does not issue it again', async function () {
		const { storage, store, refused } = memoryStorage();
		let writeOut = (): void => undefined;
		const out = new Promise<void>((resolve) => (writeOut = resolve));
		let release = (): void => undefined;
		const released = new Promise<void>((resolve) => (release = resolve));
		const wallet = await open({
			...storage,
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (refused.has('addressIndex') && key === storageKey('addressIndex')) {
					writeOut();
					await released;
				}
				return storage.setData(key, value);
			}
		});
		const first = await wallet.generateNewReceiveAddress();
		if (first.isErr()) throw first.error;
		refused.add('addressIndex');

		const pending = wallet.generateNewReceiveAddress();
		await out;
		const served = await wallet.getReceiveAddress({});
		if (served.isErr()) throw served.error;
		release();
		const second = await pending;

		expect(second.isErr()).to.equal(true);
		if (second.isOk()) return;
		expect(second.error.message).to.contain('receive address index');
		expectReported('addressIndex');

		refused.clear();
		const retried = await wallet.generateNewReceiveAddress();
		if (retried.isErr()) throw retried.error;
		expect(retried.value.address).to.not.equal(served.value);
		expect(retried.value.index).to.equal(first.value.index + 2);
		const saved = stored(store, 'addressIndex') as IWalletData['addressIndex'];
		expect(saved[wallet.addressType].index).to.equal(retried.value.index);
	});

	it('keeps a receive address an overlapping request saved when the first request is refused', async function () {
		const { storage, store } = memoryStorage();
		let refuseNext = false;
		const wallet = await open({
			...storage,
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (refuseNext && key === storageKey('addressIndex')) {
					refuseNext = false;
					// Slow enough for the second request to move the index
					// while this write is still out.
					await new Promise((resolve) => setTimeout(resolve, 50));
					return err('storage is full');
				}
				return storage.setData(key, value);
			}
		});
		const type = wallet.addressType;
		const first = await wallet.generateNewReceiveAddress();
		if (first.isErr()) throw first.error;
		refuseNext = true;

		// The create-time refresh is off, so nothing past the current index is
		// derived yet: both requests derive the next address and hold the same
		// object for it.
		const [refusedRes, issued] = await Promise.all([
			wallet.generateNewReceiveAddress(),
			wallet.generateNewReceiveAddress()
		]);

		expect(refusedRes.isErr()).to.equal(true);
		if (issued.isErr()) throw issued.error;
		expect(issued.value.index).to.equal(first.value.index + 1);
		expect(wallet.data.addressIndex[type].index).to.equal(issued.value.index);
		const saved = stored(store, 'addressIndex') as IWalletData['addressIndex'];
		expect(saved[type].index).to.equal(issued.value.index);
		const next = await wallet.generateNewReceiveAddress();
		if (next.isErr()) throw next.error;
		expect(next.value.index).to.equal(issued.value.index + 1);
	});

	it('reports refused index writes from resetAddressIndexes', async function () {
		const { storage, refused } = memoryStorage();
		const wallet = await open(storage);
		refused.add('lastUsedAddressIndex');

		await wallet.resetAddressIndexes();

		expectReported('lastUsedAddressIndex');
	});

	it('fails an address label that cannot be saved', async function () {
		const { storage, refused } = memoryStorage();
		const wallet = await open(storage);
		const address = await wallet.getReceiveAddress({});
		if (address.isErr()) throw address.error;
		refused.add('addressLabels');

		const res = await wallet.setAddressLabel(address.value, 'savings');

		expect(res.isErr()).to.equal(true);
		expectReported('addressLabels');
	});

	it('reports a refused address type write', async function () {
		const { storage, refused } = memoryStorage();
		const wallet = await open(storage);
		refused.add('addressType');
		// The refresh it starts needs Electrum, which this test does not have.
		wallet.refreshWallet = async (): Promise<Result<IWalletData>> =>
			ok(wallet.data);

		await wallet.updateAddressType(wallet.addressType);

		expectReported('addressType');
	});

	it('reports a refused header write', async function () {
		const { storage, refused } = memoryStorage();
		const wallet = await open(storage);
		refused.add('header');

		await wallet.updateHeader({ height: 10, hash: 'aa'.repeat(32), hex: '' });

		expectReported('header');
	});

	it('reports a refused balance write', async function () {
		const { storage, refused } = memoryStorage();
		const wallet = await open(storage);
		refused.add('balance');

		const res = wallet.updateWalletBalance({ balance: 5000 });
		expect(res.isOk()).to.equal(true);
		await new Promise((resolve) => setImmediate(resolve));

		expectReported('balance');
	});

	it('keeps the watched copy of a deleted transaction whose record cannot be deleted', async function () {
		const { storage, store, refused } = memoryStorage();
		const wallet = await open(storage);
		wallet.data.transactions[TXID] = transaction(TXID);
		wallet.data.unconfirmedTransactions[TXID] = transaction(TXID);
		await wallet.saveWalletData('transactions', wallet.data.transactions);
		await wallet.saveWalletData(
			'unconfirmedTransactions',
			wallet.data.unconfirmedTransactions
		);
		refused.add('transactions');

		const res = await wallet.deleteOnChainTransactionById({ txid: TXID });

		expect(res.isErr()).to.equal(true);
		expectReported('transactions');
		expect(stored(store, 'transactions')).to.have.property(TXID);
		expect(stored(store, 'unconfirmedTransactions')).to.have.property(TXID);
	});

	it('fails a ghost marking that cannot be saved', async function () {
		const { storage, refused } = memoryStorage();
		const wallet = await open(storage);
		wallet.data.transactions[TXID] = transaction(TXID);
		refused.add('transactions');

		const res = await wallet.addGhostTransaction({ txid: TXID });

		expect(res.isErr()).to.equal(true);
		expectReported('transactions');
	});

	it('still answers Err when the listener throws on the report', async function () {
		const { storage, refused } = memoryStorage();
		const res = await create(storage, {
			onMessage: (): void => {
				throw new Error('listener failed');
			}
		});
		if (res.isErr()) throw res.error;
		refused.add('header');

		const saved = await res.value.saveWalletData('header', {
			height: 1,
			hash: '',
			hex: ''
		});

		expect(saved.isErr()).to.equal(true);
	});

	it('queues a save the listener makes behind the write that threw', async function () {
		const { storage, store } = memoryStorage();
		const header = (height: number): IWalletData['header'] => ({
			height,
			hash: '',
			hex: ''
		});
		let throwNext = false;
		let release = (): void => undefined;
		const released = new Promise<void>((resolve) => (release = resolve));
		let wallet: Wallet | undefined = undefined;
		let retry: Promise<Result<string>> | undefined;
		const res = await create(
			{
				...storage,
				setData: <K extends keyof IWalletData>(
					key: string,
					value: IWalletData[K]
				): Promise<Result<boolean>> => {
					if (key === storageKey('header') && throwNext) {
						throwNext = false;
						throw new Error('adapter crashed');
					}
					if ((value as IWalletData['header'])?.height === 2) {
						return released.then(() => storage.setData(key, value));
					}
					return storage.setData(key, value);
				}
			},
			{
				onMessage: (key): void => {
					if (key === 'storageWriteFailed' && wallet && !retry) {
						retry = wallet.saveWalletData('header', header(2));
					}
				}
			}
		);
		if (res.isErr()) throw res.error;
		wallet = res.value;
		throwNext = true;

		const first = await wallet.saveWalletData('header', header(1));
		const third = wallet.saveWalletData('header', header(3));
		release();

		expect(first.isErr()).to.equal(true);
		expect((await retry)?.isOk()).to.equal(true);
		expect((await third).isOk()).to.equal(true);
		expect(stored(store, 'header')).to.deep.equal(header(3));
	});
});
