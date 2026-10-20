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
	IAddress,
	IFormattedTransaction,
	IGetAddressHistoryResponse,
	IGetUtxosResponse,
	IOnchainFees,
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

	/**
	 * Lets refreshWallet run offline. Electrum is stubbed at the wallet's
	 * edges, so the real gap scan runs against a server that reports history
	 * only for the script hashes in `used`.
	 */
	const stubRefresh = (wallet: Wallet, used: Set<string>): void => {
		wallet.checkElectrumConnection = async (): Promise<Result<string>> =>
			ok('connected');
		wallet.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(wallet.feeEstimates);
		wallet.getUtxos = async (): Promise<Result<IGetUtxosResponse>> =>
			ok({ utxos: [], balance: 0 });
		wallet.updateTransactions = async (): Promise<Result<string | undefined>> =>
			ok(undefined);
		wallet.electrum.subscribeToAddresses = async (): Promise<Result<string>> =>
			ok('subscribed');
		wallet.electrum.getAddressHistory = async ({
			scriptHashes = []
		}: {
			scriptHashes?: IAddress[];
		}): Promise<Result<IGetAddressHistoryResponse[]>> =>
			ok(
				scriptHashes
					.filter((address) => used.has(address.scriptHash))
					.map((address) => ({ ...address, tx_hash: TXID, height: 1 }))
			);
	};

	const savedIndex = (store: Map<string, string>, wallet: Wallet): number =>
		(stored(store, 'addressIndex') as IWalletData['addressIndex'])[
			wallet.addressType
		].index;

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

	// Issue #1744: the daemon creates its wallet with disableMessagesOnCreate,
	// which held back every message until the first refresh ended, this report
	// among them. A write refused at startup or during that refresh left
	// storage stale and told nobody.
	describe('created with disableMessagesOnCreate (issue #1744)', function () {
		/** Every message the listener heard, in order, by key. */
		let heard: string[];

		const openQuiet = async (storage: TStorage): Promise<Wallet> => {
			heard = [];
			const res = await create(storage, {
				disableMessagesOnCreate: true,
				onMessage: <K extends keyof TMessageDataMap>(
					key: K,
					data: TMessageDataMap[K]
				): void => {
					// The connection poll announces its own state changes on its own
					// schedule, so it is left out of the order asserted below.
					if (key === 'connectedToElectrum') return;
					heard.push(key);
					if (key === 'storageWriteFailed') {
						reports.push(data as TStorageWriteFailure);
					}
				}
			});
			if (res.isErr()) throw res.error;
			return res.value;
		};

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

			const wallet = await openQuiet(storage);

			expect(wallet.data.transaction.outputs).to.deep.equal([]);
			expect(stored(store, 'transaction')).to.deep.equal(left);
			expectReported('transaction');
			expect(heard).to.deep.equal(['storageWriteFailed']);
		});

		it('reports a refused header write during the first refresh, and holds the rest until it ends', async function () {
			const { storage, refused } = memoryStorage();
			const wallet = await openQuiet(storage);
			wallet.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
				ok(wallet.feeEstimates);
			const header = (height: number): IWalletData['header'] => ({
				height,
				hash: 'aa'.repeat(32),
				hex: ''
			});
			(
				wallet as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
			)._runRefresh = async (): Promise<Result<IWalletData>> => {
				// What the first refresh finds is history to this host.
				wallet.sendMessage('transactionReceived', {
					transaction: transaction(TXID)
				});
				await wallet.updateHeader(header(10));
				return ok(wallet.data);
			};
			refused.add('header');

			const refreshed = await wallet.refreshWallet({});

			if (refreshed.isErr()) throw refreshed.error;
			expectReported('header');
			expect(heard).to.deep.equal(['storageWriteFailed']);

			// The refresh's end lifts the hold on everything else.
			reports = [];
			heard = [];
			wallet.sendMessage('transactionReceived', {
				transaction: transaction(TXID)
			});
			await wallet.updateHeader(header(11));
			expectReported('header');
			expect(heard).to.deep.equal([
				'transactionReceived',
				'storageWriteFailed'
			]);
		});

		it('keeps reports silent too once the wallet has stopped', async function () {
			const { storage, refused } = memoryStorage();
			let release = (): void => undefined;
			const released = new Promise<void>((resolve) => (release = resolve));
			const wallet = await openQuiet({
				...storage,
				setData: async <K extends keyof IWalletData>(
					key: string,
					value: IWalletData[K]
				): Promise<Result<boolean>> => {
					if (key === storageKey('header')) await released;
					return storage.setData(key, value);
				}
			});
			refused.add('header');

			// A write out at the adapter when stop() gives up on it.
			const pending = wallet.updateHeader({ height: 1, hash: '', hex: '' });
			const stopped = await wallet.stop({ refreshTimeout: 50 });
			if (stopped.isErr()) throw stopped.error;
			release();
			await pending;

			expect(reports).to.deep.equal([]);
			expect(heard).to.deep.equal([]);
		});
	});

	it('fails a new receive address whose index cannot be saved, and a read made while its write was out', async function () {
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
		const served = wallet.getReceiveAddress({});
		release();
		const second = await pending;
		const read = await served;

		expect(second.isErr()).to.equal(true);
		if (second.isOk()) return;
		expect(second.error.message).to.contain('receive address index');
		// The read saves the index too, and storage refuses that write as well.
		expect(read.isErr()).to.equal(true);
		if (read.isOk()) return;
		expect(read.error.message).to.contain('receive address index');
		expect(reports.map((report) => report.key)).to.deep.equal([
			'addressIndex',
			'addressIndex'
		]);

		refused.clear();
		const retried = await wallet.generateNewReceiveAddress();
		if (retried.isErr()) throw retried.error;
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

	it('saves the index a retry at the gap limit returns, so a restart comes back to it (issue #1736)', async function () {
		const { storage, store, refused } = memoryStorage();
		let indexWrites = 0;
		const counted: TStorage = {
			...storage,
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (key === storageKey('addressIndex')) indexWrites++;
				return storage.setData(key, value);
			}
		};
		const wallet = await open(counted);
		const type = wallet.addressType;
		const gap = wallet.gapLimitOptions.lookBehind;
		while (wallet.data.addressIndex[type].index < gap - 1) {
			const res = await wallet.generateNewReceiveAddress();
			if (res.isErr()) throw res.error;
		}
		refused.add('addressIndex');
		const refusedRes = await wallet.generateNewReceiveAddress();
		expect(refusedRes.isErr()).to.equal(true);

		refused.clear();
		indexWrites = 0;
		const retried = await wallet.generateNewReceiveAddress();

		if (retried.isErr()) throw retried.error;
		expect(retried.value.index).to.equal(gap);
		expect(indexWrites).to.equal(1);
		const saved = stored(store, 'addressIndex') as IWalletData['addressIndex'];
		expect(saved[type].index).to.equal(gap);
		await wallet.stop();
		const restarted = await open(counted);
		const current = await restarted.getReceiveAddress({});
		if (current.isErr()) throw current.error;
		expect(current.value).to.equal(retried.value.address);
	});

	it('saves the index before getReceiveAddress returns an address whose write was refused (issue #1736)', async function () {
		const { storage, store, refused } = memoryStorage();
		const wallet = await open(storage);
		const type = wallet.addressType;
		refused.add('addressIndex');
		const refusedRes = await wallet.generateNewReceiveAddress();
		expect(refusedRes.isErr()).to.equal(true);

		const whileRefused = await wallet.getReceiveAddress({});
		expect(whileRefused.isErr()).to.equal(true);
		if (whileRefused.isOk()) return;
		expect(whileRefused.error.message).to.contain('receive address index');

		refused.clear();
		const current = await wallet.getReceiveAddress({});
		if (current.isErr()) throw current.error;
		expect(current.value).to.equal(wallet.data.addressIndex[type].address);
		const saved = stored(store, 'addressIndex') as IWalletData['addressIndex'];
		expect(saved[type].address).to.equal(current.value);
		await wallet.stop();
		const restarted = await open(storage);
		const afterRestart = await restarted.getReceiveAddress({});
		if (afterRestart.isErr()) throw afterRestart.error;
		expect(afterRestart.value).to.equal(current.value);
	});

	it('keeps an issuance that overlaps the write getReceiveAddress makes (issue #1736)', async function () {
		const { storage, store, refused } = memoryStorage();
		const wallet = await open(storage);
		const type = wallet.addressType;
		refused.add('addressIndex');
		const refusedRes = await wallet.generateNewReceiveAddress();
		expect(refusedRes.isErr()).to.equal(true);
		const unsaved = wallet.data.addressIndex[type];
		refused.clear();

		const [current, issued] = await Promise.all([
			wallet.getReceiveAddress({}),
			wallet.generateNewReceiveAddress()
		]);

		if (current.isErr()) throw current.error;
		if (issued.isErr()) throw issued.error;
		expect(current.value).to.equal(unsaved.address);
		expect(issued.value.index).to.equal(unsaved.index + 1);
		expect(wallet.data.addressIndex[type].index).to.equal(issued.value.index);
		const saved = stored(store, 'addressIndex') as IWalletData['addressIndex'];
		expect(saved[type].index).to.equal(issued.value.index);
	});

	it('does not write the index a network switch reloads over an issuance still out (issue #1736)', async function () {
		const { storage, store } = memoryStorage();
		const indexWrites: IWalletData['addressIndex'][] = [];
		let hold = false;
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
				if (key === storageKey('addressIndex')) {
					indexWrites.push(value as IWalletData['addressIndex']);
					if (hold) {
						hold = false;
						writeOut();
						await released;
					}
				}
				return storage.setData(key, value);
			}
		});
		wallet.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(wallet.feeEstimates);
		(
			wallet as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
		)._runRefresh = async (): Promise<Result<IWalletData>> => ok(wallet.data);
		const type = wallet.addressType;
		const first = await wallet.generateNewReceiveAddress();
		if (first.isErr()) throw first.error;
		const before = first.value.index;
		indexWrites.length = 0;

		hold = true;
		const pending = wallet.generateNewReceiveAddress();
		await out;
		const away = await wallet.switchNetwork(
			EAvailableNetworks.signet,
			electrumOptions.servers
		);
		if (away.isErr()) throw away.error;
		wallet.electrum.disconnect = async (): Promise<void> => undefined;
		const back = await wallet.switchNetwork(NETWORK, electrumOptions.servers);
		if (back.isErr()) throw back.error;
		const read = wallet.getReceiveAddress({});
		release();
		const issued = await pending;
		const current = await read;

		if (issued.isErr()) throw issued.error;
		if (current.isErr()) throw current.error;
		expect(issued.value.index).to.equal(before + 1);
		expect(indexWrites.map((written) => written[type].index)).to.deep.equal([
			before + 1
		]);
		const saved = stored(store, 'addressIndex') as IWalletData['addressIndex'];
		expect(saved[type].index).to.equal(issued.value.index);
		await wallet.stop();
		const restarted = await open(storage);
		const next = await restarted.generateNewReceiveAddress();
		if (next.isErr()) throw next.error;
		expect(next.value.index).to.equal(issued.value.index + 1);
	});

	// Issue #1746: switching away and back while an issuance write was out
	// reloaded the index storage held before that write landed. The write then
	// landed without moving the reloaded index, so the next generation on the
	// same instance moved to the index just issued and gave its address out
	// again.
	it('advances the next address past an issuance that landed across a switch away and back (issue #1746)', async function () {
		const { storage, store } = memoryStorage();
		let hold = false;
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
				if (hold && key === storageKey('addressIndex')) {
					hold = false;
					writeOut();
					await released;
				}
				return storage.setData(key, value);
			}
		});
		wallet.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(wallet.feeEstimates);
		(
			wallet as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
		)._runRefresh = async (): Promise<Result<IWalletData>> => ok(wallet.data);
		const type = wallet.addressType;
		const first = await wallet.generateNewReceiveAddress();
		if (first.isErr()) throw first.error;
		expect(savedIndex(store, wallet)).to.equal(first.value.index);

		hold = true;
		const pending = wallet.generateNewReceiveAddress();
		await out;
		const away = await wallet.switchNetwork(
			EAvailableNetworks.signet,
			electrumOptions.servers
		);
		if (away.isErr()) throw away.error;
		wallet.electrum.disconnect = async (): Promise<void> => undefined;
		const back = await wallet.switchNetwork(NETWORK, electrumOptions.servers);
		if (back.isErr()) throw back.error;
		release();
		const issued = await pending;

		if (issued.isErr()) throw issued.error;
		expect(issued.value.index).to.equal(first.value.index + 1);
		expect(savedIndex(store, wallet)).to.equal(issued.value.index);
		expect(
			wallet.data.addressIndex[type].index,
			'the live index holds the issuance'
		).to.equal(issued.value.index);
		const current = await wallet.getReceiveAddress({});
		if (current.isErr()) throw current.error;
		expect(current.value).to.equal(issued.value.address);

		// On the same instance, before any restart.
		const next = await wallet.generateNewReceiveAddress();
		if (next.isErr()) throw next.error;
		expect(next.value.index).to.equal(issued.value.index + 1);
		expect(next.value.address).to.not.equal(issued.value.address);
		expect(wallet.data.addressIndex[type].index).to.equal(next.value.index);
		expect(savedIndex(store, wallet)).to.equal(next.value.index);
	});

	it('advances the next address past an issuance that landed while the switch back was still installing (issue #1746)', async function () {
		const { storage, store } = memoryStorage();
		let hold = false;
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
				if (hold && key === storageKey('addressIndex')) {
					hold = false;
					writeOut();
					await released;
				}
				return storage.setData(key, value);
			}
		});
		wallet.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(wallet.feeEstimates);
		(
			wallet as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
		)._runRefresh = async (): Promise<Result<IWalletData>> => ok(wallet.data);
		const type = wallet.addressType;
		const first = await wallet.generateNewReceiveAddress();
		if (first.isErr()) throw first.error;

		hold = true;
		const pending = wallet.generateNewReceiveAddress();
		await out;
		const away = await wallet.switchNetwork(
			EAvailableNetworks.signet,
			electrumOptions.servers
		);
		if (away.isErr()) throw away.error;
		// The switch back disconnects after it has read the index and before
		// it installs that read. The write lands in between, on signet.
		wallet.electrum.disconnect = async (): Promise<void> => {
			release();
			await pending;
		};
		const back = await wallet.switchNetwork(NETWORK, electrumOptions.servers);
		if (back.isErr()) throw back.error;
		const issued = await pending;

		if (issued.isErr()) throw issued.error;
		expect(issued.value.index).to.equal(first.value.index + 1);
		expect(savedIndex(store, wallet)).to.equal(issued.value.index);
		expect(
			wallet.data.addressIndex[type].index,
			'the live index holds the issuance'
		).to.equal(issued.value.index);
		const current = await wallet.getReceiveAddress({});
		if (current.isErr()) throw current.error;
		expect(current.value).to.equal(issued.value.address);
		const next = await wallet.generateNewReceiveAddress();
		if (next.isErr()) throw next.error;
		expect(next.value.index).to.equal(issued.value.index + 1);
		expect(next.value.address).to.not.equal(issued.value.address);
		expect(savedIndex(store, wallet)).to.equal(next.value.index);
	});

	it('adopts the index a landed write carried, not a later move whose own write was refused (issue #1746)', async function () {
		const { storage, store, refused } = memoryStorage();
		let hold = false;
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
				if (key !== storageKey('addressIndex')) {
					return storage.setData(key, value);
				}
				if (refused.has('addressIndex')) return err('storage is full');
				// Taken on entry, as an adapter commits what it was handed.
				const serialized = JSON.stringify(value);
				if (hold) {
					hold = false;
					writeOut();
					await released;
				}
				store.set(key, serialized);
				return ok(true);
			}
		});
		wallet.updateFeeEstimates = async (): Promise<Result<IOnchainFees>> =>
			ok(wallet.feeEstimates);
		(
			wallet as unknown as { _runRefresh: () => Promise<Result<IWalletData>> }
		)._runRefresh = async (): Promise<Result<IWalletData>> => ok(wallet.data);
		const type = wallet.addressType;
		const first = await wallet.generateNewReceiveAddress();
		if (first.isErr()) throw first.error;

		hold = true;
		const pending = wallet.generateNewReceiveAddress();
		await out;
		const behind = wallet.generateNewReceiveAddress();
		// It derives its address first. Its index write queues behind the held
		// one once that derivation's write, answered at once here, settles.
		await new Promise((resolve) => setImmediate(resolve));
		expect(wallet.data.addressIndex[type].index).to.equal(
			first.value.index + 2
		);
		const away = await wallet.switchNetwork(
			EAvailableNetworks.signet,
			electrumOptions.servers
		);
		if (away.isErr()) throw away.error;
		wallet.electrum.disconnect = async (): Promise<void> => undefined;
		const back = await wallet.switchNetwork(NETWORK, electrumOptions.servers);
		if (back.isErr()) throw back.error;
		refused.add('addressIndex');
		release();
		const issued = await pending;
		const refusedRes = await behind;

		if (issued.isErr()) throw issued.error;
		expect(issued.value.index).to.equal(first.value.index + 1);
		expect(refusedRes.isErr()).to.equal(true);
		expect(savedIndex(store, wallet)).to.equal(issued.value.index);
		expect(
			wallet.data.addressIndex[type].index,
			'the live index holds what storage took'
		).to.equal(issued.value.index);
		refused.clear();
		const current = await wallet.getReceiveAddress({});
		if (current.isErr()) throw current.error;
		expect(current.value).to.equal(issued.value.address);
		expect(savedIndex(store, wallet)).to.equal(issued.value.index);
		await wallet.stop();
		const restarted = await open(storage);
		const next = await restarted.generateNewReceiveAddress();
		if (next.isErr()) throw next.error;
		expect(next.value.address).to.not.equal(current.value);
	});

	// Issue #1745: a refresh that found the current address used moved the
	// index in memory and threw away the result of its write. The getter then
	// served the moved index as saved, and a restart came back to the used
	// address.
	it('saves the index a refresh moved before getReceiveAddress returns it, when the refresh write was refused (issue #1745)', async function () {
		const { storage, store, refused } = memoryStorage();
		let indexWrites = 0;
		const counted: TStorage = {
			...storage,
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (key === storageKey('addressIndex')) indexWrites++;
				return storage.setData(key, value);
			}
		};
		const wallet = await open(counted);
		const type = wallet.addressType;
		const used = new Set<string>();
		stubRefresh(wallet, used);
		const first = await wallet.refreshWallet({});
		if (first.isErr()) throw first.error;
		expect(wallet.data.addressIndex[type].index).to.equal(0);
		expect(savedIndex(store, wallet)).to.equal(0);

		// A payment reaches address 0, and storage refuses the index the
		// refresh moves on to.
		used.add(wallet.data.addressIndex[type].scriptHash);
		refused.add('addressIndex');
		const second = await wallet.refreshWallet({});
		if (second.isErr()) throw second.error;
		expect(wallet.data.addressIndex[type].index).to.equal(1);
		expect(savedIndex(store, wallet)).to.equal(0);
		expectReported('addressIndex');

		const whileRefused = await wallet.getReceiveAddress({});
		expect(whileRefused.isErr()).to.equal(true);
		if (whileRefused.isOk()) return;
		expect(whileRefused.error.message).to.contain('receive address index');

		refused.clear();
		indexWrites = 0;
		const current = await wallet.getReceiveAddress({});
		if (current.isErr()) throw current.error;
		expect(current.value).to.equal(wallet.data.addressIndex[type].address);
		expect(indexWrites).to.equal(1);
		expect(savedIndex(store, wallet)).to.equal(1);
		const again = await wallet.getReceiveAddress({});
		if (again.isErr()) throw again.error;
		expect(indexWrites, 'a read of a saved index writes nothing').to.equal(1);

		await wallet.stop();
		const restarted = await open(counted);
		const afterRestart = await restarted.getReceiveAddress({});
		if (afterRestart.isErr()) throw afterRestart.error;
		expect(afterRestart.value).to.equal(current.value);
	});

	it('saves the index the first refresh set before getReceiveAddress returns it, when that write was refused (issue #1745)', async function () {
		const { storage, store, refused } = memoryStorage();
		const wallet = await open(storage);
		const type = wallet.addressType;
		stubRefresh(wallet, new Set());
		refused.add('addressIndex');
		const refreshed = await wallet.refreshWallet({});
		if (refreshed.isErr()) throw refreshed.error;
		expect(wallet.data.addressIndex[type].index).to.equal(0);
		expect(stored(store, 'addressIndex')).to.equal(undefined);
		expectReported('addressIndex');

		const whileRefused = await wallet.getReceiveAddress({});
		expect(whileRefused.isErr()).to.equal(true);
		if (whileRefused.isOk()) return;
		expect(whileRefused.error.message).to.contain('receive address index');

		refused.clear();
		const current = await wallet.getReceiveAddress({});
		if (current.isErr()) throw current.error;
		expect(current.value).to.equal(wallet.data.addressIndex[type].address);
		expect(savedIndex(store, wallet)).to.equal(0);

		// Without the saved index a restart would start over at -1 and issue
		// address 0, the one just given out, as its first new address.
		await wallet.stop();
		const restarted = await open(storage);
		const afterRestart = await restarted.getReceiveAddress({});
		if (afterRestart.isErr()) throw afterRestart.error;
		expect(afterRestart.value).to.equal(current.value);
		const next = await restarted.generateNewReceiveAddress();
		if (next.isErr()) throw next.error;
		expect(next.value.index).to.equal(1);
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
