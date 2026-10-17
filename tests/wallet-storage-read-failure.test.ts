/**
 * Regression for issue #1596: Wallet.create treated a storage read that failed
 * as an empty store, started from defaults, and the next save wrote them over
 * the frozen coins and labels it could not read.
 *
 * Fully OFFLINE: the Electrum server is an unreachable local port and the
 * create-time refresh is disabled.
 */

import * as bip39 from 'bip39';
import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	createConsoleLogger,
	createEncryptedStorage,
	EAvailableNetworks,
	EProtocol,
	err,
	getDefaultWalletData,
	getWalletDataStorageKey,
	IUtxo,
	IWallet,
	IWalletData,
	ok,
	Result,
	TStorage,
	Wallet
} from '../src';
import { TEST_MNEMONIC } from './constants';

const WALLET_NAME = 'readfailurewallet';
const NETWORK = EAvailableNetworks.regtest;
const BLACKLIST_KEY = getWalletDataStorageKey(
	WALLET_NAME,
	NETWORK,
	'blacklistedUtxos'
);

// Unreachable on purpose: this test must work offline.
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

const frozenUtxo: IUtxo = {
	address: 'bcrt1qfrozencoin',
	index: 0,
	path: "m/84'/1'/0'/0/0",
	scriptHash: 'aa'.repeat(32),
	height: 100,
	tx_hash: 'bb'.repeat(32),
	tx_pos: 0,
	value: 50000,
	publicKey: 'cc'.repeat(33)
};

type TReadFailure = 'err' | 'reject' | undefined;

/**
 * JSON-serializing in-memory storage that records every write. failRead
 * decides, per key, whether a read resolves to an Err or rejects.
 */
const memoryStorage = (): {
	storage: TStorage;
	store: Map<string, string>;
	writes: string[];
	failRead: { fn: (key: string) => TReadFailure };
} => {
	const store = new Map<string, string>();
	const writes: string[] = [];
	const failRead = { fn: (_key: string): TReadFailure => undefined };
	const storage: TStorage = {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> => {
			const failure = failRead.fn(key);
			if (failure === 'reject') throw new Error('storage is down');
			if (failure === 'err') return err('storage is down');
			const raw = store.get(key);
			if (raw === undefined) return ok(undefined as unknown as IWalletData[K]);
			return ok(JSON.parse(raw));
		},
		setData: async <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			writes.push(key);
			store.set(key, JSON.stringify(value));
			return ok(true);
		}
	};
	return { storage, store, writes, failRead };
};

describe('Wallet.create with a storage read that fails (issue #1596)', function () {
	this.timeout(60000);

	const created: Wallet[] = [];

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
			disableMessagesOnCreate: true,
			logger: createConsoleLogger('silent'),
			...extra
		});
		if (res.isOk()) created.push(res.value);
		return res;
	};

	/** A wallet that has saved a frozen coin, stopped so its writes landed. */
	const seedStore = async (storage: TStorage): Promise<void> => {
		const res = await create(storage);
		if (res.isErr()) throw res.error;
		await res.value.saveWalletData('blacklistedUtxos', [frozenUtxo]);
		await res.value.stop();
	};

	afterEach(async function () {
		await Promise.all(created.splice(0).map((wallet) => wallet.stop()));
	});

	it('refuses to start, and writes nothing, when every read fails', async function () {
		const { storage, writes, failRead } = memoryStorage();
		failRead.fn = (): TReadFailure => 'err';

		const res = await create(storage);

		expect(res.isErr()).to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.contain('Unable to read wallet data');
		expect(res.error.message).to.contain('storage is down');
		expect(writes).to.deep.equal([]);
	});

	it('refuses to start when one stored key cannot be read', async function () {
		const { storage, store, writes, failRead } = memoryStorage();
		await seedStore(storage);
		writes.length = 0;
		failRead.fn = (key): TReadFailure =>
			key === BLACKLIST_KEY ? 'err' : undefined;

		const res = await create(storage);

		expect(res.isErr()).to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.contain('(blacklistedUtxos)');
		expect(writes).to.deep.equal([]);
		expect(JSON.parse(store.get(BLACKLIST_KEY)!)).to.deep.equal([frozenUtxo]);
	});

	it('refuses to start when a read rejects', async function () {
		const { storage, writes, failRead } = memoryStorage();
		await seedStore(storage);
		writes.length = 0;
		failRead.fn = (key): TReadFailure =>
			key === BLACKLIST_KEY ? 'reject' : undefined;

		const res = await create(storage);

		expect(res.isErr()).to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.contain('(blacklistedUtxos)');
		expect(writes).to.deep.equal([]);
	});

	it('refuses an encrypted store opened with the wrong seed and leaves it untouched', async function () {
		const { storage, store } = memoryStorage();
		const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC);
		const wrongSeed = bip39.mnemonicToSeedSync(
			'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
		);
		await seedStore(createEncryptedStorage(storage, seed));
		const before = new Map(store);

		const res = await create(createEncryptedStorage(storage, wrongSeed));

		expect(res.isErr()).to.equal(true);
		if (res.isOk()) return;
		expect(res.error.message).to.contain('from storage (id)');
		expect(store).to.deep.equal(before);

		const reopened = await create(createEncryptedStorage(storage, seed));
		if (reopened.isErr()) throw reopened.error;
		expect(reopened.value.data.blacklistedUtxos).to.deep.equal([frozenUtxo]);
	});

	it('starts from defaults on a failed read with resetOnReadFailure', async function () {
		const { storage, writes, failRead } = memoryStorage();
		await seedStore(storage);
		writes.length = 0;
		failRead.fn = (): TReadFailure => 'err';

		const res = await create(storage, { resetOnReadFailure: true });
		if (res.isErr()) throw res.error;

		expect(res.value.data.blacklistedUtxos).to.deep.equal([]);
		expect(writes).to.include(
			getWalletDataStorageKey(WALLET_NAME, NETWORK, 'id')
		);
	});

	it('still creates an empty wallet over a storage that holds nothing', async function () {
		const { storage } = memoryStorage();

		const res = await create(storage);
		if (res.isErr()) throw res.error;

		expect(res.value.data).to.deep.equal({
			...getDefaultWalletData(),
			id: res.value.id
		});
	});
});
