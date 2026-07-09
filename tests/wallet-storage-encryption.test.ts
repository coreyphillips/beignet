import * as bip39 from 'bip39';
import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	createEncryptedStorage,
	EAvailableNetworks,
	EProtocol,
	IUtxo,
	IWalletData,
	ok,
	Result,
	TStorage,
	Wallet
} from '../src';
import { TEST_MNEMONIC } from './constants';

const ENC_PREFIX = 'encw1:';
const testTimeout = 60000;

// In-memory TStorage that JSON-serializes values like a typical host would,
// with the raw store exposed so tests can inspect what actually persists.
const createMemoryStorage = (): {
	storage: TStorage;
	store: Map<string, string>;
} => {
	const store = new Map<string, string>();
	const storage: TStorage = {
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
			store.set(key, JSON.stringify(value));
			return ok(true);
		}
	};
	return { storage, store };
};

const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC);
const wrongSeed = bip39.mnemonicToSeedSync(
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
);

const markerUtxo: IUtxo = {
	address: 'bc1qmarkeraddressxyz',
	index: 0,
	path: "m/84'/1'/0'/0/0",
	scriptHash: 'aa'.repeat(32),
	height: 100,
	tx_hash: 'bb'.repeat(32),
	tx_pos: 0,
	value: 12345,
	publicKey: 'cc'.repeat(33)
};

describe('Wallet Storage Encryption', function () {
	this.timeout(testTimeout);

	describe('TStorage contract', () => {
		it('Should round-trip an object value through setData/getData', async () => {
			const { storage } = createMemoryStorage();
			const encrypted = createEncryptedStorage(storage, seed);
			const setRes = await encrypted.setData!('wallet0-bitcoin-utxos', [
				markerUtxo
			]);
			if (setRes.isErr()) throw setRes.error;
			expect(setRes.value).to.equal(true);
			const getRes = await encrypted.getData!<'utxos'>('wallet0-bitcoin-utxos');
			if (getRes.isErr()) throw getRes.error;
			expect(getRes.value).to.deep.equal([markerUtxo]);
		});

		it('Should persist a prefixed ciphertext that hides the plaintext marker', async () => {
			const { storage, store } = createMemoryStorage();
			const encrypted = createEncryptedStorage(storage, seed);
			await encrypted.setData!('wallet0-bitcoin-utxos', [markerUtxo]);
			const raw = store.get('wallet0-bitcoin-utxos');
			expect(raw).to.be.a('string');
			// The host JSON-serializes the opaque string it receives.
			expect(JSON.parse(raw!)).to.be.a('string');
			expect(JSON.parse(raw!).startsWith(ENC_PREFIX)).to.equal(true);
			expect(raw!.includes(markerUtxo.address)).to.equal(false);
			expect(raw!.includes(String(markerUtxo.value))).to.equal(false);
		});

		it('Should pass legacy plaintext values through unchanged', async () => {
			const { storage, store } = createMemoryStorage();
			// Simulate a pre-encryption row written by the raw host storage.
			store.set('wallet0-bitcoin-utxos', JSON.stringify([markerUtxo]));
			store.set('wallet0-bitcoin-balance', JSON.stringify(5855));
			const encrypted = createEncryptedStorage(storage, seed);
			const utxosRes = await encrypted.getData!<'utxos'>(
				'wallet0-bitcoin-utxos'
			);
			if (utxosRes.isErr()) throw utxosRes.error;
			expect(utxosRes.value).to.deep.equal([markerUtxo]);
			const balanceRes = await encrypted.getData!<'balance'>(
				'wallet0-bitcoin-balance'
			);
			if (balanceRes.isErr()) throw balanceRes.error;
			expect(balanceRes.value).to.equal(5855);
		});

		it('Should fail to read a value written under a different seed', async () => {
			const { storage } = createMemoryStorage();
			const encrypted = createEncryptedStorage(storage, seed);
			await encrypted.setData!('wallet0-bitcoin-utxos', [markerUtxo]);
			const wrongKey = createEncryptedStorage(storage, wrongSeed);
			const getRes = await wrongKey.getData!<'utxos'>('wallet0-bitcoin-utxos');
			expect(getRes.isErr()).to.equal(true);
		});

		it('Should not synthesize getData/setData the inner storage lacks', () => {
			const encrypted = createEncryptedStorage({}, seed);
			expect(encrypted.getData).to.equal(undefined);
			expect(encrypted.setData).to.equal(undefined);
		});
	});

	describe('Wallet save/load cycle', () => {
		const walletName = 'encstoragetestwallet0';
		const { storage, store } = createMemoryStorage();
		let wallet: Wallet;

		before(async function () {
			this.timeout(testTimeout);
			// Electrum is intentionally unreachable: persistence does not need it,
			// and the background refresh failing exercises nothing under test.
			const res = await Wallet.create({
				mnemonic: TEST_MNEMONIC,
				network: EAvailableNetworks.regtest,
				name: walletName,
				storage: createEncryptedStorage(storage, seed),
				disableMessagesOnCreate: true,
				electrumOptions: {
					servers: {
						host: '127.0.0.1',
						ssl: 1,
						tcp: 1,
						protocol: EProtocol.tcp
					},
					net,
					tls
				}
			});
			if (res.isErr()) throw res.error;
			wallet = res.value;
		});

		after(async function () {
			await wallet?.stop();
			await wallet?.electrum?.disconnect();
		});

		it('Should save and reload wallet data through the encrypted storage', async () => {
			await wallet.saveWalletData('balance', 4321);
			const dataRes = await wallet.getWalletData();
			if (dataRes.isErr()) throw dataRes.error;
			expect(dataRes.value.balance).to.equal(4321);
			expect(dataRes.value.id).to.equal(wallet.id);
		});

		it('Should store every persisted value encrypted with the encw1 prefix', () => {
			expect(store.size).to.be.greaterThan(0);
			for (const [key, raw] of store.entries()) {
				const stored = JSON.parse(raw);
				expect(stored, key).to.be.a('string');
				expect(stored.startsWith(ENC_PREFIX), key).to.equal(true);
			}
			// The wallet id is a known plaintext marker saved at create time.
			const idRaw = store.get(`${walletName}-regtest-id`);
			expect(idRaw).to.be.a('string');
			expect(idRaw!.includes(wallet.id)).to.equal(false);
		});

		it('Should fail to load wallet data with the wrong seed', async () => {
			const wrongKey = createEncryptedStorage(storage, wrongSeed);
			const getRes = await wrongKey.getData!<'balance'>(
				`${walletName}-regtest-balance`
			);
			expect(getRes.isErr()).to.equal(true);
		});
	});
});
