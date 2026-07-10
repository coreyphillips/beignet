/**
 * Per-address label and wallet birthday tests. Fully OFFLINE: wallets point
 * at an unreachable Electrum port; labels and the birthday are pure wallet
 * data.
 *
 * Birthday honesty note: the Electrum protocol addresses history by
 * scripthash with no height filter, so birthdayHeight cannot bound Electrum
 * scans. These tests cover exactly what is implemented: validated storage,
 * earliest-wins persistence, and inclusion in the descriptor export.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	EAvailableNetworks,
	EProtocol,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	ok
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: these tests must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65529,
		tcp: 65529,
		protocol: EProtocol.tcp
	}
};

const network = EAvailableNetworks.regtest;
const testTimeout = 60000;
const VALID_ADDRESS = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';

const makeStorage = (): { store: Map<string, unknown>; storage: TStorage } => {
	const store = new Map<string, unknown>();
	return {
		store,
		storage: {
			getData: async <K extends keyof IWalletData>(
				key: string
			): Promise<Result<IWalletData[K]>> => {
				return ok(store.get(key) as IWalletData[K]);
			},
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				store.set(key, value);
				return ok(true);
			}
		}
	};
};

const createWallet = async (
	storage: TStorage,
	name: string,
	birthdayHeight?: number
): Promise<Wallet> => {
	const res = await Wallet.create({
		mnemonic: MNEMONIC,
		name,
		network,
		storage,
		electrumOptions,
		...(birthdayHeight !== undefined ? { birthdayHeight } : {})
	});
	if (res.isErr()) throw res.error;
	return res.value;
};

describe('Per-address labels', function () {
	this.timeout(testTimeout);

	let wallet: Wallet;
	let store: Map<string, unknown>;
	let storage: TStorage;

	before(async function () {
		({ store, storage } = makeStorage());
		wallet = await createWallet(storage, 'labeltest');
	});

	after(async function () {
		await wallet?.stop();
	});

	it('rejects an invalid address', async () => {
		const res = await wallet.setAddressLabel('notanaddress', 'x');
		expect(res.isErr()).to.equal(true);
	});

	it('rejects an oversized label', async () => {
		const res = await wallet.setAddressLabel(VALID_ADDRESS, 'x'.repeat(256));
		expect(res.isErr()).to.equal(true);
	});

	it('sets, gets and lists labels', async () => {
		const res = await wallet.setAddressLabel(VALID_ADDRESS, 'exchange payout');
		if (res.isErr()) throw res.error;
		expect(wallet.getAddressLabel(VALID_ADDRESS)).to.equal('exchange payout');
		expect(wallet.listAddressLabels()).to.deep.equal({
			[VALID_ADDRESS]: 'exchange payout'
		});
	});

	it('overwrites an existing label', async () => {
		const res = await wallet.setAddressLabel(VALID_ADDRESS, 'cold storage');
		if (res.isErr()) throw res.error;
		expect(wallet.getAddressLabel(VALID_ADDRESS)).to.equal('cold storage');
	});

	it('does not repurpose the pre-existing label fields (back-compat)', () => {
		// ISendTransaction.label (user tx label) must be untouched by address
		// labels; addressLabels is its own wallet-data map.
		expect(wallet.data.transaction.label).to.equal('');
		expect(wallet.data.addressLabels).to.be.an('object');
		// listAddressLabels returns a copy, not the live map.
		const listed = wallet.listAddressLabels();
		listed[VALID_ADDRESS] = 'mutated';
		expect(wallet.getAddressLabel(VALID_ADDRESS)).to.equal('cold storage');
	});

	it('persists labels through wallet storage', async () => {
		expect(store.has('labeltest-regtest-addressLabels')).to.equal(true);
		const reloaded = await createWallet(storage, 'labeltest');
		expect(reloaded.getAddressLabel(VALID_ADDRESS)).to.equal('cold storage');
		await reloaded.stop();
	});

	it('clears a label with an empty string', async () => {
		const res = await wallet.setAddressLabel(VALID_ADDRESS, '');
		if (res.isErr()) throw res.error;
		expect(wallet.getAddressLabel(VALID_ADDRESS)).to.equal(undefined);
		expect(wallet.listAddressLabels()).to.deep.equal({});
	});
});

describe('Wallet birthday height', function () {
	this.timeout(testTimeout);

	const wallets: Wallet[] = [];
	let store: Map<string, unknown>;
	let storage: TStorage;

	before(function () {
		({ store, storage } = makeStorage());
	});

	after(async function () {
		for (const w of wallets) await w.stop();
	});

	it('defaults to 0 (unknown) when never provided', async () => {
		const w = await createWallet(storage, 'nobday');
		wallets.push(w);
		expect(w.birthdayHeight).to.equal(0);
	});

	it('rejects an invalid birthdayHeight', async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'badbday',
			network,
			storage: makeStorage().storage,
			electrumOptions,
			birthdayHeight: -5
		});
		expect(res.isErr()).to.equal(true);
	});

	it('stores and exposes the provided birthdayHeight', async () => {
		const w = await createWallet(storage, 'bday', 800000);
		wallets.push(w);
		expect(w.birthdayHeight).to.equal(800000);
		expect(store.get('bday-regtest-birthdayHeight')).to.equal(800000);
	});

	it('persists across reloads without the option', async () => {
		const w = await createWallet(storage, 'bday');
		wallets.push(w);
		expect(w.birthdayHeight).to.equal(800000);
	});

	it('never moves the birthday later (earliest wins)', async () => {
		const w = await createWallet(storage, 'bday', 900000);
		wallets.push(w);
		expect(w.birthdayHeight).to.equal(800000);
	});

	it('moves the birthday earlier when a lower height is provided', async () => {
		const w = await createWallet(storage, 'bday', 700000);
		wallets.push(w);
		expect(w.birthdayHeight).to.equal(700000);
		expect(store.get('bday-regtest-birthdayHeight')).to.equal(700000);
	});

	it('is included in the descriptor export when set', async () => {
		const w = await createWallet(storage, 'bday');
		wallets.push(w);
		const res = w.exportDescriptors();
		if (res.isErr()) throw res.error;
		expect(res.value.birthdayHeight).to.equal(700000);
	});
});
