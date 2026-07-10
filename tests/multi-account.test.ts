/**
 * Multi-account wallet tests. Fully OFFLINE: address derivation is local and
 * the wallets point at an unreachable Electrum port.
 *
 * Two Wallet instances over the same mnemonic + storage but different
 * accounts must derive from m/purpose'/coin'/ACCOUNT' and use disjoint
 * storage keys.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	getWalletDataStorageKey,
	ok
} from '../src';

const bip32 = BIP32Factory(ecc);

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

const expectedP2wpkhAddress = (
	root: BIP32Interface,
	account: number,
	change: number,
	index: number
): string => {
	const node = root.derivePath(`m/84'/1'/${account}'/${change}/${index}`);
	const { address } = bitcoin.payments.p2wpkh({
		pubkey: node.publicKey,
		network: bitcoin.networks.regtest
	});
	return address!;
};

describe('Multi-account support', function () {
	this.timeout(testTimeout);

	let root: BIP32Interface;
	let store: Map<string, unknown>;
	let storage: TStorage;
	let wallet0: Wallet;
	let wallet1: Wallet;

	before(async function () {
		root = bip32.fromSeed(
			bip39.mnemonicToSeedSync(MNEMONIC),
			bitcoin.networks.regtest
		);
		({ store, storage } = makeStorage());
		const res0 = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'accttest',
			network,
			storage,
			electrumOptions
		});
		if (res0.isErr()) throw res0.error;
		wallet0 = res0.value;
		await wallet0.refreshWallet({});
		const res1 = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'accttest',
			network,
			storage,
			electrumOptions,
			account: 1
		});
		if (res1.isErr()) throw res1.error;
		wallet1 = res1.value;
		await wallet1.refreshWallet({});
	});

	after(async function () {
		await wallet0?.stop();
		await wallet1?.stop();
	});

	it('rejects invalid account indexes', async () => {
		for (const account of [-1, 1.5]) {
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				network,
				storage: makeStorage().storage,
				electrumOptions,
				account
			});
			expect(res.isErr(), `account ${account} should be rejected`).to.equal(
				true
			);
		}
	});

	it('exposes the account index', () => {
		expect(wallet0.account).to.equal(0);
		expect(wallet1.account).to.equal(1);
	});

	it('derives account 0 exactly as before (back-compat vector)', () => {
		const stored = wallet0.data.addressIndex[EAddressType.p2wpkh];
		expect(stored.path).to.equal("m/84'/1'/0'/0/0");
		expect(stored.address).to.equal(expectedP2wpkhAddress(root, 0, 0, 0));
	});

	it('derives account 1 from m/84h/1h/1h', () => {
		const stored = wallet1.data.addressIndex[EAddressType.p2wpkh];
		expect(stored.path).to.equal("m/84'/1'/1'/0/0");
		expect(stored.address).to.equal(expectedP2wpkhAddress(root, 1, 0, 0));
		expect(stored.address).to.not.equal(
			wallet0.data.addressIndex[EAddressType.p2wpkh].address
		);
	});

	it('derives change addresses per account', () => {
		const change0 = wallet0.data.changeAddressIndex[EAddressType.p2wpkh];
		const change1 = wallet1.data.changeAddressIndex[EAddressType.p2wpkh];
		expect(change0.address).to.equal(expectedP2wpkhAddress(root, 0, 1, 0));
		expect(change1.address).to.equal(expectedP2wpkhAddress(root, 1, 1, 0));
	});

	it('getAddress threads the account through arbitrary indexes', async () => {
		const addr0 = await wallet0.getAddress({ index: '7' });
		const addr1 = await wallet1.getAddress({ index: '7' });
		expect(addr0).to.equal(expectedP2wpkhAddress(root, 0, 0, 7));
		expect(addr1).to.equal(expectedP2wpkhAddress(root, 1, 0, 7));
	});

	it('uses disjoint storage keys per account', () => {
		expect(
			getWalletDataStorageKey('accttest', network, 'addressIndex', 0)
		).to.equal('accttest-regtest-addressIndex');
		expect(
			getWalletDataStorageKey('accttest', network, 'addressIndex', 1)
		).to.equal('accttest-regtest-acct1-addressIndex');
		expect(store.has('accttest-regtest-addressIndex')).to.equal(true);
		expect(store.has('accttest-regtest-acct1-addressIndex')).to.equal(true);
	});

	it('keeps the two accounts isolated in storage', async () => {
		// A label saved on account 1 must not leak into account 0.
		const address = wallet1.data.addressIndex[EAddressType.p2wpkh].address;
		const res = await wallet1.setAddressLabel(address, 'account one');
		if (res.isErr()) throw res.error;
		expect(wallet1.getAddressLabel(address)).to.equal('account one');
		expect(wallet0.getAddressLabel(address)).to.equal(undefined);
		expect(store.get('accttest-regtest-acct1-addressLabels')).to.deep.equal({
			[address]: 'account one'
		});
		expect(store.get('accttest-regtest-addressLabels') ?? {}).to.deep.equal({});
	});

	it('coexists: both instances keep working after interleaved use', async () => {
		const again0 = await wallet0.getAddress({ index: '0' });
		const again1 = await wallet1.getAddress({ index: '0' });
		expect(again0).to.equal(expectedP2wpkhAddress(root, 0, 0, 0));
		expect(again1).to.equal(expectedP2wpkhAddress(root, 1, 0, 0));
	});

	it('exports account-specific descriptors', () => {
		const res = wallet1.exportDescriptors();
		if (res.isErr()) throw res.error;
		expect(res.value.account).to.equal(1);
		const p2wpkh = res.value.descriptors.find(
			(d) => d.addressType === EAddressType.p2wpkh
		);
		expect(p2wpkh).to.not.equal(undefined);
		const expectedXpub = root.derivePath("m/84'/1'/1'").neutered().toBase58();
		expect(p2wpkh!.external).to.contain('/84h/1h/1h]');
		expect(p2wpkh!.external).to.contain(expectedXpub);
	});
});
