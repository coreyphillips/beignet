/**
 * Watch-only (xpub) wallet tests. Fully OFFLINE: address derivation and
 * signing guards need no Electrum connection, so the wallets point at an
 * unreachable local port and background refresh attempts fail harmlessly.
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
	Wallet,
	WatchOnlySigningError
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

// Account derivation paths assumed by watch-only wallets (regtest coin type 1).
const ACCOUNT_PATHS: { [key in EAddressType]: string } = {
	[EAddressType.p2pkh]: "m/44'/1'/0'",
	[EAddressType.p2sh]: "m/49'/1'/0'",
	[EAddressType.p2wpkh]: "m/84'/1'/0'",
	[EAddressType.p2tr]: "m/86'/1'/0'"
};

// SLIP-132 version bytes used to fabricate vpub/upub encodings in tests.
const SLIP132_VERSIONS: { [prefix: string]: number } = {
	upub: 0x044a5262,
	vpub: 0x045f1cf6
};

let root: BIP32Interface;
let fullWallet: Wallet;
const createdWallets: Wallet[] = [];

const accountXpub = (addressType: EAddressType): string => {
	return root.derivePath(ACCOUNT_PATHS[addressType]).neutered().toBase58();
};

const slip132Xpub = (addressType: EAddressType, prefix: string): string => {
	const version = SLIP132_VERSIONS[prefix];
	const slipNetwork = {
		...bitcoin.networks.regtest,
		bip32: { public: version, private: version }
	};
	const slipRoot = bip32.fromSeed(
		bip39.mnemonicToSeedSync(MNEMONIC),
		slipNetwork
	);
	return slipRoot.derivePath(ACCOUNT_PATHS[addressType]).neutered().toBase58();
};

const createWatchOnly = async (
	xpub: string,
	addressType?: EAddressType
): Promise<Wallet> => {
	const res = await Wallet.createWatchOnly({
		xpub,
		addressType,
		network,
		electrumOptions
	});
	if (res.isErr()) throw res.error;
	createdWallets.push(res.value);
	return res.value;
};

describe('Watch-Only Wallets', async function () {
	this.timeout(testTimeout);

	before(async function () {
		this.timeout(testTimeout);
		root = bip32.fromSeed(
			bip39.mnemonicToSeedSync(MNEMONIC),
			bitcoin.networks.regtest
		);
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network,
			addressType: EAddressType.p2wpkh,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		fullWallet = res.value;
		createdWallets.push(fullWallet);
	});

	after(async function () {
		await Promise.all(createdWallets.map((w) => w?.stop()));
	});

	describe('Address derivation parity with a full wallet', () => {
		const addressTypes = [
			EAddressType.p2pkh,
			EAddressType.p2sh,
			EAddressType.p2wpkh,
			EAddressType.p2tr
		];
		for (const addressType of addressTypes) {
			it(`derives byte-identical ${addressType} receive and change addresses`, async () => {
				const watchOnly = await createWatchOnly(
					accountXpub(addressType),
					addressType
				);
				expect(watchOnly.isWatchOnly).to.equal(true);
				for (const index of ['0', '1', '5', '21']) {
					const receiveFull = await fullWallet.getAddress({
						index,
						addressType,
						changeAddress: false
					});
					const receiveWatch = await watchOnly.getAddress({
						index,
						addressType,
						changeAddress: false
					});
					const changeFull = await fullWallet.getAddress({
						index,
						addressType,
						changeAddress: true
					});
					const changeWatch = await watchOnly.getAddress({
						index,
						addressType,
						changeAddress: true
					});
					expect(receiveFull).to.not.equal('');
					expect(receiveWatch).to.equal(receiveFull);
					expect(changeWatch).to.equal(changeFull);
				}
			});
		}

		it('accepts a SLIP-132 vpub and infers p2wpkh', async () => {
			const watchOnly = await createWatchOnly(
				slip132Xpub(EAddressType.p2wpkh, 'vpub')
			);
			expect(watchOnly.addressType).to.equal(EAddressType.p2wpkh);
			const address = await watchOnly.getAddress({ index: '0' });
			const expected = await fullWallet.getAddress({
				index: '0',
				addressType: EAddressType.p2wpkh
			});
			expect(address).to.equal(expected);
		});

		it('accepts a SLIP-132 upub and infers p2sh', async () => {
			const watchOnly = await createWatchOnly(
				slip132Xpub(EAddressType.p2sh, 'upub')
			);
			expect(watchOnly.addressType).to.equal(EAddressType.p2sh);
			const address = await watchOnly.getAddress({ index: '3' });
			const expected = await fullWallet.getAddress({
				index: '3',
				addressType: EAddressType.p2sh
			});
			expect(address).to.equal(expected);
		});

		it('produces the same wallet id for tpub and vpub encodings of the same account', async () => {
			const a = await createWatchOnly(
				accountXpub(EAddressType.p2wpkh),
				EAddressType.p2wpkh
			);
			const b = await createWatchOnly(slip132Xpub(EAddressType.p2wpkh, 'vpub'));
			expect(a.id).to.equal(b.id);
		});

		it('only monitors the address type of the account xpub', async () => {
			const watchOnly = await createWatchOnly(
				accountXpub(EAddressType.p2wpkh),
				EAddressType.p2wpkh
			);
			expect(watchOnly.addressTypesToMonitor).to.deep.equal([
				EAddressType.p2wpkh
			]);
		});

		it('reflects the assumed account path in address metadata', async () => {
			const watchOnly = await createWatchOnly(
				accountXpub(EAddressType.p2wpkh),
				EAddressType.p2wpkh
			);
			await watchOnly.refreshWallet({});
			const addressIndex = watchOnly.data.addressIndex[EAddressType.p2wpkh];
			expect(addressIndex.path).to.equal("m/84'/1'/0'/0/0");
			const byPath = await watchOnly.getAddressByPath({
				path: "m/84'/1'/0'/0/0"
			});
			if (byPath.isErr()) throw byPath.error;
			expect(byPath.value.address).to.equal(addressIndex.address);
		});

		it('rejects paths whose purpose does not match the account xpub', async () => {
			const watchOnly = await createWatchOnly(
				accountXpub(EAddressType.p2wpkh),
				EAddressType.p2wpkh
			);
			const res = await watchOnly.getAddressByPath({
				path: "m/44'/1'/0'/0/0"
			});
			expect(res.isErr()).to.equal(true);
		});
	});

	describe('Invalid construction', () => {
		it('rejects a wallet with neither mnemonic nor xpub', async () => {
			const res = await Wallet.create({ network, electrumOptions });
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('No mnemonic specified');
			}
		});

		it('rejects a mainnet xpub on regtest', async () => {
			const mainnetRoot = bip32.fromSeed(
				bip39.mnemonicToSeedSync(MNEMONIC),
				bitcoin.networks.bitcoin
			);
			const xpub = mainnetRoot.derivePath("m/84'/0'/0'").neutered().toBase58();
			const res = await Wallet.createWatchOnly({
				xpub,
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('does not match');
			}
		});

		it('rejects an extended PRIVATE key', async () => {
			const tprv = root.derivePath("m/84'/1'/0'").toBase58();
			const res = await Wallet.createWatchOnly({
				xpub: tprv,
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.include('PRIVATE');
			}
		});

		it('rejects an address type that conflicts with the SLIP-132 prefix', async () => {
			const res = await Wallet.createWatchOnly({
				xpub: slip132Xpub(EAddressType.p2wpkh, 'vpub'),
				addressType: EAddressType.p2pkh,
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
		});

		it('rejects garbage input', async () => {
			const res = await Wallet.createWatchOnly({
				xpub: 'vpubnotarealkey',
				network,
				electrumOptions
			});
			expect(res.isErr()).to.equal(true);
		});
	});

	describe('Signing guards', () => {
		let watchOnly: Wallet;

		before(async () => {
			watchOnly = await createWatchOnly(
				accountXpub(EAddressType.p2wpkh),
				EAddressType.p2wpkh
			);
		});

		it('send fails with the typed watch-only error', async () => {
			const res = await watchOnly.send({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				amount: 1000
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error).to.be.instanceOf(WatchOnlySigningError);
				expect(res.error.message).to.equal('watch-only wallet cannot sign');
			}
		});

		it('sendMany fails with the typed watch-only error', async () => {
			const res = await watchOnly.sendMany({
				txs: [
					{
						address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
						amount: 1000
					}
				]
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error).to.be.instanceOf(WatchOnlySigningError);
			}
		});

		it('sendMax fails with the typed watch-only error', async () => {
			const res = await watchOnly.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk'
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error).to.be.instanceOf(WatchOnlySigningError);
			}
		});

		it('sweepPrivateKey fails with the typed watch-only error', async () => {
			const res = await watchOnly.sweepPrivateKey({
				privateKey: 'cSkdqJTnvZ56deaW5PpVJPeUCAQfPV7xJocfiZxdgm9UHHmXuXzY',
				toAddress: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk'
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error).to.be.instanceOf(WatchOnlySigningError);
			}
		});

		it('getPrivateKey throws the typed watch-only error', () => {
			expect(() => watchOnly.getPrivateKey("m/84'/1'/0'/0/0")).to.throw(
				WatchOnlySigningError,
				'watch-only wallet cannot sign'
			);
		});

		it('getBip32Interface fails with the typed watch-only error', async () => {
			const res = await watchOnly.getBip32Interface();
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error).to.be.instanceOf(WatchOnlySigningError);
			}
		});

		it('createTransaction (internal signing path) fails on a watch-only wallet', async () => {
			const res = await watchOnly.transaction.createTransaction({});
			expect(res.isErr()).to.equal(true);
		});

		it('switchNetwork is rejected', async () => {
			const res = await watchOnly.switchNetwork(EAvailableNetworks.testnet);
			expect(res.isErr()).to.equal(true);
		});

		it('isValid returns false for any mnemonic', () => {
			expect(watchOnly.isValid(MNEMONIC)).to.equal(false);
		});

		it('read-only surface still works', async () => {
			expect(watchOnly.getBalance()).to.equal(0);
			expect(watchOnly.feeEstimates).to.be.an('object');
			const address = await watchOnly.getAddress({ index: '0' });
			expect(address).to.match(/^bcrt1/);
			const publicNode = watchOnly.derivePublicNode("m/84'/1'/0'/0/0");
			if (publicNode.isErr()) throw publicNode.error;
			expect(publicNode.value.publicKey.length).to.equal(33);
		});
	});
});
