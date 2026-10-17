import { expect } from 'chai';

import {
	EAvailableNetworks,
	getDefaultWalletDataKeys,
	getStorageKeyValues,
	getWalletDataStorageKey
} from '../src';

describe('getStorageKeyValues', () => {
	it('inverts getWalletDataStorageKey for every key, network and account', () => {
		const networks = [...new Set(Object.values(EAvailableNetworks))];
		// The wallet refuses hyphenated names, but the storage format does not.
		const names = ['wallet0', 'my-wallet', 'a-bitcoin-acct1', ''];
		for (const walletName of names) {
			for (const network of networks) {
				for (const value of getDefaultWalletDataKeys()) {
					for (const account of [0, 1, 12]) {
						const key = getWalletDataStorageKey(
							walletName,
							network,
							value,
							account
						);
						expect(getStorageKeyValues(key), key).to.deep.equal({
							walletName,
							network,
							account,
							value
						});
					}
				}
			}
		}
	});

	it('reads the account segment instead of reporting it as the key', () => {
		expect(
			getStorageKeyValues('wallet0-bitcoin-acct1-addresses')
		).to.deep.equal({
			walletName: 'wallet0',
			network: EAvailableNetworks.bitcoin,
			account: 1,
			value: 'addresses'
		});
	});

	it('returns undefined for keys getWalletDataStorageKey does not build', () => {
		for (const key of [
			'',
			'wallet0',
			'wallet0-bitcoin',
			'wallet0-mainnet-utxos',
			'wallet0-bitcoin-unknownKey',
			'wallet0-bitcoin-toString',
			'wallet0-bitcoin-acct0-utxos',
			'wallet0-bitcoin-acct01-utxos',
			'wallet0-bitcoin-acct-utxos',
			'wallet0-bitcoin-acct1',
			'wallet0-bitcoin-acct1-acct2-utxos'
		]) {
			expect(getStorageKeyValues(key), key).to.equal(undefined);
		}
	});
});
