/**
 * createMemoryStorage implements IWalletStorage: a key never written reads as
 * ok(undefined), a read hands back a copy of what was written, and changes to
 * the transaction map apply to the stored map. A wallet over it loads what an
 * earlier wallet saved. Fully offline (remainOffline).
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	createMemoryStorage,
	IFormattedTransaction,
	IFormattedTransactions,
	Network,
	Wallet
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const record = (txid: string): IFormattedTransaction =>
	({ txid, height: 0 }) as unknown as IFormattedTransaction;

describe('createMemoryStorage', () => {
	it('reads a key it never stored as ok(undefined)', async () => {
		const storage = createMemoryStorage();
		const res = await storage.getData<'utxos'>('mem-regtest-utxos');
		if (res.isErr()) throw res.error;
		expect(res.value).to.equal(undefined);
	});

	it('hands back a copy of what was written', async () => {
		const storage = createMemoryStorage();
		const key = 'mem-regtest-addressLabels';
		const labels = { bcrt1qfirst: 'rent' };
		await storage.setData<'addressLabels'>(key, labels);
		labels.bcrt1qfirst = 'changed after the write';

		const first = await storage.getData<'addressLabels'>(key);
		if (first.isErr()) throw first.error;
		expect(first.value).to.deep.equal({ bcrt1qfirst: 'rent' });
		first.value!.bcrt1qfirst = 'changed after the read';

		const second = await storage.getData<'addressLabels'>(key);
		if (second.isErr()) throw second.error;
		expect(second.value).to.deep.equal({ bcrt1qfirst: 'rent' });
	});

	it('applies transaction changes to the stored map', async () => {
		const storage = createMemoryStorage();
		const key = 'mem-regtest-transactions';
		await storage.setData<'transactions'>(key, {
			aa: record('aa'),
			bb: record('bb')
		});
		await storage.setTransactionChanges(key, {
			set: { cc: record('cc'), aa: { ...record('aa'), height: 7 } },
			deleted: ['bb']
		});
		const res = await storage.getData<'transactions'>(key);
		if (res.isErr()) throw res.error;
		expect(res.value).to.deep.equal({
			aa: { ...record('aa'), height: 7 },
			cc: record('cc')
		});
	});

	it('starts a missing transaction map from empty', async () => {
		const storage = createMemoryStorage();
		const key = 'mem-regtest-transactions';
		await storage.setTransactionChanges(key, {
			set: { aa: record('aa') },
			deleted: ['bb']
		});
		const res = await storage.getData<'transactions'>(key);
		if (res.isErr()) throw res.error;
		expect(res.value).to.deep.equal({ aa: record('aa') });
	});

	it('keeps each value as JSON in the map it was given', async () => {
		const values = new Map([['mem-regtest-balance', '21']]);
		const storage = createMemoryStorage(values);
		const seeded = await storage.getData<'balance'>('mem-regtest-balance');
		if (seeded.isErr()) throw seeded.error;
		expect(seeded.value).to.equal(21);

		const transactions: IFormattedTransactions = { aa: record('aa') };
		await storage.setData<'transactions'>(
			'mem-regtest-transactions',
			transactions
		);
		expect(values.get('mem-regtest-transactions')).to.equal(
			JSON.stringify(transactions)
		);
	});
});

describe('a wallet over createMemoryStorage', function () {
	this.timeout(30000);

	it('loads what an earlier wallet saved', async () => {
		const storage = createMemoryStorage();
		const params = {
			mnemonic: MNEMONIC,
			name: 'memreload',
			network: Network.regtest,
			storage,
			remainOffline: true,
			electrumOptions: { net, tls }
		};
		const first = await Wallet.create(params);
		if (first.isErr()) throw first.error;
		const label = await first.value.setAddressLabel(
			'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
			'savings'
		);
		if (label.isErr()) throw label.error;
		const updated = await first.value.updateData({ balance: 1234 });
		if (updated.isErr()) throw updated.error;
		await first.value.stop();

		const second = await Wallet.create(params);
		if (second.isErr()) throw second.error;
		try {
			expect(second.value.data.balance).to.equal(1234);
			expect(
				second.value.getAddressLabel(
					'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
				)
			).to.equal('savings');
		} finally {
			await second.value.stop();
		}
	});
});
