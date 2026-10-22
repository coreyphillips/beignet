/**
 * Wallet.data hands out a frozen copy, and updateData is the way to change
 * the wallet's data: it copies what it is given, saves each field through the
 * wallet's write queue, reports refused saves, waits for a freeze change in
 * flight before replacing the frozen coins, and counts a new receive index as
 * unsaved until storage takes it. Fully offline (remainOffline).
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	createMemoryStorage,
	EAddressType,
	err,
	IUtxo,
	IWalletData,
	IWalletStorage,
	Network,
	TStorageWriteFailure,
	Wallet
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NAME = 'updatetest';

type TGate = {
	/** Keys whose writes wait until released, refused or not. */
	hold: (key: string) => boolean;
	/** Keys whose writes are refused at once. */
	refuse: (key: string) => boolean;
	held: ((refuse: boolean) => void)[];
	/** Every write handed to setData, with its value as JSON at that moment. */
	writes: [string, string][];
};

const gatedStorage = (
	values: Map<string, string>
): { storage: IWalletStorage; gate: TGate } => {
	const inner = createMemoryStorage(values);
	const gate: TGate = {
		hold: () => false,
		refuse: () => false,
		held: [],
		writes: []
	};
	const storage: IWalletStorage = {
		getData: inner.getData,
		setData: async (key, value) => {
			gate.writes.push([key, JSON.stringify(value)]);
			if (gate.refuse(key)) return err('storage is down');
			if (gate.hold(key)) {
				const refused = await new Promise<boolean>((resolve) =>
					gate.held.push(resolve)
				);
				if (refused) return err('storage is down');
			}
			return inner.setData(key, value);
		}
	};
	return { storage, gate };
};

const waitFor = async (condition: () => boolean): Promise<void> => {
	for (let i = 0; i < 400 && !condition(); i++) {
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	expect(condition()).to.equal(true);
};

describe('Wallet.data and updateData', function () {
	this.timeout(30000);

	let wallet: Wallet;
	let values: Map<string, string>;
	let gate: TGate;
	let failures: TStorageWriteFailure[];

	const stored = (field: keyof IWalletData): unknown =>
		JSON.parse(values.get(`${NAME}-regtest-${field}`)!);

	const utxoAt = (value: number, txid = '11'.repeat(32)): IUtxo => {
		const address = wallet.data.addressIndex[EAddressType.p2wpkh];
		return {
			address: address.address,
			index: address.index,
			path: address.path,
			scriptHash: address.scriptHash,
			height: 0,
			tx_hash: txid,
			tx_pos: 0,
			value,
			publicKey: address.publicKey
		};
	};

	beforeEach(async () => {
		values = new Map();
		const gated = gatedStorage(values);
		gate = gated.gate;
		failures = [];
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: NAME,
			network: Network.regtest,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			storage: gated.storage,
			remainOffline: true,
			electrumOptions: { net, tls },
			onMessage: (key, data) => {
				if (key === 'storageWriteFailed') {
					failures.push(data as TStorageWriteFailure);
				}
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// An offline refresh stops after deriving the first addresses.
		await wallet.refreshWallet({});
		gate.writes = [];
	});

	afterEach(async () => {
		gate.hold = (): boolean => false;
		for (const release of gate.held.splice(0)) release(false);
		await wallet.stop();
	});

	it('hands out a frozen copy that does not follow later changes', async () => {
		const before = wallet.data;
		expect(Object.isFrozen(before)).to.equal(true);
		expect(Object.isFrozen(before.utxos)).to.equal(true);
		expect(Object.isFrozen(before.addressIndex[EAddressType.p2wpkh])).to.equal(
			true
		);
		expect(() => {
			(before as IWalletData).balance = 5;
		}).to.throw(TypeError);
		expect(() => (before.utxos as IUtxo[]).push(utxoAt(1))).to.throw(TypeError);

		const res = await wallet.updateData({ balance: 5 });
		if (res.isErr()) throw res.error;
		expect(before.balance).to.equal(0);
		expect(wallet.data.balance).to.equal(5);
		expect(wallet.data).to.not.equal(wallet.data);
	});

	it('replaces the fields and saves each one', async () => {
		const utxo = utxoAt(5000);
		const res = await wallet.updateData({ utxos: [utxo], balance: 5000 });
		if (res.isErr()) throw res.error;
		expect(wallet.data.utxos).to.deep.equal([utxo]);
		expect(wallet.getBalance()).to.equal(5000);
		expect(stored('utxos')).to.deep.equal([utxo]);
		expect(stored('balance')).to.equal(5000);
	});

	it('copies the values it is given', async () => {
		const utxo = utxoAt(5000);
		const utxos = [utxo];
		const res = await wallet.updateData({ utxos });
		if (res.isErr()) throw res.error;
		utxo.value = 1;
		utxos.push(utxoAt(7, '22'.repeat(32)));
		expect(wallet.data.utxos).to.deep.equal([{ ...utxo, value: 5000 }]);
	});

	it('refuses a field IWalletData does not have, and changes nothing', async () => {
		const res = await wallet.updateData({
			balance: 7,
			notAField: 1
		} as unknown as Partial<IWalletData>);
		expect(res.isErr()).to.equal(true);
		expect(wallet.data.balance).to.equal(0);
		expect(gate.writes).to.deep.equal([]);
	});

	it('reports a refused save through its result and onMessage', async () => {
		gate.refuse = (key): boolean => key.endsWith('-balance');
		const res = await wallet.updateData({ balance: 9 });
		expect(res.isErr()).to.equal(true);
		expect(failures).to.deep.equal([
			{
				key: 'balance',
				storageKey: `${NAME}-regtest-balance`,
				error: 'storage is down'
			}
		]);
		// Memory keeps the new value, as it does for the wallet's own writes.
		expect(wallet.data.balance).to.equal(9);
	});

	it('saves behind a write already made to the field', async () => {
		gate.hold = (key): boolean => key.endsWith('-balance');
		const first = wallet.updateData({ balance: 1 });
		await waitFor(() => gate.held.length === 1);
		const second = wallet.updateData({ balance: 2 });
		gate.hold = (): boolean => false;
		gate.held[0](false);
		const results = await Promise.all([first, second]);
		for (const res of results) if (res.isErr()) throw res.error;
		expect(
			gate.writes
				.filter(([key]) => key.endsWith('-balance'))
				.map(([, value]) => value)
		).to.deep.equal(['1', '2']);
		expect(stored('balance')).to.equal(2);
	});

	it('waits for an unfreeze in flight before replacing blacklistedUtxos', async () => {
		const utxo = utxoAt(5000);
		const funded = await wallet.updateData({ utxos: [utxo], balance: 5000 });
		if (funded.isErr()) throw funded.error;
		const frozen = await wallet.freezeUtxo({ txid: utxo.tx_hash, vout: 0 });
		if (frozen.isErr()) throw frozen.error;

		gate.hold = (key): boolean => key.endsWith('-blacklistedUtxos');
		const unfreezing = wallet.unfreezeUtxo({ txid: utxo.tx_hash, vout: 0 });
		await waitFor(() => gate.held.length === 1);
		const replacing = wallet.updateData({ blacklistedUtxos: [] });
		gate.hold = (): boolean => false;
		// Storage refuses the unfreeze, which then puts the coin back.
		gate.held[0](true);

		expect((await unfreezing).isErr()).to.equal(true);
		const replaced = await replacing;
		if (replaced.isErr()) throw replaced.error;
		// Applied after the rollback, so the coin the unfreeze put back is
		// replaced too, in memory and in storage alike.
		expect(wallet.listFrozenUtxos()).to.deep.equal([]);
		expect(stored('blacklistedUtxos')).to.deep.equal([]);
	});

	it('counts a new receive index as unsaved until storage takes it', async () => {
		const generated = await wallet.generateAddresses({
			addressAmount: 1,
			changeAddressAmount: 0,
			addressIndex: 3,
			addressType: EAddressType.p2wpkh
		});
		if (generated.isErr()) throw generated.error;
		const next = Object.values(generated.value.addresses)[0];
		const addressIndex = {
			...wallet.data.addressIndex,
			[EAddressType.p2wpkh]: next
		};

		gate.refuse = (key): boolean => key.endsWith('-addressIndex');
		const res = await wallet.updateData({ addressIndex });
		expect(res.isErr()).to.equal(true);
		expect(failures.map(({ key }) => key)).to.deep.equal(['addressIndex']);

		gate.refuse = (): boolean => false;
		const receive = await wallet.getReceiveAddress({});
		if (receive.isErr()) throw receive.error;
		expect(receive.value).to.equal(next.address);
		const index = stored('addressIndex') as IWalletData['addressIndex'];
		expect(index[EAddressType.p2wpkh].index).to.equal(3);
	});
});
