/**
 * sendMany and buildPsbt build from the coins they priced (#1360, #1431).
 * Fully OFFLINE: the wallet points at an unreachable Electrum port, UTXOs are
 * injected into wallet data, and nothing is broadcast.
 *
 * With any coinSelectPreference but consolidate, updateFee priced the subset
 * autoCoinSelect picks, while createTransaction and createUnsignedPsbt built
 * from every staged UTXO.
 * The change output absorbed the extra inputs and the transaction went out at
 * about half the requested rate.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import {
	address as bitcoinAddress,
	networks,
	Transaction as BitcoinTransaction
} from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	ECoinSelectPreference,
	EProtocol,
	IUtxo,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	ok
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
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

const RECIPIENT = bitcoinAddress.toBech32(Buffer.alloc(20, 3), 0, 'bcrt');

/** An in-memory TStorage, so the wallet has somewhere to persist. */
const memoryStorage = (): TStorage => {
	const store = new Map<string, unknown>();
	return {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> => ok(store.get(key) as IWalletData[K]),
		setData: async <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			store.set(key, value);
			return ok(true);
		}
	};
};

describe('sendMany coin selection (#1360)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	const injected = new Map<string, number>();

	/** Fabricates a UTXO paying to the wallet's own index-0 address. */
	const injectUtxo = (txid: string, value: number): IUtxo => {
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		if (!source?.address) throw new Error('No derived address available.');
		const utxo: IUtxo = {
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 0,
			tx_hash: txid,
			tx_pos: 0,
			value,
			publicKey: source.publicKey
		};
		wallet.data.utxos.push(utxo);
		wallet.data.balance += value;
		injected.set(txid, value);
		return utxo;
	};

	/** Fee paid by a built transaction whose inputs are all injected UTXOs. */
	const feeOf = (tx: BitcoinTransaction): number => {
		const inputTotal = tx.ins.reduce((sum, input) => {
			const txid = Buffer.from(input.hash).reverse().toString('hex');
			const value = injected.get(txid);
			if (value === undefined) throw new Error(`Unknown input ${txid}.`);
			return sum + value;
		}, 0);
		const outputTotal = tx.outs.reduce((sum, output) => sum + output.value, 0);
		return inputTotal - outputTotal;
	};

	beforeEach(async function () {
		injected.clear();
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'sendcoinselect',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			storage: memoryStorage(),
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		for (let i = 1; i <= 5; i++) {
			injectUtxo(i.toString(16).padStart(2, '0').repeat(32), 10_000);
		}
	});

	afterEach(async function () {
		await wallet?.stop();
	});

	const send = async (): Promise<BitcoinTransaction> => {
		const res = await wallet.send({
			address: RECIPIENT,
			amount: 15_000,
			satsPerByte: 10,
			broadcast: false
		});
		if (res.isErr()) throw res.error;
		return BitcoinTransaction.fromHex(res.value);
	};

	it('spends only the selected coins and pays the requested rate', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.small);

		const tx = await send();

		expect(tx.ins).to.have.length(2);
		expect(wallet.transaction.data.inputs).to.have.length(2);
		expect(feeOf(tx)).to.equal(wallet.transaction.data.fee);
		expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
	});

	it('still spends every coin under consolidate', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.consolidate);

		const tx = await send();

		expect(tx.ins).to.have.length(5);
		expect(feeOf(tx)).to.equal(wallet.transaction.data.fee);
		expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
	});

	it('builds a PSBT from the selected coins at the requested rate (#1431)', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.small);

		const built = await wallet.buildPsbt({
			address: RECIPIENT,
			amount: 15_000,
			satsPerByte: 10
		});
		if (built.isErr()) throw built.error;
		const signed = wallet.signPsbtWithOurKey(built.value.psbtBase64);
		if (signed.isErr()) throw signed.error;
		const imported = wallet.importSignedPsbt(signed.value);
		if (imported.isErr()) throw imported.error;
		const tx = BitcoinTransaction.fromHex(imported.value.txHex);

		expect(tx.ins).to.have.length(2);
		expect(built.value.inputs).to.have.length(2);
		expect(feeOf(tx)).to.equal(built.value.fee);
		expect(feeOf(tx) / tx.virtualSize()).to.be.at.least(10);
	});

	for (const twoRecipientsFirst of [false, true]) {
		it(`keeps each concurrent PSBT build on its own recipients (${
			twoRecipientsFirst ? 'two-recipient' : 'one-recipient'
		} build first, #1464)`, async function () {
			wallet.updateCoinSelectPreference(ECoinSelectPreference.small);
			const [a, b, c] = [4, 5, 6].map((fill) =>
				bitcoinAddress.toBech32(Buffer.alloc(20, fill), 0, 'bcrt')
			);
			const buildOne = (): ReturnType<Wallet['buildPsbt']> =>
				wallet.buildPsbt({ address: a, amount: 10_000, satsPerByte: 2 });
			const buildTwo = (): ReturnType<Wallet['buildPsbt']> =>
				wallet.buildPsbt({
					txs: [
						{ address: b, amount: 5_000 },
						{ address: c, amount: 6_000 }
					],
					satsPerByte: 2
				});

			const [one, two] = twoRecipientsFirst
				? (await Promise.all([buildTwo(), buildOne()])).reverse()
				: await Promise.all([buildOne(), buildTwo()]);
			if (one.isErr()) throw one.error;
			if (two.isErr()) throw two.error;
			// What the signed transaction pays, not just what the build reports.
			const paid = (psbtBase64: string): string[] => {
				const signed = wallet.signPsbtWithOurKey(psbtBase64);
				if (signed.isErr()) throw signed.error;
				const imported = wallet.importSignedPsbt(signed.value);
				if (imported.isErr()) throw imported.error;
				return BitcoinTransaction.fromHex(imported.value.txHex)
					.outs.map(({ script, value }) => ({
						address: bitcoinAddress.fromOutputScript(script, networks.regtest),
						value
					}))
					.filter(({ address }) => [a, b, c].includes(address))
					.map(({ address, value }) => `${address}:${value}`)
					.sort();
			};

			expect(paid(one.value.psbtBase64)).to.deep.equal([`${a}:10000`]);
			expect(paid(two.value.psbtBase64)).to.deep.equal(
				[`${b}:5000`, `${c}:6000`].sort()
			);
		});
	}

	it('leaves every coin to a concurrent PSBT build', async function () {
		wallet.updateCoinSelectPreference(ECoinSelectPreference.small);

		const [first, second] = await Promise.all([
			wallet.buildPsbt({ address: RECIPIENT, amount: 15_000, satsPerByte: 2 }),
			wallet.buildPsbt({ address: RECIPIENT, amount: 35_000, satsPerByte: 2 })
		]);
		if (first.isErr()) throw first.error;
		if (second.isErr()) throw second.error;

		expect(first.value.inputs).to.have.length(2);
		expect(second.value.inputs).to.have.length(4);
	});
});
