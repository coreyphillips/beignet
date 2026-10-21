/**
 * Issue #1667: getAddressFromScriptHash, getRbfData, setupTransaction and
 * formatTransactions each merged or flattened every stored address map on
 * every call to answer "is this one of ours". They now read one index, built
 * once and rebuilt only when a stored map is replaced. These cases check that
 * the answers are the ones the merges gave, over 2,000 addresses.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum server and the
 * transaction lookups getRbfData makes are a fake.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IAddress,
	IAddresses,
	ok,
	Wallet
} from '../src';
import { ITxHash } from '../src/types/wallet';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// Neither is this wallet's. The first is the BIP173 test vector.
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
const RECIPIENT = bitcoin.payments.p2wpkh({
	hash: Buffer.alloc(20, 7),
	network: bitcoin.networks.regtest
}).address!;
const PER_SIDE = 1000;

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

/** The linear scan getAddressFromScriptHash did before the index. */
const scan = (wallet: Wallet, scriptHash: string): IAddress | undefined =>
	[
		...Object.values(wallet.data.addresses),
		...Object.values(wallet.data.changeAddresses)
	]
		.flatMap((group: IAddresses) => Object.values(group))
		.find((record) => record.scriptHash === scriptHash);

const internals = (wallet: Wallet): { _addressLookup?: object } =>
	wallet as unknown as { _addressLookup?: object };

describe('Stored address lookups read one index (#1667)', function () {
	this.timeout(120000);

	let wallet: Wallet;
	let receive: IAddress[];
	let change: IAddress[];

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			disableRefreshOnCreate: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// Sets the change address setupTransaction needs; the Electrum sync
		// fails harmlessly offline.
		await wallet.refreshWallet({});

		const gen = await wallet.generateAddresses({
			addressAmount: PER_SIDE,
			changeAddressAmount: PER_SIDE,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		wallet.data.addresses.p2wpkh = gen.value.addresses;
		wallet.data.changeAddresses.p2wpkh = gen.value.changeAddresses;
		const byIndex = (a: IAddress, b: IAddress): number => a.index - b.index;
		receive = Object.values(gen.value.addresses).sort(byIndex);
		change = Object.values(gen.value.changeAddresses).sort(byIndex);
		expect(receive).to.have.length(PER_SIDE);
		expect(change).to.have.length(PER_SIDE);
	});

	after(async () => {
		await wallet?.stop({ refreshTimeout: 1000 });
	});

	it('finds each of 2,000 addresses by script hash, as the scan did, from one build', () => {
		wallet.getAddressFromScriptHash('00'.repeat(32));
		const built = internals(wallet)._addressLookup;
		expect(built).to.not.equal(undefined);

		for (const record of [...receive, ...change]) {
			const found = wallet.getAddressFromScriptHash(record.scriptHash);
			expect(found).to.equal(record);
			expect(found).to.equal(scan(wallet, record.scriptHash));
		}
		expect(wallet.getAddressFromScriptHash('00'.repeat(32))).to.equal(
			undefined
		);
		expect(internals(wallet)._addressLookup).to.equal(built);
	});

	it('tells change addresses from receive addresses', () => {
		expect(wallet.isChangeAddress(change[PER_SIDE - 1].address)).to.equal(true);
		expect(wallet.isChangeAddress(receive[PER_SIDE - 1].address)).to.equal(
			false
		);
		expect(wallet.isChangeAddress(EXTERNAL)).to.equal(false);
	});

	it('follows a stored map that is replaced', async () => {
		const original = wallet.data.addresses.p2tr;
		try {
			const gen = await wallet.generateAddresses({
				addressAmount: 1,
				changeAddressAmount: 0,
				addressIndex: 500,
				addressType: EAddressType.p2tr
			});
			if (gen.isErr()) throw gen.error;
			const [added] = Object.values(gen.value.addresses);
			expect(wallet.getAddressFromScriptHash(added.scriptHash)).to.equal(
				undefined
			);

			wallet.data.addresses.p2tr = { ...original, ...gen.value.addresses };
			expect(wallet.getAddressFromScriptHash(added.scriptHash)).to.equal(added);

			wallet.data.addresses.p2tr = {};
			expect(wallet.getAddressFromScriptHash(added.scriptHash)).to.equal(
				undefined
			);
		} finally {
			wallet.data.addresses.p2tr = original;
		}
	});

	it('setupTransaction drops a staged output to a stored change address', async () => {
		const source = receive[10];
		await wallet.resetSendTransaction();
		const res = await wallet.transaction.setupTransaction({
			utxos: [
				{
					address: source.address,
					index: source.index,
					path: source.path,
					scriptHash: source.scriptHash,
					height: 100,
					tx_hash: '1a'.repeat(32),
					tx_pos: 0,
					value: 100_000,
					publicKey: source.publicKey
				}
			],
			outputs: [
				{ address: change[PER_SIDE - 1].address, value: 10_000, index: 0 },
				{ address: RECIPIENT, value: 20_000, index: 1 }
			]
		});
		if (res.isErr()) throw res.error;
		expect(res.value.outputs?.map(({ address }) => address)).to.deep.equal([
			RECIPIENT
		]);
	});

	describe('getRbfData', () => {
		const PARENT = '1a'.repeat(32);
		const CHILD = '2b'.repeat(32);
		const spent = (): IAddress => receive[900];

		/** CHILD spends PARENT:0, paying 50,000 sats to each address in `to`. */
		const fake = (to: string[]): void => {
			const results: Record<string, unknown> = {
				[PARENT]: {
					txid: PARENT,
					confirmations: 10,
					vout: [
						{ value: 0.002, n: 0, scriptPubKey: { address: spent().address } }
					]
				},
				[CHILD]: {
					txid: CHILD,
					confirmations: 0,
					vin: [{ txid: PARENT, vout: 0, sequence: 0xfffffffd }],
					vout: to.map((address, n) => ({
						value: 0.0005,
						n,
						scriptPubKey: { address }
					}))
				}
			};
			const electrum = wallet.electrum as unknown as {
				getTransactions: (args: { txHashes: ITxHash[] }) => Promise<unknown>;
			};
			electrum.getTransactions = async ({ txHashes }): Promise<unknown> =>
				ok({
					error: false,
					id: 0,
					method: 'getTransactions',
					network: 'regtest',
					data: txHashes.map(({ tx_hash }) => ({
						id: 0,
						jsonrpc: '2.0',
						param: tx_hash,
						data: { tx_hash },
						result: results[tx_hash]
					}))
				});
		};

		it('finds the change output and the input record among 2,000 addresses', async () => {
			const changeRecord = change[950];
			fake([RECIPIENT, changeRecord.address]);

			const res = await wallet.getRbfData({ txHash: { tx_hash: CHILD } });
			if (res.isErr()) throw res.error;
			expect(res.value.changeAddress).to.equal(changeRecord.address);
			expect(res.value.inputs).to.have.length(1);
			expect(res.value.inputs[0].path).to.equal(spent().path);
			expect(res.value.inputs[0].publicKey).to.equal(spent().publicKey);
			expect(res.value.fee).to.equal(100_000);
		});

		it('still refuses when no output belongs to the wallet', async () => {
			fake([RECIPIENT, EXTERNAL]);

			const res = await wallet.getRbfData({ txHash: { tx_hash: CHILD } });
			expect(res.isErr() && res.error.message).to.equal(
				'Unable to determine change address.'
			);
		});
	});
});
