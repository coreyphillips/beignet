/**
 * Regression test for issue #1662: each formatted transaction kept the raw
 * vin array from Electrum, every input's scriptSig and witness included, and
 * the whole map is written on every change.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port and the
 * client helpers are a fake server.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	getWalletDataStorageKey,
	IAddress,
	IFormattedTransaction,
	IWalletData,
	ok,
	Result,
	TStorage,
	TTxDetails,
	Wallet
} from '../../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NAME = 'recordinputs';
const NETWORK = EAvailableNetworks.regtest;

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

/** A stranger's transaction, funding T. */
const P = '1a'.repeat(32);
/** Unconfirmed: pays the wallet from P:0. */
const T = '2b'.repeat(32);
/** A coinbase paying the wallet, as mining to it on regtest does. */
const C = '3c'.repeat(32);

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

const SIGNATURE = `30440220${'ab'.repeat(32)}0220${'cd'.repeat(32)}01`;
const PUBKEY = `02${'ef'.repeat(32)}`;

const spending = (txid: string, vout: number): TTxDetails['vin'][number] => ({
	txid,
	vout,
	scriptSig: {
		asm: `${SIGNATURE} ${PUBKEY}`,
		hex: `47${SIGNATURE}21${PUBKEY}`
	},
	txinwitness: [SIGNATURE, PUBKEY],
	sequence: 0xfffffffd
});

const coinbase = (): TTxDetails['vin'][number] => ({
	coinbase: '03a08601',
	txinwitness: ['00'.repeat(32)],
	sequence: 0xffffffff
});

const details = (
	txid: string,
	vin: TTxDetails['vin'],
	vout: Array<[string, number]>
): TTxDetails =>
	({
		txid,
		hash: txid,
		hex: '00',
		locktime: 0,
		size: 222,
		vsize: 141,
		weight: 561,
		version: 2,
		vin,
		vout: vout.map(([address, value], n) => ({
			n,
			value,
			scriptPubKey: { asm: '', hex: '', address }
		}))
	}) as TTxDetails;

/** A record as versions before #1662 stored it, raw inputs and all. */
const untrimmedRecord = (
	txid: string,
	vin: TTxDetails['vin']
): IFormattedTransaction =>
	({
		address: EXTERNAL,
		height: 0,
		scriptHash: 'ab'.repeat(32),
		totalInputValue: 0.5,
		matchedInputValue: 0,
		totalOutputValue: 0.4999,
		matchedOutputValue: 0.1,
		fee: 0.0001,
		satsPerByte: 71,
		type: EPaymentType.received,
		value: 0.1,
		txid,
		messages: [],
		vin,
		timestamp: 1_700_000_000_000,
		rbf: true,
		exists: true,
		vsize: 141
	}) as unknown as IFormattedTransaction;

const copy = <T>(value: T): T =>
	value === undefined ? value : JSON.parse(JSON.stringify(value));

type TBatch<T> = { key: string; data: T[] };

describe('stored transaction inputs (#1662)', function () {
	this.timeout(60000);

	let store: Map<string, unknown>;
	let writes: { key: string; value: unknown }[];
	let wallet: Wallet | undefined;

	const storage: TStorage = {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> =>
			ok(copy(store.get(key)) as IWalletData[K]),
		setData: async <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			writes.push({ key, value: copy(value) });
			store.set(key, copy(value));
			return ok(true);
		}
	};

	const key = (field: keyof IWalletData): string =>
		getWalletDataStorageKey(NAME, NETWORK, field);

	const writesTo = (field: keyof IWalletData): unknown[] =>
		writes.filter((write) => write.key === key(field)).map((w) => w.value);

	const openWallet = async (): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: NAME,
			network: NETWORK,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			electrumOptions,
			// The test drives the refresh itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			storage
		});
		if (res.isErr()) throw res.error;
		res.value.electrum.stopConnectionPolling();
		return res.value;
	};

	beforeEach(function () {
		store = new Map();
		writes = [];
		wallet = undefined;
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('stores each input as its outpoint and sequence, or its coinbase marker', async function () {
		wallet = await openWallet();
		const gen = await wallet.generateAddresses({
			addressAmount: 1,
			changeAddressAmount: 1,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		wallet.data.addresses.p2wpkh = gen.value.addresses;
		wallet.data.changeAddresses.p2wpkh = gen.value.changeAddresses;
		const receive = Object.values(gen.value.addresses)[0] as IAddress;

		const transactions: Record<string, TTxDetails> = {
			[P]: details(P, [spending('ee'.repeat(32), 0)], [[EXTERNAL, 1]]),
			[T]: details(
				T,
				[spending(P, 0)],
				[
					[receive.address, 0.1],
					[EXTERNAL, 0.8999]
				]
			),
			[C]: details(C, [coinbase()], [[receive.address, 50]])
		};
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => ({
					error: false,
					data: scriptHashes.data.map((a) => ({
						data: a,
						param: a.scriptHash,
						result:
							a.scriptHash === receive.scriptHash
								? [
										{ tx_hash: T, height: 0 },
										{ tx_hash: C, height: 0 }
								  ]
								: []
					}))
				})
			);
		sinon
			.stub(electrumHelpers, 'getTransactions')
			.callsFake(
				async ({ txHashes }: { txHashes: TBatch<{ tx_hash: string }> }) => ({
					error: false,
					data: txHashes.data.map((h) => ({
						id: 0,
						jsonrpc: '2.0',
						param: h.tx_hash,
						data: h,
						result: transactions[h.tx_hash]
					}))
				})
			);
		wallet.electrum.connectedToElectrum = true;
		wallet.electrum.batchDelay = 0;

		const res = await wallet.updateTransactions({});
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

		expect(wallet.data.transactions[T]?.vin).to.deep.equal([
			{ txid: P, vout: 0, sequence: 0xfffffffd }
		]);
		expect(wallet.data.transactions[C]?.vin).to.deep.equal([
			{ coinbase: '03a08601', sequence: 0xffffffff }
		]);
		// What the formatter still reads from the inputs it was given.
		expect(wallet.data.transactions[T]?.rbf).to.equal(true);
		expect(wallet.data.transactions[T]?.type).to.equal(EPaymentType.received);

		const saved = writesTo('transactions');
		expect(saved, 'one save of the new records').to.have.length(1);
		const json = JSON.stringify(saved[0]);
		expect(json).to.not.include('scriptSig');
		expect(json).to.not.include('txinwitness');
		expect(json).to.not.include(PUBKEY);
	});

	it('trims records stored with raw inputs once, on load', async function () {
		const transactions = {
			[T]: untrimmedRecord(T, [spending(P, 0), spending(P, 1)]),
			[C]: untrimmedRecord(C, [coinbase()])
		};
		store.set(key('transactions'), copy(transactions));
		store.set(key('unconfirmedTransactions'), { [T]: copy(transactions[T]) });

		wallet = await openWallet();
		const trimmedT = [
			{ txid: P, vout: 0, sequence: 0xfffffffd },
			{ txid: P, vout: 1, sequence: 0xfffffffd }
		];
		expect(wallet.data.transactions[T].vin).to.deep.equal(trimmedT);
		expect(wallet.data.transactions[C].vin).to.deep.equal([
			{ coinbase: '03a08601', sequence: 0xffffffff }
		]);
		expect(wallet.data.unconfirmedTransactions[T].vin).to.deep.equal(trimmedT);
		// Only the inputs change.
		expect({ ...wallet.data.transactions[T], vin: undefined }).to.deep.equal({
			...transactions[T],
			vin: undefined
		});

		expect(writesTo('transactions')).to.have.length(1);
		expect(writesTo('unconfirmedTransactions')).to.have.length(1);
		for (const field of ['transactions', 'unconfirmedTransactions'] as const) {
			const json = JSON.stringify(store.get(key(field)));
			expect(json, field).to.not.include('scriptSig');
			expect(json, field).to.not.include('txinwitness');
		}

		// Already trimmed: a second load writes neither map.
		await wallet.stop();
		writes = [];
		wallet = await openWallet();
		expect(wallet.data.transactions[T].vin).to.deep.equal(trimmedT);
		expect(writesTo('transactions')).to.have.length(0);
		expect(writesTo('unconfirmedTransactions')).to.have.length(0);
	});
});
