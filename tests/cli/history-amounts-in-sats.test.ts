/**
 * Issue #1692: stored transactions held their amounts only in BTC, while
 * every other wallet surface is sats, so summing balances and history was
 * off by 10^8 on one side. Each record now carries sats fields beside the
 * deprecated BTC ones, and records stored before them get them on load.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port and every
 * lookup it makes is stubbed.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	btcToSats,
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	getWalletDataStorageKey,
	IAddress,
	IFormattedTransaction,
	IGetTransactionsFromInputs,
	ITransaction,
	IUtxo,
	IWalletData,
	Msat,
	msatToSatsFloor,
	ok,
	Result,
	Sats,
	satsToMsat,
	TStorage,
	TTxDetails,
	Wallet
} from '../../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NAME = 'historysats';
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

/** P: pays 0.5 BTC to the wallet's first receive address. */
const P = '1a'.repeat(32);
/** S: the wallet's own send, spending P:0. */
const S = '2b'.repeat(32);
/** Q: a stranger's transaction, funding R. */
const Q = '3c'.repeat(32);
/** R: a stranger paying two of the wallet's addresses, spending Q:1. */
const R = '4d'.repeat(32);

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

const SATS_FIELDS = [
	['totalInputValue', 'totalInputSats'],
	['matchedInputValue', 'matchedInputSats'],
	['totalOutputValue', 'totalOutputSats'],
	['matchedOutputValue', 'matchedOutputSats'],
	['fee', 'feeSats'],
	['value', 'valueSats']
] as const;

type TSatsField = (typeof SATS_FIELDS)[number][1];

const details = (
	txid: string,
	spends: Array<[string, number]>,
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
		vin: spends.map(([prev, n]) => ({
			txid: prev,
			vout: n,
			scriptSig: { asm: '', hex: '' },
			txinwitness: [],
			sequence: 0xfffffffd
		})),
		vout: vout.map(([address, value], n) => ({
			n,
			value,
			scriptPubKey: { asm: '', hex: '', address }
		}))
	}) as TTxDetails;

const satsOf = (
	record: IFormattedTransaction
): Record<TSatsField, number | undefined> =>
	Object.fromEntries(
		SATS_FIELDS.map(([, sats]) => [sats, record[sats]])
	) as Record<TSatsField, number | undefined>;

const copy = <T>(value: T): T =>
	value === undefined ? value : JSON.parse(JSON.stringify(value));

describe('transaction amounts in sats (#1692)', function () {
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
		writes.filter((write) => write.key === key(field));

	const openWallet = async (): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: NAME,
			network: NETWORK,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			electrumOptions,
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

	describe('formatTransactions', function () {
		let A: IAddress;
		let A2: IAddress;
		let C: IAddress;

		const prevouts: Record<string, TTxDetails> = {};

		/** A transaction as the server lists it in an address's history. */
		const inHistory = (
			txid: string,
			address: IAddress,
			result: TTxDetails
		): ITransaction<IUtxo> =>
			({
				id: 0,
				jsonrpc: '2.0',
				param: txid,
				data: {
					tx_hash: txid,
					height: 0,
					address: address.address,
					scriptHash: address.scriptHash
				},
				result
			}) as unknown as ITransaction<IUtxo>;

		beforeEach(async function () {
			wallet = await openWallet();
			const gen = await wallet.generateAddresses({
				addressAmount: 2,
				changeAddressAmount: 1,
				addressType: EAddressType.p2wpkh
			});
			if (gen.isErr()) throw gen.error;
			wallet.data.addresses.p2wpkh = gen.value.addresses;
			wallet.data.changeAddresses.p2wpkh = gen.value.changeAddresses;
			const byIndex = (book: Record<string, IAddress>, i: number): IAddress =>
				Object.values(book).find((a) => a.index === i) as IAddress;
			A = byIndex(gen.value.addresses, 0);
			A2 = byIndex(gen.value.addresses, 1);
			C = byIndex(gen.value.changeAddresses, 0);

			prevouts[P] = details(P, [['ee'.repeat(32), 0]], [[A.address, 0.5]]);
			prevouts[Q] = details(
				Q,
				[['ff'.repeat(32), 0]],
				[
					[EXTERNAL, 0.3],
					[EXTERNAL, 0.4]
				]
			);
			sinon.stub(wallet.electrum, 'getTransactionsFromInputs').callsFake(
				async ({
					txHashes
				}: {
					txHashes: { tx_hash: string; vout: number }[];
				}): Promise<Result<IGetTransactionsFromInputs>> =>
					ok({
						error: false,
						id: 0,
						method: 'getTransactions',
						network: 'bitcoinRegtest',
						data: txHashes.map((h) => ({
							id: 0,
							jsonrpc: '2.0',
							param: h.tx_hash,
							data: h,
							result: prevouts[h.tx_hash]
						}))
					} as unknown as IGetTransactionsFromInputs)
			);
		});

		it('records each amount in sats beside its BTC twin', async function () {
			const send = details(
				S,
				[[P, 0]],
				[
					[EXTERNAL, 0.2],
					[C.address, 0.2999]
				]
			);
			const res = await wallet!.formatTransactions({
				transactions: [inHistory(S, C, send)]
			});
			if (res.isErr()) throw res.error;
			const record = res.value[S];

			expect(record.type).to.equal(EPaymentType.sent);
			expect(satsOf(record)).to.deep.equal({
				totalInputSats: 50_000_000,
				matchedInputSats: 50_000_000,
				totalOutputSats: 49_990_000,
				matchedOutputSats: 29_990_000,
				feeSats: 10_000,
				// What left the wallet, fee included.
				valueSats: -20_010_000
			});
			for (const [btc, sats] of SATS_FIELDS) {
				expect(record[sats], sats).to.equal(btcToSats(record[btc]));
			}
			expect(record.satsPerByte, 'sat/vB').to.equal(Math.round(10_000 / 141));
		});

		it('sums sats per output, so they are exact where the BTC sum is not', async function () {
			const receive = details(
				R,
				[[Q, 1]],
				[
					[A.address, 0.1],
					[A2.address, 0.2],
					[EXTERNAL, 0.0999]
				]
			);
			const res = await wallet!.formatTransactions({
				transactions: [inHistory(R, A, receive)]
			});
			if (res.isErr()) throw res.error;
			const record = res.value[R];

			expect(record.type).to.equal(EPaymentType.received);
			expect(record.matchedOutputValue).to.not.equal(0.3);
			expect(record.matchedOutputSats).to.equal(30_000_000);
			expect(record.valueSats).to.equal(30_000_000);
			expect(record.feeSats).to.equal(10_000);
		});
	});

	describe('records stored before the sats fields', function () {
		/** A record as versions before #1692 stored it, in BTC only. */
		const btcOnly = (
			txid: string,
			type: EPaymentType,
			value: number
		): IFormattedTransaction =>
			({
				address: EXTERNAL,
				height: 0,
				scriptHash: 'ab'.repeat(32),
				totalInputValue: 0.5,
				matchedInputValue: type === EPaymentType.sent ? 0.5 : 0,
				totalOutputValue: 0.4999,
				matchedOutputValue: type === EPaymentType.sent ? 0.2999 : 0.1,
				fee: 0.0001,
				satsPerByte: 71,
				type,
				value,
				txid,
				messages: [],
				vin: [{ txid: P, vout: 0, sequence: 0xfffffffd }],
				timestamp: 1_700_000_000_000,
				exists: true,
				vsize: 141
			}) as unknown as IFormattedTransaction;

		it('get them from their BTC fields once, on load', async function () {
			const transactions = {
				[S]: btcOnly(S, EPaymentType.sent, -0.2001),
				[R]: btcOnly(R, EPaymentType.received, 0.1)
			};
			store.set(key('transactions'), copy(transactions));
			store.set(key('unconfirmedTransactions'), { [S]: copy(transactions[S]) });

			wallet = await openWallet();
			const sent = {
				totalInputSats: 50_000_000,
				matchedInputSats: 50_000_000,
				totalOutputSats: 49_990_000,
				matchedOutputSats: 29_990_000,
				feeSats: 10_000,
				valueSats: -20_010_000
			};
			expect(satsOf(wallet.data.transactions[S])).to.deep.equal(sent);
			expect(satsOf(wallet.data.unconfirmedTransactions[S])).to.deep.equal(
				sent
			);
			expect(satsOf(wallet.data.transactions[R])).to.deep.equal({
				totalInputSats: 50_000_000,
				matchedInputSats: 0,
				totalOutputSats: 49_990_000,
				matchedOutputSats: 10_000_000,
				feeSats: 10_000,
				valueSats: 10_000_000
			});
			// The BTC fields stay as they were.
			expect(wallet.data.transactions[S].value).to.equal(-0.2001);

			expect(writesTo('transactions')).to.have.length(1);
			expect(writesTo('unconfirmedTransactions')).to.have.length(1);
			const saved = store.get(key('transactions')) as Record<
				string,
				IFormattedTransaction
			>;
			expect(satsOf(saved[S])).to.deep.equal(sent);

			// Already filled: a second load writes neither map.
			await wallet.stop();
			writes = [];
			wallet = await openWallet();
			expect(satsOf(wallet.data.transactions[S])).to.deep.equal(sent);
			expect(writesTo('transactions')).to.have.length(0);
			expect(writesTo('unconfirmedTransactions')).to.have.length(0);
		});
	});

	describe('satsToMsat and msatToSatsFloor', function () {
		it('convert between sats and msat, rounding msat down', function () {
			const sats: Sats = 1_500;
			const msat: Msat = satsToMsat(sats);
			expect(msat).to.equal(1_500_000n);
			expect(satsToMsat(0)).to.equal(0n);
			expect(satsToMsat(-2)).to.equal(-2_000n);

			expect(msatToSatsFloor(msat)).to.equal(sats);
			expect(msatToSatsFloor(1_999n)).to.equal(1);
			// Down, not toward zero.
			expect(msatToSatsFloor(-1n)).to.equal(-1);
			expect(msatToSatsFloor(-1_000n)).to.equal(-1);
			expect(msatToSatsFloor(-1_001n)).to.equal(-2);

			const max = Number.MAX_SAFE_INTEGER;
			expect(msatToSatsFloor(satsToMsat(max) + 999n)).to.equal(max);
		});

		it('refuse an amount they cannot convert exactly', function () {
			for (const sats of [0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
				expect(() => satsToMsat(sats), String(sats)).to.throw(RangeError);
			}
			expect(() =>
				msatToSatsFloor(BigInt(Number.MAX_SAFE_INTEGER + 1) * 1000n)
			).to.throw(RangeError);
			expect(() => msatToSatsFloor(2n ** 64n - 1n)).to.throw(RangeError);
		});
	});
});
