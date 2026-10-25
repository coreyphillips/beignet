/**
 * Regression tests for issue #1810: a change to one transaction record handed
 * setData the whole history, so every write cost as much as the wallet's
 * lifetime of transactions. A storage with setTransactionChanges now gets only
 * the records that changed, and one without it still gets the whole map.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port and the
 * client helpers are a fake server.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	createEncryptedStorage,
	createMemoryStorage,
	EAddressType,
	EAvailableNetworks,
	EBoostType,
	EPaymentType,
	EProtocol,
	err,
	getWalletDataStorageKey,
	IAddress,
	IFormattedTransaction,
	IFormattedTransactions,
	IGetTransactions,
	ITransaction,
	IUtxo,
	IWalletData,
	IWalletStorage,
	ok,
	Result,
	TGetData,
	TSetData,
	TSetTransactionChanges,
	TTransactionChanges,
	TTxDetails,
	TWalletStorageKey,
	Wallet
} from '../../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NAME = 'recordchanges';
const NETWORK = EAvailableNetworks.regtest;
const TIP = 500;

// Unreachable on purpose: this test must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65524,
		tcp: 65524,
		protocol: EProtocol.tcp
	}
};

/** A stranger's transaction, funding T. */
const P = '1a'.repeat(32);
/** The one record each case changes. */
const T = '2b'.repeat(32);
/** Ninety-nine more, which no case touches unless it says so. */
const OTHERS = Array.from({ length: 99 }, (_, i) =>
	(i + 1).toString(16).padStart(64, '0')
);
const BLOCK_HASH = '0e'.repeat(32);

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

/** A record as the current version stores it: trimmed inputs, sats fields. */
const record = (txid: string, height: number): IFormattedTransaction => ({
	address: EXTERNAL,
	...(height > 0 ? { blockhash: BLOCK_HASH } : {}),
	height,
	scriptHash: 'ab'.repeat(32),
	totalInputValue: 1,
	totalInputSats: 100_000_000,
	matchedInputValue: 0,
	matchedInputSats: 0,
	totalOutputValue: 0.9999,
	totalOutputSats: 99_990_000,
	matchedOutputValue: 0.1,
	matchedOutputSats: 10_000_000,
	fee: 0.0001,
	feeSats: 10_000,
	satsPerByte: 71,
	type: EPaymentType.received,
	value: 0.1,
	valueSats: 10_000_000,
	txid,
	messages: [],
	vin: [{ txid: P, vout: 0, sequence: 0xfffffffd }],
	timestamp: 1_700_000_000_000,
	rbf: true,
	exists: true,
	vsize: 141
});

/** One hundred records, T at `height` and the rest confirmed long ago. */
const history = (height: number): IFormattedTransactions => {
	const records: IFormattedTransactions = { [T]: record(T, height) };
	OTHERS.forEach((txid, i) => {
		records[txid] = record(txid, 100 + i);
	});
	return records;
};

const copy = <V>(value: V): V =>
	value === undefined ? value : JSON.parse(JSON.stringify(value));

const flush = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));

const key = <K extends keyof IWalletData>(field: K): TWalletStorageKey<K> =>
	getWalletDataStorageKey(NAME, NETWORK, field);

type TBatch<V> = { key: string; data: V[] };

/** One write the storage double received and has not finished. */
type THeldWrite = { land: () => void };

describe('transaction record changes (#1810)', function () {
	this.timeout(60000);

	/** Each stored value's JSON. */
	const store = new Map<string, string>();
	const memory = createMemoryStorage(store);
	/** Every setData call, deep copied. */
	let writes: { key: string; value: unknown }[];
	/** Every setTransactionChanges call, deep copied. */
	let changeWrites: { key: string; changes: TTransactionChanges }[];
	/** Refuses every write of the transaction map. */
	let refuse: boolean;
	/** Holds every write of the transaction map until the test lands it. */
	let hold: boolean;
	let held: THeldWrite[];
	let wallet: Wallet | undefined;

	/** Waits its turn when `hold` is set, then refuses or applies the write. */
	const transactionWrite = (
		apply: () => Promise<Result<boolean>>
	): Promise<Result<boolean>> => {
		const finish = (): Promise<Result<boolean>> =>
			refuse ? Promise.resolve(err('storage is full')) : apply();
		if (!hold) return finish();
		return new Promise((resolve) => {
			held.push({ land: (): void => resolve(finish()) });
		});
	};

	const getData: TGetData = memory.getData;

	const setData: TSetData = async (storageKey, value) => {
		// Copied now: a held write lands what the wallet handed over, not
		// what its map holds by the time the test lands it.
		const written = copy(value);
		writes.push({ key: storageKey, value: written });
		if (storageKey !== key('transactions')) {
			return memory.setData(storageKey, written);
		}
		return transactionWrite(() => memory.setData(storageKey, written));
	};

	/** Applies each change to the stored map, as getData then returns it. */
	const setTransactionChanges: TSetTransactionChanges = async (
		storageKey,
		changes
	) => {
		const written = copy(changes);
		changeWrites.push({ key: storageKey, changes: written });
		return transactionWrite(() =>
			memory.setTransactionChanges(storageKey, written)
		);
	};

	const openWallet = async (storage: IWalletStorage): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: NAME,
			network: NETWORK,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			electrumOptions,
			// The test drives every step itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			storage
		});
		if (res.isErr()) throw res.error;
		res.value.electrum.stopConnectionPolling();
		const tip = await res.value.updateData({
			header: { height: TIP, hash: '', hex: '' }
		});
		if (tip.isErr()) throw tip.error;
		await flush();
		// What loading wrote is not under test.
		writes = [];
		changeWrites = [];
		return res.value;
	};

	/** Seeds storage with the history and opens a wallet over it. */
	const seed = async (
		height: number,
		storage: IWalletStorage = { getData, setData, setTransactionChanges }
	): Promise<Wallet> => {
		await memory.setData(key('transactions'), history(height));
		await memory.setData(key('unconfirmedTransactions'), {
			[T]: record(T, height)
		});
		wallet = await openWallet(storage);
		return wallet;
	};

	const stored = (): IFormattedTransactions =>
		JSON.parse(store.get(key('transactions'))!);

	const transactionWrites = (): unknown[] =>
		writes.filter((w) => w.key === key('transactions')).map((w) => w.value);

	/** The lookup's reply carrying these answers, for the unconfirmed check. */
	const answerCheckWith = (answer: Partial<ITransaction<IUtxo>>): void => {
		sinon.stub(wallet!.electrum, 'getTransactions').resolves(
			ok<IGetTransactions>({
				error: false,
				id: 0,
				method: 'getTransactions',
				network: 'bitcoinRegtest',
				data: [
					{
						id: 0,
						jsonrpc: '2.0',
						param: T,
						data: { tx_hash: T },
						...answer
					} as unknown as ITransaction<IUtxo>
				]
			})
		);
	};

	/** The other 99 records are stored exactly as they were seeded. */
	const expectOthersUntouched = (): void => {
		const seeded = history(0);
		for (const txid of OTHERS) {
			expect(stored()[txid], txid).to.deep.equal(seeded[txid]);
		}
	};

	beforeEach(function () {
		store.clear();
		writes = [];
		changeWrites = [];
		refuse = false;
		hold = false;
		held = [];
		wallet = undefined;
	});

	afterEach(async function () {
		hold = false;
		refuse = false;
		for (let i = 0; i < held.length; i++) {
			held[i].land();
			await flush();
		}
		sinon.restore();
		await wallet?.stop();
	});

	/**
	 * Has the fake server confirm T at the tip: its receive address history
	 * holds T, and T spends P:0 into that address.
	 */
	const confirmAtTip = async (w: Wallet): Promise<void> => {
		const gen = await w.generateAddresses({
			addressAmount: 1,
			changeAddressAmount: 1,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		const generated = await w.updateData({
			addresses: { ...w.data.addresses, p2wpkh: gen.value.addresses },
			changeAddresses: {
				...w.data.changeAddresses,
				p2wpkh: gen.value.changeAddresses
			}
		});
		if (generated.isErr()) throw generated.error;
		const receive = Object.values(gen.value.addresses)[0] as IAddress;
		const vin = (txid: string): TTxDetails['vin'][number] => ({
			txid,
			vout: 0,
			scriptSig: { asm: '', hex: '' },
			txinwitness: [],
			sequence: 0xfffffffd
		});
		const details = (
			txid: string,
			inputs: TTxDetails['vin'],
			outputs: Array<[string, number]>,
			confirmations?: number
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
				...(confirmations ? { confirmations, blockhash: BLOCK_HASH } : {}),
				vin: inputs,
				vout: outputs.map(([address, value], n) => ({
					n,
					value,
					scriptPubKey: { asm: '', hex: '', address }
				}))
			}) as TTxDetails;
		const server: Record<string, TTxDetails> = {
			[P]: details(P, [vin('ee'.repeat(32))], [[EXTERNAL, 1]], 50),
			[T]: details(
				T,
				[vin(P)],
				[
					[receive.address, 0.1],
					[EXTERNAL, 0.8999]
				],
				1
			)
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
								? [{ tx_hash: T, height: TIP }]
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
						result: server[h.tx_hash]
					}))
				})
			);
		w.electrum.connectedToElectrum = true;
		w.electrum.batchDelay = 0;
	};

	it('writes only the confirmed record, out of 100', async function () {
		const w = await seed(0);
		await confirmAtTip(w);

		const res = await w.updateTransactions({});
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);
		await flush();

		expect(w.data.transactions[T].height).to.equal(TIP);
		expect(transactionWrites(), 'no write of the whole map').to.have.length(0);
		expect(changeWrites, 'one write of changes').to.have.length(1);
		const [{ key: written, changes }] = changeWrites;
		expect(written).to.equal(key('transactions'));
		expect(Object.keys(changes.set)).to.deep.equal([T]);
		expect(changes.deleted).to.deep.equal([]);
		expect(changes.set[T].height).to.equal(TIP);

		// What a restart reads back: the whole history with the one change.
		expect(Object.keys(stored())).to.have.length(100);
		expect(stored()[T].height).to.equal(TIP);
		expectOthersUntouched();
	});

	it('still writes the whole map to storage without setTransactionChanges', async function () {
		const w = await seed(0, { getData, setData });
		await confirmAtTip(w);

		const res = await w.updateTransactions({});
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);
		await flush();

		const full = transactionWrites() as IFormattedTransactions[];
		expect(full).to.have.length(1);
		expect(Object.keys(full[0])).to.have.length(100);
		expect(full[0][T].height).to.equal(TIP);
		expect(changeWrites).to.have.length(0);
	});

	it('writes only the record a reorg took out of its block', async function () {
		const w = await seed(TIP);
		// No confirmations: back in the mempool.
		answerCheckWith({ result: { txid: T } as unknown as TTxDetails });

		const res = await w.checkUnconfirmedTransactions();
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

		expect(transactionWrites()).to.have.length(0);
		expect(changeWrites).to.have.length(1);
		const { changes } = changeWrites[0];
		expect(Object.keys(changes.set)).to.deep.equal([T]);
		expect(changes.set[T].height).to.equal(0);
		expect(changes.set[T].blockhash).to.equal(undefined);
		expect(stored()[T].height).to.equal(0);
		expectOthersUntouched();
	});

	it('writes only the record of a transaction the server lost', async function () {
		const w = await seed(TIP);
		answerCheckWith({
			error: {
				code: 2,
				message:
					'No such mempool or blockchain transaction. Use gettransaction for wallet transactions.'
			}
		} as unknown as Partial<ITransaction<IUtxo>>);
		// The rescan the ghost path fires needs a server; the record is the subject.
		sinon
			.stub(
				w as unknown as { _rescanAddresses: () => unknown },
				'_rescanAddresses'
			)
			.resolves(ok(undefined));

		const res = await w.checkUnconfirmedTransactions();
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

		expect(transactionWrites()).to.have.length(0);
		expect(changeWrites).to.have.length(1);
		const { changes } = changeWrites[0];
		expect(Object.keys(changes.set)).to.deep.equal([T]);
		expect(changes.set[T].exists).to.equal(false);
		expect(changes.set[T].height).to.equal(0);
		expect(stored()[T].exists).to.equal(false);
		expectOthersUntouched();
	});

	it('writes a ghost marking as that one record', async function () {
		const w = await seed(0);
		const res = await w.addGhostTransaction({ txid: T });
		expect(res.isOk()).to.equal(true);

		expect(transactionWrites()).to.have.length(0);
		expect(changeWrites).to.have.length(1);
		expect(Object.keys(changeWrites[0].changes.set)).to.deep.equal([T]);
		expect(stored()[T].exists).to.equal(false);
		expectOthersUntouched();
	});

	it('writes a deleted transaction as its txid alone', async function () {
		const w = await seed(0);
		const res = await w.deleteOnChainTransactionById({ txid: T });
		expect(res.isOk()).to.equal(true);

		expect(transactionWrites()).to.have.length(0);
		expect(changeWrites).to.have.length(1);
		expect(changeWrites[0].changes).to.deep.equal({ set: {}, deleted: [T] });
		expect(stored()).to.not.have.property(T);
		expect(Object.keys(stored())).to.have.length(99);
		expectOthersUntouched();
	});

	it('writes the transaction an RBF boost replaced as deleted', async function () {
		const w = await seed(0);
		const internals = w as unknown as {
			addBoostedTransaction: (args: {
				newTxId: string;
				oldTxId: string;
				type: EBoostType;
				fee: number;
			}) => Promise<Result<unknown>>;
		};
		const res = await internals.addBoostedTransaction({
			oldTxId: T,
			newTxId: '3c'.repeat(32),
			type: EBoostType.rbf,
			fee: 20_000
		});
		expect(res.isOk()).to.equal(true);

		expect(transactionWrites()).to.have.length(0);
		expect(changeWrites).to.have.length(1);
		expect(changeWrites[0].changes).to.deep.equal({ set: {}, deleted: [T] });
		expect(Object.keys(stored())).to.have.length(99);
	});

	it('carries a refused change in the next write of the map', async function () {
		const w = await seed(0);
		refuse = true;
		const refused = await w.addGhostTransaction({ txid: T });
		expect(refused.isErr()).to.equal(true);
		expect(stored()[T].exists).to.equal(true);

		refuse = false;
		const next = await w.deleteOnChainTransactionById({ txid: OTHERS[0] });
		expect(next.isOk()).to.equal(true);

		expect(changeWrites).to.have.length(2);
		expect(Object.keys(changeWrites[1].changes.set)).to.deep.equal([T]);
		expect(changeWrites[1].changes.deleted).to.deep.equal([OTHERS[0]]);
		expect(stored()[T].exists).to.equal(false);
		expect(stored()).to.not.have.property(OTHERS[0]);

		// Carried once: the write after it has only its own change.
		await w.addGhostTransaction({ txid: OTHERS[1] });
		expect(Object.keys(changeWrites[2].changes.set)).to.deep.equal([OTHERS[1]]);
		expect(changeWrites[2].changes.deleted).to.deep.equal([]);
	});

	it('carries a refused change in the write already waiting behind it', async function () {
		const w = await seed(0);
		hold = true;
		refuse = true;
		const first = w.addGhostTransaction({ txid: T });
		await flush();
		const second = w.deleteOnChainTransactionById({ txid: OTHERS[0] });
		await flush();
		expect(held, 'the second waits for the first').to.have.length(1);

		held[0].land();
		expect((await first).isErr()).to.equal(true);
		refuse = false;
		await flush();
		expect(held).to.have.length(2);
		held[1].land();
		expect((await second).isOk()).to.equal(true);

		expect(changeWrites).to.have.length(2);
		expect(Object.keys(changeWrites[1].changes.set)).to.deep.equal([T]);
		expect(changeWrites[1].changes.deleted).to.deep.equal([OTHERS[0]]);
		expect(stored()[T].exists).to.equal(false);
		expect(stored()).to.not.have.property(OTHERS[0]);
	});

	it('carries a refused change past a write to another network queued behind it', async function () {
		const w = await seed(0);
		const internals = w as unknown as {
			saveWalletDataAt: (
				key: string,
				walletDataKey: string,
				data: IFormattedTransactions
			) => Promise<Result<string>>;
		};
		hold = true;
		refuse = true;
		const first = w.addGhostTransaction({ txid: T });
		await flush();
		const second = w.deleteOnChainTransactionById({ txid: OTHERS[0] });
		// What a switchNetwork leaves queued: a write under the other key.
		const other = internals.saveWalletDataAt(
			'transactions',
			`${key('transactions')}-signet`,
			{}
		);
		await flush();

		held[0].land();
		expect((await first).isErr()).to.equal(true);
		refuse = false;
		await flush();
		expect(held).to.have.length(2);
		held[1].land();
		expect((await second).isOk()).to.equal(true);
		expect((await other).isOk()).to.equal(true);

		expect(Object.keys(changeWrites[1].changes.set)).to.deep.equal([T]);
		expect(changeWrites[1].changes.deleted).to.deep.equal([OTHERS[0]]);
		expect(stored()[T].exists).to.equal(false);
		expect(stored()).to.not.have.property(OTHERS[0]);
	});

	it('merges changes issued while a write is in flight into one write', async function () {
		const w = await seed(0);
		hold = true;
		const first = w.addGhostTransaction({ txid: T });
		await flush();
		const issued = [
			w.addGhostTransaction({ txid: OTHERS[0] }),
			w.deleteOnChainTransactionById({ txid: OTHERS[1] }),
			// Deleted after it was changed: only the deletion is left to write.
			w.deleteOnChainTransactionById({ txid: OTHERS[0] })
		];
		await flush();
		held[0].land();
		expect((await first).isOk()).to.equal(true);
		await flush();
		expect(held, 'one write followed the first').to.have.length(2);
		held[1].land();
		for (const res of await Promise.all(issued)) {
			expect(res.isOk()).to.equal(true);
		}

		expect(changeWrites).to.have.length(2);
		expect(changeWrites[1].changes.set).to.deep.equal({});
		expect([...changeWrites[1].changes.deleted].sort()).to.deep.equal(
			[OTHERS[0], OTHERS[1]].sort()
		);
		expect(Object.keys(stored())).to.have.length(98);
		expect(stored()[T].exists).to.equal(false);
	});

	it('applies changes issued behind a whole-map write to that write', async function () {
		const w = await seed(0);
		hold = true;
		const first = w.addGhostTransaction({ txid: T });
		await flush();
		const full = w.saveWalletData('transactions', w.data.transactions);
		const change = w.deleteOnChainTransactionById({ txid: OTHERS[0] });
		await flush();
		held[0].land();
		await first;
		await flush();
		held[1].land();
		expect((await full).isOk()).to.equal(true);
		expect((await change).isOk()).to.equal(true);

		expect(changeWrites, 'only the first was changes').to.have.length(1);
		const maps = transactionWrites() as IFormattedTransactions[];
		expect(maps).to.have.length(1);
		expect(maps[0]).to.not.have.property(OTHERS[0]);
		expect(Object.keys(maps[0])).to.have.length(99);
	});

	it('is not passed through createEncryptedStorage', async function () {
		const encrypted = createEncryptedStorage(
			{ getData, setData, setTransactionChanges },
			Buffer.alloc(64, 1)
		);
		expect(encrypted.setTransactionChanges).to.equal(undefined);
	});
});
