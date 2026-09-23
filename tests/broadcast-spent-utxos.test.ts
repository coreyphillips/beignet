/**
 * Regression tests for issue #784: a coin an ordinary send had spent stayed in
 * listUtxos() long enough for the next coin selection to pick it. Nothing
 * dropped the inputs at broadcast time, and the UTXO set is only ever replaced
 * wholesale by a scan, which arrives on a notification at best.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port, UTXOs are
 * injected straight into wallet data, and the rn-electrum-client helpers the
 * broadcast path calls are stubbed.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

// The raw module.exports object: the compiled namespace import in src/electrum
// reads it live through getter bindings, while this file's own namespace copy
// would be non-writable and invisible to src.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IGetUtxosResponse,
	ILogger,
	IUtxo,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	decodeRawTransaction,
	err,
	ok
} from '../src';

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

const TXID_A = '11'.repeat(32);
const TXID_B = '22'.repeat(32);
const TXID_FOREIGN = '33'.repeat(32);
const BROADCAST_TXID = '44'.repeat(32);
const TXID_C = '55'.repeat(32);
const EXTERNAL_ADDRESS = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';

const makeStorage = (): TStorage => {
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

/** Copies a stored value the way a serializing adapter (SQLite) would. */
const clone = <T>(value: T): T =>
	value === undefined ? value : JSON.parse(JSON.stringify(value));

/**
 * Same, but copying on every read and write, so the store never aliases a
 * wallet array, with writes that can be refused per key (the part of the
 * storage key after the wallet name and network) and a hook that holds the
 * next write to a key until the test releases it. A held write has already
 * passed the refusal check and copied its value, as an adapter that
 * serializes on the call would have.
 */
const makeFailableStorage = (): {
	store: Map<string, unknown>;
	storage: TStorage;
	fail: { keys: string[] };
	holdNext: (key: string) => () => void;
} => {
	const store = new Map<string, unknown>();
	const fail = { keys: [] as string[] };
	const holds = new Map<string, Promise<void>>();
	const matches = (storageKey: string, key: string): boolean =>
		storageKey.endsWith(`-${key}`);
	return {
		store,
		fail,
		holdNext: (key: string): (() => void) => {
			let release!: () => void;
			holds.set(
				key,
				new Promise<void>((resolve) => {
					release = resolve;
				})
			);
			return release;
		},
		storage: {
			getData: async <K extends keyof IWalletData>(
				key: string
			): Promise<Result<IWalletData[K]>> =>
				ok(clone(store.get(key)) as IWalletData[K]),
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (fail.keys.some((k) => matches(key, k))) {
					return err('storage is down');
				}
				const copy = clone(value);
				const held = [...holds].find(([k]) => matches(key, k));
				if (held) {
					holds.delete(held[0]);
					await held[1];
				}
				store.set(key, copy);
				return ok(true);
			}
		}
	};
};

/** Fabricates a UTXO paying to one of the wallet's own derived addresses. */
const injectUtxo = (
	wallet: Wallet,
	txid: string,
	value: number,
	addressIndex = 0
): IUtxo => {
	const source =
		addressIndex === 0
			? wallet.data.addressIndex[EAddressType.p2wpkh]
			: Object.values(wallet.data.addresses[EAddressType.p2wpkh]).find(
					(a) => a.index === addressIndex
			  );
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
	return utxo;
};

/** An unsigned transaction spending the given outpoints. Nothing validates it:
 *  the broadcast is stubbed and only the inputs are read. */
const txSpending = (outpoints: IUtxo[]): string => {
	const tx = new bitcoin.Transaction();
	for (const outpoint of outpoints) {
		tx.addInput(
			Buffer.from(outpoint.tx_hash, 'hex').reverse(),
			outpoint.tx_pos
		);
	}
	tx.addOutput(
		bitcoin.address.toOutputScript(EXTERNAL_ADDRESS, bitcoin.networks.regtest),
		1000
	);
	return tx.toHex();
};

const outpoints = (utxos: IUtxo[]): string[] =>
	utxos.map((utxo) => `${utxo.tx_hash}:${utxo.tx_pos}`);

/** Yields to the event loop until the condition holds. */
const waitFor = async (condition: () => boolean): Promise<void> => {
	for (let i = 0; i < 200 && !condition(); i++) {
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	if (!condition()) throw new Error('Condition never held.');
};

describe('Broadcast drops the coins it spends', function () {
	this.timeout(testTimeout);

	let wallet: Wallet;
	let utxoA: IUtxo;
	let utxoB: IUtxo;
	let broadcast: sinon.SinonStub;

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'spentutxos',
			network,
			storage: makeStorage(),
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		utxoA = injectUtxo(wallet, TXID_A, 60000);
		utxoB = injectUtxo(wallet, TXID_B, 40000, 1);
		broadcast = sinon
			.stub(electrumHelpers, 'broadcastTransaction')
			.resolves({ error: false, data: BROADCAST_TXID });
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.resolves({ error: false, data: '' });
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('drops the inputs an ordinary send spends', async () => {
		const res = await wallet.send({
			address: EXTERNAL_ADDRESS,
			amount: 30000,
			satsPerByte: 2,
			rbf: true
		});
		if (res.isErr()) throw res.error;
		expect(broadcast.calledOnce).to.equal(true);
		const decoded = decodeRawTransaction(
			broadcast.firstCall.args[0].rawTx,
			wallet.network
		);
		if (decoded.isErr()) throw decoded.error;
		const spent = decoded.value.vin.map((vin) => `${vin.txid}:${vin.vout}`);
		expect(spent).to.include(`${utxoA.tx_hash}:${utxoA.tx_pos}`);
		// Every coin the send spent is gone from the list, and from the balance.
		const remaining = wallet.listUtxos();
		expect(
			outpoints(remaining).filter((o) => spent.includes(o))
		).to.have.length(0);
		expect(wallet.getBalance()).to.equal(
			remaining.reduce((sum, utxo) => sum + utxo.value, 0)
		);
	});

	it('drops only the coins the raw transaction names', async () => {
		const res = await wallet.broadcastTransaction(txSpending([utxoB]));
		if (res.isErr()) throw res.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoA]));
		expect(wallet.getBalance()).to.equal(60000);
	});

	it('leaves the set alone for a transaction spending nothing of ours', async () => {
		const foreign: IUtxo = { ...utxoA, tx_hash: TXID_FOREIGN };
		const res = await wallet.broadcastTransaction(txSpending([foreign]));
		if (res.isErr()) throw res.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(
			outpoints([utxoA, utxoB])
		);
		expect(wallet.getBalance()).to.equal(100000);
	});

	it('still reports the txid when the broadcast hex does not parse', async () => {
		const res = await wallet.broadcastTransaction('not-a-transaction');
		if (res.isErr()) throw res.error;
		expect(res.value).to.equal(BROADCAST_TXID);
		expect(outpoints(wallet.listUtxos())).to.deep.equal(
			outpoints([utxoA, utxoB])
		);
	});

	it('does not let a scan issued before the broadcast put the coin back', async () => {
		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		let answer!: (result: Result<IGetUtxosResponse>) => void;
		const issued = new Promise<void>((scanIssued) => {
			sinon.stub(wallet.electrum, 'getUtxos').callsFake(() => {
				scanIssued();
				return new Promise((resolve) => {
					answer = resolve;
				});
			});
		});
		const scan = wallet.getUtxos({});
		await issued;

		const res = await wallet.broadcastTransaction(txSpending([utxoA]));
		if (res.isErr()) throw res.error;

		// The server had not seen the spend when it was asked.
		answer(ok({ utxos: [utxoA, utxoB], balance: 100000 }));
		const scanRes = await scan;
		if (scanRes.isErr()) throw scanRes.error;
		expect(outpoints(scanRes.value.utxos)).to.deep.equal(outpoints([utxoB]));
		expect(scanRes.value.balance).to.equal(40000);
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(wallet.getBalance()).to.equal(40000);
	});

	it('does not let a later scan clear the record an older scan still needs', async () => {
		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		const answers: ((result: Result<IGetUtxosResponse>) => void)[] = [];
		sinon.stub(wallet.electrum, 'getUtxos').callsFake(
			() =>
				new Promise((resolve) => {
					answers.push(resolve);
				})
		);

		const stale = wallet.getUtxos({});
		await waitFor(() => answers.length === 1);

		const res = await wallet.broadcastTransaction(txSpending([utxoA]));
		if (res.isErr()) throw res.error;

		const fresh = wallet.getUtxos({});
		await waitFor(() => answers.length === 2);

		// The second scan asked after the broadcast and the server knows.
		answers[1](ok({ utxos: [utxoB], balance: 40000 }));
		const freshRes = await fresh;
		if (freshRes.isErr()) throw freshRes.error;

		// The first asked before it and does not, so it must still be filtered.
		answers[0](ok({ utxos: [utxoA, utxoB], balance: 100000 }));
		const staleRes = await stale;
		if (staleRes.isErr()) throw staleRes.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(wallet.getBalance()).to.equal(40000);
	});

	it('does not let an older scan hide a coin a newer scan restored', async () => {
		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		const answers: ((result: Result<IGetUtxosResponse>) => void)[] = [];
		sinon.stub(wallet.electrum, 'getUtxos').callsFake(
			() =>
				new Promise((resolve) => {
					answers.push(resolve);
				})
		);

		const stale = wallet.getUtxos({});
		await waitFor(() => answers.length === 1);

		const res = await wallet.broadcastTransaction(txSpending([utxoA]));
		if (res.isErr()) throw res.error;

		const fresh = wallet.getUtxos({});
		await waitFor(() => answers.length === 2);

		// The broadcast was evicted, and the scan asked after it says so.
		answers[1](ok({ utxos: [utxoA, utxoB], balance: 100000 }));
		const freshRes = await fresh;
		if (freshRes.isErr()) throw freshRes.error;
		expect(wallet.getBalance()).to.equal(100000);

		answers[0](ok({ utxos: [utxoA, utxoB], balance: 100000 }));
		const staleRes = await stale;
		if (staleRes.isErr()) throw staleRes.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(
			outpoints([utxoA, utxoB])
		);
		expect(wallet.getBalance()).to.equal(100000);
	});

	it('does not let an older scan overwrite a newer one', async () => {
		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		const answers: ((result: Result<IGetUtxosResponse>) => void)[] = [];
		sinon.stub(wallet.electrum, 'getUtxos').callsFake(
			() =>
				new Promise((resolve) => {
					answers.push(resolve);
				})
		);

		const older = wallet.getUtxos({});
		await waitFor(() => answers.length === 1);
		const newer = wallet.getUtxos({});
		await waitFor(() => answers.length === 2);

		// The coin was spent elsewhere between the two queries.
		answers[1](ok({ utxos: [utxoB], balance: 40000 }));
		const newerRes = await newer;
		if (newerRes.isErr()) throw newerRes.error;

		answers[0](ok({ utxos: [utxoA, utxoB], balance: 100000 }));
		const olderRes = await older;
		if (olderRes.isErr()) throw olderRes.error;
		expect(outpoints(olderRes.value.utxos)).to.deep.equal(outpoints([utxoB]));
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(wallet.getBalance()).to.equal(40000);
	});

	it('believes a scan issued after the broadcast that still reports the coin', async () => {
		const res = await wallet.broadcastTransaction(txSpending([utxoA]));
		if (res.isErr()) throw res.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));

		// A broadcast that never propagated must not hide a live coin.
		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		sinon
			.stub(wallet.electrum, 'getUtxos')
			.resolves(ok({ utxos: [utxoA, utxoB], balance: 100000 }));
		const scanRes = await wallet.getUtxos({});
		if (scanRes.isErr()) throw scanRes.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(
			outpoints([utxoA, utxoB])
		);
		expect(wallet.getBalance()).to.equal(100000);
	});
});

/**
 * Issue #812: the UTXO set and the balance are written as two storage keys,
 * and a refused write used to be dropped without a word, leaving the stored
 * pair from two different generations. Memory stays authoritative either
 * way. What these pin: a refusal is logged, the set is written before the
 * balance so a refused set write leaves the stored pair as it was, and a
 * concurrent writer cannot pair one call's set with another's balance.
 */
describe('UTXO state persistence (#812)', function () {
	this.timeout(testTimeout);

	const NAME = 'spentpersist';
	const UTXOS_KEY = `${NAME}-regtest-utxos`;
	const BALANCE_KEY = `${NAME}-regtest-balance`;
	const PERSIST_ERROR = 'Failed to persist the UTXO set';

	let wallet: Wallet;
	let store: Map<string, unknown>;
	let storage: TStorage;
	let fail: { keys: string[] };
	let holdNext: (key: string) => () => void;
	let errors: string[];
	let logger: ILogger;
	let utxoA: IUtxo;
	let utxoB: IUtxo;

	const storedUtxos = (): IUtxo[] => store.get(UTXOS_KEY) as IUtxo[];
	const storedBalance = (): number => store.get(BALANCE_KEY) as number;
	const sum = (utxos: IUtxo[]): number =>
		utxos.reduce((total, utxo) => total + utxo.value, 0);
	// The offline refresh logs errors of its own.
	const persistErrors = (): string[] =>
		errors.filter((message) => message.includes(PERSIST_ERROR));

	/** Makes every getUtxos scan in this test answer with the given set. */
	const scanAnswers = (answer: IGetUtxosResponse): void => {
		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		sinon.stub(wallet.electrum, 'getUtxos').resolves(ok(answer));
	};

	beforeEach(async function () {
		({ store, storage, fail, holdNext } = makeFailableStorage());
		errors = [];
		logger = {
			debug: (): void => {},
			info: (): void => {},
			warn: (): void => {},
			error: (message: string): void => {
				errors.push(message);
			}
		};
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: NAME,
			network,
			storage,
			electrumOptions,
			logger
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		utxoA = injectUtxo(wallet, TXID_A, 60000);
		utxoB = injectUtxo(wallet, TXID_B, 40000, 1);
		// The pair a scan that found both coins would have stored.
		await wallet.saveWalletData('utxos', wallet.data.utxos);
		await wallet.saveWalletData('balance', wallet.data.balance);
		sinon
			.stub(electrumHelpers, 'broadcastTransaction')
			.resolves({ error: false, data: BROADCAST_TXID });
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.resolves({ error: false, data: '' });
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('logs a refused UTXO write and still keeps the spent coin out of memory', async () => {
		fail.keys = ['utxos'];
		const res = await wallet.removeSpentUtxos(txSpending([utxoA]));
		if (res.isErr()) throw res.error;
		// The coin is spent whatever storage says, so nothing is rolled back.
		expect(outpoints(res.value)).to.deep.equal(outpoints([utxoA]));
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(wallet.getBalance()).to.equal(40000);
		expect(persistErrors()).to.have.length(1);
	});

	it('still reports the broadcast txid when the UTXO write is refused', async () => {
		fail.keys = ['utxos'];
		const res = await wallet.broadcastTransaction(txSpending([utxoA]));
		if (res.isErr()) throw res.error;
		expect(res.value).to.equal(BROADCAST_TXID);
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(persistErrors()).to.have.length(1);
	});

	it('leaves the stored set and balance agreeing when the UTXO write is refused', async () => {
		fail.keys = ['utxos'];
		const res = await wallet.broadcastTransaction(txSpending([utxoA]));
		if (res.isErr()) throw res.error;
		// Neither key moved: storage still holds the pair from before the spend.
		expect(outpoints(storedUtxos())).to.deep.equal(outpoints([utxoA, utxoB]));
		expect(storedBalance()).to.equal(100000);

		fail.keys = [];
		const reloadRes = await Wallet.create({
			mnemonic: MNEMONIC,
			name: NAME,
			network,
			storage,
			electrumOptions,
			logger,
			disableRefreshOnCreate: true
		});
		if (reloadRes.isErr()) throw reloadRes.error;
		const reloaded = reloadRes.value;
		try {
			// The spent coin A is back until the first scan lands: the record of
			// the spend never reached storage, and nothing local can bring it
			// back. What the restart must not show is a balance that disagrees
			// with the coins it offers.
			expect(reloaded.getBalance()).to.equal(sum(reloaded.listUtxos()));
		} finally {
			await reloaded.stop();
		}
	});

	// Guard: passes without the #812 fix too. It pins that the next applied
	// scan writes both keys again after a refusal.
	it('lets the next scan write the pair storage refused', async () => {
		fail.keys = ['utxos'];
		const res = await wallet.broadcastTransaction(txSpending([utxoA]));
		if (res.isErr()) throw res.error;

		fail.keys = [];
		scanAnswers({ utxos: [utxoB], balance: 40000 });
		const scanRes = await wallet.getUtxos({});
		if (scanRes.isErr()) throw scanRes.error;
		expect(outpoints(storedUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(storedBalance()).to.equal(40000);
	});

	it('keeps a scan whose UTXO write is refused successful, without splitting the stored pair', async () => {
		fail.keys = ['utxos'];
		scanAnswers({ utxos: [utxoB], balance: 40000 });
		const scanRes = await wallet.getUtxos({});
		// An Err would stop refreshWallet before its address subscriptions.
		if (scanRes.isErr()) throw scanRes.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(wallet.getBalance()).to.equal(40000);
		expect(outpoints(storedUtxos())).to.deep.equal(outpoints([utxoA, utxoB]));
		expect(storedBalance()).to.equal(100000);
		expect(persistErrors()).to.have.length(1);
	});

	it('logs a refused balance write after the set has landed', async () => {
		fail.keys = ['balance'];
		const res = await wallet.removeSpentUtxos(txSpending([utxoA]));
		if (res.isErr()) throw res.error;
		expect(outpoints(wallet.listUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(wallet.getBalance()).to.equal(40000);
		expect(outpoints(storedUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(storedBalance()).to.equal(100000);
		expect(persistErrors()).to.have.length(1);
		expect(persistErrors()[0]).to.include("UTXO set's balance");
	});

	it('does not pair a stored set with the balance of a scan that landed while it was written', async () => {
		const utxoC: IUtxo = { ...utxoB, tx_hash: TXID_C, value: 30000 };
		// The spend's set write reaches storage and waits there.
		const releaseSpendWrite = holdNext('utxos');
		const spend = wallet.removeSpentUtxos(txSpending([utxoA]));
		await waitFor(() => wallet.getBalance() === 40000);

		// A scan lands meanwhile, and its set write queues behind the spend's.
		scanAnswers({ utxos: [utxoB, utxoC], balance: 70000 });
		const scan = wallet.getUtxos({});
		await waitFor(() => wallet.getBalance() === 70000);

		// Storage refuses the scan's set write once the spend's has landed.
		fail.keys = ['utxos'];
		releaseSpendWrite();
		const [spendRes, scanRes] = await Promise.all([spend, scan]);
		if (spendRes.isErr()) throw spendRes.error;
		if (scanRes.isErr()) throw scanRes.error;

		// Memory holds the scan's answer; storage holds the spend's pair, whole.
		expect(wallet.getBalance()).to.equal(70000);
		expect(outpoints(storedUtxos())).to.deep.equal(outpoints([utxoB]));
		expect(storedBalance()).to.equal(40000);
		expect(persistErrors()).to.have.length(1);
	});

	it('logs a refused write when clearing the set, and leaves the stored pair agreeing', async () => {
		fail.keys = ['utxos'];
		await wallet.clearUtxos();
		expect(wallet.listUtxos()).to.have.length(0);
		expect(wallet.getBalance()).to.equal(0);
		expect(outpoints(storedUtxos())).to.deep.equal(outpoints([utxoA, utxoB]));
		expect(storedBalance()).to.equal(100000);
		expect(persistErrors()).to.have.length(1);
	});

	it('logs a refused write of a balance set by hand', async () => {
		fail.keys = ['balance'];
		const res = wallet.updateWalletBalance({ balance: 1000 });
		if (res.isErr()) throw res.error;
		expect(wallet.getBalance()).to.equal(1000);
		await waitFor(() =>
			errors.some((message) =>
				message.includes('Failed to persist the balance')
			)
		);
		expect(storedBalance()).to.equal(100000);
	});
});
