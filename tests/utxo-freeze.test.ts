/**
 * UTXO freeze/unfreeze tests. Fully OFFLINE: wallets are created with
 * remainOffline; UTXOs are injected directly into wallet data (signing only
 * needs the derivation path), and nothing is broadcast (broadcast: false).
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';

import {
	decodeRawTransaction,
	EAddressType,
	EAvailableNetworks,
	IUtxo,
	IWalletStorage,
	Result,
	Wallet,
	createMemoryStorage,
	err
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Wallets are created with remainOffline: these tests must work offline.
const electrumOptions = { net, tls };

const network = EAvailableNetworks.regtest;
const testTimeout = 60000;

const TXID_A = '11'.repeat(32);
const TXID_B = '22'.repeat(32);

const makeStorage = (): {
	store: Map<string, string>;
	storage: IWalletStorage;
} => {
	const store = new Map<string, string>();
	return { store, storage: createMemoryStorage(store) };
};

/**
 * Same, but blacklistedUtxos writes can be made to fail on demand, either as a
 * resolved Err (what createWalletStorage produces) or as a rejection.
 */
const makeFailableStorage = (): {
	store: Map<string, string>;
	storage: IWalletStorage;
	fail: { on: boolean; reject: boolean };
} => {
	const store = new Map<string, string>();
	const fail = { on: false, reject: false };
	const memory = createMemoryStorage(store);
	return {
		store,
		fail,
		storage: {
			...memory,
			setData: async (key, value): Promise<Result<boolean>> => {
				if (fail.on && key.endsWith('blacklistedUtxos')) {
					if (fail.reject) throw new Error('storage is down');
					return err('storage is down');
				}
				return memory.setData(key, value);
			}
		}
	};
};

/** Fabricates a UTXO paying to one of the wallet's own derived addresses. */
const injectUtxo = async (
	wallet: Wallet,
	txid: string,
	value: number,
	addressIndex = 0
): Promise<IUtxo> => {
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
	const res = await wallet.updateData({
		utxos: [...wallet.data.utxos, utxo],
		balance: wallet.data.balance + value
	});
	if (res.isErr()) throw res.error;
	return utxo;
};

/** A promise that settles only when its resolve is called. */
const deferred = (): { promise: Promise<void>; resolve: () => void } => {
	let resolve: () => void = () => {};
	const promise = new Promise<void>((r) => (resolve = r));
	return { promise, resolve };
};

describe('UTXO freeze/unfreeze', function () {
	this.timeout(testTimeout);

	let wallet: Wallet;
	let store: Map<string, string>;
	let storage: IWalletStorage;
	let utxoA: IUtxo;
	let utxoB: IUtxo;

	before(async function () {
		({ store, storage } = makeStorage());
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'freezetest',
			network,
			storage,
			electrumOptions,
			remainOffline: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		utxoA = await injectUtxo(wallet, TXID_A, 60000);
		utxoB = await injectUtxo(wallet, TXID_B, 40000, 1);
	});

	after(async function () {
		await wallet?.stop();
	});

	it('rejects freezing an unknown outpoint (fail closed)', async () => {
		const res = await wallet.freezeUtxo({ txid: 'ab'.repeat(32), index: 0 });
		expect(res.isErr()).to.equal(true);
	});

	it('rejects a malformed txid', async () => {
		const res = await wallet.freezeUtxo({ txid: 'nothex', index: 0 });
		expect(res.isErr()).to.equal(true);
	});

	it('freezes a known UTXO and lists it', async () => {
		const res = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (res.isErr()) throw res.error;
		expect(wallet.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
		const frozen = wallet.listFrozenUtxos();
		expect(frozen).to.have.length(1);
		expect(frozen[0].tx_hash).to.equal(utxoB.tx_hash);
		// keyPair must never be persisted with a frozen entry.
		expect(frozen[0]).to.not.have.property('keyPair');
	});

	it('is idempotent when freezing twice', async () => {
		const res = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (res.isErr()) throw res.error;
		expect(wallet.listFrozenUtxos()).to.have.length(1);
	});

	it('reports the balance breakdown with frozen still counted in total', () => {
		const breakdown = wallet.getBalanceBreakdown();
		expect(breakdown.total).to.equal(100000);
		expect(breakdown.spendable).to.equal(60000);
		expect(breakdown.frozen).to.equal(40000);
		// getBalance stays the total.
		expect(wallet.getBalance()).to.equal(100000);
	});

	it('excludes the frozen UTXO from send coin selection', async () => {
		const res = await wallet.send({
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			amount: 30000,
			satsPerByte: 2,
			broadcast: false,
			rbf: true
		});
		if (res.isErr()) throw res.error;
		const decoded = decodeRawTransaction(res.value, wallet.network);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.vin).to.have.length(1);
		expect(decoded.value.vin[0].txid).to.equal(utxoA.tx_hash);
		await wallet.resetSendTransaction();
	});

	it('fails a send that would need the frozen UTXO', async () => {
		// 80k needs both UTXOs; only the 60k one is spendable.
		const res = await wallet.send({
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			amount: 80000,
			satsPerByte: 2,
			broadcast: false
		});
		expect(res.isErr()).to.equal(true);
		await wallet.resetSendTransaction();
	});

	it('excludes the frozen UTXO from sendMax', async () => {
		const res = await wallet.sendMax({
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			satsPerByte: 2,
			broadcast: false
		});
		if (res.isErr()) throw res.error;
		const decoded = decodeRawTransaction(res.value, wallet.network);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.vin).to.have.length(1);
		expect(decoded.value.vin[0].txid).to.equal(utxoA.tx_hash);
		// Sweep output must be bounded by the spendable (unfrozen) value.
		// decodeRawTransaction vout values are already in sats.
		const outputTotal = decoded.value.vout.reduce((acc, v) => acc + v.value, 0);
		expect(outputTotal).to.be.lessThan(60000);
		await wallet.resetSendTransaction();
	});

	it('estimates the max send from the coins sendMax can spend (#1365)', async () => {
		// Electrum's balance also counts dust that refresh keeps out of the set.
		const dust = await wallet.updateData({
			balance: wallet.data.balance + 500
		});
		if (dust.isErr()) throw dust.error;
		try {
			const estimate = wallet.transaction.estimateTransactionCosts({
				customFeeRate: 2
			});
			if (estimate.isErr()) throw estimate.error;
			expect(estimate.value.amount + estimate.value.fee).to.equal(60000);

			const res = await wallet.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2,
				broadcast: false
			});
			if (res.isErr()) throw res.error;
			const decoded = decodeRawTransaction(res.value, wallet.network);
			if (decoded.isErr()) throw decoded.error;
			const outputTotal = decoded.value.vout.reduce(
				(acc, v) => acc + v.value,
				0
			);
			expect(estimate.value.amount).to.equal(outputTotal);
		} finally {
			await wallet.updateData({ balance: wallet.data.balance - 500 });
			await wallet.resetSendTransaction();
		}
	});

	it('excludes the frozen UTXO from buildPsbt', async () => {
		const res = await wallet.buildPsbt({
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			amount: 30000,
			satsPerByte: 2
		});
		if (res.isErr()) throw res.error;
		expect(res.value.inputs).to.have.length(1);
		expect(res.value.inputs[0].tx_hash).to.equal(utxoA.tx_hash);
		await wallet.resetSendTransaction();
	});

	it('persists frozen UTXOs through wallet storage', async () => {
		expect(store.has('freezetest-regtest-blacklistedUtxos')).to.equal(true);
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'freezetest',
			network,
			storage,
			electrumOptions,
			remainOffline: true
		});
		if (res.isErr()) throw res.error;
		const reloaded = res.value;
		expect(reloaded.listFrozenUtxos()).to.have.length(1);
		expect(reloaded.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
		await reloaded.stop();
	});

	it('errors when unfreezing a UTXO that is not frozen', async () => {
		const res = await wallet.unfreezeUtxo({ txid: TXID_A, index: 0 });
		expect(res.isErr()).to.equal(true);
	});

	it('unfreezes and makes the UTXO spendable again', async () => {
		const res = await wallet.unfreezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (res.isErr()) throw res.error;
		expect(wallet.listFrozenUtxos()).to.have.length(0);
		const breakdown = wallet.getBalanceBreakdown();
		expect(breakdown.spendable).to.equal(100000);
		expect(breakdown.frozen).to.equal(0);
		const sendRes = await wallet.sendMax({
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			satsPerByte: 2,
			broadcast: false
		});
		if (sendRes.isErr()) throw sendRes.error;
		const decoded = decodeRawTransaction(sendRes.value, wallet.network);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.vin).to.have.length(2);
		await wallet.resetSendTransaction();
	});

	it('leaves a coin frozen after staging out of the max send (#1429)', async () => {
		const staged = await wallet.transaction.setupTransaction();
		if (staged.isErr()) throw staged.error;
		expect(wallet.transaction.data.inputs).to.have.length(2);
		const frozen = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (frozen.isErr()) throw frozen.error;
		try {
			const estimate = wallet.transaction.estimateTransactionCosts({
				customFeeRate: 2
			});
			if (estimate.isErr()) throw estimate.error;
			expect(estimate.value.amount + estimate.value.fee).to.equal(60000);

			// A staged input the wallet does not hold is still counted.
			const external: IUtxo = { ...utxoA, tx_hash: '33'.repeat(32) };
			const withExternal = wallet.transaction.estimateTransactionCosts({
				customFeeRate: 2,
				transaction: {
					...wallet.transaction.data,
					inputs: [...wallet.transaction.data.inputs, external]
				}
			});
			if (withExternal.isErr()) throw withExternal.error;
			expect(withExternal.value.amount + withExternal.value.fee).to.equal(
				120000
			);

			const res = await wallet.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2,
				broadcast: false
			});
			if (res.isErr()) throw res.error;
			const decoded = decodeRawTransaction(res.value, wallet.network);
			if (decoded.isErr()) throw decoded.error;
			const outputTotal = decoded.value.vout.reduce(
				(acc, v) => acc + v.value,
				0
			);
			expect(estimate.value.amount).to.equal(outputTotal);
		} finally {
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('signs no coin frozen after staging in a direct max send (#1463)', async () => {
		const keyPair = ECPairFactory(ecc).fromPrivateKey(Buffer.alloc(32, 0x5a), {
			network: bitcoin.networks.regtest
		});
		const externalAddress = bitcoin.payments.p2wpkh({
			pubkey: keyPair.publicKey,
			network: bitcoin.networks.regtest
		}).address;
		if (!externalAddress) throw new Error('No external address.');
		const external: IUtxo = {
			address: externalAddress,
			index: 0,
			path: '',
			scriptHash: '',
			height: 0,
			tx_hash: '33'.repeat(32),
			tx_pos: 1,
			value: 50000,
			publicKey: keyPair.publicKey.toString('hex'),
			keyPair
		};

		const staged = await wallet.transaction.setupTransaction();
		if (staged.isErr()) throw staged.error;
		const added = wallet.addTxInput({ input: external });
		if (added.isErr()) throw added.error;
		const frozen = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (frozen.isErr()) throw frozen.error;
		try {
			const max = await wallet.transaction.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2
			});
			if (max.isErr()) throw max.error;
			const created = await wallet.transaction.createTransaction({});
			if (created.isErr()) throw created.error;
			const decoded = decodeRawTransaction(created.value.hex, wallet.network);
			if (decoded.isErr()) throw decoded.error;
			expect(decoded.value.vin.map((vin) => vin.txid).sort()).to.deep.equal([
				utxoA.tx_hash,
				external.tx_hash
			]);
			const outputTotal = decoded.value.vout.reduce(
				(acc, v) => acc + v.value,
				0
			);
			expect(outputTotal + wallet.transaction.data.fee).to.equal(110000);
		} finally {
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('refuses a direct max send when every staged coin is frozen (#1463)', async () => {
		const staged = await wallet.transaction.setupTransaction();
		if (staged.isErr()) throw staged.error;
		for (const utxo of [utxoA, utxoB]) {
			const frozen = await wallet.freezeUtxo({
				txid: utxo.tx_hash,
				index: utxo.tx_pos
			});
			if (frozen.isErr()) throw frozen.error;
		}
		try {
			const res = await wallet.transaction.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2
			});
			expect(res.isErr()).to.equal(true);

			// A caller that froze the coins to reserve them for this send.
			const reserved = await wallet.transaction.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2,
				spendFrozen: true
			});
			if (reserved.isErr()) throw reserved.error;
			const created = await wallet.transaction.createTransaction({
				spendFrozen: true
			});
			if (created.isErr()) throw created.error;
			const decoded = decodeRawTransaction(created.value.hex, wallet.network);
			if (decoded.isErr()) throw decoded.error;
			expect(decoded.value.vin).to.have.length(2);
		} finally {
			for (const utxo of [utxoA, utxoB]) {
				await wallet.unfreezeUtxo({ txid: utxo.tx_hash, index: utxo.tx_pos });
			}
			await wallet.resetSendTransaction();
		}
	});

	it('signs no coin frozen while max was on once max is turned off (#1494)', async () => {
		await wallet.resetSendTransaction();
		const staged = await wallet.transaction.setupTransaction();
		if (staged.isErr()) throw staged.error;
		const on = await wallet.transaction.sendMax({
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			satsPerByte: 2
		});
		if (on.isErr()) throw on.error;
		const frozen = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (frozen.isErr()) throw frozen.error;
		try {
			const off = await wallet.transaction.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2
			});
			if (off.isErr()) throw off.error;
			expect(wallet.transaction.data.max).to.equal(false);
			const created = await wallet.transaction.createTransaction({});
			expect(created.isErr()).to.equal(true);
			if (created.isErr()) {
				expect(created.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}
		} finally {
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('signs no coin frozen after staging in a plain send (#1494)', async () => {
		await wallet.resetSendTransaction();
		const staged = await wallet.transaction.setupTransaction();
		if (staged.isErr()) throw staged.error;
		const output = wallet.transaction.updateSendTransaction({
			transaction: {
				outputs: [
					{
						address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
						value: 30000,
						index: 0
					}
				]
			}
		});
		if (output.isErr()) throw output.error;
		const fee = wallet.transaction.updateFee({ satsPerByte: 2 });
		if (fee.isErr()) throw fee.error;
		expect(wallet.transaction.data.inputs).to.have.length(2);
		const frozen = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (frozen.isErr()) throw frozen.error;
		try {
			const created = await wallet.transaction.createTransaction({});
			expect(created.isErr()).to.equal(true);
			if (created.isErr()) {
				expect(created.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}

			// A caller that froze the coin to reserve it for this send.
			const reserved = await wallet.transaction.createTransaction({
				spendFrozen: true
			});
			if (reserved.isErr()) throw reserved.error;
			const decoded = decodeRawTransaction(reserved.value.hex, wallet.network);
			if (decoded.isErr()) throw decoded.error;
			expect(decoded.value.vin.map((vin) => vin.txid).sort()).to.deep.equal([
				utxoA.tx_hash,
				utxoB.tx_hash
			]);
		} finally {
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	/**
	 * Stages a plain send of both coins, starts `build`, freezes utxoB once
	 * `paused` settles, then releases the build through `resume`.
	 */
	const freezeDuringBuild = async (
		paused: Promise<void>,
		resume: () => void,
		build: () => Promise<Result<unknown>> = (): Promise<Result<unknown>> =>
			wallet.transaction.createTransaction({})
	): Promise<Result<unknown>> => {
		await wallet.resetSendTransaction();
		const staged = await wallet.transaction.setupTransaction();
		if (staged.isErr()) throw staged.error;
		const output = wallet.transaction.updateSendTransaction({
			transaction: {
				outputs: [
					{
						address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
						value: 30000,
						index: 0
					}
				]
			}
		});
		if (output.isErr()) throw output.error;
		const fee = wallet.transaction.updateFee({ satsPerByte: 2 });
		if (fee.isErr()) throw fee.error;
		expect(wallet.transaction.data.inputs).to.have.length(2);

		const building = build();
		await paused;
		const frozen = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (frozen.isErr()) throw frozen.error;
		resume();
		return building;
	};

	it('signs no coin frozen while signing keys are derived (#1524)', async () => {
		const getBip32Interface = wallet.getBip32Interface;
		const paused = deferred();
		const resume = deferred();
		wallet.getBip32Interface = async (): ReturnType<
			typeof getBip32Interface
		> => {
			paused.resolve();
			await resume.promise;
			return getBip32Interface();
		};
		try {
			const created = await freezeDuringBuild(paused.promise, resume.resolve);
			expect(wallet.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
			expect(created.isErr()).to.equal(true);
			if (created.isErr()) {
				expect(created.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}
		} finally {
			wallet.getBip32Interface = getBip32Interface;
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('signs no coin frozen while prevouts load (#1524)', async () => {
		const getTransactions = wallet.electrum.getTransactions;
		const paused = deferred();
		const resume = deferred();
		wallet.electrum.getTransactions = async (): ReturnType<
			typeof getTransactions
		> => {
			paused.resolve();
			await resume.promise;
			return err('offline');
		};
		try {
			const created = await freezeDuringBuild(paused.promise, resume.resolve);
			expect(wallet.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
			expect(created.isErr()).to.equal(true);
			if (created.isErr()) {
				expect(created.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}
		} finally {
			wallet.electrum.getTransactions = getTransactions;
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('exports no coin frozen after staging in an unsigned PSBT (#1525)', async () => {
		await wallet.resetSendTransaction();
		const staged = await wallet.transaction.setupTransaction();
		if (staged.isErr()) throw staged.error;
		const output = wallet.transaction.updateSendTransaction({
			transaction: {
				outputs: [
					{
						address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
						value: 30000,
						index: 0
					}
				]
			}
		});
		if (output.isErr()) throw output.error;
		const fee = wallet.transaction.updateFee({ satsPerByte: 2 });
		if (fee.isErr()) throw fee.error;
		expect(wallet.transaction.data.inputs).to.have.length(2);
		const frozen = await wallet.freezeUtxo({
			txid: utxoB.tx_hash,
			index: utxoB.tx_pos
		});
		if (frozen.isErr()) throw frozen.error;
		try {
			const built = await wallet.transaction.createUnsignedPsbt();
			expect(built.isErr()).to.equal(true);
			if (built.isErr()) {
				expect(built.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}

			// A caller that froze the coin to reserve it for this send.
			const reserved = await wallet.transaction.createUnsignedPsbt({
				spendFrozen: true
			});
			if (reserved.isErr()) throw reserved.error;
			const txids = reserved.value.txInputs.map(({ hash }) =>
				Buffer.from(hash).reverse().toString('hex')
			);
			expect(txids.sort()).to.deep.equal([utxoA.tx_hash, utxoB.tx_hash]);
		} finally {
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('exports no coin frozen while an unsigned PSBT loads prevouts (#1525)', async () => {
		const getTransactions = wallet.electrum.getTransactions;
		const paused = deferred();
		const resume = deferred();
		wallet.electrum.getTransactions = async (): ReturnType<
			typeof getTransactions
		> => {
			paused.resolve();
			await resume.promise;
			return err('offline');
		};
		try {
			const built = await freezeDuringBuild(
				paused.promise,
				resume.resolve,
				() => wallet.transaction.createUnsignedPsbt()
			);
			expect(wallet.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
			expect(built.isErr()).to.equal(true);
			if (built.isErr()) {
				expect(built.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}
		} finally {
			wallet.electrum.getTransactions = getTransactions;
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('exports no coin frozen after createUnsignedPsbt checked it (#1548)', async () => {
		const transaction = wallet.transaction;
		const build = transaction.createUnsignedPsbt;
		const paused = deferred();
		const resume = deferred();
		transaction.createUnsignedPsbt = async (
			...args: Parameters<typeof build>
		): ReturnType<typeof build> => {
			const built = await build(...args);
			paused.resolve();
			await resume.promise;
			return built;
		};
		try {
			// 80k needs both coins, so utxoB is selected.
			const building = wallet.buildPsbt({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				amount: 80000,
				satsPerByte: 2
			});
			await paused.promise;
			const frozen = await wallet.freezeUtxo({
				txid: utxoB.tx_hash,
				index: utxoB.tx_pos
			});
			if (frozen.isErr()) throw frozen.error;
			resume.resolve();
			const built = await building;
			expect(wallet.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
			expect(built.isErr()).to.equal(true);
			if (built.isErr()) {
				expect(built.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}
		} finally {
			transaction.createUnsignedPsbt = build;
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	/** Freezes utxoB after the send's createTransaction signed, before it returns. */
	const freezeAfterSigning = async (
		send: () => Promise<Result<string>>
	): Promise<Result<string>> => {
		const transaction = wallet.transaction;
		const create = transaction.createTransaction;
		const paused = deferred();
		const resume = deferred();
		transaction.createTransaction = async (
			...args: Parameters<typeof create>
		): ReturnType<typeof create> => {
			const created = await create(...args);
			paused.resolve();
			await resume.promise;
			return created;
		};
		try {
			const sending = send();
			await paused.promise;
			const frozen = await wallet.freezeUtxo({
				txid: utxoB.tx_hash,
				index: utxoB.tx_pos
			});
			if (frozen.isErr()) throw frozen.error;
			resume.resolve();
			return await sending;
		} finally {
			transaction.createTransaction = create;
		}
	};

	it('returns no signed hex spending a coin frozen after sendMany signed (#1564)', async () => {
		try {
			// 80k needs both coins, so utxoB is selected.
			const sent = await freezeAfterSigning(() =>
				wallet.sendMany({
					txs: [
						{
							address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
							amount: 80000
						}
					],
					satsPerByte: 2,
					broadcast: false
				})
			);
			expect(wallet.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
			expect(sent.isErr()).to.equal(true);
			if (sent.isErr()) {
				expect(sent.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}
		} finally {
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('returns no signed hex spending a coin frozen after sendMax signed (#1564)', async () => {
		try {
			const sent = await freezeAfterSigning(() =>
				wallet.sendMax({
					address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
					satsPerByte: 2,
					broadcast: false
				})
			);
			expect(wallet.isUtxoFrozen(utxoB.tx_hash, utxoB.tx_pos)).to.equal(true);
			expect(sent.isErr()).to.equal(true);
			if (sent.isErr()) {
				expect(sent.error.message).to.equal(
					`Staged input ${utxoB.tx_hash}:${utxoB.tx_pos} is frozen.`
				);
			}
		} finally {
			await wallet.unfreezeUtxo({ txid: utxoB.tx_hash, index: utxoB.tx_pos });
			await wallet.resetSendTransaction();
		}
	});

	it('prices a direct max send from the coins its own setup staged (#1495)', async () => {
		await wallet.resetSendTransaction();
		try {
			const max = await wallet.transaction.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2
			});
			if (max.isErr()) throw max.error;
			const { inputs, outputs, fee } = wallet.transaction.data;
			expect(inputs).to.have.length(2);
			expect(outputs[0].value + fee).to.equal(100000);
			const created = await wallet.transaction.createTransaction({});
			if (created.isErr()) throw created.error;
			const decoded = decodeRawTransaction(created.value.hex, wallet.network);
			if (decoded.isErr()) throw decoded.error;
			expect(decoded.value.vin).to.have.length(2);
			expect(decoded.value.vout).to.have.length(1);
			expect(decoded.value.vout[0].value).to.equal(outputs[0].value);
		} finally {
			await wallet.resetSendTransaction();
		}
	});

	it('refuses a direct max send after reset when every coin is frozen (#1495)', async () => {
		await wallet.resetSendTransaction();
		for (const utxo of [utxoA, utxoB]) {
			const frozen = await wallet.freezeUtxo({
				txid: utxo.tx_hash,
				index: utxo.tx_pos
			});
			if (frozen.isErr()) throw frozen.error;
		}
		try {
			const res = await wallet.transaction.sendMax({
				address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
				satsPerByte: 2
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.equal(
					'No inputs specified in setupTransaction.'
				);
			}
			expect(wallet.transaction.data.inputs).to.have.length(0);
		} finally {
			for (const utxo of [utxoA, utxoB]) {
				await wallet.unfreezeUtxo({ txid: utxo.tx_hash, index: utxo.tx_pos });
			}
			await wallet.resetSendTransaction();
		}
	});
});

/**
 * A freeze that never reached storage is not a freeze: the next process loads
 * the old blacklist and hands the coin back to coin selection, so a caller
 * holding the outpoint for an in-flight funding has to hear about it (#626).
 */
describe('UTXO freeze durability', function () {
	this.timeout(testTimeout);

	let wallet: Wallet;
	let store: Map<string, string>;
	let storage: IWalletStorage;
	let fail: { on: boolean; reject: boolean };
	let utxo: IUtxo;

	beforeEach(async function () {
		({ store, storage, fail } = makeFailableStorage());
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'freezedurability',
			network,
			storage,
			electrumOptions,
			remainOffline: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		await wallet.refreshWallet({});
		utxo = await injectUtxo(wallet, TXID_A, 60000);
	});

	afterEach(async function () {
		await wallet?.stop();
	});

	it('saveWalletData reports a resolved storage error', async () => {
		fail.on = true;
		const res = await wallet.saveWalletData('blacklistedUtxos', []);
		expect(res.isErr()).to.equal(true);
	});

	it('saveWalletData reports a rejected storage write', async () => {
		fail.on = true;
		fail.reject = true;
		const res = await wallet.saveWalletData('blacklistedUtxos', []);
		expect(res.isErr()).to.equal(true);
	});

	it('freezeUtxo fails and rolls back when the write is rejected', async () => {
		fail.on = true;
		const res = await wallet.freezeUtxo({
			txid: utxo.tx_hash,
			index: utxo.tx_pos
		});
		expect(res.isErr()).to.equal(true);
		expect(wallet.isUtxoFrozen(utxo.tx_hash, utxo.tx_pos)).to.equal(false);
		expect(wallet.listFrozenUtxos()).to.have.length(0);
		expect(store.has('freezedurability-regtest-blacklistedUtxos')).to.equal(
			false
		);
		// The coin is spendable, which is what the next process would see too:
		// nothing is left claiming a reservation that did not survive.
		expect(wallet.getBalanceBreakdown().frozen).to.equal(0);
	});

	it('freezeUtxo fails and rolls back when the write throws', async () => {
		fail.on = true;
		fail.reject = true;
		const res = await wallet.freezeUtxo({
			txid: utxo.tx_hash,
			index: utxo.tx_pos
		});
		expect(res.isErr()).to.equal(true);
		expect(wallet.isUtxoFrozen(utxo.tx_hash, utxo.tx_pos)).to.equal(false);
	});

	it('a failed freeze leaves the coin selectable rather than half frozen', async () => {
		fail.on = true;
		await wallet.freezeUtxo({ txid: utxo.tx_hash, index: utxo.tx_pos });
		fail.on = false;
		const sendRes = await wallet.sendMax({
			address: 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk',
			satsPerByte: 2,
			broadcast: false
		});
		if (sendRes.isErr()) throw sendRes.error;
		const decoded = decodeRawTransaction(sendRes.value, wallet.network);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.vin).to.have.length(1);
		await wallet.resetSendTransaction();
	});

	it('unfreezeUtxo fails and keeps the freeze storage still holds', async () => {
		const frozen = await wallet.freezeUtxo({
			txid: utxo.tx_hash,
			index: utxo.tx_pos
		});
		if (frozen.isErr()) throw frozen.error;

		fail.on = true;
		const res = await wallet.unfreezeUtxo({
			txid: utxo.tx_hash,
			index: utxo.tx_pos
		});
		expect(res.isErr()).to.equal(true);
		expect(wallet.isUtxoFrozen(utxo.tx_hash, utxo.tx_pos)).to.equal(true);
		// The persisted blacklist still holds it, so memory must agree.
		const persisted: IUtxo[] = JSON.parse(
			store.get('freezedurability-regtest-blacklistedUtxos')!
		);
		expect(persisted).to.have.length(1);
		expect(persisted[0].tx_hash).to.equal(utxo.tx_hash);
	});

	it('a concurrent freeze of the same coin never rides a rolled-back entry', async () => {
		// The blacklist entry is published before the write that may undo it,
		// so a second caller reading it mid-flight would be told the coin is
		// already frozen by a freeze about to disappear.
		fail.on = true;
		const [first, second] = await Promise.all([
			wallet.freezeUtxo({ txid: utxo.tx_hash, index: utxo.tx_pos }),
			wallet.freezeUtxo({ txid: utxo.tx_hash, index: utxo.tx_pos })
		]);
		expect(first.isErr()).to.equal(true);
		expect(second.isErr(), 'the second freeze is no more durable').to.equal(
			true
		);
		expect(wallet.isUtxoFrozen(utxo.tx_hash, utxo.tx_pos)).to.equal(false);
		expect(store.has('freezedurability-regtest-blacklistedUtxos')).to.equal(
			false
		);
	});

	it('a concurrent freeze of the same coin records it once', async () => {
		const [first, second] = await Promise.all([
			wallet.freezeUtxo({ txid: utxo.tx_hash, index: utxo.tx_pos }),
			wallet.freezeUtxo({ txid: utxo.tx_hash, index: utxo.tx_pos })
		]);
		expect(first.isErr()).to.equal(false);
		expect(second.isErr()).to.equal(false);
		expect(wallet.listFrozenUtxos()).to.have.length(1);
		const persisted: IUtxo[] = JSON.parse(
			store.get('freezedurability-regtest-blacklistedUtxos')!
		);
		expect(persisted).to.have.length(1);
	});

	it('reports a freeze queued behind another as not created', async () => {
		// Both calls see the coin unfrozen. Only the one that added the entry may
		// later treat it as its own to lift.
		const [first, second] = await Promise.all([
			wallet.freezeUtxoIfUnfrozen({ txid: utxo.tx_hash, index: utxo.tx_pos }),
			wallet.freezeUtxoIfUnfrozen({
				txid: utxo.tx_hash,
				index: utxo.tx_pos,
				tag: 'funding-pledge'
			})
		]);
		if (first.isErr()) throw first.error;
		if (second.isErr()) throw second.error;
		expect(first.value.created).to.equal(true);
		expect(second.value.created).to.equal(false);
		expect(wallet.listFrozenUtxos()[0].freezeTag).to.equal(undefined);
	});

	it('an untagged freeze takes over a tagged one', async () => {
		// The tagged owner lifts only entries that still carry its tag, so the
		// user's freeze has to clear it to outlive that owner's release.
		const tagged = await wallet.freezeUtxoIfUnfrozen({
			txid: utxo.tx_hash,
			index: utxo.tx_pos,
			tag: 'funding-pledge'
		});
		if (tagged.isErr()) throw tagged.error;
		const user = await wallet.freezeUtxoIfUnfrozen({
			txid: utxo.tx_hash,
			index: utxo.tx_pos
		});
		if (user.isErr()) throw user.error;
		expect(user.value.created).to.equal(true);
		const frozen = wallet.listFrozenUtxos();
		expect(frozen).to.have.length(1);
		expect(frozen[0].freezeTag).to.equal(undefined);
		expect(frozen[0].frozenAt).to.equal(undefined);
		const persisted: IUtxo[] = JSON.parse(
			store.get('freezedurability-regtest-blacklistedUtxos')!
		);
		expect(persisted).to.have.length(1);
		expect(persisted[0].freezeTag).to.equal(undefined);
	});

	it('a takeover storage refuses leaves the tagged freeze as it was', async () => {
		const tagged = await wallet.freezeUtxo({
			txid: utxo.tx_hash,
			index: utxo.tx_pos,
			tag: 'funding-pledge'
		});
		if (tagged.isErr()) throw tagged.error;
		fail.on = true;
		const user = await wallet.freezeUtxo({
			txid: utxo.tx_hash,
			index: utxo.tx_pos
		});
		expect(user.isErr()).to.equal(true);
		const frozen = wallet.listFrozenUtxos();
		expect(frozen).to.have.length(1);
		expect(frozen[0].freezeTag).to.equal('funding-pledge');
		expect(frozen[0].frozenAt).to.be.a('number');
	});
});
