/**
 * UTXO freeze/unfreeze tests. Fully OFFLINE: wallets point at an unreachable
 * Electrum port; UTXOs are injected directly into wallet data (signing only
 * needs the derivation path), and nothing is broadcast (broadcast: false).
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	decodeRawTransaction,
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IUtxo,
	IWalletData,
	Result,
	TStorage,
	Wallet,
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

const makeStorage = (): { store: Map<string, unknown>; storage: TStorage } => {
	const store = new Map<string, unknown>();
	return {
		store,
		storage: {
			getData: async <K extends keyof IWalletData>(
				key: string
			): Promise<Result<IWalletData[K]>> => {
				return ok(store.get(key) as IWalletData[K]);
			},
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				store.set(key, value);
				return ok(true);
			}
		}
	};
};

/**
 * Same, but blacklistedUtxos writes can be made to fail on demand, either as a
 * resolved Err (what createWalletStorage produces) or as a rejection.
 */
const makeFailableStorage = (): {
	store: Map<string, unknown>;
	storage: TStorage;
	fail: { on: boolean; reject: boolean };
} => {
	const store = new Map<string, unknown>();
	const fail = { on: false, reject: false };
	return {
		store,
		fail,
		storage: {
			getData: async <K extends keyof IWalletData>(
				key: string
			): Promise<Result<IWalletData[K]>> => {
				return ok(store.get(key) as IWalletData[K]);
			},
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (fail.on && key.endsWith('blacklistedUtxos')) {
					if (fail.reject) throw new Error('storage is down');
					return err('storage is down');
				}
				store.set(key, value);
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

describe('UTXO freeze/unfreeze', function () {
	this.timeout(testTimeout);

	let wallet: Wallet;
	let store: Map<string, unknown>;
	let storage: TStorage;
	let utxoA: IUtxo;
	let utxoB: IUtxo;

	before(async function () {
		({ store, storage } = makeStorage());
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'freezetest',
			network,
			storage,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});
		utxoA = injectUtxo(wallet, TXID_A, 60000);
		utxoB = injectUtxo(wallet, TXID_B, 40000, 1);
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
			electrumOptions
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
});

/**
 * A freeze that never reached storage is not a freeze: the next process loads
 * the old blacklist and hands the coin back to coin selection, so a caller
 * holding the outpoint for an in-flight funding has to hear about it (#626).
 */
describe('UTXO freeze durability', function () {
	this.timeout(testTimeout);

	let wallet: Wallet;
	let store: Map<string, unknown>;
	let storage: TStorage;
	let fail: { on: boolean; reject: boolean };
	let utxo: IUtxo;

	beforeEach(async function () {
		({ store, storage, fail } = makeFailableStorage());
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'freezedurability',
			network,
			storage,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		await wallet.refreshWallet({});
		utxo = injectUtxo(wallet, TXID_A, 60000);
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
		const persisted = store.get(
			'freezedurability-regtest-blacklistedUtxos'
		) as IUtxo[];
		expect(persisted).to.have.length(1);
		expect(persisted[0].tx_hash).to.equal(utxo.tx_hash);
	});
});
