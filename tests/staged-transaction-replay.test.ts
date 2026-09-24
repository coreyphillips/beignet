/**
 * Staged on-chain send hygiene (#1002, #1011). Fully OFFLINE: wallets point at
 * an unreachable Electrum port, UTXOs are injected directly into wallet data
 * (signing only needs the derivation path or the attached key pair), and
 * nothing is broadcast (broadcast: false).
 *
 * #1002: the wallet persisted its staged send, and setupTransaction seeded a
 * new send's outputs from the copy loaded at boot, so after a restart every
 * later send also paid the recipients of the last multi-output send.
 *
 * #1011: sweepPrivateKey and addExternalInputs attach the signing key pair to
 * the staged inputs, and the storage adapters JSON-stringify the staged send,
 * so the swept private key was written to wallet storage.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';
import ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory, ECPairInterface } from 'ecpair';

import {
	decodeRawTransaction,
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	ISendTransaction,
	IUtxo,
	IWalletData,
	Result,
	TDecodeRawTx,
	TStorage,
	Wallet,
	ok
} from '../src';
import { getDefaultSendTransaction } from '../src/shapes';

const ECPair = ECPairFactory(ecc);

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
const regtest = bitcoin.networks.regtest;
const testTimeout = 60000;

const TXID_A = '11'.repeat(32);
const TXID_B = '22'.repeat(32);
const TXID_EXTERNAL = '33'.repeat(32);
const TXID_SWEPT = '44'.repeat(32);

/** A regtest p2wpkh address nobody in these tests holds the key to. */
const recipient = (seed: number): string => {
	const pubkey = ECPair.fromPrivateKey(Buffer.alloc(32, seed), {
		network: regtest
	}).publicKey;
	const address = bitcoin.payments.p2wpkh({ pubkey, network: regtest }).address;
	if (!address) throw new Error('Unable to derive a recipient address.');
	return address;
};

const RECIPIENT_A = recipient(0xa1);
const RECIPIENT_B = recipient(0xb2);
const RECIPIENT_C = recipient(0xc3);
const RECIPIENT_D = recipient(0xd4);
const RECIPIENT_E = recipient(0xe5);

const transactionKey = (name: string): string => `${name}-regtest-transaction`;

interface IJsonStorage {
	store: Map<string, string>;
	/** Every write, in order, as the JSON text the adapter was handed. */
	history: { key: string; value: string }[];
	storage: TStorage;
}

/**
 * A Map-backed TStorage that stores the JSON text of every value, as the real
 * adapters do (createWalletStorage, createEncryptedStorage), so whatever
 * JSON.stringify makes of a key pair is exactly what the assertions read.
 */
const makeJsonStorage = (): IJsonStorage => {
	const store = new Map<string, string>();
	const history: { key: string; value: string }[] = [];
	return {
		store,
		history,
		storage: {
			getData: async <K extends keyof IWalletData>(
				key: string
			): Promise<Result<IWalletData[K]>> => {
				const raw = store.get(key);
				const value = raw === undefined ? undefined : JSON.parse(raw);
				return ok(value as IWalletData[K]);
			},
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				const text = JSON.stringify(value);
				store.set(key, text);
				history.push({ key, value: text });
				return ok(true);
			}
		}
	};
};

const storedTransaction = (
	store: Map<string, string>,
	name: string
): ISendTransaction => {
	const raw = store.get(transactionKey(name));
	if (raw === undefined) throw new Error('No staged transaction in storage.');
	return JSON.parse(raw) as ISendTransaction;
};

/** Opens a wallet on the given storage, as a process start would. */
const createWallet = async (
	name: string,
	storage: TStorage
): Promise<Wallet> => {
	const res = await Wallet.create({
		mnemonic: MNEMONIC,
		name,
		network,
		storage,
		electrumOptions
	});
	if (res.isErr()) throw res.error;
	const wallet = res.value;
	// The failed (offline) refresh still generates index-0 addresses.
	await wallet.refreshWallet({});
	return wallet;
};

/** Fabricates a UTXO paying to one of the wallet's own derived addresses. */
const injectUtxo = (wallet: Wallet, txid: string, value: number): IUtxo => {
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
	return utxo;
};

/** Fabricates a UTXO held by an external key pair (no wallet path). */
const externalUtxo = (
	keyPair: ECPairInterface,
	txid: string,
	value: number
): IUtxo => {
	const address = bitcoin.payments.p2wpkh({
		pubkey: keyPair.publicKey,
		network: regtest
	}).address;
	if (!address) throw new Error('Unable to derive the external address.');
	return {
		address,
		index: 0,
		path: '',
		scriptHash: '',
		height: 0,
		tx_hash: txid,
		tx_pos: 1,
		value,
		publicKey: keyPair.publicKey.toString('hex')
	};
};

const decode = (wallet: Wallet, hex: string): TDecodeRawTx => {
	const decoded = decodeRawTransaction(hex, wallet.network);
	if (decoded.isErr()) throw decoded.error;
	return decoded.value;
};

/** Sats paid to one address across every output (values are already sats). */
const paidTo = (decoded: TDecodeRawTx, address: string): number =>
	decoded.vout
		.filter((out) => out.scriptPubKey.address === address)
		.reduce((acc, out) => acc + out.value, 0);

/** Lets a write issued without await (updateSendTransaction) land. */
const settle = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));

describe('Staged send replay after a restart (#1002)', function () {
	this.timeout(testTimeout);

	const NAME = 'stagedreplay';
	let store: Map<string, string>;
	let storage: TStorage;
	let wallet1: Wallet;
	const wallets: Wallet[] = [];

	before(function () {
		({ store, storage } = makeJsonStorage());
	});

	after(async function () {
		for (const wallet of wallets) await wallet.stop();
	});

	it('a multi-recipient sendMany is not replayed into the sends of a wallet loaded from the same storage', async () => {
		wallet1 = await createWallet(NAME, storage);
		wallets.push(wallet1);
		injectUtxo(wallet1, TXID_A, 300_000);
		const many = await wallet1.sendMany({
			txs: [
				{ address: RECIPIENT_A, amount: 20_000 },
				{ address: RECIPIENT_B, amount: 30_000 },
				{ address: RECIPIENT_C, amount: 40_000 }
			],
			satsPerByte: 2,
			broadcast: false,
			rbf: true
		});
		if (many.isErr()) throw many.error;
		expect(
			decode(wallet1, many.value).vout,
			'three recipients and change'
		).to.have.length(4);

		// The restart: a fresh wallet on the same name and storage.
		const wallet2 = await createWallet(NAME, storage);
		wallets.push(wallet2);
		injectUtxo(wallet2, TXID_B, 300_000);
		const send = await wallet2.send({
			address: RECIPIENT_E,
			amount: 25_000,
			satsPerByte: 2,
			broadcast: false,
			rbf: true
		});
		if (send.isErr()) throw send.error;
		const decoded = decode(wallet2, send.value);
		expect(decoded.vout, 'recipient and change only').to.have.length(2);
		expect(paidTo(decoded, RECIPIENT_E)).to.equal(25_000);
		for (const stale of [RECIPIENT_A, RECIPIENT_B, RECIPIENT_C]) {
			expect(paidTo(decoded, stale), `still paying ${stale}`).to.equal(0);
		}
		// Storage holds nothing of either send once the calls have returned.
		expect(storedTransaction(store, NAME)).to.deep.equal(
			getDefaultSendTransaction()
		);
	});

	it('sendMax after the restart spends to its one recipient', async () => {
		const wallet3 = await createWallet(NAME, storage);
		wallets.push(wallet3);
		injectUtxo(wallet3, TXID_B, 300_000);
		const res = await wallet3.sendMax({
			address: RECIPIENT_E,
			satsPerByte: 2,
			broadcast: false
		});
		if (res.isErr()) throw res.error;
		const decoded = decode(wallet3, res.value);
		expect(decoded.vout).to.have.length(1);
		expect(decoded.vout[0].scriptPubKey.address).to.equal(RECIPIENT_E);
		expect(storedTransaction(store, NAME)).to.deep.equal(
			getDefaultSendTransaction()
		);
	});

	it('a later send in the same process carries only its own recipient', async () => {
		const again = await wallet1.send({
			address: RECIPIENT_D,
			amount: 25_000,
			satsPerByte: 2,
			broadcast: false,
			rbf: true
		});
		if (again.isErr()) throw again.error;
		const decoded = decode(wallet1, again.value);
		expect(decoded.vout, 'recipient and change only').to.have.length(2);
		expect(paidTo(decoded, RECIPIENT_D)).to.equal(25_000);
		expect(storedTransaction(store, NAME)).to.deep.equal(
			getDefaultSendTransaction()
		);
	});

	it('a multi-recipient buildPsbt leaves nothing staged for the next call', async () => {
		const json = makeJsonStorage();
		const name = 'stagedpsbt';
		const wallet = await createWallet(name, json.storage);
		wallets.push(wallet);
		injectUtxo(wallet, TXID_A, 300_000);
		const built = await wallet.buildPsbt({
			txs: [
				{ address: RECIPIENT_A, amount: 20_000 },
				{ address: RECIPIENT_B, amount: 30_000 },
				{ address: RECIPIENT_C, amount: 40_000 }
			],
			satsPerByte: 2
		});
		if (built.isErr()) throw built.error;
		expect(built.value.outputs, 'three recipients and change').to.have.length(
			4
		);
		// The restart: the recipients of the PSBT are not paid again.
		const reloaded = await createWallet(name, json.storage);
		wallets.push(reloaded);
		injectUtxo(reloaded, TXID_B, 300_000);
		const send = await reloaded.send({
			address: RECIPIENT_D,
			amount: 25_000,
			satsPerByte: 2,
			broadcast: false
		});
		if (send.isErr()) throw send.error;
		const decoded = decode(reloaded, send.value);
		expect(decoded.vout, 'recipient and change only').to.have.length(2);
		expect(paidTo(decoded, RECIPIENT_D)).to.equal(25_000);
		expect(storedTransaction(json.store, name)).to.deep.equal(
			getDefaultSendTransaction()
		);
	});
});

describe('Signing keys never reach wallet storage (#1011)', function () {
	this.timeout(testTimeout);

	const NAME = 'stagedkeys';
	// A fixed key so the WIF and the hex are known strings to search for.
	const keyPair = ECPair.fromPrivateKey(Buffer.alloc(32, 0x5a), {
		network: regtest
	});
	const wif = keyPair.toWIF();
	const privateKey = keyPair.privateKey;
	if (!privateKey) throw new Error('The test key pair has no private key.');
	// JSON.stringify writes a Buffer as {"type":"Buffer","data":[...]}: the
	// decimal byte list is how the key showed up in storage.
	const secrets = [
		'keyPair',
		'__D',
		'__Q',
		wif,
		privateKey.toString('hex'),
		Array.from(privateKey).join(',')
	];

	let wallet: Wallet;
	let json: IJsonStorage;

	before(async function () {
		json = makeJsonStorage();
		wallet = await createWallet(NAME, json.storage);
		injectUtxo(wallet, TXID_A, 60_000);
	});

	after(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	/** Every write of the staged send so far, as the adapter saw it. */
	const stagedWrites = (): string[] =>
		json.history
			.filter((entry) => entry.key === transactionKey(NAME))
			.map((entry) => entry.value);

	const expectKeyFree = (writes: string[]): void => {
		expect(writes.length, 'the staged send was written').to.be.greaterThan(0);
		for (const text of writes) {
			for (const secret of secrets) {
				expect(text, `storage carries ${secret.slice(0, 12)}`).to.not.include(
					secret
				);
			}
		}
	};

	it('addExternalInputs keeps the key pair on the live inputs and writes none of it', async () => {
		const setup = await wallet.transaction.setupTransaction({ satsPerByte: 2 });
		if (setup.isErr()) throw setup.error;
		// The recipient goes in first: the fee guard in addExternalInputs
		// measures the fee against the staged output total.
		const output = await wallet.transaction.addOutput({
			address: RECIPIENT_D,
			value: 70_000,
			index: 0
		});
		if (output.isErr()) throw output.error;
		const external = externalUtxo(keyPair, TXID_EXTERNAL, 50_000);
		const added = wallet.transaction.addExternalInputs({
			inputs: [external],
			keyPair
		});
		if (added.isErr()) throw added.error;
		await settle();

		expectKeyFree(stagedWrites());
		const stored = storedTransaction(json.store, NAME);
		expect(stored.inputs.map((input) => input.tx_hash)).to.include(
			TXID_EXTERNAL
		);
		// The live copy still carries the key pair, which is what signs.
		const live = wallet.transaction.data.inputs.find(
			(input) => input.tx_hash === TXID_EXTERNAL
		);
		expect(live?.keyPair).to.equal(keyPair);

		const fee = wallet.transaction.updateFee({ satsPerByte: 2 });
		if (fee.isErr()) throw fee.error;
		const created = await wallet.transaction.createTransaction({});
		if (created.isErr()) throw created.error;
		const decoded = decode(wallet, created.value.hex);
		expect(decoded.vin).to.have.length(2);
		for (const vin of decoded.vin) {
			expect(vin.txinwitness, `input ${vin.txid} is signed`).to.have.length(2);
		}
		expect(paidTo(decoded, RECIPIENT_D)).to.equal(70_000);
		expectKeyFree(stagedWrites());
		await wallet.resetSendTransaction();
	});

	it('sweepPrivateKey signs with the swept key, writes none of it and leaves nothing staged', async () => {
		const swept = externalUtxo(keyPair, TXID_SWEPT, 50_000);
		sinon
			.stub(wallet, 'getPrivateKeyInfo')
			.resolves(
				ok({ balance: 50_000, utxos: [swept], keyPair, addresses: [] })
			);
		const writesBefore = stagedWrites().length;

		const res = await wallet.sweepPrivateKey({
			privateKey: wif,
			toAddress: RECIPIENT_E,
			satsPerByte: 2,
			broadcast: false
		});
		if (res.isErr()) throw res.error;
		const decoded = decode(wallet, res.value.hex);
		expect(decoded.vin).to.have.length(1);
		expect(decoded.vin[0].txid).to.equal(TXID_SWEPT);
		expect(
			decoded.vin[0].txinwitness,
			'the swept input is signed'
		).to.have.length(2);
		expect(decoded.vout).to.have.length(1);
		expect(decoded.vout[0].scriptPubKey.address).to.equal(RECIPIENT_E);
		expect(res.value.balance).to.equal(50_000);

		// No write during the sweep carried the key, in any form.
		const writes = stagedWrites().slice(writesBefore);
		expectKeyFree(writes);
		// Nothing of the sweep is left, in storage or in the live copy.
		expect(storedTransaction(json.store, NAME)).to.deep.equal(
			getDefaultSendTransaction()
		);
		expect(wallet.transaction.data.inputs).to.have.length(0);
		expect(wallet.transaction.data.outputs).to.have.length(0);
	});
});
