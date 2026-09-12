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
	IUtxo,
	IWalletData,
	Result,
	TStorage,
	Wallet,
	decodeRawTransaction,
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
