/**
 * Regression tests for issue #1842: a UTXO scan put immature coinbase outputs
 * in the UTXO set and the balance, so a send could pick one and be rejected
 * at broadcast with "coinbase immature" while mature coins covered it.
 *
 * Fully OFFLINE: the wallet never connects (remainOffline), and the UTXO
 * listing and transaction lookups are stubbed. The restart case points at an
 * unreachable port instead, and the client helpers answer for the server.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	EScanningStrategy,
	IAddress,
	IFormattedTransaction,
	IGetUtxosResponse,
	ITransaction,
	ITxHash,
	IUtxo,
	Result,
	TTxDetails,
	Wallet,
	createMemoryStorage,
	decodeRawTransaction,
	err,
	ok
} from '../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

const REWARD = 5_000_000_000;

const sum = (utxos: IUtxo[]): number =>
	utxos.reduce((total, utxo) => total + utxo.value, 0);

const outpoints = (utxos: IUtxo[]): string[] =>
	utxos.map((utxo) => `${utxo.tx_hash}:${utxo.tx_pos}`);

describe('Immature coinbase outputs (#1842)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** The verbose transactions Electrum answers with, by txid. */
	let served: Map<string, TTxDetails>;
	/** Every txid the wallet asked Electrum for. */
	let asked: string[];
	let getUtxos: sinon.SinonStub;

	/** A coin paying the wallet's own index 0 address. */
	const coin = (txid: string, height: number, value = REWARD): IUtxo => {
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		return {
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height,
			tx_hash: txid,
			tx_pos: 0,
			value,
			publicKey: source.publicKey
		};
	};

	/** Lets Electrum return `txid`, as a coinbase or an ordinary transaction.
	 *  No hex, so a send builds its inputs from the witness UTXO. */
	const serve = (txid: string, coinbase: boolean): void => {
		served.set(txid, {
			txid,
			hash: txid,
			hex: '',
			locktime: 0,
			size: 0,
			vsize: 0,
			weight: 0,
			version: 2,
			vin: coinbase
				? [{ coinbase: '0365', sequence: 0xffffffff }]
				: [
						{
							txid: 'ee'.repeat(32),
							vout: 0,
							scriptSig: { asm: '', hex: '' },
							txinwitness: [],
							sequence: 0xfffffffd
						}
				  ],
			vout: []
		});
	};

	/** Makes each scan answer with `utxos`. */
	const scanAnswers = (utxos: IUtxo[]): void => {
		getUtxos.resolves(ok({ utxos, balance: sum(utxos) }));
	};

	const tipAt = (height: number): Promise<void> =>
		wallet.updateHeader({ height, hash: '', hex: '' });

	const scan = async (): Promise<Result<IGetUtxosResponse>> =>
		wallet.refreshUtxos({});

	beforeEach(async function () {
		served = new Map();
		asked = [];
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'coinbasematurity',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions: { net, tls },
			remainOffline: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still generates index-0 addresses.
		await wallet.refreshWallet({});

		sinon.stub(wallet, 'checkElectrumConnection').resolves(ok('connected'));
		getUtxos = sinon.stub(wallet.electrum, 'getUtxos');
		sinon
			.stub(wallet.electrum, 'getTransactions')
			.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) => {
				asked.push(...txHashes.map(({ tx_hash }) => tx_hash));
				return ok({
					error: false,
					id: 0,
					method: 'getTransactions',
					network: 'regtest',
					data: txHashes.map(
						({ tx_hash }) =>
							({
								id: 0,
								jsonrpc: '2.0',
								param: tx_hash,
								data: { tx_hash },
								result: served.get(tx_hash)
							}) as unknown as ITransaction<IUtxo>
					)
				});
			});
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('leaves immature coinbase outputs out of the set and balance, and sends from the mature one', async () => {
		await tipAt(300);
		const mature = coin('a1'.repeat(32), 101);
		const immature = [coin('b2'.repeat(32), 250), coin('c3'.repeat(32), 300)];
		[mature, ...immature].forEach((c) => serve(c.tx_hash, true));
		scanAnswers([mature, ...immature]);

		const scanned = await scan();
		if (scanned.isErr()) throw scanned.error;
		expect(scanned.value).to.deep.equal({ utxos: [mature], balance: REWARD });
		expect(wallet.listUtxos()).to.deep.equal([mature]);
		expect(wallet.getBalance()).to.equal(REWARD);
		expect(outpoints(wallet.listImmatureUtxos())).to.have.members(
			outpoints(immature)
		);
		expect(asked, 'a coin 200 deep is mature whatever it is').to.have.members(
			immature.map((c) => c.tx_hash)
		);

		const signed = await wallet.createSignedTransaction({
			address: EXTERNAL,
			amount: 100_000,
			satsPerByte: 2
		});
		if (signed.isErr()) throw signed.error;
		const decoded = decodeRawTransaction(signed.value.txHex, wallet.network);
		if (decoded.isErr()) throw decoded.error;
		expect(
			decoded.value.vin.map((vin) => `${vin.txid}:${vin.vout}`)
		).to.deep.equal(outpoints([mature]));
	});

	it('refuses a send before broadcast when every coin is an immature coinbase', async () => {
		await tipAt(300);
		const immature = [coin('b2'.repeat(32), 250), coin('c3'.repeat(32), 300)];
		immature.forEach((c) => serve(c.tx_hash, true));
		scanAnswers(immature);
		const broadcast = sinon.stub(wallet.electrum, 'broadcastTransaction');

		const scanned = await scan();
		if (scanned.isErr()) throw scanned.error;
		expect(wallet.listUtxos()).to.deep.equal([]);
		expect(wallet.getBalance()).to.equal(0);

		const sent = await wallet.send({
			address: EXTERNAL,
			amount: 100_000,
			satsPerByte: 2
		});
		expect(sent.isErr()).to.equal(true);
		if (sent.isOk()) return;
		const held = sum(immature);
		expect(sent.error.message).to.equal(
			`No spendable UTXOs available. ${held} sats in coinbase outputs have not matured.`
		);
		expect(broadcast.called).to.equal(false);
	});

	it('spends a coinbase output once the next block is 100 above it', async () => {
		const reward = coin('d4'.repeat(32), 201);
		serve(reward.tx_hash, true);
		scanAnswers([reward]);

		await tipAt(299);
		const early = await scan();
		if (early.isErr()) throw early.error;
		expect(wallet.listUtxos(), 'block 300 cannot spend it').to.deep.equal([]);
		expect(wallet.getBalance()).to.equal(0);
		expect(wallet.coinbaseMatured).to.equal(false);

		await tipAt(300);
		expect(wallet.coinbaseMatured, 'a rescan is owed').to.equal(true);
		const due = await scan();
		if (due.isErr()) throw due.error;
		expect(wallet.listUtxos(), 'block 301 can').to.deep.equal([reward]);
		expect(wallet.getBalance()).to.equal(REWARD);
		expect(wallet.listImmatureUtxos()).to.deep.equal([]);
		expect(wallet.coinbaseMatured).to.equal(false);
	});

	it('holds a coinbase output back again when a reorg lowers the tip below maturity', async () => {
		const reward = coin('d4'.repeat(32), 201);
		serve(reward.tx_hash, true);
		scanAnswers([reward]);

		await tipAt(300);
		const before = await scan();
		if (before.isErr()) throw before.error;
		expect(wallet.listUtxos()).to.deep.equal([reward]);

		await tipAt(299);
		const after = await scan();
		if (after.isErr()) throw after.error;
		expect(wallet.listUtxos()).to.deep.equal([]);
		expect(wallet.getBalance()).to.equal(0);
		expect(wallet.listImmatureUtxos()).to.deep.equal([reward]);
	});

	it('keeps ordinary coins of any age, and looks up only young confirmed ones', async () => {
		await tipAt(300);
		const young = coin('e5'.repeat(32), 300, 40_000);
		const unconfirmed = coin('f6'.repeat(32), 0, 50_000);
		const old = coin('a7'.repeat(32), 10, 60_000);
		serve(young.tx_hash, false);
		scanAnswers([young, unconfirmed, old]);

		const scanned = await scan();
		if (scanned.isErr()) throw scanned.error;
		expect(wallet.listUtxos()).to.deep.equal([young, unconfirmed, old]);
		expect(wallet.getBalance()).to.equal(150_000);
		expect(wallet.listImmatureUtxos()).to.deep.equal([]);
		expect(asked).to.deep.equal([young.tx_hash]);
	});

	it('looks each young transaction up once', async () => {
		await tipAt(300);
		const reward = coin('b2'.repeat(32), 250);
		serve(reward.tx_hash, true);
		scanAnswers([reward]);

		for (const tip of [300, 300, 301]) {
			await tipAt(tip);
			const scanned = await scan();
			if (scanned.isErr()) throw scanned.error;
			expect(wallet.listImmatureUtxos()).to.deep.equal([reward]);
		}
		expect(asked).to.deep.equal([reward.tx_hash]);
	});

	it('reads whether a coin is a coinbase from its stored record', async () => {
		await tipAt(300);
		const reward = coin('b2'.repeat(32), 250);
		const record = {
			txid: reward.tx_hash,
			vin: [{ coinbase: '0365', sequence: 0xffffffff }]
		} as IFormattedTransaction;
		const stored = await wallet.updateData({
			transactions: { [reward.tx_hash]: record }
		});
		if (stored.isErr()) throw stored.error;
		scanAnswers([reward]);

		const scanned = await scan();
		if (scanned.isErr()) throw scanned.error;
		expect(wallet.listUtxos()).to.deep.equal([]);
		expect(wallet.listImmatureUtxos()).to.deep.equal([reward]);
		expect(asked, 'nothing to ask').to.deep.equal([]);
	});

	it('fails the scan, keeping the last set, when a young transaction is not returned', async () => {
		await tipAt(300);
		const old = coin('a7'.repeat(32), 10, 60_000);
		scanAnswers([old]);
		const first = await scan();
		if (first.isErr()) throw first.error;

		const unknown = coin('c8'.repeat(32), 290, 70_000);
		scanAnswers([old, unknown]);
		const second = await scan();
		expect(second.isErr()).to.equal(true);
		expect(wallet.listUtxos()).to.deep.equal([old]);
		expect(wallet.getBalance()).to.equal(60_000);
	});

	it('waits for the tip when a scan lands before the first header', async () => {
		const reward = coin('b2'.repeat(32), 250);
		serve(reward.tx_hash, true);
		scanAnswers([reward]);
		const subscribe = sinon
			.stub(wallet.electrum, 'subscribeToHeader')
			.resolves(err('Unable to subscribe to headers.'));

		const failed = await scan();
		expect(failed.isErr(), 'no tip, no verdict').to.equal(true);
		expect(wallet.listUtxos()).to.deep.equal([]);

		subscribe.callsFake(async () => {
			await tipAt(300);
			return ok(wallet.data.header);
		});
		const scanned = await scan();
		if (scanned.isErr()) throw scanned.error;
		expect(wallet.listUtxos()).to.deep.equal([]);
		expect(wallet.listImmatureUtxos()).to.deep.equal([reward]);
	});

	it('scans every address in the first scan since the wallet loaded when a coinbase is stored', async () => {
		await tipAt(300);
		const txid = 'b2'.repeat(32);
		const record = {
			txid,
			scriptHash: wallet.data.addressIndex[EAddressType.p2wpkh].scriptHash,
			vin: [{ coinbase: '0365', sequence: 0xffffffff }]
		} as IFormattedTransaction;
		const stored = await wallet.updateData({
			transactions: { [txid]: record }
		});
		if (stored.isErr()) throw stored.error;
		// Spent since, so nothing is held back.
		scanAnswers([]);

		for (let i = 0; i < 2; i++) {
			const scanned = await scan();
			if (scanned.isErr()) throw scanned.error;
		}
		expect(getUtxos.firstCall.args[0].scanningStrategy).to.equal(
			EScanningStrategy.all
		);
		expect(getUtxos.secondCall.args[0].scanningStrategy).to.equal(
			EScanningStrategy.gapLimit
		);
	});

	it('finds every address a stored coinbase paid in the first scan since the wallet loaded', async () => {
		await tipAt(300);
		const gen = await wallet.generateAddresses({
			addressAmount: 45,
			changeAddressAmount: 0,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		const receive = Object.values(gen.value.addresses);
		const at = (index: number): IAddress =>
			receive.find((a) => a.index === index) as IAddress;
		const txid = 'b2'.repeat(32);
		// A record names one address, however many its transaction paid.
		const record = {
			txid,
			scriptHash: at(0).scriptHash,
			vin: [{ coinbase: '0365', sequence: 0xffffffff }]
		} as IFormattedTransaction;
		const stored = await wallet.updateData({
			addresses: { ...wallet.data.addresses, p2wpkh: gen.value.addresses },
			addressIndex: { ...wallet.data.addressIndex, p2wpkh: at(40) },
			transactions: { [txid]: record }
		});
		if (stored.isErr()) throw stored.error;
		// Both outside the gap window at index 40, and mature at block 301.
		const outputs: IUtxo[] = [0, 1].map((index) => {
			const { address, path, scriptHash, publicKey } = at(index);
			return {
				address,
				index,
				path,
				scriptHash,
				publicKey,
				height: 201,
				tx_hash: txid,
				tx_pos: index,
				value: REWARD
			};
		});
		serve(txid, true);
		type TScanArgs = Parameters<Wallet['electrum']['getUtxos']>[0];
		getUtxos.callsFake(async (args: TScanArgs) => {
			const listed = {
				...wallet.electrum.utxoScanAddresses(args),
				...args.additionalScriptHashes
			};
			const utxos = outputs.filter((utxo) => listed[utxo.scriptHash]);
			return ok({ utxos, balance: sum(utxos) });
		});

		const scanned = await scan();
		if (scanned.isErr()) throw scanned.error;
		expect(outpoints(wallet.listUtxos())).to.have.members(outpoints(outputs));
		expect(wallet.getBalance()).to.equal(2 * REWARD);
	});

	it('lists the address of a held-back coin in the next scan', async () => {
		await tipAt(300);
		const reward = coin('b2'.repeat(32), 250);
		serve(reward.tx_hash, true);
		scanAnswers([reward]);
		const first = await scan();
		if (first.isErr()) throw first.error;

		const second = await scan();
		if (second.isErr()) throw second.error;
		const listed = getUtxos.lastCall.args[0].additionalScriptHashes;
		expect(listed[reward.scriptHash]).to.deep.equal({
			index: reward.index,
			path: reward.path,
			address: reward.address,
			scriptHash: reward.scriptHash,
			publicKey: reward.publicKey
		});
	});
});

describe('Immature coinbase outputs across a restart (#1842)', function () {
	this.timeout(60000);

	type TBatch<T> = { key: string; data: T[] };
	type TEntry = { tx_hash: string; height: number };

	/** Unreachable on purpose: the client helpers answer in its place. */
	const ELECTRUM_PORT = 65529;
	const COINBASE = 'b2'.repeat(32);
	const FUNDING = 'ee'.repeat(32);

	let values: Map<string, string>;
	let wallet: Wallet;
	/** What the server lists for each script hash. */
	let history: Map<string, TEntry[]>;
	let unspent: Map<string, (TEntry & { tx_pos: number; value: number })[]>;
	let served: Map<string, TTxDetails>;
	let subscribed: string[];

	const open = async (): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'coinbaserestart',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			electrumOptions: {
				net,
				tls,
				servers: {
					host: '127.0.0.1',
					ssl: ELECTRUM_PORT,
					tcp: ELECTRUM_PORT,
					protocol: EProtocol.tcp
				}
			},
			disableRefreshOnCreate: true,
			storage: createMemoryStorage(values)
		});
		if (res.isErr()) throw res.error;
		const opened = res.value;
		opened.electrum.stopConnectionPolling();
		opened.electrum.connectedToElectrum = true;
		opened.electrum.batchDelay = 0;
		sinon.stub(opened.electrum, 'answeredRecently').returns(true);
		sinon.stub(opened.electrum, 'isConnected').resolves(true);
		sinon.stub(opened, 'updateFeeEstimates').resolves(ok(opened.feeEstimates));
		return opened;
	};

	const tx = (
		txid: string,
		vin: TTxDetails['vin'],
		vout: [string, number][]
	): void => {
		served.set(txid, {
			txid,
			hash: txid,
			hex: '',
			locktime: 0,
			size: 0,
			vsize: 0,
			weight: 0,
			version: 2,
			vin,
			vout: vout.map(([address, value], n) => ({
				n,
				value,
				scriptPubKey: { address, asm: '', hex: '' }
			}))
		});
	};

	/** Puts a transaction paying `to` on the server at `height`. */
	const pay = (
		txid: string,
		to: IAddress,
		height: number,
		sats: number
	): void => {
		history.set(to.scriptHash, [{ tx_hash: txid, height }]);
		unspent.set(to.scriptHash, [
			{ tx_hash: txid, height, tx_pos: 0, value: sats }
		]);
	};

	const answer = <T extends { scriptHash: string }>(
		batch: T[],
		of: Map<string, unknown[]>
	): unknown => ({
		error: false,
		data: batch.map((a) => ({
			data: a,
			param: a.scriptHash,
			result: of.get(a.scriptHash) ?? []
		}))
	});

	beforeEach(() => {
		values = new Map();
		history = new Map();
		unspent = new Map();
		served = new Map();
		subscribed = [];
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) =>
				answer(scriptHashes.data, history)
			);
		// Listings go out keyed by script hash, not as a list.
		sinon
			.stub(electrumHelpers, 'listUnspentAddressScriptHashes')
			.callsFake(
				async ({
					scriptHashes
				}: {
					scriptHashes: { data: Record<string, IAddress> };
				}) => answer(Object.values(scriptHashes.data), unspent)
			);
		sinon
			.stub(electrumHelpers, 'getTransactions')
			.callsFake(async ({ txHashes }: { txHashes: TBatch<ITxHash> }) => ({
				error: false,
				data: txHashes.data.map((data) => ({
					id: 0,
					jsonrpc: '2.0',
					param: data.tx_hash,
					data,
					result: served.get(data.tx_hash)
				}))
			}));
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.callsFake(async ({ scriptHash }: { scriptHash: string }) => {
				subscribed.push(scriptHash);
				return {
					error: false,
					id: 0,
					method: 'subscribeAddress',
					data: { id: 0, jsonrpc: '2.0', result: null }
				};
			});
	});

	afterEach(async () => {
		sinon.restore();
		await wallet?.stop();
	});

	it('finds a coinbase the receive window passed while it was immature, once it matures after a restart', async () => {
		wallet = await open();
		const gen = await wallet.generateAddresses({
			addressAmount: 45,
			changeAddressAmount: 0,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		const at = (index: number): IAddress =>
			Object.values(gen.value.addresses).find(
				(a) => a.index === index
			) as IAddress;
		// A reward at index 3, then payments that move the window past it.
		tx(
			COINBASE,
			[{ coinbase: '0365', sequence: 0xffffffff }],
			[[at(3).address, REWARD / 1e8]]
		);
		tx(
			FUNDING,
			[{ coinbase: '0366', sequence: 0xffffffff }],
			[
				[EXTERNAL, 1],
				[EXTERNAL, 1]
			]
		);
		const spend = (vout: number): TTxDetails['vin'] => [
			{
				txid: FUNDING,
				vout,
				scriptSig: { asm: '', hex: '' },
				txinwitness: [],
				sequence: 0xfffffffd
			}
		];
		tx('a1'.repeat(32), spend(0), [[at(22).address, 0.001]]);
		tx('a2'.repeat(32), spend(1), [[at(41).address, 0.002]]);
		pay(COINBASE, at(3), 100, REWARD);
		pay('a1'.repeat(32), at(22), 50, 100_000);
		pay('a2'.repeat(32), at(41), 60, 200_000);

		await wallet.updateHeader({ height: 100, hash: '', hex: '' });
		const first = await wallet.refreshWallet();
		if (first.isErr()) throw first.error;
		expect(wallet.data.addressIndex.p2wpkh.index).to.equal(42);
		expect(outpoints(wallet.listImmatureUtxos())).to.deep.equal([
			`${COINBASE}:0`
		]);
		expect(wallet.getBalance()).to.equal(300_000);
		expect(subscribed, 'watched outside the window').to.include(
			at(3).scriptHash
		);

		await wallet.stop();
		wallet = await open();
		await wallet.updateHeader({ height: 199, hash: '', hex: '' });
		for (let i = 0; i < 2; i++) {
			const refreshed = await wallet.refreshWallet();
			if (refreshed.isErr()) throw refreshed.error;
			expect(outpoints(wallet.listUtxos())).to.include(`${COINBASE}:0`);
			expect(wallet.getBalance()).to.equal(REWARD + 300_000);
		}
	});
});
