/**
 * The payer's wallet adapter (issue #613, LFBW port #532 workstream 4D).
 *
 * Two things the wallet API cannot say for itself, and that the engine leans on
 * for fund safety: a freeze belongs to whoever took it, and a transaction with a
 * height is not therefore mined.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import net from 'net';
import tls from 'tls';
import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IWalletData,
	TStorage,
	Wallet
} from '../../src';
import { directFundingWallet, IDfWallet } from '../../src/cli/direct-funding';
import { DirectFundingSender } from '../../src/lightning/direct-funding/sender/engine';
import {
	DirectFundingPaymentStore,
	DF_PAYMENTS_STORAGE_KEY
} from '../../src/lightning/direct-funding/sender/records';
import { IDfSenderCoin } from '../../src/lightning/direct-funding/sender/types';
import {
	chainHashForNetwork,
	DirectFundingErrorCode
} from '../../src/lightning/direct-funding/types';
import { Network } from '../../src/lightning/invoice/types';
import { IUtxo } from '../../src/types';
import { err, ok, Result } from '../../src/utils';
import {
	acceptingReceiver,
	FakeSenderWallet,
	flush,
	makeCoin,
	memoryStorage,
	mintRequest,
	registryWith,
	ScriptedReceiverLane
} from '../lightning/helpers/df-sender';

const NETWORK = bitcoin.networks.regtest;
const TXID = 'aa'.repeat(32);
const CONFLICT = 'bb'.repeat(32);

interface IStubWallet extends IDfWallet {
	frozen: IUtxo[];
	freezes: Array<{ txid: string; index: number; tag?: string }>;
}

/** A wallet holding one coin, with whatever freezes and transactions a test sets. */
function stubWallet(
	opts: {
		frozen?: IUtxo[];
		transactions?: Record<string, { txid: string; height?: number; vin: [] }>;
		/** What the stored header says, or a throw when there is none. */
		header?: { height: number } | 'throws';
	} = {}
): IStubWallet {
	const utxo = {
		address: 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
		tx_hash: TXID,
		tx_pos: 0,
		value: 200_000,
		height: 100,
		path: "m/84'/1'/0'/0/0",
		scriptHash: 'ff'.repeat(32)
	} as unknown as IUtxo;
	const stub = {
		frozen: opts.frozen ?? [],
		freezes: [] as Array<{ txid: string; index: number; tag?: string }>,
		listUtxos: (): IUtxo[] => [utxo],
		listFrozenUtxos: (): IUtxo[] => stub.frozen,
		isUtxoFrozen: (txid: string, index: number): boolean =>
			stub.frozen.some((f) => f.tx_hash === txid && f.tx_pos === index),
		freezeUtxoIfUnfrozen: async (args: {
			txid: string;
			index: number;
			tag?: string;
		}): Promise<Result<{ created: boolean }>> => {
			stub.freezes.push(args);
			stub.frozen.push({
				...utxo,
				...(args.tag !== undefined ? { freezeTag: args.tag } : {})
			});
			return ok({ created: true });
		},
		unfreezeUtxoIfTagged: async (args: {
			txid: string;
			index: number;
			tag: string;
		}): Promise<Result<{ unfrozen: boolean }>> => {
			const on = (f: IUtxo): boolean =>
				f.tx_hash === args.txid && f.tx_pos === args.index;
			if (stub.frozen.some((f) => on(f) && f.freezeTag !== args.tag)) {
				return ok({ unfrozen: false });
			}
			stub.frozen = stub.frozen.filter((f) => !on(f));
			return ok({ unfrozen: true });
		},
		transactions: opts.transactions ?? {},
		electrum: {
			getBlockHeader: (): { height: number } => {
				if (opts.header === 'throws') throw new Error('no header yet');
				return opts.header ?? { height: 800_000 };
			}
		}
	};
	return stub as unknown as IStubWallet;
}

describe('direct funding wallet: whose freeze is it', () => {
	it('will not adopt a freeze the operator put on the coin', async () => {
		// The wallet answers Ok for a coin that is already frozen, so without the
		// tag the engine would read the operator's reservation as its own and sign
		// a coin somebody withheld.
		const wallet = stubWallet({
			frozen: [{ tx_hash: TXID, tx_pos: 0 } as unknown as IUtxo]
		});
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.freezeUtxo(TXID, 0)).to.equal(false);
		expect(wallet.freezes).to.have.length(0);
	});

	it('leaves the operator entry in place when the payment settles', async () => {
		const wallet = stubWallet({
			frozen: [{ tx_hash: TXID, tx_pos: 0 } as unknown as IUtxo]
		});
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.unfreezeUtxo(TXID, 0)).to.equal(false);
		expect(wallet.frozen).to.have.length(1);
	});

	it('takes, re-adopts and releases its own', async () => {
		const wallet = stubWallet();
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.freezeUtxo(TXID, 0)).to.equal(true);
		expect(wallet.freezes[0].tag).to.equal('direct-funding');
		// A resumed attempt meets the freeze its own earlier run left behind.
		expect(await df.freezeUtxo(TXID, 0)).to.equal(true);
		expect(wallet.freezes, 'no second write').to.have.length(1);
		expect(await df.unfreezeUtxo(TXID, 0)).to.equal(true);
		expect(wallet.frozen).to.have.length(0);
	});
});

describe('direct funding wallet: a freeze queued ahead of ours (issue #1253)', function () {
	this.timeout(60_000);

	const MNEMONIC =
		'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
	const TXID_X = '33'.repeat(32);
	const TXID_Y = '44'.repeat(32);

	let wallet: Wallet;
	let store: Map<string, unknown>;
	// Every blacklist write waits on this before it reaches storage.
	let blacklistWrite: Promise<void> = Promise.resolve();
	let refuseBlacklistWrites = false;

	beforeEach(async function () {
		store = new Map<string, unknown>();
		const storage: TStorage = {
			getData: async <K extends keyof IWalletData>(
				key: string
			): Promise<Result<IWalletData[K]>> =>
				ok(store.get(key) as IWalletData[K]),
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				if (key.endsWith('blacklistedUtxos')) {
					await blacklistWrite;
					if (refuseBlacklistWrites) return err('storage is unavailable');
				}
				store.set(key, value);
				return ok(true);
			}
		};
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'dfqueuedfreeze',
			network: EAvailableNetworks.regtest,
			storage,
			// Unreachable on purpose: nothing here needs a server.
			electrumOptions: {
				net,
				tls,
				servers: {
					host: '127.0.0.1',
					ssl: 65529,
					tcp: 65529,
					protocol: EProtocol.tcp
				}
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// The failed (offline) refresh still derives the index-0 address.
		await wallet.refreshWallet({});
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		for (const [i, txid] of [TXID_X, TXID_Y].entries()) {
			wallet.data.utxos.push({
				address: source.address,
				index: source.index,
				path: source.path,
				scriptHash: source.scriptHash,
				height: 100 + i,
				tx_hash: txid,
				tx_pos: 0,
				value: 100_000,
				publicKey: source.publicKey
			});
		}
	});

	afterEach(async function () {
		blacklistWrite = Promise.resolve();
		refuseBlacklistWrites = false;
		await wallet?.stop();
	});

	/** Hold Y's write so whatever is queued next reaches X with no entry yet. */
	const holdBlacklist = (): {
		userY: Promise<Result<string>>;
		release: () => void;
	} => {
		let release!: () => void;
		blacklistWrite = new Promise((resolve) => (release = resolve));
		return { userY: wallet.freezeUtxo({ txid: TXID_Y, index: 0 }), release };
	};

	it('does not take the operator freeze as its reservation', async () => {
		const df = directFundingWallet(wallet, NETWORK);
		const { userY, release } = holdBlacklist();
		const userX = wallet.freezeUtxo({ txid: TXID_X, index: 0 });
		const payer = df.freezeUtxo(TXID_X, 0);
		await new Promise((resolve) => setImmediate(resolve));
		expect(wallet.isUtxoFrozen(TXID_X, 0)).to.equal(false);
		release();
		const [y, x, reserved] = await Promise.all([userY, userX, payer]);
		expect(y.isOk() && x.isOk()).to.equal(true);
		expect(reserved, 'the payer must not sign against X').to.equal(false);
		const entry = wallet
			.listFrozenUtxos()
			.find((f) => f.tx_hash === TXID_X && f.tx_pos === 0);
		expect(entry?.freezeTag).to.equal(undefined);

		expect(await df.unfreezeUtxo(TXID_X, 0)).to.equal(false);
		expect(wallet.isUtxoFrozen(TXID_X, 0), 'the operator freeze').to.equal(
			true
		);
	});

	it('still takes its own freeze when it waited in the queue', async () => {
		const df = directFundingWallet(wallet, NETWORK);
		const { userY, release } = holdBlacklist();
		const payer = df.freezeUtxo(TXID_X, 0);
		await new Promise((resolve) => setImmediate(resolve));
		release();
		const [y, reserved] = await Promise.all([userY, payer]);
		expect(y.isOk()).to.equal(true);
		expect(reserved).to.equal(true);
		expect(await df.unfreezeUtxo(TXID_X, 0)).to.equal(true);
		expect(wallet.isUtxoFrozen(TXID_X, 0)).to.equal(false);
	});

	it('does not release X when an operator freeze is queued ahead (issue #1266)', async () => {
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.freezeUtxo(TXID_X, 0)).to.equal(true);
		const { userY, release } = holdBlacklist();
		const userX = wallet.freezeUtxo({ txid: TXID_X, index: 0 });
		const payer = df.unfreezeUtxo(TXID_X, 0);
		await new Promise((resolve) => setImmediate(resolve));
		const entryX = (): IUtxo | undefined =>
			wallet
				.listFrozenUtxos()
				.find((f) => f.tx_hash === TXID_X && f.tx_pos === 0);
		expect(entryX()?.freezeTag).to.equal('direct-funding');
		release();
		const [y, x, released] = await Promise.all([userY, userX, payer]);
		expect(y.isOk() && x.isOk()).to.equal(true);
		expect(released, 'the operator now owns the freeze').to.equal(false);
		expect(entryX()?.freezeTag).to.equal(undefined);
		const stored = store.get(
			wallet.getWalletDataKey('blacklistedUtxos')
		) as IUtxo[];
		expect(
			stored.some((f) => f.tx_hash === TXID_X && f.tx_pos === 0),
			'the operator freeze in storage'
		).to.equal(true);
	});

	it('counts a freeze the operator already lifted as released (issue #1422)', async () => {
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.freezeUtxo(TXID_X, 0)).to.equal(true);
		const lifted = await wallet.unfreezeUtxo({ txid: TXID_X, index: 0 });
		expect(lifted.isOk()).to.equal(true);
		expect(await df.unfreezeUtxo(TXID_X, 0)).to.equal(true);
	});

	it('reports a release storage refused, and keeps its freeze (issue #1422)', async () => {
		const df = directFundingWallet(wallet, NETWORK);
		expect(await df.freezeUtxo(TXID_X, 0)).to.equal(true);
		refuseBlacklistWrites = true;
		expect(await df.unfreezeUtxo(TXID_X, 0)).to.equal(false);
		const entry = wallet
			.listFrozenUtxos()
			.find((f) => f.tx_hash === TXID_X && f.tx_pos === 0);
		expect(entry?.freezeTag).to.equal('direct-funding');
	});

	it('clears an interrupted payment whose freeze the operator lifted, and retries it (issue #1422)', async () => {
		const coin = makeCoin();
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		wallet.data.utxos.push({
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 100,
			tx_hash: coin.txidHex,
			tx_pos: coin.vout,
			value: Number(coin.valueSat),
			publicKey: source.publicKey
		});
		// The test coin signs; the real wallet holds its reservation.
		const df = directFundingWallet(wallet, NETWORK);
		const payer = new FakeSenderWallet([coin]);
		payer.listSpendable = (): IDfSenderCoin[] =>
			payer.coins.filter((c) => !wallet.isUtxoFrozen(c.txidHex, c.vout));
		payer.freezeUtxo = df.freezeUtxo;
		payer.unfreezeUtxo = df.unfreezeUtxo;
		const storage = memoryStorage();
		const request = mintRequest();
		const life = (): {
			sender: DirectFundingSender;
			payments: DirectFundingPaymentStore;
		} => {
			const payments = new DirectFundingPaymentStore({ storage });
			payments.restore();
			const lane = new ScriptedReceiverLane(
				request,
				acceptingReceiver(request, { noReceipt: true })
			);
			const sender = new DirectFundingSender(
				{
					wallet: payer,
					registry: registryWith(lane),
					payments,
					chainHash: (): Buffer => chainHashForNetwork(Network.REGTEST)
				},
				{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
			);
			return { sender, payments };
		};

		await life().sender.send(request.encoded, { amountSat: 100_000n });
		// A run that died after reserving the coin and before the witness left.
		const rows = JSON.parse(storage.loadWalletData(DF_PAYMENTS_STORAGE_KEY)!);
		delete rows[0].witness;
		delete rows[0].witnessSent;
		delete rows[0].attestation;
		delete rows[0].negotiatedTx;
		delete rows[0].fundingTxid;
		rows[0].status = 'OFFERED';
		rows[0].frozen = false;
		storage.saveWalletData(DF_PAYMENTS_STORAGE_KEY, JSON.stringify(rows));
		expect(rows[0].freezeReleased).to.equal(false);
		const lifted = await wallet.unfreezeUtxo({
			txid: coin.txidHex,
			index: coin.vout
		});
		expect(lifted.isOk()).to.equal(true);

		const { sender, payments } = life();
		sender.start();
		try {
			await flush();
			expect(payments.list()[0].freezeReleased).to.equal(true);
			const retried = await sender.send(request.encoded, {
				amountSat: 100_000n
			});
			expect(retried.status).to.equal('SIGNED_PENDING');
			expect(retried.spentTxid).to.equal(coin.txidHex);
		} finally {
			sender.stop();
		}
	});

	it('retries cleanup an operator freeze refused once the operator lifts it (issue #1460)', async () => {
		const coin = makeCoin();
		const source = wallet.data.addressIndex[EAddressType.p2wpkh];
		wallet.data.utxos.push({
			address: source.address,
			index: source.index,
			path: source.path,
			scriptHash: source.scriptHash,
			height: 100,
			tx_hash: coin.txidHex,
			tx_pos: coin.vout,
			value: Number(coin.valueSat),
			publicKey: source.publicKey
		});
		const df = directFundingWallet(wallet, NETWORK);
		const payer = new FakeSenderWallet([coin]);
		payer.listSpendable = (): IDfSenderCoin[] =>
			payer.coins.filter((c) => !wallet.isUtxoFrozen(c.txidHex, c.vout));
		payer.freezeUtxo = df.freezeUtxo;
		payer.unfreezeUtxo = df.unfreezeUtxo;
		const storage = memoryStorage();
		const request = mintRequest();
		const life = (): {
			sender: DirectFundingSender;
			payments: DirectFundingPaymentStore;
		} => {
			const payments = new DirectFundingPaymentStore({ storage });
			payments.restore();
			const lane = new ScriptedReceiverLane(
				request,
				acceptingReceiver(request, { noReceipt: true })
			);
			const sender = new DirectFundingSender(
				{
					wallet: payer,
					registry: registryWith(lane),
					payments,
					chainHash: (): Buffer => chainHashForNetwork(Network.REGTEST)
				},
				{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
			);
			return { sender, payments };
		};

		await life().sender.send(request.encoded, { amountSat: 100_000n });
		const rows = JSON.parse(storage.loadWalletData(DF_PAYMENTS_STORAGE_KEY)!);
		delete rows[0].witness;
		delete rows[0].witnessSent;
		delete rows[0].attestation;
		delete rows[0].negotiatedTx;
		delete rows[0].fundingTxid;
		rows[0].status = 'OFFERED';
		rows[0].frozen = false;
		storage.saveWalletData(DF_PAYMENTS_STORAGE_KEY, JSON.stringify(rows));
		expect(rows[0].freezeReleased).to.equal(false);
		// The operator takes the reservation over, so startup cleanup must refuse.
		const taken = await wallet.freezeUtxo({
			txid: coin.txidHex,
			index: coin.vout
		});
		expect(taken.isOk()).to.equal(true);

		const { sender, payments } = life();
		sender.start();
		try {
			await flush();
			expect(wallet.isUtxoFrozen(coin.txidHex, coin.vout)).to.equal(true);
			expect(payments.list()[0].freezeReleased).to.equal(false);
			let refused: unknown;
			try {
				await sender.send(request.encoded, { amountSat: 100_000n });
			} catch (e) {
				refused = e;
			}
			expect(refused).to.have.property(
				'code',
				DirectFundingErrorCode.NO_SUITABLE_UTXO
			);
			expect(wallet.isUtxoFrozen(coin.txidHex, coin.vout)).to.equal(true);

			const lifted = await wallet.unfreezeUtxo({
				txid: coin.txidHex,
				index: coin.vout
			});
			expect(lifted.isOk()).to.equal(true);
			await sender.reconcile();
			await flush();
			expect(payments.list()[0].freezeReleased).to.equal(true);
			const retried = await sender.send(request.encoded, {
				amountSat: 100_000n
			});
			expect(retried.status).to.equal('SIGNED_PENDING');
			expect(retried.spentTxid).to.equal(coin.txidHex);
		} finally {
			sender.stop();
		}
	});
});

describe('direct funding wallet: what counts as confirmed', () => {
	const tx = (
		txid: string,
		height: number
	): { txid: string; height: number; vin: [] } => ({ txid, height, vin: [] });

	it('reads an Electrum mempool height as unconfirmed', () => {
		// -1 is an unconfirmed transaction with an unconfirmed parent, and a
		// truthiness test reads it as mined: the payer would call the funding
		// CONFIRMED and release the coin while it is still in a mempool.
		for (const height of [-1, 0]) {
			const df = directFundingWallet(
				stubWallet({ transactions: { [TXID]: tx(TXID, height) } }),
				NETWORK
			);
			expect(df.txStatus(TXID)).to.deep.equal({
				known: true,
				confirmed: false
			});
		}
		const mined = directFundingWallet(
			stubWallet({ transactions: { [TXID]: tx(TXID, 100) } }),
			NETWORK
		);
		expect(mined.txStatus(TXID)?.confirmed).to.equal(true);
		expect(mined.txStatus(CONFLICT)).to.equal(null);
	});

	it('answers 0 for a tip it does not have', () => {
		// The locktime check refuses a future-locked transaction outright rather
		// than judge it against a height this wallet is guessing at.
		expect(directFundingWallet(stubWallet(), NETWORK).blockHeight()).to.equal(
			800_000
		);
		expect(
			directFundingWallet(
				stubWallet({ header: 'throws' }),
				NETWORK
			).blockHeight()
		).to.equal(0);
	});

	it('does not call a conflict won until it has actually confirmed', () => {
		const spend = (height: number): Record<string, never> =>
			({
				[CONFLICT]: {
					txid: CONFLICT,
					height,
					vin: [{ txid: TXID, vout: 0 }]
				}
			}) as unknown as Record<string, never>;
		const mempool = directFundingWallet(
			stubWallet({ transactions: spend(-1) }),
			NETWORK
		);
		// A FAILED here releases the payer's coin against a spend that may yet be
		// evicted, and rev 2 makes the conflict terminal only once it is mined.
		expect(mempool.confirmedSpendOf(TXID, 0)).to.equal(null);
		const mined = directFundingWallet(
			stubWallet({ transactions: spend(200) }),
			NETWORK
		);
		expect(mined.confirmedSpendOf(TXID, 0)).to.equal(CONFLICT);
	});
});
