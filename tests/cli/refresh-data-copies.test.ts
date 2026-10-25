/**
 * Regression test for issue #1856: every successful refresh deep-copied and
 * froze the whole wallet for its caller, including the refreshes Electrum,
 * the daemon and the wallet run themselves and never read. refreshWallet and
 * rescanAddresses still answer with such a copy; the rest copy nothing.
 *
 * Fully OFFLINE: the client helpers are stubbed with a fake server, and the
 * fixture cases stub the refresh's steps.
 */

import { Block } from 'bitcoinjs-lib';
import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	createConsoleLogger,
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	IAddress,
	IGetUtxosResponse,
	IWalletData,
	ok,
	Result,
	TTxDetails,
	Wallet
} from '../../src';
import { liveWalletData, refreshLiveWallet } from '../../src/wallet/live-data';
import { seedWalletRecords } from '../wallet-records-fixture';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const SERVER = {
	host: '127.0.0.1',
	ssl: 65515,
	tcp: 65515,
	protocol: EProtocol.tcp
};

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
/** The external transaction every payment spends. */
const PARENT = 'ee'.repeat(32);
/** A mempool payment to receive address 0. */
const PAYMENT = 'b1'.repeat(32);
/** What a server with a txindex answers for a transaction it never saw. */
const TXINDEX_MISS =
	'No such mempool or blockchain transaction. Use gettransaction for wallet transactions.';

type TBatch<T> = { key: string; data: T[] };
/** The UTXO listing sends its batch keyed by script hash. */
type TUtxoBatch = { key: string; data: Record<string, IAddress> };
type TServed = TTxDetails & { confirmations?: number };
type TNotification = [string, string | null];
type THistory = { tx_hash: string; height: number };
type TUnspent = THistory & { tx_pos: number; value: number };

/** The private members the cases below reach through a cast. */
type TWalletInternals = {
	_refresh: () => Promise<Result<void>>;
	_rescanAddresses: () => Promise<Result<void>>;
	_refreshFailed: boolean;
	setZeroIndexAddresses: () => Promise<Result<string>>;
	updateAddressIndexes: () => Promise<Result<string>>;
};

const internals = (wallet: Wallet): TWalletInternals =>
	wallet as unknown as TWalletInternals;

const dataGetter = Object.getOwnPropertyDescriptor(Wallet.prototype, 'data');

/** How many copies of a wallet's data fn made: Wallet.data makes one per read. */
const copiesDuring = async (fn: () => Promise<void>): Promise<number> => {
	if (!dataGetter?.get) throw new Error('Wallet.data is not a getter.');
	const read = dataGetter.get;
	let copies = 0;
	Object.defineProperty(Wallet.prototype, 'data', {
		...dataGetter,
		get(this: Wallet) {
			copies += 1;
			return read.call(this);
		}
	});
	try {
		await fn();
		return copies;
	} finally {
		Object.defineProperty(Wallet.prototype, 'data', dataGetter);
	}
};

/** Parseable headers, each carrying the id of the one below it, so an
 *  ordinary block is not read as a rollback. */
const chain: { hex: string; hash: string }[] = [];
const headerAt = (height: number): string => {
	while (chain.length <= height) {
		const header = Buffer.alloc(80);
		header.writeUInt32LE(1, 0);
		const below = chain[chain.length - 1];
		if (below) Buffer.from(below.hash, 'hex').reverse().copy(header, 4);
		header.writeUInt32LE(chain.length, 76);
		const hex = header.toString('hex');
		chain.push({ hex, hash: Block.fromHex(hex).getId() });
	}
	return chain[height].hex;
};

const details = (
	txid: string,
	vin: Array<{ txid: string; vout: number }>,
	vout: Array<[string, number]>,
	confirmations: number
): TServed =>
	({
		txid,
		hash: txid,
		hex: '00',
		locktime: 0,
		size: 222,
		vsize: 141,
		weight: 561,
		version: 2,
		vin: vin.map((v) => ({
			...v,
			scriptSig: { asm: '', hex: '' },
			txinwitness: [],
			sequence: 0xfffffffd
		})),
		vout: vout.map(([address, value], n) => ({
			n,
			value,
			scriptPubKey: { asm: '', hex: '', address }
		})),
		confirmations
	}) as TServed;

const waitFor = async (
	predicate: () => boolean,
	what: string
): Promise<void> => {
	const deadline = Date.now() + 10000;
	while (!predicate()) {
		if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
};

const settled = (wallet: Wallet): Promise<void> =>
	waitFor(() => !wallet.isRefreshing, 'the refresh to settle');

/** Whether the first call `spy` saw succeeded. */
const succeeded = async (spy: {
	firstCall: { returnValue: unknown };
}): Promise<boolean> =>
	((await spy.firstCall.returnValue) as Result<void>).isOk();

describe('refresh data copies (#1856)', function () {
	this.timeout(60000);

	let history: Map<string, THistory[]>;
	let unspent: Map<string, TUnspent[]>;
	let served: Map<string, TServed>;
	/** Transactions the server answers TXINDEX_MISS for. */
	let missing: Set<string>;
	/** What the client has subscribed. A stopped client forgets it. */
	let subscribed: Set<string>;
	let headerHandler: ((data: unknown[]) => Promise<void>) | undefined;
	let scriptHashHandler: ((data: TNotification) => Promise<void>) | undefined;
	/** Holds the next UTXO listing until releaseListing is called. */
	let holdNextListing: boolean;
	let releaseListing: (() => void) | undefined;
	/** Answers every UTXO listing with an error while set. */
	let failListings: boolean;
	let opened: Wallet[];

	const statusOf = (scriptHash: string): string | null => {
		const entries = history.get(scriptHash) ?? [];
		return entries.length
			? entries.map((h) => `${h.tx_hash}:${h.height}`).join(',')
			: null;
	};

	beforeEach(function () {
		history = new Map();
		unspent = new Map();
		served = new Map([
			[
				PARENT,
				details(
					PARENT,
					[{ txid: 'dd'.repeat(32), vout: 0 }],
					[[EXTERNAL, 1]],
					60
				)
			]
		]);
		missing = new Set();
		subscribed = new Set();
		headerHandler = undefined;
		scriptHashHandler = undefined;
		holdNextListing = false;
		releaseListing = undefined;
		failListings = false;
		opened = [];
		let peer: { host: string; port: number; protocol: EProtocol } | undefined;
		sinon.stub(electrumHelpers, 'getConnectedPeer').callsFake(() => peer);
		sinon.stub(electrumHelpers, 'start').callsFake(async () => {
			peer = { host: '127.0.0.1', port: 65515, protocol: EProtocol.tcp };
			return { error: false, data: 'connected' };
		});
		sinon.stub(electrumHelpers, 'stop').callsFake(async () => {
			peer = undefined;
			subscribed.clear();
			return { error: false, data: 'stopped' };
		});
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashBalance')
			.resolves({ error: false, data: { confirmed: 0, unconfirmed: 0 } });
		sinon
			.stub(electrumHelpers, 'subscribeHeader')
			.callsFake(
				async ({
					onReceive
				}: {
					onReceive: (data: unknown[]) => Promise<void>;
				}) => {
					if (headerHandler)
						return { error: false, data: 'Already Subscribed.' };
					headerHandler = onReceive;
					return { error: false, data: { height: 100, hex: headerAt(100) } };
				}
			);
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.callsFake(
				async ({
					scriptHash,
					onReceive
				}: {
					scriptHash: string;
					onReceive: (data: TNotification) => Promise<void>;
				}) => {
					scriptHashHandler ??= onReceive;
					if (subscribed.has(scriptHash)) {
						return { error: false, data: 'Already Subscribed.' };
					}
					subscribed.add(scriptHash);
					return { error: false, data: statusOf(scriptHash) };
				}
			);
		sinon
			.stub(electrumHelpers, 'getFeeEstimate')
			.resolves({ error: false, data: 0.0001 });
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => ({
					error: false,
					data: scriptHashes.data.map((a) => ({
						data: a,
						param: a.scriptHash,
						result: history.get(a.scriptHash) ?? []
					}))
				})
			);
		sinon
			.stub(electrumHelpers, 'listUnspentAddressScriptHashes')
			.callsFake(async ({ scriptHashes }: { scriptHashes: TUtxoBatch }) => {
				if (holdNextListing) {
					holdNextListing = false;
					await new Promise<void>((resolve) => {
						releaseListing = resolve;
					});
				}
				if (failListings) return { error: true, data: 'server went away' };
				return {
					error: false,
					data: Object.values(scriptHashes.data).map((a) => ({
						data: a,
						param: a.scriptHash,
						result: unspent.get(a.scriptHash) ?? []
					}))
				};
			});
		sinon
			.stub(electrumHelpers, 'getTransactions')
			.callsFake(
				async ({ txHashes }: { txHashes: TBatch<{ tx_hash: string }> }) => ({
					error: false,
					data: txHashes.data.map((h) =>
						missing.has(h.tx_hash)
							? {
									data: h,
									param: h.tx_hash,
									error: { code: 2, message: TXINDEX_MISS }
							  }
							: { data: h, param: h.tx_hash, result: served.get(h.tx_hash) }
					)
				})
			);
	});

	afterEach(async function () {
		releaseListing?.();
		for (const wallet of opened) await wallet.stop();
		sinon.restore();
	});

	const createWallet = async (refreshOnCreate = false): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			gapLimitOptions: {
				lookBehind: 2,
				lookAhead: 2,
				lookBehindChange: 2,
				lookAheadChange: 2
			},
			electrumOptions: { net, tls, servers: SERVER },
			feeEstimationSource: 'electrum',
			disableRefreshOnCreate: !refreshOnCreate,
			logger: createConsoleLogger('silent'),
			storage: {
				setData: async <K extends keyof IWalletData>(
					_key: string,
					_value: IWalletData[K]
				): Promise<Result<boolean>> => ok(true)
			}
		});
		if (res.isErr()) throw res.error;
		opened.push(res.value);
		res.value.electrum.stopConnectionPolling();
		res.value.electrum.batchDelay = 0;
		return res.value;
	};

	/** A connected wallet after its first refresh. */
	const open = async (): Promise<Wallet> => {
		const wallet = await createWallet();
		const connected = await wallet.connectToElectrum();
		if (connected.isErr()) throw connected.error;
		await waitFor(
			() => !!headerHandler && liveWalletData(wallet).header.height >= 100,
			'the header subscription'
		);
		const refreshed = await wallet.refreshWallet();
		if (refreshed.isErr()) throw refreshed.error;
		return wallet;
	};

	const firstReceiveAddress = (wallet: Wallet): IAddress => {
		const addresses = liveWalletData(wallet).addresses[EAddressType.p2wpkh];
		const first = Object.values(addresses).find((a) => a.index === 0);
		if (!first) throw new Error('No receive address 0.');
		return first;
	};

	/** A mempool payment of 100,000 sats to `address`, announced. */
	const pay = async (address: IAddress): Promise<void> => {
		served.set(
			PAYMENT,
			details(
				PAYMENT,
				[{ txid: PARENT, vout: 0 }],
				[
					[address.address, 0.001],
					[EXTERNAL, 0.9989]
				],
				0
			)
		);
		history.set(address.scriptHash, [{ tx_hash: PAYMENT, height: 0 }]);
		unspent.set(address.scriptHash, [
			{ tx_hash: PAYMENT, tx_pos: 0, height: 0, value: 100_000 }
		]);
		if (!scriptHashHandler)
			throw new Error('No script hash handler was wired.');
		await scriptHashHandler([address.scriptHash, statusOf(address.scriptHash)]);
	};

	describe('a refresh no caller reads', function () {
		it('copies nothing when its caller only waits for it', async function () {
			const wallet = await open();
			let refreshed: Result<unknown> | undefined;

			const copies = await copiesDuring(async () => {
				refreshed = await refreshLiveWallet(wallet);
			});

			expect(refreshed?.isOk()).to.equal(true);
			expect(copies).to.equal(0);
		});

		it('copies nothing for a script hash notification', async function () {
			const wallet = await open();
			const refresh = sinon.spy(internals(wallet), '_refresh');
			const address = firstReceiveAddress(wallet);

			const copies = await copiesDuring(async () => {
				await pay(address);
				await settled(wallet);
			});

			expect(refresh.calledOnce, 'the notification refreshed').to.equal(true);
			expect(copies).to.equal(0);
			const data = liveWalletData(wallet);
			expect(data.balance).to.equal(100_000);
			expect(data.transactions[PAYMENT]?.type).to.equal(EPaymentType.received);
		});

		it('copies nothing for a block that owes a full refresh', async function () {
			const wallet = await open();
			const refresh = sinon.spy(internals(wallet), '_refresh');
			internals(wallet)._refreshFailed = true;
			if (!headerHandler) throw new Error('No header handler was wired.');
			const onBlock = headerHandler;

			const copies = await copiesDuring(async () => {
				await onBlock([{ height: 101, hex: headerAt(101) }]);
				await settled(wallet);
			});

			expect(refresh.calledOnce, 'the block refreshed').to.equal(true);
			expect(copies).to.equal(0);
			expect(liveWalletData(wallet).header.height).to.equal(101);
		});

		it("copies nothing for Wallet.create's first refresh", async function () {
			const refresh = sinon.spy(
				Wallet.prototype as unknown as TWalletInternals,
				'_refresh'
			);
			let refreshed: Result<void> | undefined;

			const copies = await copiesDuring(async () => {
				await createWallet(true);
				await waitFor(() => refresh.called, 'the first refresh');
				refreshed = await refresh.firstCall.returnValue;
			});

			expect(refresh.calledOnce).to.equal(true);
			expect(refreshed?.isOk(), 'the first refresh succeeded').to.equal(true);
			expect(copies).to.equal(0);
		});

		it('copies nothing for the refresh switchNetwork starts', async function () {
			const wallet = await open();
			const refresh = sinon.spy(internals(wallet), '_refresh');

			const copies = await copiesDuring(async () => {
				const switched = await wallet.switchNetwork(
					EAvailableNetworks.signet,
					SERVER
				);
				if (switched.isErr()) throw switched.error;
				await waitFor(() => refresh.called, 'the refresh after the switch');
				await settled(wallet);
			});

			expect(refresh.calledOnce).to.equal(true);
			expect(await succeeded(refresh)).to.equal(true);
			expect(copies).to.equal(0);
		});

		it('copies nothing for the refresh updateAddressType runs', async function () {
			const wallet = await open();
			const refresh = sinon.spy(internals(wallet), '_refresh');

			const copies = await copiesDuring(() =>
				wallet.updateAddressType(EAddressType.p2wpkh)
			);

			expect(refresh.calledOnce).to.equal(true);
			expect(await succeeded(refresh)).to.equal(true);
			expect(copies).to.equal(0);
		});

		it("copies nothing for the ghost repair's rescan", async function () {
			const wallet = await open();
			const address = firstReceiveAddress(wallet);
			await pay(address);
			await settled(wallet);
			expect(liveWalletData(wallet).unconfirmedTransactions).to.have.key(
				PAYMENT
			);
			// The payment leaves the mempool, and the server never saw it.
			history.set(address.scriptHash, []);
			unspent.set(address.scriptHash, []);
			missing.add(PAYMENT);
			const rescan = sinon.spy(internals(wallet), '_rescanAddresses');

			const copies = await copiesDuring(async () => {
				const checked = await wallet.checkUnconfirmedTransactions();
				if (checked.isErr()) throw checked.error;
				await settled(wallet);
			});

			expect(rescan.calledOnce, 'the ghost was repaired').to.equal(true);
			expect(await succeeded(rescan)).to.equal(true);
			expect(copies).to.equal(0);
			const data = liveWalletData(wallet);
			expect(data.transactions[PAYMENT]?.exists).to.equal(false);
			expect(data.balance).to.equal(0);
		});

		it('copies nothing when stop() waits for it', async function () {
			const wallet = await open();
			holdNextListing = true;
			let refreshed: Result<unknown> | undefined;

			const copies = await copiesDuring(async () => {
				const running = refreshLiveWallet(wallet);
				await waitFor(() => !!releaseListing, 'the held listing');
				const stopping = wallet.stop({ refreshTimeout: 5000 });
				releaseListing?.();
				const stopped = await stopping;
				if (stopped.isErr()) throw stopped.error;
				expect(stopped.value, 'nothing was abandoned').to.equal(
					'Wallet stopped.'
				);
				refreshed = await running;
			});

			expect(refreshed?.isOk(), 'the refresh finished first').to.equal(true);
			expect(copies).to.equal(0);
		});
	});

	describe('refreshWallet', function () {
		it('answers with a frozen copy of the data, apart from the live data', async function () {
			const wallet = await open();
			await pay(firstReceiveAddress(wallet));
			await settled(wallet);
			let refreshed: Result<IWalletData> | undefined;

			const copies = await copiesDuring(async () => {
				refreshed = await wallet.refreshWallet();
			});

			expect(copies).to.equal(1);
			if (!refreshed?.isOk()) throw new Error('The refresh failed.');
			const copy = refreshed.value;
			const live = liveWalletData(wallet);
			expect(copy).to.not.equal(live);
			expect(copy).to.deep.equal(live);
			expect(Object.isFrozen(copy)).to.equal(true);
			expect(Object.isFrozen(copy.transactions[PAYMENT])).to.equal(true);
			expect(Object.isFrozen(copy.utxos[0])).to.equal(true);
			expect(() => {
				copy.balance = 1;
			}).to.throw(TypeError);
			const updated = await wallet.updateData({ balance: 42 });
			if (updated.isErr()) throw updated.error;
			expect(copy.balance).to.equal(100_000);
			expect(live.balance).to.equal(42);
		});

		it('hands every caller one refresh answers the same copy', async function () {
			const wallet = await open();
			holdNextListing = true;
			let answers: Result<IWalletData>[] = [];
			let waited: Result<unknown>[] = [];

			const copies = await copiesDuring(async () => {
				const running = wallet.refreshWallet();
				await waitFor(() => !!releaseListing, 'the held listing');
				const queued = [
					wallet.refreshWallet(),
					wallet.refreshWallet(),
					wallet.refreshWallet()
				];
				const background = [
					refreshLiveWallet(wallet),
					refreshLiveWallet(wallet)
				];
				releaseListing?.();
				answers = await Promise.all([running, ...queued]);
				waited = await Promise.all(background);
			});

			expect(answers.every((r) => r.isOk())).to.equal(true);
			expect(waited.every((r) => r.isOk())).to.equal(true);
			const [first] = answers;
			if (!first.isOk()) throw first.error;
			expect(
				answers.every((r) => r.isOk() && r.value === first.value)
			).to.equal(true);
			expect(copies).to.equal(1);
		});

		it('copies once when it queues behind a refresh no caller reads', async function () {
			const wallet = await open();
			holdNextListing = true;
			let answer: Result<IWalletData> | undefined;

			const copies = await copiesDuring(async () => {
				const running = refreshLiveWallet(wallet);
				await waitFor(() => !!releaseListing, 'the held listing');
				const queued = wallet.refreshWallet();
				releaseListing?.();
				await running;
				answer = await queued;
			});

			expect(answer?.isOk()).to.equal(true);
			expect(copies).to.equal(1);
		});

		it('gives a forced refresh alongside one in flight its own copy', async function () {
			const wallet = await open();
			holdNextListing = true;
			let forced: Result<IWalletData> | undefined;

			const copies = await copiesDuring(async () => {
				const running = refreshLiveWallet(wallet);
				await waitFor(() => !!releaseListing, 'the held listing');
				forced = await wallet.refreshWallet({ force: true });
				releaseListing?.();
				await running;
			});

			expect(forced?.isOk()).to.equal(true);
			expect(copies).to.equal(1);
		});

		it('answers rescanAddresses with one copy', async function () {
			const wallet = await open();
			let rescanned: Result<IWalletData> | undefined;

			const copies = await copiesDuring(async () => {
				rescanned = await wallet.rescanAddresses({
					shouldClearAddresses: false
				});
			});

			expect(rescanned?.isOk()).to.equal(true);
			expect(copies).to.equal(1);
		});

		it('answers a failed refresh with its error and no copy', async function () {
			const wallet = await open();
			failListings = true;
			let answer: Result<IWalletData> | undefined;
			let waited: Result<unknown> | undefined;

			const copies = await copiesDuring(async () => {
				answer = await wallet.refreshWallet();
				waited = await refreshLiveWallet(wallet);
			});

			if (!answer?.isErr() || !waited?.isErr()) {
				throw new Error('Both refreshes should have failed.');
			}
			expect(answer.error.message).to.equal(waited.error.message);
			expect(copies).to.equal(0);
		});

		it('answers a stopped wallet with an error and no copy', async function () {
			const wallet = await open();
			const stopped = await wallet.stop();
			if (stopped.isErr()) throw stopped.error;
			let answer: Result<IWalletData> | undefined;

			const copies = await copiesDuring(async () => {
				answer = await wallet.refreshWallet();
			});

			if (!answer?.isErr()) throw new Error('The refresh should have failed.');
			expect(answer.error.message).to.equal('Wallet stopped.');
			expect(copies).to.equal(0);
		});
	});
});

describe('refresh data copies over unchanged fixtures (#1856)', function () {
	this.timeout(120000);

	let wallet: Wallet;

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions: { net, tls },
			remainOffline: true,
			disableRefreshOnCreate: true,
			logger: createConsoleLogger('silent')
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		// Every step answers as a server with nothing new would, so the
		// records are the subject.
		sinon
			.stub(internals(wallet), 'setZeroIndexAddresses')
			.resolves(ok('stubbed'));
		sinon
			.stub(internals(wallet), 'updateAddressIndexes')
			.resolves(ok('stubbed'));
		sinon
			.stub(wallet, 'refreshUtxos')
			.resolves(ok<IGetUtxosResponse>({ utxos: [], balance: 0 }));
		sinon
			.stub(wallet, 'updateTransactions')
			.resolves(ok<string | undefined>(undefined));
		sinon.stub(wallet.electrum, 'subscribeToAddresses').resolves(ok('stubbed'));
		sinon.stub(wallet, 'updateFeeEstimates').resolves(ok(wallet.feeEstimates));
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	for (const records of [1_000, 10_000, 50_000]) {
		it(`copies ${records} records only for refreshWallet`, async function () {
			seedWalletRecords(wallet, records);
			const before = JSON.stringify(liveWalletData(wallet));
			let waited: Result<unknown> | undefined;
			let answer: Result<IWalletData> | undefined;

			const background = await copiesDuring(async () => {
				waited = await refreshLiveWallet(wallet);
			});
			const answered = await copiesDuring(async () => {
				answer = await wallet.refreshWallet();
			});

			expect(waited?.isOk()).to.equal(true);
			expect(background).to.equal(0);
			expect(answered).to.equal(1);
			if (!answer?.isOk()) throw new Error('The refresh failed.');
			expect(JSON.stringify(liveWalletData(wallet))).to.equal(before);
			expect(JSON.stringify(answer.value)).to.equal(before);
		});
	}
});
