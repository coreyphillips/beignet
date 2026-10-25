/**
 * Regression test for issue #1859: a notification for a UTXO tracked beyond
 * the gap limit listed the UTXOs at that address index, discarded the answer,
 * and then ran the wallet refresh, which listed them again.
 *
 * Fully OFFLINE: the client helpers are stubbed with a counting fake server.
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
	IWalletData,
	ok,
	Result,
	TTxDetails,
	Wallet
} from '../../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const SERVER = {
	host: '127.0.0.1',
	ssl: 65516,
	tcp: 65516,
	protocol: EProtocol.tcp
};

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

/** Pays receive addresses 1 to 6 and, as output 6, the old address 0. */
const FUNDING = 'f0'.repeat(32);
/** Spends the coins at addresses 1 to 6, so only address 0 holds one. */
const SWEEP = 'f1'.repeat(32);
/** The external transaction every payment from outside spends. */
const PARENT = 'ee'.repeat(32);
/** A second payment to the old address. */
const REUSE = 'a1'.repeat(32);
/** Spends the old address's coin. */
const SPEND = 'a2'.repeat(32);

type TBatch<T> = { key: string; data: T[] };
/** The UTXO listing sends its batch keyed by script hash. */
type TUtxoBatch = { key: string; data: Record<string, IAddress> };
type TServed = TTxDetails & { confirmations?: number };
type TNotification = [string, string | null];
type THistory = { tx_hash: string; height: number };
type TUnspent = THistory & { tx_pos: number; value: number };

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

describe('old address notification requests (#1859)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** Receive addresses 0 to 6. */
	let receive: IAddress[];
	/** The old address: index 0, below the window once 1 to 6 are used. */
	let old: IAddress;
	let history: Map<string, THistory[]>;
	let unspent: Map<string, TUnspent[]>;
	let served: Map<string, TServed>;
	/** What the client has subscribed. A stopped client forgets it. */
	let subscribed: Set<string>;
	let headerHandler: ((data: unknown[]) => Promise<void>) | undefined;
	let scriptHashHandler: ((data: TNotification) => Promise<void>) | undefined;
	/** The script hashes of each UTXO listing request, in order. */
	let listings: string[][];
	/** Holds the next UTXO listing until releaseListing is called. */
	let holdNextListing: boolean;
	let releaseListing: (() => void) | undefined;

	const statusOf = (scriptHash: string): string | null => {
		const entries = history.get(scriptHash) ?? [];
		return entries.length
			? entries.map((h) => `${h.tx_hash}:${h.height}`).join(',')
			: null;
	};

	/** How many listing requests named the old address. */
	const oldListed = (): number =>
		listings.filter((batch) => batch.includes(old.scriptHash)).length;

	beforeEach(async function () {
		history = new Map();
		unspent = new Map();
		served = new Map();
		subscribed = new Set();
		headerHandler = undefined;
		scriptHashHandler = undefined;
		listings = [];
		holdNextListing = false;
		releaseListing = undefined;
		let peer: { host: string; port: number; protocol: EProtocol } | undefined;
		sinon.stub(electrumHelpers, 'getConnectedPeer').callsFake(() => peer);
		sinon.stub(electrumHelpers, 'start').callsFake(async () => {
			peer = { host: '127.0.0.1', port: 65516, protocol: EProtocol.tcp };
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
				const batch = Object.values(scriptHashes.data);
				listings.push(batch.map((a) => a.scriptHash));
				if (holdNextListing) {
					holdNextListing = false;
					await new Promise<void>((resolve) => {
						releaseListing = resolve;
					});
				}
				return {
					error: false,
					data: batch.map((a) => ({
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
					data: txHashes.data.map((h) => ({
						data: h,
						param: h.tx_hash,
						result: served.get(h.tx_hash)
					}))
				})
			);

		wallet = await createWallet();
		const generated = await wallet.generateAddresses({
			addressAmount: 7,
			changeAddressAmount: 0,
			addressIndex: 0,
			addressType: EAddressType.p2wpkh
		});
		if (generated.isErr()) throw generated.error;
		receive = Object.values(generated.value.addresses).sort(
			(a, b) => a.index - b.index
		);
		old = receive[0];
		fundAndSweep();

		const connected = await wallet.connectToElectrum();
		if (connected.isErr()) throw connected.error;
		await waitFor(
			() => !!headerHandler && wallet.data.header.height >= 100,
			'the header subscription'
		);
		const refreshed = await wallet.refreshWallet();
		if (refreshed.isErr()) throw refreshed.error;

		expect(wallet.data.addressIndex[EAddressType.p2wpkh].index).to.equal(7);
		expect(
			Object.keys(wallet.electrum.utxoScanAddresses({})),
			'the old address is outside the window'
		).to.not.include(old.scriptHash);
		expect(subscribed.has(old.scriptHash), 'its coin is watched').to.equal(
			true
		);
		expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([FUNDING]);
		expect(wallet.data.balance).to.equal(100_000);
	});

	afterEach(async function () {
		releaseListing?.();
		await wallet?.stop();
		sinon.restore();
	});

	const createWallet = async (): Promise<Wallet> => {
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
			// The test drives the refresh itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			logger: createConsoleLogger('silent'),
			storage: {
				setData: async <K extends keyof IWalletData>(
					_key: string,
					_value: IWalletData[K]
				): Promise<Result<boolean>> => ok(true)
			}
		});
		if (res.isErr()) throw res.error;
		res.value.electrum.stopConnectionPolling();
		res.value.electrum.batchDelay = 0;
		return res.value;
	};

	/** One transaction pays addresses 1 to 6 and the old address, and a
	 *  later one spends all but the old address's coin. */
	const fundAndSweep = (): void => {
		served.set(
			PARENT,
			details(PARENT, [{ txid: 'dd'.repeat(32), vout: 0 }], [[EXTERNAL, 1]], 60)
		);
		served.set(
			FUNDING,
			details(
				FUNDING,
				[{ txid: PARENT, vout: 0 }],
				[
					...receive.slice(1).map((a): [string, number] => [a.address, 0.001]),
					[old.address, 0.001],
					[EXTERNAL, 0.9929]
				],
				51
			)
		);
		served.set(
			SWEEP,
			details(
				SWEEP,
				receive.slice(1).map((_, vout) => ({ txid: FUNDING, vout })),
				[[EXTERNAL, 0.0059]],
				41
			)
		);
		for (const address of receive.slice(1)) {
			history.set(address.scriptHash, [
				{ tx_hash: FUNDING, height: 50 },
				{ tx_hash: SWEEP, height: 60 }
			]);
		}
		history.set(old.scriptHash, [{ tx_hash: FUNDING, height: 50 }]);
		unspent.set(old.scriptHash, [
			{ tx_hash: FUNDING, tx_pos: 6, height: 50, value: 100_000 }
		]);
	};

	/** A mempool payment from outside to the old address. */
	const payOldAgain = (): void => {
		served.set(
			REUSE,
			details(
				REUSE,
				[{ txid: PARENT, vout: 0 }],
				[
					[old.address, 0.002],
					[EXTERNAL, 0.9979]
				],
				0
			)
		);
		history.get(old.scriptHash)?.push({ tx_hash: REUSE, height: 0 });
		unspent.get(old.scriptHash)?.push({
			tx_hash: REUSE,
			tx_pos: 0,
			height: 0,
			value: 200_000
		});
	};

	const notifyOld = async (): Promise<void> => {
		if (!scriptHashHandler)
			throw new Error('No script hash handler was wired.');
		await scriptHashHandler([old.scriptHash, statusOf(old.scriptHash)]);
	};

	const settled = (): Promise<void> =>
		waitFor(() => !wallet.isRefreshing, 'the refresh to settle');

	const utxoIds = (): string[] =>
		wallet.data.utxos.map((u) => `${u.tx_hash}:${u.tx_pos}`).sort();

	it('lists a reused old address once when it is paid again', async function () {
		payOldAgain();
		listings = [];

		await notifyOld();
		await settled();

		expect(listings.length, 'one UTXO listing').to.equal(1);
		expect(oldListed(), 'the old address is listed by the refresh').to.equal(1);
		expect(utxoIds()).to.deep.equal([`${REUSE}:0`, `${FUNDING}:6`].sort());
		expect(wallet.data.balance).to.equal(300_000);
		expect(wallet.data.transactions[REUSE]?.type).to.equal(
			EPaymentType.received
		);
		expect(wallet.data.transactions[REUSE]?.valueSats).to.equal(200_000);
	});

	it('lists a spent old coin once and drops it', async function () {
		served.set(
			SPEND,
			details(SPEND, [{ txid: FUNDING, vout: 6 }], [[EXTERNAL, 0.0009]], 0)
		);
		history.get(old.scriptHash)?.push({ tx_hash: SPEND, height: 0 });
		unspent.set(old.scriptHash, []);
		listings = [];

		await notifyOld();
		await settled();

		expect(listings.length, 'one UTXO listing').to.equal(1);
		expect(oldListed()).to.equal(1);
		expect(wallet.data.utxos).to.deep.equal([]);
		expect(wallet.data.balance).to.equal(0);
	});

	it('stays disconnected when its old-address callback disconnects', async function () {
		let disconnected: Promise<void> | undefined;
		const subscription = await wallet.electrum.subscribeToAddresses({
			scriptHashes: [old.scriptHash],
			onReceive: () => {
				disconnected = wallet.electrum.disconnect();
			}
		});
		if (subscription.isErr()) throw subscription.error;
		const refresh = sinon.spy(wallet, 'refreshWallet');
		const start = electrumHelpers.start as sinon.SinonStub;
		start.resetHistory();
		payOldAgain();

		await notifyOld();
		await disconnected;
		await settled();

		expect(refresh.notCalled).to.equal(true);
		expect(start.notCalled).to.equal(true);
		expect(wallet.electrum.isDisconnected).to.equal(true);
	});

	it('finds a payment to an old address announced while a refresh was listing', async function () {
		holdNextListing = true;
		listings = [];
		const running = wallet.refreshWallet();
		await waitFor(() => !!releaseListing, 'the held listing');
		payOldAgain();

		await notifyOld();
		releaseListing?.();
		const result = await running;
		if (result.isErr()) throw result.error;
		await settled();

		expect(listings.length, 'the held refresh and its rerun').to.equal(2);
		expect(oldListed()).to.equal(2);
		expect(utxoIds()).to.deep.equal([`${REUSE}:0`, `${FUNDING}:6`].sort());
		expect(wallet.data.balance).to.equal(300_000);
	});

	it('lists an old address once for a change it missed while disconnected', async function () {
		await wallet.electrum.disconnect();
		payOldAgain();
		listings = [];

		const connected = await wallet.connectToElectrum();
		if (connected.isErr()) throw connected.error;
		await waitFor(
			() => wallet.data.utxos.some((u) => u.tx_hash === REUSE),
			'the payment the reconnect found'
		);
		await settled();

		expect(listings.length, 'one UTXO listing').to.equal(1);
		expect(oldListed()).to.equal(1);
		expect(wallet.data.balance).to.equal(300_000);
	});
});
