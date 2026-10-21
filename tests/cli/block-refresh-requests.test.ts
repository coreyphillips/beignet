/**
 * Regression test for issue #1663: every new block ran a full wallet refresh,
 * because change addresses were never subscribed and the block refresh was
 * what found a change output.
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
	TMessageDataMap,
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
	ssl: 65518,
	tcp: 65518,
	protocol: EProtocol.tcp
};

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

type TBatch<T> = { key: string; data: T[] };
/** The UTXO listing sends its batch keyed by script hash. */
type TUtxoBatch = { key: string; data: Record<string, IAddress> };
type TServed = TTxDetails & { confirmations?: number };
type TNotification = [string, string | null];

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
	vout: Array<[string, number]>
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
		}))
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

describe('block notification refresh requests (#1663)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** Script hash to the txid paying it. */
	let paid: Map<string, string>;
	/** The block each paying transaction is in, 0 for the mempool. */
	let mined: Map<string, number>;
	/** What the server answers for a transaction. Nothing for the rest. */
	let served: Map<string, TServed>;
	/** Every script hash the client was asked to subscribe. */
	let subscribed: Set<string>;
	let headerHandler: ((data: unknown[]) => Promise<void>) | undefined;
	let scriptHashHandler: ((data: TNotification) => Promise<void>) | undefined;
	let historyAsked: string[];
	let listings: number;
	let failNextListing: boolean;
	let transactionsAsked: string[];
	let messages: (keyof TMessageDataMap)[];

	beforeEach(async function () {
		paid = new Map();
		mined = new Map();
		served = new Map();
		subscribed = new Set();
		headerHandler = undefined;
		scriptHashHandler = undefined;
		historyAsked = [];
		listings = 0;
		failNextListing = false;
		transactionsAsked = [];
		messages = [];
		const heightOf = (scriptHash: string): number =>
			mined.get(paid.get(scriptHash) ?? '') ?? 0;
		let peer: { host: string; port: number; protocol: EProtocol } | undefined;
		sinon.stub(electrumHelpers, 'getConnectedPeer').callsFake(() => peer);
		sinon.stub(electrumHelpers, 'start').callsFake(async () => {
			peer = { host: '127.0.0.1', port: 65518, protocol: EProtocol.tcp };
			return { error: false, data: 'connected' };
		});
		sinon.stub(electrumHelpers, 'stop').callsFake(async () => {
			peer = undefined;
			return { error: false, data: 'stopped' };
		});
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashBalance')
			.resolves({ error: false, data: { confirmed: 0, unconfirmed: 0 } });
		// The client wires one handler per network and answers every later
		// subscribe with "Already Subscribed.".
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
					return { error: false, data: null };
				}
			);
		sinon
			.stub(electrumHelpers, 'getFeeEstimate')
			.resolves({ error: false, data: 0.0001 });
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => {
					historyAsked.push(...scriptHashes.data.map((a) => a.scriptHash));
					return {
						error: false,
						data: scriptHashes.data.map((a) => ({
							data: a,
							param: a.scriptHash,
							result: paid.has(a.scriptHash)
								? [
										{
											tx_hash: paid.get(a.scriptHash),
											height: heightOf(a.scriptHash)
										}
								  ]
								: []
						}))
					};
				}
			);
		sinon
			.stub(electrumHelpers, 'listUnspentAddressScriptHashes')
			.callsFake(async ({ scriptHashes }: { scriptHashes: TUtxoBatch }) => {
				listings += 1;
				if (failNextListing) {
					failNextListing = false;
					return { error: true, data: 'Server busy.' };
				}
				return {
					error: false,
					data: Object.values(scriptHashes.data).map((a) => ({
						data: a,
						param: a.scriptHash,
						result: paid.has(a.scriptHash)
							? [
									{
										tx_hash: paid.get(a.scriptHash),
										tx_pos: 0,
										height: heightOf(a.scriptHash),
										value: 100_000
									}
							  ]
							: []
					}))
				};
			});
		sinon
			.stub(electrumHelpers, 'getTransactions')
			.callsFake(
				async ({ txHashes }: { txHashes: TBatch<{ tx_hash: string }> }) => {
					transactionsAsked.push(...txHashes.data.map((h) => h.tx_hash));
					return {
						error: false,
						data: txHashes.data.map((h) => ({
							data: h,
							param: h.tx_hash,
							result: served.get(h.tx_hash)
						}))
					};
				}
			);

		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: [EAddressType.p2wpkh],
			electrumOptions: { net, tls, servers: SERVER },
			feeEstimationSource: 'electrum',
			// The test drives the refresh itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			logger: createConsoleLogger('silent'),
			onMessage: (key): void => {
				messages.push(key);
			},
			storage: {
				setData: async <K extends keyof IWalletData>(
					_key: string,
					_value: IWalletData[K]
				): Promise<Result<boolean>> => ok(true)
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		wallet.electrum.stopConnectionPolling();
		wallet.electrum.batchDelay = 0;
		await connect();
		const refreshed = await wallet.refreshWallet();
		if (refreshed.isErr()) throw refreshed.error;
	});

	afterEach(async function () {
		await wallet?.stop();
		sinon.restore();
	});

	/** Connects and waits for the restore to wire the header subscription. */
	const connect = async (): Promise<void> => {
		const connected = await wallet.connectToElectrum();
		if (connected.isErr()) throw connected.error;
		await waitFor(
			() => !!headerHandler && wallet.data.header.height >= 100,
			'the header subscription'
		);
	};

	const resetCounts = (): void => {
		historyAsked = [];
		listings = 0;
		transactionsAsked = [];
		messages = [];
	};

	const block = async (height: number): Promise<void> => {
		if (!headerHandler) throw new Error('No header handler was wired.');
		await headerHandler([{ height, hex: headerAt(height) }]);
	};

	const notify = async (scriptHash: string): Promise<void> => {
		if (!scriptHashHandler)
			throw new Error('No script hash handler was wired.');
		await scriptHashHandler([scriptHash, `status-${paid.get(scriptHash)}`]);
	};

	const settled = (): Promise<void> =>
		waitFor(() => !wallet.isRefreshing, 'the refresh to settle');

	/** One coin to `address` from an external parent, in block `height` (the
	 *  tip when it is not 0, the mempool). */
	const pay = (address: IAddress, txid: string, height: number): void => {
		const parent = 'ee'.repeat(32);
		paid.set(address.scriptHash, txid);
		mined.set(txid, height);
		served.set(
			parent,
			details(parent, [{ txid: 'dd'.repeat(32), vout: 0 }], [[EXTERNAL, 1]])
		);
		served.set(txid, {
			...details(
				txid,
				[{ txid: parent, vout: 0 }],
				[
					[address.address, 0.001],
					[EXTERNAL, 0.9989]
				]
			),
			confirmations: height > 0 ? 1 : 0
		});
	};

	it('scans on the first block after a connect and not on an idle one after it', async function () {
		resetCounts();
		await block(101);
		expect(listings, 'the block a connect owes lists UTXOs').to.be.greaterThan(
			0
		);
		expect(historyAsked, 'and asks for history').to.not.deep.equal([]);

		resetCounts();
		await block(102);
		expect(listings, 'no UTXO listing on an idle block').to.equal(0);
		expect(historyAsked, 'no history request on an idle block').to.deep.equal(
			[]
		);
		expect(transactionsAsked, 'nothing to look up').to.deep.equal([]);
		expect(wallet.data.header.height).to.equal(102);
		expect(messages).to.include('newBlock');
	});

	it('scans on the next block after a reconnect', async function () {
		await block(101);
		await connect();
		resetCounts();

		await block(102);

		expect(listings, 'notifications may have been lost').to.be.greaterThan(0);
	});

	it('scans for a block in which a subscribed script changed status', async function () {
		await block(101);
		const receive = wallet.data.addressIndex[EAddressType.p2wpkh];
		expect(subscribed.has(receive.scriptHash)).to.equal(true);
		const txid = '1a'.repeat(32);
		pay(receive, txid, 102);
		resetCounts();

		// ElectrumX sends the header before the statuses it changed.
		await block(102);
		await notify(receive.scriptHash);
		await settled();

		expect(listings).to.be.greaterThan(0);
		expect(historyAsked).to.include(receive.scriptHash);
		expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
		expect(wallet.data.transactions[txid]?.height).to.equal(102);
	});

	it('finds a change output to the first unused change address without a block', async function () {
		const change = wallet.data.changeAddressIndex[EAddressType.p2wpkh];
		expect(
			subscribed.has(change.scriptHash),
			'the change window is subscribed'
		).to.equal(true);
		const txid = '2b'.repeat(32);
		pay(change, txid, 0);
		resetCounts();

		await notify(change.scriptHash);
		await settled();

		expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
		expect(wallet.data.transactions[txid]?.height).to.equal(0);
		expect(wallet.data.header.height, 'no block arrived').to.equal(100);
	});

	it('scans on the next block after a refresh failed', async function () {
		await block(101);
		failNextListing = true;
		const failed = await wallet.refreshWallet();
		expect(failed.isErr()).to.equal(true);
		resetCounts();

		await block(102);
		expect(listings, 'the block retries the refresh').to.be.greaterThan(0);

		resetCounts();
		await block(103);
		expect(listings, 'and stops once it succeeded').to.equal(0);
	});

	it('looks up a pending transaction on an idle block without scanning', async function () {
		await block(101);
		const receive = wallet.data.addressIndex[EAddressType.p2wpkh];
		const txid = '3c'.repeat(32);
		pay(receive, txid, 0);
		const record = {
			address: receive.address,
			height: 0,
			scriptHash: receive.scriptHash,
			totalInputValue: 1,
			matchedInputValue: 0,
			totalOutputValue: 0.9999,
			matchedOutputValue: 0.001,
			fee: 0.0001,
			satsPerByte: 1,
			type: EPaymentType.received,
			value: 0.001,
			txid,
			messages: [],
			vin: [],
			timestamp: 1_700_000_000_000,
			exists: true,
			vsize: 141
		};
		wallet.data.transactions[txid] = record;
		wallet.data.unconfirmedTransactions[txid] = record;
		resetCounts();

		await block(102);

		expect(transactionsAsked).to.deep.equal([txid]);
		expect(listings).to.equal(0);
		expect(historyAsked).to.deep.equal([]);
	});
});
