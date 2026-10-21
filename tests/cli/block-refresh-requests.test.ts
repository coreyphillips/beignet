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
	err,
	IAddress,
	IWalletData,
	ok,
	Result,
	TMessageDataMap,
	TTxDetails,
	Wallet
} from '../../src';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';

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

/** The transaction every payment in these tests spends. */
const PARENT = 'ee'.repeat(32);

/** How a server answers one entry of a batch it could not serve. */
const BUSY = { code: -32603, message: 'Server busy.' };

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
	/** A transaction whose batch fails once. */
	let failBatchOf: string | undefined;
	/** A transaction whose own entry is answered with an error. */
	let failEntryOf: string | undefined;
	/** A script hash whose history batch fails. */
	let failHistoryOf: string | undefined;
	/** A script hash whose UTXO entry is answered with an error. */
	let failUtxoEntryOf: string | undefined;
	/** Called as a script hash is first subscribed, before it is answered. */
	let onFirstSubscribe: ((scriptHash: string) => void) | undefined;
	/** Whether a script hash not yet subscribed is refused. */
	let refuseNewSubscriptions: boolean;
	/** A script hash whose next first subscribe waits for releaseHeld, then
	 *  fails, as a request that timed out would. */
	let holdSubscribeOf: string | undefined;
	let releaseHeld: (() => void) | undefined;
	/** Whether storage refuses the UTXO set write. */
	let refuseUtxoWrite: boolean;
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
		failBatchOf = undefined;
		failEntryOf = undefined;
		failHistoryOf = undefined;
		failUtxoEntryOf = undefined;
		onFirstSubscribe = undefined;
		refuseNewSubscriptions = false;
		holdSubscribeOf = undefined;
		releaseHeld = undefined;
		refuseUtxoWrite = false;
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
					// The client records a hash only once the server answers, so a
					// subscribe sent while this one waits goes to the server too.
					if (scriptHash === holdSubscribeOf) {
						holdSubscribeOf = undefined;
						await new Promise<void>((resolve) => {
							releaseHeld = resolve;
						});
						return { error: true, data: 'Server busy.' };
					}
					if (refuseNewSubscriptions) {
						return { error: true, data: 'Server busy.' };
					}
					subscribed.add(scriptHash);
					onFirstSubscribe?.(scriptHash);
					const txid = paid.get(scriptHash);
					return { error: false, data: txid ? `status-${txid}` : null };
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
					if (scriptHashes.data.some((a) => a.scriptHash === failHistoryOf)) {
						return { error: true, data: 'Server busy.' };
					}
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
						...(a.scriptHash === failUtxoEntryOf && { error: BUSY }),
						result:
							a.scriptHash === failUtxoEntryOf
								? undefined
								: paid.has(a.scriptHash)
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
					if (txHashes.data.some((h) => h.tx_hash === failBatchOf)) {
						failBatchOf = undefined;
						return { error: true, data: 'Server busy.' };
					}
					return {
						error: false,
						data: txHashes.data.map((h) =>
							h.tx_hash === failEntryOf
								? { data: h, param: h.tx_hash, error: BUSY }
								: { data: h, param: h.tx_hash, result: served.get(h.tx_hash) }
						)
					};
				}
			);

		wallet = await createWallet();
		await connect();
		const refreshed = await wallet.refreshWallet();
		if (refreshed.isErr()) throw refreshed.error;
	});

	afterEach(async function () {
		await wallet?.stop();
		sinon.restore();
	});

	const createWallet = async (): Promise<Wallet> => {
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
					key: string,
					_value: IWalletData[K]
				): Promise<Result<boolean>> =>
					refuseUtxoWrite && key === wallet.getWalletDataKey('utxos')
						? err('Storage refused the write.')
						: ok(true)
			}
		});
		if (res.isErr()) throw res.error;
		res.value.electrum.stopConnectionPolling();
		res.value.electrum.batchDelay = 0;
		return res.value;
	};

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

	/** Issues receive addresses until one past those generated up front. */
	const issuePastGenerated = async (from = wallet): Promise<IAddress> => {
		let issued: IAddress | undefined;
		for (let i = 0; i < 20; i++) {
			const res = await from.generateNewReceiveAddress();
			if (res.isErr()) throw new Error(res.error.message);
			issued = res.value;
		}
		expect(issued?.index).to.equal(20);
		return issued as IAddress;
	};

	/** Starts a chain watch on the receive address issuePastGenerated will
	 *  issue, before the wallet has it, and holds its subscribe until
	 *  releaseHeld fails it. Resolves once the watch has settled. */
	const holdWatchOnNextIssued = async (): Promise<{
		next: IAddress;
		watch: Promise<void>;
	}> => {
		const generated = await wallet.generateAddresses({
			addressAmount: 1,
			addressIndex: 20,
			changeAddressAmount: 0,
			addressType: EAddressType.p2wpkh
		});
		if (generated.isErr()) throw new Error(generated.error.message);
		const next = Object.values(generated.value.addresses)[0];
		holdSubscribeOf = next.scriptHash;
		const backend = new ElectrumBackend(wallet.electrum);
		const watch = backend
			.subscribeToScriptHash(next.scriptHash, () => {})
			.then(
				() => {
					throw new Error('The held subscribe succeeded.');
				},
				() => undefined
			);
		await waitFor(() => !!releaseHeld, 'the held subscribe');
		return { next, watch };
	};

	/** One coin to `address` from an external parent, in block `height` (the
	 *  tip when it is not 0, the mempool). */
	const pay = (address: IAddress, txid: string, height: number): void => {
		paid.set(address.scriptHash, txid);
		mined.set(txid, height);
		served.set(
			PARENT,
			details(PARENT, [{ txid: 'dd'.repeat(32), vout: 0 }], [[EXTERNAL, 1]])
		);
		served.set(txid, {
			...details(
				txid,
				[{ txid: PARENT, vout: 0 }],
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

	it('subscribes a receive address issued past the subscribed window', async function () {
		await block(101);
		const issued = await issuePastGenerated();
		expect(subscribed.has(issued.scriptHash)).to.equal(true);
		const txid = '4d'.repeat(32);
		pay(issued, txid, 0);

		await notify(issued.scriptHash);
		await settled();

		expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
	});

	/** Each answer a server can fail in part without failing the refresh. */
	const partialFailures: Array<
		[string, (receive: IAddress, txid: string) => void]
	> = [
		['a transaction batch', (_, txid): void => void (failBatchOf = txid)],
		['a transaction entry', (_, txid): void => void (failEntryOf = txid)],
		["an input's parent", (): void => void (failEntryOf = PARENT)],
		[
			'a history batch',
			(receive): void => void (failHistoryOf = receive.scriptHash)
		],
		[
			'a UTXO entry',
			(receive): void => void (failUtxoEntryOf = receive.scriptHash)
		]
	];
	for (const [what, fail] of partialFailures) {
		it(`scans on the next block after ${what} failed`, async function () {
			await block(101);
			const receive = wallet.data.addressIndex[EAddressType.p2wpkh];
			const txid = '5e'.repeat(32);
			pay(receive, txid, 101);
			fail(receive, txid);
			const found = (): boolean =>
				wallet.data.utxos.some((u) => u.tx_hash === txid) &&
				wallet.data.transactions[txid]?.height === 101;

			await notify(receive.scriptHash);
			await settled();
			expect(found(), 'the refresh read it in part').to.equal(false);
			failBatchOf = failEntryOf = failHistoryOf = failUtxoEntryOf = undefined;
			resetCounts();

			await block(102);
			expect(found(), 'the block reads it again').to.equal(true);

			resetCounts();
			await block(103);
			expect(listings, 'and stops once it succeeded').to.equal(0);
		});
	}

	it('scans on the next block after a first subscription found history', async function () {
		await block(101);
		const txid = '7a'.repeat(32);
		// The payment lands after the address is generated and before its
		// subscription is answered.
		onFirstSubscribe = (scriptHash): void => {
			const address = Object.values(
				wallet.data.addresses[EAddressType.p2wpkh]
			).find((a) => a.scriptHash === scriptHash);
			if (address?.index === 20) pay(address, txid, 101);
		};
		const issued = await issuePastGenerated();
		onFirstSubscribe = undefined;
		expect(paid.get(issued.scriptHash)).to.equal(txid);

		await block(102);

		expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
		expect(wallet.data.transactions[txid]?.height).to.equal(101);
	});

	it('scans on the next block after a status first heard by another wallet', async function () {
		await block(101);
		const other = await createWallet();
		try {
			const connected = await other.connectToElectrum();
			if (connected.isErr()) throw connected.error;
			const refreshed = await other.refreshWallet();
			if (refreshed.isErr()) throw refreshed.error;
			const txid = '8b'.repeat(32);
			onFirstSubscribe = (scriptHash): void => {
				const address = Object.values(
					other.data.addresses[EAddressType.p2wpkh]
				).find((a) => a.scriptHash === scriptHash);
				if (address?.index === 20) pay(address, txid, 101);
			};
			await issuePastGenerated(other);
			onFirstSubscribe = undefined;
			// Answered "Already Subscribed.", with the status the other heard.
			const issued = await issuePastGenerated();
			expect(paid.get(issued.scriptHash)).to.equal(txid);

			await block(102);

			expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
		} finally {
			await other.stop();
		}
	});

	it('still refreshes for a window address after a chain watch on it is dropped', async function () {
		await block(101);
		const other = await createWallet();
		try {
			const connected = await other.connectToElectrum();
			if (connected.isErr()) throw connected.error;
			const refreshed = await other.refreshWallet();
			if (refreshed.isErr()) throw refreshed.error;
			const receive = wallet.data.addressIndex[EAddressType.p2wpkh];
			const backend = new ElectrumBackend(wallet.electrum);
			await backend.subscribeToScriptHash(receive.scriptHash, () => {});
			backend.unsubscribeScriptHash(receive.scriptHash);
			const txid = 'ad'.repeat(32);
			pay(receive, txid, 0);

			await notify(receive.scriptHash);
			await settled();
			await block(102);

			expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
		} finally {
			await other.stop();
		}
	});

	it('scans on the next block after the UTXO set write was refused', async function () {
		await block(101);
		const receive = wallet.data.addressIndex[EAddressType.p2wpkh];
		pay(receive, '9c'.repeat(32), 101);
		refuseUtxoWrite = true;
		await notify(receive.scriptHash);
		await settled();
		refuseUtxoWrite = false;
		resetCounts();

		await block(102);
		expect(listings, 'the block writes the set again').to.be.greaterThan(0);
	});

	it('subscribes on the next block a window address whose subscription failed', async function () {
		await block(101);
		refuseNewSubscriptions = true;
		const issued = await issuePastGenerated();
		// A refresh before the server recovers fails to subscribe it as well.
		const refreshed = await wallet.refreshWallet();
		expect(refreshed.isOk()).to.equal(true);
		expect(subscribed.has(issued.scriptHash)).to.equal(false);
		refuseNewSubscriptions = false;
		resetCounts();

		await block(102);
		expect(listings, 'the block retries the refresh').to.be.greaterThan(0);
		expect(subscribed.has(issued.scriptHash)).to.equal(true);

		const txid = '6f'.repeat(32);
		pay(issued, txid, 0);
		await notify(issued.scriptHash);
		await settled();
		expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
	});

	it('still refreshes for a window address after a chain watch on it failed', async function () {
		await block(101);
		const other = await createWallet();
		try {
			const connected = await other.connectToElectrum();
			if (connected.isErr()) throw connected.error;
			const refreshed = await other.refreshWallet();
			if (refreshed.isErr()) throw refreshed.error;
			const { next, watch } = await holdWatchOnNextIssued();
			// The window's own subscribe for the hash is answered while the
			// watch's still waits.
			const issued = await issuePastGenerated();
			expect(issued.scriptHash).to.equal(next.scriptHash);
			// Held by another wallet too, so its notification is routed rather
			// than handed to every wallet.
			await issuePastGenerated(other);
			releaseHeld?.();
			await watch;
			const txid = 'c4'.repeat(32);
			pay(issued, txid, 0);

			await notify(issued.scriptHash);
			await settled();

			expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
		} finally {
			await other.stop();
		}
	});

	it('scans on the next block after a chain watch failed on a window address another wallet heard first', async function () {
		await block(101);
		const other = await createWallet();
		try {
			const connected = await other.connectToElectrum();
			if (connected.isErr()) throw connected.error;
			const refreshed = await other.refreshWallet();
			if (refreshed.isErr()) throw refreshed.error;
			const { next, watch } = await holdWatchOnNextIssued();
			const txid = 'd5'.repeat(32);
			pay(next, txid, 101);
			// The other wallet's subscribe hears the status, so this wallet's is
			// answered "Already Subscribed." and the status is left unheard here.
			await issuePastGenerated(other);
			const issued = await issuePastGenerated();
			expect(issued.scriptHash).to.equal(next.scriptHash);
			releaseHeld?.();
			await watch;

			await block(102);

			expect(wallet.data.utxos.map((u) => u.tx_hash)).to.deep.equal([txid]);
		} finally {
			await other.stop();
		}
	});
});
