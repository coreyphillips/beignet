/**
 * Regression test for issue #1661: the gap-limit scan filled its lookahead
 * window by deriving from index 0, listed every UTXO once per extension round
 * per address type, and fetched the history updateTransactions fetched again
 * a moment later.
 *
 * Fully OFFLINE: the client helpers are stubbed with a counting fake server.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	createConsoleLogger,
	createMemoryStorage,
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	IAddress,
	IAddresses,
	IGenerateAddresses,
	IWalletData,
	ok,
	Result,
	TMessageDataMap,
	TStorage,
	TTxDetails,
	Wallet
} from '../../src';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65519,
		tcp: 65519,
		protocol: EProtocol.tcp
	}
};

const TYPES = [EAddressType.p2wpkh, EAddressType.p2tr];

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

type TBatch<T> = { key: string; data: T[] };
/** The UTXO listing sends its batch keyed by script hash. */
type TUtxoBatch = { key: string; data: Record<string, IAddress> };
type TServed = TTxDetails & { confirmations?: number };

const at = (addresses: IAddresses, index: number): IAddress =>
	Object.values(addresses).find((a) => a.index === index) as IAddress;

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

describe('gap-limit scan requests (#1661)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** Script hash to the txid paying it. */
	let paid: Map<string, string>;
	/** The block each paying transaction is in, 0 for the mempool. */
	let mined: Map<string, number>;
	/** What the server answers for a transaction. Nothing for the rest. */
	let served: Map<string, TServed>;
	/** Runs as each UTXO listing goes out. */
	let onListing: () => void;
	/** Script hashes the UTXO listing answers with an error entry. */
	let failListing: Set<string>;
	/** Every script hash a get_history request named. */
	let historyAsked: string[];
	let utxoScans: number;
	/** Each index addAddresses derived that was already stored. */
	let duplicates: string[];
	let messages: (keyof TMessageDataMap)[];
	/** What the wallet wrote, as JSON, keyed as storage keys it. */
	let written: Map<string, string>;

	const open = async (storage: TStorage): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			addressTypesToMonitor: TYPES,
			electrumOptions,
			feeEstimationSource: 'electrum',
			// The test drives the refresh itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			logger: createConsoleLogger('silent'),
			onMessage: (key): void => {
				messages.push(key);
			},
			storage
		});
		if (res.isErr()) throw res.error;
		const opened = res.value;
		opened.electrum.stopConnectionPolling();
		opened.electrum.batchDelay = 0;
		const connected = await opened.connectToElectrum();
		if (connected.isErr()) throw connected.error;
		return opened;
	};

	beforeEach(async function () {
		paid = new Map();
		mined = new Map();
		served = new Map();
		onListing = (): void => undefined;
		failListing = new Set();
		historyAsked = [];
		duplicates = [];
		messages = [];
		const heightOf = (scriptHash: string): number =>
			mined.get(paid.get(scriptHash) ?? '') ?? 90;
		let peer: { host: string; port: number; protocol: EProtocol } | undefined;
		sinon.stub(electrumHelpers, 'getConnectedPeer').callsFake(() => peer);
		sinon.stub(electrumHelpers, 'start').callsFake(async () => {
			peer = { host: '127.0.0.1', port: 65519, protocol: EProtocol.tcp };
			return { error: false, data: 'connected' };
		});
		sinon.stub(electrumHelpers, 'stop').callsFake(async () => {
			peer = undefined;
			return { error: false, data: 'stopped' };
		});
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashBalance')
			.resolves({ error: false, data: { confirmed: 0, unconfirmed: 0 } });
		sinon
			.stub(electrumHelpers, 'subscribeHeader')
			.resolves({ error: false, data: { height: 100, hex: '00'.repeat(80) } });
		sinon
			.stub(electrumHelpers, 'subscribeAddress')
			.resolves({ error: false, data: null });
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
				onListing();
				return {
					error: false,
					data: Object.values(scriptHashes.data).map((a) =>
						failListing.has(a.scriptHash)
							? {
									data: a,
									param: a.scriptHash,
									error: { code: -32603, message: 'Server busy.' }
							  }
							: {
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
							  }
					)
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

		written = new Map();
		wallet = await open({
			setData: async <K extends keyof IWalletData>(
				key: string,
				value: IWalletData[K]
			): Promise<Result<boolean>> => {
				written.set(key, JSON.stringify(value));
				return ok(true);
			}
		});

		const internals = wallet as unknown as {
			addAddresses: (args: IGenerateAddresses) => Promise<unknown>;
		};
		const addAddresses = internals.addAddresses.bind(wallet);
		sinon
			.stub(internals, 'addAddresses')
			.callsFake(async (args: IGenerateAddresses) => {
				const type = args.addressType ?? wallet.addressType;
				const chains: [IAddresses, number, number, string][] = [
					[
						wallet.data.addresses[type],
						args.addressIndex ?? 0,
						args.addressAmount ?? 5,
						'receive'
					],
					[
						wallet.data.changeAddresses[type],
						args.changeAddressIndex ?? 0,
						args.changeAddressAmount ?? 5,
						'change'
					]
				];
				for (const [stored, from, amount, chain] of chains) {
					const indexes = new Set(Object.values(stored).map((a) => a.index));
					for (let i = from; i < from + amount; i++) {
						if (indexes.has(i)) duplicates.push(`${type} ${chain} ${i}`);
					}
				}
				return addAddresses(args);
			});
		utxoScans = 0;
		const getUtxos = wallet.electrum.getUtxos.bind(wallet.electrum);
		sinon
			.stub(wallet.electrum, 'getUtxos')
			.callsFake(async (...args: Parameters<typeof getUtxos>) => {
				utxoScans += 1;
				return getUtxos(...args);
			});
	});

	afterEach(async function () {
		await wallet?.stop();
		sinon.restore();
	});

	/** One coin to the address, in a transaction of its own. */
	const pay = (address: IAddress): void => {
		paid.set(address.scriptHash, address.scriptHash);
		// The UTXO scan reads a young coin's inputs to rule out a coinbase.
		served.set(
			address.scriptHash,
			details(
				address.scriptHash,
				[{ txid: 'ee'.repeat(32), vout: 0 }],
				[[address.address, 0.001]]
			)
		);
	};

	const askedMoreThanOnce = (): string[] => {
		const seen = new Set<string>();
		return historyAsked.filter((h) => seen.has(h) || !seen.add(h));
	};

	it('fills a raised lookahead past the stored addresses, lists UTXOs once and asks each history once', async function () {
		// 25 receive addresses, the last used at 20: what a scan with a
		// lookahead of 4 leaves behind once the wallet raises it to 20.
		for (const type of TYPES) {
			const gen = await wallet.generateAddresses({
				addressAmount: 25,
				changeAddressAmount: 20,
				addressType: type
			});
			if (gen.isErr()) throw gen.error;
			const data = wallet.data;
			const scanned = await wallet.updateData({
				addresses: { ...data.addresses, [type]: gen.value.addresses },
				changeAddresses: {
					...data.changeAddresses,
					[type]: gen.value.changeAddresses
				},
				addressIndex: {
					...data.addressIndex,
					[type]: at(gen.value.addresses, 21)
				},
				lastUsedAddressIndex: {
					...data.lastUsedAddressIndex,
					[type]: at(gen.value.addresses, 20)
				},
				changeAddressIndex: {
					...data.changeAddressIndex,
					[type]: at(gen.value.changeAddresses, 0)
				}
			});
			if (scanned.isErr()) throw scanned.error;
			pay(at(gen.value.addresses, 20));
		}

		const res = await wallet.refreshWallet();
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

		expect(duplicates, 'no stored address is derived again').to.deep.equal([]);
		expect(utxoScans, 'one UTXO listing for the whole refresh').to.equal(1);
		expect(askedMoreThanOnce(), 'each history asked once').to.deep.equal([]);
		for (const type of TYPES) {
			const indexes = Object.values(wallet.data.addresses[type]).map(
				(a) => a.index
			);
			expect(Math.max(...indexes), `${type} lookahead`).to.equal(40);
			expect(new Set(indexes).size, `${type} has no gaps`).to.equal(41);
			expect(wallet.data.addressIndex[type].index).to.equal(21);
			expect(wallet.data.lastUsedAddressIndex[type].index).to.equal(20);
		}
		expect(wallet.data.utxos.map((u) => u.index).sort()).to.deep.equal([
			20, 20
		]);
	});

	it('still finds a coin the extension rounds reached below the new look-behind', async function () {
		const first = await wallet.refreshWallet();
		expect(first.isOk(), first.isErr() ? first.error.message : '').to.equal(
			true
		);
		// Each payment within the lookahead of the one before: the scan
		// extends three times and moves the next index to 42, whose
		// look-behind starts at 22.
		for (const index of [3, 22, 41]) {
			const gen = await wallet.generateAddresses({
				addressAmount: 1,
				addressIndex: index,
				changeAddressAmount: 0,
				addressType: EAddressType.p2wpkh
			});
			if (gen.isErr()) throw gen.error;
			pay(at(gen.value.addresses, index));
		}
		utxoScans = 0;
		historyAsked = [];
		duplicates = [];

		const res = await wallet.refreshWallet();
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

		expect(wallet.data.addressIndex[EAddressType.p2wpkh].index).to.equal(42);
		expect(
			wallet.data.lastUsedAddressIndex[EAddressType.p2wpkh].index
		).to.equal(41);
		expect(
			wallet.data.utxos.map((u) => u.index).sort((a, b) => a - b),
			'the coin at 3 is outside the window around 42'
		).to.deep.equal([3, 22, 41]);
		expect(wallet.data.balance).to.equal(300_000);
		expect(utxoScans, 'one UTXO listing for the whole refresh').to.equal(1);
		expect(askedMoreThanOnce(), 'each history asked once').to.deep.equal([]);
		expect(duplicates).to.deep.equal([]);
	});

	for (const [restart, issued] of [
		[false, false],
		[true, false],
		[true, true]
	]) {
		it(`lists the coins the extension rounds reached on the refresh after their listing failed${
			restart ? ', across a restart' : ''
		}${
			issued ? ' after a receive address was issued' : ''
		} (#1882)`, async function () {
			const first = await wallet.refreshWallet();
			expect(first.isOk(), first.isErr() ? first.error.message : '').to.equal(
				true
			);
			for (const index of [3, 22, 41]) {
				const gen = await wallet.generateAddresses({
					addressAmount: 1,
					addressIndex: index,
					changeAddressAmount: 0,
					addressType: EAddressType.p2wpkh
				});
				if (gen.isErr()) throw gen.error;
				pay(at(gen.value.addresses, index));
			}
			// An empty address, so only the failure itself costs the listing.
			failListing.add(
				at(wallet.data.changeAddresses[EAddressType.p2wpkh], 0).scriptHash
			);

			const failed = await wallet.refreshWallet();
			expect(failed.isErr(), 'the failed entry fails the refresh').to.equal(
				true
			);
			expect(wallet.data.addressIndex[EAddressType.p2wpkh].index).to.equal(42);
			expect(wallet.data.utxos).to.deep.equal([]);

			failListing.clear();
			if (issued) {
				const address = await wallet.getReceiveAddress({});
				if (address.isErr()) throw address.error;
				const stored = written.get(wallet.getWalletDataKey('addressIndex'));
				expect(
					JSON.parse(stored!)[EAddressType.p2wpkh].index,
					'issuing saved the index past the coins'
				).to.equal(42);
			}
			if (restart) {
				await wallet.stop();
				wallet = await open(createMemoryStorage(written));
			}
			const res = await wallet.refreshWallet();
			expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

			expect(
				wallet.data.utxos.map((u) => u.index).sort((a, b) => a - b),
				'the coin at 3 is outside the window around 42'
			).to.deep.equal([3, 22, 41]);
			expect(wallet.data.balance).to.equal(300_000);
			expect(wallet.data.unlistedUtxoAddresses).to.deep.equal({});
		});
	}

	it('asks again for a history the scan was answered before the check repaired its record', async function () {
		const first = await wallet.refreshWallet();
		expect(first.isOk(), first.isErr() ? first.error.message : '').to.equal(
			true
		);
		// Y pays receive address 5 and is recorded and observed in block 97,
		// while the next index is still below 5, so the gap scan asks about it.
		const receive = at(wallet.data.addresses[EAddressType.p2wpkh], 5);
		const P = '1a'.repeat(32);
		const Y = '2b'.repeat(32);
		paid.set(receive.scriptHash, Y);
		mined.set(Y, 97);
		served.set(
			P,
			details(P, [{ txid: 'ee'.repeat(32), vout: 0 }], [[EXTERNAL, 1]])
		);
		served.set(Y, {
			...details(
				Y,
				[{ txid: P, vout: 0 }],
				[
					[receive.address, 0.001],
					[EXTERNAL, 0.9989]
				]
			),
			confirmations: 4
		});
		const record = {
			address: receive.address,
			height: 97,
			scriptHash: receive.scriptHash,
			totalInputValue: 1,
			totalInputSats: 100_000_000,
			matchedInputValue: 0,
			matchedInputSats: 0,
			totalOutputValue: 0.9999,
			totalOutputSats: 99_990_000,
			matchedOutputValue: 0.001,
			matchedOutputSats: 100_000,
			fee: 0.0001,
			feeSats: 10_000,
			satsPerByte: 1,
			type: EPaymentType.received,
			value: 0.001,
			valueSats: 100_000,
			txid: Y,
			messages: [],
			vin: [],
			timestamp: 1_700_000_000_000,
			exists: true,
			vsize: 141
		};
		const recorded = await wallet.updateData({
			header: { height: 100, hash: '', hex: '' },
			transactions: { ...wallet.data.transactions, [Y]: record },
			unconfirmedTransactions: {
				...wallet.data.unconfirmedTransactions,
				[Y]: record
			}
		});
		if (recorded.isErr()) throw recorded.error;
		// Block 97 is reorged away once the gap scan has asked about address
		// 5, and before the check in updateTransactions asks about Y.
		onListing = (): void => {
			mined.set(Y, 0);
			served.set(Y, { ...(served.get(Y) as TServed), confirmations: 0 });
		};
		historyAsked = [];
		messages = [];

		const res = await wallet.refreshWallet();
		expect(res.isOk(), res.isErr() ? res.error.message : '').to.equal(true);

		expect(messages).to.include('reorg');
		expect(wallet.data.transactions[Y].height, 'the repair stands').to.equal(0);
		expect(messages, 'nothing confirmed').to.not.include(
			'transactionConfirmed'
		);
		expect(
			historyAsked.filter((h) => h === receive.scriptHash),
			'asked again after the repair'
		).to.have.length(2);
	});
});
