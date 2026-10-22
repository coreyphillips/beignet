/**
 * Regression test for issue #1658: formatting a transaction asked Electrum
 * for the parent of every input, once per input rather than once per parent,
 * and asked again on every refresh until the transaction confirmed.
 *
 * Fully OFFLINE: the wallet points at an unreachable Electrum port and the
 * client helpers are a counting fake server.
 */

import { expect } from 'chai';
import net from 'net';
import sinon from 'sinon';
import tls from 'tls';

import {
	createMemoryStorage,
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	IAddress,
	IFormattedTransaction,
	IGetAddressHistoryResponse,
	ITransaction,
	IUtxo,
	TTxDetails,
	Wallet
} from '../../src';
import { MAX_REMEMBERED_PREVOUTS } from '../../src/wallet/constants';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline. Not remainOffline,
// which refuses each request before it reaches the fake server.
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

/** Pays the wallet on every even output and a stranger on every odd one. */
const P = '1a'.repeat(32);
/** Unconfirmed: the wallet's send spending all 20 of P's outputs. */
const T = '2b'.repeat(32);

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

const INPUTS = 20;

const details = (
	txid: string,
	vin: Array<{ txid: string; vout: number }>,
	vout: Array<[string, number]>
): TTxDetails =>
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
	}) as TTxDetails;

type TBatch<T> = { key: string; data: T[] };
type TAnswer = 'serve' | { message: string };

describe('previous output lookups (#1658)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** The wallet's first receive address, paid by P. */
	let A: IAddress;
	/** The wallet's first change address, T's change. */
	let C: IAddress;
	let transactions: Record<string, TTxDetails>;
	/** Every txid the fake server was asked for, in order. */
	let fetched: string[];
	/** The size of each request the fake server answered. */
	let requestSizes: number[];

	/** Answers each request as `answer` says for its attempt (from 0). */
	const serveTransactions = (
		answer: (attempt: number) => TAnswer = (): TAnswer => 'serve'
	): void => {
		let attempt = 0;
		sinon
			.stub(electrumHelpers, 'getTransactions')
			.callsFake(
				async ({ txHashes }: { txHashes: TBatch<{ tx_hash: string }> }) => {
					const how = answer(attempt++);
					fetched.push(...txHashes.data.map((h) => h.tx_hash));
					requestSizes.push(txHashes.data.length);
					return {
						error: false,
						data: txHashes.data.map((h) => ({
							id: 0,
							jsonrpc: '2.0',
							param: h.tx_hash,
							data: h,
							...(how === 'serve'
								? { result: transactions[h.tx_hash] }
								: { error: { code: -32603, ...how } })
						}))
					};
				}
			);
	};

	/** T as the server lists it in the change address's history. */
	const historyEntry = (): IGetAddressHistoryResponse =>
		({
			tx_hash: T,
			height: 0,
			address: C.address,
			scriptHash: C.scriptHash
		}) as IGetAddressHistoryResponse;

	const tInHistory = (): ITransaction<IUtxo> =>
		({
			id: 0,
			jsonrpc: '2.0',
			param: T,
			data: historyEntry() as unknown as IUtxo,
			result: transactions[T]
		}) as unknown as ITransaction<IUtxo>;

	/** The correct record of T. */
	const expectSent = (record: IFormattedTransaction | undefined): void => {
		expect(record?.type).to.equal(EPaymentType.sent);
		expect(record?.totalInputValue, 'every input found').to.equal(7.5);
		expect(record?.matchedInputValue, 'the even ones as ours').to.equal(5);
		expect(record?.matchedOutputValue).to.equal(1.4999);
		expect(record?.value).to.equal(-3.5001);
		expect(record?.fee).to.equal(0.0001);
	};

	beforeEach(async function () {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			feeEstimationSource: 'electrum',
			// The test drives the refresh itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			storage: createMemoryStorage()
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
		wallet.electrum.stopConnectionPolling();
		wallet.electrum.connectedToElectrum = true;
		wallet.electrum.batchLimit = 4;
		wallet.electrum.batchDelay = 0;

		const gen = await wallet.generateAddresses({
			addressAmount: 3,
			changeAddressAmount: 3,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		const stored = await wallet.updateData({
			addresses: {
				...wallet.data.addresses,
				[EAddressType.p2wpkh]: gen.value.addresses
			},
			changeAddresses: {
				...wallet.data.changeAddresses,
				[EAddressType.p2wpkh]: gen.value.changeAddresses
			}
		});
		if (stored.isErr()) throw stored.error;
		const byIndex = (book: Record<string, IAddress>, i: number): IAddress =>
			Object.values(book).find((a) => a.index === i) as IAddress;
		A = byIndex(gen.value.addresses, 0);
		C = byIndex(gen.value.changeAddresses, 0);

		const outputs: Array<[string, number]> = [];
		for (let n = 0; n < INPUTS; n++) {
			outputs.push(n % 2 === 0 ? [A.address, 0.5] : [EXTERNAL, 0.25]);
		}
		transactions = {
			[P]: details(P, [{ txid: 'ee'.repeat(32), vout: 0 }], outputs),
			[T]: details(
				T,
				outputs.map((_, vout) => ({ txid: P, vout })),
				[
					[EXTERNAL, 6],
					[C.address, 1.4999]
				]
			)
		};
		fetched = [];
		requestSizes = [];
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('fetches a parent once for all the inputs spending it, and not again on the next refresh', async function () {
		sinon
			.stub(electrumHelpers, 'getAddressScriptHashesHistory')
			.callsFake(
				async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => ({
					error: false,
					data: scriptHashes.data.map((a) => ({
						data: a,
						param: a.scriptHash,
						result:
							a.scriptHash === C.scriptHash ? [{ tx_hash: T, height: 0 }] : []
					}))
				})
			);
		serveTransactions();

		const first = await wallet.updateTransactions({});
		expect(first.isOk(), first.isErr() ? first.error.message : '').to.equal(
			true
		);
		expect(
			fetched.filter((h) => h === P),
			'P once for its 20 inputs'
		).to.have.length(1);
		expectSent(wallet.data.transactions[T]);
		expect(
			wallet.getUnconfirmedTransactions()[T],
			'T is watched until it confirms'
		).to.not.equal(undefined);

		const second = await wallet.updateTransactions({});
		expect(second.isOk(), second.isErr() ? second.error.message : '').to.equal(
			true
		);
		expect(
			fetched.filter((h) => h === T).length,
			'the second refresh looked T up again'
		).to.be.greaterThan(1);
		expect(
			fetched.filter((h) => h === P),
			'but not its parent'
		).to.have.length(1);
	});

	it('formats from remembered outputs exactly as from fetched ones', async function () {
		serveTransactions();

		const fromServer = await wallet.formatTransactions({
			transactions: [tInHistory()]
		});
		if (fromServer.isErr()) throw fromServer.error;
		expect(fetched).to.deep.equal([P]);
		expectSent(fromServer.value[T]);

		const fromMemory = await wallet.formatTransactions({
			transactions: [tInHistory()]
		});
		if (fromMemory.isErr()) throw fromMemory.error;
		expect(fetched, 'nothing asked the second time').to.deep.equal([P]);

		// An unconfirmed record is stamped when it is formatted.
		const { timestamp: _a, ...expected } = fromServer.value[T];
		const { timestamp: _b, ...actual } = fromMemory.value[T];
		expect(actual).to.deep.equal(expected);
	});

	it('retries a parent once, not once per input spending it', async function () {
		serveTransactions((attempt) =>
			attempt === 0 ? { message: 'server busy' } : 'serve'
		);

		const res = await wallet.formatTransactions({
			transactions: [tInHistory()]
		});
		if (res.isErr()) throw res.error;
		expect(fetched, 'asked and retried').to.deep.equal([P, P]);
		expect(requestSizes, 'one entry each time').to.deep.equal([1, 1]);
		expectSent(res.value[T]);
	});

	it(`remembers the ${MAX_REMEMBERED_PREVOUTS} most recently used outputs`, async function () {
		const outputs: Array<[string, number]> = [];
		for (let n = 0; n <= MAX_REMEMBERED_PREVOUTS; n++) {
			outputs.push([EXTERNAL, 0.0001]);
		}
		transactions[P] = details(P, [], outputs);
		serveTransactions();
		const lookUp = async (vouts: number[]): Promise<void> => {
			const res = await wallet.getInputData({
				inputs: vouts.map((vout) => ({ tx_hash: P, vout }))
			});
			if (res.isErr()) throw res.error;
			expect(Object.keys(res.value)).to.have.length(vouts.length);
		};

		// One more than fits: the first is forgotten.
		await lookUp(outputs.map((_, vout) => vout));
		expect(fetched).to.have.length(1);
		await lookUp([1]);
		expect(fetched, 'the second is still remembered').to.have.length(1);
		await lookUp([0]);
		expect(fetched, 'the first is asked for again').to.have.length(2);
		// Remembering the first again forgot the third, since using the second
		// moved it to the back.
		await lookUp([1]);
		expect(fetched).to.have.length(2);
		await lookUp([2]);
		expect(fetched).to.have.length(3);
	});
});
