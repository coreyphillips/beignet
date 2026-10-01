/**
 * Regression: a transaction whose inputs could not all be looked up is held
 * back, not formatted from a partial answer (issue #965).
 *
 * getInputData retried a failed prevout lookup once, then logged the error
 * and skipped the input, and formatTransactions computed the record from
 * whatever came back. The wallet's own send, with its input missing, had no
 * matched input value, so it was recorded as received, with the change as
 * its value and a fee off by the missing input, and announced with
 * transactionReceived. Nothing rewrites a confirmed record, so it could stay
 * that way. The trigger is a server too busy to answer the lookup twice.
 *
 * Fully OFFLINE: the wallet points at an unreachable port and every Electrum
 * call a refresh makes is stubbed, so this asserts on what the wallet does
 * with each answer the prevout lookup can get.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';

import {
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	IAddress,
	IFormattedTransaction,
	IGetAddressHistoryResponse,
	IGetTransactions,
	IGetTransactionsFromInputs,
	ILogger,
	ITransaction,
	ITxHash,
	IUtxo,
	IWalletData,
	ok,
	Result,
	TMessageDataMap,
	TTxDetails,
	Wallet
} from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
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

/** P: pays 0.5 BTC to the wallet's receive address. */
const P = '1a'.repeat(32);
/** S: the wallet's own send, spending P:0. */
const S = '2b'.repeat(32);
/** Q: a stranger's transaction, funding R. */
const Q = '3c'.repeat(32);
/** R: a stranger paying the wallet, spending Q:1. */
const R = '4d'.repeat(32);

/** Not this wallet's: the BIP173 test vector. */
const EXTERNAL = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';

type TOutpoint = { tx_hash: string; vout: number };

/** A transaction as the server details it. */
const details = (
	txid: string,
	vin: TOutpoint[],
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
		vin: vin.map(({ tx_hash, vout: n }) => ({
			txid: tx_hash,
			vout: n,
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

describe('a transaction whose inputs could not all be looked up (issue #965)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	let messages: Array<{ key: keyof TMessageDataMap; data: unknown }>;
	let warnings: string[];
	/** The wallet's first receive address, paid by P. */
	let A: IAddress;
	/** The wallet's second receive address, paid by R. */
	let A2: IAddress;
	/** The wallet's first change address, S's change. */
	let C: IAddress;

	const logger: ILogger = {
		debug: () => undefined,
		info: () => undefined,
		warn: (message: string) => {
			warnings.push(message);
		},
		error: () => undefined
	};

	beforeEach(async function () {
		messages = [];
		warnings = [];
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			feeEstimationSource: 'electrum',
			// This suite drives the refresh itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			logger,
			onMessage: (key, data): void => {
				messages.push({ key, data });
			},
			storage: {
				setData: async <K extends keyof IWalletData>(
					_key: string,
					_value: IWalletData[K]
				) => ok(true)
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;

		const gen = await wallet.generateAddresses({
			addressAmount: 5,
			changeAddressAmount: 5,
			addressType: EAddressType.p2wpkh
		});
		if (gen.isErr()) throw gen.error;
		wallet.data.addresses[EAddressType.p2wpkh] = gen.value.addresses;
		wallet.data.changeAddresses[EAddressType.p2wpkh] =
			gen.value.changeAddresses;
		const byIndex = (book: Record<string, IAddress>, i: number): IAddress =>
			Object.values(book).find((a) => a.index === i) as IAddress;
		A = byIndex(gen.value.addresses, 0);
		A2 = byIndex(gen.value.addresses, 1);
		C = byIndex(gen.value.changeAddresses, 0);
	});

	afterEach(async function () {
		sinon.restore();
		// Every Electrum instance polls its connection until stopped.
		await wallet?.stop();
	});

	/** The previous transactions the server can serve, by txid. */
	const prevouts = (): Record<string, TTxDetails> => ({
		[P]: details(
			P,
			[{ tx_hash: 'ee'.repeat(32), vout: 0 }],
			[[A.address, 0.5]]
		),
		[Q]: details(
			Q,
			[{ tx_hash: 'ff'.repeat(32), vout: 0 }],
			[
				[EXTERNAL, 0.3],
				[EXTERNAL, 0.4]
			]
		)
	});

	/** S: 0.2 to a stranger and 0.2999 change back to the wallet. */
	const sendDetails = (): TTxDetails =>
		details(
			S,
			[{ tx_hash: P, vout: 0 }],
			[
				[EXTERNAL, 0.2],
				[C.address, 0.2999]
			]
		);

	/** R: 0.1 to the wallet from a stranger's coin. */
	const receiveDetails = (): TTxDetails =>
		details(
			R,
			[{ tx_hash: Q, vout: 1 }],
			[
				[A2.address, 0.1],
				[EXTERNAL, 0.2999]
			]
		);

	/** A transaction's address history entry, as a refresh reads it. */
	const historyEntry = (
		txid: string,
		address: IAddress
	): IGetAddressHistoryResponse =>
		({
			tx_hash: txid,
			height: 0,
			address: address.address,
			scriptHash: address.scriptHash
		}) as IGetAddressHistoryResponse;

	/** The server's entry for a looked up transaction, echoing the request. */
	const txEntry = <T>(
		data: T,
		result?: TTxDetails,
		error?: object
	): ITransaction<T> =>
		({
			id: 0,
			jsonrpc: '2.0',
			param: (data as unknown as ITxHash).tx_hash,
			data,
			...(error ? { error } : {}),
			result
		}) as unknown as ITransaction<T>;

	type TPrevoutAnswer = 'serve' | 'empty' | { message: string };

	/**
	 * Answers every prevout lookup as `answer` says for its attempt (the first
	 * call is attempt 0). Returns the stub.
	 */
	const answerPrevouts = (
		answer: (attempt: number) => TPrevoutAnswer
	): sinon.SinonStub => {
		let attempt = 0;
		return sinon
			.stub(wallet.electrum, 'getTransactionsFromInputs')
			.callsFake(
				async ({
					txHashes
				}: {
					txHashes: TOutpoint[];
				}): Promise<Result<IGetTransactionsFromInputs>> => {
					const how = answer(attempt++);
					const data = txHashes.map((h) =>
						how === 'serve'
							? txEntry(h, prevouts()[h.tx_hash])
							: how === 'empty'
							? txEntry(h)
							: txEntry(h, undefined, { code: -32603, ...how })
					);
					return ok({
						error: false,
						id: 0,
						method: 'getTransactions',
						network: 'bitcoinRegtest',
						data
					});
				}
			);
	};

	/** Serves the history and the transactions in it for a refresh. */
	const serveHistory = (
		...entries: Array<[IGetAddressHistoryResponse, TTxDetails]>
	): void => {
		sinon
			.stub(wallet.electrum, 'getAddressHistory')
			.resolves(ok(entries.map(([entry]) => entry)));
		sinon
			.stub(wallet.electrum, 'getTransactions')
			.callsFake(
				async ({
					txHashes
				}: {
					txHashes: ITxHash[];
				}): Promise<Result<IGetTransactions>> => {
					const data = txHashes.map((h) => {
						const found = entries.find(([e]) => e.tx_hash === h.tx_hash);
						return txEntry(h as IUtxo, found?.[1]);
					});
					return ok({
						error: false,
						id: 0,
						method: 'getTransactions',
						network: 'bitcoinRegtest',
						data
					});
				}
			);
	};

	/** S as the server lists it in the change address's history. */
	const sendInHistory = (): ITransaction<IUtxo> =>
		txEntry(historyEntry(S, C) as unknown as IUtxo, sendDetails());

	const announced = (key: keyof TMessageDataMap): unknown[] =>
		messages.filter((m) => m.key === key).map((m) => m.data);

	/** The correct record of S. */
	const expectSent = (record: IFormattedTransaction | undefined): void => {
		expect(record, 'S is recorded').to.not.equal(undefined);
		expect(record?.type, 'as the send it is').to.equal(EPaymentType.sent);
		expect(record?.matchedInputValue, 'spending the 0.5 it held').to.equal(0.5);
		expect(record?.value, 'less the change').to.equal(-0.2001);
		expect(record?.fee).to.equal(0.0001);
	};

	it('leaves out a transaction whose own input could not be looked up', async function () {
		const lookups = answerPrevouts(() => ({ message: 'server busy' }));

		const res = await wallet.formatTransactions({
			transactions: [sendInHistory()]
		});
		expect(res.isOk(), 'the batch was formatted').to.equal(true);
		if (res.isErr()) return;

		expect(lookups.callCount, 'asked once and retried once').to.equal(2);
		expect(
			res.value[S],
			'not formatted from a partial answer, where it reads as received'
		).to.equal(undefined);
		expect(
			warnings.filter((w) => w.startsWith('Holding back')),
			'and the hold back is logged once'
		).to.have.length(1);
	});

	it('records the send once its input can be looked up, and never as received', async function () {
		serveHistory([historyEntry(S, C), sendDetails()]);
		let served = false;
		answerPrevouts(() => (served ? 'serve' : { message: 'server busy' }));

		const first = await wallet.updateTransactions({});
		expect(first.isOk(), 'the refresh ran').to.equal(true);
		expect(wallet.transactions[S], 'nothing recorded yet').to.equal(undefined);
		expect(wallet.getUnconfirmedTransactions()[S], 'nor watched').to.equal(
			undefined
		);
		expect(announced('transactionReceived'), 'nor announced').to.have.length(0);
		expect(announced('transactionSent')).to.have.length(0);

		served = true;
		const second = await wallet.updateTransactions({});
		expect(second.isOk(), 'the refresh ran').to.equal(true);
		expectSent(wallet.transactions[S]);
		expect(
			wallet.getUnconfirmedTransactions()[S]?.type,
			'and watched as the send'
		).to.equal(EPaymentType.sent);
		expect(announced('transactionSent'), 'announced once').to.have.length(1);
		expect(
			announced('transactionReceived'),
			'and never as a receive'
		).to.have.length(0);
	});

	it('retries an input the server answered with nothing', async function () {
		// Neither a result nor an error: skipped without a retry or a log line
		// before, so the send was formatted without its input.
		const lookups = answerPrevouts((attempt) =>
			attempt === 0 ? 'empty' : 'serve'
		);

		const res = await wallet.formatTransactions({
			transactions: [sendInHistory()]
		});
		expect(res.isOk(), 'the batch was formatted').to.equal(true);
		if (res.isErr()) return;

		expect(lookups.callCount, 'the empty answer was retried').to.equal(2);
		expectSent(res.value[S]);
	});

	it('does not retry or hold back an input Electrum calls too large to send', async function () {
		// That answer does not change, so holding the transaction back would
		// keep it out for good. The case varies between servers.
		const lookups = answerPrevouts(() => ({
			message: 'Response Too Large (at least 1000108 bytes)'
		}));

		const res = await wallet.formatTransactions({
			transactions: [sendInHistory()]
		});
		expect(res.isOk(), 'the batch was formatted').to.equal(true);
		if (res.isErr()) return;

		expect(lookups.callCount, 'asked once').to.equal(1);
		expect(res.value[S], 'and formatted as before').to.not.equal(undefined);
		expect(
			warnings.filter((w) => w.startsWith('Holding back')),
			'nothing held back'
		).to.have.length(0);
	});

	it('keeps the stored record when replacing the history while lookups fail', async function () {
		// The correct record, from a refresh when the server could answer.
		serveHistory([historyEntry(S, C), sendDetails()]);
		let served = true;
		answerPrevouts(() => (served ? 'serve' : { message: 'server busy' }));
		await wallet.updateTransactions({});
		expectSent(wallet.transactions[S]);

		served = false;
		const res = await wallet.updateTransactions({
			replaceStoredTransactions: true
		});
		expect(res.isOk(), 'the refresh ran').to.equal(true);
		expectSent(wallet.transactions[S]);
	});

	it("holds back a receive whose sender's coin could not be looked up, then records it", async function () {
		serveHistory([historyEntry(R, A2), receiveDetails()]);
		let served = false;
		answerPrevouts(() => (served ? 'serve' : { message: 'server busy' }));

		await wallet.updateTransactions({});
		expect(wallet.transactions[R], 'held back').to.equal(undefined);
		expect(announced('transactionReceived')).to.have.length(0);

		served = true;
		await wallet.updateTransactions({});
		const record = wallet.transactions[R];
		expect(record?.type, 'recorded as the receive it is').to.equal(
			EPaymentType.received
		);
		expect(record?.value).to.equal(0.1);
		expect(record?.matchedInputValue).to.equal(0);
		expect(record?.totalInputValue, 'with its input found').to.equal(0.4);
		expect(record?.fee).to.equal(0.0001);
		expect(announced('transactionReceived'), 'announced once').to.have.length(
			1
		);
	});
});
