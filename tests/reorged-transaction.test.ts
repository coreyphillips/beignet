/**
 * Regression: a transaction the chain no longer holds must stop being reported
 * as confirmed (issue #863).
 *
 * After a reorg the balance and the UTXO set were corrected but the stored
 * transaction kept its height, so the wallet's history showed a confirmed
 * receive at a block that no longer exists, against a zero balance, across
 * refreshes and restarts. Two things kept it there: the reorg was never
 * detected, because the new height for a transaction with no confirmations was
 * read as the current tip rather than zero, and the update it would have
 * triggered cleared the confirmation timestamp but not the height every
 * consumer reads.
 *
 * Fully OFFLINE: the wallet points at an unreachable port and the two Electrum
 * calls the check makes are stubbed, so this asserts on what the wallet does
 * with each answer a server can give for a reorg'd out transaction.
 *
 * The batched lookup case covers issue #872: a batched lookup that fails is
 * not an answer either, and dropping it stopped the monitoring that finds a
 * reorg. The last case covers issue #934: an entry the server answered with an
 * error reaches the formatter too, and must be skipped there.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';

// The raw module.exports object: the compiled namespace import in src/electrum
// reads it live through getter bindings, while this file's own namespace copy
// would be non-writable and invisible to src.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

import {
	EAddressType,
	EAvailableNetworks,
	EPaymentType,
	EProtocol,
	err,
	IFormattedTransaction,
	IGetTransactions,
	ITransaction,
	ITxHash,
	IUtxo,
	IWalletData,
	ok,
	Result,
	TMessageDataMap,
	TStorage,
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

const TXID = 'aab863ee62fa1d2b5c8b2f4b2b6c4d8e1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e';
const SCRIPT_HASH =
	'b7c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1';
const BLOCK_HASH =
	'0f2b1a4c6e8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a';
const REORGED_HEIGHT = 190;
const TIP = 191;

/** The wallet's stored record of the receive, as it looked when confirmed. */
const confirmedRecord = (
	height: number,
	txid = TXID
): IFormattedTransaction => ({
	address: 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
	blockhash: BLOCK_HASH,
	height,
	scriptHash: SCRIPT_HASH,
	totalInputValue: 0.5,
	matchedInputValue: 0,
	totalOutputValue: 0.4999,
	matchedOutputValue: 0.25,
	fee: 0.0001,
	satsPerByte: 1,
	type: EPaymentType.received,
	value: 0.25,
	txid,
	messages: [],
	vin: [],
	timestamp: 1_700_000_000_000,
	confirmTimestamp: 1_700_000_000_000,
	exists: true,
	vsize: 141
});

/** What the server answers for the transaction, echoing the request payload. */
const txAnswer = (
	confirmations?: number,
	error?: { code: number; message: string },
	txid = TXID
): ITransaction<IUtxo> =>
	({
		id: 0,
		jsonrpc: '2.0',
		param: txid,
		data: { tx_hash: txid },
		...(error ? { error } : {}),
		result: error
			? undefined
			: {
					...(confirmations !== undefined ? { confirmations } : {}),
					...(confirmations ? { blockhash: BLOCK_HASH } : {}),
					hash: txid,
					hex: '00',
					locktime: 0,
					size: 141,
					txid,
					version: 2,
					vin: [],
					vout: [],
					vsize: 141,
					weight: 561
			  }
	}) as unknown as ITransaction<IUtxo>;

/**
 * Run fn while observing unhandled promise rejections. Existing listeners
 * (mocha's) are detached for the duration so the probe sees every event, then
 * restored. A tick after fn lets a rejection it left behind surface.
 */
async function captureUnhandledRejections(
	fn: () => Promise<void>
): Promise<unknown[]> {
	const prior = process.listeners('unhandledRejection');
	process.removeAllListeners('unhandledRejection');
	const seen: unknown[] = [];
	const probe = (reason: unknown): void => {
		seen.push(reason);
	};
	process.on('unhandledRejection', probe);
	try {
		await fn();
		await new Promise((resolve) => setImmediate(resolve));
	} finally {
		process.removeListener('unhandledRejection', probe);
		for (const listener of prior) {
			process.on('unhandledRejection', listener);
		}
	}
	return seen;
}

describe('a transaction the chain no longer holds (issue #863)', function () {
	this.timeout(60000);

	let wallet: Wallet;
	/** Everything handed to storage, deep copied: what a restart would read. */
	let saved: Record<string, unknown>;
	let messages: Array<{ key: keyof TMessageDataMap; data: unknown }>;

	beforeEach(async function () {
		saved = {};
		messages = [];
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			// This suite drives the check itself; nothing may scan behind it.
			disableRefreshOnCreate: true,
			onMessage: (key, data): void => {
				messages.push({ key, data });
			},
			storage: {
				setData: async <K extends keyof IWalletData>(
					key: string,
					value: IWalletData[K]
				) => {
					saved[key] = JSON.parse(JSON.stringify(value));
					return ok(true);
				}
			}
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;

		wallet.data.header = { height: TIP, hash: '', hex: '' };
		wallet.data.transactions[TXID] = confirmedRecord(REORGED_HEIGHT);
		wallet.data.unconfirmedTransactions[TXID] = confirmedRecord(REORGED_HEIGHT);
	});

	afterEach(function () {
		sinon.restore();
	});

	/** The stored transactions as they were last written to storage. */
	const savedTransactions = (): Record<string, IFormattedTransaction> =>
		saved[wallet.getWalletDataKey('transactions')] as Record<
			string,
			IFormattedTransaction
		>;

	/** The transactions still under observation, as last written to storage. */
	const savedUnconfirmed = (): Record<string, IFormattedTransaction> =>
		saved[wallet.getWalletDataKey('unconfirmedTransactions')] as Record<
			string,
			IFormattedTransaction
		>;

	const answerWith = (tx: ITransaction<IUtxo>): sinon.SinonStub =>
		sinon.stub(wallet.electrum, 'getTransactions').resolves(
			ok<IGetTransactions>({
				error: false,
				id: 0,
				method: 'getTransactions',
				network: 'bitcoinRegtest',
				data: [tx]
			})
		);

	it('clears the height when the server reports no confirmations', async function () {
		answerWith(txAnswer(0));

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		const stored = wallet.transactions[TXID];
		expect(stored.height, 'the height of a block the chain lost').to.equal(0);
		expect(stored.blockhash, 'the block it named is gone with it').to.equal(
			undefined
		);
		expect(
			stored.confirmTimestamp,
			'and so is the time it was confirmed at'
		).to.equal(undefined);
		expect(
			messages.filter((m) => m.key === 'reorg'),
			'the reorg is reported once'
		).to.have.length(1);
		expect(
			(messages.find((m) => m.key === 'reorg')?.data as IUtxo[])[0].tx_hash
		).to.equal(TXID);
	});

	it('persists the cleared height, so a restart reads it too', async function () {
		answerWith(txAnswer(0));

		await wallet.checkUnconfirmedTransactions();

		const persisted = savedTransactions();
		expect(persisted, 'the transactions were written to storage').to.not.equal(
			undefined
		);
		expect(persisted[TXID].height).to.equal(0);
		expect(persisted[TXID].blockhash).to.equal(undefined);
	});

	it('clears the height when a server without a txindex loses the transaction', async function () {
		// No txindex: a reorg'd out transaction is not "unconfirmed", it is
		// unknown, and the ghost path handles it instead.
		answerWith(
			txAnswer(undefined, {
				code: 2,
				message: 'No such mempool or blockchain transaction'
			})
		);
		// The rescan the ghost path fires needs a server; the record is the subject.
		sinon.stub(wallet, 'rescanAddresses').resolves(ok(wallet.data));

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		const stored = wallet.transactions[TXID];
		expect(stored.exists, 'the server does not have it').to.equal(false);
		expect(
			stored.height,
			'so neither does the height it was found at'
		).to.equal(0);
		expect(stored.blockhash).to.equal(undefined);
		expect(stored.confirmTimestamp).to.equal(undefined);
		expect(
			messages.filter((m) => m.key === 'rbf'),
			'the removal is reported once'
		).to.have.length(1);
	});

	it('leaves the record alone when the server errors on the lookup', async function () {
		// Not a "no such transaction": the server is simply unable to answer, so
		// it has told us nothing about where the transaction is.
		answerWith(
			txAnswer(undefined, { code: -32603, message: 'server overloaded' })
		);

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		const stored = wallet.transactions[TXID];
		expect(stored.height, 'still confirmed where it was').to.equal(
			REORGED_HEIGHT
		);
		expect(stored.blockhash).to.equal(BLOCK_HASH);
		expect(
			wallet.getUnconfirmedTransactions()[TXID]?.height,
			'and still under observation'
		).to.equal(REORGED_HEIGHT);
		expect(
			messages.filter((m) => m.key === 'reorg' || m.key === 'rbf'),
			'an unanswered lookup is not a reorg'
		).to.have.length(0);
	});

	it('leaves a transaction the chain still holds alone', async function () {
		answerWith(txAnswer(2));

		await wallet.checkUnconfirmedTransactions();

		const stored = wallet.transactions[TXID];
		expect(stored.height, 'still confirmed where it was').to.equal(
			REORGED_HEIGHT
		);
		expect(stored.blockhash).to.equal(BLOCK_HASH);
		expect(
			messages.filter((m) => m.key === 'reorg'),
			'nothing was undone'
		).to.have.length(0);
	});

	it('does not read a transaction still in the mempool as reorged', async function () {
		wallet.data.transactions[TXID] = confirmedRecord(0);
		wallet.data.unconfirmedTransactions[TXID] = confirmedRecord(0);
		answerWith(txAnswer(0));

		await wallet.checkUnconfirmedTransactions();

		expect(
			messages.filter((m) => m.key === 'reorg'),
			'a transaction that was never confirmed cannot be reorged out'
		).to.have.length(0);
	});

	it('keeps a transaction whose batched lookup failed under observation (issue #872)', async function () {
		// Lookups go out in batches and a batch that fails is dropped from the
		// response, which still reports success. Nothing comes back for this
		// hash, so the reconciliation has to notice the silence for itself.
		const batch = sinon.stub(electrumHelpers, 'getTransactions').resolves({
			error: true,
			id: 0,
			method: 'getTransactions',
			network: 'bitcoinRegtest',
			data: []
		});

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);
		expect(batch.callCount, 'the lookup was attempted').to.equal(1);

		expect(
			wallet.getUnconfirmedTransactions()[TXID]?.height,
			'a failed batch says nothing, so the transaction stays observed'
		).to.equal(REORGED_HEIGHT);
		expect(
			savedUnconfirmed()[TXID]?.height,
			'and a restart reads it back, so the next refresh asks again'
		).to.equal(REORGED_HEIGHT);
		expect(
			messages.filter((m) => m.key === 'reorg' || m.key === 'rbf'),
			'a failed batch is not a reorg'
		).to.have.length(0);
	});

	it('skips an entry the server answered with an error when formatting (issue #934)', async function () {
		// A history refresh hands every lookup answer to the formatter, and a
		// server may answer one entry of a batch with an error and no result.
		// Reading that entry's txid threw inside an unawaited async callback: an
		// unhandled rejection, which terminates the process on Node >= 15.
		const FAILED_TXID = 'cd'.repeat(32);
		const failed = {
			id: 1,
			jsonrpc: '2.0',
			param: FAILED_TXID,
			data: { tx_hash: FAILED_TXID },
			error: { code: 2, message: 'server overloaded' }
		} as unknown as ITransaction<IUtxo>;

		const rejections = await captureUnhandledRejections(async () => {
			const res = await wallet.formatTransactions({
				transactions: [failed, txAnswer(2)]
			});
			expect(res.isOk(), 'the batch was formatted').to.equal(true);
			if (res.isOk()) {
				expect(
					Object.keys(res.value),
					'the answered entry is formatted, the failed one skipped'
				).to.deep.equal([TXID]);
				expect(res.value[TXID].txid).to.equal(TXID);
			}
		});
		expect(
			rejections.map((reason) => String(reason)),
			'nothing rejected unhandled'
		).to.deep.equal([]);
	});

	it('reads the rbf signal of each transaction on its own (issue #941)', async function () {
		// The flag was shared by the whole batch, so every transaction formatted
		// after one that signals replaceability was stored as rbf too. Coinbase
		// style inputs keep this offline: they need no previous output lookup.
		const withSequence = (
			txid: string,
			sequence: number
		): ITransaction<IUtxo> => {
			const answer = txAnswer(2) as unknown as {
				param: string;
				data: { tx_hash: string };
				result: { hash: string; txid: string; vin: unknown[] };
			};
			return {
				...answer,
				param: txid,
				data: { tx_hash: txid },
				result: {
					...answer.result,
					hash: txid,
					txid,
					vin: [{ coinbase: '00', sequence }]
				}
			} as unknown as ITransaction<IUtxo>;
		};
		const SIGNALS = 'ee'.repeat(32);
		const FINAL = 'ff'.repeat(32);

		const res = await wallet.formatTransactions({
			transactions: [
				withSequence(SIGNALS, 0xfffffffd),
				withSequence(FINAL, 0xffffffff)
			]
		});
		expect(res.isOk(), 'the batch was formatted').to.equal(true);
		if (res.isOk()) {
			expect(res.value[SIGNALS].rbf, 'the signalling transaction').to.equal(
				true
			);
			expect(
				res.value[FINAL].rbf,
				'a final transaction formatted after it'
			).to.equal(false);
		}
	});
});

/**
 * Regression: a reorg repair that failed to reach storage must be tried again
 * (issue #870).
 *
 * The write of the repaired transaction was not checked, while the unconfirmed
 * copy that drives the next check was advanced to zero or deleted. So a single
 * failed write left a transaction stored as confirmed at a block the chain no
 * longer has, with nothing under observation to notice it, permanently.
 *
 * Fully OFFLINE, as above, over storage that hands back copies, as a real
 * one does, and can refuse either transaction map. Every record starts out in
 * storage and reaches the wallet through a restart, so what a restart reads
 * back is exactly what each case asserts on.
 */
describe('a reorg repair that storage refuses (issue #870)', function () {
	this.timeout(60000);

	const OTHER_TXID =
		'bbb870ee62fa1d2b5c8b2f4b2b6c4d8e1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e';

	/** The private step through which a refresh observes what it found. */
	type TWalletInternals = {
		addUnconfirmedTransactions: (args: {
			transactions: Record<string, IFormattedTransaction>;
		}) => Promise<Result<string>>;
	};

	let wallet: Wallet;
	let messages: Array<{ key: keyof TMessageDataMap; data: unknown }>;
	/** What a restart would read back. */
	const store = new Map<string, unknown>();
	/** Refuses the main record, `transactions`. */
	const failMainWrite = { on: false };
	/** Refuses the copy under observation, `unconfirmedTransactions`. */
	const failMonitorWrite = { on: false };

	const copy = <T>(value: T): T =>
		value === undefined ? value : JSON.parse(JSON.stringify(value));

	const storage: TStorage = {
		getData: async <K extends keyof IWalletData>(
			key: string
		): Promise<Result<IWalletData[K]>> =>
			ok(copy(store.get(key)) as IWalletData[K]),
		setData: async <K extends keyof IWalletData>(
			key: string,
			value: IWalletData[K]
		): Promise<Result<boolean>> => {
			// Keys end in the wallet data key, and neither suffix ends the other.
			if (failMainWrite.on && key.endsWith('-transactions')) {
				return err('storage is down');
			}
			if (failMonitorWrite.on && key.endsWith('-unconfirmedTransactions')) {
				return err('storage is down');
			}
			store.set(key, copy(value));
			return ok(true);
		}
	};

	/** A wallet over whatever storage currently holds. */
	const openWallet = async (): Promise<Wallet> => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'reorgrepair',
			network: EAvailableNetworks.regtest,
			addressType: EAddressType.p2wpkh,
			electrumOptions,
			disableRefreshOnCreate: true,
			onMessage: (key, data): void => {
				messages.push({ key, data });
			},
			storage
		});
		if (res.isErr()) throw res.error;
		res.value.data.header = { height: TIP, hash: '', hex: '' };
		return res.value;
	};

	/** Closes the wallet and opens a new one over the same storage. */
	const restart = async (): Promise<void> => {
		sinon.restore();
		await wallet.stop();
		wallet = await openWallet();
	};

	/** Puts both transaction maps in storage and restarts onto them. */
	const seed = async (
		transactions: Record<string, IFormattedTransaction>,
		unconfirmed: Record<string, IFormattedTransaction>
	): Promise<void> => {
		store.set(wallet.getWalletDataKey('transactions'), copy(transactions));
		store.set(
			wallet.getWalletDataKey('unconfirmedTransactions'),
			copy(unconfirmed)
		);
		await restart();
	};

	// Answers only for the hashes actually asked about, since what is still
	// under observation is the whole subject here.
	const answerWith = (...answers: ITransaction<IUtxo>[]): void => {
		sinon
			.stub(wallet.electrum, 'getTransactions')
			.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) =>
				ok<IGetTransactions>({
					error: false,
					id: 0,
					method: 'getTransactions',
					network: 'bitcoinRegtest',
					data: answers.filter((answer) =>
						txHashes.some((h) => h.tx_hash === answer.data.tx_hash)
					)
				})
			);
	};

	/** The rescan the ghost path fires needs a server; it is counted instead. */
	const stubRescan = (): sinon.SinonStub =>
		sinon.stub(wallet, 'rescanAddresses').resolves(ok(wallet.data));

	const stored = (
		key: 'transactions' | 'unconfirmedTransactions'
	): Record<string, IFormattedTransaction> =>
		store.get(wallet.getWalletDataKey(key)) as Record<
			string,
			IFormattedTransaction
		>;

	const sent = (key: keyof TMessageDataMap): unknown[] =>
		messages.filter((m) => m.key === key);

	const noSuchTransaction = (txid = TXID): ITransaction<IUtxo> =>
		txAnswer(
			undefined,
			{
				code: 2,
				message:
					'No such mempool or blockchain transaction. Use gettransaction for wallet transactions.'
			},
			txid
		);

	beforeEach(async function () {
		store.clear();
		messages = [];
		failMainWrite.on = false;
		failMonitorWrite.on = false;
		wallet = await openWallet();
		await seed(
			{ [TXID]: confirmedRecord(REORGED_HEIGHT) },
			{ [TXID]: confirmedRecord(REORGED_HEIGHT) }
		);
	});

	afterEach(async function () {
		sinon.restore();
		await wallet?.stop();
	});

	it('reports a failed write and keeps the transaction under observation', async function () {
		answerWith(txAnswer(0));
		failMainWrite.on = true;

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isErr(), 'the check reports the write it lost').to.equal(true);

		expect(
			stored('transactions')[TXID].height,
			'the stored record was not repaired'
		).to.equal(REORGED_HEIGHT);
		expect(
			stored('unconfirmedTransactions')[TXID].height,
			'so the copy that asks again still holds the height a reorg undid'
		).to.equal(REORGED_HEIGHT);
	});

	it('repairs the record on the next check in the same session', async function () {
		answerWith(txAnswer(0));
		failMainWrite.on = true;
		await wallet.checkUnconfirmedTransactions();
		expect(
			wallet.getUnconfirmedTransactions()[TXID].height,
			'the copy the next check reads the reorg from was not advanced'
		).to.equal(REORGED_HEIGHT);

		failMainWrite.on = false;
		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the repair was tried again').to.equal(true);

		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(stored('transactions')[TXID].blockhash).to.equal(undefined);
		expect(stored('unconfirmedTransactions')[TXID].height).to.equal(0);
	});

	it('repairs a record a refresh left behind a failed write, after a restart', async function () {
		// The refresh goes on past the failed check and finds the transaction
		// in its address history at zero, which rewrites the copy under
		// observation at zero as well. So the stored record is the only place
		// the lost block is left.
		const record: IFormattedTransaction = {
			...confirmedRecord(0),
			blockhash: undefined,
			confirmTimestamp: undefined
		};
		answerWith(txAnswer(0));
		sinon
			.stub(wallet.electrum, 'getAddressHistory')
			.resolves(ok([{ tx_hash: TXID, height: 0 } as never]));
		sinon.stub(wallet, 'formatTransactions').resolves(ok({ [TXID]: record }));
		const added = sinon.spy(
			wallet as unknown as TWalletInternals,
			'addUnconfirmedTransactions'
		);
		failMainWrite.on = true;

		await wallet.updateTransactions({});
		expect(added.callCount, 'the refresh observed its history').to.equal(1);
		await added.firstCall.returnValue;
		expect(
			stored('transactions')[TXID].height,
			'the repair did not reach storage'
		).to.equal(REORGED_HEIGHT);

		failMainWrite.on = false;
		await restart();
		answerWith(txAnswer(0));
		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(stored('transactions')[TXID].blockhash).to.equal(undefined);
	});

	it('repairs the record on the next check after a restart', async function () {
		answerWith(txAnswer(0));
		failMainWrite.on = true;
		await wallet.checkUnconfirmedTransactions();

		failMainWrite.on = false;
		await restart();
		expect(
			wallet.transactions[TXID].height,
			'the restart reads the transaction back as confirmed'
		).to.equal(REORGED_HEIGHT);

		answerWith(txAnswer(0));
		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the repair was tried again').to.equal(true);

		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(stored('transactions')[TXID].blockhash).to.equal(undefined);
		expect(stored('unconfirmedTransactions')[TXID].height).to.equal(0);
	});

	it('keeps watching a ghost transaction whose write failed', async function () {
		answerWith(noSuchTransaction());
		const rescan = stubRescan();
		failMainWrite.on = true;

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isErr(), 'the check reports the write it lost').to.equal(true);

		expect(
			stored('transactions')[TXID].height,
			'the stored record was not repaired'
		).to.equal(REORGED_HEIGHT);
		expect(stored('transactions')[TXID].exists).to.equal(true);
		expect(
			stored('unconfirmedTransactions')[TXID]?.height,
			'so it is still looked up on the next check'
		).to.equal(REORGED_HEIGHT);
		expect(
			rescan.callCount,
			'and no rescan runs while it is still observed, since its refresh would repeat this check'
		).to.equal(0);
	});

	it('repairs a ghost transaction on the next check in the same session', async function () {
		answerWith(noSuchTransaction());
		const rescan = stubRescan();
		failMainWrite.on = true;
		await wallet.checkUnconfirmedTransactions();
		expect(
			wallet.getUnconfirmedTransactions()[TXID]?.height,
			'the ghost is still observed'
		).to.equal(REORGED_HEIGHT);

		failMainWrite.on = false;
		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the repair was tried again').to.equal(true);

		expect(stored('transactions')[TXID].exists).to.equal(false);
		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(stored('unconfirmedTransactions')[TXID]).to.equal(undefined);
		expect(rescan.callCount, 'the balance is rescanned once').to.equal(1);
	});

	it('keeps a transaction a refresh adds while a ghost round runs', async function () {
		// A refresh running beside the check finds a transaction already in a
		// block while the lookup is in flight. A confirmed record is not
		// fetched again, so this entry is all that would notice a later reorg.
		stubRescan();
		sinon
			.stub(wallet.electrum, 'getTransactions')
			.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) => {
				await (
					wallet as unknown as TWalletInternals
				).addUnconfirmedTransactions({
					transactions: { [OTHER_TXID]: confirmedRecord(TIP, OTHER_TXID) }
				});
				return ok<IGetTransactions>({
					error: false,
					id: 0,
					method: 'getTransactions',
					network: 'bitcoinRegtest',
					data: txHashes.map((h) => noSuchTransaction(h.tx_hash))
				});
			});

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		expect(stored('transactions')[TXID].exists).to.equal(false);
		expect(stored('unconfirmedTransactions')[TXID]).to.equal(undefined);
		expect(
			wallet.getUnconfirmedTransactions()[OTHER_TXID]?.height,
			'the new transaction is still observed'
		).to.equal(TIP);
		expect(
			stored('unconfirmedTransactions')[OTHER_TXID]?.height,
			'after a restart too'
		).to.equal(TIP);
	});

	it('repairs a ghost transaction on the next check after a restart', async function () {
		answerWith(noSuchTransaction());
		stubRescan();
		failMainWrite.on = true;
		await wallet.checkUnconfirmedTransactions();

		failMainWrite.on = false;
		await restart();
		answerWith(noSuchTransaction());
		const rescan = stubRescan();

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the repair was tried again').to.equal(true);

		expect(stored('transactions')[TXID].exists).to.equal(false);
		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(
			stored('unconfirmedTransactions')[TXID],
			'and only now is it dropped from observation'
		).to.equal(undefined);
		expect(rescan.callCount, 'the balance is rescanned').to.equal(1);
	});

	it('reports a failed write of the copy under observation', async function () {
		answerWith(txAnswer(0));
		failMonitorWrite.on = true;

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isErr(), 'Ok means every write the check made landed').to.equal(
			true
		);
		expect(
			stored('transactions')[TXID].height,
			'the repair itself is durable'
		).to.equal(0);

		failMonitorWrite.on = false;
		const retry = await wallet.checkUnconfirmedTransactions();
		expect(retry.isOk(), 'the next check writes it again').to.equal(true);
		expect(stored('unconfirmedTransactions')[TXID].height).to.equal(0);
		expect(
			sent('reorg'),
			'without reporting the reorg a second time'
		).to.have.length(1);
	});

	it('still rescans a ghost when only the write of its observed copy fails', async function () {
		answerWith(noSuchTransaction());
		const rescan = stubRescan();
		failMonitorWrite.on = true;

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isErr(), 'the lost write is reported').to.equal(true);
		expect(
			stored('transactions')[TXID].exists,
			'the repair itself is durable'
		).to.equal(false);
		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(
			rescan.callCount,
			'and the balance is still rescanned, since nothing in this session asks again'
		).to.equal(1);
	});

	it('repairs a record a lost write already left confirmed', async function () {
		// What the unchecked write left behind: the main record still at the
		// lost block, and the copy under observation already at zero.
		await seed(
			{ [TXID]: confirmedRecord(REORGED_HEIGHT) },
			{ [TXID]: confirmedRecord(0) }
		);
		answerWith(txAnswer(0));

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		expect(
			stored('transactions')[TXID].height,
			'the main record is evidence of the lost block too'
		).to.equal(0);
		expect(stored('transactions')[TXID].blockhash).to.equal(undefined);
		expect(sent('reorg'), 'the reorg is reported once').to.have.length(1);
	});

	it('leaves such a record alone while the chain still holds it', async function () {
		await seed(
			{ [TXID]: confirmedRecord(REORGED_HEIGHT) },
			{ [TXID]: confirmedRecord(0) }
		);
		answerWith(txAnswer(2));

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		expect(
			stored('transactions')[TXID].height,
			'still confirmed where it was'
		).to.equal(REORGED_HEIGHT);
		expect(stored('transactions')[TXID].blockhash).to.equal(BLOCK_HASH);
		expect(sent('reorg'), 'nothing was undone').to.have.length(0);
	});

	it('reports a reorg once when the same round also loses a transaction', async function () {
		// One transaction is back in the mempool, the other is gone. A round
		// with a ghost in it used to keep the old copy of the first, still at
		// the lost block, so the next check reported the same reorg again.
		await seed(
			{
				[TXID]: confirmedRecord(REORGED_HEIGHT),
				[OTHER_TXID]: confirmedRecord(REORGED_HEIGHT, OTHER_TXID)
			},
			{
				[TXID]: confirmedRecord(REORGED_HEIGHT),
				[OTHER_TXID]: confirmedRecord(REORGED_HEIGHT, OTHER_TXID)
			}
		);
		answerWith(txAnswer(0), noSuchTransaction(OTHER_TXID));
		stubRescan();

		const first = await wallet.checkUnconfirmedTransactions();
		const second = await wallet.checkUnconfirmedTransactions();
		expect(first.isOk(), 'the first check ran').to.equal(true);
		expect(second.isOk(), 'the second check ran').to.equal(true);

		expect(sent('reorg'), 'the reorg is reported once').to.have.length(1);
		expect(sent('rbf'), 'and so is the removal').to.have.length(1);
		expect(
			stored('unconfirmedTransactions')[TXID]?.height,
			'the transaction back in the mempool is observed at zero'
		).to.equal(0);
		expect(stored('unconfirmedTransactions')[OTHER_TXID]).to.equal(undefined);
		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(stored('transactions')[OTHER_TXID].exists).to.equal(false);
	});
});
