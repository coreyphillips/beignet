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
 * reorg. The formatter cases cover issues #934 and #941: an entry the server
 * answered with an error reaches the formatter too, and must be skipped
 * there. Then issue #945: a lost transaction the server serves again is
 * shown as held again. The cases after them cover issue #871: a node
 * without a txindex answers a transaction in no block and not in its mempool
 * in words of its own. And issue #935: for a transaction only seen in the
 * mempool, that answer is final once it outlasts two new blocks.
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
	IGetAddressHistoryResponse,
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

// Bitcoin Core's answers for a transaction it cannot find, which electrs
// relays unchanged with code 2. Every one ends in the same hint.
const WALLET_HINT = ' Use gettransaction for wallet transactions.';
/** With a txindex: in no block and not in the mempool. */
const TXINDEX_MISS = `No such mempool or blockchain transaction.${WALLET_HINT}`;
/** Without a txindex: not in the mempool, the only place such a node looks. */
const NO_TXINDEX_MISS = `No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries.${WALLET_HINT}`;
/** The same from Core before 0.17. */
const OLD_NO_TXINDEX_MISS = `No such mempool transaction. Use -txindex to enable blockchain transaction queries.${WALLET_HINT}`;
/** With a txindex still being built: says nothing about the chain. */
const STILL_INDEXING = `No such mempool transaction. Blockchain transactions are still in the process of being indexed.${WALLET_HINT}`;
/** The no-txindex answer inside the daemon error an ElectrumX or Fulcrum returns. */
const WRAPPED_NO_TXINDEX_MISS = `daemon error: DaemonError({'code': -5, 'message': '${NO_TXINDEX_MISS}'})`;

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

/**
 * The record of a transaction only ever seen in the mempool: height 0, or -1
 * with unconfirmed parents, and no block.
 */
const mempoolRecord = (height: 0 | -1 = 0): IFormattedTransaction => ({
	...confirmedRecord(height),
	blockhash: undefined,
	confirmTimestamp: undefined
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

	/** A wallet writing to `saved` and reporting to `messages`. */
	const openWallet = async (): Promise<Wallet> => {
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
		return res.value;
	};

	beforeEach(async function () {
		saved = {};
		messages = [];
		wallet = await openWallet();

		wallet.data.header = { height: TIP, hash: '', hex: '' };
		wallet.data.transactions[TXID] = confirmedRecord(REORGED_HEIGHT);
		wallet.data.unconfirmedTransactions[TXID] = confirmedRecord(REORGED_HEIGHT);
	});

	afterEach(async function () {
		sinon.restore();
		// Every Electrum instance polls its connection until stopped, and a
		// wallet left running keeps calling the shared client other suites stub.
		await wallet?.stop();
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

	/** The lookup's reply carrying these answers. */
	const lookupReply = (
		...data: ITransaction<IUtxo>[]
	): Result<IGetTransactions> =>
		ok<IGetTransactions>({
			error: false,
			id: 0,
			method: 'getTransactions',
			network: 'bitcoinRegtest',
			data
		});

	const answerWith = (tx: ITransaction<IUtxo>): sinon.SinonStub =>
		sinon.stub(wallet.electrum, 'getTransactions').resolves(lookupReply(tx));

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

	it('clears the height when a server with a txindex loses the transaction', async function () {
		// A reorg'd out transaction no mempool took back is not "unconfirmed",
		// it is unknown, and the ghost path handles it instead.
		answerWith(txAnswer(undefined, { code: 2, message: TXINDEX_MISS }));
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

	/**
	 * Issue #945: the ghost path leaves a record it clears at height 0, and a
	 * transaction back in the mempool is listed at height 0 as well. A refresh
	 * rewrote a stored record only when it was new or its height changed, so a
	 * returned transaction stayed cleared until it confirmed.
	 */
	describe('a lost transaction back in the mempool (issue #945)', function () {
		/** The transaction's address history entry, as a refresh reads it. */
		const historyEntry = {
			tx_hash: TXID,
			height: 0,
			address: confirmedRecord(0).address,
			scriptHash: SCRIPT_HASH
		} as IGetAddressHistoryResponse;

		/**
		 * The server's answer for a looked up entry: served from its mempool, or
		 * missed. A served answer echoes the entry back as its data, as the
		 * client does, and a refresh reads the height from there.
		 */
		const answer = (h: ITxHash, served: boolean): ITransaction<IUtxo> =>
			served
				? ({
						...txAnswer(0, undefined, h.tx_hash),
						data: h
				  } as unknown as ITransaction<IUtxo>)
				: txAnswer(undefined, { code: 2, message: TXINDEX_MISS }, h.tx_hash);

		/** Every lookup answered as `served` says at the time. */
		const serveWhile = (served: () => boolean): sinon.SinonStub =>
			sinon
				.stub(wallet.electrum, 'getTransactions')
				.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) =>
					lookupReply(...txHashes.map((h) => answer(h, served())))
				);

		/** Messages announcing a transaction or its confirmation since `from`. */
		const announced = (from: number): typeof messages =>
			messages
				.slice(from)
				.filter((m) =>
					[
						'transactionReceived',
						'transactionSent',
						'transactionConfirmed'
					].includes(m.key)
				);

		beforeEach(function () {
			// The rescan the ghost path fires needs a server.
			sinon.stub(wallet, 'rescanAddresses').resolves(ok(wallet.data));
			sinon
				.stub(wallet.electrum, 'getAddressHistory')
				.resolves(ok([historyEntry]));
		});

		const cases: Array<[string, () => IFormattedTransaction]> = [
			[
				'a transaction reorged out',
				(): IFormattedTransaction => confirmedRecord(REORGED_HEIGHT)
			],
			[
				'a transaction only seen in the mempool',
				(): IFormattedTransaction => mempoolRecord()
			]
		];
		for (const [kind, record] of cases) {
			it(`shows ${kind} again once it returns to the mempool`, async function () {
				wallet.data.transactions[TXID] = record();
				wallet.data.unconfirmedTransactions[TXID] = record();
				let back = false;
				serveWhile(() => back);

				await wallet.checkUnconfirmedTransactions();
				expect(wallet.transactions[TXID].exists, 'lost').to.equal(false);
				expect(wallet.transactions[TXID].height).to.equal(0);
				expect(
					wallet.getUnconfirmedTransactions()[TXID],
					'and no longer observed'
				).to.equal(undefined);

				// Rebroadcast: the history lists it at 0 and the server serves it.
				back = true;
				const before = messages.length;
				const res = await wallet.updateTransactions({});
				expect(res.isOk(), 'the refresh ran').to.equal(true);

				expect(wallet.transactions[TXID].exists, 'pending again').to.equal(
					true
				);
				const persisted = savedTransactions()[TXID];
				expect(persisted.exists, 'and a restart reads it so').to.equal(true);
				expect(persisted.height, 'in the mempool').to.equal(0);
				expect(persisted.address, 'at the same address').to.equal(
					record().address
				);
				expect(persisted.timestamp, 'first seen time kept').to.equal(
					record().timestamp
				);
				expect(
					wallet.getUnconfirmedTransactions()[TXID]?.height,
					'and observed again'
				).to.equal(0);
				expect(
					announced(before),
					'a transaction the wallet held is not news'
				).to.have.length(0);
			});
		}

		it('keeps it lost while the server still misses it', async function () {
			serveWhile(() => false);
			await wallet.checkUnconfirmedTransactions();
			expect(wallet.transactions[TXID].exists, 'lost').to.equal(false);

			// The history can lag the node, and still list a transaction the
			// node replaced or evicted. Only a served answer brings it back.
			const before = messages.length;
			const res = await wallet.updateTransactions({});
			expect(res.isOk(), 'the refresh ran').to.equal(true);

			expect(wallet.transactions[TXID].exists, 'still lost').to.equal(false);
			expect(savedTransactions()[TXID].exists).to.equal(false);
			expect(messages.slice(before), 'and nothing was reported').to.have.length(
				0
			);
		});

		it('does not undo a clearing newer than its lookup', async function () {
			// Still in the mempool when the refresh starts.
			wallet.data.transactions[TXID] = mempoolRecord();
			wallet.data.unconfirmedTransactions[TXID] = mempoolRecord();
			let gone = false;
			sinon
				.stub(wallet.electrum, 'getTransactions')
				.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) => {
					// The refresh's lookup of its address history, whose entries
					// carry a height. The node loses the transaction while it is in
					// flight, and a check beside the refresh, such as the one a new
					// header runs, clears it from that newer answer.
					if (!gone && txHashes.some((h) => 'height' in h)) {
						gone = true;
						await wallet.checkUnconfirmedTransactions();
						// Answered before the node lost it.
						return lookupReply(...txHashes.map((h) => answer(h, true)));
					}
					return lookupReply(...txHashes.map((h) => answer(h, !gone)));
				});

			const res = await wallet.updateTransactions({});
			expect(res.isOk(), 'the refresh ran').to.equal(true);

			expect(
				wallet.transactions[TXID].exists,
				'the newer answer stands'
			).to.equal(false);
			expect(savedTransactions()[TXID].exists).to.equal(false);
			expect(
				messages.filter((m) => m.key === 'rbf'),
				'the removal is reported once'
			).to.have.length(1);
		});

		it('does not undo a clearing again newer than its lookup', async function () {
			let served = false;
			let lookups = 0;
			sinon
				.stub(wallet.electrum, 'getTransactions')
				.callsFake(async ({ txHashes }: { txHashes: ITxHash[] }) => {
					// The refresh's first lookup of its address history. While it
					// is in flight, a second refresh, such as the one a rescan
					// forces, finds the transaction back. Then the node loses it
					// again, and a check clears it from that newer answer.
					if (txHashes.some((h) => 'height' in h) && ++lookups === 1) {
						await wallet.updateTransactions({});
						expect(wallet.transactions[TXID].exists, 'back').to.equal(true);
						served = false;
						await wallet.checkUnconfirmedTransactions();
						expect(wallet.transactions[TXID].exists, 'lost again').to.equal(
							false
						);
						// Answered before the node lost it again.
						return lookupReply(...txHashes.map((h) => answer(h, true)));
					}
					return lookupReply(...txHashes.map((h) => answer(h, served)));
				});

			// Already cleared when the refresh starts: its flag reads the same
			// before and after its lookup.
			await wallet.checkUnconfirmedTransactions();
			expect(wallet.transactions[TXID].exists, 'lost').to.equal(false);

			served = true;
			const res = await wallet.updateTransactions({});
			expect(res.isOk(), 'the refresh ran').to.equal(true);

			expect(
				wallet.transactions[TXID].exists,
				'the newer answer stands'
			).to.equal(false);
			expect(savedTransactions()[TXID].exists).to.equal(false);
			expect(
				messages.filter((m) => m.key === 'rbf'),
				'each removal is reported once'
			).to.have.length(2);
		});
	});

	/**
	 * Issue #871: a node without a txindex searches only its mempool, and its
	 * "no such transaction" was not read as a miss at all, so a transaction
	 * reorged out of the chain and out of every mempool stayed confirmed.
	 * electrs finds a confirmed transaction in its own index first, but only in
	 * blocks it has indexed, so the answer is a miss only for a record already
	 * seen in a block safely below the tip.
	 */
	describe('a node without a txindex (issue #871)', function () {
		const tipAt = (height: number): void => {
			wallet.data.header = { height, hash: '', hex: '' };
		};

		const miss = (message: string): ITransaction<IUtxo> =>
			txAnswer(undefined, { code: 2, message });

		const stubRescan = (): sinon.SinonStub =>
			sinon.stub(wallet, 'rescanAddresses').resolves(ok(wallet.data));

		/** The record is where it was, still observed, and nothing was sent. */
		const expectKept = (
			rescan: sinon.SinonStub,
			height = REORGED_HEIGHT
		): void => {
			const stored = wallet.transactions[TXID];
			expect(stored.exists, 'still held').to.equal(true);
			expect(stored.height, 'at the height it was found at').to.equal(height);
			expect(
				wallet.getUnconfirmedTransactions()[TXID]?.height,
				'and still observed, so the next refresh asks again'
			).to.equal(height);
			expect(
				messages.filter((m) => m.key === 'reorg' || m.key === 'rbf'),
				'nothing was reported'
			).to.have.length(0);
			expect(rescan.callCount, 'and nothing rescanned').to.equal(0);
		};

		beforeEach(function () {
			// Two blocks past the record: even a server a block behind has it.
			tipAt(REORGED_HEIGHT + 2);
		});

		it('clears the height when the node has it in neither a block nor its mempool', async function () {
			answerWith(miss(NO_TXINDEX_MISS));
			const rescan = stubRescan();

			const res = await wallet.checkUnconfirmedTransactions();
			expect(res.isOk(), 'the check ran').to.equal(true);

			const stored = wallet.transactions[TXID];
			expect(stored.exists, 'the chain does not have it').to.equal(false);
			expect(
				stored.height,
				'so neither does the height it was found at'
			).to.equal(0);
			expect(stored.blockhash).to.equal(undefined);
			expect(stored.confirmTimestamp).to.equal(undefined);
			expect(
				wallet.getUnconfirmedTransactions()[TXID],
				'and it is no longer observed'
			).to.equal(undefined);
			expect(savedTransactions()[TXID].exists).to.equal(false);
			expect(savedTransactions()[TXID].height).to.equal(0);
			expect(savedUnconfirmed()[TXID]).to.equal(undefined);

			const rbf = messages.filter((m) => m.key === 'rbf');
			expect(rbf, 'the removal is reported once').to.have.length(1);
			expect(rbf[0].data).to.deep.equal([TXID]);
			expect(messages.filter((m) => m.key === 'reorg')).to.have.length(0);
			expect(rescan.callCount, 'and the balance rescanned').to.equal(1);
		});

		it('clears a record a lost write left confirmed (issue #870)', async function () {
			// The main record still names the block while the observed copy
			// already reads zero. The main record is evidence of that block too.
			wallet.data.unconfirmedTransactions[TXID] = confirmedRecord(0);
			answerWith(miss(NO_TXINDEX_MISS));
			stubRescan();

			await wallet.checkUnconfirmedTransactions();

			expect(wallet.transactions[TXID].exists).to.equal(false);
			expect(wallet.transactions[TXID].height).to.equal(0);
			expect(savedTransactions()[TXID].height).to.equal(0);
		});

		it('waits for the tip to pass a block a lagging server may not hold yet', async function () {
			// A failover commonly lands on a server a block behind, whose
			// electrs has not indexed the newest block while its node has
			// already taken the transaction out of its mempool. Heights written
			// from a confirmation count also run a block low. So a record at the
			// tip or one block under it is asked about again, not cleared.
			answerWith(miss(NO_TXINDEX_MISS));
			const rescan = stubRescan();

			for (const tip of [REORGED_HEIGHT, REORGED_HEIGHT + 1]) {
				tipAt(tip);
				const res = await wallet.checkUnconfirmedTransactions();
				expect(res.isOk(), `the check ran at tip ${tip}`).to.equal(true);
				expectKept(rescan);
			}

			// The count of issue #935 is final here too: for a record seen in a
			// block it counts from that block. The single checks above hold this
			// rule to its own margin.
			tipAt(REORGED_HEIGHT + 2);
			await wallet.checkUnconfirmedTransactions();
			expect(
				wallet.transactions[TXID].exists,
				'once the tip has moved on, the miss is final'
			).to.equal(false);
			expect(wallet.transactions[TXID].height).to.equal(0);
			expect(rescan.callCount).to.equal(1);
		});

		it('keeps a transaction never seen in a block', async function () {
			// The same answer is what a transaction mined into a block electrs
			// has not indexed yet gets, so for one this wallet has only seen in
			// the mempool (height 0, or -1 with unconfirmed parents) it says
			// nothing about the chain.
			answerWith(miss(NO_TXINDEX_MISS));
			const rescan = stubRescan();

			for (const height of [0, -1]) {
				wallet.data.transactions[TXID] = confirmedRecord(height);
				wallet.data.unconfirmedTransactions[TXID] = confirmedRecord(height);
				await wallet.checkUnconfirmedTransactions();
				expectKept(rescan, height);
			}
		});

		it('does not read a txindex still being built as a miss', async function () {
			answerWith(miss(STILL_INDEXING));
			const rescan = stubRescan();

			await wallet.checkUnconfirmedTransactions();

			expectKept(rescan);
			expect(wallet.transactions[TXID].blockhash).to.equal(BLOCK_HASH);
		});

		it('does not read a wrapped daemon error as a miss', async function () {
			// A server that wraps daemon errors needs a txindex. Pointed at a
			// node without one, it would report every confirmed transaction as
			// missing, so only the unwrapped answer counts.
			answerWith(miss(WRAPPED_NO_TXINDEX_MISS));
			const rescan = stubRescan();

			await wallet.checkUnconfirmedTransactions();

			expectKept(rescan);
		});

		it('does not read the miss before the wallet knows a tip', async function () {
			tipAt(0);
			answerWith(miss(NO_TXINDEX_MISS));
			const rescan = stubRescan();

			await wallet.checkUnconfirmedTransactions();

			expectKept(rescan);
		});

		it('tells that answer apart from every other', function () {
			const table: Array<[string, ITransaction<IUtxo>, boolean]> = [
				['the no-txindex miss', miss(NO_TXINDEX_MISS), true],
				[
					'the no-txindex miss before Core 0.17',
					miss(OLD_NO_TXINDEX_MISS),
					true
				],
				['the txindex miss', miss(TXINDEX_MISS), false],
				['a txindex still being built', miss(STILL_INDEXING), false],
				['a wrapped daemon error', miss(WRAPPED_NO_TXINDEX_MISS), false],
				['a busy server', miss('server overloaded'), false],
				['an answer with no error', txAnswer(2), false]
			];
			for (const [what, answer, expected] of table) {
				expect(
					wallet.electrum.transactionMissingWithoutTxindex(answer),
					what
				).to.equal(expected);
			}
		});

		/**
		 * Issue #935: for a record only ever seen in the mempool, which the rule
		 * above keeps, the same answer is final once it outlasts two new blocks.
		 * electrs indexes a block before it announces the block's header, so by
		 * then a transaction mined in the meantime is found through its index,
		 * and one still missing was replaced or evicted. Counted from no lower
		 * than the highest tip this wallet held, nor than a block the record was
		 * seen in.
		 */
		describe('a miss that outlasts new blocks (issue #935)', function () {
			/** The tip this wallet holds at the first check that misses. */
			const FIRST_MISS = TIP;

			/** Checks once at each tip in turn. */
			const checkAt = async (...tips: number[]): Promise<void> => {
				for (const tip of tips) {
					tipAt(tip);
					const res = await wallet.checkUnconfirmedTransactions();
					expect(res.isOk(), `the check ran at tip ${tip}`).to.equal(true);
				}
			};

			/** Observes the record at this height, as a refresh would have. */
			const observe = (record: IFormattedTransaction): void => {
				wallet.data.transactions[TXID] = { ...record };
				wallet.data.unconfirmedTransactions[TXID] = { ...record };
			};

			/** The record is gone, reported and rescanned once, and unobserved. */
			const expectCleared = (rescan: sinon.SinonStub): void => {
				const stored = wallet.transactions[TXID];
				expect(stored.exists, 'the server does not have it').to.equal(false);
				expect(stored.height).to.equal(0);
				expect(
					wallet.getUnconfirmedTransactions()[TXID],
					'and it is no longer observed'
				).to.equal(undefined);
				expect(savedTransactions()[TXID].exists).to.equal(false);
				expect(savedUnconfirmed()[TXID]).to.equal(undefined);

				const rbf = messages.filter((m) => m.key === 'rbf');
				expect(rbf, 'the removal is reported once').to.have.length(1);
				expect(rbf[0].data).to.deep.equal([TXID]);
				expect(messages.filter((m) => m.key === 'reorg')).to.have.length(0);
				expect(rescan.callCount, 'and the balance rescanned once').to.equal(1);
			};

			/** The count the wallet keeps, which stop() drops. */
			const misses = (w: Wallet): Map<string, number> =>
				(w as unknown as { _noTxindexMisses: Map<string, number> })
					._noTxindexMisses;

			beforeEach(function () {
				observe(mempoolRecord(0));
			});

			for (const height of [0, -1] as const) {
				it(`clears a record at height ${height} once the miss outlasts two new blocks`, async function () {
					// Replaced or evicted: out of the mempool, and in no block.
					observe(mempoolRecord(height));
					answerWith(miss(NO_TXINDEX_MISS));
					const rescan = stubRescan();

					await checkAt(FIRST_MISS);
					expectKept(rescan, height);
					// A block on: it may be in that one, which a server a block
					// behind has not indexed.
					await checkAt(FIRST_MISS + 1);
					expectKept(rescan, height);

					await checkAt(FIRST_MISS + 2);
					expectCleared(rescan);
				});
			}

			it('starts counting again when the transaction is found in between', async function () {
				const lookup = answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();

				await checkAt(FIRST_MISS);
				lookup.resolves(lookupReply(txAnswer(0)));
				await checkAt(FIRST_MISS + 1);
				expectKept(rescan, 0);

				// Missed again: counted from here, not from the first miss.
				lookup.resolves(lookupReply(miss(NO_TXINDEX_MISS)));
				await checkAt(FIRST_MISS + 2, FIRST_MISS + 3);
				expectKept(rescan, 0);

				await checkAt(FIRST_MISS + 4);
				expectCleared(rescan);
			});

			it('never clears it while the tip stands still', async function () {
				answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();

				await checkAt(...new Array<number>(10).fill(FIRST_MISS));

				expectKept(rescan, 0);
			});

			it('counts nothing before the wallet knows a tip', async function () {
				answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();

				await checkAt(0, 0);
				expectKept(rescan, 0);

				// A miss counted at tip zero would be final at any tip from two on.
				await checkAt(FIRST_MISS, FIRST_MISS + 1);
				expectKept(rescan, 0);

				await checkAt(FIRST_MISS + 2);
				expectCleared(rescan);
			});

			it('keeps a record seen in a block above the tip until the tip passes it', async function () {
				// A failover to a server further behind lowers the tip below the
				// block the record was seen in, and that server announces new
				// blocks while it catches up to it. Two of them are not enough.
				observe(confirmedRecord(FIRST_MISS + 5));
				answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();

				await checkAt(FIRST_MISS, FIRST_MISS + 1, FIRST_MISS + 2);
				expectKept(rescan, FIRST_MISS + 5);
				await checkAt(FIRST_MISS + 6);
				expectKept(rescan, FIRST_MISS + 5);

				// Two blocks past it, the rule of #871 reads the miss as final.
				await checkAt(FIRST_MISS + 7);
				expectCleared(rescan);
			});

			it('counts from the highest tip this wallet held', async function () {
				// A failover to a server further behind lowered the tip from where
				// the transaction was last seen in the mempool. It may be in any
				// block that server catches up on past there.
				await wallet.updateHeader({
					height: FIRST_MISS + 5,
					hash: '',
					hex: ''
				});
				await wallet.updateHeader({ height: FIRST_MISS, hash: '', hex: '' });
				answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();

				await checkAt(FIRST_MISS, FIRST_MISS + 2, FIRST_MISS + 6);
				expectKept(rescan, 0);

				await checkAt(FIRST_MISS + 7);
				expectCleared(rescan);
			});

			it('judges the miss by the tip it was answered at', async function () {
				const lookup = answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();
				await checkAt(FIRST_MISS);

				// Two headers land while the next lookup is in flight, after the
				// server answered it.
				lookup.callsFake(async () => {
					tipAt(FIRST_MISS + 2);
					return lookupReply(miss(NO_TXINDEX_MISS));
				});
				await wallet.checkUnconfirmedTransactions();
				expectKept(rescan, 0);

				lookup.resolves(lookupReply(miss(NO_TXINDEX_MISS)));
				await checkAt(FIRST_MISS + 2);
				expectCleared(rescan);
			});

			it('counts no other answer', async function () {
				for (const message of [
					STILL_INDEXING,
					WRAPPED_NO_TXINDEX_MISS,
					'server overloaded'
				]) {
					sinon.restore();
					observe(mempoolRecord(0));
					answerWith(miss(message));
					const rescan = stubRescan();

					await checkAt(
						FIRST_MISS,
						FIRST_MISS + 1,
						FIRST_MISS + 2,
						FIRST_MISS + 5
					);

					expectKept(rescan, 0);
				}
			});

			it('counts afresh for a cleared transaction observed again', async function () {
				answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();
				await checkAt(FIRST_MISS, FIRST_MISS + 1, FIRST_MISS + 2);
				expectCleared(rescan);

				// Rebroadcast, say, and found again by a refresh. Its first miss
				// may be a block electrs has not indexed yet, so it counts afresh.
				observe(mempoolRecord(0));
				messages = [];
				rescan.resetHistory();
				await checkAt(FIRST_MISS + 10);

				expectKept(rescan, 0);
			});

			it('counts afresh for a deleted transaction observed again', async function () {
				answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();
				await checkAt(FIRST_MISS);

				await wallet.deleteOnChainTransactionById({ txid: TXID });
				observe(mempoolRecord(0));
				await checkAt(FIRST_MISS + 10);

				expectKept(rescan, 0);
			});

			it('drops the count of a transaction no longer observed', async function () {
				const lookup = answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();
				await checkAt(FIRST_MISS);

				// Gone from observation for a check.
				delete wallet.data.unconfirmedTransactions[TXID];
				lookup.resolves(lookupReply());
				await checkAt(FIRST_MISS + 1);

				observe(mempoolRecord(0));
				lookup.resolves(lookupReply(miss(NO_TXINDEX_MISS)));
				await checkAt(FIRST_MISS + 10);

				expectKept(rescan, 0);
			});

			it('starts counting again after a restart', async function () {
				answerWith(miss(NO_TXINDEX_MISS));
				stubRescan();
				await checkAt(FIRST_MISS, FIRST_MISS + 1);
				expect(misses(wallet).size, 'the miss is counted').to.equal(1);

				sinon.restore();
				await wallet.stop();
				expect(misses(wallet).size, 'stop() drops the count').to.equal(0);

				// The count is memory only, so a restart waits longer, never less.
				wallet = await openWallet();
				observe(mempoolRecord(0));
				answerWith(miss(NO_TXINDEX_MISS));
				const rescan = stubRescan();

				await checkAt(FIRST_MISS + 2, FIRST_MISS + 3);
				expectKept(rescan, 0);

				await checkAt(FIRST_MISS + 4);
				expectCleared(rescan);
			});

			it('still clears it at once when a server with a txindex misses it', async function () {
				answerWith(miss(TXINDEX_MISS));
				const rescan = stubRescan();

				await checkAt(FIRST_MISS);

				expectCleared(rescan);
			});
		});
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
		txAnswer(undefined, { code: 2, message: TXINDEX_MISS }, txid);

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

	it('repairs a mempool transaction a node without a txindex lost on the next check (issue #935)', async function () {
		// The miss has outlasted two blocks, so the count is spent. It may only
		// go once the repair lands: counted again from here, the retry would
		// wait two more blocks.
		await seed({ [TXID]: mempoolRecord() }, { [TXID]: mempoolRecord() });
		const tipAt = (height: number): void => {
			wallet.data.header = { height, hash: '', hex: '' };
		};
		answerWith(txAnswer(undefined, { code: 2, message: NO_TXINDEX_MISS }));
		const rescan = stubRescan();
		await wallet.checkUnconfirmedTransactions();

		tipAt(TIP + 2);
		failMainWrite.on = true;
		const failed = await wallet.checkUnconfirmedTransactions();
		expect(failed.isErr(), 'the check reports the write it lost').to.equal(
			true
		);
		expect(
			wallet.getUnconfirmedTransactions()[TXID]?.height,
			'the lost transaction is still observed'
		).to.equal(0);

		failMainWrite.on = false;
		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the repair was tried again').to.equal(true);

		expect(stored('transactions')[TXID].exists).to.equal(false);
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

	it('keeps a transaction a refresh adds while a check without ghosts runs (issue #944)', async function () {
		// The same race on the branch that finds no ghost: the check drops what
		// it found buried, and must not drop what it never looked up.
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
					data: txHashes.map((h) => txAnswer(6, undefined, h.tx_hash))
				});
			});

		const res = await wallet.checkUnconfirmedTransactions();
		expect(res.isOk(), 'the check ran').to.equal(true);

		expect(
			wallet.getUnconfirmedTransactions()[TXID],
			'the buried transaction leaves observation'
		).to.equal(undefined);
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

	it('keeps a transaction a refresh adds while the header path repairs a reorg (issue #944)', async function () {
		// Added while the check still awaits the repair, after its write lands
		// and before the map is replaced, so what is kept must be read after
		// that await.
		type TRepairInternals = TWalletInternals & {
			updateTransactionHeights: (txs: IUtxo[]) => Promise<Result<string>>;
		};
		const internals = wallet as unknown as TRepairInternals;
		const repair = internals.updateTransactionHeights.bind(wallet);
		sinon
			.stub(internals, 'updateTransactionHeights')
			.callsFake(async (txs: IUtxo[]) => {
				const res = await repair(txs);
				await internals.addUnconfirmedTransactions({
					transactions: { [OTHER_TXID]: confirmedRecord(TIP, OTHER_TXID) }
				});
				return res;
			});
		answerWith(txAnswer(0));

		const res = await wallet.checkUnconfirmedTransactions(true);
		expect(res.isOk(), 'the check ran').to.equal(true);

		expect(sent('reorg'), 'the reorg is reported once').to.have.length(1);
		expect(stored('transactions')[TXID].height).to.equal(0);
		expect(stored('unconfirmedTransactions')[TXID].height).to.equal(0);
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
