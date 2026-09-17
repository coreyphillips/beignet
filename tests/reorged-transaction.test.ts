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
	IFormattedTransaction,
	IGetTransactions,
	ITransaction,
	IUtxo,
	IWalletData,
	ok,
	TMessageDataMap,
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
const confirmedRecord = (height: number): IFormattedTransaction => ({
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
	txid: TXID,
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
	error?: { code: number; message: string }
): ITransaction<IUtxo> =>
	({
		id: 0,
		jsonrpc: '2.0',
		param: TXID,
		data: { tx_hash: TXID },
		...(error ? { error } : {}),
		result: error
			? undefined
			: {
					...(confirmations !== undefined ? { confirmations } : {}),
					...(confirmations ? { blockhash: BLOCK_HASH } : {}),
					hash: TXID,
					hex: '00',
					locktime: 0,
					size: 141,
					txid: TXID,
					version: 2,
					vin: [],
					vout: [],
					vsize: 141,
					weight: 561
			  }
	}) as unknown as ITransaction<IUtxo>;

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
		expect(stored.confirmTimestamp).to.equal(0);
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
		expect(
			messages.filter((m) => m.key === 'rbf'),
			'the removal is reported once'
		).to.have.length(1);
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
});
