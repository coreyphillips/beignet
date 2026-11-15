/**
 * Issue #2045: BOLT 2 says a fundee MUST wait for at least 100 blocks before
 * channel_ready when the funding transaction is a coinbase. The watcher used
 * to report a coinbase funding at minimum_depth like any other, so a miner
 * could open a channel whose commitments cannot confirm for 100 blocks and
 * have it carry HTLCs from block 3.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChainWatcher,
	IChainBackend,
	IChainWatcherChannelManager,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import type { Channel } from '../../src/lightning/channel/channel';

class MockBackend implements IChainBackend {
	private headerCbs: Array<(height: number) => void> = [];
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private txs = new Map<string, Buffer>();
	transactionReads = 0;
	transactionFailures = 0;

	setHistory(sh: string, h: Array<{ txid: string; height: number }>): void {
		this.history.set(sh, h);
	}
	setTx(tx: bitcoin.Transaction): void {
		this.txs.set(tx.getId(), tx.toBuffer());
	}
	block(height: number): void {
		for (const cb of [...this.headerCbs]) cb(height);
	}
	async subscribeToHeaders(cb: (height: number) => void): Promise<void> {
		this.headerCbs.push(cb);
	}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(
		sh: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this.history.get(sh) ?? [];
	}
	async getTransaction(txid: string): Promise<Buffer> {
		this.transactionReads++;
		if (this.transactionFailures > 0) {
			this.transactionFailures--;
			throw new Error('server unavailable');
		}
		const tx = this.txs.get(txid);
		if (!tx) throw new Error(`no tx ${txid}`);
		return tx;
	}
	async broadcastTransaction(hex: string): Promise<string> {
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

const tick = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** A coinbase paying `script`, as a block template for `height` would. */
function coinbasePaying(script: Buffer, height: number): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	// BIP 34 height push, which also makes each coinbase unique.
	const push = Buffer.alloc(4);
	push.writeUInt32LE(height);
	tx.addInput(
		Buffer.alloc(32),
		0xffffffff,
		0xffffffff,
		Buffer.concat([Buffer.from([3]), push.subarray(0, 3)])
	);
	tx.addOutput(script, 1_000_000);
	return tx;
}

/** An ordinary transaction paying `script`. */
function fundingPaying(script: Buffer): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(script, 1_000_000);
	return tx;
}

describe('Issue #2045: coinbase funding waits 100 blocks', function () {
	this.timeout(10_000);
	const channelId = Buffer.alloc(32, 7);
	const script = Buffer.from('0020' + '55'.repeat(32), 'hex');
	const scriptHash = computeScriptHash(script);
	let backend: MockBackend;
	let watcher: ChainWatcher;
	let confirmed: string[];
	let errors: Error[];
	let record: { fundingTxHex?: string };

	beforeEach(async () => {
		backend = new MockBackend();
		confirmed = [];
		errors = [];
		// A v1 fundee's record: the channel knows the txid only.
		record = {};
		const channel = {
			getFullState: () => ({
				channelId,
				temporaryChannelId: Buffer.alloc(32, 1),
				...record
			})
		} as unknown as Channel;
		const manager: IChainWatcherChannelManager = {
			on: () => {},
			off: () => {},
			listChannels: () => [channel],
			handleNewBlock: () => {},
			handleFundingConfirmed: (_id: Buffer, txid?: string) => {
				confirmed.push(txid as string);
			},
			handleFundingSpent: () => {},
			handleFundingSpendAbsent: () => false,
			handleOutputSpent: () => {},
			handleOutputUnspent: () => {}
		};
		watcher = new ChainWatcher({
			backend,
			channelManager: manager,
			missingDebounceMs: 0
		});
		watcher.on('error', (err: Error) => errors.push(err));
		await watcher.start();
	});

	afterEach(() => watcher.stop());

	/** Announce a new tip and let the scans it starts settle. */
	async function tipAt(height: number): Promise<void> {
		backend.block(height);
		await tick();
	}

	it('holds channel_ready for a coinbase funding until 100 confirmations', async () => {
		const funding = coinbasePaying(script, 200);
		backend.setTx(funding);
		backend.setHistory(scriptHash, [{ txid: funding.getId(), height: 200 }]);
		await tipAt(200);
		await watcher.watchFundingOutput(channelId, funding.getId(), 0, 3, script);
		await tick();

		for (const tip of [202, 203, 250, 298]) {
			await tipAt(tip);
			expect(confirmed, `${tip - 200 + 1} confirmations`).to.deep.equal([]);
		}
		await tipAt(299);
		expect(confirmed, '100 confirmations').to.deep.equal([funding.getId()]);
		// One answer per transaction: the lookup is not repeated every block.
		expect(backend.transactionReads).to.equal(1);
		expect(errors).to.deep.equal([]);
	});

	it('still confirms an ordinary funding at minimum_depth', async () => {
		const funding = fundingPaying(script);
		backend.setTx(funding);
		backend.setHistory(scriptHash, [{ txid: funding.getId(), height: 200 }]);
		await tipAt(201);
		await watcher.watchFundingOutput(channelId, funding.getId(), 0, 3, script);
		await tick();
		expect(confirmed).to.deep.equal([]);

		await tipAt(202);
		expect(confirmed).to.deep.equal([funding.getId()]);
		expect(errors).to.deep.equal([]);
	});

	it('reads the funding from the channel record when it holds one', async () => {
		const funding = fundingPaying(script);
		record.fundingTxHex = funding.toHex();
		backend.setHistory(scriptHash, [{ txid: funding.getId(), height: 200 }]);
		await tipAt(202);
		await watcher.watchFundingOutput(channelId, funding.getId(), 0, 3, script);
		await tick();
		expect(confirmed).to.deep.equal([funding.getId()]);
		expect(backend.transactionReads, 'no backend round trip').to.equal(0);
	});

	it('holds a minimum_depth 0 watch on a coinbase funding too', async () => {
		const funding = coinbasePaying(script, 300);
		backend.setTx(funding);
		backend.setHistory(scriptHash, [{ txid: funding.getId(), height: 300 }]);
		await tipAt(300);
		await watcher.watchFundingOutput(channelId, funding.getId(), 0, 0, script);
		await tick();
		await tipAt(301);
		expect(confirmed).to.deep.equal([]);

		await tipAt(399);
		expect(confirmed).to.deep.equal([funding.getId()]);
	});

	it('waits when the backend cannot answer, and asks again', async () => {
		const funding = fundingPaying(script);
		backend.setTx(funding);
		backend.transactionFailures = 1;
		backend.setHistory(scriptHash, [{ txid: funding.getId(), height: 200 }]);
		await tipAt(202);
		await watcher.watchFundingOutput(channelId, funding.getId(), 0, 3, script);
		await tick();
		expect(confirmed).to.deep.equal([]);
		expect(errors.map((e) => e.message)).to.have.lengthOf(1);
		expect(errors[0].message).to.match(/coinbase/);

		await tipAt(203);
		expect(confirmed).to.deep.equal([funding.getId()]);
	});

	it('refuses a backend answer that is not the asked-for transaction', async () => {
		const funding = fundingPaying(script);
		const other = fundingPaying(script);
		backend.setTx(other);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(backend as any).txs.set(funding.getId(), other.toBuffer());
		backend.setHistory(scriptHash, [{ txid: funding.getId(), height: 200 }]);
		await tipAt(202);
		await watcher.watchFundingOutput(channelId, funding.getId(), 0, 3, script);
		await tick();
		expect(confirmed).to.deep.equal([]);
		expect(errors[0]?.message).to.match(/answered/);
	});
});
