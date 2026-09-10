/**
 * Issue #775: a spend of the funding output mined between the funding's first
 * confirmation and its `minimumDepth` used to go unreported until the depth
 * arrived, because the watch only started scanning for spends then. The
 * confirmation scan now scans for the spend from the first sighting, on the
 * history it already holds, against the candidate it actually saw.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

bitcoin.initEccLib(ecc);

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

class MockBackend implements IChainBackend {
	private headerCbs: Array<(height: number) => void> = [];
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private txs = new Map<string, Buffer>();
	historyFetches = 0;

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
		this.historyFetches++;
		return this.history.get(sh) ?? [];
	}
	async getTransaction(txid: string): Promise<Buffer> {
		const t = this.txs.get(txid);
		if (!t) throw new Error(`no tx ${txid}`);
		return t;
	}
	async broadcastTransaction(hex: string): Promise<string> {
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

const tick = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** A transaction spending `txid:vout` (display-order txid). */
function spendOf(txid: string, vout: number): bitcoin.Transaction {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
	tx.addOutput(Buffer.from('0014' + '11'.repeat(20), 'hex'), 1_000);
	return tx;
}

interface IReport {
	txid: string;
	height: number;
	outpoint: { txid: string; outputIndex: number } | undefined;
}

describe('Issue #775: funding spend detection below minimumDepth', function () {
	this.timeout(10_000);
	const channelId = Buffer.alloc(32, 7);
	const script = Buffer.from('0020' + '55'.repeat(32), 'hex');
	const scriptHash = computeScriptHash(script);
	let backend: MockBackend;
	let watcher: ChainWatcher;
	let reported: IReport[];
	let absent: number;
	let seen: string[];
	let unseen: string[];
	let confirmed: string[];

	beforeEach(async () => {
		backend = new MockBackend();
		const cm = new ChannelManager({
			localBasepoints: makeBasepoints(crypto.randomBytes(32)),
			localPerCommitmentSeed: crypto.randomBytes(32),
			localFundingPrivkey: crypto.randomBytes(32)
		});
		cm.on('error', () => {});
		reported = [];
		absent = 0;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(cm as any).handleFundingSpent = (
			_id: Buffer,
			tx: bitcoin.Transaction,
			height: number,
			_dest: Buffer,
			_fee: number,
			_a: unknown,
			_b: unknown,
			_c: unknown,
			outpoint?: { txid: string; outputIndex: number }
		): unknown[] => {
			reported.push({ txid: tx.getId(), height, outpoint });
			return [];
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(cm as any).handleFundingSpendAbsent = (): boolean => {
			absent++;
			return false;
		};
		watcher = new ChainWatcher({
			backend,
			channelManager: cm,
			missingDebounceMs: 0
		});
		watcher.on('error', () => {});
		seen = [];
		unseen = [];
		confirmed = [];
		watcher.on('funding:seen', (_id: Buffer, txid: string) => seen.push(txid));
		watcher.on('funding:unseen', (_id: Buffer, txid: string) =>
			unseen.push(txid)
		);
		watcher.on('funding:confirmed', (_id: Buffer, txid: string) =>
			confirmed.push(txid)
		);
		await watcher.start();
	});

	afterEach(() => watcher.stop());

	it('reports a spend mined one block after the funding, before minimumDepth', async () => {
		const funding = crypto.randomBytes(32).toString('hex');
		backend.setHistory(scriptHash, [{ txid: funding, height: 100 }]);
		backend.block(100);
		await watcher.watchFundingOutput(channelId, funding, 0, 3, script);
		await tick();
		expect(seen).to.deep.equal([funding]);
		expect(confirmed).to.deep.equal([]);
		expect(reported).to.deep.equal([]);

		const close = spendOf(funding, 0);
		backend.setTx(close);
		backend.setHistory(scriptHash, [
			{ txid: funding, height: 100 },
			{ txid: close.getId(), height: 101 }
		]);
		backend.block(101);
		await tick();
		const expected: IReport = {
			txid: close.getId(),
			height: 101,
			outpoint: { txid: funding, outputIndex: 0 }
		};
		expect(reported, 'reported two blocks short of the depth').to.deep.equal([
			expected
		]);
		expect(confirmed).to.deep.equal([]);

		// The depth block adds the ordinary per-block re-report of the same
		// spend, which the monitor drops as a duplicate, and nothing else;
		// and it fetches the history once, the spend scan reusing it.
		const fetches = backend.historyFetches;
		backend.block(102);
		await tick();
		expect(confirmed).to.deep.equal([funding]);
		for (const r of reported) expect(r).to.deep.equal(expected);
		expect(
			backend.historyFetches - fetches,
			'one round trip for both verdicts'
		).to.equal(1);
	});

	it('stops scanning while a sighting is retracted to the mempool', async () => {
		const funding = crypto.randomBytes(32).toString('hex');
		backend.setHistory(scriptHash, [{ txid: funding, height: 100 }]);
		backend.block(100);
		await watcher.watchFundingOutput(channelId, funding, 0, 3, script);
		await tick();
		expect(absent, 'the first sighting scanned and found no spender').to.equal(
			1
		);

		backend.setHistory(scriptHash, [{ txid: funding, height: 0 }]);
		watcher.recheckAllWatches();
		await tick();
		expect(unseen).to.deep.equal([funding]);
		expect(absent, 'no scan behind a retracted sighting').to.equal(1);
		const close = spendOf(funding, 0);
		backend.setTx(close);
		backend.setHistory(scriptHash, [
			{ txid: funding, height: 0 },
			{ txid: close.getId(), height: 0 }
		]);
		watcher.recheckAllWatches();
		await tick();
		expect(reported).to.deep.equal([]);
		expect(absent).to.equal(1);

		// Mined again, with the close behind it: the scan resumes.
		backend.setHistory(scriptHash, [
			{ txid: funding, height: 101 },
			{ txid: close.getId(), height: 101 }
		]);
		backend.block(101);
		await tick();
		expect(reported).to.deep.equal([
			{
				txid: close.getId(),
				height: 101,
				outpoint: { txid: funding, outputIndex: 0 }
			}
		]);
	});

	it('scans the candidate the chain has, not the attempt the watch names', async () => {
		const newTxid = crypto.randomBytes(32).toString('hex');
		const oldTxid = crypto.randomBytes(32).toString('hex');
		const close = spendOf(oldTxid, 1);
		backend.setTx(close);
		backend.setHistory(scriptHash, [
			{ txid: oldTxid, height: 100 },
			{ txid: close.getId(), height: 101 }
		]);
		backend.block(101);
		await watcher.watchFundingOutput(
			channelId,
			newTxid,
			0,
			3,
			script,
			undefined,
			[
				{ txid: newTxid, outputIndex: 0 },
				{ txid: oldTxid, outputIndex: 1 }
			]
		);
		await tick();
		expect(seen).to.deep.equal([oldTxid]);
		expect(reported).to.deep.equal([
			{
				txid: close.getId(),
				height: 101,
				outpoint: { txid: oldTxid, outputIndex: 1 }
			}
		]);
		expect(confirmed).to.deep.equal([]);

		backend.block(102);
		await tick();
		expect(confirmed).to.deep.equal([oldTxid]);
		expect(
			reported.every(
				(r) => r.outpoint?.txid === oldTxid && r.outpoint.outputIndex === 1
			),
			'no report names another outpoint'
		).to.equal(true);
	});

	it('leaves a pre-splice leg reporting a breach of its own outpoint', async () => {
		const oldFunding = crypto.randomBytes(32).toString('hex');
		const spliceTxid = crypto.randomBytes(32).toString('hex');
		const oldScript = Buffer.from('0020' + '66'.repeat(32), 'hex');
		const breach = spendOf(oldFunding, 0);
		backend.setTx(breach);
		backend.setHistory(scriptHash, [{ txid: spliceTxid, height: 100 }]);
		backend.setHistory(computeScriptHash(oldScript), [
			{ txid: oldFunding, height: 90 },
			{ txid: spliceTxid, height: 100 },
			{ txid: breach.getId(), height: 101 }
		]);
		backend.block(101);
		// The channel's watch moved to the splice, seen below its depth; the
		// leg guards the old outpoint and vouches for the splice.
		await watcher.watchFundingOutput(channelId, spliceTxid, 0, 3, script);
		await watcher.watchFundingSpendDuringSplice(
			channelId,
			oldFunding,
			0,
			oldScript,
			spliceTxid
		);
		await tick();
		expect(reported).to.deep.equal([
			{
				txid: breach.getId(),
				height: 101,
				outpoint: { txid: oldFunding, outputIndex: 0 }
			}
		]);
	});
});
