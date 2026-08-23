/**
 * Phase 4: Chain Watcher tests.
 *
 * Verifies the ChainWatcher bridge between IChainBackend and ChannelManager:
 * - computeScriptHash utility
 * - Funding confirmation detection
 * - Block height advancement
 * - Transaction broadcast
 * - Output spend detection
 * - ChannelManager event wiring
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
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

bitcoin.initEccLib(ecc);

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		const priv = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(getPublicKey(priv));
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

/** Mock chain backend for testing */
class MockChainBackend implements IChainBackend {
	private headerCallbacks: Array<(height: number) => void> = [];
	private scriptHashCallbacks: Map<string, Array<() => void>> = new Map();
	private scriptHashHistory: Map<
		string,
		Array<{ txid: string; height: number }>
	> = new Map();
	private transactions: Map<string, Buffer> = new Map();
	private broadcastedTxs: string[] = [];

	// Control methods
	simulateNewBlock(height: number): void {
		for (const cb of this.headerCallbacks) {
			cb(height);
		}
	}

	simulateScriptHashChange(scriptHash: string): void {
		const callbacks = this.scriptHashCallbacks.get(scriptHash);
		if (callbacks) {
			for (const cb of callbacks) {
				cb();
			}
		}
	}

	setHistory(
		scriptHash: string,
		history: Array<{ txid: string; height: number }>
	): void {
		this.scriptHashHistory.set(scriptHash, history);
	}

	setTransaction(txid: string, rawTx: Buffer): void {
		this.transactions.set(txid, rawTx);
	}

	getBroadcastedTxs(): string[] {
		return this.broadcastedTxs;
	}

	// IChainBackend implementation
	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		this.headerCallbacks.push(onNewBlock);
	}

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		const existing = this.scriptHashCallbacks.get(scriptHash) || [];
		existing.push(onChange);
		this.scriptHashCallbacks.set(scriptHash, existing);
	}

	private historyHolds = 0;
	private historyGate: Promise<void> | null = null;
	private releaseGate: (() => void) | null = null;

	/** Park the next `count` history fetches until releaseHistory(). */
	holdHistory(count = 1): void {
		this.historyHolds = count;
		this.historyGate = new Promise((resolve) => {
			this.releaseGate = resolve;
		});
	}

	releaseHistory(): void {
		this.historyHolds = 0;
		this.releaseGate?.();
		this.historyGate = null;
		this.releaseGate = null;
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		// The snapshot is taken BEFORE parking, so a held call answers with
		// the history as it was when it started, which is what a stalled scan
		// really holds.
		const snapshot = this.scriptHashHistory.get(scriptHash) || [];
		if (this.historyHolds > 0) {
			this.historyHolds--;
			await this.historyGate;
		}
		return snapshot;
	}

	async getTransaction(txid: string): Promise<Buffer> {
		const tx = this.transactions.get(txid);
		if (!tx) throw new Error(`Transaction not found: ${txid}`);
		return tx;
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcastedTxs.push(rawTxHex);
		// Compute txid from the raw transaction
		const txBuf = Buffer.from(rawTxHex, 'hex');
		const hash = crypto
			.createHash('sha256')
			.update(crypto.createHash('sha256').update(txBuf).digest())
			.digest();
		return Buffer.from(hash).reverse().toString('hex');
	}
}

describe('Phase 4: Chain Watcher', () => {
	describe('computeScriptHash', () => {
		it('should compute Electrum-style script hash', () => {
			// Known test vector: P2PKH script for a known address
			const scriptPubkey = Buffer.from(
				'76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac',
				'hex'
			);
			const hash = computeScriptHash(scriptPubkey);
			expect(hash).to.be.a('string');
			expect(hash).to.have.lengthOf(64); // 32 bytes hex
		});

		it('should produce different hashes for different scripts', () => {
			const script1 = Buffer.from('0014' + '00'.repeat(20), 'hex');
			const script2 = Buffer.from('0014' + 'ff'.repeat(20), 'hex');
			expect(computeScriptHash(script1)).to.not.equal(
				computeScriptHash(script2)
			);
		});

		it('should reverse the SHA256 hash bytes', () => {
			const scriptPubkey = Buffer.from('0014aabbccdd', 'hex');
			const sha256 = crypto.createHash('sha256').update(scriptPubkey).digest();
			const expected = Buffer.from(sha256).reverse().toString('hex');
			expect(computeScriptHash(scriptPubkey)).to.equal(expected);
		});
	});

	describe('ChainWatcher lifecycle', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(() => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			// Absorb ChannelManager errors
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should start and subscribe to block headers', async () => {
			await watcher.start();
			expect(watcher.getCurrentBlockHeight()).to.equal(0);

			backend.simulateNewBlock(100);
			expect(watcher.getCurrentBlockHeight()).to.equal(100);
		});

		it('should not start twice', async () => {
			await watcher.start();
			await watcher.start(); // should be no-op
		});

		it('should emit block events on new blocks', async () => {
			await watcher.start();
			const heights: number[] = [];
			watcher.on('block', (h) => heights.push(h));

			backend.simulateNewBlock(100);
			backend.simulateNewBlock(101);

			expect(heights).to.deep.equal([100, 101]);
		});

		it('should track current block height', async () => {
			await watcher.start();

			backend.simulateNewBlock(500);
			expect(watcher.getCurrentBlockHeight()).to.equal(500);

			backend.simulateNewBlock(501);
			expect(watcher.getCurrentBlockHeight()).to.equal(501);
		});
	});

	describe('Funding confirmation detection', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should detect funding confirmation at minimum depth', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 3, scriptPubkey);

			// Set current block height
			backend.simulateNewBlock(100);

			// Simulate the funding tx appearing in history at height 98
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);

			// Trigger the script hash callback
			let confirmed = false;
			watcher.on('funding:confirmed', (cid: Buffer) => {
				if (cid.equals(channelId)) confirmed = true;
			});

			backend.simulateScriptHashChange(scriptHash);

			// Wait for async callback to complete
			await new Promise((resolve) => setTimeout(resolve, 50));

			// 100 - 98 + 1 = 3 confirmations = minimumDepth
			expect(confirmed).to.be.true;
		});

		it('adopts whichever RBF candidate confirms (issue 360)', async () => {
			const channelId = crypto.randomBytes(32);
			const newTxid = crypto.randomBytes(32).toString('hex');
			const oldTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(
				channelId,
				newTxid,
				0,
				3,
				scriptPubkey,
				undefined,
				[
					{ txid: newTxid, outputIndex: 0 },
					{ txid: oldTxid, outputIndex: 1 }
				]
			);
			backend.simulateNewBlock(100);
			// The SUPERSEDED attempt mined; the current one vanished (its
			// replacement double-spent it out of the mempool).
			backend.setHistory(scriptHash, [{ txid: oldTxid, height: 98 }]);

			const confirmedTxids: string[] = [];
			let missing = false;
			watcher.on('funding:confirmed', (_cid: Buffer, txid: string) => {
				confirmedTxids.push(txid);
			});
			watcher.on('funding:missing', () => {
				missing = true;
			});
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(confirmedTxids, 'the mined candidate is adopted').to.deep.equal([
				oldTxid
			]);
			expect(missing, 'a live candidate is never "missing"').to.equal(false);
		});

		it('a transient subscription failure keeps the candidate set across the retry (issue 360 review)', async () => {
			const channelId = crypto.randomBytes(32);
			const newTxid = crypto.randomBytes(32).toString('hex');
			const oldTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			// The first subscription attempt fails; the per-block retry
			// succeeds and MUST re-arm the full candidate set.
			const realSubscribe = backend.subscribeToScriptHash.bind(backend);
			let failures = 1;
			backend.subscribeToScriptHash = async (
				sh: string,
				cb: () => void
			): Promise<void> => {
				if (failures > 0) {
					failures--;
					throw new Error('transient subscription failure');
				}
				return realSubscribe(sh, cb);
			};

			await watcher.watchFundingOutput(
				channelId,
				newTxid,
				0,
				3,
				scriptPubkey,
				undefined,
				[
					{ txid: newTxid, outputIndex: 0 },
					{ txid: oldTxid, outputIndex: 1 }
				]
			);

			const confirmedTxids: string[] = [];
			let missing = false;
			watcher.on('funding:confirmed', (_cid: Buffer, txid: string) => {
				confirmedTxids.push(txid);
			});
			watcher.on('funding:missing', () => {
				missing = true;
			});
			// Only the OLD candidate is on chain; the retried watch must still
			// know about it.
			backend.setHistory(scriptHash, [{ txid: oldTxid, height: 98 }]);
			backend.simulateNewBlock(100);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				confirmedTxids,
				'the retried watch still tracks the superseded candidate'
			).to.deep.equal([oldTxid]);
			expect(missing).to.equal(false);
		});

		it('a stale failed-watch retry never overwrites a newer RBF watch (issue 376)', async () => {
			const channelId = crypto.randomBytes(32);
			const firstTxid = crypto.randomBytes(32).toString('hex');
			const replacementTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			// The FIRST registration's subscription fails and is queued for
			// retry. An RBF then re-registers the same channel with the
			// replacement as the current attempt, and that one succeeds.
			const realSubscribe = backend.subscribeToScriptHash.bind(backend);
			let failures = 1;
			backend.subscribeToScriptHash = async (
				sh: string,
				cb: () => void
			): Promise<void> => {
				if (failures > 0) {
					failures--;
					throw new Error('transient subscription failure');
				}
				return realSubscribe(sh, cb);
			};

			await watcher.watchFundingOutput(
				channelId,
				firstTxid,
				0,
				3,
				scriptPubkey,
				undefined,
				[{ txid: firstTxid, outputIndex: 0 }]
			);
			await watcher.watchFundingOutput(
				channelId,
				replacementTxid,
				0,
				3,
				scriptPubkey,
				undefined,
				[
					{ txid: replacementTxid, outputIndex: 0 },
					{ txid: firstTxid, outputIndex: 0 }
				]
			);

			const confirmedTxids: string[] = [];
			watcher.on('funding:confirmed', (_cid: Buffer, txid: string) => {
				confirmedTxids.push(txid);
			});

			// Both drain paths run: the per-block retry and the safety-net
			// re-check. Replaying the queued failure would put the first
			// registration (which does not know the replacement) back in the
			// map, and the attempt that actually confirms would be lost.
			backend.simulateNewBlock(100);
			await new Promise((resolve) => setTimeout(resolve, 30));
			backend.setHistory(scriptHash, [{ txid: replacementTxid, height: 98 }]);
			watcher.recheckAllWatches();
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				confirmedTxids,
				'the newer watch survived the stale retry'
			).to.deep.equal([replacementTxid]);
		});

		it('should not confirm before minimum depth', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 6, scriptPubkey);

			backend.simulateNewBlock(100);
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);

			let confirmed = false;
			watcher.on('funding:confirmed', () => {
				confirmed = true;
			});

			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			// 100 - 98 + 1 = 3, but minimumDepth = 6
			expect(confirmed).to.be.false;
		});

		it('should confirm when more blocks arrive', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 3, scriptPubkey);

			backend.simulateNewBlock(99);
			backend.setHistory(scriptHash, [{ txid, height: 99 }]);

			let confirmed = false;
			watcher.on('funding:confirmed', () => {
				confirmed = true;
			});

			// At height 99, confirmations = 1, need 3
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(confirmed).to.be.false;

			// At height 101, confirmations = 3
			backend.simulateNewBlock(101);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(confirmed).to.be.true;
		});

		it('recheckAllWatches() detects a confirmation missed while disconnected', async () => {
			// Reproduces the real bug: the funding confirmed on-chain but no
			// new-block / script-hash event was delivered (subscriptions failed to
			// establish during an Electrum outage), so the channel stayed stuck.
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 3, scriptPubkey);
			backend.simulateNewBlock(100); // sets current height; history still empty

			let confirmed = false;
			watcher.on('funding:confirmed', (cid: Buffer) => {
				if (cid.equals(channelId)) confirmed = true;
			});

			// Funding is now 3-deep on-chain, but NO event delivers it.
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);
			await new Promise((resolve) => setTimeout(resolve, 30));
			expect(confirmed, 'no event delivered → still unconfirmed').to.be.false;

			// The safety-net re-check (also fired on reconnect) picks it up.
			watcher.recheckAllWatches();
			await new Promise((resolve) => setTimeout(resolve, 30));
			expect(confirmed, 'recheckAllWatches detected the missed confirmation').to
				.be.true;
		});

		it('should not confirm unconfirmed transactions (height=0)', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchFundingOutput(channelId, txid, 0, 1, scriptPubkey);
			backend.simulateNewBlock(100);

			// height=0 means unconfirmed
			backend.setHistory(scriptHash, [{ txid, height: 0 }]);

			let confirmed = false;
			watcher.on('funding:confirmed', () => {
				confirmed = true;
			});

			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(confirmed).to.be.false;
		});
	});

	describe('Overlapping confirmation scans (issue #463)', () => {
		/**
		 * Checks for one watch can overlap: a subscription callback, a block
		 * and the recheck timer all start them, and each holds a history it
		 * fetched before its awaits. A scan that stalls while another finishes
		 * must retire, not apply its stale answer over the newer one.
		 */
		it('a stalled scan never overwrites a newer confirmation', async () => {
			const backend = new MockChainBackend();
			const channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(crypto.randomBytes(32)),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});
			const watcher = new ChainWatcher({ backend, channelManager });
			watcher.on('error', () => {});

			const channelId = crypto.randomBytes(32);
			const script = bitcoin.payments.p2wsh({
				redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
			}).output!;
			const scriptHash = computeScriptHash(script);
			const stale = 'aa'.repeat(32);
			const winner = 'bb'.repeat(32);

			await watcher.start();
			backend.simulateNewBlock(200);
			// The stalled scan's view: only the stale attempt, confirmed.
			backend.setHistory(scriptHash, [{ txid: stale, height: 100 }]);
			backend.holdHistory(1);
			const arming = watcher.watchFundingOutput(
				channelId,
				stale,
				0,
				1,
				script,
				undefined,
				[
					{ txid: stale, outputIndex: 0 },
					{ txid: winner, outputIndex: 1 }
				]
			);
			await new Promise((r) => setTimeout(r, 20));

			// The chain moves on and a second check completes against the newer
			// history while the first is still parked mid-fetch.
			backend.setHistory(scriptHash, [{ txid: winner, height: 150 }]);
			await watcher.recheckAllWatches();
			await new Promise((r) => setTimeout(r, 20));

			// Only now does the stalled scan resume, holding its stale view.
			backend.releaseHistory();
			await arming;
			await new Promise((r) => setTimeout(r, 20));

			const held = (
				watcher as unknown as {
					watchedFundings: Map<
						string,
						{ txid: string; confirmed: boolean; missingChecks?: number }
					>;
				}
			).watchedFundings.get(channelId.toString('hex'))!;
			expect(held.confirmed, 'the newer scan confirmed').to.equal(true);
			expect(held.txid, 'and the stalled one did not revert it').to.equal(
				winner
			);
			// The stalled scan held a history the confirmation is not in, so
			// on resuming it read the funding as ABSENT and counted that
			// against a watch that had just confirmed. Three of those emit
			// funding:missing for a funding that is on chain, which starts
			// BOLT 2's forget clock against it.
			expect(
				held.missingChecks ?? 0,
				'and did not count an absence against it either'
			).to.equal(0);
			watcher.stop();
		});
	});

	describe('Funding spend absence notification (issue 352)', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;
		let absentCalls: Buffer[];

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});
			absentCalls = [];
			const original =
				channelManager.handleFundingSpendAbsent.bind(channelManager);
			(channelManager as any).handleFundingSpendAbsent = (
				channelId: Buffer
			): void => {
				absentCalls.push(channelId);
				original(channelId);
			};

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		async function armConfirmedFundingWatch(): Promise<{
			channelId: Buffer;
			txid: string;
			scriptHash: string;
		}> {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);
			await watcher.watchFundingOutput(channelId, txid, 0, 1, scriptPubkey);
			backend.simulateNewBlock(100);
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);
			// Confirms the funding, which arms spend detection and runs its
			// immediate spend check against the spender-less history.
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));
			return { channelId, txid, scriptHash };
		}

		it('notifies when a fetched history contains no funding spender', async () => {
			const { channelId } = await armConfirmedFundingWatch();
			expect(absentCalls.some((cid) => cid.equals(channelId))).to.be.true;
		});

		it('does not notify while a spender is present in the history', async () => {
			const { channelId, txid, scriptHash } = await armConfirmedFundingWatch();
			absentCalls = [];

			// A tx spending the funding outpoint appears: the spend path reports
			// it and the absence path must stay silent.
			const spendTx = new bitcoin.Transaction();
			spendTx.version = 2;
			spendTx.addInput(Buffer.from(txid, 'hex').reverse(), 0, 0xffffffff);
			spendTx.addOutput(Buffer.from('0014' + '11'.repeat(20), 'hex'), 50_000);
			backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid, height: 98 },
				{ txid: spendTx.getId(), height: 99 }
			]);
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(absentCalls.some((cid) => cid.equals(channelId))).to.be.false;
		});
	});

	describe('Transaction broadcast', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should broadcast transactions via the backend', async () => {
			const rawTx = crypto.randomBytes(200);
			const txid = await watcher.broadcastTransaction(rawTx);

			expect(txid).to.be.a('string');
			expect(txid).to.have.lengthOf(64);
			expect(backend.getBroadcastedTxs()).to.have.lengthOf(1);
			expect(backend.getBroadcastedTxs()[0]).to.equal(rawTx.toString('hex'));
		});

		it('should emit broadcast:success event', async () => {
			const rawTx = crypto.randomBytes(200);
			let emittedTxid: string | null = null;
			watcher.on('broadcast:success', (t: string) => {
				emittedTxid = t;
			});

			await watcher.broadcastTransaction(rawTx);
			expect(emittedTxid).to.not.be.null;
		});

		it('should forward ChannelManager broadcast:tx events', async () => {
			const rawTx = crypto.randomBytes(200);
			// Channel manager emits broadcast:tx
			channelManager.emit('broadcast:tx', rawTx);

			// Wait for the async broadcast
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(backend.getBroadcastedTxs()).to.have.lengthOf(1);
		});
	});

	describe('ChannelManager event wiring', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should emit error when watch:funding fires with no matching channel', () => {
			let errorEmitted = false;
			watcher.on('error', () => {
				errorEmitted = true;
			});

			const txid = crypto.randomBytes(32);
			channelManager.emit('watch:funding', txid, 0, 3);

			expect(errorEmitted).to.be.true;
		});

		it('should emit watch:output:requested when ChannelManager emits watch:output', () => {
			let requested = false;
			watcher.on('watch:output:requested', () => {
				requested = true;
			});

			channelManager.emit('watch:output', 'abc123', 1);

			expect(requested).to.be.true;
		});
	});

	describe('Output spend detection', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('should detect when a watched output is spent', async () => {
			const watchedTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			await watcher.watchOutput(watchedTxid, 0, scriptPubkey);

			// Create a spending transaction
			const spendTx = new bitcoin.Transaction();
			spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
			spendTx.addOutput(scriptPubkey, 50000);
			const spendTxid = spendTx.getId();
			const spendRawTx = spendTx.toBuffer();

			backend.setHistory(scriptHash, [
				{ txid: watchedTxid, height: 100 }, // original tx
				{ txid: spendTxid, height: 101 } // spending tx
			]);
			backend.setTransaction(spendTxid, spendRawTx);

			let spentEmitted = false;
			watcher.on('output:spent', () => {
				spentEmitted = true;
			});

			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(spentEmitted).to.be.true;
		});
	});

	describe('LightningNode integration', () => {
		it('should accept chainBackend in INodeConfig', () => {
			const {
				LightningNode
			} = require('../../src/lightning/node/lightning-node');

			const seed = crypto.randomBytes(32);
			const basepoints = makeBasepoints(seed);
			const mockBackend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => ''
			};

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32),
				chainBackend: mockBackend
			});

			expect(node.getChainWatcher()).to.not.be.null;
			node.destroy();
		});

		it('restoreChainWatches watches the funding of a FORCE_CLOSED channel with no monitor', async () => {
			const {
				LightningNode
			} = require('../../src/lightning/node/lightning-node');
			const {
				createOpenerState
			} = require('../../src/lightning/channel/channel-state');
			const { Channel } = require('../../src/lightning/channel/channel');
			const {
				ChannelState,
				DEFAULT_CHANNEL_CONFIG
			} = require('../../src/lightning/channel/types');

			const seed = crypto.randomBytes(32);
			const basepoints = makeBasepoints(seed);
			const mockBackend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => ''
			};
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32),
				chainBackend: mockBackend
			});

			// A channel force-closed in a previous session whose monitor was never
			// persisted: it must still get a funding watch (the spend detection
			// lazily creates the monitor and schedules the sweeps). Skipping it
			// orphans the CSV-locked funds.
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.state = ChannelState.FORCE_CLOSED;
			state.channelId = crypto.randomBytes(32);
			state.fundingTxid = crypto.randomBytes(32);
			state.fundingOutputIndex = 0;
			state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
			const channel = new Channel(state);
			node.getChannelManager().restoreChannel(channel, 'cafe'.repeat(16));

			await node.restoreChainWatches();

			const watcher = node.getChainWatcher()!;
			const watched = (watcher as any).watchedFundings as Map<string, unknown>;
			expect(watched.has(state.channelId.toString('hex')), 'funding watched').to
				.be.true;
			node.destroy();
		});

		it('should not create ChainWatcher when no backend provided', () => {
			const {
				LightningNode
			} = require('../../src/lightning/node/lightning-node');

			const seed = crypto.randomBytes(32);
			const basepoints = makeBasepoints(seed);

			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32)
			});

			expect(node.getChainWatcher()).to.be.null;
			node.destroy();
		});
	});
});
