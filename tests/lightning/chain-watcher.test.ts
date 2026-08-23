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

	/**
	 * Keep only the FIRST callback registered per script hash, which is what
	 * the real Electrum client does: rn-electrum-client answers a repeat
	 * subscription for a script hash it already holds with "Already
	 * Subscribed." and never wires the new callback (issue #468).
	 */
	onlyFirstScriptHashCallback = false;

	async subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void> {
		const existing = this.scriptHashCallbacks.get(scriptHash) || [];
		if (this.onlyFirstScriptHashCallback && existing.length > 0) return;
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

	describe('Funding spend detection (issue #468)', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;
		let spends: Buffer[];
		let reported: Array<{ txid: string; height: number }>;

		beforeEach(async () => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});
			reported = [];
			const originalSpent =
				channelManager.handleFundingSpent.bind(channelManager);
			(channelManager as any).handleFundingSpent = (
				channelId: Buffer,
				spendingTx: bitcoin.Transaction,
				blockHeight: number,
				destinationScript: Buffer,
				feeRatePerVbyte?: number
			): ReturnType<typeof originalSpent> => {
				reported.push({ txid: spendingTx.getId(), height: blockHeight });
				return originalSpent(
					channelId,
					spendingTx,
					blockHeight,
					destinationScript,
					feeRatePerVbyte
				);
			};
			watcher = new ChainWatcher({ backend, channelManager });
			spends = [];
			watcher.on('funding:spent', (cid: Buffer) => spends.push(cid));
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		/**
		 * A funding watch confirmed at depth against a history that holds no
		 * spender yet, which is the state a live channel sits in.
		 */
		async function armConfirmedWatch(): Promise<{
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
			backend.setHistory(scriptHash, [{ txid, height: 98 }]);
			backend.simulateNewBlock(100);
			await watcher.watchFundingOutput(channelId, txid, 0, 3, scriptPubkey);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(spends, 'nothing spends the funding yet').to.have.length(0);
			return { channelId, txid, scriptHash };
		}

		/** A commitment spending the watched funding outpoint. */
		function publishClose(
			txid: string,
			scriptHash: string,
			height: number
		): string {
			const closeTx = new bitcoin.Transaction();
			closeTx.version = 2;
			closeTx.addInput(Buffer.from(txid, 'hex').reverse(), 0, 0xffffffff);
			closeTx.addOutput(Buffer.from('0014' + '22'.repeat(20), 'hex'), 40_000);
			backend.setTransaction(closeTx.getId(), closeTx.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid, height: 98 },
				{ txid: closeTx.getId(), height }
			]);
			return closeTx.getId();
		}

		it('registers a close that appears after the funding confirmed, on the next block', async () => {
			const { channelId, txid, scriptHash } = await armConfirmedWatch();

			// The close lands AFTER the watch confirmed, so the immediate spend
			// check watchFundingSpend ran against a spender-less history. A
			// block is all the node gets: no script hash notification is
			// simulated here, because the production Electrum client never
			// delivers one for the spend subscription.
			publishClose(txid, scriptHash, 101);
			backend.simulateNewBlock(101);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the block registered the close'
			).to.be.true;
		});

		it('registers a close through the confirmation subscription when the backend honours only the first callback', async () => {
			backend.onlyFirstScriptHashCallback = true;
			const { channelId, txid, scriptHash } = await armConfirmedWatch();

			// The only callback the backend holds is the one watchFundingOutput
			// registered for the confirmation. It has to cover the spend too,
			// or the notification is spent on a check that returns immediately.
			publishClose(txid, scriptHash, 101);
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the retained subscription registered the close'
			).to.be.true;
		});

		it('drops a block scan whose watch was replaced before it finished', async () => {
			const { channelId, txid, scriptHash } = await armConfirmedWatch();

			// The splice tx legitimately spends the funding outpoint. It is in
			// the history the block scan snapshots, and the node re-arms the
			// channel's watch onto the new outpoint while that scan is parked.
			const spliceTxid = publishClose(txid, scriptHash, 101);
			backend.holdHistory(1);
			backend.simulateNewBlock(101);

			const spliceScript = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			await watcher.watchFundingOutput(
				channelId,
				spliceTxid,
				0,
				3,
				spliceScript
			);
			backend.releaseHistory();
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				reported.map((r) => r.txid),
				'a retired watch reports nothing'
			).to.deep.equal([]);
		});

		it('drops an older scan that finishes after a newer one reported the close', async () => {
			const { txid, scriptHash } = await armConfirmedWatch();

			// The close is in the mempool when the first scan snapshots the
			// history, and confirmed at 101 when the second one does.
			const closeTxid = publishClose(txid, scriptHash, 0);
			backend.holdHistory(1);
			backend.simulateNewBlock(101);

			backend.setHistory(scriptHash, [
				{ txid, height: 98 },
				{ txid: closeTxid, height: 101 }
			]);
			backend.simulateNewBlock(102);
			await new Promise((resolve) => setTimeout(resolve, 50));

			backend.releaseHistory();
			await new Promise((resolve) => setTimeout(resolve, 50));

			// The stale scan's height 0 reads as "the recorded confirmation is
			// gone", which stops the monitor's depth clock and unschedules
			// every CSV sweep it had already bound to 101.
			expect(
				reported.map((r) => r.height),
				'the confirmed height is not demoted by a stale scan'
			).to.deep.equal([101]);
		});
	});

	describe('Pre-splice spend watches (issue #479)', () => {
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;
		let spends: Buffer[];
		let absentCalls: Buffer[];

		/** The registry the watches live in, for the retirement assertions. */
		function registryKeys(): string[] {
			return [
				...(
					watcher as unknown as {
						watchedFundings: Map<string, unknown>;
					}
				).watchedFundings.keys()
			];
		}

		function preSpliceKeys(channelId: Buffer): string[] {
			const prefix = `${channelId.toString('hex')}:presplice:`;
			return registryKeys().filter((k) => k.startsWith(prefix));
		}

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
			const originalAbsent =
				channelManager.handleFundingSpendAbsent.bind(channelManager);
			(channelManager as any).handleFundingSpendAbsent = (
				channelId: Buffer
			): void => {
				absentCalls.push(channelId);
				originalAbsent(channelId);
			};
			watcher = new ChainWatcher({ backend, channelManager });
			watcher.on('error', () => {});
			spends = [];
			watcher.on('funding:spent', (cid: Buffer) => spends.push(cid));
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		/**
		 * The shape restoreChainWatches and registerFundingWatch arm during an
		 * in-flight splice: the channel's own watch moved to the splice
		 * outpoint, and a spend watch left behind on the pre-splice one. The
		 * funding pubkeys do not rotate across a splice, so both share a script
		 * hash, which is exactly the case the Electrum client answers with
		 * "Already Subscribed." (issue #478).
		 */
		async function armSplice(height = 100): Promise<{
			channelId: Buffer;
			oldTxid: string;
			spliceTxid: string;
			scriptHash: string;
		}> {
			const channelId = crypto.randomBytes(32);
			const oldTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);

			// The pre-splice funding tx itself, so a scan walking the shared
			// history can fetch every entry it is not allowed to skip.
			const oldTx = new bitcoin.Transaction();
			oldTx.version = 2;
			oldTx.addInput(crypto.randomBytes(32), 0, 0xffffffff);
			oldTx.addOutput(scriptPubkey, 100_000);
			backend.setTransaction(oldTxid, oldTx.toBuffer());

			// The splice tx spends the pre-splice funding output.
			const spliceTx = new bitcoin.Transaction();
			spliceTx.version = 2;
			spliceTx.addInput(Buffer.from(oldTxid, 'hex').reverse(), 0, 0xffffffff);
			spliceTx.addOutput(scriptPubkey, 90_000);
			const spliceTxid = spliceTx.getId();
			backend.setTransaction(spliceTxid, spliceTx.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 0 }
			]);
			backend.simulateNewBlock(height);

			await watcher.watchFundingOutput(
				channelId,
				spliceTxid,
				0,
				3,
				scriptPubkey
			);
			await watcher.watchFundingSpendDuringSplice(
				channelId,
				oldTxid,
				0,
				scriptPubkey,
				spliceTxid
			);
			await new Promise((resolve) => setTimeout(resolve, 50));
			spends = [];
			absentCalls = [];
			return { channelId, oldTxid, spliceTxid, scriptHash };
		}

		/**
		 * The attack: the peer evicts our low-feerate splice from the mempool
		 * and broadcasts a revoked pre-splice commitment on the old outpoint.
		 */
		function publishBreach(
			oldTxid: string,
			scriptHash: string,
			height: number
		): string {
			const breach = new bitcoin.Transaction();
			breach.version = 2;
			breach.addInput(Buffer.from(oldTxid, 'hex').reverse(), 0, 0xffffffff);
			breach.addOutput(Buffer.from('0014' + '33'.repeat(20), 'hex'), 80_000);
			backend.setTransaction(breach.getId(), breach.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: breach.getId(), height }
			]);
			return breach.getId();
		}

		it('detects a revoked pre-splice commitment on a later block', async () => {
			// The only callback the backend retains for this script hash is the
			// funding watch's, which is what the real client does, so the
			// splice watch has no push path at all and the block is the only
			// event left.
			backend.onlyFirstScriptHashCallback = true;
			const { channelId, oldTxid, scriptHash } = await armSplice();

			publishBreach(oldTxid, scriptHash, 101);
			backend.simulateNewBlock(101);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the block registered the breach on the pre-splice outpoint'
			).to.be.true;
		});

		it('detects a revoked pre-splice commitment through recheckAllWatches', async () => {
			backend.onlyFirstScriptHashCallback = true;
			const { channelId, oldTxid, scriptHash } = await armSplice();

			publishBreach(oldTxid, scriptHash, 101);
			watcher.recheckAllWatches();
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the recheck sweep registered the breach'
			).to.be.true;
		});

		it('keeps the watch while the splice tx is unconfirmed, and retires it once that spend is final', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();
			expect(preSpliceKeys(channelId), 'armed').to.have.length(1);

			// splice_locked can leave in the same action batch as the
			// broadcast on a zero-conf channel, so a message-driven retirement
			// would drop the watch here, inside the attack window.
			backend.simulateNewBlock(101);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(
				preSpliceKeys(channelId),
				'an unconfirmed splice tx retires nothing'
			).to.have.length(1);

			// Confirmed, but not yet buried.
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 102 }
			]);
			backend.simulateNewBlock(150);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(
				preSpliceKeys(channelId),
				'a shallow splice confirmation retires nothing'
			).to.have.length(1);

			// Buried past SPEND_FINALITY_DEPTH: the old outpoint is spent for
			// good and the watch has nothing left to catch.
			backend.simulateNewBlock(202);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(
				preSpliceKeys(channelId),
				'a final splice spend retires the watch'
			).to.have.length(0);
		});

		it('does not retire on a buried transaction that spent some other outpoint', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();

			// The funding script is shared by every splice generation, so a
			// txid sitting in that history proves it is on chain and nothing
			// more. Here the ignored txid confirms and buries while spending
			// something else entirely, which is the shape a stale record
			// produces; reading it as "the old outpoint is spent for good"
			// would retire the breach watch early.
			const unrelated = new bitcoin.Transaction();
			unrelated.version = 2;
			unrelated.addInput(crypto.randomBytes(32), 7, 0xffffffff);
			unrelated.addOutput(Buffer.from('0014' + '44'.repeat(20), 'hex'), 70_000);
			backend.setTransaction(spliceTxid, unrelated.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 102 }
			]);
			backend.simulateNewBlock(300);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				preSpliceKeys(channelId),
				'the watch stays until its own outpoint is provably spent'
			).to.have.length(1);
		});

		it('keeps one watch per pre-splice outpoint', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();

			// completeSplice nulls spliceInFlight when splice_locked is sent,
			// which on a zero-conf channel is before the splice tx confirms, so
			// a second splice can be negotiated while the first one's outpoint
			// still needs watching.
			const secondSpliceTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = (
				watcher as unknown as {
					watchedFundings: Map<string, { script: Buffer }>;
				}
			).watchedFundings.get(channelId.toString('hex'))!.script;
			await watcher.watchFundingSpendDuringSplice(
				channelId,
				spliceTxid,
				0,
				scriptPubkey,
				secondSpliceTxid
			);
			await new Promise((resolve) => setTimeout(resolve, 50));

			const keys = preSpliceKeys(channelId);
			expect(keys, 'both pre-splice outpoints are watched').to.have.length(2);
			expect(keys.some((k) => k.endsWith(`${oldTxid}:0`))).to.be.true;
			expect(keys.some((k) => k.endsWith(`${spliceTxid}:0`))).to.be.true;
			expect(scriptHash).to.be.a('string');
		});

		it('does not report a spend absence for the channel while a pre-splice watch is armed', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();

			// The splice confirmed, then a reorg took it out and the revoked
			// pre-splice commitment won. The channel's own watch now finds
			// nothing spending the outpoint the splice was going to create,
			// while the pre-splice watch reports the breach. The absence
			// verdict is channel-scoped, so left alone it would demote the
			// breach the other watch just recorded, every block.
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 102 }
			]);
			backend.simulateNewBlock(103);
			await new Promise((resolve) => setTimeout(resolve, 50));

			const breachTxid = publishBreach(oldTxid, scriptHash, 104);
			backend.simulateNewBlock(104);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the breach is reported'
			).to.be.true;
			expect(
				absentCalls.some((cid) => cid.equals(channelId)),
				'no absence verdict contradicts it'
			).to.be.false;
			expect(breachTxid).to.be.a('string');
		});

		it('drops pre-splice watches with the channel, and never resurrects one after stop', async () => {
			const { channelId } = await armSplice();
			expect(preSpliceKeys(channelId)).to.have.length(1);

			expect(watcher.removeWatchedFunding(channelId), 'channel entry removed')
				.to.be.true;
			expect(
				preSpliceKeys(channelId),
				'its pre-splice watches went with it'
			).to.have.length(0);

			const late = await armSplice(200);
			watcher.stop();
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			await watcher.watchFundingSpendDuringSplice(
				late.channelId,
				late.oldTxid,
				0,
				scriptPubkey,
				late.spliceTxid
			);
			expect(
				registryKeys(),
				'a registration landing after stop leaves nothing behind'
			).to.have.length(0);
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
