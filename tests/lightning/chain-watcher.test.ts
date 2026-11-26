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
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { setupFundedAssetUpdatePair } from './helpers/asset-splice-update';
import { encodeSpliceLockedMessage } from '../../src/lightning/message/splice';
import type { IChannelManagerConfig } from '../../src/lightning/channel/channel-manager';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import type { IFinalOutputClaim } from '../../src/lightning/chain/final-output-claims';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	IFundingSpendScan,
	IRREVOCABLE_DEPTH
} from '../../src/lightning/chain/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { COMMIT_ALL } from './helpers/channel-persistence';
import { ChannelState as FinalChannelState } from '../../src/lightning/channel/types';

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
	/** One gate per parked fetch, oldest first, so they can be released
	 * individually. Arbitration between two overlapping scans turns on which
	 * one STARTED first and which one FINISHES first, and only staged release
	 * can express both independently. */
	private historyGates: Array<() => void> = [];

	/** Park the next `count` history fetches until they are released. */
	holdHistory(count = 1): void {
		this.historyHolds = count;
	}

	/** Release every parked fetch. */
	releaseHistory(): void {
		this.historyHolds = 0;
		const gates = this.historyGates;
		this.historyGates = [];
		for (const release of gates) release();
	}

	/** Release the oldest parked fetch only, leaving the rest held. */
	releaseNextHistory(): void {
		const release = this.historyGates.shift();
		release?.();
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
			await new Promise<void>((resolve) => {
				this.historyGates.push(resolve);
			});
		}
		return snapshot;
	}

	private transactionHolds = 0;
	/** Staged release, as for the history gates: a scan can stall in either
	 * fetch, and the spend-height race turns on stalling in this one. */
	private transactionGates: Array<() => void> = [];

	/** Park the next `count` transaction fetches until they are released. */
	holdTransactions(count = 1): void {
		this.transactionHolds = count;
	}

	/** Release the oldest parked transaction fetch only. */
	releaseNextTransaction(): void {
		const release = this.transactionGates.shift();
		release?.();
	}

	private transactionFailures = 0;

	/** Fail the next `count` transaction fetches, parked calls excepted. */
	failTransactions(count = 1): void {
		this.transactionFailures = count;
	}

	/** Transaction fetches asked of this backend, per txid. */
	transactionReads: Map<string, number> = new Map();

	async getTransaction(txid: string): Promise<Buffer> {
		this.transactionReads.set(txid, (this.transactionReads.get(txid) ?? 0) + 1);
		if (this.transactionFailures > 0) {
			this.transactionFailures--;
			throw new Error(`Transaction unavailable: ${txid}`);
		}
		const tx = this.transactions.get(txid);
		if (!tx) throw new Error(`Transaction not found: ${txid}`);
		if (this.transactionHolds > 0) {
			this.transactionHolds--;
			await new Promise<void>((resolve) => {
				this.transactionGates.push(resolve);
			});
		}
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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			// Absorb ChannelManager errors
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
			});
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		it('tracks the exact final funding output across depth loss, spending and reconfirmation', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const script = Buffer.concat([
				Buffer.from([0x51, 32]),
				crypto.randomBytes(32)
			]);
			const scriptHash = computeScriptHash(script);
			const coin = { txid, outputIndex: 1, valueSat: 150000, height: 98 };
			let coins = [coin];
			let offline = false;
			Object.assign(backend, {
				listUnspent: async (hash: string) => {
					expect(hash).to.equal(scriptHash);
					if (offline) throw new Error('chain unavailable');
					return coins;
				}
			});
			const events: string[] = [];
			watcher.on('funding:confirmed', () => events.push('confirmed'));
			watcher.on('funding:depth-lost', () => events.push('lost'));
			const settle = (): Promise<void> =>
				new Promise<void>((resolve) => setImmediate(resolve));
			await watcher.watchFinalFundingOutput(
				channelId,
				txid,
				1,
				3,
				script,
				coin.valueSat
			);
			backend.simulateNewBlock(99);
			await settle();
			expect(events).to.deep.equal([]);
			backend.simulateNewBlock(100);
			await settle();
			backend.simulateNewBlock(99);
			await settle();
			expect(events).to.deep.equal(['confirmed', 'lost']);
			backend.simulateNewBlock(100);
			await settle();
			coins = [
				{ ...coin, outputIndex: 0 },
				{ ...coin, height: 0 },
				{ ...coin, valueSat: coin.valueSat + 1 },
				{ ...coin, txid: 'ab'.repeat(32) }
			];
			backend.simulateScriptHashChange(scriptHash);
			await settle();
			expect(events).to.deep.equal(['confirmed', 'lost', 'confirmed', 'lost']);
			coins = [coin];
			watcher.recheckAllWatches();
			await settle();
			offline = true;
			watcher.recheckAllWatches();
			await settle();
			offline = false;
			watcher.recheckAllWatches();
			await settle();
			expect(events.slice(4)).to.deep.equal(['confirmed', 'lost', 'confirmed']);
		});

		it('recovers confirmed asset witnesses and keeps funding proofs on a spend until the funding block is orphaned', async () => {
			const id = crypto.randomBytes(32),
				script = Buffer.from('5120' + '92'.repeat(32), 'hex');
			const funding = new bitcoin.Transaction();
			funding.addInput(crypto.randomBytes(32), 0);
			funding.addOutput(script, 50000);
			funding.setWitness(0, [Buffer.alloc(64, 9)]);
			const txid = funding.getId(),
				sh = computeScriptHash(script);
			const coin = { txid, outputIndex: 0, valueSat: 50000, height: 70 };
			let spent = false,
				missing = true;
			const verdicts: boolean[] = [];
			Object.assign(backend, {
				listUnspent: async () => (spent ? [] : [coin])
			});
			Object.assign(channelManager, {
				assetOpeningAnchor: () => ({ missingWitnesses: missing }),
				observeAssetOpeningAnchor: (
					_id: string,
					deep: boolean,
					raw?: bitcoin.Transaction
				) => {
					verdicts.push(deep);
					if (raw) {
						expect(raw.toHex()).to.equal(funding.toHex());
						missing = false;
					}
				}
			});
			backend.setTransaction(txid, funding.toBuffer());
			backend.setHistory(sh, [{ txid, height: 70 }]);
			backend.simulateNewBlock(72);
			await watcher.watchFinalFundingOutput(id, txid, 0, 3, script, 50000);
			expect(missing).to.equal(false);
			expect(verdicts.slice(-1)).to.deep.equal([true]);
			spent = true;
			backend.simulateScriptHashChange(sh);
			await new Promise<void>((done) => setImmediate(done));
			expect(verdicts.slice(-1)).to.deep.equal([true]);
			backend.setHistory(sh, []);
			backend.simulateNewBlock(72);
			await new Promise<void>((done) => setImmediate(done));
			expect(verdicts.slice(-1)).to.deep.equal([false]);
		});

		for (const role of [0, 1] as const) {
			it(`selects the confirmed parent for a mempool-only asset splice as ${
				role ? 'acceptor' : 'initiator'
			}`, async function () {
				this.timeout(60000);
				watcher.stop();
				const dir = mkdtempSync(join(tmpdir(), 'asset-splice-parent-'));
				const pair = await setupFundedAssetUpdatePair(dir);
				try {
					const { store, party } = pair.f.devices[role];
					const id = pair.f.id,
						channelId = Buffer.from(id, 'hex');
					channelManager = new ChannelManager({
						finalOpening: {
							storage: store,
							root: party.root,
							dualFunding: {
								verifySpliceFunding: async () => {},
								confirmSpliceFunding: async () => {}
							}
						},
						verifyRemoteFundingInput: async () => 'unspent',
						persistence: COMMIT_ALL
					} as unknown as IChannelManagerConfig);
					channelManager.on('error', () => {});
					const { parent, candidate } =
						store.loadAssetSpliceFundingInfo(id).pending[0];
					const parentTx = bitcoin.Transaction.fromHex(
						parent.funding.fundingTxHex
					);
					const candidateTx = bitcoin.Transaction.fromHex(
						candidate.funding.fundingTxHex
					);
					const coin = candidateTx.outs[candidate.outputIndex];
					const candidateScript = computeScriptHash(coin.script);
					const parentScript = computeScriptHash(
						parentTx.outs[parent.outputIndex].script
					);
					const parentRow = { txid: parentTx.getId(), height: 60 };
					let candidateHeight = 0,
						candidateUnspent = true,
						validProof = false;
					const candidateRow = () => ({
						txid: candidateTx.getId(),
						height: candidateHeight
					});
					backend.setTransaction(parentTx.getId(), parentTx.toBuffer());
					backend.setTransaction(candidateTx.getId(), candidateTx.toBuffer());
					Object.assign(backend, {
						listUnspent: async (script: string) =>
							script === candidateScript && candidateUnspent
								? [
										{
											...candidateRow(),
											outputIndex: candidate.outputIndex,
											valueSat: coin.value
										}
								  ]
								: [],
						getAssetSpliceInclusion: async (txid: string, height: number) => {
							const found = [parentRow, candidateRow()].find(
								(r) => r.txid === txid && r.height === height
							);
							if (!validProof || !found || height <= 0)
								throw Error('Missing block proof');
							return {
								txid,
								blockHash: '35'.repeat(32),
								confirmations: 73 - height
							};
						}
					});
					channelManager.restoreAssetSpliceWatches(id);
					watcher = new ChainWatcher({
						backend,
						channelManager,
						missingDebounceMs: 0
					});
					await watcher.start();
					backend.simulateNewBlock(72);
					const scan = () =>
						watcher.watchFinalFundingOutput(
							channelId,
							candidateTx.getId(),
							candidate.outputIndex,
							3,
							coin.script,
							coin.value
						);
					const close = () =>
						channelManager.forceClose(channelId, Buffer.alloc(0));
					const broadcasts: string[] = [];
					channelManager.on('broadcast:tx', (raw: Buffer) =>
						broadcasts.push(raw.toString('hex'))
					);
					const history = () => {
						backend.setHistory(candidateScript, [candidateRow()]);
						backend.setHistory(parentScript, [parentRow, candidateRow()]);
					};
					history();
					await scan();
					expect(close().ok, 'missing parent inclusion proof').to.equal(false);
					validProof = true;
					backend.setHistory(parentScript, [parentRow]);
					await scan();
					expect(
						close().ok,
						'candidate missing from parent script history'
					).to.equal(false);
					const conflict = new bitcoin.Transaction();
					conflict.addInput(parentTx.getHash(), parent.outputIndex);
					conflict.addOutput(Buffer.from([0x51]), 1000);
					backend.setTransaction(conflict.getId(), conflict.toBuffer());
					backend.setHistory(parentScript, [
						parentRow,
						candidateRow(),
						{ txid: conflict.getId(), height: 72 }
					]);
					await scan();
					expect(close().ok, 'another confirmed parent spend').to.equal(false);
					expect(broadcasts).to.be.empty;

					history();
					await scan();
					expect(channelManager['assetUpdateHeight'](id)).to.equal(undefined);
					expect(store.loadAssetSpliceFundingInfo(id).active).to.equal(
						undefined
					);
					expect(close().ok, 'confirmed parent with a mempool splice').to.equal(
						true
					);
					expect(broadcasts[broadcasts.length - 1]).to.equal(
						parent.localCommitment
					);

					candidateHeight = 72;
					history();
					await scan();
					expect(close().ok, 'candidate at one confirmation').to.equal(true);
					expect(broadcasts[broadcasts.length - 1]).to.equal(
						candidate.localCommitment
					);
					candidateHeight = 0;
					history();
					backend.simulateNewBlock(72);
					await scan();
					expect(
						close().ok,
						'parent available again after a shallow reorg'
					).to.equal(true);
					expect(broadcasts[broadcasts.length - 1]).to.equal(
						parent.localCommitment
					);
					const child = pair.f.views[role === 0 ? 1 : 0].candidate.expected;
					expect(child.ins[0].hash.equals(candidateTx.getHash())).to.equal(
						true
					);
					const observed: string[] = [];
					watcher.on(
						'funding:spent',
						(_id: Buffer, spend: bitcoin.Transaction) =>
							observed.push(spend.getId())
					);
					candidateUnspent = false;
					backend.setTransaction(child.getId(), child.toBuffer());
					backend.setHistory(candidateScript, [
						candidateRow(),
						{ txid: child.getId(), height: -1 }
					]);
					await scan();
					expect(
						observed,
						'passively detects a candidate child in the mempool'
					).to.include(child.getId());
					expect(channelManager['assetUpdateHeight'](id)).to.equal(undefined);
					expect(close().ok, 'confirmed parent remains available').to.equal(
						true
					);
					expect(broadcasts[broadcasts.length - 1]).to.equal(
						parent.localCommitment
					);
				} finally {
					watcher.stop();
					for (const dev of pair.f.devices) dev.store.close();
					rmSync(dir, { recursive: true, force: true });
				}
			});
		}

		it('stops verifying a pending splice once a mined close spends its output, and verifies again after a reorg removes the close', async function () {
			this.timeout(60000);
			watcher.stop();
			const dir = mkdtempSync(join(tmpdir(), 'asset-splice-closed-candidate-'));
			const pair = await setupFundedAssetUpdatePair(dir);
			try {
				const { store, party } = pair.f.devices[0];
				const id = pair.f.id,
					channelId = Buffer.from(id, 'hex');
				let verifies = 0,
					spent = false;
				channelManager = new ChannelManager({
					finalOpening: {
						storage: store,
						root: party.root,
						dualFunding: {
							verifySpliceFunding: async () => {
								verifies++;
								if (spent)
									throw Error('Candidate funding has already been spent');
							},
							confirmSpliceFunding: async () => {}
						}
					},
					verifyRemoteFundingInput: async () => 'unspent',
					persistence: COMMIT_ALL
				} as unknown as IChannelManagerConfig);
				channelManager.on('error', () => {});
				const { parent, candidate } =
					store.loadAssetSpliceFundingInfo(id).pending[0];
				const parentTx = bitcoin.Transaction.fromHex(
					parent.funding.fundingTxHex
				);
				const candidateTx = bitcoin.Transaction.fromHex(
					candidate.funding.fundingTxHex
				);
				const coin = candidateTx.outs[candidate.outputIndex];
				const candidateScript = computeScriptHash(coin.script);
				const parentScript = computeScriptHash(
					parentTx.outs[parent.outputIndex].script
				);
				const parentRow = { txid: parentTx.getId(), height: 60 };
				const candidateRow = { txid: candidateTx.getId(), height: 70 };
				const close = pair.f.views[1].candidate.expected;
				expect(close.ins[0].hash.equals(candidateTx.getHash())).to.equal(true);
				let candidateUnspent = true;
				backend.setTransaction(parentTx.getId(), parentTx.toBuffer());
				backend.setTransaction(candidateTx.getId(), candidateTx.toBuffer());
				backend.setTransaction(close.getId(), close.toBuffer());
				Object.assign(backend, {
					listUnspent: async (script: string) =>
						script === candidateScript && candidateUnspent
							? [
									{
										...candidateRow,
										outputIndex: candidate.outputIndex,
										valueSat: coin.value
									}
							  ]
							: [],
					getAssetSpliceInclusion: async (txid: string, height: number) => {
						const found = [parentRow, candidateRow].find(
							(r) => r.txid === txid && r.height === height
						);
						if (!found) throw Error('Missing block proof');
						return {
							txid,
							blockHash: '35'.repeat(32),
							confirmations: 73 - height
						};
					}
				});
				channelManager.restoreFinalOpeningBroadcasts();
				watcher = new ChainWatcher({
					backend,
					channelManager,
					missingDebounceMs: 0
				});
				const errors: string[] = [];
				watcher.on('error', (err: Error) => errors.push(err.message));
				await watcher.start();
				backend.simulateNewBlock(72);
				const scan = () =>
					watcher.watchFinalFundingOutput(
						channelId,
						candidateTx.getId(),
						candidate.outputIndex,
						3,
						coin.script,
						coin.value
					);
				backend.setHistory(parentScript, [parentRow, candidateRow]);
				backend.setHistory(candidateScript, [candidateRow]);
				await scan();
				expect(verifies, 'verified at depth').to.equal(1);

				candidateUnspent = false;
				spent = true;
				backend.setHistory(candidateScript, [
					candidateRow,
					{ txid: close.getId(), height: 71 }
				]);
				const closed = (): boolean =>
					channelManager.finalOpeningInfo(channelId)[0]?.state ===
					FinalChannelState.FORCE_CLOSED;
				for (let i = 0; i < 50 && !closed(); i++) {
					await scan();
					await new Promise<void>((done) => setImmediate(done));
				}
				expect(closed(), 'the close is recorded').to.equal(true);
				const atClose = verifies;
				for (let height = 73; height < 76; height++) {
					backend.simulateNewBlock(height);
					await new Promise<void>((done) => setImmediate(done));
					await scan();
				}
				expect(verifies, 'no verification after the close').to.equal(atClose);
				const refusals = errors.filter((m) => /already been spent/.test(m));
				expect(refusals.length, 'refusals after the close').to.be.at.most(
					atClose - 1
				);

				candidateUnspent = true;
				spent = false;
				backend.setHistory(candidateScript, [candidateRow]);
				backend.simulateNewBlock(75);
				await new Promise<void>((done) => setImmediate(done));
				await scan();
				await scan();
				expect(closed(), 'the reorg removes the close').to.equal(false);
				expect(verifies, 'verified again after the reorg').to.be.greaterThan(
					atClose
				);
			} finally {
				watcher.stop();
				for (const dev of pair.f.devices) dev.store.close();
				rmSync(dir, { recursive: true, force: true });
			}
		});

		it('permits pending asset updates only for a released candidate with a current mined unspent output', async function () {
			this.timeout(60000);
			watcher.stop();
			const dir = mkdtempSync(join(tmpdir(), 'asset-splice-mixed-readiness-'));
			const pair = await setupFundedAssetUpdatePair(dir),
				d = pair.f.devices[0],
				id = pair.f.id;
			try {
				channelManager = new ChannelManager({
					finalOpening: {
						storage: d.store,
						root: d.party.root,
						dualFunding: {
							verifySpliceFunding: async () => {},
							confirmSpliceFunding: async () => {}
						}
					},
					verifyRemoteFundingInput: async () => 'unspent',
					persistence: COMMIT_ALL
				} as unknown as IChannelManagerConfig);
				channelManager.on('error', () => {});
				const { candidate } = d.store.loadAssetSpliceFundingInfo(id).pending[0],
					tx = bitcoin.Transaction.fromHex(candidate.funding.fundingTxHex);
				const txid = tx.getId(),
					index = candidate.outputIndex,
					out = tx.outs[index],
					sh = computeScriptHash(out.script);
				let present = true,
					allowProof = false,
					depth = 1;
				Object.assign(backend, {
					listUnspent: async () =>
						present
							? [{ txid, outputIndex: index, valueSat: out.value, height: 72 }]
							: [],
					getAssetSpliceInclusion: async () => {
						if (!allowProof) throw Error('No accepted chain proof');
						return { txid, blockHash: '44'.repeat(32), confirmations: depth };
					}
				});
				backend.setHistory(sh, [{ txid, height: 72 }]);
				backend.setTransaction(txid, tx.toBuffer());
				channelManager.restoreAssetSpliceWatches(id);
				watcher = new ChainWatcher({
					backend,
					channelManager,
					missingDebounceMs: 0
				});
				await watcher.start();
				backend.simulateNewBlock(72);
				const observe = () =>
					watcher.watchFinalFundingOutput(
						Buffer.from(id, 'hex'),
						txid,
						index,
						3,
						out.script,
						out.value
					);
				const updates = () => channelManager['assetUpdateHeight'](id);
				await observe();
				expect(updates()).to.equal(undefined);
				allowProof = true;
				await observe();
				expect(updates()).to.equal(72);
				expect(channelManager.isAssetSpliceFundingAvailable(id, txid)).to.equal(
					false
				);
				expect(d.store.loadAssetSpliceFundingInfo(id).active).to.equal(
					undefined
				);
				present = false;
				await observe();
				expect(updates()).to.equal(undefined);
				present = true;
				await observe();
				expect(updates()).to.equal(72);
				await channelManager.receiveAssetSpliceLocked(
					pair.f.devices[1].party.binding.nodeId,
					encodeSpliceLockedMessage({
						channelId: Buffer.from(id, 'hex'),
						fundingTxid: Buffer.from(txid, 'hex').reverse()
					})
				);
				let atImport: number | undefined;
				channelManager.once('splice:complete', () => {
					atImport = updates();
				});
				depth = 3;
				backend.simulateNewBlock(74);
				await observe();
				expect(d.store.loadAssetSpliceFundingInfo(id).pending).to.be.empty;
				expect(
					d.store.loadAssetSpliceFundingInfo(id).active?.candidate.fundingTxid
				).to.equal(txid);
				expect(
					atImport,
					'current wallet import before the legacy depth callback'
				).to.equal(74);
				expect(updates()).to.equal(74);
				present = false;
				await observe();
				expect(updates(), 'spent adopted funding').to.equal(undefined);
				present = true;
				await observe();
				expect(updates()).to.equal(74);
				// Two scans can overlap during wallet exit verification. Only the
				// newest original-device ticket identifies an observation in progress.
				const marker = () =>
					channelManager['finalFundingChecks'].get(
						id + '/' + txid + ':' + index
					);
				const reads: ((
					v: {
						txid: string;
						outputIndex: number;
						valueSat: number;
						height: number;
					}[]
				) => void)[] = [];
				Object.assign(backend, {
					listUnspent: () => new Promise((resolve) => reads.push(resolve))
				});
				const firstScan = observe();
				await new Promise<void>((resolve) => setImmediate(resolve));
				const firstTicket = marker();
				expect(firstTicket?.()).to.equal(true);
				const secondScan = observe();
				await new Promise<void>((resolve) => setImmediate(resolve));
				expect(firstTicket?.()).to.equal(false);
				expect(marker()?.()).to.equal(true);
				reads[0]([]);
				await firstScan;
				expect(marker()?.()).to.equal(true);
				let historicallyVerified = false;
				Object.assign(backend, {
					getAssetSpliceInclusion: async () => {
						expect(marker(), 'spent UTXO before its history proof').to.equal(
							undefined
						);
						historicallyVerified = true;
						return { txid, blockHash: '44'.repeat(32), confirmations: depth };
					}
				});
				reads[1]([]);
				await secondScan;
				expect(historicallyVerified).to.equal(true);
				expect(marker()).to.equal(undefined);
				channelManager.suspendAssetSpliceFunding(id, txid);
				expect(updates()).to.equal(undefined);
			} finally {
				watcher.stop();
				for (const dev of pair.f.devices) dev.store.close();
				rmSync(dir, { recursive: true, force: true });
			}
		});
		it('clears a spent splice outpoint before revalidating its historical inclusion', async () => {
			const id = crypto.randomBytes(32),
				txid = 'a2'.repeat(32);
			const script = Buffer.from('5120' + '2a'.repeat(32), 'hex');
			const coin = { txid, outputIndex: 1, valueSat: 50000, height: 70 };
			let spent = false,
				liveHeight: number | undefined;
			const history: (number | undefined)[] = [];
			Object.assign(backend, {
				listUnspent: async () => (spent ? [] : [coin]),
				getAssetSpliceInclusion: async () => ({
					txid,
					blockHash: 'ba'.repeat(32),
					confirmations: 3
				})
			});
			Object.assign(channelManager, {
				hasAssetSpliceWatch: () => true,
				observeAssetSpliceFunding: async () => {
					history.push(liveHeight);
				},
				observeFinalFunding: (
					_id: string,
					_txid: string,
					height: number | undefined
				) => {
					liveHeight = height;
				}
			});
			backend.setHistory(computeScriptHash(script), [{ txid, height: 70 }]);
			backend.simulateNewBlock(72);
			await watcher.watchFinalFundingOutput(id, txid, 1, 3, script, 50000);
			expect(liveHeight).to.equal(70);
			spent = true;
			backend.simulateScriptHashChange(computeScriptHash(script));
			await new Promise<void>((done) => setImmediate(done));
			expect(history.length).to.be.greaterThan(1);
			expect(history.at(-1)).to.equal(undefined);
		});

		it('observes a confirmed close while new headers supersede slow splice funding proofs', async () => {
			watcher.stop();
			const id = crypto.randomBytes(32);
			const fundingScript = Buffer.from('5120' + '58'.repeat(32), 'hex');
			const payoutScript = Buffer.from('5120' + '59'.repeat(32), 'hex');
			const funding = new bitcoin.Transaction();
			funding.addInput(crypto.randomBytes(32), 1);
			funding.addOutput(fundingScript, 50000);
			const close = new bitcoin.Transaction();
			close.addInput(funding.getHash(), 0);
			close.addOutput(payoutScript, 49000);
			const closeRow = { txid: close.getId(), height: 101 };
			const fundingRow = { txid: funding.getId(), height: 95 };
			const fundingHash = computeScriptHash(fundingScript);
			const payoutHash = computeScriptHash(payoutScript);
			backend.setTransaction(close.getId(), close.toBuffer());
			backend.setHistory(fundingHash, [fundingRow]);
			let spent = false;
			Object.assign(backend, {
				listUnspent: async (hash: string) => {
					if (hash === fundingHash && !spent)
						return [{ ...fundingRow, outputIndex: 0, valueSat: 50000 }];
					if (hash === payoutHash && spent)
						return [{ ...closeRow, outputIndex: 0, valueSat: 49000 }];
					return [];
				},
				getAssetSpliceInclusion: async () => ({
					txid: funding.getId(),
					blockHash: '31'.repeat(32),
					confirmations: 6
				})
			});
			const pending: (() => void)[] = [];
			const freshness: boolean[] = [];
			channelManager.hasAssetSpliceWatch = (): boolean => true;
			channelManager.observeAssetSpliceFunding = async (
				_id,
				_txid,
				_height,
				_prove,
				current
			): Promise<void> => {
				if (!spent) return;
				await new Promise<void>((done) => pending.push(done));
				freshness.push(current());
			};
			const observations: string[] = [];
			const recoveries: string[] = [];
			const errors: Error[] = [];
			watcher = new ChainWatcher({
				backend,
				channelManager,
				finalOutputClaims: (channelId, tx): IFinalOutputClaim[] => {
					expect(channelId.equals(id)).to.equal(true);
					expect(tx.toHex()).to.equal(close.toHex());
					return [
						{
							outputIndex: 0,
							relativeDelay: 1,
							absoluteHeight: 0,
							confirmedOnly: true,
							assetBalanceOutput: true,
							tx: null,
							recover: async (): Promise<null> => {
								recoveries.push(tx.getId());
								return null;
							}
						}
					];
				}
			});
			watcher.on('funding:spent', (_id, tx: bitcoin.Transaction) =>
				observations.push(tx.getId())
			);
			watcher.on('error', (error: Error) => errors.push(error));
			const tick = (): Promise<void> =>
				new Promise((done) => setImmediate(done));
			await watcher.start();
			backend.simulateNewBlock(100);
			await watcher.watchFinalFundingOutput(
				id,
				funding.getId(),
				0,
				3,
				fundingScript,
				50000,
				true
			);
			try {
				spent = true;
				backend.setHistory(fundingHash, [fundingRow, closeRow]);
				backend.simulateNewBlock(101);
				await tick();
				expect(pending).to.have.length(1);
				backend.simulateNewBlock(102);
				await tick();
				expect(pending).to.have.length(2);
				expect(freshness).to.deep.equal([]);
				expect(errors).to.deep.equal([]);
				expect(
					observations,
					'confirmed spender observed before the latest funding proof finishes'
				).to.include(close.getId());
				expect(
					recoveries,
					'mature beneficiary output reaches the claim provider'
				).to.include(close.getId());
				pending.shift()!();
				await tick();
				expect(freshness).to.deep.equal([false]);
			} finally {
				watcher.stop();
				for (const done of pending) done();
				await tick();
			}
			expect(freshness).to.deep.equal([false, false]);
		});

		it('verifies historical splice funding while a confirmed spender lookup is pending', async () => {
			const id = crypto.randomBytes(32);
			const txid = '64'.repeat(32);
			const script = Buffer.from('5120' + '65'.repeat(32), 'hex');
			const fundingHeight = 98;
			const close = new bitcoin.Transaction();
			close.addInput(Buffer.from(txid, 'hex').reverse(), 1);
			close.addOutput(Buffer.of(0x51), 49000);
			backend.setHistory(computeScriptHash(script), [
				{ txid, height: fundingHeight },
				{ txid: close.getId(), height: 100 }
			]);
			backend.setTransaction(close.getId(), close.toBuffer());
			backend.holdTransactions();
			const anchor = { txid, blockHash: '66'.repeat(32), confirmations: 3 };
			Object.assign(backend, {
				listUnspent: async () => [],
				getAssetSpliceInclusion: async (hash: string, height: number) => {
					expect(hash).to.equal(txid);
					expect(height).to.equal(fundingHeight);
					return anchor;
				}
			});
			const store = new SqliteStorage(':memory:');
			const recovery = {
				store,
				channelId: id.toString('hex'),
				finalDigest: '67'.repeat(32)
			};
			let verified = false;
			channelManager.hasAssetSpliceWatch = (): boolean => true;
			channelManager.observeAssetSpliceFunding = async (
				_id,
				_txid,
				height,
				prove,
				current
			): Promise<void> => {
				expect(height).to.equal(fundingHeight);
				expect(await prove(height!, recovery)).to.deep.equal(anchor);
				verified = current();
			};
			const spends: string[] = [];
			watcher.on('funding:spent', (_id, tx: bitcoin.Transaction) =>
				spends.push(tx.getId())
			);
			backend.simulateNewBlock(100);
			const watch = watcher.watchFinalFundingOutput(
				id,
				txid,
				1,
				3,
				script,
				50000,
				true
			);
			try {
				await new Promise<void>((done) => setImmediate(done));
				expect(backend.transactionReads.get(close.getId())).to.equal(1);
				expect(spends).to.deep.equal([]);
				expect(
					verified,
					'historical inclusion can finish before the spend read'
				).to.equal(true);
			} finally {
				backend.releaseNextTransaction();
				await watch;
				await new Promise<void>((done) => setImmediate(done));
				store.close();
			}
			expect(spends).to.deep.equal([close.getId()]);
		});

		it('finishes a mature payout while an ancestor watch observes its authorized splice successor', async function () {
			this.timeout(30000);
			watcher.stop();
			const dir = mkdtempSync(join(tmpdir(), 'asset-splice-payout-watch-'));
			const pair = await setupFundedAssetUpdatePair(dir);
			let release: (() => void) | undefined;
			try {
				const { store, party } = pair.f.devices[0];
				const id = pair.f.id,
					channelId = Buffer.from(id, 'hex');
				channelManager = new ChannelManager({
					finalOpening: {
						storage: store,
						root: party.root,
						dualFunding: {
							verifySpliceFunding: async () => {},
							confirmSpliceFunding: async () => {}
						}
					},
					verifyRemoteFundingInput: async () => 'unspent',
					persistence: COMMIT_ALL
				} as unknown as IChannelManagerConfig);
				channelManager.restoreAssetSpliceWatches(id);
				const { parent, candidate } =
					store.loadAssetSpliceFundingInfo(id).pending[0];
				const previous = bitcoin.Transaction.fromHex(
					parent.funding.fundingTxHex
				);
				const successor = bitcoin.Transaction.fromHex(
					candidate.funding.fundingTxHex
				);
				expect(
					channelManager.hasAssetSpliceWatch(id, successor.getId())
				).to.equal(true);
				expect(
					successor.ins.some(
						(input) =>
							input.hash.equals(previous.getHash()) &&
							input.index === parent.outputIndex
					)
				).to.equal(true);
				const close = new bitcoin.Transaction();
				close.addInput(successor.getHash(), candidate.outputIndex);
				const destination = Buffer.from('5120' + '12'.repeat(32), 'hex');
				close.addOutput(destination, 49000);
				const payout = new bitcoin.Transaction();
				payout.addInput(close.getHash(), 0, 3);
				payout.addOutput(Buffer.of(0x51), 48000);
				const transactions = [previous, successor, close];
				for (const tx of transactions)
					backend.setTransaction(tx.getId(), tx.toBuffer());
				const previousScript = previous.outs[parent.outputIndex].script;
				const successorScript = successor.outs[candidate.outputIndex].script;
				const rows = transactions.map((tx, i) => ({
					txid: tx.getId(),
					height: 80 + i
				}));
				backend.setHistory(computeScriptHash(previousScript), rows.slice(0, 2));
				backend.setHistory(computeScriptHash(successorScript), rows.slice(1));
				Object.assign(backend, {
					listUnspent: async (hash: string) =>
						hash === computeScriptHash(destination)
							? [{ ...rows[2], outputIndex: 0, valueSat: 49000 }]
							: []
				});
				const observed: string[] = [];
				const errors: Error[] = [];
				const held = new Promise<void>((done) => {
					release = done;
				});
				let began!: () => void;
				const recovering = new Promise<void>((done) => {
					began = done;
				});
				watcher = new ChainWatcher({
					backend,
					channelManager,
					finalOutputClaims: (_id, tx): IFinalOutputClaim[] =>
						tx.getId() !== close.getId()
							? []
							: [
									{
										outputIndex: 0,
										relativeDelay: 3,
										absoluteHeight: 0,
										confirmedOnly: true,
										assetBalanceOutput: true,
										tx: null,
										async recover(): Promise<bitcoin.Transaction> {
											began();
											await held;
											return payout;
										}
									}
							  ]
				});
				watcher.on('funding:spent', (_id, tx: bitcoin.Transaction) =>
					observed.push(tx.getId())
				);
				watcher.on('error', (error: Error) => errors.push(error));
				await watcher.start();
				backend.simulateNewBlock(100);
				const head = watcher.watchFinalFundingOutput(
					channelId,
					successor.getId(),
					candidate.outputIndex,
					1,
					successorScript,
					successor.outs[candidate.outputIndex].value,
					true
				);
				await recovering;
				await watcher.watchFinalFundingOutput(
					channelId,
					previous.getId(),
					parent.outputIndex,
					1,
					previousScript,
					previous.outs[parent.outputIndex].value
				);
				expect(observed).to.include(close.getId());
				expect(errors).to.deep.equal([]);
				release!();
				await head;
				expect(
					backend.getBroadcastedTxs(),
					'the prior splice should leave the current outpoint claim active'
				).to.deep.equal([payout.toHex()]);
				const parentOutpoint = previous.getId() + ':' + parent.outputIndex;
				expect(
					channelManager.isAssetSpliceSuccessor(
						id,
						successor.getId(),
						parentOutpoint
					)
				).to.equal(true);
				expect(
					channelManager.isAssetSpliceSuccessor(
						id,
						close.getId(),
						parentOutpoint
					)
				).to.equal(false);
				expect(
					channelManager.isAssetSpliceSuccessor(
						id,
						successor.getId(),
						previous.getId() + ':' + (parent.outputIndex + 1)
					)
				).to.equal(false);
				expect(
					channelManager.isAssetSpliceSuccessor(
						'00'.repeat(32),
						successor.getId(),
						parentOutpoint
					)
				).to.equal(false);
			} finally {
				release?.();
				watcher.stop();
				for (const device of pair.f.devices) device.store.close();
				rmSync(dir, { recursive: true, force: true });
			}
		});

		it('releases an asset payout callback only for the mature exact outpoint on a current tip', async () => {
			watcher.stop();
			let releases = 0;
			const settled: boolean[] = [];
			Object.assign(channelManager, {
				observeAssetOpeningPayout: (
					_id: Buffer,
					_parent: string,
					mined: boolean
				) => settled.push(mined)
			});
			const funding = new bitcoin.Transaction(),
				script = Buffer.from('5120' + '71'.repeat(32), 'hex');
			funding.addInput(crypto.randomBytes(32), 0);
			funding.addOutput(script, 50000);
			const parent = new bitcoin.Transaction(),
				payout = Buffer.from('5120' + '92'.repeat(32), 'hex');
			parent.addInput(funding.getHash(), 0);
			parent.addOutput(payout, 49000);
			const sweep = new bitcoin.Transaction();
			sweep.addInput(parent.getHash(), 0, 3);
			sweep.addOutput(Buffer.of(0x51), 48000);
			const coin = {
				txid: parent.getId(),
				outputIndex: 0,
				height: 100,
				valueSat: 49000
			};
			let coins = [coin];
			Object.assign(backend, {
				listUnspent: async (hash: string) =>
					hash === computeScriptHash(payout) ? coins : []
			});
			backend.setHistory(computeScriptHash(script), [
				{ txid: parent.getId(), height: 100 }
			]);
			backend.setTransaction(parent.getId(), parent.toBuffer());
			watcher = new ChainWatcher({
				backend,
				channelManager,
				finalOutputClaims: () => [
					{
						outputIndex: 0,
						relativeDelay: 3,
						assetBalanceOutput: true,
						absoluteHeight: 0,
						tx: null,
						recover: async () => {
							releases++;
							return sweep;
						}
					}
				]
			});
			await watcher.start();
			const id = crypto.randomBytes(32);
			const watch = () =>
				watcher.watchFinalFundingOutput(
					id,
					funding.getId(),
					0,
					1,
					script,
					50000
				);
			const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
			backend.simulateNewBlock(101);
			await watch();
			expect(releases).to.equal(0);
			coins = [
				{ ...coin, outputIndex: 1 },
				{ ...coin, height: 0 }
			];
			backend.simulateNewBlock(102);
			await tick();
			expect(releases).to.equal(0);
			coins = [coin];
			watcher.recheckAllWatches();
			await tick();
			expect(releases).to.equal(1);
			expect(backend.getBroadcastedTxs()).to.deep.equal([sweep.toHex()]);
			coins = [];
			const payoutHash = computeScriptHash(payout);
			const other = sweep.clone();
			other.ins[0].index++;
			backend.setHistory(payoutHash, [
				{ txid: other.getId(), height: 102 },
				{ txid: sweep.getId(), height: 0 }
			]);
			backend.setTransaction(other.getId(), other.toBuffer());
			backend.setTransaction(sweep.getId(), sweep.toBuffer());
			watcher.recheckAllWatches();
			await tick();
			expect(
				settled.slice(-1),
				'unrelated confirmed input and our unconfirmed spend'
			).to.deep.equal([false]);
			backend.setHistory(payoutHash, [{ txid: sweep.getId(), height: 102 }]);
			backend.simulateNewBlock(103);
			await tick();
			expect(
				settled.slice(-1),
				'confirmed spend of the wallet output'
			).to.deep.equal([true]);
			backend.setHistory(payoutHash, [{ txid: sweep.getId(), height: 0 }]);
			backend.simulateNewBlock(102);
			await tick();
			expect(
				settled.slice(-1),
				'spend orphaned into the mempool'
			).to.deep.equal([false]);
			watcher.stop();
			await watcher.start();
			await watch();
			expect(releases, 'no header accepted since restart').to.equal(1);
		});

		it('requires confirmed wallet receipts for every balance output of an observed commitment', async () => {
			watcher.stop();
			const funding = new bitcoin.Transaction();
			const fundingScript = Buffer.from('5120' + '71'.repeat(32), 'hex');
			funding.addInput(crypto.randomBytes(32), 0);
			funding.addOutput(fundingScript, 50000);
			const commitment = new bitcoin.Transaction();
			commitment.addInput(funding.getHash(), 0);
			const scripts = [0x92, 0x93].map((byte) =>
				Buffer.concat([Buffer.of(0x51, 32), Buffer.alloc(32, byte)])
			);
			for (const script of scripts) commitment.addOutput(script, 24000);
			const sweeps = scripts.map((_, i) => {
				const tx = new bitcoin.Transaction();
				tx.addInput(commitment.getHash(), i);
				tx.addOutput(Buffer.of(0x51), 23000);
				return tx;
			});
			const other = sweeps[0].clone();
			other.outs[0].value--;
			for (const tx of [commitment, other, ...sweeps])
				backend.setTransaction(tx.getId(), tx.toBuffer());
			const observations: boolean[] = [];
			let imported: boolean | Error = true;
			const restored: string[] = [];
			Object.assign(channelManager, {
				observeAssetOpeningPayout: (
					_id: Buffer,
					_parent: string,
					settled: boolean
				) => observations.push(settled)
			});
			Object.assign(backend, { listUnspent: async () => [] });
			backend.setHistory(computeScriptHash(fundingScript), [
				{ txid: commitment.getId(), height: 100 }
			]);
			watcher = new ChainWatcher({
				backend,
				channelManager,
				finalOutputClaims: () =>
					sweeps.map((sweep, index) => ({
						outputIndex: index,
						relativeDelay: 0,
						absoluteHeight: 0,
						assetBalanceOutput: true,
						tx: null,
						matchesAssetPayout: (spend: bitcoin.Transaction) =>
							spend.getId() === sweep.getId(),
						confirmAssetPayout: async (tx: bitcoin.Transaction) => {
							expect(tx.getId()).to.equal(sweep.getId());
							restored.push(tx.getId());
							if (imported instanceof Error) throw imported;
							return imported;
						}
					}))
			});
			await watcher.start();
			backend.simulateNewBlock(103);
			const channelId = crypto.randomBytes(32);
			const scan = async (
				first: bitcoin.Transaction | null,
				secondHeight: number,
				settled: boolean
			) => {
				backend.setHistory(
					computeScriptHash(scripts[0]),
					first ? [{ txid: first.getId(), height: 102 }] : []
				);
				backend.setHistory(computeScriptHash(scripts[1]), [
					{ txid: sweeps[1].getId(), height: secondHeight }
				]);
				observations.length = 0;
				await watcher.watchFinalFundingOutput(
					channelId,
					funding.getId(),
					0,
					1,
					fundingScript,
					50000
				);
				expect(observations).to.deep.equal([settled]);
			};
			await scan(null, 102, false);
			await scan(other, 102, false);
			expect(restored).not.to.include(other.getId());
			imported = false;
			await scan(sweeps[0], 102, false);
			imported = Error('wallet receipt not yet imported');
			await scan(sweeps[0], 102, false);
			imported = true;
			restored.length = 0;
			await scan(sweeps[0], 0, false);
			expect(restored).not.to.include(sweeps[1].getId());
			await scan(sweeps[0], 102, true);
			expect(restored).to.include.members(sweeps.map((t) => t.getId()));
			await scan(sweeps[0], 0, false);
		});

		it('discards a delayed final funding verdict superseded by a script notification', async () => {
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');
			const script = Buffer.concat([
				Buffer.from([0x51, 32]),
				crypto.randomBytes(32)
			]);
			const coin = { txid, outputIndex: 0, valueSat: 30000, height: 100 };
			let release!: () => void;
			const stale = new Promise<void>((resolve) => {
				release = resolve;
			});
			let reads = 0;
			Object.assign(backend, {
				listUnspent: async () => {
					if (++reads !== 1) return [];
					await stale;
					return [coin];
				}
			});
			const confirmations: string[] = [];
			watcher.on('funding:confirmed', (_id, hash) => confirmations.push(hash));
			backend.simulateNewBlock(100);
			const watch = watcher.watchFinalFundingOutput(
				channelId,
				txid,
				0,
				1,
				script,
				coin.valueSat
			);
			await new Promise<void>((resolve) => setImmediate(resolve));
			backend.simulateScriptHashChange(computeScriptHash(script));
			release();
			await watch;
			expect(reads).to.equal(2);
			expect(confirmations).to.deep.equal([]);
		});

		it('withdraws final readiness immediately on a replacement tip or script change', async () => {
			const id = crypto.randomBytes(32);
			const script = Buffer.concat([
				Buffer.from([0x51, 32]),
				crypto.randomBytes(32)
			]);
			const coin = {
				txid: '3b'.repeat(32),
				outputIndex: 0,
				valueSat: 90000,
				height: 40
			};
			let pending = Promise.resolve();
			Object.assign(backend, {
				listUnspent: async () => {
					await pending;
					return [coin];
				}
			});
			let ready = false;
			watcher.on('funding:confirmed', () => {
				ready = true;
			});
			watcher.on('funding:depth-lost', () => {
				ready = false;
			});
			backend.simulateNewBlock(42);
			const watch = (): Promise<void> =>
				watcher.watchFinalFundingOutput(
					id,
					coin.txid,
					0,
					3,
					script,
					coin.valueSat
				);
			await watch();
			expect(ready).to.equal(true);
			for (const notify of [
				(): void => backend.simulateNewBlock(42),
				(): void => backend.simulateScriptHashChange(computeScriptHash(script))
			]) {
				let release!: () => void;
				pending = new Promise<void>((resolve) => {
					release = resolve;
				});
				notify();
				expect(ready).to.equal(false);
				release();
				await new Promise<void>((resolve) => setImmediate(resolve));
				expect(ready).to.equal(true);
			}
			watcher.stop();
			expect(ready).to.equal(false);
			await watcher.start();
			await watch();
			expect(ready, 'restart needs a new tip').to.equal(false);
			backend.simulateNewBlock(43);
			await new Promise<void>((resolve) => setImmediate(resolve));
			expect(ready).to.equal(true);
			watcher.removeWatchedFunding(id);
			expect(ready).to.equal(false);
		});

		for (const splice of [false, true]) {
			it(
				'discards a delayed spend when the exact ' +
					(splice ? 'splice' : 'opening') +
					' funding output returns',
				async () => {
					const id = crypto.randomBytes(32);
					const script = Buffer.concat([
						Buffer.from([0x51, 32]),
						crypto.randomBytes(32)
					]);
					const scriptHash = computeScriptHash(script);
					const coin = {
						txid: '6e'.repeat(32),
						outputIndex: 1,
						valueSat: 90000,
						height: 98
					};
					const spend = new bitcoin.Transaction();
					spend.addInput(
						Buffer.from(coin.txid, 'hex').reverse(),
						coin.outputIndex
					);
					spend.addOutput(Buffer.from([0x51]), 88000);
					let coins = [coin];
					Object.assign(backend, { listUnspent: async () => coins });
					const events: string[] = [];
					watcher.on('funding:confirmed', () => events.push('confirmed'));
					watcher.on('funding:spent', () => events.push('spent'));
					const settle = (): Promise<void> =>
						new Promise<void>((resolve) => setImmediate(resolve));
					backend.simulateNewBlock(100);
					await watcher.watchFinalFundingOutput(
						id,
						coin.txid,
						coin.outputIndex,
						3,
						script,
						coin.valueSat,
						splice
					);
					coins = [];
					backend.setHistory(scriptHash, [
						{ txid: spend.getId(), height: 100 }
					]);
					backend.setTransaction(spend.getId(), spend.toBuffer());
					backend.holdTransactions();
					backend.simulateScriptHashChange(scriptHash);
					await settle();
					// A replacement branch restores this coin while the old spender is in flight.
					coins = [coin];
					backend.setHistory(scriptHash, [
						{ txid: coin.txid, height: coin.height }
					]);
					backend.simulateScriptHashChange(scriptHash);
					await settle();
					backend.releaseNextTransaction();
					await settle();
					expect(events).to.deep.equal(['confirmed', 'confirmed']);
				}
			);
		}

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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});
			const watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
			});
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

		it('a stalled discovery never restores a candidate a newer scan found gone', async () => {
			// Discovery reads the history one transaction at a time, and the
			// candidate set it produces answers the same question absence does:
			// a stale 'present' lifts the missing-funding quarantine and stops
			// BOLT 2's forget clock against a funding that is not there (#624).
			const backend = new MockChainBackend();
			const channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(crypto.randomBytes(32)),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});
			const watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
			});
			watcher.on('error', () => {});
			const recovered: string[] = [];
			watcher.on('funding:recovered', (_id: Buffer, txid: string) =>
				recovered.push(txid)
			);

			const channelId = crypto.randomBytes(32);
			const script = bitcoin.payments.p2wsh({
				redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
			}).output!;
			const scriptHash = computeScriptHash(script);
			// The attempt the restored record names, and the replacement that
			// reached the chain instead: same input, so the lineage matches and
			// discovery recognizes it as this channel's funding.
			const attemptTxid = 'cc'.repeat(32);
			const parentHash = crypto.randomBytes(32);
			const lineage = [
				[`${Buffer.from(parentHash).reverse().toString('hex')}:0`]
			];
			const replacement = new bitcoin.Transaction();
			replacement.version = 2;
			replacement.addInput(parentHash, 0);
			replacement.addOutput(script, 100_000);
			backend.setTransaction(replacement.getId(), replacement.toBuffer());

			await watcher.start();
			backend.simulateNewBlock(200);
			// Arming checks once, so two more absences reach the debounce.
			backend.setHistory(scriptHash, []);
			await watcher.watchFundingOutput(
				channelId,
				attemptTxid,
				0,
				1,
				script,
				undefined,
				undefined,
				lineage
			);
			await new Promise((r) => setTimeout(r, 20));
			for (let i = 0; i < 2; i++) {
				watcher.recheckAllWatches();
				await new Promise((r) => setTimeout(r, 20));
			}
			expect(watcher.getFundingPresence(channelId), 'reported absent').to.equal(
				'absent'
			);

			// Scan A sees the replacement confirmed and stalls fetching it.
			backend.setHistory(scriptHash, [
				{ txid: replacement.getId(), height: 150 }
			]);
			backend.holdTransactions(1);
			watcher.recheckAllWatches();
			await new Promise((r) => setTimeout(r, 20));

			// A reorg takes it out again, and scan B completes on that history
			// while A is still parked mid-fetch.
			backend.setHistory(scriptHash, []);
			watcher.recheckAllWatches();
			await new Promise((r) => setTimeout(r, 20));

			backend.releaseNextTransaction();
			await new Promise((r) => setTimeout(r, 20));
			expect(
				watcher.hasProvisionalFunding(channelId),
				'the stalled scan cannot put its candidate back'
			).to.equal(false);
			expect(
				watcher.getFundingPresence(channelId),
				'so the newer absence stands'
			).to.equal('absent');
			expect(
				recovered,
				'and nothing was announced as recovered'
			).to.have.length(0);

			// A scan that genuinely starts after the absence still records the
			// candidate, so this is an ordering rule and not a block.
			backend.setHistory(scriptHash, [
				{ txid: replacement.getId(), height: 150 }
			]);
			watcher.recheckAllWatches();
			await new Promise((r) => setTimeout(r, 20));
			expect(
				watcher.hasProvisionalFunding(channelId),
				'a fresh presence answer is honoured'
			).to.equal(true);
			expect(watcher.getFundingPresence(channelId)).to.equal('present');
			expect(recovered, 'and reported').to.deep.equal([attemptTxid]);
			watcher.stop();
		});

		it('an unreadable newer scan cannot bury an older complete discovery', async () => {
			// The other side of the same ordering rule: a scan that could not
			// read the history has concluded nothing, so it must not take the
			// ticket away from an older scan that did find the funding (#624).
			const backend = new MockChainBackend();
			const channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(crypto.randomBytes(32)),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});
			const watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
			});
			watcher.on('error', () => {});

			const channelId = crypto.randomBytes(32);
			const script = bitcoin.payments.p2wsh({
				redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
			}).output!;
			const scriptHash = computeScriptHash(script);
			const attemptTxid = 'dd'.repeat(32);
			const parentHash = crypto.randomBytes(32);
			const lineage = [
				[`${Buffer.from(parentHash).reverse().toString('hex')}:0`]
			];
			const replacement = new bitcoin.Transaction();
			replacement.version = 2;
			replacement.addInput(parentHash, 0);
			replacement.addOutput(script, 100_000);
			backend.setTransaction(replacement.getId(), replacement.toBuffer());

			await watcher.start();
			backend.simulateNewBlock(200);
			backend.setHistory(scriptHash, []);
			await watcher.watchFundingOutput(
				channelId,
				attemptTxid,
				0,
				1,
				script,
				undefined,
				undefined,
				lineage
			);
			await new Promise((r) => setTimeout(r, 20));
			for (let i = 0; i < 2; i++) {
				watcher.recheckAllWatches();
				await new Promise((r) => setTimeout(r, 20));
			}
			expect(watcher.getFundingPresence(channelId), 'reported absent').to.equal(
				'absent'
			);

			// Scan A stalls fetching the confirmed replacement.
			backend.setHistory(scriptHash, [
				{ txid: replacement.getId(), height: 150 }
			]);
			backend.holdTransactions(1);
			watcher.recheckAllWatches();
			await new Promise((r) => setTimeout(r, 20));

			// Scan B starts on the same history and its fetch fails, so it holds
			// no answer at all.
			backend.failTransactions(1);
			watcher.recheckAllWatches();
			await new Promise((r) => setTimeout(r, 20));
			expect(
				watcher.getFundingPresence(channelId),
				'an unreadable scan is not a verdict either way'
			).to.equal('absent');

			backend.releaseNextTransaction();
			await new Promise((r) => setTimeout(r, 20));
			expect(
				watcher.hasProvisionalFunding(channelId),
				'the completed scan still gets to report its candidate'
			).to.equal(true);
			expect(watcher.getFundingPresence(channelId)).to.equal('present');
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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});
			absentCalls = [];
			const original =
				channelManager.handleFundingSpendAbsent.bind(channelManager);
			(channelManager as any).handleFundingSpendAbsent = (
				channelId: Buffer,
				scan?: IFundingSpendScan
			): boolean => {
				absentCalls.push(channelId);
				return original(channelId, scan);
			};

			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
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
			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
			});
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

		it('starts exactly one spend scan per notification for a confirmed watch', async () => {
			const { channelId, txid, scriptHash } = await armConfirmedWatch();

			// The backend delivers a notification to EVERY callback registered
			// for a script hash (issue #478), so the phase-routed subscription
			// from watchFundingOutput has to be the only one this watch holds.
			// The second one watchFundingSpend used to add made each
			// notification start two identical history scans.
			publishClose(txid, scriptHash, 101);
			const originalHistory = backend.getScriptHashHistory.bind(backend);
			let historyCalls = 0;
			(backend as any).getScriptHashHistory = (
				hash: string
			): ReturnType<typeof originalHistory> => {
				historyCalls++;
				return originalHistory(hash);
			};
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the notification registered the close'
			).to.be.true;
			expect(historyCalls, 'one notification starts one spend scan').to.equal(
				1
			);
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
		let absentScans: Array<{
			channelId: Buffer;
			scan?: IFundingSpendScan;
		}>;
		let forceRetracted: boolean;
		let reported: string[];

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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});
			absentCalls = [];
			absentScans = [];
			// The monitor owns the retraction decision now, and these channels
			// have no monitor, so it always answers "nothing retracted". Tests
			// about the WATCHER's arbitration force the answer instead of
			// standing up a monitor they are not about; tests about the
			// DECISION live in chain-monitor.test.ts.
			forceRetracted = false;
			const originalAbsent =
				channelManager.handleFundingSpendAbsent.bind(channelManager);
			(channelManager as any).handleFundingSpendAbsent = (
				channelId: Buffer,
				scan?: IFundingSpendScan
			): boolean => {
				absentCalls.push(channelId);
				absentScans.push({ channelId, scan });
				return originalAbsent(channelId, scan) || forceRetracted;
			};
			reported = [];
			const originalSpent =
				channelManager.handleFundingSpent.bind(channelManager);
			(channelManager as any).handleFundingSpent = (
				cid: Buffer,
				spendingTx: bitcoin.Transaction,
				blockHeight: number,
				destinationScript: Buffer,
				feeRatePerVbyte?: number
			): ReturnType<typeof originalSpent> => {
				reported.push(spendingTx.getId());
				return originalSpent(
					cid,
					spendingTx,
					blockHeight,
					destinationScript,
					feeRatePerVbyte
				);
			};
			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
			});
			watcher.on('error', () => {});
			spends = [];
			watcher.on('funding:spent', (cid: Buffer) => spends.push(cid));
			await watcher.start();
		});

		afterEach(() => {
			watcher.stop();
		});

		const reportedTxids = (): string[] => reported;

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

			// Buried past IRREVOCABLE_DEPTH: the old outpoint is spent for
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

		it('scopes an absence verdict to the outpoint the scan covered', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();

			// The splice confirmed, then a reorg took it out and the revoked
			// pre-splice commitment won. The channel's own watch now finds
			// nothing spending the outpoint the splice was going to create,
			// while the pre-splice watch reports the breach on the OLD one.
			// Left unscoped these two would undo each other every block; what
			// keeps them apart is that each says which outpoint it is evidence
			// about, and the monitor only ever retracts a record of that same
			// outpoint (issue #479).
			// Deep enough for the channel's own watch to confirm and arm its
			// spend detection, so this really is two live watches over one
			// shared script and not just the leg talking to itself.
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 100 }
			]);
			backend.simulateNewBlock(103);
			await new Promise((resolve) => setTimeout(resolve, 50));

			const breachTxid = publishBreach(oldTxid, scriptHash, 104);
			// publishBreach rewrites the history; keep the splice in it, or the
			// channel's own watch has nothing to be watching.
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 100 },
				{ txid: breachTxid, height: 104 }
			]);
			backend.simulateNewBlock(104);
			await new Promise((resolve) => setTimeout(resolve, 50));

			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the breach is reported'
			).to.be.true;
			const mine = absentScans.filter((c) => c.channelId.equals(channelId));
			expect(mine.length, 'an absence verdict was offered').to.be.greaterThan(
				0
			);
			for (const call of mine) {
				expect(
					call.scan,
					'every absence verdict names the outpoint it is about'
				).to.not.equal(undefined);
				// The dangerous shape is a verdict that claims the outpoint the
				// breach spent WITHOUT naming the splice transaction it
				// ignores: that is the one the monitor would act on, and it
				// would demote the breach the sibling just recorded.
				if (call.scan!.txid === oldTxid) {
					expect(
						call.scan!.expectedSpendTxid,
						'a verdict about the old outpoint is the leg speaking'
					).to.equal(spliceTxid);
				} else {
					expect(
						call.scan!.txid,
						'and anything else is the channel watch, on its own outpoint'
					).to.equal(spliceTxid);
					expect(call.scan!.expectedSpendTxid).to.equal(undefined);
				}
			}
			expect(
				mine.some((c) => c.scan!.txid === spliceTxid),
				'the channel watch spoke for its own outpoint'
			).to.be.true;
			expect(breachTxid).to.be.a('string');
		});

		it('retracts a pre-splice breach when a reorg takes it out of the history', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();

			// The splice confirms, is reorged out, and the revoked pre-splice
			// commitment wins. The leg reports the breach and now OWNS the
			// channel's spend verdict.
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 102 }
			]);
			backend.simulateNewBlock(103);
			await new Promise((resolve) => setTimeout(resolve, 50));
			publishBreach(oldTxid, scriptHash, 104);
			backend.simulateNewBlock(104);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(
				spends.some((cid) => cid.equals(channelId)),
				'the breach is reported'
			).to.be.true;
			expect(
				absentScans.filter(
					(c) =>
						c.channelId.equals(channelId) &&
						c.scan?.txid === oldTxid &&
						c.scan?.expectedSpendTxid === undefined
				),
				'and nothing offers to contradict it'
			).to.have.length(0);

			// Now the breach itself is reorged out. Whoever reported a spend
			// has to be able to take it back, or the monitor keeps a
			// confirmation height that is no longer in the chain and runs its
			// finality clock against it. The leg says so by naming the outpoint
			// it scanned AND the splice transaction it deliberately ignores,
			// which is what stops the same verdict retracting a record of that
			// splice; the monitor matches the two (issue #479).
			backend.setHistory(scriptHash, [{ txid: oldTxid, height: 90 }]);
			backend.simulateNewBlock(105);
			await new Promise((resolve) => setTimeout(resolve, 50));

			const legVerdicts = absentScans.filter(
				(c) => c.channelId.equals(channelId) && c.scan?.txid === oldTxid
			);
			expect(
				legVerdicts.length,
				'the leg offers to retract the spend it reported'
			).to.be.greaterThan(0);
			expect(
				legVerdicts[0].scan!.outputIndex,
				'against the outpoint it is armed on'
			).to.equal(0);
			expect(
				legVerdicts[0].scan!.expectedSpendTxid,
				'and it names the spender it exists to ignore'
			).to.equal(spliceTxid);
		});

		it('retires exactly at the monitor irrevocable boundary, not a block before', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 200 }
			]);

			// IRREVOCABLE_DEPTH is 100 and the monitor resolves an output at
			// `tip - confirmationHeight >= 100`, i.e. at 300. Retiring at 299
			// would leave the breach undetectable for the last block before
			// the spend is irrevocable.
			backend.simulateNewBlock(299);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(
				preSpliceKeys(channelId),
				'still armed one block short of the boundary'
			).to.have.length(1);

			const retired: Array<{ txid: string; outputIndex: number }> = [];
			watcher.on(
				'funding:presplice-retired',
				(_cid: Buffer, txid: string, outputIndex: number) => {
					retired.push({ txid, outputIndex });
				}
			);
			backend.simulateNewBlock(300);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(
				preSpliceKeys(channelId),
				'retired at the boundary the monitor uses'
			).to.have.length(0);
			// The node keeps a durable record so a restart can re-arm this
			// watch; retiring it has to retire that too, or the next start
			// re-arms a watch for an outpoint nothing can spend any more.
			expect(retired, 'the retirement is announced').to.deep.equal([
				{ txid: oldTxid, outputIndex: 0 }
			]);
		});

		it('a stale sibling scan cannot reclaim the spend verdict from the canonical close', async () => {
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();
			const registry = (
				watcher as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			const chanKey = channelId.toString('hex');
			const legKey = preSpliceKeys(channelId)[0];
			const gen = (watcher as unknown as { lifecycleGeneration: number })
				.lifecycleGeneration;
			const scan = (
				watcher as unknown as {
					checkFundingSpent: (
						w: unknown,
						g: number,
						k: string
					) => Promise<void>;
				}
			).checkFundingSpent.bind(watcher);

			// The leg's scan snapshots a history holding an ORPHANED spend of
			// the old outpoint, then parks mid-flight.
			const orphan = publishBreach(oldTxid, scriptHash, 104);
			backend.holdHistory(1);
			const parked = scan(registry.get(legKey), gen, legKey).catch(() => {
				/* not the subject */
			});
			await new Promise((resolve) => setTimeout(resolve, 20));

			// While it is parked the real close of the NEW outpoint is found by
			// the channel's own watch, which takes ownership of the verdict.
			const close = new bitcoin.Transaction();
			close.version = 2;
			close.addInput(Buffer.from(spliceTxid, 'hex').reverse(), 0, 0xffffffff);
			close.addOutput(Buffer.from('0014' + '66'.repeat(20), 'hex'), 60_000);
			backend.setTransaction(close.getId(), close.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 105 },
				{ txid: close.getId(), height: 106 }
			]);
			const chanWatch = registry.get(chanKey) as { txid: string };
			chanWatch.txid = spliceTxid;
			await scan(chanWatch, gen, chanKey);
			expect(reportedTxids(), 'the canonical close is recorded').to.deep.equal([
				close.getId()
			]);

			// The parked scan now finishes. Clearing the sibling's ownership
			// flag alone would not stop it: it would pass every remaining guard
			// and put the monitor back on a transaction that is no longer in
			// the chain, taking the penalty and fee-bump tracking bound to the
			// real close with it. What stops it is the channel's scan ticket:
			// the canonical close applied a verdict AFTER this scan started.
			backend.releaseHistory();
			await parked;
			await new Promise((resolve) => setTimeout(resolve, 20));

			expect(
				reportedTxids(),
				'the orphan never reclaims the verdict'
			).to.deep.equal([close.getId()]);
			expect(orphan).to.be.a('string');
		});

		it('a scan that started later wins even when the earlier one finishes first', async () => {
			// The mirror of the case above, and the one arbitration on
			// COMPLETION order gets wrong. The leg's scan starts first and
			// finishes first, holding an orphaned pre-splice spend; the
			// channel's own scan starts after it, holding the canonical close.
			// Retiring every sibling at claim time would throw the fresher
			// answer away and leave the monitor bound to the orphan.
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();
			const registry = (
				watcher as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			const chanKey = channelId.toString('hex');
			const legKey = preSpliceKeys(channelId)[0];
			const gen = (watcher as unknown as { lifecycleGeneration: number })
				.lifecycleGeneration;
			const scan = (
				watcher as unknown as {
					checkFundingSpent: (
						w: unknown,
						g: number,
						k: string
					) => Promise<void>;
				}
			).checkFundingSpent.bind(watcher);

			const orphan = publishBreach(oldTxid, scriptHash, 104);
			backend.holdHistory(2);

			// Started FIRST, against a history holding only the orphan.
			const legScan = scan(registry.get(legKey), gen, legKey).catch(() => {
				/* not the subject */
			});
			await new Promise((resolve) => setTimeout(resolve, 20));

			// Started SECOND, against a history that also holds the real close
			// of the new outpoint.
			const close = new bitcoin.Transaction();
			close.version = 2;
			close.addInput(Buffer.from(spliceTxid, 'hex').reverse(), 0, 0xffffffff);
			close.addOutput(Buffer.from('0014' + '66'.repeat(20), 'hex'), 60_000);
			backend.setTransaction(close.getId(), close.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: orphan, height: 104 },
				{ txid: spliceTxid, height: 105 },
				{ txid: close.getId(), height: 106 }
			]);
			const chanWatch = registry.get(chanKey) as { txid: string };
			chanWatch.txid = spliceTxid;
			const chanScan = scan(chanWatch, gen, chanKey).catch(() => {
				/* not the subject */
			});
			await new Promise((resolve) => setTimeout(resolve, 20));

			// The EARLIER scan finishes first, then the later one.
			backend.releaseNextHistory();
			await legScan;
			await new Promise((resolve) => setTimeout(resolve, 20));
			backend.releaseNextHistory();
			await chanScan;
			await new Promise((resolve) => setTimeout(resolve, 20));

			expect(
				reportedTxids(),
				'the canonical close is not discarded by the older scan'
			).to.include(close.getId());
			expect(
				reportedTxids()[reportedTxids().length - 1],
				'and it is the verdict the monitor ends up holding'
			).to.equal(close.getId());
		});

		it('a retraction retires a sibling scan that started before it', async () => {
			// The absence half of the same race. Retracting used to move only
			// the retracting watch's own counter, so a sibling that had already
			// fetched its history sailed past every guard and reported a spend
			// the retraction had just contradicted.
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();
			const registry = (
				watcher as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			const chanKey = channelId.toString('hex');
			const legKey = preSpliceKeys(channelId)[0];
			const gen = (watcher as unknown as { lifecycleGeneration: number })
				.lifecycleGeneration;
			const scan = (
				watcher as unknown as {
					checkFundingSpent: (
						w: unknown,
						g: number,
						k: string
					) => Promise<void>;
				}
			).checkFundingSpent.bind(watcher);
			const chanWatch = registry.get(chanKey) as { txid: string };
			chanWatch.txid = spliceTxid;

			// The leg finds a breach and owns the channel's spend verdict.
			const breach = publishBreach(oldTxid, scriptHash, 104);
			await scan(registry.get(legKey), gen, legKey);
			expect(reportedTxids(), 'the breach is recorded').to.deep.equal([breach]);

			// The channel's own scan starts, holding a history in which the new
			// outpoint is also spent, and parks.
			const stale = new bitcoin.Transaction();
			stale.version = 2;
			stale.addInput(Buffer.from(spliceTxid, 'hex').reverse(), 0, 0xffffffff);
			stale.addOutput(Buffer.from('0014' + '77'.repeat(20), 'hex'), 50_000);
			backend.setTransaction(stale.getId(), stale.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: breach, height: 104 },
				{ txid: spliceTxid, height: 105 },
				{ txid: stale.getId(), height: 106 }
			]);
			backend.holdHistory(1);
			const parked = scan(chanWatch, gen, chanKey).catch(() => {
				/* not the subject */
			});
			await new Promise((resolve) => setTimeout(resolve, 20));

			// A reorg takes the breach out and the leg, whose outpoint the
			// monitor's record names, retracts it. This channel has no monitor,
			// so the answer is forced; the decision itself is covered in
			// chain-monitor.test.ts.
			forceRetracted = true;
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 105 }
			]);
			await scan(registry.get(legKey), gen, legKey);
			expect(
				absentCalls.some((cid) => cid.equals(channelId)),
				'the leg retracted'
			).to.be.true;

			backend.releaseHistory();
			await parked;
			await new Promise((resolve) => setTimeout(resolve, 20));

			expect(
				reportedTxids(),
				'the parked sibling does not report over the retraction'
			).to.deep.equal([breach]);
		});

		it('a repeat observation still retires an older stalled scan', async () => {
			// Freshness is about when the evidence was gathered, not about
			// whether the monitor changed as a result. Scan 1 reports the
			// breach; scan 2 stalls holding a history from before it; scan 3
			// re-observes the same breach and the monitor deduplicates it.
			// Scan 2 must still be retired when it wakes, or it contradicts a
			// spend that has since been confirmed by later evidence.
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();
			const registry = (
				watcher as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			const chanKey = channelId.toString('hex');
			const legKey = preSpliceKeys(channelId)[0];
			const gen = (watcher as unknown as { lifecycleGeneration: number })
				.lifecycleGeneration;
			const scan = (
				watcher as unknown as {
					checkFundingSpent: (
						w: unknown,
						g: number,
						k: string
					) => Promise<void>;
				}
			).checkFundingSpent.bind(watcher);
			const chanWatch = registry.get(chanKey) as { txid: string };
			chanWatch.txid = spliceTxid;

			// 1: the leg finds the breach.
			const breach = publishBreach(oldTxid, scriptHash, 104);
			await scan(registry.get(legKey), gen, legKey);
			expect(reportedTxids()).to.deep.equal([breach]);

			// 2: the channel's own scan starts against a history in which its
			// outpoint also looks spent, and parks.
			const stale = new bitcoin.Transaction();
			stale.version = 2;
			stale.addInput(Buffer.from(spliceTxid, 'hex').reverse(), 0, 0xffffffff);
			stale.addOutput(Buffer.from('0014' + '99'.repeat(20), 'hex'), 30_000);
			backend.setTransaction(stale.getId(), stale.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: breach, height: 104 },
				{ txid: spliceTxid, height: 105 },
				{ txid: stale.getId(), height: 106 }
			]);
			backend.holdHistory(1);
			const parked = scan(chanWatch, gen, chanKey).catch(() => {
				/* not the subject */
			});
			await new Promise((resolve) => setTimeout(resolve, 20));

			// 3: the leg sweeps again and re-observes the SAME breach, which
			// the monitor deduplicates.
			await scan(registry.get(legKey), gen, legKey);

			backend.releaseHistory();
			await parked;
			await new Promise((resolve) => setTimeout(resolve, 20));

			expect(
				reportedTxids(),
				'the stalled scan does not report over evidence younger than it'
			).to.deep.equal([breach, breach]);
		});

		it('a newer completed absence retires an older scan of the same outpoint', async () => {
			// The absence race with nothing to retract. The channel's own scan
			// starts against a history in which its outpoint looks spent, and
			// parks; a reorg takes that spend out; a NEWER scan of the same
			// outpoint completes against the clean history. The monitor is
			// still WATCHING, so no verdict was applied and the channel-wide
			// ticket never moved. What must stop the older scan from resuming
			// and reporting the vanished spend anyway is the outpoint's own
			// completed-scan freshness.
			const { channelId, oldTxid, spliceTxid, scriptHash } = await armSplice();
			const registry = (
				watcher as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			const chanKey = channelId.toString('hex');
			const gen = (watcher as unknown as { lifecycleGeneration: number })
				.lifecycleGeneration;
			const scan = (
				watcher as unknown as {
					checkFundingSpent: (
						w: unknown,
						g: number,
						k: string
					) => Promise<void>;
				}
			).checkFundingSpent.bind(watcher);
			const chanWatch = registry.get(chanKey) as { txid: string };
			chanWatch.txid = spliceTxid;

			// A spend of the channel's outpoint that a reorg is about to erase.
			const stale = new bitcoin.Transaction();
			stale.version = 2;
			stale.addInput(Buffer.from(spliceTxid, 'hex').reverse(), 0, 0xffffffff);
			stale.addOutput(Buffer.from('0014' + 'aa'.repeat(20), 'hex'), 30_000);
			backend.setTransaction(stale.getId(), stale.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 105 },
				{ txid: stale.getId(), height: 106 }
			]);
			backend.holdHistory(1);
			const parked = scan(chanWatch, gen, chanKey).catch(() => {
				/* not the subject */
			});
			await new Promise((resolve) => setTimeout(resolve, 20));

			// The reorg erases the spend; a newer scan of the SAME outpoint
			// runs to completion and finds nothing.
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 105 }
			]);
			await scan(chanWatch, gen, chanKey);
			expect(
				absentScans.some(
					(c) =>
						c.channelId.equals(channelId) &&
						c.scan?.txid === spliceTxid &&
						c.scan?.outputIndex === 0
				),
				'the newer scan reported the absence'
			).to.be.true;

			backend.releaseHistory();
			await parked;
			await new Promise((resolve) => setTimeout(resolve, 20));

			expect(
				reportedTxids(),
				'the older scan does not report the vanished spend over it'
			).to.deep.equal([]);
		});

		it("a leg vouches for the splice on behalf of the channel's own watch", async () => {
			// The point-of-no-return shape: our tx_signatures have left, so the
			// peer can assemble and broadcast the splice, but no WATCH_FUNDING
			// has been emitted yet - the channel's own funding watch is still
			// on the OLD outpoint and carries no expected spender of its own.
			// Arming a second watch does not stop the first one reporting the
			// legitimate splice as a spend of the funding, and classification
			// has no branch for "this is a splice", so the channel would be
			// marked closed on chain while it is very much alive. What stops it
			// is that the expected spender belongs to the OUTPOINT.
			const channelId = crypto.randomBytes(32);
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);
			const oldTxid = crypto.randomBytes(32).toString('hex');

			const oldTx = new bitcoin.Transaction();
			oldTx.version = 2;
			oldTx.addInput(crypto.randomBytes(32), 0, 0xffffffff);
			oldTx.addOutput(scriptPubkey, 100_000);
			backend.setTransaction(oldTxid, oldTx.toBuffer());

			const spliceTx = new bitcoin.Transaction();
			spliceTx.version = 2;
			spliceTx.addInput(Buffer.from(oldTxid, 'hex').reverse(), 0, 0xfffffffd);
			spliceTx.addOutput(scriptPubkey, 90_000);
			const spliceTxid = spliceTx.getId();
			backend.setTransaction(spliceTxid, spliceTx.toBuffer());

			backend.setHistory(scriptHash, [{ txid: oldTxid, height: 90 }]);
			backend.simulateNewBlock(100);
			// The channel's own funding watch, still on the outpoint the splice
			// will supersede, exactly as it stands before the broadcast.
			await watcher.watchFundingOutput(channelId, oldTxid, 0, 3, scriptPubkey);
			await watcher.watchFundingSpendDuringSplice(
				channelId,
				oldTxid,
				0,
				scriptPubkey,
				spliceTxid
			);
			await new Promise((resolve) => setTimeout(resolve, 50));
			spends = [];
			reported = [];

			// The peer publishes the splice while withholding its own
			// tx_signatures. Both watches sweep the same shared script.
			backend.setHistory(scriptHash, [
				{ txid: oldTxid, height: 90 },
				{ txid: spliceTxid, height: 101 }
			]);
			backend.simulateNewBlock(101);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(
				reportedTxids(),
				'the legitimate splice is not read as a close by either watch'
			).to.deep.equal([]);

			// A revoked pre-splice commitment on the same outpoint still is.
			const breachTxid = publishBreach(oldTxid, scriptHash, 102);
			backend.simulateNewBlock(102);
			await new Promise((resolve) => setTimeout(resolve, 50));
			// Both watches cover this outpoint, so both legitimately see it; the
			// monitor reconciles a repeat of the same transaction.
			expect(
				[...new Set(reportedTxids())],
				'but a different spender of the same outpoint is'
			).to.deep.equal([breachTxid]);
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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
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

		describe('an answer saying the network already has the tx (issue #921)', () => {
			const settle = (): Promise<void> =>
				new Promise((resolve) => setTimeout(resolve, 20));

			function captureOutcomes(): {
				successes: string[];
				failures: Error[];
				permanent: Error[];
			} {
				const out = {
					successes: [] as string[],
					failures: [] as Error[],
					permanent: [] as Error[]
				};
				watcher.on('broadcast:success', (t: string) => out.successes.push(t));
				watcher.on('broadcast:failure', (e: Error) => out.failures.push(e));
				watcher.on('broadcast:permanent_failure', (e: Error) =>
					out.permanent.push(e)
				);
				return out;
			}

			function closeLikeTx(): bitcoin.Transaction {
				const tx = new bitcoin.Transaction();
				tx.addInput(crypto.randomBytes(32), 0);
				tx.addOutput(Buffer.from('0014' + 'ab'.repeat(20), 'hex'), 50_000);
				return tx;
			}

			it('is a success on the first send, not a queued retry', async () => {
				// Core 28+ says this only while an output of the txid is unspent:
				// the close or sweep is mined. Queued, every retry hears the same
				// answer until the watcher reports a permanent failure.
				const sent: string[] = [];
				backend.broadcastTransaction = async (hex: string): Promise<string> => {
					sent.push(hex);
					throw new Error(
						'Failed to broadcast transaction: Transaction outputs already in utxo set'
					);
				};
				const outcomes = captureOutcomes();
				const tx = closeLikeTx();

				channelManager.emit('broadcast:tx', tx.toBuffer());
				await settle();
				expect(outcomes.successes).to.deep.equal([tx.getId()]);
				expect(outcomes.failures).to.have.lengthOf(0);

				for (let height = 100; height <= 112; height++) {
					backend.simulateNewBlock(height);
					await settle();
				}
				expect(sent, 'nothing was queued for a retry').to.have.lengthOf(1);
				expect(outcomes.permanent).to.have.lengthOf(0);
			});

			it('takes a queued retry out of the queue as a success', async () => {
				const sent: string[] = [];
				let answer = 'connection refused';
				backend.broadcastTransaction = async (hex: string): Promise<string> => {
					sent.push(hex);
					throw new Error(answer);
				};
				const outcomes = captureOutcomes();
				const tx = closeLikeTx();

				channelManager.emit('broadcast:tx', tx.toBuffer());
				await settle();
				expect(outcomes.failures).to.have.lengthOf(1);
				expect(outcomes.successes).to.have.lengthOf(0);

				// Mined meanwhile: the first retry hears so and stops there.
				answer = 'Transaction already in block chain';
				backend.simulateNewBlock(100);
				await settle();
				expect(outcomes.successes).to.deep.equal([tx.getId()]);

				for (let height = 101; height <= 113; height++) {
					backend.simulateNewBlock(height);
					await settle();
				}
				expect(sent).to.have.lengthOf(2);
				expect(outcomes.permanent).to.have.lengthOf(0);
			});

			it('still retries a conflicting-input refusal', async () => {
				const sent: string[] = [];
				backend.broadcastTransaction = async (hex: string): Promise<string> => {
					sent.push(hex);
					throw new Error('Input already spent by conflicting transaction');
				};
				const outcomes = captureOutcomes();

				channelManager.emit('broadcast:tx', closeLikeTx().toBuffer());
				await settle();
				backend.simulateNewBlock(100);
				await settle();
				expect(outcomes.successes).to.have.lengthOf(0);
				expect(outcomes.failures).to.have.lengthOf(1);
				expect(sent, 'retried on the next block').to.have.lengthOf(2);
			});
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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
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
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});

			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0,
				// The races below stall a scan re-reading a spend an earlier scan
				// already read. A cached spend is never re-read, so they run as
				// the watcher does once the cache has let it go.
				confirmedTxCacheBytes: 0
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

		it('retries a failed subscription without replacing the active watch', async () => {
			const subscribe = backend.subscribeToScriptHash.bind(backend);
			let attempts = 0;
			backend.subscribeToScriptHash = async (
				scriptHash,
				onChange
			): Promise<void> => {
				attempts++;
				if (attempts === 1) throw new Error('subscription unavailable');
				await subscribe(scriptHash, onChange);
			};
			const watchedTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);
			await watcher.watchOutput(watchedTxid, 0, scriptPubkey);
			const outputs = (
				watcher as unknown as {
					watchedOutputs: Map<string, unknown>;
				}
			).watchedOutputs;
			const key = `${watchedTxid}:0`;
			const registered = outputs.get(key);

			watcher.recheckAllWatches();
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(attempts).to.equal(2);
			expect(outputs.get(key)).to.equal(registered);

			const spendTx = new bitcoin.Transaction();
			spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
			spendTx.addOutput(scriptPubkey, 50000);
			backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: watchedTxid, height: 99 },
				{ txid: spendTx.getId(), height: 100 }
			]);
			let spent = false;
			watcher.on('output:spent', () => {
				spent = true;
			});
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(spent).to.equal(true);
		});

		// A watched output is the only thing that can tell the monitor a spend it
		// recorded has been reorged out, and the monitor keeps taking that news
		// until `tip - confirmationHeight >= IRREVOCABLE_DEPTH` (issue #625).
		describe('finality boundary', () => {
			const SPEND_HEIGHT = 700;

			/** Watch an output that is already spent at SPEND_HEIGHT. */
			async function armSpentOutput(): Promise<{
				watchedTxid: string;
				scriptHash: string;
			}> {
				const watchedTxid = crypto.randomBytes(32).toString('hex');
				const scriptPubkey = Buffer.from(
					'0020' + crypto.randomBytes(32).toString('hex'),
					'hex'
				);
				const scriptHash = computeScriptHash(scriptPubkey);

				const spendTx = new bitcoin.Transaction();
				spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
				spendTx.addOutput(scriptPubkey, 50000);
				backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: SPEND_HEIGHT }
				]);

				await watcher.watchOutput(watchedTxid, 0, scriptPubkey);
				return { watchedTxid, scriptHash };
			}

			/** Run a check and let its two backend fetches settle. */
			async function check(scriptHash: string): Promise<void> {
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 50));
			}

			function watchedOutputCount(): number {
				return (watcher as unknown as { watchedOutputs: Map<string, unknown> })
					.watchedOutputs.size;
			}

			it('keeps the watch until the spend reaches the monitor boundary', async () => {
				const { scriptHash } = await armSpentOutput();

				backend.simulateNewBlock(SPEND_HEIGHT + IRREVOCABLE_DEPTH - 1);
				await check(scriptHash);
				expect(
					watchedOutputCount(),
					'still armed one block short of the boundary'
				).to.equal(1);

				backend.simulateNewBlock(SPEND_HEIGHT + IRREVOCABLE_DEPTH);
				await check(scriptHash);
				expect(
					watchedOutputCount(),
					'retired at the boundary the monitor uses'
				).to.equal(0);
			});

			it('reports a reorg in the last block before the spend is irrevocable', async () => {
				const unspent: Array<{ txid: string; outputIndex: number }> = [];
				(
					channelManager as unknown as {
						handleOutputUnspent: (txid: string, outputIndex: number) => void;
					}
				).handleOutputUnspent = (txid, outputIndex): void => {
					unspent.push({ txid, outputIndex });
				};
				const { watchedTxid, scriptHash } = await armSpentOutput();

				backend.simulateNewBlock(SPEND_HEIGHT + IRREVOCABLE_DEPTH - 1);
				await check(scriptHash);

				// The reorg evicts the spend with one block still to run on the
				// monitor's finality clock. Nothing else re-arms the sweep, so a
				// watch retired here loses a penalty or HTLC claim.
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 }
				]);
				await check(scriptHash);

				expect(
					unspent,
					'the eviction reached the ChannelManager'
				).to.deep.equal([{ txid: watchedTxid, outputIndex: 0 }]);
			});

			it('does not let a stalled scan retire the watch across the boundary', async () => {
				const unspent: Array<{ txid: string; outputIndex: number }> = [];
				(
					channelManager as unknown as {
						handleOutputUnspent: (txid: string, outputIndex: number) => void;
					}
				).handleOutputUnspent = (txid, outputIndex): void => {
					unspent.push({ txid, outputIndex });
				};
				const { watchedTxid, scriptHash } = await armSpentOutput();

				backend.simulateNewBlock(SPEND_HEIGHT + IRREVOCABLE_DEPTH - 1);
				await check(scriptHash);

				// Scan A snapshots the history that still holds the spend, then stalls.
				backend.holdHistory(2);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));

				// The reorg drops the spend and the boundary block lands. The
				// notification invalidates A and queues a fresh scan.
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 }
				]);
				backend.simulateNewBlock(SPEND_HEIGHT + IRREVOCABLE_DEPTH);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));

				backend.releaseNextHistory();
				await new Promise((resolve) => setTimeout(resolve, 20));
				expect(
					watchedOutputCount(),
					'the stalled scan may not retire on a tip its history predates'
				).to.equal(1);

				backend.releaseNextHistory();
				await new Promise((resolve) => setTimeout(resolve, 20));
				expect(
					unspent,
					'so the fresher scan still gets to report the eviction'
				).to.deep.equal([{ txid: watchedTxid, outputIndex: 0 }]);
			});

			it('validates a queued sweep before retiring a stalled scan', async () => {
				const unspent: Array<{ txid: string; outputIndex: number }> = [];
				(
					channelManager as unknown as {
						handleOutputUnspent: (txid: string, outputIndex: number) => void;
					}
				).handleOutputUnspent = (txid, outputIndex): void => {
					unspent.push({ txid, outputIndex });
				};
				const { watchedTxid, scriptHash } = await armSpentOutput();

				backend.simulateNewBlock(SPEND_HEIGHT + IRREVOCABLE_DEPTH - 1);
				await check(scriptHash);
				backend.simulateNewBlock(SPEND_HEIGHT + IRREVOCABLE_DEPTH);
				backend.holdTransactions(1);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));

				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 }
				]);
				watcher.recheckAllWatches();
				backend.releaseNextTransaction();
				await new Promise((resolve) => setTimeout(resolve, 20));

				expect(unspent, 'the queued sweep reports the eviction').to.deep.equal([
					{ txid: watchedTxid, outputIndex: 0 }
				]);
				expect(watchedOutputCount(), 'the reorg watch remains armed').to.equal(
					1
				);
			});
		});

		// Spend checks can arrive while a scan is still fetching. A script hash
		// notification means its history is stale, while a periodic sweep only
		// needs one queued follow-up. Reporting stale evidence can advance the
		// monitor's finality clock too early (issue #621).
		describe('overlapping scans', () => {
			const SPEND_HEIGHT = 100;
			const REMINE_HEIGHT = 190;

			/** Spend heights the ChannelManager was told about, in order. */
			function recordSpends(): number[] {
				const heights: number[] = [];
				(
					channelManager as unknown as {
						handleOutputSpent: (
							txid: string,
							outputIndex: number,
							tx: bitcoin.Transaction,
							height: number
						) => void;
					}
				).handleOutputSpent = (_txid, _outputIndex, _tx, height): void => {
					heights.push(height);
				};
				return heights;
			}

			function recordedSpendHeight(txid: string): number | undefined {
				const outputs = (
					watcher as unknown as {
						watchedOutputs: Map<string, { spendHeight?: number }>;
					}
				).watchedOutputs;
				return outputs.get(`${txid}:0`)?.spendHeight;
			}

			it('reports a spend while recurring sweeps outpace the backend', async () => {
				const heights = recordSpends();
				const watchedTxid = crypto.randomBytes(32).toString('hex');
				const scriptPubkey = Buffer.from(
					'0020' + crypto.randomBytes(32).toString('hex'),
					'hex'
				);
				const scriptHash = computeScriptHash(scriptPubkey);
				const spendTx = new bitcoin.Transaction();
				spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
				spendTx.addOutput(scriptPubkey, 50000);
				backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: SPEND_HEIGHT }
				]);
				await watcher.watchOutput(watchedTxid, 0, scriptPubkey);

				backend.holdHistory(6);
				watcher.recheckAllWatches();
				await new Promise((resolve) => setTimeout(resolve, 20));
				for (let sweep = 0; sweep < 5; sweep++) {
					watcher.recheckAllWatches();
					backend.releaseNextHistory();
					await new Promise((resolve) => setTimeout(resolve, 20));
				}

				const reportsBeforeDrain = [...heights];
				watcher.stop();
				backend.releaseHistory();
				await new Promise((resolve) => setTimeout(resolve, 20));
				expect(
					reportsBeforeDrain,
					'a completed scan reports despite later sweeps'
				).to.deep.equal([SPEND_HEIGHT]);
			});

			it('does not let a stalled scan move a recorded spend height backward', async () => {
				const heights = recordSpends();

				const watchedTxid = crypto.randomBytes(32).toString('hex');
				const scriptPubkey = Buffer.from(
					'0020' + crypto.randomBytes(32).toString('hex'),
					'hex'
				);
				const scriptHash = computeScriptHash(scriptPubkey);
				const spendTx = new bitcoin.Transaction();
				spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
				spendTx.addOutput(scriptPubkey, 50000);
				backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: SPEND_HEIGHT }
				]);

				backend.simulateNewBlock(REMINE_HEIGHT);
				await watcher.watchOutput(watchedTxid, 0, scriptPubkey);

				// Scan A snapshots the spend where it was, then stalls fetching
				// the transaction.
				backend.holdTransactions(1);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));

				// A reorg re-mines the same spend 90 blocks higher. The notification
				// invalidates A and queues a scan against the new history.
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: REMINE_HEIGHT }
				]);
				backend.simulateScriptHashChange(scriptHash);
				backend.releaseNextTransaction();
				await new Promise((resolve) => setTimeout(resolve, 20));

				expect(
					heights,
					'the older scan may not re-date the spend it fetched'
				).to.deep.equal([REMINE_HEIGHT]);
				expect(
					recordedSpendHeight(watchedTxid),
					'and the watch keeps the height the chain actually has'
				).to.equal(REMINE_HEIGHT);
			});

			it('does not let a stalled scan retract a spend a newer scan found', async () => {
				const heights = recordSpends();
				const unspent: Array<{ txid: string; outputIndex: number }> = [];
				(
					channelManager as unknown as {
						handleOutputUnspent: (txid: string, outputIndex: number) => void;
					}
				).handleOutputUnspent = (txid, outputIndex): void => {
					unspent.push({ txid, outputIndex });
				};

				const watchedTxid = crypto.randomBytes(32).toString('hex');
				const scriptPubkey = Buffer.from(
					'0020' + crypto.randomBytes(32).toString('hex'),
					'hex'
				);
				const scriptHash = computeScriptHash(scriptPubkey);
				const spendTx = new bitcoin.Transaction();
				spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
				spendTx.addOutput(scriptPubkey, 50000);
				backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
				// The spend is in the mempool, so scan A's history has no
				// confirmed spender: it is heading for the eviction branch.
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: 0 }
				]);

				backend.simulateNewBlock(SPEND_HEIGHT);
				await watcher.watchOutput(
					watchedTxid,
					0,
					scriptPubkey,
					spendTx.getId(),
					SPEND_HEIGHT
				);

				backend.holdHistory(1);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));

				// The spend confirms. The notification invalidates A and queues a
				// scan against the confirmed history.
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: SPEND_HEIGHT }
				]);
				backend.simulateScriptHashChange(scriptHash);
				backend.releaseNextHistory();
				await new Promise((resolve) => setTimeout(resolve, 20));

				expect(heights, 'the fresh scan reported the spend').to.deep.equal([
					SPEND_HEIGHT
				]);
				expect(
					unspent,
					'the older scan may not retract it afterwards'
				).to.deep.equal([]);
				expect(
					recordedSpendHeight(watchedTxid),
					'so the spend stays recorded'
				).to.equal(SPEND_HEIGHT);
			});

			it('does not let a stalled scan speak while a newer one is still in flight', async () => {
				const heights = recordSpends();

				const watchedTxid = crypto.randomBytes(32).toString('hex');
				const scriptPubkey = Buffer.from(
					'0020' + crypto.randomBytes(32).toString('hex'),
					'hex'
				);
				const scriptHash = computeScriptHash(scriptPubkey);
				const spendTx = new bitcoin.Transaction();
				spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
				spendTx.addOutput(scriptPubkey, 50000);
				backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: REMINE_HEIGHT }
				]);

				backend.simulateNewBlock(REMINE_HEIGHT);
				await watcher.watchOutput(watchedTxid, 0, scriptPubkey);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));
				expect(heights, 'the spend is recorded where it sits').to.deep.equal([
					REMINE_HEIGHT
				]);

				// Scan A snapshots a history that still holds the pre-reorg height,
				// then stalls fetching the transaction.
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: SPEND_HEIGHT }
				]);
				backend.holdTransactions(1);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));

				// The next notification queues B. It stalls after A exits, so A
				// cannot publish before the fresh scan completes.
				backend.setHistory(scriptHash, [
					{ txid: watchedTxid, height: SPEND_HEIGHT - 1 },
					{ txid: spendTx.getId(), height: REMINE_HEIGHT }
				]);
				backend.holdTransactions(1);
				backend.simulateScriptHashChange(scriptHash);
				await new Promise((resolve) => setTimeout(resolve, 20));

				backend.releaseNextTransaction();
				await new Promise((resolve) => setTimeout(resolve, 20));

				// A stale height here is not merely corrected when B lands: the
				// monitor counts finality from it, so a block arriving in between
				// carries the output to IRREVOCABLY_RESOLVED at a depth it never had.
				expect(
					heights,
					'the older scan defers to the one that has not answered yet'
				).to.deep.equal([REMINE_HEIGHT]);
				expect(
					recordedSpendHeight(watchedTxid),
					'and the watch keeps the height the chain actually has'
				).to.equal(REMINE_HEIGHT);

				backend.releaseNextTransaction();
				await new Promise((resolve) => setTimeout(resolve, 20));
				expect(
					recordedSpendHeight(watchedTxid),
					'which is what the newer scan confirms'
				).to.equal(REMINE_HEIGHT);
			});

			// One transaction spending several watched outpoints is the normal
			// shape of a penalty or an aggregated HTLC claim, and the monitor dates
			// EVERY input it spends from whichever report arrives. So the stale
			// member re-dates the whole batch, and the stale member is the newest
			// scan its own outpoint ever had. The monitor's report only reaches
			// outputs it has already recorded against the transaction, though, so
			// silencing that member strands its own outpoint instead.
			describe('batched spends', () => {
				/** Reports the ChannelManager was given, in order. */
				function recordBatchReports(): Array<{
					txid: string;
					outputIndex: number;
					height: number;
				}> {
					const reports: Array<{
						txid: string;
						outputIndex: number;
						height: number;
					}> = [];
					(
						channelManager as unknown as {
							handleOutputSpent: (
								txid: string,
								outputIndex: number,
								tx: bitcoin.Transaction,
								height: number
							) => void;
						}
					).handleOutputSpent = (txid, outputIndex, _tx, height): void => {
						reports.push({ txid, outputIndex, height });
					};
					return reports;
				}

				/**
				 * Watch output 0 of each named parent and spend them all in one
				 * transaction. Two parents is the second shape the monitor draws a
				 * line through: a sweep can batch a commitment output with a
				 * second-level HTLC output, and a report of one never reaches the
				 * other's tracked outputs.
				 */
				async function armBatchedSpend(parents: string[]): Promise<{
					spendTxid: string;
					hashes: string[];
					setSpendHeight: (height: number) => void;
				}> {
					// Repeating a parent means two of ITS outputs are in the batch, so
					// each occurrence takes the next vout of that parent.
					const vouts = parents.map(
						(parent, index) =>
							parents.slice(0, index).filter((other) => other === parent).length
					);
					const scripts = parents.map(() =>
						Buffer.from('0020' + crypto.randomBytes(32).toString('hex'), 'hex')
					);
					const hashes = scripts.map(computeScriptHash);
					const spendTx = new bitcoin.Transaction();
					parents.forEach((parent, index) =>
						spendTx.addInput(Buffer.from(parent, 'hex').reverse(), vouts[index])
					);
					spendTx.addOutput(scripts[0], 90000);
					backend.setTransaction(spendTx.getId(), spendTx.toBuffer());

					const setSpendHeight = (height: number): void => {
						parents.forEach((parent, index) =>
							backend.setHistory(hashes[index], [
								{ txid: parent, height: SPEND_HEIGHT - 1 },
								{ txid: spendTx.getId(), height }
							])
						);
					};
					setSpendHeight(SPEND_HEIGHT);
					for (const [index, parent] of parents.entries()) {
						await watcher.watchOutput(parent, vouts[index], scripts[index]);
					}
					return { spendTxid: spendTx.getId(), hashes, setSpendHeight };
				}

				it('re-checks a stale member rather than let it re-date the batch', async () => {
					const reports = recordBatchReports();
					const parent = crypto.randomBytes(32).toString('hex');
					const { hashes, setSpendHeight } = await armBatchedSpend([
						parent,
						parent
					]);

					// Output 0's scan snapshots the spend where it was, then stalls.
					backend.holdTransactions(1);
					backend.simulateScriptHashChange(hashes[0]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					// The reorg re-mines the batch 90 blocks higher, and output 1's
					// scan reports it while output 0 is still stalled.
					setSpendHeight(REMINE_HEIGHT);
					backend.simulateScriptHashChange(hashes[1]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					backend.releaseNextTransaction();
					await new Promise((resolve) => setTimeout(resolve, 20));

					expect(
						reports.map((report) => report.height),
						'the stale member re-checked instead of re-dating the batch'
					).to.deep.equal([REMINE_HEIGHT, REMINE_HEIGHT]);
					expect(
						reports.map((report) => report.outputIndex),
						'and still reported its own outpoint'
					).to.deep.equal([1, 0]);
				});

				it('re-checks a stale member while the fresher scan is still in flight', async () => {
					const reports = recordBatchReports();
					const parent = crypto.randomBytes(32).toString('hex');
					const { hashes, setSpendHeight } = await armBatchedSpend([
						parent,
						parent
					]);

					// Both scans stall in their transaction fetch, output 0's first.
					backend.holdTransactions(2);
					backend.simulateScriptHashChange(hashes[0]);
					await new Promise((resolve) => setTimeout(resolve, 20));
					setSpendHeight(REMINE_HEIGHT);
					backend.simulateScriptHashChange(hashes[1]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					// Output 0 comes back first, so nothing has recorded the re-mine
					// yet: the only sign its history is stale is the fresher scan
					// still running over the other member.
					backend.releaseNextTransaction();
					await new Promise((resolve) => setTimeout(resolve, 20));

					expect(
						reports,
						'a pending fresher scan is reason enough to re-check'
					).to.deep.equal([
						{ txid: parent, outputIndex: 0, height: REMINE_HEIGHT }
					]);
				});

				it('re-checks a stale member after the fresher one retired', async () => {
					const reports = recordBatchReports();
					const parent = crypto.randomBytes(32).toString('hex');
					const { hashes, setSpendHeight } = await armBatchedSpend([
						parent,
						parent
					]);

					backend.holdTransactions(1);
					backend.simulateScriptHashChange(hashes[0]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					// The re-mine lands deep enough that output 1 reports it and
					// retires, leaving no sibling watch for output 0 to consult.
					setSpendHeight(REMINE_HEIGHT);
					backend.simulateNewBlock(REMINE_HEIGHT + IRREVOCABLE_DEPTH);
					backend.simulateScriptHashChange(hashes[1]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					backend.releaseNextTransaction();
					await new Promise((resolve) => setTimeout(resolve, 20));

					expect(
						reports.map((report) => report.height),
						'a retired sibling still dates the transaction'
					).to.deep.equal([REMINE_HEIGHT, REMINE_HEIGHT]);
				});

				it('re-checks a stale absence rather than retract a fresher spend', async () => {
					const reports = recordBatchReports();
					const unspent: Array<{ txid: string; outputIndex: number }> = [];
					(
						channelManager as unknown as {
							handleOutputUnspent: (txid: string, outputIndex: number) => void;
						}
					).handleOutputUnspent = (txid, outputIndex): void => {
						unspent.push({ txid, outputIndex });
					};
					const parent = crypto.randomBytes(32).toString('hex');
					const { hashes, setSpendHeight } = await armBatchedSpend([
						parent,
						parent
					]);

					// Both members record the spend where it first confirmed.
					backend.simulateScriptHashChange(hashes[0]);
					backend.simulateScriptHashChange(hashes[1]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					// A reorg drops the spend, and output 0's scan snapshots that
					// absence and stalls.
					backend.setHistory(hashes[0], [
						{ txid: parent, height: SPEND_HEIGHT - 1 }
					]);
					backend.holdHistory(1);
					backend.simulateScriptHashChange(hashes[0]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					// The spend is re-mined and output 1 reports it.
					setSpendHeight(REMINE_HEIGHT);
					backend.simulateScriptHashChange(hashes[1]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					backend.releaseNextHistory();
					await new Promise((resolve) => setTimeout(resolve, 20));

					expect(
						unspent,
						'a stale absence may not reopen a spend a fresher scan proved'
					).to.deep.equal([]);
					expect(
						reports.filter((report) => report.height === REMINE_HEIGHT).length,
						'both members ended on the re-mined height'
					).to.equal(2);
				});

				it('re-checks a stale member of a batch spanning two parents', async () => {
					const reports = recordBatchReports();
					const parents = [
						crypto.randomBytes(32).toString('hex'),
						crypto.randomBytes(32).toString('hex')
					];
					const { hashes, setSpendHeight } = await armBatchedSpend(parents);

					backend.holdTransactions(1);
					backend.simulateScriptHashChange(hashes[0]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					setSpendHeight(REMINE_HEIGHT);
					backend.simulateScriptHashChange(hashes[1]);
					await new Promise((resolve) => setTimeout(resolve, 20));

					backend.releaseNextTransaction();
					await new Promise((resolve) => setTimeout(resolve, 20));

					// The second parent's report never reached the first parent's
					// tracked outputs, so the first parent has to speak for itself,
					// with the height the transaction actually sits at.
					expect(
						reports,
						'the other parent is corrected, not silenced'
					).to.deep.equal([
						{ txid: parents[1], outputIndex: 0, height: REMINE_HEIGHT },
						{ txid: parents[0], outputIndex: 0, height: REMINE_HEIGHT }
					]);
					expect(recordedSpendHeight(parents[0])).to.equal(REMINE_HEIGHT);
				});
			});
		});

		// A spend the chain no longer has must not be reported as current: the
		// monitor would count finality against it and eventually retire the
		// watch, and nothing else re-broadcasts the claim (issue #624).
		it('a scan stalled reading the spending tx cannot revive it after a reorg', async () => {
			const events: string[] = [];
			watcher.on('output:spent', () => events.push('spent'));
			watcher.on('output:unspent', () => events.push('unspent'));

			const watchedTxid = crypto.randomBytes(32).toString('hex');
			const scriptPubkey = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const scriptHash = computeScriptHash(scriptPubkey);
			const spendTx = new bitcoin.Transaction();
			spendTx.addInput(Buffer.from(watchedTxid, 'hex').reverse(), 0);
			spendTx.addOutput(scriptPubkey, 50000);
			backend.setTransaction(spendTx.getId(), spendTx.toBuffer());
			backend.setHistory(scriptHash, [
				{ txid: watchedTxid, height: 100 },
				{ txid: spendTx.getId(), height: 101 }
			]);
			backend.simulateNewBlock(101);

			await watcher.watchOutput(watchedTxid, 0, scriptPubkey);
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(events, 'the spend is reported').to.deep.equal(['spent']);

			// Scan A snapshots the history that still holds the spend and stalls
			// reading the spending transaction.
			backend.holdTransactions(1);
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 20));

			// The reorg evicts it. The notification is news that the history moved,
			// so it invalidates scan A and queues a scan against the new history.
			// Scans of one outpoint run one at a time (issue #621), so nothing is
			// published while A is still parked.
			backend.setHistory(scriptHash, [{ txid: watchedTxid, height: 100 }]);
			backend.simulateScriptHashChange(scriptHash);
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(events, 'the stalled scan publishes nothing').to.deep.equal([
				'spent'
			]);

			// A resumes, finds itself answered for and exits without reviving the
			// spend it was holding, and the queued scan reports the eviction.
			backend.releaseNextTransaction();
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(events, 'the eviction is reported').to.deep.equal([
				'spent',
				'unspent'
			]);
			const held = (
				watcher as unknown as {
					watchedOutputs: Map<string, { spendTxid?: string }>;
				}
			).watchedOutputs.get(`${watchedTxid}:0`)!;
			expect(held.spendTxid, 'the watch still reads unspent').to.equal(
				undefined
			);
		});
	});

	// Every block and every recheck re-reads each watched script's history,
	// but a confirmed transaction it names is downloaded once (issue #1678).
	describe('Confirmed transaction cache (issue #1678)', () => {
		const CLOSE_SCRIPT = Buffer.from('0014' + '22'.repeat(20), 'hex');
		let backend: MockChainBackend;
		let channelManager: ChannelManager;
		let watcher: ChainWatcher;
		let closes: string[];

		beforeEach(() => {
			const seed = crypto.randomBytes(32);
			backend = new MockChainBackend();
			channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(seed),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32),
				persistence: COMMIT_ALL
			});
			channelManager.on('error', () => {});
			closes = [];
		});

		afterEach(() => {
			watcher.stop();
		});

		async function startWatcher(confirmedTxCacheBytes?: number): Promise<void> {
			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0,
				confirmedTxCacheBytes
			});
			watcher.on('funding:spent', (_cid: Buffer, tx: bitcoin.Transaction) =>
				closes.push(tx.getId())
			);
			await watcher.start();
		}

		function settle(): Promise<void> {
			return new Promise((resolve) => setTimeout(resolve, 20));
		}

		function reads(txid: string): number {
			return backend.transactionReads.get(txid) ?? 0;
		}

		function randomScript(): Buffer {
			return Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
		}

		/** A transaction spending `prevTxid`:0 into `script`, served by the backend. */
		function spendOf(prevTxid: string, script: Buffer): bitcoin.Transaction {
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(Buffer.from(prevTxid, 'hex').reverse(), 0, 0xffffffff);
			tx.addOutput(script, 100_000);
			backend.setTransaction(tx.getId(), tx.toBuffer());
			return tx;
		}

		/**
		 * A channel spliced twice, watched on the second splice's output. The
		 * funding script's history holds three confirmed entries, and the two
		 * the watch is not on are what every spend scan has to read.
		 */
		async function armSplicedChannel(): Promise<{
			scriptHash: string;
			history: Array<{ txid: string; height: number }>;
			spliceTxid: string;
		}> {
			const script = randomScript();
			const scriptHash = computeScriptHash(script);
			const funding = spendOf(crypto.randomBytes(32).toString('hex'), script);
			const firstSplice = spendOf(funding.getId(), script);
			const secondSplice = spendOf(firstSplice.getId(), script);
			const history = [
				{ txid: funding.getId(), height: 90 },
				{ txid: firstSplice.getId(), height: 95 },
				{ txid: secondSplice.getId(), height: 98 }
			];
			backend.setHistory(scriptHash, history);
			backend.simulateNewBlock(100);
			await watcher.watchFundingOutput(
				crypto.randomBytes(32),
				secondSplice.getId(),
				0,
				3,
				script
			);
			await settle();
			return { scriptHash, history, spliceTxid: secondSplice.getId() };
		}

		it('reads the earlier splices of a channel once across blocks and rechecks', async () => {
			await startWatcher();
			const { history, spliceTxid } = await armSplicedChannel();

			for (let height = 101; height <= 105; height++) {
				backend.simulateNewBlock(height);
				watcher.recheckAllWatches();
				await settle();
			}

			expect(
				history.slice(0, 2).map(({ txid }) => reads(txid)),
				'five blocks and five rechecks read each earlier splice once'
			).to.deep.equal([1, 1]);
			expect(
				reads(spliceTxid),
				'the watched transaction is never read'
			).to.equal(0);
			expect(closes).to.deep.equal([]);
		});

		it('still finds a close on the next block, and reads it once', async () => {
			await startWatcher();
			const { scriptHash, history, spliceTxid } = await armSplicedChannel();

			const close = spendOf(spliceTxid, CLOSE_SCRIPT);
			backend.setHistory(scriptHash, [
				...history,
				{ txid: close.getId(), height: 101 }
			]);
			backend.simulateNewBlock(101);
			await settle();
			expect(closes, 'the next block found the close').to.deep.equal([
				close.getId()
			]);

			for (let height = 102; height <= 105; height++) {
				backend.simulateNewBlock(height);
				await settle();
			}
			expect(reads(close.getId())).to.equal(1);
		});

		it('reads a mempool spender again on every scan until it confirms', async () => {
			await startWatcher();
			const { scriptHash, history, spliceTxid } = await armSplicedChannel();

			const close = spendOf(spliceTxid, CLOSE_SCRIPT);
			backend.setHistory(scriptHash, [
				...history,
				{ txid: close.getId(), height: 0 }
			]);
			for (let height = 101; height <= 103; height++) {
				backend.simulateNewBlock(height);
				await settle();
			}
			expect(
				reads(close.getId()),
				'one read per block in the mempool'
			).to.equal(3);

			backend.setHistory(scriptHash, [
				...history,
				{ txid: close.getId(), height: 104 }
			]);
			for (let height = 104; height <= 106; height++) {
				backend.simulateNewBlock(height);
				await settle();
			}
			expect(reads(close.getId()), 'and one more once confirmed').to.equal(4);
		});

		it('does not keep bytes that do not hash to the txid asked for', async () => {
			await startWatcher();
			const { scriptHash, history } = await armSplicedChannel();

			const unrelated = new bitcoin.Transaction();
			unrelated.addInput(crypto.randomBytes(32), 0);
			unrelated.addOutput(CLOSE_SCRIPT, 1_000);
			const named = crypto.randomBytes(32).toString('hex');
			backend.setTransaction(named, unrelated.toBuffer());
			backend.setHistory(scriptHash, [
				...history,
				{ txid: named, height: 101 }
			]);

			for (let height = 101; height <= 103; height++) {
				backend.simulateNewBlock(height);
				await settle();
			}
			expect(reads(named), 'asked again on every block').to.equal(3);
		});

		it('lets the least recently used transaction go once the budget is full', async () => {
			const script = randomScript();
			const scriptHash = computeScriptHash(script);
			const watched = crypto.randomBytes(32).toString('hex');
			// Same shape, so the same size: the budget holds exactly two.
			const txs = [0, 1, 2].map(() =>
				spendOf(crypto.randomBytes(32).toString('hex'), script)
			);
			const [a, b, c] = txs.map((tx) => tx.getId());
			await startWatcher(2 * txs[0].byteLength());

			backend.setHistory(scriptHash, [
				{ txid: watched, height: 98 },
				{ txid: a, height: 99 },
				{ txid: b, height: 99 }
			]);
			backend.simulateNewBlock(100);
			await watcher.watchFundingOutput(
				crypto.randomBytes(32),
				watched,
				0,
				1,
				script
			);
			await settle();

			// c pushes out a, which this scan no longer touches.
			backend.setHistory(scriptHash, [
				{ txid: watched, height: 98 },
				{ txid: b, height: 99 },
				{ txid: c, height: 101 }
			]);
			backend.simulateNewBlock(101);
			await settle();
			backend.simulateNewBlock(102);
			await settle();
			expect([a, b, c].map(reads), 'b and c stay held').to.deep.equal([
				1, 1, 1
			]);

			backend.setHistory(scriptHash, [
				{ txid: watched, height: 98 },
				{ txid: a, height: 99 }
			]);
			backend.simulateNewBlock(103);
			await settle();
			expect(reads(a), 'a was let go').to.equal(2);
		});

		it("reads a watched output's spender once while the watch waits for finality", async () => {
			await startWatcher();
			const script = randomScript();
			const scriptHash = computeScriptHash(script);
			const parent = crypto.randomBytes(32).toString('hex');
			// Address reuse puts a stranger in the history ahead of the spend.
			const stranger = spendOf(crypto.randomBytes(32).toString('hex'), script);
			const spend = spendOf(parent, CLOSE_SCRIPT);
			backend.setHistory(scriptHash, [
				{ txid: parent, height: 99 },
				{ txid: stranger.getId(), height: 100 },
				{ txid: spend.getId(), height: 101 }
			]);
			backend.simulateNewBlock(102);
			await watcher.watchOutput(parent, 0, script);

			for (let sweep = 0; sweep < 5; sweep++) {
				watcher.recheckAllWatches();
				await settle();
			}
			expect([stranger.getId(), spend.getId()].map(reads)).to.deep.equal([
				1, 1
			]);
		});
	});

	describe('LightningNode integration', () => {
		// The first require of lightning-node transpiles its whole import graph
		// under ts-node: 3 to 11 s measured at a load average of 11 to 25, and
		// past the 20 s suite timeout under heavier load, unless an earlier file
		// in the same mocha worker already loaded it. Paid once here on its own
		// budget rather than inside whichever test runs first (issue #947).
		before(function (): void {
			this.timeout(120_000);
			require('../../src/lightning/node/lightning-node');
		});

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

		it('restoreChainWatches re-arms a pre-splice spend watch after the splice locked (issue #479)', async () => {
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

			// The shape a zero-conf splice leaves behind: splice_locked went out
			// in the same action batch as the broadcast, so completeSplice has
			// already moved fundingTxid to the new outpoint and cleared
			// spliceInFlight, while the splice transaction is still only in the
			// mempool. The old outpoint remains spendable by a revoked
			// pre-splice commitment, and spliceInFlight can no longer tell the
			// next start that.
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.state = ChannelState.NORMAL;
			state.channelId = crypto.randomBytes(32);
			state.fundingTxid = crypto.randomBytes(32);
			state.fundingOutputIndex = 0;
			state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
			state.spliceInFlight = null;
			const supersededTxid = crypto.randomBytes(32).toString('hex');
			const spliceTxid = crypto.randomBytes(32).toString('hex');
			// The leg carries its OWN script: a splice can rotate the peer's
			// funding pubkey, so the channel's current funding script may hash
			// to something the superseded output never paid.
			const legScript = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			state.preSpliceSpendWatches = [
				{
					txid: supersededTxid,
					outputIndex: 1,
					script: legScript.toString('hex'),
					spliceTxid
				}
			];
			const channel = new Channel(state);
			node.getChannelManager().restoreChannel(channel, 'cafe'.repeat(16));

			await node.restoreChainWatches();

			const watcher = node.getChainWatcher()!;
			const watched = (watcher as any).watchedFundings as Map<string, unknown>;
			const legKey = `${state.channelId.toString(
				'hex'
			)}:presplice:${supersededTxid}:1`;
			expect(watched.has(legKey), 'the superseded outpoint is watched again').to
				.be.true;
			expect(
				(watched.get(legKey) as { scriptHash: string }).scriptHash,
				'armed against the recorded script, not the channel current one'
			).to.equal(computeScriptHash(legScript));
			node.destroy();
		});

		it('restoreChainWatches never leaves a signed-splice channel without an old-outpoint watch (issue #479)', async () => {
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

			// The crash shape: our splice tx_signatures left, so the peer can
			// complete and broadcast, but no leg was ever recorded (a row
			// written before the field existed, or any path that reaches the
			// point of no return without one). Restoration must not come back
			// watching only an outpoint that does not exist yet.
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.state = ChannelState.SPLICING;
			state.channelId = crypto.randomBytes(32);
			state.fundingTxid = crypto.randomBytes(32);
			state.fundingOutputIndex = 0;
			state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
			state.preSpliceSpendWatches = undefined;
			const spliceTx = new bitcoin.Transaction();
			spliceTx.version = 2;
			spliceTx.addInput(Buffer.from(state.fundingTxid), 0, 0xffffffff);
			spliceTx.addOutput(
				Buffer.from('0020' + '55'.repeat(32), 'hex'),
				1_000_000
			);
			state.spliceInFlight = {
				spliceTxid: Buffer.from(spliceTx.getId(), 'hex').reverse(),
				newFundingOutputIndex: 0,
				newFundingSatoshis: 1_000_000n,
				spliceTxHex: spliceTx.toHex(),
				fullySigned: false,
				isInitiator: true,
				localRelativeSatoshis: 0n,
				remoteRelativeSatoshis: 0n,
				remoteFundingPubkey: getPublicKey(crypto.randomBytes(32)),
				ourSharedInputSig: Buffer.alloc(64),
				ourWalletWitnesses: [],
				ourWalletInputIndices: [],
				inputPrevouts: [],
				remoteCommitmentSig: crypto.randomBytes(64),
				sentTxSignatures: true,
				receivedTxSignatures: false,
				localSpliceLocked: false,
				remoteSpliceLocked: false,
				confirmed: false
			};
			node
				.getChannelManager()
				.restoreChannel(new Channel(state), 'cafe'.repeat(16));

			await node.restoreChainWatches();

			const watched = (
				node.getChainWatcher()! as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			const oldTxid = Buffer.from(state.fundingTxid).reverse().toString('hex');
			expect(
				watched.has(
					`${state.channelId.toString('hex')}:presplice:${oldTxid}:0`
				),
				'the superseded outpoint is watched'
			).to.be.true;
		});

		it('arms a pre-splice leg when the node has restarted its chain watcher (issue #479 review)', async () => {
			// The node and the watcher keep SEPARATE generation counters, and
			// both are plain numbers. restoreChainWatches used to hand the
			// watcher its own, and ChainWatcher.start() early-returns when it is
			// already started, so the ordinary "auto-start, then start
			// explicitly" sequence left the node on 2 and the watcher on 1. The
			// arm then returned before it registered anything: no entry, no
			// error, and nothing for the recheck timer to recover.
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

			const basepoints = makeBasepoints(crypto.randomBytes(32));
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
			// Let the constructor's auto-start finish before adding the channel,
			// so the explicit start below is the one that sees it.
			await new Promise((resolve) => setTimeout(resolve, 30));

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.state = ChannelState.NORMAL;
			state.channelId = crypto.randomBytes(32);
			state.fundingTxid = crypto.randomBytes(32);
			state.fundingOutputIndex = 0;
			state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
			state.spliceInFlight = null;
			const supersededTxid = crypto.randomBytes(32).toString('hex');
			const legScript = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			state.preSpliceSpendWatches = [
				{
					txid: supersededTxid,
					outputIndex: 3,
					script: legScript.toString('hex'),
					spliceTxid: crypto.randomBytes(32).toString('hex')
				}
			];
			node
				.getChannelManager()
				.restoreChannel(new Channel(state), 'cafe'.repeat(16));

			// The second start: node generation 2, watcher generation still 1.
			await node.startChainWatcher();

			const nodeGeneration = (
				node as unknown as {
					chainStartupGeneration: number;
				}
			).chainStartupGeneration;
			const watcher = node.getChainWatcher()!;
			const watcherGeneration = (
				watcher as unknown as {
					lifecycleGeneration: number;
				}
			).lifecycleGeneration;
			expect(
				nodeGeneration,
				'the two counters have diverged, which is the whole point'
			).to.not.equal(watcherGeneration);

			const watched = (
				watcher as unknown as { watchedFundings: Map<string, unknown> }
			).watchedFundings;
			expect(
				watched.has(
					`${state.channelId.toString('hex')}:presplice:${supersededTxid}:3`
				),
				'the leg is armed regardless of the node counter'
			).to.be.true;
			node.destroy();
		});

		it('records a derived pre-splice leg durably, so the next restart is not blind (issue #479)', async () => {
			// A row that was mid-splice when the node upgraded carries the leg
			// nowhere but spliceInFlight. Arming from it without WRITING it back
			// only lasts until completeSplice clears that record, which on a
			// zero-conf channel happens before the splice confirms.
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
			const {
				serializeChannelState,
				deserializeChannelState
			} = require('../../src/lightning/storage/serialization');
			const {
				createFundingScript
			} = require('../../src/lightning/script/funding');

			const basepoints = makeBasepoints(crypto.randomBytes(32));
			const makeNode = (): any =>
				new LightningNode({
					nodePrivateKey: crypto.randomBytes(32),
					channelBasepoints: basepoints,
					perCommitmentSeed: crypto.randomBytes(32),
					fundingPrivkey: crypto.randomBytes(32),
					chainBackend: {
						subscribeToHeaders: async () => {},
						subscribeToScriptHash: async () => {},
						getScriptHashHistory: async () => [],
						getTransaction: async () => Buffer.alloc(0),
						broadcastTransaction: async () => ''
					} as IChainBackend
				});

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.state = ChannelState.SPLICING;
			state.channelId = crypto.randomBytes(32);
			state.fundingTxid = crypto.randomBytes(32);
			state.fundingOutputIndex = 2;
			state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
			state.preSpliceSpendWatches = undefined;
			const spliceTx = new bitcoin.Transaction();
			spliceTx.version = 2;
			spliceTx.addInput(Buffer.from(state.fundingTxid), 2, 0xffffffff);
			spliceTx.addOutput(
				Buffer.from('0020' + '77'.repeat(32), 'hex'),
				1_000_000
			);
			const spliceTxid = Buffer.from(spliceTx.getId(), 'hex').reverse();
			state.spliceInFlight = {
				spliceTxid,
				newFundingOutputIndex: 0,
				newFundingSatoshis: 1_000_000n,
				spliceTxHex: spliceTx.toHex(),
				fullySigned: false,
				isInitiator: true,
				localRelativeSatoshis: 0n,
				remoteRelativeSatoshis: 0n,
				// Rotated, so recomputing the script later would be wrong.
				remoteFundingPubkey: getPublicKey(crypto.randomBytes(32)),
				ourSharedInputSig: Buffer.alloc(64),
				ourWalletWitnesses: [],
				ourWalletInputIndices: [],
				inputPrevouts: [],
				remoteCommitmentSig: crypto.randomBytes(64),
				sentTxSignatures: true,
				receivedTxSignatures: false,
				localSpliceLocked: false,
				remoteSpliceLocked: false,
				confirmed: false
			};

			const first = makeNode();
			const channel = new Channel(state);
			first.getChannelManager().restoreChannel(channel, 'cafe'.repeat(16));
			await first.restoreChainWatches();

			const legs = channel.getFullState().preSpliceSpendWatches ?? [];
			expect(
				legs,
				'the derived leg was written back, not just armed'
			).to.have.length(1);
			const supersededTxid = Buffer.from(state.fundingTxid)
				.reverse()
				.toString('hex');
			expect(legs[0].txid).to.equal(supersededTxid);
			expect(legs[0].outputIndex).to.equal(2);
			expect(legs[0].spliceTxid).to.equal(
				Buffer.from(spliceTxid).reverse().toString('hex')
			);
			// The PRE-splice script, from the peer's pre-splice funding key.
			expect(legs[0].script).to.equal(
				(
					createFundingScript(
						state.localBasepoints.fundingPubkey,
						state.remoteBasepoints.fundingPubkey
					).p2wshOutput as Buffer
				).toString('hex')
			);
			first.destroy();

			// The zero-conf adoption: splice_locked went out in the same batch
			// as the broadcast, so spliceInFlight is gone while the splice tx is
			// still unconfirmed. Only the persisted record can re-arm the watch.
			const revived = deserializeChannelState(
				serializeChannelState(channel.getFullState())
			);
			revived.spliceInFlight = null;

			const second = makeNode();
			second
				.getChannelManager()
				.restoreChannel(new Channel(revived), 'cafe'.repeat(16));
			await second.restoreChainWatches();
			const watched = (
				second.getChainWatcher()! as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			expect(
				watched.has(
					`${state.channelId.toString('hex')}:presplice:${supersededTxid}:2`
				),
				'the leg survives the record that derived it'
			).to.be.true;
			second.destroy();
		});

		it('a leg whose history cannot be fetched does not abort the rest of the restore (issue #479)', async () => {
			// One transient Electrum error used to propagate out of the arm,
			// out of the channel loop and out of restoreChainWatches, taking
			// every later channel's watch, the pending-broadcast retries and the
			// reconnect monitor with it. None of those is retried anywhere.
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

			const basepoints = makeBasepoints(crypto.randomBytes(32));
			const legScript = Buffer.from(
				'0020' + crypto.randomBytes(32).toString('hex'),
				'hex'
			);
			const poisoned = computeScriptHash(legScript);
			const mockBackend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async (scriptHash: string) => {
					if (scriptHash === poisoned) throw new Error('electrum down');
					return [];
				},
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
			node.on('node:error', () => {});

			const makeChannel = (withLeg: boolean): any => {
				const state = createOpenerState({
					temporaryChannelId: crypto.randomBytes(32),
					fundingSatoshis: 100_000n,
					pushMsat: 0n,
					localConfig: DEFAULT_CHANNEL_CONFIG,
					localBasepoints: basepoints,
					localPerCommitmentSeed: crypto.randomBytes(32)
				});
				state.state = ChannelState.NORMAL;
				state.channelId = crypto.randomBytes(32);
				state.fundingTxid = crypto.randomBytes(32);
				state.fundingOutputIndex = 0;
				state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
				state.spliceInFlight = null;
				if (withLeg) {
					state.preSpliceSpendWatches = [
						{
							txid: crypto.randomBytes(32).toString('hex'),
							outputIndex: 0,
							script: legScript.toString('hex'),
							spliceTxid: crypto.randomBytes(32).toString('hex')
						}
					];
				}
				return new Channel(state);
			};

			// listChannels() preserves insertion order, so the poisoned channel
			// is restored first and the healthy one after it.
			const poisonedChannel = makeChannel(true);
			const laterChannel = makeChannel(false);
			node
				.getChannelManager()
				.restoreChannel(poisonedChannel, 'cafe'.repeat(16));
			node.getChannelManager().restoreChannel(laterChannel, 'beef'.repeat(16));

			await node.restoreChainWatches();

			const watched = (
				node.getChainWatcher()! as unknown as {
					watchedFundings: Map<string, unknown>;
				}
			).watchedFundings;
			expect(
				watched.has(poisonedChannel.getFullState().channelId.toString('hex')),
				'the poisoned channel still gets its own funding watch'
			).to.be.true;
			expect(
				watched.has(laterChannel.getFullState().channelId.toString('hex')),
				'and every later channel is still restored'
			).to.be.true;
			node.destroy();
		});

		it('keeps the old funding watched while a splice is still unsigned (issue #479)', async () => {
			// The shared input is the 2-of-2 funding, so until OUR tx_signatures
			// have left nobody can broadcast that splice: the outpoint it would
			// create does not exist, and the live funding is still the old one.
			// Moving the watch there anyway left the old output covered by
			// nothing at all - no leg is recorded before this point either,
			// because such a splice can still be aborted - so a commitment
			// spending the funding that DOES exist went unseen.
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

			const basepoints = makeBasepoints(crypto.randomBytes(32));
			const node = new LightningNode({
				nodePrivateKey: crypto.randomBytes(32),
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: crypto.randomBytes(32),
				chainBackend: {
					subscribeToHeaders: async () => {},
					subscribeToScriptHash: async () => {},
					getScriptHashHistory: async () => [],
					getTransaction: async () => Buffer.alloc(0),
					broadcastTransaction: async () => ''
				} as IChainBackend
			});

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});
			state.state = ChannelState.SPLICING;
			state.channelId = crypto.randomBytes(32);
			state.fundingTxid = crypto.randomBytes(32);
			state.fundingOutputIndex = 1;
			state.remoteBasepoints = makeBasepoints(crypto.randomBytes(32));
			state.preSpliceSpendWatches = undefined;
			const spliceTx = new bitcoin.Transaction();
			spliceTx.version = 2;
			spliceTx.addInput(Buffer.from(state.fundingTxid), 1, 0xfffffffd);
			spliceTx.addOutput(
				Buffer.from('0020' + '44'.repeat(32), 'hex'),
				1_000_000
			);
			state.spliceInFlight = {
				spliceTxid: Buffer.from(spliceTx.getId(), 'hex').reverse(),
				newFundingOutputIndex: 0,
				newFundingSatoshis: 1_000_000n,
				spliceTxHex: spliceTx.toHex(),
				fullySigned: false,
				isInitiator: true,
				localRelativeSatoshis: 0n,
				remoteRelativeSatoshis: 0n,
				remoteFundingPubkey: getPublicKey(crypto.randomBytes(32)),
				ourSharedInputSig: Buffer.alloc(64),
				ourWalletWitnesses: [],
				ourWalletInputIndices: [],
				inputPrevouts: [],
				remoteCommitmentSig: crypto.randomBytes(64),
				// The point of no return has NOT been reached.
				sentTxSignatures: false,
				receivedTxSignatures: false,
				localSpliceLocked: false,
				remoteSpliceLocked: false,
				confirmed: false
			};
			node
				.getChannelManager()
				.restoreChannel(new Channel(state), 'cafe'.repeat(16));

			await node.restoreChainWatches();

			const watched = (
				node.getChainWatcher()! as unknown as {
					watchedFundings: Map<string, { txid: string }>;
				}
			).watchedFundings;
			const oldTxid = Buffer.from(state.fundingTxid).reverse().toString('hex');
			const primary = watched.get(state.channelId.toString('hex'));
			expect(primary, 'the channel still has a funding watch').to.not.equal(
				undefined
			);
			expect(
				primary!.txid,
				'and it is still on the funding that actually exists'
			).to.equal(oldTxid);
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
