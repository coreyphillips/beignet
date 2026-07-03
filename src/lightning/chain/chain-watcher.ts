/**
 * BOLT 5: Chain Watcher — bridges an Electrum-compatible chain backend
 * to the ChannelManager's event-driven chain monitoring.
 *
 * Subscribes to blockchain events (new blocks, funding confirmations,
 * output spends) and translates them into ChannelManager calls.
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ChannelManager } from '../channel/channel-manager';
import { createFundingScript } from '../script/funding';

bitcoin.initEccLib(ecc);

/**
 * Abstract chain backend interface. Can be backed by Electrum, Esplora, etc.
 */
export interface IChainBackend {
	/** Subscribe to new block headers. Callback receives block height. */
	subscribeToHeaders(onNewBlock: (height: number) => void): Promise<void>;
	/** Subscribe to activity on a script hash. Callback fires when status changes. */
	subscribeToScriptHash(
		scriptHash: string,
		onChange: () => void
	): Promise<void>;
	/** Get transaction history for a script hash. Returns array of {txid, height}. height=0 means unconfirmed. */
	getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>>;
	/** Get a raw transaction by txid. Returns the raw transaction buffer. */
	getTransaction(txid: string): Promise<Buffer>;
	/** Broadcast a raw transaction hex. Returns txid on success. */
	broadcastTransaction(rawTxHex: string): Promise<string>;
	/** Get transaction position in a block. Returns { blockHeight, txIndex }. Optional — returns null if not supported. */
	getTransactionMerkleProof?(
		txid: string,
		height: number
	): Promise<{ blockHeight: number; txIndex: number }>;
}

/** A funding output being watched for confirmation */
interface IWatchedFunding {
	channelId: Buffer;
	txid: string; // hex, internal (reversed) byte order
	outputIndex: number;
	minimumDepth: number;
	scriptHash: string;
	confirmed: boolean;
	confirmationHeight: number;
	announcementTriggered: boolean;
	/**
	 * FFOR M7.2: when set, this outpoint belongs to an EMBEDDED-TOWER epoch (an
	 * external channel, not one of the node's own). A spend routes to the tower
	 * breach classifier (channelManager.fforHandleTowerSpend), NOT the node's
	 * own channel force-close path.
	 */
	towerEpochId?: Buffer;
}

/** A generic output being watched for spends */
interface IWatchedOutput {
	txid: string;
	outputIndex: number;
	scriptHash: string;
	/**
	 * The spend we last reported to the monitor, if any. The watch is retained after
	 * a spend (not deleted) so a reorg that evicts the spend re-fires the scripthash
	 * subscription and is detected here; these record what we last saw so we can tell
	 * an idempotent re-fire from a genuine eviction.
	 */
	spendTxid?: string;
	spendHeight?: number;
}

/**
 * Confirmations after which a spend is treated as irreversible and its watch may be
 * torn down. A reorg deeper than this is out of scope for any practical LN threat
 * model (matches the monitor's IRREVOCABLY_RESOLVED depth).
 */
const SPEND_FINALITY_DEPTH = 100;

export interface IChainWatcherConfig {
	backend: IChainBackend;
	channelManager: ChannelManager;
	/** Destination script for sweep outputs (P2WPKH). Falls back to zeros if not set. */
	destinationScript?: Buffer;
	/**
	 * Live sat/vB feerate for sweeps built when a funding spend (remote
	 * force-close / breach) is detected. Without it every sweep and penalty tx
	 * on this path is built at the hardcoded 10 sat/vB default and can sit
	 * below the market rate while the cheater's to_self_delay matures.
	 */
	getSweepFeeRatePerVbyte?: () => number;
}

/**
 * Compute the Electrum-style script hash for a given scriptPubkey.
 * SHA256(scriptPubkey) with bytes reversed (little-endian hex).
 */
export function computeScriptHash(scriptPubkey: Buffer): string {
	const hash = crypto.createHash('sha256').update(scriptPubkey).digest();
	return Buffer.from(hash).reverse().toString('hex');
}

/**
 * Watches the blockchain for funding confirmations, output spends,
 * and new blocks, bridging these events to the ChannelManager.
 *
 * Events:
 * - 'funding:confirmed' (channelId: Buffer)
 * - 'funding:spent' (channelId: Buffer, spendingTx: Transaction)
 * - 'broadcast:success' (txid: string)
 * - 'broadcast:failure' (error: Error)
 * - 'error' (error: Error)
 */
/** A failed funding watch queued for retry */
interface IFailedFundingWatch {
	channelId: Buffer;
	txid: string;
	outputIndex: number;
	minimumDepth: number;
	scriptPubkey: Buffer;
}

/** A failed output watch queued for retry */
interface IFailedOutputWatch {
	txid: string;
	outputIndex: number;
	scriptPubkey: Buffer;
}

/** A failed broadcast queued for retry */
interface IFailedBroadcast {
	rawTx: Buffer;
	txidHex: string;
	retryCount: number;
}

/** Maximum number of blocks to retry a failed broadcast before emitting permanent failure */
const MAX_BROADCAST_RETRIES = 12;

/**
 * Safety-net re-check interval. New-block events drive confirmation detection,
 * but they only fire ~every 10 min and can be missed entirely if the header /
 * script-hash subscriptions failed to establish during an Electrum outage. This
 * timer re-checks watched funding outputs (and retries failed subscriptions)
 * independently of the subscription state, so a channel whose funding confirmed
 * while we were disconnected self-heals to NORMAL within this window.
 */
const RECHECK_INTERVAL_MS = 60_000;

export class ChainWatcher extends EventEmitter {
	private backend: IChainBackend;
	private channelManager: ChannelManager;
	private watchedFundings: Map<string, IWatchedFunding> = new Map(); // channelIdHex → funding
	private watchedOutputs: Map<string, IWatchedOutput> = new Map(); // "txid:vout" → output
	private failedFundingWatches: IFailedFundingWatch[] = [];
	private failedOutputWatches: IFailedOutputWatch[] = [];
	private failedBroadcasts: IFailedBroadcast[] = [];
	private currentBlockHeight = 0;
	private started = false;
	private destinationScript: Buffer;
	private getSweepFeeRatePerVbyte?: () => number;
	private _recheckTimer: ReturnType<typeof setInterval> | null = null;

	constructor(config: IChainWatcherConfig) {
		super();
		this.backend = config.backend;
		this.channelManager = config.channelManager;
		this.destinationScript = config.destinationScript || Buffer.alloc(22);
		this.getSweepFeeRatePerVbyte = config.getSweepFeeRatePerVbyte;

		this.wireChannelManagerEvents();
	}

	/**
	 * Update the destination script used when a force-close is detected and a
	 * new monitor is created. Lets the node redirect sweeps to a wallet-owned
	 * address once one becomes available (e.g. after Electrum connects).
	 */
	setDestinationScript(destinationScript: Buffer): void {
		this.destinationScript = destinationScript;
	}

	/**
	 * Start watching the blockchain. Subscribes to block headers.
	 */
	async start(): Promise<void> {
		if (this.started) return;
		this.started = true;

		await this.backend.subscribeToHeaders((height: number) => {
			this.handleNewBlock(height);
		});

		// Safety net: periodically re-check watched funding outputs even without a
		// new-block event, so a confirmation missed during an Electrum outage is
		// picked up promptly instead of waiting for the next block (or forever, if
		// the header subscription itself failed to (re)establish).
		if (!this._recheckTimer) {
			this._recheckTimer = setInterval(() => {
				this.recheckAllWatches();
			}, RECHECK_INTERVAL_MS);
			if (this._recheckTimer.unref) this._recheckTimer.unref();
		}
	}

	/**
	 * Re-check every watched funding output for confirmation and retry any failed
	 * subscriptions, independently of new-block / subscription callbacks. Safe to
	 * call at any time (idempotent). Call it after the Electrum connection is
	 * (re)established for fast recovery; the periodic timer also invokes it.
	 */
	recheckAllWatches(): void {
		// Retry failed funding-watch subscriptions (re-subscribe + immediate check).
		if (this.failedFundingWatches.length > 0) {
			const pending = [...this.failedFundingWatches];
			this.failedFundingWatches = [];
			for (const w of pending) {
				this.watchFundingOutput(
					w.channelId,
					w.txid,
					w.outputIndex,
					w.minimumDepth,
					w.scriptPubkey
				).catch(() => {
					/* re-queued inside watchFundingOutput */
				});
			}
		}
		// Retry failed output-watch subscriptions.
		if (this.failedOutputWatches.length > 0) {
			const pendingOutputs = [...this.failedOutputWatches];
			this.failedOutputWatches = [];
			for (const w of pendingOutputs) {
				this.watchOutput(w.txid, w.outputIndex, w.scriptPubkey).catch(() => {
					/* re-queued inside watchOutput */
				});
			}
		}
		// Re-check unconfirmed fundings and watched output spends directly.
		for (const [key, watched] of this.watchedFundings) {
			if (!watched.confirmed) {
				this.checkFundingConfirmation(key).catch((err) =>
					this.emit('error', err)
				);
			}
		}
		for (const key of this.watchedOutputs.keys()) {
			this.checkOutputSpend(key).catch((err) => this.emit('error', err));
		}
	}

	/**
	 * Remove a watched funding entry by channel ID (memory cleanup after channel close).
	 * Returns true if the entry was found and removed.
	 */
	removeWatchedFunding(channelId: Buffer): boolean {
		return this.watchedFundings.delete(channelId.toString('hex'));
	}

	/**
	 * Stop watching. Clears all watched outputs.
	 */
	stop(): void {
		this.started = false;
		if (this._recheckTimer) {
			clearInterval(this._recheckTimer);
			this._recheckTimer = null;
		}
		this.watchedFundings.clear();
		this.watchedOutputs.clear();
		this.failedFundingWatches.length = 0;
		this.failedOutputWatches.length = 0;
		this.failedBroadcasts.length = 0;
		this.removeAllListeners();
	}

	/**
	 * Get the current block height as known by the watcher.
	 */
	getCurrentBlockHeight(): number {
		return this.currentBlockHeight;
	}

	/**
	 * Watch a funding output for confirmation.
	 */
	async watchFundingOutput(
		channelId: Buffer,
		txid: string,
		outputIndex: number,
		minimumDepth: number,
		scriptPubkey: Buffer
	): Promise<void> {
		const scriptHash = computeScriptHash(scriptPubkey);
		const key = channelId.toString('hex');

		const watched: IWatchedFunding = {
			channelId,
			txid,
			outputIndex,
			minimumDepth,
			scriptHash,
			confirmed: false,
			confirmationHeight: 0,
			announcementTriggered: false
		};

		this.watchedFundings.set(key, watched);

		// Subscribe to the funding script hash — queue for retry on failure
		try {
			await this.backend.subscribeToScriptHash(scriptHash, () => {
				this.checkFundingConfirmation(key).catch((err) => {
					this.emit('error', err);
				});
			});
		} catch {
			// Queue for retry on next block
			this.failedFundingWatches.push({
				channelId,
				txid,
				outputIndex,
				minimumDepth,
				scriptPubkey
			});
		}

		// Immediately check current status. Electrum's scripthash subscription only
		// fires the callback on FUTURE status changes, so a channel whose funding
		// (and possibly close) was confirmed while we were offline would otherwise
		// not be reconciled until the next new block arrives. This mirrors the
		// immediate checkFundingSpent() in watchFundingSpend().
		try {
			await this.checkFundingConfirmation(key);
		} catch (err) {
			this.emit('error', err);
		}
	}

	/**
	 * FFOR M7.2: watch an embedded-tower epoch's funding outpoint for a spend.
	 * The tower's epochs are EXTERNAL channels (between an external R and S),
	 * not the node's own, so a spend routes to the tower breach classifier
	 * (channelManager.fforHandleTowerSpend) rather than the node's force-close
	 * path. Keyed by the epoch id. Idempotent (re-registration on boot is safe).
	 */
	async watchTowerEpochFunding(
		epochId: Buffer,
		txid: string,
		outputIndex: number,
		scriptPubkey: Buffer
	): Promise<void> {
		const scriptHash = computeScriptHash(scriptPubkey);
		const key = `tower:${epochId.toString('hex')}`;
		const watched: IWatchedFunding = {
			channelId: epochId, // reused as the map key basis; never a real channel
			txid,
			outputIndex,
			minimumDepth: 1,
			scriptHash,
			confirmed: true, // we only care about spends, not confirmation depth
			confirmationHeight: 0,
			announcementTriggered: false,
			towerEpochId: Buffer.from(epochId)
		};
		this.watchedFundings.set(key, watched);
		await this.watchFundingSpend(watched);
	}

	/**
	 * Watch an output for spends (e.g., commitment outputs for sweep detection).
	 */
	async watchOutput(
		txid: string,
		outputIndex: number,
		scriptPubkey: Buffer,
		// Seed a previously recorded spend (its txid + confirmation height) so that
		// after a restart checkOutputSpend can detect a REORG that evicts it. Without
		// this seed watched.spendTxid is undefined and the eviction branch never
		// fires, hiding a reorg-then-theft of a penalty / HTLC claim.
		spendTxid?: string,
		spendHeight?: number
	): Promise<void> {
		const scriptHash = computeScriptHash(scriptPubkey);
		const key = `${txid}:${outputIndex}`;

		this.watchedOutputs.set(key, {
			txid,
			outputIndex,
			scriptHash,
			spendTxid,
			spendHeight
		});

		try {
			await this.backend.subscribeToScriptHash(scriptHash, () => {
				this.checkOutputSpend(key).catch((err) => {
					this.emit('error', err);
				});
			});
		} catch {
			// Queue for retry on next block
			this.failedOutputWatches.push({ txid, outputIndex, scriptPubkey });
		}
	}

	/**
	 * Watch an output by fetching the transaction and extracting the script.
	 * Used to handle 'watch:output:requested' events.
	 */
	async watchOutputByTxid(
		txid: string,
		outputIndex: number,
		// Forwarded to watchOutput so a restored watch re-seeds any previously
		// recorded spend and stays reorg-eviction aware.
		spendTxid?: string,
		spendHeight?: number
	): Promise<void> {
		const rawTx = await this.backend.getTransaction(txid);
		const tx = bitcoin.Transaction.fromBuffer(rawTx);
		if (outputIndex >= tx.outs.length) {
			throw new Error(
				`Output index ${outputIndex} out of range for tx ${txid}`
			);
		}
		const scriptPubkey = tx.outs[outputIndex].script;
		await this.watchOutput(
			txid,
			outputIndex,
			scriptPubkey,
			spendTxid,
			spendHeight
		);
	}

	/**
	 * Broadcast a transaction via the chain backend.
	 */
	async broadcastTransaction(rawTx: Buffer): Promise<string> {
		const txid = await this.backend.broadcastTransaction(rawTx.toString('hex'));
		this.emit('broadcast:success', txid);
		return txid;
	}

	// ─────────────── Private ───────────────

	private wireChannelManagerEvents(): void {
		// Watch funding outputs when channels enter AWAITING_FUNDING_CONFIRMED
		this.channelManager.on(
			'watch:funding',
			(
				fundingTxid: Buffer,
				fundingOutputIndex: number,
				minimumDepth: number
			) => {
				// Convert to display byte order without mutating the source Buffer
				const displayTxid = Buffer.from(fundingTxid).reverse().toString('hex');

				// Find the channel matching this funding outpoint
				const channel = this.findChannelByFunding(
					displayTxid,
					fundingOutputIndex
				);
				if (!channel) {
					this.emit(
						'error',
						new Error(
							`watch:funding: no channel found for ${displayTxid}:${fundingOutputIndex}`
						)
					);
					return;
				}

				const state = channel.getFullState();
				if (!state.remoteBasepoints) {
					this.emit(
						'error',
						new Error(
							`watch:funding: channel missing remoteBasepoints for ${displayTxid}:${fundingOutputIndex}`
						)
					);
					return;
				}

				// Reconstruct the P2WSH funding script
				const { p2wshOutput } = createFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints.fundingPubkey
				);

				const channelId = state.channelId || state.temporaryChannelId;
				this.watchFundingOutput(
					channelId,
					displayTxid,
					fundingOutputIndex,
					minimumDepth,
					p2wshOutput
				).catch((err) => {
					this.emit('error', err);
				});
			}
		);

		// Broadcast transactions (closing/sweep txs)
		this.channelManager.on('broadcast:tx', (tx: Buffer) => {
			this.broadcastTransaction(tx).catch((err) => {
				// Queue for retry on next block
				const txObj = bitcoin.Transaction.fromBuffer(tx);
				const txidHex = txObj.getId();
				// Dedup by txid
				if (!this.failedBroadcasts.some((fb) => fb.txidHex === txidHex)) {
					this.failedBroadcasts.push({
						rawTx: Buffer.from(tx),
						txidHex,
						retryCount: 0
					});
				}
				this.emit('broadcast:failure', err);
			});
		});

		// Watch outputs (from chain monitor)
		this.channelManager.on(
			'watch:output',
			(txid: string, outputIndex: number) => {
				this.emit('watch:output:requested', txid, outputIndex);
			}
		);
	}

	private handleNewBlock(height: number): void {
		this.currentBlockHeight = height;

		// Retry failed funding watch subscriptions
		if (this.failedFundingWatches.length > 0) {
			const pending = [...this.failedFundingWatches];
			this.failedFundingWatches = [];
			for (const watch of pending) {
				this.watchFundingOutput(
					watch.channelId,
					watch.txid,
					watch.outputIndex,
					watch.minimumDepth,
					watch.scriptPubkey
				).catch(() => {
					// Still failing — already re-queued inside watchFundingOutput
				});
			}
		}

		// Retry failed output watch subscriptions
		if (this.failedOutputWatches.length > 0) {
			const pendingOutputs = [...this.failedOutputWatches];
			this.failedOutputWatches = [];
			for (const watch of pendingOutputs) {
				this.watchOutput(
					watch.txid,
					watch.outputIndex,
					watch.scriptPubkey
				).catch(() => {
					// Still failing — already re-queued inside watchOutput
				});
			}
		}

		// Retry failed broadcasts
		if (this.failedBroadcasts.length > 0) {
			const pendingBroadcasts = [...this.failedBroadcasts];
			this.failedBroadcasts = [];
			for (const fb of pendingBroadcasts) {
				fb.retryCount++;
				if (fb.retryCount > MAX_BROADCAST_RETRIES) {
					this.emit(
						'broadcast:permanent_failure',
						new Error(
							`Broadcast permanently failed after ${MAX_BROADCAST_RETRIES} retries: ${fb.txidHex}`
						)
					);
					continue;
				}
				this.broadcastTransaction(fb.rawTx).catch(() => {
					// Still failing — re-queue with dedup
					if (
						!this.failedBroadcasts.some(
							(existing) => existing.txidHex === fb.txidHex
						)
					) {
						this.failedBroadcasts.push(fb);
					}
				});
			}
		}

		// Advance all chain monitors
		this.channelManager.handleNewBlock(height);

		// Check all watched fundings for confirmation and announcement depth
		for (const [key, watched] of this.watchedFundings) {
			if (!watched.confirmed) {
				this.checkFundingConfirmation(key).catch((err) => {
					this.emit('error', err);
				});
			} else if (
				!watched.announcementTriggered &&
				watched.confirmationHeight > 0
			) {
				// Check if 6 confirmations reached for channel announcement
				const depth = height - watched.confirmationHeight + 1;
				if (depth >= 6) {
					watched.announcementTriggered = true;
					this.triggerAnnouncementDepth(watched).catch((err) => {
						this.emit('error', err);
					});
				}
			}
		}

		this.emit('block', height);
	}

	/**
	 * Re-arm announcement-depth tracking for a channel's funding watch.
	 *
	 * After a splice the channel lives on a NEW funding outpoint and must be
	 * re-announced with its new SCID. The new funding is watched during the
	 * splice (for splice_locked), but its one-shot announcement trigger may
	 * have fired while the channel was still SPLICING — when it cannot sign
	 * announcements — burning the trigger with no announcement sent. Calling
	 * this after splice completion resets the trigger for the watch matching
	 * the new funding txid; if announcement depth has already been reached the
	 * announcement fires immediately, otherwise on the next block.
	 */
	rearmAnnouncementTracking(channelId: Buffer, txidDisplayHex: string): void {
		for (const watched of this.watchedFundings.values()) {
			if (
				!watched.channelId.equals(channelId) ||
				watched.txid !== txidDisplayHex
			) {
				continue;
			}
			watched.announcementTriggered = false;
			if (
				watched.confirmed &&
				watched.confirmationHeight > 0 &&
				this.currentBlockHeight - watched.confirmationHeight + 1 >= 6
			) {
				watched.announcementTriggered = true;
				this.triggerAnnouncementDepth(watched).catch((err) => {
					this.emit('error', err);
				});
			}
		}
	}

	private async triggerAnnouncementDepth(
		watched: IWatchedFunding
	): Promise<void> {
		let txIndex = 0;
		if (this.backend.getTransactionMerkleProof) {
			const proof = await this.backend.getTransactionMerkleProof(
				watched.txid,
				watched.confirmationHeight
			);
			txIndex = proof.txIndex;
		}
		this.emit(
			'announcement:depth',
			watched.channelId,
			watched.confirmationHeight,
			txIndex
		);
	}

	private async checkFundingConfirmation(key: string): Promise<void> {
		const watched = this.watchedFundings.get(key);
		if (!watched || watched.confirmed) return;

		const history = await this.backend.getScriptHashHistory(watched.scriptHash);

		// Find our funding tx in the history
		const entry = history.find((h) => h.txid === watched.txid);
		if (!entry || entry.height <= 0) return; // not yet confirmed

		// Calculate confirmations
		const confirmations = this.currentBlockHeight - entry.height + 1;
		if (confirmations >= watched.minimumDepth) {
			watched.confirmed = true;
			watched.confirmationHeight = entry.height;

			this.channelManager.handleFundingConfirmed(watched.channelId);
			this.emit('funding:confirmed', watched.channelId);

			// Now watch for the funding output being spent (force close detection)
			this.watchFundingSpend(watched).catch((err) => {
				this.emit('error', err);
			});
		}
	}

	private async watchFundingSpend(watched: IWatchedFunding): Promise<void> {
		// Subscribe to detect when the funding output is spent
		await this.backend.subscribeToScriptHash(watched.scriptHash, () => {
			this.checkFundingSpent(watched).catch((err) => {
				this.emit('error', err);
			});
		});

		// Immediately check if the output was already spent (e.g., after restart
		// where the force-close tx was confirmed while we were offline)
		await this.checkFundingSpent(watched);
	}

	private async checkFundingSpent(watched: IWatchedFunding): Promise<void> {
		const history = await this.backend.getScriptHashHistory(watched.scriptHash);

		// Look for the transaction that spends our funding output. The script's
		// history can contain MULTIPLE non-spending entries sharing the same
		// script — splices reuse the 2-of-2 funding script, so every funding
		// generation (and the splice txs between them) appears here. Checking
		// only the first non-self entry therefore missed real closes; every
		// candidate must be examined. Include both confirmed (height > 0) and
		// mempool (height <= 0) spends.
		for (const entry of history) {
			if (entry.txid === watched.txid) continue;

			const rawTx = await this.backend.getTransaction(entry.txid);
			const spendingTx = bitcoin.Transaction.fromBuffer(rawTx);

			// Verify this tx actually spends our funding output
			const spendsOurs = spendingTx.ins.some((input) => {
				const inputTxid = Buffer.from(input.hash).reverse().toString('hex');
				return (
					inputTxid === watched.txid && input.index === watched.outputIndex
				);
			});
			if (!spendsOurs) continue;

			// Use 0 for mempool txs (Electrum returns height <= 0 for unconfirmed)
			const height = entry.height > 0 ? entry.height : 0;
			// FFOR M7.2: a tower-epoch funding spend routes to the tower breach
			// classifier, NOT the node's own channel force-close path.
			if (watched.towerEpochId) {
				this.channelManager.fforHandleTowerSpend(spendingTx, height);
				this.emit('tower:funding:spent', watched.towerEpochId, spendingTx);
				return;
			}
			this.channelManager.handleFundingSpent(
				watched.channelId,
				spendingTx,
				height,
				this.destinationScript,
				this.getSweepFeeRatePerVbyte?.() ?? 10
			);
			this.emit('funding:spent', watched.channelId, spendingTx);
			return;
		}
	}

	private findChannelByFunding(
		txidHex: string,
		outputIndex: number
	): import('../channel/channel').Channel | undefined {
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			// Match the current funding outpoint.
			if (state.fundingTxid) {
				const chanTxidHex = Buffer.from(state.fundingTxid)
					.reverse()
					.toString('hex');
				if (
					chanTxidHex === txidHex &&
					state.fundingOutputIndex === outputIndex
				) {
					return channel;
				}
			}
			// Match a pending splice outpoint (during AWAITING_SPLICE_LOCKED, before
			// completeSplice swaps it into fundingTxid).
			if (state.spliceFundingTxid) {
				const spliceTxidHex = Buffer.from(state.spliceFundingTxid)
					.reverse()
					.toString('hex');
				if (
					spliceTxidHex === txidHex &&
					state.spliceFundingOutputIndex === outputIndex
				) {
					return channel;
				}
			}
		}
		return undefined;
	}

	private async checkOutputSpend(key: string): Promise<void> {
		const watched = this.watchedOutputs.get(key);
		if (!watched) return;

		const history = await this.backend.getScriptHashHistory(watched.scriptHash);

		// Find the confirmed spend of our output. The script's history may contain
		// several non-spending entries with the same script (address reuse — e.g.
		// sweeps to a fixed destination), so every confirmed candidate is checked.
		let spend: {
			tx: bitcoin.Transaction;
			txid: string;
			height: number;
		} | null = null;
		for (const entry of history) {
			if (entry.txid === watched.txid || entry.height <= 0) continue;

			const rawTx = await this.backend.getTransaction(entry.txid);
			const spendingTx = bitcoin.Transaction.fromBuffer(rawTx);

			const spendsOurs = spendingTx.ins.some((input) => {
				const inputTxid = Buffer.from(input.hash).reverse().toString('hex');
				return (
					inputTxid === watched.txid && input.index === watched.outputIndex
				);
			});
			if (!spendsOurs) continue;

			spend = { tx: spendingTx, txid: entry.txid, height: entry.height };
			break;
		}

		if (spend) {
			// Idempotent: the subscription re-fires on any scripthash change, so skip
			// re-reporting a spend we already recorded.
			if (watched.spendTxid !== spend.txid) {
				watched.spendTxid = spend.txid;
				watched.spendHeight = spend.height;
				this.channelManager.handleOutputSpent(
					watched.txid,
					watched.outputIndex,
					spend.tx,
					spend.height
				);
				this.emit('output:spent', watched.txid, watched.outputIndex);
			}
			// Retain the watch until the spend is buried deep enough to be final, so a
			// reorg before then re-fires this check and is caught by the branch below.
			if (
				this.currentBlockHeight > 0 &&
				this.currentBlockHeight - spend.height + 1 >= SPEND_FINALITY_DEPTH
			) {
				this.watchedOutputs.delete(key);
			}
			return;
		}

		// No spend in the current history. If we had previously reported one, it has
		// been evicted by a reorg — tell the monitor so it can re-broadcast our sweep
		// (penalty / HTLC-success) before the counterparty's timelock matures.
		if (watched.spendTxid !== undefined) {
			watched.spendTxid = undefined;
			watched.spendHeight = undefined;
			this.channelManager.handleOutputUnspent(
				watched.txid,
				watched.outputIndex
			);
			this.emit('output:unspent', watched.txid, watched.outputIndex);
		}
	}
}
