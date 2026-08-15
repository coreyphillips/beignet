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
import { createTaprootFundingScript } from '../script/funding-taproot';
import { isTaprootChannel } from '../channel/types';

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
	/**
	 * List unspent outputs for a script hash (Electrum
	 * blockchain.scripthash.listunspent). Optional; used to verify that a
	 * dual-funding peer's claimed prevout actually exists unspent on chain
	 * (issue #311). height 0 means unconfirmed.
	 */
	listUnspent?(scriptHash: string): Promise<
		Array<{
			txid: string;
			outputIndex: number;
			valueSat: number;
			height: number;
		}>
	>;
}

/** A funding output being watched for confirmation */
interface IWatchedFunding {
	channelId: Buffer;
	txid: string; // hex, display byte order (as Electrum history reports it)
	outputIndex: number;
	minimumDepth: number;
	scriptHash: string;
	confirmed: boolean;
	confirmationHeight: number;
	announcementTriggered: boolean;
	/**
	 * A spend by this txid is NOT a hostile close and must be ignored. Used for
	 * the pre-splice funding output during an in-flight splice: the splice tx
	 * legitimately spends it, but a revoked pre-splice commitment (a peer evicting
	 * our low-feerate splice from the mempool) spends the SAME outpoint with a
	 * different txid and must trigger the breach path.
	 */
	ignoreSpendTxid?: string;
	/**
	 * Consecutive confirmation checks in which the funding tx was absent from
	 * the script's history entirely (neither mempool nor chain). A zero-conf
	 * channel is NORMAL the moment both sides trust it; if its funding tx is
	 * evicted or replaced, the channel silently becomes fiction, so absence is
	 * alarmed via 'funding:missing' after a debounce.
	 */
	missingChecks?: number;
	missingReported?: boolean;
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
 * Chain verdict on a dual-funding peer's claimed prevout (issue #311).
 * 'unspent' = the outpoint exists unspent; 'spent-or-missing' = POSITIVE
 * evidence refutes the claim (the tx is confirmed on this script and its
 * output is no longer in the unspent set); 'unknown' = no conclusive answer
 * (disconnected, timeout, tx not indexed by this server) and callers must
 * fail open. Absence alone is NEVER conclusive: BOLT 2 permits unconfirmed
 * inputs, and a valid unconfirmed parent may simply not have reached this
 * server yet.
 */
export type RemoteInputVerdict = 'unspent' | 'spent-or-missing' | 'unknown';

/**
 * Best-effort chain verification that a peer-claimed prevout exists unspent
 * (issue #311). Interactive-tx validation is otherwise pure self-consistency
 * over bytes the peer chose. Queries the prevout script's unspent set and
 * history in parallel; only positive evidence of a spend reports
 * 'spent-or-missing'. Never throws.
 */
export async function classifyRemoteFundingInput(
	backend: IChainBackend,
	outpoint: { txidDisplayHex: string; vout: number; scriptPubKey: Buffer }
): Promise<RemoteInputVerdict> {
	// Without the unspent set there is no positive evidence path at all.
	if (!backend.listUnspent) return 'unknown';
	const scriptHash = computeScriptHash(outpoint.scriptPubKey);
	const [unspent, history] = await Promise.all([
		backend.listUnspent(scriptHash).catch(() => null),
		backend.getScriptHashHistory(scriptHash).catch(() => null)
	]);
	if (
		unspent?.some(
			(u) =>
				u.txid === outpoint.txidDisplayHex && u.outputIndex === outpoint.vout
		)
	) {
		return 'unspent';
	}
	if (!unspent || !history) return 'unknown';
	const entry = history.find((h) => h.txid === outpoint.txidDisplayHex);
	// Absent from the history: NOT conclusive. This server may simply not
	// have indexed a valid unconfirmed parent yet, and BOLT 2 permits
	// unconfirmed inputs, so treating absence as refutation would falsely
	// abort honest opens. Fail open.
	if (!entry) return 'unknown';
	// Confirmed on chain but not in the unspent set: the output provably
	// existed and has been spent. Unconfirmed (height <= 0): servers index
	// mempool utxos inconsistently, so absence from listunspent proves
	// nothing; fail open.
	return entry.height > 0 ? 'spent-or-missing' : 'unknown';
}

/**
 * Watches the blockchain for funding confirmations, output spends,
 * and new blocks, bridging these events to the ChannelManager.
 *
 * Events:
 * - 'funding:confirmed' (channelId: Buffer, txid: string): the watched txid
 *   (display byte order) that reached depth, so listeners can tell a splice
 *   confirmation from the original funding without trusting channel state
 * - 'funding:spent' (channelId: Buffer, spendingTx: Transaction)
 * - 'funding:missing' (channelId: Buffer, txid: string): the watched funding
 *   tx disappeared from mempool AND chain before confirming (evicted/replaced)
 * - 'broadcast:success' (txid: string)
 * - 'broadcast:failure' (error: Error)
 * - 'error' (error: Error)
 *
 * CONTRACT: register an 'error' listener. Chain failures are reported there
 * and NOWHERE else, and with no listener attached they are dropped rather than
 * thrown. EventEmitter's default is to throw on an unhandled 'error', which for
 * a component that emits from a dozen promise catches means a background chain
 * failure terminates the process, including during shutdown. LightningNode
 * registers one (surfaced as node:error with code CHAIN_WATCHER_ERROR); a
 * consumer driving ChainWatcher directly must do the same.
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
	/**
	 * Bumped on every start() and stop(). Chain work captures the generation it
	 * began in and re-checks it after every await, so a request that resolves
	 * after teardown cannot advance the ChannelManager, and a stale callback
	 * from a previous run cannot act on a restarted watcher. `started` alone is
	 * not enough for the second case.
	 */
	private lifecycleGeneration = 0;
	/**
	 * Whether the watcher will accept NEW chain work. True from construction, so
	 * registration on a watcher that has never been started keeps working, false
	 * from an explicit stop() until the next start().
	 *
	 * The generation alone cannot express this: it retires work that was already
	 * inside the watcher, but an operation that crosses its own await OUTSIDE
	 * the watcher (LightningNode.watchRecoveredFundingOutput fetching a funding
	 * tx, say) and calls in for the first time afterwards would default to the
	 * post-stop generation and pass every check.
	 */
	private acceptingWork = true;
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
	 * Every internal 'error' emit goes through here. EventEmitter THROWS when
	 * 'error' is emitted with no listener, and this class emits it from a dozen
	 * promise catches that can land at any time, including after teardown. A
	 * background chain failure must not become a process crash.
	 */
	private emitError(err: Error): void {
		if (this.listenerCount('error') === 0) return;
		this.emit('error', err);
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
		this.acceptingWork = true;
		this.started = true;
		const generation = ++this.lifecycleGeneration;

		// stop() detaches the ChannelManager subscriptions, so a restarted
		// watcher has to re-arm them or it never sees another channel event.
		this.wireChannelManagerEvents();

		try {
			// The backend keeps this callback: ElectrumBackend holds one header
			// callback and re-invokes it across reconnects, and stopping the
			// watcher does not clear it. Gate it on the generation, or headers
			// arriving after teardown still advance the ChannelManager.
			await this.backend.subscribeToHeaders((height: number) => {
				if (!this.isCurrentGeneration(generation)) return;
				this.handleNewBlock(height);
			});
		} catch (err) {
			if (this.lifecycleGeneration === generation) {
				// A watcher with no header subscription and no recheck timer would
				// accept watches it can never check, so it stops accepting work
				// until a start() succeeds. The throw is the loud half of this.
				this.started = false;
				this.acceptingWork = false;
				++this.lifecycleGeneration;
				this.unwireChannelManagerEvents();
			}
			throw err;
		}

		if (!this.isCurrentGeneration(generation)) return;

		// Safety net: periodically re-check watched funding outputs even without a
		// new-block event, so a confirmation missed during an Electrum outage is
		// picked up promptly instead of waiting for the next block (or forever, if
		// the header subscription itself failed to (re)establish).
		if (!this._recheckTimer) {
			this._recheckTimer = setInterval(() => {
				if (!this.isCurrentGeneration(generation)) return;
				this.recheckAllWatches();
			}, RECHECK_INTERVAL_MS);
			if (this._recheckTimer.unref) this._recheckTimer.unref();
		}
	}

	/**
	 * True while the watcher is still in the lifecycle generation the caller
	 * began in. Chain work must re-check this after every await before touching
	 * the ChannelManager or emitting.
	 *
	 * Deliberately not gated on `started`: watchFundingOutput, watchOutputByTxid
	 * and rearmAnnouncementTracking are public and documented to work on a
	 * watcher that has never been started, and requiring `started` would turn
	 * those into silent no-ops. stop() bumps the generation, so anything that
	 * needs retiring is retired either way.
	 */
	private isCurrentGeneration(generation: number): boolean {
		return this.acceptingWork && this.lifecycleGeneration === generation;
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
				this.checkFundingConfirmation(key).catch((err) => this.emitError(err));
			}
		}
		for (const key of this.watchedOutputs.keys()) {
			this.checkOutputSpend(key).catch((err) => this.emitError(err));
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
		// Refuses new work as well as retiring work already in flight: an outer
		// operation that began before stop() can still call in for the first
		// time afterwards, and it would otherwise be handed this new generation.
		this.acceptingWork = false;
		this.started = false;
		// Retires every in-flight operation: anything that resolves from here on
		// sees a generation it does not own and returns without acting.
		++this.lifecycleGeneration;
		if (this._recheckTimer) {
			clearInterval(this._recheckTimer);
			this._recheckTimer = null;
		}
		this.watchedFundings.clear();
		this.watchedOutputs.clear();
		this.failedFundingWatches.length = 0;
		this.failedOutputWatches.length = 0;
		this.failedBroadcasts.length = 0;

		// Detach from the ChannelManager, so a stopped watcher stops acting on
		// channel events. It used to keep broadcasting after node.destroy().
		// start() re-arms these.
		this.unwireChannelManagerEvents();

		// Deliberately NOT removeAllListeners(): those are the consumer's
		// handlers, including the node's 'error' handler, and in-flight chain
		// requests still reject after stop(). Removing them turned an ordinary
		// shutdown into a crash, and left the watcher permanently deaf if it was
		// ever restarted.
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
		scriptPubkey: Buffer,
		// Captured by whatever operation is registering this watch, so a stop()
		// during either await retires the whole registration.
		generation: number = this.lifecycleGeneration
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
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
				// The backend retains this callback across reconnects, so a
				// callback registered before a stop() must not start a check that
				// captures the current generation and passes every guard.
				if (!this.isCurrentGeneration(generation)) return;
				this.checkFundingConfirmation(key, generation).catch((err) => {
					this.emitError(err);
				});
			});
		} catch {
			// Queue for retry on next block, unless the watch was retired while
			// the subscription was in flight: stop() clears this queue, and
			// repopulating it afterwards revives a stale watch on the next start.
			if (
				this.isCurrentGeneration(generation) &&
				this.watchedFundings.get(key) === watched
			) {
				this.failedFundingWatches.push({
					channelId,
					txid,
					outputIndex,
					minimumDepth,
					scriptPubkey
				});
			}
			return;
		}

		if (
			!this.isCurrentGeneration(generation) ||
			this.watchedFundings.get(key) !== watched
		) {
			if (this.watchedFundings.get(key) === watched) {
				this.watchedFundings.delete(key);
			}
			return;
		}

		// Immediately check current status. Electrum's scripthash subscription only
		// fires the callback on FUTURE status changes, so a channel whose funding
		// (and possibly close) was confirmed while we were offline would otherwise
		// not be reconciled until the next new block arrives. This mirrors the
		// immediate checkFundingSpent() in watchFundingSpend().
		try {
			await this.checkFundingConfirmation(key, generation);
		} catch (err) {
			this.emitError(err);
		}
	}

	/**
	 * Watch an ALREADY-CONFIRMED funding output for a hostile spend, ignoring one
	 * expected txid. Used for the pre-splice funding output during an in-flight
	 * splice: the new-outpoint watch (watchFundingOutput, keyed by channelId) only
	 * arms spend detection once the SPLICE tx confirms, so the old output would
	 * otherwise have no spend subscription. A peer that evicts our low-feerate
	 * splice from the mempool and broadcasts a revoked pre-splice commitment
	 * spends the old outpoint with a different txid, which this detects and routes
	 * to handleFundingSpent (the breach path). This watch is intentionally NOT
	 * stored in watchedFundings so it does not collide with the channel's
	 * new-outpoint funding watch; a restart re-arms it via restoreChainWatches.
	 */
	async watchFundingSpendDuringSplice(
		channelId: Buffer,
		txid: string,
		outputIndex: number,
		scriptPubkey: Buffer,
		ignoreSpendTxid: string
	): Promise<void> {
		const watched: IWatchedFunding = {
			channelId,
			txid,
			outputIndex,
			minimumDepth: 0,
			scriptHash: computeScriptHash(scriptPubkey),
			confirmed: true,
			confirmationHeight: 0,
			announcementTriggered: true,
			ignoreSpendTxid
		};
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
		spendHeight?: number,
		// Taken at the start of whatever operation is registering this watch, so
		// a stop() during either await retires the whole registration rather
		// than just the part that had not started yet.
		generation: number = this.lifecycleGeneration
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		const scriptHash = computeScriptHash(scriptPubkey);
		const key = `${txid}:${outputIndex}`;

		const watched: IWatchedOutput = {
			txid,
			outputIndex,
			scriptHash,
			spendTxid,
			spendHeight
		};
		this.watchedOutputs.set(key, watched);

		try {
			await this.backend.subscribeToScriptHash(scriptHash, () => {
				// The backend retains this callback and re-invokes it across
				// reconnects; stop() cannot reach into it. Without this check a
				// callback registered before a stop could start a fresh check that
				// captured the CURRENT generation and passed every guard.
				if (!this.isCurrentGeneration(generation)) return;
				this.checkOutputSpend(key, generation).catch((err) => {
					this.emitError(err);
				});
			});
		} catch {
			// Queue for retry on next block, unless the watch was retired while
			// the subscription was in flight: stop() clears this queue, and
			// repopulating it afterwards revives a stale watch on the next start.
			if (
				this.isCurrentGeneration(generation) &&
				this.watchedOutputs.get(key) === watched
			) {
				this.failedOutputWatches.push({ txid, outputIndex, scriptPubkey });
			}
			return;
		}

		// Retired while subscribing: drop our own entry if it somehow outlived
		// the clear in stop(). Never touch an entry a later generation owns.
		if (
			!this.isCurrentGeneration(generation) &&
			this.watchedOutputs.get(key) === watched
		) {
			this.watchedOutputs.delete(key);
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
		// Captured before the fetch: resolving after a stop() and then installing
		// a fresh watch would hand checkOutputSpend a map entry and a generation
		// that both look current, so every downstream guard would pass.
		const generation = this.lifecycleGeneration;
		const rawTx = await this.backend.getTransaction(txid);
		if (!this.isCurrentGeneration(generation)) return;
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
			spendHeight,
			generation
		);
	}

	/**
	 * Broadcast a transaction via the chain backend.
	 */
	async broadcastTransaction(rawTx: Buffer): Promise<string> {
		const generation = this.lifecycleGeneration;
		const txid = await this.backend.broadcastTransaction(rawTx.toString('hex'));
		// The txid still goes back to the caller; only the event is suppressed,
		// so a stop() mid-broadcast does not announce a success to consumers that
		// have already torn down.
		if (this.isCurrentGeneration(generation)) {
			this.emit('broadcast:success', txid);
		}
		return txid;
	}

	// ─────────────── Private ───────────────

	/**
	 * ChannelManager subscriptions are held as named handlers so stop() can
	 * detach them. Registered inline, a stopped watcher kept receiving channel
	 * events and still broadcast transactions after the node was destroyed.
	 */
	private onWatchFunding = (
		fundingTxid: Buffer,
		fundingOutputIndex: number,
		minimumDepth: number
	): void => {
		// Convert to display byte order without mutating the source Buffer
		const displayTxid = Buffer.from(fundingTxid).reverse().toString('hex');

		// Find the channel matching this funding outpoint
		const channel = this.findChannelByFunding(displayTxid, fundingOutputIndex);
		if (!channel) {
			this.emitError(
				new Error(
					`watch:funding: no channel found for ${displayTxid}:${fundingOutputIndex}`
				)
			);
			return;
		}

		const state = channel.getFullState();
		if (!state.remoteBasepoints) {
			this.emitError(
				new Error(
					`watch:funding: channel missing remoteBasepoints for ${displayTxid}:${fundingOutputIndex}`
				)
			);
			return;
		}

		// Reconstruct the funding scriptPubKey. Simple-taproot channels fund a
		// P2TR MuSig2 key-spend output, so watching the witness-v0 P2WSH
		// scripthash would never match and the funding spend would go
		// undetected.
		const fundingScript = isTaprootChannel(state.channelType)
			? createTaprootFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints.fundingPubkey
			  ).p2trOutput
			: createFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints.fundingPubkey
			  ).p2wshOutput;

		const channelId = state.channelId || state.temporaryChannelId;
		this.watchFundingOutput(
			channelId,
			displayTxid,
			fundingOutputIndex,
			minimumDepth,
			fundingScript
		).catch((err) => {
			this.emitError(err);
		});
	};

	private onBroadcastTx = (tx: Buffer): void => {
		if (!Buffer.isBuffer(tx)) {
			// A non-Buffer payload (e.g. a bitcoin.Transaction emitted by mistake)
			// hex-encodes to "[object Object]" and cannot be broadcast; drop it
			// loudly instead of letting the failure path below throw an unhandled
			// rejection when it calls Transaction.fromBuffer on a non-Buffer.
			this.emit(
				'broadcast:failure',
				new Error('broadcast:tx received a non-Buffer payload; dropped')
			);
			return;
		}
		const generation = this.lifecycleGeneration;
		this.broadcastTransaction(tx).catch((err) => {
			// A rejection that lands after teardown must not repopulate the retry
			// queue of a watcher that is no longer retrying anything.
			if (!this.isCurrentGeneration(generation)) return;
			// Queue for retry on next block. Guard the decode so a malformed
			// payload is logged and dropped rather than throwing an unhandled
			// rejection inside this catch handler (which would crash the process).
			try {
				const txidHex = bitcoin.Transaction.fromBuffer(tx).getId();
				// Dedup by txid
				if (!this.failedBroadcasts.some((fb) => fb.txidHex === txidHex)) {
					this.failedBroadcasts.push({
						rawTx: Buffer.from(tx),
						txidHex,
						retryCount: 0
					});
				}
			} catch {
				// Not a decodable transaction; nothing to queue for retry.
			}
			this.emit('broadcast:failure', err);
		});
	};

	private onWatchOutput = (txid: string, outputIndex: number): void => {
		this.emit('watch:output:requested', txid, outputIndex);
	};

	private wireChannelManagerEvents(): void {
		// Detach first: start() re-wires after a stop(), and registering the same
		// handler twice would broadcast twice.
		this.unwireChannelManagerEvents();
		// Watch funding outputs when channels enter AWAITING_FUNDING_CONFIRMED
		this.channelManager.on('watch:funding', this.onWatchFunding);
		// Broadcast transactions (closing/sweep txs)
		this.channelManager.on('broadcast:tx', this.onBroadcastTx);
		// Watch outputs (from chain monitor)
		this.channelManager.on('watch:output', this.onWatchOutput);
	}

	private unwireChannelManagerEvents(): void {
		this.channelManager.off('watch:funding', this.onWatchFunding);
		this.channelManager.off('broadcast:tx', this.onBroadcastTx);
		this.channelManager.off('watch:output', this.onWatchOutput);
	}

	private handleNewBlock(height: number): void {
		// A retained backend header callback can fire after teardown. Advancing
		// the ChannelManager then would resolve HTLCs and drive closes for a
		// watcher that is no longer watching.
		if (!this.started) return;
		const generation = this.lifecycleGeneration;
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
					// A rejection landing after teardown must not repopulate the
					// queue stop() just cleared, or the next start retries it.
					if (!this.isCurrentGeneration(generation)) return;
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
				this.checkFundingConfirmation(key, generation).catch((err) => {
					this.emitError(err);
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
						this.emitError(err);
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
					this.emitError(err);
				});
			}
		}
	}

	private async triggerAnnouncementDepth(
		watched: IWatchedFunding
	): Promise<void> {
		const generation = this.lifecycleGeneration;
		let txIndex = 0;
		if (this.backend.getTransactionMerkleProof) {
			const proof = await this.backend.getTransactionMerkleProof(
				watched.txid,
				watched.confirmationHeight
			);
			if (!this.isCurrentGeneration(generation)) return;
			txIndex = proof.txIndex;
		}
		this.emit(
			'announcement:depth',
			watched.channelId,
			watched.confirmationHeight,
			txIndex
		);
	}

	private async checkFundingConfirmation(
		key: string,
		// Defaults to the current generation for callers that ARE the start of
		// the operation; callers reached through an earlier await pass theirs.
		generation: number = this.lifecycleGeneration
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		const watched = this.watchedFundings.get(key);
		if (!watched || watched.confirmed) return;

		const history = await this.backend.getScriptHashHistory(watched.scriptHash);

		// stop() may have run while that request was in flight. Acting now would
		// advance the ChannelManager for a watcher that is no longer watching,
		// and the map identity check catches the entry being replaced by a
		// restart rather than merely cleared.
		if (
			!this.isCurrentGeneration(generation) ||
			this.watchedFundings.get(key) !== watched
		) {
			return;
		}

		// Find our funding tx in the history
		const entry = history.find((h) => h.txid === watched.txid);
		if (!entry) {
			// The funding tx is in neither the mempool nor a block: it was
			// evicted or replaced (e.g. one of its inputs double-spent). For a
			// zero-conf channel that is already NORMAL this means the channel
			// no longer exists on the network. Alarm after a debounce so a
			// transient Electrum hiccup does not cry wolf.
			watched.missingChecks = (watched.missingChecks ?? 0) + 1;
			if (watched.missingChecks >= 3 && !watched.missingReported) {
				watched.missingReported = true;
				this.emit('funding:missing', watched.channelId, watched.txid);
			}
			return;
		}
		// Present again (mempool or chain): a reorg can bounce a tx back.
		watched.missingChecks = 0;
		watched.missingReported = false;
		if (entry.height <= 0) return; // in the mempool, not yet confirmed

		// Calculate confirmations
		const confirmations = this.currentBlockHeight - entry.height + 1;
		if (confirmations >= watched.minimumDepth) {
			watched.confirmed = true;
			watched.confirmationHeight = entry.height;

			this.channelManager.handleFundingConfirmed(watched.channelId);
			this.emit('funding:confirmed', watched.channelId, watched.txid);

			// Now watch for the funding output being spent (force close detection)
			this.watchFundingSpend(watched, generation).catch((err) => {
				this.emitError(err);
			});
		}
	}

	private async watchFundingSpend(
		watched: IWatchedFunding,
		generation: number = this.lifecycleGeneration
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		// Subscribe to detect when the funding output is spent
		await this.backend.subscribeToScriptHash(watched.scriptHash, () => {
			if (!this.isCurrentGeneration(generation)) return;
			this.checkFundingSpent(watched, generation).catch((err) => {
				this.emitError(err);
			});
		});

		// A stop() during the subscribe would otherwise let the check below start
		// fresh and capture the post-stop generation, passing every guard.
		if (!this.isCurrentGeneration(generation)) return;

		// Immediately check if the output was already spent (e.g., after restart
		// where the force-close tx was confirmed while we were offline)
		await this.checkFundingSpent(watched, generation);
	}

	private async checkFundingSpent(
		watched: IWatchedFunding,
		// Splice watches are deliberately not held in watchedFundings, so the
		// generation is the only check available here, which makes it important
		// that the caller passes the one it started in rather than letting this
		// capture a fresh one after a stop().
		generation: number = this.lifecycleGeneration
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		const history = await this.backend.getScriptHashHistory(watched.scriptHash);
		if (!this.isCurrentGeneration(generation)) return;

		// Look for the transaction that spends our funding output. The script's
		// history can contain MULTIPLE non-spending entries sharing the same
		// script — splices reuse the 2-of-2 funding script, so every funding
		// generation (and the splice txs between them) appears here. Checking
		// only the first non-self entry therefore missed real closes; every
		// candidate must be examined. Include both confirmed (height > 0) and
		// mempool (height <= 0) spends.
		for (const entry of history) {
			if (entry.txid === watched.txid) continue;
			// A legitimate splice spends the pre-splice funding output; only a
			// DIFFERENT spender (a revoked/force-close commitment) is a breach.
			if (watched.ignoreSpendTxid && entry.txid === watched.ignoreSpendTxid) {
				continue;
			}

			const rawTx = await this.backend.getTransaction(entry.txid);
			if (!this.isCurrentGeneration(generation)) return;
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

		// History fetched successfully and NO spender found. If the channel's
		// monitor has a confirmed spend recorded, that spend was reorged out
		// without even re-entering the mempool, and its irrevocable-depth clock
		// must stop counting against the vanished height (issue 352). No-op for
		// channels with no recorded spend. The splice watch is excluded: it
		// ignores the expected splice spend, so an empty result there is normal.
		if (!watched.ignoreSpendTxid) {
			this.channelManager.handleFundingSpendAbsent?.(watched.channelId);
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

	private async checkOutputSpend(
		key: string,
		generation: number = this.lifecycleGeneration
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		const watched = this.watchedOutputs.get(key);
		if (!watched) return;

		const history = await this.backend.getScriptHashHistory(watched.scriptHash);
		if (
			!this.isCurrentGeneration(generation) ||
			this.watchedOutputs.get(key) !== watched
		) {
			return;
		}

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
			if (
				!this.isCurrentGeneration(generation) ||
				this.watchedOutputs.get(key) !== watched
			) {
				return;
			}
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
