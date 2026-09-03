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
import { IRREVOCABLE_DEPTH } from './types';

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
	/** When the current run of absent answers began (ms since epoch). */
	missingSince?: number;
	/**
	 * Every funding tx this open may still confirm as (post-signatures RBF,
	 * issue #360): the current attempt plus every superseded broadcastable
	 * attempt. All attempts pay the same funding script (the funding pubkeys
	 * never rotate across RBF), so ONE scripthash subscription covers the
	 * whole set; only the txid and output index differ per attempt. Absent =
	 * the single txid/outputIndex pair above. Whichever candidate confirms
	 * is adopted into txid/outputIndex, and 'funding:missing' means ALL
	 * candidates vanished.
	 */
	candidates?: Array<{ txid: string; outputIndex: number }>;
	/** The funding output's scriptPubkey, kept for candidate discovery. */
	script: Buffer;
	/**
	 * This watch was armed from a record that may be behind what the node
	 * actually did (a row restored from disk, issue #463), so its candidate
	 * txids are not the whole answer: a funding attempt the lost process
	 * replaced by RBF confirms under a txid the record never names, and
	 * filtering the script's history down to the recorded txids would report
	 * the funding ABSENT while it sits confirmed in that very history.
	 *
	 * When set, an otherwise-empty filter falls back to reading the funding
	 * script's history for a transaction that could be a replacement of these
	 * attempts. One entry per funding attempt the record knows, holding that
	 * attempt's input outpoints as `txid:vout`.
	 *
	 * LINEAGE, not shape, is what identifies the funding. The script is not
	 * unique: channelKeyDeriver is optional, and without it every channel with
	 * a given peer shares one set of funding pubkeys and therefore one script,
	 * so an older channel's own funding and close sit in this very history and
	 * a legitimate spend of it proves nothing about WHICH channel it was. The
	 * value is not fixed either: BOLT 2 lets a peer change its
	 * funding_output_contribution between RBF attempts, which this
	 * implementation supports, so a replacement can pay a different amount. A
	 * replacement must instead share an input with every attempt it replaces,
	 * which nothing outside this negotiation can arrange and which no other
	 * channel of ours can satisfy: its funding spends coins this one never
	 * pledged.
	 */
	discoverAttemptInputs?: string[][];
	/**
	 * Confirmed script-and-value matches that are not (yet) known to be this
	 * channel's funding: candidates, never conclusions. They keep the watch
	 * reading as PRESENT, so a restored channel whose funding the record
	 * cannot name is never forgotten by the BOLT 2 clock, but nothing else is
	 * done with them. The watched outpoint is not moved, no confirmation is
	 * reported and the recorded funding payload is not retired, because any
	 * of those would act on a transaction that may be a decoy.
	 *
	 * Binding waits for a SPEND of one of them. The output pays a 2-of-2 that
	 * only this channel's two parties can satisfy, so a transaction spending
	 * it exists only if both of them signed one, which nobody who merely
	 * copied the script can arrange. A decoy therefore stays provisional
	 * forever while the search continues past it (issue #463).
	 *
	 * Written only by checkFundingConfirmation, under the ticket check below.
	 * The set answers the same question absence does, and a scan that computed
	 * it before a newer one recorded absence must not put it back (issue #624).
	 */
	provisional?: Array<{ txid: string; outputIndex: number; height: number }>;
	/**
	 * Monotonic dispenser: every confirmation scan of this watch takes the
	 * next value before its first await (issue #463).
	 *
	 * CONFIRMATION half only. The spend half is arbitrated per CHANNEL
	 * instead, by `channelSpendScans`, because a channel has more than one
	 * watch once a splice leaves a pre-splice leg behind and those watches
	 * answer for one shared monitor; a per-watch counter cannot express that.
	 * Do not merge the two.
	 */
	nextScanTicket?: number;
	/**
	 * Ticket of the newest scan whose verdict this watch now holds: an
	 * adopted outpoint, a recorded confirmation, and equally an absence or a
	 * presence, which are verdicts about the same question and were once left
	 * out of the arbitration entirely (issue #593).
	 *
	 * Arbitrating on START order rather than on which scan finishes first is
	 * what makes the answer the same in both interleavings. Overlapping scans
	 * are routine (a subscription callback, a block and the recheck timer each
	 * start one) and each holds a history it fetched before its awaits, so
	 * "first to finish wins" discards the fresher evidence half the time.
	 */
	appliedScanTicket?: number;
	/**
	 * Per-txid results of the discovery scan, so each transaction in the
	 * history is fetched once and not again on every recheck. Transactions are
	 * immutable, so both halves keep: `out` is the index of an output paying
	 * the watched script for the watched value (null if none), and `ins` are
	 * the outpoints it spends, as `txid:vout`.
	 */
	discoveryScan?: Map<string, { out: number | null; ins: string[] }>;
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
	/**
	 * This spend was SEEDED from persisted state, not observed by this
	 * watcher, so it has not been verified against the chain yet (issue
	 * #576). The first successful check reports it to the monitor even when
	 * txid and height are unchanged: that report is the live evidence the
	 * monitor's finality clock waits for after a restart. Cleared once
	 * reported (or by the eviction branch, which reports on its own).
	 */
	spendUnverified?: boolean;
	/**
	 * Spend scan arbitration for this outpoint (issues #625, #621). One scan at
	 * a time: calls arriving during it request a single follow-up instead of
	 * queueing, so sweep backpressure cannot build an unbounded backlog and no
	 * scan is ever silenced by a later one starting.
	 *
	 * A script hash notification means the history the active scan fetched may
	 * already be wrong, so it invalidates that scan outright. A recheck carries
	 * no such news and only asks for a re-fetch before the verdict is published.
	 *
	 * `activeScanSequence` is the watcher-wide sequence of the scan running now,
	 * which is what a sibling of the same batched spend consults.
	 */
	scanInFlight: boolean;
	rescanRequested: boolean;
	activeScanInvalidated: boolean;
	activeScanSequence?: number;
}

/**
 * Separates a pre-splice spend watch's registry key from the plain channelId
 * hex every other funding watch is keyed by (issue #479). The pre-splice leg
 * shares a channel with the watch on the post-splice outpoint, so it needs a
 * key of its own; nothing that looks a channel up by id can then reach it.
 */
const PRE_SPLICE_KEY_MARKER = ':presplice:';

/** Registry key for the pre-splice spend watch on one outpoint. */
function preSpliceWatchKey(
	channelId: Buffer,
	txid: string,
	outputIndex: number
): string {
	return `${channelId.toString(
		'hex'
	)}${PRE_SPLICE_KEY_MARKER}${txid}:${outputIndex}`;
}

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
	/**
	 * The least time a run of absent answers must span before
	 * 'funding:missing' fires, on top of the three-check debounce. Scans come
	 * in bursts (a subscription, then status notifications on its heels),
	 * so three absences can land within a hundred milliseconds of a watch
	 * moving to a splice output whose transaction has not been broadcast yet
	 * (issue #672). A real absence persists; a burst is not a verdict.
	 * Defaults to 30 seconds; tests pass 0.
	 */
	missingDebounceMs?: number;
}

const DEFAULT_MISSING_DEBOUNCE_MS = 30_000;

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
 *   tx disappeared from mempool AND chain before confirming (evicted/replaced).
 *   Latched: it fires once per continuous absence, so a consumer running a
 *   per-block policy against it must also poll getFundingPresence (issue #463)
 * - 'funding:recovered' (channelId: Buffer, txid: string): a funding reported
 *   missing is accounted for again, either back in mempool or chain or backed
 *   by provisional on-chain evidence. Edge-triggered on the report clearing,
 *   and the exact counterpart of the 'funding:missing' above (issue #593)
 * - 'funding:discovered' (channelId: Buffer, txid: string): a restored watch
 *   bound to a funding in the script's history that the restored record never
 *   named, having seen it spent by the two parties that alone can (issue #463)
 * - 'funding:presplice-retired' (channelId: Buffer, txid: string,
 *   outputIndex: number): a superseded pre-splice outpoint was seen spent by
 *   the splice, so its extra watch and the durable record behind it retire
 * - 'announcement:depth' (channelId: Buffer, height: number, txIndex: number)
 * - 'output:spent' (txid: string, outputIndex: number)
 * - 'output:unspent' (txid: string, outputIndex: number)
 * - 'watch:output:requested' (txid: string, outputIndex: number): this watcher
 *   needs an output watched and cannot arm it itself
 * - 'block' (height: number)
 * - 'broadcast:success' (txid: string)
 * - 'broadcast:failure' (error: Error)
 * - 'broadcast:permanent_failure' (error: Error): retries exhausted
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
	/**
	 * The full candidate set of the failed watch (post-signatures RBF): the
	 * retry must re-arm ALL of it, or one transient subscription failure
	 * would silently narrow the watch to the current attempt and a mined
	 * older candidate would go unseen (and feed the funding-missing
	 * watchdog instead).
	 */
	candidates?: Array<{ txid: string; outputIndex: number }>;
	/**
	 * Restored watches only: the attempt lineage discovery recognizes an
	 * unnamed replacement by. Carried through the retry for the same reason
	 * the candidate set is: a transient subscription failure must not
	 * silently re-arm a narrower watch than the one that failed, which here
	 * would disable discovery outright and leave the funding-missing watchdog
	 * as the only outcome (issue #463).
	 */
	discoverAttemptInputs?: string[][];
	/**
	 * The registration this failure belongs to. A retry re-registers by map
	 * overwrite, so a queued failure must not be replayed once a NEWER
	 * registration for the same channel has taken its place: an RBF that
	 * re-armed the watch with the replacement's candidate set would be
	 * clobbered back to the stale set, and the attempt that actually
	 * confirmed would go unseen. Identity, not equality: the entry is
	 * replayable only while it is still the watch the map holds.
	 */
	watched: IWatchedFunding;
}

/** A failed output watch queued for retry */
interface IFailedOutputWatch {
	/**
	 * Retry the registered object by identity. Rebuilding it would reset spend
	 * evidence and scan state, while retrying after replacement would revive a
	 * stale watch.
	 */
	key: string;
	watched: IWatchedOutput;
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

/** Spend-scan arbitration state for one channel. */
interface IChannelSpendScan {
	/** Monotonic dispenser: every scan takes the next value when it starts. */
	nextTicket: number;
	/** Ticket of the scan whose verdict the channel's monitor now holds. */
	appliedTicket: number;
	/**
	 * Ticket of the newest scan that ran to COMPLETION, per outpoint
	 * ("txid:vout"). appliedTicket advances only when the monitor applies a
	 * verdict, and a successful no-spend scan of an outpoint the monitor
	 * holds nothing about applies none, so on its own it left an older scan
	 * stalled in getTransaction free to resume afterwards and report a spend
	 * the newer history no longer contained. Per outpoint, because a
	 * completed scan is evidence about ITS outpoint and nothing else.
	 */
	completedByOutpoint: Map<string, number>;
}

export class ChainWatcher extends EventEmitter {
	private backend: IChainBackend;
	private channelManager: ChannelManager;
	private watchedFundings: Map<string, IWatchedFunding> = new Map(); // channelIdHex → funding
	/**
	 * Spend-scan arbitration, per CHANNEL (issues #468, #479).
	 *
	 * A channel has more than one watch once a splice leaves a pre-splice leg
	 * behind, and every one of them reports into the same monitor, so "is my
	 * answer still the freshest" is a question about the channel and not about
	 * one watch. Overlapping scans are routine: a block, a script hash
	 * notification and the recheck timer each start one, and each carries a
	 * history it fetched before its awaits.
	 */
	private channelSpendScans: Map<string, IChannelSpendScan> = new Map();
	private watchedOutputs: Map<string, IWatchedOutput> = new Map(); // "txid:vout" → output
	/**
	 * Dispenser for output spend scans, watcher-wide rather than per outpoint. A
	 * batched spend (a penalty, an aggregated HTLC claim) is one transaction over
	 * several watched outpoints, and the monitor dates every input it spends from
	 * whichever report arrives, so "whose history is fresher" has to be a question
	 * two different outpoints can answer against each other (issue #621).
	 */
	private outputScanSequence = 0;
	/**
	 * The newest verdict each spending transaction has been given, keyed by its
	 * txid. A batched spend is one transaction over several watched outpoints,
	 * and the monitor dates a whole batch from whichever member reports, so the
	 * unit of evidence is the transaction: a per-outpoint counter cannot see a
	 * stale member coming, since that member is the newest scan its own outpoint
	 * ever had (issue #621). A transaction confirms at one height, so a scan that
	 * disagrees with a fresher one about it is simply out of date.
	 *
	 * Read only to decide whether a verdict needs re-checking before it is
	 * published, never to suppress one. A scan silenced by a sibling leaves its
	 * own outpoint unreported to the monitor, which fans a report out only to
	 * outputs already recorded against that transaction, and its watch holding
	 * evidence nothing will come back to correct.
	 */
	private outputSpendVerdicts: Map<
		string,
		{ height?: number; sequence: number }
	> = new Map();
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
	private readonly missingDebounceMs: number;
	private _recheckTimer: ReturnType<typeof setInterval> | null = null;

	constructor(config: IChainWatcherConfig) {
		super();
		this.backend = config.backend;
		this.channelManager = config.channelManager;
		this.destinationScript = config.destinationScript || Buffer.alloc(22);
		this.getSweepFeeRatePerVbyte = config.getSweepFeeRatePerVbyte;
		this.missingDebounceMs =
			config.missingDebounceMs ?? DEFAULT_MISSING_DEBOUNCE_MS;

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
	 * Whether a queued failed funding watch has been overtaken by a newer
	 * registration for the same channel, and must therefore be dropped rather
	 * than retried.
	 *
	 * watchFundingOutput registers by map overwrite, so replaying a stale
	 * entry would reinstate the candidate set (and current txid) of a watch
	 * that has since been replaced — the shape a post-signatures RBF produces
	 * whenever the first registration's subscription failed and the
	 * replacement's succeeded. The confirmed attempt would then be absent from
	 * the watched set and go unnoticed. Compared by identity: the entry stays
	 * replayable only while the map still holds the very object it failed for.
	 */
	private isSupersededFundingWatch(entry: IFailedFundingWatch): boolean {
		return (
			this.watchedFundings.get(entry.channelId.toString('hex')) !==
			entry.watched
		);
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
				if (this.isSupersededFundingWatch(w)) continue;
				this.watchFundingOutput(
					w.channelId,
					w.txid,
					w.outputIndex,
					w.minimumDepth,
					w.scriptPubkey,
					undefined,
					w.candidates,
					w.discoverAttemptInputs
				).catch(() => {
					/* re-queued inside watchFundingOutput */
				});
			}
		}
		// Retry failed output-watch subscriptions.
		this.retryFailedOutputSubscriptions(this.lifecycleGeneration);
		// Re-check unconfirmed fundings and watched output spends directly.
		for (const [key, watched] of this.watchedFundings) {
			if (!watched.confirmed) {
				this.checkFundingConfirmation(key).catch((err) => this.emitError(err));
				continue;
			}
			// A CONFIRMED watch is looking for one thing: the spend that closes
			// the channel. Its spend subscription can have failed, or been lost
			// with a reconnect, and nothing else would ever look again, so the
			// close would sit on chain unhandled forever. Fully resolved
			// watches are retired by the node, so anything still here is still
			// waiting for that spend (issue #463).
			this.checkFundingSpent(watched, this.lifecycleGeneration, key).catch(
				(err) => this.emitError(err)
			);
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
		// Any pre-splice spend watch goes with it: the callers are the
		// channel:resolved handler and the funding-missing void, and after
		// either there is no channel left for a breach to be reported against
		// (issue #479). The return still answers for the channel's own entry.
		for (const key of this.preSpliceWatchKeysFor(channelId)) {
			this.watchedFundings.delete(key);
		}
		// Safe to drop the channel's spend-scan arbitration with its watches: a
		// scan still in flight is retired by the map-identity guard, which no
		// longer finds its watch, whatever the ticket state says.
		this.channelSpendScans.delete(channelId.toString('hex'));
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
		this.channelSpendScans.clear();
		this.watchedOutputs.clear();
		this.outputSpendVerdicts.clear();
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
		generation: number = this.lifecycleGeneration,
		// Post-signatures RBF: every candidate funding tx of this open
		// (display-order txids). All candidates pay scriptPubkey.
		candidates?: Array<{ txid: string; outputIndex: number }>,
		// Restored records only: the input lineage of every attempt the record
		// knows, to recognize a replacement it does not name (see
		// discoverAttemptInputs).
		discoverAttemptInputs?: string[][]
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
			announcementTriggered: false,
			candidates: candidates?.length ? candidates : undefined,
			script: scriptPubkey,
			discoverAttemptInputs: discoverAttemptInputs?.length
				? discoverAttemptInputs
				: undefined
		};

		this.watchedFundings.set(key, watched);

		// Subscribe to the funding script hash — queue for retry on failure
		try {
			await this.backend.subscribeToScriptHash(scriptHash, () => {
				// The backend retains this callback across reconnects, so a
				// callback registered before a stop() must not start a check that
				// captures the current generation and passes every guard.
				if (!this.isCurrentGeneration(generation)) return;
				this.onFundingScriptHashChange(key, generation);
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
					scriptPubkey,
					// Defensive copy: the retry must re-arm the full candidate
					// set, and the caller's array must not mutate under it.
					candidates: candidates?.length
						? candidates.map((c) => ({ ...c }))
						: undefined,
					discoverAttemptInputs,
					watched
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
	 * to handleFundingSpent (the breach path).
	 *
	 * The watch is held in watchedFundings under its OWN key (issue #479). It
	 * used to be held nowhere, so that it could not collide with the channel's
	 * new-outpoint watch, and the price was that neither recheckAllWatches nor
	 * handleNewBlock ever looked at it again: the outpoint got one check at arm
	 * time plus a script hash subscription the real Electrum client drops
	 * (issue #478), and a breach broadcast after that went undetected until a
	 * restart re-armed the watch. Keyed per OUTPOINT rather than per channel,
	 * because completeSplice nulls spliceInFlight as soon as splice_locked is
	 * sent, which on a zero-conf channel is the same action batch as the
	 * broadcast, so a second splice can legitimately need a second leg while the
	 * first one's tx is still unconfirmed.
	 *
	 * A confirmed, announcement-triggered entry falls straight through both
	 * sweep loops to checkFundingSpent, so re-polling, the map-identity guard
	 * and the stop() teardown all come for free.
	 */
	async watchFundingSpendDuringSplice(
		channelId: Buffer,
		txid: string,
		outputIndex: number,
		scriptPubkey: Buffer,
		ignoreSpendTxid: string
	): Promise<void> {
		// Read here, never accepted from the caller. The node keeps a startup
		// counter of its own with the same TYPE, so a caller passing "the
		// generation my operation started in" could hand this one a number from
		// the wrong object, and every arm would then return below without a
		// trace: no registry entry, no error, and nothing for the recheck timer
		// to recover. No caller outside this class has a value worth passing.
		const generation = this.lifecycleGeneration;
		// Ahead of the map write, not just inside watchFundingSpend: an outer
		// operation that began before stop() can still call in for the first
		// time afterwards, and an entry inserted then would survive into the
		// next start() and be swept against a channel that may be gone.
		if (!this.isCurrentGeneration(generation)) return;
		const key = preSpliceWatchKey(channelId, txid, outputIndex);
		const scriptHash = computeScriptHash(scriptPubkey);
		// Idempotent per outpoint. Re-arming is routine now that the channel
		// emits it in the batch reaching the point of no return as well as on
		// every watch:funding and at startup, and replacing a live entry with
		// an equivalent one would retire whatever scan is in flight against it
		// through the map-identity guard, for nothing.
		const existing = this.watchedFundings.get(key);
		if (
			existing &&
			existing.scriptHash === scriptHash &&
			existing.ignoreSpendTxid === ignoreSpendTxid
		) {
			return;
		}
		const watched: IWatchedFunding = {
			channelId,
			txid,
			outputIndex,
			minimumDepth: 0,
			scriptHash,
			script: scriptPubkey,
			confirmed: true,
			confirmationHeight: 0,
			announcementTriggered: true,
			ignoreSpendTxid
		};
		this.watchedFundings.set(key, watched);

		// The pre-splice leg's ONLY script hash subscription: the channel's
		// new-outpoint watch subscribes its own script in watchFundingOutput,
		// and nothing else covers this outpoint. Subscribed here rather than
		// in watchFundingSpend, which every confirmed channel watch also
		// reaches while already holding watchFundingOutput's subscription: a
		// second one there made every notification start two spend scans. The
		// callback routes through the same phase dispatcher, which re-reads
		// the watch from the registry, so a retired leg costs a map miss
		// rather than a stale scan. A failure must not cost the immediate
		// check below; the entry is registered, so the per-block sweeps
		// re-poll it regardless (issue #463).
		try {
			await this.backend.subscribeToScriptHash(scriptHash, () => {
				if (!this.isCurrentGeneration(generation)) return;
				this.onFundingScriptHashChange(key, generation);
			});
		} catch (err) {
			this.emitError(err as Error);
		}

		await this.watchFundingSpend(watched, generation, key);

		// Same retirement watchFundingOutput performs after its own awaits: a
		// registration overtaken by a stop() or by a newer one for the same
		// outpoint must not leave this entry behind.
		if (
			!this.isCurrentGeneration(generation) &&
			this.watchedFundings.get(key) === watched
		) {
			this.watchedFundings.delete(key);
		}
	}

	/**
	 * Every pre-splice spend watch armed for this channel (issue #479). Read
	 * off the registry rather than tracked separately, so retirement has one
	 * home.
	 */
	private preSpliceWatchKeysFor(channelId: Buffer): string[] {
		const prefix = `${channelId.toString('hex')}${PRE_SPLICE_KEY_MARKER}`;
		const keys: string[] = [];
		for (const key of this.watchedFundings.keys()) {
			if (key.startsWith(prefix)) keys.push(key);
		}
		return keys;
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
			spendHeight,
			scanInFlight: false,
			rescanRequested: false,
			activeScanInvalidated: false,
			// A seeded spend is recorded state, not something this watcher
			// saw: the monitor's finality clock stays parked until the first
			// live check confirms it (issue #576).
			...(spendTxid !== undefined ? { spendUnverified: true } : {})
		};
		this.watchedOutputs.set(key, watched);

		await this.subscribeToOutputSpend(key, watched, generation);

		// Retired while subscribing: drop our own entry if it somehow outlived
		// the clear in stop(). Never touch an entry a later generation owns.
		if (
			!this.isCurrentGeneration(generation) &&
			this.watchedOutputs.get(key) === watched
		) {
			this.watchedOutputs.delete(key);
		}
	}

	private async subscribeToOutputSpend(
		key: string,
		watched: IWatchedOutput,
		generation: number
	): Promise<void> {
		try {
			await this.backend.subscribeToScriptHash(watched.scriptHash, () => {
				// The backend retains this callback and re-invokes it across
				// reconnects; stop() cannot reach into it. Without this check a
				// callback registered before a stop could start a fresh check that
				// captured the CURRENT generation and passed every guard.
				if (!this.isCurrentGeneration(generation)) return;
				this.checkOutputSpend(key, generation, true).catch((err) => {
					this.emitError(err);
				});
			});
		} catch {
			// Queue for retry on next block, unless the watch was retired while
			// the subscription was in flight: stop() clears this queue, and
			// repopulating it afterwards revives a stale watch on the next start.
			if (
				this.isCurrentGeneration(generation) &&
				this.watchedOutputs.get(key) === watched &&
				!this.failedOutputWatches.some((entry) => entry.watched === watched)
			) {
				this.failedOutputWatches.push({ key, watched });
			}
		}
	}

	private retryFailedOutputSubscriptions(generation: number): void {
		if (this.failedOutputWatches.length === 0) return;
		const pending = [...this.failedOutputWatches];
		this.failedOutputWatches = [];
		for (const entry of pending) {
			if (this.watchedOutputs.get(entry.key) !== entry.watched) continue;
			this.subscribeToOutputSpend(entry.key, entry.watched, generation).catch(
				(err) => this.emitError(err)
			);
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
		// Post-signatures RBF: superseded broadcastable attempts can still
		// confirm (they pay the same funding script), so the watch carries
		// every candidate outpoint alongside the armed attempt's.
		const previous = state.v2PreviousAttempts ?? [];
		const candidates = previous.length
			? [
					{ txid: displayTxid, outputIndex: fundingOutputIndex },
					...previous.map((rec) => ({
						txid: Buffer.from(rec.fundingTxid).reverse().toString('hex'),
						outputIndex: rec.fundingOutputIndex
					}))
			  ]
			: undefined;
		this.watchFundingOutput(
			channelId,
			displayTxid,
			fundingOutputIndex,
			minimumDepth,
			fundingScript,
			undefined,
			candidates
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
				if (this.isSupersededFundingWatch(watch)) continue;
				this.watchFundingOutput(
					watch.channelId,
					watch.txid,
					watch.outputIndex,
					watch.minimumDepth,
					watch.scriptPubkey,
					undefined,
					watch.candidates,
					watch.discoverAttemptInputs
				).catch(() => {
					// Still failing — already re-queued inside watchFundingOutput
				});
			}
		}

		// Retry failed output watch subscriptions
		this.retryFailedOutputSubscriptions(generation);

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

		// Check all watched fundings for confirmation, announcement depth and
		// the spend that closes the channel.
		for (const [key, watched] of this.watchedFundings) {
			if (!watched.confirmed) {
				this.checkFundingConfirmation(key, generation).catch((err) => {
					this.emitError(err);
				});
				continue;
			}
			if (!watched.announcementTriggered && watched.confirmationHeight > 0) {
				// Check if 6 confirmations reached for channel announcement
				const depth = height - watched.confirmationHeight + 1;
				if (depth >= 6) {
					watched.announcementTriggered = true;
					this.triggerAnnouncementDepth(watched).catch((err) => {
						this.emitError(err);
					});
				}
			}
			// A confirmed watch is waiting for exactly one thing: the spend that
			// closes the channel. A block is the event that can turn "no spend"
			// into "spend", and the header subscription is the one notification
			// this watcher can rely on being delivered, so the close is found
			// here rather than whenever the 60s recheck timer next happens to
			// fire (issue #468). Nothing new is asked of the backend either:
			// recheckAllWatches already runs this same sweep, ten times more
			// often than a block arrives on mainnet.
			this.checkFundingSpent(watched, generation, key).catch((err) => {
				this.emitError(err);
			});
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

	/**
	 * Route a funding script hash notification to whichever check the watch is
	 * still waiting on: the confirmation before minimumDepth, and after it the
	 * spend that closes the channel.
	 *
	 * One callback covers both phases so each watch subscribes its script hash
	 * exactly once. It first existed because the Electrum client answered a
	 * repeat subscription with "Already Subscribed." and never wired the new
	 * callback, leaving the confirmation callback (which returns on its first
	 * line once the watch is confirmed) the only one delivered, so a close had
	 * nothing pushing it and waited on the recheck timer (issue #468). Now that
	 * the backend delivers a notification to EVERY callback registered for a
	 * script hash (issue #478), the single phase-routed subscription is also
	 * what keeps one notification to one scan.
	 */
	private onFundingScriptHashChange(key: string, generation: number): void {
		const watched = this.watchedFundings.get(key);
		if (!watched) return;
		if (!watched.confirmed) {
			this.checkFundingConfirmation(key, generation).catch((err) => {
				this.emitError(err);
			});
			return;
		}
		this.checkFundingSpent(watched, generation, key).catch((err) => {
			this.emitError(err);
		});
	}

	/**
	 * The funding is accounted for: reset the absence debounce and, if an
	 * absence was actually REPORTED, tell listeners it is over (issue #593).
	 *
	 * One helper rather than an assignment at each site, because a consumer
	 * holding a restriction raised by 'funding:missing' needs the counterpart
	 * from EVERY arm that clears the report, not just the one that motivated
	 * it: a lift that a provisional finding reaches but a mempool reappearance
	 * does not is a channel left quarantined by the arm nobody wired.
	 * Edge-triggered, so an ordinary present check emits nothing.
	 */
	private clearMissingReport(watched: IWatchedFunding): void {
		watched.missingChecks = 0;
		watched.missingSince = undefined;
		if (!watched.missingReported) return;
		watched.missingReported = false;
		this.emit('funding:recovered', watched.channelId, watched.txid);
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
		// Checks for one watch can overlap (a subscription callback, a block
		// and the recheck timer all start them), and each one holds a history
		// it fetched before its awaits. Whatever this scan concludes is only
		// safe to apply while no scan that STARTED LATER has concluded
		// anything since: its history is the fresher of the two.
		const ticket = watched.nextScanTicket ?? 0;
		watched.nextScanTicket = ticket + 1;
		const superseded = (): boolean =>
			!this.isCurrentGeneration(generation) ||
			this.watchedFundings.get(key) !== watched ||
			watched.confirmed ||
			(watched.appliedScanTicket ?? -1) > ticket;

		const history = await this.backend.getScriptHashHistory(watched.scriptHash);

		// stop() may have run while that request was in flight. Acting now would
		// advance the ChannelManager for a watcher that is no longer watching,
		// and the map identity check catches the entry being replaced by a
		// restart rather than merely cleared.
		if (superseded()) return;

		// Find our funding tx in the history. With RBF candidates the set is
		// "any attempt of this open": the attempts double-spend one another,
		// so at most one can confirm, and the replaced ones legitimately
		// vanish from the mempool — absence only matters when EVERY candidate
		// is gone.
		const candidates = watched.candidates?.length
			? watched.candidates
			: [{ txid: watched.txid, outputIndex: watched.outputIndex }];
		let entries = history.filter((h) =>
			candidates.some((c) => c.txid === h.txid)
		);
		if (entries.length > 0) {
			// The recorded attempt answers for itself; nothing provisional
			// applies any more.
			watched.provisional = undefined;
		} else if (watched.discoverAttemptInputs?.length) {
			// A restored record whose attempt the chain does not know: read the
			// funding out of the history instead of insisting on the txid the
			// record happens to name (issue #463).
			const discovery = await this.discoverRestoredFunding(
				watched,
				history,
				superseded
			);
			if (superseded()) return;
			// A scan that could not read the whole history and found nothing has
			// concluded nothing: its empty candidate set may be no more than the
			// entries it failed to fetch. Recording that would wipe the set an
			// older but COMPLETE scan is about to report, and claiming the ticket
			// would silence that scan for good, leaving live funding marked
			// absent. Candidates it did find still count, because an unreadable
			// entry can only add to the set.
			if (
				!discovery.complete &&
				!discovery.bound &&
				!discovery.provisional?.length
			) {
				return;
			}
			// The candidate set is a verdict about the same question absence and
			// presence answer, so it is applied HERE, under the scan-order check,
			// and never inside the scan that computed it. Discovery reads the
			// whole history a transaction at a time, which is the longest stall in
			// this method: a scan overtaken in there would otherwise restore
			// candidates the newer scan already found gone, and a stale 'present'
			// lifts a missing-funding quarantine and stops BOLT 2's forget clock
			// (issue #624).
			watched.appliedScanTicket = ticket;
			watched.provisional = discovery.provisional;
			if (discovery.bound) {
				const bound = discovery.bound;
				watched.txid = bound.txid;
				watched.outputIndex = bound.outputIndex;
				watched.candidates = undefined;
				watched.provisional = undefined;
				watched.discoveryScan = undefined;
				this.emit('funding:discovered', watched.channelId, bound.txid);
				entries = history.filter((h) => h.txid === bound.txid);
			} else if (!discovery.complete) {
				// Part of the history could not be read, so this scan does not
				// know whether the funding is there. Absence is a verdict and
				// this is not one: leave the debounce untouched and ask again.
				// It reached here holding candidates, so the ticket above stands:
				// that set is the newest answer anything has to that question.
				return;
			} else if (watched.provisional?.length) {
				// Unproven but real enough to stop the clock: something is
				// sitting on chain that pays this channel's funding script for
				// its funding value. It is NOT reported as a confirmation and
				// the watched outpoint does not move, because the evidence
				// that it is ours has not arrived yet.
				this.clearMissingReport(watched);
				return;
			}
		}
		if (entries.length === 0) {
			// No funding candidate is in the mempool or a block: evicted or
			// replaced (e.g. an input double-spent by a foreign tx). For a
			// zero-conf channel that is already NORMAL this means the channel
			// no longer exists on the network. Alarm after a debounce so a
			// transient Electrum hiccup does not cry wolf.
			watched.appliedScanTicket = ticket;
			watched.missingChecks = (watched.missingChecks ?? 0) + 1;
			watched.missingSince ??= Date.now();
			if (
				watched.missingChecks >= 3 &&
				Date.now() - watched.missingSince >= this.missingDebounceMs &&
				!watched.missingReported
			) {
				watched.missingReported = true;
				this.emit('funding:missing', watched.channelId, watched.txid);
			}
			return;
		}
		// Present again (mempool or chain): a reorg can bounce a tx back.
		watched.appliedScanTicket = ticket;
		this.clearMissingReport(watched);
		const entry = entries.find((h) => h.height > 0);
		if (!entry) return; // in the mempool, not yet confirmed

		// Calculate confirmations
		const confirmations = this.currentBlockHeight - entry.height + 1;
		if (confirmations >= watched.minimumDepth) {
			// Adopt the winning candidate into the watch itself, so spend
			// detection and the announcement proof key off the tx that is
			// actually on chain. Re-read the candidate set from the watch:
			// discovery above can have bound an outpoint the set computed at
			// the top of this method never held, and indexing that stale array
			// threw rather than adopting.
			const active = watched.candidates?.length
				? watched.candidates
				: [{ txid: watched.txid, outputIndex: watched.outputIndex }];
			const winner = active.find((c) => c.txid === entry.txid);
			if (!winner) return;
			watched.appliedScanTicket = ticket;
			watched.txid = winner.txid;
			watched.outputIndex = winner.outputIndex;
			watched.candidates = undefined;
			watched.confirmed = true;
			watched.confirmationHeight = entry.height;

			this.channelManager.handleFundingConfirmed(
				watched.channelId,
				watched.txid
			);
			this.emit('funding:confirmed', watched.channelId, watched.txid);

			// Now watch for the funding output being spent (force close detection)
			this.watchFundingSpend(watched, generation, key).catch((err) => {
				this.emitError(err);
			});
		}
	}

	/**
	 * Two-phase discovery of a restored channel's funding, for a watch whose
	 * recorded attempts the chain does not know.
	 *
	 * Phase one collects PROVISIONAL candidates: confirmed transactions in the
	 * funding script's history that pay that script and share an input with
	 * every attempt the record knows. That lineage is what identifies the
	 * funding, because neither the script nor the value can. See
	 * discoverAttemptInputs. Nothing is bound on it: an attacker cannot forge
	 * the lineage, but a candidate that merely looks like a replacement is
	 * still not known to be the one this channel ended up with.
	 *
	 * Phase two waits for one of those outputs to be SPENT, and binds to that
	 * one. The output pays a 2-of-2 of this channel's funding pubkeys, so a
	 * spend of it exists only because both parties signed one. Lineage says
	 * the coins came from this negotiation; the spend says the negotiation
	 * finished on this outpoint. A candidate that is never spent stays
	 * provisional, which is the honest answer: the channel is not forgotten,
	 * and nothing has shown which output is the one that funded it.
	 *
	 * `complete` is false when any history entry could not be read. An
	 * incomplete scan must never be reported as absence: a backend that fails
	 * selectively would otherwise run BOLT 2's forget clock against a funding
	 * that is sitting on chain.
	 *
	 * Reports the candidate set rather than writing it to the watch (issue
	 * #624). Every transaction in the history is an await this scan can be
	 * overtaken in, and the caller is where the scan-order check lives, so the
	 * result is applied there or not at all. `superseded` is that same check,
	 * so a scan already answered for stops fetching instead of reading out a
	 * history nothing will use.
	 */
	private async discoverRestoredFunding(
		watched: IWatchedFunding,
		history: Array<{ txid: string; height: number }>,
		superseded: () => boolean
	): Promise<{
		bound: { txid: string; outputIndex: number } | null;
		complete: boolean;
		provisional:
			| Array<{ txid: string; outputIndex: number; height: number }>
			| undefined;
	}> {
		const lineage = watched.discoverAttemptInputs ?? [];
		if (lineage.length === 0) {
			return { bound: null, complete: true, provisional: undefined };
		}
		const scan = (watched.discoveryScan ??= new Map());
		let complete = true;
		for (const entry of history) {
			if (scan.has(entry.txid)) continue;
			let tx: import('bitcoinjs-lib').Transaction;
			try {
				const raw = await this.backend.getTransaction(entry.txid);
				if (superseded()) {
					return { bound: null, complete: false, provisional: undefined };
				}
				tx = bitcoin.Transaction.fromBuffer(raw);
			} catch {
				// Not cached as a verdict: the next check asks again, and until
				// it can be read this scan knows less than the whole history.
				complete = false;
				continue;
			}
			const out = tx.outs.findIndex((o) => o.script.equals(watched.script));
			scan.set(entry.txid, {
				out: out < 0 ? null : out,
				ins: tx.ins.map(
					(i) => `${Buffer.from(i.hash).reverse().toString('hex')}:${i.index}`
				)
			});
		}

		// Phase one: confirmed, pays the script, and descends from every
		// attempt the record knows. Ordered by depth so a bind has a stable
		// order to choose in.
		const provisional = history
			.filter((h) => {
				if (h.height <= 0) return false;
				const scanned = scan.get(h.txid);
				if (!scanned || scanned.out == null) return false;
				return lineage.every((attemptInputs) =>
					attemptInputs.some((outpoint) => scanned.ins.includes(outpoint))
				);
			})
			.map((h) => ({
				txid: h.txid,
				outputIndex: scan.get(h.txid)!.out!,
				height: h.height
			}))
			.sort((a, b) => a.height - b.height);
		const found = provisional.length ? provisional : undefined;
		if (provisional.length === 0) {
			return { bound: null, complete, provisional: found };
		}

		// Phase two: one of them spent, by anyone, at any depth.
		const spent = new Set<string>();
		for (const [, scanned] of scan) {
			for (const outpoint of scanned.ins) spent.add(outpoint);
		}
		for (const candidate of provisional) {
			if (!spent.has(`${candidate.txid}:${candidate.outputIndex}`)) continue;
			return {
				bound: { txid: candidate.txid, outputIndex: candidate.outputIndex },
				complete,
				provisional: found
			};
		}
		return { bound: null, complete, provisional: found };
	}

	/**
	 * Whether this watch is holding an unproven funding: something on chain
	 * descends from the recorded attempts and pays the funding script, but
	 * nothing has spent it, so the channel cannot be resolved and must not be
	 * forgotten either (issue #463).
	 */
	hasProvisionalFunding(channelId: Buffer): boolean {
		const watched = this.watchedFundings.get(channelId.toString('hex'));
		return !!watched?.provisional?.length;
	}

	/**
	 * Presence of a watched funding as the chain last answered it, for the
	 * node's per-block review of the BOLT 2 forget clock (issue #463).
	 * 'unknown' until a check has actually succeeded, and until the absence
	 * debounce has run its course, so a restart never reads a fresh watch as
	 * evidence of anything.
	 */
	getFundingPresence(channelId: Buffer): 'present' | 'absent' | 'unknown' {
		const watched = this.watchedFundings.get(channelId.toString('hex'));
		if (!watched) return 'unknown';
		if (watched.confirmed || watched.missingChecks === 0) return 'present';
		// Something on chain pays this channel's funding script for its
		// funding value. Unproven, but not absent: the BOLT 2 forget clock
		// must not run against it (issue #463).
		if (watched.provisional?.length) return 'present';
		if (watched.missingReported) return 'absent';
		return 'unknown';
	}

	private async watchFundingSpend(
		watched: IWatchedFunding,
		generation: number = this.lifecycleGeneration,
		// Registry key of this watch. Required: every watch this class arms is
		// held in watchedFundings, the pre-splice legs included since issue
		// #479, and the map-identity guard the key enables is what retires a
		// scan whose watch was replaced or whose channel is gone.
		key: string
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		// No subscription of its own. Every watch reaching this method already
		// holds one whose callback dispatches by phase
		// (onFundingScriptHashChange): the channel watches from
		// watchFundingOutput, the pre-splice legs from
		// watchFundingSpendDuringSplice. The backend delivers a notification
		// to EVERY callback registered for a script hash (issue #478), so a
		// second subscription here made each notification start two identical
		// spend scans, arbitrated only after both history requests had begun.

		// Immediately check if the output was already spent (e.g., after restart
		// where the force-close tx was confirmed while we were offline).
		//
		// Guarded for the same reason the subscribe above is, and the same
		// reason watchFundingOutput guards its own immediate check: ARMING must
		// not fail because the first look failed. An Electrum error here used
		// to propagate out of watchFundingSpendDuringSplice and abort the
		// caller's entire restore loop, taking every later channel's watch, the
		// pending-broadcast retries and the reconnect monitor with it. The scan
		// itself keeps throwing for its other launch sites, which catch.
		try {
			await this.checkFundingSpent(watched, generation, key);
		} catch (err) {
			this.emitError(err as Error);
		}
	}

	private async checkFundingSpent(
		watched: IWatchedFunding,
		// The lifecycle generation the CALLER started in, not a fresh read: a
		// stop() during this scan's awaits must retire it, and capturing here
		// would pick up the post-stop value and pass every guard.
		generation: number = this.lifecycleGeneration,
		// Registry key of this watch. Required: a pre-splice leg is held in
		// watchedFundings under its own per-outpoint key since issue #479, so
		// there is no longer a watch this cannot be compared against.
		key: string
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		// Whatever this scan concludes is only safe to apply while it is still
		// answering for the current watch and no FRESHER scan of this channel
		// has concluded anything since it started. A splice replaces the
		// channel's watch with one on the new outpoint, and a scan still
		// running against the old one would report the splice tx itself as the
		// close; a scan that started earlier and finished later would demote a
		// confirmation back to the mempool height it happened to fetch (issue
		// #468).
		//
		// The ticket is taken here, before the first await, because it records
		// when this scan's evidence was gathered.
		const idHex = watched.channelId.toString('hex');
		const outKey = `${watched.txid}:${watched.outputIndex}`;
		const ticket = this.beginSpendScan(idHex);
		const superseded = (): boolean =>
			!this.isCurrentGeneration(generation) ||
			this.watchedFundings.get(key) !== watched ||
			this.spendScanOvertaken(idHex, ticket) ||
			this.outpointScanOvertaken(idHex, outKey, ticket);

		const history = await this.backend.getScriptHashHistory(watched.scriptHash);
		if (superseded()) return;

		// Look for the transaction that spends our funding output. The script's
		// history can contain MULTIPLE non-spending entries sharing the same
		// script — splices reuse the 2-of-2 funding script, so every funding
		// generation (and the splice txs between them) appears here. Checking
		// only the first non-self entry therefore missed real closes; every
		// candidate must be examined. Include both confirmed (height > 0) and
		// mempool (height <= 0) spends.
		//
		// A pre-splice leg retires on its own evidence, so the one entry it
		// skips by name is remembered rather than merely skipped (issue #479).
		let ignoredSpend: { txid: string; height: number } | null = null;
		// An expected spender is a property of the OUTPOINT, not of one watch.
		// Between our splice tx_signatures leaving and the broadcast, the
		// channel's own funding watch is still on the old outpoint and carries
		// no ignore of its own, so a peer that assembles and publishes the
		// splice while withholding its signatures would be reported by that
		// watch as a spend of the funding - and classification has no branch
		// for "this is a splice", so the channel gets marked closed on chain
		// while it is very much alive. The leg vouches for the splice on behalf
		// of every watch of the same outpoint.
		const expectedSpender = this.expectedSpenderFor(watched);

		for (const entry of history) {
			if (entry.txid === watched.txid) continue;
			// A legitimate splice spends the pre-splice funding output; only a
			// DIFFERENT spender (a revoked/force-close commitment) is a breach.
			if (expectedSpender !== undefined && entry.txid === expectedSpender) {
				// Only the leg itself retires on this evidence, so only the leg
				// remembers it: see the retirement branch below.
				if (entry.height > 0 && entry.txid === watched.ignoreSpendTxid) {
					ignoredSpend = { txid: entry.txid, height: entry.height };
				}
				continue;
			}

			const rawTx = await this.backend.getTransaction(entry.txid);
			if (superseded()) return;
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
			this.recordSpendVerdict(idHex, ticket);
			this.recordScanCompleted(idHex, outKey, ticket);
			this.channelManager.handleFundingSpent(
				watched.channelId,
				spendingTx,
				height,
				this.destinationScript,
				this.getSweepFeeRatePerVbyte?.() ?? 10,
				undefined,
				undefined,
				undefined,
				// WHICH outpoint this spends is what the monitor records as its
				// own durable ownership of the channel's spend verdict, and the
				// only thing that lets a retraction be scoped correctly after a
				// restart (issue #479). Last in the list because the arguments
				// before it are a published API this must not renumber.
				{ txid: watched.txid, outputIndex: watched.outputIndex }
			);
			this.emit('funding:spent', watched.channelId, spendingTx);
			return;
		}

		// No breach on a pre-splice leg, and the splice tx it exists to ignore
		// is buried: the old outpoint is spent for good, so the leg retires
		// itself (issue #479). Depth is the right signal and splice_locked is
		// not: on a zero-conf channel splice_locked leaves in the same action
		// batch as the broadcast, so retiring on it would drop the watch inside
		// the very window a mempool-eviction breach lives in. A reorg that
		// un-confirms the splice tx simply leaves the leg armed.
		if (
			// The leg's own evidence about its own expected spender. The
			// channel's own watch may share the skip above, but it must not
			// retire a leg it does not own.
			watched.ignoreSpendTxid !== undefined &&
			ignoredSpend !== null &&
			this.currentBlockHeight > 0 &&
			// The monitor's own boundary, `blockHeight - confirmationHeight >=
			// IRREVOCABLE_DEPTH` (chain-monitor.ts, OUTPUT_RESOLVED). A `+ 1`
			// depth here would retire a block EARLY, which for a breach watch
			// means going blind for the last block before the spend is
			// irrevocable.
			this.currentBlockHeight - ignoredSpend.height >= IRREVOCABLE_DEPTH
		) {
			// Confirm it really spent THIS outpoint before acting on it. The
			// funding script is shared by every splice generation, so a txid
			// sitting in that history proves it is on chain and nothing more,
			// and reading the wrong one as final would retire a breach watch
			// early. The fetch is gated on the depth test, so it happens once,
			// at retirement, and not on every sweep.
			const rawIgnored = await this.backend.getTransaction(ignoredSpend.txid);
			if (superseded()) return;
			const ignoredTx = bitcoin.Transaction.fromBuffer(rawIgnored);
			const spendsOurs = ignoredTx.ins.some((input) => {
				const inputTxid = Buffer.from(input.hash).reverse().toString('hex');
				return (
					inputTxid === watched.txid && input.index === watched.outputIndex
				);
			});
			if (spendsOurs && this.watchedFundings.get(key) === watched) {
				this.recordScanCompleted(idHex, outKey, ticket);
				this.watchedFundings.delete(key);
				// The node keeps a durable record of this outpoint so a restart
				// can re-arm the watch; retiring the watch retires that too
				// (issue #479).
				this.emit(
					'funding:presplice-retired',
					watched.channelId,
					watched.txid,
					watched.outputIndex
				);
				return;
			}
		}

		// History fetched successfully and NO spender of THIS outpoint found. If
		// the channel's monitor has a confirmed spend recorded, that spend was
		// reorged out without even re-entering the mempool, and its
		// irrevocable-depth clock must stop counting against the vanished
		// height (issue 352). No-op for a channel with no recorded spend.
		//
		// WHICH watch may say that is no longer decided here (issue #479). A
		// channel has more than one watch once a splice leaves a pre-splice leg
		// behind, and this watcher used to answer it from a flag it kept in
		// memory: after a restart nothing owned the verdict, a re-armed leg
		// could not retract a breach it had itself reported, and the finality
		// clock ran on against a height no longer in the chain.
		//
		// So the scan reports the outpoint it is evidence about, plus the one
		// spender it deliberately ignores, and the MONITOR decides. Its record
		// carries the outpoint it belongs to and is persisted, so ownership
		// survives the process. A sibling's silence and a leg's silence then
		// fall out of the same question instead of needing rules of their own.
		const retracted =
			this.channelManager.handleFundingSpendAbsent?.(
				watched.channelId,
				{
					txid: watched.txid,
					outputIndex: watched.outputIndex,
					// The channel-scoped answer, not this watch's own field: during
					// the splice window the channel's own watch shares the leg's
					// expected spender, and without it here that watch would offer
					// to retract a monitor record of the splice transaction itself
					// - a demotion nothing could ever undo.
					expectedSpendTxid: expectedSpender
				},
				// Prices the CPFP the manager re-arms when this retraction demotes
				// our own confirmed commitment (issue #578).
				this.getSweepFeeRatePerVbyte?.() ?? 10
			) ?? false;
		// Completion advances the outpoint's freshness whether or not the
		// monitor had anything to retract: this scan's history IS the newest
		// evidence about the outpoint, and an older scan still stalled in an
		// await must retire against it rather than resume and report a spend
		// this history no longer contains.
		this.recordScanCompleted(idHex, outKey, ticket);
		if (retracted) this.recordSpendVerdict(idHex, ticket);
	}

	/**
	 * The transaction some watch of this channel expects to spend `watched`'s
	 * outpoint, and which is therefore not a breach (issue #479).
	 *
	 * Read across the channel's watches rather than off the one scanning,
	 * because during a splice two of them cover the same outpoint: the leg,
	 * which knows the splice transaction by name, and the channel's own
	 * funding watch, which does not and would otherwise report that
	 * transaction as the close. Self-correcting: once WATCH_FUNDING moves the
	 * channel's watch to the new outpoint the two no longer match, and it is
	 * restart-safe because the leg is re-armed from disk.
	 */
	private expectedSpenderFor(watched: IWatchedFunding): string | undefined {
		const idHex = watched.channelId.toString('hex');
		for (const other of this.watchedFundings.values()) {
			if (other.ignoreSpendTxid === undefined) continue;
			if (other.channelId.toString('hex') !== idHex) continue;
			if (other.txid !== watched.txid) continue;
			if (other.outputIndex !== watched.outputIndex) continue;
			// At most one: legs are keyed per outpoint, and the channel's own
			// funding watch never carries an ignore of its own.
			return other.ignoreSpendTxid;
		}
		return undefined;
	}

	/**
	 * A ticket for a spend scan starting now. Taken BEFORE the scan's first
	 * await, so it records when the scan's evidence was gathered.
	 */
	private beginSpendScan(idHex: string): number {
		const state = this.channelSpendScans.get(idHex) ?? {
			nextTicket: 0,
			appliedTicket: 0,
			completedByOutpoint: new Map<string, number>()
		};
		this.channelSpendScans.set(idHex, state);
		return ++state.nextTicket;
	}

	/**
	 * Whether a scan that STARTED LATER than this one has already applied a
	 * verdict for the channel.
	 *
	 * Start order, not completion order. The later scan holds the fresher
	 * history whichever of the two happens to finish first, so arbitrating on
	 * completion gets one of the two interleavings wrong: it discards a
	 * canonical scan that began after an older one and merely finished behind
	 * it.
	 */
	private spendScanOvertaken(idHex: string, ticket: number): boolean {
		return (this.channelSpendScans.get(idHex)?.appliedTicket ?? 0) > ticket;
	}

	/**
	 * Whether a scan of the SAME outpoint that started later than this one has
	 * already run to completion. Completion, not application: a successful
	 * no-spend scan applies no verdict when the monitor is still WATCHING, so
	 * the channel-wide appliedTicket never moved, and an older scan stalled in
	 * getTransaction could resume afterwards and report a spend the newer
	 * history had already dropped. Scoped per outpoint because a completed
	 * scan is evidence about its own outpoint only; verdicts the monitor
	 * actually applied keep arbitrating channel-wide via appliedTicket.
	 */
	private outpointScanOvertaken(
		idHex: string,
		outKey: string,
		ticket: number
	): boolean {
		return (
			(this.channelSpendScans.get(idHex)?.completedByOutpoint.get(outKey) ??
				0) > ticket
		);
	}

	/** Record that this scan of this outpoint ran to completion. */
	private recordScanCompleted(
		idHex: string,
		outKey: string,
		ticket: number
	): void {
		const state = this.channelSpendScans.get(idHex);
		if (!state) return;
		const prev = state.completedByOutpoint.get(outKey) ?? 0;
		if (ticket > prev) state.completedByOutpoint.set(outKey, ticket);
	}

	/**
	 * Record that this scan reached the monitor, so scans that started before
	 * it retire instead of overwriting what it saw.
	 *
	 * Freshness is about WHEN THE EVIDENCE WAS GATHERED, not about whether the
	 * monitor's state changed as a result. A scan that re-observes the spend
	 * already recorded has confirmed it at ITS OWN, later moment, so an older
	 * scan still holding a history from before that must not be allowed to
	 * contradict it afterwards with an absence or a different spender. Skipping
	 * the advance because the monitor deduplicated the report left exactly that
	 * hole.
	 *
	 * This does NOT starve a sibling. The only verdict a pre-splice leg
	 * repeats is a breach on the superseded outpoint, which means the splice
	 * was evicted, which means the outpoint it would have created does not
	 * exist and the channel's own watch has nothing to report; and while both
	 * watches still cover the SAME outpoint they agree. A verdict the monitor
	 * refuses (an absence about an outpoint its record does not name) never
	 * reaches here at all.
	 */
	private recordSpendVerdict(idHex: string, ticket: number): void {
		const state = this.channelSpendScans.get(idHex);
		if (!state) return;
		state.appliedTicket = Math.max(state.appliedTicket, ticket);
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
			// Match a superseded RBF attempt's outpoint (post-signatures RBF:
			// any candidate may still confirm).
			for (const rec of state.v2PreviousAttempts ?? []) {
				const recTxidHex = Buffer.from(rec.fundingTxid)
					.reverse()
					.toString('hex');
				if (recTxidHex === txidHex && rec.fundingOutputIndex === outputIndex) {
					return channel;
				}
			}
		}
		return undefined;
	}

	private async checkOutputSpend(
		key: string,
		generation: number = this.lifecycleGeneration,
		invalidateInFlight = false
	): Promise<void> {
		if (!this.isCurrentGeneration(generation)) return;
		const watched = this.watchedOutputs.get(key);
		if (!watched) return;
		if (watched.scanInFlight) {
			watched.rescanRequested = true;
			if (invalidateInFlight) watched.activeScanInvalidated = true;
			return;
		}

		watched.scanInFlight = true;
		let retryAfterFailure = false;
		try {
			do {
				watched.rescanRequested = false;
				watched.activeScanInvalidated = false;
				await this.runOutputSpendScan(key, watched, generation);
			} while (
				this.isCurrentGeneration(generation) &&
				this.watchedOutputs.get(key) === watched &&
				watched.rescanRequested
			);
		} catch (err) {
			retryAfterFailure =
				this.isCurrentGeneration(generation) &&
				this.watchedOutputs.get(key) === watched &&
				watched.rescanRequested;
			throw err;
		} finally {
			watched.scanInFlight = false;
			delete watched.activeScanSequence;
			if (retryAfterFailure) {
				this.checkOutputSpend(key, generation).catch((err) => {
					this.emitError(err);
				});
			}
		}
	}

	private async runOutputSpendScan(
		key: string,
		watched: IWatchedOutput,
		generation: number
	): Promise<void> {
		// Both values date this scan's evidence. A header arriving during the
		// fetch cannot add depth to history that predates it.
		let sequence = ++this.outputScanSequence;
		watched.activeScanSequence = sequence;
		let tipAtScan = this.currentBlockHeight;
		const superseded = (): boolean =>
			!this.isCurrentGeneration(generation) ||
			this.watchedOutputs.get(key) !== watched ||
			watched.activeScanInvalidated;

		let history = await this.backend.getScriptHashHistory(watched.scriptHash);
		if (superseded()) return;

		for (;;) {
			// Find the confirmed spend of our output. The script's history may
			// contain unrelated entries when an address is reused.
			let spend: {
				tx: bitcoin.Transaction;
				txid: string;
				height: number;
			} | null = null;
			for (const entry of history) {
				if (entry.txid === watched.txid || entry.height <= 0) continue;

				const rawTx = await this.backend.getTransaction(entry.txid);
				if (superseded()) return;
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

			// Re-fetch before publishing whenever the history this verdict rests on
			// may already have moved: a recheck arrived mid-scan, or a fresher scan
			// of the same batched spend is around. Re-checking rather than standing
			// aside is the whole point. A scan that stays silent leaves its own
			// outpoint unreported, and the sibling that spoke over it covers the
			// rest of the batch only once the monitor has already recorded this
			// spending transaction against them (issue #621).
			if (
				watched.rescanRequested ||
				this.outputVerdictContested(watched, spend, sequence)
			) {
				sequence = ++this.outputScanSequence;
				watched.activeScanSequence = sequence;
				tipAtScan = this.currentBlockHeight;
				const validatedHistory = await this.backend.getScriptHashHistory(
					watched.scriptHash
				);
				if (superseded()) return;
				watched.rescanRequested = false;
				const unchanged =
					history.length === validatedHistory.length &&
					history.every(
						(entry, index) =>
							entry.txid === validatedHistory[index].txid &&
							entry.height === validatedHistory[index].height
					);
				if (!unchanged) {
					history = validatedHistory;
					continue;
				}
			}

			if (spend) {
				this.recordOutputSpendVerdict(spend.txid, spend.height, sequence);
				// Idempotent: the subscription re-fires on any scripthash change, so skip
				// re-reporting a spend we already recorded. Two cases are NOT idempotent
				// re-fires and must reach the monitor (issue #576): a spend seeded from
				// persisted state, which nothing has verified against the chain this
				// session and whose finality clock is parked until this report, and a
				// recorded spend that has since been re-mined at a DIFFERENT height,
				// whose depth must be recounted from where it actually sits.
				if (
					watched.spendTxid !== spend.txid ||
					watched.spendUnverified === true ||
					watched.spendHeight !== spend.height
				) {
					watched.spendTxid = spend.txid;
					watched.spendHeight = spend.height;
					delete watched.spendUnverified;
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
				// The boundary is the monitor's own, `blockHeight - confirmationHeight >=
				// IRREVOCABLE_DEPTH` (chain-monitor.ts, OUTPUT_RESOLVED): retiring on a
				// `+ 1` depth drops the watch a block early, and a reorg in that gap has
				// nothing left to report the eviction (issue #625).
				//
				// Retirement is measured against the tip this scan's own history was
				// fetched against, never the current one: a header arriving mid-scan is
				// depth the history cannot vouch for, and a watch retired on it is gone
				// for good. The history behind it was re-checked above if anything
				// suggested it had moved.
				if (tipAtScan > 0 && tipAtScan - spend.height >= IRREVOCABLE_DEPTH) {
					this.watchedOutputs.delete(key);
					this.pruneOutputSpendVerdicts(spend.txid);
				}
				return;
			}

			// No spend in the current history. A prior spend was evicted, so the
			// monitor must rebroadcast any penalty or HTLC claim.
			if (watched.spendTxid !== undefined) {
				this.recordOutputSpendVerdict(watched.spendTxid, undefined, sequence);
				watched.spendTxid = undefined;
				watched.spendHeight = undefined;
				delete watched.spendUnverified;
				this.channelManager.handleOutputUnspent(
					watched.txid,
					watched.outputIndex
				);
				this.emit('output:unspent', watched.txid, watched.outputIndex);
			}
			return;
		}
	}

	/**
	 * Would this verdict move a spending transaction a fresher scan has a say in?
	 *
	 * A fresher scan is one that recorded a different height for the same
	 * transaction, or one still in flight over another outpoint the transaction
	 * spends. Pending counts: it fetched its history later, so it is the fresher
	 * of the two whether or not it has come back yet. Only a verdict that would
	 * MOVE the transaction asks the question, so the ordinary sweep, where
	 * every member of a batch re-confirms the height already recorded, costs
	 * nothing extra.
	 *
	 * The answer is a reason to re-fetch, never a reason to stay quiet, so it can
	 * afford to be asked across parent transactions as well as within one: the
	 * spend that batches them is a single transaction at a single height, but the
	 * monitor's report of it is per outpoint and reaches only one parent's
	 * outputs.
	 */
	private outputVerdictContested(
		watched: IWatchedOutput,
		spend: { tx: bitcoin.Transaction; txid: string; height: number } | null,
		sequence: number
	): boolean {
		// An absence answers for the spend it retracts; with none recorded there
		// is no transaction in question, and nothing is reported either.
		const spendTxid = spend?.txid ?? watched.spendTxid;
		if (spendTxid === undefined) return false;
		const height = spend?.height;

		const recorded = this.outputSpendVerdicts.get(spendTxid);
		if (recorded !== undefined && recorded.height === height) return false;
		if (recorded !== undefined && recorded.sequence > sequence) return true;

		for (const sibling of this.watchedOutputs.values()) {
			if (sibling === watched) continue;
			if ((sibling.activeScanSequence ?? 0) <= sequence) continue;
			const shared = spend
				? spend.tx.ins.some(
						(input) =>
							input.index === sibling.outputIndex &&
							Buffer.from(input.hash).reverse().toString('hex') === sibling.txid
				  )
				: sibling.spendTxid === spendTxid;
			if (shared) return true;
		}
		return false;
	}

	/** Record the freshest verdict a spending transaction has been given. */
	private recordOutputSpendVerdict(
		spendTxid: string,
		height: number | undefined,
		sequence: number
	): void {
		const recorded = this.outputSpendVerdicts.get(spendTxid);
		if (recorded !== undefined && recorded.sequence > sequence) return;
		this.outputSpendVerdicts.set(spendTxid, { height, sequence });
	}

	/**
	 * Drop a retired spend's verdict once no watch still answers for it. A scan
	 * in flight anywhere holds it back: that scan may come back holding this
	 * transaction at a height a reorg has since moved, and the record is the only
	 * thing left that can tell it so once the members that saw the move retire.
	 */
	private pruneOutputSpendVerdicts(spendTxid: string): void {
		for (const watched of this.watchedOutputs.values()) {
			if (watched.spendTxid === spendTxid || watched.scanInFlight) return;
		}
		this.outputSpendVerdicts.delete(spendTxid);
	}
}
