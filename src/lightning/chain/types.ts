/**
 * BOLT 5: Chain monitor types.
 *
 * Types for tracking on-chain commitment transactions, output
 * resolution, and the chain monitoring lifecycle.
 */

/** What kind of commitment was broadcast */
export enum CommitmentType {
	COOPERATIVE_CLOSE = 'COOPERATIVE_CLOSE',
	OUR_COMMITMENT = 'OUR_COMMITMENT',
	THEIR_CURRENT_COMMITMENT = 'THEIR_CURRENT_COMMITMENT',
	THEIR_REVOKED_COMMITMENT = 'THEIR_REVOKED_COMMITMENT',
	/**
	 * A commitment with an index beyond our recorded remote state: the peer
	 * legitimately advanced past us (data loss on our side). We never saw its
	 * per-commitment point, so we can only claim our to_remote output.
	 */
	THEIR_FUTURE_COMMITMENT = 'THEIR_FUTURE_COMMITMENT',
	UNKNOWN = 'UNKNOWN'
}

/** Lifecycle of an on-chain output */
export enum OutputStatus {
	UNCONFIRMED = 'UNCONFIRMED',
	CONFIRMED = 'CONFIRMED',
	SPEND_BROADCAST = 'SPEND_BROADCAST',
	SPEND_CONFIRMED = 'SPEND_CONFIRMED',
	IRREVOCABLY_RESOLVED = 'IRREVOCABLY_RESOLVED'
}

/** Type of output on a commitment transaction */
export enum OutputType {
	TO_LOCAL = 'TO_LOCAL',
	TO_REMOTE = 'TO_REMOTE',
	OFFERED_HTLC = 'OFFERED_HTLC',
	RECEIVED_HTLC = 'RECEIVED_HTLC'
}

/** A tracked on-chain output */
export interface ITrackedOutput {
	txid: string;
	outputIndex: number;
	amount: bigint;
	outputType: OutputType;
	status: OutputStatus;
	confirmationHeight: number;
	paymentHash?: Buffer;
	/**
	 * The channel HTLC id this output was attributed to at classification.
	 * Same-hash HTLCs (MPP parts, payment retries) produce IDENTICAL output
	 * scripts, so the hash alone cannot say WHICH forward an output belongs
	 * to; consumers keying follow-up actions to a forward (the upstream fail
	 * of a timed-out outgoing leg) must match on this, never on the hash.
	 * Attribution among identical scripts is one-to-one but arbitrary, which
	 * is sufficient: one resolved output licenses exactly one leg's action.
	 */
	htlcId?: bigint;
	cltvExpiry?: number;
	witnessScript?: Buffer;
	resolutionTxid?: string;
	/** Block height when the sweep was broadcast */
	broadcastHeight?: number;
	/** Fee rate used for the initial broadcast (sat/vbyte) */
	originalFeeRate?: number;
	/** Hex of the sweep transaction for re-broadcast */
	sweepTxHex?: string;
	/**
	 * For a revoked second-level justice claim: hex of the cheater's confirmed
	 * HTLC-success/timeout tx whose output this claim spends. Retained so the
	 * claim can be re-resolved and fee-bumped (RBF) if it stalls before the
	 * cheater's to_self_delay matures — the claim's own txid is the second-level
	 * tx, not the revoked commitment, so rebuildSweep needs it to reconstruct.
	 */
	secondLevelTxHex?: string;
	/** Current fee rate for this output's sweep (tracks per-output bumps) */
	currentFeeRate?: number;
	/** Index into remoteHtlcSignatures for HTLC outputs (BOLT 3 ordering) */
	htlcSigIndex?: number;
	/**
	 * Block height at which this output's sweep transaction becomes valid
	 * (CSV/CLTV timelock matured). The sweep is held until the chain reaches
	 * this height, then broadcast. Undefined for outputs with no built sweep.
	 */
	maturityHeight?: number;
	/**
	 * Height at which this output was FIRST observed to be unclaimable at the
	 * prevailing feerate (its sweep would not cover its own fee, or would leave
	 * only dust). Retained so the skip is visible to an operator and so the
	 * "declined" notification fires once rather than on every retry.
	 */
	uneconomicSinceHeight?: number;
	/**
	 * Height at which a competing spend path opened while this output was still
	 * unclaimed: the counterparty's CSV matured, or an HTLC reached its
	 * cltv_expiry. It does NOT stop the retry, because it does not invalidate our
	 * own spend path; it marks the point where the claim became a race. Set once.
	 */
	uneconomicContestedHeight?: number;
	/**
	 * True when this TO_LOCAL output is the CSV-delayed output of OUR own
	 * second-level HTLC-success/timeout tx (tracked by resolveSecondLevelHtlcOutput),
	 * NOT a commitment to_local. On a taproot channel the two use DIFFERENT script
	 * trees (second-level = revocation-key internal + single delay leaf; commitment
	 * to_local = NUMS internal + delay/revoke leaves), so a rebuild must reconstruct
	 * the correct one. Without this tag the rebuild path would sign against the
	 * commitment to_local tree and strand the second-level funds.
	 */
	isSecondLevelHtlc?: boolean;
	/**
	 * This output's recorded spend has not been re-verified against the chain
	 * this session, so its height must not count toward finality (issue #576).
	 *
	 * Set on restore for every persisted SPEND_CONFIRMED output, and whenever
	 * the parent commitment is demoted (issue #577): the spend may have been
	 * reorged out while we were offline or while the funding watch was
	 * un-armed, and the session's first header reaches the monitor BEFORE any
	 * per-output watch re-arms, so a stale height could otherwise reach
	 * IRREVOCABLE_DEPTH with nothing able to contradict it. Cleared by the
	 * re-armed watch's first live report of the spend (which also refreshes
	 * confirmationHeight), or by the eviction path, which repairs the height
	 * itself. The recorded height is deliberately KEPT while the flag is set:
	 * it seeds the watch, and a re-report of the same height must lose no
	 * progress.
	 */
	spendReverifyPending?: boolean;
}

/** Info about a confirmed commitment transaction */
export interface ICommitmentBroadcast {
	commitmentType: CommitmentType;
	txid: string;
	blockHeight: number;
	commitmentNumber: bigint;
	trackedOutputs: ITrackedOutput[];
	/**
	 * Raw hex of a broadcast REVOKED commitment, retained so a stuck penalty
	 * sweep can be re-resolved and RBF-fee-bumped (the revoked resolver needs the
	 * full tx to read output values). Only set for revoked-commitment broadcasts.
	 */
	revokedTxHex?: string;
	/**
	 * The funding outpoint this transaction was reported as spending (issue
	 * #479).
	 *
	 * A channel has more than one watched funding outpoint once a splice leaves
	 * a pre-splice leg behind, and an absence verdict is evidence about the ONE
	 * outpoint its scan covered, so a retraction has to know which outpoint
	 * this record belongs to. Durable, and that is what makes the ownership
	 * survive a restart: it used to live only in the watcher's in-memory
	 * bookkeeping, so a re-armed leg owned nothing, could not retract a breach
	 * that had since been reorged out, and the finality clock kept advancing
	 * against a height no longer in the chain.
	 *
	 * Display-order txid, as the watcher speaks it. Absent on rows written
	 * before this field existed; see ChainMonitor.handleFundingSpendAbsent for
	 * what that means.
	 */
	spentOutpoint?: { txid: string; outputIndex: number };
	/**
	 * Output indices of this commitment that one of our broadcast claims already
	 * spends. A penalty batch can also spend settled-HTLC outputs reconstructed
	 * from revokedHtlcSnapshots, which never become tracked outputs, so the
	 * tracked set alone cannot answer "is this outpoint already claimed". Read
	 * when retrying a skipped claim, to keep the retry from building a
	 * transaction that conflicts with a live claim of our own.
	 */
	claimedOutputIndices?: number[];
}

/**
 * A funding-spend scan that fetched its script history successfully and found
 * no transaction spending `txid:outputIndex`.
 */
export interface IFundingSpendScan {
	txid: string;
	outputIndex: number;
	/**
	 * A spender this scan deliberately does not report: the splice transaction
	 * a pre-splice leg exists to ignore. A monitor record of THAT transaction
	 * is the outpoint's real, expected spender, so an empty result is not
	 * evidence against it. Its presence also marks the scan as a leg's, which
	 * is what a record predating `spentOutpoint` keys off.
	 */
	expectedSpendTxid?: string;
}

/** Chain action types returned by ChainMonitor */
export enum ChainActionType {
	BROADCAST_TX = 'CHAIN_BROADCAST_TX',
	FEE_BUMP_AND_BROADCAST = 'CHAIN_FEE_BUMP_AND_BROADCAST',
	WATCH_OUTPUT = 'CHAIN_WATCH_OUTPUT',
	WATCH_TX = 'CHAIN_WATCH_TX',
	OUTPUT_RESOLVED = 'CHAIN_OUTPUT_RESOLVED',
	CHANNEL_FULLY_RESOLVED = 'CHAIN_CHANNEL_FULLY_RESOLVED',
	PREIMAGE_LEARNED = 'CHAIN_PREIMAGE_LEARNED',
	REBUILD_SWEEP = 'CHAIN_REBUILD_SWEEP',
	SWEEP_UNECONOMIC = 'CHAIN_SWEEP_UNECONOMIC',
	ERROR = 'CHAIN_ERROR'
}

export interface IBroadcastTxChainAction {
	type: ChainActionType.BROADCAST_TX;
	tx: Buffer;
	description: string;
}

/**
 * Broadcast a transaction that cannot pay its own way and must first have a
 * wallet-funded fee bump attached (anchor channels only). The consumer attaches
 * inputs via the funding provider, then broadcasts; if no funding provider is
 * available it falls back to broadcasting `tx` as-is.
 *
 * - `htlc-fee-attach`: `tx` is a pre-signed zero-fee second-level HTLC tx. Its
 *   input-0 witness (SIGHASH_SINGLE|ANYONECANPAY) is preserved while wallet fee
 *   inputs + change are appended.
 * - `anchor-cpfp`: `tx` is the commitment tx; a child spending our local anchor
 *   (`anchorOutputIndex` / `anchorWitnessScript`) is built to bump the package.
 */
export interface IFeeBumpAndBroadcastChainAction {
	type: ChainActionType.FEE_BUMP_AND_BROADCAST;
	kind: 'htlc-fee-attach' | 'anchor-cpfp';
	tx: Buffer;
	description: string;
	/** Target fee rate in sat/vByte for the bumped transaction/package. */
	feeratePerVbyte: number;
	/** anchor-cpfp only: index of our local anchor output in the commitment. */
	anchorOutputIndex?: number;
	/** anchor-cpfp only: the anchor witness script. */
	anchorWitnessScript?: Buffer;
	/** anchor-cpfp only: virtual size of the parent (commitment) tx. */
	parentVbytes?: number;
	/** anchor-cpfp only: fee already paid by the parent (commitment) tx. */
	parentFeeSats?: bigint;
	/** anchor-cpfp only: commitment txid in display (big-endian) hex. */
	commitmentTxid?: string;
	/**
	 * anchor-cpfp taproot only: the P2TR anchor scriptPubKey. Its presence marks
	 * a taproot key-path anchor spend; the legacy path uses anchorWitnessScript.
	 */
	taprootAnchorScript?: Buffer;
	/**
	 * anchor-cpfp taproot only: merkle root of the anchor's single-leaf (16-CSV)
	 * tree, used to tweak the local delayed privkey for the BIP341 key-path spend.
	 */
	taprootAnchorMerkleRoot?: Buffer;
	/**
	 * anchor-cpfp taproot only: which of our keys spends the anchor. Our anchor
	 * on OUR commitment is keyed to the to_local delayed pubkey ('delayed', the
	 * default when absent); on the PEER's commitment it is keyed to our static
	 * to_remote payment basepoint ('payment', issue #559).
	 */
	taprootAnchorKeyRole?: 'delayed' | 'payment';
}

export interface IWatchOutputChainAction {
	type: ChainActionType.WATCH_OUTPUT;
	txid: string;
	outputIndex: number;
}

export interface IWatchTxChainAction {
	type: ChainActionType.WATCH_TX;
	txid: string;
}

export interface IOutputResolvedChainAction {
	type: ChainActionType.OUTPUT_RESOLVED;
	txid: string;
	outputIndex: number;
	/**
	 * Context for consumers acting on the resolution. An OFFERED_HTLC resolved
	 * without a known preimage is a downstream timeout: the outgoing leg of a
	 * forward is irrevocably failed, so the inbound HTLC can be failed off-chain
	 * (BOLT 2 gates the upstream update_fail_htlc on exactly this).
	 */
	channelId?: Buffer;
	outputType: OutputType;
	paymentHash?: Buffer;
	/**
	 * Exact HTLC identity of the resolved output (see ITrackedOutput.htlcId).
	 * Consumers must prefer this over paymentHash: same-hash MPP parts and
	 * retries make the hash ambiguous across forwards.
	 */
	htlcId?: bigint;
}

export interface IChannelFullyResolvedChainAction {
	type: ChainActionType.CHANNEL_FULLY_RESOLVED;
	channelId: Buffer;
}

export interface IPreimageLearnedChainAction {
	type: ChainActionType.PREIMAGE_LEARNED;
	paymentHash: Buffer;
	preimage: Buffer;
}

export interface IRebuildSweepChainAction {
	type: ChainActionType.REBUILD_SWEEP;
	output: ITrackedOutput;
	feeRatePerVbyte: number;
}

/**
 * A claim we declined to build because it cannot pay its own fee. Without this
 * the skip is silent, and an operator has no way to know a claim was declined.
 *
 * - `skipped`: the first time the output was found unaffordable. It stays under
 *   retry for as long as its outpoint is unspent.
 * - `contested`: a competing spend path has opened (the counterparty's CSV
 *   matured, or an HTLC reached its cltv_expiry) while the claim is still
 *   unbuilt. Retries CONTINUE: a competing path does not invalidate ours, it
 *   only means we are now racing for the outpoint.
 */
export interface ISweepUneconomicChainAction {
	type: ChainActionType.SWEEP_UNECONOMIC;
	reason: 'skipped' | 'contested';
	txid: string;
	outputIndex: number;
	outputType: OutputType;
	amount: bigint;
	/** Feerate (sat/vByte) at which the claim was last declined. */
	feeRatePerVbyte: number;
	/**
	 * Height at which a competing spend path opens (or opened), when one is
	 * bounded and known. Urgency, never a stopping condition.
	 */
	contestHeight?: number;
}

export interface IChainErrorAction {
	type: ChainActionType.ERROR;
	message: string;
}

export type ChainAction =
	| IBroadcastTxChainAction
	| IFeeBumpAndBroadcastChainAction
	| IWatchOutputChainAction
	| IWatchTxChainAction
	| IOutputResolvedChainAction
	| IChannelFullyResolvedChainAction
	| IPreimageLearnedChainAction
	| IRebuildSweepChainAction
	| ISweepUneconomicChainAction
	| IChainErrorAction;

/** Monitor lifecycle state */
export enum MonitorState {
	WATCHING = 'WATCHING',
	COMMITMENT_DETECTED = 'COMMITMENT_DETECTED',
	RESOLVING = 'RESOLVING',
	FULLY_RESOLVED = 'FULLY_RESOLVED'
}

/** Number of confirmations before an output is irrevocably resolved */
export const IRREVOCABLE_DEPTH = 100;

/** Minimum feerate per kw (BOLT 2 minimum) */
export const MIN_FEERATE_PER_KW = 253;

/** Convert sat/vByte to sat/kw (1 vByte = 4 weight units) */
export function satPerVbyteToSatPerKw(satPerVbyte: number): number {
	return Math.ceil((satPerVbyte * 1000) / 4);
}

/** Convert sat/kw to sat/vByte */
export function satPerKwToSatPerVbyte(satPerKw: number): number {
	return Math.ceil((satPerKw * 4) / 1000);
}
