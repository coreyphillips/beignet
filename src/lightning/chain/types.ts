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
