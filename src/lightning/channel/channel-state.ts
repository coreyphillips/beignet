/**
 * BOLT 2: Channel state snapshot.
 *
 * Full internal state for a Lightning channel, including identity,
 * funding info, local/remote configuration, basepoints, commitment
 * numbers, balances, per-commitment tracking, and HTLC tracking.
 */

import { ShaChainStore } from '../keys/shachain';
import { IChannelBasepoints } from '../keys/derivation';
import {
	ChannelState,
	ChannelRole,
	IChannelConfig,
	IHtlcEntry,
	DEFAULT_CHANNEL_CONFIG
} from './types';

/**
 * An in-flight splice that has passed the point of no return: we have sent our
 * tx_signatures (the peer can complete and broadcast the splice tx without us)
 * or fully signed it ourselves. Everything needed to resume after a disconnect
 * or restart: retransmit tx_signatures, (re)broadcast, watch the new funding
 * output, and exchange splice_locked.
 */
export interface ISpliceInFlight {
	/** Splice txid in tx.getHash() internal byte order. */
	spliceTxid: Buffer;
	newFundingOutputIndex: number;
	newFundingSatoshis: bigint;
	/** Splice tx hex with our witnesses applied; fully signed when fullySigned. */
	spliceTxHex: string;
	/** Both tx_signatures applied → safe to (re)broadcast. */
	fullySigned: boolean;
	isInitiator: boolean;
	localRelativeSatoshis: bigint;
	remoteRelativeSatoshis: bigint;
	remoteFundingPubkey: Buffer;
	/** Our signature on the shared 2-of-2 funding input (retransmit without re-signing). */
	ourSharedInputSig: Buffer;
	/** Splice-in wallet witnesses, in tx-input order (parallel to ourWalletInputIndices). */
	ourWalletWitnesses: Buffer[][];
	ourWalletInputIndices: number[];
	/** Peer's signature on OUR spliced commitment (adopted at completeSplice). */
	remoteCommitmentSig: Buffer | null;
	sentTxSignatures: boolean;
	receivedTxSignatures: boolean;
	localSpliceLocked: boolean;
	remoteSpliceLocked: boolean;
	/** Splice tx reached depth while we could not send splice_locked (disconnected). */
	confirmed: boolean;
}

export interface IChannelState {
	/** Identity */
	channelId: Buffer | null;
	temporaryChannelId: Buffer;
	role: ChannelRole;
	state: ChannelState;

	/** Funding */
	fundingSatoshis: bigint;
	pushMsat: bigint;
	fundingTxid: Buffer | null;
	fundingOutputIndex: number;
	minimumDepth: number;

	/** Local config and basepoints */
	localConfig: IChannelConfig;
	localBasepoints: IChannelBasepoints;
	localPerCommitmentSeed: Buffer;

	/** Remote config and basepoints */
	remoteConfig: IChannelConfig;
	remoteBasepoints: IChannelBasepoints | null;

	/** Commitment tracking */
	localCommitmentNumber: bigint;
	remoteCommitmentNumber: bigint;

	/**
	 * BOLT 2: true when we have pending updates (HTLC add/fulfill/fail or fee
	 * change) that have not yet been committed to the remote via a
	 * commitment_signed we sent. Set when an update is added/received, cleared
	 * when we sign a commitment. Gates whether we send commitment_signed, so we
	 * never re-commit an unchanged state (which would loop and use stale
	 * per-commitment points). Optional for backward compatibility with channel
	 * states created before this field existed (treated as false).
	 */
	needsCommitment?: boolean;

	/**
	 * A proposed-but-not-yet-committed commitment feerate (the opener's fee, set
	 * via update_fee). Held separately from localConfig/remoteConfig.feeratePerKw
	 * (the last *committed* feerate) so an interrupted fee-update round can be
	 * rolled back on channel_reestablish instead of permanently desyncing the
	 * commitment transactions. Applied to the committed config once the round
	 * finalizes; cleared (rolled back) on reestablish if still uncommitted.
	 */
	pendingFeeratePerKw?: number;

	/** Balance tracking (in millisatoshis) */
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;

	/** Per-commitment secrets */
	shaChainStore: ShaChainStore;

	/** Remote's current per-commitment point (for building their commitment) */
	remoteCurrentPerCommitmentPoint: Buffer | null;
	/** Remote's next per-commitment point */
	remoteNextPerCommitmentPoint: Buffer | null;

	/** HTLC tracking */
	localHtlcCounter: bigint;
	htlcs: Map<string, IHtlcEntry>;

	/** Cached remote signature on our latest commitment */
	remoteCommitmentSignature: Buffer | null;
	remoteHtlcSignatures: Buffer[];

	/** Negotiated channel type (feature bitmap) */
	channelType: Buffer | null;

	/** Flags */
	localChannelReady: boolean;
	remoteChannelReady: boolean;
	localShutdownScript: Buffer | null;
	remoteShutdownScript: Buffer | null;

	/** Reestablish: cached last sent commitment_signed for retransmission */
	lastSentCommitmentSigned: Buffer | null;
	/** Reestablish: cached HTLC sigs for retransmission */
	lastSentHtlcSignatures: Buffer[];
	/** Reestablish: cached revoke_and_ack secret for retransmission */
	lastSentRevokeSecret: Buffer | null;
	/** Reestablish: cached revoke_and_ack next point for retransmission */
	lastSentRevokeNextPoint: Buffer | null;
	/** Reestablish: saved state before AWAITING_REESTABLISH */
	preReestablishState: ChannelState | null;

	/** Closing: our last proposed closing fee */
	lastProposedClosingFeeSat: bigint | null;
	/** Closing: minimum acceptable fee */
	closingFeeMin: bigint | null;
	/** Closing: maximum acceptable fee */
	closingFeeMax: bigint | null;
	/** Closing: their last closing fee proposal */
	theirLastClosingFeeSat: bigint | null;

	/** Channel announcement: SCID (set at 6 confirmations) */
	shortChannelId: Buffer | null;
	/** Channel announcement: funding confirmation block height */
	fundingConfirmationHeight: number;
	/** Block height when funding tx was broadcast (for stuck detection) */
	fundingBroadcastHeight: number;
	/** Channel announcement: funding tx index in block */
	fundingTxIndex: number;
	/** Channel announcement: whether we sent our announcement sigs */
	announcementSigsSent: boolean;
	/** Channel announcement: whether we received peer's announcement sigs */
	announcementSigsReceived: boolean;
	/** Channel announcement: peer's node signature */
	remoteAnnouncementNodeSig: Buffer | null;
	/** Channel announcement: peer's bitcoin signature */
	remoteAnnouncementBitcoinSig: Buffer | null;
	/** Channel announcement: our node signature (stored for when remote sigs arrive later) */
	localAnnouncementNodeSig: Buffer | null;
	/** Channel announcement: our bitcoin signature */
	localAnnouncementBitcoinSig: Buffer | null;
	/** Channel announcement: whether to announce (from open_channel channelFlags bit 0) */
	announceChannel: boolean;

	/** SCID alias for private channels */
	scidAlias: Buffer | null;
	/** Remote's SCID alias (from their channel_ready TLV) */
	remoteScidAlias: Buffer | null;

	/** Zero-conf: channel is enabled before funding confirms */
	zeroConfEnabled: boolean;
	/** Zero-conf: peer is trusted for zero-conf */
	trustedPeer: boolean;

	/** Quiescence state */
	quiescenceState: string;
	/** Whether we initiated quiescence */
	quiescenceInitiator: boolean;

	/** Splice: funding txid for the pending splice */
	spliceFundingTxid: Buffer | null;
	/** Splice: funding output index for the pending splice */
	spliceFundingOutputIndex: number;
	/** Splice: state before splicing (to restore on abort) */
	preSpliceState: ChannelState | null;
	/**
	 * Splice: in-flight splice past the point of no return (we sent
	 * tx_signatures, or the mid-splice commitment round completed). Must survive
	 * disconnect AND restart — the splice tx may confirm at any time. Optional
	 * for backward compatibility with states created before this field existed
	 * (treated as null).
	 */
	spliceInFlight?: ISpliceInFlight | null;

	/** Dual-funding: v1 or v2 funding protocol */
	fundingVersion: 1 | 2;
	/** Dual-funding: session state (only set for v2 channels) */
	dualFundingSession: import('./dual-funding').DualFundingSession | null;
	/** Dual-funding: commitment feerate in sat/kw (v2 only) */
	commitmentFeeratePerkw: number;
	/** Dual-funding: funding tx locktime (v2 only) */
	fundingLocktime: number;
}

/**
 * Create initial state for the channel opener.
 */
export function createOpenerState(params: {
	temporaryChannelId: Buffer;
	fundingSatoshis: bigint;
	pushMsat: bigint;
	localConfig: IChannelConfig;
	localBasepoints: IChannelBasepoints;
	localPerCommitmentSeed: Buffer;
}): IChannelState {
	return {
		channelId: null,
		temporaryChannelId: params.temporaryChannelId,
		role: ChannelRole.OPENER,
		state: ChannelState.NONE,

		fundingSatoshis: params.fundingSatoshis,
		pushMsat: params.pushMsat,
		fundingTxid: null,
		fundingOutputIndex: 0,
		minimumDepth: 0,

		localConfig: { ...params.localConfig },
		localBasepoints: params.localBasepoints,
		localPerCommitmentSeed: params.localPerCommitmentSeed,

		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG },
		remoteBasepoints: null,

		localCommitmentNumber: 0n,
		remoteCommitmentNumber: 0n,
		needsCommitment: false,

		localBalanceMsat: params.fundingSatoshis * 1000n - params.pushMsat,
		remoteBalanceMsat: params.pushMsat,

		shaChainStore: new ShaChainStore(),

		remoteCurrentPerCommitmentPoint: null,
		remoteNextPerCommitmentPoint: null,

		localHtlcCounter: 0n,
		htlcs: new Map(),

		remoteCommitmentSignature: null,
		remoteHtlcSignatures: [],

		channelType: null,

		localChannelReady: false,
		remoteChannelReady: false,
		localShutdownScript: null,
		remoteShutdownScript: null,

		lastSentCommitmentSigned: null,
		lastSentHtlcSignatures: [],
		lastSentRevokeSecret: null,
		lastSentRevokeNextPoint: null,
		preReestablishState: null,

		lastProposedClosingFeeSat: null,
		closingFeeMin: null,
		closingFeeMax: null,
		theirLastClosingFeeSat: null,

		shortChannelId: null,
		fundingConfirmationHeight: 0,
		fundingBroadcastHeight: 0,
		fundingTxIndex: 0,
		announcementSigsSent: false,
		announcementSigsReceived: false,
		remoteAnnouncementNodeSig: null,
		remoteAnnouncementBitcoinSig: null,
		localAnnouncementNodeSig: null,
		localAnnouncementBitcoinSig: null,
		announceChannel: true,

		scidAlias: null,
		remoteScidAlias: null,

		zeroConfEnabled: false,
		trustedPeer: false,

		quiescenceState: 'NORMAL',
		quiescenceInitiator: false,

		spliceFundingTxid: null,
		spliceFundingOutputIndex: 0,
		preSpliceState: null,
		spliceInFlight: null,

		fundingVersion: 1,
		dualFundingSession: null,
		commitmentFeeratePerkw: 0,
		fundingLocktime: 0
	};
}

/**
 * Create initial state for the channel acceptor.
 */
export function createAcceptorState(params: {
	temporaryChannelId: Buffer;
	fundingSatoshis: bigint;
	pushMsat: bigint;
	localConfig: IChannelConfig;
	localBasepoints: IChannelBasepoints;
	localPerCommitmentSeed: Buffer;
	remoteBasepoints: IChannelBasepoints;
	remoteConfig: IChannelConfig;
}): IChannelState {
	return {
		channelId: null,
		temporaryChannelId: params.temporaryChannelId,
		role: ChannelRole.ACCEPTOR,
		state: ChannelState.NONE,

		fundingSatoshis: params.fundingSatoshis,
		pushMsat: params.pushMsat,
		fundingTxid: null,
		fundingOutputIndex: 0,
		minimumDepth: 3,

		localConfig: { ...params.localConfig },
		localBasepoints: params.localBasepoints,
		localPerCommitmentSeed: params.localPerCommitmentSeed,

		remoteConfig: { ...params.remoteConfig },
		remoteBasepoints: params.remoteBasepoints,

		localCommitmentNumber: 0n,
		remoteCommitmentNumber: 0n,
		needsCommitment: false,

		// For acceptor: remote (opener) has funding - push, local gets push
		localBalanceMsat: params.pushMsat,
		remoteBalanceMsat: params.fundingSatoshis * 1000n - params.pushMsat,

		shaChainStore: new ShaChainStore(),

		remoteCurrentPerCommitmentPoint: null,
		remoteNextPerCommitmentPoint: null,

		localHtlcCounter: 0n,
		htlcs: new Map(),

		remoteCommitmentSignature: null,
		remoteHtlcSignatures: [],

		channelType: null,

		localChannelReady: false,
		remoteChannelReady: false,
		localShutdownScript: null,
		remoteShutdownScript: null,

		lastSentCommitmentSigned: null,
		lastSentHtlcSignatures: [],
		lastSentRevokeSecret: null,
		lastSentRevokeNextPoint: null,
		preReestablishState: null,

		lastProposedClosingFeeSat: null,
		closingFeeMin: null,
		closingFeeMax: null,
		theirLastClosingFeeSat: null,

		shortChannelId: null,
		fundingConfirmationHeight: 0,
		fundingBroadcastHeight: 0,
		fundingTxIndex: 0,
		announcementSigsSent: false,
		announcementSigsReceived: false,
		remoteAnnouncementNodeSig: null,
		remoteAnnouncementBitcoinSig: null,
		localAnnouncementNodeSig: null,
		localAnnouncementBitcoinSig: null,
		announceChannel: false,

		scidAlias: null,
		remoteScidAlias: null,

		zeroConfEnabled: false,
		trustedPeer: false,

		quiescenceState: 'NORMAL',
		quiescenceInitiator: false,

		spliceFundingTxid: null,
		spliceFundingOutputIndex: 0,
		preSpliceState: null,
		spliceInFlight: null,

		fundingVersion: 1,
		dualFundingSession: null,
		commitmentFeeratePerkw: 0,
		fundingLocktime: 0
	};
}
