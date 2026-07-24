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
	IHtlcSnapshotEntry,
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
	/**
	 * Peer's second-level HTLC signatures on OUR spliced commitment, parallel
	 * to remoteCommitmentSig. Present when committed HTLCs ride through the
	 * splice (S-2.M8); absent/empty for an HTLC-free splice.
	 */
	remoteHtlcSignatures?: Buffer[];
	/**
	 * The committed commitment feerate that remoteCommitmentSig was produced
	 * at. force-close rebuilds the spliced commitment at THIS rate, not a
	 * feerate that may have been staged (update_fee) but not yet covered by the
	 * adopted signature.
	 */
	remoteCommitmentSigFeeratePerKw?: number;
	/**
	 * Lease blockheight covered by remoteCommitmentSig, captured with it for
	 * the same reason as the feerate: force-close reconstruction must never
	 * derive a signed commitment's parameters from mutable current state.
	 */
	remoteCommitmentSigLeaseBlockheight?: number;
	sentTxSignatures: boolean;
	receivedTxSignatures: boolean;
	localSpliceLocked: boolean;
	remoteSpliceLocked: boolean;
	/** Splice tx reached depth while we could not send splice_locked (disconnected). */
	confirmed: boolean;
}

/**
 * The peer's forwarding policy for the peer-to-us direction of a channel,
 * from a signature-verified channel_update the peer sent us directly.
 * Primarily for PRIVATE channels, whose updates never enter the public graph.
 */
export interface IRemoteForwardingPolicy {
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	htlcMinimumMsat: bigint;
	htlcMaximumMsat: bigint | null;
	/** channel_update timestamp: only newer updates replace the stored policy. */
	timestamp: number;
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
	 * How many revoke_and_ack messages we have RECEIVED from the peer — i.e.
	 * the index of the next remote commitment we expect the peer to revoke.
	 * remoteCommitmentNumber counts commitments we have SIGNED; while a
	 * commitment_signed of ours is in flight (unrevoked) the two differ by one.
	 * The shachain insertion index and channel_reestablish's
	 * next_revocation_number MUST come from this counter, not the sign counter:
	 * deriving them from remoteCommitmentNumber desynced the channel whenever a
	 * signature was outstanding ("Invalid per-commitment secret" locally, "bad
	 * future last_local_per_commit_secret" at CLN). Optional for backward
	 * compatibility with states persisted before it existed (see the accessors
	 * in Channel for the legacy defaults).
	 */
	remoteRevocationNumber?: bigint;

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

	/**
	 * Two-phase update_fee tracking (BOLT 2: an update takes effect on a
	 * commitment only once that commitment round covers it — mirroring CLN's
	 * per-side fee state machine):
	 *
	 * pendingFeerateSignable (acceptor only): the staged REMOTE update_fee has
	 * been committed to OUR local commitment (we verified the opener's covering
	 * commitment_signed and revoked). Only from this point may the new rate be
	 * baked into commitments WE sign — the opener builds its own commitment at
	 * the old rate until it has received our revoke_and_ack, so signing at the
	 * new rate any earlier produces a bad signature at the opener.
	 *
	 * pendingFeerateCommitted (both roles): we have SIGNED a commitment at the
	 * staged rate; the peer's next revoke_and_ack finalizes the round and
	 * promotes the staged rate to the committed config. Promoting on just any
	 * revoke_and_ack (the previous behavior) committed the rate prematurely
	 * when the update_fee interleaved with an unrelated round.
	 */
	pendingFeerateSignable?: boolean;
	pendingFeerateCommitted?: boolean;

	/**
	 * The feerate baked into OUR current local commitment — the exact rate the
	 * stored remoteCommitmentSignature was verified against. forceClose MUST
	 * rebuild the local commitment at this rate: during a fee-update round the
	 * committed configs (and pendingFeeratePerKw) can describe a different rate
	 * than the one our latest signed commitment actually uses, and rebuilding
	 * at any other rate changes the sighash and invalidates the stored
	 * signature, leaving the channel with no unilateral exit. Set atomically
	 * wherever remoteCommitmentSignature is adopted; persisted alongside it.
	 */
	lastSignedCommitFeeratePerKw?: number;

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

	/**
	 * Per-remote-commitment HTLC snapshots, keyed by remote commitment number.
	 * Records which HTLCs were present in each remote commitment we signed, so
	 * that if the counterparty broadcasts a REVOKED commitment whose HTLCs have
	 * since settled and been removed from `htlcs`, the justice/penalty transaction
	 * can still reconstruct and sweep those HTLC outputs. Without it, a cheater
	 * reclaims formerly-in-flight HTLC value the penalty was meant to confiscate.
	 */
	revokedHtlcSnapshots?: Map<string, IHtlcSnapshotEntry[]>;

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
	/**
	 * Reestablish (option_taproot): cached 98-byte partial_signature_with_nonce
	 * (32-byte MuSig2 partial || 66-byte public nonce) from the last sent
	 * commitment_signed. Replayed verbatim on retransmit — the bytes are
	 * identical to the original message, so the already-used nonce is not reused
	 * to sign anything new.
	 */
	lastSentPartialSignatureWithNonce: Buffer | null;
	/** Reestablish: cached HTLC sigs for retransmission */
	lastSentHtlcSignatures: Buffer[];
	/** Reestablish: cached revoke_and_ack secret for retransmission */
	lastSentRevokeSecret: Buffer | null;
	/** Reestablish: cached revoke_and_ack next point for retransmission */
	lastSentRevokeNextPoint: Buffer | null;
	/**
	 * Reestablish (BOLT 2): true when the most recently sent of
	 * {revoke_and_ack, commitment_signed} was the revoke_and_ack. When the
	 * peer missed BOTH, they MUST be retransmitted in their original relative
	 * order (a crossed commitment round otherwise desyncs and force-closes);
	 * this records which came last. Null until either has been sent.
	 */
	lastSentWasRevoke: boolean | null;
	/**
	 * Reestablish (BOLT 2): raw outgoing update messages (update_add_htlc /
	 * update_fulfill_htlc / update_fail_htlc) the peer has NOT yet
	 * acknowledged with a revoke_and_ack. On reconnection the peer may have
	 * lost any of these (a receiver forgets uncommitted updates; a crashed
	 * receiver restores a state that predates them), so they MUST be
	 * retransmitted BEFORE any retransmitted commitment_signed. Entries up to
	 * pendingLocalUpdatesSignedCount were covered by our last sent
	 * commitment_signed and are dropped when the peer's revoke_and_ack
	 * arrives; later entries belong to the next round and remain queued.
	 */
	pendingLocalUpdates: Array<{ type: number; payload: Buffer }>;
	/** How many pendingLocalUpdates our last sent commitment_signed covers. */
	pendingLocalUpdatesSignedCount: number;
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

	/**
	 * Closing (option_simple_close): negotiation path chosen for this closing
	 * session. Stamped by the manager from the init-feature intersection when
	 * shutdown starts; re-evaluated on reestablish. Null/absent = legacy
	 * closing_signed. Optional for backward compatibility with pre-simple-close
	 * state literals (same pattern as needsCommitment).
	 */
	simpleClose?: boolean | null;
	/**
	 * Closing (option_simple_close): the closing_complete we last sent, kept to
	 * validate the closing_sig echo, rebuild the exact tx for broadcast, and
	 * enforce RBF fee monotonicity. Cleared when negotiation restarts.
	 */
	lastLocalClosingComplete?: {
		feeSatoshis: bigint;
		locktime: number;
		closerScript: Buffer;
		closeeScript: Buffer;
		/** ClosingSigVariant values we signed and sent (1 or 2 entries). */
		sentVariants: number[];
	} | null;
	/**
	 * Closing (option_simple_close): spec forbids re-sending closing_complete
	 * until the previous one was answered with closing_sig. Reset on reconnect
	 * (negotiation restarts per spec) — intentionally NOT persisted.
	 */
	awaitingClosingSig?: boolean;

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
	/**
	 * The peer's forwarding policy for the peer-to-us direction of THIS
	 * channel, learned from a signature-verified channel_update the peer sent
	 * us directly. For PRIVATE channels this is the only source of the peer's
	 * real fees/CLTV: the graph drops updates without a prior announcement, so
	 * BOLT 11 route hints and blinded-path payment_relay would otherwise
	 * advertise OUR defaults as the peer's policy and payments would fail with
	 * fee_insufficient / incorrect_cltv_expiry whenever they differ.
	 */
	remoteForwardingPolicy?: IRemoteForwardingPolicy | null;

	/** Zero-conf: channel is enabled before funding confirms */
	zeroConfEnabled: boolean;
	/** Zero-conf: peer is trusted for zero-conf */
	trustedPeer: boolean;
	/**
	 * EXPERIMENTAL beignet extension (not BOLT 2): both sides advertised a
	 * 0 sat channel_reserve on the open, so either side may spend its balance
	 * to zero. Requires trustedPeer plus the experimental_zero_reserve init
	 * capability on both sides: without a reserve the peer has nothing at
	 * stake to lose by broadcasting a revoked commitment. Optional so states
	 * persisted before the field existed stay valid; absent means false.
	 * Persisted.
	 */
	zeroReserve?: boolean;
	/**
	 * Handshake-transient acceptor gate, set by ChannelManager before
	 * handleOpenChannel: the peer is trusted AND both sides advertise the
	 * experimental_zero_reserve capability, so a 0 reserve in its open_channel
	 * may be accepted. Never persisted; recomputed per open.
	 */
	zeroReserveAllowed?: boolean;

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

	/**
	 * Liquidity ads (bLIP-0051): absolute block height the lease expires. Set on
	 * both sides of a leased channel; the lessor's to_local stays CSV-locked until
	 * this height. Undefined for non-leased channels.
	 */
	leaseExpiry?: number;
	/**
	 * Liquidity ads: true on the lessor (seller) — the side whose to_local is
	 * CSV-locked until leaseExpiry. The lessee (buyer) leaves this false/undefined.
	 */
	isLessor?: boolean;
	/**
	 * Liquidity ads (buyer side): the lease fee in satoshis, paid THROUGH the
	 * funding transaction — the funding output must total opener_funds +
	 * seller_funds + this fee (CLN model, validated live). The tx-building
	 * caller adds it to the funding output amount. Transient during opening.
	 */
	leaseFeeSats?: bigint;
	/**
	 * Liquidity ads: the blockheight both sides agreed on at open
	 * (request_funds.blockheight). Commitment lease CSV =
	 * leaseExpiry - this (CLN model); advanced only by update_blockheight.
	 */
	leaseCommitBlockheight?: number;
	/**
	 * Two-phase update_blockheight (bLIP-0051, mirrors the pendingFeerate
	 * machine): the OPENER's staged blockheight. From receipt it applies to
	 * verifying the opener's signatures over OUR commitment; it applies to
	 * commitments WE sign only once signable, and is promoted to
	 * leaseCommitBlockheight when the round finalizes.
	 */
	pendingLeaseBlockheight?: number;
	pendingLeaseBlockheightSignable?: boolean;
	pendingLeaseBlockheightCommitted?: boolean;
	/**
	 * The lease blockheight the CURRENT SIGNED local commitment was verified
	 * at (mirrors lastSignedCommitFeeratePerKw): mid-blockheight-round the
	 * in-flight value can differ from the committed one, and rebuilding the
	 * signed commitment (force-close) with the wrong height changes the
	 * lease-locked scripts and invalidates the stored signature.
	 */
	lastSignedCommitLeaseBlockheight?: number;
	/**
	 * Every DISTINCT leaseCommitBlockheight this channel has ever committed
	 * (in promotion order, incl. the value at open). On-chain classification
	 * of an OLD (revoked) commitment must rebuild its lease-locked scripts
	 * with the blockheight in effect when THAT commitment was signed, so
	 * matchers try these as candidates. Grows only when the opener's
	 * update_blockheight rounds actually land (lessor side).
	 */
	leaseHeightHistory?: number[];
	/**
	 * Liquidity ads (bLIP-0051): the routing-fee caps the lessor signed into its
	 * will_fund. While the lease is active the lessor MUST NOT advertise a
	 * channel_update whose fees exceed these — the buyer paid for capped fees.
	 * Set on the lessor only. Base is msat; proportional is thousandths (×1000
	 * to compare against channel_update's fee_proportional_millionths).
	 */
	leaseChannelFeeMaxBaseMsat?: number;
	leaseChannelFeeMaxProportionalThousandths?: number;
	/**
	 * Cooperative close: the fully-signed mutual-close transaction (hex) we
	 * broadcast at fee/sig agreement. Persisted so that on restart, while the
	 * close is still unconfirmed, restoreChainWatches can rebroadcast it and
	 * keep the funding watch armed. Until the close is irrevocably buried a peer
	 * could still broadcast a revoked commitment on the funding output, which we
	 * must be able to detect and punish. Undefined for channels never coop-closed.
	 */
	lastCooperativeCloseTxHex?: string;
	/**
	 * option_taproot: OUR current MuSig2 verification nonce for our local
	 * commitment (the peer co-signs our commitment against it; we consume it only
	 * at force-close). This object is ALSO the secret-nonce handle (the MuSig2
	 * library keys the secret nonce by this object's identity), so it MUST be the
	 * exact value returned by generateNonce — never copied. NOT serialized, but it
	 * is DETERMINISTIC per commitment height (see Channel._deriveVerificationNonce):
	 * re-derived (identical) on reconnect/restart, which keeps the pre-reconnect
	 * commitment force-closeable. Safe because each height's nonce signs exactly
	 * one commitment, once.
	 */
	localNonce?: Uint8Array;
	/**
	 * option_taproot: OUR verification nonce (secret-handle object) for our NEXT
	 * local commitment — the one the peer will co-sign in the upcoming round. Its
	 * public part is advertised one step ahead (in channel_ready for commitment #1,
	 * then rotated via each revoke_and_ack), mirroring how next_per_commitment_point
	 * is pipelined. On adopting a new commitment this is promoted to `localNonce`
	 * (becomes the current commitment's nonce) and the next one is derived. Same
	 * deterministic-per-height + secret-handle-object-identity rules as `localNonce`.
	 */
	localNextNonce?: Uint8Array;
	/**
	 * Data loss protection (BOLT 2): set when the peer's channel_reestablish
	 * proved OUR restored state is stale (it supplied a per-commitment secret
	 * only derivable from our seed at an index we have not reached). Once set,
	 * we MUST NOT broadcast our own (revoked-by-now) commitment: doing so hands
	 * our whole balance to the peer's justice path. Recovery is passive - the
	 * honest peer force-closes with ITS newer commitment and we sweep only our
	 * to_remote from it.
	 */
	dataLossDetected?: boolean;
	/**
	 * Data loss protection: the peer's my_current_per_commitment_point from the
	 * reestablish that proved data loss. Stored for completeness/legacy
	 * commitments; static_remotekey/anchor/taproot to_remote sweeps derive from
	 * our static payment basepoint and do not need it.
	 */
	dlpRemotePerCommitmentPoint?: Buffer;

	/**
	 * option_taproot: the PEER's current 66-byte MuSig2 verification nonce (from
	 * open_channel/accept_channel, then rotated via revoke_and_ack). Used as the
	 * peer's nonce contribution when WE sign the peer's commitment.
	 */
	remoteNonce?: Buffer;
	/**
	 * option_taproot: the peer's 66-byte single-use SIGNING nonce that accompanied
	 * `remoteCommitmentSignature` (their partial signature over OUR local
	 * commitment, received inline in funding_signed/funding_created/
	 * commitment_signed). Needed to aggregate our own partial with theirs into the
	 * final key-spend witness when we broadcast our local commitment. PERSISTED
	 * (it is a public nonce, safe to store) so the current commitment stays
	 * force-closeable across a restart; paired with the deterministic, re-derivable
	 * `localNonce` for the same height. It is the SINGLE peer signing nonce bound to
	 * the current commitment height — never re-bound to a second nonce for that
	 * height, which is what keeps the deterministic verification nonce reuse-safe.
	 */
	remoteSigningNonce?: Buffer;
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
		remoteRevocationNumber: 0n,
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
		lastSentPartialSignatureWithNonce: null,
		lastSentHtlcSignatures: [],
		lastSentRevokeSecret: null,
		pendingLocalUpdates: [],
		pendingLocalUpdatesSignedCount: 0,
		lastSentRevokeNextPoint: null,
		lastSentWasRevoke: null,
		preReestablishState: null,

		lastProposedClosingFeeSat: null,
		closingFeeMin: null,
		closingFeeMax: null,
		theirLastClosingFeeSat: null,
		simpleClose: null,
		lastLocalClosingComplete: null,
		awaitingClosingSig: false,

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
		remoteRevocationNumber: 0n,
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
		lastSentPartialSignatureWithNonce: null,
		lastSentHtlcSignatures: [],
		lastSentRevokeSecret: null,
		pendingLocalUpdates: [],
		pendingLocalUpdatesSignedCount: 0,
		lastSentRevokeNextPoint: null,
		lastSentWasRevoke: null,
		preReestablishState: null,

		lastProposedClosingFeeSat: null,
		closingFeeMin: null,
		closingFeeMax: null,
		theirLastClosingFeeSat: null,
		simpleClose: null,
		lastLocalClosingComplete: null,
		awaitingClosingSig: false,

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
