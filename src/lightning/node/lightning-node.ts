/**
 * Lightning Node API: Top-level orchestrator.
 *
 * Wires together PeerManager (transport), ChannelManager (channels + HTLCs),
 * NetworkGraph (gossip/routing), onion (Sphinx packets), and invoice (BOLT 11)
 * into a unified Lightning node API.
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import { ILogger, noopLogger } from '../../logger';
import { getPublicKey } from '../crypto/ecdh';
import {
	signMessageWithKey,
	verifyMessageSignature
} from '../crypto/message-signing';
import {
	constructBlindedPath,
	processBlindedHop,
	deriveBlindedPrivkey,
	IBlindedHopData,
	IBlindedPath,
	IBlindedPaymentPath
} from '../onion/blinded-path';
import {
	ChannelManager,
	IPerChannelKeys,
	txInputOutpoints
} from '../channel/channel-manager';
import { ChannelResult } from '../channel/types';
import { Channel } from '../channel/channel';
import { isValidShutdownScript } from '../channel/validation';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../channel/splice-weight';
import {
	ChannelState,
	ChannelRole,
	HtlcState,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH,
	TESTNET_CHAIN_HASH,
	REGTEST_CHAIN_HASH,
	SIGNET_CHAIN_HASH
} from '../channel/types';
import {
	PeerManager,
	IPeerInfo,
	PeerDialCancelledError
} from '../transport/peer-manager';
import { IPeerTransportOptions } from '../transport/duplex-transport';
import { parseWebSocketUrl } from '../transport/websocket';
import { NetworkGraph } from '../gossip/network-graph';
import {
	findRoute,
	findMultiPathRoute,
	findRouteToBlindedPath,
	calculateFee,
	ILocalChannelEdge
} from '../gossip/pathfinding';
import {
	applyRapidGossipSnapshot,
	IRapidGossipResult
} from '../gossip/rapid-sync';
import { MissionControl } from '../gossip/mission-control';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage,
	INodeAddress,
	IRoute,
	IRouteHop,
	TGossipVerified,
	ADDRESS_TYPE_TORV2,
	ADDRESS_TYPE_TORV3,
	DEFAULT_PRUNE_MAX_AGE,
	gossipTimestampTooFarFuture
} from '../gossip/types';
import {
	decodeChannelAnnouncementMessage,
	decodeNodeAnnouncementMessage,
	decodeChannelUpdateMessage,
	encodeChannelAnnouncementMessage,
	encodeNodeAnnouncementMessage,
	encodeChannelUpdateMessage,
	nodeAddressToHostPort,
	announcedDialableAddresses
} from '../gossip/messages';
import {
	decodeReplyChannelRangeMessage,
	decodeReplyShortChannelIdsEndMessage,
	decodeQueryChannelRangeMessage,
	decodeQueryShortChannelIdsMessage,
	decodeGossipTimestampFilterMessage
} from '../gossip/gossip-queries';
import { GossipSyncManager } from '../gossip/gossip-sync';
import {
	verifyChannelAnnouncement,
	verifyNodeAnnouncement,
	verifyChannelUpdate,
	signChannelUpdate,
	signNodeAnnouncement
} from '../gossip/validation';
import {
	constructOnionPacket,
	encodeOnionPacket,
	decodeOnionPacket
} from '../onion/construct';
import { processOnionPacket, isFinalHop } from '../onion/process';
import { computeSharedSecrets } from '../onion/sphinx-crypto';
import {
	createFailureMessage,
	wrapFailureMessage,
	decryptFailureMessage,
	FAILURE_MESSAGE_LENGTH
} from '../onion/failures';
import {
	IHopPayload,
	KEYSEND_TLV_TYPE,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	FINAL_INCORRECT_CLTV_EXPIRY,
	FINAL_INCORRECT_HTLC_AMOUNT,
	INVALID_ONION_HMAC,
	INVALID_ONION_BLINDING,
	PERMANENT_CHANNEL_FAILURE,
	UNKNOWN_NEXT_PEER,
	REQUIRED_CHANNEL_FEATURE_MISSING,
	INCORRECT_CLTV_EXPIRY,
	FEE_INSUFFICIENT,
	TEMPORARY_CHANNEL_FAILURE,
	EXPIRY_TOO_SOON,
	AMOUNT_BELOW_MINIMUM,
	CHANNEL_DISABLED,
	MPP_TIMEOUT,
	TEMPORARY_NODE_FAILURE,
	EXPIRY_TOO_FAR
} from '../onion/types';
import { encode as encodeInvoice } from '../invoice/encode';
import { decode as decodeInvoice } from '../invoice/decode';
import {
	Network,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	DEFAULT_EXPIRY,
	IRoutingHintHop
} from '../invoice/types';
import { MessageType } from '../message/types';
import {
	PEER_STORAGE_MAX_BYTES,
	encodePeerStorageMessage,
	decodePeerStorageMessage,
	encodePeerStorageRetrievalMessage,
	decodePeerStorageRetrievalMessage
} from '../message/peer-storage';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	ICustomMessage,
	encodeCustomMessage,
	decodeCustomMessage
} from '../message/custom';
import {
	INodeConfig,
	IResourceConfig,
	IPaymentInfo,
	ICreateInvoiceOptions,
	ICreateInvoiceResult,
	IChannelInfo,
	ICloseStatus,
	INodeInfo,
	ILightningError,
	ILightningBalance,
	IFundingProvider,
	IFeeEstimator,
	IPaymentRetryContext,
	IOutboundMppState,
	PaymentStatus,
	PaymentDirection,
	IPendingMppPayment,
	IPaymentPart,
	IInvoiceInfo,
	LightningErrorCode,
	LightningPaymentError,
	InvalidChannelOpenError,
	ChannelFundingUnavailableError,
	ChannelFundingUnavailableCode,
	InvalidSpliceError,
	InvalidPeerConnectError,
	IChannelHealth,
	IStructuredLog,
	IPaymentProof,
	IPaymentEstimate,
	IKeysendOptions,
	IChannelPolicy,
	IChannelPolicyUpdate,
	clampFeeRateSatPerVbyte,
	IAutoRebalanceConfig,
	IAutoTuneFeesConfig,
	IRebalanceResult,
	IRebalanceAttempt,
	IRebalanceExecutionSummary
} from './types';
import {
	canSelectDualFundingInputs,
	selectDualFundingContribution
} from './funding-selection';
import {
	validateHexPubkey,
	validateBuffer,
	validateBufferMinMax,
	validatePositiveBigint,
	validateU32,
	validatePort,
	validateHost,
	MAX_MESSAGE_SIZE,
	MAX_SCRIPT_SIZE
} from '../validation';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	IStorageBackend,
	IPersistedChannelPolicy,
	IForwardingEvent,
	IForwardingEventFilter,
	IForwardingSummary
} from '../storage/types';
import {
	RecoveryManager,
	RecoveryCriticality,
	RecoveryMutation,
	GuardianStartupGate,
	DurabilityBarrier,
	chainLostBackfill,
	chainPromisedQuorum,
	storedTipSequence,
	RecoveryDurability,
	ChannelRecoveryStatus,
	RecoveryJournal,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	journalSupported,
	loadWriterLease,
	composeRecoveryCapsule,
	assertEmptyTarget,
	GuardianDescriptor
} from '../recovery';
import {
	IChannelPersistEvent,
	IChannelPersistRequest
} from '../channel/channel-actions';
import { FeatureFlags, Feature } from '../features/flags';
import {
	ChainWatcher,
	classifyRemoteFundingInput,
	computeScriptHash
} from '../chain/chain-watcher';
import { signP2wpkhInput } from '../chain/sweep';
import {
	satPerVbyteToSatPerKw,
	MIN_FEERATE_PER_KW,
	CommitmentType,
	MonitorState,
	OutputStatus,
	OutputType,
	ISweepUneconomicChainAction
} from '../chain/types';
import { ChainMonitor } from '../chain/chain-monitor';
import { ElectrumBackend } from '../chain/electrum-backend';
import {
	WatchtowerClient,
	IWatchtowerStore,
	IJusticeContext,
	chainHashForNetwork
} from '../watchtower';
import {
	deriveLightningKeysFromMnemonic,
	deriveChannelKeys,
	LnCoinType
} from '../keys/wallet-keys';
import * as bip32Lib from 'bip32';
import * as bip39 from 'bip39';
import { generateFromSeed } from '../keys/shachain';
import { perCommitmentPointFromSecret } from '../keys/derivation';
import { createFundingScript } from '../script/funding';
import { csvFromToLocalScript } from '../script/commitment';
import { createTaprootFundingScript } from '../script/funding-taproot';
import {
	isTaprootChannel,
	isAnchorChannel,
	hasScidAliasChannelType
} from '../channel/types';
import {
	createOpenerState,
	createAcceptorState,
	IAbandonedLocalAdd,
	IChannelState,
	IV2InFlight,
	mustNotBroadcastCommitment,
	ChannelCloseReason
} from '../channel/channel-state';
import {
	IScbChannelEntry,
	encodeScb,
	parseScbAddress,
	validateScbEntry
} from '../backup/scb';
import { signRemoteCommitment } from '../channel/commitment-builder';
import { ChannelSigner, SignerFactory } from '../keys/signer';
import { bootstrapPeers, IPeerAddress, IBootstrapConfig } from '../bootstrap';
import { OnionMessageManager } from '../onion-message/manager';
import { AsyncPaymentManager } from '../async-payments/manager';
import {
	IOnionMessagePayload,
	ISendOnionMessageOptions
} from '../onion-message/types';
import { OfferManager, ICreateOfferOptions } from '../offer/offer-manager';
import { IOffer, IBolt12Invoice } from '../offer/types';
import { PeerRateLimiter } from './rate-limiter';
import {
	LiquidityAdvisor,
	ILiquiditySnapshot,
	IChannelSnapshot
} from '../advisor/liquidity-advisor';
import { FeeAdvisor, IFeeSnapshot } from '../advisor/fee-advisor';
import {
	ChannelSuggestions,
	IChannelSuggestion
} from '../advisor/channel-suggestions';
import {
	planRebalances,
	IRebalancePlan,
	MIN_REBALANCE_SATS
} from '../advisor/rebalance-planner';
import {
	computeFeeTuneAdjustments,
	IFeeTuneInput,
	IFeeTuneAdjustment,
	DEFAULT_FEE_TUNE_FLOOR_PPM,
	DEFAULT_FEE_TUNE_CEIL_PPM
} from '../advisor/fee-tuner';

bitcoin.initEccLib(ecc);

/**
 * Top-level Lightning node orchestrator.
 *
 * Events:
 * - 'payment:received' (paymentInfo: IPaymentInfo)
 * - 'payment:sent' (paymentInfo: IPaymentInfo)
 * - 'payment:failed' (paymentInfo: IPaymentInfo)
 * - 'channel:ready' ({ channelId: Buffer })
 * - 'channel:closed' ({ channelId: Buffer })
 * - 'channel:resolved' ({ channelId: Buffer }) — close fully resolved on-chain
 * - 'channel:aborted' (temporaryChannelId: Buffer, reason: string) — a negotiated-but-unfunded open was torn down (funding failed after accept_channel)
 * - 'message:outbound' (peerPubkey: string, type: number, payload: Buffer)
 * - 'htlc:forward' (fromChannelId: Buffer, toChannelId: Buffer, amountMsat: bigint, paymentHash: Buffer)
 * - 'htlc:forward-failed' ({ inChannelId: Buffer, outChannelId: Buffer }) — a forwarded HTLC failed downstream
 * - 'peer:connect' (pubkey: string)
 * - 'peer:disconnect' (pubkey: string)
 * - 'peer:disconnect-requested' (pubkey: string): external-transport (message:outbound) mode only; the host must sever its connection to this peer, the protocol side (channels marked for reestablish) is already applied
 * - 'peer:error' (pubkey: string, error: Error)
 * - 'peer_storage:retrieved' (peerPubkey: string, blob: Buffer)
 * - 'recovery:reestablish-held' (peerPubkey: string, channelIdHex: string, expiresAt: number): a peer's channel_reestablish for a channel this node has no record of was parked instead of failed, because the node may still be an incomplete restore target (issue #462)
 * - 'sweep:uneconomic' (channelId: Buffer, action: ISweepUneconomicChainAction): an on-chain claim was declined because it cannot pay its own fee
 */

/**
 * How often to refresh + re-broadcast our own gossip (node_announcement) so the
 * node stays in the public graph. Well under the ~2-week staleness/prune window
 * peers and explorers apply, matching the periodic-refresh behaviour of LND/CLN/LDK.
 */
const GOSSIP_REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours

/**
 * Blocks of headroom before a parked hold-invoice HTLC's CLTV expiry at which we
 * auto-fail it off-chain, rather than letting it force an on-chain timeout (which
 * would close the channel). Mirrors the safety margin used for forwarded HTLCs.
 */
const HELD_HTLC_EXPIRY_MARGIN = 18;

/**
 * Largest block-height overshoot we will act on from a peer's
 * incorrect_or_unknown_payment_details. A final node a block or two ahead of us is
 * ordinary propagation skew, but believing an unbounded claim would let a peer
 * inflate the CLTV expiry of everything we send, so cap it to a realistic window.
 */
const MAX_TRUSTED_PEER_HEIGHT_SKEW = 6;

/**
 * Grace past an issued BOLT 12 invoice's expiry before its never-paid state
 * is swept, covering an HTLC already in flight at expiry (mirrors the
 * OfferManager preimage retention grace).
 */
const ISSUED_INVOICE_SWEEP_GRACE_SECONDS = 3600;

/**
 * Blocks of padding added to the final CLTV delta of an outgoing payment, on top
 * of whatever the payee advertised. We apply that delta against OUR block height,
 * so when our height is briefly behind the payee's the unpadded expiry lands below
 * what a strict payee accepts and the payment fails permanently. Mirrors LND's
 * BlockPadding.
 */
const FINAL_CLTV_EXPIRY_PADDING = 3;

/**
 * Fallback sat/vB feerate for a force-close package when we have no live fee data
 * at all (no fee estimator / no samples). Matches the historical default so nodes
 * without a fee estimator behave exactly as before.
 */
const FORCE_CLOSE_DEFAULT_SAT_PER_VBYTE = 10;

/**
 * Urgency multiplier applied to the freshest live fee sample when force-closing.
 * The commitment CPFP child and the second-level HTLC txs MUST confirm before an
 * HTLC's cltv_expiry, so we bid above the current going rate rather than at it.
 */
const FORCE_CLOSE_FEE_MULTIPLIER = 1.5;

/**
 * Invoice feature bits this payer implements (BOLT 11 `9` field). An unknown
 * even (compulsory) bit outside this set MUST fail the payment. Listed by the
 * even bit; the odd variant is unknown-odd and always safe to ignore.
 */
const PAYER_UNDERSTOOD_INVOICE_FEATURES: ReadonlySet<number> = new Set([
	Feature.TLV_ONION,
	Feature.PAYMENT_SECRET,
	Feature.BASIC_MPP,
	Feature.ROUTE_BLINDING
]);

/** BOLT 2: a node forgets an unconfirmed funding only after 2016 blocks. */
const FUNDING_FORGET_BLOCKS = 2016;

/**
 * A signed funding transaction and whether BOLT 2 yet obliges us to put it on
 * the network.
 *
 * 'candidate' is built and signed but FORBIDDEN: funding_signed has not been
 * accepted, so the 2-of-2 has no unilateral exit for us. It is retained anyway
 * so a crash in the signing window cannot lose the transaction. 'authorized'
 * is the obligation, granted only by the AUTHORIZE_FUNDING_BROADCAST action,
 * which is the one signal that has cleared both the persist gate and the
 * quorum barrier. 'restored' came off disk this startup with its authorization
 * unknown, and resolves on first read against the channel it belongs to.
 *
 * Deliberately NOT persisted: the on-disk shape stays {txid, txHex}, so an
 * entry written by any older build restores through the same path as one
 * written by this build and there is no migration to get wrong. A flag on disk
 * would be a copy of a fact the channel already holds, and the only one of the
 * two that can go stale.
 */
interface IPendingFundingTx {
	txHex: string;
	phase: 'candidate' | 'authorized' | 'restored';
	/**
	 * The backend accepted (or already knew) this transaction at least once
	 * in this process. 'authorized' alone only means we DECIDED to broadcast;
	 * the handoff can still have failed, so authorization is never evidence
	 * the transaction exists anywhere (issue #413). Process-local, like
	 * phase: a restart answers unknown and self-heals on the next retry.
	 */
	broadcastSucceeded?: boolean;
}

export class LightningNode extends EventEmitter {
	private nodePrivkey: Buffer;
	/** Genesis hashes of chains we operate on (for gossip chain-scoping). */
	private acceptableChainHashes: Buffer[];
	private nodeId: string;
	private network: Network;
	private channelManager: ChannelManager;
	private graph: NetworkGraph;
	private peerManager: PeerManager | null = null;
	private payments: Map<string, IPaymentInfo> = new Map();
	private preimages: Map<string, Buffer> = new Map();
	private scidToChannelId: Map<string, Buffer> = new Map();
	private htlcPaymentMap: Map<string, string> = new Map(); // "channelId:htlcId" → paymentHash hex
	// For forwarded HTLCs: maps "outChannelId:outHtlcId" → { inChannelId, inHtlcId }
	private forwardedHtlcs: Map<
		string,
		{ inChannelId: Buffer; inHtlcId: bigint }
	> = new Map();
	// Payment secret for receiving: paymentHashHex → paymentSecret
	private paymentSecrets: Map<string, Buffer> = new Map();
	private resourceConfig: Required<IResourceConfig>;
	private cleanupTimer: ReturnType<typeof setInterval> | null = null;
	private storage: IStorageBackend | null = null;
	/** Safety transition committer; null when the node persists nothing. */
	private recovery: RecoveryManager | null = null;
	/**
	 * Channels whose chain monitor changed inside the currently open channel
	 * transition, so the monitor delta can ride in that same transaction rather
	 * than landing in a second, independently-crashable write.
	 */
	private dirtyMonitors = new Set<string>();
	/**
	 * Channels whose monitor delta must NOT be committed on its own, because
	 * the channel transition it belonged to failed to commit. Writing it alone
	 * would leave the monitor ahead of the channel state that produced it.
	 */
	private monitorsAwaitingChannel = new Set<string>();
	/**
	 * Channel ids of the open processActions batches, innermost last. An action
	 * can re-enter the manager (a forwarded HTLC triggers an add on another
	 * channel), so this is a stack rather than a single slot.
	 */
	private openTransitions: string[] = [];
	/**
	 * Mutations a caller staged for the channel transition it is about to
	 * trigger (a preimage before fulfillHtlc, a forward linkage before
	 * addHtlc), so both halves land in one transaction.
	 */
	private stagedMutations: RecoveryMutation[] = [];
	private chainWatcher: ChainWatcher | null = null;
	/**
	 * The watcher instance these events are wired to, rather than a one-shot
	 * boolean. A boolean could never be reset, so a watcher that was stopped and
	 * started again was left with no listeners at all: no block, no error, no
	 * watch:output:requested reached the node, and it silently stopped tracking
	 * the chain. Keyed on the instance, a replacement watcher is always wired and
	 * the same one is never wired twice.
	 */
	private _wiredChainWatcher: ChainWatcher | null = null;
	private currentBlockHeight = 0;
	private htlcSafetyMargin: number;
	private forwardingEnabled: boolean;
	private eagerGossipVerify: boolean;
	private forwardingCltvDelta: number;
	private forwardingFeeBaseMsat: number;
	private forwardingFeePropMillionths: number;
	/** Liquidity ads seller policy; also published in node_announcement. */
	private readonly leaseRates?: import('../gossip/types').ILeaseRates;
	/** Per-channel routing-policy overrides (channelId hex -> partial policy). */
	private channelPolicies: Map<string, IChannelPolicyUpdate> = new Map();
	private gossipSyncManagers: Map<string, GossipSyncManager> = new Map();
	/**
	 * Broadcast gossip intake (beignet issue #437). Announcements and updates
	 * are queued here and verified in time-budgeted slices off the event loop,
	 * because a peer serving a full graph dump carries hundreds of thousands
	 * of pure-JS signature verifications; handled inline they pin the process
	 * for the whole dump, starving every route, ping, and signal handler,
	 * and the resulting pong timeouts make peers reconnect and restart the
	 * dump: a livelock. Head index instead of shift() so draining a deep
	 * queue is linear, not quadratic.
	 */
	private gossipIntake: Array<{
		pubkey: string;
		type: number;
		payload: Buffer;
	}> = [];
	private gossipIntakeHead = 0;
	private gossipIntakeDraining = false;
	private gossipIntakeDropped = 0;
	private static readonly GOSSIP_INTAKE_MAX = 30_000;
	private static readonly GOSSIP_INTAKE_SLICE_MS = 10;
	/** Our own node_announcement (cached so we can re-broadcast it for propagation). */
	private _ownNodeAnnouncement?: Buffer;
	/** Our own channel_announcement + channel_update per channel, cached for re-broadcast. */
	private _ownChannelGossip: Map<
		string,
		{ announcement: Buffer; update: Buffer }
	> = new Map();
	/** Periodic timer that refreshes + re-broadcasts our gossip so the node stays in the public graph. */
	private _gossipRefreshTimer?: ReturnType<typeof setInterval>;
	// MPP: pending multi-part payments awaiting all parts (keyed by paymentHash hex)
	private pendingMppPayments: Map<string, IPendingMppPayment> = new Map();
	// Hold invoices: payment hashes whose incoming HTLCs are parked, not settled.
	private heldInvoiceHashes: Set<string> = new Set();
	// Parked HTLCs awaiting settleHeldHtlc/cancelHeldHtlc, keyed by payment hash.
	private heldHtlcs: Map<
		string,
		Array<{
			channelId: Buffer;
			htlcId: bigint;
			amountMsat: bigint;
			cltvExpiry: number;
		}>
	> = new Map();
	private mppTimeoutMs: number;
	private alias?: string;
	private announcedAddresses: INodeAddress[] = [];
	// Newest announced address set captured per channel peer, keyed by pubkey.
	// The timestamp enforces node_announcement monotonicity for the reconnect
	// fallback path independently of the graph, which never accepts
	// announcements from nodes with only private channels — a valid signature
	// alone must not let a replayed old announcement regress the addresses.
	private announcedPeerAddresses: Map<
		string,
		{ timestamp: number; addresses: Array<{ host: string; port: number }> }
	> = new Map();
	private fundingPubkey: Buffer;
	private fundingProvider: IFundingProvider | null = null;
	private fundingPrivkey: Buffer;
	/** Custom channel-signer factory (see INodeConfig.signerFactory). */
	private signerFactory: SignerFactory | undefined;
	/** Wallet-owned script that on-chain sweeps pay into (see INodeConfig). */
	private sweepDestinationScript?: Buffer;
	private htlcBasepointSecret: Buffer | undefined;
	private delayedPaymentBasepointSecret: Buffer | undefined;
	// Per-channel basepoint secrets from the node-level-basepoints config. Stored so
	// ChainMonitor.restore signs on-chain claims with the SAME keys the create path
	// used (channel-manager) — without them restore silently substituted node/funding
	// keys, breaking penalty/to_remote/HTLC claims after a restart (audit H2).
	private revocationBasepointSecret: Buffer | undefined;
	private paymentBasepointSecret: Buffer | undefined;
	/**
	 * Signed funding txs we are OBLIGATED to broadcast (BOLT 2: once
	 * funding_signed is received the funder must broadcast), keyed by funding
	 * txid in internal byte order. An entry lives until the funding CONFIRMS,
	 * not merely until one broadcast succeeds: a transient broadcast failure
	 * or a later mempool eviction is retried on every new block, and the map
	 * is persisted so a restart resumes the obligation.
	 */
	private pendingFundingTxs: Map<string, IPendingFundingTx> = new Map();
	/** True while a startup repair frame awaits its quorum receipt. */
	private startupRepairPending = false;
	/** Channel ids whose restore-time deletion disposition FAILED. */
	private restoreDeletionFailures: string[] = [];
	/**
	 * When a re-authorization was last asked for, keyed by funding txid or, for
	 * a splice, by channel id.
	 *
	 * Two jobs, and the second is why this is a timestamp rather than a flag. A
	 * request still parked behind the barrier must not be duplicated, which the
	 * awaiting-durability check answers. A request that ENDED without being
	 * granted, because the barrier timed out or refused, has to be asked again,
	 * or a transient guardian outage would strand the obligation until the next
	 * process restart. Asking again on every block would mint a no-op frame per
	 * block while the quorum is down, so the retry is spaced.
	 */
	private reauthAttempts: Map<string, number> = new Map();
	/**
	 * Channels whose fully signed splice rebroadcast has already been
	 * authorized IN THIS PROCESS.
	 *
	 * A splice has no equivalent of the funding map's 'authorized' phase, so
	 * without this every retry window would mint another no-op frame and
	 * another barrier wait for a rebroadcast that is already permitted.
	 * Rebroadcasting is cheap and idempotent; re-authorizing is not. Process
	 * local by the same rule as the funding phase: a restart must ask again,
	 * because a local frame is not a quorum-durable one.
	 */
	private authorizedSpliceBroadcasts: Set<string> = new Set();
	private static readonly REAUTH_RETRY_MS = 10 * 60_000;
	private paymentRetryContexts: Map<string, IPaymentRetryContext> = new Map();
	private mppCleanupTimer: ReturnType<typeof setInterval> | null = null;
	// Per-HTLC shared secrets for creating encrypted failure messages (keyed by "channelIdHex:htlcId")
	private receivedHtlcSharedSecrets: Map<string, Buffer> = new Map();
	/**
	 * Incoming HTLCs we are relaying inside a blinded route, keyed like
	 * receivedHtlcSharedSecrets. BOLT 4: ANY failure on these must surface as
	 * invalid_onion_blinding — via update_fail_malformed_htlc at a hop whose
	 * blinding point arrived in update_add_htlc ('mid'), or as a normal
	 * encrypted error at the introduction node ('intro'). In-memory only: a
	 * forward interrupted by a restart falls back to an ordinary error.
	 */
	private blindedIncomingHtlcs: Map<string, 'intro' | 'mid'> = new Map();

	/**
	 * Incoming-HTLC dispatches parked because the channel was quiescing when
	 * they committed (BOLT 2: no update messages after stfu, issue 411).
	 * Drained on the manager's 'quiescence:ended' event; the per-block retry is
	 * the invariant keeper, since terminal quiescence exits (disconnect,
	 * errored, force close) emit no event. In-memory only: a restart replays
	 * these via redispatchUnresolvedReceivedHtlcs.
	 */
	private parkedQuiescentHtlcs: Map<
		string,
		Array<{ htlcId: bigint; amountMsat: bigint; paymentHash: Buffer }>
	> = new Map();
	private feeEstimator: IFeeEstimator | null = null;
	private missionControl: MissionControl;
	/** Leveled diagnostic logger (injectable via INodeConfig.logger; no-op by default). */
	private logger: ILogger;
	private maxPaymentRetries: number;
	private maxTotalInFlightHtlcs: number;
	private autoUpdateChannelFees = false;
	private rateLimiter: PeerRateLimiter;
	// Outbound MPP: tracks multi-part payment outcomes (keyed by paymentHash hex)
	private outboundMppPayments: Map<string, IOutboundMppState> = new Map();
	private invoices: Map<string, IInvoiceInfo> = new Map();
	private feeUpdateTimer: ReturnType<typeof setInterval> | null = null;
	private lastKnownFeeratePerKw = 0;
	private _stuckChannelTracker: Map<string, number> = new Map();
	private _reconnectTimers: Set<ReturnType<typeof setTimeout>> = new Set();
	private _activeWaitCleanups: Set<() => void> = new Set();
	private _destroyed = false;
	/**
	 * Bumped by destroy() and by each startChainWatcher(). The chain startup
	 * sequence is a long chain of awaits (watcher start, then a restore loop
	 * doing network work per channel), and destroy() cannot reach into it: a
	 * continuation resuming afterwards would restart the reconnect monitor
	 * destroy() just stopped, rebroadcast transactions and retry funding
	 * broadcasts for a node that is gone. Every step re-checks the generation
	 * it started in, which also retires a superseded startChainWatcher().
	 */
	private chainStartupGeneration = 0;
	private missionControlTimer: ReturnType<typeof setInterval> | null = null;
	private onionMessageManager: OnionMessageManager;
	private offerManager: OfferManager;
	private asyncPaymentManager: AsyncPaymentManager;
	// LSP-side: forwards parked for offline receivers, keyed by payment hash hex.
	private heldForwards: Map<
		string,
		{ inChannelId: Buffer; inHtlcId: bigint; incomingCltvExpiry: number }
	> = new Map();
	private graphPruneTimer: ReturnType<typeof setInterval> | null = null;
	private _chainBackend: import('../chain/chain-watcher').IChainBackend | null =
		null;
	// Close-broadcast bookkeeping for closeStatus reporting. In-memory only:
	// after a restart the spend observation (monitor commitmentBroadcast) or a
	// manual rebroadcast re-establishes the truth, so `broadcast` honestly
	// reads false in between.
	private _pendingCloseTxids: Map<string, string> = new Map(); // txidHex -> channelIdHex
	/**
	 * Channels this process has already sent an immediate recovery-close
	 * request for (issue #469). The request is a BOLT 1 error and the path
	 * that sends it also runs on errors RECEIVED, so without this two nodes
	 * answer each other forever. Reconnect still repeats it durably.
	 */
	private _recoveryCloseRequested: Set<string> = new Set();
	private _lastCloseBroadcast: Map<string, { txid: string; ok: boolean }> =
		new Map(); // channelIdHex -> last close-tx broadcast result
	// Terminal-state (CLOSED/FORCE_CLOSED/ERRORED) channel persists that
	// failed. A terminal channel may never see another transition or monitor
	// update to ride, so without this per-block retry a one-shot storage
	// failure leaves disk on the pre-close state (and without closeReason)
	// forever.
	private _failedTerminalPersists: Set<string> = new Set();
	// FORCE_CLOSED channels whose confirmed-splice close re-drive could not
	// broadcast (issue #357): retried each block until the adopted-funding
	// commitment reaches the network.
	private _pendingSpliceCloseRedrives: Set<string> = new Set();
	/**
	 * Per-output watches whose arming failed, keyed "txid:outputIndex" so a
	 * repeated failure cannot grow the queue (issue #577).
	 */
	private _pendingOutputWatches: Map<
		string,
		{ channelIdHex: string; txid: string; outputIndex: number }
	> = new Map();
	private reestablishTimeoutBlocks: number;
	private readonly autoReconnect: boolean;
	private walCheckpointTimer: ReturnType<typeof setInterval> | null = null;
	private _readyEmitted = false;
	private _pendingReconnects = 0;
	private liquidityAdvisor = new LiquidityAdvisor();
	private feeAdvisor = new FeeAdvisor();
	private channelSuggestions = new ChannelSuggestions();
	// Advisor execution (both OFF by default; see INodeConfig)
	private autoRebalanceConfig: IAutoRebalanceConfig;
	private autoTuneFeesConfig: IAutoTuneFeesConfig;
	private autoRebalanceTimer: ReturnType<typeof setInterval> | null = null;
	private autoTuneFeesTimer: ReturnType<typeof setInterval> | null = null;
	/** Rebalance-fee spend for the current UTC day (mirrors persisted metadata). */
	private rebalanceBudgetDay: { day: string; spentFeeMsat: bigint } | null =
		null;
	/** Serializes executeRebalanceRecommendations runs (budget consistency). */
	private rebalanceRunInFlight = false;
	// BOLT 1 peer storage (option_provide_storage)
	private peerStorageEnabled: boolean;
	// The feature set we advertise in init; reused for node_announcement so the
	// graph reflects what we actually support (e.g. onion messages, route
	// blinding), which is what peers consult to route offers/onion-messages to us.
	private localFeatures: FeatureFlags;
	// option_wumbo (large_channels): lift the 2^24 sat funding cap
	private largeChannels: boolean;
	// SOCKS5 proxy config, kept for connect-by-node-id Tor address gating
	private socks5Proxy: { host: string; port: number } | null;
	// Watchtower client (LND altruist wtwire). Null when no towers configured.
	private watchtowerClient: WatchtowerClient | null = null;
	/** Server side: latest blob held per peer (mirrors storage when available). */
	private peerStorageBlobs: Map<string, { blob: Buffer; receivedAt: number }> =
		new Map();
	/** Server side: last PERSISTED peer_storage timestamp per peer (rate limit). */
	private peerStorageLastAccepted: Map<string, number> = new Map();
	/** Server side: deferred disk-flush timer per peer (coalesced newest blob). */
	private peerStorageFlushTimers: Map<string, ReturnType<typeof setTimeout>> =
		new Map();
	/** Client side: our own blob, pushed to capable peers on change/connect. */
	private ourPeerStorageBlob: Buffer | null = null;
	/** Client side: newest blob each peer returned via peer_storage_retrieval. */
	private retrievedPeerStorage: Map<
		string,
		{ blob: Buffer; receivedAt: number }
	> = new Map();
	/** Recovery Capsule (spec 5.4): journal configured, capsule refresh armed. */
	private recoveryCapsuleActive = false;
	private recoveryJournal: RecoveryJournal | undefined;
	/**
	 * Guardian locators every composed capsule carries (5.4): the configured
	 * set in the guardian modes, empty for a peer-storage-only node.
	 */
	private readonly recoveryGuardians: GuardianDescriptor[];
	/**
	 * Startup quarantine (recovery 5.6). Installed at CONSTRUCTION from
	 * config.recovery.startupGate. While present and unconfirmed, the node
	 * makes NO peer contact at all, inbound or outbound, connection
	 * establishment included: a stale device discovers it was superseded
	 * before it can touch the Lightning protocol.
	 */
	private recoveryGate: GuardianStartupGate | undefined;
	/**
	 * Quorum durability barrier (recovery 5.8). Also the node's only driver
	 * of guardian replication, in every durability mode.
	 */
	private recoveryBarrier: DurabilityBarrier | undefined;
	/**
	 * Mirrors the barrier's fenced latch so every transport chokepoint sees a
	 * runtime supersession (recovery 5.8), not only the PeerManager: the
	 * event transport consults recoveryPermitsPeerTraffic too.
	 */
	private _barrierFenced = false;
	/** The constructor's dial pass was withheld pending gate confirmation. */
	private _autoReconnectDeferred = false;
	private capsuleRefreshTimer: ReturnType<typeof setTimeout> | null = null;
	private capsuleLastRefreshAt = 0;
	/**
	 * A capsule carrying real state went out this run. Until then an empty
	 * node composes nothing: see composeRecoveryCapsuleBlob.
	 */
	private capsuleCarriedState = false;
	/** A journaled commit landed after the last compose (see connect path). */
	private capsuleDirty = false;

	constructor(config: INodeConfig) {
		super();
		this.setMaxListeners(50);

		this.nodePrivkey = config.nodePrivateKey;
		this.nodeId = getPublicKey(config.nodePrivateKey).toString('hex');
		this.network = config.network || Network.REGTEST;
		this.acceptableChainHashes = config.chainHashes ?? [];
		this.storage = config.storage || null;
		// Recovery Protocol phase 1: the choke point every safety-critical write
		// goes through, so channel state, its key index, its chain monitor delta
		// and the wire bytes they authorize commit as one unit
		// (docs/RECOVERY-PROTOCOL.md 5.1).
		// Phase 2 (docs/RECOVERY-PROTOCOL.md 5.3): the hash-chained journal.
		// Opt-in and additive; when off, nothing changes. The journal appends
		// inside RecoveryManager.commit's transaction, so enabling it makes the
		// frame part of every safety transition's atomicity.
		// Phase 6 (5.8): the durability mode every frame declares, and the
		// barrier that holds wire messages until their frame is replicated.
		// async-remote is the default because it is exactly the node's
		// pre-Phase-6 conduct.
		const barrier = config.recovery?.barrier;
		// The journal is built before the logger field is assigned, and its
		// sticky-durability check reports through onDurabilityRefused during
		// construction, so the message is captured and logged below rather
		// than reaching for a logger that does not exist yet.
		let durabilityRefusal: string | null = null;
		const journal =
			this.storage &&
			config.recovery?.enabled === true &&
			journalSupported(this.storage)
				? new RecoveryJournal(
						this.storage,
						deriveRecoveryMasterKey(config.nodePrivateKey),
						getPublicKey(config.nodePrivateKey),
						// The guardian namespace keys the deterministic frame IV
						// (wire spec 1.1, 3.2); never the public node id.
						deriveRecoveryRoot(config.nodePrivateKey).recoveryId,
						{
							durability: config.recovery.durability ?? 'async-remote',
							// Binds every frame's epoch to the ACTIVE lease
							// (import-cycle-free injection): a mismatched or
							// vanished epoch record refuses the write instead
							// of encrypting frames a receipted restore could
							// never decrypt. A corrupt lease throws, which
							// refuses the write too.
							activeLeaseEpoch: (): bigint | null => {
								const loaded = loadWriterLease(this.storage!);
								return loaded.state === 'present' ? loaded.lease.epoch : null;
							},
							// Compaction must never prune a frame a guardian has not
							// received: the chain origin is immutable and guardians
							// accept only logHead.sequence + 1, so a pruned-early
							// frame wedges that guardian for good.
							retainFrom: barrier
								? (): bigint => barrier.watermark() + 1n
								: undefined,
							onDurabilityRefused: (detail): void => {
								durabilityRefusal = detail;
							},
							maxRetainedFrameGap: config.recovery.maxRetainedFrameGap,
							onCompactionForced: (detail): void => {
								this.logger?.warn(`recovery compaction: ${detail}`);
								// Deferred out of the commit's open transaction: this
								// fires from inside RecoveryManager.commit, and a
								// listener that touches storage must not run there.
								setImmediate(() => {
									this.emitStructuredLog('channel', 'recovery_backfill_lost', {
										detail
									});
									this.emit('recovery:backfill-lost', detail);
								});
							},
							snapshotIntervalFrames: config.recovery.snapshotIntervalFrames,
							snapshotIntervalBytes: config.recovery.snapshotIntervalBytes
						}
				  )
				: undefined;
		// Fail closed on a chain that promised quorum and a node that can no
		// longer deliver it. Continuing would put revoke_and_ack on the wire
		// unbarriered beneath a certified head that still reads 'quorum', and
		// a later restore of that chain would claim an exactness it does not
		// have. The remedy is to restore the guardian configuration.
		// The check is on the DATABASE, not on the journal object, because the
		// dangerous configuration is the one where no journal exists at all:
		// the sticky rule lives inside RecoveryJournal, so a run with recovery
		// switched off would append nothing while its channels kept advancing
		// past a certified head that still reads 'quorum'.
		if (
			this.storage &&
			!barrier?.enforcing &&
			chainPromisedQuorum(
				this.storage,
				deriveRecoveryMasterKey(config.nodePrivateKey),
				getPublicKey(config.nodePrivateKey)
			)
		) {
			throw new Error(
				'recovery: this database is in quorum mode but no enforcing durability ' +
					'barrier was configured, so safety-critical messages could not be held; ' +
					'restore the guardian set, or start a new recovery namespace'
			);
		}
		// And the mirror image, which would be worse because it looks like it
		// is working: an enforcing barrier with no journal has no frame to wait
		// on, so every batch reports frameSequence null, every barrier answers
		// yes, and quorum mode holds nothing at all while claiming to. Journal
		// support is not optional for the mode that depends on it.
		if (barrier?.enforcing && !journal) {
			throw new Error(
				'recovery: quorum durability needs the recovery journal, which is off ' +
					'or unsupported by this storage backend; without frames there is ' +
					'nothing for a barrier to wait on and nothing would be held'
			);
		}
		this.recoveryBarrier = barrier;
		// Phase 3 (docs/RECOVERY-PROTOCOL.md 5.4): with the journal on, every
		// journaled commit schedules a (once-per-minute throttled) refresh of
		// the peer_storage Recovery Capsule.
		this.recoveryCapsuleActive = journal !== undefined;
		this.recoveryJournal = journal;
		this.recoveryGuardians = config.recovery?.guardians ?? [];
		this.recovery = this.storage
			? new RecoveryManager(this.storage, {
					journal,
					onCommitted: journal
						? (): void => {
								this.scheduleRecoveryCapsuleRefresh();
								// Start replicating without waiting for it. This is
								// "appends are pipelined" from the commit side: the
								// frame is handed to the pump and the transition
								// returns, so later frames keep landing while an
								// earlier receipt is still outstanding.
								this.recoveryBarrier?.noteCommitted();
						  }
						: undefined,
					onError: (err: Error, context): void => {
						// persistChannel reports its own failures with the channel id
						// attached, which is strictly more useful; emitting here too
						// would give a listener two events for one failure.
						if (context.reportedByCaller) return;
						this.emit('node:error', {
							code: 'PERSISTENCE_ERROR',
							message: `safety transition failed: ${err.message}`,
							timestamp: Date.now()
						} as ILightningError);
					}
			  })
			: null;

		this.resourceConfig = {
			maxCompletedPayments:
				config.resourceConfig?.maxCompletedPayments ?? 10_000,
			completedPaymentTtlMs:
				config.resourceConfig?.completedPaymentTtlMs ?? 86_400_000,
			cleanupIntervalMs: config.resourceConfig?.cleanupIntervalMs ?? 60_000
		};

		this.htlcSafetyMargin = config.htlcSafetyMargin ?? 6;
		this.forwardingEnabled = config.forwardingEnabled ?? true;
		this.eagerGossipVerify = config.eagerGossipVerify ?? false;
		this.forwardingCltvDelta = config.forwardingCltvDelta ?? 40;
		this.forwardingFeeBaseMsat = config.forwardingFeeBaseMsat ?? 1000;
		this.forwardingFeePropMillionths = config.forwardingFeePropMillionths ?? 1;
		this.mppTimeoutMs = config.mppTimeoutMs ?? 60_000;
		this.alias = config.alias;
		// BOLT 7 requires address descriptors in ascending order by type.
		this.announcedAddresses = [...(config.announcedAddresses ?? [])].sort(
			(a, b) => a.type - b.type
		);
		this.fundingPubkey = config.channelBasepoints.fundingPubkey;
		this.fundingProvider = config.fundingProvider || null;
		this.fundingPrivkey = config.fundingPrivkey;
		this.signerFactory = config.signerFactory;
		this.sweepDestinationScript = config.sweepDestinationScript;
		this.htlcBasepointSecret = config.htlcBasepointSecret;
		this.delayedPaymentBasepointSecret = config.delayedPaymentBasepointSecret;
		this.revocationBasepointSecret = config.revocationBasepointSecret;
		this.paymentBasepointSecret = config.paymentBasepointSecret;
		this.feeEstimator = config.feeEstimator || null;
		this.socks5Proxy = config.socks5Proxy ?? null;
		this.initWatchtowerClient(config.watchtowers ?? []);
		this.logger = config.logger ?? noopLogger;
		if (durabilityRefusal) {
			this.logger.warn(`recovery durability: ${durabilityRefusal}`);
		}
		this.missionControl = new MissionControl();
		this.maxPaymentRetries = config.maxPaymentRetries ?? 3;
		this.maxTotalInFlightHtlcs = config.maxTotalInFlightHtlcs ?? 1000;
		this.rateLimiter = new PeerRateLimiter(config.rateLimitConfig);
		this.reestablishTimeoutBlocks = config.reestablishTimeoutBlocks ?? 2016;
		// Off by default: periodically bumping the commitment feerate via update_fee
		// repeatedly desynced channels (the fee round must complete with the peer, and
		// a stale/uncommitted bump breaks every subsequent HTLC). A payment-focused
		// node rarely needs it; opt in explicitly if you route and must track fees.
		this.autoUpdateChannelFees = config.autoUpdateChannelFees ?? false;
		// Anchors are the default channel type now that wallet-funded fee bumping
		// (zero-fee HTLC fee-attach + commitment CPFP) makes their force-close safe.
		// Escape hatch: pass preferAnchors: false to negotiate legacy static_remotekey.
		const preferAnchors = config.preferAnchors ?? true;

		// Set default features if not provided (includes static_remotekey).
		// Computed before the ChannelManager so per-peer feature-dependent
		// behavior (e.g. option_simple_close) can consult our own advertisement.
		const localFeatures =
			config.localFeatures || LightningNode.defaultFeatures();
		// Advertise anchor support whenever anchors are preferred (the default).
		if (
			preferAnchors &&
			!localFeatures.hasFeature(Feature.ANCHOR_ZERO_FEE_HTLC)
		) {
			localFeatures.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		}
		// option_wumbo: advertise large_channels by default, matching LND, CLN and
		// Eclair, which all default to wumbo. The bit only invites peers to propose
		// > 2^24 sat fundings; the cap is lifted for a given peer only when wumbo is
		// advertised on BOTH sides (see maxFundingForPeer), so a non-wumbo peer still
		// gets the 2^24 cap. Opt out with largeChannels: false.
		this.largeChannels = config.largeChannels ?? true;
		if (this.largeChannels) {
			localFeatures.setOptional(Feature.LARGE_CHANNELS);
		}
		// option_will_fund: advertised only when a seller policy is configured —
		// a CLN buyer refuses to even request funds (fundchannel request_amt)
		// from a peer that does not advertise the bit. The rates themselves are
		// kept for node_announcement's lease_rates TLV (issue #539): a buyer
		// pricing from the gossip ad needs the terms, and verifyWillFund's
		// contract says the signed rates must match the advertised ones.
		this.leaseRates = config.leaseRates;
		if (config.leaseRates) {
			localFeatures.setOptional(Feature.OPTION_WILL_FUND);
		}
		// Peer storage (option_provide_storage): on by default. When disabled,
		// the bit must not be advertised: advertising it obliges us to store
		// and return blobs (BOLT 1).
		this.peerStorageEnabled = config.peerStorageEnabled ?? true;
		if (!this.peerStorageEnabled) {
			localFeatures.clearBit(Feature.PROVIDE_STORAGE);
			localFeatures.clearBit(Feature.PROVIDE_STORAGE + 1);
		}
		// option_dual_fund + preferTaproot: taproot v2 opens are not
		// implemented (the commitment stage fails closed), so a v2
		// negotiation under this preference is guaranteed to die after keys
		// are derived and state is retained. The mask is GLOBAL, not
		// quorum-scoped: a preferTaproot node never advertises dual_fund,
		// generic opens route through the working v1 taproot path (the
		// configured preference is honored, never silently downgraded to a
		// non-taproot v2 type), inbound open_channel2 is refused by the
		// negotiated-feature guard, and the explicit openChannelV2 API is
		// refused by the same mask at the manager.
		if (config.preferTaproot) {
			localFeatures.clearBit(Feature.DUAL_FUND);
			localFeatures.clearBit(Feature.DUAL_FUND + 1);
		}
		this.localFeatures = localFeatures;

		this.channelManager = new ChannelManager({
			localFeatures,
			localConfig: config.channelConfig,
			localBasepoints: config.channelBasepoints,
			localPerCommitmentSeed: config.perCommitmentSeed,
			localFundingPrivkey: config.fundingPrivkey,
			htlcBasepointSecret: config.htlcBasepointSecret,
			revocationBasepointSecret: config.revocationBasepointSecret,
			paymentBasepointSecret: config.paymentBasepointSecret,
			delayedPaymentBasepointSecret: config.delayedPaymentBasepointSecret,
			preferAnchors,
			// EXPERIMENTAL (option_taproot): negotiates the taproot channel type +
			// nonces but funding cannot yet complete (commitment-round MuSig2 nonce
			// rotation is not wired into the live state machine). Off by default.
			preferTaproot: config.preferTaproot,
			// Default to the node's OWN network's chain hash, never mainnet: a
			// regtest/testnet node without explicit chainHashes previously opened
			// channels (and announced) with the mainnet hash (S-7.M1).
			chainHash: config.chainHashes?.[0] ?? this.chainHash(),
			nodePrivateKey: config.nodePrivateKey,
			channelKeyDeriver: config.channelKeyDeriver,
			signerFactory: config.signerFactory,
			// Recovery 5.8: in quorum mode this holds a batch's remaining
			// actions until the frame behind them is replicated. In every
			// other mode it answers yes synchronously and dispatch is
			// unchanged.
			durabilityBarrier: this.recoveryBarrier,
			largeChannels: this.largeChannels,
			// BOLT 2 quiescence watchdog window (default 60s in the manager).
			quiescenceTimeoutMs: config.quiescenceTimeoutMs,
			// Recovery 5.7 (issue #462): on a node that may still be an
			// incomplete restore target, park an unknown channel's reestablish
			// for this long instead of failing it. Unset everywhere else, where
			// the manager answers immediately exactly as before.
			unknownChannelReestablishHoldMs:
				config.recovery?.unknownChannelReestablishHoldMs,
			// Liquidity ads seller policy (bLIP-0051): sign will_fund for inbound
			// request_funds and fund the contribution via the fundingProvider.
			leaseRates: config.leaseRates,
			// Cooperative closes are priced from the LIVE feerate, not the
			// commitment feerate (pinned to the 253 sat/kw floor on anchors,
			// where fees ride on CPFP — a closing tx has no anchor to bump).
			getClosingFeeratePerKw: (): number | undefined => {
				const satPerVbyte = this.feeAdvisor.getCurrentRate();
				return satPerVbyte > 0
					? Math.ceil(this.clampEstimatedFeeRate(satPerVbyte) * 250)
					: undefined;
			},
			// Chain-backed check that a v2 peer's tx_add_input prevout exists
			// unspent (issue #311); only offered when a chain backend was
			// configured, and read lazily because _chainBackend is assigned
			// after this construction. Never throws: any failure is 'unknown'
			// and the manager fails open.
			...(config.chainBackend
				? {
						verifyRemoteFundingInput: async (input: {
							txid: Buffer;
							vout: number;
							scriptPubKey: Buffer;
						}): Promise<'unspent' | 'spent-or-missing' | 'unknown'> => {
							const backend = this._chainBackend;
							if (!backend) return 'unknown';
							try {
								return await classifyRemoteFundingInput(backend, {
									txidDisplayHex: Buffer.from(input.txid)
										.reverse()
										.toString('hex'),
									vout: input.vout,
									scriptPubKey: input.scriptPubKey
								});
							} catch {
								return 'unknown';
							}
						}
				  }
				: {}),
			// Whether a durable row a restart could restore survives for this
			// channel (issue #311): consulted before the manager releases an
			// abandoned v2 open's funding pledges, because the abandoned
			// listener leaves the row untouched when the store cannot answer.
			// Unreadable = assume it survives (keep the pledge); a condemned
			// row is deletion-owed and can never resume.
			hasResumableChannelRow: (channelId: Buffer): boolean => {
				if (!this.storage?.loadChannel) return false;
				try {
					const row = this.storage.loadChannel(channelId.toString('hex'));
					if (!row) return false;
					return row.state.condemned !== true;
				} catch {
					return true;
				}
			}
		});
		// Let the channel manager attach wallet inputs for anchor fee bumps
		// (zero-fee second-level HTLC txs and commitment CPFP).
		this.channelManager.setFundingProvider(this.fundingProvider);
		// A wallet-owned sweep destination handed in at CONSTRUCTION must reach
		// the channel manager too: its shutdown-script logic only learned the
		// wallet address through setSweepDestinationScript, a path taken when
		// the address resolves late. On the happy path (daemon resolved the
		// wallet address BEFORE building the node), the manager stayed on its
		// P2WPKH(funding_pubkey) fallback, so a REMOTE-initiated cooperative
		// close paid its whole payout to an address the on-chain wallet never
		// scans. The funds sat confirmed but invisible until the startup
		// fallback-recovery sweep, an extra transaction and fee that this
		// forwarding makes unnecessary.
		if (config.sweepDestinationScript) {
			this.channelManager.setMonitorDestinationScript(
				config.sweepDestinationScript
			);
		}

		// Seed the fee advisor from the estimator right away. Every later
		// refresh rides a block event, but a dual-funded openChannel pins
		// funding_feerate_perkw synchronously and refuses to run off an
		// unseeded advisor, so a fresh node must not wait a whole block
		// interval before its first v2 open can price itself.
		this.warmFeeAdvisor();

		this.graph = new NetworkGraph(this.chainHash(), {
			eagerVerify: this.eagerGossipVerify,
			// Ceiling evictions (issue #446) must reach disk, or the evicted
			// rows re-inflate the graph on the next restore.
			onChannelEvicted: (scidHex) => {
				if (typeof this.storage?.deleteGossipChannel === 'function') {
					this.safeStorage(
						() => this.storage!.deleteGossipChannel!(scidHex),
						'deleteGossipChannel'
					);
				}
			},
			// A node whose last graph channel went away is deleted from memory
			// by removeChannel; without this its gossip_nodes row would outlive
			// it forever and resurrect it on every boot (issue #447). Node rows
			// are deleted only when channel rows can be too: with
			// deleteGossipChannel absent, evicted channel rows survive on disk
			// and would restore placeholder nodes whose announcements this
			// deleted. The boot orphan gate, keyed to disk channel rows, cleans
			// such backends up instead.
			onNodeEvicted: (nodeIdHex) => {
				if (
					typeof this.storage?.deleteGossipNode === 'function' &&
					typeof this.storage.deleteGossipChannel === 'function'
				) {
					this.safeStorage(
						() => this.storage!.deleteGossipNode!(nodeIdHex),
						'deleteGossipNode'
					);
				}
			}
		});

		this.onionMessageManager = new OnionMessageManager(config.nodePrivateKey);
		this.wireOnionMessageEvents();

		this.offerManager = new OfferManager(config.nodePrivateKey, {
			onionMessageManager: this.onionMessageManager,
			// Invoices issued from an async-hold offer get fresh per-invoice
			// payment paths through the LSP: hold flag intact, the given
			// path_id in the final hop, and the TRUE aggregate payinfo
			// (reusing the offer's message paths advertised fabricated zero
			// fees, leaving the payment underfunded at the LSP hop).
			buildHoldPaymentPaths: (pathId: Buffer): IBlindedPaymentPath[] =>
				this.buildBlindedPaymentPaths(true, 3, pathId),
			// Unannounced nodes: invoice payment paths run through a peer with
			// the peer's true payinfo, so the payer can route to the
			// introduction node (issue #544). Nodes with a PUBLISHED public
			// channel (announcement_signatures exchanged, not the bare intent
			// flag) keep the CLN-style single-hop path and are reached through
			// the public graph.
			buildPrivatePaymentPaths: (pathId: Buffer): IBlindedPaymentPath[] => {
				if (this.hasPublishedPublicChannel()) return [];
				return this.buildBlindedPaymentPaths(false, 2, pathId);
			}
		});
		this.wireOfferManagerEvents();

		this.asyncPaymentManager = new AsyncPaymentManager();
		this.asyncPaymentManager.attachOnionMessageManager(
			this.onionMessageManager
		);
		// Receiver: a wake message means a sender is waiting — surface it so the
		// host can reconnect to its LSP and trigger release of the held HTLC.
		this.asyncPaymentManager.on('wake', (paymentHash?: Buffer) => {
			this.emit('payment:async-wake', paymentHash);
		});

		// Resolved once and held: the PeerManager's disconnect-time redials and
		// the startup recovery below must answer to the same switch, or turning
		// auto-reconnect off silences one and not the other.
		this.autoReconnect =
			config.autoReconnect ?? config.enableNetworking ?? false;

		// Startup ownership quarantine (recovery 5.6) arrives at CONSTRUCTION,
		// before any networking exists, so no dial, listener or inbound
		// handshake can race the gate's installation. A gate attached after
		// construction would lose that race: autoReconnectPeers() below
		// schedules real dials on zero-delay timers.
		this.recoveryGate = config.recovery?.startupGate;
		// The barrier is wired FIRST so its own gate hook is registered before
		// the gate's peer bring-up runs: replication is then already in flight
		// when the first batch arrives to be held.
		if (this.recoveryBarrier) {
			this.wireRecoveryBarrier(this.recoveryBarrier, journal);
		}
		if (this.recoveryGate) this.wireRecoveryGate(this.recoveryGate);

		if (config.enableNetworking) {
			this.peerManager = new PeerManager({
				localPrivateKey: config.nodePrivateKey,
				localFeatures,
				networks: config.chainHashes,
				autoReconnect: this.autoReconnect,
				maxReconnectDelay: config.maxReconnectDelay,
				socks5Proxy: config.socks5Proxy,
				webSocketImpl: config.webSocketImpl
			});
			this.channelManager.attachToPeerManager(this.peerManager);
			// The socket boundary answers to the startup quarantine gate
			// (recovery 5.6). ChannelManager sends via sendToPeer DIRECTLY
			// when a PeerManager is attached, so gating only the node-level
			// message:outbound relay would leave the production path open.
			this.peerManager.setOutboundGate((pubkey, type) => {
				if (this.recoveryPermitsPeerTraffic()) return true;
				this.recoveryGate?.reportBlocked(
					`suppressed outbound message type ${type} to ${pubkey}`
				);
				return false;
			});
			// Connections themselves answer to the gate too: the spec's rule
			// is "may not even connect", not "connect but stay quiet". Dials
			// throw at dialPeer (the one chokepoint every dial path uses) and
			// inbound sockets die before the BOLT 8 handshake.
			this.peerManager.setConnectionGate(() => {
				if (this.recoveryPermitsPeerTraffic()) return true;
				this.recoveryGate?.reportBlocked(
					`refused peer connection while ${this.getRecoveryGateState()}`
				);
				return false;
			});
			// Defense in depth behind the connection gate: a message arriving
			// on a connection that predates a fence is dropped at the
			// transport, before the channel manager can act on it (an inbound
			// error would otherwise force-close and BROADCAST).
			this.peerManager.setInboundGate((pubkey, type) => {
				if (this.recoveryPermitsPeerTraffic()) return true;
				this.recoveryGate?.reportBlocked(
					`dropped inbound message type ${type} from ${pubkey}`
				);
				return false;
			});
			this.registerGossipHandlers();
			this.registerOnionMessageHandler();
			this.registerPeerStorageHandlers();
			this.registerCustomMessageHandler();
			this.wirePeerManagerEvents();
		}

		// Create chain watcher if backend provided
		if (config.chainBackend) {
			this._chainBackend = config.chainBackend;
			// Sweep into a wallet-owned address when provided, so recovered funds
			// land in the tracked wallet; else fall back to the funding-key P2WPKH.
			const destinationScript = this.getSweepDestinationScript();
			this.chainWatcher = new ChainWatcher({
				backend: config.chainBackend,
				channelManager: this.channelManager,
				destinationScript,
				// Remote force-close / breach sweeps must be built at a live rate,
				// not the 10 sat/vB default (kept warm via handleNewBlock).
				getSweepFeeRatePerVbyte: (): number =>
					this.resolveForceCloseFeeRatePerVbyte()
			});
			this.wireChainWatcherEvents();
		}

		this.wireChannelManagerEvents();

		// Restore from storage if available
		if (this.storage) {
			// The quorum eligibility preflight runs BEFORE restoration touches
			// anything: restore deletes record-less DUAL_FUNDING_V2 rows
			// durably (RBF residue) and can journal the first quorum frame
			// while doing it, so a post-restore scan would both miss rows and
			// leave a half-mutated database behind its own refusal, making
			// the suggested async-remote retry impossible.
			let carriedV2Rows: string[] = [];
			if (barrier?.enforcing === true) {
				carriedV2Rows = this.assertQuorumCanCarryStoredV2Opens(
					chainPromisedQuorum(
						this.storage,
						deriveRecoveryMasterKey(config.nodePrivateKey),
						getPublicKey(config.nodePrivateKey)
					)
				);
			}
			// REPAIR INTENT FIRST: the schema migration consumes its marker
			// and restore consumes the carried rows, so a crash after either
			// but before the receipt target is stored would leave the next
			// boot with no trigger at all while the guardians still owe the
			// receipt. Persist the owed marker BEFORE any trigger is
			// consumed; the concrete tail overwrites it below, and a boot
			// that finds the bare marker gates on its own verified tip.
			const REPAIR_TAIL_KEY = 'startup_repair_tail';
			const priorTail = this.storage.getRecoveryMeta?.(REPAIR_TAIL_KEY);
			const tailOwed = priorTail != null && priorTail !== '';
			// The stored tail is either the bare intent sentinel or a decimal
			// frame sequence, nothing else. An unrecognized value means the
			// metadata is corrupt, and guessing between 'owed' and a sequence
			// would rewrite a guardian obligation from garbage: refuse.
			if (
				barrier != null &&
				tailOwed &&
				priorTail !== 'owed' &&
				!/^\d+$/.test(priorTail!)
			) {
				throw new Error(
					`recovery: the stored startup repair marker '${priorTail}' ` +
						`is not recognized; refusing to start`
				);
			}
			const needsSchemaRepair =
				this.recoveryJournal?.needsSnapshotSchemaRepair() ?? false;
			const owesRepair =
				barrier !== undefined &&
				barrier !== null &&
				(carriedV2Rows.length > 0 || needsSchemaRepair || tailOwed);
			// Write the bare sentinel ONLY when no trigger is stored yet: an
			// existing numeric tail is already durable AND may sit above the
			// local tip, so replacing it with 'owed' would let a crash right
			// here lower the next boot's receipt target to its own tip and
			// lift quarantine before the original target was receipted.
			if (owesRepair && !tailOwed) {
				this.storage.setRecoveryMeta?.(REPAIR_TAIL_KEY, 'owed');
			}
			this.restoreFromStorage();
			// One-time snapshot-content repair: heads compacted by an older
			// release omitted deleted channels' key-index rows, and a quiet
			// upgraded node might never write a replacement frame. Forcing a
			// fresh full snapshot here (once, versioned) restores the burned
			// high-water marks to whatever the guardians hold next.
			const schemaRepairSeq =
				this.recoveryJournal?.snapshotSchemaRepair() ?? null;
			if (schemaRepairSeq !== null) {
				this.emitStructuredLog('channel', 'snapshot_schema_repaired', {
					frameSequence: String(schemaRepairSeq)
				});
			}
			// A carried row entered this database OUTSIDE the journal (it
			// predates the record, or was written by a release without the
			// preflight), so guardian reconstruction would omit a channel
			// whose funding the peer may be able to broadcast. Repair that
			// BEFORE any networking, fail-closed: one frame carries every
			// still-tracked carried row, a carried row whose deletion
			// disposition FAILED refuses startup outright, and the node stays
			// quarantined behind its own traffic gates until the JOURNAL TIP
			// (which covers the repair frame, every deletion frame written
			// during restore, and the schema-repair snapshot) is
			// quorum-RECEIPTED, so nothing this node ever says can outrun
			// what the guardians can restore.
			const failedCarried = carriedV2Rows.filter((idHex) =>
				this.restoreDeletionFailures.includes(idHex)
			);
			if (failedCarried.length > 0) {
				throw new Error(
					`recovery: the carried v2 open(s) ${failedCarried.join(', ')} ` +
						`could not be dispositioned durably (deletion failed); ` +
						`refusing to start over an unrepaired quorum database`
				);
			}
			const repairMutations: RecoveryMutation[] = [];
			for (const idHex of carriedV2Rows) {
				const channel = this.channelManager.getChannel(
					Buffer.from(idHex, 'hex')
				);
				if (!channel) continue; // took a (durable) deletion disposition
				const peer = this.channelManager.getPeerForChannel(
					Buffer.from(idHex, 'hex')
				);
				repairMutations.push({
					type: 'channel_state',
					channelId: idHex,
					state: channel.getFullState(),
					peerPubkey: peer ?? ''
				});
			}
			if (repairMutations.length > 0 && this.recovery) {
				const repair = this.recovery.commit({
					criticality: RecoveryCriticality.Important,
					mutations: repairMutations,
					outboundMessages: [],
					reportedByCaller: true
				});
				if (!repair.committed) {
					throw new Error(
						`recovery: could not journal the carried v2 open(s) ` +
							`(${repair.error?.message ?? 'commit refused'}); refusing ` +
							`to start over an unrepaired quorum database`
					);
				}
			}
			// Receipt gating keys on the TIP, not one frame: deletion-only
			// dispositions and the schema repair write frames this boot too,
			// and receipts are cumulative, so the tip covers them all. The
			// intent marker written above survives any crash between trigger
			// consumption and here; the concrete tail replaces it now.
			if (owesRepair) {
				const tip = storedTipSequence(this.storage);
				if (tip === null) {
					// Fail closed: a repair is owed but the local tip cannot
					// be verified, so there is nothing sound to wait on.
					throw new Error(
						`recovery: a startup repair is owed but the journal tip ` +
							`cannot be verified; refusing to start`
					);
				}
				const numericPrior =
					tailOwed && /^\d+$/.test(priorTail!) ? BigInt(priorTail!) : null;
				const repairTail =
					numericPrior !== null && numericPrior > tip ? numericPrior : tip;
				this.storage.setRecoveryMeta?.(REPAIR_TAIL_KEY, repairTail.toString());
				this.startupRepairPending = true;
				this.emitStructuredLog('channel', 'startup_repair_pending', {
					frameSequence: String(repairTail),
					channels: carriedV2Rows
				});
				barrier!.kickReplication?.();
				void barrier!
					.whenReleased(repairTail)
					.then((outcome) => {
						if (this._destroyed) return;
						if (!outcome.released) {
							// Quarantine holds: the operator sees why, the
							// stored tail survives the restart, and the gates
							// keep refusing until a boot with a reachable
							// quorum receipts it.
							try {
								this.emitStructuredLog(
									'channel',
									'startup_repair_unreceipted',
									{ reason: outcome.reason }
								);
							} catch {
								// Reporting is best effort; the state holds.
							}
							try {
								this.emit('node:error', {
									code: 'STARTUP_REPAIR_UNRECEIPTED',
									message:
										`the startup repair frames were not accepted ` +
										`by a guardian quorum (${outcome.reason}); the ` +
										`node stays quarantined`,
									timestamp: Date.now()
								} as ILightningError);
							} catch {
								// Observer threw; quarantine already holds.
							}
							return;
						}
						// Observers first, CONTAINED: reporting must never be
						// able to corrupt the receipt transition itself.
						try {
							this.emitStructuredLog('channel', 'startup_repair_receipted', {
								frameSequence: String(repairTail)
							});
						} catch {
							// Best effort.
						}
						// The transition proper: tail cleared and quarantine
						// lifted TOGETHER, or neither (the stored tail is the
						// retry marker, so it must never be lost while the
						// node still reports pending).
						try {
							this.storage?.setRecoveryMeta?.(REPAIR_TAIL_KEY, '');
							this.startupRepairPending = false;
						} catch (err) {
							this.startupRepairPending = true;
							try {
								this.emit('node:error', {
									code: 'STARTUP_REPAIR_COMPLETION_FAILED',
									message: `finishing the startup repair failed: ${
										err instanceof Error ? err.message : String(err)
									}; the node stays quarantined`,
									timestamp: Date.now()
								} as ILightningError);
							} catch {
								// Observer threw; quarantine already holds.
							}
							return;
						}
						try {
							this.autoReconnectPeers();
						} catch (err) {
							// Readiness is guaranteed even when the reconnect
							// pass or an error observer explodes: the repair
							// IS receipted, and reporting must not undo that.
							try {
								this.emit('node:error', {
									code: 'STARTUP_RECONNECT_FAILED',
									message: `post-repair reconnect failed: ${
										err instanceof Error ? err.message : String(err)
									}`,
									timestamp: Date.now()
								} as ILightningError);
							} catch {
								// Observer threw; ready still fires below.
							}
							this.emitReady();
						}
					})
					.catch((err) => {
						// With the success path fully contained above, only a
						// genuine whenReleased rejection can land here: REPORT
						// it and keep the deterministic quarantined state (the
						// stored tail retries next boot).
						if (this._destroyed) return;
						try {
							this.emit('node:error', {
								code: 'STARTUP_REPAIR_UNRECEIPTED',
								message: `the startup repair wait failed: ${
									err instanceof Error ? err.message : String(err)
								}; the node stays quarantined`,
								timestamp: Date.now()
							} as ILightningError);
						} catch {
							// Observer threw; quarantine already holds.
						}
					});
			}
			// Auto-reconnect peers after crash recovery (Fix 2.1); deferred
			// to the receipt callback while the repair quarantine holds.
			if (!this.startupRepairPending) {
				this.autoReconnectPeers();
			}
		}

		// Compose the initial Recovery Capsule (spec 5.4) so peers connecting
		// before the first journaled transition still receive a current blob
		// via sendPeerStorageOnConnect.
		this.scheduleRecoveryCapsuleRefresh();

		this.startCleanupTimer();

		// Start MPP cleanup timer if BASIC_MPP feature is enabled
		if (localFeatures.hasFeature(Feature.BASIC_MPP)) {
			this.mppCleanupTimer = setInterval(() => {
				this.failTimedOutMppPayments();
			}, 30_000);
			if (this.mppCleanupTimer.unref) {
				this.mppCleanupTimer.unref();
			}
		}

		// Start periodic fee update timer only when explicitly enabled (see
		// autoUpdateChannelFees — off by default to avoid commitment-fee desyncs).
		if (this.feeEstimator && this.autoUpdateChannelFees) {
			this.feeUpdateTimer = setInterval(() => {
				this.checkAndUpdateFees().catch((err) => {
					this.emitStructuredLog('fee', 'update_failed', {
						error: err instanceof Error ? err.message : String(err)
					});
				});
			}, 600_000); // every 10 minutes
			if (this.feeUpdateTimer.unref) {
				this.feeUpdateTimer.unref();
			}
		}

		// Start periodic mission control persistence (every 5 min)
		if (this.storage) {
			this.missionControlTimer = setInterval(() => {
				if (this.storage && this.missionControl.size > 0) {
					try {
						this.storage.saveMissionControl(this.missionControl.export());
					} catch (err) {
						this.emit('node:error', {
							code: 'PERSISTENCE_ERROR',
							message: `Failed to persist mission control: ${
								(err as Error).message
							}`,
							timestamp: Date.now()
						} as ILightningError);
					}
				}
			}, 300_000);
			if (this.missionControlTimer.unref) {
				this.missionControlTimer.unref();
			}
		}

		// Advisor execution timers -- both features are opt-in (enabled: true).
		this.autoRebalanceConfig = config.autoRebalance ?? {};
		this.autoTuneFeesConfig = config.autoTuneFees ?? {};
		if (this.autoRebalanceConfig.enabled === true) {
			this.autoRebalanceTimer = setInterval(() => {
				this.executeRebalanceRecommendations().catch((err) => {
					this.emitStructuredLog('payment', 'auto_rebalance_failed', {
						error: err instanceof Error ? err.message : String(err)
					});
				});
			}, this.autoRebalanceConfig.intervalMs ?? 3_600_000);
			if (this.autoRebalanceTimer.unref) {
				this.autoRebalanceTimer.unref();
			}
		}
		if (this.autoTuneFeesConfig.enabled === true) {
			this.autoTuneFeesTimer = setInterval(() => {
				try {
					this.runFeeTuneOnce();
				} catch (err) {
					this.emitStructuredLog('fee', 'auto_tune_failed', {
						error: err instanceof Error ? err.message : String(err)
					});
				}
			}, this.autoTuneFeesConfig.intervalMs ?? 21_600_000);
			if (this.autoTuneFeesTimer.unref) {
				this.autoTuneFeesTimer.unref();
			}
		}

		// Start hourly graph pruning timer (also deletes from storage)
		this.graphPruneTimer = setInterval(() => {
			this.pruneStaleGossipWithStorage();
		}, 3_600_000); // every hour
		if (this.graphPruneTimer.unref) {
			this.graphPruneTimer.unref();
		}

		// Start WAL checkpoint timer (every 30 minutes)
		if (this.storage && typeof this.storage.checkpoint === 'function') {
			this.walCheckpointTimer = setInterval(() => {
				try {
					this.storage!.checkpoint!();
				} catch (err) {
					this.emit('node:error', {
						code: 'WAL_CHECKPOINT_FAILED',
						message: `WAL checkpoint failed: ${(err as Error).message}`,
						timestamp: Date.now()
					} as ILightningError);
				}
			}, 1_800_000); // 30 minutes
			if (this.walCheckpointTimer.unref) {
				this.walCheckpointTimer.unref();
			}
		}

		// Auto-start chain watcher if backend was provided
		if (this.chainWatcher) {
			this.startChainWatcher().catch((err) => {
				this.emit('node:error', {
					code: 'CHAIN_WATCHER_START_FAILED',
					message: (err as Error).message,
					timestamp: Date.now()
				} as ILightningError);
			});
		}
	}

	// ─────────────── Storage Restore ───────────────

	/**
	 * Quorum eligibility preflight over the STORED rows, read-only, before
	 * restoration mutates or journals anything.
	 *
	 * A RECORDED in-flight v2 open (v2InFlight) is resumable and quorum
	 * carries it: the record is exactly what makes the round provable
	 * again. A record-less v2 row is different in kind: it restores
	 * without a session, cannot answer a retransmitted tx_signatures or a
	 * peer's next_funding (the splice handler answers with tx_abort),
	 * and ignores funding confirmation, so carrying it would snapshot
	 * state the mode cannot actually resume. That covers every pre-NORMAL
	 * v2 state: DUAL_FUNDING_V2 and AWAITING_TX_SIGNATURES always, and
	 * AWAITING_FUNDING_CONFIRMED / AWAITING_CHANNEL_READY when the row is
	 * fundingVersion 2 (a v1 row in those states resumes fine and is left
	 * alone). Refuse to come up; finish or abandon it under async-remote
	 * first, which this preflight keeps possible by throwing before a
	 * single row is deleted or a single frame is written.
	 *
	 * EXCEPT when the journal is already sticky quorum. A pre-record v2
	 * row can have entered quorum legitimately (opened under an earlier
	 * release, quorum enabled while the guard did not exist, frames
	 * written since), and once the chain promised quorum the async-remote
	 * retry this refusal recommends is itself refused, so throwing here
	 * would leave the database with NO startup path. Such a row is
	 * carried instead, loudly: it takes its deterministic disposition
	 * (residue deletion, inert orphan, or a tx_abort answer to the peer's
	 * reestablish followed by an operator close), none of which claims
	 * the resumability this preflight polices, and none of which is
	 * broadcastable, so wire safety is untouched.
	 */
	private assertQuorumCanCarryStoredV2Opens(alreadyQuorum: boolean): string[] {
		const carried: string[] = [];
		for (const row of this.storage!.loadAllChannels()) {
			const state = row.state;
			if (state.v2InFlight) continue;
			// A row persisted mid-reestablish carries the state it will
			// return to; judge that one.
			const st =
				state.state === ChannelState.AWAITING_REESTABLISH &&
				state.preReestablishState
					? state.preReestablishState
					: state.state;
			const alwaysV2 =
				st === ChannelState.DUAL_FUNDING_V2 ||
				st === ChannelState.AWAITING_TX_SIGNATURES;
			const v2Later =
				state.fundingVersion === 2 &&
				(st === ChannelState.AWAITING_FUNDING_CONFIRMED ||
					st === ChannelState.AWAITING_CHANNEL_READY);
			if (!alwaysV2 && !v2Later) continue;
			if (alreadyQuorum) {
				this.emitStructuredLog(
					'channel',
					'quorum_carries_unresumable_v2_open',
					{
						channelId: row.channelId,
						state: st
					}
				);
				carried.push(row.channelId);
				continue;
			}
			throw new Error(
				`recovery: cannot enable quorum durability while a ` +
					`dual-funded open with no durable in-flight record is in ` +
					`progress (channel ${row.channelId} is ${st}); it cannot ` +
					`resume over reestablish, so finish or abandon it under ` +
					`async-remote durability first`
			);
		}
		return carried;
	}

	private restoreFromStorage(): void {
		if (!this.storage) return;

		// Seed the per-channel key index from storage FIRST: restoreChannel
		// advances it from each restored row, but a row removed below never
		// restores, and a stale index would hand the next channel a previous
		// channel's funding keys and per-commitment seed. Guarded call: test
		// doubles implement partial backends.
		const nextChannelIndex = this.storage.loadNextChannelIndex?.() ?? 1;
		if (nextChannelIndex > this.channelManager.nextChannelIndex) {
			this.channelManager.nextChannelIndex = nextChannelIndex;
		}

		// Restore channels — look up per-channel key index for each
		for (const {
			channelId,
			state,
			peerPubkey
		} of this.storage.loadAllChannels()) {
			// A CONDEMNED row's removal was already decided; the intent rides
			// the row itself, so there is no separate store whose read can
			// fail and silently resurrect it. Retry the deletion now; a row
			// whose deletion fails again stays condemned on disk, is NOT
			// restored, and retries at every start. The terminal event fires
			// exactly once, when the deletion lands.
			if (state.condemned) {
				if (this.deleteChannelDurably(channelId)) {
					this.emitStructuredLog('channel', 'condemned_row_removed', {
						channelId
					});
					const condemnedId = Buffer.from(channelId, 'hex');
					setImmediate(() =>
						this.emit('channel:voided', { channelId: condemnedId })
					);
				} else {
					this.emitStructuredLog('channel', 'channel_deletion_still_owed', {
						channelId
					});
				}
				continue;
			}
			// A row persisted mid-reestablish names the state it returns to,
			// and the DUAL_FUNDING_V2 dispositions below must judge THAT one:
			// a wrapped record-less row would otherwise skip the residue
			// deletion and restore as a phantom that answers nothing.
			if (
				state.state === ChannelState.AWAITING_REESTABLISH &&
				state.preReestablishState === ChannelState.DUAL_FUNDING_V2
			) {
				state.state = ChannelState.DUAL_FUNDING_V2;
				state.preReestablishState = null;
			}
			// A DUAL_FUNDING_V2 row WITH a record is a provisionally accepted
			// RBF whose post-ack traffic never arrived: the record is the
			// previous attempt, still resumable and possibly the only side
			// the peer knows. Roll the row back to it and restore normally
			// (restoreChannel marks it for reestablish); the rewrite is
			// idempotent across crashes, so the row itself needs no update.
			// Attempt-aware: a previous attempt whose witnesses left resumes
			// waiting on the chain, not on the peer.
			if (state.state === ChannelState.DUAL_FUNDING_V2 && state.v2InFlight) {
				state.state = this.v2RetainedAttemptState(state.v2InFlight);
				this.emitStructuredLog('channel', 'v2_rbf_provisional_rolled_back', {
					channelId
				});
			}
			// A record-less DUAL_FUNDING_V2 row is RBF-renegotiation residue:
			// the committed replacement's session died with the process
			// before anything was signed. There is no channel in it: no
			// funding tx, no signatures, nothing the peer can complete.
			// Remove the row durably (the voidMissingFundingChannel pattern)
			// instead of restoring a permanent channel that sends nothing,
			// answers nothing, and repeats this on every restart; a peer that
			// still asks gets the manager's unknown-channel error and gives
			// the attempt up.
			if (state.state === ChannelState.DUAL_FUNDING_V2) {
				if (this.deleteChannelDurably(channelId)) {
					this.emitStructuredLog('channel', 'v2_rbf_residue_removed', {
						channelId
					});
				} else {
					// Fail closed: the row stays on disk (retried next start),
					// the channel is NOT restored, and a quorum startup that
					// was carrying this row refuses to come up over the
					// undispositioned residue.
					this.restoreDeletionFailures.push(channelId);
					this.emitStructuredLog('channel', 'v2_rbf_residue_removal_failed', {
						channelId
					});
				}
				continue;
			}
			const channel = new Channel(state);
			const keyIndex = this.storage!.loadChannelKeyIndex(channelId);
			this.channelManager.restoreChannel(channel, peerPubkey, keyIndex);
			// This row was read off disk and nothing has checked it against
			// the peer or the chain yet. Only the STARTUP restore registers
			// that: the live re-restore paths (a blocked persist resync, an
			// abandonment revert) re-read a row this process negotiated
			// itself (issue #463).
			this.channelManager.markChannelRestoredFromDisk(
				Buffer.from(channelId, 'hex')
			);
			// AFTER restoreChannel: markForReestablish resets the splice driver
			// for non-splicing channels, and that reset clears _lastSentBatch,
			// so bytes restored before it would be silently wiped.
			this.restoreOutboxRetransmission(channelId, channel);
		}

		// Restore payments
		for (const { paymentHash, payment } of this.storage.loadAllPayments()) {
			this.payments.set(paymentHash, payment);
		}

		// Restore preimages — and re-seed the ChannelManager's preimage store so
		// monitors created by a POST-restart force-close can still claim inbound
		// HTLCs on-chain (recordPreimage is idempotent; monitors restored later
		// in this function are seeded from the same store).
		for (const { paymentHash, preimage } of this.storage.loadAllPreimages()) {
			this.preimages.set(paymentHash, preimage);
			this.channelManager.recordPreimage(
				Buffer.from(paymentHash, 'hex'),
				preimage
			);
		}

		// Restore SCID mappings
		for (const { scidHex, channelId } of this.storage.loadAllScidMappings()) {
			this.scidToChannelId.set(scidHex, channelId);
		}

		// Backfill real SCIDs for channels that were already open before this node
		// learned to register them. Without this, an existing announced channel stays
		// unforwardable until it is reopened. registerChannelScid persists the mapping,
		// so this is a one-time repair rather than work repeated every boot.
		for (const { state } of this.storage.loadAllChannels()) {
			const scid = state.shortChannelId;
			if (!scid || !state.channelId) continue;
			if (!this.shouldAcceptRealScid(state)) continue;
			if (this.scidToChannelId.has(scid.toString('hex'))) continue;
			this.registerChannelScid(state.channelId, scid);
		}

		// Restore HTLC payment mappings
		for (const {
			key,
			paymentHashHex
		} of this.storage.loadAllHtlcPaymentMappings()) {
			this.htlcPaymentMap.set(key, paymentHashHex);
		}

		// Restore forwarded HTLCs
		for (const {
			outKey,
			inChannelId,
			inHtlcId
		} of this.storage.loadAllForwardedHtlcs()) {
			this.forwardedHtlcs.set(outKey, { inChannelId, inHtlcId });
		}

		// Restore payment secrets
		for (const {
			paymentHashHex,
			secret
		} of this.storage.loadAllPaymentSecrets()) {
			this.paymentSecrets.set(paymentHashHex, secret);
		}

		// Restore HTLC shared secrets (for failure decryption after crash)
		for (const { key, secret } of this.storage.loadAllHtlcSharedSecrets()) {
			this.receivedHtlcSharedSecrets.set(key, secret);
		}

		// Restore per-channel routing-policy overrides
		if (this.storage.loadAllChannelPolicies) {
			for (const {
				channelId,
				policy
			} of this.storage.loadAllChannelPolicies()) {
				const override: IChannelPolicyUpdate = {};
				if (policy.feeBaseMsat !== undefined)
					override.feeBaseMsat = policy.feeBaseMsat;
				if (policy.feeProportionalMillionths !== undefined)
					override.feeProportionalMillionths = policy.feeProportionalMillionths;
				if (policy.cltvExpiryDelta !== undefined)
					override.cltvExpiryDelta = policy.cltvExpiryDelta;
				if (policy.htlcMinimumMsat !== undefined)
					override.htlcMinimumMsat = BigInt(policy.htlcMinimumMsat);
				if (policy.htlcMaximumMsat !== undefined)
					override.htlcMaximumMsat = BigInt(policy.htlcMaximumMsat);
				this.channelPolicies.set(channelId, override);
			}
		}

		// Restore invoices — migrate ms timestamps to seconds if needed
		for (const { paymentHashHex, invoice } of this.storage.loadAllInvoices()) {
			if (invoice.createdAt > 10_000_000_000) {
				invoice.createdAt = Math.floor(invoice.createdAt / 1000);
			}
			this.invoices.set(paymentHashHex, invoice);
			// Rebuild the hold-invoice set so incoming HTLCs are parked, not settled.
			// A cancelled hold invoice must NOT re-arm parking: drop its preimage
			// and secret from memory so a late HTLC fails with unknown-details.
			if (invoice.hold) {
				if (invoice.cancelledAt) {
					this.preimages.delete(paymentHashHex);
					this.paymentSecrets.delete(paymentHashHex);
				} else {
					this.heldInvoiceHashes.add(paymentHashHex);
				}
			}
		}

		// Restore BOLT 12 offers so a shared offer keeps answering
		// invoice_requests after a restart instead of dying with the process.
		this.offerManager.attachStorage(this.storage);

		// Restore funding txs still awaiting broadcast/confirmation so the
		// BOLT 2 broadcast obligation survives a restart.
		this.restorePendingFundingTxs();

		// Restore parked hold-invoice HTLCs so settle/cancel survive restart.
		const heldJson = this.storage.loadMetadata('held_htlcs');
		if (heldJson) {
			try {
				const parsed = JSON.parse(heldJson) as Array<{
					hashHex: string;
					htlcs: Array<{
						channelId: string;
						htlcId: string;
						amountMsat: string;
						cltvExpiry: number;
					}>;
				}>;
				for (const entry of parsed) {
					this.heldHtlcs.set(
						entry.hashHex,
						entry.htlcs.map((h) => ({
							channelId: Buffer.from(h.channelId, 'hex'),
							htlcId: BigInt(h.htlcId),
							amountMsat: BigInt(h.amountMsat),
							cltvExpiry: h.cltvExpiry
						}))
					);
				}
			} catch {
				/* ignore corrupted held-htlc metadata */
			}
		}

		// Restore block height
		const savedHeight = this.storage.loadMetadata('blockHeight');
		if (savedHeight) {
			const height = parseInt(savedHeight, 10);
			if (!isNaN(height) && height > 0) {
				this.currentBlockHeight = height;
			}
		}

		// Restore mission control
		const mcJson = this.storage.loadMissionControl();
		if (mcJson) {
			try {
				this.missionControl.import(mcJson);
			} catch (err) {
				this.emit('node:error', {
					code: 'PERSISTENCE_ERROR',
					message: `Failed to restore mission control: ${
						(err as Error).message
					}`,
					timestamp: Date.now()
				} as ILightningError);
			}
		}

		// Restore chain monitors (only if we have chain monitors to restore)
		const monitors = this.storage.loadAllChainMonitors();
		if (monitors.length > 0) {
			// Sweep into the wallet-owned address when configured (see INodeConfig),
			// else fall back to the funding-key P2WPKH.
			const destinationScript = this.getSweepDestinationScript();
			for (const { channelId, state: monitorState } of monitors) {
				const channel = this.channelManager.getChannel(
					Buffer.from(channelId, 'hex')
				);
				if (!channel) continue;
				const channelState = channel.getFullState();
				// Use the channel's per-channel signing keys when present, so on-chain
				// claims (e.g. our to_remote on a remote force-close) are signed with
				// the channel's payment basepoint rather than the node base key.
				const perCh = this.channelManager.getMonitorSigningKeys(
					Buffer.from(channelId, 'hex')
				);
				const monitor = ChainMonitor.restore(
					monitorState,
					channelState,
					destinationScript,
					10, // safe default fee rate (sat/vbyte), updated when fee estimator resolves
					// Mirror the create path (channel-manager) EXACTLY so a restored
					// monitor signs with the same per-channel secrets — using the
					// config's revocation/payment basepoint secrets, NOT node/funding
					// keys (audit H2: the wrong keys broke penalty, to_remote, and HTLC
					// claims after a restart for the node-level-basepoints config).
					perCh?.revocationBasepointSecret ||
						this.revocationBasepointSecret ||
						this.fundingPrivkey,
					perCh?.paymentBasepointSecret ||
						this.paymentBasepointSecret ||
						this.fundingPrivkey,
					undefined, // network (default)
					perCh?.delayedPaymentBasepointSecret ||
						this.delayedPaymentBasepointSecret ||
						this.fundingPrivkey,
					perCh?.htlcBasepointSecret || this.htlcBasepointSecret
				);
				this.channelManager.restoreMonitor(channelId, monitor);

				// Older monitor state could mark a revoked close fully resolved
				// before a snapshot-only penalty output was adopted. If that state
				// also closed the channel, reopen the force-close lifecycle together
				// with the repaired monitor. Cooperative closes are intentionally
				// excluded because CLOSED is valid while their monitor reaches depth.
				const restoredCommitment = monitor.getFullState().commitmentBroadcast;
				if (
					channelState.state === ChannelState.CLOSED &&
					!monitor.isFullyResolved() &&
					restoredCommitment?.commitmentType ===
						CommitmentType.THEIR_REVOKED_COMMITMENT
				) {
					channelState.state = ChannelState.FORCE_CLOSED;
					this.dirtyMonitors.add(channelId);
					this.persistChannel(Buffer.from(channelId, 'hex'));
					this.emitStructuredLog('channel', 'resolution_reopened', {
						channelId
					});
					// Reconcile: if the monitor already finished resolving every output
					// of this close (possibly in a prior session where the resolved
					// transition was never persisted), move the channel to CLOSED now so
					// it doesn't report a stale pending-close balance forever.
				} else if (
					monitor.isFullyResolved() &&
					this.channelManager.markChannelResolved(Buffer.from(channelId, 'hex'))
				) {
					this.persistChannel(Buffer.from(channelId, 'hex'));
					this.emitStructuredLog('channel', 'resolved', { channelId });
				}
			}

			// Re-arm the anchor commitment CPFP for OUR still-unconfirmed
			// force-closes: the tracking map is in-memory only, so without this a
			// restart leaves the low-fee commitment package unbumped forever.
			// rearmCommitmentCpfp resolves its own live-or-floored feerate, so this
			// MUST run regardless of whether the estimator succeeded (a transient
			// estimator error or a <=0 sample must not leave the package unbumped).
			const rearmAllCommitmentCpfp = (): void => {
				for (const { channelId: monitorChannelId } of monitors) {
					this.channelManager.rearmCommitmentCpfp(
						Buffer.from(monitorChannelId, 'hex'),
						this.resolveForceCloseFeeRatePerVbyte()
					);
				}
			};

			// Update restored chain monitors with current fee rate if estimator available
			if (this.feeEstimator) {
				this.feeEstimator
					.estimateFee(6)
					.then((rawSatPerVbyte) => {
						const satPerVbyte = this.clampEstimatedFeeRate(rawSatPerVbyte);
						if (satPerVbyte > 0) {
							this.feeAdvisor.recordSample(satPerVbyte);
							const feeratePerKw = Math.max(
								satPerVbyteToSatPerKw(satPerVbyte),
								MIN_FEERATE_PER_KW
							);
							this.channelManager.updateMonitorFeeRates(
								feeratePerKw,
								monitors.map(
									({ channelId: monitorChannelId }) => monitorChannelId
								)
							);
						}
						// Re-arm even on a <=0 sample.
						rearmAllCommitmentCpfp();
					})
					.catch((err) => {
						this.emitStructuredLog('fee', 'estimate_failed', {
							error: err instanceof Error ? err.message : String(err)
						});
						// Re-arm even when the estimator errored.
						rearmAllCommitmentCpfp();
					});
			} else {
				// No estimator: still re-arm at the fallback feerate so the
				// commitment package is at least re-broadcast + CPFP-tracked.
				rearmAllCommitmentCpfp();
			}
		}

		// Restore gossip graph. Stale rows are filtered out BEFORE the graph's
		// restore ceiling sees them: startup pruning removes them right after
		// anyway, so letting one occupy a ceiling slot first could evict (and
		// delete) a fresh row it will not outlive. Far-future timestamps do
		// not count toward freshness here for the same reason: restoreChannel
		// drops those slots, leaving such a row equally short-lived.
		const gossipRestoreCutoff =
			Math.floor(Date.now() / 1000) - DEFAULT_PRUNE_MAX_AGE;
		// Endpoints of every channel row that stays on disk past the stale
		// filter. Node-row orphanhood below is decided against DISK, not the
		// capped in-memory graph: restoreChannel keeps verified overflow rows
		// on disk without admitting them, and their node rows must survive
		// alongside them. Rows restoreChannel itself trims from disk leave
		// their endpoints in this set; those node rows are cleaned one boot
		// later, once their channel rows are gone.
		const diskChannelEndpoints = new Set<string>();
		for (const channel of this.storage.loadAllGossipChannels()) {
			const ts1 =
				channel.update1 &&
				!gossipTimestampTooFarFuture(channel.update1.timestamp)
					? channel.update1.timestamp
					: 0;
			const ts2 =
				channel.update2 &&
				!gossipTimestampTooFarFuture(channel.update2.timestamp)
					? channel.update2.timestamp
					: 0;
			if (Math.max(ts1, ts2) < gossipRestoreCutoff) {
				if (typeof this.storage.deleteGossipChannel === 'function') {
					const scidHex = channel.shortChannelId.toString('hex');
					this.safeStorage(
						() => this.storage!.deleteGossipChannel!(scidHex),
						'deleteGossipChannel'
					);
				}
				continue;
			}
			diskChannelEndpoints.add(channel.nodeId1.toString('hex'));
			diskChannelEndpoints.add(channel.nodeId2.toString('hex'));
			this.graph.restoreChannel(channel);
		}
		// The channel loop above created a graph node entry for every restored
		// channel endpoint. A node row absent from the graph AND from the
		// surviving disk channel rows' endpoints has no channel behind it: an
		// orphan leaked before node rows were deleted alongside their last
		// channel (issue #447). Restoring it would resurrect the leak in
		// memory, so delete the row and skip it. A node row referenced only by
		// a retained overflow channel row is kept on disk but not restored;
		// it returns with its channel on a later boot. Channel peer reconnects
		// are unaffected: their addresses live in the announced peer address
		// capture, not in gossip_nodes.
		for (const node of this.storage.loadAllGossipNodes()) {
			if (!this.graph.getNode(node.nodeId)) {
				const nodeIdHex = node.nodeId.toString('hex');
				if (
					!diskChannelEndpoints.has(nodeIdHex) &&
					typeof this.storage.deleteGossipNode === 'function'
				) {
					this.safeStorage(
						() => this.storage!.deleteGossipNode!(nodeIdHex),
						'deleteGossipNode'
					);
				}
				continue;
			}
			this.graph.restoreNode(node);
		}

		// Prune stale gossip immediately on restore (BOLT 7: >2 weeks = stale)
		this.pruneStaleGossipWithStorage();

		// Scan for expiring HTLCs immediately on restore (may have missed blocks while down)
		if (this.currentBlockHeight > 0) {
			this.scanExpiringOfferedHtlcs(this.currentBlockHeight);
			this.scanExpiringHtlcs(this.currentBlockHeight);
		}
	}

	/**
	 * Re-dispatch received HTLCs that were irrevocably committed before the last
	 * shutdown but whose resolution did not survive it.
	 *
	 * HTLC_FORWARDED is emitted once per HTLC, by handleRevokeAndAck, and the
	 * marker making it once-only is persisted with the channel. Once-only is
	 * correct while the process is up: it is what stops one inbound payment being
	 * re-forwarded on every later commitment round. But the marker reaches disk
	 * before the node layer has done anything with the HTLC, so a restart in that
	 * window would otherwise leave the HTLC COMMITTED with nothing left to act on
	 * it. The channel never re-emits, and scanForwardTimeouts skips any received
	 * HTLC with no outgoing leg, which is exactly the stranded shape. It would sit
	 * until its CLTV backstop fired: failed back late for a forward, or, because
	 * we hold the preimage for our own invoice, a force close for a final hop.
	 *
	 * The node-side state that does not survive a restart is what needs rebuilding
	 * here: in-flight MPP part sets and LSP-held forwards are both in-memory only.
	 * Anything whose resolution IS durable is skipped, so this is a repair pass
	 * rather than a second dispatch.
	 *
	 * Driven from `channel:restore-ready` rather than from restoreFromStorage,
	 * because a just-restored channel is in AWAITING_REESTABLISH and can send
	 * nothing: both the onward add and the fail-back would be refused for wrong
	 * state. The manager arms that event when it loads a channel from
	 * persistence and fires it once, at the tail of the reestablishment that
	 * returns the channel to NORMAL.
	 *
	 * It must NOT be driven by reestablishment alone. An ordinary TCP
	 * disconnect also moves a live channel into AWAITING_REESTABLISH, and this
	 * pass is only safe against node state that is genuinely gone: re-offering
	 * an HTLC whose inbound MPP part is still accumulated would count that part
	 * twice, so a payer could cycle the connection until the set reached its
	 * declared total having sent less than it owed. The guards below make a
	 * repeat run a no-op for everything they cover, but the MPP accumulator is
	 * not among them (it dedupes by (channel, htlc) as its own defense, which
	 * is a second line, not this one).
	 */
	private redispatchUnresolvedReceivedHtlcs(channelId: Buffer): void {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;

		for (const [key, htlc] of channel.getFullState().htlcs) {
			if (!key.startsWith('received-')) continue;
			// Only an irrevocably committed HTLC is safe to act on, and one we
			// already fulfilled or failed is resolved by definition.
			if (htlc.state !== HtlcState.COMMITTED) continue;
			// Never dispatched in the first place: handleRevokeAndAck still owes it
			// a dispatch and will emit when the round completes.
			if (htlc.forwardEmitted !== true) continue;
			// A forward already went out and its mapping was restored from storage.
			// The downstream leg resolves it; re-dispatching would offer a second
			// outgoing HTLC for one inbound payment, the very duplication the
			// marker exists to prevent.
			if (this.findOutgoingLeg(channelId, htlc.id)) continue;
			// Parked against a hold invoice. settle/cancel drives it, not the
			// forwarding machinery.
			if (this.isHeldHtlc(channelId, htlc.id)) continue;

			this.handleIncomingHtlc(
				channelId,
				htlc.id,
				htlc.amountMsat,
				htlc.paymentHash
			);
		}
	}

	/** True when this received HTLC is parked awaiting a hold-invoice decision. */
	private isHeldHtlc(channelId: Buffer, htlcId: bigint): boolean {
		for (const held of this.heldHtlcs.values()) {
			for (const h of held) {
				if (h.htlcId === htlcId && h.channelId.equals(channelId)) return true;
			}
		}
		return false;
	}

	// ─────────────── Storage Persist Helpers ───────────────

	/**
	 * Commit a channel's safety transition: its state, its key index, any chain
	 * monitor delta that this same action produced, and the exact wire bytes
	 * the transition authorizes, all in ONE storage transaction
	 * (docs/RECOVERY-PROTOCOL.md 5.1).
	 *
	 * `request` arrives with the PERSIST_STATE action when the batch has
	 * messages to send. On failure it is answered with `committed: false`,
	 * which withholds those sends: a message whose justifying state is not on
	 * disk must never reach the peer.
	 */
	/**
	 * Commit a freshly reconstructed recovery channel BEFORE it is exposed
	 * through the ChannelManager. persistChannel cannot serve here: it
	 * resolves the channel from the manager (not yet registered) and
	 * reports failure only through an event, while this install must gate
	 * on durability. Returns whether the commit landed; one
	 * PERSISTENCE_ERROR is emitted on failure.
	 */
	private persistRecoveredChannel(
		channel: Channel,
		peerPubkey: string,
		keyIndex: number | null | undefined
	): boolean {
		if (!this.storage || !this.recovery) return false;
		const channelId = channel.getChannelId();
		if (!channelId) return false;
		const channelIdHex = channelId.toString('hex');
		const mutations: RecoveryMutation[] = [
			{
				type: 'channel_state',
				channelId: channelIdHex,
				state: channel.getFullState(),
				peerPubkey
			}
		];
		if (keyIndex != null) {
			mutations.push({
				type: 'channel_key_index',
				channelId: channelIdHex,
				channelIndex: keyIndex
			});
		}
		const result = this.recovery.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations,
			outboundMessages: [],
			reportedByCaller: true
		});
		if (!result.committed) {
			this.emit('node:error', {
				code: 'PERSISTENCE_ERROR',
				channelId,
				message: `Failed to persist recovered channel: ${result.error?.message}`,
				timestamp: Date.now()
			} as ILightningError);
		}
		return result.committed;
	}

	/**
	 * persistChannel, with the outcome reported back to the caller.
	 *
	 * For the transitions a caller must not act on until they are on disk. The
	 * funding forget clock is one: an unrecorded start is a countdown that
	 * begins again at every restart, so the caller rolls it back rather than
	 * counting down from a height nothing can read back.
	 *
	 * A node configured without storage answers true. Nothing it holds
	 * survives a restart in any case, so refusing the transition would deny it
	 * a behavior it can never earn, rather than protecting anything. Every
	 * other path that does not reach the commit — an unresolvable channel, a
	 * rolled-back transaction — answers false.
	 */
	private persistChannelCommitted(channelId: Buffer): boolean {
		if (!this.storage || !this.recovery) return true;
		const request: IChannelPersistRequest = {
			outbound: [],
			// Answered by the commit itself. Anything that returns before it
			// leaves this false, which is the fail-closed direction.
			committed: false,
			outboxIds: []
		};
		this.persistChannel(channelId, request);
		return request.committed;
	}

	/**
	 * The id-addressed entry point, for the node's own call sites: they hold a
	 * channel id and the channel is in the manager under it.
	 *
	 * The dispatch path does NOT come through here. It hands over the channel
	 * it already resolved, because during a v2 open the id a channel answers
	 * to and the id it will be keyed by are briefly different things.
	 */
	private persistChannel(
		channelId: Buffer,
		request?: IChannelPersistRequest
	): void {
		if (!this.storage || !this.recovery) return;
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;
		const peer = this.channelManager.getPeerForChannel(channelId);
		if (!peer) return;
		this.persistChannelState(channel, peer, channelId, request);
	}

	private persistChannelState(
		channel: Channel,
		peer: string,
		channelId: Buffer,
		request?: IChannelPersistRequest
	): void {
		if (!this.storage || !this.recovery) return;
		const channelIdHex = channelId.toString('hex');
		const keyIndex = channel.channelKeyIndex;
		// Channel state persisted without its key index restores a channel that
		// signs its force-close with the wrong key, and the row looks complete
		// so nothing flags it. Persisted without the monitor delta this same
		// action produced, the two disagree about what has been revoked.
		const mutations: RecoveryMutation[] = [
			{
				type: 'channel_state',
				channelId: channelIdHex,
				state: channel.getFullState(),
				peerPubkey: peer
			}
		];
		if (keyIndex != null) {
			mutations.push({
				type: 'channel_key_index',
				channelId: channelIdHex,
				channelIndex: keyIndex
			});
		}
		const monitorMutation = this.takeDirtyMonitorMutation(channelIdHex);
		if (monitorMutation) mutations.push(monitorMutation);
		// A peer-proven outbox supersede (its revoke_and_ack acknowledged the
		// rows) deletes IN this same transaction: on rollback the rows survive
		// alongside the pre-revoke state that still needs them.
		if (request?.supersede) {
			mutations.push({
				type: 'outbox_supersede',
				channelId: channelIdHex,
				messageTypes: request.supersede.messageTypes
			});
		}
		// Whatever the caller staged for this transition (preimage before a
		// fulfill, linkage before a forward) commits with it or not at all.
		const staged = this.takeStagedMutations();
		mutations.push(...staged);

		const result = this.recovery.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations,
			outboundMessages: request?.outbound ?? [],
			reportedByCaller: true
		});

		if (request) {
			request.committed = result.committed;
			request.outboxIds = result.released.map((r) => r.id);
			// The frame this transition landed in, which is what a Phase 6
			// quorum barrier waits on before the batch's messages may go out.
			request.frameSequence = result.frameSequence;
		}
		if (!result.committed) {
			// Everything rolled back together: re-arm the monitor delta and put
			// the staged mutations back rather than dropping writes the caller
			// believes it made. Staged mutations are retried immediately by the
			// enclosing withStagedMutations flush (standalone durability now if
			// storage recovered) and stay staged for the next transition if
			// that fails too.
			//
			// The monitor delta is re-armed, NOT flushed on its own: writing it
			// by itself now would put the revocation on disk while the channel
			// state that produced it stayed behind, which is precisely the
			// channel/monitor disagreement this whole path exists to prevent.
			// It retries as a COMBINED channel+monitor commit on the next
			// monitor update (see persistMonitorAlone) or channel transition.
			if (monitorMutation) {
				this.dirtyMonitors.add(channelIdHex);
				this.monitorsAwaitingChannel.add(channelIdHex);
			}
			if (staged.length) this.stagedMutations.unshift(...staged);
			// A failed persist of a TERMINAL state has no later transition to
			// ride; arm the per-block retry so the close (and its closeReason)
			// still reaches disk once storage recovers.
			const failedState = channel.getFullState().state;
			if (
				failedState === ChannelState.CLOSED ||
				failedState === ChannelState.FORCE_CLOSED ||
				failedState === ChannelState.ERRORED
			) {
				this._failedTerminalPersists.add(channelIdHex);
			}
			this.emit('node:error', {
				code: 'PERSISTENCE_ERROR',
				channelId,
				message: `Failed to persist channel: ${result.error?.message}`,
				timestamp: Date.now()
			} as ILightningError);
		} else {
			this._failedTerminalPersists.delete(channelIdHex);
		}
	}

	/**
	 * Retry channel persists whose terminal state never reached disk (run
	 * once per block). Success removes the entry inside persistChannelState;
	 * another failure re-arms it there too.
	 */
	private retryFailedTerminalPersists(): void {
		if (this._failedTerminalPersists.size === 0) return;
		for (const idHex of [...this._failedTerminalPersists]) {
			const channelId = Buffer.from(idHex, 'hex');
			if (!this.channelManager.getChannel(channelId)) {
				this._failedTerminalPersists.delete(idHex);
				continue;
			}
			this.persistChannel(channelId);
		}
	}

	/**
	 * Hand a restored channel the exact wire bytes of the un-acked commitment
	 * batch it sent before the restart, from the recovery outbox
	 * (docs/RECOVERY-PROTOCOL.md 5.2).
	 *
	 * This is the case the in-memory cache cannot cover: after a restart the
	 * reestablish fallback can only rebuild the batch by re-signing, which it
	 * refuses to do for a taproot channel, since a fresh MuSig2 secret nonce
	 * must never sign material the peer may already hold under the old one.
	 * Replaying stored bytes signs nothing.
	 *
	 * Only the LAST start_batch group is restored: earlier ones are, by
	 * definition, superseded by it.
	 */
	private restoreOutboxRetransmission(
		channelIdHex: string,
		channel: Channel
	): void {
		if (!this.recovery) return;
		const rows = this.recovery.getOutbox(channelIdHex);
		if (rows.length === 0) return;

		let startBatch: Buffer | null = null;
		let commitments: Buffer[] = [];
		for (const row of rows) {
			if (row.messageType === MessageType.START_BATCH) {
				// A later batch supersedes anything collected so far.
				startBatch = row.wireMessage;
				commitments = [];
				continue;
			}
			if (startBatch && row.messageType === MessageType.COMMITMENT_SIGNED) {
				commitments.push(row.wireMessage);
			}
		}
		if (startBatch && commitments.length > 0) {
			channel.restoreLastSentBatch(startBatch, commitments);
			this.emitStructuredLog('channel', 'outbox_retransmission_restored', {
				channelId: channelIdHex,
				commitments: commitments.length
			});
		}
	}

	/**
	 * Run `fn` with `mutations` staged, so the next channel transition it
	 * triggers commits them in the SAME storage transaction as the channel
	 * state and the wire message it authorizes.
	 *
	 * This is what removes the caller-discipline hazard the Recovery Protocol
	 * calls out (5.1): a preimage saved just before fulfillHtlc, or a forward
	 * linkage saved just before addHtlc, used to be a separate write that a
	 * crash could land without the other half. Anything still staged when `fn`
	 * returns is committed on its own, so a path that persists nothing else
	 * never silently drops it.
	 *
	 * If `fn` re-enters and persists a DIFFERENT channel first, the staged
	 * mutations ride with that transition instead. Atomicity is unaffected
	 * (they still commit all-or-nothing with a channel advance); only the
	 * grouping is less tight than the ideal.
	 */
	private withStagedMutations(
		mutations: RecoveryMutation[],
		fn: () => void
	): void {
		if (!this.recovery) {
			fn();
			return;
		}
		this.stagedMutations.push(...mutations);
		try {
			fn();
		} finally {
			this.flushStagedMutations();
		}
	}

	/** Take everything staged, leaving the stage empty. */
	private takeStagedMutations(): RecoveryMutation[] {
		if (this.stagedMutations.length === 0) return [];
		return this.stagedMutations.splice(0, this.stagedMutations.length);
	}

	/** Commit any mutations no channel transition picked up. */
	private flushStagedMutations(): void {
		const mutations = this.takeStagedMutations();
		if (mutations.length === 0 || !this.recovery) return;
		const result = this.recovery.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations,
			outboundMessages: []
		});
		if (!result.committed) {
			// Keep them staged so the next transition (or the next flush)
			// retries, rather than silently dropping writes the caller believes
			// it made. The failure itself is surfaced by the manager's onError
			// hook; what must not happen is a preimage for value already paid
			// downstream evaporating because one standalone commit failed.
			this.stagedMutations.unshift(...mutations);
		}
	}

	/**
	 * Pull a channel's pending chain monitor state so it can ride in that
	 * channel's transition, clearing the dirty mark. Returns null when the
	 * monitor has no undelivered change.
	 */
	private takeDirtyMonitorMutation(
		channelIdHex: string
	): RecoveryMutation | null {
		if (!this.dirtyMonitors.has(channelIdHex)) return null;
		const monitor = this.channelManager.getMonitor(
			Buffer.from(channelIdHex, 'hex')
		);
		this.dirtyMonitors.delete(channelIdHex);
		this.monitorsAwaitingChannel.delete(channelIdHex);
		if (!monitor) return null;
		return {
			type: 'chain_monitor',
			channelId: channelIdHex,
			state: monitor.getFullState()
		};
	}

	/**
	 * Persist a chain monitor on its own, for updates with no causally linked
	 * channel action (block arrival, funding spend detection).
	 */
	private persistMonitorAlone(channelIdHex: string): void {
		if (!this.recovery) return;
		// Held back by a failed channel transition: retry as a COMBINED
		// channel+monitor commit instead of refusing outright. On a closing
		// channel this monitor update (the next block) may be the only event
		// that ever fires again, so refusing here would park every sweep and
		// justice delta in memory until a channel message that never comes;
		// the combined commit keeps the no-monitor-ahead-of-channel invariant
		// AND gives the failed persist its retry.
		if (this.monitorsAwaitingChannel.has(channelIdHex)) {
			const channelId = Buffer.from(channelIdHex, 'hex');
			if (
				this.channelManager.getChannel(channelId) &&
				this.channelManager.getPeerForChannel(channelId)
			) {
				// persistChannelState re-arms the monitor delta itself when that
				// combined commit rolls back, so this branch needs no retry of
				// its own.
				this.persistChannel(channelId);
				return;
			}
			// The channel is gone from the manager, so there is no channel
			// state left to pair with; release the hold and let the monitor
			// commit on its own below.
			this.monitorsAwaitingChannel.delete(channelIdHex);
		}
		const mutation = this.takeDirtyMonitorMutation(channelIdHex);
		if (!mutation) return;
		const result = this.recovery.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [mutation],
			outboundMessages: []
		});
		if (!result.committed) {
			// The state never reached storage, and takeDirtyMonitorMutation already
			// cleared the flag. Mark it dirty again so the next block, fee sample or
			// channel transition writes this monitor instead of dropping the delta.
			this.dirtyMonitors.add(channelIdHex);
		}
	}

	/**
	 * Commit a set of mutations as one recovery transition, reporting failure
	 * as a node:error. This is how every write to a journaled table outside a
	 * channel transition (payment metadata, invoices, forwarding events,
	 * standalone preimages) reaches storage: through RecoveryManager.commit,
	 * so the Recovery Protocol journal records it (spec 5.1/5.3, Important
	 * and SafetyCritical writes are journaled; only Reconstructable state
	 * like gossip may bypass).
	 */
	private commitMutations(
		label: string,
		mutations: RecoveryMutation[],
		criticality: RecoveryCriticality = RecoveryCriticality.Important
	): boolean {
		if (!this.recovery || mutations.length === 0) return true;
		const result = this.recovery.commit({
			criticality,
			mutations,
			outboundMessages: [],
			reportedByCaller: true
		});
		if (!result.committed) {
			this.emit('node:error', {
				code: 'PERSISTENCE_ERROR',
				message: `${label}: ${result.error?.message}`,
				timestamp: Date.now()
			} as ILightningError);
		}
		return result.committed;
	}

	/** The payment-state mutation for a tracked payment, or null. */
	private paymentMutation(paymentHash: Buffer): RecoveryMutation | null {
		const hashHex = paymentHash.toString('hex');
		const payment = this.payments.get(hashHex);
		if (!payment) return null;
		return { type: 'payment_state', paymentHash: hashHex, payment };
	}

	private persistPayment(paymentHash: Buffer): void {
		if (!this.storage) return;
		const mutation = this.paymentMutation(paymentHash);
		if (!mutation) return;
		this.commitMutations('Failed to persist payment', [mutation]);
	}

	/**
	 * Persist an invoice's full record set (preimage, payment secret, invoice
	 * row, payment record) in ONE transaction: all four land or none do. A
	 * partial set is a half-claimable payment hash that restore never flags
	 * (invoices and payments are restored independently, so a missing payment
	 * row breaks receive accounting while the hash stays fulfillable).
	 */
	private persistInvoiceRecords(
		paymentHash: Buffer,
		invoiceInfo: IInvoiceInfo,
		preimage?: Buffer,
		paymentSecret?: Buffer,
		bolt12PathId?: Buffer
	): void {
		if (!this.storage) return;
		const hashHex = paymentHash.toString('hex');
		const mutations: RecoveryMutation[] = [];
		if (preimage) {
			mutations.push({
				type: 'payment_preimage',
				paymentHash: hashHex,
				preimage
			});
		}
		if (paymentSecret) {
			mutations.push({
				type: 'payment_secret',
				paymentHash: hashHex,
				secret: paymentSecret
			});
		}
		// Same transition as the preimage: a BOLT 12 invoice must never
		// persist as claimable without its authentication path_id.
		if (bolt12PathId) {
			mutations.push({
				type: 'invoice_path_id',
				paymentHash: hashHex,
				pathId: bolt12PathId
			});
		}
		mutations.push({
			type: 'invoice_state',
			paymentHash: hashHex,
			invoice: invoiceInfo
		});
		const payment = this.paymentMutation(paymentHash);
		if (!payment) {
			// Fail closed, as the pre-journal transaction did by throwing: a
			// missing payment record must abort the WHOLE set, or the hash
			// persists half-claimable with receive accounting broken.
			this.emit('node:error', {
				code: 'PERSISTENCE_ERROR',
				message: `persistInvoiceRecords: payment record missing: ${hashHex}`,
				timestamp: Date.now()
			} as ILightningError);
			return;
		}
		mutations.push(payment);
		// SafetyCritical: the set carries a claimable preimage.
		this.commitMutations(
			'persistInvoiceRecords',
			mutations,
			RecoveryCriticality.SafetyCritical
		);
	}

	/**
	 * Wrap a storage operation in try/catch, emitting node:error on failure.
	 * Prevents disk-full or locked-DB from crashing a long-running node.
	 */
	/**
	 * Run a storage operation, reporting (not throwing) a failure. Returns
	 * whether the operation succeeded; with no storage configured nothing
	 * durable can fail, so that counts as success.
	 */
	private safeStorage(fn: () => void, operation: string): boolean {
		if (!this.storage) return true;
		try {
			fn();
			return true;
		} catch (err) {
			this.emit('node:error', {
				code: 'PERSISTENCE_ERROR',
				message: `${operation}: ${(err as Error).message}`,
				timestamp: Date.now()
			} as ILightningError);
			return false;
		}
	}

	// ─────────────── Setup ───────────────

	private wireChannelManagerEvents(): void {
		this.channelManager.on(
			'watchtower:backup',
			(
				channelId: Buffer,
				_peerPubkey: string,
				perCommitmentSecret: Buffer,
				revokedTx: Buffer
			) => {
				this.backupRevokedStateToTowers(
					channelId,
					perCommitmentSecret,
					revokedTx
				);
			}
		);
		// The real SCID only exists once the funding reaches announcement depth,
		// which is long after channel:ready. Register it the moment it is assigned
		// so we can forward HTLCs addressed by the SCID we publish to the graph.
		this.channelManager.on(
			'channel:scid-assigned',
			(channelId: Buffer, scid: Buffer) => {
				const channel = this.channelManager.getChannel(channelId);
				if (!channel || !this.shouldAcceptRealScid(channel.getFullState())) {
					return;
				}
				this.registerChannelScid(channelId, scid);
			}
		);
		// A channel restored from persistence has finished reestablishing:
		// rebuild the node-level handling its previous process took with it.
		// Its own event, fired once per restored channel, because this repair
		// must never run for a channel that stayed live (see
		// redispatchUnresolvedReceivedHtlcs).
		this.channelManager.on('channel:restore-ready', (channelId: Buffer) => {
			this.redispatchUnresolvedReceivedHtlcs(channelId);
		});
		// A restored v2 open that could never be broadcast is disposed of in
		// memory by ChannelManager.restoreChannel; this is what makes that
		// durable (issue #387). Without it the unsafe row stays on disk in
		// AWAITING_TX_SIGNATURES and comes back on every restart, and since an
		// ERRORED channel is never reconnected nothing else would clear it. A
		// condemned open persists as ERRORED rather than being deleted: the row
		// is inert either way, and keeping it leaves the force-close material
		// and the operator's view of what happened. A failed write is not fatal
		// here, unlike the RBF-residue removal above, because the disposal is
		// recomputed from the same row on the next boot; persistChannelState
		// also arms its own per-block retry for a failed terminal state.
		this.channelManager.on(
			'channel:v2-open-disposed',
			(channelId: Buffer, disposition: 'rolled-back' | 'refused') => {
				this.persistChannel(channelId);
				this.emitStructuredLog('channel', 'v2_open_disposed_on_restore', {
					channelId: channelId.toString('hex'),
					disposition
				});
			}
		);
		// A forward whose downstream leg settled while this inbound channel
		// could not carry the fulfill (killed process, or a live disconnect
		// at the moment the fulfill arrived) is owed its settle the moment
		// the channel can carry updates again. The pass gates on durable
		// facts only, which is what makes it safe on this every-reconnect
		// event where the restore repair above is not.
		this.channelManager.on('channel:reestablished', (channelId: Buffer) => {
			this.settleForwardsOwedUpstream(channelId);
			// A disconnect-during-quiescence left parked dispatches waiting for
			// the channel to carry updates again; it can now.
			this.drainParkedQuiescentHtlcs(channelId.toString('hex'));
		});
		this.channelManager.on('channel:ready', (channelId: Buffer) => {
			this.registerChannelScids(channelId);
			this.persistChannel(channelId);
			// Clear reestablish stuck tracker when channel reaches NORMAL
			this._stuckChannelTracker.delete(
				`reestablish:${channelId.toString('hex')}`
			);
			this.emit('channel:ready', { channelId });
			this.emitStructuredLog('channel', 'ready', {
				channelId: channelId.toString('hex')
			});

			// A live channel means the node is operationally usable. Signal ready
			// now rather than waiting for autoReconnectPeers() to finish every
			// stored peer — otherwise a single offline/slow peer (whose reconnect
			// only fails after its full connect timeout) holds node:ready hostage
			// and waitForReady() spuriously times out. Idempotent via _readyEmitted.
			this.emitReady();

			// After reestablish, check if we still need to send announcement_signatures.
			// This handles the case where LND sent its sigs before, but beignet never
			// sent back (e.g. ChainWatcher didn't fire announcement:depth).
			this.triggerPendingAnnouncementSigning(channelId);
		});

		this.channelManager.on(
			'channel:opening',
			(channelId: Buffer, fundingTxid: Buffer) => {
				this.emit('channel:opening', { channelId, fundingTxid });
				this.emitStructuredLog('channel', 'opening', {
					channelId: channelId.toString('hex'),
					fundingTxid: fundingTxid.toString('hex')
				});
			}
		);

		// A caller-driven v2 open owes its tx_signatures and only the embedder
		// holds the witnesses (issue 307): relay the reminder so it can answer
		// with sendTxSignatures. externalInputIndices names the subset whose
		// witnesses a third party owes (issue #572): those slots are answered
		// out of band via provideV2ExternalWitness, not sendTxSignatures.
		this.channelManager.on(
			'channel:txsigs-needed',
			(
				channelId: Buffer,
				fundingTxid: Buffer,
				fundingOutputIndex: number,
				inputIndices: number[],
				externalInputIndices?: number[]
			) => {
				this.emit('channel:txsigs-needed', {
					channelId,
					fundingTxid,
					fundingOutputIndex,
					inputIndices,
					externalInputIndices
				});
				this.emitStructuredLog('channel', 'txsigs_needed', {
					channelId: channelId.toString('hex'),
					fundingTxid: fundingTxid.toString('hex'),
					fundingOutputIndex,
					inputIndices,
					externalInputIndices
				});
			}
		);

		this.channelManager.on(
			'channel:pending-close',
			(channelId: Buffer, initiator: 'local' | 'remote') => {
				this.emit('channel:pending-close', { channelId, initiator });
				this.emitStructuredLog('channel', 'pending_close', {
					channelId: channelId.toString('hex'),
					initiator
				});
			}
		);

		this.channelManager.on(
			'channel:force-closing',
			(channelId: Buffer, initiator: 'local' | 'remote') => {
				this.emit('channel:force-closing', { channelId, initiator });
				this.emitStructuredLog('channel', 'force_closing', {
					channelId: channelId.toString('hex'),
					initiator
				});
			}
		);

		this.channelManager.on('channel:closed', (channelId: Buffer) => {
			this.persistChannel(channelId);
			// A cooperative close records its signed tx just before the manager
			// emits broadcast:tx; register the txid so the watcher's
			// broadcast:success resolves into closeStatus.broadcast.
			const closeHex = this.channelManager.getChannel(channelId)?.getFullState()
				.lastCooperativeCloseTxHex;
			if (closeHex) {
				try {
					this._registerCloseTxid(
						channelId.toString('hex'),
						bitcoin.Transaction.fromHex(closeHex).getId()
					);
				} catch {
					// Unparseable hex: broadcast simply stays unreported.
				}
			}
			// NOTE: the funding watch is deliberately NOT torn down here. 'closed'
			// fires the moment a commitment spend is classified — possibly from a
			// mempool sighting — and the spend can still be replaced (reorg, or a
			// conflicting revoked commitment winning the race). The monitor's
			// commitment-swap handling needs the watch alive to see the
			// replacement; the watcher retires spends itself after
			// SPEND_FINALITY_DEPTH, and 'channel:resolved' cleans up below.
			this.emit('channel:closed', { channelId });
			this.emitStructuredLog('channel', 'closed', {
				channelId: channelId.toString('hex')
			});
		});

		// All tracked outputs of a close irrevocably swept/claimed — transition the
		// channel out of FORCE_CLOSED/closing so it stops counting toward the
		// pending-close balance, and persist the CLOSED state.
		this.channelManager.on('channel:resolved', (channelId: Buffer) => {
			const transitioned = this.channelManager.markChannelResolved(channelId);
			if (transitioned) {
				this.persistChannel(channelId);
			}
			// Retained wire bytes exist for one purpose, retransmission on a
			// channel that can still exchange messages. A fully resolved close
			// can never reestablish, so the rows are dead weight: signed
			// commitment material sitting encrypted in the database with no
			// consumer, kept for the lifetime of the node.
			this.recovery?.clearChannelOutbox(channelId.toString('hex'));
			// A terminal channel also retires its monitor bookkeeping: a
			// lingering awaiting-channel hold would otherwise block standalone
			// monitor commits for this id forever.
			this.dirtyMonitors.delete(channelId.toString('hex'));
			this.monitorsAwaitingChannel.delete(channelId.toString('hex'));
			// Close-broadcast bookkeeping is only meaningful while the close can
			// still be rebroadcast; a resolved close retires it.
			const resolvedIdHex = channelId.toString('hex');
			this._recoveryCloseRequested.delete(resolvedIdHex);
			this._lastCloseBroadcast.delete(resolvedIdHex);
			for (const [txid, idHex] of this._pendingCloseTxids) {
				if (idHex === resolvedIdHex) this._pendingCloseTxids.delete(txid);
			}
			// Every output of the close is irrevocably resolved — a commitment
			// swap is no longer possible, so the funding watch can be retired
			// (memory cleanup for long-lived nodes).
			if (this.chainWatcher) {
				this.chainWatcher.removeWatchedFunding(channelId);
			}
			this.emit('channel:resolved', { channelId });
			this.emitStructuredLog('channel', 'resolved', {
				channelId: channelId.toString('hex')
			});
		});

		// A splice finished: the channel now lives on a NEW funding outpoint and
		// must be re-announced with its new SCID. The new funding's announcement
		// trigger may have burnt its one-shot while the channel was still
		// SPLICING (unable to sign) — re-arm it so announcement:depth fires
		// (immediately if already 6 deep, else on the next block). Without this,
		// the channel is only ever re-announced if the PEER re-sends
		// announcement_signatures first.
		this.channelManager.on('splice:complete', (channelId: Buffer) => {
			this.persistChannel(channelId);
			// The splice negotiation is over: its splice/splice_ack rows can
			// never be retransmitted again (reestablish resumes a splice from
			// channel state, never from these bytes), and nothing else retires
			// them, so a long-lived channel would accrue one pair per splice.
			this.recovery?.supersedeChannelOutbox(channelId.toString('hex'), [
				MessageType.SPLICE,
				MessageType.SPLICE_ACK
			]);
			this.emitStructuredLog('channel', 'splice_complete', {
				channelId: channelId.toString('hex')
			});
			const channel = this.channelManager.getChannel(channelId);
			const fundingTxid = channel?.getFullState().fundingTxid;
			if (this.chainWatcher && fundingTxid) {
				const displayTxid = Buffer.from(fundingTxid).reverse().toString('hex');
				this.chainWatcher.rearmAnnouncementTracking(channelId, displayTxid);
			}
			// Re-emit outward so the embedder can refresh a static channel backup
			// NOW, while fundingTxid holds the NEW (post-splice) outpoint. A backup
			// refreshed at splice initiation still encodes the OLD, already-spent
			// outpoint, so an SCB restore would watch an outpoint the splice consumed
			// and miss the peer's force-close on the new one (FS-7).
			this.emit('splice:complete', { channelId, fundingTxid });
			// A settle owed upstream that was still refused at quiescence:ended
			// (a taproot channel parks updates until splice_locked) is carried
			// now that the channel is NORMAL again. Deferred: this event fires
			// from inside a processActions dispatch.
			setImmediate(() => {
				this.settleForwardsOwedUpstream(channelId);
			});
		});

		// A splice negotiation was unwound by tx_abort (the peer's initiating
		// abort, or the echo answering ours) and the channel is back in
		// NORMAL. Relayed so a caller waiting on the splice (spliceInAndWait,
		// the JIT engine) settles now instead of burning its timeout (issue
		// #572).
		this.channelManager.on(
			'splice:aborted',
			(channelId: Buffer, reason: string) => {
				this.emitStructuredLog('channel', 'splice_aborted', {
					channelId: channelId.toString('hex'),
					reason
				});
				this.emit('splice:aborted', { channelId, reason });
			}
		);

		// A channel was failed by a BOLT 1 error (received or sent). Drive the
		// prescription to its conclusion: fail the channel ON CHAIN, rather than
		// leaving ERRORED in limbo waiting for a peer broadcast that may never
		// come.
		this.channelManager.on(
			'channel:errored',
			(channelId: Buffer, reason: string) => {
				this.handleChannelErrored(channelId, reason);
			}
		);

		// A negotiated-but-unfunded open was torn down (funding failed after
		// accept_channel). Nothing on-chain exists, so unlike channel:errored
		// there is nothing to fail on-chain — just surface it to listeners.
		this.channelManager.on(
			'channel:aborted',
			(temporaryChannelId: Buffer, reason: string) => {
				this.emit('channel:aborted', temporaryChannelId, reason);
				this.emitStructuredLog('channel', 'open_aborted', {
					temporaryChannelId: temporaryChannelId.toString('hex'),
					reason
				});
			}
		);

		// Persist-before-send: channel state, its key index, any monitor delta
		// this same action produced, and the wire bytes it authorizes all commit
		// in one transaction; the sends are released only if it commits.
		this.channelManager.on('channel:persist', (event: IChannelPersistEvent) => {
			// The synchronous dispatch nests: an action earlier in this batch
			// can have triggered a whole cascade that REMOVED this channel
			// and deleted its row (a terminal abort handshake completing
			// inside a send). Persisting now would resurrect a row nobody
			// tracks. Report success so the batch finishes; any remaining
			// sends address a negotiation the peer has already left, and its
			// manager drops them against the missing channel.
			if (
				event.channelId &&
				!this.channelManager.getChannel(event.channelId) &&
				!(
					this.channelManager as unknown as {
						findChannelByChannelIdInTemp(id: Buffer): unknown;
					}
				).findChannelByChannelIdInTemp(event.channelId)
			) {
				return;
			}
			// A node that HAS persistence answers for itself. The request
			// arrives committed:true, which is the right default only for a
			// node that persists nothing at all; leaving it true here would
			// let a listener that returned early, or an id that resolved to
			// nothing, read as a successful commit and release the batch's
			// sends. Only reaching recovery.commit may say committed.
			if (event.request && this.storage && this.recovery) {
				event.request.committed = false;
			}
			this.persistChannelState(
				event.channel,
				event.peerPubkey,
				event.channelId,
				event.request
			);
		});

		// The manager abandoned an unfunded open outright (a v2 RBF
		// renegotiation dropped on disconnect): its row must go with it, or
		// the next restart restores a channel the manager already removed.
		this.channelManager.on(
			'channel:abandoned',
			(channelId: Buffer, reason: string) => {
				const idHex = channelId.toString('hex');
				// The manager judged the attempt from MEMORY; the disk answers
				// for what was actually committed. A FAILED RBF persist leaves
				// the PREVIOUS attempt as the durable truth, with tx_ack_rbf
				// withheld behind the same failed commit, so the peer never
				// adopted the renegotiation and the prior attempt is still
				// resumable: re-restore it instead of deleting it. Every read
				// is contained: this path already runs under a possibly
				// failing store, and a thrown read must not escape the
				// disconnect handling after the manager removed the channel.
				let row: { state: IChannelState; peerPubkey: string } | null = null;
				let rowKnown = true;
				try {
					row = this.storage?.loadChannel?.(idHex) ?? null;
				} catch {
					rowKnown = false;
				}
				if (!rowKnown) {
					// The disk cannot answer: fail closed by touching nothing
					// durable. A restart re-evaluates the row under the same
					// rules with a healthy store.
					this.emitStructuredLog('channel', 'open_abandon_unresolved', {
						channelId: idHex,
						reason
					});
					return;
				}
				if (
					row &&
					(row.state.state === ChannelState.AWAITING_TX_SIGNATURES ||
						row.state.state === ChannelState.DUAL_FUNDING_V2) &&
					row.state.v2InFlight
				) {
					try {
						// A DUAL_FUNDING_V2 row with a record is the
						// receiver's provisionally accepted RBF whose
						// commit-point persist failed: the retained record
						// is the previous attempt. Roll it back exactly as a
						// restart would, into the state that attempt is
						// actually waiting in. A row already durable in
						// AWAITING_TX_SIGNATURES is not a rollback and keeps
						// the state it was persisted with.
						if (row.state.state === ChannelState.DUAL_FUNDING_V2) {
							row.state.state = this.v2RetainedAttemptState(
								row.state.v2InFlight
							);
						}
						const channel = new Channel(row.state);
						const keyIndex = this.storage!.loadChannelKeyIndex(idHex);
						this.channelManager.restoreChannel(
							channel,
							row.peerPubkey,
							keyIndex
						);
						this.emitStructuredLog(
							'channel',
							'open_abandon_reverted_to_durable',
							{ channelId: idHex, reason }
						);
					} catch {
						// Restoration failed mid-way: the row is untouched, so
						// a restart restores it; nothing terminal is emitted.
						this.emitStructuredLog('channel', 'open_abandon_unresolved', {
							channelId: idHex,
							reason
						});
					}
					return;
				}
				const deleted = row
					? this.deleteChannelDurably(idHex)
					: this.safeStorage(
							() => this.storage!.deleteChannel(idHex),
							'deleteChannel'
					  );
				if (!deleted) {
					// The row survived: the abandonment is not terminal yet.
					// Condemning the row itself makes the deletion owed at
					// the next start (the intent rides the row, so no
					// separate read can lose it); the terminal event fires
					// only when the deletion lands.
					if (!this.condemnChannelRow(idHex)) {
						// Neither the deletion nor the durable intent
						// landed: with no marker, a healthy restart would
						// silently restore the row as a live channel. Keep
						// it TRACKED instead, exactly like the recoverable
						// failed-persist arm, so this removal re-runs
						// against a store that answers.
						try {
							const channel = new Channel(row!.state);
							const keyIndex = this.storage!.loadChannelKeyIndex(idHex);
							this.channelManager.restoreChannel(
								channel,
								row!.peerPubkey,
								keyIndex
							);
							this.emitStructuredLog('channel', 'open_abandon_unresolved', {
								channelId: idHex,
								reason
							});
						} catch {
							this.emitStructuredLog('channel', 'open_abandon_unresolved', {
								channelId: idHex,
								reason
							});
						}
						return;
					}
					this.emitStructuredLog('channel', 'open_abandon_deferred', {
						channelId: idHex,
						reason
					});
					return;
				}
				this.emitStructuredLog('channel', 'open_abandoned', {
					channelId: idHex,
					reason
				});
				// The documented terminal lifecycle event for a removed
				// unfunded channel, same as voidMissingFundingChannel.
				this.emit('channel:voided', { channelId });
			}
		);

		// A processActions batch is open: monitor changes it causes belong in
		// that channel's transition rather than in a second, separate write.
		this.channelManager.on(
			'transition:begin',
			(channelIdHex: string | null) => {
				this.openTransitions.push(channelIdHex ?? '');
			}
		);
		this.channelManager.on('transition:end', (channelIdHex: string | null) => {
			this.openTransitions.pop();
			// The batch produced a monitor change but no PERSIST_STATE to carry
			// it. Flush it now, still inside the same synchronous turn, so
			// nothing is deferred past the actions that caused it. NOT while an
			// ENCLOSING transition for the same channel is still open (nested
			// batches re-enter): its persist has not run yet, and flushing here
			// would commit the monitor ahead of the channel state it belongs to.
			if (
				channelIdHex &&
				this.dirtyMonitors.has(channelIdHex) &&
				!this.openTransitions.includes(channelIdHex)
			) {
				this.persistMonitorAlone(channelIdHex);
			}
		});

		// Outbox rows reached the socket; record it for reestablish accounting.
		this.channelManager.on('outbox:sent', (ids: Array<number | null>) => {
			this.recovery?.markSent(ids);
		});

		// A failed persist withheld a batch's sends. Nothing re-queues them on
		// this connection; the reestablish exchange after a reconnect is what
		// retries the persist and replays them from durable state. Force that
		// reconnect rather than deadlocking a live connection on the PEER's
		// commitment timeout: the peer may wait indefinitely for a revoke or
		// commitment we withheld, riding every in-flight HTLC to its CLTV.
		this.channelManager.on(
			'transition:blocked',
			(peerPubkey: string, channelId: Buffer | null) => {
				this.emitStructuredLog('channel', 'transition_blocked', {
					peerPubkey,
					channelId: channelId?.toString('hex')
				});
				// Deferred: the blocked batch may still be unwinding through
				// nested dispatches; tearing the peer down mid-turn would pull
				// state out from under them.
				setImmediate(() => {
					this.requestPeerDisconnect(peerPubkey);
					// A v2 opening whose blocked persist left memory ahead of
					// disk (e.g. the replacement's commitment failed to
					// commit) resyncs to the durable truth: the attempt on
					// disk is the only one a restart would resume, so it is
					// the only one this side may keep tracking. Runs after the
					// disconnect so the reestablish rollback cannot mutate the
					// attempt this just re-installed.
					this.resyncV2OpenFromDisk(channelId);
				});
			}
		);

		// Quiescence over on a channel: re-drive any incoming-HTLC dispatches
		// parked while it was quiescing (issue 411), and any settle owed
		// upstream that was refused while the channel could not carry updates
		// (an on-chain preimage learned mid-splice; a live splice never emits
		// channel:reestablished, so the reestablish-tail pass cannot cover
		// it). Deferred: the event fires from inside a processActions
		// dispatch, and the re-driven dispositions start a dispatch of their
		// own.
		this.channelManager.on('quiescence:ended', (channelIdHex: string) => {
			setImmediate(() => {
				this.drainParkedQuiescentHtlcs(channelIdHex);
				this.settleForwardsOwedUpstream(Buffer.from(channelIdHex, 'hex'));
			});
		});

		// BOLT 2: "MUST disconnect after 60 seconds of quiescence if the HTLCs
		// are pending". The disconnect resets quiescence via markForReestablish,
		// which also reverses uncommitted adds - the spec's own escape hatch.
		this.channelManager.on(
			'quiescence:timeout',
			(channelIdHex: string, peerPubkey: string) => {
				this.emitStructuredLog('channel', 'quiescence_timeout', {
					peerPubkey,
					channelId: channelIdHex
				});
				setImmediate(() => {
					this.requestPeerDisconnect(peerPubkey);
				});
			}
		);

		// Recovery 5.7 (issue #462): a peer is waiting on a channel this node
		// has no record of, and the reply is parked rather than sent. This is
		// the operator's cue that a Recovery Capsule has to be applied before
		// the window ends, so it is surfaced rather than logged at debug.
		this.channelManager.on(
			'reestablish:held',
			(peerPubkey: string, channelId: Buffer, expiresAt: number) => {
				const channelIdHex = channelId.toString('hex');
				this.emitStructuredLog('channel', 'reestablish_held', {
					peerPubkey,
					channelId: channelIdHex,
					expiresAt
				});
				this.emit(
					'recovery:reestablish-held',
					peerPubkey,
					channelIdHex,
					expiresAt
				);
			}
		);

		// A quorum barrier is holding a batch's messages (Recovery 5.8). Purely
		// informational: the channel is waiting, not broken, and the release
		// happens on its own once the guardians answer.
		this.channelManager.on(
			'transition:held',
			(peerPubkey: string, channelIdHex: string, frame: bigint | null) => {
				this.emitStructuredLog('channel', 'transition_held', {
					peerPubkey,
					channelId: channelIdHex,
					frameSequence: frame == null ? null : frame.toString()
				});
			}
		);

		// The barrier REFUSED. This is not the failed-persist path: the state
		// did commit, so none of that path's rollback bookkeeping applies, and
		// the reason is durability rather than storage. What they share is the
		// remedy, because a peer waiting on a revoke or commitment we will
		// never send on this connection rides every in-flight HTLC to its
		// CLTV. A fenced writer is the exception: hardFreezeTransports has
		// already torn its transports down node wide, on the socket side and
		// the event side both, the moment the fence latched.
		this.channelManager.on(
			'transition:frozen',
			(
				peerPubkey: string,
				channelIdHex: string,
				reason: string,
				dropped: number
			) => {
				this.emitStructuredLog('channel', 'transition_frozen', {
					peerPubkey,
					channelId: channelIdHex,
					reason,
					dropped
				});
				this.emit('node:error', {
					code: 'DURABILITY_BARRIER_TIMEOUT',
					channelId: Buffer.from(channelIdHex, 'hex'),
					message:
						`held messages were refused by the durability barrier (${reason}); ` +
						'the channel resumes through reestablish once the quorum is reachable',
					timestamp: Date.now()
				} as ILightningError);
				if (reason === 'fenced') return;
				setImmediate(() => {
					this.requestPeerDisconnect(peerPubkey);
				});
			}
		);

		// A released batch threw partway through dispatch, so an unknown prefix
		// of its wire bytes is on the socket and its tail never went. There is
		// no safe continuation on this connection: only reestablish after a
		// reconnect replays the channel's stream from durable state. The
		// disconnect is unconditional here, unlike the frozen handler's fenced
		// exemption, because nothing else is tearing this transport down.
		this.channelManager.on(
			'transition:dispatch-failed',
			(
				peerPubkey: string,
				channelIdHex: string,
				reason: string,
				dropped: number
			) => {
				this.emitStructuredLog('channel', 'transition_dispatch_failed', {
					peerPubkey,
					channelId: channelIdHex,
					reason,
					dropped
				});
				this.emit('node:error', {
					code: 'BARRIER_DISPATCH_FAILED',
					channelId: Buffer.from(channelIdHex, 'hex'),
					message:
						`a released batch failed partway through dispatch (${reason}); ` +
						'the connection is dropped so reestablish can replay from durable state',
					timestamp: Date.now()
				} as ILightningError);
				setImmediate(() => {
					this.requestPeerDisconnect(peerPubkey);
				});
			}
		);

		this.channelManager.on(
			'message:outbound',
			(peerPubkey: string, type: number, payload: Buffer) => {
				this.emitOutbound(peerPubkey, type, payload, true);
			}
		);

		this.channelManager.on(
			'htlc:forwarded',
			(
				channelId: Buffer,
				htlcId: bigint,
				amountMsat: bigint,
				paymentHash: Buffer
			) => {
				this.persistChannel(channelId);
				this.handleIncomingHtlc(channelId, htlcId, amountMsat, paymentHash);
			}
		);

		this.channelManager.on(
			'htlc:fulfilled',
			(channelId: Buffer, htlcId: bigint, preimage: Buffer) => {
				this.handleHtlcFulfilled(channelId, htlcId, preimage);
				this.emit('htlc:fulfilled', { channelId, htlcId });
			}
		);

		this.channelManager.on(
			'htlc:failed',
			(channelId: Buffer, htlcId: bigint, reason: Buffer) => {
				this.handleHtlcFailed(channelId, htlcId, reason);
				this.emit('htlc:failed', { channelId, htlcId });
			}
		);

		// An offered HTLC the channel dropped on a held restore rather than
		// replay (issue #469). Nothing on chain resolves it, so whatever is
		// waiting on it has to be told here.
		this.channelManager.on(
			'htlc:local-add-abandoned',
			(channelId: Buffer, adds: IAbandonedLocalAdd[]) => {
				for (const add of adds) this.failAbandonedLocalAdd(channelId, add);
				this.persistChannel(channelId);
			}
		);

		this.channelManager.on(
			'error',
			(channelId: Buffer | null, message: string) => {
				// An open that failed is never funded, so the rate it asked for has
				// nothing left to apply to. Drop it, and the max-funding flag with it,
				// rather than hold them for a channel that no longer exists.
				if (channelId) {
					this.requestedFundingFeeRates.delete(channelId.toString('hex'));
					this.fundingMaxRequests.delete(channelId.toString('hex'));
				}
				const err: ILightningError = {
					code: 'CHANNEL_ERROR',
					channelId: channelId ?? undefined,
					message,
					timestamp: Date.now()
				};
				this.emit('node:error', err);
			}
		);

		// Record every node:error, wherever it was raised. These carry the reason a
		// channel open failed (peer rejection, funding build/broadcast failure,
		// disconnect mid-open). Emitting them alone is not enough: a caller that is
		// not listening loses the reason entirely, and a failed open then looks like
		// a pending channel that silently disappeared. Logging here puts the reason
		// on stdout and in the queryable action log (GET /logs?category=error).
		this.on('node:error', (err: ILightningError) => {
			const channelId = err.channelId?.toString('hex');
			this.logger.error(`${err.code}: ${err.message}`, { channelId });
			this.emitStructuredLog('error', err.code, {
				message: err.message,
				channelId
			});
		});

		// Auto-funding: build funding tx when accept_channel is received. A v2
		// (dual-funded) accept is funded through the interactive tx instead —
		// ChannelManager.autoFundDualFundedOpen — and single-funder v1 funding
		// built here would disagree with the negotiated funding outpoint.
		this.channelManager.on(
			'channel:accepted',
			(channel: Channel, peerPubkey: string) => {
				if (!this.fundingProvider) return;
				if (channel.getFullState().dualFundingSession) return;
				this.handleAutoFunding(channel, peerPubkey);
			}
		);

		// Auto-funding: broadcast funding tx after funding_signed
		// pendingFundingTxs is keyed by funding txid hex
		// The funder's BOLT 2 point of no return, dispatched as an action so a
		// failed persist can withhold it and a quorum barrier can hold it. The
		// broadcast used to ride the watch:funding emit below, which is not an
		// action and therefore sat outside every gate the dispatch path
		// applies.
		this.channelManager.on('funding:authorized', (fundingTxid: Buffer) => {
			const txidHex = fundingTxid.toString('hex');
			const entry = this.pendingFundingTxs.get(txidHex);
			if (entry) entry.phase = 'authorized';
			this.reauthAttempts.delete(txidHex);
			this.broadcastPendingFundingTx(txidHex);
		});

		this.channelManager.on(
			'funding:broadcast-authorized',
			(channelId: Buffer | null) => {
				if (channelId) {
					this.authorizedSpliceBroadcasts.add(channelId.toString('hex'));
				}
			}
		);

		// Arm spend detection on the outpoints a splice has superseded, without
		// touching the channel's own funding watch (issue #479). Reading state
		// here is safe where reading it in registerFundingWatch's splice arm is
		// not: this needs only preSpliceSpendWatches, which completeSplice never
		// touches, so a zero-conf splice_locked in the same batch cannot race it.
		this.channelManager.on('watch:presplice-spend', (channelId: Buffer) => {
			const channel = this.channelManager.getChannel(channelId);
			if (!channel) return;
			void this.armPreSpliceSpendWatches(channelId, channel.getFullState());
		});

		this.channelManager.on('watch:funding', (fundingTxid: Buffer) => {
			const txidHex = fundingTxid.toString('hex');
			// Arming the watch is deliberately NOT gated. It emits no bytes,
			// touches no chain and is idempotent, restoreChainWatches rebuilds
			// it at startup, and on a barrier refusal the right disposition is
			// the outpoint watched and the transaction not created.
			// Register the funding output with the chain watcher NOW, not only
			// on restart: live confirmation detection, announcement depth,
			// breach detection and the funding-missing watchdog (critical for
			// zero-conf channels, whose state machine no longer waits for the
			// chain) all key off this watch. Previously chain watches were only
			// armed by restoreChainWatches at startup, so a live-opened channel
			// had none of this coverage until the node restarted.
			this.registerFundingWatch(fundingTxid).catch((err) => {
				this.emitStructuredLog('chain', 'funding_watch_failed', {
					txid: txidHex,
					error: (err as Error).message
				});
			});
		});

		// Persist chain monitor state on updates. A monitor change produced by a
		// channel action (commitment advance, HTLC resolution) is marked dirty
		// and rides in that channel's transition, so the two can never disagree
		// after a crash; a standalone change (new block, funding spend seen)
		// commits immediately as its own transition, exactly as before.
		this.channelManager.on(
			'monitor:updated',
			(channelIdHex: string, _monitor: ChainMonitor) => {
				this.dirtyMonitors.add(channelIdHex);
				// ANY open transition for this channel claims the delta, not just
				// the innermost: a nested batch for another channel can sit on
				// top of the stack while this channel's own transition is still
				// open below it, and committing the monitor standalone then
				// would put it ahead of the channel state it belongs to.
				if (this.openTransitions.includes(channelIdHex)) return;
				this.persistMonitorAlone(channelIdHex);
			}
		);

		// Channel announcement ready — sign channel_update, add to graph, and broadcast
		this.channelManager.on(
			'announcement:ready',
			(
				channelId: Buffer,
				channelAnnouncement: Buffer,
				channelUpdate: Buffer
			) => {
				// Stamp the channel's EFFECTIVE routing policy (per-channel override
				// or node-wide defaults) into the update, since the Channel-built one
				// carries placeholder fee/CLTV values, then sign it.
				let signedChannelUpdate = this.refreshChannelUpdate(
					channelUpdate,
					Math.floor(Date.now() / 1000),
					channelId
				);
				if (!signedChannelUpdate) {
					// Fall back to signing the original as-is
					signedChannelUpdate = channelUpdate;
					try {
						const sig = signChannelUpdate(channelUpdate, this.nodePrivkey);
						// Write real signature into first 64 bytes of the channel_update payload
						signedChannelUpdate = Buffer.from(channelUpdate);
						sig.copy(signedChannelUpdate, 0);
					} catch {
						// If signing fails, use the original (will likely be rejected by peers)
					}
				}

				// Verify the assembled announcement before it can be advertised: the
				// counterparty's announcement_signatures are never validated on
				// receipt, so zero or garbage signatures would otherwise be cached,
				// broadcast and served as gossip (#340). Byte-identical re-encoding
				// is required so relayed copies keep valid signatures.
				let announcementValid = false;
				try {
					const annMsg = decodeChannelAnnouncementMessage(channelAnnouncement);
					try {
						announcementValid =
							verifyChannelAnnouncement(annMsg, channelAnnouncement) &&
							encodeChannelAnnouncementMessage(annMsg).equals(
								channelAnnouncement
							);
					} catch {
						announcementValid = false;
					}
					// Add to our own network graph. With invalid counterparty
					// signatures the entry stays local-only: routable, never served.
					this.graph.addChannelAnnouncement(annMsg, {
						verified: announcementValid
					});
					const updateMsg = decodeChannelUpdateMessage(signedChannelUpdate);
					let updateValid = false;
					try {
						updateValid =
							verifyChannelUpdate(
								updateMsg,
								signedChannelUpdate,
								annMsg.nodeId1,
								annMsg.nodeId2
							) &&
							encodeChannelUpdateMessage(updateMsg).equals(signedChannelUpdate);
					} catch {
						updateValid = false;
					}
					this.graph.applyChannelUpdate(updateMsg, { verified: updateValid });
				} catch {
					// Ignore decode errors for self-generated announcements
				}

				if (announcementValid) {
					// Build + cache our node_announcement (BOLT 7: required after a
					// channel is announced). Caching lets us re-broadcast it — a
					// one-shot send rarely reaches the whole network, so the node
					// never shows up on explorers.
					const nodeAnnouncementPayload = this.buildNodeAnnouncement(
						Math.floor(Date.now() / 1000)
					);
					if (nodeAnnouncementPayload) {
						this._ownNodeAnnouncement = nodeAnnouncementPayload;
					}

					// Cache this channel's gossip so we can re-broadcast it to new
					// peers and when serving gossip_timestamp_filter requests.
					this._ownChannelGossip.set(channelId.toString('hex'), {
						announcement: channelAnnouncement,
						update: signedChannelUpdate
					});

					// Broadcast to all currently-connected peers now…
					this.broadcastOwnGossip();
					// …and keep it propagating: re-broadcast (with a refreshed
					// node_announcement timestamp) periodically. Idempotent — starts
					// once.
					this.startGossipRefresh();
				}

				this.emit('announcement:ready', channelId);
			}
		);

		// Remote sent announcement_signatures but ChainWatcher hasn't fired yet —
		// sign and send ours immediately so the channel gets announced.
		this.channelManager.on(
			'announcement:needs-signing',
			(channelId: Buffer, scid: Buffer) => {
				void this.signAnnouncementForScid(channelId, scid);
			}
		);

		// A preimage learned ON-CHAIN (downstream force-closed and swept an HTLC via
		// HTLC-success, revealing it). Without a consumer this was dropped, so a
		// forwarding node that already paid downstream could never collect upstream
		// (the inbound HTLC would time out) — a loss of the forwarded amount.
		this.channelManager.on(
			'preimage:learned',
			(paymentHash: Buffer, preimage: Buffer) => {
				this.handleOnChainPreimageLearned(paymentHash, preimage);
			}
		);

		// The TIMEOUT counterpart of preimage:learned: an HTLC output we OFFERED
		// downstream resolved irrevocably on-chain without revealing a preimage,
		// so the outgoing leg of that forward is finally failed. Without a
		// consumer the inbound HTLC was never failed off-chain and
		// scanForwardTimeouts force-closed the healthy inbound channel instead
		// of sending a clean update_fail_htlc.
		this.channelManager.on(
			'output:resolved',
			(
				_txid: string,
				_outputIndex: number,
				channelId?: Buffer,
				outputType?: OutputType,
				paymentHash?: Buffer,
				htlcId?: bigint
			) => {
				if (outputType === undefined) return;
				this.handleOnChainOutputResolved(
					channelId,
					outputType,
					paymentHash,
					htlcId
				);
			}
		);

		// Relay broadcast:tx from ChannelManager (closing txs, force-close
		// commitment txs) to our own consumers.
		//
		// This listener must NOT broadcast. ChainWatcher's constructor already
		// subscribes to the same event and owns the broadcast, along with the
		// non-Buffer guard, the txid dedup and the block-driven retry queue.
		// Broadcasting here too sent every closing tx, sweep and CPFP child to
		// the backend twice: the loser came back "already in mempool", was
		// queued for MAX_BROADCAST_RETRIES blocks and surfaced as a permanent
		// false BROADCAST_FAILED. The genuine failures are wired from the
		// watcher's own broadcast:failure event in wireChainWatcherEvents().
		this.channelManager.on('broadcast:tx', (tx: Buffer) => {
			this.emit('broadcast:tx', tx);
		});

		// A claim declined because it cannot pay its own fee. Surfaced as a log and
		// an event so an operator can see that funds were left on the table, and
		// (at 'contested') that a competing spend path has opened while it stayed
		// unclaimed. Retries continue in both cases.
		this.channelManager.on(
			'sweep:uneconomic',
			(channelId: Buffer, action: ISweepUneconomicChainAction) => {
				this.emitStructuredLog('chain', `sweep_${action.reason}`, {
					channelId: channelId.toString('hex'),
					txid: action.txid,
					outputIndex: action.outputIndex,
					outputType: action.outputType,
					amountSats: action.amount.toString(),
					feeRatePerVbyte: action.feeRatePerVbyte,
					contestHeight: action.contestHeight
				});
				this.emit('sweep:uneconomic', channelId, action);
			}
		);
	}

	/**
	 * Sever a peer at this node's own initiative (durability barriers, the
	 * quiescence watchdog). Chosen PER PEER, not per node: with networking
	 * enabled a peer the PeerManager holds gets its socket dropped, and the
	 * peer:disconnect event applies the protocol side
	 * (handlePeerDisconnected) through wirePeerManagerEvents. A peer the
	 * PeerManager does not hold talks over the event transport
	 * (message:outbound mode, or the unconnected-peer fallback in
	 * emitOutbound), so there is no socket to drop: apply the protocol side
	 * directly, then notify 'peer:disconnect-requested' so the HOST severs
	 * its connection. Without both halves nothing marks the channels
	 * AWAITING_REESTABLISH, the reestablish backstop never sees them, and
	 * recovery degrades to CLTV-expiry scans.
	 */
	private requestPeerDisconnect(peerPubkey: string): void {
		if (this.peerManager?.getPeer(peerPubkey)) {
			try {
				this.peerManager.disconnectPeer(peerPubkey);
			} catch {
				// Already disconnected, or transport-level teardown raced.
			}
			return;
		}
		this.channelManager.handlePeerDisconnected(peerPubkey);
		this.notifyPeerDisconnectRequestObservers(peerPubkey);
	}

	/**
	 * Notify peer:disconnect-requested with each observer FULLY contained,
	 * the external-transport sibling of notifyPeerDisconnectObservers: the
	 * HOST listener that severs the transport may share the event with
	 * application observers, and emit() stops at the first throw, so a
	 * throwing observer ahead of the transport listener would leave the
	 * poisoned connection up.
	 */
	private notifyPeerDisconnectRequestObservers(pubkey: string): void {
		for (const listener of this.rawListeners('peer:disconnect-requested')) {
			try {
				(listener as (pubkey: string) => void)(pubkey);
			} catch (err) {
				try {
					this.emitStructuredLog('peer', 'disconnect_request_observer_failed', {
						pubkey,
						error: err instanceof Error ? err.message : String(err)
					});
				} catch {
					// Reporting is best effort; the remaining observers still run.
				}
			}
		}
	}

	/**
	 * The fence remedy, node wide (recovery 5.6/5.8): freezeConnections is
	 * the PeerManager's own irreversible teardown (listeners, ALL reconnect
	 * timers, connections still mid-handshake, every registered peer), and
	 * every channel peer that is NOT in the PeerManager's hands by then rides
	 * the event transport, so the host is asked to sever it and the channels
	 * are marked for reestablish. Traffic itself is already gated by
	 * recoveryPermitsPeerTraffic in both modes.
	 */
	private hardFreezeTransports(): void {
		this.peerManager?.freezeConnections();
		for (const pubkey of this.channelManager.listChannelPeers()) {
			this.requestPeerDisconnect(pubkey);
		}
	}

	/**
	 * Sign and send our announcement_signatures for the given SCID (which may
	 * have come from the peer, e.g. a post-splice re-announcement). Before
	 * signing, verify the SCID actually points at this channel's CURRENT
	 * funding transaction via a merkle-position lookup — signing a stale or
	 * bogus SCID produces an announcement the network rejects and burns our
	 * one announcement_signatures send for the session.
	 */
	private async signAnnouncementForScid(
		channelId: Buffer,
		scid: Buffer
	): Promise<void> {
		// Decode block height and tx index from the SCID
		const blockHeight = (scid[0] << 16) | (scid[1] << 8) | scid[2];
		const txIndex = (scid[3] << 16) | (scid[4] << 8) | scid[5];

		const channel = this.channelManager.getChannel(channelId);
		const fundingTxid = channel?.getFullState().fundingTxid;
		if (fundingTxid && this._chainBackend?.getTransactionMerkleProof) {
			try {
				// fundingTxid is stored in internal byte order; Electrum wants display order.
				const displayTxid = Buffer.from(fundingTxid).reverse().toString('hex');
				const proof = await this._chainBackend.getTransactionMerkleProof(
					displayTxid,
					blockHeight
				);
				// txIndex 0 is also what a failed lookup yields (backend swallows
				// errors) — only treat a CONFLICTING position as a mismatch.
				if (proof.txIndex !== 0 && proof.txIndex !== txIndex) {
					this.emitStructuredLog('channel', 'announcement_scid_mismatch', {
						channelId: channelId.toString('hex'),
						claimedBlockHeight: blockHeight,
						claimedTxIndex: txIndex,
						actualTxIndex: proof.txIndex
					});
					return;
				}
			} catch {
				// Unverifiable (backend down / pruned): proceed. A wrong
				// announcement is rejected by peers — no funds at risk.
			}
		}

		const localNodeId = getPublicKey(this.nodePrivkey);
		this.channelManager.triggerAnnouncementDepth(
			channelId,
			blockHeight,
			txIndex,
			localNodeId,
			this.makeAnnouncementSigner(channelId)
		);
	}

	/**
	 * Build the BOLT 7 announcement-signing callback for a channel. The
	 * bitcoin_signature MUST come from the SAME funding key the announcement
	 * advertises as bitcoin_key — the channel's per-channel funding key (via its
	 * signer), NOT the node-level base key. Signing with the base key produces
	 * an announcement peers reject ("Bad bitcoin_signature_2").
	 */
	private makeAnnouncementSigner(
		channelId: Buffer
	): (data: Buffer) => { nodeSig: Buffer; bitcoinSig: Buffer } {
		return (data: Buffer): { nodeSig: Buffer; bitcoinSig: Buffer } => {
			const hash = crypto
				.createHash('sha256')
				.update(crypto.createHash('sha256').update(data).digest())
				.digest();
			const nodeSig = Buffer.from(ecc.sign(hash, this.nodePrivkey));
			const signer = this.channelManager.getChannel(channelId)?.getSigner();
			const bitcoinSig = signer
				? signer.signFundingDigest(hash)
				: Buffer.from(ecc.sign(hash, this.fundingPrivkey));
			return { nodeSig, bitcoinSig };
		};
	}

	/**
	 * Check if a channel needs announcement_signatures sent and trigger signing.
	 * Called after channel reaches NORMAL (including after reestablishment).
	 */
	private triggerPendingAnnouncementSigning(channelId: Buffer): void {
		const channel = this.channelManager
			.listChannels()
			.find((ch) => ch.getChannelId()?.equals(channelId));
		if (!channel) return;

		const state = channel.getFullState();
		if (
			state.announcementSigsReceived &&
			!state.announcementSigsSent &&
			state.shortChannelId
		) {
			// Routed through signAnnouncementForScid so the stored SCID is
			// verified against the funding tx's actual position before signing
			// (it can be stale, e.g. from a pre-splice funding generation).
			void this.signAnnouncementForScid(channelId, state.shortChannelId);
		}
	}

	private registerGossipHandlers(): void {
		if (!this.peerManager) return;
		const gossipTypes = [
			MessageType.CHANNEL_ANNOUNCEMENT,
			MessageType.NODE_ANNOUNCEMENT,
			MessageType.CHANNEL_UPDATE,
			MessageType.QUERY_CHANNEL_RANGE,
			MessageType.REPLY_CHANNEL_RANGE,
			MessageType.QUERY_SHORT_CHANNEL_IDS,
			MessageType.REPLY_SHORT_CHANNEL_IDS_END,
			MessageType.GOSSIP_TIMESTAMP_FILTER
		];
		for (const type of gossipTypes) {
			this.peerManager.onMessage(type, (pubkey, msgType, payload) => {
				this.handleGossipMessage(pubkey, msgType, payload);
			});
		}
	}

	// ─────────────── Peer Storage (BOLT 1 option_provide_storage) ───────────────

	/** Server side: minimum interval between accepted blobs per peer. */
	private static readonly PEER_STORAGE_MIN_INTERVAL_MS = 60_000;

	private registerPeerStorageHandlers(): void {
		if (!this.peerManager) return;
		this.peerManager.onMessage(
			MessageType.PEER_STORAGE,
			(pubkey, _t, payload) => {
				this.handlePeerStorageMessage(pubkey, payload);
			}
		);
		this.peerManager.onMessage(
			MessageType.PEER_STORAGE_RETRIEVAL,
			(pubkey, _t, payload) => {
				this.handlePeerStorageRetrievalMessage(pubkey, payload);
			}
		);
	}

	/**
	 * Server side: hold the latest blob for a peer we have a channel with (or a
	 * trusted peer). Odd message type, so malformed/ineligible blobs are dropped
	 * (logged), never a connection error.
	 */
	private handlePeerStorageMessage(pubkey: string, payload: Buffer): void {
		if (!this.peerStorageEnabled) return;
		let blob: Buffer;
		try {
			blob = decodePeerStorageMessage(payload).blob;
		} catch (err) {
			this.emitStructuredLog('peer', 'peer_storage_invalid', {
				pubkey,
				error: err instanceof Error ? err.message : String(err)
			});
			return;
		}
		// Only spend storage on peers with a fund relationship: an open channel
		// in any live state, or explicit trust (zero-conf set).
		if (!this.peerQualifiesForStorage(pubkey)) {
			this.emitStructuredLog('peer', 'peer_storage_rejected', {
				pubkey,
				reason: 'no channel and not trusted'
			});
			return;
		}
		// Always keep the FRESHEST blob in memory: this is a backup of the peer's
		// latest channel state, so dropping the newest one (as a naive rate limit
		// does) loses exactly the backup that matters when state just changed.
		const now = Date.now();
		this.peerStorageBlobs.set(pubkey, { blob, receivedAt: now });

		// Rate-limit only the DISK write (a misbehaving peer must not turn every
		// update into a disk write). Within the interval, coalesce: schedule a
		// single deferred flush that persists whatever the freshest blob is when
		// it fires, so the latest backup still reaches disk.
		const last = this.peerStorageLastAccepted.get(pubkey);
		if (
			last !== undefined &&
			now - last < LightningNode.PEER_STORAGE_MIN_INTERVAL_MS
		) {
			if (!this.peerStorageFlushTimers.has(pubkey)) {
				const delay = LightningNode.PEER_STORAGE_MIN_INTERVAL_MS - (now - last);
				const timer = setTimeout(() => {
					this.peerStorageFlushTimers.delete(pubkey);
					const freshest = this.peerStorageBlobs.get(pubkey);
					if (freshest) this.persistPeerStorageBlob(pubkey, freshest.blob);
				}, delay);
				if (typeof timer.unref === 'function') timer.unref();
				this.peerStorageFlushTimers.set(pubkey, timer);
			}
			return;
		}
		this.persistPeerStorageBlob(pubkey, blob);
	}

	/** Persist a peer-storage blob and mark the rate-limit window. */
	private persistPeerStorageBlob(pubkey: string, blob: Buffer): void {
		this.peerStorageLastAccepted.set(pubkey, Date.now());
		if (this.storage?.savePeerStorageBlob) {
			this.safeStorage(
				() => this.storage!.savePeerStorageBlob!(pubkey, blob, Date.now()),
				'savePeerStorageBlob'
			);
		}
	}

	/**
	 * Client side: a peer returned the blob it held for us. Kept in memory
	 * (newest per peer) and surfaced via event; validation and any use of the
	 * contents is the caller's job: a peer may return stale data or garbage.
	 */
	private handlePeerStorageRetrievalMessage(
		pubkey: string,
		payload: Buffer
	): void {
		if (!this.peerStorageEnabled) return;
		let blob: Buffer;
		try {
			blob = decodePeerStorageRetrievalMessage(payload).blob;
		} catch (err) {
			this.emitStructuredLog('peer', 'peer_storage_retrieval_invalid', {
				pubkey,
				error: err instanceof Error ? err.message : String(err)
			});
			return;
		}
		// Unwrap our own privacy padding (see padOwnPeerStorageBlob). A blob we
		// never padded (or a peer's un-framed blob echoed back) is passed
		// through unchanged.
		const unwrapped = this.unpadOwnPeerStorageBlob(blob);
		this.retrievedPeerStorage.set(pubkey, {
			blob: unwrapped,
			receivedAt: Date.now()
		});
		this.emit('peer_storage:retrieved', pubkey, unwrapped);
	}

	/**
	 * Pad OUR outbound peer-storage blob to the fixed maximum so a storing peer
	 * cannot learn how much channel state we hold (BOLT 1 privacy). Framing:
	 * [4-byte magic 'bPS1'][4-byte big-endian real length][blob][zero pad] to
	 * PEER_STORAGE_MAX_BYTES. Only applied to our own blob; peers' blobs we
	 * store are kept verbatim.
	 */
	private padOwnPeerStorageBlob(blob: Buffer): Buffer {
		const header = Buffer.alloc(8);
		header.write('bPS1', 0, 'ascii');
		header.writeUInt32BE(blob.length, 4);
		const framed = Buffer.concat([header, blob]);
		if (framed.length > PEER_STORAGE_MAX_BYTES) {
			// An over-max frame would be rejected by the wire encoder (and by the
			// peer); throwing here keeps the failure loud instead of losing the
			// backup inside a best-effort send path.
			throw new Error(
				`peer storage blob too large to frame: ${blob.length} + 8 > ${PEER_STORAGE_MAX_BYTES} bytes`
			);
		}
		if (framed.length === PEER_STORAGE_MAX_BYTES) return framed;
		return Buffer.concat([
			framed,
			Buffer.alloc(PEER_STORAGE_MAX_BYTES - framed.length)
		]);
	}

	/** Reverse padOwnPeerStorageBlob; pass through anything not our framing. */
	private unpadOwnPeerStorageBlob(blob: Buffer): Buffer {
		if (blob.length < 8 || blob.toString('ascii', 0, 4) !== 'bPS1') {
			return blob;
		}
		const realLen = blob.readUInt32BE(4);
		if (8 + realLen > blob.length) return blob;
		return Buffer.from(blob.subarray(8, 8 + realLen));
	}

	/** Whether a peer earns storage: any non-CLOSED channel, or trusted. */
	private peerQualifiesForStorage(pubkey: string): boolean {
		if (this.channelManager.isTrustedPeer(pubkey)) return true;
		for (const channel of this.channelManager.listChannels()) {
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			if (this.channelManager.getPeerForChannel(channelId) !== pubkey) continue;
			if (channel.getState() !== ChannelState.CLOSED) return true;
		}
		return false;
	}

	/**
	 * On (re)connect: return the peer's stored blob (BOLT 1 MUST, we advertise
	 * the feature) and push our own blob if the peer advertised
	 * option_provide_storage. Best-effort: the peer may already be gone.
	 */
	private sendPeerStorageOnConnect(pubkey: string): void {
		if (!this.peerStorageEnabled || !this.peerManager) return;
		// Server direction: peer_storage_retrieval with the blob we hold.
		let held = this.peerStorageBlobs.get(pubkey);
		if (!held && this.storage?.loadPeerStorageBlob) {
			try {
				const loaded = this.storage.loadPeerStorageBlob(pubkey);
				if (loaded) {
					held = loaded;
					this.peerStorageBlobs.set(pubkey, loaded);
				}
			} catch (err) {
				this.emitStructuredLog('peer', 'peer_storage_load_failed', {
					pubkey,
					error: err instanceof Error ? err.message : String(err)
				});
			}
		}
		try {
			if (held) {
				this.peerManager.sendToPeer(
					pubkey,
					MessageType.PEER_STORAGE_RETRIEVAL,
					encodePeerStorageRetrievalMessage({ blob: held.blob })
				);
			}
			// A journaled commit may have landed inside the refresh-throttle
			// window. The throttle exists for PROVIDER rate limits, and a newly
			// connecting provider has no history with us, so it gets a freshly
			// composed capsule instead of the cached (up to a minute stale) blob.
			if (this.capsuleDirty && this.peerAdvertisesPeerStorage(pubkey)) {
				const fresh = this.composeRecoveryCapsuleBlob();
				if (fresh) this.ourPeerStorageBlob = fresh;
			}
			// Client direction: our current blob, only to peers advertising the bit.
			if (this.ourPeerStorageBlob && this.peerAdvertisesPeerStorage(pubkey)) {
				this.peerManager.sendToPeer(
					pubkey,
					MessageType.PEER_STORAGE,
					encodePeerStorageMessage({
						blob: this.padOwnPeerStorageBlob(this.ourPeerStorageBlob)
					})
				);
			}
		} catch {
			// Peer disconnected between connect event and send; ignore.
		}
	}

	private peerAdvertisesPeerStorage(pubkey: string): boolean {
		const init = this.peerManager?.getPeer(pubkey)?.getRemoteInit();
		return init ? init.features.hasFeature(Feature.PROVIDE_STORAGE) : false;
	}

	/**
	 * Set our backup blob and push it to every connected peer that advertised
	 * option_provide_storage (BOLT 1 forbids sending to others). The blob is
	 * remembered and re-pushed to each capable peer on connect. Returns the
	 * number of peers the blob was sent to.
	 *
	 * Throws on an oversized blob: silently truncated backups are worse than
	 * no backup.
	 */
	distributePeerStorage(blob: Buffer): number {
		// The privacy padding (padOwnPeerStorageBlob) frames the blob with an
		// 8-byte header before padding to the wire maximum, so the raw blob must
		// leave room for it; otherwise a blob accepted here would throw (or be
		// silently dropped by best-effort sends) at encode time.
		if (blob.length > PEER_STORAGE_MAX_BYTES - 8) {
			throw new Error(
				`peer storage blob too large: ${blob.length} > ${
					PEER_STORAGE_MAX_BYTES - 8
				} bytes (${PEER_STORAGE_MAX_BYTES} wire max minus 8-byte framing)`
			);
		}
		if (!this.peerStorageEnabled) return 0;
		this.ourPeerStorageBlob = Buffer.from(blob);
		if (!this.peerManager) return 0;
		// Fixed-size padding hides how much channel state we back up (BOLT 1).
		const payload = encodePeerStorageMessage({
			blob: this.padOwnPeerStorageBlob(this.ourPeerStorageBlob)
		});
		let sent = 0;
		for (const peer of this.peerManager.listPeers()) {
			if (!this.peerAdvertisesPeerStorage(peer.pubkey)) continue;
			try {
				this.peerManager.sendToPeer(
					peer.pubkey,
					MessageType.PEER_STORAGE,
					payload
				);
				sent++;
			} catch {
				// Peer disconnected mid-iteration; skip.
			}
		}
		return sent;
	}

	/**
	 * Throttled Recovery Capsule refresh (docs/RECOVERY-PROTOCOL.md 5.4):
	 * journaled commits (snapshots included) schedule it, but it runs at most
	 * once per minute, respecting BOLT 1 provider rate limits. Trailing edge:
	 * a burst of transitions inside the window still ends with exactly one
	 * refresh, composed from whatever state is durable when it fires.
	 */
	private scheduleRecoveryCapsuleRefresh(): void {
		if (!this.recoveryCapsuleActive || !this.peerStorageEnabled) return;
		this.capsuleDirty = true;
		const elapsed = Date.now() - this.capsuleLastRefreshAt;
		if (elapsed >= LightningNode.PEER_STORAGE_MIN_INTERVAL_MS) {
			this.refreshRecoveryCapsule();
			return;
		}
		if (this.capsuleRefreshTimer) return;
		const timer = setTimeout(() => {
			this.capsuleRefreshTimer = null;
			this.refreshRecoveryCapsule();
		}, LightningNode.PEER_STORAGE_MIN_INTERVAL_MS - elapsed);
		if (typeof timer.unref === 'function') timer.unref();
		this.capsuleRefreshTimer = timer;
	}

	/** Arm one deferred refresh on the throttle cadence (re-base retry). */
	private scheduleCapsuleRetry(): void {
		if (this.capsuleRefreshTimer) return;
		const timer = setTimeout(() => {
			this.capsuleRefreshTimer = null;
			this.refreshRecoveryCapsule();
		}, LightningNode.PEER_STORAGE_MIN_INTERVAL_MS);
		if (typeof timer.unref === 'function') timer.unref();
		this.capsuleRefreshTimer = timer;
	}

	/**
	 * Compose the current Recovery Capsule (spec 5.4) and push it to every
	 * connected peer that provides storage. The blob is also remembered and
	 * re-pushed on each future connect (distributePeerStorage semantics), so
	 * a capsule composed with no peers connected is not wasted. Returns the
	 * number of peers pushed to now.
	 *
	 * Composition reads only durable state (the SCB data and the stored
	 * journal), so a refresh racing live transitions is simply as fresh as
	 * the last committed one. Failures are logged, never thrown: capsule
	 * distribution is a replica, and must not take down the node.
	 */
	refreshRecoveryCapsule(): number {
		const blob = this.composeRecoveryCapsuleBlob();
		if (!blob) return 0;
		this.capsuleLastRefreshAt = Date.now();
		return this.distributePeerStorage(blob);
	}

	/**
	 * Compose the current capsule blob, or null when inactive or failed.
	 *
	 * The journal re-bases FIRST (prepareForReplication): a journal left
	 * stale by a recovery-disabled period must never be replicated, or the
	 * capsule's SCB and its inline Tier 2 journal would describe different
	 * points in time. A FAILED re-base prohibits inlining outright
	 * (allowInline false): a failed snapshot write leaves the old chain
	 * internally valid yet possibly stale, and staleness is exactly what
	 * composition's chain verification cannot see. The SCB and the locator
	 * head fields still go out; both failure modes are logged.
	 */
	private composeRecoveryCapsuleBlob(): Buffer | null {
		if (
			!this.recoveryCapsuleActive ||
			!this.peerStorageEnabled ||
			!this.storage
		) {
			return null;
		}
		// An empty node has nothing to back up, and pushing an empty capsule
		// can only destroy a provider's last good copy. The device that
		// matters here is a seed restore on a fresh database: it connects to
		// its old peers precisely to RETRIEVE the capsule they hold, and the
		// BOLT 1 provider keeps one blob per peer, so our empty push would
		// replace the backup before the operator can act on it (issue #453).
		// Emptiness is the restore side's own definition (assertEmptyTarget):
		// no channels, payments, invoices or secrets. Once a capsule with
		// state has gone out this run, later empties are truthful updates
		// (the last channel closed) and go out as before.
		if (!this.capsuleCarriedState && !this.storageHoldsRecoverableState()) {
			return null;
		}
		let allowInline = true;
		try {
			this.recoveryJournal?.prepareForReplication();
		} catch (err) {
			allowInline = false;
			this.emitStructuredLog('peer', 'recovery_capsule_rebase_failed', {
				error: err instanceof Error ? err.message : String(err)
			});
		}
		try {
			const data = this.buildStaticChannelBackupData();
			const encryptedScb = encodeScb(
				{
					version: 1,
					network: data.network,
					createdAt: Date.now(),
					channels: data.channels
				},
				this.nodePrivkey
			);
			const { blob, inlineError } = composeRecoveryCapsule({
				storage: this.storage,
				encryptedScb,
				guardians: this.recoveryGuardians,
				nodeSecret: this.nodePrivkey,
				allowInline
			});
			if (inlineError) {
				this.emitStructuredLog('peer', 'recovery_capsule_inline_dropped', {
					error: inlineError
				});
			}
			this.capsuleCarriedState = true;
			if (allowInline) {
				this.capsuleDirty = false;
			} else {
				// A transient re-base failure heals when the next journaled
				// append retries the snapshot, but a quiet node may not
				// transition for a while. Retry on the throttle cadence so
				// exact-backup coverage returns as soon as the failure
				// clears, and stay dirty so a connecting provider retries
				// the compose too.
				this.scheduleCapsuleRetry();
			}
			return blob;
		} catch (err) {
			this.emitStructuredLog('peer', 'recovery_capsule_refresh_failed', {
				error: err instanceof Error ? err.message : String(err)
			});
			return null;
		}
	}

	/** Whether this node's tables hold anything a restore would want back. */
	private storageHoldsRecoverableState(): boolean {
		if (!this.storage) return false;
		try {
			assertEmptyTarget(this.storage);
			return false;
		} catch {
			return true;
		}
	}

	/** Newest blob each peer has returned via peer_storage_retrieval. */
	getRetrievedPeerStorage(): Array<{
		peerPubkey: string;
		blob: Buffer;
		receivedAt: number;
	}> {
		return [...this.retrievedPeerStorage.entries()].map(
			([peerPubkey, { blob, receivedAt }]) => ({
				peerPubkey,
				blob: Buffer.from(blob),
				receivedAt
			})
		);
	}

	/**
	 * Constructor-only wiring of the startup gate (it arrives via
	 * config.recovery.startupGate; there is deliberately NO post-construction
	 * attach, because the constructor schedules dials that would race one).
	 * While the gate is closed the node makes no peer contact at all; when it
	 * opens, deferred startup networking runs; if it fences, every connection
	 * drops and the listeners stop, the spec 5.6 hard-freeze.
	 */
	private wireRecoveryGate(gate: GuardianStartupGate): void {
		gate.onOpen(() => {
			if (this._destroyed) return;
			if (this.peerManager) {
				for (const peer of this.peerManager.listPeers()) {
					try {
						this.bringUpChannelPeer(peer.pubkey);
					} catch (err) {
						// One peer failing to come up (it may have vanished mid
						// bring-up) must not reject the confirmation that opened
						// the gate, nor starve the remaining peers.
						this.emitStructuredLog('peer', 'quarantine_release_failed', {
							pubkey: peer.pubkey,
							error: err instanceof Error ? err.message : String(err)
						});
					}
				}
			}
			// The dial pass the constructor deferred (see autoReconnectPeers):
			// stored channel peers are contacted only now, ownership proven.
			if (this._autoReconnectDeferred) {
				this._autoReconnectDeferred = false;
				this.autoReconnectPeers();
			}
		});
		gate.onFenced(() => {
			// Hard-freeze (spec 5.6): a superseded writer must not exchange
			// another wire message with anyone, on either transport.
			this.hardFreezeTransports();
		});
	}

	/**
	 * Wire the quorum durability barrier into the node (recovery 5.8).
	 *
	 * Two node-owned consequences hang off it. A proven supersession is the
	 * SAME hard freeze the startup gate performs, because the two differ only
	 * in when they notice: the gate catches a device that restarts stale, the
	 * barrier catches one that was already running when it was superseded.
	 * And an advancing watermark releases the compaction the journal held back
	 * for a lagging replica.
	 */
	private wireRecoveryBarrier(
		barrier: DurabilityBarrier,
		journal: RecoveryJournal | undefined
	): void {
		barrier.onFenced((superseding) => {
			// The latch and the freeze first: they silence both transport
			// chokepoints before any public observer below gets a chance to
			// throw past them.
			this._barrierFenced = true;
			this.hardFreezeTransports();
			this.emitStructuredLog('channel', 'recovery_fenced', {
				epoch: superseding ? String(superseding.lease.epoch) : null
			});
			this.emit('recovery:fenced', superseding);
		});
		// Ownership settles asynchronously after construction, and a pump that
		// finds no lease with nobody waiting gives up rather than spinning a
		// timer forever. Frames committed during startup would then sit
		// unreplicated until the next commit, which on a quiet node is never,
		// and the journal's retain floor holds compaction at that stalled
		// watermark for exactly as long. The gate opening is the moment
		// ownership is confirmed, so it is the moment to kick.
		this.recoveryGate?.onOpen(() => {
			if (this._destroyed) return;
			barrier.kickReplication();
		});
		if (journal) {
			barrier.onDurableAdvance((through) => {
				this.emit('recovery:durable', through);
				try {
					journal.compact();
				} catch (error) {
					// Compaction is housekeeping; a failure costs disk, never
					// correctness, and must not disturb a release.
					this.emitStructuredLog('channel', 'recovery_compaction_failed', {
						error: error instanceof Error ? error.message : String(error)
					});
				}
			});
		}
	}

	/** The gate's view, for operators and tests. */
	getRecoveryGateState(): string {
		return this.recoveryGate ? this.recoveryGate.getState() : 'disabled';
	}

	/**
	 * The recovery picture in one call (spec 5.6 and 5.8): the startup gate,
	 * the durability mode and how far replication has provably got, plus
	 * every open channel's ChannelRecoveryStatus. While the gate is closed
	 * the node-level rule overrides the per-channel view: channels may not
	 * leave quarantine before ownership confirmation, whatever their own
	 * reestablish bookkeeping says.
	 *
	 * `awaitingDurability` sits BESIDE the status rather than inside it. The
	 * seven ChannelRecoveryStatus values are the spec's 5.7 machine and
	 * describe what is known about a channel's STATE; waiting on a receipt
	 * says nothing about the state, only that a message it authorized has not
	 * been allowed out yet.
	 */
	getRecoveryStatus(): {
		gate: string;
		durability: RecoveryDurability;
		/** True while a startup repair frame awaits its quorum receipt. */
		startupRepairPending: boolean;
		/** Highest journal frame a guardian quorum provably holds. */
		lastDurableSequence: string;
		/**
		 * CHANNELS holding messages behind the barrier right now, not batches.
		 * A channel releases its held batches strictly in order through a
		 * single outstanding wait, so one channel is one waiter however many
		 * batches are parked behind it.
		 */
		awaitingDurabilityCount: number;
		fenced: boolean;
		/**
		 * Compaction pruned frames the quorum never received, so this
		 * namespace can never advance again. Beside `fenced` and never folded
		 * into it: a fence means another device owns the namespace and this
		 * means nobody can advance it, and the remedies differ.
		 */
		backfillLost: boolean;
		channels: Array<{
			channelId: string;
			status: ChannelRecoveryStatus;
			awaitingDurability: boolean;
			/**
			 * A restored channel whose funding this node cannot identify on
			 * chain: something descending from its recorded attempts pays its
			 * funding script, but nothing has spent it, so which output funded
			 * the channel is unproven (issue #463). The channel is deliberately
			 * held in that state indefinitely. It is not forgotten, because a
			 * funding of its lineage is on chain; and it is not closed, because
			 * the stored commitment signs the attempt the record names and not
			 * whatever replaced it, so there is no unilateral exit to drive.
			 * The peer's close is what resolves it, and this reports the wait.
			 */
			fundingUnidentified?: boolean;
			/**
			 * A channel restored from a Recovery Capsule that no
			 * `channel_reestablish` has confirmed against its peer yet
			 * (issue #469). A capsule is best-effort recency (5.4), so until
			 * the peer answers, this node will not broadcast the channel's
			 * commitment on its own initiative: the automatic close paths are
			 * held and the channel asks the peer to close instead.
			 * A compatible reestablish does not lift it, since compatibility is
			 * not recency, so it stands for the life of the channel: such a
			 * channel also takes no new HTLCs, though existing ones still
			 * settle, and a cooperative close is refused in both directions
			 * unless the operator's acceptStaleStateRisk acknowledgement
			 * covers the negotiation. The peer's close and the operator's
			 * acknowledged close (cooperative or force) are the exits.
			 */
			restoreRecencyUnproven?: boolean;
		}>;
		/**
		 * Peers whose channel_reestablish is parked because it names a channel
		 * this node has no record of (5.7, issue #462). Non-empty only on a
		 * node configured as a possible restore target, and it is the operator's
		 * deadline: each entry's expiresAt is when the peer stops waiting and
		 * gets told the channel is unknown, which force-closes it. Deliberately
		 * NOT in `channels`, which describes channels this node HAS.
		 */
		heldReestablish: Array<{
			peer: string;
			channelId: string;
			expiresAt: number;
		}>;
	} {
		const gated = !this.recoveryPermitsPeerTraffic();
		const barrier = this.recoveryBarrier?.snapshot();
		const holding = this.channelManager.channelsAwaitingDurability();
		const channels: Array<{
			channelId: string;
			status: ChannelRecoveryStatus;
			awaitingDurability: boolean;
			fundingUnidentified?: boolean;
			restoreRecencyUnproven?: boolean;
		}> = [];
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (state.state === ChannelState.CLOSED) continue;
			const id = state.channelId ?? state.temporaryChannelId;
			const idHex = id.toString('hex');
			const fundingUnidentified =
				this.chainWatcher?.hasProvisionalFunding(id) ?? false;
			channels.push({
				channelId: idHex,
				status: gated
					? ChannelRecoveryStatus.Quarantined
					: channel.getRecoveryStatus(),
				awaitingDurability: holding.has(idHex),
				...(fundingUnidentified ? { fundingUnidentified: true } : {}),
				...(state.restoreRecencyUnproven
					? { restoreRecencyUnproven: true }
					: {})
			});
		}
		return {
			gate: this.getRecoveryGateState(),
			startupRepairPending: this.startupRepairPending,
			durability:
				this.recoveryJournal?.getDurability() ?? barrier?.durability ?? 'local',
			lastDurableSequence: (barrier?.durableThrough ?? 0n).toString(),
			// Taken from the channel manager rather than the barrier's waiter
			// count: they agree today, and deriving it from the thing the
			// field is named after keeps them agreeing.
			awaitingDurabilityCount: holding.size,
			fenced: barrier?.fenced ?? false,
			// Falls back to the database, so a node whose barrier was removed
			// (or which never had one) still reports the fact rather than a
			// reassuring false.
			backfillLost:
				barrier?.backfillLost ??
				(this.storage ? chainLostBackfill(this.storage) !== null : false),
			channels,
			heldReestablish: this.channelManager.heldUnknownChannelReestablish()
		};
	}

	/**
	 * The single question every transport chokepoint asks. With no gate
	 * configured the node runs ungated, which is the guardian-disabled mode
	 * the spec allows; with one configured, only a confirmed lease passes.
	 */
	private recoveryPermitsPeerTraffic(): boolean {
		// Startup repair quarantine: a carried v2 row's repair frame must be
		// quorum-receipted before this node talks to anyone (connections,
		// outbound messages and inbound dispatch all consult this).
		if (this.startupRepairPending) return false;
		// A runtime supersession is the same hard freeze as a fenced gate
		// (spec 5.6): a superseded writer must not exchange another wire
		// message with anyone, on either transport.
		if (this._barrierFenced) return false;
		return this.recoveryGate ? this.recoveryGate.permitsPeerTraffic() : true;
	}

	/**
	 * Public networking entry points refuse loudly while the gate is closed,
	 * rather than parking: a fenced gate never opens, and a parked promise
	 * on a fenced node would hang its caller forever.
	 */
	private assertPeerContactPermitted(operation: string): void {
		if (this.recoveryPermitsPeerTraffic()) return;
		this.recoveryGate?.reportBlocked(
			`refused ${operation} while ${this.getRecoveryGateState()}`
		);
		throw new Error(
			`Startup quarantine: ${operation} is refused until writer ownership is confirmed (gate is ${this.getRecoveryGateState()})`
		);
	}

	/**
	 * The transport boundary for every node-level outbound message. Prefer the
	 * built-in peer transport when a connected PeerManager is attached, then
	 * fall back to the event transport used by embedded integrators and tests.
	 * Both paths share the recovery gate, so a quarantined or fenced device
	 * emits zero Lightning wire messages.
	 */
	private emitOutbound(
		pubkey: string,
		type: number,
		payload: Buffer,
		transportAttempted = false
	): void {
		if (!this.recoveryPermitsPeerTraffic()) {
			this.recoveryGate?.reportBlocked(
				`suppressed outbound message type ${type} to ${pubkey}`
			);
			return;
		}
		if (
			!transportAttempted &&
			this.peerManager?.getPeer(pubkey)?.getState() === 'ready'
		) {
			this.peerManager.sendToPeer(pubkey, type, payload);
			return;
		}
		this.emit('message:outbound', pubkey, type, payload);
	}

	/**
	 * Everything a fresh connection gets once traffic is permitted. Runs from
	 * peer:connect on an ungated node, and from the gate's open hook for
	 * connections that sat inert through quarantine.
	 */
	private bringUpChannelPeer(pubkey: string): void {
		// BOLT 1 peer storage first: return the peer's stored blob and push our
		// own, before reestablish/gossip traffic (spec: ideally right after init).
		this.sendPeerStorageOnConnect(pubkey);
		this.channelManager.handlePeerReconnected(pubkey);
		// Push our own gossip to the new peer so it propagates onward — a one-shot
		// broadcast at announcement time rarely reaches the whole network.
		this.sendOwnGossipTo(pubkey);
		// Persist peer address for auto-reconnect after crash recovery (Fix 2.1)
		if (this.peerManager) {
			const addr = this.peerManager.getPeerAddress(pubkey);
			if (addr) {
				this.safeStorage(
					() => this.storage!.savePeerAddress(pubkey, addr.host, addr.port),
					'savePeerAddress'
				);
			}
		}
	}

	private wirePeerManagerEvents(): void {
		if (!this.peerManager) return;
		this.peerManager.on('peer:connect', (pubkey: string) => {
			// Quarantine holds channels BEFORE reestablish (recovery 5.6): a
			// device that cannot prove it owns its lease must not exchange
			// channel state with anyone, so the connection is left inert.
			if (!this.recoveryPermitsPeerTraffic()) {
				this.recoveryGate?.reportBlocked(
					`refused to bring up channels with ${pubkey} while quarantined`
				);
				this.notifyPeerConnectObservers(pubkey);
				return;
			}
			this.bringUpChannelPeer(pubkey);
			// The PUBLIC notification is isolated from the required bring-up
			// above: an application observer that throws must not read as a
			// failed bring-up and cost a healthy connection its teardown.
			this.notifyPeerConnectObservers(pubkey);
		});
		this.peerManager.on('peer:disconnect', (pubkey: string) => {
			this.channelManager.handlePeerDisconnected(pubkey);
			this.gossipSyncManagers.delete(pubkey);
			this.rateLimiter.removePeer(pubkey);
			this.notifyPeerDisconnectObservers(pubkey);
		});
		this.peerManager.on('peer:error', (pubkey: string, err: Error) => {
			this.emit('peer:error', pubkey, err);
		});
	}

	/**
	 * Emit the public peer:connect notification, FULLY contained: neither a
	 * throwing application observer nor a throwing diagnostic path (the
	 * structured-log event and the injectable logger are both public too)
	 * may unwind into the PeerManager's bring-up, where the throw would
	 * read as a failed bring-up and tear a healthy connection down.
	 */
	private notifyPeerConnectObservers(pubkey: string): void {
		try {
			this.emit('peer:connect', pubkey);
		} catch (err) {
			try {
				this.emitStructuredLog('peer', 'connect_observer_failed', {
					pubkey,
					error: err instanceof Error ? err.message : String(err)
				});
			} catch {
				// The log observer threw too; reporting is best effort and
				// the connection stays up, which is the outcome that matters.
			}
		}
	}

	/**
	 * Emit the public peer:disconnect notification with each observer FULLY
	 * contained, the disconnect twin of notifyPeerConnectObservers: the emit
	 * runs inside the PeerManager's teardown and replacement bookkeeping, so
	 * a throwing observer unwinding from here would leak the replacement
	 * connection or skip the auto-reconnect. Observers are dispatched
	 * individually, not via emit(): emit stops at the first throw, so a
	 * later observer whose job is cancellation (disconnectPeer) would
	 * silently depend on listener order.
	 */
	private notifyPeerDisconnectObservers(pubkey: string): void {
		for (const listener of this.rawListeners('peer:disconnect')) {
			try {
				(listener as (pubkey: string) => void)(pubkey);
			} catch (err) {
				try {
					this.emitStructuredLog('peer', 'disconnect_observer_failed', {
						pubkey,
						error: err instanceof Error ? err.message : String(err)
					});
				} catch {
					// The log observer threw too; reporting is best effort
					// and the teardown bookkeeping continues regardless.
				}
			}
		}
	}

	/**
	 * Auto-reconnect peers after crash recovery. Staggered to avoid thundering herd.
	 */
	private autoReconnectPeers(): void {
		// With auto-reconnect off this whole path is off: startup recovery
		// dials channel partners directly, on its own timers, so gating only
		// the PeerManager would leave a parked node redialing its peers on
		// every start. The ready lifecycle is this method's to complete on
		// every exit, so the disabled branch still emits it.
		if (!this.autoReconnect || !this.storage || !this.peerManager) {
			this.emitReady();
			return;
		}

		// Startup ownership quarantine: the node may not even connect to
		// channel peers before the quorum confirms the lease. Defer the whole
		// dial pass to the gate's open hook; a fenced gate never opens, so a
		// superseded device never dials at all. Ready still fires: a
		// quarantined node is constructed and operable, just silent.
		if (this.recoveryGate && !this.recoveryGate.permitsPeerTraffic()) {
			if (this.recoveryGate.getState() === 'quarantined') {
				this._autoReconnectDeferred = true;
			}
			this.emitReady();
			return;
		}

		const peerAddresses = this.storage.loadAllPeerAddresses();
		const channelPeers = new Set<string>();

		// Only reconnect peers that have channels needing reestablishment, or
		// carrying a durable recovery-close disposition (5.6): those must
		// proactively reach the peer to deliver the force-close request, or a
		// crash between the ERRORED persist and the error send would leave
		// the channel waiting forever on a peer that never dials us.
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getState();
			if (
				state === ChannelState.AWAITING_REESTABLISH ||
				state === ChannelState.AWAITING_CHANNEL_READY ||
				channel.hasRecoveryCloseDisposition()
			) {
				const channelId = channel.getChannelId();
				if (channelId) {
					const peer = this.channelManager.getPeerForChannel(channelId);
					if (peer) channelPeers.add(peer);
				}
			}
		}

		// Count how many peers we need to reconnect
		const peersToConnect = peerAddresses.filter((p) =>
			channelPeers.has(p.pubkey)
		);

		// Seed gossip-announced reconnect fallbacks for every channel peer, and
		// dial peers that have no stored address at all (they only ever
		// connected inbound) via their announcement. Without this, such peers
		// are unreachable after a restart until they dial us. Two sources,
		// newest announcement timestamp wins: the persisted capture (the only
		// record for private-only peers, whose announcements the graph
		// rejects) and the restored graph. Seeding the timestamps also keeps
		// replayed old announcements from regressing addresses post-restart.
		// A capture persisted before the far-future bound existed can carry a
		// poisoned timestamp that no later real announcement could supersede
		// (the same repair restoreChannel applies to graph rows); drop it so
		// the graph announcement or the next live capture reseeds the slot.
		const persistedAnnounced = new Map(
			(this.storage.loadAllAnnouncedPeerAddresses?.() ?? [])
				.filter((entry) => !gossipTimestampTooFarFuture(entry.timestamp))
				.map((entry) => [entry.pubkey, entry])
		);
		for (const pubkey of channelPeers) {
			let newest = persistedAnnounced.get(pubkey);
			// Addresses are dialed, so only a signature-verified announcement
			// may supply them; a deferred one is resolved by this read
			// (issue #443).
			const announcement = this.graph.getVerifiedNodeAnnouncement(
				Buffer.from(pubkey, 'hex')
			);
			if (
				announcement &&
				(!newest || announcement.timestamp > newest.timestamp)
			) {
				newest = {
					pubkey,
					timestamp: announcement.timestamp,
					addresses: announcedDialableAddresses(announcement.addresses)
				};
			}
			if (!newest) continue;
			this.announcedPeerAddresses.set(pubkey, {
				timestamp: newest.timestamp,
				addresses: newest.addresses
			});
			this.peerManager.setAnnouncedAddresses(pubkey, newest.addresses);
			if (
				newest.addresses.length > 0 &&
				!peersToConnect.some((p) => p.pubkey === pubkey)
			) {
				peersToConnect.push({
					pubkey,
					host: newest.addresses[0].host,
					port: newest.addresses[0].port
				});
			}
		}

		if (peersToConnect.length === 0) {
			this.emitReady();
			return;
		}

		this._pendingReconnects = peersToConnect.length;

		let delay = 0;
		const STAGGER_MS = 500;

		for (const { pubkey, host, port } of peersToConnect) {
			const pm = this.peerManager;
			const timer = setTimeout(() => {
				this._reconnectTimers.delete(timer);
				if (this._destroyed) return;
				pm.connectPeer(pubkey, host, port)
					.catch((err) => {
						this.emit('node:error', {
							code: 'AUTO_RECONNECT_FAILED',
							message: `Failed to reconnect ${pubkey.slice(0, 8)}...: ${
								(err as Error).message
							}`,
							timestamp: Date.now()
						} as ILightningError);
					})
					.finally(() => {
						this._pendingReconnects--;
						if (this._pendingReconnects <= 0) {
							this.emitReady();
						}
					});
			}, delay);
			timer.unref();
			this._reconnectTimers.add(timer);
			delay += STAGGER_MS;
		}
	}

	private emitReady(): void {
		if (this._readyEmitted || this._destroyed) return;
		// Readiness never outruns the startup repair quarantine; the
		// receipt path re-drives this after the quarantine lifts.
		if (this.startupRepairPending) return;
		this._readyEmitted = true;
		process.nextTick(() => {
			this.emit('node:ready');
		});
	}

	// ─────────────── Auto-Funding ───────────────

	private handleAutoFunding(channel: Channel, _peerPubkey: string): void {
		const state = channel.getFullState();
		if (!state.remoteBasepoints) return;

		const networkMap: Record<string, bitcoin.Network> = {
			[Network.MAINNET]: bitcoin.networks.bitcoin,
			[Network.TESTNET]: bitcoin.networks.testnet,
			[Network.REGTEST]: bitcoin.networks.regtest,
			[Network.SIGNET]: bitcoin.networks.testnet
		};
		const btcNetwork = networkMap[this.network] || bitcoin.networks.regtest;

		// Simple taproot channels fund a P2TR MuSig2 key-spend output, NOT the
		// witness-v0 2-of-2 P2WSH. The funding output script MUST match the one the
		// commitment signs against (taprootFundingSpk), or the peer never sees the
		// funding confirm and the commitment can't spend it.
		const { address } = isTaprootChannel(state.channelType)
			? createTaprootFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints.fundingPubkey,
					btcNetwork
			  )
			: createFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints.fundingPubkey,
					btcNetwork
			  );

		// Fund at the rate the opener asked for, if it asked for one. Sanity-clamped
		// like the estimator's own rate: a caller-supplied number is still a number
		// that can be wrong, and an absurd one here is paid to miners out of the
		// balance that was meant to go into the channel.
		const tempId = channel.getTemporaryChannelId().toString('hex');
		const requestedFeeRate = this.requestedFundingFeeRates.get(tempId);
		this.requestedFundingFeeRates.delete(tempId);
		const fundMax = this.fundingMaxRequests.has(tempId);
		this.fundingMaxRequests.delete(tempId);

		// Otherwise use a dynamic fee if an estimator is available (sanity-clamped).
		const feePromise =
			requestedFeeRate !== undefined
				? Promise.resolve(this.clampEstimatedFeeRate(requestedFeeRate))
				: this.feeEstimator
				? this.feeEstimator
						.estimateFee(6)
						.then((f) => (f > 0 ? this.clampEstimatedFeeRate(f) : undefined))
				: Promise.resolve(undefined);

		let builtTxHex: string | null = null;
		let builtTxidHex: string | null = null;
		feePromise
			.then((satsPerByte) =>
				this.fundingProvider!.buildFundingTransaction(
					address,
					state.fundingSatoshis,
					satsPerByte,
					fundMax
				)
			)
			.then(({ txHex, txid, outputIndex }) => {
				// Captured for the catch below: a throw between here and
				// setPendingFundingTx leaves pledged inputs with no entry the
				// retirement sweep could ever release (issue #412).
				builtTxHex = txHex;
				builtTxidHex = txid.toString('hex');
				// Set funding outpoint on state before signing (required for commitment building)
				state.fundingTxid = txid;
				state.fundingOutputIndex = outputIndex;

				// Sign the remote's initial commitment (use channel signer for per-channel keys)
				const signer =
					channel.getSigner() ||
					(this.signerFactory
						? this.signerFactory(channel.channelKeyIndex ?? 0)
						: new ChannelSigner(this.fundingPrivkey, this.htlcBasepointSecret));
				const { signature } = signRemoteCommitment(
					state,
					signer,
					state.remoteCurrentPerCommitmentPoint!
				);

				// Retained BEFORE createFunding so a crash in the signing window
				// cannot lose the transaction. It is a CANDIDATE, not an
				// obligation: BOLT 2 starts that at funding_signed, and nothing
				// here may put it on the network. The comment this replaces
				// claimed the funding_created to watch:funding chain completed
				// synchronously, which held only in loopback and is exactly what
				// let a block broadcast it mid-handshake.
				// The payload rides the CHANNEL state, so the frame that records
				// funding_signed carries the bytes beside the obligation and a
				// guardian restore can actually discharge what it restores. The
				// node's own map stays as the runtime index.
				state.pendingFundingTxHex = txHex;
				this.setPendingFundingTx(txid.toString('hex'), txHex);

				// Send funding_created. The broadcast now waits for the
				// authorization action handleFundingSigned emits.
				this.channelManager.createFunding(
					channel,
					txid,
					outputIndex,
					signature
				);
			})
			.catch((err) => {
				this.emit('node:error', {
					code: 'AUTO_FUNDING_FAILED',
					message: (err as Error).message,
					timestamp: Date.now()
				} as ILightningError);
				// The build succeeded but the open died before funding_created
				// went out (the same boundary abortPendingOpen no-ops past):
				// the peer never had anything to sign and nothing was
				// broadcast, so the pledged inputs free here (issue #412).
				if (builtTxHex && !channel.getChannelId()) {
					if (builtTxidHex) this.deletePendingFundingTx(builtTxidHex);
					this.releaseFundingTxPledges(builtTxHex);
				}
				// A funding failure after accept_channel must not strand the
				// negotiated channel in SENT_OPEN/SENT_ACCEPT: tear it down and
				// tell the peer, so neither side keeps a half-open channel that
				// can never fund. No-op if funding_created already went out.
				this.channelManager.abortPendingOpen(
					channel,
					`funding failed: ${(err as Error).message}`
				);
			});
	}

	/**
	 * Void a channel whose funding tx vanished before confirming and cannot
	 * (or can no longer) be rebroadcast: drop it from the manager, retire its
	 * watch, its persisted state and any retained funding tx, and tell the
	 * embedder via channel:voided.
	 */
	private voidMissingFundingChannel(channelId: Buffer, txid: string): boolean {
		const idHex = channelId.toString('hex');
		// Durable FIRST: the live channel and its funding watch are only
		// removed once the deletion, or at least the durable intent to
		// delete, exists on disk. Removing them first and failing both
		// writes would leave a storage-wide outage with neither a tracked
		// channel nor a watch while the row silently restores at the next
		// start. Returns whether the terminal decision landed durably
		// (deleted, or condemned so a restart deletes instead of restoring);
		// callers releasing resources tied to the channel (issue #311
		// funding pledges) must act only on true.
		const deleted = this.deleteChannelDurably(idHex);
		if (!deleted && !this.condemnChannelRow(idHex)) {
			this.emitStructuredLog('channel', 'channel_void_unresolved', {
				channelId: idHex,
				txid
			});
			return false;
		}
		if (!this.channelManager.voidChannel(channelId)) return true;
		this.chainWatcher?.removeWatchedFunding(channelId);
		const pendingKey = Buffer.from(txid, 'hex').reverse().toString('hex');
		const retainedTxHex = this.pendingFundingTxs.get(pendingKey)?.txHex;
		this.deletePendingFundingTx(pendingKey);
		// The void IS the durable decision that this funding is not on chain
		// and will not be rebroadcast, so whatever pledges still reserve its
		// inputs protect a transaction that will never exist (issue #412).
		// This is also the terminal for a dead channel's preserved broadcast
		// obligation, which retryPendingFundingBroadcasts deliberately never
		// retires on channel state alone.
		if (retainedTxHex) this.releaseFundingTxPledges(retainedTxHex);
		if (!deleted) {
			// The row survived but is durably condemned: the removal
			// proceeds and the terminal event fires when the deletion lands
			// at the next start. Emitting it now would claim a deletion
			// that did not happen.
			this.emitStructuredLog('channel', 'channel_void_deferred', {
				channelId: idHex,
				txid
			});
			return true;
		}
		this.emitStructuredLog('channel', 'channel_voided', {
			channelId: idHex,
			txid
		});
		this.emit('channel:voided', { channelId });
		return true;
	}

	// ─────────────── Pending funding broadcasts ───────────────

	/** Metadata key holding the persisted pending funding tx map. */
	private static readonly PENDING_FUNDING_TXS_KEY = 'pending_funding_txs';

	/** Persist the pending funding tx map (best-effort). */
	private persistPendingFundingTxs(): void {
		this.safeStorage(
			() =>
				this.storage!.saveMetadata(
					LightningNode.PENDING_FUNDING_TXS_KEY,
					JSON.stringify(
						[...this.pendingFundingTxs].map(([txid, entry]) => ({
							txid,
							txHex: entry.txHex
						}))
					)
				),
			'savePendingFundingTxs'
		);
	}

	/**
	 * A blocked persist on a v2 OPENING left its in-memory channel ahead of
	 * the row (the failed write may have carried a replacement attempt the
	 * disk never saw). Re-restore the row, restart-equivalent: the durable
	 * attempt is the only one a crash would resume, so it is the only one
	 * this side may keep tracking; a provisional DUAL_FUNDING_V2 row rolls
	 * back to its retained previous attempt exactly as a restart would.
	 * The live registration is never removed here: restoreChannel registers
	 * via a map overwrite, and every fallible step it runs (signer
	 * construction, session restores, reestablish marking) happens BEFORE
	 * that overwrite, so a throw anywhere leaves the previous object
	 * tracked and success replaces it in one step. Scoped to v2 opening
	 * shapes; established channels re-converge through the ordinary
	 * reestablish and outbox replay.
	 */
	/**
	 * The state a retained v2 opening attempt resumes in when a provisionally
	 * accepted RBF is rolled back to it.
	 *
	 * An attempt whose witnesses already left waits on the CHAIN, not on the
	 * peer: resuming it as AWAITING_TX_SIGNATURES would park it waiting for
	 * signatures that were exchanged before the renegotiation started, and it
	 * would sit there until some later reconnect shook it loose. Mirrors
	 * Channel's own `_v2StateForRecord`, and is shared by all three rollback
	 * sites (startup restore, the open-abandon revert, and the live resync)
	 * so a row cannot resume differently depending on which one ran.
	 */
	private v2RetainedAttemptState(inflight: IV2InFlight): ChannelState {
		return inflight.sentTxSignatures || inflight.fullySigned
			? ChannelState.AWAITING_FUNDING_CONFIRMED
			: ChannelState.AWAITING_TX_SIGNATURES;
	}

	private resyncV2OpenFromDisk(channelId: Buffer | null): void {
		if (!channelId || !this.storage) return;
		const idHex = channelId.toString('hex');
		let row: { state: IChannelState; peerPubkey: string } | null = null;
		try {
			row = this.storage.loadChannel?.(idHex) ?? null;
		} catch {
			return;
		}
		if (!row || !row.state.v2InFlight || row.state.condemned) return;
		if (
			row.state.state !== ChannelState.AWAITING_TX_SIGNATURES &&
			row.state.state !== ChannelState.DUAL_FUNDING_V2
		) {
			return;
		}
		try {
			if (row.state.state === ChannelState.DUAL_FUNDING_V2) {
				row.state.state = this.v2RetainedAttemptState(row.state.v2InFlight);
			}
			const channel = new Channel(row.state);
			const keyIndex = this.storage.loadChannelKeyIndex(idHex);
			this.channelManager.restoreChannel(channel, row.peerPubkey, keyIndex);
			this.emitStructuredLog('channel', 'v2_open_resynced_from_disk', {
				channelId: idHex
			});
		} catch {
			// Nothing was removed: the stale in-memory channel stays tracked
			// and the row is re-evaluated at the next start.
		}
	}

	/**
	 * Terminal channel-row deletion, routed through the recovery journal
	 * (the channel_closed mutation; the storage layer cascades the outbox
	 * rows) so the deletion is a journaled transition rather than a bare
	 * storage write; falls back to the direct delete when recovery is
	 * disabled. Returns whether the deletion landed.
	 */
	private deleteChannelDurably(idHex: string): boolean {
		if (this.recovery) {
			return this.commitMutations(
				'deleteChannel',
				[{ type: 'channel_closed', channelId: idHex }],
				RecoveryCriticality.Important
			);
		}
		return this.safeStorage(
			() => this.storage!.deleteChannel(idHex),
			'deleteChannel'
		);
	}

	/**
	 * Condemn the row itself: its durable deletion was decided but the
	 * delete failed, so the intent is written INTO the row, atomic with the
	 * state a restart reads. There is no separate tombstone store whose
	 * read can fail and silently resurrect the channel: startup either
	 * reads the condemned row (and deletes instead of restoring) or cannot
	 * read the row at all, in which case nothing restores either. Returns
	 * whether the intent is durable; a false answer means the caller must
	 * keep the channel tracked.
	 */
	private condemnChannelRow(idHex: string): boolean {
		try {
			const row = this.storage?.loadChannel?.(idHex);
			// No row: there is nothing a restart could resurrect.
			if (!row) return true;
			row.state.condemned = true;
			// Journaled like every other durable channel transition: a
			// verified-frame reconstruction must rebuild the row CONDEMNED,
			// or recovery would resurrect a channel whose deletion was
			// already decided.
			if (this.recovery) {
				return this.commitMutations(
					'condemnChannel',
					[
						{
							type: 'channel_state',
							channelId: idHex,
							state: row.state,
							peerPubkey: row.peerPubkey
						}
					],
					RecoveryCriticality.Important
				);
			}
			return this.safeStorage(
				() => this.storage!.saveChannel(idHex, row.state, row.peerPubkey),
				'saveChannel'
			);
		} catch {
			return false;
		}
	}

	/** Record a signed funding tx we are obligated to broadcast. */
	private setPendingFundingTx(txidHex: string, txHex: string): void {
		// 'candidate': retained so a crash in the signing window cannot lose the
		// transaction, but NOT yet owed. Only the authorization action promotes
		// it, and that action has cleared the persist gate and the barrier.
		this.pendingFundingTxs.set(txidHex, { txHex, phase: 'candidate' });
		this.persistPendingFundingTxs();
	}

	/** Drop a broadcast obligation (confirmed, or its channel is gone). */
	private deletePendingFundingTx(txidHex: string): void {
		this.reauthAttempts.delete(txidHex);
		// Drop the payload from channel state with the obligation it served, so
		// a confirmed channel does not carry the transaction through every
		// future snapshot. The write rides whatever transition retires the
		// obligation; losing it costs nothing, since by then the funding is
		// confirmed or the channel is gone.
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (state.fundingTxid?.toString('hex') !== txidHex) continue;
			delete state.pendingFundingTxHex;
			break;
		}
		if (this.pendingFundingTxs.delete(txidHex)) {
			this.persistPendingFundingTxs();
		}
	}

	/**
	 * May this retained funding transaction go onto the network yet?
	 *
	 * BOLT 2 starts the broadcast obligation at funding_signed, never at
	 * funding_created: without the acceptor's signature over our commitment #0
	 * the funding output has no unilateral exit for us, so a broadcast in that
	 * window puts the whole capacity behind a peer who may simply never answer.
	 * Retaining the transaction from the moment it is signed is right, so a
	 * crash in the signing window cannot lose it. Owing it is what has to wait.
	 *
	 * The answer cannot be derived from channel state alone, and that is the
	 * subtle part. handleFundingSigned mutates the channel to
	 * AWAITING_FUNDING_CONFIRMED and stores remoteCommitmentSignature while
	 * BUILDING its action array, before anything is dispatched, so a predicate
	 * reading the channel is already true the instant a quorum barrier starts
	 * holding that batch, and the next block would broadcast straight through
	 * the hold. Only the authorization ACTION knows it cleared both the persist
	 * gate and the barrier.
	 *
	 * A RESTORED entry is not resolved from the channel either, and that is the
	 * subtle half. The obligation survives a restart, because the peer's
	 * signature over our commitment #0 is on disk; the AUTHORIZATION does not,
	 * and the two are not the same thing. A channel row proves only that THIS
	 * device wrote the frame, never that the guardians accepted it, so under a
	 * barrier the original authorization may have been held when the process
	 * died and reading the row back would walk straight around the hold.
	 * Restored channel state may determine that an authorization is NEEDED. It
	 * must never BE the authorization, so the restart asks again through a
	 * fresh persist whose frame the barrier can actually wait on.
	 */
	private owesFundingBroadcast(txidHex: string): boolean {
		const entry = this.pendingFundingTxs.get(txidHex);
		if (!entry) return false;
		if (entry.phase === 'authorized') return true;
		// A candidate has no authorization dispatched yet; a restored entry
		// lost the one it had. Neither may broadcast on its own account.
		if (entry.phase === 'restored') this.requestFundingReauthorization(txidHex);
		return false;
	}

	/**
	 * Mint a fresh authorizing frame for a restored funding obligation, at most
	 * one at a time per transaction.
	 *
	 * Without the outstanding-request guard every block would append another
	 * no-op frame while the first was still waiting on the quorum. The flag is
	 * cleared when the authorization is granted, and on a refusal the next
	 * sweep asks again, which is the retry this obligation is supposed to have.
	 */
	/**
	 * Is this retained transaction owed but not yet allowed out?
	 *
	 * True exactly while the obligation exists and the authorization does not:
	 * a candidate whose funding_signed has arrived but whose authorization is
	 * still parked, or a restored entry that has not been re-asked yet. It
	 * separates "we are deliberately not broadcasting this" from "this channel
	 * is fiction", which is a distinction the absence of a transaction on chain
	 * cannot make on its own.
	 */
	private awaitingFundingAuthorization(txidHex: string): boolean {
		const entry = this.pendingFundingTxs.get(txidHex);
		if (!entry || entry.phase === 'authorized') return false;
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (state.fundingTxid?.toString('hex') !== txidHex) continue;
			// The same two conditions the live path establishes at
			// funding_signed. Without them this is an open that never got that
			// far, which genuinely has nothing to broadcast.
			return (
				state.state !== ChannelState.SENT_FUNDING_CREATED &&
				!!state.remoteCommitmentSignature
			);
		}
		return false;
	}

	private requestFundingReauthorization(txidHex: string): void {
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (state.fundingTxid?.toString('hex') !== txidHex) continue;
			const id = state.channelId ?? state.temporaryChannelId;
			if (!id) return;
			if (!this.mayAskForReauthorization(txidHex, id.toString('hex'))) return;
			this.reauthAttempts.set(txidHex, Date.now());
			if (!this.channelManager.reauthorizeFundingBroadcast(id)) {
				this.reauthAttempts.delete(txidHex);
			}
			return;
		}
	}

	/**
	 * Re-send a splice the barrier has already released in this process.
	 *
	 * Straight at the backend deliberately: the authorization this rebroadcast
	 * rides was granted through the action path and is what made these bytes
	 * sendable. Repeating the transaction is idempotent, and the alternative,
	 * a fresh frame per retry window, buys nothing.
	 */
	private rebroadcastAuthorizedSplice(idHex: string, txHex: string): void {
		if (!this._chainBackend) return;
		this._chainBackend.broadcastTransaction(txHex).catch(() => {
			// Already in mempool or confirmed, or a backend hiccup. The watch
			// on the new funding output reports the confirmation either way.
			this.emitStructuredLog('chain', 'splice_rebroadcast_failed', {
				channelId: idHex
			});
		});
	}

	/**
	 * Is a fresh re-authorization request due for this key?
	 *
	 * No while the channel is still holding messages, because the request that
	 * is parked IS the outstanding one. Yes once it is not, subject to the
	 * spacing: the previous request ended, and if it had been granted the
	 * obligation would no longer be asking.
	 */
	private mayAskForReauthorization(key: string, channelIdHex: string): boolean {
		if (this.channelManager.channelsAwaitingDurability().has(channelIdHex)) {
			return false;
		}
		const last = this.reauthAttempts.get(key);
		if (last === undefined) return true;
		return Date.now() - last >= LightningNode.REAUTH_RETRY_MS;
	}

	/**
	 * Re-ask for every fully signed splice that has not confirmed.
	 *
	 * Startup asks once, and a refusal there would otherwise strand the splice
	 * until the next restart. A splice creates a funding output, so its
	 * rebroadcast is an obligation on exactly the same footing as a v1
	 * funding one and gets the same block-driven retry.
	 */
	private retryPendingSpliceBroadcasts(): void {
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			const inflight = state.spliceInFlight;
			if (!inflight?.fullySigned) continue;
			const id = state.channelId ?? state.temporaryChannelId;
			if (!id) continue;
			const idHex = id.toString('hex');
			// Splice inputs are pledged by the same wallet bookkeeping and the
			// splice tx is retained on the same terms, so its reservation needs
			// the same renewal as a funding one.
			this.renewTransactionPledges(inflight.spliceTxHex);
			// Already authorized in this process: rebroadcast without minting
			// another frame. The barrier has answered for this splice.
			if (this.authorizedSpliceBroadcasts.has(idHex)) {
				this.rebroadcastAuthorizedSplice(idHex, inflight.spliceTxHex);
				continue;
			}
			if (!this.mayAskForReauthorization(idHex, idHex)) continue;
			this.reauthAttempts.set(idHex, Date.now());
			if (!this.channelManager.reauthorizeSpliceBroadcast(id)) {
				this.reauthAttempts.delete(idHex);
			}
		}
	}

	/**
	 * Broadcast the pending funding tx with this txid (internal byte order
	 * hex). The entry is NOT removed on success: it lives until the funding
	 * confirms, so a later mempool eviction can be answered by rebroadcast
	 * (re-sending a tx already in the mempool is accepted and idempotent).
	 * On failure the entry survives for the per-block retry; the error is
	 * surfaced but the obligation stands.
	 */
	private broadcastPendingFundingTx(txidHex: string): void {
		const entry = this.pendingFundingTxs.get(txidHex);
		if (!entry || !this.fundingProvider) return;
		// Covers all three routes that reach here: the funding:authorized emit,
		// the per-block sweep and the startup sweep.
		if (!this.owesFundingBroadcast(txidHex)) return;
		const txHex = entry.txHex;
		// Covers all three routes that reach here: the watch:funding emit, the
		// per-block sweep and the startup sweep.
		if (!this.owesFundingBroadcast(txidHex)) return;
		this.fundingProvider
			.broadcastTransaction(txHex)
			.then(() => {
				// The parent exists on the network now: closes built on top of
				// it stop being fiction (issue #413). Entry mutation is safe
				// even if the entry was retired meanwhile.
				entry.broadcastSucceeded = true;
				this.resumeSkippedCloseAfterBroadcast(txidHex);
			})
			.catch((err) => {
				const message = (err as Error)?.message ?? String(err);
				// A tx that is already mined cannot be re-sent; that is success,
				// and funding:confirmed will retire the entry.
				if (
					/already in block ?chain|already known|txn-already/i.test(message)
				) {
					entry.broadcastSucceeded = true;
					this.resumeSkippedCloseAfterBroadcast(txidHex);
					return;
				}
				this.emitStructuredLog('chain', 'funding_broadcast_failed', {
					txid: txidHex,
					error: message
				});
				this.emit('node:error', {
					code: 'FUNDING_BROADCAST_FAILED',
					message: `${message} (funding tx ${txidHex} retained; will retry)`,
					timestamp: Date.now()
				} as ILightningError);
			});
	}

	/**
	 * Keep the wallet coins a retained transaction spends reserved for it.
	 *
	 * The pledge taken when the inputs were selected is released on a timeout,
	 * and again the moment the wallet stops listing the coin, while the
	 * obligation to broadcast runs until the transaction CONFIRMS. A broadcast
	 * still failing after the pledge times out, or an eviction that hands the
	 * inputs back unspent and unfrozen, puts them back in front of the next
	 * coin selection (or an ordinary wallet send, which only respects the
	 * freeze list). Whichever spends them first, the transaction we still owe
	 * the network can never confirm again and the channel is voided: the
	 * orphaned-channel outcome pledges exist to prevent, reached through the
	 * seam between the two lifetimes.
	 *
	 * Renewed on the same cadence as the broadcast retry, so the reservation
	 * lasts exactly as long as the obligation. Best effort and never awaited:
	 * a provider failure must not break block processing, and the next block
	 * renews again.
	 */
	private renewTransactionPledges(txHex: string): void {
		const provider = this.fundingProvider;
		if (!provider?.pledgeTransactionInputs) return;
		provider.pledgeTransactionInputs(txHex).catch((err) => {
			this.emitStructuredLog('chain', 'input_pledge_renewal_failed', {
				error: (err as Error)?.message ?? String(err)
			});
		});
	}

	/**
	 * A close skipped because its funding parent was nowhere (issue #413)
	 * resumes the moment the backend accepts the parent: a commitment on top
	 * of the mempool parent is a legitimate exit, and waiting for depth would
	 * leave an errored channel unresolved for no reason. handleChannelErrored
	 * re-checks every guard, so this is idempotent and a no-op for channels
	 * that are not ERRORED.
	 */
	private resumeSkippedCloseAfterBroadcast(txidHex: string): void {
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (state.fundingTxid?.toString('hex') !== txidHex) continue;
			if (state.state === ChannelState.ERRORED && state.fundingVersion !== 2) {
				this.handleChannelErrored(
					state.channelId ?? state.temporaryChannelId,
					'funding broadcast accepted for failed channel'
				);
			}
			return;
		}
	}

	/**
	 * Best-effort release of the wallet pledges behind a retained funding
	 * tx (issue #412). Never awaited: the provider ignores outpoints it no
	 * longer holds, and the pledge TTL remains the backstop.
	 */
	private releaseFundingTxPledges(txHex: string): void {
		const provider = this.fundingProvider;
		if (!provider?.releaseInputPledges) return;
		const outpoints = txInputOutpoints(txHex);
		if (outpoints.length === 0) return;
		void provider.releaseInputPledges(outpoints).catch(() => undefined);
	}

	/**
	 * Retry every pending funding broadcast whose channel is still alive and
	 * unconfirmed, and retire entries whose channel is gone (aborted, closed
	 * or voided before confirmation): broadcasting a funding tx for a dead
	 * channel would lock coins in a 2-of-2 nobody will use. Runs on every new
	 * block and once at startup after channels are restored.
	 */
	private retryPendingFundingBroadcasts(): void {
		// Self-heal the runtime index first. A disconnect purges a channel's
		// barrier-held batch, and for a v2 open that suffix can be the
		// TX_SIGNATURES release plus the funding broadcast: the fully signed
		// transaction is already durable on the row (staged at
		// tx_signatures), but the action that would have registered the
		// runtime obligation never ran, so without this pass the per-block
		// retry has nothing to retry until a restart rebuilds the index.
		// Adopted entries land as 'restored', so they re-ask for a fresh
		// authorization exactly as a restart would; under a quorum barrier
		// nothing goes out that the barrier has not released.
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (!state.fundingTxid || !state.pendingFundingTxHex) continue;
			const txidHex = state.fundingTxid.toString('hex');
			if (this.pendingFundingTxs.has(txidHex)) continue;
			this.emitStructuredLog('chain', 'pending_funding_readopted', {
				channelId: state.channelId?.toString('hex') ?? null,
				txid: txidHex
			});
			this.adoptPendingFundingFromChannel(state, txidHex);
		}
		if (this.pendingFundingTxs.size === 0) return;
		const deadStates = new Set([
			ChannelState.CLOSED,
			ChannelState.FORCE_CLOSED,
			ChannelState.ERRORED
		]);
		const liveByTxid = new Map<string, ChannelState>();
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (state.fundingTxid) {
				liveByTxid.set(state.fundingTxid.toString('hex'), state.state);
			}
		}
		for (const [txidHex, entry] of [...this.pendingFundingTxs]) {
			const channelState = liveByTxid.get(txidHex);
			// A dead channel STATE does not end the broadcast obligation:
			// BOLT 2 starts it at funding_signed, and only a confirmation
			// (funding:confirmed retires the entry) or a void
			// (voidMissingFundingChannel deletes it) ends it. The close that
			// resolved the channel may itself be a child of this very
			// transaction, so an 'authorized' parent keeps rebroadcasting
			// through ERRORED/FORCE_CLOSED/CLOSED (issue #413), and a parked
			// candidate or restored entry whose funding_signed has landed
			// keeps waiting for its authorization (issue #412). Only an entry
			// whose channel is GONE, or whose obligation provably never began
			// (awaitingFundingAuthorization answers from the row: without the
			// remote commitment signature no authorization could ever have
			// cleared its persist gate, in this process or a previous one),
			// retires here.
			const owed =
				entry.phase === 'authorized' ||
				this.awaitingFundingAuthorization(txidHex);
			if (
				channelState === undefined ||
				(deadStates.has(channelState) && !owed)
			) {
				this.emitStructuredLog('chain', 'pending_funding_retired', {
					txid: txidHex,
					reason: channelState === undefined ? 'no channel' : channelState
				});
				// A never-owed entry retired against its LIVE row proves the
				// broadcast was never authorized in any process (the persist
				// carrying the remote signature gates the authorization), so
				// its wallet input pledges free with it (issue #412). With
				// the channel gone only a 'candidate' carries that proof
				// (signed in this process, never authorized); a channel-less
				// 'restored' or 'authorized' entry keeps its pledges, with
				// the provider TTL as the backstop.
				if (channelState !== undefined || entry.phase === 'candidate') {
					this.releaseFundingTxPledges(entry.txHex);
				}
				this.deletePendingFundingTx(txidHex);
				continue;
			}
			// Whatever the authorization says: the coins are committed to this
			// transaction from the moment it was built, and an entry still waiting
			// on a fresh authorization is one whose broadcast has not happened yet.
			this.renewTransactionPledges(entry.txHex);
			this.broadcastPendingFundingTx(txidHex);
		}
	}

	/**
	 * Rebuild the runtime index from RESTORED CHANNEL STATE.
	 *
	 * This is the half that survives a guardian restore. The node's generic
	 * metadata is local and best effort, and a device restored from frames
	 * alone has none of it; the channel row does carry the transaction, because
	 * it rides the same frame as the obligation. Entries land as 'restored', so
	 * they still have to ask for a fresh authorization before anything is sent.
	 */
	private restorePendingFundingFromChannels(): void {
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (!state.fundingTxid || !state.pendingFundingTxHex) continue;
			const txidHex = state.fundingTxid.toString('hex');
			// The journal copy WINS, unconditionally. It rode the same frame as
			// the obligation and is authenticated; the metadata map is local and
			// best effort, so letting a stale or corrupt entry sit in front of
			// it would hand a fresh authorization to unrelated bytes.
			this.adoptPendingFundingFromChannel(state, txidHex);
		}
	}

	/**
	 * Validate a row's staged funding payload and adopt it into the runtime
	 * index as 'restored' (authorization unknown, re-asked before any send).
	 */
	private adoptPendingFundingFromChannel(
		state: IChannelState,
		txidHex: string
	): void {
		let parsed: bitcoin.Transaction;
		try {
			parsed = bitcoin.Transaction.fromHex(state.pendingFundingTxHex!);
		} catch {
			this.emitStructuredLog('chain', 'pending_funding_unparseable', {
				channelId: state.channelId?.toString('hex') ?? null,
				txid: txidHex
			});
			return;
		}
		// And it has to BE the transaction this channel names. A payload
		// that hashes to something else is corruption, not an obligation:
		// broadcasting it would put an unrelated transaction on the network
		// under a channel's authorization.
		if (parsed.getHash().toString('hex') !== txidHex) {
			this.emitStructuredLog('chain', 'pending_funding_txid_mismatch', {
				channelId: state.channelId?.toString('hex') ?? null,
				expected: txidHex,
				actual: parsed.getHash().toString('hex')
			});
			this.pendingFundingTxs.delete(txidHex);
			return;
		}
		this.pendingFundingTxs.set(txidHex, {
			txHex: state.pendingFundingTxHex!,
			phase: 'restored'
		});
	}

	/** Restore the persisted pending funding tx map (called at startup). */
	private restorePendingFundingTxs(): void {
		if (!this.storage) return;
		const json = this.storage.loadMetadata(
			LightningNode.PENDING_FUNDING_TXS_KEY
		);
		if (!json) return;
		try {
			const entries = JSON.parse(json) as Array<{
				txid: string;
				txHex: string;
			}>;
			for (const entry of entries) {
				if (entry?.txid && entry?.txHex) {
					// 'restored': the authorization is unknown until it is
					// resolved against the channel, because nothing re-runs
					// handleFundingSigned across a restart.
					this.pendingFundingTxs.set(entry.txid, {
						txHex: entry.txHex,
						phase: 'restored'
					});
				}
			}
		} catch {
			/* ignore corrupted pending-funding metadata */
		}
	}

	// ─────────────── Node Info ───────────────

	getNodeId(): string {
		return this.nodeId;
	}

	/**
	 * Sign a message with the node identity key (LND-compatible: double-SHA256
	 * of 'Lightning Signed Message:' + message, compact recoverable ECDSA,
	 * zbase32). Verifiable with `lncli verifymessage`.
	 */
	signMessage(message: string): string {
		return signMessageWithKey(message, this.nodePrivkey);
	}

	/**
	 * Verify an LND-style message signature. Recovery success alone does not
	 * authenticate: the recovered pubkey must match the expected signer.
	 * `knownNode` reports whether the recovered key is in our network graph
	 * (LND's verifymessage validity criterion).
	 */
	verifyMessage(
		message: string,
		signature: string
	): { valid: boolean; pubkey: string | null; knownNode: boolean } {
		const result = verifyMessageSignature(message, signature);
		if (!result.valid || !result.pubkey) {
			return { valid: false, pubkey: null, knownNode: false };
		}
		const knownNode = this.graph.getNode(result.pubkey) !== undefined;
		return {
			valid: true,
			pubkey: result.pubkey.toString('hex'),
			knownNode
		};
	}

	getNodeInfo(): INodeInfo {
		const channels = this.channelManager.listChannels();
		return {
			nodeId: this.nodeId,
			network: this.network,
			channelCount: channels.length,
			openChannelCount: channels.filter((ch) => {
				const s = ch.getState();
				return (
					s !== ChannelState.CLOSED &&
					s !== ChannelState.FORCE_CLOSED &&
					s !== ChannelState.ERRORED
				);
			}).length,
			peerCount: this.peerManager ? this.peerManager.listPeers().length : 0,
			networkingEnabled: this.peerManager !== null,
			alias: this.alias
		};
	}

	/**
	 * Collect the per-channel data for a static channel backup. Includes every
	 * channel that has an on-chain funding outpoint and is not fully
	 * closed/resolved: recovery via the fell-behind DLP path needs the peer to
	 * still hold a live (or force-closable) commitment, so pre-funding channels
	 * have nothing on chain to recover and CLOSED channels have already
	 * resolved. Buffers are hex-encoded; the funding txid stays in INTERNAL
	 * byte order exactly as stored in channel state.
	 */
	buildStaticChannelBackupData(): {
		network: string;
		channels: IScbChannelEntry[];
	} {
		// One persisted address per peer (upserted on connect); map to 'host:port'.
		const peerAddresses = new Map<string, string[]>();
		if (this.storage) {
			for (const addr of this.storage.loadAllPeerAddresses()) {
				const list = peerAddresses.get(addr.pubkey) ?? [];
				list.push(`${addr.host}:${addr.port}`);
				peerAddresses.set(addr.pubkey, list);
			}
		}

		const channels: IScbChannelEntry[] = [];
		const seen = new Set<string>();
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (!state.fundingTxid || !state.channelId) continue;
			if (state.state === ChannelState.CLOSED) continue;
			const idHex = state.channelId.toString('hex');
			if (seen.has(idHex)) continue;
			const peer = this.channelManager.getPeerForChannel(state.channelId);
			if (!peer) continue;
			seen.add(idHex);
			channels.push({
				channelId: idHex,
				peerNodeId: peer,
				peerAddresses: peerAddresses.get(peer) ?? [],
				fundingTxid: state.fundingTxid.toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex,
				fundingSatoshis: state.fundingSatoshis.toString(),
				channelKeyIndex: channel.channelKeyIndex,
				channelType: state.channelType ? state.channelType.toString('hex') : '',
				role: state.role === ChannelRole.OPENER ? 'OPENER' : 'ACCEPTOR',
				isTaproot: isTaprootChannel(state.channelType),
				isAnchor: isAnchorChannel(state.channelType),
				// Liquidity ads: a lessor's to_remote is the lease-locked variant;
				// recovery needs these to find and sweep it. Omitted when unset so
				// non-lease backups stay byte-identical.
				...(state.leaseExpiry !== undefined
					? { leaseExpiry: state.leaseExpiry }
					: {}),
				...(state.isLessor !== undefined ? { isLessor: state.isLessor } : {}),
				...(state.leaseCommitBlockheight !== undefined
					? { leaseCommitBlockheight: state.leaseCommitBlockheight }
					: {})
			});
		}
		return { network: this.network, channels };
	}

	/**
	 * Recover channels from static-channel-backup entries.
	 *
	 * For each entry not already known to the channel manager this reconstructs
	 * a minimal recovery state (correct local keys via channelKeyIndex, NO
	 * remote basepoints, commitment numbers zeroed), marks it ERRORED with
	 * dataLossDetected so nothing local can ever be broadcast, registers and
	 * persists it, arms the funding-outpoint watch, and (best effort) contacts
	 * the peer. Recovery is passive from there: reconnecting prompts the honest
	 * peer to force-close (our reestablish state is provably stale), the funding
	 * spend is classified THEIR_FUTURE_COMMITMENT, and the chain monitor sweeps
	 * ONLY our to_remote output to the sweep destination.
	 */
	async recoverFromStaticChannelBackup(entries: IScbChannelEntry[]): Promise<{
		recovering: string[];
		skipped: Array<{ channelId: string; reason: string }>;
	}> {
		const recovering: string[] = [];
		const skipped: Array<{ channelId: string; reason: string }> = [];

		for (const entry of entries) {
			// Every field this reconstruction relies on is validated HERE, at
			// the boundary: an entry that reaches the reconstruction malformed
			// either installs an unsweepable channel or throws out of this
			// loop, taking the entries behind it with it.
			const invalid = validateScbEntry(entry);
			if (invalid) {
				skipped.push({
					channelId:
						typeof (entry as { channelId?: unknown })?.channelId === 'string'
							? entry.channelId
							: '',
					reason: invalid
				});
				continue;
			}
			const channelId = Buffer.from(entry.channelId, 'hex');
			if (this.channelManager.getChannel(channelId)) {
				skipped.push({
					channelId: entry.channelId,
					reason: 'channel already exists'
				});
				continue;
			}

			// Key derivation and channel construction happen behind a per-entry
			// boundary. Structural validation cannot promise that a configured
			// channelKeyDeriver (the caller's own callback) will not throw, and
			// a throw here must cost THIS channel only, never the entries
			// queued behind it.
			let state: IChannelState;
			let channel: Channel;
			let perChannelKeys: IPerChannelKeys | null;
			try {
				const built = this.buildRecoveryChannelState(entry, channelId);
				state = built.state;
				perChannelKeys = built.perChannelKeys;
				channel = new Channel(state);
				channel.channelKeyIndex = entry.channelKeyIndex;
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				skipped.push({
					channelId: entry.channelId,
					reason: `failed to derive recovery channel keys: ${message}`
				});
				continue;
			}

			// The disposition is useless without an address to dial after a
			// restart, and the backup's addresses were known-good persisted
			// peer addresses when the SCB was written, so restore the first
			// valid one to the same store. BEFORE the channel, as a HARD
			// prerequisite: an orphan address is harmless if channel
			// persistence fails below, but a recovery-close channel installed
			// without its dial candidate strands the close request after a
			// restart, so a failed address write SKIPS this channel entirely
			// (recovery is re-runnable; retry the SCB once storage recovers).
			// contactRecoveryPeer below is only the best-effort immediate
			// attempt and persists nothing itself.
			const peerAddresses = Array.isArray(entry.peerAddresses)
				? entry.peerAddresses
				: [];
			const dialCandidate = this.firstDialableRecoveryAddress(peerAddresses);
			if (dialCandidate && this.storage) {
				try {
					this.storage.savePeerAddress(
						entry.peerNodeId,
						dialCandidate.host,
						dialCandidate.port
					);
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					skipped.push({
						channelId: entry.channelId,
						reason: `failed to persist recovery peer address: ${message}`
					});
					this.emit('node:error', {
						code: 'PERSISTENCE_ERROR',
						message: `saveRecoveryPeerAddress: ${message}`,
						timestamp: Date.now()
					} as ILightningError);
					continue;
				}
			}

			// Durability BEFORE visibility: committing the recovered state
			// first means a failed commit installs nothing (the address above
			// is the only, harmless, orphan) instead of an undurable
			// in-memory channel reported as recovering, which a retry would
			// then skip as already existing until a restart cleared it.
			if (
				!this.persistRecoveredChannel(
					channel,
					entry.peerNodeId,
					entry.channelKeyIndex
				)
			) {
				skipped.push({
					channelId: entry.channelId,
					reason: 'failed to persist recovered channel'
				});
				continue;
			}
			try {
				// The SAME derivation that produced the state's basepoints
				// also arms the signer: one evaluation of the caller's
				// deriver per recovered channel, never two that could differ.
				this.channelManager.restoreChannel(
					channel,
					entry.peerNodeId,
					entry.channelKeyIndex,
					perChannelKeys
				);
			} catch (err) {
				// The state is already durable, so a restart or a retry picks
				// this channel up; what must not happen is the registration
				// failure taking the remaining entries down with it.
				const message = err instanceof Error ? err.message : String(err);
				skipped.push({
					channelId: entry.channelId,
					reason: `failed to register recovered channel: ${message}`
				});
				continue;
			}
			recovering.push(entry.channelId);

			this.emitStructuredLog('channel', 'recovery_started', {
				channelId: entry.channelId,
				peerNodeId: entry.peerNodeId,
				fundingTxid: entry.fundingTxid,
				fundingOutputIndex: entry.fundingOutputIndex,
				channelKeyIndex: entry.channelKeyIndex
			});

			// Watch the funding outpoint so the peer's force-close is detected and
			// swept. A watch failure is loud but does not abort the recovery of
			// the remaining channels; restoreChainWatches re-arms it on restart.
			if (this.chainWatcher) {
				try {
					await this.watchRecoveredFundingOutput(channelId, state);
				} catch (err) {
					this.emit('node:error', {
						code: 'RECOVERY_WATCH_FAILED',
						channelId,
						message: `Failed to watch recovered funding output: ${
							(err as Error).message
						}`,
						timestamp: Date.now()
					} as ILightningError);
				}
			}

			// Best-effort peer contact: reconnecting lets the peer's reestablish
			// hit our provably-stale state, prompting it to error and force-close.
			// Failures are non-fatal - recovery only needs the funding spend to
			// appear on chain eventually.
			if (this.peerManager && peerAddresses.length > 0) {
				void this.contactRecoveryPeer(entry.peerNodeId, peerAddresses);
			}
		}

		return { recovering, skipped };
	}

	/**
	 * Rebuild one backup entry's channel state: local key material for the
	 * recorded index (or the node-level basepoints for a legacy null-index
	 * channel), the funding outpoint, the channel type that decides which
	 * to_remote variant the sweep looks for, and the broadcast-banned
	 * recovery disposition.
	 *
	 * Using the SAME derivation as the original open is what makes the peer's
	 * DLP proof verifiable and the to_remote output ours to claim. Throws are
	 * the caller's to isolate: they belong to this entry alone. The derived
	 * key material is returned alongside the state so registration can reuse
	 * it instead of asking the deriver a second time.
	 */
	private buildRecoveryChannelState(
		entry: IScbChannelEntry,
		channelId: Buffer
	): { state: IChannelState; perChannelKeys: IPerChannelKeys | null } {
		const material = this.channelManager.getRecoveryChannelMaterial(
			entry.channelKeyIndex
		);
		const stateParams = {
			temporaryChannelId: Buffer.from(channelId),
			fundingSatoshis: BigInt(entry.fundingSatoshis),
			pushMsat: 0n,
			localConfig: material.localConfig,
			localBasepoints: material.basepoints,
			localPerCommitmentSeed: material.perCommitmentSeed
		};
		const state =
			entry.role === 'ACCEPTOR'
				? createAcceptorState({
						...stateParams,
						// Placeholder only - nulled right below. The peer's basepoints
						// are not in the backup; classification and to_remote resolution
						// intentionally work without them (see classifyCommitmentTx).
						remoteBasepoints: material.basepoints,
						remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
				  })
				: createOpenerState(stateParams);
		state.remoteBasepoints = null;
		state.channelId = channelId;
		state.fundingTxid = Buffer.from(entry.fundingTxid, 'hex');
		state.fundingOutputIndex = entry.fundingOutputIndex;
		state.channelType = entry.channelType
			? Buffer.from(entry.channelType, 'hex')
			: null;
		// Liquidity ads: restore the lease fields so the DLP classifier builds
		// the lease-locked to_remote variant and the sweep sets its nLockTime.
		state.leaseExpiry = entry.leaseExpiry;
		state.isLessor = entry.isLessor;
		state.leaseCommitBlockheight = entry.leaseCommitBlockheight;
		state.localCommitmentNumber = 0n;
		state.remoteCommitmentNumber = 0n;
		// Balances are unknown after data loss; the sweep takes its amount from
		// the on-chain to_remote output, so never report a fabricated balance.
		state.localBalanceMsat = 0n;
		state.remoteBalanceMsat = 0n;
		state.announceChannel = false;
		// We KNOW we have no usable commitment state: refuse every local
		// broadcast (forceClose refuses, scanStuckChannels skips) and wait for
		// the peer's force-close on-chain.
		state.state = ChannelState.ERRORED;
		state.dataLossDetected = true;
		// The durable peer-close disposition (recovery 5.6): if the immediate
		// connection attempt fails or the process restarts, startup dialing
		// selects this channel and reconnect regenerates the close request.
		state.recoveryCloseReason = 'local-data-loss';
		return { state, perChannelKeys: material.perChannelKeys };
	}

	/**
	 * First backup address entry that parses to a dialable (host, port).
	 * `parseScbAddress` is THE parser for the format, shared with entry
	 * validation and the dial loop below so none of them can drift.
	 */
	private firstDialableRecoveryAddress(
		addresses: string[]
	): { host: string; port: number } | null {
		for (const address of addresses) {
			const parsed = parseScbAddress(address);
			if (parsed) return parsed;
		}
		return null;
	}

	/** Try each known address for a recovery peer until one connects. */
	private async contactRecoveryPeer(
		peerNodeId: string,
		addresses: string[]
	): Promise<void> {
		for (const address of addresses) {
			const parsed = parseScbAddress(address);
			if (!parsed) continue;
			try {
				await this.connectPeer(peerNodeId, parsed.host, parsed.port);
				return;
			} catch {
				// Try the next address; unreachable peers are expected here.
			}
		}
		this.emitStructuredLog('peer', 'recovery_connect_failed', {
			peerNodeId,
			addresses
		});
	}

	/**
	 * Get a P2WPKH on-chain address derived from the funding public key.
	 * Send sats here to fund channels.
	 */
	/**
	 * The output script that on-chain force-close sweeps pay into: the
	 * configured wallet-owned sweepDestinationScript when set, otherwise
	 * P2WPKH(fundingPubkey) as a fallback. Exposed so callers can confirm where
	 * recovered funds will land.
	 */
	getSweepDestinationScript(): Buffer {
		if (this.sweepDestinationScript) {
			return this.sweepDestinationScript;
		}
		try {
			return bitcoin.payments.p2wpkh({ pubkey: this.fundingPubkey }).output!;
		} catch {
			// fundingPubkey may not be a valid EC point in test scenarios
			return Buffer.alloc(22);
		}
	}

	/** Map the node's Network enum to a bitcoinjs network object. */
	private getBitcoinNetwork(): bitcoin.Network {
		if (this.network === Network.MAINNET) return bitcoin.networks.bitcoin;
		if (this.network === Network.REGTEST) return bitcoin.networks.regtest;
		return bitcoin.networks.testnet;
	}

	/** The BOLT chain_hash for the node's configured network. */
	private chainHash(): Buffer {
		switch (this.network) {
			case Network.MAINNET:
				return BITCOIN_CHAIN_HASH;
			case Network.TESTNET:
				return TESTNET_CHAIN_HASH;
			case Network.SIGNET:
				return SIGNET_CHAIN_HASH;
			default:
				return REGTEST_CHAIN_HASH;
		}
	}

	/** Construct the watchtower client and wire its structured logs. */
	private initWatchtowerClient(towers: string[]): void {
		if (towers.length === 0) {
			this.watchtowerClient = null;
			return;
		}
		const btcNetwork = this.getBitcoinNetwork();
		const store =
			this.storage &&
			typeof (this.storage as IWatchtowerStore).saveWatchtowerSession ===
				'function'
				? (this.storage as unknown as IWatchtowerStore)
				: undefined;
		this.watchtowerClient = new WatchtowerClient({
			localPrivateKey: this.nodePrivkey,
			chainHash: chainHashForNetwork(btcNetwork),
			network: btcNetwork,
			towers,
			store,
			socks5Proxy: this.socks5Proxy ?? undefined
		});
		this.watchtowerClient.on('log', (entry: Record<string, unknown>) => {
			const event = String(entry.event ?? 'log');
			this.emitStructuredLog('watchtower', event, entry);
		});
	}

	/**
	 * Assemble the justice context for a revoked remote commitment and ship it to
	 * the towers. Combines the channel's static params with the per-channel
	 * signing secrets and our sweep destination.
	 */
	private backupRevokedStateToTowers(
		channelId: Buffer,
		perCommitmentSecret: Buffer,
		revokedTx: Buffer
	): void {
		const client = this.watchtowerClient;
		if (!client || !client.enabled) return;
		try {
			const channel = this.channelManager.getChannel(channelId);
			if (!channel) return;
			const state = channel.getFullState();
			if (!state.remoteBasepoints) return;
			const perCh = this.channelManager.getMonitorSigningKeys(channelId);
			const revocationBasepointSecret =
				perCh?.revocationBasepointSecret ?? this.revocationBasepointSecret;
			if (!revocationBasepointSecret) return;
			const paymentBasepointSecret =
				perCh?.paymentBasepointSecret ?? this.paymentBasepointSecret;
			const btcNetwork = this.getBitcoinNetwork();
			const ctx: IJusticeContext = {
				channelId: channelId.toString('hex'),
				revokedTx: bitcoin.Transaction.fromBuffer(revokedTx),
				perCommitmentSecret,
				revocationBasepoint: state.localBasepoints.revocationBasepoint,
				revocationBasepointSecret,
				remoteDelayedBasepoint: state.remoteBasepoints.delayedPaymentBasepoint,
				toSelfDelay: state.localConfig.toSelfDelay,
				isAnchor: isAnchorChannel(state.channelType),
				// Taproot selects the v1 (schnorr) justice kit + taproot blob type.
				isTaproot: isTaprootChannel(state.channelType),
				localPaymentPubkey: state.localBasepoints.paymentBasepoint,
				paymentBasepointSecret,
				sweepScript: this.getSweepDestinationScript(),
				network: btcNetwork,
				// Liquidity ads: lets the kit builder exclude the lease-locked
				// to_remote (lessor) / name the lessee-side blob limitation.
				isLessor: state.isLessor,
				leaseExpiry: state.leaseExpiry,
				leaseCommitBlockheight: state.leaseCommitBlockheight
			};
			client.backupRevokedState(ctx);
		} catch (err) {
			this.emitStructuredLog('watchtower', 'backup_context_failed', {
				channelId: channelId.toString('hex'),
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	/** Add a watchtower at runtime (persists nothing until a session forms). */
	addWatchtower(uri: string): void {
		if (!this.watchtowerClient) {
			this.initWatchtowerClient([uri]);
			const client = this.watchtowerClient as WatchtowerClient | null;
			void client?.start();
			return;
		}
		this.watchtowerClient.addTower(uri);
	}

	/** Remove a watchtower and drop its persisted sessions + backlog. */
	removeWatchtower(uri: string): void {
		this.watchtowerClient?.removeTower(uri);
	}

	/** Per-tower health snapshot for GET /watchtowers. */
	getWatchtowers(): ReturnType<WatchtowerClient['getHealth']> {
		return this.watchtowerClient ? this.watchtowerClient.getHealth() : [];
	}

	/**
	 * Set the wallet-owned sweep destination after construction and propagate it
	 * to the chain watcher and all existing monitors. Lets the caller redirect
	 * force-close sweeps to the wallet once a wallet address becomes available
	 * (e.g. after Electrum connects) — closing the gap where a startup with the
	 * backend down would otherwise leave sweeps targeting the funding key for
	 * the whole session. Only affects sweeps not yet built/broadcast.
	 */
	setSweepDestinationScript(destinationScript: Buffer): void {
		this.sweepDestinationScript = destinationScript;
		this.chainWatcher?.setDestinationScript(destinationScript);
		this.channelManager.setMonitorDestinationScript(destinationScript);
	}

	/**
	 * Recover funds that landed at the funding-key fallback address —
	 * P2WPKH(fundingPubkey) — back into the wallet-owned sweep destination.
	 *
	 * Force-close sweeps built while no wallet address was available pay this
	 * fallback, which the on-chain wallet does not scan, leaving the sats
	 * confirmed but invisible. This spends every UTXO at the fallback script in
	 * one transaction to the configured sweepDestinationScript. Plain P2WPKH
	 * spends of node-owned UTXOs — no channel or commitment output is touched.
	 *
	 * No-ops (returns null) when: no chain backend with UTXO listing, no
	 * wallet-owned destination configured, the destination IS the fallback,
	 * nothing to recover, or the recoverable amount would be dust after fees.
	 *
	 * @returns txid and recovered amount on broadcast, or null when skipped.
	 */
	async recoverFallbackFunds(opts?: {
		feeRatePerVbyte?: number;
	}): Promise<{ txid: string; amountSat: number; inputCount: number } | null> {
		const backend = this._chainBackend as
			| (typeof this._chainBackend & {
					listUnspent?: (scriptHash: string) => Promise<
						Array<{
							txid: string;
							outputIndex: number;
							valueSat: number;
							height: number;
						}>
					>;
			  })
			| null;
		if (!backend || typeof backend.listUnspent !== 'function') return null;
		if (!this.sweepDestinationScript) return null;

		let fallbackScript: Buffer;
		try {
			fallbackScript = bitcoin.payments.p2wpkh({ pubkey: this.fundingPubkey })
				.output!;
		} catch {
			return null; // fundingPubkey not a valid EC point (test scenarios)
		}
		if (this.sweepDestinationScript.equals(fallbackScript)) return null;

		const utxos = await backend.listUnspent(computeScriptHash(fallbackScript));
		if (utxos.length === 0) return null;

		let feeRatePerVbyte = opts?.feeRatePerVbyte ?? 0;
		if (feeRatePerVbyte <= 0 && this.feeEstimator) {
			try {
				feeRatePerVbyte = this.clampEstimatedFeeRate(
					await this.feeEstimator.estimateFee(6)
				);
			} catch {
				/* fall through to default */
			}
		}
		if (feeRatePerVbyte <= 0) feeRatePerVbyte = 10;

		// P2WPKH 1-output spend: ~11 vbytes overhead + 31 per output + 68 per input
		const vbytes = 11 + 31 + 68 * utxos.length;
		const fee = Math.ceil(feeRatePerVbyte * vbytes);
		const total = utxos.reduce((sum, u) => sum + u.valueSat, 0);
		const DUST_LIMIT = 546;
		if (total - fee < DUST_LIMIT) return null;

		const tx = new bitcoin.Transaction();
		tx.version = 2;
		for (const u of utxos) {
			tx.addInput(Buffer.from(u.txid, 'hex').reverse(), u.outputIndex);
		}
		tx.addOutput(this.sweepDestinationScript, total - fee);
		for (let i = 0; i < utxos.length; i++) {
			const sig = signP2wpkhInput(
				tx,
				i,
				this.fundingPubkey,
				utxos[i].valueSat,
				this.fundingPrivkey
			);
			tx.setWitness(i, [sig, this.fundingPubkey]);
		}

		const txid = await backend.broadcastTransaction(tx.toHex());
		this.emitStructuredLog('chain', 'fallback_recovery', {
			txid,
			amountSat: total - fee,
			inputCount: utxos.length,
			feeSat: fee
		});
		return { txid, amountSat: total - fee, inputCount: utxos.length };
	}

	getFundingAddress(): string {
		const networkMap: Record<string, bitcoin.Network> = {
			[Network.MAINNET]: bitcoin.networks.bitcoin,
			[Network.TESTNET]: bitcoin.networks.testnet,
			[Network.REGTEST]: bitcoin.networks.regtest,
			[Network.SIGNET]: bitcoin.networks.testnet
		};
		const btcNetwork = networkMap[this.network] || bitcoin.networks.regtest;
		const { address } = bitcoin.payments.p2wpkh({
			pubkey: this.fundingPubkey,
			network: btcNetwork
		});
		return address!;
	}

	getGraph(): NetworkGraph {
		return this.graph;
	}

	/**
	 * Apply a Rapid Gossip Sync snapshot to the network graph. This populates the
	 * graph for multi-hop pathfinding without crawling p2p gossip. The snapshot's
	 * chain hash must match this node's network (RGS snapshots are mainnet).
	 */
	loadRapidGossipSnapshot(data: Buffer): IRapidGossipResult {
		return applyRapidGossipSnapshot(this.graph, data);
	}

	getChannelManager(): ChannelManager {
		return this.channelManager;
	}

	getPeerManager(): PeerManager | null {
		return this.peerManager;
	}

	// ─────────────── Peer Management ───────────────

	/**
	 * Connect to a peer. When host/port are omitted, the dial address is
	 * resolved from the gossip graph's node_announcement (addresses tried in
	 * announced order; Tor addresses are skipped unless a socks5Proxy is
	 * configured), falling back to DNS bootstrap when the graph has none.
	 *
	 * `transport` is optional and additive: omit it for TCP (unchanged
	 * behavior); pass {type: 'ws'} to dial over WebSocket at ws://host:port,
	 * or {type: 'ws', url} for an explicit ws:// or wss:// URL (host/port may
	 * then be omitted — they are derived from the URL).
	 */
	async connectPeer(
		pubkey: string,
		host?: string,
		port?: number,
		transport?: IPeerTransportOptions
	): Promise<void> {
		if (!this.peerManager) {
			throw new Error('Networking is not enabled');
		}
		this.assertPeerContactPermitted('connectPeer');
		const pubkeyErr = validateHexPubkey(pubkey, 'pubkey');
		if (pubkeyErr) throw new InvalidPeerConnectError(pubkeyErr);
		if (transport?.type === 'ws' && transport.url !== undefined) {
			// Derive the dial address from the explicit URL (and reject a
			// mismatched host/port pair to avoid ambiguous bookkeeping).
			const parsed = parseWebSocketUrl(transport.url);
			if (
				(host !== undefined && host !== parsed.host) ||
				(port !== undefined && port !== parsed.port)
			) {
				throw new InvalidPeerConnectError(
					'host/port conflict with the WebSocket url (omit host/port or make them match)'
				);
			}
			host = parsed.host;
			port = parsed.port;
		}
		if (host === undefined && port === undefined) {
			if (transport?.type === 'ws') {
				throw new InvalidPeerConnectError(
					'WebSocket transport requires host+port or an explicit url'
				);
			}
			await this.connectPeerById(pubkey);
			return;
		}
		if (host === undefined || port === undefined) {
			throw new InvalidPeerConnectError(
				'host and port must be provided together (omit both to resolve from gossip/DNS)'
			);
		}
		const hostErr = validateHost(host);
		if (hostErr) throw new InvalidPeerConnectError(hostErr);
		const portErr = validatePort(port);
		if (portErr) throw new InvalidPeerConnectError(portErr);
		await this.peerManager.connectPeer(pubkey, host, port, transport);
	}

	/**
	 * Connect to a peer by node id alone, resolving its address from the
	 * gossip graph, then DNS bootstrap. Throws an error describing every
	 * address tried (and every Tor address skipped) when nothing connects.
	 */
	private async connectPeerById(pubkey: string): Promise<void> {
		const attempts: string[] = [];
		// ONE cancellation token for the whole node-id operation: a dial
		// rejects typed on its own, but disconnectPeer() can also land in
		// the gaps BETWEEN dials (most importantly while the async DNS
		// bootstrap is pending, when no dial exists to reject), and the
		// next candidate would otherwise start fresh under the bumped
		// generation and reverse the explicit disconnect.
		const cancellationToken = this.peerManager!.cancellationToken(pubkey);
		const assertNotCancelled = (): void => {
			if (this.peerManager!.cancellationToken(pubkey) !== cancellationToken) {
				throw new PeerDialCancelledError(pubkey);
			}
		};
		const isTor = (a: INodeAddress): boolean =>
			a.type === ADDRESS_TYPE_TORV2 || a.type === ADDRESS_TYPE_TORV3;

		// 1. Gossip graph: node_announcement addresses in announced order. Only
		// a signature-verified announcement may supply dial targets; a
		// deferred one is resolved by this read (issue #443).
		const announced =
			this.graph.getVerifiedNodeAnnouncement(Buffer.from(pubkey, 'hex'))
				?.addresses ?? [];
		let skippedTor = 0;
		const candidates: Array<{ host: string; port: number }> = [];
		for (const addr of announced) {
			if (isTor(addr) && !this.socks5Proxy) {
				skippedTor++;
				continue;
			}
			const dialable = nodeAddressToHostPort(addr);
			if (dialable) candidates.push(dialable);
		}
		for (const { host, port } of candidates) {
			assertNotCancelled();
			try {
				await this.peerManager!.connectPeer(pubkey, host, port);
				return;
			} catch (err) {
				// An explicit disconnectPeer() cancelled the whole node-id
				// operation, not one address: retrying the next candidate
				// would reconnect the very peer the caller just removed.
				if (err instanceof PeerDialCancelledError) throw err;
				attempts.push(
					`graph ${host}:${port} (${
						err instanceof Error ? err.message : String(err)
					})`
				);
			}
		}
		if (skippedTor > 0) {
			attempts.push(
				`skipped ${skippedTor} Tor address(es): no socks5Proxy configured`
			);
		}

		// 2. DNS bootstrap fallback when the graph produced nothing dialable.
		if (candidates.length === 0) {
			let seedPeers: IPeerAddress[] = [];
			try {
				seedPeers = await this.bootstrapPeers();
			} catch (err) {
				attempts.push(
					`DNS bootstrap failed (${
						err instanceof Error ? err.message : String(err)
					})`
				);
			}
			const matches = seedPeers.filter(
				(p) => p.pubkey.toString('hex') === pubkey
			);
			if (matches.length === 0) {
				attempts.push('DNS bootstrap returned no address for this node id');
			}
			for (const peer of matches) {
				// The DNS bootstrap awaited above is exactly the window where
				// a cancellation has no dial to reject: check the token
				// before the FIRST dns dial too.
				assertNotCancelled();
				try {
					await this.peerManager!.connectPeer(pubkey, peer.host, peer.port);
					return;
				} catch (err) {
					// See the graph loop: cancellation stops the operation.
					if (err instanceof PeerDialCancelledError) throw err;
					attempts.push(
						`dns ${peer.host}:${peer.port} (${
							err instanceof Error ? err.message : String(err)
						})`
					);
				}
			}
		}

		throw new Error(
			`Unable to resolve a connection to ${pubkey}: ${attempts.join('; ')}`
		);
	}

	disconnectPeer(pubkey: string): void {
		if (!this.peerManager) {
			throw new Error('Networking is not enabled');
		}
		this.peerManager.disconnectPeer(pubkey);
	}

	listPeers(): IPeerInfo[] {
		if (!this.peerManager) return [];
		return this.peerManager.listPeers();
	}

	isNetworkingEnabled(): boolean {
		return this.peerManager !== null;
	}

	/**
	 * Start listening for inbound peer connections.
	 */
	async listen(port: number, host?: string): Promise<void> {
		if (!this.peerManager) {
			throw new Error('Networking is not enabled');
		}
		this.assertPeerContactPermitted('listen');
		await this.peerManager.listen(port, host);
	}

	/**
	 * Start listening for inbound peers over WebSocket (opt-in; coexists with
	 * the TCP listener started via listen()).
	 */
	async listenWebSocket(port: number, host?: string): Promise<void> {
		if (!this.peerManager) {
			throw new Error('Networking is not enabled');
		}
		this.assertPeerContactPermitted('listenWebSocket');
		await this.peerManager.listenWebSocket(port, host);
	}

	/**
	 * Stop listening for inbound connections (TCP and WebSocket).
	 */
	stopListening(): void {
		if (this.peerManager) {
			this.peerManager.stopListening();
		}
	}

	/**
	 * Whether the node is listening for inbound connections.
	 */
	isListening(): boolean {
		return this.peerManager?.isListening() ?? false;
	}

	getChainWatcher(): ChainWatcher | null {
		return this.chainWatcher;
	}

	/**
	 * True while the chain startup operation that began in this generation is
	 * still the current one and the node is alive.
	 */
	private isCurrentChainStartup(generation: number): boolean {
		return !this._destroyed && this.chainStartupGeneration === generation;
	}

	private wireChainWatcherEvents(): void {
		if (!this.chainWatcher || this._wiredChainWatcher === this.chainWatcher) {
			return;
		}
		this._wiredChainWatcher = this.chainWatcher;

		this.chainWatcher.on('block', (height: number) => {
			this.currentBlockHeight = height;
			// The internal watcher path does not go through handleNewBlock, so
			// keep the fee advisor warm here too — force-closes and v2 opens
			// both price themselves synchronously off its latest sample.
			this.warmFeeAdvisor();
			// Same reason for the splice close re-drive retry (issue #357):
			// production headers run through the watcher, so a re-drive queued
			// after a transient failure must get its per-block retry here, not
			// only in handleNewBlock.
			this.retrySpliceCloseRedrives();
			// Same reasoning for un-armed output watches (issue #577).
			this.retryPendingOutputWatches();
			// And for the funding broadcast obligation (issue #412): the
			// per-block rebroadcast, the pledge renewals that ride it, and
			// the dead-entry retirement (which releases v1 pledges) must all
			// run on live headers, not only when an embedder drives
			// handleNewBlock itself.
			this.retryPendingFundingBroadcasts();
			// And the BOLT 2 forget clock, for the same reason: its only other
			// driver is a one-shot alarm (issue #463).
			this.reviewFundingMissingClocks(height);
		});
		this.chainWatcher.on('error', (err: Error) => {
			this.emit('node:error', {
				code: 'CHAIN_WATCHER_ERROR',
				message: err.message,
				timestamp: Date.now()
			} as ILightningError);
		});
		// A close tx we registered reached the network: record it so
		// closeStatus.broadcast can answer honestly before the spend is
		// observed. broadcast:failure carries no txid, so failures simply
		// never set ok; absence of success is the default.
		this.chainWatcher.on('broadcast:success', (txid: string) => {
			const idHex = this._pendingCloseTxids.get(txid);
			if (idHex !== undefined) {
				this._lastCloseBroadcast.set(idHex, { txid, ok: true });
			}
		});
		// The watcher owns the broadcast; surface its failures under the code
		// consumers already watch for. It re-queues and retries on the next
		// block, so this is a warning rather than a terminal outcome.
		this.chainWatcher.on('broadcast:failure', (err: Error) => {
			this.emit('node:error', {
				code: 'BROADCAST_FAILED',
				message: err.message,
				timestamp: Date.now()
			} as ILightningError);
		});
		// Wire watch:output:requested — handle sweep output watching after force-close
		this.chainWatcher.on(
			'watch:output:requested',
			(txid: string, outputIndex: number) => {
				this.chainWatcher!.watchOutputByTxid(txid, outputIndex).catch((err) => {
					// Reported AND queued (issue #577): the same commitment fetch
					// that fails here after a reorg would otherwise leave this
					// output permanently unwatched, with only a log line to show
					// for it.
					const channelIdHex = this._channelHexForTrackedOutput(
						txid,
						outputIndex
					);
					if (channelIdHex) {
						this._pendingOutputWatches.set(`${txid}:${outputIndex}`, {
							channelIdHex,
							txid,
							outputIndex
						});
					}
					this.emit('node:error', {
						code: 'WATCH_OUTPUT_FAILED',
						message: `Failed to watch output ${txid}:${outputIndex}: ${
							(err as Error).message
						}`,
						timestamp: Date.now()
					} as ILightningError);
				});
			}
		);

		// Wire announcement depth event — triggers channel announcement signing
		this.chainWatcher.on(
			'announcement:depth',
			(channelId: Buffer, blockHeight: number, txIndex: number) => {
				const localNodeId = getPublicKey(this.nodePrivkey);
				this.channelManager.triggerAnnouncementDepth(
					channelId,
					blockHeight,
					txIndex,
					localNodeId,
					this.makeAnnouncementSigner(channelId)
				);
				// Persist the computed shortChannelId so it survives restarts
				this.persistChannel(channelId);
			}
		);

		// Splice confirmation: when a pending splice transaction reaches the
		// required depth, send splice_locked. Initial-funding confirmation is
		// handled elsewhere; we only act when a splice is in flight.
		// The funding tx of a not-yet-confirmed channel vanished from mempool
		// AND chain (evicted or an input was double-spent). For a zero-conf
		// channel that is already NORMAL, every balance shown against it is
		// fiction: alarm, then VOID the channel. It never existed on the
		// network, so there is nothing to close and the contributed coins
		// remain onchain. 'channel:voided' lets the embedder re-handle them.
		this.chainWatcher.on(
			'funding:missing',
			(channelId: Buffer, txid: string) => {
				this.emitStructuredLog('chain', 'funding_missing', {
					channelId: channelId.toString('hex'),
					txid
				});
				this.emit('node:error', {
					code: 'FUNDING_MISSING',
					channelId,
					message: `funding tx ${txid} disappeared from mempool and chain before confirming`,
					timestamp: Date.now()
				} as ILightningError);
				this.disposeMissingFunding(channelId, txid);
			}
		);

		this.chainWatcher.on(
			'funding:confirmed',
			(channelId: Buffer, txid?: string) => {
				this.onFundingWatchConfirmed(channelId, txid);
			}
		);
		this.chainWatcher.on(
			'funding:presplice-retired',
			(channelId: Buffer, txid: string, outputIndex: number) => {
				this.retirePreSpliceSpendWatch(channelId, txid, outputIndex);
			}
		);
	}

	/**
	 * Act on a funding the chain says is absent: rebroadcast it if we owe the
	 * broadcast, otherwise run BOLT 2's forget clock and, at its end, void the
	 * channel.
	 *
	 * Reached from the watcher's one-shot 'funding:missing' alarm AND from the
	 * per-block review below, because that alarm fires ONCE per continuous
	 * absence: latched on the first report and re-armed only when the
	 * transaction reappears. A disposition driven by the alarm alone therefore
	 * gets exactly one chance, so a clock that could not start (no chain tip
	 * yet) never started, and a clock that did start was never looked at again
	 * and never reached its 2016 blocks (issue #463).
	 */
	private disposeMissingFunding(channelId: Buffer, txid: string): void {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;
		const state = channel.getFullState();
		// A vanished SPLICE tx is different: the pre-splice channel is
		// real and confirmed, and voiding it would destroy a live
		// channel. Alarm only; splice rollback is a separate path.
		if (state.spliceInFlight) return;
		// Nor while a superseded outpoint of this channel is still being
		// watched. The channel's own watch moves to the splice output at the
		// point of no return, and for a ZERO-CONF parent whose funding never
		// confirmed the evidence test below cannot speak for it, so the leg is
		// what says the pre-splice funding is real. It retires only when the
		// splice spend is irrevocable, which is exactly when absence about the
		// new outpoint starts meaning something.
		if (state.preSpliceSpendWatches?.length) return;
		// And a splice that ENDS without confirming is the same channel with
		// that record already cleared (issue #481). Both the abort path and the
		// zero-conf completeSplice null spliceInFlight while the channel's
		// funding watch still points at a splice outpoint that may never exist,
		// after which three absent answers and BOLT 2's 2016 blocks would void
		// a live, funded channel, taking its monitor and its SCB entry with it.
		//
		// So the guard turns on the invariant #463 settled rather than on a
		// local record: a channel whose funding THIS NODE'S OWN WATCHER has
		// seen on chain is never retired by absence. isFundingKnownOnChain is
		// already exactly that evidence, persisted, peer-independent and
		// fail-toward-keeping. What stays voidable is what BOLT 2's forget
		// clock is actually for: a funding that never reached the chain at all.
		if (channel.isFundingKnownOnChain()) {
			this.emitStructuredLog('chain', 'funding_missing_ignored', {
				channelId: channelId.toString('hex'),
				txid,
				reason: 'funding known on chain'
			});
			return;
		}

		const internalHex = Buffer.from(txid, 'hex').reverse().toString('hex');
		const pending = this.pendingFundingTxs.get(internalHex);
		const pendingHex = pending?.txHex;

		// The funder's own obligation comes first: if we hold the
		// transaction and are allowed to send it, absence is answered
		// by sending it rather than by waiting out a clock.
		if (
			pendingHex &&
			this.fundingProvider &&
			this.owesFundingBroadcast(internalHex)
		) {
			this.fundingProvider
				.broadcastTransaction(pendingHex)
				.then(() => {
					this.emitStructuredLog('chain', 'funding_rebroadcast', {
						channelId: channelId.toString('hex'),
						txid
					});
				})
				.catch((err) => {
					// A rejection is NOT evidence that the channel is
					// fiction. bad-txns-inputs-missingorspent covers an
					// unconfirmed parent this backend has not seen, a
					// mempool conflict need not be confirmed, and a
					// timeout says nothing at all. Retain, retry, and
					// leave forgetting to the block clock below, which
					// this side never even starts: a funder that owes
					// the broadcast answers by sending.
					this.emitStructuredLog('chain', 'funding_rebroadcast_rejected', {
						channelId: channelId.toString('hex'),
						txid,
						error: (err as Error)?.message ?? String(err)
					});
				});
			return;
		}

		// We hold the transaction but may not send it yet: ask again.
		if (pendingHex && this.awaitingFundingAuthorization(internalHex)) {
			this.emitStructuredLog('chain', 'funding_missing_unauthorized', {
				channelId: channelId.toString('hex'),
				txid
			});
			this.requestFundingReauthorization(internalHex);
			return;
		}

		// Otherwise this is the fundee, or a funder whose payload is
		// gone. Nothing to send, so the only question is the clock.
		//
		// ABSENCE IS A CLOCK, NOT A VERDICT. This alarm fires after
		// three checks find nothing and does not require that the
		// transaction was ever seen, so it cannot on its own tell an
		// evicted funding from one we are deliberately withholding, one
		// whose funder has not broadcast yet, or a backend with an
		// incomplete view. BOLT 2 gives the answer: a node forgets an
		// unconfirmed funding only after 2016 blocks. Until then the
		// channel is retained, whichever side we are, because
		// forgetting early forces a funder to close and reopen a
		// channel that was never in trouble.
		//
		// The START of that countdown has to reach disk before it
		// counts for anything. Held only in memory it is lost on the
		// next restart, the following absence starts it again at
		// whatever height the node is at by then, and a node that
		// restarts often enough never reaches the disposition at all.
		// A start that cannot be recorded therefore does not begin:
		// failing closed here means RETAINING the channel and asking
		// again on the next absence, never counting down from a height
		// no restart can read back.
		if (channel.beginFundingMissingClock(this.currentBlockHeight)) {
			if (!this.persistChannelCommitted(channelId)) {
				channel.clearFundingMissingClock();
				this.emitStructuredLog('chain', 'funding_missing_clock_unwritten', {
					channelId: channelId.toString('hex'),
					txid
				});
				return;
			}
		}
		// No usable start height: this node has no chain tip yet, or the
		// row carries a stamp written before there was one. A wait
		// cannot be measured against either, and measuring it anyway
		// compares against NaN, which is never less than
		// FUNDING_FORGET_BLOCKS and drops straight into the void. Same
		// answer as an unwritable clock start: retain, and ask again on
		// the next absence (issue #463).
		const missingSince = channel.fundingMissingSince();
		if (missingSince === undefined) {
			this.emitStructuredLog('chain', 'funding_missing_untimed', {
				channelId: channelId.toString('hex'),
				txid,
				blockHeight: this.currentBlockHeight
			});
			return;
		}
		const waited = this.currentBlockHeight - missingSince;

		if (waited < FUNDING_FORGET_BLOCKS) {
			this.emitStructuredLog('chain', 'funding_missing_waiting', {
				channelId: channelId.toString('hex'),
				txid,
				waitedBlocks: waited
			});
			return;
		}
		this.voidMissingFundingChannel(channelId, txid);
	}

	/**
	 * Per-block review of every funding-missing clock, on the chain's answer
	 * rather than on an event that fires once (see disposeMissingFunding).
	 *
	 * A funding the watcher has seen since stops any clock it started: "missing
	 * since" must not survive an observation of presence, or a countdown begun
	 * during one outage is still ticking during the next. A funding the watcher
	 * still reports absent runs the ordinary disposition, which is where the
	 * clock starts and where 2016 blocks later it ends.
	 */
	private reviewFundingMissingClocks(blockHeight: number): void {
		if (!this.chainWatcher || blockHeight <= 0) return;
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (!state.fundingTxid) continue;
			const channelId = state.channelId ?? state.temporaryChannelId;
			const presence = this.chainWatcher.getFundingPresence(channelId);
			if (presence === 'present') {
				if (channel.clearFundingMissingClock()) {
					this.persistChannel(channelId);
					this.emitStructuredLog('chain', 'funding_missing_clock_cleared', {
						channelId: channelId.toString('hex')
					});
				}
				continue;
			}
			if (presence !== 'absent') continue;
			this.disposeMissingFunding(
				channelId,
				Buffer.from(state.fundingTxid).reverse().toString('hex')
			);
		}
	}

	/**
	 * A watched funding output reached confirmation depth. `confirmedTxid` is
	 * the watched txid in display byte order; the splice branch matches it
	 * against the in-flight record rather than trusting channel state alone:
	 * spliceFundingTxid is only stamped on the tx_signatures success path,
	 * while the refusal/wire-failure retention arms and the restart re-arm
	 * watch the record's txid without it, and markErrored kills the session
	 * a live-session gate would demand (issue #357).
	 */
	private onFundingWatchConfirmed(
		channelId: Buffer,
		confirmedTxid?: string
	): void {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;
		const state = channel.getFullState();
		// The funding is mined: the BOLT 2 broadcast obligation is met, so
		// the retained signed tx (kept for eviction rebroadcasts) retires
		// and the forget clock stops. Both are channel state and both are
		// persisted here rather than left for some later transition to
		// carry: a clock left on disk after its funding CONFIRMED keeps
		// counting across the next restart, toward voiding a channel that
		// is on the chain.
		let retired = channel.clearFundingMissingClock();
		if (state.fundingTxid) {
			retired = channel.clearRetainedFundingPayload() || retired;
			this.deletePendingFundingTx(state.fundingTxid.toString('hex'));
		}
		// A v2 open force-closed before confirmation whose SUPERSEDED RBF
		// attempt then won the race: the channel adopted that attempt (and
		// stamped its record confirmed in the same persist), so the broadcast
		// commitment spends a funding output that can never exist. Rebuild
		// and rebroadcast the close against the adopted funding, on the same
		// machinery as the confirmed-splice re-drive (issue #360).
		if (
			channel.getState() === ChannelState.FORCE_CLOSED &&
			state.fundingVersion === 2 &&
			!state.spliceInFlight &&
			state.v2InFlight?.confirmed === true &&
			confirmedTxid !== undefined &&
			Buffer.from(state.v2InFlight.fundingTxid).reverse().toString('hex') ===
				confirmedTxid
		) {
			if (retired) this.persistChannel(channelId);
			void this.redriveSpliceAdoptedClose(channelId);
			return;
		}
		// Issue #413: a v1 channel failed by a BOLT 1 error before its funding
		// confirmed skipped its commitment broadcast. The outpoint exists now
		// (fundingConfirmed just stamped it durably, via the watcher's
		// channelManager.handleFundingConfirmed call): drive the close it
		// owes. handleChannelErrored re-checks every guard, so this is
		// idempotent.
		if (
			channel.getState() === ChannelState.ERRORED &&
			state.fundingVersion === 1 &&
			!state.spliceInFlight
		) {
			if (retired) this.persistChannel(channelId);
			this.handleChannelErrored(
				channelId,
				'funding confirmed for failed channel'
			);
			return;
		}
		const inflight = state.spliceInFlight;
		const spliceConfirmed =
			inflight != null &&
			(confirmedTxid !== undefined
				? Buffer.from(inflight.spliceTxid).reverse().toString('hex') ===
				  confirmedTxid
				: state.spliceFundingTxid != null);
		if (!spliceConfirmed) {
			if (retired) this.persistChannel(channelId);
			return;
		}
		// sendSpliceLocked self-validates the splice state; ignore if not ready.
		if (channel.getSpliceSession()) {
			const result = this.channelManager.sendSpliceLocked(channelId);
			if (result.ok) {
				this.persistChannel(channelId);
				return;
			}
		}
		// The channel could not announce the lock: disconnected
		// (AWAITING_REESTABLISH), force-closed, or the session died with a
		// mid-splice channel failure. Record the confirmation durably: a live
		// channel flushes splice_locked on the next channel_reestablish, and
		// the force-close planner's splice adoption keys off the confirmed
		// record.
		channel.markSpliceConfirmed();
		this.persistChannel(channelId);
		// Issue #357: the confirmed splice spends the old funding outpoint,
		// voiding any old-funding commitment this FORCE_CLOSED channel
		// broadcast. Re-drive the close on the adopted new funding instead
		// of waiting for an operator rebroadcast.
		if (channel.getState() === ChannelState.FORCE_CLOSED) {
			void this.redriveSpliceAdoptedClose(channelId);
		}
	}

	async startChainWatcher(): Promise<void> {
		const generation = ++this.chainStartupGeneration;
		// Bring up the watchtower client alongside on-chain monitoring: restore the
		// persisted backlog and connect to towers (no-op when none configured).
		if (this.watchtowerClient) {
			this.watchtowerClient.start().catch((err) => {
				if (!this.isCurrentChainStartup(generation)) return;
				this.emitStructuredLog('watchtower', 'start_failed', {
					error: err instanceof Error ? err.message : String(err)
				});
			});
		}
		if (this.chainWatcher) {
			this.wireChainWatcherEvents();
			await this.chainWatcher.start();
			if (!this.isCurrentChainStartup(generation)) return;
			// Re-watch funding outputs for all restored channels.
			//
			// Guarded, because everything after it is startup work that is
			// retried nowhere: the pending funding and splice rebroadcast
			// sweeps, and the Electrum reconnect monitor whose onResubscribed
			// hook is what re-scans every watch after a drop. The only caller of
			// startChainWatcher is the constructor's auto-start, which reports
			// and gives up. Individual watches already isolate their own
			// failures; this catches whatever a future one forgets to.
			try {
				await this.restoreChainWatches(generation);
			} catch (err) {
				this.emit('node:error', {
					code: 'CHAIN_RESTORE_WATCH_FAILED',
					message: `Failed to restore chain watches: ${(err as Error).message}`,
					timestamp: Date.now()
				} as ILightningError);
			}
			// destroy() during the restore must not let the rest of startup run:
			// it would retry funding broadcasts and restart the reconnect monitor
			// that destroy() just stopped.
			if (!this.isCurrentChainStartup(generation)) return;
			// Resume the broadcast obligation for signed funding txs that never
			// confirmed (crash between funding_signed and broadcast, or an
			// eviction while we were down). Retries again on every new block.
			// Channels are restored by now, so the payload that rode their
			// frames can seed the runtime index before the sweep asks about it.
			this.restorePendingFundingFromChannels();
			this.retryPendingFundingBroadcasts();
			this.retryPendingSpliceBroadcasts();
			// Start reconnect monitor on ElectrumBackend to resume subscriptions after drops
			if (
				this._chainBackend &&
				typeof (this._chainBackend as ElectrumBackend).startReconnectMonitor ===
					'function'
			) {
				const backend = this._chainBackend as ElectrumBackend;
				// On reconnect/resubscribe, re-scan watched fundings immediately so a
				// confirmation that landed while disconnected is picked up at once
				// (the chain watcher's periodic timer is the slower safety net).
				backend.onResubscribed = (): void => {
					if (!this.isCurrentChainStartup(generation)) return;
					this.chainWatcher?.recheckAllWatches();
				};
				backend.startReconnectMonitor();
			}
		}
	}

	/**
	 * Re-watch funding outputs for all restored channels that need monitoring.
	 * Called after startChainWatcher() to resume chain monitoring for persisted channels.
	 */
	async restoreChainWatches(
		// Defaults to the current generation for direct callers; startChainWatcher
		// passes the one its whole sequence began in.
		generation: number = this.chainStartupGeneration
	): Promise<void> {
		if (!this.chainWatcher || !this.isCurrentChainStartup(generation)) return;

		const networkMap: Record<string, bitcoin.Network> = {
			[Network.MAINNET]: bitcoin.networks.bitcoin,
			[Network.TESTNET]: bitcoin.networks.testnet,
			[Network.REGTEST]: bitcoin.networks.regtest,
			[Network.SIGNET]: bitcoin.networks.testnet
		};
		const btcNetwork = networkMap[this.network] || bitcoin.networks.regtest;

		for (const channel of this.channelManager.listChannels()) {
			// Each iteration does network work, so re-check before starting another.
			if (!this.isCurrentChainStartup(generation)) return;
			const state = channel.getFullState();
			// Only watch channels that have funding info and are not yet closed
			if (!state.fundingTxid || state.fundingOutputIndex === undefined)
				continue;
			const channelIdHex = (
				state.channelId ?? state.temporaryChannelId
			).toString('hex');
			// A cooperative close sets CLOSED at fee/sig agreement, BEFORE the
			// mutual-close tx confirms. Until the close is irrevocably buried a peer
			// could still broadcast a revoked commitment on the still-live funding
			// output, which we must be able to detect and punish. Unconditionally
			// skipping here permanently drops the watch on restart in that window.
			// Only skip once the close is fully resolved on-chain (mirrors the
			// FORCE_CLOSED gate below); otherwise re-arm any per-output watches, then
			// fall through to re-arm the funding watch and rebroadcast the stored
			// mutual close so it re-enters the mempool if the network never saw it.
			if (state.state === ChannelState.CLOSED) {
				const monitor = this.channelManager.getMonitor(
					state.channelId || state.temporaryChannelId
				);
				if (monitor && monitor.isFullyResolved()) continue;
				if (monitor) {
					for (const output of monitor.getTrackedOutputs()) {
						if (output.status === OutputStatus.IRREVOCABLY_RESOLVED) continue;
						const seedTxid =
							output.status === OutputStatus.SPEND_CONFIRMED
								? output.resolutionTxid
								: undefined;
						// Queued on failure rather than swallowed (issue #577).
						await this.armOutputWatch(
							channelIdHex,
							output.txid,
							output.outputIndex,
							seedTxid,
							seedTxid !== undefined ? output.confirmationHeight : undefined
						);
					}
				}
				if (
					state.lastCooperativeCloseTxHex &&
					this._chainBackend &&
					// A direct backend broadcast is not covered by the watcher's own
					// lifecycle gate, so it needs the node's.
					this.isCurrentChainStartup(generation)
				) {
					try {
						const txid = await this._chainBackend.broadcastTransaction(
							state.lastCooperativeCloseTxHex
						);
						this._lastCloseBroadcast.set(
							(state.channelId || state.temporaryChannelId).toString('hex'),
							{ txid, ok: true }
						);
					} catch {
						// Already in mempool/confirmed (or backend hiccup): the funding
						// watch still reports the eventual spend either way.
					}
				}
				// fall through to re-arm the funding watch below
			}
			if (state.state === ChannelState.FORCE_CLOSED) {
				const monitor = this.channelManager.getMonitor(
					state.channelId || state.temporaryChannelId
				);
				// Fully swept: nothing left on-chain to watch.
				if (monitor && monitor.isFullyResolved()) continue;
				// A monitor mid-resolution lost its per-output watches with the
				// process — re-register them so sweep confirmations are detected
				// and the monitor can actually resolve.
				if (monitor) {
					for (const output of monitor.getTrackedOutputs()) {
						if (output.status === OutputStatus.IRREVOCABLY_RESOLVED) continue;
						// Seed a previously recorded spend so a reorg that evicts our
						// penalty / HTLC claim after restart is detected (checkOutputSpend
						// only fires its eviction branch when spendTxid is set). Without
						// this the monitor would promote SPEND_CONFIRMED to irrevocable off
						// the stale height and hide a reorg-then-theft.
						const seedTxid =
							output.status === OutputStatus.SPEND_CONFIRMED
								? output.resolutionTxid
								: undefined;
						// A failure here is queued, not swallowed (issue #577): the
						// commitment fetch fails for as long as a reorg keeps it
						// evicted, and nothing else would ever arm these watches.
						await this.armOutputWatch(
							channelIdHex,
							output.txid,
							output.outputIndex,
							seedTxid,
							seedTxid !== undefined ? output.confirmationHeight : undefined
						);
					}
				}
				// NO persisted monitor (force-closed in a session that ended before
				// the spend was detected): fall through and watch the funding —
				// spend detection lazily creates the monitor from channel state and
				// schedules the sweeps. Skipping here orphans the funds.
			}

			// Build the funding P2WSH script from the channel's pubkeys. An
			// SCB-recovered channel has NO remote basepoints (the backup does not
			// carry the peer's funding pubkey), so the script cannot be rebuilt
			// locally - fetch it from the chain instead so the funding spend is
			// still detected after a restart.
			if (!state.remoteBasepoints) {
				if (state.dataLossDetected && state.fundingTxid) {
					try {
						await this.watchRecoveredFundingOutput(
							state.channelId || state.temporaryChannelId,
							state
						);
					} catch (err) {
						this.emit('node:error', {
							code: 'RECOVERY_WATCH_FAILED',
							channelId: state.channelId || state.temporaryChannelId,
							message: `Failed to watch recovered funding output: ${
								(err as Error).message
							}`,
							timestamp: Date.now()
						} as ILightningError);
					}
				}
				continue;
			}
			// The funding output the chain watcher subscribes to MUST be the real
			// on-chain scriptPubKey. Simple-taproot channels fund a P2TR MuSig2
			// key-spend output, NOT the witness-v0 2-of-2 P2WSH, so subscribing the
			// P2WSH scripthash would never match and a breach or force-close on a
			// taproot channel would go undetected (funds stranded / stolen).
			const fundingScript = isTaprootChannel(state.channelType)
				? createTaprootFundingScript(
						state.localBasepoints.fundingPubkey,
						state.remoteBasepoints.fundingPubkey,
						btcNetwork
				  ).p2trOutput
				: createFundingScript(
						state.localBasepoints.fundingPubkey,
						state.remoteBasepoints.fundingPubkey,
						btcNetwork
				  ).p2wshOutput;

			// A row written before preSpliceSpendWatches existed that was
			// mid-splice when the node upgraded carries the leg nowhere but
			// spliceInFlight, and completeSplice clears THAT at splice_locked,
			// which on a zero-conf channel precedes the splice confirming. So
			// derive the record now, from the channel's own derivation, and put
			// it on disk BEFORE the watch is armed: the next restart must find
			// a record rather than a gap, however this one ends (issue #479).
			if (state.spliceInFlight && channel.recordInFlightPreSpliceSpendWatch()) {
				try {
					this.persistChannel(state.channelId || state.temporaryChannelId);
				} catch (err) {
					// The record is in memory either way, so the watch below is
					// still armed for this session and the derivation re-runs
					// idempotently next restart. Nothing in this loop may throw:
					// what follows it in startChainWatcher is the pending
					// broadcast retries and the reconnect monitor, and neither
					// is retried anywhere.
					this.emit('node:error', {
						code: 'PRESPLICE_WATCH_FAILED',
						channelId: state.channelId || state.temporaryChannelId,
						message: `Failed to persist the derived pre-splice spend watch: ${
							(err as Error).message
						}`,
						timestamp: Date.now()
					} as ILightningError);
				}
			}

			// Superseded funding outpoints whose expected splice spend is not yet
			// irrevocable. Re-armed for EVERY channel, not just one with a live
			// spliceInFlight: completeSplice clears that record at
			// splice_locked, which on a zero-conf channel precedes the splice
			// transaction confirming, so this list is the only thing that can
			// bring the watch back (issue #479).
			await this.armPreSpliceSpendWatches(
				state.channelId || state.temporaryChannelId,
				state
			);

			const inflight = state.spliceInFlight;
			// ONLY past the point of no return. The shared input is the 2-of-2
			// funding, so until OUR tx_signatures have left nobody can broadcast
			// that splice: the outpoint it would create does not exist, and the
			// live funding is still the old one. Moving the watch there anyway
			// left the old output covered by nothing at all - the leg is
			// deliberately not recorded before this point either, because such a
			// splice can still be aborted - so a commitment spending the funding
			// that DOES exist went unseen. A pre-signature splice that aborts
			// therefore needs no re-arming: the watch never moved.
			if (inflight && inflight.sentTxSignatures === true) {
				// In-flight splice: watch the splice tx's new funding output IN
				// ADDITION to the old one, which keeps its own spend coverage
				// from the pre-splice leg armed above (the old output is
				// expected to be spent by the splice tx, and a stale
				// confirmation re-fire would trigger a premature splice_locked).
				// Also rebroadcast the fully-signed splice tx — the network may never
				// have seen it if we crashed right after persisting.
				const spliceFunding = createFundingScript(
					state.localBasepoints.fundingPubkey,
					inflight.remoteFundingPubkey,
					btcNetwork
				);
				const spliceTxidHex = Buffer.from(inflight.spliceTxid)
					.reverse()
					.toString('hex');
				await this.chainWatcher.watchFundingOutput(
					state.channelId || state.temporaryChannelId,
					spliceTxidHex,
					inflight.newFundingOutputIndex,
					state.minimumDepth ?? 3,
					spliceFunding.p2wshOutput
				);
				// The new-outpoint watch above only arms spend detection once the
				// splice tx confirms, so the OLD (still-confirmed) funding output
				// has no spend subscription of its own. That watch is armed by
				// the loop ABOVE, from the durable record, which the block ahead
				// of it derives and persists for a row that predates the field.
				// Arming it here as well, without recording it, is what made a
				// second restart come back blind once completeSplice had cleared
				// spliceInFlight (issue #479).
				if (inflight.fullySigned && this.isCurrentChainStartup(generation)) {
					// Through the ACTION path, never straight at the backend. A
					// splice creates a funding output exactly as an open does, so
					// it answers to the same rule, and a direct call here has no
					// frame, no persist gate and no barrier: a restart could put
					// on chain the very transaction the barrier was holding when
					// the process died. The rebroadcast is idempotent and the
					// watch armed above reports the confirmation either way, so
					// nothing is lost by making it wait its turn.
					this.channelManager.reauthorizeSpliceBroadcast(
						state.channelId || state.temporaryChannelId
					);
				}
				continue;
			}

			const txidHex = Buffer.from(state.fundingTxid).reverse().toString('hex');

			// Post-signatures RBF: superseded broadcastable attempts can still
			// confirm and pay the same funding script, so the restored watch
			// carries every candidate outpoint (mirrors the live watch:funding
			// arming).
			const previousAttempts = state.v2PreviousAttempts ?? [];
			const candidates = previousAttempts.length
				? [
						{ txid: txidHex, outputIndex: state.fundingOutputIndex },
						...previousAttempts.map((rec) => ({
							txid: Buffer.from(rec.fundingTxid).reverse().toString('hex'),
							outputIndex: rec.fundingOutputIndex
						}))
				  ]
				: undefined;
			// A row restored from disk can name an attempt the lost process
			// later replaced by RBF: the replacement pays this same funding
			// script, so let the watch recognize it in the script's own
			// history rather than filtering it out as absent (issue #463).
			// What identifies it is lineage, not shape: the input outpoints of
			// every attempt the record knows, which a replacement must all
			// descend from and which no other channel of ours can match.
			const discoverAttemptInputs =
				this.channelManager.isChannelRestoredFromDisk(
					state.channelId || state.temporaryChannelId
				)
					? this.recordedV2AttemptInputs(state)
					: undefined;
			await this.chainWatcher.watchFundingOutput(
				state.channelId || state.temporaryChannelId,
				txidHex,
				state.fundingOutputIndex,
				state.minimumDepth ?? 3,
				fundingScript,
				undefined,
				candidates,
				discoverAttemptInputs
			);
		}
	}

	/**
	 * The input outpoints of every v2 funding attempt this row records, as
	 * `txid:vout`, for restored-watch discovery (issue #463). Empty for a
	 * channel with no retained attempt, which disables discovery: without a
	 * recorded attempt there is no lineage to descend from, and a funding
	 * script alone identifies nothing (channelKeyDeriver is optional, so
	 * channels with one peer can share their funding pubkeys).
	 */
	private recordedV2AttemptInputs(state: IChannelState): string[][] {
		const records = [
			...(state.v2InFlight ? [state.v2InFlight] : []),
			...(state.v2PreviousAttempts ?? [])
		];
		const lineage: string[][] = [];
		for (const record of records) {
			try {
				const tx = bitcoin.Transaction.fromHex(record.fundingTxHex);
				const inputs = tx.ins.map(
					(input) =>
						`${Buffer.from(input.hash).reverse().toString('hex')}:${
							input.index
						}`
				);
				if (inputs.length > 0) lineage.push(inputs);
			} catch {
				// An unparseable payload contributes no lineage. Every other
				// attempt still constrains the search, and with none of them
				// parsing, discovery simply stays off.
			}
		}
		return lineage;
	}

	/**
	 * The watcher retired a pre-splice spend watch because the transaction it
	 * was ignoring is irrevocably confirmed as that outpoint's spender. Drop
	 * the durable record with it, so the list stays empty on a channel with no
	 * splice in flight and a later restart does not re-arm a watch for an
	 * outpoint nothing can spend any more (issue #479).
	 */
	private retirePreSpliceSpendWatch(
		channelId: Buffer,
		txid: string,
		outputIndex: number
	): void {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;
		const state = channel.getFullState();
		const remaining = (state.preSpliceSpendWatches ?? []).filter(
			(w) => !(w.txid === txid && w.outputIndex === outputIndex)
		);
		if (remaining.length === (state.preSpliceSpendWatches ?? []).length) {
			return;
		}
		state.preSpliceSpendWatches = remaining.length ? remaining : undefined;
		this.persistChannel(channelId);
	}

	/**
	 * Arm the chain watches for the channel whose funding tx this is, exactly
	 * as restoreChainWatches would on the next restart: confirmation and
	 * announcement depth detection, breach (spend) detection, and the
	 * funding-missing watchdog. Called live from watch:funding so a channel
	 * opened in this session has coverage without a restart. A splice funding
	 * re-arms the watch on the NEW outpoint and keeps spend detection on the
	 * old one (the splice tx legitimately spends it; anything else is a
	 * breach).
	 */
	/**
	 * Arm chain spend detection on every superseded funding outpoint this
	 * channel has recorded (issue #479).
	 *
	 * The leg's OWN stored script, never the channel's current one: a splice
	 * may rotate the peer's funding pubkey, so recomputing the script here
	 * would subscribe to a hash the superseded output never paid and the breach
	 * would be invisible. Held in the watcher under a per-outpoint key, so this
	 * never disturbs the channel's own funding watch.
	 *
	 * Isolated per LEG. A transient Electrum error on one outpoint must not
	 * cost the others, the channel's own funding watch, or - when this runs
	 * from the startup restore - every later channel plus the pending-broadcast
	 * retries and the reconnect monitor that follow it, none of which is
	 * retried anywhere.
	 */
	private async armPreSpliceSpendWatches(
		channelId: Buffer,
		state: IChannelState
	): Promise<void> {
		if (!this.chainWatcher) return;
		for (const leg of state.preSpliceSpendWatches ?? []) {
			try {
				await this.chainWatcher.watchFundingSpendDuringSplice(
					channelId,
					leg.txid,
					leg.outputIndex,
					Buffer.from(leg.script, 'hex'),
					leg.spliceTxid
				);
			} catch (err) {
				// Its own code, not the generic recovery one: the consequence
				// is specific and worth naming, because a revoked pre-splice
				// commitment on that outpoint can go unpunished.
				this.emit('node:error', {
					code: 'PRESPLICE_WATCH_FAILED',
					channelId,
					message: `Failed to watch pre-splice funding outpoint ${leg.txid}:${
						leg.outputIndex
					}: ${(err as Error).message}`,
					timestamp: Date.now()
				} as ILightningError);
			}
		}
	}

	private async registerFundingWatch(fundingTxid: Buffer): Promise<void> {
		if (!this.chainWatcher) return;
		const networkMap: Record<string, bitcoin.Network> = {
			[Network.MAINNET]: bitcoin.networks.bitcoin,
			[Network.TESTNET]: bitcoin.networks.testnet,
			[Network.REGTEST]: bitcoin.networks.regtest,
			[Network.SIGNET]: bitcoin.networks.testnet
		};
		const btcNetwork = networkMap[this.network] || bitcoin.networks.regtest;
		const txidHex = Buffer.from(fundingTxid).reverse().toString('hex');

		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (!state.localBasepoints) continue;
			const channelId = channel.getChannelId() ?? state.temporaryChannelId;

			const inflight = state.spliceInFlight;
			if (inflight && Buffer.from(inflight.spliceTxid).equals(fundingTxid)) {
				const spliceFunding = createFundingScript(
					state.localBasepoints.fundingPubkey,
					inflight.remoteFundingPubkey,
					btcNetwork
				);
				// Keyed by channelId, this REPLACES the original funding watch,
				// so re-arm spend detection on the old outpoint separately,
				// exactly as restoreChainWatches does.
				await this.chainWatcher.watchFundingOutput(
					channelId,
					txidHex,
					inflight.newFundingOutputIndex,
					state.minimumDepth ?? 3,
					spliceFunding.p2wshOutput
				);
				// Spend detection on the superseded outpoint comes from the
				// channel's own durable record, which was written in the batch
				// that authorized this broadcast (issue #479). Reading state
				// here instead would be racing it: on a zero-conf channel
				// splice_locked leaves in that same batch, so by the time this
				// handler runs completeSplice may already have adopted the new
				// funding, and both the outpoint and the funding keys read
				// post-splice.
				await this.armPreSpliceSpendWatches(channelId, state);
				return;
			}

			if (!state.fundingTxid?.equals(fundingTxid)) continue;
			if (!state.remoteBasepoints) continue;
			const fundingScript = isTaprootChannel(state.channelType)
				? createTaprootFundingScript(
						state.localBasepoints.fundingPubkey,
						state.remoteBasepoints.fundingPubkey,
						btcNetwork
				  ).p2trOutput
				: createFundingScript(
						state.localBasepoints.fundingPubkey,
						state.remoteBasepoints.fundingPubkey,
						btcNetwork
				  ).p2wshOutput;
			// Post-signatures RBF: carry every candidate outpoint (mirrors
			// the watch:funding arming in the chain watcher).
			const previousAttempts = state.v2PreviousAttempts ?? [];
			const candidates = previousAttempts.length
				? [
						{ txid: txidHex, outputIndex: state.fundingOutputIndex },
						...previousAttempts.map((rec) => ({
							txid: Buffer.from(rec.fundingTxid).reverse().toString('hex'),
							outputIndex: rec.fundingOutputIndex
						}))
				  ]
				: undefined;
			await this.chainWatcher.watchFundingOutput(
				channelId,
				txidHex,
				state.fundingOutputIndex,
				state.minimumDepth ?? 3,
				fundingScript,
				undefined,
				candidates
			);
			return;
		}
	}

	/**
	 * Arm the funding-outpoint watch for a channel reconstructed from a static
	 * channel backup. The backup does not carry the peer's funding pubkey, so
	 * the 2-of-2 funding scriptPubkey cannot be rebuilt locally the way
	 * restoreChainWatches does for normal channels - fetch the funding tx and
	 * take the output's script verbatim instead. Spend detection then flows
	 * through the exact same watchFundingOutput path, so the peer's force-close
	 * lazily creates a monitor and sweeps our to_remote.
	 */
	private async watchRecoveredFundingOutput(
		channelId: Buffer,
		state: IChannelState
	): Promise<void> {
		if (!this.chainWatcher || !this._chainBackend) {
			throw new Error('Chain backend is not available');
		}
		if (!state.fundingTxid) {
			throw new Error('Recovered channel has no funding txid');
		}
		const txidHex = Buffer.from(state.fundingTxid).reverse().toString('hex');
		const rawTx = await this._chainBackend.getTransaction(txidHex);
		const fundingTx = bitcoin.Transaction.fromBuffer(rawTx);
		if (state.fundingOutputIndex >= fundingTx.outs.length) {
			throw new Error(
				`Funding output index ${state.fundingOutputIndex} out of range for tx ${txidHex}`
			);
		}
		await this.chainWatcher.watchFundingOutput(
			channelId,
			txidHex,
			state.fundingOutputIndex,
			state.minimumDepth || 1,
			Buffer.from(fundingTx.outs[state.fundingOutputIndex].script)
		);
	}

	/**
	 * Discover peers via DNS seeds (BOLT 10).
	 */
	async bootstrapPeers(config?: IBootstrapConfig): Promise<IPeerAddress[]> {
		return bootstrapPeers(config);
	}

	/**
	 * Connect to peers discovered via DNS bootstrap.
	 */
	async connectToSeeds(
		maxPeers = 3,
		config?: IBootstrapConfig
	): Promise<string[]> {
		if (!this.peerManager) {
			throw new Error('Networking is not enabled');
		}
		this.assertPeerContactPermitted('connectToSeeds');
		const peers = await this.bootstrapPeers(config);
		const connected: string[] = [];
		for (const peer of peers.slice(0, maxPeers)) {
			try {
				const pubkeyHex = peer.pubkey.toString('hex');
				await this.peerManager.connectPeer(pubkeyHex, peer.host, peer.port);
				connected.push(pubkeyHex);
			} catch {
				// Skip failed connections
			}
		}
		return connected;
	}

	// ─────────────── Zero-Conf Channel Management ───────────────

	/**
	 * Add a peer as trusted for zero-conf channels.
	 */
	addTrustedPeer(pubkeyHex: string): void {
		const pubkeyErr = validateHexPubkey(pubkeyHex, 'pubkeyHex');
		if (pubkeyErr) throw new Error(pubkeyErr);
		this.channelManager.addTrustedPeer(pubkeyHex);
	}

	/**
	 * Remove a peer from the zero-conf trusted set.
	 */
	removeTrustedPeer(pubkeyHex: string): void {
		this.channelManager.removeTrustedPeer(pubkeyHex);
	}

	/**
	 * List all trusted peers for zero-conf.
	 */
	listTrustedPeers(): string[] {
		return this.channelManager.listTrustedPeers();
	}

	/**
	 * Open a zero-conf channel with a trusted peer.
	 * Channel becomes usable immediately after funding, before confirmation.
	 *
	 * @deprecated Prefer openChannel(..., trusted = true). This wrapper routes
	 * through it so the open honors the negotiated funding protocol: BOLT 2
	 * forbids a v1 open_channel once option_dual_fund is negotiated, which the
	 * old direct-to-v1 path violated between two default-featured beignet
	 * nodes. A nonzero push toward a dual-fund peer is rejected (open_channel2
	 * has no push_msat) rather than smuggled through an illegal v1 open.
	 * Throws instead of returning null on an untrusted peer.
	 */
	openZeroConfChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint
	): Channel {
		return this.openChannel(
			peerPubkey,
			fundingSatoshis,
			pushMsat,
			undefined,
			false,
			true
		);
	}

	/**
	 * Open a zero-conf channel with a trusted peer and wait for it to reach
	 * NORMAL, resolving with the funding-derived channel id (issue #572). The
	 * id changes from temporary to permanent during the open, so the wait
	 * holds the Channel object rather than an id. Failures reject fast
	 * instead of spinning to the timeout, so a caller's retry loop (the JIT
	 * engine) can engage, and every failure signal is SCOPED to this open:
	 * channel:aborted by our temporary id (the v1 funding-failure teardown),
	 * CHANNEL_ERROR by our id (the v2 "v2 open not funded" failure, or any
	 * error leaving this channel ERRORED, such as a peer's synchronous
	 * rejection), and channel:voided (the v2 abort teardown terminal). An
	 * open already dead when openChannel returns (a synchronous transport
	 * can settle the rejection inside the call) throws immediately. Throws
	 * synchronously whatever openChannel throws (untrusted peer, no fee
	 * estimate, invalid params).
	 */
	async openZeroConfChannelAndWait(
		peerPubkey: string,
		fundingSatoshis: bigint,
		timeoutMs = 120_000
	): Promise<Buffer> {
		if (this._destroyed) throw new Error('Node destroyed');
		const channel = this.openChannel(
			peerPubkey,
			fundingSatoshis,
			undefined,
			undefined,
			false,
			true
		);
		// A synchronous transport can settle the whole open inside openChannel
		// (zero-conf needs no confirmation), in EITHER direction: complete to
		// NORMAL, or reject and tear down before any listener below exists.
		// Check both before subscribing so an already-dead open fails now
		// instead of burning the full timeout (issue #572 review).
		if (channel.getState() === ChannelState.NORMAL) {
			return channel.getChannelId()!;
		}
		const terminalReason = (): string | null => {
			if (channel.getState() === ChannelState.ERRORED) {
				return 'channel errored';
			}
			const cid = channel.getChannelId();
			const tracked =
				this.channelManager.getTempChannel(channel.getTemporaryChannelId()) ===
					channel ||
				(cid !== null && this.channelManager.getChannel(cid) === channel);
			return tracked ? null : 'open was torn down';
		};
		const early = terminalReason();
		if (early !== null) {
			throw new Error(`channel open failed: ${early}`);
		}
		const matchesOpen = (id: Buffer): boolean => {
			const cid = channel.getChannelId();
			return (
				(cid !== null && cid.equals(id)) ||
				channel.getTemporaryChannelId().equals(id)
			);
		};
		return new Promise<Buffer>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				reject(
					new Error(
						`zero-conf channel to ${peerPubkey.slice(
							0,
							12
						)} not ready within ${timeoutMs}ms`
					)
				);
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.removeListener('channel:ready', onReady);
				this.removeListener('channel:aborted', onAborted);
				this.removeListener('channel:voided', onVoided);
				this.removeListener('node:error', onError);
				this._activeWaitCleanups.delete(destroyCleanup);
			};

			const destroyCleanup = (): void => {
				cleanup();
				reject(new Error('Node destroyed'));
			};
			this._activeWaitCleanups.add(destroyCleanup);

			const onReady = (data: { channelId: Buffer }): void => {
				const cid = channel.getChannelId();
				if (cid !== null && cid.equals(data.channelId)) {
					cleanup();
					resolve(cid);
				}
			};
			// The v1 funding failure path (AUTO_FUNDING_FAILED carries no
			// channelId) tears the open down via abortPendingOpen, whose
			// channel:aborted names OUR temporary id: the precise scope.
			const onAborted = (temporaryChannelId: Buffer, reason: string): void => {
				if (!channel.getTemporaryChannelId().equals(temporaryChannelId)) {
					return;
				}
				cleanup();
				reject(new Error(`channel open aborted: ${reason}`));
			};
			// The v2 abort teardown's terminal event once the abandoned row is
			// durably removed.
			const onVoided = (data: { channelId: Buffer }): void => {
				if (!matchesOpen(data.channelId)) return;
				cleanup();
				reject(new Error('channel open aborted: v2 open torn down'));
			};
			// AUTO_FUNDING_FAILED itself is deliberately NOT watched: it
			// carries no channel id, so with two concurrent opens one wallet
			// failure would reject every unfunded wait while the other open
			// kept running (issue #572 review). The v1 failure path always
			// follows it with abortPendingOpen, whose channel:aborted above
			// names OUR temporary id: that is the scoped signal.
			const onError = (err: ILightningError): void => {
				if (
					err.code !== 'CHANNEL_ERROR' ||
					err.channelId === undefined ||
					!matchesOpen(err.channelId)
				) {
					return;
				}
				// Scoped to this open: the v2 funding failure by message, or
				// any error that left the channel terminally ERRORED (a
				// peer's synchronous rejection, a failed negotiation). A
				// scoped diagnostic on a still-live channel (dispatch
				// failures deliberately do not abort) keeps waiting.
				if (
					/^v2 open not funded/.test(err.message) ||
					channel.getState() === ChannelState.ERRORED
				) {
					cleanup();
					reject(new Error(`channel open failed: ${err.message}`));
				}
			};

			this.on('channel:ready', onReady);
			this.on('channel:aborted', onAborted);
			this.on('channel:voided', onVoided);
			this.on('node:error', onError);
		});
	}

	destroy(): void {
		this._destroyed = true;
		// Retires any chain startup sequence still working through its awaits.
		++this.chainStartupGeneration;
		// Queued broadcast gossip dies with the node; the drain loop also
		// checks _destroyed so an in-flight slice stops rescheduling.
		this.gossipIntake = [];
		this.gossipIntakeHead = 0;
		// Anything held behind the barrier is refused rather than left parked.
		// A shutdown is not permission either, and the barrier's retry timer
		// must not keep the process alive.
		this.recoveryBarrier?.stop();
		this.stopCleanupTimer();
		if (this.mppCleanupTimer) {
			clearInterval(this.mppCleanupTimer);
			this.mppCleanupTimer = null;
		}
		if (this.feeUpdateTimer) {
			clearInterval(this.feeUpdateTimer);
			this.feeUpdateTimer = null;
		}
		if (this.missionControlTimer) {
			clearInterval(this.missionControlTimer);
			this.missionControlTimer = null;
		}
		if (this.graphPruneTimer) {
			clearInterval(this.graphPruneTimer);
			this.graphPruneTimer = null;
		}
		if (this.walCheckpointTimer) {
			clearInterval(this.walCheckpointTimer);
			this.walCheckpointTimer = null;
		}
		if (this._gossipRefreshTimer) {
			clearInterval(this._gossipRefreshTimer);
			this._gossipRefreshTimer = undefined;
		}
		if (this.autoRebalanceTimer) {
			clearInterval(this.autoRebalanceTimer);
			this.autoRebalanceTimer = null;
		}
		if (this.autoTuneFeesTimer) {
			clearInterval(this.autoTuneFeesTimer);
			this.autoTuneFeesTimer = null;
		}
		// Clear reconnect timers
		for (const t of this._reconnectTimers) {
			clearTimeout(t);
		}
		this._reconnectTimers.clear();
		// Clear deferred peer-storage flush timers
		if (this.capsuleRefreshTimer) {
			clearTimeout(this.capsuleRefreshTimer);
			this.capsuleRefreshTimer = null;
		}
		for (const t of this.peerStorageFlushTimers.values()) {
			clearTimeout(t);
		}
		this.peerStorageFlushTimers.clear();
		// Reject all active wait promises
		for (const cleanup of this._activeWaitCleanups) {
			cleanup();
		}
		this._activeWaitCleanups.clear();
		if (
			this._chainBackend &&
			typeof (this._chainBackend as ElectrumBackend).stopReconnectMonitor ===
				'function'
		) {
			(this._chainBackend as ElectrumBackend).stopReconnectMonitor();
		}
		if (this.chainWatcher) {
			this.chainWatcher.stop();
		}
		if (this.watchtowerClient) {
			this.watchtowerClient.stop();
		}
		if (this.peerManager) {
			this.peerManager.destroy();
		}
		this.onionMessageManager.destroy();
		this.offerManager.destroy();
		// Persist mission control on destroy
		if (this.storage && this.missionControl.size > 0) {
			try {
				this.storage.saveMissionControl(this.missionControl.export());
			} catch (err) {
				this.emit('node:error', {
					code: 'PERSISTENCE_ERROR',
					message: `Failed to persist mission control on shutdown: ${
						(err as Error).message
					}`,
					timestamp: Date.now()
				} as ILightningError);
			}
		}
		// Close storage to release WAL file handles
		if (this.storage) {
			try {
				this.storage.close();
			} catch {
				// best-effort — storage may already be closed
			}
		}
		this.payments.clear();
		this.preimages.clear();
		this.paymentSecrets.clear();
		this.invoices.clear();
		this.scidToChannelId.clear();
		this.htlcPaymentMap.clear();
		this.forwardedHtlcs.clear();
		this.gossipSyncManagers.clear();
		this.pendingMppPayments.clear();
		this.pendingFundingTxs.clear();
		this.paymentRetryContexts.clear();
		this.receivedHtlcSharedSecrets.clear();
		this.outboundMppPayments.clear();
		this._stuckChannelTracker.clear();
		this.rateLimiter.clear();
		this.removeAllListeners();
	}

	/**
	 * Graceful shutdown: waits for in-flight HTLCs to settle, persists state, then destroys.
	 */
	async gracefulShutdown(timeoutMs = 30_000): Promise<void> {
		// Stop accepting new operations
		this._destroyed = true;
		++this.chainStartupGeneration;

		// Wait for in-flight HTLCs to settle
		const hasInFlightHtlcs = (): boolean => {
			for (const ch of this.channelManager.listChannels()) {
				const state = ch.getFullState();
				if (state.htlcs && state.htlcs.size > 0) return true;
			}
			return false;
		};

		const deadline = Date.now() + timeoutMs;
		while (hasInFlightHtlcs() && Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 500));
		}

		// Persist all state
		if (this.storage) {
			try {
				// Flush all channel states
				for (const channel of this.channelManager.listChannels()) {
					const channelId = channel.getChannelId();
					if (channelId) {
						this.persistChannel(channelId);
					}
				}
				// Flush pending payments
				for (const [hashHex, payment] of this.payments) {
					if (payment.status === 'PENDING') {
						this.persistPayment(Buffer.from(hashHex, 'hex'));
					}
				}
				// Persist block height
				this.storage.saveMetadata(
					'blockHeight',
					String(this.currentBlockHeight)
				);
				if (this.missionControl.size > 0) {
					this.storage.saveMissionControl(this.missionControl.export());
				}
			} catch {
				// best-effort
			}
		}

		// Final destroy
		this.destroy();
	}

	// ─────────────── Resource Cleanup ───────────────

	private startCleanupTimer(): void {
		const interval = this.resourceConfig.cleanupIntervalMs;
		if (interval <= 0) return;
		this.cleanupTimer = setInterval(() => {
			this.pruneCompletedPayments();
		}, interval);
		if (this.cleanupTimer.unref) {
			this.cleanupTimer.unref(); // won't block process exit
		}
	}

	private stopCleanupTimer(): void {
		if (this.cleanupTimer) {
			clearInterval(this.cleanupTimer);
			this.cleanupTimer = null;
		}
	}

	/**
	 * Prune completed/failed payments that exceed TTL or size cap.
	 * Also cleans stale htlcPaymentMap entries whose payments are gone.
	 */
	pruneCompletedPayments(): number {
		const now = Date.now();
		const ttl = this.resourceConfig.completedPaymentTtlMs;
		const max = this.resourceConfig.maxCompletedPayments;
		let pruned = 0;

		// Phase 1: Remove expired entries
		for (const [hash, payment] of this.payments) {
			if (
				payment.status === PaymentStatus.COMPLETED ||
				payment.status === PaymentStatus.FAILED
			) {
				const age = now - (payment.completedAt || payment.createdAt);
				if (age > ttl) {
					this.payments.delete(hash);
					this.preimages.delete(hash);
					pruned++;
				}
			}
		}

		// Phase 2: If still over cap, remove oldest completed/failed first
		const completed: [string, IPaymentInfo][] = [];
		for (const entry of this.payments) {
			if (
				entry[1].status === PaymentStatus.COMPLETED ||
				entry[1].status === PaymentStatus.FAILED
			) {
				completed.push(entry);
			}
		}
		if (completed.length > max) {
			completed.sort(
				(a, b) =>
					(a[1].completedAt || a[1].createdAt) -
					(b[1].completedAt || b[1].createdAt)
			);
			const toRemove = completed.length - max;
			for (let i = 0; i < toRemove; i++) {
				this.payments.delete(completed[i][0]);
				this.preimages.delete(completed[i][0]);
				pruned++;
			}
		}

		// Phase 3: Clean stale htlcPaymentMap entries. Drop the persisted rows
		// with them, in one journaled transition, otherwise the mappings outlive
		// the payments they point at and are loaded straight back into memory on
		// the next restart (or resurrected by a journal reconstruction).
		const staleMappings: RecoveryMutation[] = [];
		for (const [key, hashHex] of this.htlcPaymentMap) {
			if (!this.payments.has(hashHex)) {
				this.htlcPaymentMap.delete(key);
				staleMappings.push({
					type: 'delete_htlc_payment_mapping',
					htlcKey: key
				});
			}
		}
		this.commitMutations('prune stale HTLC mappings', staleMappings);

		// Phase 4: Drop retry contexts whose payment record is gone. A dispatch
		// that throws after registering its context (route found but the add was
		// refused, say) leaves one behind with nothing to retry, and the success
		// and give-up paths only delete the context for payments that ran their
		// course. Dispatch-then-reregister during a retry is synchronous, so a
		// context can never be observed here without its payment mid-flight.
		for (const hashHex of this.paymentRetryContexts.keys()) {
			if (!this.payments.has(hashHex)) {
				this.paymentRetryContexts.delete(hashHex);
			}
		}

		return pruned;
	}

	// ─────────────── Channel Management ───────────────

	/**
	 * Whether option_dual_fund is negotiated with this peer: both sides must
	 * advertise it (BOLT 9). Ours comes from localFeatures (the default set
	 * advertises it), the peer's from the init it sent on connect. A peer we
	 * hold no init for counts as not negotiated.
	 */
	private peerNegotiatedDualFund(peerPubkey: string): boolean {
		if (!this.localFeatures.hasFeature(Feature.DUAL_FUND)) return false;
		const init = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		return init ? init.features.hasFeature(Feature.DUAL_FUND) : false;
	}

	/**
	 * Whether option_zeroconf (and its BOLT 9 dependency option_scid_alias)
	 * is negotiated with this peer. BOLT 2 says a node SHOULD NOT propose a
	 * channel type carrying features that were not negotiated, so a trusted
	 * open checks this up front and fails clearly instead of sending a
	 * mandatory channel-type bit the peer never advertised (e.g. an older
	 * daemon in a mixed-version own-node deployment). Without a peer manager
	 * (in-process harnesses) there is no init to consult and the check
	 * passes, mirroring how openChannel skips its connectivity check.
	 */
	private peerNegotiatedZeroConf(peerPubkey: string): boolean {
		if (
			!this.localFeatures.hasFeature(Feature.ZERO_CONF) ||
			!this.localFeatures.hasFeature(Feature.SCID_ALIAS)
		) {
			return false;
		}
		if (!this.peerManager) return true;
		const init = this.peerManager.getPeer(peerPubkey)?.getRemoteInit();
		return Boolean(
			init?.features.hasFeature(Feature.ZERO_CONF) &&
				init.features.hasFeature(Feature.SCID_ALIAS)
		);
	}

	/**
	 * Public view of the v1/v2 routing decision openChannel will make for
	 * this peer: dualFund mirrors peerNegotiatedDualFund exactly, and
	 * peerKnown says whether there is an init to judge by at all (a peer we
	 * are not connected to yields peerKnown false and dualFund false, which
	 * openChannel would route to v1).
	 */
	peerFundingInfo(peerPubkey: string): {
		peerKnown: boolean;
		dualFund: boolean;
	} {
		const init = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		return {
			peerKnown: Boolean(init),
			dualFund: this.peerNegotiatedDualFund(peerPubkey)
		};
	}

	/**
	 * The exact quote a max dual-funded open would commit at this rate: the
	 * SAME clamp, sat/kw conversion and provider formula as openChannel's
	 * fundMax path, so a UI previewing this number previews the amount the
	 * channel actually opens with.
	 */
	quoteDualFundingMaxOpen(satsPerVbyte: number): {
		feeratePerKw: number;
		fundingSatoshis: bigint;
		spendableSats: bigint;
		feeSats: bigint;
		inputCount: number;
	} {
		if (!Number.isFinite(satsPerVbyte) || satsPerVbyte <= 0) {
			throw new InvalidChannelOpenError(
				`satsPerVbyte (${satsPerVbyte}) must be a positive finite rate`
			);
		}
		const fp = this.fundingProvider;
		if (!fp?.quoteDualFundingMax) {
			throw new ChannelFundingUnavailableError(
				ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED,
				'quoting a max dual-funded (v2) open requires a funding provider with quoteDualFundingMax'
			);
		}
		const feeratePerKw = Math.ceil(
			this.clampEstimatedFeeRate(satsPerVbyte) * 250
		);
		return { feeratePerKw, ...fp.quoteDualFundingMax(feeratePerKw) };
	}

	/**
	 * Open a channel with a peer.
	 *
	 * trusted opens a zero-conf channel toward a peer in the zero-conf trusted
	 * set (addTrustedPeer): the zero_conf channel type goes on the wire and
	 * both sides fast-track channel_ready, so the channel is usable before the
	 * funding confirms. Only use toward a peer you control or trust
	 * completely: unconfirmed funding can be double-spent by the opener.
	 * Everything else stays standard BOLT 2, including the v1/v2 routing:
	 * a trusted open toward a dual-fund peer rides open_channel2.
	 */
	openChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint,
		satsPerVbyte?: number,
		fundMax = false,
		trusted = false
	): Channel {
		const pubkeyErr = validateHexPubkey(peerPubkey, 'peerPubkey');
		if (pubkeyErr) throw new InvalidChannelOpenError(pubkeyErr);
		const satsErr = validatePositiveBigint(fundingSatoshis, 'fundingSatoshis');
		if (satsErr) throw new InvalidChannelOpenError(satsErr);
		if (pushMsat !== undefined && pushMsat > fundingSatoshis * 1000n) {
			throw new InvalidChannelOpenError(
				`pushMsat (${pushMsat}) cannot exceed fundingSatoshis * 1000 (${
					fundingSatoshis * 1000n
				})`
			);
		}
		// `> 0` alone would admit Infinity and NaN-adjacent nonsense; a fee rate has
		// to be a real, finite, positive number before it is paid to miners.
		if (
			satsPerVbyte !== undefined &&
			(!Number.isFinite(satsPerVbyte) || satsPerVbyte <= 0)
		) {
			throw new InvalidChannelOpenError(
				`satsPerVbyte (${satsPerVbyte}) must be a positive finite rate`
			);
		}
		// A max open commits fundingSatoshis now but sweeps at funding time, and the
		// two only agree if both are priced at the same rate. Without a pinned rate,
		// handleAutoFunding would ask the estimator for a fresh one after the peer
		// accepts, and a rate that has since moved makes the sweep miss the committed
		// amount, failing the funding after negotiation. Require the caller to pin
		// the rate its max was quoted at, so only an on-chain balance change (which
		// the funding provider guards) can still cause a mismatch.
		if (fundMax && satsPerVbyte === undefined) {
			throw new InvalidChannelOpenError(
				'max funding requires a pinned satsPerVbyte (the rate the max amount was quoted at)'
			);
		}
		// A trusted open proposes a mandatory zero_conf + scid_alias channel
		// type; BOLT 2 says not to propose channel-type features the peer never
		// negotiated. Fail clearly here (an older daemon that does not
		// advertise them, say) instead of sending a proposal the peer must
		// reject with an opaque channel-type error.
		if (trusted && !this.peerNegotiatedZeroConf(peerPubkey)) {
			throw new InvalidChannelOpenError(
				`Peer ${peerPubkey} did not negotiate option_zeroconf and option_scid_alias; a trusted (zero-conf) open needs both in its init features`
			);
		}
		// BOLT 2: once option_dual_fund is negotiated with a peer, a v1
		// open_channel must not be used; dual-fund peers reject it outright
		// (CLN: "OPT_DUAL_FUND: cannot use open_channel"). Our default features
		// advertise option_dual_fund, so route the open through the v2 flow and
		// keep this one entry point working against both kinds of peer. With no
		// init from the peer there is nothing to judge by, so the open falls
		// through to v1 — which then throws 'Not connected to peer' from
		// ChannelManager.openChannel when a peer manager is attached; nothing
		// is queued for later.
		if (this.peerNegotiatedDualFund(peerPubkey)) {
			if (pushMsat !== undefined && pushMsat > 0n) {
				throw new InvalidChannelOpenError(
					'push is not possible on a dual-funded (v2) open: open_channel2 has no push_msat. Open without a push and pay the peer once the channel is ready.'
				);
			}
			if (fundMax) {
				// A v2 max cannot reuse the caller's committed amount: a v1 max is
				// quoted from the sweep transaction's actual vbytes, while a v2
				// initiator pays the cushioned interactive-tx weight formula — the
				// two disagree by design. Recompute the committed amount here from
				// the same provider and formula that will fund it, at the pinned
				// rate (required above), so funding nets out to zero change.
				const fp = this.fundingProvider;
				if (!fp?.quoteDualFundingMax || !fp.selectMaxDualFundingInputs) {
					throw new ChannelFundingUnavailableError(
						ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED,
						'max funding on a dual-funded (v2) open requires a funding provider with quoteDualFundingMax and selectMaxDualFundingInputs'
					);
				}
				const feeratePerKw = Math.ceil(
					this.clampEstimatedFeeRate(satsPerVbyte!) * 250
				);
				const quote = fp.quoteDualFundingMax(feeratePerKw);
				if (quote.fundingSatoshis <= 0n) {
					throw new ChannelFundingUnavailableError(
						ChannelFundingUnavailableCode.INSUFFICIENT_BALANCE,
						`insufficient funds for a max dual-funded open: ${quote.spendableSats} sats spendable cannot cover the ${quote.feeSats} sat funding fee`
					);
				}
				return this.openChannelV2(peerPubkey, {
					fundingSatoshis: quote.fundingSatoshis,
					fundingFeeratePerkw: feeratePerKw,
					fundMax: true,
					trusted
				});
			}
			// Same funding-fee policy as a v1 open, where handleAutoFunding
			// clamps the caller's rate or asks the estimator at funding time.
			// v2 cannot defer: open_channel2 itself carries funding_feerate_perkw,
			// so the rate is pinned NOW from the same estimator's latest sample
			// (the fee advisor, seeded at construction and refreshed per block),
			// clamped identically, and converted to sat/kw (1 vB = 4 WU, so
			// 1 sat/vB = 250 sat/kw) — the exact pattern getClosingFeeratePerKw
			// uses.
			const quotedSatPerVbyte =
				satsPerVbyte !== undefined
					? satsPerVbyte
					: this.feeAdvisor.getCurrentRate();
			// Two different "no rate" states must not collapse: with NO
			// estimator configured, the static configured feerate fallback in
			// openChannelV2 is intentional. With an estimator whose seed has
			// not landed yet (a fresh node, milliseconds after construction),
			// silently funding at the static default would underprice the
			// funding tx in an elevated mempool — the exact regression a v1
			// open avoids by asking the estimator at funding time. Refuse
			// honestly; the seed resolves almost immediately and a retry
			// succeeds.
			if (quotedSatPerVbyte <= 0 && this.feeEstimator) {
				throw new ChannelFundingUnavailableError(
					ChannelFundingUnavailableCode.FEE_ESTIMATE_NOT_READY,
					'fee estimate not ready yet for a dual-funded open (the estimator has not delivered its first sample); retry shortly or pass an explicit satsPerVbyte'
				);
			}
			return this.openChannelV2(peerPubkey, {
				fundingSatoshis,
				fundingFeeratePerkw:
					quotedSatPerVbyte > 0
						? Math.ceil(this.clampEstimatedFeeRate(quotedSatPerVbyte) * 250)
						: undefined,
				trusted
			});
		}
		// The fee rate and max marker are remembered against the temporary
		// channel id and consumed by handleAutoFunding when the peer accepts.
		// They MUST be recorded via the beforeNegotiate hook, not after
		// openChannel returns: with a synchronous transport the peer's
		// accept_channel — and therefore auto-funding — runs INSIDE the
		// openChannel call, and entries recorded after it returns are recorded
		// too late (the open then funds at the estimator default and as a
		// fixed-amount send even when a max sweep was requested).
		return this.channelManager.openChannel(
			peerPubkey,
			fundingSatoshis,
			pushMsat,
			(temporaryChannelId) => {
				const tempId = temporaryChannelId.toString('hex');
				if (satsPerVbyte !== undefined) {
					// An open that is accepted, or that fails, takes its entry with
					// it. One the peer neither accepts nor refuses leaves it behind,
					// so the map is bounded rather than trusting every open to end
					// in a way we hear about.
					if (
						this.requestedFundingFeeRates.size >=
						LightningNode.MAX_REQUESTED_FUNDING_FEE_RATES
					) {
						const oldest = this.requestedFundingFeeRates.keys().next().value;
						if (oldest !== undefined) {
							this.requestedFundingFeeRates.delete(oldest);
						}
					}
					this.requestedFundingFeeRates.set(tempId, satsPerVbyte);
				}
				// Same lifecycle as the fee rate: consumed when the peer accepts,
				// so funding sweeps instead of building a fixed-amount tx that
				// cannot cover its own change output at the max.
				if (fundMax) {
					if (
						this.fundingMaxRequests.size >=
						LightningNode.MAX_REQUESTED_FUNDING_FEE_RATES
					) {
						const oldest = this.fundingMaxRequests.values().next().value;
						if (oldest !== undefined) {
							this.fundingMaxRequests.delete(oldest);
						}
					}
					this.fundingMaxRequests.add(tempId);
				}
			},
			{ trusted }
		);
	}

	/**
	 * Funding fee rates (sat/vB) chosen by the caller, keyed by temporary channel
	 * id. Empty for an open that did not ask for one, which funds at the fee
	 * estimator's rate as before.
	 */
	private readonly requestedFundingFeeRates = new Map<string, number>();

	/**
	 * Temporary channel ids whose funding should sweep the whole balance (a "max"
	 * channel), keyed the same way as the fee rates above and consumed together
	 * when the peer accepts. Bounded by the same backstop.
	 */
	private readonly fundingMaxRequests = new Set<string>();

	/** Far more than any node has opens in flight; a backstop, not a budget. */
	private static readonly MAX_REQUESTED_FUNDING_FEE_RATES = 256;

	/**
	 * Open a dual-funded (v2) channel with a peer.
	 * Both peers can contribute funding to the channel.
	 */
	openChannelV2(
		peerPubkey: string,
		params: {
			fundingSatoshis: bigint;
			fundingFeeratePerkw?: number;
			commitmentFeeratePerkw?: number;
			locktime?: number;
			/**
			 * Liquidity ads (bLIP-0051): request the peer lease us inbound
			 * liquidity (buyer side). Requires maxLeaseRates.
			 */
			requestFunds?: import('../message/dual-funding').IRequestFunds;
			/**
			 * Buyer's LOCAL price ceiling for the lease — choose it yourself
			 * (e.g. from the ad you decided was acceptable); never copy it from
			 * the seller's will_fund reply. The lease is rejected if the seller's
			 * signed rates imply a higher fee.
			 */
			maxLeaseRates?: import('../gossip/types').ILeaseRates;
			/**
			 * channel_type feature bitmap for open_channel2. A lease
			 * (requestFunds) requires an anchor channel_type — the lessor's
			 * to_remote lease CLTV cannot ride a non-anchor P2WPKH output.
			 */
			channelType?: Buffer;
			/**
			 * Max (sweep-everything) open: fundingSatoshis must have been quoted
			 * via the funding provider's quoteDualFundingMax at
			 * fundingFeeratePerkw; funding then contributes every spendable UTXO
			 * (selectMaxDualFundingInputs) so change nets out to zero.
			 */
			fundMax?: boolean;
			/**
			 * Zero-conf trusted open: adds the zero_conf channel type (BOLT 2
			 * feature 50) and fast-tracks channel_ready after tx_signatures.
			 * Requires the peer in the zero-conf trusted set.
			 */
			trusted?: boolean;
			/**
			 * Fund the open from exactly these wallet outpoints (txid in
			 * display byte order), e.g. to channelize a specific deposit
			 * (issue #572). All named coins are contributed; allowTopUp
			 * permits adding other spendable coins when they fall short of
			 * amount + fee. Requires a funding provider that can select
			 * wallet inputs, and the returned selection is verified against
			 * the named outpoints before it funds anything. Incompatible
			 * with fundMax and contribution.
			 */
			fundingUtxos?: {
				utxos: Array<{ txid: string; vout: number }>;
				allowTopUp?: boolean;
			};
			/**
			 * Register the opener's funding inputs (possibly carrying
			 * EXTERNAL ones, issue #572) before the open_channel2 goes out,
			 * bypassing wallet selection entirely. This is the race-free way
			 * to fund an open with caller-built inputs: it wins over
			 * auto-funding in every message ordering, including a fully
			 * synchronous transport. Incompatible with fundMax, fundingUtxos
			 * and requestFunds (a lease fee is only known at accept time and
			 * cannot be added to a pre-built contribution).
			 */
			contribution?: {
				inputs: import('../channel/channel').ISpliceWalletInput[];
				changeScript: Buffer;
			};
		}
	): Channel {
		const pubkeyErr = validateHexPubkey(peerPubkey, 'peerPubkey');
		if (pubkeyErr) throw new InvalidChannelOpenError(pubkeyErr);
		const satsErr = validatePositiveBigint(
			params.fundingSatoshis,
			'fundingSatoshis'
		);
		if (satsErr) throw new InvalidChannelOpenError(satsErr);
		// Fail fast at the API boundary; handleAcceptChannel2 enforces the same
		// invariant as defense-in-depth (an uncapped lease fee could otherwise
		// drain the buyer's balance).
		if (params.requestFunds && !params.maxLeaseRates) {
			throw new InvalidChannelOpenError(
				'requestFunds requires maxLeaseRates (buyer fee ceiling)'
			);
		}
		// A lease fee is only known once the seller answers will_fund, but a max
		// open must commit the ENTIRE balance minus fees in open_channel2 —
		// there is nothing left to absorb the fee later.
		if (params.fundMax && params.requestFunds) {
			throw new InvalidChannelOpenError(
				'max funding cannot be combined with requestFunds (the lease fee is not known when the max is committed)'
			);
		}
		if (params.fundMax && params.fundingUtxos) {
			throw new InvalidChannelOpenError(
				'max funding cannot be combined with fundingUtxos (a max open already sweeps every spendable UTXO)'
			);
		}
		if (params.contribution) {
			if (params.fundMax || params.fundingUtxos || params.requestFunds) {
				throw new InvalidChannelOpenError(
					'contribution cannot be combined with fundMax, fundingUtxos or requestFunds (it replaces wallet selection outright)'
				);
			}
			if (
				!Array.isArray(params.contribution.inputs) ||
				params.contribution.inputs.length === 0 ||
				!Buffer.isBuffer(params.contribution.changeScript)
			) {
				throw new InvalidChannelOpenError(
					'contribution needs a non-empty inputs array and a changeScript Buffer'
				);
			}
		}
		if (params.fundingUtxos) {
			const list = params.fundingUtxos.utxos;
			if (!Array.isArray(list) || list.length === 0) {
				throw new InvalidChannelOpenError(
					'fundingUtxos.utxos must be a non-empty array'
				);
			}
			for (const u of list) {
				if (typeof u?.txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(u.txid)) {
					throw new InvalidChannelOpenError(
						'fundingUtxos.utxos entries need a 64-hex txid'
					);
				}
				if (!Number.isInteger(u.vout) || u.vout < 0) {
					throw new InvalidChannelOpenError(
						'fundingUtxos.utxos entries need a non-negative integer vout'
					);
				}
			}
			// Directed funding needs a provider that can select wallet inputs
			// AT ALL; without one the open would stall silently as a legacy
			// caller-driven negotiation nobody drives (issue #572 review).
			// Retryable and typed, mirroring the fee-estimate refusal.
			const fp = this.fundingProvider;
			if (!fp?.selectDualFundingInputs && !fp?.selectSpliceInputs) {
				throw new ChannelFundingUnavailableError(
					ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED,
					'fundingUtxos requires a funding provider that can select wallet inputs (selectDualFundingInputs or selectSpliceInputs)'
				);
			}
		}
		// open_channel2 carries all three as u32. Same reason as splice_init:
		// encoding runs after the channel exists and is keyed by temporary id.
		for (const [name, value] of [
			['fundingFeeratePerkw', params.fundingFeeratePerkw],
			['commitmentFeeratePerkw', params.commitmentFeeratePerkw],
			['locktime', params.locktime]
		] as Array<[string, number | undefined]>) {
			if (value === undefined) continue;
			const err = validateU32(value, name, {
				min: name === 'locktime' ? 0 : 1
			});
			if (err) throw new InvalidChannelOpenError(err);
		}

		const config = this.channelManager['config'] as {
			localConfig?: import('../channel/types').IChannelConfig;
			localBasepoints: import('../keys/derivation').IChannelBasepoints;
			localPerCommitmentSeed: Buffer;
		};
		const localConfig = config.localConfig || DEFAULT_CHANNEL_CONFIG;

		const dualParams: import('../channel/dual-funding').IDualFundingParams = {
			fundingSatoshis: params.fundingSatoshis,
			fundingFeeratePerkw:
				params.fundingFeeratePerkw ?? localConfig.feeratePerKw,
			commitmentFeeratePerkw:
				params.commitmentFeeratePerkw ?? localConfig.feeratePerKw,
			dustLimitSatoshis: localConfig.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: localConfig.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: localConfig.htlcMinimumMsat,
			toSelfDelay: localConfig.toSelfDelay,
			maxAcceptedHtlcs: localConfig.maxAcceptedHtlcs,
			locktime: params.locktime ?? 0,
			localBasepoints: config.localBasepoints,
			localPerCommitmentSeed: config.localPerCommitmentSeed,
			secondPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(config.localPerCommitmentSeed, 0xffffffffffffn - 1n)
			),
			requestFunds: params.requestFunds,
			maxLeaseRates: params.maxLeaseRates,
			channelType: params.channelType,
			fundMax: params.fundMax,
			// Txids case-normalized here so every downstream comparison
			// (provider selection, directed-selection verification) sees the
			// wallet's lowercase form.
			fundingUtxos: params.fundingUtxos
				? {
						utxos: params.fundingUtxos.utxos.map((u) => ({
							txid: u.txid.toLowerCase(),
							vout: u.vout
						})),
						...(params.fundingUtxos.allowTopUp !== undefined
							? { allowTopUp: params.fundingUtxos.allowTopUp }
							: {})
				  }
				: undefined
		};

		return this.channelManager.createDualFundedChannel(peerPubkey, dualParams, {
			trusted: params.trusted,
			contribution: params.contribution
		});
	}

	createFunding(
		channel: Channel,
		fundingTxid: Buffer,
		outputIndex: number,
		signature: Buffer
	): Buffer | null {
		const txidErr = validateBuffer(fundingTxid, 32, 'fundingTxid');
		if (txidErr) throw new Error(txidErr);
		if (!Number.isInteger(outputIndex) || outputIndex < 0) {
			throw new Error(
				`outputIndex must be a non-negative integer, got ${outputIndex}`
			);
		}
		const sigErr = validateBuffer(signature, 64, 'signature');
		if (sigErr) throw new Error(sigErr);
		return this.channelManager.createFunding(
			channel,
			fundingTxid,
			outputIndex,
			signature
		);
	}

	handleFundingConfirmed(channelId: Buffer, confirmedTxidHex?: string): void {
		this.channelManager.handleFundingConfirmed(channelId, confirmedTxidHex);
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;
		const state = channel.getFullState();
		// The confirmation ends the broadcast obligation on manually driven
		// chains too, exactly as onFundingWatchConfirmed retires it on
		// watcher-driven ones: without this the retained parent rebroadcast
		// and renewed its pledges forever (review of issue #412).
		let retired = channel.clearFundingMissingClock();
		if (state.fundingTxid) {
			retired = channel.clearRetainedFundingPayload() || retired;
			this.deletePendingFundingTx(state.fundingTxid.toString('hex'));
		}
		if (retired) this.persistChannel(channelId);
		// Issue #413: manually driven chains have no watcher event to
		// re-drive the close an ERRORED v1 channel skipped while its funding
		// was unconfirmed. fundingConfirmed just stamped the proof; drive it.
		if (
			channel.getState() === ChannelState.ERRORED &&
			state.fundingVersion === 1
		) {
			this.handleChannelErrored(
				channelId,
				'funding confirmed for failed channel'
			);
		}
	}

	closeChannel(
		channelId: Buffer,
		scriptPubkey: Buffer,
		/**
		 * The labelled acknowledgement RECOVERY-PROTOCOL 5.6 asks for. Needed
		 * only on a channel restored from a Recovery Capsule: a mutual close
		 * pays out the balances that row carries, and a stale allocation can
		 * only be the peer-favourable one (issue #469).
		 */
		acceptStaleStateRisk = false
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new Error(cidErr);
		const scriptErr = validateBufferMinMax(
			scriptPubkey,
			1,
			MAX_SCRIPT_SIZE,
			'scriptPubkey'
		);
		if (scriptErr) throw new Error(scriptErr);
		// Durable 'user' marker for closeStatus, stamped BEFORE the shutdown
		// dispatch: with a live peer the whole negotiation can complete
		// synchronously inside initiateShutdown, and once the channel is
		// CLOSED the stamp is write-once refused. If the coop close later
		// times out into a force-close, that path relabels with the terminal
		// reason.
		const channel = this.channelManager.getChannel(channelId);
		const prevReason = channel?.getFullState().closeReason;
		const stamped = channel?.recordCloseReason('user') ?? false;
		const result = this.channelManager.initiateShutdown(
			channelId,
			scriptPubkey,
			acceptStaleStateRisk
		);
		if (!result.ok) {
			if (stamped) {
				channel!.clearCloseReason();
				if (prevReason !== undefined) channel!.recordCloseReason(prevReason);
			}
			this.emit('node:error', {
				code: 'CLOSE_CHANNEL_FAILED',
				channelId,
				message: result.error!,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: result.error };
		}
		// initiateShutdown's own action batch carries no persist of the stamp,
		// so commit it here.
		if (stamped) this.persistChannel(channelId);
		return { ok: true };
	}

	/**
	 * Provide the caller-owed tx_signatures witnesses for a v2 open: the
	 * public answer to the channel:txsigs-needed event (issue 307). The
	 * witnesses cover the input indices the event carried, signed over the
	 * recorded funding tx (the channel's v2InFlight record holds
	 * fundingTxHex and inputPrevouts to re-sign against after a restart).
	 * @param channelId - 32-byte channel ID from the event
	 * @param txid - funding txid from the event (internal byte order)
	 * @param outputIndex - funding output index from the event
	 * @param witnesses - one witness stack per owed input, in index order
	 */
	sendTxSignatures(
		channelId: Buffer,
		txid: Buffer,
		outputIndex: number,
		witnesses: Buffer[][]
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new Error(cidErr);
		const txidErr = validateBuffer(txid, 32, 'txid');
		if (txidErr) throw new Error(txidErr);
		if (!Number.isInteger(outputIndex) || outputIndex < 0) {
			throw new Error(
				`outputIndex must be a non-negative integer, got ${outputIndex}`
			);
		}
		if (
			!Array.isArray(witnesses) ||
			witnesses.some(
				(w) => !Array.isArray(w) || w.some((b) => !Buffer.isBuffer(b))
			)
		) {
			throw new Error('witnesses must be an array of Buffer arrays');
		}
		const result = this.channelManager.provideTxSignatures(
			channelId,
			txid,
			outputIndex,
			witnesses
		);
		if (!result.ok) {
			this.emit('node:error', {
				code: 'SEND_TX_SIGNATURES_FAILED',
				channelId,
				message: result.error!,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: result.error };
		}
		return { ok: true };
	}

	/**
	 * Deliver a third-party input owner's witness for an EXTERNAL funding
	 * input of a v2 open (issue #572): the out-of-band answer to the
	 * externalInputIndices half of channel:txsigs-needed. The witness is
	 * validated against the recorded funding prevouts before it is stored,
	 * and delivering the last outstanding witness releases the withheld
	 * tx_signatures. A refused delivery (unknown outpoint, invalid witness)
	 * leaves the open untouched and can simply be retried with a correct
	 * witness.
	 * @param channelId - 32-byte channel ID from the event
	 * @param prevTxid - txid of the input's previous transaction, INTERNAL
	 *   byte order (tx.getHash(), not the display hex)
	 * @param prevOutputIndex - output index the funding input spends
	 * @param witness - the input's finished witness stack
	 */
	provideV2ExternalWitness(
		channelId: Buffer,
		prevTxid: Buffer,
		prevOutputIndex: number,
		witness: Buffer[]
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new Error(cidErr);
		const txidErr = validateBuffer(prevTxid, 32, 'prevTxid');
		if (txidErr) throw new Error(txidErr);
		if (!Number.isInteger(prevOutputIndex) || prevOutputIndex < 0) {
			throw new Error(
				`prevOutputIndex must be a non-negative integer, got ${prevOutputIndex}`
			);
		}
		if (!Array.isArray(witness) || witness.some((b) => !Buffer.isBuffer(b))) {
			throw new Error('witness must be an array of Buffers');
		}
		const result = this.channelManager.provideV2ExternalWitness(
			channelId,
			prevTxid,
			prevOutputIndex,
			witness
		);
		if (!result.ok) {
			this.emit('node:error', {
				code: 'PROVIDE_EXTERNAL_WITNESS_FAILED',
				channelId,
				message: result.error!,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: result.error };
		}
		return { ok: true };
	}

	/**
	 * Raw channel object by id, for hosts that drive protocol extensions
	 * (direct funding, issue #572) against the state machine directly. Covers
	 * temp-resident channels looked up by their derived permanent id, which
	 * getChannel's map lookup alone cannot resolve during a live v2 exchange.
	 */
	getRawChannel(channelId: Buffer): Channel | null {
		return (
			this.channelManager.getChannel(channelId) ??
			(
				this.channelManager as unknown as {
					findChannelByChannelIdInTemp(id: Buffer): Channel | undefined;
				}
			).findChannelByChannelIdInTemp(channelId) ??
			null
		);
	}

	/**
	 * Update the commitment fee rate on a channel (opener only).
	 * @param channelId - 32-byte channel ID
	 * @param newFeeratePerKw - New fee rate in sat/kw (minimum 253)
	 */
	updateChannelFee(
		channelId: Buffer,
		newFeeratePerKw: number
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new Error(cidErr);
		if (!Number.isInteger(newFeeratePerKw) || newFeeratePerKw < 253) {
			throw new Error(
				`feeratePerKw must be an integer >= 253, got ${newFeeratePerKw}`
			);
		}
		const result = this.channelManager.updateChannelFee(
			channelId,
			newFeeratePerKw
		);
		if (!result.ok) {
			this.emit('node:error', {
				code: 'UPDATE_FEE_FAILED',
				channelId,
				message: result.error!,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: result.error };
		}
		return { ok: true };
	}

	// ─────────────── Routing Fee Policy ───────────────

	/**
	 * Set the ROUTING policy for one channel (or 'all'): fees charged and CLTV
	 * delta required to forward through it, plus the advertised HTLC size
	 * bounds. Partial: unset fields keep any existing override or fall back to
	 * the node-wide defaults. Regenerates and re-broadcasts the channel_update
	 * for announced channels; for unannounced channels a signed update is sent
	 * directly to the peer (BOLT 7 permits this; the peer retains it for route
	 * hints, see maybeAdoptPeerChannelPolicy). Unrelated to the commitment
	 * feerate (updateChannelFee / BOLT 2 update_fee).
	 */
	setChannelPolicy(
		channelId: Buffer | 'all',
		policy: IChannelPolicyUpdate
	): void {
		this.validateChannelPolicyFields(policy);

		let targets: Buffer[];
		if (channelId === 'all') {
			targets = this.channelManager
				.listChannels()
				.map((ch) => ch.getChannelId())
				.filter((id): id is Buffer => id !== null);
		} else {
			const cidErr = validateBuffer(channelId, 32, 'channelId');
			if (cidErr) throw new Error(cidErr);
			if (!this.channelManager.getChannel(channelId)) {
				throw new Error(`Channel not found: ${channelId.toString('hex')}`);
			}
			targets = [channelId];
		}

		for (const target of targets) {
			const hex = target.toString('hex');
			const merged: IChannelPolicyUpdate = {
				...this.channelPolicies.get(hex),
				...policy
			};
			// Cross-field check on the MERGED override: a partial update must not
			// silently invert an existing min/max pair.
			if (
				merged.htlcMinimumMsat !== undefined &&
				merged.htlcMaximumMsat !== undefined &&
				merged.htlcMinimumMsat > merged.htlcMaximumMsat
			) {
				throw new Error(
					`htlcMinimumMsat (${merged.htlcMinimumMsat}) exceeds htlcMaximumMsat (${merged.htlcMaximumMsat})`
				);
			}
			this.channelPolicies.set(hex, merged);
			this.safeStorage(
				() =>
					this.storage!.saveChannelPolicy?.(
						hex,
						LightningNode.serializeChannelPolicy(merged)
					),
				'saveChannelPolicy'
			);
			this.regenerateChannelUpdateForPolicy(target);
			this.emitStructuredLog('channel', 'policy_updated', {
				channelId: hex,
				...LightningNode.serializeChannelPolicy(merged)
			});
		}
	}

	/**
	 * Effective routing policy for a channel: the per-channel override where
	 * set, node-wide defaults otherwise. Returns null for unknown channels.
	 */
	getChannelPolicy(channelId: Buffer): IChannelPolicy | null {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return null;
		const state = channel.getFullState();
		const override = this.channelPolicies.get(channelId.toString('hex'));
		// Same defaults the initial channel_update advertises. Our directional
		// channel_update describes HTLCs WE send outbound over this channel, so
		// both bounds come from what the REMOTE will accept, mirroring exactly
		// what addHtlc enforces:
		// - htlc_maximum_msat: the advertised single-HTLC policy ceiling,
		//   bounded by capacity and the peer's negotiated aggregate
		//   max_htlc_value_in_flight (BOLT 7 requires the advertisement not to
		//   exceed it; a single HTLC can never exceed the aggregate either).
		// - htlc_minimum_msat: the peer's minimum, the smallest HTLC it will
		//   accept from us.
		// Deriving either from our LOCAL config was the wrong side (that
		// bounds the peer's HTLCs toward us) and froze open-time history into
		// gossip: a channel opened under the old 500k-sat in-flight default
		// advertised a 500k ceiling for life, so route finders — including our
		// own — refused payments the channel could easily carry. Observed
		// live: 1M sats refused as NO_ROUTE on a 4.05M channel holding 1.27M
		// spendable. Remote-derived, both bounds self-heal on the next
		// channel_update refresh, and a splice updates the capacity clamp
		// while the peer's negotiated limits stay fixed, as they should.
		const capacityMsat = state.fundingSatoshis * 1000n;
		const defaultHtlcMax =
			state.remoteConfig.maxHtlcValueInFlightMsat > capacityMsat
				? capacityMsat
				: state.remoteConfig.maxHtlcValueInFlightMsat;
		const policy: IChannelPolicy = {
			feeBaseMsat: override?.feeBaseMsat ?? this.forwardingFeeBaseMsat,
			feeProportionalMillionths:
				override?.feeProportionalMillionths ?? this.forwardingFeePropMillionths,
			cltvExpiryDelta: override?.cltvExpiryDelta ?? this.forwardingCltvDelta,
			htlcMinimumMsat:
				override?.htlcMinimumMsat ?? state.remoteConfig.htlcMinimumMsat,
			htlcMaximumMsat: override?.htlcMaximumMsat ?? defaultHtlcMax,
			source:
				override && Object.keys(override).length > 0 ? 'override' : 'default'
		};
		return this.applyLeaseFeeCaps(channelId, policy);
	}

	/**
	 * Fee/CLTV policy the forwarding checks enforce for HTLCs going OUT over
	 * the given channel (the direction our channel_update advertises).
	 */
	private getForwardingPolicyForChannel(channelId: Buffer | undefined): {
		feeBaseMsat: number;
		feeProportionalMillionths: number;
		cltvExpiryDelta: number;
	} {
		const override = channelId
			? this.channelPolicies.get(channelId.toString('hex'))
			: undefined;
		return this.applyLeaseFeeCaps(channelId, {
			feeBaseMsat: override?.feeBaseMsat ?? this.forwardingFeeBaseMsat,
			feeProportionalMillionths:
				override?.feeProportionalMillionths ?? this.forwardingFeePropMillionths,
			cltvExpiryDelta: override?.cltvExpiryDelta ?? this.forwardingCltvDelta
		});
	}

	/**
	 * Clamp a fee policy to the caps we signed into will_fund while WE are
	 * the lessor and the lease is still active (bLIP-0051). The buyer paid
	 * for capped routing fees, so every surface that speaks for the channel
	 * must apply the same caps: the announced and unannounced channel_update
	 * builders, the policy reporting surface, AND the forwarding enforcement.
	 * Clamping only the advertisement while enforcing the raw defaults or
	 * override makes routes that pay the advertised fee die with
	 * fee_insufficient (issue #536 review); this helper is the single
	 * effective-policy point both sides read.
	 */
	private applyLeaseFeeCaps<
		T extends { feeBaseMsat: number; feeProportionalMillionths: number }
	>(channelId: Buffer | undefined, policy: T): T {
		if (!channelId) return policy;
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return policy;
		const st = channel.getFullState();
		if (
			!st.isLessor ||
			st.leaseExpiry === undefined ||
			(this.currentBlockHeight !== 0 &&
				this.currentBlockHeight >= st.leaseExpiry)
		) {
			return policy;
		}
		const capped = { ...policy };
		if (
			st.leaseChannelFeeMaxBaseMsat !== undefined &&
			capped.feeBaseMsat > st.leaseChannelFeeMaxBaseMsat
		) {
			capped.feeBaseMsat = st.leaseChannelFeeMaxBaseMsat;
		}
		if (st.leaseChannelFeeMaxProportionalThousandths !== undefined) {
			const capMillionths = st.leaseChannelFeeMaxProportionalThousandths * 1000;
			if (capped.feeProportionalMillionths > capMillionths) {
				capped.feeProportionalMillionths = capMillionths;
			}
		}
		return capped;
	}

	private validateChannelPolicyFields(policy: IChannelPolicyUpdate): void {
		if (
			policy.feeBaseMsat === undefined &&
			policy.feeProportionalMillionths === undefined &&
			policy.cltvExpiryDelta === undefined &&
			policy.htlcMinimumMsat === undefined &&
			policy.htlcMaximumMsat === undefined
		) {
			throw new Error('policy must set at least one field');
		}
		// channel_update encodes these as u32/u32/u16; out-of-range values would
		// wrap on the wire and advertise a policy we do not enforce.
		if (policy.feeBaseMsat !== undefined) {
			if (
				!Number.isInteger(policy.feeBaseMsat) ||
				policy.feeBaseMsat < 0 ||
				policy.feeBaseMsat > 0xffffffff
			) {
				throw new Error(
					`feeBaseMsat must be an integer in [0, 4294967295], got ${policy.feeBaseMsat}`
				);
			}
		}
		if (policy.feeProportionalMillionths !== undefined) {
			if (
				!Number.isInteger(policy.feeProportionalMillionths) ||
				policy.feeProportionalMillionths < 0 ||
				policy.feeProportionalMillionths > 0xffffffff
			) {
				throw new Error(
					`feeProportionalMillionths must be an integer in [0, 4294967295], got ${policy.feeProportionalMillionths}`
				);
			}
		}
		if (policy.cltvExpiryDelta !== undefined) {
			// Zero would leave no window to claim a forwarded HTLC on-chain after
			// learning the preimage (loss of the forwarded amount). BOLT 2/7
			// guidance recommends >= 18; small positive values are allowed but at
			// the operator's own risk.
			if (
				!Number.isInteger(policy.cltvExpiryDelta) ||
				policy.cltvExpiryDelta < 1 ||
				policy.cltvExpiryDelta > 0xffff
			) {
				throw new Error(
					`cltvExpiryDelta must be an integer in [1, 65535] (>= 18 recommended), got ${policy.cltvExpiryDelta}`
				);
			}
		}
		if (
			policy.htlcMinimumMsat !== undefined &&
			(typeof policy.htlcMinimumMsat !== 'bigint' ||
				policy.htlcMinimumMsat < 0n)
		) {
			throw new Error(
				`htlcMinimumMsat must be a non-negative bigint, got ${policy.htlcMinimumMsat}`
			);
		}
		if (
			policy.htlcMaximumMsat !== undefined &&
			(typeof policy.htlcMaximumMsat !== 'bigint' ||
				policy.htlcMaximumMsat < 0n)
		) {
			throw new Error(
				`htlcMaximumMsat must be a non-negative bigint, got ${policy.htlcMaximumMsat}`
			);
		}
		if (
			policy.htlcMinimumMsat !== undefined &&
			policy.htlcMaximumMsat !== undefined &&
			policy.htlcMinimumMsat > policy.htlcMaximumMsat
		) {
			throw new Error(
				`htlcMinimumMsat (${policy.htlcMinimumMsat}) exceeds htlcMaximumMsat (${policy.htlcMaximumMsat})`
			);
		}
	}

	private static serializeChannelPolicy(
		policy: IChannelPolicyUpdate
	): IPersistedChannelPolicy {
		const out: IPersistedChannelPolicy = {};
		if (policy.feeBaseMsat !== undefined) out.feeBaseMsat = policy.feeBaseMsat;
		if (policy.feeProportionalMillionths !== undefined)
			out.feeProportionalMillionths = policy.feeProportionalMillionths;
		if (policy.cltvExpiryDelta !== undefined)
			out.cltvExpiryDelta = policy.cltvExpiryDelta;
		if (policy.htlcMinimumMsat !== undefined)
			out.htlcMinimumMsat = policy.htlcMinimumMsat.toString();
		if (policy.htlcMaximumMsat !== undefined)
			out.htlcMaximumMsat = policy.htlcMaximumMsat.toString();
		return out;
	}

	/**
	 * Push the (new) effective policy out as a channel_update. Announced
	 * channels: rewrite the cached update, re-add to our graph, and broadcast
	 * to all peers. Unannounced channels: sign a fresh update and send it
	 * directly to the peer only.
	 */
	private regenerateChannelUpdateForPolicy(channelId: Buffer): void {
		const hex = channelId.toString('hex');
		const gossip = this._ownChannelGossip.get(hex);
		if (gossip) {
			// Strictly increasing timestamp: peers dedupe an unchanged one, so a
			// same-second policy change would never propagate.
			let timestamp = Math.floor(Date.now() / 1000);
			try {
				timestamp = Math.max(
					timestamp,
					decodeChannelUpdateMessage(gossip.update).timestamp + 1
				);
			} catch {
				// Unreadable cached update; fall through with the wall-clock time.
			}
			const refreshed = this.refreshChannelUpdate(
				gossip.update,
				timestamp,
				channelId
			);
			if (!refreshed) return;
			this._ownChannelGossip.set(hex, {
				announcement: gossip.announcement,
				update: refreshed
			});
			try {
				this.graph.applyChannelUpdate(decodeChannelUpdateMessage(refreshed), {
					verified: true
				});
			} catch {
				// Own-update decode failure only affects our local graph view.
			}
			this.broadcastOwnGossip();
			return;
		}

		const payload = this.buildDirectChannelUpdate(channelId);
		if (!payload) return;
		const peer = this.channelManager.getPeerForChannel(channelId);
		if (!peer) return;
		if (this.peerManager) {
			try {
				this.peerManager.sendToPeer(peer, MessageType.CHANNEL_UPDATE, payload);
			} catch {
				// Peer not connected; it will learn the policy from route hints.
			}
		} else {
			this.emitOutbound(peer, MessageType.CHANNEL_UPDATE, payload);
		}
	}

	/**
	 * Build and sign a channel_update for an UNANNOUNCED channel, addressed by
	 * the SCID the peer routes to us with (see getPeerAddressableScid): the real
	 * SCID once confirmed, or the alias the peer gave us, and never the real SCID
	 * on an option_scid_alias channel.
	 */
	/**
	 * BOLT 7 channel_flags with the direction bit for our side of this channel,
	 * plus the disable bit (0x02) when forwarding is off. Disabling OUR
	 * direction tells route finders not to route FROM us across the channel,
	 * which is exactly the promise a forwarding opt-out makes; the peer's
	 * opposite direction still lets payments reach us as the final recipient.
	 */
	private ourChannelFlags(ourNodeId: Buffer, peerNodeId: Buffer): number {
		const direction = Buffer.compare(ourNodeId, peerNodeId) < 0 ? 0 : 1;
		return direction | (this.forwardingEnabled ? 0 : 0x02);
	}

	private buildDirectChannelUpdate(channelId: Buffer): Buffer | null {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return null;
		const state = channel.getFullState();
		const scid = this.getPeerAddressableScid(state);
		if (!scid) return null;
		const peerHex = this.channelManager.getPeerForChannel(channelId);
		if (!peerHex) return null;
		const policy = this.getChannelPolicy(channelId);
		if (!policy) return null;
		try {
			const ourNodeId = getPublicKey(this.nodePrivkey);
			const peerNodeId = Buffer.from(peerHex, 'hex');
			// BOLT 7: htlc_maximum_msat MUST NOT exceed the channel capacity.
			const capacityMsat = state.fundingSatoshis * 1000n;
			const htlcMaxMsat =
				policy.htlcMaximumMsat > capacityMsat
					? capacityMsat
					: policy.htlcMaximumMsat;
			const payload = encodeChannelUpdateMessage({
				signature: Buffer.alloc(64), // placeholder, signed below
				// Match the chain scope the receiver enforces (acceptableChainHashes),
				// defaulting to OUR network's hash — never mainnet (S-7.M1).
				chainHash: this.acceptableChainHashes[0] ?? this.chainHash(),
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				// bit 0: htlc_maximum_msat present; bit 1: dont_forward — this
				// update is for an UNANNOUNCED channel, so a peer relaying it would
				// leak private-channel existence and policy (BOLT 7).
				messageFlags: 0x01 | 0x02,
				channelFlags: this.ourChannelFlags(ourNodeId, peerNodeId),
				cltvExpiryDelta: policy.cltvExpiryDelta,
				htlcMinimumMsat: policy.htlcMinimumMsat,
				feeBaseMsat: policy.feeBaseMsat,
				feeProportionalMillionths: policy.feeProportionalMillionths,
				htlcMaximumMsat: htlcMaxMsat
			});
			const sig = signChannelUpdate(payload, this.nodePrivkey);
			sig.copy(payload, 0);
			return payload;
		} catch {
			return null;
		}
	}

	/**
	 * Force-close with a durable reason: stamps state.closeReason BEFORE the
	 * close so it persists in the same channel:closed commit that records
	 * FORCE_CLOSED, registers the commitment txid for broadcast-success
	 * tracking, and clears the stamp again if the close was refused. Wraps
	 * channelManager.forceClose and returns its result unchanged.
	 */
	private _forceCloseWithReason(
		channelId: Buffer,
		destinationScript: Buffer,
		feeRatePerVbyte: number,
		reason: ChannelCloseReason
	): ChannelResult {
		const channel = this.channelManager.getChannel(channelId);
		const prevReason = channel?.getFullState().closeReason;
		const stamped = channel?.recordCloseReason(reason) ?? false;
		const result = this.channelManager.forceClose(
			channelId,
			destinationScript,
			feeRatePerVbyte
		);
		if (!result.ok) {
			// A refused close must not leave this attempt's label behind, but
			// it must also not erase a reason an earlier close attempt validly
			// recorded (e.g. 'user' from a coop close a failed automatic
			// escalation tried to relabel).
			if (stamped) {
				channel!.clearCloseReason();
				if (prevReason !== undefined) channel!.recordCloseReason(prevReason);
			}
			return result;
		}
		for (const action of result.actions) {
			if (action.type === 'BROADCAST_TX' && 'tx' in action) {
				this._registerCloseTxid(
					channelId.toString('hex'),
					bitcoin.Transaction.fromBuffer(action.tx).getId()
				);
				break;
			}
		}
		return result;
	}

	/**
	 * Record the close tx the engine is trying to get on chain. The entry
	 * starts with ok false (attempted, not known to have reached the network)
	 * so closeStatus can report the txid even while broadcast keeps failing,
	 * which is exactly the window a manual rebroadcast exists for;
	 * broadcast:success flips it to true. Never downgrades an existing
	 * success for the same txid.
	 */
	private _registerCloseTxid(idHex: string, txid: string): void {
		this._pendingCloseTxids.set(txid, idHex);
		const prev = this._lastCloseBroadcast.get(idHex);
		if (!prev || prev.txid !== txid) {
			this._lastCloseBroadcast.set(idHex, { txid, ok: false });
		}
	}

	forceCloseChannel(
		channelId: Buffer,
		destinationScript: Buffer
	): { ok: boolean; error?: string; commitmentTxid?: string } {
		const result = this._forceCloseWithReason(
			channelId,
			destinationScript,
			this.resolveForceCloseFeeRatePerVbyte(),
			'user'
		);
		if (!result.ok) {
			this.emit('node:error', {
				code: 'FORCE_CLOSE_FAILED',
				channelId,
				message: result.error!,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: result.error };
		}
		// Extract commitment txid from BROADCAST_TX action
		let commitmentTxid: string | undefined;
		for (const action of result.actions) {
			if (action.type === 'BROADCAST_TX' && 'tx' in action) {
				const tx = bitcoin.Transaction.fromBuffer(action.tx);
				commitmentTxid = tx.getId();
				break;
			}
		}
		return { ok: true, commitmentTxid };
	}

	/**
	 * Manually rebroadcast the recorded close transaction of a channel whose
	 * close may not have reached the network: the latest commitment of a
	 * FORCE_CLOSED channel (rebuilt byte-identically from current state), or
	 * the stored mutual close of a CLOSED channel that has not confirmed.
	 * Takes only a channelId by design: there is no way to select an older
	 * (revoked) state, the rebuild always derives from what the engine would
	 * broadcast itself. Idempotent: a duplicate is rejected harmlessly by the
	 * network and reported as success, and a confirmed close is a no-op.
	 */
	async rebroadcastClose(channelId: Buffer): Promise<{
		ok: boolean;
		error?: string;
		txid?: string;
		broadcastOk?: boolean;
	}> {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) return { ok: false, error: cidErr };
		const idHex = channelId.toString('hex');
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			return { ok: false, error: `Channel not found: ${idHex}` };
		}
		const state = channel.getState();
		const monitor = this.channelManager.getMonitor(channelId);
		// A CONFIRMED close needs no rebroadcast: no-op success. The gate is
		// isCommitmentConfirmed alone, deliberately not isFullyResolved: every
		// close now waits out IRREVOCABLE_DEPTH before resolving (issue #338),
		// and an unconfirmed mutual close is exactly what this route exists to
		// re-send.
		const closeSettled =
			monitor !== undefined && monitor.isCommitmentConfirmed();
		if (
			closeSettled &&
			(state === ChannelState.FORCE_CLOSED || state === ChannelState.CLOSED)
		) {
			return {
				ok: true,
				txid: monitor!.getFullState().commitmentBroadcast?.txid,
				broadcastOk: true
			};
		}

		if (state === ChannelState.FORCE_CLOSED) {
			const rebuilt = this.channelManager.rebuildForceCloseCommitment(
				channelId,
				this.resolveForceCloseFeeRatePerVbyte()
			);
			if (!rebuilt.ok || !rebuilt.tx) {
				return { ok: false, error: rebuilt.error };
			}
			const txid = bitcoin.Transaction.fromBuffer(rebuilt.tx).getId();
			const broadcastOk = await this._broadcastCloseTx(idHex, txid, rebuilt.tx);
			return { ok: true, txid, broadcastOk };
		}

		if (state === ChannelState.CLOSED) {
			const closeHex = channel.getFullState().lastCooperativeCloseTxHex;
			if (!closeHex) {
				return {
					ok: false,
					error: 'No close transaction recorded for this channel'
				};
			}
			let closeTx: bitcoin.Transaction;
			try {
				closeTx = bitcoin.Transaction.fromHex(closeHex);
			} catch {
				return { ok: false, error: 'Recorded close transaction is invalid' };
			}
			const txid = closeTx.getId();
			const broadcastOk = await this._broadcastCloseTx(
				idHex,
				txid,
				closeTx.toBuffer()
			);
			return { ok: true, txid, broadcastOk };
		}

		return { ok: false, error: `Channel is not closed (state ${state})` };
	}

	/**
	 * Broadcast a close tx exactly once through the watcher (or the raw
	 * backend before the watcher exists) and record the outcome for
	 * closeStatus. A duplicate rejection counts as success: that is the
	 * network saying the tx is already known.
	 */
	private async _broadcastCloseTx(
		idHex: string,
		txid: string,
		tx: Buffer
	): Promise<boolean> {
		this._pendingCloseTxids.set(txid, idHex);
		let ok = false;
		try {
			if (this.chainWatcher) {
				await this.chainWatcher.broadcastTransaction(tx);
				ok = true;
			} else if (this._chainBackend) {
				await this._chainBackend.broadcastTransaction(tx.toString('hex'));
				ok = true;
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			// Only the KNOWN duplicate-transaction rejections count as success
			// (same allowlist as broadcastPendingFundingTx). A broad match is
			// dangerous: "Input already spent by conflicting transaction" also
			// says "already" but means this tx can never be in the network.
			ok = /already in block ?chain|already known|txn-already/i.test(msg);
		}
		this._lastCloseBroadcast.set(idHex, { txid, ok });
		return ok;
	}

	/**
	 * Issue #357: a splice that confirms on a FORCE_CLOSED channel voids the
	 * old-funding commitment we broadcast (both spend the old funding
	 * outpoint), and until now only an operator rebroadcastClose re-planned
	 * the close. Rebuild through the force-close planner (whose splice
	 * adoption moves the channel onto the confirmed new funding), persist the
	 * adoption, and broadcast once, exactly as the manual path does. A
	 * failed broadcast is retried each block. Rebuild refusals are final
	 * (deterministic: a peer commitment having won refuses identically every
	 * time), except a bare confirmed-close refusal while a confirmed record
	 * still awaits adoption: that monitor state can be a stale pre-reorg
	 * record the funding-spend reconcile has yet to demote, so it retries.
	 */
	private async redriveSpliceAdoptedClose(channelId: Buffer): Promise<void> {
		const idHex = channelId.toString('hex');
		this._pendingSpliceCloseRedrives.delete(idHex);
		try {
			const rebuilt = this.channelManager.rebuildForceCloseCommitment(
				channelId,
				this.resolveForceCloseFeeRatePerVbyte()
			);
			if (!rebuilt.ok || !rebuilt.tx) {
				// A monitor-state refusal can be STALE: the splice that just
				// confirmed spends the same funding outpoint as the "confirmed"
				// old commitment, and the funding-spend reconcile demotes the
				// stale record only after this callback. While a confirmed
				// record still awaits adoption, retry each block instead of
				// dropping the re-drive.
				const ch = this.channelManager.getChannel(channelId);
				const chState = ch?.getFullState();
				const confirmedAdoption =
					chState?.spliceInFlight?.confirmed === true ||
					// A v2 RBF candidate adoption (issue #360) re-drives on the
					// same machinery and retries the same way.
					(chState?.fundingVersion === 2 &&
						chState.v2InFlight?.confirmed === true);
				if (rebuilt.retryable === true && confirmedAdoption) {
					this._pendingSpliceCloseRedrives.add(idHex);
				}
				this.emitStructuredLog('chain', 'splice_close_redrive_refused', {
					channelId: idHex,
					error: rebuilt.error
				});
				return;
			}
			// The rebuild's splice adoption mutated durable state (the new
			// funding outpoint, capacity and balances): persist BEFORE the tx
			// reaches the network, as every funding-critical broadcast does.
			this.persistChannel(channelId);
			const txid = bitcoin.Transaction.fromBuffer(rebuilt.tx).getId();
			const broadcastOk = await this._broadcastCloseTx(idHex, txid, rebuilt.tx);
			if (!broadcastOk) {
				this._pendingSpliceCloseRedrives.add(idHex);
			}
			this.emitStructuredLog('chain', 'splice_close_redriven', {
				channelId: idHex,
				txid,
				broadcastOk
			});
		} catch (err) {
			this._pendingSpliceCloseRedrives.add(idHex);
			this.emitStructuredLog('chain', 'splice_close_redrive_failed', {
				channelId: idHex,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	/**
	 * Per-block retry of splice-adopted close re-drives whose broadcast
	 * failed (issue #357): the channel is terminal, so no later transition
	 * exists for the broadcast to ride.
	 */
	/**
	 * Arm a per-output watch, queueing it for per-block retry if the backend
	 * cannot serve it right now (issue #577).
	 *
	 * The failure this exists for is not a transient hiccup: a reorg that
	 * evicts the commitment makes getTransaction(commitment txid) fail for as
	 * long as the eviction lasts, and the swallowed catch left those outputs
	 * with NO watch for the rest of the process's life, while the monitor's
	 * per-output state kept advancing as though one were arming. Nothing else
	 * re-arms them: restoreChainWatches runs once per start, and the watcher's
	 * own retry queue only covers subscription failures, not this fetch.
	 */
	private async armOutputWatch(
		channelIdHex: string,
		txid: string,
		outputIndex: number,
		seedTxid?: string,
		seedHeight?: number
	): Promise<void> {
		try {
			await this.chainWatcher!.watchOutputByTxid(
				txid,
				outputIndex,
				seedTxid,
				seedHeight
			);
		} catch {
			this._pendingOutputWatches.set(`${txid}:${outputIndex}`, {
				channelIdHex,
				txid,
				outputIndex
			});
		}
	}

	/**
	 * Per-block drain of output watches whose arming failed (issue #577). The
	 * seed is re-read from the monitor each attempt rather than remembered, so
	 * a spend recorded, evicted or resolved since the failure re-arms with
	 * what is true NOW, and an output that has since resolved (or whose
	 * channel is gone) simply drops out of the queue.
	 */
	/**
	 * The channel whose monitor tracks this output, resolved by scan because
	 * the watch:output:requested event carries only the outpoint. Called only
	 * when arming failed (issue #577), so the scan is off the hot path.
	 */
	private _channelHexForTrackedOutput(
		txid: string,
		outputIndex: number
	): string | null {
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			const id = state.channelId ?? state.temporaryChannelId;
			const monitor = this.channelManager.getMonitor(id);
			if (!monitor) continue;
			const tracked = monitor
				.getTrackedOutputs()
				.some((o) => o.txid === txid && o.outputIndex === outputIndex);
			if (tracked) return id.toString('hex');
		}
		return null;
	}

	private retryPendingOutputWatches(): void {
		if (this._pendingOutputWatches.size === 0 || !this.chainWatcher) return;
		const pending = [...this._pendingOutputWatches.values()];
		this._pendingOutputWatches.clear();
		for (const entry of pending) {
			const monitor = this.channelManager.getMonitor(
				Buffer.from(entry.channelIdHex, 'hex')
			);
			if (!monitor || monitor.isFullyResolved()) continue;
			const output = monitor
				.getTrackedOutputs()
				.find(
					(o) => o.txid === entry.txid && o.outputIndex === entry.outputIndex
				);
			if (!output || output.status === OutputStatus.IRREVOCABLY_RESOLVED) {
				continue;
			}
			const seedTxid =
				output.status === OutputStatus.SPEND_CONFIRMED
					? output.resolutionTxid
					: undefined;
			void this.armOutputWatch(
				entry.channelIdHex,
				entry.txid,
				entry.outputIndex,
				seedTxid,
				seedTxid !== undefined ? output.confirmationHeight : undefined
			);
		}
	}

	private retrySpliceCloseRedrives(): void {
		if (this._pendingSpliceCloseRedrives.size === 0) return;
		for (const idHex of [...this._pendingSpliceCloseRedrives]) {
			const channelId = Buffer.from(idHex, 'hex');
			const channel = this.channelManager.getChannel(channelId);
			if (!channel || channel.getState() !== ChannelState.FORCE_CLOSED) {
				this._pendingSpliceCloseRedrives.delete(idHex);
				continue;
			}
			void this.redriveSpliceAdoptedClose(channelId);
		}
	}

	// ─────────────── Splicing ───────────────

	/**
	 * Splice-in: add funds to an existing channel.
	 * The channel must first be quiesced. This method handles quiescence
	 * initiation if the channel is in NORMAL state, or proceeds directly
	 * if already quiescent.
	 *
	 * @param channelId - The channel to splice into
	 * @param amountSats - Amount to add (positive value)
	 * @param fundingFeeratePerkw - Feerate for the splice tx (default 253)
	 */
	spliceIn(
		channelId: Buffer,
		amountSats: bigint,
		fundingFeeratePerkw = 253
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new InvalidSpliceError(cidErr);
		const satsErr = validatePositiveBigint(amountSats, 'amountSats');
		if (satsErr) throw new InvalidSpliceError(satsErr);
		// splice_init carries funding_feerate_perkw as a u32. Refuse a bad one
		// here: encoding happens AFTER the channel has moved to SPLICING and
		// persisted, so a throw there leaves the channel wedged until restart.
		const feeErr = validateU32(fundingFeeratePerkw, 'fundingFeeratePerkw', {
			min: 1
		});
		if (feeErr) throw new InvalidSpliceError(feeErr);

		// Splice-in must fund the channel increase with wallet inputs. Source them
		// from the funding provider (UTXO selection + change + per-input signing),
		// set them on the channel, then initiate. Sourcing is async, so this mirrors
		// the auto-funding pattern: return optimistically and surface failures via
		// the node:error event.
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			return {
				ok: false,
				error: `Channel not found: ${channelId.toString('hex')}`
			};
		}
		const spliceInErr = this._validateSpliceRequest(channelId, amountSats);
		if (spliceInErr) {
			this.emit('node:error', {
				code: 'SPLICE_IN_FAILED',
				channelId,
				message: spliceInErr,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: spliceInErr };
		}
		// The issue #423 splice-in reserve rule lives in channel.initiateSplice
		// (after input selection, below): it arms only when the selection's
		// change output will actually be emitted, which a pre-selection check
		// here cannot know, and it must read the balance current at initiation,
		// not the one from before the asynchronous selection.
		if (!this.fundingProvider?.selectSpliceInputs) {
			const error =
				'splice-in requires a funding provider with selectSpliceInputs (wallet UTXO sourcing)';
			this.emit('node:error', {
				code: 'SPLICE_IN_FAILED',
				channelId,
				message: error,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error };
		}

		this.fundingProvider
			.selectSpliceInputs(amountSats, fundingFeeratePerkw)
			.then(({ inputs, changeScript }) => {
				channel.setSpliceInInputs(inputs, changeScript);
				const result = this.channelManager.initiateSplice(
					channelId,
					amountSats,
					fundingFeeratePerkw
				);
				if (!result.ok) {
					this.emit('node:error', {
						code: 'SPLICE_IN_FAILED',
						channelId,
						message: result.error!,
						timestamp: Date.now()
					} as ILightningError);
				}
			})
			.catch((err) => {
				this.emit('node:error', {
					code: 'SPLICE_IN_FAILED',
					channelId,
					message: (err as Error).message,
					timestamp: Date.now()
				} as ILightningError);
			});

		return { ok: true };
	}

	/**
	 * Splice-in and wait for the splice to lock (issue #572): resolves on the
	 * splice:complete event for this channel, rejects on a SPLICE_IN_FAILED
	 * node error scoped to it, on splice:aborted for it (a peer tx_abort
	 * unwinds the splice back to NORMAL without any failure error), or on
	 * timeout. The channel id is stable across a splice, so every signal
	 * scopes precisely. Listeners are registered BEFORE spliceIn runs so a
	 * synchronous transport cannot lose the completion; a synchronous
	 * spliceIn refusal (returned or thrown) unwinds the wait and throws.
	 */
	async spliceInAndWait(
		channelId: Buffer,
		amountSats: bigint,
		timeoutMs = 120_000,
		fundingFeeratePerkw?: number
	): Promise<void> {
		if (this._destroyed) throw new Error('Node destroyed');
		const cidHex = channelId.toString('hex');
		let cancelWait: () => void = () => undefined;
		const done = new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				reject(
					new Error(
						`splice on ${cidHex.slice(0, 12)} not locked within ${timeoutMs}ms`
					)
				);
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.removeListener('splice:complete', onComplete);
				this.removeListener('splice:aborted', onSpliceAborted);
				this.removeListener('node:error', onError);
				this._activeWaitCleanups.delete(destroyCleanup);
			};
			// Some spliceIn refusals return (or throw) without emitting
			// SPLICE_IN_FAILED; the sync failure paths below unwind through
			// this so the timer and listeners never outlive the call.
			cancelWait = cleanup;

			const destroyCleanup = (): void => {
				cleanup();
				reject(new Error('Node destroyed'));
			};
			this._activeWaitCleanups.add(destroyCleanup);

			const onComplete = (data: { channelId: Buffer }): void => {
				if (data.channelId.toString('hex') !== cidHex) return;
				cleanup();
				resolve();
			};
			// A peer tx_abort unwinds the splice back to NORMAL without any
			// SPLICE_IN_FAILED; without this arm the wait burned its full
			// timeout on a splice that was already over (issue #572 review).
			const onSpliceAborted = (data: {
				channelId: Buffer;
				reason: string;
			}): void => {
				if (data.channelId.toString('hex') !== cidHex) return;
				cleanup();
				reject(new Error(data.reason));
			};
			const onError = (err: ILightningError): void => {
				if (err.code !== 'SPLICE_IN_FAILED') return;
				if (err.channelId?.toString('hex') !== cidHex) return;
				cleanup();
				reject(new Error(err.message));
			};

			this.on('splice:complete', onComplete);
			this.on('splice:aborted', onSpliceAborted);
			this.on('node:error', onError);
		});
		// Absorb the rejection when an emitted SPLICE_IN_FAILED settles the
		// race before the synchronous throw below; without this the throw
		// leaves `done` behind as an unhandled rejection.
		done.catch(() => undefined);

		let result: { ok: boolean; error?: string };
		try {
			result = this.spliceIn(channelId, amountSats, fundingFeeratePerkw ?? 253);
		} catch (err) {
			// Validation throws (InvalidSpliceError) must not leave the timer
			// and listeners armed for the full window.
			cancelWait();
			throw err;
		}
		if (!result.ok) {
			cancelWait();
			throw new Error(result.error ?? 'splice-in failed to start');
		}
		await done;
	}

	/**
	 * Bump the fee of an unconfirmed v2 (dual-funded) open by replacing its
	 * funding transaction (BOLT 2 tx_init_rbf / tx_ack_rbf; issue #360).
	 * Opener-only. Cannot run after a restart (the wallet signing closures die
	 * with the process). Permitted until channel_ready crosses or an attempt
	 * confirms. Superseded attempts stay chain-watched, and whichever attempt
	 * confirms is adopted. The new feerate must clear the BOLT 2 floor:
	 * max(floor(previous * 25 / 24), previous + 25) sat/kw.
	 *
	 * `fundingSatoshis` changes OUR contribution to the funding output for the
	 * replacement (BOLT 2 allows a different one per attempt; issue #376);
	 * omitted keeps the current share. Lowering it, or raising it within what
	 * the registered inputs already cover, is answered synchronously. Raising
	 * it beyond that needs fresh coins, so the wallet selection runs in the
	 * background: this returns `{ ok: true }` optimistically and a failure
	 * arrives as a `node:error` with code `RBF_OPEN_FAILED`, mirroring
	 * spliceIn. Leased opens (bLIP-51) cannot change their split at all.
	 */
	rbfOpenChannelV2(
		channelId: Buffer,
		fundingFeeratePerkw: number,
		locktime?: number,
		fundingSatoshis?: bigint
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new Error(cidErr);
		// Both integers ride u32 wire fields: validate BEFORE anything on the
		// channel can mutate, so an out-of-range value cannot poison the
		// pending-request latch.
		if (
			!Number.isInteger(fundingFeeratePerkw) ||
			fundingFeeratePerkw <= 0 ||
			fundingFeeratePerkw > 0xffffffff
		) {
			throw new Error(
				`fundingFeeratePerkw must be a u32 greater than zero, got ${fundingFeeratePerkw}`
			);
		}
		if (
			locktime !== undefined &&
			(!Number.isInteger(locktime) || locktime < 0 || locktime > 0xffffffff)
		) {
			throw new Error(`locktime must be a u32, got ${locktime}`);
		}
		if (fundingSatoshis === undefined) {
			const result = this.channelManager.initiateFundingRbf(
				channelId,
				fundingFeeratePerkw,
				locktime
			);
			return result.ok ? { ok: true } : { ok: false, error: result.error };
		}
		if (typeof fundingSatoshis !== 'bigint' || fundingSatoshis <= 0n) {
			throw new Error(
				`fundingSatoshis must be a positive bigint, got ${fundingSatoshis}`
			);
		}
		// Rides a signed 64-bit TLV; the channel's encode would throw, but a
		// throw there is a caller error either way, so name it here.
		if (fundingSatoshis > 0x7fffffffffffffffn) {
			throw new Error(
				`fundingSatoshis exceeds the funding_output_contribution range, got ${fundingSatoshis}`
			);
		}
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			return {
				ok: false,
				error: `Channel not found: ${channelId.toString('hex')}`
			};
		}
		// How much (if anything) the wallet must add before this raise is
		// affordable. Decreases and covered raises quote 0 and stay on the
		// synchronous path.
		const quote = channel.quoteV2RbfContributionChange(
			fundingSatoshis,
			fundingFeeratePerkw
		);
		if (!quote.ok) return { ok: false, error: quote.error };
		if (quote.topUpSats === 0n) {
			const result = this.channelManager.initiateFundingRbf(
				channelId,
				fundingFeeratePerkw,
				locktime,
				{ fundingSatoshis }
			);
			return result.ok ? { ok: true } : { ok: false, error: result.error };
		}
		const provider = this.fundingProvider;
		if (!canSelectDualFundingInputs(provider)) {
			return {
				ok: false,
				error:
					'raising the funding contribution requires a funding provider that can select wallet inputs'
			};
		}
		// Optimistic, like spliceIn: the selection is asynchronous, so the
		// request itself is reported through node:error if it fails.
		// RBF initiation is opener-only, so this is always the initiator's fee
		// share; read it from the session rather than assume it. topUp = true:
		// quote.topUpSats already covers the contribution's fixed fee terms over
		// the registered inputs, so the selection owes only the marginal weight
		// of the coins it adds.
		selectDualFundingContribution(
			provider,
			quote.topUpSats,
			fundingFeeratePerkw,
			channel.getDualFundingSession()?.isInitiator() ?? true,
			true
		)
			.then(({ inputs }) => {
				const result = this.channelManager.initiateFundingRbf(
					channelId,
					fundingFeeratePerkw,
					locktime,
					{ fundingSatoshis, topUpInputs: inputs }
				);
				if (!result.ok) {
					// The refusal path already handed the pledges back (the
					// manager drains the channel's stash), so only report.
					this.emit('node:error', {
						code: 'RBF_OPEN_FAILED',
						channelId,
						message: result.error!,
						timestamp: Date.now()
					} as ILightningError);
				}
			})
			.catch((err) => {
				this.emit('node:error', {
					code: 'RBF_OPEN_FAILED',
					channelId,
					message: (err as Error).message,
					timestamp: Date.now()
				} as ILightningError);
			});
		return { ok: true };
	}

	/**
	 * Splice-out: withdraw funds from an existing channel.
	 * The channel must first be quiesced.
	 *
	 * @param channelId - The channel to splice from
	 * @param amountSats - Amount to withdraw (positive value, will be negated)
	 * @param fundingFeeratePerkw - Feerate for the splice tx (default 253)
	 * @param destinationScript - Optional output script (scriptPubKey) to receive
	 *   the withdrawn funds. Defaults to the node's configured sweep script
	 *   (getSweepDestinationScript()). Passing an external script pays that
	 *   address directly from the channel balance inside the splice funding
	 *   transaction. Only this splice-out is affected; force-close and justice
	 *   sweeps continue to use the sweep script.
	 */
	/**
	 * Price a splice without performing one: the on-chain fee and the largest
	 * amount that can actually move at this feerate. Splice-in asks the funding
	 * provider (same UTXO filter and weight formula as the real selection);
	 * splice-out prices from the channel's own spendable balance net of the
	 * reserve the peer actually set. Exists so a UI never has to reconstruct
	 * this arithmetic and offer an amount the daemon then rejects.
	 */
	spliceQuote(
		channelId: Buffer,
		direction: 'in' | 'out',
		fundingFeeratePerkw = 253
	): {
		direction: 'in' | 'out';
		feeSats: number;
		spendableSats: number;
		maxAmountSats: number;
		reserveSats?: number;
		inputCount?: number;
	} {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new InvalidSpliceError(cidErr);
		const feeErr = validateU32(fundingFeeratePerkw, 'fundingFeeratePerkw', {
			min: 1
		});
		if (feeErr) throw new InvalidSpliceError(feeErr);
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			throw new ChannelFundingUnavailableError(
				ChannelFundingUnavailableCode.CHANNEL_NOT_FOUND,
				`Channel not found: ${channelId.toString('hex')}`
			);
		}

		if (direction === 'out') {
			const destination = this.getSweepDestinationScript();
			const feeSats = spliceFeeSats(
				estimateSpliceTxWeight({
					walletInputCount: 0,
					destinationScriptLen: destination.length
				}),
				fundingFeeratePerkw
			);
			const state = channel.getFullState();
			const stored = state.remoteConfig?.channelReserveSatoshis ?? 0n;
			const local = channel.getBalances().localMsat / 1000n;
			// spliceOut prices the kept reserve at the POST-splice capacity, so
			// the advertised maximum must be solved against that same predicate:
			// pricing at the current capacity understates it whenever the stored
			// reserve sits below the derived one (issue #423 review). The
			// predicate is monotone in the amount (the derived reserve only
			// shrinks as more is withdrawn, and never faster than the
			// withdrawal grows), so binary search finds the boundary.
			const admits = (amountSats: bigint): boolean => {
				const derived = channel.spliceReserveWeKeepSats(
					state.fundingSatoshis - amountSats - feeSats
				);
				const reserve = derived > stored ? derived : stored;
				return amountSats + feeSats <= local - reserve;
			};
			let lo = 0n;
			let hi = local > feeSats ? local - feeSats : 0n;
			if (!admits(0n)) hi = 0n;
			while (lo < hi) {
				const mid = (lo + hi + 1n) / 2n;
				if (admits(mid)) lo = mid;
				else hi = mid - 1n;
			}
			const max = lo;
			const derivedAtMax = channel.spliceReserveWeKeepSats(
				state.fundingSatoshis - max - feeSats
			);
			const reserve = derivedAtMax > stored ? derivedAtMax : stored;
			const spendable = local > reserve ? local - reserve : 0n;
			return {
				direction,
				feeSats: Number(feeSats),
				spendableSats: Number(spendable),
				maxAmountSats: Number(max),
				reserveSats: Number(reserve)
			};
		}

		if (!this.fundingProvider?.quoteSpliceIn) {
			throw new ChannelFundingUnavailableError(
				ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED,
				'splice-in quote requires a funding provider with quoteSpliceIn (wallet UTXO sourcing)'
			);
		}
		const q = this.fundingProvider.quoteSpliceIn(fundingFeeratePerkw);
		return {
			direction,
			feeSats: Number(q.feeSats),
			spendableSats: Number(q.spendableSats),
			maxAmountSats: Number(q.maxAmountSats),
			inputCount: q.inputCount
		};
	}

	spliceOut(
		channelId: Buffer,
		amountSats: bigint,
		fundingFeeratePerkw = 253,
		destinationScript?: Buffer
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new InvalidSpliceError(cidErr);
		const satsErr = validatePositiveBigint(amountSats, 'amountSats');
		if (satsErr) throw new InvalidSpliceError(satsErr);
		// splice_init carries funding_feerate_perkw as a u32. Refuse a bad one
		// here: encoding happens AFTER the channel has moved to SPLICING and
		// persisted, so a throw there leaves the channel wedged until restart.
		const feeErr = validateU32(fundingFeeratePerkw, 'fundingFeeratePerkw', {
			min: 1
		});
		if (feeErr) throw new InvalidSpliceError(feeErr);
		if (
			destinationScript !== undefined &&
			(!Buffer.isBuffer(destinationScript) || destinationScript.length === 0)
		) {
			throw new InvalidSpliceError(
				'destinationScript must be a non-empty Buffer when provided'
			);
		}
		// A splice-out output pays channel funds to this script inside the
		// splice transaction, so restrict it to the standard address forms
		// (P2PKH/P2SH/P2WPKH/P2WSH/any witness program). A raw caller passing
		// OP_RETURN or a malformed script would irrecoverably burn the funds.
		if (
			destinationScript !== undefined &&
			!isValidShutdownScript(destinationScript, true)
		) {
			throw new InvalidSpliceError(
				'destinationScript is not a standard output script (would burn the withdrawn funds)'
			);
		}

		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			return {
				ok: false,
				error: `Channel not found: ${channelId.toString('hex')}`
			};
		}

		const destination = destinationScript ?? this.getSweepDestinationScript();

		// Sanity checks before any protocol message goes out: dust amount, peer
		// support, and spendable channel balance.
		const fee = spliceFeeSats(
			estimateSpliceTxWeight({
				walletInputCount: 0,
				destinationScriptLen: destination.length
			}),
			fundingFeeratePerkw
		);
		// The withdrawal destination receives the FULL requested amount; the
		// on-chain fee comes out of the channel (BOLT/CLN: new_funding =
		// oldCap + relative_satoshis, and we declare relative = -(amount + fee)).
		// So the channel must be able to spare amount + fee.
		let error = this._validateSpliceRequest(channelId, amountSats);
		// The destination is an interactive-tx output, so it must clear the
		// NEGOTIATED floor, not just the generic 546-sat one: a peer whose
		// commitment dust limit is larger rejects the tx_add_output and the
		// splice aborts after the fact (issue #389).
		const destinationFloor = channel.spliceInteractiveTxDustFloor();
		if (!error && amountSats < destinationFloor) {
			error = `splice-out amount ${amountSats} sats is below this channel's negotiated dust floor (${destinationFloor} sats)`;
		}
		// Footgun guard: a fee at or above the withdrawal means you'd burn more
		// on-chain than you take out — almost always a mistake (wrong feerate).
		if (!error && fee >= amountSats) {
			error = `splice-out fee (${fee} sats at ${fundingFeeratePerkw} sat/kw) meets or exceeds the amount (${amountSats} sats) — use a larger amount or a lower feerate`;
		}
		if (!error) {
			const state = channel.getFullState();
			// The reserve the channel will actually keep after adoption: the
			// stored value never falls across a splice (CLN keeps enforcing it)
			// and the derived one is priced at the POST-splice capacity (eclair
			// re-derives, and BOLT 2 aborts a tx_complete that parks the
			// withdrawing side below it; issue #423). Raise-only vs the stored
			// value alone.
			const postCapacity = state.fundingSatoshis - amountSats - fee;
			const stored = state.remoteConfig?.channelReserveSatoshis ?? 0n;
			const derived = channel.spliceReserveWeKeepSats(postCapacity);
			const reserve = derived > stored ? derived : stored;
			const spendableSats = channel.getBalances().localMsat / 1000n - reserve;
			if (amountSats + fee > spendableSats) {
				error = `insufficient channel balance for splice-out: need ${
					amountSats + fee
				} sats (amount + ${fee}-sat fee at ${fundingFeeratePerkw} sat/kw), spendable ${spendableSats} sats after the ${reserve}-sat reserve at the post-splice capacity`;
			}
		}
		if (error) {
			this.emit('node:error', {
				code: 'SPLICE_OUT_FAILED',
				channelId,
				message: error,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error };
		}

		// Record where the withdrawn funds are paid (a wallet-owned or external
		// script) before initiating, so the interactive-tx driver can add the
		// destination output.
		channel.setSpliceOutDestination(destination, amountSats);

		// Declare the splice contribution as -(amount + fee): the new funding
		// output is oldCap + relative, so folding the fee into `relative` makes our
		// built funding output match the peer's computed value (otherwise CLN
		// rejects the commitment_signed with a funding_txid mismatch). The
		// destination still receives the full `amount`; the fee is the implicit
		// difference (input - new_funding - destination).
		const result = this.channelManager.initiateSplice(
			channelId,
			-(amountSats + fee), // negative = splice-out; fee folded in
			fundingFeeratePerkw
		);

		if (!result.ok) {
			this.emit('node:error', {
				code: 'SPLICE_OUT_FAILED',
				channelId,
				message: result.error!,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: result.error };
		}

		return { ok: true };
	}

	/**
	 * Whether splicing is negotiated with a peer: option_splice and
	 * option_quiesce on BOTH feature vectors, ours and the one its current
	 * connection's init carries. Negotiation is mutual, and the local half is
	 * not hypothetical: localFeatures is caller configuration, and a node
	 * configured without splicing must not report a channel as spliceable just
	 * because the peer across it is willing. Null when there is nothing to
	 * read: the peer is not connected, or its init has not arrived yet. This
	 * is the same answer _validateSpliceRequest enforces, exposed so a client
	 * can know before it asks; a UI offering splice controls against an LND
	 * peer is offering an action the daemon will refuse every time.
	 */
	peerSupportsSplicing(peerPubkey: string): boolean | null {
		// The local half is known without asking anyone, so it is decided
		// first: a node that did not negotiate quiescence cannot splice with
		// any peer, and answering null here would misreport a certainty as
		// unknown, leaving clients to keep offering what the pre-flight is
		// certain to refuse.
		const localSupportsSplicing =
			this.localFeatures.hasFeature(Feature.QUIESCE) &&
			this.localFeatures.hasFeature(Feature.SPLICE);
		if (!localSupportsSplicing) return false;
		const init = this.peerManager?.getPeer(peerPubkey)?.getRemoteInit();
		if (!init) return null;
		return (
			init.features.hasFeature(Feature.QUIESCE) &&
			init.features.hasFeature(Feature.SPLICE)
		);
	}

	/**
	 * Shared splice pre-flight checks: dust-level amounts and peer feature
	 * support (option_splice + option_quiesce). Returns an error string or null.
	 */
	private _validateSpliceRequest(
		channelId: Buffer,
		amountSats: bigint
	): string | null {
		// Strict: the interactive-tx builder (and the negotiated-floor check
		// on splice-out destinations) accepts an output AT the floor, so the
		// preflight must too — refusing equality here would reject a
		// splice the negotiation itself is happy to complete.
		if (amountSats < LightningNode.SPLICE_MIN_AMOUNT_SATS) {
			return `splice amount ${amountSats} sats is below the dust floor (${LightningNode.SPLICE_MIN_AMOUNT_SATS} sats)`;
		}
		const peerPubkey = this.channelManager.getPeerForChannel(channelId);
		// Unknown support (no init to read) passes, as it always has: the
		// splice will fail on its own if the peer truly cannot, and refusing on
		// ignorance would block splices on reconnecting channels.
		// Not negotiated is the honest phrasing: the missing half can be the
		// peer's (an LND node) or our own (localFeatures configured without
		// splicing), and blaming the peer for a local configuration sends
		// whoever reads the error to debug the wrong node.
		if (peerPubkey && this.peerSupportsSplicing(peerPubkey) === false) {
			return 'splicing is not negotiated with this peer (option_splice/option_quiesce required on both sides)';
		}
		return null;
	}

	/** Conservative dust floor for splice amounts (covers all standard outputs). */
	private static readonly SPLICE_MIN_AMOUNT_SATS = 546n;

	listChannels(): IChannelInfo[] {
		const channels = this.channelManager.listChannels();
		return channels.map((ch) => this.buildChannelInfo(ch));
	}

	getChannel(channelId: Buffer): IChannelInfo | undefined {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return undefined;
		return this.buildChannelInfo(channel);
	}

	getChannelHealth(channelId: Buffer): IChannelHealth | null {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return null;

		const state = channel.getFullState();
		const balances = channel.getBalances();
		const capacitySats = Number(state.fundingSatoshis);
		const localSats = Number(balances.localMsat / 1000n);
		const remoteSats = Number(balances.remoteMsat / 1000n);
		const totalSats = localSats + remoteSats;
		const localPct =
			totalSats > 0 ? Math.round((localSats / totalSats) * 100) : 0;
		const remotePct =
			totalSats > 0 ? Math.round((remoteSats / totalSats) * 100) : 0;

		let htlcCount = 0;
		for (const [, htlc] of state.htlcs) {
			if (
				htlc.state === HtlcState.PENDING ||
				htlc.state === HtlcState.COMMITTED
			)
				htlcCount++;
		}
		const maxHtlcs = state.localConfig.maxAcceptedHtlcs;

		const warnings: string[] = [];
		if (localPct < 10) warnings.push('LOW_OUTBOUND_LIQUIDITY');
		if (remotePct < 10) warnings.push('LOW_INBOUND_LIQUIDITY');
		if (maxHtlcs > 0 && htlcCount >= maxHtlcs * 0.8)
			warnings.push('HTLC_SLOTS_NEARLY_FULL');
		if (state.state === ChannelState.AWAITING_REESTABLISH)
			warnings.push('AWAITING_REESTABLISH');

		return {
			channelId: (state.channelId || state.temporaryChannelId).toString('hex'),
			state: state.state,
			localBalancePct: localPct,
			remoteBalancePct: remotePct,
			htlcCount,
			maxHtlcs,
			capacitySats,
			warnings
		};
	}

	getLiquiditySnapshot(): ILiquiditySnapshot {
		// Every channel, including one held for unproven recency: channelCount
		// has to keep meaning the number of channels, and a node whose only
		// channel is held must not be told that no channels exist. What the
		// held one does not do is count as ACTIVE, and the advisor decides
		// that from htlcUsable, which already answers false for it (issue
		// #469).
		const channels = this.listChannels();
		const snapshots: IChannelSnapshot[] = channels.map((ch) => {
			const channelIdHex = ch.channelId.toString('hex');
			const reestablishKey = `reestablish:${channelIdHex}`;
			const trackedHeight = this._stuckChannelTracker.get(reestablishKey);
			const stuckBlocks =
				trackedHeight !== undefined
					? this.currentBlockHeight - trackedHeight
					: undefined;
			// A pay-through splice is judged at the conservative min of its live
			// and settle-to balances, the same figure the send path prices
			// against. Handing the advisor the raw live balance would let a
			// splice-out read as flush (live 500k, settling to 50k reads as 50%
			// outbound) and suppress the low-outbound recommendation exactly
			// when it applies.
			const effectiveLocalMsat =
				ch.htlcUsable &&
				ch.pendingSpliceLocalBalanceMsat !== undefined &&
				ch.pendingSpliceLocalBalanceMsat < ch.localBalanceMsat
					? ch.pendingSpliceLocalBalanceMsat
					: ch.localBalanceMsat;
			return {
				channelId: channelIdHex,
				state: ch.state as string,
				localBalanceMsat: effectiveLocalMsat,
				remoteBalanceMsat: ch.remoteBalanceMsat,
				capacitySats: Number(ch.fundingSatoshis),
				peerPubkey: ch.peerPubkey,
				stuckBlocks,
				// Lets the advisor keep counting a channel that pays through its
				// splice instead of zeroing the liquidity for the splice window.
				htlcUsable: ch.htlcUsable,
				// Keeps the advisor from recommending a force close of a channel
				// whose local broadcast the restore hold forbids (issue #469).
				...(ch.restoreRecencyUnproven === true
					? { restoreRecencyUnproven: true }
					: {})
			};
		});
		return this.liquidityAdvisor.analyze(snapshots);
	}

	// ─────────────── Advisor Execution (M3 phases 1+2) ───────────────

	/**
	 * Concrete circular-rebalance plan derived from the advisor's view of the
	 * current channels: saturated channels paired with depleted ones, amounts
	 * sized toward 50/50. Pure planning -- nothing is executed.
	 */
	planRebalanceRecommendations(minImbalancePct?: number): IRebalancePlan[] {
		const snapshots: IChannelSnapshot[] = this.listChannels().map((ch) => ({
			channelId: ch.channelId.toString('hex'),
			state: ch.state as string,
			localBalanceMsat: ch.localBalanceMsat,
			remoteBalanceMsat: ch.remoteBalanceMsat,
			capacitySats: Number(ch.fundingSatoshis),
			peerPubkey: ch.peerPubkey,
			// A rebalance is two new HTLCs, so a channel that refuses them
			// cannot be either leg. The planner reads this rather than the
			// state, for the same reason the advisor does (issue #469).
			htlcUsable: ch.htlcUsable,
			...(ch.restoreRecencyUnproven === true
				? { restoreRecencyUnproven: true }
				: {})
		}));
		const plans = planRebalances(snapshots, {
			minImbalancePct:
				minImbalancePct ?? this.autoRebalanceConfig.minImbalancePct
		});
		// Clamp each plan to what ONE HTLC can carry: the outbound leg (amount
		// plus fees) is bounded by the donor peer's max_htlc_value_in_flight,
		// the inbound leg by our own limit on the receiving channel. 1% of the
		// cap is held back as fee headroom.
		const clamped: IRebalancePlan[] = [];
		for (const plan of plans) {
			const fromCh = this.channelManager.getChannel(
				Buffer.from(plan.fromChannelId, 'hex')
			);
			const toCh = this.channelManager.getChannel(
				Buffer.from(plan.toChannelId, 'hex')
			);
			if (!fromCh || !toCh) continue;
			const outCapMsat =
				fromCh.getFullState().remoteConfig.maxHtlcValueInFlightMsat;
			const inCapMsat =
				toCh.getFullState().localConfig.maxHtlcValueInFlightMsat;
			const capMsat = outCapMsat < inCapMsat ? outCapMsat : inCapMsat;
			const maxAmountSats = (capMsat * 99n) / 100n / 1000n;
			const amountSats =
				plan.amountSats < maxAmountSats ? plan.amountSats : maxAmountSats;
			if (amountSats < MIN_REBALANCE_SATS) continue;
			clamped.push({ ...plan, amountSats });
		}
		return clamped;
	}

	/**
	 * Circular rebalance: pay OURSELVES out over `fromChannelId` and back in
	 * over `toChannelId`, moving `amountSats` of local balance between the two.
	 *
	 * Route construction: the graph search runs from us to the toChannel's peer
	 * with the FIRST hop pinned to fromChannel (only that channel is offered as
	 * a local edge; every other local SCID/alias is excluded), then the final
	 * peer→us hop is appended from our own routing hint for toChannel (the same
	 * SCID/policy an invoice would advertise), so the loop provably re-enters
	 * on toChannelId. `maxFeeSats` is enforced BEFORE anything is sent -- on a
	 * route costing more, this aborts without paying.
	 */
	async rebalanceChannel(options: {
		fromChannelId: Buffer;
		toChannelId: Buffer;
		amountSats: bigint;
		maxFeeSats: bigint;
		timeoutMs?: number;
	}): Promise<IRebalanceResult> {
		const { fromChannelId, toChannelId, amountSats, maxFeeSats } = options;
		const cidErr =
			validateBuffer(fromChannelId, 32, 'fromChannelId') ||
			validateBuffer(toChannelId, 32, 'toChannelId');
		if (cidErr) throw new Error(cidErr);
		if (fromChannelId.equals(toChannelId)) {
			throw new Error('fromChannelId and toChannelId must differ');
		}
		if (amountSats <= 0n) throw new Error('amountSats must be positive');
		if (maxFeeSats < 0n) throw new Error('maxFeeSats must be non-negative');

		const fromChannel = this.channelManager.getChannel(fromChannelId);
		if (!fromChannel || !fromChannel.acceptsNewHtlcs()) {
			throw new Error(
				`from channel not found or not usable: ${fromChannelId.toString('hex')}`
			);
		}
		const toChannel = this.channelManager.getChannel(toChannelId);
		if (!toChannel || !toChannel.acceptsNewHtlcs()) {
			throw new Error(
				`to channel not found or not usable: ${toChannelId.toString('hex')}`
			);
		}

		const amountMsat = amountSats * 1000n;
		const maxFeeMsat = maxFeeSats * 1000n;
		const fromState = fromChannel.getFullState();
		const toState = toChannel.getFullState();
		if (fromState.localBalanceMsat < amountMsat) {
			throw new Error('insufficient local balance on from channel');
		}
		if (toState.remoteBalanceMsat < amountMsat) {
			throw new Error('insufficient inbound capacity on to channel');
		}
		// Single-HTLC size limits -- fail fast instead of sending a doomed HTLC:
		// the loop rides ONE HTLC back in over toChannel (our own in-flight cap
		// applies); the outbound leg (amount + fees) is checked against the
		// peer's cap after the route is known below.
		if (amountMsat > toState.localConfig.maxHtlcValueInFlightMsat) {
			throw new Error(
				'amount exceeds our max_htlc_value_in_flight on the to channel'
			);
		}

		const fromScid = fromState.shortChannelId ?? fromState.scidAlias;
		if (!fromScid) {
			throw new Error('from channel has no SCID or alias yet');
		}
		const fromPeerHex = this.channelManager.getPeerForChannel(fromChannelId);
		if (!fromPeerHex) throw new Error('from channel has no known peer');

		// The final peer→us hop: our own invoice routing hint for toChannel gives
		// the SCID the peer forwards over and the fee/CLTV policy it enforces.
		const toHint = this.buildRoutingHintForChannel(toChannel);
		if (!toHint) {
			throw new Error('to channel has no usable routing hint (SCID/alias)');
		}

		// Exclude every local channel's SCID/alias except fromChannel's, so the
		// graph search can only leave (and never re-enter) through fromChannel.
		const excluded = new Set<string>();
		for (const channel of this.channelManager.listChannels()) {
			const id = channel.getChannelId();
			if (id && id.equals(fromChannelId)) continue;
			const st = channel.getFullState();
			if (st.shortChannelId) excluded.add(st.shortChannelId.toString('hex'));
			if (st.scidAlias) excluded.add(st.scidAlias.toString('hex'));
			if (st.remoteScidAlias) {
				excluded.add(st.remoteScidAlias.toString('hex'));
			}
		}

		const ourNodeId = getPublicKey(this.nodePrivkey);
		const finalCltvExpiry = this.paddedFinalCltvExpiry();
		// The toChannel peer charges its forwarding fee on the amount it relays
		// to us, and needs its CLTV delta of headroom above our final expiry.
		const toPeerFeeMsat = calculateFee(
			amountMsat,
			toHint.feeBaseMsat,
			toHint.feeProportionalMillionths
		);
		const subRoute = findRoute(
			this.graph,
			ourNodeId,
			toHint.pubkey,
			amountMsat + toPeerFeeMsat,
			finalCltvExpiry + toHint.cltvExpiryDelta,
			undefined,
			excluded,
			this.missionControl,
			undefined,
			undefined,
			undefined,
			[
				{
					shortChannelId: fromScid,
					peer: Buffer.from(fromPeerHex, 'hex'),
					outboundMsat: fromState.localBalanceMsat
				}
			]
		);
		if (!subRoute) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'No circular route from fromChannel back to toChannel'
			);
		}
		// Defense in depth: the exclusion set must have forced the first hop
		// onto fromChannel -- never send if the constraint did not hold.
		if (!subRoute.hops[0].shortChannelId.equals(fromScid)) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'Route does not leave over the requested from channel'
			);
		}

		const totalFeeMsat = subRoute.totalAmountMsat - amountMsat;
		// STRICT fee cap: abort before creating the invoice or sending anything.
		if (totalFeeMsat > maxFeeMsat) {
			throw new LightningPaymentError(
				LightningErrorCode.FEE_EXCEEDS_MAX,
				`Rebalance fee ${totalFeeMsat} msat exceeds cap ${maxFeeMsat} msat`
			);
		}
		// Outbound leg = amount + fees on one HTLC; the fromChannel peer's
		// max_htlc_value_in_flight would reject anything larger.
		if (
			subRoute.totalAmountMsat > fromState.remoteConfig.maxHtlcValueInFlightMsat
		) {
			throw new Error(
				'amount plus fees exceeds the peer max_htlc_value_in_flight on the from channel'
			);
		}

		const invoice = this.createInvoice({
			amountMsat,
			description: 'beignet circular rebalance',
			minFinalCltvExpiry: finalCltvExpiry
		});

		const hops = [
			...subRoute.hops,
			{
				pubkey: ourNodeId,
				shortChannelId: toHint.shortChannelId,
				amountToForwardMsat: amountMsat,
				outgoingCltvValue: finalCltvExpiry,
				cltvExpiryDelta: toHint.cltvExpiryDelta,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0
			}
		];

		this.emitStructuredLog('payment', 'rebalance_started', {
			fromChannelId: fromChannelId.toString('hex'),
			toChannelId: toChannelId.toString('hex'),
			amountMsat: amountMsat.toString(),
			feeMsat: totalFeeMsat.toString(),
			hops: hops.length
		});

		this.sendPaymentToRoute(
			{ hops },
			invoice.paymentHash,
			finalCltvExpiry,
			invoice.paymentSecret,
			amountMsat
		);
		await this.waitForPayment(invoice.paymentHash, options.timeoutMs ?? 60_000);

		this.emitStructuredLog('payment', 'rebalance_succeeded', {
			fromChannelId: fromChannelId.toString('hex'),
			toChannelId: toChannelId.toString('hex'),
			amountMsat: amountMsat.toString(),
			feeMsat: totalFeeMsat.toString()
		});

		return {
			paymentHash: invoice.paymentHash,
			amountMsat,
			feeMsat: totalFeeMsat,
			hops: hops.length
		};
	}

	/** Metadata key for the persisted per-day rebalance fee spend. */
	private static readonly REBALANCE_BUDGET_KEY = 'advisor:rebalance-budget';

	/** Current UTC day, the granularity at which the fee budget resets. */
	private static currentUtcDay(): string {
		return new Date().toISOString().slice(0, 10);
	}

	/** Fee spend recorded for TODAY (loads persisted state across restarts). */
	private loadRebalanceSpentMsat(): bigint {
		const day = LightningNode.currentUtcDay();
		if (!this.rebalanceBudgetDay || this.rebalanceBudgetDay.day !== day) {
			// In-memory state is missing or stale -- consult persisted metadata.
			let spent = 0n;
			if (this.storage) {
				try {
					const raw = this.storage.loadMetadata(
						LightningNode.REBALANCE_BUDGET_KEY
					);
					if (raw) {
						const parsed = JSON.parse(raw) as {
							day?: string;
							spentFeeMsat?: string;
						};
						if (parsed.day === day && parsed.spentFeeMsat) {
							spent = BigInt(parsed.spentFeeMsat);
						}
					}
				} catch {
					// Unreadable metadata counts as zero spend (budget still capped).
				}
			}
			this.rebalanceBudgetDay = { day, spentFeeMsat: spent };
		}
		return this.rebalanceBudgetDay.spentFeeMsat;
	}

	private recordRebalanceSpend(feeMsat: bigint): void {
		const spent = this.loadRebalanceSpentMsat() + feeMsat;
		this.rebalanceBudgetDay = {
			day: LightningNode.currentUtcDay(),
			spentFeeMsat: spent
		};
		this.safeStorage(
			() =>
				this.storage!.saveMetadata(
					LightningNode.REBALANCE_BUDGET_KEY,
					JSON.stringify({
						day: this.rebalanceBudgetDay!.day,
						spentFeeMsat: spent.toString()
					})
				),
			'saveRebalanceBudget'
		);
	}

	/**
	 * Execute the advisor's rebalance plan under a strict per-UTC-day fee
	 * budget. Each pair gets a fee cap of min(remaining budget, 0.5% of the
	 * amount, at least 1 sat); once the day's budget is exhausted the remaining
	 * pairs are skipped, never partially overspent. Failures are recorded and
	 * do not stop later pairs (they spent nothing).
	 */
	async executeRebalanceRecommendations(options?: {
		budgetSatsPerDay?: number;
		minImbalancePct?: number;
	}): Promise<IRebalanceExecutionSummary> {
		if (this.rebalanceRunInFlight) {
			throw new Error('a rebalance execution run is already in progress');
		}
		this.rebalanceRunInFlight = true;
		try {
			const budgetSats =
				options?.budgetSatsPerDay ??
				this.autoRebalanceConfig.budgetSatsPerDay ??
				1_000;
			if (budgetSats < 0) throw new Error('budgetSatsPerDay must be >= 0');
			const budgetMsat = BigInt(budgetSats) * 1000n;

			const plans = this.planRebalanceRecommendations(options?.minImbalancePct);
			const attempts: IRebalanceAttempt[] = [];
			let feeSpentThisRunMsat = 0n;

			for (const plan of plans) {
				const remainingMsat = budgetMsat - this.loadRebalanceSpentMsat();
				// Per-pair cap: never above the remaining daily budget, and never
				// above 0.5% of the moved amount (min 1 sat so tiny amounts route).
				const proportionalCapMsat =
					(plan.amountSats * 1000n * 5000n) / 1_000_000n;
				const perPairCapMsat =
					proportionalCapMsat > 1000n ? proportionalCapMsat : 1000n;
				const feeCapMsat =
					remainingMsat < perPairCapMsat ? remainingMsat : perPairCapMsat;
				// Below 1 sat of cap the route cannot pay any fee -- budget exhausted.
				if (feeCapMsat < 1000n) {
					attempts.push({
						fromChannelId: plan.fromChannelId,
						toChannelId: plan.toChannelId,
						amountSats: plan.amountSats,
						status: 'SKIPPED_BUDGET'
					});
					this.emitStructuredLog('payment', 'rebalance_budget_exhausted', {
						remainingMsat: remainingMsat.toString(),
						budgetMsat: budgetMsat.toString()
					});
					continue;
				}
				try {
					const result = await this.rebalanceChannel({
						fromChannelId: Buffer.from(plan.fromChannelId, 'hex'),
						toChannelId: Buffer.from(plan.toChannelId, 'hex'),
						amountSats: plan.amountSats,
						maxFeeSats: feeCapMsat / 1000n
					});
					this.recordRebalanceSpend(result.feeMsat);
					feeSpentThisRunMsat += result.feeMsat;
					attempts.push({
						fromChannelId: plan.fromChannelId,
						toChannelId: plan.toChannelId,
						amountSats: plan.amountSats,
						status: 'SUCCEEDED',
						feeMsat: result.feeMsat
					});
				} catch (err) {
					attempts.push({
						fromChannelId: plan.fromChannelId,
						toChannelId: plan.toChannelId,
						amountSats: plan.amountSats,
						status: 'FAILED',
						error: err instanceof Error ? err.message : String(err)
					});
				}
			}

			const spent = this.loadRebalanceSpentMsat();
			return {
				attempts,
				succeeded: attempts.filter((a) => a.status === 'SUCCEEDED').length,
				failed: attempts.filter((a) => a.status === 'FAILED').length,
				skippedBudget: attempts.filter((a) => a.status === 'SKIPPED_BUDGET')
					.length,
				feeSpentMsat: feeSpentThisRunMsat,
				budgetRemainingMsat: budgetMsat > spent ? budgetMsat - spent : 0n
			};
		} finally {
			this.rebalanceRunInFlight = false;
		}
	}

	/**
	 * One routing-fee auto-tune pass (phase 2). Deterministic per snapshot:
	 * each NORMAL channel gets at most ONE ppm adjustment per pass, computed by
	 * the pure fee-tuner from its local balance and the forwards ledger over
	 * the past interval window (see computeFeeTuneAdjustments for the rules).
	 * `now` is injectable for tests; the periodic timer passes the real clock.
	 */
	runFeeTuneOnce(now: number = Date.now()): IFeeTuneAdjustment[] {
		const intervalMs = this.autoTuneFeesConfig.intervalMs ?? 21_600_000;
		const floorPpm =
			this.autoTuneFeesConfig.floorPpm ?? DEFAULT_FEE_TUNE_FLOOR_PPM;
		const ceilPpm =
			this.autoTuneFeesConfig.ceilPpm ?? DEFAULT_FEE_TUNE_CEIL_PPM;
		if (floorPpm < 0 || ceilPpm < floorPpm) {
			throw new Error('autoTuneFees requires 0 <= floorPpm <= ceilPpm');
		}
		const since = now - intervalMs;

		const inputs: IFeeTuneInput[] = [];
		for (const channel of this.channelManager.listChannels()) {
			if (channel.getState() !== ChannelState.NORMAL) continue;
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const hex = channelId.toString('hex');
			const policy = this.getChannelPolicy(channelId);
			if (!policy) continue;
			const st = channel.getFullState();
			const capacityMsat = st.fundingSatoshis * 1000n;
			if (capacityMsat <= 0n) continue;
			const forwards = this.listForwards({ since, until: now, channelId: hex });
			inputs.push({
				channelId: hex,
				currentPpm: policy.feeProportionalMillionths,
				localBalanceFraction:
					Number(st.localBalanceMsat) / Number(capacityMsat),
				outboundForwards: forwards.filter((f) => f.outChannelId === hex).length,
				totalForwards: forwards.length
			});
		}

		const adjustments = computeFeeTuneAdjustments(inputs, {
			floorPpm,
			ceilPpm
		});
		for (const adj of adjustments) {
			this.setChannelPolicy(Buffer.from(adj.channelId, 'hex'), {
				feeProportionalMillionths: adj.newPpm
			});
			this.emitStructuredLog('fee', 'auto_tune_adjusted', {
				channelId: adj.channelId,
				oldPpm: adj.oldPpm,
				newPpm: adj.newPpm,
				reason: adj.reason,
				windowMs: intervalMs
			});
		}
		return adjustments;
	}

	getFeeSnapshot(): IFeeSnapshot | null {
		return this.feeAdvisor.getSnapshot();
	}

	getChannelSuggestions(count?: number): IChannelSuggestion[] {
		// Collect existing peer pubkeys to exclude
		const excludeNodeIds = new Set<string>();
		for (const ch of this.channelManager.listChannels()) {
			const fullState = ch.getFullState();
			const channelId = fullState.channelId || fullState.temporaryChannelId;
			const peer = this.channelManager.getPeerForChannel(channelId);
			if (peer) excludeNodeIds.add(peer);
		}

		// Collect payment destinations for relevance scoring
		const paymentDestinations = new Set<string>();
		for (const payment of this.payments.values()) {
			if (payment.route) {
				const lastHop = payment.route.hops[payment.route.hops.length - 1];
				if (lastHop) paymentDestinations.add(lastHop.pubkey.toString('hex'));
			}
		}

		return this.channelSuggestions.suggest(this.graph, this.nodeId, {
			excludeNodeIds,
			paymentDestinations,
			maxResults: count
		});
	}

	private buildChannelInfo(channel: Channel): IChannelInfo {
		const state = channel.getFullState();
		const balances = channel.getBalances();
		const channelId = state.channelId || state.temporaryChannelId;
		const info: IChannelInfo = {
			channelId,
			// A v2 open carries its derived channel_id from accept_channel2 on,
			// but the peer map keeps the temporary-id key until the channel is
			// promoted (AWAITING_FUNDING_CONFIRMED). Fall back to the temp id so
			// a mid-negotiation channel still reports its peer instead of an
			// empty pubkey (which the dashboard renders as an unknown, offline
			// peer with a Reconnect button that cannot work).
			peerPubkey:
				this.channelManager.getPeerForChannel(channelId) ??
				this.channelManager.getPeerForChannel(state.temporaryChannelId) ??
				'',
			state: state.state,
			localBalanceMsat: balances.localMsat,
			remoteBalanceMsat: balances.remoteMsat,
			fundingSatoshis: state.fundingSatoshis,
			channelType: state.channelType
		};
		if (state.fundingTxid) {
			info.fundingTxid = Buffer.from(state.fundingTxid)
				.reverse()
				.toString('hex');
			// Gated on fundingTxid: the state field defaults to 0 before any
			// funding exists, and a fake 0 outpoint must not be reported.
			info.fundingOutputIndex = state.fundingOutputIndex;
		}
		const pendingSplice = channel.getPendingSpliceLocalBalanceMsat();
		if (pendingSplice !== null)
			info.pendingSpliceLocalBalanceMsat = pendingSplice;
		info.htlcUsable = channel.acceptsNewHtlcs();
		// The reason a NORMAL channel can still answer false, so a consumer can
		// tell "mid-splice and parked" from "restored and held" (issue #469).
		if (state.restoreRecencyUnproven === true) {
			info.restoreRecencyUnproven = true;
		}
		// Present exactly when the channel is mid-splice by EFFECTIVE state
		// (looking through a reconnect): true = pay-through accounting (counted
		// in the canonical balance at min(live, settle-to)), false = parked
		// (lives entirely in the splicing bucket).
		const effInfoState =
			state.state === ChannelState.AWAITING_REESTABLISH
				? state.preReestablishState ?? state.state
				: state.state;
		if (effInfoState === ChannelState.SPLICING) {
			info.payThroughSplice = channel.isHtlcUsable(true);
		}
		if (state.shortChannelId)
			info.shortChannelId = state.shortChannelId.toString('hex');
		info.feeratePerKw = state.localConfig.feeratePerKw;
		// Count active HTLCs (PENDING or COMMITTED)
		let htlcCount = 0;
		for (const [, htlc] of state.htlcs) {
			if (
				htlc.state === HtlcState.PENDING ||
				htlc.state === HtlcState.COMMITTED
			)
				htlcCount++;
		}
		info.htlcCount = htlcCount;
		info.localReserveMsat = state.remoteConfig.channelReserveSatoshis * 1000n;
		info.remoteReserveMsat = state.localConfig.channelReserveSatoshis * 1000n;
		info.isPrivate = !state.announceChannel;
		// Effective routing policy (per-channel override or node defaults)
		const policy = this.getChannelPolicy(channelId);
		if (policy) {
			info.feeBaseMsat = policy.feeBaseMsat;
			info.feeProportionalMillionths = policy.feeProportionalMillionths;
			info.cltvExpiryDelta = policy.cltvExpiryDelta;
			info.htlcMinimumMsat = policy.htlcMinimumMsat;
			info.htlcMaximumMsat = policy.htlcMaximumMsat;
		}
		const closeStatus = this._buildCloseStatus(state, channelId);
		if (closeStatus) info.closeStatus = closeStatus;
		return info;
	}

	/**
	 * Derive closeStatus for a closing/closed channel from persisted channel
	 * state, the monitor's classified commitment spend, and the in-memory
	 * close-broadcast bookkeeping. Returns undefined for channels that are
	 * not closing.
	 */
	private _buildCloseStatus(
		state: IChannelState,
		channelId: Buffer
	): ICloseStatus | undefined {
		const s = state.state;
		const closing =
			s === ChannelState.SHUTTING_DOWN ||
			s === ChannelState.NEGOTIATING_CLOSING ||
			s === ChannelState.CLOSED ||
			s === ChannelState.FORCE_CLOSED ||
			// A pre-funding error has nothing on chain to report (the field is
			// initialized to null, so a bare undefined check is not enough).
			(s === ChannelState.ERRORED && state.fundingTxid != null);
		if (!closing) return undefined;

		const idHex = channelId.toString('hex');
		const monitor = this.channelManager.getMonitor(channelId);
		const cb = monitor?.getFullState().commitmentBroadcast ?? null;
		const last = this._lastCloseBroadcast.get(idHex);

		let closer: ICloseStatus['closer'];
		if (cb) {
			switch (cb.commitmentType) {
				case CommitmentType.COOPERATIVE_CLOSE:
					closer = 'cooperative';
					break;
				case CommitmentType.OUR_COMMITMENT:
					closer = 'local';
					break;
				case CommitmentType.THEIR_CURRENT_COMMITMENT:
				case CommitmentType.THEIR_REVOKED_COMMITMENT:
				case CommitmentType.THEIR_FUTURE_COMMITMENT:
					closer = 'remote';
					break;
				default:
					closer = 'unknown';
			}
		} else if (s === ChannelState.FORCE_CLOSED) {
			// Only our own force close reaches FORCE_CLOSED before a spend is
			// observed; a remote close is classified at detection time.
			closer = 'local';
		} else if (
			s === ChannelState.SHUTTING_DOWN ||
			s === ChannelState.NEGOTIATING_CLOSING
		) {
			closer = 'cooperative';
		} else if (s === ChannelState.CLOSED) {
			closer = state.lastCooperativeCloseTxHex ? 'cooperative' : 'unknown';
		} else {
			closer = 'unknown';
		}

		const status: ICloseStatus = {
			closer,
			broadcast: cb !== null || last?.ok === true,
			// The monitor's classified spend height, NOT a tracked output's
			// confirmationHeight (handleOutputSpent overwrites that with the
			// sweep's height). 0 covers both mempool-first sightings and a close
			// that has not been seen at all.
			confirmationHeight: cb ? cb.blockHeight : 0,
			resolution:
				monitor === undefined
					? 'pending'
					: monitor.getState() === MonitorState.FULLY_RESOLVED
					? // Belt for pre-#338-fix persisted state that reached
					  // FULLY_RESOLVED unconfirmed: never report a terminal
					  // guarantee for a close a reorg can void.
					  monitor.isCommitmentConfirmed()
						? 'resolved'
						: 'pending'
					: monitor.getState() === MonitorState.RESOLVING
					? // A cooperative close waits out IRREVOCABLE_DEPTH in
					  // RESOLVING (issue #338). While the close tx is unconfirmed
					  // nothing is being swept, so that window reads 'pending'.
					  cb?.commitmentType === CommitmentType.COOPERATIVE_CLOSE &&
					  !monitor.isCommitmentConfirmed()
						? 'pending'
						: 'sweeping'
					: 'pending'
		};
		// Our stamped reason describes OUR close. When the spend that actually
		// resolved the channel was the peer's (simultaneous-close race, or a
		// remote close after our coop attempt), the reason no longer describes
		// what happened: peer closes report no reason, per the contract.
		if (state.closeReason && (closer === 'local' || closer === 'cooperative')) {
			status.reason = state.closeReason;
		}

		if (cb?.txid) {
			status.closingTxid = cb.txid;
		} else if (state.lastCooperativeCloseTxHex) {
			try {
				status.closingTxid = bitcoin.Transaction.fromHex(
					state.lastCooperativeCloseTxHex
				).getId();
			} catch {
				// Unparseable stored hex: leave the txid unset.
			}
		} else if (last) {
			status.closingTxid = last.txid;
		}

		// to_local CSV maturity: only meaningful for OUR confirmed commitment.
		if (cb && cb.commitmentType === CommitmentType.OUR_COMMITMENT && monitor) {
			const toLocal = monitor
				.getTrackedOutputs()
				.find(
					(o) => o.outputType === OutputType.TO_LOCAL && !o.isSecondLevelHtlc
				);
			if (toLocal) {
				if (
					toLocal.maturityHeight !== undefined &&
					toLocal.maturityHeight !== Number.MAX_SAFE_INTEGER
				) {
					// Authoritative: derived from the actual sweep tx.
					status.fundsAvailableHeight = toLocal.maturityHeight;
				} else if (cb.blockHeight > 0) {
					const csv = toLocal.witnessScript
						? csvFromToLocalScript(toLocal.witnessScript) ??
						  state.localConfig.toSelfDelay
						: state.localConfig.toSelfDelay;
					status.fundsAvailableHeight = cb.blockHeight + csv;
				}
				// Unconfirmed commitment: no CSV base yet, leave unset.
			}
		}
		return status;
	}

	// ─────────────── SCID Registration ───────────────

	registerChannelScid(channelId: Buffer, scid: Buffer): void {
		this.scidToChannelId.set(scid.toString('hex'), channelId);
		this.safeStorage(
			() => this.storage!.saveScidMapping(scid.toString('hex'), channelId),
			'saveScidMapping'
		);
	}

	/**
	 * Register every short_channel_id by which a peer may address this channel when
	 * asking us to FORWARD: both SCID aliases and, for announced channels, the real
	 * confirmed SCID. Senders route from the public gossip graph, which carries the
	 * real SCID, so without that entry every forward through us fails the lookup in
	 * handleForward() and is failed back as unknown_next_peer while direct payments
	 * (whose final hop payload has no short_channel_id at all) still succeed.
	 */
	private registerChannelScids(channelId: Buffer): void {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;

		// Register our local SCID alias (what the remote will use to refer to this channel)
		const alias = channel.getScidAlias();
		if (alias) {
			this.registerChannelScid(channelId, alias);
		}

		// Register remote's SCID alias (what we use to refer to this channel to the remote)
		const remoteAlias = channel.getRemoteScidAlias();
		if (remoteAlias) {
			this.registerChannelScid(channelId, remoteAlias);
		}

		// Register the real confirmed SCID. Null until the funding reaches
		// announcement depth, so this is also driven by 'channel:scid-assigned'.
		const state = channel.getFullState();
		if (state.shortChannelId && this.shouldAcceptRealScid(state)) {
			this.registerChannelScid(channelId, state.shortChannelId);
		}
	}

	/**
	 * Whether incoming HTLCs may address this channel by its real SCID.
	 *
	 * BOLT 2 conditions this on the negotiated CHANNEL TYPE, not on
	 * announce_channel: only when channel_type includes option_scid_alias must a
	 * node refuse the real short_channel_id. Gating on announceChannel instead
	 * would reject every private channel, including ones that never negotiated
	 * option_scid_alias, and those are routinely addressed by their real SCID via
	 * invoice route hints (buildRoutingHintForChannel prefers the real SCID over
	 * the alias, so this node's own private invoices would be unpayable).
	 *
	 * An announced channel is unaffected: BOLT 2 forbids pairing option_scid_alias
	 * with announce_channel, so an announced channel never trips this.
	 */
	private shouldAcceptRealScid(state: IChannelState): boolean {
		return !hasScidAliasChannelType(state.channelType);
	}

	/**
	 * The short_channel_id a PEER uses to address this channel when routing an
	 * HTLC to us: the SCID for BOLT 11 r fields, blinded-path hops, and the
	 * channel_update we send directly over an unannounced channel.
	 *
	 * The alias direction matters and is easy to get backwards. BOLT 2 says the
	 * SENDER of an alias in channel_ready "MUST always recognize the alias as a
	 * short_channel_id for incoming HTLCs to this channel", so the node that
	 * generated an alias is the node that resolves it. Our peer therefore resolves
	 * the alias IT generated and sent to us, which we store as remoteScidAlias.
	 * Our own scidAlias is what WE resolve, so advertising it would name an SCID
	 * the peer is not required to recognise. BOLT 2 matches this from the other
	 * side: the receiver "MAY use any of the alias it received, in BOLT 11 r
	 * fields".
	 *
	 * With option_scid_alias in channel_type the real SCID is not an option at
	 * all: BOLT 2 says a node "MUST NOT use the real short_channel_id in BOLT 11 r
	 * fields", and shouldAcceptRealScid means our own forwarding side would refuse
	 * it anyway. Advertising it would hand payers a route we reject.
	 *
	 * Returns null when nothing addressable exists yet, which is correct: a hint
	 * the peer cannot resolve is worse than no hint.
	 */
	private getPeerAddressableScid(state: IChannelState): Buffer | null {
		if (hasScidAliasChannelType(state.channelType)) {
			return state.remoteScidAlias;
		}
		return state.shortChannelId ?? state.remoteScidAlias;
	}

	// ─────────────── Gossip Propagation ───────────────

	/**
	 * Build and sign our node_announcement for the given timestamp. Returns null
	 * if encoding/signing fails. (node_announcement carries our alias/colour and
	 * is what explorers use to list the node.)
	 */
	private buildNodeAnnouncement(timestamp: number): Buffer | null {
		try {
			const nodeId = getPublicKey(this.nodePrivkey);
			const aliasBuffer = Buffer.alloc(32);
			if (this.alias) {
				// BOLT 7: alias is a 32-byte field that MUST be valid UTF-8. A raw
				// byte-count truncation can split the last multi-byte codepoint,
				// yielding invalid UTF-8; trim whole codepoints to fit 32 bytes.
				let aliasStr = this.alias;
				while (Buffer.byteLength(aliasStr, 'utf8') > 32) {
					aliasStr = [...aliasStr].slice(0, -1).join('');
				}
				Buffer.from(aliasStr, 'utf8').copy(aliasBuffer, 0);
			}
			// node_announcement MUST advertise the features we actually support, not
			// just large_channels: remote nodes make routing decisions (onion-message
			// relay, route blinding) from the graph, so an almost-empty features
			// field made CLN/eclair/LDK refuse to route onion messages to us and
			// left our BOLT 12 offers unreachable to non-direct peers. Reuse the init
			// feature set (large_channels is already in it when wumbo is enabled).
			const payload = encodeNodeAnnouncementMessage({
				signature: Buffer.alloc(64), // placeholder — signed below
				features: this.localFeatures.toBuffer(),
				timestamp,
				nodeId,
				rgbColor: Buffer.from([0, 0, 0]),
				alias: aliasBuffer,
				addresses: this.announcedAddresses,
				// A configured seller publishes its rates in the lease_rates TLV
				// (issue #539). The option_will_fund bit alone told buyers we
				// sell but not at what price, so anything pricing from the
				// gossip ad skipped us or requested blind; these are the exact
				// rates will_fund signs (verifyWillFund's contract). Undefined
				// for non-sellers: no TLV is emitted.
				leaseRates: this.leaseRates
			});
			const sig = signNodeAnnouncement(payload, this.nodePrivkey);
			sig.copy(payload, 0);
			return payload;
		} catch {
			return null;
		}
	}

	/**
	 * Refresh a cached channel_update: bump its timestamp, stamp the channel's
	 * EFFECTIVE routing policy (per-channel override or node defaults) when a
	 * channelId is given, and re-sign. This is a pure gossip message: it never
	 * touches the commitment state machine, HTLCs or update_fee, so it cannot
	 * trigger a force-close. Returns null if decode/encode/sign fails.
	 */
	private refreshChannelUpdate(
		cachedUpdate: Buffer,
		timestamp: number,
		channelId?: Buffer
	): Buffer | null {
		try {
			const msg = decodeChannelUpdateMessage(cachedUpdate);
			msg.timestamp = timestamp;
			// Reflect the current forwarding policy in the BOLT 7 disable bit
			// (0x02), preserving the direction bit and any others. A node that
			// declines to forward must not keep advertising its direction as
			// routable; a stale in-flight route that still reaches us is caught
			// by the handleForwardHtlc opt-out.
			msg.channelFlags = this.forwardingEnabled
				? msg.channelFlags & ~0x02
				: msg.channelFlags | 0x02;
			const policy = channelId ? this.getChannelPolicy(channelId) : null;
			if (policy && channelId) {
				msg.cltvExpiryDelta = policy.cltvExpiryDelta;
				msg.feeBaseMsat = policy.feeBaseMsat;
				msg.feeProportionalMillionths = policy.feeProportionalMillionths;
				msg.htlcMinimumMsat = policy.htlcMinimumMsat;
				// BOLT 7: htlc_maximum_msat MUST NOT exceed the channel capacity.
				const st = this.channelManager.getChannel(channelId)!.getFullState();
				const capacityMsat = st.fundingSatoshis * 1000n;
				msg.htlcMaximumMsat =
					policy.htlcMaximumMsat > capacityMsat
						? capacityMsat
						: policy.htlcMaximumMsat;
				// The bLIP-0051 lessor fee clamp already happened inside
				// getChannelPolicy (applyLeaseFeeCaps), the same effective
				// policy the forwarding checks enforce, so what this update
				// advertises is exactly what an HTLC will be held to.
			}
			const payload = encodeChannelUpdateMessage(msg);
			const sig = signChannelUpdate(payload, this.nodePrivkey);
			sig.copy(payload, 0);
			return payload;
		} catch {
			return null;
		}
	}

	/**
	 * Send our cached gossip (channel_announcement + channel_update for each of our
	 * announced channels, plus our node_announcement) to a single peer. The peer
	 * floods valid, unseen messages onward — this is how our node reaches the wider
	 * graph and the explorers that index it.
	 */
	private sendOwnGossipTo(pubkey: string): void {
		if (!this.peerManager) return;
		try {
			for (const { announcement, update } of this._ownChannelGossip.values()) {
				this.peerManager.sendToPeer(
					pubkey,
					MessageType.CHANNEL_ANNOUNCEMENT,
					announcement
				);
				this.peerManager.sendToPeer(pubkey, MessageType.CHANNEL_UPDATE, update);
			}
			if (this._ownNodeAnnouncement) {
				this.peerManager.sendToPeer(
					pubkey,
					MessageType.NODE_ANNOUNCEMENT,
					this._ownNodeAnnouncement
				);
			}
		} catch {
			// Peer may have disconnected — ignore.
		}
	}

	/** Re-broadcast our cached gossip to every currently-connected peer. */
	private broadcastOwnGossip(): void {
		if (!this.peerManager) return;
		for (const peer of this.peerManager.listPeers()) {
			this.sendOwnGossipTo(peer.pubkey);
		}
	}

	/**
	 * Periodically refresh our node_announcement (bump its timestamp + re-sign) and
	 * re-broadcast all our gossip, so the node stays in the public graph rather than
	 * being pruned as stale (peers/explorers drop gossip older than ~2 weeks). Starts
	 * once; safe to call repeatedly.
	 */
	private startGossipRefresh(): void {
		if (this._gossipRefreshTimer || this._ownChannelGossip.size === 0) return;
		this._gossipRefreshTimer = setInterval(() => {
			const now = Math.floor(Date.now() / 1000);
			// Bump the node_announcement timestamp + re-sign so peers treat it as
			// fresh (an unchanged timestamp is deduped and won't reset the prune clock).
			const refreshed = this.buildNodeAnnouncement(now);
			if (refreshed) {
				this._ownNodeAnnouncement = refreshed;
			}
			// Likewise refresh each channel_update so the CHANNELS aren't pruned as
			// stale either. Same policy, fresh timestamp — pure gossip, no force-close risk.
			for (const [channelIdHex, gossip] of this._ownChannelGossip) {
				const refreshedUpdate = this.refreshChannelUpdate(
					gossip.update,
					now,
					Buffer.from(channelIdHex, 'hex')
				);
				if (refreshedUpdate) {
					this._ownChannelGossip.set(channelIdHex, {
						announcement: gossip.announcement,
						update: refreshedUpdate
					});
				}
			}
			this.broadcastOwnGossip();
		}, GOSSIP_REFRESH_INTERVAL_MS);
		if (this._gossipRefreshTimer.unref) this._gossipRefreshTimer.unref();
	}

	// ─────────────── Routing Hints ───────────────

	/**
	 * Build routing hints for private channels, using SCID aliases.
	 * Each hint is one route (array of hops). For direct channels,
	 * each hint has a single hop — the peer's info.
	 */
	private getPrivateChannelRoutingHints(): IRoutingHintHop[][] {
		const hints: IRoutingHintHop[][] = [];

		// Emit a hint for EVERY usable channel — private AND public. Relying on
		// gossip for public channels (LND's behaviour) is too fragile for a
		// wallet/agent node: a freshly-announced channel often hasn't propagated
		// to the payer's graph yet, so without a hint the invoice is unpayable
		// even though the channel is healthy. Including a hint for an
		// already-propagated public channel is harmless (the payer dedupes it).
		for (const channel of this.channelManager.listChannels()) {
			const hop = this.buildRoutingHintForChannel(channel);
			if (hop) hints.push([hop]);
		}

		return hints;
	}

	/**
	 * The peer→us routing hint for one channel (the hop a payer -- or our own
	 * circular rebalance -- uses to land the final hop on this channel), or null
	 * when the channel is unusable or lacks an SCID/alias.
	 */
	private buildRoutingHintForChannel(channel: Channel): IRoutingHintHop | null {
		const state = channel.getFullState();
		// Look through a reconnect (SCID and peer info stay valid for hints),
		// and admit a usable mid-splice channel: it receives fine, still under
		// its pre-splice scid until the lock.
		if (!channel.acceptsNewHtlcs(true)) return null;

		const channelId = channel.getChannelId();
		if (!channelId) return null;

		const peerPubkeyHex = this.channelManager.getPeerForChannel(channelId);
		if (!peerPubkeyHex) return null;

		// SCID for the peer→us hop = the SCID the peer uses to forward HTLCs to
		// us, which is the real SCID once confirmed or else the alias the PEER
		// generated and sent us. See getPeerAddressableScid: BOLT 2 makes the
		// alias generator the alias resolver, so our own scidAlias is the wrong
		// direction here.
		const scid = this.getPeerAddressableScid(state);
		if (!scid) return null;

		const peerPubkey = Buffer.from(peerPubkeyHex, 'hex');

		// Advertise the PEER's actual fee/CLTV policy for the peer→us direction,
		// not our own forwarding defaults. The peer is the forwarding node for
		// this hop, so the hint must match what it really requires — otherwise it
		// rejects the HTLC (e.g. incorrect_cltv_expiry / fee insufficient). For a
		// public channel the peer's channel_update is in our graph; for a
		// PRIVATE channel the graph never stores it, so use the policy the peer
		// sent us directly on this channel (state.remoteForwardingPolicy). Our
		// own defaults are the last resort only.
		let feeBaseMsat = this.forwardingFeeBaseMsat;
		let feeProportionalMillionths = this.forwardingFeePropMillionths;
		let cltvExpiryDelta = this.forwardingCltvDelta;
		const directPolicy = state.remoteForwardingPolicy;
		if (directPolicy) {
			feeBaseMsat = directPolicy.feeBaseMsat;
			feeProportionalMillionths = directPolicy.feeProportionalMillionths;
			cltvExpiryDelta = directPolicy.cltvExpiryDelta;
		}
		if (state.shortChannelId) {
			const graphChannel = this.graph.getChannel(state.shortChannelId);
			const peerUpdate = graphChannel?.nodeId1.equals(peerPubkey)
				? graphChannel.update1
				: graphChannel?.nodeId2.equals(peerPubkey)
				? graphChannel.update2
				: undefined;
			// Prefer whichever the peer signed most recently.
			if (
				peerUpdate &&
				(!directPolicy || peerUpdate.timestamp >= directPolicy.timestamp)
			) {
				feeBaseMsat = peerUpdate.feeBaseMsat;
				feeProportionalMillionths = peerUpdate.feeProportionalMillionths;
				cltvExpiryDelta = peerUpdate.cltvExpiryDelta;
			}
		}

		return {
			pubkey: peerPubkey,
			shortChannelId: scid,
			feeBaseMsat,
			feeProportionalMillionths,
			cltvExpiryDelta
		};
	}

	/**
	 * Find a graph edge that extends a blinded path one hop upstream of our
	 * direct peer: a public channel `intro → peer` whose far endpoint is not us
	 * and whose intro-authored channel_update provides the forwarding policy.
	 * Returns the intro node, the edge SCID, and intro's relay policy.
	 */
	private findBlindedIntroExtension(peerPubkey: Buffer): {
		introPubkey: Buffer;
		shortChannelId: Buffer;
		cltvExpiryDelta: number;
		feeBaseMsat: number;
		feeProportionalMillionths: number;
	} | null {
		const ourNodeId = getPublicKey(this.nodePrivkey);
		for (const edge of this.graph.getNodeChannels(peerPubkey)) {
			const introIsNode1 = edge.nodeId2.equals(peerPubkey);
			const introPubkey = introIsNode1 ? edge.nodeId1 : edge.nodeId2;
			if (introPubkey.equals(ourNodeId) || introPubkey.equals(peerPubkey)) {
				continue;
			}
			// Policy for the intro → peer direction is authored by the intro node.
			const update = introIsNode1 ? edge.update1 : edge.update2;
			if (!update) continue;
			return {
				introPubkey,
				shortChannelId: edge.shortChannelId,
				cltvExpiryDelta: update.cltvExpiryDelta,
				feeBaseMsat: update.feeBaseMsat,
				feeProportionalMillionths: update.feeProportionalMillionths
			};
		}
		return null;
	}

	/**
	 * Build receiver route-blinding blinded payment paths, one per usable
	 * channel. By default each path has 3 nodes [intro → peer → us] when the
	 * public graph offers a forwarding node upstream of our peer (the payer
	 * then learns a node two hops away, not our direct peer), falling back to
	 * the 2-node path [peer → us] otherwise. Mirrors
	 * getPrivateChannelRoutingHints for peer/scid/policy selection.
	 *
	 * The advertised payInfo aggregates ALL forwarding hops (fees compound:
	 * an upstream hop charges its fee on the amount including downstream
	 * fees) so the payer can size fees/timelocks correctly.
	 */
	private buildBlindedPaymentPaths(
		asyncHold = false,
		numHops = 3,
		pathId?: Buffer
	): IBlindedPaymentPath[] {
		const paths: IBlindedPaymentPath[] = [];
		const ourNodeId = getPublicKey(this.nodePrivkey);
		// Absolute CLTV bound for the path's payment constraints. Before the
		// first block arrives the height is 0 and "0 + 2016" is an absolute
		// bound the chain passed years ago: every relay would refuse the
		// payment as expired (issue #544 review). Fall back to the largest
		// height the CLTV encoding allows (500,000,000 is the height/timestamp
		// boundary), which disables the anti-probing bound rather than
		// shipping one that can never pass.
		const maxCltvExpiry =
			this.currentBlockHeight > 0
				? this.currentBlockHeight + 2016
				: 499_999_999;

		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (!channel.acceptsNewHtlcs(true)) continue;

			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peerPubkeyHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerPubkeyHex) continue;
			// Same SCID selection as routing hints: the SCID the peer resolves.
			const scid = this.getPeerAddressableScid(state);
			if (!scid) continue;
			const peerPubkey = Buffer.from(peerPubkeyHex, 'hex');

			// Peer's actual policy for the peer→us hop (same logic as routing
			// hints): graph update for public channels, the channel_update the
			// peer sent us directly for private ones, our defaults last.
			let feeBaseMsat = this.forwardingFeeBaseMsat;
			let feeProportionalMillionths = this.forwardingFeePropMillionths;
			let cltvExpiryDelta = this.forwardingCltvDelta;
			let htlcMinimumMsat = 0n;
			let htlcMaximumMsat: bigint | null = null;
			const directPolicy = state.remoteForwardingPolicy;
			if (directPolicy) {
				feeBaseMsat = directPolicy.feeBaseMsat;
				feeProportionalMillionths = directPolicy.feeProportionalMillionths;
				cltvExpiryDelta = directPolicy.cltvExpiryDelta;
				htlcMinimumMsat = directPolicy.htlcMinimumMsat;
				htlcMaximumMsat = directPolicy.htlcMaximumMsat;
			}
			if (state.shortChannelId) {
				const graphChannel = this.graph.getChannel(state.shortChannelId);
				const peerUpdate = graphChannel?.nodeId1.equals(peerPubkey)
					? graphChannel.update1
					: graphChannel?.nodeId2.equals(peerPubkey)
					? graphChannel.update2
					: undefined;
				if (
					peerUpdate &&
					(!directPolicy || peerUpdate.timestamp >= directPolicy.timestamp)
				) {
					feeBaseMsat = peerUpdate.feeBaseMsat;
					feeProportionalMillionths = peerUpdate.feeProportionalMillionths;
					cltvExpiryDelta = peerUpdate.cltvExpiryDelta;
					htlcMinimumMsat = peerUpdate.htlcMinimumMsat;
					htlcMaximumMsat = peerUpdate.htlcMaximumMsat ?? null;
				}
			}

			// Advertise the peer's real htlc_minimum_msat in the blinded hop's
			// payment_constraints so the payer never sends a sub-minimum HTLC the
			// peer would reject (the same masked-failure class as the fee gap).
			const paymentConstraints = { maxCltvExpiry, htlcMinimumMsat };
			// Peer hop: forward to us over this channel, named by SCID ONLY.
			// BOLT 4 route blinding allows exactly one of short_channel_id /
			// next_node_id per relay hop, and payment relay is SCID-addressed
			// (our own relay resolves hopData.shortChannelId too); emitting
			// both made compliant introduction nodes reject the whole path
			// (issue #544 review). next_node_id belongs to MESSAGE paths, which
			// buildBlindedMessagePaths now builds. For async receive, mark the
			// hop hold_htlc so the LSP parks the HTLC until we return.
			const peerHop: IBlindedHopData = {
				shortChannelId: scid,
				paymentRelay: {
					cltvExpiryDelta,
					feeProportionalMillionths,
					feeBaseMsat
				},
				paymentConstraints,
				...(asyncHold ? { holdHtlc: true } : {})
			};
			// Final hop (us): recipient, no onward forwarding. Our own minimum is
			// 0; do not inherit the peer's htlc_minimum constraint here. The
			// optional path_id binds messages arriving over this path back to
			// whatever published it (e.g. a BOLT 12 offer), for receiver-side
			// verification.
			const finalHop: IBlindedHopData = {
				paymentConstraints: { maxCltvExpiry, htlcMinimumMsat: 0n },
				...(pathId ? { pathId } : {})
			};

			let nodeIds = [peerPubkey, ourNodeId];
			let hopDataList: IBlindedHopData[] = [peerHop, finalHop];
			// Aggregated payInfo across all relay hops (starts with peer's).
			let aggBase = feeBaseMsat;
			let aggProp = feeProportionalMillionths;
			let aggCltv = cltvExpiryDelta;

			// Extend one hop upstream of the peer when requested and the graph
			// offers a candidate: [intro → peer → us].
			if (numHops >= 3) {
				const ext = this.findBlindedIntroExtension(peerPubkey);
				if (ext) {
					const introHop: IBlindedHopData = {
						shortChannelId: ext.shortChannelId,
						paymentRelay: {
							cltvExpiryDelta: ext.cltvExpiryDelta,
							feeProportionalMillionths: ext.feeProportionalMillionths,
							feeBaseMsat: ext.feeBaseMsat
						},
						paymentConstraints
					};
					nodeIds = [ext.introPubkey, peerPubkey, ourNodeId];
					hopDataList = [introHop, peerHop, finalHop];
					// The intro (upstream) hop charges its fee on the amount
					// INCLUDING the peer hop's fee, so fees compound:
					//   base = baseIntro + basePeer + ceil(basePeer * propIntro / 1e6)
					//   prop = propIntro + propPeer + ceil(propIntro * propPeer / 1e6)
					aggBase =
						ext.feeBaseMsat +
						feeBaseMsat +
						Math.ceil((feeBaseMsat * ext.feeProportionalMillionths) / 1e6);
					aggProp =
						ext.feeProportionalMillionths +
						feeProportionalMillionths +
						Math.ceil(
							(ext.feeProportionalMillionths * feeProportionalMillionths) / 1e6
						);
					aggCltv = ext.cltvExpiryDelta + cltvExpiryDelta;
				}
			}

			let path;
			try {
				path = constructBlindedPath(
					crypto.randomBytes(32),
					nodeIds,
					hopDataList
				);
			} catch {
				continue; // skip a channel whose key can't be blinded
			}

			// The advertised payInfo is everything the payer has to size the
			// payment with; a blinded path hides the hops, so nothing can be
			// left for the payer to infer (issue #544 review):
			// - cltv_expiry_delta must INCLUDE our final min_final delta or
			//   the payment arrives under-timelocked and we fail it;
			// - min/max must reflect the peer's actual policy (bounded by
			//   capacity) or the payer sends amounts the peer refuses.
			const capacityMsat = state.fundingSatoshis * 1000n;
			paths.push({
				path,
				payInfo: {
					feeBaseMsat: aggBase,
					feeProportionalMillionths: aggProp,
					cltvExpiryDelta: aggCltv + DEFAULT_MIN_FINAL_CLTV_EXPIRY,
					htlcMinimumMsat,
					htlcMaximumMsat:
						htlcMaximumMsat !== null && htlcMaximumMsat < capacityMsat
							? htlcMaximumMsat
							: capacityMsat
				}
			});
		}

		return paths;
	}

	/**
	 * Blinded MESSAGE paths through our peers, for offer/reply delivery: per
	 * usable channel, [peer → us] (or [intro → peer → us] with numHops >= 3
	 * and a graph candidate). Message relay is next_node_id-addressed (BOLT 4;
	 * our own OnionMessageManager forwards on hopData.nextNodeId), and a
	 * message hop must not carry payment_relay/payment_constraints/hold
	 * records, so these are built apart from the payment paths rather than
	 * reusing them (issue #544 review). The optional path_id rides the final
	 * hop for receiver-side binding (e.g. a BOLT 12 offer's invoice_requests).
	 */
	private buildBlindedMessagePaths(
		numHops = 2,
		pathId?: Buffer
	): IBlindedPath[] {
		const paths: IBlindedPath[] = [];
		const ourNodeId = getPublicKey(this.nodePrivkey);
		for (const channel of this.channelManager.listChannels()) {
			if (!channel.acceptsNewHtlcs(true)) continue;
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peerPubkeyHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerPubkeyHex) continue;
			const peerPubkey = Buffer.from(peerPubkeyHex, 'hex');

			const peerHop: IBlindedHopData = { nextNodeId: ourNodeId };
			const finalHop: IBlindedHopData = pathId ? { pathId } : {};
			let nodeIds = [peerPubkey, ourNodeId];
			let hopDataList: IBlindedHopData[] = [peerHop, finalHop];
			if (numHops >= 3) {
				const ext = this.findBlindedIntroExtension(peerPubkey);
				if (ext) {
					nodeIds = [ext.introPubkey, peerPubkey, ourNodeId];
					hopDataList = [{ nextNodeId: peerPubkey }, peerHop, finalHop];
				}
			}
			try {
				paths.push(
					constructBlindedPath(crypto.randomBytes(32), nodeIds, hopDataList)
				);
			} catch {
				continue; // skip a channel whose key can't be blinded
			}
		}
		return paths;
	}

	/**
	 * Whether this node has a channel a payer can actually find in the public
	 * graph: usable, marked for announcement AND with announcement_signatures
	 * exchanged (that is when the channel_announcement exists and goes out).
	 * announceChannel alone is an INTENT flag: it stays true on pending and
	 * closed channels, and a preferTaproot opener keeps it true while the
	 * wire flag is private, so gating on it suppressed valid private paths
	 * (issue #544 review).
	 */
	private hasPublishedPublicChannel(): boolean {
		return this.channelManager.listChannels().some((channel) => {
			const st = channel.getFullState();
			return (
				st.announceChannel === true &&
				st.announcementSigsSent &&
				st.announcementSigsReceived &&
				channel.acceptsNewHtlcs(true)
			);
		});
	}

	// ─────────────── Gossip Handling ───────────────

	private handleGossipMessage(
		pubkey: string,
		type: number,
		payload: Buffer
	): void {
		switch (type) {
			// Broadcast gossip is queued, not handled inline: see gossipIntake.
			// Query/reply traffic stays synchronous below; it is low-volume,
			// request-scoped, and a sync manager mid-conversation should not
			// wait behind a queued dump.
			case MessageType.CHANNEL_ANNOUNCEMENT:
			case MessageType.NODE_ANNOUNCEMENT:
				this.enqueueBroadcastGossip(pubkey, type, payload);
				break;
			case MessageType.CHANNEL_UPDATE: {
				// A peer's update for one of OUR channels is not crowd gossip:
				// it feeds invoice route hints and blinded-path payment_relay
				// right now, and its volume is bounded by our channel count,
				// so it keeps the synchronous path. Decode here is cheap; the
				// expensive signature check stays behind the graph's gates.
				let ours = false;
				try {
					ours = this.channelUpdateTargetsOurChannel(
						decodeChannelUpdateMessage(payload)
					);
				} catch {
					return; // malformed gossip — same silent drop as the handler's
				}
				if (ours) {
					this.handleChannelUpdate(payload);
					break;
				}
				this.enqueueBroadcastGossip(pubkey, type, payload);
				break;
			}
			case MessageType.REPLY_CHANNEL_RANGE: {
				const syncMgr = this.gossipSyncManagers.get(pubkey);
				if (syncMgr) {
					const msg = decodeReplyChannelRangeMessage(payload);
					const responses = syncMgr.handleReplyChannelRange(msg);
					for (const resp of responses) {
						this.emitOutbound(pubkey, resp.type, resp.payload);
					}
				}
				break;
			}
			case MessageType.REPLY_SHORT_CHANNEL_IDS_END: {
				const syncMgr = this.gossipSyncManagers.get(pubkey);
				if (syncMgr) {
					const msg = decodeReplyShortChannelIdsEndMessage(payload);
					const responses = syncMgr.handleReplyShortChannelIdsEnd(msg);
					for (const resp of responses) {
						this.emitOutbound(pubkey, resp.type, resp.payload);
					}
				}
				break;
			}
			case MessageType.QUERY_CHANNEL_RANGE: {
				const syncMgr = this.getOrCreateSyncManager(pubkey);
				const msg = decodeQueryChannelRangeMessage(payload);
				const responses = syncMgr.handleQueryChannelRange(msg);
				for (const resp of responses) {
					this.emitOutbound(pubkey, resp.type, resp.payload);
				}
				break;
			}
			case MessageType.QUERY_SHORT_CHANNEL_IDS: {
				const syncMgr = this.getOrCreateSyncManager(pubkey);
				const msg = decodeQueryShortChannelIdsMessage(payload);
				const responses = syncMgr.handleQueryShortChannelIds(msg);
				for (const resp of responses) {
					this.emitOutbound(pubkey, resp.type, resp.payload);
				}
				break;
			}
			case MessageType.GOSSIP_TIMESTAMP_FILTER:
				// A peer requesting gossip: at minimum send our own announcements so we
				// propagate into its graph (and onward to explorers). We always include
				// them regardless of the requested window — our node_announcement is
				// refreshed periodically, so its timestamp is current.
				decodeGossipTimestampFilterMessage(payload);
				this.sendOwnGossipTo(pubkey);
				break;
		}
	}

	/**
	 * Queue one broadcast gossip message. Bounded: a flood beyond the cap is
	 * dropped newest-first (dropping oldest would orphan queued updates from
	 * their announcements) and counted, with one structured log per overflow
	 * episode rather than per message.
	 */
	private enqueueBroadcastGossip(
		pubkey: string,
		type: number,
		payload: Buffer
	): void {
		const queued = this.gossipIntake.length - this.gossipIntakeHead;
		if (queued >= LightningNode.GOSSIP_INTAKE_MAX) {
			if (this.gossipIntakeDropped === 0) {
				this.emitStructuredLog('peer', 'gossip_intake_overflow', {
					pubkey,
					queued
				});
			}
			this.gossipIntakeDropped++;
			return;
		}
		this.gossipIntake.push({ pubkey, type, payload });
		if (!this.gossipIntakeDraining) {
			this.gossipIntakeDraining = true;
			setImmediate(() => this.drainGossipIntake());
		}
	}

	/**
	 * Verify and apply queued broadcast gossip in time-budgeted slices,
	 * yielding to the event loop between slices so a graph-sized dump costs
	 * throughput, never liveness. Runs until the queue is empty, then reports
	 * how much an overflow episode dropped (if any) and closes it.
	 */
	private drainGossipIntake(): void {
		const sliceStart = Date.now();
		while (
			this.gossipIntakeHead < this.gossipIntake.length &&
			!this._destroyed &&
			Date.now() - sliceStart < LightningNode.GOSSIP_INTAKE_SLICE_MS
		) {
			const item = this.gossipIntake[this.gossipIntakeHead++];
			try {
				switch (item.type) {
					case MessageType.CHANNEL_ANNOUNCEMENT:
						this.handleChannelAnnouncement(item.payload);
						break;
					case MessageType.NODE_ANNOUNCEMENT:
						this.handleNodeAnnouncement(item.payload);
						break;
					case MessageType.CHANNEL_UPDATE:
						this.handleChannelUpdate(item.payload);
						break;
				}
			} catch (err) {
				this.emitStructuredLog('peer', 'gossip_intake_failed', {
					pubkey: item.pubkey,
					type: item.type,
					error: err instanceof Error ? err.message : String(err)
				});
			}
		}
		if (this.gossipIntakeHead < this.gossipIntake.length && !this._destroyed) {
			setImmediate(() => this.drainGossipIntake());
			return;
		}
		this.gossipIntake = [];
		this.gossipIntakeHead = 0;
		this.gossipIntakeDraining = false;
		if (this.gossipIntakeDropped > 0) {
			this.emitStructuredLog('peer', 'gossip_intake_overflow_ended', {
				dropped: this.gossipIntakeDropped
			});
			this.gossipIntakeDropped = 0;
		}
	}

	/**
	 * Resolves when every currently queued broadcast gossip message has been
	 * processed. Tests and callers that feed gossip and then read the graph
	 * need this barrier; the intake is otherwise deliberately asynchronous.
	 */
	async flushGossip(): Promise<void> {
		while (
			this.gossipIntakeHead < this.gossipIntake.length ||
			this.gossipIntakeDraining
		) {
			await new Promise<void>((resolve) => setImmediate(resolve));
		}
	}

	private getOrCreateSyncManager(pubkey: string): GossipSyncManager {
		let mgr = this.gossipSyncManagers.get(pubkey);
		if (!mgr) {
			mgr = new GossipSyncManager(this.graph, this.chainHash());
			this.gossipSyncManagers.set(pubkey, mgr);
		}
		return mgr;
	}

	/**
	 * Initiate gossip sync with a connected peer.
	 */
	initiateGossipSync(pubkey: string): void {
		const mgr = this.getOrCreateSyncManager(pubkey);
		const messages = mgr.initiateSync();
		for (const msg of messages) {
			this.emitOutbound(pubkey, msg.type, msg.payload);
		}
	}

	/**
	 * Get gossip sync state for a peer.
	 */
	getGossipSyncState(pubkey: string): string | null {
		const mgr = this.gossipSyncManagers.get(pubkey);
		return mgr ? mgr.getState() : null;
	}

	private handleChannelAnnouncement(payload: Buffer): void {
		let msg: IChannelAnnouncementMessage;
		try {
			msg = decodeChannelAnnouncementMessage(payload);
		} catch {
			return; // malformed gossip — drop silently
		}
		// Ask the graph before paying for four signature verifications: a
		// re-served known announcement cannot change anything (issue #437).
		if (!this.graph.wouldAcceptChannelAnnouncement(msg)) {
			return;
		}
		// Lazy mode (default): admit with deferred provenance and skip the
		// signature work entirely; verification pays for itself only at serve
		// time, when a gossip query asks for the entry (issue #443).
		let verified: TGossipVerified = 'deferred';
		if (this.eagerGossipVerify) {
			if (!verifyChannelAnnouncement(msg, payload)) {
				return;
			}
			// The signature covers the full payload, signed future fields
			// included. If the codec cannot reproduce it byte for byte, a
			// served re-encoding would carry invalid signatures, so keep the
			// entry routable but never serve it (#340).
			verified = encodeChannelAnnouncementMessage(msg).equals(payload);
		}
		if (this.graph.addChannelAnnouncement(msg, { verified })) {
			const ch = this.graph.getChannel(msg.shortChannelId);
			if (ch)
				this.safeStorage(
					() =>
						this.storage!.saveGossipChannel(
							msg.shortChannelId.toString('hex'),
							ch
						),
					'saveGossipChannel'
				);
		}
	}

	private handleNodeAnnouncement(payload: Buffer): void {
		let msg: INodeAnnouncementMessage;
		try {
			msg = decodeNodeAnnouncementMessage(payload);
		} catch {
			return; // malformed gossip (e.g. zero timestamp) — drop silently
		}
		// BOLT 7: far-future refusal before the capture path; its private
		// freshness map would otherwise let a validly signed max-u32
		// announcement pin the peer's reconnect fallback address against
		// every later real announcement (issue #446).
		if (gossipTimestampTooFarFuture(msg.timestamp)) {
			return;
		}
		// Verification is worth paying for only if SOME consumer would take
		// the result: the graph (freshness/verified gate) or the channel-peer
		// address capture below (its own freshness map). Otherwise this is a
		// re-served known announcement and its signature proves nothing new.
		const captureWorthwhile = this.nodeAnnouncementCaptureWorthwhile(msg);
		if (!this.graph.wouldAcceptNodeAnnouncement(msg) && !captureWorthwhile) {
			return;
		}
		// Address capture must only ever consume VERIFIED announcements (an
		// unproven claim could redirect a channel peer's reconnects), so a
		// capture-worthy announcement is verified eagerly even in lazy mode.
		// Everything else defers to serve time (issue #443).
		let verified: TGossipVerified = 'deferred';
		if (this.eagerGossipVerify || captureWorthwhile) {
			if (!verifyNodeAnnouncement(msg, payload)) {
				return;
			}
			// A signature-verified announcement from a channel peer is the only
			// dialable address we ever learn for peers that connected inbound
			// (their TCP source port is ephemeral, so it is never stored).
			// Capture it even when the graph rejects the announcement below — a
			// node with only private channels never enters the graph, yet its
			// channels still need a reconnect path or they sit in
			// AWAITING_REESTABLISH forever.
			this.captureChannelPeerAddresses(msg);
			// Serve only what re-encodes byte-identically (see handleChannelAnnouncement).
			verified = encodeNodeAnnouncementMessage(msg).equals(payload);
		}
		if (this.graph.applyNodeAnnouncement(msg, { verified })) {
			const node = this.graph.getNode(msg.nodeId);
			if (node)
				this.safeStorage(
					() => this.storage!.saveGossipNode(msg.nodeId.toString('hex'), node),
					'saveGossipNode'
				);
		}
	}

	/** Pubkeys of every peer we currently have a channel with. */
	private channelPeerPubkeys(): Set<string> {
		const peers = new Set<string>();
		for (const channel of this.channelManager.listChannels()) {
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peer = this.channelManager.getPeerForChannel(channelId);
			if (peer) peers.add(peer);
		}
		return peers;
	}

	/**
	 * Keep a channel peer's announced addresses as reconnect fallbacks and
	 * persist them (with the announcement timestamp) so the peer stays
	 * dialable after a restart. These are deliberately NOT written to
	 * peer_addresses: that store holds last-known-good addresses proven by a
	 * successful outbound dial, and an unproven gossip claim persisted there
	 * would shadow every later announcement (the peer:connect handler is what
	 * promotes a fallback once a dial to it succeeds). The newest announcement
	 * always supersedes, including down to an empty address list.
	 */
	/**
	 * The pre-verification mirror of captureChannelPeerAddresses' own gates:
	 * true only for a channel peer's announcement strictly newer than the one
	 * whose addresses we already hold. Must not drift from that method.
	 */
	private nodeAnnouncementCaptureWorthwhile(
		msg: INodeAnnouncementMessage
	): boolean {
		if (!this.peerManager) return false;
		const pubkey = msg.nodeId.toString('hex');
		if (!this.channelPeerPubkeys().has(pubkey)) return false;
		const previous = this.announcedPeerAddresses.get(pubkey);
		return !previous || msg.timestamp > previous.timestamp;
	}

	private captureChannelPeerAddresses(msg: INodeAnnouncementMessage): void {
		if (!this.peerManager) return;
		const pubkey = msg.nodeId.toString('hex');
		if (!this.channelPeerPubkeys().has(pubkey)) return;
		// A valid signature does not make an old announcement current: reject
		// anything not strictly newer than what we already hold (mirrors the
		// graph's freshness rule, which cannot cover private-only peers).
		const previous = this.announcedPeerAddresses.get(pubkey);
		if (previous && msg.timestamp <= previous.timestamp) return;
		const candidates = announcedDialableAddresses(msg.addresses);
		this.announcedPeerAddresses.set(pubkey, {
			timestamp: msg.timestamp,
			addresses: candidates
		});
		this.peerManager.setAnnouncedAddresses(pubkey, candidates);
		if (this.storage?.saveAnnouncedPeerAddresses) {
			this.safeStorage(
				() =>
					this.storage!.saveAnnouncedPeerAddresses!(
						pubkey,
						msg.timestamp,
						candidates
					),
				'saveAnnouncedPeerAddresses'
			);
		}
	}

	private handleChannelUpdate(payload: Buffer): void {
		let msg: IChannelUpdateMessage;
		try {
			msg = decodeChannelUpdateMessage(payload);
		} catch {
			return; // malformed gossip (e.g. zero timestamp) — drop silently
		}
		// BOLT 7: a far-future timestamp is refused before ANY side effect.
		// The graph gate below refuses it too, but the policy-adoption path
		// runs first and keys its own freshness off the same timestamp:
		// adopted once, a max-u32 update would pin our route hints and
		// blinded-path policy against every later real update (issue #446).
		if (gossipTimestampTooFarFuture(msg.timestamp)) {
			return;
		}
		// Peer policy for OUR channels: private channels never get an
		// announcement, so their updates can never live in the graph. Retain a
		// signature-verified direct update on the channel state instead — the
		// only real source of the peer's fees/CLTV for invoice route hints and
		// blinded-path payment_relay.
		this.maybeAdoptPeerChannelPolicy(msg, payload);
		const channel = this.graph.getChannel(msg.shortChannelId);
		if (!channel) {
			return; // no prior announcement
		}
		// A stale re-send against a verified slot cannot change the graph;
		// refuse it by timestamp before paying for the signature (issue #437).
		if (!this.graph.wouldAcceptChannelUpdate(msg)) {
			return;
		}
		// Updates naming one of OUR channels keep eager verification even in
		// lazy mode: their graph slots back invoice route hints and must never
		// sit deferred. Everything else defers to serve time (issue #443).
		let verified: TGossipVerified = 'deferred';
		if (this.eagerGossipVerify || this.channelUpdateTargetsOurChannel(msg)) {
			if (
				!verifyChannelUpdate(msg, payload, channel.nodeId1, channel.nodeId2)
			) {
				return;
			}
			// Serve only what re-encodes byte-identically (see handleChannelAnnouncement).
			verified = encodeChannelUpdateMessage(msg).equals(payload);
		}
		if (this.graph.applyChannelUpdate(msg, { verified })) {
			const ch = this.graph.getChannel(msg.shortChannelId);
			if (ch)
				this.safeStorage(
					() =>
						this.storage!.saveGossipChannel(
							msg.shortChannelId.toString('hex'),
							ch
						),
					'saveGossipChannel'
				);
		}
	}

	/**
	 * If a channel_update targets one of OUR channels (by real SCID or either
	 * side's alias) and is validly signed by that channel's PEER, retain the
	 * policy on the channel state. This is how the peer's real forwarding
	 * policy for PRIVATE channels reaches invoice route hints and blinded-path
	 * payment_relay; the graph only stores updates for announced channels.
	 */
	/**
	 * Whether a channel_update's SCID (real or either side's alias) names one
	 * of our own channels: the intake fork between the synchronous own-channel
	 * path and the queued crowd-gossip path. Mirrors the candidate matching in
	 * maybeAdoptPeerChannelPolicy below; they must not drift.
	 */
	private channelUpdateTargetsOurChannel(msg: IChannelUpdateMessage): boolean {
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			const scids = [
				state.shortChannelId,
				state.scidAlias,
				state.remoteScidAlias
			].filter((s): s is Buffer => s !== null);
			if (scids.some((s) => s.equals(msg.shortChannelId))) return true;
		}
		return false;
	}

	private maybeAdoptPeerChannelPolicy(
		msg: IChannelUpdateMessage,
		payload: Buffer
	): void {
		// A channel_update for another chain can never describe one of our
		// channels; drop it before touching channel state.
		if (
			this.acceptableChainHashes.length > 0 &&
			!this.acceptableChainHashes.some((h) => h.equals(msg.chainHash))
		) {
			return;
		}
		const ourNodeId = getPublicKey(this.nodePrivkey);
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			const scids = [
				state.shortChannelId,
				state.scidAlias,
				state.remoteScidAlias
			].filter((s): s is Buffer => s !== null);
			if (!scids.some((s) => s.equals(msg.shortChannelId))) continue;

			// A non-matching candidate must NOT end the scan: remoteScidAlias is a
			// peer-chosen value, so a malicious peer could otherwise alias-collide
			// with the real SCID of an honest peer's channel and (by sorting
			// earlier) permanently shadow its policy. Skip to the next channel.
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peerHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerHex) continue;
			const peerNodeId = Buffer.from(peerHex, 'hex');

			// The update must be authored by the PEER (direction bit selects the
			// lexicographically ordered node id) and carry its valid signature.
			const [nodeId1, nodeId2] =
				Buffer.compare(ourNodeId, peerNodeId) < 0
					? [ourNodeId, peerNodeId]
					: [peerNodeId, ourNodeId];
			const signer = (msg.channelFlags & 1) === 0 ? nodeId1 : nodeId2;
			if (!signer.equals(peerNodeId)) continue; // our own update, or wrong channel
			if (!verifyChannelUpdate(msg, payload, nodeId1, nodeId2)) continue;

			const adopted = channel.adoptRemoteForwardingPolicy({
				feeBaseMsat: msg.feeBaseMsat,
				feeProportionalMillionths: msg.feeProportionalMillionths,
				cltvExpiryDelta: msg.cltvExpiryDelta,
				htlcMinimumMsat: msg.htlcMinimumMsat,
				htlcMaximumMsat: msg.htlcMaximumMsat ?? null,
				timestamp: msg.timestamp
			});
			if (adopted) {
				this.persistChannel(channelId);
			}
			return;
		}
	}

	// ─────────────── Invoice Management ───────────────

	createInvoice(options: ICreateInvoiceOptions): ICreateInvoiceResult {
		// Validate description / descriptionHash (BOLT 11: exactly one required)
		if (
			options.description !== undefined &&
			options.descriptionHash !== undefined
		) {
			throw new Error('Cannot specify both description and descriptionHash');
		}
		if (
			options.description === undefined &&
			options.descriptionHash === undefined
		) {
			throw new Error('Must specify either description or descriptionHash');
		}

		// Hold invoice with an externally-held preimage: the caller supplies only
		// the hash, so we never learn the preimage until settle time. Otherwise we
		// generate the preimage ourselves (and can hold it for a hold invoice).
		const externalHash =
			options.hold && options.paymentHash ? options.paymentHash : undefined;
		if (externalHash && externalHash.length !== 32) {
			throw new Error('paymentHash must be 32 bytes');
		}
		const preimage = externalHash ? undefined : crypto.randomBytes(32);
		const paymentHash =
			externalHash ?? crypto.createHash('sha256').update(preimage!).digest();
		const paymentSecret = crypto.randomBytes(32);

		if (preimage) {
			this.preimages.set(paymentHash.toString('hex'), preimage);
		}
		this.paymentSecrets.set(paymentHash.toString('hex'), paymentSecret);
		if (options.hold) {
			this.heldInvoiceHashes.add(paymentHash.toString('hex'));
		}

		// Build routing hints for all channels
		const routingHints = this.getPrivateChannelRoutingHints();

		// Warn if we have a NORMAL channel that could receive (has inbound) but
		// produced no hint — payers may then be unable to find a route to us
		// (e.g. missing SCID/alias, or relying on gossip that hasn't propagated).
		const allChannels = this.channelManager.listChannels();
		if (routingHints.length === 0) {
			const receivableNormal = allChannels.some((ch) =>
				ch.acceptsNewHtlcs(true)
			);
			if (receivableNormal) {
				this.emit('node:error', {
					code: 'NO_ROUTING_HINTS',
					message:
						'Invoice created without routing hints despite having a channel with inbound liquidity (likely missing a usable SCID/alias). Payers may not find a route.',
					timestamp: Date.now()
				} as ILightningError);
			}
		}

		// Optionally build receiver route-blinding blinded paths. When present we
		// advertise blinded paths INSTEAD of cleartext hints (privacy is the whole
		// point — a cleartext hint for the same channel would leak our node id).
		const blindedPaths = options.useBlindedPaths
			? this.buildBlindedPaymentPaths(
					options.asyncHold,
					options.blindedPathNumHops ?? 3
			  )
			: [];
		const useBlinded = blindedPaths.length > 0;

		// Build invoice feature bits (BOLT 11 requires these when payment_secret is present)
		const invoiceFeatures = FeatureFlags.empty();
		invoiceFeatures.setCompulsory(Feature.TLV_ONION); // bit 8
		invoiceFeatures.setCompulsory(Feature.PAYMENT_SECRET); // bit 14
		invoiceFeatures.setOptional(Feature.BASIC_MPP); // bit 17
		if (useBlinded) {
			invoiceFeatures.setOptional(Feature.ROUTE_BLINDING); // bit 25
		}

		const invoiceStr = encodeInvoice({
			network: this.network,
			amountMsat: options.amountMsat,
			description: options.description,
			descriptionHash: options.descriptionHash,
			paymentHash,
			paymentSecret,
			expiry: options.expiry ?? DEFAULT_EXPIRY,
			minFinalCltvExpiry:
				options.minFinalCltvExpiry ?? DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			privateKey: this.nodePrivkey,
			payeeNodeKey: getPublicKey(this.nodePrivkey),
			// Cleartext hints are suppressed under blinding (they would leak the
			// node id blinding hides) UNLESS the caller opts into including them
			// so non-blinded-aware payers can still route (S-4 LOW).
			routingHints:
				(!useBlinded || options.includeCleartextHintsWithBlinded) &&
				routingHints.length > 0
					? routingHints
					: undefined,
			blindedPaths: useBlinded ? blindedPaths : undefined,
			featureBits: invoiceFeatures
		});

		const payment: IPaymentInfo = {
			paymentHash,
			preimage,
			amountMsat: options.amountMsat || 0n,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.INCOMING,
			createdAt: Date.now()
		};
		this.payments.set(paymentHash.toString('hex'), payment);

		// Persist
		const createdAtSecs = Math.floor(Date.now() / 1000);

		this.persistInvoiceRecords(
			paymentHash,
			{
				paymentHash: paymentHash.toString('hex'),
				bolt11: invoiceStr,
				amountMsat: options.amountMsat,
				description: options.description,
				expiry: options.expiry ?? DEFAULT_EXPIRY,
				createdAt: createdAtSecs,
				hold: options.hold
			},
			preimage,
			paymentSecret
		);

		// Store invoice info
		this.invoices.set(paymentHash.toString('hex'), {
			paymentHash: paymentHash.toString('hex'),
			bolt11: invoiceStr,
			amountMsat: options.amountMsat,
			description: options.description,
			expiry: options.expiry ?? DEFAULT_EXPIRY,
			createdAt: createdAtSecs,
			hold: options.hold
		});

		return { bolt11: invoiceStr, paymentHash, paymentSecret };
	}

	// ─────────────── Payment Sending ───────────────

	/**
	 * Build local-channel routing edges for our usable (NORMAL) channels so that
	 * pathfinding can route over them — including a direct payment to a channel
	 * peer — even when the channel is not in the public gossip graph (private or
	 * not yet announced). Matches LND/CLN/LDK behaviour.
	 */
	/**
	 * The channel sendPaymentToRoute would select for this route's first hop
	 * (same selection order: route SCID first, then peer + amount), so a
	 * pre-dispatch check compares against exactly what a dispatch would use.
	 */
	private firstHopChannelFor(route: IRoute): Channel | undefined {
		const firstHop = route.hops[0];
		const firstHopPubkey = firstHop.pubkey.toString('hex');
		return (
			this.findLocalChannelByScid(firstHop.shortChannelId, firstHopPubkey) ??
			this.findChannelForPeer(firstHopPubkey, route.totalAmountMsat)
		);
	}

	private getLocalChannelEdges(): ILocalChannelEdge[] {
		const edges: ILocalChannelEdge[] = [];
		for (const channel of this.channelManager.listChannels()) {
			if (!channel.acceptsNewHtlcs()) continue;
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peerHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerHex) continue;
			const st = channel.getFullState();
			// A splice keeps using its pre-splice scid until the lock.
			const scid = st.shortChannelId ?? st.scidAlias;
			if (!scid) continue;
			// The ceiling is the channel's spendable liquidity — reserve,
			// in-flight HTLCs and commit fee subtracted, and mid-splice the min
			// across both fundings — so the router does not size a route or an
			// MPP part past what addHtlc admits on liquidity grounds (addHtlc
			// still enforces more: HTLC minimums, in-flight count/value caps,
			// dust exposure, channel state). The raw localBalanceMsat bound
			// previously used for NORMAL channels let a near-balance single
			// path or MPP part through that could only die locally in addHtlc
			// as "insufficient balance" (#254).
			const outboundMsat = channel.getSpendableOutboundMsat();
			if (outboundMsat <= 0n) continue;
			edges.push({
				shortChannelId: scid,
				peer: Buffer.from(peerHex, 'hex'),
				outboundMsat,
				// The PEER's htlc_minimum_msat: addHtlc refuses an outgoing HTLC
				// below it, so the router must not plan one (the overlay edge
				// otherwise defaults the minimum to zero, and since local edges
				// shadow announced graph copies, the graph's advertised minimum
				// no longer applies either).
				htlcMinimumMsat: st.remoteConfig.htlcMinimumMsat
			});
		}
		return edges;
	}

	sendPayment(
		invoiceStr: string,
		excludedChannels?: Set<string>,
		maxFeeMsat?: bigint,
		amountMsat?: bigint
	): IPaymentInfo {
		const invoice = decodeInvoice(invoiceStr);

		// Payment deduplication: reject duplicate in-flight payments (Fix 1.4)
		const dedupHashHex = invoice.paymentHash.toString('hex');
		const existingPayment = this.payments.get(dedupHashHex);
		if (existingPayment && existingPayment.status === PaymentStatus.PENDING) {
			throw new LightningPaymentError(
				LightningErrorCode.DUPLICATE_PAYMENT,
				'Payment already in flight for this invoice'
			);
		}

		const destination = invoice.payeeNodeKey || invoice.recoveredPubkey;
		if (!destination) {
			throw new LightningPaymentError(
				LightningErrorCode.INVALID_INVOICE,
				'Cannot determine payee from invoice'
			);
		}

		let paymentAmountMsat = invoice.amountMsat;
		if (paymentAmountMsat === undefined) {
			if (amountMsat === undefined) {
				throw new LightningPaymentError(
					LightningErrorCode.MISSING_AMOUNT,
					'Invoice has no amount and no amountMsat provided'
				);
			}
			paymentAmountMsat = amountMsat;
		}

		// Check invoice expiry before attempting payment (Fix 8)
		const expiryTimestamp =
			invoice.timestamp + (invoice.expiry ?? DEFAULT_EXPIRY);
		if (Math.floor(Date.now() / 1000) > expiryTimestamp) {
			const payment: IPaymentInfo = {
				paymentHash: invoice.paymentHash,
				amountMsat: paymentAmountMsat,
				status: PaymentStatus.FAILED,
				direction: PaymentDirection.OUTGOING,
				failureReason: `Invoice expired at ${new Date(
					expiryTimestamp * 1000
				).toISOString()}`,
				createdAt: Date.now(),
				completedAt: Date.now()
			};
			this.payments.set(invoice.paymentHash.toString('hex'), payment);
			this.emit('payment:failed', payment);
			return payment;
		}

		// BOLT 11 payer MUSTs: fail the payment when the invoice requires a
		// feature we do not understand (unknown even bit in the `9` field), and
		// never pay a secretless invoice (payment_secret is compulsory; without
		// it any forwarding node can probe or steal an amount-adjusted payment).
		if (invoice.featureBits) {
			for (const bit of invoice.featureBits.listSetBits()) {
				if (bit % 2 === 0 && !PAYER_UNDERSTOOD_INVOICE_FEATURES.has(bit)) {
					throw new LightningPaymentError(
						LightningErrorCode.INVALID_INVOICE,
						`Invoice requires unknown feature bit ${bit}`
					);
				}
			}
		}
		if (!invoice.paymentSecret) {
			throw new LightningPaymentError(
				LightningErrorCode.INVALID_INVOICE,
				'Invoice has no payment secret (s field); refusing to pay'
			);
		}

		const finalCltvExpiry = this.paddedFinalCltvExpiry(
			invoice.minFinalCltvExpiry
		);
		const sourceNodeId = getPublicKey(this.nodePrivkey);

		// Route blinding: if the invoice advertises blinded paths, route through
		// one (the sender learns only the introduction node, never the payee).
		if (invoice.blindedPaths && invoice.blindedPaths.length > 0) {
			const blinded = invoice.blindedPaths[0];
			const blindedRoute = findRouteToBlindedPath(
				this.graph,
				sourceNodeId,
				blinded.path,
				blinded.payInfo,
				paymentAmountMsat,
				finalCltvExpiry,
				undefined,
				excludedChannels,
				this.missionControl,
				this.getLocalChannelEdges()
			);
			if (!blindedRoute) {
				throw new LightningPaymentError(
					LightningErrorCode.NO_ROUTE,
					'No route to blinded path introduction node'
				);
			}
			// The fee cap judges the fee actually PAID: a self-introduction
			// send removes our own introduction fee on the wire, so a
			// genuinely zero-fee payment must pass maxFeeMsat 0 (issue #550
			// review). prepareSelfIntroSend also validates the path, so an
			// unusable self-intro path fails here by name.
			const selfIntroForCap = this.prepareSelfIntroSend(blindedRoute);
			const effectiveFeeMsat =
				selfIntroForCap?.wireRoute.totalFeeMsat ?? blindedRoute.totalFeeMsat;
			if (maxFeeMsat !== undefined && effectiveFeeMsat > maxFeeMsat) {
				throw new LightningPaymentError(
					LightningErrorCode.FEE_EXCEEDS_MAX,
					'Route fee exceeds maximum'
				);
			}
			const bHashHex = invoice.paymentHash.toString('hex');
			if (!this.paymentRetryContexts.has(bHashHex)) {
				this.paymentRetryContexts.set(bHashHex, {
					invoiceStr,
					excludedChannels: excludedChannels || new Set(),
					retryCount: 0,
					maxRetries: this.maxPaymentRetries,
					maxFeeMsat,
					amountMsat
				});
			}
			return this.sendPaymentToRoute(
				blindedRoute,
				invoice.paymentHash,
				finalCltvExpiry,
				invoice.paymentSecret,
				paymentAmountMsat
			);
		}

		const localChannels = this.getLocalChannelEdges();
		let route = findRoute(
			this.graph,
			sourceNodeId,
			destination,
			paymentAmountMsat,
			finalCltvExpiry,
			undefined,
			excludedChannels,
			this.missionControl,
			undefined,
			invoice.routingHints,
			undefined,
			localChannels
		);
		// The router can bound our first hop looser than what addHtlc enforces
		// (a graph update's advertised maximum, or a race against in-flight
		// HTLCs), so a single-path route the outgoing channel cannot actually
		// carry would only die locally in addHtlc as "insufficient balance".
		// When the selected channel exists but cannot carry the total, treat
		// the route as unroutable up front so the MPP fallback below can split
		// the payment across channels (#254). When NO channel is found at all,
		// keep the route: MPP could not dispatch either, and sendPaymentToRoute
		// reports the precise no-channel failure.
		if (route) {
			const firstHopChannel = this.firstHopChannelFor(route);
			if (
				firstHopChannel &&
				firstHopChannel.getSpendableOutboundMsat() < route.totalAmountMsat
			) {
				route = null;
			}
		}
		// MPP requires the recipient to advertise basic_mpp (BOLT 4): splitting
		// to a non-MPP recipient locks every part until the mpp_timeout.
		if (
			!route &&
			invoice.paymentSecret &&
			invoice.featureBits?.hasFeature(Feature.BASIC_MPP)
		) {
			// Try multi-path routing as fallback. Retries re-enter here with the
			// retry context's exclusion set, so failed SCIDs must be excluded
			// from MPP parts exactly as they are from single-path routes.
			const multiRoute = findMultiPathRoute(
				this.graph,
				sourceNodeId,
				destination,
				paymentAmountMsat,
				finalCltvExpiry,
				undefined,
				undefined,
				this.missionControl,
				invoice.routingHints,
				undefined,
				localChannels,
				excludedChannels
			);
			if (multiRoute) {
				if (maxFeeMsat !== undefined && multiRoute.totalFeeMsat > maxFeeMsat) {
					throw new LightningPaymentError(
						LightningErrorCode.FEE_EXCEEDS_MAX,
						'Route fee exceeds maximum'
					);
				}
				return this.sendPaymentMpp(
					invoiceStr,
					invoice,
					multiRoute,
					finalCltvExpiry,
					excludedChannels
				);
			}
		}
		if (!route) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'No route found to destination'
			);
		}

		// Check fee cap
		if (maxFeeMsat !== undefined && route.totalFeeMsat > maxFeeMsat) {
			throw new LightningPaymentError(
				LightningErrorCode.FEE_EXCEEDS_MAX,
				'Route fee exceeds maximum'
			);
		}

		// Store retry context for this payment
		const hashHex = invoice.paymentHash.toString('hex');
		if (!this.paymentRetryContexts.has(hashHex)) {
			this.paymentRetryContexts.set(hashHex, {
				invoiceStr,
				excludedChannels: excludedChannels || new Set(),
				retryCount: 0,
				maxRetries: this.maxPaymentRetries,
				maxFeeMsat,
				amountMsat
			});
		}

		return this.sendPaymentToRoute(
			route,
			invoice.paymentHash,
			finalCltvExpiry,
			invoice.paymentSecret,
			paymentAmountMsat
		);
	}

	sendPaymentToRoute(
		route: {
			hops: Array<{
				pubkey: Buffer;
				shortChannelId: Buffer;
				amountToForwardMsat: bigint;
				outgoingCltvValue: number;
				encryptedRecipientData?: Buffer;
				blindingPoint?: Buffer;
			}>;
		},
		paymentHash: Buffer,
		finalCltvExpiry: number,
		paymentSecret?: Buffer,
		totalMsat?: bigint
	): IPaymentInfo {
		if (route.hops.length === 0) {
			throw new Error('Route must have at least one hop');
		}

		// BOLT 4 self-introduction (issue #550): a blinded path can name US as
		// its introduction node; the routine case is an unannounced node's
		// BOLT 12 offer whose payment path runs through its direct peer, and
		// we ARE that peer. prepareSelfIntroSend processes our own hop the way
		// a relaying forward would and hands back the wire-true view: the
		// onion starts at the SECOND blinded hop, the amount/CLTV have our
		// payment_relay inverted away (we do not charge ourselves the
		// introduction fee), and the next blinding point rides
		// update_add_htlc. Everything recorded below (payment.route, shared
		// secrets, failure indices) uses that wire-true route, so failure
		// attribution and the height-skew retry read the hop that actually
		// erred (issue #550 review).
		const selfIntro = this.prepareSelfIntroSend(route);
		const hops = selfIntro ? selfIntro.wireRoute.hops : route.hops;

		// Route CLTV values are RELATIVE deltas (from pathfinding). Each hop's
		// outgoing_cltv_value on the wire must be ABSOLUTE (current block height +
		// accumulated delta), otherwise the final node rejects the HTLC as
		// "cltv expiry too soon" (incorrect_or_unknown_payment_details).
		const baseHeight = this.cltvBaseHeight(paymentHash);

		// Convert route hops to onion hop payloads.
		// For intermediate hops: the payload tells the hop what to FORWARD (next hop's
		// amount/cltv), and which channel to use (next hop's SCID).
		// For the final hop: the payload contains the payment amount/cltv directly.
		const onionHops: { pubkey: Buffer; payload: IHopPayload }[] = hops.map(
			(hop, idx) => {
				const isFinal = idx === hops.length - 1;
				const payload: IHopPayload = isFinal
					? {
							amountToForwardMsat: hop.amountToForwardMsat,
							outgoingCltvValue: hop.outgoingCltvValue + baseHeight
					  }
					: {
							amountToForwardMsat: hops[idx + 1].amountToForwardMsat,
							outgoingCltvValue: hops[idx + 1].outgoingCltvValue + baseHeight,
							shortChannelId: hops[idx + 1].shortChannelId
					  };
				if (isFinal && paymentSecret) {
					payload.paymentSecret = paymentSecret;
					payload.totalMsat = totalMsat ?? hop.amountToForwardMsat;
				}
				// Route blinding (BOLT 4): the introduction node and each blinded
				// hop read their own encrypted_recipient_data (TLV 10) to learn the
				// real next node/scid; the introduction node also receives the
				// blinding_point (TLV 12). These belong to THIS hop, not the next.
				if (hop.encryptedRecipientData) {
					payload.encryptedRecipientData = hop.encryptedRecipientData;
					// BOLT 4: a blinded hop MUST NOT carry a cleartext short_channel_id
					// — its onward channel lives in encrypted_recipient_data. Leaving a
					// (zero) SCID makes LND reject the payload as invalid_onion_blinding.
					delete payload.shortChannelId;
					// A blinded INTERMEDIATE hop also omits amt_to_forward/outgoing_cltv
					// (derived from encrypted payment_relay). The final hop keeps them
					// and MUST carry total_amount_msat (TLV 18) — the blinded path's
					// path_id authenticates the payment there, not payment_data, and
					// CLN fails a blinded final payload without it as
					// invalid_onion_payload.
					if (!isFinal) {
						payload.omitForwardAmounts = true;
					} else {
						payload.totalAmountMsat = totalMsat ?? hop.amountToForwardMsat;
					}
				}
				if (hop.blindingPoint) {
					payload.blindingPoint = hop.blindingPoint;
				}
				return { pubkey: hop.pubkey, payload };
			}
		);

		// Generate session key and compute shared secrets for failure decryption
		const sessionKey = crypto.randomBytes(32);
		const hopPubkeys = hops.map((h) => h.pubkey);
		const { sharedSecrets } = computeSharedSecrets(sessionKey, hopPubkeys);

		// Construct and encode onion packet
		const onionPacket = constructOnionPacket(
			sessionKey,
			onionHops,
			paymentHash
		);
		const onionBuf = encodeOnionPacket(onionPacket);

		// Find outgoing channel to first hop. When the route's first-hop SCID
		// names one of OUR channels to that peer (e.g. a circular rebalance that
		// must leave over a specific channel), honor it; otherwise fall back to
		// smart selection by balance (Fix 3.3). A self-introduction send has
		// already resolved its channel from OUR decrypted hop's onward SCID:
		// the first remaining hop's pubkey is a BLINDED id, which no peer
		// lookup can resolve.
		const firstHopPubkey = hops[0].pubkey.toString('hex');
		const outChannel =
			selfIntro?.outChannel ??
			this.findLocalChannelByScid(hops[0].shortChannelId, firstHopPubkey) ??
			this.findChannelForPeer(firstHopPubkey, hops[0].amountToForwardMsat);
		if (!outChannel) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_CHANNEL_TO_HOP,
				`No channel to first hop ${firstHopPubkey}`
			);
		}

		const channelId = outChannel.getChannelId()!;
		const cltvExpiry =
			(selfIntro?.wireCltvRel ?? hops[0].outgoingCltvValue) + baseHeight;
		const amount = selfIntro?.wireAmountMsat ?? hops[0].amountToForwardMsat;

		// Create payment info BEFORE addHtlc because in synchronous loopback
		// the entire fulfill chain runs during addHtlc
		const payment: IPaymentInfo = {
			paymentHash,
			amountMsat: amount,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			cltvBaseHeight: baseHeight,
			// The WIRE-TRUE route: for a self-introduction send this is the
			// sliced tail with the intro fee removed from the totals, so
			// failure indices decoded against sharedSecrets name the hop that
			// actually erred and the reported fee is the fee actually paid
			// (issue #550 review).
			route: (selfIntro?.wireRoute ?? route) as {
				hops: Array<{
					pubkey: Buffer;
					shortChannelId: Buffer;
					amountToForwardMsat: bigint;
					outgoingCltvValue: number;
					feeBaseMsat: number;
					feeProportionalMillionths: number;
					cltvExpiryDelta: number;
				}>;
				totalAmountMsat: bigint;
				totalCltvDelta: number;
				totalFeeMsat: bigint;
			},
			sharedSecrets,
			createdAt: Date.now()
		};
		this.payments.set(paymentHash.toString('hex'), payment);

		// Track offered HTLC → payment mapping
		const htlcId = outChannel.getFullState().localHtlcCounter;
		const htlcKey = `${channelId.toString('hex')}:offered-${htlcId}`;
		this.htlcPaymentMap.set(htlcKey, paymentHash.toString('hex'));
		{
			const mutations: RecoveryMutation[] = [
				{
					type: 'htlc_payment_mapping',
					htlcKey,
					paymentHash: paymentHash.toString('hex')
				}
			];
			const paymentMutation = this.paymentMutation(paymentHash);
			if (paymentMutation) mutations.unshift(paymentMutation);
			this.commitMutations(
				'persist payment + HTLC mapping',
				mutations,
				RecoveryCriticality.SafetyCritical
			);
		}

		// Add HTLC to channel (may trigger synchronous fulfillment via loopback)
		const result = this.channelManager.addHtlc(
			channelId,
			amount,
			paymentHash,
			cltvExpiry,
			onionBuf,
			// Self-introduction send (issue #550): the peer inside the blinded
			// segment derives its key from this point, delivered on
			// update_add_htlc exactly as a relaying forward delivers it.
			selfIntro?.blindingPoint
		);
		if (!result.ok) {
			payment.status = PaymentStatus.FAILED;
			payment.completedAt = Date.now();
			// The HTLC never left this node, so there is no onion failure to
			// decrypt and failureCode stays undefined. addHtlc already knows why
			// (no such channel, peer not connected, insufficient balance); losing
			// that string is what makes a local failure look like a mystery.
			payment.failureReason =
				result.error ?? 'Local failure: could not add HTLC to the channel';
			// htlcKey was derived from localHtlcCounter before the add, and a refused
			// add does not consume that id, so the mapping written above now points
			// at an id a later unrelated HTLC will take. Drop it in both places, and
			// persist the FAILED status so storage does not keep the PENDING row
			// written moments ago. One journaled transition carries both.
			this.htlcPaymentMap.delete(htlcKey);
			const failMutations: RecoveryMutation[] = [
				{ type: 'delete_htlc_payment_mapping', htlcKey }
			];
			const failPayment = this.paymentMutation(paymentHash);
			if (failPayment) failMutations.push(failPayment);
			this.commitMutations('release failed HTLC mapping', failMutations);
			this.emit('payment:failed', payment);
		}

		return payment;
	}

	/**
	 * Final CLTV delta to send an outgoing payment with, given the payee's
	 * advertised min_final_cltv_expiry_delta (or our default when it advertised
	 * none), plus padding for block-height skew. See FINAL_CLTV_EXPIRY_PADDING.
	 */
	private paddedFinalCltvExpiry(minFinalCltvExpiry?: number): number {
		return (
			(minFinalCltvExpiry ?? DEFAULT_MIN_FINAL_CLTV_EXPIRY) +
			FINAL_CLTV_EXPIRY_PADDING
		);
	}

	/**
	 * Block height to convert relative route CLTV deltas into absolute wire values.
	 *
	 * Normally our own height, but a final node that already failed THIS payment
	 * for being ahead of us has told us its height, and sending against our stale
	 * view again would fail identically. Taking the max only ever raises the
	 * expiry, which is the safe direction. Scoped per payment so one payee's claim
	 * cannot steer unrelated payments.
	 */
	private cltvBaseHeight(paymentHash: Buffer): number {
		const ctx = this.paymentRetryContexts.get(paymentHash.toString('hex'));
		return Math.max(this.currentBlockHeight, ctx?.cltvBaseHeightOverride ?? 0);
	}

	/**
	 * Recognise the transient half of the overloaded PERM|15 failure: a final node
	 * rejecting our expiry because its block height is ahead of ours, rather than
	 * because the payment hash is unknown, the secret is wrong, or the amount is
	 * off. Every one of those shares this code, so the height alone is not enough
	 * to call a failure transient:
	 *
	 * - it must come from the FINAL hop, since BOLT 4 defines the field as the
	 *   final node's height, and
	 * - it must exceed the height THIS attempt was built against, otherwise it
	 *   tells us nothing we did not already act on and every later failure to the
	 *   same payee would masquerade as skew until the retries ran out.
	 */
	private noteHeightSkewFailure(
		payment: IPaymentInfo,
		failureData?: Buffer,
		route: IPaymentInfo['route'] = payment.route
	): boolean {
		if (payment.failureCode !== INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS) {
			return false;
		}
		const finalHopIndex = (route?.hops.length ?? 0) - 1;
		if (finalHopIndex < 0 || payment.failureSourceIndex !== finalHopIndex) {
			return false;
		}
		// [u64 htlc_msat][u32 height]; older peers may send it empty.
		if (!failureData || failureData.length < 12) return false;

		const reportedHeight = failureData.readUInt32BE(8);
		const attemptBase = payment.cltvBaseHeight ?? this.currentBlockHeight;
		if (reportedHeight <= attemptBase) return false;
		if (
			reportedHeight - this.currentBlockHeight >
			MAX_TRUSTED_PEER_HEIGHT_SKEW
		) {
			return false;
		}

		const ctx = this.paymentRetryContexts.get(
			payment.paymentHash.toString('hex')
		);
		if (!ctx) return false;
		ctx.cltvBaseHeightOverride = Math.max(
			ctx.cltvBaseHeightOverride ?? 0,
			reportedHeight
		);
		return true;
	}

	/**
	 * Record a blinded-path-level failure for a BOLT 12 payment, and report
	 * whether rotating to another of the invoice's paths is possible.
	 *
	 * A failure sourced at or beyond the introduction node but BEFORE the
	 * final hop failed inside the blinded segment: the erring "channel" is
	 * opaque (zeroed SCID), so only skipping the whole path can route around
	 * it. The final hop is the recipient, whose failures judge the payment
	 * itself (wrong amount, unknown hash) rather than the path, with one
	 * exception: invalid_onion_blinding, which BOLT 4 has every blinded hop,
	 * final included, return for any error inside a blinded path. Height
	 * skew is excluded outright, since there the path did nothing wrong.
	 *
	 * When the criterion holds, the attempt's path index is added to the
	 * context's excluded set. Returns true only if a non-excluded path
	 * remains, which is what justifies retrying a code whose PERM bits
	 * would otherwise end the payment.
	 */
	private noteBolt12BlindedPathFailure(
		ctx: IPaymentRetryContext | undefined,
		payment: IPaymentInfo,
		route: IPaymentInfo['route'],
		heightSkew: boolean
	): boolean {
		if (!ctx?.bolt12Invoice || heightSkew) return false;
		if (ctx.bolt12PathIndex === undefined) return false;
		const hops = route?.hops as IRouteHop[] | undefined;
		if (!hops || payment.failureSourceIndex === undefined) return false;
		const introIndex = hops.findIndex(
			(hop) =>
				hop.encryptedRecipientData !== undefined ||
				hop.blindingPoint !== undefined
		);
		if (introIndex < 0 || payment.failureSourceIndex < introIndex) {
			return false;
		}
		const blindedSegmentFailure =
			payment.failureSourceIndex < hops.length - 1 ||
			payment.failureCode === INVALID_ONION_BLINDING;
		if (!blindedSegmentFailure) return false;
		if (!ctx.bolt12ExcludedPathIndices) {
			ctx.bolt12ExcludedPathIndices = new Set();
		}
		ctx.bolt12ExcludedPathIndices.add(ctx.bolt12PathIndex);
		return (
			ctx.bolt12ExcludedPathIndices.size <
			(ctx.bolt12Invoice.paths?.length ?? 0)
		);
	}

	/**
	 * Send a keysend (spontaneous) payment — bLIP-0003.
	 *
	 * The sender generates a random preimage, includes it in the final hop
	 * via TLV type 5482373484, and the recipient extracts + verifies it.
	 */
	sendKeysend(options: IKeysendOptions): IPaymentInfo {
		// A fresh preimage per call, so each keysend is its own payment.
		return this.dispatchKeysend(options, crypto.randomBytes(32));
	}

	/**
	 * Send a keysend against a caller-supplied preimage.
	 *
	 * Split out from sendKeysend so a retry can replay the SAME preimage, and
	 * therefore the same payment hash. Generating a new one would make the retry a
	 * different payment that no longer matches the retry context, the in-flight
	 * record, or anything the caller is waiting on.
	 */
	private dispatchKeysend(
		options: IKeysendOptions,
		preimage: Buffer,
		excludedChannels?: Set<string>
	): IPaymentInfo {
		const {
			destination,
			amountMsat,
			maxFeeMsat,
			customRecords: extraRecords,
			metadata
		} = options;

		// Validate destination (33-byte compressed pubkey)
		if (!destination || destination.length !== 33) {
			throw new LightningPaymentError(
				LightningErrorCode.INVALID_KEYSEND,
				'destination must be a 33-byte compressed public key'
			);
		}
		if (amountMsat <= 0n) {
			throw new LightningPaymentError(
				LightningErrorCode.INVALID_KEYSEND,
				'amountMsat must be positive'
			);
		}

		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const hashHex = paymentHash.toString('hex');

		// Payment deduplication
		const existingPayment = this.payments.get(hashHex);
		if (existingPayment && existingPayment.status === PaymentStatus.PENDING) {
			throw new LightningPaymentError(
				LightningErrorCode.DUPLICATE_PAYMENT,
				'Payment already in flight'
			);
		}

		const finalCltvExpiry = this.paddedFinalCltvExpiry();
		const sourceNodeId = getPublicKey(this.nodePrivkey);

		const route = findRoute(
			this.graph,
			sourceNodeId,
			destination,
			amountMsat,
			finalCltvExpiry,
			undefined,
			excludedChannels,
			this.missionControl,
			undefined,
			undefined,
			undefined,
			this.getLocalChannelEdges()
		);
		if (!route) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'No route found to destination'
			);
		}

		if (maxFeeMsat !== undefined && route.totalFeeMsat > maxFeeMsat) {
			throw new LightningPaymentError(
				LightningErrorCode.FEE_EXCEEDS_MAX,
				'Route fee exceeds maximum'
			);
		}

		// A keysend has no invoice to re-pay, so record what a retry needs to
		// replay it: the same preimage, and therefore the same payment hash.
		// Registered only after the route and fee checks pass, mirroring
		// sendPayment: a dispatch that throws above must not leave a context
		// behind for a payment that never existed.
		if (!this.paymentRetryContexts.has(hashHex)) {
			this.paymentRetryContexts.set(hashHex, {
				keysend: { options, preimage },
				excludedChannels: excludedChannels ?? new Set(),
				retryCount: 0,
				maxRetries: this.maxPaymentRetries,
				maxFeeMsat
			});
		}

		const hops = route.hops;
		// Route CLTVs are relative deltas; the wire needs absolute (height + delta).
		const baseHeight = this.cltvBaseHeight(paymentHash);

		// Build onion hop payloads — final hop gets keysend TLV
		const keysendRecords = new Map<number, Buffer>();
		keysendRecords.set(KEYSEND_TLV_TYPE, preimage);
		if (extraRecords) {
			for (const [type, value] of extraRecords) {
				keysendRecords.set(type, value);
			}
		}

		const onionHops: { pubkey: Buffer; payload: IHopPayload }[] = hops.map(
			(hop, idx) => {
				const isFinal = idx === hops.length - 1;
				const payload: IHopPayload = isFinal
					? {
							amountToForwardMsat: hop.amountToForwardMsat,
							outgoingCltvValue: hop.outgoingCltvValue + baseHeight,
							customRecords: keysendRecords
					  }
					: {
							amountToForwardMsat: hops[idx + 1].amountToForwardMsat,
							outgoingCltvValue: hops[idx + 1].outgoingCltvValue + baseHeight,
							shortChannelId: hops[idx + 1].shortChannelId
					  };
				return { pubkey: hop.pubkey, payload };
			}
		);

		const sessionKey = crypto.randomBytes(32);
		const hopPubkeys = hops.map((h) => h.pubkey);
		const { sharedSecrets } = computeSharedSecrets(sessionKey, hopPubkeys);
		const onionPacket = constructOnionPacket(
			sessionKey,
			onionHops,
			paymentHash
		);
		const onionBuf = encodeOnionPacket(onionPacket);

		// Find outgoing channel
		const firstHopPubkey = hops[0].pubkey.toString('hex');
		const outChannel = this.findChannelForPeer(
			firstHopPubkey,
			hops[0].amountToForwardMsat
		);
		if (!outChannel) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_CHANNEL_TO_HOP,
				`No channel to first hop ${firstHopPubkey}`
			);
		}

		const channelId = outChannel.getChannelId()!;
		const cltvExpiry = hops[0].outgoingCltvValue + baseHeight;
		const amount = hops[0].amountToForwardMsat;

		// Create payment record BEFORE addHtlc (synchronous loopback pattern)
		const payment: IPaymentInfo = {
			paymentHash,
			preimage,
			amountMsat: amount,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			cltvBaseHeight: baseHeight,
			route: route as IPaymentInfo['route'],
			sharedSecrets,
			createdAt: Date.now(),
			metadata: { _keysend: 'true', ...(metadata || {}) }
		};
		this.payments.set(hashHex, payment);

		// Track offered HTLC → payment mapping
		const htlcId = outChannel.getFullState().localHtlcCounter;
		const htlcKey = `${channelId.toString('hex')}:offered-${htlcId}`;
		this.htlcPaymentMap.set(htlcKey, hashHex);
		{
			const mutations: RecoveryMutation[] = [
				{ type: 'htlc_payment_mapping', htlcKey, paymentHash: hashHex }
			];
			const paymentMutation = this.paymentMutation(paymentHash);
			if (paymentMutation) mutations.unshift(paymentMutation);
			this.commitMutations(
				'persist payment + HTLC mapping',
				mutations,
				RecoveryCriticality.SafetyCritical
			);
		}

		const result = this.channelManager.addHtlc(
			channelId,
			amount,
			paymentHash,
			cltvExpiry,
			onionBuf
		);
		if (!result.ok) {
			payment.status = PaymentStatus.FAILED;
			payment.completedAt = Date.now();
			// The HTLC never left this node, so there is no onion failure to
			// decrypt and failureCode stays undefined. addHtlc already knows why
			// (no such channel, peer not connected, insufficient balance); losing
			// that string is what makes a local failure look like a mystery.
			payment.failureReason =
				result.error ?? 'Local failure: could not add HTLC to the channel';
			// Same stale-mapping and unpersisted-status cleanup as sendPayment.
			this.htlcPaymentMap.delete(htlcKey);
			const failMutations: RecoveryMutation[] = [
				{ type: 'delete_htlc_payment_mapping', htlcKey }
			];
			const failPayment = this.paymentMutation(paymentHash);
			if (failPayment) failMutations.push(failPayment);
			this.commitMutations('release failed HTLC mapping', failMutations);
			this.emit('payment:failed', payment);
		}

		return payment;
	}

	/**
	 * Send a payment using multi-path routing (MPP).
	 * Splits payment across multiple routes, each carrying a portion.
	 */
	private sendPaymentMpp(
		invoiceStr: string,
		invoice: {
			paymentHash: Buffer;
			paymentSecret?: Buffer;
			amountMsat?: bigint;
		},
		multiRoute: {
			parts: Array<{
				hops: Array<{
					pubkey: Buffer;
					shortChannelId: Buffer;
					amountToForwardMsat: bigint;
					outgoingCltvValue: number;
					feeBaseMsat: number;
					feeProportionalMillionths: number;
					cltvExpiryDelta: number;
				}>;
				totalAmountMsat: bigint;
				totalCltvDelta: number;
				totalFeeMsat: bigint;
			}>;
			totalAmountMsat: bigint;
			totalFeeMsat: bigint;
		},
		_finalCltvExpiry: number,
		excludedChannels?: Set<string>
	): IPaymentInfo {
		const paymentHash = invoice.paymentHash;
		const hashHex = paymentHash.toString('hex');
		const totalMsat = invoice.amountMsat!;

		// Create a single payment record
		const payment: IPaymentInfo = {
			paymentHash,
			amountMsat: totalMsat,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now()
		};
		this.payments.set(hashHex, payment);

		// Store retry context. Seed it with the exclusions this attempt was
		// routed under so a retry keeps avoiding those SCIDs and the failure
		// handler accumulates onto the same set.
		if (!this.paymentRetryContexts.has(hashHex)) {
			this.paymentRetryContexts.set(hashHex, {
				invoiceStr,
				excludedChannels: excludedChannels ?? new Set(),
				retryCount: 0,
				maxRetries: this.maxPaymentRetries
			});
		}

		// Track MPP state
		const mppState: IOutboundMppState = {
			paymentHash,
			totalMsat,
			parts: [],
			createdAt: Date.now()
		};
		this.outboundMppPayments.set(hashHex, mppState);

		// Dispatch each part
		for (const partRoute of multiRoute.parts) {
			const hops = partRoute.hops;
			if (hops.length === 0) continue;
			// Route CLTVs are relative deltas; the wire needs absolute (height + delta).
			const baseHeight = this.cltvBaseHeight(paymentHash);
			// Every part converts against the same height, so this records what a
			// height-skew failure has to beat to count as new information.
			payment.cltvBaseHeight = baseHeight;

			// Each part's final hop must have paymentSecret and totalMsat = full invoice amount
			const onionHops: { pubkey: Buffer; payload: IHopPayload }[] = hops.map(
				(hop, idx) => {
					const isFinal = idx === hops.length - 1;
					const payload: IHopPayload = isFinal
						? {
								amountToForwardMsat: hop.amountToForwardMsat,
								outgoingCltvValue: hop.outgoingCltvValue + baseHeight
						  }
						: {
								amountToForwardMsat: hops[idx + 1].amountToForwardMsat,
								outgoingCltvValue: hops[idx + 1].outgoingCltvValue + baseHeight,
								shortChannelId: hops[idx + 1].shortChannelId
						  };
					if (isFinal && invoice.paymentSecret) {
						payload.paymentSecret = invoice.paymentSecret;
						payload.totalMsat = totalMsat; // Full amount, not part amount
					}
					return { pubkey: hop.pubkey, payload };
				}
			);

			const sessionKey = crypto.randomBytes(32);
			const hopPubkeys = hops.map((h) => h.pubkey);
			const { sharedSecrets } = computeSharedSecrets(sessionKey, hopPubkeys);

			const onionPacket = constructOnionPacket(
				sessionKey,
				onionHops,
				paymentHash
			);
			const onionBuf = encodeOnionPacket(onionPacket);

			// Honor the planner's channel: MPP capacity was accounted per SCID,
			// so each part must leave over the channel it was sized for.
			// Peer-based selection could reseat the part on a sibling channel
			// (chosen by balance) that cannot actually carry it, and a locally
			// refused part cannot be rolled back once earlier parts are out.
			// Same selection rule as sendPaymentToRoute.
			const outChannel = this.firstHopChannelFor(partRoute);
			if (!outChannel) continue;

			const channelId = outChannel.getChannelId()!;
			const cltvExpiry = hops[0].outgoingCltvValue + baseHeight;
			const amount = hops[0].amountToForwardMsat;

			const htlcId = outChannel.getFullState().localHtlcCounter;
			const mppHtlcKey = `${channelId.toString('hex')}:offered-${htlcId}`;
			this.htlcPaymentMap.set(mppHtlcKey, hashHex);
			this.commitMutations(
				'saveHtlcPaymentMapping',
				[
					{
						type: 'htlc_payment_mapping',
						htlcKey: mppHtlcKey,
						paymentHash: hashHex
					}
				],
				RecoveryCriticality.SafetyCritical
			);

			// The first part doubles as the payment-level route/secrets (display
			// and single-path fallbacks); every part keeps its own for failure
			// decryption, since each part is a distinct onion.
			if (!payment.sharedSecrets) {
				payment.sharedSecrets = sharedSecrets;
				payment.route = partRoute as IPaymentInfo['route'];
			}

			mppState.parts.push({
				route: partRoute,
				channelId,
				htlcId,
				amountMsat: amount,
				status: PaymentStatus.PENDING,
				sharedSecrets
			});

			const result = this.channelManager.addHtlc(
				channelId,
				amount,
				paymentHash,
				cltvExpiry,
				onionBuf
			);
			if (!result.ok) {
				// No rollback of the parts already dispatched: BOLT 2 gives no way to
				// withdraw an update_add_htlc we have sent. Only the downstream peer
				// can fail it back, or it times out. The loop that used to stand here
				// called failHtlc with these OFFERED ids and the default RECEIVED
				// direction, which at best errored and at worst cancelled an unrelated
				// inbound HTLC that happened to share the numeric id. It was
				// unreachable until addHtlc started reporting refusals honestly.
				//
				// The dispatched parts settle themselves: the payee cannot claim an
				// incomplete MPP set, so it fails them back on its own MPP timeout.
				this.htlcPaymentMap.delete(mppHtlcKey);
				mppState.parts.pop();

				// Part failed to dispatch — mark payment failed
				payment.status = PaymentStatus.FAILED;
				payment.completedAt = Date.now();
				payment.failureReason = `Local failure: MPP part could not be dispatched (${
					result.error ?? 'unknown reason'
				})`;
				this.outboundMppPayments.delete(hashHex);
				// The mapping release and the FAILED record are one journaled
				// transition, mirroring the single-path local-failure cleanup.
				const mppFailMutations: RecoveryMutation[] = [
					{ type: 'delete_htlc_payment_mapping', htlcKey: mppHtlcKey }
				];
				const mppFailPayment = this.paymentMutation(paymentHash);
				if (mppFailPayment) mppFailMutations.push(mppFailPayment);
				this.commitMutations('release failed MPP mapping', mppFailMutations);
				this.emit('payment:failed', payment);
				return payment;
			}
		}

		// With a synchronous transport a part can fail back before the next
		// part is even dispatched, so resolution-time cleanup is deferred
		// until here (see IOutboundMppState.dispatchComplete).
		mppState.dispatchComplete = true;
		if (mppState.parts.every((part) => part.status !== PaymentStatus.PENDING)) {
			this.outboundMppPayments.delete(hashHex);
		}

		return payment;
	}

	// ─────────────── HTLC Event Handlers ───────────────

	private handleIncomingHtlc(
		channelId: Buffer,
		htlcId: bigint,
		amountMsat: bigint,
		paymentHash: Buffer
	): void {
		this.emitStructuredLog('htlc', 'received', {
			channelId: channelId.toString('hex'),
			htlcId: htlcId.toString(),
			amountMsat: amountMsat.toString(),
			paymentHash: paymentHash.toString('hex')
		});
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;

		// BOLT 2 quiescence: "MUST NOT send an update message after stfu". An
		// add that crossed our own stfu can reach COMMITTED while the channel is
		// still quiescing (issue 411), and every disposition below can send
		// update_fail_htlc/update_fulfill_htlc. Park the dispatch before ANY arm
		// runs (the cap/rate-limit fails below included); it is re-driven when
		// the manager reports quiescence over, with a per-block retry covering
		// the exits that emit no event (disconnect, errored, force close).
		if (channel.isQuiescing()) {
			this.parkQuiescentHtlc(channelId, htlcId, amountMsat, paymentHash);
			return;
		}

		// Global HTLC limit check
		if (this.getTotalInFlightHtlcCount() > this.maxTotalInFlightHtlcs) {
			this.channelManager.failHtlc(
				channelId,
				htlcId,
				createFailureMessage(Buffer.alloc(32), TEMPORARY_NODE_FAILURE)
			);
			return;
		}

		// Per-peer rate limit check
		const peerPubkey = this.channelManager.getPeerForChannel(channelId);
		if (peerPubkey && !this.rateLimiter.tryConsume(peerPubkey)) {
			this.channelManager.failHtlc(
				channelId,
				htlcId,
				createFailureMessage(Buffer.alloc(32), TEMPORARY_NODE_FAILURE)
			);
			return;
		}

		// Get the onion routing packet from the HTLC entry
		const htlcEntry = channel.getFullState().htlcs.get(`received-${htlcId}`);
		if (!htlcEntry) return;

		const onionBuf = htlcEntry.onionRoutingPacket;

		// Route blinding: if this HTLC arrived with a blinding_point (we are a
		// downstream blinded hop, not the introduction node), the sender encrypted
		// our onion layer to our blinded node id, so we must peel it with the
		// matching blinded private key. The introduction node has no message-level
		// blinding_point (it receives it inside the onion as TLV 12) and so keeps
		// using its real key.
		const onionPrivkey = htlcEntry.blindingPoint
			? deriveBlindedPrivkey(htlcEntry.blindingPoint, this.nodePrivkey)
			: this.nodePrivkey;

		let onionPacket;
		let processed;
		try {
			onionPacket = decodeOnionPacket(onionBuf);
			processed = processOnionPacket(onionPacket, onionPrivkey, paymentHash);
		} catch (err) {
			// Onion processing failed — fail the HTLC and emit structured error
			this.emit('node:error', {
				code: 'ONION_PROCESSING_FAILED',
				channelId,
				message: `Onion processing failed for HTLC ${htlcId} on channel ${channelId.toString(
					'hex'
				)}: ${(err as Error).message || 'unknown'}`,
				timestamp: Date.now()
			} as ILightningError);
			// BOLT 4 route blinding: an HTLC that arrived with a blinding point is
			// inside a blinded route, so even an unparseable onion must surface as
			// invalid_onion_blinding via update_fail_malformed_htlc.
			if (htlcEntry.blindingPoint) {
				this.channelManager.failMalformedHtlc(
					channelId,
					htlcId,
					crypto.createHash('sha256').update(onionBuf).digest(),
					INVALID_ONION_BLINDING
				);
				return;
			}
			// BOLT 4: INVALID_ONION_HMAC — we can't decrypt, so use a zero shared secret
			// (the sender will not be able to decrypt this, but it's the best we can do)
			this.channelManager.failHtlc(
				channelId,
				htlcId,
				createFailureMessage(Buffer.alloc(32), INVALID_ONION_HMAC)
			);
			return;
		}

		// Store the shared secret for this HTLC (used for creating proper failure messages)
		const htlcSecretKey = `${channelId.toString('hex')}:${htlcId}`;
		this.receivedHtlcSharedSecrets.set(htlcSecretKey, processed.sharedSecret);
		// Journaled: a restore missing this secret cannot onion-encrypt a
		// failure for the in-flight inbound HTLC (SafetyCritical linkage).
		this.commitMutations(
			'saveHtlcSharedSecret',
			[
				{
					type: 'htlc_shared_secret',
					key: htlcSecretKey,
					secret: processed.sharedSecret
				}
			],
			RecoveryCriticality.SafetyCritical
		);

		// Policy fail-backs (issue 410): BOLT 2's dust-exposure section says an
		// HTLC over the ceiling SHOULD be failed once committed and its preimage
		// never revealed, so this runs before any dispatch. The CLTV horizon is
		// our policy with the same shape. BOLT 4 splits the code by hop role: a
		// forwarding node answers temporary_channel_failure / expiry_too_far,
		// but a final node must not return forwarding-only errors and answers
		// the non-leaking incorrect_or_unknown_payment_details instead. Inside
		// a blinded route the reason must not leak either way (BOLT 4), so
		// those surface as invalid_onion_blinding. Replayed idempotently on
		// restart via redispatchUnresolvedReceivedHtlcs.
		const finalHop = isFinalHop(processed.nextPacket);
		let policyCode: number | null = null;
		if (
			channel.getFullState().restoreRecencyUnproven === true &&
			htlcEntry.addedWhileRestoreUnproven === true
		) {
			// A capsule-restored channel whose recency cannot be proven takes
			// no NEW HTLCs (issue #469). Settling this would reveal a preimage
			// against a peer we could never escalate against, because every
			// automatic close is refused while the hold stands, so the on-chain
			// claim the deadline backstops exist to make can never happen;
			// forwarding is the same bet with an extra leg.
			//
			// NEW is decided by the entry's admission-time provenance, not by
			// the hold alone: this same path handles the redispatch of HTLCs
			// already committed in the capsule (redispatchUnresolvedReceivedHtlcs
			// after a restart), and those predate the hold, still settle off
			// chain, and are exactly what the restore promises to preserve.
			//
			// Decided HERE rather than before the onion is processed, so the
			// failure is encrypted under the sender's own shared secret and can
			// actually be read, and so it takes the same role-correct and
			// blinded-route handling as every other policy fail-back below.
			this.emitStructuredLog('htlc', 'refused_restore_unproven', {
				channelId: channelId.toString('hex'),
				htlcId: htlcId.toString(),
				finalHop
			});
			policyCode = finalHop
				? INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
				: TEMPORARY_CHANNEL_FAILURE;
		} else if (channel.receivedHtlcExceedsDustExposure(htlcId)) {
			policyCode = finalHop
				? INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
				: TEMPORARY_CHANNEL_FAILURE;
		} else if (
			this.currentBlockHeight > 0 &&
			htlcEntry.cltvExpiry >
				this.currentBlockHeight + Channel.MAX_HTLC_CLTV_EXPIRY_DELTA
		) {
			policyCode = finalHop
				? INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
				: EXPIRY_TOO_FAR;
		}
		if (policyCode !== null) {
			// TLV 12 (current_blinding_point) marks the introduction node; a
			// message-level blinding point means we are a downstream blinded hop.
			const blindedRole: 'intro' | 'mid' | undefined = processed.hopPayload
				.blindingPoint
				? 'intro'
				: htlcEntry.blindingPoint
				? 'mid'
				: undefined;
			if (blindedRole) {
				this.failBlindedIncomingHtlc(
					channelId,
					htlcId,
					blindedRole,
					processed.sharedSecret
				);
				return;
			}
			this.cleanupHtlcSharedSecret(htlcSecretKey);
			this.channelManager.failHtlc(
				channelId,
				htlcId,
				createFailureMessage(
					processed.sharedSecret,
					policyCode,
					policyCode === INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
						? this.incorrectPaymentDetailsData(amountMsat)
						: this.updateFlaggedFailureData(policyCode)
				)
			);
			return;
		}

		if (finalHop) {
			// We are the final destination. htlcEntry.blindingPoint is the
			// update_add_htlc path key a downstream blinded final hop received
			// (absent when we are the path's introduction node, which gets the
			// path key inside the onion as TLV 12) — needed to decrypt our own
			// final-hop recipient data for the BOLT 12 path_id check.
			this.handleFinalHopHtlc(
				channelId,
				htlcId,
				amountMsat,
				paymentHash,
				processed.hopPayload,
				htlcEntry.cltvExpiry,
				htlcEntry.blindingPoint
			);
		} else {
			// Forward to next hop — pass incoming HTLC details for CLTV/fee enforcement.
			// htlcEntry.blindingPoint is the message-level blinding point a downstream
			// blinded hop received (absent at the introduction node, which gets it in
			// the onion); needed so a MID blinded hop can decrypt its hop data.
			this.handleForwardHtlc(
				channelId,
				htlcId,
				paymentHash,
				processed,
				amountMsat,
				htlcEntry.cltvExpiry,
				htlcEntry.blindingPoint
			);
		}
	}

	private parkQuiescentHtlc(
		channelId: Buffer,
		htlcId: bigint,
		amountMsat: bigint,
		paymentHash: Buffer
	): void {
		const key = channelId.toString('hex');
		const list = this.parkedQuiescentHtlcs.get(key) ?? [];
		if (!list.some((e) => e.htlcId === htlcId)) {
			list.push({ htlcId, amountMsat, paymentHash });
		}
		this.parkedQuiescentHtlcs.set(key, list);
	}

	/**
	 * Re-drive incoming-HTLC dispatches parked while their channel was
	 * quiescing. Each entry is deleted BEFORE the re-invoke: handleIncomingHtlc
	 * re-parks it if quiescence resumed, and a still-parked entry must never be
	 * dispatched twice by the event drain and the per-block retry racing.
	 */
	private drainParkedQuiescentHtlcs(channelIdHex: string): void {
		const list = this.parkedQuiescentHtlcs.get(channelIdHex);
		if (!list?.length) return;
		const channelId = Buffer.from(channelIdHex, 'hex');
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			// Channel removed from the manager: nothing left to fail against.
			this.parkedQuiescentHtlcs.delete(channelIdHex);
			return;
		}
		const state = channel.getState();
		if (
			state === ChannelState.ERRORED ||
			state === ChannelState.CLOSED ||
			state === ChannelState.FORCE_CLOSED
		) {
			// Terminal: the HTLCs resolve on-chain, not by update messages.
			this.parkedQuiescentHtlcs.delete(channelIdHex);
			return;
		}
		// Not merely "no longer quiescing": after a disconnect-during-quiescence
		// the channel sits in AWAITING_REESTABLISH, where failHtlc/fulfillHtlc
		// refuse and a drained entry would be consumed and stranded. Hold until
		// the channel can carry updates again; the per-block retry gets it there.
		if (channel.isQuiescing() || !channel.canSettleHtlcs()) return;
		this.parkedQuiescentHtlcs.delete(channelIdHex);
		for (const entry of list) {
			this.handleIncomingHtlc(
				channelId,
				entry.htlcId,
				entry.amountMsat,
				entry.paymentHash
			);
		}
	}

	/**
	 * BOLT 4 final-node safety checks common to every terminating HTLC (keysend
	 * and invoice), run before any preimage is revealed. Returns a failure reason
	 * buffer if the HTLC must be failed, or null if it is safe to proceed.
	 */
	/**
	 * BOLT 4 failure data for incorrect_or_unknown_payment_details:
	 * [`u64`:`htlc_msat`][`u32`:`height`], where height is our best known block
	 * height when the HTLC arrived.
	 *
	 * The height is not decoration. PERM|15 is overloaded: it covers a genuinely
	 * unknown payment hash (permanent) and an expiry that no longer meets our
	 * min_final_cltv_expiry_delta (transient, and usually just block-height skew).
	 * Returning our height is what lets the sender tell those apart instead of
	 * abandoning a payment that would succeed on retry.
	 */
	private incorrectPaymentDetailsData(amountMsat: bigint): Buffer {
		const data = Buffer.alloc(12);
		data.writeBigUInt64BE(amountMsat, 0);
		data.writeUInt32BE(this.currentBlockHeight, 8);
		return data;
	}

	/**
	 * BOLT 4 failure data for the UPDATE-flagged failures a forwarding node
	 * returns. Each carries fixed fields (the HTLC amount or CLTV the check was
	 * judged against) followed by [`u16`:`len`][`len*byte`:`channel_update`].
	 *
	 * We send the fixed fields with len = 0. The channel_update itself is no
	 * longer mandatory: BOLT 4 now says nodes "are expected to transition away
	 * from including it" and that a node not providing one sets len to zero,
	 * which is what Eclair and LDK already do. What we must not do is what we
	 * did before this existed: send the failure with EMPTY data, which omits
	 * the fixed fields too and leaves the payer unable to tell what amount or
	 * expiry was rejected.
	 */
	private updateFlaggedFailureData(
		failureCode: number,
		fields: { htlcMsat?: bigint; cltvExpiry?: number } = {}
	): Buffer | undefined {
		switch (failureCode) {
			case TEMPORARY_CHANNEL_FAILURE:
			case EXPIRY_TOO_SOON:
				// [u16 len]
				return Buffer.alloc(2);
			case AMOUNT_BELOW_MINIMUM:
			case FEE_INSUFFICIENT: {
				// [u64 htlc_msat][u16 len]. Throw rather than default a missing
				// amount to zero: a syntactically valid but semantically bogus
				// failure would mislead the payer, and a missing field here is a
				// caller bug, not a runtime condition.
				if (fields.htlcMsat === undefined) {
					throw new Error(`Missing htlcMsat for failure code ${failureCode}`);
				}
				const data = Buffer.alloc(10);
				data.writeBigUInt64BE(fields.htlcMsat, 0);
				return data;
			}
			case INCORRECT_CLTV_EXPIRY: {
				// [u32 cltv_expiry][u16 len]. Per BOLT 4 this is the cltv_expiry of
				// the OUTGOING HTLC (the onion's outgoing_cltv_value), not the
				// incoming one. Same no-silent-default rule as htlcMsat above.
				if (fields.cltvExpiry === undefined) {
					throw new Error('Missing cltvExpiry for INCORRECT_CLTV_EXPIRY');
				}
				const data = Buffer.alloc(6);
				data.writeUInt32BE(fields.cltvExpiry, 0);
				return data;
			}
			case CHANNEL_DISABLED:
				// [u16 disabled_flags][u16 len]
				return Buffer.alloc(4);
			default:
				return undefined;
		}
	}

	private finalHopSafetyFailure(
		sharedSecret: Buffer | undefined,
		hopPayload: IHopPayload | undefined,
		incomingCltvExpiry: number | undefined,
		amountMsat: bigint,
		hashHex: string
	): Buffer | null {
		const fail = (code: number): Buffer =>
			sharedSecret
				? createFailureMessage(
						sharedSecret,
						code,
						code === INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
							? this.incorrectPaymentDetailsData(amountMsat)
							: undefined
				  )
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);

		if (incomingCltvExpiry !== undefined) {
			// final_incorrect_cltv_expiry: the HTLC cltv_expiry MUST be >= the onion's
			// outgoing_cltv_value. A sender may over-provision it (a strictly larger
			// value is fine); only a SHORTFALL is a tampered timeout. (Previously this
			// required exact equality and rejected a compliant over-provisioning
			// sender.)
			if (
				hopPayload?.outgoingCltvValue !== undefined &&
				incomingCltvExpiry < hopPayload.outgoingCltvValue
			) {
				this.emitStructuredLog('htlc', 'final_incorrect_cltv', {
					paymentHash: hashHex,
					htlcCltv: incomingCltvExpiry,
					onionCltv: hopPayload.outgoingCltvValue
				});
				return fail(FINAL_INCORRECT_CLTV_EXPIRY);
			}
			// expiry-too-soon. BOLT 4 is explicit here: "if incoming cltv_expiry <
			// current_block_height + min_final_cltv_expiry_delta: MUST fail the
			// HTLC". We advertise DEFAULT_MIN_FINAL_CLTV_EXPIRY, so that is what we
			// enforce, and relaxing it would both break conformance and leave us
			// short of the headroom we need to win an on-chain claim race.
			//
			// This condition is transient when it is simply block-height skew, so
			// the failure carries our height (see incorrectPaymentDetailsData) and
			// the SENDER is responsible for noticing and retrying. Do not "fix" a
			// skew-induced failure by lowering this bound.
			if (
				this.currentBlockHeight > 0 &&
				incomingCltvExpiry <
					this.currentBlockHeight + DEFAULT_MIN_FINAL_CLTV_EXPIRY
			) {
				this.emitStructuredLog('htlc', 'final_expiry_too_soon', {
					paymentHash: hashHex,
					htlcCltv: incomingCltvExpiry,
					height: this.currentBlockHeight
				});
				return fail(INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS);
			}
		}

		// final_incorrect_htlc_amount: the HTLC amount MUST be >= the onion's
		// amt_to_forward. This catches a hop that skimmed the amount even for
		// keysend / zero-amount invoices, which have no invoice-amount check.
		if (
			hopPayload?.amountToForwardMsat !== undefined &&
			amountMsat < hopPayload.amountToForwardMsat
		) {
			this.emitStructuredLog('htlc', 'final_incorrect_htlc_amount', {
				paymentHash: hashHex,
				received: amountMsat.toString(),
				amtToForward: hopPayload.amountToForwardMsat.toString()
			});
			return fail(FINAL_INCORRECT_HTLC_AMOUNT);
		}

		return null;
	}

	private handleFinalHopHtlc(
		channelId: Buffer,
		htlcId: bigint,
		amountMsat: bigint,
		paymentHash: Buffer,
		hopPayload?: IHopPayload,
		incomingCltvExpiry?: number,
		incomingBlindingPoint?: Buffer
	): void {
		const hashHex = paymentHash.toString('hex');
		const htlcSecretKey = `${channelId.toString('hex')}:${htlcId}`;
		const sharedSecret = this.receivedHtlcSharedSecrets.get(htlcSecretKey);

		// BOLT 4 final-node safety checks that apply to EVERY terminating HTLC
		// (keysend and invoice alike) and MUST run BEFORE any preimage is revealed:
		// the cltv_expiry must be >= the onion's outgoing_cltv_value with a safe
		// claim window, and the amount must be >= amt_to_forward. Running these
		// first fixes keysend settling a next-block-expiring or skimmed HTLC.
		const safetyReason = this.finalHopSafetyFailure(
			sharedSecret,
			hopPayload,
			incomingCltvExpiry,
			amountMsat,
			hashHex
		);
		if (safetyReason) {
			this.cleanupHtlcSharedSecret(htlcSecretKey);
			this.channelManager.failHtlc(channelId, htlcId, safetyReason);
			return;
		}

		// Keysend: extract preimage from custom TLV records (bLIP-0003)
		const keysendPreimage = hopPayload?.customRecords?.get(KEYSEND_TLV_TYPE);
		if (keysendPreimage) {
			if (keysendPreimage.length !== 32) {
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
							this.incorrectPaymentDetailsData(amountMsat)
					  )
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
			const expectedHash = crypto
				.createHash('sha256')
				.update(keysendPreimage)
				.digest();
			if (!expectedHash.equals(paymentHash)) {
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
							this.incorrectPaymentDetailsData(amountMsat)
					  )
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
			// Valid keysend — store preimage and create incoming payment record
			this.preimages.set(hashHex, keysendPreimage);
			const incomingPayment: IPaymentInfo = {
				paymentHash,
				preimage: keysendPreimage,
				amountMsat,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.INCOMING,
				createdAt: Date.now(),
				metadata: { _keysend: 'true' }
			};
			this.payments.set(hashHex, incomingPayment);
			if (this.storage) {
				this.commitMutations(
					'keysend receive',
					[
						{
							type: 'payment_preimage',
							paymentHash: hashHex,
							preimage: keysendPreimage
						},
						{
							type: 'payment_state',
							paymentHash: hashHex,
							payment: incomingPayment
						}
					],
					RecoveryCriticality.SafetyCritical
				);
			}
			this.fulfillPayment(channelId, htlcId, paymentHash, keysendPreimage);
			return;
		}

		const preimage = this.preimages.get(hashHex);
		const isHold = this.heldInvoiceHashes.has(hashHex);

		// A hold invoice may legitimately have no preimage yet (held externally),
		// so don't reject for a missing preimage in that case — we'll park below.
		if (!preimage && !isHold) {
			this.emitStructuredLog('htlc', 'unknown_payment_hash', {
				paymentHash: hashHex
			});
			const reason = sharedSecret
				? createFailureMessage(
						sharedSecret,
						INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
						this.incorrectPaymentDetailsData(amountMsat)
				  )
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.cleanupHtlcSharedSecret(htlcSecretKey);
			this.channelManager.failHtlc(channelId, htlcId, reason);
			return;
		}

		// Validate payment secret. BOLT 4: when the invoice carries a
		// payment_secret, the final hop MUST reject an HTLC that omits OR
		// mismatches it — not only when the sender chose to include one. This
		// defends against payment probing and unauthorized payment to the same
		// hash. When no invoice secret exists (e.g. keysend), enforcement is
		// skipped here and the payment is validated by preimage instead.
		const expectedSecret = this.paymentSecrets.get(hashHex);
		if (expectedSecret) {
			if (
				!hopPayload?.paymentSecret ||
				!hopPayload.paymentSecret.equals(expectedSecret)
			) {
				this.emitStructuredLog('htlc', 'payment_secret_mismatch', {
					paymentHash: hashHex
				});
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
							this.incorrectPaymentDetailsData(amountMsat)
					  )
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
		}

		// BOLT 12: an invoice we issued binds its payment to the path_id we
		// encrypted into the final hop of the invoice's blinded payment path
		// (BOLT 12 has no payment_secret TLV). Recover the path_id from THIS
		// HTLC's final-hop recipient data — the path key is the onion's TLV 12
		// when we are the path's introduction node, or the update_add_htlc
		// path key when the path had upstream hops — and require an exact
		// match before any preimage is revealed. An HTLC for the hash sent
		// OUTSIDE the path (probe, forged, or leaked hash) fails exactly like
		// a payment_secret mismatch, so the sender learns nothing.
		//
		// FAIL CLOSED: the check triggers on the invoice's persisted bolt12
		// marker OR a registered expectation, and a BOLT 12 invoice whose
		// expected path_id is unknown (evicted, or state loss) is rejected. A
		// missing expectation must never skip authentication while the
		// preimage is still claimable.
		const expectedPathId = this.offerManager.getInvoicePathId(paymentHash);
		if (expectedPathId || this.invoices.get(hashHex)?.bolt12) {
			// BOLT 4: the final payload of a blinded path carries EXACTLY
			// amt_to_forward, outgoing_cltv_value, total_amount_msat and
			// encrypted_recipient_data (plus current_path_key when we are the
			// introduction node). total_amount_msat is REQUIRED, and
			// payment_data MUST NOT appear (BOLT 12 has no payment_secret).
			// Accepting a payload that mixes both total mechanisms would let
			// the sender pick whichever total the receiver validates against,
			// so malformed shapes are rejected before any preimage can be
			// revealed. Scoped to BOLT 12 receives: blinded paths in BOLT 11
			// invoices are a non-spec beignet construct whose payments
			// legitimately authenticate via payment_data.
			if (
				hopPayload?.paymentSecret !== undefined ||
				hopPayload?.totalMsat !== undefined ||
				hopPayload?.totalAmountMsat === undefined
			) {
				this.emitStructuredLog('htlc', 'malformed_blinded_final_payload', {
					paymentHash: hashHex,
					hasPaymentData:
						hopPayload?.paymentSecret !== undefined ||
						hopPayload?.totalMsat !== undefined,
					hasTotalAmountMsat: hopPayload?.totalAmountMsat !== undefined
				});
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
							this.incorrectPaymentDetailsData(amountMsat)
					  )
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
			let receivedPathId: Buffer | undefined;
			const pathKey = hopPayload?.blindingPoint ?? incomingBlindingPoint;
			if (pathKey && hopPayload?.encryptedRecipientData?.length) {
				try {
					receivedPathId = processBlindedHop(
						pathKey,
						this.nodePrivkey,
						hopPayload.encryptedRecipientData
					).hopData.pathId;
				} catch {
					// Undecryptable recipient data: treated as an absent path_id.
				}
			}
			if (
				!expectedPathId ||
				!receivedPathId ||
				!receivedPathId.equals(expectedPathId)
			) {
				this.emitStructuredLog('htlc', 'payment_path_id_mismatch', {
					paymentHash: hashHex,
					expectationKnown: !!expectedPathId
				});
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
							this.incorrectPaymentDetailsData(amountMsat)
					  )
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
		}

		// (final-hop cltv/amount safety was validated up front, before any
		// preimage was revealed — see finalHopSafetyFailure.)

		// BOLT 4: total_amount_msat exists only inside a blinded final
		// payload. On a cleartext final payload it is a field no conformant
		// sender emits, and accepting it would give unauthenticated payments
		// a second, unvalidated total mechanism.
		if (
			hopPayload?.totalAmountMsat !== undefined &&
			!hopPayload.encryptedRecipientData?.length
		) {
			this.emitStructuredLog('htlc', 'total_amount_msat_outside_blinded', {
				paymentHash: hashHex
			});
			const reason = sharedSecret
				? createFailureMessage(
						sharedSecret,
						INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
						this.incorrectPaymentDetailsData(amountMsat)
				  )
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.cleanupHtlcSharedSecret(htlcSecretKey);
			this.channelManager.failHtlc(channelId, htlcId, reason);
			return;
		}

		// The part's amount is the onion-declared amt_to_forward. The incoming
		// HTLC only has to COVER it (validated up front in
		// finalHopSafetyFailure) and may legitimately exceed it, so
		// classifying or accumulating by the incoming amount would count HTLC
		// overfunding as payment progress and could settle a set whose onion
		// amounts never reached the declared total.
		const partAmountMsat = hopPayload?.amountToForwardMsat ?? amountMsat;

		// The sender-declared multi-part total. BOLT 11 payment_data carries it
		// in total_msat; a blinded final hop carries no payment_data at all and
		// declares it in total_amount_msat (TLV 18) instead, with the path_id
		// check above as the per-part authenticity gate. Recognising only the
		// payment_data field made every part of a split BOLT 12 payment look
		// like a standalone underpaying HTLC, so a spec-compliant MPP payer
		// could not pay a beignet-issued offer (#262). The precedence is safe:
		// a BOLT 12 payload carrying payment_data was rejected above, so both
		// fields coexist only on the non-spec BOLT 11 blinded path, where
		// payment_data governs.
		const declaredTotalMsat =
			hopPayload?.totalMsat ?? hopPayload?.totalAmountMsat;

		// A total below its own part contradicts itself;
		// final_incorrect_htlc_amount is the BOLT 4 code for a part whose
		// amounts are inconsistent.
		if (declaredTotalMsat !== undefined && declaredTotalMsat < partAmountMsat) {
			this.emitStructuredLog('htlc', 'declared_total_below_part', {
				paymentHash: hashHex,
				declaredTotal: declaredTotalMsat.toString(),
				partAmount: partAmountMsat.toString()
			});
			const reason = sharedSecret
				? createFailureMessage(sharedSecret, FINAL_INCORRECT_HTLC_AMOUNT)
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.cleanupHtlcSharedSecret(htlcSecretKey);
			this.channelManager.failHtlc(channelId, htlcId, reason);
			return;
		}

		// Validate the received amount against the invoice (BOLT 4). The final
		// node MUST NOT fulfill (and reveal the preimage) for less than the
		// invoiced amount, and SHOULD reject gross overpayment (> 2x). Without
		// this, a payer can settle a large invoice with a tiny HTLC and still
		// obtain the proof-of-payment. For MPP the sender-declared total is
		// what the parts accumulate toward, so validating it here (and the
		// existing handleMppPart accumulation to that total) bounds the real
		// received total. Zero-amount ("any amount") invoices are exempt.
		const finalInvoice = this.invoices.get(hashHex);
		if (
			finalInvoice &&
			finalInvoice.amountMsat &&
			finalInvoice.amountMsat > 0n
		) {
			// A present declared total is validated AS the claim, never
			// silently replaced by the (possibly larger) incoming HTLC value:
			// otherwise an HTLC overfunded up to the invoice amount could
			// smuggle through a declared total below it. The incoming amount
			// is additionally bounded against gross overpayment on its own.
			const claimedTotal = declaredTotalMsat ?? partAmountMsat;
			if (
				claimedTotal < finalInvoice.amountMsat ||
				claimedTotal > finalInvoice.amountMsat * 2n ||
				amountMsat > finalInvoice.amountMsat * 2n
			) {
				this.emitStructuredLog('htlc', 'incorrect_payment_amount', {
					paymentHash: hashHex,
					received: claimedTotal.toString(),
					invoiced: finalInvoice.amountMsat.toString()
				});
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
							this.incorrectPaymentDetailsData(amountMsat)
					  )
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
		}

		// Hold invoice: park the HTLC instead of settling. The preimage is revealed
		// later via settleHeldHtlc (e.g. async receive), or the HTLC is failed via
		// cancelHeldHtlc / the CLTV sweeper. Validation above (secret/cltv/amount)
		// has already run, so a parked HTLC is known-good — it only awaits release.
		if (isHold) {
			this.parkHeldHtlc(
				channelId,
				htlcId,
				paymentHash,
				amountMsat,
				incomingCltvExpiry ?? 0
			);
			return;
		}

		// MPP: a declared total above this part's amount marks a multi-part
		// payment, whether declared via payment_data (BOLT 11) or
		// total_amount_msat on a blinded final hop (BOLT 12).
		if (declaredTotalMsat !== undefined && declaredTotalMsat > partAmountMsat) {
			this.handleMppPart(
				channelId,
				htlcId,
				partAmountMsat,
				paymentHash,
				hopPayload!,
				preimage!,
				declaredTotalMsat
			);
			return;
		}

		// Single-part payment — fulfill immediately
		this.emitStructuredLog('htlc', 'fulfilling', {
			paymentHash: hashHex,
			amountMsat: amountMsat.toString()
		});
		this.fulfillPayment(channelId, htlcId, paymentHash, preimage!);
	}

	/**
	 * Park a validated incoming HTLC for a hold invoice. It awaits release via
	 * settleHeldHtlc / cancelHeldHtlc (or the CLTV sweeper). Emits 'htlc:held'.
	 */
	private parkHeldHtlc(
		channelId: Buffer,
		htlcId: bigint,
		paymentHash: Buffer,
		amountMsat: bigint,
		cltvExpiry: number
	): void {
		const hashHex = paymentHash.toString('hex');
		const list = this.heldHtlcs.get(hashHex) ?? [];
		// Dedup a duplicate park for the same channel+htlc (e.g. on reestablish).
		if (
			!list.some((h) => h.channelId.equals(channelId) && h.htlcId === htlcId)
		) {
			list.push({ channelId, htlcId, amountMsat, cltvExpiry });
			this.heldHtlcs.set(hashHex, list);
			this.persistHeldHtlcs();
		}
		this.emitStructuredLog('htlc', 'held', {
			paymentHash: hashHex,
			amountMsat: amountMsat.toString()
		});
		this.emit('htlc:held', { paymentHash, amountMsat });
	}

	/**
	 * Settle a hold invoice: reveal the preimage and fulfill every parked HTLC
	 * for the payment hash. With no preimage argument the node uses the one it
	 * generated at createInvoice; an external preimage (validated against the
	 * hash) is required for hold invoices created with an external payment hash.
	 * Returns false when nothing is parked for the hash.
	 */
	settleHeldHtlc(paymentHash: Buffer, preimage?: Buffer): boolean {
		const hashHex = paymentHash.toString('hex');
		const held = this.heldHtlcs.get(hashHex);
		if (!held || held.length === 0) return false;

		const pre = preimage ?? this.preimages.get(hashHex);
		if (!pre) {
			throw new Error('settleHeldHtlc: no preimage available for hold invoice');
		}
		const hash = crypto.createHash('sha256').update(pre).digest();
		if (!hash.equals(paymentHash)) {
			throw new Error('settleHeldHtlc: preimage does not match payment hash');
		}

		// Persist the preimage and deliver it to the chain monitors before
		// fulfilling, so a force-close mid-settle can still claim on-chain.
		this.preimages.set(hashHex, pre);
		this.commitMutations(
			'savePreimage',
			[{ type: 'payment_preimage', paymentHash: hashHex, preimage: pre }],
			RecoveryCriticality.SafetyCritical
		);
		this.channelManager.recordPreimage(paymentHash, pre);

		for (const h of held) {
			this.cleanupHtlcSharedSecret(
				`${h.channelId.toString('hex')}:${h.htlcId}`
			);
			this.channelManager.fulfillHtlc(h.channelId, h.htlcId, pre);
		}

		this.heldHtlcs.delete(hashHex);
		this.heldInvoiceHashes.delete(hashHex);
		this.persistHeldHtlcs();

		const payment = this.payments.get(hashHex);
		if (payment) {
			payment.status = PaymentStatus.COMPLETED;
			payment.preimage = pre;
			payment.completedAt = Date.now();
			this.safeStorage(
				() => this.persistPayment(paymentHash),
				'persistPayment'
			);
			this.emit('payment:received', payment);
			this.emitInvoiceSettled(paymentHash, payment);
		}
		this.emitStructuredLog('payment', 'received', {
			paymentHash: hashHex,
			held: 'true'
		});
		return true;
	}

	/**
	 * Emit invoice:settled when a settled receive corresponds to an invoice WE
	 * issued. Spontaneous receives (keysend) have no invoice entry and only
	 * fire payment:received.
	 */
	private emitInvoiceSettled(paymentHash: Buffer, payment: IPaymentInfo): void {
		const invoice = this.invoices.get(paymentHash.toString('hex'));
		if (!invoice) return;
		this.emit('invoice:settled', {
			paymentHash,
			bolt11: invoice.bolt11,
			amountMsat: payment.amountMsat
		});
		this.emitStructuredLog('payment', 'invoice_settled', {
			paymentHash: paymentHash.toString('hex'),
			amountMsat: payment.amountMsat.toString()
		});
	}

	/**
	 * Cancel a hold invoice: fail every parked HTLC back to the payer.
	 * Returns false when nothing is parked for the hash.
	 */
	cancelHeldHtlc(
		paymentHash: Buffer,
		failureCode: number = INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
	): boolean {
		const hashHex = paymentHash.toString('hex');
		const held = this.heldHtlcs.get(hashHex);
		if (!held || held.length === 0) return false;

		for (const h of held) {
			const key = `${h.channelId.toString('hex')}:${h.htlcId}`;
			const ss = this.receivedHtlcSharedSecrets.get(key);
			// This path defaults to incorrect_or_unknown_payment_details, and the
			// CLTV sweeper cancels through it with that default, so it needs the
			// same [htlc_msat][height] payload as every other PERM|15 we send.
			const reason = ss
				? createFailureMessage(
						ss,
						failureCode,
						failureCode === INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
							? this.incorrectPaymentDetailsData(h.amountMsat)
							: undefined
				  )
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.cleanupHtlcSharedSecret(key);
			this.channelManager.failHtlc(h.channelId, h.htlcId, reason);
		}

		this.heldHtlcs.delete(hashHex);
		this.heldInvoiceHashes.delete(hashHex);
		this.persistHeldHtlcs();
		this.markHoldInvoiceCancelled(hashHex);
		this.emitStructuredLog('htlc', 'held_cancelled', { paymentHash: hashHex });
		return true;
	}

	/**
	 * Record hold-invoice cancellation so a restart cannot re-arm parking for
	 * the hash, and drop the preimage/secret so a late HTLC fails with
	 * incorrect_or_unknown_payment_details instead of settling.
	 */
	private markHoldInvoiceCancelled(hashHex: string): void {
		this.preimages.delete(hashHex);
		this.paymentSecrets.delete(hashHex);
		const mutations: RecoveryMutation[] = [
			{ type: 'delete_payment_secret', paymentHash: hashHex }
		];
		const invoice = this.invoices.get(hashHex);
		if (invoice && !invoice.cancelledAt) {
			invoice.cancelledAt = Date.now();
			mutations.push({
				type: 'invoice_state',
				paymentHash: hashHex,
				invoice
			});
		}
		const payment = this.payments.get(hashHex);
		if (
			payment &&
			payment.direction === PaymentDirection.INCOMING &&
			payment.status !== PaymentStatus.COMPLETED
		) {
			payment.status = PaymentStatus.FAILED;
			const paymentMutation = this.paymentMutation(Buffer.from(hashHex, 'hex'));
			if (paymentMutation) mutations.push(paymentMutation);
		}
		// One journaled SafetyCritical transition: the secret deletion is what
		// makes a late HTLC fail instead of settling, and a restore that
		// resurrected it would quietly re-arm the cancelled hash.
		this.commitMutations(
			'markHoldInvoiceCancelled',
			mutations,
			RecoveryCriticality.SafetyCritical
		);
	}

	/**
	 * Cancel a hold invoice by payment hash: fails any parked HTLC back to the
	 * payer (incorrect_or_unknown_payment_details) and closes the invoice so
	 * future HTLCs are rejected. Works before an HTLC arrives (unlike
	 * cancelHeldHtlc). Returns the number of HTLCs failed, or null when the
	 * hash is not a known open hold invoice.
	 */
	cancelHoldInvoice(paymentHash: Buffer): { htlcsFailed: number } | null {
		const hashHex = paymentHash.toString('hex');
		const held = this.heldHtlcs.get(hashHex);
		if (held && held.length > 0) {
			const count = held.length;
			// cancelHeldHtlc also marks the invoice cancelled.
			this.cancelHeldHtlc(paymentHash);
			return { htlcsFailed: count };
		}
		if (!this.heldInvoiceHashes.has(hashHex)) return null;
		this.heldInvoiceHashes.delete(hashHex);
		this.markHoldInvoiceCancelled(hashHex);
		this.emitStructuredLog('htlc', 'held_cancelled', { paymentHash: hashHex });
		return { htlcsFailed: 0 };
	}

	/**
	 * List hold invoices with their derived lifecycle state.
	 * OPEN: created, no HTLC parked yet. ACCEPTED: HTLC(s) parked awaiting
	 * settle/cancel. SETTLED: preimage revealed, payment received.
	 * CANCELLED: failed back (explicitly or by the CLTV sweeper).
	 */
	listHoldInvoices(): Array<{
		paymentHash: string;
		bolt11: string;
		amountMsat?: bigint;
		description?: string;
		expiry: number;
		createdAt: number;
		state: 'OPEN' | 'ACCEPTED' | 'SETTLED' | 'CANCELLED';
		heldAmountMsat: bigint;
		htlcCount: number;
	}> {
		const out: ReturnType<LightningNode['listHoldInvoices']> = [];
		for (const [hashHex, invoice] of this.invoices) {
			if (!invoice.hold) continue;
			const held = this.heldHtlcs.get(hashHex) ?? [];
			let heldAmountMsat = 0n;
			for (const h of held) heldAmountMsat += h.amountMsat;
			const payment = this.payments.get(hashHex);
			let state: 'OPEN' | 'ACCEPTED' | 'SETTLED' | 'CANCELLED';
			if (held.length > 0) {
				state = 'ACCEPTED';
			} else if (
				payment?.status === PaymentStatus.COMPLETED &&
				payment.direction === PaymentDirection.INCOMING
			) {
				state = 'SETTLED';
			} else if (invoice.cancelledAt || !this.heldInvoiceHashes.has(hashHex)) {
				state = 'CANCELLED';
			} else {
				state = 'OPEN';
			}
			out.push({
				paymentHash: hashHex,
				bolt11: invoice.bolt11,
				amountMsat: invoice.amountMsat,
				description: invoice.description,
				expiry: invoice.expiry,
				createdAt: invoice.createdAt,
				state,
				heldAmountMsat,
				htlcCount: held.length
			});
		}
		return out;
	}

	/**
	 * Fail parked HTLCs approaching their CLTV expiry, so we resolve them
	 * off-chain rather than forcing an on-chain timeout (which closes the
	 * channel and risks the payer reclaiming after we may have leaked a preimage).
	 */
	private scanExpiringHeldHtlcs(height: number): void {
		if (height <= 0) return;
		for (const [hashHex, held] of this.heldHtlcs) {
			const soon = held.some(
				(h) =>
					h.cltvExpiry > 0 && h.cltvExpiry - height <= HELD_HTLC_EXPIRY_MARGIN
			);
			if (soon) {
				this.cancelHeldHtlc(Buffer.from(hashHex, 'hex'));
			}
		}
	}

	/** Persist the parked-HTLC map so settle/cancel survive a restart. */
	private persistHeldHtlcs(): void {
		if (!this.storage) return;
		const serial: Array<{
			hashHex: string;
			htlcs: Array<{
				channelId: string;
				htlcId: string;
				amountMsat: string;
				cltvExpiry: number;
			}>;
		}> = [];
		for (const [hashHex, held] of this.heldHtlcs) {
			serial.push({
				hashHex,
				htlcs: held.map((h) => ({
					channelId: h.channelId.toString('hex'),
					htlcId: h.htlcId.toString(),
					amountMsat: h.amountMsat.toString(),
					cltvExpiry: h.cltvExpiry
				}))
			});
		}
		this.safeStorage(
			() => this.storage!.saveMetadata('held_htlcs', JSON.stringify(serial)),
			'persistHeldHtlcs'
		);
	}

	/** List parked hold-invoice HTLCs (for agents/operators). */
	listHeldHtlcs(): Array<{
		paymentHash: Buffer;
		amountMsat: bigint;
		htlcCount: number;
	}> {
		const out: Array<{
			paymentHash: Buffer;
			amountMsat: bigint;
			htlcCount: number;
		}> = [];
		for (const [hashHex, held] of this.heldHtlcs) {
			let total = 0n;
			for (const h of held) total += h.amountMsat;
			out.push({
				paymentHash: Buffer.from(hashHex, 'hex'),
				amountMsat: total,
				htlcCount: held.length
			});
		}
		return out;
	}

	// ─────────────── Async Payments (LSP-side held forwards) ───────────────

	/** Direct access to the AsyncPaymentManager (events, manual control). */
	getAsyncPaymentManager(): AsyncPaymentManager {
		return this.asyncPaymentManager;
	}

	/**
	 * LSP: release a forward parked for a now-online receiver (also triggered by
	 * a release_held_htlc onion message). Returns false if nothing is parked.
	 */
	releaseHeldForward(paymentHash: Buffer): boolean {
		return this.asyncPaymentManager.handleRelease(paymentHash);
	}

	/** Payment hashes of forwards currently parked for offline receivers. */
	listHeldForwards(): Buffer[] {
		return this.asyncPaymentManager.listHeldForwards();
	}

	/** Receiver: ask the LSP to release the HTLC held for this payment hash. */
	sendAsyncRelease(lspNodeId: Buffer, paymentHash: Buffer): void {
		this.asyncPaymentManager.sendRelease(lspNodeId, paymentHash);
	}

	/** Sender: nudge an offline receiver to come online for this payment hash. */
	sendAsyncWake(receiverNodeId: Buffer, paymentHash: Buffer): void {
		this.asyncPaymentManager.sendWake(receiverNodeId, paymentHash);
	}

	/**
	 * Fail LSP-side held forwards approaching their inbound CLTV expiry, so the
	 * channel isn't force-closed waiting on an offline receiver who never returns.
	 */
	private scanExpiringHeldForwards(height: number): void {
		if (height <= 0) return;
		for (const [hashHex, hf] of this.heldForwards) {
			if (
				hf.incomingCltvExpiry > 0 &&
				hf.incomingCltvExpiry - height <= HELD_HTLC_EXPIRY_MARGIN
			) {
				this.asyncPaymentManager.failHeldForward(Buffer.from(hashHex, 'hex'));
			}
		}
	}

	/**
	 * Accumulate one part of a multi-part payment. Parts group by payment
	 * hash; each part's authenticity was already enforced upstream in
	 * handleFinalHopHtlc (the payment_secret match for BOLT 11 parts, the
	 * blinded path_id match for BOLT 12 parts, which have no payment_data).
	 * amountMsat is the part's onion-declared amt_to_forward, NOT the
	 * incoming HTLC value, which may exceed it; declaredTotalMsat is the
	 * sender-declared total the parts accumulate toward: payment_data
	 * total_msat or blinded-final total_amount_msat.
	 */
	private handleMppPart(
		channelId: Buffer,
		htlcId: bigint,
		amountMsat: bigint,
		paymentHash: Buffer,
		hopPayload: IHopPayload,
		preimage: Buffer,
		declaredTotalMsat: bigint
	): void {
		const hashHex = paymentHash.toString('hex');

		// Get or create pending MPP payment
		let pending = this.pendingMppPayments.get(hashHex);
		if (!pending) {
			pending = {
				// Absent for blinded-final parts: BOLT 12 has no payment_secret,
				// the per-part path_id check upstream authenticates instead.
				paymentSecret: hopPayload.paymentSecret,
				totalMsat: declaredTotalMsat,
				receivedParts: [],
				createdAt: Date.now()
			};
			this.pendingMppPayments.set(hashHex, pending);
		} else if (declaredTotalMsat !== pending.totalMsat) {
			// BOLT 4: every part of a multi-part payment MUST carry the same
			// total, and on disagreement the receiver SHOULD fail the ENTIRE
			// HTLC set with final_incorrect_htlc_amount: the set's declared
			// total is now ambiguous, keeping parked parts alive locks the
			// payer's funds until the MPP timeout, and a sender could keep
			// injecting mismatched parts to hold state open indefinitely.
			for (const p of pending.receivedParts) {
				if (p.status !== PaymentStatus.PENDING) continue;
				p.status = PaymentStatus.FAILED;
				const partKey = `${p.channelId.toString('hex')}:${p.htlcId}`;
				const partSecret = this.receivedHtlcSharedSecrets.get(partKey);
				const partReason = partSecret
					? createFailureMessage(partSecret, FINAL_INCORRECT_HTLC_AMOUNT)
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(partKey);
				this.channelManager.failHtlc(p.channelId, p.htlcId, partReason);
			}
			this.pendingMppPayments.delete(hashHex);
			const secretKey = `${channelId.toString('hex')}:${htlcId}`;
			const sharedSecret = this.receivedHtlcSharedSecrets.get(secretKey);
			const reason = sharedSecret
				? createFailureMessage(sharedSecret, FINAL_INCORRECT_HTLC_AMOUNT)
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.cleanupHtlcSharedSecret(secretKey);
			this.channelManager.failHtlc(channelId, htlcId, reason);
			return;
		}

		// One HTLC is one part. Completion sums the array, so accumulating the
		// same (channel, htlc) twice would credit money that was never sent:
		// the set would reach its declared total, reveal the preimage and
		// settle, while only the single real HTLC exists to settle. Nothing
		// upstream should offer the same HTLC twice, and this is the check that
		// means a path which does cannot turn it into value.
		const alreadyCounted = pending.receivedParts.some(
			(p) => p.htlcId === htlcId && p.channelId.equals(channelId)
		);
		if (alreadyCounted) {
			this.emitStructuredLog('htlc', 'mpp_duplicate_part_ignored', {
				paymentHash: hashHex,
				channelId: channelId.toString('hex'),
				htlcId: htlcId.toString()
			});
			return;
		}

		// Add this part
		const part: IPaymentPart = {
			partIndex: pending.receivedParts.length,
			channelId,
			htlcId,
			amountMsat,
			status: PaymentStatus.PENDING
		};
		pending.receivedParts.push(part);

		// Calculate total received so far
		let totalReceived = 0n;
		for (const p of pending.receivedParts) {
			totalReceived += p.amountMsat;
		}

		// Check if we have enough
		if (totalReceived >= pending.totalMsat) {
			// Deliver the preimage to the chain monitors BEFORE fulfilling any part,
			// so every part's received HTLC can still be claimed on-chain if a channel
			// force-closes mid-settlement. recordPreimage keys on the payment hash and
			// fans out to all monitors, so a single call covers all parts — and placing
			// it before the loop means it runs even if a fulfillHtlc throws mid-loop.
			// (Mirrors the single-payment path in fulfillPayment.)
			this.channelManager.recordPreimage(paymentHash, preimage);

			// Fulfill ALL parts atomically
			for (const p of pending.receivedParts) {
				p.status = PaymentStatus.COMPLETED;
				this.channelManager.fulfillHtlc(p.channelId, p.htlcId, preimage);
			}
			this.pendingMppPayments.delete(hashHex);

			// Update payment status
			const payment = this.payments.get(hashHex);
			if (payment) {
				payment.status = PaymentStatus.COMPLETED;
				payment.completedAt = Date.now();
				this.persistPayment(paymentHash);
				this.emit('payment:received', payment);
				this.emitInvoiceSettled(paymentHash, payment);
			}
		}
	}

	/**
	 * Fail all timed-out MPP partial payments.
	 */
	failTimedOutMppPayments(): void {
		const now = Date.now();
		for (const [hashHex, pending] of this.pendingMppPayments) {
			if (now - pending.createdAt > this.mppTimeoutMs) {
				// Fail all parts
				for (const part of pending.receivedParts) {
					if (part.status === PaymentStatus.PENDING) {
						part.status = PaymentStatus.FAILED;
						const htlcSecretKey = `${part.channelId.toString('hex')}:${
							part.htlcId
						}`;
						const sharedSecret =
							this.receivedHtlcSharedSecrets.get(htlcSecretKey);
						const reason = sharedSecret
							? createFailureMessage(sharedSecret, MPP_TIMEOUT)
							: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
						this.cleanupHtlcSharedSecret(htlcSecretKey);
						this.channelManager.failHtlc(part.channelId, part.htlcId, reason);
					}
				}
				this.pendingMppPayments.delete(hashHex);
			}
		}
	}

	private fulfillPayment(
		channelId: Buffer,
		htlcId: bigint,
		paymentHash: Buffer,
		preimage: Buffer
	): void {
		const hashHex = paymentHash.toString('hex');
		// Clean up shared secret on fulfillment
		this.cleanupHtlcSharedSecret(`${channelId.toString('hex')}:${htlcId}`);

		// Deliver the preimage to the chain monitors so this received HTLC can be
		// claimed on-chain if the channel force-closes before/around settlement
		// (e.g. hold invoices, or a crash in this window). Without this the monitor
		// never sees the preimage and the counterparty reclaims via timeout.
		this.channelManager.recordPreimage(paymentHash, preimage);

		// Clean up payment secret after successful fulfillment
		this.paymentSecrets.delete(hashHex);

		const payment = this.payments.get(hashHex);
		if (payment) {
			payment.status = PaymentStatus.COMPLETED;
			payment.completedAt = Date.now();
		}

		// Persist BEFORE sending fulfill message: on crash, reestablish
		// retransmits. The payment record, the consumed payment secret and the
		// fulfill message now commit as ONE transition rather than as a
		// transaction followed by an independent send.
		const settledPayment = this.payments.get(hashHex);
		this.withStagedMutations(
			[
				{ type: 'delete_payment_secret', paymentHash: hashHex },
				...(settledPayment
					? [
							{
								type: 'payment_state' as const,
								paymentHash: hashHex,
								payment: settledPayment
							}
					  ]
					: [])
			],
			() => {
				this.channelManager.fulfillHtlc(channelId, htlcId, preimage);
			}
		);
		// Note: commitment_signed is NOT sent here — it's sent by
		// ChannelManager.handleRevokeAndAck after detecting FULFILLED HTLCs.
		// The htlc:forwarded event fires synchronously during handleRevokeAndAck
		// processing, so the auto-commit runs after this fulfillment completes.

		if (this.storage) {
			try {
				this.persistChannel(channelId);
			} catch {
				/* best-effort */
			}
		}

		if (payment) {
			this.emit('payment:received', payment);
			this.emitInvoiceSettled(paymentHash, payment);
			this.emitStructuredLog('payment', 'received', {
				paymentHash: hashHex,
				amountMsat: Number(payment.amountMsat),
				status: payment.status
			});
		}
	}

	private handleForwardHtlc(
		inChannelId: Buffer,
		inHtlcId: bigint,
		paymentHash: Buffer,
		processed: {
			hopPayload: IHopPayload;
			nextPacket: {
				version: number;
				ephemeralKey: Buffer;
				routingInfo: Buffer;
				hmac: Buffer;
			};
			sharedSecret: Buffer;
		},
		incomingAmountMsat: bigint,
		incomingCltvExpiry: number,
		incomingBlindingPoint?: Buffer
	): void {
		const { hopPayload, nextPacket, sharedSecret } = processed;
		const inHtlcSecretKey = `${inChannelId.toString('hex')}:${inHtlcId}`;

		// Route blinding (BOLT 4): a blinded forwarding hop reads its encrypted
		// recipient data (TLV 10) for the real onward SCID and its payment_relay,
		// and derives the next hop's blinding point. The introduction node gets the
		// blinding point in the onion (TLV 12); a downstream/mid hop gets it via
		// update_add_htlc (incomingBlindingPoint) — supporting blinded chains of any
		// length. For blinded hops the forward amount/CLTV are derived from the
		// hop's own payment_relay (not the cleartext onion), so per-hop fees
		// distribute correctly across >2 blinded hops.
		let outgoingScid = hopPayload.shortChannelId;
		let nextBlindingPoint: Buffer | undefined;
		let holdForLsp = false;
		let blindedOutAmount: bigint | undefined;
		let blindedOutCltv: number | undefined;
		let blindedMaxCltv: number | undefined;
		const effectiveBlindingPoint =
			hopPayload.blindingPoint ?? incomingBlindingPoint;
		if (effectiveBlindingPoint && hopPayload.encryptedRecipientData) {
			try {
				const { hopData, nextBlindingKey } = processBlindedHop(
					effectiveBlindingPoint,
					this.nodePrivkey,
					hopPayload.encryptedRecipientData
				);
				outgoingScid = hopData.shortChannelId;
				nextBlindingPoint = nextBlindingKey;
				holdForLsp = !!hopData.holdHtlc;
				if (hopData.paymentRelay) {
					const relay = hopData.paymentRelay;
					// BOLT 4 route blinding: invert the sender's fee computation with
					// the spec's ceiling formula. Charging the proportional fee on the
					// INCOMING amount instead forwards a few msat short and the
					// downstream node fails the HTLC.
					const propPlusOne =
						1_000_000n + BigInt(relay.feeProportionalMillionths);
					blindedOutAmount =
						((incomingAmountMsat - BigInt(relay.feeBaseMsat)) * 1_000_000n +
							propPlusOne -
							1n) /
						propPlusOne;
					blindedOutCltv = incomingCltvExpiry - relay.cltvExpiryDelta;
				}
				blindedMaxCltv = hopData.paymentConstraints?.maxCltvExpiry;
			} catch {
				outgoingScid = undefined;
			}
		}
		const isBlindedForward = blindedOutAmount !== undefined;
		const forwardAmount = blindedOutAmount ?? hopPayload.amountToForwardMsat;
		const forwardCltv = blindedOutCltv ?? hopPayload.outgoingCltvValue;

		// BOLT 4 route blinding: remember that this incoming HTLC is part of a
		// blinded route (and our role in it) so that EVERY failure — local checks
		// here, addHtlc errors, and downstream failures relayed later — surfaces
		// as invalid_onion_blinding instead of leaking the real cause.
		// TLV 12 (current_blinding_point) marks the introduction node and takes
		// precedence, matching effectiveBlindingPoint above; otherwise the
		// blinding point arrived in update_add_htlc and we are a mid hop.
		const inBlindedRole: 'intro' | 'mid' | undefined = effectiveBlindingPoint
			? hopPayload.blindingPoint
				? 'intro'
				: 'mid'
			: undefined;
		if (inBlindedRole) {
			this.blindedIncomingHtlcs.set(inHtlcSecretKey, inBlindedRole);
		}

		// Fail the incoming HTLC with the given code — or, inside a blinded
		// route, with invalid_onion_blinding regardless of the local cause.
		// UPDATE-flagged codes carry the BOLT 4 fixed fields for that code (see
		// updateFlaggedFailureData); without them the payer cannot tell what
		// amount or expiry was rejected.
		const failIncoming = (
			failureCode: number,
			fields?: { htlcMsat?: bigint; cltvExpiry?: number }
		): void => {
			if (inBlindedRole) {
				this.failBlindedIncomingHtlc(
					inChannelId,
					inHtlcId,
					inBlindedRole,
					sharedSecret
				);
				return;
			}
			this.cleanupHtlcSharedSecret(inHtlcSecretKey);
			this.channelManager.failHtlc(
				inChannelId,
				inHtlcId,
				createFailureMessage(
					sharedSecret,
					failureCode,
					this.updateFlaggedFailureData(failureCode, fields)
				)
			);
		};

		// Forwarding opt-out: a node that does not want to be a routing hop
		// declines every forward up front, before any onward lookup or policy
		// work. temporary_node_failure is the correct code: this is a node-wide
		// policy, not one outgoing channel misbehaving, and unlike
		// temporary_channel_failure it carries no required channel_update payload
		// (BOLT 4). A blinded hop still fails as invalid_onion_blinding via
		// failIncoming, so we do not leak that the decline was policy.
		if (!this.forwardingEnabled) {
			this.emitStructuredLog('htlc', 'forward_declined', {
				paymentHash: paymentHash.toString('hex'),
				inChannelId: inChannelId.toString('hex'),
				inHtlcId: Number(inHtlcId),
				amountInMsat: Number(incomingAmountMsat),
				reason: 'forwarding_disabled'
			});
			failIncoming(TEMPORARY_NODE_FAILURE);
			return;
		}

		// A relay moving other people's money through our channels should be as
		// visible in the log as a payment is. Log the ATTEMPT here (resolution is
		// logged from recordForwardingEvent / the failure paths).
		this.emitStructuredLog('htlc', 'forward_attempt', {
			paymentHash: paymentHash.toString('hex'),
			inChannelId: inChannelId.toString('hex'),
			inHtlcId: Number(inHtlcId),
			amountInMsat: Number(incomingAmountMsat),
			outgoingScid: outgoingScid?.toString('hex'),
			blinded: isBlindedForward
		});

		if (!outgoingScid) {
			failIncoming(UNKNOWN_NEXT_PEER);
			return;
		}

		// Look up outgoing channel via SCID (real SCID for blinded hops) BEFORE
		// the policy checks: the fee/CLTV we enforce is the OUTGOING channel's
		// effective policy (per-channel override or node defaults).
		const scidHex = outgoingScid.toString('hex');
		const outChannelId = this.scidToChannelId.get(scidHex);
		if (!outChannelId) {
			failIncoming(UNKNOWN_NEXT_PEER);
			return;
		}
		const outPolicy = this.getForwardingPolicyForChannel(outChannelId);

		// For a blinded hop the fee/CLTV are defined by payment_relay (the forward
		// amount above already subtracts the relay fee); just ensure it's viable.
		// For a cleartext hop, enforce our own forwarding policy.
		if (isBlindedForward) {
			// Enforce OUR own CLTV cushion even on a blinded hop: cltvExpiryDelta comes
			// from the recipient-authored encrypted_recipient_data, so without this a
			// malicious path builder could set delta=1 and leave us ~1 block to claim
			// the outgoing HTLC on-chain after revealing the preimage → loss of the
			// forwarded amount. Also honour payment_constraints.maxCltvExpiry.
			if (
				forwardAmount <= 0n ||
				incomingCltvExpiry - forwardCltv < outPolicy.cltvExpiryDelta ||
				(blindedMaxCltv !== undefined && incomingCltvExpiry > blindedMaxCltv)
			) {
				// A blinded hop converts this to invalid_onion_blinding inside
				// failIncoming, but pass the fields anyway so a future non-blinded
				// caller of this branch cannot produce a fieldless failure. BOLT 4:
				// the reported cltv_expiry is the OUTGOING HTLC's.
				failIncoming(INCORRECT_CLTV_EXPIRY, {
					cltvExpiry: forwardCltv
				});
				return;
			}
		} else {
			// CLTV delta enforcement: incoming CLTV must exceed outgoing by our delta
			if (incomingCltvExpiry < forwardCltv + outPolicy.cltvExpiryDelta) {
				// BOLT 4: "report the cltv_expiry of the outgoing HTLC", i.e. the
				// onion's outgoing_cltv_value, not the incoming HTLC's expiry.
				failIncoming(INCORRECT_CLTV_EXPIRY, {
					cltvExpiry: forwardCltv
				});
				return;
			}
			// Fee enforcement: incoming amount must cover outgoing amount + our fee
			const requiredFee =
				BigInt(outPolicy.feeBaseMsat) +
				(forwardAmount * BigInt(outPolicy.feeProportionalMillionths)) /
					1_000_000n;
			if (incomingAmountMsat < forwardAmount + requiredFee) {
				failIncoming(FEE_INSUFFICIENT, { htlcMsat: incomingAmountMsat });
				return;
			}
		}

		// The actual onward forward, deferred so an async LSP hold can run it later
		// (on release) with a current HTLC counter. Synchronous loopback may
		// complete the whole fulfillment chain during addHtlc, so we track the
		// outgoing→incoming link BEFORE forwarding (same timing as payment storage).
		const performForward = (): void => {
			const nextOnionBuf = encodeOnionPacket(nextPacket);
			const outChannel = this.channelManager.getChannel(outChannelId);
			const outHtlcId = outChannel
				? outChannel.getFullState().localHtlcCounter
				: 0n;
			const outKey = `${outChannelId.toString('hex')}:offered-${outHtlcId}`;
			this.forwardedHtlcs.set(outKey, { inChannelId, inHtlcId });

			// The linkage and the outgoing add are ONE safety transition
			// (docs/RECOVERY-PROTOCOL.md 5.1): a crash between them would leave
			// an HTLC in flight downstream with no record of the inbound leg it
			// pays for, so the downstream preimage could never be applied
			// upstream and the forwarded value would be lost.
			let result: ChannelResult | null = null;
			this.withStagedMutations(
				[{ type: 'forwarded_htlc', outKey, inChannelId, inHtlcId }],
				() => {
					// For a blinded forward, hand the next hop its blinding point and
					// use the payment_relay-derived amount/CLTV.
					result = this.channelManager.addHtlc(
						outChannelId,
						forwardAmount,
						paymentHash,
						forwardCltv,
						nextOnionBuf,
						nextBlindingPoint
					);
				}
			);

			if (!result || !(result as ChannelResult).ok) {
				// Forward failed — fail the incoming HTLC back. Drop the persisted
				// row too, not just the in-memory one: the outgoing id was read off
				// localHtlcCounter before the add, and a refused add does not consume
				// it, so a surviving row maps an id a later unrelated HTLC will take
				// onto this inbound leg and would settle it against the wrong payment.
				this.forwardedHtlcs.delete(outKey);
				this.withStagedMutations(
					[{ type: 'delete_forwarded_htlc', outKey }],
					() => {
						failIncoming(TEMPORARY_CHANNEL_FAILURE);
					}
				);
				return;
			}

			this.emit(
				'htlc:forward',
				inChannelId,
				outChannelId,
				forwardAmount,
				paymentHash
			);
		};

		// Async payments (LSP role): the recipient's blinded path marked this hop
		// hold_htlc, so park the forward and wait for a release_held_htlc onion
		// message (handled by AsyncPaymentManager) before forwarding to the now-
		// online receiver. The CLTV sweeper fails it back if release never comes.
		if (holdForLsp) {
			const hashHex = paymentHash.toString('hex');
			this.heldForwards.set(hashHex, {
				inChannelId,
				inHtlcId,
				incomingCltvExpiry
			});
			this.asyncPaymentManager.registerHeldForward({
				paymentHash,
				release: () => {
					this.heldForwards.delete(hashHex);
					performForward();
				},
				fail: () => {
					this.heldForwards.delete(hashHex);
					failIncoming(UNKNOWN_NEXT_PEER);
				}
			});
			this.emit('htlc:held-forward', {
				paymentHash,
				amountMsat: hopPayload.amountToForwardMsat
			});
			this.emitStructuredLog('htlc', 'held_forward', { paymentHash: hashHex });
			return;
		}

		performForward();
	}

	/**
	 * Consume a preimage learned ON-CHAIN (extracted from a counterparty's
	 * HTLC-success spend). Two actions, both required to avoid loss of a forwarded
	 * amount we already paid downstream:
	 *  1. Seed EVERY chain monitor via recordPreimage so any inbound HTLC with this
	 *     hash can be claimed on-chain if its channel force-closes (the core fix).
	 *  2. Off-chain settle any still-live INBOUND (received) HTLC matching the hash,
	 *     so a healthy inbound channel resolves cleanly instead of forcing a close.
	 * A channel that cannot carry the fulfill right now (mid-reestablish after a
	 * restart or disconnect, or quiescing for a splice) is skipped with its
	 * forward linkage intact, and settleForwardsOwedUpstream completes the settle
	 * from the persisted preimage at the reestablish tail, at quiescence end, or
	 * at splice completion.
	 * recordPreimage is idempotent, so re-learning a preimage is harmless.
	 */
	private handleOnChainPreimageLearned(
		paymentHash: Buffer,
		preimage: Buffer
	): void {
		const hashHex = paymentHash.toString('hex');
		this.preimages.set(hashHex, preimage);
		this.commitMutations(
			'savePreimage',
			[{ type: 'payment_preimage', paymentHash: hashHex, preimage }],
			RecoveryCriticality.SafetyCritical
		);
		// Seed all monitors (on-chain claim path for every inbound HTLC of this hash).
		this.channelManager.recordPreimage(paymentHash, preimage);

		// Settle the inbound leg off-chain where the channel is still usable.
		for (const channel of this.channelManager.listChannels()) {
			const cid = channel.getChannelId();
			if (!cid) continue;
			for (const [key, htlc] of channel.getFullState().htlcs) {
				if (!key.startsWith('received-')) continue;
				if (
					htlc.state !== HtlcState.COMMITTED &&
					htlc.state !== HtlcState.PENDING
				)
					continue;
				if (!htlc.paymentHash.equals(paymentHash)) continue;
				// The gate that keeps the linkage delete below honest, same
				// discipline as settleForwardUpstream: a channel that cannot
				// carry the fulfill refuses it without throwing, and consuming
				// the forward linkage around that refusal would prime the
				// restore-time redispatch to re-forward the same inbound HTLC
				// for value the downstream already claimed on-chain. The
				// preimage is already durable (saved above), so the retained
				// linkage lets settleForwardsOwedUpstream finish the settle
				// when the channel can carry updates again.
				if (!channel.canFulfillHtlc(htlc.id)) continue;
				this.cleanupHtlcSharedSecret(`${cid.toString('hex')}:${htlc.id}`);
				// Re-stage the preimage with the fulfill it authorizes. The
				// save above already ran, but staging makes the pairing
				// structural instead of leaving it to the ordering of two
				// independent writes.
				this.withStagedMutations(
					[{ type: 'payment_preimage', paymentHash: hashHex, preimage }],
					() => {
						this.channelManager.fulfillHtlc(cid, htlc.id, preimage);
					}
				);
				// Drop any forwarding bookkeeping for the matching outgoing leg,
				// riding the channel transition below as staged mutations.
				const fwdCleanup: RecoveryMutation[] = [];
				for (const [outKey, fwd] of this.forwardedHtlcs) {
					if (fwd.inChannelId.equals(cid) && fwd.inHtlcId === htlc.id) {
						this.forwardedHtlcs.delete(outKey);
						fwdCleanup.push({ type: 'delete_forwarded_htlc', outKey });
					}
				}
				this.withStagedMutations(fwdCleanup, () => {
					this.persistChannel(cid);
				});
			}
		}

		this.emit('preimage:learned', paymentHash, preimage);
	}

	/**
	 * A tracked output resolved irrevocably on-chain. The case that needs
	 * off-chain follow-up here is an OFFERED_HTLC (the outgoing leg of a
	 * forward) resolved WITHOUT a preimage: the downstream never settled and
	 * our HTLC-timeout (or the peer's own timeout claim) is now irrevocable,
	 * which is exactly the BOLT 2 condition for refunding the upstream. Fail
	 * the inbound HTLC off-chain so the healthy inbound channel resolves with
	 * update_fail_htlc instead of the scanForwardTimeouts force-close.
	 * Preimage resolutions are handled by handleOnChainPreimageLearned.
	 */
	private handleOnChainOutputResolved(
		channelId: Buffer | undefined,
		outputType: OutputType,
		paymentHash?: Buffer,
		htlcId?: bigint
	): void {
		if (outputType !== OutputType.OFFERED_HTLC) return;
		if (!channelId || !paymentHash) return;
		// A known preimage means the downstream DID settle; the fulfill path
		// (handleOnChainPreimageLearned / handleHtlcFulfilled) owns the inbound leg.
		if (this.preimages.has(paymentHash.toString('hex'))) return;

		const outChannelIdHex = channelId.toString('hex');
		for (const [outKey, forward] of this.forwardedHtlcs) {
			if (!outKey.startsWith(`${outChannelIdHex}:offered-`)) continue;
			// Exact identity first: same-hash HTLCs (MPP parts, retries) are
			// separate forwards, and one resolved output licenses failing
			// exactly ONE of them. Only a legacy record with no recorded
			// htlcId falls back to the hash match (and its `break` below still
			// bounds it to one leg).
			if (
				htlcId !== undefined &&
				outKey !== `${outChannelIdHex}:offered-${htlcId}`
			)
				continue;
			const inChannel = this.channelManager.getChannel(forward.inChannelId);
			const inHtlc = inChannel
				?.getFullState()
				.htlcs.get(`received-${forward.inHtlcId}`);
			if (!inHtlc || !inHtlc.paymentHash.equals(paymentHash)) continue;
			if (
				inHtlc.state !== HtlcState.PENDING &&
				inHtlc.state !== HtlcState.COMMITTED
			)
				continue;
			// Same discipline as failForwardUpstream (issue 297): a refusal must
			// be established BEFORE the shared-secret cleanup and the linkage
			// delete below, or a quiescence-deferred fail leaves the durable
			// state claiming the refund happened (issue 569). The retained
			// linkage plus the monitor's resolved-without-preimage record
			// re-drive the upstream fail from settleForwardsOwedUpstream.
			if (!inChannel!.canFailHtlc(forward.inHtlcId)) continue;

			const inSecretKey = `${forward.inChannelId.toString('hex')}:${
				forward.inHtlcId
			}`;
			// BOLT 4 route blinding: failures of a blinded forward must surface as
			// invalid_onion_blinding (update_fail_malformed_htlc for a 'mid' hop).
			const blindedRole = this.blindedRoleFor(
				forward.inChannelId,
				forward.inHtlcId
			);
			if (blindedRole) {
				this.failBlindedIncomingHtlc(
					forward.inChannelId,
					forward.inHtlcId,
					blindedRole
				);
			} else {
				const sharedSecret = this.receivedHtlcSharedSecrets.get(inSecretKey);
				const reason = sharedSecret
					? createFailureMessage(sharedSecret, PERMANENT_CHANNEL_FAILURE)
					: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
				this.cleanupHtlcSharedSecret(inSecretKey);
				this.channelManager.failHtlc(
					forward.inChannelId,
					forward.inHtlcId,
					reason
				);
			}
			this.forwardedHtlcs.delete(outKey);
			this.withStagedMutations(
				[{ type: 'delete_forwarded_htlc', outKey }],
				() => {
					this.persistChannel(forward.inChannelId);
				}
			);
			break;
		}
	}

	private handleHtlcFulfilled(
		channelId: Buffer,
		htlcId: bigint,
		preimage: Buffer
	): void {
		// Persist preimage immediately (proof of payment) before any message sends
		const preimageHash = crypto.createHash('sha256').update(preimage).digest();
		this.preimages.set(preimageHash.toString('hex'), preimage);
		this.commitMutations(
			'savePreimage',
			[
				{
					type: 'payment_preimage',
					paymentHash: preimageHash.toString('hex'),
					preimage
				}
			],
			RecoveryCriticality.SafetyCritical
		);

		// Check if this is a forwarded HTLC — propagate fulfillment upstream
		const outKey = `${channelId.toString('hex')}:offered-${htlcId}`;
		const forward = this.forwardedHtlcs.get(outKey);
		if (forward) {
			this.settleForwardUpstream(outKey, forward, preimage, preimageHash);
			this.persistChannel(channelId);
			return;
		}

		// Hash preimage to find the payment
		const paymentHash = crypto.createHash('sha256').update(preimage).digest();
		const hashHex = paymentHash.toString('hex');
		const payment = this.payments.get(hashHex);

		if (
			payment &&
			payment.direction === PaymentDirection.OUTGOING &&
			(payment.status === PaymentStatus.PENDING ||
				payment.status === PaymentStatus.FAILED)
		) {
			payment.status = PaymentStatus.COMPLETED;
			payment.preimage = preimage;
			payment.completedAt = Date.now();
			// Preserve invoice string for payment proof before deleting retry context
			const retryCtx = this.paymentRetryContexts.get(hashHex);
			if (retryCtx?.invoiceStr) {
				if (!payment.metadata) payment.metadata = {};
				payment.metadata._invoice = retryCtx.invoiceStr;
			}
			this.paymentRetryContexts.delete(hashHex);
			this.outboundMppPayments.delete(hashHex);
			// Record success in MissionControl
			if (payment.route) {
				for (const hop of payment.route.hops) {
					this.missionControl.recordSuccess(hop.shortChannelId.toString('hex'));
				}
			}
			// Clean up HTLC payment mapping. The mapping teardown, the consumed
			// secret and the settled payment record ride the channel transition
			// as staged mutations: one journaled transaction instead of an
			// unjournaled wrapper around four writes.
			this.htlcPaymentMap.delete(outKey);
			const settledMutations: RecoveryMutation[] = [
				{ type: 'delete_htlc_payment_mapping', htlcKey: outKey },
				{ type: 'delete_payment_secret', paymentHash: hashHex }
			];
			const settledPaymentMutation = this.paymentMutation(paymentHash);
			if (settledPaymentMutation) settledMutations.push(settledPaymentMutation);
			this.withStagedMutations(settledMutations, () => {
				this.persistChannel(channelId);
			});
			this.emit('payment:sent', payment);
			this.emitStructuredLog('payment', 'sent', {
				paymentHash: hashHex,
				amountMsat: Number(payment.amountMsat),
				status: payment.status
			});
		}
	}

	/**
	 * Propagate a downstream fulfill to the inbound leg it pays for. Returns
	 * whether the inbound channel accepted the fulfill.
	 *
	 * The preimage reaches the chain monitors unconditionally, but the
	 * linkage delete and the forwarding ledger row are consumed ONLY when
	 * the inbound channel can actually carry the fulfill: they ride the same
	 * storage transaction as the fulfill's own state, so a crash cannot
	 * separate them, and a refusal (inbound peer disconnected, or still
	 * mid-reestablish when a restart's replayed fulfill arrives) leaves the
	 * linkage in place for settleForwardsOwedUpstream to retry once the
	 * channel returns to NORMAL. Consuming it around a refused fulfill
	 * would strand the upstream leg and, worse, prime the restore-time
	 * redispatch pass to forward the same inbound HTLC a second time.
	 *
	 * Repeat-tolerant by construction: the linkage row survives exactly
	 * until the settle it admits becomes durable, so a replayed fulfill
	 * that finds it is not a duplicate but the first effective run, and one
	 * that does not finds nothing to redo.
	 */
	private settleForwardUpstream(
		outKey: string,
		forward: { inChannelId: Buffer; inHtlcId: bigint },
		preimage: Buffer,
		preimageHash: Buffer
	): boolean {
		// Deliver the preimage to the chain monitors before settling the
		// incoming leg. We learned this preimage from the downstream fulfill;
		// if the incoming channel force-closes before our upstream fulfill
		// confirms, the monitor must already hold the preimage to claim the
		// inbound HTLC on-chain. Without this the forwarded value is lost via
		// the counterparty's timeout path.
		this.channelManager.recordPreimage(preimageHash, preimage);

		// The gate that keeps the staged consumption honest: everything
		// staged below commits with the fulfill's transition or, if nothing
		// commits inside the callback, on its own. A refusal must therefore
		// be established BEFORE staging, not discovered after.
		const inChannel = this.channelManager.getChannel(forward.inChannelId);
		if (!inChannel || !inChannel.canFulfillHtlc(forward.inHtlcId)) {
			return false;
		}

		// Both legs of the forward settle here: build the ledger entry now,
		// while both HTLC entries still exist (they are dropped on revoke).
		const outParts = outKey.split(':');
		const outChannelId = Buffer.from(outParts[0], 'hex');
		const outHtlcId = BigInt(outParts[1].replace('offered-', ''));
		const ledger = this.buildForwardingEvent(outChannelId, outHtlcId, forward);

		// The preimage, the closed-out linkage, the ledger row and the
		// upstream fulfill are ONE transition: this is the preimage that lets
		// us claim the inbound leg for value we have already paid downstream,
		// so it must never be on the wire without being on disk.
		const mutations: RecoveryMutation[] = [
			{
				type: 'payment_preimage',
				paymentHash: preimageHash.toString('hex'),
				preimage
			},
			{ type: 'delete_forwarded_htlc', outKey }
		];
		if (ledger?.mutation) mutations.push(ledger.mutation);
		this.withStagedMutations(mutations, () => {
			this.channelManager.fulfillHtlc(
				forward.inChannelId,
				forward.inHtlcId,
				preimage
			);
		});
		this.forwardedHtlcs.delete(outKey);
		this.cleanupHtlcSharedSecret(
			`${forward.inChannelId.toString('hex')}:${forward.inHtlcId}`
		);
		ledger?.emit();
		return true;
	}

	/**
	 * Settle upstream any forward on this inbound channel whose downstream
	 * leg already revealed its preimage while the channel could not carry
	 * the fulfill: the process was killed after the downstream settle
	 * became durable, the inbound peer was disconnected when it arrived, or
	 * the channel was quiescing for a splice. Driven from every point where
	 * the channel regains the ability to carry updates: the reestablish
	 * tail, quiescence end, and splice completion.
	 *
	 * Gated on durable facts only: the linkage row survives exactly until
	 * the upstream fulfill commits, the preimage exists only once the
	 * downstream fulfill was processed, and a COMMITTED received HTLC is
	 * the only shape owed a settle. All three hold or the pass skips, so
	 * running it for a channel whose state never went away is a no-op.
	 */
	private settleForwardsOwedUpstream(inChannelId: Buffer): void {
		const channel = this.channelManager.getChannel(inChannelId);
		if (!channel) return;
		const state = channel.getFullState();
		for (const [outKey, forward] of [...this.forwardedHtlcs]) {
			if (!forward.inChannelId.equals(inChannelId)) continue;
			const entry = state.htlcs.get(`received-${forward.inHtlcId}`);
			if (!entry || entry.state !== HtlcState.COMMITTED) continue;
			const preimage = this.preimages.get(entry.paymentHash.toString('hex'));
			if (preimage) {
				this.settleForwardUpstream(
					outKey,
					forward,
					preimage,
					entry.paymentHash
				);
				continue;
			}
			// The fail side of the same debt (issue 297): the outgoing leg
			// failed durably, but the fail owed upstream never became durable
			// (killed process, or the inbound peer was disconnected when the
			// downstream fail arrived). The downstream reason bytes died with
			// the process, so the refund carries a synthesized
			// temporary_channel_failure, which refunds the payer identically.
			const outParts = outKey.split(':');
			const outChannel = this.channelManager.getChannel(
				Buffer.from(outParts[0], 'hex')
			);
			const outState = outChannel?.getFullState();
			const outHtlc = outState?.htlcs.get(outParts[1]);
			// An entry that is GONE from a live NORMAL outbound channel also
			// means the leg failed: an off-chain fulfill makes its preimage
			// durable BEFORE any removal round can complete, so the settle
			// branch above would have taken it. A missing or closed outbound
			// channel stays ambiguous (an on-chain claim can still reveal the
			// preimage later) and is left to the chain machinery and the CLTV
			// sweeper, exactly like scanForwardTimeouts.
			// The on-chain form of the same fact (issue 569): THIS forward's
			// offered output resolved irrevocably and no preimage was ever
			// learned (the settle branch above takes the entry when one
			// exists). This is exactly the predicate handleOnChainOutputResolved
			// acted on; a fail refused there (inbound quiescing) retries here.
			// Matched on the output's recorded htlcId, never the hash alone:
			// same-hash MPP parts and retries are separate forwards, and one
			// timed-out output must not fail every same-hash leg upstream while
			// another leg's output is still unresolved and claimable. A legacy
			// record with no htlcId never matches; those forwards keep the
			// pre-retry behavior (chain machinery and the CLTV sweeper).
			const outHtlcId = BigInt(outParts[1].slice('offered-'.length));
			const outgoingTimedOutOnChain =
				this.channelManager
					.getMonitor(Buffer.from(outParts[0], 'hex'))
					?.getTrackedOutputs()
					.some(
						(o) =>
							o.outputType === OutputType.OFFERED_HTLC &&
							o.status === OutputStatus.IRREVOCABLY_RESOLVED &&
							o.htlcId === outHtlcId &&
							o.paymentHash?.equals(entry.paymentHash) === true
					) === true;
			const outgoingFailed =
				outHtlc?.state === HtlcState.FAILED ||
				(outHtlc === undefined &&
					outState !== undefined &&
					outState.state === ChannelState.NORMAL) ||
				outgoingTimedOutOnChain;
			if (!outgoingFailed) continue;
			const secretKey = `${forward.inChannelId.toString('hex')}:${
				forward.inHtlcId
			}`;
			const sharedSecret = this.receivedHtlcSharedSecrets.get(secretKey);
			const reason = sharedSecret
				? createFailureMessage(
						sharedSecret,
						TEMPORARY_CHANNEL_FAILURE,
						// TEMPORARY_CHANNEL_FAILURE carries the UPDATE flag, so
						// BOLT 4 still requires the two-byte channel_update
						// length even when the update itself is omitted. Empty
						// data here is malformed, and a strict peer may treat
						// the whole failure as such.
						this.updateFlaggedFailureData(TEMPORARY_CHANNEL_FAILURE)
				  )
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.failForwardUpstream(
				outKey,
				forward,
				Buffer.from(outParts[0], 'hex'),
				forward.inHtlcId,
				reason,
				true
			);
		}
	}

	/**
	 * Propagate a downstream failure to the inbound leg it refunds. Mirror
	 * of settleForwardUpstream, with the same discipline (issue 297): the
	 * forward linkage is consumed ONLY when the inbound channel actually
	 * accepts the fail, riding the same storage transaction as the fail's
	 * own state, and a refusal (inbound peer disconnected, or still
	 * mid-reestablish when a restart's replayed fail arrives) leaves the
	 * linkage for settleForwardsOwedUpstream to retry at the next
	 * reestablish tail. `preWrapped` marks a reason that is already a
	 * complete failure message (the owed-pass synthesis) rather than the
	 * downstream's bytes to wrap.
	 */
	/**
	 * The blinded-route role of an inbound HTLC, surviving a restart. The
	 * live map is memory-only; a MID hop's blinding point arrived in
	 * update_add_htlc and is durable on the HTLC entry, so the required
	 * update_fail_malformed_htlc wire form can be reconstructed after a
	 * crash (issue 569 review: a retried fail must not degrade to a plain
	 * update_fail_htlc). An INTRO node's blinding lived only in the onion
	 * payload and is not reconstructible, but its required form IS the
	 * plain update_fail_htlc, so the fallback stays correct there too.
	 */
	private blindedRoleFor(
		inChannelId: Buffer,
		inHtlcId: bigint
	): 'intro' | 'mid' | undefined {
		const key = `${inChannelId.toString('hex')}:${inHtlcId}`;
		const live = this.blindedIncomingHtlcs.get(key);
		if (live) return live;
		const entry = this.channelManager
			.getChannel(inChannelId)
			?.getFullState()
			.htlcs.get(`received-${inHtlcId}`);
		return entry?.blindingPoint ? 'mid' : undefined;
	}

	private failForwardUpstream(
		outKey: string,
		forward: { inChannelId: Buffer; inHtlcId: bigint },
		outChannelId: Buffer,
		outHtlcId: bigint,
		reason: Buffer,
		preWrapped = false
	): boolean {
		// The gate that keeps the staged consumption honest, exactly as in
		// settleForwardUpstream: a refusal must be established BEFORE the
		// linkage delete is staged, or the flush commits it standalone. It
		// also precedes the failure events below: a refused retry (inbound
		// quiescing, per-block owed pass) leaves the HTLC COMMITTED and its
		// linkage intact, so reporting forward_failed there would be false
		// and would repeat on every retry.
		const inChannel = this.channelManager.getChannel(forward.inChannelId);
		if (!inChannel || !inChannel.canFailHtlc(forward.inHtlcId)) {
			return false;
		}

		// Resolution counterpart to forward_attempt for the failure case, so
		// every attempted forward pairs with a 'forwarded' or 'forward_failed'
		// line rather than going silent when the downstream leg fails.
		this.emitStructuredLog('htlc', 'forward_failed', {
			inChannelId: forward.inChannelId.toString('hex'),
			inHtlcId: Number(forward.inHtlcId),
			outChannelId: outChannelId.toString('hex'),
			outHtlcId: Number(outHtlcId)
		});
		this.emit('htlc:forward-failed', {
			inChannelId: forward.inChannelId,
			outChannelId
		});

		const inHtlcSecretKey = `${forward.inChannelId.toString('hex')}:${
			forward.inHtlcId
		}`;
		// BOLT 4 route blinding: a downstream failure of a blinded forward must
		// NOT be relayed (it would leak the blinded portion); replace it with
		// invalid_onion_blinding.
		const blindedRole = this.blindedRoleFor(
			forward.inChannelId,
			forward.inHtlcId
		);
		if (blindedRole) {
			this.withStagedMutations(
				[{ type: 'delete_forwarded_htlc', outKey }],
				() => {
					this.failBlindedIncomingHtlc(
						forward.inChannelId,
						forward.inHtlcId,
						blindedRole
					);
				}
			);
			this.forwardedHtlcs.delete(outKey);
			this.persistChannel(outChannelId);
			return true;
		}
		const inSharedSecret = this.receivedHtlcSharedSecrets.get(inHtlcSecretKey);
		const wrappedReason = preWrapped
			? reason
			: inSharedSecret
			? wrapFailureMessage(inSharedSecret, reason)
			: reason;
		this.withStagedMutations(
			[{ type: 'delete_forwarded_htlc', outKey }],
			() => {
				this.channelManager.failHtlc(
					forward.inChannelId,
					forward.inHtlcId,
					wrappedReason
				);
			}
		);
		this.forwardedHtlcs.delete(outKey);
		this.cleanupHtlcSharedSecret(inHtlcSecretKey);
		this.persistChannel(outChannelId);
		return true;
	}

	/**
	 * Build a forwarding-ledger entry for a forward whose downstream fulfill
	 * arrived, as a stageable mutation plus the events to emit once the
	 * settle actually happens. Amounts come from the live HTLC entries on
	 * both legs; a forward whose entries are already gone (a replayed
	 * fulfill settling after the removal rounds completed) yields null:
	 * there is no accurate amount left to record.
	 */
	private buildForwardingEvent(
		outChannelId: Buffer,
		outHtlcId: bigint,
		forward: { inChannelId: Buffer; inHtlcId: bigint }
	): { mutation: RecoveryMutation | null; emit: () => void } | null {
		const outState = this.channelManager
			.getChannel(outChannelId)
			?.getFullState();
		const inState = this.channelManager
			.getChannel(forward.inChannelId)
			?.getFullState();
		const outHtlc = outState?.htlcs.get(`offered-${outHtlcId}`);
		const inHtlc = inState?.htlcs.get(`received-${forward.inHtlcId}`);
		if (!outHtlc || !inHtlc) return null;
		const amountInMsat = inHtlc.amountMsat;
		const amountOutMsat = outHtlc.amountMsat;
		const emit = (): void => {
			this.emit('htlc:forwarded', {
				inChannelId: forward.inChannelId,
				outChannelId,
				amountInMsat,
				amountOutMsat,
				feeMsat: amountInMsat - amountOutMsat
			});
			// Resolution counterpart to the forward_attempt log, at the same
			// level as a settled payment: a completed relay should leave a
			// trace, not just an SSE event no log consumer sees.
			this.emitStructuredLog('htlc', 'forwarded', {
				paymentHash: inHtlc.paymentHash?.toString('hex'),
				inChannelId: forward.inChannelId.toString('hex'),
				outChannelId: outChannelId.toString('hex'),
				amountInMsat: Number(amountInMsat),
				amountOutMsat: Number(amountOutMsat),
				feeMsat: Number(amountInMsat - amountOutMsat)
			});
		};
		if (
			!this.storage ||
			typeof this.storage.saveForwardingEvent !== 'function'
		) {
			return { mutation: null, emit };
		}
		return {
			mutation: {
				type: 'forwarding_event',
				event: {
					settledAt: Date.now(),
					inChannelId: forward.inChannelId.toString('hex'),
					outChannelId: outChannelId.toString('hex'),
					inScid: inState?.shortChannelId?.toString('hex'),
					outScid: outState?.shortChannelId?.toString('hex'),
					amountInMsat,
					amountOutMsat,
					feeMsat: amountInMsat - amountOutMsat
				}
			},
			emit
		};
	}

	/**
	 * Fail an incoming HTLC that is part of a blinded route (BOLT 4): every
	 * failure must surface as invalid_onion_blinding with the sha256 of the
	 * onion we received, so the sender learns nothing about the blinded
	 * portion. A hop whose blinding point arrived in update_add_htlc ('mid')
	 * MUST use update_fail_malformed_htlc; the introduction node ('intro')
	 * returns a normally encrypted failure.
	 */
	private failBlindedIncomingHtlc(
		inChannelId: Buffer,
		inHtlcId: bigint,
		role: 'intro' | 'mid',
		sharedSecret?: Buffer
	): void {
		const inHtlcSecretKey = `${inChannelId.toString('hex')}:${inHtlcId}`;
		const htlcEntry = this.channelManager
			.getChannel(inChannelId)
			?.getFullState()
			.htlcs.get(`received-${inHtlcId}`);
		const sha256OfOnion = htlcEntry?.onionRoutingPacket
			? crypto
					.createHash('sha256')
					.update(htlcEntry.onionRoutingPacket)
					.digest()
			: Buffer.alloc(32);
		const secret =
			sharedSecret ?? this.receivedHtlcSharedSecrets.get(inHtlcSecretKey);
		this.cleanupHtlcSharedSecret(inHtlcSecretKey);
		if (role === 'mid') {
			this.channelManager.failMalformedHtlc(
				inChannelId,
				inHtlcId,
				sha256OfOnion,
				INVALID_ONION_BLINDING
			);
			return;
		}
		this.channelManager.failHtlc(
			inChannelId,
			inHtlcId,
			createFailureMessage(
				secret ?? Buffer.alloc(32),
				INVALID_ONION_BLINDING,
				sha256OfOnion
			)
		);
	}

	/**
	 * An offered HTLC the channel abandoned before any signature covered it:
	 * the reestablish rollback on a capsule-restored channel whose recency
	 * cannot be proven (issue #469).
	 *
	 * It never reached a commitment, so nothing on chain will ever resolve it -
	 * but its incoming leg, or the payment attempt that dispatched it, is still
	 * waiting. Route both to exactly the paths a peer-sent update_fail_htlc
	 * would have taken.
	 *
	 * Idempotent and safe to run late: both branches no-op when their record is
	 * already gone, and both have durable backstops behind them (the
	 * owed-upstream pass treats an entry gone from a live NORMAL outbound
	 * channel as a failed leg, and the stuck-payment sweep fails a pending
	 * outbound payment with no HTLC).
	 */
	private failAbandonedLocalAdd(
		channelId: Buffer,
		add: IAbandonedLocalAdd
	): void {
		const outKey = `${channelId.toString('hex')}:offered-${add.htlcId}`;
		this.emitStructuredLog('htlc', 'local_add_abandoned', {
			channelId: channelId.toString('hex'),
			htlcId: Number(add.htlcId),
			paymentHash: add.paymentHash.toString('hex'),
			amountMsat: Number(add.amountMsat)
		});
		const forward = this.forwardedHtlcs.get(outKey);
		if (forward) {
			// Synthesized locally under the INBOUND shared secret, the same
			// shape the owed-upstream pass uses for a downstream failure whose
			// reason bytes are gone: there are no downstream bytes here either,
			// and it refunds the payer identically. A refusal leaves the
			// linkage for that pass to retry.
			const secretKey = `${forward.inChannelId.toString('hex')}:${
				forward.inHtlcId
			}`;
			const sharedSecret = this.receivedHtlcSharedSecrets.get(secretKey);
			const reason = sharedSecret
				? createFailureMessage(
						sharedSecret,
						TEMPORARY_CHANNEL_FAILURE,
						// TEMPORARY_CHANNEL_FAILURE carries the UPDATE flag, so
						// BOLT 4 still requires the two-byte channel_update
						// length even when the update itself is omitted. Empty
						// data here is malformed, and a strict peer may treat
						// the whole failure as such.
						this.updateFlaggedFailureData(TEMPORARY_CHANNEL_FAILURE)
				  )
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.failForwardUpstream(
				outKey,
				forward,
				channelId,
				add.htlcId,
				reason,
				true
			);
			return;
		}
		this.handleHtlcFailed(
			channelId,
			add.htlcId,
			Buffer.alloc(0),
			'Outgoing HTLC abandoned: the channel was restored from a Recovery ' +
				'Capsule and its state cannot be proven current'
		);
	}

	private handleHtlcFailed(
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer,
		/**
		 * Set when the failure was generated HERE rather than returned by the
		 * peer: `reason` is then already a complete failure message (or empty)
		 * and this string is the human-readable cause.
		 */
		localFailureReason?: string
	): void {
		// Check if this is a forwarded HTLC — wrap and propagate failure upstream
		const outKey = `${channelId.toString('hex')}:offered-${htlcId}`;
		const forward = this.forwardedHtlcs.get(outKey);
		if (forward) {
			this.failForwardUpstream(
				outKey,
				forward,
				channelId,
				htlcId,
				reason,
				localFailureReason !== undefined
			);
			return;
		}

		// Find the payment associated with this HTLC
		const key = outKey;
		const hashHex = this.htlcPaymentMap.get(key);
		if (!hashHex) return;

		const payment = this.payments.get(hashHex);
		if (!payment || payment.direction !== PaymentDirection.OUTGOING) return;

		// MPP: every part is a distinct onion, so a returned failure decrypts
		// only with the secrets of the part it came back on, and its culpable
		// hop lives on that part's route. The first part's secrets on the
		// payment record are wrong for every later part.
		const mppState = this.outboundMppPayments.get(hashHex);
		const failedPart = mppState?.parts.find(
			(part) => part.htlcId === htlcId && part.channelId.equals(channelId)
		);
		if (failedPart) failedPart.status = PaymentStatus.FAILED;
		const failureSecrets = failedPart?.sharedSecrets ?? payment.sharedSecrets;
		const failureRoute = failedPart?.route ?? payment.route;

		// Decrypt failure message if we have shared secrets
		let failureData: Buffer | undefined;
		// BOLT 2: update_fail_malformed_htlc carries a BARE failure code with
		// the BADONION bit (the channel layer surfaces it as a synthetic
		// 4-byte reason), not an onion-encrypted blob. Only our DIRECT peer
		// can send it (a downstream malformed gets wrapped by the relays), so
		// attribute it to wire hop 0 instead of feeding it to the failure
		// decryptor, where it can never match an HMAC. Without this a
		// compliant blinded peer's invalid_onion_blinding was unreadable, the
		// broken path was never excluded, and the retry hammered it while a
		// working path sat unused (issue #550 review).
		if (
			reason.length === 4 &&
			(reason.readUInt16BE(0) & 0x8000) !== 0 &&
			reason.readUInt16BE(2) === 0
		) {
			payment.failureCode = reason.readUInt16BE(0);
			payment.failureSourceIndex = 0;
		} else if (failureSecrets && reason.length > 0) {
			const result = decryptFailureMessage(failureSecrets, reason);
			if (result) {
				payment.failureCode = result.failure.failureCode;
				payment.failureSourceIndex = result.originIndex;
				failureData = result.failure.failureData;
			} else {
				// No HMAC in the chain matched, so we cannot tell which hop failed or
				// why. Record that rather than leaving an empty failure that reads
				// identically to one that never reached the network at all.
				payment.failureReason =
					'Remote failure could not be decrypted (no hop HMAC matched)';
			}
		} else if (reason.length === 0) {
			payment.failureReason =
				localFailureReason ?? 'Peer failed the HTLC with an empty reason';
		}

		// PERM|15 is overloaded, so the PERM bit alone does not mean "give up":
		// BOLT 4 returns the final node's height precisely so we can spot the
		// transient case, where it rejected our expiry only because it is ahead of
		// us. This records that height so the retry below is built against it
		// rather than repeating the same stale expiry.
		const heightSkew = this.noteHeightSkewFailure(
			payment,
			failureData,
			failureRoute
		);

		// Record failure in MissionControl for future pathfinding. Skipped for
		// height skew: no channel misbehaved, our expiry was stale, so penalising
		// the route would degrade pathfinding over an innocent channel.
		const culpableScid = this.getCulpableHopScid(payment, failureRoute);
		if (culpableScid && !heightSkew) {
			this.missionControl.recordFailure(culpableScid, payment.amountMsat);
		}

		// A channel_update embedded in the failure is NOT applied to the graph.
		// BOLT 4: the origin node MAY consider it when calculating routes to
		// retry this payment, but MUST NOT expose it to third parties in any
		// other context, "including applying the channel_update to the local
		// network graph". The rule exists because any hop on the path can forge
		// one: the failure does not prove which channel it describes, so
		// applying it lets one intermediate poison our view of an arbitrary
		// channel, and graph contents are served onward via gossip queries.
		// LDK dropped this handling for the same reason, and peers are
		// transitioning away from embedding updates at all (we send len 0
		// ourselves since #177). Routing around the failure is handled by the
		// MissionControl penalty above and the retry's excludedChannels below;
		// fresh policy arrives via ordinary gossip.

		// Attempt payment retry for temporary failures, plus the height-skew case
		// detected above.
		const retryCtx = this.paymentRetryContexts.get(hashHex);
		const maxRetries = retryCtx?.maxRetries ?? this.maxPaymentRetries;

		// A failure INSIDE the blinded segment of a BOLT 12 payment implicates
		// the blinded path rather than any public channel: its hops are opaque
		// and their SCIDs zeroed, so the channel exclusion below cannot route
		// around it. Exclude the path index instead, so the retry rotates to
		// the invoice's other paths. When another path remains this also
		// justifies a retry for invalid_onion_blinding, whose PERM|BADONION
		// bits would otherwise read as final: it is the one code every blinded
		// hop returns for any error, precisely so the sender learns nothing
		// beyond "use a different blinded path" (BOLT 4).
		const bolt12PathFailover = this.noteBolt12BlindedPathFailure(
			retryCtx,
			payment,
			failureRoute,
			heightSkew
		);
		// MPP payments are never auto-retried here: redispatching the FULL
		// invoice while sibling parts are still held by the recipient lets the
		// old parts and the retry's parts sum past total_msat, and the
		// recipient fulfills every held part, overpaying the invoice. Until a
		// part-level retry exists, a failed part fails the payment; the
		// recipient releases the sibling holds at its own MPP timeout. The
		// culpable SCID is still recorded in MissionControl above, and the
		// exclusion set still serves manual re-sends.
		if (
			retryCtx &&
			!mppState &&
			retryCtx.retryCount < maxRetries &&
			(heightSkew ||
				bolt12PathFailover ||
				!this.isPermanentFailure(payment.failureCode))
		) {
			// Exclude the failing channel's SCID from future routes. Skipped for
			// height skew: the route is fine, our expiry was stale, and banning a
			// healthy channel would push the retry onto a worse path.
			if (culpableScid && !heightSkew) {
				retryCtx.excludedChannels.add(culpableScid);
			}

			// First-hop diversification: also exclude previous first hop on retries
			if (
				!heightSkew &&
				retryCtx.retryCount > 0 &&
				payment.route &&
				payment.route.hops.length > 0
			) {
				retryCtx.excludedChannels.add(
					payment.route.hops[0].shortChannelId.toString('hex')
				);
			}

			retryCtx.retryCount++;

			// This HTLC attempt is over whatever happens next, and a retry gets its
			// own channel and htlc id, so release this attempt's mapping here rather
			// than only on the give-up path below. Otherwise a retry that succeeds
			// returns early and leaves the failed attempt mapped to this payment
			// hash forever, in memory and in storage.
			this.htlcPaymentMap.delete(key);
			this.commitMutations('release retried HTLC mapping', [
				{ type: 'delete_htlc_payment_mapping', htlcKey: key }
			]);

			// sendPayment() rejects a second payment for a hash that is still
			// registered, so unregister the finished attempt before redispatching.
			// Leaving it registered is what made every retry throw
			// DUPLICATE_PAYMENT into the catch below, so no retry ever actually
			// dispatched. Deliberately do NOT clear this record's failure fields
			// first: if the retry cannot be dispatched we put this exact object
			// back and report it, and a record whose failureCode had been wiped
			// would explain nothing about why the payment failed.
			this.payments.delete(hashHex);
			try {
				// A keysend has no invoice, so replay it from its original preimage
				// to keep the same payment hash. A BOLT 12 payment has no invoice
				// STRING, so re-dispatch its decoded invoice; re-entering
				// payBolt12Invoice re-routes with the exclusions (rotating to the
				// invoice's other blinded paths when the failed one is unusable).
				let retried: IPaymentInfo;
				if (retryCtx.keysend) {
					retried = this.dispatchKeysend(
						retryCtx.keysend.options,
						retryCtx.keysend.preimage,
						retryCtx.excludedChannels
					);
				} else if (retryCtx.bolt12Invoice) {
					retried = this.payBolt12Invoice(
						retryCtx.bolt12Invoice,
						retryCtx.excludedChannels
					);
				} else {
					retried = this.sendPayment(
						retryCtx.invoiceStr!,
						retryCtx.excludedChannels,
						retryCtx.maxFeeMsat,
						retryCtx.amountMsat
					);
				}
				retried.retryCount = retryCtx.retryCount;
				return; // Retry dispatched
			} catch (err) {
				// The retry never left the node. Roll the counter back so
				// retryCount keeps meaning "retries actually dispatched" (with
				// exclusions honored by MPP too, an exhausted graph lands here
				// routinely). Restore the attempt that did fail, keeping its
				// original onion failure, and append why the retry could not be
				// sent rather than discarding that reason silently.
				retryCtx.retryCount--;
				this.payments.set(hashHex, payment);
				payment.retryCount = retryCtx.retryCount;
				const detail = err instanceof Error ? err.message : String(err);
				payment.failureReason = payment.failureReason
					? `${payment.failureReason}; retry not dispatched: ${detail}`
					: `Retry not dispatched: ${detail}`;
			}
		}

		// No retry or retry exhausted — mark as permanently failed. Sibling
		// MPP parts fail back one at a time, each landing here with its own
		// htlc mapping; the payment-level transition (timestamp + event) must
		// happen only once.
		this.paymentRetryContexts.delete(hashHex);
		const firstFailure = payment.status !== PaymentStatus.FAILED;
		payment.status = PaymentStatus.FAILED;
		if (firstFailure) payment.completedAt = Date.now();
		// Keep the MPP state until dispatch has finished and every part has
		// resolved, so each sibling failure still decrypts with its own
		// part's secrets; then drop it.
		if (
			mppState?.dispatchComplete &&
			mppState.parts.every((part) => part.status !== PaymentStatus.PENDING)
		) {
			this.outboundMppPayments.delete(hashHex);
		}
		// Clean up HTLC payment mapping. The mapping teardown and the failed
		// payment record ride the channel transition as staged mutations, one
		// journaled transaction, mirroring the settled-payment teardown.
		this.htlcPaymentMap.delete(key);
		const failedTeardown: RecoveryMutation[] = [
			{ type: 'delete_htlc_payment_mapping', htlcKey: key }
		];
		const failedPaymentMutation = this.paymentMutation(payment.paymentHash);
		if (failedPaymentMutation) failedTeardown.push(failedPaymentMutation);
		this.withStagedMutations(failedTeardown, () => {
			this.persistChannel(channelId);
		});
		if (firstFailure) this.emit('payment:failed', payment);
	}

	/**
	 * The short_channel_id to blame for a failed payment, or undefined when the
	 * failure implicates a node rather than a channel.
	 *
	 * decryptFailureMessage returns the index of the ERRING HOP, and a route hop's
	 * shortChannelId is the channel used to REACH that hop (see buildRoute in
	 * pathfinding). The channel at fault is therefore the erring node's OUTGOING
	 * one, hops[index + 1], not hops[index]. Blaming hops[index] penalises the
	 * channel that worked, and for a failure at hop 0 that is our own channel to
	 * our peer, which MissionControl then scores down and retries exclude,
	 * eventually leaving no route at all.
	 *
	 * Channel-scoped failures are those carrying the UPDATE flag (0x1000), which by
	 * definition describe the outgoing channel, plus the two BOLT 4 failures that
	 * also describe the outgoing channel but carry no channel_update and therefore
	 * no UPDATE flag: unknown_next_peer and required_channel_feature_missing.
	 * permanent_channel_failure needs no special case, it is PERM|UPDATE|8.
	 */
	private getCulpableHopScid(
		payment: IPaymentInfo,
		route: IPaymentInfo['route'] = payment.route
	): string | undefined {
		const index = payment.failureSourceIndex;
		if (!route || index === undefined) return undefined;
		const code = payment.failureCode;
		if (code === undefined) return undefined;

		if (!this.isChannelScopedFailure(code)) return undefined;

		// The final hop has no outgoing channel, so there is nothing to blame.
		const outgoingHop = route.hops[index + 1];
		return outgoingHop?.shortChannelId.toString('hex');
	}

	/**
	 * Whether an onion failure code describes the erring node's OUTGOING CHANNEL
	 * (as opposed to the node itself, or the payment as seen by the final hop).
	 */
	private isChannelScopedFailure(code: number): boolean {
		// NODE (0x2000) failures describe the node, never one of its channels.
		if ((code & 0x2000) !== 0) return false;
		if ((code & 0x1000) !== 0) return true;
		return (
			code === UNKNOWN_NEXT_PEER || code === REQUIRED_CHANNEL_FEATURE_MISSING
		);
	}

	/**
	 * Check if a failure code indicates a permanent failure that should not be retried.
	 * PERM flag (0x4000) and BADONION flag (0x8000) indicate permanent failures.
	 * EXPIRY_TOO_FAR (21) is also permanent.
	 */
	private isPermanentFailure(failureCode?: number): boolean {
		if (failureCode === undefined) return false;
		// PERM flag
		if (failureCode & 0x4000) return true;
		// BADONION flag
		if (failureCode & 0x8000) return true;
		// Individual permanent codes
		if (failureCode === EXPIRY_TOO_FAR) return true;
		return false;
	}

	// ─────────────── Payment Queries ───────────────

	getPayment(paymentHash: Buffer): IPaymentInfo | undefined {
		return this.payments.get(paymentHash.toString('hex'));
	}

	listPayments(): IPaymentInfo[] {
		return [...this.payments.values()];
	}

	/**
	 * List settled forwards (newest first). Storage-backed: without a storage
	 * backend that supports the forwarding ledger, returns [].
	 */
	listForwards(filter?: IForwardingEventFilter): IForwardingEvent[] {
		if (
			!this.storage ||
			typeof this.storage.listForwardingEvents !== 'function'
		) {
			return [];
		}
		try {
			return this.storage.listForwardingEvents(filter);
		} catch {
			return [];
		}
	}

	/** Aggregate totals (count, volume out, fees earned) over settled forwards. */
	getForwardingSummary(options?: { since?: number }): IForwardingSummary {
		if (
			!this.storage ||
			typeof this.storage.getForwardingSummary !== 'function'
		) {
			return { count: 0, volumeOutMsat: 0n, feesEarnedMsat: 0n };
		}
		try {
			return this.storage.getForwardingSummary(options);
		} catch {
			return { count: 0, volumeOutMsat: 0n, feesEarnedMsat: 0n };
		}
	}

	/**
	 * Get a cryptographic payment proof for a completed payment.
	 * Returns null if payment not found, not completed, or missing preimage.
	 */
	getPaymentProof(paymentHash: Buffer): IPaymentProof | null {
		const hashHex = paymentHash.toString('hex');
		const payment = this.payments.get(hashHex);
		if (!payment) return null;
		if (payment.status !== PaymentStatus.COMPLETED) return null;
		if (!payment.preimage) return null;

		const proof: IPaymentProof = {
			paymentHash: payment.paymentHash,
			preimage: payment.preimage,
			amountMsat: payment.amountMsat,
			completedAt: payment.completedAt || payment.createdAt
		};

		// Include the original invoice string if stored in metadata
		if (payment.metadata?._invoice) {
			proof.invoice = payment.metadata._invoice;
		}

		if (payment.route) {
			proof.route = payment.route;
		}

		return proof;
	}

	/**
	 * Set or update metadata on a payment (for agent labeling).
	 */
	setPaymentMetadata(
		paymentHash: Buffer,
		metadata: Record<string, string>
	): void {
		const hashHex = paymentHash.toString('hex');
		const existing = this.payments.get(hashHex);
		if (existing) {
			existing.metadata = { ...existing.metadata, ...metadata };
			this.commitMutations('savePaymentMetadata', [
				{ type: 'payment_state', paymentHash: hashHex, payment: existing }
			]);
		}
	}

	/**
	 * Estimate the route fee for a payment without sending.
	 */
	estimateRouteFee(
		bolt11: string,
		amountSats?: number
	): { feeSats: number; hops: number; cltvDelta: number } | null {
		try {
			const decoded = decodeInvoice(bolt11);
			// Same precedence sendPayment applies (see estimatePayment).
			const amountMsat =
				decoded.amountMsat ??
				(amountSats !== undefined ? BigInt(amountSats) * 1000n : undefined);
			if (amountMsat === undefined) return null;

			const destination = decoded.payeeNodeKey || decoded.recoveredPubkey;
			if (!destination) return null;

			const sourceBuf = Buffer.from(this.nodeId, 'hex');
			const route = findRoute(
				this.graph,
				sourceBuf,
				destination,
				amountMsat,
				decoded.minFinalCltvExpiry || DEFAULT_MIN_FINAL_CLTV_EXPIRY,
				20, // maxHops
				undefined, // excludedChannels
				this.missionControl,
				undefined, // maxCltvExpiry
				decoded.routingHints,
				undefined, // currentTimestamp
				this.getLocalChannelEdges()
			);
			if (!route) return null;
			return {
				feeSats: Number(route.totalFeeMsat / 1000n),
				hops: route.hops.length,
				cltvDelta: route.totalCltvDelta
			};
		} catch {
			return null;
		}
	}

	/**
	 * Estimate payment success probability, fees, and route quality for an invoice.
	 * Uses MissionControl penalty history and route analysis to provide intelligence
	 * without sending an actual payment.
	 *
	 * @param bolt11 - BOLT 11 invoice string
	 * @param amountSats - Optional amount for amount-less invoices
	 * @returns Payment estimate or null if no route or invalid invoice
	 */
	estimatePayment(
		bolt11: string,
		amountSats?: number
	): IPaymentEstimate | null {
		try {
			const decoded = decodeInvoice(bolt11);
			// The precedence sendPayment applies: a fixed invoice is paid for its
			// ENCODED amount and the override serves an amountless one, so an
			// estimate built on the override describes a payment that will never
			// be made (issue #528).
			const amountMsat =
				decoded.amountMsat ??
				(amountSats !== undefined ? BigInt(amountSats) * 1000n : undefined);
			if (amountMsat === undefined) return null;

			const destination = decoded.payeeNodeKey || decoded.recoveredPubkey;
			if (!destination) return null;

			const sourceBuf = Buffer.from(this.nodeId, 'hex');

			// Try to find a route
			const route = findRoute(
				this.graph,
				sourceBuf,
				destination,
				amountMsat,
				decoded.minFinalCltvExpiry || DEFAULT_MIN_FINAL_CLTV_EXPIRY,
				20, // maxHops
				undefined, // excludedChannels
				this.missionControl,
				undefined, // maxCltvExpiry
				decoded.routingHints,
				undefined, // currentTimestamp
				this.getLocalChannelEdges()
			);

			if (!route) return null;

			// Calculate success probability from MissionControl penalties
			let successProbability = 1.0;
			for (const hop of route.hops) {
				const scidHex = hop.shortChannelId.toString('hex');
				const penalty = this.missionControl.getPenalty(scidHex, amountMsat);
				// Higher penalty = lower success probability
				// MissionControl penalties are in msat, normalize to a probability
				const hopProb =
					penalty > 0n
						? Math.max(0.1, 1.0 - Number(penalty) / 1_000_000)
						: 0.95;
				successProbability *= hopProb;
			}

			const successPct = Math.round(successProbability * 100);
			const hopCount = route.hops.length;
			const feeSats = Number(route.totalFeeMsat / 1000n);

			// Route quality based on hop count and probability
			let routeQuality: 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
			if (hopCount > 4 || successPct < 50) routeQuality = 'LOW';
			else if (hopCount > 2 || successPct < 75) routeQuality = 'MEDIUM';

			// Estimated time: ~2s per hop for HTLC settlement
			const estimatedTimeMs = hopCount * 2000;

			// Check if alternative routes exist (MPP)
			let alternativeAvailable = false;
			try {
				const altRoute = findMultiPathRoute(
					this.graph,
					sourceBuf,
					destination,
					amountMsat,
					decoded.minFinalCltvExpiry || DEFAULT_MIN_FINAL_CLTV_EXPIRY,
					undefined,
					undefined,
					this.missionControl,
					decoded.routingHints,
					undefined, // currentTimestamp
					this.getLocalChannelEdges()
				);
				alternativeAvailable = altRoute !== null && altRoute.parts.length > 1;
			} catch {
				// No alternative route
			}

			// Warnings
			let warning: string | undefined;
			if (feeSats > Number(amountMsat / 1000n) * 0.03) {
				warning = 'Fees exceed 3% of payment amount';
			} else if (hopCount > 3) {
				warning = 'Long route may be less reliable';
			} else if (successPct < 60) {
				warning = 'Low success probability based on historical data';
			}

			return {
				successProbabilityPct: successPct,
				estimatedTimeMs,
				routeQuality,
				warning,
				alternativeAvailable,
				estimatedFeeSats: feeSats,
				hopCount
			};
		} catch {
			return null;
		}
	}

	/**
	 * Probe a route to a destination without committing real funds.
	 * Sends an HTLC with a random payment hash. If the final hop returns
	 * INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, the route is viable.
	 * Results are recorded in MissionControl.
	 *
	 * @returns { success: true, feeSats, hops } if route is viable, { success: false } otherwise
	 */
	probeRoute(
		destination: string,
		amountSats: number
	): {
		success: boolean;
		feeSats?: number;
		hops?: number;
		path?: Array<{ pubkey: string; shortChannelId: string }>;
	} {
		try {
			const amountMsat = BigInt(amountSats) * 1000n;
			const destBuf = Buffer.from(destination, 'hex');
			const sourceBuf = Buffer.from(this.nodeId, 'hex');

			const route = findRoute(
				this.graph,
				sourceBuf,
				destBuf,
				amountMsat,
				DEFAULT_MIN_FINAL_CLTV_EXPIRY,
				20,
				undefined,
				this.missionControl,
				undefined, // maxCltvExpiry
				undefined, // routingHints
				undefined, // currentTimestamp
				this.getLocalChannelEdges()
			);
			if (!route) return { success: false };

			// Route exists — we can estimate viability from the graph
			// Record the probe as "success" in mission control for first hop
			if (route.hops.length > 0) {
				this.missionControl.recordSuccess(
					route.hops[0].shortChannelId.toString('hex')
				);
			}

			return {
				success: true,
				feeSats: Number(route.totalFeeMsat / 1000n),
				hops: route.hops.length,
				// A hop's shortChannelId is the channel used to REACH it, so this is
				// exactly the set of SCIDs the onion will name. Surfacing them is what
				// makes an unknown_next_peer diagnosable without reproducing it.
				path: route.hops.map((h) => ({
					pubkey: h.pubkey.toString('hex'),
					shortChannelId: h.shortChannelId.toString('hex')
				}))
			};
		} catch {
			return { success: false };
		}
	}

	/**
	 * Compute a route to a destination via the network graph WITHOUT sending a
	 * payment or mutating MissionControl. Returns the raw pathfinding route
	 * (relative CLTV deltas, bigint msat amounts) or null if no path exists.
	 */
	queryRoute(
		destination: Buffer,
		amountMsat: bigint,
		finalCltvExpiry: number = DEFAULT_MIN_FINAL_CLTV_EXPIRY
	): IRoute | null {
		const sourceBuf = Buffer.from(this.nodeId, 'hex');
		return findRoute(
			this.graph,
			sourceBuf,
			destination,
			amountMsat,
			finalCltvExpiry,
			undefined,
			undefined,
			this.missionControl,
			undefined, // maxCltvExpiry
			undefined, // routingHints
			undefined, // currentTimestamp
			this.getLocalChannelEdges()
		);
	}

	// ─────────────── Message Handling (testing support) ───────────────

	handlePeerMessage(pubkey: string, type: number, payload: Buffer): void {
		// Startup quarantine: the event-transport inbound boundary (the
		// networked path is gated inside PeerManager). Nothing may reach the
		// channel manager before ownership is confirmed; an inbound error
		// message would otherwise force-close and BROADCAST on a device that
		// may no longer own the channel state it stores.
		if (!this.recoveryPermitsPeerTraffic()) {
			this.recoveryGate?.reportBlocked(
				`dropped inbound message type ${type} from ${pubkey}`
			);
			return;
		}
		if (Buffer.isBuffer(payload) && payload.length > MAX_MESSAGE_SIZE) {
			this.emit('node:error', {
				code: 'MESSAGE_TOO_LARGE',
				message: `Message payload ${payload.length} bytes exceeds maximum ${MAX_MESSAGE_SIZE}`,
				timestamp: Date.now()
			} as ILightningError);
			return;
		}
		// Route gossip messages (including query types 261-265)
		if (
			type === MessageType.CHANNEL_ANNOUNCEMENT ||
			type === MessageType.NODE_ANNOUNCEMENT ||
			type === MessageType.CHANNEL_UPDATE ||
			type === MessageType.QUERY_CHANNEL_RANGE ||
			type === MessageType.REPLY_CHANNEL_RANGE ||
			type === MessageType.QUERY_SHORT_CHANNEL_IDS ||
			type === MessageType.REPLY_SHORT_CHANNEL_IDS_END ||
			type === MessageType.GOSSIP_TIMESTAMP_FILTER
		) {
			this.handleGossipMessage(pubkey, type, payload);
		}

		// Route onion messages to OnionMessageManager
		if (type === MessageType.ONION_MESSAGE) {
			this.onionMessageManager.handleMessage(pubkey, payload);
		}

		// Beignet-to-beignet custom traffic (issue #546). Odd type: peers that
		// do not speak it never send it, so anything arriving is addressed to
		// this surface and never falls through to the channel manager. Unknown
		// subtypes and versions ride the event untouched (receivers must
		// tolerate them); an undecodable envelope is logged and dropped
		// without disconnecting the peer.
		if (type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
			// Decode failures and observer failures are DIFFERENT errors and
			// neither may reach the transport (issue #546 review): a throwing
			// 'custom-message' listener is the observer's bug, not a peer
			// decode failure, and a throwing 'log' listener during either
			// report would otherwise escape and cost the peer its connection.
			let msg: ICustomMessage;
			try {
				msg = decodeCustomMessage(payload);
			} catch (err) {
				try {
					this.emitStructuredLog('peer', 'custom_message_decode_failed', {
						pubkey,
						error: err instanceof Error ? err.message : String(err)
					});
				} catch {
					// A throwing log observer must not disconnect the peer.
				}
				return;
			}
			try {
				this.emit('custom-message', {
					peerPubkey: pubkey,
					version: msg.version,
					subtype: msg.subtype,
					payload: msg.payload
				});
			} catch (err) {
				try {
					this.emitStructuredLog('peer', 'custom_message_listener_failed', {
						pubkey,
						subtype: msg.subtype,
						error: err instanceof Error ? err.message : String(err)
					});
				} catch {
					// Same rule: observers never take the transport down.
				}
			}
			return;
		}

		// Route channel messages to ChannelManager
		this.channelManager.handleMessage(pubkey, type, payload);
	}

	/**
	 * Send a beignet custom message to a connected peer. Carried on a single
	 * odd wire type, so non-beignet peers silently ignore it (BOLT 1).
	 * Outbound rides peerManager.sendToPeer, which the recovery outbound gate
	 * already fences during startup quarantine.
	 */
	sendCustomMessage(
		peerPubkeyHex: string,
		subtype: number,
		payload: Buffer
	): void {
		if (!this.peerManager) {
			throw new Error('Networking is not enabled on this node');
		}
		const envelope = encodeCustomMessage(subtype, payload);
		this.peerManager.sendToPeer(
			peerPubkeyHex,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			envelope
		);
	}

	// ─────────────── Chain Monitor Delegation ───────────────

	handleFundingSpent(
		channelId: Buffer,
		spendingTx: import('bitcoinjs-lib').Transaction,
		blockHeight: number,
		destinationScript: Buffer
	): void {
		this.channelManager.handleFundingSpent(
			channelId,
			spendingTx,
			blockHeight,
			destinationScript,
			this.resolveForceCloseFeeRatePerVbyte()
		);
	}

	handleNewBlock(blockHeight: number): void {
		this.currentBlockHeight = blockHeight;
		this.channelManager.handleNewBlock(blockHeight);
		// Funding txs we are obligated to broadcast (BOLT 2) but which have
		// not confirmed yet: retry, so a transient failure at watch:funding
		// or a mempool eviction never orphans a signed funding.
		this.retryPendingFundingBroadcasts();
		this.retryPendingSpliceBroadcasts();
		this.retryFailedTerminalPersists();
		this.retrySpliceCloseRedrives();
		this.retryPendingOutputWatches();
		// Re-CPFP any stuck anchor force-close commitment at the current live feerate
		// so a fee spike after the original broadcast cannot pin the package (M1).
		this.channelManager.reCpfpStuckCommitments(
			blockHeight,
			this.resolveForceCloseFeeRatePerVbyte()
		);
		this.scanExpiringHtlcs(blockHeight);
		// Invariant keeper for HTLC dispatches parked during quiescence: the
		// terminal quiescence exits (disconnect, errored, force close) emit no
		// 'quiescence:ended', so retry every parked channel each block.
		for (const channelIdHex of [...this.parkedQuiescentHtlcs.keys()]) {
			this.drainParkedQuiescentHtlcs(channelIdHex);
		}
		// Same invariant keeper for settles owed upstream (issue 569): a settle
		// refused while the inbound channel was quiescing left its forward
		// linkage row as the durable retry token, and a terminal quiescence
		// exit emits no 'quiescence:ended' to finish it. Runs before the
		// timeout scans below so an owed settle consumes its linkage before
		// scanForwardTimeouts judges the same HTLC. Refusals are
		// pure-predicate cheap, so re-running per block costs nothing.
		const owedInbound = new Set<string>();
		for (const forward of this.forwardedHtlcs.values()) {
			owedInbound.add(forward.inChannelId.toString('hex'));
		}
		for (const inChannelIdHex of owedInbound) {
			this.settleForwardsOwedUpstream(Buffer.from(inChannelIdHex, 'hex'));
		}
		this.scanExpiringOfferedHtlcs(blockHeight);
		this.scanExpiringHeldHtlcs(blockHeight);
		this.scanExpiringHeldForwards(blockHeight);
		this.scanForwardTimeouts(blockHeight);
		this.scanStuckChannels(blockHeight);
		this.reviewFundingMissingClocks(blockHeight);
		this.scanStuckPayments();
		this.sweepExpiredIssuedInvoices();
		if (blockHeight % 10 === 0) {
			this.scanExpiredPendingPayments();
		}
		if (this.storage) {
			try {
				this.storage.saveMetadata('blockHeight', String(blockHeight));
			} catch {
				// best-effort
			}
		}
		// Keep the fee advisor warm so a (synchronous) force-close can resolve a live
		// feerate for its commitment CPFP + time-sensitive HTLC txs (H2). Non-blocking.
		this.warmFeeAdvisor();
	}

	/**
	 * Record a fresh estimator sample into the fee advisor and feed the live
	 * rate to every active chain monitor so the RBF re-bump floor tracks the
	 * market (monitors created mid-session otherwise keep their build-time
	 * rate forever). Non-blocking, best-effort; no-op without an estimator.
	 *
	 * Called at construction (initial seed), on every chain-watcher block, and
	 * from handleNewBlock. The seed matters beyond force-closes: a dual-funded
	 * openChannel must pin funding_feerate_perkw synchronously inside
	 * open_channel2, so the advisor must hold a sample by the time the first
	 * open is attempted — v1 can ask the estimator at funding time, v2 cannot.
	 */
	private warmFeeAdvisor(): void {
		if (!this.feeEstimator) return;
		this.feeEstimator
			.estimateFee(6)
			.then((rawSatPerVbyte) => {
				const satPerVbyte = this.clampEstimatedFeeRate(rawSatPerVbyte);
				if (satPerVbyte > 0) {
					this.feeAdvisor.recordSample(satPerVbyte);
					// updateFeeRate expects sat/kw: 1 sat/vB = 250 sat/kw.
					this.channelManager.updateMonitorFeeRates(satPerVbyte * 250);
				}
			})
			.catch(() => {
				/* best-effort; consumers fall back to their own defaults */
			});
	}

	getCurrentBlockHeight(): number {
		return this.currentBlockHeight;
	}

	/**
	 * Resolve a conservative sat/vB feerate for a force-close package — the commitment
	 * CPFP child and the time-sensitive second-level HTLC txs, which must confirm
	 * before an HTLC's cltv_expiry. Uses the freshest live fee sample (kept warm in
	 * handleNewBlock / the monitor-restore loop) with an urgency multiplier, and falls
	 * back to the historical default ONLY when we have no fee data at all — so a node
	 * with a fee estimator never force-closes at a fee a routine mempool spike would
	 * strand (H2), while nodes without one behave exactly as before.
	 */
	private resolveForceCloseFeeRatePerVbyte(): number {
		const live = this.feeAdvisor.getCurrentRate();
		if (live <= 0) return FORCE_CLOSE_DEFAULT_SAT_PER_VBYTE;
		return Math.max(
			Math.ceil(live * FORCE_CLOSE_FEE_MULTIPLIER),
			FORCE_CLOSE_DEFAULT_SAT_PER_VBYTE
		);
	}

	/**
	 * A channel failed by a BOLT 1 error, ours or the peer's. BOLT 1 requires
	 * the channel to be FAILED, not merely remembered as failed: broadcast our
	 * latest commitment so resolution does not depend on the peer acting (LND's
	 * ErrRecoveryError, for one, waits for us). Skips channels with nothing on
	 * chain, and channels where data loss was detected, since broadcasting a
	 * provably stale commitment would hand the peer the justice path; there we
	 * keep waiting for the peer's commitment, which is the only safe outcome.
	 */
	private handleChannelErrored(channelId: Buffer, reason: string): void {
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;
		const state = channel.getFullState();
		if (state.state !== ChannelState.ERRORED) return;
		if (!state.fundingTxid) return;
		if (mustNotBroadcastCommitment(state)) {
			// Proven stale or unprovable (recovery 5.6): broadcasting our
			// commitment is forbidden; the peer's close resolves the channel.
			// FIRST, ahead of the v2 disposition below: 5.6's only safe exit
			// is the peer closing, and that needs the channel, its monitor and
			// its funding watch to still be here when the peer's commitment
			// lands. A restore marks these rows precisely because their record
			// cannot be trusted to describe the chain, so a removal decided
			// from that record is the one thing this state must not do
			// (issue #463).
			this.emitStructuredLog('channel', 'errored_awaiting_peer_close', {
				channelId: channelId.toString('hex'),
				reason
			});
			return;
		}
		// A capsule-restored row no reestablish has confirmed yet (issue #469).
		// Here rather than only at the shared guard below, for the reason the
		// #463 comment above gives: the v2 disposition between the two can
		// REMOVE the channel, and a removal decided from a record whose recency
		// is unproven is the one thing this state must not do. The channel
		// keeps asking the peer to close on every reconnect meanwhile.
		if (this.skipAutoCloseRestoreUnproven(state, `errored: ${reason}`)) {
			// Nothing automatic will ever close this channel, so the peer-close
			// request is the only thing that moves it, and it has to leave NOW.
			// handlePeerReconnected regenerates it on every reconnect, but a
			// channel the peer errors while it is already connected would
			// otherwise sit until something else happened to reconnect them,
			// with both sides waiting on the other (issue #469).
			//
			// ONCE per channel per process. The request IS a BOLT 1 error, and
			// this path runs on every error we process, including the one a
			// peer sends back in answer to ours: sending unconditionally makes
			// two nodes trade errors forever. The durable repeat lives on the
			// reconnect path, which is naturally paced, so nothing is lost.
			//
			// Latched BEFORE the send, not after it. processActions dispatches
			// synchronously, so the peer's answering error can re-enter this
			// very method before the call returns, and a latch set afterwards
			// is still empty when it does. Cleared again if nothing was
			// actually sent, so a channel with no disposition yet can still
			// ask later.
			const idHex = channelId.toString('hex');
			if (!this._recoveryCloseRequested.has(idHex)) {
				this._recoveryCloseRequested.add(idHex);
				if (!this.channelManager.sendRecoveryCloseRequest(channelId)) {
					this._recoveryCloseRequested.delete(idHex);
				}
			}
			return;
		}
		if (state.v2InFlight && !channel.isV2AttemptBroadcastable()) {
			// A v2 open the peer provably cannot broadcast: our witnesses
			// never left AND the funding tx still needs them, so a
			// commitment spending its outpoint can never confirm and
			// "closing on chain" is a fiction. This is the diverged-RBF
			// terminal (the peer answered reestablish with unknown-channel
			// after dropping its side); void the channel instead of
			// broadcasting into nothing. A broadcastable attempt, including
			// the zero-local-input case where the peer needs no witness
			// bytes from us at all, keeps the watch and the force-close
			// path below instead.
			//
			// The VOID needs more than the record does. "Nothing to broadcast"
			// is a claim about what this node did; "nothing on chain" is a
			// claim about the chain, and a row read off disk at startup can be
			// an older view of an open that has since funded (a Recovery
			// Capsule is best-effort recency, docs/RECOVERY-PROTOCOL.md 5.4).
			// Deleting the channel there takes the funding watch, the lazily
			// built monitor and the SCB entry with it, which is exactly how a
			// peer's force-close went unswept in issue #463. So the removal is
			// declined for such a row and the channel is retained: the
			// funding-missing watchdog still removes it if the chain says the
			// funding is not there, after three absent history answers and
			// BOLT 2's 2016 blocks.
			if (this.channelManager.isChannelRestoredFromDisk(channelId)) {
				this.emitStructuredLog('channel', 'errored_unsigned_v2_retained', {
					channelId: channelId.toString('hex'),
					reason
				});
				return;
			}
			this.emitStructuredLog('channel', 'errored_unsigned_v2_voided', {
				channelId: channelId.toString('hex'),
				reason
			});
			// Nothing anyone can broadcast: the pledges reserving our inputs
			// protect a transaction that will never exist, so they release
			// as soon as the void's durable terminal decision lands
			// (issue #311). A void that could not delete or condemn the row
			// keeps the pledges: a restart would restore the open and its
			// inputs must still be reserved.
			const pledges = channel.getReleasableV2PledgeOutpoints();
			const voided = this.voidMissingFundingChannel(
				channelId,
				state.fundingTxid.toString('hex')
			);
			if (voided && pledges.length > 0) {
				void this.fundingProvider
					?.releaseInputPledges?.(pledges)
					.catch(() => undefined);
			}
			return;
		}
		if (
			this.skipAutoCloseFundingNotOnChain(channel, state, `errored: ${reason}`)
		) {
			// A v1 open failed before its funding is known on chain (acceptor:
			// the opener may never publish; manual opener: we cannot see the
			// mempool). Leave the channel ERRORED: fundingConfirmed stamps the
			// confirmation durably and re-drives this close, and the
			// funding-missing clock (FUNDING_FORGET_BLOCKS) retires the
			// channel if the funding never appears. Skip, do NOT void
			// (issue #413).
			return;
		}
		const result = this._forceCloseWithReason(
			channelId,
			this.getSweepDestinationScript(),
			this.resolveForceCloseFeeRatePerVbyte(),
			'CHANNEL_FAILED_FORCE_CLOSED'
		);
		if (!result.ok) {
			// Say what actually happened: the channel is still ERRORED and
			// nothing was broadcast. Claiming a close here would point an
			// operator away from the real problem.
			this.emit('node:error', {
				code: 'CHANNEL_FAILED_FORCE_CLOSE_FAILED',
				channelId,
				message: `channel failed (${reason}); unable to force-close: ${result.error}`,
				timestamp: Date.now()
			} as ILightningError);
			this.emitStructuredLog('channel', 'errored_force_close_failed', {
				channelId: channelId.toString('hex'),
				reason,
				error: result.error
			});
			return;
		}
		this.emit('node:error', {
			code: 'CHANNEL_FAILED_FORCE_CLOSED',
			channelId,
			message: `channel failed (${reason}); force-closing to resolve on chain`,
			timestamp: Date.now()
		} as ILightningError);
		this.emitStructuredLog('channel', 'errored_force_closing', {
			channelId: channelId.toString('hex'),
			reason
		});
	}

	/**
	 * The issue-#413 gate for automatically closing a v1 channel on chain:
	 * the channel's own persisted local evidence, OR the opener carve-out -
	 * WE staged this funding tx and the backend ACCEPTED it at least once
	 * (retryPendingFundingBroadcasts keeps pushing it every block), so the
	 * outpoint is ours to create and a commitment on top of the mempool
	 * parent is a legitimate exit. Covers the zero-conf opener, whose ready
	 * flags carry no chain evidence. Authorization alone is NOT enough: it
	 * only means we decided to broadcast, and the handoff may have failed.
	 * Process-local by design: channel state must never BE the broadcast
	 * evidence. 'candidate' and 'restored' entries answer false - the tx may
	 * never have left this process.
	 */
	private fundingKnownOnChain(channel: Channel, state: IChannelState): boolean {
		if (channel.isFundingKnownOnChain()) return true;
		const txidHex = state.fundingTxid!.toString('hex');
		const entry = this.pendingFundingTxs.get(txidHex);
		return entry?.phase === 'authorized' && entry.broadcastSucceeded === true;
	}

	/**
	 * The other shared guard every AUTOMATIC force-close path runs before
	 * broadcasting a commitment (issue #469): this channel was restored from a
	 * Recovery Capsule and no `channel_reestablish` has confirmed it against
	 * the peer yet, so our latest local commitment may be one the peer already
	 * holds a revocation for. Broadcasting it on our own initiative forfeits
	 * the whole balance to the justice path.
	 *
	 * Kept beside skipAutoCloseFundingNotOnChain rather than folded into it,
	 * because the two skips end differently: that one self-clears once the
	 * funding confirms, this one waits for the peer or for an operator.
	 * While it holds, the channel asks the peer to close instead
	 * (Channel.buildRecoveryCloseActions, regenerated on every reconnect), and
	 * forceCloseChannel stays ungated, which is 5.6's labelled escape hatch.
	 */
	private skipAutoCloseRestoreUnproven(
		state: IChannelState,
		context: string
	): boolean {
		if (state.restoreRecencyUnproven !== true) return false;
		this.emitStructuredLog('channel', 'close_skipped_restore_unproven', {
			channelId: (state.channelId ?? state.temporaryChannelId).toString('hex'),
			context
		});
		return true;
	}

	/**
	 * The shared guard every AUTOMATIC v1 force-close path runs before
	 * broadcasting a commitment (issue #413): a commitment spending an
	 * outpoint not known to exist cannot "close on chain" - the broadcast
	 * fails or hangs while the node reports a close that did not happen, and
	 * whatever the close was meant to claim cannot confirm without the
	 * parent either. Returns true when the close must be skipped; the caller
	 * leaves the channel as it is. fundingConfirmed stamps the confirmation
	 * durably when it arrives and the failure-resolution paths re-drive the
	 * close then. The operator API (forceCloseChannel) stays ungated: an
	 * explicit command may know better than we do.
	 */
	private skipAutoCloseFundingNotOnChain(
		channel: Channel,
		state: IChannelState,
		context: string
	): boolean {
		if (!state.fundingTxid) return false;
		if (
			state.fundingVersion === 2 &&
			!this.v2CloseNeedsFundingOnChain(channel, state)
		) {
			return false;
		}
		if (this.fundingKnownOnChain(channel, state)) return false;
		this.emitStructuredLog('channel', 'close_skipped_funding_not_on_chain', {
			channelId: (state.channelId ?? state.temporaryChannelId).toString('hex'),
			context
		});
		return true;
	}

	/**
	 * Whether a v2 open answers to the funding-on-chain guard above, which the
	 * v2 family was exempt from while handleChannelErrored removed these
	 * channels outright instead (issue #463).
	 *
	 * Only an open still short of channel_ready whose recorded attempt nobody
	 * can broadcast: that is the one shape whose commitment provably spends an
	 * outpoint that may never exist, and it is the shape now retained rather
	 * than voided, so the automatic closes need the same guard the removal
	 * used to make unnecessary. Everything else keeps the ungated v2
	 * behaviour, zero-conf channels in particular: isFundingKnownOnChain
	 * answers false for a trusted zero-conf peer by design (issue #413), so a
	 * broader test here would disarm every automatic exit a live zero-conf
	 * channel has.
	 */
	private v2CloseNeedsFundingOnChain(
		channel: Channel,
		state: IChannelState
	): boolean {
		return (
			state.v2InFlight != null &&
			!channel.isV2AttemptBroadcastable() &&
			!state.localChannelReady &&
			!state.remoteChannelReady
		);
	}

	/**
	 * Sanity-clamp an IFeeEstimator sample before it feeds any LN operation
	 * (see clampFeeRateSatPerVbyte), logging a structured warning when the
	 * estimator's value was actually adjusted.
	 */
	private clampEstimatedFeeRate(satPerVbyte: number): number {
		return clampFeeRateSatPerVbyte(satPerVbyte, (original, clamped) => {
			this.emitStructuredLog('fee', 'estimate_clamped', {
				original,
				clamped
			});
		});
	}

	/**
	 * Blocks before an inbound HTLC's cltv_expiry at which, if we hold its
	 * preimage but the off-chain fulfill has not been acked, we force-close the
	 * inbound channel to claim on-chain. Must leave enough room for our
	 * HTLC-success to confirm before the peer's HTLC-timeout becomes spendable at
	 * cltv_expiry (LDK-style CLTV_CLAIM_BUFFER).
	 */
	private static readonly INBOUND_HTLC_CLAIM_FORCE_CLOSE_BUFFER = 18;

	/**
	 * Scan all channels for received HTLCs that are close to expiry.
	 * Auto-fail any that are within the safety margin. Separately, force-close to
	 * claim any inbound HTLC we already hold the preimage for (or that is
	 * FULFILLED off-chain) whose counterparty may never ack the removal.
	 */
	private scanExpiringHtlcs(blockHeight: number): void {
		const claimBuffer = Math.max(
			LightningNode.INBOUND_HTLC_CLAIM_FORCE_CLOSE_BUFFER,
			this.htlcSafetyMargin
		);
		const channels = this.channelManager.listChannels();
		for (const channel of channels) {
			const state = channel.getFullState();
			const effectiveState = state.preReestablishState ?? state.state;
			// ERRORED is admitted for the on-chain claim backstop below: a failed
			// channel is exactly the one whose peer cannot be trusted to resolve an
			// HTLC we hold the preimage for, so disarming the backstop there is
			// backwards. markForReestablish never wraps ERRORED, so the literal
			// state is the whole story. dataLossDetected stays excluded: our
			// commitment is provably stale and broadcasting it forfeits the whole
			// balance to the justice path.
			const errored =
				state.state === ChannelState.ERRORED &&
				!mustNotBroadcastCommitment(state);
			if (effectiveState !== ChannelState.NORMAL && !errored) continue;

			for (const [key, htlc] of state.htlcs) {
				if (!key.startsWith('received-')) continue;

				// Backstop (HIGH-4): if we hold this inbound HTLC's preimage (either
				// it is already FULFILLED off-chain, and an adversarial upstream never
				// acks the removal, leaving it FULFILLED indefinitely, or we learned
				// the preimage from downstream), our only guaranteed way to collect the
				// funds is an on-chain HTLC-success. Failing it (below) would forfeit
				// value we can actually claim. Force-close the inbound channel while a
				// claim buffer remains before cltv_expiry, so our HTLC-success is the
				// only valid spend and the peer cannot win an HTLC-timeout race.
				const paymentHashHex = htlc.paymentHash?.toString('hex');
				// A parked hold-invoice HTLC whose preimage was never revealed must
				// be failed off-chain by the held-HTLC sweeper (same margin), not
				// force-closed to claim: claiming would settle a payment the
				// operator has not released.
				const parkedHold =
					htlc.state !== HtlcState.FULFILLED &&
					paymentHashHex !== undefined &&
					this.heldInvoiceHashes.has(paymentHashHex);
				const haveClaim =
					!parkedHold &&
					(htlc.state === HtlcState.FULFILLED ||
						(paymentHashHex !== undefined &&
							this.preimages.has(paymentHashHex)));
				if (haveClaim && htlc.cltvExpiry - blockHeight <= claimBuffer) {
					const channelId = state.channelId || state.temporaryChannelId;
					// Without the funding parent on chain the HTLC-success claim
					// cannot confirm either, so this close protects nothing
					// (issue #413).
					// Or the row's recency is unproven (issue #469): one HTLC's
					// value is a bounded loss, a revoked commitment is the whole
					// balance.
					if (
						this.skipAutoCloseRestoreUnproven(
							state,
							'HTLC_CLAIM_FORCE_CLOSE'
						) ||
						this.skipAutoCloseFundingNotOnChain(
							channel,
							state,
							'HTLC_CLAIM_FORCE_CLOSE'
						)
					) {
						continue;
					}
					this.emit('node:error', {
						code: 'HTLC_CLAIM_FORCE_CLOSE',
						channelId,
						message: `inbound HTLC ${htlc.id} preimage held but unacked ${claimBuffer} blocks before expiry (${htlc.cltvExpiry}); force-closing to claim via HTLC-success`,
						timestamp: Date.now()
					} as ILightningError);
					this._forceCloseWithReason(
						channelId,
						this.getSweepDestinationScript(),
						this.resolveForceCloseFeeRatePerVbyte(),
						'HTLC_CLAIM_FORCE_CLOSE'
					);
					break; // channel is closing; stop scanning it
				}

				if (
					htlc.state !== HtlcState.PENDING &&
					htlc.state !== HtlcState.COMMITTED
				)
					continue;

				// BOLT 2 forbids further updates once the channel has failed, so the
				// off-chain fail below is for operational channels only. An inbound
				// HTLC we cannot claim costs us nothing to leave: the upstream
				// refunds itself via its HTLC-timeout once the commitment confirms.
				if (errored) continue;

				// BOLT 2 quiescence: no update messages after stfu. The ChannelState
				// stays NORMAL through a quiescence handshake, so it must be asked
				// directly; the quiescence watchdog's disconnect is the spec's
				// remedy for an HTLC nearing its deadline during quiescence.
				if (channel.isQuiescing()) continue;

				if (htlc.cltvExpiry - blockHeight <= this.htlcSafetyMargin) {
					const channelId = state.channelId || state.temporaryChannelId;
					const htlcSecretKey = `${channelId.toString('hex')}:${htlc.id}`;
					const blindedRole = this.blindedRoleFor(channelId, htlc.id);
					if (blindedRole) {
						this.failBlindedIncomingHtlc(channelId, htlc.id, blindedRole);
						continue;
					}
					const htlcSharedSecret =
						this.receivedHtlcSharedSecrets.get(htlcSecretKey);
					const reason = htlcSharedSecret
						? createFailureMessage(
								htlcSharedSecret,
								EXPIRY_TOO_SOON,
								this.updateFlaggedFailureData(EXPIRY_TOO_SOON)
						  )
						: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
					this.cleanupHtlcSharedSecret(htlcSecretKey);
					this.channelManager.failHtlc(channelId, htlc.id, reason);
				}
			}
		}
	}

	/**
	 * Scan forwarded HTLCs whose incoming CLTV is dangerously close.
	 *
	 * BOLT 2 fund-safety: the upstream update_fail_htlc may only be sent once the
	 * OUTGOING leg is irrevocably resolved as failed. Failing the inbound leg on
	 * time alone while the outbound leg is still claimable lets the downstream
	 * settle its HTLC-success after we already refunded upstream, so we would refund
	 * A AND pay B. So when the deadline nears with the outbound leg unresolved we
	 * force-close the INBOUND channel (moving resolution on-chain, where our
	 * inbound HTLC-success/timeout is the authoritative spend) and RETAIN the
	 * forward mapping until final resolution, instead of failing off-chain.
	 */
	private scanForwardTimeouts(blockHeight: number): void {
		const doubleMargin = this.htlcSafetyMargin * 2;
		const channels = this.channelManager.listChannels();

		for (const channel of channels) {
			const state = channel.getFullState();
			// ERRORED is admitted for the force-close path only: no further updates
			// are allowed on a failed channel, so on-chain is the sole way to
			// resolve a forwarded HTLC stuck on it. dataLossDetected must never
			// broadcast; the peer's commitment resolves those channels.
			const errored =
				state.state === ChannelState.ERRORED &&
				!mustNotBroadcastCommitment(state);
			if (state.state !== ChannelState.NORMAL && !errored) continue;
			const channelId = state.channelId || state.temporaryChannelId;

			for (const [key, htlc] of state.htlcs) {
				if (!key.startsWith('received-')) continue;
				if (
					htlc.state !== HtlcState.PENDING &&
					htlc.state !== HtlcState.COMMITTED
				)
					continue;

				// Check if this is a forwarded HTLC (has an outgoing leg)
				const outKey = this.findOutgoingLeg(channelId, htlc.id);
				if (!outKey) continue;

				if (htlc.cltvExpiry - blockHeight > doubleMargin) continue;

				// Determine the outgoing leg's resolution state. outKey encodes the
				// outgoing channel + the offered HTLC id we sent downstream.
				const outParts = outKey.split(':');
				const outChannelIdHex = outParts[0];
				const outHtlcIdStr = outParts[1]?.replace('offered-', '');
				let outgoingFailed = false;
				if (outChannelIdHex && outHtlcIdStr) {
					const outChannel = this.channelManager.getChannel(
						Buffer.from(outChannelIdHex, 'hex')
					);
					const outHtlc = outChannel
						?.getFullState()
						.htlcs.get(`offered-${outHtlcIdStr}`);
					// Only an explicitly FAILED outgoing HTLC is safe to refund upstream
					// for: we owe the downstream nothing. Anything else (still in-flight,
					// FULFILLED, or already removed/ambiguous) means the downstream can
					// still legitimately claim, so refunding upstream would double-pay.
					outgoingFailed = outHtlc?.state === HtlcState.FAILED;
				}

				// An errored inbound channel cannot carry the update_fail_htlc even
				// when the outbound leg failed cleanly, so it always takes the
				// force-close path below.
				if (outgoingFailed && !errored) {
					// Safe: complete the failure upstream off-chain.
					const htlcSecretKey = `${channelId.toString('hex')}:${htlc.id}`;
					const blindedRole = this.blindedRoleFor(channelId, htlc.id);
					if (blindedRole) {
						this.failBlindedIncomingHtlc(channelId, htlc.id, blindedRole);
						this.forwardedHtlcs.delete(outKey);
						continue;
					}
					const sharedSecret =
						this.receivedHtlcSharedSecrets.get(htlcSecretKey);
					const reason = sharedSecret
						? createFailureMessage(
								sharedSecret,
								EXPIRY_TOO_SOON,
								this.updateFlaggedFailureData(EXPIRY_TOO_SOON)
						  )
						: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
					this.cleanupHtlcSharedSecret(htlcSecretKey);
					this.channelManager.failHtlc(channelId, htlc.id, reason);
					this.forwardedHtlcs.delete(outKey);
					continue;
				}

				// Outbound unresolved: never fail upstream on time alone. Force-close
				// the inbound channel so resolution moves on-chain, and keep the forward
				// mapping so a late downstream settlement can still be honored.
				// Unless the funding parent is not known on chain, in which case
				// nothing built on it can resolve anything (issue #413).
				// Or the row's recency is unproven (issue #469).
				if (
					this.skipAutoCloseRestoreUnproven(
						state,
						'FORWARD_TIMEOUT_FORCE_CLOSE'
					) ||
					this.skipAutoCloseFundingNotOnChain(
						channel,
						state,
						'FORWARD_TIMEOUT_FORCE_CLOSE'
					)
				) {
					continue;
				}
				this.emit('node:error', {
					code: 'FORWARD_TIMEOUT_FORCE_CLOSE',
					channelId,
					message: `forwarded HTLC ${htlc.id} inbound expiry near (${htlc.cltvExpiry}) with outbound leg unresolved; force-closing inbound to resolve on-chain`,
					timestamp: Date.now()
				} as ILightningError);
				this._forceCloseWithReason(
					channelId,
					this.getSweepDestinationScript(),
					this.resolveForceCloseFeeRatePerVbyte(),
					'FORWARD_TIMEOUT_FORCE_CLOSE'
				);
				break; // channel is closing; stop scanning it
			}
		}
	}

	/**
	 * Find the outgoing leg key for a forwarded HTLC given its incoming channel+htlcId.
	 */
	private findOutgoingLeg(
		inChannelId: Buffer,
		inHtlcId: bigint
	): string | null {
		const inChannelIdHex = inChannelId.toString('hex');
		for (const [outKey, { inChannelId: fwdInId, inHtlcId: fwdInHtlcId }] of this
			.forwardedHtlcs) {
			if (
				fwdInId.toString('hex') === inChannelIdHex &&
				fwdInHtlcId === inHtlcId
			) {
				return outKey;
			}
		}
		return null;
	}

	/**
	 * Count total in-flight HTLCs across all channels.
	 */
	getTotalInFlightHtlcCount(): number {
		let count = 0;
		const channels = this.channelManager.listChannels();
		for (const channel of channels) {
			const state = channel.getFullState();
			for (const [, htlc] of state.htlcs) {
				if (
					htlc.state === HtlcState.PENDING ||
					htlc.state === HtlcState.COMMITTED
				) {
					count++;
				}
			}
		}
		return count;
	}

	// ─────────────── Static Factories ───────────────

	/**
	 * Create a LightningNode from a BIP39 mnemonic.
	 * Derives all necessary keys automatically.
	 */
	static fromMnemonic(
		mnemonic: string,
		options?: {
			passphrase?: string;
			coinType?: number;
			network?: Network;
			storage?: IStorageBackend;
			enableNetworking?: boolean;
			localFeatures?: FeatureFlags;
			chainHashes?: Buffer[];
			alias?: string;
			announcedAddresses?: INodeAddress[];
			fundingProvider?: IFundingProvider;
			feeEstimator?: IFeeEstimator;
			logger?: ILogger;
			socks5Proxy?: { host: string; port: number };
			webSocketImpl?: import('../transport/websocket').WebSocketConstructor;
			preferAnchors?: boolean;
			largeChannels?: boolean;
			chainBackend?: import('../chain/chain-watcher').IChainBackend;
			autoReconnect?: boolean;
			autoUpdateChannelFees?: boolean;
			forwardingEnabled?: boolean;
			forwardingFeeBaseMsat?: number;
			forwardingFeePropMillionths?: number;
			forwardingCltvDelta?: number;
			leaseRates?: import('../gossip/types').ILeaseRates;
			eagerGossipVerify?: boolean;
			sweepDestinationScript?: Buffer;
			peerStorageEnabled?: boolean;
			autoRebalance?: IAutoRebalanceConfig;
			autoTuneFees?: IAutoTuneFeesConfig;
			watchtowers?: string[];
			recovery?: INodeConfig['recovery'];
			channelKeyDeriver?: (
				channelIndex: number
			) => import('../channel/channel-manager').IPerChannelKeys;
		}
	): LightningNode {
		const coinType = options?.coinType ?? LnCoinType.REGTEST;
		const keys = deriveLightningKeysFromMnemonic(
			mnemonic,
			options?.passphrase,
			coinType
		);

		// Build per-channel key deriver from BIP32 root (unless caller provides one)
		let channelKeyDeriver = options?.channelKeyDeriver;
		if (!channelKeyDeriver) {
			const seed = bip39.mnemonicToSeedSync(mnemonic, options?.passphrase);
			const BIP32Factory = bip32Lib.BIP32Factory(ecc);
			const root = BIP32Factory.fromSeed(seed);
			channelKeyDeriver = (
				channelIndex: number
			): ReturnType<NonNullable<INodeConfig['channelKeyDeriver']>> => {
				const ck = deriveChannelKeys(root, coinType, channelIndex);
				return {
					fundingPrivkey: ck.fundingPrivkey,
					basepoints: ck.channelBasepoints,
					perCommitmentSeed: ck.perCommitmentSeed,
					htlcBasepointSecret: ck.htlcBasepointSecret,
					revocationBasepointSecret: ck.revocationBasepointSecret,
					paymentBasepointSecret: ck.paymentBasepointSecret,
					delayedPaymentBasepointSecret: ck.delayedPaymentBasepointSecret
				};
			};
		}

		return new LightningNode({
			nodePrivateKey: keys.nodePrivateKey,
			channelBasepoints: keys.channelBasepoints,
			perCommitmentSeed: keys.perCommitmentSeed,
			fundingPrivkey: keys.fundingPrivkey,
			htlcBasepointSecret: keys.htlcBasepointSecret,
			revocationBasepointSecret: keys.revocationBasepointSecret,
			paymentBasepointSecret: keys.paymentBasepointSecret,
			delayedPaymentBasepointSecret: keys.delayedPaymentBasepointSecret,
			network: options?.network,
			storage: options?.storage,
			enableNetworking: options?.enableNetworking,
			autoReconnect: options?.autoReconnect,
			autoUpdateChannelFees: options?.autoUpdateChannelFees,
			forwardingEnabled: options?.forwardingEnabled,
			forwardingFeeBaseMsat: options?.forwardingFeeBaseMsat,
			forwardingFeePropMillionths: options?.forwardingFeePropMillionths,
			forwardingCltvDelta: options?.forwardingCltvDelta,
			leaseRates: options?.leaseRates,
			eagerGossipVerify: options?.eagerGossipVerify,
			localFeatures: options?.localFeatures,
			chainHashes: options?.chainHashes,
			alias: options?.alias,
			announcedAddresses: options?.announcedAddresses,
			fundingProvider: options?.fundingProvider,
			feeEstimator: options?.feeEstimator,
			logger: options?.logger,
			socks5Proxy: options?.socks5Proxy,
			webSocketImpl: options?.webSocketImpl,
			preferAnchors: options?.preferAnchors,
			largeChannels: options?.largeChannels,
			chainBackend: options?.chainBackend,
			sweepDestinationScript: options?.sweepDestinationScript,
			peerStorageEnabled: options?.peerStorageEnabled,
			autoRebalance: options?.autoRebalance,
			autoTuneFees: options?.autoTuneFees,
			watchtowers: options?.watchtowers,
			recovery: options?.recovery,
			channelKeyDeriver
		});
	}

	/**
	 * Build the default feature flags for a LightningNode.
	 * Includes static_remotekey (optional) and other standard features.
	 */
	static defaultFeatures(): FeatureFlags {
		const flags = FeatureFlags.empty();
		flags.setOptional(Feature.DATA_LOSS_PROTECT);
		flags.setOptional(Feature.GOSSIP_QUERIES);
		flags.setCompulsory(Feature.TLV_ONION);
		flags.setOptional(Feature.STATIC_REMOTE_KEY);
		flags.setCompulsory(Feature.PAYMENT_SECRET);
		flags.setOptional(Feature.BASIC_MPP);
		flags.setOptional(Feature.ONION_MESSAGES);
		flags.setOptional(Feature.CHANNEL_TYPE);
		flags.setOptional(Feature.SCID_ALIAS);
		flags.setOptional(Feature.KEYSEND);
		flags.setOptional(Feature.QUIESCE);
		flags.setOptional(Feature.SPLICE);
		// Anchors are the default channel type (LND/CLN/Eclair all default to them).
		// Advertised so peers may propose anchor channels and so we negotiate them.
		flags.setOptional(Feature.ANCHOR_ZERO_FEE_HTLC);
		// Simplified mutual close + its BOLT 9 dependency. We already accept any
		// segwit shutdown script (isValidShutdownScript is always called with
		// allowAnySegwit), so advertising anysegwit only states existing behavior.
		flags.setOptional(Feature.SHUTDOWN_ANY_SEGWIT);
		flags.setOptional(Feature.SIMPLE_CLOSE);
		// Dual-funded (v2) channel establishment: both the open_channel2 initiator
		// and acceptor paths are implemented and interop-validated.
		flags.setOptional(Feature.DUAL_FUND);
		// Zero-conf support. Advertising the bit only signals capability: a
		// zero_conf channel_type is still rejected, and minimum_depth stays
		// non-zero, unless the peer is in the trusted set (ZeroConfManager).
		flags.setOptional(Feature.ZERO_CONF);
		// Peer storage (BOLT 1): we hold one small blob per channel/trusted peer
		// and return it on reconnect, enabling peers to recover their static
		// channel backup from us (and vice versa). Gated by peerStorageEnabled;
		// the constructor clears the bit when that config flag is false.
		flags.setOptional(Feature.PROVIDE_STORAGE);
		// LARGE_CHANNELS (18) is not set here but the constructor sets it by
		// default (largeChannels defaults to true), so it is advertised unless
		// opted out; the > 2^24 cap is still only lifted with a wumbo peer.
		//
		// Defined in Feature but intentionally not advertised by default:
		//  - ANCHOR_OUTPUTS (20): legacy anchors, superseded by bit 22 above.
		//  - GOSSIP_QUERIES_EX (10): extended queries not implemented.
		//  - UPFRONT_SHUTDOWN_SCRIPT (4): parsed from channel-open messages but
		//    not enforced, so the bit is not advertised.
		//  - OPTION_WILL_FUND (112): liquidity ads negotiate via open_channel2
		//    TLVs when liquidity rates are configured; init-bit advertising is a
		//    separate decision.
		//  - ROUTE_BLINDING (24): advertised per-invoice (see invoiceFeatures),
		//    not in the init set.
		//  - OPTION_TAPROOT (180/181): negotiated via channel_type when
		//    preferTaproot is set; staging bits are not init-advertised.
		return flags;
	}

	// ─────────────── Onion Messages ───────────────

	/**
	 * Send an onion message to a destination node.
	 */
	sendOnionMessage(
		destination: Buffer,
		messageData: Map<number, Buffer>,
		options?: ISendOnionMessageOptions
	): void {
		this.onionMessageManager.sendOnionMessage(
			destination,
			messageData,
			options
		);
	}

	/**
	 * Send a route-blinded onion message through intermediate forwarding nodes
	 * (BOLT 4: the sphinx layer is addressed to blinded node ids; each
	 * intermediate learns only its next hop).
	 */
	sendMultiHopOnionMessage(
		intermediateNodes: Buffer[],
		destination: Buffer,
		messageData: Map<number, Buffer>,
		options?: ISendOnionMessageOptions
	): void {
		this.onionMessageManager.sendMultiHopOnionMessage(
			intermediateNodes,
			destination,
			messageData,
			options
		);
	}

	/**
	 * Get the OnionMessageManager for direct access.
	 */
	getOnionMessageManager(): OnionMessageManager {
		return this.onionMessageManager;
	}

	private wireOnionMessageEvents(): void {
		this.onionMessageManager.on(
			'message:received',
			(_fromPeer: string, payload: IOnionMessagePayload) => {
				this.emit('onion:received', payload);
			}
		);
		this.onionMessageManager.on(
			'message:error',
			(_fromPeer: string, err: Error) => {
				this.emit('node:error', {
					code: 'ONION_MESSAGE_ERROR',
					message: err.message,
					timestamp: Date.now()
				} as ILightningError);
			}
		);
	}

	private registerCustomMessageHandler(): void {
		if (!this.peerManager) return;
		// Beignet-to-beignet custom traffic rides one odd type (issue #546);
		// route it through handlePeerMessage so it sits behind the same
		// startup-quarantine gate as every other inbound message (the
		// PeerManager inbound gate already dropped it at the transport when
		// the fence is up; this is the event-transport twin).
		this.peerManager.onMessage(
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			(pubkey, msgType, payload) => {
				this.handlePeerMessage(pubkey, msgType, payload);
			}
		);
	}

	private registerOnionMessageHandler(): void {
		if (!this.peerManager) return;

		// Wire the send function to PeerManager
		this.onionMessageManager.setSendFunction(
			(toPeer: string, type: number, payload: Buffer) => {
				if (this.peerManager) {
					try {
						this.peerManager.sendToPeer(toPeer, type, payload);
					} catch {
						// Peer may not be connected — silently ignore
					}
				}
			}
		);

		// Register handler for type 513 messages
		this.peerManager.onMessage(
			MessageType.ONION_MESSAGE,
			(pubkey, _type, payload) => {
				this.onionMessageManager.handleMessage(pubkey, payload);
			}
		);
	}

	// ─────────────── BOLT 12 Offers ───────────────

	/**
	 * Create a BOLT 12 offer.
	 *
	 * With `asyncHold`, the offer's blinded path is built through our always-online
	 * LSP (our channel peer) and the introduction hop is marked hold_htlc, so the
	 * LSP parks an inbound HTLC until we come online and release it (async
	 * receive). Caller-supplied `paths` take precedence over the auto-built one.
	 */
	createOffer(options: ICreateOfferOptions): {
		offer: IOffer;
		encoded: string;
	} {
		const createOpts = { ...options };
		// BOLT 12: an offer without offer_chains implies bitcoin MAINNET, so a
		// regtest/testnet node's offer read by a compliant payer fails with
		// "wrong chain" before anything else happens (observed live: CLN
		// refuses fetchinvoice on such an offer; issue #544 review's interop
		// gate found it). Stamp our chain whenever it is not the implied one.
		if (!createOpts.chains) {
			const ours = this.acceptableChainHashes[0] ?? this.chainHash();
			if (!ours.equals(BITCOIN_CHAIN_HASH)) {
				createOpts.chains = [ours];
			}
		}
		if (
			!createOpts.paths &&
			(createOpts.asyncHold || !this.hasPublishedPublicChannel())
		) {
			// One path_id shared by every path of this offer: invoice_requests
			// must arrive over one of them (verified in handleInvoiceRequest).
			// These are the offer's MESSAGE paths (next_node_id-addressed, no
			// payment records); the payment paths of each issued invoice are
			// rebuilt fresh at issuance (asyncHold is persisted with the offer
			// so that survives a restart). An UNANNOUNCED node builds them for
			// every offer, not just async ones: BOLT 12 requires a private
			// node's offer to carry reachable paths, because an external payer
			// cannot deliver an invoice_request to a node id that is in no
			// public graph (issue #544 review).
			const pathId = crypto.randomBytes(32);
			const paths = this.buildBlindedMessagePaths(
				createOpts.asyncHold ? 3 : 2,
				pathId
			);
			if (paths.length > 0) {
				createOpts.paths = paths;
				createOpts.pathId = pathId;
			}
		}
		return this.offerManager.createOffer(createOpts);
	}

	/**
	 * Request an invoice for a BOLT 12 offer.
	 * Sends an invoice_request via onion message and waits for the reply.
	 * @param timeoutMs Optional timeout (default: uses OfferManager's internal timeout)
	 */
	async requestInvoice(
		offer: IOffer,
		options?: {
			amount?: bigint;
			quantity?: bigint;
			payerNote?: string;
			chain?: Buffer;
			timeoutMs?: number;
		}
	): Promise<IBolt12Invoice> {
		const request = this.offerManager.requestInvoice(offer, options);
		if (options?.timeoutMs) {
			return Promise.race([
				request,
				new Promise<never>((_, reject) =>
					setTimeout(
						() =>
							reject(
								new Error(
									`BOLT 12 invoice request timed out after ${options.timeoutMs}ms`
								)
							),
						options.timeoutMs
					)
				)
			]);
		}
		return request;
	}

	/**
	 * Pay a BOLT 12 invoice by extracting payment info and delegating to sendPayment.
	 * This creates a BOLT 11-like payment flow using the BOLT 12 invoice details.
	 */
	payBolt12Invoice(
		invoice: IBolt12Invoice,
		excludedChannels?: Set<string>
	): IPaymentInfo {
		if (!invoice.paymentHash || !invoice.amount || !invoice.nodeId) {
			throw new Error('BOLT 12 invoice missing required fields');
		}

		// Payment deduplication, as in sendPayment: a second dispatch for a
		// hash still in flight would fight the first attempt's retry context
		// and in-flight record.
		const dedupHashHex = invoice.paymentHash.toString('hex');
		const existingPayment = this.payments.get(dedupHashHex);
		if (existingPayment && existingPayment.status === PaymentStatus.PENDING) {
			throw new LightningPaymentError(
				LightningErrorCode.DUPLICATE_PAYMENT,
				'Payment already in flight for this invoice'
			);
		}

		const destination = invoice.nodeId;
		const amountMsat = invoice.amount;
		const finalCltvExpiry = this.paddedFinalCltvExpiry();
		const sourceNodeId = getPublicKey(this.nodePrivkey);

		// Route blinding: BOLT 12 invoices natively carry blinded payment paths.
		// Route through one (shared blinded sender with the BOLT 11 path). Try
		// each advertised path in turn, skipping paths whose blinded segment
		// already failed: a retry re-enters here with the failed channels and
		// path indices excluded, so a path that is no longer usable rotates to
		// the invoice's other paths instead of failing the payment.
		if (invoice.paths && invoice.paths.length > 0) {
			const excludedPaths = this.paymentRetryContexts.get(
				invoice.paymentHash.toString('hex')
			)?.bolt12ExcludedPathIndices;
			let blindedRoute: IRoute | null = null;
			let pathIndex = 0;
			for (let i = 0; i < invoice.paths.length && !blindedRoute; i++) {
				if (excludedPaths?.has(i)) continue;
				const payInfo = invoice.blindedPayInfo?.[i] ?? {
					feeBaseMsat: 0,
					feeProportionalMillionths: 0,
					cltvExpiryDelta: 0,
					htlcMinimumMsat: 0n,
					htlcMaximumMsat: amountMsat
				};
				blindedRoute = findRouteToBlindedPath(
					this.graph,
					sourceNodeId,
					invoice.paths[i],
					payInfo,
					amountMsat,
					finalCltvExpiry,
					undefined,
					excludedChannels,
					this.missionControl,
					// Our own channels: a direct channel to the introduction node must
					// be routable even when it never entered the public gossip graph
					// (private channels; a fresh interop channel paying a CLN offer).
					this.getLocalChannelEdges()
				);
				// A self-introduction path is accepted by route construction as
				// the bare tail BEFORE its decryption, constraints or channel
				// resolution ran, so a locally unusable path would end the scan
				// here and abort the payment even when the invoice advertises
				// another usable path (issue #550 review). Validate now and
				// keep scanning on a typed local refusal.
				if (blindedRoute) {
					try {
						this.prepareSelfIntroSend(blindedRoute);
					} catch (err) {
						if (
							err instanceof LightningPaymentError &&
							(err.code === LightningErrorCode.NO_ROUTE ||
								err.code === LightningErrorCode.NO_CHANNEL_TO_HOP)
						) {
							blindedRoute = null;
							continue;
						}
						throw err;
					}
				}
				if (blindedRoute) pathIndex = i;
			}
			if (!blindedRoute) {
				throw new Error('No route to BOLT 12 blinded path introduction node');
			}
			return this.dispatchBolt12Route(
				blindedRoute,
				invoice,
				finalCltvExpiry,
				excludedChannels,
				pathIndex
			);
		}

		const route = findRoute(
			this.graph,
			sourceNodeId,
			destination,
			amountMsat,
			finalCltvExpiry,
			undefined,
			excludedChannels,
			this.missionControl,
			undefined,
			undefined,
			undefined,
			this.getLocalChannelEdges()
		);
		if (!route) {
			throw new Error('No route found to BOLT 12 invoice destination');
		}

		return this.dispatchBolt12Route(
			route,
			invoice,
			finalCltvExpiry,
			excludedChannels
		);
	}

	/**
	 * Register the retry context for a BOLT 12 dispatch and send along the
	 * route, so the failure handler can re-route a transient failure and the
	 * height-skew recovery applies exactly as it does to BOLT 11 and keysend
	 * payments. There is no invoice string to re-pay, so the context carries
	 * the decoded invoice and a retry re-enters payBolt12Invoice with the
	 * accumulated exclusions; the blinded path index used by this attempt is
	 * recorded so a failure inside the blinded segment can exclude the path.
	 *
	 * The context is registered only after a route was found, and a context
	 * created HERE is removed again when the dispatch fails locally (an
	 * exception, or addHtlc refusing the HTLC): a local failure never
	 * reaches the onion failure handler, so nothing else would clean it up
	 * and nothing can retry it. A pre-existing context is left alone; during
	 * a retry the failure handler owns its rollback and give-up behavior.
	 */
	private dispatchBolt12Route(
		route: IRoute,
		invoice: IBolt12Invoice,
		finalCltvExpiry: number,
		excludedChannels?: Set<string>,
		pathIndex?: number
	): IPaymentInfo {
		const hashHex = invoice.paymentHash.toString('hex');
		const created = !this.paymentRetryContexts.has(hashHex);
		if (created) {
			this.paymentRetryContexts.set(hashHex, {
				bolt12Invoice: invoice,
				excludedChannels: excludedChannels ?? new Set(),
				retryCount: 0,
				maxRetries: this.maxPaymentRetries
			});
		}
		const ctx = this.paymentRetryContexts.get(hashHex)!;
		ctx.bolt12PathIndex = pathIndex;
		try {
			const payment = this.sendPaymentToRoute(
				route,
				invoice.paymentHash,
				finalCltvExpiry,
				// BOLT 12 has no payment_secret: the blinded path's encrypted
				// path_id authenticates this payment at the recipient.
				undefined,
				invoice.amount
			);
			if (created && payment.status === PaymentStatus.FAILED) {
				this.paymentRetryContexts.delete(hashHex);
			}
			return payment;
		} catch (err) {
			if (created) this.paymentRetryContexts.delete(hashHex);
			throw err;
		}
	}

	/**
	 * Get the OfferManager for direct access.
	 */
	getOfferManager(): OfferManager {
		return this.offerManager;
	}

	private wireOfferManagerEvents(): void {
		this.offerManager.on('offer:created', (offer: IOffer) => {
			this.emit('offer:created', offer);
		});
		// A stored offer row that failed its integrity check or decode at
		// load: surfaced so corruption is visible instead of silently skipped.
		this.offerManager.on(
			'offer:corrupt',
			(info: { offerIdHex: string; reason: string }) => {
				this.emitStructuredLog('error', 'offer_corrupt_row', {
					offerId: info.offerIdHex,
					reason: info.reason
				});
			}
		);
		this.offerManager.on('invoice:received', (invoice: IBolt12Invoice) => {
			this.emit('bolt12:invoice:received', invoice);
		});
		// Issuer side: a BOLT 12 invoice we created in response to an invoice_request.
		// Register its preimage/amount into the SAME stores the BOLT 11 receive
		// path uses, so an incoming HTLC for this payment_hash is validated and
		// fulfilled (without this the preimage lived only in OfferManager and the
		// HTLC was failed with unknown_payment_hash). NO payment_secret is
		// registered: BOLT 12 defines no payment_secret TLV, so a secret minted
		// at issuance could never reach the payer, and enforcing one failed
		// every incoming HTLC for the invoice (#252). The blinded payment
		// path's path_id authenticates instead (checked in handleFinalHopHtlc
		// against OfferManager.getInvoicePathId).
		this.offerManager.on(
			'invoice:issued',
			(invoice: IBolt12Invoice, preimage: Buffer, pathId: Buffer) => {
				const hashHex = invoice.paymentHash.toString('hex');
				this.preimages.set(hashHex, preimage);
				// bolt12 marks the invoice for the receive path's FAIL-CLOSED
				// path_id check: a BOLT 12 invoice whose expected path_id is
				// missing is rejected, never fulfilled unauthenticated.
				const invoiceInfo: IInvoiceInfo = {
					paymentHash: hashHex,
					bolt11: '',
					amountMsat: invoice.amount,
					description: invoice.description,
					expiry: invoice.relativeExpiry ?? DEFAULT_EXPIRY,
					createdAt: Number(invoice.createdAt),
					bolt12: true
				};
				this.invoices.set(hashHex, invoiceInfo);
				// Track an INCOMING payment so the receive path emits payment:received
				// and getPayment() works — exactly as createInvoice does for BOLT 11.
				if (!this.payments.has(hashHex)) {
					this.payments.set(hashHex, {
						paymentHash: invoice.paymentHash,
						preimage,
						amountMsat: invoice.amount,
						status: PaymentStatus.PENDING,
						direction: PaymentDirection.INCOMING,
						createdAt: Date.now()
					});
				}
				this.persistInvoiceRecords(
					invoice.paymentHash,
					invoiceInfo,
					preimage,
					undefined,
					pathId
				);
				this.emit('bolt12:invoice:issued', invoice);
				// Issuance is remote-driven (any invoice_request mints one), so
				// the sweep must also run BETWEEN blocks: every 256th issuance
				// bounds the overshoot past the cap to 255 entries during a
				// flood while keeping the per-issuance cost amortized (#259).
				if (++this.issuedInvoiceSweepCounter % 256 === 0) {
					this.sweepExpiredIssuedInvoices();
				}
			}
		);
		this.offerManager.on('invoice:error', (error: { error: string }) => {
			this.emit('node:error', {
				code: 'BOLT12_INVOICE_ERROR',
				message: error.error,
				timestamp: Date.now()
			} as ILightningError);
		});
	}

	// ─────────────── Phase 2: HTLC Timeout + Payment Cleanup ───────────────

	/**
	 * Cap on issued-but-unpaid BOLT 12 invoices retained inside the expiry
	 * window (mirrors OfferManager's preimage bound). Past it the sweep
	 * evicts oldest-first down to 90% (hysteresis, so a sustained flood does
	 * not resweep on every issuance).
	 */
	private bolt12IssuedInvoiceCap = 10_000;
	/** Issuances since start; every 256th triggers a sweep between blocks. */
	private issuedInvoiceSweepCounter = 0;

	/**
	 * Sweep issued-but-unpaid BOLT 12 invoices whose expiry has passed.
	 *
	 * Every valid remote invoice_request mints an invoice whose preimage,
	 * invoice info, PENDING payment record (and, for legacy rows, payment
	 * secret) are copied into the node's receive stores and persisted, and
	 * nothing cleaned them up unless an HTLC actually arrived and resolved.
	 * Requests are remote-driven and free to send, so a single shared offer
	 * was a permanent memory AND database amplification target (#259).
	 *
	 * Removal is expiry-based: created_at + expiry plus a grace window for
	 * an HTLC in flight at expiry. The sweep never touches a hold invoice, a
	 * hash with a parked HTLC or a partially accumulated MPP set, or any
	 * payment record that is not a PENDING incoming placeholder, and it
	 * deletes the persisted rows of a batch in one transaction (preimage,
	 * legacy payment secret, path_id, invoice, payment). A hard cap
	 * backstops the unexpired window; evicting an entry only makes that
	 * invoice unpayable (the receive path fails closed), never
	 * unauthenticated. BOLT 11 invoices are NOT swept: they are
	 * operator-created and finite, and wallets expect them to stay
	 * queryable, matching LND/CLN retention.
	 */
	private sweepExpiredIssuedInvoices(): void {
		const nowSec = Math.floor(Date.now() / 1000);
		const expired: string[] = [];
		const unexpired: Array<{ hashHex: string; createdAt: number }> = [];
		for (const [hashHex, inv] of this.invoices) {
			if (!inv.bolt12) continue;
			if (inv.hold) continue;
			if (this.heldHtlcs.has(hashHex)) continue;
			if (this.pendingMppPayments.has(hashHex)) continue;
			// AFFIRMATIVE never-paid check: only the PENDING incoming
			// placeholder minted at issuance marks an invoice as never paid. A
			// MISSING record is not license to sweep: pruneCompletedPayments
			// drops settled payments (and their preimages) from MEMORY after
			// their TTL while the durable rows remain, so "no record" can mean
			// "paid, then pruned", and sweeping then would destroy the
			// persisted payment history and preimage of a settled payment.
			const payment = this.payments.get(hashHex);
			if (
				!payment ||
				payment.status !== PaymentStatus.PENDING ||
				payment.direction !== PaymentDirection.INCOMING
			) {
				continue;
			}
			if (
				nowSec >=
				inv.createdAt + inv.expiry + ISSUED_INVOICE_SWEEP_GRACE_SECONDS
			) {
				expired.push(hashHex);
			} else {
				unexpired.push({ hashHex, createdAt: inv.createdAt });
			}
		}

		// Copy before appending cap evictions: aliasing the expired array made
		// the telemetry below count evictions as expiries (capEvicted always 0).
		const expiredCount = expired.length;
		const toRemove = [...expired];
		if (unexpired.length > this.bolt12IssuedInvoiceCap) {
			const evictTo = Math.floor(this.bolt12IssuedInvoiceCap * 0.9);
			unexpired.sort((a, b) => a.createdAt - b.createdAt);
			const excess = unexpired.length - evictTo;
			for (let i = 0; i < excess; i++) {
				toRemove.push(unexpired[i].hashHex);
			}
		}
		if (toRemove.length === 0) return;

		// Durable rows FIRST: if the transaction fails, the in-memory copies
		// are kept too, so runtime and persisted state never diverge and the
		// next sweep retries the whole batch. All five deletes are REQUIRED
		// interface members (no optional chaining): a backend skipping
		// deletePreimage would leave an orphaned preimage row that a restart
		// restores WITHOUT the invoice's bolt12 marker or expected path_id,
		// making the hash claimable outside the fail-closed path check, and
		// one skipping deleteInvoicePathId would accumulate path_id rows
		// forever, the amplification this sweep exists to stop.
		if (this.storage) {
			const mutations: RecoveryMutation[] = [];
			for (const hashHex of toRemove) {
				mutations.push(
					{ type: 'delete_preimage', paymentHash: hashHex },
					{ type: 'delete_payment_secret', paymentHash: hashHex },
					{ type: 'delete_invoice_path_id', paymentHash: hashHex },
					{ type: 'delete_invoice', paymentHash: hashHex },
					{ type: 'delete_payment', paymentHash: hashHex }
				);
			}
			// SafetyCritical, and journaled: a restore that resurrected a swept
			// preimage would reopen the issued-unpaid amplification this sweep
			// exists to close.
			if (
				!this.commitMutations(
					'sweepExpiredIssuedInvoices',
					mutations,
					RecoveryCriticality.SafetyCritical
				)
			) {
				return;
			}
		}
		for (const hashHex of toRemove) {
			this.preimages.delete(hashHex);
			this.paymentSecrets.delete(hashHex);
			this.invoices.delete(hashHex);
			this.payments.delete(hashHex);
			this.offerManager.removeInvoiceState(hashHex);
		}
		this.emitStructuredLog('payment', 'issued_invoice_sweep', {
			removed: toRemove.length,
			expired: expiredCount,
			capEvicted: toRemove.length - expiredCount
		});
	}

	/**
	 * Scan offered HTLCs whose CLTV has expired at the current block height.
	 * Marks associated payments as FAILED and cleans up state.
	 */
	private scanExpiringOfferedHtlcs(blockHeight: number): void {
		const channels = this.channelManager.listChannels();
		for (const channel of channels) {
			const state = channel.getFullState();
			const effectiveState = state.preReestablishState ?? state.state;
			// ERRORED is admitted so the force-close backstop below still guards an
			// offered HTLC on a failed channel: the value is OURS, and the
			// downstream can claim it with the preimage whether or not the channel
			// is operational. dataLossDetected must never broadcast.
			const errored =
				state.state === ChannelState.ERRORED &&
				!mustNotBroadcastCommitment(state);
			if (effectiveState !== ChannelState.NORMAL && !errored) continue;
			const channelId = state.channelId || state.temporaryChannelId;

			for (const [key, htlc] of state.htlcs) {
				if (!key.startsWith('offered-')) continue;
				if (
					htlc.state !== HtlcState.PENDING &&
					htlc.state !== HtlcState.COMMITTED
				)
					continue;

				if (blockHeight >= htlc.cltvExpiry) {
					// Find associated payment
					const htlcKey = `${channelId.toString('hex')}:${key}`;
					const hashHex = this.htlcPaymentMap.get(htlcKey);
					if (hashHex) {
						this.failPayment(
							Buffer.from(hashHex, 'hex'),
							`HTLC timed out on-chain at block ${blockHeight} (cltv_expiry ${htlc.cltvExpiry})`
						);
					}
					// This is an OFFERED HTLC: we cannot fail it off-chain (only the
					// peer or on-chain resolution can remove it). The associated
					// outbound payment is marked failed above; the on-chain backstop
					// below force-closes to claim it via the timeout path. Calling
					// channelManager.failHtlc here (with the offered id) previously fell
					// through to the received-keyed path and canceled an unrelated
					// same-id inbound HTLC, refunding upstream while its downstream leg
					// could still settle.
				}

				// On-chain backstop: if the peer has not signed away an offered HTLC
				// well past its expiry, the downstream can still claim it with the
				// preimage while we hold nothing. Force-close to claim the HTLC via
				// the timeout path before that window closes. The grace period only
				// exists to give the off-chain fail a chance to complete; a failed
				// channel has no off-chain path, so waiting would just extend the
				// downstream's preimage-claim window for nothing.
				const graceBlocks = errored
					? 0
					: LightningNode.OFFERED_HTLC_FORCE_CLOSE_GRACE_BLOCKS;
				if (blockHeight >= htlc.cltvExpiry + graceBlocks) {
					// Without the funding parent on chain the timeout claim
					// cannot confirm and neither can the downstream's preimage
					// claim: the close protects nothing (issue #413).
					// Or the row's recency is unproven (issue #469).
					if (
						this.skipAutoCloseRestoreUnproven(
							state,
							'HTLC_EXPIRY_FORCE_CLOSE'
						) ||
						this.skipAutoCloseFundingNotOnChain(
							channel,
							state,
							'HTLC_EXPIRY_FORCE_CLOSE'
						)
					) {
						continue;
					}
					this.emit('node:error', {
						code: 'HTLC_EXPIRY_FORCE_CLOSE',
						channelId,
						message: `offered HTLC ${htlc.id} still active ${graceBlocks} blocks past expiry (${htlc.cltvExpiry}); force-closing to claim via timeout path`,
						timestamp: Date.now()
					} as ILightningError);
					this._forceCloseWithReason(
						channelId,
						this.getSweepDestinationScript(),
						this.resolveForceCloseFeeRatePerVbyte(),
						'HTLC_EXPIRY_FORCE_CLOSE'
					);
					break; // channel is closing; no further HTLC scanning on it
				}
			}
		}
	}

	/**
	 * Blocks past an offered HTLC's cltv_expiry after which an unresolved HTLC
	 * triggers a force-close (the off-chain fail was not accepted by the peer).
	 */
	private static readonly OFFERED_HTLC_FORCE_CLOSE_GRACE_BLOCKS = 6;

	/**
	 * Publicly fail a payment by its payment hash.
	 * Marks a PENDING payment as FAILED, persists, cleans up retry context, emits payment:failed.
	 */
	failPayment(paymentHash: Buffer, reason?: string): void {
		const hashHex = paymentHash.toString('hex');
		const payment = this.payments.get(hashHex);
		if (!payment || payment.status !== PaymentStatus.PENDING) return;

		payment.status = PaymentStatus.FAILED;
		payment.completedAt = Date.now();
		if (payment.failureCode === undefined) {
			payment.failureReason = reason ?? 'Payment failed locally';
		}
		this.paymentRetryContexts.delete(hashHex);
		this.outboundMppPayments.delete(hashHex);
		this.persistPayment(paymentHash);
		this.emit('payment:failed', payment);
		this.emitStructuredLog('payment', 'failed', {
			paymentHash: hashHex,
			amountMsat: Number(payment.amountMsat),
			status: payment.status,
			failureCode: payment.failureCode
		});
	}

	/**
	 * Scan for stuck PENDING outbound payments with no corresponding HTLC.
	 * Fails payments that have been PENDING for >10 minutes with no active HTLC.
	 */
	private scanStuckPayments(): void {
		const TEN_MINUTES = 10 * 60 * 1000;
		const now = Date.now();
		const channels = this.channelManager.listChannels();

		// Build set of all active offered HTLC payment hashes
		const activeHtlcHashes = new Set<string>();
		for (const channel of channels) {
			const state = channel.getFullState();
			const channelId = state.channelId || state.temporaryChannelId;
			for (const [key, htlc] of state.htlcs) {
				if (!key.startsWith('offered-')) continue;
				if (
					htlc.state !== HtlcState.PENDING &&
					htlc.state !== HtlcState.COMMITTED
				)
					continue;
				const htlcKey = `${channelId.toString('hex')}:${key}`;
				const hashHex = this.htlcPaymentMap.get(htlcKey);
				if (hashHex) activeHtlcHashes.add(hashHex);
			}
		}

		for (const [hashHex, payment] of this.payments) {
			if (payment.status !== PaymentStatus.PENDING) continue;
			if (payment.direction !== PaymentDirection.OUTGOING) continue;
			if (now - payment.createdAt < TEN_MINUTES) continue;
			if (activeHtlcHashes.has(hashHex)) continue;

			// No active HTLC and payment older than 10 min → fail
			this.failPayment(
				payment.paymentHash,
				'Stuck payment swept: no active HTLC after 10 minutes'
			);
		}
	}

	/**
	 * Scan for PENDING outbound payments whose invoice has expired. The
	 * expiry comes from the retry context's payment source: the decoded
	 * BOLT 11 invoice string, or the BOLT 12 invoice's created_at plus
	 * relative_expiry. A keysend has no invoice and therefore no expiry.
	 */
	private scanExpiredPendingPayments(): void {
		const now = Math.floor(Date.now() / 1000);
		for (const [hashHex, payment] of this.payments) {
			if (payment.status !== PaymentStatus.PENDING) continue;
			if (payment.direction !== PaymentDirection.OUTGOING) continue;

			const retryCtx = this.paymentRetryContexts.get(hashHex);
			if (!retryCtx) continue;

			let expiryTimestamp: number | undefined;
			if (retryCtx.bolt12Invoice) {
				expiryTimestamp =
					Number(retryCtx.bolt12Invoice.createdAt) +
					(retryCtx.bolt12Invoice.relativeExpiry ?? DEFAULT_EXPIRY);
			} else if (retryCtx.invoiceStr) {
				try {
					const { decode } = require('../invoice/decode');
					const decoded = decode(retryCtx.invoiceStr);
					expiryTimestamp = (decoded.timestamp || 0) + (decoded.expiry || 3600);
				} catch {
					// Can't decode invoice — skip
				}
			}
			if (expiryTimestamp !== undefined && now > expiryTimestamp) {
				this.failPayment(
					payment.paymentHash,
					'Invoice expired while the payment was still in flight'
				);
			}
		}
	}

	// ─────────────── Node Ready ───────────────

	/**
	 * Wait for the node to be fully operational (peers reconnected after crash recovery).
	 * Resolves immediately if already ready or no channels exist.
	 */
	waitForReady(timeoutMs = 30_000): Promise<void> {
		if (this._destroyed) return Promise.reject(new Error('Node destroyed'));
		if (this._readyEmitted) return Promise.resolve();

		// The startup repair quarantine outranks the fast paths: every
		// gate refuses traffic until the repair receipt lands, so a node in
		// that state is NOT ready no matter what its channel list says.
		if (!this.startupRepairPending) {
			// No channels at all → consider ready
			if (this.channelManager.listChannels().length === 0) {
				this.emitReady();
				return Promise.resolve();
			}

			// Already has NORMAL channels → consider ready
			const hasNormal = this.channelManager
				.listChannels()
				.some((ch) => ch.getState() === ChannelState.NORMAL);
			if (hasNormal) {
				this.emitReady();
				return Promise.resolve();
			}
		}

		return new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				reject(new Error(`Node did not become ready within ${timeoutMs}ms`));
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.removeListener('node:ready', onReady);
				this._activeWaitCleanups.delete(destroyCleanup);
			};

			const destroyCleanup = (): void => {
				cleanup();
				reject(new Error('Node destroyed'));
			};
			this._activeWaitCleanups.add(destroyCleanup);

			const onReady = (): void => {
				cleanup();
				resolve();
			};

			this.on('node:ready', onReady);
		});
	}

	// ─────────────── Phase 4: Agent Ergonomics ───────────────

	/**
	 * Send a payment and await completion or failure.
	 * Returns a Promise that resolves with the payment info on success,
	 * or rejects on failure or timeout.
	 */
	async sendPaymentAsync(
		invoiceStr: string,
		timeoutMs = 60_000,
		maxFeeMsat?: bigint,
		amountMsat?: bigint
	): Promise<IPaymentInfo> {
		const invoice = decodeInvoice(invoiceStr);
		const paymentHashHex = invoice.paymentHash.toString('hex');

		return new Promise<IPaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				this.failPayment(
					invoice.paymentHash,
					`No resolution within the ${timeoutMs}ms wait window`
				);
				reject(new Error(`Payment timed out after ${timeoutMs}ms`));
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.removeListener('payment:sent', onSent);
				this.removeListener('payment:failed', onFailed);
			};

			const onSent = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					resolve(info);
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					reject(
						new Error(
							`Payment failed${
								info.failureCode !== undefined
									? ` (code ${info.failureCode})`
									: ''
							}`
						)
					);
				}
			};

			this.on('payment:sent', onSent);
			this.on('payment:failed', onFailed);

			try {
				this.sendPayment(invoiceStr, undefined, maxFeeMsat, amountMsat);
			} catch (err: unknown) {
				cleanup();
				reject(err instanceof Error ? err : new Error(String(err)));
			}
		});
	}

	/**
	 * Wait for a channel to reach NORMAL state.
	 * Resolves immediately if already NORMAL. Rejects on timeout.
	 */
	async waitForChannelReady(
		channelId: Buffer,
		timeoutMs = 60_000
	): Promise<void> {
		if (this._destroyed) throw new Error('Node destroyed');

		// Check if already NORMAL
		const channel = this.channelManager.getChannel(channelId);
		if (channel && channel.getState() === ChannelState.NORMAL) {
			return;
		}

		const cidHex = channelId.toString('hex');
		return new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				reject(
					new Error(
						`Channel ${cidHex} did not become ready within ${timeoutMs}ms`
					)
				);
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.removeListener('channel:ready', onReady);
				this._activeWaitCleanups.delete(destroyCleanup);
			};

			const destroyCleanup = (): void => {
				cleanup();
				reject(new Error('Node destroyed'));
			};
			this._activeWaitCleanups.add(destroyCleanup);

			const onReady = (data: { channelId: Buffer }): void => {
				if (data.channelId.toString('hex') === cidHex) {
					cleanup();
					resolve();
				}
			};

			this.on('channel:ready', onReady);
		});
	}

	/**
	 * List all invoices created by this node.
	 */
	listInvoices(): IInvoiceInfo[] {
		return [...this.invoices.values()];
	}

	/**
	 * Get a specific invoice by payment hash (hex).
	 */
	getInvoice(paymentHashHex: string): IInvoiceInfo | null {
		return this.invoices.get(paymentHashHex) ?? null;
	}

	/**
	 * Wait for a payment identified by its payment hash (any direction).
	 * Resolves immediately if already settled. Rejects on failure.
	 */
	waitForPayment(
		paymentHash: Buffer,
		timeoutMs = 60_000
	): Promise<IPaymentInfo> {
		if (this._destroyed) return Promise.reject(new Error('Node destroyed'));

		const hashHex = paymentHash.toString('hex');

		// Check if already completed (any direction)
		const existing = this.payments.get(hashHex);
		if (existing) {
			if (existing.status === PaymentStatus.COMPLETED) {
				return Promise.resolve(existing);
			}
			if (existing.status === PaymentStatus.FAILED) {
				return Promise.reject(
					new Error(
						`Payment already failed${
							existing.failureCode !== undefined
								? ` (code ${existing.failureCode})`
								: ''
						}`
					)
				);
			}
		}

		return new Promise<IPaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				reject(new Error(`waitForPayment timed out after ${timeoutMs}ms`));
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.removeListener('payment:received', onPayment);
				this.removeListener('payment:sent', onPayment);
				this.removeListener('payment:failed', onFailed);
				this._activeWaitCleanups.delete(destroyCleanup);
			};

			const destroyCleanup = (): void => {
				cleanup();
				reject(new Error('Node destroyed'));
			};
			this._activeWaitCleanups.add(destroyCleanup);

			const onPayment = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === hashHex) {
					cleanup();
					resolve(info);
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === hashHex) {
					cleanup();
					reject(
						new Error(
							`Payment failed${
								info.failureCode !== undefined
									? ` (code ${info.failureCode})`
									: ''
							}`
						)
					);
				}
			};

			this.on('payment:received', onPayment);
			this.on('payment:sent', onPayment);
			this.on('payment:failed', onFailed);
		});
	}

	/**
	 * Get aggregate balance across all NORMAL channels.
	 */
	getBalance(): ILightningBalance {
		let localBalanceMsat = 0n;
		let remoteBalanceMsat = 0n;
		let unsettledBalanceMsat = 0n;

		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			// Accounting classifies by EFFECTIVE state: the splice's accounting
			// phase survives a disconnect (AWAITING_REESTABLISH wrapping
			// SPLICING), or a splice-out would bounce back to its full
			// pre-splice balance the moment the peer drops and double-count
			// against the on-chain side. Routing keeps strict acceptsNewHtlcs().
			const effState =
				state.state === ChannelState.AWAITING_REESTABLISH
					? state.preReestablishState ?? state.state
					: state.state;
			if (effState === ChannelState.SPLICING) {
				// Pay-through splices count at the conservative side of their two
				// fundings — a splice-out's balance is already committed to
				// leave; a splice-in's arriving sats sit in the splicing bucket
				// until the lock. Parked splices (taproot, pre point-of-no-return)
				// live entirely in the bucket.
				if (!channel.isHtlcUsable(true)) continue;
				const pending =
					channel.getPendingSpliceLocalBalanceMsat() ?? state.localBalanceMsat;
				localBalanceMsat +=
					pending < state.localBalanceMsat ? pending : state.localBalanceMsat;
			} else if (
				state.state !== ChannelState.NORMAL &&
				state.state !== ChannelState.AWAITING_REESTABLISH
			) {
				continue;
			} else {
				localBalanceMsat += state.localBalanceMsat;
			}
			remoteBalanceMsat += state.remoteBalanceMsat;
			for (const [, htlc] of state.htlcs) {
				if (
					htlc.state === HtlcState.PENDING ||
					htlc.state === HtlcState.COMMITTED
				) {
					unsettledBalanceMsat += htlc.amountMsat;
				}
			}
		}

		return { localBalanceMsat, remoteBalanceMsat, unsettledBalanceMsat };
	}

	// ─────────────── Phase 6: Timeout Safety Nets ───────────────

	/**
	 * Scan for channels stuck in intermediate states for too long.
	 * AWAITING_FUNDING_CONFIRMED > 2016 blocks → abandon channel
	 * SHUTTING_DOWN/NEGOTIATING_CLOSING > 1 hour (converted to blocks ~6/hr) → force-close
	 * ERRORED with a funded channel > reestablishTimeoutBlocks → force-close
	 */
	private scanStuckChannels(blockHeight: number): void {
		const channels = this.channelManager.listChannels();
		for (const channel of channels) {
			const state = channel.getFullState();
			const channelId = state.channelId || state.temporaryChannelId;

			// The never-broadcast invariant (recovery 5.6): proven stale or
			// unprovable, auto force-closing here would broadcast a possibly
			// revoked commitment and lose the whole balance to the justice
			// path. StateUncertain is permanent absent independently verified
			// storage provenance; only the peer's force close resolves the
			// channel. Never time it out.
			// (Channel.forceClose refuses too - this skip avoids even trying.)
			if (mustNotBroadcastCommitment(state)) {
				continue;
			}
			// Restored from a capsule and not yet confirmed against the peer
			// (issue #469). Covers every timeout backstop below: a timeout is
			// this node acting on its own initiative, which is exactly what a
			// row of unproven recency may not do.
			if (this.skipAutoCloseRestoreUnproven(state, 'stuck channel scan')) {
				continue;
			}

			const effectiveState =
				state.state === ChannelState.AWAITING_REESTABLISH
					? state.preReestablishState || state.state
					: state.state;
			if (effectiveState === ChannelState.AWAITING_FUNDING_CONFIRMED) {
				// Stamp broadcast height on first observation (lazy init for channels created before this field)
				if (state.fundingBroadcastHeight === 0 && blockHeight > 0) {
					state.fundingBroadcastHeight = blockHeight;
				}
				// If channel has been waiting for funding confirmation for > 2016 blocks
				if (
					state.fundingBroadcastHeight > 0 &&
					blockHeight - state.fundingBroadcastHeight > 2016
				) {
					this.emit('node:error', {
						code: 'STUCK_CHANNEL',
						channelId,
						message: `Channel ${channelId.toString(
							'hex'
						)} stuck in AWAITING_FUNDING_CONFIRMED for > 2016 blocks`,
						timestamp: Date.now()
					} as ILightningError);
				}
			}

			// Auto-force-close channels stuck in AWAITING_REESTABLISH for too long.
			// The tracker must measure CONTIGUOUS blocks in the state: a successful
			// reestablish of an established channel emits no channel:ready (that
			// only fires at initial establishment), so the entry stamped during an
			// earlier disconnect survives the reconnect. Without the else-cleanup
			// below, once that stale entry is reestablishTimeoutBlocks old, the
			// next transient disconnect is force-closed on the very next block.
			const reestablishKey = `reestablish:${channelId.toString('hex')}`;
			if (state.state !== ChannelState.AWAITING_REESTABLISH) {
				this._stuckChannelTracker.delete(reestablishKey);
			} else {
				if (!this._stuckChannelTracker.has(reestablishKey)) {
					this._stuckChannelTracker.set(reestablishKey, blockHeight);
				} else {
					const startHeight = this._stuckChannelTracker.get(reestablishKey)!;
					if (
						blockHeight - startHeight > this.reestablishTimeoutBlocks &&
						// Issue #413: a vanished peer whose funding never reached
						// the chain has nothing to close on. The tracker stays
						// armed; the close fires once the funding is known, and
						// the funding-missing clock retires the channel if not.
						!this.skipAutoCloseFundingNotOnChain(
							channel,
							state,
							'REESTABLISH_TIMEOUT_FORCE_CLOSED'
						)
					) {
						try {
							const destScript = bitcoin.payments.p2wpkh({
								pubkey: this.fundingPubkey
							}).output!;
							this._forceCloseWithReason(
								channelId,
								destScript,
								this.resolveForceCloseFeeRatePerVbyte(),
								'REESTABLISH_TIMEOUT_FORCE_CLOSED'
							);
							this._stuckChannelTracker.delete(reestablishKey);
							this.emit('node:error', {
								code: 'REESTABLISH_TIMEOUT_FORCE_CLOSED',
								channelId,
								message: `Channel ${channelId.toString(
									'hex'
								)} stuck in AWAITING_REESTABLISH for > ${
									this.reestablishTimeoutBlocks
								} blocks, force-closing`,
								timestamp: Date.now()
							} as ILightningError);
						} catch {
							// Ignore force-close errors
						}
					}
				}
			}

			// A failed (ERRORED) channel: markErrored leaves resolution to the
			// peer's force-close, but nothing guarantees the peer ever broadcasts
			// (LND's ErrRecoveryError, for one, waits for US to close). Give it the
			// same patience as a vanished peer, then broadcast our commitment to
			// recover the funds. dataLossDetected never reaches here (skipped at the
			// top), and a channel that died before funding broadcast has nothing on
			// chain to close. HTLC-bearing errored channels are handled sooner by
			// the HTLC scanners; this is the catch-all for the quiet ones.
			const erroredKey = `errored:${channelId.toString('hex')}`;
			if (state.state !== ChannelState.ERRORED) {
				// Same contiguity rule as the reestablish tracker above.
				this._stuckChannelTracker.delete(erroredKey);
			} else if (state.fundingTxid) {
				if (!this._stuckChannelTracker.has(erroredKey)) {
					this._stuckChannelTracker.set(erroredKey, blockHeight);
				} else {
					const startHeight = this._stuckChannelTracker.get(erroredKey)!;
					if (blockHeight - startHeight > this.reestablishTimeoutBlocks) {
						if (
							this.skipAutoCloseFundingNotOnChain(
								channel,
								state,
								'errored timeout backstop'
							)
						) {
							// Issue #413: the timeout has served but the close
							// cannot happen yet. KEEP the tracker: the close
							// fires on the first block after the funding is
							// known on chain; if it never appears, the
							// funding-missing clock (FUNDING_FORGET_BLOCKS)
							// retires the channel instead.
						} else {
							try {
								this._forceCloseWithReason(
									channelId,
									this.getSweepDestinationScript(),
									this.resolveForceCloseFeeRatePerVbyte(),
									'ERRORED_TIMEOUT_FORCE_CLOSED'
								);
								this._stuckChannelTracker.delete(erroredKey);
								this.emit('node:error', {
									code: 'ERRORED_TIMEOUT_FORCE_CLOSED',
									channelId,
									message: `Channel ${channelId.toString(
										'hex'
									)} ERRORED for > ${
										this.reestablishTimeoutBlocks
									} blocks with no close from the peer; force-closing to recover funds`,
									timestamp: Date.now()
								} as ILightningError);
							} catch {
								// Ignore force-close errors
							}
						}
					}
				}
			}

			const shutdownKey = `stuck:${channelId.toString('hex')}`;
			if (
				effectiveState !== ChannelState.SHUTTING_DOWN &&
				effectiveState !== ChannelState.NEGOTIATING_CLOSING
			) {
				// Same contiguity rule as the reestablish tracker above.
				this._stuckChannelTracker.delete(shutdownKey);
			} else {
				// Approximate: if channel has been shutting down for > ~10 blocks (~1 hour)
				// We use a createdAt-based check since we don't have a shutdownStartBlock field
				// Use block height heuristic: if current height advanced by 10 from when we last saw this state
				if (!this._stuckChannelTracker.has(shutdownKey)) {
					this._stuckChannelTracker.set(shutdownKey, blockHeight);
				} else {
					const startHeight = this._stuckChannelTracker.get(shutdownKey)!;
					if (
						blockHeight - startHeight > 10 &&
						// Issue #413: no close without the funding on chain.
						!this.skipAutoCloseFundingNotOnChain(
							channel,
							state,
							'STUCK_CHANNEL_FORCE_CLOSED'
						)
					) {
						// Force close the stuck channel
						try {
							const destScript = bitcoin.payments.p2wpkh({
								pubkey: this.fundingPubkey
							}).output!;
							this._forceCloseWithReason(
								channelId,
								destScript,
								this.resolveForceCloseFeeRatePerVbyte(),
								'STUCK_CHANNEL_FORCE_CLOSED'
							);
							this._stuckChannelTracker.delete(shutdownKey);
							this.emit('node:error', {
								code: 'STUCK_CHANNEL_FORCE_CLOSED',
								channelId,
								message: `Channel ${channelId.toString('hex')} stuck in ${
									state.state
								} for > 10 blocks, force-closing`,
								timestamp: Date.now()
							} as ILightningError);
						} catch {
							// Ignore force-close errors
						}
					}
				}
			}
		}
	}

	// ─────────────── Helpers ───────────────

	/**
	 * Check if fee rate has changed significantly and send update_fee to all opener channels.
	 */
	private async checkAndUpdateFees(): Promise<void> {
		if (!this.feeEstimator) return;

		const satPerVbyte = this.clampEstimatedFeeRate(
			await this.feeEstimator.estimateFee(6)
		);
		if (satPerVbyte <= 0) return;

		this.feeAdvisor.recordSample(satPerVbyte);

		const newFeeratePerKw = Math.max(
			satPerVbyteToSatPerKw(satPerVbyte),
			MIN_FEERATE_PER_KW
		);

		// Only update if changed by more than 20%
		if (this.lastKnownFeeratePerKw > 0) {
			const ratio = newFeeratePerKw / this.lastKnownFeeratePerKw;
			if (ratio > 0.8 && ratio < 1.2) return;
		}

		this.lastKnownFeeratePerKw = newFeeratePerKw;

		// Send update_fee to all channels where we are the opener
		for (const channel of this.channelManager.listChannels()) {
			if (channel.getState() !== ChannelState.NORMAL) continue;
			const state = channel.getFullState();
			if (state.role !== ChannelRole.OPENER) continue;
			const channelId = state.channelId || state.temporaryChannelId;
			this.updateChannelFee(channelId, newFeeratePerKw);
		}
	}

	/**
	 * Prune stale gossip channels from both in-memory graph and storage.
	 */
	private pruneStaleGossipWithStorage(): void {
		const now = Math.floor(Date.now() / 1000);

		// Collect stale SCIDs before pruning from graph
		const staleScids: string[] = [];
		if (
			this.storage &&
			typeof this.storage.deleteGossipChannel === 'function'
		) {
			const channels = this.graph.getAllChannels();
			const cutoff = now - DEFAULT_PRUNE_MAX_AGE;
			for (const channel of channels) {
				const ts1 = channel.update1?.timestamp ?? 0;
				const ts2 = channel.update2?.timestamp ?? 0;
				const latest = Math.max(ts1, ts2);
				if (latest < cutoff) {
					staleScids.push(channel.shortChannelId.toString('hex'));
				}
			}
		}

		// Prune from in-memory graph
		this.graph.pruneStaleChannels(now);

		// Delete from storage
		if (
			this.storage &&
			typeof this.storage.deleteGossipChannel === 'function'
		) {
			for (const scidHex of staleScids) {
				try {
					this.storage.deleteGossipChannel!(scidHex);
				} catch {
					// best-effort
				}
			}
		}
	}

	private emitStructuredLog(
		category: IStructuredLog['category'],
		action: string,
		data: Record<string, unknown>
	): void {
		const log: IStructuredLog = {
			category,
			action,
			timestamp: Date.now(),
			data
		};
		this.emit('log', log);
		// Mirror to the injectable diagnostic logger (no-op unless configured).
		// The persisted action log below stays untouched and separate.
		this.logger.debug(`${category}:${action}`, data);
		// Persist to storage if available
		if (this.storage && typeof this.storage.saveActionLog === 'function') {
			try {
				this.storage.saveActionLog({
					category,
					action,
					timestamp: log.timestamp,
					data: JSON.stringify(data)
				});
			} catch {
				// best-effort persistence
			}
		}
	}

	getActionLog(options?: {
		category?: string;
		since?: number;
		limit?: number;
	}): IStructuredLog[] {
		if (!this.storage || typeof this.storage.loadActionLog !== 'function') {
			return [];
		}
		try {
			const rows = this.storage.loadActionLog(options);
			return rows.map((row) => ({
				category: row.category as IStructuredLog['category'],
				action: row.action,
				timestamp: row.timestamp,
				data: JSON.parse(row.data)
			}));
		} catch {
			return [];
		}
	}

	private cleanupHtlcSharedSecret(key: string): void {
		this.receivedHtlcSharedSecrets.delete(key);
		this.blindedIncomingHtlcs.delete(key);
		// Journaled, so a reconstruction does not resurrect the secret of an
		// HTLC that already resolved.
		this.commitMutations('deleteHtlcSharedSecret', [
			{ type: 'delete_htlc_shared_secret', key }
		]);
	}

	/**
	 * Resolve a route's first-hop SCID (real SCID or either side's alias) to one
	 * of OUR usable channels to that peer. Returns undefined when the SCID does
	 * not name a local channel -- callers then fall back to peer-based selection.
	 */
	/**
	 * Process OUR OWN introduction hop of a blinded route (issue #550), or
	 * return null when the route's first hop is not us-as-introduction.
	 *
	 * Mirrors the relaying forward's blinded-hop handling, checks included
	 * (issue #550 review): the encrypted_data must carry payment_relay and
	 * EXACTLY ONE of short_channel_id / next_node_id (BOLT 4); the onward
	 * channel resolves by SCID or, for a next_node_id path, by peer; and
	 * payment_constraints are enforced here the way the relay enforces them,
	 * because past this point no one else will on our behalf. The wire
	 * amount/CLTV apply the relay's ceiling inversion, so we never charge
	 * ourselves the introduction fee, and the returned wireRoute (sliced
	 * tail, adjusted totals) is what callers must store and check fee caps
	 * against. Throws LightningPaymentError (NO_ROUTE / NO_CHANNEL_TO_HOP)
	 * on an unusable path, which path-selection loops treat as "try the
	 * invoice's next path".
	 */
	private prepareSelfIntroSend(route: {
		hops: Array<{
			pubkey: Buffer;
			shortChannelId: Buffer;
			amountToForwardMsat: bigint;
			outgoingCltvValue: number;
			encryptedRecipientData?: Buffer;
			blindingPoint?: Buffer;
		}>;
		totalAmountMsat?: bigint;
		totalCltvDelta?: number;
		totalFeeMsat?: bigint;
	}): {
		wireRoute: {
			hops: typeof route.hops;
			totalAmountMsat: bigint;
			totalCltvDelta: number;
			totalFeeMsat: bigint;
		};
		outChannel: Channel;
		blindingPoint: Buffer;
		wireAmountMsat: bigint;
		wireCltvRel: number;
		introFeeMsat: bigint;
	} | null {
		const hops = route.hops;
		if (
			hops.length < 2 ||
			!hops[0].blindingPoint ||
			!hops[0].encryptedRecipientData ||
			!hops[0].pubkey.equals(getPublicKey(this.nodePrivkey))
		) {
			return null;
		}
		let hopData: IBlindedHopData;
		let nextBlindingKey: Buffer;
		try {
			({ hopData, nextBlindingKey } = processBlindedHop(
				hops[0].blindingPoint,
				this.nodePrivkey,
				hops[0].encryptedRecipientData
			));
		} catch {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'Cannot decrypt our own introduction hop of the blinded path'
			);
		}
		if (!hopData.paymentRelay) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'Our introduction hop carries no payment_relay'
			);
		}
		// BOLT 4: exactly one of short_channel_id / next_node_id per relay
		// hop. Both present is the malformed shape a relay rejects; neither
		// names no onward direction at all.
		if (hopData.shortChannelId && hopData.nextNodeId) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'Our introduction hop carries both short_channel_id and next_node_id'
			);
		}
		if (!hopData.shortChannelId && !hopData.nextNodeId) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'Our introduction hop names no onward channel'
			);
		}
		// The relay's ceiling inversion (BOLT 4): charging the proportional
		// fee on the incoming amount instead forwards a few msat short and
		// the downstream node fails the HTLC.
		const relay = hopData.paymentRelay;
		const inAmount = hops[0].amountToForwardMsat;
		const propPlusOne = 1_000_000n + BigInt(relay.feeProportionalMillionths);
		const outAmount =
			((inAmount - BigInt(relay.feeBaseMsat)) * 1_000_000n + propPlusOne - 1n) /
			propPlusOne;
		const outCltv = hops[0].outgoingCltvValue - relay.cltvExpiryDelta;
		if (outAmount <= 0n || outCltv <= 0) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_ROUTE,
				'Blinded path payment_relay leaves nothing to forward'
			);
		}
		// payment_constraints, enforced the way the relay enforces them
		// (issue #550 review): the notional incoming expiry must sit under
		// the path's absolute bound, and the amount over its minimum. An
		// expired path must fail HERE by name, not complete or die opaquely
		// downstream.
		const constraints = hopData.paymentConstraints;
		if (constraints) {
			const absIncomingCltv =
				hops[0].outgoingCltvValue + this.currentBlockHeight;
			if (absIncomingCltv > constraints.maxCltvExpiry) {
				throw new LightningPaymentError(
					LightningErrorCode.NO_ROUTE,
					'Blinded path expired: max_cltv_expiry is behind the required expiry'
				);
			}
			if (inAmount < constraints.htlcMinimumMsat) {
				throw new LightningPaymentError(
					LightningErrorCode.NO_ROUTE,
					'Amount below the blinded path htlc_minimum_msat'
				);
			}
		}
		const outChannel = hopData.shortChannelId
			? this.resolveLocalChannelByScid(hopData.shortChannelId)
			: this.findChannelForPeer(hopData.nextNodeId!.toString('hex'), outAmount);
		if (!outChannel) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_CHANNEL_TO_HOP,
				hopData.shortChannelId
					? `No usable channel for the blinded path's onward SCID ` +
					  hopData.shortChannelId.toString('hex')
					: `No usable channel to the blinded path's next node ` +
					  hopData.nextNodeId!.toString('hex')
			);
		}
		// The wire-true route: the onion starts at the SECOND blinded hop
		// (still encrypted to the blinded node ids; the peer derives its key
		// from the blinding point on the add). The hops' own fields stay
		// untouched, so the final payload keeps the recipient's exact amount
		// and CLTV; only the totals shed our introduction fee.
		const introFeeMsat = inAmount - outAmount;
		const totalFee = route.totalFeeMsat ?? 0n;
		return {
			wireRoute: {
				hops: hops.slice(1),
				totalAmountMsat: outAmount,
				totalCltvDelta: outCltv,
				totalFeeMsat: totalFee > introFeeMsat ? totalFee - introFeeMsat : 0n
			},
			outChannel,
			blindingPoint: nextBlindingKey,
			wireAmountMsat: outAmount,
			wireCltvRel: outCltv,
			introFeeMsat
		};
	}

	/**
	 * Resolve one of OUR usable channels by any SCID it answers to: the real
	 * SCID, our alias, or the alias the peer gave us. Peer-agnostic, for the
	 * self-introduction blinded send (issue #550), where the SCID comes out
	 * of our own decrypted hop and the next node is known only by its blinded
	 * id. Prefers the registered mapping, falls back to a channel scan so
	 * alias-only channels resolve too.
	 */
	private resolveLocalChannelByScid(scid: Buffer): Channel | undefined {
		const mapped = this.scidToChannelId.get(scid.toString('hex'));
		if (mapped) {
			const channel = this.channelManager.getChannel(mapped);
			if (channel && channel.acceptsNewHtlcs()) return channel;
		}
		for (const channel of this.channelManager.listChannels()) {
			if (!channel.acceptsNewHtlcs()) continue;
			const st = channel.getFullState();
			if (
				(st.shortChannelId && st.shortChannelId.equals(scid)) ||
				(st.scidAlias && st.scidAlias.equals(scid)) ||
				(st.remoteScidAlias && st.remoteScidAlias.equals(scid))
			) {
				return channel;
			}
		}
		return undefined;
	}

	private findLocalChannelByScid(
		scid: Buffer | undefined,
		peerPubkeyHex: string
	): Channel | undefined {
		if (!scid || scid.length === 0 || scid.equals(Buffer.alloc(scid.length))) {
			return undefined;
		}
		for (const channel of this.channelManager.getChannelsByPeer(
			peerPubkeyHex
		)) {
			if (!channel.acceptsNewHtlcs()) continue;
			const st = channel.getFullState();
			if (
				(st.shortChannelId && st.shortChannelId.equals(scid)) ||
				(st.scidAlias && st.scidAlias.equals(scid)) ||
				(st.remoteScidAlias && st.remoteScidAlias.equals(scid))
			) {
				return channel;
			}
		}
		return undefined;
	}

	private findChannelForPeer(
		peerPubkeyHex: string,
		amountMsat?: bigint
	): Channel | undefined {
		const channels = this.channelManager.getChannelsByPeer(peerPubkeyHex);
		const normalChannels = channels.filter((ch) => ch.acceptsNewHtlcs());

		if (normalChannels.length === 0) return undefined;
		if (normalChannels.length === 1) return normalChannels[0];

		// Rank by SPENDABLE outbound, not raw local balance: reserve, commit
		// fee and in-flight HTLCs can make the bigger-balance channel exactly
		// the one that refuses the HTLC (#254 review).
		const bySpendable = normalChannels
			.map((ch) => ({ ch, spendable: ch.getSpendableOutboundMsat() }))
			.sort((a, b) =>
				a.spendable > b.spendable ? -1 : a.spendable < b.spendable ? 1 : 0
			);

		// If amount specified, prefer a channel that can actually carry it
		if (amountMsat !== undefined) {
			const sufficient = bySpendable.find((e) => e.spendable >= amountMsat);
			if (sufficient) return sufficient.ch;
		}

		// Fall back to the most spendable channel
		return bySpendable[0].ch;
	}
}
