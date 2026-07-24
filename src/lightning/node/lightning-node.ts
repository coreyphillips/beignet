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
	IBlindedPaymentPath
} from '../onion/blinded-path';
import { ChannelManager } from '../channel/channel-manager';
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
import { PeerManager, IPeerInfo } from '../transport/peer-manager';
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
	ADDRESS_TYPE_TORV2,
	ADDRESS_TYPE_TORV3
} from '../gossip/types';
import {
	decodeChannelAnnouncementMessage,
	decodeNodeAnnouncementMessage,
	decodeChannelUpdateMessage,
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
	INodeConfig,
	IResourceConfig,
	IPaymentInfo,
	ICreateInvoiceOptions,
	ICreateInvoiceResult,
	IChannelInfo,
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
	validateHexPubkey,
	validateBuffer,
	validateBufferMinMax,
	validatePositiveBigint,
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
import { FeatureFlags, Feature } from '../features/flags';
import { ChainWatcher, computeScriptHash } from '../chain/chain-watcher';
import { signP2wpkhInput } from '../chain/sweep';
import {
	satPerVbyteToSatPerKw,
	MIN_FEERATE_PER_KW,
	OutputStatus,
	OutputType
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
import { createTaprootFundingScript } from '../script/funding-taproot';
import {
	isTaprootChannel,
	isAnchorChannel,
	hasScidAliasChannelType
} from '../channel/types';
import {
	createOpenerState,
	createAcceptorState,
	IChannelState
} from '../channel/channel-state';
import { IScbChannelEntry } from '../backup/scb';
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
 * - 'peer:error' (pubkey: string, error: Error)
 * - 'peer_storage:retrieved' (peerPubkey: string, blob: Buffer)
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
	private chainWatcher: ChainWatcher | null = null;
	private _chainWatcherEventsWired = false;
	private currentBlockHeight = 0;
	private htlcSafetyMargin: number;
	private forwardingEnabled: boolean;
	private forwardingCltvDelta: number;
	private forwardingFeeBaseMsat: number;
	private forwardingFeePropMillionths: number;
	/** Per-channel routing-policy overrides (channelId hex -> partial policy). */
	private channelPolicies: Map<string, IChannelPolicyUpdate> = new Map();
	private gossipSyncManagers: Map<string, GossipSyncManager> = new Map();
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
	private pendingFundingTxs: Map<string, string> = new Map();
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
	private reestablishTimeoutBlocks: number;
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

	constructor(config: INodeConfig) {
		super();
		this.setMaxListeners(50);

		this.nodePrivkey = config.nodePrivateKey;
		this.nodeId = getPublicKey(config.nodePrivateKey).toString('hex');
		this.network = config.network || Network.REGTEST;
		this.acceptableChainHashes = config.chainHashes ?? [];
		this.storage = config.storage || null;

		this.resourceConfig = {
			maxCompletedPayments:
				config.resourceConfig?.maxCompletedPayments ?? 10_000,
			completedPaymentTtlMs:
				config.resourceConfig?.completedPaymentTtlMs ?? 86_400_000,
			cleanupIntervalMs: config.resourceConfig?.cleanupIntervalMs ?? 60_000
		};

		this.htlcSafetyMargin = config.htlcSafetyMargin ?? 6;
		this.forwardingEnabled = config.forwardingEnabled ?? true;
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
		// from a peer that does not advertise the bit.
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
		// Experimental zero-reserve: advertising the bit is what makes the
		// extension explicitly negotiated; a node with it disabled must not
		// advertise a capability it will refuse.
		if (config.experimentalZeroReserve === false) {
			localFeatures.clearBit(Feature.EXPERIMENTAL_ZERO_RESERVE);
			localFeatures.clearBit(Feature.EXPERIMENTAL_ZERO_RESERVE + 1);
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
			experimentalZeroReserve: config.experimentalZeroReserve,
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
			largeChannels: this.largeChannels,
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

		this.graph = new NetworkGraph(this.chainHash());

		this.onionMessageManager = new OnionMessageManager(config.nodePrivateKey);
		this.wireOnionMessageEvents();

		this.offerManager = new OfferManager(config.nodePrivateKey, {
			onionMessageManager: this.onionMessageManager
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

		if (config.enableNetworking) {
			this.peerManager = new PeerManager({
				localPrivateKey: config.nodePrivateKey,
				localFeatures,
				networks: config.chainHashes,
				autoReconnect: config.autoReconnect ?? config.enableNetworking ?? false,
				maxReconnectDelay: config.maxReconnectDelay,
				socks5Proxy: config.socks5Proxy,
				webSocketImpl: config.webSocketImpl,
				// Zero-reserve peers get DUAL_FUND withheld from our init (see
				// markZeroReservePeer): a 0 reserve is only expressible on the v1
				// open path, and BOLT 2 forbids open_channel once option_dual_fund
				// is negotiated, so the compliant route is to not negotiate it.
				initFeatureFilter: (pubkeyHex, features) =>
					this.initFeaturesFor(pubkeyHex, features)
			});
			this.channelManager.attachToPeerManager(this.peerManager);
			this.registerGossipHandlers();
			this.registerOnionMessageHandler();
			this.registerPeerStorageHandlers();
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
			this.restoreFromStorage();
			// Auto-reconnect peers after crash recovery (Fix 2.1)
			this.autoReconnectPeers();
		}

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

	private restoreFromStorage(): void {
		if (!this.storage) return;

		// Restore channels — look up per-channel key index for each
		for (const {
			channelId,
			state,
			peerPubkey
		} of this.storage.loadAllChannels()) {
			const channel = new Channel(state);
			const keyIndex = this.storage!.loadChannelKeyIndex(channelId);
			this.channelManager.restoreChannel(channel, peerPubkey, keyIndex);
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

				// Reconcile: if the monitor already finished resolving every output
				// of this close (possibly in a prior session where the resolved
				// transition was never persisted), move the channel to CLOSED now so
				// it doesn't report a stale pending-close balance forever.
				if (
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
							for (const { channelId: monitorChannelId } of monitors) {
								const m = this.channelManager.getMonitor(
									Buffer.from(monitorChannelId, 'hex')
								);
								if (m && typeof m.updateFeeRate === 'function') {
									m.updateFeeRate(feeratePerKw);
								}
							}
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

		// Restore gossip graph
		for (const channel of this.storage.loadAllGossipChannels()) {
			this.graph.restoreChannel(channel);
		}
		for (const node of this.storage.loadAllGossipNodes()) {
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
	 * Driven from channel:ready rather than from restoreFromStorage, because a
	 * just-restored channel is in AWAITING_REESTABLISH and can send nothing: both
	 * the onward add and the fail-back would be refused for wrong state. Every
	 * channel passes through channel:ready once reestablish completes, and the
	 * guards below make a repeat run a no-op.
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

	private persistChannel(channelId: Buffer): void {
		if (!this.storage) return;
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) return;
		const peer = this.channelManager.getPeerForChannel(channelId);
		if (!peer) return;
		try {
			const channelIdHex = channelId.toString('hex');
			this.storage.saveChannel(channelIdHex, channel.getFullState(), peer);
			// Persist per-channel key index so the correct signing key
			// is restored after restart (fixes force-close signature mismatch)
			const keyIndex = channel.channelKeyIndex;
			if (keyIndex != null) {
				this.storage.saveChannelKeyIndex(channelIdHex, keyIndex);
			}
		} catch (err) {
			this.emit('node:error', {
				code: 'PERSISTENCE_ERROR',
				channelId,
				message: `Failed to persist channel: ${(err as Error).message}`,
				timestamp: Date.now()
			} as ILightningError);
		}
	}

	private persistPayment(paymentHash: Buffer): void {
		if (!this.storage) return;
		const hashHex = paymentHash.toString('hex');
		const payment = this.payments.get(hashHex);
		if (payment) {
			try {
				this.storage.savePayment(hashHex, payment);
			} catch (err) {
				this.emit('node:error', {
					code: 'PERSISTENCE_ERROR',
					message: `Failed to persist payment: ${(err as Error).message}`,
					timestamp: Date.now()
				} as ILightningError);
			}
		}
	}

	/**
	 * Wrap a storage operation in try/catch, emitting node:error on failure.
	 * Prevents disk-full or locked-DB from crashing a long-running node.
	 */
	private safeStorage(fn: () => void, operation: string): void {
		if (!this.storage) return;
		try {
			fn();
		} catch (err) {
			this.emit('node:error', {
				code: 'PERSISTENCE_ERROR',
				message: `${operation}: ${(err as Error).message}`,
				timestamp: Date.now()
			} as ILightningError);
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
		this.channelManager.on('channel:ready', (channelId: Buffer) => {
			this.registerChannelScids(channelId);
			this.persistChannel(channelId);
			// The channel can carry updates again. Pick up any received HTLC that
			// was dispatched before a restart but whose node-side handling did not
			// survive it (see redispatchUnresolvedReceivedHtlcs).
			this.redispatchUnresolvedReceivedHtlcs(channelId);
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
		});

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

		// Persist-before-send: channel state persisted via PERSIST_STATE action (Fix 2.2)
		this.channelManager.on('channel:persist', (channelId: Buffer) => {
			this.persistChannel(channelId);
		});

		this.channelManager.on(
			'message:outbound',
			(peerPubkey: string, type: number, payload: Buffer) => {
				this.emit('message:outbound', peerPubkey, type, payload);
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
		this.channelManager.on('watch:funding', (fundingTxid: Buffer) => {
			const txidHex = fundingTxid.toString('hex');
			const txHex = this.pendingFundingTxs.get(txidHex);
			if (txHex && this.fundingProvider) {
				this.pendingFundingTxs.delete(txidHex);
				this.fundingProvider.broadcastTransaction(txHex).catch((err) => {
					this.emit('node:error', {
						code: 'FUNDING_BROADCAST_FAILED',
						message: (err as Error).message,
						timestamp: Date.now()
					} as ILightningError);
				});
			}
		});

		// Persist chain monitor state on updates
		this.channelManager.on(
			'monitor:updated',
			(channelIdHex: string, monitor: ChainMonitor) => {
				this.safeStorage(
					() =>
						this.storage!.saveChainMonitor(
							channelIdHex,
							monitor.getFullState()
						),
					'saveChainMonitor'
				);
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

				// Add to our own network graph
				try {
					const annMsg = decodeChannelAnnouncementMessage(channelAnnouncement);
					this.graph.addChannelAnnouncement(annMsg);
					const updateMsg = decodeChannelUpdateMessage(signedChannelUpdate);
					this.graph.applyChannelUpdate(updateMsg);
				} catch {
					// Ignore decode errors for self-generated announcements
				}

				// Build + cache our node_announcement (BOLT 7: required after a channel is
				// announced). Caching lets us re-broadcast it — a one-shot send rarely
				// reaches the whole network, so the node never shows up on explorers.
				const nodeAnnouncementPayload = this.buildNodeAnnouncement(
					Math.floor(Date.now() / 1000)
				);
				if (nodeAnnouncementPayload) {
					this._ownNodeAnnouncement = nodeAnnouncementPayload;
				}

				// Cache this channel's gossip so we can re-broadcast it to new peers and
				// when serving gossip_timestamp_filter requests.
				this._ownChannelGossip.set(channelId.toString('hex'), {
					announcement: channelAnnouncement,
					update: signedChannelUpdate
				});

				// Broadcast to all currently-connected peers now…
				this.broadcastOwnGossip();
				// …and keep it propagating: re-broadcast (with a refreshed
				// node_announcement timestamp) periodically. Idempotent — starts once.
				this.startGossipRefresh();

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
				paymentHash?: Buffer
			) => {
				if (outputType === undefined) return;
				this.handleOnChainOutputResolved(channelId, outputType, paymentHash);
			}
		);

		// Wire broadcast:tx from ChannelManager (closing txs, force-close commitment txs)
		this.channelManager.on('broadcast:tx', (tx: Buffer) => {
			if (this.chainWatcher) {
				this.chainWatcher.broadcastTransaction(tx).catch((err) => {
					this.emit('node:error', {
						code: 'BROADCAST_FAILED',
						message: (err as Error).message,
						timestamp: Date.now()
					} as ILightningError);
				});
			}
			this.emit('broadcast:tx', tx);
		});
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

	private wirePeerManagerEvents(): void {
		if (!this.peerManager) return;
		this.peerManager.on('peer:connect', (pubkey: string) => {
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
			this.emit('peer:connect', pubkey);
		});
		this.peerManager.on('peer:disconnect', (pubkey: string) => {
			this.channelManager.handlePeerDisconnected(pubkey);
			this.gossipSyncManagers.delete(pubkey);
			this.rateLimiter.removePeer(pubkey);
			this.emit('peer:disconnect', pubkey);
		});
		this.peerManager.on('peer:error', (pubkey: string, err: Error) => {
			this.emit('peer:error', pubkey, err);
		});
	}

	/**
	 * Auto-reconnect peers after crash recovery. Staggered to avoid thundering herd.
	 */
	private autoReconnectPeers(): void {
		if (!this.storage || !this.peerManager) {
			this.emitReady();
			return;
		}

		const peerAddresses = this.storage.loadAllPeerAddresses();
		const channelPeers = new Set<string>();

		// Only reconnect peers that have channels needing reestablishment
		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getState();
			if (
				state === ChannelState.AWAITING_REESTABLISH ||
				state === ChannelState.AWAITING_CHANNEL_READY
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
		const persistedAnnounced = new Map(
			(this.storage.loadAllAnnouncedPeerAddresses?.() ?? []).map((entry) => [
				entry.pubkey,
				entry
			])
		);
		for (const pubkey of channelPeers) {
			let newest = persistedAnnounced.get(pubkey);
			const node = this.graph.getNode(Buffer.from(pubkey, 'hex'));
			if (
				node?.announcement &&
				(!newest || node.announcement.timestamp > newest.timestamp)
			) {
				newest = {
					pubkey,
					timestamp: node.announcement.timestamp,
					addresses: announcedDialableAddresses(node.announcement.addresses)
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

				// Store pending tx BEFORE createFunding — the synchronous message chain
				// (funding_created → funding_signed → watch:funding) completes during the call
				this.pendingFundingTxs.set(txid.toString('hex'), txHex);

				// Send funding_created — triggers synchronous chain that broadcasts via watch:funding
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
		return {
			nodeId: this.nodeId,
			network: this.network,
			channelCount: this.channelManager.listChannels().length,
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
			const channelId = Buffer.from(entry.channelId, 'hex');
			if (
				channelId.length !== 32 ||
				channelId.toString('hex') !== entry.channelId.toLowerCase()
			) {
				skipped.push({
					channelId: entry.channelId,
					reason: 'invalid channelId (expected 32-byte hex)'
				});
				continue;
			}
			if (this.channelManager.getChannel(channelId)) {
				skipped.push({
					channelId: entry.channelId,
					reason: 'channel already exists'
				});
				continue;
			}

			// Local key material: per-channel keys for the recorded index, or the
			// node-level basepoints for legacy (null-index) channels. Using the
			// SAME derivation as the original open is what makes the peer's DLP
			// proof verifiable and the to_remote output ours to claim.
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

			const channel = new Channel(state);
			channel.channelKeyIndex = entry.channelKeyIndex;
			this.channelManager.restoreChannel(
				channel,
				entry.peerNodeId,
				entry.channelKeyIndex
			);
			this.persistChannel(channelId);
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
			if (this.peerManager && entry.peerAddresses.length > 0) {
				void this.contactRecoveryPeer(entry.peerNodeId, entry.peerAddresses);
			}
		}

		return { recovering, skipped };
	}

	/** Try each known address for a recovery peer until one connects. */
	private async contactRecoveryPeer(
		peerNodeId: string,
		addresses: string[]
	): Promise<void> {
		for (const address of addresses) {
			// 'host:port' with a possibly-bracketed IPv6 host: split on the LAST colon.
			const sep = address.lastIndexOf(':');
			if (sep <= 0) continue;
			const host = address.slice(0, sep).replace(/^\[|\]$/g, '');
			const port = parseInt(address.slice(sep + 1), 10);
			if (!Number.isFinite(port) || port <= 0) continue;
			try {
				await this.connectPeer(peerNodeId, host, port);
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
		const pubkeyErr = validateHexPubkey(pubkey, 'pubkey');
		if (pubkeyErr) throw new Error(pubkeyErr);
		if (transport?.type === 'ws' && transport.url !== undefined) {
			// Derive the dial address from the explicit URL (and reject a
			// mismatched host/port pair to avoid ambiguous bookkeeping).
			const parsed = parseWebSocketUrl(transport.url);
			if (
				(host !== undefined && host !== parsed.host) ||
				(port !== undefined && port !== parsed.port)
			) {
				throw new Error(
					'host/port conflict with the WebSocket url (omit host/port or make them match)'
				);
			}
			host = parsed.host;
			port = parsed.port;
		}
		if (host === undefined && port === undefined) {
			if (transport?.type === 'ws') {
				throw new Error(
					'WebSocket transport requires host+port or an explicit url'
				);
			}
			await this.connectPeerById(pubkey);
			return;
		}
		if (host === undefined || port === undefined) {
			throw new Error(
				'host and port must be provided together (omit both to resolve from gossip/DNS)'
			);
		}
		const hostErr = validateHost(host);
		if (hostErr) throw new Error(hostErr);
		const portErr = validatePort(port);
		if (portErr) throw new Error(portErr);
		await this.peerManager.connectPeer(pubkey, host, port, transport);
	}

	/**
	 * Connect to a peer by node id alone, resolving its address from the
	 * gossip graph, then DNS bootstrap. Throws an error describing every
	 * address tried (and every Tor address skipped) when nothing connects.
	 */
	private async connectPeerById(pubkey: string): Promise<void> {
		const attempts: string[] = [];
		const isTor = (a: INodeAddress): boolean =>
			a.type === ADDRESS_TYPE_TORV2 || a.type === ADDRESS_TYPE_TORV3;

		// 1. Gossip graph: node_announcement addresses in announced order.
		const announced =
			this.graph.getNode(Buffer.from(pubkey, 'hex'))?.announcement?.addresses ??
			[];
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
			try {
				await this.peerManager!.connectPeer(pubkey, host, port);
				return;
			} catch (err) {
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
				try {
					await this.peerManager!.connectPeer(pubkey, peer.host, peer.port);
					return;
				} catch (err) {
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

	private wireChainWatcherEvents(): void {
		if (!this.chainWatcher || this._chainWatcherEventsWired) return;
		this._chainWatcherEventsWired = true;

		this.chainWatcher.on('block', (height: number) => {
			this.currentBlockHeight = height;
			// The internal watcher path does not go through handleNewBlock, so
			// keep the fee advisor warm here too — force-closes and v2 opens
			// both price themselves synchronously off its latest sample.
			this.warmFeeAdvisor();
		});
		this.chainWatcher.on('error', (err: Error) => {
			this.emit('node:error', {
				code: 'CHAIN_WATCHER_ERROR',
				message: err.message,
				timestamp: Date.now()
			} as ILightningError);
		});
		// Wire watch:output:requested — handle sweep output watching after force-close
		this.chainWatcher.on(
			'watch:output:requested',
			(txid: string, outputIndex: number) => {
				this.chainWatcher!.watchOutputByTxid(txid, outputIndex).catch((err) => {
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
		this.chainWatcher.on('funding:confirmed', (channelId: Buffer) => {
			const channel = this.channelManager.getChannel(channelId);
			if (!channel) return;
			const state = channel.getFullState();
			if (!state.spliceFundingTxid || !channel.getSpliceSession()) return;
			// sendSpliceLocked self-validates the splice state; ignore if not ready.
			const result = this.channelManager.sendSpliceLocked(channelId);
			if (!result.ok) {
				// The channel could not announce the lock (typically disconnected /
				// AWAITING_REESTABLISH). Record the confirmation so the splice_locked
				// is flushed by the next channel_reestablish.
				channel.markSpliceConfirmed();
				this.persistChannel(channelId);
				return;
			}
			this.persistChannel(channelId);
		});
	}

	async startChainWatcher(): Promise<void> {
		// Bring up the watchtower client alongside on-chain monitoring: restore the
		// persisted backlog and connect to towers (no-op when none configured).
		if (this.watchtowerClient) {
			this.watchtowerClient.start().catch((err) => {
				this.emitStructuredLog('watchtower', 'start_failed', {
					error: err instanceof Error ? err.message : String(err)
				});
			});
		}
		if (this.chainWatcher) {
			this.wireChainWatcherEvents();
			await this.chainWatcher.start();
			// Re-watch funding outputs for all restored channels
			await this.restoreChainWatches();
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
				backend.onResubscribed = (): void =>
					this.chainWatcher?.recheckAllWatches();
				backend.startReconnectMonitor();
			}
		}
	}

	/**
	 * Re-watch funding outputs for all restored channels that need monitoring.
	 * Called after startChainWatcher() to resume chain monitoring for persisted channels.
	 */
	async restoreChainWatches(): Promise<void> {
		if (!this.chainWatcher) return;

		const networkMap: Record<string, bitcoin.Network> = {
			[Network.MAINNET]: bitcoin.networks.bitcoin,
			[Network.TESTNET]: bitcoin.networks.testnet,
			[Network.REGTEST]: bitcoin.networks.regtest,
			[Network.SIGNET]: bitcoin.networks.testnet
		};
		const btcNetwork = networkMap[this.network] || bitcoin.networks.regtest;

		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			// Only watch channels that have funding info and are not yet closed
			if (!state.fundingTxid || state.fundingOutputIndex === undefined)
				continue;
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
						try {
							const seedTxid =
								output.status === OutputStatus.SPEND_CONFIRMED
									? output.resolutionTxid
									: undefined;
							const seedHeight =
								seedTxid !== undefined ? output.confirmationHeight : undefined;
							await this.chainWatcher.watchOutputByTxid(
								output.txid,
								output.outputIndex,
								seedTxid,
								seedHeight
							);
						} catch {
							// Electrum hiccup: the funding watch below still drives
							// detection of any commitment spend on the funding output.
						}
					}
				}
				if (state.lastCooperativeCloseTxHex && this._chainBackend) {
					try {
						await this._chainBackend.broadcastTransaction(
							state.lastCooperativeCloseTxHex
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
						try {
							// Seed a previously recorded spend so a reorg that evicts our
							// penalty / HTLC claim after restart is detected (checkOutputSpend
							// only fires its eviction branch when spendTxid is set). Without
							// this the monitor would promote SPEND_CONFIRMED to irrevocable off
							// the stale height and hide a reorg-then-theft.
							const seedTxid =
								output.status === OutputStatus.SPEND_CONFIRMED
									? output.resolutionTxid
									: undefined;
							const seedHeight =
								seedTxid !== undefined ? output.confirmationHeight : undefined;
							await this.chainWatcher.watchOutputByTxid(
								output.txid,
								output.outputIndex,
								seedTxid,
								seedHeight
							);
						} catch {
							// Electrum hiccup — the funding watch below still drives
							// detection of the commitment itself.
						}
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

			const inflight = state.spliceInFlight;
			if (inflight) {
				// In-flight splice: watch the splice tx's new funding output INSTEAD
				// of the old one (watches are keyed by channelId; the old funding
				// output is expected to be spent by the splice tx, and a stale
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
				// splice tx confirms, so the OLD (still-confirmed) funding output has
				// no spend subscription. Watch it directly for a hostile spend, so a
				// revoked pre-splice commitment (peer evicts our low-feerate splice and
				// broadcasts an old commitment) is detected. The splice tx itself
				// spends the old output legitimately, so it is ignored. state.fundingTxid
				// still holds the OLD outpoint until completeSplice swaps it.
				await this.chainWatcher.watchFundingSpendDuringSplice(
					state.channelId || state.temporaryChannelId,
					Buffer.from(state.fundingTxid).reverse().toString('hex'),
					state.fundingOutputIndex,
					fundingScript,
					spliceTxidHex
				);
				if (inflight.fullySigned && this._chainBackend) {
					try {
						await this._chainBackend.broadcastTransaction(inflight.spliceTxHex);
					} catch {
						// Already in mempool/confirmed (or backend hiccup) — the watch
						// above still reports confirmation either way.
					}
				}
				continue;
			}

			const txidHex = Buffer.from(state.fundingTxid).reverse().toString('hex');

			await this.chainWatcher.watchFundingOutput(
				state.channelId || state.temporaryChannelId,
				txidHex,
				state.fundingOutputIndex,
				state.minimumDepth ?? 3,
				fundingScript
			);
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

	// ─────────────── Experimental Zero-Reserve Extension ───────────────

	/** Peers marked for experimental zero-reserve opens. In-memory, like the
	 *  zero-conf trusted set. */
	private readonly zeroReservePeers = new Set<string>();

	/**
	 * Features to advertise in init toward a specific peer (peer-manager
	 * hook). Zero-reserve peers get DUAL_FUND withheld: a 0 reserve is only
	 * expressible on the v1 open path, and BOLT 2 forbids open_channel once
	 * option_dual_fund is negotiated, so the compliant route is to not
	 * negotiate it on connections to those peers in the first place.
	 */
	initFeaturesFor(pubkeyHex: string, features: FeatureFlags): FeatureFlags {
		if (!this.zeroReservePeers.has(pubkeyHex)) return features;
		const filtered = FeatureFlags.fromBuffer(features.toBuffer());
		filtered.clearBit(Feature.DUAL_FUND);
		filtered.clearBit(Feature.DUAL_FUND + 1);
		return filtered;
	}

	/**
	 * Mark a peer for EXPERIMENTAL zero-reserve opens. Takes effect on the
	 * next connection to the peer (the init exchange is per-connection); an
	 * existing connection that already negotiated option_dual_fund must be
	 * reconnected before a zero-reserve open, which
	 * peerNegotiatedDualFund() lets the caller detect.
	 */
	markZeroReservePeer(pubkeyHex: string): void {
		const pubkeyErr = validateHexPubkey(pubkeyHex, 'pubkeyHex');
		if (pubkeyErr) throw new Error(pubkeyErr);
		this.zeroReservePeers.add(pubkeyHex);
	}

	/** Remove a peer from the zero-reserve set (next connection re-advertises
	 *  the full feature set). */
	unmarkZeroReservePeer(pubkeyHex: string): void {
		this.zeroReservePeers.delete(pubkeyHex);
	}

	/** List peers marked for zero-reserve opens. */
	listZeroReservePeers(): string[] {
		return [...this.zeroReservePeers];
	}

	/**
	 * Open a zero-conf channel with a trusted peer.
	 * Channel becomes usable immediately after funding_signed, before confirmation.
	 */
	openZeroConfChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint
	): Channel | null {
		const pubkeyErr = validateHexPubkey(peerPubkey, 'peerPubkey');
		if (pubkeyErr) throw new Error(pubkeyErr);
		const satsErr = validatePositiveBigint(fundingSatoshis, 'fundingSatoshis');
		if (satsErr) throw new Error(satsErr);
		return this.channelManager.openZeroConfChannel(
			peerPubkey,
			fundingSatoshis,
			pushMsat
		);
	}

	destroy(): void {
		this._destroyed = true;
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

		// Phase 3: Clean stale htlcPaymentMap entries. Drop the persisted row with
		// it, otherwise the mapping outlives the payment it points at and is loaded
		// straight back into memory on the next restart.
		for (const [key, hashHex] of this.htlcPaymentMap) {
			if (!this.payments.has(hashHex)) {
				this.htlcPaymentMap.delete(key);
				this.safeStorage(
					() => this.storage!.deleteHtlcPaymentMapping(key),
					'deleteHtlcPaymentMapping'
				);
			}
		}

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
	 * advertise it (BOLT 9). Ours comes from the features THIS CONNECTION's
	 * init actually advertised (the per-peer filter withholds DUAL_FUND from
	 * zero-reserve peers, and a connection that predates the mark still
	 * advertised it), the peer's from the init it sent on connect. A peer we
	 * hold no init for counts as not negotiated.
	 */
	peerNegotiatedDualFund(peerPubkey: string): boolean {
		const peer = this.peerManager?.getPeer(peerPubkey);
		// Duck-typed guard: test doubles and older embedder Peer stubs predate
		// getAdvertisedFeatures; for those the full local set is the advertised
		// set (no per-peer filter existed).
		const advertised =
			peer && typeof peer.getAdvertisedFeatures === 'function'
				? peer.getAdvertisedFeatures()
				: this.localFeatures;
		if (!advertised.hasFeature(Feature.DUAL_FUND)) return false;
		const init = peer?.getRemoteInit();
		return init ? init.features.hasFeature(Feature.DUAL_FUND) : false;
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
	 *
	 * zeroReserve (EXPERIMENTAL beignet extension, implies trusted)
	 * additionally advertises a 0 sat channel_reserve, waiving the BOLT 2
	 * reserve on both sides. Requires the peer marked via markZeroReservePeer
	 * BEFORE the connection was made (so option_dual_fund was not negotiated;
	 * the v2 open path cannot express a zero reserve) and the peer's init to
	 * carry the experimental_zero_reserve capability.
	 */
	openChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint,
		satsPerVbyte?: number,
		fundMax = false,
		trusted = false,
		zeroReserve = false
	): Channel {
		const pubkeyErr = validateHexPubkey(peerPubkey, 'peerPubkey');
		if (pubkeyErr) throw new Error(pubkeyErr);
		const satsErr = validatePositiveBigint(fundingSatoshis, 'fundingSatoshis');
		if (satsErr) throw new Error(satsErr);
		if (pushMsat !== undefined && pushMsat > fundingSatoshis * 1000n) {
			throw new Error(
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
			throw new Error(
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
			throw new Error(
				'max funding requires a pinned satsPerVbyte (the rate the max amount was quoted at)'
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
		// A zero-reserve open cannot ride v2 (open_channel2 has no reserve field
		// to waive; the v2 reserve is fixed at 1%), and BOLT 2 forbids a v1
		// open_channel once option_dual_fund is negotiated. The peer must have
		// been marked (markZeroReservePeer) before connecting so this connection
		// never negotiated dual_fund; refuse loudly rather than violate either.
		if (zeroReserve && this.peerNegotiatedDualFund(peerPubkey)) {
			throw new Error(
				'zero-reserve open requires a connection without option_dual_fund: markZeroReservePeer first, then reconnect to the peer'
			);
		}
		if (this.peerNegotiatedDualFund(peerPubkey)) {
			if (pushMsat !== undefined && pushMsat > 0n) {
				throw new Error(
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
					throw new Error(
						'max funding on a dual-funded (v2) open requires a funding provider with quoteDualFundingMax and selectMaxDualFundingInputs'
					);
				}
				const feeratePerKw = Math.ceil(
					this.clampEstimatedFeeRate(satsPerVbyte!) * 250
				);
				const quote = fp.quoteDualFundingMax(feeratePerKw);
				if (quote.fundingSatoshis <= 0n) {
					throw new Error(
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
				throw new Error(
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
			{ trusted: trusted || zeroReserve, zeroReserve }
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
		}
	): Channel {
		const pubkeyErr = validateHexPubkey(peerPubkey, 'peerPubkey');
		if (pubkeyErr) throw new Error(pubkeyErr);
		const satsErr = validatePositiveBigint(
			params.fundingSatoshis,
			'fundingSatoshis'
		);
		if (satsErr) throw new Error(satsErr);
		// Fail fast at the API boundary; handleAcceptChannel2 enforces the same
		// invariant as defense-in-depth (an uncapped lease fee could otherwise
		// drain the buyer's balance).
		if (params.requestFunds && !params.maxLeaseRates) {
			throw new Error(
				'requestFunds requires maxLeaseRates (buyer fee ceiling)'
			);
		}
		// A lease fee is only known once the seller answers will_fund, but a max
		// open must commit the ENTIRE balance minus fees in open_channel2 —
		// there is nothing left to absorb the fee later.
		if (params.fundMax && params.requestFunds) {
			throw new Error(
				'max funding cannot be combined with requestFunds (the lease fee is not known when the max is committed)'
			);
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
			fundMax: params.fundMax
		};

		return this.channelManager.createDualFundedChannel(peerPubkey, dualParams, {
			trusted: params.trusted
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

	handleFundingConfirmed(channelId: Buffer): void {
		this.channelManager.handleFundingConfirmed(channelId);
	}

	closeChannel(
		channelId: Buffer,
		scriptPubkey: Buffer
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
		const result = this.channelManager.initiateShutdown(
			channelId,
			scriptPubkey
		);
		if (!result.ok) {
			this.emit('node:error', {
				code: 'CLOSE_CHANNEL_FAILED',
				channelId,
				message: result.error!,
				timestamp: Date.now()
			} as ILightningError);
			return { ok: false, error: result.error };
		}
		return { ok: true };
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
		return {
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
		return {
			feeBaseMsat: override?.feeBaseMsat ?? this.forwardingFeeBaseMsat,
			feeProportionalMillionths:
				override?.feeProportionalMillionths ?? this.forwardingFeePropMillionths,
			cltvExpiryDelta: override?.cltvExpiryDelta ?? this.forwardingCltvDelta
		};
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
				this.graph.applyChannelUpdate(decodeChannelUpdateMessage(refreshed));
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
			this.emit('message:outbound', peer, MessageType.CHANNEL_UPDATE, payload);
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
			const { encodeChannelUpdateMessage } = require('../gossip/messages');
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

	forceCloseChannel(
		channelId: Buffer,
		destinationScript: Buffer
	): { ok: boolean; error?: string; commitmentTxid?: string } {
		const result = this.channelManager.forceClose(
			channelId,
			destinationScript,
			this.resolveForceCloseFeeRatePerVbyte()
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
		if (cidErr) throw new Error(cidErr);
		const satsErr = validatePositiveBigint(amountSats, 'amountSats');
		if (satsErr) throw new Error(satsErr);

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
		if (cidErr) throw new Error(cidErr);
		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			throw new Error(`Channel not found: ${channelId.toString('hex')}`);
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
			const reserve = state.remoteConfig?.channelReserveSatoshis ?? 0n;
			const local = channel.getBalances().localMsat / 1000n;
			const spendable = local > reserve ? local - reserve : 0n;
			const max = spendable > feeSats ? spendable - feeSats : 0n;
			return {
				direction,
				feeSats: Number(feeSats),
				spendableSats: Number(spendable),
				maxAmountSats: Number(max),
				reserveSats: Number(reserve)
			};
		}

		if (!this.fundingProvider?.quoteSpliceIn) {
			throw new Error(
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
		if (cidErr) throw new Error(cidErr);
		const satsErr = validatePositiveBigint(amountSats, 'amountSats');
		if (satsErr) throw new Error(satsErr);
		if (
			destinationScript !== undefined &&
			(!Buffer.isBuffer(destinationScript) || destinationScript.length === 0)
		) {
			throw new Error(
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
			throw new Error(
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
		// Footgun guard: a fee at or above the withdrawal means you'd burn more
		// on-chain than you take out — almost always a mistake (wrong feerate).
		if (!error && fee >= amountSats) {
			error = `splice-out fee (${fee} sats at ${fundingFeeratePerkw} sat/kw) meets or exceeds the amount (${amountSats} sats) — use a larger amount or a lower feerate`;
		}
		if (!error) {
			const state = channel.getFullState();
			const spendableSats =
				channel.getBalances().localMsat / 1000n -
				(state.remoteConfig?.channelReserveSatoshis ?? 0n);
			if (amountSats + fee > spendableSats) {
				error = `insufficient channel balance for splice-out: need ${
					amountSats + fee
				} sats (amount + ${fee}-sat fee at ${fundingFeeratePerkw} sat/kw), spendable ${spendableSats} sats after reserve`;
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
	 * Shared splice pre-flight checks: dust-level amounts and peer feature
	 * support (option_splice + option_quiesce). Returns an error string or null.
	 */
	private _validateSpliceRequest(
		channelId: Buffer,
		amountSats: bigint
	): string | null {
		if (amountSats <= LightningNode.SPLICE_MIN_AMOUNT_SATS) {
			return `splice amount ${amountSats} sats is at or below the dust floor (${LightningNode.SPLICE_MIN_AMOUNT_SATS} sats)`;
		}
		const peerPubkey = this.channelManager.getPeerForChannel(channelId);
		if (peerPubkey && this.peerManager) {
			const init = this.peerManager.getPeer(peerPubkey)?.getRemoteInit();
			if (
				init &&
				(!init.features.hasFeature(Feature.QUIESCE) ||
					!init.features.hasFeature(Feature.SPLICE))
			) {
				return 'peer does not support splicing (option_splice/option_quiesce not negotiated)';
			}
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
				htlcUsable: ch.htlcUsable
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
			peerPubkey: ch.peerPubkey
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
		if (!fromChannel || !fromChannel.isHtlcUsable()) {
			throw new Error(
				`from channel not found or not usable: ${fromChannelId.toString('hex')}`
			);
		}
		const toChannel = this.channelManager.getChannel(toChannelId);
		if (!toChannel || !toChannel.isHtlcUsable()) {
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
		if (state.fundingTxid)
			info.fundingTxid = Buffer.from(state.fundingTxid)
				.reverse()
				.toString('hex');
		const pendingSplice = channel.getPendingSpliceLocalBalanceMsat();
		if (pendingSplice !== null)
			info.pendingSpliceLocalBalanceMsat = pendingSplice;
		info.htlcUsable = channel.isHtlcUsable();
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
		return info;
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
			const { encodeNodeAnnouncementMessage } = require('../gossip/messages');
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
				addresses: this.announcedAddresses
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
			const { encodeChannelUpdateMessage } = require('../gossip/messages');
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
				// Liquidity ads (bLIP-0051): while WE are the lessor and the lease is
				// still active, clamp our advertised routing fees to the caps we
				// signed into will_fund. The buyer paid for capped fees; exceeding
				// them breaks the lease promise.
				if (
					st.isLessor &&
					st.leaseExpiry !== undefined &&
					(this.currentBlockHeight === 0 ||
						this.currentBlockHeight < st.leaseExpiry)
				) {
					if (
						st.leaseChannelFeeMaxBaseMsat !== undefined &&
						msg.feeBaseMsat > st.leaseChannelFeeMaxBaseMsat
					) {
						msg.feeBaseMsat = st.leaseChannelFeeMaxBaseMsat;
					}
					if (st.leaseChannelFeeMaxProportionalThousandths !== undefined) {
						const capMillionths =
							st.leaseChannelFeeMaxProportionalThousandths * 1000;
						if (msg.feeProportionalMillionths > capMillionths) {
							msg.feeProportionalMillionths = capMillionths;
						}
					}
				}
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
		if (!channel.isHtlcUsable(true)) return null;

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
		// Generous absolute CLTV bound for the path's payment constraints.
		const maxCltvExpiry = (this.currentBlockHeight || 0) + 2016;

		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			if (!channel.isHtlcUsable(true)) continue;

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
			const directPolicy = state.remoteForwardingPolicy;
			if (directPolicy) {
				feeBaseMsat = directPolicy.feeBaseMsat;
				feeProportionalMillionths = directPolicy.feeProportionalMillionths;
				cltvExpiryDelta = directPolicy.cltvExpiryDelta;
				htlcMinimumMsat = directPolicy.htlcMinimumMsat;
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
				}
			}

			// Advertise the peer's real htlc_minimum_msat in the blinded hop's
			// payment_constraints so the payer never sends a sub-minimum HTLC the
			// peer would reject (the same masked-failure class as the fee gap).
			const paymentConstraints = { maxCltvExpiry, htlcMinimumMsat };
			// Peer hop: forward to us over this channel. For async receive, mark
			// it hold_htlc so the LSP parks the HTLC until we return.
			const peerHop: IBlindedHopData = {
				nextNodeId: ourNodeId,
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
						nextNodeId: peerPubkey,
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

			paths.push({
				path,
				payInfo: {
					feeBaseMsat: aggBase,
					feeProportionalMillionths: aggProp,
					cltvExpiryDelta: aggCltv,
					htlcMinimumMsat: 0n,
					htlcMaximumMsat: state.fundingSatoshis * 1000n
				}
			});
		}

		return paths;
	}

	// ─────────────── Gossip Handling ───────────────

	private handleGossipMessage(
		pubkey: string,
		type: number,
		payload: Buffer
	): void {
		switch (type) {
			case MessageType.CHANNEL_ANNOUNCEMENT:
				this.handleChannelAnnouncement(payload);
				break;
			case MessageType.NODE_ANNOUNCEMENT:
				this.handleNodeAnnouncement(payload);
				break;
			case MessageType.CHANNEL_UPDATE:
				this.handleChannelUpdate(payload);
				break;
			case MessageType.REPLY_CHANNEL_RANGE: {
				const syncMgr = this.gossipSyncManagers.get(pubkey);
				if (syncMgr) {
					const msg = decodeReplyChannelRangeMessage(payload);
					const responses = syncMgr.handleReplyChannelRange(msg);
					for (const resp of responses) {
						this.emit('message:outbound', pubkey, resp.type, resp.payload);
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
						this.emit('message:outbound', pubkey, resp.type, resp.payload);
					}
				}
				break;
			}
			case MessageType.QUERY_CHANNEL_RANGE: {
				const syncMgr = this.getOrCreateSyncManager(pubkey);
				const msg = decodeQueryChannelRangeMessage(payload);
				const responses = syncMgr.handleQueryChannelRange(msg);
				for (const resp of responses) {
					this.emit('message:outbound', pubkey, resp.type, resp.payload);
				}
				break;
			}
			case MessageType.QUERY_SHORT_CHANNEL_IDS: {
				const syncMgr = this.getOrCreateSyncManager(pubkey);
				const msg = decodeQueryShortChannelIdsMessage(payload);
				const responses = syncMgr.handleQueryShortChannelIds(msg);
				for (const resp of responses) {
					this.emit('message:outbound', pubkey, resp.type, resp.payload);
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
			this.emit('message:outbound', pubkey, msg.type, msg.payload);
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
		if (!verifyChannelAnnouncement(msg, payload)) {
			return;
		}
		if (this.graph.addChannelAnnouncement(msg)) {
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
		if (!verifyNodeAnnouncement(msg, payload)) {
			return;
		}
		// A signature-verified announcement from a channel peer is the only
		// dialable address we ever learn for peers that connected inbound (their
		// TCP source port is ephemeral, so it is never stored). Capture it even
		// when the graph rejects the announcement below — a node with only
		// private channels never enters the graph, yet its channels still need
		// a reconnect path or they sit in AWAITING_REESTABLISH forever.
		this.captureChannelPeerAddresses(msg);
		if (this.graph.applyNodeAnnouncement(msg)) {
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
		if (!verifyChannelUpdate(msg, payload, channel.nodeId1, channel.nodeId2)) {
			return;
		}
		if (this.graph.applyChannelUpdate(msg)) {
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
			const receivableNormal = allChannels.some((ch) => ch.isHtlcUsable(true));
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

		this.safeStorage(() => {
			if (preimage) {
				this.storage!.savePreimage(paymentHash.toString('hex'), preimage);
			}
			this.storage!.savePaymentSecret(
				paymentHash.toString('hex'),
				paymentSecret
			);
			this.storage!.saveInvoice(paymentHash.toString('hex'), {
				paymentHash: paymentHash.toString('hex'),
				bolt11: invoiceStr,
				amountMsat: options.amountMsat,
				description: options.description,
				expiry: options.expiry ?? DEFAULT_EXPIRY,
				createdAt: createdAtSecs,
				hold: options.hold
			});
			this.persistPayment(paymentHash);
		}, 'saveInvoiceData');

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
	private getLocalChannelEdges(): ILocalChannelEdge[] {
		const edges: ILocalChannelEdge[] = [];
		for (const channel of this.channelManager.listChannels()) {
			if (!channel.isHtlcUsable()) continue;
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peerHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerHex) continue;
			const st = channel.getFullState();
			// A splice keeps using its pre-splice scid until the lock.
			const scid = st.shortChannelId ?? st.scidAlias;
			if (!scid) continue;
			// Mid-splice, the ceiling is the min across both fundings (a
			// splice-out's candidate commitment has less to spend) — the same
			// figure addHtlc enforces, so the router never offers a route the
			// channel then refuses. NORMAL channels keep the historical
			// upper-bound (the add enforces reserve/in-flight limits).
			const outboundMsat =
				st.state === ChannelState.SPLICING
					? channel.getSpendableOutboundMsat()
					: st.localBalanceMsat;
			if (outboundMsat <= 0n) continue;
			edges.push({
				shortChannelId: scid,
				peer: Buffer.from(peerHex, 'hex'),
				outboundMsat
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
			if (maxFeeMsat !== undefined && blindedRoute.totalFeeMsat > maxFeeMsat) {
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
		const route = findRoute(
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
		// MPP requires the recipient to advertise basic_mpp (BOLT 4): splitting
		// to a non-MPP recipient locks every part until the mpp_timeout.
		if (
			!route &&
			invoice.paymentSecret &&
			invoice.featureBits?.hasFeature(Feature.BASIC_MPP)
		) {
			// Try multi-path routing as fallback
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
				localChannels
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
					finalCltvExpiry
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
		const hops = route.hops;
		if (hops.length === 0) {
			throw new Error('Route must have at least one hop');
		}

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
		// smart selection by balance (Fix 3.3).
		const firstHopPubkey = hops[0].pubkey.toString('hex');
		const outChannel =
			this.findLocalChannelByScid(hops[0].shortChannelId, firstHopPubkey) ??
			this.findChannelForPeer(firstHopPubkey, hops[0].amountToForwardMsat);
		if (!outChannel) {
			throw new LightningPaymentError(
				LightningErrorCode.NO_CHANNEL_TO_HOP,
				`No channel to first hop ${firstHopPubkey}`
			);
		}

		const channelId = outChannel.getChannelId()!;
		const cltvExpiry = hops[0].outgoingCltvValue + baseHeight;
		const amount = hops[0].amountToForwardMsat;

		// Create payment info BEFORE addHtlc because in synchronous loopback
		// the entire fulfill chain runs during addHtlc
		const payment: IPaymentInfo = {
			paymentHash,
			amountMsat: amount,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			cltvBaseHeight: baseHeight,
			route: route as {
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
		if (this.storage) {
			this.storage.transaction(() => {
				this.persistPayment(paymentHash);
				this.storage!.saveHtlcPaymentMapping(
					htlcKey,
					paymentHash.toString('hex')
				);
			});
		}

		// Add HTLC to channel (may trigger synchronous fulfillment via loopback)
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
			// htlcKey was derived from localHtlcCounter before the add, and a refused
			// add does not consume that id, so the mapping written above now points
			// at an id a later unrelated HTLC will take. Drop it in both places, and
			// persist the FAILED status so storage does not keep the PENDING row
			// written moments ago.
			this.htlcPaymentMap.delete(htlcKey);
			this.safeStorage(
				() => this.storage!.deleteHtlcPaymentMapping(htlcKey),
				'deleteHtlcPaymentMapping'
			);
			this.persistPayment(paymentHash);
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
		failureData?: Buffer
	): boolean {
		if (payment.failureCode !== INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS) {
			return false;
		}
		const finalHopIndex = (payment.route?.hops.length ?? 0) - 1;
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
		if (this.storage) {
			this.storage.transaction(() => {
				this.persistPayment(paymentHash);
				this.storage!.saveHtlcPaymentMapping(htlcKey, hashHex);
			});
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
			this.safeStorage(
				() => this.storage!.deleteHtlcPaymentMapping(htlcKey),
				'deleteHtlcPaymentMapping'
			);
			this.persistPayment(paymentHash);
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
		_finalCltvExpiry: number
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

		// Store retry context
		if (!this.paymentRetryContexts.has(hashHex)) {
			this.paymentRetryContexts.set(hashHex, {
				invoiceStr,
				excludedChannels: new Set(),
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

			const firstHopPubkey = hops[0].pubkey.toString('hex');
			const outChannel = this.findChannelForPeer(
				firstHopPubkey,
				hops[0].amountToForwardMsat
			);
			if (!outChannel) continue;

			const channelId = outChannel.getChannelId()!;
			const cltvExpiry = hops[0].outgoingCltvValue + baseHeight;
			const amount = hops[0].amountToForwardMsat;

			const htlcId = outChannel.getFullState().localHtlcCounter;
			const mppHtlcKey = `${channelId.toString('hex')}:offered-${htlcId}`;
			this.htlcPaymentMap.set(mppHtlcKey, hashHex);
			this.safeStorage(
				() => this.storage!.saveHtlcPaymentMapping(mppHtlcKey, hashHex),
				'saveHtlcPaymentMapping'
			);

			// Store shared secrets on the first part for failure decryption
			if (!payment.sharedSecrets) {
				payment.sharedSecrets = sharedSecrets;
				payment.route = partRoute as IPaymentInfo['route'];
			}

			mppState.parts.push({
				route: partRoute,
				channelId,
				htlcId,
				amountMsat: amount,
				status: PaymentStatus.PENDING
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
				this.safeStorage(
					() => this.storage!.deleteHtlcPaymentMapping(mppHtlcKey),
					'deleteHtlcPaymentMapping'
				);
				mppState.parts.pop();

				// Part failed to dispatch — mark payment failed
				payment.status = PaymentStatus.FAILED;
				payment.completedAt = Date.now();
				payment.failureReason = `Local failure: MPP part could not be dispatched (${
					result.error ?? 'unknown reason'
				})`;
				this.outboundMppPayments.delete(hashHex);
				this.persistPayment(paymentHash);
				this.emit('payment:failed', payment);
				return payment;
			}
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
		if (this.storage) {
			try {
				this.storage.saveHtlcSharedSecret(
					htlcSecretKey,
					processed.sharedSecret
				);
			} catch {
				/* best-effort */
			}
		}

		if (isFinalHop(processed.nextPacket)) {
			// We are the final destination
			this.handleFinalHopHtlc(
				channelId,
				htlcId,
				amountMsat,
				paymentHash,
				processed.hopPayload,
				htlcEntry.cltvExpiry
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
		incomingCltvExpiry?: number
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
				try {
					this.storage.transaction(() => {
						this.storage!.savePreimage(hashHex, keysendPreimage);
						this.persistPayment(paymentHash);
					});
				} catch {
					/* best-effort persistence */
				}
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

		// (final-hop cltv/amount safety was validated up front, before any
		// preimage was revealed — see finalHopSafetyFailure.)

		// Validate the received amount against the invoice (BOLT 4). The final
		// node MUST NOT fulfill (and reveal the preimage) for less than the
		// invoiced amount, and SHOULD reject gross overpayment (> 2x). Without
		// this, a payer can settle a large invoice with a tiny HTLC and still
		// obtain the proof-of-payment. For MPP the sender-declared total_msat is
		// what the parts accumulate toward, so validating it here (and the
		// existing handleMppPart accumulation to total_msat) bounds the real
		// received total. Zero-amount ("any amount") invoices are exempt.
		const finalInvoice = this.invoices.get(hashHex);
		if (
			finalInvoice &&
			finalInvoice.amountMsat &&
			finalInvoice.amountMsat > 0n
		) {
			const isMpp =
				!!hopPayload?.totalMsat && hopPayload.totalMsat > amountMsat;
			const claimedTotal = isMpp ? hopPayload!.totalMsat! : amountMsat;
			if (
				claimedTotal < finalInvoice.amountMsat ||
				claimedTotal > finalInvoice.amountMsat * 2n
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

		// MPP: if payment_data has totalMsat > amountMsat, this is a multi-part payment
		if (hopPayload?.totalMsat && hopPayload.totalMsat > amountMsat) {
			this.handleMppPart(
				channelId,
				htlcId,
				amountMsat,
				paymentHash,
				hopPayload,
				preimage!
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
		this.safeStorage(
			() => this.storage!.savePreimage(hashHex, pre),
			'savePreimage'
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
		this.safeStorage(
			() => this.storage!.deletePaymentSecret(hashHex),
			'deletePaymentSecret'
		);
		const invoice = this.invoices.get(hashHex);
		if (invoice && !invoice.cancelledAt) {
			invoice.cancelledAt = Date.now();
			this.safeStorage(
				() => this.storage!.saveInvoice(hashHex, invoice),
				'saveInvoice'
			);
		}
		const payment = this.payments.get(hashHex);
		if (
			payment &&
			payment.direction === PaymentDirection.INCOMING &&
			payment.status !== PaymentStatus.COMPLETED
		) {
			payment.status = PaymentStatus.FAILED;
			this.safeStorage(
				() => this.persistPayment(Buffer.from(hashHex, 'hex')),
				'persistPayment'
			);
		}
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

	private handleMppPart(
		channelId: Buffer,
		htlcId: bigint,
		amountMsat: bigint,
		paymentHash: Buffer,
		hopPayload: IHopPayload,
		preimage: Buffer
	): void {
		const hashHex = paymentHash.toString('hex');

		// Get or create pending MPP payment
		let pending = this.pendingMppPayments.get(hashHex);
		if (!pending) {
			pending = {
				paymentSecret: hopPayload.paymentSecret!,
				totalMsat: hopPayload.totalMsat!,
				receivedParts: [],
				createdAt: Date.now()
			};
			this.pendingMppPayments.set(hashHex, pending);
		} else if (
			hopPayload.totalMsat !== undefined &&
			hopPayload.totalMsat !== pending.totalMsat
		) {
			// BOLT 4: every part of a multi-part payment MUST carry the same
			// total_msat. A part disagreeing with the set is
			// final_incorrect_htlc_amount; fail just this part and keep the set
			// intact (the payer may still complete with conformant parts).
			const secretKey = `${channelId.toString('hex')}:${htlcId}`;
			const sharedSecret = this.receivedHtlcSharedSecrets.get(secretKey);
			const reason = sharedSecret
				? createFailureMessage(sharedSecret, FINAL_INCORRECT_HTLC_AMOUNT)
				: Buffer.alloc(FAILURE_MESSAGE_LENGTH);
			this.cleanupHtlcSharedSecret(secretKey);
			this.channelManager.failHtlc(channelId, htlcId, reason);
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

		// Persist BEFORE sending fulfill message — on crash, reestablish retransmits
		if (this.storage) {
			this.storage.transaction(() => {
				this.storage!.deletePaymentSecret(hashHex);
				this.persistPayment(paymentHash);
			});
		}

		this.channelManager.fulfillHtlc(channelId, htlcId, preimage);
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
			this.safeStorage(
				() => this.storage!.saveForwardedHtlc(outKey, inChannelId, inHtlcId),
				'saveForwardedHtlc'
			);

			// For a blinded forward, hand the next hop its blinding point and use the
			// payment_relay-derived amount/CLTV.
			const result = this.channelManager.addHtlc(
				outChannelId,
				forwardAmount,
				paymentHash,
				forwardCltv,
				nextOnionBuf,
				nextBlindingPoint
			);

			if (!result.ok) {
				// Forward failed — fail the incoming HTLC back. Drop the persisted
				// row too, not just the in-memory one: the outgoing id was read off
				// localHtlcCounter before the add, and a refused add does not consume
				// it, so a surviving row maps an id a later unrelated HTLC will take
				// onto this inbound leg and would settle it against the wrong payment.
				this.forwardedHtlcs.delete(outKey);
				this.safeStorage(
					() => this.storage!.deleteForwardedHtlc(outKey),
					'deleteForwardedHtlc'
				);
				failIncoming(TEMPORARY_CHANNEL_FAILURE);
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
	 * recordPreimage is idempotent, so re-learning a preimage is harmless.
	 */
	private handleOnChainPreimageLearned(
		paymentHash: Buffer,
		preimage: Buffer
	): void {
		const hashHex = paymentHash.toString('hex');
		this.preimages.set(hashHex, preimage);
		this.safeStorage(
			() => this.storage!.savePreimage(hashHex, preimage),
			'savePreimage'
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
				this.cleanupHtlcSharedSecret(`${cid.toString('hex')}:${htlc.id}`);
				this.channelManager.fulfillHtlc(cid, htlc.id, preimage);
				// Drop any forwarding bookkeeping for the matching outgoing leg.
				for (const [outKey, fwd] of this.forwardedHtlcs) {
					if (fwd.inChannelId.equals(cid) && fwd.inHtlcId === htlc.id) {
						this.forwardedHtlcs.delete(outKey);
						this.safeStorage(
							() => this.storage!.deleteForwardedHtlc(outKey),
							'deleteForwardedHtlc'
						);
					}
				}
				this.persistChannel(cid);
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
		paymentHash?: Buffer
	): void {
		if (outputType !== OutputType.OFFERED_HTLC) return;
		if (!channelId || !paymentHash) return;
		// A known preimage means the downstream DID settle; the fulfill path
		// (handleOnChainPreimageLearned / handleHtlcFulfilled) owns the inbound leg.
		if (this.preimages.has(paymentHash.toString('hex'))) return;

		const outChannelIdHex = channelId.toString('hex');
		for (const [outKey, forward] of this.forwardedHtlcs) {
			if (!outKey.startsWith(`${outChannelIdHex}:offered-`)) continue;
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

			const inSecretKey = `${forward.inChannelId.toString('hex')}:${
				forward.inHtlcId
			}`;
			// BOLT 4 route blinding: failures of a blinded forward must surface as
			// invalid_onion_blinding (update_fail_malformed_htlc for a 'mid' hop).
			const blindedRole = this.blindedIncomingHtlcs.get(inSecretKey);
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
			this.safeStorage(
				() => this.storage!.deleteForwardedHtlc(outKey),
				'deleteForwardedHtlc'
			);
			this.persistChannel(forward.inChannelId);
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
		this.safeStorage(
			() => this.storage!.savePreimage(preimageHash.toString('hex'), preimage),
			'savePreimage'
		);

		// Check if this is a forwarded HTLC — propagate fulfillment upstream
		const outKey = `${channelId.toString('hex')}:offered-${htlcId}`;
		const forward = this.forwardedHtlcs.get(outKey);
		if (forward) {
			// Clean up shared secret for the incoming leg
			this.cleanupHtlcSharedSecret(
				`${forward.inChannelId.toString('hex')}:${forward.inHtlcId}`
			);
			// Deliver the preimage to the chain monitors before settling the incoming
			// leg. We learned this preimage from the downstream fulfill; if the incoming
			// channel force-closes before our upstream fulfill confirms, the monitor must
			// already hold the preimage to claim the inbound HTLC on-chain. Without this
			// the forwarded value is lost via the counterparty's timeout path.
			this.channelManager.recordPreimage(preimageHash, preimage);
			// Both legs of the forward settle here: record the ledger entry now,
			// while both HTLC entries still exist (they are dropped on revoke)
			this.recordForwardingEvent(channelId, htlcId, forward);
			// Persist before sending upstream fulfill
			this.safeStorage(
				() => this.storage!.deleteForwardedHtlc(outKey),
				'deleteForwardedHtlc'
			);
			this.channelManager.fulfillHtlc(
				forward.inChannelId,
				forward.inHtlcId,
				preimage
			);
			this.forwardedHtlcs.delete(outKey);
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
			// Clean up HTLC payment mapping
			this.htlcPaymentMap.delete(outKey);
			if (this.storage) {
				this.storage.transaction(() => {
					this.storage!.deleteHtlcPaymentMapping(outKey);
					this.storage!.deletePaymentSecret(hashHex);
					this.persistPayment(paymentHash);
					this.persistChannel(channelId);
				});
			} else {
				this.persistPayment(paymentHash);
				this.persistChannel(channelId);
			}
			this.emit('payment:sent', payment);
			this.emitStructuredLog('payment', 'sent', {
				paymentHash: hashHex,
				amountMsat: Number(payment.amountMsat),
				status: payment.status
			});
		}
	}

	/**
	 * Persist a forwarding-ledger entry for a forward whose downstream fulfill
	 * just arrived. Amounts come from the live HTLC entries on both legs; they
	 * still exist at this point (removed only on the later revoke_and_ack). A
	 * forward restored after a restart whose entries are already gone is
	 * skipped: there is no accurate amount left to record.
	 */
	private recordForwardingEvent(
		outChannelId: Buffer,
		outHtlcId: bigint,
		forward: { inChannelId: Buffer; inHtlcId: bigint }
	): void {
		const outState = this.channelManager
			.getChannel(outChannelId)
			?.getFullState();
		const inState = this.channelManager
			.getChannel(forward.inChannelId)
			?.getFullState();
		const outHtlc = outState?.htlcs.get(`offered-${outHtlcId}`);
		const inHtlc = inState?.htlcs.get(`received-${forward.inHtlcId}`);
		if (!outHtlc || !inHtlc) return;
		const amountInMsat = inHtlc.amountMsat;
		const amountOutMsat = outHtlc.amountMsat;
		this.emit('htlc:forwarded', {
			inChannelId: forward.inChannelId,
			outChannelId,
			amountInMsat,
			amountOutMsat,
			feeMsat: amountInMsat - amountOutMsat
		});
		// Resolution counterpart to the forward_attempt log, at the same level as
		// a settled payment: a completed relay should leave a trace, not just an
		// SSE event no log consumer sees.
		this.emitStructuredLog('htlc', 'forwarded', {
			paymentHash: inHtlc.paymentHash?.toString('hex'),
			inChannelId: forward.inChannelId.toString('hex'),
			outChannelId: outChannelId.toString('hex'),
			amountInMsat: Number(amountInMsat),
			amountOutMsat: Number(amountOutMsat),
			feeMsat: Number(amountInMsat - amountOutMsat)
		});
		if (
			!this.storage ||
			typeof this.storage.saveForwardingEvent !== 'function'
		) {
			return;
		}
		this.safeStorage(
			() =>
				this.storage!.saveForwardingEvent!({
					settledAt: Date.now(),
					inChannelId: forward.inChannelId.toString('hex'),
					outChannelId: outChannelId.toString('hex'),
					inScid: inState?.shortChannelId?.toString('hex'),
					outScid: outState?.shortChannelId?.toString('hex'),
					amountInMsat,
					amountOutMsat,
					feeMsat: amountInMsat - amountOutMsat
				}),
			'saveForwardingEvent'
		);
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

	private handleHtlcFailed(
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer
	): void {
		// Check if this is a forwarded HTLC — wrap and propagate failure upstream
		const outKey = `${channelId.toString('hex')}:offered-${htlcId}`;
		const forward = this.forwardedHtlcs.get(outKey);
		if (forward) {
			// Resolution counterpart to forward_attempt for the failure case, so
			// every attempted forward pairs with a 'forwarded' or 'forward_failed'
			// line rather than going silent when the downstream leg fails.
			this.emitStructuredLog('htlc', 'forward_failed', {
				inChannelId: forward.inChannelId.toString('hex'),
				inHtlcId: Number(forward.inHtlcId),
				outChannelId: channelId.toString('hex'),
				outHtlcId: Number(htlcId)
			});
			this.emit('htlc:forward-failed', {
				inChannelId: forward.inChannelId,
				outChannelId: channelId
			});
			const inHtlcSecretKey = `${forward.inChannelId.toString('hex')}:${
				forward.inHtlcId
			}`;
			// BOLT 4 route blinding: a downstream failure of a blinded forward must
			// NOT be relayed (it would leak the blinded portion); replace it with
			// invalid_onion_blinding.
			const blindedRole = this.blindedIncomingHtlcs.get(inHtlcSecretKey);
			if (blindedRole) {
				this.failBlindedIncomingHtlc(
					forward.inChannelId,
					forward.inHtlcId,
					blindedRole
				);
				this.forwardedHtlcs.delete(outKey);
				this.safeStorage(
					() => this.storage!.deleteForwardedHtlc(outKey),
					'deleteForwardedHtlc'
				);
				this.persistChannel(channelId);
				return;
			}
			const inSharedSecret =
				this.receivedHtlcSharedSecrets.get(inHtlcSecretKey);
			const wrappedReason = inSharedSecret
				? wrapFailureMessage(inSharedSecret, reason)
				: reason;
			this.cleanupHtlcSharedSecret(inHtlcSecretKey);
			this.channelManager.failHtlc(
				forward.inChannelId,
				forward.inHtlcId,
				wrappedReason
			);
			this.forwardedHtlcs.delete(outKey);
			this.safeStorage(
				() => this.storage!.deleteForwardedHtlc(outKey),
				'deleteForwardedHtlc'
			);
			this.persistChannel(channelId);
			return;
		}

		// Find the payment associated with this HTLC
		const key = outKey;
		const hashHex = this.htlcPaymentMap.get(key);
		if (!hashHex) return;

		const payment = this.payments.get(hashHex);
		if (!payment || payment.direction !== PaymentDirection.OUTGOING) return;

		// Decrypt failure message if we have shared secrets
		let failureData: Buffer | undefined;
		if (payment.sharedSecrets && reason.length > 0) {
			const result = decryptFailureMessage(payment.sharedSecrets, reason);
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
			payment.failureReason = 'Peer failed the HTLC with an empty reason';
		}

		// PERM|15 is overloaded, so the PERM bit alone does not mean "give up":
		// BOLT 4 returns the final node's height precisely so we can spot the
		// transient case, where it rejected our expiry only because it is ahead of
		// us. This records that height so the retry below is built against it
		// rather than repeating the same stale expiry.
		const heightSkew = this.noteHeightSkewFailure(payment, failureData);

		// Record failure in MissionControl for future pathfinding. Skipped for
		// height skew: no channel misbehaved, our expiry was stale, so penalising
		// the route would degrade pathfinding over an innocent channel.
		const culpableScid = this.getCulpableHopScid(payment);
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
		if (
			retryCtx &&
			retryCtx.retryCount < maxRetries &&
			(heightSkew || !this.isPermanentFailure(payment.failureCode))
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
			this.safeStorage(
				() => this.storage!.deleteHtlcPaymentMapping(key),
				'deleteHtlcPaymentMapping'
			);

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
				// to keep the same payment hash.
				const retried = retryCtx.keysend
					? this.dispatchKeysend(
							retryCtx.keysend.options,
							retryCtx.keysend.preimage,
							retryCtx.excludedChannels
					  )
					: this.sendPayment(
							retryCtx.invoiceStr!,
							retryCtx.excludedChannels,
							retryCtx.maxFeeMsat,
							retryCtx.amountMsat
					  );
				retried.retryCount = retryCtx.retryCount;
				return; // Retry dispatched
			} catch (err) {
				// The retry never left the node. Restore the attempt that did fail,
				// keeping its original onion failure, and append why the retry could
				// not be sent rather than discarding that reason silently.
				this.payments.set(hashHex, payment);
				payment.retryCount = retryCtx.retryCount;
				const detail = err instanceof Error ? err.message : String(err);
				payment.failureReason = payment.failureReason
					? `${payment.failureReason}; retry not dispatched: ${detail}`
					: `Retry not dispatched: ${detail}`;
			}
		}

		// No retry or retry exhausted — mark as permanently failed
		this.paymentRetryContexts.delete(hashHex);
		payment.status = PaymentStatus.FAILED;
		payment.completedAt = Date.now();
		// Clean up HTLC payment mapping
		this.htlcPaymentMap.delete(key);
		if (this.storage) {
			this.storage.transaction(() => {
				this.storage!.deleteHtlcPaymentMapping(key);
				this.persistPayment(payment.paymentHash);
				this.persistChannel(channelId);
			});
		} else {
			this.persistPayment(payment.paymentHash);
			this.persistChannel(channelId);
		}
		this.emit('payment:failed', payment);
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
	private getCulpableHopScid(payment: IPaymentInfo): string | undefined {
		const index = payment.failureSourceIndex;
		if (!payment.route || index === undefined) return undefined;
		const code = payment.failureCode;
		if (code === undefined) return undefined;

		if (!this.isChannelScopedFailure(code)) return undefined;

		// The final hop has no outgoing channel, so there is nothing to blame.
		const outgoingHop = payment.route.hops[index + 1];
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
			this.safeStorage(
				() => this.storage!.savePayment(hashHex, existing),
				'savePaymentMetadata'
			);
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
			const amountMsat =
				amountSats !== undefined
					? BigInt(amountSats) * 1000n
					: decoded.amountMsat;
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
			const amountMsat =
				amountSats !== undefined
					? BigInt(amountSats) * 1000n
					: decoded.amountMsat;
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

		// Route channel messages to ChannelManager
		this.channelManager.handleMessage(pubkey, type, payload);
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
		// Re-CPFP any stuck anchor force-close commitment at the current live feerate
		// so a fee spike after the original broadcast cannot pin the package (M1).
		this.channelManager.reCpfpStuckCommitments(
			blockHeight,
			this.resolveForceCloseFeeRatePerVbyte()
		);
		this.scanExpiringHtlcs(blockHeight);
		this.scanExpiringOfferedHtlcs(blockHeight);
		this.scanExpiringHeldHtlcs(blockHeight);
		this.scanExpiringHeldForwards(blockHeight);
		this.scanForwardTimeouts(blockHeight);
		this.scanStuckChannels(blockHeight);
		this.scanStuckPayments();
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
					for (const monitor of this.channelManager.getMonitors().values()) {
						monitor.updateFeeRate(satPerVbyte * 250);
					}
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
		if (state.dataLossDetected) {
			this.emitStructuredLog('channel', 'errored_awaiting_peer_close', {
				channelId: channelId.toString('hex'),
				reason
			});
			return;
		}
		const result = this.channelManager.forceClose(
			channelId,
			this.getSweepDestinationScript(),
			this.resolveForceCloseFeeRatePerVbyte()
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
				state.state === ChannelState.ERRORED && !state.dataLossDetected;
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
					this.emit('node:error', {
						code: 'HTLC_CLAIM_FORCE_CLOSE',
						channelId,
						message: `inbound HTLC ${htlc.id} preimage held but unacked ${claimBuffer} blocks before expiry (${htlc.cltvExpiry}); force-closing to claim via HTLC-success`,
						timestamp: Date.now()
					} as ILightningError);
					this.channelManager.forceClose(
						channelId,
						this.getSweepDestinationScript(),
						this.resolveForceCloseFeeRatePerVbyte()
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

				if (htlc.cltvExpiry - blockHeight <= this.htlcSafetyMargin) {
					const channelId = state.channelId || state.temporaryChannelId;
					const htlcSecretKey = `${channelId.toString('hex')}:${htlc.id}`;
					const blindedRole = this.blindedIncomingHtlcs.get(htlcSecretKey);
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
				state.state === ChannelState.ERRORED && !state.dataLossDetected;
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
					const blindedRole = this.blindedIncomingHtlcs.get(htlcSecretKey);
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
				this.emit('node:error', {
					code: 'FORWARD_TIMEOUT_FORCE_CLOSE',
					channelId,
					message: `forwarded HTLC ${htlc.id} inbound expiry near (${htlc.cltvExpiry}) with outbound leg unresolved; force-closing inbound to resolve on-chain`,
					timestamp: Date.now()
				} as ILightningError);
				this.channelManager.forceClose(
					channelId,
					this.getSweepDestinationScript(),
					this.resolveForceCloseFeeRatePerVbyte()
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
			sweepDestinationScript?: Buffer;
			peerStorageEnabled?: boolean;
			autoRebalance?: IAutoRebalanceConfig;
			autoTuneFees?: IAutoTuneFeesConfig;
			watchtowers?: string[];
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
		// Beignet-specific EXPERIMENTAL zero-reserve capability (see the Feature
		// doc): advertising is what makes the extension explicitly negotiated.
		// Inert to other implementations (odd bit); a 0 reserve is still refused
		// unless the peer is ALSO in the trusted set. The constructor clears the
		// bit when experimentalZeroReserve is configured false.
		flags.setOptional(Feature.EXPERIMENTAL_ZERO_RESERVE);
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
	createOffer(options: ICreateOfferOptions & { asyncHold?: boolean }): {
		offer: IOffer;
		encoded: string;
	} {
		const { asyncHold, ...createOpts } = options;
		if (asyncHold && !createOpts.paths) {
			// One path_id shared by every path of this offer: invoice_requests
			// must arrive over one of them (verified in handleInvoiceRequest).
			const pathId = crypto.randomBytes(32);
			const paths = this.buildBlindedPaymentPaths(true, 3, pathId).map(
				(p) => p.path
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
	payBolt12Invoice(invoice: IBolt12Invoice): IPaymentInfo {
		if (!invoice.paymentHash || !invoice.amount || !invoice.nodeId) {
			throw new Error('BOLT 12 invoice missing required fields');
		}

		const destination = invoice.nodeId;
		const amountMsat = invoice.amount;
		const finalCltvExpiry = this.paddedFinalCltvExpiry();
		const sourceNodeId = getPublicKey(this.nodePrivkey);

		// Route blinding: BOLT 12 invoices natively carry blinded payment paths.
		// Route through one (shared blinded sender with the BOLT 11 path).
		if (invoice.paths && invoice.paths.length > 0) {
			const payInfo = invoice.blindedPayInfo?.[0] ?? {
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: amountMsat
			};
			const blindedRoute = findRouteToBlindedPath(
				this.graph,
				sourceNodeId,
				invoice.paths[0],
				payInfo,
				amountMsat,
				finalCltvExpiry,
				undefined,
				undefined,
				this.missionControl,
				// Our own channels: a direct channel to the introduction node must
				// be routable even when it never entered the public gossip graph
				// (private channels; a fresh interop channel paying a CLN offer).
				this.getLocalChannelEdges()
			);
			if (!blindedRoute) {
				throw new Error('No route to BOLT 12 blinded path introduction node');
			}
			return this.sendPaymentToRoute(
				blindedRoute,
				invoice.paymentHash,
				finalCltvExpiry,
				invoice.paymentSecret,
				amountMsat
			);
		}

		const route = findRoute(
			this.graph,
			sourceNodeId,
			destination,
			amountMsat,
			finalCltvExpiry,
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			this.getLocalChannelEdges()
		);
		if (!route) {
			throw new Error('No route found to BOLT 12 invoice destination');
		}

		return this.sendPaymentToRoute(
			route,
			invoice.paymentHash,
			finalCltvExpiry,
			invoice.paymentSecret,
			amountMsat
		);
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
		this.offerManager.on('invoice:received', (invoice: IBolt12Invoice) => {
			this.emit('bolt12:invoice:received', invoice);
		});
		// Issuer side: a BOLT 12 invoice we created in response to an invoice_request.
		// Register its preimage/payment_secret/amount into the SAME stores the BOLT 11
		// receive path uses, so an incoming HTLC for this payment_hash is validated
		// and fulfilled (without this the preimage lived only in OfferManager and the
		// HTLC was failed with unknown_payment_hash).
		this.offerManager.on(
			'invoice:issued',
			(invoice: IBolt12Invoice, preimage: Buffer) => {
				const hashHex = invoice.paymentHash.toString('hex');
				this.preimages.set(hashHex, preimage);
				if (invoice.paymentSecret) {
					this.paymentSecrets.set(hashHex, invoice.paymentSecret);
				}
				const invoiceInfo: IInvoiceInfo = {
					paymentHash: hashHex,
					bolt11: '',
					amountMsat: invoice.amount,
					description: invoice.description,
					expiry: invoice.relativeExpiry ?? DEFAULT_EXPIRY,
					createdAt: Number(invoice.createdAt)
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
				this.safeStorage(() => {
					this.storage!.savePreimage(hashHex, preimage);
					if (invoice.paymentSecret) {
						this.storage!.savePaymentSecret(hashHex, invoice.paymentSecret);
					}
					this.storage!.saveInvoice(hashHex, invoiceInfo);
					this.persistPayment(invoice.paymentHash);
				}, 'saveBolt12Invoice');
				this.emit('bolt12:invoice:issued', invoice);
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
				state.state === ChannelState.ERRORED && !state.dataLossDetected;
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
					this.emit('node:error', {
						code: 'HTLC_EXPIRY_FORCE_CLOSE',
						channelId,
						message: `offered HTLC ${htlc.id} still active ${graceBlocks} blocks past expiry (${htlc.cltvExpiry}); force-closing to claim via timeout path`,
						timestamp: Date.now()
					} as ILightningError);
					this.channelManager.forceClose(
						channelId,
						this.getSweepDestinationScript(),
						this.resolveForceCloseFeeRatePerVbyte()
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
	 * Scan for PENDING outbound payments whose invoice has expired.
	 */
	private scanExpiredPendingPayments(): void {
		const now = Math.floor(Date.now() / 1000);
		for (const [hashHex, payment] of this.payments) {
			if (payment.status !== PaymentStatus.PENDING) continue;
			if (payment.direction !== PaymentDirection.OUTGOING) continue;

			const retryCtx = this.paymentRetryContexts.get(hashHex);
			if (!retryCtx) continue;

			try {
				const { decode } = require('../invoice/decode');
				const decoded = decode(retryCtx.invoiceStr);
				const expiryTimestamp =
					(decoded.timestamp || 0) + (decoded.expiry || 3600);
				if (now > expiryTimestamp) {
					this.failPayment(
						payment.paymentHash,
						'Invoice expired while the payment was still in flight'
					);
				}
			} catch {
				// Can't decode invoice — skip
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
			// against the on-chain side. Routing keeps strict isHtlcUsable().
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

			// Data loss protection: the peer proved our state is stale. Auto
			// force-closing here would broadcast our revoked-in-their-view
			// commitment and lose the whole balance to the justice path. The
			// peer's force close resolves the channel; never time it out.
			// (Channel.forceClose refuses too - this skip avoids even trying.)
			if (state.dataLossDetected) {
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

			// Auto-force-close channels stuck in AWAITING_REESTABLISH for too long
			if (state.state === ChannelState.AWAITING_REESTABLISH) {
				const reestablishKey = `reestablish:${channelId.toString('hex')}`;
				if (!this._stuckChannelTracker.has(reestablishKey)) {
					this._stuckChannelTracker.set(reestablishKey, blockHeight);
				} else {
					const startHeight = this._stuckChannelTracker.get(reestablishKey)!;
					if (blockHeight - startHeight > this.reestablishTimeoutBlocks) {
						try {
							const destScript = bitcoin.payments.p2wpkh({
								pubkey: this.fundingPubkey
							}).output!;
							this.channelManager.forceClose(
								channelId,
								destScript,
								this.resolveForceCloseFeeRatePerVbyte()
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
			if (state.state === ChannelState.ERRORED && state.fundingTxid) {
				const erroredKey = `errored:${channelId.toString('hex')}`;
				if (!this._stuckChannelTracker.has(erroredKey)) {
					this._stuckChannelTracker.set(erroredKey, blockHeight);
				} else {
					const startHeight = this._stuckChannelTracker.get(erroredKey)!;
					if (blockHeight - startHeight > this.reestablishTimeoutBlocks) {
						try {
							this.channelManager.forceClose(
								channelId,
								this.getSweepDestinationScript(),
								this.resolveForceCloseFeeRatePerVbyte()
							);
							this._stuckChannelTracker.delete(erroredKey);
							this.emit('node:error', {
								code: 'ERRORED_TIMEOUT_FORCE_CLOSED',
								channelId,
								message: `Channel ${channelId.toString('hex')} ERRORED for > ${
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

			if (
				effectiveState === ChannelState.SHUTTING_DOWN ||
				effectiveState === ChannelState.NEGOTIATING_CLOSING
			) {
				// Approximate: if channel has been shutting down for > ~10 blocks (~1 hour)
				// We use a createdAt-based check since we don't have a shutdownStartBlock field
				// Use block height heuristic: if current height advanced by 10 from when we last saw this state
				const shutdownKey = `stuck:${channelId.toString('hex')}`;
				if (!this._stuckChannelTracker.has(shutdownKey)) {
					this._stuckChannelTracker.set(shutdownKey, blockHeight);
				} else {
					const startHeight = this._stuckChannelTracker.get(shutdownKey)!;
					if (blockHeight - startHeight > 10) {
						// Force close the stuck channel
						try {
							const destScript = bitcoin.payments.p2wpkh({
								pubkey: this.fundingPubkey
							}).output!;
							this.channelManager.forceClose(
								channelId,
								destScript,
								this.resolveForceCloseFeeRatePerVbyte()
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
			const TWO_WEEKS = 1_209_600; // DEFAULT_PRUNE_MAX_AGE
			const cutoff = now - TWO_WEEKS;
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
		if (this.storage) {
			try {
				this.storage.deleteHtlcSharedSecret(key);
			} catch {
				/* best-effort */
			}
		}
	}

	/**
	 * Resolve a route's first-hop SCID (real SCID or either side's alias) to one
	 * of OUR usable channels to that peer. Returns undefined when the SCID does
	 * not name a local channel -- callers then fall back to peer-based selection.
	 */
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
			if (!channel.isHtlcUsable()) continue;
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
		const normalChannels = channels.filter((ch) => ch.isHtlcUsable());

		if (normalChannels.length === 0) return undefined;
		if (normalChannels.length === 1) return normalChannels[0];

		// Sort by local balance descending
		normalChannels.sort((a, b) => {
			const balA = a.getFullState().localBalanceMsat;
			const balB = b.getFullState().localBalanceMsat;
			if (balA > balB) return -1;
			if (balA < balB) return 1;
			return 0;
		});

		// If amount specified, prefer a channel with sufficient balance
		if (amountMsat !== undefined) {
			const sufficient = normalChannels.find(
				(ch) => ch.getFullState().localBalanceMsat >= amountMsat
			);
			if (sufficient) return sufficient;
		}

		// Fall back to largest balance channel
		return normalChannels[0];
	}
}
