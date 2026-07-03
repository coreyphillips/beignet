/**
 * Lightning Node API: Top-level orchestrator.
 *
 * Wires together PeerManager (transport), ChannelManager (channels + HTLCs),
 * NetworkGraph (gossip/routing), onion (Sphinx packets), and invoice (BOLT 11)
 * into a unified Lightning node API.
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import { getPublicKey } from '../crypto/ecdh';
import {
	constructBlindedPath,
	processBlindedHop,
	deriveBlindedPrivkey,
	IBlindedHopData,
	IBlindedPaymentPath
} from '../onion/blinded-path';
import { ChannelManager } from '../channel/channel-manager';
import { Channel } from '../channel/channel';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../channel/splice-weight';
import {
	ChannelState,
	ChannelRole,
	HtlcState,
	DEFAULT_CHANNEL_CONFIG
} from '../channel/types';
import { PeerManager, IPeerInfo } from '../transport/peer-manager';
import { NetworkGraph } from '../gossip/network-graph';
import {
	findRoute,
	findMultiPathRoute,
	findRouteToBlindedPath,
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
	INodeAnnouncementMessage
} from '../gossip/types';
import {
	decodeChannelAnnouncementMessage,
	decodeNodeAnnouncementMessage,
	decodeChannelUpdateMessage
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
	extractChannelUpdate
} from '../onion/failures';
import {
	IHopPayload,
	KEYSEND_TLV_TYPE,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	FINAL_INCORRECT_CLTV_EXPIRY,
	INVALID_ONION_HMAC,
	UNKNOWN_NEXT_PEER,
	INCORRECT_CLTV_EXPIRY,
	FEE_INSUFFICIENT,
	TEMPORARY_CHANNEL_FAILURE,
	EXPIRY_TOO_SOON,
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
	IKeysendOptions
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
import { IStorageBackend } from '../storage/types';
import { FeatureFlags, Feature } from '../features/flags';
import { ChainWatcher, computeScriptHash } from '../chain/chain-watcher';
import { signP2wpkhInput } from '../chain/sweep';
import {
	satPerVbyteToSatPerKw,
	MIN_FEERATE_PER_KW,
	OutputStatus
} from '../chain/types';
import { ChainMonitor } from '../chain/chain-monitor';
import { ElectrumBackend } from '../chain/electrum-backend';
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
import { isTaprootChannel } from '../channel/types';
import { signRemoteCommitment } from '../channel/commitment-builder';
import { ChannelSigner } from '../keys/signer';
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
 * - 'message:outbound' (peerPubkey: string, type: number, payload: Buffer)
 * - 'htlc:forward' (fromChannelId: Buffer, toChannelId: Buffer, amountMsat: bigint, paymentHash: Buffer)
 * - 'peer:connect' (pubkey: string)
 * - 'peer:disconnect' (pubkey: string)
 * - 'peer:error' (pubkey: string, error: Error)
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

export class LightningNode extends EventEmitter {
	private nodePrivkey: Buffer;
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
	private forwardingCltvDelta: number;
	private forwardingFeeBaseMsat: number;
	private forwardingFeePropMillionths: number;
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
	private advertisedLeaseRates?: import('../gossip/types').ILeaseRates;
	private advertisedFforTerms?: import('../gossip/types').IFforTerms;
	private fundingPubkey: Buffer;
	private fundingProvider: IFundingProvider | null = null;
	private fundingPrivkey: Buffer;
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
	private feeEstimator: IFeeEstimator | null = null;
	private missionControl: MissionControl;
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

	constructor(config: INodeConfig) {
		super();
		this.setMaxListeners(50);

		this.nodePrivkey = config.nodePrivateKey;
		this.nodeId = getPublicKey(config.nodePrivateKey).toString('hex');
		this.network = config.network || Network.REGTEST;
		this.storage = config.storage || null;

		this.resourceConfig = {
			maxCompletedPayments:
				config.resourceConfig?.maxCompletedPayments ?? 10_000,
			completedPaymentTtlMs:
				config.resourceConfig?.completedPaymentTtlMs ?? 86_400_000,
			cleanupIntervalMs: config.resourceConfig?.cleanupIntervalMs ?? 60_000
		};

		this.htlcSafetyMargin = config.htlcSafetyMargin ?? 6;
		this.forwardingCltvDelta = config.forwardingCltvDelta ?? 40;
		this.forwardingFeeBaseMsat = config.forwardingFeeBaseMsat ?? 1000;
		this.forwardingFeePropMillionths = config.forwardingFeePropMillionths ?? 1;
		this.mppTimeoutMs = config.mppTimeoutMs ?? 60_000;
		this.alias = config.alias;
		this.advertisedLeaseRates = config.leaseRates;
		this.advertisedFforTerms = config.fforTerms;
		this.fundingPubkey = config.channelBasepoints.fundingPubkey;
		this.fundingProvider = config.fundingProvider || null;
		this.fundingPrivkey = config.fundingPrivkey;
		this.sweepDestinationScript = config.sweepDestinationScript;
		this.htlcBasepointSecret = config.htlcBasepointSecret;
		this.delayedPaymentBasepointSecret = config.delayedPaymentBasepointSecret;
		this.revocationBasepointSecret = config.revocationBasepointSecret;
		this.paymentBasepointSecret = config.paymentBasepointSecret;
		this.feeEstimator = config.feeEstimator || null;
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
			chainHash: config.chainHashes?.[0],
			nodePrivateKey: config.nodePrivateKey,
			channelKeyDeriver: config.channelKeyDeriver,
			// Liquidity ads (bLIP-51) + FFOR standing terms (§11.3): the manager
			// answers request_funds (will_fund) and enforces the advertised FFOR
			// terms against incoming ff_init.
			leaseRates: config.leaseRates,
			fforTerms: config.fforTerms
		});
		// Let the channel manager attach wallet inputs for anchor fee bumps
		// (zero-fee second-level HTLC txs and commitment CPFP).
		this.channelManager.setFundingProvider(this.fundingProvider);

		this.graph = new NetworkGraph();

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
				socks5Proxy: config.socks5Proxy
			});
			this.channelManager.attachToPeerManager(this.peerManager);
			this.registerGossipHandlers();
			this.registerOnionMessageHandler();
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

		// Restore invoices — migrate ms timestamps to seconds if needed
		for (const { paymentHashHex, invoice } of this.storage.loadAllInvoices()) {
			if (invoice.createdAt > 10_000_000_000) {
				invoice.createdAt = Math.floor(invoice.createdAt / 1000);
			}
			this.invoices.set(paymentHashHex, invoice);
			// Rebuild the hold-invoice set so incoming HTLCs are parked, not settled.
			if (invoice.hold) {
				this.heldInvoiceHashes.add(paymentHashHex);
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
					.then((satPerVbyte) => {
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
		this.channelManager.on('channel:ready', (channelId: Buffer) => {
			this.registerChannelAliases(channelId);
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
		});

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
			}
		);

		this.channelManager.on(
			'htlc:failed',
			(channelId: Buffer, htlcId: bigint, reason: Buffer) => {
				this.handleHtlcFailed(channelId, htlcId, reason);
			}
		);

		this.channelManager.on(
			'error',
			(channelId: Buffer | null, message: string) => {
				const err: ILightningError = {
					code: 'CHANNEL_ERROR',
					channelId: channelId ?? undefined,
					message,
					timestamp: Date.now()
				};
				this.emit('node:error', err);
			}
		);

		// Auto-funding: build funding tx when accept_channel is received
		this.channelManager.on(
			'channel:accepted',
			(channel: Channel, peerPubkey: string) => {
				if (!this.fundingProvider) return;
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
				// Sign the channel_update before broadcasting (it arrives with a placeholder signature)
				let signedChannelUpdate = channelUpdate;
				try {
					const sig = signChannelUpdate(channelUpdate, this.nodePrivkey);
					// Write real signature into first 64 bytes of the channel_update payload
					signedChannelUpdate = Buffer.from(channelUpdate);
					sig.copy(signedChannelUpdate, 0);
				} catch {
					// If signing fails, use the original (will likely be rejected by peers)
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
		return (data: Buffer) => {
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

	private wirePeerManagerEvents(): void {
		if (!this.peerManager) return;
		this.peerManager.on('peer:connect', (pubkey: string) => {
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

		// Use dynamic fee if estimator available
		const feePromise = this.feeEstimator
			? this.feeEstimator.estimateFee(6).then((f) => (f > 0 ? f : undefined))
			: Promise.resolve(undefined);

		feePromise
			.then((satsPerByte) =>
				this.fundingProvider!.buildFundingTransaction(
					address,
					state.fundingSatoshis,
					satsPerByte
				)
			)
			.then(({ txHex, txid, outputIndex }) => {
				// Set funding outpoint on state before signing (required for commitment building)
				state.fundingTxid = txid;
				state.fundingOutputIndex = outputIndex;

				// Sign the remote's initial commitment (use channel signer for per-channel keys)
				const signer =
					channel.getSigner() ||
					new ChannelSigner(this.fundingPrivkey, this.htlcBasepointSecret);
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
			});
	}

	// ─────────────── Node Info ───────────────

	getNodeId(): string {
		return this.nodeId;
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
				feeRatePerVbyte = await this.feeEstimator.estimateFee(6);
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

	async connectPeer(pubkey: string, host: string, port: number): Promise<void> {
		if (!this.peerManager) {
			throw new Error('Networking is not enabled');
		}
		const pubkeyErr = validateHexPubkey(pubkey, 'pubkey');
		if (pubkeyErr) throw new Error(pubkeyErr);
		const hostErr = validateHost(host);
		if (hostErr) throw new Error(hostErr);
		const portErr = validatePort(port);
		if (portErr) throw new Error(portErr);
		await this.peerManager.connectPeer(pubkey, host, port);
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
	 * Stop listening for inbound connections.
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

			// Build the funding P2WSH script from the channel's pubkeys
			if (!state.remoteBasepoints) continue;
			const { p2wshOutput } = createFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints.fundingPubkey,
				btcNetwork
			);

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
				p2wshOutput
			);
		}
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
		// Clear reconnect timers
		for (const t of this._reconnectTimers) {
			clearTimeout(t);
		}
		this._reconnectTimers.clear();
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

		// Phase 3: Clean stale htlcPaymentMap entries
		for (const [key, hashHex] of this.htlcPaymentMap) {
			if (!this.payments.has(hashHex)) {
				this.htlcPaymentMap.delete(key);
			}
		}

		return pruned;
	}

	// ─────────────── Channel Management ───────────────

	openChannel(
		peerPubkey: string,
		fundingSatoshis: bigint,
		pushMsat?: bigint
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
		return this.channelManager.openChannel(
			peerPubkey,
			fundingSatoshis,
			pushMsat
		);
	}

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
			maxLeaseRates: params.maxLeaseRates
		};

		return this.channelManager.createDualFundedChannel(peerPubkey, dualParams);
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
	 */
	spliceOut(
		channelId: Buffer,
		amountSats: bigint,
		fundingFeeratePerkw = 253
	): { ok: boolean; error?: string } {
		const cidErr = validateBuffer(channelId, 32, 'channelId');
		if (cidErr) throw new Error(cidErr);
		const satsErr = validatePositiveBigint(amountSats, 'amountSats');
		if (satsErr) throw new Error(satsErr);

		const channel = this.channelManager.getChannel(channelId);
		if (!channel) {
			return {
				ok: false,
				error: `Channel not found: ${channelId.toString('hex')}`
			};
		}

		const destinationScript = this.getSweepDestinationScript();

		// Sanity checks before any protocol message goes out: dust amount, peer
		// support, and spendable channel balance.
		const fee = spliceFeeSats(
			estimateSpliceTxWeight({
				walletInputCount: 0,
				destinationScriptLen: destinationScript.length
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

		// Record where the withdrawn funds are paid (a wallet-owned script) before
		// initiating, so the interactive-tx driver can add the destination output.
		channel.setSpliceOutDestination(destinationScript, amountSats);

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
			return {
				channelId: channelIdHex,
				state: ch.state as string,
				localBalanceMsat: ch.localBalanceMsat,
				remoteBalanceMsat: ch.remoteBalanceMsat,
				capacitySats: Number(ch.fundingSatoshis),
				peerPubkey: ch.peerPubkey,
				stuckBlocks
			};
		});
		return this.liquidityAdvisor.analyze(snapshots);
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
			peerPubkey: this.channelManager.getPeerForChannel(channelId) ?? '',
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

	private registerChannelAliases(channelId: Buffer): void {
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
				Buffer.from(this.alias, 'utf8').copy(
					aliasBuffer,
					0,
					0,
					Math.min(32, Buffer.byteLength(this.alias, 'utf8'))
				);
			}
			const payload = encodeNodeAnnouncementMessage({
				signature: Buffer.alloc(64), // placeholder — signed below
				features: Buffer.alloc(0),
				timestamp,
				nodeId,
				rgbColor: Buffer.from([0, 0, 0]),
				alias: aliasBuffer,
				addresses: [],
				// Liquidity ads (bLIP-51) + FFOR standing terms (§11.3): a node
				// selling inbound liquidity advertises both side by side.
				leaseRates: this.advertisedLeaseRates,
				fforTerms: this.advertisedFforTerms
			});
			const sig = signNodeAnnouncement(payload, this.nodePrivkey);
			sig.copy(payload, 0);
			return payload;
		} catch {
			return null;
		}
	}

	/**
	 * Refresh a cached channel_update: bump only its timestamp and re-sign, keeping
	 * the exact same policy (fees/CLTV/flags/SCID). This is a pure gossip message —
	 * it never touches the commitment state machine, HTLCs or update_fee, so it
	 * cannot trigger a force-close. Returns null if decode/encode/sign fails.
	 */
	private refreshChannelUpdate(
		cachedUpdate: Buffer,
		timestamp: number
	): Buffer | null {
		try {
			const { encodeChannelUpdateMessage } = require('../gossip/messages');
			const msg = decodeChannelUpdateMessage(cachedUpdate);
			msg.timestamp = timestamp;
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
				const refreshedUpdate = this.refreshChannelUpdate(gossip.update, now);
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
		const channels = this.channelManager.listChannels();

		for (const channel of channels) {
			const state = channel.getFullState();
			// Use preReestablishState for channels awaiting reestablish after restart —
			// the SCID and peer info are still valid for routing hints
			const effectiveState = state.preReestablishState ?? channel.getState();
			if (effectiveState !== ChannelState.NORMAL) continue;

			// Emit a hint for EVERY usable channel — private AND public. Relying on
			// gossip for public channels (LND's behaviour) is too fragile for a
			// wallet/agent node: a freshly-announced channel often hasn't propagated
			// to the payer's graph yet, so without a hint the invoice is unpayable
			// even though the channel is healthy. Including a hint for an
			// already-propagated public channel is harmless (the payer dedupes it).
			const channelId = channel.getChannelId();
			if (!channelId) continue;

			const peerPubkeyHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerPubkeyHex) continue;

			// SCID for the peer→us hop = the SCID the peer uses to forward HTLCs to
			// us. Per option_scid_alias the alias WE sent in channel_ready is what
			// the peer accepts for incoming HTLCs to us, so use the real SCID (once
			// confirmed) or OUR own scidAlias — NOT remoteScidAlias (the peer's
			// alias, which we use to route to them, the wrong direction).
			const scid = state.shortChannelId || state.scidAlias;
			if (!scid) continue;

			const peerPubkey = Buffer.from(peerPubkeyHex, 'hex');

			// Advertise the PEER's actual fee/CLTV policy for the peer→us direction,
			// not our own forwarding defaults. The peer is the forwarding node for
			// this hop, so the hint must match what it really requires — otherwise it
			// rejects the HTLC (e.g. incorrect_cltv_expiry / fee insufficient). For a
			// public channel the peer's channel_update is in our graph; look it up and
			// use it. Fall back to our defaults only when it isn't available (e.g. a
			// private channel that was never announced).
			let feeBaseMsat = this.forwardingFeeBaseMsat;
			let feeProportionalMillionths = this.forwardingFeePropMillionths;
			let cltvExpiryDelta = this.forwardingCltvDelta;
			if (state.shortChannelId) {
				const graphChannel = this.graph.getChannel(state.shortChannelId);
				const peerUpdate = graphChannel?.nodeId1.equals(peerPubkey)
					? graphChannel.update1
					: graphChannel?.nodeId2.equals(peerPubkey)
					? graphChannel.update2
					: undefined;
				if (peerUpdate) {
					feeBaseMsat = peerUpdate.feeBaseMsat;
					feeProportionalMillionths = peerUpdate.feeProportionalMillionths;
					cltvExpiryDelta = peerUpdate.cltvExpiryDelta;
				}
			}

			const hop: IRoutingHintHop = {
				pubkey: peerPubkey,
				shortChannelId: scid,
				feeBaseMsat,
				feeProportionalMillionths,
				cltvExpiryDelta
			};

			hints.push([hop]);
		}

		return hints;
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
		numHops = 3
	): IBlindedPaymentPath[] {
		const paths: IBlindedPaymentPath[] = [];
		const ourNodeId = getPublicKey(this.nodePrivkey);
		// Generous absolute CLTV bound for the path's payment constraints.
		const maxCltvExpiry = (this.currentBlockHeight || 0) + 2016;

		for (const channel of this.channelManager.listChannels()) {
			const state = channel.getFullState();
			const effectiveState = state.preReestablishState ?? channel.getState();
			if (effectiveState !== ChannelState.NORMAL) continue;

			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peerPubkeyHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerPubkeyHex) continue;
			const scid = state.shortChannelId || state.scidAlias;
			if (!scid) continue;
			const peerPubkey = Buffer.from(peerPubkeyHex, 'hex');

			// Peer's actual policy for the peer→us hop (same logic as routing hints).
			let feeBaseMsat = this.forwardingFeeBaseMsat;
			let feeProportionalMillionths = this.forwardingFeePropMillionths;
			let cltvExpiryDelta = this.forwardingCltvDelta;
			if (state.shortChannelId) {
				const graphChannel = this.graph.getChannel(state.shortChannelId);
				const peerUpdate = graphChannel?.nodeId1.equals(peerPubkey)
					? graphChannel.update1
					: graphChannel?.nodeId2.equals(peerPubkey)
					? graphChannel.update2
					: undefined;
				if (peerUpdate) {
					feeBaseMsat = peerUpdate.feeBaseMsat;
					feeProportionalMillionths = peerUpdate.feeProportionalMillionths;
					cltvExpiryDelta = peerUpdate.cltvExpiryDelta;
				}
			}

			const paymentConstraints = { maxCltvExpiry, htlcMinimumMsat: 0n };
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
			// Final hop (us): recipient, no onward forwarding.
			const finalHop: IBlindedHopData = { paymentConstraints };

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
			mgr = new GossipSyncManager(this.graph);
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
		if (this.graph.applyNodeAnnouncement(msg)) {
			const node = this.graph.getNode(msg.nodeId);
			if (node)
				this.safeStorage(
					() => this.storage!.saveGossipNode(msg.nodeId.toString('hex'), node),
					'saveGossipNode'
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
			const receivableNormal = allChannels.some((ch) => {
				const st = ch.getFullState();
				const effState = st.preReestablishState ?? ch.getState();
				return effState === ChannelState.NORMAL;
			});
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
			routingHints:
				!useBlinded && routingHints.length > 0 ? routingHints : undefined,
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
			if (channel.getState() !== ChannelState.NORMAL) continue;
			const channelId = channel.getChannelId();
			if (!channelId) continue;
			const peerHex = this.channelManager.getPeerForChannel(channelId);
			if (!peerHex) continue;
			const st = channel.getFullState();
			const scid = st.shortChannelId ?? st.scidAlias;
			if (!scid) continue;
			if (st.localBalanceMsat <= 0n) continue;
			edges.push({
				shortChannelId: scid,
				peer: Buffer.from(peerHex, 'hex'),
				// Upper-bound capacity for the routing gate; the actual outgoing
				// channel selection and HTLC add enforce reserve/in-flight limits.
				outboundMsat: st.localBalanceMsat
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
				createdAt: Date.now(),
				completedAt: Date.now()
			};
			this.payments.set(invoice.paymentHash.toString('hex'), payment);
			this.emit('payment:failed', payment);
			return payment;
		}

		const finalCltvExpiry =
			invoice.minFinalCltvExpiry ?? DEFAULT_MIN_FINAL_CLTV_EXPIRY;
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
		if (!route && invoice.paymentSecret) {
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
		const baseHeight = this.currentBlockHeight;

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
					// (derived from encrypted payment_relay). The final hop keeps them.
					if (!isFinal) {
						payload.omitForwardAmounts = true;
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

		// Find outgoing channel to first hop (smart selection by balance, Fix 3.3)
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

		// Create payment info BEFORE addHtlc because in synchronous loopback
		// the entire fulfill chain runs during addHtlc
		const payment: IPaymentInfo = {
			paymentHash,
			amountMsat: amount,
			status: PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
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
			this.emit('payment:failed', payment);
		}

		return payment;
	}

	/**
	 * Send a keysend (spontaneous) payment — bLIP-0003.
	 *
	 * The sender generates a random preimage, includes it in the final hop
	 * via TLV type 5482373484, and the recipient extracts + verifies it.
	 */
	sendKeysend(options: IKeysendOptions): IPaymentInfo {
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

		// Generate random preimage and compute payment hash
		const preimage = crypto.randomBytes(32);
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

		const finalCltvExpiry = DEFAULT_MIN_FINAL_CLTV_EXPIRY;
		const sourceNodeId = getPublicKey(this.nodePrivkey);

		const route = findRoute(
			this.graph,
			sourceNodeId,
			destination,
			amountMsat,
			finalCltvExpiry,
			undefined,
			undefined,
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

		const hops = route.hops;
		// Route CLTVs are relative deltas; the wire needs absolute (height + delta).
		const baseHeight = this.currentBlockHeight;

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
			const baseHeight = this.currentBlockHeight;

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
				// Rollback all previously dispatched parts
				for (const dispatched of mppState.parts) {
					if (dispatched.status === PaymentStatus.PENDING) {
						this.channelManager.failHtlc(
							dispatched.channelId,
							dispatched.htlcId,
							createFailureMessage(Buffer.alloc(32), TEMPORARY_CHANNEL_FAILURE)
						);
					}
				}
				// Part failed to dispatch — mark payment failed
				payment.status = PaymentStatus.FAILED;
				payment.completedAt = Date.now();
				this.outboundMppPayments.delete(hashHex);
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

		// Keysend: extract preimage from custom TLV records (bLIP-0003)
		const keysendPreimage = hopPayload?.customRecords?.get(KEYSEND_TLV_TYPE);
		if (keysendPreimage) {
			if (keysendPreimage.length !== 32) {
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
					  )
					: Buffer.alloc(290);
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
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
					  )
					: Buffer.alloc(290);
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
						INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
				  )
				: Buffer.alloc(290);
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
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
					  )
					: Buffer.alloc(290);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
		}

		// Validate the HTLC CLTV at the final hop (BOLT 4). Two checks:
		//  1. final_incorrect_cltv_expiry: the on-chain HTLC cltv_expiry must equal
		//     the outgoing_cltv_value the sender put in the onion. A mismatch means
		//     a hop tampered with the timeout.
		//  2. expiry-too-soon: the cltv_expiry must leave at least min_final_cltv
		//     blocks before it expires, or we could reveal the preimage yet fail to
		//     claim the HTLC on-chain in time (payer reclaims after learning it).
		//     Reported as INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS per modern BOLT 4
		//     (avoid leaking which condition failed).
		if (incomingCltvExpiry !== undefined) {
			if (
				hopPayload?.outgoingCltvValue !== undefined &&
				incomingCltvExpiry !== hopPayload.outgoingCltvValue
			) {
				this.emitStructuredLog('htlc', 'final_incorrect_cltv', {
					paymentHash: hashHex,
					htlcCltv: incomingCltvExpiry,
					onionCltv: hopPayload.outgoingCltvValue
				});
				const reason = sharedSecret
					? createFailureMessage(sharedSecret, FINAL_INCORRECT_CLTV_EXPIRY)
					: Buffer.alloc(290);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
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
				const reason = sharedSecret
					? createFailureMessage(
							sharedSecret,
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
					  )
					: Buffer.alloc(290);
				this.cleanupHtlcSharedSecret(htlcSecretKey);
				this.channelManager.failHtlc(channelId, htlcId, reason);
				return;
			}
		}

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
							INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
					  )
					: Buffer.alloc(290);
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
		}
		this.emitStructuredLog('payment', 'received', {
			paymentHash: hashHex,
			held: 'true'
		});
		return true;
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
			const reason = ss
				? createFailureMessage(ss, failureCode)
				: Buffer.alloc(290);
			this.cleanupHtlcSharedSecret(key);
			this.channelManager.failHtlc(h.channelId, h.htlcId, reason);
		}

		this.heldHtlcs.delete(hashHex);
		this.heldInvoiceHashes.delete(hashHex);
		this.persistHeldHtlcs();
		this.emitStructuredLog('htlc', 'held_cancelled', { paymentHash: hashHex });
		return true;
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
							: Buffer.alloc(290);
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
					const relayFee =
						BigInt(relay.feeBaseMsat) +
						(incomingAmountMsat * BigInt(relay.feeProportionalMillionths)) /
							1_000_000n;
					blindedOutAmount = incomingAmountMsat - relayFee;
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

		if (!outgoingScid) {
			this.cleanupHtlcSharedSecret(inHtlcSecretKey);
			this.channelManager.failHtlc(
				inChannelId,
				inHtlcId,
				createFailureMessage(sharedSecret, UNKNOWN_NEXT_PEER)
			);
			return;
		}

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
				incomingCltvExpiry - forwardCltv < this.forwardingCltvDelta ||
				(blindedMaxCltv !== undefined && incomingCltvExpiry > blindedMaxCltv)
			) {
				this.cleanupHtlcSharedSecret(inHtlcSecretKey);
				this.channelManager.failHtlc(
					inChannelId,
					inHtlcId,
					createFailureMessage(sharedSecret, INCORRECT_CLTV_EXPIRY)
				);
				return;
			}
		} else {
			// CLTV delta enforcement: incoming CLTV must exceed outgoing by our delta
			if (incomingCltvExpiry < forwardCltv + this.forwardingCltvDelta) {
				this.cleanupHtlcSharedSecret(inHtlcSecretKey);
				this.channelManager.failHtlc(
					inChannelId,
					inHtlcId,
					createFailureMessage(sharedSecret, INCORRECT_CLTV_EXPIRY)
				);
				return;
			}
			// Fee enforcement: incoming amount must cover outgoing amount + our fee
			const requiredFee =
				BigInt(this.forwardingFeeBaseMsat) +
				(forwardAmount * BigInt(this.forwardingFeePropMillionths)) / 1_000_000n;
			if (incomingAmountMsat < forwardAmount + requiredFee) {
				this.cleanupHtlcSharedSecret(inHtlcSecretKey);
				this.channelManager.failHtlc(
					inChannelId,
					inHtlcId,
					createFailureMessage(sharedSecret, FEE_INSUFFICIENT)
				);
				return;
			}
		}

		// Look up outgoing channel via SCID (real SCID for blinded hops)
		const scidHex = outgoingScid.toString('hex');
		const outChannelId = this.scidToChannelId.get(scidHex);
		if (!outChannelId) {
			this.cleanupHtlcSharedSecret(inHtlcSecretKey);
			this.channelManager.failHtlc(
				inChannelId,
				inHtlcId,
				createFailureMessage(sharedSecret, UNKNOWN_NEXT_PEER)
			);
			return;
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
				// Forward failed — fail the incoming HTLC back
				this.forwardedHtlcs.delete(outKey);
				this.cleanupHtlcSharedSecret(inHtlcSecretKey);
				this.channelManager.failHtlc(
					inChannelId,
					inHtlcId,
					createFailureMessage(sharedSecret, TEMPORARY_CHANNEL_FAILURE)
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
					this.cleanupHtlcSharedSecret(inHtlcSecretKey);
					this.channelManager.failHtlc(
						inChannelId,
						inHtlcId,
						createFailureMessage(sharedSecret, UNKNOWN_NEXT_PEER)
					);
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
			if (retryCtx) {
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

	private handleHtlcFailed(
		channelId: Buffer,
		htlcId: bigint,
		reason: Buffer
	): void {
		// Check if this is a forwarded HTLC — wrap and propagate failure upstream
		const outKey = `${channelId.toString('hex')}:offered-${htlcId}`;
		const forward = this.forwardedHtlcs.get(outKey);
		if (forward) {
			const inHtlcSecretKey = `${forward.inChannelId.toString('hex')}:${
				forward.inHtlcId
			}`;
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
			}
		}

		// Record failure in MissionControl for future pathfinding
		if (payment.route && payment.failureSourceIndex !== undefined) {
			const failingHop = payment.route.hops[payment.failureSourceIndex];
			if (failingHop) {
				this.missionControl.recordFailure(
					failingHop.shortChannelId.toString('hex'),
					payment.amountMsat
				);
			}
		}

		// Extract and apply embedded channel_update from failure data
		if (
			payment.failureCode !== undefined &&
			failureData &&
			failureData.length > 0
		) {
			const updatePayload = extractChannelUpdate(
				payment.failureCode,
				failureData
			);
			if (updatePayload && updatePayload.length > 0) {
				try {
					const update = decodeChannelUpdateMessage(updatePayload);
					if (update && this.graph) {
						this.graph.applyChannelUpdate(update);
					}
				} catch {
					// Invalid channel_update — ignore silently
				}
			}
		}

		// Attempt payment retry for temporary failures
		const retryCtx = this.paymentRetryContexts.get(hashHex);
		const maxRetries = retryCtx?.maxRetries ?? this.maxPaymentRetries;
		if (
			retryCtx &&
			retryCtx.retryCount < maxRetries &&
			!this.isPermanentFailure(payment.failureCode)
		) {
			// Exclude the failing channel's SCID from future routes
			if (payment.route && payment.failureSourceIndex !== undefined) {
				const failingHop = payment.route.hops[payment.failureSourceIndex];
				if (failingHop) {
					retryCtx.excludedChannels.add(
						failingHop.shortChannelId.toString('hex')
					);
				}
			}

			// First-hop diversification: also exclude previous first hop on retries
			if (
				retryCtx.retryCount > 0 &&
				payment.route &&
				payment.route.hops.length > 0
			) {
				retryCtx.excludedChannels.add(
					payment.route.hops[0].shortChannelId.toString('hex')
				);
			}

			retryCtx.retryCount++;
			payment.retryCount = retryCtx.retryCount;

			// Reset payment status for retry
			payment.status = PaymentStatus.PENDING;
			payment.failureCode = undefined;
			payment.failureSourceIndex = undefined;
			payment.completedAt = undefined;

			try {
				this.sendPayment(
					retryCtx.invoiceStr,
					retryCtx.excludedChannels,
					retryCtx.maxFeeMsat,
					retryCtx.amountMsat
				);
				return; // Retry initiated successfully
			} catch {
				// Retry failed (e.g. no alternative route) — fall through to mark as failed
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
	): { success: boolean; feeSats?: number; hops?: number } {
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
				hops: route.hops.length
			};
		} catch {
			return { success: false };
		}
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
		if (this.feeEstimator) {
			this.feeEstimator
				.estimateFee(6)
				.then((satPerVbyte) => {
					if (satPerVbyte > 0) {
						this.feeAdvisor.recordSample(satPerVbyte);
						// Feed the live rate to every active monitor so the RBF
						// re-bump floor tracks the market. Monitors created
						// mid-session (funding spend detected by the watcher)
						// otherwise keep their build-time rate forever.
						// updateFeeRate expects sat/kw: 1 sat/vB = 250 sat/kw.
						for (const monitor of this.channelManager.getMonitors().values()) {
							monitor.updateFeeRate(satPerVbyte * 250);
						}
					}
				})
				.catch(() => {
					/* best-effort; force-close falls back to the default feerate */
				});
		}
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
			if (effectiveState !== ChannelState.NORMAL) continue;

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
				const haveClaim =
					htlc.state === HtlcState.FULFILLED ||
					(paymentHashHex !== undefined && this.preimages.has(paymentHashHex));
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

				if (htlc.cltvExpiry - blockHeight <= this.htlcSafetyMargin) {
					const channelId = state.channelId || state.temporaryChannelId;
					const htlcSecretKey = `${channelId.toString('hex')}:${htlc.id}`;
					const htlcSharedSecret =
						this.receivedHtlcSharedSecrets.get(htlcSecretKey);
					const reason = htlcSharedSecret
						? createFailureMessage(htlcSharedSecret, EXPIRY_TOO_SOON)
						: Buffer.alloc(290);
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
			if (state.state !== ChannelState.NORMAL) continue;
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

				if (outgoingFailed) {
					// Safe: complete the failure upstream off-chain.
					const htlcSecretKey = `${channelId.toString('hex')}:${htlc.id}`;
					const sharedSecret =
						this.receivedHtlcSharedSecrets.get(htlcSecretKey);
					const reason = sharedSecret
						? createFailureMessage(sharedSecret, EXPIRY_TOO_SOON)
						: Buffer.alloc(290);
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
			fundingProvider?: IFundingProvider;
			feeEstimator?: IFeeEstimator;
			socks5Proxy?: { host: string; port: number };
			preferAnchors?: boolean;
			chainBackend?: import('../chain/chain-watcher').IChainBackend;
			autoReconnect?: boolean;
			autoUpdateChannelFees?: boolean;
			sweepDestinationScript?: Buffer;
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
			channelKeyDeriver = (channelIndex: number) => {
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
			localFeatures: options?.localFeatures,
			chainHashes: options?.chainHashes,
			alias: options?.alias,
			fundingProvider: options?.fundingProvider,
			feeEstimator: options?.feeEstimator,
			socks5Proxy: options?.socks5Proxy,
			preferAnchors: options?.preferAnchors,
			chainBackend: options?.chainBackend,
			sweepDestinationScript: options?.sweepDestinationScript,
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
			const paths = this.buildBlindedPaymentPaths(true).map((p) => p.path);
			if (paths.length > 0) {
				createOpts.paths = paths;
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
		const finalCltvExpiry = DEFAULT_MIN_FINAL_CLTV_EXPIRY;
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
				this.missionControl
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
			if (effectiveState !== ChannelState.NORMAL) continue;
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
						this.failPayment(Buffer.from(hashHex, 'hex'));
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
				// the timeout path before that window closes.
				if (
					blockHeight >=
					htlc.cltvExpiry + LightningNode.OFFERED_HTLC_FORCE_CLOSE_GRACE_BLOCKS
				) {
					this.emit('node:error', {
						code: 'HTLC_EXPIRY_FORCE_CLOSE',
						channelId,
						message: `offered HTLC ${htlc.id} still active ${LightningNode.OFFERED_HTLC_FORCE_CLOSE_GRACE_BLOCKS} blocks past expiry (${htlc.cltvExpiry}); force-closing to claim via timeout path`,
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
	failPayment(paymentHash: Buffer): void {
		const hashHex = paymentHash.toString('hex');
		const payment = this.payments.get(hashHex);
		if (!payment || payment.status !== PaymentStatus.PENDING) return;

		payment.status = PaymentStatus.FAILED;
		payment.completedAt = Date.now();
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
			this.failPayment(payment.paymentHash);
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
					this.failPayment(payment.paymentHash);
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
				this.failPayment(invoice.paymentHash);
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
			if (
				state.state !== ChannelState.NORMAL &&
				state.state !== ChannelState.AWAITING_REESTABLISH
			)
				continue;
			localBalanceMsat += state.localBalanceMsat;
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
	 */
	private scanStuckChannels(blockHeight: number): void {
		const channels = this.channelManager.listChannels();
		for (const channel of channels) {
			const state = channel.getFullState();
			const channelId = state.channelId || state.temporaryChannelId;

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

		const satPerVbyte = await this.feeEstimator.estimateFee(6);
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
		if (this.storage) {
			try {
				this.storage.deleteHtlcSharedSecret(key);
			} catch {
				/* best-effort */
			}
		}
	}

	private findChannelForPeer(
		peerPubkeyHex: string,
		amountMsat?: bigint
	): Channel | undefined {
		const channels = this.channelManager.getChannelsByPeer(peerPubkeyHex);
		const normalChannels = channels.filter(
			(ch) => ch.getState() === ChannelState.NORMAL
		);

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
