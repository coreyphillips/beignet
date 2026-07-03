/**
 * BOLT Node API: Types and configuration.
 *
 * Defines the interfaces and enums for the LightningNode orchestrator,
 * including node config, payment tracking, invoice creation, and
 * channel/node info queries.
 */

import { Network } from '../invoice/types';
import { IChannelConfig, ChannelState } from '../channel/types';
import { IChannelBasepoints } from '../keys/derivation';
import { IRoute } from '../gossip/types';
import { FeatureFlags } from '../features/flags';
import { IStorageBackend, IInvoiceInfo } from '../storage/types';
import { IChainBackend } from '../chain/chain-watcher';
import { IPerChannelKeys } from '../channel/channel-manager';

export type { IInvoiceInfo };

export interface IResourceConfig {
	/** Maximum completed/failed payments to retain (default 10_000) */
	maxCompletedPayments?: number;
	/** TTL for completed payments in ms (default 86_400_000 = 24h) */
	completedPaymentTtlMs?: number;
	/** Cleanup interval in ms (default 60_000 = 1 min) */
	cleanupIntervalMs?: number;
}

export interface IFeeEstimator {
	/** Estimate fee in sat/vByte for a given confirmation target. Returns -1 if unavailable. */
	estimateFee(targetBlocks: number): Promise<number>;
}

export interface IFundingProvider {
	buildFundingTransaction(
		address: string,
		amountSats: bigint,
		satsPerByte?: number
	): Promise<{ txHex: string; txid: Buffer; outputIndex: number }>;

	broadcastTransaction(txHex: string): Promise<string>;

	/**
	 * Splice-in only (optional): select wallet UTXOs covering `amountSats` plus
	 * fees and return them as splice inputs (each with its prevTx, value and a
	 * witness-signing closure) along with a change script. Required for
	 * `node.spliceIn` to fund the channel increase from the on-chain wallet.
	 */
	selectSpliceInputs?(
		amountSats: bigint,
		feeratePerKw: number
	): Promise<{
		inputs: import('../channel/channel').ISpliceWalletInput[];
		changeScript: Buffer;
	}>;

	/**
	 * Anchor fee-bumping (optional): select wallet UTXOs to fund a fee bump and
	 * return them (each with prevTx, value and a witness-signing closure) plus a
	 * change script. Used to attach a fee input to a zero-fee second-level HTLC
	 * tx, or to build a CPFP child that spends a commitment's local anchor.
	 *
	 * `targetFeeSats` is the fee the bumped transaction must pay EXCLUDING the
	 * wallet's own added inputs and change output — the provider accounts for the
	 * marginal weight of those itself. The caller (chain layer) finalises the
	 * change amount from the fully-assembled transaction.
	 */
	selectFeeBumpInputs?(
		targetFeeSats: bigint,
		feeratePerKw: number
	): Promise<{
		inputs: import('../channel/channel').ISpliceWalletInput[];
		changeScript: Buffer;
	}>;
}

export interface INodeConfig {
	nodePrivateKey: Buffer;
	network?: Network;
	channelConfig?: IChannelConfig;
	channelBasepoints: IChannelBasepoints;
	perCommitmentSeed: Buffer;
	fundingPrivkey: Buffer;
	/** HTLC basepoint secret for signing HTLC second-level transactions */
	htlcBasepointSecret?: Buffer;
	/** Revocation basepoint secret for penalty sweeps */
	revocationBasepointSecret?: Buffer;
	/** Payment basepoint secret for to_remote claims */
	paymentBasepointSecret?: Buffer;
	/** Delayed payment basepoint secret for to_local claims */
	delayedPaymentBasepointSecret?: Buffer;
	/** Funding provider for auto-funding channels (builds + broadcasts funding tx) */
	fundingProvider?: IFundingProvider;
	/** Enable PeerManager networking (default false — backward compatible) */
	enableNetworking?: boolean;
	/** Features to advertise in init messages */
	localFeatures?: FeatureFlags;
	/** Chain hashes for init messages */
	chainHashes?: Buffer[];
	/** Enable auto-reconnection (default false) */
	autoReconnect?: boolean;
	/** Max reconnect delay in ms */
	maxReconnectDelay?: number;
	/** Resource management config */
	resourceConfig?: IResourceConfig;
	/** Storage backend for persistence */
	storage?: IStorageBackend;
	/** Chain backend for blockchain monitoring (Electrum, Esplora, etc.) */
	chainBackend?: IChainBackend;
	/** HTLC safety margin in blocks before force-failing expiring HTLCs (default 6) */
	htlcSafetyMargin?: number;
	/** CLTV delta for forwarding (default 40) */
	forwardingCltvDelta?: number;
	/** Base fee in msat for forwarding (default 1000) */
	forwardingFeeBaseMsat?: number;
	/** Proportional fee in millionths for forwarding (default 1) */
	forwardingFeePropMillionths?: number;
	/** MPP partial payment timeout in ms (default 60000) */
	mppTimeoutMs?: number;
	/** Human-readable node alias (max 32 bytes UTF-8, per BOLT 7) */
	alias?: string;
	/**
	 * Liquidity ads (bLIP-0051): advertise these lease rates in our
	 * node_announcement (node_ann_tlvs type 1, option_will_fund).
	 */
	leaseRates?: import('../gossip/types').ILeaseRates;
	/**
	 * FFOR standing terms (specs/ffor-offline-receive.md section 11.3):
	 * advertised alongside the lease rates (node_ann_tlvs type 55007).
	 */
	fforTerms?: import('../gossip/types').IFforTerms;
	/** SOCKS5 proxy for outbound peer connections (e.g. Tor on 127.0.0.1:9050) */
	socks5Proxy?: { host: string; port: number };
	/** Prefer anchor channels (option_anchors_zero_fee_htlc_tx) when opening channels */
	preferAnchors?: boolean;
	/**
	 * EXPERIMENTAL — propose simple taproot channels (option_taproot). Negotiates
	 * the channel type + MuSig2 nonces on open/accept, but the commitment-round
	 * signing (nonce rotation) is not yet wired into the live state machine, so
	 * funding cannot complete. Off by default.
	 */
	preferTaproot?: boolean;
	/** Fee estimator for dynamic fee rates */
	feeEstimator?: IFeeEstimator;
	/** Maximum payment retries (default 3) */
	maxPaymentRetries?: number;
	/** Global HTLC limit across all channels (default 1000) */
	maxTotalInFlightHtlcs?: number;
	/** Starting channel key index (for per-channel HD derivation) */
	nextChannelIndex?: number;
	/** Per-channel key derivation callback — produces unique keys per channel index */
	channelKeyDeriver?: (channelIndex: number) => IPerChannelKeys;
	/** Per-peer rate limit config */
	rateLimitConfig?: {
		maxHtlcsPerSecond?: number;
		burstMultiplier?: number;
	};
	/** Number of blocks a channel can remain in AWAITING_REESTABLISH before force-closing (default 2016 ≈ 2 weeks) */
	reestablishTimeoutBlocks?: number;
	/**
	 * Periodically bump channel commitment feerates via update_fee from the fee
	 * estimator (default false). Off by default: an uncommitted/unsynced fee bump
	 * desyncs the commitment transactions and breaks subsequent HTLCs.
	 */
	autoUpdateChannelFees?: boolean;
	/**
	 * Output script that on-chain force-close sweeps (to_local after CSV, our
	 * to_remote claim on a remote force-close) pay into. Should be an address the
	 * caller's on-chain wallet owns and scans, so recovered funds show up in the
	 * wallet balance and are spendable. Defaults to P2WPKH(fundingPubkey) — an
	 * LN-key address the wallet does NOT track — for backward compatibility.
	 */
	sweepDestinationScript?: Buffer;
}

export enum PaymentStatus {
	PENDING = 'PENDING',
	COMPLETED = 'COMPLETED',
	FAILED = 'FAILED'
}

export enum PaymentDirection {
	OUTGOING = 'OUTGOING',
	INCOMING = 'INCOMING'
}

export interface IPaymentInfo {
	paymentHash: Buffer;
	preimage?: Buffer;
	amountMsat: bigint;
	status: PaymentStatus;
	direction: PaymentDirection;
	route?: IRoute;
	sharedSecrets?: Buffer[];
	failureCode?: number;
	failureSourceIndex?: number;
	retryCount?: number;
	createdAt: number;
	completedAt?: number;
	metadata?: Record<string, string>;
}

export interface IPaymentRetryContext {
	invoiceStr: string;
	excludedChannels: Set<string>;
	retryCount: number;
	maxRetries: number;
	/** Fee cap preserved across retries */
	maxFeeMsat?: bigint;
	/** Amount for amount-less invoices, preserved across retries */
	amountMsat?: bigint;
}

export interface ICreateInvoiceOptions {
	amountMsat?: bigint;
	description?: string;
	descriptionHash?: Buffer;
	expiry?: number;
	minFinalCltvExpiry?: number;
	/**
	 * Emit receiver route-blinding blinded paths instead of cleartext routing
	 * hints (BOLT 4 / BOLT 11). Each usable channel becomes a 2-hop blinded path
	 * [peer → us] so payers learn the introduction node (our peer) but not our
	 * node id. NOTE: beignet's encrypted hop data is not yet BOLT 4 TLV, so the
	 * introduction peer must also be a beignet node — interop with LND/CLN as the
	 * introduction node is a follow-up. Falls back to cleartext hints when no
	 * blinded path can be built.
	 */
	useBlindedPaths?: boolean;
	/**
	 * Number of NODES in each generated blinded path, including us (only
	 * meaningful with `useBlindedPaths`). 3 (the default) inserts one real
	 * forwarding node between the introduction node and us when the public
	 * graph offers one — the payer then learns a node TWO hops away from us
	 * instead of our direct peer. Falls back to a 2-node path [peer → us]
	 * per-channel when the graph has no usable candidate. 2 disables the
	 * extension entirely.
	 */
	blindedPathNumHops?: number;
	/**
	 * Hold invoice: park matching HTLCs instead of settling immediately. The
	 * payment is held until settleHeldHtlc() (reveals the preimage) or
	 * cancelHeldHtlc() (fails it). Underpins async receive and escrow-style flows.
	 */
	hold?: boolean;
	/**
	 * Optional externally-supplied 32-byte payment hash for a hold invoice whose
	 * preimage is held elsewhere (the node never learns it until settle time).
	 * Only honoured together with `hold`. When omitted, the node generates the
	 * preimage/hash itself and can settle without an external preimage.
	 */
	paymentHash?: Buffer;
	/**
	 * Async receive: mark the introduction (LSP) hop of the blinded path with
	 * hold_htlc, so the always-online LSP parks the inbound HTLC until this
	 * (offline) node comes back and releases it. Requires `useBlindedPaths`.
	 */
	asyncHold?: boolean;
}

export interface IChannelInfo {
	channelId: Buffer;
	peerPubkey: string;
	state: ChannelState;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	fundingSatoshis: bigint;
	channelType: Buffer | null;
	fundingTxid?: string;
	shortChannelId?: string;
	feeratePerKw?: number;
	htlcCount?: number;
	/** Reserve we must maintain (set by remote peer), in msat */
	localReserveMsat?: bigint;
	/** Reserve remote must maintain (set by us), in msat */
	remoteReserveMsat?: bigint;
	/** Whether this channel is private (unannounced) */
	isPrivate?: boolean;
}

export interface INodeInfo {
	nodeId: string;
	network: Network;
	channelCount: number;
	peerCount: number;
	networkingEnabled: boolean;
	alias?: string;
}

export interface ILightningError {
	code: string;
	channelId?: Buffer;
	message: string;
	timestamp: number;
}

export interface IPaymentPart {
	partIndex: number;
	channelId: Buffer;
	htlcId: bigint;
	amountMsat: bigint;
	status: PaymentStatus;
}

export interface IPendingMppPayment {
	paymentSecret: Buffer;
	totalMsat: bigint;
	receivedParts: IPaymentPart[];
	createdAt: number;
}

export interface IMultiPathRoute {
	parts: IRoute[];
	totalAmountMsat: bigint;
	totalFeeMsat: bigint;
}

export interface IOutboundMppPart {
	route: IRoute;
	channelId: Buffer;
	htlcId: bigint;
	amountMsat: bigint;
	status: PaymentStatus;
}

export interface ILightningBalance {
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	unsettledBalanceMsat: bigint;
}

export interface ICreateInvoiceResult {
	bolt11: string;
	paymentHash: Buffer;
	paymentSecret: Buffer;
}

export interface IOutboundMppState {
	paymentHash: Buffer;
	totalMsat: bigint;
	parts: IOutboundMppPart[];
	createdAt: number;
}

// ─── Typed Payment Errors ───

export enum LightningErrorCode {
	NO_ROUTE = 'NO_ROUTE',
	DUPLICATE_PAYMENT = 'DUPLICATE_PAYMENT',
	NO_CHANNEL_TO_HOP = 'NO_CHANNEL_TO_HOP',
	FEE_EXCEEDS_MAX = 'FEE_EXCEEDS_MAX',
	MISSING_AMOUNT = 'MISSING_AMOUNT',
	INVALID_INVOICE = 'INVALID_INVOICE',
	INVOICE_EXPIRED = 'INVOICE_EXPIRED',
	INVALID_KEYSEND = 'INVALID_KEYSEND'
}

export interface IKeysendOptions {
	/** 33-byte compressed public key of the destination node */
	destination: Buffer;
	/** Amount to send in millisatoshis */
	amountMsat: bigint;
	/** Maximum fee in millisatoshis (optional) */
	maxFeeMsat?: bigint;
	/** Additional custom TLV records to include in the onion (optional) */
	customRecords?: Map<number, Buffer>;
	/** Payment metadata (optional) */
	metadata?: Record<string, string>;
}

/**
 * Typed error for Lightning payment failures.
 * Extends Error for backward compatibility with existing catch blocks.
 */
export class LightningPaymentError extends Error {
	code: LightningErrorCode;

	constructor(code: LightningErrorCode, message: string) {
		super(message);
		this.name = 'LightningPaymentError';
		this.code = code;
	}
}

// ─── Channel Health ───

export interface IChannelHealth {
	channelId: string;
	state: string;
	localBalancePct: number;
	remoteBalancePct: number;
	htlcCount: number;
	maxHtlcs: number;
	capacitySats: number;
	warnings: string[];
}

// ─── Structured Logging ───

export interface IStructuredLog {
	category: 'payment' | 'channel' | 'htlc' | 'fee' | 'peer' | 'chain';
	action: string;
	timestamp: number;
	data: Record<string, unknown>;
}

// ─── Payment Proof ───

export interface IPaymentProof {
	paymentHash: Buffer;
	preimage: Buffer;
	amountMsat: bigint;
	completedAt: number;
	invoice?: string;
	route?: IRoute;
}

// ─── Payment Intelligence ───

export interface IPaymentEstimate {
	successProbabilityPct: number;
	estimatedTimeMs: number;
	routeQuality: 'HIGH' | 'MEDIUM' | 'LOW';
	warning?: string;
	alternativeAvailable: boolean;
	estimatedFeeSats: number;
	hopCount: number;
}
