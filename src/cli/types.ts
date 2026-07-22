/**
 * CLI types — JSON-serializable response types.
 * All IDs are hex strings, all amounts are numbers in satoshis.
 */

import { TLogLevel } from '../logger';

export interface NodeInfo {
	nodeId: string;
	alias?: string;
	network: string;
	blockHeight: number;
	onchainBalanceSats: number;
	lightningBalanceSats: number;
	/**
	 * Funds from force-closed / closing channels being recovered on-chain
	 * (claimable, but not yet spendable in the wallet — some outputs are still
	 * CSV/CLTV timelocked). May briefly overlap with onchainBalanceSats while a
	 * sweep confirms.
	 */
	pendingCloseBalanceSats: number;
	/**
	 * Local balance stuck in ERRORED channels (peer sent an error / channel
	 * failed without a close in progress). Not spendable over Lightning and not
	 * being recovered on-chain — typically needs a force-close to resolve.
	 */
	erroredBalanceSats: number;
	/**
	 * Splice-in-transit funds. For a channel paying through its splice
	 * (pay-during-splice, ECDSA pending-lock), the canonical lightning balance
	 * already counts it at the conservative side of its two fundings, and this
	 * bucket holds only what is still arriving (a splice-in's added sats until
	 * the lock). For a parked mid-splice channel (taproot, or before the point
	 * of no return), the whole settle-to balance sits here. Rejoins
	 * lightningBalanceSats at splice_locked.
	 */
	splicingBalanceSats: number;
	channelCount: number;
	peerCount: number;
	listening: boolean;
	/** WebSocket listener port when accepting inbound WS peers (opt-in). */
	websocketPort?: number;
}

export type PeerState = 'connected' | 'connecting' | 'disconnected';

export interface PeerInfo {
	pubkey: string;
	host: string;
	port: number;
	state: PeerState;
}

export type ChannelStateString =
	| 'NONE'
	| 'AWAITING_FUNDING_CONFIRMED'
	| 'AWAITING_CHANNEL_READY'
	| 'NORMAL'
	| 'SHUTTING_DOWN'
	| 'NEGOTIATING_CLOSING'
	| 'FORCE_CLOSED'
	| 'AWAITING_REESTABLISH'
	| 'CLOSED'
	| 'ANNOUNCEMENT_READY';

export interface ChannelInfo {
	channelId: string;
	peerPubkey: string;
	state: ChannelStateString;
	localBalanceSats: number;
	remoteBalanceSats: number;
	capacitySats: number;
	isAnchor: boolean;
	isPrivate?: boolean;
	fundingTxid?: string;
	shortChannelId?: string;
	feeratePerKw?: number;
	htlcCount?: number;
	/**
	 * Local balance this channel settles to when its in-flight splice locks.
	 * Present only while a splice is past its point of no return; the live
	 * localBalanceSats stays pre-splice until splice_locked.
	 */
	pendingSpliceLocalBalanceSats?: number;
	/** Whether the channel can carry HTLC traffic right now (0.6.0+). */
	htlcUsable?: boolean;
	/**
	 * Present exactly when mid-splice by effective state: true = paying
	 * through the splice (counted in the canonical balance), false = parked.
	 */
	payThroughSplice?: boolean;
	/** Effective routing policy (per-channel override or node defaults) */
	feeBaseMsat?: number;
	feeProportionalMillionths?: number;
	cltvExpiryDelta?: number;
	/** Msat values as decimal strings (bigint in the library) */
	htlcMinimumMsat?: string;
	htlcMaximumMsat?: string;
}

export interface ChannelPolicyInfo {
	channelId: string;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	/** Msat values as decimal strings (bigint in the library) */
	htlcMinimumMsat: string;
	htlcMaximumMsat: string;
	/** 'override' when a per-channel override is set, 'default' otherwise */
	source: 'override' | 'default';
}

export interface PaymentRouteHop {
	pubkey: string;
	shortChannelId: string;
	feeMsat: number;
}

export interface PaymentRoute {
	hops: PaymentRouteHop[];
	totalFeeMsat: number;
	hopCount: number;
}

export interface PaymentInfo {
	paymentHash: string;
	preimage?: string;
	amountSats: number;
	feeSats?: number;
	status: 'PENDING' | 'COMPLETED' | 'FAILED';
	direction: 'OUTGOING' | 'INCOMING';
	failureCode?: number;
	failureDescription?: string;
	createdAt: number;
	completedAt?: number;
	metadata?: Record<string, string>;
	route?: PaymentRoute;
}

export interface PaymentProof {
	paymentHash: string;
	preimage: string;
	amountSats: number;
	completedAt: number;
	invoice?: string;
	hopCount?: number;
	feeSats?: number;
}

export interface PaymentProofVerification {
	valid: boolean;
	proof?: PaymentProof;
	error?: string;
}

export interface InvoiceInfo {
	bolt11: string;
	paymentHash: string;
	paymentSecret?: string;
	amountSats?: number;
	description?: string;
	expiry?: number;
	createdAt?: number;
	status?: 'PENDING' | 'PAID' | 'EXPIRED';
}

export interface HoldInvoiceInfo {
	paymentHash: string;
	bolt11: string;
	/** OPEN: unpaid. ACCEPTED: HTLC(s) parked. SETTLED / CANCELLED: resolved. */
	state: 'OPEN' | 'ACCEPTED' | 'SETTLED' | 'CANCELLED';
	/** Total msat currently parked (string for JSON safety). */
	heldAmountMsat: string;
	htlcCount: number;
	amountSats?: number;
	description?: string;
	expiry: number;
	createdAt: number;
}

export interface DecodedInvoice {
	network: string;
	amountSats?: number;
	timestamp: number;
	paymentHash: string;
	paymentSecret?: string;
	description?: string;
	payeeNodeKey?: string;
	expiry?: number;
	minFinalCltvExpiry?: number;
	routingHints?: Array<
		Array<{
			pubkey: string;
			shortChannelId: string;
			feeBaseMsat: number;
			feeProportionalMillionths: number;
			cltvExpiryDelta: number;
		}>
	>;
	warnings?: string[];
}

export interface TxInfo {
	txid: string;
	hex: string;
}

/**
 * What an on-chain transaction costs, from the same coin selection a send runs,
 * rather than from a caller's guess at it.
 *
 * The figures are exact for the UTXO set as it stands, which is the most a quote
 * can promise: coin selection is deterministic, so nothing here drifts on its
 * own, but a confirmation, a freeze, or another spend changes which inputs are
 * available and therefore what the transaction costs. Quote close to sending,
 * and treat a quote as current rather than as a reservation. Nothing here binds
 * the inputs a later send will pick.
 */
export type TOnchainQuote = {
	/** The rate the quote was made at. */
	satsPerVbyte: number;
	/** The fee this transaction pays, at the current UTXO set. */
	feeSats: number;
	/** Its size in virtual bytes, from the selected inputs and outputs. */
	vsize: number;
	/** Set when quoting a sweep: the amount sendable once its own fee is out. */
	maxSendSats?: number;
	/** The highest rate this transaction can pay without the fee taking half the balance. */
	maxSatsPerVbyte: number;
};

export interface OnchainTxInfo {
	txid: string;
	type: 'sent' | 'received';
	valueSats: number;
	feeSats: number;
	satsPerVbyte: number;
	address: string;
	height?: number;
	confirmed: boolean;
	timestamp: number;
	confirmTimestamp?: number;
}

export interface UtxoInfo {
	txid: string;
	vout: number;
	address: string;
	valueSats: number;
	height: number;
	/** Frozen UTXOs are excluded from coin selection until unfrozen. */
	frozen: boolean;
}

/**
 * BIP 380 output descriptors for the on-chain wallet. Public material only;
 * private keys are never exported.
 */
export interface DescriptorsInfo {
	fingerprint: string;
	network: string;
	account: number;
	birthdayHeight?: number;
	watchOnly: boolean;
	descriptors: Array<{
		addressType: string;
		external: string;
		internal: string;
	}>;
}

/** Unsigned PSBT built for an external signer (hardware wallet). */
export interface PsbtBuildInfo {
	psbtBase64: string;
	feeSats: number;
	vsizeEstimate: number;
	satsPerVbyte: number;
	inputs: Array<{
		txid: string;
		vout: number;
		address: string;
		valueSats: number;
		path: string;
	}>;
	outputs: Array<{
		address?: string;
		valueSats: number;
	}>;
}

/** Finalized transaction extracted from a signed PSBT. NOT broadcast. */
export interface PsbtImportInfo {
	txid: string;
	txHex: string;
}

/** Result of an RBF/CPFP fee bump. */
export interface BoostResult {
	/** Txid of the replacement (RBF) or child (CPFP) transaction. */
	txid: string;
	hex: string;
	boostType: 'rbf' | 'cpfp';
	/** Total fee paid by the new transaction, in sats. */
	feeSats: number;
	/** The transaction that was boosted. */
	originalTxid: string;
}

/** Unconfirmed wallet transactions eligible for fee bumping, by method. */
export interface BoostableTransactions {
	rbf: OnchainTxInfo[];
	cpfp: OnchainTxInfo[];
}

/** Result of a UTXO consolidation (send-max-to-self). */
export interface ConsolidateResult {
	txid: string;
	hex: string;
	/** Number of UTXOs spent into the single output. */
	utxosConsolidated: number;
	/** Fresh wallet address the consolidated output pays to. */
	address: string;
	feeSats: number;
}

export interface BalanceInfo {
	onchain: number;
	lightning: number;
	/**
	 * Currently spendable funds: onchain + lightning. Deliberately excludes
	 * splicingSats (and pending-close funds): those are accounted for but not
	 * spendable until their transitions complete.
	 */
	total: number;
	unsettledSats?: number;
	/**
	 * Splice-in-transit funds (see NodeInfo.splicingBalanceSats). Rejoins
	 * lightning at splice_locked.
	 */
	splicingSats?: number;
}

export interface OfferInfo {
	offerId: string;
	description: string;
	encoded?: string;
	amountSats?: number;
	issuer?: string;
	issuerId?: string;
	quantityMax?: number;
	absoluteExpiry?: number;
}

export interface TrustedPeerInfo {
	pubkey: string;
	trusted: boolean;
}

export interface SpliceResult {
	ok: boolean;
	error?: string;
}

export interface BootstrapPeerInfo {
	pubkey: string;
	host: string;
	port: number;
}

export interface Bolt12InvoiceInfo {
	paymentHash: string;
	amountSats: number;
	description: string;
	nodeId: string;
	createdAt: number;
	relativeExpiry?: number;
}

export interface BeignetConfig {
	mnemonic?: string;
	network?: 'mainnet' | 'testnet' | 'regtest' | 'signet';
	alias?: string;
	dataDir?: string;
	electrumHost?: string;
	electrumPort?: number;
	electrumTls?: boolean;
	electrumServers?: Array<{ host: string; port: number; tls?: boolean }>;
	/** Fee estimate source: 'electrum' | 'http' | 'auto' (default 'auto'). */
	feeEstimationSource?: 'electrum' | 'http' | 'auto';
	listenPort?: number;
	/** Accept inbound Lightning peers over WebSocket on this port (opt-in;
	 *  coexists with the TCP listener on listenPort). */
	websocketPort?: number;
	daemonPort?: number;
	daemonHost?: string;
	preferAnchors?: boolean;
	/** option_wumbo: advertise large_channels and lift the 2^24 sat funding cap. */
	largeChannels?: boolean;
	/** Legacy single API bearer token. Still honored with implicit admin scope. */
	apiToken?: string;
	/** Named API keys with permission scopes (readonly/invoice/admin).
	 *  expiresAt (optional, ISO 8601): key stops authenticating at that time. */
	apiKeys?: Array<{
		name: string;
		key: string;
		scopes: Array<'readonly' | 'invoice' | 'admin'>;
		expiresAt?: string;
	}>;
	autoBootstrap?: boolean;
	backupPath?: string;
	backupIntervalMs?: number;
	dailySpendLimitSats?: number;
	connectTimeoutMs?: number;
	tlsCert?: string;
	tlsKey?: string;
	/** SOCKS5 proxy as "host:port" for outbound Lightning peer connections (e.g. Tor). */
	torProxy?: string;
	/** Addresses to advertise in node_announcement, as "host[:port]" strings
	 *  (IPv4, "[ipv6]:port", Tor v3 ".onion", or DNS hostname). */
	announceAddresses?: string[];
	/** Watchtowers to ship justice data to, as "pubkey@host:port" URIs. */
	watchtowers?: string[];
	/** Relay per-HTLC events (htlc:forwarded/fulfilled/failed) over SSE and
	 *  webhooks. Off by default: routing nodes generate one event per HTLC. */
	htlcEvents?: boolean;
	/** Relay third-party HTLCs, i.e. act as a routing hop (default true). Set
	 *  false so a wallet declines all forwards. Env: BEIGNET_FORWARDING_ENABLED. */
	forwardingEnabled?: boolean;
	/** Daemon diagnostic log level ('debug' | 'info' | 'warn' | 'error' |
	 *  'silent'). When set, the daemon prints leveled diagnostics to stderr;
	 *  unset keeps the daemon silent (status quo). */
	logLevel?: TLogLevel;
}

export interface HealthInfo {
	status: 'ready' | 'syncing' | 'degraded';
	uptime: number;
	blockHeight: number;
	electrumConnected: boolean;
	peerCount: number;
	channelCount: number;
	readyChannelCount: number;
	graphNodes: number;
	graphChannels: number;
}

export interface EventMessage {
	type: string;
	data: Record<string, unknown>;
}

export interface ApiResponse<T> {
	ok: boolean;
	result?: T;
	error?: { code: string; message: string };
}

export interface PaymentFilter {
	status?: 'PENDING' | 'COMPLETED' | 'FAILED';
	direction?: 'OUTGOING' | 'INCOMING';
	since?: number;
	limit?: number;
	offset?: number;
	/** Filter by metadata key existence (or key+value when used with metadataValue) */
	metadataKey?: string;
	/** Filter by metadata key=value match (requires metadataKey) */
	metadataValue?: string;
}

export interface ForwardsFilter {
	since?: number;
	until?: number;
	limit?: number;
	offset?: number;
	/** Match events where this channel was the inbound OR outbound leg. */
	channelId?: string;
}

/** One settled forward. Msat values are decimal strings (JSON-safe bigint). */
export interface ForwardingEventInfo {
	id: number;
	settledAt: number;
	inChannelId: string;
	outChannelId: string;
	inScid?: string;
	outScid?: string;
	amountInMsat: string;
	amountOutMsat: string;
	feeMsat: string;
}

export interface ForwardingSummaryInfo {
	count: number;
	volumeOutMsat: string;
	feesEarnedMsat: string;
}

export interface RouteEstimate {
	feeSats: number;
	hops: number;
	cltvDelta: number;
}

export interface GraphInfo {
	nodeCount: number;
	channelCount: number;
	/** Epoch ms of the last gossip/RGS sync completed this session, if any */
	lastSyncAt?: number;
}

/** One direction's routing policy from a channel_update. */
export interface GraphChannelPolicy {
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	/** Msat values as decimal strings (bigint in the library) */
	htlcMinimumMsat: string;
	htlcMaximumMsat?: string;
	disabled: boolean;
	/** channel_update timestamp (seconds since epoch) */
	lastUpdate: number;
}

export interface GraphChannelInfo {
	/** Human-readable SCID: "<block>x<txIndex>x<outputIndex>" */
	shortChannelId: string;
	node1Pubkey: string;
	node2Pubkey: string;
	/**
	 * Capacity is not gossiped in channel_announcement; when either direction
	 * advertises htlc_maximum_msat this is the larger of the two as sats.
	 */
	capacitySats?: number;
	/** Policy for the node1 -> node2 direction (channel_update direction 0) */
	node1Policy?: GraphChannelPolicy;
	/** Policy for the node2 -> node1 direction (channel_update direction 1) */
	node2Policy?: GraphChannelPolicy;
}

export interface GraphNodeInfo {
	pubkey: string;
	alias?: string;
	/** RGB color from node_announcement as hex (e.g. "ff9900") */
	color?: string;
	addresses?: Array<{ type: number; host: string; port: number }>;
	featuresHex?: string;
	/** node_announcement timestamp (seconds since epoch) */
	lastUpdate?: number;
	channelCount: number;
	/** SCIDs of the node's known channels, "<block>x<txIndex>x<outputIndex>" */
	channels: string[];
}

export interface GraphDescribeResult {
	totalChannels: number;
	limit: number;
	offset: number;
	channels: GraphChannelInfo[];
}

export interface RouteHop {
	pubkey: string;
	/** "<block>x<txIndex>x<outputIndex>" (16-char hex also accepted on input) */
	shortChannelId: string;
	/** Msat as decimal string (bigint in the library) */
	amountToForwardMsat: string;
	/** RELATIVE CLTV delta from pathfinding (absolute height added at send) */
	outgoingCltvValue: number;
	/** Fee this hop charges for forwarding, msat as decimal string (0 on final) */
	feeMsat: string;
	cltvExpiryDelta: number;
}

export interface RouteQueryResult {
	destination: string;
	amountSats: number;
	hops: RouteHop[];
	/** Msat as decimal strings (bigint in the library) */
	totalAmountMsat: string;
	totalFeeMsat: string;
	totalCltvDelta: number;
	finalCltvExpiry: number;
}

export interface NodeStats {
	totalPaymentsSent: number;
	totalPaymentsReceived: number;
	totalPaymentsFailed: number;
	totalSatsSent: number;
	totalSatsReceived: number;
	totalFeesPaid: number;
	successRate: number;
	uptimeMs: number;
	windowMs?: number;
	avgPaymentTimeSec?: number;
	avgFeePct?: number;
}

export interface LiquidityRecommendation {
	type: 'OPEN_CHANNEL' | 'CLOSE_CHANNEL' | 'REBALANCE_NEEDED' | 'BUY_LEASE';
	priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
	reason: string;
	channelId?: string;
}

export interface LiquiditySnapshot {
	totalLocalBalanceSats: number;
	totalRemoteBalanceSats: number;
	totalCapacitySats: number;
	channelCount: number;
	activeChannelCount: number;
	outboundLiquidityPct: number;
	inboundLiquidityPct: number;
	/** Total local balance held back as channel reserve, unspendable (sats). */
	reserveSats: number;
	/** Local balance above the reserve, i.e. what can actually be sent (sats).
	 *  Zero while a channel's balance is still below its reserve. */
	sendableSats: number;
	recommendations: LiquidityRecommendation[];
}

/** One planned circular rebalance (not yet executed). */
export interface RebalancePlanInfo {
	fromChannelId: string;
	toChannelId: string;
	amountSats: number;
	reason: string;
}

/** GET /advisor/recommendations: analyze() output plus the concrete plan. */
export interface AdvisorRecommendations extends LiquiditySnapshot {
	rebalancePlan: RebalancePlanInfo[];
}

/** Outcome of one circular rebalance. Msat values are decimal strings. */
export interface RebalanceResult {
	paymentHash: string;
	amountSats: number;
	feeMsat: string;
	feeSats: number;
	hops: number;
}

export interface RebalanceAttemptInfo {
	fromChannelId: string;
	toChannelId: string;
	amountSats: number;
	status: 'SUCCEEDED' | 'FAILED' | 'SKIPPED_BUDGET';
	feeMsat?: string;
	error?: string;
}

/** POST /advisor/execute-rebalances result. Msat values are decimal strings. */
export interface RebalanceExecutionSummary {
	attempts: RebalanceAttemptInfo[];
	succeeded: number;
	failed: number;
	skippedBudget: number;
	feeSpentMsat: string;
	budgetRemainingMsat: string;
}

export interface WebhookRegistration {
	id: string;
	url: string;
	events: string[];
	secret?: string;
	createdAt: number;
}

export interface QueuedPayment {
	id: string;
	bolt11: string;
	priority: number;
	status: 'queued' | 'dispatching' | 'completed' | 'failed' | 'cancelled';
	amountSats?: number;
	maxFeeSats?: number;
	metadata?: Record<string, string>;
	error?: string;
	createdAt: number;
	completedAt?: number;
}

export interface ChannelSuggestion {
	nodeId: string;
	alias?: string;
	score: number;
	channelCount: number;
	totalCapacitySats: number;
	reason: string;
}

export interface FeeSnapshot {
	currentSatPerVbyte: number;
	trend: 'RISING' | 'FALLING' | 'STABLE';
	percentile: number;
	recommendation: 'OPEN_NOW' | 'WAIT' | 'NEUTRAL';
	estimatedOpenChannelCostSats: number;
	sampleCount: number;
	minSatPerVbyte: number;
	maxSatPerVbyte: number;
	avgSatPerVbyte: number;
}

export interface PaymentEstimate {
	successProbabilityPct: number;
	estimatedTimeMs: number;
	routeQuality: 'HIGH' | 'MEDIUM' | 'LOW';
	warning?: string;
	alternativeAvailable: boolean;
	estimatedFeeSats: number;
	hopCount: number;
}

export interface ActionLogEntry {
	category: string;
	action: string;
	timestamp: number;
	data: Record<string, unknown>;
}

export interface ReadinessCheck {
	name: string;
	status: 'PASS' | 'WARN' | 'FAIL';
	severity: 'CRITICAL' | 'WARNING' | 'INFO';
	message: string;
}

export interface ReadinessReport {
	score: number; // 0-100 weighted pass rate
	ready: boolean; // true if no CRITICAL failures
	checks: ReadinessCheck[];
}

export interface RetryPaymentOptions {
	maxRetries?: number;
	backoffMs?: number;
	maxFeeSats?: number;
	amountSats?: number;
	metadata?: Record<string, string>;
}

export interface RetryPaymentResult extends PaymentInfo {
	attempts: number;
}

export type PaymentValidationStatus = 'OK' | 'WARN' | 'FAIL';

export interface PaymentValidation {
	/** Whether the payment should proceed: OK = go, WARN = proceed with caution, FAIL = do not send */
	status: PaymentValidationStatus;
	/** Human-readable summary */
	summary: string;
	/** Individual check results */
	checks: PaymentValidationCheck[];
	/** Decoded invoice details (if decode succeeded) */
	invoice?: DecodedInvoice;
}

export interface PaymentValidationCheck {
	name: string;
	status: PaymentValidationStatus;
	message: string;
}

export interface BeignetNodeEvents {
	'payment:received': (info: PaymentInfo) => void;
	'payment:sent': (info: PaymentInfo) => void;
	'payment:failed': (info: PaymentInfo) => void;
	'payment:retry': (data: {
		paymentHash: string;
		attempt: number;
		maxRetries: number;
		nextRetryMs: number;
		error: string;
	}) => void;
	'invoice:settled': (data: {
		paymentHash: string;
		bolt11: string;
		amountSats: number;
	}) => void;
	'channel:opening': (data: { channelId: string; fundingTxid: string }) => void;
	'channel:ready': (data: { channelId: string }) => void;
	'channel:pending-close': (data: {
		channelId: string;
		initiator: 'local' | 'remote';
	}) => void;
	'channel:force-closing': (data: {
		channelId: string;
		initiator: 'local' | 'remote';
	}) => void;
	'channel:closed': (data: { channelId: string }) => void;
	'htlc:forwarded': (data: {
		inChannelId: string;
		outChannelId: string;
		amountInMsat: string;
		amountOutMsat: string;
		feeMsat: string;
	}) => void;
	'htlc:fulfilled': (data: { channelId: string; htlcId: string }) => void;
	'htlc:failed': (data: { channelId: string; htlcId: string }) => void;
	'peer:connect': (data: { pubkey: string }) => void;
	'peer:disconnect': (data: { pubkey: string }) => void;
	'peer:error': (data: { pubkey: string; message: string }) => void;
	'node:error': (data: {
		code: string;
		message: string;
		timestamp: number;
	}) => void;
	'node:ready': () => void;
	log: (entry: {
		level: string;
		message: string;
		data?: Record<string, unknown>;
		timestamp: number;
	}) => void;
	'backup:completed': (data: { path: string; timestamp: number }) => void;
	'backup:failed': (data: {
		path: string;
		error: string;
		timestamp: number;
	}) => void;
	'electrum:failover': (data: {
		from: { host: string; port: number };
		to: { host: string; port: number };
		timestamp: number;
	}) => void;
}
