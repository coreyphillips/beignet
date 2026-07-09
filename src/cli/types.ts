/**
 * CLI types — JSON-serializable response types.
 * All IDs are hex strings, all amounts are numbers in satoshis.
 */

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
	channelCount: number;
	peerCount: number;
	listening: boolean;
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
}

export interface BalanceInfo {
	onchain: number;
	lightning: number;
	total: number;
	unsettledSats?: number;
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
	network?: 'mainnet' | 'testnet' | 'regtest';
	alias?: string;
	dataDir?: string;
	electrumHost?: string;
	electrumPort?: number;
	electrumTls?: boolean;
	electrumServers?: Array<{ host: string; port: number; tls?: boolean }>;
	listenPort?: number;
	daemonPort?: number;
	daemonHost?: string;
	preferAnchors?: boolean;
	apiToken?: string;
	autoBootstrap?: boolean;
	backupPath?: string;
	backupIntervalMs?: number;
	dailySpendLimitSats?: number;
	connectTimeoutMs?: number;
	tlsCert?: string;
	tlsKey?: string;
	/** SOCKS5 proxy as "host:port" for outbound Lightning peer connections (e.g. Tor). */
	torProxy?: string;
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

export interface RouteEstimate {
	feeSats: number;
	hops: number;
	cltvDelta: number;
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
	recommendations: LiquidityRecommendation[];
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
	'channel:ready': (data: { channelId: string }) => void;
	'channel:closed': (data: { channelId: string }) => void;
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
