/**
 * CLI types — JSON-serializable response types.
 * All IDs are hex strings, all amounts are numbers in satoshis.
 */

import { TLogLevel } from '../logger';
import type { IGuardianConfigEntry } from '../lightning/recovery/assembly';
import type { SpliceRefusalCode } from '../lightning/node/types';

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
	/**
	 * Every known channel row, including CLOSED/FORCE_CLOSED ones (kept for
	 * history). Use openChannelCount for the number of operating channels.
	 */
	channelCount: number;
	/** Channels not in a terminal state (CLOSED, FORCE_CLOSED, ERRORED). */
	openChannelCount: number;
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
	| 'ERRORED'
	| 'ANNOUNCEMENT_READY';

/**
 * How a channel's close is progressing. Present on closing/closed channels
 * (SHUTTING_DOWN, NEGOTIATING_CLOSING, CLOSED, FORCE_CLOSED, and ERRORED
 * with an on-chain funding output).
 */
export interface CloseStatus {
	/** Who published (or is negotiating) the close. */
	closer: 'local' | 'remote' | 'cooperative' | 'unknown';
	/**
	 * Why WE closed: 'user' for an API-initiated close, otherwise the
	 * automatic close code (e.g. REESTABLISH_TIMEOUT_FORCE_CLOSED). Absent
	 * for a close the peer initiated.
	 */
	reason?: string;
	/** Txid of the commitment or mutual close transaction, when known. */
	closingTxid?: string;
	/**
	 * Whether the daemon believes the close tx reached the network: the last
	 * broadcast attempt succeeded or the spend was observed on chain.
	 */
	broadcast: boolean;
	/** Block height the close confirmed at; 0 while unconfirmed. */
	confirmationHeight: number;
	/** Sweep progress across the close's tracked outputs. */
	resolution: 'pending' | 'sweeping' | 'resolved';
	/**
	 * Height at which the to_local CSV matures and our main balance becomes
	 * spendable. Only present for our own force close once computable.
	 */
	fundsAvailableHeight?: number;
}

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
	/** Funding output index in fundingTxid; present exactly when it is. */
	fundingOutputIndex?: number;
	shortChannelId?: string;
	feeratePerKw?: number;
	htlcCount?: number;
	/**
	 * Local balance this channel settles to when its in-flight splice locks.
	 * Present only while a splice is past its point of no return; the live
	 * localBalanceSats stays pre-splice until splice_locked.
	 */
	pendingSpliceLocalBalanceSats?: number;
	/** Whether the channel will accept a NEW HTLC (0.6.0+). */
	htlcUsable?: boolean;
	/**
	 * The channel was restored from a Recovery Capsule and its state has not
	 * been proven current, so it takes no new HTLCs and is offered to no
	 * router. Existing HTLCs still settle; a cooperative close is refused in
	 * both directions without the acceptStaleStateRisk acknowledgement.
	 */
	restoreRecencyUnproven?: boolean;
	/**
	 * Neither mempool nor chain can account for the funding, so the channel is
	 * quarantined: no new HTLCs, no router edge, no routing hint. Reversible
	 * and not a close; it clears by itself when the funding is seen again.
	 */
	fundingUnaccounted?: boolean;
	/**
	 * Present exactly when mid-splice by effective state: true = paying
	 * through the splice (counted in the canonical balance), false = parked.
	 */
	payThroughSplice?: boolean;
	/**
	 * Whether the connected peer negotiated option_splice + option_quiesce.
	 * Absent when the peer is disconnected or its init has not arrived, so
	 * absence means "unknown", never "unsupported".
	 */
	peerSupportsSplicing?: boolean;
	/** Effective routing policy (per-channel override or node defaults) */
	feeBaseMsat?: number;
	feeProportionalMillionths?: number;
	cltvExpiryDelta?: number;
	/** Msat values as decimal strings (bigint in the library) */
	htlcMinimumMsat?: string;
	htlcMaximumMsat?: string;
	/** Close progress; present for closing/closed channels. */
	closeStatus?: CloseStatus;
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

/**
 * The direct-funding policy as the LFBW app reads it (issue #613). The field
 * names are the app's, not the library's: the dashboard hides its whole policy
 * card when `GET /direct-funding/config` fails and requires `lspPubkey` to be
 * present in a readback after posting `{minAmountSat}` alone, so this shape is
 * a contract until that app is updated under its own tracking issue.
 */
/**
 * GET /jit/status (issue #668): the JIT receive role as it stands. `lsp` is
 * null when the role is off (BEIGNET_JIT_RECEIVE unset); the client ceilings
 * apply either way.
 */
export interface JitStatusInfo {
	/** Whether this node runs the LSP role (fronts channel funding for peers). */
	enabled: boolean;
	/** The most this node accepts from an LSP's quote for its own receives. */
	client: { maxFlatFeeSat: number; maxFeePpm: number };
	lsp: {
		/** Opening fee deducted from a delivery. */
		flatFeeSat: number;
		feePpm: number;
		/** Most fronted for one client, open or splice. */
		maxClientFundingSats: number;
		/** Fundings (opens plus splices) allowed in flight at once. */
		maxConcurrentFundings: number;
		/** Lifetime budget across restarts; null means none. */
		maxTotalFundingSats: number | null;
		maxLiveIntentsPerPeer: number;
		maxLiveIntents: number;
		/** Sats a live funding has claimed against the budget right now. */
		reservedSats: number;
		/** Cumulative sats fronted, across restarts. */
		frontedSats: number;
		liveIntents: number;
		/** HTLCs held while a funding runs. */
		heldParts: number;
		fundingsInFlight: number;
	} | null;
}

/**
 * GET /jit/quote (issue #687): what a just-in-time receive of this size
 * would cost at the named LSP and whether it would be served right now,
 * asked without registering an intent. A decline is an answer, not an
 * error: `accepted` false with `reason` in plain language.
 */
export interface JitQuoteInfo {
	lspPubkey: string;
	/** The receive priced; null for an amount-less invoice (the cap is priced). */
	amountSats: number | null;
	/** Whether the LSP would register this receive as things stand. */
	accepted: boolean;
	/** Plain-language refusal, shown as is; null when accepted. */
	reason: string | null;
	/** Opening fee the LSP would deduct from the delivery. */
	flatFeeSat: number;
	feePpm: number;
	/** That fee on this receive (sat, rounded up). */
	feeSats: number;
	/** Most the LSP fronts for one client, open or splice. */
	maxClientFundingSats: number;
	/** What the LSP would front for this receive; 0 when refused. */
	fundingSats: number;
	/** Whether this node's own ceilings would accept the quoted fee. */
	withinCeilings: boolean;
	/** Those ceilings, so a refusal on them can be explained. */
	client: { maxFlatFeeSat: number; maxFeePpm: number };
}

export interface DirectFundingConfigInfo {
	/** The liquidity peer every direct-funded channel is negotiated with. */
	lspPubkey: string | null;
	lspHost: string | null;
	lspPort: number | null;
	/**
	 * Inbound the operator would like bought alongside. Recorded and reported
	 * so the app can round-trip it; nothing consumes it yet, because buying a
	 * lease alongside a direct-funded open is not part of the ported protocol.
	 */
	targetInboundSat: number;
	/** Whether a direct-funded open may go zero-conf. */
	trusted: boolean;
	/**
	 * Whether a paired (trusted) payer's offer may be served by splicing the
	 * existing channel with the liquidity peer instead of opening a second
	 * one. Anonymous payers always get a new confirmed channel regardless.
	 */
	allowSplice: boolean;
	/** Smallest offer served, never below the 5000 sat protocol floor. */
	minAmountSat: number;
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

/**
 * A peer-aware max channel-funding quote: the daemon decides v1 vs v2 the
 * same way openChannel does, so the previewed amount is the amount the
 * channel actually commits.
 */
export type TChannelFundingQuote = {
	/** Which funding flow openChannel would use toward this peer. */
	method: 'v1' | 'v2';
	/** False when the peer sent no init (not connected): the v2 judgment
	 *  cannot be made and the quote falls back to the v1 sweep. */
	peerKnown: boolean;
	/** The rate the quote was made at. */
	satsPerVbyte: number;
	/** The exact amount a max open commits as funding_satoshis. */
	fundingSatoshis: number;
	/** The funding fee at this rate. */
	feeSats: number;
	/** v2 only: the pinned interactive-tx rate in sat/kw. */
	feeratePerKw?: number;
	/** v2 only: the wallet balance the quote drew on. */
	spendableSats?: number;
	/** Inputs the funding would spend. */
	inputCount?: number;
	/** v1 only: sweep tx virtual size. */
	vsize?: number;
	/** v1 only: the highest rate the sweep could pay. */
	maxSatsPerVbyte?: number;
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

/**
 * A started splice, or the refusal that stopped it. The daemon routes answer a
 * refusal as a failure envelope with the mapped error code, so over HTTP this
 * is only ever `{ ok: true }` (issue #618); an embedder calling BeignetNode
 * directly still gets the refusal in hand.
 */
export interface SpliceResult {
	ok: boolean;
	error?: string;
	code?: SpliceRefusalCode;
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
	/** Serve GET /metrics without authentication (default false). */
	metricsPublic?: boolean;
	/** Allow non-loopback bind / wildcard CORS without auth (default false). */
	insecure?: boolean;
	/** Relay third-party HTLCs, i.e. act as a routing hop (default true). Set
	 *  false so a wallet declines all forwards. Env: BEIGNET_FORWARDING_ENABLED. */
	forwardingEnabled?: boolean;
	/** Signature-verify foreign broadcast gossip at intake (default false:
	 *  verification is deferred until a gossip query asks for the entry;
	 *  nothing unverified is ever served either way). Set true on relay-class
	 *  nodes that serve the graph. Env: BEIGNET_EAGER_GOSSIP_VERIFY, exact
	 *  'true' or 'false'; anything else is ignored. */
	eagerGossipVerify?: boolean;
	/** Dial known peers (channel partners included) on start and on disconnect
	 *  (default true). Set false and, with neither listenPort nor
	 *  websocketPort configured, the node is genuinely quiet: channels stay
	 *  watched on-chain but unreachable over the wire, which is what an
	 *  operator deliberately parking a Lightning node wants. Env:
	 *  BEIGNET_AUTO_RECONNECT, exact 'true' or 'false'; anything else is
	 *  ignored and the default (reconnect on) rules. */
	autoReconnect?: boolean;
	/** Daemon diagnostic log level ('debug' | 'info' | 'warn' | 'error' |
	 *  'silent'). When set, the daemon prints leveled diagnostics to stderr;
	 *  unset keeps the daemon silent (status quo). */
	logLevel?: TLogLevel;
	/** Recovery Protocol mode (docs/RECOVERY-PROTOCOL.md section 8):
	 *  'off' | 'peer-storage' | 'async-remote' | 'quorum'. Exact values only;
	 *  anything else is ignored and the default (off) rules. Env:
	 *  BEIGNET_RECOVERY_MODE. */
	recoveryMode?: string;
	/** Guardian set for async-remote/quorum modes, as
	 *  "<64-hex-x-only-pubkey>@<http(s) url>" URIs (crash-v1: exactly three).
	 *  The config file may instead hold objects { guardianId, url, auth? },
	 *  the shape POST /recovery/capsule-guardians hands back, so a transport
	 *  credential recovered from peer storage can re-enter a guardian mode.
	 *  Malformed entries refuse daemon startup rather than silently changing
	 *  the quorum arithmetic. Env: BEIGNET_RECOVERY_GUARDIANS (comma list). */
	recoveryGuardians?: Array<string | IGuardianConfigEntry>;
	/** Recovery fault-model profile. 'crash-v1' is the only accepted value
	 *  and the default when a guardian mode is configured. Env:
	 *  BEIGNET_RECOVERY_PROFILE. */
	recoveryProfile?: string;
	/** Guardian modes: idle writer lease re-check cadence in ms (default
	 *  300000, 0 disables). Env: BEIGNET_RECOVERY_LEASE_CHECK_MS. */
	recoveryLeaseCheckIntervalMs?: number;
	/** peer-storage mode: how long a peer's channel_reestablish for a channel
	 *  this node has no record of is held before the BOLT 1 error goes out
	 *  (default 600000, 0 answers immediately). Env:
	 *  BEIGNET_RECOVERY_REESTABLISH_HOLD_MS. */
	recoveryReestablishHoldMs?: number;
	/** peer-storage mode: apply the best Recovery Capsule storage peers
	 *  return, on a boot whose database is empty, with no operator call
	 *  (issue #690). Local durability has no fencing, so this automates an
	 *  unfenced adoption: an old device still running keeps acting on the
	 *  same channels. Off by default; an embedder asks the operator once
	 *  (at seed import) and passes it at spawn. Refused outside
	 *  peer-storage mode. Env: BEIGNET_RECOVERY_AUTO_APPLY, exact 'true' or
	 *  'false'; anything else is ignored and the default (off) rules. */
	recoveryAutoApply?: boolean;
	/** Auto-apply settle floor in ms from the first capsule's arrival
	 *  (default 15000): the capsule is applied once every connected storage
	 *  peer has answered and at least this long has passed, so a stale
	 *  replica that answers a moment later still takes part. Env:
	 *  BEIGNET_RECOVERY_AUTO_APPLY_SETTLE_MS. */
	recoveryAutoApplySettleMs?: number;
	/** Auto-apply ceiling in ms from the first capsule's arrival (default
	 *  120000): storage peers that never connect are not waited for past
	 *  this. Must exceed the settle floor and fit inside the reestablish
	 *  hold, which is the window this automation exists to beat. Env:
	 *  BEIGNET_RECOVERY_AUTO_APPLY_MAX_WAIT_MS. */
	recoveryAutoApplyMaxWaitMs?: number;
	/** Serve the reference guardian to other nodes over bolt8 sessions at
	 *  this node's Lightning address (docs/RECOVERY-GUARDIAN-WIRE.md 2.7,
	 *  issue #699). Needs listenPort. Independent of this node's own
	 *  recovery mode. Env: BEIGNET_GUARDIAN_SERVE (exact true/false). */
	guardianServe?: boolean;
	/** Bearer token every guardian session must present; absent runs open
	 *  (BOLT 8 already encrypts and authenticates the host, so the token is
	 *  an allow-list, not confidentiality). Env: BEIGNET_GUARDIAN_TOKEN. */
	guardianToken?: string;
	/** Content one guardian set may store (its encoded rows; SQLite's
	 *  overhead comes on top) before a write that would cross it is refused
	 *  with ERR_QUOTA_EXCEEDED (default 268435456, 256 MiB). Refuses, never
	 *  deletes. Env: BEIGNET_GUARDIAN_MAX_BYTES. */
	guardianMaxBytesPerSet?: number;
	/** Guardian sets this node will register (default 16). Env:
	 *  BEIGNET_GUARDIAN_MAX_SETS. */
	guardianMaxSets?: number;
	/** Advertised per-record ciphertext limit (default 4194304, 4 MiB; the
	 *  protocol cap is 16 MiB). Env: BEIGNET_GUARDIAN_MAX_CIPHERTEXT_BYTES. */
	guardianMaxCiphertextBytes?: number;
	/** Node-wide default routing fee policy advertised in channel_update
	 *  (BOLT 7; base u32 msat, proportional u32 millionths, cltv delta u16).
	 *  Per-channel overrides set through the channel policy update surface win
	 *  over these defaults. Envs: BEIGNET_FEE_BASE_MSAT, BEIGNET_FEE_PPM,
	 *  BEIGNET_CLTV_DELTA (whole integers; anything else refuses startup).
	 *  Issue #532 workstream 1B. */
	routingFeeBaseMsat?: number;
	routingFeePpm?: number;
	routingCltvDelta?: number;
	/** Liquidity ads (bLIP-0051, option_will_fund) SELLER policy: answer a
	 *  buyer's request_funds by leasing inbound at these rates. Env:
	 *  BEIGNET_LEASE_RATES, a JSON object with the five lease_rates fields
	 *  (fundingWeightWitness, leaseFeeBasis, leaseFeeBaseSat,
	 *  channelFeeMaxBaseMsat, channelFeeMaxProportionalThousandths). A
	 *  malformed or out-of-range value refuses startup: the rates are encoded
	 *  into the signed will_fund record, where an out-of-range field would
	 *  silently wrap on the wire. Unset means never sell. */
	leaseRates?: import('../lightning/gossip/types').ILeaseRates;
	/** JIT channel receive (issue #532 workstream 3B). `enabled`
	 *  (BEIGNET_JIT_RECEIVE, exact 'true'/'false') runs the LSP role: HTLCs
	 *  addressed to intercept SCIDs registered by wallet peers are held while a
	 *  zero-conf channel is funded with THIS node's coins, charged at
	 *  BEIGNET_JIT_FLAT_FEE_SAT + BEIGNET_JIT_FEE_PPM. BEIGNET_JIT_MAX_FLAT_FEE_SAT
	 *  and BEIGNET_JIT_MAX_FEE_PPM are the other role and apply regardless: they
	 *  cap what an LSP may quote us when POST /jit/invoice asks for one.
	 *  BEIGNET_JIT_MAX_CLIENT_FUNDING_SAT, BEIGNET_JIT_MAX_CONCURRENT_FUNDINGS
	 *  and BEIGNET_JIT_MAX_TOTAL_FUNDING_SAT bound what the LSP role fronts
	 *  (per client, in flight at once, and cumulatively across restarts; the
	 *  last unset means no lifetime budget), issue #665. Whole integers;
	 *  anything else refuses startup. */
	jitReceive?: {
		enabled?: boolean;
		flatFeeSat?: number;
		feePpm?: number;
		maxFlatFeeSat?: number;
		maxFeePpm?: number;
		maxClientFundingSats?: number;
		maxConcurrentFundings?: number;
		maxTotalFundingSats?: number;
	};
	/** Relay direct-funding frames for OTHER nodes (BEIGNET_DF_RELAY, exact
	 *  'true'/'false'). Off by default: forwarding opaque frames between
	 *  strangers is work done for other people. Paying and being paid over the
	 *  three lanes needs nothing switched on. */
	dfRelay?: boolean;
	/** Smallest direct-funding offer this node serves (BEIGNET_DF_MIN_AMOUNT).
	 *  Clamps up to the 5000 sat protocol floor; below that the payer's own fee
	 *  share dominates the payment. A partly numeric value refuses startup. */
	dfMinAmountSat?: number;
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
	/**
	 * On-chain lifecycle, one appearance and at most one confirmation per
	 * transaction. `transaction:received` fires when an incoming transaction
	 * first appears, `transaction:sent` when an outgoing one does; either may
	 * already carry a height when the transaction was found at a catch-up
	 * sync after downtime, and no separate confirmation fires for that case.
	 * `transaction:confirmed` fires only for the transition, a transaction
	 * the wallet already held moving from the mempool into a block, in
	 * either direction with `info.type` saying which. Initial-sync history
	 * does not replay as events.
	 */
	'transaction:received': (info: OnchainTxInfo) => void;
	'transaction:sent': (info: OnchainTxInfo) => void;
	'transaction:confirmed': (info: OnchainTxInfo) => void;
	/** A replacement was observed: the listed txids were replaced (RBF) and
	 *  are dead; whatever was watching them should stop (issue #548). */
	'onchain:rbf': (data: { txids: string[] }) => void;
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
	/** The true terminal event of a close: every on-chain output of the channel is irrevocably swept or claimed and the channel state becomes CLOSED. */
	'channel:resolved': (data: { channelId: string }) => void;
	/** The channel was removed with nothing to close on chain, and its persisted state was durably deleted: its unconfirmed funding tx vanished from mempool and chain, or the open was aborted or abandoned before any funding existed. */
	'channel:voided': (data: { channelId: string }) => void;
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
		/**
		 * The channel the error belongs to, when there is one. Relayed over SSE
		 * and webhooks since #464 and carried by the onError callback, but it was
		 * missing from this signature, so a typed subscriber could not read the
		 * one field that says which open just failed.
		 */
		channelId?: string;
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
	/** Recovery Protocol (docs/RECOVERY-PROTOCOL.md section 8). The first
	 *  three originate in LightningNode and are relayed JSON-safe; the last
	 *  three originate here (the daemon owns the barrier and the restore). */
	'recovery:durable': (data: { through: string }) => void;
	'recovery:fenced': (data: {
		supersededBy: {
			epoch: string;
			writerPublicKey: string;
			sequence: string;
			frameHash: string;
		} | null;
	}) => void;
	'recovery:backfill-lost': (data: { detail: string }) => void;
	/** peer-storage mode: a peer's channel_reestablish for a channel this node
	 *  has no record of was held instead of failed (issue #462). Apply a
	 *  Recovery Capsule before expiresAt or the peer force-closes. */
	'recovery:reestablish-held': (data: {
		peerPubkey: string;
		channelId: string;
		expiresAt: number;
	}) => void;
	'recovery:guardian_unreachable': (data: {
		detail: string;
		sequence?: string;
	}) => void;
	/** A storage peer returned a Recovery Capsule that became (or replaced)
	 *  this node's best candidate from that peer (issue #690). Only newer
	 *  heads are announced, so an equal-head re-send after a reconnect is
	 *  silent. candidates counts the peers holding a valid capsule. */
	'recovery:capsule-retrieved': (data: {
		fromPeer: string;
		writerEpoch: string;
		latestSequence: string;
		inline: boolean;
		channelCount: number;
		candidates: number;
	}) => void;
	'recovery:restore-progress': (data: { type: string; detail: string }) => void;
	'recovery:restored': (data: {
		exact: boolean;
		framesApplied: number;
		guardiansRepaired: number;
		epoch: string;
		/** Capsule restores only: 2 = exact state installed, 1 = SCB only. */
		tier?: 1 | 2;
		/** Capsule restores only: true after a Tier 2 install replaced the database. */
		restartRequired?: boolean;
		/** Capsule restores only: the node was rebuilt in-process on the
		 *  installed state (the automatic path), so no restart follows. */
		resumed?: boolean;
	}) => void;
	/**
	 * Guardian hosting (issue #699): this node started serving a set; a
	 * quota refused a registration or a write; a session violated framing
	 * and was dropped.
	 */
	'guardian:set-registered': (data: { detail: string; setId?: string }) => void;
	'guardian:quota-refused': (data: { detail: string; setId?: string }) => void;
	'guardian:session-violation': (data: {
		detail: string;
		peer?: string;
	}) => void;
	/**
	 * Guardian-set rotation (wire 5.9, issue #701): each step of a rotation
	 * this node runs; the switch, with the set that carries the journal from
	 * then on; and a boot that followed a retired set to the live one.
	 */
	'recovery:rotation-progress': (data: {
		type: string;
		detail: string;
		generation?: string;
	}) => void;
	'recovery:rotated': (data: {
		generation: string;
		guardians: Array<{ guardianId: string; url: string }>;
	}) => void;
	'recovery:rotation-followed': (data: {
		generation: string;
		from: string[];
		to: string[];
	}) => void;
	/**
	 * JIT receive, LSP side (issue #669). Relayed JSON-safe: every satoshi and
	 * millisatoshi figure is a decimal string. `jit:intent` is a wallet's
	 * accepted request, keyed by the intercept scid the LSP minted for it;
	 * `jit:intercepted` a payment part held for it (or, on the splice path,
	 * for an existing channel); `jit:funding` the open or splice starting;
	 * `jit:forwarded` the held parts delivered; `jit:failed` the parts failed
	 * back upstream with the reason.
	 */
	'jit:intent': (data: {
		scidHex: string;
		walletPubkeyHex: string;
		paymentHashHex?: string;
		maxAmountMsat: string;
		expectedTotalMsat?: string;
		targetRemainingInboundSat: string;
		expiresAt: number;
	}) => void;
	'jit:intent-superseded': (data: {
		scidHex: string;
		walletPubkeyHex: string;
	}) => void;
	'jit:intercepted': (data: {
		scidHex?: string;
		channelIdHex?: string;
		amountMsat: string;
	}) => void;
	'jit:funding': (data: {
		scidHex?: string;
		channelIdHex?: string;
		fundingSats: string;
	}) => void;
	'jit:forwarded': (data: {
		scidHex?: string;
		channelIdHex?: string;
		parts: number;
	}) => void;
	'jit:failed': (data: {
		scidHex?: string;
		channelIdHex?: string;
		parts: number;
		reason: string;
	}) => void;
	/**
	 * Direct funding, receiver side (issue #669): a payer's offer accepted
	 * (`paired` says whether it came from a peer in the trusted set, which is
	 * what decides zero-conf and the splice path), declined or failed with the
	 * reason, or completed with the funding out.
	 */
	'direct-funding:offer:accepted': (data: {
		offerId: string;
		paired: boolean;
		resumed?: boolean;
	}) => void;
	'direct-funding:offer:declined': (data: {
		offerId: string;
		reason: string;
	}) => void;
	'direct-funding:offer:failed': (data: {
		offerId: string;
		reason: string;
	}) => void;
	'direct-funding:offer:completed': (data: { offerId: string }) => void;
}
