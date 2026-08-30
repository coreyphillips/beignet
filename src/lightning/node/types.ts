/**
 * BOLT Node API: Types and configuration.
 *
 * Defines the interfaces and enums for the LightningNode orchestrator,
 * including node config, payment tracking, invoice creation, and
 * channel/node info queries.
 */

import { IRoutingHintHop, Network } from '../invoice/types';
import { IBolt12Invoice } from '../offer/types';
import { IChannelConfig, ChannelState } from '../channel/types';
import { IChannelBasepoints } from '../keys/derivation';
import { IRoute, INodeAddress } from '../gossip/types';
import { FeatureFlags } from '../features/flags';
import { IStorageBackend, IInvoiceInfo } from '../storage/types';
import { IChainBackend } from '../chain/chain-watcher';
import { ILogger } from '../../logger';
import { IPerChannelKeys } from '../channel/channel-manager';
import { SignerFactory } from '../keys/signer';
import { WebSocketConstructor } from '../transport/websocket';
import { GuardianStartupGate } from '../recovery/startup-gate';
import { DurabilityBarrier } from '../recovery/durability-barrier';
import { RecoveryDurability } from '../recovery/types';
import type { GuardianDescriptor } from '../recovery/capsule';

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

/** Ceiling for estimator-supplied feerates fed into LN operations (sat/vB).
 *  A buggy or unit-confused estimator (e.g. one returning sat/kvB or a
 *  BTC-denominated value) must not translate into absurd commitment feerates
 *  or funding/sweep fees; 5000 sat/vB comfortably exceeds any observed
 *  mempool peak. */
export const MAX_FEE_RATE_SAT_PER_VBYTE = 5000;

/**
 * Sanity-clamp an IFeeEstimator result before it feeds LN operations: cap at
 * MAX_FEE_RATE_SAT_PER_VBYTE and floor positive sub-1 values to 1 sat/vB.
 * Non-positive / non-finite values pass through unchanged; they are the
 * estimator's "unavailable" signal and every caller has its own fallback.
 * `onClamp` fires only when the value was actually adjusted.
 */
export function clampFeeRateSatPerVbyte(
	satPerVbyte: number,
	onClamp?: (original: number, clamped: number) => void
): number {
	if (Number.isNaN(satPerVbyte) || satPerVbyte <= 0) return satPerVbyte;
	let clamped = satPerVbyte;
	if (clamped > MAX_FEE_RATE_SAT_PER_VBYTE) {
		clamped = MAX_FEE_RATE_SAT_PER_VBYTE;
	}
	if (clamped < 1) {
		clamped = 1;
	}
	if (clamped !== satPerVbyte && onClamp) {
		onClamp(satPerVbyte, clamped);
	}
	return clamped;
}

/**
 * Restriction on which wallet coins a selection may use (issue #572).
 *
 * `utxos` names outpoints (txid in display byte order, as listUtxos reports)
 * that MUST all be contributed: a named outpoint that is missing, frozen or
 * otherwise unspendable makes the selection throw naming it, never silently
 * skip it. When the named coins fall short of amount + fee, `allowTopUp`
 * permits completing the selection from the remaining spendable coins;
 * without it the selection throws the normal insufficient-funds error.
 * Omitted entirely, the selection is unrestricted (existing behavior).
 */
export interface IUtxoSelectionOpts {
	utxos?: Array<{ txid: string; vout: number }>;
	allowTopUp?: boolean;
}

export interface IFundingProvider {
	/**
	 * Build (but do not broadcast) the channel funding transaction.
	 * @param max When true, sweep the whole balance into the funding output (no
	 *   change). The caller must have committed funding_satoshis equal to the swept
	 *   amount; the provider verifies the output matches.
	 */
	buildFundingTransaction(
		address: string,
		amountSats: bigint,
		satsPerByte?: number,
		max?: boolean
	): Promise<{ txHex: string; txid: Buffer; outputIndex: number }>;

	broadcastTransaction(txHex: string): Promise<string>;

	/**
	 * Renew the input pledges of a transaction we are still obligated to
	 * broadcast (optional).
	 *
	 * A funding (or splice) transaction is retained and retried until it
	 * CONFIRMS, which can outlast the pledge that reserved its inputs: the
	 * provider frees a pledge on a timeout, and again when the wallet stops
	 * listing the coin, so a mempool eviction hands the inputs back unspent AND
	 * unfrozen. Either way a later funding or an ordinary wallet send can
	 * double-spend the transaction we still owe the network. The node calls this
	 * once per block and once at startup for every retained transaction, so a
	 * pledge lives exactly as long as the obligation it protects; when the
	 * obligation retires the calls stop and the pledge ages out as usual.
	 *
	 * Implementations must be idempotent and must not throw for coins the wallet
	 * no longer holds (the transaction's own confirmed or in-mempool spend).
	 */
	pledgeTransactionInputs?(txHex: string): Promise<void>;

	/**
	 * Release the pledges holding these exact outpoints (optional). Called when
	 * a v2 open is conclusively dead before any tx_signatures were released, so
	 * its reserved coins return to the spendable pool at once instead of
	 * waiting out the pledge TTL (issue #311). `txid` is display-order hex.
	 *
	 * Implementations must only unfreeze coins they themselves pledged (never
	 * user freezes), must ignore unknown outpoints, and must be idempotent.
	 */
	releaseInputPledges?(
		outpoints: Array<{ txid: string; vout: number }>
	): Promise<void>;

	/**
	 * Splice-in (optional): select wallet UTXOs covering `amountSats` plus fees
	 * and return them as splice inputs (each with its prevTx, value and a
	 * witness-signing closure) along with a change script. Required for
	 * `node.spliceIn` to fund the channel increase from the on-chain wallet.
	 *
	 * Sized with the SPLICE weight (estimateSpliceTxWeight), which includes the
	 * shared 2-of-2 funding input a splice always spends. A v2 open funding
	 * transaction has no such input, so this is NOT the right selector for a
	 * dual-funding contribution: use selectDualFundingInputs, which the v2 open
	 * paths prefer and fall back from to this method only for providers that
	 * predate it (issue #380).
	 */
	selectSpliceInputs?(
		amountSats: bigint,
		feeratePerKw: number,
		opts?: IUtxoSelectionOpts
	): Promise<{
		inputs: import('../channel/channel').ISpliceWalletInput[];
		changeScript: Buffer;
	}>;

	/**
	 * Price a splice-in without performing one (optional): the fee and the
	 * largest fundable amount at this feerate, computed with the same UTXO
	 * filter and weight formula selectSpliceInputs will use.
	 */
	quoteSpliceIn?(feeratePerKw: number): {
		spendableSats: bigint;
		feeSats: bigint;
		maxAmountSats: bigint;
		inputCount: number;
	};

	/**
	 * Price a max (sweep-everything) dual-funded v2 open (optional; required,
	 * with selectMaxDualFundingInputs, for openChannel with fundMax toward a
	 * dual-fund peer). Synchronous because open_channel2 commits
	 * funding_satoshis up front. The quote prices contributing EVERY spendable
	 * UTXO as the initiator at this feerate using the SAME weight formula the
	 * channel's contribution computation applies
	 * (dualFundingContributionWeight), so the committed amount leaves exactly
	 * the interactive-tx fee behind and the funding transaction carries no
	 * change output.
	 */
	quoteDualFundingMax?(feeratePerKw: number): {
		/** spendableSats minus feeSats (0n when the fee exceeds the balance). */
		fundingSatoshis: bigint;
		spendableSats: bigint;
		feeSats: bigint;
		inputCount: number;
	};

	/**
	 * Select EVERY spendable wallet UTXO for a max dual-funded open (optional,
	 * paired with quoteDualFundingMax). The channel derives change as
	 * inputs - contribution - fee, which lands on exactly zero when the
	 * balance is unchanged since the quote; a deposit that lands in between
	 * simply becomes change (or extra fee below the dust limit), and a spend
	 * in between aborts the open as underfunded rather than guessing.
	 */
	selectMaxDualFundingInputs?(): Promise<{
		inputs: import('../channel/channel').ISpliceWalletInput[];
		changeScript: Buffer;
	}>;

	/**
	 * Select wallet UTXOs to fund a dual-funded (v2 open) contribution of
	 * `amountSats` (optional; used by the opener's auto-funding, a lease
	 * seller's acceptor contribution and an RBF contribution raise).
	 *
	 * The target MUST be priced with dualFundingContributionWeight(count,
	 * initiator) from channel/splice-weight, the SAME formula the channel's
	 * contribution computation applies to derive change as
	 * inputs - contribution - fee. Sizing with the splice weight instead
	 * under-reserves once the input count grows past the point where the
	 * splice estimator's shared-funding-input term stops covering the
	 * difference, and the open then dies as underfunded after accept_channel2
	 * (issue #380).
	 *
	 * `initiator` selects our fee share: the initiator additionally pays the
	 * common transaction fields and the shared funding output.
	 *
	 * `topUp` marks an `amountSats` that already covers those fixed terms
	 * because the contribution already holds registered inputs (an RBF raise).
	 * Such a selection MUST charge only dualFundingTopUpWeight(count), the
	 * marginal per-input weight; charging a second full contribution
	 * double-counts the fixed terms and refuses a raise the wallet can afford.
	 */
	selectDualFundingInputs?(
		amountSats: bigint,
		feeratePerKw: number,
		initiator: boolean,
		topUp?: boolean,
		opts?: IUtxoSelectionOpts
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
	/**
	 * Custom channel signer factory (ISigner) so channel signing keys can
	 * live out of process (remote/external signer). When set it replaces the
	 * internal ChannelSigner construction for every channel, keyed by the
	 * channel's key index. Library-level injection only (no transport). The
	 * raw key Buffers above remain required for non-signer paths (sweeps,
	 * chain monitors); with a factory they are simply never used to sign
	 * channel commitments.
	 */
	signerFactory?: SignerFactory;
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
	/**
	 * Recovery Protocol journal (docs/RECOVERY-PROTOCOL.md 5.3, Phase 2).
	 * Default OFF: when enabled (and the storage backend supports frames),
	 * every safety-critical transition also appends an encrypted, hash-chained
	 * frame in the same transaction, with periodic full-state snapshots and
	 * compaction. With `peerStorageEnabled` too, the node also distributes a
	 * Recovery Capsule over peer_storage (5.4, Phase 3): SCB + journal
	 * locator, with the full journal inline whenever it fits, refreshed on
	 * journaled commits at most once per minute. Purely additive; disabling
	 * it changes nothing else.
	 */
	recovery?: {
		enabled?: boolean;
		/**
		 * How durable a safety transition must be before the wire messages it
		 * authorizes may reach the peer (5.8, Phase 6). Defaults to
		 * `async-remote`, which is the node's pre-Phase-6 conduct: fsync,
		 * continue, replicate in the background.
		 *
		 * `quorum` is the only value that changes behaviour. It holds
		 * revoke_and_ack, update_fulfill_htlc, commitment_signed, the
		 * irreversible splice messages and the data-loss error until the
		 * journal frame behind them has reached a guardian quorum, and it
		 * REQUIRES `barrier`. What it buys is the Tier 3 guarantee: once a
		 * peer has seen new channel state from us, sufficient remote
		 * information already exists to restore that state, so a restored
		 * device resumes the channel instead of falling back to DLP.
		 *
		 * Quorum is sticky. Once this journal has written quorum frames the
		 * writer stays in quorum mode whatever this says, because a certified
		 * head reading 'quorum' must never be followed by an unbarriered
		 * frame. Leaving the mode means starting a new namespace, not editing
		 * a config value.
		 */
		durability?: RecoveryDurability;
		/**
		 * The barrier itself (5.8, Phase 6). Built outside the node with its
		 * guardian set, exactly as `startupGate` is, and required whenever
		 * `durability` resolves to `quorum`. It also drives replication in
		 * every mode, so an `async-remote` node passes one too if it wants its
		 * journal replicated at all.
		 *
		 * Its pump is kicked by three things: a commit, a barrier waiter, and
		 * ownership settling. The node performs the third when a `startupGate`
		 * is configured alongside it. WITHOUT a gate it is the integrator's
		 * job: call `barrier.kickReplication()` as soon as the barrier's
		 * `lease` closure starts returning the new lease, or a frame committed
		 * before ownership settled stays unreplicated until the next commit,
		 * which on a quiet node is never.
		 */
		barrier?: DurabilityBarrier;
		/**
		 * Frames compaction will hold back for a guardian that has not caught
		 * up, before pruning anyway.
		 *
		 * Defaults to 1024 in `local` and `async-remote`, where a dead replica
		 * costs durability alone and unbounded disk is the worse failure. In
		 * `quorum` there is NO default: crossing the ceiling deletes frames
		 * fewer than `required` guardians ever accepted, so those frames exist
		 * nowhere and the namespace is finished. Setting this in quorum mode is
		 * opting in to that outcome.
		 */
		maxRetainedFrameGap?: number;
		/** Delta frames between full-state snapshots (default 256). */
		snapshotIntervalFrames?: number;
		/**
		 * Delta plaintext bytes between snapshots, whichever of the two
		 * limits trips first (default 4 MiB).
		 */
		snapshotIntervalBytes?: number;
		/**
		 * Startup ownership quarantine (5.6, Phase 5). A guardian-backed
		 * node MUST pass its gate HERE, at construction, never afterward:
		 * the constructor schedules auto-reconnect dials, so a gate
		 * installed later races them and can lose. With a gate present the
		 * node starts quarantined and refuses ALL peer contact, inbound and
		 * outbound, including connection establishment itself, until a
		 * guardian quorum confirms the writer lease via gate.confirm(); a
		 * proven newer epoch fences the node permanently instead. Omit only
		 * for a node genuinely running without guardians.
		 */
		startupGate?: GuardianStartupGate;
		/**
		 * Guardian locators embedded in every Recovery Capsule the node
		 * pushes to storage peers (5.4; wire 2.4 for the recoverable
		 * credential), so a seed restore finds the guardian set from peer
		 * storage alone instead of needing it from configuration. Pure data:
		 * the node never dials a descriptor, the barrier and gate above
		 * already hold the clients. `buildGuardianRecovery` fills this from
		 * the parsed set; a peer-storage-only node has none.
		 */
		guardians?: GuardianDescriptor[];
		/**
		 * How long an inbound channel_reestablish naming a channel this node
		 * has NO record of is held before the BOLT 1 error goes out (5.7,
		 * issue #462). Absent or 0 answers immediately, which is what every
		 * mode but peer-storage wants.
		 *
		 * Set it on a node that may be an INCOMPLETE restore target. A node
		 * restoring over peer_storage boots on a deliberately empty database
		 * and receives the peer's reestablish in the same instant as the
		 * Recovery Capsule that would answer it, so failing the channel there
		 * force-closes exactly the channel the restore is about to resume.
		 * The peer waits indefinitely for silence and permanently for an
		 * error, so the deferral costs nothing and buys the restore window.
		 * The error is deferred, never dropped.
		 *
		 * Guardian modes have no use for it: their startup gate already
		 * refuses all peer contact until ownership is confirmed, and a
		 * guardian restore rebuilds the database before the node runs.
		 */
		unknownChannelReestablishHoldMs?: number;
	};
	/** Chain backend for blockchain monitoring (Electrum, Esplora, etc.) */
	chainBackend?: IChainBackend;
	/** HTLC safety margin in blocks before force-failing expiring HTLCs (default 6) */
	htlcSafetyMargin?: number;
	/**
	 * Whether to relay third-party HTLCs (be a routing hop). Default true, which
	 * preserves the historical behaviour: any node with an announced channel
	 * forwards. Set false to decline all forwards (a wallet that does not want to
	 * route); declined forwards fail back promptly with temporary_node_failure,
	 * and our channel_updates advertise the BOLT 7 disable bit so route finders
	 * stop selecting us. Does not affect our own sends or receives.
	 */
	forwardingEnabled?: boolean;
	/**
	 * Whether to signature-verify foreign broadcast gossip at intake. Default
	 * false: entries are admitted with deferred provenance and verified only
	 * when a gossip query asks for them, which skips nearly the entire
	 * first-dump verification cost for wallet nodes (issue #443). Nothing
	 * unverified is ever served to gossip queries in either mode. Set true on
	 * relay-class nodes that want to serve the graph: intake and restore then
	 * verify eagerly, and signatureless RGS-primed entries are re-requested
	 * from peers so their signed copies become servable.
	 */
	eagerGossipVerify?: boolean;
	/**
	 * JIT channel receive, LSP role (issue #594): hold HTLCs addressed to
	 * intercept SCIDs this node minted for wallet peers, fund a zero-conf
	 * channel to the client (or splice its existing one bigger), then forward.
	 * Off unless `enabled` is set; the caps in IJitReceiveConfig are the only
	 * ceiling on what this node will front with its own coins.
	 */
	jitReceive?: import('../liquidity/jit-receive').IJitReceiveConfig;
	/**
	 * JIT channel receive, WALLET role (issue #595): the most this node will
	 * let an LSP quote before `requestJitReceive` refuses the ack. Separate
	 * from `jitReceive`, which is the LSP role: a wallet that only receives
	 * runs no engine, and a node that runs the engine need not buy from
	 * anybody. Defaults are blunt refusal ceilings, not a price.
	 */
	jitReceiveClient?: {
		/** Flat part ceiling (sat); default JIT_CLIENT_MAX_FLAT_FEE_SAT. */
		maxFlatFeeSat?: bigint;
		/** Proportional part ceiling (ppm); default JIT_CLIENT_MAX_FEE_PPM. */
		maxFeePpm?: number;
	};
	/**
	 * Third-party direct funding (issue #532 phase 4): an unrelated payer's
	 * on-chain payment becomes this node's channel funding. Absent means the
	 * whole feature, lanes included, is never constructed.
	 *
	 * Present is not the same as active: the receiver serves nothing until an
	 * operator names a liquidity peer to negotiate the funding with, and mints
	 * nothing until `mintDirectFundingRequest` is called.
	 */
	directFunding?: IDirectFundingNodeConfig;
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
	/** Addresses to advertise in our node_announcement (BOLT 7 descriptors,
	 *  e.g. from parseAnnouncedAddress). Only meaningful once the node has at
	 *  least one announced (public) channel. */
	announcedAddresses?: INodeAddress[];
	/** SOCKS5 proxy for outbound peer connections (e.g. Tor on 127.0.0.1:9050) */
	socks5Proxy?: { host: string; port: number };
	/**
	 * WebSocket constructor for outbound WS peer connections. Defaults to the
	 * in-repo RFC-cased Node client under Node (CLN's ws listener rejects the
	 * built-in WebSocket's lowercased headers) and to globalThis.WebSocket in
	 * browsers. Only consulted when a peer is dialed with transport
	 * {type: 'ws'}; mirrors how electrumOptions injects net/tls.
	 */
	webSocketImpl?: WebSocketConstructor;
	/**
	 * Watchtowers to ship encrypted justice data to at every revocation, as
	 * `pubkey@host:port` URIs (LND altruist wtwire protocol). Empty/undefined
	 * disables the watchtower client entirely.
	 */
	watchtowers?: string[];
	/** Prefer anchor channels (option_anchors_zero_fee_htlc_tx) when opening channels */
	preferAnchors?: boolean;
	/**
	 * option_wumbo (large_channels, bit 18, default false): advertise the bit
	 * and lift the BOLT 2 2^24 sat funding cap to MAX_WUMBO_FUNDING_SATOSHIS
	 * (10 BTC) for peers that also advertise it. Opens/accepts/splices with
	 * non-wumbo peers keep the 2^24 cap.
	 */
	largeChannels?: boolean;
	/**
	 * Propose simple taproot channels (option_taproot) when opening channels.
	 * MuSig2 funding and commitment signing (deterministic verification nonces)
	 * are fully wired into the live state machine; the complete lifecycle
	 * (open, payments both directions, reestablish, cooperative close, force
	 * close) is validated against LND on regtest. Off by default because the
	 * feature bit is still in staging upstream (180/181); not recommended for
	 * mainnet balances yet.
	 */
	preferTaproot?: boolean;
	/**
	 * Liquidity ads (bLIP-0051) SELLER policy: when set, an inbound
	 * open_channel2 carrying request_funds is answered with a signed will_fund
	 * at these rates and the requested contribution is funded from the node's
	 * on-chain wallet (fundingProvider). Leave unset to never sell leases.
	 */
	leaseRates?: import('../gossip/types').ILeaseRates;
	/**
	 * BOLT 1 peer storage (option_provide_storage, default true): store the
	 * latest peer_storage blob per channel/trusted peer and return it on
	 * reconnect, and push our own blob (set via distributePeerStorage) to
	 * capable peers. When false the feature bit is not advertised and both
	 * directions are disabled.
	 */
	peerStorageEnabled?: boolean;
	/** Fee estimator for dynamic fee rates */
	feeEstimator?: IFeeEstimator;
	/**
	 * Leveled diagnostic logger (debug/info/warn/error). Defaults to a no-op
	 * logger (the node is silent today), so injecting one only adds output.
	 * Every structured action log entry is mirrored to logger.debug as
	 * "category:action" alongside the persisted action log.
	 */
	logger?: ILogger;
	/** Maximum payment retries (default 3) */
	maxPaymentRetries?: number;
	/** Global HTLC limit across all channels (default 1000) */
	maxTotalInFlightHtlcs?: number;
	/**
	 * BOLT 2 quiescence watchdog window in ms (default 60_000): "MUST
	 * disconnect after 60 seconds of quiescence if the HTLCs are pending".
	 * Injectable so tests can shrink it.
	 */
	quiescenceTimeoutMs?: number;
	/** Starting channel key index (for per-channel HD derivation) */
	nextChannelIndex?: number;
	/**
	 * Per-channel key derivation callback, producing unique keys per channel
	 * index. MUST be pure and deterministic: the same index has to answer
	 * with the same key material for the life of the wallet, since a
	 * channel's basepoints are committed to on chain while its signing
	 * secrets are re-derived on every restart and every recovery.
	 */
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
	/**
	 * Automatic circular rebalancing (default DISABLED). When enabled, a
	 * periodic scan runs the advisor's rebalance plan via
	 * executeRebalanceRecommendations, spending at most budgetSatsPerDay in
	 * routing fees per UTC day (tracked in memory and persisted via metadata).
	 */
	autoRebalance?: IAutoRebalanceConfig;
	/**
	 * Automatic routing-fee (ppm) tuning (default DISABLED). When enabled, a
	 * periodic loop nudges each channel's proportional fee up 25% when its
	 * outbound side is depleted but still forwarding, and down 25% when it saw
	 * no forwards in the window, clamped to [floorPpm, ceilPpm].
	 */
	autoTuneFees?: IAutoTuneFeesConfig;
}

// ─── Direct funding ───

/**
 * The operator policy for third-party direct funding (#613). Everything here is
 * settable at runtime through `LightningNode.setDirectFundingPolicy`, which is
 * what `POST /direct-funding/configure` drives; the values passed at
 * construction are the starting point, and the persisted policy wins over them
 * on a restart.
 */
export interface IDirectFundingPolicy {
	/** The peer every direct-funded channel is negotiated with. */
	liquidityPeer?: string;
	/** Where that peer is reachable, for the relay and onion descriptors. */
	liquidityHost?: string;
	liquidityPort?: number;
	/** Smallest offer this receiver serves; the 5000 sat floor applies under it. */
	minAmountSat?: number;
	/** Largest offer this receiver serves. Unset means no ceiling. */
	maxAmountSat?: number;
	/** Let a direct-funded open go zero-conf (the app calls this `trusted`). */
	allowZeroConf?: boolean;
	/** Serve offers by splicing an existing channel rather than opening one. */
	allowSplice?: boolean;
	/**
	 * Inbound liquidity the operator would like bought alongside. Recorded and
	 * reported so the operator surface can round-trip it; nothing consumes it
	 * yet, because buying a lease alongside a direct-funded open is not part of
	 * the ported protocol.
	 */
	targetInboundSat?: number;
}

export interface IDirectFundingNodeConfig {
	/** Which lanes this node runs; every one is on unless switched off. */
	directPeer?: boolean;
	onion?: boolean;
	relay?: boolean;
	/**
	 * Relay direct-funding frames for OTHER nodes. A separate operator opt-in
	 * (BEIGNET_DF_RELAY) because it is work done for strangers, metered but not
	 * free.
	 */
	relayServer?: boolean;
	/** Life of a minted request, capped at a week. */
	requestTtlMs?: number;
	/** The starting policy; a persisted one replaces it on restore. */
	policy?: IDirectFundingPolicy;
}

// ─── Advisor Execution ───

export interface IAutoRebalanceConfig {
	/** Master switch -- MUST be explicitly set to true (default false). */
	enabled?: boolean;
	/** Max routing fees to spend on rebalances per UTC day (default 1000). */
	budgetSatsPerDay?: number;
	/** Local-balance percent below/above which a channel is imbalanced (default 20). */
	minImbalancePct?: number;
	/** Scan interval in ms (default 3_600_000 = 1 hour). */
	intervalMs?: number;
}

export interface IAutoTuneFeesConfig {
	/** Master switch -- MUST be explicitly set to true (default false). */
	enabled?: boolean;
	/** Tune interval AND forwarding observation window in ms (default 6 hours). */
	intervalMs?: number;
	/** Lowest ppm the tuner will ever set (default 1). */
	floorPpm?: number;
	/** Highest ppm the tuner will ever set (default 10_000). */
	ceilPpm?: number;
}

/** Outcome of one circular rebalance (msat values are bigint in the library). */
export interface IRebalanceResult {
	paymentHash: Buffer;
	/** Amount that arrived back on the inbound channel. */
	amountMsat: bigint;
	/** Total routing fee paid for the loop. */
	feeMsat: bigint;
	/** Number of hops in the circular route (including the final hop to us). */
	hops: number;
}

/** One attempted rebalance inside executeRebalanceRecommendations. */
export interface IRebalanceAttempt {
	fromChannelId: string;
	toChannelId: string;
	amountSats: bigint;
	status: 'SUCCEEDED' | 'FAILED' | 'SKIPPED_BUDGET';
	feeMsat?: bigint;
	error?: string;
}

export interface IRebalanceExecutionSummary {
	attempts: IRebalanceAttempt[];
	succeeded: number;
	failed: number;
	skippedBudget: number;
	/** Fees spent by THIS run in msat. */
	feeSpentMsat: bigint;
	/** Remaining fee budget for the current UTC day in msat. */
	budgetRemainingMsat: bigint;
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
	/**
	 * Why a payment failed when no onion failure code is available: it failed
	 * LOCALLY, before the HTLC ever reached the network, or a peer's failure came
	 * back undecryptable. Without this a local failure is indistinguishable from a
	 * remote one, since both surface only as an absent failureCode.
	 */
	failureReason?: string;
	retryCount?: number;
	/**
	 * Block height this attempt converted its relative route CLTV deltas against.
	 * A payee reporting a height at or below this cannot be telling us anything
	 * new, so it is what a height-skew failure must be judged against, not our
	 * live height.
	 */
	cltvBaseHeight?: number;
	createdAt: number;
	completedAt?: number;
	metadata?: Record<string, string>;
}

/** A keysend has no invoice to re-pay, so a retry replays these instead. */
export interface IKeysendRetrySource {
	options: IKeysendOptions;
	/** Reused so the retry keeps the original payment hash. */
	preimage: Buffer;
}

export interface IPaymentRetryContext {
	/** Absent for keysend and BOLT 12, which replay their own sources. */
	invoiceStr?: string;
	keysend?: IKeysendRetrySource;
	/**
	 * A BOLT 12 payment has no invoice string to re-pay, so a retry
	 * re-dispatches the decoded invoice through payBolt12Invoice with the
	 * accumulated channel exclusions.
	 */
	bolt12Invoice?: IBolt12Invoice;
	/** Index into bolt12Invoice.paths used by the current attempt. */
	bolt12PathIndex?: number;
	/**
	 * Indices of bolt12Invoice.paths whose BLINDED segment failed. Channel
	 * exclusion cannot route around a blinded hop (its SCID is opaque), so
	 * route selection skips these paths entirely and a retry rotates to the
	 * invoice's other paths (BOLT 4: on a failure from a blinded hop the
	 * origin SHOULD use a different blinded path).
	 */
	bolt12ExcludedPathIndices?: Set<number>;
	excludedChannels: Set<string>;
	retryCount: number;
	maxRetries: number;
	/** Fee cap preserved across retries */
	maxFeeMsat?: bigint;
	/** Amount for amount-less invoices, preserved across retries */
	amountMsat?: bigint;
	/**
	 * Height a payee reported when it rejected this payment for being ahead of
	 * us. Scoped to this payment on purpose: it is what one final node claimed,
	 * not the chain's height, so it must not steer unrelated payments.
	 */
	cltvBaseHeightOverride?: number;
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
	 * With `useBlindedPaths`, ALSO emit cleartext BOLT 11 routing hints (tag 3)
	 * for private channels, so a payer that does not understand the non-spec
	 * blinded-paths tag (25) can still route (e.g. CLN/LND paying a private
	 * channel). Off by default: a cleartext hint exposes the node id that
	 * blinding is meant to hide, so this trades that privacy for routability.
	 */
	includeCleartextHintsWithBlinded?: boolean;
	/**
	 * Routing hints the CALLER supplies, emitted alongside the ones built from
	 * our own channels. The case this exists for is JIT receive (issue #594): a
	 * wallet with no channel at all is payable through a hint naming its LSP
	 * and the intercept SCID that LSP minted, which no channel of ours can
	 * produce because the channel does not exist yet.
	 */
	extraRoutingHints?: IRoutingHintHop[][];
	/**
	 * JIT receive, wallet side (issue #595): the opening-fee QUOTE the LSP
	 * returned in its ack. The final hop then accepts HTLCs short of their
	 * onion's amt_to_forward by at most that fee, evaluated against the total
	 * the payment declares and bounded in AGGREGATE across the payment's parts.
	 * Without it the invoice behaves exactly as any other, so this is the one
	 * thing that makes a skimmed JIT delivery settle rather than fail BOLT 4.
	 */
	jitFeeAllowance?: { flatFeeSat: number; feePpm: number };
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
	/**
	 * Funding output index in fundingTxid; present exactly when fundingTxid
	 * is. With it a consumer holds the full funding outpoint (direct funding
	 * builds its funding-output attestation from it, issue #572).
	 */
	fundingOutputIndex?: number;
	shortChannelId?: string;
	feeratePerKw?: number;
	htlcCount?: number;
	/**
	 * Local balance the channel settles to when its in-flight splice locks.
	 * Present only while a splice is past its point of no return; the live
	 * localBalanceMsat stays pre-splice until splice_locked.
	 */
	pendingSpliceLocalBalanceMsat?: bigint;
	/**
	 * Whether the channel will accept a NEW HTLC: it can carry traffic right
	 * now (NORMAL, or ECDSA pending-lock mid-splice with pay-during-splice
	 * active) AND its state is provably current.
	 *
	 * This is the sending gate. It is deliberately NOT "can exchange updates":
	 * a channel answering false here can still settle and fail the HTLCs it
	 * already has, and can still negotiate a close.
	 */
	htlcUsable?: boolean;
	/**
	 * The channel was restored from a Recovery Capsule and no
	 * channel_reestablish has proven its state current, so it takes no NEW
	 * HTLCs and is offered to no router or planner (issue #469). Existing
	 * HTLCs still settle; a cooperative close is refused in both directions
	 * unless the operator's acceptStaleStateRisk acknowledgement covers the
	 * negotiation. Present only while the hold stands; it is the reason a
	 * NORMAL channel can report htlcUsable false.
	 */
	restoreRecencyUnproven?: boolean;
	/**
	 * Neither mempool nor chain can account for this channel's funding and this
	 * node has no broadcast left to answer with, so the channel is quarantined:
	 * it takes no NEW HTLCs and is offered to no router or planner (issue #593).
	 * Existing HTLCs still settle and fail, and a close still negotiates.
	 *
	 * Reversible, and NOT the BOLT 2 forget decision: the channel keeps every
	 * key, commitment and watch, and the flag clears by itself when the funding
	 * is seen again. Present only while the quarantine stands; it is, alongside
	 * restoreRecencyUnproven, the other reason a NORMAL channel can report
	 * htlcUsable false.
	 */
	fundingUnaccounted?: boolean;
	/**
	 * Present exactly when the channel is mid-splice by effective state
	 * (looking through a reconnect): true = pay-through accounting (counted in
	 * the canonical balance at min(live, settle-to)); false = parked (its
	 * settle-to balance lives entirely in the splicing bucket).
	 */
	payThroughSplice?: boolean;
	/** Reserve we must maintain (set by remote peer), in msat */
	localReserveMsat?: bigint;
	/** Reserve remote must maintain (set by us), in msat */
	remoteReserveMsat?: bigint;
	/** Whether this channel is private (unannounced) */
	isPrivate?: boolean;
	/** Effective routing policy (per-channel override or node defaults) */
	feeBaseMsat?: number;
	feeProportionalMillionths?: number;
	cltvExpiryDelta?: number;
	htlcMinimumMsat?: bigint;
	htlcMaximumMsat?: bigint;
	/**
	 * Close progress, present for channels that are closing or closed
	 * (SHUTTING_DOWN, NEGOTIATING_CLOSING, CLOSED, FORCE_CLOSED, and ERRORED
	 * with an on-chain funding output).
	 */
	closeStatus?: ICloseStatus;
}

/**
 * How a channel's close is progressing, derived from persisted channel state
 * and the chain monitor's classified commitment spend.
 */
export interface ICloseStatus {
	/** Who published (or is negotiating) the close. */
	closer: 'local' | 'remote' | 'cooperative' | 'unknown';
	/**
	 * Why WE closed: 'user' for an API-initiated close, otherwise the
	 * automatic close code (e.g. REESTABLISH_TIMEOUT_FORCE_CLOSED). Absent
	 * for a close the peer initiated.
	 */
	reason?: string;
	/** Txid (display byte order) of the commitment or mutual close, when known. */
	closingTxid?: string;
	/**
	 * Whether the daemon believes the close tx reached the network: the last
	 * broadcast attempt succeeded or the spend was observed on chain.
	 */
	broadcast: boolean;
	/** Block height the close confirmed at; 0 while unconfirmed. */
	confirmationHeight: number;
	/**
	 * On-chain resolution progress: 'pending' until the close tx confirms,
	 * 'sweeping' while outputs are being swept and/or the close waits out its
	 * anti-reorg depth, 'resolved' once every output is irrevocably settled.
	 */
	resolution: 'pending' | 'sweeping' | 'resolved';
	/**
	 * Height at which the to_local CSV matures and our main balance becomes
	 * spendable. Only present for our own force close once computable.
	 */
	fundsAvailableHeight?: number;
}

// ─── Channel Routing Policy ───

/**
 * Partial per-channel routing-policy override. Unset fields fall back to the
 * node-wide defaults (forwardingFeeBaseMsat / forwardingFeePropMillionths /
 * forwardingCltvDelta) and the channel's negotiated htlc_minimum_msat /
 * capacity-capped max_htlc_value_in_flight_msat.
 */
export interface IChannelPolicyUpdate {
	feeBaseMsat?: number;
	feeProportionalMillionths?: number;
	cltvExpiryDelta?: number;
	htlcMinimumMsat?: bigint;
	htlcMaximumMsat?: bigint;
}

/** Effective routing policy for a channel plus where each value came from. */
export interface IChannelPolicy {
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
	htlcMinimumMsat: bigint;
	htlcMaximumMsat: bigint;
	/** 'override' when a per-channel override is set, 'default' otherwise */
	source: 'override' | 'default';
}

export interface INodeInfo {
	nodeId: string;
	network: Network;
	/**
	 * Every known channel row, including CLOSED/FORCE_CLOSED ones (kept for
	 * history). Use openChannelCount for the number of operating channels.
	 */
	channelCount: number;
	/** Channels not in a terminal state (CLOSED, FORCE_CLOSED, ERRORED). */
	openChannelCount: number;
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
	/**
	 * Absent for blinded-final (BOLT 12) parts, which carry no payment_data:
	 * their per-part authenticity is the blinded path_id check instead.
	 */
	paymentSecret?: Buffer;
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
	/**
	 * This part's own onion shared secrets. Every part is a distinct onion,
	 * so a returned failure can only be decrypted (and its culpable hop
	 * attributed) with the secrets of the part it came back on.
	 */
	sharedSecrets: Buffer[];
}

export interface ILightningBalance {
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	unsettledBalanceMsat: bigint;
}

/**
 * Everything needed to place one forward onto an outgoing channel, carried as
 * a record so the forward can happen LATER than the HTLC that asked for it:
 * after an async-payment release, or onto a channel that did not exist when
 * the HTLC arrived (JIT receive). `forwardAmountMsat` is deliberately mutable
 * so an LSP can deduct an agreed opening fee before the add.
 */
export interface IForwardablePart {
	inChannelId: Buffer;
	inHtlcId: bigint;
	paymentHash: Buffer;
	forwardAmountMsat: bigint;
	forwardCltv: number;
	/** The INBOUND leg's expiry: the deadline every hold is bounded by. */
	incomingCltvExpiry: number;
	nextPacket: {
		version: number;
		ephemeralKey: Buffer;
		routingInfo: Buffer;
		hmac: Buffer;
	};
	nextBlindingPoint?: Buffer;
	/**
	 * Fail the inbound leg upstream, blinded-safe (see handleForwardHtlc).
	 * Returns false when the channel could not carry the failure (it is
	 * reestablishing, say), which a holder must treat as an obligation it
	 * still owes rather than as a resolution.
	 */
	failIncoming: (failureCode: number) => boolean;
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
	/**
	 * Set once every part has been dispatched. In a synchronous transport a
	 * part can fail back while later parts are still being sent; the state
	 * must not be dropped until dispatch has finished AND every part has
	 * resolved, or the late parts' failures lose their decryption context.
	 */
	dispatchComplete?: boolean;
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

/**
 * A request refused for the caller's own arguments: as written it cannot be
 * served, whatever the node's state. Extends Error so existing catch blocks and
 * message assertions keep working, and gives the CLI layer one thing to key on:
 * it maps any of these to a BeignetError INVALID_PARAMS so the daemon answers
 * 400 carrying the message, instead of scrubbing an untyped throw to a generic
 * 500 (issue #464). Node faults stay untyped on purpose, so they keep scrubbing.
 *
 * Subclassed per surface so a caller can still tell an open from a splice from
 * a dial; catch the base when the distinction does not matter.
 */
export class InvalidRequestError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'InvalidRequestError';
	}
}

/** A channel open refused for the caller's own arguments. */
export class InvalidChannelOpenError extends InvalidRequestError {
	constructor(message: string) {
		super(message);
		this.name = 'InvalidChannelOpenError';
	}
}

/**
 * A peer dial refused for the caller's own arguments (a malformed pubkey, a
 * host without a port, a host/port pair contradicting the WebSocket url).
 * Without this the CLI's blanket wrap turns them into CONNECT_FAILED, which
 * answers 502 and tells an agent to retry a request that can never succeed.
 */
export class InvalidPeerConnectError extends InvalidRequestError {
	constructor(message: string) {
		super(message);
		this.name = 'InvalidPeerConnectError';
	}
}

/** Why a channel-funding request the node cannot currently serve was refused. */
export enum ChannelFundingUnavailableCode {
	/** No funding provider able to quote this open or splice. */
	FUNDING_PROVIDER_REQUIRED = 'FUNDING_PROVIDER_REQUIRED',
	/** Spendable balance cannot cover the funding fee. */
	INSUFFICIENT_BALANCE = 'INSUFFICIENT_BALANCE',
	/** The estimator has not delivered a sample yet; a retry succeeds. */
	FEE_ESTIMATE_NOT_READY = 'FEE_ESTIMATE_NOT_READY',
	/** No such channel on this node. */
	CHANNEL_NOT_FOUND = 'CHANNEL_NOT_FOUND'
}

/**
 * A channel-funding request (open, max-open quote, splice quote) refused for the
 * NODE's own state or configuration rather than the caller's arguments: the
 * request is well formed, this node cannot serve it as things stand.
 * INVALID_PARAMS would be a lie for these, so each carries a code the CLI layer
 * maps to a code and status of its own (issue #471), instead of scrubbing an
 * untyped throw to a generic 500. The sibling for argument refusals is
 * InvalidChannelOpenError; node faults stay untyped and keep scrubbing.
 */
export class ChannelFundingUnavailableError extends Error {
	code: ChannelFundingUnavailableCode;

	constructor(code: ChannelFundingUnavailableCode, message: string) {
		super(message);
		this.name = 'ChannelFundingUnavailableError';
		this.code = code;
	}
}

/**
 * A splice refused for the caller's own arguments. Same contract as
 * InvalidChannelOpenError, under its own name because a splice is not an open.
 */
export class InvalidSpliceError extends InvalidRequestError {
	constructor(message: string) {
		super(message);
		this.name = 'InvalidSpliceError';
	}
}

/**
 * Why a splice request was refused. These refusals are returned rather than
 * thrown, because a splice starts asynchronously and the request that failed
 * was well formed enough to reach the engine. Untyped, the reason survives
 * only as an English sentence, which a boundary can neither classify nor
 * answer with anything but a success (issue #618). The sibling for argument
 * refusals is InvalidSpliceError, which still throws.
 */
export enum SpliceRefusalCode {
	/** No such channel on this node. */
	CHANNEL_NOT_FOUND = 'CHANNEL_NOT_FOUND',
	/** option_splice/option_quiesce is missing on one side of the pair. */
	SPLICING_NOT_NEGOTIATED = 'SPLICING_NOT_NEGOTIATED',
	/** The amount cannot be spliced as asked (dust floors, fee above amount). */
	INVALID_PARAMS = 'INVALID_PARAMS',
	/** The channel cannot spare the amount plus the splice fee. */
	INSUFFICIENT_BALANCE = 'INSUFFICIENT_BALANCE',
	/** No funding provider able to source the splice-in's wallet inputs. */
	FUNDING_PROVIDER_REQUIRED = 'FUNDING_PROVIDER_REQUIRED',
	/** The channel exists but would not start the splice (state, peer, size). */
	SPLICE_REFUSED = 'SPLICE_REFUSED'
}

/** A refused splice: why, in one sentence and as a code. */
export interface ISpliceRefusal {
	error: string;
	code: SpliceRefusalCode;
}

/**
 * The answer from a splice request (spliceIn, spliceInWithInputs, spliceOut):
 * `ok: true` means the splice was started, not that it completed. A refusal
 * carries both the human message and the code that classifies it.
 */
export interface ISpliceRequestResult extends Partial<ISpliceRefusal> {
	ok: boolean;
}

/**
 * An open or splice that did not FINISH within the wait's timeout. Distinct
 * from every other funding failure because it says nothing about the
 * operation: the wait only stopped listening, and the funding it started is
 * still live. A caller that retries on this runs a second funding beside the
 * first (issue #594).
 */
export class FundingWaitTimeoutError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'FundingWaitTimeoutError';
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
	category:
		| 'payment'
		| 'channel'
		| 'htlc'
		| 'fee'
		| 'peer'
		| 'chain'
		| 'watchtower'
		// Node-level errors (ILightningError). The action is the error code, e.g.
		// CHANNEL_ERROR or AUTO_FUNDING_FAILED.
		| 'error';
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
