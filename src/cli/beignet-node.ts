/**
 * BeignetNode: Simplified wrapper class for AI-friendly Bitcoin + Lightning.
 *
 * Wires together Wallet, LightningNode, SqliteStorage, WalletFundingProvider,
 * and ElectrumBackend behind a single class with plain JSON return types.
 */

import * as path from 'path';
import * as fs from 'fs';
import * as net from 'net';
import * as tls from 'tls';
import { promises as dnsPromises } from 'dns';
import {
	acquireInstanceLock,
	releaseInstanceLock,
	InstanceLockError
} from './instance-lock';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import { Wallet } from '../wallet';
import { getDefaultSendTransaction } from '../shapes/wallet';
import { EAddressType, ISendTransaction } from '../types/wallet';
import { ILogger, TLogLevel, LOG_LEVEL_PRIORITY } from '../logger';
import { generateMnemonic, getBitcoinJsNetwork } from '../utils/helpers';
import { btcToSats } from '../utils/conversion';
import {
	EAvailableNetworks,
	EBoostType,
	EPaymentType,
	IFormattedTransaction,
	IOnchainFees,
	TMessageDataMap
} from '../types/wallet';
import { createWalletStorage } from './wallet-storage';
import { EProtocol } from '../types/electrum';
import { LightningNode } from '../lightning/node/lightning-node';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../lightning/channel/splice-weight';
import {
	isPrivateNetworkUrl,
	l402Fetch,
	IL402Credential,
	IL402RequestInit,
	MemoryL402CredentialStore,
	readCappedBody
} from '../lightning/l402';
import { IPaymentInfo } from '../lightning/node/types';
import { IPeerTransportOptions } from '../lightning/transport/duplex-transport';
import { WalletFundingProvider } from '../lightning/wallet/wallet-funding-provider';
import { SqliteStorage } from '../lightning/storage/sqlite-storage';
import { deriveStorageKey } from '../lightning/storage/encryption';
import {
	encodeScb,
	decodeScb,
	IStaticChannelBackup
} from '../lightning/backup/scb';
import * as bip39 from 'bip39';
import {
	fetchRapidGossipSnapshot,
	DEFAULT_RGS_URL
} from '../lightning/gossip/rapid-sync';
import { parseAnnouncedAddress } from '../lightning/gossip/messages';
import {
	INodeAddress,
	IGraphChannel,
	IChannelUpdateMessage,
	IRoute,
	CHANNEL_FLAG_DISABLED,
	encodeShortChannelId,
	decodeShortChannelId
} from '../lightning/gossip/types';
import { ElectrumBackend } from '../lightning/chain/electrum-backend';
import {
	Network,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY
} from '../lightning/invoice/types';
import {
	LnCoinType,
	deriveLightningKeysFromMnemonic
} from '../lightning/keys/wallet-keys';
import {
	GuardianBootDecision,
	GuardianState,
	IGuardianConfigEntry,
	IParsedGuardian,
	IRestoreResult,
	RestoreRefusedError,
	buildGuardianRecovery,
	parseGuardianEntry,
	decodeRecoveryCapsuleBlob,
	restoreBestRecoveryCapsule,
	assertEmptyTarget,
	CapsuleCandidateError,
	GuardianDescriptor,
	chainPromisedQuorum,
	deriveRecoveryMasterKey
} from '../lightning/recovery';
import { getPublicKey } from '../lightning/crypto/ecdh';
import {
	DF_HARD_MIN_OFFER_AMOUNT_SAT,
	DirectFundingError,
	DirectFundingPaymentStore,
	DirectFundingSender,
	IDfPaymentRecord,
	IDfSendResult,
	chainHashForNetwork
} from '../lightning/direct-funding';
import { directFundingWallet } from './direct-funding';
import { AUTH_KEY_OVERRIDES_STORAGE_KEY } from './auth';
import {
	INodeConfig,
	InvalidRequestError,
	ChannelFundingUnavailableError,
	ChannelFundingUnavailableCode
} from '../lightning/node/types';
import {
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH,
	SIGNET_CHAIN_HASH,
	isAnchorChannel,
	ChannelState
} from '../lightning/channel/types';
import { decode as decodeInvoice } from '../lightning/invoice/decode';
import { decodeOffer } from '../lightning/offer/decode';
import {
	BeignetError,
	BeignetErrorCode,
	describeFailureCode,
	isRetryableError
} from './errors';
import { PaymentQueue } from './payment-queue';
import {
	NodeInfo,
	PeerInfo,
	ChannelInfo,
	PaymentInfo,
	InvoiceInfo,
	DecodedInvoice,
	TxInfo,
	OnchainTxInfo,
	UtxoInfo,
	DescriptorsInfo,
	PsbtBuildInfo,
	PsbtImportInfo,
	BoostResult,
	BoostableTransactions,
	ConsolidateResult,
	BalanceInfo,
	OfferInfo,
	TrustedPeerInfo,
	SpliceResult,
	BootstrapPeerInfo,
	HealthInfo,
	PaymentFilter,
	ForwardsFilter,
	ForwardingEventInfo,
	ForwardingSummaryInfo,
	RouteEstimate,
	NodeStats,
	PaymentProof,
	PaymentProofVerification,
	LiquiditySnapshot,
	FeeSnapshot,
	PaymentEstimate,
	BeignetNodeEvents,
	QueuedPayment,
	ChannelSuggestion,
	ActionLogEntry,
	ReadinessReport,
	ReadinessCheck,
	RetryPaymentOptions,
	RetryPaymentResult,
	PaymentValidation,
	PaymentValidationCheck,
	PaymentValidationStatus,
	ChannelPolicyInfo,
	HoldInvoiceInfo,
	GraphInfo,
	GraphChannelInfo,
	GraphChannelPolicy,
	GraphNodeInfo,
	GraphDescribeResult,
	RouteHop,
	RouteQueryResult,
	RebalancePlanInfo,
	AdvisorRecommendations,
	RebalanceResult,
	RebalanceExecutionSummary,
	TOnchainQuote,
	TChannelFundingQuote,
	DirectFundingConfigInfo
} from './types';

export type LogLevel = TLogLevel;

export interface LogEntry {
	level: LogLevel;
	message: string;
	data?: Record<string, unknown>;
	timestamp: number;
}

export interface BeignetNodeOptions {
	mnemonic?: string;
	network?: 'mainnet' | 'testnet' | 'regtest' | 'signet';
	alias?: string;
	dataDir?: string;
	/**
	 * Skip the single-instance lock on the data dir (default false). Leave this
	 * off unless you have a specific reason — two instances sharing one data dir
	 * share a node identity and SQLite DB, which causes connection churn and
	 * risks database corruption.
	 */
	allowMultipleInstances?: boolean;
	electrumHost?: string;
	electrumPort?: number;
	electrumTls?: boolean;
	/**
	 * Where the wallet sources on-chain fee estimates (default 'auto'):
	 * 'electrum' queries only the connected Electrum server (no clearnet HTTP
	 * leak), 'http' uses mempool.space/blocktank, 'auto' prefers Electrum and
	 * falls back to HTTP when Electrum is unavailable.
	 */
	feeEstimationSource?: 'electrum' | 'http' | 'auto';
	/**
	 * On-chain address type for the wallet (default 'p2wpkh'). 'p2tr' gives
	 * taproot deposit addresses; channel funding and splices can spend both
	 * kinds (issue #548, LFBW port #532 workstream 1F).
	 */
	addressType?: 'p2wpkh' | 'p2tr';
	listenPort?: number;
	/**
	 * Accept inbound Lightning peers over WebSocket (RFC 6455) on this port.
	 * Opt-in and additive: coexists with the TCP listener on listenPort.
	 */
	websocketPort?: number;
	preferAnchors?: boolean;
	/**
	 * option_wumbo (large_channels, default false): advertise the bit and lift
	 * the 2^24 sat funding cap (up to 10 BTC) for peers that also advertise it.
	 */
	largeChannels?: boolean;
	autoBootstrap?: boolean;
	/** Enable auto-reconnection to peers (default true) */
	autoReconnect?: boolean;
	/**
	 * Periodically bump channel commitment feerates via update_fee (default false).
	 * Off by default — an unsynced fee bump desyncs commitments and breaks HTLCs.
	 */
	autoUpdateChannelFees?: boolean;
	/**
	 * Relay third-party HTLCs, i.e. act as a routing hop (default true). Set false
	 * for a wallet that should not route: every forward is declined up front with
	 * temporary_node_failure and our channel_updates advertise the BOLT 7 disable
	 * bit. Does not affect the node's own sends/receives.
	 */
	forwardingEnabled?: boolean;
	/**
	 * Node-wide default routing fee policy advertised in channel_update, mapped
	 * onto the library's forwardingFeeBaseMsat / forwardingFeePropMillionths /
	 * forwardingCltvDelta (defaults 1000 / 1 / 40). BOLT 7 encodes them as
	 * u32 / u32 / u16; out-of-range values are refused in init because the wire
	 * write would otherwise wrap or throw only after gossip is being built.
	 * Per-channel overrides via updateChannelPolicy win over these defaults.
	 * Issue #532 workstream 1B.
	 */
	routingFeeBaseMsat?: number;
	routingFeePpm?: number;
	routingCltvDelta?: number;
	/**
	 * Liquidity ads (bLIP-0051, option_will_fund) SELLER policy: answer a
	 * buyer's request_funds by leasing inbound liquidity at these rates, funded
	 * from this wallet. Setting it advertises the option_will_fund feature bit.
	 * Refused in init unless every field is an integer within its wire width
	 * (u16 or u32): the rates are encoded into the SIGNED will_fund record,
	 * where channel_fee_max_base_msat is a tu32 whose encoder silently wraps an
	 * out-of-range value, i.e. the node would sign rates it never configured.
	 */
	leaseRates?: import('../lightning/gossip/types').ILeaseRates;
	/**
	 * JIT channel receive (issue #595). `enabled` turns on the LSP role, which
	 * fronts channel funding with this node's own coins for wallet peers and
	 * charges flatFeeSat + feePpm for it. maxFlatFeeSat / maxFeePpm are the
	 * other role, and apply whether or not the LSP role is on: they cap what
	 * this node accepts when it asks an LSP for a JIT receive of its own.
	 */
	jitReceive?: {
		enabled?: boolean;
		flatFeeSat?: number;
		feePpm?: number;
		maxFlatFeeSat?: number;
		maxFeePpm?: number;
	};
	/**
	 * Relay direct-funding frames for OTHER nodes (BEIGNET_DF_RELAY, issue
	 * #613). Off by default: forwarding opaque frames between strangers is work
	 * done for other people, metered but not free. The three lanes this node
	 * uses for its own payments and receives are always available.
	 */
	dfRelay?: boolean;
	/**
	 * Smallest direct-funding offer this node will serve (BEIGNET_DF_MIN_AMOUNT).
	 * Values under the 5000 sat protocol floor, zero included, clamp up to it.
	 */
	dfMinAmountSat?: number;
	/**
	 * Request a gossip graph sync from each peer on connect (default true).
	 * Without this the node only knows its own channels and cannot route
	 * multi-hop payments to destinations beyond its direct peers.
	 */
	autoGossipSync?: boolean;
	/**
	 * Download the full network graph via Rapid Gossip Sync on startup (default
	 * true on mainnet). This is the reliable, lightweight way to obtain the graph
	 * needed for multi-hop routing — a few MB over HTTPS instead of crawling p2p
	 * gossip. Set false to rely solely on p2p gossip from peers.
	 */
	rapidGossipSync?: boolean;
	/** Rapid Gossip Sync snapshot URL (defaults to the public LDK endpoint). */
	rapidGossipSyncUrl?: string;
	/**
	 * Signature-verify foreign broadcast gossip at intake (default false).
	 * By default verification is deferred until a gossip query asks for an
	 * entry, which skips nearly the whole first-dump verification cost;
	 * nothing unverified is ever served either way. Set true on relay-class
	 * nodes that serve the graph: intake and restore verify eagerly and
	 * signatureless RGS-primed entries are re-fetched signed from peers.
	 */
	eagerGossipVerify?: boolean;
	/** Optional error callback — receives all node:error events instead of silently absorbing them */
	onError?: (error: {
		code: string;
		message: string;
		timestamp: number;
		channelId?: string;
	}) => void;
	/** Log level (default 'info'). Set to 'silent' to suppress. */
	logLevel?: LogLevel;
	/**
	 * Leveled diagnostic logger. When set, every log entry that passes
	 * logLevel is forwarded to it (in addition to the 'log' event) and it is
	 * injected into the underlying Wallet and LightningNode. When unset,
	 * behavior is unchanged: BeignetNode only emits 'log' events and the
	 * wallet keeps its default console output.
	 */
	logger?: ILogger;
	/** Multiple Electrum servers for failover redundancy */
	electrumServers?: Array<{ host: string; port: number; tls?: boolean }>;
	/** Path for automated periodic backups (enables backup scheduling) */
	backupPath?: string;
	/** Backup interval in milliseconds (default: 6 hours, requires backupPath) */
	backupIntervalMs?: number;
	/**
	 * COMBINED daily spending limit in satoshis, shared by Lightning payments
	 * (payInvoice/sendKeysend/sendPaymentAsync) AND external on-chain sends
	 * (sendOnchain and sendMaxOnchain, counted as amount + fee). Excluded by
	 * design: consolidateUtxos (self-pay), channel opens/splices/funding, and
	 * bumpFeeOnchain/boostOnchain (fee-only). Resets at midnight UTC.
	 * NOTE: before v0.3.0 this limit covered Lightning only.
	 */
	dailySpendLimitSats?: number;
	/** Maximum amount in satoshis for a single payment. Rejects any payInvoice/sendKeysend/sendPaymentAsync call exceeding this. Prevents accidental large payments. */
	maxPaymentSats?: number;
	/** Timeout for connectPeer() in milliseconds (default: 15000) */
	connectTimeoutMs?: number;
	/**
	 * SOCKS5 proxy for reaching Tor `.onion` peers, as "host:port"
	 * (e.g. "127.0.0.1:9050"). Required to connect to peers that only advertise
	 * an onion address. Needs a running Tor daemon/Tor Browser on that port.
	 */
	torProxy?: string;
	/**
	 * Addresses to advertise in our node_announcement so remote peers can
	 * discover and dial us, as "host[:port]" strings (port defaults to 9735).
	 * Supports IPv4, "[ipv6]:port", Tor v3 ".onion" and DNS hostnames.
	 * Only announced once the node has at least one public channel.
	 */
	announceAddresses?: string[];
	/**
	 * Watchtowers to ship encrypted justice data to at every revocation, as
	 * "pubkey@host:port" URIs (LND altruist wtwire protocol). Off when empty.
	 */
	watchtowers?: string[];
	/**
	 * Recovery Protocol mode (docs/RECOVERY-PROTOCOL.md section 8). Exact
	 * values 'off' | 'peer-storage' | 'async-remote' | 'quorum'; anything
	 * else is treated as off, the safe fallback (an existing quorum-marked
	 * database still refuses to start unbarriered at the library level).
	 */
	recoveryMode?: string;
	/**
	 * Guardian set for the guardian-backed modes, as
	 * "<64-hex-x-only-pubkey>@<http(s) url>" URIs or structured
	 * { guardianId, url, auth? } entries (crash-v1: exactly three). The
	 * structured form carries the transport credential a retrieved capsule
	 * hands back through revealCapsuleGuardians. A malformed entry throws
	 * rather than silently changing the quorum arithmetic; the daemon
	 * validates these before create so a typo never boots a node.
	 */
	recoveryGuardians?: Array<string | IGuardianConfigEntry>;
	/** Fault-model profile; 'crash-v1' is the only value and the default. */
	recoveryProfile?: string;
	/**
	 * Guardian modes: how often an idle confirmed writer re-asks the guardian
	 * set whether its lease is still current (issue #455). Default 5 minutes;
	 * 0 disables. A proven newer epoch fences exactly as a refused append
	 * would; an outage never changes the gate.
	 */
	recoveryLeaseCheckIntervalMs?: number;
	/**
	 * peer-storage mode: how long a peer's channel_reestablish for a channel
	 * this node has no record of is held before the BOLT 1 error goes out
	 * (issue #462). Default 10 minutes; 0 answers immediately, which is the
	 * pre-#462 conduct. A node restoring over peer_storage boots empty on
	 * purpose and gets the peer's reestablish in the same instant as the
	 * Recovery Capsule that answers it, so failing the channel there
	 * force-closes exactly what the restore is about to resume. Ignored in
	 * every other mode.
	 */
	recoveryReestablishHoldMs?: number;
	/**
	 * Encrypt the SQLite database at rest with a key derived from the wallet
	 * seed (default true). An existing plaintext database is migrated in place
	 * on first open; restoring a backup requires the same mnemonic. Set false
	 * to keep storage in plaintext.
	 */
	storageEncryption?: boolean;
	/**
	 * BOLT 1 peer storage (default true): push our seed-encrypted static
	 * channel backup to connected peers that advertise option_provide_storage,
	 * store one small blob per channel/trusted peer in return, and keep the
	 * newest valid SCB peers hand back on reconnect (see
	 * getPeerRetrievedBackup). Recovery stays explicit via restoreFromScb.
	 */
	peerStorageEnabled?: boolean;
	/**
	 * Automatic circular rebalancing (default DISABLED). When enabled the node
	 * periodically executes the advisor's rebalance plan, spending at most
	 * budgetSatsPerDay in routing fees per UTC day. Off unless enabled: true.
	 */
	autoRebalance?: {
		enabled?: boolean;
		budgetSatsPerDay?: number;
		minImbalancePct?: number;
		intervalMs?: number;
	};
	/**
	 * Automatic routing-fee (ppm) tuning (default DISABLED). When enabled the
	 * node periodically nudges each channel's proportional fee up 25% when its
	 * outbound side is depleted but still forwarding, and down 25% when it saw
	 * no forwards in the window, clamped to [floorPpm, ceilPpm].
	 */
	autoTuneFees?: {
		enabled?: boolean;
		intervalMs?: number;
		floorPpm?: number;
		ceilPpm?: number;
	};
}

/**
 * Resolved on every call for the same reason as the config paths (issue #604):
 * a module-level const froze HOME at import time, so a caller that redirected
 * HOME still got the developer's real ~/.beignet/data. Every daemon boot that
 * omits an explicit dataDir lands here, so the freeze put real wallet
 * databases outside the caller's chosen directory.
 */
function defaultDataDir(): string {
	return path.join(
		process.env.HOME || process.env.USERPROFILE || '.',
		'.beignet',
		'data'
	);
}

export type RecoveryMode = 'off' | 'peer-storage' | 'async-remote' | 'quorum';

/**
 * Exact values only; anything else is off. The typo-tolerant fallback is
 * safe here because guardians configured alongside an unrecognized mode
 * still refuse daemon startup (guardians require a guardian mode), and an
 * existing quorum-marked database refuses to start unbarriered at the
 * library level, so a typo can never silently downgrade a protected node.
 */
export function parseRecoveryMode(value: string | undefined): RecoveryMode {
	return value === 'peer-storage' ||
		value === 'async-remote' ||
		value === 'quorum'
		? value
		: 'off';
}

/** RestoreRefusedError reasons as daemon error codes (HTTP mapping lives in daemon.ts). */
/** Durable record of a Tier 2 capsule restore's pending database swap. */
interface ICapsuleRestoreMarker {
	version: 1;
	stagedAt: number;
	/** Basename of the fully installed restored database. */
	staged: string;
	/** Basename the previous database is moved aside under. */
	keep: string;
	head: { writerEpoch: string; latestSequence: string };
	tier: 2;
}

/**
 * A capsule guardian descriptor as the daemon reports it: identity and
 * transports only. The capsule may carry a transport credential (wire 2.4);
 * it is encrypted under the node secret for exactly that reason and never
 * leaves the capsule through a readonly route or a log line.
 */
export interface IReportedGuardian {
	guardianId: string;
	transports: Array<{
		type: 'onion-http' | 'https' | 'local-http';
		url: string;
	}>;
}

/**
 * Strip userinfo from a URL before it is reported or logged. The parser
 * refuses credentials in guardian URLs, but a descriptor is data from a
 * capsule, and a readonly route must not be the place that leaks one.
 */
function redactUrl(url: string): string {
	try {
		const parsed = new URL(url);
		if (parsed.username === '' && parsed.password === '') return url;
		parsed.username = '';
		parsed.password = '';
		return parsed.toString();
	} catch {
		return '<invalid url>';
	}
}

function redactGuardians(
	descriptors: GuardianDescriptor[]
): IReportedGuardian[] {
	// The decoder shape-checks descriptors (assertGuardianDescriptors), so
	// every entry has an id and at least one transport; the credential stays
	// behind here, both the structured `auth` and anything inside a URL.
	return descriptors.map((g) => ({
		guardianId: g.guardianId,
		transports: g.transports.map((t) => ({
			type: t.type,
			url: redactUrl(t.url)
		}))
	}));
}

/** Same guardian identities, in any order. */
function sameGuardianIds(a: string[], b: string[]): boolean {
	if (a.length !== b.length) return false;
	const sortedA = a.map((id) => id.toLowerCase()).sort();
	const sortedB = b.map((id) => id.toLowerCase()).sort();
	return sortedA.every((id, i) => id === sortedB[i]);
}

/** Write through a temp file and rename, so a crash never leaves a torn file. */
function writeFileAtomic(filePath: string, content: string): void {
	const tmp = `${filePath}.tmp`;
	fs.writeFileSync(tmp, content);
	fs.renameSync(tmp, filePath);
}

const RESTORE_ERROR_CODES: Record<RestoreRefusedError['reason'], string> = {
	'no-quorum': 'RESTORE_NO_QUORUM',
	'unknown-namespace': 'RESTORE_UNKNOWN_NAMESPACE',
	conflict: 'RESTORE_CONFLICT',
	'cas-exhausted': 'RESTORE_CAS_EXHAUSTED',
	'head-unverifiable': 'RESTORE_HEAD_UNVERIFIABLE',
	'target-unsupported': 'RESTORE_TARGET_UNSUPPORTED'
};

/**
 * Compute the default per-wallet data directory for a mnemonic.
 *
 * The storage filename is keyed only by network (`<network>.db`), so without
 * per-wallet namespacing every run with the same `dataDir` would open the SAME
 * database and load another seed's channels/balance/identity. Namespacing the
 * default directory by a hash of the mnemonic ensures each seed gets its own
 * database. The hash is one-way — the seed cannot be recovered from the path.
 */
export function defaultDataDirForMnemonic(
	mnemonic: string,
	baseDir: string = defaultDataDir()
): string {
	const walletTag = crypto
		.createHash('sha256')
		.update(mnemonic.normalize('NFKD').trim())
		.digest('hex')
		.slice(0, 16);
	return path.join(baseDir, walletTag);
}

/**
 * Resolve when the given promise settles (either way) or after timeoutMs,
 * whichever comes first; never rejects. Gossip sync deferral waits on this
 * rather than on the RGS promise directly: a failed or hung snapshot download
 * must release deferred syncs, never block them (issue #441). The timer is
 * unref()d so a pending latch cannot hold the process open.
 */
export function gossipPrimeLatch(
	rgs: Promise<unknown>,
	timeoutMs: number
): Promise<void> {
	return new Promise<void>((resolve) => {
		const timer = setTimeout(resolve, timeoutMs);
		timer.unref?.();
		const settle = (): void => {
			clearTimeout(timer);
			resolve();
		};
		rgs.then(settle, settle);
	});
}

/** Format an 8-byte SCID buffer as "<block>x<txIndex>x<outputIndex>". */
export function formatScid(scid: Buffer): string {
	const { block, txIndex, outputIndex } = decodeShortChannelId(scid);
	return `${block}x${txIndex}x${outputIndex}`;
}

/**
 * Parse an SCID from "<block>x<txIndex>x<outputIndex>" or 16-char hex into the
 * 8-byte wire buffer. Throws BeignetError INVALID_PARAMS on malformed input.
 */
export function parseScid(scid: string): Buffer {
	const human = scid.match(/^(\d+)x(\d+)x(\d+)$/);
	if (human) {
		return encodeShortChannelId({
			block: parseInt(human[1], 10),
			txIndex: parseInt(human[2], 10),
			outputIndex: parseInt(human[3], 10)
		});
	}
	if (/^[0-9a-fA-F]{16}$/.test(scid)) {
		return Buffer.from(scid, 'hex');
	}
	throw new BeignetError(
		BeignetErrorCode.INVALID_PARAMS,
		`Invalid short channel id: ${scid} (expected <block>x<txIndex>x<output> or 16-char hex)`
	);
}

/**
 * Decode a user-supplied BOLT 11 string. The parser throws plain Error, which
 * the daemon scrubs to a generic 500 and logs as an unhandled server fault;
 * a typed INVALID_INVOICE keeps the parser's message and answers 400.
 */
export function decodeInvoiceInput(
	bolt11: string
): ReturnType<typeof decodeInvoice> {
	try {
		return decodeInvoice(bolt11);
	} catch (err: unknown) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_INVOICE,
			`Invalid invoice: ${
				err instanceof Error ? err.message : 'failed to decode'
			}`
		);
	}
}

/**
 * What an msat amount can cost the sat-denominated spending limits, rounded UP.
 * Truncating instead made every sub-satoshi invoice invisible to admission and
 * to the daily total alike: a 999 msat invoice was checked and recorded as 0
 * sats, which skips both limits outright, and any fractional amount above that
 * was understated. Rounding up is the direction a limit has to err in.
 */
export function spendLimitSats(amountMsat: bigint): number {
	return Number((amountMsat + 999n) / 1000n);
}

/**
 * The amount an invoice payment has to be admitted and accounted for, in sats.
 *
 * The ENCODED amount wins wherever the invoice carries one, because that is
 * what the engine pays: sendPayment applies the caller's override only to an
 * amountless invoice. Preferring the override let `amountSats: 1` — or 0, which
 * skips the checks, the reservation and the accounting entirely — walk a fixed
 * invoice of any size past both limits (issues #526, #528).
 *
 * Zero means there is nothing to admit or record: an amountless invoice with no
 * usable override, which the engine refuses on its own.
 */
export function paymentSpendSats(
	amountMsat: bigint | undefined,
	amountSats?: number
): number {
	return amountMsat !== undefined
		? spendLimitSats(amountMsat)
		: amountSats ?? 0;
}

/**
 * Decode a user-supplied BOLT 12 offer string. Same contract as
 * decodeInvoiceInput: parse failures become a typed INVALID_OFFER (400).
 */
export function decodeOfferInput(
	offerStr: string
): ReturnType<typeof decodeOffer> {
	try {
		return decodeOffer(offerStr);
	} catch (err: unknown) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_OFFER,
			`Invalid offer: ${
				err instanceof Error ? err.message : 'failed to decode'
			}`
		);
	}
}

/**
 * The code a refusal the node cannot currently serve reaches the caller as.
 * INVALID_PARAMS would be a lie for every one of these: the request is well
 * formed, this node cannot serve it as things stand (issue #471).
 */
const FUNDING_UNAVAILABLE_CODES: Record<
	ChannelFundingUnavailableCode,
	BeignetErrorCode
> = {
	[ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED]:
		BeignetErrorCode.FUNDING_PROVIDER_REQUIRED,
	[ChannelFundingUnavailableCode.INSUFFICIENT_BALANCE]:
		BeignetErrorCode.INSUFFICIENT_BALANCE,
	[ChannelFundingUnavailableCode.FEE_ESTIMATE_NOT_READY]:
		BeignetErrorCode.FEE_ESTIMATE_NOT_READY,
	[ChannelFundingUnavailableCode.CHANNEL_NOT_FOUND]:
		BeignetErrorCode.CHANNEL_NOT_FOUND
};

/**
 * Run a channel-funding request (open, quote or splice), converting the engine's
 * typed refusals into BeignetErrors that keep their message. The daemon only
 * passes a BeignetError through; anything else is logged as an unhandled fault
 * and scrubbed to a generic 500, which hid honest, actionable refusals such as a
 * push toward a dual-fund peer (issue #464) or a max open on an empty wallet
 * (issue #471). Refusals about the caller's arguments answer INVALID_PARAMS
 * (400); refusals about this node's state or configuration answer a code of
 * their own. Node faults are deliberately not converted: they still scrub.
 */
function fundingOrRefuse<T>(run: () => T): T {
	try {
		return run();
	} catch (err: unknown) {
		if (err instanceof InvalidRequestError) {
			throw new BeignetError(BeignetErrorCode.INVALID_PARAMS, err.message);
		}
		if (err instanceof ChannelFundingUnavailableError) {
			throw new BeignetError(FUNDING_UNAVAILABLE_CODES[err.code], err.message);
		}
		throw err;
	}
}

/** Convert pathfinding route hops to the JSON shape used by the daemon/CLI. */
export function routeHopsToJson(route: IRoute): RouteHop[] {
	return route.hops.map((hop, idx) => {
		// A hop's fee = what it receives minus what it forwards; the final hop
		// forwards nothing so its fee is 0.
		const feeMsat =
			idx < route.hops.length - 1
				? hop.amountToForwardMsat - route.hops[idx + 1].amountToForwardMsat
				: 0n;
		return {
			pubkey: hop.pubkey.toString('hex'),
			shortChannelId: formatScid(hop.shortChannelId),
			amountToForwardMsat: hop.amountToForwardMsat.toString(),
			outgoingCltvValue: hop.outgoingCltvValue,
			feeMsat: feeMsat.toString(),
			cltvExpiryDelta: hop.cltvExpiryDelta
		};
	});
}

/** Convert JSON route hops back to the shape sendPaymentToRoute expects. */
export function jsonToRouteHops(hops: RouteHop[]): Array<{
	pubkey: Buffer;
	shortChannelId: Buffer;
	amountToForwardMsat: bigint;
	outgoingCltvValue: number;
}> {
	return hops.map((hop, idx) => {
		if (!hop.pubkey || !/^[0-9a-fA-F]{66}$/.test(hop.pubkey)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				`Route hop ${idx}: pubkey must be a 33-byte hex string`
			);
		}
		let amountToForwardMsat: bigint;
		try {
			amountToForwardMsat = BigInt(hop.amountToForwardMsat);
		} catch {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				`Route hop ${idx}: amountToForwardMsat must be a decimal string`
			);
		}
		if (
			typeof hop.outgoingCltvValue !== 'number' ||
			!Number.isInteger(hop.outgoingCltvValue) ||
			hop.outgoingCltvValue < 0
		) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				`Route hop ${idx}: outgoingCltvValue must be a non-negative integer`
			);
		}
		return {
			pubkey: Buffer.from(hop.pubkey, 'hex'),
			shortChannelId: parseScid(hop.shortChannelId),
			amountToForwardMsat,
			outgoingCltvValue: hop.outgoingCltvValue
		};
	});
}

/** Hard page-size cap for GET /graph/describe (the graph can be huge). */
const GRAPH_DESCRIBE_MAX_LIMIT = 500;

/**
 * One dispatched async payment attempt's claim on the daily budget.
 *
 * A claim has two lifetimes. Its RESERVATION holds `sats` in
 * _pendingSpendSats so nothing else is admitted against capacity this attempt
 * may still spend, and ends at `expiresAt` or when the engine tells us the
 * attempt dispatched nothing. The RECORD outlives that: a settlement arriving
 * after the reservation lapsed still moved real money, and still has to be
 * charged to the day it lands on.
 */
export interface AsyncSpendClaim {
	sats: number;
	/** Epoch ms at which the reservation lapses (see the TTL below). */
	expiresAt: number;
	/** Whether `sats` is still counted in _pendingSpendSats. */
	reserved: boolean;
}

/**
 * How long a dispatched async payment keeps HOLDING daily budget. The hold has
 * to outlive the payment's own FAILED report: BOLT 2 has no way to retract an
 * update_add_htlc, so cancelPayment(), the engine's stuck-payment sweep and its
 * expired-invoice sweep all mark a payment failed while its HTLC is still live,
 * and the engine deliberately completes such a payment when the preimage turns
 * up. One full daily window is where the hold ends, because by then the budget
 * the payment was admitted against has itself rolled over.
 *
 * This is emphatically not a claim that the HTLC is dead by then — routing
 * tolerates CLTV lockups of up to a fortnight. It is only the point where
 * pinning a DAILY budget stops making sense, so the claim's record stays behind
 * and a later settlement is charged to the day it actually arrives on.
 */
export const ASYNC_SPEND_CLAIM_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Memory guard on the claim ledger, counted in CLAIMS rather than in payment
 * hashes: resubmitting one invoice claims once per attempt, so a per-hash bound
 * never ran on the case that grows fastest.
 *
 * Records whose reservation has already lapsed are dropped first, since all
 * they can still do is charge a late settlement. Reaching the cap on RESERVED
 * claims refuses the submission instead: releasing a live claim to make room
 * hands back budget an outstanding HTLC can still spend, and failing open is
 * the one direction a spending limit must never fail in.
 */
export const MAX_ASYNC_SPEND_CLAIMS = 4096;

/**
 * Default ceiling on an L402 response body. The body is buffered and then
 * re-serialized into the daemon's JSON envelope, so a remote server's response
 * size is a memory cost here, not just a transfer one.
 */
const DEFAULT_L402_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

const DEFAULT_ELECTRUM: Record<
	string,
	{ host: string; port: number; useTls: boolean }
> = {
	mainnet: { host: 'fulcrum.bitkit.blocktank.to', port: 8900, useTls: true },
	testnet: { host: 'electrum.blockstream.info', port: 60002, useTls: true },
	signet: { host: 'mempool.space', port: 60602, useTls: true },
	regtest: { host: '34.65.252.32', port: 18483, useTls: false }
};

/**
 * Resolve a host to a routable IPv4 address. Returns the host unchanged if it is
 * already an IP literal, has no IPv4 record, or resolution fails. Avoids the
 * IPv6 link-local (fe80::…) that mDNS `.local` names often return first, which
 * the Electrum client's bare socket.connect cannot reach (no %zone id).
 */
async function resolveHostToIPv4(host: string): Promise<string> {
	if (net.isIP(host)) return host; // already an IP literal
	try {
		const { address } = await dnsPromises.lookup(host, { family: 4 });
		return address || host;
	} catch {
		return host;
	}
}

/**
 * Numbers arriving over HTTP are whatever JSON.parse made of them, so `> 0` is
 * not a check: it lets through 0.5 satoshis, Infinity, and 2^60. Reject them at
 * the edge rather than leaving deeper transaction code to trip over them.
 */
function requirePositiveSafeInteger(value: unknown, field: string): number {
	if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			`${field} must be a positive whole number of satoshis`
		);
	}
	return value;
}

/**
 * A satoshi amount that may legitimately be nothing: a fee ceiling of zero
 * ("route for free or fail"), an invoice with no amount, a push of nothing.
 * Everything else requirePositiveSafeInteger refuses is refused here too.
 */
function requireNonNegativeSafeInteger(value: unknown, field: string): number {
	if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			`${field} must be a whole number of satoshis, zero or greater`
		);
	}
	return value;
}

/**
 * Raise a direct-funding minimum to the protocol floor.
 *
 * Below 5000 sat the payer's own share of the transaction fee starts to
 * dominate the payment and a channel is the wrong instrument for it, so the
 * receiver engine enforces the floor whatever it is configured with. Applied at
 * the CLI boundary as well, because the dashboard compares the value it reads
 * back against the one it asked for and would otherwise show a minimum this
 * node does not have.
 */
export function clampDirectFundingMinimum(value: number): number {
	const floor = Number(DF_HARD_MIN_OFFER_AMOUNT_SAT);
	return value > floor ? value : floor;
}

/**
 * Blocks of final-CLTV headroom an invoice may ask payers for. The value goes
 * straight into the BOLT 11 `c` tag, so an absurd one produces a syntactically
 * valid invoice that no sender will pay: 2016 is a fortnight of blocks, well
 * past any real settlement window and under the max_cltv_expiry senders cap
 * whole routes at. Floor 1, since zero leaves no window to claim at all.
 */
const MAX_MIN_FINAL_CLTV_EXPIRY = 2016;

function requireFinalCltvExpiry(value: unknown): number {
	if (
		typeof value !== 'number' ||
		!Number.isInteger(value) ||
		value < 1 ||
		value > MAX_MIN_FINAL_CLTV_EXPIRY
	) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			`minFinalCltvExpiry must be an integer between 1 and ` +
				`${MAX_MIN_FINAL_CLTV_EXPIRY} blocks`
		);
	}
	return value;
}

/**
 * A millisatoshi field that reaches the library as a bigint but is accepted
 * from callers as a number or a decimal string. BigInt() is the only thing
 * that ever validated it, by throwing, so both spellings are checked here
 * instead: a whole non-negative number, or digits only.
 */
function requireMsatValue(value: number | string, field: string): bigint {
	if (typeof value === 'number') {
		return BigInt(requireNonNegativeSafeInteger(value, field));
	}
	if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
		return BigInt(value);
	}
	throw new BeignetError(
		BeignetErrorCode.INVALID_PARAMS,
		`${field} must be a whole number of millisatoshis, or a string of digits`
	);
}

/** A fee rate may be fractional, but it must be a real, positive, finite number. */
function requirePositiveFiniteNumber(value: unknown, field: string): number {
	if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			`${field} must be a positive finite number`
		);
	}
	return value;
}

/**
 * The funding amounts every channel-open entry point takes. Guard before
 * BigInt(): a fractional amount throws an uncaught RangeError, and a string
 * amount reaches the spend-limit math where + concatenates instead of adding.
 * Shared so no open path can be added without them (issue #472); zero is left
 * to the engine, which refuses it as a caller-argument refusal.
 */
function requireOpenAmounts(amountSats: unknown, pushSats?: unknown): void {
	if (typeof amountSats !== 'number' || !Number.isSafeInteger(amountSats)) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			'amountSats must be an integer number of satoshis'
		);
	}
	if (amountSats < 0) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			'amountSats must be >= 0'
		);
	}
	if (
		pushSats !== undefined &&
		(typeof pushSats !== 'number' ||
			!Number.isSafeInteger(pushSats) ||
			pushSats < 0)
	) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			'pushSats must be a non-negative integer number of satoshis'
		);
	}
}

/**
 * A value the wire carries as a u32 (feerate_perkw, locktime). Buffer's
 * writeUInt32BE truncates 1.5 to 1 and throws on 2^32, and both happen after
 * the channel's state machine has moved, so the bound is enforced here.
 */
function requireU32(value: unknown, field: string, min = 1): number {
	if (
		typeof value !== 'number' ||
		!Number.isInteger(value) ||
		value < min ||
		value > 0xffffffff
	) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			`${field} must be an integer between ${min} and 4294967295`
		);
	}
	return value;
}

/**
 * Wire widths of the five option_will_fund lease_rates fields (see
 * encodeLeaseRates in lightning/gossip/types.ts). leaseFeeBaseSat is written
 * as a u32 and channelFeeMaxBaseMsat as a tu32 whose encoder silently WRAPS
 * an out-of-range value, so an unchecked field would land inside a record
 * this node signs (seller) or a fee ceiling it enforces (buyer) holding a
 * different number than the operator wrote.
 */
const LEASE_RATE_FIELD_MAX: ReadonlyArray<
	[keyof import('../lightning/gossip/types').ILeaseRates, number]
> = [
	['fundingWeightWitness', 0xffff],
	['leaseFeeBasis', 0xffff],
	['channelFeeMaxProportionalThousandths', 0xffff],
	['leaseFeeBaseSat', 0xffffffff],
	['channelFeeMaxBaseMsat', 0xffffffff]
];

/**
 * Why a lease-rates value is unacceptable, or null when it is valid. Shared
 * by daemon startup (naming BEIGNET_LEASE_RATES), BeignetNode.init (naming
 * the leaseRates option), and openChannelV2 (naming maxLeaseRates), so every
 * entry path enforces the same field-and-width table (issue #532).
 */
export function leaseRatesRefusal(value: unknown): string | null {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return (
			'must be a JSON object with fundingWeightWitness, leaseFeeBasis, ' +
			'leaseFeeBaseSat, channelFeeMaxBaseMsat and ' +
			'channelFeeMaxProportionalThousandths'
		);
	}
	const record = value as Record<string, unknown>;
	for (const [field, max] of LEASE_RATE_FIELD_MAX) {
		const v = record[field];
		if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > max) {
			return (
				`${field} must be an integer between 0 and ${max} ` +
				`(got ${String(v)})`
			);
		}
	}
	return null;
}

/**
 * Wire and arithmetic bounds of the JIT receive fee fields. The ack writes
 * flatFeeSat as a u64 and feePpm as a u32, but a ppm above a million is a fee
 * larger than the payment it is taken from, which is not a policy anybody can
 * mean, and it would have the LSP refuse every one of its own fundings.
 */
const JIT_FEE_FIELD_MAX: ReadonlyArray<[string, number]> = [
	['flatFeeSat', 0xffffffff],
	['feePpm', 1_000_000],
	['maxFlatFeeSat', 0xffffffff],
	['maxFeePpm', 1_000_000]
];

/**
 * Why a JIT receive config is unacceptable, or null when it is valid. Shared
 * by daemon startup (naming the BEIGNET_JIT_* variables) and BeignetNode.init
 * (naming the option), so both entry paths refuse the same values. `enabled`
 * is the only boolean and is checked separately: integerEnv surfaces a partly
 * numeric env value as NaN, which every numeric field below rejects.
 */
export function jitReceiveRefusal(value: unknown): string | null {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return 'must be an object';
	}
	const record = value as Record<string, unknown>;
	if (record.enabled !== undefined && typeof record.enabled !== 'boolean') {
		return `enabled must be a boolean (got ${String(record.enabled)})`;
	}
	for (const [field, max] of JIT_FEE_FIELD_MAX) {
		const v = record[field];
		if (v === undefined) continue;
		if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > max) {
			return `${field} must be an integer between 0 and ${max} (got ${String(
				v
			)})`;
		}
	}
	return null;
}

/**
 * A 32-byte channel id as hex. Buffer.from(x, 'hex') silently truncates at the
 * first non-hex character, so an unchecked id reaches the engine as a short
 * buffer and reads as a malformed-argument fault rather than a bad request.
 */
function requireChannelIdHex(value: unknown, field = 'channelId'): Buffer {
	if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
		throw new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			`${field} must be a 64-character hex channel id`
		);
	}
	return Buffer.from(value, 'hex');
}

/**
 * A channel restored from a Recovery Capsule whose state no channel_reestablish
 * has proven current (issue #469). It stays NORMAL, keeps its balance and
 * closes cooperatively, and it settles the HTLCs it already has - but it takes
 * no new ones and is offered to no router, so no readiness or capacity surface
 * may count it. Read off the wire field rather than recomputed: these surfaces
 * hold serialized channel info, not Channel objects.
 */
function isHeldRestore(ch: { restoreRecencyUnproven?: boolean }): boolean {
	return ch.restoreRecencyUnproven === true;
}

export class BeignetNode extends EventEmitter {
	// ─── Typed event overloads ───
	on<K extends keyof BeignetNodeEvents>(
		event: K,
		listener: BeignetNodeEvents[K]
	): this;
	on(event: string | symbol, listener: (...args: unknown[]) => void): this;
	on(event: string | symbol, listener: (...args: unknown[]) => void): this {
		return super.on(event, listener);
	}

	once<K extends keyof BeignetNodeEvents>(
		event: K,
		listener: BeignetNodeEvents[K]
	): this;
	once(event: string | symbol, listener: (...args: unknown[]) => void): this;
	once(event: string | symbol, listener: (...args: unknown[]) => void): this {
		return super.once(event, listener);
	}

	emit<K extends keyof BeignetNodeEvents>(
		event: K,
		...args: Parameters<BeignetNodeEvents[K]>
	): boolean;
	emit(event: string | symbol, ...args: unknown[]): boolean;
	emit(event: string | symbol, ...args: unknown[]): boolean {
		return super.emit(event, ...args);
	}

	private wallet!: Wallet;
	private node!: LightningNode;
	private storage!: SqliteStorage;
	/** Wallet-owned output script that force-close sweeps pay into. */
	private sweepDestinationScript?: Buffer;
	/** Background timer retrying wallet sweep-address resolution (see scheduleSweepAddressRefresh). */
	private _sweepRefreshTimer?: ReturnType<typeof setInterval>;
	/** Background timer waiting for Electrum before fallback-fund recovery (see runFallbackRecoveryWhenConnected). */
	private _fallbackRecoveryTimer?: ReturnType<typeof setInterval>;
	/**
	 * Bound on the cooperative close's wallet-address lookup (issue #542
	 * review): getNextAvailableAddress can enter an Electrum reconnect whose
	 * server_version handshake carries no timeout of its own (the same hazard
	 * HEADER_SUBSCRIBE_GATE_MS bounds in electrum/index.ts), and an unbounded
	 * wait here means the close never reaches the engine and the cached or
	 * funding-key fallbacks never run. Well above the client's own 10s
	 * request timeouts, so a lookup that is merely slow still wins.
	 */
	private _closeAddressLookupTimeoutMs = 15_000;
	/** The startup wallet refresh; waitForInitialSync awaits it (issue #548). */
	private _initialSync?: Promise<void>;
	// ─── Recovery Protocol surface (docs/RECOVERY-PROTOCOL.md section 8) ───
	/** Parsed mode; 'off' unless a recognized mode was configured. */
	private recoveryMode: RecoveryMode = 'off';
	/** Parsed guardian set, kept for the status surface. */
	private recoveryGuardianSet: IParsedGuardian[] = [];
	/** The node-level recovery config fragment initNode passes at construction. */
	private recoveryNodeConfig?: INodeConfig['recovery'];
	/** The assembled run decision (guardian modes only). */
	private _recoveryRun?: Extract<GuardianBootDecision, { kind: 'run' }>;
	/** Present while this device must restore before it can run. */
	private _restoreDecision?: Extract<
		GuardianBootDecision,
		{ kind: 'restore-required' }
	>;
	/** True from the restore-required decision until initNode completes. */
	private _restorePending = false;
	private _restoreInFlight = false;
	private _lastRestoreEvent?: { type: string; detail: string };
	/** init opts, kept so a restore can run the deferred node construction. */
	private _deferredOpts?: BeignetNodeOptions;
	/** The direct-funding payer, built over the node's own lane registry. */
	private directFundingSender?: DirectFundingSender;
	/** Backoff timer for the startup gate confirmation loop. */
	private _confirmTimer?: ReturnType<typeof setTimeout>;
	private _leaseCheckTimer?: ReturnType<typeof setInterval>;
	private _leaseCheckInFlight = false;
	private _leaseCheckIntervalMs = BeignetNode.DEFAULT_LEASE_CHECK_INTERVAL_MS;
	/** peer-storage unknown-reestablish hold window (issue #462). */
	private _reestablishHoldMs = BeignetNode.DEFAULT_REESTABLISH_HOLD_MS;
	private mnemonic: string;
	private networkName: 'mainnet' | 'testnet' | 'regtest' | 'signet';
	private dataDir: string;
	/** Path to the single-instance lock file (null if locking was skipped). */
	private _lockPath: string | null = null;
	/** Bound process-exit handler that releases the lock; removed on destroy. */
	private _lockExitHandler: (() => void) | null = null;
	private destroyed = false;
	private startedAt = Date.now();
	private logLevel: LogLevel = 'info';
	private logger?: ILogger;
	private autoGossipSync = true;
	private rapidGossipSync = true;
	private rapidGossipSyncUrl?: string;
	/**
	 * Cap on how long connect-time gossip sync waits for the boot RGS attempt.
	 * The snapshot fetch's own 60s timeout is idle-socket only, so a trickling
	 * download could otherwise defer sync indefinitely. Static and mutable so
	 * tests can shrink it (the GOSSIP_INTAKE_MAX pattern).
	 */
	static INITIAL_GOSSIP_PRIME_TIMEOUT_MS = 90_000;
	/** Idle writer lease re-check cadence (issue #455). */
	private static readonly DEFAULT_LEASE_CHECK_INTERVAL_MS = 5 * 60_000;
	/**
	 * peer-storage mode: how long an unknown channel's reestablish is held
	 * before the peer is told the channel is unknown (issue #462). Long
	 * enough for an operator to read `capsules` off GET /recovery/status and
	 * run POST /recovery/restore-capsule, short enough that a peer waiting on
	 * a channel this node genuinely never had resolves within one reconnect
	 * cycle.
	 */
	private static readonly DEFAULT_REESTABLISH_HOLD_MS = 10 * 60_000;
	/** Largest delay Node's timers honor; beyond it they fire after 1 ms. */
	private static readonly MAX_TIMER_MS = 2_147_483_647;
	/**
	 * Non-null only while the boot-time RGS attempt is in flight (mainnet with
	 * rapidGossipSync on). Connect-time gossip sync waits on it so a fresh
	 * node does not request the entire graph from its first peer while RGS is
	 * about to provide the same data; once the graph is primed,
	 * getMissingSCIDs shrinks the p2p request to what RGS lacks (issue #441).
	 * Cleared to null on settle so later reconnects sync immediately.
	 */
	private _initialGossipPrime: Promise<void> | null = null;
	/**
	 * Resolves the boot RGS settlement the latch above waits on. The latch is
	 * installed BEFORE the LightningNode exists (its constructor already
	 * schedules persisted-peer reconnects, so any later install leaves a
	 * window where an early connect sees no latch); the RGS attempt itself
	 * starts further down the boot sequence and releases through this.
	 */
	private _releaseBootRgs: (() => void) | null = null;
	/**
	 * Pubkeys with a deferred gossip sync already queued on the latch. A
	 * connect/disconnect/reconnect churn during the RGS window must produce
	 * one sync per peer, not one per connect: a duplicate initiateGossipSync
	 * resets the same sync state machine mid-handshake and re-sends the
	 * range queries.
	 */
	private readonly _deferredGossipSyncs = new Set<string>();
	private paymentQueue?: PaymentQueue;
	private backupTimer?: ReturnType<typeof setInterval>;
	private backupPath?: string;
	private electrumServerCount = 1;
	private _failoverInProgress = false;
	private _backupPromise?: Promise<void>;
	private _listenPort?: number;
	private _websocketPort?: number;
	private _connectTimeoutMs = 15_000;
	private _dailySpendLimitSats?: number;
	// _dailySpentSats is the combined LN + onchain total; the two source
	// counters below only feed the GET /spend-limit breakdown.
	private _dailySpentSats = 0;
	private _dailySpentLightningSats = 0;
	private _dailySpentOnchainSats = 0;
	private _dailySpendResetTime = 0;
	private _pendingSpendSats = 0;
	/**
	 * paymentHash hex -> the budget claim of every async attempt dispatched for
	 * that hash, oldest first. A payment submitted through the fire-and-forget
	 * path returns before it settles and so has no local listener to release
	 * its reservation; the forwarding payment:sent handler installed in
	 * create() charges one claim per settlement, which keeps the listener count
	 * constant no matter how many async payments are in flight.
	 *
	 * A claim's sats stay counted in _pendingSpendSats until its reservation is
	 * released, and a payment reporting FAILED does NOT release it: the HTLC
	 * cannot be retracted and the engine completes the payment if the preimage
	 * turns up, so freeing the budget there let a caller cancel a live payment
	 * to win its daily allowance back and spend it twice. A reservation ends
	 * only when a settlement charges it, when the engine reported dispatching
	 * nothing, or when it expires (ASYNC_SPEND_CLAIM_TTL_MS). The record itself
	 * outlives the reservation so that a settlement arriving afterwards is
	 * still charged, to the day it arrives on.
	 *
	 * One claim per ATTEMPT, not per hash: a resubmission dispatched while an
	 * earlier attempt's HTLC may still be out there is a second live claim, and
	 * either of them can be the one that settles.
	 */
	private readonly _asyncSpendClaims = new Map<string, AsyncSpendClaim[]>();
	/**
	 * paymentHash hex -> how many blocking sends (payInvoice) currently own that
	 * hash's spend accounting. Their own listener records the settlement, so the
	 * forwarding handler in create() must not charge an async claim for the same
	 * event. Held only for as long as the listener is installed.
	 */
	private readonly _blockingPaymentHashes = new Map<string, number>();
	private _maxPaymentSats?: number;
	/**
	 * Paid L402 credentials, so a gated API is paid for once rather than per
	 * request. In memory by design: a credential is a bearer token for paid
	 * access, and where a durable copy lands is a deployment decision.
	 */
	private readonly _l402Credentials = new MemoryL402CredentialStore();
	private _draining = false;
	private peerStorageEnabled = true;
	/** Epoch ms of the last gossip/RGS sync completed this session. */
	private _lastGraphSyncAt?: number;
	/** Newest VALID SCB a peer returned via peer storage (never auto-restored). */
	private _peerRetrievedScb: {
		encoded: string;
		createdAt: number;
		fromPeer: string;
		channelCount: number;
		source: 'scb' | 'capsule';
	} | null = null;
	/**
	 * Best Recovery Capsule each peer has returned (spec 5.4): the raw blob
	 * for restoreBestRecoveryCapsule plus its decoded head for the status
	 * route. Never auto-restored.
	 */
	private readonly _peerRetrievedCapsules = new Map<
		string,
		{
			blob: Buffer;
			writerEpoch: bigint;
			latestSequence: bigint;
			inline: boolean;
			channelCount: number;
			/** The guardian locators the capsule names (spec 5.4, issue #457). */
			guardians: GuardianDescriptor[];
			receivedAt: number;
		}
	>();
	/** A non-empty SCB went out to storage peers this run. */
	private _pushedChannelBackup = false;
	private _nodeSecret?: Buffer;
	private _storageEncryptionKey?: Buffer;
	/**
	 * A Tier 2 capsule restore replaced the database underneath this daemon;
	 * only a restart builds a node on it (see restoreFromCapsules).
	 */
	private _restartRequired = false;
	/** recovery:fenced is relayed once per process, whichever path noticed. */
	private _recoveryFenceRelayed = false;

	private constructor(
		mnemonic: string,
		networkName: 'mainnet' | 'testnet' | 'regtest' | 'signet',
		dataDir: string
	) {
		super();
		this.mnemonic = mnemonic;
		this.networkName = networkName;
		this.dataDir = dataDir;
	}

	private log(
		level: LogLevel,
		message: string,
		data?: Record<string, unknown>
	): void {
		if (LOG_LEVEL_PRIORITY[level] < LOG_LEVEL_PRIORITY[this.logLevel]) return;
		const entry: LogEntry = { level, message, data, timestamp: Date.now() };
		this.emit('log', entry);
		if (this.logger && level !== 'silent') {
			this.logger[level](message, data);
		}
	}

	static async create(opts: BeignetNodeOptions = {}): Promise<BeignetNode> {
		const mnemonic = opts.mnemonic || generateMnemonic();
		const networkName = opts.network || 'mainnet';
		// Namespace the default storage per-wallet so different mnemonics never
		// share a database (which would load another seed's channels/identity).
		// An explicit dataDir is respected as-is (one wallet per dataDir).
		const dataDir = opts.dataDir || defaultDataDirForMnemonic(mnemonic);

		// Ensure data directory exists
		fs.mkdirSync(dataDir, { recursive: true });

		const instance = new BeignetNode(mnemonic, networkName, dataDir);
		await instance.init(opts);
		return instance;
	}

	private async init(opts: BeignetNodeOptions): Promise<void> {
		if (opts.logLevel) this.logLevel = opts.logLevel;
		if (opts.logger) this.logger = opts.logger;
		this.autoGossipSync = opts.autoGossipSync ?? true;
		this.peerStorageEnabled = opts.peerStorageEnabled ?? true;
		this.rapidGossipSync = opts.rapidGossipSync ?? true;
		this.rapidGossipSyncUrl = opts.rapidGossipSyncUrl;
		if (opts.recoveryLeaseCheckIntervalMs !== undefined) {
			// setInterval silently turns NaN and anything past 2^31-1 ms into a
			// 1 ms timer, which would poll the guardian set continuously.
			const ms = opts.recoveryLeaseCheckIntervalMs;
			if (!Number.isInteger(ms) || ms < 0 || ms > BeignetNode.MAX_TIMER_MS) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`recoveryLeaseCheckIntervalMs must be an integer between 0 and ` +
						`${BeignetNode.MAX_TIMER_MS} (got ${String(ms)})`
				);
			}
			this._leaseCheckIntervalMs = ms;
		}
		if (opts.recoveryReestablishHoldMs !== undefined) {
			// setTimeout turns anything past 2^31-1 ms into a 1 ms delay, which
			// would look like a configured hold that never actually holds.
			const ms = opts.recoveryReestablishHoldMs;
			if (!Number.isInteger(ms) || ms < 0 || ms > BeignetNode.MAX_TIMER_MS) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`recoveryReestablishHoldMs must be an integer between 0 and ` +
						`${BeignetNode.MAX_TIMER_MS} (got ${String(ms)})`
				);
			}
			this._reestablishHoldMs = ms;
		}
		// Routing fee defaults ride in channel_update as u32/u32/u16 (BOLT 7);
		// an out-of-range value would wrap on the wire or throw only once
		// gossip is being rebuilt, so it is refused here instead, matching the
		// per-channel updateChannelPolicy bounds (issue #532 workstream 1B).
		if (opts.routingFeeBaseMsat !== undefined) {
			const v = opts.routingFeeBaseMsat;
			if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`routingFeeBaseMsat must be an integer between 0 and ` +
						`4294967295 (got ${String(v)})`
				);
			}
		}
		if (opts.routingFeePpm !== undefined) {
			const v = opts.routingFeePpm;
			if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`routingFeePpm must be an integer between 0 and ` +
						`4294967295 (got ${String(v)})`
				);
			}
		}
		if (opts.routingCltvDelta !== undefined) {
			// Zero would leave no window to claim a forwarded HTLC on-chain
			// after learning the preimage, so the floor is 1 as on the
			// per-channel surface; BOLT 2/7 guidance recommends >= 18.
			const v = opts.routingCltvDelta;
			if (!Number.isInteger(v) || v < 1 || v > 0xffff) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`routingCltvDelta must be an integer between 1 and 65535 ` +
						`(>= 18 recommended, got ${String(v)})`
				);
			}
		}
		if (opts.leaseRates !== undefined) {
			const refusal = leaseRatesRefusal(opts.leaseRates);
			if (refusal !== null) {
				throw new BeignetError('INVALID_PARAMS', `leaseRates: ${refusal}`);
			}
		}
		if (opts.jitReceive !== undefined) {
			const refusal = jitReceiveRefusal(opts.jitReceive);
			if (refusal !== null) {
				throw new BeignetError('INVALID_PARAMS', `jitReceive: ${refusal}`);
			}
		}
		const networkName = this.networkName;

		// 2. Acquire the single-instance lock before touching storage. Two
		// instances on one data dir share a node identity (peer churns the
		// duplicate connection → connect/disconnect storm) and one SQLite DB
		// (corruption risk). Opt out with allowMultipleInstances if you really
		// know the two instances won't collide.
		if (!opts.allowMultipleInstances) {
			const lockPath = path.join(this.dataDir, `${networkName}.lock`);
			try {
				// reclaimForeignHost: after a container recreate the recorded
				// pid is meaningless here, and this daemon is the wallet's only
				// legitimate starter — take the leftover lock over.
				acquireInstanceLock(lockPath, {
					reclaimForeignHost: true,
					onReclaim: (holder, reason) => {
						this.log(
							'warn',
							`[beignet] Reclaimed stale instance lock (pid ${holder.pid} on ` +
								`${holder.hostname}, ${reason}) at ${lockPath}`
						);
					}
				});
			} catch (e) {
				if (e instanceof InstanceLockError) {
					throw new BeignetError(
						BeignetErrorCode.INSTANCE_ALREADY_RUNNING,
						e.message
					);
				}
				throw e;
			}
			this._lockPath = lockPath;
			// Safety net: release the lock if the process exits without destroy()
			// (Ctrl-C, uncaught error). A hard kill leaves it, but the next start
			// reclaims a stale lock via PID liveness (same host) or a hostname
			// change (recreated container), so no manual cleanup is needed.
			this._lockExitHandler = (): void => releaseInstanceLock(lockPath);
			process.once('exit', this._lockExitHandler);
		}

		// 3. Open SQLite storage
		const dbPath = path.join(this.dataDir, `${networkName}.db`);

		// Backward-compat notice: earlier versions stored every wallet in a single
		// shared `<network>.db` under the default data dir. That meant any mnemonic
		// loaded another seed's channels. Storage is now namespaced per-wallet, so
		// pre-existing data at the legacy path is no longer auto-loaded — surface it
		// rather than silently appearing to have lost the channels.
		if (!opts.dataDir) {
			const legacyDir = defaultDataDir();
			const legacyDb = path.join(legacyDir, `${networkName}.db`);
			if (fs.existsSync(legacyDb) && !fs.existsSync(dbPath)) {
				const legacyMsg =
					`[beignet] Found a legacy shared database at ${legacyDb}. ` +
					`Storage is now per-wallet (${dbPath}), so it is no longer auto-loaded. ` +
					`If it held this wallet's channels, re-run with dataDir set to "${legacyDir}" to use it.`;
				this.log('warn', legacyMsg);
				if (!this.logger) {
					// Preserve the historical console notice when no logger is injected.
					// eslint-disable-next-line no-console
					console.warn(legacyMsg);
				}
			}
		}

		// Encryption at rest (default on): derive the storage key from the BIP39
		// seed of the wallet mnemonic - the same seed material the Lightning and
		// on-chain keys derive from - so DB files and backups are unreadable
		// without the mnemonic. Pre-existing plaintext rows migrate on open().
		let encryptionKey: Buffer | undefined;
		if (opts.storageEncryption ?? true) {
			encryptionKey = deriveStorageKey(bip39.mnemonicToSeedSync(this.mnemonic));
		}

		this._storageEncryptionKey = encryptionKey;
		// A Tier 2 capsule restore that crashed mid-swap left its durable
		// marker; finish the install before anything opens the database.
		this.finishStagedCapsuleRestore(dbPath);
		this.storage = new SqliteStorage(
			dbPath,
			(err) => {
				this.log('warn', 'Skipped corrupted storage row during load', {
					error: err instanceof Error ? err.message : String(err)
				});
			},
			encryptionKey ? { encryptionKey } : undefined
		);
		this.storage.open();

		// Recovery Protocol boot decision (docs/RECOVERY-PROTOCOL.md section
		// 8). Guardian modes ask the guardian set who owns this namespace
		// BEFORE any node exists: a fresh database whose namespace the
		// guardians hold must restore, never run, and the daemon holds it in
		// the restore-pending state until restoreFromGuardians completes.
		await this.prepareRecovery(opts);
		if (this._restorePending) {
			this._deferredOpts = opts;
			this.log(
				'warn',
				'Recovery restore required: this database is fresh and the ' +
					'guardian set holds its namespace. The daemon serves only the ' +
					'recovery surface until POST /recovery/restore runs.'
			);
			return;
		}

		await this.initNode(opts);
	}

	/**
	 * Everything past the boot decision: on-chain wallet, Electrum, the
	 * LightningNode itself and its listeners. Runs from init for a runnable
	 * node, and from restoreFromGuardians for a node that booted
	 * restore-pending.
	 */
	private async initNode(opts: BeignetNodeOptions): Promise<void> {
		const networkName = this.networkName;
		const defaults = DEFAULT_ELECTRUM[networkName];
		const rawElectrumHost = opts.electrumHost || defaults.host;
		const electrumPort = opts.electrumPort || defaults.port;
		const electrumTls = opts.electrumTls ?? defaults.useTls;

		// Resolve the Electrum host to IPv4 up front. A `.local` (mDNS) or
		// dual-stack name often resolves to an IPv6 link-local address (fe80::…)
		// first, which the Electrum client's bare socket.connect(port, host)
		// stalls on (link-local needs a %zone id), producing intermittent
		// "Unable to connect" / blockHeight 0. Pin to the routable IPv4 address.
		const electrumHost = await resolveHostToIPv4(rawElectrumHost);
		if (electrumHost !== rawElectrumHost) {
			this.log('info', 'Resolved Electrum host to IPv4', {
				host: rawElectrumHost,
				ipv4: electrumHost
			});
		}

		// 1. Map network name to beignet types
		const beignetNetwork = this.toBeignetNetwork(networkName);
		const lnNetwork = this.toLnNetwork(networkName);
		const coinType = this.toCoinType(networkName);
		let chainHash = BITCOIN_CHAIN_HASH;
		if (networkName === 'regtest') chainHash = REGTEST_CHAIN_HASH;
		if (networkName === 'signet') chainHash = SIGNET_CHAIN_HASH;

		// 3. Create on-chain wallet
		const electrumServer = {
			host: electrumHost,
			ssl: electrumTls ? electrumPort : 0,
			tcp: electrumTls ? 0 : electrumPort,
			protocol: electrumTls ? EProtocol.ssl : EProtocol.tcp
		};
		const walletResult = await Wallet.create({
			mnemonic: this.mnemonic,
			network: beignetNetwork,
			// BeignetNode owns the ONE startup refresh (init step 15) so
			// waitForInitialSync can hold its promise; without this flag
			// Wallet.create fires its own and the wallet could scan twice at
			// boot (issue #548 review).
			disableRefreshOnCreate: true,
			// The option strings match EAddressType's values, so the cast is a
			// vocabulary bridge, not a coercion (issue #548).
			...(opts.addressType
				? { addressType: opts.addressType as EAddressType }
				: {}),
			...(opts.feeEstimationSource
				? { feeEstimationSource: opts.feeEstimationSource }
				: {}),
			electrumOptions: {
				net,
				tls,
				servers: electrumServer
			},
			disableMessagesOnCreate: true,
			// The wallet's own news (a transaction arriving, a transaction
			// confirming), relayed as daemon events. Messages stay disabled
			// through the initial sync above, so history never replays as
			// arrivals; what reaches the handler happened while the daemon was
			// watching, or was found new at a catch-up sync, which is still
			// news to whoever runs the node.
			onMessage: (key, data) => this.onWalletMessage(key, data),
			// Route wallet diagnostics through the injected logger when provided;
			// otherwise keep the wallet's default console logger (status quo).
			...(this.logger ? { logger: this.logger } : {}),
			// Enable RBF wallet-wide: canBoost() only ever reports rbf when this
			// flag is set, so without it /tx/bump-fee could never apply. Send
			// paths pass it per-transaction so outputs actually signal BIP 125.
			rbf: true,
			// Persist wallet state (addresses, UTXOs, transactions) through the
			// node's SQLite DB so a restart syncs incrementally from Electrum
			// instead of rebuilding from scratch. Rows are encrypted at rest iff
			// the storage encryption key above is set; the DB file is per-network
			// and keys embed the network, so testnet/mainnet data cannot mix.
			storage: createWalletStorage(this.storage)
		});
		if (walletResult.isErr()) {
			throw new BeignetError(
				'WALLET_CREATE_FAILED',
				walletResult.error.message
			);
		}
		this.wallet = walletResult.value;

		// 4. Create funding provider from wallet
		const fundingProvider = new WalletFundingProvider(this.wallet);

		// 5. Create electrum backend for chain monitoring
		const electrumBackend = new ElectrumBackend(this.wallet.electrum);

		// 5b. Wire Electrum failover if multiple servers configured
		if (opts.electrumServers && opts.electrumServers.length > 1) {
			let currentServerIndex = 0;
			const servers = opts.electrumServers;
			electrumBackend.onFailoverNeeded = async (): Promise<void> => {
				if (this._failoverInProgress) return;
				this._failoverInProgress = true;
				const startIndex = currentServerIndex;
				try {
					for (let i = 0; i < servers.length - 1; i++) {
						const oldIndex = currentServerIndex;
						currentServerIndex = (currentServerIndex + 1) % servers.length;
						if (currentServerIndex === startIndex) {
							currentServerIndex = (currentServerIndex + 1) % servers.length;
						}
						const oldServer = servers[oldIndex];
						const newServer = servers[currentServerIndex];
						this.log('warn', 'Electrum failover triggered', {
							from: `${oldServer.host}:${oldServer.port}`,
							to: `${newServer.host}:${newServer.port}`
						});
						try {
							const serverConfig = {
								host: newServer.host,
								ssl: newServer.tls ? newServer.port : 0,
								tcp: newServer.tls ? 0 : newServer.port,
								protocol: newServer.tls ? EProtocol.ssl : EProtocol.tcp
							};
							const result = await this.wallet.connectToElectrum(serverConfig);
							if (result.isErr()) continue;
							electrumBackend.setElectrum(this.wallet.electrum);
							await electrumBackend.resubscribeAll();
							this.emit('electrum:failover', {
								from: { host: oldServer.host, port: oldServer.port },
								to: { host: newServer.host, port: newServer.port },
								timestamp: Date.now()
							});
							return;
						} catch {
							// Try next server
						}
					}
					// All servers failed
					this.emit('node:error', {
						code: 'ELECTRUM_FAILOVER_FAILED',
						message: 'All Electrum servers failed during failover',
						timestamp: Date.now()
					});
				} finally {
					this._failoverInProgress = false;
				}
			};
		}

		// 5c. Derive a wallet-owned address for on-chain force-close sweeps, so
		// recovered funds land in the tracked wallet balance and are spendable
		// (rather than at the LN funding key, which the wallet does not scan).
		// This can fail if Electrum isn't connected yet at startup; if so we keep
		// retrying in the background (see scheduleSweepAddressRefresh) and redirect
		// sweeps to the wallet once an address resolves, instead of being stuck on
		// the funding-key fallback for the whole session.
		// Bounded: the fresh-address leg can enter the untimed Electrum
		// handshake, and unbounded it hangs create() itself (issue #548
		// review). scheduleSweepAddressRefresh below keeps retrying.
		const sweepDestinationScript = await this.raceWithTimeout(
			this.resolveWalletSweepScript().catch(() => undefined),
			BeignetNode.STARTUP_ADDRESS_LOOKUP_TIMEOUT_MS
		);
		if (sweepDestinationScript) {
			this.sweepDestinationScript = sweepDestinationScript;
		}

		// 6. Create Lightning node from mnemonic
		// Parse the optional Tor SOCKS5 proxy ("host:port") for reaching .onion peers.
		let socks5Proxy: { host: string; port: number } | undefined;
		if (opts.torProxy) {
			const [proxyHost, proxyPort] = opts.torProxy.split(':');
			const port = parseInt(proxyPort, 10);
			if (!proxyHost || !Number.isFinite(port)) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`Invalid torProxy "${opts.torProxy}" — expected "host:port"`
				);
			}
			socks5Proxy = { host: proxyHost, port };
		}

		// Parse addresses to advertise in our node_announcement (BOLT 7).
		let announcedAddresses: INodeAddress[] | undefined;
		if (opts.announceAddresses && opts.announceAddresses.length > 0) {
			announcedAddresses = opts.announceAddresses.map((addr) => {
				try {
					return parseAnnouncedAddress(addr);
				} catch (e) {
					throw new BeignetError(
						'INVALID_PARAMS',
						e instanceof Error ? e.message : `Invalid address "${addr}"`
					);
				}
			});
		}

		// Install the gossip-prime latch before the LightningNode exists: its
		// constructor schedules persisted-peer reconnects, and the awaits
		// between construction and the RGS kick-off below (fee estimation,
		// listen) would otherwise let an early peer connect observe no latch
		// and start the full p2p sync this latch exists to defer (issue #441).
		// The RGS attempt itself starts later in boot and releases the latch
		// through _releaseBootRgs; the timeout therefore caps total deferral
		// from here, which also bounds it if boot fails before RGS starts.
		if (this.rapidGossipSync && this.networkName === 'mainnet') {
			const settled = new Promise<void>((resolve) => {
				this._releaseBootRgs = resolve;
			});
			this._initialGossipPrime = gossipPrimeLatch(
				settled,
				BeignetNode.INITIAL_GOSSIP_PRIME_TIMEOUT_MS
			).then(() => {
				this._initialGossipPrime = null;
			});
		}

		this.node = LightningNode.fromMnemonic(this.mnemonic, {
			coinType,
			network: lnNetwork,
			storage: this.storage,
			enableNetworking: true,
			autoReconnect: opts.autoReconnect ?? true,
			autoUpdateChannelFees: opts.autoUpdateChannelFees ?? false,
			forwardingEnabled: opts.forwardingEnabled ?? true,
			// The routing* -> forwarding* rename seam: the CLI layer speaks the
			// operator vocabulary (and the BEIGNET_FEE_* envs), the library
			// speaks BOLT 7 forwarding terms. Undefined keeps the library
			// defaults (1000 / 1 / 40).
			forwardingFeeBaseMsat: opts.routingFeeBaseMsat,
			forwardingFeePropMillionths: opts.routingFeePpm,
			forwardingCltvDelta: opts.routingCltvDelta,
			leaseRates: opts.leaseRates,
			// The LSP engine only exists when explicitly switched on; the client
			// ceilings apply either way, because asking an LSP for a JIT receive
			// is not the same role as being one.
			jitReceive:
				opts.jitReceive?.enabled === true
					? {
							enabled: true,
							...(opts.jitReceive.flatFeeSat !== undefined
								? { flatFeeSat: BigInt(opts.jitReceive.flatFeeSat) }
								: {}),
							...(opts.jitReceive.feePpm !== undefined
								? { feePpm: opts.jitReceive.feePpm }
								: {})
					  }
					: undefined,
			jitReceiveClient:
				opts.jitReceive?.maxFlatFeeSat !== undefined ||
				opts.jitReceive?.maxFeePpm !== undefined
					? {
							...(opts.jitReceive.maxFlatFeeSat !== undefined
								? { maxFlatFeeSat: BigInt(opts.jitReceive.maxFlatFeeSat) }
								: {}),
							...(opts.jitReceive.maxFeePpm !== undefined
								? { maxFeePpm: opts.jitReceive.maxFeePpm }
								: {})
					  }
					: undefined,
			// Third-party direct funding (#613). Always constructed on the daemon:
			// the lanes have to be listening before an offer for a request minted
			// in a previous run arrives, and nothing is served until an operator
			// names a liquidity peer through POST /direct-funding/configure.
			directFunding: {
				relayServer: opts.dfRelay === true,
				policy:
					opts.dfMinAmountSat !== undefined
						? { minAmountSat: clampDirectFundingMinimum(opts.dfMinAmountSat) }
						: {}
			},
			eagerGossipVerify: opts.eagerGossipVerify ?? false,
			localFeatures: LightningNode.defaultFeatures(),
			chainHashes: [chainHash],
			alias: opts.alias,
			announcedAddresses,
			fundingProvider,
			preferAnchors: opts.preferAnchors,
			largeChannels: opts.largeChannels,
			chainBackend: electrumBackend,
			feeEstimator: electrumBackend,
			logger: this.logger,
			sweepDestinationScript,
			socks5Proxy,
			peerStorageEnabled: this.peerStorageEnabled,
			autoRebalance: opts.autoRebalance,
			autoTuneFees: opts.autoTuneFees,
			watchtowers: opts.watchtowers,
			recovery: this.recoveryNodeConfig
		});

		// If the wallet sweep address couldn't be resolved yet (e.g. Electrum was
		// down at startup), keep retrying and redirect sweeps to the wallet as
		// soon as one is available — so force-close recovery doesn't get stuck on
		// the invisible funding-key fallback.
		if (!sweepDestinationScript) {
			this.scheduleSweepAddressRefresh();
		}

		// Forward errors to callback or absorb to prevent process crash
		this.node.on(
			'node:error',
			(err: {
				code: string;
				message: string;
				timestamp: number;
				channelId?: Buffer;
			}) => {
				if (opts.onError) {
					opts.onError({
						code: err.code,
						message: err.message,
						timestamp: err.timestamp,
						channelId: err.channelId ? err.channelId.toString('hex') : undefined
					});
				}
				// Carry the channel id, as onError already does. Without it a
				// subscriber (SSE, webhooks) cannot tell which channel an error
				// belongs to, so an error raised while a channel is being opened
				// is indistinguishable from an unrelated one on another channel.
				this.emit('node:error', {
					code: err.code,
					message: err.message,
					timestamp: err.timestamp,
					channelId: err.channelId ? err.channelId.toString('hex') : undefined
				});
			}
		);

		// Forward payment events with JSON-safe types + structured logging
		this.node.on('payment:received', (info: IPaymentInfo) => {
			const pi = this.toPaymentInfo(info);
			this.log('info', 'Payment received', {
				paymentHash: pi.paymentHash,
				amountSats: pi.amountSats
			});
			this.emit('payment:received', pi);
		});
		this.node.on('payment:sent', (info: IPaymentInfo) => {
			const pi = this.toPaymentInfo(info);
			// Before the forward, so a subscriber reading the daily spend from
			// this event sees the settled payment already counted.
			this._chargeAsyncSpendClaim(pi.paymentHash);
			this.log('info', 'Payment sent', {
				paymentHash: pi.paymentHash,
				amountSats: pi.amountSats,
				feeSats: pi.feeSats
			});
			this.emit('payment:sent', pi);
		});
		this.node.on('payment:failed', (info: IPaymentInfo) => {
			const pi = this.toPaymentInfo(info);
			// Deliberately no spend accounting here. A failure report is not the
			// end of an async payment's claim on the daily budget: the HTLC it
			// dispatched cannot be withdrawn and can still be fulfilled, so the
			// claim runs until a settlement charges it or it expires. See
			// _asyncSpendClaims.
			// A bare failure code cannot be acted on: the same code means very
			// different things depending on WHICH hop returned it. Log the erring hop
			// and the channel it was asked to forward over, so a route failure can be
			// told apart from a destination failure without reproducing it.
			//
			// failureCode is absent entirely when the payment failed LOCALLY and the
			// HTLC never reached the network. That used to log as a lone
			// "failureCode: undefined", which reads like a decoding bug rather than
			// "your peer is unreachable", so carry the reason instead.
			this.log('warn', 'Payment failed', {
				paymentHash: pi.paymentHash,
				failureCode: pi.failureCode,
				...(info.failureReason ? { reason: info.failureReason } : {}),
				...this.describeFailureSource(info)
			});
			this.emit('payment:failed', pi);
		});

		// Forward channel events
		this.node.on('channel:ready', (data: { channelId: Buffer }) => {
			const channelId = data.channelId.toString('hex');
			this.log('info', 'Channel ready', { channelId });
			this.refreshStaticChannelBackup();
			this.emit('channel:ready', { channelId });
		});
		this.node.on('channel:closed', (data: { channelId: Buffer }) => {
			const channelId = data.channelId.toString('hex');
			this.log('info', 'Channel closed', { channelId });
			this.refreshStaticChannelBackup();
			this.emit('channel:closed', { channelId });
		});
		this.node.on('channel:voided', (data: { channelId: Buffer }) => {
			const channelId = data.channelId.toString('hex');
			this.log(
				'warn',
				'Channel voided: removed with nothing to close on chain (funding tx vanished, or the open was aborted or abandoned before funding)',
				{
					channelId
				}
			);
			this.refreshStaticChannelBackup();
			this.emit('channel:voided', { channelId });
		});
		// A resolved channel leaves the SCB channel set (state becomes CLOSED),
		// so refresh here. Also relay the event: it is the true terminal event
		// of a close (every on-chain output irrevocably swept).
		this.node.on('channel:resolved', (data: { channelId: Buffer }) => {
			this.refreshStaticChannelBackup();
			const channelId = data.channelId.toString('hex');
			// The engine gates resolution on IRREVOCABLE_DEPTH (issue #338), so
			// a live monitor only reaches here confirmed. Kept as a belt for
			// pre-fix persisted state: an unconfirmed close is not a terminal
			// guarantee (a reorg can void it), so never relay it as one.
			const monitor = this.node.getChannelManager().getMonitor(data.channelId);
			if (monitor && !monitor.isCommitmentConfirmed()) {
				this.log(
					'warn',
					'Suppressing channel:resolved relay for unconfirmed close',
					{ channelId }
				);
				return;
			}
			this.log('info', 'Channel resolved', { channelId });
			this.emit('channel:resolved', { channelId });
		});
		// Refresh the SCB when a splice LOCKS, not when it is initiated: only now
		// does fundingTxid hold the new post-splice outpoint, so the backup encodes
		// the outpoint a restore must actually watch (FS-7).
		this.node.on('splice:complete', () => {
			this.refreshStaticChannelBackup();
		});
		this.node.on(
			'channel:opening',
			(data: { channelId: Buffer; fundingTxid: Buffer }) => {
				const channelId = data.channelId.toString('hex');
				const fundingTxid = data.fundingTxid.toString('hex');
				this.log('info', 'Channel opening', { channelId, fundingTxid });
				this.emit('channel:opening', { channelId, fundingTxid });
			}
		);
		this.node.on(
			'channel:pending-close',
			(data: { channelId: Buffer; initiator: 'local' | 'remote' }) => {
				const channelId = data.channelId.toString('hex');
				this.log('info', 'Channel pending close', {
					channelId,
					initiator: data.initiator
				});
				this.emit('channel:pending-close', {
					channelId,
					initiator: data.initiator
				});
			}
		);
		this.node.on(
			'channel:force-closing',
			(data: { channelId: Buffer; initiator: 'local' | 'remote' }) => {
				const channelId = data.channelId.toString('hex');
				this.log('warn', 'Channel force-closing', {
					channelId,
					initiator: data.initiator
				});
				this.emit('channel:force-closing', {
					channelId,
					initiator: data.initiator
				});
			}
		);

		// Invoice settled: an invoice WE issued was paid (keysend receives fire
		// only payment:received).
		this.node.on(
			'invoice:settled',
			(data: { paymentHash: Buffer; bolt11: string; amountMsat: bigint }) => {
				const info = {
					paymentHash: data.paymentHash.toString('hex'),
					bolt11: data.bolt11,
					amountSats: Number(data.amountMsat / 1000n)
				};
				this.log('info', 'Invoice settled', {
					paymentHash: info.paymentHash,
					amountSats: info.amountSats
				});
				this.emit('invoice:settled', info);
			}
		);

		// HTLC-level events (high volume; the daemon only exposes these over
		// SSE/webhooks when htlcEvents is enabled). Forwards ALSO get a daemon
		// log line: relaying other people's money through our channels should be
		// as visible in the log as a payment is. Without this a node can forward
		// continuously and the log shows nothing, which made the #173 incident
		// expensive to diagnose.
		this.node.on(
			'htlc:forward',
			(
				inChannelId: Buffer,
				outChannelId: Buffer,
				amountMsat: bigint,
				paymentHash: Buffer
			) => {
				this.log('info', 'HTLC forward', {
					paymentHash: paymentHash.toString('hex'),
					inChannelId: inChannelId.toString('hex'),
					outChannelId: outChannelId.toString('hex'),
					amountSats: (amountMsat / 1000n).toString()
				});
			}
		);
		this.node.on(
			'htlc:forwarded',
			(data: {
				inChannelId: Buffer;
				outChannelId: Buffer;
				amountInMsat: bigint;
				amountOutMsat: bigint;
				feeMsat: bigint;
			}) => {
				this.log('info', 'HTLC forwarded', {
					inChannelId: data.inChannelId.toString('hex'),
					outChannelId: data.outChannelId.toString('hex'),
					amountInSats: (data.amountInMsat / 1000n).toString(),
					amountOutSats: (data.amountOutMsat / 1000n).toString(),
					feeMsat: data.feeMsat.toString()
				});
				this.emit('htlc:forwarded', {
					inChannelId: data.inChannelId.toString('hex'),
					outChannelId: data.outChannelId.toString('hex'),
					amountInMsat: data.amountInMsat.toString(),
					amountOutMsat: data.amountOutMsat.toString(),
					feeMsat: data.feeMsat.toString()
				});
			}
		);
		this.node.on(
			'htlc:forward-failed',
			(data: { inChannelId: Buffer; outChannelId: Buffer }) => {
				this.log('info', 'HTLC forward failed', {
					inChannelId: data.inChannelId.toString('hex'),
					outChannelId: data.outChannelId.toString('hex')
				});
			}
		);
		this.node.on(
			'htlc:fulfilled',
			(data: { channelId: Buffer; htlcId: bigint }) => {
				this.emit('htlc:fulfilled', {
					channelId: data.channelId.toString('hex'),
					htlcId: data.htlcId.toString()
				});
			}
		);
		this.node.on(
			'htlc:failed',
			(data: { channelId: Buffer; htlcId: bigint }) => {
				this.emit('htlc:failed', {
					channelId: data.channelId.toString('hex'),
					htlcId: data.htlcId.toString()
				});
			}
		);

		// Forward peer events
		this.node.on('peer:connect', (pubkey: string) => {
			this.log('debug', 'Peer connected', { pubkey });
			// Pull the gossip graph from the peer so we can route multi-hop payments
			// to destinations beyond our direct channels. Without this the graph
			// stays empty and only direct-peer payments work.
			if (this.autoGossipSync) {
				const prime = this._initialGossipPrime;
				if (prime) {
					// Boot RGS is still in flight: a sync now would request the
					// entire graph this node is about to receive from the
					// snapshot and verify all of it (issue #441). One deferred
					// sync per pubkey: a reconnect during the window must not
					// queue a second continuation, or both would fire on
					// release and reset the same sync state machine.
					if (!this._deferredGossipSyncs.has(pubkey)) {
						this._deferredGossipSyncs.add(pubkey);
						void prime.then(() => {
							this._deferredGossipSyncs.delete(pubkey);
							if (this.destroyed) return;
							const stillConnected = this.node
								.listPeers()
								.some((p) => p.pubkey === pubkey);
							if (!stillConnected) return;
							this.startGossipSync(pubkey);
						});
					}
				} else {
					this.startGossipSync(pubkey);
				}
			}
			this.emit('peer:connect', { pubkey });
		});
		this.node.on('peer:disconnect', (pubkey: string) => {
			this.log('debug', 'Peer disconnected', { pubkey });
			this.emit('peer:disconnect', { pubkey });
		});
		// The transport error that caused a disconnect (pong timeout, decrypt
		// failure, socket reset, ...) is the only place the reason is known —
		// surface it or disconnects are silent.
		this.node.on('peer:error', (pubkey: string, err: Error) => {
			this.log('warn', 'Peer error', { pubkey, error: err.message });
			this.emit('peer:error', { pubkey, message: err.message });
		});

		// Forward node:ready event
		this.node.on('node:ready', () => {
			this.log('info', 'Node ready');
			this.emit('node:ready');
		});

		// Recovery Protocol events (docs/RECOVERY-PROTOCOL.md section 8),
		// relayed with JSON-safe payloads. recovery:guardian_unreachable and
		// the restore events originate HERE rather than in LightningNode: the
		// daemon owns the barrier and the restore driver, so it bridges their
		// callbacks (see prepareRecovery and restoreFromGuardians).
		this.node.on('recovery:durable', (through: bigint) => {
			this.emit('recovery:durable', { through: through.toString() });
		});
		this.node.on('recovery:fenced', (superseding?: GuardianState) => {
			this.log(
				'error',
				'Recovery fenced: a newer writer epoch owns this namespace; ' +
					'this device must not send another channel message'
			);
			this.relayRecoveryFenced(superseding);
		});
		this.node.on('recovery:backfill-lost', (detail: string) => {
			this.log('error', 'Recovery backfill lost', { detail });
			this.emit('recovery:backfill-lost', { detail });
		});
		this.node.on(
			'recovery:reestablish-held',
			(peerPubkey: string, channelId: string, expiresAt: number) => {
				this.log(
					'warn',
					'Holding a peer channel_reestablish for an unknown channel: ' +
						'apply a Recovery Capsule (/recovery/restore-capsule) before ' +
						'the hold expires, or the peer will force-close',
					{ peerPubkey, channelId, expiresAt }
				);
				this.emit('recovery:reestablish-held', {
					peerPubkey,
					channelId,
					expiresAt
				});
			}
		);

		// Peer storage: peers that hold our SCB return it on every reconnect.
		// Keep only blobs that decrypt as OUR backup (a peer may return stale
		// data or garbage) and only the newest of those. Never auto-restored.
		this.node.on('peer_storage:retrieved', (peerPubkey: string, blob: Buffer) =>
			this.handleRetrievedPeerStorage(peerPubkey, blob)
		);
		// Prime the distributed blob so on-connect pushes carry the current SCB
		// (channels are already restored from storage at this point).
		if (this.peerStorageEnabled) {
			this.refreshStaticChannelBackup();
		}

		// 7. Warm fee cache so getFeeSnapshot() works immediately
		try {
			await electrumBackend.estimateFee(6);
		} catch {
			// Non-fatal: fallback to default fee rate
		}

		// 8. Track electrum server count for readiness check
		if (opts.electrumServers && opts.electrumServers.length > 0) {
			this.electrumServerCount = opts.electrumServers.length;
		}

		// 9. Start automated backup scheduling
		if (opts.backupPath) {
			this.backupPath = opts.backupPath;
			const intervalMs = opts.backupIntervalMs ?? 6 * 60 * 60 * 1000; // default 6 hours
			this.backupTimer = setInterval(() => {
				this.performScheduledBackup();
			}, intervalMs);
			if (this.backupTimer.unref) {
				this.backupTimer.unref();
			}
		}

		// 10. Start listening if port specified
		if (opts.listenPort) {
			try {
				await this.node.listen(opts.listenPort);
				this._listenPort = opts.listenPort;
			} catch {
				// Non-fatal
			}
		}
		if (opts.websocketPort) {
			try {
				await this.node.listenWebSocket(opts.websocketPort);
				this._websocketPort = opts.websocketPort;
			} catch {
				// Non-fatal
			}
		}

		// 11. Connect timeout + Daily spending limit
		if (opts.connectTimeoutMs !== undefined && opts.connectTimeoutMs > 0) {
			this._connectTimeoutMs = opts.connectTimeoutMs;
		}
		if (
			opts.dailySpendLimitSats !== undefined &&
			opts.dailySpendLimitSats > 0
		) {
			this._dailySpendLimitSats = opts.dailySpendLimitSats;
			this._resetDailySpendIfNeeded();
		}
		if (opts.maxPaymentSats !== undefined && opts.maxPaymentSats > 0) {
			this._maxPaymentSats = opts.maxPaymentSats;
		}

		// 12. Auto-bootstrap peer discovery
		if (opts.autoBootstrap) {
			this.node.connectToSeeds().catch(() => {
				/* best-effort: bootstrap failures are non-fatal */
			});
		}

		// Default graph source: download the full network graph via Rapid Gossip
		// Sync (mainnet). Runs in the background so it never blocks startup; the
		// graph fills in within a few seconds, enabling multi-hop routing.
		// Connect-time p2p gossip sync defers behind the latch (installed
		// earlier, before the node existed) until this first attempt settles,
		// success or not (issue #441).
		if (this.rapidGossipSync && this.networkName === 'mainnet') {
			const rgs = this.syncRapidGossip().catch((err) => {
				this.log('warn', 'Rapid gossip sync failed', {
					error: err instanceof Error ? err.message : String(err)
				});
			});
			const release = this._releaseBootRgs;
			if (release) {
				void rgs.then(release);
			}
		}

		// 12b. Direct funding: attach the lanes to the receiver and build the
		// payer over the same registry. Both halves need the node up, and the
		// receiver has to be listening before an offer arrives for a request
		// minted before the last restart.
		await this.startDirectFunding();

		// 13. Recover any funds stranded at the funding-key fallback address from
		// past force-close sweeps (sessions where no wallet address was available).
		// No-op when the fallback address is empty. Runs in the background, but
		// only once Electrum is actually connected — probing a still-connecting
		// socket otherwise surfaces a noisy "Connection to server lost" trace.
		if (this.sweepDestinationScript) {
			this.runFallbackRecoveryWhenConnected();
		}

		// 14. Guardian modes: confirm the writer lease with the quorum. The
		// gate holds ALL peer traffic until this succeeds, so it retries on a
		// backoff for as long as the guardians are unreachable (spec 5.6:
		// silence is not evidence of ownership, and a quarantined node safely
		// does nothing).
		if (this._recoveryRun) {
			this.startRecoveryConfirmLoop();
		}

		// 15. Initial wallet sync, in the background so create() keeps its
		// historical timing (issue #548). Without this the wallet never calls
		// subscribeToAddresses, so incoming on-chain deposits are invisible
		// until someone manually refreshes. Await waitForInitialSync() when
		// the balance and live deposit events must be reliable. The promise
		// settles on failure too (Electrum down at boot is normal); the
		// wallet's own reconnect-and-refresh machinery catches up later. The
		// wait is BOUNDED: an Electrum server that accepts the socket but
		// never answers server_version has no timeout of its own, and an
		// unbounded refresh would leave the documented settling guarantee a
		// lie (issue #548 review). On the bound the promise settles while the
		// refresh keeps running in the background.
		this._initialSync = (async (): Promise<void> => {
			let timer: ReturnType<typeof setTimeout> | undefined;
			const deadline = new Promise<'timeout'>((resolve) => {
				timer = setTimeout(
					() => resolve('timeout'),
					BeignetNode.INITIAL_SYNC_TIMEOUT_MS
				);
				timer.unref?.();
			});
			const attempt = this.wallet
				.refreshWallet({})
				.then((res) => {
					if (res.isErr()) {
						this.log('warn', 'Initial wallet refresh failed', {
							error: res.error.message
						});
					}
				})
				.catch((err) => {
					this.log('warn', 'Initial wallet refresh failed', {
						error: err instanceof Error ? err.message : String(err)
					});
				});
			const winner = await Promise.race([attempt, deadline]);
			if (timer) clearTimeout(timer);
			if (winner === 'timeout') {
				this.log(
					'warn',
					'Initial wallet refresh still running at the startup bound; ' +
						'continuing in the background',
					{ boundMs: BeignetNode.INITIAL_SYNC_TIMEOUT_MS }
				);
			}
		})();
	}

	/**
	 * Bound on the startup wallet refresh wait: the Electrum server_version
	 * handshake carries no timeout of its own, so a server that accepts the
	 * socket and says nothing would otherwise leave waitForInitialSync
	 * pending for the life of the process (issue #548 review). Generous,
	 * because a large wallet's first scan is legitimately slow.
	 */
	private static INITIAL_SYNC_TIMEOUT_MS = 120_000;

	/**
	 * Bound on init's wallet sweep-address resolution: the same untimed
	 * handshake would otherwise hang BeignetNode.create() itself, before any
	 * later bound can apply (issue #548 review, found by the silent-server
	 * test). On expiry init proceeds with the funding-key fallback and the
	 * background refresh keeps retrying.
	 */
	private static STARTUP_ADDRESS_LOOKUP_TIMEOUT_MS = 15_000;

	/**
	 * Race a promise against a timeout, resolving undefined on expiry. The
	 * loser keeps running in the background; callers own any fallback.
	 */
	private async raceWithTimeout<T>(
		promise: Promise<T>,
		timeoutMs: number
	): Promise<T | undefined> {
		let timer: ReturnType<typeof setTimeout> | undefined;
		const deadline = new Promise<undefined>((resolve) => {
			timer = setTimeout(() => resolve(undefined), timeoutMs);
			timer.unref?.();
		});
		try {
			return await Promise.race([promise, deadline]);
		} finally {
			if (timer) clearTimeout(timer);
		}
	}

	/**
	 * Resolves once the startup wallet refresh (balance scan plus Electrum
	 * address subscriptions) has settled or the startup bound elapsed. After
	 * this, getBalance() reflects the chain and the transaction:* events fire
	 * for live activity. Settles even when the refresh failed (offline boot):
	 * it signals "the attempt finished", not "the wallet is synced". Throws
	 * NODE_RESTORE_PENDING during guardian restore-pending startup, where no
	 * sync was attempted at all.
	 */
	async waitForInitialSync(): Promise<void> {
		if (!this._initialSync) {
			throw new BeignetError(
				'NODE_RESTORE_PENDING',
				'No wallet sync was attempted: this node is holding for a ' +
					'Recovery Protocol restore. Complete POST /recovery/restore first.'
			);
		}
		await this._initialSync;
	}

	/**
	 * Parse the recovery configuration and, in a guardian mode, make the boot
	 * decision against the guardian set. Sets recoveryNodeConfig for initNode
	 * (run), or _restorePending (restore-required), or throws (unavailable:
	 * no quorum to decide ownership with, which a fresh boot cannot proceed
	 * past; a restarting daemon self-heals when the guardians return).
	 */
	private async prepareRecovery(opts: BeignetNodeOptions): Promise<void> {
		const mode = parseRecoveryMode(opts.recoveryMode);
		this.recoveryMode = mode;
		if (mode === 'off') return;
		if (mode === 'peer-storage') {
			// Journal + Recovery Capsule over peer_storage, no guardians.
			// 'local' is the honest durability label for a node with no
			// replicator; capsule distribution rides peerStorageEnabled.
			//
			// This is the only mode that can be an INCOMPLETE restore target:
			// it boots empty on purpose and waits for the operator to apply a
			// capsule. Hold an unknown channel's reestablish for that window
			// rather than failing the channel the restore is about to resume
			// (spec 5.7, issue #462).
			this.recoveryNodeConfig = {
				enabled: true,
				durability: 'local',
				unknownChannelReestablishHoldMs: this._reestablishHoldMs
			};
			return;
		}
		// Guardian-backed modes. The daemon validates the guardian set before
		// create; parsing again here gives library callers the same refusals.
		const guardians = (opts.recoveryGuardians ?? []).map(parseGuardianEntry);
		this.recoveryGuardianSet = guardians;
		const decision = await buildGuardianRecovery({
			storage: this.storage,
			nodeSecret: this.nodeSecret(),
			durability: mode,
			guardians,
			onBarrierEvent: (event) => {
				if (event.type === 'barrier:unreachable') {
					this.log('warn', 'Recovery guardian unreachable', {
						detail: event.detail
					});
					this.emit('recovery:guardian_unreachable', {
						detail: event.detail,
						...(event.sequence !== undefined
							? { sequence: event.sequence.toString() }
							: {})
					});
				}
			},
			onGateEvent: (event) => {
				this.log(
					event.type === 'gate:fenced' ? 'error' : 'info',
					`Recovery gate: ${event.type}`,
					{ detail: event.detail }
				);
			},
			onReplicationEvent: (event) => {
				this.log('debug', `Recovery replication: ${event.type}`, {
					detail: event.detail
				});
			}
		});
		if (decision.kind === 'run') {
			this._recoveryRun = decision;
			this.recoveryNodeConfig = decision.recovery;
			return;
		}
		if (decision.kind === 'restore-required') {
			this._restoreDecision = decision;
			this._restorePending = true;
			return;
		}
		throw new BeignetError(
			'RECOVERY_UNAVAILABLE',
			`Recovery ${decision.outcome}: ${decision.detail}. Ownership of ` +
				'this namespace cannot be decided without a guardian quorum; ' +
				'retry when the guardian set is reachable.'
		);
	}

	/**
	 * Confirm the writer lease with the guardian quorum, retrying on a
	 * 5s-doubling-to-60s backoff until confirmed or fenced. The gate opening
	 * releases the node's held dials; a fence is relayed so operators see it.
	 */
	private startRecoveryConfirmLoop(): void {
		const run = this._recoveryRun;
		if (!run) return;
		let delayMs = 5_000;
		const attempt = async (): Promise<void> => {
			if (this.destroyed) return;
			try {
				const outcome = await run.confirm();
				if (outcome.state === 'confirmed') {
					this.log('info', 'Recovery gate confirmed; peer traffic released', {
						confirming: outcome.confirming
					});
					this.startRecoveryLeaseCheck();
					return;
				}
				if (outcome.state === 'fenced') {
					// The gate found a newer epoch at startup: same event the
					// barrier relays for a running node, same payload shape.
					this.relayRecoveryFenced(outcome.supersededBy);
					return;
				}
				this.log('warn', 'Recovery gate still quarantined; retrying', {
					confirming: outcome.confirming,
					nextRetryMs: delayMs
				});
			} catch (err) {
				this.log('warn', 'Recovery gate confirmation attempt failed', {
					error: err instanceof Error ? err.message : String(err),
					nextRetryMs: delayMs
				});
			}
			this._confirmTimer = setTimeout(() => {
				void attempt();
			}, delayMs);
			this._confirmTimer.unref?.();
			delayMs = Math.min(delayMs * 2, 60_000);
		};
		void attempt();
	}

	/**
	 * Relay a fence ONCE, whichever side noticed the takeover first (the
	 * barrier on a refused append, the startup gate, or the idle lease
	 * check), with one payload shape. The lease check has nothing left to
	 * learn once the device is fenced, so it stops here too.
	 */
	private relayRecoveryFenced(supersededBy: GuardianState | undefined): void {
		this.stopRecoveryLeaseCheck();
		if (this._recoveryFenceRelayed) return;
		this._recoveryFenceRelayed = true;
		this.emit('recovery:fenced', {
			supersededBy: supersededBy
				? {
						epoch: supersededBy.lease.epoch.toString(),
						writerPublicKey: supersededBy.lease.writerPublicKey.toString('hex'),
						sequence: supersededBy.logHead.sequence.toString(),
						frameHash: supersededBy.logHead.frameHash.toString('hex')
				  }
				: null
		});
	}

	/**
	 * Periodic lease re-check for an idle confirmed writer (issue #455).
	 *
	 * Fencing is enforced on commits and the startup gate covers restarts,
	 * so a superseded device that stays idle keeps reporting itself as the
	 * owner until one of those happens. This asks the guardian set on a
	 * cadence and, on a proven newer epoch, fences through the same gate
	 * path the startup check uses (the node hard-freezes its transports and
	 * the status route flips to fenced). It needs no quorum: one verified
	 * higher-epoch state is the same evidence a refused append yields. An
	 * outage or a partial answer changes nothing, by the gate's contract.
	 */
	private startRecoveryLeaseCheck(): void {
		const run = this._recoveryRun;
		if (!run || this._leaseCheckTimer || this._leaseCheckIntervalMs <= 0) {
			return;
		}
		this._leaseCheckTimer = setInterval(() => {
			if (this.destroyed || this._leaseCheckInFlight) return;
			this._leaseCheckInFlight = true;
			run
				.recheck()
				.then((outcome) => {
					if (outcome.state !== 'fenced') return;
					this.log(
						'error',
						'Recovery lease check: a newer writer epoch owns this ' +
							'namespace; this device is fenced'
					);
					this.relayRecoveryFenced(outcome.supersededBy);
				})
				.catch((err) => {
					this.log('debug', 'Recovery lease check failed', {
						error: err instanceof Error ? err.message : String(err)
					});
				})
				.finally(() => {
					this._leaseCheckInFlight = false;
				});
		}, this._leaseCheckIntervalMs);
		this._leaseCheckTimer.unref?.();
	}

	private stopRecoveryLeaseCheck(): void {
		if (this._leaseCheckTimer) {
			clearInterval(this._leaseCheckTimer);
			this._leaseCheckTimer = undefined;
		}
	}

	/** True while the daemon must hold every route except the recovery surface. */
	get restorePending(): boolean {
		return this._restorePending;
	}

	/**
	 * The recovery picture for GET /recovery/status. Always answers (a 404
	 * from an older daemon is the "predates the feature" probe; a 200 with
	 * state 'disabled' means supported but off).
	 */
	getRecoverySurfaceStatus(): {
		mode: RecoveryMode;
		profile: 'crash-v1' | null;
		guardians: Array<{ guardianId: string; url: string }>;
		state:
			| 'disabled'
			| 'running'
			| 'restore-required'
			| 'restoring'
			| 'restart-required'
			| 'fenced';
		node: ReturnType<LightningNode['getRecoveryStatus']> | null;
		/** Recovery Capsules storage peers returned this session (spec 5.4). */
		capsules: {
			candidates: number;
			best: {
				writerEpoch: string;
				latestSequence: string;
				inline: boolean;
				channelCount: number;
				/**
				 * Guardian locators the capsule names, credentials redacted:
				 * what a seed restore with no configuration needs to rebuild
				 * BEIGNET_RECOVERY_GUARDIANS (issue #457). Reported, never
				 * adopted over the configured set.
				 */
				guardians: IReportedGuardian[];
				fromPeer: string;
				receivedAt: number;
			} | null;
		};
		restore?: {
			inProgress: boolean;
			lastEvent?: { type: string; detail: string };
		};
	} {
		const guardians = this.recoveryGuardianSet.map((g) => ({
			guardianId: g.guardianId.toString('hex'),
			url: g.url
		}));
		const profile =
			this.recoveryMode === 'async-remote' || this.recoveryMode === 'quorum'
				? ('crash-v1' as const)
				: null;
		const capsules = this.describeRetrievedCapsules();
		const restore = {
			inProgress: this._restoreInFlight,
			...(this._lastRestoreEvent ? { lastEvent: this._lastRestoreEvent } : {})
		};
		if (this._restartRequired) {
			return {
				mode: this.recoveryMode,
				profile,
				guardians,
				state: 'restart-required',
				node: null,
				capsules,
				restore
			};
		}
		if (this.recoveryMode === 'off') {
			return {
				mode: 'off',
				profile: null,
				guardians: [],
				state: 'disabled',
				node: null,
				capsules
			};
		}
		if (this._restorePending) {
			return {
				mode: this.recoveryMode,
				profile,
				guardians,
				state: this._restoreInFlight ? 'restoring' : 'restore-required',
				node: null,
				capsules,
				restore
			};
		}
		const node = this.node.getRecoveryStatus();
		return {
			mode: this.recoveryMode,
			profile,
			guardians,
			state: node.fenced || node.gate === 'fenced' ? 'fenced' : 'running',
			node,
			capsules
		};
	}

	/** True after a Tier 2 capsule restore: only a restart serves a node again. */
	get restartRequired(): boolean {
		return this._restartRequired;
	}

	/** Best retrieved capsule by (writerEpoch, latestSequence), for status. */
	private describeRetrievedCapsules(): ReturnType<
		BeignetNode['getRecoverySurfaceStatus']
	>['capsules'] {
		let best:
			| (ReturnType<
					BeignetNode['getRecoverySurfaceStatus']
			  >['capsules']['best'] & {
					epoch: bigint;
					sequence: bigint;
			  })
			| null = null;
		for (const [fromPeer, c] of this._peerRetrievedCapsules) {
			// Highest head wins; at an equal head an inline replica beats an
			// SCB-only twin, which is also the order the restore tries them.
			if (
				!best ||
				c.writerEpoch > best.epoch ||
				(c.writerEpoch === best.epoch && c.latestSequence > best.sequence) ||
				(c.writerEpoch === best.epoch &&
					c.latestSequence === best.sequence &&
					c.inline &&
					!best.inline)
			) {
				best = {
					epoch: c.writerEpoch,
					sequence: c.latestSequence,
					writerEpoch: c.writerEpoch.toString(),
					latestSequence: c.latestSequence.toString(),
					inline: c.inline,
					channelCount: c.channelCount,
					guardians: redactGuardians(c.guardians),
					fromPeer,
					receivedAt: c.receivedAt
				};
			}
		}
		if (!best) return { candidates: 0, best: null };
		const { epoch: _e, sequence: _s, ...rest } = best;
		return { candidates: this._peerRetrievedCapsules.size, best: rest };
	}

	/**
	 * The admin handoff of the best retrieved capsule's guardian set WITH
	 * its transport credentials (POST /recovery/capsule-guardians). The
	 * status route redacts credentials because it is readonly; an operator
	 * restarting in a guardian mode whose guardians require authentication
	 * needs them back, and the config file accepts exactly the entries
	 * returned here. Nothing is adopted or persisted by this call.
	 */
	revealCapsuleGuardians(): {
		fromPeer: string;
		head: { writerEpoch: string; latestSequence: string };
		guardians: GuardianDescriptor[];
		/** Config-file ready entries for recoveryGuardians. */
		entries: IGuardianConfigEntry[];
	} {
		const best = this.describeRetrievedCapsules().best;
		if (!best) {
			throw new BeignetError(
				'CAPSULE_RESTORE_NO_CANDIDATES',
				'No storage peer has returned a Recovery Capsule this session. ' +
					'Connect to the peers this node had channels with and retry.'
			);
		}
		const held = this._peerRetrievedCapsules.get(best.fromPeer)!;
		return {
			fromPeer: best.fromPeer,
			head: {
				writerEpoch: best.writerEpoch,
				latestSequence: best.latestSequence
			},
			guardians: held.guardians,
			entries: held.guardians.map((g) => ({
				guardianId: g.guardianId,
				url: g.transports[0].url,
				...(g.auth ? { auth: g.auth } : {})
			}))
		};
	}

	/**
	 * Restore this node from the Recovery Capsules storage peers returned
	 * (POST /recovery/restore-capsule, spec 5.4): peer-storage mode's
	 * counterpart to restoreFromGuardians.
	 *
	 * The capsules only arrive once a node is running and connected, but a
	 * Tier 2 install needs an EMPTY database, and even a fresh peer-storage
	 * node has journaled its genesis snapshot by then. So the install goes
	 * into a new database file, the running node (which must itself hold no
	 * channel state) is torn down, the files are swapped, and the daemon
	 * holds in the restart-required state: a restart boots on the restored
	 * state and the channels resume through reestablish. The previous
	 * database is kept beside it, never deleted. A Tier 1 outcome (no inline
	 * journal validated) needs none of that: the embedded SCB goes through
	 * recoverFromStaticChannelBackup on the live node, exactly like
	 * POST /restore/scb.
	 *
	 * Local durability has no fencing (spec 5.6): if the old device is still
	 * running, nothing stops it from acting on the same channels, which is
	 * why the daemon route demands an explicit confirm.
	 *
	 * A capsule that names guardians belongs to a guardian-backed namespace
	 * and is refused: that state restores through the guardian set with
	 * fencing. `unfenced` is the explicitly labelled escape hatch spec 5.7
	 * reserves for an operator whose guardian set is gone (issue #459): it
	 * proceeds anyway, cannot fence the old writer and says so, and is
	 * limited to a chain that never promised quorum, because a quorum-marked
	 * journal refuses to boot unbarriered and so could only ever be restored
	 * through its guardians or the SCB route.
	 */
	async restoreFromCapsules(options: { unfenced?: boolean } = {}): Promise<{
		tier: 1 | 2;
		channelCount: number;
		framesApplied: number;
		head: { writerEpoch: string; latestSequence: string };
		newestSeenHead: { writerEpoch: string; latestSequence: string };
		rejectedCandidates: number;
		restartRequired: boolean;
		/**
		 * Set when the escape hatch restored a guardian-backed capsule: the
		 * old writer is NOT fenced, and these are the guardians it named.
		 */
		unfenced?: { guardians: IReportedGuardian[] };
		recovering?: string[];
		skipped?: Array<{ channelId: string; reason: string }>;
	}> {
		if (this._restoreInFlight) {
			throw new BeignetError(
				'RESTORE_IN_PROGRESS',
				'A restore is already running; poll the status route.'
			);
		}
		// The escape hatch is authorization, so only the exact boolean counts:
		// a truthy string from a library caller must not open it.
		if (
			options.unfenced !== undefined &&
			typeof options.unfenced !== 'boolean'
		) {
			throw new BeignetError('INVALID_PARAMS', 'unfenced must be a boolean');
		}
		const unfencedRequested = options.unfenced === true;
		if (this.recoveryMode !== 'peer-storage' || this._restorePending) {
			throw new BeignetError(
				'CAPSULE_RESTORE_UNSUPPORTED',
				'Capsule restore applies to peer-storage mode only. Guardian ' +
					'modes restore through the guardian set (the /recovery/restore ' +
					'route); with recovery off there is no journal to restore, so ' +
					'use the SCB a peer returned (/backup/peer-retrieved) with the ' +
					'SCB restore route instead.'
			);
		}
		if (this._peerRetrievedCapsules.size === 0) {
			throw new BeignetError(
				'CAPSULE_RESTORE_NO_CANDIDATES',
				'No storage peer has returned a Recovery Capsule this session. ' +
					'Connect to the peers this node had channels with and retry.'
			);
		}
		try {
			assertEmptyTarget(this.storage);
		} catch (err) {
			throw new BeignetError(
				'CAPSULE_RESTORE_TARGET_DIRTY',
				'This database already holds channel, payment or invoice state ' +
					'that a restore would discard; run the restore from a fresh ' +
					'data directory (' +
					(err instanceof Error ? err.message : String(err)) +
					')'
			);
		}
		this._restoreInFlight = true;
		const progress = (type: string, detail: string): void => {
			this._lastRestoreEvent = { type, detail };
			this.log('info', `Capsule restore: ${type}`, { detail });
			this.emit('recovery:restore-progress', { type, detail });
		};
		const stagedPath = path.join(
			this.dataDir,
			`${this.networkName}.db.capsule-restore`
		);
		const dropStaged = (): void => {
			for (const suffix of ['', '-wal', '-shm']) {
				try {
					fs.unlinkSync(`${stagedPath}${suffix}`);
				} catch {
					// Not there.
				}
			}
		};
		try {
			const blobs = [...this._peerRetrievedCapsules.values()].map(
				(c) => c.blob
			);
			progress(
				'capsule:selecting',
				`${blobs.length} candidate capsule(s) from storage peers`
			);
			dropStaged();
			// Everything up to the marker write is a TARGET failure unless the
			// library says otherwise: the candidates are only to blame for a
			// CapsuleCandidateError (nothing decrypted, conflicting heads, no
			// candidate validated); a staged file that cannot be opened or
			// written is an operational fault and is reported as one.
			const installFailure = (err: unknown): BeignetError =>
				err instanceof CapsuleCandidateError
					? new BeignetError(
							'CAPSULE_RESTORE_FAILED',
							`No retrieved capsule could be restored: ${err.message}`
					  )
					: new BeignetError(
							'CAPSULE_RESTORE_INSTALL_FAILED',
							`Could not write the restored database: ${
								err instanceof Error ? err.message : String(err)
							}`
					  );
			let staged: SqliteStorage;
			try {
				staged = new SqliteStorage(
					stagedPath,
					() => {
						/* a fresh file has no rows to skip */
					},
					this._storageEncryptionKey
						? { encryptionKey: this._storageEncryptionKey }
						: undefined
				);
				staged.open();
			} catch (err) {
				dropStaged();
				throw installFailure(err);
			}
			let result: ReturnType<typeof restoreBestRecoveryCapsule>;
			try {
				result = restoreBestRecoveryCapsule(blobs, staged, this.nodeSecret(), {
					scratchStorage: (): SqliteStorage => {
						const scratch = new SqliteStorage(':memory:');
						scratch.open();
						return scratch;
					}
				});
				// Retrieval already refuses wrong-network capsules; this is the
				// belt on those braces, and a candidate defect if it ever fires.
				const expectedNetwork = this.toLnNetwork(this.networkName);
				if (result.scb.network !== expectedNetwork) {
					throw new CapsuleCandidateError(
						`capsule SCB network "${result.scb.network}" does not match ` +
							`this node's network "${expectedNetwork}"`
					);
				}
			} catch (err) {
				staged.close();
				dropStaged();
				throw installFailure(err);
			}
			const head = {
				writerEpoch: result.capsule.writerEpoch.toString(),
				latestSequence: result.capsule.latestSequence.toString()
			};
			const newestSeenHead = {
				writerEpoch: result.newestSeenHead.writerEpoch.toString(),
				latestSequence: result.newestSeenHead.latestSequence.toString()
			};
			// A capsule that names guardians describes a guardian-backed
			// namespace, and neither tier below is the right restore for one.
			// Tier 2 here would install the state without the 5.7 takeover
			// that fences a still-running old writer (and a quorum-marked
			// journal then refuses to boot unbarriered anyway); Tier 1 would
			// persist DLP recovery and ask the peers to force-close channels
			// the guardians could have resumed exactly. Stop before either
			// acts: the locators are on the status route and the admin
			// handoff, and the restore is the guardian path after a restart.
			// The SCB emergency path stays what it always was, the peer
			// retrieved backup through the SCB restore route.
			// A quorum-marked chain never installs from peer storage, locators
			// or not (a capsule from before #458 carries none): the node
			// refuses to run it unbarriered at construction, so the install
			// could never boot in this mode, and every exactness that chain
			// certified rests on the guardian quorum this route bypasses.
			if (
				result.tier === 2 &&
				chainPromisedQuorum(
					staged,
					deriveRecoveryMasterKey(this.nodeSecret()),
					getPublicKey(this.nodeSecret())
				)
			) {
				staged.close();
				dropStaged();
				throw new BeignetError(
					'CAPSULE_RESTORE_QUORUM_NAMESPACE',
					'The best capsule carries a quorum-durability journal, which ' +
						'cannot boot without its guardian quorum even unfenced; ' +
						'restore through the guardian set, or recover the channels ' +
						'from the peer-retrieved backup with the SCB restore route.'
				);
			}
			let unfenced: { guardians: IReportedGuardian[] } | undefined;
			if (result.capsule.guardians.length > 0) {
				const locators = redactGuardians(result.capsule.guardians);
				if (!unfencedRequested) {
					staged.close();
					dropStaged();
					this.log(
						'warn',
						'Capsule restore refused: capsule names a guardian set',
						{
							guardians: locators
						}
					);
					throw new BeignetError(
						'CAPSULE_RESTORE_GUARDIAN_BACKED',
						`The best capsule names ${locators.length} guardian(s): its state ` +
							'belongs to a guardian-backed namespace, which restores through ' +
							'the guardian set with fencing, not from peer storage. Restart ' +
							'in that recovery mode with the guardians the capsule names ' +
							'(capsules.best.guardians on the status route, or the ' +
							'capsule-guardians handoff when they need credentials); for an ' +
							'emergency SCB-only recovery use the peer-retrieved backup with ' +
							'the SCB restore route. An operator whose guardian set is gone ' +
							'can pass unfenced: true, which cannot fence the old writer.'
					);
				}
				// The escape hatch: the quorum guard above already ran.
				unfenced = { guardians: locators };
				this.log(
					'warn',
					'UNFENCED capsule restore: the capsule names a guardian set and ' +
						'the previous writer is not fenced; if it still runs, it keeps ' +
						'acting on these channels',
					{ guardians: locators }
				);
				progress(
					'capsule:unfenced',
					`restoring a guardian-backed capsule without fencing: the previous writer is NOT fenced (${locators.length} guardian(s) named)`
				);
			}
			const common = {
				channelCount: result.scb.channels.length,
				framesApplied: result.framesApplied,
				head,
				newestSeenHead,
				rejectedCandidates: result.rejectedCandidates,
				...(unfenced ? { unfenced } : {})
			};

			if (result.tier === 1) {
				// Nothing was written to the staged file; the SCB is the whole
				// answer and the live node takes it like any SCB restore.
				staged.close();
				dropStaged();
				progress(
					'capsule:tier1',
					`no inline journal validated; recovering ${common.channelCount} channel(s) from the embedded SCB`
				);
				const { recovering, skipped } =
					await this.node.recoverFromStaticChannelBackup(result.scb.channels);
				const info = {
					tier: 1 as const,
					...common,
					restartRequired: false,
					recovering,
					skipped
				};
				progress(
					'restore:complete',
					`Tier 1: ${recovering.length} channel(s) recovering, ${skipped.length} skipped`
				);
				this.emit('recovery:restored', {
					exact: false,
					framesApplied: 0,
					guardiansRepaired: 0,
					epoch: head.writerEpoch,
					tier: 1,
					restartRequired: false
				});
				return info;
			}

			// Tier 2: the staged database is the node's exact state. The daemon
			// state that lives beside the channel state in this database (the
			// persisted API-key rotations and revocations above all, then the
			// webhooks and the peer addresses the operator just used) is
			// carried across, or a restart would resurrect a revoked key.
			try {
				this.carryDaemonState(this.storage, staged);
			} catch (err) {
				staged.close();
				dropStaged();
				throw installFailure(err);
			}
			staged.close();
			progress(
				'capsule:installed',
				`Tier 2: ${result.framesApplied} frame(s) replayed at epoch ${head.writerEpoch} sequence ${head.latestSequence}`
			);

			// The swap is two renames with a crash window between them. The
			// marker written first makes it durable: init() finishes whatever
			// a crash left behind before the next boot opens a database, so
			// no restart can land on an empty one. From the marker on, only a
			// restart serves a node again, whatever happens below.
			const dbPath = path.join(this.dataDir, `${this.networkName}.db`);
			const keptPath = `${dbPath}.pre-capsule-restore-${new Date()
				.toISOString()
				.replace(/[:.]/g, '-')}`;
			const marker: ICapsuleRestoreMarker = {
				version: 1,
				stagedAt: Date.now(),
				staged: path.basename(stagedPath),
				keep: path.basename(keptPath),
				head,
				tier: 2
			};
			try {
				writeFileAtomic(
					this.capsuleRestoreMarkerPath(),
					JSON.stringify(marker)
				);
			} catch (err) {
				dropStaged();
				throw installFailure(err);
			}
			this._restartRequired = true;
			// Tear the running node down (its destroy closes the database), then
			// swap the files through the same path a crashed swap resumes on.
			this.teardownNodeForRestart();
			try {
				this.finishStagedCapsuleRestore(dbPath);
			} catch (err) {
				// The marker is still there: the next boot completes the swap.
				this.log('error', 'Capsule restore swap did not complete', {
					error: err instanceof Error ? err.message : String(err)
				});
				throw new BeignetError(
					'CAPSULE_RESTORE_INSTALL_FAILED',
					'The restored database was written but the file swap did not ' +
						'complete; restart the daemon, which finishes the install (' +
						(err instanceof Error ? err.message : String(err)) +
						')'
				);
			}
			const info = {
				tier: 2 as const,
				...common,
				restartRequired: true
			};
			progress(
				'restore:complete',
				`restored database installed (previous kept at ${path.basename(
					keptPath
				)}); restart the daemon to resume ${common.channelCount} channel(s)`
			);
			this.emit('recovery:restored', {
				exact: true,
				framesApplied: result.framesApplied,
				guardiansRepaired: 0,
				epoch: head.writerEpoch,
				tier: 2,
				restartRequired: true
			});
			return info;
		} finally {
			this._restoreInFlight = false;
		}
	}

	/**
	 * Stop everything that touches the node or its database ahead of the
	 * restore swap. Deliberately NOT destroy(): the daemon, its emitter (SSE
	 * subscribers watching the restore) and the instance lock stay up so the
	 * operator can read the status route and stop the daemon cleanly.
	 */
	private teardownNodeForRestart(): void {
		if (this.backupTimer) {
			clearInterval(this.backupTimer);
			this.backupTimer = undefined;
		}
		if (this._sweepRefreshTimer) {
			clearInterval(this._sweepRefreshTimer);
			this._sweepRefreshTimer = undefined;
		}
		if (this._fallbackRecoveryTimer) {
			clearInterval(this._fallbackRecoveryTimer);
			this._fallbackRecoveryTimer = undefined;
		}
		this.paymentQueue?.removeAllListeners();
		this.node.destroy();
		void (this.wallet as Wallet | undefined)?.stop().catch(() => {
			/* best effort */
		});
	}

	private capsuleRestoreMarkerPath(): string {
		return path.join(this.dataDir, `${this.networkName}.capsule-restore.json`);
	}

	/**
	 * Daemon-local state that lives in the database beside the channel
	 * state, and must follow the operator into the restored one: persisted
	 * API-key rotations and revocations (a dropped override resurrects a
	 * revoked secret), registered webhooks, and the peer addresses just
	 * used to retrieve the capsules (so the restored node dials its channel
	 * peers on its own). The auth override is mandatory; the rest is best
	 * effort and logged.
	 */
	private carryDaemonState(from: SqliteStorage, to: SqliteStorage): void {
		const overrides = from.loadWalletData(AUTH_KEY_OVERRIDES_STORAGE_KEY);
		if (overrides !== null) {
			to.saveWalletData(AUTH_KEY_OVERRIDES_STORAGE_KEY, overrides);
		}
		try {
			for (const hook of from.loadAllWebhooks()) {
				to.saveWebhook(
					hook.id,
					hook.url,
					hook.events,
					hook.secretHash,
					hook.createdAt
				);
			}
		} catch (err) {
			this.log('warn', 'Could not carry webhooks into the restore', {
				error: err instanceof Error ? err.message : String(err)
			});
		}
		try {
			for (const peer of from.loadAllPeerAddresses()) {
				to.savePeerAddress(peer.pubkey, peer.host, peer.port);
			}
		} catch (err) {
			this.log('warn', 'Could not carry peer addresses into the restore', {
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	/**
	 * Complete a marker-backed database swap, at restore time and on the
	 * boot after a crash. Idempotent over every state the two renames can
	 * be interrupted in: both files present (nothing moved yet), only the
	 * staged file present (the canonical database was moved aside), or
	 * only the canonical one (the swap finished, the marker did not clear).
	 * The previous database is only ever renamed, never deleted, and only
	 * after it is verified to hold no channel state.
	 */
	private finishStagedCapsuleRestore(dbPath: string): void {
		const markerPath = this.capsuleRestoreMarkerPath();
		if (!fs.existsSync(markerPath)) return;
		let marker: ICapsuleRestoreMarker;
		try {
			marker = JSON.parse(
				fs.readFileSync(markerPath, 'utf8')
			) as ICapsuleRestoreMarker;
			if (
				marker.version !== 1 ||
				typeof marker.staged !== 'string' ||
				typeof marker.keep !== 'string'
			) {
				throw new Error('unrecognized marker shape');
			}
		} catch (err) {
			throw new BeignetError(
				'CAPSULE_RESTORE_INSTALL_FAILED',
				`Unreadable capsule restore marker at ${markerPath} (${
					err instanceof Error ? err.message : String(err)
				}); inspect the data directory before starting`
			);
		}
		const stagedPath = path.join(this.dataDir, marker.staged);
		const keptPath = path.join(this.dataDir, marker.keep);
		const sidecars = ['-wal', '-shm'];
		const moveAside = (): void => {
			// The restore verified emptiness before writing the marker; verify
			// again here so a database that somehow gained channel state in
			// between is never moved out from under its channels.
			const current = new SqliteStorage(
				dbPath,
				() => {
					/* residue check only */
				},
				this._storageEncryptionKey
					? { encryptionKey: this._storageEncryptionKey }
					: undefined
			);
			current.open();
			try {
				assertEmptyTarget(current);
			} finally {
				current.close();
			}
			fs.renameSync(dbPath, keptPath);
			for (const suffix of sidecars) {
				try {
					fs.renameSync(`${dbPath}${suffix}`, `${keptPath}${suffix}`);
				} catch {
					// A clean close leaves none behind.
				}
			}
		};
		const stagedExists = fs.existsSync(stagedPath);
		const dbExists = fs.existsSync(dbPath);
		if (stagedExists) {
			if (dbExists) moveAside();
			for (const suffix of sidecars) {
				try {
					fs.unlinkSync(`${stagedPath}${suffix}`);
				} catch {
					// None expected: the staged database was closed cleanly.
				}
			}
			fs.renameSync(stagedPath, dbPath);
			this.log('info', 'Capsule restore installed', {
				head: marker.head,
				previous: marker.keep
			});
		} else if (!dbExists) {
			// Neither file: nothing this marker refers to exists any more.
			fs.unlinkSync(markerPath);
			throw new BeignetError(
				'CAPSULE_RESTORE_INSTALL_FAILED',
				`Capsule restore marker found but neither ${marker.staged} nor ` +
					`the database exists; the previous database may be at ` +
					`${marker.keep}. Inspect the data directory before starting`
			);
		}
		fs.unlinkSync(markerPath);
	}

	/** Node identity secret; the capsule key and its embedded SCB derive from it. */
	private nodeSecret(): Buffer {
		if (!this._nodeSecret) {
			this._nodeSecret = deriveLightningKeysFromMnemonic(
				this.mnemonic,
				undefined,
				this.toCoinType(this.networkName)
			).nodePrivateKey;
		}
		return this._nodeSecret;
	}

	/**
	 * Take this namespace over from the guardian replicas and start the node
	 * on the restored state (POST /recovery/restore). Only meaningful in the
	 * restore-pending boot state. The epoch takeover permanently fences any
	 * still-running old writer, which is why the daemon route demands an
	 * explicit confirm. Crash-safe and re-runnable: the driver persists its
	 * pending acquisition before any request and installs everything in one
	 * transaction, so a crash lands the next boot back in restore-pending and
	 * a second call resumes idempotently.
	 */
	async restoreFromGuardians(): Promise<{
		exact: boolean;
		framesApplied: number;
		guardiansRepaired: number;
		epoch: string;
	}> {
		// In-flight first: mid-restore the pending markers are already being
		// consumed (the decision clears before the deferred node build), and
		// the truthful answer for a second caller is "one is running".
		if (this._restoreInFlight) {
			throw new BeignetError(
				'RESTORE_IN_PROGRESS',
				'A guardian restore is already running; watch ' +
					'recovery:restore-progress over SSE or poll the status route.'
			);
		}
		if (!this._restorePending || !this._restoreDecision) {
			throw new BeignetError(
				'RESTORE_NOT_PENDING',
				'Guardian restore only applies while the daemon is in the ' +
					'restore-required state (a fresh database whose namespace the ' +
					'guardian set holds). This node is ' +
					(this.recoveryMode === 'off' || this.recoveryMode === 'peer-storage'
						? 'not running a guardian recovery mode.'
						: 'already running on its own state.')
			);
		}
		this._restoreInFlight = true;
		try {
			const driver = this._restoreDecision.buildRestoreDriver((event) => {
				this._lastRestoreEvent = { type: event.type, detail: event.detail };
				this.log('info', `Recovery restore: ${event.type}`, {
					detail: event.detail
				});
				this.emit('recovery:restore-progress', {
					type: event.type,
					detail: event.detail
				});
			});
			let result: IRestoreResult;
			try {
				result = await driver.restore();
			} catch (err) {
				if (err instanceof RestoreRefusedError) {
					throw new BeignetError(RESTORE_ERROR_CODES[err.reason], err.message);
				}
				throw err;
			}
			// The lease is durably installed, so re-running the boot decision
			// short-circuits on it (already-held, no network) and yields the
			// runnable assembly for the deferred node construction.
			const opts = this._deferredOpts!;
			this._restoreDecision = undefined;
			await this.prepareRecovery(opts);
			if (!this._recoveryRun) {
				throw new BeignetError(
					'INTERNAL_ERROR',
					'Restore installed a lease but the reassembly did not yield a ' +
						'runnable recovery state'
				);
			}
			await this.initNode(opts);
			this._restorePending = false;
			const info = {
				exact: result.wireSafetyProof !== undefined,
				framesApplied: result.framesApplied,
				guardiansRepaired: result.guardiansRepaired,
				epoch: result.lease.epoch.toString()
			};
			this.emit('recovery:restored', info);
			this.log('info', 'Recovery restore complete', info);
			return info;
		} finally {
			this._restoreInFlight = false;
		}
	}

	/**
	 * Run fallback-fund recovery once Electrum is connected. At startup the
	 * Electrum socket is often still opening, so an immediate listUnspent probe
	 * fails noisily. This waits (bounded) for connectivity, then attempts
	 * recovery exactly once. Best-effort: gives up quietly after ~60s.
	 */
	private runFallbackRecoveryWhenConnected(): void {
		const attempt = (): void => {
			this.recoverFallbackFunds().catch((err) => {
				this.log('warn', 'Fallback fund recovery failed', {
					error: err instanceof Error ? err.message : String(err)
				});
			});
		};
		if (this.wallet?.electrum?.connectedToElectrum) {
			attempt();
			return;
		}
		let waitedMs = 0;
		this._fallbackRecoveryTimer = setInterval(() => {
			waitedMs += 2000;
			const done =
				this.wallet?.electrum?.connectedToElectrum || waitedMs >= 60_000;
			if (!done) return;
			if (this._fallbackRecoveryTimer) {
				clearInterval(this._fallbackRecoveryTimer);
				this._fallbackRecoveryTimer = undefined;
			}
			if (this.wallet?.electrum?.connectedToElectrum) attempt();
		}, 2000);
		if (this._fallbackRecoveryTimer.unref) this._fallbackRecoveryTimer.unref();
	}

	/**
	 * Sweep UTXOs sitting at the funding-key fallback address —
	 * P2WPKH(fundingPubkey), which the wallet does not scan — into a
	 * wallet-owned address. Returns the broadcast txid and recovered amount,
	 * or null when there is nothing to recover (or no wallet address yet).
	 */
	async recoverFallbackFunds(opts?: {
		feeRatePerVbyte?: number;
	}): Promise<{ txid: string; amountSat: number; inputCount: number } | null> {
		const result = await this.node.recoverFallbackFunds(opts);
		if (result) {
			this.log('info', 'Recovered fallback funds to wallet', {
				txid: result.txid,
				amountSat: result.amountSat,
				inputCount: result.inputCount
			});
		}
		return result;
	}

	// ─────────────── Escape hatches ───────────────

	/**
	 * Direct access to the underlying LightningNode for features BeignetNode
	 * does not proxy (held forwards, routing-hint injection, custom
	 * messages). Issue #548, LFBW port #532 workstream 1F. Throws
	 * NODE_RESTORE_PENDING during guardian restore-pending startup, where the
	 * node deliberately does not exist yet: returning undefined behind a
	 * non-optional type would move the crash to the caller (issue #548
	 * review).
	 */
	get lightningNode(): LightningNode {
		if (!this.node) {
			throw new BeignetError(
				'NODE_RESTORE_PENDING',
				'The Lightning node does not exist yet: this daemon is holding ' +
					'for a Recovery Protocol restore. Complete POST /recovery/restore ' +
					'first.'
			);
		}
		return this.node;
	}

	/** Direct access to the underlying on-chain Wallet. Same restore-pending
	 *  contract as lightningNode. */
	get onchainWallet(): Wallet {
		if (!this.wallet) {
			throw new BeignetError(
				'NODE_RESTORE_PENDING',
				'The wallet does not exist yet: this daemon is holding for a ' +
					'Recovery Protocol restore. Complete POST /recovery/restore first.'
			);
		}
		return this.wallet;
	}

	// ─────────────── Info ───────────────

	getInfo(): NodeInfo {
		const info = this.node.getNodeInfo();
		const lightningBalance = this.getLightningBalanceSats();
		const result: NodeInfo = {
			nodeId: info.nodeId,
			alias: info.alias,
			network: this.networkName,
			blockHeight: this.node.getCurrentBlockHeight(),
			onchainBalanceSats: this.wallet.getBalance(),
			lightningBalanceSats: lightningBalance,
			pendingCloseBalanceSats: this.getPendingCloseBalanceSats(),
			erroredBalanceSats: this.getErroredBalanceSats(),
			splicingBalanceSats: this.getSplicingBalanceSats(),
			channelCount: info.channelCount,
			openChannelCount: info.openChannelCount,
			peerCount: info.peerCount,
			listening: this.node.isListening()
		};
		if (this._websocketPort !== undefined) {
			result.websocketPort = this._websocketPort;
		}
		return result;
	}

	getMnemonic(): string {
		return this.mnemonic;
	}

	/**
	 * Sign a message with the node identity key (LND-compatible format,
	 * verifiable with `lncli verifymessage`).
	 */
	signMessage(message: string): { signature: string; pubkey: string } {
		if (typeof message !== 'string' || message.length === 0) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'message required'
			);
		}
		return {
			signature: this.node.signMessage(message),
			pubkey: this.node.getNodeId()
		};
	}

	/**
	 * Verify an LND-style message signature: recovers the signer pubkey and
	 * reports whether it belongs to a node in our network graph. Callers must
	 * check the recovered pubkey against the expected signer.
	 */
	verifyMessage(
		message: string,
		signature: string
	): { valid: boolean; pubkey: string | null; knownNode: boolean } {
		if (typeof message !== 'string' || typeof signature !== 'string') {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'message and signature required'
			);
		}
		return this.node.verifyMessage(message, signature);
	}

	getBalance(): BalanceInfo {
		const onchain = this.wallet.getBalance();
		const lnBalance = this.node.getBalance();
		const lightning = Number(lnBalance.localBalanceMsat / 1000n);
		const unsettledSats = Number(lnBalance.unsettledBalanceMsat / 1000n);
		const splicingSats = this.getSplicingBalanceSats();
		return {
			onchain,
			lightning,
			total: onchain + lightning,
			unsettledSats,
			splicingSats
		};
	}

	/**
	 * Sum of local balances in force-closed / closing channels — funds being
	 * recovered on-chain (claimable, possibly still timelocked), which are not
	 * counted as live lightning balance and not yet in the wallet. Surfaces
	 * funds that would otherwise be invisible after a force-close.
	 */
	private getPendingCloseBalanceSats(): number {
		const recovering = new Set<ChannelState>([
			ChannelState.FORCE_CLOSED,
			ChannelState.SHUTTING_DOWN,
			ChannelState.NEGOTIATING_CLOSING
		]);
		let totalMsat = 0n;
		for (const ch of this.node.listChannels()) {
			if (recovering.has(ch.state)) {
				totalMsat += ch.localBalanceMsat;
			}
		}
		return Number(totalMsat / 1000n);
	}

	/**
	 * Sum of local balances in ERRORED channels — funds stuck after a channel
	 * failure with no close in progress. Counted in neither the live lightning
	 * balance nor the pending-close balance; surfaced so they aren't invisible.
	 * Recovering them typically requires force-closing the channel.
	 */
	private getErroredBalanceSats(): number {
		let totalMsat = 0n;
		for (const ch of this.node.listChannels()) {
			if (ch.state === ChannelState.ERRORED) {
				totalMsat += ch.localBalanceMsat;
			}
		}
		return Number(totalMsat / 1000n);
	}

	/**
	 * Local balance in channels with a splice in flight: the balance each
	 * channel SETTLES TO when its splice locks, not the live pre-splice figure.
	 * The distinction is the whole point: the live localBalanceMsat stays
	 * pre-splice until splice_locked, so after a max splice-in the newly added
	 * sats would appear in no bucket at all (on-chain swept, lightning
	 * excludes SPLICING, and the old local balance never contained them), and
	 * after a splice-out the bucket would overstate what rejoins Lightning.
	 * Falls back to the live balance for a channel still negotiating (before
	 * the point of no return), when the wallet inputs are still visible in the
	 * on-chain balance.
	 */
	private getSplicingBalanceSats(): number {
		let totalMsat = 0n;
		for (const ch of this.node.listChannels()) {
			// payThroughSplice is present exactly when the channel is mid-splice
			// by EFFECTIVE state — including one disconnected mid-splice, whose
			// in-transit funds must not vanish from the bucket while the peer is
			// away.
			if (ch.payThroughSplice === undefined) continue;
			const pending = ch.pendingSpliceLocalBalanceMsat ?? ch.localBalanceMsat;
			if (ch.payThroughSplice) {
				// Pay-during-splice: the canonical balance already counts this
				// channel at min(live, settle-to); the bucket holds only what is
				// still in transit — a splice-in's arriving sats. A splice-out's
				// departing sats surface on the on-chain side once the splice tx
				// is seen, not here.
				const counted =
					pending < ch.localBalanceMsat ? pending : ch.localBalanceMsat;
				totalMsat += pending - counted;
			} else {
				// Parked channel (taproot, or pre point-of-no-return): the whole
				// settle-to balance is out of the canonical figure until the lock.
				totalMsat += pending;
			}
		}
		return Number(totalMsat / 1000n);
	}

	/**
	 * Best-effort derivation of a wallet-owned output script for force-close
	 * sweeps. Returns undefined if the wallet can't produce an address yet
	 * (e.g. Electrum not connected). Never throws.
	 */
	private async resolveWalletSweepScript(): Promise<Buffer | undefined> {
		// Preferred: the current unused wallet address. This requires Electrum
		// to gap-scan for the next unused index.
		const fresh = await this.resolveCurrentWalletAddressScript();
		if (fresh) return fresh;
		// Fallback: deterministically derive a wallet-owned address (index 0) with
		// NO network dependency. Reusing index 0 is a minor privacy tradeoff, but
		// it guarantees force-close sweeps always target a wallet-scanned address
		// rather than the invisible funding-key P2WPKH — even when Electrum is down
		// at startup, which is exactly when an offline force-close is detected on
		// restart and a sweep gets built. recoverFallbackFunds remains a safety net
		// for funds stranded by older sessions. (The cooperative-close path
		// deliberately does NOT use this leg: on a mature wallet index 0 can
		// sit outside the 20-address scan window behind the current index, and
		// nothing rescues it, so the close chain prefers its cached script and
		// then the rescuable funding key instead; issue #542 review.)
		const bitcoin = require('bitcoinjs-lib');
		try {
			const address = await this.wallet.getAddress({ index: '0' });
			if (address) {
				return bitcoin.address.toOutputScript(
					address,
					this.getBitcoinNetwork()
				);
			}
		} catch {
			// give up — caller keeps the funding-key fallback + background refresh
		}
		return undefined;
	}

	/**
	 * The current unused wallet address as an output script, or undefined when
	 * the wallet cannot produce one (Electrum needed for the gap scan).
	 */
	private async resolveCurrentWalletAddressScript(): Promise<
		Buffer | undefined
	> {
		const bitcoin = require('bitcoinjs-lib');
		try {
			const res = await this.wallet.getNextAvailableAddress();
			if (res.isOk()) {
				return bitcoin.address.toOutputScript(
					res.value.addressIndex.address,
					this.getBitcoinNetwork()
				) as Buffer;
			}
		} catch {
			// fall through to the caller's next leg
		}
		return undefined;
	}

	/**
	 * Retry resolving a wallet sweep address in the background until it succeeds,
	 * then redirect all future/pending force-close sweeps to it. Stops on success
	 * or after a bounded number of attempts. Closes the gap where Electrum being
	 * down at startup would otherwise pin sweeps to the funding-key fallback.
	 */
	private scheduleSweepAddressRefresh(): void {
		if (this._sweepRefreshTimer) return;
		let attempts = 0;
		const tick = async (): Promise<void> => {
			attempts++;
			const script = await this.resolveWalletSweepScript();
			if (script) {
				this.sweepDestinationScript = script;
				this.node.setSweepDestinationScript(script);
				this.log(
					'info',
					'Force-close sweep destination set to wallet address',
					{}
				);
				if (this._sweepRefreshTimer) {
					clearInterval(this._sweepRefreshTimer);
					this._sweepRefreshTimer = undefined;
				}
				// A wallet address just became available — pull any funds stranded
				// at the funding-key fallback into the wallet too.
				this.recoverFallbackFunds().catch((err) => {
					this.log('warn', 'Fallback fund recovery failed', {
						error: err instanceof Error ? err.message : String(err)
					});
				});
			} else if (attempts >= 120) {
				// ~10 min at 5s; give up quietly
				if (this._sweepRefreshTimer) {
					clearInterval(this._sweepRefreshTimer);
					this._sweepRefreshTimer = undefined;
				}
			}
		};
		this._sweepRefreshTimer = setInterval(() => {
			void tick();
		}, 5000);
		if (this._sweepRefreshTimer.unref) this._sweepRefreshTimer.unref();
	}

	private getLightningBalanceSats(): number {
		// Use the canonical balance, which counts only channels whose funds are
		// still live on Lightning (NORMAL / AWAITING_REESTABLISH). Force-closed
		// and closing channels are excluded: their funds are no longer spendable
		// over Lightning — they are being swept back to the on-chain wallet from
		// the (CSV-locked) force-close outputs, and would otherwise be
		// double-counted once they confirm on-chain. Keeps getInfo() consistent
		// with getBalance().
		return Number(this.node.getBalance().localBalanceMsat / 1000n);
	}

	// ─────────────── On-chain ───────────────

	async getNewAddress(): Promise<string> {
		const result = await this.wallet.getNextAvailableAddress();
		if (result.isErr()) {
			throw new BeignetError('ADDRESS_FAILED', result.error.message);
		}
		return result.value.addressIndex.address;
	}

	async sendOnchain(
		address: string,
		amountSats: number,
		satsPerVbyte?: number
	): Promise<TxInfo> {
		// External onchain sends share the daily budget with Lightning
		// payments. Fail fast on the amount alone before building.
		this._checkSpendLimit(amountSats);
		// wallet.send with broadcast:true resolves to the txid, not the raw
		// hex, so build first (broadcast:false returns the hex) and broadcast
		// separately to report both txid and hex. rbf must be passed per-send:
		// the wallet-level flag does not propagate into setupTransaction.
		const result = await this.wallet.send({
			address,
			amount: amountSats,
			broadcast: false,
			rbf: this.wallet.rbf,
			...(satsPerVbyte !== undefined ? { satsPerByte: satsPerVbyte } : {})
		});
		if (result.isErr()) {
			throw new BeignetError('SEND_FAILED', result.error.message);
		}
		// No limit configured: broadcast without touching the budget.
		if (this._dailySpendLimitSats === undefined) {
			return this._broadcastRawTx(result.value);
		}
		// Re-check with the real fee included, then reserve the total so
		// concurrent sends cannot both pass before either records.
		const totalSats = this._builtOnchainTotalSats(amountSats);
		try {
			this._checkSpendLimit(totalSats);
		} catch (e) {
			await this.wallet.resetSendTransaction();
			throw e;
		}
		this._pendingSpendSats += totalSats;
		try {
			const info = await this._broadcastRawTx(result.value);
			this._recordSpend(totalSats, 'onchain');
			return info;
		} finally {
			this._pendingSpendSats -= totalSats;
		}
	}

	/**
	 * Builds an UNSIGNED PSBT for an external signer (hardware wallet).
	 * Nothing is signed or broadcast.
	 */
	async buildPsbt(
		outputs: Array<{ address: string; amountSats: number }>,
		satsPerVbyte?: number
	): Promise<PsbtBuildInfo> {
		if (!Array.isArray(outputs) || outputs.length === 0) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'outputs array required'
			);
		}
		for (const output of outputs) {
			if (!output?.address || typeof output.amountSats !== 'number') {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					'each output requires address and amountSats'
				);
			}
		}
		this._validateFeeRate(satsPerVbyte);
		const result = await this.wallet.buildPsbt({
			txs: outputs.map((o) => ({ address: o.address, amount: o.amountSats })),
			rbf: this.wallet.rbf,
			...(satsPerVbyte !== undefined ? { satsPerByte: satsPerVbyte } : {})
		});
		if (result.isErr()) {
			throw new BeignetError('PSBT_BUILD_FAILED', result.error.message);
		}
		const built = result.value;
		return {
			psbtBase64: built.psbtBase64,
			feeSats: built.fee,
			vsizeEstimate: built.vsizeEstimate,
			satsPerVbyte: built.satsPerByte,
			inputs: built.inputs.map((input) => ({
				txid: input.tx_hash,
				vout: input.tx_pos,
				address: input.address,
				valueSats: input.value,
				path: input.path
			})),
			outputs: built.outputs.map((output) => ({
				address: output.address,
				valueSats: output.value
			}))
		};
	}

	/**
	 * Validates and finalizes an externally signed PSBT. Returns the raw
	 * transaction WITHOUT broadcasting; use sendRawTransaction-style flows or
	 * the wallet broadcast explicitly.
	 */
	importSignedPsbt(psbtBase64: string): PsbtImportInfo {
		if (!psbtBase64 || typeof psbtBase64 !== 'string') {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'psbtBase64 required'
			);
		}
		const result = this.wallet.importSignedPsbt(psbtBase64);
		if (result.isErr()) {
			throw new BeignetError('PSBT_IMPORT_FAILED', result.error.message);
		}
		return { txid: result.value.txid, txHex: result.value.txHex };
	}

	/** Combines partially signed copies of the same PSBT (multi-party flows). */
	combinePsbts(psbts: string[]): { psbtBase64: string } {
		if (!Array.isArray(psbts) || psbts.length < 2) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'psbts array with at least two entries required'
			);
		}
		const result = this.wallet.combinePsbts(psbts);
		if (result.isErr()) {
			throw new BeignetError('PSBT_COMBINE_FAILED', result.error.message);
		}
		return { psbtBase64: result.value };
	}

	/** Broadcast a built raw transaction and report both txid and hex. */
	private async _broadcastRawTx(hex: string): Promise<TxInfo> {
		const bitcoin = await import('bitcoinjs-lib');
		const tx = bitcoin.Transaction.fromHex(hex);
		const broadcastRes = await this.wallet.electrum.broadcastTransaction({
			rawTx: hex
		});
		if (broadcastRes.isErr()) {
			throw new BeignetError('SEND_FAILED', broadcastRes.error.message);
		}
		return { txid: tx.getId(), hex };
	}

	/** Reject a fee rate that is not a positive finite number. */
	private _validateFeeRate(
		satsPerVbyte: number | undefined,
		required = false
	): void {
		if (satsPerVbyte === undefined) {
			if (required) {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					'satsPerVbyte required'
				);
			}
			return;
		}
		if (
			typeof satsPerVbyte !== 'number' ||
			!Number.isFinite(satsPerVbyte) ||
			satsPerVbyte <= 0
		) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'satsPerVbyte must be a positive number'
			);
		}
	}

	private _validateTxid(txid: string): void {
		if (typeof txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(txid)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'txid must be a 64-character hex string'
			);
		}
	}

	/**
	 * Quote an on-chain transaction: what it will cost, without building one.
	 *
	 * A client cannot work this out for itself. The fee depends on which UTXOs coin
	 * selection picks, on their script types, and on whether change is needed, none
	 * of which a client knows. Guessing it means quoting one number and spending
	 * another, and sizing a "max" against a guess either strands sats or builds a
	 * transaction that cannot be funded.
	 *
	 * This is a pure calculation. It assembles a transaction in memory and prices
	 * it, and touches neither the wallet's staged send transaction nor its stored
	 * data. It must stay that way: that staging area is what a real send builds in,
	 * so a quote that reset or repopulated it could erase a send being prepared
	 * alongside it, and a route classified `readonly` has no business writing to
	 * the wallet at all.
	 *
	 * The figures hold for the UTXO set as it stands. A confirmation, a freeze, or
	 * another spend changes the inputs available and so changes the fee; coin
	 * selection itself is deterministic, so nothing else will.
	 *
	 * `max` prices a sweep, and reports the exact amount that leaves once its own
	 * fee is taken out.
	 */
	async quoteOnchain({
		address,
		amountSats,
		satsPerVbyte,
		max = false,
		channelFunding = false
	}: {
		address?: string;
		amountSats?: number;
		satsPerVbyte?: number;
		max?: boolean;
		channelFunding?: boolean;
	} = {}): Promise<TOnchainQuote> {
		const satsPerByte =
			satsPerVbyte === undefined
				? this.wallet.feeEstimates.normal
				: requirePositiveFiniteNumber(satsPerVbyte, 'satsPerVbyte');
		if (!max) {
			requirePositiveSafeInteger(amountSats, 'amountSats');
		}

		const txn = this.wallet.transaction;
		// The same UTXOs a send would gather: everything spendable, frozen ones out.
		const inputs = txn.removeBlackListedUtxos(this.wallet.data.utxos);
		if (!inputs.length) {
			throw new BeignetError(
				BeignetErrorCode.SEND_FAILED,
				'No UTXOs available.'
			);
		}
		const changeAddress =
			this.wallet.data.changeAddressIndex[this.wallet.addressType]?.address;
		if (!changeAddress) {
			throw new BeignetError(
				BeignetErrorCode.SEND_FAILED,
				'No change address available.'
			);
		}

		// Priced in memory, against a transaction the wallet never sees.
		const transaction: ISendTransaction = {
			...getDefaultSendTransaction(),
			rbf: this.wallet.rbf,
			satsPerByte,
			max,
			changeAddress,
			inputs,
			outputs: [
				{
					address: address || this.fundingSampleAddress(channelFunding),
					value: amountSats ?? 0,
					index: 0
				}
			]
		};

		if (max) {
			const maxSend = txn.getMaxSendAmount({ satsPerByte, transaction });
			if (maxSend.isErr()) {
				throw new BeignetError(
					BeignetErrorCode.SEND_FAILED,
					maxSend.error.message
				);
			}
			const info = this.wallet.getFeeInfo({ satsPerByte, transaction });
			if (info.isErr()) {
				throw new BeignetError(
					BeignetErrorCode.SEND_FAILED,
					info.error.message
				);
			}
			return {
				satsPerVbyte: satsPerByte,
				feeSats: maxSend.value.fee,
				vsize: info.value.transactionByteCount,
				maxSendSats: maxSend.value.amount,
				maxSatsPerVbyte: info.value.maxSatPerByte
			};
		}

		const info = this.wallet.getFeeInfo({ satsPerByte, transaction });
		if (info.isErr()) {
			throw new BeignetError(BeignetErrorCode.SEND_FAILED, info.error.message);
		}
		return {
			satsPerVbyte: satsPerByte,
			feeSats: info.value.totalFee,
			vsize: info.value.transactionByteCount,
			maxSatsPerVbyte: info.value.maxSatPerByte
		};
	}

	/**
	 * An address of the type an output will actually use, for quoting a transaction
	 * whose destination is not known yet. Only the script type matters: that is what
	 * decides the output's size.
	 *
	 * A channel funding output is the 2-of-2 the commitment signs against. That is a
	 * P2WSH here, because this node does not open taproot channels: preferTaproot is
	 * a LightningNode option and BeignetNode never passes it. If it ever does, this
	 * has to learn about the P2TR key-spend funding output at the same time, or a
	 * taproot open will be quoted against the wrong script.
	 */
	private fundingSampleAddress(channelFunding: boolean): string {
		if (!channelFunding) {
			// The wallet's own current receive address, of the type it actually uses.
			// Reading it does not consume it.
			return this.wallet.data.addressIndex[this.wallet.addressType].address;
		}
		const bitcoin = require('bitcoinjs-lib');
		// A witness-v0 32-byte program: the shape of a 2-of-2 funding output. The
		// bytes are irrelevant, only the script type is.
		return bitcoin.address.fromOutputScript(
			Buffer.concat([Buffer.from([0x00, 0x20]), Buffer.alloc(32)]),
			this.getBitcoinNetwork()
		);
	}

	/**
	 * Peer-aware max channel-funding quote. Decides v1 vs v2 exactly the way
	 * openChannel does (both inits advertising option_dual_fund), then prices
	 * the max open with the SAME arithmetic that funding path will commit:
	 *
	 * - v2 peer: the engine's quoteDualFundingMaxOpen (clamped rate converted
	 *   to sat/kw, the cushioned interactive-tx weight formula, zero change).
	 * - v1 peer, or a peer we hold no init for (peerKnown false): the
	 *   existing sweep-based quote from the actual transaction vbytes.
	 *
	 * The two formulas disagree by a few sats by design, which is the whole
	 * reason a UI cannot reconstruct this number: it must ask the daemon.
	 * Read-only, like quoteOnchain.
	 */
	async quoteChannelFunding({
		peerPubkey,
		satsPerVbyte
	}: {
		peerPubkey: string;
		satsPerVbyte?: number;
	}): Promise<TChannelFundingQuote> {
		if (!/^[0-9a-fA-F]{66}$/.test(peerPubkey ?? '')) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'peerPubkey must be a 66-character hex pubkey'
			);
		}
		const satsPerByte =
			satsPerVbyte === undefined
				? this.wallet.feeEstimates.normal
				: requirePositiveFiniteNumber(satsPerVbyte, 'satsPerVbyte');

		const { peerKnown, dualFund } = this.node.peerFundingInfo(peerPubkey);
		if (dualFund) {
			const quote = fundingOrRefuse(() =>
				this.node.quoteDualFundingMaxOpen(satsPerByte)
			);
			return {
				method: 'v2',
				peerKnown,
				satsPerVbyte: satsPerByte,
				feeratePerKw: quote.feeratePerKw,
				fundingSatoshis: Number(quote.fundingSatoshis),
				feeSats: Number(quote.feeSats),
				spendableSats: Number(quote.spendableSats),
				inputCount: quote.inputCount
			};
		}
		const sweep = await this.quoteOnchain({
			satsPerVbyte: satsPerByte,
			max: true,
			channelFunding: true
		});
		return {
			method: 'v1',
			peerKnown,
			satsPerVbyte: sweep.satsPerVbyte,
			fundingSatoshis: sweep.maxSendSats ?? 0,
			feeSats: sweep.feeSats,
			vsize: sweep.vsize,
			maxSatsPerVbyte: sweep.maxSatsPerVbyte
		};
	}

	/**
	 * Sweep the entire spendable on-chain balance to one address. The output
	 * value is balance minus fee; the wallet rejects rates where the fee would
	 * consume the whole balance.
	 */
	async sendMaxOnchain(
		address: string,
		satsPerVbyte?: number
	): Promise<TxInfo> {
		if (
			!address ||
			typeof address !== 'string' ||
			!this.wallet.validateAddress(address)
		) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				`Invalid ${this.networkName} address: ${address}`
			);
		}
		this._validateFeeRate(satsPerVbyte);
		const result = await this.wallet.sendMax({
			address,
			satsPerByte: satsPerVbyte ?? this.wallet.feeEstimates.normal,
			rbf: this.wallet.rbf,
			broadcast: false
		});
		if (result.isErr()) {
			throw new BeignetError('SEND_FAILED', result.error.message);
		}
		// No limit configured: broadcast without touching the budget.
		if (this._dailySpendLimitSats === undefined) {
			return this._broadcastRawTx(result.value);
		}
		// A sweep drains the entire input value (send amount + fee). Check it
		// against the shared daily budget BEFORE broadcast; the amount is only
		// known once the transaction has been built.
		const totalSats = this.wallet.transaction.getTransactionInputValue({
			inputs: this.wallet.transaction.data.inputs
		});
		if (totalSats <= 0) {
			// Fail closed: never broadcast a sweep the limit cannot account for.
			await this.wallet.resetSendTransaction();
			throw new BeignetError(
				'SPENDING_LIMIT_EXCEEDED',
				'Unable to determine the swept amount for the daily spend limit check; refusing to send'
			);
		}
		try {
			this._checkSpendLimit(totalSats);
		} catch (e) {
			await this.wallet.resetSendTransaction();
			throw e;
		}
		this._pendingSpendSats += totalSats;
		try {
			const info = await this._broadcastRawTx(result.value);
			this._recordSpend(totalSats, 'onchain');
			return info;
		} finally {
			this._pendingSpendSats -= totalSats;
		}
	}

	/**
	 * Replace an unconfirmed, RBF-signalling wallet transaction with a
	 * higher-fee version (BIP 125). Throws NOT_BOOSTABLE when RBF is not
	 * possible; use boostOnchain for the automatic RBF-else-CPFP path.
	 * Fee-only operation: EXCLUDED from the daily spend limit by design.
	 */
	async bumpFeeOnchain(
		txid: string,
		satsPerVbyte: number
	): Promise<BoostResult> {
		this._validateTxid(txid);
		this._validateFeeRate(satsPerVbyte, true);
		const can = this.wallet.canBoost(txid);
		if (!can.rbf) {
			throw new BeignetError(
				BeignetErrorCode.NOT_BOOSTABLE,
				can.cpfp
					? `Transaction ${txid} cannot be replaced via RBF; use POST /tx/boost (CPFP) instead`
					: `Transaction ${txid} is not boostable (unknown, already confirmed, or balance too low)`
			);
		}
		return this._boostRbf(txid, satsPerVbyte);
	}

	/**
	 * Fee-bump an unconfirmed wallet transaction, choosing RBF when canBoost
	 * allows it and CPFP otherwise. Falls back to CPFP when RBF setup fails
	 * (e.g. the change output cannot be identified) and CPFP is possible.
	 * Fee-only operation: EXCLUDED from the daily spend limit by design.
	 */
	async boostOnchain(
		txid: string,
		satsPerVbyte?: number
	): Promise<BoostResult> {
		this._validateTxid(txid);
		this._validateFeeRate(satsPerVbyte);
		const can = this.wallet.canBoost(txid);
		if (!can.canBoost) {
			throw new BeignetError(
				BeignetErrorCode.NOT_BOOSTABLE,
				`Transaction ${txid} is not boostable (unknown, already confirmed, or balance too low)`
			);
		}
		if (can.rbf) {
			try {
				return await this._boostRbf(txid, satsPerVbyte);
			} catch (e) {
				const rbfImpossible =
					e instanceof BeignetError &&
					e.code === BeignetErrorCode.NOT_BOOSTABLE;
				if (!(rbfImpossible && can.cpfp)) throw e;
			}
		}
		return this._boostCpfp(txid, satsPerVbyte);
	}

	private async _boostRbf(
		txid: string,
		satsPerVbyte?: number
	): Promise<BoostResult> {
		const setup = await this.wallet.transaction.setupRbf({ txid });
		if (setup.isErr()) {
			await this.wallet.resetSendTransaction();
			throw new BeignetError(
				BeignetErrorCode.NOT_BOOSTABLE,
				setup.error.message
			);
		}
		try {
			// setupRbf defaults to the fast feerate; apply a requested rate through
			// updateFee so the wallet's fee-overpayment guards run.
			if (satsPerVbyte !== undefined) {
				const feeRes = this.wallet.transaction.updateFee({
					satsPerByte: satsPerVbyte
				});
				if (feeRes.isErr()) {
					throw new BeignetError(
						BeignetErrorCode.INVALID_PARAMS,
						feeRes.error.message
					);
				}
			}
			// BIP 125 rule 3/4: the replacement must pay strictly more than the
			// original fee or the network rejects it; fail with a clear message
			// instead of a broadcast error.
			const original =
				this.wallet.unconfirmedTransactions[txid] ??
				this.wallet.transactions[txid];
			const originalFeeSats = original ? btcToSats(original.fee) : 0;
			const newFeeSats = this.wallet.transaction.data.fee;
			if (newFeeSats <= originalFeeSats) {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					`Replacement fee ${newFeeSats} sats does not exceed the original fee ${originalFeeSats} sats; raise satsPerVbyte`
				);
			}
			const createRes = await this.wallet.transaction.createTransaction();
			if (createRes.isErr()) {
				throw new BeignetError('SEND_FAILED', createRes.error.message);
			}
			const info = await this._broadcastRawTx(createRes.value.hex);
			await this._recordBoost(txid, info.txid, EBoostType.rbf, newFeeSats);
			return {
				...info,
				boostType: 'rbf',
				feeSats: newFeeSats,
				originalTxid: txid
			};
		} finally {
			await this.wallet.resetSendTransaction();
		}
	}

	private async _boostCpfp(
		txid: string,
		satsPerVbyte?: number
	): Promise<BoostResult> {
		const setup = await this.wallet.transaction.setupCpfp({
			txid,
			...(satsPerVbyte !== undefined ? { satsPerByte: satsPerVbyte } : {})
		});
		if (setup.isErr()) {
			await this.wallet.resetSendTransaction();
			throw new BeignetError(
				BeignetErrorCode.NOT_BOOSTABLE,
				setup.error.message
			);
		}
		try {
			const feeSats = setup.value.fee;
			const createRes = await this.wallet.transaction.createTransaction();
			if (createRes.isErr()) {
				throw new BeignetError('SEND_FAILED', createRes.error.message);
			}
			const info = await this._broadcastRawTx(createRes.value.hex);
			await this._recordBoost(txid, info.txid, EBoostType.cpfp, feeSats);
			return {
				...info,
				boostType: 'cpfp',
				feeSats,
				originalTxid: txid
			};
		} finally {
			await this.wallet.resetSendTransaction();
		}
	}

	/** Record a broadcast boost; bookkeeping failure must not fail the bump. */
	private async _recordBoost(
		oldTxId: string,
		newTxId: string,
		type: EBoostType,
		fee: number
	): Promise<void> {
		const res = await this.wallet.addBoostedTransaction({
			oldTxId,
			newTxId,
			type,
			fee
		});
		if (res.isErr()) {
			this.log('warn', 'Failed to record boosted transaction', {
				oldTxId,
				newTxId,
				error: res.error.message
			});
		}
	}

	/** Unconfirmed wallet transactions that can be fee-bumped, by method. */
	listBoostableTransactions(): BoostableTransactions {
		const { rbf, cpfp } = this.wallet.getBoostableTransactions();
		return {
			rbf: rbf.map((tx) => this.toOnchainTxInfo(tx)),
			cpfp: cpfp.map((tx) => this.toOnchainTxInfo(tx))
		};
	}

	/**
	 * Consolidate every spendable UTXO into a single output at a fresh wallet
	 * address. Implemented as send-max-to-self: wallet.sendMax spends ALL
	 * wallet UTXOs by construction, which is exactly a consolidation, and it
	 * reuses the wallet's existing fee ceiling guards.
	 */
	async consolidateUtxos(satsPerVbyte?: number): Promise<ConsolidateResult> {
		// Self-pay: funds return to the wallet, so consolidation is EXCLUDED
		// from the daily spend limit by design (only external sends count).
		this._validateFeeRate(satsPerVbyte);
		// Frozen UTXOs are excluded from coin selection, so count only
		// spendable ones here.
		const utxoCount = this.wallet
			.listUtxos()
			.filter((u) => !this.wallet.isUtxoFrozen(u.tx_hash, u.tx_pos)).length;
		if (utxoCount < 2) {
			throw new BeignetError(
				BeignetErrorCode.NOTHING_TO_CONSOLIDATE,
				`Nothing to consolidate: wallet has ${utxoCount} spendable UTXO(s), need at least 2`
			);
		}
		const address = await this.getNewAddress();
		const result = await this.wallet.sendMax({
			address,
			satsPerByte: satsPerVbyte ?? this.wallet.feeEstimates.normal,
			rbf: this.wallet.rbf,
			broadcast: false
		});
		if (result.isErr()) {
			throw new BeignetError('SEND_FAILED', result.error.message);
		}
		const feeSats = this.wallet.transaction.data.fee;
		const info = await this._broadcastRawTx(result.value);
		return { ...info, utxosConsolidated: utxoCount, address, feeSats };
	}

	async refreshWallet(): Promise<void> {
		const result = await this.wallet.refreshWallet({});
		if (result.isErr()) {
			throw new BeignetError('REFRESH_FAILED', result.error.message);
		}
	}

	/**
	 * On-chain events were the one kind of money movement the daemon never
	 * spoke about: a Lightning payment landing emits payment:received, but an
	 * on-chain receive changed /transactions and said nothing, leaving
	 * clients to poll for the difference. The wallet has reported these all
	 * along; nothing was listening.
	 */
	private onWalletMessage<K extends keyof TMessageDataMap>(
		key: K,
		data: TMessageDataMap[K]
	): void {
		// A replacement is its own kind of news: the txids a client was
		// watching are now dead, and nothing else says so (issue #548). The
		// payload is the wallet's replaced-txid list, not a transaction.
		if (key === 'rbf') {
			this.log('info', 'Onchain transaction replaced (RBF)', {
				txids: data as string[]
			});
			this.emit('onchain:rbf', { txids: data as string[] });
			return;
		}
		const relayed = {
			transactionReceived: {
				event: 'transaction:received',
				label: 'Transaction received'
			},
			transactionSent: {
				event: 'transaction:sent',
				label: 'Transaction sent'
			},
			transactionConfirmed: {
				event: 'transaction:confirmed',
				label: 'Transaction confirmed'
			}
		} as const;
		if (!(key in relayed)) return;
		const { event, label } = relayed[key as keyof typeof relayed];
		const { transaction } = data as TMessageDataMap['transactionReceived'];
		const info = this.toOnchainTxInfo(transaction);
		this.log('info', label, {
			txid: info.txid,
			type: info.type,
			valueSats: info.valueSats
		});
		this.emit(event, info);
	}

	// IFormattedTransaction stores value/fee in BTC (see wallet formatting),
	// so both need conversion to satisfy the *Sats field names.
	private toOnchainTxInfo(tx: IFormattedTransaction): OnchainTxInfo {
		return {
			txid: tx.txid,
			type:
				tx.type === EPaymentType.sent
					? ('sent' as const)
					: ('received' as const),
			valueSats: btcToSats(tx.value),
			feeSats: btcToSats(tx.fee),
			satsPerVbyte: tx.satsPerByte,
			address: tx.address,
			...(tx.height ? { height: tx.height } : {}),
			confirmed: Boolean(tx.height),
			timestamp: tx.timestamp,
			...(tx.confirmTimestamp !== undefined
				? { confirmTimestamp: tx.confirmTimestamp }
				: {})
		};
	}

	listOnchainTransactions(): OnchainTxInfo[] {
		// wallet.transactions already includes unconfirmed txs;
		// unconfirmedTransactions is a subset copy, so no merge here.
		return Object.values(this.wallet.transactions)
			.map((tx) => this.toOnchainTxInfo(tx))
			.sort((a, b) => b.timestamp - a.timestamp);
	}

	listUtxos(): UtxoInfo[] {
		// Trimmed shape: drops keyPair/publicKey so key material never
		// lands in REPL output or logs.
		return this.wallet.listUtxos().map((utxo) => ({
			txid: utxo.tx_hash,
			vout: utxo.tx_pos,
			address: utxo.address,
			valueSats: utxo.value,
			height: utxo.height,
			frozen: this.wallet.isUtxoFrozen(utxo.tx_hash, utxo.tx_pos)
		}));
	}

	/** Freeze a UTXO: excluded from all coin selection until unfrozen. */
	async freezeUtxo(txid: string, index: number): Promise<{ frozen: string }> {
		this._validateTxid(txid);
		const res = await this.wallet.freezeUtxo({ txid, index });
		if (res.isErr()) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				res.error.message
			);
		}
		return { frozen: `${txid}:${index}` };
	}

	/** Unfreeze a previously frozen UTXO. */
	async unfreezeUtxo(
		txid: string,
		index: number
	): Promise<{ unfrozen: string }> {
		this._validateTxid(txid);
		const res = await this.wallet.unfreezeUtxo({ txid, index });
		if (res.isErr()) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				res.error.message
			);
		}
		return { unfrozen: `${txid}:${index}` };
	}

	/** Set (or clear with an empty label) a user label for an address. */
	async setAddressLabel(
		address: string,
		label: string
	): Promise<{ address: string; label: string }> {
		const res = await this.wallet.setAddressLabel(address, label);
		if (res.isErr()) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				res.error.message
			);
		}
		return { address, label };
	}

	/** All user address labels keyed by address. */
	listAddressLabels(): Record<string, string> {
		return this.wallet.listAddressLabels();
	}

	/** BIP 380 output descriptors for the wallet (no private keys, ever). */
	exportDescriptors(): DescriptorsInfo {
		const res = this.wallet.exportDescriptors();
		if (res.isErr()) {
			throw new BeignetError('DESCRIPTOR_EXPORT_FAILED', res.error.message);
		}
		return res.value;
	}

	async getFeeEstimates(): Promise<IOnchainFees> {
		try {
			return await this.wallet.getFeeEstimates();
		} catch (e) {
			throw new BeignetError(
				'FEE_ESTIMATE_FAILED',
				e instanceof Error ? e.message : String(e)
			);
		}
	}

	validateAddress(address: string): boolean {
		return this.wallet.validateAddress(address);
	}

	getWallet(): Wallet {
		return this.wallet;
	}

	// ─────────────── Peers ───────────────

	async connectPeer(
		pubkey: string,
		host?: string,
		port?: number,
		transport?: IPeerTransportOptions
	): Promise<PeerInfo> {
		// Where we are dialing, for error messages: explicit host:port, or the
		// gossip/DNS resolution the library performs when both are omitted.
		const target =
			transport?.type === 'ws' && transport.url !== undefined
				? transport.url
				: host !== undefined && port !== undefined
				? `${host}:${port}`
				: 'resolved address (gossip graph / DNS bootstrap)';
		let timer: ReturnType<typeof setTimeout> | undefined;
		const connectPromise = this.node.connectPeer(pubkey, host, port, transport);
		const timeoutPromise = new Promise<never>((_, reject) => {
			timer = setTimeout(
				() =>
					reject(
						new BeignetError(
							'CONNECT_TIMEOUT',
							`connectPeer timed out after ${this._connectTimeoutMs}ms (is ${target} the peer's P2P address?)`
						)
					),
				this._connectTimeoutMs
			);
		});
		try {
			await Promise.race([connectPromise, timeoutPromise]);
		} catch (err) {
			if (err instanceof BeignetError) throw err;
			// A malformed pubkey or an unpaired host/port is the caller's own
			// request, not a dial that failed: CONNECT_FAILED answers 502 and
			// tells an agent to retry something that can never succeed.
			if (err instanceof InvalidRequestError) {
				throw new BeignetError(BeignetErrorCode.INVALID_PARAMS, err.message);
			}
			// Wrap raw transport/handshake failures so callers get a clean error
			// instead of an uncaught socket exception. A mid-handshake close almost
			// always means a wrong node pubkey or a non-LN address/port.
			throw new BeignetError(
				'CONNECT_FAILED',
				`Failed to connect to ${pubkey.slice(0, 16)}…@${target}: ${
					(err as Error).message
				}`
			);
		} finally {
			if (timer) clearTimeout(timer);
		}
		// When the library resolved the address, report the one it connected to.
		const connected = this.node.listPeers().find((p) => p.pubkey === pubkey);
		return {
			pubkey,
			host: host ?? connected?.host ?? '',
			port: port ?? connected?.port ?? 0,
			state: 'connected'
		};
	}

	disconnectPeer(pubkey: string): void {
		this.node.disconnectPeer(pubkey);
	}

	listPeers(): PeerInfo[] {
		return this.node.listPeers().map((p) => ({
			pubkey: p.pubkey,
			host: p.host,
			port: p.port,
			state: p.state as import('./types').PeerState
		}));
	}

	/**
	 * Start a p2p gossip sync with one peer, logging rather than throwing on
	 * failure. The automatic connect-time path routes through here, deferred
	 * behind _initialGossipPrime while the boot RGS attempt is in flight.
	 */
	private startGossipSync(pubkey: string): void {
		try {
			this.node.initiateGossipSync(pubkey);
		} catch (err) {
			this.log('warn', 'Gossip sync failed to start', {
				pubkey,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	/**
	 * Request a gossip graph sync. Pass a peer pubkey to sync from that peer, or
	 * omit to sync from all connected peers. Populates the network graph so the
	 * node can route multi-hop payments to destinations beyond its direct peers.
	 * Returns the pubkeys synced from. Explicit calls bypass the boot-time RGS
	 * deferral that gates the automatic connect-time sync.
	 */
	syncGossip(pubkey?: string): string[] {
		const peers = pubkey
			? [pubkey]
			: this.node.listPeers().map((p) => p.pubkey);
		const synced: string[] = [];
		for (const pk of peers) {
			try {
				this.node.initiateGossipSync(pk);
				synced.push(pk);
			} catch (err) {
				this.log('warn', 'Gossip sync failed', {
					pubkey: pk,
					error: err instanceof Error ? err.message : String(err)
				});
			}
		}
		if (synced.length > 0) this._lastGraphSyncAt = Date.now();
		return synced;
	}

	/**
	 * Download and apply a Rapid Gossip Sync snapshot, populating the network
	 * graph for multi-hop routing (a few MB over HTTPS). RGS snapshots are
	 * mainnet-only; on other networks this is a no-op. Returns ingestion counts.
	 */
	async syncRapidGossip(): Promise<{
		channelsAdded: number;
		updatesApplied: number;
	} | null> {
		if (this.networkName !== 'mainnet') {
			this.log('warn', 'Rapid gossip sync is only available on mainnet', {});
			return null;
		}
		const url = this.rapidGossipSyncUrl ?? DEFAULT_RGS_URL;
		this.log('info', 'Rapid gossip sync: downloading snapshot', { url });
		const data = await fetchRapidGossipSnapshot(url);
		const result = this.node.loadRapidGossipSnapshot(data);
		this._lastGraphSyncAt = Date.now();
		this.log('info', 'Rapid gossip sync complete', {
			channelsAdded: result.channelsAdded,
			updatesApplied: result.updatesApplied,
			nodes: result.nodeCount
		});
		this.emit('gossip:synced', {
			channelsAdded: result.channelsAdded,
			updatesApplied: result.updatesApplied
		});
		return {
			channelsAdded: result.channelsAdded,
			updatesApplied: result.updatesApplied
		};
	}

	// ─────────────── Channels ───────────────

	openChannel(
		pubkey: string,
		amountSats: number,
		pushSats?: number,
		satsPerVbyte?: number,
		max = false,
		trusted = false
	): ChannelInfo {
		requireOpenAmounts(amountSats, pushSats);
		const fundingSatoshis = BigInt(amountSats);
		const pushMsat =
			pushSats !== undefined ? BigInt(pushSats) * 1000n : undefined;
		const channel = fundingOrRefuse(() =>
			this.node.openChannel(
				pubkey,
				fundingSatoshis,
				pushMsat,
				satsPerVbyte,
				max,
				trusted
			)
		);
		const state = channel.getFullState();
		const balances = channel.getBalances();
		const channelId = state.channelId || state.temporaryChannelId;
		this.refreshStaticChannelBackup();
		return {
			channelId: channelId.toString('hex'),
			peerPubkey: pubkey,
			state: state.state as import('./types').ChannelStateString,
			localBalanceSats: Number(balances.localMsat / 1000n),
			remoteBalanceSats: Number(balances.remoteMsat / 1000n),
			// From the channel state, not the caller's amountSats: a max open
			// toward a dual-fund peer commits the engine's own quote, which is
			// what the channel is actually funded at.
			capacitySats: Number(state.fundingSatoshis),
			isAnchor: isAnchorChannel(state.channelType)
		};
	}

	async openChannelAndWait(
		pubkey: string,
		amountSats: number,
		opts?: { pushSats?: number; timeoutMs?: number }
	): Promise<ChannelInfo> {
		const info = this.openChannel(pubkey, amountSats, opts?.pushSats);
		await this.waitForChannelReady(info.channelId, opts?.timeoutMs ?? 120_000);
		// Refresh channel info after it's ready
		const updated = this.getChannel(info.channelId);
		return updated || info;
	}

	async connectAndOpenChannel(
		pubkey: string,
		host: string,
		port: number,
		amountSats: number,
		opts?: {
			pushSats?: number;
			satsPerVbyte?: number;
			max?: boolean;
			trusted?: boolean;
		}
	): Promise<ChannelInfo> {
		await this.connectPeer(pubkey, host, port);
		// A trusted open requires the peer in the trusted set; the caller asking
		// for a trusted open IS the trust declaration, so register it here.
		if (opts?.trusted) {
			this.node.addTrustedPeer(pubkey);
		}
		return this.openChannel(
			pubkey,
			amountSats,
			opts?.pushSats,
			opts?.satsPerVbyte,
			opts?.max,
			opts?.trusted ?? false
		);
	}

	async ensureMinimumChannels(
		count: number,
		satsPerChannel: number,
		_opts?: { timeoutMs?: number }
	): Promise<ChannelInfo[]> {
		// Check existing ready channels
		const existing = this.getReadyChannels();
		if (existing.length >= count) return existing;

		const needed = count - existing.length;
		// Request extra suggestions to account for connection failures
		const suggestions = this.getChannelSuggestions(needed * 2);

		if (suggestions.length === 0) {
			return existing;
		}

		const graph = this.node.getGraph();

		// Open channels to suggested peers (in parallel)
		const opened: ChannelInfo[] = [...existing];
		const openPromises: Promise<void>[] = [];
		let openedCount = 0;

		for (let i = 0; i < suggestions.length && openedCount < needed; i++) {
			const suggestion = suggestions[i];
			openedCount++;
			const promise = (async (): Promise<void> => {
				try {
					// Look up address from gossip graph. Dialing requires a
					// signature-verified announcement; a deferred one is
					// resolved by this read (issue #443).
					const addrs = graph.getVerifiedNodeAnnouncement(
						Buffer.from(suggestion.nodeId, 'hex')
					)?.addresses;
					if (addrs && addrs.length > 0) {
						const addr =
							addrs.find((a) => a.type === 1 || a.type === 2) || addrs[0];
						try {
							await this.connectPeer(suggestion.nodeId, addr.host, addr.port);
						} catch {
							// May already be connected — continue
						}
					} else {
						// No address available — skip this suggestion
						return;
					}
					const ch = this.openChannel(suggestion.nodeId, satsPerChannel);
					opened.push(ch);
				} catch {
					// Skip failed opens
				}
			})();
			openPromises.push(promise);
		}

		await Promise.all(openPromises);
		return opened;
	}

	async closeChannel(
		channelId: string,
		// Required for a capsule-restored channel, whose balances nothing can
		// prove current: a mutual close signs the allocation this row carries,
		// and a stale one is peer-favourable by construction (issue #469).
		acceptStaleStateRisk = false
	): Promise<{ ok: boolean; error?: string }> {
		// Validated the way forceCloseChannel already validates: Buffer.from
		// truncates at the first non-hex pair, so a caller's spelling is not an
		// identity and a malformed id would silently address some other channel
		// (issue #463/#469).
		const idBuf = requireChannelIdHex(channelId);
		// An unknown channel is the caller's mistake, not a node fault. It used
		// to fall through to the engine and come back as CLOSE_FAILED, which
		// has no status entry and therefore shipped as a retryable 500 with
		// "Channel not found" in the body (issue #474).
		if (!this.node.getChannel(idBuf)) {
			throw new BeignetError(
				BeignetErrorCode.CHANNEL_NOT_FOUND,
				`Channel not found: ${idBuf.toString('hex')}`
			);
		}
		// Pay the cooperative-close output to an address the on-chain wallet
		// actually scans (issue #542, LFBW port #532 workstream 1C). The old
		// funding-key script was invisible to the wallet: the payout sat
		// confirmed on-chain while the balance read zero until
		// recoverFallbackFunds swept it, a second transaction and fee. The
		// chain: the current unused wallet address (BOUNDED, because the
		// lookup can enter an Electrum handshake with no timeout of its own
		// and the close must reach the engine regardless), then the sweep
		// script resolved at startup, then the funding-key P2WPKH that
		// recoverFallbackFunds can still rescue. The index-0 leg the
		// force-close startup resolution uses is deliberately NOT in this
		// chain: on a mature wallet index 0 can sit outside the 20-address
		// scan window behind the current index and nothing rescues it, which
		// would recreate the invisible payout this change removes (issue #542
		// review). Every leg is derived locally from our own keys, so the
		// chain always terminates in a script we control.
		let scriptPubkey = await this.boundedCurrentWalletAddressScript();
		if (!scriptPubkey) scriptPubkey = this.sweepDestinationScript;
		if (!scriptPubkey) {
			const bitcoin = require('bitcoinjs-lib');
			scriptPubkey = bitcoin.address.toOutputScript(
				this.node.getFundingAddress(),
				this.getBitcoinNetwork()
			) as Buffer;
		}
		return this.node.closeChannel(idBuf, scriptPubkey, acceptStaleStateRisk);
	}

	/**
	 * The close path's wallet-address lookup, raced against
	 * _closeAddressLookupTimeoutMs so a non-settling Electrum handshake can
	 * never park the close before it reaches the engine.
	 */
	private async boundedCurrentWalletAddressScript(): Promise<
		Buffer | undefined
	> {
		return this.raceWithTimeout(
			this.resolveCurrentWalletAddressScript().catch(() => undefined),
			this._closeAddressLookupTimeoutMs
		);
	}

	forceCloseChannel(
		channelId: string,
		// The labelled risk acknowledgement RECOVERY-PROTOCOL 5.6 asks for
		// (issue #469). Required only for a channel restored from a Recovery
		// Capsule, whose recency nothing can prove: this node refuses to
		// broadcast such a commitment on its own initiative because the peer
		// may already hold a revocation for it, and an operator command is the
		// documented exit. It should be a decision, not a default, so the
		// route refuses without it and says why.
		acceptStaleStateRisk = false
	): {
		ok: boolean;
		error?: string;
		commitmentTxid?: string;
	} {
		// Validate before deciding anything from it. Buffer.from(x, 'hex')
		// truncates at the first non-hex pair and is case insensitive, so a
		// caller's spelling is not an identity: 'AB...' and 'ab...xyz' both
		// decode to the same channel while matching no canonical id, which
		// walked straight past the acknowledgement below.
		if (!/^[0-9a-fA-F]{64}$/.test(channelId)) {
			throw new BeignetError(
				'INVALID_PARAMS',
				'channelId must be 64 hex characters'
			);
		}
		const idBuf = Buffer.from(channelId, 'hex');
		// Same reason closeChannel refuses one: an unknown channel is a caller
		// mistake, and FORCE_CLOSE_FAILED carries no status, so it shipped as a
		// 500 (issue #474). Checked before the acknowledgement so a typo is
		// answered as a typo rather than as a restore refusal.
		if (!this.node.getChannel(idBuf)) {
			throw new BeignetError(
				BeignetErrorCode.CHANNEL_NOT_FOUND,
				`Channel not found: ${idBuf.toString('hex')}`
			);
		}
		// Compare on the DECODED bytes, which is what the engine resolves.
		const canonicalId = idBuf.toString('hex');
		const held = this.node
			.getRecoveryStatus()
			.channels.find((c) => c.channelId === canonicalId)
			?.restoreRecencyUnproven;
		if (held === true && acceptStaleStateRisk !== true) {
			throw new BeignetError(
				'INVALID_PARAMS',
				'This channel was restored from a Recovery Capsule and its state ' +
					'cannot be proven current, so the node will not broadcast its ' +
					'commitment on its own initiative. If the peer holds a newer ' +
					'state, force closing publishes a revoked commitment and the ' +
					'whole channel balance is lost to the justice path. Waiting for ' +
					'the peer to close is the safe outcome. Set ' +
					'acceptStaleStateRisk: true to force close anyway.'
			);
		}
		// Sweep recovered funds into the wallet-owned address (tracked + spendable)
		// when available; fall back to the LN funding address otherwise.
		let destinationScript = this.sweepDestinationScript;
		if (!destinationScript) {
			const bitcoin = require('bitcoinjs-lib');
			destinationScript = bitcoin.address.toOutputScript(
				this.node.getFundingAddress(),
				this.getBitcoinNetwork()
			);
		}
		return this.node.forceCloseChannel(idBuf, destinationScript!);
	}

	/**
	 * Rebroadcast the recorded close tx of a force-closed channel (or the
	 * stored mutual close of a CLOSED one). Only a channelId: the engine
	 * always rebuilds from the latest state, so no older commitment can be
	 * selected.
	 */
	rebroadcastClose(channelId: string): Promise<{
		ok: boolean;
		error?: string;
		txid?: string;
		broadcastOk?: boolean;
	}> {
		return this.node.rebroadcastClose(Buffer.from(channelId, 'hex'));
	}

	listChannels(): ChannelInfo[] {
		return this.node.listChannels().map((ch) => this.toChannelInfo(ch));
	}

	getChannel(channelId: string): ChannelInfo | null {
		const ch = this.node.getChannel(Buffer.from(channelId, 'hex'));
		if (!ch) return null;
		return this.toChannelInfo(ch);
	}

	getChannelHealth(
		channelId: string
	): import('../lightning/node/types').IChannelHealth | null {
		return this.node.getChannelHealth(Buffer.from(channelId, 'hex'));
	}

	getChannelDiagnostics(channelId: string): Record<string, unknown> | null {
		const channelIdBuf = Buffer.from(channelId, 'hex');
		const channel = this.node.getChannelManager().getChannel(channelIdBuf);
		if (!channel) return null;

		const state = channel.getFullState();
		// Mid-negotiation v2 channels are keyed by temporary id in the peer map
		// (see buildChannelInfo); fall back so diagnostics name the peer too.
		const peerPubkey =
			this.node.getChannelManager().getPeerForChannel(channelIdBuf) ||
			this.node
				.getChannelManager()
				.getPeerForChannel(channel.getTemporaryChannelId()) ||
			'';
		const isPeerConnected = this.listPeers().some(
			(p) => p.pubkey === peerPubkey
		);

		const scidAlias = channel.getScidAlias();
		const remoteScidAlias = channel.getRemoteScidAlias();
		const shortChannelId = channel.getShortChannelId();
		// Only SCIDs the remote will recognize (not our own alias)
		const effectiveScid = remoteScidAlias || shortChannelId;

		const issues: string[] = [];
		if (!isPeerConnected)
			issues.push(
				'PEER_DISCONNECTED: Channel partner not connected. They will mark the channel inactive.'
			);
		if (!effectiveScid)
			issues.push(
				'NO_USABLE_SCID: No SCID the remote peer recognizes. Need 6 confirmations for real SCID, or remote must send alias in channel_ready. Routing hints will be skipped — invoice will have no route.'
			);
		// Pay-during-splice (0.6.0): a channel paying through its splice is
		// fully usable — hints generate, payments flow — so it is not an issue.
		const acceptsNewThrough = channel.acceptsNewHtlcs(true);
		if (state.restoreRecencyUnproven === true)
			issues.push(
				'HELD_RESTORE: Channel was restored from a Recovery Capsule and its state has not been proven current, so it takes no new HTLCs. Routing hints will be skipped.'
			);
		if (state.fundingUnaccounted === true)
			issues.push(
				'FUNDING_UNACCOUNTED: Neither mempool nor chain can account for the funding transaction, so the channel takes no new HTLCs. Routing hints will be skipped. Existing HTLCs still settle, and the quarantine lifts by itself if the funding reappears.'
			);
		if (
			state.state !== 'NORMAL' &&
			state.preReestablishState !== 'NORMAL' &&
			!acceptsNewThrough
		) {
			issues.push(
				`NOT_NORMAL: Channel state is ${state.state} (pre-reestablish: ${
					state.preReestablishState || 'none'
				}). Routing hints require a usable channel.`
			);
		}
		if (!state.announceChannel)
			issues.push(
				'PRIVATE_CHANNEL: Channel is private (not announced). Routing hints are required for payments.'
			);
		if (state.announceChannel && !state.announcementSigsSent)
			issues.push(
				'ANNOUNCEMENT_INCOMPLETE: Channel is public but announcement_signatures not yet sent.'
			);
		if (state.announceChannel && !state.announcementSigsReceived)
			issues.push(
				'ANNOUNCEMENT_INCOMPLETE: Channel is public but announcement_signatures not yet received from peer.'
			);
		if (state.remoteBalanceMsat === 0n)
			issues.push(
				'NO_INBOUND: Remote balance is 0. You cannot receive payments on this channel.'
			);

		return {
			channelId,
			peerPubkey,
			state: state.state,
			preReestablishState: state.preReestablishState || null,
			isPeerConnected,
			announceChannel: state.announceChannel,
			announcementSigsSent: state.announcementSigsSent || false,
			announcementSigsReceived: state.announcementSigsReceived || false,
			scidAlias: scidAlias?.toString('hex') || null,
			remoteScidAlias: remoteScidAlias?.toString('hex') || null,
			shortChannelId: shortChannelId?.toString('hex') || null,
			effectiveScid: effectiveScid?.toString('hex') || null,
			// A held restore is NORMAL, so state alone said yes while the same
			// response reported HELD_RESTORE and said hints are skipped. The
			// hint is generated iff the channel will take a new HTLC, which is
			// the one predicate the hint builder itself consults (issue #469).
			willGenerateRoutingHint: !!effectiveScid && acceptsNewThrough,
			localBalanceSats: Number(state.localBalanceMsat / 1000n),
			remoteBalanceSats: Number(state.remoteBalanceMsat / 1000n),
			issues
		};
	}

	private toChannelInfo(ch: {
		channelId: Buffer;
		peerPubkey: string;
		state: string;
		localBalanceMsat: bigint;
		remoteBalanceMsat: bigint;
		fundingSatoshis: bigint;
		channelType?: Buffer | null;
		fundingTxid?: string;
		fundingOutputIndex?: number;
		shortChannelId?: string;
		feeratePerKw?: number;
		htlcCount?: number;
		pendingSpliceLocalBalanceMsat?: bigint;
		htlcUsable?: boolean;
		restoreRecencyUnproven?: boolean;
		fundingUnaccounted?: boolean;
		payThroughSplice?: boolean;
		localReserveMsat?: bigint;
		remoteReserveMsat?: bigint;
		isPrivate?: boolean;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
		cltvExpiryDelta?: number;
		htlcMinimumMsat?: bigint;
		htlcMaximumMsat?: bigint;
		closeStatus?: import('../lightning/node/types').ICloseStatus;
	}): ChannelInfo {
		// Import ChannelStateString to satisfy the narrowed type
		type CS = import('./types').ChannelStateString;
		const peerPubkey =
			ch.peerPubkey ||
			this.node.getChannelManager().getPeerForChannel(ch.channelId) ||
			'';
		const info: ChannelInfo = {
			channelId: ch.channelId.toString('hex'),
			peerPubkey,
			state: ch.state as CS,
			localBalanceSats: Number(ch.localBalanceMsat / 1000n),
			remoteBalanceSats: Number(ch.remoteBalanceMsat / 1000n),
			capacitySats: Number(ch.fundingSatoshis),
			isAnchor: isAnchorChannel(ch.channelType ?? null)
		};
		// What the connected peer's init negotiated, read rather than guessed:
		// a client deciding whether to offer splice controls has no other way
		// to know, and reconstructing feature bits client-side is exactly the
		// kind of daemon arithmetic the UI is not supposed to redo. Omitted
		// when there is no init to read (peer disconnected), which a client
		// should treat as "offer it and let the daemon answer".
		if (peerPubkey) {
			const splice = this.node.peerSupportsSplicing(peerPubkey);
			if (splice !== null) info.peerSupportsSplicing = splice;
		}
		if (ch.fundingTxid) {
			info.fundingTxid = ch.fundingTxid;
			if (ch.fundingOutputIndex !== undefined) {
				info.fundingOutputIndex = ch.fundingOutputIndex;
			}
		}
		if (ch.shortChannelId) info.shortChannelId = ch.shortChannelId;
		if (ch.feeratePerKw !== undefined) info.feeratePerKw = ch.feeratePerKw;
		if (ch.htlcCount !== undefined) info.htlcCount = ch.htlcCount;
		if (ch.pendingSpliceLocalBalanceMsat !== undefined)
			info.pendingSpliceLocalBalanceSats = Number(
				ch.pendingSpliceLocalBalanceMsat / 1000n
			);
		// The dashboard's Send gating reads these off the wire; dropping them
		// here re-parked every mid-splice channel in the UI while the daemon
		// happily paid through the window.
		if (ch.htlcUsable !== undefined) info.htlcUsable = ch.htlcUsable;
		if (ch.restoreRecencyUnproven)
			info.restoreRecencyUnproven = ch.restoreRecencyUnproven;
		if (ch.fundingUnaccounted) info.fundingUnaccounted = ch.fundingUnaccounted;
		if (ch.payThroughSplice !== undefined)
			info.payThroughSplice = ch.payThroughSplice;
		if (ch.isPrivate !== undefined) info.isPrivate = ch.isPrivate;
		if (ch.feeBaseMsat !== undefined) info.feeBaseMsat = ch.feeBaseMsat;
		if (ch.feeProportionalMillionths !== undefined)
			info.feeProportionalMillionths = ch.feeProportionalMillionths;
		if (ch.cltvExpiryDelta !== undefined)
			info.cltvExpiryDelta = ch.cltvExpiryDelta;
		if (ch.htlcMinimumMsat !== undefined)
			info.htlcMinimumMsat = ch.htlcMinimumMsat.toString();
		if (ch.htlcMaximumMsat !== undefined)
			info.htlcMaximumMsat = ch.htlcMaximumMsat.toString();
		// All fields are JSON-safe primitives; pass through untouched.
		if (ch.closeStatus) info.closeStatus = ch.closeStatus;
		return info;
	}

	// ─────────────── Invoices ───────────────

	createInvoice(
		amountSats?: number,
		description?: string,
		expirySecs?: number,
		descriptionHash?: Buffer,
		minFinalCltvExpiry?: number
	): InvoiceInfo {
		// Zero and undefined both mean "amountless invoice"; anything else has
		// to survive BigInt(), which a fractional amountSats does not (#474).
		const amountMsat =
			amountSats !== undefined && amountSats !== 0
				? BigInt(requireNonNegativeSafeInteger(amountSats, 'amountSats')) *
				  1000n
				: undefined;
		const result = this.node.createInvoice({
			amountMsat,
			description: descriptionHash ? undefined : description || '',
			descriptionHash,
			expiry: expirySecs,
			// Extra final-CLTV headroom for a receive whose settlement may fund a
			// channel on the fly (a JIT open, or an LSP splice).
			...(minFinalCltvExpiry !== undefined
				? { minFinalCltvExpiry: requireFinalCltvExpiry(minFinalCltvExpiry) }
				: {})
		});
		const info: InvoiceInfo = {
			bolt11: result.bolt11,
			paymentHash: result.paymentHash.toString('hex'),
			paymentSecret: result.paymentSecret.toString('hex'),
			amountSats: amountSats || undefined
		};
		if (expirySecs !== undefined) info.expiry = expirySecs;
		return info;
	}

	/**
	 * Wallet side of JIT receive as one call: register the intent with the LSP
	 * over the beignet custom-message protocol and return an invoice payable
	 * through a channel that does not exist yet. The LSP intercepts the HTLC on
	 * the intercept SCID in the returned hint, funds the channel, forwards, and
	 * deducts the quoted opening fee from the delivery.
	 *
	 * Needs the LSP peer connected and running the JIT receive engine. A
	 * declined, timed-out or over-priced intent throws, and no invoice is
	 * created: nothing then carries an allowance for a fee nobody agreed.
	 */
	async createJitInvoice(opts: {
		lspPubkey: string;
		amountSats?: number;
		description?: string;
		expirySecs?: number;
		/** Inbound to leave over after the receive (sat). */
		targetRemainingInboundSat?: number;
		/** Ceilings on the LSP's quote; default to the node's configured ones. */
		maxFlatFeeSat?: number;
		maxFeePpm?: number;
	}): Promise<InvoiceInfo & { flatFeeSat: number; feePpm: number }> {
		if (!/^0[23][0-9a-fA-F]{64}$/.test(opts.lspPubkey)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'lspPubkey must be a 33-byte compressed public key (66 hex chars)'
			);
		}
		const amountMsat =
			opts.amountSats !== undefined && opts.amountSats !== 0
				? BigInt(requireNonNegativeSafeInteger(opts.amountSats, 'amountSats')) *
				  1000n
				: undefined;
		const result = await this.node.createJitInvoice({
			lspPubkeyHex: opts.lspPubkey,
			amountMsat,
			description: opts.description || '',
			...(opts.expirySecs !== undefined ? { expiry: opts.expirySecs } : {}),
			targetRemainingInboundSat: BigInt(
				requireNonNegativeSafeInteger(
					opts.targetRemainingInboundSat ?? 0,
					'targetRemainingInboundSat'
				)
			),
			...(opts.maxFlatFeeSat !== undefined
				? {
						maxFlatFeeSat: BigInt(
							requireNonNegativeSafeInteger(opts.maxFlatFeeSat, 'maxFlatFeeSat')
						)
				  }
				: {}),
			...(opts.maxFeePpm !== undefined
				? {
						maxFeePpm: requireNonNegativeSafeInteger(
							opts.maxFeePpm,
							'maxFeePpm'
						)
				  }
				: {})
		});
		const info: InvoiceInfo & { flatFeeSat: number; feePpm: number } = {
			bolt11: result.bolt11,
			paymentHash: result.paymentHash.toString('hex'),
			paymentSecret: result.paymentSecret.toString('hex'),
			amountSats: opts.amountSats || undefined,
			flatFeeSat: Number(result.flatFeeSat),
			feePpm: result.feePpm
		};
		if (opts.expirySecs !== undefined) info.expiry = opts.expirySecs;
		return info;
	}

	// ───────── Third-party direct funding (issue #613) ─────────

	/**
	 * Build the payer over the node's own lane registry and start serving as a
	 * receiver. Both halves share one registry, which is what lets a node pay
	 * and be paid over the same connection.
	 */
	private async startDirectFunding(): Promise<void> {
		const registry = this.node.getDirectFundingRegistry();
		if (!registry) return;
		const payments = new DirectFundingPaymentStore({
			storage: {
				saveWalletData: (key, value): void =>
					this.getStorage().saveWalletData(key, value),
				loadWalletData: (key): string | null =>
					this.getStorage().loadWalletData(key)
			}
		});
		payments.restore();
		this.directFundingSender = new DirectFundingSender({
			wallet: directFundingWallet(
				this.wallet,
				this.getBitcoinNetwork() as import('bitcoinjs-lib').Network
			),
			registry,
			payments,
			chainHash: (): Buffer =>
				chainHashForNetwork(this.toLnNetwork(this.networkName)),
			log: (action, data): void => this.log('info', action, data)
		});
		this.directFundingSender.start();
		await this.node.startDirectFunding();
	}

	/**
	 * Merge an operator policy update in and return the whole effective config.
	 *
	 * A MERGE, never a replace: the LFBW dashboard posts `{minAmountSat}` alone
	 * and then requires `lspPubkey` to still be present in the readback, and the
	 * app's manager posts the other five without `minAmountSat`.
	 */
	configureDirectFunding(update: {
		lspPubkey?: string;
		lspHost?: string;
		lspPort?: number;
		targetInboundSat?: number;
		trusted?: boolean;
		minAmountSat?: number;
	}): DirectFundingConfigInfo {
		if (
			update.lspPubkey !== undefined &&
			!/^0[23][0-9a-fA-F]{64}$/.test(update.lspPubkey)
		) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'lspPubkey must be a 33-byte compressed public key (66 hex chars)'
			);
		}
		if (update.lspPort !== undefined) {
			if (
				!Number.isInteger(update.lspPort) ||
				update.lspPort < 1 ||
				update.lspPort > 65535
			) {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					'lspPort must be a TCP port between 1 and 65535'
				);
			}
		}
		if (update.lspHost !== undefined && update.lspHost.length === 0) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'lspHost must not be empty'
			);
		}
		this.node.setDirectFundingPolicy({
			...(update.lspPubkey !== undefined
				? { liquidityPeer: update.lspPubkey }
				: {}),
			...(update.lspHost !== undefined
				? { liquidityHost: update.lspHost }
				: {}),
			...(update.lspPort !== undefined
				? { liquidityPort: update.lspPort }
				: {}),
			...(update.trusted !== undefined
				? { allowZeroConf: update.trusted }
				: {}),
			...(update.targetInboundSat !== undefined
				? {
						targetInboundSat: requireNonNegativeSafeInteger(
							update.targetInboundSat,
							'targetInboundSat'
						)
				  }
				: {}),
			...(update.minAmountSat !== undefined
				? {
						// Clamped here rather than at the engine, because the dashboard
						// compares the value it reads back against the one it asked for.
						minAmountSat: clampDirectFundingMinimum(
							requireNonNegativeSafeInteger(update.minAmountSat, 'minAmountSat')
						)
				  }
				: {})
		});
		return this.getDirectFundingConfig();
	}

	/** The effective direct-funding policy, in the shape the app reads. */
	getDirectFundingConfig(): DirectFundingConfigInfo {
		const policy = this.node.getDirectFundingPolicy() ?? {};
		return {
			lspPubkey: policy.liquidityPeer ?? null,
			lspHost: policy.liquidityHost ?? null,
			lspPort: policy.liquidityPort ?? null,
			targetInboundSat: policy.targetInboundSat ?? 0,
			trusted: policy.allowZeroConf === true,
			minAmountSat: clampDirectFundingMinimum(policy.minAmountSat ?? 0)
		};
	}

	/**
	 * Mint a payment request: a receipt hash whose preimage stays here, and the
	 * base64url envelope a payer pays.
	 *
	 * `host` and `port` are the caller's and are passed through untouched. The
	 * dashboard sends the browser's own hostname and the app's manager sends
	 * PUBLIC_HOST, both with this wallet's listen port, and this node has no way
	 * to know which is right.
	 */
	createDirectFundingRequest(opts: {
		host?: string;
		port?: number;
		amountSats?: number;
	}): { paymentHash: string; expiresAt: number; request: string } {
		if (opts.port !== undefined) {
			if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					'port must be a TCP port between 1 and 65535'
				);
			}
		}
		const amountSats =
			opts.amountSats !== undefined && opts.amountSats !== 0
				? requireNonNegativeSafeInteger(opts.amountSats, 'amountSats')
				: undefined;
		try {
			const minted = this.node.mintDirectFundingRequest({
				...(opts.host !== undefined ? { host: opts.host } : {}),
				...(opts.port !== undefined ? { port: opts.port } : {}),
				...(amountSats !== undefined ? { amountSat: BigInt(amountSats) } : {})
			});
			return {
				paymentHash: minted.record.receiptHash,
				expiresAt: minted.expiresAt,
				request: minted.request
			};
		} catch (err) {
			// A mint that fails degrades to a plain BIP 21 URI in the app, silently,
			// so the log line is the only place the operator can see it happened.
			this.log('warn', 'direct funding request mint failed', {
				error: err instanceof Error ? err.message : String(err)
			});
			throw this.directFundingFailure(err);
		}
	}

	/**
	 * Pay a direct-funding request out of one of our coins.
	 *
	 * Rejects only BEFORE our witness leaves the device. After that it resolves
	 * with whatever is known, because the caller's fallback on a throw is a
	 * second on-chain payment of the same amount, and a late rejection would
	 * make that a double spend of the user's money rather than a recovery.
	 */
	async sendDirectFunding(opts: {
		request?: string;
		amountSats?: number;
		maxTotalFeeSat?: number;
		/** Documented alias for maxTotalFeeSat: what the LFBW app posts today. */
		feeHeadroomSats?: number;
	}): Promise<IDfSendResult> {
		const sender = this.directFundingSender;
		if (!sender) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'direct funding is not available on this node'
			);
		}
		if (!opts.request || typeof opts.request !== 'string') {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'request (the payment request from the BIP 21 URI) is required'
			);
		}
		const ceiling = opts.maxTotalFeeSat ?? opts.feeHeadroomSats;
		try {
			return await sender.send(opts.request, {
				...(opts.amountSats !== undefined && opts.amountSats !== 0
					? {
							amountSat: BigInt(
								requireNonNegativeSafeInteger(opts.amountSats, 'amountSats')
							)
					  }
					: {}),
				...(ceiling !== undefined
					? {
							maxTotalFeeSat: BigInt(
								requireNonNegativeSafeInteger(ceiling, 'maxTotalFeeSat')
							)
					  }
					: {})
			});
		} catch (err) {
			throw this.directFundingFailure(err);
		}
	}

	/** Every direct-funding payment this device has a record of. */
	listDirectFundingPayments(): IDfPaymentRecord[] {
		return this.directFundingSender?.payments() ?? [];
	}

	/**
	 * Map a coded protocol refusal onto the daemon's error vocabulary. The codes
	 * are carried through verbatim: they are what tells the app a refusal to
	 * fund apart from a transport failure, and only one of those is worth
	 * falling back on.
	 */
	private directFundingFailure(err: unknown): Error {
		if (err instanceof DirectFundingError) {
			return new BeignetError(err.code, err.message);
		}
		return err instanceof Error ? err : new Error(String(err));
	}

	/**
	 * Create a hold invoice for a caller-supplied payment hash. The preimage
	 * stays with the caller: an incoming HTLC parks (payer sees the payment as
	 * in-flight) until settleHoldInvoice(preimage) or cancelHoldInvoice(hash).
	 * Parked HTLCs are auto-cancelled by the CLTV sweeper before their expiry
	 * safety margin, so they can never ride into an on-chain timeout.
	 */
	createHoldInvoice(opts: {
		/** 32-byte payment hash, hex. sha256(preimage) held by the caller. */
		paymentHash: string;
		amountMsat?: bigint;
		amountSats?: number;
		description?: string;
		/** Invoice expiry in seconds. */
		expiry?: number;
	}): InvoiceInfo {
		if (!/^[0-9a-fA-F]{64}$/.test(opts.paymentHash)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'paymentHash must be 32 bytes hex (64 hex chars)'
			);
		}
		const amountMsat =
			opts.amountMsat ??
			(opts.amountSats !== undefined && opts.amountSats !== 0
				? BigInt(requireNonNegativeSafeInteger(opts.amountSats, 'amountSats')) *
				  1000n
				: undefined);
		const result = this.node.createInvoice({
			amountMsat,
			description: opts.description || '',
			expiry: opts.expiry,
			hold: true,
			paymentHash: Buffer.from(opts.paymentHash, 'hex')
		});
		const info: InvoiceInfo = {
			bolt11: result.bolt11,
			paymentHash: result.paymentHash.toString('hex'),
			paymentSecret: result.paymentSecret.toString('hex')
		};
		if (amountMsat !== undefined) info.amountSats = Number(amountMsat / 1000n);
		if (opts.expiry !== undefined) info.expiry = opts.expiry;
		return info;
	}

	/**
	 * Settle a hold invoice with its preimage. Validates sha256(preimage)
	 * against the parked HTLCs' payment hash and fulfills all of them (every
	 * MPP part). Throws when nothing is parked for the hash.
	 */
	settleHoldInvoice(preimage: string): { paymentHash: string } {
		if (!/^[0-9a-fA-F]{64}$/.test(preimage)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'preimage must be 32 bytes hex (64 hex chars)'
			);
		}
		const preimageBuf = Buffer.from(preimage, 'hex');
		const paymentHash = crypto
			.createHash('sha256')
			.update(preimageBuf)
			.digest();
		const settled = this.node.settleHeldHtlc(paymentHash, preimageBuf);
		if (!settled) {
			throw new BeignetError(
				BeignetErrorCode.NOT_FOUND,
				'No parked HTLCs for this preimage (invoice unknown, not yet paid, or already resolved)'
			);
		}
		return { paymentHash: paymentHash.toString('hex') };
	}

	/**
	 * Cancel a hold invoice: fails any parked HTLC back to the payer with
	 * incorrect_or_unknown_payment_details and closes the invoice to future
	 * HTLCs. Throws when the hash is not a known open hold invoice.
	 */
	cancelHoldInvoice(paymentHash: string): {
		paymentHash: string;
		htlcsFailed: number;
	} {
		if (!/^[0-9a-fA-F]{64}$/.test(paymentHash)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'paymentHash must be 32 bytes hex (64 hex chars)'
			);
		}
		const result = this.node.cancelHoldInvoice(Buffer.from(paymentHash, 'hex'));
		if (!result) {
			throw new BeignetError(
				BeignetErrorCode.NOT_FOUND,
				'No open hold invoice for this payment hash'
			);
		}
		return { paymentHash, htlcsFailed: result.htlcsFailed };
	}

	/** List hold invoices with lifecycle state and parked HTLC totals. */
	listHoldInvoices(): HoldInvoiceInfo[] {
		return this.node.listHoldInvoices().map((inv) => {
			const info: HoldInvoiceInfo = {
				paymentHash: inv.paymentHash,
				bolt11: inv.bolt11,
				state: inv.state,
				heldAmountMsat: inv.heldAmountMsat.toString(),
				htlcCount: inv.htlcCount,
				expiry: inv.expiry,
				createdAt: inv.createdAt
			};
			if (inv.amountMsat !== undefined) {
				info.amountSats = Number(inv.amountMsat / 1000n);
			}
			if (inv.description) info.description = inv.description;
			return info;
		});
	}

	decodeInvoice(bolt11: string): DecodedInvoice {
		const inv = decodeInvoiceInput(bolt11);
		const result: DecodedInvoice = {
			network: inv.network,
			timestamp: inv.timestamp,
			paymentHash: inv.paymentHash.toString('hex'),
			description: inv.description,
			expiry: inv.expiry,
			minFinalCltvExpiry: inv.minFinalCltvExpiry
		};
		if (inv.amountMsat !== undefined) {
			result.amountSats = Number(inv.amountMsat / 1000n);
		}
		if (inv.paymentSecret) {
			result.paymentSecret = inv.paymentSecret.toString('hex');
		}
		if (inv.payeeNodeKey) {
			result.payeeNodeKey = inv.payeeNodeKey.toString('hex');
		} else if (inv.recoveredPubkey) {
			result.payeeNodeKey = inv.recoveredPubkey.toString('hex');
		}
		if (inv.routingHints) {
			result.routingHints = inv.routingHints.map((hops) =>
				hops.map((h) => ({
					pubkey: h.pubkey.toString('hex'),
					shortChannelId: h.shortChannelId.toString('hex'),
					feeBaseMsat: h.feeBaseMsat,
					feeProportionalMillionths: h.feeProportionalMillionths,
					cltvExpiryDelta: h.cltvExpiryDelta
				}))
			);
		}
		// Add warnings for common routing issues
		const warnings: string[] = [];
		const isOurInvoice = result.payeeNodeKey === this.getInfo().nodeId;
		if (isOurInvoice && !result.routingHints?.length) {
			warnings.push(
				'NO_ROUTING_HINTS: Invoice has no routing hints. Payers without a direct channel in their gossip graph will not find a route.'
			);
		}
		if (isOurInvoice && this.listPeers().length === 0) {
			warnings.push(
				'NO_PEERS: No peers connected. Channel partner may mark channel as inactive and refuse to route.'
			);
		}
		if (warnings.length > 0) {
			result.warnings = warnings;
		}
		return result;
	}

	// ─────────────── Spending Limits ───────────────

	private _resetDailySpendIfNeeded(): void {
		const now = Date.now();
		if (now >= this._dailySpendResetTime) {
			// Reset at next midnight UTC
			const tomorrow = new Date();
			tomorrow.setUTCHours(24, 0, 0, 0);
			this._dailySpendResetTime = tomorrow.getTime();
			this._dailySpentSats = 0;
			this._dailySpentLightningSats = 0;
			this._dailySpentOnchainSats = 0;
		}
	}

	private _checkSpendLimit(amountSats: number): void {
		if (this._dailySpendLimitSats === undefined) return;
		this._resetDailySpendIfNeeded();
		// An async payment holds its claim past its own failure report, so the
		// sweep is what stops one that can no longer settle from pinning the
		// budget for good.
		this._expireAsyncSpendClaims();
		const effectiveSpent = this._dailySpentSats + this._pendingSpendSats;
		if (effectiveSpent + amountSats > this._dailySpendLimitSats) {
			const remaining = Math.max(0, this._dailySpendLimitSats - effectiveSpent);
			throw new BeignetError(
				'SPENDING_LIMIT_EXCEEDED',
				`Daily spend limit exceeded. Limit: ${this._dailySpendLimitSats} sats, spent: ${this._dailySpentSats} sats, remaining: ${remaining} sats, requested: ${amountSats} sats`
			);
		}
	}

	private _checkMaxPayment(amountSats: number): void {
		if (this._maxPaymentSats === undefined) return;
		if (amountSats > this._maxPaymentSats) {
			throw new BeignetError(
				'SPENDING_LIMIT_EXCEEDED',
				`Payment amount ${amountSats} sats exceeds per-payment limit of ${this._maxPaymentSats} sats`
			);
		}
	}

	private _recordSpend(
		amountSats: number,
		source: 'lightning' | 'onchain' = 'lightning'
	): void {
		if (this._dailySpendLimitSats === undefined) return;
		// Before the counters are touched, not only on the check/read paths: a
		// payment submitted yesterday can settle after midnight UTC, and adding
		// it to the expired day's total means the next _resetDailySpendIfNeeded
		// (whichever of a check or a read happens to run first) erases it. That
		// made a read-only getDailySpendInfo decide whether the spend counted.
		this._resetDailySpendIfNeeded();
		this._dailySpentSats += amountSats;
		if (source === 'onchain') {
			this._dailySpentOnchainSats += amountSats;
		} else {
			this._dailySpentLightningSats += amountSats;
		}
	}

	/**
	 * Reserves the budget one async attempt can still spend, and returns the
	 * claim so its caller can drop that exact attempt again. Appended rather
	 * than replacing what the hash already holds: see _asyncSpendClaims.
	 *
	 * Nothing is claimed when no daily limit is configured. _pendingSpendSats
	 * is then read by nobody and _recordSpend does nothing, so a claim could
	 * only grow the ledger — and eventually refuse submissions — on behalf of
	 * accounting that does not exist.
	 */
	private _openAsyncSpendClaim(
		paymentHashHex: string,
		amountSats: number
	): AsyncSpendClaim | undefined {
		if (this._dailySpendLimitSats === undefined) return undefined;
		this._expireAsyncSpendClaims();
		if (
			this._pruneAsyncSpendClaims(MAX_ASYNC_SPEND_CLAIMS - 1) >=
			MAX_ASYNC_SPEND_CLAIMS
		) {
			this.log('warn', 'Async spend claim ledger full; refusing the payment', {
				paymentHash: paymentHashHex,
				reservedClaims: MAX_ASYNC_SPEND_CLAIMS
			});
			throw new BeignetError(
				'SPENDING_LIMIT_EXCEEDED',
				`Too many unsettled async payments: ${MAX_ASYNC_SPEND_CLAIMS} still hold daily budget. Wait for them to settle or to time out.`
			);
		}
		const claim: AsyncSpendClaim = {
			sats: amountSats,
			expiresAt: Date.now() + ASYNC_SPEND_CLAIM_TTL_MS,
			reserved: true
		};
		const claims = this._asyncSpendClaims.get(paymentHashHex);
		if (claims) claims.push(claim);
		else this._asyncSpendClaims.set(paymentHashHex, [claim]);
		this._pendingSpendSats += amountSats;
		return claim;
	}

	/**
	 * Forgets one attempt's claim entirely, for a submission the engine threw
	 * on: no payment record was created and no HTLC left the node, so there is
	 * nothing left that could ever settle under this claim. Matched by
	 * identity, so it never takes another attempt's claim, and a no-op once a
	 * synchronous settlement has already charged this one.
	 */
	private _closeAsyncSpendClaim(
		paymentHashHex: string,
		claim: AsyncSpendClaim
	): void {
		const claims = this._asyncSpendClaims.get(paymentHashHex);
		if (!claims) return;
		const index = claims.indexOf(claim);
		if (index === -1) return;
		claims.splice(index, 1);
		if (claims.length === 0) this._asyncSpendClaims.delete(paymentHashHex);
		this._releaseAsyncSpendClaim(claim);
	}

	/**
	 * Gives one claim's reservation back while keeping its record. For a claim
	 * whose window has passed, and for one the engine reported dispatching
	 * nothing for: neither should go on pinning daily budget, and neither is
	 * proof that no HTLC behind it will ever settle.
	 */
	private _releaseAsyncSpendClaim(claim: AsyncSpendClaim): void {
		if (!claim.reserved) return;
		claim.reserved = false;
		this._pendingSpendSats -= claim.sats;
	}

	/**
	 * Charges one async attempt against the daily budget when a payment
	 * settles. Exactly one claim per settlement: a hash can carry several live
	 * attempts, each able to settle on its own, and a repeat terminal event for
	 * a hash with nothing left to charge is a no-op.
	 *
	 * A no-op too while a blocking caller owns the hash, since payInvoice's own
	 * listener records that settlement itself.
	 */
	private _chargeAsyncSpendClaim(paymentHashHex: string): void {
		if (this._blockingPaymentHashes.has(paymentHashHex)) return;
		this._expireAsyncSpendClaims();
		const claims = this._asyncSpendClaims.get(paymentHashHex);
		if (!claims || claims.length === 0) return;
		// The oldest claim still holding budget, so a settlement frees a
		// reservation wherever there is one to free. Failing that the oldest
		// record: a settlement whose reservation lapsed first still spent the
		// money, and the day it lands on is the day that has to carry it.
		const reserved = claims.findIndex((entry) => entry.reserved);
		const [claim] = claims.splice(reserved === -1 ? 0 : reserved, 1);
		if (claims.length === 0) this._asyncSpendClaims.delete(paymentHashHex);
		// Released before the spend is recorded, so a concurrent
		// _checkSpendLimit never sees the same sats counted twice.
		this._releaseAsyncSpendClaim(claim);
		this._recordSpend(claim.sats);
	}

	/**
	 * Marks a hash whose spend accounting a blocking send owns, for as long as
	 * that send's own listener is installed. Counted, so the first of two
	 * overlapping calls to finish does not unmark the hash under the second.
	 */
	private _acquireBlockingPayment(paymentHashHex: string): void {
		this._blockingPaymentHashes.set(
			paymentHashHex,
			(this._blockingPaymentHashes.get(paymentHashHex) ?? 0) + 1
		);
	}

	private _releaseBlockingPayment(paymentHashHex: string): void {
		const held = this._blockingPaymentHashes.get(paymentHashHex);
		if (held === undefined) return;
		if (held > 1) this._blockingPaymentHashes.set(paymentHashHex, held - 1);
		else this._blockingPaymentHashes.delete(paymentHashHex);
	}

	/**
	 * Gives back the reservation of every claim whose window has passed. Called
	 * wherever the ledger is read or written, so the accounting needs no timer
	 * of its own. The records stay: see _releaseAsyncSpendClaim.
	 */
	private _expireAsyncSpendClaims(): void {
		const now = Date.now();
		for (const claims of this._asyncSpendClaims.values()) {
			for (const claim of claims) {
				if (claim.reserved && claim.expiresAt <= now) {
					this._releaseAsyncSpendClaim(claim);
				}
			}
		}
	}

	private _countAsyncSpendClaims(): number {
		let total = 0;
		for (const claims of this._asyncSpendClaims.values())
			total += claims.length;
		return total;
	}

	/**
	 * Trims the ledger to `target` claims by forgetting the oldest records that
	 * no longer reserve anything, and returns what it could get the count down
	 * to. All such a record can still do is charge a late settlement, and the
	 * newer ones are the likelier to see one.
	 *
	 * Reserved claims are never dropped: that would release budget an
	 * outstanding HTLC can still spend. When only those are left the count
	 * stays above the target and the caller refuses the submission instead.
	 */
	private _pruneAsyncSpendClaims(target: number): number {
		let count = this._countAsyncSpendClaims();
		if (count <= target) return count;
		// Map iteration is insertion-ordered, so this walks the hashes oldest
		// first, and each hash's own claims oldest first within it.
		for (const [paymentHashHex, claims] of this._asyncSpendClaims) {
			for (let i = 0; i < claims.length && count > target; ) {
				if (claims[i].reserved) {
					i++;
					continue;
				}
				claims.splice(i, 1);
				count--;
			}
			if (claims.length === 0) this._asyncSpendClaims.delete(paymentHashHex);
			if (count <= target) break;
		}
		return count;
	}

	/**
	 * Returns the on-chain amount+fee an external send will subtract from the
	 * daily budget, computed from the transaction the wallet just built.
	 * FAIL CLOSED: when a limit is configured and the built fee cannot be
	 * read as a finite non-negative number, the send is rejected rather than
	 * checked against an understated total.
	 */
	private _builtOnchainTotalSats(amountSats: number): number {
		const feeSats = this.wallet.transaction?.data?.fee;
		if (!Number.isFinite(feeSats) || feeSats < 0) {
			if (this._dailySpendLimitSats !== undefined) {
				throw new BeignetError(
					'SPENDING_LIMIT_EXCEEDED',
					'Unable to determine the transaction fee for the daily spend limit check; refusing to send'
				);
			}
			return amountSats;
		}
		return amountSats + feeSats;
	}

	getDailySpendInfo(): {
		limitSats: number | null;
		spentSats: number;
		remainingSats: number;
		resetsAt: number;
		totalSats: number;
		lightningSats: number;
		onchainSats: number;
	} {
		this._resetDailySpendIfNeeded();
		const limit = this._dailySpendLimitSats ?? null;
		return {
			// Back-compat fields (spentSats == totalSats):
			limitSats: limit,
			spentSats: this._dailySpentSats,
			remainingSats:
				limit !== null ? Math.max(0, limit - this._dailySpentSats) : Infinity,
			resetsAt: this._dailySpendResetTime,
			// Breakdown: the limit is a single combined LN + onchain budget.
			totalSats: this._dailySpentSats,
			lightningSats: this._dailySpentLightningSats,
			onchainSats: this._dailySpentOnchainSats
		};
	}

	// ─────────────── Drain Mode ───────────────

	setDraining(enabled: boolean): void {
		this._draining = enabled;
	}

	isDraining(): boolean {
		return this._draining;
	}

	hasPendingPayments(): boolean {
		// A restore-pending daemon has no node and therefore no payments; the
		// stop route's drain poll must not crash on it.
		if (this._restorePending) return false;
		const payments = this.node.listPayments();
		return payments.some((p) => p.status === 'PENDING');
	}

	private _checkDraining(): void {
		if (this._draining) {
			throw new BeignetError(
				'SERVICE_DRAINING',
				'Node is draining — no new payments accepted'
			);
		}
	}

	// ─────────────── Payment Validation ───────────────

	/**
	 * Pre-flight validation: checks whether a payment is likely to succeed.
	 * Combines invoice decoding, amount limits, spending limits, channel capacity,
	 * invoice expiry, and route availability into a single structured response.
	 * Never throws — always returns a PaymentValidation result.
	 */
	validatePayment(bolt11: string, amountSats?: number): PaymentValidation {
		const checks: PaymentValidationCheck[] = [];
		let decoded: ReturnType<typeof decodeInvoice> | null = null;
		let decodedInfo: DecodedInvoice | undefined;

		// 1. Decode invoice
		try {
			decoded = decodeInvoice(bolt11);
			decodedInfo = this.decodeInvoice(bolt11);
			checks.push({
				name: 'INVOICE_DECODE',
				status: 'OK',
				message: 'Invoice decoded successfully'
			});
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : 'Unknown decode error';
			checks.push({
				name: 'INVOICE_DECODE',
				status: 'FAIL',
				message: `Invalid invoice: ${msg}`
			});
			return this._buildValidationResult(checks, decodedInfo);
		}

		// The amount payInvoice would admit and the engine would pay, so the
		// preview cannot report limits for an amount nobody will spend (#528).
		const effectiveAmountSats =
			decoded.amountMsat !== undefined
				? spendLimitSats(decoded.amountMsat)
				: amountSats;

		// 2. Amount specified
		if (effectiveAmountSats === undefined || effectiveAmountSats <= 0) {
			checks.push({
				name: 'AMOUNT',
				status: 'FAIL',
				message:
					'No amount specified and invoice has no amount — provide amountSats'
			});
		} else {
			checks.push({
				name: 'AMOUNT',
				status: 'OK',
				message: `Amount: ${effectiveAmountSats} sats`
			});
		}

		// 3. Invoice expiry
		if (decoded.timestamp !== undefined && decoded.expiry !== undefined) {
			const expiresAt = Number(decoded.timestamp) + Number(decoded.expiry);
			const nowSecs = Math.floor(Date.now() / 1000);
			if (nowSecs >= expiresAt) {
				checks.push({
					name: 'EXPIRY',
					status: 'FAIL',
					message: 'Invoice has expired'
				});
			} else {
				const remainingSecs = expiresAt - nowSecs;
				if (remainingSecs < 120) {
					checks.push({
						name: 'EXPIRY',
						status: 'WARN',
						message: `Invoice expires in ${remainingSecs}s — may timeout during payment`
					});
				} else {
					checks.push({
						name: 'EXPIRY',
						status: 'OK',
						message: `Invoice valid for ${remainingSecs}s`
					});
				}
			}
		} else {
			checks.push({ name: 'EXPIRY', status: 'OK', message: 'No expiry set' });
		}

		if (effectiveAmountSats !== undefined && effectiveAmountSats > 0) {
			// 4. Per-payment limit
			if (
				this._maxPaymentSats !== undefined &&
				effectiveAmountSats > this._maxPaymentSats
			) {
				checks.push({
					name: 'MAX_PAYMENT',
					status: 'FAIL',
					message: `Amount ${effectiveAmountSats} sats exceeds per-payment limit of ${this._maxPaymentSats} sats`
				});
			} else if (this._maxPaymentSats !== undefined) {
				checks.push({
					name: 'MAX_PAYMENT',
					status: 'OK',
					message: `Within per-payment limit (${this._maxPaymentSats} sats)`
				});
			}

			// 5. Daily spending limit
			if (this._dailySpendLimitSats !== undefined) {
				this._resetDailySpendIfNeeded();
				// Same sweep _checkSpendLimit runs, so the preview reports the
				// budget the real check would apply.
				this._expireAsyncSpendClaims();
				const effectiveSpent = this._dailySpentSats + this._pendingSpendSats;
				const remaining = Math.max(
					0,
					this._dailySpendLimitSats - effectiveSpent
				);
				if (effectiveAmountSats > remaining) {
					checks.push({
						name: 'DAILY_LIMIT',
						status: 'FAIL',
						message: `Amount ${effectiveAmountSats} sats exceeds daily remaining of ${remaining} sats`
					});
				} else {
					checks.push({
						name: 'DAILY_LIMIT',
						status: 'OK',
						message: `Within daily limit (${remaining} sats remaining)`
					});
				}
			}

			// 6. Channel capacity
			const capacity = this.canSend(effectiveAmountSats);
			if (!capacity.canSend) {
				checks.push({
					name: 'CAPACITY',
					status: 'FAIL',
					message: `Insufficient outbound capacity. Available: ${capacity.availableSats} sats, needed: ${effectiveAmountSats} sats`
				});
			} else {
				checks.push({
					name: 'CAPACITY',
					status: 'OK',
					message: `Sufficient capacity (${capacity.availableSats} sats available)`
				});
			}

			// 7. Route availability
			const estimate = this.estimatePayment(bolt11, amountSats);
			if (estimate === null) {
				checks.push({
					name: 'ROUTE',
					status: 'WARN',
					message: 'No route found — payment may fail or require MPP'
				});
			} else if (estimate.successProbabilityPct < 50) {
				checks.push({
					name: 'ROUTE',
					status: 'WARN',
					message: `Low success probability: ${estimate.successProbabilityPct}% (estimated fee: ${estimate.estimatedFeeSats} sats, ${estimate.hopCount} hops)`
				});
			} else {
				checks.push({
					name: 'ROUTE',
					status: 'OK',
					message: `Route found: ${estimate.successProbabilityPct}% probability, ~${estimate.estimatedFeeSats} sats fee, ${estimate.hopCount} hops`
				});
			}
		}

		// 8. Draining check
		if (this._draining) {
			checks.push({
				name: 'SERVICE_STATE',
				status: 'FAIL',
				message: 'Node is draining — no new payments accepted'
			});
		}

		// 9. Active channels check
		const readyChannels = this.getReadyChannels();
		if (readyChannels.length === 0) {
			checks.push({
				name: 'CHANNELS',
				status: 'FAIL',
				message: 'No active channels — cannot send payments'
			});
		}

		return this._buildValidationResult(checks, decodedInfo);
	}

	private _buildValidationResult(
		checks: PaymentValidationCheck[],
		invoice?: DecodedInvoice
	): PaymentValidation {
		const hasFail = checks.some((c) => c.status === 'FAIL');
		const hasWarn = checks.some((c) => c.status === 'WARN');
		const status: PaymentValidationStatus = hasFail
			? 'FAIL'
			: hasWarn
			? 'WARN'
			: 'OK';

		const failMessages = checks
			.filter((c) => c.status === 'FAIL')
			.map((c) => c.message);
		const warnMessages = checks
			.filter((c) => c.status === 'WARN')
			.map((c) => c.message);

		let summary: string;
		if (hasFail) {
			summary = `Payment blocked: ${failMessages.join('; ')}`;
		} else if (hasWarn) {
			summary = `Payment may succeed with warnings: ${warnMessages.join('; ')}`;
		} else {
			summary = 'All checks passed — payment is likely to succeed';
		}

		return { status, summary, checks, invoice };
	}

	// ─────────────── Payments ───────────────

	async payInvoice(
		bolt11: string,
		timeoutMs = 60_000,
		maxFeeSats?: number,
		amountSats?: number,
		metadata?: Record<string, string>
	): Promise<PaymentInfo> {
		this._checkDraining();
		// Decode to get paymentHash for event matching
		const decoded = decodeInvoiceInput(bolt11);
		const paymentHashHex = decoded.paymentHash.toString('hex');

		// Per-payment and daily spending limit checks, applied to what the engine
		// will actually pay rather than to what the caller asked for (#528).
		const spendAmountSats = paymentSpendSats(decoded.amountMsat, amountSats);
		// Converted BEFORE the spend accounting below, not after it. Every
		// decrement of _pendingSpendSats lives inside the Promise executor
		// further down, which a RangeError out of BigInt() never reaches: the
		// counter would stay raised for the life of the process, and once it
		// passed dailySpendLimit _checkSpendLimit would refuse every real
		// payment until the daemon restarted (issue #474).
		const maxFeeMsat =
			maxFeeSats !== undefined
				? BigInt(requireNonNegativeSafeInteger(maxFeeSats, 'maxFeeSats')) *
				  1000n
				: undefined;
		const amountMsat =
			amountSats !== undefined
				? BigInt(requireNonNegativeSafeInteger(amountSats, 'amountSats')) *
				  1000n
				: undefined;

		if (spendAmountSats > 0) {
			this._checkMaxPayment(spendAmountSats);
			this._checkSpendLimit(spendAmountSats);
			this._pendingSpendSats += spendAmountSats;
		}

		// This call owns the hash's spend accounting for as long as its own
		// listener is installed: the forwarding handler in create() would
		// otherwise charge an async claim for the settlement the listener
		// records, counting one payment twice.
		//
		// The claims a fire-and-forget attempt on this hash already holds stay
		// where they are, reservations and all. This attempt adds an HTLC to
		// the ones already out there rather than replacing them, and the engine
		// reports at most one of them settling (it emits nothing further for a
		// hash it has marked completed), so the rest have to go on holding
		// budget on their own account.
		this._acquireBlockingPayment(paymentHashHex);
		let blockingReleased = false;
		const releaseBlockingPayment = (): void => {
			if (blockingReleased) return;
			blockingReleased = true;
			this._releaseBlockingPayment(paymentHashHex);
		};

		// One release shared by every exit, and idempotent, because more than
		// one can run for a single payment (a timeout followed by a late
		// payment:failed). The reservation is deliberately held for the whole
		// in-flight window: it is what stops two concurrent payments both
		// passing the daily limit before either records a spend, so this must
		// never become a `finally` around the synchronous body.
		let released = false;
		const releaseReservation = (): void => {
			if (spendAmountSats <= 0 || released) return;
			released = true;
			this._pendingSpendSats -= spendAmountSats;
		};

		// Store metadata on the payment if provided. Guarded, because nothing
		// between the reservation above and the executor below may strand it.
		try {
			if (metadata) {
				this.node.setPaymentMetadata(decoded.paymentHash, metadata);
			}
		} catch (err: unknown) {
			releaseReservation();
			releaseBlockingPayment();
			throw err;
		}

		return new Promise<PaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				releaseReservation();
				// Clean up the ghost payment to free channel capacity
				this.node.failPayment(decoded.paymentHash);
				reject(
					new BeignetError(
						'PAYMENT_TIMEOUT',
						`Payment timed out after ${timeoutMs}ms`
					)
				);
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.node.removeListener('payment:sent', onSent);
				this.node.removeListener('payment:failed', onFailed);
				// Safe here rather than after the accounting below: the handler
				// in create() is registered first, so it has already seen this
				// same event and declined to charge for it.
				releaseBlockingPayment();
			};

			const onSent = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					// Released before the spend is recorded, so a concurrent
					// _checkSpendLimit never sees the same sats counted twice.
					releaseReservation();
					if (spendAmountSats > 0) this._recordSpend(spendAmountSats);
					resolve(this.toPaymentInfo(info));
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					releaseReservation();
					const failDesc =
						info.failureCode !== undefined
							? describeFailureCode(info.failureCode)
							: 'unknown';
					reject(
						new BeignetError(
							'PAYMENT_FAILED',
							`Payment failed: ${failDesc}`,
							info.failureCode
						)
					);
				}
			};

			this.node.on('payment:sent', onSent);
			this.node.on('payment:failed', onFailed);

			try {
				this.node.sendPayment(bolt11, undefined, maxFeeMsat, amountMsat);
			} catch (err: unknown) {
				cleanup();
				// A payment that never started holds no capacity. Without this
				// the reservation outlived every refused send (no route, a
				// duplicate, a peer that is gone) and ratcheted the counter up
				// until the daily limit refused real payments (issue #474).
				releaseReservation();
				const msg = err instanceof Error ? err.message : String(err);
				// Use typed error code if available, fall back to string matching
				let code = 'PAYMENT_FAILED';
				if (err instanceof Error && 'code' in err) {
					const lpErr = err as { code: string };
					const codeMap: Record<string, string> = {
						NO_ROUTE: 'NO_ROUTE',
						DUPLICATE_PAYMENT: 'DUPLICATE_PAYMENT',
						NO_CHANNEL_TO_HOP: 'PEER_NOT_CONNECTED',
						FEE_EXCEEDS_MAX: 'PAYMENT_FAILED',
						MISSING_AMOUNT: 'INVALID_PARAMS',
						INVALID_INVOICE: 'INVALID_PARAMS',
						INVOICE_EXPIRED: 'INVOICE_EXPIRED'
					};
					code = codeMap[lpErr.code] || 'PAYMENT_FAILED';
				} else {
					if (msg.includes('No route found')) code = 'NO_ROUTE';
					else if (msg.includes('already in flight'))
						code = 'DUPLICATE_PAYMENT';
					else if (
						msg.includes('No channel to first hop') ||
						msg.includes('Peer not found')
					)
						code = 'PEER_NOT_CONNECTED';
				}
				reject(new BeignetError(code, msg));
			}
		});
	}

	async payInvoiceSafe(
		bolt11: string,
		timeoutMs = 60_000,
		maxFeeSats?: number,
		amountSats?: number,
		metadata?: Record<string, string>
	): Promise<PaymentInfo> {
		try {
			return await this.payInvoice(
				bolt11,
				timeoutMs,
				maxFeeSats,
				amountSats,
				metadata
			);
		} catch (err: unknown) {
			// Extract payment hash if possible (bolt11 itself may be invalid)
			let hashHex = 'unknown';
			let amount = 0;
			try {
				const decoded = decodeInvoice(bolt11);
				hashHex = decoded.paymentHash.toString('hex');
				amount =
					decoded.amountMsat !== undefined
						? Number(decoded.amountMsat / 1000n)
						: 0;
			} catch {
				/* bolt11 is malformed — use defaults */
			}

			// Return persisted record if available
			if (hashHex !== 'unknown') {
				const existing = this.getPayment(hashHex);
				if (existing) return existing;
			}

			const message = err instanceof Error ? err.message : String(err);
			const code = err instanceof BeignetError ? err.code : 'PAYMENT_FAILED';
			return {
				paymentHash: hashHex,
				amountSats: amount,
				status: 'FAILED',
				direction: 'OUTGOING',
				failureDescription: `[${code}] ${message}`,
				createdAt: Date.now()
			};
		}
	}

	async payInvoiceWithRetry(
		bolt11: string,
		opts: RetryPaymentOptions = {}
	): Promise<RetryPaymentResult> {
		const maxRetries = opts.maxRetries ?? 3;
		const backoffMs = opts.backoffMs ?? 2000;
		const decoded = decodeInvoiceInput(bolt11);
		const paymentHashHex = decoded.paymentHash.toString('hex');
		let lastError: BeignetError | undefined;

		for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
			try {
				const result = await this.payInvoice(
					bolt11,
					60_000,
					opts.maxFeeSats,
					opts.amountSats,
					opts.metadata
				);
				return { ...result, attempts: attempt };
			} catch (err: unknown) {
				if (!(err instanceof BeignetError)) throw err;
				lastError = err;

				// Don't retry permanent failures
				if (!isRetryableError(err)) {
					const pi = this.getPayment(paymentHashHex);
					if (pi) return { ...pi, attempts: attempt };
					return {
						paymentHash: paymentHashHex,
						amountSats:
							decoded.amountMsat !== undefined
								? Number(decoded.amountMsat / 1000n)
								: 0,
						status: 'FAILED',
						direction: 'OUTGOING',
						failureDescription: err.message,
						createdAt: Date.now(),
						attempts: attempt
					};
				}

				// If we've exhausted retries, break
				if (attempt > maxRetries) break;

				// Calculate backoff delay
				const delayMs = backoffMs * Math.pow(2, attempt - 1);
				this.log('info', `Payment retry ${attempt}/${maxRetries}`, {
					paymentHash: paymentHashHex,
					nextRetryMs: delayMs,
					error: err.message
				});
				this.emit('payment:retry', {
					paymentHash: paymentHashHex,
					attempt,
					maxRetries,
					nextRetryMs: delayMs,
					error: err.message
				});

				// Wait for backoff
				await new Promise((resolve) => setTimeout(resolve, delayMs));

				// Check drain mode before retrying
				if (this._draining) {
					const pi = this.getPayment(paymentHashHex);
					if (pi) return { ...pi, attempts: attempt };
					return {
						paymentHash: paymentHashHex,
						amountSats:
							decoded.amountMsat !== undefined
								? Number(decoded.amountMsat / 1000n)
								: 0,
						status: 'FAILED',
						direction: 'OUTGOING',
						failureDescription: 'Node is draining — retry aborted',
						createdAt: Date.now(),
						attempts: attempt
					};
				}

				// Pre-flight check: can we still send?
				if (decoded.amountMsat !== undefined) {
					const amountSats = Number(decoded.amountMsat / 1000n);
					const check = this.canSend(amountSats);
					if (!check.canSend) {
						const pi = this.getPayment(paymentHashHex);
						if (pi) return { ...pi, attempts: attempt };
						return {
							paymentHash: paymentHashHex,
							amountSats,
							status: 'FAILED',
							direction: 'OUTGOING',
							failureDescription: 'Insufficient outbound liquidity for retry',
							createdAt: Date.now(),
							attempts: attempt
						};
					}
				}
			}
		}

		// All retries exhausted
		const pi = this.getPayment(paymentHashHex);
		if (pi) return { ...pi, attempts: maxRetries + 1 };
		return {
			paymentHash: paymentHashHex,
			amountSats:
				decoded.amountMsat !== undefined
					? Number(decoded.amountMsat / 1000n)
					: 0,
			status: 'FAILED',
			direction: 'OUTGOING',
			failureDescription: lastError?.message ?? 'All retries exhausted',
			createdAt: Date.now(),
			attempts: maxRetries + 1
		};
	}

	sendPaymentAsync(
		bolt11: string,
		maxFeeSats?: number,
		amountSats?: number,
		metadata?: Record<string, string>
	): { paymentHash: string; status: 'PENDING' | 'FAILED' } {
		// Returning before the payment settles is the point of this method, not
		// a licence to skip admission: drain mode, the per-payment limit and the
		// daily limit all apply, and the claim they raise is charged by the
		// forwarding payment:sent handler in create() rather than by a listener
		// of our own (issue #526).
		this._checkDraining();
		const decoded = decodeInvoiceInput(bolt11);
		const paymentHashHex = decoded.paymentHash.toString('hex');
		// Admitted on what the engine will pay, not on the caller's override.
		const spendAmountSats = paymentSpendSats(decoded.amountMsat, amountSats);
		// Converted BEFORE the spend accounting below, for the reason
		// payInvoice's copy documents: a RangeError out of BigInt() must not
		// leave the reservation raised for the life of the process (issue #474).
		const maxFeeMsat =
			maxFeeSats !== undefined
				? BigInt(requireNonNegativeSafeInteger(maxFeeSats, 'maxFeeSats')) *
				  1000n
				: undefined;
		const amountMsat =
			amountSats !== undefined
				? BigInt(requireNonNegativeSafeInteger(amountSats, 'amountSats')) *
				  1000n
				: undefined;

		// This attempt's own claim, opened BEFORE the send both because a later
		// submission must not pass the daily limit on capacity this one already
		// holds and because sendPayment can emit a terminal event synchronously
		// (an expired invoice fails inside the call) that the handler in
		// create() has to find a claim for. A resubmission of a hash whose
		// earlier attempt may still be live gets a claim of its own rather than
		// replacing that one: either attempt can be the one that settles.
		let claim: AsyncSpendClaim | undefined;
		if (spendAmountSats > 0) {
			this._checkMaxPayment(spendAmountSats);
			this._checkSpendLimit(spendAmountSats);
			claim = this._openAsyncSpendClaim(paymentHashHex, spendAmountSats);
		}

		let result: IPaymentInfo;
		try {
			if (metadata) {
				this.node.setPaymentMetadata(decoded.paymentHash, metadata);
			}
			result = this.node.sendPayment(bolt11, undefined, maxFeeMsat, amountMsat);
		} catch (err: unknown) {
			// A payment that never started holds no capacity. Matched by
			// identity, so a refused duplicate frees only this submission's
			// claim and leaves the in-flight attempt's alone.
			if (claim) this._closeAsyncSpendClaim(paymentHashHex, claim);
			throw err;
		}
		// Not every refusal throws. An expired invoice, a locally refused
		// addHtlc and an undispatchable MPP part all RETURN a failed payment,
		// having emitted payment:failed inside the call above — and a failure
		// report deliberately releases nothing (see _asyncSpendClaims), so
		// without this a caller burns a day's allowance for 24 hours on
		// payments that were never sent. The reservation goes; the record
		// stays, because the MPP case leaves earlier parts out there and one of
		// them landing still has to be charged.
		if (claim && result.status === 'FAILED') {
			this._releaseAsyncSpendClaim(claim);
		}
		return {
			paymentHash: paymentHashHex,
			// What the engine actually reported. Answering PENDING for a
			// payment it has already failed sends a caller off to poll a record
			// that will never change.
			status: result.status === 'FAILED' ? 'FAILED' : 'PENDING'
		};
	}

	/**
	 * Send a keysend (spontaneous) payment — blocks until settled or timeout.
	 */
	async sendKeysend(
		pubkey: string,
		amountSats: number,
		timeoutMs = 60_000,
		maxFeeSats?: number,
		metadata?: Record<string, string>
	): Promise<PaymentInfo> {
		this._checkDraining();
		// Guarded before the accounting for the same reason payInvoice is: the
		// decrements all live in the callbacks below, so a RangeError here used
		// to leave _pendingSpendSats permanently raised (issue #474).
		const amountMsat =
			BigInt(requireNonNegativeSafeInteger(amountSats, 'amountSats')) * 1000n;
		const maxFeeMsat =
			maxFeeSats !== undefined
				? BigInt(requireNonNegativeSafeInteger(maxFeeSats, 'maxFeeSats')) *
				  1000n
				: undefined;
		this._checkMaxPayment(amountSats);
		this._checkSpendLimit(amountSats);
		this._pendingSpendSats += amountSats;
		// Idempotent, and shared by every exit, for the reason payInvoice's
		// copy documents: the reservation is held for the whole in-flight
		// window, and a keysend that never started holds no capacity.
		let released = false;
		const releaseReservation = (): void => {
			if (released) return;
			released = true;
			this._pendingSpendSats -= amountSats;
		};
		const destination = Buffer.from(pubkey, 'hex');

		let result: IPaymentInfo;
		try {
			result = this.node.sendKeysend({
				destination,
				amountMsat,
				maxFeeMsat,
				metadata
			});
		} catch (err: unknown) {
			releaseReservation();
			throw err;
		}
		const paymentHashHex = result.paymentHash.toString('hex');

		// If already settled synchronously
		if (result.status !== 'PENDING') {
			releaseReservation();
			if (result.status === 'COMPLETED') this._recordSpend(amountSats);
			return this.toPaymentInfo(result);
		}

		return new Promise<PaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				releaseReservation();
				this.node.failPayment(result.paymentHash);
				reject(
					new BeignetError(
						'PAYMENT_TIMEOUT',
						`Keysend timed out after ${timeoutMs}ms`
					)
				);
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.node.removeListener('payment:sent', onSent);
				this.node.removeListener('payment:failed', onFailed);
			};

			const onSent = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					releaseReservation();
					this._recordSpend(amountSats);
					resolve(this.toPaymentInfo(info));
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					releaseReservation();
					const failDesc =
						info.failureCode !== undefined
							? describeFailureCode(info.failureCode)
							: 'unknown';
					reject(
						new BeignetError(
							'PAYMENT_FAILED',
							`Keysend failed: ${failDesc}`,
							info.failureCode
						)
					);
				}
			};

			this.node.on('payment:sent', onSent);
			this.node.on('payment:failed', onFailed);
		});
	}

	/**
	 * Send a keysend payment — never throws, always returns a PaymentInfo.
	 */
	async sendKeysendSafe(
		pubkey: string,
		amountSats: number,
		timeoutMs = 60_000,
		maxFeeSats?: number,
		metadata?: Record<string, string>
	): Promise<PaymentInfo> {
		try {
			return await this.sendKeysend(
				pubkey,
				amountSats,
				timeoutMs,
				maxFeeSats,
				metadata
			);
		} catch (err: unknown) {
			const message = err instanceof Error ? err.message : String(err);
			const code = err instanceof BeignetError ? err.code : 'PAYMENT_FAILED';
			return {
				paymentHash: 'unknown',
				amountSats,
				status: 'FAILED',
				direction: 'OUTGOING',
				failureDescription: `[${code}] ${message}`,
				createdAt: Date.now()
			};
		}
	}

	listPayments(filter?: PaymentFilter): PaymentInfo[] {
		let payments = this.node.listPayments().map((p) => this.toPaymentInfo(p));

		// Sort by createdAt descending (newest first)
		payments.sort((a, b) => b.createdAt - a.createdAt);

		if (filter) {
			if (filter.status) {
				payments = payments.filter((p) => p.status === filter.status);
			}
			if (filter.direction) {
				payments = payments.filter((p) => p.direction === filter.direction);
			}
			if (filter.since !== undefined) {
				payments = payments.filter((p) => p.createdAt >= filter.since!);
			}
			if (filter.metadataKey !== undefined) {
				if (filter.metadataValue !== undefined) {
					payments = payments.filter(
						(p) => p.metadata?.[filter.metadataKey!] === filter.metadataValue
					);
				} else {
					payments = payments.filter(
						(p) => p.metadata !== undefined && filter.metadataKey! in p.metadata
					);
				}
			}
			if (filter.offset !== undefined && filter.offset > 0) {
				payments = payments.slice(filter.offset);
			}
			if (filter.limit !== undefined && filter.limit > 0) {
				payments = payments.slice(0, filter.limit);
			}
		}

		return payments;
	}

	getPayment(paymentHash: string): PaymentInfo | null {
		const p = this.node.getPayment(Buffer.from(paymentHash, 'hex'));
		if (!p) return null;
		return this.toPaymentInfo(p);
	}

	/** Settled forwards, newest first. Msat values as strings (JSON-safe). */
	listForwards(filter?: ForwardsFilter): ForwardingEventInfo[] {
		return this.node.listForwards(filter).map((f) => ({
			id: f.id,
			settledAt: f.settledAt,
			inChannelId: f.inChannelId,
			outChannelId: f.outChannelId,
			inScid: f.inScid,
			outScid: f.outScid,
			amountInMsat: f.amountInMsat.toString(),
			amountOutMsat: f.amountOutMsat.toString(),
			feeMsat: f.feeMsat.toString()
		}));
	}

	/** Forwarding totals: count, volume forwarded out, fees earned. */
	getForwardingSummary(since?: number): ForwardingSummaryInfo {
		const summary = this.node.getForwardingSummary(
			since !== undefined ? { since } : undefined
		);
		return {
			count: summary.count,
			volumeOutMsat: summary.volumeOutMsat.toString(),
			feesEarnedMsat: summary.feesEarnedMsat.toString()
		};
	}

	/** Per-tower watchtower health (LND altruist client). */
	listWatchtowers(): ReturnType<LightningNode['getWatchtowers']> {
		return this.node.getWatchtowers();
	}

	/** Add a watchtower by `pubkey@host:port` URI. */
	addWatchtower(uri: string): void {
		this.node.addWatchtower(uri);
	}

	/** Remove a watchtower and drop its persisted sessions + backlog. */
	removeWatchtower(uri: string): void {
		this.node.removeWatchtower(uri);
	}

	// ─────────────── L402 (Lightning HTTP 402) ───────────────

	/**
	 * Fetch an L402-gated URL, paying the challenge if the server issues one.
	 *
	 * Payment goes through `payInvoice`, so the node's existing per-payment
	 * maximum and daily spend limit apply on top of the per-call
	 * `maxPriceSats` cap. That layering is deliberate: `maxPriceSats` bounds
	 * what THIS request may cost, and the wallet policy bounds what the node
	 * may spend at all. An unattended agent needs both.
	 *
	 * Credentials are reused across calls for the lifetime of the process, so
	 * a paid API is paid for once rather than per request.
	 */
	async l402Fetch(
		url: string,
		init: IL402RequestInit = {},
		options: {
			maxPriceSats: number;
			maxFeeSats?: number;
			timeoutMs?: number;
			fetchTimeoutMs?: number;
			scopePerPath?: boolean;
			allowUnverifiedMacaroon?: boolean;
			allowCrossOriginChallenge?: boolean;
			allowPrivateNetwork?: boolean;
			maxResponseBytes?: number;
		}
	): Promise<{
		status: number;
		body: string;
		truncated: boolean;
		paid: boolean;
		amountPaidSats: number;
		paymentHash?: string;
	}> {
		this._checkDraining();
		// This method is reachable over the daemon API, which makes it a
		// fetch-this-URL-for-me proxy running on the node's machine. Refuse
		// targets only that machine can see (localhost, RFC 1918, the cloud
		// metadata endpoint) unless the caller opts in, and refuse schemes
		// fetch would happily serve from outside HTTP (file:, data:).
		this._assertL402TargetAllowed(url, options.allowPrivateNetwork);
		const result = await l402Fetch(url, init, {
			...options,
			credentials: this._l402Credentials,
			payer: {
				payInvoice: async (
					bolt11: string,
					payOptions
				): Promise<{ preimage: Buffer }> => {
					const info = await this.payInvoice(
						bolt11,
						payOptions.timeoutMs ?? 60_000,
						payOptions.maxFeeSats
					);
					if (!info.preimage) {
						throw new BeignetError(
							'PAYMENT_FAILED',
							'L402 payment completed without a preimage, so no credential can be built'
						);
					}
					return { preimage: Buffer.from(info.preimage, 'hex') };
				}
			}
		});
		// A redirect can land on a host the caller never named. The paid path
		// already refuses cross-origin challenges, but an unpaid response that
		// followed a redirect to a private target must not be relayed either.
		if (result.response.url) {
			this._assertL402TargetAllowed(
				result.response.url,
				options.allowPrivateNetwork
			);
		}
		// The body is relayed to the daemon caller, so its size has to be
		// bounded here. Refuse a response that declares itself too large, and
		// stream-read the rest under the cap (a server can lie about
		// content-length, so the declared size alone is not a bound, and
		// buffering first then truncating would let the full body into memory
		// anyway).
		const cap = options.maxResponseBytes ?? DEFAULT_L402_MAX_RESPONSE_BYTES;
		const declared = Number(result.response.headers.get('content-length'));
		if (Number.isFinite(declared) && declared > cap) {
			throw new BeignetError(
				'RESPONSE_TOO_LARGE',
				`L402 response declares ${declared} bytes, above the ${cap} byte limit`
			);
		}
		const { body, truncated } = await readCappedBody(result.response, cap);
		return {
			status: result.response.status,
			body,
			truncated,
			paid: result.paid,
			amountPaidSats: result.amountPaidSats,
			paymentHash: result.credential?.paymentHash
		};
	}

	/**
	 * Refuse an L402 fetch target outside plain HTTP or inside the private
	 * address space, unless the caller opted in. Judged from the URL text
	 * only; a public name resolving privately (DNS rebinding) is not caught
	 * here.
	 */
	private _assertL402TargetAllowed(
		url: string,
		allowPrivateNetwork?: boolean
	): void {
		let protocol: string;
		try {
			protocol = new URL(url).protocol;
		} catch {
			throw new BeignetError('INVALID_PARAMS', `L402 fetch URL is invalid`);
		}
		if (protocol !== 'http:' && protocol !== 'https:') {
			throw new BeignetError(
				'INVALID_PARAMS',
				`L402 fetch only supports http and https URLs, got ${protocol}`
			);
		}
		if (!allowPrivateNetwork && isPrivateNetworkUrl(url)) {
			throw new BeignetError(
				'PRIVATE_NETWORK_REFUSED',
				'L402 fetch target names a private, loopback, or link-local host; pass allowPrivateNetwork to permit it'
			);
		}
	}

	/**
	 * Paid L402 credentials held by this process. The preimage is the bearer
	 * half of the credential, so it is masked here the way webhook HMAC
	 * secrets are: the list identifies what is held and what it cost, it does
	 * not export usable tokens to stdout or logs.
	 */
	listL402Credentials(): IL402Credential[] {
		return this._l402Credentials
			.list()
			.map((credential) => ({ ...credential, preimage: '***' }));
	}

	/** Forget a paid credential, so the next request pays again. */
	forgetL402Credential(scope: string): void {
		this._l402Credentials.delete(scope);
	}

	getPaymentProof(paymentHash: string): PaymentProof | null {
		const proof = this.node.getPaymentProof(Buffer.from(paymentHash, 'hex'));
		if (!proof) return null;
		return {
			paymentHash: proof.paymentHash.toString('hex'),
			preimage: proof.preimage.toString('hex'),
			amountSats: Number(proof.amountMsat / 1000n),
			completedAt: proof.completedAt,
			invoice: proof.invoice,
			hopCount: proof.route?.hops.length,
			feeSats: proof.route
				? Number(proof.route.totalFeeMsat / 1000n)
				: undefined
		};
	}

	verifyPaymentProof(paymentHash: string): PaymentProofVerification {
		const proof = this.getPaymentProof(paymentHash);
		if (!proof) return { valid: false, error: 'No proof found' };
		const computed = crypto
			.createHash('sha256')
			.update(Buffer.from(proof.preimage, 'hex'))
			.digest('hex');
		if (computed !== proof.paymentHash) {
			return {
				valid: false,
				proof,
				error: 'Preimage does not match payment hash'
			};
		}
		return { valid: true, proof };
	}

	/**
	 * Update the channel's COMMITMENT transaction feerate (BOLT 2 update_fee,
	 * min 253 sat/kw). This is not the routing fee policy (base fee msat /
	 * proportional millionths); see updateChannelPolicy for that.
	 */
	updateChannelFee(
		channelId: string,
		feeratePerKw: number
	): { ok: boolean; error?: string } {
		return this.node.updateChannelFee(
			Buffer.from(channelId, 'hex'),
			feeratePerKw
		);
	}

	/**
	 * Set the ROUTING fee policy for one channel or all channels. Msat fields
	 * accept number or decimal string (they are bigint in the library).
	 * Regenerates and re-broadcasts the channel_update. Throws on invalid
	 * values or unknown channelId.
	 */
	updateChannelPolicy(
		channelId: string | 'all',
		policy: {
			feeBaseMsat?: number;
			feeProportionalMillionths?: number;
			cltvExpiryDelta?: number;
			htlcMinimumMsat?: number | string;
			htlcMaximumMsat?: number | string;
		}
	): { updated: number; policies: ChannelPolicyInfo[] } {
		const update: import('../lightning/node/types').IChannelPolicyUpdate = {};
		if (policy.feeBaseMsat !== undefined)
			update.feeBaseMsat = policy.feeBaseMsat;
		if (policy.feeProportionalMillionths !== undefined)
			update.feeProportionalMillionths = policy.feeProportionalMillionths;
		if (policy.cltvExpiryDelta !== undefined)
			update.cltvExpiryDelta = policy.cltvExpiryDelta;
		// The msat fields take a number or a decimal string, and BigInt()
		// throws on anything else: a RangeError on a fractional number, a
		// SyntaxError on a non-numeric string. Over HTTP the route's own catch
		// scrubbed both into a 500; an SDK caller got the raw throw. Refuse
		// them as what they are (issue #474).
		if (policy.htlcMinimumMsat !== undefined)
			update.htlcMinimumMsat = requireMsatValue(
				policy.htlcMinimumMsat,
				'htlcMinimumMsat'
			);
		if (policy.htlcMaximumMsat !== undefined)
			update.htlcMaximumMsat = requireMsatValue(
				policy.htlcMaximumMsat,
				'htlcMaximumMsat'
			);

		const targets =
			channelId === 'all'
				? this.node.listChannels().map((ch) => ch.channelId.toString('hex'))
				: [channelId];
		this.node.setChannelPolicy(
			channelId === 'all' ? 'all' : Buffer.from(channelId, 'hex'),
			update
		);
		const policies = targets
			.map((id) => this.getChannelPolicy(id))
			.filter((p): p is ChannelPolicyInfo => p !== null);
		return { updated: policies.length, policies };
	}

	/** Effective routing policy for a channel, or null if unknown. */
	getChannelPolicy(channelId: string): ChannelPolicyInfo | null {
		const policy = this.node.getChannelPolicy(Buffer.from(channelId, 'hex'));
		if (!policy) return null;
		return {
			channelId,
			feeBaseMsat: policy.feeBaseMsat,
			feeProportionalMillionths: policy.feeProportionalMillionths,
			cltvExpiryDelta: policy.cltvExpiryDelta,
			htlcMinimumMsat: policy.htlcMinimumMsat.toString(),
			htlcMaximumMsat: policy.htlcMaximumMsat.toString(),
			source: policy.source
		};
	}

	cancelPayment(paymentHash: string): { ok: boolean } {
		this.node.failPayment(Buffer.from(paymentHash, 'hex'));
		return { ok: true };
	}

	/**
	 * Structured log fields naming the hop that returned an onion failure and the
	 * channel it was asked to forward over. failureSourceIndex is the index of the
	 * ERRING hop; a route hop's shortChannelId is the channel used to REACH it, so
	 * the channel the hop could not use is the NEXT hop's. Empty when the route or
	 * source index is unknown (an undecryptable failure, or a local send error).
	 */
	private describeFailureSource(p: IPaymentInfo): {
		failureSourceIndex?: number;
		failureSourceNode?: string;
		failureOutgoingScid?: string;
	} {
		const index = p.failureSourceIndex;
		if (index === undefined || !p.route) return {};

		const fields: {
			failureSourceIndex?: number;
			failureSourceNode?: string;
			failureOutgoingScid?: string;
		} = { failureSourceIndex: index };

		const erringHop = p.route.hops[index];
		if (erringHop) {
			fields.failureSourceNode = erringHop.pubkey.toString('hex');
		}
		const outgoingHop = p.route.hops[index + 1];
		if (outgoingHop) {
			try {
				fields.failureOutgoingScid = formatScid(outgoingHop.shortChannelId);
			} catch {
				// Non-decodable SCID (e.g. a random alias), so hex is still useful.
				fields.failureOutgoingScid = outgoingHop.shortChannelId.toString('hex');
			}
		}
		return fields;
	}

	private toPaymentInfo(p: IPaymentInfo): PaymentInfo {
		const info: PaymentInfo = {
			paymentHash: p.paymentHash.toString('hex'),
			amountSats: Number(p.amountMsat / 1000n),
			status: p.status,
			direction: p.direction,
			createdAt: p.createdAt
		};
		if (p.preimage) info.preimage = p.preimage.toString('hex');
		if (p.completedAt !== undefined) info.completedAt = p.completedAt;
		if (p.failureCode !== undefined) {
			info.failureCode = p.failureCode;
			info.failureDescription = describeFailureCode(p.failureCode);
		} else if (p.failureReason) {
			// A local failure has no onion code, so without this the API reports a
			// FAILED payment with nothing at all to explain it.
			info.failureDescription = p.failureReason;
		}
		if (p.route?.totalFeeMsat !== undefined) {
			info.feeSats = Number(p.route.totalFeeMsat / 1000n);
		}
		if (p.route) {
			info.route = {
				hops: p.route.hops.map((h) => ({
					pubkey: h.pubkey.toString('hex'),
					shortChannelId: h.shortChannelId.toString('hex'),
					feeMsat: h.feeBaseMsat
				})),
				totalFeeMsat: Number(p.route.totalFeeMsat),
				hopCount: p.route.hops.length
			};
		}
		if (p.metadata) info.metadata = p.metadata;
		return info;
	}

	// ─────────────── Wait APIs ───────────────

	async waitForChannelReady(
		channelId: string,
		timeoutMs = 60_000
	): Promise<void> {
		return this.node.waitForChannelReady(
			Buffer.from(channelId, 'hex'),
			timeoutMs
		);
	}

	/**
	 * Wait for the node to be fully operational (peers reconnected, channels restored).
	 * Resolves immediately if already ready or no channels exist.
	 */
	async waitForReady(timeoutMs = 30_000): Promise<void> {
		return this.node.waitForReady(timeoutMs);
	}

	async waitForPayment(
		paymentHash: string,
		timeoutMs = 60_000
	): Promise<PaymentInfo> {
		const info = await this.node.waitForPayment(
			Buffer.from(paymentHash, 'hex'),
			timeoutMs
		);
		return this.toPaymentInfo(info);
	}

	// ─────────────── DNS Bootstrap (BOLT 10) ───────────────

	async bootstrapPeers(): Promise<BootstrapPeerInfo[]> {
		const peers = await this.node.bootstrapPeers();
		return peers.map((p) => ({
			pubkey: p.pubkey.toString('hex'),
			host: p.host,
			port: p.port
		}));
	}

	async connectToSeeds(maxPeers?: number): Promise<string[]> {
		return this.node.connectToSeeds(maxPeers);
	}

	// ─────────────── Zero-Conf Channels ───────────────

	addTrustedPeer(pubkey: string): TrustedPeerInfo {
		this.node.addTrustedPeer(pubkey);
		return { pubkey, trusted: true };
	}

	removeTrustedPeer(pubkey: string): TrustedPeerInfo {
		this.node.removeTrustedPeer(pubkey);
		return { pubkey, trusted: false };
	}

	listTrustedPeers(): TrustedPeerInfo[] {
		return this.node.listTrustedPeers().map((pubkey) => ({
			pubkey,
			trusted: true
		}));
	}

	openZeroConfChannel(
		peerPubkey: string,
		amountSats: number,
		pushSats?: number
	): ChannelInfo {
		requireOpenAmounts(amountSats, pushSats);
		const fundingSatoshis = BigInt(amountSats);
		const pushMsat =
			pushSats !== undefined ? BigInt(pushSats) * 1000n : undefined;
		const channel = fundingOrRefuse(() =>
			this.node.openZeroConfChannel(peerPubkey, fundingSatoshis, pushMsat)
		);
		if (!channel) {
			throw new BeignetError(
				'ZERO_CONF_FAILED',
				'Failed to open zero-conf channel'
			);
		}
		const state = channel.getFullState();
		const balances = channel.getBalances();
		const channelId = state.channelId || state.temporaryChannelId;
		this.refreshStaticChannelBackup();
		return {
			channelId: channelId.toString('hex'),
			peerPubkey,
			state: state.state as import('./types').ChannelStateString,
			localBalanceSats: Number(balances.localMsat / 1000n),
			remoteBalanceSats: Number(balances.remoteMsat / 1000n),
			capacitySats: amountSats,
			isAnchor: isAnchorChannel(state.channelType)
		};
	}

	// ─────────────── Dual-Funding (v2 Channels) ───────────────

	openChannelV2(
		peerPubkey: string,
		params: {
			amountSats: number;
			fundingFeeratePerkw?: number;
			commitmentFeeratePerkw?: number;
			locktime?: number;
			/** Liquidity ads buyer (issue #532 1B): ask the peer to lease us
			 *  this much inbound into the channel being opened. */
			requestFunds?: { requestedSats: number; blockheight: number };
			/** The buyer's own price ceiling for the lease. The library
			 *  refuses requestFunds without it; the seller's advertised rates
			 *  must never be echoed back here, or any price is "acceptable". */
			maxLeaseRates?: import('../lightning/gossip/types').ILeaseRates;
		}
	): ChannelInfo {
		requireOpenAmounts(params.amountSats);
		if (params.fundingFeeratePerkw !== undefined)
			requireU32(params.fundingFeeratePerkw, 'fundingFeeratePerkw');
		if (params.commitmentFeeratePerkw !== undefined)
			requireU32(params.commitmentFeeratePerkw, 'commitmentFeeratePerkw');
		if (params.locktime !== undefined)
			requireU32(params.locktime, 'locktime', 0);
		if (params.requestFunds !== undefined) {
			// Shape-check before touching fields: a null or scalar body value
			// would otherwise TypeError into a scrubbed 500 instead of a 400.
			if (
				typeof params.requestFunds !== 'object' ||
				params.requestFunds === null
			) {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					'requestFunds must be an object with requestedSats and blockheight'
				);
			}
			// Guard before BigInt(): a fractional requestedSats throws an
			// uncaught RangeError there. The u64 wire field is wider than
			// Number, so the safe-integer bound is the honest JSON limit.
			requirePositiveSafeInteger(
				params.requestFunds.requestedSats,
				'requestFunds.requestedSats'
			);
			// The seller re-windows blockheight against its own tip
			// (LEASE_BLOCKHEIGHT_*_TOLERANCE); here only the u32 wire width is
			// enforced, since encode throws after the channel already exists.
			requireU32(params.requestFunds.blockheight, 'requestFunds.blockheight');
		}
		if (params.maxLeaseRates !== undefined) {
			// A fractional or oversized field would only surface inside the
			// lease fee math AFTER open_channel2 has gone out; refuse at the
			// JSON edge instead. The requestFunds/maxLeaseRates pairing rule
			// stays with the library, which throws an InvalidRequestError that
			// fundingOrRefuse maps to INVALID_PARAMS.
			const refusal = leaseRatesRefusal(params.maxLeaseRates);
			if (refusal !== null) {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					`maxLeaseRates: ${refusal}`
				);
			}
		}
		const channel = fundingOrRefuse(() =>
			this.node.openChannelV2(peerPubkey, {
				fundingSatoshis: BigInt(params.amountSats),
				fundingFeeratePerkw: params.fundingFeeratePerkw,
				commitmentFeeratePerkw: params.commitmentFeeratePerkw,
				locktime: params.locktime,
				requestFunds: params.requestFunds
					? {
							requestedSats: BigInt(params.requestFunds.requestedSats),
							blockheight: params.requestFunds.blockheight
					  }
					: undefined,
				maxLeaseRates: params.maxLeaseRates
			})
		);
		const state = channel.getFullState();
		const balances = channel.getBalances();
		const channelId = state.channelId || state.temporaryChannelId;
		this.refreshStaticChannelBackup();
		return {
			channelId: channelId.toString('hex'),
			peerPubkey,
			state: state.state as import('./types').ChannelStateString,
			localBalanceSats: Number(balances.localMsat / 1000n),
			remoteBalanceSats: Number(balances.remoteMsat / 1000n),
			capacitySats: params.amountSats,
			isAnchor: isAnchorChannel(state.channelType)
		};
	}

	// ─────────────── Splicing ───────────────

	spliceQuote(
		channelId: string,
		direction: 'in' | 'out',
		feeratePerkw: number
	): ReturnType<LightningNode['spliceQuote']> {
		const idBuf = requireChannelIdHex(channelId);
		requireU32(feeratePerkw, 'feeratePerkw');
		return fundingOrRefuse(() =>
			this.node.spliceQuote(idBuf, direction, feeratePerkw)
		);
	}

	spliceIn(
		channelId: string,
		amountSats: number,
		feeratePerkw: number,
		fundingUtxos?: {
			utxos: Array<{ txid: string; vout: number }>;
			allowTopUp?: boolean;
		}
	): SpliceResult {
		const idBuf = requireChannelIdHex(channelId);
		requirePositiveSafeInteger(amountSats, 'amountSats');
		requireU32(feeratePerkw, 'feeratePerkw');
		// fundingUtxos is shape-checked by the node, one copy of the rules; its
		// InvalidSpliceError converts to INVALID_PARAMS through fundingOrRefuse
		// like every other splice refusal.
		const result = fundingOrRefuse(() =>
			this.node.spliceIn(idBuf, BigInt(amountSats), feeratePerkw, fundingUtxos)
		);
		// The SCB is refreshed on the splice:complete event (when fundingTxid holds
		// the new outpoint), NOT here at initiation where it still holds the old one.
		return result;
	}

	spliceOut(
		channelId: string,
		amountSats: number,
		feeratePerkw: number,
		destinationAddress?: string
	): SpliceResult {
		const idBuf = requireChannelIdHex(channelId);
		requirePositiveSafeInteger(amountSats, 'amountSats');
		requireU32(feeratePerkw, 'feeratePerkw');
		let destinationScript: Buffer | undefined;
		if (destinationAddress !== undefined) {
			// A provided-but-empty (or non-string) destination is a caller bug,
			// not a request for the wallet default: a truthy check here let an
			// empty address fall through and silently pay the wallet instead
			// (issue #534 review).
			if (
				typeof destinationAddress !== 'string' ||
				destinationAddress.length === 0
			) {
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					'destinationAddress must be a non-empty string when provided'
				);
			}
			const bitcoin = require('bitcoinjs-lib');
			try {
				destinationScript = bitcoin.address.toOutputScript(
					destinationAddress,
					this.getBitcoinNetwork()
				);
			} catch (err: unknown) {
				// An address this network cannot decode is the caller's typo,
				// not a node fault: refuse it rather than scrubbing to a 500.
				throw new BeignetError(
					BeignetErrorCode.INVALID_PARAMS,
					`destinationAddress is not a valid address for this network: ${
						err instanceof Error ? err.message : 'failed to decode'
					}`
				);
			}
		}
		// An address-targeted splice-out is an external send: the destination
		// receives the full amount and the channel additionally pays the
		// on-chain fee (the engine declares relative = -(amount + fee), same
		// fee formula as below), so both count against the shared daily
		// budget, like sendOnchain (issue #534 review). Wallet-credited
		// splice-outs stay outside the limit: those funds return to our own
		// wallet. Checked before the engine call (fail fast, like sendOnchain)
		// and recorded only when the engine accepts the initiation; a splice
		// that later fails in negotiation holds the budget until the UTC
		// midnight reset, which errs on the safe side.
		let externalSpendSats: number | undefined;
		if (destinationScript !== undefined) {
			const feeSats = Number(
				spliceFeeSats(
					estimateSpliceTxWeight({
						walletInputCount: 0,
						destinationScriptLen: destinationScript.length
					}),
					feeratePerkw
				)
			);
			externalSpendSats = amountSats + feeSats;
			this._checkSpendLimit(externalSpendSats);
		}
		const result = fundingOrRefuse(() =>
			this.node.spliceOut(
				idBuf,
				BigInt(amountSats),
				feeratePerkw,
				destinationScript
			)
		);
		if (externalSpendSats !== undefined && result.ok) {
			this._recordSpend(externalSpendSats, 'onchain');
		}
		// The SCB is refreshed on the splice:complete event (when fundingTxid holds
		// the new outpoint), NOT here at initiation where it still holds the old one.
		return result;
	}

	// ─────────────── BOLT 12 Offers ───────────────

	decodeOfferString(offerStr: string): OfferInfo {
		const offer = decodeOfferInput(offerStr);
		return this.toOfferInfo(offer, offerStr);
	}

	createOffer(options: {
		description: string;
		amountSats?: number;
		issuer?: string;
		expirySecs?: number;
	}): OfferInfo {
		if (
			options.amountSats !== undefined &&
			(typeof options.amountSats !== 'number' ||
				!Number.isSafeInteger(options.amountSats) ||
				options.amountSats < 0)
		) {
			throw new BeignetError(
				'INVALID_PARAMS',
				'amountSats must be a non-negative integer number of satoshis'
			);
		}
		if (
			options.expirySecs !== undefined &&
			(typeof options.expirySecs !== 'number' ||
				!Number.isSafeInteger(options.expirySecs) ||
				options.expirySecs <= 0)
		) {
			throw new BeignetError(
				'INVALID_PARAMS',
				'expirySecs must be a positive integer number of seconds'
			);
		}
		const amountMsat =
			options.amountSats !== undefined
				? BigInt(options.amountSats) * 1000n
				: undefined;
		// Sum in bigint: expirySecs alone is a safe integer, but the sum with
		// now can exceed 2^53 and round before a number-based conversion.
		const absoluteExpiry =
			options.expirySecs !== undefined
				? BigInt(Math.floor(Date.now() / 1000)) + BigInt(options.expirySecs)
				: undefined;
		const { offer, encoded } = this.node.createOffer({
			description: options.description,
			amount: amountMsat,
			issuer: options.issuer,
			absoluteExpiry
		});
		return this.toOfferInfo(offer, encoded);
	}

	/**
	 * Remove a stored offer by its hex id, from memory and storage. Returns
	 * false when no such offer exists.
	 */
	removeOffer(offerId: string): boolean {
		if (!/^[0-9a-f]{64}$/i.test(offerId)) {
			throw new BeignetError(
				'INVALID_PARAMS',
				'offerId must be 64 hex characters'
			);
		}
		return this.node.getOfferManager().removeOffer(Buffer.from(offerId, 'hex'));
	}

	listOffers(): OfferInfo[] {
		const mgr = this.node.getOfferManager();
		// The encoding rides along: it is the string a payer needs, and
		// without it a listing can only show the offer id.
		return mgr
			.listOfferEntries()
			.map(({ offer, encoded }) => this.toOfferInfo(offer, encoded));
	}

	async payOffer(
		offerStr: string,
		amountSats?: number,
		timeoutMs = 60_000
	): Promise<PaymentInfo> {
		// Paying an offer spends outbound liquidity exactly as payInvoice does,
		// so it runs the same admission: drain mode, both spending limits, a
		// reservation for the in-flight window and the daily accounting on
		// settlement (issue #529). Checked here so a draining node does not even
		// go asking a payee for an invoice.
		this._checkDraining();
		const offer = decodeOfferInput(offerStr);

		// Request invoice from the offer. Guarded before BigInt(): a fractional
		// amount threw an uncaught RangeError that shipped as a scrubbed 500
		// (issue #474).
		const requestOptions =
			amountSats !== undefined
				? {
						amount:
							BigInt(requireNonNegativeSafeInteger(amountSats, 'amountSats')) *
							1000n
				  }
				: undefined;

		const bolt12Invoice = await this.node.requestInvoice(offer, requestOptions);
		// Re-checked after the await: the request is a round trip to the payee,
		// and it is the dispatch below, not the request above, that a drain
		// started meanwhile has to stop.
		this._checkDraining();
		const paymentHashHex = bolt12Invoice.paymentHash.toString('hex');

		// What payBolt12Invoice will actually pay is the invoice's own amount:
		// the payee prices the offer, and there is nothing else to pay (an
		// amountless BOLT 12 invoice is refused outright). Admitting on the
		// caller's amountSats instead is the precedence #528 removed from the
		// BOLT 11 paths, so the shared helper decides it here too.
		const spendAmountSats = paymentSpendSats(bolt12Invoice.amount, amountSats);

		if (spendAmountSats > 0) {
			this._checkMaxPayment(spendAmountSats);
			this._checkSpendLimit(spendAmountSats);
			this._pendingSpendSats += spendAmountSats;
		}

		// This call owns the hash's spend accounting for as long as its own
		// listener is installed, for the reason payInvoice's copy documents:
		// the forwarding handler in create() would otherwise charge an async
		// claim on this hash for the settlement the listener below records.
		this._acquireBlockingPayment(paymentHashHex);

		// One release shared by every exit, and idempotent, because more than
		// one can run for a single payment (a timeout followed by a late
		// payment:failed). Held for the whole in-flight window: it is what
		// stops two concurrent offer payments both passing the daily limit
		// before either records a spend.
		let released = false;
		const releaseReservation = (): void => {
			if (spendAmountSats <= 0 || released) return;
			released = true;
			this._pendingSpendSats -= spendAmountSats;
		};

		return new Promise<PaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				releaseReservation();
				this.node.failPayment(bolt12Invoice.paymentHash);
				reject(
					new BeignetError(
						'PAYMENT_TIMEOUT',
						`Payment timed out after ${timeoutMs}ms`
					)
				);
			}, timeoutMs);

			const cleanup = (): void => {
				clearTimeout(timer);
				this.node.removeListener('payment:sent', onSent);
				this.node.removeListener('payment:failed', onFailed);
				// Safe here rather than after the accounting below: the handler
				// in create() is registered first, so it has already seen this
				// same event and declined to charge for it.
				this._releaseBlockingPayment(paymentHashHex);
			};

			const onSent = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					// Released before the spend is recorded, so a concurrent
					// _checkSpendLimit never sees the same sats counted twice.
					releaseReservation();
					if (spendAmountSats > 0) this._recordSpend(spendAmountSats);
					resolve(this.toPaymentInfo(info));
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					releaseReservation();
					const failDesc =
						info.failureCode !== undefined
							? describeFailureCode(info.failureCode)
							: 'unknown';
					reject(
						new BeignetError(
							'PAYMENT_FAILED',
							`Payment failed: ${failDesc}`,
							info.failureCode
						)
					);
				}
			};

			this.node.on('payment:sent', onSent);
			this.node.on('payment:failed', onFailed);

			try {
				this.node.payBolt12Invoice(bolt12Invoice);
			} catch (err: unknown) {
				cleanup();
				// A payment that never started holds no capacity. Without this a
				// refused dispatch (no route, a duplicate, a missing amount)
				// ratcheted the counter up until the daily limit refused real
				// payments, as it did on the BOLT 11 path (issue #474).
				releaseReservation();
				const msg = err instanceof Error ? err.message : String(err);
				reject(new BeignetError('PAYMENT_FAILED', msg));
			}
		});
	}

	private toOfferInfo(
		offer: import('../lightning/offer/types').IOffer,
		encoded?: string
	): OfferInfo {
		const info: OfferInfo = {
			offerId: offer.offerId.toString('hex'),
			description: offer.description
		};
		if (offer.amount !== undefined) {
			info.amountSats = Math.floor(Number(offer.amount) / 1000);
		}
		if (offer.issuer) info.issuer = offer.issuer;
		if (offer.issuerId) info.issuerId = offer.issuerId.toString('hex');
		if (offer.quantityMax !== undefined)
			info.quantityMax = Number(offer.quantityMax);
		if (offer.absoluteExpiry !== undefined)
			info.absoluteExpiry = Number(offer.absoluteExpiry);
		if (encoded) info.encoded = encoded;
		return info;
	}

	// ─────────────── Invoices (List) ───────────────

	getInvoice(paymentHash: string): InvoiceInfo | null {
		const inv = this.node.getInvoice(paymentHash);
		if (!inv) return null;
		const info: InvoiceInfo = {
			bolt11: inv.bolt11,
			paymentHash: inv.paymentHash
		};
		if (inv.amountMsat !== undefined) {
			info.amountSats = Number(inv.amountMsat / 1000n);
		}
		if (inv.description) info.description = inv.description;
		if (inv.expiry !== undefined) info.expiry = inv.expiry;
		if (inv.createdAt !== undefined) info.createdAt = inv.createdAt;
		// Derive status
		const payment = this.node.getPayment(Buffer.from(inv.paymentHash, 'hex'));
		if (
			payment &&
			payment.status === 'COMPLETED' &&
			payment.direction === 'INCOMING'
		) {
			info.status = 'PAID';
		} else if (
			inv.createdAt !== undefined &&
			inv.expiry !== undefined &&
			Date.now() / 1000 > inv.createdAt + inv.expiry
		) {
			info.status = 'EXPIRED';
		} else {
			info.status = 'PENDING';
		}
		return info;
	}

	listInvoices(): InvoiceInfo[] {
		return this.node.listInvoices().map((inv) => {
			const info: InvoiceInfo = {
				bolt11: inv.bolt11,
				paymentHash: inv.paymentHash
			};
			if (inv.amountMsat !== undefined) {
				info.amountSats = Number(inv.amountMsat / 1000n);
			}
			if (inv.description) info.description = inv.description;
			if (inv.expiry !== undefined) info.expiry = inv.expiry;
			if (inv.createdAt !== undefined) info.createdAt = inv.createdAt;
			// Derive status from payment map + expiry
			const payment = this.node.getPayment(Buffer.from(inv.paymentHash, 'hex'));
			if (
				payment &&
				payment.status === 'COMPLETED' &&
				payment.direction === 'INCOMING'
			) {
				info.status = 'PAID';
			} else if (
				inv.createdAt !== undefined &&
				inv.expiry !== undefined &&
				Date.now() / 1000 > inv.createdAt + inv.expiry
			) {
				info.status = 'EXPIRED';
			} else {
				info.status = 'PENDING';
			}
			return info;
		});
	}

	// ─────────────── Health ───────────────

	getHealth(): HealthInfo {
		const blockHeight = this.node.getCurrentBlockHeight();
		const electrumConnected =
			this.wallet?.electrum?.connectedToElectrum ?? false;
		const channels = this.node.listChannels();
		const readyChannels = channels.filter(
			(ch) => ch.state === ChannelState.NORMAL && !isHeldRestore(ch)
		);
		const peerCount = this.node.listPeers().length;
		const graph = this.node.getGraph();

		// Only channels that were fully established and should be operational
		// right now get a vote on "degraded". A channel mid-open, mid-splice or
		// in a cooperative shutdown is a deliberate operation in progress, not a
		// fault: a wallet whose only channel is waiting on funding confirmations
		// is doing exactly what it was asked to. AWAITING_REESTABLISH and
		// ERRORED are the states that mean an established channel is broken.
		const operating = channels.filter(
			(ch) =>
				(ch.state === ChannelState.NORMAL ||
					ch.state === ChannelState.SPLICING) &&
				!isHeldRestore(ch)
		);
		const broken = channels.filter(
			(ch) =>
				ch.state === ChannelState.AWAITING_REESTABLISH ||
				ch.state === ChannelState.ERRORED
		);

		let status: HealthInfo['status'] = 'ready';
		if (!electrumConnected) {
			status = 'degraded';
		} else if (blockHeight === 0) {
			status = 'syncing';
		} else if (broken.length > 0 && operating.length === 0) {
			// Every established channel is broken
			status = 'degraded';
		} else if (peerCount === 0 && operating.length > 0) {
			// Has operational channels but no peers connected to use them with
			status = 'degraded';
		}

		return {
			status,
			uptime: Date.now() - this.startedAt,
			blockHeight,
			electrumConnected,
			peerCount,
			channelCount: channels.length,
			readyChannelCount: readyChannels.length,
			graphNodes: graph.getNodeCount(),
			graphChannels: graph.getChannelCount()
		};
	}

	isReady(): boolean {
		const health = this.getHealth();
		return health.status === 'ready' && health.readyChannelCount > 0;
	}

	// ─────────────── Mainnet Readiness ───────────────

	getMainnetReadiness(): ReadinessReport {
		const checks: ReadinessCheck[] = [];

		// 1. STORAGE_CONFIGURED (CRITICAL) — check if SQLite storage is being used
		checks.push({
			name: 'STORAGE_CONFIGURED',
			status: this.storage ? 'PASS' : 'FAIL',
			severity: 'CRITICAL',
			message: this.storage
				? 'SQLite storage is configured'
				: 'No persistent storage — channel state will be lost on restart'
		});

		// 2. CHAIN_BACKEND_CONNECTED (CRITICAL) — check if electrum/chain backend is connected
		const health = this.getHealth();
		checks.push({
			name: 'CHAIN_BACKEND_CONNECTED',
			status: health.electrumConnected ? 'PASS' : 'FAIL',
			severity: 'CRITICAL',
			message: health.electrumConnected
				? 'Chain backend connected'
				: 'Chain backend not connected — cannot monitor transactions'
		});

		// 3. AUTO_RECONNECT_ENABLED (WARNING)
		const nodeInfo = this.node.getNodeInfo();
		const channels = this.node.listChannels();
		const readyChannels = channels.filter(
			(ch) => ch.state === 'NORMAL' && !isHeldRestore(ch)
		);

		checks.push({
			name: 'AUTO_RECONNECT_ENABLED',
			status: nodeInfo.networkingEnabled ? 'PASS' : 'WARN',
			severity: 'WARNING',
			message: nodeInfo.networkingEnabled
				? 'Networking and auto-reconnect enabled'
				: 'Networking disabled — node cannot reconnect to peers'
		});

		// 4. ANCHOR_CHANNELS_PREFERRED (WARNING)
		const hasAnchor = channels.some(
			(ch) => ch.channelType != null && isAnchorChannel(ch.channelType)
		);
		checks.push({
			name: 'ANCHOR_CHANNELS_PREFERRED',
			status: hasAnchor || channels.length === 0 ? 'PASS' : 'WARN',
			severity: 'WARNING',
			message: hasAnchor
				? 'Anchor channels in use (recommended for fee bumping)'
				: channels.length === 0
				? 'No channels yet (anchor will be used by default)'
				: 'No anchor channels — consider opening anchor channels for improved fee management'
		});

		// 5. HAS_ACTIVE_CHANNEL (INFO)
		checks.push({
			name: 'HAS_ACTIVE_CHANNEL',
			status: readyChannels.length > 0 ? 'PASS' : 'WARN',
			severity: 'INFO',
			message:
				readyChannels.length > 0
					? `${readyChannels.length} active channel(s)`
					: 'No active channels — open a channel to send/receive payments'
		});

		// 6. GOSSIP_GRAPH_POPULATED (INFO)
		const graph = this.node.getGraph();
		checks.push({
			name: 'GOSSIP_GRAPH_POPULATED',
			status: graph.getChannelCount() > 0 ? 'PASS' : 'WARN',
			severity: 'INFO',
			message:
				graph.getChannelCount() > 0
					? `Gossip graph has ${graph.getNodeCount()} nodes and ${graph.getChannelCount()} channels`
					: 'Gossip graph is empty — pathfinding will not work until gossip is synced'
		});

		// 7. FEE_ESTIMATOR_AVAILABLE (WARNING)
		const feeSnapshot = this.getFeeSnapshot();
		checks.push({
			name: 'FEE_ESTIMATOR_AVAILABLE',
			status: feeSnapshot !== null ? 'PASS' : 'WARN',
			severity: 'WARNING',
			message:
				feeSnapshot !== null
					? `Fee estimator active (${feeSnapshot.sampleCount} samples)`
					: 'Fee estimator has no data — fee-sensitive operations may use defaults'
		});

		// 8. ELECTRUM_REDUNDANCY (WARNING) — single electrum server is a SPOF
		checks.push({
			name: 'ELECTRUM_REDUNDANCY',
			status: this.electrumServerCount > 1 ? 'PASS' : 'WARN',
			severity: 'WARNING',
			message:
				this.electrumServerCount > 1
					? `${this.electrumServerCount} Electrum servers configured for failover`
					: 'Only 1 Electrum server configured — no failover if it goes down'
		});

		// 9. BACKUP_CONFIGURED (WARNING) — no backup means channel state could be lost
		checks.push({
			name: 'BACKUP_CONFIGURED',
			status: this.backupPath ? 'PASS' : 'WARN',
			severity: 'WARNING',
			message: this.backupPath
				? `Automated backups configured to ${this.backupPath}`
				: 'No backup path configured — channel state is only in the primary database'
		});

		// 10. SUFFICIENT_CHANNELS (WARNING) — single channel is a SPOF
		checks.push({
			name: 'SUFFICIENT_CHANNELS',
			status:
				readyChannels.length >= 2 || channels.length === 0 ? 'PASS' : 'WARN',
			severity: 'WARNING',
			message:
				readyChannels.length >= 2
					? `${readyChannels.length} ready channels (redundancy OK)`
					: channels.length === 0
					? 'No channels yet'
					: `Only ${readyChannels.length} ready channel — single channel is a point of failure`
		});

		// 11. CHANNEL_BALANCE_HEALTH (INFO) — all channels depleted in one direction
		const depletedChannels = readyChannels.filter((ch) => {
			const capacity = ch.fundingSatoshis;
			if (capacity === 0n) return false;
			const localPct = Number(
				(ch.localBalanceMsat * 100n) / (capacity * 1000n)
			);
			return localPct > 90 || localPct < 10;
		});
		checks.push({
			name: 'CHANNEL_BALANCE_HEALTH',
			status:
				readyChannels.length === 0 ||
				depletedChannels.length < readyChannels.length
					? 'PASS'
					: 'WARN',
			severity: 'INFO',
			message:
				readyChannels.length === 0
					? 'No active channels to assess'
					: depletedChannels.length < readyChannels.length
					? 'Channel balances are healthy'
					: `All ${readyChannels.length} channel(s) are >90% depleted in one direction`
		});

		// 12. CHANNEL_BACKUP: the recovery tier, which decides what a lost
		// device costs (issue #454). The severity follows the outcome because
		// the scoring below is severity specific: a fenced or namespace-lost
		// node is a CRITICAL failure (it must not operate, or can never open
		// another channel), everything short of a confirmed guardian quorum
		// is a WARNING.
		checks.push(this.channelBackupReadiness());

		// Calculate weighted score
		// CRITICAL failures = -30, WARNINGs = -10, INFOs = -5
		let score = 100;
		let hasCriticalFailure = false;
		for (const check of checks) {
			if (check.status === 'FAIL' && check.severity === 'CRITICAL') {
				hasCriticalFailure = true;
				score -= 30;
			} else if (check.status === 'WARN' && check.severity === 'WARNING') {
				score -= 10;
			} else if (check.status === 'WARN' && check.severity === 'INFO') {
				score -= 5;
			}
		}
		score = Math.max(0, score);

		return {
			score,
			ready: !hasCriticalFailure,
			checks
		};
	}

	private channelBackupReadiness(): ReadinessCheck {
		const name = 'CHANNEL_BACKUP';
		const mode = this.recoveryMode;
		if (mode === 'off') {
			return {
				name,
				status: 'WARN',
				severity: 'WARNING',
				message:
					'No recovery mode: a lost device can only force-close its ' +
					'channels from the SCB (set BEIGNET_RECOVERY_MODE)'
			};
		}
		const status = this.node.getRecoveryStatus();
		if (status.fenced || status.gate === 'fenced') {
			return {
				name,
				status: 'FAIL',
				severity: 'CRITICAL',
				message:
					'Another device owns this recovery namespace; this node is ' +
					'fenced and must not operate'
			};
		}
		if (status.backfillLost) {
			return {
				name,
				status: 'FAIL',
				severity: 'CRITICAL',
				message:
					'This recovery namespace lost its guardian backfill; no ' +
					'further channel state can be proven durable'
			};
		}
		if (mode === 'peer-storage') {
			return {
				name,
				status: 'WARN',
				severity: 'WARNING',
				message:
					'Recovery capsules go to storage peers only (Tier 2 restore ' +
					'via /recovery/restore-capsule); no guardian quorum, so no ' +
					'fencing between devices'
			};
		}
		if (status.gate !== 'confirmed') {
			return {
				name,
				status: 'WARN',
				severity: 'WARNING',
				message:
					`Guardian mode ${mode}: the quorum has not confirmed this ` +
					'lease yet; channels stay quarantined'
			};
		}
		return {
			name,
			status: 'PASS',
			severity: 'WARNING',
			message:
				`Channel state replicated to a guardian quorum (${mode}, durable ` +
				`through ${status.lastDurableSequence}); a lost device resumes ` +
				'its channels'
		};
	}

	// ─────────────── Liquidity Advisor ───────────────

	getLiquiditySnapshot(): LiquiditySnapshot {
		const snapshot = this.node.getLiquiditySnapshot();
		// The reserve every channel holds back on our side is unspendable, so what
		// can actually be sent is the local balance above it, summed over routable
		// channels, the same figure canSend() reports. Surfacing both lets callers
		// show a true "can send" (zero while still below the reserve) instead of the
		// raw local balance, which overstates it.
		//
		// Routable means NORMAL or htlcUsable: a channel paying through its splice
		// still sends, so it must keep counting. Filtering on NORMAL alone zeroed
		// the sendable figure for the whole splice window, which read as having no
		// funds while a payment would in fact go through. Mid-splice the spendable
		// side is the conservative min of the live and settle-to balances,
		// mirroring the balance side of the channel's own add gate. (The true
		// per-add ceiling, getSpendableOutboundMsat, additionally reserves the
		// funder's commitment fee; this aggregation, like the NORMAL-channel
		// figure before it, prices only balance minus reserve.)
		let reserveMsat = 0n;
		let sendableMsat = 0n;
		for (const ch of this.node.listChannels()) {
			// A held restore is NORMAL with htlcUsable false, so this two-clause
			// test admitted it on the first clause alone (issue #469). Its
			// balance is real, but it can carry nothing, so it contributes no
			// sendable sats and reserves nothing worth reporting.
			if (isHeldRestore(ch)) continue;
			if (ch.state !== ChannelState.NORMAL && !ch.htlcUsable) continue;
			const chReserveMsat = ch.localReserveMsat ?? 0n;
			reserveMsat += chReserveMsat;
			const effLocalMsat =
				ch.pendingSpliceLocalBalanceMsat !== undefined &&
				ch.pendingSpliceLocalBalanceMsat < ch.localBalanceMsat
					? ch.pendingSpliceLocalBalanceMsat
					: ch.localBalanceMsat;
			sendableMsat +=
				effLocalMsat > chReserveMsat ? effLocalMsat - chReserveMsat : 0n;
		}
		return {
			totalLocalBalanceSats: snapshot.totalLocalBalanceSats,
			totalRemoteBalanceSats: snapshot.totalRemoteBalanceSats,
			totalCapacitySats: snapshot.totalCapacitySats,
			channelCount: snapshot.channelCount,
			activeChannelCount: snapshot.activeChannelCount,
			outboundLiquidityPct: snapshot.outboundLiquidityPct,
			inboundLiquidityPct: snapshot.inboundLiquidityPct,
			reserveSats: Number(reserveMsat / 1000n),
			sendableSats: Number(sendableMsat / 1000n),
			recommendations: snapshot.recommendations
		};
	}

	/**
	 * Advisor recommendations: the liquidity analysis (same engine as
	 * getLiquiditySnapshot) plus the concrete circular-rebalance plan the
	 * executor would run. Read-only -- nothing is executed.
	 */
	getAdvisorRecommendations(): AdvisorRecommendations {
		const plan: RebalancePlanInfo[] = this.node
			.planRebalanceRecommendations()
			.map((p) => ({
				fromChannelId: p.fromChannelId,
				toChannelId: p.toChannelId,
				amountSats: Number(p.amountSats),
				reason: p.reason
			}));
		return { ...this.getLiquiditySnapshot(), rebalancePlan: plan };
	}

	/**
	 * Circular rebalance: self-payment out over fromChannelId and back in over
	 * toChannelId. Aborts (without paying anything) if the route fee exceeds
	 * maxFeeSats.
	 */
	async rebalanceChannel(
		fromChannelId: string,
		toChannelId: string,
		amountSats: number,
		maxFeeSats: number
	): Promise<RebalanceResult> {
		if (!/^[0-9a-fA-F]{64}$/.test(fromChannelId))
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'fromChannelId must be 64 hex chars'
			);
		if (!/^[0-9a-fA-F]{64}$/.test(toChannelId))
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'toChannelId must be 64 hex chars'
			);
		if (!Number.isInteger(amountSats) || amountSats <= 0)
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'amountSats must be a positive integer'
			);
		if (!Number.isInteger(maxFeeSats) || maxFeeSats < 0)
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'maxFeeSats must be a non-negative integer'
			);
		const result = await this.node.rebalanceChannel({
			fromChannelId: Buffer.from(fromChannelId, 'hex'),
			toChannelId: Buffer.from(toChannelId, 'hex'),
			amountSats: BigInt(amountSats),
			maxFeeSats: BigInt(maxFeeSats)
		});
		this.log('info', 'Rebalance completed', {
			fromChannelId,
			toChannelId,
			amountSats,
			feeMsat: result.feeMsat.toString()
		});
		return {
			paymentHash: result.paymentHash.toString('hex'),
			amountSats,
			feeMsat: result.feeMsat.toString(),
			feeSats: Number(result.feeMsat / 1000n),
			hops: result.hops
		};
	}

	/**
	 * Execute the advisor's rebalance plan under the per-UTC-day fee budget
	 * (persisted, so restarts cannot overspend the same day).
	 */
	async executeRebalances(
		budgetSatsPerDay?: number
	): Promise<RebalanceExecutionSummary> {
		if (
			budgetSatsPerDay !== undefined &&
			(!Number.isInteger(budgetSatsPerDay) || budgetSatsPerDay < 0)
		) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'budgetSatsPerDay must be a non-negative integer'
			);
		}
		const summary = await this.node.executeRebalanceRecommendations({
			budgetSatsPerDay
		});
		return {
			attempts: summary.attempts.map((a) => ({
				fromChannelId: a.fromChannelId,
				toChannelId: a.toChannelId,
				amountSats: Number(a.amountSats),
				status: a.status,
				feeMsat: a.feeMsat?.toString(),
				error: a.error
			})),
			succeeded: summary.succeeded,
			failed: summary.failed,
			skippedBudget: summary.skippedBudget,
			feeSpentMsat: summary.feeSpentMsat.toString(),
			budgetRemainingMsat: summary.budgetRemainingMsat.toString()
		};
	}

	// ─────────────── Fee Advisor ───────────────

	getFeeSnapshot(): FeeSnapshot | null {
		return this.node.getFeeSnapshot();
	}

	// ─────────────── Channel Suggestions ───────────────

	getChannelSuggestions(count?: number): ChannelSuggestion[] {
		return this.node.getChannelSuggestions(count);
	}

	// ─────────────── Route Estimation & Probing ───────────────

	estimateRouteFee(bolt11: string, amountSats?: number): RouteEstimate | null {
		return this.node.estimateRouteFee(bolt11, amountSats);
	}

	estimatePayment(bolt11: string, amountSats?: number): PaymentEstimate | null {
		return this.node.estimatePayment(bolt11, amountSats);
	}

	probeRoute(
		destination: string,
		amountSats: number
	): {
		success: boolean;
		feeSats?: number;
		hops?: number;
		path?: Array<{ pubkey: string; shortChannelId: string }>;
	} {
		const result = this.node.probeRoute(destination, amountSats);
		if (!result.path) return result;
		return {
			...result,
			path: result.path.map((hop) => ({
				pubkey: hop.pubkey,
				shortChannelId: formatScid(Buffer.from(hop.shortChannelId, 'hex'))
			}))
		};
	}

	// ─────────────── Graph Queries ───────────────

	getGraphInfo(): GraphInfo {
		const graph = this.node.getGraph();
		const info: GraphInfo = {
			nodeCount: graph.getNodeCount(),
			channelCount: graph.getChannelCount()
		};
		if (this._lastGraphSyncAt !== undefined) {
			info.lastSyncAt = this._lastGraphSyncAt;
		}
		return info;
	}

	getGraphNode(pubkey: string): GraphNodeInfo | null {
		if (!/^[0-9a-fA-F]{66}$/.test(pubkey)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'pubkey must be a 33-byte hex string'
			);
		}
		const graph = this.node.getGraph();
		const node = graph.getNode(Buffer.from(pubkey, 'hex'));
		if (!node) return null;
		const info: GraphNodeInfo = {
			pubkey: node.nodeId.toString('hex'),
			channelCount: node.channels.size,
			channels: graph
				.getNodeChannels(node.nodeId)
				.map((ch) => formatScid(ch.shortChannelId))
		};
		const ann = node.announcement;
		if (ann) {
			// alias is a fixed 32-byte field, zero-padded on the wire
			const alias = ann.alias
				.subarray(0, ann.alias.indexOf(0) === -1 ? 32 : ann.alias.indexOf(0))
				.toString('utf8');
			if (alias.length > 0) info.alias = alias;
			info.color = ann.rgbColor.toString('hex');
			info.addresses = ann.addresses.map((a) => ({
				type: a.type,
				host: a.host,
				port: a.port
			}));
			info.featuresHex = ann.features.toString('hex');
			info.lastUpdate = ann.timestamp;
		}
		return info;
	}

	getGraphChannel(scid: string): GraphChannelInfo | null {
		const scidBuf = parseScid(scid);
		const channel = this.node.getGraph().getChannel(scidBuf);
		if (!channel) return null;
		return this.toGraphChannelInfo(channel);
	}

	/** Paged dump of known graph channels (limit is capped at 500). */
	describeGraph(limit?: number, offset?: number): GraphDescribeResult {
		const cappedLimit = Math.min(
			Math.max(1, Math.floor(limit ?? GRAPH_DESCRIBE_MAX_LIMIT)),
			GRAPH_DESCRIBE_MAX_LIMIT
		);
		const safeOffset = Math.max(0, Math.floor(offset ?? 0));
		const all = this.node.getGraph().getAllChannels();
		return {
			totalChannels: all.length,
			limit: cappedLimit,
			offset: safeOffset,
			channels: all
				.slice(safeOffset, safeOffset + cappedLimit)
				.map((ch) => this.toGraphChannelInfo(ch))
		};
	}

	private toGraphChannelInfo(channel: IGraphChannel): GraphChannelInfo {
		const info: GraphChannelInfo = {
			shortChannelId: formatScid(channel.shortChannelId),
			node1Pubkey: channel.nodeId1.toString('hex'),
			node2Pubkey: channel.nodeId2.toString('hex')
		};
		// Capacity is not gossiped; the larger advertised htlc_maximum_msat is
		// the best known lower bound.
		const max1 = channel.update1?.htlcMaximumMsat;
		const max2 = channel.update2?.htlcMaximumMsat;
		const best = (max1 ?? 0n) > (max2 ?? 0n) ? max1 : max2;
		if (best !== undefined) info.capacitySats = Number(best / 1000n);
		if (channel.update1) {
			info.node1Policy = this.toGraphChannelPolicy(channel.update1);
		}
		if (channel.update2) {
			info.node2Policy = this.toGraphChannelPolicy(channel.update2);
		}
		return info;
	}

	private toGraphChannelPolicy(
		update: IChannelUpdateMessage
	): GraphChannelPolicy {
		const policy: GraphChannelPolicy = {
			feeBaseMsat: update.feeBaseMsat,
			feeProportionalMillionths: update.feeProportionalMillionths,
			cltvExpiryDelta: update.cltvExpiryDelta,
			htlcMinimumMsat: update.htlcMinimumMsat.toString(),
			disabled: (update.channelFlags & CHANNEL_FLAG_DISABLED) !== 0,
			lastUpdate: update.timestamp
		};
		if (update.htlcMaximumMsat !== undefined) {
			policy.htlcMaximumMsat = update.htlcMaximumMsat.toString();
		}
		return policy;
	}

	/**
	 * Compute a route to a destination WITHOUT sending. The returned hops mirror
	 * the shape POST /payment/send-to-route accepts, so the two compose.
	 */
	queryRoute(
		destination: string,
		amountSats: number,
		maxFeeSats?: number
	): RouteQueryResult {
		if (!/^[0-9a-fA-F]{66}$/.test(destination)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'destination must be a 33-byte hex string'
			);
		}
		if (!Number.isInteger(amountSats) || amountSats <= 0) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'amountSats must be a positive integer'
			);
		}
		// Checked here rather than at the comparison below, which only runs
		// when a route was found: a bad ceiling is the caller's mistake either
		// way, and it used to reach BigInt() unguarded (issue #474).
		if (maxFeeSats !== undefined) {
			requireNonNegativeSafeInteger(maxFeeSats, 'maxFeeSats');
		}
		const amountMsat = BigInt(amountSats) * 1000n;
		const route = this.node.queryRoute(
			Buffer.from(destination, 'hex'),
			amountMsat,
			DEFAULT_MIN_FINAL_CLTV_EXPIRY
		);
		if (!route) {
			throw new BeignetError(
				BeignetErrorCode.NO_ROUTE,
				'No route found to destination'
			);
		}
		if (
			maxFeeSats !== undefined &&
			route.totalFeeMsat > BigInt(maxFeeSats) * 1000n
		) {
			throw new BeignetError(
				'FEE_EXCEEDS_MAX',
				`Route fee ${route.totalFeeMsat} msat exceeds maximum ${maxFeeSats} sats`
			);
		}
		return {
			destination,
			amountSats,
			hops: routeHopsToJson(route),
			totalAmountMsat: route.totalAmountMsat.toString(),
			totalFeeMsat: route.totalFeeMsat.toString(),
			totalCltvDelta: route.totalCltvDelta,
			finalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY
		};
	}

	/**
	 * Send a payment along an explicit route (from queryRoute / POST
	 * /route/query). paymentSecret is required by most modern invoices.
	 */
	sendToRoute(
		paymentHash: string,
		route: { hops: RouteHop[] },
		paymentSecret?: string
	): PaymentInfo {
		if (!/^[0-9a-fA-F]{64}$/.test(paymentHash)) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'paymentHash must be a 32-byte hex string'
			);
		}
		if (!route || !Array.isArray(route.hops) || route.hops.length === 0) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'route.hops must be a non-empty array'
			);
		}
		if (
			paymentSecret !== undefined &&
			!/^[0-9a-fA-F]{64}$/.test(paymentSecret)
		) {
			throw new BeignetError(
				BeignetErrorCode.INVALID_PARAMS,
				'paymentSecret must be a 32-byte hex string'
			);
		}
		this._checkDraining();
		const hops = jsonToRouteHops(route.hops);
		const finalHop = hops[hops.length - 1];
		try {
			const payment = this.node.sendPaymentToRoute(
				{ hops },
				Buffer.from(paymentHash, 'hex'),
				finalHop.outgoingCltvValue,
				paymentSecret ? Buffer.from(paymentSecret, 'hex') : undefined,
				finalHop.amountToForwardMsat
			);
			return this.toPaymentInfo(payment);
		} catch (err) {
			if (err instanceof BeignetError) throw err;
			// Surface library payment errors (NO_CHANNEL_TO_HOP, ...) by code
			const code =
				err !== null && typeof err === 'object' && 'code' in err
					? String((err as { code: unknown }).code)
					: 'PAYMENT_FAILED';
			throw new BeignetError(
				code,
				err instanceof Error ? err.message : String(err)
			);
		}
	}

	// ─────────────── Channel Readiness Helpers ───────────────

	getReadyChannels(): ChannelInfo[] {
		return this.node
			.listChannels()
			.filter((ch) => ch.state === ChannelState.NORMAL && !isHeldRestore(ch))
			.map((ch) => this.toChannelInfo(ch));
	}

	canSend(amountSats: number): {
		canSend: boolean;
		bestChannelId?: string;
		availableSats: number;
	} {
		// The routes reach this through parseIntParam, but an SDK caller does
		// not, and a fractional amount threw out of BigInt() (issue #474).
		const amountMsat =
			BigInt(requireNonNegativeSafeInteger(amountSats, 'amountSats')) * 1000n;
		let bestChannel: ChannelInfo | null = null;
		let bestAvailableMsat = 0n;
		let totalAvailableMsat = 0n;

		for (const ch of this.node.listChannels()) {
			if (ch.state !== ChannelState.NORMAL || isHeldRestore(ch)) continue;
			// Subtract channel reserve — we must maintain this minimum balance
			const reserveMsat = ch.localReserveMsat ?? 0n;
			const available =
				ch.localBalanceMsat > reserveMsat
					? ch.localBalanceMsat - reserveMsat
					: 0n;
			totalAvailableMsat += available;
			if (available > bestAvailableMsat) {
				bestAvailableMsat = available;
				bestChannel = this.toChannelInfo(ch);
			}
		}

		return {
			canSend: bestAvailableMsat >= amountMsat,
			bestChannelId: bestChannel?.channelId,
			availableSats: Number(totalAvailableMsat / 1000n)
		};
	}

	canReceive(amountSats: number): {
		canReceive: boolean;
		bestChannelId?: string;
		availableSats: number;
	} {
		// Same as canSend: guarded for the SDK callers the route parsing does
		// not cover (issue #474).
		const amountMsat =
			BigInt(requireNonNegativeSafeInteger(amountSats, 'amountSats')) * 1000n;
		let bestChannel: ChannelInfo | null = null;
		let bestAvailableMsat = 0n;
		let totalAvailableMsat = 0n;

		for (const ch of this.node.listChannels()) {
			if (ch.state !== ChannelState.NORMAL || isHeldRestore(ch)) continue;
			// Subtract channel reserve — remote must maintain this minimum balance
			const reserveMsat = ch.remoteReserveMsat ?? 0n;
			const available =
				ch.remoteBalanceMsat > reserveMsat
					? ch.remoteBalanceMsat - reserveMsat
					: 0n;
			totalAvailableMsat += available;
			if (available > bestAvailableMsat) {
				bestAvailableMsat = available;
				bestChannel = this.toChannelInfo(ch);
			}
		}

		return {
			canReceive: bestAvailableMsat >= amountMsat,
			bestChannelId: bestChannel?.channelId,
			availableSats: Number(totalAvailableMsat / 1000n)
		};
	}

	// ─────────────── Payment Metadata ───────────────

	setPaymentMetadata(
		paymentHash: string,
		metadata: Record<string, string>
	): void {
		this.node.setPaymentMetadata(Buffer.from(paymentHash, 'hex'), metadata);
	}

	// ─────────────── Payment Queue ───────────────

	private getPaymentQueue(): PaymentQueue {
		if (!this.paymentQueue) {
			this.paymentQueue = new PaymentQueue(
				(bolt11, timeout, maxFee, amount, meta) =>
					this.payInvoiceSafe(bolt11, timeout, maxFee, amount, meta),
				(amount) => this.canSend(amount),
				undefined,
				this.storage
			);
		}
		return this.paymentQueue;
	}

	enqueuePayment(
		bolt11: string,
		priority?: number,
		opts?: {
			amountSats?: number;
			maxFeeSats?: number;
			metadata?: Record<string, string>;
		}
	): QueuedPayment {
		return this.getPaymentQueue().enqueue(bolt11, priority, opts);
	}

	listQueue(): QueuedPayment[] {
		return this.getPaymentQueue().list();
	}

	cancelQueuedPayment(id: string): boolean {
		return this.getPaymentQueue().cancel(id);
	}

	// ─────────────── Statistics ───────────────

	getStats(windowMs?: number): NodeStats {
		const payments = this.node.listPayments();
		const now = Date.now();
		let sent = 0;
		let received = 0;
		let failed = 0;
		let satsSent = 0;
		let satsReceived = 0;
		let feesPaid = 0;
		let totalPaymentTimeMs = 0;
		let completedWithTimeCount = 0;
		let totalFeePct = 0;
		let feePctCount = 0;

		for (const p of payments) {
			// Apply time window filter
			if (windowMs !== undefined && now - p.createdAt > windowMs) continue;

			if (p.direction === 'OUTGOING' && p.status === 'COMPLETED') {
				sent++;
				satsSent += Number(p.amountMsat / 1000n);
				if (p.route?.totalFeeMsat !== undefined) {
					const fee = Number(p.route.totalFeeMsat / 1000n);
					feesPaid += fee;
					if (p.amountMsat > 0n) {
						totalFeePct +=
							(Number(p.route.totalFeeMsat) / Number(p.amountMsat)) * 100;
						feePctCount++;
					}
				}
				if (p.completedAt && p.createdAt) {
					totalPaymentTimeMs += p.completedAt - p.createdAt;
					completedWithTimeCount++;
				}
			} else if (p.direction === 'INCOMING' && p.status === 'COMPLETED') {
				received++;
				satsReceived += Number(p.amountMsat / 1000n);
			} else if (p.status === 'FAILED') {
				failed++;
			}
		}

		const totalAttempts = sent + failed;
		const successRate = totalAttempts > 0 ? sent / totalAttempts : 0;

		const stats: NodeStats = {
			totalPaymentsSent: sent,
			totalPaymentsReceived: received,
			totalPaymentsFailed: failed,
			totalSatsSent: satsSent,
			totalSatsReceived: satsReceived,
			totalFeesPaid: feesPaid,
			successRate: Math.round(successRate * 10000) / 10000, // 4 decimal places
			uptimeMs: Date.now() - this.startedAt
		};

		if (windowMs !== undefined) {
			stats.windowMs = windowMs;
		}

		if (completedWithTimeCount > 0) {
			stats.avgPaymentTimeSec =
				Math.round((totalPaymentTimeMs / completedWithTimeCount / 1000) * 100) /
				100;
		}

		if (feePctCount > 0) {
			stats.avgFeePct = Math.round((totalFeePct / feePctCount) * 100) / 100;
		}

		return stats;
	}

	// ─────────────── Action Log ───────────────

	getActionLog(options?: {
		category?: string;
		since?: number;
		limit?: number;
	}): ActionLogEntry[] {
		return this.node.getActionLog(options);
	}

	// ─────────────── Prometheus Metrics ───────────────

	getMetrics(): string {
		const lines: string[] = [];
		const health = this.getHealth();
		const balance = this.getBalance();
		const stats = this.getStats();
		const channels = this.node.listChannels();

		// Channel counts by state
		const stateCounts: Record<string, number> = {};
		for (const ch of channels) {
			stateCounts[ch.state] = (stateCounts[ch.state] || 0) + 1;
		}
		lines.push('# HELP beignet_channels_total Number of channels by state');
		lines.push('# TYPE beignet_channels_total gauge');
		for (const [state, count] of Object.entries(stateCounts)) {
			lines.push(`beignet_channels_total{state="${state}"} ${count}`);
		}
		if (Object.keys(stateCounts).length === 0) {
			lines.push('beignet_channels_total{state="NONE"} 0');
		}

		// Payment counts
		lines.push(
			'# HELP beignet_payments_total Total payments by status and direction'
		);
		lines.push('# TYPE beignet_payments_total gauge');
		lines.push(
			`beignet_payments_total{status="COMPLETED",direction="OUTGOING"} ${stats.totalPaymentsSent}`
		);
		lines.push(
			`beignet_payments_total{status="COMPLETED",direction="INCOMING"} ${stats.totalPaymentsReceived}`
		);
		lines.push(
			`beignet_payments_total{status="FAILED",direction="OUTGOING"} ${stats.totalPaymentsFailed}`
		);

		// Balance
		lines.push('# HELP beignet_balance_sats Balance in satoshis by type');
		lines.push('# TYPE beignet_balance_sats gauge');
		lines.push(`beignet_balance_sats{type="onchain"} ${balance.onchain}`);
		lines.push(`beignet_balance_sats{type="lightning"} ${balance.lightning}`);
		lines.push(`beignet_balance_sats{type="total"} ${balance.total}`);

		// Electrum connected
		lines.push(
			'# HELP beignet_electrum_connected Whether Electrum backend is connected'
		);
		lines.push('# TYPE beignet_electrum_connected gauge');
		lines.push(
			`beignet_electrum_connected ${health.electrumConnected ? 1 : 0}`
		);

		// Peer count
		lines.push('# HELP beignet_peers_connected Number of connected peers');
		lines.push('# TYPE beignet_peers_connected gauge');
		lines.push(`beignet_peers_connected ${health.peerCount}`);

		// Uptime
		lines.push('# HELP beignet_uptime_seconds Node uptime in seconds');
		lines.push('# TYPE beignet_uptime_seconds gauge');
		lines.push(
			`beignet_uptime_seconds ${Math.floor(
				(Date.now() - this.startedAt) / 1000
			)}`
		);

		// Block height
		lines.push('# HELP beignet_block_height Current block height');
		lines.push('# TYPE beignet_block_height gauge');
		lines.push(`beignet_block_height ${health.blockHeight}`);

		// Success rate
		lines.push(
			'# HELP beignet_payment_success_rate Payment success rate (0-1)'
		);
		lines.push('# TYPE beignet_payment_success_rate gauge');
		lines.push(`beignet_payment_success_rate ${stats.successRate}`);

		// Fees paid
		lines.push(
			'# HELP beignet_fees_paid_sats Total routing fees paid in satoshis'
		);
		lines.push('# TYPE beignet_fees_paid_sats counter');
		lines.push(`beignet_fees_paid_sats ${stats.totalFeesPaid}`);

		// Graph size
		lines.push('# HELP beignet_graph_nodes Number of nodes in gossip graph');
		lines.push('# TYPE beignet_graph_nodes gauge');
		lines.push(`beignet_graph_nodes ${health.graphNodes}`);
		lines.push(
			'# HELP beignet_graph_channels Number of channels in gossip graph'
		);
		lines.push('# TYPE beignet_graph_channels gauge');
		lines.push(`beignet_graph_channels ${health.graphChannels}`);

		return lines.join('\n') + '\n';
	}

	// ─────────────── Database Backup ───────────────

	async backup(destPath: string): Promise<void> {
		await this.storage.backup(destPath);
	}

	private performScheduledBackup(): void {
		if (!this.backupPath || this.destroyed) return;
		this._backupPromise = this.storage
			.backup(this.backupPath)
			.then(() => {
				this.log('info', 'Scheduled backup completed', {
					path: this.backupPath
				});
				this.emit('backup:completed', {
					path: this.backupPath!,
					timestamp: Date.now()
				});
			})
			.catch((err: Error) => {
				this.log('error', 'Scheduled backup failed', {
					path: this.backupPath,
					error: err.message
				});
				this.emit('backup:failed', {
					path: this.backupPath!,
					error: err.message,
					timestamp: Date.now()
				});
			})
			.finally(() => {
				this._backupPromise = undefined;
			});
	}

	/** Trigger an on-demand backup (if backupPath is configured) */
	triggerBackup(): void {
		this.performScheduledBackup();
	}

	// ─────────────── Static Channel Backup ───────────────

	/**
	 * Build, encrypt, and persist the static channel backup. The blob is
	 * encrypted under the BIP39 seed of the wallet mnemonic (same seed material
	 * as storage encryption), written atomically to <dataDir>/channels.scb, and
	 * also returned for out-of-band storage.
	 */
	exportStaticChannelBackup(): {
		encoded: string;
		channelCount: number;
		path: string;
	} {
		const data = this.node.buildStaticChannelBackupData();
		const backup: IStaticChannelBackup = {
			version: 1,
			network: data.network,
			createdAt: Date.now(),
			channels: data.channels
		};
		const seed = bip39.mnemonicToSeedSync(this.mnemonic);
		const encoded = encodeScb(backup, seed);
		const scbPath = path.join(this.dataDir, 'channels.scb');
		// Atomic write: a crash mid-write must never leave a truncated backup.
		const tmpPath = `${scbPath}.tmp`;
		fs.writeFileSync(tmpPath, encoded);
		fs.renameSync(tmpPath, scbPath);
		return { encoded, channelCount: data.channels.length, path: scbPath };
	}

	/**
	 * Restore channels from an encoded static channel backup blob.
	 *
	 * Decrypts the blob with this wallet's seed (the SCB is only decodable with
	 * the mnemonic that created it), refuses a backup taken on a different
	 * network, and hands the entries to the library recovery flow: each unknown
	 * channel is reconstructed in a broadcast-banned ERRORED state, its funding
	 * outpoint is watched, and funds arrive on-chain when the peer force-closes.
	 */
	async restoreFromScb(encoded: string): Promise<{
		recovering: string[];
		skipped: Array<{ channelId: string; reason: string }>;
		channelCount: number;
	}> {
		const seed = bip39.mnemonicToSeedSync(this.mnemonic);
		const backup = decodeScb(encoded.trim(), seed);
		const expectedNetwork = this.toLnNetwork(this.networkName);
		if (backup.network !== expectedNetwork) {
			throw new BeignetError(
				'INVALID_PARAMS',
				`SCB network "${backup.network}" does not match this node's network "${expectedNetwork}"`
			);
		}
		const { recovering, skipped } =
			await this.node.recoverFromStaticChannelBackup(backup.channels);
		this.log('info', 'SCB restore processed', {
			channelCount: backup.channels.length,
			recovering: recovering.length,
			skipped: skipped.length
		});
		return { recovering, skipped, channelCount: backup.channels.length };
	}

	/**
	 * Re-export the SCB after a channel-set change. A backup failure must never
	 * crash the node, so failures only log a warning. When peer storage is
	 * enabled, the fresh blob is also pushed to every connected peer that
	 * advertises option_provide_storage (and to capable peers on connect).
	 */
	private refreshStaticChannelBackup(): void {
		if (this.destroyed || this._restartRequired) return;
		try {
			const { encoded, channelCount } = this.exportStaticChannelBackup();
			if (!this.peerStorageEnabled) return;
			// With a recovery mode on, the library's Recovery Capsule (which
			// embeds this same SCB) is the blob storage peers hold, on its own
			// rate-limited schedule; pushing the plain SCB beside it would just
			// race it for the one slot a provider keeps (issue #453).
			if (this.recoveryNodeConfig?.enabled) return;
			// An empty backup can only destroy a provider's last good copy, and
			// a seed-restored node connects to its old peers precisely to get
			// that copy back. Push empties only after a real backup went out
			// this run (the last channel closed: a truthful update).
			if (channelCount === 0 && !this._pushedChannelBackup) return;
			const sent = this.node.distributePeerStorage(
				Buffer.from(encoded, 'utf8')
			);
			if (channelCount > 0) this._pushedChannelBackup = true;
			if (sent > 0) {
				this.log('debug', 'Pushed SCB to peer storage', { peers: sent });
			}
		} catch (err) {
			this.log('warn', 'Static channel backup refresh failed', {
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	/**
	 * Validate a peer-returned storage blob as OUR seed-encrypted SCB and keep
	 * the newest valid one. Undecodable blobs are ignored: peers are untrusted
	 * and may return anything.
	 */
	private handleRetrievedPeerStorage(peerPubkey: string, blob: Buffer): void {
		// A Recovery Capsule (spec 5.4) is what a node in any recovery mode
		// pushes; it embeds an SCB, so Tier 1 never regresses when the blob
		// a peer returns happens to be the capsule (issue #453). Both the
		// capsule and its SCB are keyed by the node secret, not the wallet
		// seed the plain SCB uses.
		const capsule = decodeRecoveryCapsuleBlob(blob, this.nodeSecret());
		if (capsule) {
			let embedded: IStaticChannelBackup;
			try {
				embedded = decodeScb(capsule.encryptedScb, this.nodeSecret());
			} catch {
				this.log(
					'debug',
					'Ignoring capsule whose embedded SCB does not decode',
					{
						fromPeer: peerPubkey
					}
				);
				return;
			}
			// Testnet, regtest and signet share a coin type, so a capsule from
			// this seed's node on another of those networks authenticates
			// here. It is not a candidate: left in, its head could win the
			// selection and fail the whole restore on the network check.
			if (
				!this.retrievedBackupMatchesNetwork(embedded, peerPubkey, 'capsule')
			) {
				return;
			}
			const held = this._peerRetrievedCapsules.get(peerPubkey);
			const inline = capsule.inlineRecoveryState !== undefined;
			// Higher head wins. At an equal head a replica carrying the inline
			// Tier 2 journal is never displaced by an SCB-only twin (the same
			// node composes both shapes of one head when a re-base fails).
			if (
				!held ||
				capsule.writerEpoch > held.writerEpoch ||
				(capsule.writerEpoch === held.writerEpoch &&
					capsule.latestSequence > held.latestSequence) ||
				(capsule.writerEpoch === held.writerEpoch &&
					capsule.latestSequence === held.latestSequence &&
					(inline || !held.inline))
			) {
				this._peerRetrievedCapsules.set(peerPubkey, {
					blob: Buffer.from(blob),
					writerEpoch: capsule.writerEpoch,
					latestSequence: capsule.latestSequence,
					inline,
					channelCount: embedded.channels.length,
					guardians: capsule.guardians,
					receivedAt: Date.now()
				});
				this.log('info', 'Recovered capsule from peer storage', {
					fromPeer: peerPubkey,
					writerEpoch: capsule.writerEpoch.toString(),
					latestSequence: capsule.latestSequence.toString(),
					inline,
					channelCount: embedded.channels.length,
					guardians: capsule.guardians.length
				});
				// The capsule's locators are reported, never adopted: a set
				// that disagrees with the configured one is a stale
				// pre-enablement capsule or an operator error (set replacement
				// does not exist in v1, wire 5.9), and either way the operator
				// decides. Warn once per change of set from this peer, not on
				// every equal-head re-send after a reconnect.
				if (
					this.recoveryGuardianSet.length > 0 &&
					!sameGuardianIds(
						capsule.guardians.map((g) => g.guardianId),
						this.recoveryGuardianSet.map((g) => g.guardianId.toString('hex'))
					) &&
					(!held ||
						!sameGuardianIds(
							capsule.guardians.map((g) => g.guardianId),
							held.guardians.map((g) => g.guardianId)
						))
				) {
					this.log(
						'warn',
						'Retrieved capsule names a guardian set that differs from ' +
							'the configured one; the configured set stays in force',
						{
							fromPeer: peerPubkey,
							capsule: redactGuardians(capsule.guardians),
							configured: this.recoveryGuardianSet.map((g) => ({
								guardianId: g.guardianId.toString('hex'),
								url: g.url
							}))
						}
					);
				}
			}
			// Surface the Tier 1 material under the wallet seed, the key
			// restoreFromScb (POST /restore/scb) decodes with.
			const seed = bip39.mnemonicToSeedSync(this.mnemonic);
			this.offerRetrievedScb(
				encodeScb(embedded, seed),
				embedded,
				peerPubkey,
				'capsule'
			);
			return;
		}
		let backup: IStaticChannelBackup;
		const encoded = blob.toString('utf8');
		try {
			const seed = bip39.mnemonicToSeedSync(this.mnemonic);
			backup = decodeScb(encoded, seed);
		} catch {
			this.log('debug', 'Ignoring peer storage blob that is not our SCB', {
				fromPeer: peerPubkey
			});
			return;
		}
		if (!this.retrievedBackupMatchesNetwork(backup, peerPubkey, 'scb')) return;
		this.offerRetrievedScb(encoded, backup, peerPubkey, 'scb');
	}

	/** A retrieved backup from another network is ignored, not kept. */
	private retrievedBackupMatchesNetwork(
		backup: IStaticChannelBackup,
		fromPeer: string,
		source: 'scb' | 'capsule'
	): boolean {
		const expected = this.toLnNetwork(this.networkName);
		if (backup.network === expected) return true;
		this.log('debug', 'Ignoring peer storage backup from another network', {
			fromPeer,
			source,
			network: backup.network,
			expected
		});
		return false;
	}

	/**
	 * Keep the most useful retrieved SCB: newest by createdAt, except that an
	 * empty backup never displaces one with channels. A seed-restored node
	 * pushes nothing while empty (refreshStaticChannelBackup), but a peer
	 * may still hold an empty blob from a session that closed its last
	 * channel, and for a restore the copy that names channels is the one
	 * worth keeping (recovering an already-closed channel is harmless).
	 */
	private offerRetrievedScb(
		encoded: string,
		backup: IStaticChannelBackup,
		fromPeer: string,
		source: 'scb' | 'capsule'
	): void {
		const held = this._peerRetrievedScb;
		if (held) {
			if (backup.channels.length === 0 && held.channelCount > 0) return;
			if (
				held.createdAt >= backup.createdAt &&
				!(held.channelCount === 0 && backup.channels.length > 0)
			) {
				return;
			}
		}
		this._peerRetrievedScb = {
			encoded,
			createdAt: backup.createdAt,
			fromPeer,
			channelCount: backup.channels.length,
			source
		};
		this.log('info', 'Recovered SCB from peer storage', {
			fromPeer,
			source,
			createdAt: backup.createdAt,
			channelCount: backup.channels.length
		});
	}

	/**
	 * Newest valid SCB a peer has returned via BOLT 1 peer storage this
	 * session (directly, or embedded in a Recovery Capsule), or null.
	 * Recovery stays explicit: feed `encoded` to restoreFromScb (daemon:
	 * POST /restore/scb) when recovering.
	 */
	getPeerRetrievedBackup(): {
		encoded: string;
		createdAt: number;
		fromPeer: string;
		channelCount: number;
		source: 'scb' | 'capsule';
	} | null {
		return this._peerRetrievedScb;
	}

	// ─────────────── Node URI ───────────────

	getNodeUri(externalHost?: string): string | null {
		if (!this._listenPort) return null;
		const info = this.node.getNodeInfo();
		const host = externalHost || '127.0.0.1';
		return `${info.nodeId}@${host}:${this._listenPort}`;
	}

	// ─────────────── Node Access ───────────────

	getNode(): LightningNode {
		return this.node;
	}

	/** Access the underlying SqliteStorage — used by daemon for webhook/queue persistence. */
	getStorage(): SqliteStorage {
		return this.storage;
	}

	// ─────────────── Lifecycle ───────────────

	async gracefulShutdown(timeoutMs = 30_000): Promise<void> {
		if (this.destroyed) return;
		this.destroyed = true;
		if (this.backupTimer) {
			clearInterval(this.backupTimer);
			this.backupTimer = undefined;
		}
		if (this._sweepRefreshTimer) {
			clearInterval(this._sweepRefreshTimer);
			this._sweepRefreshTimer = undefined;
		}
		if (this._fallbackRecoveryTimer) {
			clearInterval(this._fallbackRecoveryTimer);
			this._fallbackRecoveryTimer = undefined;
		}
		this.paymentQueue?.removeAllListeners();
		this.directFundingSender?.stop();
		if (this._confirmTimer) {
			clearTimeout(this._confirmTimer);
			this._confirmTimer = undefined;
		}
		this.stopRecoveryLeaseCheck();
		// Await any in-flight backup before closing storage
		if (this._backupPromise) {
			await this._backupPromise.catch(() => {
				/* best-effort: backup errors already surface via backup:failed */
			});
		}
		// A restore-pending daemon never built the node or the wallet.
		await (this.node as LightningNode | undefined)?.gracefulShutdown(timeoutMs);
		this.storage.close();
		this.removeAllListeners();
		try {
			await (this.wallet as Wallet | undefined)?.stop();
		} catch {
			// Ignore shutdown errors
		}
		this.releaseLock();
	}

	async destroy(): Promise<void> {
		if (this.destroyed) return;
		this.destroyed = true;
		if (this.backupTimer) {
			clearInterval(this.backupTimer);
			this.backupTimer = undefined;
		}
		if (this._sweepRefreshTimer) {
			clearInterval(this._sweepRefreshTimer);
			this._sweepRefreshTimer = undefined;
		}
		if (this._fallbackRecoveryTimer) {
			clearInterval(this._fallbackRecoveryTimer);
			this._fallbackRecoveryTimer = undefined;
		}
		if (this._confirmTimer) {
			clearTimeout(this._confirmTimer);
			this._confirmTimer = undefined;
		}
		this.stopRecoveryLeaseCheck();
		this.paymentQueue?.removeAllListeners();
		this.directFundingSender?.stop();
		// A restore-pending daemon never built the node or the wallet; the
		// definite-assignment assertions on the fields do not change that.
		(this.node as LightningNode | undefined)?.destroy();
		this.storage.close();
		this.removeAllListeners();
		try {
			await (this.wallet as Wallet | undefined)?.stop();
		} catch {
			// Ignore shutdown errors
		}
		this.releaseLock();
	}

	/** Release the single-instance lock and detach its exit handler. */
	private releaseLock(): void {
		if (this._lockExitHandler) {
			process.removeListener('exit', this._lockExitHandler);
			this._lockExitHandler = null;
		}
		if (this._lockPath) {
			releaseInstanceLock(this._lockPath);
			this._lockPath = null;
		}
	}

	// ─────────────── Internal Helpers ───────────────

	private toBeignetNetwork(network: string): EAvailableNetworks {
		switch (network) {
			case 'mainnet':
				return EAvailableNetworks.bitcoin;
			case 'testnet':
				return EAvailableNetworks.testnet;
			case 'regtest':
				return EAvailableNetworks.regtest;
			case 'signet':
				return EAvailableNetworks.signet;
			default:
				return EAvailableNetworks.bitcoin;
		}
	}

	private toLnNetwork(network: string): Network {
		switch (network) {
			case 'mainnet':
				return Network.MAINNET;
			case 'testnet':
				return Network.TESTNET;
			case 'regtest':
				return Network.REGTEST;
			case 'signet':
				return Network.SIGNET;
			default:
				return Network.MAINNET;
		}
	}

	private toCoinType(network: string): number {
		switch (network) {
			case 'mainnet':
				return LnCoinType.BITCOIN;
			case 'testnet':
				return LnCoinType.TESTNET;
			case 'regtest':
				return LnCoinType.REGTEST;
			case 'signet':
				return LnCoinType.SIGNET;
			default:
				return LnCoinType.BITCOIN;
		}
	}

	private getBitcoinNetwork(): unknown {
		// getBitcoinJsNetwork covers signet, which bitcoinjs-lib's networks
		// object lacks.
		return getBitcoinJsNetwork(this.toBeignetNetwork(this.networkName));
	}
}
