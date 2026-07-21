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
import { ISendTransaction } from '../types/wallet';
import { ILogger, TLogLevel, LOG_LEVEL_PRIORITY } from '../logger';
import { generateMnemonic, getBitcoinJsNetwork } from '../utils/helpers';
import { btcToSats } from '../utils/conversion';
import {
	EAvailableNetworks,
	EBoostType,
	EPaymentType,
	IFormattedTransaction,
	IOnchainFees
} from '../types/wallet';
import { createWalletStorage } from './wallet-storage';
import { EProtocol } from '../types/electrum';
import { LightningNode } from '../lightning/node/lightning-node';
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
import { LnCoinType } from '../lightning/keys/wallet-keys';
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
	TOnchainQuote
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
	 * (payInvoice/sendKeysend) AND external on-chain sends (sendOnchain and
	 * sendMaxOnchain, counted as amount + fee). Excluded by design:
	 * consolidateUtxos (self-pay), channel opens/splices/funding, and
	 * bumpFeeOnchain/boostOnchain (fee-only). Resets at midnight UTC.
	 * NOTE: before v0.3.0 this limit covered Lightning only.
	 */
	dailySpendLimitSats?: number;
	/** Maximum amount in satoshis for a single payment. Rejects any payInvoice/sendKeysend call exceeding this. Prevents accidental large payments. */
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

const DEFAULT_DATA_DIR = path.join(
	process.env.HOME || process.env.USERPROFILE || '.',
	'.beignet',
	'data'
);

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
	baseDir: string = DEFAULT_DATA_DIR
): string {
	const walletTag = crypto
		.createHash('sha256')
		.update(mnemonic.normalize('NFKD').trim())
		.digest('hex')
		.slice(0, 16);
	return path.join(baseDir, walletTag);
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
	private _maxPaymentSats?: number;
	private _draining = false;
	private peerStorageEnabled = true;
	/** Epoch ms of the last gossip/RGS sync completed this session. */
	private _lastGraphSyncAt?: number;
	/** Newest VALID SCB a peer returned via peer storage (never auto-restored). */
	private _peerRetrievedScb: {
		encoded: string;
		createdAt: number;
		fromPeer: string;
	} | null = null;

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

		// 2. Acquire the single-instance lock before touching storage. Two
		// instances on one data dir share a node identity (peer churns the
		// duplicate connection → connect/disconnect storm) and one SQLite DB
		// (corruption risk). Opt out with allowMultipleInstances if you really
		// know the two instances won't collide.
		if (!opts.allowMultipleInstances) {
			const lockPath = path.join(this.dataDir, `${networkName}.lock`);
			try {
				acquireInstanceLock(lockPath);
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
			// reclaims a stale lock via PID liveness, so no manual cleanup is needed.
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
			const legacyDb = path.join(DEFAULT_DATA_DIR, `${networkName}.db`);
			if (fs.existsSync(legacyDb) && !fs.existsSync(dbPath)) {
				const legacyMsg =
					`[beignet] Found a legacy shared database at ${legacyDb}. ` +
					`Storage is now per-wallet (${dbPath}), so it is no longer auto-loaded. ` +
					`If it held this wallet's channels, re-run with dataDir set to "${DEFAULT_DATA_DIR}" to use it.`;
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
			...(opts.feeEstimationSource
				? { feeEstimationSource: opts.feeEstimationSource }
				: {}),
			electrumOptions: {
				net,
				tls,
				servers: electrumServer
			},
			disableMessagesOnCreate: true,
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
			electrumBackend.onFailoverNeeded = async () => {
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
		const sweepDestinationScript = await this.resolveWalletSweepScript();
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

		this.node = LightningNode.fromMnemonic(this.mnemonic, {
			coinType,
			network: lnNetwork,
			storage: this.storage,
			enableNetworking: true,
			autoReconnect: opts.autoReconnect ?? true,
			autoUpdateChannelFees: opts.autoUpdateChannelFees ?? false,
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
			watchtowers: opts.watchtowers
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
			this.log('info', 'Payment sent', {
				paymentHash: pi.paymentHash,
				amountSats: pi.amountSats,
				feeSats: pi.feeSats
			});
			this.emit('payment:sent', pi);
		});
		this.node.on('payment:failed', (info: IPaymentInfo) => {
			const pi = this.toPaymentInfo(info);
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
		// A resolved channel leaves the SCB channel set (state becomes CLOSED),
		// so refresh here too even though the event is not re-emitted.
		this.node.on('channel:resolved', () => {
			this.refreshStaticChannelBackup();
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
		// SSE/webhooks when htlcEvents is enabled).
		this.node.on(
			'htlc:forwarded',
			(data: {
				inChannelId: Buffer;
				outChannelId: Buffer;
				amountInMsat: bigint;
				amountOutMsat: bigint;
				feeMsat: bigint;
			}) => {
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
				try {
					this.node.initiateGossipSync(pubkey);
				} catch (err) {
					this.log('warn', 'Gossip sync failed to start', {
						pubkey,
						error: err instanceof Error ? err.message : String(err)
					});
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
		if (this.rapidGossipSync && this.networkName === 'mainnet') {
			this.syncRapidGossip().catch((err) => {
				this.log('warn', 'Rapid gossip sync failed', {
					error: err instanceof Error ? err.message : String(err)
				});
			});
		}

		// 13. Recover any funds stranded at the funding-key fallback address from
		// past force-close sweeps (sessions where no wallet address was available).
		// No-op when the fallback address is empty. Runs in the background, but
		// only once Electrum is actually connected — probing a still-connecting
		// socket otherwise surfaces a noisy "Connection to server lost" trace.
		if (this.sweepDestinationScript) {
			this.runFallbackRecoveryWhenConnected();
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
		const bitcoin = require('bitcoinjs-lib');
		// Preferred: a fresh, unused wallet address. This requires Electrum to
		// gap-scan for the next unused index.
		try {
			const res = await this.wallet.getNextAvailableAddress();
			if (res.isOk()) {
				return bitcoin.address.toOutputScript(
					res.value.addressIndex.address,
					this.getBitcoinNetwork()
				);
			}
		} catch {
			// fall through to deterministic derivation
		}
		// Fallback: deterministically derive a wallet-owned address (index 0) with
		// NO network dependency. Reusing index 0 is a minor privacy tradeoff, but
		// it guarantees force-close sweeps always target a wallet-scanned address
		// rather than the invisible funding-key P2WPKH — even when Electrum is down
		// at startup, which is exactly when an offline force-close is detected on
		// restart and a sweep gets built. recoverFallbackFunds remains a safety net
		// for funds stranded by older sessions.
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
	 * Request a gossip graph sync. Pass a peer pubkey to sync from that peer, or
	 * omit to sync from all connected peers. Populates the network graph so the
	 * node can route multi-hop payments to destinations beyond its direct peers.
	 * Returns the pubkeys synced from.
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
		max = false
	): ChannelInfo {
		const fundingSatoshis = BigInt(amountSats);
		const pushMsat =
			pushSats !== undefined ? BigInt(pushSats) * 1000n : undefined;
		const channel = this.node.openChannel(
			pubkey,
			fundingSatoshis,
			pushMsat,
			satsPerVbyte,
			max
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
			capacitySats: amountSats,
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
		opts?: { pushSats?: number; satsPerVbyte?: number; max?: boolean }
	): Promise<ChannelInfo> {
		await this.connectPeer(pubkey, host, port);
		return this.openChannel(
			pubkey,
			amountSats,
			opts?.pushSats,
			opts?.satsPerVbyte,
			opts?.max
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
			const promise = (async () => {
				try {
					// Look up address from gossip graph
					const graphNode = graph.getNode(
						Buffer.from(suggestion.nodeId, 'hex')
					);
					const addrs = graphNode?.announcement?.addresses;
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

	closeChannel(channelId: string): { ok: boolean; error?: string } {
		const idBuf = Buffer.from(channelId, 'hex');
		// Derive a P2WPKH script from the funding address for the closing output
		const address = this.node.getFundingAddress();
		const bitcoin = require('bitcoinjs-lib');
		const scriptPubkey = bitcoin.address.toOutputScript(
			address,
			this.getBitcoinNetwork()
		);
		return this.node.closeChannel(idBuf, scriptPubkey);
	}

	forceCloseChannel(channelId: string): {
		ok: boolean;
		error?: string;
		commitmentTxid?: string;
	} {
		const idBuf = Buffer.from(channelId, 'hex');
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
		const peerPubkey =
			this.node.getChannelManager().getPeerForChannel(channelIdBuf) || '';
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
		const htlcUsableThrough = channel.isHtlcUsable(true);
		if (
			state.state !== 'NORMAL' &&
			state.preReestablishState !== 'NORMAL' &&
			!htlcUsableThrough
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
			willGenerateRoutingHint:
				!!effectiveScid &&
				(state.state === 'NORMAL' ||
					state.preReestablishState === 'NORMAL' ||
					htlcUsableThrough),
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
		shortChannelId?: string;
		feeratePerKw?: number;
		htlcCount?: number;
		pendingSpliceLocalBalanceMsat?: bigint;
		htlcUsable?: boolean;
		payThroughSplice?: boolean;
		localReserveMsat?: bigint;
		remoteReserveMsat?: bigint;
		isPrivate?: boolean;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
		cltvExpiryDelta?: number;
		htlcMinimumMsat?: bigint;
		htlcMaximumMsat?: bigint;
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
		if (ch.fundingTxid) info.fundingTxid = ch.fundingTxid;
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
		return info;
	}

	// ─────────────── Invoices ───────────────

	createInvoice(
		amountSats?: number,
		description?: string,
		expirySecs?: number,
		descriptionHash?: Buffer
	): InvoiceInfo {
		const amountMsat =
			amountSats !== undefined && amountSats !== 0
				? BigInt(amountSats) * 1000n
				: undefined;
		const result = this.node.createInvoice({
			amountMsat,
			description: descriptionHash ? undefined : description || '',
			descriptionHash,
			expiry: expirySecs
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
				? BigInt(opts.amountSats) * 1000n
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
		const inv = decodeInvoice(bolt11);
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
		this._dailySpentSats += amountSats;
		if (source === 'onchain') {
			this._dailySpentOnchainSats += amountSats;
		} else {
			this._dailySpentLightningSats += amountSats;
		}
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

		const invoiceAmountSats =
			decoded.amountMsat !== undefined
				? Number(decoded.amountMsat / 1000n)
				: undefined;
		const effectiveAmountSats = amountSats ?? invoiceAmountSats;

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
		const decoded = decodeInvoice(bolt11);
		const paymentHashHex = decoded.paymentHash.toString('hex');

		// Per-payment and daily spending limit checks
		const spendAmountSats =
			amountSats ??
			(decoded.amountMsat !== undefined
				? Number(decoded.amountMsat / 1000n)
				: 0);
		if (spendAmountSats > 0) {
			this._checkMaxPayment(spendAmountSats);
			this._checkSpendLimit(spendAmountSats);
			this._pendingSpendSats += spendAmountSats;
		}

		const maxFeeMsat =
			maxFeeSats !== undefined ? BigInt(maxFeeSats) * 1000n : undefined;
		const amountMsat =
			amountSats !== undefined ? BigInt(amountSats) * 1000n : undefined;

		// Store metadata on the payment if provided
		if (metadata) {
			this.node.setPaymentMetadata(decoded.paymentHash, metadata);
		}

		return new Promise<PaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				if (spendAmountSats > 0) this._pendingSpendSats -= spendAmountSats;
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
			};

			const onSent = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					if (spendAmountSats > 0) {
						this._pendingSpendSats -= spendAmountSats;
						this._recordSpend(spendAmountSats);
					}
					resolve(this.toPaymentInfo(info));
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					if (spendAmountSats > 0) this._pendingSpendSats -= spendAmountSats;
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
		const decoded = decodeInvoice(bolt11);
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
	): { paymentHash: string; status: 'PENDING' } {
		const decoded = decodeInvoice(bolt11);
		const maxFeeMsat =
			maxFeeSats !== undefined ? BigInt(maxFeeSats) * 1000n : undefined;
		const amountMsat =
			amountSats !== undefined ? BigInt(amountSats) * 1000n : undefined;
		if (metadata) {
			this.node.setPaymentMetadata(decoded.paymentHash, metadata);
		}
		this.node.sendPayment(bolt11, undefined, maxFeeMsat, amountMsat);
		return {
			paymentHash: decoded.paymentHash.toString('hex'),
			status: 'PENDING'
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
		this._checkMaxPayment(amountSats);
		this._checkSpendLimit(amountSats);
		this._pendingSpendSats += amountSats;
		const destination = Buffer.from(pubkey, 'hex');
		const amountMsat = BigInt(amountSats) * 1000n;
		const maxFeeMsat =
			maxFeeSats !== undefined ? BigInt(maxFeeSats) * 1000n : undefined;

		const result = this.node.sendKeysend({
			destination,
			amountMsat,
			maxFeeMsat,
			metadata
		});
		const paymentHashHex = result.paymentHash.toString('hex');

		// If already settled synchronously
		if (result.status !== 'PENDING') {
			this._pendingSpendSats -= amountSats;
			if (result.status === 'COMPLETED') this._recordSpend(amountSats);
			return this.toPaymentInfo(result);
		}

		return new Promise<PaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
				this._pendingSpendSats -= amountSats;
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
					this._pendingSpendSats -= amountSats;
					this._recordSpend(amountSats);
					resolve(this.toPaymentInfo(info));
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					this._pendingSpendSats -= amountSats;
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
		if (policy.htlcMinimumMsat !== undefined)
			update.htlcMinimumMsat = BigInt(policy.htlcMinimumMsat);
		if (policy.htlcMaximumMsat !== undefined)
			update.htlcMaximumMsat = BigInt(policy.htlcMaximumMsat);

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
		const fundingSatoshis = BigInt(amountSats);
		const pushMsat =
			pushSats !== undefined ? BigInt(pushSats) * 1000n : undefined;
		const channel = this.node.openZeroConfChannel(
			peerPubkey,
			fundingSatoshis,
			pushMsat
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
		}
	): ChannelInfo {
		const channel = this.node.openChannelV2(peerPubkey, {
			fundingSatoshis: BigInt(params.amountSats),
			fundingFeeratePerkw: params.fundingFeeratePerkw,
			commitmentFeeratePerkw: params.commitmentFeeratePerkw,
			locktime: params.locktime
		});
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
		return this.node.spliceQuote(
			Buffer.from(channelId, 'hex'),
			direction,
			feeratePerkw
		);
	}

	spliceIn(
		channelId: string,
		amountSats: number,
		feeratePerkw: number
	): SpliceResult {
		const idBuf = Buffer.from(channelId, 'hex');
		const result = this.node.spliceIn(idBuf, BigInt(amountSats), feeratePerkw);
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
		const idBuf = Buffer.from(channelId, 'hex');
		let destinationScript: Buffer | undefined;
		if (destinationAddress) {
			const bitcoin = require('bitcoinjs-lib');
			destinationScript = bitcoin.address.toOutputScript(
				destinationAddress,
				this.getBitcoinNetwork()
			);
		}
		const result = this.node.spliceOut(
			idBuf,
			BigInt(amountSats),
			feeratePerkw,
			destinationScript
		);
		// The SCB is refreshed on the splice:complete event (when fundingTxid holds
		// the new outpoint), NOT here at initiation where it still holds the old one.
		return result;
	}

	// ─────────────── BOLT 12 Offers ───────────────

	decodeOfferString(offerStr: string): OfferInfo {
		const offer = decodeOffer(offerStr);
		return this.toOfferInfo(offer, offerStr);
	}

	createOffer(options: {
		description: string;
		amountSats?: number;
		issuer?: string;
	}): OfferInfo {
		const amountMsat =
			options.amountSats !== undefined
				? BigInt(options.amountSats) * 1000n
				: undefined;
		const { offer, encoded } = this.node.createOffer({
			description: options.description,
			amount: amountMsat,
			issuer: options.issuer
		});
		return this.toOfferInfo(offer, encoded);
	}

	listOffers(): OfferInfo[] {
		const mgr = this.node.getOfferManager();
		return mgr.listOffers().map((offer) => this.toOfferInfo(offer));
	}

	async payOffer(
		offerStr: string,
		amountSats?: number,
		timeoutMs = 60_000
	): Promise<PaymentInfo> {
		const offer = decodeOffer(offerStr);

		// Request invoice from the offer
		const requestOptions =
			amountSats !== undefined
				? { amount: BigInt(amountSats) * 1000n }
				: undefined;

		const bolt12Invoice = await this.node.requestInvoice(offer, requestOptions);
		const paymentHashHex = bolt12Invoice.paymentHash.toString('hex');

		return new Promise<PaymentInfo>((resolve, reject) => {
			const timer = setTimeout(() => {
				cleanup();
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
			};

			const onSent = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
					resolve(this.toPaymentInfo(info));
				}
			};
			const onFailed = (info: IPaymentInfo): void => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					cleanup();
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
			(ch) => ch.state === ChannelState.NORMAL
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
				ch.state === ChannelState.NORMAL || ch.state === ChannelState.SPLICING
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
		const readyChannels = channels.filter((ch) => ch.state === 'NORMAL');

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

	// ─────────────── Liquidity Advisor ───────────────

	getLiquiditySnapshot(): LiquiditySnapshot {
		const snapshot = this.node.getLiquiditySnapshot();
		// The reserve every channel holds back on our side is unspendable, so what
		// can actually be sent is the local balance above it, summed over routable
		// channels, the same figure canSend() reports. Surfacing both lets callers
		// show a true "can send" (zero while still below the reserve) instead of the
		// raw local balance, which overstates it.
		let reserveMsat = 0n;
		let sendableMsat = 0n;
		for (const ch of this.node.listChannels()) {
			if (ch.state !== ChannelState.NORMAL) continue;
			const chReserveMsat = ch.localReserveMsat ?? 0n;
			reserveMsat += chReserveMsat;
			sendableMsat +=
				ch.localBalanceMsat > chReserveMsat
					? ch.localBalanceMsat - chReserveMsat
					: 0n;
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
			.filter((ch) => ch.state === ChannelState.NORMAL)
			.map((ch) => this.toChannelInfo(ch));
	}

	canSend(amountSats: number): {
		canSend: boolean;
		bestChannelId?: string;
		availableSats: number;
	} {
		const amountMsat = BigInt(amountSats) * 1000n;
		let bestChannel: ChannelInfo | null = null;
		let bestAvailableMsat = 0n;
		let totalAvailableMsat = 0n;

		for (const ch of this.node.listChannels()) {
			if (ch.state !== ChannelState.NORMAL) continue;
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
		const amountMsat = BigInt(amountSats) * 1000n;
		let bestChannel: ChannelInfo | null = null;
		let bestAvailableMsat = 0n;
		let totalAvailableMsat = 0n;

		for (const ch of this.node.listChannels()) {
			if (ch.state !== ChannelState.NORMAL) continue;
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
		if (this.destroyed) return;
		try {
			const { encoded } = this.exportStaticChannelBackup();
			if (this.peerStorageEnabled) {
				const sent = this.node.distributePeerStorage(
					Buffer.from(encoded, 'utf8')
				);
				if (sent > 0) {
					this.log('debug', 'Pushed SCB to peer storage', { peers: sent });
				}
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
		if (
			this._peerRetrievedScb &&
			this._peerRetrievedScb.createdAt >= backup.createdAt
		) {
			return;
		}
		this._peerRetrievedScb = {
			encoded,
			createdAt: backup.createdAt,
			fromPeer: peerPubkey
		};
		this.log('info', 'Recovered SCB from peer storage', {
			fromPeer: peerPubkey,
			createdAt: backup.createdAt,
			channelCount: backup.channels.length
		});
	}

	/**
	 * Newest valid SCB a peer has returned via BOLT 1 peer storage this
	 * session, or null. Recovery stays explicit: feed `encoded` to
	 * restoreFromScb (daemon: POST /restore/scb) when recovering.
	 */
	getPeerRetrievedBackup(): {
		encoded: string;
		createdAt: number;
		fromPeer: string;
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
		// Await any in-flight backup before closing storage
		if (this._backupPromise) {
			await this._backupPromise.catch(() => {
				/* best-effort: backup errors already surface via backup:failed */
			});
		}
		await this.node.gracefulShutdown(timeoutMs);
		this.storage.close();
		this.removeAllListeners();
		try {
			await this.wallet.stop();
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
		this.paymentQueue?.removeAllListeners();
		this.node.destroy();
		this.storage.close();
		this.removeAllListeners();
		try {
			await this.wallet.stop();
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
