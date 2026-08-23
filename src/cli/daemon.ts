/**
 * HTTP daemon: lightweight http.createServer() on 127.0.0.1.
 * Routes HTTP endpoints to BeignetNode methods.
 * Uniform JSON envelope: { ok: true, result } or { ok: false, error: { code, message } }.
 */

import * as http from 'http';
import * as net from 'net';
import * as https from 'https';
import * as fs from 'fs';
import { Console } from 'console';
import {
	BeignetNode,
	BeignetNodeOptions,
	parseRecoveryMode
} from './beignet-node';
import { parseGuardianEntry } from '../lightning/recovery';
import { ILogger, createConsoleLogger } from '../logger';
import { BeignetError } from './errors';
import { L402Error } from '../lightning/l402';
import { ApiResponse, RouteHop } from './types';
import { getOpenApiSpec } from './openapi';
import { WebhookManager } from './webhooks';
import { PaymentQueue } from './payment-queue';
import {
	HttpRateLimiter,
	RateLimitOptions,
	clientKeyForRequest
} from './http-rate-limiter';
import { encodeBip21 } from '../utils/transaction';
import {
	ApiKeyAuthenticator,
	ApiKeyDefinition,
	AuthSuccess,
	AUTH_KEY_OVERRIDES_STORAGE_KEY,
	StoredKeyOverride,
	getRouteScopes,
	scopesAllowRoute
} from './auth';

export interface DaemonOptions extends BeignetNodeOptions {
	daemonPort?: number;
	daemonHost?: string;
	/** Legacy single bearer token. Still honored, with implicit admin scope. */
	apiToken?: string;
	/** Named API keys with permission scopes (readonly/invoice/admin). */
	apiKeys?: ApiKeyDefinition[];
	cors?: boolean | string;
	/** Optional rate limiting configuration. Disabled by default. */
	rateLimit?: RateLimitOptions;
	/** Path to TLS certificate file (PEM). Enables HTTPS when set with tlsKey. */
	tlsCert?: string;
	/** Path to TLS private key file (PEM). Required when tlsCert is set. */
	tlsKey?: string;
	/** Relay per-HTLC events (htlc:forwarded/fulfilled/failed) over SSE and
	 *  webhooks. Off by default: routing nodes generate one event per HTLC. */
	htlcEvents?: boolean;
	/** Serve GET /metrics without authentication (balances, channel and peer
	 *  counts). Off by default: metrics disclose finances to anyone who can
	 *  reach the port. */
	metricsPublic?: boolean;
	/** Escape hatch for deliberately insecure setups: allows a non-loopback
	 *  bind without authentication and wildcard CORS without authentication,
	 *  both refused at startup otherwise. */
	insecure?: boolean;
}

const MAX_BODY_BYTES = 1_048_576; // 1 MB
const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const IDEMPOTENCY_CLEANUP_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

interface CachedResponse {
	response: unknown;
	bodyHash: string;
	expiresAt: number;
}

const IDEMPOTENT_ROUTES = new Set([
	'POST /invoice/pay',
	'POST /invoice/pay-safe',
	'POST /invoice/pay-async',
	'POST /invoice/pay-retry',
	'POST /keysend',
	'POST /keysend/safe',
	// An L402 fetch pays an invoice, and a retried fetch gets a fresh
	// challenge with a fresh invoice, so an un-keyed retry pays twice.
	'POST /l402/fetch',
	// Fee-spending advisor execution: retries must not double-spend fees.
	'POST /rebalance',
	'POST /advisor/execute-rebalances'
]);

function success<T>(result: T): ApiResponse<T> {
	return { ok: true, result };
}

function failure(code: string, message: string): ApiResponse<never> {
	return { ok: false, error: { code, message } };
}

/** 403 message: which scopes the route accepts (admin always qualifies). */
function insufficientScopeMessage(auth: AuthSuccess, routeKey: string): string {
	const accepted = [...getRouteScopes(routeKey), 'admin'].join(', ');
	const who = auth.keyName === null ? 'API key' : `API key "${auth.keyName}"`;
	return `${who} lacks the required scope (accepted: ${accepted})`;
}

export async function parseBody(
	req: http.IncomingMessage
): Promise<Record<string, unknown>> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		let totalBytes = 0;
		req.on('data', (chunk: Buffer) => {
			totalBytes += chunk.length;
			if (totalBytes > MAX_BODY_BYTES) {
				req.destroy();
				reject(
					new BeignetError(
						'BODY_TOO_LARGE',
						`Request body exceeds ${MAX_BODY_BYTES} bytes`
					)
				);
				return;
			}
			chunks.push(chunk);
		});
		req.on('end', () => {
			if (chunks.length === 0) {
				resolve({});
				return;
			}
			try {
				resolve(JSON.parse(Buffer.concat(chunks).toString()));
			} catch {
				// A truncated payment body must be a parse error, not an empty
				// body that answers "bolt11 required" and collides every
				// malformed request onto one idempotency bodyHash.
				reject(
					new BeignetError('INVALID_JSON', 'Request body is not valid JSON')
				);
			}
		});
		req.on('error', () => {
			// Stream was destroyed due to body size limit
			reject(
				new BeignetError(
					'BODY_TOO_LARGE',
					`Request body exceeds ${MAX_BODY_BYTES} bytes`
				)
			);
		});
	});
}

// Routes exempt from authentication. GET /metrics is deliberately absent:
// it reports balances, so it is auth-gated unless metricsPublic opts out.
export const AUTH_EXEMPT_ROUTES = new Set([
	'GET /health',
	'GET /ready',
	'GET /openapi.json'
]);

/**
 * Routes a restore-pending daemon still serves (GET /events bypasses this
 * set through its own dispatcher arm, so SSE restore progress flows too).
 */
const RESTORE_PENDING_ROUTES = new Set([
	'GET /recovery/status',
	'POST /recovery/restore',
	'GET /openapi.json',
	'POST /stop'
]);

/**
 * Routes a daemon still serves after a Tier 2 capsule restore replaced its
 * database: the node underneath is gone until a restart builds one on the
 * restored state.
 */
const RESTART_REQUIRED_ROUTES = new Set([
	'GET /recovery/status',
	'GET /openapi.json',
	'POST /stop'
]);

/** HTTP status for a failure envelope; unmapped codes are server faults. */
const STATUS_BY_ERROR_CODE: Record<string, number> = {
	INVALID_PARAMS: 400,
	INVALID_JSON: 400,
	INVALID_INVOICE: 400,
	INVALID_OFFER: 400,
	UNAUTHORIZED: 401,
	FORBIDDEN: 403,
	MNEMONIC_REQUIRES_AUTH: 403,
	NOT_FOUND: 404,
	IDEMPOTENCY_CONFLICT: 409,
	BODY_TOO_LARGE: 413,
	RATE_LIMITED: 429,
	// L402 refusals are decisions about the caller's request, not node faults.
	// They must not read as 5xx, which is the class agents retry on: retrying
	// a refused challenge just fetches a new invoice and refuses that too.
	L402_PRICE_ABOVE_CAP: 402,
	L402_AMOUNTLESS_INVOICE: 402,
	L402_HASH_COMMITMENT_MISMATCH: 402,
	L402_UNVERIFIABLE_MACAROON: 402,
	L402_UNUSABLE_MACAROON: 402,
	L402_CROSS_ORIGIN_CHALLENGE: 402,
	L402_INVALID_INVOICE: 400,
	L402_NO_PAYER: 400,
	// The caller's response-size cap and the private-target guard are caller
	// decisions too, and a network failure reaching the TARGET is upstream
	// trouble, not a node fault: none of them may read as a retryable 500.
	RESPONSE_TOO_LARGE: 413,
	PRIVATE_NETWORK_REFUSED: 403,
	L402_FETCH_FAILED: 502,
	// Unknown channel / wrong state / nothing recorded to rebroadcast are all
	// problems with the caller's request, not node faults: never a 5xx.
	REBROADCAST_FAILED: 400,
	// Recovery Protocol surface (docs/RECOVERY-PROTOCOL.md section 8).
	// 503s are genuinely retryable (a quorum that answers later changes the
	// answer); 409s are state conflicts the caller must react to; the rest
	// are caller or configuration problems, never node faults.
	NODE_RESTORE_PENDING: 503,
	RESTORE_IN_PROGRESS: 409,
	RESTORE_NOT_PENDING: 409,
	RESTORE_NO_QUORUM: 503,
	RESTORE_CAS_EXHAUSTED: 503,
	RESTORE_UNKNOWN_NAMESPACE: 404,
	RESTORE_CONFLICT: 409,
	RESTORE_HEAD_UNVERIFIABLE: 502,
	RESTORE_TARGET_UNSUPPORTED: 400,
	NODE_RESTART_REQUIRED: 503,
	CAPSULE_RESTORE_UNSUPPORTED: 409,
	CAPSULE_RESTORE_NO_CANDIDATES: 404,
	CAPSULE_RESTORE_TARGET_DIRTY: 409,
	CAPSULE_RESTORE_FAILED: 409,
	CAPSULE_RESTORE_GUARDIAN_BACKED: 409,
	CAPSULE_RESTORE_QUORUM_NAMESPACE: 409,
	CAPSULE_RESTORE_INSTALL_FAILED: 500,
	// Domain failures from BeignetErrorCode (issue #471). Every one of these
	// used to fall through to the 500 default, so a failed peer dial read as a
	// node fault, which is the class an agent retries. Same vocabulary as the
	// blocks above: 502/504 when the trouble is upstream of us (the peer, the
	// network), 409 when the node's own state conflicts with the request, 503
	// when waiting genuinely changes the answer.
	CONNECT_FAILED: 502,
	CONNECT_TIMEOUT: 504,
	PAYMENT_FAILED: 502,
	PAYMENT_TIMEOUT: 504,
	NO_ROUTE: 502,
	OPEN_FAILED: 502,
	PEER_NOT_CONNECTED: 409,
	INSUFFICIENT_BALANCE: 409,
	CHANNEL_NOT_READY: 409,
	DUPLICATE_PAYMENT: 409,
	NOT_BOOSTABLE: 409,
	NOTHING_TO_CONSOLIDATE: 409,
	NODE_DESTROYED: 409,
	FUNDING_PROVIDER_REQUIRED: 409,
	CHANNEL_NOT_FOUND: 404,
	INVOICE_EXPIRED: 410,
	SPENDING_LIMIT_EXCEEDED: 403,
	SERVICE_DRAINING: 503,
	FEE_ESTIMATE_NOT_READY: 503
	// Left unmapped on purpose, so they keep the 500 default:
	// WALLET_CREATE_FAILED, ADDRESS_FAILED and REFRESH_FAILED are node faults,
	// and SEND_FAILED, CLOSE_FAILED, FORCE_CLOSE_FAILED and ZERO_CONF_FAILED
	// are grab-bags whose producers span caller state and genuine faults; each
	// needs splitting before it can carry one honest status.
	// INSTANCE_ALREADY_RUNNING is a startup refusal and never reaches HTTP.
};

export function statusForErrorCode(code: string): number {
	return STATUS_BY_ERROR_CODE[code] ?? 500;
}

/** End the response, mapping a failure envelope to its HTTP status. */
function endWithResult(res: http.ServerResponse, result: unknown): void {
	const failureLike = result as { ok?: boolean; error?: { code?: string } };
	if (failureLike?.ok === false && failureLike.error?.code) {
		res.statusCode = statusForErrorCode(failureLike.error.code);
	}
	res.end(JSON.stringify(result));
}

/**
 * Read an optional integer query parameter, throwing INVALID_PARAMS on a
 * non-integer value instead of letting NaN silently change query semantics
 * (a NaN bound in SQLite matches nothing, which reads as an empty ledger
 * rather than an invalid query).
 */
export function parseIntParam(
	query: URLSearchParams,
	name: string,
	opts: { min?: number; max?: number } = {}
): number | undefined {
	const raw = query.get(name);
	if (raw === null || raw === '') return undefined;
	const value = Number(raw);
	if (!Number.isFinite(value) || !Number.isInteger(value)) {
		throw new BeignetError('INVALID_PARAMS', `${name} must be an integer`);
	}
	if (opts.min !== undefined && value < opts.min) {
		throw new BeignetError('INVALID_PARAMS', `${name} must be >= ${opts.min}`);
	}
	if (opts.max !== undefined && value > opts.max) {
		throw new BeignetError('INVALID_PARAMS', `${name} must be <= ${opts.max}`);
	}
	return value;
}

/**
 * Node events relayed to SSE clients and webhooks. Per-HTLC events are opt-in
 * via htlcEvents because routing nodes generate one event per HTLC.
 */
export function getRelayedEvents(htlcEvents?: boolean): string[] {
	const events = [
		'payment:received',
		'payment:sent',
		'payment:failed',
		'invoice:settled',
		// On-chain money movements, sourced from the wallet rather than the
		// lightning node. Without these an on-chain receive is invisible until
		// a client polls /transactions for the difference. Appearance events
		// are per direction; the confirmation is a transition and covers both.
		'transaction:received',
		'transaction:sent',
		'transaction:confirmed',
		'channel:opening',
		'channel:ready',
		'channel:pending-close',
		'channel:force-closing',
		'channel:closed',
		// The true terminal event of a close: every on-chain output
		// irrevocably swept, state becomes CLOSED. channel:closed only says a
		// commitment spend was classified; consumers tracking close resolution
		// need this one.
		'channel:resolved',
		'peer:connect',
		'peer:disconnect',
		// Every channel failure reason (peer rejection, funding build/broadcast
		// failure, disconnect mid-open) is reported as node:error. Without it on
		// this list a failed open is invisible to clients: the pending channel
		// just disappears and nothing ever says why.
		'node:error',
		'node:ready',
		// Recovery Protocol (docs/RECOVERY-PROTOCOL.md section 8). Always on:
		// low volume by construction (durability watermark advances, fences,
		// restore progress), and the umbrel dashboard's degraded-state badge
		// rides them.
		'recovery:durable',
		'recovery:fenced',
		'recovery:backfill-lost',
		'recovery:reestablish-held',
		'recovery:guardian_unreachable',
		'recovery:restore-progress',
		'recovery:restored'
	];
	if (htlcEvents === true) {
		events.push('htlc:forwarded', 'htlc:fulfilled', 'htlc:failed');
	}
	return events;
}

/** What a boot has taken so far, so a failed start can hand it all back. */
interface IStartedResources {
	node?: BeignetNode;
	release: Array<() => void>;
}

/** A running daemon: the HTTP server, the node, and the one way to stop both. */
export interface IStartedDaemon {
	server: http.Server;
	node: BeignetNode;
	/**
	 * Graceful teardown of everything the boot created: the payment queue's
	 * listeners, the node (falling back to destroy), the rate limiter, the
	 * idempotency sweep, open SSE connections and the HTTP server. Webhook
	 * registrations persist by contract and are NOT deleted. Repeat callers
	 * share the first call's in-flight promise; the POST /stop route and the
	 * CLI signal handler both use it.
	 */
	stop: (timeoutMs?: number) => Promise<void>;
}

export async function startDaemon(
	opts: DaemonOptions
): Promise<IStartedDaemon> {
	// Anything taken after the node boots has to be handed back if the start
	// then fails. The error leaves the caller with no handle at all, so the
	// SQLite database, the single-instance lock, the Electrum poll, the backup
	// timer and the daemon's own sweep timers would outlive the failed start
	// with nothing able to reach them. `await` here rather than a bare return,
	// so a late rejection (server.listen answering EADDRINUSE) lands in this
	// catch too.
	const started: IStartedResources = { release: [] };
	try {
		return await bootDaemon(opts, started);
	} catch (e) {
		for (const release of started.release) {
			try {
				release();
			} catch {
				// Best effort: the start failure is the one worth reporting.
			}
		}
		if (started.node) {
			await started.node.destroy().catch(() => {
				// Best effort, as above.
			});
		}
		throw e;
	}
}

async function bootDaemon(
	opts: DaemonOptions,
	started: IStartedResources
): Promise<IStartedDaemon> {
	const port =
		opts.daemonPort !== undefined && opts.daemonPort !== null
			? opts.daemonPort
			: 2112;
	const host = opts.daemonHost || '127.0.0.1';
	// Validates apiKeys (names/keys/scopes) up front; throws INVALID_PARAMS
	// on bad config before the node is created.
	const authenticator = new ApiKeyAuthenticator(opts.apiToken, opts.apiKeys);
	// Refuse plainly dangerous configurations before the node is created. A
	// wallet daemon reachable beyond loopback with no authentication hands
	// /send, /channel/forceclose and /mnemonic to the whole network segment;
	// wildcard CORS without authentication lets any page the operator visits
	// drive those same routes. `insecure: true` is the deliberate escape.
	// A literal loopback IP or the localhost name only: a HOSTNAME beginning
	// with "127." (e.g. 127.example.com) could resolve anywhere.
	const isLoopbackHost =
		host === 'localhost' ||
		host === '::1' ||
		(net.isIPv4(host) && host.startsWith('127.'));
	if (!isLoopbackHost && !authenticator.enabled && opts.insecure !== true) {
		throw new BeignetError(
			'INVALID_PARAMS',
			`Refusing to bind ${host} without authentication. Configure apiToken or apiKeys, or set insecure: true to accept the risk.`
		);
	}
	if (opts.cors === true && !authenticator.enabled && opts.insecure !== true) {
		throw new BeignetError(
			'INVALID_PARAMS',
			'Refusing wildcard CORS without authentication. Configure apiToken or apiKeys, set an explicit cors origin, or set insecure: true to accept the risk.'
		);
	}
	// Config-only checks belong here, ahead of BeignetNode.create: a typo is
	// not worth booting a node for, and one that throws further down leaves the
	// caller no handle to destroy.
	if (opts.tlsCert && !opts.tlsKey) {
		throw new BeignetError(
			'INVALID_PARAMS',
			'tlsKey is required when tlsCert is provided'
		);
	}
	if (opts.tlsKey && !opts.tlsCert) {
		throw new BeignetError(
			'INVALID_PARAMS',
			'tlsCert is required when tlsKey is provided'
		);
	}
	// A typo here would silently fall back to socket-address keying, so a
	// non-IP entry is a config error, not something to skip over.
	for (const proxy of opts.rateLimit?.trustedProxies ?? []) {
		if (net.isIP(proxy.trim()) === 0) {
			throw new BeignetError(
				'INVALID_PARAMS',
				`rateLimit.trustedProxies entry is not an IP address: ${proxy}`
			);
		}
	}
	// Recovery Protocol configuration (docs/RECOVERY-PROTOCOL.md section 8).
	// The MODE follows the ignore-typos rule (unknown values fall back to
	// off, the safe direction), but everything that changes the quorum
	// arithmetic is validated hard: a silently dropped guardian or profile
	// would leave the operator believing in protection that is not there.
	const recoveryMode = parseRecoveryMode(opts.recoveryMode);
	if (
		opts.recoveryProfile !== undefined &&
		opts.recoveryProfile !== 'crash-v1'
	) {
		throw new BeignetError(
			'INVALID_PARAMS',
			`Unknown recovery profile "${opts.recoveryProfile}"; crash-v1 is ` +
				'the only accepted value (and the default)'
		);
	}
	if (
		opts.recoveryLeaseCheckIntervalMs !== undefined &&
		(!Number.isInteger(opts.recoveryLeaseCheckIntervalMs) ||
			opts.recoveryLeaseCheckIntervalMs < 0 ||
			opts.recoveryLeaseCheckIntervalMs > 2_147_483_647)
	) {
		// Node's timers turn NaN and anything past 2^31-1 ms into a 1 ms
		// delay, which would poll the guardian set continuously.
		throw new BeignetError(
			'INVALID_PARAMS',
			`Invalid recovery lease check interval "${String(
				opts.recoveryLeaseCheckIntervalMs
			)}"; BEIGNET_RECOVERY_LEASE_CHECK_MS must be an integer between 0 ` +
				'and 2147483647 (0 disables the check)'
		);
	}
	if (
		opts.recoveryReestablishHoldMs !== undefined &&
		(!Number.isInteger(opts.recoveryReestablishHoldMs) ||
			opts.recoveryReestablishHoldMs < 0 ||
			opts.recoveryReestablishHoldMs > 2_147_483_647)
	) {
		// Same trap as the lease check: past 2^31-1 ms a timer fires after 1 ms,
		// so an over-large hold would silently behave like no hold at all.
		throw new BeignetError(
			'INVALID_PARAMS',
			`Invalid recovery reestablish hold "${String(
				opts.recoveryReestablishHoldMs
			)}"; BEIGNET_RECOVERY_REESTABLISH_HOLD_MS must be an integer ` +
				'between 0 and 2147483647 (0 answers immediately)'
		);
	}
	const guardianEntries = opts.recoveryGuardians ?? [];
	if (recoveryMode === 'async-remote' || recoveryMode === 'quorum') {
		if (guardianEntries.length !== 3) {
			throw new BeignetError(
				'INVALID_PARAMS',
				`Recovery mode ${recoveryMode} needs exactly 3 guardians ` +
					`(crash-v1 is 2-of-3); got ${guardianEntries.length}`
			);
		}
		for (const entry of guardianEntries) {
			try {
				parseGuardianEntry(entry);
			} catch (e) {
				throw new BeignetError(
					'INVALID_PARAMS',
					e instanceof Error ? e.message : String(e)
				);
			}
		}
	} else if (guardianEntries.length > 0) {
		throw new BeignetError(
			'INVALID_PARAMS',
			`Recovery guardians are configured but the recovery mode is ` +
				`"${opts.recoveryMode ?? 'off'}" (resolved: ${recoveryMode}); ` +
				'guardians need async-remote or quorum'
		);
	}
	// Diagnostic logger: an injected opts.logger wins; otherwise a configured
	// logLevel creates a console logger on stderr (stdout stays reserved for
	// command output). With neither, the daemon stays silent as before.
	let logger: ILogger | undefined = opts.logger;
	if (!logger && opts.logLevel && opts.logLevel !== 'silent') {
		const stderrConsole = new Console({
			stdout: process.stderr,
			stderr: process.stderr
		});
		logger = createConsoleLogger(opts.logLevel, stderrConsole);
	}
	const node = await BeignetNode.create(logger ? { ...opts, logger } : opts);
	started.node = node;
	const storage = node.getStorage();
	// Durable auth-key state: persisted rotate/revoke overrides live in the
	// encrypted wallet_data table and are re-applied over the config-declared
	// keys on every start (so a restart no longer resurrects a revoked or
	// rotated-away secret). Attached before the server accepts requests.
	authenticator.attachOverrideStore({
		load: (): Record<string, StoredKeyOverride> | null => {
			try {
				const raw = storage.loadWalletData(AUTH_KEY_OVERRIDES_STORAGE_KEY);
				if (raw === null) return null;
				const parsed = JSON.parse(raw);
				return typeof parsed === 'object' &&
					parsed !== null &&
					!Array.isArray(parsed)
					? (parsed as Record<string, StoredKeyOverride>)
					: null;
			} catch {
				return null;
			}
		},
		save: (overrides): void => {
			storage.saveWalletData(
				AUTH_KEY_OVERRIDES_STORAGE_KEY,
				JSON.stringify(overrides)
			);
		}
	});
	const webhookManager = new WebhookManager(storage);
	const paymentQueue = new PaymentQueue(
		(bolt11, timeout, maxFee, amount, meta) =>
			node.payInvoiceSafe(bolt11, timeout, maxFee, amount, meta),
		(amount) => node.canSend(amount),
		undefined,
		storage
	);
	const rateLimiter = opts.rateLimit
		? new HttpRateLimiter(opts.rateLimit)
		: null;
	if (rateLimiter) started.release.push(() => rateLimiter.destroy());

	// Idempotency cache
	const idempotencyCache = new Map<string, CachedResponse>();
	const idempotencyCleanupTimer = setInterval(() => {
		const now = Date.now();
		for (const [key, entry] of idempotencyCache) {
			if (now >= entry.expiresAt) idempotencyCache.delete(key);
		}
	}, IDEMPOTENCY_CLEANUP_INTERVAL_MS);
	if (idempotencyCleanupTimer.unref) idempotencyCleanupTimer.unref();
	started.release.push(() => clearInterval(idempotencyCleanupTimer));

	type RouteHandler = (
		body: Record<string, unknown>,
		query: URLSearchParams
	) => unknown;

	const routes: Record<string, RouteHandler> = {
		'GET /info': () => success(node.getInfo()),
		'GET /mnemonic': () => {
			if (!authenticator.enabled) {
				return failure(
					'MNEMONIC_REQUIRES_AUTH',
					'Configure apiToken or apiKeys to enable mnemonic access'
				);
			}
			return success({ mnemonic: node.getMnemonic() });
		},
		'GET /balance': () => success(node.getBalance()),
		'GET /peers': () => success(node.listPeers()),
		'GET /channels': () => success(node.listChannels()),
		'GET /payments': (_body, query) => {
			const filter: Record<string, unknown> = {};
			if (query.get('status')) filter.status = query.get('status');
			if (query.get('direction')) filter.direction = query.get('direction');
			const since = parseIntParam(query, 'since', { min: 0 });
			if (since !== undefined) filter.since = since;
			const limit = parseIntParam(query, 'limit', { min: 0 });
			if (limit !== undefined) filter.limit = limit;
			const offset = parseIntParam(query, 'offset', { min: 0 });
			if (offset !== undefined) filter.offset = offset;
			if (query.get('metadataKey'))
				filter.metadataKey = query.get('metadataKey');
			if (query.get('metadataValue'))
				filter.metadataValue = query.get('metadataValue');
			return success(
				node.listPayments(
					// eslint-disable-next-line @typescript-eslint/no-explicit-any -- query params are unvalidated strings; listPayments tolerates unknown values
					Object.keys(filter).length > 0 ? (filter as any) : undefined
				)
			);
		},
		'GET /forwards': (_body, query) => {
			const filter: Record<string, unknown> = {};
			const since = parseIntParam(query, 'since', { min: 0 });
			if (since !== undefined) filter.since = since;
			const until = parseIntParam(query, 'until', { min: 0 });
			if (until !== undefined) filter.until = until;
			const limit = parseIntParam(query, 'limit', { min: 0 });
			if (limit !== undefined) filter.limit = limit;
			const offset = parseIntParam(query, 'offset', { min: 0 });
			if (offset !== undefined) filter.offset = offset;
			if (query.get('channelId')) filter.channelId = query.get('channelId');
			return success(
				node.listForwards(
					// eslint-disable-next-line @typescript-eslint/no-explicit-any -- query params are unvalidated strings; listForwards tolerates unknown values
					Object.keys(filter).length > 0 ? (filter as any) : undefined
				)
			);
		},
		'GET /forwards/summary': (_body, query) => {
			const since = parseIntParam(query, 'since', { min: 0 });
			return success(node.getForwardingSummary(since));
		},
		'GET /invoices': () => success(node.listInvoices()),
		'GET /invoice': (_body, query) => {
			const paymentHash = query.get('paymentHash');
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			const inv = node.getInvoice(paymentHash);
			if (!inv) return failure('NOT_FOUND', 'Invoice not found');
			return success(inv);
		},
		'GET /health': () => success(node.getHealth()),
		'GET /ready': () => success({ ready: node.isReady() }),
		'GET /readiness': () => success(node.getMainnetReadiness()),
		'GET /openapi.json': () => getOpenApiSpec(),
		'GET /stats': (_body, query) => {
			const windowMs = parseIntParam(query, 'window', { min: 0 });
			return success(node.getStats(windowMs));
		},
		'GET /spend-limit': () => success(node.getDailySpendInfo()),
		'GET /liquidity': () => success(node.getLiquiditySnapshot()),
		'GET /watchtowers': () => success({ towers: node.listWatchtowers() }),
		'POST /watchtower/add': (body) => {
			const { uri } = body as { uri?: string };
			if (!uri) return failure('INVALID_PARAMS', 'uri required');
			try {
				node.addWatchtower(uri);
			} catch (err) {
				return failure(
					'INVALID_PARAMS',
					err instanceof Error ? err.message : String(err)
				);
			}
			return success({ added: uri });
		},
		'DELETE /watchtower/remove': (body) => {
			const { uri } = body as { uri?: string };
			if (!uri) return failure('INVALID_PARAMS', 'uri required');
			node.removeWatchtower(uri);
			return success({ removed: uri });
		},
		'GET /advisor/recommendations': () =>
			success(node.getAdvisorRecommendations()),
		'POST /advisor/execute-rebalances': async (body) => {
			const { budgetSatsPerDay } = body as { budgetSatsPerDay?: number };
			return success(await node.executeRebalances(budgetSatsPerDay));
		},
		'POST /rebalance': async (body) => {
			const { fromChannelId, toChannelId, amountSats, maxFeeSats } = body as {
				fromChannelId: string;
				toChannelId: string;
				amountSats: number;
				maxFeeSats: number;
			};
			// maxFeeSats is mandatory: fee-spending endpoints never guess a cap.
			if (
				!fromChannelId ||
				!toChannelId ||
				amountSats === undefined ||
				maxFeeSats === undefined
			) {
				return failure(
					'INVALID_PARAMS',
					'fromChannelId, toChannelId, amountSats, and maxFeeSats required'
				);
			}
			return success(
				await node.rebalanceChannel(
					fromChannelId,
					toChannelId,
					amountSats,
					maxFeeSats
				)
			);
		},
		'GET /fees': () => {
			const snapshot = node.getFeeSnapshot();
			if (!snapshot) return failure('NO_DATA', 'No fee samples recorded yet');
			return success(snapshot);
		},
		'GET /fees/estimates': async () => success(await node.getFeeEstimates()),
		'GET /transactions': (_body, query) => {
			const limitParam = query.get('limit');
			let txs = node.listOnchainTransactions();
			if (limitParam !== null) {
				const limit = Number(limitParam);
				if (!Number.isInteger(limit) || limit < 0)
					return failure(
						'INVALID_PARAMS',
						'limit must be a non-negative integer'
					);
				txs = txs.slice(0, limit);
			}
			return success(txs);
		},
		'GET /utxos': () => success(node.listUtxos()),
		'POST /utxo/freeze': async (body) => {
			const { txid, index } = body as { txid?: string; index?: number };
			if (!txid || index === undefined)
				return failure('INVALID_PARAMS', 'txid and index required');
			return success(await node.freezeUtxo(txid, index));
		},
		'POST /utxo/unfreeze': async (body) => {
			const { txid, index } = body as { txid?: string; index?: number };
			if (!txid || index === undefined)
				return failure('INVALID_PARAMS', 'txid and index required');
			return success(await node.unfreezeUtxo(txid, index));
		},
		'POST /address/label': async (body) => {
			const { address, label } = body as { address?: string; label?: string };
			if (!address || label === undefined)
				return failure(
					'INVALID_PARAMS',
					'address and label required (empty label clears)'
				);
			return success(await node.setAddressLabel(address, label));
		},
		'GET /address/labels': () => success(node.listAddressLabels()),
		'GET /wallet/descriptors': () => success(node.exportDescriptors()),
		'GET /channel/suggestions': (_body, query) => {
			const count = parseIntParam(query, 'count', { min: 1 });
			return success(node.getChannelSuggestions(count));
		},

		'GET /logs': (_body, query) => {
			const options: Record<string, unknown> = {};
			if (query.get('category')) options.category = query.get('category');
			const since = parseIntParam(query, 'since', { min: 0 });
			if (since !== undefined) options.since = since;
			const limit = parseIntParam(query, 'limit', { min: 0 });
			if (limit !== undefined) options.limit = limit;
			return success(
				node.getActionLog(
					// eslint-disable-next-line @typescript-eslint/no-explicit-any -- remaining string params pass through; integers are validated above
					Object.keys(options).length > 0 ? (options as any) : undefined
				)
			);
		},

		'POST /address/new': async (body) => {
			const {
				bip21: wantBip21,
				amountSats,
				label,
				message
			} = (body ?? {}) as {
				bip21?: boolean;
				amountSats?: number;
				label?: string;
				message?: string;
			};
			const address = await node.getNewAddress();
			if (!wantBip21) return success({ address });
			const uri = encodeBip21({ address, amountSats, label, message });
			if (uri.isErr()) return failure('INVALID_PARAMS', uri.error.message);
			return success({ address, bip21: uri.value });
		},
		'POST /wallet/refresh': async () => {
			await node.refreshWallet();
			return success({ refreshed: true });
		},

		'POST /send': async (body) => {
			const { address, amountSats, satsPerVbyte } = body as {
				address: string;
				amountSats: number;
				satsPerVbyte?: number;
			};
			if (!address || amountSats === undefined)
				return failure('INVALID_PARAMS', 'address and amountSats required');
			return success(await node.sendOnchain(address, amountSats, satsPerVbyte));
		},

		// What an on-chain transaction will really cost. A client cannot work this
		// out: the fee depends on which UTXOs coin selection picks, their script
		// types, and whether change is needed. Quoting it here means the number
		// shown is the number spent.
		'POST /tx/quote': async (body) => {
			const { address, amountSats, satsPerVbyte, max, channelFunding } =
				body as {
					address?: string;
					amountSats?: number;
					satsPerVbyte?: number;
					max?: boolean;
					channelFunding?: boolean;
				};
			return success(
				await node.quoteOnchain({
					address,
					amountSats,
					satsPerVbyte,
					max,
					channelFunding
				})
			);
		},

		'POST /send-max': async (body) => {
			const { address, satsPerVbyte } = body as {
				address: string;
				satsPerVbyte?: number;
			};
			if (!address) return failure('INVALID_PARAMS', 'address required');
			return success(await node.sendMaxOnchain(address, satsPerVbyte));
		},
		'POST /tx/bump-fee': async (body) => {
			const { txid, satsPerVbyte } = body as {
				txid: string;
				satsPerVbyte: number;
			};
			if (!txid || satsPerVbyte === undefined)
				return failure('INVALID_PARAMS', 'txid and satsPerVbyte required');
			return success(await node.bumpFeeOnchain(txid, satsPerVbyte));
		},
		'POST /tx/boost': async (body) => {
			const { txid, satsPerVbyte } = body as {
				txid: string;
				satsPerVbyte?: number;
			};
			if (!txid) return failure('INVALID_PARAMS', 'txid required');
			return success(await node.boostOnchain(txid, satsPerVbyte));
		},
		'GET /transactions/boostable': () =>
			success(node.listBoostableTransactions()),
		'POST /consolidate': async (body) => {
			const { satsPerVbyte } = body as { satsPerVbyte?: number };
			return success(await node.consolidateUtxos(satsPerVbyte));
		},

		// ── External-signer PSBT flow ──
		'POST /psbt/build': async (body) => {
			const { outputs, satsPerVbyte } = body as {
				outputs?: Array<{ address: string; amountSats: number }>;
				satsPerVbyte?: number;
			};
			if (!outputs || !Array.isArray(outputs) || outputs.length === 0)
				return failure(
					'INVALID_PARAMS',
					'outputs array of { address, amountSats } required'
				);
			return success(await node.buildPsbt(outputs, satsPerVbyte));
		},
		'POST /psbt/import-signed': (body) => {
			const { psbtBase64 } = body as { psbtBase64?: string };
			if (!psbtBase64) return failure('INVALID_PARAMS', 'psbtBase64 required');
			return success(node.importSignedPsbt(psbtBase64));
		},
		'POST /psbt/combine': (body) => {
			const { psbts } = body as { psbts?: string[] };
			if (!psbts || !Array.isArray(psbts) || psbts.length < 2)
				return failure(
					'INVALID_PARAMS',
					'psbts array with at least two base64 PSBTs required'
				);
			return success(node.combinePsbts(psbts));
		},

		'POST /peer/connect': async (body) => {
			const {
				pubkey,
				host: peerHost,
				port: peerPort,
				transport: peerTransport,
				url: peerUrl
			} = body as {
				pubkey: string;
				host?: string;
				port?: number;
				transport?: string;
				url?: string;
			};
			if (!pubkey) return failure('INVALID_PARAMS', 'pubkey required');
			// Additive WebSocket support: transport 'ws' and/or an explicit
			// ws:// / wss:// url. Omitting both preserves TCP behavior exactly.
			if (
				peerTransport !== undefined &&
				peerTransport !== 'tcp' &&
				peerTransport !== 'ws'
			)
				return failure('INVALID_PARAMS', "transport must be 'tcp' or 'ws'");
			if (peerUrl !== undefined) {
				if (typeof peerUrl !== 'string' || !/^wss?:\/\//i.test(peerUrl))
					return failure('INVALID_PARAMS', 'url must be a ws:// or wss:// URL');
				if (peerTransport === 'tcp')
					return failure(
						'INVALID_PARAMS',
						"transport 'tcp' cannot be combined with a WebSocket url"
					);
				return success(
					await node.connectPeer(pubkey, peerHost, peerPort, {
						type: 'ws',
						url: peerUrl
					})
				);
			}
			// host/port are optional together: when omitted the node resolves the
			// address from the gossip graph / DNS bootstrap.
			if ((peerHost === undefined) !== (peerPort === undefined))
				return failure(
					'INVALID_PARAMS',
					'host and port must be provided together (omit both to resolve by node id)'
				);
			if (peerTransport === 'ws') {
				if (peerHost === undefined)
					return failure(
						'INVALID_PARAMS',
						"transport 'ws' requires host+port or url"
					);
				return success(
					await node.connectPeer(pubkey, peerHost, peerPort, { type: 'ws' })
				);
			}
			return success(await node.connectPeer(pubkey, peerHost, peerPort));
		},
		'POST /peer/disconnect': (body) => {
			const { pubkey } = body as { pubkey: string };
			if (!pubkey) return failure('INVALID_PARAMS', 'pubkey required');
			node.disconnectPeer(pubkey);
			return success({ disconnected: true });
		},

		'POST /channel/open': (body) => {
			const { pubkey, amountSats, pushSats, satsPerVbyte, max } = body as {
				pubkey: string;
				amountSats: number;
				pushSats?: number;
				satsPerVbyte?: number;
				max?: boolean;
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			return success(
				node.openChannel(pubkey, amountSats, pushSats, satsPerVbyte, max)
			);
		},
		'POST /channel/close': (body) => {
			const { channelId } = body as { channelId: string };
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const result = node.closeChannel(channelId);
			if (!result.ok)
				return failure('CLOSE_FAILED', result.error || 'Close failed');
			return success({ closed: true });
		},
		'POST /channel/forceclose': (body) => {
			const { channelId } = body as { channelId: string };
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const result = node.forceCloseChannel(channelId);
			if (!result.ok)
				return failure(
					'FORCE_CLOSE_FAILED',
					result.error || 'Force close failed'
				);
			return success({
				forceClosed: true,
				commitmentTxid: result.commitmentTxid
			});
		},
		// Re-drive the close broadcast of a FORCE_CLOSED channel (or a CLOSED
		// one whose mutual close has not confirmed). Only a channelId is
		// accepted: the engine rebuilds the latest commitment byte-identically,
		// so an older (revoked) state can never be selected. Idempotent.
		'POST /channel/rebroadcast-close': async (body) => {
			const { channelId } = body as { channelId: string };
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const result = await node.rebroadcastClose(channelId);
			if (!result.ok)
				return failure(
					'REBROADCAST_FAILED',
					result.error || 'Rebroadcast failed'
				);
			return success({ txid: result.txid, broadcastOk: result.broadcastOk });
		},
		// Sets the channel's COMMITMENT transaction feerate (BOLT 2 update_fee).
		// This is not the routing fee policy (base fee / proportional millionths);
		// routing policy control is a separate planned endpoint.
		'POST /channel/update-commitment-feerate': (body) => {
			const { channelId, feeratePerKw } = body as {
				channelId: string;
				feeratePerKw: number;
			};
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			if (feeratePerKw === undefined)
				return failure('INVALID_PARAMS', 'feeratePerKw required');
			return success(node.updateChannelFee(channelId, feeratePerKw));
		},
		// Sets the ROUTING fee policy advertised in channel_update. Unrelated to
		// the commitment feerate endpoint above.
		'POST /channel/update-policy': (body) => {
			const {
				channelId,
				all,
				feeBaseMsat,
				feeProportionalMillionths,
				cltvExpiryDelta,
				htlcMinimumMsat,
				htlcMaximumMsat
			} = body as {
				channelId?: string;
				all?: boolean;
				feeBaseMsat?: number;
				feeProportionalMillionths?: number;
				cltvExpiryDelta?: number;
				htlcMinimumMsat?: number | string;
				htlcMaximumMsat?: number | string;
			};
			if (!channelId && all !== true)
				return failure('INVALID_PARAMS', 'channelId or all:true required');
			try {
				return success(
					node.updateChannelPolicy(all === true ? 'all' : channelId!, {
						feeBaseMsat,
						feeProportionalMillionths,
						cltvExpiryDelta,
						htlcMinimumMsat,
						htlcMaximumMsat
					})
				);
			} catch (err) {
				return failure('INVALID_PARAMS', (err as Error).message);
			}
		},
		'GET /channel/policy': (body, query) => {
			const channelId =
				query.get('channelId') || (body as { channelId?: string }).channelId;
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const policy = node.getChannelPolicy(channelId);
			if (!policy) return failure('NOT_FOUND', 'Channel not found');
			return success(policy);
		},
		'GET /channel': (body, query) => {
			const channelId =
				query.get('channelId') || (body as { channelId?: string }).channelId;
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const ch = node.getChannel(channelId);
			if (!ch) return failure('NOT_FOUND', 'Channel not found');
			return success(ch);
		},
		'GET /channel/health': (body, query) => {
			const channelId =
				query.get('channelId') || (body as { channelId?: string }).channelId;
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const health = node.getChannelHealth(channelId);
			if (!health) return failure('NOT_FOUND', 'Channel not found');
			return success(health);
		},
		'POST /channels/ensure-minimum': async (body) => {
			const { count, satsPerChannel, timeoutMs } = body as {
				count: number;
				satsPerChannel: number;
				timeoutMs?: number;
			};
			if (count === undefined || satsPerChannel === undefined)
				return failure('INVALID_PARAMS', 'count and satsPerChannel required');
			return success(
				await node.ensureMinimumChannels(count, satsPerChannel, { timeoutMs })
			);
		},
		'POST /channel/connect-and-open': async (body) => {
			const {
				pubkey,
				host: peerHost,
				port: peerPort,
				amountSats,
				pushSats,
				satsPerVbyte,
				max,
				trusted
			} = body as {
				pubkey: string;
				host: string;
				port: number;
				amountSats: number;
				pushSats?: number;
				satsPerVbyte?: number;
				max?: boolean;
				trusted?: boolean;
			};
			if (!pubkey || !peerHost || !peerPort || amountSats === undefined) {
				return failure(
					'INVALID_PARAMS',
					'pubkey, host, port, and amountSats required'
				);
			}
			return success(
				await node.connectAndOpenChannel(
					pubkey,
					peerHost,
					peerPort,
					amountSats,
					{ pushSats, satsPerVbyte, max, trusted }
				)
			);
		},

		'POST /invoice/validate': (body) => {
			const { bolt11, amountSats } = body as {
				bolt11: string;
				amountSats?: number;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			return success(node.validatePayment(bolt11, amountSats));
		},
		'POST /invoice/create': (body) => {
			const { amountSats, description, expirySecs, descriptionHash } = body as {
				amountSats?: number;
				description?: string;
				expirySecs?: number;
				descriptionHash?: string;
			};
			const hashBuf = descriptionHash
				? Buffer.from(descriptionHash, 'hex')
				: undefined;
			return success(
				node.createInvoice(amountSats, description, expirySecs, hashBuf)
			);
		},
		'POST /invoice/create-hold': (body) => {
			const { paymentHash, amountMsat, amountSats, description, expiry } =
				body as {
					paymentHash?: string;
					amountMsat?: string | number;
					amountSats?: number;
					description?: string;
					expiry?: number;
				};
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			let amountMsatBig: bigint | undefined;
			if (amountMsat !== undefined) {
				try {
					amountMsatBig = BigInt(amountMsat);
				} catch {
					return failure('INVALID_PARAMS', 'amountMsat must be an integer');
				}
			}
			return success(
				node.createHoldInvoice({
					paymentHash,
					amountMsat: amountMsatBig,
					amountSats,
					description,
					expiry
				})
			);
		},
		'POST /invoice/settle-hold': (body) => {
			const { preimage } = body as { preimage?: string };
			if (!preimage) return failure('INVALID_PARAMS', 'preimage required');
			return success(node.settleHoldInvoice(preimage));
		},
		'POST /invoice/cancel-hold': (body) => {
			const { paymentHash } = body as { paymentHash?: string };
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			return success(node.cancelHoldInvoice(paymentHash));
		},
		'GET /invoices/held': () => success(node.listHoldInvoices()),
		'POST /invoice/decode': (body) => {
			const { bolt11 } = body as { bolt11: string };
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			return success(node.decodeInvoice(bolt11));
		},
		'POST /invoice/pay': async (body) => {
			const { bolt11, timeoutMs, maxFeeSats, amountSats, metadata } = body as {
				bolt11: string;
				timeoutMs?: number;
				maxFeeSats?: number;
				amountSats?: number;
				metadata?: Record<string, string>;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			return success(
				await node.payInvoice(
					bolt11,
					timeoutMs,
					maxFeeSats,
					amountSats,
					metadata
				)
			);
		},
		'POST /invoice/pay-async': (body) => {
			const { bolt11, maxFeeSats, amountSats, metadata } = body as {
				bolt11: string;
				maxFeeSats?: number;
				amountSats?: number;
				metadata?: Record<string, string>;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			try {
				return success(
					node.sendPaymentAsync(bolt11, maxFeeSats, amountSats, metadata)
				);
			} catch (err: unknown) {
				const msg = err instanceof Error ? err.message : String(err);
				return failure('PAYMENT_FAILED', msg);
			}
		},
		'POST /invoice/pay-safe': async (body) => {
			const { bolt11, timeoutMs, maxFeeSats, amountSats, metadata } = body as {
				bolt11: string;
				timeoutMs?: number;
				maxFeeSats?: number;
				amountSats?: number;
				metadata?: Record<string, string>;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			return success(
				await node.payInvoiceSafe(
					bolt11,
					timeoutMs,
					maxFeeSats,
					amountSats,
					metadata
				)
			);
		},
		'POST /invoice/pay-retry': async (body) => {
			const {
				bolt11,
				maxRetries,
				backoffMs,
				maxFeeSats,
				amountSats,
				metadata
			} = body as {
				bolt11: string;
				maxRetries?: number;
				backoffMs?: number;
				maxFeeSats?: number;
				amountSats?: number;
				metadata?: Record<string, string>;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			return success(
				await node.payInvoiceWithRetry(bolt11, {
					maxRetries,
					backoffMs,
					maxFeeSats,
					amountSats,
					metadata
				})
			);
		},
		'POST /keysend': async (body) => {
			const { pubkey, amountSats, timeoutMs, maxFeeSats, metadata } = body as {
				pubkey: string;
				amountSats: number;
				timeoutMs?: number;
				maxFeeSats?: number;
				metadata?: Record<string, string>;
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			try {
				return success(
					await node.sendKeysend(
						pubkey,
						amountSats,
						timeoutMs,
						maxFeeSats,
						metadata
					)
				);
			} catch (err: unknown) {
				const msg = err instanceof Error ? err.message : String(err);
				const code = err instanceof BeignetError ? err.code : 'PAYMENT_FAILED';
				return failure(code, msg);
			}
		},
		'POST /keysend/safe': async (body) => {
			const { pubkey, amountSats, timeoutMs, maxFeeSats, metadata } = body as {
				pubkey: string;
				amountSats: number;
				timeoutMs?: number;
				maxFeeSats?: number;
				metadata?: Record<string, string>;
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			return success(
				await node.sendKeysendSafe(
					pubkey,
					amountSats,
					timeoutMs,
					maxFeeSats,
					metadata
				)
			);
		},
		'POST /offer/decode': (body) => {
			const { offer } = body as { offer: string };
			if (!offer) return failure('INVALID_PARAMS', 'offer required');
			return success(node.decodeOfferString(offer));
		},
		'POST /channel/open-and-wait': async (body) => {
			const { pubkey, amountSats, pushSats, timeoutMs } = body as {
				pubkey: string;
				amountSats: number;
				pushSats?: number;
				timeoutMs?: number;
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			return success(
				await node.openChannelAndWait(pubkey, amountSats, {
					pushSats,
					timeoutMs
				})
			);
		},
		'POST /payment/cancel': (body) => {
			const { paymentHash } = body as { paymentHash: string };
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			return success(node.cancelPayment(paymentHash));
		},

		'GET /payment': (body, query) => {
			const paymentHash =
				query.get('paymentHash') ||
				(body as { paymentHash?: string }).paymentHash;
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			const p = node.getPayment(paymentHash);
			if (!p) return failure('NOT_FOUND', 'Payment not found');
			return success(p);
		},
		'POST /l402/fetch': async (body) => {
			const {
				url,
				method,
				headers,
				body: requestBody,
				maxPriceSats,
				maxFeeSats,
				timeoutMs,
				fetchTimeoutMs,
				scopePerPath,
				allowUnverifiedMacaroon,
				allowCrossOriginChallenge,
				allowPrivateNetwork,
				maxResponseBytes
			} = body as {
				url: string;
				method?: string;
				headers?: Record<string, string>;
				body?: string;
				maxPriceSats?: number;
				maxFeeSats?: number;
				timeoutMs?: number;
				fetchTimeoutMs?: number;
				scopePerPath?: boolean;
				allowUnverifiedMacaroon?: boolean;
				allowCrossOriginChallenge?: boolean;
				allowPrivateNetwork?: boolean;
				maxResponseBytes?: number;
			};
			if (!url) return failure('INVALID_PARAMS', 'url required');
			// The cap is mandatory over HTTP, not defaulted: a remote response
			// header triggers the payment, so the price ceiling has to be a
			// deliberate choice by the caller rather than one we invent. It is
			// also an integer: a fractional cap would reach BigInt() in the
			// payer and throw an opaque server fault instead of a 400.
			if (!Number.isInteger(maxPriceSats) || (maxPriceSats as number) < 0) {
				return failure(
					'INVALID_PARAMS',
					'maxPriceSats required, a non-negative integer satoshi cap on what one challenge may cost'
				);
			}
			for (const [name, value] of [
				['maxFeeSats', maxFeeSats],
				['timeoutMs', timeoutMs],
				['fetchTimeoutMs', fetchTimeoutMs],
				['maxResponseBytes', maxResponseBytes]
			] as Array<[string, number | undefined]>) {
				if (value !== undefined && (!Number.isInteger(value) || value < 0)) {
					return failure(
						'INVALID_PARAMS',
						`${name} must be a non-negative integer`
					);
				}
			}
			try {
				return success(
					await node.l402Fetch(
						url,
						{ method, headers, body: requestBody },
						{
							maxPriceSats: maxPriceSats as number,
							maxFeeSats,
							timeoutMs,
							fetchTimeoutMs,
							scopePerPath,
							allowUnverifiedMacaroon,
							allowCrossOriginChallenge,
							allowPrivateNetwork,
							maxResponseBytes
						}
					)
				);
			} catch (err: unknown) {
				if (err instanceof L402Error) {
					return failure(`L402_${err.code}`, err.message);
				}
				// BeignetError codes (RESPONSE_TOO_LARGE, payment failures, the
				// private-target guard) map to their own statuses centrally.
				if (err instanceof BeignetError) throw err;
				// What remains is the network layer failing to reach the target
				// (DNS, refused, reset, timeout). The top-level message names
				// the caller's own URL and is worth relaying; the cause chain
				// can carry resolved addresses and socket detail, so it stays
				// out of the envelope.
				const msg = err instanceof Error ? err.message : String(err);
				return failure('L402_FETCH_FAILED', `fetch failed: ${msg}`);
			}
		},
		'GET /l402/credentials': () => success(node.listL402Credentials()),
		'DELETE /l402/credential': (_body, query) => {
			const scope = query.get('scope');
			if (!scope) return failure('INVALID_PARAMS', 'scope required');
			node.forgetL402Credential(scope);
			return success({ scope, forgotten: true });
		},
		'GET /payment/proof': (_body, query) => {
			const paymentHash = query.get('paymentHash');
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			const proof = node.getPaymentProof(paymentHash);
			if (!proof)
				return failure(
					'NOT_FOUND',
					'Payment proof not found (payment may not be completed)'
				);
			return success(proof);
		},
		'GET /payment/verify-proof': (_body, query) => {
			const paymentHash = query.get('paymentHash');
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			return success(node.verifyPaymentProof(paymentHash));
		},
		'GET /node/uri': (_body, query) => {
			const externalHost = query.get('host') || undefined;
			const uri = node.getNodeUri(externalHost);
			if (!uri) return failure('NOT_FOUND', 'Node is not listening');
			return success({ uri });
		},

		// ── DNS Bootstrap (BOLT 10) ──
		'POST /peers/bootstrap': async () => success(await node.bootstrapPeers()),
		'POST /peers/connect-seeds': async (body) => {
			const { maxPeers } = body as { maxPeers?: number };
			return success({ connected: await node.connectToSeeds(maxPeers) });
		},

		// ── Zero-Conf Channels ──
		'POST /trusted-peer/add': (body) => {
			const { pubkey } = body as { pubkey: string };
			if (!pubkey) return failure('INVALID_PARAMS', 'pubkey required');
			return success(node.addTrustedPeer(pubkey));
		},
		'POST /trusted-peer/remove': (body) => {
			const { pubkey } = body as { pubkey: string };
			if (!pubkey) return failure('INVALID_PARAMS', 'pubkey required');
			return success(node.removeTrustedPeer(pubkey));
		},
		'GET /trusted-peers': () => success(node.listTrustedPeers()),
		'POST /channel/open-zeroconf': (body) => {
			const { pubkey, amountSats, pushSats } = body as {
				pubkey: string;
				amountSats: number;
				pushSats?: number;
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			return success(node.openZeroConfChannel(pubkey, amountSats, pushSats));
		},

		// ── Dual-Funding (v2 Channels) ──
		'POST /channel/open-v2': (body) => {
			const {
				pubkey,
				amountSats,
				fundingFeeratePerkw,
				commitmentFeeratePerkw,
				locktime
			} = body as {
				pubkey: string;
				amountSats: number;
				fundingFeeratePerkw?: number;
				commitmentFeeratePerkw?: number;
				locktime?: number;
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			return success(
				node.openChannelV2(pubkey, {
					amountSats,
					fundingFeeratePerkw,
					commitmentFeeratePerkw,
					locktime
				})
			);
		},

		// Peer-aware max funding preview. A client cannot decide this itself:
		// whether the open rides v1 or v2 depends on the peer's init features,
		// and the two flows price a max open with different formulas.
		'POST /channel/funding-quote': async (body) => {
			const { peerPubkey, satsPerVbyte } = body as {
				peerPubkey: string;
				satsPerVbyte?: number;
			};
			if (!peerPubkey) return failure('INVALID_PARAMS', 'peerPubkey required');
			return success(
				await node.quoteChannelFunding({ peerPubkey, satsPerVbyte })
			);
		},

		// ── Splicing ──
		'POST /channel/splice-quote': (body) => {
			const { channelId, direction, feeratePerkw } = body as {
				channelId: string;
				direction: 'in' | 'out';
				feeratePerkw: number;
			};
			if (
				!channelId ||
				(direction !== 'in' && direction !== 'out') ||
				feeratePerkw === undefined
			)
				return failure(
					'INVALID_PARAMS',
					"channelId, direction ('in' or 'out') and feeratePerkw required"
				);
			return success(node.spliceQuote(channelId, direction, feeratePerkw));
		},
		'POST /channel/splice-in': (body) => {
			const { channelId, amountSats, feeratePerkw } = body as {
				channelId: string;
				amountSats: number;
				feeratePerkw: number;
			};
			if (!channelId || amountSats === undefined || feeratePerkw === undefined)
				return failure(
					'INVALID_PARAMS',
					'channelId, amountSats, and feeratePerkw required'
				);
			return success(node.spliceIn(channelId, amountSats, feeratePerkw));
		},
		'POST /channel/splice-out': (body) => {
			const { channelId, amountSats, feeratePerkw } = body as {
				channelId: string;
				amountSats: number;
				feeratePerkw: number;
			};
			if (!channelId || amountSats === undefined || feeratePerkw === undefined)
				return failure(
					'INVALID_PARAMS',
					'channelId, amountSats, and feeratePerkw required'
				);
			return success(node.spliceOut(channelId, amountSats, feeratePerkw));
		},

		// ── Wait APIs ──
		'POST /node/wait-ready': async (body) => {
			const { timeoutMs } = body as { timeoutMs?: number };
			await node.waitForReady(timeoutMs);
			return success({ ready: true });
		},
		'POST /channel/wait-ready': async (body) => {
			const { channelId, timeoutMs } = body as {
				channelId: string;
				timeoutMs?: number;
			};
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			await node.waitForChannelReady(channelId, timeoutMs);
			return success({ channelId, ready: true });
		},
		'POST /payment/wait': async (body) => {
			const { paymentHash, timeoutMs } = body as {
				paymentHash: string;
				timeoutMs?: number;
			};
			if (!paymentHash)
				return failure('INVALID_PARAMS', 'paymentHash required');
			return success(await node.waitForPayment(paymentHash, timeoutMs));
		},

		// ── Route Estimation ──
		'POST /route/estimate': (body) => {
			const { bolt11, amountSats } = body as {
				bolt11: string;
				amountSats?: number;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			const estimate = node.estimateRouteFee(bolt11, amountSats);
			if (!estimate) return failure('NO_ROUTE', 'No route found');
			return success(estimate);
		},

		// ── Payment Intelligence ──
		'POST /payment/estimate': (body) => {
			const { bolt11, amountSats } = body as {
				bolt11: string;
				amountSats?: number;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			const estimate = node.estimatePayment(bolt11, amountSats);
			if (!estimate)
				return failure(
					'NO_ROUTE',
					'Unable to estimate payment (no route or invalid invoice)'
				);
			return success(estimate);
		},

		// ── Channel Readiness ──
		'GET /channels/ready': () => success(node.getReadyChannels()),
		'GET /can-send': (_body, query) => {
			const amountSats = parseIntParam(query, 'amountSats', { min: 0 }) ?? 0;
			return success(node.canSend(amountSats));
		},
		'GET /can-receive': (_body, query) => {
			const amountSats = parseIntParam(query, 'amountSats', { min: 0 }) ?? 0;
			return success(node.canReceive(amountSats));
		},

		// ── Payment Metadata ──
		'POST /payment/metadata': (body) => {
			const { paymentHash, metadata } = body as {
				paymentHash: string;
				metadata: Record<string, string>;
			};
			if (!paymentHash || !metadata)
				return failure('INVALID_PARAMS', 'paymentHash and metadata required');
			node.setPaymentMetadata(paymentHash, metadata);
			return success({ updated: true });
		},

		// ── Route Probing ──
		'POST /route/probe': (body) => {
			const { destination, amountSats } = body as {
				destination: string;
				amountSats: number;
			};
			if (!destination || amountSats === undefined)
				return failure('INVALID_PARAMS', 'destination and amountSats required');
			return success(node.probeRoute(destination, amountSats));
		},

		// ── Graph Queries ──
		'GET /graph/info': () => success(node.getGraphInfo()),
		'GET /graph/node': (_body, query) => {
			const pubkey = query.get('pubkey');
			if (!pubkey) return failure('INVALID_PARAMS', 'pubkey required');
			const info = node.getGraphNode(pubkey);
			if (!info) return failure('NOT_FOUND', 'Node not found in graph');
			return success(info);
		},
		'GET /graph/channel': (_body, query) => {
			const scid = query.get('scid');
			if (!scid) return failure('INVALID_PARAMS', 'scid required');
			const info = node.getGraphChannel(scid);
			if (!info) return failure('NOT_FOUND', 'Channel not found in graph');
			return success(info);
		},
		'GET /graph/describe': (_body, query) => {
			const limitParam = query.get('limit');
			const offsetParam = query.get('offset');
			let limit: number | undefined;
			let offset: number | undefined;
			if (limitParam !== null) {
				limit = Number(limitParam);
				if (!Number.isInteger(limit) || limit < 1)
					return failure('INVALID_PARAMS', 'limit must be a positive integer');
			}
			if (offsetParam !== null) {
				offset = Number(offsetParam);
				if (!Number.isInteger(offset) || offset < 0)
					return failure(
						'INVALID_PARAMS',
						'offset must be a non-negative integer'
					);
			}
			return success(node.describeGraph(limit, offset));
		},

		// ── Route Query / Send-to-Route ──
		'POST /route/query': (body) => {
			const { destination, amountSats, maxFeeSats } = body as {
				destination: string;
				amountSats: number;
				maxFeeSats?: number;
			};
			if (!destination || amountSats === undefined)
				return failure('INVALID_PARAMS', 'destination and amountSats required');
			return success(node.queryRoute(destination, amountSats, maxFeeSats));
		},
		'POST /payment/send-to-route': (body) => {
			const { paymentHash, route, paymentSecret } = body as {
				paymentHash: string;
				route: { hops: RouteHop[] };
				paymentSecret?: string;
			};
			if (!paymentHash || !route)
				return failure('INVALID_PARAMS', 'paymentHash and route required');
			return success(node.sendToRoute(paymentHash, route, paymentSecret));
		},

		// ── Message Signing ──
		'POST /message/sign': (body) => {
			const { message } = body as { message?: string };
			if (!message) return failure('INVALID_PARAMS', 'message required');
			return success(node.signMessage(message));
		},
		'POST /message/verify': (body) => {
			const { message, signature } = body as {
				message?: string;
				signature?: string;
			};
			if (!message || !signature)
				return failure('INVALID_PARAMS', 'message and signature required');
			return success(node.verifyMessage(message, signature));
		},

		// ── Gossip Sync ──
		'POST /gossip/sync': (body) => {
			const { pubkey } = body as { pubkey?: string };
			return success({ syncedFrom: node.syncGossip(pubkey) });
		},
		'POST /gossip/sync-rapid': async () => {
			const result = await node.syncRapidGossip();
			if (!result) {
				return failure(
					'INVALID_PARAMS',
					'Rapid gossip sync is only available on mainnet'
				);
			}
			return success(result);
		},

		// ── Diagnostics & Recovery ──
		'GET /channel/diagnostics': (body, query) => {
			const channelId =
				query.get('channelId') || (body as { channelId?: string }).channelId;
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const diagnostics = node.getChannelDiagnostics(channelId);
			if (!diagnostics) return failure('NOT_FOUND', 'Channel not found');
			return success(diagnostics);
		},
		'POST /address/validate': (body) => {
			const { address } = body as { address?: string };
			if (!address) return failure('INVALID_PARAMS', 'address required');
			return success({ address, valid: node.validateAddress(address) });
		},
		'POST /recover-fallback-funds': async (body) => {
			const { feeRatePerVbyte } = body as { feeRatePerVbyte?: number };
			const result = await node.recoverFallbackFunds(
				feeRatePerVbyte !== undefined ? { feeRatePerVbyte } : undefined
			);
			return success(result ?? { recovered: false });
		},
		'POST /backup/trigger': () => {
			node.triggerBackup();
			return success({ triggered: true });
		},

		// ── Database Backup ──
		'POST /backup': async (body) => {
			const { destPath } = body as { destPath: string };
			if (!destPath) return failure('INVALID_PARAMS', 'destPath required');
			if (
				destPath.includes('..') ||
				destPath.includes('%2e%2e') ||
				destPath.includes('%2E%2E')
			) {
				return failure('INVALID_PARAMS', 'Path traversal not allowed');
			}
			await node.backup(destPath);
			return success({ backed_up: true });
		},
		'GET /backup/scb': () => success(node.exportStaticChannelBackup()),
		// Newest valid SCB returned by a peer via BOLT 1 peer storage. Recovery
		// stays explicit: POST /restore/scb with the returned `encoded` blob.
		'GET /backup/peer-retrieved': () => {
			const retrieved = node.getPeerRetrievedBackup();
			if (!retrieved) {
				return failure(
					'NOT_FOUND',
					'No peer-retrieved backup this session (no capable peer has returned our SCB yet)'
				);
			}
			return success(retrieved);
		},
		'POST /restore/scb': async (body) => {
			const { encoded, path: scbPath } = body as {
				encoded?: string;
				path?: string;
			};
			if ((encoded ? 1 : 0) + (scbPath ? 1 : 0) !== 1) {
				return failure(
					'INVALID_PARAMS',
					'Provide exactly one of encoded or path'
				);
			}
			let blob = encoded;
			if (scbPath) {
				if (
					scbPath.includes('..') ||
					scbPath.includes('%2e%2e') ||
					scbPath.includes('%2E%2E')
				) {
					return failure('INVALID_PARAMS', 'Path traversal not allowed');
				}
				try {
					blob = fs.readFileSync(scbPath, 'utf8');
				} catch (err) {
					return failure(
						'INVALID_PARAMS',
						`Cannot read SCB file: ${(err as Error).message}`
					);
				}
			}
			return success(await node.restoreFromScb(blob!));
		},

		// ── BOLT 12 Offers ──
		'POST /offer/create': (body) => {
			const { description, amountSats, issuer, expirySecs } = body as {
				description: string;
				amountSats?: number;
				issuer?: string;
				expirySecs?: number;
			};
			if (!description)
				return failure('INVALID_PARAMS', 'description required');
			return success(
				node.createOffer({ description, amountSats, issuer, expirySecs })
			);
		},
		'GET /offers': () => success(node.listOffers()),
		'DELETE /offer': (_body, query) => {
			const offerId = query.get('offerId');
			if (!offerId) return failure('INVALID_PARAMS', 'offerId required');
			const removed = node.removeOffer(offerId);
			if (!removed) return failure('NOT_FOUND', 'Offer not found');
			return success({ removed: true });
		},
		'POST /offer/pay': async (body) => {
			const { offer, amountSats, timeoutMs } = body as {
				offer: string;
				amountSats?: number;
				timeoutMs?: number;
			};
			if (!offer) return failure('INVALID_PARAMS', 'offer required');
			return success(await node.payOffer(offer, amountSats, timeoutMs));
		},

		// ── Guardian Recovery (docs/RECOVERY-PROTOCOL.md section 8) ──
		// Distinct from the SCB flows above: an SCB restore force-closes every
		// channel; a guardian restore RESUMES them from replicated state.
		'GET /recovery/status': () => success(node.getRecoverySurfaceStatus()),
		'POST /recovery/restore': async (body) => {
			// The epoch takeover permanently fences any still-running old
			// writer, so a bare POST must not trigger it by accident.
			const { confirm } = body as { confirm?: boolean };
			if (confirm !== true) {
				return failure(
					'INVALID_PARAMS',
					'Guardian restore permanently fences the previous writer; ' +
						'pass {"confirm": true} to proceed'
				);
			}
			return success(await node.restoreFromGuardians());
		},
		'POST /recovery/restore-capsule': async (body) => {
			// Peer-storage mode: restore from the Recovery Capsules storage
			// peers returned (spec 5.4). Local durability has no fencing, so
			// an old device still running would keep acting on the same
			// channels; a bare POST must not start that by accident.
			const { confirm, unfenced } = body as {
				confirm?: boolean;
				unfenced?: boolean;
			};
			if (confirm !== true) {
				return failure(
					'INVALID_PARAMS',
					'Capsule restore replaces this database with the retrieved ' +
						'state and, at Tier 2, requires a daemon restart; pass ' +
						'{"confirm": true} to proceed'
				);
			}
			if (unfenced !== undefined && typeof unfenced !== 'boolean') {
				return failure('INVALID_PARAMS', 'unfenced must be a boolean');
			}
			return success(await node.restoreFromCapsules({ unfenced }));
		},
		'POST /recovery/capsule-guardians': (body) => {
			// The one place a retrieved capsule's guardian credentials leave
			// the daemon (the status route redacts them): admin scope, and an
			// explicit confirm so a scripted status sweep cannot collect them.
			const { confirm } = body as { confirm?: boolean };
			if (confirm !== true) {
				return failure(
					'INVALID_PARAMS',
					'This returns the guardian set of the best retrieved capsule ' +
						'INCLUDING transport credentials; pass {"confirm": true} ' +
						'to proceed'
				);
			}
			return success(node.revealCapsuleGuardians());
		},

		// ── Webhooks ──
		'POST /webhooks/register': (body) => {
			const { url, events, secret } = body as {
				url: string;
				events: string[];
				secret?: string;
			};
			if (!url || !events || !Array.isArray(events) || events.length === 0) {
				return failure('INVALID_PARAMS', 'url and events array required');
			}
			return success(webhookManager.register(url, events, secret));
		},
		'DELETE /webhooks/unregister': (body) => {
			const { id } = body as { id: string };
			if (!id) return failure('INVALID_PARAMS', 'id required');
			const removed = webhookManager.unregister(id);
			if (!removed) return failure('NOT_FOUND', 'Webhook not found');
			return success({ unregistered: true });
		},
		'GET /webhooks': () => success(webhookManager.list()),

		// ── Payment Queue ──
		'POST /queue/add': (body) => {
			const { bolt11, priority, amountSats, maxFeeSats, metadata } = body as {
				bolt11: string;
				priority?: number;
				amountSats?: number;
				maxFeeSats?: number;
				metadata?: Record<string, string>;
			};
			if (!bolt11) return failure('INVALID_PARAMS', 'bolt11 required');
			return success(
				paymentQueue.enqueue(bolt11, priority, {
					amountSats,
					maxFeeSats,
					metadata
				})
			);
		},
		'GET /queue': () => success(paymentQueue.list()),
		'POST /queue/cancel': (body) => {
			const { id } = body as { id: string };
			if (!id) return failure('INVALID_PARAMS', 'id required');
			const cancelled = paymentQueue.cancel(id);
			if (!cancelled)
				return failure(
					'NOT_FOUND',
					'Queued payment not found or already processing'
				);
			return success({ cancelled: true });
		},

		// ── Scoped API keys (admin-only) ──
		'GET /auth/keys': () => success({ keys: authenticator.listKeys() }),
		'POST /auth/keys/revoke': (body) => {
			const { name } = body as { name?: string };
			if (!name) return failure('INVALID_PARAMS', 'name required');
			const revoked = authenticator.revoke(name);
			if (!revoked)
				return failure(
					'NOT_FOUND',
					`No API key named "${name}" (the legacy apiToken has no name; remove it from the config and restart)`
				);
			return success({ revoked: name });
		},
		'POST /auth/keys/rotate': (body) => {
			const { name } = body as { name?: string };
			if (!name) return failure('INVALID_PARAMS', 'name required');
			const rotated = authenticator.rotate(name);
			if (!rotated)
				return failure(
					'NOT_FOUND',
					`No API key named "${name}" (the legacy apiToken has no name and cannot be rotated; change it in the config and restart)`
				);
			return success({
				...rotated,
				warning:
					'Store this key now: it is shown only once and cannot be retrieved again'
			});
		}
	};

	// DEPRECATED alias: the old name implied routing fee policy, but the handler
	// sets the commitment feerate. Kept for compatibility; remove in a future major.
	routes['POST /channel/update-fee'] =
		routes['POST /channel/update-commitment-feerate'];

	const sseClients: Set<http.ServerResponse> = new Set();

	const corsOrigin =
		opts.cors === true ? '*' : typeof opts.cors === 'string' ? opts.cors : null;

	const requestHandler = async (
		req: http.IncomingMessage,
		res: http.ServerResponse
	): Promise<void> => {
		const parsedUrl = new URL(
			req.url || '/',
			`http://${req.headers.host || 'localhost'}`
		);
		// API versioning: strip /v1/ prefix for backward compat
		let pathname = parsedUrl.pathname;
		if (pathname.startsWith('/v1/')) {
			pathname = pathname.slice(3); // '/v1/info' → '/info'
		}
		const query = parsedUrl.searchParams;
		const routeKey = `${req.method} ${pathname}`;
		res.setHeader('X-API-Version', '1');

		// ── CORS headers ──
		if (corsOrigin) {
			res.setHeader('Access-Control-Allow-Origin', corsOrigin);
			res.setHeader(
				'Access-Control-Allow-Methods',
				'GET, POST, DELETE, OPTIONS'
			);
			res.setHeader(
				'Access-Control-Allow-Headers',
				'Content-Type, Authorization'
			);
		}

		// ── OPTIONS preflight ──
		if (req.method === 'OPTIONS') {
			res.statusCode = 204;
			res.end();
			return;
		}

		// ── Rate limiting (opt-in) ──
		// Runs before every auth check (including the SSE endpoint's) so
		// failed authentication attempts count against the bucket; keyed on
		// the peer address because the Authorization header is
		// caller-controlled and varying it would mint a fresh bucket per
		// guess. X-Forwarded-For is honored only from configured
		// trustedProxies; otherwise a proxy's clients share its bucket.
		const authExempt =
			AUTH_EXEMPT_ROUTES.has(routeKey) ||
			(routeKey === 'GET /metrics' && opts.metricsPublic === true);
		if (rateLimiter && !authExempt) {
			const clientKey = clientKeyForRequest(
				req.socket.remoteAddress,
				req.headers['x-forwarded-for'],
				opts.rateLimit?.trustedProxies
			);
			if (!rateLimiter.isAllowed(clientKey)) {
				res.setHeader('Content-Type', 'application/json');
				res.statusCode = 429;
				res.end(JSON.stringify(failure('RATE_LIMITED', 'Too many requests')));
				return;
			}
		}

		// ── SSE endpoint ──
		if (routeKey === 'GET /events') {
			if (authenticator.enabled) {
				const auth = authenticator.authenticate(req.headers['authorization']);
				if (!auth.ok) {
					res.setHeader('Content-Type', 'application/json');
					res.statusCode = 401;
					res.end(
						JSON.stringify(
							failure('UNAUTHORIZED', 'Invalid or missing Authorization header')
						)
					);
					return;
				}
				if (!scopesAllowRoute(auth.scopes, routeKey)) {
					res.setHeader('Content-Type', 'application/json');
					res.statusCode = 403;
					res.end(
						JSON.stringify(
							failure('FORBIDDEN', insufficientScopeMessage(auth, routeKey))
						)
					);
					return;
				}
			}
			const sseHeaders: Record<string, string> = {
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				Connection: 'keep-alive'
			};
			if (corsOrigin) {
				sseHeaders['Access-Control-Allow-Origin'] = corsOrigin;
				sseHeaders['Access-Control-Allow-Methods'] =
					'GET, POST, DELETE, OPTIONS';
				sseHeaders['Access-Control-Allow-Headers'] =
					'Content-Type, Authorization';
			}
			res.writeHead(200, sseHeaders);
			// SSE comment line: parsers ignore it; flushes headers to the client
			// immediately instead of buffering until the first event/keepalive.
			res.write(': connected\n\n');
			sseClients.add(res);
			// Send keepalive every 30s to prevent proxy timeouts
			const keepalive = setInterval(() => {
				res.write(': keepalive\n\n');
			}, 30_000);
			req.on('close', () => {
				clearInterval(keepalive);
				sseClients.delete(res);
			});
			return;
		}

		res.setHeader('Content-Type', 'application/json');

		// ── Auth middleware ──
		// 401 for a bad/absent key, 403 for a valid key without the required
		// scope. Unclassified routes fail closed to admin-only (see
		// ROUTE_SCOPES in auth.ts and the drift test that keeps it complete).
		if (authenticator.enabled && !authExempt) {
			const auth = authenticator.authenticate(req.headers['authorization']);
			if (!auth.ok) {
				res.statusCode = 401;
				res.end(
					JSON.stringify(
						failure('UNAUTHORIZED', 'Invalid or missing Authorization header')
					)
				);
				return;
			}
			if (!scopesAllowRoute(auth.scopes, routeKey)) {
				res.statusCode = 403;
				res.end(
					JSON.stringify(
						failure('FORBIDDEN', insufficientScopeMessage(auth, routeKey))
					)
				);
				return;
			}
		}

		// ── Restore-pending hold (docs/RECOVERY-PROTOCOL.md section 8) ──
		// A daemon booted against a fresh database whose recovery namespace
		// the guardian set holds has no node underneath it yet: only the
		// recovery surface (plus SSE above, stop and the spec) can answer.
		// Everything else, /health included, refuses with a code that says
		// exactly what to do; health checks reading 503 as not-ready is the
		// truthful answer for a node awaiting its state.
		if (node.restorePending && !RESTORE_PENDING_ROUTES.has(routeKey)) {
			endWithResult(
				res,
				failure(
					'NODE_RESTORE_PENDING',
					'This daemon is holding for a guardian restore: the database ' +
						'is fresh and the guardian set holds its namespace. Run the ' +
						'admin-scoped restore under /recovery, or check its status ' +
						'route.'
				)
			);
			return;
		}
		if (node.restartRequired && !RESTART_REQUIRED_ROUTES.has(routeKey)) {
			endWithResult(
				res,
				failure(
					'NODE_RESTART_REQUIRED',
					'A capsule restore replaced this database; restart the daemon ' +
						'to run on the restored state (the status route under ' +
						'/recovery reports the restore).'
				)
			);
			return;
		}

		// ── Prometheus metrics endpoint (text/plain) ──
		// Sits behind the auth middleware: it reports balances, channel and
		// peer counts, which are finances, not liveness (metricsPublic opts
		// back into the old unauthenticated behavior).
		if (routeKey === 'GET /metrics') {
			res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
			res.end(node.getMetrics());
			return;
		}

		// Handle /stop specially — graceful shutdown
		if (req.method === 'POST' && pathname === '/stop') {
			const stopBody = await parseBody(req).catch(() => ({}));
			const drainRequested =
				(stopBody as Record<string, unknown>).drain === true;
			const drainTimeoutMs =
				typeof (stopBody as Record<string, unknown>).drainTimeoutMs === 'number'
					? ((stopBody as Record<string, unknown>).drainTimeoutMs as number)
					: 60_000;

			if (drainRequested) {
				node.setDraining(true);
				// Poll for pending payments to settle
				const drainStart = Date.now();
				while (
					node.hasPendingPayments() &&
					Date.now() - drainStart < drainTimeoutMs
				) {
					await new Promise((r) => setTimeout(r, 2000));
				}
			}
			res.end(
				JSON.stringify(success({ stopped: true, drained: drainRequested }))
			);
			await stop();
			return;
		}

		const handler = routes[routeKey];
		if (!handler) {
			res.statusCode = 404;
			res.end(JSON.stringify(failure('NOT_FOUND', `No route: ${routeKey}`)));
			return;
		}

		try {
			const body = await parseBody(req);

			// ── Idempotency key support ──
			const idempotencyKey = req.headers['x-idempotency-key'] as
				| string
				| undefined;
			if (idempotencyKey && IDEMPOTENT_ROUTES.has(routeKey)) {
				const cacheKey = `${routeKey}:${idempotencyKey}`;
				const bodyHash = JSON.stringify(body);
				const cached = idempotencyCache.get(cacheKey);
				if (cached) {
					if (cached.bodyHash !== bodyHash) {
						res.statusCode = 409;
						res.end(
							JSON.stringify(
								failure(
									'IDEMPOTENCY_CONFLICT',
									'Idempotency key already used with a different request body'
								)
							)
						);
						return;
					}
					endWithResult(res, cached.response);
					return;
				}
				const result = await handler(body, query);
				idempotencyCache.set(cacheKey, {
					response: result,
					bodyHash: bodyHash,
					expiresAt: Date.now() + IDEMPOTENCY_TTL_MS
				});
				endWithResult(res, result);
				return;
			}

			const result = await handler(body, query);
			endWithResult(res, result);
		} catch (err: unknown) {
			if (err instanceof BeignetError) {
				res.statusCode = statusForErrorCode(err.code);
				res.end(JSON.stringify(failure(err.code, err.message)));
			} else {
				// Unknown throw: log the detail server-side and answer with a
				// generic message. Raw messages leak filesystem paths and
				// database layout; HTTP 200 on errors blinds every proxy and
				// health check in front of the daemon. An unhandled exception
				// is worth a stderr line even when logging is not configured;
				// discarding it makes the generic 500 undiagnosable.
				const detail =
					err instanceof Error ? err.stack ?? err.message : String(err);
				if (logger) {
					logger.error(`Unhandled error on ${routeKey}: ${detail}`);
				} else {
					process.stderr.write(
						`[beignet-daemon] Unhandled error on ${routeKey}: ${detail}\n`
					);
				}
				res.statusCode = 500;
				res.end(
					JSON.stringify(failure('INTERNAL_ERROR', 'Internal server error'))
				);
			}
		}
	};

	// Create server (HTTP or HTTPS)
	let server: http.Server;
	if (opts.tlsCert && opts.tlsKey) {
		const tlsOptions = {
			cert: fs.readFileSync(opts.tlsCert),
			key: fs.readFileSync(opts.tlsKey)
		};
		server = https.createServer(tlsOptions, (req, res) => {
			void requestHandler(req, res);
		});
	} else {
		server = http.createServer((req, res) => {
			void requestHandler(req, res);
		});
	}

	// The one teardown path for a successful boot, shared by the POST /stop
	// route and whatever handle the caller keeps (the CLI's signal handler).
	// The in-flight promise is memoized so a second caller (a signal during
	// /stop) waits for the SAME teardown instead of resolving early and
	// letting the process exit before it finishes. Webhook registrations are
	// deliberately left alone: they persist across restarts by contract, and
	// dispatch stops with the node's listeners.
	let stopping: Promise<void> | null = null;
	const stop = (timeoutMs = 30_000): Promise<void> => {
		stopping ??= (async (): Promise<void> => {
			paymentQueue.removeAllListeners();
			await node.gracefulShutdown(timeoutMs).catch(() => node.destroy());
			if (rateLimiter) rateLimiter.destroy();
			clearInterval(idempotencyCleanupTimer);
			// SSE responses hold their sockets open indefinitely; destroy them
			// so the server can actually finish closing. destroy() fires each
			// request's close handler, which clears its keepalive interval.
			for (const client of sseClients) {
				client.destroy();
			}
			sseClients.clear();
			server.close();
		})();
		return stopping;
	};

	// Wire up SSE events from BeignetNode (already JSON-safe types)
	const sseEvents = getRelayedEvents(opts.htlcEvents);
	for (const eventName of sseEvents) {
		node.on(eventName, (data: unknown) => {
			if (sseClients.size === 0) return;
			const message = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
			for (const client of sseClients) {
				client.write(message);
			}
		});
	}

	// Wire up webhook dispatch for the same events
	for (const eventName of sseEvents) {
		node.on(eventName, (data: unknown) => {
			webhookManager.dispatch(eventName, data);
		});
	}

	return new Promise((resolve, reject) => {
		server.on('error', reject);
		server.listen(port, host, () => {
			logger?.info(`Daemon listening on ${host}:${port}`);
			resolve({ server, node, stop });
		});
	});
}
