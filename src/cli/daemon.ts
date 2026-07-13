/**
 * HTTP daemon: lightweight http.createServer() on 127.0.0.1.
 * Routes HTTP endpoints to BeignetNode methods.
 * Uniform JSON envelope: { ok: true, result } or { ok: false, error: { code, message } }.
 */

import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import { Console } from 'console';
import { BeignetNode, BeignetNodeOptions } from './beignet-node';
import { ILogger, createConsoleLogger } from '../logger';
import { BeignetError } from './errors';
import { ApiResponse, RouteHop } from './types';
import { getOpenApiSpec } from './openapi';
import { WebhookManager } from './webhooks';
import { PaymentQueue } from './payment-queue';
import { HttpRateLimiter, RateLimitOptions } from './http-rate-limiter';
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
				resolve({});
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

// Routes exempt from authentication
export const AUTH_EXEMPT_ROUTES = new Set([
	'GET /health',
	'GET /ready',
	'GET /openapi.json',
	'GET /metrics'
]);

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
		'channel:opening',
		'channel:ready',
		'channel:pending-close',
		'channel:force-closing',
		'channel:closed',
		'peer:connect',
		'peer:disconnect',
		// Every channel failure reason (peer rejection, funding build/broadcast
		// failure, disconnect mid-open) is reported as node:error. Without it on
		// this list a failed open is invisible to clients: the pending channel
		// just disappears and nothing ever says why.
		'node:error',
		'node:ready'
	];
	if (htlcEvents === true) {
		events.push('htlc:forwarded', 'htlc:fulfilled', 'htlc:failed');
	}
	return events;
}

export async function startDaemon(
	opts: DaemonOptions
): Promise<{ server: http.Server; node: BeignetNode }> {
	const port =
		opts.daemonPort !== undefined && opts.daemonPort !== null
			? opts.daemonPort
			: 2112;
	const host = opts.daemonHost || '127.0.0.1';
	// Validates apiKeys (names/keys/scopes) up front; throws INVALID_PARAMS
	// on bad config before the node is created.
	const authenticator = new ApiKeyAuthenticator(opts.apiToken, opts.apiKeys);
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

	// Idempotency cache
	const idempotencyCache = new Map<string, CachedResponse>();
	const idempotencyCleanupTimer = setInterval(() => {
		const now = Date.now();
		for (const [key, entry] of idempotencyCache) {
			if (now >= entry.expiresAt) idempotencyCache.delete(key);
		}
	}, IDEMPOTENCY_CLEANUP_INTERVAL_MS);
	if (idempotencyCleanupTimer.unref) idempotencyCleanupTimer.unref();

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
			if (query.get('since')) filter.since = Number(query.get('since'));
			if (query.get('limit')) filter.limit = Number(query.get('limit'));
			if (query.get('offset')) filter.offset = Number(query.get('offset'));
			if (query.get('metadataKey'))
				filter.metadataKey = query.get('metadataKey');
			if (query.get('metadataValue'))
				filter.metadataValue = query.get('metadataValue');
			return success(
				node.listPayments(
					Object.keys(filter).length > 0 ? (filter as any) : undefined
				)
			);
		},
		'GET /forwards': (_body, query) => {
			const filter: Record<string, unknown> = {};
			if (query.get('since')) filter.since = Number(query.get('since'));
			if (query.get('until')) filter.until = Number(query.get('until'));
			if (query.get('limit')) filter.limit = Number(query.get('limit'));
			if (query.get('offset')) filter.offset = Number(query.get('offset'));
			if (query.get('channelId')) filter.channelId = query.get('channelId');
			return success(
				node.listForwards(
					Object.keys(filter).length > 0 ? (filter as any) : undefined
				)
			);
		},
		'GET /forwards/summary': (_body, query) => {
			const since = query.get('since') ? Number(query.get('since')) : undefined;
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
			const windowMs = query.get('window')
				? Number(query.get('window'))
				: undefined;
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
			const count = query.get('count') ? Number(query.get('count')) : undefined;
			return success(node.getChannelSuggestions(count));
		},

		'GET /logs': (_body, query) => {
			const options: Record<string, unknown> = {};
			if (query.get('category')) options.category = query.get('category');
			if (query.get('since')) options.since = Number(query.get('since'));
			if (query.get('limit')) options.limit = Number(query.get('limit'));
			return success(
				node.getActionLog(
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
			const { pubkey, amountSats, pushSats, satsPerVbyte } = body as {
				pubkey: string;
				amountSats: number;
				pushSats?: number;
				satsPerVbyte?: number;
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			return success(
				node.openChannel(pubkey, amountSats, pushSats, satsPerVbyte)
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
				satsPerVbyte
			} = body as {
				pubkey: string;
				host: string;
				port: number;
				amountSats: number;
				pushSats?: number;
				satsPerVbyte?: number;
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
					{ pushSats, satsPerVbyte }
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

		// ── Splicing ──
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
			const amountSats = Number(query.get('amountSats') || '0');
			return success(node.canSend(amountSats));
		},
		'GET /can-receive': (_body, query) => {
			const amountSats = Number(query.get('amountSats') || '0');
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
			const { description, amountSats, issuer } = body as {
				description: string;
				amountSats?: number;
				issuer?: string;
			};
			if (!description)
				return failure('INVALID_PARAMS', 'description required');
			return success(node.createOffer({ description, amountSats, issuer }));
		},
		'GET /offers': () => success(node.listOffers()),
		'POST /offer/pay': async (body) => {
			const { offer, amountSats, timeoutMs } = body as {
				offer: string;
				amountSats?: number;
				timeoutMs?: number;
			};
			if (!offer) return failure('INVALID_PARAMS', 'offer required');
			return success(await node.payOffer(offer, amountSats, timeoutMs));
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

	// TLS validation
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
			res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
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
				sseHeaders['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
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

		// ── Prometheus metrics endpoint (text/plain) ──
		if (routeKey === 'GET /metrics') {
			res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
			res.end(node.getMetrics());
			return;
		}

		res.setHeader('Content-Type', 'application/json');

		// ── Auth middleware ──
		// 401 for a bad/absent key, 403 for a valid key without the required
		// scope. Unclassified routes fail closed to admin-only (see
		// ROUTE_SCOPES in auth.ts and the drift test that keeps it complete).
		if (authenticator.enabled && !AUTH_EXEMPT_ROUTES.has(routeKey)) {
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

		// ── Rate limiting (opt-in) ──
		if (rateLimiter && !AUTH_EXEMPT_ROUTES.has(routeKey)) {
			const clientKey =
				req.headers['authorization'] || req.socket.remoteAddress || 'unknown';
			if (!rateLimiter.isAllowed(clientKey)) {
				res.statusCode = 429;
				res.end(JSON.stringify(failure('RATE_LIMITED', 'Too many requests')));
				return;
			}
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
			webhookManager.clear();
			paymentQueue.removeAllListeners();
			await node.gracefulShutdown().catch(() => node.destroy());
			if (rateLimiter) rateLimiter.destroy();
			clearInterval(idempotencyCleanupTimer);
			server.close();
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
					res.end(JSON.stringify(cached.response));
					return;
				}
				const result = await handler(body, query);
				idempotencyCache.set(cacheKey, {
					response: result,
					bodyHash: bodyHash,
					expiresAt: Date.now() + IDEMPOTENCY_TTL_MS
				});
				res.end(JSON.stringify(result));
				return;
			}

			const result = await handler(body, query);
			res.end(JSON.stringify(result));
		} catch (err: unknown) {
			if (err instanceof BeignetError) {
				if (err.code === 'BODY_TOO_LARGE') {
					res.statusCode = 413;
				}
				res.end(JSON.stringify(failure(err.code, err.message)));
			} else {
				const msg = err instanceof Error ? err.message : String(err);
				res.end(JSON.stringify(failure('INTERNAL_ERROR', msg)));
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
		server = https.createServer(tlsOptions, requestHandler);
	} else {
		server = http.createServer(requestHandler);
	}

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
			resolve({ server, node });
		});
	});
}
