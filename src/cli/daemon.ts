/**
 * HTTP daemon: lightweight http.createServer() on 127.0.0.1.
 * Routes HTTP endpoints to BeignetNode methods.
 * Uniform JSON envelope: { ok: true, result } or { ok: false, error: { code, message } }.
 */

import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
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
import * as bitcoinjs from 'bitcoinjs-lib';
import * as nodeCrypto from 'crypto';
import {
	attachDirectFundingReceiver,
	attachRelayForwarder,
	sendDirectFunding,
	lnTransport,
	relayTransport,
	rendezvousTopic,
	IDirectFundingReceiverDeps
} from './direct-funding';
import {
	startSwarmReceiver,
	swarmConnect,
	ISwarmReceiver
} from './swarm-transport';
import {
	onionDfDispatcher,
	createOnionLane,
	mintDfBlindedPath,
	serializeBlindedPath,
	deserializeBlindedPath
} from './df-onion';
import {
	IDfRequestEnvelope,
	IDfTransportDescriptor,
	canonicalRequestMessage,
	encodeRequestEnvelope,
	decodeAndVerifyRequestEnvelope,
	mintRequestEncryptionKeys,
	senderDeriveKey,
	encryptedTransport
} from './df-envelope';
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
	/** Announce on a DHT topic derived from the node pubkey so senders can
	 *  reach this node for direct funding with the pubkey alone. */
	swarm?: boolean;
	/** Act as a blind direct-funding relay: forward sealed RELAY frames
	 *  between connected peers, stamping the sender identity. For LSPs. */
	dfRelay?: boolean;
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

	// Beignet-native 1-tx direct funding: the recipient side is armed at
	// startup and answers offers as soon as an LSP is configured (at runtime,
	// via POST /direct-funding/configure). A beignet-aware sender's onchain
	// payment then becomes this node's channel-funding transaction directly.
	// Receipt hashes minted via /direct-funding/request live here until their
	// preimage is revealed as the delivery receipt.
	const directFundingState: {
		lspPubkey?: string;
		/** The LSP's reachable address, signed into requests as the relay
		 *  transport so senders can route sealed frames through it. */
		lspHost?: string;
		lspPort?: number;
		targetInboundSat: number;
		trusted: boolean;
		receipts: Map<
			string,
			{
				preimageHex: string;
				rendezvousSecretHex: string;
				expiresAt: number;
				requestId: string;
				encryptionPrivateKeyPem: string;
				/** Seed of the request's swarm Noise identity, so a restart
				 *  re-arms the SAME key the envelope pinned. */
				swarmSeedHex?: string;
				/** Private path_id of the request's blinded onion path. Never
				 *  present in the envelope: BOLT 4 path_id must be unknowable
				 *  to the payer, or anyone holding the request could mint a
				 *  route that passes the issued-path check. */
				onionPathSecretHex?: string;
			}
		>;
		requestsById: Map<string, string>;
		requestsByPathSecret: Map<string, string>;
	} = {
		targetInboundSat: 0,
		trusted: false,
		receipts: new Map(),
		requestsById: new Map(),
		requestsByPathSecret: new Map()
	};
	const DIRECT_FUNDING_REQUEST_TTL_MS = 60 * 60 * 1000;
	let swarmReceiver: ISwarmReceiver | null = null;
	// Outstanding requests survive a daemon restart: every envelope handed
	// out stays payable for its full hour. The file holds request secrets
	// (preimages, encryption keys, identity seeds) and lives next to the
	// wallet's other private state.
	const requestsFile = opts.dataDir
		? path.join(opts.dataDir, 'direct-funding-requests.json')
		: null;
	const persistRequests = (): void => {
		if (!requestsFile) return;
		try {
			const entries = [...directFundingState.receipts.entries()].map(
				([hash, e]) => ({ hash, ...e })
			);
			fs.writeFileSync(requestsFile, JSON.stringify(entries), {
				mode: 0o600
			});
		} catch (err) {
			process.stderr.write(
				`direct-funding: could not persist requests: ${(err as Error).message}\n`
			);
		}
	};
	// A used or expired request leaves its rendezvous topic: the receiver's
	// DHT footprint shrinks to "only while a request is outstanding".
	const retireRequest = (hashHex: string): void => {
		const entry = directFundingState.receipts.get(hashHex);
		if (!entry) return;
		directFundingState.receipts.delete(hashHex);
		directFundingState.requestsById.delete(entry.requestId);
		if (entry.onionPathSecretHex) {
			directFundingState.requestsByPathSecret.delete(entry.onionPathSecretHex);
		}
		if (swarmReceiver) {
			swarmReceiver.removeRequest(rendezvousTopic(entry.rendezvousSecretHex));
		}
		persistRequests();
	};
	const pruneExpiredRequests = (): void => {
		const now = Date.now();
		for (const [hash, entry] of directFundingState.receipts) {
			if (entry.expiresAt <= now) retireRequest(hash);
		}
	};
	const btcNetwork =
		opts.network === 'mainnet'
			? bitcoinjs.networks.bitcoin
			: opts.network === 'testnet'
			? bitcoinjs.networks.testnet
			: bitcoinjs.networks.regtest;
	const directFundingDeps: IDirectFundingReceiverDeps = {
		getLspPubkey: () => directFundingState.lspPubkey,
		getTargetInboundSat: () => directFundingState.targetInboundSat,
		getTrusted: () => directFundingState.trusted,
		getReceiptPreimage: (hashHex) => {
			const entry = directFundingState.receipts.get(hashHex);
			if (!entry || entry.expiresAt <= Date.now()) return undefined;
			return entry.preimageHex;
		},
		onReceiptUsed: (hashHex) => retireRequest(hashHex),
		getRequestEncryptionPem: (requestId) => {
			const hash = directFundingState.requestsById.get(requestId);
			if (!hash) return undefined;
			const entry = directFundingState.receipts.get(hash);
			if (!entry || entry.expiresAt <= Date.now()) return undefined;
			return entry.encryptionPrivateKeyPem;
		},
		resolveOnionPathSecret: (pathSecretHex) => {
			const hash = directFundingState.requestsByPathSecret.get(pathSecretHex);
			if (!hash) return undefined;
			const entry = directFundingState.receipts.get(hash);
			if (!entry || entry.expiresAt <= Date.now()) return undefined;
			return entry.requestId;
		},
		network: btcNetwork,
		onEvent: (kind, detail) => {
			process.stderr.write(`direct-funding ${kind}: ${detail}\n`);
		}
	};
	attachDirectFundingReceiver(node, directFundingDeps);
	// Blind relay (opt-in, LSP role): forward sealed frames between connected
	// peers. The relay stamps sender identity and reads nothing else.
	if (opts.dfRelay) {
		attachRelayForwarder(node);
	}
	// All onion-message direct-funding frames a wallet receives arrive from
	// ONE peer (its introduction node), and an LSP forwards for many senders
	// over each wallet connection, so the conservative per-peer default
	// aggregates across every concurrent exchange. Raise it to a level that
	// throttles abuse, not payments.
	node.lightningNode
		.getOnionMessageManager()
		.setRateLimitConfig({ maxPerWindow: 120 });
	// Swarm listener (opt-in): announce on a DHT topic derived from the node
	// pubkey, so senders holding only the pubkey from a payment request can
	// reach this node with no dialable address.
	if (opts.swarm) {
		try {
			swarmReceiver = startSwarmReceiver(node, directFundingDeps, (l) =>
				process.stderr.write(`${l}\n`)
			);
		} catch (err) {
			process.stderr.write(
				`swarm listener failed to start: ${(err as Error).message}\n`
			);
		}
	}
	// Restore outstanding requests from disk: entries reload into the maps
	// and each request's swarm identity re-arms from its persisted seed, so
	// the Noise key the envelope pinned answers again. Expired entries are
	// dropped on the way in.
	if (requestsFile && fs.existsSync(requestsFile)) {
		try {
			const raw = JSON.parse(fs.readFileSync(requestsFile, 'utf8')) as Array<{
				hash: string;
				preimageHex: string;
				rendezvousSecretHex: string;
				expiresAt: number;
				requestId: string;
				encryptionPrivateKeyPem: string;
				swarmSeedHex?: string;
				onionPathSecretHex?: string;
			}>;
			const now = Date.now();
			let restored = 0;
			for (const e of raw) {
				if (!e?.hash || e.expiresAt <= now) continue;
				const { hash, ...entry } = e;
				directFundingState.receipts.set(hash, entry);
				directFundingState.requestsById.set(entry.requestId, hash);
				if (entry.onionPathSecretHex) {
					directFundingState.requestsByPathSecret.set(
						entry.onionPathSecretHex,
						hash
					);
				}
				if (swarmReceiver && entry.swarmSeedHex) {
					swarmReceiver.addRequest(
						rendezvousTopic(entry.rendezvousSecretHex),
						Buffer.from(entry.swarmSeedHex, 'hex')
					);
				}
				restored++;
			}
			persistRequests();
			if (restored > 0) {
				process.stderr.write(
					`direct-funding: restored ${restored} outstanding request(s)\n`
				);
			}
		} catch (err) {
			process.stderr.write(
				`direct-funding: could not restore requests: ${(err as Error).message}\n`
			);
		}
	}

	const routes: Record<string, RouteHandler> = {
		// ── Direct funding (1-tx receive) ──
		'POST /direct-funding/configure': (body) => {
			const { lspPubkey, lspHost, lspPort, targetInboundSat, trusted } =
				body as {
					lspPubkey?: string;
					/** Where the LSP is reachable; signed into payment requests as
					 *  the relay transport (the production default for senders that
					 *  cannot reach the receiver directly). */
					lspHost?: string;
					lspPort?: number;
					targetInboundSat?: number;
					/** Negotiate option_zeroconf into direct-funded opens (the LSP
					 *  must trust this node). */
					trusted?: boolean;
				};
			if (!lspPubkey) return failure('INVALID_PARAMS', 'lspPubkey required');
			directFundingState.lspPubkey = lspPubkey;
			if (lspHost !== undefined) directFundingState.lspHost = lspHost;
			if (lspPort !== undefined) directFundingState.lspPort = lspPort;
			if (targetInboundSat !== undefined) {
				directFundingState.targetInboundSat = targetInboundSat;
			}
			if (trusted !== undefined) directFundingState.trusted = trusted;
			return success({
				lspPubkey: directFundingState.lspPubkey,
				lspHost: directFundingState.lspHost ?? null,
				lspPort: directFundingState.lspPort ?? null,
				targetInboundSat: directFundingState.targetInboundSat,
				trusted: directFundingState.trusted
			});
		},
		'GET /direct-funding/config': () =>
			success({
				lspPubkey: directFundingState.lspPubkey ?? null,
				lspHost: directFundingState.lspHost ?? null,
				lspPort: directFundingState.lspPort ?? null,
				targetInboundSat: directFundingState.targetInboundSat,
				trusted: directFundingState.trusted
			}),
		// Mint a receipt hash for an onchain payment request. The preimage
		// stays here; a beignet sender's direct funding carrying this hash is
		// answered with the preimage after broadcast — a provable delivery
		// receipt bound to the request.
		'POST /direct-funding/request': (body) => {
			pruneExpiredRequests();
			const { host, port, amountSats } = body as {
				/** Host hint for the identified Lightning path, signed into the
				 *  envelope so a sender knows the receiver vouched for it. */
				host?: string;
				port?: number;
				amountSats?: number;
			};
			const preimage = nodeCrypto.randomBytes(32);
			const hash = nodeCrypto
				.createHash('sha256')
				.update(preimage)
				.digest('hex');
			// Dedicated rendezvous secret, separate from the receipt hash:
			// discovery and receipt semantics get independent lifecycles.
			const rendezvousSecretHex = nodeCrypto.randomBytes(32).toString('hex');
			const requestId = nodeCrypto.randomBytes(16).toString('hex');
			const encryption = mintRequestEncryptionKeys();
			const expiresAt = Date.now() + DIRECT_FUNDING_REQUEST_TTL_MS;
			const transports: IDfTransportDescriptor[] = [];
			let swarmSeedHex: string | undefined;
			let onionPathSecretHex: string | undefined;
			if (host && port) transports.push({ type: 'ln', host, port });
			if (
				directFundingState.lspPubkey &&
				directFundingState.lspHost &&
				directFundingState.lspPort
			) {
				// Onion path first: same reach as the relay (via the LSP), none
				// of the metadata. The path_id inside the blinded path is a
				// PRIVATE per-request secret (not the request id the payer
				// holds), so only a path this node minted can carry it.
				try {
					onionPathSecretHex = nodeCrypto.randomBytes(32).toString('hex');
					transports.push({
						type: 'onion',
						host: directFundingState.lspHost,
						port: directFundingState.lspPort,
						path: serializeBlindedPath(
							mintDfBlindedPath(
								directFundingState.lspPubkey,
								node.getInfo().nodeId,
								onionPathSecretHex
							)
						)
					});
				} catch {
					onionPathSecretHex = undefined;
					/* blinded path minting failed: request still works via relay */
				}
				// The relay is the onion path's introduction node, so when the
				// onion descriptor is present a separate lsp descriptor would
				// duplicate it byte for byte; the sender synthesizes the relay
				// fallback from the onion intro instead. Emitted only when the
				// blinded path could not be minted.
				if (!onionPathSecretHex) {
					transports.push({
						type: 'lsp',
						nodeId: directFundingState.lspPubkey,
						host: directFundingState.lspHost,
						port: directFundingState.lspPort
					});
				}
			}
			if (swarmReceiver) {
				// A fresh Noise identity (and DHT node) exists for this request
				// alone; the envelope pins it, and it dies with the request. The
				// seed is persisted so a daemon restart re-arms the same key.
				const seed = nodeCrypto.randomBytes(32);
				swarmSeedHex = seed.toString('hex');
				transports.push({
					type: 'swarm',
					rendezvous: rendezvousSecretHex,
					noiseKey: swarmReceiver.addRequest(
						rendezvousTopic(rendezvousSecretHex),
						seed
					)
				});
			}
			const unsigned: Omit<IDfRequestEnvelope, 'sig'> = {
				v: 2,
				requestId,
				receiverNodeId: node.getInfo().nodeId,
				expiresAt,
				...(amountSats && amountSats > 0 ? { amountSat: amountSats } : {}),
				receiptHash: hash,
				encryptionKey: encryption.publicKeyHex,
				transports
			};
			const sig = node.signMessage(
				canonicalRequestMessage(unsigned)
			).signature;
			directFundingState.receipts.set(hash, {
				preimageHex: preimage.toString('hex'),
				rendezvousSecretHex,
				expiresAt,
				requestId,
				encryptionPrivateKeyPem: encryption.privateKeyPem,
				...(swarmSeedHex ? { swarmSeedHex } : {}),
				...(onionPathSecretHex ? { onionPathSecretHex } : {})
			});
			directFundingState.requestsById.set(requestId, hash);
			if (onionPathSecretHex) {
				directFundingState.requestsByPathSecret.set(onionPathSecretHex, hash);
			}
			persistRequests();
			return success({
				paymentHash: hash,
				expiresAt,
				request: encodeRequestEnvelope({ ...unsigned, sig })
			});
		},
		// Sender side: pay a beignet payment request by funding the receiver's
		// channel directly from one of our UTXOs. The request is decoded and
		// its node-key signature and expiry verified before ANY network
		// activity; transports are tried in the order the receiver signed them
		// (identified Lightning path first, then the pinned per-request DHT
		// rendezvous); every frame is sealed to the request's encryption key.
		'POST /direct-funding/send': async (body) => {
			const { request, amountSats, feeHeadroomSats } = body as {
				request?: string;
				amountSats?: number;
				feeHeadroomSats?: number;
			};
			if (!request)
				return failure('INVALID_PARAMS', 'request (payment request) required');
			const env = decodeAndVerifyRequestEnvelope(request);
			const amount = env.amountSat ?? amountSats;
			if (!amount || amount <= 0)
				return failure(
					'INVALID_PARAMS',
					'amountSats required: the request does not fix an amount'
				);
			if (env.amountSat && amountSats && amountSats !== env.amountSat)
				return failure(
					'INVALID_PARAMS',
					`the request fixes the amount at ${env.amountSat} sats`
				);
			const { keys, ephemeralPublicHex } = senderDeriveKey(
				env.encryptionKey,
				env.requestId
			);
			const sendOpts = {
				recipientPubkey: env.receiverNodeId,
				amountSat: amount,
				feeHeadroomSat: feeHeadroomSats ?? 1000,
				receiptHashHex: env.receiptHash
			};
			// One retry with a short pause absorbs transient connect failures
			// (a peer mid-restart, a listener racing up) without changing the
			// exactly-once protocol semantics: retries happen strictly BEFORE
			// any frame flows, never after.
			const connectWithRetry = async (
				peerId: string,
				host: string,
				port: number
			): Promise<boolean> => {
				for (let attempt = 0; attempt < 2; attempt++) {
					const ok = await node
						.connectPeer(peerId, host, port)
						.then(() => true)
						.catch(() => node.listPeers().some((p) => p.pubkey === peerId));
					if (ok) return true;
					if (attempt === 0) {
						await new Promise((r) => setTimeout(r, 1500));
					}
				}
				return false;
			};
			const ln = env.transports.find((t) => t.type === 'ln');
			if (ln?.host && ln?.port) {
				const connected = await connectWithRetry(
					env.receiverNodeId,
					ln.host,
					ln.port
				);
				if (connected) {
					return success(
						await sendDirectFunding(
							node,
							btcNetwork,
							encryptedTransport(
								lnTransport(node, env.receiverNodeId),
								keys,
								env.requestId,
								{ ephemeralPublicHex }
							),
							sendOpts
						)
					);
				}
			}
			// Onion transport: route sealed frames through the introduction
			// node as onion messages over the request's blinded path, with our
			// own blinded reply path attached to every frame. The intro node
			// forwards fixed-size onions it cannot read; the receiver never
			// learns our node id. An unusable descriptor or an unreachable
			// intro node falls through; once frames flow the attempt commits.
			const on = env.transports.find((t) => t.type === 'onion');
			if (on?.host && on.port && on.path) {
				let onionPath: ReturnType<typeof deserializeBlindedPath> | null =
					null;
				try {
					onionPath = deserializeBlindedPath(on.path);
				} catch {
					onionPath = null;
				}
				if (onionPath) {
					const introId = onionPath.introductionNodeId.toString('hex');
					const introUp = await connectWithRetry(introId, on.host, on.port);
					if (introUp) {
						const dispatcher = onionDfDispatcher(node);
						const localPathId = nodeCrypto.randomBytes(16).toString('hex');
						const lane = createOnionLane(node, dispatcher, localPathId, {
							sendPath: onionPath,
							includeReplyPath: mintDfBlindedPath(
								introId,
								node.getInfo().nodeId,
								localPathId
							)
						});
						return success(
							await sendDirectFunding(
								node,
								btcNetwork,
								encryptedTransport(lane, keys, env.requestId, {
									ephemeralPublicHex
								}),
								sendOpts
							)
						);
					}
				}
			}
			// Relay transport: connect to the receiver's LSP and route sealed
			// frames through it. Frames stay opaque to the relay; only
			// connection failures fall through to the next transport.
			const onionDesc = env.transports.find((t) => t.type === 'onion');
			const lsp =
				env.transports.find((t) => t.type === 'lsp') ??
				(onionDesc?.path && onionDesc.host && onionDesc.port
					? {
							type: 'lsp' as const,
							nodeId: onionDesc.path.intro,
							host: onionDesc.host,
							port: onionDesc.port
					  }
					: undefined);
			if (lsp?.nodeId && lsp.host && lsp.port) {
				const relayUp = await connectWithRetry(lsp.nodeId, lsp.host, lsp.port);
				if (relayUp) {
					return success(
						await sendDirectFunding(
							node,
							btcNetwork,
							encryptedTransport(
								relayTransport(node, lsp.nodeId, env.receiverNodeId),
								keys,
								env.requestId,
								{ ephemeralPublicHex }
							),
							sendOpts
						)
					);
				}
			}
			const sw = env.transports.find((t) => t.type === 'swarm');
			if (!sw?.rendezvous)
				return failure(
					'UNREACHABLE',
					'no reachable transport in the payment request'
				);
			const { transport, close } = await swarmConnect(
				rendezvousTopic(sw.rendezvous),
				{ expectedNoiseKeyHex: sw.noiseKey }
			);
			try {
				return success(
					await sendDirectFunding(
						node,
						btcNetwork,
						encryptedTransport(transport, keys, env.requestId, {
							ephemeralPublicHex
						}),
						sendOpts
					)
				);
			} finally {
				void close();
			}
		},

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
					// eslint-disable-next-line @typescript-eslint/no-explicit-any -- query params are unvalidated strings; listPayments tolerates unknown values
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
					// eslint-disable-next-line @typescript-eslint/no-explicit-any -- query params are unvalidated strings; listForwards tolerates unknown values
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
					// eslint-disable-next-line @typescript-eslint/no-explicit-any -- query params are unvalidated strings; getActionLog tolerates unknown values
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
		'POST /channel/close': async (body) => {
			const { channelId } = body as { channelId: string };
			if (!channelId) return failure('INVALID_PARAMS', 'channelId required');
			const result = await node.closeChannel(channelId);
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
			const { amountSats, description, expirySecs, descriptionHash, minFinalCltvExpiry } =
				body as {
					amountSats?: number;
					description?: string;
					expirySecs?: number;
					descriptionHash?: string;
					/** Extra final-CLTV headroom for receives whose settlement may
					 *  fund a channel on the fly (LSP splice). */
					minFinalCltvExpiry?: number;
				};
			const hashBuf = descriptionHash
				? Buffer.from(descriptionHash, 'hex')
				: undefined;
			return success(
				node.createInvoice(
					amountSats,
					description,
					expirySecs,
					hashBuf,
					minFinalCltvExpiry
				)
			);
		},
		// Wallet side of JIT receive: registers the intent with the LSP over
		// the beignet custom-message protocol and returns an invoice payable
		// through a channel that does not exist yet. Requires the LSP peer to
		// be connected and running with jitReceive enabled.
		'POST /jit/invoice': async (body) => {
			const {
				lspPubkey,
				amountSats,
				description,
				expirySecs,
				targetRemainingInboundSat
			} = body as {
				lspPubkey?: string;
				amountSats?: number;
				description?: string;
				expirySecs?: number;
				targetRemainingInboundSat?: number;
			};
			if (!lspPubkey) return failure('INVALID_PARAMS', 'lspPubkey required');
			return success(
				await node.createJitInvoice({
					lspPubkey,
					amountSats,
					description,
					expirySecs,
					targetRemainingInboundSat
				})
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
				locktime,
				requestFunds,
				maxLeaseRates
			} = body as {
				pubkey: string;
				amountSats: number;
				fundingFeeratePerkw?: number;
				commitmentFeeratePerkw?: number;
				locktime?: number;
				/** bLIP-51 buyer: ask the peer to lease this much inbound into
				 *  the channel being opened. */
				requestFunds?: { requestedSats: number; blockheight: number };
				/** Buyer's price ceiling for the lease (required with
				 *  requestFunds); the open aborts if the seller asks more. */
				maxLeaseRates?: {
					fundingWeightWitness: number;
					leaseFeeBasis: number;
					leaseFeeBaseSat: number;
					channelFeeMaxBaseMsat: number;
					channelFeeMaxProportionalThousandths: number;
				};
			};
			if (!pubkey || amountSats === undefined)
				return failure('INVALID_PARAMS', 'pubkey and amountSats required');
			if (requestFunds && !maxLeaseRates)
				return failure(
					'INVALID_PARAMS',
					'maxLeaseRates required with requestFunds'
				);
			return success(
				node.openChannelV2(pubkey, {
					amountSats,
					fundingFeeratePerkw,
					commitmentFeeratePerkw,
					locktime,
					requestFunds,
					maxLeaseRates
				})
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
			const { channelId, amountSats, feeratePerkw, address } = body as {
				channelId: string;
				amountSats: number;
				feeratePerkw: number;
				/** Optional external destination: the splice tx pays this address
				 *  directly, so channel funds reach a third party in one
				 *  transaction with no wallet hop. Defaults to the wallet. */
				address?: string;
			};
			if (!channelId || amountSats === undefined || feeratePerkw === undefined)
				return failure(
					'INVALID_PARAMS',
					'channelId, amountSats, and feeratePerkw required'
				);
			return success(node.spliceOut(channelId, amountSats, feeratePerkw, address));
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
