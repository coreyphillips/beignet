/**
 * The daemon's HTTP routes and what each one carries: the API key scopes it
 * accepts and how the request pipeline treats it. ROUTE_SCOPES in auth.ts and
 * the daemon's per-route sets are read from this table, and the daemon will
 * not start unless its handlers answer exactly the routes listed here.
 */

import type { ApiScope } from './auth';

export interface RouteDef {
	readonly method: 'GET' | 'POST' | 'DELETE';
	readonly path: string;
	/**
	 * The scopes the route accepts besides admin, which always qualifies, so
	 * `[]` is admin-only. 'exempt' serves the route with no credential at all.
	 */
	readonly scopes: readonly Exclude<ApiScope, 'admin'>[] | 'exempt';
	/**
	 * Honours X-Idempotency-Key: a keyed retry with the same body gets the first
	 * answer instead of running again. Any other POST that carries the header
	 * is refused, so no caller believes a retry is safe when it is not.
	 */
	readonly idempotent?: boolean;
	/**
	 * A long-poll wait. It holds a socket, a timer and node listeners until it
	 * settles, so it counts against a per-credential cap.
	 */
	readonly wait?: boolean;
	/** Served while the daemon holds for a guardian restore, with no node yet. */
	readonly allowedDuringRestore?: boolean;
	/**
	 * Served while a capsule restore rebuilds the node in-process, and after
	 * one that replaced the database, when only a restart brings a node back.
	 */
	readonly allowedWhileRestartRequired?: boolean;
	/**
	 * Answered by its own arm of the request pipeline (the event stream, the
	 * metrics text, the API document, the shutdown) rather than by a handler in
	 * the dispatch table.
	 */
	readonly inline?: boolean;
}

const ROUTE_TABLE = [
	// ── Auth-exempt: liveness probes and the API document ──
	{ method: 'GET', path: '/health', scopes: 'exempt' },
	{ method: 'GET', path: '/ready', scopes: 'exempt' },
	{
		method: 'GET',
		path: '/openapi.json',
		scopes: 'exempt',
		allowedDuringRestore: true,
		allowedWhileRestartRequired: true,
		inline: true
	},

	// ── Read-only monitoring (GET) ──
	// Not exempt: it reports balances, channel and peer counts, which are
	// finances, not liveness (metricsPublic opts back out of auth).
	{ method: 'GET', path: '/metrics', scopes: ['readonly'], inline: true },
	{ method: 'GET', path: '/info', scopes: ['readonly'] },
	{ method: 'GET', path: '/balance', scopes: ['readonly'] },
	{ method: 'GET', path: '/peers', scopes: ['readonly'] },
	{ method: 'GET', path: '/channels', scopes: ['readonly'] },
	{ method: 'GET', path: '/channels/ready', scopes: ['readonly'] },
	{ method: 'GET', path: '/payments', scopes: ['readonly'] },
	{ method: 'GET', path: '/payment', scopes: ['readonly'] },
	{ method: 'GET', path: '/onchain/sweep', scopes: ['readonly'] },
	{ method: 'GET', path: '/payment/proof', scopes: ['readonly'] },
	{ method: 'GET', path: '/payment/verify-proof', scopes: ['readonly'] },
	{ method: 'GET', path: '/forwards', scopes: ['readonly'] },
	{ method: 'GET', path: '/forwards/summary', scopes: ['readonly'] },
	{ method: 'GET', path: '/readiness', scopes: ['readonly'] },
	{ method: 'GET', path: '/stats', scopes: ['readonly'] },
	{ method: 'GET', path: '/spend-limit', scopes: ['readonly'] },
	{ method: 'GET', path: '/liquidity', scopes: ['readonly'] },
	{ method: 'GET', path: '/watchtowers', scopes: ['readonly'] },
	{ method: 'GET', path: '/advisor/recommendations', scopes: ['readonly'] },
	{ method: 'GET', path: '/fees', scopes: ['readonly'] },
	{ method: 'GET', path: '/fees/estimates', scopes: ['readonly'] },
	{ method: 'GET', path: '/transactions', scopes: ['readonly'] },
	{ method: 'GET', path: '/transactions/boostable', scopes: ['readonly'] },
	{ method: 'GET', path: '/utxos', scopes: ['readonly'] },
	{ method: 'GET', path: '/address/labels', scopes: ['readonly'] },
	{ method: 'GET', path: '/wallet/descriptors', scopes: ['readonly'] },
	{ method: 'GET', path: '/channel', scopes: ['readonly'] },
	{ method: 'GET', path: '/channel/health', scopes: ['readonly'] },
	{ method: 'GET', path: '/channel/policy', scopes: ['readonly'] },
	{ method: 'GET', path: '/channel/diagnostics', scopes: ['readonly'] },
	{ method: 'GET', path: '/channel/suggestions', scopes: ['readonly'] },
	{ method: 'GET', path: '/logs', scopes: ['readonly'] },
	{ method: 'GET', path: '/node/uri', scopes: ['readonly'] },
	{ method: 'GET', path: '/trusted-peers', scopes: ['readonly'] },
	{ method: 'GET', path: '/can-send', scopes: ['readonly'] },
	{ method: 'GET', path: '/graph/info', scopes: ['readonly'] },
	{ method: 'GET', path: '/graph/node', scopes: ['readonly'] },
	{ method: 'GET', path: '/graph/channel', scopes: ['readonly'] },
	{ method: 'GET', path: '/graph/describe', scopes: ['readonly'] },
	{ method: 'GET', path: '/backup/scb', scopes: ['readonly'] },
	{ method: 'GET', path: '/backup/peer-retrieved', scopes: ['readonly'] },
	{ method: 'GET', path: '/queue', scopes: ['readonly'] },
	// Recovery Protocol status: diagnostics, like /channel/diagnostics.
	{
		method: 'GET',
		path: '/recovery/status',
		scopes: ['readonly'],
		allowedDuringRestore: true,
		allowedWhileRestartRequired: true
	},
	// FFOR offline receive (issue #729). Reads are read-only; a slot invoice
	// is an invoice; everything that starts, closes, credits or enforces an
	// epoch moves this node's liquidity or its on-chain position and takes
	// the full key, like a force close.
	{ method: 'GET', path: '/receive/status', scopes: ['readonly'] },
	{ method: 'GET', path: '/receive/quote', scopes: ['readonly'] },
	{ method: 'POST', path: '/receive/invoice', scopes: [] },
	{ method: 'GET', path: '/ffor/epochs', scopes: ['readonly'] },
	{ method: 'GET', path: '/ffor/settlements', scopes: ['readonly'] },
	{ method: 'GET', path: '/ffor/epoch', scopes: ['readonly'] },
	{ method: 'GET', path: '/ffor/witness/status', scopes: ['readonly'] },
	{ method: 'GET', path: '/ffor/issuer/status', scopes: ['readonly'] },
	{ method: 'GET', path: '/ffor/issuer/issued', scopes: ['readonly'] },
	{ method: 'POST', path: '/ffor/invoice', scopes: ['invoice'] },
	{ method: 'POST', path: '/ffor/epoch/start', scopes: [] },
	{ method: 'POST', path: '/ffor/epoch/close', scopes: [] },
	{ method: 'POST', path: '/ffor/epoch/abort', scopes: [] },
	{ method: 'POST', path: '/ffor/preimage', scopes: [] },
	{ method: 'POST', path: '/ffor/witness/provision', scopes: [] },
	{ method: 'POST', path: '/ffor/witness/close', scopes: [] },
	{ method: 'POST', path: '/ffor/issuer/offer', scopes: ['invoice'] },
	{ method: 'POST', path: '/ffor/issuer/provision', scopes: [] },
	{ method: 'POST', path: '/ffor/recover', scopes: [] },
	{ method: 'POST', path: '/ffor/sync', scopes: [] },
	{ method: 'POST', path: '/ffor/enforce', scopes: [] },
	// The guardian this node serves to others (issue #699).
	{ method: 'GET', path: '/guardian/status', scopes: ['readonly'] },

	// ── Read-only POSTs (pure queries, no state change, no funds) ──
	{ method: 'POST', path: '/route/estimate', scopes: ['readonly'] },
	{ method: 'POST', path: '/route/query', scopes: ['readonly'] },
	{ method: 'POST', path: '/payment/estimate', scopes: ['readonly'] },
	// Prices a transaction without building or broadcasting one. It runs the same
	// setup and coin selection a send would, but on scratch state that is reset
	// again, so nothing is spent and nothing is left behind.
	{ method: 'POST', path: '/tx/quote', scopes: ['readonly'] },
	{ method: 'POST', path: '/message/verify', scopes: ['readonly'] },
	{ method: 'POST', path: '/address/validate', scopes: ['readonly'] },
	{
		method: 'POST',
		path: '/node/wait-ready',
		scopes: ['readonly'],
		wait: true
	},
	{
		method: 'POST',
		path: '/channel/wait-ready',
		scopes: ['readonly'],
		wait: true
	},

	// ── Invoice/receive routes readable by monitors too ──
	{ method: 'GET', path: '/invoices', scopes: ['readonly', 'invoice'] },
	{ method: 'GET', path: '/invoice', scopes: ['readonly', 'invoice'] },
	{ method: 'GET', path: '/invoices/held', scopes: ['readonly', 'invoice'] },
	{ method: 'GET', path: '/offers', scopes: ['readonly', 'invoice'] },
	{ method: 'GET', path: '/can-receive', scopes: ['readonly', 'invoice'] },
	// Its arm runs ahead of the restore holds, so restore progress reaches
	// SSE clients while nothing else answers.
	{
		method: 'GET',
		path: '/events',
		scopes: ['readonly', 'invoice'],
		allowedDuringRestore: true,
		allowedWhileRestartRequired: true,
		inline: true
	},
	{ method: 'POST', path: '/invoice/decode', scopes: ['readonly', 'invoice'] },
	{ method: 'POST', path: '/invoice/pay-all/quote', scopes: ['readonly'] },
	{
		method: 'POST',
		path: '/invoice/validate',
		scopes: ['readonly', 'invoice']
	},
	{ method: 'POST', path: '/offer/decode', scopes: ['readonly', 'invoice'] },
	{
		method: 'POST',
		path: '/payment/wait',
		scopes: ['readonly', 'invoice'],
		wait: true
	},

	// ── Receive-side mutations (invoice scope) ──
	{ method: 'POST', path: '/invoice/create', scopes: ['invoice'] },
	// Same scope as any other issued invoice: it registers an intent with an
	// LSP and returns a BOLT 11 string. The funding it may trigger is the
	// LSP's, out of the LSP's coins, and the fee it authorizes is bounded by
	// the node's own configured ceilings, not by the caller's.
	{ method: 'POST', path: '/jit/invoice', scopes: ['invoice'] },
	// Role readback, no secrets in it: fees, caps, sats reserved and fronted.
	{ method: 'GET', path: '/jit/status', scopes: ['readonly'] },
	// A price, asked of a peer: registers nothing, moves nothing.
	{ method: 'GET', path: '/jit/quote', scopes: ['readonly'] },
	// Reverse swap provider (issue #737): reading the ledger is readonly;
	// cancelling an unpaid swap closes a hold invoice, admin only.
	{ method: 'GET', path: '/swaps/status', scopes: ['readonly'] },
	{ method: 'GET', path: '/swaps', scopes: ['readonly'] },
	{ method: 'POST', path: '/swaps/cancel', scopes: [] },
	// Mints a receipt secret and hands out a payable artifact. It moves no
	// money: the same shape as POST /invoice/create and POST /jit/invoice.
	// Its two siblings are admin, deliberately: configure sets the liquidity
	// peer and the trust flag, and send spends a UTXO.
	{ method: 'POST', path: '/direct-funding/request', scopes: ['invoice'] },
	// Policy readback, no secrets in it.
	{ method: 'GET', path: '/direct-funding/config', scopes: ['readonly'] },
	{ method: 'POST', path: '/invoice/create-hold', scopes: ['invoice'] },
	{ method: 'POST', path: '/invoice/settle-hold', scopes: ['invoice'] },
	{ method: 'POST', path: '/invoice/cancel-hold', scopes: ['invoice'] },
	{ method: 'POST', path: '/offer/create', scopes: ['invoice'] },
	{ method: 'DELETE', path: '/offer', scopes: ['invoice'] },
	{ method: 'POST', path: '/address/new', scopes: ['invoice'] },

	// ── Admin-only: secrets / sensitive management surface ──
	{ method: 'GET', path: '/mnemonic', scopes: [] },
	// HMAC secrets are masked in list(), but callback URLs can embed
	// credentials; webhook management is one admin-only unit
	{ method: 'GET', path: '/webhooks', scopes: [] },

	// ── Admin-only: spending / fund movement ──
	// An on-chain send broadcasts a transaction. A caller that loses the
	// response cannot tell "not broadcast" from "broadcast, answer lost", and
	// checking the chain instead races the mempool.
	{ method: 'POST', path: '/send', scopes: [], idempotent: true },
	{ method: 'POST', path: '/send-max', scopes: [], idempotent: true },
	{ method: 'POST', path: '/onchain/sweep/prepare', scopes: [] },
	{ method: 'POST', path: '/onchain/sweep/submit', scopes: [] },
	{ method: 'POST', path: '/onchain/sweep/cancel', scopes: [] },
	{ method: 'POST', path: '/tx/bump-fee', scopes: [] },
	{ method: 'POST', path: '/tx/boost', scopes: [] },
	{ method: 'POST', path: '/consolidate', scopes: [] },
	{ method: 'POST', path: '/invoice/pay', scopes: [], idempotent: true },
	{ method: 'POST', path: '/invoice/pay-all', scopes: [], idempotent: true },
	{ method: 'POST', path: '/invoice/pay-safe', scopes: [], idempotent: true },
	{ method: 'POST', path: '/invoice/pay-async', scopes: [], idempotent: true },
	{ method: 'POST', path: '/invoice/pay-retry', scopes: [], idempotent: true },
	{ method: 'POST', path: '/keysend', scopes: [], idempotent: true },
	{ method: 'POST', path: '/keysend/safe', scopes: [], idempotent: true },
	// Each call requests a fresh BOLT 12 invoice with a fresh payment hash, so
	// the engine's duplicate-hash refusal cannot catch a retry (#1018).
	{ method: 'POST', path: '/offer/pay', scopes: [], idempotent: true },
	// L402: fetch spends, and a credential IS a bearer token for paid access,
	// so reading or dropping one is admin work too, not readonly. A retried
	// fetch gets a fresh challenge with a fresh invoice, so an un-keyed retry
	// pays twice.
	{ method: 'POST', path: '/l402/fetch', scopes: [], idempotent: true },
	{ method: 'GET', path: '/l402/credentials', scopes: [] },
	{ method: 'DELETE', path: '/l402/credential', scopes: [] },
	{ method: 'POST', path: '/payment/send-to-route', scopes: [] },
	{ method: 'POST', path: '/payment/cancel', scopes: [] },
	{ method: 'POST', path: '/queue/add', scopes: [] },
	{ method: 'POST', path: '/queue/cancel', scopes: [] },
	// Fee-spending advisor execution: retries must not double-spend fees.
	{ method: 'POST', path: '/rebalance', scopes: [], idempotent: true },
	{
		method: 'POST',
		path: '/advisor/execute-rebalances',
		scopes: [],
		idempotent: true
	},
	{ method: 'POST', path: '/recover-fallback-funds', scopes: [] },
	// Spends a UTXO into a stranger's channel funding. As fund-moving as
	// POST /send, and the empty list is what says so. The engine is idempotent
	// on the request id whether or not a key is supplied, which is what the
	// app needs since it sends none; the key only lets a client that DOES
	// supply one get the cached response without the engine re-deriving it.
	{
		method: 'POST',
		path: '/direct-funding/send',
		scopes: [],
		idempotent: true
	},

	// ── Admin-only: on-chain wallet mutation ──
	{ method: 'POST', path: '/utxo/freeze', scopes: [] },
	{ method: 'POST', path: '/utxo/unfreeze', scopes: [] },
	{ method: 'POST', path: '/address/label', scopes: [] },
	{ method: 'POST', path: '/wallet/refresh', scopes: [] },
	{ method: 'POST', path: '/psbt/build', scopes: [] },
	{ method: 'POST', path: '/psbt/import-signed', scopes: [] },
	{ method: 'POST', path: '/psbt/combine', scopes: [] },

	// ── Admin-only: channel and peer management ──
	{ method: 'POST', path: '/peer/connect', scopes: [] },
	{ method: 'POST', path: '/peer/disconnect', scopes: [] },
	// Dials the peer a stranger's request names, as POST /peer/connect would.
	{ method: 'POST', path: '/direct-funding/prepare', scopes: [] },
	{ method: 'POST', path: '/peers/bootstrap', scopes: [] },
	{ method: 'POST', path: '/peers/connect-seeds', scopes: [] },
	{ method: 'POST', path: '/trusted-peer/add', scopes: [] },
	{ method: 'POST', path: '/trusted-peer/remove', scopes: [] },
	// Sets the liquidity peer every direct-funded channel is negotiated with,
	// and whether such an open may go zero-conf.
	{ method: 'POST', path: '/direct-funding/configure', scopes: [] },
	// A retried open opens a second channel. open-and-wait is left out: its
	// wait usually outlasts the timeout, and a thrown timeout is not cached,
	// so a keyed retry would open again anyway.
	{ method: 'POST', path: '/channel/open', scopes: [], idempotent: true },
	{
		method: 'POST',
		path: '/channel/open-zeroconf',
		scopes: [],
		idempotent: true
	},
	{ method: 'POST', path: '/channel/open-v2', scopes: [], idempotent: true },
	{ method: 'POST', path: '/channel/open-and-wait', scopes: [] },
	{
		method: 'POST',
		path: '/channel/connect-and-open',
		scopes: [],
		idempotent: true
	},
	{ method: 'POST', path: '/channels/ensure-minimum', scopes: [] },
	{ method: 'POST', path: '/channel/close', scopes: [] },
	{ method: 'POST', path: '/channel/close-quote', scopes: ['readonly'] },
	{ method: 'POST', path: '/channel/forceclose', scopes: [] },
	{ method: 'POST', path: '/channel/rebroadcast-close', scopes: [] },
	{ method: 'POST', path: '/channel/funding-quote', scopes: ['readonly'] },
	{ method: 'POST', path: '/channel/splice-quote', scopes: ['readonly'] },
	{ method: 'POST', path: '/channel/splice-in', scopes: [] },
	// A retried splice-out moves the funds twice, to an external address: a
	// real spend.
	{
		method: 'POST',
		path: '/channel/splice-out',
		scopes: [],
		idempotent: true
	},
	{ method: 'POST', path: '/channel/update-commitment-feerate', scopes: [] },
	// Deprecated alias of /channel/update-commitment-feerate, served by the
	// same handler.
	{ method: 'POST', path: '/channel/update-fee', scopes: [] },
	{ method: 'POST', path: '/channel/update-policy', scopes: [] },

	// ── Admin-only: node identity, gossip, probing ──
	{ method: 'POST', path: '/message/sign', scopes: [] },
	{ method: 'POST', path: '/gossip/sync', scopes: [] },
	{ method: 'POST', path: '/gossip/sync-rapid', scopes: [] },
	{ method: 'POST', path: '/route/probe', scopes: [] },
	{ method: 'POST', path: '/payment/metadata', scopes: [] },

	// ── Admin-only: backups, watchtowers, webhooks, lifecycle ──
	{ method: 'POST', path: '/backup', scopes: [] },
	{ method: 'POST', path: '/backup/trigger', scopes: [] },
	{ method: 'POST', path: '/restore/scb', scopes: [] },
	// The guardian-restore takeover permanently fences the previous writer.
	{
		method: 'POST',
		path: '/recovery/restore',
		scopes: [],
		allowedDuringRestore: true
	},
	{ method: 'POST', path: '/recovery/restore-capsule', scopes: [] },
	// Hands back a retrieved capsule's guardian credentials.
	{ method: 'POST', path: '/recovery/capsule-guardians', scopes: [] },
	// Dials a remote node to resolve its guardian entry (issue #699).
	{ method: 'POST', path: '/recovery/resolve-guardian', scopes: [] },
	// Retires the current guardian set for good.
	{ method: 'POST', path: '/recovery/rotate-guardians', scopes: [] },
	{ method: 'POST', path: '/watchtower/add', scopes: [] },
	{ method: 'DELETE', path: '/watchtower/remove', scopes: [] },
	{ method: 'POST', path: '/webhooks/register', scopes: [] },
	{ method: 'DELETE', path: '/webhooks/unregister', scopes: [] },
	{
		method: 'POST',
		path: '/stop',
		scopes: [],
		allowedDuringRestore: true,
		allowedWhileRestartRequired: true,
		inline: true
	},

	// ── Admin-only: API key management ──
	{ method: 'GET', path: '/auth/keys', scopes: [] },
	{ method: 'POST', path: '/auth/keys/revoke', scopes: [] },
	{ method: 'POST', path: '/auth/keys/rotate', scopes: [] }
] as const satisfies readonly RouteDef[];

export const ROUTES: readonly RouteDef[] = ROUTE_TABLE;

type Route = (typeof ROUTE_TABLE)[number];
type KeyOf<R extends RouteDef> = R extends RouteDef
	? `${R['method']} ${R['path']}`
	: never;

/** The routes the dispatch table answers, as request keys ("GET /info"). */
export type HandledRouteKey = KeyOf<Exclude<Route, { inline: true }>>;

/** The key a request is dispatched on: "POST /tx/quote". */
export function routeKey(route: RouteDef): string {
	return `${route.method} ${route.path}`;
}

/** The keys of the routes that pass `test`. */
export function routeKeysWhere(
	test: (route: RouteDef) => boolean
): ReadonlySet<string> {
	return new Set(ROUTES.filter(test).map(routeKey));
}

/**
 * The dispatch table, one handler per route that is not inline. Throws when a
 * route has no handler or a handler has no route, so a route cannot ship
 * without its scopes and flags.
 */
export function dispatchTable<H>(
	handlers: Readonly<Record<HandledRouteKey, H>>
): ReadonlyMap<string, H> {
	const byKey = handlers as Readonly<Record<string, H | undefined>>;
	const table = new Map<string, H>();
	for (const route of ROUTES) {
		if (route.inline === true) continue;
		const key = routeKey(route);
		const handler = byKey[key];
		if (handler === undefined) throw new Error(`No handler for ${key}`);
		table.set(key, handler);
	}
	const unrouted = Object.keys(handlers).filter((key) => !table.has(key));
	if (unrouted.length > 0) {
		throw new Error(`Handlers with no route in ROUTES: ${unrouted.join(', ')}`);
	}
	return table;
}
