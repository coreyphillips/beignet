/**
 * Scoped API authentication for the HTTP daemon (M6).
 *
 * Multiple named API keys with permission scopes replace the single static
 * bearer token. The legacy `apiToken` keeps working with implicit admin
 * scope. All comparisons are constant-time: both the presented key and each
 * candidate are hashed with SHA-256 and compared via crypto.timingSafeEqual,
 * which avoids length leaks and length-mismatch throws.
 *
 * Scopes:
 * - `readonly`: every GET route plus POSTs that are pure queries (estimate,
 *   validate, decode, wait). Default deny: anything that mutates state,
 *   moves funds, or reveals secrets is excluded.
 * - `invoice`: creating and looking up invoices/offers and receive-side
 *   routes (new address, hold-invoice lifecycle, waiting for payments).
 * - `admin`: everything, including spending, channel management, backups,
 *   webhooks, and key revocation.
 *
 * Route classification lives in ROUTE_SCOPES below. Routes absent from the
 * map FAIL CLOSED (admin-only); a drift test
 * (tests/cli/auth-scopes.test.ts) fails when a daemon route ships without
 * an explicit classification.
 */

import { createHash, timingSafeEqual } from 'crypto';
import { BeignetError } from './errors';

export type ApiScope = 'readonly' | 'invoice' | 'admin';

export const API_SCOPES: ReadonlySet<ApiScope> = new Set([
	'readonly',
	'invoice',
	'admin'
]);

/** One named API key from config: { name, key, scopes }. */
export interface ApiKeyDefinition {
	name: string;
	key: string;
	scopes: ApiScope[];
}

export interface AuthSuccess {
	ok: true;
	/** Key name, or null for the legacy single apiToken (implicit admin). */
	keyName: string | null;
	scopes: ReadonlySet<ApiScope>;
}

export interface AuthFailure {
	ok: false;
}

export type AuthResult = AuthSuccess | AuthFailure;

/**
 * Non-admin scopes accepted per route. `admin` is always accepted and is
 * never listed; `[]` therefore means admin-only. Routes NOT present here
 * fail closed to admin-only, and the drift test fails the build until the
 * route is classified.
 */
export const ROUTE_SCOPES: Record<string, ApiScope[]> = {
	// ── Read-only monitoring (GET) ──
	'GET /info': ['readonly'],
	'GET /balance': ['readonly'],
	'GET /peers': ['readonly'],
	'GET /channels': ['readonly'],
	'GET /channels/ready': ['readonly'],
	'GET /payments': ['readonly'],
	'GET /payment': ['readonly'],
	'GET /payment/proof': ['readonly'],
	'GET /payment/verify-proof': ['readonly'],
	'GET /forwards': ['readonly'],
	'GET /forwards/summary': ['readonly'],
	'GET /readiness': ['readonly'],
	'GET /stats': ['readonly'],
	'GET /spend-limit': ['readonly'],
	'GET /liquidity': ['readonly'],
	'GET /watchtowers': ['readonly'],
	'GET /advisor/recommendations': ['readonly'],
	'GET /fees': ['readonly'],
	'GET /fees/estimates': ['readonly'],
	'GET /transactions': ['readonly'],
	'GET /transactions/boostable': ['readonly'],
	'GET /utxos': ['readonly'],
	'GET /address/labels': ['readonly'],
	'GET /wallet/descriptors': ['readonly'],
	'GET /channel': ['readonly'],
	'GET /channel/health': ['readonly'],
	'GET /channel/policy': ['readonly'],
	'GET /channel/diagnostics': ['readonly'],
	'GET /channel/suggestions': ['readonly'],
	'GET /logs': ['readonly'],
	'GET /node/uri': ['readonly'],
	'GET /trusted-peers': ['readonly'],
	'GET /can-send': ['readonly'],
	'GET /graph/info': ['readonly'],
	'GET /graph/node': ['readonly'],
	'GET /graph/channel': ['readonly'],
	'GET /graph/describe': ['readonly'],
	'GET /backup/scb': ['readonly'],
	'GET /backup/peer-retrieved': ['readonly'],
	'GET /queue': ['readonly'],

	// ── Read-only POSTs (pure queries, no state change, no funds) ──
	'POST /route/estimate': ['readonly'],
	'POST /route/query': ['readonly'],
	'POST /payment/estimate': ['readonly'],
	'POST /message/verify': ['readonly'],
	'POST /address/validate': ['readonly'],
	'POST /node/wait-ready': ['readonly'],
	'POST /channel/wait-ready': ['readonly'],

	// ── Invoice/receive routes readable by monitors too ──
	'GET /invoices': ['readonly', 'invoice'],
	'GET /invoice': ['readonly', 'invoice'],
	'GET /invoices/held': ['readonly', 'invoice'],
	'GET /offers': ['readonly', 'invoice'],
	'GET /can-receive': ['readonly', 'invoice'],
	'GET /events': ['readonly', 'invoice'],
	'POST /invoice/decode': ['readonly', 'invoice'],
	'POST /invoice/validate': ['readonly', 'invoice'],
	'POST /offer/decode': ['readonly', 'invoice'],
	'POST /payment/wait': ['readonly', 'invoice'],

	// ── Receive-side mutations (invoice scope) ──
	'POST /invoice/create': ['invoice'],
	'POST /invoice/create-hold': ['invoice'],
	'POST /invoice/settle-hold': ['invoice'],
	'POST /invoice/cancel-hold': ['invoice'],
	'POST /offer/create': ['invoice'],
	'POST /address/new': ['invoice'],

	// ── Admin-only: secrets / sensitive management surface ──
	'GET /mnemonic': [],
	// HMAC secrets are masked in list(), but callback URLs can embed
	// credentials; webhook management is one admin-only unit
	'GET /webhooks': [],

	// ── Admin-only: spending / fund movement ──
	'POST /send': [],
	'POST /send-max': [],
	'POST /tx/bump-fee': [],
	'POST /tx/boost': [],
	'POST /consolidate': [],
	'POST /invoice/pay': [],
	'POST /invoice/pay-safe': [],
	'POST /invoice/pay-async': [],
	'POST /invoice/pay-retry': [],
	'POST /keysend': [],
	'POST /keysend/safe': [],
	'POST /offer/pay': [],
	'POST /payment/send-to-route': [],
	'POST /payment/cancel': [],
	'POST /queue/add': [],
	'POST /queue/cancel': [],
	'POST /rebalance': [],
	'POST /advisor/execute-rebalances': [],
	'POST /recover-fallback-funds': [],

	// ── Admin-only: on-chain wallet mutation ──
	'POST /utxo/freeze': [],
	'POST /utxo/unfreeze': [],
	'POST /address/label': [],
	'POST /wallet/refresh': [],
	'POST /psbt/build': [],
	'POST /psbt/import-signed': [],
	'POST /psbt/combine': [],

	// ── Admin-only: channel and peer management ──
	'POST /peer/connect': [],
	'POST /peer/disconnect': [],
	'POST /peers/bootstrap': [],
	'POST /peers/connect-seeds': [],
	'POST /trusted-peer/add': [],
	'POST /trusted-peer/remove': [],
	'POST /channel/open': [],
	'POST /channel/open-zeroconf': [],
	'POST /channel/open-v2': [],
	'POST /channel/open-and-wait': [],
	'POST /channel/connect-and-open': [],
	'POST /channels/ensure-minimum': [],
	'POST /channel/close': [],
	'POST /channel/forceclose': [],
	'POST /channel/splice-in': [],
	'POST /channel/splice-out': [],
	'POST /channel/update-commitment-feerate': [],
	'POST /channel/update-fee': [],
	'POST /channel/update-policy': [],

	// ── Admin-only: node identity, gossip, probing ──
	'POST /message/sign': [],
	'POST /gossip/sync': [],
	'POST /gossip/sync-rapid': [],
	'POST /route/probe': [],
	'POST /payment/metadata': [],

	// ── Admin-only: backups, watchtowers, webhooks, lifecycle ──
	'POST /backup': [],
	'POST /backup/trigger': [],
	'POST /restore/scb': [],
	'POST /watchtower/add': [],
	'DELETE /watchtower/remove': [],
	'POST /webhooks/register': [],
	'DELETE /webhooks/unregister': [],
	'POST /stop': [],

	// ── Admin-only: API key management ──
	'GET /auth/keys': [],
	'POST /auth/keys/revoke': []
};

/**
 * Accepted non-admin scopes for a route. Unknown routes fail closed
 * (admin-only).
 */
export function getRouteScopes(routeKey: string): ApiScope[] {
	return ROUTE_SCOPES[routeKey] ?? [];
}

/** True when `scopes` grants access to `routeKey`. Admin grants everything. */
export function scopesAllowRoute(
	scopes: ReadonlySet<ApiScope>,
	routeKey: string
): boolean {
	if (scopes.has('admin')) return true;
	return getRouteScopes(routeKey).some((s) => scopes.has(s));
}

function sha256(input: string): Buffer {
	return createHash('sha256').update(input, 'utf8').digest();
}

interface CandidateKey {
	name: string | null;
	digest: Buffer;
	scopes: ReadonlySet<ApiScope>;
}

/**
 * Authenticates bearer tokens against the legacy apiToken (implicit admin)
 * and named scoped API keys, with an in-memory revocation set. Removing a
 * key from the config file is the durable revocation mechanism; runtime
 * revocation covers the window until restart.
 */
export class ApiKeyAuthenticator {
	private readonly candidates: CandidateKey[] = [];
	private readonly revoked = new Set<string>();
	private readonly keyNames: string[] = [];

	constructor(apiToken?: string, apiKeys?: ApiKeyDefinition[]) {
		if (apiToken) {
			this.candidates.push({
				name: null,
				digest: sha256(apiToken),
				scopes: new Set<ApiScope>(['admin'])
			});
		}
		for (const def of apiKeys ?? []) {
			this.addKeyDefinition(def, apiToken);
		}
	}

	private addKeyDefinition(def: ApiKeyDefinition, apiToken?: string): void {
		if (!def || typeof def.name !== 'string' || def.name.trim() === '') {
			throw new BeignetError(
				'INVALID_PARAMS',
				'apiKeys entries require a non-empty name'
			);
		}
		if (typeof def.key !== 'string' || def.key === '') {
			throw new BeignetError(
				'INVALID_PARAMS',
				`apiKeys entry "${def.name}" requires a non-empty key`
			);
		}
		if (
			!Array.isArray(def.scopes) ||
			def.scopes.length === 0 ||
			def.scopes.some((s) => !API_SCOPES.has(s))
		) {
			throw new BeignetError(
				'INVALID_PARAMS',
				`apiKeys entry "${def.name}" requires scopes from: readonly, invoice, admin`
			);
		}
		if (this.keyNames.includes(def.name)) {
			throw new BeignetError(
				'INVALID_PARAMS',
				`Duplicate apiKeys name "${def.name}"`
			);
		}
		if (apiToken !== undefined && def.key === apiToken) {
			throw new BeignetError(
				'INVALID_PARAMS',
				`apiKeys entry "${def.name}" duplicates the legacy apiToken value`
			);
		}
		const digest = sha256(def.key);
		for (const existing of this.candidates) {
			if (existing.name !== null && timingSafeEqual(existing.digest, digest)) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`apiKeys entry "${def.name}" duplicates the key of "${existing.name}"`
				);
			}
		}
		this.keyNames.push(def.name);
		this.candidates.push({
			name: def.name,
			digest,
			scopes: new Set<ApiScope>(def.scopes)
		});
	}

	/** True when any credential (legacy token or named key) is configured. */
	get enabled(): boolean {
		return this.candidates.length > 0;
	}

	/**
	 * Authenticate an Authorization header value. Constant-time: the
	 * presented token is hashed once and compared against every candidate
	 * digest (no early exit), so response time does not depend on which key
	 * matched or how much of a key matched. Revoked keys never match.
	 */
	authenticate(header: string | undefined): AuthResult {
		if (!header) return { ok: false };
		const match = header.match(/^bearer\s+(.+)$/i);
		if (!match) return { ok: false };
		const presented = sha256(match[1]);
		let matched: CandidateKey | null = null;
		for (const candidate of this.candidates) {
			const equal = timingSafeEqual(candidate.digest, presented);
			if (
				equal &&
				matched === null &&
				(candidate.name === null || !this.revoked.has(candidate.name))
			) {
				matched = candidate;
			}
		}
		if (!matched) return { ok: false };
		return { ok: true, keyName: matched.name, scopes: matched.scopes };
	}

	/**
	 * Revoke a named key for the lifetime of this process. Returns false for
	 * unknown names. The legacy apiToken has no name and cannot be revoked at
	 * runtime; remove it from the config and restart instead.
	 */
	revoke(name: string): boolean {
		if (!this.keyNames.includes(name)) return false;
		this.revoked.add(name);
		return true;
	}

	/** Named keys (never the secrets): name, scopes, revoked flag. */
	listKeys(): Array<{ name: string; scopes: ApiScope[]; revoked: boolean }> {
		return this.candidates
			.filter((c): c is CandidateKey & { name: string } => c.name !== null)
			.map((c) => ({
				name: c.name,
				scopes: [...c.scopes],
				revoked: this.revoked.has(c.name)
			}));
	}
}
