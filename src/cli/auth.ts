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

import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { BeignetError } from './errors';

export type ApiScope = 'readonly' | 'invoice' | 'admin';

export const API_SCOPES: ReadonlySet<ApiScope> = new Set([
	'readonly',
	'invoice',
	'admin'
]);

/** One named API key from config: { name, key, scopes, expiresAt? }. */
export interface ApiKeyDefinition {
	name: string;
	key: string;
	scopes: ApiScope[];
	/**
	 * Optional expiry as an ISO 8601 timestamp (e.g. "2027-01-01T00:00:00Z").
	 * Validated at construction; an expired key fails authentication exactly
	 * like an unknown key (401). The legacy apiToken cannot expire.
	 */
	expiresAt?: string;
}

/**
 * Persisted per-name override for a config-declared key. Only digests are
 * ever stored, never plaintext secrets.
 */
export interface StoredKeyOverride {
	/**
	 * SHA-256 hex of the CONFIG-declared secret at the time the override was
	 * written. If the operator later changes the key's secret in the config,
	 * the digests no longer match and the override is pruned: an explicit
	 * config re-key always wins over stored rotation/revocation state.
	 */
	configDigest: string;
	/** Durable revocation flag (fixes in-memory-only revocation of M6). */
	revoked?: boolean;
	/** SHA-256 hex of the rotated secret that replaces the config secret. */
	keyDigest?: string;
	/** ISO 8601 timestamp of the last rotation. */
	rotatedAt?: string;
	/** Optional expiry override (ISO 8601) applied over the config expiresAt. */
	expiresAt?: string;
}

/**
 * Durable backend for auth-key overrides (daemon wires this to the node's
 * encrypted SQLite storage). load() returns null when nothing is stored or
 * the stored value is unreadable; save() replaces the whole map.
 */
export interface AuthOverrideStore {
	load(): Record<string, StoredKeyOverride> | null;
	save(overrides: Record<string, StoredKeyOverride>): void;
}

/** wallet_data key under which auth-key overrides are persisted. The colon
 *  segments can never collide with on-chain wallet keys, which always end in
 *  an IWalletData field name ("<wallet>-<network>-<field>"). */
export const AUTH_KEY_OVERRIDES_STORAGE_KEY = 'daemon:auth-key-overrides:v1';

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
	'POST /auth/keys/revoke': [],
	'POST /auth/keys/rotate': []
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

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

interface CandidateKey {
	name: string | null;
	digest: Buffer;
	scopes: ReadonlySet<ApiScope>;
	/** SHA-256 hex of the CONFIG-declared secret (named keys only). Stays the
	 *  config digest after rotation replaces `digest`; anchors overrides. */
	configDigestHex?: string;
	/** Effective expiry (config value or persisted override). */
	expiresAt?: string;
	expiresAtMs?: number;
	/** ISO timestamp of the last rotation, when the key was ever rotated. */
	rotatedAt?: string;
}

/**
 * Authenticates bearer tokens against the legacy apiToken (implicit admin)
 * and named scoped API keys.
 *
 * Rotation and revocation are durable once an AuthOverrideStore is attached
 * (the daemon wires one backed by the node's encrypted SQLite storage):
 * per-name overrides (revoked flag, rotated-secret digest, rotatedAt) are
 * persisted and re-applied over the config-declared keys on the next start.
 * The config file remains the source of truth for the key SET; overrides
 * apply by name, and an override is pruned when its name left the config or
 * when the config secret for that name changed (explicit re-key wins).
 * Without a store, rotation/revocation still work for the process lifetime.
 */
export class ApiKeyAuthenticator {
	private readonly candidates: CandidateKey[] = [];
	private readonly revoked = new Set<string>();
	private readonly keyNames: string[] = [];
	private overrides: Record<string, StoredKeyOverride> = {};
	private store: AuthOverrideStore | null = null;

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
		let expiresAtMs: number | undefined;
		if (def.expiresAt !== undefined) {
			expiresAtMs =
				typeof def.expiresAt === 'string' ? Date.parse(def.expiresAt) : NaN;
			if (!Number.isFinite(expiresAtMs)) {
				throw new BeignetError(
					'INVALID_PARAMS',
					`apiKeys entry "${def.name}" has an unparseable expiresAt ` +
						`(use ISO 8601, e.g. "2027-01-01T00:00:00Z")`
				);
			}
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
			scopes: new Set<ApiScope>(def.scopes),
			configDigestHex: digest.toString('hex'),
			expiresAt: def.expiresAt,
			expiresAtMs
		});
	}

	/** True when any credential (legacy token or named key) is configured. */
	get enabled(): boolean {
		return this.candidates.length > 0;
	}

	private isExpired(candidate: CandidateKey): boolean {
		return (
			candidate.expiresAtMs !== undefined && Date.now() >= candidate.expiresAtMs
		);
	}

	/**
	 * Attach a durable override store: load persisted per-name overrides,
	 * prune stale ones (name no longer in config, config secret changed, or
	 * malformed entry), apply the rest over the config-declared keys, and use
	 * the store for all future rotate/revoke writes. Called by the daemon
	 * once the node's storage exists, before the HTTP server accepts requests.
	 */
	attachOverrideStore(store: AuthOverrideStore): void {
		this.store = store;
		const loaded = store.load();
		const kept: Record<string, StoredKeyOverride> = {};
		let pruned = false;
		for (const [name, override] of Object.entries(loaded ?? {})) {
			const candidate = this.candidates.find((c) => c.name === name);
			if (
				!candidate ||
				typeof override !== 'object' ||
				override === null ||
				typeof override.configDigest !== 'string' ||
				override.configDigest !== candidate.configDigestHex ||
				(override.keyDigest !== undefined &&
					!SHA256_HEX_RE.test(override.keyDigest))
			) {
				// Stale or malformed: the key left the config, the operator
				// re-keyed it in the config (config wins), or corrupt data.
				pruned = true;
				continue;
			}
			kept[name] = override;
			if (override.keyDigest !== undefined) {
				candidate.digest = Buffer.from(override.keyDigest, 'hex');
				candidate.rotatedAt = override.rotatedAt;
			}
			if (override.revoked === true) {
				this.revoked.add(name);
			}
			if (override.expiresAt !== undefined) {
				const ms =
					typeof override.expiresAt === 'string'
						? Date.parse(override.expiresAt)
						: NaN;
				// Unparseable stored expiry is ignored (never brick startup on
				// corrupt storage); config validation already ran.
				if (Number.isFinite(ms)) {
					candidate.expiresAt = override.expiresAt;
					candidate.expiresAtMs = ms;
				}
			}
		}
		this.overrides = kept;
		// Rewrite only when something was pruned, so entries never linger.
		if (pruned) store.save(kept);
	}

	/**
	 * Authenticate an Authorization header value. Constant-time: the
	 * presented token is hashed once and compared against every candidate
	 * digest (no early exit), so response time does not depend on which key
	 * matched or how much of a key matched. Revoked and expired keys never
	 * match (both fail exactly like an unknown key).
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
				(candidate.name === null || !this.revoked.has(candidate.name)) &&
				!this.isExpired(candidate)
			) {
				matched = candidate;
			}
		}
		if (!matched) return { ok: false };
		return { ok: true, keyName: matched.name, scopes: matched.scopes };
	}

	/**
	 * Revoke a named key, effective immediately. Returns false for unknown
	 * names. With an attached store the revocation is persisted and survives
	 * restarts (removing the key from the config remains the ultimate
	 * mechanism); without one it lasts for the process lifetime. The legacy
	 * apiToken has no name and cannot be revoked here; remove it from the
	 * config and restart instead.
	 */
	revoke(name: string): boolean {
		const candidate = this.candidates.find((c) => c.name === name);
		if (!candidate || candidate.name === null) return false;
		// Memory first: the security effect must not depend on storage health.
		this.revoked.add(name);
		this.overrides = {
			...this.overrides,
			[name]: {
				...(this.overrides[name] ?? {
					configDigest: candidate.configDigestHex ?? ''
				}),
				revoked: true
			}
		};
		this.store?.save(this.overrides);
		return true;
	}

	/**
	 * Rotate a named key: mint a cryptographically random 32-byte secret
	 * (hex) that replaces the current one. The old secret stops
	 * authenticating immediately; the new secret is returned ONCE and only
	 * its SHA-256 digest is ever stored. Rotating a revoked key reinstates
	 * it under the new secret (the compromised secret stays dead). Returns
	 * null for unknown names; the legacy apiToken has no name and cannot be
	 * rotated.
	 */
	rotate(
		name: string
	): { name: string; key: string; rotatedAt: string } | null {
		const candidate = this.candidates.find((c) => c.name === name);
		if (!candidate || candidate.name === null) return null;
		const newKey = randomBytes(32).toString('hex');
		const newDigest = sha256(newKey);
		const rotatedAt = new Date().toISOString();
		const override: StoredKeyOverride = {
			...(this.overrides[name] ?? {
				configDigest: candidate.configDigestHex ?? ''
			}),
			keyDigest: newDigest.toString('hex'),
			rotatedAt
		};
		delete override.revoked;
		const next = { ...this.overrides, [name]: override };
		// Persist BEFORE applying in memory: if the write fails, the old
		// secret keeps working and no one holds a secret that a restart
		// would silently invalidate.
		this.store?.save(next);
		this.overrides = next;
		candidate.digest = newDigest;
		candidate.rotatedAt = rotatedAt;
		this.revoked.delete(name);
		return { name, key: newKey, rotatedAt };
	}

	/**
	 * Named keys (never the secrets): name, scopes, revoked/expired flags,
	 * plus expiresAt/rotatedAt when set.
	 */
	listKeys(): Array<{
		name: string;
		scopes: ApiScope[];
		revoked: boolean;
		expired: boolean;
		expiresAt?: string;
		rotatedAt?: string;
	}> {
		return this.candidates
			.filter((c): c is CandidateKey & { name: string } => c.name !== null)
			.map((c) => ({
				name: c.name,
				scopes: [...c.scopes],
				revoked: this.revoked.has(c.name),
				expired: this.isExpired(c),
				...(c.expiresAt !== undefined ? { expiresAt: c.expiresAt } : {}),
				...(c.rotatedAt !== undefined ? { rotatedAt: c.rotatedAt } : {})
			}));
	}
}
