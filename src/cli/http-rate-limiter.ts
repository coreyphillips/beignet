/**
 * HttpRateLimiter: Token bucket rate limiter for the HTTP daemon.
 * Keyed by peer address; the daemon consults it before authentication so
 * failed auth attempts are throttled too.
 * Opt-in — disabled by default unless rateLimit is configured.
 */

import * as net from 'net';

export interface RateLimitOptions {
	/** Maximum requests per window (default 100) */
	maxRequests?: number;
	/** Time window in milliseconds (default 60000 = 1 minute) */
	windowMs?: number;
	/**
	 * Reverse-proxy addresses (exact IPs) whose X-Forwarded-For header may be
	 * used for bucket keying. Without this, every request arriving through a
	 * proxy shares the proxy's single bucket. The header is only consulted
	 * when the direct peer is listed here — trusting it unconditionally would
	 * let any direct caller mint fresh buckets and dodge the pre-auth
	 * throttle by rotating fake addresses.
	 */
	trustedProxies?: string[];
	/**
	 * Most client buckets held at once (default 100,000). Past it the least
	 * recently seen bucket is dropped, so a caller rotating addresses faster
	 * than buckets refill cannot grow the map without bound.
	 */
	maxClients?: number;
}

/**
 * Lowercase, trim, and unmap IPv4-mapped IPv6 (::ffff:1.2.3.4 -> 1.2.3.4) so
 * socket addresses compare equal to their configured spellings.
 */
function normalizeAddress(addr: string): string {
	let normalized = addr.trim().toLowerCase();
	if (normalized.startsWith('::ffff:') && net.isIPv4(normalized.slice(7))) {
		normalized = normalized.slice(7);
	}
	return normalized;
}

/**
 * Derive the rate-limit bucket key for a request. When the direct peer is a
 * trusted proxy, walk X-Forwarded-For right to left past trusted hops and key
 * on the first untrusted entry — the address the nearest trusted proxy saw.
 * Entries further left are caller-controlled and never consulted. Falls back
 * to the peer address when the header is absent or every hop is trusted.
 */
export function clientKeyForRequest(
	remoteAddress: string | undefined,
	forwardedFor: string | string[] | undefined,
	trustedProxies?: string[]
): string {
	const peer = remoteAddress ? normalizeAddress(remoteAddress) : 'unknown';
	if (!trustedProxies || trustedProxies.length === 0) return peer;
	const trusted = new Set(trustedProxies.map(normalizeAddress));
	if (!trusted.has(peer)) return peer;

	const headerValue = Array.isArray(forwardedFor)
		? forwardedFor.join(',')
		: forwardedFor;
	if (!headerValue) return peer;
	const hops = headerValue
		.split(',')
		.map(normalizeAddress)
		.filter((hop) => hop.length > 0);
	for (let i = hops.length - 1; i >= 0; i--) {
		if (!trusted.has(hops[i])) return hops[i];
	}
	return peer;
}

interface TokenBucket {
	tokens: number;
	lastRefill: number;
}

const DEFAULT_MAX_REQUESTS = 100;
const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_MAX_CLIENTS = 100_000;
const PRUNE_INTERVAL_MS = 5 * 60_000; // 5 minutes

export class HttpRateLimiter {
	// Insertion order is recency order: isAllowed moves a key to the end, so
	// the first entry is always the least recently seen.
	private buckets = new Map<string, TokenBucket>();
	private maxRequests: number;
	private windowMs: number;
	private maxClients: number;
	private pruneTimer: ReturnType<typeof setInterval> | null = null;

	constructor(options?: RateLimitOptions) {
		this.maxRequests = options?.maxRequests ?? DEFAULT_MAX_REQUESTS;
		this.windowMs = options?.windowMs ?? DEFAULT_WINDOW_MS;
		this.maxClients = Math.max(1, options?.maxClients ?? DEFAULT_MAX_CLIENTS);

		// Prune stale buckets every 5 minutes
		this.pruneTimer = setInterval(() => this.prune(), PRUNE_INTERVAL_MS);
		if (this.pruneTimer.unref) {
			this.pruneTimer.unref();
		}
	}

	/**
	 * Check if a request is allowed for the given client key.
	 * Returns true if allowed, false if rate limited.
	 */
	isAllowed(clientKey: string): boolean {
		const now = Date.now();
		let bucket = this.buckets.get(clientKey);

		if (bucket) {
			this.buckets.delete(clientKey);
		} else {
			// Dropping a bucket early only hands its key a full one sooner, and
			// the least recently seen key has refilled the most anyway.
			if (this.buckets.size >= this.maxClients) {
				const oldest = this.buckets.keys().next().value;
				if (oldest !== undefined) this.buckets.delete(oldest);
			}
			bucket = { tokens: this.maxRequests, lastRefill: now };
		}
		this.buckets.set(clientKey, bucket);

		// Refill tokens based on elapsed time
		const elapsed = now - bucket.lastRefill;
		if (elapsed > 0) {
			const refill = (elapsed / this.windowMs) * this.maxRequests;
			bucket.tokens = Math.min(this.maxRequests, bucket.tokens + refill);
			bucket.lastRefill = now;
		}

		if (bucket.tokens >= 1) {
			bucket.tokens -= 1;
			return true;
		}

		return false;
	}

	/**
	 * Remove every bucket idle for a full window. Refill tops a bucket up to
	 * maxRequests within one window, so a fresh bucket for that key is the
	 * same bucket. The stored token count cannot be consulted instead: it is
	 * only refilled inside isAllowed, so an idle bucket keeps whatever count
	 * its last request left.
	 */
	prune(): number {
		const now = Date.now();
		let pruned = 0;
		for (const [key, bucket] of this.buckets) {
			if (now - bucket.lastRefill >= this.windowMs) {
				this.buckets.delete(key);
				pruned++;
			}
		}
		return pruned;
	}

	/**
	 * Get the number of tracked clients.
	 */
	get size(): number {
		return this.buckets.size;
	}

	/**
	 * Clean up the prune timer.
	 */
	destroy(): void {
		if (this.pruneTimer) {
			clearInterval(this.pruneTimer);
			this.pruneTimer = null;
		}
		this.buckets.clear();
	}
}
