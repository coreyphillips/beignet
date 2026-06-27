/**
 * HttpRateLimiter: Token bucket rate limiter for the HTTP daemon.
 * Keyed by client identifier (API token or IP address).
 * Opt-in — disabled by default unless rateLimit is configured.
 */

export interface RateLimitOptions {
	/** Maximum requests per window (default 100) */
	maxRequests?: number;
	/** Time window in milliseconds (default 60000 = 1 minute) */
	windowMs?: number;
}

interface TokenBucket {
	tokens: number;
	lastRefill: number;
}

const DEFAULT_MAX_REQUESTS = 100;
const DEFAULT_WINDOW_MS = 60_000;
const PRUNE_INTERVAL_MS = 5 * 60_000; // 5 minutes

export class HttpRateLimiter {
	private buckets = new Map<string, TokenBucket>();
	private maxRequests: number;
	private windowMs: number;
	private pruneTimer: ReturnType<typeof setInterval> | null = null;

	constructor(options?: RateLimitOptions) {
		this.maxRequests = options?.maxRequests ?? DEFAULT_MAX_REQUESTS;
		this.windowMs = options?.windowMs ?? DEFAULT_WINDOW_MS;

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

		if (!bucket) {
			bucket = { tokens: this.maxRequests, lastRefill: now };
			this.buckets.set(clientKey, bucket);
		}

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
	 * Remove stale entries (buckets that have been full/idle for > 2 windows).
	 */
	prune(): number {
		const now = Date.now();
		const staleThreshold = this.windowMs * 2;
		let pruned = 0;
		for (const [key, bucket] of this.buckets) {
			if (
				now - bucket.lastRefill > staleThreshold &&
				bucket.tokens >= this.maxRequests - 1
			) {
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
