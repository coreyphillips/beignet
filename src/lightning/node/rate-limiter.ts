/**
 * PeerRateLimiter: Token bucket rate limiter per peer.
 *
 * Prevents peers from flooding the node with HTLC requests.
 * Each peer gets an independent bucket that refills at a steady rate.
 */

export interface IRateLimitConfig {
	/** Maximum HTLCs per second per peer (default 30) */
	maxHtlcsPerSecond?: number;
	/** Burst multiplier (default 2) — bucket capacity = maxHtlcsPerSecond * burstMultiplier */
	burstMultiplier?: number;
}

interface IBucket {
	tokens: number;
	lastRefill: number;
}

export class PeerRateLimiter {
	private buckets: Map<string, IBucket> = new Map();
	private maxTokens: number;
	private refillRate: number; // tokens per millisecond

	constructor(config?: IRateLimitConfig) {
		const maxHtlcsPerSecond = config?.maxHtlcsPerSecond ?? 30;
		const burstMultiplier = config?.burstMultiplier ?? 2;
		this.maxTokens = maxHtlcsPerSecond * burstMultiplier;
		this.refillRate = maxHtlcsPerSecond / 1000; // per ms
	}

	/**
	 * Try to consume a token for the given peer.
	 * Returns true if the request is allowed, false if rate-limited.
	 */
	tryConsume(peerPubkey: string): boolean {
		const now = Date.now();
		let bucket = this.buckets.get(peerPubkey);

		if (!bucket) {
			bucket = { tokens: this.maxTokens, lastRefill: now };
			this.buckets.set(peerPubkey, bucket);
		}

		// Refill tokens based on elapsed time
		const elapsed = now - bucket.lastRefill;
		if (elapsed > 0) {
			bucket.tokens = Math.min(
				this.maxTokens,
				bucket.tokens + elapsed * this.refillRate
			);
			bucket.lastRefill = now;
		}

		if (bucket.tokens >= 1) {
			bucket.tokens -= 1;
			return true;
		}

		return false;
	}

	/**
	 * Remove a peer's bucket (e.g., on disconnect).
	 */
	removePeer(peerPubkey: string): void {
		this.buckets.delete(peerPubkey);
	}

	/**
	 * Clear all buckets.
	 */
	clear(): void {
		this.buckets.clear();
	}

	/**
	 * Number of tracked peers.
	 */
	get size(): number {
		return this.buckets.size;
	}
}
