/**
 * BOLT 9: Feature flag bit definitions and operations.
 *
 * Feature flags are exchanged in `init` messages and embedded in invoices,
 * node announcements, and channel announcements.
 *
 * Convention:
 *   - Even bit numbers = compulsory (sender MUST support)
 *   - Odd bit numbers = optional (sender MAY support)
 *   - Features are identified by their even bit position
 *   - If a node sets an even bit, it requires the peer to understand the feature
 *   - If a node sets an odd bit, the feature is optional
 */

/**
 * Known feature bits per BOLT 9.
 * Values represent the even (compulsory) bit position.
 * Optional variant is always evenBit + 1.
 */
export enum Feature {
	/** Requires or supports extra `channel_reestablish` fields (BOLT 2) */
	DATA_LOSS_PROTECT = 0,
	/** Node is an upfront shutdown script supporter */
	UPFRONT_SHUTDOWN_SCRIPT = 4,
	/** Gossip queries (BOLT 7) */
	GOSSIP_QUERIES = 6,
	/** TLV onion payloads (required for modern payments) */
	TLV_ONION = 8,
	/** Extended gossip queries */
	GOSSIP_QUERIES_EX = 10,
	/** Static remote key (BOLT 3) */
	STATIC_REMOTE_KEY = 12,
	/** Payment secret required (BOLT 4/11) */
	PAYMENT_SECRET = 14,
	/** Basic multi-part payments */
	BASIC_MPP = 16,
	/** Large channel support (wumbo) */
	LARGE_CHANNELS = 18,
	/** Anchor outputs */
	ANCHOR_OUTPUTS = 20,
	/** Zero-fee anchor outputs */
	ANCHOR_ZERO_FEE_HTLC = 22,
	/** Route blinding */
	ROUTE_BLINDING = 24,
	/** Shutdown with any segwit version */
	SHUTDOWN_ANY_SEGWIT = 26,
	/** Dual funding (BOLT 2 v2 channel establishment) */
	DUAL_FUND = 28,
	/** Onion messages */
	ONION_MESSAGES = 38,
	/** Quiescence / STFU (BOLT 2) — prerequisite for splicing */
	QUIESCE = 34,
	/** Channel type negotiation */
	CHANNEL_TYPE = 44,
	/** SCID alias */
	SCID_ALIAS = 46,
	/** Zero-conf channels */
	ZERO_CONF = 50,
	/** Keysend (bLIP-0003) — spontaneous payments via sender-generated preimage */
	KEYSEND = 54,
	/** Channel splicing (lightning/bolts PR #1160, option_splice) */
	SPLICE = 62,
	/**
	 * Simple taproot channels (option_taproot, lightning/bolts PR #995): MuSig2
	 * key-spend P2TR funding + taproot commitment/HTLC outputs.
	 *
	 * Bits 180/181 — LND's *staging* assignment (`simple-taproot-chans-x`), which
	 * is what LND v0.20 actually advertises (verified live: getinfo shows feature
	 * 181). The "final" bits 80/81 are reserved in the spec but NOT yet activated
	 * by any production node, so we negotiate the staging bit for interop. With
	 * base=180, setOptional() advertises bit 181, matching LND exactly.
	 */
	OPTION_TAPROOT = 180,
	/**
	 * Liquidity ads / option_will_fund (bLIP-0051): advertises that this node
	 * leases inbound liquidity (rates carried in node_announcement). Experimental
	 * bit pending a spec assignment.
	 */
	OPTION_WILL_FUND = 112
}

/**
 * Internal representation: feature flags as a Buffer of bytes.
 * Bit 0 is the least significant bit of byte[length-1].
 * Higher bit numbers extend to lower byte indices.
 */
export class FeatureFlags {
	private flags: Buffer;

	constructor(flags?: Buffer) {
		this.flags = flags ? Buffer.from(flags) : Buffer.alloc(0);
	}

	/**
	 * Create FeatureFlags from a raw byte buffer.
	 */
	static fromBuffer(buf: Buffer): FeatureFlags {
		return new FeatureFlags(buf);
	}

	/**
	 * Create FeatureFlags with no features set.
	 */
	static empty(): FeatureFlags {
		return new FeatureFlags();
	}

	/**
	 * Set a feature bit. The buffer is expanded as needed.
	 * @param bit - Bit position to set (0-indexed)
	 */
	setBit(bit: number): void {
		if (bit < 0) {
			throw new Error(`Bit position must be non-negative, got ${bit}`);
		}
		const byteIndex = Math.floor(bit / 8);
		const bitIndex = bit % 8;

		// Ensure buffer is large enough (bits are stored big-endian: high bytes first)
		const neededLength = byteIndex + 1;
		if (neededLength > this.flags.length) {
			const newFlags = Buffer.alloc(neededLength);
			// Copy existing flags to the right (end) of the new buffer
			this.flags.copy(newFlags, neededLength - this.flags.length);
			this.flags = newFlags;
		}

		// Bit 0 is LSB of last byte, so byte index from the end
		const bufIndex = this.flags.length - 1 - byteIndex;
		this.flags[bufIndex] |= 1 << bitIndex;
	}

	/**
	 * Clear a feature bit.
	 * @param bit - Bit position to clear
	 */
	clearBit(bit: number): void {
		const byteIndex = Math.floor(bit / 8);
		const bufIndex = this.flags.length - 1 - byteIndex;
		if (bufIndex < 0 || bufIndex >= this.flags.length) {
			return; // Bit is already clear (outside buffer)
		}
		const bitIndex = bit % 8;
		this.flags[bufIndex] &= ~(1 << bitIndex);
	}

	/**
	 * Check if a specific bit is set.
	 * @param bit - Bit position to check
	 * @returns True if the bit is set
	 */
	hasBit(bit: number): boolean {
		const byteIndex = Math.floor(bit / 8);
		const bufIndex = this.flags.length - 1 - byteIndex;
		if (bufIndex < 0 || bufIndex >= this.flags.length) {
			return false;
		}
		const bitIndex = bit % 8;
		return (this.flags[bufIndex] & (1 << bitIndex)) !== 0;
	}

	/**
	 * Set a feature as compulsory (even bit).
	 * @param feature - Feature enum value (even bit position)
	 */
	setCompulsory(feature: Feature): void {
		this.setBit(feature);
	}

	/**
	 * Set a feature as optional (odd bit = even bit + 1).
	 * @param feature - Feature enum value (even bit position)
	 */
	setOptional(feature: Feature): void {
		this.setBit(feature + 1);
	}

	/**
	 * Check if a feature is supported (either compulsory or optional).
	 * @param feature - Feature enum value (even bit position)
	 * @returns True if either the even or odd bit is set
	 */
	hasFeature(feature: Feature): boolean {
		return this.hasBit(feature) || this.hasBit(feature + 1);
	}

	/**
	 * Check if a feature is set as compulsory.
	 * @param feature - Feature enum value (even bit position)
	 */
	isCompulsory(feature: Feature): boolean {
		return this.hasBit(feature);
	}

	/**
	 * Check if a feature is set as optional.
	 * @param feature - Feature enum value (even bit position)
	 */
	isOptional(feature: Feature): boolean {
		return this.hasBit(feature + 1);
	}

	/**
	 * Check compatibility with a peer's features.
	 * Returns true if all compulsory features from both sides are understood.
	 * @param remote - The remote peer's feature flags
	 * @param localKnown - Set of features this node understands
	 * @returns True if features are compatible
	 */
	isCompatible(remote: FeatureFlags, localKnown: Set<Feature>): boolean {
		// Check that we understand all remote compulsory features
		const maxBits = Math.max(this.maxBit(), remote.maxBit());
		for (let bit = 0; bit <= maxBits; bit += 2) {
			// If remote sets compulsory (even) bit, we must know this feature
			if (remote.hasBit(bit)) {
				if (!localKnown.has(bit as Feature)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Get the highest bit position that is set.
	 * @returns Highest set bit, or -1 if no bits are set
	 */
	maxBit(): number {
		for (let i = 0; i < this.flags.length; i++) {
			if (this.flags[i] !== 0) {
				const bytePos = this.flags.length - 1 - i;
				for (let bit = 7; bit >= 0; bit--) {
					if (this.flags[i] & (1 << bit)) {
						return bytePos * 8 + bit;
					}
				}
			}
		}
		return -1;
	}

	/**
	 * Serialize to a buffer (trimming leading zero bytes).
	 */
	toBuffer(): Buffer {
		// Find first non-zero byte
		let start = 0;
		while (start < this.flags.length && this.flags[start] === 0) {
			start++;
		}
		if (start === this.flags.length) {
			return Buffer.alloc(0);
		}
		return Buffer.from(this.flags.subarray(start));
	}

	/**
	 * Get the list of all set feature bit positions.
	 */
	listSetBits(): number[] {
		const bits: number[] = [];
		for (let i = this.flags.length - 1; i >= 0; i--) {
			const bytePos = this.flags.length - 1 - i;
			for (let bit = 0; bit < 8; bit++) {
				if (this.flags[i] & (1 << bit)) {
					bits.push(bytePos * 8 + bit);
				}
			}
		}
		return bits.sort((a, b) => a - b);
	}
}

/**
 * Check if a remote peer requires features we don't support (BOLT 1).
 *
 * A required feature has its even bit set. We support it if either the
 * even or odd bit for that feature is set in our local flags.
 *
 * @returns Array of unsupported required feature bit numbers (empty = compatible)
 */
export function hasUnsupportedRequiredFeatures(
	localFeatures: FeatureFlags,
	remoteFeatures: FeatureFlags
): number[] {
	const unsupported: number[] = [];
	const maxBit = remoteFeatures.maxBit();

	for (let bit = 0; bit <= maxBit; bit += 2) {
		// Even bit = required/compulsory
		if (remoteFeatures.hasBit(bit)) {
			// We support this feature if we have either the even or odd bit set
			if (!localFeatures.hasBit(bit) && !localFeatures.hasBit(bit + 1)) {
				unsupported.push(bit);
			}
		}
	}

	return unsupported;
}
