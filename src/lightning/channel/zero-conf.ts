/**
 * BOLT 2 Extension: Zero-confirmation channel management.
 *
 * Enables channels to be used before the funding transaction confirms.
 * Requires both peers to support option_zeroconf (feature bit 50) and
 * option_scid_alias (feature bit 46).
 *
 * Security: Only use with trusted peers, as unconfirmed funding can be
 * double-spent.
 */

export class ZeroConfManager {
	private trustedPeers: Set<string> = new Set();
	private jitClients: Set<string> = new Set();

	/**
	 * Add a peer to the trusted set for zero-conf channels.
	 */
	addTrustedPeer(pubkeyHex: string): void {
		this.trustedPeers.add(pubkeyHex);
	}

	/**
	 * Remove a peer from the trusted set.
	 */
	removeTrustedPeer(pubkeyHex: string): void {
		this.trustedPeers.delete(pubkeyHex);
	}

	/**
	 * Check if a peer is trusted for zero-conf.
	 */
	isTrustedPeer(pubkeyHex: string): boolean {
		return this.trustedPeers.has(pubkeyHex);
	}

	/**
	 * List all trusted peers.
	 */
	listTrustedPeers(): string[] {
		return [...this.trustedPeers];
	}

	/**
	 * Replace the JIT-client set: peers whose registered receive intent
	 * authorizes an OUTBOUND zero-conf open from us (issue #594).
	 *
	 * Deliberately NOT the trusted set. Membership there is symmetric: it also
	 * makes us accept an INBOUND zero-conf channel from the peer and treat it
	 * as usable at depth 0, which is a claim about the peer's honesty. A JIT
	 * client has made no such claim on us; we are the one taking the funding
	 * risk, with our own coins and our own caps. So this set is consulted only
	 * where WE are the opener, and the operator's explicit trust stays the only
	 * way an inbound zero-conf channel is accepted.
	 */
	setJitClients(pubkeyHexes: Iterable<string>): void {
		this.jitClients = new Set(pubkeyHexes);
	}

	/** Is this peer a JIT client with a live receive intent? */
	isJitClient(pubkeyHex: string): boolean {
		return this.jitClients.has(pubkeyHex);
	}

	listJitClients(): string[] {
		return [...this.jitClients];
	}

	/** May WE open a zero-conf channel to this peer? */
	canOpenZeroConfTo(pubkeyHex: string): boolean {
		return this.trustedPeers.has(pubkeyHex) || this.jitClients.has(pubkeyHex);
	}

	/**
	 * Determine if a channel should use zero-conf mode.
	 * Requires the peer to be trusted AND the channel to be opened with zeroConf option.
	 */
	shouldUseZeroConf(
		peerPubkeyHex: string,
		requestedZeroConf: boolean
	): boolean {
		return requestedZeroConf && this.trustedPeers.has(peerPubkeyHex);
	}

	/**
	 * Clear all trusted peers.
	 */
	clearTrustedPeers(): void {
		this.trustedPeers.clear();
	}
}
