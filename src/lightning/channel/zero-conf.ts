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
