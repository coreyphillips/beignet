/**
 * On-chain fee-rate sanity helpers. Every fee rate obtained from a remote
 * source (Electrum server or HTTP endpoint) must pass through the clamp so a
 * malicious or broken server cannot poison local fee estimates.
 */

/**
 * Hard ceiling for accepted fee rates. Mirrors MAX_FEE_RATE_SAT_PER_VBYTE in
 * src/lightning/node/types.ts (kept separate to avoid a wallet -> lightning
 * import).
 */
export const MAX_FEE_RATE_SAT_PER_VBYTE = 5000;

/**
 * Clamps a remote-sourced fee rate to [1, MAX_FEE_RATE_SAT_PER_VBYTE] sat/vB.
 * Returns 0 for unusable input (non-finite or <= 0) so callers can reject it.
 * @param {number} rate
 * @returns {number}
 */
export const clampFeeRate = (rate: number): number => {
	if (!Number.isFinite(rate) || rate <= 0) {
		return 0;
	}
	return Math.max(1, Math.min(Math.floor(rate), MAX_FEE_RATE_SAT_PER_VBYTE));
};

/**
 * Converts a blockchain.estimatefee result (BTC/kB, or -1 when the server has
 * no estimate) to a clamped sat/vB rate. Returns 0 when unusable.
 * @param {number} btcPerKb
 * @returns {number}
 */
export const btcPerKbToSatPerVbyte = (btcPerKb: number): number => {
	if (!Number.isFinite(btcPerKb) || btcPerKb <= 0) {
		return 0;
	}
	// BTC/kB * 1e8 sat/BTC / 1000 vB/kB = BTC/kB * 1e5 sat/vB
	return clampFeeRate(btcPerKb * 1e5);
};
