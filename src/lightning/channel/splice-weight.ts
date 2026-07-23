/**
 * Splice transaction weight estimation.
 *
 * The splice initiator pays the on-chain fee, computed as
 * estimated_weight * feerate_perkw / 1000. The estimate must agree between the
 * wallet's input selection (which must cover amount + fee for splice-in) and
 * the channel's contribution computation (which derives the change / new
 * funding amounts) — both MUST use estimateSpliceTxWeight, never a duplicated
 * constant.
 */

/**
 * Non-witness overhead: version(4) + locktime(4) + input/output count
 * varints(2) = 10 bytes ×4 = 40 WU, plus segwit marker+flag = 2 WU.
 */
export const SPLICE_TX_BASE_WEIGHT = 42;

/**
 * The shared 2-of-2 funding input: outpoint(36) + scriptSig len(1) + sequence(4)
 * = 41 bytes ×4 = 164 WU, plus witness [<>, sig, sig, witness_script] ≈ 222 WU.
 */
export const SHARED_FUNDING_INPUT_WEIGHT = 386;

/**
 * A P2WPKH wallet input: 41 bytes ×4 = 164 WU + witness (sig + pubkey) ≈ 108 WU.
 * Matches the per-input figures used by utils/transaction getByteCount.
 */
export const P2WPKH_INPUT_WEIGHT = 272;

/** Dust threshold (sats) for P2WPKH change/destination outputs. */
export const P2WPKH_DUST_LIMIT = 294n;

/**
 * Weight of an output: amount(8) + script length varint(1) + script bytes,
 * all non-witness (×4). P2WPKH (22) → 124 WU, P2WSH/P2TR (34) → 172 WU.
 */
export function outputWeight(scriptLen: number): number {
	return (8 + 1 + scriptLen) * 4;
}

/**
 * Estimate the total weight of a splice transaction.
 *
 * Always includes the shared 2-of-2 funding input and the new funding output.
 * For splice-in pass walletInputCount and changeScriptLen; for splice-out pass
 * destinationScriptLen. The change output is counted even when the channel
 * later drops a dust change output — a slight, safe overestimate.
 */
export function estimateSpliceTxWeight(opts: {
	walletInputCount: number;
	fundingScriptLen?: number;
	changeScriptLen?: number;
	destinationScriptLen?: number;
}): number {
	let weight =
		SPLICE_TX_BASE_WEIGHT +
		SHARED_FUNDING_INPUT_WEIGHT +
		opts.walletInputCount * P2WPKH_INPUT_WEIGHT +
		outputWeight(opts.fundingScriptLen ?? 34);
	if (opts.changeScriptLen !== undefined) {
		weight += outputWeight(opts.changeScriptLen);
	}
	if (opts.destinationScriptLen !== undefined) {
		weight += outputWeight(opts.destinationScriptLen);
	}
	return weight;
}

/**
 * Fee in satoshis for a given weight at a feerate in sat per kiloweight.
 */
export function spliceFeeSats(weight: number, feeratePerKw: number): bigint {
	return BigInt(Math.ceil((weight * feeratePerKw) / 1000));
}

/**
 * Interactive-tx (v2 open) contribution weight for OUR side, cushioned.
 *
 * P2WPKH input ≈ 272 WU cushioned to 320 (the peer's balance check estimates
 * our witness weight before seeing it; under-reserving fails the negotiation,
 * a few extra sats simply shrink the change), plus a change output (124 WU
 * cushioned to 140). The initiator additionally pays the common transaction
 * fields (~42 WU) and the shared P2WSH/P2TR funding output (172 WU),
 * cushioned to 240 together.
 *
 * The channel's contribution computation derives change as
 * inputs - contribution - fee(this weight), and a max-open quote derives the
 * committed funding amount as inputs - fee(this weight) — both MUST use this
 * function, never a re-derived constant, or a max open either fails as
 * underfunded or strands sats in an unintended change output.
 */
export function dualFundingContributionWeight(
	inputCount: number,
	initiator: boolean
): number {
	let weight = 320 * inputCount + 140;
	if (initiator) weight += 240;
	return weight;
}
