/**
 * Routing-fee auto-tuner: computes per-channel proportional-fee (ppm) nudges
 * from simple utilization signals. Pure and deterministic -- the caller
 * supplies balances and forwarding counts; this module only does arithmetic.
 */

/** Utilization inputs for one channel over the observation window. */
export interface IFeeTuneInput {
	channelId: string;
	/** Current effective proportional fee in millionths (ppm). */
	currentPpm: number;
	/** Local balance as a fraction of capacity (0..1). */
	localBalanceFraction: number;
	/** Settled forwards that left over this channel during the window. */
	outboundForwards: number;
	/** Settled forwards that touched this channel (either leg) in the window. */
	totalForwards: number;
}

export interface IFeeTuneAdjustment {
	channelId: string;
	oldPpm: number;
	newPpm: number;
	reason: 'DEPLETED_OUTBOUND' | 'IDLE';
}

export interface IFeeTuneOptions {
	/** Lowest ppm the tuner will set (idle nudges never go below). */
	floorPpm: number;
	/** Highest ppm the tuner will set (depletion nudges never exceed). */
	ceilPpm: number;
}

export const DEFAULT_FEE_TUNE_FLOOR_PPM = 1;
export const DEFAULT_FEE_TUNE_CEIL_PPM = 10_000;

/** Local balance below this fraction of capacity counts as depleted. */
const DEPLETION_THRESHOLD = 0.2;
/** Multiplicative step per interval (25% up or down). */
const NUDGE_UP_FACTOR = 1.25;
const NUDGE_DOWN_FACTOR = 0.75;

/**
 * One adjustment per channel per call: channels that are being drained
 * (local balance under 20% AND outbound forwards in the window) get their ppm
 * raised 25% (price up scarce outbound liquidity, capped at ceilPpm); channels
 * with NO forwards at all get it lowered 25% (attract flow, floored at
 * floorPpm). Everything in between is left alone. Rounding is ceil on the way
 * up and floor on the way down with a minimum step of 1 ppm, so every emitted
 * adjustment changes the value.
 */
export function computeFeeTuneAdjustments(
	inputs: IFeeTuneInput[],
	options: IFeeTuneOptions
): IFeeTuneAdjustment[] {
	const adjustments: IFeeTuneAdjustment[] = [];
	for (const input of inputs) {
		const ppm = input.currentPpm;
		if (
			input.localBalanceFraction < DEPLETION_THRESHOLD &&
			input.outboundForwards > 0
		) {
			// Depleted AND still forwarding: demand outstrips supply, raise price.
			const raised = Math.max(ppm + 1, Math.ceil(ppm * NUDGE_UP_FACTOR));
			const newPpm = Math.min(options.ceilPpm, raised);
			if (newPpm !== ppm) {
				adjustments.push({
					channelId: input.channelId,
					oldPpm: ppm,
					newPpm,
					reason: 'DEPLETED_OUTBOUND'
				});
			}
		} else if (input.totalForwards === 0) {
			// No traffic either way: price may be uncompetitive, lower it.
			const lowered = Math.min(ppm - 1, Math.floor(ppm * NUDGE_DOWN_FACTOR));
			const newPpm = Math.max(options.floorPpm, lowered);
			if (newPpm !== ppm) {
				adjustments.push({
					channelId: input.channelId,
					oldPpm: ppm,
					newPpm,
					reason: 'IDLE'
				});
			}
		}
	}
	return adjustments;
}
