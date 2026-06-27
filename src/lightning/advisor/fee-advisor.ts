/**
 * FeeAdvisor: On-chain fee rate trend analysis.
 * Maintains a circular buffer of 144 samples (~24h at 10-min intervals).
 * Pure analysis -- no side effects or network calls.
 */

export type FeeTrend = 'RISING' | 'FALLING' | 'STABLE';
export type FeeRecommendation = 'OPEN_NOW' | 'WAIT' | 'NEUTRAL';

export interface IFeeSnapshot {
	currentSatPerVbyte: number;
	trend: FeeTrend;
	percentile: number; // 0-100, where 100 = highest fee in buffer
	recommendation: FeeRecommendation;
	estimatedOpenChannelCostSats: number;
	sampleCount: number;
	minSatPerVbyte: number;
	maxSatPerVbyte: number;
	avgSatPerVbyte: number;
}

const MAX_SAMPLES = 144;
const OPEN_CHANNEL_VBYTES = 154; // ~1-input 2-output P2WPKH funding tx

export class FeeAdvisor {
	private samples: number[] = [];
	private pointer = 0;
	private filled = false;

	/**
	 * Record a new fee rate sample (sat/vByte).
	 */
	recordSample(satPerVbyte: number): void {
		if (satPerVbyte <= 0) return;
		if (this.samples.length < MAX_SAMPLES) {
			this.samples.push(satPerVbyte);
		} else {
			this.samples[this.pointer] = satPerVbyte;
			this.filled = true;
		}
		this.pointer = (this.pointer + 1) % MAX_SAMPLES;
	}

	/**
	 * Get the current fee snapshot with trend analysis and recommendation.
	 * Returns null if no samples have been recorded.
	 */
	getSnapshot(): IFeeSnapshot | null {
		if (this.samples.length === 0) return null;

		const current = this.getCurrentRate();
		const sorted = [...this.samples].sort((a, b) => a - b);
		const min = sorted[0];
		const max = sorted[sorted.length - 1];
		const avg = sorted.reduce((s, v) => s + v, 0) / sorted.length;

		// Percentile: how many samples are <= current
		const belowOrEqual = sorted.filter((s) => s <= current).length;
		const percentile = Math.round((belowOrEqual / sorted.length) * 100);

		const trend = this.computeTrend();
		const recommendation = this.computeRecommendation(percentile, trend);

		return {
			currentSatPerVbyte: current,
			trend,
			percentile,
			recommendation,
			estimatedOpenChannelCostSats: Math.ceil(current * OPEN_CHANNEL_VBYTES),
			sampleCount: this.samples.length,
			minSatPerVbyte: min,
			maxSatPerVbyte: max,
			avgSatPerVbyte: Math.round(avg * 100) / 100
		};
	}

	/**
	 * Get the most recently recorded fee rate.
	 */
	getCurrentRate(): number {
		if (this.samples.length === 0) return 0;
		// pointer points to the next write position, so current is pointer-1
		const idx =
			this.pointer === 0
				? this.filled
					? MAX_SAMPLES - 1
					: this.samples.length - 1
				: this.pointer - 1;
		return this.samples[idx];
	}

	/**
	 * Get the number of recorded samples.
	 */
	get sampleCount(): number {
		return this.samples.length;
	}

	private computeTrend(): FeeTrend {
		if (this.samples.length < 6) return 'STABLE';

		// Compare the average of the last 6 samples vs the previous 6
		const total = this.samples.length;
		const recentCount = Math.min(6, Math.floor(total / 2));
		const recent: number[] = [];
		const older: number[] = [];

		for (let i = 0; i < recentCount; i++) {
			const recentIdx =
				(this.pointer - 1 - i + this.samples.length) % this.samples.length;
			recent.push(this.samples[recentIdx]);
			const olderIdx =
				(this.pointer - 1 - recentCount - i + this.samples.length) %
				this.samples.length;
			older.push(this.samples[olderIdx]);
		}

		const recentAvg = recent.reduce((s, v) => s + v, 0) / recent.length;
		const olderAvg = older.reduce((s, v) => s + v, 0) / older.length;

		// 10% threshold for trend detection
		if (recentAvg > olderAvg * 1.1) return 'RISING';
		if (recentAvg < olderAvg * 0.9) return 'FALLING';
		return 'STABLE';
	}

	private computeRecommendation(
		percentile: number,
		trend: FeeTrend
	): FeeRecommendation {
		// Low fees + falling/stable = good time to open
		if (percentile <= 30 && trend !== 'RISING') return 'OPEN_NOW';
		if (percentile <= 20) return 'OPEN_NOW'; // Very low even if rising
		// High fees + rising = wait
		if (percentile >= 70 && trend === 'RISING') return 'WAIT';
		if (percentile >= 80) return 'WAIT'; // Very high regardless of trend
		return 'NEUTRAL';
	}
}
