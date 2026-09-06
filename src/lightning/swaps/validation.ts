/** Block-based CLTV values must stay below the timestamp threshold. */
export function assertBlockHeight(value: number, name: string): void {
	if (!Number.isSafeInteger(value) || value < 1 || value >= 500_000_000) {
		throw new Error(
			`${name} must be an integer block height from 1 to 499999999`
		);
	}
}

export const MAX_MONEY_SATOSHIS = 2_100_000_000_000_000n;

export function assertSatoshis(value: bigint, name: string): void {
	if (typeof value !== 'bigint' || value <= 0n || value > MAX_MONEY_SATOSHIS) {
		throw new Error(
			`${name} must be positive satoshis within Bitcoin's money range`
		);
	}
}
