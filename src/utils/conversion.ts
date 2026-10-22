import { default as bitcoinUnits } from 'bitcoin-units';

/**
 * An amount in satoshis, as the wallet and `BeignetNode` take and return
 * amounts. A plain alias of `number`, so it changes no caller.
 */
export type Sats = number;

/**
 * An amount in millisatoshis, as the Lightning protocol layer holds amounts.
 * A plain alias of `bigint`, so it changes no caller.
 */
export type Msat = bigint;

/**
 * Converts a value in BTC to sats
 * @param {number} btc
 * @returns {Sats}
 */
export const btcToSats = (btc: number): Sats => {
	try {
		return Number(bitcoinUnits(btc, 'BTC').to('satoshi').value().toFixed(0));
	} catch {
		return 0;
	}
};

/**
 * Converts a value in sats to BTC
 * @param sats
 * @returns {number}
 */
export const satsToBtc = (sats: Sats): number => {
	return bitcoinUnits(sats, 'sats').to('BTC').value();
};

/**
 * Converts whole sats to msat. Refuses a fraction, and a number past
 * `Number.MAX_SAFE_INTEGER`, which may no longer be the amount it was meant
 * to be.
 * @param {Sats} sats
 * @returns {Msat}
 */
export const satsToMsat = (sats: Sats): Msat => {
	if (!Number.isSafeInteger(sats)) {
		throw new RangeError(`Not a whole number of sats: ${sats}`);
	}
	return BigInt(sats) * 1000n;
};

/**
 * Converts msat to whole sats, rounding down: a sub-satoshi remainder cannot
 * be paid or spent on chain. Refuses a result past `Number.MAX_SAFE_INTEGER`
 * rather than return a number that is not exact.
 * @param {Msat} msat
 * @returns {Sats}
 */
export const msatToSatsFloor = (msat: Msat): Sats => {
	// bigint division truncates toward zero, which rounds a negative amount up.
	const truncated = msat / 1000n;
	const sats = msat < 0n && msat % 1000n !== 0n ? truncated - 1n : truncated;
	if (
		sats > BigInt(Number.MAX_SAFE_INTEGER) ||
		sats < BigInt(Number.MIN_SAFE_INTEGER)
	) {
		throw new RangeError(`${msat} msat is past the safe integer range`);
	}
	return Number(sats);
};
