/**
 * The fee coins a node that forwards keeps for the spends of its asset
 * channels' outputs that have a deadline (issue #2098, step 6): the size of
 * such a coin, how many of those spends the coins it has ready can pay for,
 * and whether a spend without a deadline may take coins now.
 *
 * A fee coin is spent whole, with no change, and each further coin a spend
 * takes adds an input of its own. So what ready coins can pay for is
 * counted spend by spend, with whole coins, at the rate of the moment and
 * within the cap one fee action may burn.
 */

/** What one fee input adds to a spend: a P2WPKH input, in vbytes. */
export const FIXED_OUTPUT_FEE_INPUT_VBYTES = 68;

/**
 * The largest spend with a deadline of an asset channel's output, on its
 * own, in vbytes: the claim of a received HTLC by its preimage (a
 * second-level success transaction, or a claim from the peer's commitment)
 * and the penalty of an output of a revoked commitment, without the fee
 * input that pays for it. The tests measure every such spend against it.
 */
export const FIXED_OUTPUT_DEADLINE_SPEND_VBYTES = 240;

/** The least a fee coin is: the dust limit of its P2WPKH output. */
const FEE_COIN_DUST = 330n;

/**
 * The size of a fee coin kept for a spend with a deadline: the fee of the
 * largest such spend with one fee input, at `ratePerVbyte`, and never under
 * the dust limit.
 */
export function reserveCoinSatoshis(ratePerVbyte: number): bigint {
	if (!Number.isFinite(ratePerVbyte) || ratePerVbyte <= 0) {
		throw new Error('A reserve rate is a positive number of sat/vB');
	}
	const fee = BigInt(
		Math.ceil(
			(FIXED_OUTPUT_DEADLINE_SPEND_VBYTES + FIXED_OUTPUT_FEE_INPUT_VBYTES) *
				ratePerVbyte
		)
	);
	return fee > FEE_COIN_DUST ? fee : FEE_COIN_DUST;
}

/**
 * How many spends with a deadline the coins can each pay for with whole
 * coins, at `ratePerVbyte`, with no spend burning more than `capSatoshis`.
 * Each spend takes the smallest coin that pays for it alone, or else the
 * fewest coins, largest first, that pay for it with the inputs they add.
 */
export function fundableDeadlineSpends(
	coins: readonly bigint[],
	ratePerVbyte: number,
	capSatoshis: bigint
): number {
	if (!Number.isFinite(ratePerVbyte) || ratePerVbyte <= 0) return 0;
	const fee = (inputs: number): bigint =>
		BigInt(
			Math.ceil(
				(FIXED_OUTPUT_DEADLINE_SPEND_VBYTES +
					FIXED_OUTPUT_FEE_INPUT_VBYTES * inputs) *
					ratePerVbyte
			)
		);
	const left = coins
		.filter((value) => value > 0n && value <= capSatoshis)
		.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
	let spends = 0;
	while (left.length > 0) {
		const alone = left.findIndex((value) => value >= fee(1));
		if (alone >= 0) {
			left.splice(alone, 1);
			spends++;
			continue;
		}
		const taken: number[] = [];
		let sum = 0n;
		for (let i = left.length - 1; i >= 0; i--) {
			if (sum + left[i] > capSatoshis) continue;
			sum += left[i];
			taken.push(i);
			if (sum >= fee(taken.length)) break;
		}
		if (taken.length === 0 || sum < fee(taken.length)) break;
		for (const i of taken) left.splice(i, 1);
		spends++;
	}
	return spends;
}

/**
 * Whether a spend without a deadline may ask for fee coins now, on a node
 * that keeps coins for its spends with a deadline: when none waits, as
 * before (the pool then splits for it if it has to), and otherwise only
 * while the coins ready would still pay for every one of those once this
 * spend has taken its own.
 */
export function noDeadlineSpendMayAsk(options: {
	readyCoins: readonly bigint[];
	ratePerVbyte: number;
	capSatoshis: bigint;
	/** The spends with a deadline the coins have to cover. */
	need: number;
}): boolean {
	if (options.need <= 0) return true;
	return (
		fundableDeadlineSpends(
			options.readyCoins,
			options.ratePerVbyte,
			options.capSatoshis
		) >=
		options.need + 1
	);
}
