/**
 * BOLT 11: Amount encoding/decoding for the human-readable part (HRP).
 *
 * Amounts are encoded as an integer plus a multiplier suffix:
 *   m = milli (10^-3 BTC), u = micro (10^-6), n = nano (10^-9), p = pico (10^-12)
 *
 * The HRP format is: "ln" + network_prefix + [amount + multiplier]
 */

import { Network } from './types';

/** Multiplier suffix → millisatoshis per unit. 'p' is special: 1/10 msat. */
const MULTIPLIER_MSAT: Record<string, bigint> = {
	m: 100_000_000n, // 1 mBTC = 100,000,000 msat
	u: 100_000n, // 1 uBTC = 100,000 msat
	n: 100n, // 1 nBTC = 100 msat
	p: 1n // 1 pBTC = 0.1 msat → encode as 10p = 1 msat
};

/** BTC → msat conversion (1 BTC = 100,000,000,000 msat). */
const BTC_TO_MSAT = 100_000_000_000n;

/** Ordered from largest to smallest multiplier for encoding. */
const MULTIPLIER_ORDER: Array<{ suffix: string; msatPerUnit: bigint }> = [
	{ suffix: 'm', msatPerUnit: 100_000_000n },
	{ suffix: 'u', msatPerUnit: 100_000n },
	{ suffix: 'n', msatPerUnit: 100n },
	{ suffix: 'p', msatPerUnit: 1n }
];

/**
 * Convert a millisatoshi amount to the HRP amount string (digits + multiplier).
 * Chooses the largest multiplier that produces an integer coefficient.
 *
 * For 'p' (pico), the coefficient is msat * 10 (since 1p = 0.1 msat).
 */
export function msatToHrpAmount(amountMsat: bigint): string {
	if (amountMsat <= 0n) {
		throw new Error('Amount must be positive');
	}

	// Try whole BTC first (no multiplier)
	if (amountMsat % BTC_TO_MSAT === 0n) {
		return (amountMsat / BTC_TO_MSAT).toString();
	}

	// Try each multiplier from largest to smallest
	for (const { suffix, msatPerUnit } of MULTIPLIER_ORDER) {
		if (suffix === 'p') {
			// pico: coefficient = msat * 10 (must be integer, which it always is)
			const coefficient = amountMsat * 10n;
			return coefficient.toString() + suffix;
		}
		if (amountMsat % msatPerUnit === 0n) {
			return (amountMsat / msatPerUnit).toString() + suffix;
		}
	}

	// Unreachable: pico always works
	throw new Error('Cannot encode amount');
}

/**
 * Parse an HRP amount string (digits + optional multiplier) to millisatoshis.
 */
export function hrpAmountToMsat(amountStr: string): bigint {
	if (amountStr.length === 0) {
		throw new Error('Empty amount string');
	}

	const lastChar = amountStr[amountStr.length - 1];
	const multiplierMsat = MULTIPLIER_MSAT[lastChar];

	if (multiplierMsat !== undefined) {
		const digits = amountStr.slice(0, -1);
		if (digits.length === 0 || !/^\d+$/.test(digits)) {
			throw new Error(`Invalid amount digits: "${digits}"`);
		}
		if (digits.length > 1 && digits[0] === '0') {
			throw new Error('Leading zeros in amount');
		}
		const coefficient = BigInt(digits);
		if (lastChar === 'p') {
			// pico: 1p = 0.1 msat, so coefficient must be divisible by 10
			if (coefficient % 10n !== 0n) {
				throw new Error('Pico amount not divisible by 10 (sub-millisatoshi)');
			}
			return coefficient / 10n;
		}
		return coefficient * multiplierMsat;
	}

	// No multiplier → whole BTC
	if (!/^\d+$/.test(amountStr)) {
		throw new Error(`Invalid amount: "${amountStr}"`);
	}
	if (amountStr.length > 1 && amountStr[0] === '0') {
		throw new Error('Leading zeros in amount');
	}
	return BigInt(amountStr) * BTC_TO_MSAT;
}

/** All valid network prefixes. */
const NETWORK_PREFIXES: Record<string, Network> = {
	bc: Network.MAINNET,
	tb: Network.TESTNET,
	bcrt: Network.REGTEST,
	tbs: Network.SIGNET
};

/**
 * Parse the full HRP string into network and optional amount.
 * HRP format: "ln" + network_prefix + [amount]
 */
export function parseHrp(hrp: string): {
	network: Network;
	amountMsat: bigint | null;
} {
	if (!hrp.startsWith('ln')) {
		throw new Error(`Invalid HRP: must start with "ln", got "${hrp}"`);
	}
	const afterLn = hrp.slice(2);

	// Try each network prefix (longest first to avoid prefix conflicts)
	const prefixes = Object.keys(NETWORK_PREFIXES).sort(
		(a, b) => b.length - a.length
	);
	for (const prefix of prefixes) {
		if (afterLn.startsWith(prefix)) {
			const network = NETWORK_PREFIXES[prefix];
			const amountPart = afterLn.slice(prefix.length);
			if (amountPart.length === 0) {
				return { network, amountMsat: null };
			}
			return { network, amountMsat: hrpAmountToMsat(amountPart) };
		}
	}

	throw new Error(`Unknown network prefix in HRP: "${hrp}"`);
}

/**
 * Build the HRP string from network and optional amount.
 */
export function buildHrp(network: Network, amountMsat?: bigint): string {
	const base = 'ln' + network;
	if (amountMsat === undefined) {
		return base;
	}
	return base + msatToHrpAmount(amountMsat);
}
