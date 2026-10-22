/**
 * Helpers used by wallet.ts, helpers.ts and transaction.ts. They live here,
 * importing none of the three, so those modules can share them without
 * loading each other in a cycle.
 */
import { bech32m } from 'bech32';
import { Network } from '../network';
import type { Result } from './result';
import { err, ok } from './result';

/**
 * Returns if the provided string is a valid Bech32m encoded string (taproot/p2tr address).
 * @param {string} address
 * @returns { isValid: boolean; network: Network }
 */
export const isValidBech32mEncodedString = (
	address: string
): { isValid: boolean; network: Network } => {
	const invalid = {
		isValid: false,
		network: Network.bitcoin
	};
	try {
		const decoded = bech32m.decode(address);
		// BIP-350: a well-formed checksum is not enough — bech32m addresses
		// carry a witness version (word 0) in 1..16 and a program of 2..40
		// bytes, and taproot (v1) is exactly 32. A bare checksum check accepted
		// junk like "bc1p...<any length>".
		const version = decoded.words[0];
		if (version === undefined || version < 1 || version > 16) return invalid;
		const program = bech32m.fromWords(decoded.words.slice(1));
		if (program.length < 2 || program.length > 40) return invalid;
		if (version === 1 && program.length !== 32) return invalid;
		switch (decoded.prefix) {
			case 'bc':
				return { isValid: true, network: Network.bitcoin };
			case 'tb':
				// 'tb' is shared by testnet and signet; beignet models signet
				// under the testnet params, so it is reported as testnet.
				return { isValid: true, network: Network.testnet };
			case 'bcrt':
				return { isValid: true, network: Network.regtest };
			default:
				return invalid;
		}
	} catch (error) {
		return invalid;
	}
};

/**
 * Returns each network once.
 * @returns {Network[]}
 */
export const availableNetworks = (): Network[] => Object.values(Network);

/**
 * Sum a specific value in an array of objects.
 * @param {T[]} arr
 * @param {keyof T} value
 * @returns {Result<number>}
 */
export const reduceValue = <T>({
	arr,
	value
}: {
	arr: T[];
	value: keyof T;
}): Result<number> => {
	try {
		if (!value) {
			return err('No value specified.');
		}
		const total = arr.reduce((acc, cur) => {
			return acc + Number(cur[value]);
		}, 0);
		// The trailing `|| 0` this replaces turned a NaN total, which one missing
		// or non-numeric entry produces, into a clean 0. Zero is a legitimate
		// total here, so the failure was indistinguishable from an empty set.
		if (!Number.isFinite(total)) {
			return err(
				`Non-numeric value encountered while summing "${String(value)}".`
			);
		}
		return ok(total);
	} catch (e) {
		return err(e);
	}
};

/**
 * Returns the difference between two address indexes.
 * @param addrIndex1
 * @param addrIndex2
 * @returns number
 */
export const getAddressIndexDiff = (addrIndex1 = 0, addrIndex2 = 0): number => {
	if (addrIndex1 < 0) addrIndex1 = -1;
	if (addrIndex2 < 0) addrIndex2 = -1;
	return Math.abs(addrIndex1 - addrIndex2);
};
