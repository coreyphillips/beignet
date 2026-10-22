import type {
	IFormattedTransactions,
	IWalletStorage,
	TGetData,
	TSetData,
	TSetTransactionChanges
} from '../types';
import { ok } from './result';

/**
 * Returns an IWalletStorage that keeps its values in memory, so they are gone
 * when the process exits. It implements the whole contract, and is the one
 * to start from when writing a persistent store.
 *
 * Each value is kept as JSON, as a persistent store would keep it, so every
 * read hands back a fresh copy and a value that does not survive JSON fails
 * here too.
 * @param {Map<string, string>} [values] Holds each key's JSON. Pass a map to
 * seed the storage, or to look at what the wallet wrote.
 * @returns {Required<IWalletStorage>}
 */
export const createMemoryStorage = (
	values: Map<string, string> = new Map()
): Required<IWalletStorage> => {
	const getData: TGetData = async (key) => {
		const json = values.get(key);
		return ok(json === undefined ? undefined : JSON.parse(json));
	};
	const setData: TSetData = async (key, value) => {
		values.set(key, JSON.stringify(value));
		return ok(true);
	};
	const setTransactionChanges: TSetTransactionChanges = async (
		key,
		{ set, deleted }
	) => {
		const json = values.get(key);
		const transactions: IFormattedTransactions =
			json === undefined ? {} : JSON.parse(json);
		Object.assign(transactions, set);
		for (const txid of deleted) delete transactions[txid];
		values.set(key, JSON.stringify(transactions));
		return ok(true);
	};
	return { getData, setData, setTransactionChanges };
};
